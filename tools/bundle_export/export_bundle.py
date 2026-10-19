#!/usr/bin/env python3
"""Export one binary to a format-2 TDO_v2 Ghidra Bundle.

Runs Ghidra 12.0.4 analyzeHeadless with ghidra/GhidraV2BundleExport.java as a
post-script and verifies the receipt.

Run it on Linux/WSL (POSIX).  On Windows the exporter itself fails at
publication: GhidraV2BundleExport.forceDirectory() opens the staging directory
as a FileChannel to fsync it, which Windows rejects with
java.nio.file.AccessDeniedException.  Bundle admission is also POSIX-only, so
write the bundle to a Linux filesystem (not /mnt/<drive>) owned by the user
that will run the engine.  --mirror-to copies the published files elsewhere
(e.g. the repo's output/bundles on D:) for inspection only.

Function selection: exactly one of --function-name (repeatable; the exporter
adds the transitive call/reference closure), --functions-from-manifest, or
--entry SPACE OFFSET. --stop-at-name SYMBOL (repeatable) / --stop-at-internal-models
LIBRARY: those functions are exported but the closure does not follow their
calls (a library's functions with an internal model: the derivation cuts there,
tools/derive_models).

A prepared Ghidra project (--ghidra-project path/to/Name.gpr --project-program
/folder/FILE): the program the user imported AND analyzed there is processed
as is (-process -noanalysis -readOnly); the exporter refuses a program that is
not analyzed, and one whose recorded executable SHA-256 differs from BINARY.

Example:
  python3 tools/bundle_export/export_bundle.py       /mnt/d/01_gitproject/09_tdo_testbed/build/win-debug/dfbench_win_core.exe       --functions-from-manifest /mnt/d/01_gitproject/09_tdo_testbed/manifests/cases_manifest.json       --output-root /root/tdo_bundles/win-debug --mirror-to output/bundles/win-debug
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
GHIDRA_DIR = REPO / "ghidra"
DEFAULT_GHIDRA = REPO.parent / "ghidra_12.0.4_PUBLIC"
if os.name == "nt":
    DEFAULT_OUT = REPO / "output" / "bundles"
    DEFAULT_JDK = Path(r"C:\Program Files\Eclipse Adoptium\jdk-21.0.4.7-hotspot")
else:
    DEFAULT_OUT = Path.home() / "tdo_bundles"
    DEFAULT_JDK = Path("/usr/lib/jvm/java-21-openjdk-amd64")
SOURCES = {
    "--bundle-exporter-sha256": "GhidraV2BundleExport.java",
    "--profile-exporter-sha256": "GhidraV2CallInterfaceProfile.java",
    "--naming-exporter-sha256": "GhidraV2CallNaming.java",
    "--effect-exporter-sha256": "GhidraV2CallEffect.java",
}
# Exported functions of libdfbench_importlib.dll (no manifest cases of its own).
IMPORTLIB_FUNCTIONS = (
    "dfb_import_identity",
    "dfb_import_write_out",
    "dfb_get_opaque_fn",
    "dfb_external_no_summary",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_functions(manifest: Path, binary_stem: str) -> list[str]:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    names = [c["function"] for c in data["cases"] if c["binary"] == binary_stem]
    if not names and binary_stem.startswith("libdfbench_importlib"):
        names = list(IMPORTLIB_FUNCTIONS)
    if not names:
        raise SystemExit(f"manifest has no cases for binary {binary_stem!r}")
    return sorted(set(names))


def internal_model_names(library: str, extra_dirs=()) -> list[str]:
    """Original names of the internal entries of model files for ``library``
    (models/external, then ``extra_dirs`` and TDO_V2_MODEL_DIRS, as
    ``summary_store.model_paths``): where the library's own derivation cuts."""
    names = []
    dirs = [REPO / "models" / "external", *extra_dirs]
    dirs += [Path(item) for item in os.environ.get("TDO_V2_MODEL_DIRS", "").split(os.pathsep) if item]
    for path in sorted({path for directory in dirs for path in Path(directory).glob("*.json")}):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("kind") != "declared" or library.upper() not in {
                item.upper() for item in data.get("libraries", ())}:
            continue
        names += [name for entry in data["entries"] if entry.get("internal")
                  for name in entry.get("original_names", ())]
    if not names:
        raise SystemExit(f"no internal models for {library}")
    return names


def mirror(published: Path, target_root: Path) -> Path:
    target_root.mkdir(parents=True, exist_ok=True)
    target = target_root / published.name
    if target.exists():
        raise SystemExit(f"mirror target exists: {target}")
    shutil.copytree(published, target)
    return target


CLEANUP_SECONDS = 30.0


def _members(group: int) -> list[tuple[int, int, str]]:
    """(pid, parent pid, state) of every process of ``group`` (Linux /proc)."""
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", encoding="ascii", errors="replace") as handle:
                fields = handle.read().rsplit(")", 1)[1].split()
        except OSError:
            continue
        if int(fields[2]) == group:
            found.append((int(entry), int(fields[1]), fields[0]))
    return found


def _threads_running(pid: int) -> bool:
    """A process shown as a zombie may still have running threads (its main
    thread called pthread_exit): any thread not dead counts (Astra K1d impl.
    round 2, P1)."""
    try:
        tasks = os.listdir(f"/proc/{pid}/task")
    except OSError:
        return False
    for task in tasks:
        try:
            with open(f"/proc/{pid}/task/{task}/stat", encoding="ascii", errors="replace") as handle:
                if handle.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X"):
                    return True
        except OSError:
            continue
    return False


def run_bounded(command, env, total: float):
    """(returncode, timed out, stopped): ``command`` with a total monotonic
    deadline (docs 25.30 K1d). Linux / WSL: its own session and process group;
    this process becomes a child subreaper (adopted orphans are reaped). The
    leader is NOT reaped until every signal to its group has been sent: its
    unreaped pid anchors the group id, which the kernel cannot reuse meanwhile
    (Astra K1d impl. P1-1). On timeout, error, KeyboardInterrupt AND after a
    normal exit of the leader the group's live members are stopped (TERM,
    5 s, KILL), adopted zombies reaped, until no live member is left (bounded
    by CLEANUP_SECONDS; ``stopped`` False: not shown gone). Descendants that
    leave the process group escape this cleanup (run_supervised's cgroup
    contains them). Elsewhere: a plain timeout of the leader (documented)."""
    if not sys.platform.startswith("linux"):
        try:
            return subprocess.run(command, env=env, timeout=total).returncode, False, True
        except subprocess.TimeoutExpired:
            return None, True, True
    import ctypes
    import signal

    PR_SET_CHILD_SUBREAPER = 36
    ctypes.CDLL(None, use_errno=True).prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
    process = subprocess.Popen(command, env=env, start_new_session=True)
    group = leader = process.pid
    me = os.getpid()
    timed_out = False

    def live():
        return [pid for pid, _, state in _members(group)
                if state not in ("Z", "X") or _threads_running(pid)]

    def reap_adopted():   # zombies adopted from the group, never the leader
        for pid, parent, state in _members(group):
            if state == "Z" and parent == me and pid != leader and not _threads_running(pid):
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass

    try:
        limit = time.monotonic() + total
        while True:   # the leader's exit, observed without reaping it
            if os.waitid(os.P_PID, leader, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
                break
            if time.monotonic() > limit:
                timed_out = True
                break
            time.sleep(0.1)
    finally:
        for sig, pause in ((signal.SIGTERM, 5.0), (signal.SIGKILL, 0.0)):
            reap_adopted()
            if not live():
                break
            os.killpg(group, sig)   # (anchored: the leader is unreaped)
            until = time.monotonic() + pause
            while time.monotonic() < until and live():
                reap_adopted()
                time.sleep(0.05)
        deadline = time.monotonic() + CLEANUP_SECONDS
        while live() and time.monotonic() < deadline:
            reap_adopted()
            time.sleep(0.05)
        stopped = not live()
        reap_adopted()
        if stopped:
            try:
                process.wait(CLEANUP_SECONDS)   # the anchor released last (bounded)
            except subprocess.TimeoutExpired:
                stopped = False
    return process.returncode, timed_out, stopped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--ghidra", type=Path, default=DEFAULT_GHIDRA)
    parser.add_argument("--java-home", type=Path, default=DEFAULT_JDK)
    sel = parser.add_mutually_exclusive_group(required=True)
    sel.add_argument("--function-name", action="append")
    sel.add_argument("--functions-from-manifest", type=Path)
    sel.add_argument("--entry", nargs=2, action="append", metavar=("SPACE", "OFFSET"))
    parser.add_argument("--exclude-function", action="append", default=[],
                        help="drop this name from a manifest/name selection")
    parser.add_argument("--generation", help="64 lowercase hex (default: random)")
    parser.add_argument("--max-mem", default="8G")
    parser.add_argument("--analysis-timeout", type=int, default=3600)
    parser.add_argument("--mirror-to", type=Path,
                        help="also copy the published generation under this directory")
    parser.add_argument("--keep-project", action="store_true")
    parser.add_argument("--total-timeout", type=float, default=None,
                        help="seconds for the whole Ghidra run (default: analysis timeout + 1 h); "
                             "on expiry the run fails and its process group is stopped")
    parser.add_argument("--stop-at-name", action="append", default=[],
                        help="export this function but do not follow its calls (exact symbol)")
    parser.add_argument("--stop-at-internal-models", metavar="LIBRARY",
                        help="stop at every function an internal model of LIBRARY names (models/external)")
    parser.add_argument("--model-dir", action="append", default=[], type=Path,
                        help="extra model directory for --stop-at-internal-models (as the derivation's)")
    parser.add_argument("--ghidra-project", type=Path,
                        help="a prepared project (.gpr): process its analyzed program, no import, no analysis")
    parser.add_argument("--project-program", help="the program's path in the project, e.g. /libs/CORE.DLL")
    args = parser.parse_args()
    if (args.ghidra_project is None) != (args.project_program is None):
        raise SystemExit("--ghidra-project and --project-program go together")

    binary = args.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"binary not found: {binary}")
    out_root = args.output_root.resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(out_root, 0o755)
    generation = args.generation or secrets.token_hex(32)
    nonce = secrets.token_hex(32)
    logs = out_root.parent / (out_root.name + ".logs")
    logs.mkdir(exist_ok=True)
    receipt = logs / f"{generation}.receipt"

    script_args = [
        "--output-root", str(out_root),
        "--generation", generation,
        "--original-executable", str(binary),
        "--original-size", str(binary.stat().st_size),
        "--original-sha256", sha256_file(binary),
    ]
    for flag, name in SOURCES.items():
        script_args += [flag, sha256_file(GHIDRA_DIR / name)]
    script_args += ["--receipt-path", str(receipt), "--receipt-nonce", nonce]
    stops = list(args.stop_at_name)
    if args.stop_at_internal_models:
        stops += internal_model_names(args.stop_at_internal_models, args.model_dir)
    for name in sorted(set(stops)):
        script_args += ["--stop-at-name", name]
    if args.ghidra_project is not None:
        script_args += ["--require-analyzed"]
    if args.entry:
        for space, offset in args.entry:
            script_args += ["--entry", space, offset]
    else:
        names = args.function_name or manifest_functions(
            args.functions_from_manifest, binary.stem)
        names = [n for n in names if n not in set(args.exclude_function)]
        for name in names:
            script_args += ["--function-name", name]

    headless = args.ghidra / "support" / (
        "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    if args.ghidra_project is not None:
        project = args.ghidra_project.resolve()
        folder, _, program = args.project_program.rpartition("/")
        project_dir = None
        target = [str(project.parent), project.stem + (folder if folder else ""),
                  "-process", program, "-noanalysis"]
    else:
        project_dir = Path(tempfile.mkdtemp(prefix="tdo_ghidra_proj_"))
        target = [str(project_dir), "tdo_export", "-import", str(binary)]
    command = [
        *(() if os.name == "nt" else ("bash",)), str(headless), *target,
        "-readOnly",
        "-analysisTimeoutPerFile", str(args.analysis_timeout),
        "-scriptPath", str(GHIDRA_DIR),
        "-log", str(logs / f"{generation}.ghidra.log"),
        "-scriptlog", str(logs / f"{generation}.script.log"),
        "-postScript", "GhidraV2BundleExport.java", *script_args,
    ]
    env = dict(os.environ)
    if args.java_home and args.java_home.is_dir():
        env["JAVA_HOME"] = str(args.java_home)
        env["PATH"] = str(args.java_home / "bin") + os.pathsep + env.get("PATH", "")
    env["MAXMEM"] = args.max_mem
    (logs / f"{generation}.command.json").write_text(
        json.dumps({"binary": str(binary), "command": command}, indent=1),
        encoding="utf-8")
    print(f"[export] generation {generation}", flush=True)
    started = time.time()
    total = args.total_timeout if args.total_timeout is not None else args.analysis_timeout + 3600
    returncode, timed_out, stopped = run_bounded(command, env, total)
    elapsed = time.time() - started
    if not stopped:
        # the process group could not be shown gone: keep the project for inspection
        print(f"[export] FAILED: Ghidra processes did not stop; project kept at {project_dir}", file=sys.stderr)
        return 1
    if project_dir is not None and not args.keep_project:
        shutil.rmtree(project_dir, ignore_errors=True)
    if timed_out:
        print(f"[export] FAILED: total timeout {total:.0f}s exceeded", file=sys.stderr)
        return 1

    published = out_root / generation
    expected_receipt = f"{generation}\n{nonce}\n".encode("ascii")
    if not published.is_dir() or not receipt.is_file() or \
            receipt.read_bytes() != expected_receipt:
        print(f"[export] FAILED (rc={returncode}, {elapsed:.0f}s); "
              f"see {logs / (generation + '.script.log')}", file=sys.stderr)
        return 1
    files = sorted(published.iterdir())
    total = sum(f.stat().st_size for f in files)
    print(f"[export] published {published} ({len(files)} files, {total} bytes, "
          f"{elapsed:.0f}s)")
    index = logs / "index.jsonl"
    record = {"generation": generation, "binary": str(binary),
              "sha256": sha256_file(binary), "files": len(files), "bytes": total,
              "stop_at": sorted(set(stops)), "seconds": round(elapsed),
              "ghidra_project": None if args.ghidra_project is None
              else [str(args.ghidra_project), args.project_program]}
    if args.mirror_to:
        record["mirror"] = str(mirror(published, args.mirror_to.resolve()))
        print(f"[export] mirrored to {record['mirror']}")
    with index.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
