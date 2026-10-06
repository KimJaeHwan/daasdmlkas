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
--entry SPACE OFFSET.

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


def mirror(published: Path, target_root: Path) -> Path:
    target_root.mkdir(parents=True, exist_ok=True)
    target = target_root / published.name
    if target.exists():
        raise SystemExit(f"mirror target exists: {target}")
    shutil.copytree(published, target)
    return target


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
    args = parser.parse_args()

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
    if args.entry:
        for space, offset in args.entry:
            script_args += ["--entry", space, offset]
    else:
        names = args.function_name or manifest_functions(
            args.functions_from_manifest, binary.stem)
        names = [n for n in names if n not in set(args.exclude_function)]
        for name in names:
            script_args += ["--function-name", name]

    project_dir = Path(tempfile.mkdtemp(prefix="tdo_ghidra_proj_"))
    headless = args.ghidra / "support" / (
        "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    command = [
        *(() if os.name == "nt" else ("bash",)), str(headless), str(project_dir), "tdo_export",
        "-import", str(binary),
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
    result = subprocess.run(command, env=env)
    elapsed = time.time() - started
    if not args.keep_project:
        shutil.rmtree(project_dir, ignore_errors=True)

    published = out_root / generation
    expected_receipt = f"{generation}\n{nonce}\n".encode("ascii")
    if not published.is_dir() or not receipt.is_file() or \
            receipt.read_bytes() != expected_receipt:
        print(f"[export] FAILED (rc={result.returncode}, {elapsed:.0f}s); "
              f"see {logs / (generation + '.script.log')}", file=sys.stderr)
        return 1
    files = sorted(published.iterdir())
    total = sum(f.stat().st_size for f in files)
    print(f"[export] published {published} ({len(files)} files, {total} bytes, "
          f"{elapsed:.0f}s)")
    index = logs / "index.jsonl"
    record = {"generation": generation, "binary": str(binary),
              "sha256": sha256_file(binary), "files": len(files), "bytes": total}
    if args.mirror_to:
        record["mirror"] = str(mirror(published, args.mirror_to.resolve()))
        print(f"[export] mirrored to {record['mirror']}")
    with index.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
