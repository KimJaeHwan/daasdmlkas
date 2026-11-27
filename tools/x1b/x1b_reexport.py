"""X-1b replay (design_x1b_method_r3 A / section 4): every expected pair (Bundle + old generation) is exported once,
with a fresh generation id, by a tree's exporter; each output is verified raw and recorded in the pairs file.
Run in WSL with python3.

usage: x1b_reexport.py <tree> [--old /root/tdo_bundles3] [--new /root/tdo_bundles4] [--pairs FILE] [--only NAME ...]
                       [--jobs N]
The first old generation of a Bundle (the one the gate reads: sorted first) is published under <new>/<name>; any
further old generation under <new>/<name>.second, .third ...
"""
import argparse
import concurrent.futures
import hashlib
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from x1b_bundle_tools import Bundle, verify  # noqa: E402

GHIDRA = __import__("os").environ.get("TDO_GHIDRA", "/mnt/d/01_gitproject/14_TDO_v2/ghidra_12.0.4_PUBLIC")
SELECTORS = ("--function-name", "--exclude-function", "--stop-at-name", "--stop-at-internal-models")
SUFFIXES = ("", ".second", ".third", ".fourth")
LOCK = threading.Lock()


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected_pairs(old: Path):
    """[(pair key, publish name, old generation dir, command document)] -- one per old generation."""
    by_name = {}
    for command in sorted(old.glob("**/*.logs/*.command.json")):
        name = str(command.parent.relative_to(old))[:-len(".logs")]
        generation = old / name / command.name[:-len(".command.json")]
        if generation.is_dir():
            by_name.setdefault(name, []).append((generation, json.loads(command.read_text())))
    for name, items in sorted(by_name.items()):
        for index, (generation, document) in enumerate(sorted(items, key=lambda item: item[0].name)):
            yield f"{name}#{generation.name[:12]}", name + SUFFIXES[index], generation, document


def replay_args(document) -> list[str]:
    command, args = document["command"], []
    if "-import" not in command:
        raise SystemExit("only -import exports are replayed here (project exports: see x1b_reexport_projects)")
    index = 0
    while index < len(command):
        token = command[index]
        if token == "--entry":
            args += [token, command[index + 1], command[index + 2]]
            index += 3
            continue
        if token in SELECTORS:
            args += [token, command[index + 1]]
            index += 2
            continue
        index += 1
    return args


def record(old_generation: Path, published: Path) -> dict:
    old, new = Bundle(old_generation), Bundle(published)
    return {
        "old": {"generation": old_generation.name, "path": str(old_generation),
                "manifest_sha256": file_sha(old_generation / "manifest.json"),
                "seal_sha256": file_sha(old_generation / "seal.json")},
        "published": {"generation": published.name, "path": str(published),
                      "manifest_sha256": file_sha(published / "manifest.json"),
                      "seal_sha256": file_sha(published / "seal.json")},
        "original_sha256": new.rows[new.manifest["original_member_id"]]["sha256"],
        "rule": "derived-from-published",
    }


def check(old_generation: Path, published: Path) -> list[str]:
    problems = verify(published)
    old, new = Bundle(old_generation), Bundle(published)
    if old.rows[old.manifest["original_member_id"]]["sha256"] != new.rows[new.manifest["original_member_id"]]["sha256"]:
        problems.append("original SHA-256 differs from the old Bundle (swapped original)")
    receipts = list((published.parent.parent / (published.parent.name + ".logs")).glob(f"{published.name}.receipt"))
    if not receipts:
        problems.append("no export receipt")
    return problems


EXTRA = []


def export(tree: Path, new: Path, pairs_file: Path, key: str, name: str, old_generation: Path, document) -> str:
    out = new / name
    published = [path for path in out.iterdir() if path.is_dir() and not path.name.endswith(".staging")] \
        if out.exists() else []
    if len(published) > 1:
        return f"{key}: FAILED more than one published generation under {out}"
    if not published:
        start = time.time()
        done = subprocess.run(["python3", str(tree / "tools/bundle_export/export_bundle.py"), document["binary"],
                               "--output-root", str(out), "--ghidra", GHIDRA, *replay_args(document), *EXTRA],
                              capture_output=True, text=True)
        if done.returncode != 0:
            return f"{key}: FAILED export rc={done.returncode} {time.time() - start:.0f}s\n  {done.stderr.strip()[-600:]}"
        published = [path for path in out.iterdir() if path.is_dir() and not path.name.endswith(".staging")]
        if len(published) != 1:
            return f"{key}: FAILED no single published generation"
    problems = check(old_generation, published[0])
    if problems:
        return f"{key}: FAILED verification: " + "; ".join(problems[:4])
    with LOCK:
        data = json.loads(pairs_file.read_text()) if pairs_file.exists() else {"pairs": {}}
        data["pairs"][key] = {"name": name, **record(old_generation, published[0])}
        pairs_file.write_text(json.dumps(data, indent=1, sort_keys=True))
    return f"{key}: ok {published[0]}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tree", type=Path)
    parser.add_argument("--old", type=Path, default=Path("/root/tdo_bundles3"))
    parser.add_argument("--new", type=Path, default=Path("/root/tdo_bundles4"))
    parser.add_argument("--pairs", type=Path, default=Path("/root/x1b_pairs.json"))
    parser.add_argument("--only", action="append", default=[])
    parser.add_argument("--jobs", type=int, default=3)
    parser.add_argument("--no-s1-prescript", action="store_true", help="attribution evidence exports")
    args = parser.parse_args()
    if args.no_s1_prescript:
        EXTRA.append("--no-s1-prescript")
    work = [item for item in expected_pairs(args.old) if not args.only or item[1] in args.only or item[0] in args.only]
    failed = 0
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        for line in pool.map(lambda item: export(args.tree, args.new, args.pairs, *item), work):
            print(line, flush=True)
            failed += " ok " not in line
    print(f"REEXPORTDONE {len(work)} expected pairs, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
