"""X-1b stages 0 and 1 for one pair (design_x1b_method_r3): derive the comparison copy from the published Bundle,
strip it relative to the old input (the control), build one copy per feature group, compare members, dump paired
snapshots (default + legacy) and compare strictly and through the coordinate projection. Run in WSL with the tdo
venv; results go to <out>/<pair>/result.json.

usage: x1b_stages.py <tree> <pairs.json> <pair key> [--out /root/x1b_runs] [--configs default,legacy] [--jobs N]
"""
import argparse
import concurrent.futures
from contextlib import redirect_stdout
from io import StringIO
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import x1b_bundle_tools as tools  # noqa: E402

# (proof_input / exception_handlers need S1 and row lengths: the proof effect is s1+fte+len+proof against
# s1+fte+len)
GROUPS = {"s1+fte": ("s1", "fte"), "s1+fte+len": ("s1", "fte", "len"), "s1+fte+len+proof": ("s1", "fte", "len", "proof"),
          "reg": ("reg",), "len": ("len",), "x1+len": ("x1", "len")}
PY = sys.executable


def digests(path: Path) -> dict:
    return {"manifest_sha256": tools.sha((path / "manifest.json").read_bytes()),
            "seal_sha256": tools.sha((path / "seal.json").read_bytes())}


def dump(tree: Path, generation: Path, out: Path, config: str) -> str:
    if out.exists():
        return f"{out.name}: cached"
    start = time.time()
    done = subprocess.run(["timeout", "3600", PY, "tools/graph_fidelity/semantic_snapshot.py", "dump", str(generation),
                           str(out), "--config", config, "--paired-sections"], cwd=tree,
                          env={**os.environ, "PYTHONPATH": "src", "PYTHONHASHSEED": "0"}, capture_output=True, text=True)
    if done.returncode != 0:
        out.with_suffix(".failed").write_text(done.stdout[-3000:] + done.stderr[-3000:])
        return f"{out.name}: FAILED rc={done.returncode}"
    return f"{out.name}: {time.time() - start:.0f}s"


def compare(comparison, pair: dict, left: Path, right: Path, projected: bool) -> dict:
    with redirect_stdout(StringIO()) as output:
        try:
            rc = comparison.compare(left, right, pair, projected)
        except Exception as error:
            # A failed comparison must leave a result and allow the next pair to run.
            rc = 2
            print(f"[compare] {left.name} vs {right.name}: {type(error).__name__}: {error}")
    lines = output.getvalue().strip().splitlines()
    return {"rc": rc, "summary": lines[-1] if lines else "",
            "differences": [line for line in lines[:-1]][:40]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tree", type=Path)
    parser.add_argument("pairs", type=Path)
    parser.add_argument("key")
    parser.add_argument("--out", type=Path, default=Path("/root/x1b_runs"))
    parser.add_argument("--configs", default="default,legacy")
    parser.add_argument("--jobs", type=int, default=3)
    parser.add_argument("--compare-only", action="store_true",
                        help="reuse the copies, pair records and dumps of an earlier run; redo the comparisons only")
    args = parser.parse_args()
    pair = json.loads(args.pairs.read_text())["pairs"][args.key]
    old, published = Path(pair["old"]["path"]), Path(pair["published"]["path"])
    work = args.out / args.key.replace("/", "_").replace("#", "@")
    work.mkdir(parents=True, exist_ok=True)
    result = {"key": args.key, "old": str(old), "published": str(published), "stage0": {}, "stage1": {}}

    if args.compare_only:
        previous = json.loads((work / "result.json").read_text())
        result["stage0"]["members"] = previous["stage0"]["members"]
        local_pairs = work / "pairs.json"
        comparisons = [("stage0", "old", "control")] + [("stage1", "control", group) for group in GROUPS] +                       [("stage1", "s1+fte+len", "s1+fte+len+proof"), ("cut", "old", "published")]
        return finish(args, work, result, local_pairs, comparisons)
    # copies: derived (old id) -> control (all additions the old input lacks removed) -> one copy per group
    derived = tools.derive(published, work / "derived", old.name)
    control = tools.strip(derived, work / "control", old)
    copies = {"control": control, "published": published, "old": old}
    for group, keep in GROUPS.items():
        copies[group] = tools.strip(derived, work / f"g_{group}", old, set(keep))
    result["stage0"]["members"] = tools.members(old, control)

    # local pair records for the comparisons (left / right inputs named by their digests)
    local = {"pairs": {}}
    comparisons = [("stage0", "old", "control")] + [("stage1", "control", group) for group in GROUPS] + \
                  [("stage1", "s1+fte+len", "s1+fte+len+proof"), ("cut", "old", "published")]
    for _, left, right in comparisons:
        local["pairs"][f"{left}~{right}"] = {"left": digests(copies[left]), "right": digests(copies[right])}
    local_pairs = work / "pairs.json"
    local_pairs.write_text(json.dumps(local, indent=1))

    configs = args.configs.split(",")
    dumps = [(name, path, config) for name, path in copies.items() for config in configs]
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        for line in pool.map(lambda item: dump(args.tree, item[1], work / f"{item[0]}.{item[2]}.json.gz", item[2]),
                             dumps):
            print(f"[{args.key}] {line}", flush=True)
    return finish(args, work, result, local_pairs, comparisons)


def finish(args, work, result, local_pairs, comparisons) -> int:
    sys.path.insert(0, str(args.tree.resolve() / "tools" / "graph_fidelity"))
    from semantic_snapshot import PairedComparison

    configs = args.configs.split(",")
    pairs = json.loads(local_pairs.read_text())["pairs"]
    for config in configs:
        with PairedComparison() as comparison:
            for stage, left, right in comparisons:
                key = f"{left}~{right}"
                a, b = work / f"{left}.{config}.json.gz", work / f"{right}.{config}.json.gz"
                entry = {"strict": None, "projected": None}
                if a.exists() and b.exists():
                    entry["strict"] = compare(comparison, pairs[key], a, b, False)
                    entry["projected"] = compare(comparison, pairs[key], a, b, True)
                else:
                    entry["missing"] = [str(path) for path in (a, b) if not path.exists()]
                target = result["stage0"] if stage == "stage0" else result["stage1"] if stage == "stage1" else result
                target.setdefault(key, {})[config] = entry
    (work / "result.json").write_text(json.dumps(result, indent=1))
    ok = not result["stage0"]["members"] and all(
        entry.get("strict", {}) and entry["strict"]["rc"] == 0
        for entry in result["stage0"]["old~control"].values())
    print(f"STAGESDONE {args.key} stage0={'identical' if ok else 'DIFFERS'} -> {work / 'result.json'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
