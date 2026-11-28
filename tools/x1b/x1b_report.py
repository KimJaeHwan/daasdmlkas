"""X-1b report (design_x1b_method_r3 sections 2, 3, E, H): one markdown table from /root/x1b_runs/*/result.json plus
the interaction set per pair (section level: D(full) vs the union of the single-group D(g), both directions, from
the projected snapshots). Run in WSL with the tdo venv.

usage: x1b_report.py [--runs /root/x1b_runs] [--tree <wt_x1b>] > report.md
"""
import argparse
import json
import sys
from pathlib import Path

# stage-0 member differences attributed to a listed producer change, with the evidence that ties them to it
ATTRIBUTED = {
    "image-info: $.exports.length": "S1 pre-script: three IMPORTED data labels (.bss / __DTOR_LIST__ / __CTOR_LIST__) "
                                    "leave the external entry points (plain import 63 exports, with the pre-script 60: "
                                    "tools/x1b/DumpExports.java)",
}
GROUPS = ("s1+fte", "s1+fte+len", "s1+fte+len+proof", "reg", "len", "x1+len")
# whole-pair stage-0 attribution from the evidence exports (export_bundle --no-s1-prescript, /root/x1b_attr): the
# re-export without S1's pre-script, stripped, equals the old Bundle (zlib, v2) or equals it for every old function by
# entry with only single-row internal thunks added (v3: G-T G2 ea1a058)
PAIR_ATTRIBUTION = {
    "zlib": "S1 pre-script: no-prescript export stripped == old (members)",
    "v2-win-debug-full": "S1 pre-script: no-prescript export stripped == old (members)",
    "v3-win-release-full": "S1 pre-script + G-T G2 internal thunks (+6 single-row BRANCH functions); every old "
                           "function identical by entry without the pre-script",
    "v3-win32-release-full": "S1 pre-script + G-T G2 internal thunk (+1 single-row BRANCH function); every old "
                             "function identical by entry without the pre-script",
}


def short(entry):
    if entry is None:
        return "skip"   # (legacy not run on this pair: owner 2026-11-27)
    if not entry.get("strict"):
        return "missing"
    strict, projected = entry["strict"]["summary"], entry["projected"]["summary"]
    def word(line):
        return "=" if "identical" in line else line.split(":")[-1].strip().split(" (")[0] if "differ" in line else "ERR"
    return f"{word(strict)} / {word(projected)}"


def projected_sections(path: Path, project):
    from paired_projection import Ambiguous
    from snapshot_sections import open_snapshot

    with open_snapshot(path) as snapshot:
        try:
            return project(snapshot)
        except Ambiguous as error:
            raise Ambiguous(f"{path.name}: {error}") from error


def interaction(work: Path, config: str, project):
    files = {name: work / f"{name}.{config}.json.gz" for name in ("control", "published", *GROUPS)}
    if not all(path.exists() for path in files.values()):
        return None
    digests = {name: projected_sections(path, project) for name, path in files.items()}
    def delta(name):
        return {section for section in digests["control"]
                if digests["control"][section] != digests[name].get(section)} | \
               (set(digests[name]) - set(digests["control"]))
    union = set().union(*(delta(group) for group in GROUPS))
    full = delta("published")
    return {"full_only": sorted(full - union), "groups_only": sorted(union - full), "full": len(full),
            "union": len(union)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=Path, default=Path("/root/x1b_runs"))
    parser.add_argument("--tree", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--no-interaction", action="store_true")
    args = parser.parse_args()
    sys.path.insert(0, str(args.tree / "src"))
    sys.path.insert(0, str(args.tree / "tools" / "graph_fidelity"))
    from paired_projection import Ambiguous, project_snapshot

    print("| pair | stage 0 members | stage 0 default / legacy | " +
          " | ".join(GROUPS) + " | proof effect | old vs published | interaction (default) |")
    print("|---" * (6 + len(GROUPS)) + "|")
    notes = []
    status = 0
    for path in sorted(args.runs.glob("*/result.json")):
        result = json.loads(path.read_text())
        work = path.parent
        members = result["stage0"]["members"]
        pair_reason = PAIR_ATTRIBUTION.get(result["key"].split("#")[0])
        unexplained = [] if pair_reason else             [item for item in members if not any(item.startswith(key) for key in ATTRIBUTED)]
        attributed = [item for item in members if item not in unexplained]
        member_cell = "=" if not members else (f"{len(attributed)} attributed" if not unexplained
                                               else f"**{len(unexplained)} unexplained**")
        if unexplained:
            notes.append(f"- {result['key']}: unexplained stage-0 member differences: {unexplained[:5]}")
        stage0 = result["stage0"].get("old~control", {})
        s0 = " / ".join(("skip" if c not in stage0 else
                         "=" if ((stage0.get(c) or {}).get("strict") or {}).get("rc") == 0 else "**DIFF**")
                        for c in ("default", "legacy"))
        cells = []
        for group in GROUPS:
            entry = result["stage1"].get(f"control~{group}", {})
            cells.append(" ; ".join(f"{c[0]}:{short(entry.get(c))}" for c in ("default", "legacy")))
        proof = result["stage1"].get("s1+fte+len~s1+fte+len+proof", {})
        proof_cell = " ; ".join(f"{c[0]}:{short(proof.get(c))}" for c in ("default", "legacy"))
        cut = result.get("old~published", {})
        cut_cell = " ; ".join(f"{c[0]}:{short(cut.get(c))}" for c in ("default", "legacy"))
        inter = None
        inter_cell = "-"
        if not args.no_interaction:
            try:
                inter = interaction(work, "default", project_snapshot)
                inter_cell = "=" if inter is not None else "missing"
            except Ambiguous as error:
                inter_cell = "**incomplete**"
                notes.append(f"- {result['key']} interaction: {error}")
                status = 2
        if inter and (inter["full_only"] or inter["groups_only"]):
            inter_cell = f"**full-only {len(inter['full_only'])}, groups-only {len(inter['groups_only'])}**"
            notes.append(f"- {result['key']}: interaction: full-only {inter['full_only'][:6]}, "
                         f"groups-only {inter['groups_only'][:6]}")
        for name, entry in [("stage1 " + g, result["stage1"].get(f"control~{g}", {})) for g in GROUPS] + \
                           [("proof", proof), ("old vs published", cut)]:
            for config, item in entry.items():
                if item.get("projected") and item["projected"]["rc"] != 0:
                    details = item["projected"]["differences"] or [item["projected"]["summary"]]
                    notes.append(f"- {result['key']} {name} {config}: " +
                                 "; ".join(line[:220] for line in details[:4]))
        print(f"| {result['key']} | {member_cell} | {s0} | " + " | ".join(cells) +
              f" | {proof_cell} | {cut_cell} | {inter_cell} |")
    print("\nCells: strict / projected per config (d = default, l = legacy); '=' identical, a number = sections "
          "differing; 'skip' = legacy not run (owner 2026-11-27: the legacy engine runs only on the corpus and on the "
          "Bundles the gate snapshots in legacy -- v2-win-debug-full, v3-win-release-full; zlib legacy takes over "
          "an hour per snapshot and is not in the gate). Attributed stage-0 member differences:")
    for key, reason in ATTRIBUTED.items():
        print(f"- `{key}`: {reason}")
    for key, reason in PAIR_ATTRIBUTION.items():
        print(f"- pair `{key}`: {reason}")
    if notes:
        print("\nDifferences to explain:")
        print("\n".join(notes))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
