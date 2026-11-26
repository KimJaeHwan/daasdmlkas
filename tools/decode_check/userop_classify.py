"""Classify x86-64 userops from the userop test Bundle (POSIX / WSL, built decoders).

For each test function (one instruction), joins Ghidra's actual row p-code (the CALLOTHER numbers it emitted),
the decoders' results on the verified bytes, and the generator's map. A userop is:
- ``no_flow``: every row that uses it decodes, in every voter and mode, as a valid instruction with no transfer
  (flow "none"), and the row's other flow ops are CONSTANT-destination (intra-instruction) branches only;
- ``flow``: some voter reports a transfer / OS / trap kind for a row that uses it;
- ``privileged``: some row that uses it is privileged or OS-gated per iced's op-code info (is_privileged,
  must_be_cpl0, may_require_cpl0 -- e.g. rdmsr, in / out, and cpuid / rdtsc the OS can make fault): in user-mode
  code the continuation then depends on the OS, so it is never pinned as no-flow (ISA fact annotations, TBR to-do,
  will expose it per row for TDO to decide);
- ``unknown``: invalid, failed or disagreeing decodes, or a row with a real branch besides it;
- ``not_exercised``: no test row uses it (not assembled, prefix / subtable only, or never emitted).
Names come from the Ghidra userop listing (GhidraV2ListUserOps, x86:LE:64:default 4.6).

    PYTHONPATH=src python3 tools/decode_check/userop_classify.py <generation> <map.json> <userops listing> \
        <userops.json> --out classification.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent / "bundle_lint"))

import check  # noqa: E402
import decode_check  # noqa: E402
import decoders  # noqa: E402

LISTING = re.compile(r"USEROP x86:LE:64:default 4\.6 (\d+) (\S+)")


def _privilege(data: bytes, address: int):
    """iced's privilege facts for the instruction at ``data`` (None when it is unprivileged)."""
    import iced_x86

    instr = iced_x86.Decoder(64, data, ip=address).decode()
    code = instr.op_code()
    facts = [name for name in ("is_privileged", "must_be_cpl0", "may_require_cpl0") if getattr(code, name)]
    return facts or None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("generation", type=Path)
    parser.add_argument("map", type=Path)
    parser.add_argument("listing", type=Path)
    parser.add_argument("userops", type=Path)
    parser.add_argument("--binary", type=Path, required=True, help="the test .so (for symbol addresses)")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    names = {int(m.group(1)): m.group(2) for m in LISTING.finditer(args.listing.read_text())}
    test_map = json.loads(args.map.read_text())
    symbols = {}
    for line in subprocess.run(["nm", "-D", "--defined-only", str(args.binary)], capture_output=True,
                               text=True).stdout.splitlines() + \
            subprocess.run(["nm", "--defined-only", str(args.binary)], capture_output=True, text=True).stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in test_map["functions"]:
            symbols[int(parts[0], 16)] = parts[2]
    facts = decode_check.collect(args.generation, _HERE.parents[1] / "ghidra" / "GhidraV2CallNaming.java")
    manifest = json.loads((args.generation / "manifest.json").read_bytes())
    original_path = next(row["path"] for row in manifest["members"] if row["id"] == manifest["original_member_id"])
    original = (args.generation / original_path).read_bytes()
    mapping = check.parse_original(original)
    image = check.Image(args.generation, mapping, facts["image_base"], original)
    bias = facts["image_base"] - mapping.image_base
    per_userop = {}
    rows_seen = 0
    for function in facts["functions"]:
        for row in function["rows"]:
            name = symbols.get(row["address"] - bias)
            if name is None:
                continue
            rows_seen += 1
            window = image.window(row["address"], row["space"])
            ballot = decoders.ballot(window["bytes"], row["address"]) if window["bytes"] else {"intel": (), "amd": ()}
            votes = list(ballot["intel"]) + list(ballot["amd"])
            statuses = sorted({d.status for d in votes})
            flows = sorted({d.flow for d in votes if d.status == "ok"})
            emitted = [op["inputs"][0]["offset"] for op in row["ops"]
                       if op["opcode"] == "CALLOTHER" and op["inputs"] and op["inputs"][0]["kind"] == "CONSTANT"]
            real_branches = [op["opcode"] for op in row["ops"]
                             if op["opcode"] in ("BRANCH", "CBRANCH", "BRANCHIND", "CALL", "CALLIND", "RETURN")
                             and not (op["opcode"] in ("BRANCH", "CBRANCH") and op["inputs"]
                                      and op["inputs"][0]["kind"] == "CONSTANT")]
            privilege = None
            iced = next((d for d in votes if d.voter == "iced" and not d.amd and d.status == "ok"), None)
            if iced is not None:
                info = _privilege(window["bytes"], row["address"])
                if info:
                    privilege = info
            if not votes or statuses != ["ok"] or len(votes) < 5:
                verdict = "unknown"
            elif flows == ["none"] and privilege:
                verdict = "privileged"
            elif flows != ["none"]:
                verdict = "flow"
            elif real_branches:
                verdict = "unknown"
            else:
                verdict = "no_flow"
            for index in emitted:
                item = per_userop.setdefault(index, {"name": names.get(index, f"#{index}"), "rows": []})
                item["rows"].append({"function": name, "line": test_map["functions"][name]["line"],
                                     "verdict": verdict, "flows": flows, "statuses": statuses,
                                     "privilege": privilege,
                                     "real_branches": real_branches})
    result = {}
    for index, item in sorted(per_userop.items()):
        verdicts = {row["verdict"] for row in item["rows"]}
        overall = "flow" if "flow" in verdicts else "unknown" if "unknown" in verdicts else \
            "privileged" if "privileged" in verdicts else "no_flow"
        result[str(index)] = {"name": item["name"], "class": overall, "rows": len(item["rows"]),
                              "examples": item["rows"][:3]}
    declared = json.loads(args.userops.read_text())["usage"]
    by_name = {v: k for k, v in names.items()}
    for userop in declared:
        index = by_name.get(userop)
        if index is not None and str(index) not in result:
            result[str(index)] = {"name": userop, "class": "not_exercised", "rows": 0, "examples": []}
    summary = {}
    for item in result.values():
        summary[item["class"]] = summary.get(item["class"], 0) + 1
    args.out.write_text(json.dumps({"rows_seen": rows_seen, "summary": summary, "userops": result,
                                    "not_assembled": test_map["not_assembled"]}, indent=1, sort_keys=True) + "\n")
    print("rows", rows_seen, "summary", summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
