"""Platform parity: the same code's outputs from the office (WSL x86-64) and this machine must match.

usage: parity_check.py <office_dir> <this_dir> <name>
Allowed differences: the decoder build digests (libraries are rebuilt per platform) and output paths.
On a facts mismatch the first differing row is printed with its key, to start the investigation there.
"""
import hashlib
import json
import sys
from pathlib import Path

OFFICE, HERE, NAME = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
ok = True


def check(label, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + label + (f"  {detail}" if detail else ""))


def strip_decoders(x):
    """Drop library / build digests anywhere under a 'decoders' key; keep versions, voters and commits."""
    if isinstance(x, dict):
        out = {}
        for k, v in x.items():
            # (per-platform build artefacts: the decoder libraries and the iced wheel RECORD; sources and commits
            #  stay compared) and output paths
            if k in ("library_sha256", "libxed_sha256", "record_sha256", "evidence_out"):
                continue
            out[k] = strip_decoders(v)
        return out
    if isinstance(x, list):
        return [strip_decoders(v) for v in x]
    return x


fo, fh = (OFFICE / f"{NAME}.facts.json").read_bytes(), (HERE / f"{NAME}.facts.json").read_bytes()
same = hashlib.sha256(fo).digest() == hashlib.sha256(fh).digest()
check("facts file byte-identical", same)
if not same:
    a, b = json.loads(fo), json.loads(fh)
    for key in sorted(set(a) | set(b)):
        if key != "rows" and a.get(key) != b.get(key):
            print("   differs at top-level key", key)
    for i, (ra, rb) in enumerate(zip(a["rows"], b["rows"])):
        if ra != rb:
            print("   first differing row", i, ra.get("id"), ra.get("observation"))
            for k in sorted(set(ra) | set(rb)):
                if ra.get(k) != rb.get(k):
                    print("     field", k, json.dumps(ra.get(k))[:200], "|", json.dumps(rb.get(k))[:200])
            break
    if len(a["rows"]) != len(b["rows"]):
        print("   row counts", len(a["rows"]), len(b["rows"]))

eo = json.loads((OFFICE / f"{NAME}.evidence5.json").read_bytes())
eh = json.loads((HERE / f"{NAME}.evidence5.json").read_bytes())
check("-5 common_facts block identical", eo.pop("common_facts") == eh.pop("common_facts"))
check("evidence identical except decoder build digests", strip_decoders(eo) == strip_decoders(eh))

ro = json.loads((OFFICE / f"{NAME}.json").read_bytes())
rh = json.loads((HERE / f"{NAME}.json").read_bytes())
check("report rows identical", ro["rows"] == rh["rows"])
check("report header identical except decoder build digests / paths",
      strip_decoders(ro["header"]) == strip_decoders(rh["header"]),
      ",".join(k for k in ro["header"] if strip_decoders(ro["header"].get(k)) != strip_decoders(rh["header"].get(k))))
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
