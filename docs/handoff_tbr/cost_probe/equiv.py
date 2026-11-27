"""E1 / E2 / E4 (design_tbr_g2a_cost r1 s4, r2 D3-D4): compare a new run (-5) with the 798b903 oracle run (-4).

usage: equiv.py <wt_new> <oracle_dir> <new_dir> <name>
"""
import hashlib
import json
import sys
from pathlib import Path

WT, ORACLE, NEW, NAME = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]
sys.path[:0] = [str(WT / "tools/decode_check")]
import common_facts as cf  # noqa: E402

ok = True


def check(label, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + label + (f"  {detail}" if detail else ""))


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


# E4: facts file bytes and the block digest (LF excluded)
fo, fn = ORACLE / f"{NAME}.facts.json", NEW / f"{NAME}.facts.json"
check("E4 facts file sha", sha(fo) == sha(fn), sha(fn))
eo = json.loads((ORACLE / f"{NAME}.evidence4.json").read_bytes())
en = json.loads((NEW / f"{NAME}.evidence5.json").read_bytes())
bo, bn = eo["common_facts"], en["common_facts"]
body = fn.read_bytes()
check("E4 block facts_sha256 == SHA256(file without LF)",
      bo["facts_sha256"] == bn["facts_sha256"] == hashlib.sha256(body[:-1]).hexdigest() and body.endswith(b"\n"))
check("E4 row_set_sha256", bo["row_set_sha256"] == bn["row_set_sha256"])
check("-5 schema / rule", (en["schema"], bn["schema"], bn["rule_version"])
      == ("g1-decode-evidence-5", cf.VERDICT_SCHEMA2, cf.VERDICT_RULE))

# E1: -5 expanded == oracle -4 rows (row refs, unit order, selectors, codes, state)
expanded = cf.expand_block5(bn)
check("E1 rows count", len(expanded) == len(bo["rows"]), f"{len(expanded)} rows, {len(bn['unit_sets'])} sets")
same = sum(a == b for a, b in zip(expanded, bo["rows"]))
check("E1 expanded rows equal", same == len(bo["rows"]), f"{same}/{len(bo['rows'])}")
del expanded

# rest of the evidence document unchanged (only schema and the common_facts block differ)
rest_o = {k: v for k, v in eo.items() if k not in ("schema", "common_facts")}
rest_n = {k: v for k, v in en.items() if k not in ("schema", "common_facts")}
# (the producer's tool_digest is the digest of the tool's own code, which this change edits: expected difference)
check("producer.tool_digest differs (code changed)", rest_o["producer"].pop("tool_digest") != rest_n["producer"].pop("tool_digest"))
check("evidence outside common_facts equal", rest_o == rest_n,
      ",".join(k for k in rest_o if rest_o.get(k) != rest_n.get(k)))
del eo, en

# E2: the whole report common_facts header; rule is the one named difference (r2 D3)
ho = json.loads((ORACLE / f"{NAME}.json").read_bytes())["header"]["common_facts"]
hn = json.loads((NEW / f"{NAME}.json").read_bytes())["header"]["common_facts"]
check("E2 oracle rule", ho["rule"] == "g2a-3")
check("E2 complete common_facts header", cf.canonical(hn) == cf.canonical(dict(ho, rule="g2a-4")),
      ",".join(k for k in sorted(set(ho) | set(hn)) if k != "rule" and ho.get(k) != hn.get(k)))
print("unit_sets", len(bn["unit_sets"]))

if NAME == "zlib":
    facts = json.loads(body)
    canonical = cf.canonical(facts)
    check("D3 facts producer rule", facts["producer"]["rule"] == "g2a-3")
    check("D4 canonical file plus LF", body == canonical + b"\n")
    check("D4 canonical block digest", bn["facts_sha256"] == hashlib.sha256(canonical).hexdigest())

print("RESULT", "PASS" if ok else "FAIL")
raise SystemExit(0 if ok else 1)
