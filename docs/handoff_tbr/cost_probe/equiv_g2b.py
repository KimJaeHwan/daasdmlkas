"""G2b equivalence against c15a29a (design_tbr_g2b_code_facts r2 E7): usage equiv_g2b.py <base_dir> <new_dir> <name>.

Allowed differences:
- facts file: producer.rule (g2a-3 -> g2b-1) and program.code (U -> the G2b block);
- -5 common_facts block: facts_sha256 only, and it must equal SHA-256 of the new facts file without its single LF;
- evidence outside the block: producer.tool_digest only;
- report header common_facts: the new "code" key only.
"""
import hashlib
import json
import sys
from pathlib import Path

BASE, NEW, NAME = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
ok = True


def check(label, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + label + (f"  {detail}" if detail else ""))


# facts
fb_raw, fn_raw = (BASE / f"{NAME}.facts.json").read_bytes(), (NEW / f"{NAME}.facts.json").read_bytes()
fb, fn = json.loads(fb_raw), json.loads(fn_raw)
check("facts producer.rule g2a-3 -> g2b-1", (fb["producer"]["rule"], fn["producer"]["rule"]) == ("g2a-3", "g2b-1"))
check("base program.code is U", isinstance(fb["program"]["code"], dict) and "unobserved" in fb["program"]["code"])
code = fn["program"]["code"]
check("new program.code present", isinstance(code, dict) and "regions" in code and "sites" in code)
for doc in (fb, fn):
    doc["producer"].pop("rule")
    doc["program"].pop("code")
check("facts otherwise identical (rows, bundle, program, schema, source)", fb == fn,
      ",".join(k for k in fb if fb.get(k) != fn.get(k)))
rows = len(fn["rows"])
del fb, fn

# -5 block
eb = json.loads((BASE / f"{NAME}.evidence5.json").read_bytes())
en = json.loads((NEW / f"{NAME}.evidence5.json").read_bytes())
bb, bn = eb.pop("common_facts"), en.pop("common_facts")
check("new facts file ends with exactly one LF", fn_raw.endswith(b"\n") and not fn_raw.endswith(b"\n\n"))
check("block facts_sha256 = SHA-256(new facts without LF)", bn["facts_sha256"] == hashlib.sha256(fn_raw[:-1]).hexdigest())
check("block otherwise identical", {k: v for k, v in bb.items() if k != "facts_sha256"}
      == {k: v for k, v in bn.items() if k != "facts_sha256"})
check("evidence producer.tool_digest differs (code changed)", eb["producer"].pop("tool_digest") != en["producer"].pop("tool_digest"))
check("evidence outside the block identical", eb == en, ",".join(k for k in eb if eb.get(k) != en.get(k)))
del eb, en

# Compare the complete report. Each side's explicitly requested evidence output
# path is checked before normalizing the two run directories.
rb = json.loads((BASE / f"{NAME}.json").read_bytes())
rn = json.loads((NEW / f"{NAME}.json").read_bytes())
summary = rn["header"]["common_facts"].pop("code", None)
check("new report has G2b summary", isinstance(summary, dict) and summary.get("rule") == "g2b-1")
for directory, report in ((BASE, rb), (NEW, rn)):
    supplied = report["header"].get("evidence_out")
    expected_path = directory / f"{NAME}.evidence5.json"
    check("report evidence output matches requested path",
          isinstance(supplied, str) and Path(supplied).resolve() == expected_path.resolve())
    report["header"]["evidence_out"] = expected_path.name
check("complete report header and rows otherwise identical", rb == rn)
print("SUMMARY", json.dumps({k: summary[k] for k in ("sites", "trap_forms", "import_routes", "rwx_per_api",
                                                     "rows_outside_code", "verified_encoding")}))
print("SURVEY_UNRESOLVED", json.dumps(summary["unresolved"]))
print("SURVEY_UNSUPPORTED", json.dumps(summary["unsupported"]))
print("FACTS_BYTES", len(fb_raw), len(fn_raw), f"{100 * (len(fn_raw) - len(fb_raw)) / len(fb_raw):+.1f}%", "rows", rows)
print("RESULT", "PASS" if ok else "FAIL")
raise SystemExit(0 if ok else 1)
