"""X-1b H (closed plan r4 4.7): the UE migration outputs from the published UE producer Bundle.
1. the shipped template's v3 stack evidence switch list vs the published Bundle's v5 s3-off switch list;
2. the UE template re-derived under s3-off from the published Bundle (its own sealed evidence, extracted) and
   compared with the shipped template (as tools/gate/check_ue_template.py does).
Run in WSL from the tree: PYTHONPATH=src:tools/bundle_export python x1b_ue_template.py <published gen> <out dir>
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd() / "tools" / "derive_models"))
from derive_models import derive_library  # noqa: E402

GENERATION, OUT = Path(sys.argv[1]), Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)
SHIPPED = json.loads(Path("models/derived/ue_core_win64_fstring.json").read_text(encoding="utf-8"))
OLD_EVIDENCE = Path.home() / "ghidra_link_evidence" / "core.stack.json"

manifest = json.loads((GENERATION / "manifest.json").read_text())
rows = {row["id"]: row for row in manifest["members"]}
evidence_bytes = (GENERATION / rows[manifest["stack_switch_evidence_member"]]["path"]).read_bytes()
evidence_file = OUT / "published.stack.json"
evidence_file.write_bytes(evidence_bytes)
new = json.loads(evidence_bytes)
old = json.loads(OLD_EVIDENCE.read_text())

def switch_keys(items):
    return sorted((item.get("function"), item.get("space_id"), item.get("byte_offset"), item.get("cause"))
                  for item in items)

old_switches = old.get("switches") or []
new_off = new["policies"]["s3-off"]["switches"]
report = {
    "old_evidence": {"file": str(OLD_EVIDENCE), "detector": old.get("detector"), "switches": len(old_switches)},
    "published_evidence": {"detector": new.get("detector"), "s3_off_switches": len(new_off),
                           "s3_on_switches": len(new["policies"]["s3-on"]["switches"])},
    "switch_lists_equal": switch_keys(old_switches) == switch_keys(new_off),
}
names = [entry["name"] for entry in SHIPPED["entries"]]
raw, refused, missing = derive_library(
    GENERATION, SHIPPED["source"]["library"], names, file_id=SHIPPED["id"], version=SHIPPED["version"],
    stack_evidence=[str(evidence_file)], entry_values_not_frame=False, per_export=False, log=lambda line: None)
(OUT / "rederived.json").write_text(json.dumps(raw, indent=1) + "\n", encoding="utf-8")
problems = []
if refused or missing:
    problems.append(f"refused {sorted(refused)} missing {missing}")
for new_entry, old_entry in zip(raw["entries"], SHIPPED["entries"]):
    if new_entry != old_entry:
        problems.append(f"entry {old_entry['name']} differs")
if len(raw["entries"]) != len(SHIPPED["entries"]):
    problems.append("entry count differs")
for key in sorted((set(raw["source"]) | set(SHIPPED["source"])) - {"producer"}):
    if raw["source"].get(key) != SHIPPED["source"].get(key):
        problems.append(f"source.{key} differs")
report["template"] = "identical to the shipped template" if not problems else problems
(OUT / "report.json").write_text(json.dumps(report, indent=1))
print(json.dumps(report, indent=1))
