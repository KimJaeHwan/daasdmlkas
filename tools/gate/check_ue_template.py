"""Gate step (local, this machine): re-derive the shipped UE template with the
tree under test and compare it with models/derived/ue_core_win64_fstring.json.

usage (in the tree): PYTHONPATH=src:tools/bundle_export python tools/gate/check_ue_template.py <out.json>
Prints UETEMPLATE OK (exit 0), or UETEMPLATE STALE with what differs /
UETEMPLATE UNVERIFIABLE (exit 1). Inputs: the Bundle the template names (producer.bundle) under
$TDO_BUNDLES/ue-core-probe, the stack evidence $TDO_EVIDENCE/core.stack.json (tools/gate/env.sh), frame off."""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd() / "tools" / "derive_models"))
from derive_models import derive_library  # noqa: E402

HOME = Path.home()
DATA = Path(os.environ.get("TDO_DATA", HOME))
BUNDLES = Path(os.environ.get("TDO_BUNDLES", DATA / "tdo_bundles3"))
EVIDENCE = str(Path(os.environ.get("TDO_EVIDENCE", DATA / "ghidra_link_evidence")) / "core.stack.json")
SHIPPED = Path("models/derived/ue_core_win64_fstring.json")

shipped = json.loads(SHIPPED.read_text(encoding="utf-8"))
producer = shipped["source"].get("producer", {}).get("bundle")
BUNDLE = str(BUNDLES / "ue-core-probe" / str(producer))
if not producer or not Path(BUNDLE).is_dir():
    print(f"UETEMPLATE UNVERIFIABLE: the shipped template's Bundle ({producer}) is not under {BUNDLES / 'ue-core-probe'}")
    sys.exit(1)
if not Path(EVIDENCE).is_file():
    print(f"UETEMPLATE UNVERIFIABLE: no stack evidence {EVIDENCE}")
    sys.exit(1)
names = [entry["name"] for entry in shipped["entries"]]
raw, refused, missing = derive_library(
    Path(BUNDLE), shipped["source"]["library"], names, file_id=shipped["id"], version=shipped["version"],
    stack_evidence=[EVIDENCE], entry_values_not_frame=False, per_export=False, log=lambda line: None)
Path(sys.argv[1]).write_text(json.dumps(raw, indent=1) + "\n", encoding="utf-8")
problems = []
if refused or missing:
    problems.append(f"refused {sorted(refused)} missing {missing}")
for new, old in zip(raw["entries"], shipped["entries"]):
    if new != old:
        problems.append(f"entry {old['name']} differs")
if len(raw["entries"]) != len(shipped["entries"]):
    problems.append("entry count differs")
for key in sorted((set(raw["source"]) | set(shipped["source"])) - {"producer"}):   # (producer: recorded only)
    if raw["source"].get(key) != shipped["source"].get(key):
        problems.append(f"source.{key} differs")
print("UETEMPLATE OK" if not problems else "UETEMPLATE STALE: " + "; ".join(problems))
sys.exit(1 if problems else 0)
