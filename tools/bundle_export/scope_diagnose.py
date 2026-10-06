#!/usr/bin/env python3
"""List the scope-construction result of every Bundle function (no naming).

ObservedFunctionSession raises "observed function scope could not be
constructed" and kills its iterator on the first UnresolvedFunctionScope;
this diagnostic drives the lower configured-extraction envelope directly so
every function's ScopeConstructionReason is visible.  POSIX/WSL only.

  ~/venvs/tdo/bin/python tools/bundle_export/scope_diagnose.py <generation>
"""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import sys


def main() -> int:
    from tdo_v2._configured_bundle_reader import read_configured_bundle
    from tdo_v2._scope_contracts import _mint_orchestrator_capability
    from tdo_v2.integration.configured_bundle import admit_frozen_bundle
    from tdo_v2.scope_identity import open_configured_extraction

    generation = Path(sys.argv[1])
    manifest = json.loads((generation / "manifest.json").read_text(encoding="utf-8"))
    entries = []
    for row in manifest["functions"]:
        data = json.loads((generation / f"{row['observation_member']}.json").read_text())
        entry = data.get("entry", {})
        entries.append((row["id"], entry.get("space_id"), entry.get("byte_offset"),
                        len(data.get("instructions", []))))

    provider = read_configured_bundle(admit_frozen_bundle(str(generation)))
    reasons: Counter[str] = Counter()
    with open_configured_extraction(provider, _mint_orchestrator_capability()) as envelope:
        print("program:", type(envelope.program_result).__name__,
              getattr(envelope.program_result, "reason", ""))
        for index, unit in enumerate(envelope.iter_scoped_functions()):
            function = unit.scopes.function
            kind = type(function).__name__
            if kind != "ConstructedFunctionScope":
                member, space, offset, count = entries[index]
                reason = f"{function.stage.value}/{function.reason.value}"
                reasons[reason] += 1
                print(f"  [{index}] {member} entry={space}:{offset:#x} "
                      f"instructions={count}: {reason}")
            else:
                reasons["constructed"] += 1
    print(dict(reasons))
    return 0


if __name__ == "__main__":
    sys.exit(main())
