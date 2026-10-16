"""Operation records of one function's outputs (docs 25.28), from a Bundle (WSL).

usage: derivations.py <generation> --function <entry> [--exit] [--json out] [--models]

``--function``: the entry offset in hex (``140001aa0``) or a function key
(``1b1:140001aa0``); ``--list`` prints the function keys. Analyzes the Bundle
with callee summaries (as the runs do: import-slots-hold-their-exports on,
models with ``--models``) and prints, for every normal exit of the function,
each output run's record: the operations its value went through, over the
function's entry registers and entry memory. The use: a handler function's
semantics (e.g. a VM handler: its outputs as expressions over the context it
receives). Diagnostics only.
"""

from __future__ import annotations

import argparse
import json
import sys
from hashlib import sha256
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

from tdo_v2.configured_naming_contracts import (  # noqa: E402
    CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation,
)
from tdo_v2.integration.configured_bundle import admit_frozen_bundle  # noqa: E402
from tdo_v2.integration.observed_function_session import open_observed_function_session  # noqa: E402
from tdo_v2.interprocedural import analyze_units  # noqa: E402
from tdo_v2.operation_records import Limits, render, run_records  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("generation", type=Path)
    parser.add_argument("--function")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--exit", help="only this exit block key")
    parser.add_argument("--json", type=Path)
    parser.add_argument("--models", action="store_true", help="apply the external models (models/external)")
    parser.add_argument("--max-nodes", type=int, default=Limits.nodes)
    args = parser.parse_args()
    binding = NamingBindingExpectation(
        sha256((REPO / "ghidra" / "GhidraV2CallNaming.java").read_bytes()).digest(),
        CALL_NAMING_GHIDRA_VERSION,
    )
    with open_observed_function_session(admit_frozen_bundle(args.generation), naming_binding=binding) as session:
        units = [evidence.unit for evidence in session.iter_functions()]
    options = {"assume_import_slots_hold_exports": True}
    if args.models:
        sys.path.insert(0, str(REPO / "tools" / "bundle_export"))
        import run_dfbench
        from tdo_v2.image_info import load_image_info

        options.update(image_info=load_image_info(args.generation),
                       external_models=run_dfbench.external_models(args.generation),
                       pcodeop_models=run_dfbench.pcodeop_models())
    results = analyze_units(units, **options)
    if args.list or not args.function:
        for key in sorted(results):
            print(key)
        return 0
    wanted = args.function.lower()
    matches = [key for key in results if key == wanted or key.split(":", 1)[-1] == wanted.removeprefix("0x")]
    if len(matches) != 1:
        print(f"no single function {args.function!r}: {matches or 'none'} (--list)", file=sys.stderr)
        return 1
    analyzed = results[matches[0]]
    if analyzed.summary is None:
        print(f"{matches[0]}: no summary (the function did not normalize)", file=sys.stderr)
        return 1
    records = [record for record in run_records(analyzed.normalized, analyzed.unit, analyzed.summary,
                                                origins=analyzed.origins, declared=analyzed.declared,
                                                limits=Limits(nodes=args.max_nodes))
               if args.exit is None or record.get("exit") == args.exit]
    for record in records:
        if record.get("run_kind") == "identity":
            continue
        print(render(record))
        print()
    if args.json:
        args.json.write_text(json.dumps(records, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
