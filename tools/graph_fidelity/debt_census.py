"""Which debts keep summary-engine roots unsure (WSL).

usage: debt_census.py <generation> [--assume-boundary-effects]
For every sink root of the summary engine, lists the debt node kinds its
slice reaches and, for may-alias debts, what kind of writer causes them
(the function's own unknown-address write, a summarized call effect, an
ordinary write). Prints a histogram over roots.
"""

from __future__ import annotations

import argparse
import collections
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "bundle_export"))

import run_dfbench  # noqa: E402
import tdo_v2.interprocedural as interprocedural  # noqa: E402
from tdo_v2 import summary_engine  # noqa: E402
from tdo_v2.graph_contracts import NodeKind  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("generation", type=Path)
    parser.add_argument("--assume-boundary-effects", action="store_true")
    args = parser.parse_args()
    captured = {}
    original = interprocedural.analyze_units

    def spy(*items, **options):
        captured["results"] = original(*items, **options)
        return captured["results"]

    summary_engine.analyze_units = spy
    run = summary_engine.analyze_frozen_bundle_with_summaries(
        args.generation,
        naming_exporter_source=REPO / "ghidra" / "GhidraV2CallNaming.java",
        boundary_provider=run_dfbench.boundary_provider(
            args.assume_boundary_effects, run_dfbench.abi_of(args.generation)),
        assume_boundary_call_effects=args.assume_boundary_effects,
    )
    by_entry = {
        (item.unit.scopes.function.entry.space_id, item.unit.scopes.function.entry.byte_offset): item
        for item in captured["results"].values()
    }
    histogram = collections.Counter()
    unsure = 0
    for root in run.roots:
        if root.is_effectively_complete:
            continue
        unsure += 1
        item = by_entry[(root.function_space_id, root.function_byte_offset)]
        normalized = item.normalized
        graph = normalized.dependencies
        reachable = graph.backward_reachable(root.root_nodes)
        unknown_writers = {e.operation_key for e in normalized.effects
                           if e.memory_write is not None or e.unresolved_writes}
        alias_rows = {row.operation_key: row for row in normalized.may_alias_reads}
        kinds = set()
        for node in reachable:
            record = graph.node(node)
            if record.kind is not NodeKind.MEMORY_DEBT:
                continue
            if record.label == "may_alias_read":
                for reader, row in alias_rows.items():
                    for writer in row.writers:
                        if writer in unknown_writers:
                            kinds.add("may_alias:own unknown-address write" if "~" not in writer
                                      else "may_alias:unresolved call effect")
                        elif "~" in writer:
                            kinds.add("may_alias:summarized call write")
                        else:
                            kinds.add("may_alias:ordinary write")
            else:
                kinds.add(record.label)
        if root.local_completeness.unbound_roots:
            kinds.add("unbound root")
        for kind in kinds or {"(other)"}:
            histogram[kind] += 1
    print(f"roots={len(run.roots)} unsure={unsure}")
    for kind, count in histogram.most_common():
        print(f"  {count:4}  {kind}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
