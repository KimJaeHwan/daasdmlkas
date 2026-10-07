"""Golden snapshots of per-function normalization results (WSL).

usage:
  ssa_snapshot.py dump <generation> <out.json.gz> [--assume-boundary-effects]
  ssa_snapshot.py compare <a.json.gz> <b.json.gz> [--terminal-runs-only]

For every function the session yields, ``dump`` records the full
``LocalMemorySsaResult`` (atoms, definitions, joins, reads, unresolved
occurrences, state nodes, terminal states) plus a dependency-graph summary
(node keys/kinds, edges by endpoint keys and kind/operation/occurrence/span)
and the normalization failure reason if any. ``compare`` reports the first
differences per function; ``--terminal-runs-only`` compares terminal states
as run sequences (tree-shape independent) instead of serialized nodes.
"""

from __future__ import annotations

import argparse
from enum import Enum
import gzip
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
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction  # noqa: E402


def _plain(value):
    """Dataclasses/enums/tuples -> JSON-able, deterministic."""
    if isinstance(value, Enum):
        return _plain(value.value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    if hasattr(value, "__dataclass_fields__"):
        return {name: _plain(getattr(value, name)) for name in value.__dataclass_fields__}
    return repr(value)


def _graph_summary(graph):
    nodes = {}
    for node in range(graph.node_count):
        if graph.has_node(node):
            record = graph.node(node)
            nodes[node] = record.key
    edges = sorted(
        (nodes[source], nodes[target], record.kind, record.operation, record.occurrence,
         None if record.span is None else repr(record.span))
        for source, target, record in graph.weighted_edges()
    )
    kinds = sorted((record.key, str(record.kind)) for record in
                   (graph.node(node) for node in nodes))
    return {"nodes": kinds, "edges": edges}


def dump(args) -> int:
    provider = None
    if args.assume_boundary_effects:
        sys.path.insert(0, str(REPO / "tools" / "bundle_export"))
        import run_dfbench
        from tdo_v2.engine import assumed_boundary_effects
        provider = run_dfbench.boundary_provider(assume_call_effect=True)
    binding = NamingBindingExpectation(
        sha256((REPO / "ghidra" / "GhidraV2CallNaming.java").read_bytes()).digest(),
        CALL_NAMING_GHIDRA_VERSION,
    )
    rows = {}
    with open_observed_function_session(admit_frozen_bundle(Path(args.generation)),
                                        naming_binding=binding) as session:
        for evidence in session.iter_functions():
            entry = hex(evidence.unit.scopes.function.entry.byte_offset)
            assumed = assumed_boundary_effects(evidence, provider) if provider else {}
            result = FunctionNormalizer().normalize(evidence.unit, assumed_call_effects=assumed)
            if type(result) is not NormalizedFunction:
                rows[entry] = {"failure": result.reason.value}
                continue
            rows[entry] = {
                "memory_ssa": _plain(result.memory_ssa),
                "graph": _graph_summary(result.dependencies),
            }
            print(f"[snapshot] {entry}", file=sys.stderr, flush=True)
    with gzip.open(args.out, "wt", encoding="utf-8") as handle:
        json.dump(rows, handle, sort_keys=True)
    print(f"[snapshot] {len(rows)} functions -> {args.out}")
    return 0


def _terminal_runs(ssa):
    nodes = ssa["state_nodes"]

    def walk(node_id, out):
        if node_id is None:
            return
        node = nodes[node_id]
        walk(node["left_node_id"], out)
        out.append((node["start_atom"], node["stop_atom"], tuple(node["definition_ids"])))
        walk(node["right_node_id"], out)

    result = []
    for state in ssa["observed_terminal_states"]:
        runs = []
        walk(state["root_node_id"], runs)
        result.append((state["block_key"], runs))
    return result


def compare(args) -> int:
    with gzip.open(args.a, "rt", encoding="utf-8") as handle:
        a = json.load(handle)
    with gzip.open(args.b, "rt", encoding="utf-8") as handle:
        b = json.load(handle)
    differences = 0
    for entry in sorted(set(a) | set(b)):
        left, right = a.get(entry), b.get(entry)
        if left is None or right is None:
            print(entry, "only in", "b" if left is None else "a")
            differences += 1
            continue
        if "failure" in left or "failure" in right:
            if left != right:
                print(entry, "failure differs", left.get("failure"), right.get("failure"))
                differences += 1
            continue
        fields = []
        for name in sorted(left["memory_ssa"]):
            if args.terminal_runs_only and name in ("state_nodes", "observed_terminal_states"):
                continue
            if left["memory_ssa"][name] != right["memory_ssa"][name]:
                fields.append(name)
        if args.terminal_runs_only and _terminal_runs(left["memory_ssa"]) != _terminal_runs(right["memory_ssa"]):
            fields.append("terminal_runs")
        if left["graph"] != right["graph"]:
            fields.append("graph")
        if fields:
            print(entry, "differs:", fields)
            differences += 1
    print(f"[compare] {len(set(a) | set(b))} functions, {differences} differ")
    return 1 if differences else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("dump")
    d.add_argument("generation")
    d.add_argument("out")
    d.add_argument("--assume-boundary-effects", action="store_true",
                   help="TEST-ONLY special condition: declared boundary call effects")
    c = sub.add_parser("compare")
    c.add_argument("a")
    c.add_argument("b")
    c.add_argument("--terminal-runs-only", action="store_true")
    args = parser.parse_args()
    return dump(args) if args.command == "dump" else compare(args)


if __name__ == "__main__":
    raise SystemExit(main())
