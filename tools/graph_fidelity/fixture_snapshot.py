"""Semantic snapshots of the large synthetic fixtures (docs 25.30, phase 0).

usage: fixture_snapshot.py <name> <out.json.gz>     (names: tests/intra/large_fixtures.FIXTURES / BEYOND)

Analyzes the fixture alone (``analyze_units``) and records what
semantic_snapshot records per function, plus direct evaluator probes:
``constant_values`` for every (operation, input) and ``register_value_deltas``
for every register definition, each in the forward and the reversed request
order (one projector per call: warm across the requests of one order).
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "intra"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from semantic_snapshot import SNAPSHOT_VERSION, _write, encode  # noqa: E402


def main() -> int:
    import large_fixtures
    from synthetic import program_units
    from tdo_v2.interprocedural import analyze_units
    from tdo_v2.normalize import NormalizedFunction
    from tdo_v2.relative_memory import constant_values, register_value_deltas
    from tdo_v2.span_geometry import StorageObjectKind

    name, out = sys.argv[1], Path(sys.argv[2])
    started = time.time()
    # the probes run outside analyze_units: the same room it gives the evaluator
    from tdo_v2.interprocedural import ANALYSIS_RECURSION_LIMIT

    sys.setrecursionlimit(max(sys.getrecursionlimit(), ANALYSIS_RECURSION_LIMIT))
    builder = large_fixtures.build(name)
    results = analyze_units(program_units(builder))
    sections = {}
    for key, item in sorted(results.items()):
        analyzed = encode(item, key)
        normalized = analyzed.pop("normalized")
        sections[f"function:{key}:normalized"] = normalized
        sections[f"function:{key}:summary"] = analyzed.pop("summary", None)
        sections[f"function:{key}:analyzed"] = analyzed
        normalized_function = item.normalized
        if type(normalized_function) is not NormalizedFunction:
            continue
        observation = item.unit.observation
        inputs = [((f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:{operation.opcode}"), varnode)
                  for row in observation.instructions for ordinal, operation in enumerate(row.operations)
                  for varnode in operation.inputs]
        definitions = [(index, definition.span) for index, definition in enumerate(normalized_function.memory_ssa.definitions)
                       if definition.span.object_id.kind is StorageObjectKind.REGISTER_FILE and definition.span.size == 8]
        for order, sequence in (("forward", inputs), ("reversed", inputs[::-1])):
            found = constant_values(normalized_function, observation, sequence)
            sections[f"probe:{key}:constant_values:{order}"] = encode(
                [[request[0], index, found.get(request)] for index, request in enumerate(sequence)], "constants")
        for order, sequence in (("forward", definitions), ("reversed", definitions[::-1])):
            found = register_value_deltas(normalized_function, observation, sequence)
            sections[f"probe:{key}:register_value_deltas:{order}"] = encode(
                [[index, found.get(request)] for index, request in enumerate(sequence)], "deltas")
    meta = {"snapshot_version": SNAPSHOT_VERSION, "generation": f"fixture:{name}", "config": "fixture",
            "bindings": [], "options": None, "models": None, "python": sys.version.split()[0],
            "seconds": round(time.time() - started, 1)}
    return _write(out, meta, sections, f"{len(results)} functions")


if __name__ == "__main__":
    raise SystemExit(main())
