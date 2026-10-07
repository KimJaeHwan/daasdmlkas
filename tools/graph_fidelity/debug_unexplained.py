"""Debug one function's unexplained / missing dependencies (WSL).

usage: debug_unexplained.py <generation> <entry-hex> [--assume-boundary-effects]
Re-runs the oracle like measure_bundle.py and prints, per unexplained or
missing dependency, the reader, byte, writer, and how the writer produced
that byte (the operation that wrote it in the run).
"""

from __future__ import annotations

import random
import sys
from hashlib import sha256
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "intra"))
sys.path.insert(0, str(REPO / "tools" / "graph_fidelity"))

import pcode_interpreter  # noqa: E402
from graph_oracle import check  # noqa: E402
from measure_bundle import image_reader, stack_pointer  # noqa: E402
from tdo_v2.configured_naming_contracts import (  # noqa: E402
    CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation,
)
from tdo_v2.integration.configured_bundle import admit_frozen_bundle  # noqa: E402
from tdo_v2.integration.observed_function_session import open_observed_function_session  # noqa: E402
from tdo_v2.normalize import FunctionNormalizer  # noqa: E402

writes_log: list = []
_original_write = pcode_interpreter.Interpreter._write


def _logged_write(self, writer, space_id, offset, size, value):
    writes_log.append((writer, space_id, offset, size))
    return _original_write(self, writer, space_id, offset, size, value)


pcode_interpreter.Interpreter._write = _logged_write


def main() -> int:
    generation, entry = Path(sys.argv[1]), int(sys.argv[2], 16)
    binding = NamingBindingExpectation(
        sha256((REPO / "ghidra" / "GhidraV2CallNaming.java").read_bytes()).digest(),
        CALL_NAMING_GHIDRA_VERSION,
    )
    image = image_reader(generation)
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        spaces = session.program_result.evidence.address_spaces
        const = next(row.space_id for row in spaces if row.is_constant_space)
        regs = next(row.space_id for row in spaces if row.is_register_space)
        unique = next(row.space_id for row in spaces if row.is_unique_space)
        for evidence in session.iter_functions():
            if evidence.unit.scopes.function.entry.byte_offset != entry:
                continue
            observation = evidence.unit.observation
            normalized = FunctionNormalizer().normalize(evidence.unit)
            sp_offset, sp_size = stack_pointer(observation, regs, (0x20, 8))

            def pool(seed):
                rng = random.Random(seed)
                base = rng.choice((0x7FFF_1000, 0x7FFF_1008, 0x5000_0000))
                values = {reg: rng.choice((base, base + 8, base + 0x40, rng.getrandbits(31)))
                          for reg in range(0, 0x40, 8)}
                values[sp_offset] = 0x7000_0000
                return values

            for seed in range(6):
                writes_log.clear()
                report = check(normalized, observation, seeds=[seed], register_pools=pool,
                               spaces=(const, regs, unique), havoc_calls=(regs, sp_offset, sp_size),
                               image=image)
                for item in (report.silent + report.covered_by_debt)[:3]:
                    dependency = item[0] if isinstance(item, tuple) else item
                    print("seed", seed, item)
                    call_prefix = dependency.writer.rsplit(":", 2)[0] if isinstance(dependency.writer, str) else ""
                    hits = [w for w in writes_log if (w[0] == dependency.writer or (call_prefix and w[0].startswith(call_prefix)))
                            and w[1] == dependency.space_id
                            and w[2] <= dependency.offset < w[2] + w[3]]
                    print("   writer wrote it via", [(w[0], hex(w[2]), w[3]) for w in hits[:3]])
                    describe_reader(normalized, dependency.reader)
                    print("   all writes of that instruction", [(w[0], w[1], hex(w[2]), w[3]) for w in writes_log if call_prefix and w[0].startswith(call_prefix)][:6])
            return 0
    return 1


def describe_reader(normalized, reader: str) -> None:
    """Print the graph's incoming edges of one reader operation."""
    graph = normalized.dependencies
    node = graph.node_for_key(f"op:{reader}")
    print("reader node", node)
    if node is None:
        return
    for source, _, record in graph._graph.in_edges(node):
        item = graph.node(source)
        print("   <-", record.kind, getattr(item, "kind", None), getattr(item, "label", None),
              item.key[:90], record.span)


if __name__ == "__main__":
    raise SystemExit(main())
