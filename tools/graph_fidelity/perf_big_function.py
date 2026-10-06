"""Time normalization and one backward slice on large synthetic call-free functions.

usage: python tools/graph_fidelity/perf_big_function.py [sizes...]
Each function has random value/memory ops, cmov, and a forward or backward
conditional branch every ~8 instructions, so the CFG has many blocks and loops.
"""

from __future__ import annotations

import random
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / "src"), str(REPO / "tests" / "intra")]

from synthetic import (  # noqa: E402
    CODE_BASE, FunctionBuilder, ZF, CF, normalize_with_observation, reg, slice_from,
)
from test_graph_fidelity import _cmov, _random_memory_ops, _random_value_op  # noqa: E402
from tdo_v2.graph_contracts import NodeKind  # noqa: E402


def build(size: int, seed: int = 1) -> FunctionBuilder:
    rng = random.Random(seed)
    builder = FunctionBuilder()
    labels = []
    for index in range(size):
        if index % 8 == 0:
            labels.append(f"L{index}")
            builder.label(labels[-1])
        kind = rng.random()
        if kind < 0.45:
            builder.ins(_random_value_op(rng))
        elif kind < 0.85:
            builder.ins(*_random_memory_ops(rng))
        elif kind < 0.9:
            builder.ins(*_cmov(rng, CODE_BASE + 4 * (len(builder._rows) + 1)))
        else:
            builder.cbranch(rng.choice(labels), reg(rng.choice((ZF, CF)), 1))
    return builder.ret(realistic=True)


def main() -> int:
    sizes = [int(arg) for arg in sys.argv[1:]] or [250, 500, 1000, 2000]
    for size in sizes:
        builder = build(size)
        start = time.perf_counter()
        function, _ = normalize_with_observation(builder)
        normalized = time.perf_counter() - start
        graph = function.dependencies
        reads = [
            node for node in range(graph.node_count)
            if graph.has_node(node) and graph.node(node).kind is NodeKind.OPERATION
        ]
        start = time.perf_counter()
        slice_from(function, reads[-1])
        sliced = time.perf_counter() - start
        print(f"instructions={size:5} normalize={normalized:7.2f}s slice={sliced:6.2f}s "
              f"nodes={graph.node_count} edges={graph.edge_count}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
