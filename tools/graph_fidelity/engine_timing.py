"""Normalization time per function under each memory SSA engine (WSL).

usage: engine_timing.py <generation> [engine ...] [--top N]
Default engines: dense sparse. Prints totals and the slowest functions
(by the first engine), with the memory SSA share of each.
"""

from __future__ import annotations

import argparse
import os
import time
from hashlib import sha256
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

from tdo_v2 import memory_ssa  # noqa: E402
from tdo_v2.configured_naming_contracts import (  # noqa: E402
    CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation,
)
from tdo_v2.integration.configured_bundle import admit_frozen_bundle  # noqa: E402
from tdo_v2.integration.observed_function_session import open_observed_function_session  # noqa: E402
from tdo_v2.normalize import FunctionNormalizer  # noqa: E402

ssa_seconds = [0.0]


def _timed(name):
    builder = memory_ssa._ENGINES[name]

    def run(unit):
        began = time.perf_counter()
        try:
            return builder(unit)
        finally:
            ssa_seconds[0] += time.perf_counter() - began

    return run


def measure(generation: Path, engine: str) -> dict[str, tuple[int, float, float]]:
    memory_ssa.register_memory_ssa_engine(f"timed-{engine}", _timed(engine))
    os.environ[memory_ssa.MEMORY_SSA_ENGINE_ENV] = f"timed-{engine}"
    binding = NamingBindingExpectation(
        sha256((REPO / "ghidra" / "GhidraV2CallNaming.java").read_bytes()).digest(),
        CALL_NAMING_GHIDRA_VERSION,
    )
    rows = {}
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        for evidence in session.iter_functions():
            entry = hex(evidence.unit.scopes.function.entry.byte_offset)
            ssa_seconds[0] = 0.0
            began = time.perf_counter()
            FunctionNormalizer().normalize(evidence.unit)
            rows[entry] = (len(evidence.unit.observation.instructions),
                           time.perf_counter() - began, ssa_seconds[0])
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("generation", type=Path)
    parser.add_argument("engines", nargs="*", default=["dense", "sparse"])
    parser.add_argument("--top", type=int, default=5)
    args = parser.parse_args()
    results = {engine: measure(args.generation, engine) for engine in args.engines}
    for engine, rows in results.items():
        total = sum(row[1] for row in rows.values())
        ssa = sum(row[2] for row in rows.values())
        print(f"{engine:8} functions={len(rows)} normalize={total:8.1f}s memory-ssa={ssa:8.1f}s")
    first = results[args.engines[0]]
    print("slowest:")
    for entry in sorted(first, key=lambda key: -first[key][1])[:args.top]:
        cells = " | ".join(
            f"{engine} {results[engine][entry][1]:7.1f}s (ssa {results[engine][entry][2]:6.1f}s)"
            for engine in args.engines
        )
        print(f"  {entry} instructions={first[entry][0]:5}  {cells}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
