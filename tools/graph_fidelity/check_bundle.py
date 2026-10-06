"""Run the interpreter-vs-graph fidelity check on every call-free Bundle function.

usage (WSL): ~/venvs/tdo/bin/python tools/graph_fidelity/check_bundle.py <generation> [--runs N]
"""

from __future__ import annotations

import argparse
import collections
import random
import sys
from hashlib import sha256
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "intra"))

from graph_oracle import check, check_control  # noqa: E402
from tdo_v2.configured_naming_contracts import (  # noqa: E402
    CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation,
)
from tdo_v2.integration.configured_bundle import admit_frozen_bundle  # noqa: E402
from tdo_v2.integration.observed_function_session import open_observed_function_session  # noqa: E402
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction  # noqa: E402

CALLS = {"CALL", "CALLIND", "CALLOTHER"}
X64_REGISTERS = (0x0, 0x8, 0x10, 0x18, 0x30, 0x38, 0x80, 0x88)  # RAX RCX RDX RBX RSI RDI R8 R9
RSP = 0x20


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("generation", type=Path)
    parser.add_argument("--runs", type=int, default=16)
    args = parser.parse_args()
    binding = NamingBindingExpectation(
        sha256((REPO / "ghidra" / "GhidraV2CallNaming.java").read_bytes()).digest(),
        CALL_NAMING_GHIDRA_VERSION,
    )
    snapshot = admit_frozen_bundle(args.generation)
    stats = collections.Counter()
    examples = []
    with open_observed_function_session(snapshot, naming_binding=binding) as session:
        program = session.program_result
        spaces = program.evidence.address_spaces
        const = next(row.space_id for row in spaces if row.is_constant_space)
        regs = next(row.space_id for row in spaces if row.is_register_space)
        unique = next(row.space_id for row in spaces if row.is_unique_space)
        for evidence in session.iter_functions():
            observation = evidence.unit.observation
            stats["functions"] += 1
            if any(op.opcode in CALLS for ins in observation.instructions for op in ins.operations):
                continue
            stats["call_free"] += 1
            normalized = FunctionNormalizer().normalize(evidence.unit)
            if type(normalized) is not NormalizedFunction:
                stats["unresolved"] += 1
                continue

            def pool(seed):
                rng = random.Random(seed)
                base = rng.choice((0x7FFF_1000, 0x7FFF_1008, 0x5000_0000))
                values = {reg: rng.choice((base, base + 8, base + 0x40, rng.getrandbits(32)))
                          for reg in X64_REGISTERS}
                values[RSP] = 0x7000_0000
                return values

            report = check(normalized, observation, seeds=range(args.runs),
                           register_pools=pool, spaces=(const, regs, unique))
            stats["runs"] += report.runs
            stats["unsupported_runs"] += report.unsupported
            stats["checked"] += report.checked
            stats["silent"] += len(report.silent)
            stats["unexplained"] += len(report.covered_by_debt)
            violations = check_control(normalized, observation, seeds=range(min(args.runs, 4)),
                                       register_pools=pool, spaces=(const, regs, unique))
            stats["control_violations"] += len(violations)
            stats["control_dependences"] += len(normalized.control_dependences)
            entry = evidence.unit.scopes.function.entry
            for item in (report.silent + report.covered_by_debt)[:2]:
                examples.append((hex(entry.byte_offset), item))
    print(dict(stats))
    for row in examples[:20]:
        print(" ", row)
    return 0


if __name__ == "__main__":
    sys.exit(main())
