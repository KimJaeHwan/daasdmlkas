"""S0: check function summaries on a Bundle against concrete runs (WSL).

usage: measure_summary.py <generation> [--runs N] [--json out]
For every function: normalize, summarize (tdo_v2.function_summary), run the
interpreter with provenance (calls havoced) and require dynamic ⊆ static
(tests/intra/summary_oracle.py). Prints totals, violations by kind, summary
runs by kind and the slowest summaries.
"""

from __future__ import annotations

import argparse
import collections
import json
import random
import sys
import time
from hashlib import sha256
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "intra"))
sys.path.insert(0, str(REPO / "tools" / "graph_fidelity"))

from measure_bundle import image_reader, stack_pointer  # noqa: E402
from summary_oracle import check_summary  # noqa: E402
from tdo_v2.configured_naming_contracts import (  # noqa: E402
    CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation,
)
from tdo_v2.function_summary import summarize_function  # noqa: E402
from tdo_v2.integration.configured_bundle import admit_frozen_bundle  # noqa: E402
from tdo_v2.integration.observed_function_session import open_observed_function_session  # noqa: E402
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("generation", type=Path)
    parser.add_argument("--runs", type=int, default=6)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    binding = NamingBindingExpectation(
        sha256((REPO / "ghidra" / "GhidraV2CallNaming.java").read_bytes()).digest(),
        CALL_NAMING_GHIDRA_VERSION,
    )
    image = image_reader(args.generation)
    totals = collections.Counter()
    violations = collections.Counter()
    kinds = collections.Counter()
    samples = []
    timings = []
    with open_observed_function_session(admit_frozen_bundle(args.generation), naming_binding=binding) as session:
        spaces = session.program_result.evidence.address_spaces
        const = next(row.space_id for row in spaces if row.is_constant_space)
        regs = next(row.space_id for row in spaces if row.is_register_space)
        unique = next(row.space_id for row in spaces if row.is_unique_space)
        language = session.program_result.evidence.translation_namespace.language_id
        default_sp = (0x10, 4) if ":32:" in language else (0x20, 8)
        for evidence in session.iter_functions():
            observation = evidence.unit.observation
            normalized = FunctionNormalizer().normalize(evidence.unit)
            entry = hex(evidence.unit.scopes.function.entry.byte_offset)
            totals["functions"] += 1
            if type(normalized) is not NormalizedFunction:
                totals["normalize_failures"] += 1
                continue
            began = time.time()
            summary = summarize_function(normalized, observation)
            timings.append((time.time() - began, entry, len(observation.instructions)))
            for item in summary.exits:
                for run in item.runs:
                    kinds[run.kind.value] += 1
            sp_offset, sp_size = stack_pointer(observation, regs, default_sp)

            def pool(seed, sp_offset=sp_offset):
                rng = random.Random(seed)
                base = rng.choice((0x7FFF_1000, 0x7FFF_1008, 0x5000_0000))
                values = {reg: rng.choice((base, base + 8, base + 0x40, rng.getrandbits(31)))
                          for reg in range(0, 0x40, 8)}
                values[sp_offset] = 0x7000_0000
                return values

            report = check_summary(summary, observation, seeds=range(args.runs), register_pools=pool,
                                   spaces=(const, regs, unique), havoc_calls=(regs, sp_offset, sp_size),
                                   image=image)
            totals["runs"] += report.runs
            totals["skipped_runs"] += report.unsupported
            totals["checked_bytes"] += report.checked
            for row in report.violations:
                violations[row[0]] += 1
                if len(samples) < 5:
                    samples.append((entry, repr(row)[:200]))
    timings.sort(reverse=True)
    result = {
        "totals": dict(totals), "violations": dict(violations), "summary_runs": dict(kinds),
        "samples": samples,
        "slowest": [(entry, instructions, round(seconds, 2)) for seconds, entry, instructions in timings[:3]],
        "summary_seconds": round(sum(item[0] for item in timings), 1),
    }
    print(json.dumps(result))
    if args.json:
        args.json.write_text(json.dumps(result, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
