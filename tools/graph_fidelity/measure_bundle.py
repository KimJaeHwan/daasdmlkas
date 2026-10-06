"""Stage-1 measurement: how complete is the graph on a Bundle's functions?

For every function the session yields (it stops at the first function whose
scope cannot be constructed; that point is reported), this script records:
size and shape, normalization result or typed failure reason, and the
interpreter oracle's verdict (missing / unexplained / control violations,
runs skipped and why, opcodes executed only opaquely). Calls are havoced
(registers), so call-free and call-containing functions are both covered;
callee memory effects are out of scope.

usage (WSL): ~/venvs/tdo/bin/python tools/graph_fidelity/measure_bundle.py <generation> [--runs N] [--json out]
"""

from __future__ import annotations

import argparse
import collections
import json
import random
import sys
import time
import traceback
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
from tdo_v2.observed_call_state import observed_call_state_projections  # noqa: E402

CALLS = {"CALL", "CALLIND", "CALLOTHER"}


def image_reader(generation: Path):
    manifest = json.loads((generation / "manifest.json").read_text())
    paths = {row["id"]: row["path"] for row in manifest["members"]}
    blocks = []
    for row in manifest["blocks"]:
        if row["member_id"] and row["is_initialized"]:
            data = (generation / paths[row["member_id"]]).read_bytes()
            blocks.append((row["space_id"], row["byte_start"], data))

    def read(space_id: int, address: int):
        for space, start, data in blocks:
            if space == space_id and start <= address < start + len(data):
                return data[address - start]
        return None

    return read


def stack_pointer(observation, register_space, fallback):
    for row in observed_call_state_projections(observation):
        base = row.memory_transition.caller_base
        return base.byte_offset, base.byte_size
    return fallback


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("generation", type=Path)
    parser.add_argument("--runs", type=int, default=8)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    binding = NamingBindingExpectation(
        sha256((REPO / "ghidra" / "GhidraV2CallNaming.java").read_bytes()).digest(),
        CALL_NAMING_GHIDRA_VERSION,
    )
    snapshot = admit_frozen_bundle(args.generation)
    image = image_reader(args.generation)
    totals = collections.Counter()
    reasons = collections.Counter()
    skipped = collections.Counter()
    opaque = collections.Counter()
    problems = []
    functions = []
    started = time.time()
    with open_observed_function_session(snapshot, naming_binding=binding) as session:
        program = session.program_result
        spaces = program.evidence.address_spaces
        language = program.evidence.translation_namespace.language_id
        const = next(row.space_id for row in spaces if row.is_constant_space)
        regs = next(row.space_id for row in spaces if row.is_register_space)
        unique = next(row.space_id for row in spaces if row.is_unique_space)
        is32 = ":32:" in language
        default_sp = (0x10, 4) if is32 else (0x20, 8)   # ESP / RSP in Ghidra x86
        width = 4 if is32 else 8
        iterator = session.iter_functions()
        while True:
            try:
                evidence = next(iterator)
            except StopIteration:
                break
            except Exception as error:  # noqa: BLE001 - the session iterator is now dead
                totals["stopped_by_iterator_error"] = 1
                problems.append(("iterator", "".join(traceback.format_exception_only(error)).strip()))
                break
            observation = evidence.unit.observation
            ops = [op.opcode for ins in observation.instructions for op in ins.operations]
            has_calls = any(op in CALLS for op in ops)
            branches = ops.count("CBRANCH") + ops.count("BRANCHIND")
            entry = evidence.unit.scopes.function.entry.byte_offset
            row = {
                "entry": hex(entry), "instructions": len(observation.instructions),
                "calls": has_calls, "branches": branches,
            }
            totals["functions"] += 1
            totals["call_free" if not has_calls else "with_calls"] += 1
            if not has_calls and branches:
                totals["call_free_with_branches"] += 1
            began = time.time()
            try:
                normalized = FunctionNormalizer().normalize(evidence.unit)
            except Exception as error:  # noqa: BLE001
                row["result"] = "exception:" + type(error).__name__
                reasons[row["result"]] += 1
                problems.append((hex(entry), "".join(traceback.format_exception_only(error)).strip()))
                functions.append(row)
                continue
            row["normalize_seconds"] = round(time.time() - began, 3)
            if type(normalized) is not NormalizedFunction:
                row["result"] = normalized.reason.value
                reasons[row["result"]] += 1
                functions.append(row)
                continue
            row["result"] = "ok"
            sp_offset, sp_size = stack_pointer(observation, regs, default_sp)

            def pool(seed, sp_offset=sp_offset):
                rng = random.Random(seed)
                base = rng.choice((0x7FFF_1000, 0x7FFF_1008, 0x5000_0000))
                values = {
                    reg: rng.choice((base, base + 8, base + 0x40, rng.getrandbits(31)))
                    for reg in range(0, 0x40, 8)
                }
                values[sp_offset] = 0x7000_0000
                return values

            havoc = (regs, sp_offset, sp_size) if has_calls else None
            report = check(normalized, observation, seeds=range(args.runs), register_pools=pool,
                           spaces=(const, regs, unique), havoc_calls=havoc, image=image)
            violations = check_control(normalized, observation, seeds=range(min(4, args.runs)),
                                       register_pools=pool, spaces=(const, regs, unique),
                                       havoc_calls=havoc, image=image)
            row.update({
                "runs": report.runs, "skipped_runs": report.unsupported,
                "checked": report.checked, "missing": len(report.silent),
                "unexplained": len(report.covered_by_debt), "control_violations": len(violations),
            })
            for reason, count in report.unsupported_reasons.items():
                skipped[reason] += count
            for opcode in report.opaque_opcodes:
                opaque[opcode] += 1
            for key in ("runs", "skipped_runs", "checked", "missing", "unexplained", "control_violations"):
                totals[key] += row[key]
            if row["missing"] or row["unexplained"] or row["control_violations"]:
                sample = (report.silent + report.covered_by_debt)[:1]
                problems.append((hex(entry), {"missing": row["missing"], "unexplained": row["unexplained"],
                                              "control": row["control_violations"], "sample": repr(sample)[:300],
                                              "control_sample": violations[:2]}))
            functions.append(row)
    totals["seconds"] = round(time.time() - started, 1)
    sizes = sorted(row["instructions"] for row in functions)
    summary = {
        "generation": str(args.generation), "language": language, "totals": dict(totals),
        "normalize_failures": dict(reasons), "skipped_run_reasons": dict(skipped),
        "opaque_opcodes": dict(opaque),
        "size": {"max": sizes[-1] if sizes else 0, "median": sizes[len(sizes) // 2] if sizes else 0},
        "largest_call_free": sorted(
            (r for r in functions if not r["calls"]), key=lambda r: -r["instructions"])[:5],
        "slowest": sorted(functions, key=lambda r: -r.get("normalize_seconds", 0))[:3],
        "problems": problems[:20],
    }
    print(json.dumps(summary, indent=1, default=str))
    if args.json:
        args.json.write_text(json.dumps({"summary": summary, "functions": functions}, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
