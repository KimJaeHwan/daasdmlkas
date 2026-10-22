"""S1: interprocedural graph fidelity on a Bundle (WSL).

usage: measure_program.py <generation> [--runs N] [--json out]
Analyzes all functions bottom-up with callee summaries (tdo_v2.interprocedural),
then runs every function with its Bundle callees executed for real
(external / unknown calls havoced) and checks the caller graphs
(tests/intra/program_oracle.py): no silent misses, values through calls reach
their caller-level inputs.
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
from program_oracle import check_program  # noqa: E402
from tdo_v2.configured_naming_contracts import (  # noqa: E402
    CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation,
)
from tdo_v2.integration.configured_bundle import admit_frozen_bundle  # noqa: E402
from tdo_v2.integration.observed_function_session import open_observed_function_session  # noqa: E402
from tdo_v2.interprocedural import analyze_units  # noqa: E402
from tdo_v2.normalize import NormalizedFunction  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("generation", type=Path)
    parser.add_argument("--runs", type=int, default=4)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--lanes", action="store_true",
                        help="also run the byte-lane oracle (tests/intra/lane_oracle.check_lanes) per function")
    parser.add_argument("--forward", action="store_true",
                        help="also check every forward value fact (docs 25.33 F0, tdo_v2.forward) on the runs "
                             "(tests/intra/forward_oracle.check_forward)")
    parser.add_argument("--models", action="store_true",
                        help="apply the declared external models (win64) and run those library "
                             "functions with their real semantics in the interpreter")
    parser.add_argument("--binding", action="append", default=[], type=Path,
                        help="a model binding file (docs 25.20 F), with same-result-functions, "
                             "accessor-result-separate and accessor-private-state on; the bound bodies run "
                             "for real in the interpreter. The analysis then also takes run_dfbench's "
                             "frame and globals assumptions (home space 0x28, globals-disjoint-from-stack, "
                             "debug-break traps), as the real runs do")
    args = parser.parse_args()
    binding = NamingBindingExpectation(
        sha256((REPO / "ghidra" / "GhidraV2CallNaming.java").read_bytes()).digest(),
        CALL_NAMING_GHIDRA_VERSION,
    )
    image = image_reader(args.generation)
    totals = collections.Counter()
    samples = []
    with open_observed_function_session(admit_frozen_bundle(args.generation), naming_binding=binding) as session:
        spaces = session.program_result.evidence.address_spaces
        const = next(row.space_id for row in spaces if row.is_constant_space)
        regs = next(row.space_id for row in spaces if row.is_register_space)
        unique = next(row.space_id for row in spaces if row.is_unique_space)
        address_bits = {row.space_id: row.address_size_bits for row in spaces if row.is_memory_space}
        memory_space_ids = sorted(address_bits)
        language = session.program_result.evidence.translation_namespace.language_id
        default_sp = (0x10, 4) if ":32:" in language else (0x20, 8)
        units = [evidence.unit for evidence in session.iter_functions()]
    began = time.time()
    options, externals, userops, external_abi = {}, None, frozenset(), "win64"
    if args.models:
        sys.path.insert(0, str(REPO / "tools" / "bundle_export"))
        import run_dfbench
        from tdo_v2.image_info import load_image_info

        info = load_image_info(args.generation)
        models = run_dfbench.external_models(args.generation)
        markers = run_dfbench.pcodeop_models()
        # as the runs (summary_engine): import-slots-hold-their-exports on -- a
        # model bound at an import slot rests on it
        options = {"image_info": info, "external_models": models, "pcodeop_models": markers,
                   "assume_import_slots_hold_exports": True}
        namespace = units[0].scopes.program.evidence.translation_namespace if units else None
        language = namespace and (namespace.language_id, namespace.major_version, namespace.minor_version)
        userops = frozenset(index for model in markers if language in model.languages for index in model.no_effect)
        # every modeled import runs for real (or the run is skipped: Unsupported)
        # the models' convention is the binary's (models/external per ABI)
        external_abi = "sysv64" if run_dfbench.abi_of(args.generation) == "sysv64" else "win64"
        externals = {thunk: models.lookup(row)[1].name for row in (info.imports if info else ())
                     if models.lookup(row) for thunk in (*row.thunks, *row.slots)}
    if args.binding:
        from tdo_v2.summary_store import load_binding_file

        options.update(model_bindings=tuple(load_binding_file(path) for path in args.binding),
                       assume_same_result_functions=True, assume_accessor_result_separate=True,
                       assume_accessor_private_state=True, private_frame_above=0x28,
                       assume_globals_disjoint_from_stack=True, assume_debug_break_traps_do_not_return=True)
    results = analyze_units(units, **options)
    totals["analysis_seconds"] = round(time.time() - began, 1)
    if args.forward:   # (every fact rests on the run's assumptions)
        from tdo_v2.summary_engine import run_assumptions

        run_labels = run_assumptions(results, home_space=options.get("private_frame_above", 0),
                                     traps=options.get("assume_debug_break_traps_do_not_return", False),
                                     pcodeop_models=options.get("pcodeop_models"))
        from tdo_v2.forward import context_facts

        # F2a: callee facts with each call site's bindings, checked in the caller's runs
        contexts_of: dict = {}
        for fact in context_facts(results, assumptions=lambda key, item: (
                *run_labels, *item.inherited_assumptions, *item.declared.values())):
            contexts_of.setdefault(fact.context[0], []).append(fact)
    # every function of the program runs for real (a bound one included)
    program = {
        (unit.scopes.function.entry.space_id, unit.scopes.function.entry.byte_offset): unit.observation
        for unit in units if unit.observation is not None
    }
    for key, item in sorted(results.items()):
        totals["functions"] += 1
        totals["calls_internal"] += len(item.calls)
        totals["calls_proven"] += len(item.proven)
        totals["calls_modeled"] += len(item.declared)
        if type(item.normalized) is not NormalizedFunction:
            totals["normalize_failures"] += 1
            continue
        observation = item.unit.observation
        sp_offset, sp_size = stack_pointer(observation, regs, default_sp)

        def pool(seed, sp_offset=sp_offset):
            rng = random.Random(seed)
            base = rng.choice((0x7FFF_1000, 0x7FFF_1008, 0x5000_0000))
            values = {reg: rng.choice((base, base + 8, base + 0x40, rng.getrandbits(31)))
                      for reg in range(0, 0x40, 8)}
            values[sp_offset] = 0x7000_0000
            return values

        report = check_program(item.normalized, observation, program, seeds=range(args.runs),
                               register_pools=pool, spaces=(const, regs, unique),
                               havoc_calls=(regs, sp_offset, sp_size), image=image,
                               externals=externals, no_effect_userops=userops, address_bits=address_bits,
                               external_abi=external_abi,
                               private_frame_above=options.get("private_frame_above", 0))
        totals["runs"] += report.runs
        totals["skipped_runs"] += report.unsupported
        totals["checked"] += report.checked
        totals["through_calls"] += report.through_calls
        totals["missing"] += len(report.silent)
        totals["unexplained"] += len(report.covered_by_debt)
        if args.lanes:
            from lane_oracle import check_lanes
            lanes = check_lanes(item.normalized, item.unit, seeds=range(args.runs), register_pools=pool,
                                external_abi=external_abi,
                                const_space=const, havoc_calls=(regs, sp_offset, sp_size), reg_space=regs,
                                unique_space=unique, program=program, externals=externals, image=image,
                                no_effect_userops=userops, address_bits=address_bits)
            totals["lane_checked"] += lanes.checked
            totals["lane_missing"] += len(lanes.missing)
            totals["lane_unclassified"] += lanes.unclassified
            totals["lane_nested"] += lanes.nested
            totals["lane_not_subset"] += lanes.not_subset
            for row in lanes.missing[:2]:
                if len(samples) < 6:
                    samples.append((key, "lane " + repr(row)[:200]))
        if args.forward:
            from forward_oracle import check_forward
            from tdo_v2.forward import forward_facts

            contexts = contexts_of.get(key, [])
            facts = (*forward_facts(item.normalized, item.unit,
                                    assumptions=(*run_labels, *item.inherited_assumptions, *item.declared.values())),
                     *contexts)
            forward = check_forward(item.unit, facts, seeds=range(args.runs), register_pools=pool,
                                    const_space=const, reg_space=regs, havoc_calls=(regs, sp_offset, sp_size),
                                    image=image, program=program, externals=externals,
                                    no_effect_userops=userops, address_bits=address_bits,
                                    external_abi=external_abi)
            totals["forward_facts"] += len(facts) - len(contexts)
            totals["forward_context_facts"] += len(contexts)
            totals["forward_unexercised"] += forward.unexercised
            totals["forward_checked"] += forward.checked
            totals["forward_failures"] += len(forward.failures)
            for row in forward.failures[:2]:
                if len(samples) < 6:
                    samples.append((key, "forward " + repr(row)[:200]))
        # bytes calls wrote, checked against the places of their runs
        # (program_oracle: covered / only unevaluable places / failed, failed
        # but explained by a debt), and the footprints of preserving calls
        for name in ("place_checked", "place_covered", "place_unlocated_only", "place_failed",
                     "place_failed_debt", "place_no_activation", "footprint_checked", "footprint_unlocated",
                     "same_result_checked", "same_result_unchecked", "private_unchecked"):
            totals[name] += getattr(report, name)
        totals["same_result_violations"] += len(report.same_result_violations)
        totals["same_result_uses"] += len(getattr(item.normalized, "same_result_uses", ()))
        for row in report.silent[:2]:
            if len(samples) < 6:
                samples.append((key, repr(row)[:240]))
    result = {"totals": dict(totals), "samples": samples}
    print(json.dumps(result))
    if args.json:
        args.json.write_text(json.dumps(result, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
