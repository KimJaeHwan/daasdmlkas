"""Layer 2 ``operations`` of ``bundle_lint`` (design G0 r0..r6): per call row,
per S1 exit, per CALLOTHER, and the program's register evidence -- each value
read from an engine function, never recomputed.

Keys: validated operations ``<function id>/<operation key>``; S1 exit rows
(validated rows without an operation) ``<function id>/#<array index>`` (r6 s5).
"""

from __future__ import annotations

from pathlib import Path

from report import Row, operation_row_key, source_row_key

REPO = Path(__file__).resolve().parents[2]


def _coord(value) -> str | None:
    return None if value is None else f"{value.space_id:x}:{value.byte_offset:x}"


def register_rows(program) -> list[Row]:
    """stack / link / program counter as ``isa_identity`` reads them (r4 s6)."""
    from tdo_v2.isa_identity import link_register, program_counter, stack_register

    evidence = program.evidence
    namespace = evidence.translation_namespace
    rows = [Row("operations", "language", "program", "evaluated", "applied", "engine",
                {"language_id": namespace.language_id, "major": namespace.major_version,
                 "minor": namespace.minor_version})]
    for name, lookup in (("stack_register", stack_register), ("link_register", link_register),
                         ("program_counter", program_counter)):
        found = lookup(evidence)
        if found is None:
            rows.append(Row("operations", name, "program", "evaluated", "withheld", "engine"))
        else:
            rows.append(Row("operations", name, "program", "evaluated", "applied", "engine",
                            {"name": found.name, "space_id": found.space_id, "byte_offset": found.byte_offset,
                             "byte_size": found.byte_size}))
    return rows


def call_rows(claim, function_keys) -> list[Row]:
    from tdo_v2.control_projection import call_like_instruction, control_successor_coordinates
    from tdo_v2.integration.configured_target_resolution import _selected_resolved_target
    from tdo_v2.interprocedural import _plain_push_call, _program_memory_space
    from tdo_v2.observed_call_state import observed_call_state_projections
    from tdo_v2.pcode_blocks import _landing_pads

    evidence, unit = claim.evidence, claim.unit
    observation = unit.observation
    entry = unit.scopes.function.entry
    local = {row.address for row in observation.instructions}
    by_address = {row.address: row for row in observation.instructions}
    memory_space = _program_memory_space(unit)
    projected = {row.call_operation_key for row in observed_call_state_projections(observation)}
    rows = []
    for seed, naming in zip(evidence.seeds.callsites, evidence.naming.rows, strict=True):
        key = operation_row_key(claim.function_id, seed.operation_key)
        target = _selected_resolved_target(naming)
        aliases = sorted({alias.value for alias in (() if target is None else target.aliases)
                          if alias.policy_admissible})
        instruction = by_address[seed.locator.instruction]
        successors = control_successor_coordinates(instruction, local_addresses=local, function_entry=entry)
        pads = _landing_pads(instruction, local, entry, successors) if call_like_instruction(instruction) else ()
        detail = {
            "opcode": seed.operation_key.rsplit(":", 1)[1],
            "resolution": naming.resolution.state.value,
            "reason": None if naming.resolution.reason is None else naming.resolution.reason.value,
            "target": None if target is None else _coord(target.coordinate),
            "target_is_function": target is not None and _coord(target.coordinate) in function_keys,
            "aliases": aliases,
            "push_projection": seed.operation_key in projected,
            "plain_push": bool(memory_space is not None and seed.operation_key.endswith(":CALL")
                               and _plain_push_call(unit, seed.operation_key, memory_space)),
            "flow_targets": sorted(_coord(item) for item in instruction.flow_targets),
            "local_successors": sorted(_coord(item) for item in successors),
            "landing_pads": sorted(_coord(item) for item in pads),
        }
        if naming.resolution.state.value in ("RESOLVED_NAMED", "RESOLVED_UNNAMED"):
            verdict = "applied"
        elif naming.resolution.state.value == "INDIRECT":
            verdict = "not_applicable"
        else:
            verdict = "unrecognized"
        rows.append(Row("operations", "call", key, "evaluated", verdict, "engine", detail))
    return rows


def exit_rows(claim, function_keys) -> list[Row]:
    """S1 fallthrough exits as ``(source, target, kind, function)`` and whether
    the engine's reach rule (control_context.py:104) gets an edge from it."""
    rows = []
    exits = getattr(claim.unit.observation, "fallthrough_exits", ())
    for index, row in enumerate(exits):
        function = _coord(row.function)
        reach = function is not None and function in function_keys
        rows.append(Row("operations", "s1_exit", source_row_key(claim.function_id, index), "evaluated",
                        "applied" if reach else "not_applicable", "lint",
                        {"source": _coord(row.source), "target": _coord(row.target),
                         "kind": row.kind, "function": function,
                         "reach_edge": reach}))
    return rows


def callother_rows(claim, models) -> list[Row]:
    """Every CALLOTHER with its index and operands; whether a p-code op model of
    the language declares it no-effect or a trap (``no_effect_calls`` /
    ``trap_operations``: a lint diagnostic -- application is layer 3)."""
    from tdo_v2.call_seeds import _operation_key
    from tdo_v2.pcodeop_models import no_effect_calls, trap_operations
    from tdo_v2._scope_contracts import VarnodeKindCode

    unit = claim.unit
    namespace = unit.scopes.program.evidence.translation_namespace
    language = (namespace.language_id, namespace.major_version, namespace.minor_version)
    applicable = [model.file_id for model in models if language in model.languages]
    no_effect = no_effect_calls(unit, models)
    traps = trap_operations(unit, models)
    rows = []
    for instruction in unit.observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            if operation.opcode != "CALLOTHER":
                continue
            op_key = _operation_key(instruction.address, ordinal, operation.opcode)
            constants = [item.coordinate.byte_offset if item.kind is VarnodeKindCode.CONSTANT else None
                         for item in operation.inputs]
            index = constants[0] if constants else None
            known = index is not None and any(index in model.no_effect or index in (model.traps or {})
                                              for model in models if language in model.languages)
            detail = {"index": index, "operands": constants[1:], "models": applicable,
                      "no_effect": op_key in no_effect, "trap_match": op_key in traps,
                      "output": operation.output is not None}
            if not applicable:
                verdict = "unsupported"
            elif op_key in no_effect or op_key in traps:
                verdict = "applied"
            else:
                verdict = "unrecognized" if not known else "not_applicable"
            rows.append(Row("operations", "callother", operation_row_key(claim.function_id, op_key),
                            "evaluated", verdict, "lint", detail))
    return rows


def _models(options):
    from tdo_v2.pcodeop_models import load_pcodeop_models

    paths = options.get("lint_pcodeop_models")
    if paths is None:
        paths = sorted(str(path) for path in (REPO / "models" / "pcodeops").glob("*.json"))
    return load_pcodeop_models(paths)


def rows(diagnosis, generation, options) -> list[Row]:
    from tdo_v2._scope_results import ConstructedProgramScope

    program = diagnosis.program_value
    if type(program) is not ConstructedProgramScope:
        return []
    out = register_rows(program)
    function_keys = {claim.entry for claim in diagnosis.claims if claim.entry}
    models = _models(options)
    for claim in diagnosis.claims:
        if claim.evidence is None:
            continue
        out.extend(call_rows(claim, function_keys))
        out.extend(exit_rows(claim, function_keys))
        out.extend(callother_rows(claim, models))
    return out
