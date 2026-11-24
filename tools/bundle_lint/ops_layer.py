"""Layer 2 ``operations`` of ``bundle_lint`` (design G0 r0..r6): per call and
tail-call row, per recogniser, per S1 exit, per BRANCHIND, per CALLOTHER, the
program's register evidence and the engine's fixed conventions -- each value
read from an engine function, never recomputed.

Keys: validated operations ``<function id>/<operation key>``; rows of the
member's own JSON array (S1 exits, source rows of refused functions)
``<function id>/#<array index in the member>`` (r6 s5).

``source``: ``engine`` when the verdict is an engine function's answer;
``lint`` when the lint maps engine facts onto a verdict (Fable impl r1 P3).
"""

from __future__ import annotations

import json
from pathlib import Path

from report import Row, operation_row_key, source_row_key

REPO = Path(__file__).resolve().parents[2]


def _coord(value) -> str | None:
    return None if value is None else f"{value.space_id:x}:{value.byte_offset:x}"


def _raw_coord(value) -> str | None:
    """A member's own coordinate, as far as it is well formed (Astra impl r2 P1)."""
    if not isinstance(value, dict):
        return None
    space, offset = value.get("space_id"), value.get("byte_offset")
    if type(space) is int and type(offset) is int and space >= 0 and offset >= 0:
        return f"{space:x}:{offset:x}"
    return f"malformed:{json.dumps(value, sort_keys=True)[:120]}"


# -- program-level -------------------------------------------------------------------------

def register_rows(program) -> list[Row]:
    """stack / link / program counter as ``isa_identity`` reads them (r4 s6):
    ``not_applicable`` where the ISA table has no such register (x86 link),
    ``withheld`` where the ISA has one and the evidence lacks it."""
    from tdo_v2 import isa_identity

    evidence = program.evidence
    namespace = evidence.translation_namespace
    parts = tuple(namespace.language_id.split(":"))[:3]
    rows = [Row("operations", "language", "program", "evaluated", "applied", "engine",
                {"language_id": namespace.language_id, "major": namespace.major_version,
                 "minor": namespace.minor_version})]
    for name, lookup, table in (
            ("stack_register", isa_identity.stack_register, isa_identity._STACK_REGISTERS),
            ("link_register", isa_identity.link_register, isa_identity._LINK_REGISTERS),
            ("program_counter", isa_identity.program_counter, isa_identity._PROGRAM_COUNTERS)):
        found = lookup(evidence)
        if found is not None:
            rows.append(Row("operations", name, "program", "evaluated", "applied", "engine",
                            {"name": found.name, "space_id": found.space_id, "byte_offset": found.byte_offset,
                             "byte_size": found.byte_size}))
        elif parts not in table:
            rows.append(Row("operations", name, "program", "evaluated", "not_applicable", "lint",
                            {"why": "the ISA table has no such register"}))
        else:
            rows.append(Row("operations", name, "program", "evaluated", "withheld", "engine",
                            {"wanted": list(table[parts])}))
    return rows


# fixed register offsets the engine compares against literally (convention keys, r1 s5);
# each is pinned by a guard test on the engine source
FIXED_OFFSETS = (
    # (language prefix, register name, offset, size, where the engine uses it)
    (("x86", "LE", "64"), "RSP", 0x20, 8, "interprocedural._plain_push_call"),
    (("x86", "LE", "64"), "RIP", 0x288, 8, "interprocedural._X64_RIP"),
)


def convention_rows(program, models, model_paths) -> list[Row]:
    evidence = program.evidence
    namespace = evidence.translation_namespace
    parts = tuple(namespace.language_id.split(":"))[:3]
    language = (namespace.language_id, namespace.major_version, namespace.minor_version)
    table = {row.name: row for row in (evidence.register_evidence.registers if evidence.register_evidence else ())}
    rows = []
    for prefix, name, offset, size, where in FIXED_OFFSETS:
        key = f"{name}@{where}"
        if parts != prefix:
            rows.append(Row("operations", "fixed_register", key, "evaluated", "not_applicable", "lint"))
            continue
        row = table.get(name)
        if row is None:
            rows.append(Row("operations", "fixed_register", key, "evaluated", "withheld", "lint",
                            {"why": "no register evidence row", "engine": [offset, size]}))
            continue
        same = (row.byte_offset, row.byte_size) == (offset, size)
        rows.append(Row("operations", "fixed_register", key, "evaluated", "applied" if same else "unsupported",
                        "lint", {"evidence": [row.byte_offset, row.byte_size], "engine": [offset, size]}))
    applicable = sorted(model.file_id for model in models if language in model.languages)
    rows.append(Row("operations", "pcodeop_language", "program", "evaluated",
                    "applied" if applicable else "not_applicable", "lint",
                    {"language": list(language), "models": applicable, "model_files": model_paths}))
    return rows


# -- per function ------------------------------------------------------------------------

def _raw_observation(generation: Path, claim) -> dict | None:
    if claim.observation_member is None:
        return None
    manifest = json.loads((generation / "manifest.json").read_bytes())
    path = next((row["path"] for row in manifest["members"] if row["id"] == claim.observation_member), None)
    if path is None:
        return None
    try:
        return json.loads((generation / path).read_bytes())
    except ValueError:
        return None


def source_rows(claim, raw) -> list[Row]:
    """A refused function's own instruction array, keyed by index (an address
    may be missing or repeated); nothing is validated, so ``not_reached``."""
    rows = []
    instructions = raw.get("instructions") if isinstance(raw, dict) else None
    if not isinstance(instructions, list):
        return [Row("operations", "source_rows", claim.function_id, "not_reached", None, "lint",
                    {"why": "no instruction array"})]
    for index, item in enumerate(instructions):
        address = item.get("address") if isinstance(item, dict) else None
        ops = item.get("operations") if isinstance(item, dict) else None
        rows.append(Row("operations", "source_row", source_row_key(claim.function_id, index), "not_reached", None,
                        "lint", {"address": _raw_coord(address) if isinstance(address, dict) else None,
                                 "opcodes": [op.get("opcode") for op in ops if isinstance(op, dict)]
                                 if isinstance(ops, list) else None}))
    return rows


def _resolution(naming):
    from tdo_v2.integration.configured_target_resolution import _selected_resolved_target

    target = _selected_resolved_target(naming)
    aliases = sorted({alias.value for alias in (() if target is None else target.aliases) if alias.policy_admissible})
    state = naming.resolution.state.value
    verdict = "applied" if state in ("RESOLVED_NAMED", "RESOLVED_UNNAMED") else \
        "not_applicable" if state == "INDIRECT" else "unrecognized"
    return target, aliases, state, verdict


def call_rows(claim, function_keys) -> list[Row]:
    from tdo_v2.call_relations import call_relations
    from tdo_v2.control_projection import call_like_instruction, control_successor_coordinates
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
    relations = call_relations(observation, unit.scopes)
    from tdo_v2 import isa_identity

    parts = tuple(unit.scopes.program.evidence.translation_namespace.language_id.split(":"))[:3]
    pushes = parts not in isa_identity._LINK_REGISTERS
    rows = []
    for seed, naming in zip(evidence.seeds.callsites, evidence.naming.rows, strict=True):
        key = operation_row_key(claim.function_id, seed.operation_key)
        target, aliases, state, verdict = _resolution(naming)
        instruction = by_address[seed.locator.instruction]
        opcode = seed.operation_key.rsplit(":", 1)[1]
        successors = control_successor_coordinates(instruction, local_addresses=local, function_entry=entry)
        pads = _landing_pads(instruction, local, entry, successors) if call_like_instruction(instruction) else ()
        rows.append(Row("operations", "call", key, "evaluated", verdict, "lint", {
            "opcode": opcode, "resolution": state,
            "reason": None if naming.resolution.reason is None else naming.resolution.reason.value,
            "target": None if target is None else _coord(target.coordinate),
            "target_is_function": target is not None and _coord(target.coordinate) in function_keys,
            "aliases": aliases,
            "flow_targets": sorted(_coord(item) for item in instruction.flow_targets),
            "successors": sorted(_coord(item) for item in successors),
            "local_successors": sorted(_coord(item) for item in successors if item in local),
            "landing_pads": sorted(_coord(item) for item in pads),
        }))
        # the recognisers as verdict rows (Fable impl r1 P1-2). Criteria (Astra impl r2
        # P1, Fable impl r2 P2-1): on an ISA whose calls push the continuation (no
        # link register in isa_identity's table) the projection and the push relation
        # apply to every native call (CALL / CALLIND), _plain_push_call to a direct
        # CALL; on a link-register ISA the push rows are not_applicable and the link
        # relation applies to every native call.
        relation = relations.get(seed.operation_key)
        if pushes:
            checks = (
                ("push_projection", True, seed.operation_key in projected),
                ("plain_push", opcode == "CALL", bool(memory_space is not None and opcode == "CALL"
                                                      and _plain_push_call(unit, seed.operation_key, memory_space))),
                ("push_relation", True, relation is not None and relation.kind == "push"),
            )
        else:
            checks = (("push_projection", False, False), ("plain_push", False, False),
                      ("push_relation", False, False),
                      ("link_relation", True, relation is not None and relation.kind == "link"))
        for check, applies, held in checks:
            if not applies:
                rows.append(Row("operations", check, key, "evaluated", "not_applicable", "lint"))
            else:
                # (plain_push is recognition only: the callee state proof is separate, interprocedural.py:1224)
                rows.append(Row("operations", check, key, "evaluated", "applied" if held else "unrecognized",
                                "engine"))
    return rows


def tail_rows(claim, function_keys) -> list[Row]:
    """Tail-call naming (``naming.tail_rows`` aligned with ``evidence.tails``)."""
    evidence = claim.evidence
    rows = []
    for seed, naming in zip(evidence.tails, evidence.naming.tail_rows, strict=True):
        target, aliases, state, verdict = _resolution(naming)
        rows.append(Row("operations", "tail_call", operation_row_key(claim.function_id, seed.operation_key),
                        "evaluated", verdict, "lint", {
                            "resolution": state,
                            "reason": None if naming.resolution.reason is None else naming.resolution.reason.value,
                            "target": None if target is None else _coord(target.coordinate),
                            "target_is_function": target is not None and _coord(target.coordinate) in function_keys,
                            "aliases": aliases}))
    return rows


def exit_rows(claim, raw, function_keys, superseded=False) -> list[Row]:
    """S1 fallthrough exits as ``(source, target, kind, function)`` keyed by the
    member's own array index; ``reach_edge`` applies the engine's rule
    (control_context.py:104, pinned by a guard) to the functions this Bundle
    admitted -- the engine uses its published results, so a function that later
    fails normalisation still counts here (``source: lint``)."""
    validated = {(_coord(row.source), _coord(row.target), row.kind, _coord(row.function))
                 for row in getattr(claim.unit.observation, "fallthrough_exits", ())}
    rows = []
    raw_exits = raw.get("fallthrough_exits", []) if isinstance(raw, dict) else []
    for index, item in enumerate(raw_exits if isinstance(raw_exits, list) else []):
        try:
            value = (_raw_coord(item["source"]), _raw_coord(item["target"]), item["kind"],
                     _raw_coord(item["function"]) if item.get("function") is not None else None)
        except (KeyError, TypeError):
            value = None
        key = source_row_key(claim.function_id, index)
        if value is None or value not in validated:
            rows.append(Row("operations", "s1_exit", key, "evaluated", "unrecognized", "lint",
                            {"raw": item if isinstance(item, dict) else None}))
            continue
        source, target, kind, function = value
        # (a member another member of the same entry replaces is never the one the
        # summary analyses, summary_engine.py:412: no edge from it -- Astra impl r2 P2)
        reach = function is not None and function in function_keys and not superseded
        detail = {"source": source, "target": target, "kind": kind, "function": function, "reach_edge": reach}
        if superseded:
            detail["superseded_by_duplicate_entry"] = True
        rows.append(Row("operations", "s1_exit", key, "evaluated", "applied" if reach else "not_applicable",
                        "lint", detail))
    return rows


def branchind_rows(claim, raw) -> list[Row]:
    """Every row with a BRANCHIND (any ordinal): the member's own target list,
    the validated ``flow_targets`` and the engine's local successors (facts);
    the verdict is the engine's own predicate ``unknown_transfer_sites``
    (control_context.py:62): an unknown transfer -> ``withheld`` (Astra impl r2 P1)."""
    from tdo_v2.control_context import site_key, unknown_transfer_sites
    from tdo_v2.control_projection import control_successor_coordinates

    unit = claim.unit
    entry = claim.entry
    unknown = unknown_transfer_sites(entry, unit.observation)
    local = {row.address for row in unit.observation.instructions}
    raw_rows = {}
    for item in (raw.get("instructions", []) if isinstance(raw, dict) else []):
        if isinstance(item, dict):
            raw_rows.setdefault(_raw_coord(item.get("address")), item)
    rows = []
    for instruction in unit.observation.instructions:
        if not any(operation.opcode == "BRANCHIND" for operation in instruction.operations):
            continue
        site = site_key(entry, instruction.address)
        item = raw_rows.get(_coord(instruction.address), {})
        successors = control_successor_coordinates(instruction, local_addresses=local,
                                                   function_entry=unit.scopes.function.entry)
        rows.append(Row("operations", "branchind", f"{claim.function_id}/{site}", "evaluated",
                        "withheld" if site in unknown else "applied", "engine", {
                            "unknown_transfer": site in unknown,
                            "raw_targets": sorted(str(_raw_coord(t)) for t in item.get("flow_targets", [])
                                                  if isinstance(t, dict)),
                            "flow_targets": sorted(_coord(t) for t in instruction.flow_targets),
                            "local_successors": sorted(_coord(t) for t in successors if t in local)}))
    return rows


def rep_rows(claim) -> list[Row]:
    """rep string sites the engine recognises (``rep_strings.rep_sites``): their
    proof inside the summary run is not public -> application rows in layer 3."""
    from tdo_v2.rep_strings import rep_sites

    return [Row("operations", "rep_site", f"{claim.function_id}/{_coord(address)}", "evaluated", "applied", "engine")
            for address in sorted(rep_sites(claim.unit.observation), key=lambda a: (a.space_id, a.byte_offset))]


def callother_rows(claim, models) -> list[Row]:
    """Every CALLOTHER (``callother_model_match``, a lint diagnostic -- the
    summary applies a model only when it is given one, layer 3):
    no-effect / trap model match via the engine (``no_effect_calls`` /
    ``trap_operations``), the intrinsic refinement (``refinements_for``).
    Verdicts (Fable impl r1 P2-2): matched -> applied; an index a model lists
    but whose shape or operand does not match -> unrecognized (no-effect) /
    not_applicable (trap index, other operand); an index no model lists ->
    not_applicable (``no_model``); no model for the language -> unsupported."""
    from tdo_v2._scope_contracts import VarnodeKindCode
    from tdo_v2.call_seeds import _operation_key
    from tdo_v2.intrinsic_refinements import refinements_for
    from tdo_v2.pcodeop_models import no_effect_calls, trap_operations

    unit = claim.unit
    namespace = unit.scopes.program.evidence.translation_namespace
    language = (namespace.language_id, namespace.major_version, namespace.minor_version)
    applicable = [model for model in models if language in model.languages]
    no_effect = no_effect_calls(unit, models)
    traps = trap_operations(unit, models)
    refined = refinements_for(unit)
    rows = []
    for instruction in unit.observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            if operation.opcode != "CALLOTHER":
                continue
            op_key = _operation_key(instruction.address, ordinal, operation.opcode)
            constants = [item.coordinate.byte_offset if item.kind is VarnodeKindCode.CONSTANT else None
                         for item in operation.inputs]
            index = constants[0] if constants else None
            listed_no_effect = index is not None and any(index in model.no_effect for model in applicable)
            listed_trap = index is not None and any(index in (model.traps or {}) for model in applicable)
            detail = {"index": index, "operands": constants[1:], "models": [m.file_id for m in applicable],
                      "no_effect": op_key in no_effect, "trap_match": op_key in traps,
                      "refinement": op_key in refined, "output": operation.output is not None}
            if not applicable:
                verdict = "unsupported"
            elif op_key in no_effect or op_key in traps:
                verdict = "applied"
            elif listed_no_effect:
                verdict = "unrecognized"
            else:
                verdict = "not_applicable"
                if not listed_trap:
                    detail["no_model"] = True
            rows.append(Row("operations", "callother_model_match", operation_row_key(claim.function_id, op_key),
                            "evaluated", verdict, "lint", detail))
    return rows


def model_paths(options) -> list[str]:
    """The p-code op model files of the diagnostics: the summary's own
    (``pcodeop_models``) when given (Astra impl r1 P2), else the shipped ones."""
    paths = options.get("pcodeop_models")
    if paths is None:
        paths = sorted(str(path) for path in (REPO / "models" / "pcodeops").glob("*.json"))
    return list(paths)


def rows(diagnosis, generation, options) -> list[Row]:
    from tdo_v2._scope_results import ConstructedProgramScope
    from tdo_v2.pcodeop_models import load_pcodeop_models

    program = diagnosis.program_value
    if type(program) is not ConstructedProgramScope:
        return []
    paths = model_paths(options)
    models = load_pcodeop_models(paths)
    out = register_rows(program) + convention_rows(program, models, paths)
    function_keys = {claim.entry for claim in diagnosis.claims if claim.entry}
    last = {}
    for claim in diagnosis.claims:
        if claim.evidence is not None:
            last[claim.entry] = claim
    for claim in diagnosis.claims:
        try:
            raw = _raw_observation(generation, claim)
            if claim.scope != "constructed":
                out.extend(source_rows(claim, raw))
                continue
            if claim.evidence is None:
                continue
            out.extend(call_rows(claim, function_keys))
            out.extend(tail_rows(claim, function_keys))
            out.extend(exit_rows(claim, raw, function_keys, superseded=last.get(claim.entry) is not claim))
            out.extend(branchind_rows(claim, raw))
            out.extend(rep_rows(claim))
            out.extend(callother_rows(claim, models))
        except Exception as error:   # (one function's rows never stop the report)
            out.append(Row("operations", "layer_error", claim.function_id or f"#{claim.index}", "error", None,
                           "lint", {"class": type(error).__qualname__, "message": str(error)}))
    return out
