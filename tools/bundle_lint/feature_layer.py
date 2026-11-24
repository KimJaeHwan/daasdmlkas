"""Layer 3 ``features`` of ``bundle_lint`` (design G0 r0..r6).

In the diagnosis process: the stack-pointer identification of every admitted
function (``may_alias._stack_pointer``, compared by success / register /
width / memory space -- never by object id, r6 s6), and, with
``lint_normalize``, a standalone ``FunctionNormalizer.normalize`` per function
under the same execution context the summary sets (r6 s4) -- labelled
``standalone``: it has no proven call effects, so it is not the summary's
result. Per-site application inside the summary run (traps, rep) is not
public: those rows are ``unobserved`` (built by ``lint.py``, r5 s1).
"""

from __future__ import annotations

from report import Row, operation_row_key

# the summary entry's defaults (summary_engine.analyze_frozen_bundle_with_summaries)
DEFAULTS = {
    "assume_globals_disjoint_from_stack": True,
    "assume_readonly_image_constant": True,
    "assume_direction_flag_clear": True,
    "assume_import_slots_hold_exports": True,
    "assume_entry_values_not_frame": True,
    "assume_opaque_callees_leave_no_stack_addresses": True,
    "assume_pre_escape_values_not_frame": True,
    "assume_opaque_callees_restore_stack_pointer": True,
    "assume_win64_home_space_private": True,
}


def stack_rows(claim) -> list[Row]:
    from tdo_v2.may_alias import _stack_pointer, _unit_stub

    scopes = claim.unit.scopes
    found = _stack_pointer(_unit_stub(scopes), claim.unit.observation, scopes.resolution_context,
                           scopes.program.evidence.address_spaces)
    if found is None:
        return [Row("features", "stack_pointer", claim.function_id, "evaluated", "withheld", "engine")]
    _, bias, register_space, offset, size = found
    from tdo_v2._scope_contracts import VarnodeKindCode

    spaces = sorted({operation.inputs[0].coordinate.byte_offset for instruction in claim.unit.observation.instructions
                     for operation in instruction.operations
                     if operation.opcode in ("LOAD", "STORE") and operation.inputs
                     and operation.inputs[0].kind is VarnodeKindCode.CONSTANT})
    # (the object id is never compared: it changes with the observation digest, r6 s6)
    return [Row("features", "stack_pointer", claim.function_id, "evaluated", "applied", "engine",
                {"register_space": register_space, "register_offset": offset, "register_size": size,
                 "address_bits": bias.bit_length() - 1, "memory_spaces": spaces})]


class StandaloneContext:
    """The context variables the summary sets around its run
    (interprocedural.py:282-288), set / reset here for standalone runs."""

    def __init__(self, options: dict, image_info, units=(), evidences=()) -> None:
        self.options = {name: options.get(name, value) for name, value in DEFAULTS.items()}
        self.image_info = image_info
        self.units = tuple(units)        # one per entry, the last member (summary_engine.py:412)
        self.evidences = tuple(evidences)
        self.home_space = 0
        self.switches_stack = False
        self._tokens = []

    def __enter__(self):
        import sys

        from tdo_v2.call_clobber import OPAQUE_RESTORES_SP
        from tdo_v2.interprocedural import ANALYSIS_RECURSION_LIMIT
        from tdo_v2.may_alias import ENTRY_VALUES_NOT_FRAME, OPAQUE_NO_STACK_ADDRESSES, PRE_ESCAPE_NOT_FRAME
        from tdo_v2.relative_memory import IMPORT_SLOTS, ImportSlots

        from tdo_v2.interprocedural import program_switches_stack

        o = self.options
        # interprocedural.py:641-650: a stack switch anywhere withdraws
        # globals-disjoint-from-stack, and the import atoms follow that switch
        if o["assume_globals_disjoint_from_stack"] and program_switches_stack(self.units):
            self.switches_stack = True
            o["assume_globals_disjoint_from_stack"] = False
        slots = ImportSlots(self.image_info) if o["assume_import_slots_hold_exports"] and self.image_info else None
        if slots is not None:
            slots.active = o["assume_globals_disjoint_from_stack"]
        # win64-home-space-callee-private: summary_engine.py:503 (Astra impl r1 P2)
        from tdo_v2.summary_engine import _x86_64

        info = self.image_info
        self.home_space = 0x28 if o["assume_win64_home_space_private"] and o["assume_entry_values_not_frame"]             and info is not None and info.executable_format.startswith("Portable Executable")             and _x86_64(self.evidences) else 0
        self._tokens = [
            (IMPORT_SLOTS, IMPORT_SLOTS.set(slots)),
            (ENTRY_VALUES_NOT_FRAME, ENTRY_VALUES_NOT_FRAME.set(bool(o["assume_entry_values_not_frame"]))),
            (OPAQUE_NO_STACK_ADDRESSES,
             OPAQUE_NO_STACK_ADDRESSES.set(bool(o["assume_opaque_callees_leave_no_stack_addresses"]))),
            (PRE_ESCAPE_NOT_FRAME, PRE_ESCAPE_NOT_FRAME.set(bool(o["assume_pre_escape_values_not_frame"]))),
            (OPAQUE_RESTORES_SP, OPAQUE_RESTORES_SP.set(bool(o["assume_opaque_callees_restore_stack_pointer"]))),
        ]
        self._limit = sys.getrecursionlimit()
        sys.setrecursionlimit(max(self._limit, ANALYSIS_RECURSION_LIMIT))
        return self

    def __exit__(self, *exc) -> None:
        import sys

        sys.setrecursionlimit(self._limit)
        for variable, token in reversed(self._tokens):
            variable.reset(token)
        self._tokens = []

    def header(self) -> dict:
        from tdo_v2.relative_memory import IMPORT_SLOTS

        slots = IMPORT_SLOTS.get()
        return {**self.options, "import_slots_context": slots is not None,
                "import_slots_active": slots is not None and slots.active,
                "stack_switch_withdrew_globals": self.switches_stack, "private_frame_above": self.home_space,
                "stack_evidence": "none (the summary's stack_evidence default)"}


def readonly_image(generation, image_info, options):
    """Exactly as summary_engine.py:206-210 (Fable r6 P3-1)."""
    from tdo_v2.image_info import ReadOnlyImage

    assume = options.get("assume_readonly_image_constant", DEFAULTS["assume_readonly_image_constant"])
    return ReadOnlyImage(generation, image_info) if assume and image_info is not None else None


def normalize_rows(claim, image, context) -> list[Row]:
    from tdo_v2.interprocedural import ANALYSIS_FAILURES, _failure_reason
    from tdo_v2.resource_limits import RESOURCE_FAILURES
    from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction
    from tdo_v2.rep_strings import rep_sites

    o = context.options
    key = claim.function_id
    try:
        result = FunctionNormalizer().normalize(
            claim.unit, assume_globals_disjoint_from_stack=o["assume_globals_disjoint_from_stack"],
            readonly_image=image, assume_direction_flag_clear=o["assume_direction_flag_clear"],
            private_frame_above=context.home_space)
    except RESOURCE_FAILURES as error:   # (a resource failure is no verdict: Astra impl r4 P2)
        reason = _failure_reason(error).value if isinstance(error, ANALYSIS_FAILURES) else type(error).__name__
        return [Row("features", "standalone_normalize", key, "error", None, "lint",
                    {"reason": reason, "detail": str(error)})]
    if type(result) is not NormalizedFunction:
        return [Row("features", "standalone_normalize", key, "evaluated", "refused", "engine",
                    {"reason": getattr(result.reason, "value", str(result.reason)),
                     "detail": str(getattr(result, "detail", "") or "")})]
    uses = tuple(result.premise_uses)
    rows = [Row("features", "standalone_normalize", key, "evaluated", "applied", "engine",
                {"premises": sorted({name for name, _, _ in uses}),
                 "import_slots": result.assumes_import_slots_hold_exports})]
    for name, _, where in uses:
        if name == "readonly-image-data-is-constant":
            rows.append(Row("features", "readonly_use", f"{key}/{where}", "evaluated", "applied", "engine"))
    from tdo_v2.normalize import _coordinate_key

    proven = {item[0]: item for item in result.rep_blocks}
    for address in sorted(rep_sites(claim.unit.observation), key=lambda a: (a.space_id, a.byte_offset)):
        site = _coordinate_key(address)
        hit = proven.get(site)
        if hit is None:
            rows.append(Row("features", "standalone_rep", f"{key}/{site}", "evaluated", "withheld", "engine"))
        else:
            rows.append(Row("features", "standalone_rep", f"{key}/{site}", "evaluated", "applied", "engine",
                            {"count": hit[1], "direction": hit[2]}))
    return rows


def summary_run(results: dict):
    """The summary run whose final columns the site rows read: strict when it
    completed, else retain when it completed (Fable impl r4 P2) -- (name, child)
    or (None, the strict child or None)."""
    for name in ("summary", "summary-retain"):
        child = results.get(name)
        if child is not None and child.get("run_state") == "evaluated" and child.get("completed"):
            return name, child
    return None, results.get("summary")


def site_state(results: dict, superseded: bool, on: bool = True) -> tuple[str, str | None]:
    """(run_state, run name) of a per-site row (Astra impl r5 P2): path or option
    not run -> not_run; child timeout -> timeout; resource exception -> error; a
    pre-analysis stop the diagnosis predicted and the child matched -> not_reached;
    a completed run whose member was replaced by a later one of its entry ->
    not_reached; otherwise a completed run -> evaluated (the caller decides) and
    anything else -> unobserved."""
    import diagnose

    name, child = summary_run(results)
    if child is None or not on:
        return "not_run", None
    if name is not None:
        return ("not_reached" if superseded else "evaluated"), name
    if child.get("run_state") == "timeout":
        return "timeout", None
    if child.get("run_state") != "evaluated" or (child.get("exception") or {}).get("resource"):
        return "error", None
    prediction = results.get("_predictions", {}).get("summary")
    state, verdict, _ = diagnose.check_stop(prediction, child)
    if verdict == "applied" and diagnose.pre_analysis(prediction):
        return "not_reached", None
    return "unobserved", None


def trap_application_rows(op_rows, results: dict, options: dict) -> list[Row]:
    """Per trap site (a ``callother_model_match`` row with ``trap_match``) and rep
    site: whether the summary run applied the cut / proved the rep site is not
    public (r5 s1), so a completed run gives ``unobserved``; the other states by
    ``site_state``."""
    models = options.get("pcodeop_models")
    traps_on = options.get("assume_debug_break_traps_do_not_return", True) and bool(models)
    out = []
    for row in op_rows:
        if row.check == "callother_model_match" and row.detail.get("trap_match"):
            check, on = "trap_application", traps_on
        elif row.check == "rep_site":
            check, on = "rep_application", True   # (rep sites are proved in every summary run)
        else:
            continue
        superseded = bool(row.detail.get("superseded_by_duplicate_entry"))
        state, name = site_state(results, superseded, on)
        if state == "evaluated":
            state = "unobserved"
        out.append(Row("features", check, row.key, state, None, "lint", {"run": name} if name else {}))
    return out


def rows(diagnosis, generation, options) -> list[Row]:
    out = []
    claims = [claim for claim in diagnosis.claims if claim.evidence is not None]
    for claim in claims:
        out.extend(stack_rows(claim))
    if options.get("lint_normalize") and not diagnosis.program.get("ok"):
        # the summary stops at the program check (Astra impl r4 P2)
        out.append(Row("features", "standalone_context", "program", "not_reached", None, "lint",
                       {"why": "program scope refused", "program": diagnosis.program}))
    elif options.get("lint_normalize") and not diagnosis.image_info.get("ok"):
        # the summary stops before its context exists when image-info fails to load
        # (summary_engine.py:205): no standalone run under another condition (Astra impl r3 P2)
        out.append(Row("features", "standalone_context", "program", "not_reached", None, "lint",
                       {"why": "image-info failed to load", "error": diagnosis.image_info.get("error")}))
    elif options.get("lint_normalize"):
        image_info = diagnosis.image_info_value
        image = readonly_image(generation, image_info, options)
        last = {}   # the context: one member per entry, the last, as the summary keeps it (summary_engine.py:412)
        for claim in claims:
            last[claim.entry] = claim
        unique = list(last.values())
        with StandaloneContext(options, image_info, [claim.unit for claim in unique],
                               [claim.evidence for claim in unique]) as context:
            out.append(Row("features", "standalone_context", "program", "evaluated", "applied", "lint",
                           {**context.header(), "readonly_image": image is not None}))
            for claim in claims:   # (every member is normalised: Astra impl r2 P2)
                produced = normalize_rows(claim, image, context)
                if last[claim.entry] is not claim:   # (the mark goes on the normalize row itself)
                    produced = [Row(row.layer, row.check, row.key, row.run_state, row.verdict, row.source,
                                    {**row.detail, "superseded_by_duplicate_entry": True})
                                if row.check == "standalone_normalize" else row for row in produced]
                out.extend(produced)
    return out


__all__ = ("rows", "trap_application_rows", "operation_row_key")
