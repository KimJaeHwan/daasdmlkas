"""A summarized callee's entry loads at the return-address slot the CALL
pushed. The persistent SSA drops the CALL's transient operations
(``observed_call_state``), so the push comes back as a definition: the call
row ``~push`` (``normalize._push_row``). Every read form -- plain ``[RSP]``,
indexed ``[RSP + RDX]``, an RCX = RSP-8 alias, a pointer slot holding it --
then reaches the pushed return address by ordinary reaching definitions,
and a read through another base gets ``may_alias``'s debt for that write
unless the frame rule excludes it (docs 25.72 / 25.73)."""

import json

import synthetic
import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    CODE_BASE, R8, R9, RAX, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const, copy, load, op,
    program_units, reg, slice_from,
    store, sub, tmp,
)
from tdo_v2.interprocedural import analyze_units
from tdo_v2.graph import CONTROL_DEPENDENCE_EDGE
from tdo_v2.span_geometry import StorageObjectKind

CALLEE = CODE_BASE + 0x800


def _program(prelude=()):
    t = tmp(0x100)
    caller = FunctionBuilder().ins(*prelude, copy(reg(RDX), const(0)), sub(t, reg(RSP), const(8)),
                                   store(t, const(0x1400)))
    after = caller._address(len(caller._rows) + 3)   # (the call below is the third row from here)
    caller = (caller.ins(store(const(after + 0x3000), reg(RSI)))
              .ins(store(const(0x1400 + 0x3000), reg(RDI)))
              .call(CALLEE)
              .ins(add(t, reg(RAX), const(0x3000)), load(reg(RBX), t))
              .ret())
    callee = FunctionBuilder(entry=CALLEE).ins(add(tmp(0x200), reg(RSP), reg(RDX)), load(reg(RAX), tmp(0x200))).ret()
    return caller, callee, after


def test_an_indexed_read_of_the_pushed_return_address_is_not_the_pre_call_value():
    caller, callee, _ = _program()
    units = program_units(caller, callee)
    analyzed = analyze_units(units)["1:1000"]
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    report = check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=range(6),
                           register_pools=pools, havoc_calls=(REG, RSP, 8))
    assert report.checked and report.silent == [], report.silent[:4]
    # (``[SP + RDX]``: SP plus another atom -- a wild object, which the push reaches as debt)
    assert _push_debt(analyzed) == _entry_loads(analyzed)


def _checked(callee_read, prelude=(), registers=None, **options):
    """The program above with the callee's read replaced (and ``prelude`` run
    first in the caller; ``registers``: entry values fixed for every run;
    ``options``: for ``analyze_units``): (analyzed caller, report)."""
    caller, _, _ = _program(prelude)
    callee = FunctionBuilder(entry=CALLEE).ins(*callee_read).ret()
    units = program_units(caller, callee)
    analyzed = analyze_units(units, **options)["1:1000"]
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000, **(registers or {})}
    report = check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=range(6),
                           register_pools=pools, havoc_calls=(REG, RSP, 8))
    return analyzed, report


def _call(analyzed):
    return next(key for key in analyzed.proven if key.endswith(":CALL"))


def _slot_fragments_not_from_push(analyzed):
    """Fragments of the call's entry loads, on the bytes the push wrote,
    whose definition is not the push: the pre-call bytes underneath it."""
    ssa = analyzed.normalized.memory_ssa
    call = _call(analyzed)
    (pushed,) = [item.span for item in ssa.definitions if item.operation_key == call + "~push"]
    return [fragment for read in ssa.reads
            if ssa.actions[read.action_id].operation_key.startswith(call + "~ld")
            for fragment in read.fragments if fragment.span.overlaps(pushed)
            and ssa.definitions[fragment.definition_ids[0]].operation_key != call + "~push"]


def _push_debt(analyzed):
    """The call's entry loads that carry may-alias debt for the push."""
    call = _call(analyzed)
    return {row.operation_key for row in analyzed.normalized.may_alias_reads
            if row.operation_key.startswith(call + "~ld") and call + "~push" in row.writers}


def _entry_loads(analyzed):
    """The call's entry loads not bound to the push's object (another base;
    the callee's own return read of ``[RSP]`` is on it, exactly)."""
    ssa = analyzed.normalized.memory_ssa
    call = _call(analyzed)
    (pushed,) = [item.span for item in ssa.definitions if item.operation_key == call + "~push"]
    on_stack = {ssa.actions[read.action_id].operation_key for read in ssa.reads
                if read.span.object_id == pushed.object_id}
    return {action.operation_key for action in ssa.actions
            if action.operation_key.startswith(call + "~ld") and action.operation_key not in on_stack}


def test_a_plain_read_of_the_pushed_return_address_is_not_the_pre_call_value():
    """The same with no index: the callee loads ``[RSP]`` (Fable, the same
    hole on main before the merge -- a summary source at the return-address
    slot was bound to the caller's pre-call bytes)."""
    analyzed, report = _checked((load(reg(RAX), reg(RSP)),))
    assert report.checked and report.silent == [], report.silent[:4]
    assert _slot_fragments_not_from_push(analyzed) == [] and not _push_debt(analyzed)


def test_a_read_above_the_pushed_slot_stays_exact():
    """``[RSP + 8]`` in the callee is the caller's ``[SP]`` before the call:
    clear of the pushed bytes, so it is still bound exactly (no new debt)."""
    analyzed, report = _checked((add(tmp(0x200), reg(RSP), const(8)), load(reg(RAX), tmp(0x200))))
    assert report.checked and report.silent == [] and report.covered_by_debt == []
    call = next(key for key in analyzed.proven if key.endswith(":CALL"))
    assert not any(row.operation_key.startswith(call) for row in analyzed.normalized.call_clobber_reads)


def test_a_read_through_a_register_alias_of_the_slot_is_not_the_pre_call_value():
    """``lea rcx, [rsp - 8]; call f`` and the callee loads ``[RCX]``: the
    anchor is not the stack pointer, but its value is the pushed slot
    (Fable, review of the plain-read fix)."""
    analyzed, report = _checked((load(reg(RAX), reg(RCX)),), prelude=(sub(reg(RCX), reg(RSP), const(8)),))
    assert report.checked and report.silent == [], report.silent[:4]
    assert _slot_fragments_not_from_push(analyzed) == [] and not _push_debt(analyzed)


def test_a_read_through_a_pointer_slot_holding_the_slot_is_not_the_pre_call_value():
    """The same address stored in a global the callee loads first:
    ``[[0x2000]]`` with ``[0x2000] = RSP - 8`` (Fable, the same review)."""
    t = tmp(0x300)
    analyzed, report = _checked((load(reg(RCX), const(0x2000)), load(reg(RAX), reg(RCX))),
                                prelude=(sub(t, reg(RSP), const(8)), store(const(0x2000), t)))
    assert report.checked and report.silent == [], report.silent[:4]
    assert _slot_fragments_not_from_push(analyzed) == []


def test_a_read_through_the_stack_pointer_plus_a_register_is_not_bound():
    """``lea rcx, [rsp + r8 - 8]``: not the stack pointer's own atoms, yet
    the pushed slot whenever R8 is 0 -- a stack-derived base is never bound
    to pre-call bytes (Astra, round 2)."""
    t = tmp(0x300)
    analyzed, report = _checked((load(reg(RAX), reg(RCX)),),
                                prelude=(add(t, reg(RSP), reg(R8)), sub(reg(RCX), t, const(8))))
    assert report.checked and report.silent == [], report.silent[:4]
    assert _push_debt(analyzed) == _entry_loads(analyzed)


def test_a_read_through_the_callers_entry_pointer_is_still_bound():
    """The callee reads ``[RCX]`` with RCX the caller's own entry value: no
    entry value addresses the caller's new frame, where the slot lies (the
    named assumption ``may_alias`` uses, reported), so it binds exactly."""
    analyzed, report = _checked((load(reg(RAX), reg(RCX)),))
    assert report.checked and report.silent == [], report.silent[:4]
    assert not _push_debt(analyzed) and analyzed.normalized.assumes_entry_values_not_frame


def test_a_store_and_read_through_the_stack_pointer_plus_a_register_is_not_the_stored_value():
    """``rcx = rsp + r8; [rcx] = 0x1400; call f`` with R8 = -8 at run time,
    the callee reads ``[RCX]``: the caller's own store is the one reaching
    definition of that object, so binding it would be a complete, wrong
    slice (Fable, round 2)."""
    analyzed, report = _checked((load(reg(RAX), reg(RCX)),),
                                prelude=(add(reg(RCX), reg(RSP), reg(R8)), store(reg(RCX), const(0x1400))),
                                registers={R8: (1 << 64) - 8})
    assert report.checked and report.silent == [], report.silent[:4]
    assert _push_debt(analyzed) == _entry_loads(analyzed)


def test_an_entry_pointer_read_is_not_bound_with_the_frame_assumption_off():
    """Entry R9 = RSP - 8 (the caller's own pushed slot); the caller stores
    through R9 and the callee reads ``[R9]``. With entry-values-do-not-
    address-the-new-frame switched off nothing excludes the slot: refused
    (Astra, round 3)."""
    analyzed, report = _checked((load(reg(RAX), reg(R9)),), prelude=(store(reg(R9), const(0x1400)),),
                                registers={R9: 0x7000_0000 - 8}, assume_entry_values_not_frame=False)
    assert report.checked and report.silent == [], report.silent[:4]
    assert _push_debt(analyzed) == _entry_loads(analyzed)
    assert not analyzed.normalized.assumes_entry_values_not_frame


def test_an_entry_pointer_read_after_an_earlier_stack_escape_follows_the_frame_rule():
    """``[0x2000] = RSP - 8`` before the call, nothing escaping after it: the
    push is a frame write like any other -- private by ``may_alias``'s rule
    (no escape reachable from it), so it reaches no entry-value object; a
    read through the caller's entry R9 stays exact (entry R9 is fixed before
    the escape)."""
    t = tmp(0x300)
    analyzed, report = _checked((load(reg(RAX), reg(R9)),),
                                prelude=(sub(t, reg(RSP), const(8)), store(const(0x2000), t),
                                         store(reg(R9), const(0x1400))))
    assert report.checked and report.silent == [], report.silent[:4]
    assert not _push_debt(analyzed)


def test_an_absolute_read_of_the_slot_is_not_bound_with_both_assumptions_off():
    """The callee reads the constant address ``0x6ffffff8`` -- the pushed
    slot when the stack sits at ``0x70000000``. With entry-values-do-not-
    address-the-new-frame and globals-disjoint-from-stack both off nothing
    excludes it: not bound (Astra, round 4: 144 silent dependencies)."""
    slot = 0x7000_0000 - 8
    analyzed, report = _checked((load(reg(RAX), const(slot)),), prelude=(store(const(slot), const(0x1400)),),
                                assume_entry_values_not_frame=False)
    assert report.checked and report.silent == [], report.silent[:4]
    assert _push_debt(analyzed) == _entry_loads(analyzed)


def test_an_absolute_read_is_bound_under_globals_disjoint_from_stack():
    """The same read with globals-disjoint-from-stack taken: a constant is
    never a stack address, so it binds exactly (precision kept)."""
    analyzed, report = _checked((load(reg(RAX), const(0x2000)),), assume_entry_values_not_frame=False,
                                assume_globals_disjoint_from_stack=True)
    assert report.checked and report.silent == [], report.silent[:4]
    assert not _push_debt(analyzed)


def test_a_slot_read_in_another_space_is_not_the_return_address(monkeypatch):
    """The callee's ``[RSP]`` in space 5, the push in RAM (space 1): not the
    pushed slot, so not the return address -- it is the caller's space-5
    store (Astra, round 7: a no-input definition there was a silent miss)."""
    other = 5
    original = synthetic.parse_raw_json

    def parse(text):
        data = json.loads(text)
        if isinstance(data, dict) and "address_spaces" in data and all(
                row["space_id"] != other for row in data["address_spaces"]):
            data["address_spaces"].append(synthetic._space(other, mem=True))
        return original(json.dumps(data))

    monkeypatch.setattr(synthetic, "parse_raw_json", parse)
    t = tmp(0x300)
    analyzed, report = _checked((op("LOAD", [const(other), reg(RSP)], reg(RAX)),),
                                prelude=(sub(t, reg(RSP), const(8)), op("STORE", [const(other), t, reg(RDX)])))
    assert report.checked and report.silent == [], report.silent[:4]


def test_a_stack_argument_to_the_call_itself_keeps_an_entry_pointer_read_exact():
    """``lea rcx, [rsp - 8]; call f`` (the call itself receives a stack
    address: a stack escape at the CALL) and the callee reads ``[R9]``, R9
    the caller's entry value: at callee entry nothing has run since the push,
    so the push reaches other objects only at the CALL (``may_alias``
    ``push_deferred``) -- the read stays exact (docs 25.73 B)."""
    analyzed, report = _checked((load(reg(RAX), reg(R9)), load(reg(RBX), reg(RCX))),
                                prelude=(sub(reg(RCX), reg(RSP), const(8)),))
    assert report.checked and report.silent == [], report.silent[:4]
    assert not _push_debt(analyzed) and _slot_fragments_not_from_push(analyzed) == []


def test_the_callers_read_below_its_stack_after_the_return_is_the_push():
    """After the call the caller reads ``[RSP - 8]``: the bytes the push wrote
    (the callee left them), not the caller's earlier store there."""
    t, u = tmp(0x300), tmp(0x310)
    caller = (FunctionBuilder().ins(sub(t, reg(RSP), const(8)), store(t, reg(RDI)))
              .call(CALLEE).ins(sub(u, reg(RSP), const(8)), load(reg(RAX), u)).ret())
    callee = FunctionBuilder(entry=CALLEE).ins(copy(reg(RBX), const(1))).ret()
    units = program_units(caller, callee)
    analyzed = analyze_units(units)["1:1000"]
    ssa = analyzed.normalized.memory_ssa
    (pushed,) = [item.span for item in ssa.definitions if item.operation_key == _call(analyzed) + "~push"]
    (read,) = [read for read in ssa.reads if ssa.actions[read.action_id].operation_key.endswith(":LOAD")
               and read.span.overlaps(pushed)]
    assert {ssa.definitions[fragment.definition_ids[0]].operation_key for fragment in read.fragments} \
        == {_call(analyzed) + "~push"}


def test_a_call_in_a_loop_receiving_a_stack_address_keeps_the_entry_read_exact():
    """The same call in a loop: on the second iteration the earlier CALL's
    escape precedes this one -- the push then reaches other objects before
    the callee's entry loads (escapes strictly before the call, Fable)."""
    flag = tmp(0x400, 1)
    caller = (FunctionBuilder().sub_rsp(0x20)
              .label("top").ins(sub(reg(RCX), reg(RSP), const(8))).call(CALLEE)
              .cbranch("top", flag, op("INT_NOTEQUAL", [reg(RSI), const(0)], flag))
              .add_rsp(0x20).ret())
    # (the callee uses RCX as an address: the call is an escape)
    callee = FunctionBuilder(entry=CALLEE).ins(load(reg(RAX), reg(R9)), load(reg(RBX), reg(RCX))).ret()
    units = program_units(caller, callee)
    analyzed = analyze_units(units)["1:1000"]
    assert _push_debt(analyzed) == _entry_loads(analyzed) != set()


def test_an_escape_before_an_escaping_call_keeps_the_pushs_debt():
    """``[0x2000] = RSP - 8`` (an escape) before a call that itself receives
    a stack address: no deferral (escapes strictly before the call) -- the
    push reaches the other objects at once, so the callee's entry read
    through R9 carries its debt, as any frame write followed by an escape
    (Astra / Fable, push-definition design review)."""
    t = tmp(0x300)
    analyzed, report = _checked((load(reg(RAX), reg(R9)), load(reg(RBX), reg(RCX))),
                                prelude=(sub(t, reg(RSP), const(8)), store(const(0x2000), t),
                                         sub(reg(RCX), reg(RSP), const(8))))
    assert report.checked and report.silent == [], report.silent[:4]
    assert _push_debt(analyzed) == _entry_loads(analyzed) != set()


def test_a_conditional_calls_push_depends_on_its_condition():
    """``[SP - 8] = 0x1234; if (RSI) call f; RAX = [SP - 8]``: the bytes are
    the old constant or the return address -- which one rests on RSI, so the
    push has the CALL's control dependence edge, as a conditional STORE has
    (Astra, push-definition review; the data slice itself excludes control
    edges for every write alike)."""
    flag, t, u = tmp(0x400, 1), tmp(0x300), tmp(0x310)
    caller = (FunctionBuilder().ins(sub(t, reg(RSP), const(8)), store(t, const(0x1234)))
              .cbranch("skip", flag, op("INT_EQUAL", [reg(RSI), const(0)], flag))
              .call(CALLEE).label("skip").ins(sub(u, reg(RSP), const(8))))
    reader = f"1:{caller._address(len(caller._rows)):x}:0:LOAD"
    caller.ins(load(reg(RAX), u)).ret()
    callee = FunctionBuilder(entry=CALLEE).ins(copy(reg(RBX), const(1))).ret()
    function = analyze_units(program_units(caller, callee))["1:1000"].normalized
    graph = function.dependencies
    call = next(row.dependent for row in function.control_dependences if row.dependent.endswith(":CALL"))
    deciders = {graph.node(source).key for source, _, record in graph.in_edges(graph.node_for_key(f"op:{call}~push"))
                if record.kind == CONTROL_DEPENDENCE_EDGE}
    assert deciders == {f"op:{row.decision}" for row in function.control_dependences if row.dependent == call} != set()
    found = slice_from(function, graph.node_for_key("op:" + reader))
    assert set(range(RSP, RSP + 8)) <= found.register_bytes   # (and the push reached: the read is complete)
    assert found.is_complete
