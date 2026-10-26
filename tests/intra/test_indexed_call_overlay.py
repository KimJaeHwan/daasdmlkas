"""A callee's indexed read of its entry stack (``[SP + RDX]``) may read the
return address the CALL just pushed. The persistent SSA removes that push
(``observed_call_state``), so the caller must not bind such a read to the
pre-call bytes underneath: the read is checked against the push overlay like
an indexed access's base and index inputs (Astra, merge review of the
forward-memory branch: a complete slice missed the real dependency)."""

import json

import synthetic
import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    CODE_BASE, R8, R9, RAX, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const, copy, load, op,
    program_units, reg,
    store, sub, tmp,
)
from tdo_v2.interprocedural import analyze_units
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


def _pushed_slot_reads(analyzed):
    """The call's entry loads bound to the caller's pre-call ``[SP-8, SP)``
    -- the bytes the push overwrote. (The oracle alone misses the aliased
    forms below: the bound read is may-alias with the caller's global stores,
    so the slice over-approximates and the wrong value is not silent.)"""
    ssa = analyzed.normalized.memory_ssa
    call = next(key for key in analyzed.proven if key.endswith(":CALL"))
    top = 1 << 64
    return [read for read in ssa.reads
            if ssa.actions[read.action_id].operation_key.startswith(call + "~ld")
            and read.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE
            and read.span.start < top and read.span.start + read.span.size > top - 8]


def _entry_reads(analyzed):
    """The call's entry loads bound to any caller memory bytes."""
    ssa = analyzed.normalized.memory_ssa
    call = next(key for key in analyzed.proven if key.endswith(":CALL"))
    return [read for read in ssa.reads if ssa.actions[read.action_id].operation_key.startswith(call + "~ld")
            and read.span.object_id.kind in (StorageObjectKind.FUNCTION_RELATIVE, StorageObjectKind.ADDRESS_SPACE)]


def test_a_plain_read_of_the_pushed_return_address_is_not_the_pre_call_value():
    """The same with no index: the callee loads ``[RSP]`` (Fable, the same
    hole on main before the merge -- a summary source at the return-address
    slot was bound to the caller's pre-call bytes)."""
    analyzed, report = _checked((load(reg(RAX), reg(RSP)),))
    assert report.checked and report.silent == [], report.silent[:4]
    assert _pushed_slot_reads(analyzed) == []


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
    assert _pushed_slot_reads(analyzed) == []


def test_a_read_through_a_pointer_slot_holding_the_slot_is_not_the_pre_call_value():
    """The same address stored in a global the callee loads first:
    ``[[0x2000]]`` with ``[0x2000] = RSP - 8`` (Fable, the same review)."""
    t = tmp(0x300)
    analyzed, report = _checked((load(reg(RCX), const(0x2000)), load(reg(RAX), reg(RCX))),
                                prelude=(sub(t, reg(RSP), const(8)), store(const(0x2000), t)))
    assert report.checked and report.silent == [], report.silent[:4]
    assert _pushed_slot_reads(analyzed) == []


def test_a_read_through_the_stack_pointer_plus_a_register_is_not_bound():
    """``lea rcx, [rsp + r8 - 8]``: not the stack pointer's own atoms, yet
    the pushed slot whenever R8 is 0 -- a stack-derived base is never bound
    to pre-call bytes (Astra, round 2)."""
    t = tmp(0x300)
    analyzed, report = _checked((load(reg(RAX), reg(RCX)),),
                                prelude=(add(t, reg(RSP), reg(R8)), sub(reg(RCX), t, const(8))))
    assert report.checked and report.silent == [], report.silent[:4]
    assert _entry_reads(analyzed) == []


def test_a_read_through_the_callers_entry_pointer_is_still_bound():
    """The callee reads ``[RCX]`` with RCX the caller's own entry value: no
    entry value addresses the caller's new frame, where the slot lies (the
    named assumption ``may_alias`` uses, reported), so it binds exactly."""
    analyzed, report = _checked((load(reg(RAX), reg(RCX)),))
    assert report.checked and report.silent == [], report.silent[:4]
    assert _entry_reads(analyzed) and analyzed.normalized.assumes_entry_values_not_frame


def test_a_store_and_read_through_the_stack_pointer_plus_a_register_is_not_the_stored_value():
    """``rcx = rsp + r8; [rcx] = 0x1400; call f`` with R8 = -8 at run time,
    the callee reads ``[RCX]``: the caller's own store is the one reaching
    definition of that object, so binding it would be a complete, wrong
    slice (Fable, round 2)."""
    analyzed, report = _checked((load(reg(RAX), reg(RCX)),),
                                prelude=(add(reg(RCX), reg(RSP), reg(R8)), store(reg(RCX), const(0x1400))),
                                registers={R8: (1 << 64) - 8})
    assert report.checked and report.silent == [], report.silent[:4]
    assert _entry_reads(analyzed) == []


def test_an_entry_pointer_read_is_not_bound_with_the_frame_assumption_off():
    """Entry R9 = RSP - 8 (the caller's own pushed slot); the caller stores
    through R9 and the callee reads ``[R9]``. With entry-values-do-not-
    address-the-new-frame switched off nothing excludes the slot: refused
    (Astra, round 3)."""
    analyzed, report = _checked((load(reg(RAX), reg(R9)),), prelude=(store(reg(R9), const(0x1400)),),
                                registers={R9: 0x7000_0000 - 8}, assume_entry_values_not_frame=False)
    assert report.checked and report.silent == [], report.silent[:4]
    assert _entry_reads(analyzed) == [] and not analyzed.normalized.assumes_entry_values_not_frame


def test_an_entry_pointer_read_is_not_bound_after_a_stack_escape():
    """``[0x2000] = RSP - 8`` before the call: the frame is no longer private
    there (``may_alias``'s escape rule), so a read through the caller's entry
    R9 is not bound either (Astra, round 3)."""
    t = tmp(0x300)
    analyzed, report = _checked((load(reg(RAX), reg(R9)),),
                                prelude=(sub(t, reg(RSP), const(8)), store(const(0x2000), t),
                                         store(reg(R9), const(0x1400))))
    assert report.checked and report.silent == [], report.silent[:4]
    assert _entry_reads(analyzed) == []


def test_an_absolute_read_of_the_slot_is_not_bound_with_both_assumptions_off():
    """The callee reads the constant address ``0x6ffffff8`` -- the pushed
    slot when the stack sits at ``0x70000000``. With entry-values-do-not-
    address-the-new-frame and globals-disjoint-from-stack both off nothing
    excludes it: not bound (Astra, round 4: 144 silent dependencies)."""
    slot = 0x7000_0000 - 8
    analyzed, report = _checked((load(reg(RAX), const(slot)),), prelude=(store(const(slot), const(0x1400)),),
                                assume_entry_values_not_frame=False)
    assert report.checked and report.silent == [], report.silent[:4]
    assert _entry_reads(analyzed) == []


def test_an_absolute_read_is_bound_under_globals_disjoint_from_stack():
    """The same read with globals-disjoint-from-stack taken: a constant is
    never a stack address, so it binds exactly (precision kept)."""
    analyzed, _ = _checked((load(reg(RAX), const(0x2000)),), assume_entry_values_not_frame=False,
                           assume_globals_disjoint_from_stack=True)
    assert _entry_reads(analyzed)


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
