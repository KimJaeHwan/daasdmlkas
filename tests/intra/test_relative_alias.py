"""P0-1: reads that a write through another memory object may have overwritten.

See docs/intra_function_stabilization.md. Each test slices backward from a
LOAD. A possible alias must either make the stored value (RDX) reachable as
an origin or mark the slice incomplete; the implementation does both
(``may_alias_read`` debt with writer -> debt -> read edges).
"""

import pytest

from synthetic import (
    CODE_BASE, DATA_BASE, RAX, RBX, RCX, RDI, RDX, RSI, RSP, FunctionBuilder,
    add, const, copy, load, normalize, operation_node_at, program_units, reg, slice_from,
    store, straight, sub, tmp,
)
from tdo_v2.interprocedural import analyze_units, program_switches_stack
from tdo_v2.normalize import FunctionNormalizer

T = tmp(0x100)


def _first_load(*instructions, index):
    """Normalize with a realistic ``ret`` and slice from the LOAD of instruction ``index``."""
    function = normalize(straight(*instructions, realistic_return=True))
    ordinal = next(
        position for position, operation in enumerate(instructions[index])
        if operation[0] == "LOAD"
    )
    return function, slice_from(function, operation_node_at(function, index, ordinal))


def test_same_pointer_reaches_stored_value():
    """Control: *(RDI) = RDX; RAX = *(RDI)."""
    function, result = _first_load(
        [store(reg(RDI), reg(RDX))], [load(reg(RAX), reg(RDI))], index=1
    )
    assert result.registers() == {"RDI", "RDX"}
    assert result.is_complete
    # only the ret's return-address load (entry SP, reachable by RDI) is flagged
    assert [row.operation_key for row in function.may_alias_reads] == [f"1:{0x1008:x}:0:LOAD"]


# -- relative vs relative --------------------------------------------------

def test_distinct_entry_pointers_report_possible_origin_and_debt():
    """*(RDI) = RDX; RAX = *(RSI): RDI == RSI is possible."""
    function, result = _first_load(
        [store(reg(RDI), reg(RDX))], [load(reg(RAX), reg(RSI))], index=1
    )
    assert result.reaches(RDX)          # the possible writer's value
    assert result.reaches(RSI)
    assert not result.is_complete
    (row,) = [r for r in function.may_alias_reads if r.operation_key == f"1:{0x1004:x}:0:LOAD"]
    assert row.writers == (f"1:{0x1000:x}:0:STORE",)


def test_read_before_the_other_write_has_no_debt():
    """RAX = *(RSI); *(RDI) = RDX."""
    function, result = _first_load(
        [load(reg(RAX), reg(RSI))], [store(reg(RDI), reg(RDX))], index=0
    )
    assert result.registers() == {"RSI"}
    assert result.is_complete


def test_own_object_rewrite_clears_the_alias():
    """*(RDI) = RDX; *(RSI) = RCX; RAX = *(RSI): the last write to RSI's bytes wins."""
    function, result = _first_load(
        [store(reg(RDI), reg(RDX))], [store(reg(RSI), reg(RCX))], [load(reg(RAX), reg(RSI))],
        index=2,
    )
    assert result.reaches(RCX) and not result.reaches(RDX)
    assert result.is_complete


# -- relative vs absolute --------------------------------------------------

def test_pointer_write_then_global_read_is_not_silently_complete():
    function, result = _first_load(
        [store(reg(RDI), reg(RDX))], [load(reg(RAX), const(DATA_BASE + 0x10))], index=1
    )
    assert result.reaches(RDX)
    assert not result.is_complete


def test_global_write_then_pointer_read_is_not_silently_complete():
    function, result = _first_load(
        [store(const(DATA_BASE + 0x10), reg(RDX))], [load(reg(RAX), reg(RDI))], index=1
    )
    assert result.reaches(RDX)
    assert not result.is_complete


def test_two_globals_are_one_exact_object():
    function, result = _first_load(
        [store(const(DATA_BASE + 0x10), reg(RDX))], [load(reg(RAX), const(DATA_BASE + 0x18))],
        index=1,
    )
    assert not result.reaches(RDX)
    assert result.is_complete


# -- stack frame -----------------------------------------------------------

def test_private_stack_slot_does_not_alias_entry_pointer():
    """RSP -= 8; *(RSP) = RBX; *(RDI) = RDX; RAX = *(RSP).

    The slot is below the entry stack pointer (identified by the observed
    ``ret`` shape) and no stack-derived value escapes, so RDI cannot reach it.
    """
    function, result = _first_load(
        [sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), reg(RBX))],
        [store(reg(RDI), reg(RDX))],
        [load(reg(RAX), reg(RSP))],
        index=2,
    )
    assert result.registers() == {"RBX", "RSP"}
    assert result.is_complete


def test_stack_without_observed_ret_shape_is_not_trusted():
    """Same code but a bare RETURN: the stack pointer is not identified."""
    function = normalize(straight(
        [sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), reg(RBX))],
        [store(reg(RDI), reg(RDX))],
        [load(reg(RAX), reg(RSP))],
        realistic_return=False,
    ))
    result = slice_from(function, operation_node_at(function, 2))
    assert result.reaches(RBX) and not result.is_complete


def test_escaped_frame_address_is_not_silently_complete():
    """RCX = RSP-8 is stored through RDI, so RSI may point at the slot."""
    function, result = _first_load(
        [sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), reg(RBX))],
        [store(reg(RDI), reg(RSP))],
        [store(reg(RSI), reg(RDX))],
        [load(reg(RAX), reg(RSP))],
        index=3,
    )
    assert result.reaches(RBX) and result.reaches(RDX)
    assert not result.is_complete


def test_caller_frame_bytes_are_never_private():
    """*(RSP+0x10) is above the entry SP (caller frame): RDI may point there."""
    function, result = _first_load(
        [add(T, reg(RSP), const(0x10)), store(T, reg(RBX))],
        [store(reg(RDI), reg(RDX))],
        [add(T, reg(RSP), const(0x10)), load(reg(RAX), T)],
        index=2,
    )
    assert result.reaches(RDX)
    assert not result.is_complete


# -- escape is per program point ---------------------------------------------

def test_frame_read_before_a_later_escape_stays_private():
    """The slot is read before RSP is stored through RSI: no base holds it yet."""
    function, result = _first_load(
        [sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), reg(RBX))],
        [store(reg(RDI), reg(RDX))],
        [load(reg(RAX), reg(RSP))],
        [store(reg(RSI), reg(RSP))],
        index=2,
    )
    assert result.registers() == {"RBX", "RSP"}
    assert result.is_complete


def test_frame_write_before_an_escape_is_visible_through_another_base():
    """*(RSP) = RBX; *(RDI) = RSP (escape); RAX = *(RSI): RSI may be the slot."""
    function, result = _first_load(
        [sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), reg(RBX))],
        [store(reg(RDI), reg(RSP))],
        [load(reg(RAX), reg(RSI))],
        index=2,
    )
    assert result.reaches(RBX)
    assert not result.is_complete


def test_escape_later_in_a_loop_reaches_the_loop_head():
    """The escape at the loop's end precedes the next iteration's read."""
    builder = (
        FunctionBuilder()
        .ins(sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), reg(RBX)))
        .label("top")
        .ins(store(reg(RDI), reg(RDX)))
        .ins(load(reg(RAX), reg(RSP)))
        .ins(store(reg(RSI), reg(RSP)))
        .cbranch("top", reg(RCX, 1))
        .ret()
    )
    function = normalize(builder)
    result = slice_from(function, operation_node_at(function, 2))
    assert result.reaches(RDX)
    assert not result.is_complete


# -- named assumption: constant addresses never alias the stack --------------

def _home_space_reload(*between, assume):
    """*(RSP+8) = RCX (caller home space); between; RAX = *(RSP+8)."""
    (unit,) = program_units(straight(
        [add(T, reg(RSP), const(8)), store(T, reg(RCX))],
        *between,
        [add(T, reg(RSP), const(8)), load(reg(RAX), T)],
        realistic_return=True,
    ))
    function = FunctionNormalizer().normalize(unit, assume_globals_disjoint_from_stack=assume)
    assert function.assumes_globals_disjoint_from_stack is assume
    return slice_from(function, operation_node_at(function, 1 + len(between), 1))


def test_global_write_may_alias_the_stack_without_the_assumption():
    result = _home_space_reload([store(const(DATA_BASE + 0x10), reg(RDX))], assume=False)
    assert result.reaches(RDX)
    assert not result.is_complete


def test_assumption_separates_globals_from_the_stack():
    result = _home_space_reload([store(const(DATA_BASE + 0x10), reg(RDX))], assume=True)
    assert result.registers() == {"RCX", "RSP"}
    assert result.is_complete


def test_assumption_keeps_pointer_writes_aliasing_the_stack():
    """RDI may still point into the stack."""
    result = _home_space_reload([store(reg(RDI), reg(RDX))], assume=True)
    assert result.reaches(RDX)
    assert not result.is_complete


def test_stack_switch_withdraws_the_assumption():
    """``mov rsp, [global]``: the program may run on a stack in static data."""
    ordinary = straight(
        [add(T, reg(RSP), const(8)), store(T, reg(RCX))], realistic_return=True,
    )
    switching = straight(
        [load(T, const(DATA_BASE)), copy(reg(RSP), T)], realistic_return=True,
    )
    switching.entry = CODE_BASE + 0x100
    units = program_units(ordinary, switching)
    found = program_switches_stack(units)
    assert list(found) == [f"1:{CODE_BASE + 0x100:x}"]
    assert program_switches_stack(program_units(ordinary)) == {}
    results = analyze_units(units, assume_globals_disjoint_from_stack=True)
    assert not any(item.normalized.assumes_globals_disjoint_from_stack for item in results.values())
    (alone,) = analyze_units(program_units(ordinary), assume_globals_disjoint_from_stack=True).values()
    assert alone.normalized.assumes_globals_disjoint_from_stack


def test_a_value_derived_from_the_stack_on_one_path_only_is_a_switch():
    """rax = rsp on one path, rax = [global] on the other; rsp = rax: the
    stack may move into static data -- a MUST check flags it (a value derived
    from the stack pointer on some path only does not clear it)."""
    from synthetic import CODE_BASE, FunctionBuilder, RAX, ZF

    switching = (FunctionBuilder(entry=CODE_BASE + 0x100)
                 .cbranch("other", reg(ZF, 1))
                 .ins(copy(reg(RAX), reg(RSP)))
                 .branch("join")
                 .label("other").ins(load(reg(RAX), const(DATA_BASE)))
                 .label("join").ins(copy(reg(RSP), reg(RAX)))
                 .ret())
    assert list(program_switches_stack(program_units(switching))) == [f"1:{CODE_BASE + 0x100:x}"]


def test_a_frame_pointer_epilogue_is_no_switch():
    """rbp = rsp; ...; rsp = rbp (leave): derived from the stack pointer on every path."""
    from synthetic import RBP

    leave = straight([copy(reg(RBP), reg(RSP))], [add(T, reg(RBP), const(8)), store(T, reg(RCX))],
                     [copy(reg(RSP), reg(RBP))], realistic_return=True)
    assert program_switches_stack(program_units(leave)) == {}


def test_a_function_without_its_own_stack_shapes_is_checked_with_the_programs():
    """A lone jump that loads rsp from a global (no call, no return): checked
    with the program's stack pointer (another function's call shape)."""
    from synthetic import CODE_BASE, FunctionBuilder

    caller = FunctionBuilder().sub_rsp(0x28).call(CODE_BASE + 0x400).add_rsp(0x28).ret()
    jumper = (FunctionBuilder(entry=CODE_BASE + 0x200).ins(load(T, const(DATA_BASE)), copy(reg(RSP), T))
              .tail_call(CODE_BASE + 0x400))
    found = program_switches_stack(program_units(caller, jumper))
    assert f"1:{CODE_BASE + 0x200:x}" in found


def _switches(*builders):
    return program_switches_stack(program_units(*builders))


SWITCHER = CODE_BASE + 0x100


@pytest.mark.parametrize("case", ["call-clobbers", "partial-byte", "cancelled", "callother", "negated-load"])
def test_coefficient_counterexamples_are_switches(case):
    """Reviewers' counterexamples (step 24.1 review): a value only partly, or
    no longer, "the stack pointer + a number" is a switch."""
    from synthetic import R8, op

    callee = CODE_BASE + 0x800
    body = FunctionBuilder(entry=SWITCHER)
    if case == "call-clobbers":                  # rax = rsp; call f (rax: its result); rsp = rax
        body.ins(copy(reg(RAX), reg(RSP))).call(callee).ins(copy(reg(RSP), reg(RAX)))
    elif case == "partial-byte":                 # rax = static; al = spl; rsp = rax
        body.ins(copy(reg(RAX), const(DATA_BASE))).ins(copy(reg(RAX, 1), reg(RSP, 1))).ins(copy(reg(RSP), reg(RAX)))
    elif case == "cancelled":                    # rax = rsp - rsp + static; rsp = rax
        body.ins(copy(reg(RAX), reg(RSP))).ins(sub(reg(RAX), reg(RAX), reg(RSP))) \
            .ins(add(reg(RAX), reg(RAX), const(DATA_BASE))).ins(copy(reg(RSP), reg(RAX)))
    elif case == "callother":                    # rsp = CALLOTHER(5, rsp)
        body.ins(op("CALLOTHER", [const(5, 4), reg(RSP)], reg(RSP)))
    else:                                        # rax = [rcx] - rsp; rsp += rax  (rsp := [rcx])
        body.ins(load(reg(R8), reg(RCX))).ins(sub(reg(R8), reg(R8), reg(RSP))).ins(add(reg(RSP), reg(RSP), reg(R8)))
    leaf = FunctionBuilder(entry=callee).ret()
    assert f"1:{SWITCHER:x}" in _switches(body.ret(), leaf)


@pytest.mark.parametrize("case", ["frame-pointer-across-call", "alignment", "alloca", "unreached-epilogue"])
def test_ordinary_stack_adjustments_are_no_switch(case):
    from synthetic import RBP, op

    callee = CODE_BASE + 0x800
    body = FunctionBuilder(entry=SWITCHER)
    if case == "frame-pointer-across-call":      # rbp = rsp; call f; rsp = rbp (rbp: call-preserved)
        body.ins(copy(reg(RBP), reg(RSP))).call(callee).ins(copy(reg(RSP), reg(RBP))).ret()
    elif case == "alignment":                    # and rsp, -16
        body.ins(op("INT_AND", [reg(RSP), const(0xFFFFFFFFFFFFFFF0)], reg(RSP))).ret()
    elif case == "alloca":                       # sub rsp, rax (rax: an argument)
        body.ins(sub(reg(RSP), reg(RSP), reg(RAX))).ret()
    else:                                        # code after the return no path reaches: add rsp, 0x28; ret
        body.ret().add_rsp(0x28).ret()
    leaf = FunctionBuilder(entry=callee).ret()
    assert _switches(body, leaf) == {}


def test_a_program_with_return_shapes_only_still_checks_a_jumper():
    """A leaf (return shape only) and a jumper loading rsp: the program's stack
    pointer comes from the return shape (Astra P2)."""
    leaf = straight([copy(reg(RAX), reg(RCX))], realistic_return=True)
    jumper = FunctionBuilder(entry=SWITCHER).ins(load(T, const(DATA_BASE)), copy(reg(RSP), T)).tail_call(CODE_BASE + 0x800)
    assert f"1:{SWITCHER:x}" in _switches(leaf, jumper)


@pytest.mark.parametrize("case", ["sign-bit-mask", "low-mask", "partial-write"])
def test_round_two_counterexamples_are_switches(case):
    """Astra (review round 2): a mask that is no alignment, and a partial write
    over a stack-derived register, leave no "stack pointer + a number"."""
    from synthetic import op

    body = FunctionBuilder(entry=SWITCHER)
    if case == "sign-bit-mask":                  # rsp &= 0x8000000000000000; rsp += static
        body.ins(op("INT_AND", [reg(RSP), const(0x8000000000000000)], reg(RSP))) \
            .ins(add(reg(RSP), reg(RSP), const(DATA_BASE)))
    elif case == "low-mask":                     # rax = rsp & 0x7fff...; rsp -= rax; rsp += static
        body.ins(op("INT_AND", [reg(RSP), const(0x7FFFFFFFFFFFFFFF)], reg(RAX))) \
            .ins(sub(reg(RSP), reg(RSP), reg(RAX))).ins(add(reg(RSP), reg(RSP), const(DATA_BASE)))
    else:                                        # rax = rsp; al = 0; rsp -= rax; rsp += static
        body.ins(copy(reg(RAX), reg(RSP))).ins(copy(reg(RAX, 1), const(0, 1))) \
            .ins(sub(reg(RSP), reg(RSP), reg(RAX))).ins(add(reg(RSP), reg(RSP), const(DATA_BASE)))
    assert f"1:{SWITCHER:x}" in _switches(body.ret())


def test_a_loaded_adjustment_is_the_named_exception():
    """rsp -= [x]: a loaded number adjusting the stack pointer is taken as no
    stack pointer (alloca / __chkstk sizes) -- the reported assumption
    stack-switch-check-exceptions; a direct restore rsp = [x] is a switch."""
    from synthetic import R8

    adjust = FunctionBuilder(entry=SWITCHER).ins(load(reg(R8), reg(RCX))).ins(sub(reg(RSP), reg(RSP), reg(R8))).ret()
    restore = FunctionBuilder(entry=SWITCHER).ins(load(reg(RSP), reg(RCX))).ret()
    assert _switches(adjust) == {}
    assert f"1:{SWITCHER:x}" in _switches(restore)


def test_a_user_op_without_output_keeps_what_registers_hold():
    """rax = rsp; userop(); rsp -= rax; rsp += static: the user op changes only
    its output (none) -- rax is still the stack pointer, so the result is the
    static address: a switch (Astra, round 3)."""
    from synthetic import op

    body = (FunctionBuilder(entry=SWITCHER).ins(copy(reg(RAX), reg(RSP)))
            .ins(op("CALLOTHER", [const(0x2F, 4)]))
            .ins(sub(reg(RSP), reg(RSP), reg(RAX))).ins(add(reg(RSP), reg(RSP), const(DATA_BASE))).ret())
    assert f"1:{SWITCHER:x}" in _switches(body)


def test_a_call_result_adjustment_is_the_named_exception():
    """rax = rsp; call f; rsp -= rax: rax after the call is taken as holding no
    stack pointer (__chkstk sizes) -- stack-switch-check-exceptions, not a
    finding of the check (Astra, round 3: now named)."""
    callee = CODE_BASE + 0x800
    body = (FunctionBuilder(entry=SWITCHER).ins(copy(reg(RAX), reg(RSP))).call(callee)
            .ins(sub(reg(RSP), reg(RSP), reg(RAX))).ret())
    assert _switches(body, FunctionBuilder(entry=callee).ret()) == {}
