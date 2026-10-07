"""P0-1: reads that a write through another memory object may have overwritten.

See docs/intra_function_stabilization.md. Each test slices backward from a
LOAD. A possible alias must either make the stored value (RDX) reachable as
an origin or mark the slice incomplete; the implementation does both
(``may_alias_read`` debt with writer -> debt -> read edges).
"""

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
