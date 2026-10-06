"""P0-1: reads that a write through another memory object may have overwritten.

See docs/intra_function_stabilization.md. Each test slices backward from a
LOAD. A possible alias must either make the stored value (RDX) reachable as
an origin or mark the slice incomplete; the implementation does both
(``may_alias_read`` debt with writer -> debt -> read edges).
"""

from synthetic import (
    DATA_BASE, RAX, RBX, RCX, RDI, RDX, RSI, RSP,
    add, const, load, normalize, operation_node_at, reg, slice_from,
    store, straight, sub, tmp,
)

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
