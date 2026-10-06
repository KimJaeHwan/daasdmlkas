"""P0-1: implicit no-alias between distinct memory objects.

See docs/intra_function_stabilization.md. Each test slices backward from a
LOAD and asks whether the stored value (RDX) is reached or, failing that,
whether the slice at least reports itself incomplete.

Tests marked ``xfail(strict=True)`` state the *sound* expectation and fail
today; the ``*_characterization`` tests pin today's (unsound) behavior so a
fix shows up as an intentional diff.
"""

import pytest

from synthetic import (
    DATA_BASE, RAX, RCX, RDI, RDX, RSI, RSP,
    add, const, load, normalize, operation_node_at, reg, slice_from, slice_op,
    store, straight, tmp,
)

P0_1 = pytest.mark.xfail(
    strict=True,
    reason="P0-1: distinct memory objects are silently assumed not to alias",
)
T = tmp(0x100)


def sliced(*instructions, seed_index=None):
    function = normalize(straight(*instructions))
    if seed_index is None:
        return slice_op(function, "LOAD")
    return slice_from(function, operation_node_at(function, seed_index))


def test_same_pointer_reaches_stored_value():
    """Control: *(RDI) = RDX; RAX = *(RDI)."""
    result = sliced([store(reg(RDI), reg(RDX))], [load(reg(RAX), reg(RDI))])
    assert result.registers() == {"RDI", "RDX"}
    assert result.is_complete


# -- relative vs relative --------------------------------------------------

@P0_1
def test_distinct_entry_pointers_must_not_be_silently_complete():
    """*(RDI) = RDX; RAX = *(RSI): RDI == RSI is possible."""
    result = sliced([store(reg(RDI), reg(RDX))], [load(reg(RAX), reg(RSI))])
    assert result.reaches(RDX) or not result.is_complete


def test_distinct_entry_pointers_characterization():
    result = sliced([store(reg(RDI), reg(RDX))], [load(reg(RAX), reg(RSI))])
    assert result.registers() == {"RSI"}
    assert result.is_complete
    assert result.result.reachable_unresolved_read_nodes == ()
    assert result.result.function_unresolved_write_nodes == ()


# -- relative vs absolute --------------------------------------------------

@P0_1
def test_pointer_write_then_global_read_must_not_be_silently_complete():
    """*(RDI) = RDX; RAX = *(global): RDI may point at the global."""
    result = sliced(
        [store(reg(RDI), reg(RDX))],
        [load(reg(RAX), const(DATA_BASE + 0x10))],
    )
    assert result.reaches(RDX) or not result.is_complete


@P0_1
def test_global_write_then_pointer_read_must_not_be_silently_complete():
    """*(global) = RDX; RAX = *(RDI): the reverse direction."""
    result = sliced(
        [store(const(DATA_BASE + 0x10), reg(RDX))],
        [load(reg(RAX), reg(RDI))],
    )
    assert result.reaches(RDX) or not result.is_complete


def test_global_write_then_pointer_read_characterization():
    result = sliced(
        [store(const(DATA_BASE + 0x10), reg(RDX))],
        [load(reg(RAX), reg(RDI))],
    )
    assert result.registers() == {"RDI"}
    assert result.is_complete


# -- stack frame -----------------------------------------------------------

def test_private_stack_slot_does_not_alias_entry_pointer():
    """RSP -= 8; *(RSP) = RBX; *(RDI) = RDX; RAX = *(RSP).

    The new slot is below the entry stack pointer and its address never
    escapes, so RDI cannot point at it: RBX (not RDX) and complete. This must
    stay true after the P0-1 fix (the non-escape proof rule).
    """
    from synthetic import RBX, sub

    result = sliced(
        [sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), reg(RBX))],
        [store(reg(RDI), reg(RDX))],
        [load(reg(RAX), reg(RSP))],
    )
    assert result.registers() == {"RBX", "RSP"}
    assert result.is_complete


@P0_1
def test_escaped_frame_address_must_not_be_silently_complete():
    """RCX = RSP+0x10; *(RDI) = RCX; *(RSI) = RDX; RAX = *(RSP+0x10).

    The slot's address escapes through *(RDI), and RSP+0x10 lies in the
    caller's frame anyway, so *(RSI) may write it.
    """
    result = sliced(
        [add(reg(RCX), reg(RSP), const(0x10))],
        [store(reg(RDI), reg(RCX))],
        [store(reg(RSI), reg(RDX))],
        [add(T, reg(RSP), const(0x10)), load(reg(RAX), T)],
    )
    assert result.reaches(RDX) or not result.is_complete
