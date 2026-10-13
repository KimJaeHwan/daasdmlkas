"""Characterization of intrafunction memory tracking that is correct today.

These cases must keep passing through the P0 fixes (no precision loss).
"""

from synthetic import (
    DATA_BASE, RAX, RCX, RDI, RDX, RSI, ZF,
    FunctionBuilder, add, const, copy, load, normalize, op, operation_node_at,
    reg, slice_from, slice_op, store, straight, tmp,
)

T = tmp(0x100)


def sliced_at(builder, index):
    function = normalize(builder)
    return slice_from(function, operation_node_at(function, index))


def test_same_base_disjoint_offset_is_independent():
    """*(RDI) = RDX; RAX = *(RDI+8)."""
    result = slice_op(normalize(straight(
        [store(reg(RDI), reg(RDX))],
        [add(T, reg(RDI), const(8)), load(reg(RAX), T)],
    )), "LOAD")
    assert result.registers() == {"RDI"}
    assert result.is_complete


def test_partial_overlap_reaches_stored_value():
    """*(RDI) = RDX (8 bytes); EAX = *(RDI+4) (4 bytes)."""
    result = slice_op(normalize(straight(
        [store(reg(RDI), reg(RDX))],
        [add(T, reg(RDI), const(4)), load(reg(RAX, 4), T)],
    )), "LOAD")
    assert result.reaches(RDX)
    assert result.is_complete


def test_pointer_copy_is_tracked():
    """RSI = RDI; *(RDI) = RDX; RAX = *(RSI)."""
    result = slice_op(normalize(straight(
        [copy(reg(RSI), reg(RDI))],
        [store(reg(RDI), reg(RDX))],
        [load(reg(RAX), reg(RSI))],
    )), "LOAD")
    assert result.registers() == {"RDI", "RDX"}
    assert result.is_complete


def test_double_dereference_is_tracked():
    """RCX = *(RDI); *(RCX) = RDX; RAX = *(RCX)."""
    result = sliced_at(straight(
        [load(reg(RCX), reg(RDI))],
        [store(reg(RCX), reg(RDX))],
        [load(reg(RAX), reg(RCX))],
    ), 2)
    assert result.registers() == {"RDI", "RDX"}
    assert result.is_complete


def test_non_affine_address_stays_unresolved():
    """RCX = RDI*RSI; *(RCX) = RDX; RAX = *(RCX) -> debt, not a guess."""
    result = sliced_at(straight(
        [op("INT_MULT", [reg(RDI), reg(RSI)], reg(RCX))],
        [store(reg(RCX), reg(RDX))],
        [load(reg(RAX), reg(RCX))],
    ), 2)
    assert not result.is_complete


def test_a_scaled_address_is_one_exact_place():
    """RCX = RDI*2; *(RCX) = RDX; RAX = *(RCX): the same atom tuple twice --
    the same address on every run (array step C1): RAX is RDX, complete."""
    result = sliced_at(straight(
        [op("INT_MULT", [reg(RDI), const(2)], reg(RCX))],
        [store(reg(RCX), reg(RDX))],
        [load(reg(RAX), reg(RCX))],
    ), 2)
    assert result.is_complete
    assert "RDX" in result.registers()


def test_read_before_write_is_not_affected():
    """RAX = *(RSI); *(RDI) = RDX."""
    result = slice_op(normalize(straight(
        [load(reg(RAX), reg(RSI))],
        [store(reg(RDI), reg(RDX))],
    )), "LOAD")
    assert result.registers() == {"RSI"}
    assert result.is_complete


def test_global_store_then_load():
    result = slice_op(normalize(straight(
        [store(const(DATA_BASE + 0x10), reg(RDX))],
        [load(reg(RAX), const(DATA_BASE + 0x10))],
    )), "LOAD")
    assert result.registers() == {"RDX"}
    assert result.is_complete


def test_conditional_write_joins_with_entry_memory():
    """if (!ZF) *(RDI) = RDX; RAX = *(RDI): both RDX and old *(RDI)."""
    builder = (
        FunctionBuilder()
        .cbranch("skip", reg(ZF, 1))
        .ins(store(reg(RDI), reg(RDX)))
        .label("skip")
        .ins(load(reg(RAX), reg(RDI)))
        .ret(realistic=False)
    )
    result = slice_op(normalize(builder), "LOAD")
    assert result.registers() == {"RDI", "RDX"}
    assert any(kind == "function_relative" for kind, _ in result.memory_bytes)
    assert result.is_complete


def test_loop_advancing_pointer_stays_unresolved():
    """do { *(RDI) = RDX; RDI += 8; } while (ZF); RAX = *(RDI)."""
    builder = (
        FunctionBuilder()
        .label("top")
        .ins(store(reg(RDI), reg(RDX)))
        .ins(add(reg(RDI), reg(RDI), const(8)))
        .cbranch("top", reg(ZF, 1))
        .ins(load(reg(RAX), reg(RDI)))
        .ret(realistic=False)
    )
    result = slice_op(normalize(builder), "LOAD")
    assert not result.is_complete
