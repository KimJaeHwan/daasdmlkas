"""Self-checks for the synthetic harness (attribution, realistic frames)."""

from synthetic import (
    RAX, RBP, RBX, RDI, RDX, RSP,
    FunctionBuilder, const, copy, load, normalize, operation_node_at, reg,
    slice_from, slice_op, store, straight, sub,
)


def test_attribution_uses_edge_spans_not_entry_label():
    """Adjacent registers share one ENTRY node; RBX must not be reported as RDX."""
    result = slice_op(normalize(straight(
        [sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), reg(RBX))],
        [store(reg(RDI), reg(RDX))],
        [load(reg(RAX), reg(RSP))],
        realistic_return=True,
    )), "LOAD", index=2)
    assert result.reaches(RBX)
    assert not result.reaches(RDX)


def test_realistic_return_loads_return_address_from_stack():
    function = normalize(straight([copy(reg(RAX), reg(RDX))], realistic_return=True))
    # instruction 1 is ret: op 0 is RIP = *(RSP)
    result = slice_from(function, operation_node_at(function, 1, 0))
    assert result.registers() == {"RSP"}
    assert any(kind == "function_relative" for kind, _ in result.memory_bytes)


def test_prologue_epilogue_function_normalizes():
    builder = (
        FunctionBuilder()
        .push(RBP)
        .sub_rsp(0x20)
        .ins(store(reg(RDI), reg(RDX)))
        .ins(load(reg(RAX), reg(RDI)))
        .add_rsp(0x20)
        .pop(RBP)
        .ret()
    )
    function = normalize(builder)
    result = slice_from(function, operation_node_at(function, 3))
    assert result.registers() == {"RDI", "RDX"}
    assert result.is_complete
    # the saved RBP is restored from the private frame slot
    restored = slice_from(function, operation_node_at(function, 5, 0))
    assert restored.reaches(RBP)
    assert restored.is_complete


def test_two_function_program_normalizes_with_shared_program_scope():
    from synthetic import CODE_BASE, normalize_program

    callee = FunctionBuilder(entry=CODE_BASE + 0x800).ins(copy(reg(RAX), const(7))).ret()
    caller = FunctionBuilder().call(CODE_BASE + 0x800).ins(copy(reg(RDX), reg(RAX))).ret()
    caller_fn, callee_fn = normalize_program(caller, callee)
    assert caller_fn.scopes.program == callee_fn.scopes.program
    assert caller_fn.scopes.function.entry != callee_fn.scopes.function.entry
    result = slice_from(callee_fn, operation_node_at(callee_fn, 0, entry=CODE_BASE + 0x800))
    assert result.is_complete
