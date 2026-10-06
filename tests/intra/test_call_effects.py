"""P0-3: reads that may observe an unevidenced call's writes carry debt.

The engine's local normalization has no call-effect evidence, so before the
fix an opaque CALL was transparent: pre-call definitions flowed through it and
the slice was complete. Now such a read keeps the pre-call origin reachable but
gets a ``call_clobber_read`` debt (``src/tdo_v2/call_clobber.py``).
"""

from synthetic import (
    DATA_BASE, R8, R9, RAX, RCX, RDI, RDX, RSP, ZF,
    FunctionBuilder, add, const, copy, load, normalize, op, operation_node_at,
    reg, slice_from, store, tmp,
)

T = tmp(0x100)


def _slices(builder):
    function = normalize(builder)
    return lambda index: slice_from(function, operation_node_at(function, index))


def _after_call():
    return _slices(
        FunctionBuilder()
        .ins(copy(reg(RAX), reg(RDX)))                 # 0
        .call(0x1800)                                  # 1
        .ins(copy(reg(RCX), reg(RAX)))                 # 2  RAX after call
        .ins(load(reg(R8), reg(RDI)))                  # 3  *(RDI) after call
        .ins(load(reg(R9), const(DATA_BASE)))          # 4  *(global) after call
        .ret()
    )


# -- the original silent cases ---------------------------------------------

def test_register_read_after_call_keeps_origin_but_is_incomplete():
    result = _after_call()(2)
    assert result.reaches(RDX)          # pre-call origin is still reported
    assert not result.is_complete       # ... but no longer as certain


def test_pointer_read_after_call_is_incomplete():
    assert not _after_call()(3).is_complete


def test_global_read_after_call_is_incomplete():
    assert not _after_call()(4).is_complete


# -- controls: no false debt -------------------------------------------------

def test_value_written_after_call_is_complete():
    """call f; RAX = 7; RCX = RAX."""
    slices = _slices(
        FunctionBuilder()
        .call(0x1800)
        .ins(copy(reg(RAX), const(7)))
        .ins(copy(reg(RCX), reg(RAX)))
        .ret()
    )
    assert slices(2).is_complete


def test_read_before_call_is_complete():
    """RAX = RDX; RCX = RAX; call f."""
    slices = _slices(
        FunctionBuilder()
        .ins(copy(reg(RAX), reg(RDX)))
        .ins(copy(reg(RCX), reg(RAX)))
        .call(0x1800)
        .ret()
    )
    result = slices(1)
    assert result.reaches(RDX) and result.is_complete


def test_rewrite_on_the_calling_path_is_complete():
    """RAX = RDX; if (ZF) { call f; RAX = 1 }; RCX = RAX."""
    slices = _slices(
        FunctionBuilder()
        .ins(copy(reg(RAX), reg(RDX)))                 # 0
        .cbranch("join", reg(ZF, 1))                   # 1
        .call(0x1800)                                  # 2
        .ins(copy(reg(RAX), const(1)))                 # 3
        .label("join")
        .ins(copy(reg(RCX), reg(RAX)))                 # 4
        .ret()
    )
    result = slices(4)
    assert result.reaches(RDX) and result.is_complete


def test_call_on_one_path_only_is_incomplete():
    """RAX = RDX; if (ZF) call f; RCX = RAX."""
    slices = _slices(
        FunctionBuilder()
        .ins(copy(reg(RAX), reg(RDX)))                 # 0
        .cbranch("join", reg(ZF, 1))                   # 1
        .call(0x1800)                                  # 2
        .label("join")
        .ins(copy(reg(RCX), reg(RAX)))                 # 3
        .ret()
    )
    result = slices(3)
    assert result.reaches(RDX) and not result.is_complete


def test_loop_back_edge_carries_call_to_earlier_read():
    """top: RCX = RAX; call f; if (ZF) goto top."""
    slices = _slices(
        FunctionBuilder()
        .ins(copy(reg(RAX), reg(RDX)))                 # 0
        .label("top")
        .ins(copy(reg(RCX), reg(RAX)))                 # 1
        .call(0x1800)                                  # 2
        .cbranch("top", reg(ZF, 1))                    # 3
        .ret()
    )
    assert not slices(1).is_complete


# -- evidenced exemptions ------------------------------------------------------

def test_stack_pointer_is_preserved_across_call():
    """RCX = RSP after the call: the call/ret stack shape is observed."""
    slices = _slices(
        FunctionBuilder()
        .call(0x1800)
        .ins(copy(reg(RCX), reg(RSP)))
        .ret()
    )
    assert slices(1).is_complete


def test_private_stack_slot_survives_call():
    """*(RSP+8) = RDX; call f; RAX = *(RSP+8): the slot's address never escapes."""
    function = normalize(
        FunctionBuilder()
        .ins(add(T, reg(RSP), const(8)), store(T, reg(RDX)))      # 0
        .call(0x1800)                                             # 1
        .ins(add(T, reg(RSP), const(8)), load(reg(RAX), T))       # 2
        .ret()
    )
    seed = slice_from(function, operation_node_at(function, 2, 1))  # the LOAD
    assert seed.reaches(RDX)
    assert seed.is_complete


def test_escaped_stack_slot_is_incomplete_after_call():
    """RDI = RSP+8 passes the slot's address out; the callee may write it."""
    function = normalize(
        FunctionBuilder()
        .ins(add(T, reg(RSP), const(8)), store(T, reg(RDX)))      # 0
        .ins(add(reg(RDI), reg(RSP), const(8)))                   # 1
        .call(0x1800)                                             # 2
        .ins(add(T, reg(RSP), const(8)), load(reg(RAX), T))       # 3
        .ret()
    )
    seed = slice_from(function, operation_node_at(function, 3, 1))
    assert seed.reaches(RDX)
    assert not seed.is_complete


# -- other opaque control transfers --------------------------------------------

def test_indirect_call_is_opaque():
    function = normalize(
        FunctionBuilder()
        .ins(copy(reg(RCX), reg(RDX)))
        .ins(op("CALLIND", [reg(RAX)]))
        .ins(copy(reg(R8), reg(RCX)))
        .ret()
    )
    assert not slice_from(function, operation_node_at(function, 2)).is_complete


def test_callother_is_opaque():
    function = normalize(
        FunctionBuilder()
        .ins(copy(reg(RCX), reg(RDX)))
        .ins(op("CALLOTHER", [const(0x10, 4)]))
        .ins(copy(reg(R8), reg(RCX)))
        .ret()
    )
    assert not slice_from(function, operation_node_at(function, 2)).is_complete


def test_function_without_calls_has_no_call_debt():
    function = normalize(
        FunctionBuilder()
        .ins(copy(reg(RAX), reg(RDX)))
        .ins(copy(reg(RCX), reg(RAX)))
        .ret()
    )
    assert function.call_clobber_nodes == ()
    assert slice_from(function, operation_node_at(function, 1)).is_complete


def test_root_explanation_reports_call_clobber_gap():
    from tdo_v2.integration.configured_explanation_graph import root_local_explanation

    function = normalize(
        FunctionBuilder()
        .ins(copy(reg(RAX), reg(RDX)))
        .call(0x1800)
        .ins(copy(reg(RCX), reg(RAX)))
        .ret()
    )
    root = operation_node_at(function, 2)
    reachable = slice_from(function, root).result.reachable_nodes
    report = root_local_explanation(function, reachable, (root,), 0)
    kinds = [gap["kind"] for gap in report["gaps"]]
    assert kinds == ["call_clobber_read"]
    assert report["status"] == "partial"
