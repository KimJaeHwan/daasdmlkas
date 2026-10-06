"""P0-3b: call-clobber debt discharged only by exact internal-callee evidence.

Every test runs the real interprocedural engine path
(``engine.analyze_observed_functions``) on a small synthetic program:
``main`` calls helpers, gets a value from ``source`` and passes it to
``sink`` in ECX. ``local_completeness`` keeps the raw call debt;
``effective_completeness`` removes debt discharged by callee evidence.
"""

from synthetic import (
    CODE_BASE, RAX, RBP, RBX, RCX, RDI, RDX, RSP, ZF,
    FunctionBuilder, add, analyze_program, boundary, const, copy, load, op, reg,
    store, tmp,
)

T = tmp(0x100)

MAIN, SOURCE, SINK, HELPER, INNER = (
    CODE_BASE, CODE_BASE + 0x800, CODE_BASE + 0xA00, CODE_BASE + 0xC00, CODE_BASE + 0xE00,
)
PROVIDER = boundary({"source": 4}, {"sink": 4})


def _source_returning_constant():
    return (
        FunctionBuilder(entry=SOURCE)
        .push(RBP).ins(copy(reg(RBP), reg(RSP)))
        .ins(copy(reg(RAX, 4), const(7, 4)))
        .pop(RBP).ret()
    )


def _sink():
    return FunctionBuilder(entry=SINK).ret()


def _root(functions):
    roots = analyze_program(functions, PROVIDER)
    return roots[("main", "sink.arg0")]


def _main_through_helper():
    """RBX = source(); helper(); sink(EBX)."""
    return (
        FunctionBuilder(entry=MAIN)
        .call(SOURCE)
        .ins(copy(reg(RBX, 4), reg(RAX, 4)))
        .call(HELPER)
        .ins(copy(reg(RCX, 4), reg(RBX, 4)))
        .call(SINK)
        .ret()
    )


# -- MUST_WRITTEN ----------------------------------------------------------------

def test_source_return_value_discharges_call_debt():
    root = _root({
        "main": FunctionBuilder(entry=MAIN)
        .call(SOURCE).ins(copy(reg(RCX, 4), reg(RAX, 4))).call(SINK).ret(),
        "source": _source_returning_constant(),
        "sink": _sink(),
    })
    assert root.reached_origin_labels == ("source.ret",)
    assert not root.is_locally_complete
    assert root.is_effectively_complete


def test_conditional_return_write_is_not_discharged():
    """source writes EAX on one path only: the old EAX may survive."""
    source = (
        FunctionBuilder(entry=SOURCE)
        .cbranch("out", reg(ZF, 1))
        .ins(copy(reg(RAX, 4), const(7, 4)))
        .label("out")
        .ret()
    )
    root = _root({
        "main": FunctionBuilder(entry=MAIN)
        .call(SOURCE).ins(copy(reg(RCX, 4), reg(RAX, 4))).call(SINK).ret(),
        "source": source,
        "sink": _sink(),
    })
    assert not root.is_effectively_complete


def test_source_boundary_value_is_its_label_even_with_inner_debt():
    """source returns *(RDI*2): the boundary declares its result as the origin."""
    source = (
        FunctionBuilder(entry=SOURCE)
        .ins(op("INT_MULT", [reg(RDI), const(2)], reg(RCX)))
        .ins(load(reg(RAX, 4), reg(RCX)))
        .ret()
    )
    root = _root({
        "main": FunctionBuilder(entry=MAIN)
        .call(SOURCE).ins(copy(reg(RCX, 4), reg(RAX, 4))).call(SINK).ret(),
        "source": source,
        "sink": _sink(),
    })
    assert root.reached_origin_labels == ("source.ret",)
    assert root.is_effectively_complete


def test_incomplete_intermediate_value_is_not_discharged():
    """helper returns source() + *(RDI*2): the unknown load may add origins."""
    helper = (
        FunctionBuilder(entry=HELPER)
        .call(SOURCE)
        .ins(op("INT_MULT", [reg(RDI), const(2)], reg(RCX)))
        .ins(load(reg(RDX, 4), reg(RCX)))
        .ins(op("INT_ADD", [reg(RAX, 4), reg(RDX, 4)], reg(RAX, 4)))
        .ret()
    )
    root = _root({
        "main": FunctionBuilder(entry=MAIN)
        .call(HELPER).ins(copy(reg(RCX, 4), reg(RAX, 4))).call(SINK).ret(),
        "source": _source_returning_constant(),
        "helper": helper,
        "sink": _sink(),
    })
    assert not root.is_effectively_complete


# -- PRESERVED -------------------------------------------------------------------

def test_saved_and_restored_register_discharges_call_debt():
    helper = (
        FunctionBuilder(entry=HELPER)
        .push(RBX).ins(copy(reg(RBX), const(0))).pop(RBX).ret()
    )
    root = _root({
        "main": _main_through_helper(), "source": _source_returning_constant(),
        "helper": helper, "sink": _sink(),
    })
    assert root.reached_origin_labels == ("source.ret",)
    assert root.is_effectively_complete


def test_clobbered_register_is_not_discharged():
    helper = FunctionBuilder(entry=HELPER).ins(copy(reg(RBX), const(0))).ret()
    root = _root({
        "main": _main_through_helper(), "source": _source_returning_constant(),
        "helper": helper, "sink": _sink(),
    })
    assert not root.is_effectively_complete


def test_nested_call_that_keeps_the_saved_slot_is_discharged():
    """helper: push rbx; call inner; pop rbx -- inner provably writes nothing."""
    helper = FunctionBuilder(entry=HELPER).push(RBX).call(INNER).pop(RBX).ret()
    inner = FunctionBuilder(entry=INNER).ret()
    root = _root({
        "main": _main_through_helper(), "source": _source_returning_constant(),
        "helper": helper, "inner": inner, "sink": _sink(),
    })
    assert root.is_effectively_complete


def test_nested_call_overwriting_the_saved_slot_is_not_discharged():
    """inner writes its entry SP + 8 = helper's saved-RBX slot."""
    helper = FunctionBuilder(entry=HELPER).push(RBX).call(INNER).pop(RBX).ret()
    inner = (
        FunctionBuilder(entry=INNER)
        .ins(add(T, reg(RSP), const(8)), store(T, reg(RDI)))
        .ret()
    )
    root = _root({
        "main": _main_through_helper(), "source": _source_returning_constant(),
        "helper": helper, "inner": inner, "sink": _sink(),
    })
    assert not root.is_effectively_complete


def test_recursive_helper_is_not_discharged():
    helper = (
        FunctionBuilder(entry=HELPER)
        .push(RBX)
        .cbranch("done", reg(ZF, 1))
        .call(HELPER)
        .label("done")
        .pop(RBX).ret()
    )
    root = _root({
        "main": _main_through_helper(), "source": _source_returning_constant(),
        "helper": helper, "sink": _sink(),
    })
    assert not root.is_effectively_complete


def test_unknown_callee_is_not_discharged():
    """helper is not part of the program (no evidence at all)."""
    root = _root({
        "main": _main_through_helper(), "source": _source_returning_constant(),
        "sink": _sink(),
    })
    assert not root.is_effectively_complete


# -- FRAME_PRESERVED ---------------------------------------------------------------
#
# main: sub rsp,0x28; EAX = source(); [rsp+0x20] = EAX; helper(); ECX = [rsp+0x20]; sink()
# The slot is main-entry-SP - 8. helper's entry SP is main-entry-SP - 0x30, so
# in helper coordinates the slot is [+0x28, +0x2C).

from synthetic import DATA_BASE, R8  # noqa: E402


def _main_with_stack_slot(*, leak_slot_in_rdi=False):
    main = FunctionBuilder(entry=MAIN).sub_rsp(0x28).call(SOURCE)
    main.ins(add(T, reg(RSP), const(0x20)), store(T, reg(RAX, 4)))
    if leak_slot_in_rdi:
        main.ins(add(reg(RDI), reg(RSP), const(0x20)))
    return (
        main.call(HELPER)
        .ins(add(T, reg(RSP), const(0x20)), load(reg(RCX, 4), T))
        .call(SINK)
        .add_rsp(0x28)
        .ret()
    )


def _frame_root(helper, *, extra=None, leak_slot_in_rdi=False):
    functions = {
        "main": _main_with_stack_slot(leak_slot_in_rdi=leak_slot_in_rdi),
        "source": _source_returning_constant(),
        "helper": helper,
        "sink": _sink(),
    }
    functions.update(extra or {})
    return _root(functions)


def _writes_at(offset, size=8, entry=HELPER):
    """helper: *(entry RSP + offset) = R8 (no frame setup)."""
    return (
        FunctionBuilder(entry=entry)
        .ins(add(T, reg(RSP), const(offset & 0xFFFFFFFFFFFFFFFF)), store(T, reg(R8, size)))
        .ret()
    )


def test_callee_writing_only_its_own_frame_discharges_slot_debt():
    helper = (
        FunctionBuilder(entry=HELPER)
        .push(RBP).ins(copy(reg(RBP), reg(RSP))).sub_rsp(0x10)
        .ins(add(T, reg(RBP), const(-8 & 0xFFFFFFFFFFFFFFFF)), store(T, reg(R8)))
        .add_rsp(0x10).pop(RBP).ret()
    )
    root = _frame_root(helper)
    assert root.reached_origin_labels == ("source.ret",)
    assert root.is_effectively_complete


def test_callee_shadow_space_write_beside_the_slot_discharges():
    root = _frame_root(_writes_at(0x8))
    assert root.is_effectively_complete


def test_callee_write_into_the_slot_through_its_stack_pointer_is_not_discharged():
    root = _frame_root(_writes_at(0x28, 4))
    assert not root.is_effectively_complete


def test_callee_write_through_pointer_argument_is_not_discharged():
    helper = FunctionBuilder(entry=HELPER).ins(store(reg(RDI), reg(R8, 4))).ret()
    root = _frame_root(helper, leak_slot_in_rdi=True)
    assert not root.is_effectively_complete


def test_callee_write_through_loaded_pointer_is_not_discharged():
    helper = (
        FunctionBuilder(entry=HELPER)
        .ins(add(T, reg(RSP), const(0x10)), load(reg(RAX), T))
        .ins(store(reg(RAX), reg(R8, 4)))
        .ret()
    )
    root = _frame_root(helper)
    assert not root.is_effectively_complete


def test_callee_global_write_discharges_by_axiom():
    helper = FunctionBuilder(entry=HELPER).ins(store(const(DATA_BASE), reg(R8))).ret()
    root = _frame_root(helper)
    assert root.is_effectively_complete


def _helper_calling_inner():
    """helper: sub rsp,0x20; call inner; add rsp,0x20 (inner entry = helper - 0x28)."""
    return (
        FunctionBuilder(entry=HELPER)
        .sub_rsp(0x20).call(INNER).add_rsp(0x20).ret()
    )


def test_nested_callee_own_frame_write_discharges():
    root = _frame_root(_helper_calling_inner(), extra={"inner": _writes_at(-0x10, entry=INNER)})
    assert root.is_effectively_complete


def test_nested_callee_writing_the_shifted_slot_is_not_discharged():
    # slot is helper +0x28 = inner +0x50
    root = _frame_root(_helper_calling_inner(), extra={"inner": _writes_at(0x50, 4, entry=INNER)})
    assert not root.is_effectively_complete


def test_recursive_callee_is_not_frame_discharged():
    helper = (
        FunctionBuilder(entry=HELPER)
        .sub_rsp(0x20)
        .cbranch("done", reg(ZF, 1))
        .call(HELPER)
        .label("done")
        .add_rsp(0x20).ret()
    )
    root = _frame_root(helper)
    assert not root.is_effectively_complete


def test_callee_with_callother_is_not_frame_discharged():
    helper = FunctionBuilder(entry=HELPER).ins(op("CALLOTHER", [const(0x10, 4)])).ret()
    root = _frame_root(helper)
    assert not root.is_effectively_complete


def test_unknown_callee_is_not_frame_discharged():
    functions = {
        "main": _main_with_stack_slot(), "source": _source_returning_constant(),
        "sink": _sink(),
    }
    assert not _root(functions).is_effectively_complete
