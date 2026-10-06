"""P0-3b: call-clobber debt discharged only by exact internal-callee evidence.

Every test runs the real interprocedural engine path
(``engine.analyze_observed_functions``) on a small synthetic program:
``main`` calls helpers, gets a value from ``source`` and passes it to
``sink`` in ECX. ``local_completeness`` keeps the raw call debt;
``effective_completeness`` removes debt discharged by callee evidence.
"""

from synthetic import (
    CODE_BASE, RAX, RBP, RBX, RCX, RDI, RSP, ZF,
    FunctionBuilder, analyze_program, boundary, const, copy, load, op, reg,
)

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


def test_incomplete_callee_value_is_not_discharged():
    """source returns *(RDI*2): its own slice has unresolved-address debt."""
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


def test_nested_call_between_save_and_restore_is_not_discharged():
    """helper: push rbx; call inner; pop rbx -- inner could overwrite the slot."""
    helper = (
        FunctionBuilder(entry=HELPER)
        .push(RBX).call(INNER).pop(RBX).ret()
    )
    inner = FunctionBuilder(entry=INNER).ret()
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
