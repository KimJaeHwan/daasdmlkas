"""TEST-ONLY special condition: boundary calls cut with a declared effect.

With ``assume_boundary_call_effects=True`` and rules that set
``assume_call_effect``, a source call is modelled as writing only its declared
output register and a sink call as writing nothing; every other register and
all memory are *assumed* preserved. The code between boundaries is then
sliced as if call-free. This is a declared assumption for testing, not
observed evidence, and is off by default.
"""

from synthetic import (
    CODE_BASE, RAX, RBX, RCX, RDX, ZF,
    FunctionBuilder, analyze_program, boundary, const, copy, reg,
)

MAIN, SOURCE, SINK, HELPER = CODE_BASE, CODE_BASE + 0x800, CODE_BASE + 0xA00, CODE_BASE + 0xC00


def _program(main, extra=None):
    functions = {
        "main": main,
        "source": FunctionBuilder(entry=SOURCE).ins(copy(reg(RAX, 4), const(7, 4))).ret(),
        "sink": FunctionBuilder(entry=SINK).ret(),
    }
    functions.update(extra or {})
    return functions


def _root(main, *, assume, extra=None):
    provider = boundary({"source": 4}, {"sink": 4}, assume_call_effect=assume)
    roots = analyze_program(_program(main, extra), provider, assume_boundary_call_effects=assume)
    return roots[("main", "sink.arg0")]


def _direct():
    return FunctionBuilder(entry=MAIN).call(SOURCE).ins(copy(reg(RCX, 4), reg(RAX, 4))).call(SINK).ret()


def test_default_keeps_call_debt():
    root = _root(_direct(), assume=False)
    assert not root.is_locally_complete


def test_assumed_source_output_is_a_local_origin():
    root = _root(_direct(), assume=True)
    assert root.local_origin_labels == ("source.ret",)
    assert root.is_locally_complete


def test_branchy_body_between_boundaries_is_sliced_locally():
    """if (ZF) ECX = EAX else ECX = 0; sink(ECX)."""
    main = (
        FunctionBuilder(entry=MAIN)
        .call(SOURCE)
        .cbranch("zero", reg(ZF, 1))
        .ins(copy(reg(RCX, 4), reg(RAX, 4)))
        .branch("join")
        .label("zero")
        .ins(copy(reg(RCX, 4), const(0, 4)))
        .label("join")
        .call(SINK)
        .ret()
    )
    root = _root(main, assume=True)
    assert root.local_origin_labels == ("source.ret",)
    assert root.is_locally_complete


def test_other_registers_are_assumed_preserved_across_the_source_call():
    """RBX = RDX; source(); sink(EBX): complete only because of the assumption."""
    main = (
        FunctionBuilder(entry=MAIN)
        .ins(copy(reg(RBX), reg(RDX)))
        .call(SOURCE)
        .ins(copy(reg(RCX, 4), reg(RBX, 4)))
        .call(SINK)
        .ret()
    )
    assert _root(main, assume=True).is_locally_complete
    assert not _root(main, assume=False).is_locally_complete


def test_non_boundary_call_still_carries_debt():
    """source(); helper(); sink(EAX): helper has no declared effect."""
    main = (
        FunctionBuilder(entry=MAIN)
        .call(SOURCE).call(HELPER)
        .ins(copy(reg(RCX, 4), reg(RAX, 4)))
        .call(SINK).ret()
    )
    root = _root(main, assume=True, extra={"helper": FunctionBuilder(entry=HELPER).ret()})
    assert not root.is_locally_complete


def test_rules_without_the_flag_are_not_assumed():
    provider = boundary({"source": 4}, {"sink": 4}, assume_call_effect=False)
    roots = analyze_program(_program(_direct()), provider, assume_boundary_call_effects=True)
    assert not roots[("main", "sink.arg0")].is_locally_complete


def test_default_mode_does_not_claim_a_joined_sink_argument_complete():
    """Without the assumption the sink's argument (a JOIN) has no graph node to
    root at; the root binds to the call's consume event and must be incomplete,
    never an empty "complete" answer."""
    main = (
        FunctionBuilder(entry=MAIN)
        .call(SOURCE)
        .cbranch("zero", reg(ZF, 1))
        .ins(copy(reg(RCX, 4), reg(RAX, 4)))
        .branch("join")
        .label("zero")
        .ins(copy(reg(RCX, 4), const(0, 4)))
        .label("join")
        .call(SINK)
        .ret()
    )
    root = _root(main, assume=False)
    assert not root.is_locally_complete
    assert not root.is_effectively_complete
    assert root.local_completeness.unbound_roots == 1


def test_declared_boundary_calls_do_not_make_the_frame_escape():
    """RBP = RSP; *(RBP-8) = EAX; *(global) = 1; sink(*(RBP-8)).

    With an undeclared call, the frame-pointer copy counts as an escape and the
    global write may alias the slot. Declared boundary calls observe nothing,
    so the private slot stays private.
    """
    from synthetic import DATA_BASE, RBP, RSP, add, load, store, tmp

    T = tmp(0x100)
    main = (
        FunctionBuilder(entry=MAIN)
        .push(RBP).ins(copy(reg(RBP), reg(RSP))).sub_rsp(0x20)
        .call(SOURCE)
        .ins(add(T, reg(RBP), const(-8 & 0xFFFFFFFFFFFFFFFF)), store(T, reg(RAX, 4)))
        .ins(store(const(DATA_BASE), const(1, 4)))
        .ins(add(T, reg(RBP), const(-8 & 0xFFFFFFFFFFFFFFFF)), load(reg(RCX, 4), T))
        .call(SINK)
        .add_rsp(0x20).pop(RBP).ret()
    )
    root = _root(main, assume=True)
    assert root.local_origin_labels == ("source.ret",)
    assert root.is_locally_complete
