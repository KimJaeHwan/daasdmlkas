"""P0-3b: call-clobber debt discharged only by exact internal-callee evidence.

Every test runs the real interprocedural engine path
(``engine.analyze_observed_functions``) on a small synthetic program:
``main`` calls helpers, gets a value from ``source`` and passes it to
``sink`` in ECX. ``local_completeness`` keeps the raw call debt;
``effective_completeness`` removes debt discharged by callee evidence.
"""

import pytest

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


def test_a_constant_store_between_save_and_restore_needs_globals_disjoint():
    """PE-c (Astra r1 P1, Fable P2-1): helper saves RBX on its stack, stores to
    a constant address, restores RBX. Without globals-disjoint-from-stack the
    store may be the saved slot (a may-alias debt on the restoring load): no
    preservation certificate."""
    from synthetic import DATA_BASE, R8

    # (the save slot is the caller's home space [entry rsp + 8], not this frame's private bytes)
    helper = (FunctionBuilder(entry=HELPER)
              .ins(add(T, reg(RSP), const(8)), store(T, reg(RBX)))
              .ins(store(const(DATA_BASE), reg(R8)))
              .ins(add(T, reg(RSP), const(8)), load(reg(RBX), T))
              .ret())
    functions = {"main": _main_through_helper(), "source": _source_returning_constant(), "helper": helper,
                 "sink": _sink()}
    off = analyze_program(functions, PROVIDER)
    assert not off[("main", "sink.arg0")].is_effectively_complete
    on = analyze_program(functions, PROVIDER, normalize_options={"assume_globals_disjoint_from_stack": True})
    assert on[("main", "sink.arg0")].is_effectively_complete


@pytest.mark.parametrize("through", ("restore", "save"))
def test_a_restore_through_a_reloaded_pointer_needs_a_debt_free_address(through):
    """PE-c (Astra r3 P1-3): the pointer to the save slot is spilled, a constant
    store follows, the pointer is reloaded; RBX is saved to the slot and restored
    through the reloaded pointer. Without globals-disjoint-from-stack the
    constant store may have overwritten the spilled pointer: the restore's
    address carries alias debt, so no certificate (the restoring LOAD itself
    has no alias row). ``through`` "save": the save goes through the pointer
    and the restore is direct."""
    from synthetic import DATA_BASE, R8, R9

    T2 = tmp(0x108)
    helper = (FunctionBuilder(entry=HELPER).sub_rsp(0x20)
              .ins(add(T, reg(RSP), const(8)), add(T2, reg(RSP), const(0x10)), store(T2, T))   # [rsp+16] = &slot
              .ins(store(const(DATA_BASE), reg(R8)))
              .ins(add(T2, reg(RSP), const(0x10)), load(reg(R9), T2))                          # r9 = [rsp+16]
              .ins(add(T, reg(RSP), const(8))))
    if through == "restore":
        helper.ins(store(T, reg(RBX)), copy(reg(RBX), const(0)), load(reg(RBX), reg(R9)))   # [rsp+8]=rbx; rbx=[r9]
    else:
        helper.ins(store(reg(R9), reg(RBX)), copy(reg(RBX), const(0)), load(reg(RBX), T))   # [r9]=rbx; rbx=[rsp+8]
    helper.add_rsp(0x20).ret()
    functions = {"main": _main_through_helper(), "source": _source_returning_constant(), "helper": helper,
                 "sink": _sink()}
    off = analyze_program(functions, PROVIDER)
    assert not off[("main", "sink.arg0")].is_effectively_complete
    on = analyze_program(functions, PROVIDER, normalize_options={"assume_globals_disjoint_from_stack": True})
    assert on[("main", "sink.arg0")].is_effectively_complete


def test_a_constant_store_between_push_and_pop_needs_globals_disjoint():
    """PE-c (Astra r2 P1, PE-c-2; owner 2026-11-25: fix the analysis rule): the
    save slot is the helper's own new-frame byte (push / pop). The private-frame
    rule kept a constant-address writer out of it even without
    globals-disjoint-from-stack, which a constant address rests on."""
    from synthetic import DATA_BASE, R8

    helper = FunctionBuilder(entry=HELPER).push(RBX).ins(store(const(DATA_BASE), reg(R8))).pop(RBX).ret()
    functions = {"main": _main_through_helper(), "source": _source_returning_constant(), "helper": helper,
                 "sink": _sink()}
    off = analyze_program(functions, PROVIDER)
    assert not off[("main", "sink.arg0")].is_effectively_complete
    on = analyze_program(functions, PROVIDER, normalize_options={"assume_globals_disjoint_from_stack": True})
    assert on[("main", "sink.arg0")].is_effectively_complete


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_a_push_between_save_and_restore_at_a_constant_address_needs_globals_disjoint(engine, monkeypatch):
    """PE-c (Astra r3 P1-1 / Fable r3 P1-1): the private-frame rule is
    symmetric -- without globals-disjoint-from-stack the helper's own push may
    land on the constant-address save slot: [D] = RBX; push R8; RBX = [D]."""
    from synthetic import DATA_BASE, R8
    from tdo_v2._sparse_dataflow import DATAFLOW_ENGINE_ENV

    monkeypatch.setenv(DATAFLOW_ENGINE_ENV, engine)
    helper = (FunctionBuilder(entry=HELPER).ins(store(const(DATA_BASE), reg(RBX))).push(R8)
              .ins(load(reg(RBX), const(DATA_BASE))).pop(R8).ret())
    functions = {"main": _main_through_helper(), "source": _source_returning_constant(), "helper": helper,
                 "sink": _sink()}
    off = analyze_program(functions, PROVIDER)
    assert not off[("main", "sink.arg0")].is_effectively_complete
    on = analyze_program(functions, PROVIDER, normalize_options={"assume_globals_disjoint_from_stack": True})
    assert on[("main", "sink.arg0")].is_effectively_complete


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_a_push_crosses_a_constant_address_exit_byte_without_globals_disjoint(engine, monkeypatch):
    """PE-c (Fable r3 P1-1): the helper's exit summary of [D] must show its
    push as a crossing writer when globals-disjoint-from-stack is off."""
    from synthetic import DATA_BASE, R8
    from tdo_v2._sparse_dataflow import DATAFLOW_ENGINE_ENV

    from synthetic import normalize_with_observation
    from tdo_v2.function_summary import summarize_function
    from tdo_v2.model import StorageObjectKind

    monkeypatch.setenv(DATAFLOW_ENGINE_ENV, engine)
    helper = FunctionBuilder(entry=HELPER).ins(store(const(DATA_BASE), reg(RBX, 4))).push(R8).pop(R8).ret()

    def crossed(options):
        function, observation = normalize_with_observation(helper, normalize_options=options)
        (exit_summary,) = summarize_function(function, observation).exits
        runs = [run for run in exit_summary.runs if run.span.object_id.kind is StorageObjectKind.ADDRESS_SPACE
                and run.span.start <= DATA_BASE < run.span.end]
        assert runs
        return {label for run in runs for label in run.crossed if label.startswith("alias:")}

    assert crossed(None)   # (the push: "alias:<its STORE>")
    assert not crossed({"assume_globals_disjoint_from_stack": True})


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


def test_callee_global_write_discharges_under_globals_disjoint_from_stack():
    """PE-c (r18 amendment 8): a constant-address write is kept out of the
    caller's stack slot only under globals-disjoint-from-stack (it was an
    unlabelled axiom); without the assumption it may be the slot."""
    helper = FunctionBuilder(entry=HELPER).ins(store(const(DATA_BASE), reg(R8))).ret()
    functions = {"main": _main_with_stack_slot(), "source": _source_returning_constant(), "helper": helper,
                 "sink": _sink()}
    on = analyze_program(functions, PROVIDER, normalize_options={"assume_globals_disjoint_from_stack": True})
    assert on[("main", "sink.arg0")].is_effectively_complete
    off = analyze_program(functions, PROVIDER)
    assert not off[("main", "sink.arg0")].is_effectively_complete


@pytest.mark.parametrize("nested", (True, False))
def test_a_store_through_a_pointer_an_inner_call_may_overwrite_is_no_fixed_write(nested):
    """PE-c (Astra r3 P1-4, its fixture): helper sets [G] to a constant address,
    calls inner (which overwrites [G] with RDI), then stores through the
    reloaded [G]. Normalization marks that store uncertain; the frame proof must
    not take it for a constant-address write, even under
    globals-disjoint-from-stack. Control (``nested`` False): the same store with
    no inner call -- a genuinely fixed write, discharged under the assumption."""
    G = DATA_BASE + 0x40
    helper = FunctionBuilder(entry=HELPER).sub_rsp(0x28).ins(store(const(G), const(DATA_BASE + 0x100)))
    extra = {}
    if nested:
        helper.call(INNER)
        extra["inner"] = FunctionBuilder(entry=INNER).ins(store(const(G), reg(RDI))).ret()
    helper.ins(load(reg(RAX), const(G))).ins(store(reg(RAX), const(0))).add_rsp(0x28).ret()
    functions = {"main": _main_with_stack_slot(), "source": _source_returning_constant(), "helper": helper,
                 "sink": _sink(), **extra}
    on = analyze_program(functions, PROVIDER, normalize_options={"assume_globals_disjoint_from_stack": True})
    assert on[("main", "sink.arg0")].is_effectively_complete is (not nested)


def test_a_stack_switch_elsewhere_withdraws_the_frame_proof_end_to_end():
    """r18 amendment 8's own case: a function elsewhere in the program loads
    the stack pointer from memory, so globals-disjoint-from-stack is withdrawn
    for the run; the helper's constant-address write may then be the caller's
    slot -- the summary-engine root is no longer complete."""
    from synthetic import CODE_BASE, analyze_summaries

    helper = FunctionBuilder(entry=HELPER).ins(store(const(DATA_BASE), reg(R8))).ret()
    bodies = [_main_with_stack_slot(), _source_returning_constant(), helper, _sink()]
    names = {SOURCE: "source", SINK: "sink", HELPER: "helper"}

    def root(extra=()):
        run = analyze_summaries([*bodies, *extra], PROVIDER, names=names)
        found, = [item for item in run.roots if item.label == "sink.arg0" and item.function_byte_offset == MAIN]
        return found, run.assumptions

    plain, labels = root()
    assert plain.is_effectively_complete and "globals-disjoint-from-stack" in labels
    switch = FunctionBuilder(entry=CODE_BASE + 0x600).ins(load(reg(RBX), T)).ins(copy(reg(RSP), reg(RBX))).ret()
    switched, labels = root([switch])
    assert "globals-disjoint-from-stack" not in labels and not switched.is_effectively_complete


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


# -- a debt node per (read, crossing call) (docs 25.83 S2d) ---------------------

INNER2 = CODE_BASE + 0x600


def _keeps_rbx(entry):
    return FunctionBuilder(entry=entry).push(RBX).ins(copy(reg(RBX), const(0))).pop(RBX).ret()


def _main_through_two_helpers():
    """RBX = source(); helper(); inner(); sink(EBX) -- EBX crosses both."""
    return (
        FunctionBuilder(entry=MAIN)
        .call(SOURCE)
        .ins(copy(reg(RBX, 4), reg(RAX, 4)))
        .call(HELPER).call(INNER)
        .ins(copy(reg(RCX, 4), reg(RBX, 4)))
        .call(SINK)
        .ret()
    )


def test_a_read_crossing_two_calls_counts_once_and_needs_both_discharged():
    functions = {"main": _main_through_two_helpers(), "source": _source_returning_constant(),
                 "helper": _keeps_rbx(HELPER), "inner": _keeps_rbx(INNER), "sink": _sink()}
    root = _root(functions)
    assert root.is_effectively_complete
    # (one debt per read: rbx=eax after source, rcx=ebx after helper and inner)
    assert root.local_completeness.reachable_unresolved_reads == 2
    functions["inner"] = FunctionBuilder(entry=INNER).ins(copy(reg(RBX), const(0))).ret()
    root = _root(functions)
    assert not root.is_effectively_complete
    assert root.effective_completeness.reachable_unresolved_reads == 1   # (helper's pair alone is discharged)


def test_a_saved_slot_crossing_two_nested_calls_needs_both_to_keep_it():
    """helper: push rbx; call inner; call inner2; pop rbx -- the pop crosses both
    (the callee-side judgement, ``_callee_read_discharged``, on pair rows)."""
    helper = FunctionBuilder(entry=HELPER).push(RBX).call(INNER).call(INNER2).pop(RBX).ret()
    functions = {"main": _main_through_helper(), "source": _source_returning_constant(), "helper": helper,
                 "inner": FunctionBuilder(entry=INNER).ret(), "inner2": FunctionBuilder(entry=INNER2).ret(),
                 "sink": _sink()}
    assert _root(functions).is_effectively_complete
    functions["inner2"] = (FunctionBuilder(entry=INNER2)
                           .ins(add(T, reg(RSP), const(8)), store(T, reg(RDI))).ret())   # (the saved slot)
    assert not _root(functions).is_effectively_complete


def test_the_callee_side_judges_a_shared_row_once(monkeypatch):
    """The pop's row stands for two pair nodes (inner, inner2): judged once per
    context within a discharge, also on the recursive callee path."""
    from collections import Counter

    from tdo_v2.integration.configured_call_clobber_discharge import CallClobberDischarger

    judged = Counter()
    original = CallClobberDischarger._discharge_read

    def counting(self, entry, read, context, active):
        judged[(entry, read, id(context), active)] += 1
        return original(self, entry, read, context, active)

    monkeypatch.setattr(CallClobberDischarger, "_discharge_read", counting)
    helper = FunctionBuilder(entry=HELPER).push(RBX).call(INNER).call(INNER2).pop(RBX).ret()
    root = _root({"main": _main_through_helper(), "source": _source_returning_constant(), "helper": helper,
                  "inner": FunctionBuilder(entry=INNER).ret(), "inner2": FunctionBuilder(entry=INNER2).ret(),
                  "sink": _sink()})
    assert root.is_effectively_complete
    assert judged and max(judged.values()) == 1


@pytest.mark.parametrize("on", (True, False))
@pytest.mark.parametrize("arms", (2, 1))
def test_a_push_pop_whose_stack_pointer_joins_two_arms_stays_preserved(arms, on):
    """Fable PE-c r4 P2-1: the restore's address (the stack pointer) reaches it
    through a JOIN of two definitions (one arm moves it and back); the
    address-slice check accepts a JOIN of clean definitions, with or without
    globals-disjoint-from-stack (no constant store in play). ``arms`` 1: the
    control without a join."""
    helper = FunctionBuilder(entry=HELPER).push(RBX)
    if arms == 2:
        helper.cbranch("done", reg(ZF, 1)).push(RCX).pop(RCX).label("done")
    else:
        helper.push(RCX).pop(RCX)
    helper.ins(copy(reg(RBX), const(0))).pop(RBX).ret()
    functions = {"main": _main_through_helper(), "source": _source_returning_constant(), "helper": helper,
                 "sink": _sink()}
    roots = analyze_program(functions, PROVIDER, normalize_options={"assume_globals_disjoint_from_stack": on})
    assert roots[("main", "sink.arg0")].is_effectively_complete
