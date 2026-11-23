"""(G-T G3b-4, docs 25.110; design r19-r20) Physical callee contexts through composed tails.

A physical CALL context ``C -> F`` whose callee leaves through a composed
``branch`` / ``cbranch`` tail to an analyzed ``T`` expands the tail as a nested
``kind: "tail"`` context: ``T``'s body bound at the tail (no push; its entry view
is ``F``'s plus ``F``'s events before the tail), and ``T``'s RETURN must reach
``C``'s fallthrough with ``C``'s pre-push stack -- checked on the run, no ABI
assumption. ``F``'s terminal rows name the tail context; the record validator
requires the row and the context to correspond. Stage 1 binds ``T``'s entry
through the tail's staged reads only (pass-through bytes are cut by the P-fix
rule); ``branchind`` tails, escape edges and the root's own tails stay refused.
"""

import copy

import pytest

from pcode_interpreter import Interpreter
from record_oracle import entry_reader, final_register
from synthetic import (
    CONST, RAM, REG, RAX, RCX, RDI, RDX, RSP, FunctionBuilder, add, const, copy as copy_op, load, op, reg, store,
    sub, tmp,
)
from test_gt_conditional_tails import _to
from test_physical_call_records import POINTER, STACK, _case, _record

from tdo_v2._record_memory import evaluate_physical
from tdo_v2.operation_records import Ineligible

F, T, U = 0x1800, 0x1a00, 0x1c00
ROOT_KEY = "1:1008:0:INT_ADD"   # C: sub rsp; call F; rax += 5 <- the root
FALLTHROUGH = 0x1008            # C's call at 0x1004 pushes its fallthrough


def _caller():
    return FunctionBuilder().sub_rsp(0x28).call(F).ins(add(reg(RAX), reg(RAX), const(5))).add_rsp(0x28).ret()


def _jump(builder, index=None):
    """Turn the builder's last ``tail_call`` row into an unflagged BRANCH tail."""
    raw = builder.to_json()
    row = raw["instructions"][-1 if index is None else index]
    row["operations"][-1]["opcode"] = "BRANCH"
    row["flow_type"]["is_call"], row["flow_type"]["is_jump"] = False, True
    builder.to_json = lambda raw=raw: raw
    return builder


def _returns(entry=T, increment=1):
    """``rax = rdi + increment; ret``."""
    return FunctionBuilder(entry=entry).ins(add(reg(RAX), reg(RDI), const(increment))).ret()


def _run(case, rcx=0x40, rdi=0x30):
    vm = Interpreter(case["item"].unit.observation, constant_space=CONST, seed=0, program=case["program"],
                     resume_unvalidated_returns=True)
    for offset, contents in ((RSP, STACK), (RCX, rcx), (RDI, rdi), (RDX, POINTER)):
        vm.preset(REG, offset, 8, contents)
    vm.preset(RAM, STACK, 8, 0x2000)
    vm.preset(RAM, POINTER, 8, 0x77)
    vm.run()
    return vm


def _equal(case, record, **inputs):
    vm = _run(case, **inputs)
    assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8)
    return vm


def _tail_contexts(record):
    return {key: context for key, context in record.get("physical_calls", {}).items() if context.get("kind") == "tail"}


# -- positive: VM-equal -------------------------------------------------------------------


def test_a_branch_tail_callee_evaluates_through_its_target():
    middle = _jump(FunctionBuilder(entry=F).ins(copy_op(reg(RDI), reg(RCX))).tail_call(T))
    case = _case(_caller(), middle, _returns())
    record = _record(case, ROOT_KEY)
    assert not record.get("physical_call_cuts") and len(_tail_contexts(record)) == 1
    (tail,) = _tail_contexts(record).values()
    assert tail["push"] is None and tail["parent_context"] == "1:1004:2:CALL" and tail["function"] == "1:1a00"
    assert {row["expected_target"] for row in tail["returns"]} == {FALLTHROUGH}
    _equal(case, record)


@pytest.mark.parametrize("rcx", [0, 0x40])
def test_a_conditional_tail_callee_evaluates_on_both_outcomes(rcx):
    flag = tmp(0x320, 1)
    middle = (FunctionBuilder(entry=F).ins(copy_op(reg(RDI), reg(RCX)))
              .cbranch("x", flag, op("INT_EQUAL", [reg(RCX), const(0)], flag))
              .ins(copy_op(reg(RAX), const(7))).label("x").ret())
    case = _case(_caller(), _to(middle, 1, T), _returns())
    record = _record(case, ROOT_KEY)
    rows = record["physical_calls"]["1:1004:2:CALL"]["returns"]
    assert sorted("tail_context" in row for row in rows) == [False, True]
    _equal(case, record, rcx=rcx)


def test_a_thunk_without_a_return_evaluates():
    """A pure-tail ``F`` (no RETURN): its only terminal is the tail row."""
    case = _case(_caller(), _jump(FunctionBuilder(entry=F).tail_call(T)), _returns())
    record = _record(case, ROOT_KEY)
    (row,) = record["physical_calls"]["1:1004:2:CALL"]["returns"]
    assert row["tail_context"] and row["expected_target"] == FALLTHROUGH
    _equal(case, record)


def test_a_tail_chain_evaluates():
    """``F -> T -> U``: T's own composed tail is a nested tail context."""
    case = _case(_caller(), _jump(FunctionBuilder(entry=F).tail_call(T)),
                 _jump(FunctionBuilder(entry=T).ins(add(reg(RDI), reg(RDI), const(2))).tail_call(U)),
                 _returns(U, 3))
    record = _record(case, ROOT_KEY)
    tails = _tail_contexts(record)
    assert len(tails) == 2 and {context["function"] for context in tails.values()} == {"1:1a00", "1:1c00"}
    _equal(case, record)


def test_a_return_slot_overwritten_then_restored_is_accepted():
    """``t = [rsp]; [rsp] = 0x9999; [rsp] = t; jmp T``: what T's RETURN loads is
    the restored address -- a write to the slot is not a failure by itself."""
    saved = tmp(0x340)
    middle = _jump(FunctionBuilder(entry=F).ins(load(saved, reg(RSP)), store(reg(RSP), const(0x9999)),
                                                store(reg(RSP), saved)).tail_call(T))
    case = _case(_caller(), middle, _returns())
    _equal(case, _record(case, ROOT_KEY))


def test_a_stack_moved_by_f_and_compensated_by_t_is_accepted():
    """``F: rsp -= 8; [rsp] = C's fallthrough; jmp T``, ``T: rsp += 8 ... ret`` would
    return elsewhere; here ``F: rsp -= 8; jmp T`` and ``T: rsp += 8; ret``: T reads
    the right slot and leaves C's stack."""
    middle = _jump(FunctionBuilder(entry=F).ins(sub(reg(RSP), reg(RSP), const(8))).tail_call(T))
    target = FunctionBuilder(entry=T).ins(add(reg(RSP), reg(RSP), const(8))) \
        .ins(add(reg(RAX), reg(RDI), const(1))).ret()
    case = _case(_caller(), middle, target)
    _equal(case, _record(case, ROOT_KEY))


def test_two_conditional_tails_in_one_callee():
    flag, other = tmp(0x320, 1), tmp(0x328, 1)
    middle = (FunctionBuilder(entry=F).ins(copy_op(reg(RDI), reg(RCX)))
              .cbranch("x", flag, op("INT_EQUAL", [reg(RCX), const(0)], flag))
              .cbranch("x", other, op("INT_EQUAL", [reg(RCX), const(1)], other))
              .ins(copy_op(reg(RAX), const(7))).label("x").ret())
    middle = _to(_to(middle, 1, T), 2, U)
    case = _case(_caller(), middle, _returns(), _returns(U, 9))
    record = _record(case, ROOT_KEY)
    assert len(_tail_contexts(record)) == 2
    for rcx in (0, 1, 0x40):
        _equal(case, record, rcx=rcx)


# -- negative ---------------------------------------------------------------------------


def test_a_return_slot_overwritten_with_another_target_refuses():
    middle = _jump(FunctionBuilder(entry=F).ins(store(reg(RSP), const(0x9999))).tail_call(T))
    case = _case(_caller(), middle, _returns())
    record = _record(case, ROOT_KEY)
    with pytest.raises(Ineligible, match="return target mismatch"):
        evaluate_physical(record, entry_reader(_run(case)))


def test_a_wrong_final_stack_with_the_right_target_refuses():
    """``F: rsp -= 8; [rsp] = C's fallthrough; jmp T``: T's RETURN loads the right
    target from the slot F wrote, but leaves SP 8 below C's -- the stack check."""
    middle = _jump(FunctionBuilder(entry=F).ins(sub(reg(RSP), reg(RSP), const(8)),
                                                store(reg(RSP), const(FALLTHROUGH))).tail_call(T))
    case = _case(_caller(), middle, _returns())
    record = _record(case, ROOT_KEY)
    with pytest.raises(Ineligible, match="return stack mismatch"):
        evaluate_physical(record, entry_reader(_run(case)))


def test_a_callee_with_an_escape_edge_is_still_refused():
    flag = tmp(0x320, 1)
    middle = (FunctionBuilder(entry=F).cbranch("x", flag, op("INT_EQUAL", [reg(RCX), const(0)], flag))
              .ins(copy_op(reg(RAX), const(7))).label("x").ret())
    case = _case(_caller(), _to(middle, 0, 0x1e00))
    record = _record(case, ROOT_KEY)
    assert record.get("physical_call_cuts", {}).get("1:1004:2:CALL") and not _tail_contexts(record)
    from tdo_v2._record_calls import _admitted_tails
    from tdo_v2.operation_records import _StitchCut

    with pytest.raises(_StitchCut, match="physical callee has a non-RETURN exit"):
        _admitted_tails(case["callee"])   # (the admission itself, whatever refused the call first)


def test_a_crossed_register_inside_the_target_is_cut():
    """P-fix inside the tail context: ``T: rax = 0; call H (rax unknown); ret``."""
    unknown = tmp(0x300)
    inner = FunctionBuilder(entry=0x1e00).ins(op("INT_XOR", [reg(RCX), reg(RDX)], unknown),
                                              load(reg(RAX), unknown)).ret()
    target = FunctionBuilder(entry=T).sub_rsp(0x28).ins(copy_op(reg(RAX), const(0))).call(0x1e00) \
        .add_rsp(0x28).ret()
    case = _case(_caller(), _jump(FunctionBuilder(entry=F).tail_call(T)), target, inner)
    record = _record(case, ROOT_KEY)
    assert any("crosses a call" in row["reason"] for row in record.get("physical_output_cuts", ())), \
        record.get("physical_output_cuts")


# -- the correspondence contract (design r20 final fixes) --------------------------------


def _branch_case():
    middle = _jump(FunctionBuilder(entry=F).ins(copy_op(reg(RDI), reg(RCX))).tail_call(T))
    case = _case(_caller(), middle, _returns())
    return case, _record(case, ROOT_KEY)


def _tamper(record, change):
    altered = copy.deepcopy(record)
    change(altered, next(key for key, item in altered["physical_calls"].items() if item.get("kind") == "tail"))
    return altered


CORRESPONDENCE = "physical tail terminal correspondence"


@pytest.mark.parametrize("change, reason", [
    pytest.param(lambda record, tail: record["physical_calls"][tail]["returns"][0].update(expected_target=0x2222),
                 CORRESPONDENCE, id="child-continuation"),
    pytest.param(lambda record, tail: record["physical_calls"]["1:1004:2:CALL"]["returns"][0]
                 .update(tail_context="1:1004:2:CALL"), "physical tail (terminal|export) correspondence",
                 id="row-reference"),
    pytest.param(lambda record, tail: record["physical_calls"]["1:1004:2:CALL"].update(
        events=[event for event in record["physical_calls"]["1:1004:2:CALL"]["events"]
                if event.get("context") != tail]), CORRESPONDENCE, id="event-removed"),
    pytest.param(lambda record, tail: record["physical_calls"][tail].update(parent_context=tail),
                 "parent cycle", id="parent"),
    pytest.param(lambda record, tail: record["physical_calls"][tail].update(call="1:1800:0:BRANCH"),
                 "unknown physical call context", id="site"),
    pytest.param(lambda record, tail: record["physical_calls"][tail].update(push={"kind": "store"}),
                 "incomplete physical tail context", id="push"),
])
def test_an_altered_tail_correspondence_refuses(change, reason):
    case, record = _branch_case()
    vm = _equal(case, record)
    with pytest.raises(Ineligible, match=reason):
        evaluate_physical(_tamper(record, change), entry_reader(vm))


# -- code review r1 (Astra REJECT P1 x2, P2) -------------------------------------------------


def _node(record, identifier):
    return next(node for node in record["nodes"] if node["id"] == identifier)


def test_a_substituted_tail_export_refuses():
    """The parent's wrapper must hold exactly the tail context's export: putting
    F's ``rdi = rcx`` producer in it (0x45 instead of 0x46) refuses."""
    case, record = _branch_case()
    vm = _equal(case, record)

    def change(altered, tail):
        (output,) = altered["physical_calls"]["1:1004:2:CALL"]["outputs"]
        wrapper = _node(altered, output["part"]["node"])
        forged = next(node for node in altered["nodes"] if node.get("physical_context") == "1:1004:2:CALL"
                      and str(node.get("key", "")).endswith(":COPY"))
        wrapper["parts"][0]["node"] = forged["id"]
    with pytest.raises(Ineligible, match="physical tail export correspondence"):
        evaluate_physical(_tamper(record, change), entry_reader(vm))


def test_a_forged_continuation_stack_refuses():
    """Every inherited ``expected_stack`` replaced, consistently, by the leaf
    RETURN's own stack operand: the call context's rows must expect the
    pre-push SP its push was built from."""
    middle = _jump(FunctionBuilder(entry=F).ins(sub(reg(RSP), reg(RSP), const(8)),
                                                store(reg(RSP), const(FALLTHROUGH))).tail_call(T))
    case = _case(_caller(), middle, _returns())
    record = _record(case, ROOT_KEY)

    def change(altered, tail):
        forged = copy.deepcopy(altered["physical_calls"][tail]["returns"][0]["stack"])
        for context in altered["physical_calls"].values():
            for row in context.get("returns", ()):
                row["expected_stack"] = forged
            if "return" in context:
                context["return"]["expected_stack"] = forged
    with pytest.raises(Ineligible, match="physical continuation stack is not the push's"):
        evaluate_physical(_tamper(record, change), entry_reader(_run(case)))


def test_a_tail_event_that_is_no_call_refuses():
    case, record = _branch_case()
    vm = _equal(case, record)

    def change(altered, tail):
        for event in altered["physical_calls"]["1:1004:2:CALL"]["events"]:
            if event.get("context") == tail:
                event["kind"] = "write"
    with pytest.raises(Ineligible, match="physical tail terminal correspondence"):
        evaluate_physical(_tamper(record, change), entry_reader(vm))


def test_an_orphan_tail_context_refuses():
    """A ``kind: "tail"`` context no parent row names."""
    case, record = _branch_case()
    vm = _equal(case, record)

    def change(altered, tail):
        orphan = altered["physical_calls"][tail + "#orphan"] = copy.deepcopy(altered["physical_calls"][tail])
        orphan["outputs"] = []   # (no exports: only the reverse correspondence can refuse it)
    with pytest.raises(Ineligible, match="physical tail terminal correspondence"):
        evaluate_physical(_tamper(record, change), entry_reader(vm))


def test_a_memory_write_in_the_tail_target_is_read_back_by_the_caller():
    """``C: call F; rax = [rdx] + 5``, ``F: jmp T``, ``T: [rdx] = rdi; ret``: the
    caller's LOAD sees T's store through the tail context's body."""
    caller = (FunctionBuilder().sub_rsp(0x28).call(F)
              .ins(load(reg(RAX), reg(RDX)), add(reg(RAX), reg(RAX), const(5))).add_rsp(0x28).ret())
    target = FunctionBuilder(entry=T).ins(store(reg(RDX), reg(RDI))).ret()
    case = _case(caller, _jump(FunctionBuilder(entry=F).tail_call(T)), target)
    record = _record(case, "1:1008:1:INT_ADD")
    assert _tail_contexts(record)
    vm = _equal(case, record)
    assert final_register(vm, RAX, 8) == 0x35


def test_a_neutered_tail_event_refuses():
    """(Fable r1 P2-1) The one tail event turned into an inactive non-call event:
    the child would never be validated -- the correspondence requires a call
    event at the row's site and guard (M5 stays as the runtime defence)."""
    case, record = _branch_case()
    vm = _equal(case, record)

    def change(altered, tail):
        for event in altered["physical_calls"]["1:1004:2:CALL"]["events"]:
            if event.get("context") == tail:
                event.update(kind="opaque", guard=0)
    with pytest.raises(Ineligible, match="physical tail terminal correspondence"):
        evaluate_physical(_tamper(record, change), entry_reader(vm))


def test_a_tail_record_renders():
    from tdo_v2.operation_records import render

    case, record = _branch_case()
    text = render(record)
    assert "physical tail " in text and "tail -> " in text


@pytest.mark.parametrize("reads", [True, False])
def test_a_call_in_f_before_the_tail_never_leaks_its_stale_input(reads):
    """(Fable r1 P2-3) ``F: rax = 0x11; call H (rax unknown); jmp T`` with ``T``
    reading rax (``rax += 1``) or passing it through: the record is cut or equals
    the run -- never built from the pre-call constant."""
    unknown = tmp(0x300)
    inner = FunctionBuilder(entry=0x1e00).ins(op("INT_XOR", [reg(RCX), reg(RDX)], unknown),
                                              load(reg(RAX), unknown)).ret()
    middle = _jump(FunctionBuilder(entry=F).sub_rsp(0x28).ins(copy_op(reg(RAX), const(0x11))).call(0x1e00)
                   .add_rsp(0x28).tail_call(T))
    target = FunctionBuilder(entry=T).ins(add(reg(RAX), reg(RAX), const(1))) if reads \
        else FunctionBuilder(entry=T).ins(add(reg(RDI), reg(RDI), const(1)))
    case = _case(_caller(), middle, target.ret(), inner)
    record = _record(case, ROOT_KEY)
    vm = _run(case)
    # stage 2: T's rax is bound through the tail snapshot / the unmodified
    # staged read, whose trace stops at H's call: the run's value or a named
    # cut -- never the pre-call constant (stage 1 pinned the cut)
    if not reads:   # (a pass-through register has no exit run in T: P-fix)
        assert any("has no exit run" in row["reason"] for row in record.get("physical_output_cuts", ())),             record.get("physical_output_cuts")
        with pytest.raises(Ineligible):
            evaluate_physical(record, entry_reader(vm))
        return
    value = evaluate_physical(record, entry_reader(vm)).value
    assert value == final_register(vm, RAX, 8) and value != 0x12


def test_a_nested_call_context_flipped_to_a_tail_refuses():
    """(Fable r1 P2-2) An ordinary nested call context of F relabelled
    ``kind: "tail"`` (push dropped): no parent row names it -- refused."""
    inner = FunctionBuilder(entry=0x1e00).ins(add(reg(RAX), reg(RDI), const(2))).ret()
    middle = _jump(FunctionBuilder(entry=F).sub_rsp(0x28).call(0x1e00).add_rsp(0x28)
                   .ins(copy_op(reg(RDI), reg(RAX))).tail_call(T))
    case = _case(_caller(), middle, _returns(), inner)
    record = _record(case, ROOT_KEY)
    nested = [key for key, context in record["physical_calls"].items()
              if context.get("kind") is None and context.get("parent_context") == "1:1004:2:CALL"]
    assert nested, sorted(record["physical_calls"])
    vm = _run(case)

    def change(altered, tail):
        altered["physical_calls"][nested[0]].update(kind="tail", push=None)
    with pytest.raises(Ineligible, match="physical tail terminal correspondence"):
        evaluate_physical(_tamper(record, change), entry_reader(vm))



# -- stage 2 (design r20 final fixes): tail register snapshots ----------------------------------


def test_a_value_an_earlier_call_in_f_exports_reaches_t_through_the_tail_snapshot():
    """(stage 2) ``F: call H (rax = rdi + 2); jmp T``, ``T: rax += 1``: T's rax
    binds through the tail boundary (the trace stops at H's call, H's export
    supplies it) -- equal to the run (stage 1 refused: no CALL projection)."""
    inner = FunctionBuilder(entry=0x1e00).ins(add(reg(RAX), reg(RDI), const(2))).ret()
    middle = _jump(FunctionBuilder(entry=F).sub_rsp(0x28).call(0x1e00).add_rsp(0x28).tail_call(T))
    target = FunctionBuilder(entry=T).ins(add(reg(RAX), reg(RAX), const(1))).ret()
    case = _case(_caller(), middle, target, inner)
    record = _record(case, ROOT_KEY)
    _equal(case, record)
    assert not record.get("physical_output_cuts"), record.get("physical_output_cuts")


@pytest.mark.parametrize("rcx", [0, 0x40])
def test_a_conditional_tail_binds_through_its_edge_block_snapshot(rcx):
    """(stage 2) a conditional tail: the group is in the taken edge block, the
    trace starts at the raw CBRANCH in its source block -- both outcomes equal
    the run."""
    flag = tmp(0x320, 1)
    inner = FunctionBuilder(entry=0x1e00).ins(add(reg(RAX), reg(RDI), const(2))).ret()
    middle = (FunctionBuilder(entry=F).sub_rsp(0x28).call(0x1e00).add_rsp(0x28)
              .cbranch("x", flag, op("INT_EQUAL", [reg(RCX), const(0)], flag))
              .ins(copy_op(reg(RAX), const(7))).label("x").ret())
    target = FunctionBuilder(entry=T).ins(add(reg(RAX), reg(RAX), const(1))).ret()
    case = _case(_caller(), _to(middle, 3, T), target, inner)
    record = _record(case, ROOT_KEY)
    _equal(case, record, rcx=rcx)


def test_a_pass_through_register_stays_cut_in_stage_2():
    """(stage 2 limit) ``F: rax = 0x77; jmp T`` with T not touching rax: T has
    no exit run for rax (P-fix) and the tail-export contract only accepts the
    tail context's own export -- a named cut, never a guessed value."""
    middle = _jump(FunctionBuilder(entry=F).ins(copy_op(reg(RAX), const(0x77))).tail_call(T))
    case = _case(_caller(), middle, FunctionBuilder(entry=T).ins(add(reg(RDI), reg(RDI), const(1))).ret())
    record = _record(case, ROOT_KEY)
    assert any("has no exit run" in row["reason"] for row in record.get("physical_output_cuts", ()))
    with pytest.raises(Ineligible):
        evaluate_physical(record, entry_reader(_run(case)))



@pytest.mark.parametrize("through_call", [False, True])
@pytest.mark.parametrize("rcx", [0, 0x40])
def test_a_register_t_only_branches_on_binds_through_the_tail_snapshot(through_call, rcx):
    """(stage 2; Astra r1) T uses rdi only in its branch condition, so the tail
    has no staged read of it: rdi binds through the tail snapshot -- F's own
    ``rdi = 0`` or an earlier call H's ``rdi = 0`` (F wrote 1 before it).
    Equal to the run on both outcomes of F's conditional tail."""
    flag, zero = tmp(0x320, 1), tmp(0x328, 1)
    inner = FunctionBuilder(entry=0x1e00).ins(copy_op(reg(RDI), const(0))).ret()
    middle = FunctionBuilder(entry=F).sub_rsp(0x28)
    if through_call:
        middle.ins(copy_op(reg(RDI), const(1))).call(0x1e00)
    else:
        middle.ins(copy_op(reg(RDI), const(0)))
    middle.add_rsp(0x28).cbranch("x", flag, op("INT_EQUAL", [reg(RCX), const(0)], flag))         .ins(copy_op(reg(RAX), const(7))).label("x").ret()
    index = 4 if through_call else 3
    target = (FunctionBuilder(entry=T).ins(copy_op(reg(RAX), const(17)))
              .cbranch("y", zero, op("INT_EQUAL", [reg(RDI), const(0)], zero))
              .ins(copy_op(reg(RAX), const(16))).label("y").ins(add(reg(RAX), reg(RAX), const(1))).ret())
    case = _case(_caller(), _to(middle, index, T), target, *((inner,) if through_call else ()))
    record = _record(case, ROOT_KEY)
    _equal(case, record, rcx=rcx)



@pytest.mark.parametrize("failure, reason", [
    ("empty", "tail boundary without staged rows"),
    ("error", "tail snapshot unavailable"),
])
def test_a_missing_tail_snapshot_is_a_named_cut(monkeypatch, failure, reason):
    """(stage 2; Astra r2 P1) no group for the site (e.g. a taken block holding
    only its ``~edge`` marker) or a failing snapshot pass: the tail context is
    cut with a named reason -- never a crash (r2: an unimported ``_StitchCut``)."""
    import tdo_v2.memory_ssa as memory_ssa

    def broken(unit, ssa, groups):
        if failure == "error":
            raise KeyError("raw definition missing")
        return {}
    monkeypatch.setattr(memory_ssa, "tail_register_snapshots", broken)
    middle = _jump(FunctionBuilder(entry=F).ins(copy_op(reg(RDI), reg(RCX))).tail_call(T))
    case = _case(_caller(), middle, _returns())
    record = _record(case, ROOT_KEY)
    assert reason in set((record.get("physical_call_cuts") or {}).values()), record.get("physical_call_cuts")


@pytest.mark.parametrize("adjust, ok", [(8, True), (16, False)])
def test_a_tail_takes_sp_from_its_snapshot_without_a_staged_sp_read(adjust, ok):
    """(stage 2; Astra r1 P2-2 / r2 P3) F saves [rsp] in rdx and jumps to T; T
    sets rax = 18, advances rsp and returns through rdx. No staged SP read:
    SP comes from the tail snapshot (empty skip set) -- equal to the run; a
    wrong SP adjustment is refused at the return check."""
    target = FunctionBuilder(entry=T).ins(copy_op(reg(RAX), const(18))).ret()
    raw = target.to_json()
    ops = raw["instructions"][-1]["operations"]
    ops[0].update(opcode="COPY", inputs=[reg(RDX)])
    for item in ops:
        if item["opcode"] == "INT_ADD" and item["inputs"][1].get("kind_code") == 1:   # (the constant 8)
            item["inputs"][1]["byte_offset"] = adjust
    target.to_json = lambda: raw
    middle = _jump(FunctionBuilder(entry=F).ins(load(reg(RDX), reg(RSP))).tail_call(T))
    case = _case(_caller(), middle, target)
    record = _record(case, ROOT_KEY)
    vm = _run(case)
    if ok:
        assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8) == 23
    else:
        with pytest.raises(Ineligible):
            evaluate_physical(record, entry_reader(vm))
