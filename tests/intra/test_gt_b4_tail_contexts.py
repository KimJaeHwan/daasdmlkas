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
                 .update(tail_context="1:1004:2:CALL"), CORRESPONDENCE, id="row-reference"),
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
