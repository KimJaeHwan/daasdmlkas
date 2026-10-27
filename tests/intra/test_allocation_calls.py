"""Caller-owned allocation lifetime across original physical call ports."""

import pytest

from synthetic import (RAX, RBX, RCX, RDI, RDX, RSI, RSP, FunctionBuilder,
                       add, const, copy, load, op, program_units, reg, store, tmp)
from test_allocation_lifetime import FLAG, _contracts, _key, without_allocator_windows
from test_external_models import MODELS, THUNKS, _image
from tdo_v2._allocation_lifetime import AllocationAnalysis
from tdo_v2.forward import probe
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import load_external_models


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def engines(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_FORWARD", "1")


@pytest.fixture(scope="module")
def models():
    return without_allocator_windows(load_external_models(MODELS, "x86:LE:64:default", "win64"))


def _helper(kind="quiet"):
    body = FunctionBuilder(0x1600).sub_rsp(0x28)
    # Both original full-width physical entry registers are observed.  These
    # are two aliases of the caller's one allocation, not new allocation IDs.
    body.ins(copy(tmp(0x180), reg(RCX)), copy(tmp(0x188), reg(RDX)))
    if kind == "conditional-free":
        body.cbranch("skip-free", reg(RDI, 1))
    if kind in ("free", "conditional-free"):
        body.ins(copy(reg(RCX), reg(RDX))).call(THUNKS["free"])
    elif kind == "memory-free":
        body.ins(load(reg(RCX), reg(RDX))).call(THUNKS["free"])
    elif kind == "quiet":
        # A real modeled release call makes this helper non-quiet to the
        # caller, while free(NULL) leaves its passed allocation live.
        body.ins(copy(reg(RCX), const(0))).call(THUNKS["free"])
    elif kind == "opaque":
        body.call(0x1700)
    elif kind == "recursive":
        body.call(0x1600)
    if kind == "conditional-free":
        body.label("skip-free")
    return body.add_rsp(0x28).ret()


def _caller(*, pass_kind="full", calls=1, helper=0x1600):
    body = FunctionBuilder().sub_rsp(0x60).ins(copy(reg(RCX), const(8)))
    allocation = _key(body, 2, "CALL")
    body.call(THUNKS["malloc"]).ins(copy(reg(RBX), reg(RAX)))
    body.cbranch("done", FLAG, op("INT_EQUAL", [reg(RBX), const(0)], FLAG))
    slot = tmp(0x100)
    saved = _key(body, 1, "STORE")
    body.ins(add(slot, reg(RSP), const(0x30)), store(slot, const(0x11223344)))
    crossings = []
    for _ in range(calls):
        if pass_kind == "full":
            body.ins(copy(reg(RCX), reg(RBX)), copy(reg(RDX), reg(RBX)))
        elif pass_kind == "partial":
            body.ins(copy(reg(RCX, 4), reg(RBX, 4)), copy(reg(RDX, 4), reg(RBX, 4)))
        elif pass_kind == "memory":
            body.ins(add(slot, reg(RSP), const(0x30)), store(slot, reg(RBX)),
                     copy(reg(RCX), slot), copy(reg(RDX), slot))
        else:
            raise ValueError(pass_kind)
        call = _key(body, 2, "CALL")
        body.call(helper)
        crossings.append(call)
    writer = _key(body, 0, "STORE")
    body.ins(store(reg(RBX), const(0x12345678, 4)))
    reader = _key(body, 1, "LOAD")
    body.ins(add(slot, reg(RSP), const(0x30)), load(reg(RSI, 4), slot))
    body.label("done").add_rsp(0x60).ret()
    return body, dict(allocation=allocation, crossings=tuple(crossings), saved=saved,
                      writer=writer, reader=reader)


def _run(models, caller, helper, contracts):
    units = program_units(caller, helper) if helper is not None else program_units(caller)
    return analyze_units(units, image_info=_image(), external_models=models,
                         lifecycle_contracts=contracts, private_frame_above=40,
                         assume_globals_disjoint_from_stack=True,
                         assume_entry_values_not_frame=False,
                         assume_opaque_callees_leave_no_stack_addresses=False)


def _lifetime(results, points):
    item = results["1:1000"]
    analysis = AllocationAnalysis(item, results=results)
    pointer = analysis.input(points["writer"], analysis.ops[points["writer"]].inputs[1])
    return item, analysis, pointer, analysis.lifetime(pointer, points["writer"])


def _debt(item, points):
    return next((row for row in item.normalized.may_alias_reads
                 if row.operation_key == points["reader"] and points["writer"] in row.plain), None)


def test_two_full_entry_aliases_survive_quiet_helper_and_consume_raw_heap_debt(models):
    caller, points = _caller()
    helper = _helper()
    baseline = _run(models, caller, helper, ())
    results = _run(models, caller, helper, _contracts(models, release=True))
    item, analysis, pointer, lifetime = _lifetime(results, points)
    assert _debt(baseline["1:1000"], points) is not None
    assert pointer.targets and len(pointer.targets) == 1
    allocation = next(iter(pointer.targets)).allocation
    assert allocation.event == points["allocation"] and allocation.function == item.key
    assert lifetime.live and analysis.access(points["writer"]) is not None
    assert len(lifetime.calls) == 1
    crossing = lifetime.calls[0]
    assert crossing.allocation == allocation
    assert crossing.context == (item.key, points["crossings"][0])
    assert crossing.input_states == crossing.output_states == ("live",)
    assert {span.start for span, _ in crossing.ports} >= {RCX, RDX}
    assert _debt(item, points) is None
    assert any(proof.writer == points["writer"] for proof in item.normalized.forward_memory_proofs)
    generic = results["1:1600"]
    assert generic.normalized.activation_entry is None and not generic.activations
    assert generic.normalized.memory_ssa == baseline["1:1600"].normalized.memory_ssa


def test_helper_conditional_free_unions_all_normal_exits_and_keeps_heap_debt(models):
    caller, points = _caller()
    results = _run(models, caller, _helper("conditional-free"), _contracts(models, release=True))
    item, _, pointer, lifetime = _lifetime(results, points)
    assert pointer.targets and len(lifetime.calls) == 1
    assert not lifetime.live
    assert set(lifetime.calls[0].output_states) >= {"live", "ended"}
    assert _debt(item, points) is not None
    assert not any(proof.writer == points["writer"] for proof in item.normalized.forward_memory_proofs)


def test_two_calls_to_same_helper_have_distinct_caller_owned_contexts(models):
    caller, points = _caller(calls=2)
    results = _run(models, caller, _helper(), _contracts(models, release=True))
    _, _, pointer, lifetime = _lifetime(results, points)
    assert pointer.targets and lifetime.live
    assert len(lifetime.calls) == 2
    assert {call.context for call in lifetime.calls} == {
        ("1:1000", point) for point in points["crossings"]}
    assert {call.allocation for call in lifetime.calls} == {next(iter(pointer.targets)).allocation}


@pytest.mark.parametrize("kind,pass_kind", (("free", "partial"), ("memory-free", "memory"),
                                           ("opaque", "full"), ("recursive", "full")))
def test_unproved_entry_or_helper_keeps_lifetime_unknown(models, kind, pass_kind):
    caller, points = _caller(pass_kind=pass_kind)
    results = _run(models, caller, _helper(kind),
                   _contracts(models, release=kind in ("free", "memory-free")))
    item, _, pointer, lifetime = _lifetime(results, points)
    assert not lifetime.live
    assert _debt(item, points) is not None
    assert not any(proof.writer == points["writer"] for proof in item.normalized.forward_memory_proofs)


def test_unknown_helper_without_summary_cannot_transfer_lifetime(models):
    caller, points = _caller(helper=0x1700)
    results = _run(models, caller, None, _contracts(models))
    item, _, pointer, lifetime = _lifetime(results, points)
    assert not lifetime.live
    assert _debt(item, points) is not None
