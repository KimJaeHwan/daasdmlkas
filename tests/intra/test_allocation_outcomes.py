"""A realloc failure preserves its old epoch only on a proved NULL-result path.

The certificate is query-local: it never licenses a CALL-wide memory effect.
All guards, result copies, and pointer uses below are original p-code witnesses.
"""

import pytest

from synthetic import (RAX, RBX, RCX, RDI, RDX, RSP, add, const, copy,
                       load, op, program_units, reg, store, tmp)
from test_allocation_lifetime import FLAG, _begin, _contracts, _finish, _guard, _key, without_allocator_windows
from test_external_models import MODELS, THUNKS, _image
from tdo_v2._allocation_lifetime import AllocationAnalysis
from tdo_v2._allocation_outcomes import failed_resize
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


def _run(builder, models, contracts):
    results = analyze_units(
        program_units(builder), image_info=_image(), external_models=models,
        lifecycle_contracts=contracts, private_frame_above=40,
        assume_globals_disjoint_from_stack=True,
        assume_entry_values_not_frame=False,
        assume_opaque_callees_leave_no_stack_addresses=False,
    )
    item = results["1:1000"]
    return item, AllocationAnalysis(item, results=results)


def _case(*, query="failure", size=16, result_edit=None, before_query=None,
          old_argument=None, result_register=RAX, spill_result=False):
    builder, allocation = _begin()
    _guard(builder)
    slot = tmp(0x100)
    saved = _key(builder, 1, "STORE")
    builder.ins(add(slot, reg(RSP), const(0x30)), store(slot, const(0x1234)))
    if old_argument is None:
        builder.ins(copy(reg(RCX), reg(RBX)))
    else:
        old_argument(builder)
    builder.ins(copy(reg(RDX), const(size)))
    resize = _key(builder, 2, "CALL")
    builder.call(THUNKS["realloc"])
    if result_edit is not None:
        result_edit(builder)
    if spill_result:
        result_slot = tmp(0x120)
        builder.ins(add(result_slot, reg(RSP), const(0x40)),
                    store(result_slot, reg(RAX)), load(reg(RDI), result_slot))
        result_register = RDI
    if query == "failure":
        builder.cbranch("failed", FLAG,
                        op("INT_EQUAL", [reg(result_register), const(0)], FLAG))
        builder.branch("done")
        builder.label("failed")
    elif query == "success":
        builder.cbranch("done", FLAG,
                        op("INT_EQUAL", [reg(result_register), const(0)], FLAG))
    elif query == "join":
        builder.cbranch("joined", FLAG,
                        op("INT_EQUAL", [reg(result_register), const(0)], FLAG))
        builder.label("joined")
    else:
        raise AssertionError(query)
    if before_query is not None:
        before_query(builder)
    heap = _key(builder, 0, "STORE")
    builder.ins(store(reg(RBX), const(0x5678, 4)))
    reader = _key(builder, 1, "LOAD")
    builder.ins(add(slot, reg(RSP), const(0x30)), load(reg(RDI), slot))
    return _finish(builder), dict(allocation=allocation, saved=saved,
                                  resize=resize, heap=heap, reader=reader)


def _lifetime(analysis, points):
    pointer = analysis.input(points["heap"], analysis.ops[points["heap"]].inputs[1])
    return analysis.lifetime(pointer, points["heap"])


def _heap_debt(item, points):
    return any(row.operation_key == points["reader"] and points["heap"] in row.plain
               for row in item.normalized.may_alias_reads)


@pytest.mark.parametrize("spill_result", (False, True))
def test_failure_null_guard_preserves_old_live_extent_and_excludes_heap_store_only(models,
                                                                                     spill_result):
    builder, points = _case(spill_result=spill_result)
    baseline, _ = _run(builder, models, ())
    item, analysis = _run(builder, models, _contracts(models, resize=True))
    assert _heap_debt(baseline, points)
    assert failed_resize(analysis, points["resize"], points["heap"])
    lifetime = _lifetime(analysis, points)
    assert lifetime.live and lifetime.states[0][1] == ("live",)
    assert len(lifetime.outcomes) == 1
    failure = lifetime.outcomes[0]
    assert failure.call == points["resize"] and failure.query == points["heap"]
    assert failure.guard in analysis.ops and analysis.ops[failure.guard].opcode == "CBRANCH"
    assert failure.definitions  # original full-width result/guard SSA witnesses
    assert failure.failure_edge[0] == failure.success_edge[0] == failure.guard
    assert failure.failure_edge[1] != failure.success_edge[1]
    assert failure.size == 16
    assert failure.contract == _contracts(models, resize=True)[1].label
    assert set(failure.requires) <= set(lifetime.requires)
    access = analysis.access(points["heap"])
    assert access is not None and access.live
    assert any(label.startswith("lifecycle-contract:audited-malloc@v1#") for label in access.requires)
    assert any(label.startswith("lifecycle-contract:audited-realloc@v1#") for label in access.requires)
    assert not _heap_debt(item, points)
    assert any(proof.writer == points["heap"] and proof.read == points["reader"]
               for proof in item.normalized.forward_memory_proofs)
    assert set(access.requires) <= set(item.normalized.forward_memory_requires)
    assert set(item.normalized.forward_memory_requires) <= set(item.inherited_assumptions)
    # A separate, pre-CALL live-base/owned-range proof may already discharge
    # the stack CALL debt. It must not cite this query-local failure outcome.
    assert all(decision.reason == "live-owned-allocation-disjoint-stack"
               and decision.evidence[0].point == points["resize"]
               for decision in item.call_memory_decisions if decision.demand.call == points["resize"])


@pytest.mark.parametrize("query", ("success", "join"))
def test_success_or_join_cannot_preserve_old_allocation(models, query):
    builder, points = _case(query=query)
    item, analysis = _run(builder, models, _contracts(models, resize=True))
    assert not failed_resize(analysis, points["resize"], points["heap"])
    lifetime = _lifetime(analysis, points)
    assert not lifetime.live
    if query == "join":
        assert lifetime.states[0][1] == ("ended", "live")
    assert analysis.access(points["heap"]) is None
    assert _heap_debt(item, points)


@pytest.mark.parametrize("size,failure", ((0, "retain"), (16, "unknown")))
def test_zero_size_or_unknown_failure_has_no_retain_certificate(models, size, failure):
    builder, points = _case(size=size)
    contracts = _contracts(models, resize=True, resize_changes={"failure": failure})
    item, analysis = _run(builder, models, contracts)
    assert not failed_resize(analysis, points["resize"], points["heap"])
    assert not _lifetime(analysis, points).live
    assert analysis.access(points["heap"]) is None
    assert _heap_debt(item, points)


@pytest.mark.parametrize("result_edit", (
    lambda body: body.ins(copy(reg(RAX), const(0))),
    lambda body: body.ins(copy(reg(RAX + 4, 4), const(0, 4))),
))
def test_overwritten_or_partially_overwritten_result_is_not_original_null_guard(models,
                                                                                 result_edit):
    builder, points = _case(result_edit=result_edit)
    item, analysis = _run(builder, models, _contracts(models, resize=True))
    assert not failed_resize(analysis, points["resize"], points["heap"])
    assert not _lifetime(analysis, points).live
    assert analysis.access(points["heap"]) is None
    assert _heap_debt(item, points)


@pytest.mark.parametrize("intervening", ("free", "opaque"))
def test_intervening_release_or_unknown_call_blocks_failure_path_access(models, intervening):
    def before_query(body):
        if intervening == "free":
            body.ins(copy(reg(RCX), reg(RBX))).call(THUNKS["free"])
        else:
            body.call(0x1700)

    builder, points = _case(before_query=before_query)
    item, analysis = _run(builder, models, _contracts(models, release=True, resize=True))
    assert failed_resize(analysis, points["resize"], points["heap"])
    assert not _lifetime(analysis, points).live
    assert analysis.access(points["heap"]) is None
    assert _heap_debt(item, points)


def test_scalar_null_plus_eight_is_not_a_valid_old_resize_pointer(models):
    def old_argument(body):
        body.ins(copy(reg(RCX), const(0)), add(reg(RCX), reg(RCX), const(8)))

    builder, points = _case(old_argument=old_argument)
    item, analysis = _run(builder, models, _contracts(models, resize=True))
    assert not _lifetime(analysis, points).live
    assert analysis.access(points["heap"]) is None
    assert _heap_debt(item, points)
    assert not any(decision.demand.call == points["resize"] and decision.preserved
                   for decision in item.call_memory_decisions)


@pytest.mark.parametrize("old_argument", (
    lambda body: body.ins(copy(reg(RCX), reg(RBX)), add(reg(RCX), reg(RCX), const(1))),
    lambda body: body.ins(copy(reg(RCX), reg(RDI))),
    lambda body: body.ins(copy(reg(RCX), reg(RBX))).call(THUNKS["free"])
                     .ins(copy(reg(RCX), reg(RBX))),
))
def test_invalid_old_resize_argument_is_not_rescued_by_failure_guard(models, old_argument):
    builder, points = _case(old_argument=old_argument)
    item, analysis = _run(builder, models, _contracts(models, release=True, resize=True))
    assert not _lifetime(analysis, points).live
    assert analysis.access(points["heap"]) is None
    assert _heap_debt(item, points)
    assert not any(decision.demand.call == points["resize"] and decision.preserved
                   for decision in item.call_memory_decisions)


def test_null_guard_for_another_resize_result_does_not_retain_first_old_epoch(models):
    builder, _ = _begin()
    _guard(builder)
    builder.ins(copy(reg(RCX), const(8)))
    builder.call(THUNKS["malloc"]).ins(copy(reg(RDI), reg(RAX)))
    builder.cbranch("done", FLAG, op("INT_EQUAL", [reg(RDI), const(0)], FLAG))
    builder.ins(copy(reg(RCX), reg(RBX)), copy(reg(RDX), const(16)))
    first = _key(builder, 2, "CALL")
    builder.call(THUNKS["realloc"])
    builder.ins(copy(reg(RCX), reg(RDI)), copy(reg(RDX), const(16)))
    second = _key(builder, 2, "CALL")
    builder.call(THUNKS["realloc"])
    builder.cbranch("second-failed", FLAG, op("INT_EQUAL", [reg(RAX), const(0)], FLAG))
    builder.branch("done")
    builder.label("second-failed")
    heap = _key(builder, 0, "STORE")
    builder.ins(store(reg(RBX), const(7, 4)))
    item, analysis = _run(_finish(builder), models, _contracts(models, resize=True))
    assert first in analysis.contracts and second in analysis.contracts
    assert not failed_resize(analysis, first, heap)
    assert failed_resize(analysis, second, heap)
    pointer = analysis.input(heap, analysis.ops[heap].inputs[1])
    assert pointer.targets and next(iter(pointer.targets)).allocation.event != second
    assert not analysis.lifetime(pointer, heap).live
    assert analysis.access(heap) is None
