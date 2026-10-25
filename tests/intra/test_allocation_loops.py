"""Allocation lifetime is per dynamic loop occurrence, not a static CALL key."""

import pytest

from synthetic import (RAX, RBX, RCX, RDI, RSI, RSP, FunctionBuilder, add,
                       const, copy, load, op, program_units, reg, store, tmp)
from test_allocation_lifetime import FLAG, _begin, _contracts, _finish, _guard, _key
from test_external_models import MODELS, THUNKS, _image
from tdo_v2._allocation_lifetime import AllocationAnalysis
from tdo_v2.interprocedural import analyze_units
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.summary_store import load_external_models


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def engines(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_FORWARD", "1")


@pytest.fixture(scope="module")
def models():
    return load_external_models(MODELS, "x86:LE:64:default", "win64")


def _run(builder, models, *, release=False):
    result = analyze_units(
        program_units(builder), image_info=_image(), external_models=models,
        lifecycle_contracts=_contracts(models, release=release), private_frame_above=40,
        assume_globals_disjoint_from_stack=True,
        assume_entry_values_not_frame=False,
        assume_opaque_callees_leave_no_stack_addresses=False,
    )
    item = result["1:1000"]
    return item, AllocationAnalysis(item, results=result)


def _evidence(analysis, writer):
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    return pointer, analysis.lifetime(pointer, writer)


def test_birth_outside_loop_remains_live_at_every_query_visit(models):
    builder, allocation = _begin()
    _guard(builder)
    builder.label("loop")
    writer = _key(builder, 0, "STORE")
    builder.ins(store(reg(RBX), const(7, 4)))
    builder.cbranch("loop", reg(RSI, 1))
    _, analysis = _run(_finish(builder), models)
    pointer, evidence = _evidence(analysis, writer)
    assert {target.allocation.event for target in pointer.targets} == {allocation}
    assert {target.allocation.occurrence for target in pointer.targets} == {"single"}
    assert evidence.live and evidence.states[0][1] == ("live",)
    assert analysis.access(writer) is not None


def test_free_after_query_reaches_next_visit_of_same_static_query(models):
    builder, allocation = _begin()
    _guard(builder)
    builder.label("loop")
    writer = _key(builder, 0, "STORE")
    builder.ins(store(reg(RBX), const(7, 4)))
    builder.ins(copy(reg(RCX), reg(RBX)))
    release = _key(builder, 2, "CALL")
    builder.call(THUNKS["free"])
    builder.cbranch("loop", reg(RSI, 1))
    _, analysis = _run(_finish(builder), models, release=True)
    pointer, evidence = _evidence(analysis, writer)
    assert {target.allocation.event for target in pointer.targets} == {allocation}
    assert release in analysis.contracts and release in evidence.events
    assert not evidence.live and {"live", "ended"} <= set(evidence.states[0][1])
    assert analysis.access(writer) is None


def _family(*, guard=True, spill=False, old_alias=False, two_births=False, inner_cycle=False, entry_nop=False):
    builder = FunctionBuilder()
    if entry_nop:
        builder.ins()
    builder.sub_rsp(0x60)
    slot = tmp(0x100)
    if spill:
        builder.ins(add(slot, reg(RSP), const(0x30)), store(slot, const(0)))
    builder.label("loop")
    if old_alias:
        builder.ins(add(slot, reg(RSP), const(0x30)), load(reg(RDI), slot))
    if two_births:
        builder.cbranch("second-birth", reg(RSI, 1))
    builder.ins(copy(reg(RCX), const(8)))
    first = _key(builder, 2, "CALL")
    builder.call(THUNKS["malloc"])
    if two_births:
        builder.ins(copy(reg(RBX), reg(RAX))).branch("join-births")
        builder.label("second-birth").ins(copy(reg(RCX), const(8)))
        second = _key(builder, 2, "CALL")
        builder.call(THUNKS["malloc"]).ins(copy(reg(RBX), reg(RAX)))
        builder.label("join-births")
        pointer = RBX
    else:
        second, pointer = None, RAX
    if inner_cycle:
        builder.label("inner-cycle").ins(copy(tmp(0x300), reg(RDI)))
        builder.cbranch("inner-cycle", reg(RDI, 1))
    if guard:
        builder.cbranch("end-iteration", FLAG,
                        op("INT_EQUAL", [reg(pointer), const(0)], FLAG))
    writer = _key(builder, 0, "STORE")
    builder.ins(store(reg(RDI if old_alias else pointer), const(7, 4)))
    if spill:
        builder.ins(add(slot, reg(RSP), const(0x30)), store(slot, reg(pointer)))
    if not old_alias and not two_births:
        builder.ins(copy(reg(RCX), reg(pointer)))
        release = _key(builder, 2, "CALL")
        builder.call(THUNKS["free"])
    else:
        release = None
    builder.label("end-iteration").cbranch("loop", reg(RSI, 1))
    builder.add_rsp(0x60).ret()
    return builder, dict(first=first, second=second, writer=writer, release=release)


def test_loop_local_family_birth_guard_store_free_is_one_current_instance(models):
    builder, points = _family()
    _, analysis = _run(builder, models, release=True)
    pointer, evidence = _evidence(analysis, points["writer"])
    assert len(pointer.targets) == 1
    ref = next(iter(pointer.targets)).allocation
    assert ref.event == points["first"] and ref.occurrence == "family"
    assert analysis.local_occurrence(pointer, ref, points["writer"])
    assert evidence.live and evidence.states[0][1] == ("live",)
    assert points["release"] in analysis.contracts
    assert analysis.access(points["writer"]) is not None


@pytest.mark.parametrize("guard", (False, True))
def test_empty_entry_block_keeps_current_family_or_unproved_nullable_state(models, guard):
    builder, points = _family(entry_nop=True, guard=guard)
    _, analysis = _run(builder, models, release=True)
    assert not analysis.block_ops[analysis.graph.entry]
    pointer, evidence = _evidence(analysis, points["writer"])
    (target,) = pointer.targets
    assert target.allocation.occurrence == "family"
    assert analysis.local_occurrence(pointer, target.allocation, points["writer"])
    assert evidence.live == guard
    assert (analysis.access(points["writer"]) is not None) == guard


def test_loop_local_nullable_birth_without_guard_is_not_access(models):
    builder, points = _family(guard=False)
    _, analysis = _run(builder, models, release=True)
    pointer, evidence = _evidence(analysis, points["writer"])
    assert pointer.targets and next(iter(pointer.targets)).allocation.occurrence == "family"
    assert not evidence.live and analysis.access(points["writer"]) is None


def test_cycle_between_birth_and_use_is_not_a_closed_current_instance(models):
    builder, points = _family(inner_cycle=True)
    _, analysis = _run(builder, models, release=True)
    pointer, evidence = _evidence(analysis, points["writer"])
    assert pointer.targets and next(iter(pointer.targets)).allocation.occurrence == "family"
    assert not evidence.live and analysis.access(points["writer"]) is None


def test_previous_iteration_spilled_alias_is_not_current_family(models):
    builder, points = _family(spill=True, old_alias=True)
    _, analysis = _run(builder, models)
    pointer, evidence = _evidence(analysis, points["writer"])
    assert any(identity[0] is MemoryDefinitionKind.JOIN for identity in pointer.definitions)
    assert not evidence.live and analysis.access(points["writer"]) is None


def test_register_loop_carried_old_alias_is_not_the_new_birth(models):
    builder = FunctionBuilder().sub_rsp(0x60).ins(copy(reg(RBX), const(0))).label("loop")
    builder.ins(copy(reg(RDI), reg(RBX)), copy(reg(RCX), const(8)))
    allocation = _key(builder, 2, "CALL")
    builder.call(THUNKS["malloc"]).ins(copy(reg(RBX), reg(RAX)))
    builder.cbranch("end-iteration", FLAG,
                    op("INT_EQUAL", [reg(RBX), const(0)], FLAG))
    writer = _key(builder, 0, "STORE")
    builder.ins(store(reg(RDI), const(7, 4)))
    builder.label("end-iteration").cbranch("loop", reg(RSI, 1))
    builder.add_rsp(0x60).ret()
    _, analysis = _run(builder, models)
    pointer, evidence = _evidence(analysis, writer)
    assert allocation in analysis.contracts
    assert not evidence.live and analysis.access(writer) is None


def test_old_spilled_family_alias_cannot_release_current_new_instance(models):
    slot = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x60)
               .ins(add(slot, reg(RSP), const(0x30)), store(slot, const(0))))
    builder.label("loop")
    builder.ins(add(slot, reg(RSP), const(0x30)), load(reg(RDI), slot),
                copy(reg(RCX), const(8)))
    allocation = _key(builder, 2, "CALL")
    builder.call(THUNKS["malloc"]).ins(copy(reg(RBX), reg(RAX)))
    builder.cbranch("end-iteration", FLAG,
                    op("INT_EQUAL", [reg(RBX), const(0)], FLAG))
    builder.ins(copy(reg(RCX), reg(RDI)))
    release = _key(builder, 2, "CALL")
    builder.call(THUNKS["free"])
    writer = _key(builder, 0, "STORE")
    builder.ins(store(reg(RBX), const(7, 4)))
    builder.ins(add(slot, reg(RSP), const(0x30)), store(slot, reg(RBX)))
    builder.label("end-iteration").cbranch("loop", reg(RSI, 1))
    builder.add_rsp(0x60).ret()
    _, analysis = _run(builder, models, release=True)
    pointer, evidence = _evidence(analysis, writer)
    assert release in analysis.contracts and allocation in analysis.contracts
    assert len(pointer.targets) == 1
    ref = next(iter(pointer.targets)).allocation
    assert ref.event == allocation and ref.occurrence == "family"
    assert analysis.local_occurrence(pointer, ref, writer)
    old = analysis.argument(release, (RCX, 8))
    assert any(identity[0] is MemoryDefinitionKind.JOIN for identity in old.definitions)
    assert not analysis.local_occurrence(old, ref, release)
    assert not evidence.live and analysis.access(writer) is None


def test_join_of_two_loop_birth_sites_is_not_one_current_occurrence(models):
    builder, points = _family(two_births=True)
    _, analysis = _run(builder, models)
    pointer, evidence = _evidence(analysis, points["writer"])
    assert points["first"] in analysis.contracts and points["second"] in analysis.contracts
    assert {target.allocation.event for target in pointer.targets} == {points["first"], points["second"]}
    assert any(identity[0] is MemoryDefinitionKind.JOIN for identity in pointer.definitions)
    assert not evidence.live and analysis.access(points["writer"]) is None
