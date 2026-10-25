"""Multi-target effects merge real memory in physical entry-register coordinates.

Concrete callees execute in the program oracle; positive cases also require a
complete caller memory slice through the merged effect, not just target discovery.
"""

from dataclasses import replace

import pytest

import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    DATA_BASE, R8, RAX, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder,
    add, const, copy, load, op, reg, slice_op, store, tmp,
)
from test_multi_target_calls import A, B, OPAQUE, ROOT, _analyze, _call
from tdo_v2.call_summary_effects import (
    AnchoredSpan, ProvenCallEffect, ProvenMemoryRun, _compose_fixed_memory,
    derive_composed_call_effect, derive_proven_call_effect,
)
from tdo_v2.interprocedural import _relative_anchors
from tdo_v2.span_geometry import ByteSpan, StorageObjectKind


def _caller(*, source_slots=False, read=None, displacement=0):
    target, other, index = tmp(0x100), tmp(0x180), tmp(0x200)
    initial = [add(reg(RDX), reg(RSP), const(displacement % (1 << 64))), store(reg(RDX), reg(RBX))]
    if source_slots:
        initial += [add(target, reg(RDX), const(8)), store(target, reg(RSI)),
                    add(other, reg(RDX), const(16)), store(other, reg(RDI))]
    return (FunctionBuilder().sub_rsp(0x48)
            .ins(*initial)
            .ins(add(target, reg(RSP), const(0x20)), store(target, const(A)),
                 add(other, reg(RSP), const(0x28)), store(other, const(B)))
            .ins(op("INT_AND", [reg(RCX), const(1)], index),
                 op("INT_MULT", [index, const(8)], index), add(index, index, reg(RSP)),
                 add(index, index, const(0x20)), load(reg(RAX), index))
            .call_indirect(RAX).ins(load(reg(R8), reg(RDX) if read is None else read)).add_rsp(0x48).ret())


def _check(results, program, *, complete=False, externals=None):
    item = results[ROOT]
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000, RCX: seed % 2}
    report = check_program(item.normalized, item.unit.observation, program, seeds=range(8),
                           register_pools=pools, havoc_calls=(REG, RSP, 8), externals=externals)
    assert report.runs == 8 and report.silent == [], report.silent[:3]
    if complete:
        assert slice_op(item.normalized, "LOAD", 5).result.is_complete
        assert report.through_calls > 0
    return report


def _effect(results):
    item = results[ROOT]
    return item.proven[_call(item)]


def _members(results):
    return tuple((results[key].summary, _relative_anchors(results[key].unit, results[key].normalized))
                 for key in ("1:1800", "1:1900"))


def _derive(members, **kwargs):
    registers = next(iter(members[0][1].values()))[0].object_id
    return derive_composed_call_effect(members, "targets:1:1800|1:1900", registers, 0x300,
                                       excluded=(ByteSpan(registers, RSP, 8),),
                                       stack_deltas={(RSP, 8): -8}, **kwargs)


def test_same_anchor_unites_both_targets_inputs_in_real_memory(monkeypatch):
    a = FunctionBuilder(entry=A).ins(add(tmp(0x100), reg(RSI), const(3)), store(reg(RDX), tmp(0x100))).ret()
    b = FunctionBuilder(entry=B).ins(op("INT_XOR", [reg(RDI), const(7)], tmp(0x100)),
                                   store(reg(RDX), tmp(0x100))).ret()
    results, program = _analyze(monkeypatch, _caller(), a, b)
    effect = _effect(results)
    assert effect.preserves_memory and not effect.unknown_memory
    (run,) = effect.memory_runs
    assert (run.write.anchor.start, run.write.displacement, run.write.size) == (RDX, 0, 8)
    assert not run.keeps_old and {RDX, RSI, RDI} <= {span.start for span in run.reads}
    loaded = slice_op(results[ROOT].normalized, "LOAD", 5)
    assert set(range(RSI, RSI + 8)) | set(range(RDI, RDI + 8)) <= loaded.register_bytes
    _check(results, program, complete=True)

    sources = {}
    merged = _derive(_members(results), memory_sources=sources)
    assert merged.memory_runs == effect.memory_runs
    assert tuple(index for index, _ in sources[run.write]) == (0, 1)
    for index, original in sources[run.write]:
        summary, anchors = _members(results)[index]
        own = derive_proven_call_effect(summary, "member", run.write.anchor.object_id, 0x300,
                                        anchors=anchors, excluded=(ByteSpan(run.write.anchor.object_id, RSP, 8),),
                                        stack_deltas={(RSP, 8): -8})
        assert original in own.memory_runs


def test_a_nonwriting_target_preserves_the_actual_old_memory(monkeypatch):
    a = FunctionBuilder(entry=A).ins(store(reg(RDX), reg(RSI))).ret()
    b = FunctionBuilder(entry=B).ret()
    results, program = _analyze(monkeypatch, _caller(), a, b)
    (run,) = _effect(results).memory_runs
    assert run.keeps_old and not _effect(results).unknown_memory
    loaded = slice_op(results[ROOT].normalized, "LOAD", 5)
    assert set(range(RBX, RBX + 8)) | set(range(RSI, RSI + 8)) <= loaded.register_bytes
    sources = {}
    _derive(_members(results), memory_sources=sources)
    assert sources[run.write][1] == (1, None)
    _check(results, program, complete=True)


@pytest.mark.parametrize("offset", (0, 4))
def test_partial_four_and_eight_byte_writes_split_the_preserved_half(monkeypatch, offset):
    a = FunctionBuilder(entry=A).ins(add(tmp(0x100), reg(RDX), const(offset)),
                                   store(tmp(0x100), reg(RSI, 4))).ret()
    b = FunctionBuilder(entry=B).ins(store(reg(RDX), reg(RDI))).ret()
    results, program = _analyze(monkeypatch, _caller(), a, b)
    effect = _effect(results)
    assert [(run.write.displacement, run.write.size, run.keeps_old) for run in effect.memory_runs] == [
        (0, 4, offset != 0), (4, 4, offset == 0),
    ]
    assert not effect.unknown_memory and all(run.value is None for run in effect.memory_runs)
    sources = {}
    _derive(_members(results), memory_sources=sources)
    assert sources[effect.memory_runs[1 if offset == 0 else 0].write][0] == (0, None)
    assert sources[effect.memory_runs[0].write][1][1].write.size == 8
    _check(results, program, complete=True)


def test_entry_memory_loads_from_both_targets_reach_the_caller(monkeypatch):
    def target(entry, offset):
        return (FunctionBuilder(entry=entry).ins(add(tmp(0x100), reg(RDX), const(offset)),
                                                load(tmp(0x180), tmp(0x100)),
                                                store(reg(RDX), tmp(0x180))).ret())

    results, program = _analyze(monkeypatch, _caller(source_slots=True), target(A, 8), target(B, 16))
    (run,) = _effect(results).memory_runs
    assert {(access.displacement, access.size) for access in run.loads} == {(8, 8), (16, 8)}
    loaded = slice_op(results[ROOT].normalized, "LOAD", 5)
    assert set(range(RSI, RSI + 8)) | set(range(RDI, RDI + 8)) <= loaded.register_bytes
    _check(results, program, complete=True)


def test_shared_global_writes_keep_the_existing_global_composition(monkeypatch):
    a = FunctionBuilder(entry=A).ins(store(const(DATA_BASE), reg(RSI))).ret()
    b = FunctionBuilder(entry=B).ins(store(const(DATA_BASE), reg(RDI))).ret()
    results, program = _analyze(monkeypatch, _caller(read=const(DATA_BASE)), a, b)
    sources = {}
    effect = _derive(_members(results), memory_sources=sources)
    (run,) = effect.memory_runs
    assert run.write.anchor is None and run.write.span.start == DATA_BASE
    assert not run.keeps_old and not sources
    _check(results, program, complete=True)


def test_different_physical_anchors_keep_unknown_memory(monkeypatch):
    a = FunctionBuilder(entry=A).ins(store(reg(RDX), reg(RSI))).ret()
    b = FunctionBuilder(entry=B).ins(store(reg(RDI), reg(RBX))).ret()
    results, program = _analyze(monkeypatch, _caller(), a, b)
    effect = _effect(results)
    assert not effect.memory_runs and effect.unknown_memory
    _check(results, program)


def test_a_narrower_pointer_register_keeps_unlocated_memory_debt(monkeypatch):
    a = FunctionBuilder(entry=A).ins(store(reg(RDX), reg(RSI))).ret()
    b = FunctionBuilder(entry=B).ins(store(reg(RDX, 4), reg(RBX))).ret()
    results, program = _analyze(monkeypatch, _caller(), a, b)
    # This x86-64 extraction cannot anchor the narrow pointer. The old
    # effect's provisional run remains, with all-memory call-clobber debt;
    # it must not acquire a synthesized fixed-memory proof.
    assert not _effect(results).preserves_memory
    sources = {}
    _derive(_members(results), memory_sources=sources)
    assert not sources
    assert not slice_op(results[ROOT].normalized, "LOAD", 5).result.is_complete
    _check(results, program)


def test_a_real_member_alias_condition_keeps_the_caller_memory_slice_incomplete(monkeypatch):
    a = FunctionBuilder(entry=A).ins(store(reg(RDX), reg(RSI))).ret()
    b = (FunctionBuilder(entry=B).ins(store(reg(RDX), reg(RBX)))
         .ins(load(tmp(0x100), reg(RDI))).ins(store(reg(RDX), tmp(0x100))).ret())
    results, program = _analyze(monkeypatch, _caller(), a, b)
    assert any(run.conditions for exit in results["1:1900"].summary.exits for run in exit.runs)
    effect = _effect(results)
    assert not effect.memory_runs and effect.unknown_memory
    assert not slice_op(results[ROOT].normalized, "LOAD", 5).result.is_complete
    sources = {}
    _derive(_members(results), memory_sources=sources)
    assert not sources
    _check(results, program)


def test_a_pointer_chain_write_keeps_the_space_unknown(monkeypatch):
    a = FunctionBuilder(entry=A).ins(store(reg(RDX), reg(RSI))).ret()
    b = FunctionBuilder(entry=B).ins(load(tmp(0x100), reg(RDX)), store(tmp(0x100), reg(RDI))).ret()
    results, program = _analyze(monkeypatch, _caller(), a, b)
    effect = _effect(results)
    assert not effect.memory_runs and effect.unknown_memory
    assert any(access.pointer is not None for access in effect.unknown_memory)
    _check(results, program)


def test_an_opaque_inner_call_does_not_turn_into_old_memory(monkeypatch):
    a = FunctionBuilder(entry=A).ins(store(reg(RDX), reg(RSI))).ret()
    b = FunctionBuilder(entry=B).ins(store(reg(RDX), reg(RDI))).call(OPAQUE).ret()
    results, program = _analyze(monkeypatch, _caller(), a, b)
    effect = _effect(results)
    assert not effect.preserves_memory and not effect.memory_runs
    assert effect.unknown_memory
    _check(results, program)


def test_an_unknown_address_writer_blocks_fixed_memory_promotion(monkeypatch):
    a = FunctionBuilder(entry=A).ins(store(reg(RDX), reg(RSI))).ret()
    b = (FunctionBuilder(entry=B)
         .ins(op("INT_XOR", [reg(RDX), reg(RSI)], tmp(0x100)), store(tmp(0x100), reg(RBX)))
         .ins(store(reg(RDX), reg(RDI))).ret())
    results, program = _analyze(monkeypatch, _caller(), a, b)
    assert results["1:1900"].summary.unknown_writers
    effect = _effect(results)
    assert not effect.preserves_memory and not effect.memory_runs and effect.unknown_memory
    _check(results, program)


@pytest.mark.parametrize("below", (False, True))
def test_all_target_writes_keep_the_callers_below_frame_debt(monkeypatch, below):
    a = FunctionBuilder(entry=A).ins(store(reg(RDX), reg(RSI))).push(RBX).pop(RBX).ret()
    b = FunctionBuilder(entry=B).ins(store(reg(RDX), reg(RDI))).ret()
    results, program = _analyze(monkeypatch, _caller(displacement=-16 if below else 0), a, b)
    effect = _effect(results)
    assert effect.clobbers_below and effect.memory_runs and not effect.unknown_memory
    assert slice_op(results[ROOT].normalized, "LOAD", 5).result.is_complete is not below
    _check(results, program, complete=not below)


def test_unexported_frame_writes_cannot_prove_a_missing_byte_kept_old_memory(monkeypatch):
    a = FunctionBuilder(entry=A).ins(store(reg(RDX), reg(RSI, 4))).push(RBX).pop(RBX).ret()
    b = FunctionBuilder(entry=B).ins(store(reg(RDX), reg(RDI))).ret()
    results, program = _analyze(monkeypatch, _caller(), a, b)
    effect = _effect(results)
    assert effect.clobbers_below and not effect.memory_runs and effect.unknown_memory
    sources = {}
    _derive(_members(results), memory_sources=sources)
    assert not sources
    _check(results, program)


@pytest.mark.parametrize("all_dead", (False, True))
def test_nonreturning_members_do_not_contribute_old_memory_alternatives(monkeypatch, all_dead):
    from test_noreturn_models import ABORT, _analyze as analyze_with_abort_model

    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    a = FunctionBuilder(entry=A).ins(store(reg(RDX), reg(RSI)))
    a = a.call(ABORT).ret() if all_dead else a.ret()
    b = FunctionBuilder(entry=B).ins(store(reg(RDX), reg(RDI))).call(ABORT).ret()
    results = analyze_with_abort_model(_caller(), a, b)
    program = {(1, int(key.split(":")[1], 16)): item.unit.observation for key, item in results.items()}
    assert results["1:1900"].summary.dead_exits and not results["1:1900"].summary.exits
    effect = _effect(results)
    assert effect.noreturn is all_dead
    sources = {}
    derived = _derive(_members(results), memory_sources=sources)
    if all_dead:
        assert not effect.memory_runs and not derived.memory_runs and not sources
    else:
        (run,) = effect.memory_runs
        assert not run.keeps_old
        assert tuple(index for index, _ in sources[run.write]) == (0,)
    _check(results, program, complete=not all_dead, externals={(1, ABORT): "abort"})


@pytest.mark.parametrize("problem", ("debt", "condition", "writer-condition"))
def test_member_alias_debts_and_conditions_are_not_laundered(monkeypatch, problem):
    a = FunctionBuilder(entry=A).ins(store(reg(RDX), reg(RSI))).ret()
    b = FunctionBuilder(entry=B).ins(store(reg(RDX), reg(RDI))).ret()
    results, program = _analyze(monkeypatch, _caller(), a, b)
    members = list(_members(results))
    summary, anchors = members[1]
    memory = next(run for exit in summary.exits for run in exit.runs
                  if run.writers and run.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE)
    pair = (memory.span, memory.span)
    if problem == "writer-condition":
        summary = replace(summary, writer_conditions=(pair,))
    else:
        changed = replace(memory, debts=("may_alias_read",)) if problem == "debt" \
            else replace(memory, conditions=(pair,))
        summary = replace(summary, exits=tuple(replace(exit, runs=tuple(
            changed if run is memory else run for run in exit.runs)) for exit in summary.exits))
    members[1] = (summary, anchors)
    sources = {}
    effect = _derive(tuple(members), memory_sources=sources)
    assert not effect.memory_runs and not sources
    assert effect.unknown_memory or not effect.preserves_memory
    _check(results, program, complete=True)


def test_origins_of_both_original_member_runs_are_united(monkeypatch):
    a = FunctionBuilder(entry=A).ins(store(reg(RDX), reg(RSI))).ret()
    b = FunctionBuilder(entry=B).ins(store(reg(RDX), reg(RDI))).ret()
    results, _ = _analyze(monkeypatch, _caller(), a, b)
    members = tuple((replace(summary, exits=tuple(replace(exit, runs=tuple(
        replace(run, origins=(f"origin:{index}",))
        if run.writers and run.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE else run
        for run in exit.runs)) for exit in summary.exits)), anchors)
        for index, (summary, anchors) in enumerate(_members(results)))
    (run,) = _derive(members).memory_runs
    assert run.origins == ("origin:0", "origin:1")


def test_unknown_span_replacement_keeps_unproven_bytes_and_negative_displacements(monkeypatch):
    a = FunctionBuilder(entry=A).ins(store(reg(RDX), reg(RSI))).ret()
    b = FunctionBuilder(entry=B).ins(store(reg(RDX), reg(RDI))).ret()
    results, _ = _analyze(monkeypatch, _caller(), a, b)
    (run,) = _effect(results).memory_runs
    anchor = run.write.anchor
    write = AnchoredSpan(anchor, -4, 4, 1)
    own = ProvenMemoryRun(write, run.reads, (), False)
    baseline = ProvenCallEffect("targets", (), (), unknown_memory=(AnchoredSpan(anchor, -8, 16, 1),))
    member = ProvenCallEffect("member", (), (), memory_runs=(own,), preserves_memory=True)
    merged = _compose_fixed_memory(baseline, ((0, member), (1, member)))
    assert [item.write for item in merged.memory_runs] == [write]
    assert [(item.displacement, item.size) for item in merged.unknown_memory] == [(-8, 4), (0, 8)]


@pytest.mark.parametrize("different,partial", ((False, False), (True, False), (False, True)))
def test_pointer_facts_survive_only_equal_whole_alternatives(monkeypatch, different, partial):
    a = FunctionBuilder(entry=A).ins(store(reg(RDX), reg(RSI))).ret()
    b = FunctionBuilder(entry=B).ins(store(reg(RDX), reg(RDI) if different else reg(RSI))).ret()
    results, _ = _analyze(monkeypatch, _caller(), a, b)
    members = list(_members(results))
    if partial:
        summary, anchors = members[0]
        summary = replace(summary, exits=tuple(replace(exit, runs=tuple(
            replace(run, span=ByteSpan(run.span.object_id, run.span.start, 4))
            if run.writers and run.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE else run
            for run in exit.runs)) for exit in summary.exits))
        members[0] = summary, anchors
    effect = _derive(tuple(members))
    if different or partial:
        assert all(run.value is None for run in effect.memory_runs)
    else:
        assert effect.memory_runs[0].value[0] == "same_reg"
