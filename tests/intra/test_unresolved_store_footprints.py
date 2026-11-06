"""A bounded unknown STORE remains unknown outside exact disjoint reads."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from graph_oracle import check
from synthetic import RAX, RBX, RCX, RDI, RDX, RSP, FunctionBuilder, add, const, load, op, program_units, reg, store, tmp
from test_forward_memory_refinement import ROOT, _baseline
from test_guarded_ranges import _scan
from tdo_v2 import _forward_memory as refinement
from tdo_v2.forward import forward_facts, probe
from tdo_v2.interprocedural import analyze_units
from tdo_v2.may_alias import derive_may_alias_reads
from tdo_v2.model import UnresolvedReason, UnresolvedStorage
from tdo_v2.normalize import FunctionNormalizer


READ, WRITER = "1:100c:0:LOAD", "1:1008:5:STORE"


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def forward_engine(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)


def _body(*, displacement=16, mask=7, base=RSP, width=1, address_bytes=8):
    index, wide, address, slot = tmp(0x100, 4), tmp(0x110), tmp(0x120), tmp(0x130)
    # DIV is already supported by forward values but not the static address
    # projector. This isolates the footprint consumer from new range rules.
    body = (FunctionBuilder().sub_rsp(64)
            .ins(add(slot, reg(RSP), const(48)), store(slot, const(0x8877, 2)))
            .ins(op("INT_AND", [reg(RCX, 4), const(mask, 4)], index),
                 op("INT_DIV", [index, const(1, 4)], index), op("INT_ZEXT", [index], wide),
                 add(address, reg(base), const(displacement & ((1 << 64) - 1))),
                 add(address, address, wide), store({**address, "byte_size": address_bytes}, reg(RDX, width)))
            .ins(load(reg(RAX, 2), slot)))
    return body.add_rsp(64).ret()


def _target(plan):
    return [] if plan is None else [proof for proof in plan.proofs if (proof.read, proof.writer) == (READ, WRITER)]


def _effect(unit, key=WRITER):
    return next(effect for block in unit.blocks for effect in block.effects if effect.operation_key == key)


def _changed_unit(unit, **changes):
    return replace(unit, blocks=tuple(replace(block, effects=tuple(
        replace(effect, **changes) if effect.operation_key == WRITER else effect
        for effect in block.effects)) for block in unit.blocks))


def test_unknown_footprint_removes_only_the_exact_read_label_and_keeps_raw_writes():
    original, options, plan = _baseline(_body())
    (proof,) = _target(plan)
    baseline = original.normalized
    raw = _effect(baseline.forward_inputs.effect_unit)
    assert raw.memory_write is not None and not raw.writes
    assert len(baseline.memory_ssa.unresolved_writes) == 1
    assert proof.write_fact in forward_facts(baseline, original.unit)
    assert proof.write_fact.claim.items[0][1].lo == -48
    assert proof.write_fact.claim.items[0][1].hi == -41
    plan.verify()

    replay = FunctionNormalizer().normalize(original.unit, **options, _forward_memory_plan=plan)
    assert not any(row.operation_key == READ and WRITER in row.writers for row in replay.may_alias_reads)
    assert replay.memory_ssa.unresolved_writes == baseline.memory_ssa.unresolved_writes
    assert replay.memory_graph.unresolved_write_nodes
    assert _effect(replay.forward_inputs.effect_unit) == raw
    assert any(node.kind.value == "memory_debt" and node.label == "unresolved_memory_write"
               for node in (replay.dependencies.node(i) for i in range(replay.dependencies.node_count)))
    for stack in (0x70000000, 8):
        report = check(replay, original.unit.observation, seeds=range(8), register_pools=lambda seed: {
            RSP: stack, RCX: seed, RDX: 0xA0 + seed})
        assert report.checked and not report.silent and not report.opaque_opcodes


def test_full_engine_retains_summary_unknown_writer(monkeypatch):
    units = program_units(_body())
    monkeypatch.setenv("TDO_V2_FORWARD", "0")
    baseline = analyze_units(units)[ROOT]
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    replay = analyze_units(units)[ROOT]
    assert _target(SimpleNamespace(proofs=replay.normalized.forward_memory_proofs))
    assert WRITER in baseline.summary.unknown_writers
    assert replay.summary.unknown_writers == baseline.summary.unknown_writers
    assert replay.normalized.memory_ssa.unresolved_writes == baseline.normalized.memory_ssa.unresolved_writes


@pytest.mark.parametrize("changes", (
    {"displacement": 48}, {"displacement": 47, "width": 2}, {"base": RDI},
    {"mask": 15}, {"width": 17}, {"address_bytes": 4},
))
def test_overlap_changed_base_access_width_and_caps_keep_the_debt(changes):
    original, _, plan = _baseline(_body(**changes))
    assert not _target(plan)
    assert any(row.operation_key == READ and WRITER in row.writers for row in original.normalized.may_alias_reads)


def test_plain_footprint_cannot_remove_the_same_writers_uncertain_label():
    original, _, plan = _baseline(_body())
    assert _target(plan)
    inputs = original.normalized.forward_inputs
    rows = derive_may_alias_reads(inputs.effect_unit, inputs.observation, inputs.context, inputs.address_spaces,
                                 uncertain_writers=frozenset({WRITER}), read_separations=plan)
    (row,) = [row for row in rows if row.operation_key == READ]
    assert WRITER in row.uncertain and WRITER in row.writers and WRITER not in row.plain


@pytest.mark.parametrize("change", ("width", "extra_write", "extra_unknown", "extra_read", "call"))
def test_extra_or_changed_effects_are_not_a_raw_store_footprint(change):
    original, options, plan = _baseline(_body())
    inputs = original.normalized.forward_inputs
    raw = _effect(inputs.effect_unit)
    changes = {
        "width": {"memory_write": replace(raw.memory_write, width=2)},
        "extra_write": {"writes": (raw.reads[0],)},
        "extra_unknown": {"unresolved_writes": (replace(raw.memory_write,
            address=UnresolvedStorage(UnresolvedReason.UNKNOWN_SPACE), width=raw.memory_write.raw_address.size),)},
        "extra_read": {"memory_read": raw.memory_write},
        "call": {"call_targets": ("unexpected",)},
    }[change]
    changed = _changed_unit(inputs.effect_unit, **changes)
    normalized = replace(original.normalized, forward_inputs=replace(inputs, effect_unit=changed))
    result = SimpleNamespace(**{**original.__dict__, "normalized": normalized})
    assert not _target(refinement.prepare_memory_refinement(result, options))
    with pytest.raises(refinement.RefinementRefused):
        refinement.exclusions_for(plan, changed)


def test_unknown_writer_proof_keeps_source_fact_pins():
    original, options, plan = _baseline(_body())
    (proof,) = _target(plan)
    forged = replace(plan, proofs=tuple(replace(row, write_fact=replace(row.write_fact, context=("foreign",)))
                                       if row is proof else row for row in plan.proofs))
    with pytest.raises(refinement.RefinementRefused):
        forged.verify()
    with pytest.raises(refinement.RefinementRefused):
        FunctionNormalizer().normalize(original.unit, **options, _forward_memory_plan=forged)


@pytest.mark.parametrize("second_displacement", (6, 8))
def test_guarded_scan_to_unknown_store_to_exact_read_composes(second_displacement):
    rows, _ = _scan()
    address, slot, tail = tmp(0x500), tmp(0x510), tmp(0x520)
    body = (FunctionBuilder().sub_rsp(16)
            .ins(add(slot, reg(RSP), const(6)), store(slot, const(0x1111111111111111)),
                 add(tail, reg(RSP), const(14)), store(tail, const(0x7D77, 2)))
            .ins(*rows)
            .ins(op("INT_XOR", [reg(RAX, 4), const(28, 4)], reg(RAX, 4)),
                 op("INT_RIGHT", [reg(RAX, 4), const(2, 4)], reg(RAX, 4)),
                 op("INT_ZEXT", [reg(RAX, 4)], reg(RAX)))
            .ins(add(address, reg(RSP), const(4)), add(address, address, reg(RAX)),
                 store(address, const(0x755C, 2)))
            .ins(add(address, reg(RSP), const(second_displacement)), add(address, address, reg(RAX)),
                 store(address, const(0x7B, 1)))
            .ins(load(reg(RAX, 2), tail))
            .ins(load(reg(RBX), slot)).add_rsp(16).ret())
    short_read, long_read = "1:1018:0:LOAD", "1:101c:0:LOAD"
    first, second = "1:1010:2:STORE", "1:1014:2:STORE"
    original, options, plan = _baseline(body)
    assert plan is not None
    baseline = original.normalized
    assert len(baseline.memory_ssa.unresolved_writes) == 2
    assert all(_effect(baseline.forward_inputs.effect_unit, key).memory_write is not None for key in (first, second))
    selected = {proof.writer for proof in plan.proofs if proof.read == short_read}
    assert selected == ({first, second} if second_displacement == 6 else {first})
    assert not any(proof.read == long_read for proof in plan.proofs)
    replay = FunctionNormalizer().normalize(original.unit, **options, _forward_memory_plan=plan)
    assert replay.memory_ssa.unresolved_writes == baseline.memory_ssa.unresolved_writes
    assert replay.memory_graph.unresolved_write_nodes
    remaining = {row.operation_key: set(row.writers) for row in replay.may_alias_reads}
    assert remaining.get(short_read, set()) == (set() if second_displacement == 6 else {second})
    assert remaining[long_read] == {first, second}
    if second_displacement == 6:
        proof = next(proof for proof in plan.proofs if proof.read == short_read)
        found, _ = probe(replay, short_read, (proof.span,))
        assert replay.memory_ssa.definitions[found[proof.span]].operation_key == "1:1004:3:STORE"
    report = check(replay, original.unit.observation, seeds=range(9), register_pools=lambda seed: {
        RSP: 0x70000000, RCX: (1 << (seed * 4)) if seed < 8 else 0})
    assert report.checked and not report.silent and not report.opaque_opcodes


def test_a_debt_tainted_base_has_no_unknown_store_footprint():
    index, wide, address, slot, pointer = (tmp(0x100, 4), tmp(0x110), tmp(0x120), tmp(0x130), tmp(0x140))
    unknown = tmp(0x150)
    body = (FunctionBuilder().sub_rsp(64)
            .ins(add(slot, reg(RSP), const(48)), store(slot, const(0x8877, 2)),
                 add(pointer, reg(RSP), const(32)), store(pointer, reg(RSP)))
            .ins(op("INT_MULT", [reg(RDI), reg(RDI)], unknown), store(unknown, reg(RDX)))
            .ins(load(reg(RBX), pointer))
            .ins(op("INT_AND", [reg(RCX, 4), const(7, 4)], index),
                 op("INT_DIV", [index, const(1, 4)], index), op("INT_ZEXT", [index], wide),
                 add(address, reg(RBX), const(16)), add(address, address, wide), store(address, reg(RDX, 1)))
            .ins(load(reg(RAX, 2), slot)).add_rsp(64).ret())
    original, _, plan = _baseline(body)
    writer, read = "1:1010:5:STORE", "1:1014:0:LOAD"
    assert not any(fact.operation == writer for fact in forward_facts(original.normalized, original.unit))
    assert plan is None or not any(proof.read == read and proof.writer == writer for proof in plan.proofs)
    assert any(row.operation_key == read and writer in row.writers for row in original.normalized.may_alias_reads)
