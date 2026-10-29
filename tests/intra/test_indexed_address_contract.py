"""Bounded original-entry indexed addresses stay locatable and portable."""

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace

import pytest

from synthetic import RAX, RBX, RCX, RDI, RDX, RSP
from tdo_v2.call_summary_effects import (
    AnchoredSpan, IndexedOffset, ProvenCallEffect, ProvenMemoryRun, ProvenRunEffect,
    anchored_span, call_load_keys, derive_composed_call_effect, derive_proven_call_effect,
)
from tdo_v2.function_summary import FUNCTION_SUMMARY_VERSION, ExitSummary, FunctionSummary, SummaryKind, SummaryRun
from tdo_v2.indexed_address import IndexedAnchor
from tdo_v2.span_geometry import ByteSpan, StorageObjectId, StorageObjectKind, StorageScopeId, StorageScopeKind
from tdo_v2.summary_templates import TemplateError, TemplateRefused, _ObjectTable, instantiate


PROGRAM = StorageScopeId(StorageScopeKind.PROGRAM, b"p" * 32)
FUNCTION = StorageScopeId(StorageScopeKind.FUNCTION, b"f" * 32)
REGISTERS = StorageObjectId(StorageObjectKind.REGISTER_FILE, PROGRAM, 0)
GLOBAL = StorageObjectId(StorageObjectKind.ADDRESS_SPACE, PROGRAM, 1)
HEADER = StorageObjectId(StorageObjectKind.FUNCTION_RELATIVE, FUNCTION, 1)
INDEXED = StorageObjectId(StorageObjectKind.FUNCTION_RELATIVE, FUNCTION, 2)
BIAS = 1 << 64


def _reg(offset, size=8):
    return ByteSpan(REGISTERS, offset, size)


def _relation(memory=False, **changes):
    relation = IndexedAnchor(ByteSpan(HEADER, BIAS, 8) if memory else _reg(RDI),
                             ByteSpan(HEADER, BIAS + 8, 4) if memory else _reg(RDX, 4),
                             1, "sext", 0xFFFFFFFF, 2)
    return replace(relation, **changes)


def _summary(relation, *, register=False, conditions=()):
    span = _reg(RAX) if register else ByteSpan(INDEXED, BIAS + 7, 2)
    run = SummaryRun(span, SummaryKind.COMPUTED, (1,), ("write",), (_reg(RBX, 2),), (), (), (),
                     conditions=conditions)
    # (a callee that restores the call shape's push: RSP + 8 at its exit)
    return FunctionSummary(FUNCTION_SUMMARY_VERSION, (ExitSummary("exit", (run,)),), (), (),
                           register_deltas=(((RSP, 8), 8),), address_relations=((INDEXED, relation),))


def _effect(summary):
    """At an x86-64 push call (RSP -8): the restoration is proven, so the
    effect is complete and states its observed registers (docs 25.85)."""
    return derive_proven_call_effect(summary, "indexed", REGISTERS, 128, excluded=(_reg(RSP),),
                                     anchors={HEADER: (_reg(RCX), 1)}, stack_deltas={(RSP, 8): -8})


def _template(relation, *, writer_condition=False):
    table = _ObjectTable({HEADER: (_reg(RCX), 1)}, {INDEXED: relation})
    run = _summary(relation).exits[0].runs[0]
    return {"exits": [{"block": "dll:exit", "runs": [table.run(run)]}], "unknown_writers": [],
            "writer_objects": [], "inner_calls": [], "register_deltas": [], "independent_delta_proofs": [], "dead_exits": [],
            "writer_conditions": [table.pair((run.span, ByteSpan(HEADER, BIAS, 8)))] if writer_condition else [],
            "stack_values_out": False, "objects": table.rows}


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_disabled_rep_operations_do_not_become_raw_indexed_relation_candidates(monkeypatch, engine):
    from synthetic import R9, program_units
    from test_rep_strings import _function
    from tdo_v2.interprocedural import analyze_units
    from tdo_v2.operation_records import eligibility, run_records

    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    (unit,) = program_units(_function(("reg", R9))[0])
    result = analyze_units([unit])["1:1000"]
    assert any(operation is None for _, operation in result.normalized.operation_overrides)
    assert result.summary is not None and result.summary.address_relations == ()
    records = run_records(result.normalized, result.unit, result.summary)
    assert "unproven rep" in {eligibility(record) for record in records}


@pytest.mark.parametrize("width,extend,preoffset,scale", [(4, "sext", 0xFFFFFFFF, 3),
                                                       (4, "zext", 0, -7),
                                                       (8, "identity", (1 << 64) - 1, -(1 << 63))])
def test_indexed_anchor_is_immutable_and_preserves_source_width_arithmetic(width, extend, preoffset, scale):
    relation = _relation(index=_reg(RDX, width), extend=extend, preoffset=preoffset, scale=scale)
    assert relation == IndexedAnchor(_reg(RDI), _reg(RDX, width), 1, extend, preoffset, scale)
    assert hash(relation)
    with pytest.raises(FrozenInstanceError):
        relation.scale = 0


@pytest.mark.parametrize("change", [
    {"base": _reg(RDI, 4)}, {"index": _reg(RDX, 2)}, {"extend": "identity"}, {"extend": "SEXT"},
    {"index": _reg(RDX), "extend": "sext"}, {"preoffset": -1}, {"preoffset": 1 << 32},
    {"preoffset": False}, {"scale": 0}, {"scale": 1 << 63}, {"scale": -(1 << 63) - 1},
    {"scale": True}, {"space_id": True}, {"space_id": -1}, {"base": None},
])
def test_invalid_indexed_relations_are_not_silently_coerced(change):
    with pytest.raises((TypeError, ValueError)):
        _relation(**change)


@pytest.mark.parametrize("register,memory,extend", [
    (None, None, "sext"), (_reg(RDX, 4), AnchoredSpan(_reg(RCX), 8, 4, 1), "sext"),
    (ByteSpan(HEADER, BIAS, 4), None, "sext"), (_reg(RDX, 4), None, "identity"),
])
def test_indexed_offset_requires_exactly_one_supported_source(register, memory, extend):
    with pytest.raises((TypeError, ValueError)):
        IndexedOffset(register, memory, extend, 0, 2)


@pytest.mark.parametrize("memory", [False, True])
def test_anchored_index_keeps_base_index_displacement_and_source_inputs(memory):
    relation = _relation(memory)
    summary = _summary(relation)
    effect = _effect(summary)
    (run,) = effect.memory_runs
    access = run.write
    assert access.displacement == 7 and access.size == 2 and access.space_id == 1
    assert access.index.extend == "sext" and access.index.preoffset == 0xFFFFFFFF and access.index.scale == 2
    if memory:
        assert access.anchor is None and access.pointer == AnchoredSpan(_reg(RCX), 0, 8, 1)
        assert access.index.memory == AnchoredSpan(_reg(RCX), 8, 4, 1) and access.index.register is None
        assert set(effect.observed_registers) == {_reg(RBX, 2), _reg(RCX)}
        assert list(call_load_keys("call", effect)) == [access.pointer, access.index.memory]
    else:
        assert access.anchor == _reg(RDI) and access.pointer is None
        assert access.index.register == _reg(RDX, 4) and access.index.memory is None
        assert set(effect.observed_registers) == {_reg(RBX, 2), _reg(RDI), _reg(RDX, 4)}


@pytest.mark.parametrize("child", ["base", "index"])
def test_global_or_unlocatable_entry_children_are_not_claimed_as_indexed_places(child):
    for object_id in (GLOBAL, INDEXED):
        width = 8 if child == "base" else 4
        relation = _relation(**{child: ByteSpan(object_id, BIAS, width)})
        assert anchored_span(ByteSpan(INDEXED, BIAS, 2), {HEADER: (_reg(RCX), 1)},
                             relations={INDEXED: relation}) is None
        with pytest.raises(TemplateRefused):
            _template(relation)


def test_pointer_and_index_memory_loads_are_recursive_deduplicated_and_in_order():
    base = AnchoredSpan(_reg(RDI), 0, 8, 1)
    index_pointer = AnchoredSpan(_reg(RCX), 0, 8, 1)
    index = AnchoredSpan(None, 8, 4, 1, pointer=index_pointer)
    target = AnchoredSpan(None, 3, 2, 1, pointer=base, index=IndexedOffset(None, index, "zext", 1, 5))
    condition_index = AnchoredSpan(_reg(RDX), 0, 4, 1)
    condition = AnchoredSpan(_reg(RBX), 0, 2, 1,
                             index=IndexedOffset(None, condition_index, "sext", 0, 2))
    run = ProvenMemoryRun(target, (), (target,), False, conditions=((condition, target),))
    effect = ProvenCallEffect("callee", (), (), (run,), writer_conditions=((target, condition),))
    assert list(call_load_keys("call", effect).items()) == [
        (base, "call~ld0"), (index_pointer, "call~ld1"), (index, "call~ld2"),
        (target, "call~ld3"), (condition_index, "call~ld4")]


def test_condition_only_index_inputs_are_observed_and_loaded_without_strengthening_conditions():
    relation = _relation(memory=True)
    side = ByteSpan(INDEXED, BIAS + 7, 2)
    condition = (side, ByteSpan(HEADER, BIAS, 8))
    summary = _summary(relation, register=True, conditions=(condition,))
    effect = _effect(summary)
    assert set(effect.observed_registers) == {_reg(RBX, 2), _reg(RCX)}
    assert effect.runs[0].conditions and len(call_load_keys("call", effect)) == 2
    summary = replace(summary, writer_conditions=(condition,))
    effect = _effect(summary)
    assert effect.writer_conditions and len(call_load_keys("call", effect)) == 2


@pytest.mark.parametrize("memory", [False, True])
def test_strict_template_roundtrip_rebases_only_memory_space_and_preserves_indexed_contract(memory):
    relation = _relation(memory)
    raw = _template(relation, writer_condition=True)
    indexed = next(row["indexed"] for row in raw["objects"] if "indexed" in row)
    assert set(indexed) == {"base", "index", "extend", "preoffset", "scale"}
    summary, anchors = instantiate(raw, "portable-indexed", REGISTERS, 9)
    (object_id, restored), = summary.address_relations
    assert restored.space_id == 9 and (restored.extend, restored.preoffset, restored.scale) == ("sext", 0xFFFFFFFF, 2)
    assert object_id not in anchors
    effect = derive_proven_call_effect(summary, "imported", REGISTERS, 128, anchors=anchors)
    (run,) = effect.memory_runs
    assert run.write.space_id == 9 and run.write.displacement == 7 and run.write.index.scale == 2
    assert effect.writer_conditions and all(side.space_id == 9 for pair in effect.writer_conditions for side in pair)


@pytest.mark.parametrize("field,value", [("extend", "identity"), ("extend", True), ("preoffset", False),
                                        ("preoffset", -1), ("preoffset", 1 << 32), ("scale", 0),
                                        ("scale", 1 << 63), ("scale", True), ("extra", 0)])
def test_template_rejects_malformed_indexed_descriptor(field, value):
    raw = deepcopy(_template(_relation()))
    next(row["indexed"] for row in raw["objects"] if "indexed" in row)[field] = value
    with pytest.raises(TemplateError):
        instantiate(raw, "bad-indexed", REGISTERS, 1)


@pytest.mark.parametrize("change", ["cycle", "local", "indexed-child"])
def test_template_rejects_cycles_and_children_without_basic_entry_locations(change):
    raw = _template(_relation(memory=True))
    indexed = raw["objects"][0]["indexed"]
    child = indexed["base"]["object"]
    if change == "cycle":
        indexed["base"]["object"] = 0
    elif change == "local":
        raw["objects"][child] = {"local": True}
    else:
        raw["objects"][child] = {"indexed": {"base": {"object": "registers", "start": RDI, "size": 8},
                                               "index": {"object": "registers", "start": RDX, "size": 4},
                                               "extend": "sext", "preoffset": 0, "scale": 2}}
    with pytest.raises(TemplateError):
        instantiate(raw, "bad-child", REGISTERS, 1)


def test_composed_summary_carries_relation_union_but_not_a_conflicting_same_object_claim():
    relation = _relation()
    summary = _summary(relation)
    # Two targets writing one relative memory domain stay unknown (existing
    # contested-memory rule), even when their descriptors happen to match.
    effect = derive_composed_call_effect(((summary, {}), (summary, {})), "targets", REGISTERS, 128)
    assert effect.unknown_memory and effect.unknown_memory[0].index is not None
    conflict = _summary(replace(relation, scale=3))
    effect = derive_composed_call_effect(((summary, {}), (conflict, {})), "targets", REGISTERS, 128)
    assert not effect.memory_runs and not effect.preserves_memory
