"""Caller-owned activation inputs never replace generic callee ENTRY facts."""

from dataclasses import FrozenInstanceError, replace

import pytest

from synthetic import RAX, RBX, RCX, RDX, RSP, FunctionBuilder, add, const, load, program_units, reg, store, tmp
from tdo_v2._activation_entry import ACTIVE_ENTRY, ActivationEntry, entry_for, entry_seed, using_entry
from tdo_v2.constant_value import ExactConstant
from tdo_v2.forward import _analyze, context_facts, forward_facts, probe
from tdo_v2.interprocedural import analyze_units
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.normalize import FunctionNormalizer
from tdo_v2.span_geometry import ByteSpan, StorageObjectId, StorageObjectKind, StorageScopeId, StorageScopeKind


PROGRAM = StorageScopeId(StorageScopeKind.PROGRAM, b"p" * 32)
SCOPE = StorageScopeId(StorageScopeKind.FUNCTION, b"f" * 32)
OTHER = StorageScopeId(StorageScopeKind.FUNCTION, b"g" * 32)
REGISTERS = StorageObjectId(StorageObjectKind.REGISTER_FILE, PROGRAM, 0)
MEMORY = StorageObjectId(StorageObjectKind.FUNCTION_RELATIVE, SCOPE, 1)
DST, BASE = ByteSpan(REGISTERS, RCX, 8), ByteSpan(REGISTERS, RSP, 8)
DATA = ByteSpan(MEMORY, 1 << 64, 8)
CONTEXT = ("1:2000", "1:2010:2:CALL")


def _entry(**changes):
    fields = dict(scope=SCOPE, context=CONTEXT, registers=((DST, BASE, 80),),
                  memory=((DATA, ExactConstant(8, 0x8877665544332211)),), requires=("caller-memory",))
    fields.update(changes)
    return ActivationEntry(**fields)


def test_exact_scope_whole_register_and_little_endian_memory_subspan():
    state = _entry()
    assert entry_for(SCOPE) is None and entry_seed(SCOPE, DATA) is None
    with using_entry(state):
        assert entry_for(SCOPE) is state and entry_for(OTHER) is None
        assert entry_seed(SCOPE, DST) == ("affine", BASE, 80)
        assert entry_seed(SCOPE, ByteSpan(REGISTERS, RCX, 4)) is None
        assert entry_seed(SCOPE, DATA) == ("constant", ExactConstant(8, 0x8877665544332211))
        assert entry_seed(SCOPE, ByteSpan(MEMORY, DATA.start + 2, 3)) == ("constant", ExactConstant(3, 0x554433))
        assert entry_seed(SCOPE, ByteSpan(MEMORY, DATA.start + 7, 2)) is None
        assert entry_seed(SCOPE, ByteSpan(MEMORY, DATA.start, 16)) is None
        assert entry_seed(OTHER, DATA) is None
        with using_entry(None):
            assert ACTIVE_ENTRY.get() is None
        assert ACTIVE_ENTRY.get() is state
    assert ACTIVE_ENTRY.get() is None
    with pytest.raises(FrozenInstanceError):
        state.context = ("other", "call")


@pytest.mark.parametrize("change", (
    {"scope": PROGRAM}, {"context": ()}, {"context": ("caller", "")}, {"requires": ["label"]},
    {"registers": [(DST, BASE, 80)]}, {"registers": ((DST, BASE, True),)},
    {"registers": ((DST, ByteSpan(REGISTERS, RSP, 4), 0),)},
    {"registers": ((DST, BASE, 1 << 63),)},
    {"registers": ((DST, BASE, 0), (ByteSpan(REGISTERS, RCX + 4, 4), ByteSpan(REGISTERS, RSP, 4), 0))},
    {"memory": ((DATA, ExactConstant(4, 0)),)},
    {"memory": ((DATA, ExactConstant(8, 0)), (DATA, ExactConstant(8, 1)))},
    {"memory": ((DATA, ExactConstant(8, 0)), (ByteSpan(MEMORY, DATA.start + 4, 4), ExactConstant(4, 0)))},
    {"memory": ((ByteSpan(StorageObjectId(StorageObjectKind.FUNCTION_RELATIVE, OTHER, 1), 0, 8),
                 ExactConstant(8, 0)),)},
))
def test_malformed_overlapping_and_foreign_inputs_are_refused(change):
    with pytest.raises((TypeError, ValueError)):
        _entry(**change)


@pytest.fixture(autouse=True)
def forward_on(monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")


def _item(builder):
    return analyze_units(program_units(builder), assume_entry_values_not_frame=False,
                         assume_opaque_callees_leave_no_stack_addresses=False)["1:1000"]


def _memory_read(item, ordinal=0):
    normalized = item.normalized
    reads = [read for read in normalized.memory_ssa.reads
             if read.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE
             and normalized.memory_ssa.actions[read.action_id].operation_key.endswith(":LOAD")]
    return reads[ordinal]


def _captured(item, memory=(), registers=(), context=CONTEXT):
    state = ActivationEntry(item.normalized.memory_ssa.function_scope, context, registers, memory, ("seed-proof",))
    return replace(item.normalized, activation_entry=state), state


def _call(item):
    return next(f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:CALLIND"
                for row in item.unit.observation.instructions
                for ordinal, operation in enumerate(row.operations) if operation.opcode == "CALLIND")


def _register_span(item, start, size=8):
    object_id = next(definition.span.object_id for definition in item.normalized.memory_ssa.definitions
                     if definition.span.object_id.kind is StorageObjectKind.REGISTER_FILE)
    return ByteSpan(object_id, start, size)


def test_entry_memory_inside_a_coalesced_definition_and_returned_bind_are_captured():
    item = _item(FunctionBuilder().ins(load(tmp(0x300, 16), reg(RCX)))
                 .ins(load(reg(RAX), reg(RCX)))
                 .ins(add(tmp(0x400), reg(RCX), const(8)), load(reg(RDX), tmp(0x400)))
                 .call_indirect(RAX).ret())
    read = _memory_read(item, 1)
    (fragment,) = read.fragments
    (identifier,) = fragment.definition_ids
    definition = item.normalized.memory_ssa.definitions[identifier]
    assert definition.kind is MemoryDefinitionKind.ENTRY and definition.span.contains(read.span)
    assert definition.span.size > read.span.size == 8
    normalized, state = _captured(item, ((read.span, ExactConstant(8, 0)),))
    analysis = _analyze(normalized, item.unit)
    result, uncovered = _register_span(item, RAX), _register_span(item, RDX)
    # bind runs after _analyze has restored its ContextVar. It must re-enter
    # its own capture, not another ambient activation or the generic state.
    with using_entry(_entry()):
        values, labels = analysis.bind(_call(item), (result, uncovered))
        assert values[result].single_number() == 0 and "seed-proof" in labels
        assert values[uncovered].is_top
    assert ACTIVE_ENTRY.get() is None
    generic, _ = _analyze(item.normalized, item.unit).bind(_call(item), (result,))
    assert generic[result].is_top
    assert state.context == CONTEXT


def test_register_affine_facts_are_scoped_labelled_and_have_distinct_ids():
    item = _item(FunctionBuilder().ins(load(reg(RAX), reg(RCX))).ret())
    destination, base = _register_span(item, RCX), _register_span(item, RSP)
    captured, state = _captured(item, registers=((destination, base, 80),))
    generic = forward_facts(item.normalized, item.unit)
    facts = forward_facts(captured, item.unit, assumptions=("run-policy",))
    assert facts and all(fact.context == CONTEXT and {"run-policy", "seed-proof"} <= set(fact.requires)
                         for fact in facts)
    target = next(fact for fact in facts if fact.operation == "1:1000:0:LOAD")
    assert target.claim.items[0][0] == ("entry", RSP, 8)
    assert target.claim.items[0][1].lo == target.claim.items[0][1].hi == 80
    assert next(fact for fact in generic if fact.operation == target.operation).id != target.id
    other = replace(captured, activation_entry=replace(state, context=("1:2000", "1:2020:2:CALL")))
    assert next(fact for fact in forward_facts(other, item.unit) if fact.operation == target.operation).id != target.id
    with using_entry(state):
        assert forward_facts(item.normalized, item.unit) == generic
    assert context_facts({item.key: replace(item, normalized=captured)}) == ()


def test_a_later_data_write_is_not_replaced_by_the_entry_literal():
    item = _item(FunctionBuilder().ins(store(reg(RCX), const(23)))
                 .ins(load(reg(RAX), reg(RCX))).call_indirect(RAX).ret())
    read = _memory_read(item)
    normalized, _ = _captured(item, ((read.span, ExactConstant(8, 0)),))
    (fragment,) = read.fragments
    assert item.normalized.memory_ssa.definitions[fragment.definition_ids[0]].kind is MemoryDefinitionKind.DATA_WRITE
    result = _register_span(item, RAX)
    values, _ = _analyze(normalized, item.unit).bind(_call(item), (result,))
    assert values[result].single_number() == 23


@pytest.mark.parametrize("kind", ("call", "alias"))
def test_entry_memory_seed_cannot_bypass_call_or_alias_debt(kind):
    if kind == "call":
        builder = FunctionBuilder().call(0x1800).ins(load(reg(RAX), reg(RSP)))
    else:
        builder = FunctionBuilder().ins(store(reg(RDX), const(19))).ins(load(reg(RAX), reg(RCX)))
    item = _item(builder.call_indirect(RAX).ret())
    read = _memory_read(item)
    normalized, _ = _captured(item, ((read.span, ExactConstant(8, 0)),))
    reader = item.normalized.memory_ssa.actions[read.action_id].operation_key
    debts = normalized.call_clobber_reads if kind == "call" else normalized.may_alias_reads
    assert any(row.operation_key == reader for row in debts)
    result = _register_span(item, RAX)
    values, _ = _analyze(normalized, item.unit).bind(_call(item), (result,))
    assert values[result].is_top


def test_probe_masks_ambient_state_and_includes_captured_labels():
    item = _item(FunctionBuilder().ins(load(reg(RAX), reg(RCX))).call_indirect(RAX).ret())
    read = _memory_read(item)
    normalized, state = _captured(item, ((read.span, ExactConstant(8, 0)),))
    with using_entry(state):
        _, generic_labels = probe(item.normalized, _call(item), (read.span,))
        assert "seed-proof" not in generic_labels
    _, captured_labels = probe(normalized, _call(item), (read.span,))
    assert "seed-proof" in captured_labels and ACTIVE_ENTRY.get() is None


def test_generic_bind_masks_a_matching_ambient_activation_and_foreign_capture_is_ignored():
    item = _item(FunctionBuilder().ins(load(reg(RAX), reg(RCX))).call_indirect(RAX).ret())
    read = _memory_read(item)
    _, state = _captured(item, ((read.span, ExactConstant(8, 0)),))
    generic = _analyze(item.normalized, item.unit)
    result = _register_span(item, RAX)
    with using_entry(state):
        values, labels = generic.bind(_call(item), (result,))
        assert values[result].is_top and "seed-proof" not in labels
        assert ACTIVE_ENTRY.get() is state
    foreign = replace(item.normalized, activation_entry=_entry())
    assert forward_facts(foreign, item.unit) == forward_facts(item.normalized, item.unit)


def test_normalizer_captures_and_generic_normalization_stays_generic():
    (unit,) = program_units(FunctionBuilder().ins(load(reg(RAX), reg(RCX))).ret())
    state = ActivationEntry(unit.scopes.function.scope, CONTEXT, (), (), ("seed-proof",))
    with using_entry(state):
        captured = FunctionNormalizer().normalize(unit)
    assert captured.activation_entry is state
    assert FunctionNormalizer().normalize(unit).activation_entry is None
