"""Shared index LOAD identities must produce real, byte-exact SSA edges.

The existing interpreter/graph oracle executes the synthetic observations;
equal numeric ranges alone never stand in for equal stored values.
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from graph_oracle import check
from synthetic import (
    CODE_BASE, REG, RAX, RCX, RDI, RDX, RSP, FunctionBuilder, add, const, copy,
    load, op, program_units, reg, slice_from, store, tmp,
)
from tdo_v2._forward_memory import RefinementRefused
from tdo_v2.forward import forward_facts
from tdo_v2.interprocedural import analyze_units
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction


ROOT = "1:1000"


def _fixture(case="shared"):
    builder, keys = FunctionBuilder().sub_rsp(0x40), {}
    slot, other_slot = tmp(0x130), tmp(0x140)
    index, first, second = tmp(0x100, 4), tmp(0x200, 4), tmp(0x210, 4)
    wide, address = tmp(0x300), tmp(0x310)
    flag, counter = tmp(0x800, 1), tmp(0x900)

    def ins(name, ordinal, *operations):
        key = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:{ordinal}:{operations[ordinal][0]}"
        keys[name] = key
        builder.ins(*operations)

    mask = 0x80000003 if case == "sext-zext" else 3
    ins("index_store", 2, op("INT_AND", [reg(RCX, 4), const(mask, 4)], index),
        add(slot, reg(RSP), const(0x30)), store(slot, index))
    if case == "different-index":
        builder.ins(op("INT_AND", [reg(RDI, 4), const(3, 4)], index),
                    add(other_slot, reg(RSP), const(0x34)), store(other_slot, index))
    if case == "loop":
        builder.ins(copy(counter, const(2))).label("again")
    ins("first_index_load", 0, load(first, slot))
    if case == "bypass-store":
        builder.cbranch("after-store", flag, op("INT_AND", [reg(RDI, 1), const(1, 1)], flag))
    ins("array_store", 4, op("INT_SEXT", [first], wide),
        op("INT_MULT", [wide, const(4)], address), add(address, address, reg(RSP)),
        add(address, address, const(0x10)), store(address, reg(RDX, 4)))
    if case == "bypass-store":
        builder.label("after-store")
    if case == "overwrite":
        builder.ins(store(slot, const(0, 4)))
    elif case == "partial-overwrite":
        builder.ins(add(other_slot, slot, const(1)), store(other_slot, const(0x80, 1)))
    elif case == "opaque-call":
        builder.call(CODE_BASE + 0xD00)
    ins("second_index_load", 0, load(second, other_slot if case == "different-index" else slot))
    extension = "INT_ZEXT" if case == "sext-zext" else "INT_SEXT"
    builder.ins(op(extension, [second], wide), op("INT_MULT", [wide, const(4)], address),
                add(address, address, reg(RSP)), add(address, address, const(0x10)))
    if case == "later-store":
        ins("later_store", 0, store(address, reg(RDI, 4)))
    ins("array_load", 0, load(reg(RAX, 4), address))
    if case == "loop":
        builder.ins(op("INT_SUB", [counter, const(1)], counter))
        builder.cbranch("again", flag, op("INT_NOTEQUAL", [counter, const(0)], flag))
    return builder.add_rsp(0x40).ret(), keys


def _analyze(builder, monkeypatch, enabled, engine):
    monkeypatch.setenv("TDO_V2_FORWARD", "1" if enabled else "0")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    (unit,) = program_units(builder)
    item = analyze_units([unit])[ROOT]
    assert isinstance(item.normalized, NormalizedFunction) and item.summary is not None
    return item


def _memory_reads(normalized, key):
    ssa = normalized.memory_ssa
    return [row for row in ssa.reads if ssa.actions[row.action_id].operation_key == key
            and row.span.object_id.kind.value in ("function_relative", "address_space")]


def _exact_writer(normalized, reader, writer):
    ssa = normalized.memory_ssa
    (read,) = _memory_reads(normalized, reader)
    assert read.span.size == 4 and len(read.fragments) == 1
    (fragment,) = read.fragments
    assert fragment.span == read.span and len(fragment.definition_ids) == 1
    (identifier,) = fragment.definition_ids
    definition = ssa.definitions[identifier]
    assert definition.kind is MemoryDefinitionKind.DATA_WRITE
    assert definition.operation_key == writer and definition.span == read.span
    (action,) = [row for row in ssa.actions if row.operation_key == writer]
    assert action.write_definition_ids[definition.write_ordinal] == identifier
    return read, identifier


def _oracle(item, case):
    report = check(item.normalized, item.unit.observation, seeds=range(8),
                   register_pools=lambda seed: {RSP: 0x70000000,
                                                RCX: seed | (0x80000000 if case == "sext-zext" and seed & 1 else 0),
                                                RDI: seed + 1, RDX: 0x12345678 + seed},
                   havoc_calls=(REG, RSP, 8) if case == "opaque-call" else None)
    assert report.runs == 8 and report.checked and not report.unsupported
    assert not report.opaque_opcodes and not report.silent, report.silent


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_equal_stored_index_values_create_the_original_array_store_to_load_edge(monkeypatch, engine):
    body, keys = _fixture()
    before = _analyze(body, monkeypatch, False, engine)
    after = _analyze(body, monkeypatch, True, engine)
    old, normalized = before.normalized, after.normalized
    assert not old.load_value_proofs
    assert any(row.operation_key == keys["array_load"] for row in old.may_alias_reads)
    proofs = normalized.load_value_proofs
    assert {proof.reader for proof in proofs} == {keys["first_index_load"], keys["second_index_load"]}
    assert len({proof.value_class for proof in proofs}) == 1
    assert all(proof.span.size == 4 and proof.definition[0] is MemoryDefinitionKind.DATA_WRITE
               and proof.definition[1] == keys["index_store"] for proof in proofs)
    read, identifier = _exact_writer(normalized, keys["array_load"], keys["array_store"])
    graph = normalized.dependencies
    definition_node = normalized.memory_graph.definition_nodes[identifier]
    store_node = graph.node_for_key("op:" + keys["array_store"])
    load_node = graph.node_for_key("op:" + keys["array_load"])
    assert any(source == store_node and target == definition_node and edge.kind == "memory_defines"
               and edge.span == read.span for source, target, edge in graph.out_edges(store_node))
    assert any(source == definition_node and target == load_node and edge.kind == "memory_read"
               and edge.span == read.span for source, target, edge in graph.in_edges(load_node))
    assert not any(row.operation_key == keys["array_load"]
                   for row in (*normalized.may_alias_reads, *normalized.call_clobber_reads))
    assert slice_from(normalized, load_node).is_complete
    _oracle(before, "shared")
    _oracle(after, "shared")


@pytest.mark.parametrize("engine", ("sparse", "dense"))
@pytest.mark.parametrize("case", ("overwrite", "partial-overwrite", "different-index", "bypass-store",
                                 "loop", "opaque-call", "later-store", "sext-zext"))
def test_counterexamples_keep_byte_writers_and_unproven_debts(monkeypatch, engine, case):
    body, keys = _fixture(case)
    before = _analyze(body, monkeypatch, False, engine)
    after = _analyze(body, monkeypatch, True, engine)
    normalized = after.normalized
    if case == "later-store":
        # Identity reuse cannot replace an intervening exact last writer.
        for item in (before, after):
            _exact_writer(item.normalized, keys["array_load"], keys["later_store"])
    else:
        assert not normalized.load_value_proofs
        assert any(row.operation_key == keys["array_load"]
                   for row in (*normalized.may_alias_reads, *normalized.call_clobber_reads))
        assert not slice_from(normalized, normalized.dependencies.node_for_key(
            "op:" + keys["array_load"])).is_complete
    if case == "different-index":
        facts = {row.operation: row for row in forward_facts(normalized, after.unit)}
        # Same finite address ranges do not authorize merging independent values.
        assert facts[keys["array_store"]].claim == facts[keys["array_load"]].claim
    _oracle(before, case)
    _oracle(after, case)


def test_identity_bindings_accept_equal_context_and_reject_other_ssa_scope_or_digest(monkeypatch):
    normalize, inspected = FunctionNormalizer.normalize, []

    def inspect(self, unit, **options):
        plan = options.get("_load_identity_plan")
        if plan is not None:
            inputs, ssa = plan.baseline.forward_inputs, plan.baseline.memory_ssa
            equivalent = replace(inputs.context)
            assert equivalent == inputs.context and equivalent is not inputs.context
            bindings = plan.bindings(inputs.effect_unit, inputs.observation, equivalent,
                                     inputs.address_spaces, ssa)
            assert bindings == {(proof.reader, proof.span.size): proof.value_class for proof in plan.proofs}
            foreign_scope = replace(ssa.function_scope, digest=b"\xff" * 32)
            for changed in (replace(ssa, function_scope=foreign_scope), replace(ssa, unit_digest=b"\xfe" * 32)):
                with pytest.raises(RefinementRefused):
                    plan.bindings(inputs.effect_unit, inputs.observation, inputs.context,
                                  inputs.address_spaces, changed)
            with pytest.raises(RefinementRefused):
                plan.bindings(inputs.effect_unit, inputs.observation,
                              replace(inputs.context, function_scope=foreign_scope), inputs.address_spaces, ssa)
            inspected.append(unit)
        return normalize(self, unit, **options)

    monkeypatch.setattr(FunctionNormalizer, "normalize", inspect)
    body, keys = _fixture()
    item = _analyze(body, monkeypatch, True, "sparse")
    assert inspected == [item.unit]
    _exact_writer(item.normalized, keys["array_load"], keys["array_store"])


def test_optional_identity_budget_keeps_the_existing_memory_refinement_result(monkeypatch):
    from test_forward_memory_refinement import _baseline
    from tdo_v2 import _load_identity

    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    body, keys = _fixture()
    original, options, memory_plan = _baseline(body)
    assert memory_plan is not None
    n1 = FunctionNormalizer().normalize(original.unit, **options, _forward_memory_plan=memory_plan)
    source = SimpleNamespace(unit=original.unit, normalized=n1, key=ROOT, declared={},
                             inherited_assumptions=frozenset(), proven={})
    assert _load_identity.prepare_load_identities(source, options) is not None
    monkeypatch.setattr(_load_identity, "MAX_LOAD_IDENTITIES", 0)
    assert _load_identity.prepare_load_identities(source, options) is None
    capped = analyze_units([original.unit])[ROOT].normalized
    assert not capped.load_value_proofs
    assert capped.memory_ssa == n1.memory_ssa
    assert capped.may_alias_reads == n1.may_alias_reads
    assert capped.forward_memory_proofs == n1.forward_memory_proofs
    assert any(row.operation_key == keys["array_load"] for row in capped.may_alias_reads)


@pytest.mark.parametrize("scope", ("function", "run"))
@pytest.mark.parametrize("stage", ("normalize", "accepts"))
def test_n2_hard_exhaustion_never_publishes_the_already_finished_n1(monkeypatch, scope, stage):
    from tdo_v2._load_identity import LoadIdentityPlan
    from tdo_v2.normalize import NormalizationFailureReason, UnresolvedNormalizedFunction
    from tdo_v2.resource_limits import AnalysisBudgetExceeded

    body, _ = _fixture()
    units = program_units(body)
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    normalize = FunctionNormalizer.normalize
    attempted = []

    def exhausted(self, unit, **options):
        if options.get("_load_identity_plan") is not None:
            attempted.append(unit)
            assert options["_load_identity_plan"].baseline.forward_memory_proofs
            raise AnalysisBudgetExceeded("work", "n2-test", scope=scope)
        return normalize(self, unit, **options)

    def exhausted_acceptance(self, result):
        attempted.append(result.unit)
        assert self.baseline.forward_memory_proofs and result.normalized.load_value_proofs
        raise AnalysisBudgetExceeded("work", "n2-accept-test", scope=scope)

    if stage == "normalize":
        monkeypatch.setattr(FunctionNormalizer, "normalize", exhausted)
    else:
        monkeypatch.setattr(LoadIdentityPlan, "accepts", exhausted_acceptance)
    provenance = {}
    result = analyze_units(units, record_provenance=provenance)[ROOT]
    assert attempted == units
    assert result.summary is None and isinstance(result.normalized, UnresolvedNormalizedFunction)
    expected = NormalizationFailureReason.ANALYSIS_BUDGET if scope == "function" else \
        NormalizationFailureReason.ANALYSIS_RUN_BUDGET
    assert result.normalized.reason is expected
    assert provenance == {}
