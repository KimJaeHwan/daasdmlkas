"""A finite address union preserves each candidate, never a selected value."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from synthetic import RAX, RCX, RDI, RDX, RSP, FunctionBuilder, add, const, load, op, program_units, reg, store, tmp
from test_forward_memory_refinement import ROOT, _baseline
from tdo_v2 import _forward_memory as refinement
from tdo_v2.forward import forward_facts, probe
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.model import ResolvedStorage
from tdo_v2.normalize import FunctionNormalizer
from tdo_v2.span_geometry import StorageObjectKind


TABLE = 0x5000


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def engines(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)


def _body(*, mask=15, width=1, base=TABLE, prefix=(), opaque=False, tainted=False, fault=False):
    index, wide, address, slot = tmp(0x100, 4), tmp(0x110), tmp(0x120), tmp(0x130)
    body = FunctionBuilder().ins(*prefix) if prefix else FunctionBuilder()
    body.ins(add(slot, reg(RSP), const(64)), store(slot, const(7)))
    if tainted:
        body.ins(store(reg(RDI), const(3)), load(reg(RCX, 4), slot))
    body.ins(op("INT_AND", [reg(RCX, 4), const(mask, 4)], index),
             op("INT_DIV", [index, const(1, 4)], index), op("INT_ZEXT", [index], wide),
             add(address, wide, const(base)))
    if opaque:
        body.ins(store(reg(RDI), const(9)))
    body.ins(load(reg(RAX, width), address))
    if fault:
        return body.cbranch("fault", reg(RDX, 1)).ret().label("fault").ud2()
    return body.ret()


def _replay(**kwargs):
    options = kwargs.pop("options", {})
    original, options, plan = _baseline(_body(**kwargs), **options)
    assert plan is not None and len(plan.address_reads) == 1
    plan.verify()
    normalized = FunctionNormalizer().normalize(original.unit, **options, _forward_memory_plan=plan)
    return original, options, plan, normalized


def _effect(normalized, key):
    return next(effect for block in normalized.forward_inputs.effect_unit.blocks for effect in block.effects
                if effect.operation_key == key)


def _ports(normalized, key):
    action = next(index for index, row in enumerate(normalized.memory_ssa.actions) if row.operation_key == key)
    return [row for row in normalized.memory_ssa.reads if row.action_id == action
            and row.span.object_id.kind is StorageObjectKind.ADDRESS_SPACE]


def test_sixteen_alternatives_keep_one_byte_output_and_every_entry_endpoint():
    original, options, plan, replay = _replay()
    (claim,) = plan.address_reads
    before, after = _effect(original.normalized, claim.read), _effect(replay, claim.read)
    assert claim.read_fact in forward_facts(original.normalized, original.unit)
    assert [span.start for span in claim.spans] == list(range(TABLE, TABLE + 16))
    assert all(span.size == 1 for span in claim.spans)
    assert after.writes == before.writes and after.writes[0].span.size == 1
    assert after.reads[0] == before.reads[0]  # original address dependency
    assert tuple(row.span for row in after.reads[1:]) == claim.spans
    ports = _ports(replay, claim.read)
    assert len(ports) == 16
    assert {definition for row in ports for part in row.fragments for definition in part.definition_ids}
    assert all(replay.memory_ssa.definitions[index].kind is MemoryDefinitionKind.ENTRY
               for row in ports for part in row.fragments for index in part.definition_ids)
    assert not replay.assumes_readonly_image_constant
    found, _ = probe(replay, claim.read, claim.spans)
    assert all(value is None for value in found.values())  # original stack alias still active
    result = SimpleNamespace(unit=original.unit, normalized=replay, key=ROOT, declared={},
                             inherited_assumptions=frozenset(), proven={})
    assert refinement.prepare_memory_refinement(result, options) is None  # no self authorization


@pytest.mark.parametrize("globals_disjoint", (False, True))
def test_only_existing_named_global_stack_policy_can_remove_the_stack_alias(globals_disjoint):
    _, _, plan, replay = _replay(options={"assume_globals_disjoint_from_stack": globals_disjoint})
    read = plan.address_reads[0].read
    aliases = [row for row in replay.may_alias_reads if row.operation_key == read]
    assert bool(aliases) is not globals_disjoint
    assert bool(replay.assumes_globals_disjoint_from_stack) is globals_disjoint


def test_candidate_specific_writers_and_partial_overwrite_all_remain_sources():
    prefix = (store(const(TABLE), const(0x1122334455667788)),
              store(const(TABLE + 3), const(0xAB, 1)))
    _, _, plan, replay = _replay(prefix=prefix)
    ports = _ports(replay, plan.address_reads[0].read)
    assert len(ports) == 16
    writers = {}
    for row in ports:
        definitions = {replay.memory_ssa.definitions[index] for part in row.fragments for index in part.definition_ids}
        writers[row.span.start] = {definition.operation_key for definition in definitions}
    assert writers[TABLE] == {"1:1000:0:STORE"}
    assert writers[TABLE + 3] == {"1:1000:1:STORE"}
    assert writers[TABLE + 7] == {"1:1000:0:STORE"}
    assert writers[TABLE + 8] == {None}


def test_candidate_join_keeps_both_entry_and_branch_writer_endpoints():
    index, wide, address = tmp(0x100, 4), tmp(0x110), tmp(0x120)
    body = (FunctionBuilder().cbranch("write", reg(RDX, 1)).branch("merge")
            .label("write").ins(store(const(TABLE + 3), const(7, 1)))
            .label("merge").ins(op("INT_AND", [reg(RCX, 4), const(15, 4)], index),
                op("INT_DIV", [index, const(1, 4)], index), op("INT_ZEXT", [index], wide),
                add(address, wide, const(TABLE))).ins(load(reg(RAX, 1), address)).ret())
    original, options, plan = _baseline(body)
    assert plan is not None and len(plan.address_reads) == 1
    replay = FunctionNormalizer().normalize(original.unit, **options, _forward_memory_plan=plan)
    (port,) = [row for row in _ports(replay, plan.address_reads[0].read) if row.span.start == TABLE + 3]
    (join,) = port.fragments[0].definition_ids
    assert replay.memory_ssa.definitions[join].kind is MemoryDefinitionKind.JOIN
    sources = next(row.source_definition_ids for row in replay.memory_ssa.joins if row.join_definition_id == join)
    assert {replay.memory_ssa.definitions[index].kind for index in sources} == {
        MemoryDefinitionKind.DATA_WRITE, MemoryDefinitionKind.ENTRY}


@pytest.mark.parametrize("identical", (False, True))
def test_output_consumers_never_choose_first_candidate_or_concatenate_them(identical):
    from tdo_v2.forward import _analyze
    from tdo_v2.interprocedural import analyze_units
    from tdo_v2.operation_records import evaluate, root_record

    values = [7] * 16 if identical else list(range(1, 17))
    unit, = program_units(_body(prefix=tuple(store(const(TABLE + index), const(value, 1))
                                             for index, value in enumerate(values))))
    result = analyze_units((unit,), assume_globals_disjoint_from_stack=True)[ROOT]
    normalized = result.normalized
    read = normalized.forward_inputs.read_separations.address_reads[0].read
    definition = next(index for index, row in enumerate(normalized.memory_ssa.definitions)
                      if row.kind is MemoryDefinitionKind.DATA_WRITE and row.operation_key == read)
    output = normalized.memory_ssa.definitions[definition].span
    terminal = next(row.operation_key for row in normalized.memory_ssa.actions
                    if row.operation_key.endswith(":RETURN"))
    found, _ = _analyze(normalized, unit).bind(terminal, (output,))
    assert found[output].is_top or identical and found[output].single_number() == 7
    runs = [run for exit in result.summary.exits for run in exit.runs if run.span == output]
    assert runs and all(run.literal is None or identical and run.literal.unsigned == 7 for run in runs)
    record = root_record(normalized, unit, [(normalized.memory_graph.definition_nodes[definition], None)])
    node = next(row for row in record["nodes"] if row.get("key") == read)
    assert node["output"]["size"] == 1 and len(node["memory"]) == 16
    # The existing record evaluator conservatively unions address choices.
    # An equal value may collapse; different values must never select one.
    allowed = evaluate(record, lambda node: 0)
    assert allowed == set(values)


def test_unknown_writer_and_address_taint_are_not_discharged_by_the_union():
    original, _, plan, replay = _replay(opaque=True, tainted=True)
    read = plan.address_reads[0].read
    assert replay.memory_ssa.unresolved_writes == original.normalized.memory_ssa.unresolved_writes
    assert any(row.operation_key == read and row.writers for row in replay.may_alias_reads)
    assert any(row.operation_key.endswith(":LOAD") and row.operation_key != read
               for row in replay.may_alias_reads)  # upstream address producer's debt remains
    before = _effect(original.normalized, read)
    assert _effect(replay, read).reads[0] == before.reads[0]


def test_one_opaque_candidate_keeps_its_original_debt_among_clean_entries():
    from test_forward_memory_refinement import _options
    from tdo_v2.call_summary_effects import AnchoredSpan, ProvenCallEffect, StackRestoration
    from tdo_v2.operation_records import root_record
    from tdo_v2.span_geometry import ByteSpan, StorageObjectId

    index, wide, address = tmp(0x100, 4), tmp(0x110), tmp(0x120)
    body = (FunctionBuilder().call(0x1400).ins(
        op("INT_AND", [reg(RCX, 4), const(15, 4)], index),
        op("INT_DIV", [index, const(1, 4)], index), op("INT_ZEXT", [index], wide),
        add(address, wide, const(TABLE))).ins(load(reg(RAX, 1), address)).ret())
    unit, = program_units(body)
    span = ByteSpan(StorageObjectId(StorageObjectKind.ADDRESS_SPACE, unit.scopes.program.scope, 1), TABLE + 3, 1)
    effect = ProvenCallEffect("1:1400", (), (), preserves_memory=True, observes_registers=False,
        stack_restoration=StackRestoration.PROVEN, unknown_memory=(AnchoredSpan(None, 0, 1, 1, span),))
    options = {**_options(), "proven_call_effects": {"1:1000:2:CALL": effect},
               "assume_globals_disjoint_from_stack": True}
    baseline = FunctionNormalizer().normalize(unit, **options)
    source = SimpleNamespace(unit=unit, normalized=baseline, key=ROOT, declared={}, proven={},
                             inherited_assumptions=frozenset())
    plan = refinement.prepare_memory_refinement(source, options)
    assert plan is not None and len(plan.address_reads) == 1
    replay = FunctionNormalizer().normalize(unit, **options, _forward_memory_plan=plan)
    read = plan.address_reads[0].read
    ports = _ports(replay, read)
    assert len(ports) == 16
    opaque = [row for row in ports if row.span.start == TABLE + 3]
    assert len(opaque) == 1
    assert {replay.memory_ssa.definitions[index].operation_key
            for part in opaque[0].fragments for index in part.definition_ids} == {"1:1000:2:CALL~u0"}
    assert all(replay.memory_ssa.definitions[index].kind is MemoryDefinitionKind.ENTRY
               for row in ports if row.span.start != TABLE + 3
               for part in row.fragments for index in part.definition_ids)
    definition = next(index for index, row in enumerate(replay.memory_ssa.definitions)
                      if row.kind is MemoryDefinitionKind.DATA_WRITE and row.operation_key == read)
    record = root_record(replay, unit, [(replay.memory_graph.definition_nodes[definition], None)])
    assert replay.opaque_nodes and any(row["kind"] == "debt" for row in record["nodes"])


@pytest.mark.parametrize("changes", ({"mask": 127}, {"width": 17},
                                     {"base": (1 << 64) - 8, "width": 2}))
def test_large_or_wrapping_domains_are_not_partially_projected(changes):
    _, _, plan = _baseline(_body(**changes))
    assert plan is None or not plan.address_reads


@pytest.mark.parametrize("change", ("omit_candidate", "width", "fact", "read"))
def test_partial_or_changed_baseline_claim_is_refused(change):
    original, options, plan, _ = _replay()
    claim = plan.address_reads[0]
    changed = {
        "omit_candidate": replace(claim, spans=claim.spans[:-1]),
        "width": replace(claim, spans=tuple(replace(span, size=2) for span in claim.spans)),
        "fact": replace(claim, read_fact=replace(claim.read_fact, context=("foreign",))),
        "read": replace(claim, read="1:1:0:LOAD"),
    }[change]
    forged = replace(plan, address_reads=(changed,))
    with pytest.raises(refinement.RefinementRefused):
        forged.verify()
    with pytest.raises(refinement.RefinementRefused):
        FunctionNormalizer().normalize(original.unit, **options, _forward_memory_plan=forged)
