"""Opt-in allocation evidence at the original memory-SSA consumers.

The contracts are test-only, symbol-specific Win64 profiles.  These checks
never treat allocation identity as a numeric address fact or a legacy free.
"""

from dataclasses import replace

import pytest

from synthetic import (RBX, RCX, RDI, RDX, RSI, RSP, add,
                       const, copy, load, program_units, reg, store, tmp)
from test_allocation_lifetime import FLAG, _begin, _contracts, _finish, _guard, _key, without_allocator_windows
from test_external_models import MODELS, THUNKS, _image
from tdo_v2._allocation_lifetime import AllocationAnalysis
from tdo_v2._allocation_memory import prepare_allocation_refinement
from tdo_v2._forward_memory import RefinementRefused
from tdo_v2.effects import UnresolvedMemoryAccess
from tdo_v2.forward import probe
from tdo_v2.interprocedural import analyze_units
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.normalize import NormalizationFailureReason
from tdo_v2.resource_limits import last_run
from tdo_v2.summary_store import load_external_models
from tdo_v2.summary_templates import TemplateRefused, export_summary


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def engines(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_FORWARD", "1")


@pytest.fixture(scope="module")
def models():
    return without_allocator_windows(load_external_models(MODELS, "x86:LE:64:default", "win64"))


def _case(*, heap_offset=0, heap_width=4, guarded=True, after=None, before=None,
          save_width=8, load_width=8):
    builder, allocation = _begin()
    if guarded:
        _guard(builder)
    slot = tmp(0x100)
    saved = _key(builder, 1, "STORE")
    builder.ins(add(slot, reg(RSP), const(0x30)), store(slot, reg(RBX, save_width)))
    if before is not None:
        before(builder)
    if heap_offset:
        builder.ins(add(reg(RDI), reg(RBX), const(heap_offset)))
    else:
        builder.ins(copy(reg(RDI), reg(RBX)))
    heap = _key(builder, 0, "STORE")
    builder.ins(store(reg(RDI), const(0x12345678, heap_width)))
    builder.ins(copy(reg(RCX), reg(RBX)), copy(reg(RDX), const(16)))
    resize = _key(builder, 2, "CALL")
    builder.call(THUNKS["realloc"])
    if after is not None:
        after(builder)
    reader = _key(builder, 1, "LOAD")
    builder.ins(add(slot, reg(RSP), const(0x30)), load(reg(RDI, load_width), slot))
    return _finish(builder), dict(allocation=allocation, saved=saved, heap=heap,
                                  resize=resize, reader=reader)


def _run(builder, models, contracts):
    result = analyze_units(
        program_units(builder), image_info=_image(), external_models=models,
        lifecycle_contracts=contracts, private_frame_above=40,
        assume_globals_disjoint_from_stack=True,
        assume_entry_values_not_frame=False,
        assume_opaque_callees_leave_no_stack_addresses=False,
    )
    return result["1:1000"]


def _read(item, key):
    return next(read for read in item.normalized.memory_ssa.reads
                if item.normalized.memory_ssa.actions[read.action_id].operation_key == key
                and read.span.object_id.kind.value in ("function_relative", "address_space"))


def _debt(item, points):
    return next((row for row in item.normalized.may_alias_reads
                 if row.operation_key == points["reader"] and points["heap"] in row.plain), None)


def test_optin_removes_heap_store_then_resize_call_debt_without_losing_saved_writer(models):
    builder, points = _case()
    contracts = _contracts(models, resize=True)
    default = _run(builder, models, ())
    refined = _run(builder, models, contracts)
    assert _debt(default, points) is not None
    assert any(row.operation_key == points["reader"] and points["resize"] in row.intervening_calls
               for row in default.normalized.call_clobber_reads)
    assert _debt(refined, points) is None
    assert any(proof.read == points["reader"] and proof.writer == points["heap"]
               and isinstance(proof.read_fact, tuple) and proof.write_fact.live
               for proof in refined.normalized.forward_memory_proofs)
    assert any(decision.preserved and decision.demand.reader == points["reader"]
               and decision.demand.call == points["resize"]
               for decision in refined.call_memory_decisions)
    assert not any(row.operation_key == points["reader"] and points["resize"] in row.intervening_calls
                   for row in refined.normalized.call_clobber_reads)
    read = _read(refined, points["reader"])
    found, requires = probe(refined.normalized, points["reader"], (read.span,))
    assert found[read.span] is not None
    assert refined.normalized.memory_ssa.definitions[found[read.span]].operation_key == points["saved"]
    assert any(label.startswith("lifecycle-contract:") for label in requires)
    assert set(refined.normalized.forward_memory_requires) <= set(requires)
    assert set(refined.normalized.forward_memory_requires) <= set(refined.inherited_assumptions)
    # 2b-P B8: an accepted refinement's requirements are use records
    used = {name for name, stage, _ in refined.normalized.premise_uses if stage == "refinement"}
    assert any(label.startswith("lifecycle-contract:") for label in used), used
    allocation, _ = _allocation_source(refined)
    assert set(allocation.requires) <= set(refined.normalized.forward_memory_requires)
    assert all(set(decision.requires) <= set(refined.normalized.forward_memory_requires)
               for decision in refined.call_memory_decisions if decision.preserved)
    assert all(not hasattr(proof.write_fact, "claim") for proof in refined.normalized.forward_memory_proofs
               if isinstance(proof.read_fact, tuple))


def test_default_empty_and_forward_off_do_not_consume_allocation_contracts(models, monkeypatch):
    builder, points = _case()
    contracts = _contracts(models, resize=True)
    baseline = _run(builder, models, ())
    assert not any(isinstance(row.read_fact, tuple) for row in baseline.normalized.forward_memory_proofs)
    assert _debt(baseline, points) is not None
    monkeypatch.setenv("TDO_V2_FORWARD", "0")
    off = _run(builder, models, contracts)
    assert not any(isinstance(row.read_fact, tuple) for row in off.normalized.forward_memory_proofs)
    assert not off.call_memory_decisions
    assert _debt(off, points) is not None


@pytest.mark.parametrize("heap_offset,heap_width", ((5, 4), (0, 16)))
def test_outside_owned_extent_keeps_original_store_debt(models, heap_offset, heap_width):
    builder, points = _case(heap_offset=heap_offset, heap_width=heap_width)
    refined = _run(builder, models, _contracts(models, resize=True))
    assert _debt(refined, points) is not None
    assert not any(proof.writer == points["heap"] for proof in refined.normalized.forward_memory_proofs)


def test_nullable_allocation_without_guard_keeps_store_debt(models):
    builder, points = _case(guarded=False)
    refined = _run(builder, models, _contracts(models, resize=True))
    assert _debt(refined, points) is not None
    assert not any(proof.writer == points["heap"] for proof in refined.normalized.forward_memory_proofs)


def test_nonmemory_space_selector_cannot_be_excluded_as_heap_store(models):
    builder, points = _case()
    _, address, ordinal, _ = points["heap"].split(":")
    row = builder._rows[(int(address, 16) - builder.entry) // builder.stride]
    code, inputs, output = row.ops[int(ordinal)]
    assert code == "STORE"
    row.ops[int(ordinal)] = (code, [const(2), *inputs[1:]], output)  # register space, not RAM
    refined = _run(builder, models, _contracts(models, resize=True))
    assert not any(proof.writer == points["heap"] for proof in refined.normalized.forward_memory_proofs)


@pytest.mark.parametrize("error", ("wrong-symbol", "wrong-digest"))
def test_unmatched_contract_cannot_remove_store_or_call_debt(models, error):
    builder, points = _case()
    contracts = tuple(replace(contract, **({"symbol_names": ("not-" + contract.symbol_names[0],)}
                                            if error == "wrong-symbol" else {"model_digest": "0" * 64}))
                      for contract in _contracts(models, resize=True))
    refined = _run(builder, models, contracts)
    assert _debt(refined, points) is not None
    assert not refined.call_memory_decisions


def test_plan_rejects_contract_mutation_and_reader_snapshot_change(models):
    builder, points = _case()
    refined = _run(builder, models, _contracts(models, resize=True))
    plan = refined.normalized.forward_inputs.read_separations
    assert plan is not None
    plan.verify()
    with pytest.raises(RefinementRefused):
        replace(plan, contracts=()).verify()
    with pytest.raises(RefinementRefused):
        replace(plan, source=replace(plan.source, allocation_contracts=())).verify()
    source_reader = tuple((key, object() if key == "readonly_image" else value)
                          for key, value in plan.source.normalization_options)
    with pytest.raises(RefinementRefused):
        replace(plan, source=replace(plan.source, normalization_options=source_reader)).verify()
    changed_reader = tuple((key, object() if key == "readonly_image" else value)
                           for key, value in plan.options)
    assert changed_reader != plan.options
    with pytest.raises(RefinementRefused):
        replace(plan, options=changed_reader).verify()
    with pytest.raises(RefinementRefused):
        replace(plan, signature=(*plan.signature[:-1], object())).verify()


def _allocation_source(item):
    plan = item.normalized.forward_inputs.read_separations
    while plan is not None and plan.evidence_kind != "allocation":
        plan = plan.source.normalized.forward_inputs.read_separations
    assert plan is not None
    return plan, plan.source


@pytest.mark.parametrize("defect", ("explicit-none-override", "unresolved-read", "unresolved-write",
                                     "mismatched-write-width", "unknown-read-address"))
def test_optional_consumer_never_excludes_a_disputed_original_effect(models, defect):
    builder, points = _case()
    refined = _run(builder, models, _contracts(models, resize=True))
    plan, source = _allocation_source(refined)
    assert any(proof.writer == points["heap"] for proof in plan.proofs)
    normalized = source.normalized
    if defect == "explicit-none-override":
        normalized = replace(normalized, operation_overrides=(*normalized.operation_overrides,
                                                               (points["heap"], None)))
    elif defect == "unknown-read-address":
        debts = tuple(replace(row, unknown_address=True, spans=())
                      if row.operation_key == points["reader"] else row
                      for row in normalized.may_alias_reads)
        normalized = replace(normalized, may_alias_reads=debts)
    else:
        effects = []
        for row in normalized.effects:
            if row.operation_key == (points["reader"] if defect == "unresolved-read" else points["heap"]):
                if defect == "unresolved-read":
                    row = replace(row, unresolved_reads=(UnresolvedMemoryAccess(None, 8),))
                elif defect == "unresolved-write":
                    row = replace(row, unresolved_writes=(UnresolvedMemoryAccess(None, 4),))
                else:
                    (written,) = [value for value in row.writes
                                  if hasattr(value, "span") and value.span.object_id.kind.value in
                                  ("function_relative", "address_space")]
                    row = replace(row, writes=tuple(replace(value, span=replace(value.span, size=8))
                                                    if value is written else value for value in row.writes))
            effects.append(row)
        normalized = replace(normalized, effects=tuple(effects))
    candidate = replace(source, normalized=normalized)
    assert prepare_allocation_refinement(candidate, dict(plan.options)) is None
    with pytest.raises(RefinementRefused):
        replace(plan, source=candidate).verify()


def test_unknown_free_argument_or_one_arm_release_keeps_store_debt(models):
    def unknown_free(builder):
        builder.ins(copy(reg(RCX), reg(RSI))).call(THUNKS["free"])

    def conditional_free(builder):
        builder.cbranch("skip-free", reg(RSI, 1))
        builder.ins(copy(reg(RCX), reg(RBX))).call(THUNKS["free"])
        builder.label("skip-free")

    for before in (unknown_free, conditional_free):
        builder, points = _case(before=before)
        refined = _run(builder, models, _contracts(models, release=True, resize=True))
        assert _debt(refined, points) is not None
        assert not any(proof.writer == points["heap"] for proof in refined.normalized.forward_memory_proofs)


def test_opaque_call_before_heap_store_keeps_original_debt(models):
    builder, points = _case(before=lambda body: body.call(0x1700))
    refined = _run(builder, models, _contracts(models, resize=True))
    assert _debt(refined, points) is not None
    assert not any(proof.writer == points["heap"] for proof in refined.normalized.forward_memory_proofs)


def test_later_opaque_call_debt_survives_resize_preservation(models):
    builder, points = _case(after=lambda body: body.call(0x1700))
    refined = _run(builder, models, _contracts(models, resize=True))
    assert any(decision.preserved and decision.demand.call == points["resize"]
               for decision in refined.call_memory_decisions)
    assert any(row.operation_key == points["reader"] and any(call != points["resize"]
               for call in row.intervening_calls) for row in refined.normalized.call_clobber_reads)
    read = _read(refined, points["reader"])
    assert probe(refined.normalized, points["reader"], (read.span,))[0][read.span] is None


def test_later_partial_stack_write_join_survives_both_exclusions(models):
    def after(builder):
        builder.cbranch("skip-partial", reg(RSI, 1))
        slot = tmp(0x100)
        builder.ins(add(slot, reg(RSP), const(0x30)), store(slot, const(7, 1)))
        builder.label("skip-partial")

    builder, points = _case(after=after)
    refined = _run(builder, models, _contracts(models, resize=True))
    assert any(decision.preserved and decision.demand.call == points["resize"]
               for decision in refined.call_memory_decisions)
    read = _read(refined, points["reader"])
    assert any(refined.normalized.memory_ssa.definitions[identifier].kind is MemoryDefinitionKind.JOIN
               for fragment in read.fragments for identifier in fragment.definition_ids)
    assert probe(refined.normalized, points["reader"], (read.span,))[0][read.span] is None


def test_optin_lifecycle_analysis_cannot_be_exported_as_generic_template(models):
    builder, _ = _case()
    refined = _run(builder, models, _contracts(models, resize=True))
    with pytest.raises(TemplateRefused, match="opt-in lifecycle evidence"):
        export_summary(refined, {refined.key: refined})


def test_original_run_and_summary_dependencies_reach_lifetime_and_sealed_plan(models):
    builder, points = _case()
    refined = _run(builder, models, _contracts(models, resize=True))
    _, source = _allocation_source(refined)
    run_label, summary_label = "test-original-run-policy", "test-original-summary-input"
    altered = replace(source,
                      inherited_assumptions=source.inherited_assumptions | {run_label},
                      summary_inputs=(source.summary_inputs[0], source.summary_inputs[1],
                                      (*source.summary_inputs[2], summary_label)))
    analysis = AllocationAnalysis(altered, results={altered.key: altered})
    evidence = analysis.access(points["heap"])
    assert evidence is not None and evidence.live
    assert {run_label, summary_label} <= set(evidence.requires)
    plan = prepare_allocation_refinement(altered, dict(altered.normalization_options),
                                         results={altered.key: altered})
    assert plan is not None
    plan.verify()
    assert {run_label, summary_label} <= set(plan.requires)
    assert {run_label, summary_label} <= set(plan.proofs[0].write_fact.requires)


@pytest.mark.parametrize("change", ("source-model", "source-cfg", "source-reader", "peer-model",
                                   "peer-cfg", "peer-reader", "peer-summary-input"))
def test_lifecycle_plan_rejects_changed_original_or_peer_snapshot(models, change):
    builder, _ = _case()
    refined = _run(builder, models, _contracts(models, resize=True))
    allocation_plan, source = _allocation_source(refined)
    plan = prepare_allocation_refinement(source, dict(allocation_plan.options), results={source.key: source})
    assert plan is not None
    plan.verify()
    peer = source
    if change.endswith("model"):
        peer = replace(peer, allocation_models=())
    elif change.endswith("cfg"):
        other_builder, _ = _case(guarded=False)
        other = _run(other_builder, models, _contracts(models, resize=True))
        peer = replace(peer, unit=other.unit, normalized=other.normalized)
    elif change.endswith("reader"):
        changed = tuple((key, object() if key == "readonly_image" else value)
                        for key, value in peer.normalization_options)
        peer = replace(peer, normalization_options=changed)
    else:
        peer = replace(peer, summary_inputs=(peer.summary_inputs[0], peer.summary_inputs[1],
                                                  (*peer.summary_inputs[2], "changed-summary-input")))
    forged = (replace(plan, source=peer) if change.startswith("source")
              else replace(plan, peers=((source.key, peer),)))
    with pytest.raises(RefinementRefused):
        forged.verify()


def test_lifecycle_work_is_charged_and_function_budget_failure_is_typed(models, monkeypatch):
    builder, _ = _case()
    baseline = _run(builder, models, ())
    assert baseline.summary is not None
    baseline_work = last_run().work
    assert baseline_work > 0
    optin = _run(builder, models, _contracts(models, resize=True))
    assert optin.summary is not None
    optin_work = last_run().work
    assert optin_work > baseline_work
    monkeypatch.setenv("TDO_V2_FUNCTION_WORK", str(baseline_work + 8))
    assert _run(builder, models, ()).summary is not None
    capped = _run(builder, models, _contracts(models, resize=True))
    assert capped.normalized.reason is NormalizationFailureReason.ANALYSIS_BUDGET
    assert capped.failure_detail == "function:work" and capped.summary is None


def test_refused_optional_evidence_atomically_keeps_original_graph(models, monkeypatch):
    from tdo_v2 import _allocation_memory
    builder, points = _case()
    baseline = _run(builder, models, ())

    def refuse(*args, **kwargs):
        raise RefinementRefused("unsupported original lifetime input")

    monkeypatch.setattr(_allocation_memory, "prepare_allocation_refinement", refuse)
    monkeypatch.setattr(_allocation_memory, "prepare_allocation_call_refinement", refuse)
    refused = _run(builder, models, _contracts(models, resize=True))
    assert refused.normalized.memory_ssa == baseline.normalized.memory_ssa
    assert refused.normalized.may_alias_reads == baseline.normalized.may_alias_reads
    assert refused.normalized.call_clobber_reads == baseline.normalized.call_clobber_reads
    assert refused.summary == baseline.summary
    assert _debt(refused, points) is not None
    assert not refused.allocation_lifetimes and not refused.call_memory_decisions
