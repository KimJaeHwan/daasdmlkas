"""N0-bound memory separation plans: replay, refusal and byte geometry."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from graph_oracle import check
from synthetic import (
    CODE_BASE, RAM, RAX, RCX, RDI, RDX, RSP, FunctionBuilder, add, const, load, op,
    program_units, reg, store, tmp,
)
from tdo_v2 import _forward_memory as refinement
from tdo_v2.forward import Interval, Value, forward_facts, probe
from tdo_v2.interprocedural import analyze_units
from tdo_v2.may_alias import derive_may_alias_reads
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction


ROOT, READ, WRITER = "1:1000", "1:1010:0:LOAD", "1:100c:4:STORE"


@pytest.fixture(autouse=True)
def forward_on(monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")


def _body(*, displacement=0x10, mask=3, base=RSP, width=4, extra_read=False):
    index, wide, address, slot = tmp(0x100, 4), tmp(0x110), tmp(0x120), tmp(0x130)
    initial = op("INT_AND", [reg(RCX, 4), const(mask, 4)], index) if mask is not None else \
        op("COPY", [reg(RCX, 4)], index)
    builder = (FunctionBuilder().sub_rsp(0x40)
               .ins(initial, add(slot, reg(RSP), const(0x30)), store(slot, index))
               .ins(load(reg(RCX, 4), slot))
               .ins(op("INT_SEXT", [reg(RCX, 4)], wide), op("INT_MULT", [wide, const(4)], address),
                    add(address, address, reg(base)), add(address, address, const(displacement)),
                    store(address, reg(RDX, width)))
               .ins(load(reg(RAX, 4), slot)))
    if extra_read:
        builder.ins(op("INT_MULT", [reg(RDI), reg(RDI)], address), load(reg(RAX), address))
    return builder.add_rsp(0x40).ret()


def _options(**changes):
    return dict(assumed_call_effects={}, proven_call_effects={}, assume_globals_disjoint_from_stack=False,
                readonly_image=None, assume_direction_flag_clear=False, private_frame_above=0,
                open_conditions={}, **changes)


def _baseline(builder=None, **options):
    (unit,) = program_units(builder or _body())
    selected = _options()
    selected.update(options)
    normalized = FunctionNormalizer().normalize(unit, **selected)
    assert isinstance(normalized, NormalizedFunction)
    result = SimpleNamespace(unit=unit, normalized=normalized, key=ROOT, declared={},
                             inherited_assumptions=frozenset(), proven={})
    return result, selected, refinement.prepare_memory_refinement(result, selected)


def _target(plan):
    return [] if plan is None else [proof for proof in plan.proofs if (proof.read, proof.writer) == (READ, WRITER)]


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_full_baseline_proof_removes_only_the_disjoint_writer(engine, monkeypatch):
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    original, options, plan = _baseline()
    (proof,) = _target(plan)
    assert proof.span.size == 4
    assert plan.bind(original.unit, options) == plan.proofs
    plan.verify()
    replay = FunctionNormalizer().normalize(original.unit, **options, _forward_memory_plan=plan)
    assert replay.forward_memory_proofs == plan.proofs
    assert any(row.operation_key == READ and WRITER in row.plain for row in original.normalized.may_alias_reads)
    assert all(WRITER not in row.writers for row in replay.may_alias_reads if row.operation_key == READ)
    report = check(replay, original.unit.observation, seeds=range(8), register_pools=lambda seed: {
        RSP: 0x70000000, RCX: seed, RDX: 0x12345678 + seed})
    assert report.runs == 8 and report.checked and not report.silent and not report.opaque_opcodes


@pytest.mark.parametrize("change", (
    {"assume_globals_disjoint_from_stack": True}, {"private_frame_above": 0x28},
    {"assume_direction_flag_clear": True}, {"readonly_image": object()},
    {"assumed_call_effects": {"changed": object()}}, {"proven_call_effects": {"changed": object()}},
    {"open_conditions": {"changed": object()}},
))
def test_changed_normalization_policy_cannot_reuse_a_plan(change):
    original, options, plan = _baseline()
    assert plan is not None
    with pytest.raises(refinement.RefinementRefused):
        plan.bind(original.unit, {**options, **change})
    with pytest.raises(refinement.RefinementRefused):
        FunctionNormalizer().normalize(original.unit, **{**options, **change}, _forward_memory_plan=plan)


def test_identical_observation_in_another_batch_is_not_the_same_plan_activation():
    original, options, plan = _baseline()
    (another,) = program_units(_body())
    assert another is not original.unit
    assert another.observation == original.unit.observation
    with pytest.raises(refinement.RefinementRefused):
        plan.bind(another, options)
    changed, = program_units(_body(mask=7))
    with pytest.raises(refinement.RefinementRefused):
        FunctionNormalizer().normalize(changed, **options, _forward_memory_plan=plan)


@pytest.mark.parametrize("field", ("id", "claim", "operation", "function", "input", "context", "requires",
                                    "writer", "read", "span"))
def test_full_proof_tampering_is_rejected_at_every_consumer(field):
    original, options, plan = _baseline()
    proof = plan.proofs[0]
    fact = proof.write_fact
    if field in ("writer", "read"):
        altered = replace(proof, **{field: "1:1:0:STORE" if field == "writer" else "1:1:0:LOAD"})
    elif field == "span":
        altered = replace(proof, span=replace(proof.span, start=proof.span.start + 1))
    else:
        changes = {"id": "not-the-baseline-id", "claim": Value.top(64), "operation": READ,
                   "function": "1:2000", "input": 2, "context": (ROOT, "1:1000:0:CALL"),
                   "requires": ("forged-assumption",)}
        altered = replace(proof, write_fact=replace(fact, **{field: changes[field]}))
    forged = replace(plan, proofs=(altered, *plan.proofs[1:]))
    for consume in (
        forged.verify, lambda: forged.bind(original.unit, options),
        lambda: refinement.exclusions_for(forged, original.normalized.forward_inputs.effect_unit),
        lambda: FunctionNormalizer().normalize(original.unit, **options, _forward_memory_plan=forged),
    ):
        with pytest.raises(refinement.RefinementRefused):
            consume()


@pytest.mark.parametrize("case", (
    {"displacement": 0x30}, {"displacement": 0x2E}, {"base": RDI}, {"mask": None}, {"mask": 15},
    {"width": 32},
))
def test_overlap_different_base_top_and_local_bounds_do_not_discharge(case):
    original, _, plan = _baseline(_body(**case))
    assert any(row.operation_key == READ for row in original.normalized.may_alias_reads)
    assert not _target(plan)


def test_a_32_bit_memory_space_is_not_a_64_bit_separation():
    original, options, plan = _baseline()
    assert _target(plan)
    inputs = original.normalized.forward_inputs
    spaces = tuple(replace(space, address_size_bits=32) if space.space_id == RAM else space
                   for space in inputs.address_spaces)
    narrowed = replace(original.normalized, forward_inputs=replace(inputs, address_spaces=spaces))
    assert not _target(refinement.prepare_memory_refinement(
        SimpleNamespace(unit=original.unit, key=ROOT, normalized=narrowed, declared={},
                        inherited_assumptions=frozenset(), proven={}), options))


def test_modular_byte_footprints_keep_wrapping_bytes():
    _, _, plan = _baseline()
    fact = plan.proofs[0].write_fact
    mask = (1 << 64) - 1
    wrapping = replace(fact, claim=Value(64, ((("entry", RSP, 8), Interval.offset(-2, 64)),)))
    assert refinement._offsets(wrapping, 4) == (("entry", RSP, 8), frozenset((mask - 1, mask, 0, 1)))
    assert refinement._offsets(wrapping, 17) is None
    wide = replace(wrapping, claim=Value(64, ((("entry", RSP, 8), Interval(-4, 4, 1, 64, True)),)))
    assert refinement._offsets(wide, 1) is None  # nine candidates exceed MAX_CANDIDATES


def test_n0_assumptions_survive_replay_facts_and_existing_probe():
    original, options, _ = _baseline()
    labels = ("external-model:test-original-only@v1", "n0-policy-only")
    plan = refinement.prepare_memory_refinement(original, options, assumptions=labels)
    assert set(labels) <= set(plan.requires)
    replay = FunctionNormalizer().normalize(original.unit, **options, _forward_memory_plan=plan)
    assert set(plan.requires) <= set(replay.forward_memory_requires)
    assert all(set(labels) <= set(fact.requires) for fact in forward_facts(replay, original.unit))
    (proof,) = _target(plan)
    found, requires = probe(replay, READ, (proof.span,))
    assert found[proof.span] is not None
    assert set(labels) <= set(requires)
    result = SimpleNamespace(key=ROOT, unit=original.unit, normalized=replay, declared={},
                             inherited_assumptions=frozenset(), proven={})
    assert refinement.prepare_memory_refinement(result, options) is None  # N1 cannot authorize another replay


def test_unknown_read_is_not_discharged_by_a_plain_write_proof():
    original, options, plan = _baseline(_body(extra_read=True))
    assert _target(plan)
    unknown = {row.operation_key for row in original.normalized.may_alias_reads if row.unknown_address}
    assert unknown
    replay = FunctionNormalizer().normalize(original.unit, **options, _forward_memory_plan=plan)
    assert unknown <= {row.operation_key for row in replay.may_alias_reads if row.unknown_address}


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_plain_exclusion_never_removes_the_same_writers_uncertain_effect(engine, monkeypatch):
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    original, _, plan = _baseline()
    inputs = original.normalized.forward_inputs
    rows = derive_may_alias_reads(
        inputs.effect_unit, inputs.observation, inputs.context, inputs.address_spaces,
        uncertain_writers=frozenset({WRITER}), read_separations=plan)
    (row,) = [row for row in rows if row.operation_key == READ]
    assert WRITER in row.writers and WRITER in row.uncertain
    assert WRITER not in row.plain


@pytest.mark.parametrize("policy", ("ENTRY_VALUES_NOT_FRAME", "OPAQUE_NO_STACK_ADDRESSES"))
def test_changed_ambient_alias_policy_refuses_the_original_plan(policy):
    from tdo_v2 import may_alias

    original, options, plan = _baseline()
    variable = getattr(may_alias, policy)
    token = variable.set(not variable.get())
    try:
        with pytest.raises(refinement.RefinementRefused):
            plan.bind(original.unit, options)
        with pytest.raises(refinement.RefinementRefused):
            refinement.exclusions_for(plan, original.normalized.forward_inputs.effect_unit)
    finally:
        variable.reset(token)


def test_n0_model_label_is_inherited_without_a_caller_resupplying_it():
    original, options, _ = _baseline()
    original.declared = {"1:1000:0:CALL": "external-model:n0-only@v1"}
    original.inherited_assumptions = frozenset({"callee-n0-only"})
    plan = refinement.prepare_memory_refinement(original, options)
    labels = {"external-model:n0-only@v1", "callee-n0-only"}
    assert labels <= set(plan.requires)
    replay = FunctionNormalizer().normalize(original.unit, **options, _forward_memory_plan=plan)
    assert all(labels <= set(fact.requires) for fact in forward_facts(replay, original.unit))
    (proof,) = _target(plan)
    _, requires = probe(replay, READ, (proof.span,))
    assert labels <= set(requires)


def test_removing_an_assumption_from_every_copied_claim_still_fails_source_n0_validation():
    original, options, _ = _baseline()
    label = "external-model:load-bearing-n0@v1"
    original.declared = {"1:1000:0:CALL": label}
    plan = refinement.prepare_memory_refinement(original, options, assumptions=(label,))
    assert all(label in fact.requires for proof in plan.proofs for fact in (proof.read_fact, proof.write_fact))

    def stripped(labels):
        return tuple(item for item in labels if item != label)

    forged = replace(plan, requires=stripped(plan.requires), assumptions=stripped(plan.assumptions), proofs=tuple(
        replace(proof, read_fact=replace(proof.read_fact, requires=stripped(proof.read_fact.requires)),
                write_fact=replace(proof.write_fact, requires=stripped(proof.write_fact.requires)))
        for proof in plan.proofs))
    with pytest.raises(refinement.RefinementRefused):
        forged.verify()
    with pytest.raises(refinement.RefinementRefused):
        FunctionNormalizer().normalize(original.unit, **options, _forward_memory_plan=forged)


@pytest.mark.parametrize("change", ("read", "writer", "scope"))
def test_consumer_refuses_an_effect_unit_missing_the_original_occurrence(change):
    original, _, plan = _baseline()
    unit = original.normalized.forward_inputs.effect_unit
    if change == "scope":
        foreign, _, _ = _baseline(_body(mask=7))
        changed = foreign.normalized.forward_inputs.effect_unit
    else:
        key = READ if change == "read" else WRITER
        blocks = tuple(replace(block, effects=tuple(replace(effect, operation_key=effect.operation_key + "~changed")
                       if effect.operation_key == key else effect for effect in block.effects))
                       for block in unit.blocks)
        changed = replace(unit, blocks=blocks)
    with pytest.raises(refinement.RefinementRefused):
        refinement.exclusions_for(plan, changed)


def test_mutating_the_original_result_after_planning_invalidates_the_plan():
    original, options, plan = _baseline()
    original.inherited_assumptions = frozenset({"new-assumption-after-n0"})
    with pytest.raises(refinement.RefinementRefused):
        plan.bind(original.unit, options)


def test_forward_off_and_optional_proof_cap_keep_n0(monkeypatch):
    units = program_units(_body())
    monkeypatch.setenv("TDO_V2_FORWARD", "0")
    off = analyze_units(units)[ROOT]
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setattr(refinement, "MAX_PROOFS", 0)
    capped = analyze_units(units)[ROOT]
    assert not capped.normalized.forward_memory_proofs
    assert capped.normalized.memory_ssa == off.normalized.memory_ssa
    assert capped.normalized.may_alias_reads == off.normalized.may_alias_reads
    assert capped.summary == off.summary


def test_replay_refusal_keeps_the_entire_original_summary_and_provenance(monkeypatch):
    units = program_units(_body())
    monkeypatch.setenv("TDO_V2_FORWARD", "0")
    old_provenance = {}
    off = analyze_units(units, record_provenance=old_provenance)[ROOT]
    original = FunctionNormalizer.normalize
    attempted = []

    def refuse(self, unit, **options):
        if options.get("_forward_memory_plan") is not None:
            attempted.append(unit)
            raise refinement.RefinementRefused("test replay refusal")
        return original(self, unit, **options)

    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setattr(FunctionNormalizer, "normalize", refuse)
    provenance = {}
    result = analyze_units(units, record_provenance=provenance)[ROOT]
    assert attempted == units
    assert result.summary == off.summary
    assert result.normalized.memory_ssa == off.normalized.memory_ssa
    assert result.normalized.may_alias_reads == off.normalized.may_alias_reads
    assert not result.normalized.forward_memory_proofs
    assert set(provenance) == {id(result)}
    assert provenance[id(result)][0] is result
    assert provenance[id(result)][1] == old_provenance[id(off)][1]


@pytest.mark.parametrize("scope", ("function", "run"))
def test_replay_budget_exhaustion_is_a_typed_failure_not_optional_fallback(monkeypatch, scope):
    from tdo_v2.resource_limits import AnalysisBudgetExceeded
    from tdo_v2.normalize import NormalizationFailureReason, UnresolvedNormalizedFunction

    units = program_units(_body())
    normalize = FunctionNormalizer.normalize
    attempts = []

    def exhausted(self, unit, **options):
        if options.get("_forward_memory_plan") is not None:
            attempts.append(unit)
            raise AnalysisBudgetExceeded("work", "refinement-test", scope=scope)
        return normalize(self, unit, **options)

    monkeypatch.setattr(FunctionNormalizer, "normalize", exhausted)
    provenance = {}
    result = analyze_units(units, record_provenance=provenance)[ROOT]
    assert attempts == units
    assert isinstance(result.normalized, UnresolvedNormalizedFunction)
    expected = NormalizationFailureReason.ANALYSIS_BUDGET if scope == "function" else \
        NormalizationFailureReason.ANALYSIS_RUN_BUDGET
    assert result.normalized.reason is expected
    assert result.summary is None and not provenance


@pytest.mark.parametrize("kind", ("self", "mutual"))
def test_recursive_components_do_not_even_prepare_memory_refinement(kind, monkeypatch):
    calls = []
    prepare = refinement.prepare_memory_refinement

    def counted(result, *args, **options):
        calls.append(result.key)
        return prepare(result, *args, **options)

    monkeypatch.setattr(refinement, "prepare_memory_refinement", counted)
    other = CODE_BASE + 0x800
    root = FunctionBuilder().sub_rsp(0x28).call(CODE_BASE if kind == "self" else other).add_rsp(0x28).ret()
    functions = [root] if kind == "self" else [
        root, FunctionBuilder(entry=other).sub_rsp(0x28).call(CODE_BASE).add_rsp(0x28).ret()]
    results = analyze_units(program_units(*functions))
    assert results and not calls
    assert all(not row.normalized.forward_memory_proofs for row in results.values())


def test_a_multi_target_self_edge_skips_refinement_after_the_edge_is_discovered(monkeypatch):
    import test_multi_target_calls as tables
    from tdo_v2.interprocedural import _forward_targets

    other = CODE_BASE + 0x800
    monkeypatch.setattr(tables, "A", CODE_BASE)
    monkeypatch.setattr(tables, "B", other)
    calls = []
    prepare = refinement.prepare_memory_refinement

    def counted(result, *args, **options):
        calls.append(result.key)
        return prepare(result, *args, **options)

    monkeypatch.setattr(refinement, "prepare_memory_refinement", counted)
    results = analyze_units(program_units(tables._table(), tables._returns(other, 1)))
    targets, _ = _forward_targets(results[ROOT], results, None)
    assert next(iter(targets.values())) == (ROOT, f"1:{other:x}")
    assert calls.count(ROOT) == 1  # first unresolved round only; discovered self-edge makes later rounds recursive
    assert calls.count(f"1:{other:x}") >= 2
    assert not results[ROOT].normalized.forward_memory_proofs
