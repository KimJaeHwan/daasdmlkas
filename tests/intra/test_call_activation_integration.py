"""Activation candidates publish atomically and obey the existing hard limits."""

import pytest

from synthetic import FunctionBuilder, program_units
from test_call_activation_lifetime import _case, _run, models
from test_external_models import _image
from test_summary_templates import IMAGE, _every_constant_relocates
from tools.graph_fidelity.semantic_snapshot import encode
from tdo_v2 import _call_activation as activation, resource_limits
from tdo_v2._activation_entry import ACTIVE_ENTRY
from tdo_v2.interprocedural import _ledger_key, analyze_units
from tdo_v2.normalize import FunctionNormalizer, NormalizationFailureReason, UnresolvedNormalizedFunction
from tdo_v2.relative_memory import ImageBaseTracking
from tdo_v2.summary_templates import TemplateRefused, export_summary


@pytest.fixture(autouse=True)
def forward_on(monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    for variable in ("TDO_V2_FUNCTION_WORK", "TDO_V2_RUN_WORK"):
        monkeypatch.delenv(variable, raising=False)


@pytest.mark.parametrize("side", ("caller", "callee"))
@pytest.mark.parametrize("field", ("normalization_options", "normalization_context", "summary_inputs", "lifetime_models"))
def test_original_policy_or_model_mutation_invalidates_the_candidate(models, monkeypatch, side, field):
    result, points = _run(models)
    candidate = result["1:1000"]
    context = candidate.activations[points["outer"]]
    original, callee, *_ = context.activation_witness
    assert activation.revalidate_activation(original, candidate, context)
    target = original if side == "caller" else callee
    if field == "normalization_options":
        changed = dict(target.normalization_options)
        changed["private_frame_above"] += 1
        changed = tuple(changed.items())
    elif field == "normalization_context":
        changed = (not target.normalization_context[0], *target.normalization_context[1:])
    elif field == "summary_inputs":
        changed = (frozenset({"changed-control-cut"}), *target.summary_inputs[1:])
    else:
        changed = () if target.lifetime_models else callee.lifetime_models
    assert changed != getattr(target, field)
    with monkeypatch.context() as patch:
        patch.setattr(target, field, changed)
        assert not activation.revalidate_activation(original, candidate, context)
    assert activation.revalidate_activation(original, candidate, context)


def test_rejected_candidate_matches_whole_original_result_and_provenance(models, monkeypatch):
    before_provenance = {}
    with monkeypatch.context() as patch:
        patch.setattr(activation, "replay_activation", lambda *args, **kwargs: None)
        before, _ = _run(models, record_provenance=before_provenance)
    rejected = []

    def refuse(original, candidate, replay, **options):
        rejected.append((original, candidate, replay))
        return False

    monkeypatch.setattr(activation, "revalidate_activation", refuse)
    provenance = {}
    after, _ = _run(models, record_provenance=provenance)
    assert len(rejected) == 1
    assert encode(after) == encode(before)
    assert set(provenance) == {id(item) for item in after.values()}
    for key, item in after.items():
        assert item.summary == before[key].summary and item.proven == before[key].proven
        assert provenance[id(item)][0] is item
        assert encode(provenance[id(item)][1]) == encode(before_provenance[id(before[key])][1])
    original, candidate, context = rejected[0]
    assert after[original.key] is original
    assert id(candidate) not in provenance and id(context) not in provenance
    assert all(not item.activations and item.normalized.activation_entry is None for item in after.values())


def _watch_stages(patch):
    """Observe existing work counters; do not inject exceptions or change a ledger."""
    events, caller_keys, replayed = [], [], []
    replay = activation.replay_activation
    normalize_entry = activation._normalize
    normalize = FunctionNormalizer.normalize

    def note(stage):
        resource_limits.checkpoint()
        budget = resource_limits.current_run()
        events.append((stage, resource_limits.logical_work(), budget.ledgers[caller_keys[-1]].work))

    def watched_replay(caller, *args, **options):
        caller_keys.append(_ledger_key(caller.unit))
        result = replay(caller, *args, **options)
        if result is not None:
            replayed.append(result)
        return result

    def watched_entry(callee, state, effects=None):
        if state.memory and effects is None:
            note("replay")
        elif effects is not None:
            note("memory")
        return normalize_entry(callee, state, effects)

    def watched_normalize(self, unit, **options):
        if replayed and unit.observation.instructions[0].address.byte_offset == 0x1000:
            note("candidate")
        return normalize(self, unit, **options)

    patch.setattr(activation, "replay_activation", watched_replay)
    patch.setattr(activation, "_normalize", watched_entry)
    patch.setattr(FunctionNormalizer, "normalize", watched_normalize)
    return events, replayed


@pytest.mark.parametrize("stage", ("replay", "memory", "candidate"))
@pytest.mark.parametrize("scope", ("function", "run"))
def test_real_work_limit_during_replay_or_caller_reanalysis_never_publishes_candidate(
        models, monkeypatch, stage, scope):
    # First measure this small program's existing deterministic work ledger,
    # then configure a real environment work limit one unit into the selected
    # stage. Neither AnalysisBudgetExceeded nor a substitute verdict is injected.
    with monkeypatch.context() as patch:
        events, _ = _watch_stages(patch)
        calibration, _ = _run(models)
    assert calibration["1:1000"].activations
    event = next(row for row in events if row[0] == stage)
    limit = event[1 if scope == "run" else 2] + 1
    monkeypatch.setenv("TDO_V2_RUN_WORK" if scope == "run" else "TDO_V2_FUNCTION_WORK", str(limit))
    provenance = {}
    with monkeypatch.context() as patch:
        attempts, contexts = _watch_stages(patch)
        result, _ = _run(models, record_provenance=provenance)
    assert any(row[0] == stage for row in attempts)
    failed = result["1:1000"]
    assert isinstance(failed.normalized, UnresolvedNormalizedFunction)
    expected = NormalizationFailureReason.ANALYSIS_BUDGET if scope == "function" else \
        NormalizationFailureReason.ANALYSIS_RUN_BUDGET
    assert failed.normalized.reason is expected
    assert failed.failure_detail == f"{scope}:work" and failed.summary is None
    assert not failed.activations and id(failed) not in provenance
    assert all(id(context) not in provenance for context in contexts)
    if stage == "candidate":
        assert contexts  # A completed replay really preceded caller reanalysis.
    assert all(identifier == id(item) and item in result.values() and not item.activations
               for identifier, (item, _) in provenance.items())
    budget = resource_limits.last_run()
    assert budget.diagnostic_work == 0
    assert (budget.exhausted == "work") == (scope == "run")
    assert budget.work >= event[1] and ACTIVE_ENTRY.get() is None
    assert (budget.work if scope == "run" else budget.ledgers[_ledger_key(failed.unit)].work) > limit


def test_context_and_its_transitive_callers_are_not_generic_export_templates(models):
    (caller, callee), points = _case()
    wrapper = FunctionBuilder(0x1200).sub_rsp(0x28).call(0x1000).add_rsp(0x28).ret()
    with ImageBaseTracking((IMAGE,), _every_constant_relocates):
        result = analyze_units(program_units(caller, callee, wrapper), image_info=_image(), external_models=models,
                               private_frame_above=40, assume_globals_disjoint_from_stack=True,
                               assume_entry_values_not_frame=False,
                               assume_opaque_callees_leave_no_stack_addresses=False)
    context = result["1:1000"].activations[points["outer"]]
    generic = result["1:1600"]
    # The generic serializer intentionally cannot encode a live image tracker;
    # compare all normalized semantics and preserve the capture itself by identity.
    before = encode((generic.normalized, generic.summary, generic.proven))
    policy = generic.normalization_context
    for item in (context, result["1:1000"], result["1:1200"]):
        with pytest.raises(TemplateRefused, match="caller-owned activation"):
            export_summary(item, result)
    assert encode((generic.normalized, generic.summary, generic.proven)) == before
    assert generic.normalization_context is policy
    assert generic.normalized.activation_entry is None and not generic.activations
