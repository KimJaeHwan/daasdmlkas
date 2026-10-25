"""Demand-scoped call nonmodification over the existing SSA and call effects.

A decision concerns (CALL, byte range), NOT the value of a later read or
whether an allocation is alive. Demands come from the original debt graph.
The first proof provider closes a matched null-is-fresh model's free set;
nonnull/unknown lifetimes deliberately remain unknown. Future lifetime facts
must discharge the same range obligation, not add exceptions to the caller
entry-state transport or manufacture a second memory graph.
"""
from dataclasses import dataclass, replace

from .resource_limits import step
from .span_geometry import ByteSpan, StorageObjectKind


@dataclass(frozen=True, slots=True)
class CallMemoryDemand:
    reader: str
    call: str
    span: ByteSpan


@dataclass(frozen=True, slots=True)
class CallMemoryDecision:
    demand: CallMemoryDemand
    preserved: bool
    reason: str
    requires: tuple[str, ...] = ()
    model_digest: str | None = None
    model_label: str = ""
    evidence: tuple = ()


def memory_demands(normalized):
    """Existing exact memory read ranges, irrespective of opcode/width/delay."""
    found = set()
    for row in normalized.call_clobber_reads:
        for span in row.spans:
            if span.object_id.kind not in (StorageObjectKind.FUNCTION_RELATIVE, StorageObjectKind.ADDRESS_SPACE):
                continue
            for call in row.intervening_calls:
                step()
                found.add(CallMemoryDemand(row.operation_key, call, span))
    return tuple(sorted(found, key=lambda row: (row.call, row.reader, row.span.canonical_key)))


def decide_call_memory(item, *, readonly_image=None, assumptions=()):
    """Return explicit no-write/unknown decisions; do not mutate SSA/effects.

    All inputs are the finished context's own graph, matched model identities
    and original pre-call forward facts. No result from this decision batch
    is used to establish another decision in the batch.
    """
    from .forward import _analyze
    from .normalize import _call_below_bounds
    from .observed_call_state import observed_call_state_projections

    normalized = item.normalized
    demands = memory_demands(normalized)
    if not demands:
        return ()
    analysis = _analyze(normalized, item.unit, readonly_image=readonly_image, assumptions=assumptions)
    effects = dict(normalized.proven_call_effects)
    transitions = {row.call_operation_key: row.memory_transition
                   for row in observed_call_state_projections(item.unit.observation)}
    inputs = normalized.forward_inputs
    bounds = {key: (obj, bound) for key, obj, bound in _call_below_bounds(
        effects, transitions, inputs.effect_unit, normalized.memory_ssa,
        item.unit.observation, item.unit.scopes, item.unit.scopes.resolution_context,
        include_unpreserved=True)}
    models = {call: (model_file, entry) for call, model_file, entry in item.lifetime_models}
    # Bind a model's operands once, even when many reads demand its ranges.
    contracts = {}
    decisions = []
    for demand in demands:
        step()
        call = demand.call
        if call not in contracts:
            reason, used = "call-footprint-unproved", ()
            model_file, entry = models.get(call, (None, None))
            effect = effects.get(call)
            if entry is not None:
                matched = any(replace(entry, inherited=original.inherited) == original
                              and set(original.inherited) <= set(entry.inherited)
                              and set(entry.inherited) - set(original.inherited)
                              <= {"import-slots-hold-their-exports", "library-internal-model-cuts"}
                              for original in model_file.entries)
                if effect is not None and effect.callee == entry.label and matched \
                        and not entry.refusal and not entry.callbacks_invokes and entry.template is None \
                        and entry.keeps_other_memory and entry.frees \
                        and all(old in {pair[1] for pair in entry.same_object} for old in entry.frees) \
                        and effect.same_object_registers and effect.restores_stack and effect.clobbers_below \
                        and not (effect.noreturn or effect.memory_runs or effect.unknown_memory
                                 or effect.writer_conditions or effect.extent_registers or effect.preserves_memory):
                    reason = "allocation-lifetime-unproved"
                    if analysis.bind is not None:
                        register = effect.same_object_registers[0][1].object_id
                        freed = tuple(ByteSpan(register, start, size) for start, size in entry.frees)
                        values, used = analysis.bind(call, freed)
                        if all(values[span].single_number() == 0 for span in freed):
                            reason = "null-free-set-empty"
            contracts[call] = reason, tuple(sorted(set(used) | set(analysis.labels))), model_file, entry
        reason, requires, model_file, entry = contracts[call]
        if reason == "null-free-set-empty":
            transition = transitions.get(call)
            geometry = bounds.get(call)
            # Require the entire demanded range outside the CALL's observed
            # return-address overlay AND the callee's lower frame. No partial
            # overlap, pointer-origin, allocation extent or lifetime shortcut.
            if transition is None or transition.displacement_delta != -8 or geometry is None:
                reason = "call-geometry-unproved"
            elif demand.span.object_id != geometry[0] or demand.span.start < geometry[1] + 8:
                reason = "range-outside-proven-stack-region"
        decisions.append(CallMemoryDecision(demand, reason == "null-free-set-empty", reason, requires,
                                            None if model_file is None else model_file.digest,
                                            "" if entry is None else entry.label))
    return tuple(decisions)


def refine_call_memory(item, *, readonly_image=None, assumptions=()):
    """Consume range decisions through normal call effects and memory SSA.

    Unknown decisions keep the entry context intact. Preserving C's range
    removes only C's debt; later writes, other calls and JOINs remain the
    responsibility of the unchanged normalizer/SSA/query engine.
    """
    from ._activation_entry import using_entry
    from ._call_activation import _policy
    from ._forward_memory import RefinementRefused

    state = item.normalized.activation_entry
    if state is None:
        raise ValueError("call memory refinement requires an evidenced entry context")
    if readonly_image is not dict(item.normalization_options).get("readonly_image"):
        raise RefinementRefused("call memory refinement changed its image reader")
    with _policy(item), using_entry(state):
        return _refine_call_memory(item, readonly_image=readonly_image, assumptions=assumptions)


def _refine_call_memory(item, *, readonly_image=None, assumptions=()):
    from ._call_activation import _normalize, _summarize
    from ._forward_memory import RefinementRefused
    from .forward import _analyze
    from .normalize import NormalizedFunction

    state = item.normalized.activation_entry
    decisions = decide_call_memory(item, readonly_image=readonly_image,
                                  assumptions=tuple(sorted(set(assumptions) | set(state.requires))))
    base = replace(item, call_memory_decisions=decisions)
    effects = dict(item.normalized.proven_call_effects)
    additions = {}
    for decision in decisions:
        if decision.preserved:
            additions.setdefault(decision.demand.call, set()).add(decision.demand.span)
    if not additions:
        return base
    state = replace(state, requires=tuple(sorted(set(state.requires) | {
        label for row in decisions if row.preserved for label in row.requires})))
    for call, spans in additions.items():
        effect = effects[call]
        effects[call] = replace(effect, preserved=(*effect.preserved, *sorted(
            spans - set(effect.preserved), key=lambda span: span.canonical_key)))
    try:
        final = _normalize(item, state, effects)
    except RefinementRefused:
        return replace(base, call_memory_decisions=tuple(replace(row, preserved=False,
                       reason="replay-inputs-changed") if row.preserved else row for row in decisions))
    if type(final) is not NormalizedFunction:
        # Ordinary unsupported normalization is a refused optional refinement.
        # Hard work/depth failures are exceptions and propagate unchanged.
        return replace(base, call_memory_decisions=tuple(replace(row, preserved=False,
                       reason="replay-normalization-refused") if row.preserved else row for row in decisions))
    for decision in decisions:
        if decision.preserved and any(
                row.operation_key == decision.demand.reader and decision.demand.call in row.intervening_calls
                and any(span.overlaps(decision.demand.span) for span in row.spans)
                for row in final.call_clobber_reads):
            return replace(base, call_memory_decisions=tuple(replace(row, preserved=False,
                           reason="replay-debt-mismatch") if row.preserved else row for row in decisions))
    labels = _analyze(final, item.unit, readonly_image=readonly_image, assumptions=state.requires).labels
    state = replace(state, requires=tuple(sorted(set(state.requires) | set(labels)
                                                | set(final.forward_memory_requires))))
    final = replace(final, activation_entry=state)
    summary, anchors = _summarize(item, final)
    return replace(base, normalized=final, summary=summary, anchors=anchors, proven=effects,
                   inherited_assumptions=base.inherited_assumptions | frozenset(state.requires)
                   | frozenset(final.forward_memory_requires))
