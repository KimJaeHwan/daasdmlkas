"""Caller-owned entry-state replay over the existing normalizer and SSA.

This layer transports evidenced inputs, not allocation lifetime or memory
preservation claims. A separate call-memory consumer may refine its result.
"""
from dataclasses import replace
from contextlib import contextmanager

from .constant_value import ExactConstant
from .memory_contracts import MemoryDefinitionKind
from .resource_limits import step
from .span_geometry import ByteSpan, StorageObjectKind


def _source_signature(item):
    from ._forward_memory import _freeze
    options = dict(item.normalization_options)
    reader = options.pop("readonly_image", None)
    return (id(item.unit), id(item.normalized), _freeze(options), id(reader),
            item.normalization_context, item.summary_inputs, item.lifetime_models,
            item.allocation_models, item.allocation_contracts, item.replay_feedback)


@contextmanager
def _policy(callee):
    import os
    from .may_alias import ENTRY_VALUES_NOT_FRAME, OPAQUE_NO_STACK_ADDRESSES, PRE_ESCAPE_NOT_FRAME
    from .relative_memory import IMPORT_SLOTS, IMAGE_BASE_TRACKING, index_addresses, DEFINITION_ATOMS
    from ._forward_memory import RefinementRefused

    if os.environ.get("TDO_V2_FORWARD") != "1" or len(callee.normalization_context) != 9:
        raise RefinementRefused("activation lacks the original normalization policies")
    frame, opaque, imports, active, image, indexed, atoms, pre, restores = callee.normalization_context
    from .call_clobber import OPAQUE_RESTORES_SP
    inputs = callee.normalized.forward_inputs
    if inputs is None or (inputs.entry_values_not_frame, inputs.opaque_no_stack_addresses,
                          inputs.pre_escape_values_not_frame) != (frame, opaque, pre) \
            or index_addresses() != indexed or DEFINITION_ATOMS != atoms \
            or imports is not None and imports.active != active:
        raise RefinementRefused("activation normalization policies changed")
    tokens = [(ENTRY_VALUES_NOT_FRAME, ENTRY_VALUES_NOT_FRAME.set(frame)),
              (OPAQUE_NO_STACK_ADDRESSES, OPAQUE_NO_STACK_ADDRESSES.set(opaque)),
              (PRE_ESCAPE_NOT_FRAME, PRE_ESCAPE_NOT_FRAME.set(pre)),
              (OPAQUE_RESTORES_SP, OPAQUE_RESTORES_SP.set(restores)),
              (IMPORT_SLOTS, IMPORT_SLOTS.set(imports)), (IMAGE_BASE_TRACKING, IMAGE_BASE_TRACKING.set(image))]
    try:
        yield
    finally:
        for variable, token in reversed(tokens):
            variable.reset(token)


def _first(normalized, call):
    from .forward import first_effect
    return first_effect(normalized, call)


def _single(value, bits):
    if value is None or value.is_top or value.bits != bits or len(value.items) != 1:
        return None
    base, offset = value.items[0]
    return (base, offset.lo) if offset.single and offset.signed else None


def _stack(item):
    from .may_alias import _stack_pointer, _unit_stub
    return _stack_pointer(_unit_stub(item.unit.scopes), item.unit.observation,
                          item.unit.scopes.resolution_context, item.unit.scopes.program.evidence.address_spaces)


def _inputs(caller, callee, call, assumptions, readonly_image):
    from .forward import _analyze, _call_local_writes, _moved
    from .interprocedural import _register_file
    from .observed_call_state import observed_call_state_projections

    if caller.normalized.forward_inputs is None or callee.normalized.forward_inputs is None:
        return None
    shape = next((row for row in observed_call_state_projections(caller.unit.observation)
                  if row.call_operation_key == call), None)
    if shape is None or caller.calls.get(call) != callee.key or caller.unit.scopes.program != callee.unit.scopes.program:
        return None
    keys = {effect.operation_key for block in caller.normalized.forward_inputs.effect_unit.blocks
            for effect in block.effects}
    if any(key in keys for key in shape.transient_operation_keys):
        return None
    transition = shape.memory_transition
    register, _ = _register_file(callee.unit.observation, callee.unit.scopes.resolution_context)
    # the observed shape's push (its recognizer checked the return-address
    # STORE and no other stack-pointer write): one pointer width w, 4 or 8
    width = transition.callee_base.byte_size
    if register is None or width not in (4, 8) or transition.displacement_delta != -width:
        return None
    bits = 8 * width
    sp = ByteSpan(register, transition.callee_base.byte_offset, width)
    bases = {anchor for anchor, _ in callee.anchors.values()
             if anchor.object_id.kind is StorageObjectKind.REGISTER_FILE and anchor.size == width}
    bases.add(sp)
    analysis = _analyze(caller.normalized, caller.unit, readonly_image=readonly_image, assumptions=assumptions)
    if analysis.bind is None:
        return None
    values, used = analysis.bind(call, tuple(sorted(bases, key=lambda span: span.canonical_key)))
    before = values.get(sp)
    if before is None or before.is_top:
        return None
    after = _moved(before, transition.displacement_delta, transition.displacement_delta, 0)
    stack = _single(after, bits)
    writes = _call_local_writes(caller.unit.observation, call, (sp.start, sp.size))
    if stack is None or writes is None or stack[0][0] != "entry":
        return None
    relations = []
    for span, value in values.items():
        step()
        current = _single(value, bits)
        if span == sp or current is None or current[0] != stack[0] \
                or any(span.start < start + size and start < span.end for start, size in writes) \
                or abs(current[1] - stack[1]) >= 1 << (bits - 2):
            continue   # (|delta| at the relative-start seam: that relation is refused)
        relations.append((span, sp, current[1] - stack[1]))
    geometry = _stack(caller)
    if not relations or geometry is None:
        return None
    caller_object, bias, _, offset, size = geometry
    caller_anchor = caller.anchors.get(caller_object)
    space = None if caller_anchor is None else next((row for row in caller.unit.scopes.program.evidence.address_spaces
                                                     if row.space_id == caller_anchor[1]), None)
    if (offset, size) != stack[0][1:] or space is None or not space.is_memory_space \
            or space.address_size_bits != bits:
        return None
    return sp, stack[1], caller_object, bias, tuple(relations), tuple(sorted(set(analysis.labels) | set(used)))


def _normalize(callee, state, effects=None):
    from ._activation_entry import using_entry
    from .normalize import FunctionNormalizer

    options = dict(callee.normalization_options)
    if effects is not None:
        options["proven_call_effects"] = effects
    with _policy(callee), using_entry(state):
        return FunctionNormalizer().normalize(callee.unit, **options)


def _summarize(callee, normalized):
    """Replay the original summary's control cuts, not just its SSA options."""
    from ._activation_entry import using_entry
    from .function_summary import summarize_function
    from .interprocedural import _relative_anchors

    dead_ops, dead_jumps, _ = callee.summary_inputs
    with _policy(callee), using_entry(normalized.activation_entry):
        summary = summarize_function(normalized, callee.unit.observation, {}, (), dead_ops,
                                     noreturn_jumps=dead_jumps)
        anchors = _relative_anchors(callee.unit, normalized)
    return summary, anchors


def _frame_compatible(callee, normalized, sp, relations):
    """Do not specialize a binding that contradicts a retained frame premise.

    Compare the original resolved accesses with the mapped accesses, including
    their displacement and full byte range. Unlocated accesses are not a proof
    that a known entry pointer stays outside the private frame.
    """
    from .interprocedural import _relative_anchors
    from .model import ResolvedStorage

    original = callee.normalized.forward_inputs
    if not original.entry_values_not_frame:
        return True
    above = original.private_frame_above
    if any(delta < above for _, _, delta in relations):
        return False
    anchors = _relative_anchors(callee.unit, normalized)
    old_anchors = callee.anchors
    old = {effect.operation_key: effect for effect in callee.normalized.effects}
    for effect in normalized.effects:
        step()
        if effect.memory_read is not None or effect.memory_write is not None \
                or effect.unresolved_reads or effect.unresolved_writes:
            return False
        for role in ("reads", "writes"):
            for storage in getattr(effect, role):
                if type(storage) is not ResolvedStorage:
                    continue
                span = storage.span
                if span.object_id.kind is not StorageObjectKind.FUNCTION_RELATIVE:
                    continue
                anchor = anchors.get(span.object_id)
                if anchor is None:
                    return False
                if anchor[0] != sp or span.start >= (1 << (8 * sp.size)) + above:
                    continue
                previous = old.get(effect.operation_key)
                if previous is None or not any(
                        type(item) is ResolvedStorage and old_anchors.get(item.span.object_id) == anchor
                        and item.span.start == span.start and item.span.size == span.size
                        for item in getattr(previous, role)):
                    return False
    return True


def _memory_inputs(caller, callee, normalized, sp, delta, caller_object, bias, readonly_image, assumptions):
    from .forward import _analyze, probe
    from .interprocedural import _relative_anchors
    from ._load_identity import definition_identity

    anchors = _relative_anchors(callee.unit, normalized)
    caller_anchor = caller.anchors.get(caller_object)
    if caller_anchor is None:
        return (), (), ()
    memory_space = caller_anchor[1]
    analysis = _analyze(caller.normalized, caller.unit, readonly_image=readonly_image, assumptions=assumptions)
    first = _first(caller.normalized, normalized.activation_entry.context[1])
    if first is None or analysis.bind is None:
        return (), (), ()
    seeds, witnesses, labels = [], [], set(analysis.labels)
    ssa = normalized.memory_ssa
    # ENTRY definitions coalesce adjacent fields. Demand only the original
    # read fragments, not a whole coalesced TArray header whose other fields
    # may be unknown. A later DATA_WRITE is never an entry input.
    requested = {fragment.span for read in ssa.reads for fragment in read.fragments
                 if len(fragment.definition_ids) == 1 and
                 ssa.definitions[fragment.definition_ids[0]].kind is MemoryDefinitionKind.ENTRY}
    for span in sorted(requested, key=lambda span: (-span.size, span.canonical_key)):
        step()
        if not 0 < span.size <= 16 \
                or anchors.get(span.object_id) != (sp, memory_space):
            continue
        displacement = span.start - (1 << (8 * sp.size))   # (the relative zero point: 2^bits)
        # The observed CALL pushes its return address here (sp.size bytes:
        # the shape's push). Caller pre-push RAM is not the callee's ENTRY
        # value, including partial overlaps.
        if displacement < sp.size and displacement + span.size > 0 \
                or any(span.overlaps(previous) for previous, _ in seeds):
            continue
        source = ByteSpan(caller_object, bias + delta + displacement, span.size)
        ids, used = probe(caller.normalized, first, (source,))
        identifier = ids.get(source)
        if type(identifier) is not int:
            continue
        values, used_value = analysis.bind(normalized.activation_entry.context[1], (source,))
        number = values[source].single_number()
        if number is None:
            continue
        literal = ExactConstant(span.size, number)
        seeds.append((span, literal))
        witnesses.append((source, definition_identity(caller.normalized.memory_ssa.definitions[identifier]), literal))
        labels.update((*used, *used_value))
        if len(seeds) >= 16:
            break
    return tuple(seeds), tuple(witnesses), tuple(sorted(labels))


def replay_activation(caller, callee, call, *, readonly_image=None, assumptions=()):
    """Optional context result, or None. The generic callee is never changed."""
    from ._forward_memory import RefinementRefused
    if readonly_image is not dict(callee.normalization_options).get("readonly_image") \
            or readonly_image is not dict(caller.normalization_options).get("readonly_image"):
        return None
    try:
        with _policy(callee):
            return _replay_activation(caller, callee, call, readonly_image=readonly_image, assumptions=assumptions)
    except RefinementRefused:
        return None


def _replay_activation(caller, callee, call, *, readonly_image=None, assumptions=()):
    from ._activation_entry import ActivationEntry
    from .normalize import NormalizedFunction

    if callee.unit.scopes.program.evidence.translation_namespace.language_id.split(":")[1:3] \
            not in (["LE", "64"], ["LE", "32"]) \
            or getattr(caller.normalized, "activation_entry", None) is not None \
            or getattr(callee.normalized, "activation_entry", None) is not None \
            or callee.activations or callee.origins or callee.projected_sinks or callee.recursion_unresolved \
            or callee.summary is None or callee.summary.sink_demands \
            or not callee.normalization_options or len(callee.summary_inputs) != 3 \
            or type(callee.normalized) is not NormalizedFunction:
        return None
    bound = _inputs(caller, callee, call, assumptions, readonly_image)
    if bound is None:
        return None
    sp, delta, caller_object, bias, relations, labels = bound
    state = ActivationEntry(callee.unit.scopes.function.scope, (caller.key, call), relations, (), labels)
    first = _normalize(callee, state)
    if type(first) is not NormalizedFunction:
        return None
    if not _frame_compatible(callee, first, sp, relations):
        return None
    seeds, witnesses, used = _memory_inputs(caller, callee, first, sp, delta, caller_object, bias,
                                          readonly_image, assumptions)
    state = replace(state, memory=seeds, requires=tuple(sorted(
        set(labels) | set(used) | set(assumptions) | set(callee.summary_inputs[2])
        | set(callee.inherited_assumptions) | set(callee.declared.values()))))
    final = _normalize(callee, state) if seeds else first
    if type(final) is not NormalizedFunction:
        return None
    # Keep the requirements captured even when the first normalization can
    # be reused: the input context is independent of optional memory seeds.
    final = replace(final, activation_entry=state)
    # Entry substitution is consumed by the normalizer, probe and crossing
    # calculation alike. No surrogate source/sink graph is built here.
    summary, anchors = _summarize(callee, final)
    result = replace(callee, normalized=final, summary=summary,
                     anchors=anchors, inherited_assumptions=callee.inherited_assumptions
                     | frozenset(state.requires), activation_witness=(caller, callee, call, witnesses),
                     activation_inputs=(_source_signature(caller), _source_signature(callee)))
    return result


def revalidate_activation(original, candidate, replay, *, readonly_image=None, assumptions=()):
    """The caller's adopted result must still supply the ORIGINAL inputs."""
    from .forward import _analyze, probe
    from ._load_identity import definition_identity
    from .normalize import NormalizedFunction

    if len(replay.activation_witness) != 4 or type(candidate.normalized) is not NormalizedFunction \
            or candidate.normalized.forward_inputs is None:
        return False
    source, callee, call, witnesses = replay.activation_witness
    if source is not original or candidate.unit is not original.unit:
        return False
    if replay.activation_inputs != (_source_signature(original), _source_signature(callee)):
        return False
    first = _first(candidate.normalized, call)
    analysis = _analyze(candidate.normalized, candidate.unit, readonly_image=readonly_image, assumptions=assumptions)
    if first is None or analysis.bind is None:
        return False
    # Rebuild the independent register/call-shape bindings as well.
    before = _inputs(original, callee, call, assumptions, readonly_image)
    after = _inputs(candidate, callee, call, assumptions, readonly_image)
    if before is None or after is None or before[:5] != after[:5]:
        return False
    for span, identity, literal in witnesses:
        found, _ = probe(candidate.normalized, first, (span,))
        identifier = found.get(span)
        values, _ = analysis.bind(call, (span,))
        if type(identifier) is not int or definition_identity(candidate.normalized.memory_ssa.definitions[identifier]) \
                != identity or values[span].single_number() != literal.unsigned:
            return False
    return True
