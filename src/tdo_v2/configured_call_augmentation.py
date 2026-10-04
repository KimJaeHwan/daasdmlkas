"""Project configured V4 call fragments onto observed local effects."""

from __future__ import annotations

from .call_effect_contracts import CallEffectDirection
from .configured_effect_contracts import ConfiguredFunctionCallEffectEvidenceV4
from .effects import EffectKind, ObservedEffect, ObservedEffectBlock, ObservedEffectUnit
from .model import ByteSpan, ResolvedStorage


def augment_configured_call_effects_v4(
    raw_unit: ObservedEffectUnit,
    effects: ConfiguredFunctionCallEffectEvidenceV4,
    /,
) -> ObservedEffectUnit:
    """Add admitted physical call fragments without assigning ABI roles."""
    if type(raw_unit) is not ObservedEffectUnit:
        raise TypeError("raw effect unit must be an exact ObservedEffectUnit")
    if type(effects) is not ConfiguredFunctionCallEffectEvidenceV4:
        raise TypeError(
            "configured call effects must be exact V4 evidence"
        )
    effects._validate()
    if effects.seeds.function_scope != raw_unit.function_scope:
        raise ValueError("configured call effects and raw unit use different functions")
    if raw_unit.effect_evidence_digest != effects.canonical_digest:
        raise ValueError("raw unit does not carry the configured V4 evidence digest")

    records_by_key = {
        seed.operation_key: record
        for seed, record in zip(
            effects.seeds.callsites,
            effects.calls,
            strict=True,
        )
    }
    seen: set[str] = set()
    blocks: list[ObservedEffectBlock] = []
    for block in raw_unit.blocks:
        changed = False
        projected: list[ObservedEffect] = []
        for raw_effect in block.effects:
            record = records_by_key.get(raw_effect.operation_key)
            if record is None:
                if raw_effect.kind is EffectKind.CALL:
                    raise ValueError("raw call effect has no exact configured V4 evidence")
                projected.append(raw_effect)
                continue
            if raw_effect.kind is not EffectKind.CALL:
                raise ValueError("configured V4 evidence matched a non-call effect")
            seen.add(raw_effect.operation_key)
            reads = tuple(
                ResolvedStorage(fragment.span)
                for fragment in record.pre_read.fragments
            )
            writes = tuple(
                ResolvedStorage(fragment.span)
                for fragment in record.post_write.fragments
            )
            if not reads and not writes:
                projected.append(raw_effect)
                continue
            projected.append(_project_call(raw_effect, reads, writes))
            changed = True
        blocks.append(
            ObservedEffectBlock(block.key, block.predecessors, tuple(projected))
            if changed
            else block
        )
    if seen != set(records_by_key):
        raise ValueError("configured V4 evidence does not exactly cover call operations")
    if all(current is original for current, original in zip(blocks, raw_unit.blocks)):
        return raw_unit
    return ObservedEffectUnit(
        raw_unit.contract_version,
        raw_unit.function_scope,
        raw_unit.entry_block_key,
        tuple(blocks),
        raw_unit.observed_terminal_block_keys,
        effect_evidence_digest=effects.canonical_digest,
    )


def _project_call(
    raw_effect: ObservedEffect,
    configured_reads: tuple[ResolvedStorage, ...],
    configured_writes: tuple[ResolvedStorage, ...],
) -> ObservedEffect:
    reads = _deduplicate_reads(raw_effect.reads + configured_reads)
    concrete_writes = tuple(
        value.span for value in raw_effect.writes if type(value) is ResolvedStorage
    ) + tuple(value.span for value in configured_writes)
    writes = tuple(ResolvedStorage(span) for span in _partition_spans(concrete_writes))
    return ObservedEffect(
        operation_key=raw_effect.operation_key,
        kind=raw_effect.kind,
        reads=reads,
        writes=writes,
        memory_read=raw_effect.memory_read,
        memory_write=raw_effect.memory_write,
        call_targets=raw_effect.call_targets,
        block_key=raw_effect.block_key,
        unresolved_reads=raw_effect.unresolved_reads,
        unresolved_writes=raw_effect.unresolved_writes,
    )


def _deduplicate_reads(values: tuple[object, ...]) -> tuple[object, ...]:
    result: list[object] = []
    for value in values:
        if value not in result:
            result.append(value)
    return tuple(result)


def _partition_spans(spans: tuple[ByteSpan, ...]) -> tuple[ByteSpan, ...]:
    endpoints: dict[tuple[object, int], int] = {}
    for span in spans:
        start = (span.object_id, span.start)
        end = (span.object_id, span.end)
        endpoints[start] = endpoints.get(start, 0) + 1
        endpoints[end] = endpoints.get(end, 0) - 1

    partitions: list[ByteSpan] = []
    active = 0
    previous_object = None
    previous_point = None
    for (object_id, point), delta in sorted(endpoints.items()):
        if object_id != previous_object:
            if active:
                raise AssertionError("configured call partition did not close")
            previous_object = object_id
            previous_point = point
        elif active:
            assert previous_point is not None
            partitions.append(ByteSpan(object_id, previous_point, point - previous_point))
        active += delta
        previous_point = point
    if active:
        raise AssertionError("configured call partition did not close")
    return tuple(sorted(partitions, key=lambda span: span.canonical_key))


__all__ = ("augment_configured_call_effects_v4",)
