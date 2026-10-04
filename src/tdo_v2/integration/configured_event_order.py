"""Ordering, identity, and selection rules for interprocedural events."""

from __future__ import annotations

from ..memory_contracts import MemoryDefinitionKind
from .configured_interprocedural_contracts import InterproceduralOriginProof
from .configured_interprocedural_records import WriteEvent as _WriteEvent

def _prefer_shorter_events(previous, current):
    grouped = {}
    for event in previous + current:
        grouped.setdefault(_event_location_key(event), []).append(event)
    selected = []
    for events in grouped.values():
        exemplar = min(events, key=_event_key)
        origins = _prefer_shorter_origins(
            tuple(origin for event in events for origin in event.origins)
        )
        selected.append(
            _WriteEvent(
                exemplar.caller_scope_digest,
                exemplar.call_position,
                exemplar.call_operation_key,
                exemplar.callee_entry,
                exemplar.callee_scope_digest,
                exemplar.callee_write_operation_key,
                exemplar.target_span,
                exemplar.pointer_dereferences,
                origins,
                exemplar.target_path,
            )
        )
    return tuple(sorted(selected, key=_event_key))

def _event_cache_semantics(cache):
    return tuple(
        (entry, tuple(sorted(_event_semantic_key(event) for event in events)))
        for entry, events in sorted(cache.items())
    )

def _event_semantic_key(event):
    return (
        _event_location_key(event),
        tuple(
            sorted({_origin_semantic_key(origin) for origin in event.origins})
        ),
    )

def _event_location_key(event):
    return (
        event.caller_scope_digest,
        event.call_position,
        event.call_operation_key,
        event.callee_entry,
        event.callee_scope_digest,
        event.callee_write_operation_key,
        event.target_span.canonical_key,
        event.pointer_dereferences,
    )

def _origin_semantic_key(origin):
    return (
        origin.label,
        origin.function_entry,
        origin.function_scope_digest,
        origin.node,
    )

def _origin_proof_key(origin):
    return (
        len(origin.prior_transfers),
        tuple(step.canonical_key for step in origin.prior_transfers),
    )

def _prefer_shorter_origins(origins):
    selected = {}
    for origin in origins:
        key = _origin_semantic_key(origin)
        prior = selected.get(key)
        if prior is None or _origin_proof_key(origin) < _origin_proof_key(prior):
            selected[key] = origin
    return tuple(
        sorted(
            selected.values(),
            key=lambda item: (_origin_semantic_key(item), _origin_proof_key(item)),
        )
    )

def _origin_proofs_for_event(view, event):
    return tuple(
        InterproceduralOriginProof(
            origin.label,
            origin.function_entry,
            origin.function_scope_digest,
            origin.node,
            view.scope_digest,
            event.call_operation_key,
            event.callee_entry,
            event.callee_scope_digest,
            event.callee_write_operation_key,
            event.target_span,
            event.pointer_dereferences,
            origin.prior_transfers,
        )
        for origin in event.origins
    )

def _event_key(event):
    return (
        event.call_position,
        event.call_operation_key,
        event.callee_entry,
        event.callee_write_operation_key,
        event.target_span.canonical_key,
        tuple(
            (
                origin.label,
                origin.function_entry,
                origin.node,
                tuple(step.canonical_key for step in origin.prior_transfers),
            )
            for origin in event.origins
        ),
    )

def _overlapping_events(events, span):
    return tuple(event for event in events if event.target_span.overlaps(span))

def _effective_access_span(view, operation_key, fallback, *, read):
    resolver = getattr(view, "effective_access_span", None)
    if not callable(resolver):
        return None
    return resolver(operation_key, fallback, read=read)

def _definition_access_spans(view, definition):
    resolver = getattr(view, "definition_access_spans", None)
    if not callable(resolver):
        return ()
    return resolver(definition)

def _latest_preceding_events(view, events, before_operation_key):
    eligible = tuple(
        event
        for event in events
        if view.may_precede(event.call_operation_key, before_operation_key)
    )
    local_writes = tuple(
        definition
        for definition in view.memory.definitions
        if definition.kind is MemoryDefinitionKind.DATA_WRITE
        and definition.operation_key is not None
    )
    surviving = []
    for event in eligible:
        blockers = {
            other.call_operation_key
            for other in eligible
            if other.call_operation_key != event.call_operation_key
            and event.target_span.overlaps(other.target_span)
        }
        blockers.update(
            definition.operation_key
            for definition in local_writes
            if any(
                event.target_span.overlaps(span)
                for span in _definition_access_spans(view, definition)
            )
        )
        if view.can_reach_without_operations(
            event.call_operation_key,
            before_operation_key,
            tuple(blockers),
        ):
            surviving.append(event)
    return tuple(surviving)

__all__ = ["_definition_access_spans","_effective_access_span","_event_cache_semantics","_event_key","_event_location_key","_event_semantic_key","_latest_preceding_events","_origin_proof_key","_origin_proofs_for_event","_origin_semantic_key","_overlapping_events","_prefer_shorter_events","_prefer_shorter_origins"]
