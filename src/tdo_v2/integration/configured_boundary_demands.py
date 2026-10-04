"""Boundary-node selection and sink-entry demand projection."""

from __future__ import annotations

from ..boundary import BoundaryKind
from ..memory_contracts import MemoryDefinitionKind
from ..model import ByteSpan
from ..observed_boundary_projection import ObservedBoundaryNode, ObservedBoundaryProjection
from ..physical_state import PhysicalStateResolver, PhysicalValueResolver
from .configured_boundary_mapping import (
    _mapped_or_observed_call_span,
    _mapped_or_observed_pointer_anchor,
    _pointer_at_span,
)
from .configured_interprocedural_contracts import ConfiguredFunctionAnalysis
from .configured_interprocedural_records import SinkEntryDemand as _SinkEntryDemand
from .configured_physical_state import _FunctionPhysicalStateBackend
from .configured_value_domain import compose_pointer_path as _compose_pointer_path
from .observed_slice import run_observed_boundary_slices

def _analyses_from_boundary_nodes(preliminary, nodes):
    analyses = []
    for item in preliminary:
        projection = ObservedBoundaryProjection(
            _canonical_boundary_nodes(nodes[item.entry])
        )
        analyses.append(
            ConfiguredFunctionAnalysis(
                item.evidence,
                item.normalized,
                projection,
                run_observed_boundary_slices(item.normalized, projection),
            )
        )
    return tuple(analyses)

def _sink_boundary_nodes(
    caller,
    label,
    call_operation_key,
    call_position,
    occurrence_ordinal,
    fragments,
):
    rows = []
    event_only = []
    for fragment_ordinal, span in fragments:
        definition_id = caller.state_definition(span, call_position)
        if definition_id is None:
            event_only.append((fragment_ordinal, span))
            continue
        rows.append(
            ObservedBoundaryNode(
                BoundaryKind.SINK,
                label,
                caller.memory_graph.definition_nodes[definition_id],
                occurrence_ordinal,
                fragment_ordinal,
                (span,),
            )
        )
    action_id = caller.action_ids.get(call_operation_key)
    if event_only and action_id is not None:
        rows.append(
            ObservedBoundaryNode(
                BoundaryKind.SINK,
                label,
                caller.memory_graph.action_nodes[action_id],
                occurrence_ordinal,
                min(item[0] for item in event_only),
                tuple(
                    sorted(
                        {item[1] for item in event_only},
                        key=lambda item: item.canonical_key,
                    )
                ),
            )
        )
    return tuple(rows)

def _direct_sink_boundary_nodes(
    caller,
    label,
    call_operation_key,
    call_position,
    occurrence_ordinal,
    selectors,
):
    """Bind a sink to exact physical definitions or its exact consume event."""
    backend = _FunctionPhysicalStateBackend(caller)
    span_resolver = PhysicalStateResolver(backend)
    value_resolver = PhysicalValueResolver(backend)
    rows = []
    event_spans = []
    seen_definition_ids = set()
    fragment_ordinal = 0
    for selector in selectors:
        selector_definition_ids = value_resolver.resolve(selector, call_position)
        span = span_resolver.resolve(selector, call_position)
        if span is None and not selector_definition_ids:
            return ()
        if seen_definition_ids.intersection(selector_definition_ids):
            return ()
        seen_definition_ids.update(selector_definition_ids)
        if not selector_definition_ids:
            if span in event_spans:
                return ()
            event_spans.append(span)
            fragment_ordinal += 1
            continue
        for definition_id in selector_definition_ids:
            rows.append(
                ObservedBoundaryNode(
                    BoundaryKind.SINK,
                    label,
                    caller.memory_graph.definition_nodes[definition_id],
                    occurrence_ordinal,
                    fragment_ordinal,
                    () if span is None else (span,),
                )
            )
            fragment_ordinal += 1
    action_id = caller.action_ids.get(call_operation_key)
    if event_spans and action_id is not None:
        rows.append(
            ObservedBoundaryNode(
                BoundaryKind.SINK,
                label,
                caller.memory_graph.action_nodes[action_id],
                occurrence_ordinal,
                min(
                    ordinal
                    for ordinal, selector in enumerate(selectors)
                    if span_resolver.resolve(selector, call_position) in event_spans
                ),
                tuple(sorted(event_spans, key=lambda item: item.canonical_key)),
            )
        )
    return tuple(rows)

def _project_sink_entry_demand(
    caller,
    demand,
    call_position,
    correspondence=(),
    *,
    callee=None,
    call_operation_key=None,
):
    if demand.direct_span is not None:
        return (
            _mapped_or_observed_call_span(
                caller,
                callee,
                demand.direct_span,
                call_operation_key,
                call_position,
                correspondence,
            ),
            demand,
        )
    if (
        demand.pointer_anchor_span is None
        or demand.address_space_id is None
        or not demand.pointer_offsets
    ):
        return None, None
    caller_anchor, pointer_offsets = _mapped_or_observed_pointer_anchor(
        caller,
        callee,
        demand.pointer_anchor_span,
        demand.pointer_offsets,
        call_operation_key,
        call_position,
        correspondence,
    )
    if caller_anchor is None:
        return None, None
    actual = _pointer_at_span(caller, caller_anchor, call_position)
    if actual is None:
        return None, None
    combined = _compose_pointer_path(actual, pointer_offsets, demand.address_space_id)
    combined = caller.resolve_local_pointer_prefix(
        combined,
        before_position=call_position,
        address_space_id=demand.address_space_id,
    )
    anchor = caller.memory.definitions[combined.anchor_definition_id]
    caller_demand = None
    if anchor.kind is MemoryDefinitionKind.ENTRY:
        caller_anchor_span = ByteSpan(
            anchor.span.object_id,
            anchor.span.start + combined.anchor_byte_offset,
            combined.byte_size,
        )
        caller_demand = _SinkEntryDemand(
            demand.label,
            pointer_anchor_span=caller_anchor_span,
            pointer_offsets=combined.offsets,
            pointer_byte_size=combined.byte_size,
            address_space_id=demand.address_space_id,
            target_size=demand.target_size,
        )
    caller_span = caller.materialize_path(
        combined,
        before_position=call_position,
        target_size=demand.target_size,
        address_space_id=demand.address_space_id,
    )
    if caller_span is None:
        return None, caller_demand
    return caller_span, caller_demand

def _canonical_boundary_nodes(
    values: list[ObservedBoundaryNode],
) -> tuple[ObservedBoundaryNode, ...]:
    unique = {}
    for item in values:
        unique.setdefault((item.kind.value, item.label, item.node), item)
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (
                item.kind.value,
                item.label,
                item.node,
                item.occurrence_ordinal,
                item.fragment_ordinal,
            ),
        )
    )

__all__ = ["_analyses_from_boundary_nodes","_canonical_boundary_nodes","_direct_sink_boundary_nodes","_project_sink_entry_demand","_sink_boundary_nodes"]
