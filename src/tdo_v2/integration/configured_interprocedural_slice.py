"""Conservative cross-function completion for configured boundary slices.

This layer composes only evidence already admitted by the configured Bundle:
exact direct targets, exact physical storage, function-relative pointer
expressions, terminal memory states, and local SSA definitions.  It assigns no
argument or return role.  Unsupported control flow, storage splits, pointer
arithmetic, or aliasing stays as debt in the local slice.
"""

from __future__ import annotations

from .._scope_contracts import AddressCoordinate
from ..boundary import BoundaryKind, BoundaryProvider, CallBoundary
from ..external_summary import (
    ExternalSummaryProvider,
    NullExternalSummaryProvider,
)
from ..normalize import NormalizedFunction
from ..observed_boundary_projection import (
    EMPTY_OBSERVED_BOUNDARIES,
    ObservedBoundaryNode,
)
from .configured_boundary_demands import (
    _analyses_from_boundary_nodes,
    _canonical_boundary_nodes,
    _direct_sink_boundary_nodes,
    _project_sink_entry_demand,
    _sink_boundary_nodes,
)
from .configured_coordinate_events import _bind_coordinate_event_memory_views
from .configured_function_view import _FunctionView
from .configured_interprocedural_contracts import (
    ConfiguredFunctionAnalysis,
    InterproceduralOriginProof,
    InterproceduralSliceCompletion,
    InterproceduralTransferProof,
)
from .configured_origin_projection import _complete_slice
from .configured_physical_state import _boundary_state_spans
from .configured_reachability import _reachable_entry_demands
from .configured_target_resolution import (
    _external_callback_edges,
    _observed_internal_call_targets,
    _selected_resolved_target,
)
from .configured_write_event_engine import _stabilized_write_events
from .observed_function_session import ObservedFunctionEvidence

def complete_configured_interprocedural_slices(
    analyses: tuple[ConfiguredFunctionAnalysis, ...], /,
    external_provider: ExternalSummaryProvider | None = None,
    *, finite_context_request=None,
) -> tuple[tuple[AddressCoordinate, tuple[InterproceduralSliceCompletion, ...]], ...]:
    """Complete local slices with exact direct-call storage-state evidence."""
    if finite_context_request is not None:
        # Deliberately before _FunctionView and the all-function event cache.
        # Lazy import preserves the dependency/work profile of the default path.
        from .configured_finite_context_inputs import stop_selected_finite_context_request
        stop_selected_finite_context_request(analyses, finite_context_request)
    if type(analyses) is not tuple or any(
        type(item) is not ConfiguredFunctionAnalysis for item in analyses
    ):
        raise TypeError("interprocedural analyses must be an exact tuple")
    entries = tuple(item.entry for item in analyses)
    if len(set(entries)) != len(entries):
        raise ValueError("interprocedural function entries must be unique")
    views = {item.entry: _FunctionView(item) for item in analyses}
    _bind_coordinate_event_memory_views(views)
    event_cache = _stabilized_write_events(
        views,
        NullExternalSummaryProvider()
        if external_provider is None
        else external_provider,
    )
    completed = []
    for analysis in analyses:
        view = views[analysis.entry]
        events = event_cache[analysis.entry]
        rows = tuple(
            _complete_slice(view, local_slice, events, views)
            for local_slice in analysis.slices
        )
        completed.append((analysis.entry, rows))
    return tuple(completed)

def build_observed_function_analyses(
    rows: tuple[tuple[ObservedFunctionEvidence, NormalizedFunction], ...],
    provider: BoundaryProvider,
    /,
    external_provider: ExternalSummaryProvider | None = None,
) -> tuple[ConfiguredFunctionAnalysis, ...]:
    """Bind external names after deriving call flow from physical storage only."""
    if type(rows) is not tuple or any(
        type(row) is not tuple
        or len(row) != 2
        or type(row[0]) is not ObservedFunctionEvidence
        or type(row[1]) is not NormalizedFunction
        for row in rows
    ):
        raise TypeError("observed analyses require exact evidence/function pairs")
    preliminary = tuple(
        ConfiguredFunctionAnalysis(evidence, normalized, EMPTY_OBSERVED_BOUNDARIES, ())
        for evidence, normalized in rows
    )
    entries = tuple(item.entry for item in preliminary)
    if len(set(entries)) != len(entries):
        raise ValueError("observed function entries must be unique")
    views = {item.entry: _FunctionView(item) for item in preliminary}
    external_provider = (
        NullExternalSummaryProvider()
        if external_provider is None
        else external_provider
    )
    coordinate_events = _bind_coordinate_event_memory_views(views)
    nodes: dict[AddressCoordinate, list[ObservedBoundaryNode]] = {
        item.entry: [] for item in preliminary
    }
    direct_calls = []

    for caller in preliminary:
        caller_view = views[caller.entry]
        for occurrence_ordinal, (seed, naming) in enumerate(
            zip(
                caller.evidence.seeds.callsites,
                caller.evidence.naming.rows,
                strict=True,
            )
        ):
            target = _selected_resolved_target(naming)
            targets = tuple(
                (coordinate, ())
                for coordinate in _observed_internal_call_targets(
                    caller_view,
                    seed,
                    naming,
                    views,
                    coordinate_events[caller.entry],
                )
            )
            if not targets and target is not None and target.is_external:
                targets = _external_callback_edges(
                    caller_view,
                    seed,
                    target,
                    views,
                    external_provider,
                )
            if not targets:
                continue
            aliases = tuple(
                sorted(
                    {
                        alias.value
                        for alias in (() if target is None else target.aliases)
                        if alias.policy_admissible
                    }
                )
            )
            namespace = caller.evidence.unit.scopes.program.evidence.translation_namespace
            boundary = CallBoundary(
                f"{caller.entry.space_id:x}:{caller.entry.byte_offset:x}",
                seed.operation_key,
                aliases,
                namespace.language_id,
            )
            matches = provider.classify(boundary)
            call_position = caller_view.position(seed.operation_key)
            if call_position is None:
                continue
            for target_coordinate, correspondence in targets:
                callee_view = views[target_coordinate]
                direct_calls.append(
                    (
                        caller.entry,
                        seed.operation_key,
                        callee_view.analysis.entry,
                        call_position,
                        occurrence_ordinal,
                        correspondence,
                    )
                )
                for match in matches:
                    if match.kind is BoundaryKind.SOURCE:
                        source_spans = _boundary_state_spans(
                            provider,
                            boundary,
                            match,
                            callee_view,
                            len(callee_view.operations),
                        )
                        for fragment_ordinal, definition_id in enumerate(
                            callee_view.source_origin_definition_ids(source_spans)
                        ):
                            nodes[callee_view.analysis.entry].append(
                                ObservedBoundaryNode(
                                    BoundaryKind.SOURCE,
                                    match.label,
                                    callee_view.memory_graph.definition_nodes[definition_id],
                                    occurrence_ordinal,
                                    fragment_ordinal,
                                )
                            )
                    elif match.kind is BoundaryKind.SINK:
                        selectors = provider.state(boundary, match)
                        sink_nodes = _direct_sink_boundary_nodes(
                            caller_view,
                            match.label,
                            seed.operation_key,
                            call_position,
                            occurrence_ordinal,
                            selectors,
                        )
                        nodes[caller.entry].extend(sink_nodes)

    analyses = _analyses_from_boundary_nodes(preliminary, nodes)
    demands = {
        item.entry: {
            demand.canonical_key: demand
            for local_slice in item.slices
            for demand in _reachable_entry_demands(
                views[item.entry], local_slice
            )
        }
        for item in analyses
    }
    for _ in range(len(preliminary)):
        additions = 0
        existing = {
            entry: {
                (item.kind.value, item.label, item.node)
                for item in _canonical_boundary_nodes(values)
            }
            for entry, values in nodes.items()
        }
        for (
            caller_entry,
            call_operation_key,
            callee_entry,
            call_position,
            occurrence_ordinal,
            correspondence,
        ) in direct_calls:
            caller_view = views[caller_entry]
            for fragment_ordinal, demand in enumerate(
                sorted(
                    demands[callee_entry].values(),
                    key=lambda item: item.canonical_key,
                )
            ):
                caller_span, caller_demand = _project_sink_entry_demand(
                    caller_view,
                    demand,
                    call_position,
                    correspondence,
                    callee=views[callee_entry],
                    call_operation_key=call_operation_key,
                )
                if caller_demand is not None:
                    demand_key = caller_demand.canonical_key
                    if demand_key not in demands[caller_entry]:
                        demands[caller_entry][demand_key] = caller_demand
                        additions += 1
                if caller_span is None:
                    continue
                for boundary in _sink_boundary_nodes(
                    caller_view,
                    demand.label,
                    call_operation_key,
                    call_position,
                    occurrence_ordinal,
                    ((fragment_ordinal, caller_span),),
                ):
                    identity = (boundary.kind.value, boundary.label, boundary.node)
                    if identity in existing[caller_entry]:
                        continue
                    existing[caller_entry].add(identity)
                    nodes[caller_entry].append(boundary)
                    additions += 1
        if not additions:
            break
        analyses = _analyses_from_boundary_nodes(preliminary, nodes)
    return analyses

__all__ = (
    "ConfiguredFunctionAnalysis",
    "InterproceduralOriginProof",
    "InterproceduralTransferProof",
    "InterproceduralSliceCompletion",
    "build_observed_function_analyses",
    "complete_configured_interprocedural_slices",
)
