"""Fail-closed isolation of one finite root from legacy global completion.

This uses the same admitted target resolution as configured boundary discovery.
It is an isolation rule for that compatibility engine, not proof that every
unresolved machine-level indirect call cannot reach the excluded component.
"""

from __future__ import annotations

from .._scope_contracts import AddressCoordinate
from ..external_summary import ExternalSummaryProvider
from .configured_coordinate_events import _bind_coordinate_event_memory_views
from .configured_function_view import _FunctionView
from .configured_interprocedural_contracts import ConfiguredFunctionAnalysis
from .configured_target_resolution import (
    _external_callback_edges, _observed_internal_call_targets,
    _selected_resolved_target,
)


def _reachable(start, graph):
    reached = set()
    pending = [start]
    while pending:
        entry = pending.pop()
        if entry in reached:
            continue
        reached.add(entry)
        pending.extend(graph[entry] - reached)
    return reached


def _cyclic_nodes(graph, allowed):
    """Iterative SCC walk; no Python recursion depth or repeated closure walk."""
    visited = set()
    finishing = []
    for start in sorted(allowed):
        if start in visited:
            continue
        visited.add(start)
        stack = [(start, iter(sorted(graph[start] & allowed)))]
        while stack:
            node, children = stack[-1]
            child = next(children, None)
            if child is None:
                finishing.append(node)
                stack.pop()
            elif child not in visited:
                visited.add(child)
                stack.append((child, iter(sorted(graph[child] & allowed))))
    reverse = {entry: set() for entry in allowed}
    for entry in allowed:
        for target in graph[entry] & allowed:
            reverse[target].add(entry)
    assigned = set()
    cyclic = set()
    for start in reversed(finishing):
        if start in assigned:
            continue
        component = set()
        pending = [start]
        while pending:
            entry = pending.pop()
            if entry in assigned:
                continue
            assigned.add(entry)
            component.add(entry)
            pending.extend(reverse[entry] - assigned)
        if len(component) > 1 or start in graph[start]:
            cyclic.update(component)
    return cyclic


def isolated_finite_legacy_exclusions(
    analyses: tuple[ConfiguredFunctionAnalysis, ...],
    selected_entries: tuple[AddressCoordinate, ...],
    finite_entry: AddressCoordinate,
    external_provider: ExternalSummaryProvider,
) -> frozenset[AddressCoordinate]:
    """Exclude exactly the selected root and its observed reachable cycles.

    Every observed incoming edge from a retained function is a hard stop.
    This keeps shared, noncyclic source/sink helpers in legacy completion.
    """
    if (type(analyses) is not tuple or not analyses
            or any(type(item) is not ConfiguredFunctionAnalysis for item in analyses)
            or type(selected_entries) is not tuple
            or not selected_entries
            or len(set(selected_entries)) != len(selected_entries)
            or type(finite_entry) is not AddressCoordinate
            or finite_entry not in selected_entries):
        raise ValueError("mixed-profile dispatch needs unique admitted selections")
    views = {item.entry: _FunctionView(item) for item in analyses}
    if len(views) != len(analyses) or any(entry not in views for entry in selected_entries):
        raise ValueError("mixed-profile selected entry is missing or ambiguous")
    coordinate_events = _bind_coordinate_event_memory_views(views)
    graph = {entry: set() for entry in views}
    for entry, view in views.items():
        evidence = view.analysis.evidence
        for seed, naming in zip(evidence.seeds.callsites, evidence.naming.rows, strict=True):
            graph[entry].update(_observed_internal_call_targets(
                view, seed, naming, views, coordinate_events[entry],
            ))
            target = _selected_resolved_target(naming)
            if target is not None and target.is_external:
                graph[entry].update(coordinate for coordinate, _ in
                    _external_callback_edges(view, seed, target, views, external_provider))
    closure = _reachable(finite_entry, graph)
    cyclic = _cyclic_nodes(graph, closure)
    if not cyclic:
        raise ValueError("mixed-profile finite root has no observed recursive cycle")
    excluded = {finite_entry} | cyclic
    if any(graph[entry] & excluded for entry in views if entry not in excluded):
        raise ValueError("mixed-profile excluded component has an observed incoming call")
    if any(_reachable(entry, graph) & excluded for entry in selected_entries
           if entry != finite_entry):
        raise ValueError("another selected root reaches the finite component")
    return frozenset(excluded)
