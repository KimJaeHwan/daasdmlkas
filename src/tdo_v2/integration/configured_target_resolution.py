"""Direct, indirect, and callback target resolution from admitted evidence."""

from __future__ import annotations

from .._scope_contracts import AddressCoordinate
from ..configured_naming_contracts import NamingResolutionState
from ..external_summary import ExternalCallBoundary
from .configured_known_coordinates import _known_function_coordinates
from .configured_physical_state import _physical_state_span
from .configured_reachability import _reachable_event_reads_for_input

def _resolved_target(naming):
    if naming.resolution.state is not NamingResolutionState.RESOLVED_NAMED:
        return None
    return _selected_resolved_target(naming)

def _selected_resolved_target(naming):
    if naming.resolution.state not in (
        NamingResolutionState.RESOLVED_NAMED,
        NamingResolutionState.RESOLVED_UNNAMED,
    ):
        return None
    ordinal = naming.resolution.terminal_target_ordinal
    if ordinal is None or ordinal >= len(naming.targets):
        return None
    return naming.targets[ordinal]

def _observed_internal_call_targets(
    view,
    seed,
    naming,
    views,
    coordinate_events=(),
    entry_coordinate_resolver=None,
):
    """Return only exact internal targets, independent of naming quality."""
    target = _selected_resolved_target(naming)
    if target is not None:
        return (target.coordinate,) if target.coordinate in views else ()
    if naming.resolution.state is not NamingResolutionState.INDIRECT:
        return ()
    return _observed_indirect_targets(
        view,
        seed.operation_key,
        views,
        coordinate_events,
        entry_coordinate_resolver,
    )

def _external_boundary(view, seed, target):
    aliases = tuple(
        sorted(
            {
                alias.value
                for alias in target.aliases
                if alias.policy_admissible
            }
        )
    )
    namespace = view.analysis.evidence.unit.scopes.program.evidence.translation_namespace
    return ExternalCallBoundary(
        f"{view.analysis.entry.space_id:x}:{view.analysis.entry.byte_offset:x}",
        seed.operation_key,
        aliases,
        namespace.language_id,
    )

def _external_callback_edges(caller, seed, target, views, provider):
    call_position = caller.position(seed.operation_key)
    if call_position is None:
        return ()
    rows = []
    for model in provider.callbacks(_external_boundary(caller, seed, target)):
        selector = _physical_state_span(
            caller, model.callback_pointer, call_position
        )
        if selector is None:
            continue
        definition_id = caller.state_definition(selector, call_position)
        if definition_id is None:
            continue
        for coordinate in _known_function_coordinates(
            caller, definition_id, selector, views
        ):
            callee = views[coordinate]
            correspondence = []
            for mapping in model.inputs:
                caller_span = _physical_state_span(
                    caller, mapping.caller_value, call_position
                )
                callee_span = _physical_state_span(
                    callee, mapping.callback_value, 0
                )
                if caller_span is None or callee_span is None:
                    correspondence = []
                    break
                correspondence.append((callee_span, caller_span))
            if len(correspondence) != len(model.inputs):
                continue
            if (
                len({callee_span for callee_span, _ in correspondence})
                != len(correspondence)
                or len({caller_span for _, caller_span in correspondence})
                != len(correspondence)
            ):
                continue
            rows.append((coordinate, tuple(correspondence)))
    return tuple(sorted(set(rows), key=lambda item: item[0]))

def _observed_indirect_targets(
    view,
    operation_key,
    views,
    coordinate_events=(),
    entry_coordinate_resolver=None,
):
    operation = view.operation(operation_key)
    if operation is None or operation.opcode != "CALLIND" or not operation.inputs:
        return ()
    flow_candidates = {
        target
        for target in view.operation_flow_targets.get(operation_key, ())
        if target in views
    }
    complete_resolver = getattr(view, "complete_coordinate_values_for_input", None)
    complete = (
        None
        if complete_resolver is None
        else complete_resolver(operation_key, operation.inputs[0])
    )
    if complete is not None:
        return (
            tuple(sorted(complete))
            if complete and all(target in views for target in complete)
            else ()
        )
    if entry_coordinate_resolver is not None:
        specialized = entry_coordinate_resolver.values_for_input(
            operation_key,
            operation.inputs[0],
        )
        if specialized is not None:
            return (
                tuple(sorted(specialized))
                if specialized and all(target in views for target in specialized)
                else ()
            )
    candidates = set(flow_candidates)
    coordinate = view.coordinate_for_input(operation_key, operation.inputs[0])
    if coordinate in views:
        candidates.add(coordinate)
    for value in view.integer_values_for_input(operation_key, operation.inputs[0]) or ():
        candidate = AddressCoordinate(view.analysis.entry.space_id, value)
        if candidate in views:
            candidates.add(candidate)
    read_rows = _reachable_event_reads_for_input(
        view, operation_key, operation.inputs[0]
    )
    latest = set()
    for read_span, read_operation_key in read_rows:
        matching = tuple(
            event
            for event in coordinate_events
            if event.target_span.overlaps(read_span)
            and view.definitely_precedes(
                event.call_operation_key,
                read_operation_key,
            )
        )
        latest.update(
            event
            for event in matching
            if not any(
                event is not other
                and view.definitely_precedes(
                    event.call_operation_key,
                    other.call_operation_key,
                )
                and view.definitely_precedes(
                    other.call_operation_key,
                    read_operation_key,
                )
                for other in matching
            )
        )
    candidates.update(
        event.coordinate for event in latest if event.coordinate in views
    )
    return tuple(sorted(candidates))

def _observed_indirect_target(
    view,
    operation_key,
    views,
    coordinate_events=(),
    entry_coordinate_resolver=None,
):
    targets = _observed_indirect_targets(
        view,
        operation_key,
        views,
        coordinate_events,
        entry_coordinate_resolver,
    )
    return targets[0] if len(targets) == 1 else None

__all__ = ["_external_boundary","_external_callback_edges","_observed_indirect_target","_observed_indirect_targets","_observed_internal_call_targets","_resolved_target","_selected_resolved_target"]
