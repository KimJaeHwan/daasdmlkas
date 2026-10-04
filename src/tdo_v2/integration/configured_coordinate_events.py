"""Coordinate write events and exact LOAD/STORE alias binding."""

from __future__ import annotations

from .._scope_contracts import AddressCoordinate, VarnodeKindCode
from ..memory_contracts import MemoryDefinitionKind
from ..model import ByteSpan, StorageObjectId, StorageObjectKind
from .configured_boundary_mapping import _caller_span_for_relative_entry
from .configured_call_coordinates import _CallCoordinateResolver
from .configured_event_order import _latest_preceding_events, _overlapping_events
from .configured_interprocedural_records import CoordinateWriteEvent as _CoordinateWriteEvent
from .configured_known_coordinates import (
    _observed_transient_coordinate_for_relative_entry,
)
from .configured_target_resolution import _selected_resolved_target
from .configured_value_domain import FINITE_VALUE_LIMIT as _FINITE_VALUE_LIMIT

def _caller_coordinate_write_events(caller, views):
    events = []
    for seed, naming in zip(
        caller.analysis.evidence.seeds.callsites,
        caller.analysis.evidence.naming.rows,
        strict=True,
    ):
        target = _selected_resolved_target(naming)
        if target is None:
            continue
        callee = views.get(target.coordinate)
        call_position = caller.position(seed.operation_key)
        if callee is None or call_position is None:
            continue
        resolver = _CallCoordinateResolver(
            caller,
            callee,
            seed.operation_key,
            call_position,
        )
        for definition_id, target_span in callee.terminal_data_writes():
            coordinates = _callee_written_coordinates(
                caller,
                callee,
                definition_id,
                call_position,
                views,
                seed.operation_key,
                resolver,
            )
            for coordinate in coordinates or ():
                events.append(
                    _CoordinateWriteEvent(
                        call_position,
                        seed.operation_key,
                        target_span,
                        coordinate,
                    )
                )
    return tuple(
        sorted(
            set(events),
            key=lambda item: (
                item.call_position,
                item.call_operation_key,
                item.target_span.canonical_key,
                item.coordinate,
            ),
        )
    )

def _bind_coordinate_event_memory_views(views):
    """Rebuild exact physical memory aliases for each short-lived view."""
    coordinate_events = {
        entry: _caller_coordinate_write_events(view, views)
        for entry, view in views.items()
    }
    for entry, view in views.items():
        _bind_exact_memory_spans_from_coordinate_events(
            view,
            coordinate_events[entry],
        )
    return coordinate_events

def _callee_written_coordinate(
    caller,
    callee,
    definition_id,
    call_position,
    views,
    call_operation_key=None,
    resolver=None,
):
    coordinates = _callee_written_coordinates(
        caller,
        callee,
        definition_id,
        call_position,
        views,
        call_operation_key,
        resolver,
    )
    return next(iter(coordinates)) if coordinates is not None and len(coordinates) == 1 else None


def _callee_written_coordinates(
    caller,
    callee,
    definition_id,
    call_position,
    views,
    call_operation_key=None,
    resolver=None,
):
    definition = callee.memory.definitions[definition_id]
    if resolver is None:
        resolver = _CallCoordinateResolver(
            caller,
            callee,
            call_operation_key,
            call_position,
        )
    direct = resolver.values_for_definition(
        definition_id,
        definition.span,
    )
    if direct is not None:
        return direct
    candidates = set()
    for operation_key, entry_span in _written_value_entry_reads(
        callee, definition_id
    ):
        caller_span = entry_span
        if caller_span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE:
            transient = _observed_transient_coordinate_for_relative_entry(
                caller,
                callee,
                operation_key,
                caller_span,
                call_operation_key,
            )
            if transient is not None:
                candidates.add(transient)
                continue
            caller_span = _caller_span_for_relative_entry(
                caller,
                callee,
                operation_key,
                caller_span,
                call_position,
                call_operation_key=call_operation_key,
            )
        if caller_span is None:
            continue
        caller_definition = caller.state_definition(caller_span, call_position)
        if caller_definition is None:
            continue
        caller_resolver = getattr(
            caller, "complete_coordinate_values_for_definition", None
        )
        coordinates = (
            None
            if caller_resolver is None
            else caller_resolver(caller_definition, caller_span)
        )
        if coordinates is not None:
            candidates.update(coordinates)
    return (
        frozenset(candidates)
        if 0 < len(candidates) <= _FINITE_VALUE_LIMIT
        else None
    )

def _written_value_entry_reads(view, definition_id):
    """Return only function-entry fragments that carry a written value."""
    rows = set()
    active = set()

    def walk(current_id, requested_span, consumer_operation_key):
        key = (current_id, requested_span.start, requested_span.size)
        if key in active or not 0 <= current_id < len(view.memory.definitions):
            return
        definition = view.memory.definitions[current_id]
        if not definition.span.contains(requested_span):
            return
        if definition.kind is MemoryDefinitionKind.ENTRY:
            rows.add((consumer_operation_key, requested_span))
            return
        if definition.kind is MemoryDefinitionKind.JOIN:
            active.add(key)
            try:
                for source_id in view._join_sources.get(current_id, ()):
                    walk(source_id, requested_span, consumer_operation_key)
            finally:
                active.remove(key)
            return
        if (
            definition.kind is not MemoryDefinitionKind.DATA_WRITE
            or definition.operation_key is None
        ):
            return
        operation_key = definition.operation_key
        operation = view.operation(operation_key)
        if operation is None:
            return
        active.add(key)
        try:
            if operation.opcode == "LOAD" and len(operation.inputs) >= 2:
                for read in view.memory.reads:
                    if view.memory.actions[read.action_id].operation_key != operation_key:
                        continue
                    for fragment in read.fragments:
                        for source_id in fragment.definition_ids:
                            walk(source_id, fragment.span, operation_key)
                return
            if operation.opcode == "STORE" and len(operation.inputs) == 3:
                inputs = (operation.inputs[2],)
            elif operation.opcode in {"COPY", "CAST", "INT_ZEXT", "INT_SEXT"}:
                inputs = operation.inputs[:1]
            elif operation.opcode in {
                "INT_ADD",
                "INT_SUB",
                "INT_MULT",
                "INT_LEFT",
                "INT_AND",
                "INT_OR",
                "INT_XOR",
            }:
                inputs = operation.inputs
            else:
                return
            for varnode in inputs:
                if varnode.kind is VarnodeKindCode.CONSTANT:
                    continue
                resolved = view._observed_input_definition(operation_key, varnode)
                if resolved is not None:
                    walk(resolved[0], resolved[1], operation_key)
        finally:
            active.remove(key)

    definition = view.memory.definitions[definition_id]
    walk(definition_id, definition.span, definition.operation_key)
    return tuple(
        sorted(rows, key=lambda item: (item[0] or "", item[1].canonical_key))
    )

def _bind_exact_memory_spans_from_coordinate_events(view, events):
    """Bind exact LOAD/STORE coordinates proven by physical value events."""
    program_scope = view.analysis.evidence.unit.scopes.program.scope
    for operation_key, (_, operation) in view.operations.items():
        if operation.opcode not in {"LOAD", "STORE"} or len(operation.inputs) < 2:
            continue
        selector = operation.inputs[0]
        if selector.kind is not VarnodeKindCode.CONSTANT:
            continue
        read = operation.opcode == "LOAD"
        target = (
            view.operation_exact_read_spans
            if read
            else view.operation_exact_write_spans
        )
        if operation_key in target:
            continue
        width = (
            operation.output.byte_size
            if read and operation.output is not None
            else operation.inputs[2].byte_size
            if not read and len(operation.inputs) == 3
            else None
        )
        coordinate = _coordinate_for_input_with_events(
            view,
            operation_key,
            operation.inputs[1],
            events,
        )
        if (
            width is None
            or coordinate is None
            or coordinate.space_id != selector.coordinate.byte_offset
        ):
            continue
        target[operation_key] = ByteSpan(
            StorageObjectId(
                StorageObjectKind.ADDRESS_SPACE,
                program_scope,
                coordinate.space_id,
            ),
            coordinate.byte_offset,
            width,
        )

def _coordinate_for_input_with_events(
    view,
    operation_key,
    varnode,
    events,
    active=None,
):
    direct = view.coordinate_for_input(operation_key, varnode)
    if direct is not None:
        return direct
    resolved = view._observed_input_definition(operation_key, varnode)
    if resolved is None:
        return None
    if active is None:
        active = set()
    return _coordinate_for_definition_with_events(
        view,
        resolved[0],
        resolved[1],
        operation_key,
        events,
        active,
    )

def _coordinate_for_definition_with_events(
    view,
    definition_id,
    requested_span,
    before_operation_key,
    events,
    active,
):
    key = (definition_id, requested_span.start, requested_span.size)
    if key in active or not 0 <= definition_id < len(view.memory.definitions):
        return None
    direct = view.coordinate_for_definition(definition_id, requested_span)
    if direct is not None:
        return direct
    definition = view.memory.definitions[definition_id]
    if definition.kind is MemoryDefinitionKind.ENTRY:
        matching = _latest_preceding_events(
            view,
            _overlapping_events(events, requested_span),
            before_operation_key,
        )
        exact = tuple(
            event
            for event in matching
            if event.target_span.contains(requested_span)
        )
        if len(exact) == 1:
            event = exact[0]
            return AddressCoordinate(
                event.coordinate.space_id,
                event.coordinate.byte_offset
                + requested_span.start
                - event.target_span.start,
            )
    if (
        definition.kind is not MemoryDefinitionKind.DATA_WRITE
        or definition.operation_key is None
    ):
        return None
    operation_key = definition.operation_key
    operation = view.operation(operation_key)
    if operation is None or operation.output is None:
        return None
    active.add(key)
    try:
        if operation.opcode in {"COPY", "CAST"} and len(operation.inputs) == 1:
            return _coordinate_for_input_with_events(
                view, operation_key, operation.inputs[0], events, active
            )
        if operation.opcode not in {"INT_ADD", "INT_SUB"} or len(operation.inputs) != 2:
            return None
        candidates = []
        pairs = ((0, 1), (1, 0)) if operation.opcode == "INT_ADD" else ((0, 1),)
        for coordinate_index, value_index in pairs:
            coordinate = _coordinate_for_input_with_events(
                view,
                operation_key,
                operation.inputs[coordinate_index],
                events,
                active,
            )
            value = view._exact_integer_for_input(
                operation_key,
                operation.inputs[value_index],
            )
            if coordinate is not None and value is not None:
                candidates.append((coordinate, value))
        if len(candidates) != 1:
            return None
        coordinate, value = candidates[0]
        if operation.opcode == "INT_SUB":
            value = -value
        return AddressCoordinate(
            coordinate.space_id,
            (coordinate.byte_offset + value)
            % (1 << (requested_span.size * 8)),
        )
    finally:
        active.remove(key)

__all__ = ["_bind_coordinate_event_memory_views","_bind_exact_memory_spans_from_coordinate_events","_callee_written_coordinate","_callee_written_coordinates","_caller_coordinate_write_events","_coordinate_for_definition_with_events","_coordinate_for_input_with_events","_written_value_entry_reads"]
