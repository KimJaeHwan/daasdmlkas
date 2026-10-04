"""Exact function-coordinate recovery from observed physical state."""

from __future__ import annotations

from .._scope_contracts import AddressCoordinate, VarnodeKindCode
from ..memory_contracts import MemoryDefinitionKind
from ..model import StorageObjectKind
from ..observed_call_state import observed_call_state_projections
from ..physical_state import PhysicalMemorySlice, PhysicalRegisterSlice
from .configured_physical_state import _physical_state_span

def _observed_transient_coordinate_for_relative_entry(
    caller,
    callee,
    operation_key,
    entry_span,
    call_operation_key,
):
    """Read a coordinate only from one exact observed call-local memory write."""
    if call_operation_key is None:
        return None
    operation = callee.operation(operation_key)
    if operation is None or operation.opcode != "LOAD" or len(operation.inputs) < 2:
        return None
    selector = operation.inputs[0]
    if selector.kind is not VarnodeKindCode.CONSTANT:
        return None
    path = callee.pointer_for_input(operation_key, operation.inputs[1])
    position = callee.position(operation_key)
    if path is None or position is None:
        return None
    path = callee.resolve_local_pointer_prefix(
        path,
        before_position=position,
        address_space_id=selector.coordinate.byte_offset,
    )
    if not path.offsets:
        return None
    anchor = callee.memory.definitions[path.anchor_definition_id]
    if (
        anchor.kind is not MemoryDefinitionKind.ENTRY
        or anchor.span.object_id.kind is not StorageObjectKind.REGISTER_FILE
        or path.anchor_byte_offset != 0
        or len(path.offsets) != 1
    ):
        return None
    callee_selector = PhysicalMemorySlice(
        PhysicalRegisterSlice(anchor.span.start, path.byte_size),
        path.offsets[0],
        entry_span.size,
    )
    if _physical_state_span(callee, callee_selector, 0) != entry_span:
        return None
    candidates = set()
    for projection in observed_call_state_projections(caller.observation):
        if projection.call_operation_key != call_operation_key:
            continue
        caller_selector = projection.project_memory(callee_selector)
        if caller_selector == projection.transient_coordinate.selector:
            candidates.add(projection.transient_coordinate.coordinate)
    return next(iter(candidates)) if len(candidates) == 1 else None

def _known_function_coordinate(view, definition_id, span, views):
    complete_resolver = getattr(
        view, "complete_coordinate_values_for_definition", None
    )
    if complete_resolver is not None:
        complete = complete_resolver(definition_id, span)
        if complete is not None:
            return (
                next(iter(complete))
                if len(complete) == 1 and next(iter(complete)) in views
                else None
            )
    candidates = set()
    coordinate = view.coordinate_for_definition(definition_id, span)
    if coordinate in views:
        candidates.add(coordinate)
    reference_resolver = getattr(
        view, "coordinate_reference_for_definition", None
    )
    if reference_resolver is not None:
        reference = reference_resolver(definition_id, span)
        if reference in views:
            candidates.add(reference)
    value = view.constant_for_definition(definition_id, span)
    if value is not None:
        candidate = AddressCoordinate(view.analysis.entry.space_id, value)
        if candidate in views:
            candidates.add(candidate)
    for value in view.integer_values_for_definition(definition_id, span) or ():
        candidate = AddressCoordinate(view.analysis.entry.space_id, value)
        if candidate in views:
            candidates.add(candidate)
    return next(iter(candidates)) if len(candidates) == 1 else None

def _known_function_coordinates(view, definition_id, span, views):
    """Return every target only when one finite coordinate set is complete."""
    complete_resolver = getattr(
        view, "complete_coordinate_values_for_definition", None
    )
    complete = (
        None
        if complete_resolver is None
        else complete_resolver(definition_id, span)
    )
    if complete is not None:
        if complete and all(coordinate in views for coordinate in complete):
            return tuple(sorted(complete))
        return ()
    coordinate = _known_function_coordinate(view, definition_id, span, views)
    return () if coordinate is None else (coordinate,)

__all__ = ["_known_function_coordinate","_known_function_coordinates","_observed_transient_coordinate_for_relative_entry"]
