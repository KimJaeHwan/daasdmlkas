"""Physical byte-span correspondence across configured call boundaries."""

from __future__ import annotations

from .._scope_contracts import VarnodeKindCode
from ..memory_contracts import MemoryDefinitionKind
from ..model import ByteSpan, StorageObjectKind
from ..observed_call_state import observed_call_preserves_register, observed_call_state_projections
from ..physical_state import PhysicalMemorySlice, PhysicalRegisterSlice
from .configured_interprocedural_records import PointerPath as _PointerPath
from .configured_physical_state import _physical_state_span, _register_span
from .configured_value_domain import (
    compose_pointer_path as _compose_pointer_path,
    signed_width_value as _signed_width_value,
)

def _mapped_or_observed_call_span(
    caller,
    callee,
    callee_span,
    call_operation_key,
    call_position,
    correspondence,
):
    explicit = _corresponding_caller_span(callee_span, correspondence)
    if explicit is not None:
        return explicit
    mapped = callee_span
    if callee_span.object_id.kind is not StorageObjectKind.FUNCTION_RELATIVE:
        return mapped
    if callee is None or call_operation_key is None:
        return None
    projections = tuple(
        item
        for item in observed_call_state_projections(caller.observation)
        if item.call_operation_key == call_operation_key
    )
    candidates = set()
    for projection in projections:
        transition = projection.memory_transition
        callee_selector = PhysicalMemorySlice(
            transition.callee_base,
            _signed_width_value(
                callee_span.start,
                transition.callee_base.byte_size,
            ),
            callee_span.size,
        )
        if _physical_state_span(callee, callee_selector, 0) != callee_span:
            continue
        caller_selector = projection.project_memory(callee_selector)
        if caller_selector is None:
            continue
        caller_span = _physical_state_span(caller, caller_selector, call_position)
        if caller_span is not None:
            candidates.add(caller_span)
    return next(iter(candidates)) if len(candidates) == 1 else None

def _mapped_or_observed_pointer_anchor(
    caller,
    callee,
    callee_anchor,
    offsets,
    call_operation_key,
    call_position,
    correspondence,
):
    explicit = _corresponding_caller_span(callee_anchor, correspondence)
    if explicit is not None:
        return explicit, offsets
    mapped = callee_anchor
    if correspondence:
        if (
            callee is None
            or not offsets
            or callee_anchor.object_id.kind is not StorageObjectKind.REGISTER_FILE
        ):
            return None, ()
        entry_value = _physical_state_span(
            callee,
            PhysicalMemorySlice(
                PhysicalRegisterSlice(callee_anchor.start, callee_anchor.size),
                offsets[0],
                callee_anchor.size,
            ),
            0,
        )
        mapped_value = (
            None
            if entry_value is None
            else _mapped_caller_span(entry_value, correspondence)
        )
        if mapped_value is None or mapped_value == entry_value:
            return None, ()
        return mapped_value, offsets[1:]
    if callee is None or call_operation_key is None or not offsets:
        return None, ()
    if callee_anchor.object_id.kind is not StorageObjectKind.REGISTER_FILE:
        return None, ()
    base = PhysicalRegisterSlice(callee_anchor.start, callee_anchor.size)
    projections = tuple(
        item
        for item in observed_call_state_projections(caller.observation)
        if item.call_operation_key == call_operation_key
    )
    candidates = set()
    callee_selector = PhysicalMemorySlice(base, offsets[0], callee_anchor.size)
    for projection in projections:
        caller_selector = projection.project_memory(callee_selector)
        if caller_selector is None:
            continue
        if (
            _register_span(callee, callee_selector.base) != callee_anchor
            or _register_span(caller, caller_selector.base) != mapped
        ):
            continue
        candidates.add((mapped, (caller_selector.displacement, *offsets[1:])))
    if len(candidates) == 1:
        return next(iter(candidates))
    if candidates:
        return None, ()
    if (
        _register_span(callee, base) == callee_anchor
        and _register_span(caller, base) == mapped
        and observed_call_preserves_register(
            caller.observation,
            call_operation_key,
            base,
        )
    ):
        return mapped, offsets
    return None, ()

def _mapped_caller_span(callee_span, correspondence):
    mapped = _corresponding_caller_span(callee_span, correspondence)
    return callee_span if mapped is None else mapped

def _corresponding_caller_span(callee_span, correspondence):
    for mapped_callee, mapped_caller in correspondence:
        if not mapped_callee.contains(callee_span):
            continue
        offset = callee_span.start - mapped_callee.start
        if offset + callee_span.size > mapped_caller.size:
            continue
        return ByteSpan(
            mapped_caller.object_id,
            mapped_caller.start + offset,
            callee_span.size,
        )
    return None

def _caller_actual_pointer(
    caller,
    callee,
    call_operation_key,
    callee_entry_span,
    call_position,
    correspondence=(),
):
    caller_span = _mapped_or_observed_call_span(
        caller,
        callee,
        callee_entry_span,
        call_operation_key,
        call_position,
        correspondence,
    )
    if caller_span is None:
        return None
    return _pointer_at_span(caller, caller_span, call_position)

def _pointer_at_span(caller, caller_span, call_position):
    definition_id = caller.state_definition(caller_span, call_position)
    if definition_id is None:
        return None
    return caller.pointer_for_definition(definition_id, caller_span)

def _caller_span_for_relative_entry(
    caller,
    callee,
    operation_key,
    entry_span,
    call_position,
    correspondence=(),
    *,
    call_operation_key=None,
):
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
    address_space_id = selector.coordinate.byte_offset
    path = callee.resolve_local_pointer_prefix(
        path,
        before_position=position,
        address_space_id=address_space_id,
    )
    if (
        correspondence
        and path.offsets
        and callable(getattr(callee, "materialize_path", None))
    ):
        prefix_path = _PointerPath(
            path.anchor_definition_id,
            path.anchor_byte_offset,
            (path.offsets[0],),
            path.byte_size,
            address_space_id,
        )
        prefix_span = callee.materialize_path(
            prefix_path,
            before_position=position,
            target_size=path.byte_size,
            address_space_id=address_space_id,
        )
        matches = (
            ()
            if prefix_span is None
            else tuple(
                (mapped_callee, mapped_caller)
                for mapped_callee, mapped_caller in correspondence
                if mapped_callee.contains(prefix_span)
                and (
                    prefix_span.start - mapped_callee.start + prefix_span.size
                    <= mapped_caller.size
                )
            )
        )
        if len(matches) > 1:
            return None
        if len(matches) == 1:
            mapped_callee, mapped_caller = matches[0]
            prefix_offset = prefix_span.start - mapped_callee.start
            caller_prefix_span = ByteSpan(
                mapped_caller.object_id,
                mapped_caller.start + prefix_offset,
                prefix_span.size,
            )
            remaining_offsets = path.offsets[1:]
            if not remaining_offsets:
                return (
                    caller_prefix_span
                    if caller_prefix_span.size == entry_span.size
                    else None
                )
            definition_id = caller.state_definition(
                caller_prefix_span, call_position
            )
            if definition_id is None:
                return None
            caller_pointer = caller.pointer_for_definition(
                definition_id, caller_prefix_span
            )
            if caller_pointer is None:
                return None
            combined = _compose_pointer_path(
                caller_pointer, remaining_offsets, address_space_id
            )
            return caller.materialize_path(
                combined,
                before_position=call_position,
                target_size=entry_span.size,
                address_space_id=address_space_id,
            )
    return _caller_span_for_entry_path(
        caller,
        callee,
        path,
        entry_span.size,
        call_position,
        correspondence,
        call_operation_key=call_operation_key,
        address_space_id=address_space_id,
    )


def _caller_span_for_entry_path(
    caller,
    callee,
    path,
    target_size,
    call_position,
    correspondence=(),
    *,
    call_operation_key=None,
    address_space_id=None,
):
    """Project one ENTRY-anchored physical pointer path into the caller."""
    combined = _caller_path_for_entry_path(
        caller,
        callee,
        path,
        call_position,
        correspondence,
        call_operation_key=call_operation_key,
        address_space_id=address_space_id,
    )
    if combined is None:
        return None
    effective_space = path.address_space_id if address_space_id is None else address_space_id
    return caller.materialize_path(
        combined,
        before_position=call_position,
        target_size=target_size,
        address_space_id=effective_space,
    )


def _caller_path_for_entry_path(
    caller,
    callee,
    path,
    call_position,
    correspondence=(),
    *,
    call_operation_key=None,
    address_space_id=None,
):
    """Preserve an ENTRY-anchored pointer path across one physical call edge."""
    anchor = callee.memory.definitions[path.anchor_definition_id]
    if anchor.kind is not MemoryDefinitionKind.ENTRY:
        return None
    anchor_span = ByteSpan(
        anchor.span.object_id,
        anchor.span.start + path.anchor_byte_offset,
        path.byte_size,
    )
    caller_anchor, caller_offsets = _mapped_or_observed_pointer_anchor(
        caller,
        callee,
        anchor_span,
        path.offsets,
        call_operation_key,
        call_position,
        correspondence,
    )
    if caller_anchor is None:
        return None
    actual = _pointer_at_span(caller, caller_anchor, call_position)
    if actual is None:
        return None
    effective_space = path.address_space_id if address_space_id is None else address_space_id
    return _compose_pointer_path(actual, caller_offsets, effective_space)


def _caller_span_for_entry_path_through_context(
    caller,
    callee,
    path,
    target_size,
    call_position,
    correspondence=(),
    *,
    call_operation_key=None,
    address_space_id=None,
    caller_entry_context=None,
):
    """Keep pointer provenance through nested calls and materialize only once."""
    current_view = caller
    current_path = _caller_path_for_entry_path(
        caller,
        callee,
        path,
        call_position,
        correspondence,
        call_operation_key=call_operation_key,
        address_space_id=address_space_id,
    )
    if current_path is None:
        return None
    context = caller_entry_context
    while context is not None:
        if context.child is not current_view:
            return None
        current_path = _caller_path_for_entry_path(
            context.parent,
            current_view,
            current_path,
            context.call_position,
            context.correspondence,
            call_operation_key=context.call_operation_key,
            address_space_id=current_path.address_space_id,
        )
        if current_path is None:
            return None
        current_view = context.parent
        call_position = context.call_position
        context = context.parent_context
    effective_space = (
        current_path.address_space_id
        if address_space_id is None
        else address_space_id
    )
    return current_view.materialize_path(
        current_path,
        before_position=call_position,
        target_size=target_size,
        address_space_id=effective_space,
    )

__all__ = ["_caller_actual_pointer","_caller_path_for_entry_path","_caller_span_for_entry_path","_caller_span_for_entry_path_through_context","_caller_span_for_relative_entry","_corresponding_caller_span","_mapped_caller_span","_mapped_or_observed_call_span","_mapped_or_observed_pointer_anchor","_pointer_at_span"]
