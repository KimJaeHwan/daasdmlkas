"""Physical register and memory projection for configured analysis."""

from __future__ import annotations

from dataclasses import dataclass

from .._scope_contracts import VarnodeKindCode
from ..model import ByteSpan, StorageObjectId, StorageObjectKind
from ..observed_call_state import observed_call_state_projections
from ..physical_state import (
    PhysicalMemorySlice,
    PhysicalRegisterSlice,
    PhysicalStateResolver,
)
from .configured_function_view import _FunctionView

def _register_span(view, selector):
    register_spaces = tuple(
        row
        for row in view.analysis.evidence.unit.scopes.program.evidence.address_spaces
        if row.is_register_space
    )
    if len(register_spaces) != 1:
        return None
    return ByteSpan(
        StorageObjectId(
            StorageObjectKind.REGISTER_FILE,
            view.analysis.evidence.unit.scopes.program.scope,
            0,
        ),
        selector.byte_offset,
        selector.byte_size,
    )

@dataclass(frozen=True, slots=True)
class _FunctionPhysicalStateBackend:
    view: _FunctionView

    def register_span(self, selector: PhysicalRegisterSlice) -> ByteSpan | None:
        return _register_span(self.view, selector)

    def memory_candidates(
        self,
        selector: PhysicalMemorySlice,
        before_position: int,
    ) -> tuple[ByteSpan, ...]:
        base_span = _register_span(self.view, selector.base)
        if base_span is None:
            return ()
        definition_id = self.view.state_definition(base_span, before_position)
        if definition_id is None:
            return ()
        paths = self.view.complete_physical_pointer_candidates(
            definition_id,
            base_span,
        )
        candidates = {
            span
            for path in paths
            for address_space_id in self.view.loaded_memory_space_ids
            if (
                span := self.view._direct_span(
                    path.with_offset(selector.displacement),
                    selector.byte_size,
                    address_space_id,
                )
            )
            is not None
        }
        return tuple(sorted(candidates, key=lambda item: item.canonical_key))

    def value_ids(
        self,
        selector: PhysicalRegisterSlice | PhysicalMemorySlice,
        before_position: int,
    ) -> tuple[int, ...]:
        if type(selector) is PhysicalRegisterSlice:
            span = self.register_span(selector)
            definition_id = (
                None
                if span is None
                else self.view.state_definition(span, before_position)
            )
            return () if definition_id is None else (definition_id,)
        if type(selector) is not PhysicalMemorySlice:
            raise TypeError("physical value selector must be exact")

        candidates = self.memory_candidates(selector, before_position)
        materialized_ids = ()
        if len(candidates) == 1:
            definition_id = self.view.state_definition(
                candidates[0],
                before_position,
            )
            if definition_id is not None:
                materialized_ids = (definition_id,)

        relational_ids = _relational_memory_value_definition_ids(
            self.view,
            selector,
            before_position,
        )
        if materialized_ids:
            return materialized_ids
        return relational_ids if len(relational_ids) == 1 else ()

def _relational_memory_value_definition_ids(view, selector, before_position):
    """Resolve one latest STORE by an exact physical affine relation."""
    loaded_spaces = tuple(getattr(view, "loaded_memory_space_ids", ()))
    if len(loaded_spaces) != 1:
        return ()
    loaded_space = loaded_spaces[0]
    base_span = _register_span(view, selector.base)
    if base_span is None:
        return ()
    base_definition = view.state_definition(base_span, before_position)
    if base_definition is None:
        return ()
    target_relation = view.canonical_physical_affine_relation(
        base_definition,
        base_span,
        selector.displacement,
    )
    before_keys = tuple(
        operation_key
        for operation_key, (position, _) in view.operations.items()
        if position == before_position
    )
    if target_relation is None or len(before_keys) != 1:
        return ()
    before_key = before_keys[0]
    observation = getattr(view, "observation", None)
    transient_keys = (
        frozenset()
        if observation is None
        else frozenset(
            operation_key
            for projection in observed_call_state_projections(observation)
            for operation_key in projection.transient_operation_keys
        )
    )

    matches = []
    for operation_key, (position, operation) in view.operations.items():
        if (
            position >= before_position
            or operation.opcode != "STORE"
            or len(operation.inputs) != 3
            or operation.inputs[2].byte_size != selector.byte_size
            or not view.definitely_precedes(operation_key, before_key)
        ):
            continue
        address_space = operation.inputs[0]
        if (
            address_space.kind is not VarnodeKindCode.CONSTANT
            or address_space.coordinate.byte_offset != loaded_space
        ):
            continue
        store_pointer = view._observed_input_definition(
            operation_key,
            operation.inputs[1],
        )
        store_relation = (
            None
            if store_pointer is None
            else view.canonical_physical_affine_relation(*store_pointer)
        )
        if store_relation != target_relation:
            continue
        source = view.definition_for_input(operation_key, operation.inputs[2])
        if source is None:
            continue
        matches.append(
            (
                position,
                operation_key,
                source[0],
                address_space.coordinate.byte_offset,
            )
        )

    if len({row[3] for row in matches}) != 1:
        return ()

    latest = tuple(
        row
        for row in matches
        if not any(
            row[1] != other[1]
            and view.definitely_precedes(row[1], other[1])
            for other in matches
        )
    )
    if len(latest) != 1:
        return ()
    candidate = latest[0]
    target_root, target_span, target_offset = target_relation
    for operation_key, (_, operation) in view.operations.items():
        if (
            operation_key == candidate[1]
            or operation_key == before_key
            or operation_key in transient_keys
            or not view.may_precede(candidate[1], operation_key)
            or not view.may_precede(operation_key, before_key)
        ):
            continue
        if operation.opcode in {"CALL", "CALLIND"}:
            return ()
        if operation.opcode != "STORE" or len(operation.inputs) != 3:
            continue
        address_space = operation.inputs[0]
        if (
            address_space.kind is not VarnodeKindCode.CONSTANT
            or address_space.coordinate.byte_offset != loaded_space
        ):
            continue
        store_pointer = view._observed_input_definition(
            operation_key,
            operation.inputs[1],
        )
        store_relation = (
            None
            if store_pointer is None
            else view.canonical_physical_affine_relation(*store_pointer)
        )
        if store_relation is None:
            return ()
        store_root, store_span, store_offset = store_relation
        if store_root != target_root or store_span != target_span:
            return ()
        store_size = operation.inputs[2].byte_size
        if (
            store_offset < target_offset + selector.byte_size
            and target_offset < store_offset + store_size
        ):
            return ()
    return (candidate[2],)

def _boundary_state_spans(provider, boundary, match, view, position):
    selectors = provider.state(boundary, match)
    return PhysicalStateResolver(_FunctionPhysicalStateBackend(view)).resolve_all(
        selectors,
        position,
    )

def _physical_state_span(view, selector, before_position):
    return PhysicalStateResolver(_FunctionPhysicalStateBackend(view)).resolve(
        selector,
        before_position,
    )

def _physical_state_spans(view, selector, before_position):
    span = _physical_state_span(view, selector, before_position)
    return () if span is None else (span,)

__all__ = [
    "_FunctionPhysicalStateBackend",
    "_register_span",
    "_relational_memory_value_definition_ids",
]
