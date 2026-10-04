"""Finite address coordinates specialized at one observed call boundary."""

from __future__ import annotations

from .._scope_contracts import AddressCoordinate, VarnodeKindCode
from ..memory_contracts import MemoryDefinitionKind
from .configured_boundary_mapping import _mapped_or_observed_call_span
from .configured_call_values import _CallIntegerResolver
from .configured_value_domain import (
    FINITE_VALUE_LIMIT as _FINITE_VALUE_LIMIT,
    merge_finite_coordinate_sets as _merge_finite_coordinate_sets,
)


class _CallCoordinateResolver:
    """Resolve exact finite coordinates using caller state at one callsite."""

    def __init__(
        self,
        caller,
        callee,
        call_operation_key,
        call_position,
        correspondence=(),
    ) -> None:
        self._caller = caller
        self._callee = callee
        self._call_operation_key = call_operation_key
        self._call_position = call_position
        self._correspondence = correspondence
        self._integers = _CallIntegerResolver(
            caller,
            callee,
            call_operation_key,
            call_position,
            correspondence,
        )
        self._cache = {}
        self._active = set()

    def values_for_input(self, operation_key, varnode):
        direct = self._callee.complete_coordinate_values_for_input(
            operation_key,
            varnode,
        )
        if direct is not None:
            return direct
        resolved = self._callee._observed_input_definition(operation_key, varnode)
        if resolved is None:
            return None
        return self.values_for_definition(*resolved)

    def values_for_definition(self, definition_id, requested_span):
        direct = self._callee.complete_coordinate_values_for_definition(
            definition_id,
            requested_span,
        )
        if direct is not None:
            return direct
        key = (definition_id, requested_span.start, requested_span.size)
        if key in self._cache:
            return self._cache[key]
        if key in self._active:
            return None
        if not 0 <= definition_id < len(self._callee.memory.definitions):
            return None
        definition = self._callee.memory.definitions[definition_id]
        if not definition.span.contains(requested_span):
            return None
        self._active.add(key)
        try:
            if definition.kind is MemoryDefinitionKind.ENTRY:
                result = self._entry_values(requested_span)
            elif definition.kind is MemoryDefinitionKind.JOIN:
                result = _merge_finite_coordinate_sets(
                    tuple(
                        self.values_for_definition(source_id, requested_span)
                        for source_id in self._callee._join_sources.get(
                            definition_id,
                            (),
                        )
                    )
                )
            elif definition.kind is MemoryDefinitionKind.DATA_WRITE:
                result = self._values_from_write(
                    definition.operation_key,
                    definition.span,
                )
            else:
                result = None
        finally:
            self._active.remove(key)
        self._cache[key] = result
        return result

    def _entry_values(self, callee_span):
        caller_span = _mapped_or_observed_call_span(
            self._caller,
            self._callee,
            callee_span,
            self._call_operation_key,
            self._call_position,
            self._correspondence,
        )
        if caller_span is None:
            return None
        definition_id = self._caller.state_definition(
            caller_span,
            self._call_position,
        )
        if definition_id is None:
            return None
        return self._caller.complete_coordinate_values_for_definition(
            definition_id,
            caller_span,
        )

    def _values_from_write(self, operation_key, requested_span):
        operation = (
            None if operation_key is None else self._callee.operation(operation_key)
        )
        if operation_key is None or operation is None:
            return None
        if operation.opcode == "STORE" and len(operation.inputs) == 3:
            source = operation.inputs[2]
            return (
                self.values_for_input(operation_key, source)
                if source.byte_size == requested_span.size
                else None
            )
        if operation.output is None or operation.output.byte_size != requested_span.size:
            return None
        if operation.opcode in {"COPY", "CAST"} and len(operation.inputs) == 1:
            source = operation.inputs[0]
            return (
                self.values_for_input(operation_key, source)
                if source.byte_size == requested_span.size
                else None
            )
        if operation.opcode in {"INT_ADD", "INT_SUB"} and len(operation.inputs) == 2:
            return self._offset_coordinates(operation_key, operation, requested_span)
        if operation.opcode == "INT_AND" and len(operation.inputs) == 2:
            return self._masked_coordinates(operation_key, operation, requested_span)
        if operation.opcode != "LOAD" or len(operation.inputs) < 2:
            return None
        local_span = self._callee._relative_access_span(
            operation_key,
            read=True,
            byte_size=operation.output.byte_size,
        )
        if local_span is None:
            return None
        definition_id = self._callee.definition_for_span(operation_key, local_span)
        if definition_id is None:
            return None
        return self.values_for_definition(definition_id, local_span)

    def _offset_coordinates(self, operation_key, operation, requested_span):
        pairs = ((0, 1), (1, 0)) if operation.opcode == "INT_ADD" else ((0, 1),)
        candidate_sets = set()
        modulus = 1 << (requested_span.size * 8)
        for coordinate_index, value_index in pairs:
            coordinates = self.values_for_input(
                operation_key,
                operation.inputs[coordinate_index],
            )
            values = self._integers.values_for_input(
                operation_key,
                operation.inputs[value_index],
            )
            if (
                coordinates is None
                or values is None
                or len(coordinates) * len(values) > _FINITE_VALUE_LIMIT
            ):
                continue
            sign = -1 if operation.opcode == "INT_SUB" else 1
            candidate_sets.add(
                frozenset(
                    AddressCoordinate(
                        coordinate.space_id,
                        (coordinate.byte_offset + sign * value) % modulus,
                    )
                    for coordinate in coordinates
                    for value in values
                )
            )
        return next(iter(candidate_sets)) if len(candidate_sets) == 1 else None

    def _masked_coordinates(self, operation_key, operation, requested_span):
        candidate_sets = set()
        modulus = 1 << (requested_span.size * 8)
        for coordinate_index, mask_index in ((0, 1), (1, 0)):
            coordinates = self.values_for_input(
                operation_key,
                operation.inputs[coordinate_index],
            )
            masks = self._integers.values_for_input(
                operation_key,
                operation.inputs[mask_index],
            )
            if (
                coordinates is None
                or masks is None
                or len(coordinates) * len(masks) > _FINITE_VALUE_LIMIT
            ):
                continue
            candidate_sets.add(
                frozenset(
                    AddressCoordinate(
                        coordinate.space_id,
                        (coordinate.byte_offset & mask) % modulus,
                    )
                    for coordinate in coordinates
                    for mask in masks
                )
            )
        return next(iter(candidate_sets)) if len(candidate_sets) == 1 else None


__all__ = ["_CallCoordinateResolver"]
