"""Address-coordinate behavior for a configured function view."""

from __future__ import annotations

from .._scope_contracts import AddressCoordinate, ValidatedOperation, ValidatedVarnode, VarnodeKindCode
from ..memory_contracts import MemoryDefinitionKind
from ..model import ByteSpan, ResolvedStorage, StorageObjectKind
from ..storage import _resolve_validated_storage
from .configured_value_domain import (
    FINITE_VALUE_LIMIT as _FINITE_VALUE_LIMIT,
    merge_finite_coordinate_sets as _merge_finite_coordinate_sets,
    storage_ref as _storage_ref,
)

class _FunctionCoordinateValueMixin:
    def coordinate_for_input(
        self, operation_key: str, varnode: ValidatedVarnode
    ) -> AddressCoordinate | None:
        if varnode.kind is VarnodeKindCode.ADDRESS:
            return varnode.coordinate
        resolved = self.definition_for_input(operation_key, varnode)
        if resolved is None:
            storage = _resolve_validated_storage(
                _storage_ref(varnode),
                self.analysis.evidence.unit.scopes.resolution_context,
            )
            position = self.position(operation_key)
            if type(storage) is ResolvedStorage and position is not None:
                definition_id = self._latest_definition(storage.span, position)
                if definition_id is not None:
                    resolved = (definition_id, storage.span)
        if resolved is None:
            return None
        return self.coordinate_for_definition(*resolved)

    def coordinate_for_definition(
        self, definition_id: int, requested_span: ByteSpan
    ) -> AddressCoordinate | None:
        cache_key = (definition_id, requested_span.start, requested_span.size)
        if cache_key in self._coordinate_cache:
            return self._coordinate_cache[cache_key]
        if cache_key in self._coordinate_active:
            return None
        if not 0 <= definition_id < len(self.memory.definitions):
            return None
        definition = self.memory.definitions[definition_id]
        if (
            definition.kind is not MemoryDefinitionKind.DATA_WRITE
            or not definition.span.contains(requested_span)
            or definition.operation_key is None
        ):
            return None
        operation_key = definition.operation_key
        operation = self.operation(operation_key)
        if operation is None:
            return None
        self._coordinate_active.add(cache_key)
        try:
            result = self._coordinate_from_write(
                operation_key, operation, requested_span
            )
        finally:
            self._coordinate_active.remove(cache_key)
        self._coordinate_cache[cache_key] = result
        return result

    def complete_coordinate_values_for_input(
        self, operation_key: str, varnode: ValidatedVarnode
    ) -> frozenset[AddressCoordinate] | None:
        """Return every exact coordinate carried by one finite SSA value."""
        resolved = self._observed_input_definition(operation_key, varnode)
        if resolved is None:
            return (
                frozenset((varnode.coordinate,))
                if varnode.kind is VarnodeKindCode.ADDRESS
                else None
            )
        return self.complete_coordinate_values_for_definition(*resolved)

    def complete_coordinate_values_for_definition(
        self, definition_id: int, requested_span: ByteSpan
    ) -> frozenset[AddressCoordinate] | None:
        cache_key = (definition_id, requested_span.start, requested_span.size)
        if cache_key in self._coordinate_values_cache:
            return self._coordinate_values_cache[cache_key]
        if cache_key in self._coordinate_values_active:
            return None
        if not 0 <= definition_id < len(self.memory.definitions):
            return None
        definition = self.memory.definitions[definition_id]
        if not definition.span.contains(requested_span):
            return None
        self._coordinate_values_active.add(cache_key)
        try:
            if definition.kind is MemoryDefinitionKind.JOIN:
                result = _merge_finite_coordinate_sets(
                    tuple(
                        self.complete_coordinate_values_for_definition(
                            source_id, requested_span
                        )
                        for source_id in self._join_sources.get(definition_id, ())
                    )
                )
            elif definition.kind is MemoryDefinitionKind.DATA_WRITE:
                operation = (
                    None
                    if definition.operation_key is None
                    else self.operation(definition.operation_key)
                )
                result = self._coordinate_values_from_write(
                    definition.operation_key,
                    operation,
                    requested_span,
                )
                reference = self.coordinate_reference_for_definition(
                    definition_id, requested_span
                )
                if reference is not None:
                    referenced = frozenset((reference,))
                    result = referenced if result is None else (
                        result if result == referenced else None
                    )
            else:
                result = None
        finally:
            self._coordinate_values_active.remove(cache_key)
        self._coordinate_values_cache[cache_key] = result
        return result

    def _coordinate_values_from_write(
        self,
        operation_key: str | None,
        operation: ValidatedOperation | None,
        requested_span: ByteSpan,
    ) -> frozenset[AddressCoordinate] | None:
        if operation_key is None or operation is None:
            return None
        if operation.opcode == "STORE" and len(operation.inputs) == 3:
            source = operation.inputs[2]
            if source.byte_size != requested_span.size:
                return None
            return self.complete_coordinate_values_for_input(operation_key, source)
        if operation.output is None or operation.output.byte_size != requested_span.size:
            return None
        if operation.opcode in {"COPY", "CAST"} and len(operation.inputs) == 1:
            source = operation.inputs[0]
            if source.byte_size != requested_span.size:
                return None
            return self.complete_coordinate_values_for_input(operation_key, source)
        if operation.opcode == "INT_AND" and len(operation.inputs) == 2:
            candidates = []
            modulus = 1 << (requested_span.size * 8)
            for coordinate_index, mask_index in ((0, 1), (1, 0)):
                coordinate_input = operation.inputs[coordinate_index]
                mask_input = operation.inputs[mask_index]
                if (
                    coordinate_input.byte_size != requested_span.size
                    or mask_input.byte_size != requested_span.size
                ):
                    continue
                coordinates = self.complete_coordinate_values_for_input(
                    operation_key, coordinate_input
                )
                masks = self.integer_values_for_input(operation_key, mask_input)
                if (
                    coordinates is None
                    or masks is None
                    or len(coordinates) * len(masks) > _FINITE_VALUE_LIMIT
                ):
                    continue
                candidates.append(
                    frozenset(
                        AddressCoordinate(
                            coordinate.space_id,
                            (coordinate.byte_offset & mask) % modulus,
                        )
                        for coordinate in coordinates
                        for mask in masks
                    )
                )
            distinct = frozenset(candidates)
            return next(iter(distinct)) if len(distinct) == 1 else None
        if operation.opcode != "LOAD" or len(operation.inputs) < 2:
            return None
        selector = operation.inputs[0]
        position = self.position(operation_key)
        if selector.kind is not VarnodeKindCode.CONSTANT or position is None:
            return None
        paths = self.complete_physical_pointer_candidates_for_input(
            operation_key, operation.inputs[1]
        )
        if not paths:
            return None
        spans = set()
        for path in paths:
            span = self._direct_span(
                path,
                operation.output.byte_size,
                selector.coordinate.byte_offset,
            )
            if span is None:
                return None
            effective = self.effective_access_span(
                operation_key,
                span,
                read=True,
            )
            if effective is None:
                return None
            spans.add(effective)
        values = []
        for span in sorted(spans, key=lambda item: item.canonical_key):
            source_id = self._latest_definition(span, position)
            if source_id is None:
                return None
            values.append(
                self.complete_coordinate_values_for_definition(source_id, span)
            )
        return _merge_finite_coordinate_sets(tuple(values))

    def coordinate_reference_for_definition(
        self, definition_id: int, requested_span: ByteSpan
    ) -> AddressCoordinate | None:
        """Return one explicit instruction reference carried by this write."""
        if not 0 <= definition_id < len(self.memory.definitions):
            return None
        definition = self.memory.definitions[definition_id]
        if (
            definition.kind is not MemoryDefinitionKind.DATA_WRITE
            or definition.operation_key is None
            or definition.span != requested_span
        ):
            return None
        operation = self.operation(definition.operation_key)
        if operation is None:
            return None
        if operation.opcode == "STORE" and len(operation.inputs) == 3:
            carrier_size = operation.inputs[2].byte_size
        elif operation.output is not None:
            carrier_size = operation.output.byte_size
        else:
            return None
        sibling_keys = getattr(self, "instruction_operation_keys", {}).get(
            definition.operation_key,
            (definition.operation_key,),
        )
        carriers = []
        for candidate_id, candidate in enumerate(self.memory.definitions):
            if (
                candidate.kind is not MemoryDefinitionKind.DATA_WRITE
                or candidate.operation_key not in sibling_keys
                or candidate.span.size != carrier_size
            ):
                continue
            candidate_operation = self.operation(candidate.operation_key)
            if candidate_operation is None:
                continue
            if candidate_operation.opcode == "STORE" and len(candidate_operation.inputs) == 3:
                carriers.append(candidate_id)
            elif (
                candidate_operation.output is not None
                and candidate.span.object_id.kind
                is not StorageObjectKind.FUNCTION_UNIQUE
            ):
                carriers.append(candidate_id)
        if carriers != [definition_id] or carrier_size != requested_span.size:
            return None
        references = getattr(self, "operation_function_references", {}).get(
            definition.operation_key, ()
        ) or self.operation_coordinate_references.get(definition.operation_key, ())
        if len(references) != 1:
            return None
        return references[0]

    def _coordinate_from_write(
        self,
        operation_key: str,
        operation: ValidatedOperation,
        requested_span: ByteSpan,
    ) -> AddressCoordinate | None:
        if operation.opcode == "STORE" and len(operation.inputs) == 3:
            source = operation.inputs[2]
            if source.byte_size != requested_span.size:
                return None
            return self.coordinate_for_input(operation_key, source)
        if operation.output is None or operation.output.byte_size != requested_span.size:
            return None
        if operation.opcode in {"COPY", "CAST"} and len(operation.inputs) == 1:
            source = operation.inputs[0]
            if source.byte_size != requested_span.size:
                return None
            return self.coordinate_for_input(operation_key, source)
        if operation.opcode != "LOAD" or len(operation.inputs) < 2:
            return None
        local_span = self._relative_access_span(
            operation_key,
            read=True,
            byte_size=operation.output.byte_size,
        )
        position = self.position(operation_key)
        if local_span is None or position is None:
            return None
        definition_id = self._latest_definition(local_span, position)
        if definition_id is None:
            return None
        return self.coordinate_for_definition(definition_id, local_span)


__all__ = ["_FunctionCoordinateValueMixin"]
