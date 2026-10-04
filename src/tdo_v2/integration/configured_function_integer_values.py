"""Finite integer-value behavior for a configured function view."""

from __future__ import annotations

from .._scope_contracts import ValidatedOperation, ValidatedVarnode, VarnodeKindCode
from ..memory_contracts import MemoryDefinitionKind
from ..model import ByteSpan, ResolvedStorage
from ..storage import _resolve_validated_storage
from .configured_value_domain import (
    combine_finite_integer_values as _combine_finite_integer_values,
    merge_finite_value_sets as _merge_finite_value_sets,
    sign_extend as _sign_extend,
    signed_constant as _signed_constant,
    signed_width_value as _signed_width_value,
    storage_ref as _storage_ref,
)

class _FunctionIntegerValueMixin:
    def _exact_integer_for_input(
        self, operation_key: str, varnode: ValidatedVarnode
    ) -> int | None:
        value = self.constant_for_input(operation_key, varnode)
        if value is not None:
            return value
        values = self.integer_values_for_input(operation_key, varnode)
        if values is None or len(values) != 1:
            return None
        return _signed_width_value(next(iter(values)), varnode.byte_size)

    def constant_for_input(
        self, operation_key: str, varnode: ValidatedVarnode
    ) -> int | None:
        if varnode.kind is VarnodeKindCode.CONSTANT:
            return _signed_constant(varnode)
        resolved = self.definition_for_input(operation_key, varnode)
        if resolved is None:
            return None
        return self.constant_for_definition(*resolved)

    def constant_for_definition(
        self, definition_id: int, requested_span: ByteSpan
    ) -> int | None:
        cache_key = (definition_id, requested_span.start, requested_span.size)
        if cache_key in self._constant_cache:
            return self._constant_cache[cache_key]
        if cache_key in self._constant_active:
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
        operation = self.operation(definition.operation_key)
        if (
            operation is None
            or operation.output is None
            or operation.output.byte_size != requested_span.size
            or operation.opcode not in {"COPY", "CAST"}
            or len(operation.inputs) != 1
            or operation.inputs[0].byte_size != requested_span.size
        ):
            return None
        self._constant_active.add(cache_key)
        try:
            result = self.constant_for_input(
                definition.operation_key, operation.inputs[0]
            )
        finally:
            self._constant_active.remove(cache_key)
        self._constant_cache[cache_key] = result
        return result

    def integer_values_for_input(
        self, operation_key: str, varnode: ValidatedVarnode
    ) -> frozenset[int] | None:
        """Return a small, exact finite value set carried by observed SSA."""
        if varnode.kind in {VarnodeKindCode.CONSTANT, VarnodeKindCode.ADDRESS}:
            return frozenset(
                (varnode.coordinate.byte_offset % (1 << (varnode.byte_size * 8)),)
            )
        resolved = self._observed_input_definition(operation_key, varnode)
        if resolved is None:
            return None
        return self.integer_values_for_definition(*resolved)

    def _observed_input_definition(
        self, operation_key: str, varnode: ValidatedVarnode
    ) -> tuple[int, ByteSpan] | None:
        resolved = self.definition_for_input(operation_key, varnode)
        if resolved is not None:
            return resolved
        storage = _resolve_validated_storage(
            _storage_ref(varnode),
            self.analysis.evidence.unit.scopes.resolution_context,
        )
        position = self.position(operation_key)
        if type(storage) is not ResolvedStorage or position is None:
            return None
        definition_id = self._latest_definition(storage.span, position)
        return (
            None
            if definition_id is None
            else (definition_id, storage.span)
        )

    def integer_values_for_definition(
        self, definition_id: int, requested_span: ByteSpan
    ) -> frozenset[int] | None:
        cache_key = (definition_id, requested_span.start, requested_span.size)
        if cache_key in self._integer_values_cache:
            return self._integer_values_cache[cache_key]
        if cache_key in self._integer_values_active:
            return None
        if not 0 <= definition_id < len(self.memory.definitions):
            return None
        definition = self.memory.definitions[definition_id]
        if not definition.span.contains(requested_span):
            return None
        self._integer_values_active.add(cache_key)
        try:
            if definition.kind is MemoryDefinitionKind.JOIN:
                result = _merge_finite_value_sets(
                    tuple(
                        self.integer_values_for_definition(source_id, requested_span)
                        for source_id in self._join_sources.get(definition_id, ())
                    )
                )
            elif definition.kind is MemoryDefinitionKind.DATA_WRITE:
                result = self._integer_values_from_write(
                    definition.operation_key, definition.span
                )
                if result is not None and requested_span != definition.span:
                    result = (
                        frozenset(
                            value % (1 << (requested_span.size * 8))
                            for value in result
                        )
                        if requested_span.start == definition.span.start
                        else None
                    )
            else:
                result = None
        finally:
            self._integer_values_active.remove(cache_key)
        self._integer_values_cache[cache_key] = result
        return result

    def _integer_values_from_write(
        self, operation_key: str | None, requested_span: ByteSpan
    ) -> frozenset[int] | None:
        operation = None if operation_key is None else self.operation(operation_key)
        if operation_key is None or operation is None:
            return None
        source = None
        if operation.opcode == "STORE" and len(operation.inputs) == 3:
            source = operation.inputs[2]
        elif operation.output is not None and operation.output.byte_size == requested_span.size:
            if operation.opcode in {"COPY", "CAST"} and len(operation.inputs) == 1:
                source = operation.inputs[0]
            elif operation.opcode in {"INT_ZEXT", "INT_SEXT"} and len(operation.inputs) == 1:
                values = self.integer_values_for_input(
                    operation_key, operation.inputs[0]
                )
                if values is None:
                    return None
                source_bits = operation.inputs[0].byte_size * 8
                target_bits = requested_span.size * 8
                if operation.opcode == "INT_ZEXT":
                    return frozenset(value % (1 << source_bits) for value in values)
                return frozenset(
                    _sign_extend(value, source_bits, target_bits) for value in values
                )
            elif operation.opcode in {
                "INT_ADD",
                "INT_SUB",
                "INT_MULT",
                "INT_LEFT",
                "INT_AND",
                "INT_OR",
                "INT_XOR",
            } and len(operation.inputs) == 2:
                if operation.opcode == "INT_XOR":
                    left_definition = self._observed_input_definition(
                        operation_key,
                        operation.inputs[0],
                    )
                    right_definition = self._observed_input_definition(
                        operation_key,
                        operation.inputs[1],
                    )
                    if (
                        left_definition is not None
                        and left_definition == right_definition
                    ):
                        return frozenset((0,))
                left = self.integer_values_for_input(operation_key, operation.inputs[0])
                right = self.integer_values_for_input(operation_key, operation.inputs[1])
                return _combine_finite_integer_values(
                    operation.opcode,
                    left,
                    right,
                    requested_span.size,
                )
            elif operation.opcode == "LOAD" and len(operation.inputs) >= 2:
                return self._integer_values_from_load(operation_key, operation)
        if source is None or source.byte_size != requested_span.size:
            return None
        return self.integer_values_for_input(operation_key, source)

    def _integer_values_from_load(
        self, operation_key: str, operation: ValidatedOperation
    ) -> frozenset[int] | None:
        if operation.output is None:
            return None
        local_span = self._relative_access_span(
            operation_key,
            read=True,
            byte_size=operation.output.byte_size,
        )
        if local_span is not None:
            definition_id = self.definition_for_span(operation_key, local_span)
            if definition_id is not None:
                result = self.integer_values_for_definition(definition_id, local_span)
                if result is not None:
                    return result
        selector = operation.inputs[0]
        if selector.kind is not VarnodeKindCode.CONSTANT:
            return None
        position = self.position(operation_key)
        if position is None:
            return None
        values = []
        for path in self.pointer_candidates_for_input(
            operation_key, operation.inputs[1]
        ):
            span = self._direct_span(
                path,
                operation.output.byte_size,
                selector.coordinate.byte_offset,
            )
            if span is None:
                continue
            effective = self.effective_access_span(
                operation_key,
                span,
                read=True,
            )
            if effective is None:
                continue
            definition_id = self._latest_definition(effective, position)
            if definition_id is None:
                continue
            candidate = self.integer_values_for_definition(
                definition_id,
                effective,
            )
            if candidate is not None:
                values.append(candidate)
        return _merge_finite_value_sets(tuple(values))


__all__ = ["_FunctionIntegerValueMixin"]
