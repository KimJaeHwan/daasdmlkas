"""Finite physical values specialized at one observed call boundary."""

from __future__ import annotations

from .._scope_contracts import VarnodeKindCode
from ..memory_contracts import MemoryDefinitionKind
from .configured_boundary_mapping import _mapped_or_observed_call_span
from .configured_value_domain import (
    combine_finite_integer_values as _combine_finite_integer_values,
    merge_finite_value_sets as _merge_finite_value_sets,
    sign_extend as _sign_extend,
)


class _CallIntegerResolver:
    """Resolve only finite values proven by caller/callee physical spans."""

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
        self._cache = {}
        self._active = set()

    def values_for_input(self, operation_key, varnode):
        direct = self._callee.integer_values_for_input(operation_key, varnode)
        if direct is not None:
            return direct
        resolved = self._callee._observed_input_definition(operation_key, varnode)
        if resolved is None:
            return None
        return self.values_for_definition(*resolved)

    def values_for_definition(self, definition_id, requested_span):
        direct = self._callee.integer_values_for_definition(
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
                result = _merge_finite_value_sets(
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
        return self._caller.integer_values_for_definition(
            definition_id,
            caller_span,
        )

    def _values_from_write(self, operation_key, requested_span):
        operation = (
            None if operation_key is None else self._callee.operation(operation_key)
        )
        if operation_key is None or operation is None:
            return None
        source = None
        if operation.opcode == "STORE" and len(operation.inputs) == 3:
            source = operation.inputs[2]
        elif (
            operation.output is not None
            and operation.output.byte_size == requested_span.size
        ):
            if operation.opcode in {"COPY", "CAST"} and len(operation.inputs) == 1:
                source = operation.inputs[0]
            elif operation.opcode in {"INT_ZEXT", "INT_SEXT"} and len(operation.inputs) == 1:
                values = self.values_for_input(operation_key, operation.inputs[0])
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
                return _combine_finite_integer_values(
                    operation.opcode,
                    self.values_for_input(operation_key, operation.inputs[0]),
                    self.values_for_input(operation_key, operation.inputs[1]),
                    requested_span.size,
                )
            elif operation.opcode == "LOAD" and len(operation.inputs) >= 2:
                local_span = self._callee._relative_access_span(
                    operation_key,
                    read=True,
                    byte_size=operation.output.byte_size,
                )
                if local_span is None:
                    return None
                definition_id = self._callee.definition_for_span(
                    operation_key,
                    local_span,
                )
                if definition_id is None:
                    return None
                return self.values_for_definition(definition_id, local_span)
        if source is None or source.byte_size != requested_span.size:
            return None
        return self.values_for_input(operation_key, source)


__all__ = ["_CallIntegerResolver"]
