"""Pointer-path behavior for a configured function view."""

from __future__ import annotations

from .._scope_contracts import ValidatedVarnode, VarnodeKindCode
from ..memory_contracts import MemoryDefinitionKind
from ..model import ByteSpan
from .configured_bounded_values import bounded_integer_values_for_input
from .configured_interprocedural_records import PointerPath as _PointerPath
from .configured_value_domain import (
    pointer_path_sort_key as _pointer_path_sort_key,
    signed_width_value as _signed_width_value,
)

class _FunctionPointerValueMixin:
    def pointer_for_input(
        self, operation_key: str, varnode: ValidatedVarnode
    ) -> _PointerPath | None:
        resolved = self.definition_for_input(operation_key, varnode)
        if resolved is None:
            return None
        return self.pointer_for_definition(*resolved)

    def pointer_for_definition(
        self, definition_id: int, requested_span: ByteSpan
    ) -> _PointerPath | None:
        cache_key = (definition_id, requested_span.start, requested_span.size)
        if cache_key in self._pointer_cache:
            return self._pointer_cache[cache_key]
        if cache_key in self._pointer_active:
            return None
        if not 0 <= definition_id < len(self.memory.definitions):
            return None
        definition = self.memory.definitions[definition_id]
        if not definition.span.contains(requested_span):
            return None
        self._pointer_active.add(cache_key)
        try:
            if definition.kind is MemoryDefinitionKind.ENTRY:
                result = _PointerPath(
                    definition_id,
                    requested_span.start - definition.span.start,
                    (0,),
                    requested_span.size,
                )
            elif definition.kind is MemoryDefinitionKind.DATA_WRITE:
                result = self._pointer_from_write(definition, requested_span)
            else:
                result = None
        finally:
            self._pointer_active.remove(cache_key)
        self._pointer_cache[cache_key] = result
        return result

    def _pointer_from_write(self, definition, requested_span) -> _PointerPath | None:
        operation_key = definition.operation_key
        operation = self.operation(operation_key)
        if operation_key is None or operation is None:
            return None
        source = None
        if operation.opcode == "STORE" and len(operation.inputs) == 3:
            source = operation.inputs[2]
        elif operation.output is not None and operation.output.byte_size == requested_span.size:
            if operation.opcode in {"COPY", "CAST"} and len(operation.inputs) == 1:
                source = operation.inputs[0]
            elif operation.opcode == "LOAD" and len(operation.inputs) >= 2:
                address = self.pointer_for_input(operation_key, operation.inputs[1])
                selector = operation.inputs[0]
                if (
                    address is None
                    or selector.kind is not VarnodeKindCode.CONSTANT
                    or operation.output.byte_size != requested_span.size
                ):
                    return None
                local_span = self._relative_access_span(
                    operation_key,
                    read=True,
                    byte_size=operation.output.byte_size,
                )
                position = self.position(operation_key)
                if local_span is not None and position is not None:
                    definition_id = self._latest_definition(local_span, position)
                    if definition_id is not None:
                        local = self.pointer_for_definition(
                            definition_id, local_span
                        )
                        if local is not None:
                            return local
                return address.through_load(
                    selector.coordinate.byte_offset,
                    operation.output.byte_size,
                )
            elif operation.opcode == "INT_ADD" and len(operation.inputs) == 2:
                return self._pointer_add(operation_key, operation.inputs, requested_span.size, 1)
            elif operation.opcode == "INT_SUB" and len(operation.inputs) == 2:
                return self._pointer_add(operation_key, operation.inputs, requested_span.size, -1)
        if source is None or source.byte_size != requested_span.size:
            return None
        return self.pointer_for_input(operation_key, source)

    def _pointer_add(self, operation_key, inputs, byte_size, sign) -> _PointerPath | None:
        if sign == -1:
            value, constant_input = inputs
            displacement = self._exact_integer_for_input(
                operation_key, constant_input
            )
            if displacement is None:
                return None
        else:
            resolved = tuple(
                (item, self._exact_integer_for_input(operation_key, item))
                for item in inputs
            )
            constants = tuple(
                (item, constant)
                for item, constant in resolved
                if constant is not None
            )
            values = tuple(item for item, constant in resolved if constant is None)
            if len(constants) != 1 or len(values) != 1:
                return None
            value = values[0]
            constant_input, displacement = constants[0]
        if constant_input.byte_size != byte_size or value.byte_size != byte_size:
            return None
        base = self.pointer_for_input(operation_key, value)
        if base is None:
            return None
        return base.with_offset(displacement if sign == 1 else -displacement)

    def pointer_candidates_for_input(
        self, operation_key: str, varnode: ValidatedVarnode
    ) -> tuple[_PointerPath, ...]:
        exact = self.pointer_for_input(operation_key, varnode)
        if exact is not None:
            return (exact,)
        resolved = self._observed_input_definition(operation_key, varnode)
        if resolved is None:
            return ()
        return self.pointer_candidates_for_definition(*resolved)

    def pointer_candidates_for_definition(
        self, definition_id: int, requested_span: ByteSpan
    ) -> tuple[_PointerPath, ...]:
        cache_key = (definition_id, requested_span.start, requested_span.size)
        cached = self._pointer_candidates_cache.get(cache_key)
        if cached is not None:
            return cached
        if cache_key in self._pointer_candidates_active:
            return ()
        if not 0 <= definition_id < len(self.memory.definitions):
            return ()
        definition = self.memory.definitions[definition_id]
        if not definition.span.contains(requested_span):
            return ()
        self._pointer_candidates_active.add(cache_key)
        try:
            if definition.kind is MemoryDefinitionKind.JOIN:
                rows = []
                for source_id in self._join_sources.get(definition_id, ()):
                    exact = self.pointer_for_definition(source_id, requested_span)
                    if exact is not None:
                        rows.append(exact)
                    else:
                        rows.extend(
                            self.pointer_candidates_for_definition(
                                source_id, requested_span
                            )
                        )
            elif definition.kind is MemoryDefinitionKind.DATA_WRITE:
                rows = self._pointer_candidates_from_write(
                    definition.operation_key, requested_span
                )
            else:
                rows = ()
        finally:
            self._pointer_candidates_active.remove(cache_key)
        result = tuple(sorted(set(rows), key=_pointer_path_sort_key))
        self._pointer_candidates_cache[cache_key] = result
        return result

    def complete_physical_pointer_candidates(
        self,
        definition_id: int,
        requested_span: ByteSpan,
        *,
        integer_values_for_input=None,
    ) -> tuple[_PointerPath, ...]:
        """Solve a finite pointer relation and reject non-converging cycles."""
        value_resolver = (
            self.integer_values_for_input
            if integer_values_for_input is None
            else integer_values_for_input
        )
        root = (definition_id, requested_span)
        rules: dict[
            tuple[int, ByteSpan],
            list[
                tuple[
                    tuple[int, ByteSpan] | None,
                    str,
                    int,
                    _PointerPath | None,
                ]
            ],
        ] = {}

        def dependency_for_input(operation_key, varnode, expected_size):
            resolved = self._observed_input_definition(operation_key, varnode)
            if resolved is None or resolved[1].size != expected_size:
                return None
            return resolved

        def discover(key):
            if key in rules:
                return True
            current_id, current_span = key
            if not 0 <= current_id < len(self.memory.definitions):
                return False
            definition = self.memory.definitions[current_id]
            if not definition.span.contains(current_span):
                return False
            rules[key] = []
            if definition.kind is MemoryDefinitionKind.ENTRY:
                rules[key].append(
                    (
                        None,
                        "seed",
                        0,
                        _PointerPath(
                            current_id,
                            current_span.start - definition.span.start,
                            (0,),
                            current_span.size,
                        ),
                    )
                )
                return True
            if definition.kind is MemoryDefinitionKind.JOIN:
                sources = self._join_sources.get(current_id, ())
                if not sources:
                    return False
                for source_id in sources:
                    dependency = (source_id, current_span)
                    rules[key].append((dependency, "offset", 0, None))
                    if not discover(dependency):
                        return False
                return True
            if (
                definition.kind is not MemoryDefinitionKind.DATA_WRITE
                or definition.operation_key is None
            ):
                return False
            operation_key = definition.operation_key
            operation = self.operation(operation_key)
            if operation is None:
                return False

            dependencies = []
            if operation.opcode == "STORE" and len(operation.inputs) == 3:
                dependency = dependency_for_input(
                    operation_key, operation.inputs[2], current_span.size
                )
                if dependency is not None:
                    dependencies.append((dependency, "offset", (0,)))
            elif (
                operation.output is not None
                and operation.output.byte_size == current_span.size
                and operation.opcode in {"COPY", "CAST"}
                and len(operation.inputs) == 1
            ):
                dependency = dependency_for_input(
                    operation_key, operation.inputs[0], current_span.size
                )
                if dependency is not None:
                    dependencies.append((dependency, "offset", (0,)))
            elif (
                operation.output is not None
                and operation.output.byte_size == current_span.size
                and operation.opcode == "LOAD"
                and len(operation.inputs) >= 2
                and operation.inputs[0].kind is VarnodeKindCode.CONSTANT
            ):
                dependency = dependency_for_input(
                    operation_key,
                    operation.inputs[1],
                    operation.inputs[1].byte_size,
                )
                if dependency is not None:
                    dependencies.append(
                        (
                            dependency,
                            "load",
                            (operation.inputs[0].coordinate.byte_offset,),
                        )
                    )
            elif (
                operation.output is not None
                and operation.output.byte_size == current_span.size
                and operation.opcode == "INT_SUB"
                and len(operation.inputs) == 2
            ):
                dependency = dependency_for_input(
                    operation_key, operation.inputs[0], current_span.size
                )
                values = value_resolver(
                    operation_key,
                    operation.inputs[1],
                )
                if dependency is not None and values:
                    dependencies.append(
                        (
                            dependency,
                            "offset",
                            tuple(
                                -_signed_width_value(
                                    value,
                                    operation.inputs[1].byte_size,
                                )
                                for value in values
                            ),
                        )
                    )
            elif (
                operation.output is not None
                and operation.output.byte_size == current_span.size
                and operation.opcode == "INT_ADD"
                and len(operation.inputs) == 2
            ):
                for pointer_index, value_index in ((0, 1), (1, 0)):
                    dependency = dependency_for_input(
                        operation_key,
                        operation.inputs[pointer_index],
                        current_span.size,
                    )
                    values = value_resolver(
                        operation_key,
                        operation.inputs[value_index],
                    )
                    if dependency is not None and values:
                        dependencies.append(
                            (
                                dependency,
                                "offset",
                                tuple(
                                    _signed_width_value(
                                        value,
                                        operation.inputs[value_index].byte_size,
                                    )
                                    for value in values
                                ),
                            )
                        )
                if len(dependencies) != 1:
                    return False
            if len(dependencies) != 1:
                return False
            dependency, transform, values = dependencies[0]
            rules[key].extend(
                (dependency, transform, value, None) for value in values
            )
            return discover(dependency)

        if not discover(root):
            return ()
        values = {
            key: {
                seed
                for dependency, _, _, seed in items
                if dependency is None and seed is not None
            }
            for key, items in rules.items()
        }
        for _ in range(512):
            updated = {key: set(paths) for key, paths in values.items()}
            for key, items in rules.items():
                for dependency, transform, value, seed in items:
                    if dependency is None:
                        if seed is not None:
                            updated[key].add(seed)
                        continue
                    if transform == "offset":
                        transformed = tuple(
                            path.with_offset(value) for path in values[dependency]
                        )
                    elif transform == "load":
                        transformed = tuple(
                            path.through_load(value, key[1].size)
                            for path in values[dependency]
                        )
                    else:
                        return ()
                    updated[key].update(transformed)
                    if len(updated[key]) > 256:
                        return ()
            if updated == values:
                return tuple(sorted(values[root], key=_pointer_path_sort_key))
            values = updated
        return ()

    def complete_physical_pointer_candidates_for_input(
        self,
        operation_key: str,
        varnode: ValidatedVarnode,
    ) -> tuple[_PointerPath, ...]:
        resolved = self._observed_input_definition(operation_key, varnode)
        if resolved is None:
            return ()
        return self.complete_physical_pointer_candidates(
            *resolved,
            integer_values_for_input=lambda key, value: (
                bounded_integer_values_for_input(self, key, value)
            ),
        )

    def canonical_physical_affine_relation(
        self,
        definition_id: int,
        requested_span: ByteSpan,
        offset: int = 0,
    ) -> tuple[int, ByteSpan, int] | None:
        """Peel one exact affine SSA chain without crossing a merge."""
        if type(offset) is not int:
            raise TypeError("physical affine offset must be an exact int")
        seen = set()
        while True:
            key = (definition_id, requested_span.start, requested_span.size, offset)
            if key in seen:
                return None
            seen.add(key)
            if not 0 <= definition_id < len(self.memory.definitions):
                return None
            definition = self.memory.definitions[definition_id]
            if not definition.span.contains(requested_span):
                return None
            if (
                definition.kind is not MemoryDefinitionKind.DATA_WRITE
                or definition.operation_key is None
            ):
                return definition_id, requested_span, offset
            operation_key = definition.operation_key
            operation = self.operation(operation_key)
            if operation is None or operation.output is None:
                return definition_id, requested_span, offset

            dependency = None
            delta = 0
            if operation.opcode in {"COPY", "CAST"} and len(operation.inputs) == 1:
                dependency = self._observed_input_definition(
                    operation_key,
                    operation.inputs[0],
                )
            elif operation.opcode == "INT_SUB" and len(operation.inputs) == 2:
                dependency = self._observed_input_definition(
                    operation_key,
                    operation.inputs[0],
                )
                values = self.integer_values_for_input(
                    operation_key,
                    operation.inputs[1],
                )
                if values is None or len(values) != 1:
                    return definition_id, requested_span, offset
                delta = -_signed_width_value(
                    next(iter(values)),
                    operation.inputs[1].byte_size,
                )
            elif operation.opcode == "INT_ADD" and len(operation.inputs) == 2:
                candidates = []
                for pointer_index, value_index in ((0, 1), (1, 0)):
                    candidate = self._observed_input_definition(
                        operation_key,
                        operation.inputs[pointer_index],
                    )
                    values = self.integer_values_for_input(
                        operation_key,
                        operation.inputs[value_index],
                    )
                    if candidate is not None and values is not None and len(values) == 1:
                        candidates.append(
                            (
                                candidate,
                                _signed_width_value(
                                    next(iter(values)),
                                    operation.inputs[value_index].byte_size,
                                ),
                            )
                        )
                if len(candidates) != 1:
                    return definition_id, requested_span, offset
                dependency, delta = candidates[0]
            else:
                return definition_id, requested_span, offset

            if dependency is None or dependency[1].size != requested_span.size:
                return definition_id, requested_span, offset
            definition_id, requested_span = dependency
            offset += delta

    def _pointer_candidates_from_write(
        self, operation_key: str | None, requested_span: ByteSpan
    ) -> tuple[_PointerPath, ...]:
        operation = None if operation_key is None else self.operation(operation_key)
        if operation_key is None or operation is None:
            return ()
        if operation.opcode == "STORE" and len(operation.inputs) == 3:
            return self.pointer_candidates_for_input(operation_key, operation.inputs[2])
        if operation.output is None or operation.output.byte_size != requested_span.size:
            return ()
        if operation.opcode in {"COPY", "CAST"} and len(operation.inputs) == 1:
            return self.pointer_candidates_for_input(operation_key, operation.inputs[0])
        if operation.opcode == "LOAD" and len(operation.inputs) >= 2:
            selector = operation.inputs[0]
            if selector.kind is not VarnodeKindCode.CONSTANT:
                return ()
            return tuple(
                path.through_load(
                    selector.coordinate.byte_offset,
                    operation.output.byte_size,
                )
                for path in self.pointer_candidates_for_input(
                    operation_key, operation.inputs[1]
                )
            )
        if operation.opcode not in {"INT_ADD", "INT_SUB"} or len(operation.inputs) != 2:
            return ()
        left, right = operation.inputs
        rows = []
        left_paths = self.pointer_candidates_for_input(operation_key, left)
        right_values = self.integer_values_for_input(operation_key, right)
        if left_paths and right_values is not None:
            sign = -1 if operation.opcode == "INT_SUB" else 1
            rows.extend(
                path.with_offset(sign * _signed_width_value(value, right.byte_size))
                for path in left_paths
                for value in right_values
            )
        if operation.opcode == "INT_ADD":
            right_paths = self.pointer_candidates_for_input(operation_key, right)
            left_values = self.integer_values_for_input(operation_key, left)
            if right_paths and left_values is not None:
                rows.extend(
                    path.with_offset(_signed_width_value(value, left.byte_size))
                    for path in right_paths
                    for value in left_values
                )
        return tuple(rows)


__all__ = ["_FunctionPointerValueMixin"]
