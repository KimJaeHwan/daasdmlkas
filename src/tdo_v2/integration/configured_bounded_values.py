"""Finite induction values proven by observed storage and control flow."""

from __future__ import annotations

from .._scope_contracts import VarnodeKindCode
from ..memory_contracts import MemoryDefinitionKind
from ..model import ByteSpan, StorageObjectKind
from .configured_value_domain import signed_width_value


_MAX_BOUNDED_VALUES = 64
_FORWARDING_OPS = frozenset({"COPY", "CAST", "INT_ZEXT", "INT_SEXT"})
_CONTROL_FORWARDING_OPS = _FORWARDING_OPS | {"BOOL_NEGATE"}


def bounded_integer_values_for_input(view, operation_key, varnode):
    """Return one finite induction domain when CFG and storage prove its bound."""
    resolved = view._observed_input_definition(operation_key, varnode)
    if resolved is not None:
        load = _local_load_source(view, *resolved)
        if load is not None:
            values = _bounded_values_for_load(
                view,
                load[0],
                load[1],
                operation_key,
            )
            if values is not None:
                return values
    return view.integer_values_for_input(operation_key, varnode)


def _local_load_source(view, definition_id, requested_span):
    seen = set()
    while definition_id not in seen:
        seen.add(definition_id)
        if not 0 <= definition_id < len(view.memory.definitions):
            return None
        definition = view.memory.definitions[definition_id]
        operation_key = definition.operation_key
        operation = None if operation_key is None else view.operation(operation_key)
        if operation is None or operation.output is None:
            return None
        if operation.opcode in _FORWARDING_OPS and len(operation.inputs) == 1:
            resolved = view._observed_input_definition(
                operation_key, operation.inputs[0]
            )
            if resolved is None:
                return None
            definition_id, requested_span = resolved
            continue
        identity = _identity_input(operation)
        if identity is not None:
            resolved = view._observed_input_definition(operation_key, identity)
            if resolved is None:
                return None
            definition_id, requested_span = resolved
            continue
        if operation.opcode != "LOAD" or len(operation.inputs) < 2:
            return None
        local_span = view._relative_access_span(
            operation_key,
            read=True,
            byte_size=operation.output.byte_size,
        )
        if (
            local_span is None
            or local_span.object_id.kind is not StorageObjectKind.FUNCTION_RELATIVE
        ):
            return None
        return operation_key, local_span
    return None


def _bounded_values_for_load(view, load_key, local_span, use_key):
    definition_id = view.definition_for_span(load_key, local_span)
    if definition_id is None:
        return None
    sources = _join_leaf_definitions(view, definition_id)
    if len(sources) != 2:
        return None

    initial = []
    updates = []
    for source_id in sources:
        update = _written_recurrence(view, source_id, local_span)
        if update is not None:
            updates.append(update)
            continue
        constant = _written_singleton(view, source_id)
        if constant is not None:
            initial.append(constant)
            continue
    if len(initial) != 1 or len(updates) != 1:
        return None
    seed = initial[0]
    step, update_key = updates[0]
    if step <= 0:
        return None

    bounds = []
    for compare_key, (_, operation) in view.operations.items():
        if operation.opcode not in {"INT_LESS", "INT_SLESS"}:
            continue
        if len(operation.inputs) != 2:
            continue
        left = _input_local_load(view, compare_key, operation.inputs[0])
        if left != local_span:
            continue
        right = _singleton_input_value(view, compare_key, operation.inputs[1])
        if right is None:
            continue
        bound = (
            signed_width_value(right, operation.inputs[1].byte_size)
            if operation.opcode == "INT_SLESS"
            else right
        )
        if not _comparison_guards_use(view, compare_key, use_key, update_key):
            continue
        bounds.append(bound)
    if len(set(bounds)) != 1:
        return None
    bound = bounds[0]
    if seed < 0 or bound <= seed:
        return None
    values = tuple(range(seed, bound, step))
    if not values or len(values) > _MAX_BOUNDED_VALUES:
        return None
    return frozenset(values)


def _join_leaf_definitions(view, definition_id):
    pending = [definition_id]
    leaves = []
    seen = set()
    while pending:
        current = pending.pop()
        if current in seen or not 0 <= current < len(view.memory.definitions):
            return ()
        seen.add(current)
        definition = view.memory.definitions[current]
        if definition.kind is MemoryDefinitionKind.JOIN:
            sources = view._join_sources.get(current, ())
            if not sources:
                return ()
            pending.extend(sources)
        else:
            leaves.append(current)
    return tuple(sorted(leaves))


def _written_singleton(view, definition_id):
    definition = view.memory.definitions[definition_id]
    operation_key = definition.operation_key
    operation = None if operation_key is None else view.operation(operation_key)
    if (
        definition.kind is not MemoryDefinitionKind.DATA_WRITE
        or operation is None
        or operation.opcode != "STORE"
        or len(operation.inputs) != 3
    ):
        return None
    return _singleton_input_value(view, operation_key, operation.inputs[2])


def _written_recurrence(view, definition_id, local_span):
    definition = view.memory.definitions[definition_id]
    operation_key = definition.operation_key
    operation = None if operation_key is None else view.operation(operation_key)
    if (
        definition.kind is not MemoryDefinitionKind.DATA_WRITE
        or operation is None
        or operation.opcode != "STORE"
        or len(operation.inputs) != 3
    ):
        return None
    resolved = view._observed_input_definition(operation_key, operation.inputs[2])
    if resolved is None:
        return None
    affine = _recurrence_expression(view, *resolved, local_span)
    return None if affine is None else (affine, operation_key)


def _recurrence_expression(view, definition_id, requested_span, local_span):
    seen = set()
    while definition_id not in seen:
        seen.add(definition_id)
        if not 0 <= definition_id < len(view.memory.definitions):
            return None
        definition = view.memory.definitions[definition_id]
        operation_key = definition.operation_key
        operation = None if operation_key is None else view.operation(operation_key)
        if operation is None or operation.output is None:
            return None
        if operation.opcode in _FORWARDING_OPS and len(operation.inputs) == 1:
            resolved = view._observed_input_definition(
                operation_key, operation.inputs[0]
            )
            if resolved is None:
                return None
            definition_id, requested_span = resolved
            continue
        if operation.opcode not in {"INT_ADD", "INT_SUB"} or len(operation.inputs) != 2:
            return None
        candidates = []
        if _input_local_load(view, operation_key, operation.inputs[0]) == local_span:
            value = _singleton_input_value(view, operation_key, operation.inputs[1])
            if value is not None:
                candidates.append(value if operation.opcode == "INT_ADD" else -value)
        if (
            operation.opcode == "INT_ADD"
            and _input_local_load(view, operation_key, operation.inputs[1]) == local_span
        ):
            value = _singleton_input_value(view, operation_key, operation.inputs[0])
            if value is not None:
                candidates.append(value)
        return candidates[0] if len(candidates) == 1 else None
    return None


def _input_local_load(view, operation_key, varnode):
    resolved = view._observed_input_definition(operation_key, varnode)
    if resolved is None:
        return None
    load = _local_load_source(view, *resolved)
    return None if load is None else load[1]


def _singleton_input_value(view, operation_key, varnode):
    if varnode.kind in {VarnodeKindCode.CONSTANT, VarnodeKindCode.ADDRESS}:
        return varnode.coordinate.byte_offset % (1 << (varnode.byte_size * 8))
    values = view.integer_values_for_input(operation_key, varnode)
    if values is None or len(values) != 1:
        return None
    return next(iter(values))


def _comparison_guards_use(view, compare_key, use_key, update_key):
    compare_block = view.operation_blocks.get(compare_key)
    use_block = view.operation_blocks.get(use_key)
    if compare_block is None or use_block is None:
        return False
    if compare_block not in view._dominators.get(use_block, ()):
        return False
    if not view.may_precede(compare_key, use_key):
        return False
    if not view.may_precede(use_key, update_key):
        return False
    if not view.may_precede(update_key, compare_key):
        return False
    return any(
        operation.opcode == "CBRANCH"
        and _input_origin_operation_key(view, key, operation.inputs[-1])
        == compare_key
        for key, (_, operation) in view.operations.items()
        if operation.inputs
    )


def _input_origin_operation_key(view, operation_key, varnode):
    resolved = view._observed_input_definition(operation_key, varnode)
    if resolved is None:
        return None
    definition_id, _ = resolved
    seen = set()
    while definition_id not in seen:
        seen.add(definition_id)
        if not 0 <= definition_id < len(view.memory.definitions):
            return None
        definition = view.memory.definitions[definition_id]
        key = definition.operation_key
        operation = None if key is None else view.operation(key)
        if operation is None:
            return key
        if operation.opcode not in _CONTROL_FORWARDING_OPS or len(operation.inputs) != 1:
            return key
        resolved = view._observed_input_definition(key, operation.inputs[0])
        if resolved is None:
            return key
        definition_id, _ = resolved
    return None


def _identity_input(operation):
    if len(operation.inputs) != 2:
        return None
    left, right = operation.inputs
    left_value = _literal_value(left)
    right_value = _literal_value(right)
    if operation.opcode == "INT_ADD":
        if left_value == 0:
            return right
        if right_value == 0:
            return left
    if operation.opcode == "INT_SUB" and right_value == 0:
        return left
    if operation.opcode == "INT_MULT":
        if left_value == 1:
            return right
        if right_value == 1:
            return left
    return None


def _literal_value(varnode):
    if varnode.kind not in {VarnodeKindCode.CONSTANT, VarnodeKindCode.ADDRESS}:
        return None
    return varnode.coordinate.byte_offset % (1 << (varnode.byte_size * 8))


__all__ = ["bounded_integer_values_for_input"]
