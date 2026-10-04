"""Definition and entry-demand reachability for configured slicing."""

from __future__ import annotations

from .._scope_contracts import VarnodeKindCode
from ..memory_contracts import MemoryDefinitionKind
from ..model import ByteSpan, ResolvedStorage, StorageObjectKind
from ..storage import _resolve_validated_storage
from .configured_event_order import _effective_access_span
from .configured_function_view import _FunctionView
from .configured_interprocedural_records import SinkEntryDemand as _SinkEntryDemand
from .configured_value_domain import storage_ref as _storage_ref

def _reachable_entry_reads(view, reachable):
    rows = set()
    for read in view.memory.reads:
        operation_key = view.memory.actions[read.action_id].operation_key
        for fragment in read.fragments:
            if any(
                view.memory.definitions[definition_id].kind
                is MemoryDefinitionKind.ENTRY
                and view.memory_graph.definition_nodes[definition_id] in reachable
                for definition_id in fragment.definition_ids
            ):
                effective = _effective_access_span(
                    view,
                    operation_key,
                    fragment.span,
                    read=True,
                )
                if effective is not None:
                    rows.add((effective, operation_key))
    return tuple(sorted(rows, key=lambda item: (item[0].canonical_key, item[1])))

def _reachable_entry_demands(view, local_slice):
    reachable = set(local_slice.result.reachable_nodes)
    rows = {}
    for entry_span, operation_key in _reachable_entry_reads(view, reachable):
        if entry_span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE:
            demand = _relative_entry_demand(
                view, local_slice.root.label, operation_key, entry_span
            )
        else:
            demand = _SinkEntryDemand(
                local_slice.root.label,
                direct_span=entry_span,
                target_size=entry_span.size,
            )
        if demand is not None:
            rows.setdefault(demand.canonical_key, demand)
    return tuple(sorted(rows.values(), key=lambda item: item.canonical_key))

def _relative_entry_demand(view, label, operation_key, entry_span):
    operation = view.operation(operation_key)
    if operation is None or operation.opcode != "LOAD" or len(operation.inputs) < 2:
        return None
    selector = operation.inputs[0]
    if selector.kind is not VarnodeKindCode.CONSTANT:
        return None
    path = view.pointer_for_input(operation_key, operation.inputs[1])
    position = view.position(operation_key)
    if path is None or position is None:
        return None
    address_space_id = selector.coordinate.byte_offset
    path = view.resolve_local_pointer_prefix(
        path,
        before_position=position,
        address_space_id=address_space_id,
    )
    anchor = view.memory.definitions[path.anchor_definition_id]
    if anchor.kind is not MemoryDefinitionKind.ENTRY:
        return None
    anchor_span = ByteSpan(
        anchor.span.object_id,
        anchor.span.start + path.anchor_byte_offset,
        path.byte_size,
    )
    return _SinkEntryDemand(
        label,
        pointer_anchor_span=anchor_span,
        pointer_offsets=path.offsets,
        pointer_byte_size=path.byte_size,
        address_space_id=address_space_id,
        target_size=entry_span.size,
    )

def _reachable_address_reads_for_input(view, operation_key, varnode):
    return tuple(
        span
        for span, _ in _reachable_event_reads_for_input(
            view,
            operation_key,
            varnode,
        )
        if span.object_id.kind is StorageObjectKind.ADDRESS_SPACE
    )


def _reachable_event_reads_for_input(view, operation_key, varnode):
    """Return physical ENTRY reads on the selector's backward dependency path."""
    storage = _resolve_validated_storage(
        _storage_ref(varnode),
        view.analysis.evidence.unit.scopes.resolution_context,
    )
    if type(storage) is not ResolvedStorage:
        return ()
    position = view.position(operation_key)
    if position is None:
        return ()
    definition_id = view._latest_definition(storage.span, position)
    if definition_id is None:
        return ()
    reachable = _definition_reachable(view, definition_id)
    rows = {
        (
            _effective_access_span(
                view,
                view.memory.actions[read.action_id].operation_key,
                fragment.span,
                read=True,
            ),
            view.memory.actions[read.action_id].operation_key,
        )
        for read in view.memory.reads
        for fragment in read.fragments
        if any(
            view.memory.definitions[item].kind is MemoryDefinitionKind.ENTRY
            and view.memory_graph.definition_nodes[item] in reachable
            for item in fragment.definition_ids
        )
    }
    return tuple(
        sorted(
            (
                (span, read_key)
                for span, read_key in rows
                if span is not None
                and span.object_id.kind
                in (StorageObjectKind.REGISTER_FILE, StorageObjectKind.ADDRESS_SPACE)
            ),
            key=lambda item: (item[0].canonical_key, item[1]),
        )
    )

def _definition_reachable(view: _FunctionView, definition_id: int) -> set[int]:
    node = view.memory_graph.definition_nodes[definition_id]
    reachable = set(view.normalized.dependencies.backward_reachable((node,)))
    return _expand_reachable_local_load_candidates(view, reachable)

def _expand_reachable_local_load_candidates(view: _FunctionView, reachable) -> set[int]:
    """Follow finite, materializable local targets of reachable LOADs."""
    result = set(reachable)
    operation_for_key = getattr(view, "operation", None)
    if not callable(operation_for_key):
        return result
    changed = True
    while changed:
        changed = False
        for definition_id, definition in enumerate(view.memory.definitions):
            if (
                definition.kind is not MemoryDefinitionKind.DATA_WRITE
                or view.memory_graph.definition_nodes[definition_id] not in result
                or definition.operation_key is None
            ):
                continue
            try:
                operation = operation_for_key(definition.operation_key)
            except AttributeError:
                return result
            if (
                operation is None
                or operation.opcode != "LOAD"
                or operation.output is None
                or len(operation.inputs) < 2
                or operation.inputs[0].kind is not VarnodeKindCode.CONSTANT
            ):
                continue
            position = view.position(definition.operation_key)
            if position is None:
                continue
            for path in view.pointer_candidates_for_input(
                definition.operation_key, operation.inputs[1]
            ):
                span = view._direct_span(
                    path,
                    operation.output.byte_size,
                    operation.inputs[0].coordinate.byte_offset,
                )
                if span is None:
                    continue
                effective = _effective_access_span(
                    view,
                    definition.operation_key,
                    span,
                    read=True,
                )
                if effective is None:
                    continue
                local_definition_id = view._latest_definition(effective, position)
                if local_definition_id is None:
                    continue
                local_node = view.memory_graph.definition_nodes[local_definition_id]
                addition = set(
                    view.normalized.dependencies.backward_reachable((local_node,))
                )
                if not addition.issubset(result):
                    result.update(addition)
                    changed = True
    return result

__all__ = ["_definition_reachable","_expand_reachable_local_load_candidates","_reachable_address_reads_for_input","_reachable_entry_demands","_reachable_entry_reads","_reachable_event_reads_for_input","_relative_entry_demand"]
