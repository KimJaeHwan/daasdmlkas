"""Source-origin projection and final configured slice completion."""

from __future__ import annotations

from dataclasses import dataclass

from ..memory_contracts import MemoryDefinitionKind
from ..model import StorageObjectKind
from .configured_boundary_mapping import (
    _caller_span_for_relative_entry,
    _mapped_caller_span,
    _mapped_or_observed_call_span,
)
from .configured_event_order import (
    _effective_access_span,
    _latest_preceding_events,
    _origin_proofs_for_event,
    _overlapping_events,
    _prefer_shorter_origins,
)
from .configured_call_byte_explanation import certify_call_byte_replacement
from .configured_dynamic_alias_explanation import (
    certify_dynamic_aliases, dynamic_alias_reachable_nodes,
)
from .configured_function_view import _FunctionView
from .configured_interprocedural_contracts import (
    InterproceduralSliceCompletion,
    ObservedCallByteReplacement,
)
from .configured_interprocedural_records import OriginReference as _OriginReference
from .configured_reachability import (
    _definition_reachable,
    _expand_reachable_local_load_candidates,
)


@dataclass(frozen=True, slots=True)
class _CallOriginContext:
    parent: object
    child: object
    call_operation_key: str
    call_position: int
    prior_events: tuple
    correspondence: tuple = ()
    parent_context: object | None = None

def _value_origins(
    caller,
    seed,
    callee,
    definition_id,
    call_position,
    prior_events,
    callee_events=(),
    correspondence=(),
    caller_entry_context=None,
):
    reachable = _definition_reachable(callee, definition_id)
    origins = {
        _OriginReference(
            boundary.label,
            callee.analysis.entry,
            callee.scope_digest,
            boundary.node,
        )
        for boundary in callee.analysis.boundaries.report_origins
        if boundary.node in reachable
    }
    origins.update(
        _origins_from_reachable_events(callee, reachable, callee_events)
    )
    entry_reads = {
        (fragment.span, callee.memory.actions[read.action_id].operation_key)
        for read in callee.memory.reads
        for fragment in read.fragments
        if callee.memory.definitions[fragment.definition_ids[0]].kind
        is MemoryDefinitionKind.ENTRY
        and callee.memory_graph.definition_nodes[fragment.definition_ids[0]]
        in reachable
    }
    for entry_span, operation_key in sorted(
        entry_reads, key=lambda item: (item[0].canonical_key, item[1])
    ):
        entry_span = _effective_access_span(
            callee,
            operation_key,
            entry_span,
            read=True,
        )
        if entry_span is None:
            continue
        if entry_span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE:
            caller_span = _caller_span_for_relative_entry(
                caller,
                callee,
                operation_key,
                entry_span,
                call_position,
                correspondence,
                call_operation_key=seed.operation_key,
            )
            if caller_span is not None:
                origins.update(
                    _origins_from_latest_state(
                        caller,
                        caller_span,
                        seed.operation_key,
                        call_position,
                        prior_events,
                        caller_entry_context,
                    )
                )
        else:
            origins.update(
                _caller_origins_for_entry(
                    caller, seed, entry_span, call_position, prior_events,
                    correspondence, caller_entry_context,
                )
            )
    return tuple(
        sorted(
            origins,
            key=lambda item: (
                item.label,
                item.function_entry,
                item.node,
                tuple(step.canonical_key for step in item.prior_transfers),
            ),
        )
    )

def _origins_from_reachable_events(view, reachable, events):
    origins = set()
    for read in view.memory.reads:
        operation_key = view.memory.actions[read.action_id].operation_key
        read_position = view.position(operation_key)
        if read_position is None:
            continue
        for fragment in read.fragments:
            if not any(
                view.memory_graph.definition_nodes[definition_id] in reachable
                for definition_id in fragment.definition_ids
            ):
                continue
            effective = _effective_access_span(
                view,
                operation_key,
                fragment.span,
                read=True,
            )
            if effective is None:
                continue
            matching = _latest_preceding_events(
                view,
                _overlapping_events(events, effective),
                operation_key,
            )
            if not matching:
                continue
            for event in matching:
                transfer = event.transfer
                origins.update(
                    _OriginReference(
                        origin.label,
                        origin.function_entry,
                        origin.function_scope_digest,
                        origin.node,
                        origin.prior_transfers + (transfer,),
                    )
                    for origin in event.origins
                )
    return tuple(
        sorted(
            origins,
            key=lambda item: (
                item.label,
                item.function_entry,
                item.node,
                tuple(step.canonical_key for step in item.prior_transfers),
            ),
        )
    )

def _caller_origins_for_entry(
    caller,
    seed,
    entry_span,
    call_position,
    prior_events,
    correspondence=(),
    caller_entry_context=None,
):
    origins = set()
    if entry_span.object_id.kind in (
        StorageObjectKind.REGISTER_FILE,
        StorageObjectKind.ADDRESS_SPACE,
    ):
        origins.update(
            _origins_from_latest_state(
                caller,
                _mapped_caller_span(entry_span, correspondence),
                seed.operation_key,
                call_position,
                prior_events,
                caller_entry_context,
            )
        )
    return tuple(
        sorted(
            origins,
            key=lambda item: (
                item.label,
                item.function_entry,
                item.node,
                tuple(step.canonical_key for step in item.prior_transfers),
            ),
        )
    )

def _origins_from_latest_state(
    caller,
    span,
    before_operation_key,
    before_position,
    events,
    caller_entry_context=None,
):
    matching = _latest_preceding_events(
        caller,
        _overlapping_events(events, span),
        before_operation_key,
    )
    local = caller.latest_definition(span, before_position)
    include_local = local is not None
    if local is not None and matching:
        local_key = caller.memory.definitions[local[1]].operation_key
        include_local = caller.can_reach_without_operations(
            local_key,
            before_operation_key,
            tuple(event.call_operation_key for event in matching),
        )
    origins = []
    if include_local:
        reachable = _definition_reachable(caller, local[1])
        origins.extend(
            _OriginReference(
                boundary.label,
                caller.analysis.entry,
                caller.scope_digest,
                boundary.node,
            )
            for boundary in caller.analysis.boundaries.report_origins
            if boundary.node in reachable
        )
        origins.extend(
            _origins_from_reachable_events(caller, reachable, events)
        )
        origins.extend(
            _origins_from_parent_entries(
                caller,
                reachable,
                caller_entry_context,
            )
        )
    for event in matching:
        transfer = event.transfer
        origins.extend(
            _OriginReference(
                origin.label,
                origin.function_entry,
                origin.function_scope_digest,
                origin.node,
                origin.prior_transfers + (transfer,),
            )
            for origin in event.origins
        )
    return _prefer_shorter_origins(tuple(origins))


def _origins_from_parent_entries(view, reachable, context):
    if context is None or context.child is not view:
        return ()
    spans = set()
    for read in view.memory.reads:
        operation_key = view.memory.actions[read.action_id].operation_key
        for fragment in read.fragments:
            definition_id = fragment.definition_ids[0]
            definition = view.memory.definitions[definition_id]
            if (
                definition.kind is not MemoryDefinitionKind.ENTRY
                or view.memory_graph.definition_nodes[definition_id] not in reachable
            ):
                continue
            effective = _effective_access_span(
                view,
                operation_key,
                fragment.span,
                read=True,
            )
            if effective is not None:
                spans.add(effective)
    origins = []
    for entry_span in sorted(spans, key=lambda item: item.canonical_key):
        parent_span = _mapped_or_observed_call_span(
            context.parent,
            view,
            entry_span,
            context.call_operation_key,
            context.call_position,
            context.correspondence,
        )
        if parent_span is None:
            continue
        origins.extend(
            _origins_from_latest_state(
                context.parent,
                parent_span,
                context.call_operation_key,
                context.call_position,
                context.prior_events,
                context.parent_context,
            )
        )
    return _prefer_shorter_origins(tuple(origins))


def _complete_slice(view, local_slice, events, views=None):
    reachable = _expand_reachable_local_load_candidates(
        view, local_slice.result.reachable_nodes
    )
    proofs = set()
    replacements = set()
    root_local_nodes = frozenset(local_slice.result.reachable_nodes)
    dynamic_aliases = (
        certify_dynamic_aliases(view, root_local_nodes, views)
        if type(view) is _FunctionView else ()
    )
    diagnostic_nodes = (
        dynamic_alias_reachable_nodes(view, root_local_nodes, dynamic_aliases)
        if dynamic_aliases else root_local_nodes
    )
    for read in view.memory.reads:
        operation_key = view.memory.actions[read.action_id].operation_key
        read_position = view.position(operation_key)
        if read_position is None:
            continue
        for fragment in read.fragments:
            definition_nodes = tuple(
                view.memory_graph.definition_nodes[item]
                for item in fragment.definition_ids
            )
            if not any(node in reachable for node in definition_nodes):
                continue
            effective = _effective_access_span(
                view,
                operation_key,
                fragment.span,
                read=True,
            )
            if effective is None:
                continue
            matching = _latest_preceding_events(
                view,
                _overlapping_events(events, effective),
                operation_key,
            )
            if not matching:
                continue
            for event in matching:
                event_proofs = _origin_proofs_for_event(view, event)
                proofs.update(event_proofs)
                callee = None if views is None else views.get(event.callee_entry)
                if callee is None:
                    continue
                certificate = certify_call_byte_replacement(
                    view, callee, event, read, fragment, diagnostic_nodes
                )
                if certificate is None:
                    continue
                reader_node, old_nodes = certificate
                replacements.update(
                    ObservedCallByteReplacement(
                        proof, operation_key, reader_node, fragment.span, old_nodes
                    )
                    for proof in event_proofs
                )

    root_spans = local_slice.root.physical_spans
    if not root_spans:
        try:
            root_definition_id = view.memory_graph.definition_nodes.index(
                local_slice.root.node
            )
        except ValueError:
            root_definition_id = None
        if root_definition_id is not None:
            root_spans = (view.memory.definitions[root_definition_id].span,)
    callsites = view.analysis.evidence.seeds.callsites
    if (
        root_spans
        and local_slice.root.occurrence_ordinal < len(callsites)
    ):
        sink_operation_key = callsites[
            local_slice.root.occurrence_ordinal
        ].operation_key
        for root_span in root_spans:
            matching = _latest_preceding_events(
                view,
                _overlapping_events(events, root_span),
                sink_operation_key,
            )
            for event in matching:
                proofs.update(_origin_proofs_for_event(view, event))
    return InterproceduralSliceCompletion(
        local_slice.root.node,
        tuple(sorted(proofs, key=lambda item: item.canonical_key)),
        tuple(sorted(replacements, key=lambda item: item.canonical_key)),
        dynamic_aliases,
    )

__all__ = ["_caller_origins_for_entry","_complete_slice","_origins_from_latest_state","_origins_from_reachable_events","_value_origins"]
