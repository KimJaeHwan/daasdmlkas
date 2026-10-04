"""Interprocedural write-event production and recursive stabilization."""

from __future__ import annotations

from .._scope_contracts import AddressCoordinate, VarnodeKindCode
from ..external_summary import ExternalCallBoundary, ExternalSummaryProvider, ExternalTransferKind
from ..memory_contracts import MemoryDefinitionKind
from ..model import ByteSpan, StorageObjectKind
from .configured_boundary_mapping import (
    _caller_path_for_entry_path,
    _caller_span_for_entry_path,
    _caller_span_for_relative_entry,
)
from .configured_call_values import _CallIntegerResolver
from .configured_call_coordinates import _CallCoordinateResolver
from .configured_coordinate_events import _caller_coordinate_write_events
from .configured_event_order import (
    _event_cache_semantics,
    _event_key,
    _prefer_shorter_events,
)
from .configured_external_transfer import exact_external_transfer_extent
from .configured_function_view import _FunctionView
from .configured_interprocedural_records import (
    OriginReference as _OriginReference,
    WriteEvent as _WriteEvent,
)
from .configured_memory_projection import (
    byte_preserving_load_paths,
    byte_preserving_load_span,
    partition_span_by_overlaps,
)
from .configured_origin_projection import (
    _CallOriginContext,
    _origins_from_latest_state,
    _value_origins,
)
from .configured_physical_state import _physical_state_span
from .configured_target_resolution import (
    _external_callback_edges,
    _observed_internal_call_targets,
    _selected_resolved_target,
)

def _external_write_events(
    caller,
    seed,
    naming,
    target,
    call_position,
    prior_events,
    provider,
    caller_entry_context=None,
):
    aliases = tuple(
        sorted(
            {
                alias.value
                for alias in target.aliases
                if alias.policy_admissible
            }
        )
    )
    namespace = caller.analysis.evidence.unit.scopes.program.evidence.translation_namespace
    models = provider.summarize(
        ExternalCallBoundary(
            f"{caller.analysis.entry.space_id:x}:{caller.analysis.entry.byte_offset:x}",
            seed.operation_key,
            aliases,
            namespace.language_id,
        )
    )
    events = []
    for model in models:
        transfer_extent = exact_external_transfer_extent(
            caller,
            model,
            call_position,
        )
        if model.extent is not None and transfer_extent is None:
            continue
        destination = _physical_state_span(
            caller, model.destination_pointer, call_position
        )
        if destination is None:
            continue
        destination_definition = caller.state_definition(destination, call_position)
        if destination_definition is None:
            continue
        destination_path = caller.pointer_for_definition(
            destination_definition, destination
        )
        if destination_path is None:
            continue
        for target_span, displacement, address_space_id in (
            _observed_destination_reads(
                caller,
                seed.operation_key,
                call_position,
                destination_path,
            )
        ):
            if (
                transfer_extent is not None
                and (
                    displacement < 0
                    or displacement + target_span.size > transfer_extent
                )
            ):
                continue
            source_span = _external_source_span(
                caller,
                model,
                call_position,
                displacement,
                target_span.size,
                address_space_id,
            )
            if source_span is None:
                continue
            origins = _origins_from_latest_state(
                caller,
                source_span,
                seed.operation_key,
                call_position,
                prior_events,
                caller_entry_context,
            )
            if not origins:
                continue
            events.append(
                _WriteEvent(
                    caller.scope_digest,
                    call_position,
                    seed.operation_key,
                    target.coordinate,
                    target.target_digest,
                    f"external-summary:{model.model_id}",
                    target_span,
                    1,
                    origins,
                )
            )
    return tuple(sorted(events, key=_event_key))

def _observed_destination_reads(
    view, call_operation_key, call_position, destination_path
):
    result = set()
    for operation_key, (position, operation) in view.operations.items():
        if (
            position <= call_position
            or not view.definitely_precedes(call_operation_key, operation_key)
            or operation.opcode != "LOAD"
            or operation.output is None
            or len(operation.inputs) < 2
        ):
            continue
        selector = operation.inputs[0]
        if selector.kind is not VarnodeKindCode.CONSTANT:
            continue
        address_space_id = selector.coordinate.byte_offset
        read_path = view.pointer_for_input(operation_key, operation.inputs[1])
        if read_path is None:
            continue
        read_path = view.resolve_local_pointer_prefix(
            read_path,
            before_position=position,
            address_space_id=address_space_id,
        )
        base_path = view.resolve_local_pointer_prefix(
            destination_path,
            before_position=call_position,
            address_space_id=address_space_id,
        )
        if (
            len(read_path.offsets) != 1
            or len(base_path.offsets) != 1
            or read_path.anchor_definition_id != base_path.anchor_definition_id
            or read_path.anchor_byte_offset != base_path.anchor_byte_offset
        ):
            continue
        target_span = view._relative_access_span(
            operation_key,
            read=True,
            byte_size=operation.output.byte_size,
        )
        if target_span is None:
            continue
        result.add(
            (
                target_span,
                read_path.offsets[0] - base_path.offsets[0],
                address_space_id,
            )
        )
    return tuple(
        sorted(result, key=lambda item: (item[0].canonical_key, item[1], item[2]))
    )

def _external_source_span(
    view,
    model,
    call_position,
    displacement,
    target_size,
    address_space_id,
):
    source = _physical_state_span(view, model.source, call_position)
    if source is None:
        return None
    if model.kind is ExternalTransferKind.OBSERVED_VALUE_TO_MEMORY:
        if displacement < 0 or displacement + target_size > source.size:
            return None
        return ByteSpan(source.object_id, source.start + displacement, target_size)
    if model.kind is not ExternalTransferKind.OBSERVED_MEMORY_COPY:
        return None
    source_definition = view.state_definition(source, call_position)
    if source_definition is None:
        return None
    source_path = view.pointer_for_definition(source_definition, source)
    if source_path is None or len(source_path.offsets) != 1:
        return None
    return view.materialize_path(
        source_path.with_offset(displacement),
        before_position=call_position,
        target_size=target_size,
        address_space_id=address_space_id,
    )

def _caller_write_events(
    caller: _FunctionView,
    views: dict[AddressCoordinate, _FunctionView],
    cache: dict[AddressCoordinate, tuple[_WriteEvent, ...]] | None = None,
    active: frozenset[AddressCoordinate] = frozenset(),
    recursive_seed: dict[AddressCoordinate, tuple[_WriteEvent, ...]] | None = None,
    external_provider: ExternalSummaryProvider | None = None,
    entry_coordinate_resolver=None,
    entry_origin_context=None,
) -> tuple[_WriteEvent, ...]:
    entry = caller.analysis.entry
    if not active and cache is not None and entry in cache:
        return cache[entry]
    if entry in active:
        return () if recursive_seed is None else recursive_seed.get(entry, ())
    nested_active = active | {entry}
    events: list[_WriteEvent] = []
    calls = []
    coordinate_events = _caller_coordinate_write_events(caller, views)
    for seed, naming in zip(
        caller.analysis.evidence.seeds.callsites,
        caller.analysis.evidence.naming.rows,
        strict=True,
    ):
        call_position = caller.position(seed.operation_key)
        if call_position is None:
            continue
        target = _selected_resolved_target(naming)
        for coordinate in _observed_internal_call_targets(
            caller,
            seed,
            naming,
            views,
            coordinate_events,
            entry_coordinate_resolver,
        ):
            calls.append((call_position, seed, naming, target, views[coordinate]))
        if target is not None and target.is_external:
            calls.append((call_position, seed, naming, target, None))
    for call_position, seed, naming, target, callee in sorted(
        calls,
        key=lambda item: (
            item[0],
            item[1].operation_key,
            AddressCoordinate(0, 0)
            if item[4] is None
            else item[4].analysis.entry,
        ),
    ):
        prior = tuple(
            event
            for event in events
            if caller.definitely_precedes(
                event.call_operation_key, seed.operation_key
            )
        )
        if callee is None:
            if (
                target is not None
                and target.is_external
                and external_provider is not None
            ):
                events.extend(
                    _external_write_events(
                        caller,
                        seed,
                        naming,
                        target,
                        call_position,
                        prior,
                        external_provider,
                        entry_origin_context,
                    )
                )
                for callback_entry, correspondence in _external_callback_edges(
                    caller,
                    seed,
                    target,
                    views,
                    external_provider,
                ):
                    callback = views[callback_entry]
                    callback_events = _caller_write_events(
                        callback,
                        views,
                        cache,
                        nested_active,
                        recursive_seed,
                        external_provider,
                        _CallCoordinateResolver(
                            caller,
                            callback,
                            seed.operation_key,
                            call_position,
                            correspondence,
                        ),
                        _CallOriginContext(
                            caller,
                            callback,
                            seed.operation_key,
                            call_position,
                            prior,
                            correspondence,
                            entry_origin_context,
                        ),
                    )
                    events.extend(
                        _callee_write_events(
                            caller,
                            seed,
                            callback,
                            call_position,
                            prior,
                            callback_events,
                            correspondence,
                            entry_origin_context,
                        )
                    )
                    events.extend(
                        _callee_terminal_events(
                            caller,
                            seed,
                            callback,
                            call_position,
                            prior,
                            callback_events,
                            correspondence,
                            entry_origin_context,
                        )
                    )
            continue
        callee_events = _caller_write_events(
            callee,
            views,
            cache,
            nested_active,
            recursive_seed,
            external_provider,
            _CallCoordinateResolver(
                caller,
                callee,
                seed.operation_key,
                call_position,
            ),
            _CallOriginContext(
                caller,
                callee,
                seed.operation_key,
                call_position,
                prior,
                (),
                entry_origin_context,
            ),
        )
        events.extend(
            _callee_write_events(
                caller,
                seed,
                callee,
                call_position,
                prior,
                callee_events,
                (),
                entry_origin_context,
            )
        )
        events.extend(
            _callee_terminal_events(
                caller,
                seed,
                callee,
                call_position,
                prior,
                callee_events,
                (),
                entry_origin_context,
            )
        )
    result = tuple(sorted(events, key=_event_key))
    if not active and cache is not None:
        cache[entry] = result
    return result

def _stabilized_write_events(views, external_provider):
    previous: dict[AddressCoordinate, tuple[_WriteEvent, ...]] = {
        entry: () for entry in views
    }
    for _ in range(len(views) + 1):
        current = {}
        for entry, view in views.items():
            computed = _caller_write_events(
                view,
                views,
                {},
                recursive_seed=previous,
                external_provider=external_provider,
            )
            current[entry] = _prefer_shorter_events(previous[entry], computed)
        if _event_cache_semantics(current) == _event_cache_semantics(previous):
            return current
        previous = current
    raise RuntimeError("interprocedural write-event fixed point did not stabilize")

def _callee_write_events(
    caller,
    seed,
    callee,
    call_position,
    prior_events,
    callee_events=(),
    correspondence=(),
    caller_entry_context=None,
):
    events = []
    value_resolver = _CallIntegerResolver(
        caller,
        callee,
        seed.operation_key,
        call_position,
        correspondence,
    )
    for operation_key, (_, operation) in callee.operations.items():
        if operation.opcode != "STORE" or len(operation.inputs) != 3:
            continue
        value = callee.definition_for_input(operation_key, operation.inputs[2])
        if value is None:
            continue
        target_paths = callee.complete_physical_pointer_candidates_for_input(
            operation_key, operation.inputs[1]
        )
        if not target_paths:
            resolved = callee._observed_input_definition(
                operation_key,
                operation.inputs[1],
            )
            if resolved is not None:
                target_paths = callee.complete_physical_pointer_candidates(
                    *resolved,
                    integer_values_for_input=value_resolver.values_for_input,
                )
        if not target_paths:
            target_path = callee.pointer_for_input(
                operation_key, operation.inputs[1]
            )
            target_paths = () if target_path is None else (target_path,)
        fragmented_relation = _bounded_byte_preserving_copy_events(
            caller,
            seed,
            callee,
            operation_key,
            value[0],
            target_paths,
            call_position,
            prior_events,
            correspondence,
            caller_entry_context,
        )
        if fragmented_relation:
            events.extend(fragmented_relation)
            continue
        if len(target_paths) != 1:
            continue
        target_path = target_paths[0]
        address_space_id = target_path.address_space_id
        if address_space_id is None:
            selector = operation.inputs[0]
            if selector.kind is not VarnodeKindCode.CONSTANT:
                continue
            address_space_id = selector.coordinate.byte_offset
        write_position = callee.position(operation_key)
        if write_position is None:
            continue
        target_path = callee.resolve_local_pointer_prefix(
            target_path,
            before_position=write_position,
            address_space_id=address_space_id,
        )
        caller_target_path = _caller_path_for_entry_path(
            caller,
            callee,
            target_path,
            call_position,
            correspondence,
            call_operation_key=seed.operation_key,
            address_space_id=address_space_id,
        )
        if caller_target_path is None:
            continue
        target_span = caller.materialize_path(
            caller_target_path,
            before_position=call_position,
            target_size=operation.inputs[2].byte_size,
            address_space_id=address_space_id,
        )
        if target_span is None:
            continue
        fragmented = _byte_preserving_copy_events(
            caller,
            seed,
            callee,
            operation_key,
            value[0],
            target_span,
            target_path,
            call_position,
            prior_events,
            correspondence,
            caller_entry_context,
        )
        if fragmented:
            events.extend(fragmented)
            continue
        origins = _value_origins(
            caller,
            seed,
            callee,
            value[0],
            call_position,
            prior_events,
            callee_events,
            correspondence,
            caller_entry_context,
        )
        if (
            not origins
            and value_resolver.values_for_input(
                operation_key,
                operation.inputs[2],
            )
            is None
        ):
            continue
        events.append(
            _WriteEvent(
                caller.scope_digest,
                call_position,
                seed.operation_key,
                callee.analysis.entry,
                callee.scope_digest,
                operation_key,
                target_span,
                max(0, len(target_path.offsets) - 1),
                origins,
                caller_target_path,
            )
        )
    return events


def _bounded_byte_preserving_copy_events(
    caller,
    seed,
    callee,
    operation_key,
    value_definition_id,
    target_paths,
    call_position,
    prior_events,
    correspondence,
    caller_entry_context=None,
):
    """Project a finite, CFG-proven byte-copy relation across one call."""
    load = byte_preserving_load_paths(callee, value_definition_id)
    if load is None:
        return None
    load_operation_key, source_paths = load
    if len(source_paths) <= 1 and len(target_paths) <= 1:
        return None
    load_position = callee.position(load_operation_key)
    write_position = callee.position(operation_key)
    operation = callee.operation(operation_key)
    if load_position is None or write_position is None or operation is None:
        return None
    if operation.opcode != "STORE" or len(operation.inputs) != 3:
        return None
    source_paths = tuple(
        callee.resolve_local_pointer_prefix(
            path,
            before_position=load_position,
            address_space_id=path.address_space_id,
        )
        for path in source_paths
    )
    target_paths = tuple(
        callee.resolve_local_pointer_prefix(
            path,
            before_position=write_position,
            address_space_id=path.address_space_id,
        )
        for path in target_paths
    )
    paired = _paired_affine_paths(source_paths, target_paths)
    if paired is None:
        return None
    events = []
    for source_path, target_path in paired:
        caller_source = _caller_span_for_entry_path(
            caller,
            callee,
            source_path,
            operation.inputs[2].byte_size,
            call_position,
            correspondence,
            call_operation_key=seed.operation_key,
        )
        caller_target_path = _caller_path_for_entry_path(
            caller,
            callee,
            target_path,
            call_position,
            correspondence,
            call_operation_key=seed.operation_key,
        )
        target_span = (
            None
            if caller_target_path is None
            else caller.materialize_path(
                caller_target_path,
                before_position=call_position,
                target_size=operation.inputs[2].byte_size,
                address_space_id=target_path.address_space_id,
            )
        )
        if caller_source is None or target_span is None:
            return None
        origins = _origins_from_latest_state(
            caller,
            caller_source,
            seed.operation_key,
            call_position,
            prior_events,
            caller_entry_context,
        )
        if not origins:
            continue
        events.append(
            _WriteEvent(
                caller.scope_digest,
                call_position,
                seed.operation_key,
                callee.analysis.entry,
                callee.scope_digest,
                operation_key,
                target_span,
                max(0, len(target_path.offsets) - 1),
                origins,
                caller_target_path,
            )
        )
    return tuple(events)


def _paired_affine_paths(source_paths, target_paths):
    """Pair two finite one-dimensional relations by equal relative offsets."""
    if len(source_paths) != len(target_paths) or len(source_paths) < 2:
        return None
    if any(len(path.offsets) != 1 for path in (*source_paths, *target_paths)):
        return None
    ordered_source = tuple(sorted(source_paths, key=lambda path: path.offsets[0]))
    ordered_target = tuple(sorted(target_paths, key=lambda path: path.offsets[0]))
    source_base = ordered_source[0].offsets[0]
    target_base = ordered_target[0].offsets[0]
    source_offsets = tuple(path.offsets[0] - source_base for path in ordered_source)
    target_offsets = tuple(path.offsets[0] - target_base for path in ordered_target)
    if source_offsets != target_offsets or len(set(source_offsets)) != len(source_offsets):
        return None
    return tuple(zip(ordered_source, ordered_target))


def _byte_preserving_copy_events(
    caller,
    seed,
    callee,
    operation_key,
    value_definition_id,
    target_span,
    target_path,
    call_position,
    prior_events,
    correspondence,
    caller_entry_context=None,
):
    load = byte_preserving_load_span(callee, value_definition_id)
    if load is None:
        return None
    load_operation_key, source_span = load
    if source_span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE:
        caller_source = _caller_span_for_relative_entry(
            caller,
            callee,
            load_operation_key,
            source_span,
            call_position,
            correspondence,
            call_operation_key=seed.operation_key,
        )
    elif source_span.object_id.kind is StorageObjectKind.ADDRESS_SPACE:
        caller_source = source_span
    else:
        return None
    if caller_source is None or caller_source.size != target_span.size:
        return None
    boundaries = []
    for candidate in caller.memory.definitions:
        if (
            candidate.kind is MemoryDefinitionKind.DATA_WRITE
            and candidate.operation_key is not None
            and caller.may_precede(candidate.operation_key, seed.operation_key)
        ):
            boundaries.extend(caller.definition_access_spans(candidate))
    boundaries.extend(
        event.target_span
        for event in prior_events
        if caller.may_precede(event.call_operation_key, seed.operation_key)
    )
    events = []
    for source_piece in partition_span_by_overlaps(
        caller_source,
        tuple(boundaries),
    ):
        origins = _origins_from_latest_state(
            caller,
            source_piece,
            seed.operation_key,
            call_position,
            prior_events,
            caller_entry_context,
        )
        if not origins:
            continue
        target_piece = ByteSpan(
            target_span.object_id,
            target_span.start + source_piece.start - caller_source.start,
            source_piece.size,
        )
        events.append(
            _WriteEvent(
                caller.scope_digest,
                call_position,
                seed.operation_key,
                callee.analysis.entry,
                callee.scope_digest,
                operation_key,
                target_piece,
                max(0, len(target_path.offsets) - 1),
                origins,
            )
        )
    return tuple(events)

def _callee_terminal_events(
    caller,
    seed,
    callee,
    call_position,
    prior_events,
    callee_events=(),
    correspondence=(),
    caller_entry_context=None,
):
    """Project exact program-scoped callee terminal writes into the caller."""
    events = []
    value_resolver = _CallIntegerResolver(
        caller,
        callee,
        seed.operation_key,
        call_position,
        correspondence,
    )
    for definition_id, terminal_span in callee.terminal_data_writes():
        target_spans = caller.terminal_transfer_spans(
            seed.operation_key, terminal_span
        )
        definition = callee.memory.definitions[definition_id]
        origins = _value_origins(
            caller,
            seed,
            callee,
            definition_id,
            call_position,
            prior_events,
            callee_events,
            correspondence,
            caller_entry_context,
        )
        if (
            not origins
            and value_resolver.values_for_definition(
                definition_id,
                terminal_span,
            )
            is None
        ):
            continue
        events.extend(
            _WriteEvent(
                caller.scope_digest,
                call_position,
                seed.operation_key,
                callee.analysis.entry,
                callee.scope_digest,
                definition.operation_key,
                target_span,
                0,
                origins,
            )
            for target_span in target_spans
        )
    for nested in callee_events:
        if not callee.event_reaches_an_exit(nested, callee_events):
            continue
        origins = tuple(
            _OriginReference(
                origin.label,
                origin.function_entry,
                origin.function_scope_digest,
                origin.node,
                _lifted_origin_transfers(origin, nested),
            )
            for origin in nested.origins
        )
        if nested.target_path is None:
            projected_targets = tuple(
                (target_span, None)
                for target_span in caller.terminal_transfer_spans(
                    seed.operation_key, nested.target_span
                )
            )
        else:
            caller_target_path = _caller_path_for_entry_path(
                caller,
                callee,
                nested.target_path,
                call_position,
                correspondence,
                call_operation_key=seed.operation_key,
            )
            target_span = (
                None
                if caller_target_path is None
                else caller.materialize_path(
                    caller_target_path,
                    before_position=call_position,
                    target_size=nested.target_span.size,
                    address_space_id=caller_target_path.address_space_id,
                )
            )
            projected_targets = (
                () if target_span is None else ((target_span, caller_target_path),)
            )
        events.extend(
            _WriteEvent(
                caller.scope_digest,
                call_position,
                seed.operation_key,
                callee.analysis.entry,
                callee.scope_digest,
                nested.call_operation_key,
                target_span,
                nested.pointer_dereferences,
                origins,
                target_path,
            )
            for target_span, target_path in projected_targets
        )
    return events


def _lifted_origin_transfers(origin, nested):
    """Keep only call edges that form a continuous nested-origin proof."""
    transfer = nested.transfer
    prior = origin.prior_transfers
    if prior:
        previous = prior[-1]
        if previous.caller_scope_digest in (
            transfer.caller_scope_digest,
            transfer.callee_scope_digest,
        ):
            return prior + (transfer,)
        return prior
    if origin.function_scope_digest == transfer.callee_scope_digest:
        return (transfer,)
    return ()

__all__ = ["_bounded_byte_preserving_copy_events","_byte_preserving_copy_events","_callee_terminal_events","_callee_write_events","_caller_write_events","_external_source_span","_external_write_events","_lifted_origin_transfers","_observed_destination_reads","_paired_affine_paths","_stabilized_write_events"]
