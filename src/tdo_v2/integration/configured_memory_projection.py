"""Exact byte-range projection helpers for configured analysis."""

from __future__ import annotations

from .._scope_contracts import VarnodeKindCode
from ..model import ByteSpan, StorageObjectKind


def definition_ids_covering_span(
    terminal: dict[ByteSpan, tuple[int, ...]],
    requested: ByteSpan,
) -> tuple[int, ...]:
    """Return one definition set only for exact, contiguous terminal coverage."""
    pieces = tuple(
        sorted(
            (
                (span, definition_ids)
                for span, definition_ids in terminal.items()
                if span.overlaps(requested)
            ),
            key=lambda item: item[0].canonical_key,
        )
    )
    if (
        not pieces
        or pieces[0][0].start > requested.start
        or pieces[-1][0].end < requested.end
        or any(
            left[0].end < right[0].start
            for left, right in zip(pieces, pieces[1:])
        )
        or any(definition_ids != pieces[0][1] for _, definition_ids in pieces[1:])
    ):
        return ()
    return pieces[0][1]


def byte_preserving_load_span(view, definition_id: int) -> tuple[str, ByteSpan] | None:
    """Trace an equal-width COPY/CAST chain to one exact memory LOAD."""
    seen = set()
    current = definition_id
    while current not in seen:
        seen.add(current)
        if not 0 <= current < len(view.memory.definitions):
            return None
        definition = view.memory.definitions[current]
        operation_key = definition.operation_key
        if operation_key is None:
            return None
        operation = view.operation(operation_key)
        if operation is None or operation.output is None:
            return None
        if operation.opcode in {"COPY", "CAST"} and len(operation.inputs) == 1:
            source = operation.inputs[0]
            if source.byte_size != operation.output.byte_size:
                return None
            resolved = view.definition_for_input(operation_key, source)
            if resolved is None:
                return None
            current = resolved[0]
            continue
        if (
            operation.opcode != "LOAD"
            or len(operation.inputs) < 2
            or operation.inputs[0].kind is not VarnodeKindCode.CONSTANT
        ):
            return None
        action_id = view.action_ids.get(operation_key)
        if action_id is None:
            return None
        candidates = []
        for read in view.memory.reads:
            if read.action_id != action_id:
                continue
            for fragment in read.fragments:
                if fragment.span.size != operation.output.byte_size:
                    continue
                effective = view.effective_access_span(
                    operation_key,
                    fragment.span,
                    read=True,
                )
                if effective is not None and effective.object_id.kind in (
                    StorageObjectKind.FUNCTION_RELATIVE,
                    StorageObjectKind.ADDRESS_SPACE,
                ):
                    candidates.append(effective)
        unique = tuple(sorted(set(candidates), key=lambda item: item.canonical_key))
        return (operation_key, unique[0]) if len(unique) == 1 else None
    return None


def byte_preserving_load_paths(view, definition_id: int):
    """Trace an equal-width COPY/CAST chain to finite physical LOAD paths."""
    seen = set()
    current = definition_id
    while current not in seen:
        seen.add(current)
        if not 0 <= current < len(view.memory.definitions):
            return None
        definition = view.memory.definitions[current]
        operation_key = definition.operation_key
        if operation_key is None:
            return None
        operation = view.operation(operation_key)
        if operation is None or operation.output is None:
            return None
        if operation.opcode in {"COPY", "CAST"} and len(operation.inputs) == 1:
            source = operation.inputs[0]
            if source.byte_size != operation.output.byte_size:
                return None
            resolved = view.definition_for_input(operation_key, source)
            if resolved is None:
                return None
            current = resolved[0]
            continue
        if (
            operation.opcode != "LOAD"
            or len(operation.inputs) < 2
            or operation.inputs[0].kind is not VarnodeKindCode.CONSTANT
        ):
            return None
        paths = view.complete_physical_pointer_candidates_for_input(
            operation_key,
            operation.inputs[1],
        )
        return (operation_key, paths) if paths else None
    return None


def partition_span_by_overlaps(
    requested: ByteSpan,
    candidates: tuple[ByteSpan, ...],
) -> tuple[ByteSpan, ...]:
    """Partition one span at every observed overlapping byte boundary."""
    boundaries = {requested.start, requested.end}
    for candidate in candidates:
        if candidate.object_id != requested.object_id or not candidate.overlaps(requested):
            continue
        boundaries.add(max(requested.start, candidate.start))
        boundaries.add(min(requested.end, candidate.end))
    ordered = sorted(boundaries)
    return tuple(
        ByteSpan(requested.object_id, start, stop - start)
        for start, stop in zip(ordered, ordered[1:])
        if start < stop
    )


__all__ = [
    "byte_preserving_load_paths",
    "byte_preserving_load_span",
    "definition_ids_covering_span",
    "partition_span_by_overlaps",
]
