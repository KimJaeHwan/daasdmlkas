"""Two-phase loaded-memory planning and exact positioned-stream validation."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256

from ._scope_contracts import (
    CommittedMemoryRun,
    FrozenMemoryBlockDescriptor,
    PositionedChunk,
    U64_MAX,
    require_bool,
    require_u64,
)
from ._scope_wire import _LoadedMemoryDigestBuilder


class _MemoryFailureKind(StrEnum):
    CONFLICTING = "conflicting"
    INCOMPLETE = "incomplete"
    MISSING = "missing"


class _MemoryCommitmentError(ValueError):
    def __init__(self, kind: _MemoryFailureKind) -> None:
        self.kind = kind
        super().__init__(kind.value)


@dataclass(frozen=True, slots=True)
class _ReadSpan:
    handle: object
    block_offset: int
    length: int


@dataclass(frozen=True, slots=True)
class _PlannedRun:
    committed: CommittedMemoryRun
    spans: tuple[_ReadSpan, ...]


@dataclass(frozen=True, slots=True)
class _MemoryCommitment:
    digest: bytes
    runs: tuple[CommittedMemoryRun, ...]


def _original_executable_digest(size: object, chunks: object) -> bytes:
    try:
        require_u64(size, "original executable size")
    except (TypeError, ValueError) as exc:
        raise _MemoryCommitmentError(_MemoryFailureKind.INCOMPLETE) from exc
    if size == 0:
        raise _MemoryCommitmentError(_MemoryFailureKind.INCOMPLETE)
    digest = sha256()
    for chunk in _consume_positioned(chunks, 0, size):
        digest.update(chunk.data)
    return digest.digest()


def _loaded_memory_commitment(
    descriptors: object,
    snapshot_complete: object,
    read_exact: Callable[[object, int, int], object],
) -> _MemoryCommitment:
    planned, structurally_incomplete = _plan_runs(descriptors)
    if structurally_incomplete:
        completeness_ok = False
    else:
        try:
            marker = snapshot_complete() if callable(snapshot_complete) else snapshot_complete
            require_bool(marker, "snapshot completeness")
            completeness_ok = marker is True
        except Exception:
            completeness_ok = False
    if not completeness_ok:
        raise _MemoryCommitmentError(_MemoryFailureKind.INCOMPLETE)
    if not planned:
        raise _MemoryCommitmentError(_MemoryFailureKind.MISSING)

    builder = _LoadedMemoryDigestBuilder(len(planned))
    for run in planned:
        builder.start_run(run.committed)
        if not run.committed.is_initialized:
            continue
        for span in run.spans:
            try:
                stream = read_exact(span.handle, span.block_offset, span.length)
                for chunk in _consume_positioned(
                    stream,
                    span.block_offset,
                    span.block_offset + span.length,
                ):
                    builder.update_bytes(chunk.data)
            except _MemoryCommitmentError:
                raise
            except Exception as exc:
                raise _MemoryCommitmentError(_MemoryFailureKind.INCOMPLETE) from exc
    return _MemoryCommitment(
        digest=builder.finish(),
        runs=tuple(run.committed for run in planned),
    )


def _plan_runs(descriptors: object) -> tuple[tuple[_PlannedRun, ...], bool]:
    if type(descriptors) is not tuple:
        return (), True
    included: list[FrozenMemoryBlockDescriptor] = []
    incomplete = False
    for row in descriptors:
        if type(row) is not FrozenMemoryBlockDescriptor:
            incomplete = True
            continue
        if not row.is_loaded:
            continue
        if row.is_overlay or row.is_mapped:
            incomplete = True
            continue
        if row.is_external:
            continue
        included.append(row)

    included.sort(key=lambda row: (row.space_id, row.byte_start))
    for left, right in zip(included, included[1:]):
        if left.space_id == right.space_id and right.byte_start < left.byte_start + left.byte_size:
            raise _MemoryCommitmentError(_MemoryFailureKind.CONFLICTING)

    logical: list[tuple[int, int, int, bool, list[_ReadSpan]]] = []
    for row in included:
        span = _ReadSpan(row.block_handle, 0, row.byte_size)
        if logical:
            space_id, start, size, initialized, spans = logical[-1]
            if (
                space_id == row.space_id
                and start + size == row.byte_start
                and initialized is row.is_initialized
            ):
                spans.append(span)
                logical[-1] = (
                    space_id,
                    start,
                    size + row.byte_size,
                    initialized,
                    spans,
                )
                continue
        logical.append((row.space_id, row.byte_start, row.byte_size, row.is_initialized, [span]))

    split: list[_PlannedRun] = []
    for space_id, start, size, initialized, spans in logical:
        split.extend(_split_logical_run(space_id, start, size, initialized, tuple(spans)))
    return tuple(split), incomplete


def _split_logical_run(
    space_id: int,
    start: int,
    size: int,
    initialized: bool,
    spans: tuple[_ReadSpan, ...],
) -> tuple[_PlannedRun, ...]:
    result: list[_PlannedRun] = []
    remaining = size
    run_start = start
    span_index = 0
    span_consumed = 0
    while remaining:
        piece_size = min(remaining, U64_MAX)
        piece_remaining = piece_size
        piece_spans: list[_ReadSpan] = []
        while piece_remaining:
            span = spans[span_index]
            available = span.length - span_consumed
            take = min(piece_remaining, available)
            piece_spans.append(
                _ReadSpan(span.handle, span.block_offset + span_consumed, take)
            )
            piece_remaining -= take
            span_consumed += take
            if span_consumed == span.length:
                span_index += 1
                span_consumed = 0
        result.append(
            _PlannedRun(
                CommittedMemoryRun(space_id, run_start, piece_size, initialized),
                tuple(piece_spans) if initialized else (),
            )
        )
        run_start += piece_size
        remaining -= piece_size
    return tuple(result)


def _consume_positioned(
    stream: object,
    expected_start: int,
    expected_end: int,
) -> Iterator[PositionedChunk]:
    if isinstance(stream, Sequence):
        raise _MemoryCommitmentError(_MemoryFailureKind.INCOMPLETE)
    try:
        iterator = iter(stream)
    except TypeError as exc:
        raise _MemoryCommitmentError(_MemoryFailureKind.INCOMPLETE) from exc
    if iterator is not stream:
        raise _MemoryCommitmentError(_MemoryFailureKind.INCOMPLETE)
    offset = expected_start
    while True:
        try:
            chunk = next(iterator)
        except StopIteration:
            break
        except Exception as exc:
            raise _MemoryCommitmentError(_MemoryFailureKind.INCOMPLETE) from exc
        if type(chunk) is not PositionedChunk or chunk.offset != offset:
            raise _MemoryCommitmentError(_MemoryFailureKind.INCOMPLETE)
        offset += len(chunk.data)
        if offset > expected_end:
            raise _MemoryCommitmentError(_MemoryFailureKind.INCOMPLETE)
        yield chunk
    if offset != expected_end:
        raise _MemoryCommitmentError(_MemoryFailureKind.INCOMPLETE)
