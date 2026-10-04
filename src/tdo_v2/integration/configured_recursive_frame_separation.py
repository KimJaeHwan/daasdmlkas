"""Symbolic byte separation for complete observed frame inventories.

Call edges are caller-supplied identities, not verified target evidence. This
checker reasons over unbounded integer offsets only; it neither rules out
machine-address wrap nor proves non-escape, alias safety, return transport, or
permission to omit a configured write event.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..model import ByteSpan
from .configured_recursive_frame_inventory import (
    CallTokenObservation,
    EntryRelativeInterval,
    RecursiveFrameInventory,
)


class FrameSeparationDebtReason(StrEnum):
    INCOMPLETE_INVENTORY = "incomplete_inventory"
    UNSUPPORTED_SHAPE = "unsupported_shape"
    MISSING_OR_AMBIGUOUS_EDGE = "missing_or_ambiguous_edge"
    OVERLAPPING_FOOTPRINT = "overlapping_footprint"
    RESOURCE_BOUND = "resource_bound"


class RecursiveFrameSeparationIncomplete(RuntimeError):
    def __init__(self, reason: FrameSeparationDebtReason, detail: str) -> None:
        if type(reason) is not FrameSeparationDebtReason or type(detail) is not str:
            raise TypeError("frame separation debt requires exact reason and detail")
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason.value}: {detail}")


@dataclass(frozen=True, slots=True)
class CallerSuppliedCallEdge:
    caller_scope_digest: bytes
    call_operation_key: str
    callee_scope_digest: bytes

    def __post_init__(self) -> None:
        if (
            type(self.caller_scope_digest) is not bytes
            or len(self.caller_scope_digest) != 32
            or type(self.callee_scope_digest) is not bytes
            or len(self.callee_scope_digest) != 32
            or type(self.call_operation_key) is not str
            or not self.call_operation_key
        ):
            raise TypeError("call edge requires exact scope digests and operation key")


@dataclass(frozen=True, slots=True)
class SymbolicCallSeparation:
    caller_scope_digest: bytes
    call_operation_key: str
    callee_scope_digest: bytes
    child_entry_offset: int
    call_token_start: int
    call_token_stop: int
    parent_local_floor: int
    child_local_floor_in_parent: int


@dataclass(frozen=True, slots=True)
class SymbolicFrameSeparation:
    calls: tuple[SymbolicCallSeparation, ...]
    assumption: str = "unbounded_integer_offsets_only; no concrete address or privacy claim"


@dataclass(frozen=True, slots=True)
class _Shape:
    inventory: RecursiveFrameInventory
    anchor_span: ByteSpan
    address_space_id: int
    word_size: int
    ordinary: tuple[EntryRelativeInterval, ...]
    local_floor: int
    calls: dict[str, CallTokenObservation]


def _debt(reason: FrameSeparationDebtReason, detail: str) -> None:
    raise RecursiveFrameSeparationIncomplete(reason, detail)


def _same_anchor(left: EntryRelativeInterval, right: EntryRelativeInterval) -> bool:
    return (
        left.anchor_definition_id == right.anchor_definition_id
        and left.anchor_span == right.anchor_span
        and left.address_space_id == right.address_space_id
    )


def _overlap(left: EntryRelativeInterval, right: EntryRelativeInterval) -> bool:
    return left.offset < right.stop and right.offset < left.stop


def _validate_interval(interval: EntryRelativeInterval) -> None:
    if (
        type(interval) is not EntryRelativeInterval
        or type(interval.anchor_definition_id) is not int
        or interval.anchor_definition_id < 0
        or type(interval.anchor_span) is not ByteSpan
        or type(interval.address_space_id) is not int
        or interval.address_space_id < 0
        or type(interval.offset) is not int
        or type(interval.byte_size) is not int
        or interval.byte_size <= 0
    ):
        _debt(FrameSeparationDebtReason.UNSUPPORTED_SHAPE, "non-exact integer byte interval")


def _shape(inventory: RecursiveFrameInventory) -> _Shape:
    if (
        type(inventory.function_scope_digest) is not bytes
        or len(inventory.function_scope_digest) != 32
        or type(inventory.observation_digest) is not bytes
        or len(inventory.observation_digest) != 32
        or type(inventory.memory_unit_digest) is not bytes
        or len(inventory.memory_unit_digest) != 32
    ):
        _debt(FrameSeparationDebtReason.UNSUPPORTED_SHAPE, "invalid inventory identities")
    if not inventory.complete:
        _debt(FrameSeparationDebtReason.INCOMPLETE_INVENTORY, "unresolved observed access")
    if not inventory.return_tokens:
        _debt(FrameSeparationDebtReason.UNSUPPORTED_SHAPE, "missing observed return token")
    first_return = inventory.return_tokens[0].interval
    _validate_interval(first_return)
    width = first_return.byte_size
    if width <= 0 or first_return.offset != 0:
        _debt(FrameSeparationDebtReason.UNSUPPORTED_SHAPE, "return token is not entry-relative [0, width)")
    for ret in inventory.return_tokens:
        _validate_interval(ret.interval)
        if (
            type(ret.after_offset) is not int
            or
            not _same_anchor(first_return, ret.interval)
            or ret.interval.offset != 0
            or ret.interval.byte_size != width
            or ret.after_offset != width
        ):
            _debt(FrameSeparationDebtReason.UNSUPPORTED_SHAPE, "inconsistent return-token layout")
    rows = {row.operation_key: row for row in inventory.accesses}
    if len(rows) != len(inventory.accesses):
        _debt(FrameSeparationDebtReason.UNSUPPORTED_SHAPE, "duplicate raw memory operation")
    return_loads = {ret.load_operation_key for ret in inventory.return_tokens}
    token_stores = {call.store_operation_key for call in inventory.call_tokens}
    if len(token_stores) != len(inventory.call_tokens):
        _debt(FrameSeparationDebtReason.UNSUPPORTED_SHAPE, "duplicate call-token store")
    if return_loads & token_stores:
        _debt(FrameSeparationDebtReason.UNSUPPORTED_SHAPE, "return load aliases call-token operation")
    for ret in inventory.return_tokens:
        raw = rows.get(ret.load_operation_key)
        if raw is None or raw.opcode != "LOAD" or raw.interval != ret.interval:
            _debt(FrameSeparationDebtReason.UNSUPPORTED_SHAPE, "return token lacks exact raw LOAD")
    ordinary = []
    stores = []
    for row in inventory.accesses:
        access = row.interval
        if access is None:
            _debt(FrameSeparationDebtReason.INCOMPLETE_INVENTORY, "unresolved raw memory operation")
        _validate_interval(access)
        if row.operation_key in return_loads or row.operation_key in token_stores:
            continue
        if (
            row.opcode not in {"LOAD", "STORE"}
            or not _same_anchor(first_return, access)
            or access.byte_size <= 0
            or access.offset >= 0
            or access.stop > 0
        ):
            _debt(FrameSeparationDebtReason.UNSUPPORTED_SHAPE, "ordinary access is not within one negative frame")
        ordinary.append(access)
        if row.opcode == "STORE":
            if any(_overlap(access, previous) for previous in stores):
                _debt(FrameSeparationDebtReason.OVERLAPPING_FOOTPRINT, "ordinary STORE intervals overlap")
            stores.append(access)
    floor = min((access.offset for access in ordinary), default=0)
    calls: dict[str, CallTokenObservation] = {}
    for call in inventory.call_tokens:
        access = call.interval
        _validate_interval(access)
        raw = rows.get(call.store_operation_key)
        if (
            type(call.before_offset) is not int
            or call.call_operation_key in calls
            or raw is None
            or raw.opcode != "STORE"
            or raw.interval != access
            or not _same_anchor(first_return, access)
            or access.byte_size != width
            or access.offset >= 0
            or access.stop != call.before_offset
            or access.stop > floor
        ):
            _debt(FrameSeparationDebtReason.OVERLAPPING_FOOTPRINT, "call token is not below ordinary locals")
        calls[call.call_operation_key] = call
    return _Shape(
        inventory, first_return.anchor_span,
        first_return.address_space_id, width, tuple(ordinary), floor, calls,
    )


def check_symbolic_frame_separation(
    inventories: tuple[RecursiveFrameInventory, ...],
    edges: tuple[CallerSuppliedCallEdge, ...],
    /,
    *,
    max_functions: int = 64,
    max_accesses: int = 4096,
    max_edges: int = 256,
) -> SymbolicFrameSeparation:
    """Check closed call-edge spatial geometry, with no export authority."""
    if (
        type(inventories) is not tuple
        or any(type(row) is not RecursiveFrameInventory for row in inventories)
        or type(edges) is not tuple
        or any(type(row) is not CallerSuppliedCallEdge for row in edges)
    ):
        raise TypeError("symbolic separation requires exact immutable inventories and edges")
    limits = (max_functions, max_accesses, max_edges)
    if any(type(limit) is not int or limit <= 0 for limit in limits):
        raise ValueError("symbolic separation limits must be positive exact integers")
    if (
        len(inventories) > max_functions
        or sum(len(row.accesses) for row in inventories) > max_accesses
        or len(edges) > max_edges
    ):
        _debt(FrameSeparationDebtReason.RESOURCE_BOUND, "symbolic separation resource limit")
    by_scope = {row.function_scope_digest: row for row in inventories}
    if len(by_scope) != len(inventories):
        _debt(FrameSeparationDebtReason.UNSUPPORTED_SHAPE, "duplicate function scope")
    shapes = {key: _shape(row) for key, row in by_scope.items()}
    expected = {(key, call_key) for key, shape in shapes.items() for call_key in shape.calls}
    actual = {(edge.caller_scope_digest, edge.call_operation_key) for edge in edges}
    if len(actual) != len(edges) or actual != expected:
        _debt(FrameSeparationDebtReason.MISSING_OR_AMBIGUOUS_EDGE, "call edges are not an exact closed inventory")
    separated = []
    for edge in sorted(edges, key=lambda item: (item.caller_scope_digest, item.call_operation_key, item.callee_scope_digest)):
        caller = shapes.get(edge.caller_scope_digest)
        callee = shapes.get(edge.callee_scope_digest)
        if caller is None or callee is None:
            _debt(FrameSeparationDebtReason.MISSING_OR_AMBIGUOUS_EDGE, "callee has no complete frame inventory")
        call = caller.calls[edge.call_operation_key]
        if (
            caller.anchor_span != callee.anchor_span
            or caller.address_space_id != callee.address_space_id
            or caller.word_size != callee.word_size
        ):
            _debt(FrameSeparationDebtReason.UNSUPPORTED_SHAPE, "call endpoints disagree on physical stack base")
        child_entry = call.interval.offset
        if child_entry >= 0 or call.interval.stop > caller.local_floor:
            _debt(FrameSeparationDebtReason.OVERLAPPING_FOOTPRINT, "child entry or token overlaps caller frame")
        for access in callee.ordinary:
            projected_start = child_entry + access.offset
            projected_stop = child_entry + access.stop
            if projected_stop > call.interval.offset or any(
                projected_start < parent.stop and parent.offset < projected_stop
                for parent in caller.ordinary
            ):
                _debt(FrameSeparationDebtReason.OVERLAPPING_FOOTPRINT, "child local overlaps caller frame or token")
        separated.append(SymbolicCallSeparation(
            edge.caller_scope_digest, edge.call_operation_key,
            edge.callee_scope_digest, child_entry, call.interval.offset,
            call.interval.stop, caller.local_floor,
            child_entry + callee.local_floor,
        ))
    return SymbolicFrameSeparation(tuple(separated))


__all__ = [
    "CallerSuppliedCallEdge", "FrameSeparationDebtReason",
    "RecursiveFrameSeparationIncomplete", "SymbolicCallSeparation",
    "SymbolicFrameSeparation", "check_symbolic_frame_separation",
]
