"""Internal immutable records used by interprocedural slice completion."""

from __future__ import annotations

from dataclasses import dataclass

from .._scope_contracts import AddressCoordinate
from ..model import ByteSpan
from .configured_interprocedural_contracts import InterproceduralTransferProof


@dataclass(frozen=True, slots=True)
class PointerPath:
    anchor_definition_id: int
    anchor_byte_offset: int
    offsets: tuple[int, ...]
    byte_size: int
    address_space_id: int | None = None

    def with_offset(self, value: int) -> "PointerPath":
        return PointerPath(
            self.anchor_definition_id,
            self.anchor_byte_offset,
            self.offsets[:-1] + (self.offsets[-1] + value,),
            self.byte_size,
            self.address_space_id,
        )

    def through_load(self, address_space_id: int, byte_size: int) -> "PointerPath":
        return PointerPath(
            self.anchor_definition_id,
            self.anchor_byte_offset,
            self.offsets + (0,),
            byte_size,
            address_space_id,
        )


@dataclass(frozen=True, slots=True)
class SinkEntryDemand:
    """Exact ENTRY storage required by a sink in this function or a callee."""

    label: str
    direct_span: ByteSpan | None = None
    pointer_anchor_span: ByteSpan | None = None
    pointer_offsets: tuple[int, ...] = ()
    pointer_byte_size: int = 0
    address_space_id: int | None = None
    target_size: int = 0

    @property
    def canonical_key(self) -> tuple[object, ...]:
        if self.direct_span is not None:
            storage_key = ("direct", self.direct_span.canonical_key)
        else:
            storage_key = (
                "pointer",
                None
                if self.pointer_anchor_span is None
                else self.pointer_anchor_span.canonical_key,
                self.pointer_offsets,
                self.pointer_byte_size,
                self.address_space_id,
                self.target_size,
            )
        return (self.label, storage_key)


@dataclass(frozen=True, slots=True)
class OriginReference:
    label: str
    function_entry: AddressCoordinate
    function_scope_digest: bytes
    node: int
    prior_transfers: tuple[InterproceduralTransferProof, ...] = ()


@dataclass(frozen=True, slots=True)
class WriteEvent:
    caller_scope_digest: bytes
    call_position: int
    call_operation_key: str
    callee_entry: AddressCoordinate
    callee_scope_digest: bytes
    callee_write_operation_key: str
    target_span: ByteSpan
    pointer_dereferences: int
    origins: tuple[OriginReference, ...]
    target_path: PointerPath | None = None

    @property
    def transfer(self) -> InterproceduralTransferProof:
        return InterproceduralTransferProof(
            self.caller_scope_digest,
            self.call_operation_key,
            self.callee_entry,
            self.callee_scope_digest,
            self.callee_write_operation_key,
            self.target_span,
            self.pointer_dereferences,
        )


@dataclass(frozen=True, slots=True)
class CoordinateWriteEvent:
    call_position: int
    call_operation_key: str
    target_span: ByteSpan
    coordinate: AddressCoordinate


__all__ = [
    "CoordinateWriteEvent",
    "OriginReference",
    "PointerPath",
    "SinkEntryDemand",
    "WriteEvent",
]
