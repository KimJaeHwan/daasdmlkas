"""Immutable input and storage models for structured Low-PCode."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from .span_geometry import (
    ByteSpan,
    StorageObjectId,
    StorageObjectKind,
    StorageScopeId,
    StorageScopeKind,
)


class VarnodeKind(StrEnum):
    CONSTANT = "constant"
    REGISTER = "register"
    UNIQUE = "unique"
    ADDRESS = "address"
    STORAGE = "storage"
    UNKNOWN = "unknown"


class UnresolvedReason(StrEnum):
    MISSING_SCOPE = "missing_scope"
    INVALID_SCOPE = "invalid_scope"
    MISSING_OFFSET = "missing_offset"
    INVALID_OFFSET = "invalid_offset"
    UNKNOWN_SPACE = "unknown_space"
    MISSING_SPACE_ID = "missing_space_id"
    INVALID_SPACE_ID = "invalid_space_id"
    CONFLICTING_SPACE = "conflicting_space"
    MISSING_UNIT = "missing_unit"
    INVALID_UNIT = "invalid_unit"
    MISSING_ADDRESS_SIZE = "missing_address_size"
    INVALID_ADDRESS_SIZE = "invalid_address_size"
    RANGE_OUT_OF_BOUNDS = "range_out_of_bounds"
    UNSUPPORTED_KIND = "unsupported_kind"


@dataclass(frozen=True, slots=True)
class StorageResolutionContext:
    program_scope: StorageScopeId | None
    function_scope: StorageScopeId | None

    def __post_init__(self) -> None:
        for field in (self.program_scope, self.function_scope):
            if field is not None and type(field) is not StorageScopeId:
                raise TypeError("resolution scopes must be exact StorageScopeId values or None")


@dataclass(frozen=True, slots=True)
class ResolvedStorage:
    span: ByteSpan

    def __post_init__(self) -> None:
        if type(self.span) is not ByteSpan:
            raise TypeError("resolved storage requires an exact ByteSpan")


@dataclass(frozen=True, slots=True)
class UnresolvedStorage:
    reason: UnresolvedReason

    def __post_init__(self) -> None:
        if type(self.reason) is not UnresolvedReason:
            raise TypeError("unresolved storage requires an exact UnresolvedReason")


@dataclass(frozen=True, slots=True)
class NonStorage:
    pass


@dataclass(frozen=True, slots=True)
class ByteRange:
    identity: str
    start: int
    size: int

    def __post_init__(self) -> None:
        if not self.identity:
            raise ValueError("byte-range identity must not be empty")
        if self.start < 0:
            raise ValueError("byte-range start must be non-negative")
        if self.size <= 0:
            raise ValueError("byte-range size must be positive")

    @property
    def end(self) -> int:
        return self.start + self.size

    def overlaps(self, other: "ByteRange") -> bool:
        return (
            self.identity == other.identity
            and self.start < other.end
            and other.start < self.end
        )

    def contains(self, other: "ByteRange") -> bool:
        return (
            self.identity == other.identity
            and self.start <= other.start
            and other.end <= self.end
        )

    def intersection(self, other: "ByteRange") -> "ByteRange | None":
        if not self.overlaps(other):
            return None
        start = max(self.start, other.start)
        end = min(self.end, other.end)
        return ByteRange(self.identity, start, end - start)


@dataclass(frozen=True, slots=True)
class RegisterAlias:
    name: str
    canonical: str
    offset: int
    size: int
    least_significant_bit: int = 0


@dataclass(frozen=True, slots=True)
class AddressSpace:
    name: str
    space_id: int | None
    address_size: int | None
    word_size: int | None
    kind: str | None
    is_memory_space: bool | None = None
    is_overlay_space: bool | None = None


@dataclass(frozen=True, slots=True)
class ArchitectureFacts:
    language_id: str | None
    processor: str | None
    compiler_spec_id: str | None
    pointer_size: int | None
    endian: str | None
    registers: tuple[RegisterAlias, ...]
    address_spaces: tuple[AddressSpace, ...]


@dataclass(frozen=True, slots=True)
class StorageRef:
    kind: VarnodeKind
    space: str
    offset: int | None
    size: int
    register_name: str | None = None
    space_id: int | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not VarnodeKind:
            raise TypeError("storage kind must be an exact VarnodeKind")
        if type(self.space) is not str:
            raise TypeError("storage space must be an exact str")
        if self.offset is not None and type(self.offset) is not int:
            raise TypeError("storage offset must be an exact int or None")
        if type(self.size) is not int:
            raise TypeError("storage size must be an exact int")
        if self.register_name is not None and type(self.register_name) is not str:
            raise TypeError("register name must be an exact str or None")
        if self.space_id is not None and type(self.space_id) is not int:
            raise TypeError("storage space ID must be an exact int or None")
        if self.size <= 0:
            raise ValueError("storage size must be positive")
        if self.space_id is not None and self.space_id < 0:
            raise ValueError("storage space ID must be non-negative")

    @property
    def stable_key(self) -> str:
        offset = "unknown" if self.offset is None else f"{self.offset:x}"
        register = self.register_name or ""
        space_id = "unknown" if self.space_id is None else f"{self.space_id:x}"
        return f"{self.kind}:{space_id}:{self.space}:{offset}:{self.size}:{register}"


@dataclass(frozen=True, slots=True)
class Varnode:
    storage: StorageRef
    address: str | None
    raw_type: str | None

    @property
    def is_constant(self) -> bool:
        return self.storage.kind is VarnodeKind.CONSTANT


@dataclass(frozen=True, slots=True)
class PcodeOperation:
    instruction_address: str
    ordinal: int
    opcode: str
    inputs: tuple[Varnode, ...]
    output: Varnode | None
    seqnum: str | None

    @property
    def stable_key(self) -> str:
        return f"{self.instruction_address}:{self.ordinal}:{self.opcode}"


@dataclass(frozen=True, slots=True)
class CallTarget:
    name: str | None
    entry: str | None
    resolved: bool
    is_external: bool


@dataclass(frozen=True, slots=True)
class Instruction:
    address: str
    length: int
    assembly: str | None
    mnemonic: str | None
    flow_type: str | None
    flow_targets: tuple[str, ...]
    fallthrough: str | None
    call_targets: tuple[CallTarget, ...]
    operations: tuple[PcodeOperation, ...]


@dataclass(frozen=True, slots=True)
class FunctionDocument:
    schema_version: int
    dumper: str | None
    function_name: str
    start_address: str
    architecture: ArchitectureFacts
    instructions: tuple[Instruction, ...]
    metadata_identity: Mapping[str, Any]
