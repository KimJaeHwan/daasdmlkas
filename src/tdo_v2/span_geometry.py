"""Minimal immutable storage identity and half-open byte-span geometry."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


STORAGE_GEOMETRY_CONTRACT_VERSION = 1


class StorageScopeKind(StrEnum):
    PROGRAM = "program"
    FUNCTION = "function"


class StorageObjectKind(StrEnum):
    REGISTER_FILE = "register_file"
    ADDRESS_SPACE = "address_space"
    FUNCTION_UNIQUE = "function_unique"
    FUNCTION_RELATIVE = "function_relative"


@dataclass(frozen=True, order=True, slots=True)
class StorageScopeId:
    kind: StorageScopeKind
    digest: bytes

    def __post_init__(self) -> None:
        if type(self.kind) is not StorageScopeKind:
            raise TypeError("storage scope kind must be an exact StorageScopeKind")
        if type(self.digest) is not bytes:
            raise TypeError("storage scope digest must be exact bytes")
        if len(self.digest) != 32:
            raise ValueError("storage scope digest must contain exactly 32 bytes")


@dataclass(frozen=True, order=True, slots=True)
class StorageObjectId:
    kind: StorageObjectKind
    scope: StorageScopeId
    space_key: int

    def __post_init__(self) -> None:
        if type(self.kind) is not StorageObjectKind:
            raise TypeError("storage object kind must be an exact StorageObjectKind")
        if type(self.scope) is not StorageScopeId:
            raise TypeError("storage object scope must be an exact StorageScopeId")
        if type(self.space_key) is not int:
            raise TypeError("storage object space key must be an exact int")

        required_scope = (
            StorageScopeKind.FUNCTION
            if self.kind in (
                StorageObjectKind.FUNCTION_UNIQUE,
                StorageObjectKind.FUNCTION_RELATIVE,
            )
            else StorageScopeKind.PROGRAM
        )
        if self.scope.kind is not required_scope:
            raise TypeError(f"{self.kind.value} requires a {required_scope.value} scope")
        if self.space_key < 0:
            raise ValueError("storage object space key must be non-negative")
        if self.kind in (
            StorageObjectKind.REGISTER_FILE,
            StorageObjectKind.FUNCTION_UNIQUE,
        ) and self.space_key != 0:
            raise ValueError(f"{self.kind.value} requires space key zero")


@dataclass(frozen=True, order=True, slots=True)
class ByteSpan:
    object_id: StorageObjectId
    start: int
    size: int

    def __post_init__(self) -> None:
        if type(self.object_id) is not StorageObjectId:
            raise TypeError("byte span object must be an exact StorageObjectId")
        if type(self.start) is not int:
            raise TypeError("byte span start must be an exact int")
        if type(self.size) is not int:
            raise TypeError("byte span size must be an exact int")
        if self.start < 0:
            raise ValueError("byte span start must be non-negative")
        if self.size <= 0:
            raise ValueError("byte span size must be positive")

    @property
    def end(self) -> int:
        return self.start + self.size

    def overlaps(self, other: "ByteSpan") -> bool:
        self._require_span(other)
        return (
            self.object_id == other.object_id
            and self.start < other.end
            and other.start < self.end
        )

    def contains(self, other: "ByteSpan") -> bool:
        self._require_span(other)
        return (
            self.object_id == other.object_id
            and self.start <= other.start
            and other.end <= self.end
        )

    def intersection(self, other: "ByteSpan") -> "ByteSpan | None":
        self._require_span(other)
        if not self.overlaps(other):
            return None
        start = max(self.start, other.start)
        end = min(self.end, other.end)
        return ByteSpan(self.object_id, start, end - start)

    def subtract(self, other: "ByteSpan") -> tuple["ByteSpan", ...]:
        self._require_span(other)
        overlap = self.intersection(other)
        if overlap is None:
            return (self,)
        residuals: list[ByteSpan] = []
        if self.start < overlap.start:
            residuals.append(ByteSpan(self.object_id, self.start, overlap.start - self.start))
        if overlap.end < self.end:
            residuals.append(ByteSpan(self.object_id, overlap.end, self.end - overlap.end))
        return tuple(residuals)

    @property
    def canonical_key(self) -> tuple[str, ...]:
        return (
            "storage-v1",
            self.object_id.kind.value,
            self.object_id.scope.kind.value,
            self.object_id.scope.digest.hex(),
            format(self.object_id.space_key, "x"),
            format(self.start, "x"),
            format(self.size, "x"),
        )

    @classmethod
    def from_canonical_key(cls, value: object) -> "ByteSpan":
        try:
            if type(value) is not tuple or len(value) != 7:
                raise ValueError("canonical storage key must be an exact seven-item tuple")
            if any(type(field) is not str for field in value):
                raise ValueError("canonical storage key fields must be exact strings")
            version, object_kind, scope_kind, digest_hex, key_hex, start_hex, size_hex = value
            if version != "storage-v1":
                raise ValueError("unsupported canonical storage key version")
            if len(digest_hex) != 64 or any(c not in "0123456789abcdef" for c in digest_hex):
                raise ValueError("scope digest must be 64 lowercase hexadecimal characters")
            integers = (key_hex, start_hex, size_hex)
            if any(not _is_canonical_hex(field) for field in integers):
                raise ValueError("storage integers must use canonical lowercase hexadecimal")
            scope = StorageScopeId(StorageScopeKind(scope_kind), bytes.fromhex(digest_hex))
            object_id = StorageObjectId(
                StorageObjectKind(object_kind), scope, int(key_hex, 16)
            )
            return cls(object_id, int(start_hex, 16), int(size_hex, 16))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid canonical storage key: {exc}") from exc

    @staticmethod
    def _require_span(other: object) -> None:
        if type(other) is not ByteSpan:
            raise TypeError("geometry operand must be an exact ByteSpan")


def _is_canonical_hex(value: str) -> bool:
    if not value or any(c not in "0123456789abcdef" for c in value):
        return False
    return value == "0" or not value.startswith("0")


__all__ = (
    "STORAGE_GEOMETRY_CONTRACT_VERSION",
    "ByteSpan",
    "StorageObjectId",
    "StorageObjectKind",
    "StorageScopeId",
    "StorageScopeKind",
)
