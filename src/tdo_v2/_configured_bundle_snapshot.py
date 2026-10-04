"""Architect-owned admitted snapshot values for configured extraction."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from threading import current_thread
from typing import Protocol

from .scope_identity import IO_CHUNK_BYTES, PositionedChunk


FORMAT_VERSION_V1 = 1
FORMAT_VERSION_V2 = 2
MAX_SELECTED_FUNCTIONS = 4_096
MAX_BLOCKS = 65_536
MAX_PAYLOAD_MEMBERS = 77_827
MAX_CANDIDATE_BYTES = 256 * 1024 * 1024
MAX_CALL_SIDECAR_BYTES = 64 * 1024 * 1024
MAX_CALL_INTERFACE_PROFILE_BYTES = 1 * 1024 * 1024
MAX_CONTROL_BYTES = 16 * 1024 * 1024
_ADMISSION_CONSTRUCTOR = object()
_SNAPSHOT_CONSTRUCTOR = object()
_RESERVED_MEMBER_NAMES = frozenset(
    ("manifest.json", "seal.json", ".configured-bundle.lock")
)


class _BundleByteSource(Protocol):
    def chunks(self, handle: object, offset: int, length: int) -> Iterator[PositionedChunk]: ...
    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class _BundleContainerIdentity:
    format_version: int
    generation_id: bytes
    manifest_byte_size: int
    manifest_sha256_digest: bytes
    seal_byte_size: int
    seal_sha256_digest: bytes

    def __post_init__(self) -> None:
        if type(self.format_version) is not int or self.format_version not in (
            FORMAT_VERSION_V1,
            FORMAT_VERSION_V2,
        ):
            raise TypeError("bundle format version must be exactly 1 or 2")
        if type(self.generation_id) is not bytes or len(self.generation_id) != 32:
            raise TypeError("bundle generation ID must be exact 32-byte bytes")
        for label, size in (
            ("bundle manifest size", self.manifest_byte_size),
            ("bundle seal size", self.seal_byte_size),
        ):
            _require_u64(size, label)
            if not 1 <= size <= MAX_CONTROL_BYTES:
                raise ValueError(f"{label} is outside the configured bound")
        for label, digest in (
            ("bundle manifest SHA-256", self.manifest_sha256_digest),
            ("bundle seal SHA-256", self.seal_sha256_digest),
        ):
            if type(digest) is not bytes or len(digest) != 32:
                raise TypeError(f"{label} must be exact 32-byte bytes")


@dataclass(frozen=True, slots=True)
class _BundleMemberIdentity:
    member_id: str
    relative_name: str
    byte_size: int
    sha256_digest: bytes

    def __post_init__(self) -> None:
        _require_wire_id(self.member_id, "bundle member identity ID")
        if (
            type(self.relative_name) is not str
            or not 1 <= len(self.relative_name) <= 255
            or not self.relative_name.isascii()
            or self.relative_name in (".", "..")
            or self.relative_name in _RESERVED_MEMBER_NAMES
            or "/" in self.relative_name
            or "\\" in self.relative_name
            or not self.relative_name[0].isalnum()
            or any(
                character
                not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
                for character in self.relative_name
            )
        ):
            raise TypeError("bundle member identity name must be one safe relative filename")
        _require_u64(self.byte_size, "bundle member identity size")
        if self.byte_size == 0:
            raise ValueError("bundle member identity size must be positive")
        if type(self.sha256_digest) is not bytes or len(self.sha256_digest) != 32:
            raise TypeError("bundle member identity SHA-256 must be exact 32-byte bytes")


@dataclass(frozen=True, slots=True)
class _BundleMember:
    member_id: str
    relative_name: str
    byte_size: int
    sha256_digest: bytes
    source_handle: object = field(compare=False, repr=False)

    def __post_init__(self) -> None:
        _require_wire_id(self.member_id, "bundle member ID")
        if (
            type(self.relative_name) is not str
            or not 1 <= len(self.relative_name) <= 255
            or not self.relative_name.isascii()
            or self.relative_name in (".", "..")
            or self.relative_name in _RESERVED_MEMBER_NAMES
            or "/" in self.relative_name
            or "\\" in self.relative_name
            or not self.relative_name[0].isalnum()
            or any(
                character
                not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
                for character in self.relative_name
            )
        ):
            raise TypeError("bundle member name must be one safe relative filename")
        _require_u64(self.byte_size, "bundle member size")
        if self.byte_size == 0:
            raise ValueError("bundle member size must be positive")
        if type(self.sha256_digest) is not bytes or len(self.sha256_digest) != 32:
            raise TypeError("bundle member SHA-256 must be exact 32-byte bytes")

    @property
    def identity(self) -> _BundleMemberIdentity:
        return _BundleMemberIdentity(
            self.member_id,
            self.relative_name,
            self.byte_size,
            self.sha256_digest,
        )


@dataclass(frozen=True, slots=True)
class _BundleBlock:
    block_id: str
    space_id: int
    byte_start: int
    byte_size: int
    is_loaded: bool
    is_initialized: bool
    is_overlay: bool
    is_external: bool
    is_mapped: bool
    member: _BundleMember | None

    def __post_init__(self) -> None:
        _require_wire_id(self.block_id, "bundle block ID")
        for name in ("space_id", "byte_start", "byte_size"):
            _require_u64(getattr(self, name), f"bundle block {name}")
        if self.byte_size == 0 or self.byte_start + self.byte_size > 1 << 64:
            raise ValueError("bundle block extent is invalid")
        for name in (
            "is_loaded",
            "is_initialized",
            "is_overlay",
            "is_external",
            "is_mapped",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"bundle block {name} must be exact bool")
        included = (
            self.is_loaded
            and self.is_initialized
            and not self.is_overlay
            and not self.is_external
            and not self.is_mapped
        )
        if included is not (type(self.member) is _BundleMember):
            raise ValueError("bundle block member does not match structural inclusion")
        if type(self.member) is _BundleMember and self.member.byte_size != self.byte_size:
            raise ValueError("bundle block member size must match its descriptor")


@dataclass(frozen=True, slots=True)
class _BundleFunctionTransportIdentity:
    function_id: str
    observation_member: _BundleMemberIdentity
    call_names_member: _BundleMemberIdentity | None
    call_effects_member: _BundleMemberIdentity | None

    def __post_init__(self) -> None:
        _require_wire_id(self.function_id, "bundle function identity ID")
        if type(self.observation_member) is not _BundleMemberIdentity:
            raise TypeError("bundle function observation identity must be exact")
        for label, member in (
            ("call naming", self.call_names_member),
            ("call effect", self.call_effects_member),
        ):
            if member is not None and type(member) is not _BundleMemberIdentity:
                raise TypeError(f"bundle function {label} identity must be exact")
        if (self.call_names_member is None) != (self.call_effects_member is None):
            raise ValueError("bundle function identity sidecars must agree")


@dataclass(frozen=True, slots=True)
class _BundleFunction:
    function_id: str
    observation_member: _BundleMember
    call_names_member: _BundleMember | None
    call_effects_member: _BundleMember | None

    def __post_init__(self) -> None:
        _require_wire_id(self.function_id, "bundle function ID")
        if type(self.observation_member) is not _BundleMember:
            raise TypeError("bundle function observation member must be exact")
        if self.observation_member.byte_size > MAX_CANDIDATE_BYTES:
            raise ValueError("bundle function candidate exceeds configured bound")
        for label, member in (
            ("call naming", self.call_names_member),
            ("call effect", self.call_effects_member),
        ):
            if member is not None and type(member) is not _BundleMember:
                raise TypeError(f"bundle function {label} member must be exact")
            if type(member) is _BundleMember and member.byte_size > MAX_CALL_SIDECAR_BYTES:
                raise ValueError(f"bundle function {label} member exceeds configured bound")
        present = tuple(
            member
            for member in (self.call_names_member, self.call_effects_member)
            if member is not None
        )
        if len(present) == 1:
            raise ValueError("bundle function call sidecars must be both present or both absent")
        members = (self.observation_member, *present)
        if len({id(member) for member in members}) != len(members):
            raise ValueError("bundle function roles must use distinct members")

    @property
    def is_v2(self) -> bool:
        return self.call_names_member is not None

    @property
    def transport_identity(self) -> _BundleFunctionTransportIdentity:
        return _BundleFunctionTransportIdentity(
            self.function_id,
            self.observation_member.identity,
            None if self.call_names_member is None else self.call_names_member.identity,
            None if self.call_effects_member is None else self.call_effects_member.identity,
        )


@dataclass(frozen=True, slots=True)
class _BundleInventory:
    container_identity: _BundleContainerIdentity
    original: _BundleMember
    program: _BundleMember
    call_interface_profile_member: _BundleMember | None
    blocks: tuple[_BundleBlock, ...]
    functions: tuple[_BundleFunction, ...]

    def __post_init__(self) -> None:
        if type(self.container_identity) is not _BundleContainerIdentity:
            raise TypeError("bundle container identity must be exact")
        if type(self.original) is not _BundleMember or type(self.program) is not _BundleMember:
            raise TypeError("bundle original and program members must be exact")
        if self.program.byte_size > MAX_CANDIDATE_BYTES:
            raise ValueError("bundle program candidate exceeds configured bound")
        if type(self.blocks) is not tuple or any(type(row) is not _BundleBlock for row in self.blocks):
            raise TypeError("bundle blocks must be an exact tuple")
        if len(self.blocks) > MAX_BLOCKS:
            raise ValueError("bundle block count exceeds the configured bound")
        if type(self.functions) is not tuple or any(
            type(row) is not _BundleFunction for row in self.functions
        ):
            raise TypeError("bundle functions must be an exact tuple")
        if not 1 <= len(self.functions) <= MAX_SELECTED_FUNCTIONS:
            raise ValueError("bundle function count is outside the configured bound")
        if self.format_version == FORMAT_VERSION_V1:
            if self.call_interface_profile_member is not None or any(
                row.is_v2 for row in self.functions
            ):
                raise ValueError("format-1 bundle cannot contain configured call members")
        else:
            if type(self.call_interface_profile_member) is not _BundleMember:
                raise TypeError("format-2 bundle requires an exact call-interface profile member")
            if self.call_interface_profile_member.byte_size > MAX_CALL_INTERFACE_PROFILE_BYTES:
                raise ValueError("call-interface profile member exceeds configured bound")
            if any(not row.is_v2 for row in self.functions):
                raise ValueError("format-2 bundle requires both call sidecars per function")
        if len({row.block_id for row in self.blocks}) != len(self.blocks):
            raise ValueError("bundle block IDs must be unique")
        if len({row.function_id for row in self.functions}) != len(self.functions):
            raise ValueError("bundle function IDs must be unique")
        if tuple(row.block_id for row in self.blocks) != tuple(
            sorted(row.block_id for row in self.blocks)
        ):
            raise ValueError("bundle block IDs must be canonically ordered")
        if tuple(row.function_id for row in self.functions) != tuple(
            sorted(row.function_id for row in self.functions)
        ):
            raise ValueError("bundle function IDs must be canonically ordered")
        members = [self.original, self.program]
        if self.call_interface_profile_member is not None:
            members.append(self.call_interface_profile_member)
        members.extend(row.member for row in self.blocks if row.member is not None)
        for row in self.functions:
            members.append(row.observation_member)
            if row.call_names_member is not None:
                members.append(row.call_names_member)
            if row.call_effects_member is not None:
                members.append(row.call_effects_member)
        if len({row.member_id for row in members}) != len(members):
            raise ValueError("bundle member IDs must be unique")
        if len({row.relative_name for row in members}) != len(members):
            raise ValueError("bundle member names must be unique")
        if len({id(row) for row in members}) != len(members):
            raise ValueError("bundle member roles must not alias descriptors")
        if len({id(row.source_handle) for row in members}) != len(members):
            raise ValueError("bundle source handles must not alias")
        if len(members) > MAX_PAYLOAD_MEMBERS:
            raise ValueError("bundle member count exceeds the configured bound")

    @property
    def generation_id(self) -> bytes:
        return self.container_identity.generation_id

    @property
    def format_version(self) -> int:
        return self.container_identity.format_version


class _BundleAdmission:
    __slots__ = ("_active", "_generation_id")

    def __init__(self, generation_id: bytes, constructor: object) -> None:
        if constructor is not _ADMISSION_CONSTRUCTOR:
            raise PermissionError("bundle admission constructor is private")
        if type(generation_id) is not bytes or len(generation_id) != 32:
            raise TypeError("bundle generation ID must be exact 32-byte bytes")
        self._generation_id = generation_id
        self._active = True

    def revoke(self) -> None:
        self._active = False

    def __reduce_ex__(self, protocol: int):
        raise TypeError("bundle admission cannot be serialized")


def _mint_bundle_admission(generation_id: bytes) -> _BundleAdmission:
    return _BundleAdmission(generation_id, _ADMISSION_CONSTRUCTOR)


def _admit_bundle_snapshot(
    inventory: _BundleInventory,
    source: _BundleByteSource,
    admission: _BundleAdmission,
) -> "_ConfiguredBundleV2Snapshot | _ConfiguredBundleV1CompatibilitySnapshot":
    if type(inventory) is not _BundleInventory:
        raise TypeError("bundle inventory must be exact")
    if type(admission) is not _BundleAdmission or not admission._active:
        raise PermissionError("bundle admission is not active")
    if inventory.generation_id != admission._generation_id:
        raise PermissionError("bundle generation does not match admission")
    if not callable(getattr(source, "chunks", None)) or not callable(getattr(source, "close", None)):
        raise TypeError("bundle byte source does not satisfy its contract")
    admission.revoke()
    try:
        snapshot_type = (
            _ConfiguredBundleV2Snapshot
            if inventory.format_version == FORMAT_VERSION_V2
            else _ConfiguredBundleV1CompatibilitySnapshot
        )
        return snapshot_type(inventory, source, _SNAPSHOT_CONSTRUCTOR)
    except BaseException:
        source.close()
        raise


class _SnapshotClaim:
    __slots__ = ("_active", "_snapshot")

    def __init__(self, snapshot: "_ConfiguredBundleSnapshotBase", constructor: object) -> None:
        if constructor is not _SNAPSHOT_CONSTRUCTOR:
            raise PermissionError("configured snapshot claim constructor is private")
        self._snapshot = snapshot
        self._active = True

    def revoke(self) -> None:
        self._active = False

    def __reduce_ex__(self, protocol: int):
        raise TypeError("configured snapshot claims cannot be serialized")


def _claim_bundle_snapshot(
    snapshot: "_ConfiguredBundleV2Snapshot | _ConfiguredBundleV1CompatibilitySnapshot",
) -> _SnapshotClaim:
    if type(snapshot) not in (
        _ConfiguredBundleV2Snapshot,
        _ConfiguredBundleV1CompatibilitySnapshot,
    ):
        raise TypeError("configured bundle snapshot must use an exact nominal type")
    return snapshot._claim()


class _ConfiguredBundleSnapshotBase:
    __slots__ = ("_inventory", "_member_indexes", "_owner", "_source", "_state")

    def __init__(self, inventory: _BundleInventory, source: _BundleByteSource, constructor: object) -> None:
        if constructor is not _SNAPSHOT_CONSTRUCTOR:
            raise PermissionError("configured bundle snapshot constructor is private")
        self._inventory = inventory
        self._source = source
        self._owner = current_thread()
        members = [inventory.original, inventory.program]
        if inventory.call_interface_profile_member is not None:
            members.append(inventory.call_interface_profile_member)
        members.extend(row.member for row in inventory.blocks if row.member is not None)
        for row in inventory.functions:
            members.append(row.observation_member)
            if row.call_names_member is not None:
                members.append(row.call_names_member)
            if row.call_effects_member is not None:
                members.append(row.call_effects_member)
        self._member_indexes = {id(member): member for member in members}
        self._state = "active"

    def inventory(self, claim: _SnapshotClaim, /) -> _BundleInventory:
        self._require_claim(claim)
        return self._inventory

    def _claim(self) -> _SnapshotClaim:
        self._require_owner()
        if self._state != "active":
            raise RuntimeError("configured bundle snapshot is not claimable")
        token = _SnapshotClaim(self, _SNAPSHOT_CONSTRUCTOR)
        self._state = "claimed"
        return token

    def verified_chunks(
        self,
        claim: _SnapshotClaim,
        member: _BundleMember,
        offset: int = 0,
        length: int | None = None,
    ) -> Iterator[PositionedChunk]:
        self._require_claim(claim)
        self._require_member(member)
        if length is None:
            length = member.byte_size - offset
        _require_u64(offset, "bundle read offset")
        _require_u64(length, "bundle read length")
        if length == 0 or offset + length > member.byte_size:
            raise ValueError("bundle read extent is invalid")
        return self._verified_stream(claim, member, offset, length)

    def verified_bytes(
        self,
        claim: _SnapshotClaim,
        member: _BundleMember,
        *,
        max_bytes: int = MAX_CANDIDATE_BYTES,
    ) -> bytes:
        self._require_claim(claim)
        self._require_member(member)
        _require_u64(max_bytes, "bundle materialization bound")
        if max_bytes == 0:
            raise ValueError("bundle materialization bound must be positive")
        if member.byte_size > max_bytes:
            raise ValueError("bundle candidate exceeds configured bound")
        return b"".join(chunk.data for chunk in self.verified_chunks(claim, member))

    def close(self, claim: _SnapshotClaim, /) -> None:
        self._require_owner()
        if self._state == "closed":
            return
        self._require_claim(claim)
        self._state = "closed"
        claim.revoke()
        self._source.close()

    def _verified_stream(
        self,
        claim: _SnapshotClaim,
        member: _BundleMember,
        offset: int,
        length: int,
    ) -> Iterator[PositionedChunk]:
        if offset == 0 and length == member.byte_size:
            yield from self._consume(claim, member, 0, member.byte_size, verify=True)
            return

        requested_end = offset + length
        for chunk in self._consume(claim, member, 0, member.byte_size, verify=True):
            chunk_end = chunk.offset + len(chunk.data)
            start = max(offset, chunk.offset)
            end = min(requested_end, chunk_end)
            if start < end:
                relative = start - chunk.offset
                yield PositionedChunk(start, chunk.data[relative : relative + end - start])

    def _consume(
        self,
        claim: _SnapshotClaim,
        member: _BundleMember,
        offset: int,
        length: int,
        *,
        verify: bool,
    ) -> Iterator[PositionedChunk]:
        self._require_claim(claim)
        stream = self._source.chunks(member.source_handle, offset, length)
        if isinstance(stream, Sequence) or iter(stream) is not stream:
            raise ValueError("bundle member stream must be a lazy iterator")
        expected = offset
        digest = sha256() if verify else None
        for chunk in stream:
            self._require_claim(claim)
            if type(chunk) is not PositionedChunk or chunk.offset != expected:
                raise ValueError("bundle member stream is not exactly positioned")
            if len(chunk.data) > IO_CHUNK_BYTES or expected + len(chunk.data) > offset + length:
                raise ValueError("bundle member stream exceeds its requested extent")
            expected += len(chunk.data)
            if digest is not None:
                digest.update(chunk.data)
            yield chunk
        if expected != offset + length:
            raise ValueError("bundle member stream is incomplete")
        if digest is not None and digest.digest() != member.sha256_digest:
            raise ValueError("bundle member transport digest mismatch")

    def _require_member(self, member: _BundleMember) -> None:
        if type(member) is not _BundleMember:
            raise TypeError("bundle member must be exact")
        if self._member_indexes.get(id(member)) is not member:
            raise ValueError("bundle member is foreign to this snapshot")

    def _require_owner(self) -> None:
        if current_thread() is not self._owner:
            raise RuntimeError("configured bundle snapshot is owner-thread confined")

    def _require_open(self) -> None:
        self._require_owner()
        if self._state == "closed":
            raise RuntimeError("configured bundle snapshot is closed")

    def _require_claim(self, claim: object) -> None:
        self._require_owner()
        if (
            self._state != "claimed"
            or type(claim) is not _SnapshotClaim
            or claim._active is not True
            or claim._snapshot is not self
        ):
            raise RuntimeError("configured bundle snapshot claim is not active")

    def __reduce_ex__(self, protocol: int):
        raise TypeError("configured bundle snapshot cannot be serialized")


class _ConfiguredBundleV2Snapshot(_ConfiguredBundleSnapshotBase):
    __slots__ = ()

    def __init__(self, inventory, source, constructor) -> None:
        if type(inventory) is not _BundleInventory or inventory.format_version != FORMAT_VERSION_V2:
            raise TypeError("format-2 snapshot requires an exact format-2 inventory")
        super().__init__(inventory, source, constructor)


class _ConfiguredBundleV1CompatibilitySnapshot(_ConfiguredBundleSnapshotBase):
    __slots__ = ()

    def __init__(self, inventory, source, constructor) -> None:
        if type(inventory) is not _BundleInventory or inventory.format_version != FORMAT_VERSION_V1:
            raise TypeError("format-1 snapshot requires an exact compatibility inventory")
        super().__init__(inventory, source, constructor)


def _require_u64(value: object, label: str) -> None:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise TypeError(f"{label} must be an exact unsigned 64-bit int")


def _require_wire_id(value: object, label: str) -> None:
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
    if (
        type(value) is not str
        or not 1 <= len(value) <= 128
        or not value.isascii()
        or not value[0].isalnum()
        or any(character not in allowed for character in value)
    ):
        raise TypeError(f"{label} must use the configured ASCII ID grammar")
