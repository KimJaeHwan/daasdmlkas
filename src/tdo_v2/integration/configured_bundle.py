"""Admission for live and read-only frozen configured Ghidra bundles."""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

from .._configured_bundle_snapshot import (
    _BundleBlock,
    _BundleContainerIdentity,
    _BundleFunction,
    _BundleInventory,
    _BundleMember,
    FORMAT_VERSION_V1,
    FORMAT_VERSION_V2,
    MAX_BLOCKS,
    MAX_CONTROL_BYTES,
    MAX_PAYLOAD_MEMBERS,
    MAX_SELECTED_FUNCTIONS,
    _admit_bundle_snapshot,
    _mint_bundle_admission,
)
from ..scope_identity import IO_CHUNK_BYTES, PositionedChunk


_LOCK_NAME = ".configured-bundle.lock"
_MANIFEST_NAME = "manifest.json"
_SEAL_NAME = "seal.json"
_WIRE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z", re.ASCII)
MAX_FROZEN_BUNDLE_BYTES = 512 * 1024 * 1024
_RECEIPT_MINT = object()


class BundleAdmissionError(ValueError):
    pass


@dataclass(frozen=True, slots=True, init=False)
class LiveBundleContainerReceipt:
    """Control-byte identity obtained from a live format-2 capture.

    Its provenance is the direct capture handoff, never report contents. It
    does not authenticate the extractor or provider by itself.
    """

    container_identity: _BundleContainerIdentity

    def __init__(self, identity: _BundleContainerIdentity, *, _mint: object) -> None:
        if _mint is not _RECEIPT_MINT or type(identity) is not _BundleContainerIdentity:
            raise TypeError("live bundle receipt requires live admission")
        if identity.format_version != FORMAT_VERSION_V2:
            raise TypeError("live bundle receipt requires format 2")
        object.__setattr__(self, "container_identity", identity)

    def __reduce_ex__(self, protocol: int):
        raise TypeError("live bundle receipt cannot be serialized")


@dataclass(frozen=True, slots=True)
class _FileHandle:
    member_id: str
    token: object


@dataclass(frozen=True, slots=True)
class _FileRecord:
    handle: _FileHandle
    name: str
    byte_size: int
    identity: tuple[int, int]


class ConfiguredBundleCapture:
    """One live generation token and exclusive cooperative freeze."""

    __slots__ = (
        "_admission",
        "_closed",
        "_generation",
        "_lock_fd",
        "_owner",
        "_receipt",
        "_root",
        "_root_fd",
        "_transferred",
    )

    def __init__(self, output_root: str | os.PathLike[str]) -> None:
        _require_nofollow()
        root = Path(output_root).expanduser().resolve(strict=False)
        root.mkdir(parents=True, exist_ok=True)
        self._root_fd = -1
        self._lock_fd = -1
        self._closed = False
        self._transferred = False
        self._owner = os.getpid()
        self._root = root
        self._generation = b""
        self._admission = None
        self._receipt = None
        try:
            root_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            self._root_fd = os.open(root, root_flags)
            _require_secure_directory(os.fstat(self._root_fd), "bundle root")
            self._generation = secrets.token_bytes(32)
            self._admission = _mint_bundle_admission(self._generation)
            flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
            flags |= os.O_NOFOLLOW
            self._lock_fd = os.open(_LOCK_NAME, flags, 0o600, dir_fd=self._root_fd)
            _require_secure_regular(os.fstat(self._lock_fd), "bundle lock")
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
            entry = os.stat(_LOCK_NAME, dir_fd=self._root_fd, follow_symlinks=False)
            opened = os.fstat(self._lock_fd)
            if (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino):
                raise BundleAdmissionError("bundle lock entry changed during admission")
        except BaseException:
            self.close()
            raise

    @property
    def generation_hex(self) -> str:
        self._require_active()
        return self._generation.hex()

    @property
    def output_root(self) -> Path:
        self._require_active()
        return self._root

    @property
    def published_path(self) -> Path:
        self._require_active()
        return self._root / self.generation_hex

    def admit_published(self):
        """Admit one exact format-2 configured bundle."""
        return self._admit_published(FORMAT_VERSION_V2)

    def admit_published_with_receipt(self):
        """Return the live snapshot and its directly captured control pin."""
        snapshot = self._admit_published(FORMAT_VERSION_V2)
        return snapshot, self.live_receipt

    @property
    def live_receipt(self) -> LiveBundleContainerReceipt:
        """Receipt retained by this capture after its lease moves to the snapshot."""
        if self._receipt is None:
            raise RuntimeError("configured bundle has no live format-2 receipt")
        return self._receipt

    def admit_published_v1_compatibility(self):
        """Admit legacy format 1 without configured call evidence."""
        return self._admit_published(FORMAT_VERSION_V1)

    def _admit_published(self, expected_version: int):
        self._require_active()
        if self._transferred:
            raise RuntimeError("configured bundle capture was already admitted")
        generation_fd = -1
        source = None
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            flags |= os.O_NOFOLLOW
            generation_fd = os.open(self.generation_hex, flags, dir_fd=self._root_fd)
            _require_secure_directory(os.fstat(generation_fd), "bundle generation")
            inventory, records = _load_inventory(
                generation_fd, self._generation, expected_version
            )
            receipt = (
                LiveBundleContainerReceipt(
                    inventory.container_identity, _mint=_RECEIPT_MINT
                )
                if expected_version == FORMAT_VERSION_V2
                else None
            )
            fcntl.flock(self._lock_fd, fcntl.LOCK_SH)
            source = _FrozenFileSource(
                self._root_fd,
                self._lock_fd,
                generation_fd,
                records,
                self._owner,
            )
            self._root_fd = -1
            self._lock_fd = -1
            generation_fd = -1
            result = _admit_bundle_snapshot(inventory, source, self._admission)
            self._receipt = receipt
            self._transferred = True
            self._closed = True
            return result
        except BaseException:
            try:
                if source is not None:
                    source.close()
                elif generation_fd >= 0:
                    os.close(generation_fd)
            finally:
                self.close()
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._admission is not None:
            self._admission.revoke()
        owner = os.getpid() == self._owner
        failures = []
        if self._lock_fd >= 0:
            try:
                if owner:
                    fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            except OSError as exc:
                failures.append(exc)
            try:
                os.close(self._lock_fd)
            except OSError as exc:
                failures.append(exc)
            self._lock_fd = -1
        if self._root_fd >= 0:
            try:
                os.close(self._root_fd)
            except OSError as exc:
                failures.append(exc)
            self._root_fd = -1
        if failures:
            raise failures[0]

    def _require_active(self) -> None:
        if self._closed or os.getpid() != self._owner:
            raise RuntimeError("configured bundle capture is not active")

    def __enter__(self) -> "ConfiguredBundleCapture":
        self._require_active()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def __reduce_ex__(self, protocol: int):
        raise TypeError("configured bundle capture cannot be serialized")


def admit_frozen_bundle(
    generation_path: str | os.PathLike[str],
    *,
    max_total_bytes: int = MAX_FROZEN_BUNDLE_BYTES,
):
    """Admit an existing format-2 generation without extraction or writes.

    The caller must retain the directory while using the returned snapshot.
    Every subsequent member read is checked again against its admitted digest.
    """
    return _admit_frozen_bundle(generation_path, max_total_bytes, None)


def admit_pinned_frozen_bundle(
    generation_path: str | os.PathLike[str],
    *,
    expected_receipt: LiveBundleContainerReceipt,
    max_total_bytes: int = MAX_FROZEN_BUNDLE_BYTES,
):
    """Admit frozen bytes only when they match a direct live-capture receipt."""
    if type(expected_receipt) is not LiveBundleContainerReceipt:
        raise BundleAdmissionError("trusted live capture receipt is required")
    return _admit_frozen_bundle(generation_path, max_total_bytes, expected_receipt)


def _admit_frozen_bundle(generation_path, max_total_bytes, expected_receipt):
    _require_nofollow()
    if (
        type(max_total_bytes) is not int
        or not 1 <= max_total_bytes <= MAX_FROZEN_BUNDLE_BYTES
    ):
        raise BundleAdmissionError("frozen bundle byte bound is invalid")
    path = Path(generation_path)
    generation = _hex_digest(path.name, "frozen bundle generation directory")
    generation_fd = -1
    source = None
    try:
        generation_fd = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        _require_secure_directory(os.fstat(generation_fd), "bundle generation")
        inventory, records = _load_inventory(generation_fd, generation, FORMAT_VERSION_V2)
        if (
            expected_receipt is not None
            and inventory.container_identity != expected_receipt.container_identity
        ):
            raise BundleAdmissionError("frozen bundle differs from trusted live receipt")
        total_bytes = inventory.container_identity.manifest_byte_size
        total_bytes += inventory.container_identity.seal_byte_size
        total_bytes += sum(row.byte_size for row in records)
        if total_bytes > max_total_bytes:
            raise BundleAdmissionError("frozen bundle exceeds its byte bound")
        _verify_frozen_members(generation_fd, inventory, records)
        if expected_receipt is not None:
            _verify_control_identity(generation_fd, expected_receipt.container_identity)
        source = _FrozenFileSource(-1, -1, generation_fd, records, os.getpid())
        generation_fd = -1
        snapshot = _admit_bundle_snapshot(
            inventory, source, _mint_bundle_admission(generation)
        )
        source = None
        return snapshot
    except BundleAdmissionError:
        raise
    except (OSError, RecursionError, TypeError, ValueError) as exc:
        raise BundleAdmissionError("frozen bundle admission failed") from exc
    finally:
        if source is not None:
            source.close()
        if generation_fd >= 0:
            os.close(generation_fd)


def _verify_control_identity(generation_fd, identity) -> None:
    for name, size, digest in (
        (
            _MANIFEST_NAME,
            identity.manifest_byte_size,
            identity.manifest_sha256_digest,
        ),
        (_SEAL_NAME, identity.seal_byte_size, identity.seal_sha256_digest),
    ):
        data, _ = _read_control_member(generation_fd, name)
        if len(data) != size or hashlib.sha256(data).digest() != digest:
            raise BundleAdmissionError("frozen bundle control bytes changed during admission")


def _verify_frozen_members(generation_fd, inventory, records) -> None:
    members = [
        inventory.original,
        inventory.program,
        inventory.call_interface_profile_member,
    ]
    members.extend(row.member for row in inventory.blocks if row.member is not None)
    for row in inventory.functions:
        members.extend(
            (row.observation_member, row.call_names_member, row.call_effects_member)
        )
    by_id = {row.member_id: row for row in members}
    for record in records:
        fd = _open_regular_member(generation_fd, record)
        try:
            digest = hashlib.sha256()
            offset = 0
            while offset < record.byte_size:
                chunk = os.pread(fd, min(IO_CHUNK_BYTES, record.byte_size - offset), offset)
                if not chunk:
                    raise BundleAdmissionError("frozen bundle member ended early")
                digest.update(chunk)
                offset += len(chunk)
            if digest.digest() != by_id[record.handle.member_id].sha256_digest:
                raise BundleAdmissionError("frozen bundle member digest mismatch")
        finally:
            os.close(fd)


class _FrozenFileSource:
    __slots__ = ("_closed", "_generation_fd", "_lock_fd", "_owner", "_records", "_root_fd")

    def __init__(self, root_fd, lock_fd, generation_fd, records, owner) -> None:
        self._root_fd = root_fd
        self._lock_fd = lock_fd
        self._generation_fd = generation_fd
        self._records = {id(row.handle): row for row in records}
        self._owner = owner
        self._closed = False

    def chunks(self, handle, offset, length):
        self._require_active()
        row = self._records.get(id(handle))
        if row is None or handle is not row.handle:
            raise ValueError("bundle file handle is foreign")
        return self._stream(row, offset, length)

    def _stream(self, row, offset, length):
        fd = _open_regular_member(self._generation_fd, row)
        try:
            position = offset
            end = offset + length
            while position < end:
                self._require_active()
                data = os.pread(fd, min(IO_CHUNK_BYTES, end - position), position)
                if not data:
                    raise BundleAdmissionError("bundle member read ended early")
                yield PositionedChunk(position, data)
                position += len(data)
        finally:
            os.close(fd)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        owner = os.getpid() == self._owner
        failures = []
        try:
            os.close(self._generation_fd)
        except OSError as exc:
            failures.append(exc)
        try:
            if owner and self._lock_fd >= 0:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
        except OSError as exc:
            failures.append(exc)
        for fd in (self._lock_fd, self._root_fd):
            if fd < 0:
                continue
            try:
                os.close(fd)
            except OSError as exc:
                failures.append(exc)
        if failures:
            raise failures[0]

    def _require_active(self) -> None:
        if self._closed or os.getpid() != self._owner:
            raise RuntimeError("bundle byte source is not active")


def _load_inventory(generation_fd: int, generation: bytes, expected_version: int):
    if type(expected_version) is not int or expected_version not in (
        FORMAT_VERSION_V1,
        FORMAT_VERSION_V2,
    ):
        raise TypeError("expected bundle format must be exactly 1 or 2")
    seal_bytes, seal_identity = _read_control_member(generation_fd, _SEAL_NAME)
    manifest_bytes, manifest_identity = _read_control_member(generation_fd, _MANIFEST_NAME)
    if seal_identity == manifest_identity:
        raise BundleAdmissionError("bundle control files must not alias")
    seal = _unique_json(seal_bytes, "bundle seal")
    _exact_keys(
        seal,
        {"schema_version", "generation_id", "manifest_size", "manifest_sha256"},
        "bundle seal",
    )
    _exact_int(
        seal["schema_version"],
        "bundle seal schema version",
        expected=expected_version,
    )
    if seal["generation_id"] != generation.hex():
        raise BundleAdmissionError("bundle seal generation does not match live admission")
    _exact_int(seal["manifest_size"], "bundle manifest size", expected=len(manifest_bytes))
    if seal["manifest_sha256"] != hashlib.sha256(manifest_bytes).hexdigest():
        raise BundleAdmissionError("bundle manifest seal does not match")

    manifest = _unique_json(manifest_bytes, "bundle manifest")
    manifest_fields = {
        "schema_version",
        "generation_id",
        "original_member_id",
        "program_member_id",
        "members",
        "blocks",
        "functions",
    }
    if expected_version == FORMAT_VERSION_V2:
        manifest_fields.add("call_interface_profile_member")
    _exact_keys(manifest, manifest_fields, "bundle manifest")
    _exact_int(
        manifest["schema_version"],
        "bundle schema version",
        expected=expected_version,
    )
    if manifest["generation_id"] != generation.hex():
        raise BundleAdmissionError("bundle manifest generation does not match admission")
    if type(manifest["members"]) is not list or type(manifest["blocks"]) is not list or type(
        manifest["functions"]
    ) is not list:
        raise BundleAdmissionError("bundle manifest collections must be arrays")
    if len(manifest["members"]) > MAX_PAYLOAD_MEMBERS:
        raise BundleAdmissionError("bundle member count exceeds the configured bound")
    if len(manifest["blocks"]) > MAX_BLOCKS:
        raise BundleAdmissionError("bundle block count exceeds the configured bound")
    if not 1 <= len(manifest["functions"]) <= MAX_SELECTED_FUNCTIONS:
        raise BundleAdmissionError("bundle function count is outside the configured bound")

    records_by_id: dict[str, _FileRecord] = {}
    members_by_id: dict[str, _BundleMember] = {}
    identities: set[tuple[int, int]] = {seal_identity, manifest_identity}
    member_names: set[str] = set()
    for raw in manifest["members"]:
        _exact_keys(raw, {"id", "path", "size", "sha256"}, "bundle member")
        member_id = _exact_id(raw["id"], "bundle member ID")
        name = _safe_name(raw["path"])
        size = _exact_int(raw["size"], "bundle member size", positive=True)
        digest = _hex_digest(raw["sha256"], "bundle member SHA-256")
        if member_id in records_by_id or name in member_names:
            raise BundleAdmissionError("bundle member IDs and paths must be unique")
        stat_result = os.stat(name, dir_fd=generation_fd, follow_symlinks=False)
        _require_secure_regular(stat_result, "bundle member")
        if stat_result.st_size != size:
            raise BundleAdmissionError("bundle member size does not match manifest")
        identity = (stat_result.st_dev, stat_result.st_ino)
        if identity in identities:
            raise BundleAdmissionError("bundle members must not alias one file")
        identities.add(identity)
        member_names.add(name)
        handle = _FileHandle(member_id, object())
        record = _FileRecord(handle, name, size, identity)
        records_by_id[member_id] = record
        members_by_id[member_id] = _BundleMember(member_id, name, size, digest, handle)

    original = _member_reference(manifest["original_member_id"], members_by_id, "original")
    program = _member_reference(manifest["program_member_id"], members_by_id, "program")
    used = {original.member_id, program.member_id}
    profile = None
    if expected_version == FORMAT_VERSION_V2:
        profile = _member_reference(
            manifest["call_interface_profile_member"],
            members_by_id,
            "call-interface profile",
        )
        used.add(profile.member_id)
    blocks = []
    for raw in manifest["blocks"]:
        fields = {
            "id",
            "space_id",
            "byte_start",
            "byte_size",
            "is_loaded",
            "is_initialized",
            "is_overlay",
            "is_external",
            "is_mapped",
            "member_id",
        }
        _exact_keys(raw, fields, "bundle block")
        member_id = raw["member_id"]
        member = None
        if member_id is not None:
            member = _member_reference(member_id, members_by_id, "block")
            used.add(member.member_id)
        blocks.append(
            _BundleBlock(
                _exact_id(raw["id"], "bundle block ID"),
                _exact_int(raw["space_id"], "bundle block space ID"),
                _exact_int(raw["byte_start"], "bundle block start"),
                _exact_int(raw["byte_size"], "bundle block size", positive=True),
                _exact_bool(raw["is_loaded"], "bundle block loaded flag"),
                _exact_bool(raw["is_initialized"], "bundle block initialized flag"),
                _exact_bool(raw["is_overlay"], "bundle block overlay flag"),
                _exact_bool(raw["is_external"], "bundle block external flag"),
                _exact_bool(raw["is_mapped"], "bundle block mapped flag"),
                member,
            )
        )
    functions = []
    for raw in manifest["functions"]:
        if expected_version == FORMAT_VERSION_V1:
            _exact_keys(raw, {"id", "member_id"}, "bundle function")
            observation = _member_reference(
                raw["member_id"], members_by_id, "function observation"
            )
            call_names = None
            effects = None
        else:
            _exact_keys(
                raw,
                {
                    "id",
                    "observation_member",
                    "call_names_member",
                    "call_effects_member",
                },
                "bundle function",
            )
            observation = _member_reference(
                raw["observation_member"],
                members_by_id,
                "function observation",
            )
            call_names = _member_reference(
                raw["call_names_member"], members_by_id, "call naming"
            )
            effects = _member_reference(
                raw["call_effects_member"], members_by_id, "call effects"
            )
        used.add(observation.member_id)
        if call_names is not None:
            used.add(call_names.member_id)
        if effects is not None:
            used.add(effects.member_id)
        functions.append(
            _BundleFunction(
                _exact_id(raw["id"], "bundle function ID"),
                observation,
                call_names,
                effects,
            )
        )
    if used != set(members_by_id):
        raise BundleAdmissionError("bundle manifest contains unreferenced members")
    if expected_version == FORMAT_VERSION_V2:
        if tuple(row.block_id for row in blocks) != tuple(
            sorted(row.block_id for row in blocks)
        ):
            raise BundleAdmissionError("bundle block IDs are not canonically ordered")
        if tuple(row.function_id for row in functions) != tuple(
            sorted(row.function_id for row in functions)
        ):
            raise BundleAdmissionError("bundle function IDs are not canonically ordered")
        role_members = [original, program, profile]
        role_members.extend(row.member for row in blocks if row.member is not None)
        for row in functions:
            role_members.extend(
                (
                    row.observation_member,
                    row.call_names_member,
                    row.call_effects_member,
                )
            )
        if tuple(members_by_id) != tuple(row.member_id for row in role_members):
            raise BundleAdmissionError(
                "bundle members do not match the canonical role-slot order"
            )
    expected_names = member_names | {_MANIFEST_NAME, _SEAL_NAME}
    if set(os.listdir(generation_fd)) != expected_names:
        raise BundleAdmissionError("bundle generation contains unlisted entries")
    container = _BundleContainerIdentity(
        expected_version,
        generation,
        len(manifest_bytes),
        hashlib.sha256(manifest_bytes).digest(),
        len(seal_bytes),
        hashlib.sha256(seal_bytes).digest(),
    )
    inventory = _BundleInventory(
        container,
        original,
        program,
        profile,
        tuple(blocks),
        tuple(functions),
    )
    return inventory, tuple(records_by_id.values())


def _read_control_member(
    generation_fd: int, name: str
) -> tuple[bytes, tuple[int, int]]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(name, flags, dir_fd=generation_fd)
    try:
        row = os.fstat(fd)
        _require_secure_regular(row, name)
        if not 1 <= row.st_size <= MAX_CONTROL_BYTES:
            raise BundleAdmissionError(f"{name} size is outside the configured bound")
        data = bytearray()
        while len(data) < row.st_size:
            piece = os.read(fd, min(IO_CHUNK_BYTES, row.st_size - len(data)))
            if not piece:
                raise BundleAdmissionError(f"{name} ended early")
            data.extend(piece)
        if os.read(fd, 1):
            raise BundleAdmissionError(f"{name} exceeds its observed size")
        return bytes(data), (row.st_dev, row.st_ino)
    finally:
        os.close(fd)


def _open_regular_member(generation_fd: int, row: _FileRecord) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(row.name, flags, dir_fd=generation_fd)
    actual = os.fstat(fd)
    try:
        _require_secure_regular(actual, "bundle member")
        if actual.st_size != row.byte_size or (actual.st_dev, actual.st_ino) != row.identity:
            raise BundleAdmissionError("bundle member changed after admission")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _unique_json(data: bytes, label: str) -> dict[str, object]:
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise BundleAdmissionError(f"{label} contains duplicate members")
            result[key] = value
        return result

    try:
        result = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                BundleAdmissionError(f"{label} contains a non-finite number")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BundleAdmissionError(f"{label} is not strict JSON") from exc
    if type(result) is not dict:
        raise BundleAdmissionError(f"{label} root must be an object")
    return result


def _exact_keys(value, names, label):
    if type(value) is not dict or set(value) != names:
        raise BundleAdmissionError(f"{label} fields do not match the format")


def _exact_int(value, label, *, expected=None, positive=False):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise BundleAdmissionError(f"{label} must be an exact unsigned integer")
    if positive and value == 0:
        raise BundleAdmissionError(f"{label} must be positive")
    if expected is not None and value != expected:
        raise BundleAdmissionError(f"{label} does not match the required value")
    return value


def _exact_text(value, label):
    if type(value) is not str or not value:
        raise BundleAdmissionError(f"{label} must be nonempty exact text")
    return value


def _exact_id(value, label):
    if (
        type(value) is not str
        or not 1 <= len(value) <= 128
        or not value.isascii()
        or _WIRE_NAME.fullmatch(value) is None
    ):
        raise BundleAdmissionError(f"{label} does not match the configured ID grammar")
    return value


def _exact_bool(value, label):
    if type(value) is not bool:
        raise BundleAdmissionError(f"{label} must be exact bool")
    return value


def _safe_name(value):
    if (
        type(value) is not str
        or not 1 <= len(value) <= 255
        or not value.isascii()
        or _WIRE_NAME.fullmatch(value) is None
        or value in {_MANIFEST_NAME, _SEAL_NAME, _LOCK_NAME}
    ):
        raise BundleAdmissionError("bundle member path is not a safe flat name")
    return value


def _hex_digest(value, label):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise BundleAdmissionError(f"{label} must be lowercase hex")
    return bytes.fromhex(value)


def _member_reference(value, members, label):
    value = _exact_id(value, f"bundle {label} member reference")
    try:
        return members[value]
    except KeyError as exc:
        raise BundleAdmissionError(f"bundle {label} member reference is unknown") from exc


def _require_secure_regular(row, label):
    if not stat.S_ISREG(row.st_mode) or row.st_uid != os.getuid() or row.st_nlink != 1:
        raise BundleAdmissionError(f"{label} is not a secure regular file")
    if row.st_mode & 0o022:
        raise BundleAdmissionError(f"{label} must not be group/other writable")


def _require_secure_directory(row, label):
    if not stat.S_ISDIR(row.st_mode) or row.st_uid != os.getuid():
        raise BundleAdmissionError(f"{label} is not a secure directory")
    if row.st_mode & 0o022:
        raise BundleAdmissionError(f"{label} must not be group/other writable")


def _require_nofollow():
    if not hasattr(os, "O_NOFOLLOW"):
        raise BundleAdmissionError("configured admission requires O_NOFOLLOW")
