"""Architect-owned neutral contracts for configured call-interface profiles."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256


CALL_INTERFACE_PROFILE_SCHEMA_ID = "tdo-v2-call-interface-profile-v1"
CALL_INTERFACE_PROFILE_SCHEMA_VERSION = 1
CALL_INTERFACE_PROFILE_REVISION = 1
CALL_INTERFACE_PROFILE_EXPORTER_REVISION = 1
CALL_INTERFACE_PROFILE_GHIDRA_VERSION = "12.0.4"
CALL_INTERFACE_PROFILE_JVM_CHARSET = "UTF-8"
CONFIGURED_BUNDLE_MANIFEST_SCHEMA_ID = "tdo-v2-configured-bundle-manifest-v2"
CONFIGURED_BUNDLE_SEAL_SCHEMA_ID = "tdo-v2-configured-bundle-seal-v2"

MAX_PROFILE_BYTES = 1 * 1024 * 1024
MAX_PROFILE_MODELS = 256
MAX_PROFILE_TEXT_BYTES = 4_096
MAX_PACKED_IDENTITY_BYTES = 1 * 1024 * 1024
MAX_AGGREGATE_PACKED_IDENTITY_BYTES = 16 * 1024 * 1024
MAX_PROFILE_IDENTITY_FIELDS = 64
PROFILE_CAPTURE_DEADLINE_SECONDS = 60
PROFILE_CAPTURE_MAX_HEAP_BYTES = 2 * 1024 * 1024 * 1024

_LOADER_IDENTITY_DOMAIN = "tdo-v2-ghidra-loader-identity-v1"
_LANGUAGE_IDENTITY_DOMAIN = "tdo-v2-ghidra-language-identity-v1"
_COMPILER_SPEC_IDENTITY_DOMAIN = "tdo-v2-ghidra-compiler-spec-identity-v1"
_MODEL_IDENTITY_DOMAIN = "tdo-v2-ghidra-prototype-model-identity-v1"
_PROFILE_CONTENT_DOMAIN = "tdo-v2-call-interface-profile-content-v1"
_U64_LIMIT = 1 << 64


class ProfileAuthorityMode(StrEnum):
    EXPLICIT_ONLY = "EXPLICIT_ONLY"
    EXPLICIT_AND_PROGRAM_DEFAULT = "EXPLICIT_AND_PROGRAM_DEFAULT"


class DefaultModelState(StrEnum):
    ABSENT = "ABSENT"
    PRESENT = "PRESENT"
    INELIGIBLE = "INELIGIBLE"


class DefaultModelIneligibleReason(StrEnum):
    NOT_IN_INVENTORY = "NOT_IN_INVENTORY"
    AMBIGUOUS_INVENTORY_IDENTITY = "AMBIGUOUS_INVENTORY_IDENTITY"
    MERGED_MODEL = "MERGED_MODEL"
    ERROR_PLACEHOLDER = "ERROR_PLACEHOLDER"


class ProfileAdmissionStatus(StrEnum):
    ADMITTED = "ADMITTED"
    REJECTED_MODE_MISMATCH = "REJECTED_MODE_MISMATCH"
    REJECTED_LOADER_BINDING = "REJECTED_LOADER_BINDING"
    REJECTED_LANGUAGE_BINDING = "REJECTED_LANGUAGE_BINDING"
    REJECTED_MODEL_INVENTORY = "REJECTED_MODEL_INVENTORY"


@dataclass(frozen=True, slots=True)
class CapturedLoaderIdentity:
    executable_sha256: bytes
    executable_format: str
    compiler_label: str
    identity_digest: bytes

    def __post_init__(self) -> None:
        _require_digest(self.executable_sha256, "loader executable SHA-256")
        _require_text(self.executable_format, "loader executable format")
        _require_text(self.compiler_label, "loader compiler label")
        _require_digest(self.identity_digest, "loader identity digest")
        if self.identity_digest != loader_identity_digest(
            self.executable_sha256,
            self.executable_format,
            self.compiler_label,
        ):
            raise ValueError("loader identity digest does not match its fields")


@dataclass(frozen=True, slots=True)
class CapturedLanguageIdentity:
    language_id: str
    major_version: int
    minor_version: int
    is_big_endian: bool
    instruction_alignment: int
    identity_digest: bytes

    def __post_init__(self) -> None:
        _require_text(self.language_id, "language ID")
        _require_u64(self.major_version, "language major version")
        _require_u64(self.minor_version, "language minor version")
        _require_bool(self.is_big_endian, "language endianness")
        _require_u64(self.instruction_alignment, "instruction alignment")
        if not 1 <= self.instruction_alignment <= 0xFFFF_FFFF:
            raise ValueError("instruction alignment is outside its bound")
        _require_digest(self.identity_digest, "language identity digest")
        if self.identity_digest != language_identity_digest(
            self.language_id,
            self.major_version,
            self.minor_version,
            self.is_big_endian,
            self.instruction_alignment,
        ):
            raise ValueError("language identity digest does not match its fields")


@dataclass(frozen=True, slots=True)
class CapturedCompilerSpecIdentity:
    compiler_spec_id: str
    packed_encoding_size: int
    packed_encoding_digest: bytes
    identity_digest: bytes

    def __post_init__(self) -> None:
        _require_text(self.compiler_spec_id, "compiler-spec ID")
        _require_packed_size(self.packed_encoding_size, "compiler-spec encoding size")
        _require_digest(self.packed_encoding_digest, "compiler-spec encoding digest")
        _require_digest(self.identity_digest, "compiler-spec identity digest")
        if self.identity_digest != compiler_spec_identity_digest(
            self.compiler_spec_id,
            self.packed_encoding_size,
            self.packed_encoding_digest,
        ):
            raise ValueError("compiler-spec identity digest does not match its fields")


@dataclass(frozen=True, slots=True)
class CapturedModelInventoryRow:
    inventory_ordinal: int
    packed_encoding_size: int
    packed_encoding_digest: bytes
    is_merged: bool
    is_error_placeholder: bool
    is_program_extension: bool
    allow_explicit: bool
    allow_program_default: bool
    model_digest: bytes

    def __post_init__(self) -> None:
        _require_u64(self.inventory_ordinal, "model inventory ordinal")
        _require_packed_size(self.packed_encoding_size, "model encoding size")
        _require_digest(self.packed_encoding_digest, "model encoding digest")
        _require_bool(self.is_merged, "merged-model flag")
        _require_bool(self.is_error_placeholder, "error-placeholder flag")
        _require_bool(self.is_program_extension, "program-extension flag")
        _require_bool(self.allow_explicit, "explicit-model permission")
        _require_bool(self.allow_program_default, "default-model permission")
        _require_digest(self.model_digest, "model identity digest")

    @property
    def eligible(self) -> bool:
        return not self.is_merged and not self.is_error_placeholder

    def expected_model_digest(self, compiler_spec_identity_digest: bytes) -> bytes:
        return model_identity_digest(compiler_spec_identity_digest, self)


@dataclass(frozen=True, slots=True)
class CapturedDefaultModel:
    state: DefaultModelState
    inventory_ordinal: int | None = None
    model_digest: bytes | None = None
    reason: DefaultModelIneligibleReason | None = None

    def __post_init__(self) -> None:
        _require_exact(self.state, DefaultModelState, "default-model state")
        if self.state is DefaultModelState.PRESENT:
            _require_u64(self.inventory_ordinal, "default-model inventory ordinal")
            _require_digest(self.model_digest, "default-model digest")
            if self.reason is not None:
                raise ValueError("present default model cannot have a reason")
            return
        if self.inventory_ordinal is not None or self.model_digest is not None:
            raise ValueError("non-present default model cannot cite an inventory row")
        if self.state is DefaultModelState.INELIGIBLE:
            _require_exact(
                self.reason,
                DefaultModelIneligibleReason,
                "default-model ineligible reason",
            )
        elif self.reason is not None:
            raise ValueError("absent default model cannot have a reason")

    def canonical_bytes(self) -> bytes:
        if self.state is DefaultModelState.ABSENT:
            return b"\x00"
        if self.state is DefaultModelState.PRESENT:
            assert self.inventory_ordinal is not None
            assert self.model_digest is not None
            return b"\x01" + _u64(self.inventory_ordinal) + _bytes(self.model_digest)
        assert self.reason is not None
        return b"\x02" + _text(self.reason.value)


@dataclass(frozen=True, slots=True)
class ProfileTransportExpectation:
    generation_id: bytes
    manifest_schema_id: str
    seal_schema_id: str
    program_member_id: str
    program_member_sha256: bytes

    def __post_init__(self) -> None:
        _require_digest(self.generation_id, "profile generation ID")
        _require_text(self.manifest_schema_id, "manifest schema ID")
        _require_text(self.seal_schema_id, "seal schema ID")
        _require_text(self.program_member_id, "program member ID")
        _require_digest(self.program_member_sha256, "program member SHA-256")


@dataclass(frozen=True, slots=True)
class ProfileBindingExpectation:
    exporter_source_sha256: bytes
    authority_mode: ProfileAuthorityMode
    original_executable_sha256: bytes
    language_id: str
    language_major_version: int
    language_minor_version: int

    def __post_init__(self) -> None:
        _require_digest(self.exporter_source_sha256, "expected exporter source SHA-256")
        _require_exact(self.authority_mode, ProfileAuthorityMode, "expected authority mode")
        _require_digest(
            self.original_executable_sha256,
            "expected original executable SHA-256",
        )
        _require_text(self.language_id, "expected language ID")
        _require_u64(self.language_major_version, "expected language major version")
        _require_u64(self.language_minor_version, "expected language minor version")


@dataclass(frozen=True, slots=True)
class CapturedConfiguredProfile:
    exporter_source_sha256: bytes
    authority_mode: ProfileAuthorityMode
    loader: CapturedLoaderIdentity
    language: CapturedLanguageIdentity
    compiler_spec: CapturedCompilerSpecIdentity
    raw_model_count: int
    rows: tuple[CapturedModelInventoryRow, ...]
    default_model: CapturedDefaultModel
    semantic_content_digest: bytes

    def __post_init__(self) -> None:
        _require_digest(self.exporter_source_sha256, "profile exporter source SHA-256")
        _require_exact(self.authority_mode, ProfileAuthorityMode, "profile authority mode")
        _require_exact(self.loader, CapturedLoaderIdentity, "profile loader identity")
        _require_exact(self.language, CapturedLanguageIdentity, "profile language identity")
        _require_exact(
            self.compiler_spec,
            CapturedCompilerSpecIdentity,
            "profile compiler-spec identity",
        )
        _require_u64(self.raw_model_count, "raw model count")
        _require_exact_tuple(self.rows, CapturedModelInventoryRow, "model inventory")
        if len(self.rows) > MAX_PROFILE_MODELS:
            raise ValueError("model inventory exceeds its bound")
        _require_exact(self.default_model, CapturedDefaultModel, "profile default model")
        _require_digest(self.semantic_content_digest, "profile semantic content digest")

    @property
    def expected_content_digest(self) -> bytes:
        return profile_content_digest(
            self.exporter_source_sha256,
            self.authority_mode,
            self.loader,
            self.language,
            self.compiler_spec,
            self.rows,
            self.default_model,
            raw_model_count=self.raw_model_count,
        )


@dataclass(frozen=True, slots=True)
class ConfiguredProfileDecodeResult:
    status: ProfileAdmissionStatus
    profile: CapturedConfiguredProfile

    def __post_init__(self) -> None:
        _require_exact(self.status, ProfileAdmissionStatus, "profile admission status")
        _require_exact(self.profile, CapturedConfiguredProfile, "captured profile")


def loader_identity_digest(
    executable_sha256: bytes,
    executable_format: str,
    compiler_label: str,
) -> bytes:
    _require_digest(executable_sha256, "loader executable SHA-256")
    return _digest(
        _text(_LOADER_IDENTITY_DOMAIN)
        + _bytes(executable_sha256)
        + _text(executable_format)
        + _text(compiler_label)
    )


def language_identity_digest(
    language_id: str,
    major_version: int,
    minor_version: int,
    is_big_endian: bool,
    instruction_alignment: int,
) -> bytes:
    return _digest(
        _text(_LANGUAGE_IDENTITY_DOMAIN)
        + _text(language_id)
        + _u64(major_version)
        + _u64(minor_version)
        + _bool(is_big_endian)
        + _u64(instruction_alignment)
    )


def compiler_spec_identity_digest(
    compiler_spec_id: str,
    packed_encoding_size: int,
    packed_encoding_digest: bytes,
) -> bytes:
    return _digest(
        _text(_COMPILER_SPEC_IDENTITY_DOMAIN)
        + _text(CALL_INTERFACE_PROFILE_GHIDRA_VERSION)
        + _text(CALL_INTERFACE_PROFILE_JVM_CHARSET)
        + _text(compiler_spec_id)
        + _u64(packed_encoding_size)
        + _bytes(packed_encoding_digest)
    )


def model_identity_digest(
    compiler_spec_digest: bytes,
    row: CapturedModelInventoryRow,
) -> bytes:
    _require_digest(compiler_spec_digest, "compiler-spec identity digest")
    _require_exact(row, CapturedModelInventoryRow, "model inventory row")
    return _digest(
        _text(_MODEL_IDENTITY_DOMAIN)
        + _bytes(compiler_spec_digest)
        + _u64(row.inventory_ordinal)
        + _u64(row.packed_encoding_size)
        + _bytes(row.packed_encoding_digest)
        + _bool(row.is_merged)
        + _bool(row.is_error_placeholder)
        + _bool(row.is_program_extension)
    )


def profile_content_digest(
    exporter_source_sha256: bytes,
    authority_mode: ProfileAuthorityMode,
    loader: CapturedLoaderIdentity,
    language: CapturedLanguageIdentity,
    compiler_spec: CapturedCompilerSpecIdentity,
    rows: tuple[CapturedModelInventoryRow, ...],
    default_model: CapturedDefaultModel,
    *,
    raw_model_count: int | None = None,
) -> bytes:
    _require_digest(exporter_source_sha256, "exporter source SHA-256")
    _require_exact(authority_mode, ProfileAuthorityMode, "profile authority mode")
    _require_exact(loader, CapturedLoaderIdentity, "loader identity")
    _require_exact(language, CapturedLanguageIdentity, "language identity")
    _require_exact(compiler_spec, CapturedCompilerSpecIdentity, "compiler-spec identity")
    _require_exact_tuple(rows, CapturedModelInventoryRow, "model inventory")
    _require_exact(default_model, CapturedDefaultModel, "default model")
    if len(rows) > MAX_PROFILE_MODELS:
        raise ValueError("model inventory exceeds its bound")
    if raw_model_count is None:
        raw_model_count = len(rows)
    _require_u64(raw_model_count, "raw model count")
    encoded_rows = b"".join(_model_row_bytes(row) for row in rows)
    return _digest(
        _text(_PROFILE_CONTENT_DOMAIN)
        + _u64(CALL_INTERFACE_PROFILE_SCHEMA_VERSION)
        + _u64(CALL_INTERFACE_PROFILE_EXPORTER_REVISION)
        + _bytes(exporter_source_sha256)
        + _u64(CALL_INTERFACE_PROFILE_REVISION)
        + _text(authority_mode.value)
        + _text(CALL_INTERFACE_PROFILE_GHIDRA_VERSION)
        + _text(CALL_INTERFACE_PROFILE_JVM_CHARSET)
        + _bytes(loader.identity_digest)
        + _bytes(language.identity_digest)
        + _bytes(compiler_spec.identity_digest)
        + _u64(raw_model_count)
        + _u64(len(rows))
        + encoded_rows
        + default_model.canonical_bytes()
    )


def _model_row_bytes(row: CapturedModelInventoryRow) -> bytes:
    return (
        _u64(row.inventory_ordinal)
        + _u64(row.packed_encoding_size)
        + _bytes(row.packed_encoding_digest)
        + _bool(row.is_merged)
        + _bool(row.is_error_placeholder)
        + _bool(row.is_program_extension)
        + _bool(row.allow_explicit)
        + _bool(row.allow_program_default)
        + _bytes(row.model_digest)
    )


def _digest(value: bytes) -> bytes:
    return sha256(value).digest()


def _u64(value: int) -> bytes:
    _require_u64(value, "encoded integer")
    return value.to_bytes(8, byteorder="big", signed=False)


def _bool(value: bool) -> bytes:
    _require_bool(value, "encoded boolean")
    return b"\x01" if value else b"\x00"


def _bytes(value: bytes) -> bytes:
    if type(value) is not bytes:
        raise TypeError("encoded byte string must be exact bytes")
    if len(value) >= _U64_LIMIT:
        raise ValueError("encoded byte string exceeds unsigned 64-bit length")
    return _u64(len(value)) + value


def _text(value: str) -> bytes:
    _require_text(value, "encoded text")
    return _bytes(value.encode("utf-8", errors="strict"))


def _require_text(value: str, label: str) -> None:
    if type(value) is not str:
        raise TypeError(f"{label} must be exact str")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} must be strict UTF-8") from exc
    if not 1 <= len(encoded) <= MAX_PROFILE_TEXT_BYTES:
        raise ValueError(f"{label} is outside its byte bound")


def _require_digest(value: bytes, label: str) -> None:
    if type(value) is not bytes or len(value) != 32:
        raise TypeError(f"{label} must be exact 32-byte bytes")


def _require_u64(value: int | None, label: str) -> None:
    if type(value) is not int or not 0 <= value < _U64_LIMIT:
        raise TypeError(f"{label} must be an unsigned 64-bit integer")


def _require_bool(value: bool, label: str) -> None:
    if type(value) is not bool:
        raise TypeError(f"{label} must be exact bool")


def _require_packed_size(value: int, label: str) -> None:
    _require_u64(value, label)
    if not 1 <= value <= MAX_PACKED_IDENTITY_BYTES:
        raise ValueError(f"{label} is outside its bound")


def _require_exact(value: object, cls: type, label: str) -> None:
    if type(value) is not cls:
        raise TypeError(f"{label} must be exact {cls.__name__}")


def _require_exact_tuple(value: object, cls: type, label: str) -> None:
    if type(value) is not tuple or any(type(item) is not cls for item in value):
        raise TypeError(f"{label} must be an exact tuple of {cls.__name__}")
