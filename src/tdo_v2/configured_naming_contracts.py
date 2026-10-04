"""Architect-owned neutral contracts for configured call-naming capture."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256

from ._scope_contracts import AddressCoordinate, ValidatedVarnode, VarnodeKindCode
from .configured_profile_contracts import (
    CONFIGURED_BUNDLE_MANIFEST_SCHEMA_ID,
    CONFIGURED_BUNDLE_SEAL_SCHEMA_ID,
)


CALL_NAMING_SCHEMA_ID = "tdo-v2-call-naming-sidecar-v1"
CALL_NAMING_SCHEMA_VERSION = 1
CALL_NAMING_EXPORTER_REVISION = 1
CALL_NAMING_GHIDRA_VERSION = "12.0.4"
CALL_NAMING_INVENTORY_COMPLETENESS = "COMPLETE"

MAX_NAMING_MEMBER_BYTES = 64 * 1024 * 1024
MAX_NAMING_ROWS = 16_384
MAX_NAMING_THUNK_EDGES = 64
MAX_NAMING_TARGETS = MAX_NAMING_THUNK_EDGES + 1
MAX_NAMING_ALIASES_PER_TARGET = 16
MAX_NAMING_SCANNED_SYMBOLS_PER_TARGET = 64
MAX_NAMING_ALIAS_BYTES = 4_096
MAX_NAMING_AGGREGATE_ALIAS_BYTES = 1 * 1024 * 1024
NAMING_CAPTURE_DEADLINE_SECONDS = 60

_TARGET_DOMAIN = "tdo-v2-call-naming-target-v1"
_ROW_DOMAIN = "tdo-v2-call-naming-row-v1"
_CONTENT_DOMAIN = "tdo-v2-call-naming-content-v1"
_BOUNDARY_TARGET_DOMAIN = "tdo-v2-configured-boundary-target-v1"
_U64_LIMIT = 1 << 64


class NamingOpcode(StrEnum):
    CALL = "CALL"
    CALLIND = "CALLIND"


class NamingSourceQuality(StrEnum):
    DEFAULT = "DEFAULT"
    ANALYSIS = "ANALYSIS"
    AI = "AI"
    IMPORTED = "IMPORTED"
    USER_DEFINED = "USER_DEFINED"


class NamingAliasKind(StrEnum):
    SYMBOL = "SYMBOL"
    ORIGINAL_IMPORT = "ORIGINAL_IMPORT"


class NamingResolutionState(StrEnum):
    INDIRECT = "INDIRECT"
    UNRESOLVED = "UNRESOLVED"
    RESOLVED_NAMED = "RESOLVED_NAMED"
    RESOLVED_UNNAMED = "RESOLVED_UNNAMED"


class NamingUnresolvedReason(StrEnum):
    MISSING_SELECTOR = "MISSING_SELECTOR"
    OPAQUE_SELECTOR = "OPAQUE_SELECTOR"
    NON_ADDRESS_SELECTOR = "NON_ADDRESS_SELECTOR"
    NO_EXACT_FUNCTION = "NO_EXACT_FUNCTION"
    THUNK_TARGET_MISSING = "THUNK_TARGET_MISSING"
    THUNK_CYCLE = "THUNK_CYCLE"
    THUNK_DEPTH_EXCEEDED = "THUNK_DEPTH_EXCEEDED"


@dataclass(frozen=True, slots=True)
class NamingTransportExpectation:
    generation_id: bytes
    manifest_schema_id: str
    seal_schema_id: str
    observation_member_id: str
    observation_member_sha256: bytes
    function_entry: AddressCoordinate

    def __post_init__(self) -> None:
        _require_digest(self.generation_id, "naming generation ID")
        _require_exact_text(
            self.manifest_schema_id,
            CONFIGURED_BUNDLE_MANIFEST_SCHEMA_ID,
            "naming manifest schema ID",
        )
        _require_exact_text(
            self.seal_schema_id,
            CONFIGURED_BUNDLE_SEAL_SCHEMA_ID,
            "naming seal schema ID",
        )
        _require_text(self.observation_member_id, "observation member ID")
        _require_digest(
            self.observation_member_sha256,
            "observation member SHA-256",
        )
        _require_exact(self.function_entry, AddressCoordinate, "function entry")


@dataclass(frozen=True, slots=True)
class NamingBindingExpectation:
    exporter_source_sha256: bytes
    ghidra_version: str

    def __post_init__(self) -> None:
        _require_digest(self.exporter_source_sha256, "naming exporter source SHA-256")
        _require_exact_text(
            self.ghidra_version,
            CALL_NAMING_GHIDRA_VERSION,
            "naming Ghidra version",
        )


@dataclass(frozen=True, order=True, slots=True)
class CapturedNamingAlias:
    kind: NamingAliasKind
    value: str
    source_quality: NamingSourceQuality | None = None

    def __post_init__(self) -> None:
        _require_exact(self.kind, NamingAliasKind, "naming alias kind")
        _require_alias_text(self.value)
        if self.kind is NamingAliasKind.SYMBOL:
            _require_exact(
                self.source_quality,
                NamingSourceQuality,
                "symbol alias source quality",
            )
        elif self.source_quality is not None:
            raise ValueError("original-import alias cannot have source quality")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (
            0 if self.kind is NamingAliasKind.SYMBOL else 1,
            "" if self.source_quality is None else self.source_quality.value,
            self.value.encode("utf-8", errors="strict"),
        )

    def canonical_bytes(self) -> bytes:
        if self.kind is NamingAliasKind.SYMBOL:
            assert self.source_quality is not None
            return b"\x00" + _text(self.source_quality.value) + _text(self.value)
        return b"\x01" + _text(self.value)

    @property
    def policy_admissible(self) -> bool:
        return self.kind is NamingAliasKind.ORIGINAL_IMPORT or (
            self.source_quality is not NamingSourceQuality.DEFAULT
        )


@dataclass(frozen=True, slots=True)
class CapturedNamingTarget:
    target_ordinal: int
    coordinate: AddressCoordinate
    is_external: bool
    is_thunk: bool
    aliases: tuple[CapturedNamingAlias, ...]
    target_digest: bytes

    def __post_init__(self) -> None:
        _require_u64(self.target_ordinal, "naming target ordinal")
        _require_exact(self.coordinate, AddressCoordinate, "naming target coordinate")
        _require_bool(self.is_external, "external target flag")
        _require_bool(self.is_thunk, "thunk target flag")
        _require_exact_tuple(self.aliases, CapturedNamingAlias, "naming target aliases")
        if len(self.aliases) > MAX_NAMING_ALIASES_PER_TARGET:
            raise ValueError("naming target aliases exceed their bound")
        if len(set(self.aliases)) != len(self.aliases):
            raise ValueError("naming target aliases must be unique")
        if tuple(sorted(self.aliases, key=lambda item: item.canonical_key)) != self.aliases:
            raise ValueError("naming target aliases must be canonical and ordered")
        original_import_count = sum(
            alias.kind is NamingAliasKind.ORIGINAL_IMPORT for alias in self.aliases
        )
        if original_import_count > 1:
            raise ValueError("naming target has multiple original-import aliases")
        if original_import_count and not self.is_external:
            raise ValueError("internal naming target cannot have an original-import alias")
        if self.is_external and self.is_thunk:
            raise ValueError("external naming target cannot be a thunk")
        _require_digest(self.target_digest, "naming target digest")
        if self.target_digest != naming_target_digest(
            self.target_ordinal,
            self.coordinate,
            self.is_external,
            self.is_thunk,
            self.aliases,
        ):
            raise ValueError("naming target digest does not match its fields")

    @property
    def canonical_body(self) -> bytes:
        return (
            _u64(self.target_ordinal)
            + _coordinate(self.coordinate)
            + _bool(self.is_external)
            + _bool(self.is_thunk)
            + _seq(tuple(alias.canonical_bytes() for alias in self.aliases))
        )

    @property
    def is_named(self) -> bool:
        return any(alias.policy_admissible for alias in self.aliases)


@dataclass(frozen=True, slots=True)
class CapturedNamingResolution:
    state: NamingResolutionState
    reason: NamingUnresolvedReason | None = None
    terminal_target_ordinal: int | None = None
    cycle_target_ordinal: int | None = None

    def __post_init__(self) -> None:
        _require_exact(self.state, NamingResolutionState, "naming resolution state")
        if self.state is NamingResolutionState.INDIRECT:
            if any(
                value is not None
                for value in (
                    self.reason,
                    self.terminal_target_ordinal,
                    self.cycle_target_ordinal,
                )
            ):
                raise ValueError("indirect resolution cannot carry detail")
            return
        if self.state is NamingResolutionState.UNRESOLVED:
            _require_exact(self.reason, NamingUnresolvedReason, "unresolved reason")
            if self.terminal_target_ordinal is not None:
                raise ValueError("unresolved resolution cannot cite a terminal target")
            if self.reason is NamingUnresolvedReason.THUNK_CYCLE:
                _require_u64(self.cycle_target_ordinal, "cycle target ordinal")
            elif self.cycle_target_ordinal is not None:
                raise ValueError("only a thunk cycle can cite a cycle target")
            return
        if self.reason is not None or self.cycle_target_ordinal is not None:
            raise ValueError("resolved naming cannot carry unresolved detail")
        _require_u64(self.terminal_target_ordinal, "terminal target ordinal")

    def canonical_bytes(self) -> bytes:
        if self.state is NamingResolutionState.INDIRECT:
            return b"\x00"
        if self.state is NamingResolutionState.UNRESOLVED:
            assert self.reason is not None
            optional = (
                b"\x00"
                if self.cycle_target_ordinal is None
                else b"\x01" + _u64(self.cycle_target_ordinal)
            )
            return b"\x01" + _text(self.reason.value) + optional
        assert self.terminal_target_ordinal is not None
        tag = b"\x02" if self.state is NamingResolutionState.RESOLVED_NAMED else b"\x03"
        return tag + _u64(self.terminal_target_ordinal)


@dataclass(frozen=True, slots=True)
class CapturedNamingRow:
    instruction: AddressCoordinate
    operation_ordinal: int
    opcode: NamingOpcode
    selector: ValidatedVarnode | None
    resolution: CapturedNamingResolution
    targets: tuple[CapturedNamingTarget, ...]
    row_digest: bytes

    def __post_init__(self) -> None:
        _require_exact(self.instruction, AddressCoordinate, "naming instruction")
        _require_u64(self.operation_ordinal, "naming operation ordinal")
        _require_exact(self.opcode, NamingOpcode, "naming opcode")
        if self.selector is not None:
            _require_exact(self.selector, ValidatedVarnode, "naming selector")
        _require_exact(self.resolution, CapturedNamingResolution, "naming resolution")
        _require_exact_tuple(self.targets, CapturedNamingTarget, "naming targets")
        if len(self.targets) > MAX_NAMING_TARGETS:
            raise ValueError("naming targets exceed their bound")
        ordinals = tuple(target.target_ordinal for target in self.targets)
        if len(set(ordinals)) != len(ordinals):
            raise ValueError("naming target ordinals must be unique")
        coordinates = tuple(target.coordinate for target in self.targets)
        if len(set(coordinates)) != len(coordinates):
            raise ValueError("naming target coordinates must be unique")
        if ordinals != tuple(range(len(self.targets))):
            raise ValueError("naming target ordinals must be contiguous and ordered")
        self._validate_resolution_shape()
        _require_digest(self.row_digest, "naming row digest")
        if self.row_digest != naming_row_digest(
            self.instruction,
            self.operation_ordinal,
            self.opcode,
            self.selector,
            self.resolution,
            self.targets,
        ):
            raise ValueError("naming row digest does not match its fields")

    @property
    def canonical_body(self) -> bytes:
        return (
            _coordinate(self.instruction)
            + _u64(self.operation_ordinal)
            + _text(self.opcode.value)
            + _selector(self.selector)
            + self.resolution.canonical_bytes()
            + _seq(
                tuple(
                    target.canonical_body + _bytes(target.target_digest)
                    for target in self.targets
                )
            )
        )

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (
            self.instruction.space_id,
            self.instruction.byte_offset,
            self.operation_ordinal,
        )

    def _validate_resolution_shape(self) -> None:
        state = self.resolution.state
        reason = self.resolution.reason
        if self.opcode is NamingOpcode.CALLIND:
            if state is not NamingResolutionState.INDIRECT or self.targets:
                raise ValueError("CALLIND requires target-free INDIRECT naming")
            return
        if state is NamingResolutionState.INDIRECT:
            raise ValueError("CALL cannot use INDIRECT naming")
        expected_pre_reason = None
        if self.selector is None:
            expected_pre_reason = NamingUnresolvedReason.MISSING_SELECTOR
        elif self.selector.kind is VarnodeKindCode.OPAQUE:
            expected_pre_reason = NamingUnresolvedReason.OPAQUE_SELECTOR
        elif self.selector.kind is not VarnodeKindCode.ADDRESS:
            expected_pre_reason = NamingUnresolvedReason.NON_ADDRESS_SELECTOR
        if expected_pre_reason is not None:
            if (
                state is not NamingResolutionState.UNRESOLVED
                or reason is not expected_pre_reason
                or self.targets
            ):
                raise ValueError("direct selector shape and naming resolution disagree")
            return
        assert self.selector is not None
        if self.targets and self.targets[0].coordinate != self.selector.coordinate:
            raise ValueError("first naming target must equal the direct selector")
        if state is NamingResolutionState.UNRESOLVED:
            if reason is NamingUnresolvedReason.NO_EXACT_FUNCTION:
                if self.targets:
                    raise ValueError("missing exact function cannot retain targets")
                return
            if reason is NamingUnresolvedReason.THUNK_TARGET_MISSING:
                if (
                    not self.targets
                    or len(self.targets) == MAX_NAMING_TARGETS
                    or any(not target.is_thunk for target in self.targets)
                ):
                    raise ValueError("missing thunk target requires a retained thunk prefix")
                return
            if reason is NamingUnresolvedReason.THUNK_CYCLE:
                cycle = self.resolution.cycle_target_ordinal
                if (
                    not self.targets
                    or len(self.targets) == MAX_NAMING_TARGETS
                    or any(not target.is_thunk for target in self.targets)
                    or cycle is None
                    or cycle >= len(self.targets)
                ):
                    raise ValueError("thunk cycle detail does not match its target prefix")
                return
            if reason is NamingUnresolvedReason.THUNK_DEPTH_EXCEEDED:
                if len(self.targets) != MAX_NAMING_TARGETS or any(
                    not target.is_thunk for target in self.targets
                ):
                    raise ValueError("thunk depth exhaustion requires the complete bounded prefix")
                return
            raise ValueError("address selector has an invalid unresolved reason")
        if not self.targets or self.targets[-1].is_thunk:
            raise ValueError("resolved naming requires a terminal non-thunk target")
        if any(not target.is_thunk for target in self.targets[:-1]):
            raise ValueError("resolved naming has a non-thunk intermediate target")
        if self.resolution.terminal_target_ordinal != len(self.targets) - 1:
            raise ValueError("resolved naming must cite the last target")
        expected_named = self.targets[-1].is_named
        if expected_named != (state is NamingResolutionState.RESOLVED_NAMED):
            raise ValueError("resolved naming state disagrees with terminal aliases")


@dataclass(frozen=True, slots=True)
class CapturedNamingSidecar:
    exporter_source_sha256: bytes
    rows: tuple[CapturedNamingRow, ...]
    semantic_content_digest: bytes

    def __post_init__(self) -> None:
        _require_digest(self.exporter_source_sha256, "naming exporter source SHA-256")
        _require_exact_tuple(self.rows, CapturedNamingRow, "naming rows")
        if len(self.rows) > MAX_NAMING_ROWS:
            raise ValueError("naming rows exceed their bound")
        if len({row.canonical_key for row in self.rows}) != len(self.rows):
            raise ValueError("naming row identities must be unique")
        if tuple(sorted(self.rows, key=lambda item: item.canonical_key)) != self.rows:
            raise ValueError("naming rows must be canonical and ordered")
        alias_bytes = sum(
            len(alias.value.encode("utf-8", errors="strict"))
            for row in self.rows
            for target in row.targets
            for alias in target.aliases
        )
        if alias_bytes > MAX_NAMING_AGGREGATE_ALIAS_BYTES:
            raise ValueError("aggregate naming alias bytes exceed their bound")
        _require_digest(self.semantic_content_digest, "naming content digest")
        if self.semantic_content_digest != naming_content_digest(
            self.exporter_source_sha256,
            self.rows,
        ):
            raise ValueError("naming content digest does not match its rows")


def naming_target_digest(
    target_ordinal: int,
    coordinate: AddressCoordinate,
    is_external: bool,
    is_thunk: bool,
    aliases: tuple[CapturedNamingAlias, ...],
) -> bytes:
    body = _target_body(target_ordinal, coordinate, is_external, is_thunk, aliases)
    return _digest(_text(_TARGET_DOMAIN) + body)


def naming_row_digest(
    instruction: AddressCoordinate,
    operation_ordinal: int,
    opcode: NamingOpcode,
    selector: ValidatedVarnode | None,
    resolution: CapturedNamingResolution,
    targets: tuple[CapturedNamingTarget, ...],
) -> bytes:
    body = _row_body(
        instruction,
        operation_ordinal,
        opcode,
        selector,
        resolution,
        targets,
    )
    return _digest(_text(_ROW_DOMAIN) + body)


def _target_body(
    target_ordinal: int,
    coordinate: AddressCoordinate,
    is_external: bool,
    is_thunk: bool,
    aliases: tuple[CapturedNamingAlias, ...],
) -> bytes:
    _require_u64(target_ordinal, "naming target ordinal")
    _require_exact(coordinate, AddressCoordinate, "naming target coordinate")
    _require_bool(is_external, "external target flag")
    _require_bool(is_thunk, "thunk target flag")
    _require_exact_tuple(aliases, CapturedNamingAlias, "naming target aliases")
    return (
        _u64(target_ordinal)
        + _coordinate(coordinate)
        + _bool(is_external)
        + _bool(is_thunk)
        + _seq(tuple(alias.canonical_bytes() for alias in aliases))
    )


def _row_body(
    instruction: AddressCoordinate,
    operation_ordinal: int,
    opcode: NamingOpcode,
    selector: ValidatedVarnode | None,
    resolution: CapturedNamingResolution,
    targets: tuple[CapturedNamingTarget, ...],
) -> bytes:
    _require_exact(instruction, AddressCoordinate, "naming instruction")
    _require_u64(operation_ordinal, "naming operation ordinal")
    _require_exact(opcode, NamingOpcode, "naming opcode")
    if selector is not None:
        _require_exact(selector, ValidatedVarnode, "naming selector")
    _require_exact(resolution, CapturedNamingResolution, "naming resolution")
    _require_exact_tuple(targets, CapturedNamingTarget, "naming targets")
    return (
        _coordinate(instruction)
        + _u64(operation_ordinal)
        + _text(opcode.value)
        + _selector(selector)
        + resolution.canonical_bytes()
        + _seq(
            tuple(
                target.canonical_body + _bytes(target.target_digest)
                for target in targets
            )
        )
    )


def naming_content_digest(
    exporter_source_sha256: bytes,
    rows: tuple[CapturedNamingRow, ...],
) -> bytes:
    _require_digest(exporter_source_sha256, "naming exporter source SHA-256")
    _require_exact_tuple(rows, CapturedNamingRow, "naming rows")
    if len(rows) > MAX_NAMING_ROWS:
        raise ValueError("naming rows exceed their bound")
    digest = sha256()
    digest.update(_text(_CONTENT_DOMAIN))
    digest.update(_u64(CALL_NAMING_SCHEMA_VERSION))
    digest.update(_u64(CALL_NAMING_EXPORTER_REVISION))
    digest.update(_bytes(exporter_source_sha256))
    digest.update(_text(CALL_NAMING_GHIDRA_VERSION))
    digest.update(_text(CALL_NAMING_INVENTORY_COMPLETENESS))
    digest.update(_u64(len(rows)))
    for row in rows:
        digest.update(row.canonical_body)
        digest.update(_bytes(row.row_digest))
    return digest.digest()


def boundary_naming_target_digest(target: CapturedNamingTarget) -> bytes:
    _require_exact(target, CapturedNamingTarget, "boundary naming target")
    if target.is_thunk or not target.is_named:
        raise ValueError("boundary naming target must be a named terminal target")
    aliases = tuple(alias for alias in target.aliases if alias.policy_admissible)
    return _digest(
        _text(_BOUNDARY_TARGET_DOMAIN)
        + _coordinate(target.coordinate)
        + _text("external" if target.is_external else "internal")
        + _seq(tuple(_boundary_alias_bytes(alias) for alias in aliases))
    )


def _boundary_alias_bytes(alias: CapturedNamingAlias) -> bytes:
    _require_exact(alias, CapturedNamingAlias, "boundary naming alias")
    if not alias.policy_admissible:
        raise ValueError("default alias is not boundary-admissible")
    if alias.kind is NamingAliasKind.SYMBOL:
        assert alias.source_quality is not None
        kind = "ghidra_symbol:" + alias.source_quality.value
    else:
        kind = "original_import"
    return _text(kind) + _text(alias.value)


def _selector(selector: ValidatedVarnode | None) -> bytes:
    if selector is None:
        return b"\x00"
    _require_exact(selector, ValidatedVarnode, "naming selector")
    return (
        b"\x01"
        + _u64(int(selector.kind))
        + _coordinate(selector.coordinate)
        + _u64(selector.byte_size)
    )


def _coordinate(value: AddressCoordinate) -> bytes:
    _require_exact(value, AddressCoordinate, "encoded coordinate")
    return _u64(value.space_id) + _u64(value.byte_offset)


def _seq(values: tuple[bytes, ...]) -> bytes:
    if type(values) is not tuple or any(type(value) is not bytes for value in values):
        raise TypeError("encoded sequence must be an exact tuple of bytes")
    return _u64(len(values)) + b"".join(values)


def _digest(value: bytes) -> bytes:
    return sha256(value).digest()


def _u64(value: int | None) -> bytes:
    _require_u64(value, "encoded integer")
    assert value is not None
    return value.to_bytes(8, byteorder="big", signed=False)


def _bool(value: bool) -> bytes:
    _require_bool(value, "encoded boolean")
    return b"\x01" if value else b"\x00"


def _bytes(value: bytes) -> bytes:
    if type(value) is not bytes:
        raise TypeError("encoded byte string must be exact bytes")
    return _u64(len(value)) + value


def _text(value: str) -> bytes:
    _require_text(value, "encoded text")
    return _bytes(value.encode("utf-8", errors="strict"))


def _require_alias_text(value: object) -> None:
    _require_text(value, "naming alias")
    assert type(value) is str
    if len(value.encode("utf-8", errors="strict")) > MAX_NAMING_ALIAS_BYTES:
        raise ValueError("naming alias exceeds its byte bound")


def _require_text(value: object, label: str) -> None:
    if type(value) is not str:
        raise TypeError(f"{label} must be exact str")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} must be strict UTF-8") from exc
    if not encoded:
        raise ValueError(f"{label} must not be empty")


def _require_exact_text(value: object, expected: str, label: str) -> None:
    _require_text(value, label)
    if value != expected:
        raise ValueError(f"{label} changed")


def _require_digest(value: object, label: str) -> None:
    if type(value) is not bytes or len(value) != 32:
        raise TypeError(f"{label} must be exact 32-byte bytes")


def _require_u64(value: int | None, label: str) -> None:
    if type(value) is not int or not 0 <= value < _U64_LIMIT:
        raise TypeError(f"{label} must be an unsigned 64-bit integer")


def _require_bool(value: object, label: str) -> None:
    if type(value) is not bool:
        raise TypeError(f"{label} must be exact bool")


def _require_exact(value: object, cls: type, label: str) -> None:
    if type(value) is not cls:
        raise TypeError(f"{label} must be exact {cls.__name__}")


def _require_exact_tuple(value: object, cls: type, label: str) -> None:
    if type(value) is not tuple or any(type(item) is not cls for item in value):
        raise TypeError(f"{label} must be an exact tuple of {cls.__name__}")
