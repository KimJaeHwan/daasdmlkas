"""Mechanical decoder for one configured call-naming sidecar."""

from __future__ import annotations

from dataclasses import dataclass

from ._scope_raw import RawObject
from .call_contracts import FunctionCallSeedUnit
from .configured_naming_contracts import (
    CALL_NAMING_EXPORTER_REVISION, CALL_NAMING_GHIDRA_VERSION,
    CALL_NAMING_INVENTORY_COMPLETENESS, CALL_NAMING_SCHEMA_ID,
    CALL_NAMING_SCHEMA_VERSION, MAX_NAMING_AGGREGATE_ALIAS_BYTES,
    MAX_NAMING_ALIASES_PER_TARGET, MAX_NAMING_ALIAS_BYTES, MAX_NAMING_ROWS,
    MAX_NAMING_TARGETS, AddressCoordinate, CapturedNamingAlias,
    CapturedNamingResolution, CapturedNamingRow, CapturedNamingSidecar,
    CapturedNamingTarget, NamingAliasKind, NamingBindingExpectation,
    NamingOpcode, NamingResolutionState, NamingSourceQuality,
    NamingTransportExpectation, NamingUnresolvedReason, ValidatedVarnode,
    VarnodeKindCode, naming_content_digest, naming_row_digest,
    naming_target_digest,
)


_ROOT_KEYS = (
    "schema_id", "schema_version", "exporter_revision", "exporter_source_sha256",
    "ghidra_version", "transport", "inventory_completeness", "calls",
    "semantic_content_digest",
)
_TRANSPORT_KEYS = (
    "generation_id", "manifest_schema_id", "seal_schema_id",
    "observation_member_id", "observation_member_sha256", "function_entry",
)
_COORDINATE_KEYS = ("space_id", "byte_offset")
_ROW_KEYS = (
    "instruction", "operation_ordinal", "opcode", "selector", "resolution",
    "targets", "row_digest",
)
_TARGET_KEYS = (
    "target_ordinal", "coordinate", "is_external", "is_thunk", "aliases",
    "target_digest",
)
_U64_LIMIT = 1 << 64
_HEX_DIGITS = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class _CoordinateStage:
    space_id: int; byte_offset: int

@dataclass(frozen=True, slots=True)
class _SelectorStage:
    kind: VarnodeKindCode; coordinate: _CoordinateStage; byte_size: int

@dataclass(frozen=True, slots=True)
class _AliasStage:
    kind: NamingAliasKind; source_quality: NamingSourceQuality | None; value: str

@dataclass(frozen=True, slots=True)
class _TargetStage:
    target_ordinal: int; coordinate: _CoordinateStage
    is_external: bool; is_thunk: bool
    aliases: tuple[_AliasStage, ...]; supplied_digest: bytes

@dataclass(frozen=True, slots=True)
class _ResolutionStage:
    state: NamingResolutionState; reason: NamingUnresolvedReason | None = None
    terminal_target_ordinal: int | None = None; cycle_target_ordinal: int | None = None

@dataclass(frozen=True, slots=True)
class _RowStage:
    instruction: _CoordinateStage; operation_ordinal: int; opcode: NamingOpcode
    selector: _SelectorStage | None; resolution: _ResolutionStage
    targets: tuple[_TargetStage, ...]; supplied_digest: bytes


def decode_configured_naming(
    raw: RawObject,
    transport: NamingTransportExpectation,
    binding: NamingBindingExpectation,
    seeds: FunctionCallSeedUnit,
    /,
) -> CapturedNamingSidecar:
    _require_exact(raw, RawObject, "configured naming object")
    _require_exact(transport, NamingTransportExpectation, "naming transport")
    _require_exact(binding, NamingBindingExpectation, "naming binding")
    _require_exact(seeds, FunctionCallSeedUnit, "call seeds")
    _preflight_duplicates(raw)

    _exact_text(
        _unique_member(raw, "schema_id", "naming root"),
        CALL_NAMING_SCHEMA_ID,
        "naming schema ID",
    )
    _exact_u64(
        _unique_member(raw, "schema_version", "naming root"),
        CALL_NAMING_SCHEMA_VERSION,
        "naming schema version",
    )
    _exact_u64(
        _unique_member(raw, "exporter_revision", "naming root"),
        CALL_NAMING_EXPORTER_REVISION,
        "naming exporter revision",
    )
    root = _exact_object(raw, _ROOT_KEYS, "naming root")

    exporter_digest = _digest(root["exporter_source_sha256"], "exporter source SHA-256")
    if exporter_digest != binding.exporter_source_sha256:
        raise ValueError("naming exporter source SHA-256 does not match runner binding")
    _exact_text(root["ghidra_version"], CALL_NAMING_GHIDRA_VERSION, "naming Ghidra version")
    if root["ghidra_version"] != binding.ghidra_version:
        raise ValueError("naming Ghidra version does not match runner binding")
    _exact_text(
        root["inventory_completeness"],
        CALL_NAMING_INVENTORY_COMPLETENESS,
        "naming inventory completeness",
    )
    supplied_content_digest = _digest(
        root["semantic_content_digest"], "naming content digest"
    )

    _decode_transport(root["transport"], transport)
    if transport.function_entry != seeds.function_entry:
        raise ValueError("naming transport function entry does not match call seeds")
    raw_rows = _array(root["calls"], "naming calls")
    if len(raw_rows) > MAX_NAMING_ROWS:
        raise ValueError("naming rows exceed their bound")

    staged_rows: list[_RowStage | None] = [None] * len(raw_rows)
    aggregate_alias_bytes = 0
    for index, raw_row in enumerate(raw_rows):
        staged_row, aggregate_alias_bytes = _stage_row(
            raw_row,
            index,
            aggregate_alias_bytes,
        )
        staged_rows[len(raw_rows) - index - 1] = staged_row

    _validate_stage_order(staged_rows)
    _validate_stage_coverage(staged_rows, seeds)

    semantic_targets: list[tuple[CapturedNamingTarget, ...] | None] = [None] * len(raw_rows)
    for index, stage in enumerate(reversed(staged_rows)):
        assert stage is not None
        targets = tuple(_construct_target(item) for item in stage.targets)
        semantic_targets[len(raw_rows) - index - 1] = targets
    retained_rows = tuple(_construct_rows(staged_rows, semantic_targets))

    computed_content_digest = naming_content_digest(exporter_digest, retained_rows)
    if computed_content_digest != supplied_content_digest:
        raise ValueError("naming content digest does not match its rows")
    return CapturedNamingSidecar(exporter_digest, retained_rows, computed_content_digest)
def _decode_transport(raw: object, expected: NamingTransportExpectation) -> None:
    values = _exact_object(raw, _TRANSPORT_KEYS, "naming transport")
    generation_id = _digest(values["generation_id"], "naming generation ID")
    if generation_id != expected.generation_id:
        raise ValueError("naming generation ID does not match transport")
    _expected_text(values["manifest_schema_id"], expected.manifest_schema_id, "manifest schema ID")
    _expected_text(values["seal_schema_id"], expected.seal_schema_id, "seal schema ID")
    _expected_text(
        values["observation_member_id"],
        expected.observation_member_id,
        "observation member ID",
    )
    observation_digest = _digest(values["observation_member_sha256"],
                                 "observation member SHA-256")
    if observation_digest != expected.observation_member_sha256:
        raise ValueError("observation member SHA-256 does not match transport")
    function_entry = _coordinate(values["function_entry"], "transport function entry")
    if function_entry != expected.function_entry:
        raise ValueError("function entry does not match transport")
def _stage_row(
    raw: object,
    index: int,
    aggregate_alias_bytes: int,
) -> tuple[_RowStage, int]:
    label = f"naming row {index}"
    values = _exact_object(raw, _ROW_KEYS, label)
    instruction = _stage_coordinate(values["instruction"], f"{label} instruction")
    operation_ordinal = _u64(values["operation_ordinal"],
                             f"{label} operation ordinal")
    opcode = _enum(values["opcode"], NamingOpcode, f"{label} opcode")
    selector = _stage_selector(values["selector"], f"{label} selector")
    resolution = _stage_resolution(values["resolution"], f"{label} resolution")
    raw_targets = _array(values["targets"], f"{label} targets")
    if len(raw_targets) > MAX_NAMING_TARGETS:
        raise ValueError(f"{label} targets exceed their bound")

    targets: list[_TargetStage | None] = [None] * len(raw_targets)
    for target_index, raw_target in enumerate(raw_targets):
        staged_target, aggregate_alias_bytes = _stage_target(
            raw_target,
            target_index,
            aggregate_alias_bytes,
            label,
        )
        targets[len(raw_targets) - target_index - 1] = staged_target
    return (
        _RowStage(
            instruction,
            operation_ordinal,
            opcode,
            selector,
            resolution,
            tuple(_drain(targets)),
            _digest(values["row_digest"], f"{label} digest"),
        ),
        aggregate_alias_bytes,
    )
def _stage_target(
    raw: object,
    index: int,
    aggregate_alias_bytes: int,
    row_label: str,
) -> tuple[_TargetStage, int]:
    label = f"{row_label} target {index}"
    values = _exact_object(raw, _TARGET_KEYS, label)
    target_ordinal = _u64(values["target_ordinal"], f"{label} ordinal")
    coordinate = _stage_coordinate(values["coordinate"], f"{label} coordinate")
    is_external = _boolean(values["is_external"], f"{label} external flag")
    is_thunk = _boolean(values["is_thunk"], f"{label} thunk flag")
    raw_aliases = _array(values["aliases"], f"{label} aliases")
    if len(raw_aliases) > MAX_NAMING_ALIASES_PER_TARGET:
        raise ValueError(f"{label} aliases exceed their bound")
    aliases: list[_AliasStage | None] = [None] * len(raw_aliases)
    for alias_index, raw_alias in enumerate(raw_aliases):
        staged_alias, aggregate_alias_bytes = _stage_alias(
            raw_alias,
            alias_index,
            label,
            aggregate_alias_bytes,
        )
        aliases[len(raw_aliases) - alias_index - 1] = staged_alias
    return (
        _TargetStage(
            target_ordinal,
            coordinate,
            is_external,
            is_thunk,
            tuple(_drain(aliases)),
            _digest(values["target_digest"], f"{label} digest"),
        ),
        aggregate_alias_bytes,
    )
def _stage_alias(
    raw: object,
    index: int,
    target_label: str,
    aggregate_alias_bytes: int,
) -> tuple[_AliasStage, int]:
    label = f"{target_label} alias {index}"
    kind = _enum(_unique_member(raw, "kind", label), NamingAliasKind, f"{label} kind")
    expected_keys = (("kind", "source_quality", "value")
                     if kind is NamingAliasKind.SYMBOL else ("kind", "value"))
    values = _exact_object(raw, expected_keys, label)
    quality = None
    if kind is NamingAliasKind.SYMBOL:
        quality = _enum(
            values["source_quality"],
            NamingSourceQuality,
            f"{label} source quality",
        )
    value, byte_count = _bounded_text(values["value"], MAX_NAMING_ALIAS_BYTES, label)
    if aggregate_alias_bytes + byte_count > MAX_NAMING_AGGREGATE_ALIAS_BYTES:
        raise ValueError("aggregate naming alias bytes exceed their bound")
    return _AliasStage(kind, quality, value), aggregate_alias_bytes + byte_count
def _stage_selector(raw: object, label: str) -> _SelectorStage | None:
    state = _text(_unique_member(raw, "state", label), f"{label} state")
    if state == "MISSING":
        _exact_object(raw, ("state",), label)
        return None
    if state != "PRESENT":
        raise ValueError(f"{label} state is not recognized")
    values = _exact_object(
        raw,
        ("state", "kind_code", "space_id", "byte_offset", "byte_size"),
        label,
    )
    kind_code = _u64(values["kind_code"], f"{label} kind code")
    if kind_code not in (1, 2, 3, 4, 5, 7):
        raise ValueError(f"{label} kind code is not an admitted ADR-0027 value")
    space_id = _u64(values["space_id"], f"{label} space ID")
    byte_offset = _u64(values["byte_offset"], f"{label} byte offset")
    byte_size = _u64(values["byte_size"], f"{label} byte size")
    if byte_size == 0:
        raise ValueError(f"{label} byte size must be positive")
    return _SelectorStage(
        VarnodeKindCode(kind_code),
        _CoordinateStage(space_id, byte_offset),
        byte_size,
    )


def _stage_resolution(raw: object, label: str) -> _ResolutionStage:
    state = _enum(_unique_member(raw, "state", label), NamingResolutionState,
                  f"{label} state")
    if state is NamingResolutionState.INDIRECT:
        _exact_object(raw, ("state",), label)
        return _ResolutionStage(state)
    if state in (
        NamingResolutionState.RESOLVED_NAMED,
        NamingResolutionState.RESOLVED_UNNAMED,
    ):
        values = _exact_object(raw, ("state", "terminal_target_ordinal"), label)
        ordinal = _u64(values["terminal_target_ordinal"],
                       f"{label} terminal target ordinal")
        return _ResolutionStage(state, terminal_target_ordinal=ordinal)

    values = _object_with_required(
        raw,
        ("state", "reason", "cycle_target_ordinal"),
        ("state", "reason"),
        label,
    )
    reason = _enum(values["reason"], NamingUnresolvedReason, f"{label} reason")
    if reason is NamingUnresolvedReason.THUNK_CYCLE:
        values = _exact_object(raw, ("state", "reason", "cycle_target_ordinal"), label)
        ordinal = _u64(values["cycle_target_ordinal"],
                       f"{label} cycle target ordinal")
        return _ResolutionStage(state, reason, cycle_target_ordinal=ordinal)
    _exact_object(raw, ("state", "reason"), label)
    return _ResolutionStage(state, reason)
def _construct_rows(
    stages: list[_RowStage | None],
    target_rows: list[tuple[CapturedNamingTarget, ...] | None],
):
    while stages:
        stage = stages.pop()
        targets = target_rows.pop()
        assert stage is not None
        assert targets is not None
        yield _construct_row(stage, targets)
def _construct_row(
    stage: _RowStage, targets: tuple[CapturedNamingTarget, ...]
) -> CapturedNamingRow:
    instruction = _build_coordinate(stage.instruction)
    selector = _build_selector(stage.selector)
    resolution = _build_resolution(stage.resolution)
    computed_digest = naming_row_digest(
        instruction,
        stage.operation_ordinal,
        stage.opcode,
        selector,
        resolution,
        targets,
    )
    row = CapturedNamingRow(
        instruction,
        stage.operation_ordinal,
        stage.opcode,
        selector,
        resolution,
        targets,
        computed_digest,
    )
    if computed_digest != stage.supplied_digest:
        raise ValueError("naming row digest does not match its fields")
    return row
def _construct_target(stage: _TargetStage) -> CapturedNamingTarget:
    coordinate = _build_coordinate(stage.coordinate)
    aliases = tuple(
        CapturedNamingAlias(item.kind, item.value, item.source_quality)
        for item in stage.aliases
    )
    computed_digest = naming_target_digest(
        stage.target_ordinal,
        coordinate,
        stage.is_external,
        stage.is_thunk,
        aliases,
    )
    target = CapturedNamingTarget(
        stage.target_ordinal,
        coordinate,
        stage.is_external,
        stage.is_thunk,
        aliases,
        computed_digest,
    )
    if computed_digest != stage.supplied_digest:
        raise ValueError("naming target digest does not match its fields")
    return target

def _build_selector(stage: _SelectorStage | None) -> ValidatedVarnode | None:
    if stage is None:
        return None
    return ValidatedVarnode(
        stage.kind,
        _build_coordinate(stage.coordinate),
        stage.byte_size,
    )

def _build_resolution(stage: _ResolutionStage) -> CapturedNamingResolution:
    return CapturedNamingResolution(
        stage.state,
        stage.reason,
        stage.terminal_target_ordinal,
        stage.cycle_target_ordinal,
    )

def _validate_stage_order(stages: list[_RowStage | None]) -> None:
    row_keys: set[tuple[int, int, int]] = set()
    for stage in reversed(stages):
        assert stage is not None
        for target in stage.targets:
            alias_keys: set[tuple[object, ...]] = set()
            for alias in target.aliases:
                key = _alias_key(alias)
                if key in alias_keys:
                    raise ValueError("naming target aliases must be unique")
                alias_keys.add(key)
        ordinals: set[int] = set()
        coordinates: set[_CoordinateStage] = set()
        for target in stage.targets:
            if target.target_ordinal in ordinals:
                raise ValueError("naming target ordinals must be unique")
            if target.coordinate in coordinates:
                raise ValueError("naming target coordinates must be unique")
            ordinals.add(target.target_ordinal)
            coordinates.add(target.coordinate)
        key = _row_key(stage)
        if key in row_keys:
            raise ValueError("naming row identities must be unique")
        row_keys.add(key)
    previous_row = None
    for stage in reversed(stages):
        assert stage is not None
        for target in stage.targets:
            previous_alias = None
            for alias in target.aliases:
                key = _alias_key(alias)
                if previous_alias is not None and previous_alias >= key:
                    raise ValueError("naming target aliases must be canonical and ordered")
                previous_alias = key
        if any(target.target_ordinal != index for index, target in enumerate(stage.targets)):
            raise ValueError("naming target ordinals must be contiguous and ordered")
        key = _row_key(stage)
        if previous_row is not None and previous_row >= key:
            raise ValueError("naming rows must be canonical and ordered")
        previous_row = key

def _validate_stage_coverage(
    stages: list[_RowStage | None], seeds: FunctionCallSeedUnit
) -> None:
    if len(stages) != len(seeds.callsites):
        raise ValueError("naming rows do not exactly cover call occurrences")
    for stage, site in zip(reversed(stages), seeds.callsites, strict=True):
        assert stage is not None
        occurrence = site.occurrence
        if (
            stage.instruction.space_id != occurrence.instruction.space_id
            or stage.instruction.byte_offset != occurrence.instruction.byte_offset
            or stage.operation_ordinal != occurrence.operation_ordinal
            or stage.opcode.value != occurrence.opcode
            or not _selector_matches(stage.selector, occurrence.selector)
        ):
            raise ValueError("naming row does not match its exact call occurrence")

def _selector_matches(stage: _SelectorStage | None, value: object) -> bool:
    if stage is None:
        return value is None
    return (
        type(value) is ValidatedVarnode
        and stage.kind is value.kind
        and stage.coordinate.space_id == value.coordinate.space_id
        and stage.coordinate.byte_offset == value.coordinate.byte_offset
        and stage.byte_size == value.byte_size
    )

def _row_key(stage: _RowStage) -> tuple[int, int, int]:
    return (stage.instruction.space_id, stage.instruction.byte_offset,
            stage.operation_ordinal)

def _alias_key(stage: _AliasStage) -> tuple[object, ...]:
    return (0 if stage.kind is NamingAliasKind.SYMBOL else 1,
            "" if stage.source_quality is None else stage.source_quality.value,
            _strict_utf8(stage.value))

def _coordinate(raw: object, label: str) -> AddressCoordinate:
    return _build_coordinate(_stage_coordinate(raw, label))

def _stage_coordinate(raw: object, label: str) -> _CoordinateStage:
    values = _exact_object(raw, _COORDINATE_KEYS, label)
    return _CoordinateStage(
        _u64(values["space_id"], f"{label} space ID"),
        _u64(values["byte_offset"], f"{label} byte offset"),
    )

def _build_coordinate(stage: _CoordinateStage) -> AddressCoordinate:
    return AddressCoordinate(stage.space_id, stage.byte_offset)

def _drain(values: list):
    while values:
        value = values.pop()
        assert value is not None
        yield value


def _preflight_duplicates(value: object) -> None:
    if type(value) is RawObject:
        seen: set[str] = set()
        for member in value.members:
            if member.name in seen:
                raise ValueError(f"configured naming object has duplicate key {member.name!r}")
            seen.add(member.name)
            _preflight_duplicates(member.value)
    elif type(value) is tuple:
        for item in value:
            _preflight_duplicates(item)


def _exact_object(raw: object, keys: tuple[str, ...], label: str) -> dict[str, object]:
    return _object_with_required(raw, keys, keys, label)


def _object_with_required(
    raw: object,
    allowed_keys: tuple[str, ...],
    required_keys: tuple[str, ...],
    label: str,
) -> dict[str, object]:
    _require_exact(raw, RawObject, label)
    seen = {member.name for member in raw.members}
    allowed = set(allowed_keys)
    unknown = tuple(name for name in seen if name not in allowed)
    if unknown:
        name = min(unknown, key=_strict_utf8)
        raise ValueError(f"{label} has unknown key {name!r}")
    for name in required_keys:
        if name not in seen:
            raise ValueError(f"{label} is missing key {name!r}")
    return {member.name: member.value for member in raw.members}


def _unique_member(raw: object, name: str, label: str) -> object:
    _require_exact(raw, RawObject, label)
    for member in raw.members:
        if member.name == name:
            return member.value
    raise ValueError(f"{label} is missing key {name!r}")


def _strict_utf8(value: str) -> bytes:
    try:
        return value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("configured naming text must be strict UTF-8") from exc


def _array(value: object, label: str) -> tuple[object, ...]:
    if type(value) is not tuple:
        raise TypeError(f"{label} must be an exact tuple")
    return value


def _u64(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value < _U64_LIMIT:
        raise TypeError(f"{label} must be an unsigned 64-bit integer")
    return value


def _exact_u64(value: object, expected: int, label: str) -> None:
    decoded = _u64(value, label)
    if decoded != expected:
        raise ValueError(f"{label} changed")


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{label} must be exact bool")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{label} must be exact str")
    encoded = _strict_utf8(value)
    if not encoded:
        raise ValueError(f"{label} must not be empty")
    return value


def _bounded_text(value: object, maximum: int, label: str) -> tuple[str, int]:
    decoded = _text(value, label)
    byte_count = len(_strict_utf8(decoded))
    if byte_count > maximum:
        raise ValueError(f"{label} exceeds its byte bound")
    return decoded, byte_count


def _exact_text(value: object, expected: str, label: str) -> None:
    decoded = _text(value, label)
    if decoded != expected:
        raise ValueError(f"{label} changed")


def _expected_text(value: object, expected: str, label: str) -> None:
    decoded = _text(value, label)
    if decoded != expected:
        raise ValueError(f"{label} does not match transport")


def _digest(value: object, label: str) -> bytes:
    if type(value) is not str:
        raise TypeError(f"{label} must be exact lowercase hexadecimal text")
    if len(value) != 64 or any(character not in _HEX_DIGITS for character in value):
        raise ValueError(f"{label} must be exact lowercase 32-byte hexadecimal")
    return bytes.fromhex(value)


def _enum(value: object, enum_type: type, label: str):
    decoded = _text(value, label)
    try:
        return enum_type(decoded)
    except ValueError as exc:
        raise ValueError(f"{label} is not recognized") from exc


def _require_exact(value: object, cls: type, label: str) -> None:
    if type(value) is not cls:
        raise TypeError(f"{label} must be exact {cls.__name__}")
