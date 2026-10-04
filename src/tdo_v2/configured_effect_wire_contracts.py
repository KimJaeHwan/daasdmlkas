"""Architect-owned neutral wire contracts for configured call effects."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import TypeAlias

from ._scope_contracts import AddressCoordinate, VarnodeKindCode
from .configured_profile_contracts import (
    CONFIGURED_BUNDLE_MANIFEST_SCHEMA_ID,
    CONFIGURED_BUNDLE_SEAL_SCHEMA_ID,
)


CALL_EFFECT_SCHEMA_ID = "tdo-v2-call-effect-sidecar-v1"
CALL_EFFECT_SCHEMA_VERSION = 1
CALL_EFFECT_EXPORTER_REVISION = 1
CALL_EFFECT_GHIDRA_VERSION = "12.0.4"
CALL_EFFECT_EXPORTER_SOURCE_SET_DOMAIN = (
    "tdo-v2-call-effect-exporter-source-set-v1"
)

MAX_EFFECT_MEMBER_BYTES = 64 * 1024 * 1024
MAX_EFFECT_ROWS = 16_384
MAX_EFFECT_FIXED_FORMALS = 1_024
MAX_EFFECT_RETURNED_PARAMETERS = MAX_EFFECT_FIXED_FORMALS + 2
MAX_EFFECT_OVERRIDE_FIXED_SHAPES = 1_024
MAX_EFFECT_CUSTOM_PARAMETERS = 1_024
MAX_EFFECT_SLOTS_PER_DIRECTION = 1_024
MAX_EFFECT_PIECES_PER_ASSIGNMENT = 64
MAX_EFFECT_CAPTURED_PIECES_PER_CALL = 8_192
MAX_EFFECT_OVERRIDE_NAMESPACE_SYMBOLS = 4_096
MAX_EFFECT_SELECTED_OVERRIDES = 64
CALL_EFFECT_CAPTURE_DEADLINE_SECONDS = 60
EFFECT_RUNTIME_CLASS_IDS = (
    "GhidraV2BundleExport",
    "GhidraV2CallEffect",
    "GhidraV2CallInterfaceProfile",
    "GhidraV2CallNaming",
)

_ROW_DOMAIN = "tdo-v2-call-effect-row-v1"
_CONTENT_DOMAIN = "tdo-v2-call-effect-content-v1"
_U64_LIMIT = 1 << 64


class EffectOpcode(StrEnum):
    CALL = "CALL"
    CALLIND = "CALLIND"


class EffectSourceQuality(StrEnum):
    DEFAULT = "DEFAULT"
    ANALYSIS = "ANALYSIS"
    AI = "AI"
    IMPORTED = "IMPORTED"
    USER_DEFINED = "USER_DEFINED"


class OverrideEvidenceState(StrEnum):
    NO_NAMESPACE = "NO_NAMESPACE"
    SCANNED = "SCANNED"


class OverrideDecodeState(StrEnum):
    UNDECODABLE = "UNDECODABLE"
    DECODED = "DECODED"


class InterfaceState(StrEnum):
    NO_INTERFACE_SUBJECT = "NO_INTERFACE_SUBJECT"
    UNASSIGNABLE_INTERFACE = "UNASSIGNABLE_INTERFACE"
    ASSIGNMENT_CAPTURED = "ASSIGNMENT_CAPTURED"


class NoInterfaceReason(StrEnum):
    INDIRECT_CALL = "INDIRECT_CALL"
    MISSING_SELECTOR = "MISSING_SELECTOR"
    OPAQUE_SELECTOR = "OPAQUE_SELECTOR"
    NON_ADDRESS_SELECTOR = "NON_ADDRESS_SELECTOR"
    NO_EXACT_FUNCTION = "NO_EXACT_FUNCTION"


class UnassignableReason(StrEnum):
    OVERRIDE_PRESENT = "OVERRIDE_PRESENT"
    THUNK_INTERFACE_DELEGATED = "THUNK_INTERFACE_DELEGATED"
    CUSTOM_STORAGE_PRESENT = "CUSTOM_STORAGE_PRESENT"
    UNKNOWN_CONVENTION = "UNKNOWN_CONVENTION"
    MODEL_ABSENT = "MODEL_ABSENT"
    MODEL_NOT_PERMITTED = "MODEL_NOT_PERMITTED"
    MODEL_REFERENCE_AMBIGUOUS = "MODEL_REFERENCE_AMBIGUOUS"
    MODEL_ERROR_PLACEHOLDER = "MODEL_ERROR_PLACEHOLDER"
    INVALID_ALLOCATION_SHAPE = "INVALID_ALLOCATION_SHAPE"
    FORMAL_CORRELATION_FAILED = "FORMAL_CORRELATION_FAILED"
    THIS_CORRELATION_FAILED = "THIS_CORRELATION_FAILED"
    UNEXPECTED_AUTO_PARAMETER = "UNEXPECTED_AUTO_PARAMETER"
    ASSIGNMENT_FAILED = "ASSIGNMENT_FAILED"


class ModelSelectionState(StrEnum):
    PROGRAM_DEFAULT = "PROGRAM_DEFAULT"
    EXPLICIT_REFERENCE = "EXPLICIT_REFERENCE"


class VarargBoundaryState(StrEnum):
    NOT_VARARGS = "NOT_VARARGS"
    PRESENT = "PRESENT"


class EffectDirectionTag(StrEnum):
    PRE_READ = "PRE_READ"
    POST_WRITE = "POST_WRITE"


class CorrelationRole(StrEnum):
    FIXED = "FIXED"
    THIS = "THIS"
    HIDDEN_RETURN_POINTER = "HIDDEN_RETURN_POINTER"
    RESULT = "RESULT"


class AssignmentState(StrEnum):
    VOID = "VOID"
    UNASSIGNED = "UNASSIGNED"
    BAD = "BAD"
    ASSIGNED = "ASSIGNED"


class PieceOrigin(StrEnum):
    DIRECT_STORAGE = "DIRECT_STORAGE"
    JOIN_COMPONENT = "JOIN_COMPONENT"
    SYNTHETIC_JOIN = "SYNTHETIC_JOIN"


class EffectStorageClass(StrEnum):
    CONSTANT = "CONSTANT"
    REGISTER = "REGISTER"
    UNIQUE = "UNIQUE"
    ADDRESS = "ADDRESS"
    STACK = "STACK"
    HASH = "HASH"
    JOIN = "JOIN"
    OTHER = "OTHER"


@dataclass(frozen=True, slots=True)
class CapturedEffectSelector:
    kind: VarnodeKindCode
    coordinate: AddressCoordinate
    byte_size: int

    def __post_init__(self) -> None:
        _require_exact(self.kind, VarnodeKindCode, "effect selector kind")
        _require_exact(self.coordinate, AddressCoordinate, "effect selector coordinate")
        _require_u64(self.byte_size, "effect selector byte size")
        if self.byte_size == 0:
            raise ValueError("effect selector byte size must be positive")


@dataclass(frozen=True, slots=True)
class RuntimeClassEvidence:
    class_id: str
    class_sha256: bytes

    def __post_init__(self) -> None:
        _require_text(self.class_id, "runtime class ID")
        _require_digest(self.class_sha256, "runtime class SHA-256")


@dataclass(frozen=True, slots=True)
class EffectTransportExpectation:
    generation_id: bytes
    manifest_schema_id: str
    seal_schema_id: str
    observation_member_id: str
    observation_member_sha256: bytes
    profile_member_id: str
    profile_member_sha256: bytes
    function_entry: AddressCoordinate
    runtime_classes: tuple[RuntimeClassEvidence, ...]

    def __post_init__(self) -> None:
        _require_digest(self.generation_id, "effect generation ID")
        _require_exact_text(
            self.manifest_schema_id,
            CONFIGURED_BUNDLE_MANIFEST_SCHEMA_ID,
            "effect manifest schema ID",
        )
        _require_exact_text(
            self.seal_schema_id,
            CONFIGURED_BUNDLE_SEAL_SCHEMA_ID,
            "effect seal schema ID",
        )
        _require_text(self.observation_member_id, "effect observation member ID")
        _require_digest(self.observation_member_sha256, "observation member SHA-256")
        _require_text(self.profile_member_id, "effect profile member ID")
        _require_digest(self.profile_member_sha256, "profile member SHA-256")
        _require_exact(self.function_entry, AddressCoordinate, "effect function entry")
        _require_exact_tuple(
            self.runtime_classes,
            RuntimeClassEvidence,
            "effect runtime classes",
        )
        if tuple(row.class_id for row in self.runtime_classes) != EFFECT_RUNTIME_CLASS_IDS:
            raise ValueError("effect runtime classes must be the exact fixed tuple")


@dataclass(frozen=True, slots=True)
class EffectBindingExpectation:
    exporter_source_sha256: bytes
    ghidra_version: str

    def __post_init__(self) -> None:
        _require_digest(self.exporter_source_sha256, "effect exporter source SHA-256")
        _require_exact_text(
            self.ghidra_version,
            CALL_EFFECT_GHIDRA_VERSION,
            "effect Ghidra version",
        )


@dataclass(frozen=True, slots=True)
class AllocationShape:
    metatype_code: int
    byte_size: int

    def __post_init__(self) -> None:
        _require_u64(self.metatype_code, "allocation metatype code")
        _require_u64(self.byte_size, "allocation byte size")
        if self.metatype_code not in (2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 14):
            raise ValueError("unsupported allocation metatype code")
        if (self.metatype_code == 14) != (self.byte_size == 0):
            raise ValueError("only VOID allocation shape has zero size")

    def canonical_bytes(self) -> bytes:
        return _u64(self.metatype_code) + _u64(self.byte_size)


@dataclass(frozen=True, slots=True)
class OverrideShape:
    has_varargs: bool
    fixed_allocation_shapes: tuple[AllocationShape, ...]
    result_is_void: bool
    result_allocation_shape: AllocationShape

    def __post_init__(self) -> None:
        _require_bool(self.has_varargs, "override varargs flag")
        _require_exact_tuple(
            self.fixed_allocation_shapes,
            AllocationShape,
            "override fixed shapes",
        )
        if len(self.fixed_allocation_shapes) > MAX_EFFECT_OVERRIDE_FIXED_SHAPES:
            raise ValueError("override fixed shapes exceed their bound")
        _require_bool(self.result_is_void, "override result void flag")
        _require_exact(
            self.result_allocation_shape,
            AllocationShape,
            "override result allocation shape",
        )
        if self.result_is_void != (self.result_allocation_shape.metatype_code == 14):
            raise ValueError("override result void facts disagree")

    def canonical_bytes(self) -> bytes:
        return (
            _bool(self.has_varargs)
            + _seq(tuple(item.canonical_bytes() for item in self.fixed_allocation_shapes))
            + _bool(self.result_is_void)
            + self.result_allocation_shape.canonical_bytes()
        )


@dataclass(frozen=True, slots=True)
class CapturedOverride:
    symbol_id: int
    source_quality: EffectSourceQuality
    decode_state: OverrideDecodeState
    shape: OverrideShape | None = None

    def __post_init__(self) -> None:
        _require_u64(self.symbol_id, "override symbol ID")
        _require_exact(self.source_quality, EffectSourceQuality, "override source quality")
        _require_exact(self.decode_state, OverrideDecodeState, "override decode state")
        if self.decode_state is OverrideDecodeState.DECODED:
            _require_exact(self.shape, OverrideShape, "decoded override shape")
        elif self.shape is not None:
            raise ValueError("undecodable override cannot have a shape")

    def canonical_bytes(self) -> bytes:
        body = _u64(self.symbol_id) + _text(self.source_quality.value)
        if self.decode_state is OverrideDecodeState.UNDECODABLE:
            return body + _text(self.decode_state.value)
        assert self.shape is not None
        return body + _text(self.decode_state.value) + self.shape.canonical_bytes()


@dataclass(frozen=True, slots=True)
class CapturedOverrideEvidence:
    state: OverrideEvidenceState
    scanned_symbol_count: int | None = None
    selected: tuple[CapturedOverride, ...] = ()

    def __post_init__(self) -> None:
        _require_exact(self.state, OverrideEvidenceState, "override evidence state")
        _require_exact_tuple(self.selected, CapturedOverride, "selected overrides")
        if self.state is OverrideEvidenceState.NO_NAMESPACE:
            if self.scanned_symbol_count is not None or self.selected:
                raise ValueError("absent override namespace cannot carry scan evidence")
            return
        _require_u64(self.scanned_symbol_count, "scanned override symbol count")
        assert self.scanned_symbol_count is not None
        if self.scanned_symbol_count > MAX_EFFECT_OVERRIDE_NAMESPACE_SYMBOLS:
            raise ValueError("scanned override symbols exceed their bound")
        if len(self.selected) > MAX_EFFECT_SELECTED_OVERRIDES:
            raise ValueError("selected overrides exceed their bound")
        if self.scanned_symbol_count < len(self.selected):
            raise ValueError("scanned override count is smaller than selected count")
        ids = tuple(item.symbol_id for item in self.selected)
        if len(set(ids)) != len(ids) or ids != tuple(sorted(ids)):
            raise ValueError("selected override IDs must be unique and ordered")

    def canonical_bytes(self) -> bytes:
        if self.state is OverrideEvidenceState.NO_NAMESPACE:
            return _text(self.state.value)
        assert self.scanned_symbol_count is not None
        return (
            _text(self.state.value)
            + _u64(self.scanned_symbol_count)
            + _seq(tuple(item.canonical_bytes() for item in self.selected))
        )


@dataclass(frozen=True, slots=True)
class StorageFacts:
    valid: bool
    bad: bool
    unassigned: bool
    void: bool
    total_byte_size: int
    varnode_count: int

    def __post_init__(self) -> None:
        for label, value in (
            ("valid", self.valid),
            ("bad", self.bad),
            ("unassigned", self.unassigned),
            ("void", self.void),
        ):
            _require_bool(value, f"storage {label} flag")
        _require_u64(self.total_byte_size, "storage total byte size")
        _require_u64(self.varnode_count, "storage varnode count")

    def canonical_bytes(self) -> bytes:
        return (
            _bool(self.valid)
            + _bool(self.bad)
            + _bool(self.unassigned)
            + _bool(self.void)
            + _u64(self.total_byte_size)
            + _u64(self.varnode_count)
        )


@dataclass(frozen=True, slots=True)
class CapturedEffectPiece:
    piece_ordinal: int
    origin: PieceOrigin
    storage_class: EffectStorageClass
    kind_code: int
    space_id: int
    byte_offset: int
    byte_size: int

    def __post_init__(self) -> None:
        _require_u64(self.piece_ordinal, "effect piece ordinal")
        _require_exact(self.origin, PieceOrigin, "effect piece origin")
        _require_exact(self.storage_class, EffectStorageClass, "effect storage class")
        _require_u64(self.kind_code, "effect piece kind code")
        if self.kind_code not in tuple(int(item) for item in VarnodeKindCode):
            raise ValueError("effect piece kind code is unsupported")
        _require_u64(self.space_id, "effect piece space ID")
        _require_u64(self.byte_offset, "effect piece byte offset")
        _require_u64(self.byte_size, "effect piece byte size")
        if self.byte_size == 0 or self.byte_offset + self.byte_size > _U64_LIMIT:
            raise ValueError("effect piece extent is invalid")
        expected = {
            EffectStorageClass.CONSTANT: 1,
            EffectStorageClass.REGISTER: 2,
            EffectStorageClass.UNIQUE: 3,
            EffectStorageClass.ADDRESS: 4,
        }.get(self.storage_class, 7)
        if self.kind_code != expected:
            raise ValueError("effect storage class and kind code disagree")

    def canonical_bytes(self) -> bytes:
        return (
            _u64(self.piece_ordinal)
            + _text(self.origin.value)
            + _text(self.storage_class.value)
            + _u64(self.kind_code)
            + _u64(self.space_id)
            + _u64(self.byte_offset)
            + _u64(self.byte_size)
        )


@dataclass(frozen=True, slots=True)
class CapturedAssignment:
    state: AssignmentState
    storage_facts: StorageFacts
    pieces: tuple[CapturedEffectPiece, ...] = ()

    def __post_init__(self) -> None:
        _require_exact(self.state, AssignmentState, "assignment state")
        _require_exact(self.storage_facts, StorageFacts, "assignment storage facts")
        _require_exact_tuple(self.pieces, CapturedEffectPiece, "assignment pieces")
        if len(self.pieces) > MAX_EFFECT_PIECES_PER_ASSIGNMENT:
            raise ValueError("assignment pieces exceed their bound")
        expected_state = _storage_state(self.storage_facts)
        if self.state is not expected_state:
            raise ValueError("assignment state and storage facts disagree")
        if self.state is AssignmentState.ASSIGNED:
            if not self.pieces:
                raise ValueError("assigned storage requires pieces")
            ordinals = tuple(item.piece_ordinal for item in self.pieces)
            if ordinals != tuple(range(len(self.pieces))):
                raise ValueError("effect piece ordinals must be contiguous and ordered")
            if self.storage_facts.varnode_count != len(self.pieces):
                raise ValueError("assignment piece count disagrees with storage facts")
            if self.storage_facts.total_byte_size != sum(item.byte_size for item in self.pieces):
                raise ValueError("assignment piece sizes disagree with storage facts")
            synthetic = tuple(
                item for item in self.pieces if item.origin is PieceOrigin.SYNTHETIC_JOIN
            )
            if synthetic and (
                len(self.pieces) != 1
                or synthetic[0].storage_class is not EffectStorageClass.JOIN
            ):
                raise ValueError("synthetic join must be one opaque join piece")
            if any(
                item.storage_class is EffectStorageClass.JOIN
                and item.origin is not PieceOrigin.SYNTHETIC_JOIN
                for item in self.pieces
            ):
                raise ValueError("JOIN storage class requires synthetic-join origin")
        elif self.pieces:
            raise ValueError("non-assigned storage cannot have pieces")

    def canonical_bytes(self) -> bytes:
        body = _text(self.state.value) + self.storage_facts.canonical_bytes()
        if self.state is AssignmentState.ASSIGNED:
            body += _seq(tuple(item.canonical_bytes() for item in self.pieces))
        return body


@dataclass(frozen=True, slots=True)
class SlotCorrelation:
    role: CorrelationRole
    formal_ordinal: int | None = None
    returned_parameter_ordinal: int | None = None

    def __post_init__(self) -> None:
        _require_exact(self.role, CorrelationRole, "slot correlation role")
        if self.role is CorrelationRole.FIXED:
            _require_u64(self.formal_ordinal, "fixed formal ordinal")
            if self.returned_parameter_ordinal is not None:
                raise ValueError("fixed correlation cannot carry THIS ordinal")
        elif self.role is CorrelationRole.THIS:
            _require_u64(self.returned_parameter_ordinal, "returned THIS ordinal")
            if self.formal_ordinal is not None:
                raise ValueError("THIS correlation cannot carry formal ordinal")
        elif self.formal_ordinal is not None or self.returned_parameter_ordinal is not None:
            raise ValueError("automatic/result correlation cannot carry an ordinal")

    def canonical_bytes(self) -> bytes:
        body = _text(self.role.value)
        if self.role is CorrelationRole.FIXED:
            assert self.formal_ordinal is not None
            return body + _u64(self.formal_ordinal)
        if self.role is CorrelationRole.THIS:
            assert self.returned_parameter_ordinal is not None
            return body + _u64(self.returned_parameter_ordinal)
        return body


@dataclass(frozen=True, slots=True)
class CapturedModelSlot:
    slot_ordinal: int
    assignment_ordinal: int
    correlation: SlotCorrelation
    allocation_shape: AllocationShape
    is_indirect: bool
    assignment: CapturedAssignment

    def __post_init__(self) -> None:
        _require_u64(self.slot_ordinal, "model slot ordinal")
        _require_u64(self.assignment_ordinal, "model assignment ordinal")
        _require_exact(self.correlation, SlotCorrelation, "model slot correlation")
        _require_exact(self.allocation_shape, AllocationShape, "model slot shape")
        _require_bool(self.is_indirect, "model slot indirect flag")
        _require_exact(self.assignment, CapturedAssignment, "model slot assignment")

    def canonical_bytes(self) -> bytes:
        return (
            _u64(self.slot_ordinal)
            + _u64(self.assignment_ordinal)
            + self.correlation.canonical_bytes()
            + self.allocation_shape.canonical_bytes()
            + _bool(self.is_indirect)
            + self.assignment.canonical_bytes()
        )


@dataclass(frozen=True, slots=True)
class CapturedEffectDirection:
    direction: EffectDirectionTag
    open_variable_tail: bool
    slots: tuple[CapturedModelSlot, ...]

    def __post_init__(self) -> None:
        _require_exact(self.direction, EffectDirectionTag, "effect direction")
        _require_bool(self.open_variable_tail, "open variable tail")
        _require_exact_tuple(self.slots, CapturedModelSlot, "effect direction slots")
        if len(self.slots) > MAX_EFFECT_SLOTS_PER_DIRECTION:
            raise ValueError("effect direction slots exceed their bound")
        if tuple(item.slot_ordinal for item in self.slots) != tuple(range(len(self.slots))):
            raise ValueError("effect slot ordinals must be contiguous and ordered")
        roles = tuple(item.correlation.role for item in self.slots)
        if self.direction is EffectDirectionTag.POST_WRITE:
            if self.open_variable_tail or roles != (CorrelationRole.RESULT,):
                raise ValueError("POST_WRITE requires one closed result slot")
        elif CorrelationRole.RESULT in roles:
            raise ValueError("PRE_READ cannot contain a result slot")

    def canonical_bytes(self) -> bytes:
        return (
            _text(self.direction.value)
            + _bool(self.open_variable_tail)
            + _seq(tuple(item.canonical_bytes() for item in self.slots))
        )


@dataclass(frozen=True, slots=True)
class CapturedFormal:
    formal_ordinal: int
    symbol_source_quality: EffectSourceQuality
    allocation_shape: AllocationShape

    def __post_init__(self) -> None:
        _require_u64(self.formal_ordinal, "formal ordinal")
        _require_exact(self.symbol_source_quality, EffectSourceQuality, "formal source quality")
        _require_exact(self.allocation_shape, AllocationShape, "formal allocation shape")

    def canonical_bytes(self) -> bytes:
        return (
            _u64(self.formal_ordinal)
            + _text(self.symbol_source_quality.value)
            + self.allocation_shape.canonical_bytes()
        )


@dataclass(frozen=True, slots=True)
class CapturedResult:
    symbol_source_quality: EffectSourceQuality
    is_void: bool
    allocation_shape: AllocationShape

    def __post_init__(self) -> None:
        _require_exact(self.symbol_source_quality, EffectSourceQuality, "result source quality")
        _require_bool(self.is_void, "result void flag")
        _require_exact(self.allocation_shape, AllocationShape, "result allocation shape")
        if self.is_void != (self.allocation_shape.metatype_code == 14):
            raise ValueError("result void and allocation shape disagree")

    def canonical_bytes(self) -> bytes:
        return (
            _text(self.symbol_source_quality.value)
            + _bool(self.is_void)
            + self.allocation_shape.canonical_bytes()
        )


@dataclass(frozen=True, slots=True)
class CapturedSignature:
    signature_source_quality: EffectSourceQuality
    has_varargs: bool
    has_no_return: bool
    fixed_formals: tuple[CapturedFormal, ...]
    result: CapturedResult

    def __post_init__(self) -> None:
        _require_exact(self.signature_source_quality, EffectSourceQuality, "signature source quality")
        _require_bool(self.has_varargs, "signature varargs flag")
        _require_bool(self.has_no_return, "signature no-return flag")
        _require_exact_tuple(self.fixed_formals, CapturedFormal, "fixed formals")
        if len(self.fixed_formals) > MAX_EFFECT_FIXED_FORMALS:
            raise ValueError("fixed formals exceed their bound")
        if tuple(item.formal_ordinal for item in self.fixed_formals) != tuple(range(len(self.fixed_formals))):
            raise ValueError("fixed formal ordinals must be contiguous and ordered")
        _require_exact(self.result, CapturedResult, "captured result")

    def canonical_bytes(self) -> bytes:
        return (
            _text(self.signature_source_quality.value)
            + _bool(self.has_varargs)
            + _bool(self.has_no_return)
            + _seq(tuple(item.canonical_bytes() for item in self.fixed_formals))
            + self.result.canonical_bytes()
        )


@dataclass(frozen=True, slots=True)
class CapturedModelSelection:
    state: ModelSelectionState
    profile_model_ordinal: int
    profile_model_identity_digest: bytes
    model_has_this_pointer: bool

    def __post_init__(self) -> None:
        _require_exact(self.state, ModelSelectionState, "model selection state")
        _require_u64(self.profile_model_ordinal, "profile model ordinal")
        _require_digest(self.profile_model_identity_digest, "profile model digest")
        _require_bool(self.model_has_this_pointer, "model THIS flag")

    def canonical_bytes(self) -> bytes:
        return (
            _text(self.state.value)
            + _u64(self.profile_model_ordinal)
            + _bytes(self.profile_model_identity_digest)
            + _bool(self.model_has_this_pointer)
        )


@dataclass(frozen=True, slots=True)
class CapturedVarargBoundary:
    state: VarargBoundaryState
    first_vararg_slot: int | None = None

    def __post_init__(self) -> None:
        _require_exact(self.state, VarargBoundaryState, "vararg boundary state")
        if self.state is VarargBoundaryState.PRESENT:
            _require_u64(self.first_vararg_slot, "first vararg slot")
        elif self.first_vararg_slot is not None:
            raise ValueError("non-varargs boundary cannot carry a slot")

    def canonical_bytes(self) -> bytes:
        body = _text(self.state.value)
        if self.state is VarargBoundaryState.PRESENT:
            assert self.first_vararg_slot is not None
            body += _u64(self.first_vararg_slot)
        return body


@dataclass(frozen=True, slots=True)
class CapturedCustomResult:
    symbol_source_quality: EffectSourceQuality
    is_void: bool
    allocation_shape: AllocationShape
    assignment: CapturedAssignment

    def __post_init__(self) -> None:
        _require_exact(
            self.symbol_source_quality,
            EffectSourceQuality,
            "custom result quality",
        )
        _require_bool(self.is_void, "custom result void flag")
        _require_exact(self.allocation_shape, AllocationShape, "custom result shape")
        _require_exact(self.assignment, CapturedAssignment, "custom result assignment")
        if self.is_void != (self.allocation_shape.metatype_code == 14):
            raise ValueError("custom result void and allocation shape disagree")

    def canonical_bytes(self) -> bytes:
        return (
            _text(self.symbol_source_quality.value)
            + _bool(self.is_void)
            + self.allocation_shape.canonical_bytes()
            + self.assignment.canonical_bytes()
        )


@dataclass(frozen=True, slots=True)
class CapturedCustomParameter:
    database_ordinal: int
    symbol_source_quality: EffectSourceQuality
    allocation_shape: AllocationShape
    assignment: CapturedAssignment

    def __post_init__(self) -> None:
        _require_u64(self.database_ordinal, "custom parameter ordinal")
        _require_exact(self.symbol_source_quality, EffectSourceQuality, "custom parameter quality")
        _require_exact(self.allocation_shape, AllocationShape, "custom parameter shape")
        _require_exact(self.assignment, CapturedAssignment, "custom parameter assignment")

    def canonical_bytes(self) -> bytes:
        return (
            _u64(self.database_ordinal)
            + _text(self.symbol_source_quality.value)
            + self.allocation_shape.canonical_bytes()
            + self.assignment.canonical_bytes()
        )


@dataclass(frozen=True, slots=True)
class CapturedCustomStorage:
    result: CapturedCustomResult
    parameters: tuple[CapturedCustomParameter, ...]

    def __post_init__(self) -> None:
        _require_exact(self.result, CapturedCustomResult, "custom result")
        _require_exact_tuple(self.parameters, CapturedCustomParameter, "custom parameters")
        if len(self.parameters) > MAX_EFFECT_CUSTOM_PARAMETERS:
            raise ValueError("custom parameters exceed their bound")
        if tuple(item.database_ordinal for item in self.parameters) != tuple(range(len(self.parameters))):
            raise ValueError("custom parameter ordinals must be contiguous and ordered")

    def canonical_bytes(self) -> bytes:
        return self.result.canonical_bytes() + _seq(
            tuple(item.canonical_bytes() for item in self.parameters)
        )


@dataclass(frozen=True, slots=True)
class NoInterfaceCapture:
    reason: NoInterfaceReason
    state: InterfaceState = InterfaceState.NO_INTERFACE_SUBJECT

    def __post_init__(self) -> None:
        _require_exact(self.reason, NoInterfaceReason, "no-interface reason")
        if self.state is not InterfaceState.NO_INTERFACE_SUBJECT:
            raise ValueError("no-interface capture has the wrong state")

    def canonical_bytes(self) -> bytes:
        return _text(self.state.value) + _text(self.reason.value)


@dataclass(frozen=True, slots=True)
class UnassignableInterfaceCapture:
    subject: AddressCoordinate
    reason: UnassignableReason
    custom_storage: CapturedCustomStorage | None = None
    state: InterfaceState = InterfaceState.UNASSIGNABLE_INTERFACE

    def __post_init__(self) -> None:
        _require_exact(self.subject, AddressCoordinate, "unassignable subject")
        _require_exact(self.reason, UnassignableReason, "unassignable reason")
        if self.state is not InterfaceState.UNASSIGNABLE_INTERFACE:
            raise ValueError("unassignable capture has the wrong state")
        if self.reason is UnassignableReason.CUSTOM_STORAGE_PRESENT:
            _require_exact(self.custom_storage, CapturedCustomStorage, "custom storage")
        elif self.custom_storage is not None:
            raise ValueError("only custom-storage rejection can retain a transcript")

    def canonical_bytes(self) -> bytes:
        body = _text(self.state.value) + _coordinate(self.subject) + _text(self.reason.value)
        if self.custom_storage is not None:
            body += self.custom_storage.canonical_bytes()
        return body


@dataclass(frozen=True, slots=True)
class AssignmentInterfaceCapture:
    subject: AddressCoordinate
    returned_parameter_count: int
    model_selection: CapturedModelSelection
    signature: CapturedSignature
    vararg_boundary: CapturedVarargBoundary
    directions: tuple[CapturedEffectDirection, CapturedEffectDirection]
    state: InterfaceState = InterfaceState.ASSIGNMENT_CAPTURED

    def __post_init__(self) -> None:
        _require_exact(self.subject, AddressCoordinate, "assignment subject")
        _require_u64(self.returned_parameter_count, "returned parameter count")
        if self.returned_parameter_count > MAX_EFFECT_RETURNED_PARAMETERS:
            raise ValueError("returned parameter count exceeds its bound")
        _require_exact(self.model_selection, CapturedModelSelection, "model selection")
        _require_exact(self.signature, CapturedSignature, "captured signature")
        _require_exact(self.vararg_boundary, CapturedVarargBoundary, "vararg boundary")
        if self.state is not InterfaceState.ASSIGNMENT_CAPTURED:
            raise ValueError("assignment capture has the wrong state")
        if type(self.directions) is not tuple or len(self.directions) != 2 or any(
            type(item) is not CapturedEffectDirection for item in self.directions
        ):
            raise TypeError("assignment directions must be an exact two-item tuple")
        if tuple(item.direction for item in self.directions) != (
            EffectDirectionTag.PRE_READ,
            EffectDirectionTag.POST_WRITE,
        ):
            raise ValueError("assignment directions must be PRE then POST")
        self._validate_cross_fields()

    def _validate_cross_fields(self) -> None:
        pre, post = self.directions
        if pre.open_variable_tail != self.signature.has_varargs:
            raise ValueError("signature and variable-tail facts disagree")
        expected_boundary = len(self.signature.fixed_formals) + int(
            self.model_selection.model_has_this_pointer
        )
        if self.signature.has_varargs:
            if (
                self.vararg_boundary.state is not VarargBoundaryState.PRESENT
                or self.vararg_boundary.first_vararg_slot != expected_boundary
            ):
                raise ValueError("vararg boundary does not match fixed inputs")
        elif self.vararg_boundary.state is not VarargBoundaryState.NOT_VARARGS:
            raise ValueError("non-varargs signature has a vararg boundary")
        pre_roles = tuple(slot.correlation.role for slot in pre.slots)
        if pre_roles.count(CorrelationRole.THIS) != int(
            self.model_selection.model_has_this_pointer
        ):
            raise ValueError("THIS slot cardinality disagrees with model")
        fixed = tuple(
            slot.correlation.formal_ordinal
            for slot in pre.slots
            if slot.correlation.role is CorrelationRole.FIXED
        )
        if fixed != tuple(range(len(self.signature.fixed_formals))):
            raise ValueError("fixed slot correlation is incomplete or unordered")
        if pre_roles.count(CorrelationRole.HIDDEN_RETURN_POINTER) > 1:
            raise ValueError("assignment has multiple hidden-return-pointer slots")
        expected_slot_count = (
            len(self.signature.fixed_formals)
            + int(self.model_selection.model_has_this_pointer)
            + 1
            + pre_roles.count(CorrelationRole.HIDDEN_RETURN_POINTER)
        )
        if len(pre.slots) + len(post.slots) != expected_slot_count:
            raise ValueError("assignment role cardinality is inconsistent")
        minimum_returned = len(self.signature.fixed_formals) + int(
            self.model_selection.model_has_this_pointer
        )
        hidden_role_count = pre_roles.count(CorrelationRole.HIDDEN_RETURN_POINTER)
        if self.returned_parameter_count != minimum_returned + hidden_role_count:
            raise ValueError(
                "returned parameter count must exactly include the hidden-result role"
            )
        this_slots = tuple(
            slot for slot in pre.slots if slot.correlation.role is CorrelationRole.THIS
        )
        if this_slots:
            ordinal = this_slots[0].correlation.returned_parameter_ordinal
            assert ordinal is not None
            if ordinal >= self.returned_parameter_count:
                raise ValueError("returned THIS ordinal is outside the parameter array")
        formals = {
            item.formal_ordinal: item.allocation_shape
            for item in self.signature.fixed_formals
        }
        for slot in pre.slots:
            role = slot.correlation.role
            if role is CorrelationRole.FIXED:
                assert slot.correlation.formal_ordinal is not None
                if slot.allocation_shape != formals[slot.correlation.formal_ordinal]:
                    raise ValueError("fixed slot allocation shape disagrees with formal")
            elif role is CorrelationRole.HIDDEN_RETURN_POINTER:
                if slot.allocation_shape.metatype_code != 6:
                    raise ValueError("hidden-return-pointer slot must have pointer shape")
        result_slot = post.slots[0]
        if result_slot.allocation_shape != self.signature.result.allocation_shape:
            raise ValueError("result slot allocation shape disagrees with signature")
        assignment_ordinals = tuple(
            slot.assignment_ordinal for direction in self.directions for slot in direction.slots
        )
        if len(set(assignment_ordinals)) != len(assignment_ordinals):
            raise ValueError("assignment ordinals must be unique")
        expected_count = len(pre.slots) + len(post.slots)
        if set(assignment_ordinals) != set(range(expected_count)):
            raise ValueError("assignment ordinals must cover the complete range")
        if post.slots[0].assignment_ordinal != 0 or tuple(
            slot.assignment_ordinal for slot in pre.slots
        ) != tuple(range(1, len(pre.slots) + 1)):
            raise ValueError("assignment ordinals must preserve output-first list order")

    def canonical_bytes(self) -> bytes:
        return (
            _text(self.state.value)
            + _coordinate(self.subject)
            + _u64(self.returned_parameter_count)
            + self.model_selection.canonical_bytes()
            + self.signature.canonical_bytes()
            + self.vararg_boundary.canonical_bytes()
            + _seq(tuple(item.canonical_bytes() for item in self.directions))
        )


InterfaceCapture: TypeAlias = (
    NoInterfaceCapture | UnassignableInterfaceCapture | AssignmentInterfaceCapture
)


@dataclass(frozen=True, slots=True)
class CapturedEffectRow:
    instruction: AddressCoordinate
    operation_ordinal: int
    opcode: EffectOpcode
    selector: CapturedEffectSelector | None
    override_evidence: CapturedOverrideEvidence
    interface_capture: InterfaceCapture
    row_digest: bytes

    def __post_init__(self) -> None:
        _require_exact(self.instruction, AddressCoordinate, "effect instruction")
        _require_u64(self.operation_ordinal, "effect operation ordinal")
        _require_exact(self.opcode, EffectOpcode, "effect opcode")
        if self.selector is not None:
            _require_exact(self.selector, CapturedEffectSelector, "effect selector")
        _require_exact(self.override_evidence, CapturedOverrideEvidence, "override evidence")
        if type(self.interface_capture) not in (
            NoInterfaceCapture,
            UnassignableInterfaceCapture,
            AssignmentInterfaceCapture,
        ):
            raise TypeError("effect interface capture has an invalid exact type")
        self._validate_cross_fields()
        _require_digest(self.row_digest, "effect row digest")
        if self.row_digest != effect_row_digest(
            self.instruction,
            self.operation_ordinal,
            self.opcode,
            self.selector,
            self.override_evidence,
            self.interface_capture,
        ):
            raise ValueError("effect row digest does not match its fields")

    def _validate_cross_fields(self) -> None:
        capture = self.interface_capture
        if self.opcode is EffectOpcode.CALLIND:
            if (
                type(capture) is not NoInterfaceCapture
                or capture.reason is not NoInterfaceReason.INDIRECT_CALL
            ):
                raise ValueError("CALLIND must retain INDIRECT_CALL evidence")
            return

        if self.selector is None:
            expected_reason = NoInterfaceReason.MISSING_SELECTOR
        elif self.selector.kind is VarnodeKindCode.OPAQUE:
            expected_reason = NoInterfaceReason.OPAQUE_SELECTOR
        elif self.selector.kind is not VarnodeKindCode.ADDRESS:
            expected_reason = NoInterfaceReason.NON_ADDRESS_SELECTOR
        else:
            expected_reason = NoInterfaceReason.NO_EXACT_FUNCTION

        if type(capture) is NoInterfaceCapture:
            if capture.reason is not expected_reason:
                raise ValueError("CALL selector and no-interface reason disagree")
            return
        if self.selector is None or self.selector.kind is not VarnodeKindCode.ADDRESS:
            raise ValueError("interface subject requires one direct address selector")
        if capture.subject != self.selector.coordinate:
            raise ValueError("interface subject must equal the direct selector")
        selected = self.override_evidence.selected
        if type(capture) is UnassignableInterfaceCapture:
            if capture.reason is UnassignableReason.OVERRIDE_PRESENT:
                if not selected:
                    raise ValueError("override rejection requires selected evidence")
            elif selected:
                raise ValueError("non-override rejection cannot retain selected overrides")
        elif selected:
            raise ValueError("assignment capture cannot retain selected overrides")

    @property
    def canonical_key(self) -> tuple[int, int, int]:
        return (
            self.instruction.space_id,
            self.instruction.byte_offset,
            self.operation_ordinal,
        )

    @property
    def canonical_body(self) -> bytes:
        return _row_body(
            self.instruction,
            self.operation_ordinal,
            self.opcode,
            self.selector,
            self.override_evidence,
            self.interface_capture,
        )


@dataclass(frozen=True, slots=True)
class CapturedEffectSidecar:
    exporter_source_sha256: bytes
    profile_semantic_content_digest: bytes
    rows: tuple[CapturedEffectRow, ...]
    semantic_content_digest: bytes

    def __post_init__(self) -> None:
        _require_digest(self.exporter_source_sha256, "effect exporter source SHA-256")
        _require_digest(self.profile_semantic_content_digest, "profile content digest")
        _require_exact_tuple(self.rows, CapturedEffectRow, "effect rows")
        if len(self.rows) > MAX_EFFECT_ROWS:
            raise ValueError("effect rows exceed their bound")
        for row in self.rows:
            capture = row.interface_capture
            if type(capture) is AssignmentInterfaceCapture:
                count = sum(
                    len(slot.assignment.pieces)
                    for direction in capture.directions
                    for slot in direction.slots
                )
            elif (
                type(capture) is UnassignableInterfaceCapture
                and capture.custom_storage is not None
            ):
                count = len(capture.custom_storage.result.assignment.pieces) + sum(
                    len(item.assignment.pieces)
                    for item in capture.custom_storage.parameters
                )
            else:
                count = 0
            if count > MAX_EFFECT_CAPTURED_PIECES_PER_CALL:
                raise ValueError("captured pieces exceed their per-call bound")
        _require_digest(self.semantic_content_digest, "effect content digest")
        if self.semantic_content_digest != effect_content_digest(
            self.exporter_source_sha256,
            self.profile_semantic_content_digest,
            self.rows,
        ):
            raise ValueError("effect content digest does not match its rows")


def effect_row_digest(
    instruction: AddressCoordinate,
    operation_ordinal: int,
    opcode: EffectOpcode,
    selector: CapturedEffectSelector | None,
    override_evidence: CapturedOverrideEvidence,
    interface_capture: InterfaceCapture,
) -> bytes:
    return _digest(
        _text(_ROW_DOMAIN)
        + _row_body(
            instruction,
            operation_ordinal,
            opcode,
            selector,
            override_evidence,
            interface_capture,
        )
    )


def effect_content_digest(
    exporter_source_sha256: bytes,
    profile_semantic_content_digest: bytes,
    rows: tuple[CapturedEffectRow, ...],
) -> bytes:
    _require_digest(exporter_source_sha256, "effect exporter source SHA-256")
    _require_digest(profile_semantic_content_digest, "profile content digest")
    _require_exact_tuple(rows, CapturedEffectRow, "effect rows")
    digest = sha256()
    digest.update(_text(_CONTENT_DOMAIN))
    digest.update(_u64(CALL_EFFECT_SCHEMA_VERSION))
    digest.update(_u64(CALL_EFFECT_EXPORTER_REVISION))
    digest.update(_bytes(exporter_source_sha256))
    digest.update(_text(CALL_EFFECT_GHIDRA_VERSION))
    digest.update(_bytes(profile_semantic_content_digest))
    digest.update(_u64(len(rows)))
    for row in rows:
        digest.update(row.canonical_body)
        digest.update(_bytes(row.row_digest))
    return digest.digest()


def _row_body(
    instruction: AddressCoordinate,
    operation_ordinal: int,
    opcode: EffectOpcode,
    selector: CapturedEffectSelector | None,
    override_evidence: CapturedOverrideEvidence,
    interface_capture: InterfaceCapture,
) -> bytes:
    _require_exact(instruction, AddressCoordinate, "effect instruction")
    _require_u64(operation_ordinal, "effect operation ordinal")
    _require_exact(opcode, EffectOpcode, "effect opcode")
    if selector is not None:
        _require_exact(selector, CapturedEffectSelector, "effect selector")
    _require_exact(override_evidence, CapturedOverrideEvidence, "override evidence")
    if type(interface_capture) not in (
        NoInterfaceCapture,
        UnassignableInterfaceCapture,
        AssignmentInterfaceCapture,
    ):
        raise TypeError("effect interface capture has an invalid exact type")
    return (
        _coordinate(instruction)
        + _u64(operation_ordinal)
        + _text(opcode.value)
        + _selector(selector)
        + override_evidence.canonical_bytes()
        + interface_capture.canonical_bytes()
    )


def _storage_state(facts: StorageFacts) -> AssignmentState:
    if facts.void:
        state = AssignmentState.VOID
    elif facts.unassigned:
        state = AssignmentState.UNASSIGNED
    elif facts.bad or not facts.valid:
        state = AssignmentState.BAD
    else:
        state = AssignmentState.ASSIGNED
    if state is not AssignmentState.ASSIGNED and (
        facts.varnode_count != 0 or facts.total_byte_size != 0
    ):
        raise ValueError("non-assigned storage facts must have zero size and count")
    return state


def _selector(value: CapturedEffectSelector | None) -> bytes:
    if value is None:
        return _text("MISSING")
    return (
        _text("PRESENT")
        + _u64(int(value.kind))
        + _u64(value.coordinate.space_id)
        + _u64(value.coordinate.byte_offset)
        + _u64(value.byte_size)
    )


def _coordinate(value: AddressCoordinate) -> bytes:
    _require_exact(value, AddressCoordinate, "encoded coordinate")
    return _u64(value.space_id) + _u64(value.byte_offset)


def _bool(value: bool) -> bytes:
    _require_bool(value, "encoded boolean")
    return b"\x01" if value else b"\x00"


def _u64(value: int) -> bytes:
    _require_u64(value, "encoded unsigned integer")
    return value.to_bytes(8, "big")


def _bytes(value: bytes) -> bytes:
    if type(value) is not bytes:
        raise TypeError("encoded bytes must be exact bytes")
    if len(value) >= _U64_LIMIT:
        raise ValueError("encoded byte length exceeds unsigned 64-bit")
    return _u64(len(value)) + value


def _text(value: str) -> bytes:
    _require_text(value, "encoded text")
    return _bytes(value.encode("utf-8", errors="strict"))


def _seq(values: tuple[bytes, ...]) -> bytes:
    if type(values) is not tuple or any(type(value) is not bytes for value in values):
        raise TypeError("encoded sequence must be an exact bytes tuple")
    return _u64(len(values)) + b"".join(values)


def _digest(value: bytes) -> bytes:
    if type(value) is not bytes:
        raise TypeError("digest preimage must be exact bytes")
    return sha256(value).digest()


def _require_exact(value: object, expected: type, label: str) -> None:
    if type(value) is not expected:
        raise TypeError(f"{label} must be an exact {expected.__name__}")


def _require_exact_tuple(value: object, expected: type, label: str) -> None:
    if type(value) is not tuple or any(type(item) is not expected for item in value):
        raise TypeError(f"{label} must be an exact {expected.__name__} tuple")


def _require_bool(value: object, label: str) -> None:
    if type(value) is not bool:
        raise TypeError(f"{label} must be an exact bool")


def _require_u64(value: object, label: str) -> None:
    if type(value) is not int:
        raise TypeError(f"{label} must be an exact int")
    if not 0 <= value < _U64_LIMIT:
        raise ValueError(f"{label} exceeds unsigned 64-bit")


def _require_digest(value: object, label: str) -> None:
    if type(value) is not bytes:
        raise TypeError(f"{label} must be exact bytes")
    if len(value) != 32:
        raise ValueError(f"{label} must contain exactly 32 bytes")


def _require_text(value: object, label: str) -> None:
    if type(value) is not str or not value:
        raise TypeError(f"{label} must be a nonempty exact str")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} must be strict UTF-8") from exc


def _require_exact_text(value: object, expected: str, label: str) -> None:
    _require_text(value, label)
    if value != expected:
        raise ValueError(f"{label} is unsupported")


__all__ = (
    "CALL_EFFECT_CAPTURE_DEADLINE_SECONDS",
    "CALL_EFFECT_EXPORTER_REVISION",
    "CALL_EFFECT_EXPORTER_SOURCE_SET_DOMAIN",
    "CALL_EFFECT_GHIDRA_VERSION",
    "CALL_EFFECT_SCHEMA_ID",
    "CALL_EFFECT_SCHEMA_VERSION",
    "EFFECT_RUNTIME_CLASS_IDS",
    "AllocationShape",
    "AssignmentInterfaceCapture",
    "AssignmentState",
    "CapturedAssignment",
    "CapturedCustomParameter",
    "CapturedCustomResult",
    "CapturedCustomStorage",
    "CapturedEffectDirection",
    "CapturedEffectPiece",
    "CapturedEffectRow",
    "CapturedEffectSelector",
    "CapturedEffectSidecar",
    "CapturedFormal",
    "CapturedModelSelection",
    "CapturedModelSlot",
    "CapturedOverride",
    "CapturedOverrideEvidence",
    "CapturedResult",
    "CapturedSignature",
    "CapturedVarargBoundary",
    "CorrelationRole",
    "EffectBindingExpectation",
    "EffectDirectionTag",
    "EffectOpcode",
    "EffectSourceQuality",
    "EffectStorageClass",
    "EffectTransportExpectation",
    "InterfaceCapture",
    "InterfaceState",
    "ModelSelectionState",
    "NoInterfaceCapture",
    "NoInterfaceReason",
    "OverrideDecodeState",
    "OverrideEvidenceState",
    "OverrideShape",
    "PieceOrigin",
    "RuntimeClassEvidence",
    "SlotCorrelation",
    "StorageFacts",
    "UnassignableInterfaceCapture",
    "UnassignableReason",
    "VarargBoundaryState",
    "effect_content_digest",
    "effect_row_digest",
)
