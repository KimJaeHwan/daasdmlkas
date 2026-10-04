"""Exact, architect-owned values shared by deterministic scope construction."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
import re

from .model import StorageScopeId, StorageScopeKind


U64_LIMIT = 1 << 64
U64_MAX = U64_LIMIT - 1
IO_CHUNK_BYTES = 1_048_576
MAX_FUNCTION_INSTRUCTIONS = 262_144
MAX_FUNCTION_OPERATIONS = 1_048_576
MAX_OPERATION_INPUTS = 65_536
MAX_FUNCTION_VARNODES = 4_194_304
MAX_OPCODE_ASCII_BYTES = 64
MAX_FLOW_TARGETS_PER_INSTRUCTION = 65_536
MAX_FUNCTION_FLOW_TARGETS = 1_048_576
MAX_DATA_REFERENCES_PER_INSTRUCTION = 65_536
MAX_FUNCTION_DATA_REFERENCES = 1_048_576
MAX_CALL_OCCURRENCES = 16_384
MAX_CALL_CONTEXT_TARGET_REFERENCES = 1_048_576
_OPCODE = re.compile(r"[A-Z][A-Z0-9_]*", flags=re.ASCII)


class EvidenceOrigin(StrEnum):
    CONFIGURED_EXTRACTION = "configured_extraction"
    DETACHED = "detached"
    UNKNOWN = "unknown"


class VarnodeKindCode(IntEnum):
    CONSTANT = 1
    REGISTER = 2
    UNIQUE = 3
    ADDRESS = 4
    STORAGE = 5
    UNKNOWN = 6
    OPAQUE = 7


class AddressSpaceClassV2(StrEnum):
    CONSTANT = "CONSTANT"
    REGISTER = "REGISTER"
    UNIQUE = "UNIQUE"
    ADDRESS = "ADDRESS"
    OPAQUE = "OPAQUE"


@dataclass(frozen=True, slots=True)
class InstructionFlowEvidence:
    """Exact Ghidra FlowType predicates retained without role inference."""

    is_flow: bool
    has_fallthrough: bool
    is_call: bool
    is_jump: bool
    is_terminal: bool
    is_computed: bool
    is_conditional: bool
    is_unconditional: bool
    is_override: bool

    def __post_init__(self) -> None:
        for name in (
            "is_flow",
            "has_fallthrough",
            "is_call",
            "is_jump",
            "is_terminal",
            "is_computed",
            "is_conditional",
            "is_unconditional",
            "is_override",
        ):
            require_bool(getattr(self, name), f"instruction flow {name}")
        if self.is_call and self.is_jump:
            raise ValueError("instruction flow cannot be both call and jump")
        if self.is_conditional and self.is_unconditional:
            raise ValueError("instruction flow cannot be both conditional and unconditional")


@dataclass(frozen=True, order=True, slots=True)
class AddressCoordinate:
    space_id: int
    byte_offset: int

    def __post_init__(self) -> None:
        require_u64(self.space_id, "coordinate space ID")
        require_u64(self.byte_offset, "coordinate byte offset")


@dataclass(frozen=True, slots=True)
class TranslationNamespace:
    language_id: str
    major_version: int
    minor_version: int

    def __post_init__(self) -> None:
        require_text(self.language_id, "language ID", nonempty=True)
        require_u64(self.major_version, "language major version")
        require_u64(self.minor_version, "language minor version")


@dataclass(frozen=True, slots=True)
class AddressSpaceEvidence:
    space_id: int
    address_size_bits: int
    addressable_unit_bytes: int
    is_constant_space: bool
    is_register_space: bool
    is_unique_space: bool
    is_memory_space: bool
    is_overlay_space: bool
    is_external_space: bool
    is_loaded_memory_space: bool | None = None
    is_non_loaded_memory_space: bool | None = None
    has_signed_offset: bool | None = None

    def __post_init__(self) -> None:
        require_u64(self.space_id, "address-space ID")
        require_u64(self.address_size_bits, "address-space size")
        require_u64(self.addressable_unit_bytes, "addressable unit")
        if not 1 <= self.address_size_bits <= 64:
            raise ValueError("address-space size must be from 1 through 64 bits")
        if not 1 <= self.addressable_unit_bytes <= 8:
            raise ValueError("addressable unit must be from 1 through 8 bytes")
        if self.address_size_bits + (self.addressable_unit_bytes - 1).bit_length() > 64:
            raise ValueError("address-space byte capacity exceeds unsigned 64-bit")
        for name in _SPACE_BOOLEAN_FIELDS:
            require_bool(getattr(self, name), name)
        revision_fields = (
            self.is_loaded_memory_space,
            self.is_non_loaded_memory_space,
            self.has_signed_offset,
        )
        if all(value is None for value in revision_fields):
            return
        if any(value is None for value in revision_fields):
            raise ValueError("address-space classification revision is partial")
        require_bool(self.is_loaded_memory_space, "is_loaded_memory_space")
        require_bool(
            self.is_non_loaded_memory_space,
            "is_non_loaded_memory_space",
        )
        require_bool(self.has_signed_offset, "has_signed_offset")

    @property
    def classification_revision(self) -> int:
        return 1 if self.has_signed_offset is None else 2


def classify_address_space_v2(row: AddressSpaceEvidence) -> AddressSpaceClassV2:
    require_exact(row, AddressSpaceEvidence, "address-space classification row")
    if row.classification_revision != 2:
        raise ValueError("address-space classification requires revision 2")
    common = not row.is_overlay_space and not row.is_external_space
    nonmemory = (
        row.is_loaded_memory_space is False
        and row.is_non_loaded_memory_space is False
    )
    if (
        common
        and nonmemory
        and row.is_constant_space
        and not row.is_register_space
        and not row.is_unique_space
        and not row.is_memory_space
    ):
        return AddressSpaceClassV2.CONSTANT
    if (
        common
        and nonmemory
        and not row.is_constant_space
        and row.is_register_space
        and not row.is_unique_space
        and not row.is_memory_space
    ):
        return AddressSpaceClassV2.REGISTER
    if (
        common
        and nonmemory
        and not row.is_constant_space
        and not row.is_register_space
        and row.is_unique_space
        and not row.is_memory_space
    ):
        return AddressSpaceClassV2.UNIQUE
    if (
        common
        and not row.is_constant_space
        and not row.is_register_space
        and not row.is_unique_space
        and row.is_memory_space
        and row.is_loaded_memory_space is True
        and row.is_non_loaded_memory_space is False
        and row.has_signed_offset is False
    ):
        return AddressSpaceClassV2.ADDRESS
    return AddressSpaceClassV2.OPAQUE


_SPACE_BOOLEAN_FIELDS = (
    "is_constant_space",
    "is_register_space",
    "is_unique_space",
    "is_memory_space",
    "is_overlay_space",
    "is_external_space",
)


@dataclass(frozen=True, slots=True)
class FrozenMemoryBlockDescriptor:
    block_handle: object = field(compare=False, repr=False)
    space_id: int
    byte_start: int
    byte_size: int
    is_loaded: bool
    is_initialized: bool
    is_overlay: bool
    is_external: bool
    is_mapped: bool

    def __post_init__(self) -> None:
        require_u64(self.space_id, "memory-block space ID")
        require_u64(self.byte_start, "memory-block byte start")
        require_u64(self.byte_size, "memory-block byte size")
        if self.byte_size == 0:
            raise ValueError("memory-block byte size must be positive")
        if self.byte_start + self.byte_size > U64_LIMIT:
            raise ValueError("memory-block extent exceeds unsigned 64-bit")
        for name in (
            "is_loaded",
            "is_initialized",
            "is_overlay",
            "is_external",
            "is_mapped",
        ):
            require_bool(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class PositionedChunk:
    offset: int
    data: bytes

    def __post_init__(self) -> None:
        require_u64(self.offset, "chunk offset")
        if type(self.data) is not bytes:
            raise TypeError("chunk data must be exact bytes")
        if not 1 <= len(self.data) <= IO_CHUNK_BYTES:
            raise ValueError("chunk data length is outside the configured bound")
        if self.offset + len(self.data) > U64_LIMIT:
            raise ValueError("chunk extent exceeds unsigned 64-bit")


@dataclass(frozen=True, slots=True)
class CommittedMemoryRun:
    space_id: int
    byte_start: int
    byte_size: int
    is_initialized: bool

    def __post_init__(self) -> None:
        require_u64(self.space_id, "committed-run space ID")
        require_u64(self.byte_start, "committed-run byte start")
        require_u64(self.byte_size, "committed-run byte size")
        if self.byte_size == 0:
            raise ValueError("committed-run byte size must be positive")
        if self.byte_start + self.byte_size > U64_LIMIT:
            raise ValueError("committed-run extent exceeds unsigned 64-bit")
        require_bool(self.is_initialized, "committed-run initialized state")

    @property
    def byte_end(self) -> int:
        return self.byte_start + self.byte_size


@dataclass(frozen=True, slots=True)
class VerifiedProgramSnapshotEvidence:
    executable_sha256: bytes
    loaded_memory_digest: bytes
    image_base: AddressCoordinate
    translation_namespace: TranslationNamespace
    address_space_classification_revision: int = 1
    address_spaces: tuple[AddressSpaceEvidence, ...] = ()

    def __post_init__(self) -> None:
        require_digest(self.executable_sha256, "executable SHA-256")
        require_digest(self.loaded_memory_digest, "loaded-memory digest")
        require_exact(self.image_base, AddressCoordinate, "image base")
        require_exact(self.translation_namespace, TranslationNamespace, "translation namespace")
        if type(self.address_space_classification_revision) is not int:
            raise TypeError("address-space classification revision must be an exact int")
        if self.address_space_classification_revision not in (1, 2):
            raise ValueError("unsupported address-space classification revision")
        if type(self.address_spaces) is not tuple or any(
            type(row) is not AddressSpaceEvidence for row in self.address_spaces
        ):
            raise TypeError("program address spaces must be an exact evidence tuple")
        if tuple(sorted(self.address_spaces, key=lambda row: row.space_id)) != self.address_spaces:
            raise ValueError("program address spaces must be sorted by numeric space ID")
        if len({row.space_id for row in self.address_spaces}) != len(self.address_spaces):
            raise ValueError("program address-space IDs must be unique")
        if any(
            row.classification_revision
            != self.address_space_classification_revision
            for row in self.address_spaces
        ):
            raise ValueError("program and address-space revisions must be homogeneous")


@dataclass(frozen=True, slots=True)
class FunctionScopeEvidence:
    program_scope: StorageScopeId
    entry: AddressCoordinate
    observation_digest: bytes

    def __post_init__(self) -> None:
        require_exact(self.program_scope, StorageScopeId, "program scope")
        if self.program_scope.kind is not StorageScopeKind.PROGRAM:
            raise TypeError("function evidence requires a PROGRAM scope")
        require_exact(self.entry, AddressCoordinate, "function entry")
        require_digest(self.observation_digest, "function observation digest")


@dataclass(frozen=True, slots=True)
class ValidatedVarnode:
    kind: VarnodeKindCode
    coordinate: AddressCoordinate
    byte_size: int

    def __post_init__(self) -> None:
        require_exact(self.kind, VarnodeKindCode, "varnode kind")
        if self.kind is VarnodeKindCode.UNKNOWN:
            raise ValueError("validated varnode kind cannot be UNKNOWN")
        require_exact(self.coordinate, AddressCoordinate, "varnode coordinate")
        require_u64(self.byte_size, "varnode byte size")
        if self.byte_size == 0:
            raise ValueError("varnode byte size must be positive")


@dataclass(frozen=True, slots=True)
class ValidatedOperation:
    opcode: str
    inputs: tuple[ValidatedVarnode, ...]
    output: ValidatedVarnode | None

    def __post_init__(self) -> None:
        require_text(self.opcode, "opcode", nonempty=True, ascii_only=True)
        if not _is_valid_opcode(self.opcode):
            raise ValueError("opcode must match [A-Z][A-Z0-9_]*")
        if type(self.inputs) is not tuple or any(type(item) is not ValidatedVarnode for item in self.inputs):
            raise TypeError("operation inputs must be an exact varnode tuple")
        if self.output is not None and type(self.output) is not ValidatedVarnode:
            raise TypeError("operation output must be an exact varnode or None")


@dataclass(frozen=True, order=True, slots=True)
class InstructionDataReference:
    coordinate: AddressCoordinate
    is_read: bool
    is_write: bool
    referenced_function_entry: AddressCoordinate | None = None

    def __post_init__(self) -> None:
        require_exact(self.coordinate, AddressCoordinate, "data reference coordinate")
        require_bool(self.is_read, "data reference is_read")
        require_bool(self.is_write, "data reference is_write")
        if self.referenced_function_entry is not None:
            require_exact(
                self.referenced_function_entry,
                AddressCoordinate,
                "referenced function entry",
            )


@dataclass(frozen=True, slots=True)
class ValidatedInstruction:
    address: AddressCoordinate
    fallthrough: AddressCoordinate | None
    flow_targets: tuple[AddressCoordinate, ...]
    operations: tuple[ValidatedOperation, ...]
    flow: InstructionFlowEvidence
    data_references: tuple[InstructionDataReference, ...] = ()

    def __post_init__(self) -> None:
        require_exact(self.address, AddressCoordinate, "instruction address")
        if self.fallthrough is not None:
            require_exact(self.fallthrough, AddressCoordinate, "fallthrough")
        if type(self.flow_targets) is not tuple or any(
            type(item) is not AddressCoordinate for item in self.flow_targets
        ):
            raise TypeError("flow targets must be an exact coordinate tuple")
        if tuple(sorted(set(self.flow_targets))) != self.flow_targets:
            raise ValueError("flow targets must be sorted and unique")
        if type(self.operations) is not tuple or any(type(item) is not ValidatedOperation for item in self.operations):
            raise TypeError("operations must be an exact operation tuple")
        require_exact(self.flow, InstructionFlowEvidence, "instruction flow evidence")
        if type(self.data_references) is not tuple or any(
            type(item) is not InstructionDataReference for item in self.data_references
        ):
            raise TypeError("data references must be an exact reference tuple")
        if tuple(sorted(set(self.data_references))) != self.data_references:
            raise ValueError("data references must be sorted and unique")


@dataclass(frozen=True, slots=True)
class ValidatedFunctionObservation:
    instructions: tuple[ValidatedInstruction, ...]

    def __post_init__(self) -> None:
        if type(self.instructions) is not tuple or any(
            type(item) is not ValidatedInstruction for item in self.instructions
        ):
            raise TypeError("instructions must be an exact instruction tuple")
        addresses = tuple(item.address for item in self.instructions)
        if len(addresses) != len(set(addresses)):
            raise ValueError("instruction addresses must be unique")


def require_exact(value: object, expected: type, label: str) -> None:
    if type(value) is not expected:
        raise TypeError(f"{label} must be an exact {expected.__name__}")


def require_u64(value: object, label: str) -> None:
    if type(value) is not int:
        raise TypeError(f"{label} must be an exact int")
    if not 0 <= value < U64_LIMIT:
        raise ValueError(f"{label} must fit unsigned 64-bit")


def require_bool(value: object, label: str) -> None:
    if type(value) is not bool:
        raise TypeError(f"{label} must be an exact bool")


def require_digest(value: object, label: str) -> None:
    if type(value) is not bytes:
        raise TypeError(f"{label} must be exact bytes")
    if len(value) != 32:
        raise ValueError(f"{label} must contain exactly 32 bytes")


def require_text(value: object, label: str, *, nonempty: bool = False, ascii_only: bool = False) -> None:
    if type(value) is not str:
        raise TypeError(f"{label} must be an exact str")
    if nonempty and not value:
        raise ValueError(f"{label} must be non-empty")
    if value == "UNKNOWN":
        raise ValueError(f"{label} cannot use the UNKNOWN diagnostic sentinel")
    try:
        value.encode("ascii" if ascii_only else "utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        encoding = "ASCII" if ascii_only else "UTF-8"
        raise ValueError(f"{label} must be strict {encoding} text") from exc


def _is_valid_opcode(
    value: object,
    max_ascii_bytes: int = MAX_OPCODE_ASCII_BYTES,
) -> bool:
    return (
        type(value) is str
        and value != "UNKNOWN"
        and 1 <= len(value) <= max_ascii_bytes
        and value.isascii()
        and _OPCODE.fullmatch(value) is not None
    )


class _OrchestratorCapability:
    __slots__ = ()

    def __reduce_ex__(self, protocol: int):
        raise TypeError("configured-extraction capability cannot be serialized")


_ORCHESTRATOR_CAPABILITY = _OrchestratorCapability()


class _ConstructionPermit:
    __slots__ = ("_active",)

    def __init__(self, capability: _OrchestratorCapability) -> None:
        if capability is not _ORCHESTRATOR_CAPABILITY:
            raise PermissionError("invalid configured-extraction capability")
        self._active = True

    def require_active(self) -> None:
        if self._active is not True:
            raise RuntimeError("scope construction permit is inactive")

    def revoke(self) -> None:
        self._active = False

    def __reduce_ex__(self, protocol: int):
        raise TypeError("scope construction permit cannot be serialized")


def _mint_orchestrator_capability() -> _OrchestratorCapability:
    return _ORCHESTRATOR_CAPABILITY
