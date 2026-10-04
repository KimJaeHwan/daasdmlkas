"""Architect-owned authority and storage admission for configured call effects."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256

from ._scope_contracts import (
    AddressSpaceClassV2,
    AddressSpaceEvidence,
    CommittedMemoryRun,
    U64_LIMIT,
    VerifiedProgramSnapshotEvidence,
    classify_address_space_v2,
)
from ._scope_results import ConstructedProgramScope
from .call_contracts import CallOccurrenceId, FunctionCallSeedUnit
from .call_effect_contracts import CallEffectDirection
from .configured_effect_wire_contracts import (
    CALL_EFFECT_EXPORTER_REVISION,
    CALL_EFFECT_GHIDRA_VERSION,
    CALL_EFFECT_SCHEMA_ID,
    CALL_EFFECT_SCHEMA_VERSION,
    AssignmentInterfaceCapture,
    CapturedAssignment,
    CapturedEffectPiece,
    CapturedEffectRow,
    CapturedEffectSelector,
    CapturedEffectSidecar,
    CapturedModelSlot,
    CorrelationRole,
    EffectBindingExpectation,
    EffectDirectionTag,
    EffectSourceQuality,
    EffectStorageClass,
    EffectTransportExpectation,
    ModelSelectionState,
    UnassignableInterfaceCapture,
    effect_content_digest,
    effect_row_digest,
)
from .configured_profile_contracts import (
    CapturedConfiguredProfile,
    ConfiguredProfileDecodeResult,
    DefaultModelState,
    ProfileAdmissionStatus,
)
from .span_geometry import (
    ByteSpan,
    StorageObjectId,
    StorageObjectKind,
    StorageScopeId,
    StorageScopeKind,
)


AUTHORITY_PROFILE_REVISION = 1
PROGRAM_STORAGE_AUTHORITY_REVISION = 1
STORAGE_ADMISSION_BASIS_REVISION = 1

_CAPTURE_PROVENANCE_DOMAIN = "tdo-v2-call-effect-capture-provenance-v1"
_CALL_AUTHORITY_DOMAIN = "tdo-v2-call-effect-authority-v4"
_AUTHORITY_PROFILE_DOMAIN = "tdo-v2-call-interface-authority-profile-v1"
_PROGRAM_STORAGE_AUTHORITY_DOMAIN = "tdo-v2-call-storage-program-authority-v1"
_DECLARED_PIECE_DOMAIN = "tdo-v2-call-effect-declared-piece-v1"
_STORAGE_ADMISSION_BASIS_DOMAIN = "tdo-v2-call-storage-admission-basis-v1"
_STORAGE_AUTHORITY_DOMAIN = "tdo-v2-call-storage-authority-v1"
_STORAGE_PERMIT_PAYLOAD_DOMAIN = "tdo-v2-call-storage-permit-payload-v1"
_U64_LIMIT = 1 << 64


class RegisterSpaceState(StrEnum):
    ABSENT = "ABSENT"
    UNIQUE = "UNIQUE"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class RegisterSpaceAuthority:
    state: RegisterSpaceState
    row: AddressSpaceEvidence | None = None

    def __post_init__(self) -> None:
        _require_exact(self.state, RegisterSpaceState, "register-space state")
        if self.state is RegisterSpaceState.UNIQUE:
            _require_exact(self.row, AddressSpaceEvidence, "unique register-space row")
            assert self.row is not None
            if not _is_register_space(self.row):
                raise ValueError("unique register-space row is not classified REGISTER")
        elif self.row is not None:
            raise ValueError("non-unique register-space authority cannot retain a row")

    def canonical_bytes(self) -> bytes:
        if self.state is not RegisterSpaceState.UNIQUE:
            return _text(self.state.value)
        assert self.row is not None
        return _text(self.state.value) + _address_space_v2(self.row)


class _SealedLifecycle:
    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("live authority state is immutable outside its owner")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("live authority state is immutable outside its owner")


@dataclass(frozen=True, order=True, slots=True)
class DeclaredPieceRef:
    direction: CallEffectDirection
    slot_ordinal: int
    piece_ordinal: int
    declared_piece_digest: bytes

    def __post_init__(self) -> None:
        _require_exact(self.direction, CallEffectDirection, "declared-piece direction")
        _require_u64(self.slot_ordinal, "declared-piece slot ordinal")
        _require_u64(self.piece_ordinal, "declared-piece ordinal")
        _require_digest(self.declared_piece_digest, "declared-piece digest")

    @property
    def identity_key(self) -> tuple[int, int, int]:
        return (
            _direction_rank(self.direction),
            self.slot_ordinal,
            self.piece_ordinal,
        )

    @property
    def canonical_key(self) -> tuple[int, int, int, bytes]:
        return (
            *self.identity_key,
            self.declared_piece_digest,
        )

    def wire_bytes(self) -> bytes:
        return (
            _text(_wire_direction(self.direction).value)
            + _u64(self.slot_ordinal)
            + _u64(self.piece_ordinal)
            + _bytes(self.declared_piece_digest)
        )

    def semantic_bytes(self) -> bytes:
        return (
            _text(self.direction.value)
            + _u64(self.slot_ordinal)
            + _u64(self.piece_ordinal)
            + _bytes(self.declared_piece_digest)
        )


@dataclass(frozen=True, slots=True, init=False)
class ValidatedCallStorageSpan:
    span: ByteSpan
    storage_admission_basis_digest: bytes
    storage_authority_digest: bytes

    @classmethod
    def _create(
        cls,
        authority: object,
        span: ByteSpan,
        storage_admission_basis_digest: bytes,
        storage_authority_digest: bytes,
    ) -> "ValidatedCallStorageSpan":
        if authority is not _VALIDATED_SPAN_AUTHORITY:
            raise PermissionError("validated call-storage spans are session-owned")
        value = object.__new__(cls)
        object.__setattr__(value, "span", span)
        object.__setattr__(
            value,
            "storage_admission_basis_digest",
            storage_admission_basis_digest,
        )
        object.__setattr__(value, "storage_authority_digest", storage_authority_digest)
        value._validate()
        return value

    def _validate(self) -> None:
        _require_exact(self.span, ByteSpan, "validated call-storage span")
        _require_digest(
            self.storage_admission_basis_digest,
            "storage-admission-basis digest",
        )
        _require_digest(self.storage_authority_digest, "storage-authority digest")

    def canonical_bytes(self) -> bytes:
        self._validate()
        return (
            _span(self.span)
            + _bytes(self.storage_admission_basis_digest)
            + _bytes(self.storage_authority_digest)
        )

    def __reduce_ex__(self, protocol: int):
        raise TypeError("validated call-storage spans cannot be serialized")


@dataclass(frozen=True, slots=True, init=False)
class AdmittedDeclaredPiece:
    ref: DeclaredPieceRef
    validated_span: ValidatedCallStorageSpan

    @classmethod
    def _create(
        cls,
        ref: DeclaredPieceRef,
        validated_span: ValidatedCallStorageSpan,
        permit: "_CallStoragePermit",
    ) -> "AdmittedDeclaredPiece":
        _require_exact(ref, DeclaredPieceRef, "admitted declared-piece ref")
        _require_exact(
            validated_span,
            ValidatedCallStorageSpan,
            "admitted validated span",
        )
        payload = call_storage_permit_payload_digest(
            ref,
            validated_span.span,
            permit.call_authority_digest,
            permit.program_storage_authority_digest,
            validated_span.storage_admission_basis_digest,
            validated_span.storage_authority_digest,
        )
        permit.consume(payload)
        value = object.__new__(cls)
        object.__setattr__(value, "ref", ref)
        object.__setattr__(value, "validated_span", validated_span)
        return value

    def canonical_bytes(self) -> bytes:
        return self.ref.semantic_bytes() + self.validated_span.canonical_bytes()

    def __reduce_ex__(self, protocol: int):
        raise TypeError("admitted declared pieces cannot be serialized")


class ConfiguredProfileAdmissionReceipt(_SealedLifecycle):
    __slots__ = ("_active", "profile")

    def __init__(
        self,
        authority: object,
        result: ConfiguredProfileDecodeResult,
    ) -> None:
        if authority is not _PROFILE_RECEIPT_AUTHORITY:
            raise PermissionError("profile admission receipts are decoder-owned")
        _require_exact(result, ConfiguredProfileDecodeResult, "profile decode result")
        if result.status is not ProfileAdmissionStatus.ADMITTED:
            raise ValueError("only an admitted profile can mint a receipt")
        if result.profile.semantic_content_digest != result.profile.expected_content_digest:
            raise ValueError("profile receipt requires a verified content digest")
        object.__setattr__(self, "profile", result.profile)
        object.__setattr__(self, "_active", True)

    def require_active(self) -> None:
        if self._active is not True:
            raise RuntimeError("profile admission receipt is inactive")

    def revoke(self) -> None:
        object.__setattr__(self, "_active", False)

    def __reduce_ex__(self, protocol: int):
        raise TypeError("profile admission receipts cannot be serialized")


class ConfiguredEffectCaptureReceipt(_SealedLifecycle):
    __slots__ = (
        "_active",
        "binding",
        "occurrences",
        "profile_receipt",
        "seeds",
        "sidecar",
        "transport",
    )

    def __init__(
        self,
        authority: object,
        sidecar: CapturedEffectSidecar,
        transport: EffectTransportExpectation,
        binding: EffectBindingExpectation,
        profile_receipt: ConfiguredProfileAdmissionReceipt,
        seeds: FunctionCallSeedUnit,
    ) -> None:
        if authority is not _CAPTURE_RECEIPT_AUTHORITY:
            raise PermissionError("effect capture receipts are decoder-owned")
        _require_exact(sidecar, CapturedEffectSidecar, "effect sidecar")
        _require_exact(transport, EffectTransportExpectation, "effect transport")
        _require_exact(binding, EffectBindingExpectation, "effect binding")
        _require_exact(
            profile_receipt,
            ConfiguredProfileAdmissionReceipt,
            "effect profile receipt",
        )
        _require_exact(seeds, FunctionCallSeedUnit, "effect call seeds")
        profile_receipt.require_active()
        occurrences = _validate_effect_capture_inputs(
            sidecar,
            transport,
            binding,
            profile_receipt.profile,
            seeds,
        )
        object.__setattr__(self, "sidecar", sidecar)
        object.__setattr__(self, "transport", transport)
        object.__setattr__(self, "binding", binding)
        object.__setattr__(self, "profile_receipt", profile_receipt)
        object.__setattr__(self, "seeds", seeds)
        object.__setattr__(self, "occurrences", occurrences)
        object.__setattr__(self, "_active", True)

    @property
    def capture_provenance_digest(self) -> bytes:
        self.require_active()
        return call_capture_provenance_digest(self.sidecar.exporter_source_sha256)

    def require_active(self) -> None:
        if self._active is not True:
            raise RuntimeError("effect capture receipt is inactive")

    def revoke(self) -> None:
        object.__setattr__(self, "_active", False)

    def __reduce_ex__(self, protocol: int):
        raise TypeError("effect capture receipts cannot be serialized")


class ConfiguredCallStorageAuthoritySnapshot(_SealedLifecycle):
    __slots__ = (
        "_active",
        "committed_runs",
        "evidence",
        "program_scope",
        "program_storage_authority_digest",
        "register_space",
    )

    def __init__(
        self,
        authority: object,
        program_scope: StorageScopeId,
        evidence: VerifiedProgramSnapshotEvidence,
        committed_runs: tuple[CommittedMemoryRun, ...],
        register_space: RegisterSpaceAuthority,
        digest: bytes,
    ) -> None:
        if authority is not _SNAPSHOT_AUTHORITY:
            raise PermissionError("call-storage snapshots are session-owned")
        object.__setattr__(self, "program_scope", program_scope)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "committed_runs", committed_runs)
        object.__setattr__(self, "register_space", register_space)
        object.__setattr__(self, "program_storage_authority_digest", digest)
        object.__setattr__(self, "_active", True)

    def require_active(self) -> None:
        if self._active is not True:
            raise RuntimeError("call-storage authority snapshot is inactive")

    def close(self) -> None:
        object.__setattr__(self, "_active", False)

    def __reduce_ex__(self, protocol: int):
        raise TypeError("call-storage authority snapshots cannot be serialized")


class _CallStoragePermit(_SealedLifecycle):
    __slots__ = (
        "_active",
        "_capture_receipt",
        "_evidence",
        "_payload_digest",
        "_profile_receipt",
        "_program_scope",
        "_snapshot",
        "call_authority_digest",
        "program_storage_authority_digest",
    )

    def __init__(
        self,
        authority: object,
        payload_digest: bytes,
        call_authority_digest: bytes,
        snapshot: ConfiguredCallStorageAuthoritySnapshot,
        profile_receipt: ConfiguredProfileAdmissionReceipt,
        capture_receipt: ConfiguredEffectCaptureReceipt,
    ) -> None:
        if authority is not _STORAGE_PERMIT_AUTHORITY:
            raise PermissionError("call-storage permits are session-owned")
        _require_digest(payload_digest, "call-storage permit payload")
        _require_digest(call_authority_digest, "permit call-authority digest")
        snapshot.require_active()
        profile_receipt.require_active()
        capture_receipt.require_active()
        object.__setattr__(self, "_payload_digest", payload_digest)
        object.__setattr__(self, "call_authority_digest", call_authority_digest)
        object.__setattr__(self, "program_storage_authority_digest", (
            snapshot.program_storage_authority_digest
        ))
        object.__setattr__(self, "_snapshot", snapshot)
        object.__setattr__(self, "_program_scope", snapshot.program_scope)
        object.__setattr__(self, "_evidence", snapshot.evidence)
        object.__setattr__(self, "_profile_receipt", profile_receipt)
        object.__setattr__(self, "_capture_receipt", capture_receipt)
        object.__setattr__(self, "_active", True)

    def consume(self, payload_digest: bytes) -> None:
        if self._active is not True:
            raise RuntimeError("call-storage permit is inactive")
        self._snapshot.require_active()
        self._profile_receipt.require_active()
        self._capture_receipt.require_active()
        if (
            self._snapshot.program_scope is not self._program_scope
            or self._snapshot.evidence is not self._evidence
        ):
            raise PermissionError("call-storage permit authority identity changed")
        _require_digest(payload_digest, "call-storage construction payload")
        if payload_digest != self._payload_digest:
            raise PermissionError("call-storage permit is bound to other evidence")
        object.__setattr__(self, "_active", False)

    def __reduce_ex__(self, protocol: int):
        raise TypeError("call-storage permits cannot be serialized")


class ConfiguredCallAuthoritySession(_SealedLifecycle):
    __slots__ = (
        "_active",
        "_admitted_pieces",
        "authority_profile_digest",
        "capture_receipt",
        "profile_receipt",
        "seeds",
        "snapshot",
    )

    def __init__(
        self,
        authority: object,
        snapshot: ConfiguredCallStorageAuthoritySnapshot,
        profile_receipt: ConfiguredProfileAdmissionReceipt,
        capture_receipt: ConfiguredEffectCaptureReceipt,
        seeds: FunctionCallSeedUnit,
        authority_profile: bytes,
    ) -> None:
        if authority is not _SESSION_AUTHORITY:
            raise PermissionError("configured-call authority sessions are architect-owned")
        object.__setattr__(self, "snapshot", snapshot)
        object.__setattr__(self, "profile_receipt", profile_receipt)
        object.__setattr__(self, "capture_receipt", capture_receipt)
        object.__setattr__(self, "seeds", seeds)
        object.__setattr__(self, "authority_profile_digest", authority_profile)
        object.__setattr__(self, "_admitted_pieces", {})
        object.__setattr__(self, "_active", True)

    def require_active(self) -> None:
        if self._active is not True:
            raise RuntimeError("configured-call authority session is inactive")
        self.snapshot.require_active()
        self.profile_receipt.require_active()
        self.capture_receipt.require_active()

    def call_authority_digest(
        self,
        occurrence: CallOccurrenceId,
        row: CapturedEffectRow,
    ) -> bytes:
        self._validate_call_context(occurrence, row)
        return call_authority_digest(
            occurrence.occurrence_digest,
            row.row_digest,
            self.capture_receipt.sidecar.profile_semantic_content_digest,
            self.authority_profile_digest,
            self.capture_receipt.capture_provenance_digest,
        )

    def admit_piece(
        self,
        occurrence: CallOccurrenceId,
        row: CapturedEffectRow,
        direction: EffectDirectionTag,
        slot_ordinal: int,
        piece_ordinal: int,
    ) -> AdmittedDeclaredPiece | None:
        self._validate_call_context(occurrence, row)
        slot, piece = _locate_piece(row, direction, slot_ordinal, piece_ordinal)
        ref = declared_piece_ref(
            occurrence.occurrence_digest,
            row.row_digest,
            direction,
            slot_ordinal,
            piece_ordinal,
            piece,
        )
        if not self._piece_semantics_admissible(row, direction, slot):
            return None
        mapped = _map_piece(self.snapshot, piece)
        if mapped is None:
            return None
        admitted = self._admitted_pieces.get(ref)
        if admitted is not None:
            return admitted
        span, authority_extents = mapped
        call_authority = self.call_authority_digest(
            occurrence,
            row,
        )
        basis = storage_admission_basis_digest(
            self.snapshot.program_storage_authority_digest,
            span,
            authority_extents,
        )
        storage_authority = storage_authority_digest(
            self.snapshot.program_scope.digest,
            self.snapshot.program_storage_authority_digest,
            call_authority,
            ref.declared_piece_digest,
            span,
            basis,
        )
        validated = ValidatedCallStorageSpan._create(
            _VALIDATED_SPAN_AUTHORITY,
            span,
            basis,
            storage_authority,
        )
        payload = call_storage_permit_payload_digest(
            ref,
            span,
            call_authority,
            self.snapshot.program_storage_authority_digest,
            basis,
            storage_authority,
        )
        permit = _CallStoragePermit(
            _STORAGE_PERMIT_AUTHORITY,
            payload,
            call_authority,
            self.snapshot,
            self.profile_receipt,
            self.capture_receipt,
        )
        admitted = AdmittedDeclaredPiece._create(ref, validated, permit)
        self._admitted_pieces[ref] = admitted
        return admitted

    def _validate_call_context(
        self,
        occurrence: CallOccurrenceId,
        row: CapturedEffectRow,
    ) -> None:
        self.require_active()
        _require_exact(occurrence, CallOccurrenceId, "authority call occurrence")
        _require_exact(row, CapturedEffectRow, "authority call row")
        pairs = zip(
            self.capture_receipt.occurrences,
            self.capture_receipt.sidecar.rows,
            strict=True,
        )
        if not any(
            retained_occurrence is occurrence and retained_row is row
            for retained_occurrence, retained_row in pairs
        ):
            raise PermissionError("call occurrence and effect row are not an owned pair")

    def _piece_semantics_admissible(
        self,
        row: CapturedEffectRow,
        direction: EffectDirectionTag,
        slot: CapturedModelSlot,
    ) -> bool:
        capture = row.interface_capture
        if type(capture) is not AssignmentInterfaceCapture:
            return False
        if not _selected_model_is_authorized(self.profile_receipt.profile, capture):
            return False
        if _quality_rank(capture.signature.signature_source_quality) < 1:
            return False
        if not _slot_quality_admitted(capture, slot):
            return False
        if (
            direction is EffectDirectionTag.POST_WRITE
            and slot.correlation.role is CorrelationRole.RESULT
            and slot.is_indirect
        ):
            return False
        return True

    def close(self) -> None:
        if self._active:
            object.__setattr__(self, "_active", False)
            self._admitted_pieces.clear()
            self.snapshot.close()
            self.capture_receipt.revoke()

    def __enter__(self) -> "ConfiguredCallAuthoritySession":
        self.require_active()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __reduce_ex__(self, protocol: int):
        raise TypeError("configured-call authority sessions cannot be serialized")


_PROFILE_RECEIPT_AUTHORITY = object()
_CAPTURE_RECEIPT_AUTHORITY = object()
_SNAPSHOT_AUTHORITY = object()
_STORAGE_PERMIT_AUTHORITY = object()
_VALIDATED_SPAN_AUTHORITY = object()
_SESSION_AUTHORITY = object()


def _mint_profile_admission_receipt(
    result: ConfiguredProfileDecodeResult,
) -> ConfiguredProfileAdmissionReceipt:
    return ConfiguredProfileAdmissionReceipt(_PROFILE_RECEIPT_AUTHORITY, result)


def _validate_effect_capture_inputs(
    sidecar: CapturedEffectSidecar,
    transport: EffectTransportExpectation,
    binding: EffectBindingExpectation,
    profile: CapturedConfiguredProfile,
    seeds: FunctionCallSeedUnit,
) -> tuple[CallOccurrenceId, ...]:
    """Revalidate immutable sibling evidence before profile authority is minted."""

    _require_exact(sidecar, CapturedEffectSidecar, "effect sidecar")
    _require_exact(transport, EffectTransportExpectation, "effect transport")
    _require_exact(binding, EffectBindingExpectation, "effect binding")
    _require_exact(profile, CapturedConfiguredProfile, "configured profile")
    _require_exact(seeds, FunctionCallSeedUnit, "effect call seeds")
    if binding.exporter_source_sha256 != sidecar.exporter_source_sha256:
        raise ValueError("effect binding and sidecar exporter digests disagree")
    occurrences = tuple(seed.occurrence for seed in seeds.callsites)
    _validate_occurrence_inventory(sidecar.rows, occurrences)
    for row in sidecar.rows:
        expected_row_digest = effect_row_digest(
            row.instruction,
            row.operation_ordinal,
            row.opcode,
            row.selector,
            row.override_evidence,
            row.interface_capture,
        )
        if row.row_digest != expected_row_digest:
            raise ValueError("effect row digest does not match its fields")
    if sidecar.profile_semantic_content_digest != profile.semantic_content_digest:
        raise ValueError("effect sidecar cites another configured profile")
    expected_content_digest = effect_content_digest(
        sidecar.exporter_source_sha256,
        sidecar.profile_semantic_content_digest,
        sidecar.rows,
    )
    if sidecar.semantic_content_digest != expected_content_digest:
        raise ValueError("effect content digest does not match its rows")
    if transport.function_entry != seeds.function_entry:
        raise ValueError("effect transport cites another function entry")
    for row in sidecar.rows:
        capture = row.interface_capture
        if (
            type(capture) is AssignmentInterfaceCapture
            and not _selected_model_is_authorized(profile, capture)
        ):
            raise ValueError("assignment capture cites an unauthorized selected model")
    return occurrences


def _mint_effect_capture_receipt(
    sidecar: CapturedEffectSidecar,
    transport: EffectTransportExpectation,
    binding: EffectBindingExpectation,
    profile_receipt: ConfiguredProfileAdmissionReceipt,
    seeds: FunctionCallSeedUnit,
) -> ConfiguredEffectCaptureReceipt:
    return ConfiguredEffectCaptureReceipt(
        _CAPTURE_RECEIPT_AUTHORITY,
        sidecar,
        transport,
        binding,
        profile_receipt,
        seeds,
    )


def _open_configured_call_authority_session(
    program: ConstructedProgramScope,
    seeds: FunctionCallSeedUnit,
    profile_receipt: ConfiguredProfileAdmissionReceipt,
    capture_receipt: ConfiguredEffectCaptureReceipt,
) -> ConfiguredCallAuthoritySession:
    _require_exact(program, ConstructedProgramScope, "constructed program scope")
    _require_exact(seeds, FunctionCallSeedUnit, "configured call seeds")
    _require_exact(
        profile_receipt,
        ConfiguredProfileAdmissionReceipt,
        "profile admission receipt",
    )
    _require_exact(
        capture_receipt,
        ConfiguredEffectCaptureReceipt,
        "effect capture receipt",
    )
    profile_receipt.require_active()
    capture_receipt.require_active()
    if capture_receipt.profile_receipt is not profile_receipt:
        raise PermissionError("effect capture does not retain this profile receipt")
    if capture_receipt.seeds is not seeds:
        raise PermissionError("effect capture does not retain these call seeds")
    if seeds.program_scope is not program.scope:
        raise PermissionError("call seeds do not retain the exact program scope")
    committed_runs = program._retained_committed_runs()
    if committed_runs is None:
        raise ValueError("constructed program lacks retained committed-memory authority")
    evidence = program.evidence
    if evidence.address_space_classification_revision != 2:
        raise ValueError("configured storage authority requires address-space revision 2")
    _validate_program_binding(profile_receipt.profile, evidence)
    _validate_committed_runs(evidence, committed_runs)
    _validate_captured_piece_spaces(evidence, capture_receipt.sidecar)
    register_space = _register_space_authority(evidence.address_spaces)
    storage_digest = program_storage_authority_digest(
        program.scope.digest,
        evidence,
        register_space,
        committed_runs,
    )
    snapshot = ConfiguredCallStorageAuthoritySnapshot(
        _SNAPSHOT_AUTHORITY,
        program.scope,
        evidence,
        committed_runs,
        register_space,
        storage_digest,
    )
    try:
        profile_digest = authority_profile_digest(
            program.scope.digest,
            profile_receipt.profile,
        )
        return ConfiguredCallAuthoritySession(
            _SESSION_AUTHORITY,
            snapshot,
            profile_receipt,
            capture_receipt,
            seeds,
            profile_digest,
        )
    except BaseException:
        snapshot.close()
        raise


def _validate_occurrence_inventory(
    rows: tuple[CapturedEffectRow, ...],
    occurrences: tuple[CallOccurrenceId, ...],
) -> None:
    if len(rows) != len(occurrences):
        raise ValueError("effect rows do not exactly cover call occurrences")
    for row, occurrence in zip(rows, occurrences, strict=True):
        if (
            row.instruction != occurrence.instruction
            or row.operation_ordinal != occurrence.operation_ordinal
            or row.opcode.value != occurrence.opcode
            or not _selector_matches(row.selector, occurrence.selector)
        ):
            raise ValueError("effect row order or identity disagrees with call occurrences")


def _selector_matches(
    captured: CapturedEffectSelector | None,
    retained: object,
) -> bool:
    if captured is None or retained is None:
        return captured is retained
    return (
        captured.kind is retained.kind
        and captured.coordinate == retained.coordinate
        and captured.byte_size == retained.byte_size
    )


def call_capture_provenance_digest(exporter_source_sha256: bytes) -> bytes:
    _require_digest(exporter_source_sha256, "effect exporter source SHA-256")
    return _digest(
        _text(_CAPTURE_PROVENANCE_DOMAIN)
        + _text(CALL_EFFECT_SCHEMA_ID)
        + _u64(CALL_EFFECT_SCHEMA_VERSION)
        + _u64(CALL_EFFECT_EXPORTER_REVISION)
        + _bytes(exporter_source_sha256)
        + _text(CALL_EFFECT_GHIDRA_VERSION)
    )


def call_authority_digest(
    occurrence_digest: bytes,
    row_digest: bytes,
    profile_semantic_content_digest: bytes,
    authority_profile_digest_value: bytes,
    capture_provenance_digest: bytes,
) -> bytes:
    for value, label in (
        (occurrence_digest, "occurrence digest"),
        (row_digest, "effect row digest"),
        (profile_semantic_content_digest, "profile semantic-content digest"),
        (authority_profile_digest_value, "authority-profile digest"),
        (capture_provenance_digest, "capture-provenance digest"),
    ):
        _require_digest(value, label)
    return _digest(
        _text(_CALL_AUTHORITY_DOMAIN)
        + _bytes(occurrence_digest)
        + _bytes(row_digest)
        + _bytes(profile_semantic_content_digest)
        + _bytes(authority_profile_digest_value)
        + _bytes(capture_provenance_digest)
    )


def authority_profile_digest(
    program_scope_digest: bytes,
    profile: CapturedConfiguredProfile,
) -> bytes:
    _require_digest(program_scope_digest, "program scope digest")
    _require_exact(profile, CapturedConfiguredProfile, "configured profile")
    namespace = profile.language
    return _digest(
        _text(_AUTHORITY_PROFILE_DOMAIN)
        + _u64(AUTHORITY_PROFILE_REVISION)
        + _bytes(profile.semantic_content_digest)
        + _bytes(program_scope_digest)
        + _text(profile.authority_mode.value)
        + _bytes(profile.loader.executable_sha256)
        + _text(namespace.language_id)
        + _u64(namespace.major_version)
        + _u64(namespace.minor_version)
    )


def program_storage_authority_digest(
    program_scope_digest: bytes,
    evidence: VerifiedProgramSnapshotEvidence,
    register_space: RegisterSpaceAuthority,
    committed_runs: tuple[CommittedMemoryRun, ...],
) -> bytes:
    _require_digest(program_scope_digest, "program scope digest")
    _require_exact(evidence, VerifiedProgramSnapshotEvidence, "program evidence")
    _require_exact(register_space, RegisterSpaceAuthority, "register-space authority")
    _require_exact_tuple(committed_runs, CommittedMemoryRun, "committed memory runs")
    if evidence.address_space_classification_revision != 2:
        raise ValueError("program storage authority requires revision-2 spaces")
    return _digest(
        _text(_PROGRAM_STORAGE_AUTHORITY_DOMAIN)
        + _u64(PROGRAM_STORAGE_AUTHORITY_REVISION)
        + _bytes(program_scope_digest)
        + _bytes(evidence.executable_sha256)
        + _bytes(evidence.loaded_memory_digest)
        + _u64(evidence.address_space_classification_revision)
        + _seq(tuple(_address_space_v2(row) for row in evidence.address_spaces))
        + register_space.canonical_bytes()
        + _seq(tuple(_committed_run_extent(run) for run in committed_runs))
    )


def declared_piece_digest(
    row_digest: bytes,
    occurrence_digest: bytes,
    direction: EffectDirectionTag,
    slot_ordinal: int,
    piece_ordinal: int,
    piece: CapturedEffectPiece,
) -> bytes:
    _require_digest(row_digest, "effect row digest")
    _require_digest(occurrence_digest, "occurrence digest")
    _require_exact(direction, EffectDirectionTag, "wire effect direction")
    _require_u64(slot_ordinal, "declared-piece slot ordinal")
    _require_u64(piece_ordinal, "declared-piece ordinal")
    _require_exact(piece, CapturedEffectPiece, "captured effect piece")
    if piece.piece_ordinal != piece_ordinal:
        raise ValueError("declared-piece ordinal disagrees with captured piece")
    return _digest(
        _text(_DECLARED_PIECE_DOMAIN)
        + _bytes(row_digest)
        + _bytes(occurrence_digest)
        + _text(direction.value)
        + _u64(slot_ordinal)
        + _u64(piece_ordinal)
        + piece.canonical_bytes()
    )


def declared_piece_ref(
    occurrence_digest: bytes,
    row_digest: bytes,
    direction: EffectDirectionTag,
    slot_ordinal: int,
    piece_ordinal: int,
    piece: CapturedEffectPiece,
) -> DeclaredPieceRef:
    return DeclaredPieceRef(
        _semantic_direction(direction),
        slot_ordinal,
        piece_ordinal,
        declared_piece_digest(
            row_digest,
            occurrence_digest,
            direction,
            slot_ordinal,
            piece_ordinal,
            piece,
        ),
    )


def storage_admission_basis_digest(
    program_storage_authority_digest_value: bytes,
    span: ByteSpan,
    authority_extents: tuple[bytes, ...],
) -> bytes:
    _require_digest(
        program_storage_authority_digest_value,
        "program-storage-authority digest",
    )
    _require_exact(span, ByteSpan, "storage-admission span")
    if type(authority_extents) is not tuple or any(
        type(item) is not bytes for item in authority_extents
    ):
        raise TypeError("authority extents must be an exact bytes tuple")
    if not authority_extents:
        raise ValueError("storage admission requires at least one authority extent")
    return _digest(
        _text(_STORAGE_ADMISSION_BASIS_DOMAIN)
        + _u64(STORAGE_ADMISSION_BASIS_REVISION)
        + _bytes(program_storage_authority_digest_value)
        + _span(span)
        + _seq(authority_extents)
    )


def storage_authority_digest(
    program_scope_digest: bytes,
    program_storage_authority_digest_value: bytes,
    call_authority_digest_value: bytes,
    declared_piece_digest_value: bytes,
    span: ByteSpan,
    storage_admission_basis_digest_value: bytes,
) -> bytes:
    for value, label in (
        (program_scope_digest, "program scope digest"),
        (program_storage_authority_digest_value, "program-storage-authority digest"),
        (call_authority_digest_value, "call-authority digest"),
        (declared_piece_digest_value, "declared-piece digest"),
        (storage_admission_basis_digest_value, "storage-admission-basis digest"),
    ):
        _require_digest(value, label)
    _require_exact(span, ByteSpan, "storage-authority span")
    return _digest(
        _text(_STORAGE_AUTHORITY_DOMAIN)
        + _bytes(program_scope_digest)
        + _bytes(program_storage_authority_digest_value)
        + _bytes(call_authority_digest_value)
        + _bytes(declared_piece_digest_value)
        + _span(span)
        + _bytes(storage_admission_basis_digest_value)
    )


def call_storage_permit_payload_digest(
    ref: DeclaredPieceRef,
    span: ByteSpan,
    call_authority_digest_value: bytes,
    program_storage_authority_digest_value: bytes,
    storage_admission_basis_digest_value: bytes,
    storage_authority_digest_value: bytes,
) -> bytes:
    _require_exact(ref, DeclaredPieceRef, "permit declared-piece ref")
    _require_exact(span, ByteSpan, "permit span")
    for value, label in (
        (call_authority_digest_value, "call-authority digest"),
        (program_storage_authority_digest_value, "program-storage-authority digest"),
        (storage_admission_basis_digest_value, "storage-admission-basis digest"),
        (storage_authority_digest_value, "storage-authority digest"),
    ):
        _require_digest(value, label)
    return _digest(
        _text(_STORAGE_PERMIT_PAYLOAD_DOMAIN)
        + ref.semantic_bytes()
        + _span(span)
        + _bytes(call_authority_digest_value)
        + _bytes(program_storage_authority_digest_value)
        + _bytes(storage_admission_basis_digest_value)
        + _bytes(storage_authority_digest_value)
    )


def _locate_piece(
    row: CapturedEffectRow,
    direction: EffectDirectionTag,
    slot_ordinal: int,
    piece_ordinal: int,
) -> tuple[CapturedModelSlot, CapturedEffectPiece]:
    _require_exact(direction, EffectDirectionTag, "piece direction")
    _require_u64(slot_ordinal, "piece slot ordinal")
    _require_u64(piece_ordinal, "piece ordinal")
    capture = row.interface_capture
    if type(capture) is not AssignmentInterfaceCapture:
        raise ValueError("only assignment capture has declared pieces")
    direction_row = capture.directions[0 if direction is EffectDirectionTag.PRE_READ else 1]
    if slot_ordinal >= len(direction_row.slots):
        raise ValueError("piece slot ordinal is outside its direction")
    slot = direction_row.slots[slot_ordinal]
    if piece_ordinal >= len(slot.assignment.pieces):
        raise ValueError("piece ordinal is outside its assignment")
    return slot, slot.assignment.pieces[piece_ordinal]


def _selected_model_is_authorized(
    profile: CapturedConfiguredProfile,
    capture: AssignmentInterfaceCapture,
) -> bool:
    selection = capture.model_selection
    matches = tuple(
        row
        for row in profile.rows
        if row.inventory_ordinal == selection.profile_model_ordinal
        and row.model_digest == selection.profile_model_identity_digest
    )
    if len(matches) != 1:
        return False
    row = matches[0]
    if not row.eligible:
        return False
    if selection.state is ModelSelectionState.EXPLICIT_REFERENCE:
        return row.allow_explicit
    default = profile.default_model
    return (
        default.state is DefaultModelState.PRESENT
        and default.inventory_ordinal == row.inventory_ordinal
        and default.model_digest == row.model_digest
        and row.allow_program_default
    )


def _slot_quality_admitted(
    capture: AssignmentInterfaceCapture,
    slot: CapturedModelSlot,
) -> bool:
    role = slot.correlation.role
    if role is CorrelationRole.THIS:
        return True
    if role is CorrelationRole.FIXED:
        assert slot.correlation.formal_ordinal is not None
        quality = capture.signature.fixed_formals[
            slot.correlation.formal_ordinal
        ].symbol_source_quality
    else:
        quality = capture.signature.result.symbol_source_quality
    return _quality_rank(quality) >= 1


def _map_piece(
    snapshot: ConfiguredCallStorageAuthoritySnapshot,
    piece: CapturedEffectPiece,
) -> tuple[ByteSpan, tuple[bytes, ...]] | None:
    snapshot.require_active()
    scope = snapshot.program_scope
    if piece.storage_class is EffectStorageClass.REGISTER:
        classified = tuple(
            row
            for row in snapshot.evidence.address_spaces
            if row.space_id == piece.space_id
        )
        if len(classified) != 1 or not _is_register_space(classified[0]):
            raise ValueError(
                "REGISTER piece contradicts retained address-space classification"
            )
        register = snapshot.register_space
        if register.state is not RegisterSpaceState.UNIQUE:
            return None
        assert register.row is not None
        if register.row is not classified[0] or not _extent_fits_space(
            register.row,
            piece.byte_offset,
            piece.byte_size,
        ):
            return None
        span = ByteSpan(
            StorageObjectId(StorageObjectKind.REGISTER_FILE, scope, 0),
            piece.byte_offset,
            piece.byte_size,
        )
        return span, (_register_space_extent(register.row),)
    if piece.storage_class is not EffectStorageClass.ADDRESS:
        return None
    rows = tuple(
        row for row in snapshot.evidence.address_spaces if row.space_id == piece.space_id
    )
    if len(rows) != 1 or not _is_address_space(rows[0]):
        raise ValueError(
            "ADDRESS piece contradicts retained address-space classification"
        )
    if not _extent_fits_space(
        rows[0],
        piece.byte_offset,
        piece.byte_size,
    ):
        return None
    end = piece.byte_offset + piece.byte_size
    matching = {
        (run.space_id, run.byte_start, run.byte_size, run.is_initialized): run
        for run in snapshot.committed_runs
        if run.space_id == piece.space_id
        and run.byte_start <= piece.byte_offset
        and end <= run.byte_end
    }
    if not matching:
        return None
    runs = tuple(matching[key] for key in sorted(matching))
    if len({run.is_initialized for run in runs}) != 1:
        return None
    span = ByteSpan(
        StorageObjectId(StorageObjectKind.ADDRESS_SPACE, scope, piece.space_id),
        piece.byte_offset,
        piece.byte_size,
    )
    return span, tuple(_committed_run_extent(run) for run in runs)


def _validate_program_binding(
    profile: CapturedConfiguredProfile,
    evidence: VerifiedProgramSnapshotEvidence,
) -> None:
    if profile.loader.executable_sha256 != evidence.executable_sha256:
        raise ValueError("profile executable does not match program evidence")
    namespace = evidence.translation_namespace
    language = profile.language
    if (
        language.language_id != namespace.language_id
        or language.major_version != namespace.major_version
        or language.minor_version != namespace.minor_version
    ):
        raise ValueError("profile language does not match program evidence")


def _validate_committed_runs(
    evidence: VerifiedProgramSnapshotEvidence,
    runs: tuple[CommittedMemoryRun, ...],
) -> None:
    keys = tuple(
        (run.space_id, run.byte_start, run.byte_size, run.is_initialized)
        for run in runs
    )
    if keys != tuple(sorted(keys)):
        raise ValueError("committed memory runs must be ordered")
    by_id = {row.space_id: row for row in evidence.address_spaces}
    for run in runs:
        row = by_id.get(run.space_id)
        if row is None or not _is_address_space(row) or not _extent_fits_space(
            row,
            run.byte_start,
            run.byte_size,
        ):
            raise ValueError("committed run is outside admitted memory space")


def _validate_captured_piece_spaces(
    evidence: VerifiedProgramSnapshotEvidence,
    sidecar: CapturedEffectSidecar,
) -> None:
    for row in sidecar.rows:
        capture = row.interface_capture
        assignments: list[CapturedAssignment] = []
        if type(capture) is AssignmentInterfaceCapture:
            assignments.extend(
                slot.assignment
                for direction in capture.directions
                for slot in direction.slots
            )
        elif (
            type(capture) is UnassignableInterfaceCapture
            and capture.custom_storage is not None
        ):
            assignments.append(capture.custom_storage.result.assignment)
            assignments.extend(
                parameter.assignment
                for parameter in capture.custom_storage.parameters
            )
        for assignment in assignments:
            for piece in assignment.pieces:
                _validate_piece_space_classification(evidence, piece)


def _validate_piece_space_classification(
    evidence: VerifiedProgramSnapshotEvidence,
    piece: CapturedEffectPiece,
) -> None:
    matches = tuple(
        row for row in evidence.address_spaces if row.space_id == piece.space_id
    )
    if len(matches) != 1:
        raise ValueError("effect piece does not resolve one retained address space")
    row = matches[0]
    classifiers = {
        EffectStorageClass.CONSTANT: _is_constant_space,
        EffectStorageClass.REGISTER: _is_register_space,
        EffectStorageClass.UNIQUE: _is_unique_space,
        EffectStorageClass.ADDRESS: _is_address_space,
    }
    classifier = classifiers.get(piece.storage_class, _is_opaque_space)
    if not classifier(row):
        raise ValueError(
            "effect piece contradicts retained address-space classification"
        )


def _register_space_authority(
    rows: tuple[AddressSpaceEvidence, ...],
) -> RegisterSpaceAuthority:
    matches = tuple(row for row in rows if _is_register_space(row))
    if not matches:
        return RegisterSpaceAuthority(RegisterSpaceState.ABSENT)
    if len(matches) == 1:
        return RegisterSpaceAuthority(RegisterSpaceState.UNIQUE, matches[0])
    return RegisterSpaceAuthority(RegisterSpaceState.AMBIGUOUS)


def _is_register_space(row: AddressSpaceEvidence) -> bool:
    return classify_address_space_v2(row) is AddressSpaceClassV2.REGISTER


def _is_constant_space(row: AddressSpaceEvidence) -> bool:
    return classify_address_space_v2(row) is AddressSpaceClassV2.CONSTANT


def _is_unique_space(row: AddressSpaceEvidence) -> bool:
    return classify_address_space_v2(row) is AddressSpaceClassV2.UNIQUE


def _is_address_space(row: AddressSpaceEvidence) -> bool:
    return classify_address_space_v2(row) is AddressSpaceClassV2.ADDRESS


def _is_opaque_space(row: AddressSpaceEvidence) -> bool:
    return classify_address_space_v2(row) is AddressSpaceClassV2.OPAQUE


def _extent_fits_space(
    row: AddressSpaceEvidence,
    start: int,
    size: int,
) -> bool:
    if type(start) is not int or type(size) is not int or start < 0 or size <= 0:
        return False
    end = start + size
    capacity = row.addressable_unit_bytes * (1 << row.address_size_bits)
    return end <= U64_LIMIT and end <= capacity


def _address_space_v2(value: AddressSpaceEvidence) -> bytes:
    _require_exact(value, AddressSpaceEvidence, "revision-2 address space")
    if value.classification_revision != 2:
        raise ValueError("address-space encoding requires revision 2")
    return (
        _u64(value.space_id)
        + _u64(value.address_size_bits)
        + _u64(value.addressable_unit_bytes)
        + _bool(value.has_signed_offset)
        + _bool(value.is_constant_space)
        + _bool(value.is_register_space)
        + _bool(value.is_unique_space)
        + _bool(value.is_memory_space)
        + _bool(value.is_loaded_memory_space)
        + _bool(value.is_non_loaded_memory_space)
        + _bool(value.is_overlay_space)
        + _bool(value.is_external_space)
    )


def _register_space_extent(row: AddressSpaceEvidence) -> bytes:
    return _text("REGISTER_SPACE") + _address_space_v2(row)


def _committed_run_extent(run: CommittedMemoryRun) -> bytes:
    _require_exact(run, CommittedMemoryRun, "committed authority run")
    return (
        _text("COMMITTED_RUN")
        + _u64(run.space_id)
        + _u64(run.byte_start)
        + _u64(run.byte_size)
        + _bool(run.is_initialized)
    )


def _span(value: ByteSpan) -> bytes:
    _require_exact(value, ByteSpan, "encoded configured span")
    rank = {
        StorageObjectKind.REGISTER_FILE: 0,
        StorageObjectKind.ADDRESS_SPACE: 1,
    }.get(value.object_id.kind)
    if rank is None or value.object_id.scope.kind is not StorageScopeKind.PROGRAM:
        raise ValueError("configured span must use admitted program storage")
    if value.end > _U64_LIMIT:
        raise ValueError("configured span exceeds unsigned 64-bit")
    return (
        _u64(rank)
        + _u64(0)
        + _bytes(value.object_id.scope.digest)
        + _u64(value.object_id.space_key)
        + _u64(value.start)
        + _u64(value.size)
    )


def _quality_rank(value: EffectSourceQuality) -> int:
    _require_exact(value, EffectSourceQuality, "effect source quality")
    return {
        EffectSourceQuality.DEFAULT: 0,
        EffectSourceQuality.ANALYSIS: 1,
        EffectSourceQuality.AI: 1,
        EffectSourceQuality.IMPORTED: 2,
        EffectSourceQuality.USER_DEFINED: 3,
    }[value]


def _semantic_direction(value: EffectDirectionTag) -> CallEffectDirection:
    _require_exact(value, EffectDirectionTag, "wire direction")
    return (
        CallEffectDirection.PRE_READ
        if value is EffectDirectionTag.PRE_READ
        else CallEffectDirection.POST_WRITE
    )


def _wire_direction(value: CallEffectDirection) -> EffectDirectionTag:
    _require_exact(value, CallEffectDirection, "semantic direction")
    return (
        EffectDirectionTag.PRE_READ
        if value is CallEffectDirection.PRE_READ
        else EffectDirectionTag.POST_WRITE
    )


def _direction_rank(value: CallEffectDirection) -> int:
    return 0 if value is CallEffectDirection.PRE_READ else 1


def _digest(value: bytes) -> bytes:
    if type(value) is not bytes:
        raise TypeError("digest preimage must be exact bytes")
    return sha256(value).digest()


def _bool(value: bool | None) -> bytes:
    if type(value) is not bool:
        raise TypeError("encoded boolean must be exact bool")
    return b"\x01" if value else b"\x00"


def _u64(value: int) -> bytes:
    _require_u64(value, "encoded unsigned integer")
    return value.to_bytes(8, "big")


def _bytes(value: bytes) -> bytes:
    if type(value) is not bytes:
        raise TypeError("encoded bytes must be exact bytes")
    return _u64(len(value)) + value


def _text(value: str) -> bytes:
    if type(value) is not str:
        raise TypeError("encoded text must be exact str")
    return _bytes(value.encode("utf-8", errors="strict"))


def _seq(values: tuple[bytes, ...]) -> bytes:
    if type(values) is not tuple or any(type(value) is not bytes for value in values):
        raise TypeError("encoded sequence must be an exact bytes tuple")
    return _u64(len(values)) + b"".join(values)


def _require_exact(value: object, expected: type, label: str) -> None:
    if type(value) is not expected:
        raise TypeError(f"{label} must be an exact {expected.__name__}")


def _require_exact_tuple(value: object, expected: type, label: str) -> None:
    if type(value) is not tuple or any(type(item) is not expected for item in value):
        raise TypeError(f"{label} must be an exact {expected.__name__} tuple")


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


__all__ = (
    "AUTHORITY_PROFILE_REVISION",
    "PROGRAM_STORAGE_AUTHORITY_REVISION",
    "STORAGE_ADMISSION_BASIS_REVISION",
    "AdmittedDeclaredPiece",
    "ConfiguredCallAuthoritySession",
    "ConfiguredCallStorageAuthoritySnapshot",
    "ConfiguredEffectCaptureReceipt",
    "ConfiguredProfileAdmissionReceipt",
    "DeclaredPieceRef",
    "RegisterSpaceAuthority",
    "RegisterSpaceState",
    "ValidatedCallStorageSpan",
    "authority_profile_digest",
    "call_authority_digest",
    "call_capture_provenance_digest",
    "call_storage_permit_payload_digest",
    "declared_piece_digest",
    "declared_piece_ref",
    "program_storage_authority_digest",
    "storage_admission_basis_digest",
    "storage_authority_digest",
)
