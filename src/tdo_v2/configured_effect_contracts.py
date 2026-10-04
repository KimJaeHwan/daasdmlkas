"""Architect-owned terminal semantic contracts for configured call effects."""

from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass, replace
from enum import StrEnum
from hashlib import sha256
from itertools import groupby
from typing import TypeAlias

from .call_contracts import CallOccurrenceId, FunctionCallSeedUnit
from .call_effect_contracts import (
    CallEffectCompleteness,
    CallEffectDirection,
    FunctionCallEffectEvidence,
    RawCallPortRole,
    RawObservedCallPort,
)
from .configured_effect_authority_contracts import (
    AdmittedDeclaredPiece,
    ConfiguredCallAuthoritySession,
    DeclaredPieceRef,
    declared_piece_ref,
)
from .configured_effect_wire_contracts import (
    CALL_EFFECT_EXPORTER_REVISION,
    CALL_EFFECT_SCHEMA_VERSION,
    AssignmentInterfaceCapture,
    AssignmentState,
    CapturedEffectRow,
    CapturedModelSlot,
    CorrelationRole,
    EffectDirectionTag,
    EffectSourceQuality,
    EffectStorageClass,
    NoInterfaceCapture,
    UnassignableInterfaceCapture,
    UnassignableReason,
)
from .span_geometry import ByteSpan, StorageObjectKind, StorageScopeKind


CONFIGURED_CALL_EFFECT_CONTRACT_VERSION = 4
MAX_CONFIGURED_DIRECTION_PORTS = 256
MAX_CONFIGURED_CALL_PORTS = 256
MAX_CONFIGURED_DIRECTION_FRAGMENTS = 256
MAX_CONFIGURED_CALL_FRAGMENTS = 256
MAX_CONFIGURED_DIRECTION_ENDPOINTS = 8_192
MAX_CONFIGURED_CALL_ENDPOINTS = 8_192
MAX_CONFIGURED_DIRECTION_DECLARED_PIECES = 4_096
MAX_CONFIGURED_CALL_DECLARED_PIECES = 8_192
MAX_CONFIGURED_CALL_DEBTS = 6_149
MAX_CONFIGURED_DIRECTION_DEBTS = MAX_CONFIGURED_CALL_DEBTS
MAX_CONFIGURED_FRAGMENT_CONTRIBUTORS = 64
MAX_CONFIGURED_CALL_RELATIONS = 8_192
MAX_CONFIGURED_FUNCTION_DECLARED_PIECES = 262_144
MAX_CONFIGURED_FUNCTION_FRAGMENTS_AND_DEBTS = 262_144
MAX_CONFIGURED_FUNCTION_RELATIONS = 1_048_576

_COVERAGE_CITATION_DOMAIN = "tdo-v2-call-effect-coverage-citation-v4"
_SLOT_EVIDENCE_DOMAIN = "tdo-v2-call-effect-slot-evidence-v4"
_DEBT_DOMAIN = "tdo-v2-call-effect-debt-v4"
_FRAGMENT_DOMAIN = "tdo-v2-configured-call-fragment-v4"
_FUNCTION_EFFECT_DOMAIN = "tdo-v2-call-effect-configured-v4"
_U64_MAX = (1 << 64) - 1


class ConfiguredDirectionDebtReason(StrEnum):
    INTERFACE_AUTHORITY_UNAVAILABLE = "INTERFACE_AUTHORITY_UNAVAILABLE"
    OVERRIDE_PRESENT = "OVERRIDE_PRESENT"
    CUSTOM_STORAGE_PRESENT = "CUSTOM_STORAGE_PRESENT"
    SIGNATURE_QUALITY_BELOW_THRESHOLD = "SIGNATURE_QUALITY_BELOW_THRESHOLD"
    HIDDEN_RESULT_PROJECTION_DEFERRED = "HIDDEN_RESULT_PROJECTION_DEFERRED"
    OPEN_VARIABLE_TAIL = "OPEN_VARIABLE_TAIL"


class ConfiguredSlotDebtReason(StrEnum):
    SLOT_QUALITY_BELOW_THRESHOLD = "SLOT_QUALITY_BELOW_THRESHOLD"
    UNASSIGNED_STORAGE = "UNASSIGNED_STORAGE"
    BAD_STORAGE = "BAD_STORAGE"


class ConfiguredPieceDebtReason(StrEnum):
    SIGNATURE_QUALITY_BELOW_THRESHOLD = "SIGNATURE_QUALITY_BELOW_THRESHOLD"
    SLOT_QUALITY_BELOW_THRESHOLD = "SLOT_QUALITY_BELOW_THRESHOLD"
    FORCED_INDIRECT_RESULT = "FORCED_INDIRECT_RESULT"
    STACK_PROJECTION_DEFERRED = "STACK_PROJECTION_DEFERRED"
    UNSUPPORTED_STORAGE_KIND = "UNSUPPORTED_STORAGE_KIND"
    STORAGE_AUTHORITY_REJECTED = "STORAGE_AUTHORITY_REJECTED"


_DIRECTION_REASON_RANK = {
    reason: rank for rank, reason in enumerate(ConfiguredDirectionDebtReason)
}
_SLOT_REASON_RANK = {reason: rank for rank, reason in enumerate(ConfiguredSlotDebtReason)}
_PIECE_REASON_RANK = {
    reason: rank for rank, reason in enumerate(ConfiguredPieceDebtReason)
}


@dataclass(frozen=True, slots=True)
class DirectionalPieceCoverage:
    direction: CallEffectDirection
    declared_refs: tuple[DeclaredPieceRef, ...]
    accounted_refs: tuple[DeclaredPieceRef, ...]
    open_variable_tail: bool
    call_authority_digest: bytes
    citation_digest: bytes

    def __post_init__(self) -> None:
        _require_exact(self.direction, CallEffectDirection, "coverage direction")
        _require_ref_tuple(self.declared_refs, "coverage declared refs")
        _require_ref_tuple(self.accounted_refs, "coverage accounted refs")
        _require_bool(self.open_variable_tail, "coverage open-variable-tail")
        _require_digest(self.call_authority_digest, "coverage call authority")
        _require_digest(self.citation_digest, "coverage citation")
        _require_ref_order(self.declared_refs, "coverage declared refs")
        _require_ref_order(self.accounted_refs, "coverage accounted refs")
        if any(ref.direction is not self.direction for ref in self.declared_refs):
            raise ValueError("coverage declared refs use the wrong direction")
        if any(ref.direction is not self.direction for ref in self.accounted_refs):
            raise ValueError("coverage accounted refs use the wrong direction")
        if not _is_ordered_ref_subset(self.accounted_refs, self.declared_refs):
            raise ValueError("coverage accounted refs must be a declared subset")

    def canonical_bytes(self) -> bytes:
        return (
            _text(self.direction.value)
            + _seq(tuple(ref.semantic_bytes() for ref in self.declared_refs))
            + _seq(tuple(ref.semantic_bytes() for ref in self.accounted_refs))
            + _bool(self.open_variable_tail)
            + _bytes(self.call_authority_digest)
            + _bytes(self.citation_digest)
        )


@dataclass(frozen=True, slots=True)
class ConfiguredDirectionDebt:
    direction: CallEffectDirection
    reason: ConfiguredDirectionDebtReason
    evidence_digest: bytes
    debt_digest: bytes

    def __post_init__(self) -> None:
        _require_exact(self.direction, CallEffectDirection, "direction debt direction")
        _require_exact(self.reason, ConfiguredDirectionDebtReason, "direction debt reason")
        _require_digest(self.evidence_digest, "direction debt evidence")
        _require_digest(self.debt_digest, "direction debt digest")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (_direction_rank(self.direction), 0, _U64_MAX, _U64_MAX,
                _DIRECTION_REASON_RANK[self.reason], self.evidence_digest)

    def body_bytes(self) -> bytes:
        return (
            _text("DIRECTION")
            + _text(self.direction.value)
            + _text(self.reason.value)
            + _bytes(self.evidence_digest)
        )

    def canonical_bytes(self) -> bytes:
        return self.body_bytes() + _bytes(self.debt_digest)


@dataclass(frozen=True, slots=True)
class ConfiguredSlotDebt:
    direction: CallEffectDirection
    slot_ordinal: int
    reason: ConfiguredSlotDebtReason
    evidence_digest: bytes
    debt_digest: bytes

    def __post_init__(self) -> None:
        _require_exact(self.direction, CallEffectDirection, "slot debt direction")
        _require_u64(self.slot_ordinal, "slot debt ordinal")
        _require_exact(self.reason, ConfiguredSlotDebtReason, "slot debt reason")
        _require_digest(self.evidence_digest, "slot debt evidence")
        _require_digest(self.debt_digest, "slot debt digest")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (_direction_rank(self.direction), 1, self.slot_ordinal, _U64_MAX,
                _SLOT_REASON_RANK[self.reason], self.evidence_digest)

    def body_bytes(self) -> bytes:
        return (
            _text("SLOT")
            + _text(self.direction.value)
            + _u64(self.slot_ordinal)
            + _text(self.reason.value)
            + _bytes(self.evidence_digest)
        )

    def canonical_bytes(self) -> bytes:
        return self.body_bytes() + _bytes(self.debt_digest)


@dataclass(frozen=True, slots=True)
class ConfiguredPieceDebt:
    direction: CallEffectDirection
    slot_ordinal: int
    piece_ordinal: int
    declared_piece_digest: bytes
    reason: ConfiguredPieceDebtReason
    evidence_digest: bytes
    debt_digest: bytes

    def __post_init__(self) -> None:
        _require_exact(self.direction, CallEffectDirection, "piece debt direction")
        _require_u64(self.slot_ordinal, "piece debt slot ordinal")
        _require_u64(self.piece_ordinal, "piece debt ordinal")
        _require_digest(self.declared_piece_digest, "piece debt declared-piece digest")
        _require_exact(self.reason, ConfiguredPieceDebtReason, "piece debt reason")
        _require_digest(self.evidence_digest, "piece debt evidence")
        _require_digest(self.debt_digest, "piece debt digest")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (_direction_rank(self.direction), 2, self.slot_ordinal,
                self.piece_ordinal, _PIECE_REASON_RANK[self.reason],
                self.evidence_digest)

    @property
    def ref_key(self) -> tuple[int, int, bytes]:
        return (self.slot_ordinal, self.piece_ordinal, self.declared_piece_digest)

    def body_bytes(self) -> bytes:
        return (
            _text("PIECE")
            + _text(self.direction.value)
            + _u64(self.slot_ordinal)
            + _u64(self.piece_ordinal)
            + _bytes(self.declared_piece_digest)
            + _text(self.reason.value)
            + _bytes(self.evidence_digest)
        )

    def canonical_bytes(self) -> bytes:
        return self.body_bytes() + _bytes(self.debt_digest)


ConfiguredEffectDebt: TypeAlias = (
    ConfiguredDirectionDebt | ConfiguredSlotDebt | ConfiguredPieceDebt
)


@dataclass(frozen=True, slots=True)
class CanonicalConfiguredFragment:
    fragment_ordinal: int
    direction: CallEffectDirection
    span: ByteSpan
    contributions: tuple[DeclaredPieceRef, ...]
    fragment_digest: bytes

    def __post_init__(self) -> None:
        _require_u64(self.fragment_ordinal, "configured fragment ordinal")
        _require_exact(self.direction, CallEffectDirection, "configured fragment direction")
        _require_configured_span(self.span, "configured fragment span")
        _require_ref_tuple(self.contributions, "configured fragment contributions")
        _require_ref_order(self.contributions, "configured fragment contributions")
        if not self.contributions:
            raise ValueError("configured fragments require at least one contribution")
        if len(self.contributions) > MAX_CONFIGURED_FRAGMENT_CONTRIBUTORS:
            raise ValueError("configured fragment contributors exceed their bound")
        if any(ref.direction is not self.direction for ref in self.contributions):
            raise ValueError("configured fragment contributions use the wrong direction")
        _require_digest(self.fragment_digest, "configured fragment digest")

    @property
    def physical_key(self) -> tuple[object, ...]:
        return _span_key(self.span)

    def canonical_bytes(self) -> bytes:
        return (
            _u64(self.fragment_ordinal)
            + _text(self.direction.value)
            + _span(self.span)
            + _seq(tuple(ref.semantic_bytes() for ref in self.contributions))
            + _bytes(self.fragment_digest)
        )


@dataclass(frozen=True, slots=True)
class ConfiguredDirectionalCallEffectV4:
    direction: CallEffectDirection
    completeness: CallEffectCompleteness
    coverage: DirectionalPieceCoverage
    admitted_pieces: tuple[AdmittedDeclaredPiece, ...]
    raw_ports: tuple[RawObservedCallPort, ...]
    fragments: tuple[CanonicalConfiguredFragment, ...]
    debts: tuple[ConfiguredEffectDebt, ...]

    def __post_init__(self) -> None:
        _require_exact(self.direction, CallEffectDirection, "configured direction")
        _require_exact(self.completeness, CallEffectCompleteness, "configured completeness")
        if self.completeness is CallEffectCompleteness.CONFLICT:
            raise ValueError("wire version 1 cannot produce conflicting authorities")
        _require_exact(self.coverage, DirectionalPieceCoverage, "configured coverage")
        if self.coverage.direction is not self.direction:
            raise ValueError("configured coverage uses the wrong direction")
        _require_exact_tuple(self.admitted_pieces, AdmittedDeclaredPiece,
                             "configured admitted pieces")
        _require_exact_tuple(self.raw_ports, RawObservedCallPort,
                             "configured raw ports")
        _require_exact_tuple(self.fragments, CanonicalConfiguredFragment,
                             "configured fragments")
        _require_debt_tuple(self.debts)
        if len(self.raw_ports) > MAX_CONFIGURED_DIRECTION_PORTS:
            raise ValueError("configured direction raw ports exceed their bound")
        if len(self.fragments) > MAX_CONFIGURED_DIRECTION_FRAGMENTS:
            raise ValueError("configured direction fragments exceed their bound")
        if len(self.debts) > MAX_CONFIGURED_DIRECTION_DEBTS:
            raise ValueError("configured direction debts exceed their bound")
        if (
            len(self.coverage.declared_refs)
            > MAX_CONFIGURED_DIRECTION_DECLARED_PIECES
        ):
            raise ValueError("configured direction declared pieces exceed their bound")
        self._validate_inventories()
        self._validate_fragments()
        self._validate_completeness()

    def _validate_inventories(self) -> None:
        refs = tuple(piece.ref for piece in self.admitted_pieces)
        _require_ref_order(refs, "configured admitted pieces")
        if refs != self.coverage.accounted_refs:
            raise ValueError("admitted pieces must exactly equal accounted refs")
        unresolved = _ordered_ref_difference(
            self.coverage.declared_refs,
            self.coverage.accounted_refs,
        )
        piece_debts = tuple(
            debt for debt in self.debts if type(debt) is ConfiguredPieceDebt
        )
        debt_refs = tuple(sorted(
            (
                _direction_rank(debt.direction),
                debt.slot_ordinal,
                debt.piece_ordinal,
                debt.declared_piece_digest,
            )
            for debt in piece_debts
        ))
        unresolved_refs = tuple(
            (
                _direction_rank(ref.direction),
                ref.slot_ordinal,
                ref.piece_ordinal,
                ref.declared_piece_digest,
            )
            for ref in unresolved
        )
        if debt_refs != unresolved_refs:
            raise ValueError("every unaccounted declared piece requires exactly one debt")
        if any(port.direction is not self.direction for port in self.raw_ports):
            raise ValueError("raw ports use the wrong configured direction")
        raw_keys = tuple((port.raw_port_ordinal, port.canonical_digest)
                         for port in self.raw_ports)
        if raw_keys != tuple(sorted(raw_keys)) or _has_adjacent_duplicate(raw_keys):
            raise ValueError("raw ports must retain deterministic seed-operand order")
        if any(fragment.direction is not self.direction for fragment in self.fragments):
            raise ValueError("configured fragments use the wrong direction")
        debt_keys = tuple(debt.canonical_key for debt in self.debts)
        if debt_keys != tuple(sorted(debt_keys)) or _has_adjacent_duplicate(debt_keys):
            raise ValueError("configured debts must be unique and canonical")
        if any(debt.direction is not self.direction for debt in self.debts):
            raise ValueError("configured debts use the wrong direction")

    def _validate_fragments(self) -> None:
        keys = tuple(fragment.physical_key for fragment in self.fragments)
        if keys != tuple(sorted(keys)) or _has_adjacent_duplicate(keys):
            raise ValueError("configured fragments must use canonical physical order")
        if tuple(fragment.fragment_ordinal for fragment in self.fragments) != tuple(
            range(len(self.fragments))
        ):
            raise ValueError("configured fragment ordinals must be gap-free")
        if len(self.admitted_pieces) > MAX_CONFIGURED_DIRECTION_ENDPOINTS // 2:
            raise ValueError("configured direction endpoints exceed their bound")
        physical = sorted(
            self.admitted_pieces,
            key=lambda piece: _span_key(piece.validated_span.span),
        )
        plans: list[
            tuple[
                StorageObjectId,
                tuple[tuple[AdmittedDeclaredPiece, int, int], ...],
                tuple[int, ...],
            ]
        ] = []
        endpoint_count = 0
        fragment_count = 0
        for object_id, grouped in groupby(
            physical,
            key=lambda piece: piece.validated_span.span.object_id,
        ):
            pieces = tuple(sorted(grouped, key=lambda piece: piece.ref.canonical_key))
            raw_endpoints: list[int] = []
            for piece in pieces:
                if len(raw_endpoints) > MAX_CONFIGURED_DIRECTION_ENDPOINTS - 2:
                    raise ValueError("configured direction endpoints exceed their bound")
                span = piece.validated_span.span
                raw_endpoints.append(span.start)
                raw_endpoints.append(span.end)
            raw_endpoints.sort()
            endpoints: list[int] = []
            for endpoint in raw_endpoints:
                if endpoints and endpoints[-1] == endpoint:
                    continue
                if endpoint_count >= MAX_CONFIGURED_DIRECTION_ENDPOINTS:
                    raise ValueError("configured direction endpoints exceed their bound")
                endpoints.append(endpoint)
                endpoint_count += 1

            differences = [0] * len(endpoints)
            placements: list[tuple[AdmittedDeclaredPiece, int, int]] = []
            for piece in pieces:
                span = piece.validated_span.span
                start_index = bisect_left(endpoints, span.start)
                end_index = bisect_left(endpoints, span.end)
                differences[start_index] += 1
                differences[end_index] -= 1
                placements.append((piece, start_index, end_index))
            active_count = 0
            for delta in differences[:-1]:
                active_count += delta
                if active_count > MAX_CONFIGURED_FRAGMENT_CONTRIBUTORS:
                    raise ValueError("configured fragment contributors exceed their bound")
                if active_count:
                    if fragment_count >= MAX_CONFIGURED_DIRECTION_FRAGMENTS:
                        raise ValueError("configured direction fragments exceed their bound")
                    fragment_count += 1
            plans.append((object_id, tuple(placements), tuple(endpoints)))

        expected: list[tuple[ByteSpan, tuple[DeclaredPieceRef, ...]]] = []
        relation_count = 0
        for object_id, placements, endpoints in plans:
            contributors: list[list[DeclaredPieceRef]] = [
                [] for _ in range(len(endpoints) - 1)
            ]
            for piece, start_index, end_index in placements:
                for atom_index in range(start_index, end_index):
                    if relation_count >= MAX_CONFIGURED_CALL_RELATIONS:
                        raise ValueError("configured direction relations exceed the call bound")
                    contributors[atom_index].append(piece.ref)
                    relation_count += 1
            for atom_index, refs in enumerate(contributors):
                if not refs:
                    continue
                span = ByteSpan(
                    object_id,
                    endpoints[atom_index],
                    endpoints[atom_index + 1] - endpoints[atom_index],
                )
                specification = (span, tuple(refs))
                if (
                    expected
                    and expected[-1][0].object_id == span.object_id
                    and expected[-1][0].end == span.start
                    and expected[-1][1] == specification[1]
                ):
                    previous_span, previous_refs = expected[-1]
                    expected[-1] = (
                        ByteSpan(
                            previous_span.object_id,
                            previous_span.start,
                            span.end - previous_span.start,
                        ),
                        previous_refs,
                    )
                else:
                    expected.append(specification)

        if len(expected) != len(self.fragments):
            raise ValueError("configured fragments must exactly partition admitted spans")
        for fragment, (expected_span, contributors) in zip(
            self.fragments,
            expected,
            strict=True,
        ):
            if fragment.span != expected_span:
                raise ValueError("configured fragments must exactly partition admitted spans")
            if fragment.contributions != contributors:
                raise ValueError("fragment contributors must equal all covering pieces")

    def _validate_completeness(self) -> None:
        expected = _direction_completeness(
            self.coverage.declared_refs,
            self.coverage.accounted_refs,
            self.debts,
            self.coverage.open_variable_tail,
        )
        if self.completeness is not expected:
            raise ValueError("configured direction completeness is not derived exactly")

    def canonical_bytes(self) -> bytes:
        return (
            _text(self.direction.value)
            + _text(self.completeness.value)
            + self.coverage.canonical_bytes()
            + _seq(tuple(piece.canonical_bytes() for piece in self.admitted_pieces))
            + _seq(tuple(_bytes(port.canonical_digest) for port in self.raw_ports))
            + _seq(tuple(fragment.canonical_bytes() for fragment in self.fragments))
            + _seq(tuple(debt.canonical_bytes() for debt in self.debts))
        )


@dataclass(frozen=True, slots=True)
class ConfiguredCallEffectRecordV4:
    occurrence: CallOccurrenceId
    row_digest: bytes
    pre_read: ConfiguredDirectionalCallEffectV4
    post_write: ConfiguredDirectionalCallEffectV4

    def __post_init__(self) -> None:
        _require_exact(self.occurrence, CallOccurrenceId, "configured call occurrence")
        _require_digest(self.row_digest, "configured call row digest")
        _require_exact(self.pre_read, ConfiguredDirectionalCallEffectV4,
                       "configured pre-read direction")
        _require_exact(self.post_write, ConfiguredDirectionalCallEffectV4,
                       "configured post-write direction")
        if self.pre_read.direction is not CallEffectDirection.PRE_READ:
            raise ValueError("configured call pre-read arm has the wrong direction")
        if self.post_write.direction is not CallEffectDirection.POST_WRITE:
            raise ValueError("configured call post-write arm has the wrong direction")
        if (
            self.pre_read.coverage.call_authority_digest
            != self.post_write.coverage.call_authority_digest
        ):
            raise ValueError("configured call directions disagree on call authority")
        _validate_configured_call_bounds(self.pre_read, self.post_write)
        for direction in (self.pre_read, self.post_write):
            for debt in direction.debts:
                expected = configured_effect_debt_digest(
                    self.occurrence.occurrence_digest, debt
                )
                if debt.debt_digest != expected:
                    raise ValueError("configured debt digest does not match its body")
            for fragment in direction.fragments:
                expected = configured_fragment_digest(
                    self.occurrence.occurrence_digest,
                    fragment.direction,
                    fragment.span,
                    fragment.contributions,
                )
                if fragment.fragment_digest != expected:
                    raise ValueError("configured fragment digest does not match its body")

    @property
    def raw_ports(self) -> tuple[RawObservedCallPort, ...]:
        return self.pre_read.raw_ports + self.post_write.raw_ports

    def canonical_bytes(self) -> bytes:
        return (
            _bytes(self.occurrence.occurrence_digest)
            + _bytes(self.row_digest)
            + self.pre_read.canonical_bytes()
            + self.post_write.canonical_bytes()
        )


class _ConfiguredEffectAuthority:
    __slots__ = ()


_CONFIGURED_EFFECT_AUTHORITY = _ConfiguredEffectAuthority()


class _ConfiguredEffectPermit:
    __slots__ = (
        "_active",
        "_authority_profile_digest",
        "_baseline",
        "_calls",
        "_effect_capture_digest",
        "_payload_digest",
        "_profile_semantic_content_digest",
        "_seeds",
        "_session",
    )

    def __init__(
        self,
        authority: _ConfiguredEffectAuthority,
        session: ConfiguredCallAuthoritySession,
        baseline: FunctionCallEffectEvidenceV3,
        calls: tuple[ConfiguredCallEffectRecordV4, ...],
        payload_digest: bytes,
    ) -> None:
        if authority is not _CONFIGURED_EFFECT_AUTHORITY:
            raise PermissionError("configured-effect permits are architect-owned")
        _require_exact(
            session,
            ConfiguredCallAuthoritySession,
            "configured-effect permit session",
        )
        _require_exact(
            baseline,
            FunctionCallEffectEvidenceV3,
            "configured-effect v3 baseline",
        )
        baseline._validate()
        if baseline.seeds is not session.seeds:
            raise PermissionError("configured-effect baseline retains other call seeds")
        _require_exact_tuple(calls, ConfiguredCallEffectRecordV4,
                             "configured-effect permit calls")
        _require_digest(payload_digest, "configured-effect permit payload")
        session.require_active()
        _validate_session_bound_graph(session, baseline, calls)
        object.__setattr__(self, "_active", True)
        object.__setattr__(self, "_session", session)
        object.__setattr__(self, "_baseline", baseline)
        object.__setattr__(self, "_seeds", session.seeds)
        object.__setattr__(self, "_calls", calls)
        object.__setattr__(
            self,
            "_effect_capture_digest",
            session.capture_receipt.sidecar.semantic_content_digest,
        )
        object.__setattr__(
            self,
            "_profile_semantic_content_digest",
            session.profile_receipt.profile.semantic_content_digest,
        )
        object.__setattr__(
            self,
            "_authority_profile_digest",
            session.authority_profile_digest,
        )
        object.__setattr__(self, "_payload_digest", payload_digest)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("configured-effect permit state is owner-controlled")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("configured-effect permit state is owner-controlled")

    def consume(
        self,
        seeds: FunctionCallSeedUnit,
        effect_capture_digest: bytes,
        profile_semantic_content_digest: bytes,
        authority_profile_digest: bytes,
        calls: tuple[ConfiguredCallEffectRecordV4, ...],
        payload_digest: bytes,
    ) -> None:
        if self._active is not True:
            raise RuntimeError("configured-effect permit is inactive")
        self._session.require_active()
        if (
            seeds is not self._seeds
            or calls is not self._calls
            or effect_capture_digest != self._effect_capture_digest
            or profile_semantic_content_digest
            != self._profile_semantic_content_digest
            or authority_profile_digest != self._authority_profile_digest
            or payload_digest != self._payload_digest
        ):
            raise PermissionError("configured-effect permit is bound to other evidence")
        _validate_session_bound_graph(self._session, self._baseline, calls)
        object.__setattr__(self, "_active", False)

    def revoke(self) -> None:
        object.__setattr__(self, "_active", False)

    def __reduce_ex__(self, protocol: int):
        raise TypeError("configured-effect permits cannot be serialized")


@dataclass(frozen=True, slots=True, init=False)
class ConfiguredFunctionCallEffectEvidenceV4:
    contract_version: int
    seeds: FunctionCallSeedUnit
    effect_capture_digest: bytes
    profile_semantic_content_digest: bytes
    authority_profile_digest: bytes
    calls: tuple[ConfiguredCallEffectRecordV4, ...]
    canonical_digest: bytes

    @classmethod
    def _create(
        cls,
        seeds: FunctionCallSeedUnit,
        effect_capture_digest: bytes,
        profile_semantic_content_digest: bytes,
        authority_profile_digest: bytes,
        calls: tuple[ConfiguredCallEffectRecordV4, ...],
        canonical_digest: bytes,
        permit: _ConfiguredEffectPermit,
    ) -> "ConfiguredFunctionCallEffectEvidenceV4":
        _require_exact(permit, _ConfiguredEffectPermit, "configured-effect permit")
        value = object.__new__(cls)
        object.__setattr__(value, "contract_version", CONFIGURED_CALL_EFFECT_CONTRACT_VERSION)
        object.__setattr__(value, "seeds", seeds)
        object.__setattr__(value, "effect_capture_digest", effect_capture_digest)
        object.__setattr__(value, "profile_semantic_content_digest",
                           profile_semantic_content_digest)
        object.__setattr__(value, "authority_profile_digest", authority_profile_digest)
        _require_exact_tuple(calls, ConfiguredCallEffectRecordV4,
                             "configured call records")
        _validate_configured_function_bounds(calls)
        object.__setattr__(value, "calls", calls)
        object.__setattr__(value, "canonical_digest", canonical_digest)
        value._validate()
        permit.consume(
            seeds,
            effect_capture_digest,
            profile_semantic_content_digest,
            authority_profile_digest,
            calls,
            canonical_digest,
        )
        return value

    def _validate(self) -> None:
        if type(self.contract_version) is not int:
            raise TypeError("configured call-effect version must be an exact int")
        if self.contract_version != CONFIGURED_CALL_EFFECT_CONTRACT_VERSION:
            raise ValueError("unsupported configured call-effect version")
        _require_exact(self.seeds, FunctionCallSeedUnit, "configured call-effect seeds")
        _require_digest(self.effect_capture_digest, "configured effect capture digest")
        _require_digest(self.profile_semantic_content_digest,
                        "configured profile semantic content digest")
        _require_digest(self.authority_profile_digest,
                        "configured authority-profile digest")
        _require_exact_tuple(self.calls, ConfiguredCallEffectRecordV4,
                             "configured call records")
        _require_digest(self.canonical_digest, "configured function effect digest")
        if len(self.calls) != len(self.seeds.callsites) or any(
            call.occurrence != seed.occurrence
            for call, seed in zip(self.calls, self.seeds.callsites, strict=True)
        ):
            raise ValueError("configured calls must exactly cover retained call seeds")
        call_keys = tuple(call.occurrence.canonical_key for call in self.calls)
        if call_keys != tuple(sorted(call_keys)) or _has_adjacent_duplicate(call_keys):
            raise ValueError("configured calls must be unique and canonical")
        _validate_configured_function_bounds(self.calls)
        self._validate_nested_digests()
        self._validate_raw_inventory()
        expected = configured_function_effect_digest(
            self.seeds,
            self.effect_capture_digest,
            self.profile_semantic_content_digest,
            self.authority_profile_digest,
            self.calls,
        )
        if self.canonical_digest != expected:
            raise ValueError("configured function effect digest does not match its graph")

    def _validate_nested_digests(self) -> None:
        for call in self.calls:
            for direction in (call.pre_read, call.post_write):
                expected = coverage_citation_digest(
                    call.occurrence.occurrence_digest,
                    direction.direction,
                    call.row_digest,
                    self.profile_semantic_content_digest,
                    self.authority_profile_digest,
                    direction.coverage.declared_refs,
                )
                if direction.coverage.citation_digest != expected:
                    raise ValueError("coverage citation digest does not match its evidence")

    def _validate_raw_inventory(self) -> None:
        for seed, call in zip(self.seeds.callsites, self.calls, strict=True):
            raw_ports = call.raw_ports
            ordinals = tuple(port.raw_port_ordinal for port in raw_ports)
            if ordinals != tuple(range(len(raw_ports))):
                raise ValueError("configured call raw-port ordinals must be gap-free")
            descriptors = tuple(sorted(
                (
                    port.role.value,
                    -1 if port.input_ordinal is None else port.input_ordinal,
                )
                for port in raw_ports
            ))
            if _has_adjacent_duplicate(descriptors):
                raise ValueError("raw port cannot duplicate a seed operand")
            for port in raw_ports:
                if port.occurrence != call.occurrence:
                    raise ValueError("raw port belongs to another call occurrence")
                if port.observation_digest != self.seeds.observation_digest:
                    raise ValueError("raw port belongs to another observation")
                if port.span.size != port.varnode.byte_size:
                    raise ValueError("raw port span must preserve varnode width")
                if port.role is RawCallPortRole.INPUT:
                    ordinal = port.input_ordinal
                    assert ordinal is not None
                    if ordinal >= len(seed.inputs) or port.varnode is not seed.inputs[ordinal]:
                        raise ValueError("raw input port must retain exact seed identity")
                elif seed.explicit_output is None or port.varnode is not seed.explicit_output:
                    raise ValueError("raw output port must retain exact seed identity")

    @property
    def function_scope(self):
        return self.seeds.function_scope

    @property
    def observation_digest(self) -> bytes:
        return self.seeds.observation_digest

    @property
    def seed_digest(self) -> bytes:
        return self.seeds.canonical_digest

    def __reduce_ex__(self, protocol: int):
        raise TypeError("configured call-effect evidence cannot be serialized")


FunctionCallEffectEvidenceV3 = FunctionCallEffectEvidence
CallEffectEvidence: TypeAlias = (
    FunctionCallEffectEvidenceV3 | ConfiguredFunctionCallEffectEvidenceV4
)


def _mint_configured_effect_permit(
    session: ConfiguredCallAuthoritySession,
    baseline: FunctionCallEffectEvidenceV3,
    calls: tuple[ConfiguredCallEffectRecordV4, ...],
    canonical_digest: bytes,
) -> _ConfiguredEffectPermit:
    _require_exact(
        session,
        ConfiguredCallAuthoritySession,
        "configured-effect permit session",
    )
    _require_exact_tuple(calls, ConfiguredCallEffectRecordV4,
                         "configured-effect permit calls")
    expected = configured_function_effect_digest(
        session.seeds,
        session.capture_receipt.sidecar.semantic_content_digest,
        session.profile_receipt.profile.semantic_content_digest,
        session.authority_profile_digest,
        calls,
    )
    if canonical_digest != expected:
        raise PermissionError("configured-effect permit digest is not session-derived")
    return _ConfiguredEffectPermit(
        _CONFIGURED_EFFECT_AUTHORITY,
        session,
        baseline,
        calls,
        canonical_digest,
    )


def _validate_session_bound_graph(
    session: ConfiguredCallAuthoritySession,
    baseline: FunctionCallEffectEvidenceV3,
    calls: tuple[ConfiguredCallEffectRecordV4, ...],
) -> None:
    session.require_active()
    _require_exact(
        baseline,
        FunctionCallEffectEvidenceV3,
        "configured-effect v3 baseline",
    )
    baseline._validate()
    if baseline.seeds is not session.seeds:
        raise PermissionError("configured-effect baseline retains other call seeds")
    rows = session.capture_receipt.sidecar.rows
    seeds = session.seeds.callsites
    occurrences = session.capture_receipt.occurrences
    if (
        len(calls) != len(rows)
        or len(calls) != len(baseline.calls)
        or len(calls) != len(seeds)
        or len(calls) != len(occurrences)
    ):
        raise PermissionError("configured graph does not cover the authority session")
    for seed, occurrence, baseline_call, row, call in zip(
        seeds,
        occurrences,
        baseline.calls,
        rows,
        calls,
        strict=True,
    ):
        if occurrence != seed.occurrence:
            raise PermissionError("authority session occurrence disagrees with its seed")
        if call.occurrence is not occurrence or call.row_digest != row.row_digest:
            raise PermissionError("configured graph cites another call occurrence or row")
        expected_raw_ports = tuple(
            port
            for port in baseline_call.ports
            if type(port) is RawObservedCallPort
        )
        if (
            len(call.raw_ports) != len(expected_raw_ports)
            or any(
                actual is not expected
                for actual, expected in zip(
                    call.raw_ports,
                    expected_raw_ports,
                    strict=True,
                )
            )
        ):
            raise PermissionError(
                "configured graph does not retain the exact v3 raw-port inventory"
            )
        call_authority = session.call_authority_digest(occurrence, row)
        _validate_session_direction(
            session,
            occurrence,
            row,
            EffectDirectionTag.PRE_READ,
            call.pre_read,
            call_authority,
        )
        _validate_session_direction(
            session,
            occurrence,
            row,
            EffectDirectionTag.POST_WRITE,
            call.post_write,
            call_authority,
        )


def _validate_session_direction(
    session: ConfiguredCallAuthoritySession,
    occurrence: CallOccurrenceId,
    row: CapturedEffectRow,
    wire_direction: EffectDirectionTag,
    actual: ConfiguredDirectionalCallEffectV4,
    call_authority: bytes,
) -> None:
    semantic_direction = _semantic_direction(wire_direction)
    if actual.direction is not semantic_direction:
        raise PermissionError("configured graph direction disagrees with capture")
    declared, admitted, debts, open_tail = _derive_session_direction(
        session,
        occurrence,
        row,
        wire_direction,
        call_authority,
    )
    accounted = tuple(piece.ref for piece in admitted)
    coverage = actual.coverage
    if (
        coverage.declared_refs != declared
        or coverage.accounted_refs != accounted
        or coverage.open_variable_tail is not open_tail
        or coverage.call_authority_digest != call_authority
        or len(actual.admitted_pieces) != len(admitted)
        or any(
            actual_piece is not admitted_piece
            for actual_piece, admitted_piece in zip(
                actual.admitted_pieces,
                admitted,
                strict=True,
            )
        )
        or actual.debts != debts
    ):
        raise PermissionError("configured graph is not the exact session derivation")


def _derive_session_direction(
    session: ConfiguredCallAuthoritySession,
    occurrence: CallOccurrenceId,
    row: CapturedEffectRow,
    wire_direction: EffectDirectionTag,
    call_authority: bytes,
) -> tuple[
    tuple[DeclaredPieceRef, ...],
    tuple[AdmittedDeclaredPiece, ...],
    tuple[ConfiguredEffectDebt, ...],
    bool,
]:
    semantic_direction = _semantic_direction(wire_direction)
    capture = row.interface_capture
    if type(capture) is NoInterfaceCapture:
        debt = _direction_debt(
            occurrence,
            semantic_direction,
            ConfiguredDirectionDebtReason.INTERFACE_AUTHORITY_UNAVAILABLE,
            call_authority,
        )
        return (), (), (debt,), False
    if type(capture) is UnassignableInterfaceCapture:
        if capture.reason is UnassignableReason.OVERRIDE_PRESENT:
            reason = ConfiguredDirectionDebtReason.OVERRIDE_PRESENT
            evidence = row.row_digest
        elif capture.reason is UnassignableReason.CUSTOM_STORAGE_PRESENT:
            reason = ConfiguredDirectionDebtReason.CUSTOM_STORAGE_PRESENT
            evidence = row.row_digest
        else:
            reason = ConfiguredDirectionDebtReason.INTERFACE_AUTHORITY_UNAVAILABLE
            evidence = call_authority
        debt = _direction_debt(occurrence, semantic_direction, reason, evidence)
        return (), (), (debt,), False
    if type(capture) is not AssignmentInterfaceCapture:
        raise TypeError("authority session retained an unknown interface capture")

    captured_direction = capture.directions[
        0 if wire_direction is EffectDirectionTag.PRE_READ else 1
    ]
    signature_blocked = _quality_rank(
        capture.signature.signature_source_quality
    ) < 1
    declared: list[DeclaredPieceRef] = []
    admitted: list[AdmittedDeclaredPiece] = []
    debts: list[ConfiguredEffectDebt] = []
    if signature_blocked:
        _append_configured_debt(
            debts,
            _direction_debt(
                occurrence,
                semantic_direction,
                ConfiguredDirectionDebtReason.SIGNATURE_QUALITY_BELOW_THRESHOLD,
                row.row_digest,
            )
        )
    if (
        wire_direction is EffectDirectionTag.POST_WRITE
        and captured_direction.slots[0].correlation.role is CorrelationRole.RESULT
        and captured_direction.slots[0].is_indirect
    ):
        _append_configured_debt(
            debts,
            _direction_debt(
                occurrence,
                semantic_direction,
                ConfiguredDirectionDebtReason.HIDDEN_RESULT_PROJECTION_DEFERRED,
                row.row_digest,
            )
        )
    if captured_direction.open_variable_tail:
        _append_configured_debt(
            debts,
            _direction_debt(
                occurrence,
                semantic_direction,
                ConfiguredDirectionDebtReason.OPEN_VARIABLE_TAIL,
                row.row_digest,
            )
        )

    for slot in captured_direction.slots:
        slot_digest = slot_evidence_digest(
            occurrence.occurrence_digest,
            row.row_digest,
            semantic_direction,
            slot.slot_ordinal,
            slot.canonical_bytes(),
        )
        slot_blocked = _slot_quality_blocked(capture, slot)
        if slot_blocked:
            _append_configured_debt(
                debts,
                _slot_debt(
                    occurrence,
                    semantic_direction,
                    slot.slot_ordinal,
                    ConfiguredSlotDebtReason.SLOT_QUALITY_BELOW_THRESHOLD,
                    slot_digest,
                )
            )
        if slot.assignment.state is AssignmentState.UNASSIGNED:
            _append_configured_debt(
                debts,
                _slot_debt(
                    occurrence,
                    semantic_direction,
                    slot.slot_ordinal,
                    ConfiguredSlotDebtReason.UNASSIGNED_STORAGE,
                    slot_digest,
                )
            )
        elif slot.assignment.state is AssignmentState.BAD:
            _append_configured_debt(
                debts,
                _slot_debt(
                    occurrence,
                    semantic_direction,
                    slot.slot_ordinal,
                    ConfiguredSlotDebtReason.BAD_STORAGE,
                    slot_digest,
                )
            )
        for piece in slot.assignment.pieces:
            ref = declared_piece_ref(
                occurrence.occurrence_digest,
                row.row_digest,
                wire_direction,
                slot.slot_ordinal,
                piece.piece_ordinal,
                piece,
            )
            if len(declared) >= MAX_CONFIGURED_DIRECTION_DECLARED_PIECES:
                raise ValueError("configured direction declared pieces exceed their bound")
            declared.append(ref)
            reason: ConfiguredPieceDebtReason | None
            evidence: bytes
            if signature_blocked:
                reason = ConfiguredPieceDebtReason.SIGNATURE_QUALITY_BELOW_THRESHOLD
                evidence = row.row_digest
            elif slot_blocked:
                reason = ConfiguredPieceDebtReason.SLOT_QUALITY_BELOW_THRESHOLD
                evidence = slot_digest
            elif (
                wire_direction is EffectDirectionTag.POST_WRITE
                and slot.correlation.role is CorrelationRole.RESULT
                and slot.is_indirect
            ):
                reason = ConfiguredPieceDebtReason.FORCED_INDIRECT_RESULT
                evidence = slot_digest
            elif piece.storage_class is EffectStorageClass.STACK:
                reason = ConfiguredPieceDebtReason.STACK_PROJECTION_DEFERRED
                evidence = ref.declared_piece_digest
            elif piece.storage_class not in (
                EffectStorageClass.REGISTER,
                EffectStorageClass.ADDRESS,
            ):
                reason = ConfiguredPieceDebtReason.UNSUPPORTED_STORAGE_KIND
                evidence = ref.declared_piece_digest
            else:
                admitted_piece = session.admit_piece(
                    occurrence,
                    row,
                    wire_direction,
                    slot.slot_ordinal,
                    piece.piece_ordinal,
                )
                if admitted_piece is None:
                    reason = ConfiguredPieceDebtReason.STORAGE_AUTHORITY_REJECTED
                    evidence = ref.declared_piece_digest
                else:
                    reason = None
                    evidence = b""
                    admitted.append(admitted_piece)
            if reason is not None:
                _append_configured_debt(
                    debts,
                    _piece_debt(
                        occurrence,
                        ref,
                        reason,
                        evidence,
                    )
                )

    return (
        tuple(declared),
        tuple(admitted),
        tuple(sorted(debts, key=lambda debt: debt.canonical_key)),
        captured_direction.open_variable_tail,
    )


def _append_configured_debt(
    debts: list[ConfiguredEffectDebt],
    debt: ConfiguredEffectDebt,
) -> None:
    if len(debts) >= MAX_CONFIGURED_DIRECTION_DEBTS:
        raise ValueError("configured direction debts exceed their bound")
    debts.append(debt)


def _configured_direction_relation_count(
    direction: ConfiguredDirectionalCallEffectV4,
) -> int:
    return sum(len(fragment.contributions) for fragment in direction.fragments)


def _validate_configured_call_bounds(
    pre_read: ConfiguredDirectionalCallEffectV4,
    post_write: ConfiguredDirectionalCallEffectV4,
) -> None:
    raw_port_count = len(pre_read.raw_ports) + len(post_write.raw_ports)
    if raw_port_count > MAX_CONFIGURED_CALL_PORTS:
        raise ValueError("one configured call exceeds its raw-port bound")

    declared_count = (
        len(pre_read.coverage.declared_refs)
        + len(post_write.coverage.declared_refs)
    )
    if declared_count > MAX_CONFIGURED_CALL_DECLARED_PIECES:
        raise ValueError("one configured call exceeds its declared-piece bound")

    debt_count = len(pre_read.debts) + len(post_write.debts)
    if debt_count > MAX_CONFIGURED_CALL_DEBTS:
        raise ValueError("one configured call exceeds its debt bound")

    endpoint_count = 2 * (
        len(pre_read.admitted_pieces) + len(post_write.admitted_pieces)
    )
    if endpoint_count > MAX_CONFIGURED_CALL_ENDPOINTS:
        raise ValueError("one configured call exceeds its endpoint bound")

    fragment_count = len(pre_read.fragments) + len(post_write.fragments)
    if fragment_count > MAX_CONFIGURED_CALL_FRAGMENTS:
        raise ValueError("one configured call exceeds its fragment bound")
    if raw_port_count + fragment_count > (
        MAX_CONFIGURED_CALL_PORTS + MAX_CONFIGURED_CALL_FRAGMENTS
    ):
        raise ValueError("one configured call exceeds its combined output bound")

    relation_count = (
        _configured_direction_relation_count(pre_read)
        + _configured_direction_relation_count(post_write)
    )
    if relation_count > MAX_CONFIGURED_CALL_RELATIONS:
        raise ValueError("one configured call exceeds its relation bound")


def _validate_configured_function_bounds(
    calls: tuple[ConfiguredCallEffectRecordV4, ...],
) -> None:
    declared_count = 0
    fragments_and_debts = 0
    relation_count = 0
    for call in calls:
        _validate_configured_call_bounds(call.pre_read, call.post_write)

        next_declared = declared_count + (
            len(call.pre_read.coverage.declared_refs)
            + len(call.post_write.coverage.declared_refs)
        )
        if next_declared > MAX_CONFIGURED_FUNCTION_DECLARED_PIECES:
            raise ValueError("configured function declared pieces exceed their bound")

        next_fragments_and_debts = fragments_and_debts + (
            len(call.pre_read.fragments)
            + len(call.post_write.fragments)
            + len(call.pre_read.debts)
            + len(call.post_write.debts)
        )
        if (
            next_fragments_and_debts
            > MAX_CONFIGURED_FUNCTION_FRAGMENTS_AND_DEBTS
        ):
            raise ValueError(
                "configured function fragments and debts exceed their bound"
            )

        next_relations = relation_count + (
            _configured_direction_relation_count(call.pre_read)
            + _configured_direction_relation_count(call.post_write)
        )
        if next_relations > MAX_CONFIGURED_FUNCTION_RELATIONS:
            raise ValueError("configured function relations exceed their bound")

        declared_count = next_declared
        fragments_and_debts = next_fragments_and_debts
        relation_count = next_relations


def _direction_debt(
    occurrence: CallOccurrenceId,
    direction: CallEffectDirection,
    reason: ConfiguredDirectionDebtReason,
    evidence_digest: bytes,
) -> ConfiguredDirectionDebt:
    value = ConfiguredDirectionDebt(direction, reason, evidence_digest, bytes(32))
    return replace(
        value,
        debt_digest=configured_effect_debt_digest(
            occurrence.occurrence_digest,
            value,
        ),
    )


def _slot_debt(
    occurrence: CallOccurrenceId,
    direction: CallEffectDirection,
    slot_ordinal: int,
    reason: ConfiguredSlotDebtReason,
    evidence_digest: bytes,
) -> ConfiguredSlotDebt:
    value = ConfiguredSlotDebt(
        direction,
        slot_ordinal,
        reason,
        evidence_digest,
        bytes(32),
    )
    return replace(
        value,
        debt_digest=configured_effect_debt_digest(
            occurrence.occurrence_digest,
            value,
        ),
    )


def _piece_debt(
    occurrence: CallOccurrenceId,
    ref: DeclaredPieceRef,
    reason: ConfiguredPieceDebtReason,
    evidence_digest: bytes,
) -> ConfiguredPieceDebt:
    value = ConfiguredPieceDebt(
        ref.direction,
        ref.slot_ordinal,
        ref.piece_ordinal,
        ref.declared_piece_digest,
        reason,
        evidence_digest,
        bytes(32),
    )
    return replace(
        value,
        debt_digest=configured_effect_debt_digest(
            occurrence.occurrence_digest,
            value,
        ),
    )


def _slot_quality_blocked(
    capture: AssignmentInterfaceCapture,
    slot: CapturedModelSlot,
) -> bool:
    role = slot.correlation.role
    if role is CorrelationRole.THIS:
        return False
    if role is CorrelationRole.FIXED:
        ordinal = slot.correlation.formal_ordinal
        if ordinal is None:
            raise ValueError("fixed slot lacks its validated formal ordinal")
        quality = capture.signature.fixed_formals[ordinal].symbol_source_quality
    else:
        quality = capture.signature.result.symbol_source_quality
    return _quality_rank(quality) < 1


def _quality_rank(value: EffectSourceQuality) -> int:
    _require_exact(value, EffectSourceQuality, "configured source quality")
    return {
        EffectSourceQuality.DEFAULT: 0,
        EffectSourceQuality.ANALYSIS: 1,
        EffectSourceQuality.AI: 2,
        EffectSourceQuality.IMPORTED: 3,
        EffectSourceQuality.USER_DEFINED: 4,
    }[value]


def _semantic_direction(value: EffectDirectionTag) -> CallEffectDirection:
    _require_exact(value, EffectDirectionTag, "configured wire direction")
    if value is EffectDirectionTag.PRE_READ:
        return CallEffectDirection.PRE_READ
    return CallEffectDirection.POST_WRITE


def coverage_citation_digest(
    occurrence_digest: bytes,
    direction: CallEffectDirection,
    row_digest: bytes,
    profile_semantic_content_digest: bytes,
    authority_profile_digest: bytes,
    declared_refs: tuple[DeclaredPieceRef, ...],
) -> bytes:
    _require_digest(occurrence_digest, "coverage occurrence digest")
    _require_exact(direction, CallEffectDirection, "coverage digest direction")
    _require_digest(row_digest, "coverage row digest")
    _require_digest(profile_semantic_content_digest, "coverage profile digest")
    _require_digest(authority_profile_digest, "coverage authority-profile digest")
    _require_ref_tuple(declared_refs, "coverage digest declared refs")
    _require_ref_order(declared_refs, "coverage digest declared refs")
    if any(ref.direction is not direction for ref in declared_refs):
        raise ValueError("coverage digest refs use the wrong direction")
    return _digest(
        _text(_COVERAGE_CITATION_DOMAIN)
        + _bytes(occurrence_digest)
        + _text(_wire_direction(direction))
        + _bytes(row_digest)
        + _bytes(profile_semantic_content_digest)
        + _bytes(authority_profile_digest)
        + _seq(tuple(ref.wire_bytes() for ref in declared_refs))
    )


def slot_evidence_digest(
    occurrence_digest: bytes,
    row_digest: bytes,
    direction: CallEffectDirection,
    slot_ordinal: int,
    encoded_slot: bytes,
) -> bytes:
    _require_digest(occurrence_digest, "slot evidence occurrence digest")
    _require_digest(row_digest, "slot evidence row digest")
    _require_exact(direction, CallEffectDirection, "slot evidence direction")
    _require_u64(slot_ordinal, "slot evidence ordinal")
    if type(encoded_slot) is not bytes:
        raise TypeError("encoded slot must be exact bytes")
    return _digest(
        _text(_SLOT_EVIDENCE_DOMAIN)
        + _bytes(occurrence_digest)
        + _bytes(row_digest)
        + _text(_wire_direction(direction))
        + _u64(slot_ordinal)
        + encoded_slot
    )


def configured_effect_debt_digest(
    occurrence_digest: bytes,
    debt: ConfiguredEffectDebt,
) -> bytes:
    _require_digest(occurrence_digest, "debt occurrence digest")
    if type(debt) not in (ConfiguredDirectionDebt, ConfiguredSlotDebt,
                          ConfiguredPieceDebt):
        raise TypeError("configured debt must use an exact debt variant")
    return _digest(_text(_DEBT_DOMAIN) + _bytes(occurrence_digest) + debt.body_bytes())


def configured_fragment_digest(
    occurrence_digest: bytes,
    direction: CallEffectDirection,
    span: ByteSpan,
    contributions: tuple[DeclaredPieceRef, ...],
) -> bytes:
    _require_digest(occurrence_digest, "fragment occurrence digest")
    _require_exact(direction, CallEffectDirection, "fragment digest direction")
    _require_configured_span(span, "fragment digest span")
    _require_ref_tuple(contributions, "fragment digest contributions")
    _require_ref_order(contributions, "fragment digest contributions")
    if not contributions:
        raise ValueError("fragment digest requires contributions")
    if any(ref.direction is not direction for ref in contributions):
        raise ValueError("fragment digest contributions use the wrong direction")
    return _digest(
        _text(_FRAGMENT_DOMAIN)
        + _bytes(occurrence_digest)
        + _text(direction.value)
        + _span(span)
        + _seq(tuple(ref.semantic_bytes() for ref in contributions))
    )


def configured_function_effect_digest(
    seeds: FunctionCallSeedUnit,
    effect_capture_digest: bytes,
    profile_semantic_content_digest: bytes,
    authority_profile_digest: bytes,
    calls: tuple[ConfiguredCallEffectRecordV4, ...],
) -> bytes:
    _require_exact(seeds, FunctionCallSeedUnit, "configured effect digest seeds")
    _require_digest(effect_capture_digest, "configured effect capture digest")
    _require_digest(profile_semantic_content_digest, "configured profile digest")
    _require_digest(authority_profile_digest, "configured authority-profile digest")
    _require_exact_tuple(calls, ConfiguredCallEffectRecordV4,
                         "configured effect digest calls")
    return _digest(
        _text(_FUNCTION_EFFECT_DOMAIN)
        + _u64(CONFIGURED_CALL_EFFECT_CONTRACT_VERSION)
        + _u64(CALL_EFFECT_SCHEMA_VERSION)
        + _u64(CALL_EFFECT_EXPORTER_REVISION)
        + _bytes(seeds.observation_digest)
        + _bytes(seeds.function_scope.digest)
        + _bytes(seeds.canonical_digest)
        + _bytes(effect_capture_digest)
        + _bytes(profile_semantic_content_digest)
        + _bytes(authority_profile_digest)
        + _seq(tuple(call.canonical_bytes() for call in calls))
    )


def _direction_completeness(
    declared_refs: tuple[DeclaredPieceRef, ...],
    accounted_refs: tuple[DeclaredPieceRef, ...],
    debts: tuple[ConfiguredEffectDebt, ...],
    open_variable_tail: bool,
) -> CallEffectCompleteness:
    if (
        declared_refs == accounted_refs
        and not debts
        and open_variable_tail is False
    ):
        return CallEffectCompleteness.COMPLETE
    if accounted_refs:
        return CallEffectCompleteness.PARTIAL
    return CallEffectCompleteness.UNAVAILABLE


def _require_gapless_reconstruction(
    expected: ByteSpan,
    fragments: tuple[ByteSpan, ...],
) -> None:
    _require_configured_span(expected, "reconstructed configured span")
    if type(fragments) is not tuple or any(type(item) is not ByteSpan for item in fragments):
        raise TypeError("reconstruction fragments must be an exact ByteSpan tuple")
    if not fragments:
        raise ValueError("an admitted piece requires fragment reconstruction")
    cursor = expected.start
    for fragment in fragments:
        _require_configured_span(fragment, "reconstruction fragment")
        if fragment.object_id != expected.object_id or fragment.start != cursor:
            raise ValueError("configured fragments do not reconstruct a gapless span")
        if fragment.end > expected.end:
            raise ValueError("configured fragment exceeds its admitted piece")
        cursor = fragment.end
    if cursor != expected.end:
        raise ValueError("configured fragments do not reconstruct the complete span")


def _require_debt_tuple(value: object) -> None:
    if type(value) is not tuple or any(
        type(item) not in (ConfiguredDirectionDebt, ConfiguredSlotDebt, ConfiguredPieceDebt)
        for item in value
    ):
        raise TypeError("configured debts must be an exact closed debt tuple")


def _require_ref_tuple(value: object, label: str) -> None:
    _require_exact_tuple(value, DeclaredPieceRef, label)


def _require_ref_order(value: tuple[DeclaredPieceRef, ...], label: str) -> None:
    keys = tuple(item.canonical_key for item in value)
    identities = tuple(item.identity_key for item in value)
    if keys != tuple(sorted(keys)) or _has_adjacent_duplicate(identities):
        raise ValueError(f"{label} must be unique and piece-key ordered")


def _is_ordered_ref_subset(
    subset: tuple[DeclaredPieceRef, ...],
    superset: tuple[DeclaredPieceRef, ...],
) -> bool:
    subset_index = 0
    superset_index = 0
    while subset_index < len(subset) and superset_index < len(superset):
        subset_key = subset[subset_index].canonical_key
        superset_key = superset[superset_index].canonical_key
        if subset_key == superset_key:
            subset_index += 1
            superset_index += 1
        elif superset_key < subset_key:
            superset_index += 1
        else:
            return False
    return subset_index == len(subset)


def _ordered_ref_difference(
    minuend: tuple[DeclaredPieceRef, ...],
    subtrahend: tuple[DeclaredPieceRef, ...],
) -> tuple[DeclaredPieceRef, ...]:
    result: list[DeclaredPieceRef] = []
    subtrahend_index = 0
    for ref in minuend:
        key = ref.canonical_key
        while (
            subtrahend_index < len(subtrahend)
            and subtrahend[subtrahend_index].canonical_key < key
        ):
            subtrahend_index += 1
        if (
            subtrahend_index < len(subtrahend)
            and subtrahend[subtrahend_index].canonical_key == key
        ):
            subtrahend_index += 1
        else:
            result.append(ref)
    return tuple(result)


def _has_adjacent_duplicate(values: tuple[object, ...]) -> bool:
    return any(values[index - 1] == values[index] for index in range(1, len(values)))


def _wire_direction(value: CallEffectDirection) -> str:
    _require_exact(value, CallEffectDirection, "configured wire direction")
    return "PRE_READ" if value is CallEffectDirection.PRE_READ else "POST_WRITE"


def _require_configured_span(value: object, label: str) -> None:
    _require_exact(value, ByteSpan, label)
    assert isinstance(value, ByteSpan)
    if value.object_id.kind not in (
        StorageObjectKind.REGISTER_FILE,
        StorageObjectKind.ADDRESS_SPACE,
    ):
        raise ValueError(f"{label} must use configured program storage")
    if value.object_id.scope.kind is not StorageScopeKind.PROGRAM:
        raise ValueError(f"{label} must use a program scope")
    for item, item_label in (
        (value.object_id.space_key, "space key"),
        (value.start, "start"),
        (value.size, "size"),
    ):
        _require_u64(item, f"{label} {item_label}")
    if value.end > 1 << 64:
        raise ValueError(f"{label} end exceeds unsigned 64-bit address space")


def _span_key(value: ByteSpan) -> tuple[object, ...]:
    _require_configured_span(value, "configured span key")
    return (
        _storage_kind_rank(value.object_id.kind),
        0,
        value.object_id.scope.digest,
        value.object_id.space_key,
        value.start,
        value.size,
    )


def _span(value: ByteSpan) -> bytes:
    _require_configured_span(value, "encoded configured span")
    return (
        _u64(_storage_kind_rank(value.object_id.kind))
        + _u64(0)
        + _bytes(value.object_id.scope.digest)
        + _u64(value.object_id.space_key)
        + _u64(value.start)
        + _u64(value.size)
    )


def _storage_kind_rank(value: StorageObjectKind) -> int:
    if value is StorageObjectKind.REGISTER_FILE:
        return 0
    if value is StorageObjectKind.ADDRESS_SPACE:
        return 1
    raise ValueError("unsupported configured storage-object kind")


def _direction_rank(value: CallEffectDirection) -> int:
    _require_exact(value, CallEffectDirection, "configured direction rank")
    return 0 if value is CallEffectDirection.PRE_READ else 1


def _digest(value: bytes) -> bytes:
    if type(value) is not bytes:
        raise TypeError("digest preimage must be exact bytes")
    return sha256(value).digest()


def _bool(value: bool) -> bytes:
    _require_bool(value, "encoded boolean")
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


def _require_bool(value: object, label: str) -> None:
    if type(value) is not bool:
        raise TypeError(f"{label} must be an exact bool")


def _require_u64(value: object, label: str) -> None:
    if type(value) is not int:
        raise TypeError(f"{label} must be an exact int")
    if not 0 <= value <= _U64_MAX:
        raise ValueError(f"{label} exceeds unsigned 64-bit")


def _require_digest(value: object, label: str) -> None:
    if type(value) is not bytes:
        raise TypeError(f"{label} must be exact bytes")
    if len(value) != 32:
        raise ValueError(f"{label} must contain exactly 32 bytes")


__all__ = (
    "CONFIGURED_CALL_EFFECT_CONTRACT_VERSION",
    "MAX_CONFIGURED_CALL_FRAGMENTS",
    "MAX_CONFIGURED_CALL_ENDPOINTS",
    "MAX_CONFIGURED_CALL_DEBTS",
    "MAX_CONFIGURED_CALL_DECLARED_PIECES",
    "MAX_CONFIGURED_CALL_PORTS",
    "MAX_CONFIGURED_CALL_RELATIONS",
    "MAX_CONFIGURED_DIRECTION_DECLARED_PIECES",
    "MAX_CONFIGURED_DIRECTION_DEBTS",
    "MAX_CONFIGURED_DIRECTION_FRAGMENTS",
    "MAX_CONFIGURED_DIRECTION_ENDPOINTS",
    "MAX_CONFIGURED_DIRECTION_PORTS",
    "MAX_CONFIGURED_FRAGMENT_CONTRIBUTORS",
    "MAX_CONFIGURED_FUNCTION_DECLARED_PIECES",
    "MAX_CONFIGURED_FUNCTION_FRAGMENTS_AND_DEBTS",
    "MAX_CONFIGURED_FUNCTION_RELATIONS",
    "CallEffectEvidence",
    "CanonicalConfiguredFragment",
    "ConfiguredCallEffectRecordV4",
    "ConfiguredDirectionDebt",
    "ConfiguredDirectionDebtReason",
    "ConfiguredDirectionalCallEffectV4",
    "ConfiguredEffectDebt",
    "ConfiguredFunctionCallEffectEvidenceV4",
    "ConfiguredPieceDebt",
    "ConfiguredPieceDebtReason",
    "ConfiguredSlotDebt",
    "ConfiguredSlotDebtReason",
    "DirectionalPieceCoverage",
    "FunctionCallEffectEvidenceV3",
    "configured_effect_debt_digest",
    "configured_fragment_digest",
    "configured_function_effect_digest",
    "coverage_citation_digest",
    "slot_evidence_digest",
)
