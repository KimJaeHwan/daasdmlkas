"""Architect-owned neutral call-effect evidence and binding contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
from typing import TypeAlias

from .call_contracts import CallOccurrenceId, FunctionCallSeedUnit
from .model import ByteSpan, StorageScopeId, StorageScopeKind
from ._scope_contracts import ValidatedVarnode


CALL_EFFECT_CONTRACT_VERSION = 3
MAX_CALL_EFFECT_PORTS = 256
MAX_CALL_EFFECT_DEBTS = 2_048


class CallEffectDirection(StrEnum):
    PRE_READ = "pre_read"
    POST_WRITE = "post_write"


class CallEffectCompleteness(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    CONFLICT = "conflict"


class CallEffectEvidenceKind(StrEnum):
    CONFIGURED = "configured"
    UNCONFIGURED_UNAVAILABLE = "unconfigured_unavailable"


class RawCallPortRole(StrEnum):
    INPUT = "input"
    OUTPUT = "output"


class CallEffectDebtReason(StrEnum):
    UNCONFIGURED_EVIDENCE = "unconfigured_evidence"
    NO_INTERFACE_SUBJECT = "no_interface_subject"
    ABSENT_MODEL = "absent_model"
    INCOMPATIBLE_MODEL_CLAIMS = "incompatible_model_claims"
    ERROR_PLACEHOLDER_MODEL = "error_placeholder_model"
    UNKNOWN_CONVENTION = "unknown_convention"
    OVERRIDE_ABSENCE_UNPROVED = "override_absence_unproved"
    CALL_OVERRIDE_PRESENT = "call_override_present"
    CUSTOM_STORAGE_CONTRADICTION = "custom_storage_contradiction"
    ASSIGNMENT_FAILURE = "assignment_failure"
    SOURCE_QUALITY_BELOW_THRESHOLD = "source_quality_below_threshold"
    FORMAL_CORRELATION_FAILURE = "formal_correlation_failure"
    AUTO_CORRELATION_FAILURE = "auto_correlation_failure"
    UNSUPPORTED_STORAGE = "unsupported_storage"
    STACK_PROJECTION_REQUIRED = "stack_projection_required"
    FORCED_INDIRECT_RESULT = "forced_indirect_result"
    HIDDEN_COMPOUND_RESULT = "hidden_compound_result"
    VARARGS_UNOBSERVED = "varargs_unobserved"
    UNASSIGNED_PIECE = "unassigned_piece"


class _CallStorageAuthority:
    __slots__ = ()


_CALL_STORAGE_AUTHORITY = _CallStorageAuthority()


class _CallStoragePermit:
    __slots__ = ("_active", "_payload_digest")

    def __init__(
        self,
        authority: _CallStorageAuthority,
        payload_digest: bytes,
    ) -> None:
        if authority is not _CALL_STORAGE_AUTHORITY:
            raise PermissionError("call-storage permits are architect-owned")
        _require_digest(payload_digest, "call-storage permit payload")
        self._active = True
        self._payload_digest = payload_digest

    def consume(self, payload_digest: bytes) -> None:
        if self._active is not True:
            raise RuntimeError("call-storage permit is inactive")
        _require_digest(payload_digest, "call-storage construction payload")
        if payload_digest != self._payload_digest:
            raise PermissionError("call-storage permit is bound to other evidence")
        self._active = False

    def revoke(self) -> None:
        self._active = False

    def __reduce_ex__(self, protocol: int):
        raise TypeError("call-storage permits cannot be serialized")


def _mint_call_storage_permit(payload_digest: bytes) -> _CallStoragePermit:
    return _CallStoragePermit(_CALL_STORAGE_AUTHORITY, payload_digest)


@dataclass(frozen=True, slots=True, init=False)
class ValidatedCallStoragePiece:
    span: ByteSpan
    authority_digest: bytes
    claim_digest: bytes

    @classmethod
    def _create(
        cls,
        span: ByteSpan,
        authority_digest: bytes,
        claim_digest: bytes,
        permit: _CallStoragePermit,
    ) -> "ValidatedCallStoragePiece":
        _require_exact(permit, _CallStoragePermit, "call-storage permit")
        permit.consume(_call_storage_piece_digest(span, authority_digest, claim_digest))
        value = object.__new__(cls)
        object.__setattr__(value, "span", span)
        object.__setattr__(value, "authority_digest", authority_digest)
        object.__setattr__(value, "claim_digest", claim_digest)
        value._validate()
        return value

    def _validate(self) -> None:
        _require_exact(self.span, ByteSpan, "validated call-storage span")
        _require_digest(self.authority_digest, "call-storage authority digest")
        _require_digest(self.claim_digest, "call-storage claim digest")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (*self.span.canonical_key, self.authority_digest, self.claim_digest)

    def __reduce_ex__(self, protocol: int):
        raise TypeError("validated call-storage pieces cannot be serialized")


@dataclass(frozen=True, slots=True)
class RawObservedCallPort:
    occurrence: CallOccurrenceId
    role: RawCallPortRole
    input_ordinal: int | None
    varnode: ValidatedVarnode
    span: ByteSpan
    observation_digest: bytes
    raw_port_ordinal: int

    def __post_init__(self) -> None:
        _require_exact(self.occurrence, CallOccurrenceId, "raw port occurrence")
        _require_exact(self.role, RawCallPortRole, "raw port role")
        _require_exact(self.varnode, ValidatedVarnode, "raw port varnode")
        _require_exact(self.span, ByteSpan, "raw port span")
        _require_digest(self.observation_digest, "raw port observation digest")
        _require_u64(self.raw_port_ordinal, "raw port ordinal")
        if self.role is RawCallPortRole.INPUT:
            _require_u64(self.input_ordinal, "raw input ordinal")
            if self.input_ordinal == 0:
                raise ValueError("raw selector input cannot become a storage port")
        elif self.input_ordinal is not None:
            raise ValueError("raw output ports cannot invent an input ordinal")

    @property
    def direction(self) -> CallEffectDirection:
        if self.role is RawCallPortRole.INPUT:
            return CallEffectDirection.PRE_READ
        return CallEffectDirection.POST_WRITE

    @property
    def canonical_digest(self) -> bytes:
        return _digest(_raw_port_payload(self))

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (
            _direction_rank(self.direction),
            0,
            self.raw_port_ordinal,
            0,
            self.canonical_digest,
        )


@dataclass(frozen=True, slots=True)
class ConfiguredCallEffectContribution:
    slot_ordinal: int
    claim_digest: bytes

    def __post_init__(self) -> None:
        _require_u64(self.slot_ordinal, "configured contribution slot ordinal")
        _require_digest(self.claim_digest, "configured contribution claim digest")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (self.slot_ordinal, self.claim_digest)


@dataclass(frozen=True, slots=True)
class ConfiguredCallEffectPort:
    occurrence: CallOccurrenceId
    direction: CallEffectDirection
    fragment_ordinal: int
    piece: ValidatedCallStoragePiece
    effect_evidence_digest: bytes
    contributions: tuple[ConfiguredCallEffectContribution, ...]

    def __post_init__(self) -> None:
        _require_exact(self.occurrence, CallOccurrenceId, "configured port occurrence")
        _require_exact(self.direction, CallEffectDirection, "configured port direction")
        _require_u64(self.fragment_ordinal, "configured fragment ordinal")
        _require_exact(self.piece, ValidatedCallStoragePiece, "configured port piece")
        self.piece._validate()
        _require_digest(self.effect_evidence_digest, "configured effect digest")
        _require_exact_tuple(
            self.contributions,
            ConfiguredCallEffectContribution,
            "configured contributions",
        )
        if not self.contributions:
            raise ValueError("configured port requires at least one contribution")
        _require_strictly_increasing(
            (item.canonical_key for item in self.contributions),
            "configured contributions",
        )
        if self.piece.claim_digest not in self.contributing_claim_digests:
            raise ValueError("configured port must retain its validated claim")

    @property
    def span(self) -> ByteSpan:
        return self.piece.span

    @property
    def slot_ordinals(self) -> tuple[int, ...]:
        return tuple(sorted({item.slot_ordinal for item in self.contributions}))

    @property
    def contributing_claim_digests(self) -> tuple[bytes, ...]:
        return tuple(sorted({item.claim_digest for item in self.contributions}))

    @property
    def canonical_digest(self) -> bytes:
        return _digest(_configured_port_payload(self, include_effect_digest=True))

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (
            _direction_rank(self.direction),
            1,
            self.slot_ordinals,
            self.fragment_ordinal,
            _digest(_configured_port_payload(self, include_effect_digest=False)),
        )


@dataclass(frozen=True, slots=True)
class DirectionalCallInterfaceCoverage:
    """Cited declared-slot accounting for one independently judged direction."""

    direction: CallEffectDirection
    declared_slot_ordinals: tuple[int, ...]
    accounted_slot_ordinals: tuple[int, ...]
    varargs_omitted: bool
    authority_digest: bytes
    citation_digest: bytes

    def __post_init__(self) -> None:
        _require_exact(self.direction, CallEffectDirection, "coverage direction")
        _require_u64_tuple(self.declared_slot_ordinals, "declared slot ordinals")
        _require_u64_tuple(self.accounted_slot_ordinals, "accounted slot ordinals")
        if not set(self.accounted_slot_ordinals).issubset(
            self.declared_slot_ordinals
        ):
            raise ValueError("accounted slots must belong to the declared inventory")
        if type(self.varargs_omitted) is not bool:
            raise TypeError("varargs omission must be an exact bool")
        _require_digest(self.authority_digest, "coverage authority digest")
        _require_digest(self.citation_digest, "coverage citation digest")

    @property
    def is_complete(self) -> bool:
        return (
            self.accounted_slot_ordinals == self.declared_slot_ordinals
            and not self.varargs_omitted
        )

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (
            _direction_rank(self.direction),
            self.declared_slot_ordinals,
            self.accounted_slot_ordinals,
            self.varargs_omitted,
            self.authority_digest,
            self.citation_digest,
        )


CallEffectPort: TypeAlias = ConfiguredCallEffectPort | RawObservedCallPort


@dataclass(frozen=True, slots=True)
class DirectionalCallEffectDebt:
    occurrence: CallOccurrenceId
    direction: CallEffectDirection
    reason: CallEffectDebtReason
    slot_ordinal: int | None
    authority_digest: bytes
    evidence_digest: bytes

    def __post_init__(self) -> None:
        _require_exact(self.occurrence, CallOccurrenceId, "call debt occurrence")
        _require_exact(self.direction, CallEffectDirection, "call debt direction")
        _require_exact(self.reason, CallEffectDebtReason, "call debt reason")
        if self.slot_ordinal is not None:
            _require_u64(self.slot_ordinal, "call debt slot ordinal")
        _require_digest(self.authority_digest, "call debt authority digest")
        _require_digest(self.evidence_digest, "call debt evidence digest")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (
            _direction_rank(self.direction),
            -1 if self.slot_ordinal is None else self.slot_ordinal,
            self.reason.value,
            self.authority_digest,
            self.evidence_digest,
        )


@dataclass(frozen=True, slots=True)
class CallEffectRecord:
    occurrence: CallOccurrenceId
    pre_read_completeness: CallEffectCompleteness
    post_write_completeness: CallEffectCompleteness
    ports: tuple[CallEffectPort, ...]
    debts: tuple[DirectionalCallEffectDebt, ...]
    pre_read_coverage: DirectionalCallInterfaceCoverage | None = None
    post_write_coverage: DirectionalCallInterfaceCoverage | None = None

    def __post_init__(self) -> None:
        _require_exact(self.occurrence, CallOccurrenceId, "call effect occurrence")
        _require_exact(
            self.pre_read_completeness,
            CallEffectCompleteness,
            "pre-read completeness",
        )
        _require_exact(
            self.post_write_completeness,
            CallEffectCompleteness,
            "post-write completeness",
        )
        if CallEffectCompleteness.CONFLICT in (
            self.pre_read_completeness,
            self.post_write_completeness,
        ):
            raise ValueError("call-effect schema version 1 cannot admit conflicts")
        _require_union_tuple(
            self.ports,
            (ConfiguredCallEffectPort, RawObservedCallPort),
            "call effect ports",
        )
        _require_exact_tuple(
            self.debts, DirectionalCallEffectDebt, "call effect debts"
        )
        if len(self.ports) > MAX_CALL_EFFECT_PORTS:
            raise ValueError("call effect port count exceeds the configured bound")
        if len(self.debts) > MAX_CALL_EFFECT_DEBTS:
            raise ValueError("call effect debt count exceeds the configured bound")
        if any(port.occurrence != self.occurrence for port in self.ports):
            raise ValueError("call effect ports must bind the exact occurrence")
        if any(debt.occurrence != self.occurrence for debt in self.debts):
            raise ValueError("call effect debts must bind the exact occurrence")
        _require_strictly_increasing(
            (port.canonical_key for port in self.ports), "call effect ports"
        )
        _require_strictly_increasing(
            (debt.canonical_key for debt in self.debts), "call effect debts"
        )
        self._validate_direction(CallEffectDirection.PRE_READ)
        self._validate_direction(CallEffectDirection.POST_WRITE)
        self._validate_configured_fragments()
        raw_ordinals = tuple(
            port.raw_port_ordinal
            for port in self.ports
            if type(port) is RawObservedCallPort
        )
        if raw_ordinals != tuple(range(len(raw_ordinals))):
            raise ValueError("raw call-port ordinals must be gap-free")
        coverages = tuple(
            value
            for value in (self.pre_read_coverage, self.post_write_coverage)
            if value is not None
        )
        if len({value.authority_digest for value in coverages}) > 1:
            raise ValueError("one call occurrence cannot mix interface authorities")

    def completeness(self, direction: CallEffectDirection) -> CallEffectCompleteness:
        _require_exact(direction, CallEffectDirection, "call effect direction")
        if direction is CallEffectDirection.PRE_READ:
            return self.pre_read_completeness
        return self.post_write_completeness

    def _validate_direction(self, direction: CallEffectDirection) -> None:
        state = self.completeness(direction)
        coverage = (
            self.pre_read_coverage
            if direction is CallEffectDirection.PRE_READ
            else self.post_write_coverage
        )
        if coverage is not None:
            _require_exact(
                coverage,
                DirectionalCallInterfaceCoverage,
                "directional call-interface coverage",
            )
            if coverage.direction is not direction:
                raise ValueError("call-interface coverage uses the wrong direction")
        configured = tuple(
            port
            for port in self.ports
            if type(port) is ConfiguredCallEffectPort and port.direction is direction
        )
        debt = tuple(item for item in self.debts if item.direction is direction)
        if configured and coverage is None:
            raise ValueError("configured call-effect pieces require cited slot coverage")
        if coverage is not None:
            configured_slots = tuple(
                sorted(
                    {
                        slot
                        for port in configured
                        for slot in port.slot_ordinals
                    }
                )
            )
            if configured_slots != coverage.accounted_slot_ordinals:
                raise ValueError(
                    "accounted slots must exactly match configured call-effect pieces"
                )
            if any(
                port.piece.authority_digest != coverage.authority_digest
                for port in configured
            ):
                raise ValueError(
                    "configured call-effect pieces must use the coverage authority"
                )
            declared = set(coverage.declared_slot_ordinals)
            debt_slots = {
                item.slot_ordinal for item in debt if item.slot_ordinal is not None
            }
            if not debt_slots.issubset(declared):
                raise ValueError("directional debt slots must belong to coverage")
            missing = declared - set(coverage.accounted_slot_ordinals)
            if any(
                item.slot_ordinal is not None
                and item.authority_digest != coverage.authority_digest
                for item in debt
            ):
                raise ValueError("directional slot debt must use the coverage authority")
            if state is CallEffectCompleteness.PARTIAL and not missing.issubset(
                debt_slots
            ):
                raise ValueError("every missing interface slot requires exact debt")
        if state is CallEffectCompleteness.COMPLETE:
            if debt:
                raise ValueError("complete call-effect directions cannot retain debt")
            if coverage is None or not coverage.is_complete:
                raise ValueError(
                    "complete call-effect directions require exact cited slot coverage"
                )
            if coverage.declared_slot_ordinals and not configured:
                raise ValueError(
                    "nonempty complete coverage requires an admitted configured piece"
                )
        if state is CallEffectCompleteness.PARTIAL and (not configured or not debt):
            raise ValueError("partial call-effect directions require a piece and debt")
        if state is CallEffectCompleteness.PARTIAL and (
            coverage is None or coverage.is_complete
        ):
            raise ValueError("partial call-effect directions require incomplete coverage")
        if state is CallEffectCompleteness.UNAVAILABLE and (configured or not debt):
            raise ValueError(
                "unavailable call-effect directions require debt and no admitted piece"
            )

    def _validate_configured_fragments(self) -> None:
        for direction in CallEffectDirection:
            values = tuple(
                port
                for port in self.ports
                if type(port) is ConfiguredCallEffectPort
                and port.direction is direction
            )
            if tuple(port.fragment_ordinal for port in values) != tuple(
                range(len(values))
            ):
                raise ValueError("configured fragment ordinals must be gap-free")
            ordered = sorted(
                values,
                key=lambda port: port.span.canonical_key,
            )
            for left, right in zip(ordered, ordered[1:]):
                if left.span.overlaps(right.span):
                    raise ValueError("configured fragments must be disjoint")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (
            self.occurrence.function_scope.digest,
            self.occurrence.instruction.space_id,
            self.occurrence.instruction.byte_offset,
            self.occurrence.operation_ordinal,
        )


class _CallEffectAuthority:
    __slots__ = ()


_CALL_EFFECT_AUTHORITY = _CallEffectAuthority()


class _CallEffectPermit:
    __slots__ = ("_active", "_payload_digest", "_seeds")

    def __init__(
        self,
        authority: _CallEffectAuthority,
        seeds: FunctionCallSeedUnit,
        payload_digest: bytes,
    ) -> None:
        if authority is not _CALL_EFFECT_AUTHORITY:
            raise PermissionError("call-effect permits are architect-owned")
        _require_exact(seeds, FunctionCallSeedUnit, "call-effect permit seeds")
        _require_digest(payload_digest, "call-effect permit payload")
        self._active = True
        self._seeds = seeds
        self._payload_digest = payload_digest

    def consume(self, seeds: FunctionCallSeedUnit, payload_digest: bytes) -> None:
        if self._active is not True:
            raise RuntimeError("call-effect permit is inactive")
        _require_exact(seeds, FunctionCallSeedUnit, "call-effect construction seeds")
        _require_digest(payload_digest, "call-effect construction payload")
        if seeds is not self._seeds or payload_digest != self._payload_digest:
            raise PermissionError("call-effect permit is bound to other evidence")
        self._active = False

    def revoke(self) -> None:
        self._active = False

    def __reduce_ex__(self, protocol: int):
        raise TypeError("call-effect permits cannot be serialized")


def _mint_call_effect_permit(
    seeds: FunctionCallSeedUnit,
    payload_digest: bytes,
) -> _CallEffectPermit:
    return _CallEffectPermit(_CALL_EFFECT_AUTHORITY, seeds, payload_digest)


@dataclass(frozen=True, slots=True, init=False)
class FunctionCallEffectEvidence:
    contract_version: int
    kind: CallEffectEvidenceKind
    seeds: FunctionCallSeedUnit
    effect_evidence_digest: bytes
    calls: tuple[CallEffectRecord, ...]

    @classmethod
    def _create(
        cls,
        contract_version: int,
        kind: CallEffectEvidenceKind,
        seeds: FunctionCallSeedUnit,
        effect_evidence_digest: bytes,
        calls: tuple[CallEffectRecord, ...],
        permit: _CallEffectPermit,
    ) -> "FunctionCallEffectEvidence":
        _require_exact(permit, _CallEffectPermit, "call-effect permit")
        permit.consume(seeds, effect_evidence_digest)
        value = object.__new__(cls)
        object.__setattr__(value, "contract_version", contract_version)
        object.__setattr__(value, "kind", kind)
        object.__setattr__(value, "seeds", seeds)
        object.__setattr__(value, "effect_evidence_digest", effect_evidence_digest)
        object.__setattr__(value, "calls", calls)
        value._validate()
        return value

    def _validate(self) -> None:
        if type(self.contract_version) is not int:
            raise TypeError("call-effect contract version must be an exact int")
        if self.contract_version != CALL_EFFECT_CONTRACT_VERSION:
            raise ValueError("unsupported call-effect contract version")
        _require_exact(self.kind, CallEffectEvidenceKind, "call-effect evidence kind")
        _require_exact(self.seeds, FunctionCallSeedUnit, "call-effect seeds")
        _require_digest(self.effect_evidence_digest, "call-effect evidence digest")
        _require_exact_tuple(self.calls, CallEffectRecord, "call effect records")
        _require_strictly_increasing(
            (record.canonical_key for record in self.calls), "call effect records"
        )
        if len(self.calls) != len(self.seeds.callsites) or any(
            record.occurrence != seed.occurrence
            for record, seed in zip(self.calls, self.seeds.callsites, strict=True)
        ):
            raise ValueError("call-effect records must exactly cover the retained seeds")
        if any(record.occurrence.function_scope != self.function_scope for record in self.calls):
            raise ValueError("call effect records must use the evidence function scope")
        _validate_raw_port_inventory(self.seeds, self.calls)
        raw_observation_digests = {
            port.observation_digest
            for record in self.calls
            for port in record.ports
            if type(port) is RawObservedCallPort
        }
        if raw_observation_digests and raw_observation_digests != {
            self.observation_digest
        }:
            raise ValueError(
                "raw call ports must retain the exact function observation digest"
            )
        configured_digests = {
            port.effect_evidence_digest
            for record in self.calls
            for port in record.ports
            if type(port) is ConfiguredCallEffectPort
        }
        if configured_digests and configured_digests != {self.effect_evidence_digest}:
            raise ValueError("configured ports must retain the exact function effect digest")
        if self.kind is CallEffectEvidenceKind.UNCONFIGURED_UNAVAILABLE:
            self._validate_unconfigured_shape()
        expected = _function_effect_digest(
            self.kind,
            self.seeds,
            self.calls,
        )
        if self.effect_evidence_digest != expected:
            raise ValueError("call-effect evidence digest does not match its payload")

    def _validate_unconfigured_shape(self) -> None:
        for record in self.calls:
            if (
                record.pre_read_completeness
                is not CallEffectCompleteness.UNAVAILABLE
                or record.post_write_completeness
                is not CallEffectCompleteness.UNAVAILABLE
                or record.pre_read_coverage is not None
                or record.post_write_coverage is not None
            ):
                raise ValueError(
                    "unconfigured evidence requires unavailable uncovered directions"
                )
            if any(type(port) is not RawObservedCallPort for port in record.ports):
                raise ValueError("unconfigured evidence cannot contain configured ports")
            if len(record.debts) != 2 or tuple(
                debt.direction for debt in record.debts
            ) != tuple(CallEffectDirection):
                raise ValueError(
                    "unconfigured evidence requires one debt for each direction"
                )
            if any(
                debt.reason is not CallEffectDebtReason.UNCONFIGURED_EVIDENCE
                for debt in record.debts
            ):
                raise ValueError("unconfigured evidence requires explicit unconfigured debt")

    @property
    def canonical_digest(self) -> bytes:
        return self.effect_evidence_digest

    @property
    def function_scope(self) -> StorageScopeId:
        return self.seeds.function_scope

    @property
    def observation_digest(self) -> bytes:
        return self.seeds.observation_digest

    @property
    def seed_digest(self) -> bytes:
        return self.seeds.canonical_digest

    def __reduce_ex__(self, protocol: int):
        raise TypeError("configured call-effect evidence cannot be serialized")


def unavailable_call_effect_evidence(
    seeds: FunctionCallSeedUnit,
    /,
    *,
    raw_ports: tuple[RawObservedCallPort, ...] = (),
) -> FunctionCallEffectEvidence:
    """Create explicit raw-only compatibility evidence without configured authority."""
    _require_exact(seeds, FunctionCallSeedUnit, "unconfigured call-effect seeds")
    _require_exact_tuple(raw_ports, RawObservedCallPort, "unconfigured raw ports")
    raw_by_occurrence: dict[CallOccurrenceId, list[RawObservedCallPort]] = {
        seed.occurrence: [] for seed in seeds.callsites
    }
    for port in raw_ports:
        try:
            raw_by_occurrence[port.occurrence].append(port)
        except KeyError as exc:
            raise ValueError("raw call port does not belong to the retained seeds") from exc
    authority_digest = _digest(
        [
            "tdo-v2-unconfigured-call-authority-v3",
            seeds.function_scope.digest.hex(),
            seeds.observation_digest.hex(),
            seeds.canonical_digest.hex(),
        ]
    )
    calls = []
    for seed in seeds.callsites:
        occurrence = seed.occurrence
        debts = tuple(
            DirectionalCallEffectDebt(
                occurrence,
                direction,
                CallEffectDebtReason.UNCONFIGURED_EVIDENCE,
                None,
                authority_digest,
                _digest(
                    [
                        "tdo-v2-unconfigured-call-debt-v1",
                        occurrence.occurrence_digest.hex(),
                        direction.value,
                    ]
                ),
            )
            for direction in CallEffectDirection
        )
        calls.append(
            CallEffectRecord(
                occurrence,
                CallEffectCompleteness.UNAVAILABLE,
                CallEffectCompleteness.UNAVAILABLE,
                tuple(raw_by_occurrence[occurrence]),
                debts,
            )
        )
    records = tuple(calls)
    _validate_raw_port_inventory(seeds, records)
    digest = _function_effect_digest(
        CallEffectEvidenceKind.UNCONFIGURED_UNAVAILABLE,
        seeds,
        records,
    )
    permit = _mint_call_effect_permit(seeds, digest)
    try:
        return FunctionCallEffectEvidence._create(
            CALL_EFFECT_CONTRACT_VERSION,
            CallEffectEvidenceKind.UNCONFIGURED_UNAVAILABLE,
            seeds,
            digest,
            records,
            permit,
        )
    finally:
        permit.revoke()


def _function_effect_digest(
    kind: CallEffectEvidenceKind,
    seeds: FunctionCallSeedUnit,
    calls: tuple[CallEffectRecord, ...],
) -> bytes:
    _require_exact(seeds, FunctionCallSeedUnit, "call-effect digest seeds")
    _require_exact(kind, CallEffectEvidenceKind, "call-effect digest kind")
    _require_exact_tuple(calls, CallEffectRecord, "call-effect digest records")
    if kind is CallEffectEvidenceKind.UNCONFIGURED_UNAVAILABLE:
        return _digest(
            [
                "tdo-v2-call-effect-unavailable-v3",
                seeds.function_scope.digest.hex(),
                seeds.observation_digest.hex(),
                seeds.canonical_digest.hex(),
                [_call_effect_record_payload(record) for record in calls],
            ]
        )
    return _digest(
        [
            "tdo-v2-call-effect-configured-v3",
            seeds.function_scope.digest.hex(),
            seeds.observation_digest.hex(),
            seeds.canonical_digest.hex(),
            [_call_effect_record_payload(record) for record in calls],
        ]
    )


def _call_effect_record_payload(record: CallEffectRecord) -> list[object]:
    return [
        record.occurrence.occurrence_digest.hex(),
        record.pre_read_completeness.value,
        record.post_write_completeness.value,
        [
            _configured_port_payload(port, include_effect_digest=False)
            if type(port) is ConfiguredCallEffectPort
            else _raw_port_payload(port)
            for port in record.ports
        ],
        [
            [
                debt.direction.value,
                debt.reason.value,
                debt.slot_ordinal,
                debt.authority_digest.hex(),
                debt.evidence_digest.hex(),
            ]
            for debt in record.debts
        ],
        _coverage_payload(record.pre_read_coverage),
        _coverage_payload(record.post_write_coverage),
    ]


def _coverage_payload(
    value: DirectionalCallInterfaceCoverage | None,
) -> list[object] | None:
    if value is None:
        return None
    return [
        value.direction.value,
        list(value.declared_slot_ordinals),
        list(value.accounted_slot_ordinals),
        value.varargs_omitted,
        value.authority_digest.hex(),
        value.citation_digest.hex(),
    ]


def _validate_raw_port_inventory(
    seeds: FunctionCallSeedUnit,
    records: tuple[CallEffectRecord, ...],
) -> None:
    for seed, record in zip(seeds.callsites, records, strict=True):
        raw_ports = tuple(
            port for port in record.ports if type(port) is RawObservedCallPort
        )
        for port in raw_ports:
            if port.observation_digest != seeds.observation_digest:
                raise ValueError("raw call port uses another observation")
            if port.span.size != port.varnode.byte_size:
                raise ValueError("raw call port span must preserve varnode width")
            if port.role is RawCallPortRole.INPUT:
                ordinal = port.input_ordinal
                assert ordinal is not None
                if ordinal >= len(seed.inputs) or port.varnode is not seed.inputs[ordinal]:
                    raise ValueError("raw input port must match its exact seed operand")
            elif seed.explicit_output is None or port.varnode is not seed.explicit_output:
                raise ValueError("raw output port must match the exact seed output")
        descriptors = tuple(
            (port.role, port.input_ordinal) for port in raw_ports
        )
        if len(set(descriptors)) != len(descriptors):
            raise ValueError("raw call ports cannot duplicate an operand or output")
        input_ordinals = tuple(
            port.input_ordinal
            for port in raw_ports
            if port.role is RawCallPortRole.INPUT
        )
        if input_ordinals != tuple(sorted(input_ordinals)):
            raise ValueError("raw input ports must follow exact seed operand order")


def _configured_port_payload(
    value: ConfiguredCallEffectPort, *, include_effect_digest: bool
) -> list[object]:
    payload = [
        "tdo-v2-configured-call-port-v2",
        value.occurrence.occurrence_digest.hex(),
        value.direction.value,
        value.fragment_ordinal,
        list(value.span.canonical_key),
        value.piece.authority_digest.hex(),
        value.piece.claim_digest.hex(),
        [
            [item.slot_ordinal, item.claim_digest.hex()]
            for item in value.contributions
        ],
    ]
    if include_effect_digest:
        payload.append(value.effect_evidence_digest.hex())
    return payload


def _raw_port_payload(value: RawObservedCallPort) -> list[object]:
    return [
        "tdo-v2-raw-call-port-v1",
        value.occurrence.occurrence_digest.hex(),
        value.role.value,
        value.direction.value,
        value.input_ordinal,
        [
            int(value.varnode.kind),
            value.varnode.coordinate.space_id,
            value.varnode.coordinate.byte_offset,
            value.varnode.byte_size,
        ],
        list(value.span.canonical_key),
        value.observation_digest.hex(),
        value.raw_port_ordinal,
    ]


def _digest(payload: object) -> bytes:
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    ).digest()


def _direction_rank(value: CallEffectDirection) -> int:
    if value is CallEffectDirection.PRE_READ:
        return 0
    return 1


def _require_exact(value: object, expected: type, label: str) -> None:
    if type(value) is not expected:
        raise TypeError(f"{label} must be an exact {expected.__name__}")


def _require_u64(value: object, label: str) -> None:
    if type(value) is not int:
        raise TypeError(f"{label} must be an exact int")
    if not 0 <= value < 1 << 64:
        raise ValueError(f"{label} must fit unsigned 64-bit")


def _require_digest(value: object, label: str) -> None:
    if type(value) is not bytes:
        raise TypeError(f"{label} must be exact bytes")
    if len(value) != 32:
        raise ValueError(f"{label} must contain exactly 32 bytes")
    if value == bytes(32):
        raise ValueError(f"{label} cannot use the zero sentinel")


def _require_digest_tuple(value: object, label: str, *, nonempty: bool) -> None:
    if type(value) is not tuple:
        raise TypeError(f"{label} must be an exact tuple")
    for item in value:
        _require_digest(item, label)
    if nonempty and not value:
        raise ValueError(f"{label} must not be empty")
    if tuple(sorted(set(value))) != value:
        raise ValueError(f"{label} must be sorted and unique")


def _require_u64_tuple(value: object, label: str) -> None:
    if type(value) is not tuple:
        raise TypeError(f"{label} must be an exact tuple")
    for item in value:
        _require_u64(item, label)
    if tuple(sorted(set(value))) != value:
        raise ValueError(f"{label} must be sorted and unique")


def _call_storage_piece_digest(
    span: ByteSpan,
    authority_digest: bytes,
    claim_digest: bytes,
) -> bytes:
    _require_exact(span, ByteSpan, "call-storage piece span")
    _require_digest(authority_digest, "call-storage piece authority")
    _require_digest(claim_digest, "call-storage piece claim")
    return _digest(
        [
            "tdo-v2-call-storage-piece-v1",
            list(span.canonical_key),
            authority_digest.hex(),
            claim_digest.hex(),
        ]
    )


def _require_exact_tuple(value: object, expected: type, label: str) -> None:
    if type(value) is not tuple or any(type(item) is not expected for item in value):
        raise TypeError(f"{label} must be an exact {expected.__name__} tuple")


def _require_union_tuple(value: object, expected: tuple[type, ...], label: str) -> None:
    if type(value) is not tuple or any(type(item) not in expected for item in value):
        raise TypeError(f"{label} must use exact closed-union variants")


def _require_strictly_increasing(values, label: str) -> None:
    marker = object()
    previous = marker
    for value in values:
        if previous is not marker and value <= previous:
            raise ValueError(f"{label} must be canonically sorted and unique")
        previous = value


__all__ = (
    "CALL_EFFECT_CONTRACT_VERSION",
    "CallEffectCompleteness",
    "ConfiguredCallEffectContribution",
    "CallEffectDebtReason",
    "CallEffectDirection",
    "CallEffectEvidenceKind",
    "CallEffectPort",
    "CallEffectRecord",
    "ConfiguredCallEffectPort",
    "DirectionalCallInterfaceCoverage",
    "DirectionalCallEffectDebt",
    "FunctionCallEffectEvidence",
    "RawCallPortRole",
    "RawObservedCallPort",
    "ValidatedCallStoragePiece",
    "unavailable_call_effect_evidence",
)
