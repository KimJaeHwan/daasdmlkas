"""Architect-owned immutable contracts for observed call transitions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
from typing import TypeAlias

from .model import (
    StorageScopeId,
    StorageScopeKind,
)
from ._scope_contracts import (
    AddressCoordinate,
    FunctionScopeEvidence,
    ValidatedVarnode,
    VarnodeKindCode,
)
from ._scope_results import (
    ConstructedFunctionScope,
    ScopeBundleResult,
    UnresolvedFunctionScope,
)
from ._scope_wire import _derive_function_scope


CALL_OBSERVATION_CONTRACT_VERSION = 2
CALL_OCCURRENCE_CONTRACT_VERSION = 1


class CallOperationKind(StrEnum):
    DIRECT = "direct"
    INDIRECT = "indirect"


class CallTargetFailureReason(StrEnum):
    MISSING_SELECTOR = "missing_selector"
    DIRECT_SELECTOR_NOT_ADDRESS = "direct_selector_not_address"


class CalleeEffectCompleteness(StrEnum):
    UNOBSERVED = "unobserved"


class CallSeedFailureReason(StrEnum):
    MISSING_VALIDATED_OBSERVATION = "missing_validated_observation"
    MISSING_CONSTRUCTED_FUNCTION_SCOPE = "missing_constructed_function_scope"


@dataclass(frozen=True, order=True, slots=True)
class CallSiteLocator:
    function_scope: StorageScopeId
    instruction: AddressCoordinate
    operation_ordinal: int

    def __post_init__(self) -> None:
        _require_function_scope(self.function_scope, "callsite function scope")
        _require_exact(self.instruction, AddressCoordinate, "callsite instruction")
        _require_nonnegative_int(self.operation_ordinal, "callsite operation ordinal")


@dataclass(frozen=True, slots=True)
class CallOccurrenceId:
    """One canonical raw CALL/CALLIND occurrence, independent of target policy."""

    function_scope: StorageScopeId
    instruction: AddressCoordinate
    operation_ordinal: int
    opcode: str
    selector: ValidatedVarnode | None

    def __post_init__(self) -> None:
        _require_function_scope(self.function_scope, "call occurrence function scope")
        _require_exact(self.instruction, AddressCoordinate, "call occurrence instruction")
        _require_nonnegative_int(
            self.operation_ordinal, "call occurrence operation ordinal"
        )
        if type(self.opcode) is not str:
            raise TypeError("call occurrence opcode must be an exact str")
        if self.opcode not in ("CALL", "CALLIND"):
            raise ValueError("call occurrence opcode must be CALL or CALLIND")
        if self.selector is not None:
            _require_exact(
                self.selector, ValidatedVarnode, "call occurrence selector"
            )

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (
            self.function_scope.digest,
            self.instruction.space_id,
            self.instruction.byte_offset,
            self.operation_ordinal,
            self.opcode,
            () if self.selector is None else tuple(_varnode_payload(self.selector)),
        )

    @property
    def occurrence_digest(self) -> bytes:
        return _digest(_call_occurrence_payload(self))


@dataclass(frozen=True, slots=True)
class InstructionFlowContext:
    fallthrough: AddressCoordinate | None
    flow_targets: tuple[AddressCoordinate, ...]

    def __post_init__(self) -> None:
        if self.fallthrough is not None:
            _require_exact(self.fallthrough, AddressCoordinate, "instruction fallthrough")
        _require_exact_tuple(self.flow_targets, AddressCoordinate, "instruction flow targets")
        _require_strictly_increasing(self.flow_targets, "instruction flow targets")


@dataclass(frozen=True, slots=True)
class DirectCallTarget:
    coordinate: AddressCoordinate

    def __post_init__(self) -> None:
        _require_exact(self.coordinate, AddressCoordinate, "direct target coordinate")


@dataclass(frozen=True, slots=True)
class IndirectCallTarget:
    selector: ValidatedVarnode

    def __post_init__(self) -> None:
        _require_exact(self.selector, ValidatedVarnode, "indirect target selector")


@dataclass(frozen=True, slots=True)
class UnresolvedCallTarget:
    reason: CallTargetFailureReason
    selector: ValidatedVarnode | None = None

    def __post_init__(self) -> None:
        _require_exact(self.reason, CallTargetFailureReason, "target failure reason")
        if self.selector is not None:
            _require_exact(self.selector, ValidatedVarnode, "unresolved target selector")
        if (self.reason is CallTargetFailureReason.MISSING_SELECTOR) != (
            self.selector is None
        ):
            raise ValueError("target failure reason and selector presence disagree")


CallTargetEvidence: TypeAlias = DirectCallTarget | IndirectCallTarget | UnresolvedCallTarget


@dataclass(frozen=True, slots=True)
class CallSiteSeed:
    locator: CallSiteLocator
    operation_key: str
    kind: CallOperationKind
    inputs: tuple[ValidatedVarnode, ...]
    explicit_output: ValidatedVarnode | None
    target: CallTargetEvidence
    instruction_context: InstructionFlowContext
    callee_effects: CalleeEffectCompleteness = CalleeEffectCompleteness.UNOBSERVED

    def __post_init__(self) -> None:
        _require_exact(self.locator, CallSiteLocator, "callsite locator")
        _require_nonempty_text(self.operation_key, "callsite operation key")
        _require_exact(self.kind, CallOperationKind, "call operation kind")
        _require_exact_tuple(self.inputs, ValidatedVarnode, "call inputs")
        if self.explicit_output is not None:
            _require_exact(self.explicit_output, ValidatedVarnode, "call explicit output")
        if type(self.target) not in (
            DirectCallTarget,
            IndirectCallTarget,
            UnresolvedCallTarget,
        ):
            raise TypeError("call target must use an exact target-evidence variant")
        _require_exact(
            self.instruction_context,
            InstructionFlowContext,
            "call instruction context",
        )
        _require_exact(self.callee_effects, CalleeEffectCompleteness, "callee effects")
        if self.callee_effects is not CalleeEffectCompleteness.UNOBSERVED:
            raise ValueError("version 1 cannot claim observed callee effects")
        if not self.inputs:
            if type(self.target) is not UnresolvedCallTarget or (
                self.target.reason is not CallTargetFailureReason.MISSING_SELECTOR
            ):
                raise ValueError("a call without inputs requires missing-selector evidence")
            return

        selector = self.inputs[0]
        if self.kind is CallOperationKind.INDIRECT:
            if type(self.target) is not IndirectCallTarget or self.target.selector != selector:
                raise ValueError("an indirect call requires its exact first input as selector")
            return

        if selector.kind is VarnodeKindCode.ADDRESS:
            if type(self.target) is not DirectCallTarget or self.target.coordinate != selector.coordinate:
                raise ValueError("an address direct selector requires its exact coordinate")
        elif type(self.target) is not UnresolvedCallTarget or (
            self.target.reason is not CallTargetFailureReason.DIRECT_SELECTOR_NOT_ADDRESS
            or self.target.selector != selector
        ):
            raise ValueError("a non-address direct selector requires exact unresolved evidence")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (
            self.locator.function_scope.digest,
            self.locator.instruction.space_id,
            self.locator.instruction.byte_offset,
            self.locator.operation_ordinal,
        )

    @property
    def occurrence(self) -> CallOccurrenceId:
        return CallOccurrenceId(
            self.locator.function_scope,
            self.locator.instruction,
            self.locator.operation_ordinal,
            "CALL" if self.kind is CallOperationKind.DIRECT else "CALLIND",
            None if not self.inputs else self.inputs[0],
        )


class _CallSeedAuthority:
    pass


_CALL_SEED_AUTHORITY = _CallSeedAuthority()


class _CallSeedPermit:
    __slots__ = ("_active", "_payload_digest")

    def __init__(self, authority: _CallSeedAuthority, payload_digest: bytes) -> None:
        if authority is not _CALL_SEED_AUTHORITY:
            raise TypeError("call-seed permits are architect-owned")
        _require_digest(payload_digest, "call-seed permit payload")
        self._active = True
        self._payload_digest = payload_digest

    def consume(self, payload_digest: bytes) -> None:
        if not self._active:
            raise RuntimeError("call-seed permit is no longer active")
        _require_digest(payload_digest, "call-seed construction payload")
        if payload_digest != self._payload_digest:
            raise PermissionError("call-seed permit is bound to other evidence")
        self._active = False

    def revoke(self) -> None:
        self._active = False

    def __reduce_ex__(self, protocol: int):
        raise TypeError("call-seed permits cannot be serialized")


def _mint_call_seed_permit(payload_digest: bytes) -> _CallSeedPermit:
    return _CallSeedPermit(_CALL_SEED_AUTHORITY, payload_digest)


@dataclass(frozen=True, slots=True, init=False)
class FunctionCallSeedUnit:
    contract_version: int
    program_scope: StorageScopeId
    function_scope: StorageScopeId
    function_entry: AddressCoordinate
    observation_digest: bytes
    callsites: tuple[CallSiteSeed, ...]

    @classmethod
    def _create(
        cls,
        contract_version: int,
        program_scope: StorageScopeId,
        function_scope: StorageScopeId,
        function_entry: AddressCoordinate,
        observation_digest: bytes,
        callsites: tuple[CallSiteSeed, ...],
        permit: _CallSeedPermit,
    ) -> "FunctionCallSeedUnit":
        _require_exact(permit, _CallSeedPermit, "call-seed permit")
        value = object.__new__(cls)
        object.__setattr__(value, "contract_version", contract_version)
        object.__setattr__(value, "program_scope", program_scope)
        object.__setattr__(value, "function_scope", function_scope)
        object.__setattr__(value, "function_entry", function_entry)
        object.__setattr__(value, "observation_digest", observation_digest)
        object.__setattr__(value, "callsites", callsites)
        value._validate()
        permit.consume(value.canonical_digest)
        return value

    def _validate(self) -> None:
        _require_version(self.contract_version)
        _require_program_scope(self.program_scope, "call-seed program scope")
        _require_function_scope(self.function_scope, "call-seed function scope")
        _require_exact(self.function_entry, AddressCoordinate, "call-seed function entry")
        _require_digest(self.observation_digest, "call-seed observation digest")
        expected_scope = _derive_function_scope(
            FunctionScopeEvidence(
                self.program_scope,
                self.function_entry,
                self.observation_digest,
            )
        )
        if self.function_scope != expected_scope:
            raise ValueError("call-seed function scope does not match its exact evidence")
        _require_exact_tuple(self.callsites, CallSiteSeed, "callsite seeds")
        keys = tuple(site.canonical_key for site in self.callsites)
        _require_strictly_increasing(keys, "callsite seeds")
        if any(site.locator.function_scope != self.function_scope for site in self.callsites):
            raise ValueError("every callsite must use the unit function scope")
        operation_keys: set[str] = set()
        contexts: dict[AddressCoordinate, InstructionFlowContext] = {}
        for site in self.callsites:
            if site.operation_key in operation_keys:
                raise ValueError("callsite operation keys must be unique")
            operation_keys.add(site.operation_key)
            previous = contexts.setdefault(site.locator.instruction, site.instruction_context)
            if previous != site.instruction_context:
                raise ValueError("callsites in one instruction require identical flow context")

    @property
    def canonical_digest(self) -> bytes:
        return _digest(_seed_unit_payload(self))


@dataclass(frozen=True, slots=True)
class UnresolvedFunctionCallSeeds:
    scopes: ScopeBundleResult
    reason: CallSeedFailureReason

    def __post_init__(self) -> None:
        _require_exact(self.scopes, ScopeBundleResult, "unresolved call-seed scopes")
        _require_exact(self.reason, CallSeedFailureReason, "call-seed failure reason")
        if type(self.scopes.function) is ConstructedFunctionScope:
            raise ValueError("constructed function scope cannot be an unresolved call seed")
        function = self.scopes.function
        if type(function) is not UnresolvedFunctionScope:
            raise TypeError("unresolved call seeds require an unresolved function scope")
        retained = function.validated_observation_digest
        if self.reason is CallSeedFailureReason.MISSING_VALIDATED_OBSERVATION:
            if retained is not None:
                raise ValueError("missing-observation call seed cannot retain an observation")
        elif retained is None:
            raise ValueError("missing-scope call seed requires retained observation evidence")


FunctionCallSeedResult: TypeAlias = FunctionCallSeedUnit | UnresolvedFunctionCallSeeds


def _seed_unit_payload(unit: FunctionCallSeedUnit) -> list[object]:
    return _seed_fields_payload(
        unit.program_scope,
        unit.function_scope,
        unit.function_entry,
        unit.observation_digest,
        unit.callsites,
    )


def _seed_digest(
    program_scope: StorageScopeId,
    function_scope: StorageScopeId,
    function_entry: AddressCoordinate,
    observation_digest: bytes,
    callsites: tuple[CallSiteSeed, ...],
) -> bytes:
    return _digest(
        _seed_fields_payload(
            program_scope,
            function_scope,
            function_entry,
            observation_digest,
            callsites,
        )
    )


def _seed_fields_payload(
    program_scope: StorageScopeId,
    function_scope: StorageScopeId,
    function_entry: AddressCoordinate,
    observation_digest: bytes,
    callsites: tuple[CallSiteSeed, ...],
) -> list[object]:
    return [
        "call-seed-unit-v2",
        program_scope.digest.hex(),
        function_scope.digest.hex(),
        _coordinate_payload(function_entry),
        observation_digest.hex(),
        [_seed_payload(site) for site in callsites],
    ]


def _seed_payload(site: CallSiteSeed) -> list[object]:
    return [
        site.occurrence.occurrence_digest.hex(),
        site.locator.function_scope.digest.hex(),
        _coordinate_payload(site.locator.instruction),
        site.locator.operation_ordinal,
        site.operation_key,
        site.kind.value,
        [_varnode_payload(item) for item in site.inputs],
        None if site.explicit_output is None else _varnode_payload(site.explicit_output),
        _target_payload(site.target),
        None
        if site.instruction_context.fallthrough is None
        else _coordinate_payload(site.instruction_context.fallthrough),
        [_coordinate_payload(item) for item in site.instruction_context.flow_targets],
        site.callee_effects.value,
    ]


def _call_occurrence_payload(value: CallOccurrenceId) -> list[object]:
    return [
        "tdo-v2-call-occurrence-v1",
        value.function_scope.digest.hex(),
        _coordinate_payload(value.instruction),
        value.operation_ordinal,
        value.opcode,
        ["missing"]
        if value.selector is None
        else ["present", *_varnode_payload(value.selector)],
    ]


def _target_payload(target: CallTargetEvidence) -> list[object]:
    if type(target) is DirectCallTarget:
        return ["direct", _coordinate_payload(target.coordinate)]
    if type(target) is IndirectCallTarget:
        return ["indirect", _varnode_payload(target.selector)]
    return [
        "unresolved",
        target.reason.value,
        None if target.selector is None else _varnode_payload(target.selector),
    ]


def _varnode_payload(value: ValidatedVarnode) -> list[object]:
    return [
        int(value.kind),
        value.coordinate.space_id,
        value.coordinate.byte_offset,
        value.byte_size,
    ]


def _coordinate_payload(value: AddressCoordinate) -> list[int]:
    return [value.space_id, value.byte_offset]


def _digest(payload: object) -> bytes:
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).digest()


def _require_version(value: object) -> None:
    if type(value) is not int:
        raise TypeError("call contract version must be an exact int")
    if value != CALL_OBSERVATION_CONTRACT_VERSION:
        raise ValueError("unsupported call-observation contract version")


def _require_program_scope(value: object, label: str) -> None:
    if type(value) is not StorageScopeId or value.kind is not StorageScopeKind.PROGRAM:
        raise TypeError(f"{label} must be an exact PROGRAM scope")


def _require_function_scope(value: object, label: str) -> None:
    if type(value) is not StorageScopeId or value.kind is not StorageScopeKind.FUNCTION:
        raise TypeError(f"{label} must be an exact FUNCTION scope")


def _require_exact(value: object, expected: type, label: str) -> None:
    if type(value) is not expected:
        raise TypeError(f"{label} must be an exact {expected.__name__}")


def _require_exact_tuple(value: object, expected: type, label: str) -> None:
    if type(value) is not tuple or any(type(item) is not expected for item in value):
        raise TypeError(f"{label} must be an exact {expected.__name__} tuple")


def _require_nonempty_text(value: object, label: str) -> None:
    if type(value) is not str or not value:
        raise TypeError(f"{label} must be a non-empty exact str")


def _require_nonnegative_int(value: object, label: str) -> None:
    if type(value) is not int:
        raise TypeError(f"{label} must be an exact int")
    if value < 0:
        raise ValueError(f"{label} must be non-negative")


def _require_digest(value: object, label: str) -> None:
    if type(value) is not bytes:
        raise TypeError(f"{label} must be exact bytes")
    if len(value) != 32:
        raise ValueError(f"{label} must contain exactly 32 bytes")


def _require_strictly_increasing(values, label: str) -> None:
    marker = object()
    previous = marker
    for value in values:
        if previous is not marker and value <= previous:
            raise ValueError(f"{label} must be canonically sorted and unique")
        previous = value
