"""Closed scope-construction result algebra and carrier invariants."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TypeAlias

from ._scope_contracts import (
    AddressCoordinate,
    CommittedMemoryRun,
    FunctionScopeEvidence,
    ValidatedFunctionObservation,
    VerifiedProgramSnapshotEvidence,
    _ConstructionPermit,
    require_digest,
    require_exact,
)
from ._scope_wire import _derive_function_scope, _derive_program_scope, _observation_digest
from .model import StorageResolutionContext, StorageScopeId


class ScopeConstructionStage(StrEnum):
    PROGRAM_CONTENT = "program_content"
    PROGRAM_COORDINATE = "program_coordinate"
    FUNCTION_COORDINATE = "function_coordinate"
    FUNCTION_OBSERVATION = "function_observation"


class ScopeConstructionReason(StrEnum):
    PROGRAM_DUPLICATE_FIELD = "program_duplicate_field"
    MISSING_EXECUTABLE_SHA256 = "missing_executable_sha256"
    INVALID_EXECUTABLE_SHA256 = "invalid_executable_sha256"
    UNVERIFIED_PROGRAM_CONTENT = "unverified_program_content"
    MISSING_LOADED_MEMORY_DIGEST = "missing_loaded_memory_digest"
    INCOMPLETE_PROGRAM_SNAPSHOT = "incomplete_program_snapshot"
    CONFLICTING_PROGRAM_SNAPSHOT = "conflicting_program_snapshot"
    MISSING_TRANSLATION_NAMESPACE = "missing_translation_namespace"
    INVALID_TRANSLATION_NAMESPACE = "invalid_translation_namespace"
    PROGRAM_COORDINATE_DUPLICATE_FIELD = "program_coordinate_duplicate_field"
    INCOMPLETE_PROGRAM_ADDRESS_SPACES = "incomplete_program_address_spaces"
    INVALID_PROGRAM_ADDRESS_SPACES = "invalid_program_address_spaces"
    CONFLICTING_PROGRAM_ADDRESS_SPACES = "conflicting_program_address_spaces"
    MISSING_IMAGE_BASE = "missing_image_base"
    INVALID_IMAGE_BASE = "invalid_image_base"
    FUNCTION_COORDINATE_DUPLICATE_FIELD = "function_coordinate_duplicate_field"
    PARENT_PROGRAM_UNRESOLVED = "parent_program_unresolved"
    MISSING_FUNCTION_ENTRY = "missing_function_entry"
    INVALID_FUNCTION_ENTRY = "invalid_function_entry"
    FUNCTION_OBSERVATION_DUPLICATE_FIELD = "function_observation_duplicate_field"
    MISSING_FUNCTION_OBSERVATION = "missing_function_observation"
    INVALID_FUNCTION_OBSERVATION = "invalid_function_observation"
    INCOMPLETE_FUNCTION_OBSERVATION = "incomplete_function_observation"
    CONFLICTING_FUNCTION_OBSERVATION = "conflicting_function_observation"


_REASON_STAGE = {
    ScopeConstructionReason.PROGRAM_DUPLICATE_FIELD: ScopeConstructionStage.PROGRAM_CONTENT,
    ScopeConstructionReason.MISSING_EXECUTABLE_SHA256: ScopeConstructionStage.PROGRAM_CONTENT,
    ScopeConstructionReason.INVALID_EXECUTABLE_SHA256: ScopeConstructionStage.PROGRAM_CONTENT,
    ScopeConstructionReason.UNVERIFIED_PROGRAM_CONTENT: ScopeConstructionStage.PROGRAM_CONTENT,
    ScopeConstructionReason.MISSING_LOADED_MEMORY_DIGEST: ScopeConstructionStage.PROGRAM_CONTENT,
    ScopeConstructionReason.INCOMPLETE_PROGRAM_SNAPSHOT: ScopeConstructionStage.PROGRAM_CONTENT,
    ScopeConstructionReason.CONFLICTING_PROGRAM_SNAPSHOT: ScopeConstructionStage.PROGRAM_CONTENT,
    ScopeConstructionReason.MISSING_TRANSLATION_NAMESPACE: ScopeConstructionStage.PROGRAM_CONTENT,
    ScopeConstructionReason.INVALID_TRANSLATION_NAMESPACE: ScopeConstructionStage.PROGRAM_CONTENT,
    ScopeConstructionReason.PROGRAM_COORDINATE_DUPLICATE_FIELD: ScopeConstructionStage.PROGRAM_COORDINATE,
    ScopeConstructionReason.INCOMPLETE_PROGRAM_ADDRESS_SPACES: ScopeConstructionStage.PROGRAM_COORDINATE,
    ScopeConstructionReason.INVALID_PROGRAM_ADDRESS_SPACES: ScopeConstructionStage.PROGRAM_COORDINATE,
    ScopeConstructionReason.CONFLICTING_PROGRAM_ADDRESS_SPACES: ScopeConstructionStage.PROGRAM_COORDINATE,
    ScopeConstructionReason.MISSING_IMAGE_BASE: ScopeConstructionStage.PROGRAM_COORDINATE,
    ScopeConstructionReason.INVALID_IMAGE_BASE: ScopeConstructionStage.PROGRAM_COORDINATE,
    ScopeConstructionReason.FUNCTION_COORDINATE_DUPLICATE_FIELD: ScopeConstructionStage.FUNCTION_COORDINATE,
    ScopeConstructionReason.PARENT_PROGRAM_UNRESOLVED: ScopeConstructionStage.FUNCTION_COORDINATE,
    ScopeConstructionReason.MISSING_FUNCTION_ENTRY: ScopeConstructionStage.FUNCTION_COORDINATE,
    ScopeConstructionReason.INVALID_FUNCTION_ENTRY: ScopeConstructionStage.FUNCTION_COORDINATE,
    ScopeConstructionReason.FUNCTION_OBSERVATION_DUPLICATE_FIELD: ScopeConstructionStage.FUNCTION_OBSERVATION,
    ScopeConstructionReason.MISSING_FUNCTION_OBSERVATION: ScopeConstructionStage.FUNCTION_OBSERVATION,
    ScopeConstructionReason.INVALID_FUNCTION_OBSERVATION: ScopeConstructionStage.FUNCTION_OBSERVATION,
    ScopeConstructionReason.INCOMPLETE_FUNCTION_OBSERVATION: ScopeConstructionStage.FUNCTION_OBSERVATION,
    ScopeConstructionReason.CONFLICTING_FUNCTION_OBSERVATION: ScopeConstructionStage.FUNCTION_OBSERVATION,
}


@dataclass(frozen=True, slots=True, init=False)
class ConstructedProgramScope:
    scope: StorageScopeId
    evidence: VerifiedProgramSnapshotEvidence
    _committed_runs: tuple[CommittedMemoryRun, ...] | None = field(
        repr=False,
        compare=False,
    )

    @classmethod
    def _create(
        cls,
        evidence: VerifiedProgramSnapshotEvidence,
        permit: _ConstructionPermit,
        committed_runs: tuple[CommittedMemoryRun, ...] | None = None,
    ) -> "ConstructedProgramScope":
        require_exact(evidence, VerifiedProgramSnapshotEvidence, "program evidence")
        require_exact(permit, _ConstructionPermit, "construction permit")
        if committed_runs is not None and (
            type(committed_runs) is not tuple
            or any(type(run) is not CommittedMemoryRun for run in committed_runs)
        ):
            raise TypeError("committed memory runs must be an exact run tuple")
        permit.require_active()
        value = object.__new__(cls)
        object.__setattr__(value, "scope", _derive_program_scope(evidence))
        object.__setattr__(value, "evidence", evidence)
        object.__setattr__(value, "_committed_runs", committed_runs)
        return value

    def _retained_committed_runs(self) -> tuple[CommittedMemoryRun, ...] | None:
        return self._committed_runs


@dataclass(frozen=True, slots=True)
class UnresolvedProgramScope:
    stage: ScopeConstructionStage
    reason: ScopeConstructionReason

    def __post_init__(self) -> None:
        require_exact(self.stage, ScopeConstructionStage, "program failure stage")
        require_exact(self.reason, ScopeConstructionReason, "program failure reason")
        if self.stage not in (
            ScopeConstructionStage.PROGRAM_CONTENT,
            ScopeConstructionStage.PROGRAM_COORDINATE,
        ) or _REASON_STAGE[self.reason] is not self.stage:
            raise ValueError("program scope stage and reason are incompatible")


@dataclass(frozen=True, slots=True, init=False)
class ConstructedFunctionScope:
    scope: StorageScopeId
    program_scope: StorageScopeId
    entry: AddressCoordinate
    observation_digest: bytes

    @classmethod
    def _create(
        cls,
        program_scope: StorageScopeId,
        entry: AddressCoordinate,
        observation_digest: bytes,
        permit: _ConstructionPermit,
    ) -> "ConstructedFunctionScope":
        evidence = FunctionScopeEvidence(program_scope, entry, observation_digest)
        require_exact(permit, _ConstructionPermit, "construction permit")
        permit.require_active()
        value = object.__new__(cls)
        object.__setattr__(value, "scope", _derive_function_scope(evidence))
        object.__setattr__(value, "program_scope", program_scope)
        object.__setattr__(value, "entry", entry)
        object.__setattr__(value, "observation_digest", observation_digest)
        return value


@dataclass(frozen=True, slots=True)
class UnresolvedFunctionScope:
    stage: ScopeConstructionStage
    reason: ScopeConstructionReason
    validated_observation_digest: bytes | None = None

    def __post_init__(self) -> None:
        require_exact(self.stage, ScopeConstructionStage, "function failure stage")
        require_exact(self.reason, ScopeConstructionReason, "function failure reason")
        if self.stage not in (
            ScopeConstructionStage.FUNCTION_COORDINATE,
            ScopeConstructionStage.FUNCTION_OBSERVATION,
        ) or _REASON_STAGE[self.reason] is not self.stage:
            raise ValueError("function scope stage and reason are incompatible")
        if self.validated_observation_digest is not None:
            require_digest(self.validated_observation_digest, "validated observation digest")
        if (
            self.stage is ScopeConstructionStage.FUNCTION_OBSERVATION
            or self.reason is ScopeConstructionReason.PARENT_PROGRAM_UNRESOLVED
        ) and self.validated_observation_digest is not None:
            raise ValueError("this function failure cannot retain an observation digest")


ProgramScopeConstructionResult: TypeAlias = ConstructedProgramScope | UnresolvedProgramScope
FunctionScopeConstructionResult: TypeAlias = ConstructedFunctionScope | UnresolvedFunctionScope


@dataclass(frozen=True, slots=True)
class ScopeBundleResult:
    program: ProgramScopeConstructionResult
    function: FunctionScopeConstructionResult

    def __post_init__(self) -> None:
        if type(self.program) not in (ConstructedProgramScope, UnresolvedProgramScope):
            raise TypeError("bundle program result has an invalid exact type")
        if type(self.function) not in (ConstructedFunctionScope, UnresolvedFunctionScope):
            raise TypeError("bundle function result has an invalid exact type")
        if type(self.program) is UnresolvedProgramScope:
            if not (
                type(self.function) is UnresolvedFunctionScope
                and self.function.reason is ScopeConstructionReason.PARENT_PROGRAM_UNRESOLVED
            ):
                raise ValueError("an unresolved program requires parent-unresolved function")
        elif type(self.function) is ConstructedFunctionScope:
            if self.function.program_scope != self.program.scope:
                raise ValueError("function scope is bound to a different program")
        elif self.function.reason is ScopeConstructionReason.PARENT_PROGRAM_UNRESOLVED:
            raise ValueError("a constructed program cannot have parent-unresolved function")

    @property
    def resolution_context(self) -> StorageResolutionContext:
        program_scope = self.program.scope if type(self.program) is ConstructedProgramScope else None
        function_scope = self.function.scope if type(self.function) is ConstructedFunctionScope else None
        return StorageResolutionContext(program_scope, function_scope)


@dataclass(frozen=True, slots=True)
class ScopedFunctionUnit:
    scopes: ScopeBundleResult
    observation: ValidatedFunctionObservation | None

    def __post_init__(self) -> None:
        require_exact(self.scopes, ScopeBundleResult, "scope bundle")
        if self.observation is not None:
            require_exact(self.observation, ValidatedFunctionObservation, "validated observation")
        function = self.scopes.function
        if type(function) is ConstructedFunctionScope:
            if self.observation is None or _observation_digest(self.observation) != function.observation_digest:
                raise ValueError("constructed function is not bound to its observation")
        else:
            retained = function.validated_observation_digest
            actual = None if self.observation is None else _observation_digest(self.observation)
            if actual != retained:
                raise ValueError("unresolved function observation binding is inconsistent")
