"""Single-owner configured extraction envelope and total precedence reducers."""

from __future__ import annotations

from collections.abc import Iterator
from threading import current_thread
from typing import Protocol

from ._scope_contracts import (
    FrozenMemoryBlockDescriptor,
    PositionedChunk,
    TranslationNamespace,
    VerifiedProgramSnapshotEvidence,
    _ConstructionPermit,
    _OrchestratorCapability,
    _mint_orchestrator_capability,
)
from ._scope_memory import (
    _MemoryCommitmentError,
    _MemoryFailureKind,
    _loaded_memory_commitment,
    _original_executable_digest,
)
from ._scope_observation import _FunctionValidation, _validate_function_candidate
from ._scope_program import _AddressSpaceIndex, _ProgramValidation, _validate_program_candidate
from ._scope_raw import RawObject, _FieldState, _field, _has_duplicate
from ._scope_results import (
    ConstructedFunctionScope,
    ConstructedProgramScope,
    ProgramScopeConstructionResult,
    ScopeBundleResult,
    ScopeConstructionReason,
    ScopeConstructionStage,
    ScopedFunctionUnit,
    UnresolvedFunctionScope,
    UnresolvedProgramScope,
)


class FrozenProgramViewProvider(Protocol):
    def original_executable_size(self) -> int: ...
    def original_executable_chunks(self) -> Iterator[PositionedChunk]: ...
    def memory_descriptors(self) -> tuple[FrozenMemoryBlockDescriptor, ...]: ...
    def read_exact(self, handle: object, block_relative_offset: int, length: int) -> Iterator[PositionedChunk]: ...
    def snapshot_complete(self) -> bool: ...
    def spaces_complete(self) -> bool: ...
    def program_candidate(self) -> RawObject: ...
    def function_handles(self) -> object: ...
    def observation_complete(self, handle: object) -> bool: ...
    def function_candidate(self, handle: object) -> RawObject | None: ...
    def close(self) -> None: ...


_ENVELOPE_CONSTRUCTOR = object()


def open_configured_extraction(
    provider: FrozenProgramViewProvider,
    capability: _OrchestratorCapability,
) -> "ConfiguredExtractionEnvelope":
    if capability is not _mint_orchestrator_capability():
        raise PermissionError("invalid configured-extraction capability")
    return ConfiguredExtractionEnvelope(provider, capability, _ENVELOPE_CONSTRUCTOR)


class ConfiguredExtractionEnvelope:
    __slots__ = (
        "_entered",
        "_busy",
        "_cleanup_complete",
        "_closing",
        "_function_iterator",
        "_function_iterator_claimed",
        "_index",
        "_owner",
        "_permit",
        "_program_result",
        "_provider_cleanup_complete",
        "_provider",
        "_closed",
    )

    def __init__(
        self,
        provider: FrozenProgramViewProvider,
        capability: _OrchestratorCapability,
        constructor: object,
    ) -> None:
        if constructor is not _ENVELOPE_CONSTRUCTOR:
            raise PermissionError("configured envelope constructor is private")
        if capability is not _mint_orchestrator_capability():
            raise PermissionError("invalid configured-extraction capability")
        self._provider = provider
        self._owner = current_thread()
        self._permit: _ConstructionPermit | None = None
        self._program_result: ProgramScopeConstructionResult | None = None
        self._index: _AddressSpaceIndex | None = None
        self._entered = False
        self._closed = False
        self._busy = False
        self._cleanup_complete = False
        self._provider_cleanup_complete = False
        self._closing = False
        self._function_iterator: _ScopedFunctionIterator | None = None
        self._function_iterator_claimed = False

    def __enter__(self) -> "ConfiguredExtractionEnvelope":
        self._require_owner()
        if self._closed or self._entered:
            raise RuntimeError("configured envelope cannot be re-entered")
        self._entered = True
        self._permit = _ConstructionPermit(_mint_orchestrator_capability())
        try:
            self._busy = True
            try:
                self._program_result, self._index = self._construct_program()
            finally:
                self._busy = False
            return self
        except BaseException as primary:
            try:
                self._close()
            except BaseException as cleanup:
                primary.add_note(f"configured envelope cleanup also failed: {cleanup!r}")
            raise

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._require_owner()
        if not self._entered or self._cleanup_complete:
            raise RuntimeError("configured envelope is not active")
        if self._busy or self._closing:
            raise RuntimeError("configured envelope is non-reentrant")
        self._close()

    @property
    def program_result(self) -> ProgramScopeConstructionResult:
        self._require_public_idle()
        assert self._program_result is not None
        return self._program_result

    def iter_scoped_functions(self) -> Iterator[ScopedFunctionUnit]:
        self._require_public_idle()
        if self._function_iterator_claimed:
            raise RuntimeError("function iterator is single-use")
        self._function_iterator_claimed = True
        try:
            handles = iter(self._provider.function_handles())
        except Exception as exc:
            raise RuntimeError("function handle enumeration failed") from exc
        iterator = _ScopedFunctionIterator(self, handles)
        self._function_iterator = iterator
        return iterator

    def _construct_program(
        self,
    ) -> tuple[ProgramScopeConstructionResult, _AddressSpaceIndex | None]:
        candidate = self._safe_program_candidate()
        if _configured_program_duplicate(candidate):
            return _program_failure(ScopeConstructionReason.PROGRAM_DUPLICATE_FIELD), None

        size_method = getattr(self._provider, "original_executable_size", None)
        chunks_method = getattr(self._provider, "original_executable_chunks", None)
        if not callable(size_method) or not callable(chunks_method):
            return _program_failure(ScopeConstructionReason.MISSING_EXECUTABLE_SHA256), None
        try:
            executable_digest = _original_executable_digest(size_method(), chunks_method())
        except Exception:
            return _program_failure(ScopeConstructionReason.INVALID_EXECUTABLE_SHA256), None

        try:
            descriptors = self._provider.memory_descriptors()
            memory = _loaded_memory_commitment(
                descriptors,
                self._provider.snapshot_complete,
                self._provider.read_exact,
            )
        except _MemoryCommitmentError as exc:
            reasons = {
                _MemoryFailureKind.CONFLICTING: ScopeConstructionReason.CONFLICTING_PROGRAM_SNAPSHOT,
                _MemoryFailureKind.INCOMPLETE: ScopeConstructionReason.INCOMPLETE_PROGRAM_SNAPSHOT,
                _MemoryFailureKind.MISSING: ScopeConstructionReason.MISSING_LOADED_MEMORY_DIGEST,
            }
            return _program_failure(reasons[exc.kind]), None
        except Exception:
            return _program_failure(ScopeConstructionReason.INCOMPLETE_PROGRAM_SNAPSHOT), None

        try:
            spaces_complete = self._provider.spaces_complete()
        except Exception:
            spaces_complete = None
        validation = _validate_program_candidate(candidate, spaces_complete, memory.runs)
        failure = _program_validation_failure(validation)
        if failure is not None:
            return failure, None
        assert validation.namespace is not None
        assert validation.image_base is not None
        if validation.classification_revision not in (1, 2):
            raise AssertionError("accepted program validation lacks a revision")
        unique_spaces = tuple({row.space_id: row for row in validation.spaces}.values())
        unique_spaces = tuple(sorted(unique_spaces, key=lambda row: row.space_id))
        index = _AddressSpaceIndex(unique_spaces, memory.runs)
        evidence = VerifiedProgramSnapshotEvidence(
            executable_digest,
            memory.digest,
            validation.image_base,
            validation.namespace,
            validation.classification_revision,
            unique_spaces,
        )
        assert self._permit is not None
        return ConstructedProgramScope._create(
            evidence,
            self._permit,
            memory.runs,
        ), index

    def _safe_program_candidate(self) -> object:
        try:
            return self._provider.program_candidate()
        except Exception:
            return None

    def _construct_function(self, handle: object) -> ScopedFunctionUnit:
        self._require_active()
        assert self._program_result is not None
        if type(self._program_result) is UnresolvedProgramScope:
            function = UnresolvedFunctionScope(
                ScopeConstructionStage.FUNCTION_COORDINATE,
                ScopeConstructionReason.PARENT_PROGRAM_UNRESOLVED,
            )
            return ScopedFunctionUnit(ScopeBundleResult(self._program_result, function), None)

        assert self._index is not None
        try:
            raw = self._provider.function_candidate(handle)
        except Exception:
            function = UnresolvedFunctionScope(
                ScopeConstructionStage.FUNCTION_OBSERVATION,
                ScopeConstructionReason.INCOMPLETE_FUNCTION_OBSERVATION,
            )
            return ScopedFunctionUnit(ScopeBundleResult(self._program_result, function), None)
        if raw is None:
            function = UnresolvedFunctionScope(
                ScopeConstructionStage.FUNCTION_OBSERVATION,
                ScopeConstructionReason.MISSING_FUNCTION_OBSERVATION,
            )
            return ScopedFunctionUnit(ScopeBundleResult(self._program_result, function), None)
        validation = _validate_function_candidate(raw, self._index)
        try:
            complete = self._provider.observation_complete(handle)
        except Exception:
            complete = None
        function, observation = self._reduce_function(validation, complete)
        return ScopedFunctionUnit(ScopeBundleResult(self._program_result, function), observation)

    def _reduce_function(self, value: _FunctionValidation, complete: object):
        observation_valid = value.observation is not None and complete is True and type(complete) is bool
        retained_digest = value.observation_digest if observation_valid else None
        if value.duplicate_entry:
            return _function_coordinate_failure(
                ScopeConstructionReason.FUNCTION_COORDINATE_DUPLICATE_FIELD,
                retained_digest,
            ), value.observation if observation_valid else None
        if value.missing_entry:
            return _function_coordinate_failure(
                ScopeConstructionReason.MISSING_FUNCTION_ENTRY,
                retained_digest,
            ), value.observation if observation_valid else None
        if value.invalid_entry:
            return _function_coordinate_failure(
                ScopeConstructionReason.INVALID_FUNCTION_ENTRY,
                retained_digest,
            ), value.observation if observation_valid else None
        observation_reason = None
        if value.duplicate_observation:
            observation_reason = ScopeConstructionReason.FUNCTION_OBSERVATION_DUPLICATE_FIELD
        elif value.missing_observation:
            observation_reason = ScopeConstructionReason.MISSING_FUNCTION_OBSERVATION
        elif value.invalid_observation:
            observation_reason = ScopeConstructionReason.INVALID_FUNCTION_OBSERVATION
        elif value.incomplete_observation or type(complete) is not bool or complete is not True:
            observation_reason = ScopeConstructionReason.INCOMPLETE_FUNCTION_OBSERVATION
        elif value.conflicting_observation:
            observation_reason = ScopeConstructionReason.CONFLICTING_FUNCTION_OBSERVATION
        if observation_reason is not None:
            return UnresolvedFunctionScope(
                ScopeConstructionStage.FUNCTION_OBSERVATION,
                observation_reason,
            ), None
        assert value.entry is not None and value.observation is not None and value.observation_digest is not None
        assert self._permit is not None
        function = ConstructedFunctionScope._create(
            self._program_result.scope,
            value.entry,
            value.observation_digest,
            self._permit,
        )
        return function, value.observation

    def _require_owner(self) -> None:
        if current_thread() is not self._owner:
            raise RuntimeError("configured envelope is confined to its owner thread")

    def _require_active(self) -> None:
        self._require_owner()
        if not self._entered or self._closed:
            raise RuntimeError("configured envelope is not active")

    def _require_public_idle(self) -> None:
        self._require_active()
        if self._busy:
            raise RuntimeError("configured envelope is non-reentrant")

    def _begin_advance(self, iterator: "_ScopedFunctionIterator") -> None:
        self._require_public_idle()
        if iterator is not self._function_iterator:
            raise RuntimeError("function iterator is detached")
        self._busy = True

    def _end_advance(self) -> None:
        self._busy = False

    def _close(self) -> None:
        if self._cleanup_complete:
            return
        if self._closing:
            raise RuntimeError("configured envelope is non-reentrant")
        self._closed = True
        self._closing = True
        if self._permit is not None:
            self._permit.revoke()
        iterator = self._function_iterator
        iterator_error: BaseException | None = None
        if iterator is not None:
            try:
                iterator._release()
            except BaseException as exc:
                iterator_error = exc
            else:
                self._function_iterator = None
        provider_error: BaseException | None = None
        if not self._provider_cleanup_complete:
            try:
                close = getattr(self._provider, "close", None)
                if callable(close):
                    close()
            except BaseException as exc:
                provider_error = exc
            else:
                self._provider_cleanup_complete = True
        self._cleanup_complete = (
            self._function_iterator is None and self._provider_cleanup_complete
        )
        self._closing = False
        if iterator_error is not None:
            if provider_error is not None:
                iterator_error.add_note(
                    f"configured provider cleanup also failed: {provider_error!r}"
                )
            raise iterator_error
        if provider_error is not None:
            raise provider_error

    def __reduce_ex__(self, protocol: int):
        raise TypeError("configured extraction envelope cannot be serialized")


class _ScopedFunctionIterator:
    __slots__ = ("_envelope", "_exhausted", "_handles")

    def __init__(self, envelope: ConfiguredExtractionEnvelope, handles: Iterator[object]) -> None:
        self._envelope = envelope
        self._handles = handles
        self._exhausted = False

    def __iter__(self) -> "_ScopedFunctionIterator":
        self._envelope._require_public_idle()
        if self._exhausted:
            return self
        return self

    def __next__(self) -> ScopedFunctionUnit:
        self._envelope._require_public_idle()
        if self._exhausted:
            raise StopIteration
        self._envelope._begin_advance(self)
        try:
            try:
                handle = next(self._handles)
            except StopIteration:
                self._release()
                raise
            except BaseException as primary:
                self._release_preserving(primary)
                raise
            try:
                return self._envelope._construct_function(handle)
            except BaseException as primary:
                self._release_preserving(primary)
                raise
        finally:
            self._envelope._end_advance()

    def _release(self) -> None:
        if self._handles is None:
            return
        self._exhausted = True
        handles = self._handles
        close = getattr(handles, "close", None)
        if callable(close):
            close()
        self._handles = None

    def _release_preserving(self, primary: BaseException) -> None:
        try:
            self._release()
        except BaseException as cleanup:
            primary.add_note(f"function iterator cleanup also failed: {cleanup!r}")

    def __reduce_ex__(self, protocol: int):
        raise TypeError("configured function iterator cannot be serialized")


def _configured_program_duplicate(raw: object) -> bool:
    if type(raw) is not RawObject:
        return False
    if _field(raw, "translation_namespace").state is _FieldState.DUPLICATE:
        return True
    if (
        _field(raw, "address_space_classification_revision").state
        is _FieldState.DUPLICATE
    ):
        return True
    translation = _field(raw, "translation_namespace")
    return (
        translation.state is _FieldState.PRESENT
        and type(translation.value) is RawObject
        and _has_duplicate(translation.value, ("language_id", "major_version", "minor_version"))
    )


def _program_validation_failure(value: _ProgramValidation) -> UnresolvedProgramScope | None:
    if value.duplicate_program:
        return _program_failure(ScopeConstructionReason.PROGRAM_DUPLICATE_FIELD)
    if value.missing_translation:
        return _program_failure(ScopeConstructionReason.MISSING_TRANSLATION_NAMESPACE)
    if value.invalid_translation:
        return _program_failure(ScopeConstructionReason.INVALID_TRANSLATION_NAMESPACE)
    coordinate_reasons = (
        (value.duplicate_coordinate, ScopeConstructionReason.PROGRAM_COORDINATE_DUPLICATE_FIELD),
        (value.incomplete_spaces, ScopeConstructionReason.INCOMPLETE_PROGRAM_ADDRESS_SPACES),
        (value.invalid_spaces, ScopeConstructionReason.INVALID_PROGRAM_ADDRESS_SPACES),
        (value.conflicting_spaces, ScopeConstructionReason.CONFLICTING_PROGRAM_ADDRESS_SPACES),
        (value.missing_image_base, ScopeConstructionReason.MISSING_IMAGE_BASE),
        (value.invalid_image_base, ScopeConstructionReason.INVALID_IMAGE_BASE),
    )
    for present, reason in coordinate_reasons:
        if present:
            return _program_failure(reason)
    return None


def _program_failure(reason: ScopeConstructionReason) -> UnresolvedProgramScope:
    stage = (
        ScopeConstructionStage.PROGRAM_CONTENT
        if reason in {
            ScopeConstructionReason.PROGRAM_DUPLICATE_FIELD,
            ScopeConstructionReason.MISSING_EXECUTABLE_SHA256,
            ScopeConstructionReason.INVALID_EXECUTABLE_SHA256,
            ScopeConstructionReason.UNVERIFIED_PROGRAM_CONTENT,
            ScopeConstructionReason.MISSING_LOADED_MEMORY_DIGEST,
            ScopeConstructionReason.INCOMPLETE_PROGRAM_SNAPSHOT,
            ScopeConstructionReason.CONFLICTING_PROGRAM_SNAPSHOT,
            ScopeConstructionReason.MISSING_TRANSLATION_NAMESPACE,
            ScopeConstructionReason.INVALID_TRANSLATION_NAMESPACE,
        }
        else ScopeConstructionStage.PROGRAM_COORDINATE
    )
    return UnresolvedProgramScope(stage, reason)


def _function_coordinate_failure(reason, digest):
    return UnresolvedFunctionScope(ScopeConstructionStage.FUNCTION_COORDINATE, reason, digest)
