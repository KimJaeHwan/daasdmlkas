"""Lease-safe decoding of observed function evidence and call names."""

from __future__ import annotations

from dataclasses import dataclass
from threading import current_thread
from typing import Iterator

from .._configured_bundle_reader import read_configured_bundle
from .._scope_contracts import _mint_orchestrator_capability
from .._scope_results import (
    ConstructedFunctionScope,
    ConstructedProgramScope,
    ProgramScopeConstructionResult,
    ScopedFunctionUnit,
)
from ..call_contracts import FunctionCallSeedUnit
from ..call_seeds import seed_function_calls
from ..configured_naming import decode_configured_naming
from ..configured_naming_contracts import (
    CapturedNamingSidecar,
    NamingBindingExpectation,
    NamingTransportExpectation,
)
from ..configured_profile_contracts import (
    CONFIGURED_BUNDLE_MANIFEST_SCHEMA_ID,
    CONFIGURED_BUNDLE_SEAL_SCHEMA_ID,
)
from ..scope_identity import open_configured_extraction, parse_raw_json


__all__ = (
    "ObservedFunctionEvidence",
    "ObservedFunctionSession",
    "open_observed_function_session",
)


@dataclass(frozen=True, slots=True)
class ObservedFunctionEvidence:
    """Observed P-code plus exact direct-call naming for one function."""

    unit: ScopedFunctionUnit
    seeds: FunctionCallSeedUnit
    naming: CapturedNamingSidecar

    def __reduce_ex__(self, protocol: int):
        raise TypeError("observed function evidence cannot be serialized")


@dataclass(frozen=True, slots=True)
class _CapturedObservedRoles:
    transport_identity: object
    naming_bytes: bytes


class _ObservedScopeProvider:
    """Retain naming bytes while projecting observations to the scope envelope."""

    __slots__ = ("_failure", "_pending", "_provider")

    def __init__(self, provider: object) -> None:
        self._provider = provider
        self._pending: _CapturedObservedRoles | None = None
        self._failure: BaseException | None = None

    def original_executable_size(self):
        return self._provider.original_executable_size()

    def original_executable_chunks(self):
        return self._provider.original_executable_chunks()

    def memory_descriptors(self):
        return self._provider.memory_descriptors()

    def read_exact(self, handle, block_relative_offset, length):
        return self._provider.read_exact(handle, block_relative_offset, length)

    def snapshot_complete(self):
        return self._provider.snapshot_complete()

    def spaces_complete(self):
        return self._provider.spaces_complete()

    def program_candidate(self):
        return self._provider.program_candidate()

    def function_handles(self):
        return self._provider.function_handles()

    def observation_complete(self, handle):
        return self._provider.observation_complete(handle)

    def function_candidate(self, handle):
        if self._pending is not None or self._failure is not None:
            raise RuntimeError("previous observed function roles were not collected")
        try:
            with self._provider.claim_function_transport(handle) as guard:
                identity = guard.transport_identity
                observation = guard.observation_candidate()
                naming_bytes = guard.call_names_bytes()
        except BaseException as exc:
            self._failure = exc
            raise
        self._pending = _CapturedObservedRoles(identity, naming_bytes)
        return observation

    def collect_function_roles(self) -> _CapturedObservedRoles:
        if self._failure is not None:
            failure = self._failure
            self._failure = None
            raise RuntimeError("observed function role capture failed") from failure
        captured = self._pending
        if captured is None:
            raise RuntimeError("observed function roles were not captured")
        self._pending = None
        return captured

    def discard_function_roles(self) -> None:
        self._pending = None
        self._failure = None

    def close(self) -> None:
        self.discard_function_roles()
        self._provider.close()


class ObservedFunctionSession:
    """Single-owner session that admits observations without ABI semantics."""

    __slots__ = (
        "_active",
        "_entered",
        "_envelope",
        "_generation_id",
        "_iterator_claimed",
        "_naming_binding",
        "_owner",
        "_provider_adapter",
        "_snapshot",
    )

    def __init__(
        self,
        snapshot: object,
        naming_binding: NamingBindingExpectation,
    ) -> None:
        _require_exact(naming_binding, NamingBindingExpectation, "naming binding")
        self._snapshot = snapshot
        self._naming_binding = naming_binding
        self._owner = current_thread()
        self._provider_adapter: _ObservedScopeProvider | None = None
        self._envelope = None
        self._generation_id: bytes | None = None
        self._entered = False
        self._active = False
        self._iterator_claimed = False

    def __enter__(self) -> "ObservedFunctionSession":
        self._require_owner()
        if self._entered:
            raise RuntimeError("observed function session cannot be re-entered")
        self._entered = True
        provider = read_configured_bundle(self._snapshot)
        self._snapshot = None
        try:
            generation_id = provider.container_identity.generation_id
            adapter = _ObservedScopeProvider(provider)
            envelope = open_configured_extraction(
                adapter,
                _mint_orchestrator_capability(),
            )
            envelope.__enter__()
        except BaseException as primary:
            envelope = locals().get("envelope")
            if envelope is not None:
                try:
                    envelope.__exit__(None, None, None)
                except BaseException as cleanup:
                    primary.add_note(
                        f"observed function session cleanup also failed: {cleanup!r}"
                    )
            else:
                try:
                    provider.close()
                except BaseException as cleanup:
                    primary.add_note(
                        f"observed function provider cleanup also failed: {cleanup!r}"
                    )
            raise
        self._provider_adapter = adapter
        self._envelope = envelope
        self._generation_id = generation_id
        self._active = True
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._require_owner()
        if not self._active or self._envelope is None:
            raise RuntimeError("observed function session is not active")
        self._active = False
        try:
            self._envelope.__exit__(exc_type, exc, traceback)
        finally:
            if self._provider_adapter is not None:
                self._provider_adapter.discard_function_roles()
            self._envelope = None
            self._provider_adapter = None
            self._generation_id = None

    @property
    def program_result(self) -> ProgramScopeConstructionResult:
        self._require_active()
        assert self._envelope is not None
        return self._envelope.program_result

    def iter_functions(self) -> Iterator[ObservedFunctionEvidence]:
        self._require_active()
        if self._iterator_claimed:
            raise RuntimeError("observed function iterator is single-use")
        self._iterator_claimed = True
        assert self._envelope is not None
        return _ObservedFunctionIterator(self, self._envelope.iter_scoped_functions())

    def _decode_function(
        self,
        unit: ScopedFunctionUnit,
        captured: _CapturedObservedRoles,
    ) -> ObservedFunctionEvidence:
        self._require_active()
        function = unit.scopes.function
        program = unit.scopes.program
        if (
            type(program) is not ConstructedProgramScope
            or type(function) is not ConstructedFunctionScope
        ):
            raise ValueError("observed function scope could not be constructed")
        seeds = seed_function_calls(unit)
        if type(seeds) is not FunctionCallSeedUnit:
            raise ValueError("observed function call seeds could not be constructed")

        observation = captured.transport_identity.observation_member
        assert self._generation_id is not None
        transport = NamingTransportExpectation(
            self._generation_id,
            CONFIGURED_BUNDLE_MANIFEST_SCHEMA_ID,
            CONFIGURED_BUNDLE_SEAL_SCHEMA_ID,
            observation.member_id,
            observation.sha256_digest,
            seeds.function_entry,
        )
        naming = decode_configured_naming(
            parse_raw_json(captured.naming_bytes),
            transport,
            self._naming_binding,
            seeds,
        )
        return ObservedFunctionEvidence(unit, seeds, naming)

    def _require_owner(self) -> None:
        if current_thread() is not self._owner:
            raise RuntimeError("observed function session is owner-thread confined")

    def _require_active(self) -> None:
        self._require_owner()
        if not self._active:
            raise RuntimeError("observed function session is not active")

    def __reduce_ex__(self, protocol: int):
        raise TypeError("observed function session cannot be serialized")


class _ObservedFunctionIterator:
    __slots__ = ("_failed", "_scoped", "_session")

    def __init__(
        self,
        session: ObservedFunctionSession,
        scoped: Iterator[ScopedFunctionUnit],
    ) -> None:
        self._session = session
        self._scoped = scoped
        self._failed = False

    def __iter__(self) -> "_ObservedFunctionIterator":
        self._session._require_active()
        return self

    def __next__(self) -> ObservedFunctionEvidence:
        self._session._require_active()
        if self._failed:
            raise RuntimeError("observed function iterator failed")
        adapter = self._session._provider_adapter
        if adapter is None:
            raise RuntimeError("observed function iterator is detached")
        try:
            unit = next(self._scoped)
            captured = adapter.collect_function_roles()
            return self._session._decode_function(unit, captured)
        except StopIteration:
            raise
        except BaseException:
            self._failed = True
            raise

    def __reduce_ex__(self, protocol: int):
        raise TypeError("observed function iterator cannot be serialized")


def open_observed_function_session(
    snapshot: object,
    /,
    *,
    naming_binding: NamingBindingExpectation,
) -> ObservedFunctionSession:
    """Create a single-use observation and call-naming session."""

    return ObservedFunctionSession(snapshot, naming_binding)


def _require_exact(value: object, expected: type, label: str) -> None:
    if type(value) is not expected:
        raise TypeError(f"{label} must be an exact {expected.__name__}")
