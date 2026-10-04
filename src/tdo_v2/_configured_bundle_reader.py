"""Projection of an admitted configured bundle into the scope provider protocol."""

from collections.abc import Iterator as _Iterator
from threading import current_thread as _current_thread

from ._configured_bundle_snapshot import (
    MAX_CALL_INTERFACE_PROFILE_BYTES as _MAX_PROFILE_BYTES,
    MAX_CALL_SIDECAR_BYTES as _MAX_SIDECAR_BYTES,
    _ConfiguredBundleV1CompatibilitySnapshot,
    _ConfiguredBundleV2Snapshot,
    _claim_bundle_snapshot,
)
from .scope_identity import (
    FrozenMemoryBlockDescriptor as _FrozenMemoryBlockDescriptor,
    FrozenProgramViewProvider as _FrozenProgramViewProvider,
    PositionedChunk as _PositionedChunk,
    RawObject as _RawObject,
    parse_raw_json as _parse_raw_json,
)

__all__ = (
    "read_configured_bundle",
    "read_configured_bundle_v1_compatibility",
)
_FUNCTION_GUARD_CONSTRUCTOR = object()


class _BlockHandle:
    __slots__ = ()

    def __reduce_ex__(self, protocol: int):
        raise TypeError("configured block handle cannot be serialized")


class _FunctionHandle:
    __slots__ = ()

    def __reduce_ex__(self, protocol: int):
        raise TypeError("configured function handle cannot be serialized")


class _OwnerBoundStream(_Iterator[_PositionedChunk]):
    __slots__ = ("_provider", "_stream")

    def __init__(
        self,
        provider: "_ConfiguredBundleProvider",
        stream: _Iterator[_PositionedChunk],
    ) -> None:
        self._provider = provider
        self._stream = stream

    def __next__(self) -> _PositionedChunk:
        self._provider._require_active()
        return next(self._stream)

    def __reduce_ex__(self, protocol: int):
        raise TypeError("configured bundle stream cannot be serialized")


class _ConfiguredBundleProvider:
    __slots__ = (
        "_active_guards", "_block_handles", "_block_indexes", "_block_used",
        "_closed", "_function_handles", "_function_indexes", "_function_parsed",
        "_function_used", "_functions_claimed", "_inventory", "_observation_used",
        "_original_claimed", "_owner", "_program_claimed", "_program_verified",
        "_snapshot", "_snapshot_claim",
    )

    def __init__(self, snapshot, snapshot_claim) -> None:
        self._owner = _current_thread()
        self._snapshot = snapshot
        self._snapshot_claim = snapshot_claim
        self._inventory = snapshot.inventory(snapshot_claim)
        self._block_handles = tuple(_BlockHandle() for _ in self._inventory.blocks)
        self._block_indexes = {
            id(handle): index
            for index, handle in enumerate(self._block_handles)
        }
        self._block_used = [False] * len(self._inventory.blocks)
        self._function_handles = tuple(_FunctionHandle() for _ in self._inventory.functions)
        self._function_indexes = {
            id(handle): index
            for index, handle in enumerate(self._function_handles)
        }
        self._function_used = [False] * len(self._inventory.functions)
        self._function_parsed = [False] * len(self._inventory.functions)
        self._observation_used = [False] * len(self._inventory.functions)
        self._original_claimed = False
        self._program_claimed = False
        self._program_verified = False
        self._functions_claimed = False
        self._active_guards = 0
        self._closed = False

    def original_executable_size(self) -> int:
        self._require_active()
        return self._inventory.original.byte_size
    def original_executable_chunks(self) -> _Iterator[_PositionedChunk]:
        self._require_active()
        if self._original_claimed:
            raise RuntimeError("original executable stream is single-use")
        self._original_claimed = True
        stream = self._snapshot.verified_chunks(
            self._snapshot_claim,
            self._inventory.original,
        )
        return _OwnerBoundStream(self, stream)
    def memory_descriptors(self) -> tuple[_FrozenMemoryBlockDescriptor, ...]:
        self._require_active()
        return tuple(
            _FrozenMemoryBlockDescriptor(
                handle, row.space_id, row.byte_start, row.byte_size,
                row.is_loaded, row.is_initialized, row.is_overlay,
                row.is_external, row.is_mapped,
            )
            for row, handle in zip(self._inventory.blocks, self._block_handles)
        )
    def read_exact(
        self,
        handle: object,
        block_relative_offset: int,
        length: int,
    ) -> _Iterator[_PositionedChunk]:
        self._require_active()
        index = self._block_index(handle)
        if self._block_used[index]:
            raise RuntimeError("configured block handle has already been used")
        self._block_used[index] = True
        member = self._inventory.blocks[index].member
        if member is None:
            raise ValueError("configured block handle has no byte member")
        stream = self._snapshot.verified_chunks(
            self._snapshot_claim, member, block_relative_offset, length
        )
        return _OwnerBoundStream(self, stream)
    def snapshot_complete(self) -> bool:
        self._require_active()
        return self._program_verified
    def spaces_complete(self) -> bool:
        self._require_active()
        return self._program_verified
    def program_candidate(self) -> _RawObject:
        self._require_active()
        if self._program_claimed:
            raise RuntimeError("configured program candidate is single-use")
        self._program_claimed = True
        payload = self._snapshot.verified_bytes(self._snapshot_claim, self._inventory.program)
        self._program_verified = True
        return _parse_raw_json(payload)
    def function_handles(self) -> object:
        self._require_active()
        if self._functions_claimed:
            raise RuntimeError("configured function handles are single-use")
        self._functions_claimed = True
        return self._function_handles
    def observation_complete(self, handle: object) -> bool:
        self._require_active()
        return self._function_parsed[self._function_index(handle)]
    def function_candidate(self, handle: object) -> _RawObject | None:
        self._require_active()
        index = self._claim_function(handle)
        self._observation_used[index] = True
        self._invalidate_sidecars(index)
        raw = _parse_raw_json(self._snapshot.verified_bytes(
            self._snapshot_claim, self._inventory.functions[index].observation_member
        ))
        self._function_parsed[index] = True
        return raw
    def close(self) -> None:
        self._require_owner()
        if self._closed:
            return
        if self._active_guards:
            raise RuntimeError("configured bundle provider has an active function guard")
        self._closed = True
        self._block_used[:] = [True] * len(self._block_used)
        self._block_indexes.clear()
        self._function_used[:] = [True] * len(self._function_used)
        self._function_parsed[:] = [False] * len(self._function_parsed)
        self._function_indexes.clear()
        self._snapshot.close(self._snapshot_claim)
    def _require_active(self) -> None:
        self._require_owner()
        if self._closed:
            raise RuntimeError("configured bundle provider is closed")
        self._snapshot.inventory(self._snapshot_claim)
    def _require_owner(self) -> None:
        if _current_thread() is not self._owner:
            raise RuntimeError("configured bundle provider is owner-thread confined")
    def _block_index(self, handle: object) -> int:
        if type(handle) is _BlockHandle:
            index = self._block_indexes.get(id(handle))
            if index is not None and handle is self._block_handles[index]:
                return index
        raise ValueError("block handle is foreign or forged")
    def _function_index(self, handle: object) -> int:
        if type(handle) is _FunctionHandle:
            index = self._function_indexes.get(id(handle))
            if index is not None and handle is self._function_handles[index]:
                return index
        raise ValueError("function handle is foreign or forged")
    def _claim_function(self, handle: object) -> int:
        index = self._function_index(handle)
        if self._function_used[index]:
            raise RuntimeError("configured function has already been used")
        self._function_used[index] = True
        return index
    def _invalidate_sidecars(self, index: int) -> None:
        """V1 has no sidecar roles; V2 overrides this projection."""

    def _enter_function_guard(self, handle: object) -> "_FunctionTransportGuard":
        self._require_active()
        index = self._function_index(handle)
        if self._function_used[index]:
            raise RuntimeError("configured function has already been claimed")
        self._function_used[index] = True
        self._active_guards += 1
        try:
            return _FunctionTransportGuard(
                self,
                index,
                _FUNCTION_GUARD_CONSTRUCTOR,
            )
        except BaseException:
            self._active_guards -= 1
            raise
    def __reduce_ex__(self, protocol: int):
        raise TypeError("configured bundle provider cannot be serialized")


class _ConfiguredBundleV1Provider(_ConfiguredBundleProvider):
    __slots__ = ()


class _ConfiguredBundleV2Provider(_ConfiguredBundleProvider):
    __slots__ = (
        "_container_identity",
        "_profile_identity",
        "_profile_used",
        "_sidecar_used",
    )

    def __init__(self, snapshot, snapshot_claim) -> None:
        super().__init__(snapshot, snapshot_claim)
        profile = self._inventory.call_interface_profile_member
        if profile is None:
            raise RuntimeError("admitted V2 bundle is missing its call-interface profile")
        self._container_identity = self._inventory.container_identity
        self._profile_identity = profile.identity
        self._profile_used = False
        self._sidecar_used = [False] * (2 * len(self._inventory.functions))

    @property
    def container_identity(self):
        self._require_active()
        return self._container_identity
    @property
    def call_interface_profile_identity(self):
        self._require_active()
        return self._profile_identity
    def call_interface_profile_bytes(self) -> bytes:
        self._require_active()
        if self._profile_used:
            raise RuntimeError("configured call-interface profile has already been consumed")
        self._profile_used = True
        profile = self._inventory.call_interface_profile_member
        if profile is None:
            raise RuntimeError("admitted V2 bundle lost its call-interface profile")
        return self._snapshot.verified_bytes(
            self._snapshot_claim, profile, max_bytes=_MAX_PROFILE_BYTES
        )
    def claim_function_transport(self, handle: object) -> "_FunctionTransportReservation":
        self._require_active()
        index = self._function_index(handle)
        if self._function_used[index]:
            raise RuntimeError("configured function has already been claimed")
        return _FunctionTransportReservation(self, handle)
    def _invalidate_sidecars(self, index: int) -> None:
        self._sidecar_used[2 * index] = True
        self._sidecar_used[2 * index + 1] = True
    def _consume_sidecar(self, index: int, role: int) -> bytes:
        self._require_active()
        slot = 2 * index + role
        if self._sidecar_used[slot]:
            raise RuntimeError("configured function role has already been consumed")
        self._sidecar_used[slot] = True
        function = self._inventory.functions[index]
        member = function.call_names_member if role == 0 else function.call_effects_member
        if member is None:
            raise RuntimeError("admitted V2 bundle lost a required function sidecar")
        return self._snapshot.verified_bytes(
            self._snapshot_claim, member, max_bytes=_MAX_SIDECAR_BYTES
        )
    def _guard_observation(self, index: int) -> _RawObject:
        self._require_active()
        if self._observation_used[index]:
            raise RuntimeError("configured function role has already been consumed")
        self._observation_used[index] = True
        raw = _parse_raw_json(self._snapshot.verified_bytes(
            self._snapshot_claim, self._inventory.functions[index].observation_member
        ))
        self._function_parsed[index] = True
        return raw
    def _function_transport_identity(self, index: int):
        return self._inventory.functions[index].transport_identity
    def _finish_function_guard(self, index: int) -> None:
        self._sidecar_used[2 * index] = True
        self._sidecar_used[2 * index + 1] = True
        self._observation_used[index] = True
        self._active_guards -= 1


class _FunctionTransportReservation:
    __slots__ = ("_entered", "_exited", "_guard", "_handle", "_index", "_owner", "_provider")
    def __init__(self, provider: _ConfiguredBundleV2Provider, handle: object) -> None:
        self._provider = provider
        self._handle = handle
        self._index = None
        self._guard = None
        self._owner = _current_thread()
        self._entered = False
        self._exited = False
    def __enter__(self) -> "_FunctionTransportGuard":
        self._provider._require_owner()
        if _current_thread() is not self._owner:
            raise RuntimeError("configured function reservation is owner-thread confined")
        if self._entered or self._exited:
            raise RuntimeError("configured function reservation is non-reentrant")
        guard = self._provider._enter_function_guard(self._handle)
        self._index = guard._index
        self._guard = guard
        self._entered = True
        return guard
    def __exit__(self, exc_type, exc, traceback) -> None:
        self._provider._require_owner()
        if not self._entered or self._exited:
            raise RuntimeError("configured function reservation is not active")
        guard = self._guard
        index = self._index
        if guard is None or index is None:
            raise RuntimeError("configured function reservation lost its active guard")
        self._exited = True
        guard._exited = True
        self._provider._finish_function_guard(index)
    def __reduce_ex__(self, protocol: int):
        raise TypeError("configured function reservation cannot be serialized")

class _FunctionTransportGuard:
    __slots__ = ("_entered", "_exited", "_identity", "_index", "_provider")
    def __init__(
        self,
        provider: _ConfiguredBundleV2Provider,
        index: int,
        constructor: object,
    ) -> None:
        if constructor is not _FUNCTION_GUARD_CONSTRUCTOR:
            raise PermissionError("configured function guard constructor is private")
        self._provider = provider
        self._index = index
        self._identity = provider._function_transport_identity(index)
        self._entered = True
        self._exited = False
    @property
    def transport_identity(self):
        self._require_active()
        return self._identity
    def observation_candidate(self) -> _RawObject:
        self._require_active()
        return self._provider._guard_observation(self._index)
    def call_names_bytes(self) -> bytes:
        self._require_active()
        return self._provider._consume_sidecar(self._index, 0)
    def call_effects_bytes(self) -> bytes:
        self._require_active()
        return self._provider._consume_sidecar(self._index, 1)
    def _require_active(self) -> None:
        self._provider._require_owner()
        if not self._entered or self._exited:
            raise RuntimeError("configured function guard is not active")
        self._provider._require_active()
    def __reduce_ex__(self, protocol: int):
        raise TypeError("configured function guard cannot be serialized")


def _construct_provider(snapshot, expected_type, provider_type):
    if type(snapshot) is not expected_type:
        raise TypeError("configured bundle reader requires its exact nominal snapshot")
    snapshot_claim = _claim_bundle_snapshot(snapshot)
    try:
        return provider_type(snapshot, snapshot_claim)
    except BaseException:
        snapshot.close(snapshot_claim)
        raise


def read_configured_bundle(snapshot: _ConfiguredBundleV2Snapshot, /) -> _FrozenProgramViewProvider:
    """Return a private V2 provider owning one exact active admitted snapshot."""
    return _construct_provider(snapshot, _ConfiguredBundleV2Snapshot, _ConfiguredBundleV2Provider)


def read_configured_bundle_v1_compatibility(
    snapshot: _ConfiguredBundleV1CompatibilitySnapshot, /
) -> _FrozenProgramViewProvider:
    """Return the observations-only provider for an exact V1 snapshot."""
    return _construct_provider(
        snapshot,
        _ConfiguredBundleV1CompatibilitySnapshot,
        _ConfiguredBundleV1Provider,
    )
