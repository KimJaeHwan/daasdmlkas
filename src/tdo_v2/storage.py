"""Architecture-metadata-driven structured storage resolution."""

from __future__ import annotations

from .model import (
    AddressSpace,
    ArchitectureFacts,
    ByteSpan,
    NonStorage,
    ResolvedStorage,
    StorageObjectId,
    StorageObjectKind,
    StorageRef,
    StorageResolutionContext,
    StorageScopeId,
    StorageScopeKind,
    UnresolvedReason,
    UnresolvedStorage,
    VarnodeKind,
)


class StorageResolver:
    """Resolve observed raw storage using only structured metadata evidence."""

    def __init__(self, architecture: ArchitectureFacts) -> None:
        if type(architecture) is not ArchitectureFacts:
            raise TypeError("architecture must be an exact ArchitectureFacts")
        if type(architecture.address_spaces) is not tuple:
            raise TypeError("address spaces must be an exact tuple")
        if any(type(row) is not AddressSpace for row in architecture.address_spaces):
            raise TypeError("address-space rows must be exact AddressSpace values")
        self._address_spaces = architecture.address_spaces

    def resolve(
        self, storage: StorageRef, context: StorageResolutionContext
    ) -> ResolvedStorage | UnresolvedStorage | NonStorage:
        if type(storage) is not StorageRef:
            raise TypeError("storage must be an exact StorageRef")
        if type(context) is not StorageResolutionContext:
            raise TypeError("context must be an exact StorageResolutionContext")

        kind = storage.kind
        if kind is VarnodeKind.CONSTANT:
            return NonStorage()
        if not any(
            kind is supported
            for supported in (
                VarnodeKind.REGISTER,
                VarnodeKind.UNIQUE,
                VarnodeKind.ADDRESS,
                VarnodeKind.STORAGE,
            )
        ):
            return _unresolved(UnresolvedReason.UNSUPPORTED_KIND)

        if kind is VarnodeKind.UNIQUE:
            scope = context.function_scope
            scope_kind = StorageScopeKind.FUNCTION
            object_kind = StorageObjectKind.FUNCTION_UNIQUE
        else:
            scope = context.program_scope
            scope_kind = StorageScopeKind.PROGRAM
            object_kind = StorageObjectKind.REGISTER_FILE

        if scope is None:
            return _unresolved(UnresolvedReason.MISSING_SCOPE)
        if scope.kind is not scope_kind:
            return _unresolved(UnresolvedReason.INVALID_SCOPE)

        offset = storage.offset
        if offset is None:
            return _unresolved(UnresolvedReason.MISSING_OFFSET)
        if type(offset) is not int or offset < 0:
            return _unresolved(UnresolvedReason.INVALID_OFFSET)

        if kind is VarnodeKind.REGISTER or kind is VarnodeKind.UNIQUE:
            return _resolved(object_kind, scope, 0, offset, storage.size)
        return self._resolve_address(storage, scope, offset)

    def _resolve_address(
        self, storage: StorageRef, scope: StorageScopeId, offset: int
    ) -> ResolvedStorage | UnresolvedStorage:
        selected_id = storage.space_id
        if selected_id is None:
            return _unresolved(UnresolvedReason.MISSING_SPACE_ID)
        if type(selected_id) is not int or selected_id < 0:
            return _unresolved(UnresolvedReason.INVALID_SPACE_ID)

        same_id = tuple(
            row
            for row in self._address_spaces
            if type(row.space_id) is int and row.space_id == selected_id
        )
        if not same_id:
            return _unresolved(UnresolvedReason.UNKNOWN_SPACE)

        classification = _space_classification(same_id[0])
        if any(
            classification != _space_classification(row)
            for row in same_id[1:]
        ):
            return _unresolved(UnresolvedReason.CONFLICTING_SPACE)
        if not _is_supported_memory(same_id[0]):
            return _unresolved(UnresolvedReason.UNSUPPORTED_KIND)
        if any(row.word_size is None for row in same_id):
            return _unresolved(UnresolvedReason.MISSING_UNIT)
        if any(
            type(row.word_size) is not int or not 1 <= row.word_size <= 8
            for row in same_id
        ):
            return _unresolved(UnresolvedReason.INVALID_UNIT)
        if any(row.address_size is None for row in same_id):
            return _unresolved(UnresolvedReason.MISSING_ADDRESS_SIZE)
        if any(not _has_valid_address_size(row) for row in same_id):
            return _unresolved(UnresolvedReason.INVALID_ADDRESS_SIZE)

        geometries = {(row.word_size, row.address_size) for row in same_id}
        if len(geometries) != 1:
            return _unresolved(UnresolvedReason.CONFLICTING_SPACE)
        unit, address_size = geometries.pop()
        capacity = unit << address_size
        if offset + storage.size > capacity:
            return _unresolved(UnresolvedReason.RANGE_OUT_OF_BOUNDS)
        return _resolved(
            StorageObjectKind.ADDRESS_SPACE,
            scope,
            selected_id,
            offset,
            storage.size,
        )


def _resolve_validated_storage(
    storage: StorageRef,
    context: StorageResolutionContext,
) -> ResolvedStorage | UnresolvedStorage | NonStorage:
    """Resolve storage already validated by the configured scope envelope."""
    if type(storage) is not StorageRef:
        raise TypeError("storage must be an exact StorageRef")
    if type(context) is not StorageResolutionContext:
        raise TypeError("context must be an exact StorageResolutionContext")
    if storage.offset is None:
        return _unresolved(UnresolvedReason.MISSING_OFFSET)
    if type(storage.offset) is not int or storage.offset < 0:
        return _unresolved(UnresolvedReason.INVALID_OFFSET)
    if storage.kind is VarnodeKind.CONSTANT:
        return NonStorage()
    if storage.kind is VarnodeKind.UNIQUE:
        scope = context.function_scope
        if scope is None:
            return _unresolved(UnresolvedReason.MISSING_SCOPE)
        if scope.kind is not StorageScopeKind.FUNCTION:
            return _unresolved(UnresolvedReason.INVALID_SCOPE)
        return _resolved(
            StorageObjectKind.FUNCTION_UNIQUE,
            scope,
            0,
            storage.offset,
            storage.size,
        )
    if storage.kind in (VarnodeKind.REGISTER, VarnodeKind.ADDRESS, VarnodeKind.STORAGE):
        scope = context.program_scope
        if scope is None:
            return _unresolved(UnresolvedReason.MISSING_SCOPE)
        if scope.kind is not StorageScopeKind.PROGRAM:
            return _unresolved(UnresolvedReason.INVALID_SCOPE)
        if storage.kind is VarnodeKind.REGISTER:
            return _resolved(
                StorageObjectKind.REGISTER_FILE,
                scope,
                0,
                storage.offset,
                storage.size,
            )
        if storage.space_id is None:
            return _unresolved(UnresolvedReason.MISSING_SPACE_ID)
        if type(storage.space_id) is not int or storage.space_id < 0:
            return _unresolved(UnresolvedReason.INVALID_SPACE_ID)
        return _resolved(
            StorageObjectKind.ADDRESS_SPACE,
            scope,
            storage.space_id,
            storage.offset,
            storage.size,
        )
    return _unresolved(UnresolvedReason.UNSUPPORTED_KIND)


def _is_supported_memory(row: AddressSpace) -> bool:
    return (
        type(row.is_memory_space) is bool
        and row.is_memory_space is True
        and type(row.is_overlay_space) is bool
        and row.is_overlay_space is False
    )


def _space_classification(row: AddressSpace) -> tuple[int, int]:
    return (
        _classification_field(row.is_memory_space),
        _classification_field(row.is_overlay_space),
    )


def _classification_field(value: object) -> int:
    if value is None:
        return 0
    if type(value) is bool:
        return 1 if value is False else 2
    return 3


def _has_valid_address_size(row: AddressSpace) -> bool:
    address_size = row.address_size
    unit = row.word_size
    return (
        type(address_size) is int
        and 1 <= address_size <= 64
        and address_size + (unit - 1).bit_length() <= 64
    )


def _resolved(
    kind: StorageObjectKind,
    scope: StorageScopeId,
    space_key: int,
    start: int,
    size: int,
) -> ResolvedStorage:
    return ResolvedStorage(ByteSpan(StorageObjectId(kind, scope, space_key), start, size))


def _unresolved(reason: UnresolvedReason) -> UnresolvedStorage:
    return UnresolvedStorage(reason)
