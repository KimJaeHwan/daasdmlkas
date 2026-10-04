"""Detached evidence degradation with deterministic precedence."""

from __future__ import annotations

from ._scope_raw import RawObject, _FieldState, _field, _has_duplicate
from ._scope_results import (
    ScopeConstructionReason,
    ScopeConstructionStage,
    UnresolvedProgramScope,
)


def load_detached_program_scope(raw: RawObject) -> UnresolvedProgramScope:
    if type(raw) is not RawObject:
        raise TypeError("detached scope input must be an exact RawObject")
    duplicate = _has_duplicate(
        raw,
        ("executable_sha256", "loaded_memory_digest", "translation_namespace"),
    )
    translation = _field(raw, "translation_namespace")
    if translation.state is _FieldState.PRESENT and type(translation.value) is RawObject:
        duplicate |= _has_duplicate(
            translation.value,
            ("language_id", "major_version", "minor_version"),
        )
    if duplicate:
        return UnresolvedProgramScope(
            ScopeConstructionStage.PROGRAM_CONTENT,
            ScopeConstructionReason.PROGRAM_DUPLICATE_FIELD,
        )
    executable = _field(raw, "executable_sha256")
    if executable.state is _FieldState.MISSING:
        return UnresolvedProgramScope(
            ScopeConstructionStage.PROGRAM_CONTENT,
            ScopeConstructionReason.MISSING_EXECUTABLE_SHA256,
        )
    if not _is_hex32(executable.value):
        return UnresolvedProgramScope(
            ScopeConstructionStage.PROGRAM_CONTENT,
            ScopeConstructionReason.INVALID_EXECUTABLE_SHA256,
        )
    return UnresolvedProgramScope(
        ScopeConstructionStage.PROGRAM_CONTENT,
        ScopeConstructionReason.UNVERIFIED_PROGRAM_CONTENT,
    )


def _is_hex32(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
