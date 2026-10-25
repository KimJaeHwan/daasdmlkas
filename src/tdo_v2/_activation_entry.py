"""Bounded entry values of one caller-owned callee activation.

The owner validates the caller's original pre-call evidence. These inputs
are not generic callee facts, allocation bounds, or a replacement memory SSA.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from .constant_value import ExactConstant
from .span_geometry import ByteSpan, StorageObjectKind, StorageScopeId, StorageScopeKind


@dataclass(frozen=True, slots=True)
class ActivationEntry:
    scope: StorageScopeId
    context: tuple[str, str]
    registers: tuple[tuple[ByteSpan, ByteSpan, int], ...]
    memory: tuple[tuple[ByteSpan, ExactConstant], ...]
    requires: tuple[str, ...]

    def __post_init__(self):
        if type(self.scope) is not StorageScopeId or self.scope.kind is not StorageScopeKind.FUNCTION:
            raise TypeError("activation requires an exact function scope")
        if type(self.context) is not tuple or len(self.context) != 2 \
                or any(type(item) is not str or not item for item in self.context):
            raise TypeError("activation context is (caller function, original call)")
        if type(self.requires) is not tuple or any(type(item) is not str or not item for item in self.requires):
            raise TypeError("activation requirements must be exact nonempty strings")
        if type(self.registers) is not tuple or type(self.memory) is not tuple:
            raise TypeError("activation inputs must be immutable tuples")
        destinations = []
        for row in self.registers:
            if type(row) is not tuple or len(row) != 3:
                raise TypeError("register seed is (destination, base, signed delta)")
            destination, base, delta = row
            if type(destination) is not ByteSpan or type(base) is not ByteSpan \
                    or destination.object_id.kind is not StorageObjectKind.REGISTER_FILE \
                    or base.object_id.kind is not StorageObjectKind.REGISTER_FILE \
                    or destination.object_id != base.object_id or destination.size != base.size \
                    or not 1 <= destination.size <= 16 or type(delta) is not int:
                raise TypeError("register seed needs same-file, same-width whole registers")
            bits = 8 * destination.size
            if not -(1 << (bits - 1)) <= delta < 1 << (bits - 1):
                raise ValueError("register seed delta is not signed at its width")
            if any(destination.overlaps(previous) for previous in destinations):
                raise ValueError("overlapping register activation seeds")
            destinations.append(destination)
        spans = []
        for row in self.memory:
            if type(row) is not tuple or len(row) != 2:
                raise TypeError("memory seed is (span, exact constant)")
            span, literal = row
            if type(span) is not ByteSpan or span.object_id.kind not in (
                    StorageObjectKind.FUNCTION_RELATIVE, StorageObjectKind.ADDRESS_SPACE) \
                    or type(literal) is not ExactConstant or literal.byte_size != span.size:
                raise TypeError("memory seed needs an exact full-width memory literal")
            if span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE and span.object_id.scope != self.scope:
                raise ValueError("memory seed belongs to another function")
            if any(span.overlaps(previous) for previous in spans):
                raise ValueError("overlapping memory activation seeds")
            spans.append(span)


ACTIVE_ENTRY: ContextVar[ActivationEntry | None] = ContextVar("tdo_activation_entry", default=None)


@contextmanager
def using_entry(state: ActivationEntry | None):
    """Use captured state, including masking an unrelated ambient activation."""
    if state is not None and type(state) is not ActivationEntry:
        raise TypeError("activation state must be ActivationEntry or None")
    token = ACTIVE_ENTRY.set(state)
    try:
        yield state
    finally:
        ACTIVE_ENTRY.reset(token)


def entry_for(scope):
    state = ACTIVE_ENTRY.get()
    return state if type(state) is ActivationEntry and state.scope == scope else None


def entry_seed(scope, requested_span):
    """One exact register or wholly covered little-endian memory value.

    Partial overlap never supplies uncovered bytes; a subregister cannot use
    a whole-register affine relation (carries would need another proof).
    """
    state = entry_for(scope)
    if state is None or type(requested_span) is not ByteSpan:
        return None
    if requested_span.object_id.kind is StorageObjectKind.REGISTER_FILE:
        for destination, base, delta in state.registers:
            if destination == requested_span:
                return "affine", base, delta
        return None
    for span, literal in state.memory:
        if span.contains(requested_span):
            shift = 8 * (requested_span.start - span.start)
            unsigned = (literal.unsigned >> shift) & ((1 << (8 * requested_span.size)) - 1)
            return "constant", ExactConstant(requested_span.size, unsigned)
    return None
