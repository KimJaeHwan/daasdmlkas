"""(O-1, docs 25.105) A digest-free order for a proven call effect's rows.

The staged rows of a summarized call are emitted in the order of the effect's
lists (``memory_runs``, ``unknown_memory``, row ``loads`` / conditions,
``writer_conditions``): their labels (``~<n>``, ``~u<n>``, ``~ld<j>``) follow
that order. Results do not depend on it (a call's output rows are one
simultaneous state, ``_call_groups``), but labels should not change when a
Bundle's bytes change. ``canonical_effect`` sorts those lists by ``_stable``,
a positional, digest-free encoding of every field -- exact only when every
storage it meets is a register-file or address-space object (one per program
scope; exported effect storage reduces to those through anchoring). A list
with any other storage keeps its order (labels only: a named limitation, as is
the ``~ov`` order and ``sink_demands`` order, design_o1_r4 final fixes).
Duplicates (equal items) are dropped."""

from __future__ import annotations

import dataclasses
from enum import Enum

from .model import StorageObjectKind
from .span_geometry import ByteSpan

_EXACT_KINDS = frozenset({StorageObjectKind.REGISTER_FILE, StorageObjectKind.ADDRESS_SPACE})


class _Inexact(Exception):
    """A value whose order would rest on a digest."""


def _stable(value):
    """Positional, digest-free encoding (every element an int-tagged tuple,
    so any two encodings compare)."""
    if value is None:
        return (0,)
    if type(value) is bool:
        return (1, value)
    if type(value) is int:
        return (2, value)
    if type(value) is str:
        return (3, value)
    if isinstance(value, Enum):
        return (4, type(value).__name__, str(value.value))
    if type(value) is ByteSpan:
        object_id = value.object_id
        if object_id.kind not in _EXACT_KINDS:
            raise _Inexact(object_id.kind)
        return (5, object_id.kind.value, object_id.scope.kind.value, object_id.space_key, value.start, value.size)
    if isinstance(value, tuple):
        return (6, tuple(_stable(item) for item in value))
    if isinstance(value, (set, frozenset)):
        return (7, tuple(sorted(_stable(item) for item in value)))
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return (8, type(value).__name__,
                tuple(_stable(getattr(value, field.name)) for field in dataclasses.fields(value)))
    raise _Inexact(type(value).__name__)


def _ordered(items) -> tuple:
    """``items`` sorted by ``_stable`` with equal items dropped; unchanged
    (duplicates still dropped) when any key is inexact."""
    items = tuple(items)
    try:
        keyed = sorted(((_stable(item), index) for index, item in enumerate(items)), key=lambda pair: pair)
    except _Inexact:
        keyed = [(None, index) for index in range(len(items))]
    found, seen = [], set()
    for _, index in keyed:
        item = items[index]
        try:
            if item in seen:
                continue
            seen.add(item)
        except TypeError:   # (an unhashable item: compared by equality)
            if item in found:
                continue
        found.append(item)
    return tuple(found)


def _inner(row):
    """A run / sink demand with its ``loads`` and ``conditions`` ordered."""
    changes = {}
    if hasattr(row, "loads"):
        changes["loads"] = _ordered(row.loads)
    if hasattr(row, "conditions"):
        changes["conditions"] = _ordered(row.conditions)
    return dataclasses.replace(row, **changes) if changes else row


def canonical_effect(effect):
    """``effect`` with its row lists in the digest-free order (None stays
    None). ``sink_demands`` keep their order (their positional ``sink<i>``
    identities are published) -- only their inner lists are ordered."""
    from .call_summary_effects import ProvenCallEffect

    if type(effect) is not ProvenCallEffect:
        return effect   # (None, or a caller's own stand-in)
    return dataclasses.replace(
        effect,
        runs=tuple(_inner(run) for run in effect.runs),
        memory_runs=_ordered(_inner(run) for run in effect.memory_runs),
        unknown_memory=_ordered(effect.unknown_memory),
        writer_conditions=_ordered(effect.writer_conditions),
        sink_demands=tuple(_inner(demand) for demand in effect.sink_demands),
    )
