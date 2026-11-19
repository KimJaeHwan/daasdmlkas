"""(O-1, docs 25.105) A summarized call's output rows are one simultaneous
final state.

A call ``c``'s **output rows** are its staged rows labelled ``c~<n>`` (register
and memory outputs and accessor results share that index), ``c~u<n>`` (unknown
memory) and ``c~ov<n>`` (overlap regions). The normalisation emits them as one
contiguous run of a block (``normalize._call_effect_rows``). In the callee they
are written in an order nobody knows, so no output row may kill a sibling's
candidate: every kill engine (dense / sparse may-alias, exit crossings) moves
the kills of a group's members to the group's first position and keeps every
gen where it is (``design_o1_r2.md`` .. ``r4``).

Fail-safes -- the members kill nothing (an over-approximation): the call's
output rows in a block are not one contiguous run, or a member other than the
first reads tracked memory (a read there would see pre-call writers the hoisted
kill already removed). Both are counted (``o1_group_failsafe_*``)."""

from __future__ import annotations

import re

from .model import ResolvedStorage, StorageObjectKind
from .phases import count as phase_count

_OUTPUT_TAG = re.compile(r"(?:\d+|u\d+|ov\d+)")
_MEMORY_KINDS = frozenset({StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE})
_CACHE: dict = {}   # id(effects tuple) -> (effects, groups); identity-checked
_CACHE_LIMIT = 4096


def output_call(key: str) -> str | None:
    """The call key whose output row ``key`` is (``c~<n>``, ``c~u<n>``,
    ``c~ov<n>``), else None (``~push``, ``~ld``, ``~in``, raw ops, ...)."""
    base, sep, tag = key.rpartition("~")
    if not sep or not base or _OUTPUT_TAG.fullmatch(tag) is None:
        return None
    return base


def _tracked_read(effect) -> bool:
    if effect.memory_read is not None or effect.unresolved_reads:
        return True
    return any(type(evidence) is ResolvedStorage and evidence.span.object_id.kind in _MEMORY_KINDS
               for evidence in effect.reads)


def call_output_groups(effects) -> dict:
    """Output-row key -> its group: ``(first position, member positions)``
    for a member of a valid group of two or more rows, or None for a member
    of a call whose rows fail a fail-safe (it kills nothing). Keys absent:
    ordinary effects (and single-row groups, whose kill stays in place)."""
    effects = tuple(effects)
    hit = _CACHE.get(id(effects))
    if hit is not None and hit[0] is effects:
        return hit[1]
    runs: dict = {}
    for position, effect in enumerate(effects):
        call = output_call(effect.operation_key)
        if call is not None:
            runs.setdefault(call, []).append(position)
    groups: dict = {}
    for call, positions in runs.items():
        if len(positions) < 2:
            continue
        keys = [effects[position].operation_key for position in positions]
        if positions != list(range(positions[0], positions[-1] + 1)):
            phase_count("o1_group_failsafe_noncontiguous", 1)
            groups.update(dict.fromkeys(keys))
        elif any(_tracked_read(effects[position]) for position in positions[1:]):
            phase_count("o1_group_failsafe_read", 1)
            groups.update(dict.fromkeys(keys))
        else:
            group = (positions[0], tuple(positions))
            groups.update(dict.fromkeys(keys, group))
    if len(_CACHE) >= _CACHE_LIMIT:
        _CACHE.clear()
    _CACHE[id(effects)] = (effects, groups)
    return groups
