"""CallClobberRead records from the chi view (docs 25.83 S2b'): the lazy
sparse chi SSA (``_chi_shadow.LazySparse``, V2) derives the rows
``call_clobber`` derives today, for the value view (the chi-free memory SSA,
V1) to stay untouched. Behind ``TDO_V2_CHI_RECORDS`` (off by default):

- ``check``: V2's rows are used and must equal ``call_clobber``'s exactly --
  same rows, same order (consumers zip rows with their debt nodes by order);
  any difference raises ``ChiRecordsMismatch``;
- ``only``: V2's rows are used, ``call_clobber`` is not run (a measurement
  and the test that consumers receive V2's rows).

V2's work is the analysis's own (``step``, the run's budget). Its own bound:
a function whose calls x connected spans exceed ``LIMIT`` falls back to
``call_clobber``'s rows explicitly (``FALLBACKS``), never an empty set."""

from __future__ import annotations

import os

from .model import ResolvedStorage
from .resource_limits import step
from .span_geometry import ByteSpan

LIMIT = 200_000
# function scope -> reason, for the functions that used call_clobber's rows
FALLBACKS: dict = {}


class ChiRecordsMismatch(AssertionError):
    """The chi view's records differ from ``call_clobber``'s."""


def mode() -> str | None:
    value = os.environ.get("TDO_V2_CHI_RECORDS")
    if value in (None, "", "0"):
        return None
    if value not in ("check", "only"):
        raise ValueError(f"TDO_V2_CHI_RECORDS={value!r}: expected check or only")
    return value


def chi_records(memory_unit, effect_unit, calls, preserved, memory_keeping) -> tuple:
    """``call_clobber``'s rows, from the chi view: per effect (blocks by key,
    effects in order) the read bytes some call's chi reaches -- per read one
    span from its first to its last such byte -- and the calls crossed."""
    from .call_clobber import CallClobberRead
    from ._chi_shadow import LazySparse

    if memory_unit.effect_evidence_digest != effect_unit.effect_evidence_digest:
        raise ChiRecordsMismatch("the memory unit is not this effect unit's")
    lazy = LazySparse(memory_unit, frozenset(calls), preserved, frozenset(memory_keeping))
    rows = []
    for block in sorted(effect_unit.blocks, key=lambda item: item.key):
        for effect in block.effects:
            spans, crossed_all = [], set()
            for evidence in effect.reads:
                if type(evidence) is not ResolvedStorage:
                    continue
                span = evidence.span
                first = last = None
                for offset in range(span.start, span.end):
                    step()
                    crossed = lazy.crossed_at(effect.operation_key, span.object_id, offset)
                    if crossed:
                        first = offset if first is None else first
                        last = offset
                        crossed_all |= crossed
                if first is not None:
                    spans.append(ByteSpan(span.object_id, first, last + 1 - first))
            if spans:
                rows.append(CallClobberRead(effect.operation_key, tuple(spans), tuple(sorted(crossed_all))))
    return tuple(rows)


def records(scope, legacy, memory_unit, effect_unit, observation, context, assumed_calls, proven_preserved,
            unrestored, memory_keeping):
    """The rows the consumers get: ``legacy()`` (call_clobber's) when the
    switch is off or the function is over ``LIMIT``; else V2's, compared
    with ``legacy()`` under ``check``."""
    selected = mode()
    if selected is None:
        return legacy()
    from .call_clobber import clobber_inputs
    from .memory_ssa import _build_partition

    calls, preserved = clobber_inputs(observation, context, assumed_calls, proven_preserved, unrestored)
    if not calls:
        return legacy()
    present = sum(1 for block in memory_unit.blocks for action in block.actions if action.operation_key in calls)
    if present * len(_build_partition(memory_unit).connected) > LIMIT:
        FALLBACKS[scope] = "limit"
        return legacy()
    rows = chi_records(memory_unit, effect_unit, calls, preserved, memory_keeping & calls)
    if selected == "check":
        expected = tuple(legacy())
        if rows != expected:
            index = next((i for i, (a, b) in enumerate(zip(rows, expected)) if a != b), min(len(rows), len(expected)))
            left = repr(rows[index])[:300] if index < len(rows) else "<missing>"
            right = repr(expected[index])[:300] if index < len(expected) else "<missing>"
            raise ChiRecordsMismatch(f"chi records differ from call_clobber's: {len(rows)} vs {len(expected)} rows, "
                                     f"first difference at [{index}]: {left} != {right}")
    return rows
