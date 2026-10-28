"""CallClobberRead records from the chi view (docs 25.83 S2b', D5'): the lazy
sparse chi SSA (``_chi_shadow.LazySparse``, V2) derives the rows
``call_clobber`` derived, for the value view (the chi-free memory SSA, V1) to
stay untouched. ``TDO_V2_CHI_RECORDS`` selects the producer:

- unset / ``only`` (the default): V2's rows;
- ``check``: V2's rows, which must equal ``call_clobber``'s exactly -- same
  rows, same order (by operation key; consumers zip rows with their debt
  nodes by order); any difference raises ``ChiRecordsMismatch``;
- ``legacy``: ``call_clobber``'s rows (V2 not run).

V2's work is the analysis's own (``step``: the function's and the run's
budgets) and has a bound of its own: a function whose present calls x
connected spans exceed ``LIMIT`` is not attempted, and V2 stops after
``work_bound`` units (``bounded``: ``BoundExceeded``). Either way the
function's rows are ``call_clobber``'s, recorded per run in
``RunBudget.fallbacks["chi_records"]`` (function scope -> "limit" / "work"),
never an empty set. A function without a call with an effect has no chi:
its rows are empty without running either engine (``call_clobber`` returns
the same: no clobbering call, nothing crossed)."""

from __future__ import annotations

import os

from .model import ResolvedStorage
from .resource_limits import BoundExceeded, bounded, current_run, step
from .span_geometry import ByteSpan

LIMIT = 200_000
# V2's own work bound: a base plus a share per memory action (the gate
# Bundles used at most ~150 units per action before the per-class memo: docs 25.83 D5')
WORK_BASE = 1_000_000
WORK_PER_ACTION = 2_000


class ChiRecordsMismatch(AssertionError):
    """The chi view's records differ from ``call_clobber``'s."""


def mode() -> str:
    value = os.environ.get("TDO_V2_CHI_RECORDS")
    if value in (None, ""):
        return "only"
    if value not in ("only", "check", "legacy"):
        raise ValueError(f"TDO_V2_CHI_RECORDS={value!r}: expected only, check or legacy")
    return value


def work_bound(memory_unit) -> int:
    return WORK_BASE + WORK_PER_ACTION * sum(len(block.actions) for block in memory_unit.blocks)


def fallbacks(run=None) -> dict:
    """Function scope -> reason, for the functions of ``run`` (default: the
    current one) that used ``call_clobber``'s rows."""
    run = run or current_run()
    return {} if run is None else run.fallbacks.get("chi_records", {})


def _fall_back(scope, reason, legacy):
    run = current_run()
    if run is not None:
        run.fallbacks.setdefault("chi_records", {})[scope] = reason
    return legacy()


def chi_records(memory_unit, effect_unit, calls, preserved, memory_keeping) -> tuple:
    """``call_clobber``'s rows, from the chi view: per effect the read bytes
    some call's chi reaches -- per read one span from its first to its last
    such byte -- and the calls crossed; sorted by operation key as both
    ``call_clobber`` engines return them."""
    from .call_clobber import CallClobberRead
    from ._chi_shadow import LazySparse

    if memory_unit.effect_evidence_digest != effect_unit.effect_evidence_digest:
        raise ChiRecordsMismatch("the memory unit is not this effect unit's")
    lazy = LazySparse(memory_unit, frozenset(calls), preserved, frozenset(memory_keeping))
    rows = []
    for block in sorted(effect_unit.blocks, key=lambda item: item.key):
        for effect in block.effects:
            spans, crossed_all, merged = [], set(), set()
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
                        if id(crossed) not in merged:   # (crossed_at's cached set: once per read)
                            merged.add(id(crossed))
                            step(len(crossed))
                            crossed_all |= crossed
                if first is not None:
                    spans.append(ByteSpan(span.object_id, first, last + 1 - first))
            if spans:
                rows.append(CallClobberRead(effect.operation_key, tuple(spans), tuple(sorted(crossed_all))))
    return tuple(sorted(rows, key=lambda row: row.operation_key))


def records(scope, legacy, memory_unit, effect_unit, observation, context, assumed_calls, proven_preserved,
            unrestored, memory_keeping, calls=None):
    """The rows the consumers get: V2's (compared with ``legacy()`` under
    ``check``); ``legacy()`` (``call_clobber``'s) under ``legacy`` or as the
    recorded fallback over V2's bounds."""
    selected = mode()
    if selected == "legacy":
        return legacy()
    from .call_clobber import clobber_inputs
    from .memory_ssa import _build_partition

    calls, preserved = clobber_inputs(observation, context, assumed_calls, proven_preserved, unrestored, calls)
    if not calls:
        rows = ()   # (no chi: nothing crossed)
    else:
        present = sum(1 for block in memory_unit.blocks for action in block.actions if action.operation_key in calls)
        if present * len(_build_partition(memory_unit).connected) > LIMIT:
            return _fall_back(scope, "limit", legacy)
        try:
            with bounded("chi_records", work_bound(memory_unit)):
                rows = chi_records(memory_unit, effect_unit, calls, preserved, memory_keeping & calls)
        except BoundExceeded as error:
            if error.name != "chi_records":
                raise
            return _fall_back(scope, "work", legacy)
    if selected == "check":
        expected = tuple(legacy())
        if rows != expected:
            index = next((i for i, (a, b) in enumerate(zip(rows, expected)) if a != b), min(len(rows), len(expected)))
            left = repr(rows[index])[:300] if index < len(rows) else "<missing>"
            right = repr(expected[index])[:300] if index < len(expected) else "<missing>"
            raise ChiRecordsMismatch(f"chi records differ from call_clobber's: {len(rows)} vs {len(expected)} rows, "
                                     f"first difference at [{index}]: {left} != {right}")
    return rows
