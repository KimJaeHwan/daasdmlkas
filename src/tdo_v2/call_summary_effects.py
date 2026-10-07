"""Proven call effects from callee summaries (interprocedural S1a, registers).

A ``ProvenCallEffect`` turns a callee ``FunctionSummary`` into what one call
site may assume, in caller coordinates, without calling conventions:

* ``runs``: register bytes the callee writes on some normal exit, each group
  with the caller register bytes its value depends on (a byte left unchanged
  on some exit also depends on itself: a may-write keeps the old value).
* ``preserved``: register bytes the call leaves exactly as they were
  (untouched or IDENTITY on every exit) -- plus the written ones, because
  normalization places the run effects just before the CALL operation.

Everything else stays an opaque call effect (call-clobber debt): register
bytes that are UNKNOWN on some exit or computed from callee entry memory or
through debts, all memory (S1b binds pointer-relative memory), and callees
with tail exits or no normal exit.
"""

from __future__ import annotations

from dataclasses import dataclass

from .function_summary import FunctionSummary, SummaryKind
from .span_geometry import ByteSpan, StorageObjectKind


@dataclass(frozen=True, slots=True)
class ProvenRunEffect:
    writes: tuple[ByteSpan, ...]
    reads: tuple[ByteSpan, ...]


@dataclass(frozen=True, slots=True)
class ProvenCallEffect:
    callee: str                        # callee entry, "space:offset" hex
    runs: tuple[ProvenRunEffect, ...]
    preserved: tuple[ByteSpan, ...]    # caller register bytes the call leaves unchanged


def derive_proven_call_effect(
    summary: FunctionSummary,
    callee: str,
    register_object,
    register_limit: int,
    excluded: tuple[ByteSpan, ...] = (),
) -> ProvenCallEffect | None:
    """``register_object``: the program register file; ``register_limit``: one
    past the highest register byte the caller uses; ``excluded``: bytes the
    caller models itself (the stack pointer of an observed call shape)."""
    if summary.tail_exits or not summary.exits:
        return None
    skip = {offset for span in excluded for offset in range(span.start, span.end)}
    per_exit = []
    for exit_summary in summary.exits:
        verdicts: dict[int, object] = {}
        for run in exit_summary.runs:
            if run.span.object_id.kind is not StorageObjectKind.REGISTER_FILE:
                continue
            verdict = _verdict(run)
            for offset in range(run.span.start, run.span.end):
                verdicts[offset] = verdict
        per_exit.append(verdicts)
    # byte -> "self" (unchanged) | "unknown" | (frozenset of source spans, keeps_old);
    # a byte an exit does not mention is unchanged on that exit
    state: dict[int, object] = {}
    for offset in set().union(*per_exit):
        value = None
        for verdicts in per_exit:
            value = _merge(value, verdicts.get(offset, "self"))
        state[offset] = value
    # a byte no exit mentions was untouched by the function itself, but an inner
    # call that does not provably preserve it may still have changed it
    for _, kept in summary.inner_calls:
        kept_offsets = {
            offset for span in kept if span.object_id.kind is StorageObjectKind.REGISTER_FILE
            for offset in range(span.start, span.end)
        }
        for offset in range(register_limit):
            if offset not in state and offset not in kept_offsets:
                state[offset] = "unknown"
    groups: dict[tuple, list[int]] = {}
    unknown: set[int] = set()
    for offset, value in state.items():
        if offset in skip or value in (None, "self"):
            continue
        if value == "unknown":
            unknown.add(offset)
            continue
        sources, keeps_old = value
        groups.setdefault((sources, keeps_old), []).append(offset)
    runs = []
    for (sources, keeps_old), offsets in sorted(groups.items(), key=lambda item: min(item[1])):
        writes = tuple(_spans(register_object, offsets))
        reads = set(sources)
        if keeps_old:
            reads.update(writes)
        runs.append(ProvenRunEffect(writes, tuple(sorted(reads, key=lambda span: span.canonical_key))))
    preserved = [offset for offset in range(register_limit) if offset not in unknown and offset not in skip]
    return ProvenCallEffect(callee, tuple(runs), tuple(_spans(register_object, preserved)))


def _verdict(run):
    if run.kind is SummaryKind.UNKNOWN or run.debts:
        return "unknown"
    if run.kind is SummaryKind.IDENTITY:
        return "self"
    if any(source.object_id.kind is not StorageObjectKind.REGISTER_FILE for source in run.sources):
        return "unknown"  # depends on callee entry memory: S1b
    return (frozenset(run.sources), False)


def _merge(current, verdict):
    if current == "unknown" or verdict == "unknown":
        return "unknown"
    if current is None:
        return verdict
    if verdict == "self":
        return current if current == "self" else (current[0], True)
    if current == "self":
        return (verdict[0], True)
    return (current[0] | verdict[0], current[1] or verdict[1])


def _spans(object_id, offsets):
    run_start = previous = None
    for offset in sorted(offsets):
        if previous is not None and offset == previous + 1:
            previous = offset
            continue
        if run_start is not None:
            yield ByteSpan(object_id, run_start, previous + 1 - run_start)
        run_start = previous = offset
    if run_start is not None:
        yield ByteSpan(object_id, run_start, previous + 1 - run_start)


__all__ = ("ProvenCallEffect", "ProvenRunEffect", "derive_proven_call_effect")
