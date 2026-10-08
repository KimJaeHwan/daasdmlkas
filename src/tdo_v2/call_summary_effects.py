"""Proven call effects from callee summaries (interprocedural S1a/S1b).

A ``ProvenCallEffect`` turns a callee ``FunctionSummary`` into what one call
site may assume, without calling conventions:

* ``runs``: register bytes the callee writes on some normal exit, each group
  with the caller register bytes its value depends on and the callee-entry
  memory it reads (``loads``); a byte left unchanged on some exit also
  depends on itself (a may-write keeps the old value).
* ``memory_runs``: memory the callee writes through an entry-register-anchored
  pointer (``AnchoredSpan``: callee entry register value + displacement; the
  stack pointer anchors the callee frame) or at a global address, with its
  inputs likewise. The caller binds each anchor to its own value of that
  register at the call (relative-memory projection, once -- no re-substitution).
* ``preserved``: register bytes the call leaves exactly as they were (plus the
  written ones: normalization places the run effects just before the CALL).
* ``preserves_memory``: every memory byte the call may change is a memory run;
  otherwise (unknown-address writes, unanchored objects, UNKNOWN memory runs,
  opaque inner calls) all memory keeps call-clobber debt.

Register bytes UNKNOWN on some exit, computed through debts or from
unanchored memory, or that an inner call may change, stay opaque.
"""

from __future__ import annotations

from dataclasses import dataclass

from .function_summary import ExitSummary, FunctionSummary, SummaryKind, SummaryRun
from .span_geometry import ByteSpan, StorageObjectKind


@dataclass(frozen=True, slots=True)
class AnchoredSpan:
    """Memory at (callee entry value of ``anchor``) + ``displacement``, at a
    global address (``anchor`` None, ``span`` the ADDRESS_SPACE bytes), or at
    (the pointer stored at ``pointer`` at callee entry) + ``displacement``
    (``anchor`` and ``span`` None; a pointer passed in memory, e.g. ``**pp``
    or a 32-bit stack argument). The caller evaluates every base once, at the
    call (``MAX_POINTER_DEPTH`` levels)."""

    anchor: ByteSpan | None
    displacement: int
    size: int
    space_id: int
    span: ByteSpan | None = None
    pointer: "AnchoredSpan | None" = None


MAX_POINTER_DEPTH = 2


@dataclass(frozen=True, slots=True)
class ProvenRunEffect:
    writes: tuple[ByteSpan, ...]
    reads: tuple[ByteSpan, ...]
    loads: tuple[AnchoredSpan, ...] = ()
    origins: tuple[str, ...] = ()      # source labels the value may come from (inside the callee)
    # (read, write) pairs the caller must prove disjoint (``interprocedural``);
    # a pair it cannot is passed back as ``failed_conditions`` and the bytes
    # become unknown
    conditions: tuple[tuple[AnchoredSpan, AnchoredSpan], ...] = ()
    # pointer value (``SummaryRun.value``) for the caller: ("nonstack",),
    # ("same_reg", register span, null_is_fresh) -- the caller's value of that
    # register at the call -- or ("same_mem", AnchoredSpan, null_is_fresh) --
    # the caller's memory there at the call; None: unknown
    value: tuple | None = None


@dataclass(frozen=True, slots=True)
class ProvenMemoryRun:
    write: AnchoredSpan
    reads: tuple[ByteSpan, ...]
    loads: tuple[AnchoredSpan, ...]
    keeps_old: bool
    origins: tuple[str, ...] = ()
    conditions: tuple[tuple[AnchoredSpan, AnchoredSpan], ...] = ()
    value: tuple | None = None   # as ``ProvenRunEffect.value``


@dataclass(frozen=True, slots=True)
class ProvenSinkDemand:
    """A sink root inside the callee, as the caller's values at the call:
    register bytes (``reads``) and callee-entry memory (``loads``).
    ``complete`` is False when the callee root is incomplete or some entry
    byte it needs has no anchor the caller can bind (dropped from loads)."""

    label: str
    reads: tuple[ByteSpan, ...]
    loads: tuple[AnchoredSpan, ...]
    origins: tuple[str, ...]
    complete: bool
    # (read, write) pairs that must be disjoint for the root to be complete
    # (``SinkDemand.conditions``), decided at the call site
    conditions: tuple[tuple[AnchoredSpan, AnchoredSpan], ...] = ()


@dataclass(frozen=True, slots=True)
class ProvenCallEffect:
    callee: str                        # callee entry, "space:offset" hex
    runs: tuple[ProvenRunEffect, ...]
    preserved: tuple[ByteSpan, ...]    # caller register bytes the call leaves unchanged
    memory_runs: tuple[ProvenMemoryRun, ...] = ()
    preserves_memory: bool = False
    # the callee may use a register value it receives as an address (or keep it
    # in memory outside its own frame): a stack address in a register escapes
    observes_registers: bool = True
    sink_demands: tuple[ProvenSinkDemand, ...] = ()
    # the callee's stack pointer at every exit undoes the call shape's push
    # (summary AFFINE c == -displacement delta); otherwise the caller's stack
    # pointer after the call is unknown (call-clobber debt), not assumed
    restores_stack: bool = True
    # a composed tail jump (no return-address push): the caller's stack
    # pointer, left out of the runs, moves by the target's AFFINE c at its
    # exit (None: unknown) -- the jumping function's summary adds it
    tail_stack: tuple[ByteSpan, ...] = ()
    tail_stack_delta: int | None = None
    # the callee may also change memory below its entry stack pointer (its own
    # frame and its callees' frames): not exported byte by byte; the caller
    # treats its stack below the call-time stack pointer as clobbered and,
    # with ``preserves_memory``, everything else as kept
    clobbers_below: bool = False
    # registers whose value at the call the caller should prove constant (an
    # external model's extents, e.g. memcpy's count); read by a ``~ext`` row
    extent_registers: tuple[ByteSpan, ...] = ()
    # registers the call sets to the address of a block it allocates (an
    # external model's ``fresh``, e.g. malloc): never an address of existing
    # memory, the stack included -- part of that model's named assumption
    fresh_registers: tuple[ByteSpan, ...] = ()
    # with ``observes_registers``: the registers it may use as an address or
    # keep (an external model's ``observes``); None: every register
    observed_registers: tuple[ByteSpan, ...] | None = None
    # (written register, register at the call): the result is an address in
    # the same object as the argument (an external model's ``same_object_as``,
    # e.g. realloc under no-use-of-old-pointer-after-realloc)
    same_object_registers: tuple[tuple[ByteSpan, ByteSpan], ...] = ()


def derive_proven_call_effect(
    summary: FunctionSummary,
    callee: str,
    register_object,
    register_limit: int,
    excluded: tuple[ByteSpan, ...] = (),
    anchors: dict | None = None,
    stack_deltas: dict | None = None,
    tail: bool = False,
    failed_conditions: frozenset = frozenset(),
) -> ProvenCallEffect | None:
    """``register_object``: the program register file; ``register_limit``: one
    past the highest register byte the caller uses; ``excluded``: bytes the
    caller models itself (the stack pointer of an observed call shape);
    ``anchors``: callee FUNCTION_RELATIVE object -> (anchor register span,
    address space id) for objects addressed from one entry register value;
    ``stack_deltas``: excluded register (offset, size) -> the call shape's
    displacement delta (callee entry stack pointer - caller's); ``tail``: the
    site is a tail jump (``excluded`` = the stack pointer, composed by delta)."""
    anchors = anchors or {}
    skip = {offset for span in excluded for offset in range(span.start, span.end)}

    def anchored(span: ByteSpan, depth: int = 0) -> AnchoredSpan | None:
        kind = span.object_id.kind
        if kind is StorageObjectKind.ADDRESS_SPACE:
            return AnchoredSpan(None, span.start, span.size, span.object_id.space_key, span)
        if kind is StorageObjectKind.FUNCTION_RELATIVE and span.object_id in anchors:
            anchor, space_id = anchors[span.object_id]
            # relative objects are biased by 2**(address bits) (relative_memory);
            # an anchor is pointer-sized (a width mismatch fails the caller's
            # projection: debt, not a wrong address)
            displacement = span.start - (1 << (8 * anchor.size))
            if anchor.object_id.kind is StorageObjectKind.REGISTER_FILE:
                return AnchoredSpan(anchor, displacement, span.size, space_id)
            if depth >= MAX_POINTER_DEPTH:
                return None
            slot = anchored(anchor, depth + 1)  # the pointer's own location at entry
            if slot is None:
                return None
            return AnchoredSpan(None, displacement, span.size, space_id, pointer=slot)
        return None

    stack = {(span.start, span.size) for span in excluded}

    # every claim of a summary with writer conditions holds only with them: a
    # caller that cannot locate them, or found one failing, gets nothing proven
    # but the sink demands (registers and memory unknown, stack not restored)
    if summary.writer_conditions and _anchored_conditions(
            _Conditions(summary.writer_conditions), anchored, failed_conditions) is None:
        summary = _all_unknown(summary, register_object, register_limit)

    def below(span: ByteSpan) -> bool:
        """Callee stack bytes entirely below its entry stack pointer."""
        row = anchors.get(span.object_id)
        return row is not None and row[0].object_id.kind is StorageObjectKind.REGISTER_FILE \
            and (row[0].start, row[0].size) in stack and span.end <= 1 << (8 * row[0].size)

    clobbers_below = False
    sink_demands = tuple(_sink_demand(demand, anchored) for demand in summary.sink_demands)
    if summary.tail_exits or not summary.exits:
        if not sink_demands:
            return None
        # no state is proven, but the callee's sink roots still bind at the call
        # (a wrapper that never returns normally must not lose its sink)
        return ProvenCallEffect(callee, (), (), sink_demands=sink_demands)

    # memory writers the call exports as memory runs (anchored or global)
    exported = {
        writer for exit_summary in summary.exits for run in exit_summary.runs
        if run.span.object_id.kind is not StorageObjectKind.REGISTER_FILE
        and anchored(run.span) is not None for writer in run.writers
    }
    per_exit = []
    memory_ok = not summary.unknown_writers
    for exit_summary in summary.exits:
        verdicts: dict[tuple, object] = {}
        for run in exit_summary.runs:
            kind = run.span.object_id.kind
            if kind is StorageObjectKind.FUNCTION_UNIQUE:
                continue
            verdict = _verdict(run, anchored, failed_conditions)
            if kind is not StorageObjectKind.REGISTER_FILE and below(run.span):
                clobbers_below = clobbers_below or verdict != "self"
                continue
            if verdict == "unknown" and kind is not StorageObjectKind.REGISTER_FILE                     and _only_exported_aliasing(run, exported):
                # unknown only because an exported memory write may alias these
                # bytes: in the caller that write is an ordinary write to the bound
                # object, and the caller's may-alias analysis covers the overlap
                verdict = _verdict_without_crossings(run, anchored, failed_conditions)
            if kind is not StorageObjectKind.REGISTER_FILE and verdict != "self" and (
                    verdict == "unknown" or anchored(run.span) is None):
                memory_ok = False
            for offset in range(run.span.start, run.span.end):
                verdicts[(run.span.object_id, offset)] = verdict
        per_exit.append(verdicts)
    # byte -> "self" (unchanged) | "unknown" | (frozenset of sources, keeps_old);
    # a byte an exit does not mention is unchanged on that exit
    state: dict[tuple, object] = {}
    for item in set().union(*per_exit):
        value = None
        for verdicts in per_exit:
            value = _merge(value, verdicts.get(item, "self"))
        state[item] = value
    # a register no exit mentions was untouched by the function itself, but an
    # inner call that does not provably preserve it may still have changed it
    for _, kept, keeps_memory, inner_below in summary.inner_calls:
        memory_ok = memory_ok and keeps_memory
        clobbers_below = clobbers_below or inner_below
        kept_offsets = {
            offset for span in kept if span.object_id.kind is StorageObjectKind.REGISTER_FILE
            for offset in range(span.start, span.end)
        }
        for offset in range(register_limit):
            if (register_object, offset) not in state and offset not in kept_offsets:
                state[(register_object, offset)] = "unknown"

    register_groups: dict[tuple, list[int]] = {}
    memory_groups: dict[tuple, list[tuple]] = {}
    unknown: set[int] = set()
    for (object_id, offset), value in state.items():
        is_register = object_id.kind is StorageObjectKind.REGISTER_FILE
        if is_register and offset in skip:
            continue
        if value in (None, "self"):
            continue
        if value == "unknown":
            if is_register:
                unknown.add(offset)
            continue
        if is_register:
            register_groups.setdefault(value, []).append(offset)
        elif anchored(ByteSpan(object_id, offset, 1)) is not None:
            memory_groups.setdefault(value, []).append((object_id, offset))

    def split_sources(sources):
        registers, loads = [], []
        for source in sources:
            if type(source) is tuple:  # ("origin", label) / ("pointer", value)
                continue
            if source.object_id.kind is StorageObjectKind.REGISTER_FILE:
                registers.append(source)
            else:
                loads.append(anchored(source))
        return (tuple(sorted(registers, key=lambda span: span.canonical_key)),
                tuple(sorted(set(loads), key=repr)))

    # the width of the pointers whose values the summary states
    summary_pointer_size = next((run.span.size for item in summary.exits for run in item.runs
                                 if run.value is not None), None)
    runs = []
    for (sources, keeps_old, conditions), offsets in sorted(register_groups.items(), key=lambda item: min(item[1])):
        writes = tuple(_spans(register_object, offsets))
        registers, loads = split_sources(sources)
        value = _pointer_value(sources, keeps_old, writes, summary_pointer_size, anchored)
        if value is not None and value[0] == "same_reg" and value[1] not in registers:
            value = None  # the input rows read only the run's registers
        if value is not None and value[0] == "same_mem" and value[1] not in loads:
            value = None
        if keeps_old:
            registers = tuple(sorted(set(registers) | set(writes), key=lambda span: span.canonical_key))
        runs.append(ProvenRunEffect(writes, registers, loads, _origins(sources), _sorted_pairs(conditions),
                                    value))
    memory_runs = []
    for (sources, keeps_old, conditions), items in sorted(memory_groups.items(), key=lambda item: repr(min(item[1], key=repr))):
        registers, loads = split_sources(sources)
        by_object: dict = {}
        for object_id, offset in items:
            by_object.setdefault(object_id, []).append(offset)
        for object_id, offsets in sorted(by_object.items(), key=repr):
            spans = list(_spans(object_id, offsets))
            for span in spans:
                value = _pointer_value(sources, keeps_old, spans, summary_pointer_size, anchored)
                if value is not None and value[0] == "same_reg" and value[1] not in registers:
                    value = None
                if value is not None and value[0] == "same_mem" and value[1] not in loads:
                    value = None
                memory_runs.append(ProvenMemoryRun(anchored(span), registers, loads, keeps_old, _origins(sources),
                                                   _sorted_pairs(conditions), value))
    preserved = [offset for offset in range(register_limit) if offset not in unknown and offset not in skip]

    def through_register(access):
        return access is not None and access.anchor is not None and             (access.anchor.start, access.anchor.size) not in stack
    observes = not memory_ok or any(
        through_register(run.write) or any(through_register(load) for load in run.loads)
        or (run.write.anchor is None and run.reads)  # a register value kept in global memory
        for run in memory_runs
    ) or any(through_register(load) for run in runs for load in run.loads)
    deltas = dict(summary.register_deltas)
    restores = all(
        deltas.get(key) == -delta for key, delta in (stack_deltas or {}).items()
    )
    tail_stack, tail_delta = (), None
    if tail:
        tail_stack = tuple(excluded)
        found = {deltas.get((span.start, span.size)) for span in excluded}
        tail_delta = found.pop() if len(found) == 1 else None
    return ProvenCallEffect(
        callee, tuple(runs), tuple(_spans(register_object, preserved)), tuple(memory_runs), memory_ok,
        observes, sink_demands, restores, tail_stack, tail_delta, clobbers_below,
    )


def _sink_demand(demand, anchored) -> ProvenSinkDemand:
    registers, loads, complete = [], set(), demand.complete
    for source in demand.sources:
        if source.object_id.kind is StorageObjectKind.REGISTER_FILE:
            registers.append(source)
            continue
        access = anchored(source)
        if access is None:
            complete = False  # entry memory the caller cannot locate
        else:
            loads.add(access)
    conditions = set()
    for left, right in demand.conditions:
        pair = (anchored(left), anchored(right))
        if None in pair:
            complete = False  # a side the caller cannot locate: undecidable
        else:
            conditions.add(pair)
    return ProvenSinkDemand(
        demand.label, tuple(sorted(registers, key=lambda span: span.canonical_key)),
        tuple(sorted(loads, key=repr)), demand.origins, complete, tuple(sorted(conditions, key=repr)),
    )


def _origins(sources) -> tuple[str, ...]:
    return tuple(sorted(item[1] for item in sources if type(item) is tuple and item[0] == "origin"))


def _with_origins(sources, run) -> frozenset:
    """The verdict's sources, origin labels and the run's pointer value (a
    ("pointer", value) marker: bytes of one pointer stay one group, and a
    merge of exits with different values keeps both markers -- no value)."""
    return frozenset(sources) | {("origin", label) for label in run.origins} | {("pointer", run.value)}


def _pointer_value(sources, keeps_old, spans, size, anchored):
    """The caller-facing pointer value of one output run, or None."""
    markers = [item[1] for item in sources if type(item) is tuple and item[0] == "pointer"]
    if len(markers) != 1 or markers[0] is None or keeps_old or len(spans) != 1 or spans[0].size != size:
        return None
    value = markers[0]
    if value == ("nonstack",):
        return value
    _, entry, null_is_fresh = value
    if entry.object_id.kind is StorageObjectKind.REGISTER_FILE:
        return ("same_reg", entry, null_is_fresh)
    access = anchored(entry)
    return None if access is None else ("same_mem", access, null_is_fresh)


def _only_exported_aliasing(run, exported) -> bool:
    return bool(run.crossed) and not run.debts and all(
        label.startswith("alias:") and label[len("alias:"):] in exported for label in run.crossed
    )


def _sorted_pairs(conditions) -> tuple:
    return tuple(sorted(conditions, key=repr))


@dataclass(frozen=True, slots=True)
class _Conditions:
    conditions: tuple


def _all_unknown(summary, register_object, register_limit):
    from dataclasses import replace as _replace

    run = SummaryRun(ByteSpan(register_object, 0, register_limit), SummaryKind.UNKNOWN, (0,),
                     ("conditional-writer",), (), (), (), ("uncertain:conditional-writer",))
    return _replace(
        summary, exits=tuple(ExitSummary(item.block_key, (run,)) for item in summary.exits),
        unknown_writers=("conditional-writer",), register_deltas=(), writer_conditions=(),
    )


def _anchored_conditions(run, anchored, failed):
    """The run's alias conditions as anchored pairs, or None when one cannot
    be located by a caller or a caller already found it failing."""
    pairs = set()
    for left, right in run.conditions:
        pair = (anchored(left), anchored(right))
        if None in pair or pair in failed:
            return None
        pairs.add(pair)
    return frozenset(pairs)


def _verdict_without_crossings(run, anchored, failed=frozenset()):
    if not run.writers and all(span.object_id == run.span.object_id for span in run.sources):
        return "self"  # entry contents, not rewritten by the function itself
    for source in run.sources:
        if source.object_id.kind is not StorageObjectKind.REGISTER_FILE and anchored(source) is None:
            return "unknown"
    conditions = _anchored_conditions(run, anchored, failed)
    if conditions is None:
        return "unknown"
    return (_with_origins(run.sources, run), False, conditions)


def _verdict(run, anchored, failed=frozenset()):
    if run.kind is SummaryKind.UNKNOWN or run.debts:
        return "unknown"
    if run.kind is SummaryKind.IDENTITY:
        return "self"
    for source in run.sources:
        if source.object_id.kind is not StorageObjectKind.REGISTER_FILE and anchored(source) is None:
            return "unknown"  # entry memory with no anchor the caller can bind
    conditions = _anchored_conditions(run, anchored, failed)
    if conditions is None:
        return "unknown"
    return (_with_origins(run.sources, run), False, conditions)


def _merge(current, verdict):
    """Values: "self", "unknown", or (sources, keeps old value, conditions)."""
    if current == "unknown" or verdict == "unknown":
        return "unknown"
    if current is None:
        return verdict
    if verdict == "self":
        return current if current == "self" else (current[0], True, current[2])
    if current == "self":
        return (verdict[0], True, verdict[2])
    return (current[0] | verdict[0], current[1] or verdict[1], current[2] | verdict[2])


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


__all__ = (
    "AnchoredSpan", "ProvenCallEffect", "ProvenMemoryRun", "ProvenRunEffect", "ProvenSinkDemand",
    "derive_proven_call_effect",
)
