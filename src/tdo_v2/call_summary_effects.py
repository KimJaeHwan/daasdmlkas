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
* ``unknown_memory``: anchored or global memory the callee writes with a value
  the summary cannot state (UNKNOWN runs, runs computed through debts): the
  place is exact, the value is not -- the caller writes those bytes with an
  "opaque_call_write" debt.
* ``preserves_memory``: every memory byte the call may change is a memory run
  or unknown memory; otherwise (unknown-address writes, unanchored objects,
  opaque inner calls) all memory keeps call-clobber debt -- except, with
  ``memory_runs_final`` (external models), the bytes its memory runs write at
  an exactly known place (``normalize._kept_call_memory``).

Register bytes UNKNOWN on some exit, computed through debts or from
unanchored memory, or that an inner call may change, stay opaque.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .constant_value import ExactConstant
from .function_summary import ExitSummary, FunctionSummary, SummaryKind, SummaryRun
from .indexed_address import IndexedAnchor, _validate_offset
from .span_geometry import ByteSpan, StorageObjectKind


@dataclass(frozen=True, slots=True)
class AnchoredSpan:
    """Memory at (callee entry value of ``anchor``) + ``displacement``, at a
    global address (``anchor`` None, ``span`` the ADDRESS_SPACE bytes), or at
    (the pointer stored at ``pointer`` at callee entry) + ``displacement``
    (``anchor`` and ``span`` None; a pointer passed in memory, e.g. ``**pp``
    or a 32-bit stack argument). The caller evaluates every base once, at the
    call (``MAX_POINTER_DEPTH`` levels). With ``index``, add its scaled,
    extended entry value to that base before the ordinary displacement.
    The index's preoffset addition wraps at its source width."""

    anchor: ByteSpan | None
    displacement: int
    size: int
    space_id: int
    span: ByteSpan | None = None
    pointer: "AnchoredSpan | None" = None
    index: "IndexedOffset | None" = None


@dataclass(frozen=True, slots=True)
class IndexedOffset:
    """An entry index, evaluated once from one register or anchored memory."""

    register: ByteSpan | None
    memory: AnchoredSpan | None
    extend: str
    preoffset: int
    scale: int

    def __post_init__(self) -> None:
        if (self.register is None) == (self.memory is None):
            raise ValueError("indexed offset requires exactly one source")
        if self.register is not None:
            if type(self.register) is not ByteSpan or self.register.object_id.kind is not StorageObjectKind.REGISTER_FILE:
                raise TypeError("indexed register must be an exact register ByteSpan")
            width = self.register.size
        else:
            if type(self.memory) is not AnchoredSpan:
                raise TypeError("indexed memory must be an exact AnchoredSpan")
            width = self.memory.size
        _validate_offset(width, self.extend, self.preoffset, self.scale)


MAX_POINTER_DEPTH = 2


def anchored_span(span: ByteSpan, anchors: dict, depth: int = 0, relations=None) -> "AnchoredSpan | None":
    """Where a caller finds callee bytes ``span`` at the call (``anchors``:
    the callee's FUNCTION_RELATIVE object -> (entry register span, space)):
    a global, (an entry register's value) + displacement, or (the pointer
    at another anchored place) + displacement (``MAX_POINTER_DEPTH``
    levels); None when the caller cannot locate it."""
    kind = span.object_id.kind
    relation = (relations or {}).get(span.object_id)
    if kind is StorageObjectKind.FUNCTION_RELATIVE and relation is not None:
        if type(relation) is not IndexedAnchor or depth >= MAX_POINTER_DEPTH:
            return None
        allowed = (StorageObjectKind.REGISTER_FILE, StorageObjectKind.FUNCTION_RELATIVE)
        if relation.base.object_id.kind not in allowed or relation.index.object_id.kind not in allowed:
            return None
        anchor, pointer, register, memory = None, None, None, None
        if relation.base.object_id.kind is StorageObjectKind.REGISTER_FILE:
            anchor = relation.base
        else:
            pointer = anchored_span(relation.base, anchors, depth + 1)
            if pointer is None:
                return None
        if relation.index.object_id.kind is StorageObjectKind.REGISTER_FILE:
            register = relation.index
        else:
            memory = anchored_span(relation.index, anchors, depth + 1)
            if memory is None:
                return None
        index = IndexedOffset(register, memory, relation.extend, relation.preoffset, relation.scale)
        return AnchoredSpan(anchor, span.start - (1 << 64), span.size, relation.space_id,
                            pointer=pointer, index=index)
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
        slot = anchored_span(anchor, anchors, depth + 1)  # the pointer's own location at entry
        if slot is None:
            return None
        return AnchoredSpan(None, displacement, span.size, space_id, pointer=slot)
    return None


def call_load_keys(call_key: str, proven) -> dict:
    """AnchoredSpan -> the key of the ``~ld<j>`` row that loads it at the
    call, in the order ``normalize._proven_call_rows`` creates them (runs'
    loads, memory runs' kept old values and pointer bases, unknown memory's
    pointer/index bases, sink demands' loads, then condition bases; pointer
    and index slots precede their target and are evaluated before outputs).
    An accessor's slot, loaded last, is not listed."""
    keys: dict = {}

    def load(access):
        if access in keys:
            return
        if access.pointer is not None:
            load(access.pointer)
        if access.index is not None and access.index.memory is not None:
            load(access.index.memory)
        keys[access] = f"{call_key}~ld{len(keys)}"

    def bases(access):
        if access.pointer is not None:
            load(access.pointer)
        if access.index is not None and access.index.memory is not None:
            load(access.index.memory)

    for run in (*proven.runs, *proven.memory_runs):
        for item in run.loads:
            load(item)
        if isinstance(run, ProvenMemoryRun):
            if run.keeps_old:
                load(run.write)
            bases(run.write)
    for access in proven.unknown_memory:
        bases(access)
    for demand in proven.sink_demands:
        for item in demand.loads:
            load(item)
    for row in (*proven.runs, *proven.memory_runs, *proven.sink_demands):
        for pair in row.conditions:
            for side in pair:
                bases(side)
    for pair in proven.writer_conditions:
        for side in pair:
            bases(side)
    return keys


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
    # the caller's memory there at the call; ("offset_reg", register span, c):
    # the caller's value of that register at the call + c (docs 25.80 R1);
    # None: unknown
    value: tuple | None = None
    literal: ExactConstant | None = None


@dataclass(frozen=True, slots=True)
class ProvenMemoryRun:
    write: AnchoredSpan
    reads: tuple[ByteSpan, ...]
    loads: tuple[AnchoredSpan, ...]
    keeps_old: bool
    origins: tuple[str, ...] = ()
    conditions: tuple[tuple[AnchoredSpan, AnchoredSpan], ...] = ()
    value: tuple | None = None   # as ``ProvenRunEffect.value``
    literal: ExactConstant | None = None


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
    # (register span, extent, label): the register's value addresses an object
    # whose first ``extent`` bytes are in no thread's stack (an external
    # model's ``result_nonstack``, resting on its declared ``label``) -- used
    # only in the calling function (``relative_memory`` nonstack windows)
    nonstack_results: tuple[tuple[ByteSpan, int, str], ...] = ()
    # (register span, bytes, never_null label | None): a fresh register's block
    # size proven at the call (docs 25.79; this function only)
    fresh_extents: tuple = ()
    # with ``observes_registers``: the registers it may use as an address or
    # keep (an external model's ``observes``); None: every register
    observed_registers: tuple[ByteSpan, ...] | None = None
    # (written register, register at the call): the result is an address in
    # the same object as the argument (an external model's ``same_object_as``,
    # e.g. realloc under no-use-of-old-pointer-after-realloc)
    same_object_registers: tuple[tuple[ByteSpan, ByteSpan], ...] = ()
    # the callee never returns (every exit dead, ``FunctionSummary.dead_exits``):
    # the caller's path past the call is dead
    noreturn: bool = False
    # anchored or global memory the callee writes with an unknown value: exact
    # places (``preserves_memory`` keeps the rest), each byte with debt
    unknown_memory: tuple[AnchoredSpan, ...] = ()
    # the summary's writer conditions as anchored (read, write) pairs: every
    # claim of this effect -- preserved bytes and memory included -- holds only
    # with them, so the caller decides them at the call (``~cw`` row) and
    # re-derives the effect with any pair not proven disjoint as failed
    writer_conditions: tuple = ()
    # the memory runs are the values of their bytes when the call returns,
    # whatever else it clobbers (an external model: "the rest of memory is as
    # other_memory says"): a call not keeping memory still keeps the bytes
    # its runs write at an exactly known place (``normalize._kept_call_memory``)
    memory_runs_final: bool = False
    # an accessor model under same-result-functions (docs 25.20): (model id,
    # identity -- the entry's label and its file's digest --, result register
    # span, input register spans, the read slot as an AnchoredSpan, the
    # result's nonstack window -- (extent, label) from ``nonstack_results``, or
    # None --, write_back, the result_separate_from_reads extent under
    # accessor-result-separate or None)
    same_result: tuple | None = None
    # model ids (or "*") whose accessor state this call leaves unchanged
    preserves_accessor_state: tuple[str, ...] = ()
    # a proof that the call keeps every accessor's hidden state (docs 25.26):
    # its callee runs no call and no store and returns at its entry stack
    # pointer -- the reason, or None
    state_proof: str | None = None
    # its model leaves out library-private writes (accessor-private-state):
    # the program oracle counts such writes outside the footprint apart
    omits_private_writes: bool = False
    # the call may leave a value derived from the caller's stack pointer where
    # the caller cannot see it (an output read from the stack pointer, e.g.
    # ``lea rax, [rsp+8]; ret``, or an effect not exported whole): the caller's
    # stack taint follows no call output, so the call itself is a stack escape
    # (``may_alias._stack_taint``); a declared model never sets it
    escapes_stack: bool = False
    # Provenance only: the facts in restores_stack/tail_stack_delta remain
    # semantic. Original-CFG certificates justify them independently of a
    # refused memory-writer condition and survive in the query graph/record.
    register_delta_proofs: tuple = field(default=(), compare=False)


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
    rejections: list | None = None,
) -> ProvenCallEffect | None:
    """``register_object``: the program register file; ``register_limit``: one
    past the highest register byte the caller uses; ``excluded``: bytes the
    caller models itself (the stack pointer of an observed call shape);
    ``anchors``: callee FUNCTION_RELATIVE object -> (anchor register span,
    address space id) for objects addressed from one entry register value;
    ``stack_deltas``: excluded register (offset, size) -> the call shape's
    displacement delta (callee entry stack pointer - caller's); ``tail``: the
    site is a tail jump (``excluded`` = the stack pointer, composed by delta).
    ``rejections`` (operation records only, docs 25.31 C9-5): every alias
    condition dropped here is appended as (where, callee pair, reason) --
    "unlocatable" (a side the caller cannot locate) or "failed" (the caller
    already found it failing)."""
    anchors = anchors or {}
    relations = dict(getattr(summary, "address_relations", ()))
    skip = {offset for span in excluded for offset in range(span.start, span.end)}

    def anchored(span: ByteSpan) -> AnchoredSpan | None:
        return anchored_span(span, anchors, relations=relations)

    stack = {(span.start, span.size) for span in excluded}

    # every claim of a summary with writer conditions holds only with them: a
    # caller that cannot locate them, or found one failing, gets nothing proven
    # but the sink demands (registers and memory unknown, stack not restored)
    writer_pairs = frozenset()
    if summary.writer_conditions:
        writer_pairs = _anchored_conditions(_Conditions(summary.writer_conditions), anchored, failed_conditions,
                                            rejections, "writer")
        if writer_pairs is None:
            summary = _all_unknown(summary, register_object, register_limit)
            writer_pairs = frozenset()

    def below(span: ByteSpan) -> bool:
        """Callee stack bytes entirely below its entry stack pointer."""
        row = anchors.get(span.object_id)
        return row is not None and row[0].object_id.kind is StorageObjectKind.REGISTER_FILE \
            and (row[0].start, row[0].size) in stack and span.end <= 1 << (8 * row[0].size)

    clobbers_below = False
    sink_demands = tuple(_sink_demand(demand, anchored, rejections, f"sink{index}")
                         for index, demand in enumerate(summary.sink_demands))
    if not summary.exits and not summary.tail_exits and summary.dead_exits:
        return ProvenCallEffect(callee, (), (), sink_demands=sink_demands, noreturn=True, escapes_stack=True)
    if summary.tail_exits or not summary.exits:
        if not sink_demands:
            return None
        # no state is proven, but the callee's sink roots still bind at the call
        # (a wrapper that never returns normally must not lose its sink)
        return ProvenCallEffect(callee, (), (), sink_demands=sink_demands, escapes_stack=True)

    # memory writers the call exports as memory runs (anchored or global)
    exported = {
        writer for exit_summary in summary.exits for run in exit_summary.runs
        if run.span.object_id.kind is not StorageObjectKind.REGISTER_FILE
        and anchored(run.span) is not None for writer in run.writers
    }
    # a write to an exported object whose bytes later writes of that object
    # cover on every path (a dead store, so in no run): had it landed on other
    # bytes, the covering write lands on the same addresses, and that one is
    # exported -- the caller's may-alias of it covers the overlap
    anchored_objects = {
        run.span.object_id for exit_summary in summary.exits for run in exit_summary.runs
        if run.span.object_id.kind is not StorageObjectKind.REGISTER_FILE and anchored(run.span) is not None
    }
    exported |= {writer for writer, object_id in summary.writer_objects if object_id in anchored_objects}
    per_exit = []
    memory_ok = not summary.unknown_writers
    for exit_summary in summary.exits:
        verdicts: dict[tuple, object] = {}
        for run in exit_summary.runs:
            kind = run.span.object_id.kind
            if kind is StorageObjectKind.FUNCTION_UNIQUE:
                continue
            verdict = _verdict(run, anchored, failed_conditions, rejections, (exit_summary.block_key, run.span))
            if kind is not StorageObjectKind.REGISTER_FILE and below(run.span):
                clobbers_below = clobbers_below or verdict != "self"
                continue
            # (a write to the return-address slot is an ordinary run: in the
            # caller it lands on the CALL's push definition, ``normalize._push_row``)
            if verdict == "unknown" and kind is not StorageObjectKind.REGISTER_FILE \
                    and _only_exported_aliasing(run, exported):
                # unknown only because an exported memory write may alias these
                # bytes: in the caller that write is an ordinary write to the bound
                # object, and the caller's may-alias analysis covers the overlap
                verdict = _verdict_without_crossings(run, anchored, failed_conditions, rejections,
                                                     (exit_summary.block_key, run.span))
            # an unknown value at an anchored place is unknown memory there; a
            # write the caller cannot locate leaves no memory kept
            if kind is not StorageObjectKind.REGISTER_FILE and verdict != "self" \
                    and anchored(run.span) is None:
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
    unknown_bytes: dict = {}   # memory object -> offsets of unknown value
    for (object_id, offset), value in state.items():
        is_register = object_id.kind is StorageObjectKind.REGISTER_FILE
        if is_register and offset in skip:
            continue
        if value in (None, "self"):
            continue
        if value == "unknown":
            if is_register:
                unknown.add(offset)
            elif anchored(ByteSpan(object_id, offset, 1)) is not None:
                unknown_bytes.setdefault(object_id, []).append(offset)
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
        if value is not None and value[0] in ("same_reg", "offset_reg") and value[1] not in registers:
            value = None  # the input rows read only the run's registers
        if value is not None and value[0] == "offset_reg" and skip.intersection(range(value[1].start, value[1].end)):
            value = None  # (the stack pointer: its callee value is another, docs 25.80 R1)
        if value is not None and value[0] == "same_mem" and value[1] not in loads:
            value = None
        if keeps_old:
            registers = tuple(sorted(set(registers) | set(writes), key=lambda span: span.canonical_key))
        runs.append(ProvenRunEffect(writes, registers, loads, _origins(sources), _sorted_pairs(conditions),
                                    value, _literal_value(sources, keeps_old, writes)))
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
                if value is not None and value[0] in ("same_reg", "offset_reg") and value[1] not in registers:
                    value = None
                if value is not None and value[0] == "offset_reg" \
                        and skip.intersection(range(value[1].start, value[1].end)):
                    value = None
                if value is not None and value[0] == "same_mem" and value[1] not in loads:
                    value = None
                memory_runs.append(ProvenMemoryRun(anchored(span), registers, loads, keeps_old, _origins(sources),
                                                   _sorted_pairs(conditions), value,
                                                   _literal_value(sources, keeps_old, (span,))))
    preserved = [offset for offset in range(register_limit) if offset not in unknown and offset not in skip]
    unknown_memory = tuple(
        anchored(span) for object_id, offsets in sorted(unknown_bytes.items(), key=repr)
        for span in _spans(object_id, offsets)
    )

    deltas = dict(summary.register_deltas)
    restores = all(
        deltas.get(key) == -delta for key, delta in (stack_deltas or {}).items()
    )
    # every effect of the call is exported: no inner call, memory kept, no
    # byte of unknown value (the stack pointer's included), the stack pointer
    # restored, every sink root complete -- then the registers the effects read
    # are all the call can use or keep
    complete = not summary.inner_calls and memory_ok and restores \
        and all(value != "unknown" for value in state.values()) and all(demand.complete for demand in sink_demands)
    observed = _observed_registers(runs, memory_runs, unknown_memory, writer_pairs, sink_demands, skip) \
        if complete else None
    observes = observed is None or bool(observed)
    # a value derived from the callee's stack pointer it lets out (its own
    # stack taint: ``FunctionSummary.stack_values_out`` -- the summary's reads
    # also hold the stack pointer as a LOAD / STORE address), or an effect not
    # exported whole: the caller's stack taint, which follows no call output
    # and leaves the stack pointer out, cannot see where that value went
    escapes = not complete or summary.stack_values_out
    tail_stack, tail_delta = (), None
    if tail:
        tail_stack = tuple(excluded)
        found = {deltas.get((span.start, span.size)) for span in excluded}
        tail_delta = found.pop() if len(found) == 1 else None
    return ProvenCallEffect(
        callee, tuple(runs), tuple(_spans(register_object, preserved)), tuple(memory_runs), memory_ok,
        observes, sink_demands, restores, tail_stack, tail_delta, clobbers_below,
        writer_conditions=_sorted_pairs(writer_pairs), unknown_memory=unknown_memory,
        observed_registers=observed, escapes_stack=escapes,
        register_delta_proofs=tuple(proof for proof in summary.independent_delta_proofs
            if proof.register in stack and deltas.get(proof.register) == proof.delta),
    )


def derive_composed_call_effect(
    members: tuple,
    callee: str,
    register_object,
    register_limit: int,
    excluded: tuple[ByteSpan, ...] = (),
    stack_deltas: dict | None = None,
    failed_conditions: frozenset = frozenset(),
    memory_sources: dict | None = None,
) -> ProvenCallEffect | None:
    """The effect of a call that reaches ONE of several functions (an indirect
    call whose target set is proven, docs 25.33 F1b): ``members`` = ((summary,
    anchors), ...). Each dynamic call runs one member, so the call's exits are
    the members' exits together and the per-exit merge of
    ``derive_proven_call_effect`` composes them (a byte one member leaves
    untouched keeps its old value; preserved = every member preserves it; the
    stack is restored only with one delta; noreturn only if every member
    never returns) -- after three per-member steps the single-function merge
    does not need:
    * an opaque member (tail exits, or no exit and no dead exit: no effect of
      its own) makes the whole call opaque -- but for the members' sink
      demands, as for one such callee (a sink-only effect, or None);
    * inner calls: a register byte no exit of the member mentions and some
      inner call of the member does not keep is UNKNOWN on every exit of that
      member (``derive_proven_call_effect``'s post-merge fill, per member --
      another member's write of that byte must not hide it);
    * memory: callee objects are scoped to their function, so two members'
      writes may land on one caller place under different objects, and the
      caller's rows would apply them one after the other (one value lost).
      In an address space where more than one member writes memory other
      than one shared global object, these writes start UNKNOWN. Only direct
      memory runs proven separately for every member can replace that debt:
      one shared physical entry-register anchor, one address space, no
      unexplained writes or alias conditions. They merge on anchored bytes,
      without renaming any member's objects. Frame bytes below
      the callee's entry stack pointer are left as they are
      (``derive_proven_call_effect`` handles them before any memory key); a
      run with no writer (UNKNOWN only by crossings: e.g. every member's
      return-address slot) is no write of its own to contest. A member's
      real write into its return slot is contested like any other.
    Writer conditions, sink demands, unknown writers, inner calls, dead exits
    and anchors are united; register deltas are kept where every returning
    member states the same delta. ``memory_sources``, when supplied, records
    each synthesized write's original (member index, ProvenMemoryRun or None
    for proven preservation) alternatives, for operation-record provenance."""
    from dataclasses import replace as _replace

    stack = {(span.start, span.size) for span in excluded}
    merged_anchors: dict = {}
    merged_relations: dict = {}
    conflicted_relations = set()
    # a member opaque alone (tail exits, or no exit and no dead exit) is never
    # dropped: the composition gets a tail exit, so ``derive_proven_call_effect``
    # proves no state -- but every member's sink demands still bind at the call
    opaque_members = []
    for index, (summary, anchors) in enumerate(members):
        if summary.tail_exits or (not summary.exits and not summary.dead_exits):
            opaque_members.append(f"opaque-member:{index}")
        merged_anchors.update(anchors or {})
        for object_id, relation in dict(getattr(summary, "address_relations", ())).items():
            if object_id in merged_relations and merged_relations[object_id] != relation:
                conflicted_relations.add(object_id)
            merged_relations[object_id] = relation

    def frame(span, anchors) -> bool:
        """The member's own frame: bytes below its entry stack pointer."""
        row = (anchors or {}).get(span.object_id)
        if row is None or row[0].object_id.kind is not StorageObjectKind.REGISTER_FILE \
                or (row[0].start, row[0].size) not in stack:
            return False
        return span.end <= 1 << (8 * row[0].size)

    def written(run, anchors) -> bool:
        """A memory run that is a write of the member's: it has writers. A
        writer-less run (UNKNOWN: bytes the member never wrote that a crossing
        -- an aliasing store, an unknown-address store, an inner call -- may
        have changed) is the consequence of effects composed elsewhere
        (their own runs, ``unknown_writers``, ``inner_calls``): no write of
        its own to contest -- e.g. every member's return-address slot."""
        return run.span.object_id.kind not in (StorageObjectKind.REGISTER_FILE, StorageObjectKind.FUNCTION_UNIQUE) \
            and run.kind is not SummaryKind.IDENTITY and bool(run.writers) and not frame(run.span, anchors)

    def space_of(span, anchors):
        if span.object_id.kind is StorageObjectKind.ADDRESS_SPACE:
            return span.object_id.space_key
        row = (anchors or {}).get(span.object_id)
        if row is not None:
            return row[1]
        relation = merged_relations.get(span.object_id)
        return None if relation is None else relation.space_id

    # (space -> {member index: written objects}): memory writes outside the frame
    writers: dict = {}
    for index, (summary, anchors) in enumerate(members):
        for exit_summary in summary.exits:
            for run in exit_summary.runs:
                if written(run, anchors):
                    writers.setdefault(space_of(run.span, anchors), {}).setdefault(index, set()).add(run.span.object_id)
    contested = {
        space for space, by_member in writers.items()
        if len(by_member) > 1 and (len(set().union(*by_member.values())) > 1 or any(
            object_id.kind is not StorageObjectKind.ADDRESS_SPACE for objects in by_member.values()
            for object_id in objects))
    }

    exits, unknown_writers, writer_objects, inner_calls, sink_demands = [], [], [], [], []
    writer_conditions, dead_exits = [], []
    deltas = None
    values_out = False
    for index, (summary, anchors) in enumerate(members):
        mentioned = {offset for exit_summary in summary.exits for run in exit_summary.runs
                     if run.span.object_id.kind is StorageObjectKind.REGISTER_FILE
                     for offset in range(run.span.start, run.span.end)}
        filled = set()
        for _, kept, _, _ in summary.inner_calls:
            kept_offsets = {offset for span in kept if span.object_id.kind is StorageObjectKind.REGISTER_FILE
                            for offset in range(span.start, span.end)}
            filled |= {offset for offset in range(register_limit)
                       if offset not in mentioned and offset not in kept_offsets}
        fill = tuple(SummaryRun(span, SummaryKind.UNKNOWN, (), ("inner-call",), (), (), (), ("uncertain:inner-call",))
                     for span in _spans(register_object, filled))
        for exit_summary in summary.exits:
            runs = []
            for run in exit_summary.runs:
                if written(run, anchors) and space_of(run.span, anchors) in contested:
                    run = _replace(run, kind=SummaryKind.UNKNOWN, debts=(*run.debts, "uncertain:several-targets"),
                                   literal=None)
                runs.append(run)
            exits.append(ExitSummary(exit_summary.block_key, (*runs, *fill)))
        unknown_writers += summary.unknown_writers
        writer_objects += summary.writer_objects
        inner_calls += summary.inner_calls
        sink_demands += summary.sink_demands
        writer_conditions += summary.writer_conditions
        dead_exits += summary.dead_exits
        values_out = values_out or summary.stack_values_out
        if summary.exits:   # (a member that never returns states no delta)
            own = dict(summary.register_deltas)
            deltas = own if deltas is None else {slot: delta for slot, delta in deltas.items() if own.get(slot) == delta}
    version = members[0][0].version
    if any(summary.version != version for summary, _ in members):
        return None
    composed = FunctionSummary(
        version, tuple(exits), tuple(unknown_writers), tuple(writer_objects),
        tuple(tail for summary, _ in members for tail in summary.tail_exits) + tuple(opaque_members),
        tuple(inner_calls),
        tuple(sink_demands), tuple(sorted((deltas or {}).items())), tuple(dead_exits), tuple(writer_conditions),
        values_out,
        tuple(sorted(((key, value) for key, value in merged_relations.items() if key not in conflicted_relations),
                     key=lambda pair: repr(pair[0]))),
    )
    effect = derive_proven_call_effect(
        composed, callee, register_object, register_limit, excluded=excluded, anchors=merged_anchors,
        stack_deltas=stack_deltas, failed_conditions=failed_conditions,
    )
    if effect is None or opaque_members or effect.noreturn:
        return effect
    member_effects = tuple(
        (index, derive_proven_call_effect(
            summary, callee, register_object, register_limit, excluded=excluded, anchors=anchors,
            stack_deltas=stack_deltas, failed_conditions=failed_conditions,
        ))
        for index, (summary, anchors) in enumerate(members) if summary.exits
    )
    return _compose_fixed_memory(effect, member_effects, memory_sources)


def _compose_fixed_memory(effect, member_effects, memory_sources=None):
    """Refine only fixed anchored bytes, after each member proved its own
    effect. Missing bytes are old memory only when that member accounts for
    all memory writes, and has no other write that could alias this anchor.
    Global, pointer-chain and conflicting-anchor spaces keep the old result.
    No summary object is rewritten into another function's namespace."""
    from dataclasses import replace

    if not member_effects or any(own is None or not own.preserves_memory or own.writer_conditions
                                 for _, own in member_effects):
        return effect

    spaces: dict = {}
    blocked = set()
    for _, own in member_effects:
        for access in own.unknown_memory:
            blocked.add(access.space_id)
        for run in own.memory_runs:
            access = run.write
            if access.anchor is None or access.anchor.object_id.kind is not StorageObjectKind.REGISTER_FILE \
                    or access.pointer is not None or access.span is not None or access.index is not None or run.conditions:
                blocked.add(access.space_id)
                continue
            spaces.setdefault(access.space_id, set()).add(access.anchor)

    synthesized = []
    replaced: dict = {}
    for space, anchors in sorted(spaces.items()):
        if space in blocked or len(anchors) != 1:
            continue
        (anchor,) = anchors
        grids = []
        conflict = False
        for index, own in member_effects:
            grid = {}
            for run in own.memory_runs:
                if run.write.space_id != space:
                    continue
                for offset in range(run.write.displacement, run.write.displacement + run.write.size):
                    if offset in grid:
                        conflict = True  # more than one final value for a member's byte
                    grid[offset] = run
            grids.append((index, own, grid))
        if conflict:
            continue
        offsets = set().union(*(grid.keys() for _, _, grid in grids))
        # Below-frame writes stay represented by clobbers_below: the caller
        # applies that region's debt after the run outputs. They cannot prove
        # that a byte missing from one member kept its old memory value.
        if any(own.clobbers_below and offsets - grid.keys() for _, own, grid in grids):
            continue
        # Keep original run boundaries, even when the merged dependencies are
        # equal: every output interval has one unambiguous source per member.
        groups = []
        for offset in sorted(offsets):
            alternatives = tuple((index, grid.get(offset)) for index, _, grid in grids)
            if groups and groups[-1][1] == offset and groups[-1][2] == alternatives:
                start, _, sources = groups[-1]
                groups[-1] = (start, offset + 1, sources)
            else:
                groups.append((offset, offset + 1, alternatives))
        for start, end, alternatives in groups:
            write = AnchoredSpan(anchor, start, end - start, space)
            runs = tuple(run for _, run in alternatives if run is not None)
            keeps_old = any(run is None or run.keeps_old for _, run in alternatives)
            reads = tuple(sorted({span for run in runs for span in run.reads}, key=lambda span: span.canonical_key))
            loads = tuple(sorted({access for run in runs for access in run.loads}, key=repr))
            origins = tuple(sorted({origin for run in runs for origin in run.origins}))
            # Pointer facts describe a whole pointer, never a split portion or
            # an old-memory alternative. Equal dependency sets are not proof
            # that two alternatives carry the same pointer value.
            value = runs[0].value if not keeps_old and all(
                run.write == write and run.value == runs[0].value for run in runs
            ) else None
            if value is None and runs and not keeps_old and all(
                    run.write == write and run.value is not None and run.value[0] == "nonstack" for run in runs):
                from .function_summary import join_nonstack

                value = join_nonstack(run.value for run in runs)   # (windows joined, docs 25.79 3b)
            synthesized.append(ProvenMemoryRun(write, reads, loads, keeps_old, origins, value=value))
            if memory_sources is not None:
                memory_sources[write] = alternatives
        replaced[(space, anchor)] = offsets
    if not synthesized:
        return effect

    def remaining(access):
        offsets = replaced.get((access.space_id, access.anchor)) if access.pointer is None \
            and access.span is None and access.index is None else None
        if offsets is None:
            return (access,)
        # Replace exactly the proven byte grid, not an overlapping unknown
        # span's other bytes (nor a place under another physical anchor).
        left = set(range(access.displacement, access.displacement + access.size)) - offsets
        base = min(left, default=0)  # ByteSpan offsets are unsigned; displacements need not be.
        return tuple(AnchoredSpan(access.anchor, base + span.start, span.size, access.space_id)
                     for span in _spans(access.anchor.object_id, (offset - base for offset in left)))

    memory_runs = [replace(run, write=access, value=run.value if access == run.write else None,
                           literal=run.literal if access == run.write else None)
                   for run in effect.memory_runs for access in remaining(run.write)]
    unknown_memory = tuple(access for item in effect.unknown_memory for access in remaining(item))
    return replace(effect, memory_runs=tuple(memory_runs + synthesized), unknown_memory=unknown_memory)


def _observed_registers(runs, memory_runs, unknown_memory, writer_pairs, sink_demands, skip) -> tuple:
    """The register bytes at the call an exported effect depends on: the
    reads of every register and memory run and sink root, and the root anchor
    register of every place it reads or writes (a pointer chain's first
    level), its conditions' included -- but the caller's own stack pointer
    (``skip``: its taint is the stack pointer itself)."""
    found = set()

    def anchor_of(access):
        if access is None:
            return
        if access.anchor is not None:
            found.add(access.anchor)
        anchor_of(access.pointer)
        if access.index is not None:
            if access.index.register is not None:
                found.add(access.index.register)
            anchor_of(access.index.memory)

    def pairs(conditions):
        for left, right in conditions:
            anchor_of(left)
            anchor_of(right)

    for row in (*runs, *memory_runs, *sink_demands):
        found.update(row.reads)
        for access in row.loads:
            anchor_of(access)
        pairs(row.conditions)
    for row in memory_runs:
        anchor_of(row.write)
    for access in unknown_memory:
        anchor_of(access)
    pairs(writer_pairs)
    return tuple(sorted((span for span in found if not set(range(span.start, span.end)) <= skip),
                        key=lambda span: span.canonical_key))


def _sink_demand(demand, anchored, rejections=None, where=None) -> ProvenSinkDemand:
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
            if rejections is not None:
                rejections.append((where, (left, right), "unlocatable"))
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
    ("pointer", value[, span]) marker: bytes of one pointer stay one group, a
    merge of exits with different values keeps both markers -- no value --
    and two pointers with equal values (rax and rcx both a copy of rdi) stay
    two groups, each its own pointer-size run)."""
    marker = ("pointer", run.value) if run.value is None else ("pointer", run.value, run.span)
    # Keep the original full span: equal adjacent scalar stores must not turn
    # into a wider scalar, and a partial output must not reuse the old bits.
    literal = run.literal if type(run.literal) is ExactConstant and run.literal.byte_size == run.span.size \
        and run.kind is SummaryKind.COMPUTED and not run.debts and not run.crossed else None
    literal_marker = ("literal", literal, run.span) if literal is not None else ("literal", None)
    return frozenset(sources) | {("origin", label) for label in run.origins} | {marker, literal_marker}


def _literal_value(sources, keeps_old, spans):
    """An unchanged, full-width scalar agreed by every contributing exit."""
    markers = [item for item in sources if type(item) is tuple and item[0] == "literal"]
    if keeps_old or len(spans) != 1 or len(markers) != 1:
        return None
    marker = markers[0]
    if len(marker) != 3 or type(marker[1]) is not ExactConstant:
        return None
    literal, original = marker[1:]
    return literal if original == spans[0] and literal.byte_size == spans[0].size else None


def _pointer_value(sources, keeps_old, spans, size, anchored):
    """The caller-facing pointer value of one output run, or None."""
    from .function_summary import join_nonstack

    markers = [item[1] for item in sources if type(item) is tuple and item[0] == "pointer"]
    if len(markers) > 1 and all(item is not None and item[0] == "nonstack" for item in markers):
        markers = [join_nonstack(markers)]   # (exits agreeing on "a block": windows joined, docs 25.79 3b)
    if len(markers) != 1 or markers[0] is None or keeps_old or len(spans) != 1 or spans[0].size != size:
        return None
    value = markers[0]
    if value[0] == "nonstack":
        return value
    if value[0] == "offset":
        _, entry, delta = value
        return ("offset_reg", entry, delta) if entry.object_id.kind is StorageObjectKind.REGISTER_FILE else None
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
        unknown_writers=("conditional-writer",),
        # Preserve only separately recomputed original-CFG facts. Ordinary
        # register_deltas may have used a conditional spill/LOAD and are lost.
        register_deltas=_independent_delta_facts(summary),
        writer_conditions=(),
    )


def _independent_delta_facts(summary):
    from .register_delta_proofs import RegisterDeltaProof, validate_proof_record
    facts, kept = dict(summary.register_deltas), {}
    for proof in summary.independent_delta_proofs:
        if type(proof) is not RegisterDeltaProof or validate_proof_record(proof.record()) != proof \
                or proof.register in kept or facts.get(proof.register) != proof.delta:
            raise ValueError("invalid independent register delta certificate in summary")
        kept[proof.register] = proof.delta
    return tuple(sorted(kept.items()))


def _anchored_conditions(run, anchored, failed, rejections=None, where=None):
    """The run's alias conditions as anchored pairs, or None when one cannot
    be located by a caller or a caller already found it failing
    (``rejections``: each such pair appended with its reason)."""
    pairs = set()
    dropped = False
    for left, right in run.conditions:
        pair = (anchored(left), anchored(right))
        if None in pair or pair in failed:
            if rejections is None:
                return None
            rejections.append((where, (left, right), "unlocatable" if None in pair else "failed"))
            dropped = True
            continue
        pairs.add(pair)
    return None if dropped else frozenset(pairs)


def _verdict_without_crossings(run, anchored, failed=frozenset(), rejections=None, where=None):
    if not run.writers and all(span.object_id == run.span.object_id for span in run.sources):
        return "self"  # entry contents, not rewritten by the function itself
    for source in run.sources:
        if source.object_id.kind is not StorageObjectKind.REGISTER_FILE and anchored(source) is None:
            return "unknown"
    conditions = _anchored_conditions(run, anchored, failed, rejections, where)
    if conditions is None:
        return "unknown"
    return (_with_origins(run.sources, run), False, conditions)


def _verdict(run, anchored, failed=frozenset(), rejections=None, where=None):
    if run.kind is SummaryKind.UNKNOWN or run.debts:
        return "unknown"
    if run.kind is SummaryKind.IDENTITY:
        return "self"
    for source in run.sources:
        if source.object_id.kind is not StorageObjectKind.REGISTER_FILE and anchored(source) is None:
            return "unknown"  # entry memory with no anchor the caller can bind
    conditions = _anchored_conditions(run, anchored, failed, rejections, where)
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
    "anchored_span",
    "call_load_keys",
    "AnchoredSpan", "IndexedOffset", "ProvenCallEffect", "ProvenMemoryRun", "ProvenRunEffect", "ProvenSinkDemand",
    "derive_composed_call_effect", "derive_proven_call_effect",
)
