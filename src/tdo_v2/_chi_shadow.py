"""Shadow chi memory SSA -- an equivalence check, never a consumer (design
``.census6/design_opaque_call_def.md`` round 3, first step; docs 25.83).

An opaque call as a DEFINITION: after each call action of the production
memory unit the shadow inserts ``{call}~chr`` (reading the call's footprint:
every tracked span minus what the call is proven to preserve and minus the
call's own writes -- the bytes ``call_clobber`` adds it to, its ``called``
point lying between the call's reads and its writes) and ``{call}~chi`` (a
KILL write of the same spans). The reads of ``~chr`` are the pre-call reaching
definitions per fragment, so a chi definition's sources are byte-exact. The
dense engine builds the shadow SSA; production is untouched.

Per read byte of the production unit (streamed, nothing kept but mismatches)
the check compares
(a) the calls met walking chi definitions back to their sources (JOINs and
    chis expanded, a visited set for loops) with ``call_clobber``'s byte state
    at that read (a recorded dense replay of its transfer, same inputs); a
    byte the replay does not know is a mismatch,
(b) the ordinary definitions reached (ENTRY / data / kill writes) with the
    production SSA's reaching definitions (JOINs expanded),
(c) the public records: per read operation the shadow's (dirty spans, calls)
    aggregated as ``call_clobber._transfer`` aggregates them equal the
    production ``CallClobberRead`` rows (before ``subtract_copy_clobbers``;
    the default sparse engine).
Work is charged to a ``diagnostic`` ledger (never the analysis budgets)."""

from __future__ import annotations

from dataclasses import replace

from .memory_contracts import LocalStorageAction, MemoryDefinitionKind, MemoryWriteMode
from .model import ResolvedStorage
from .resource_limits import DiagnosticExhausted, diagnostic, step
from .span_geometry import ByteSpan, StorageObjectKind

_MEMORY_KINDS = (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)
# function scope -> mismatches, "skipped", or an error text: the LAST pass of
# each function checked (``TDO_V2_CHI_SHADOW`` set); read by tests and tools
RESULTS: dict = {}
# function scope -> {(terminal block, object): {offset: calls}} of the shadow's
# exit states (nonempty sets only); TERMINAL_MISMATCHES: scope -> check (c)
# against ``function_summary._exit_crossings`` (``compare_terminals``)
TERMINALS: dict = {}
TERMINAL_MISMATCHES: dict = {}
# calls x connected spans above which a function is skipped; diagnostic work bound
LIMIT = 200_000
WORK = 20_000_000


def record(scope, *args) -> None:
    TERMINALS.pop(scope, None)
    try:
        with diagnostic(WORK):
            RESULTS[scope] = check(*args, scope=scope)
    except DiagnosticExhausted:
        RESULTS[scope] = "exhausted"
    except Exception as error:   # (the shadow build itself failed: reported, never raised)
        RESULTS[scope] = f"{type(error).__name__}: {error}"


def _subtract(span, holes) -> list:
    """``span`` minus the ``holes`` spans of its object (intervals)."""
    pieces = [(span.start, span.end)]
    for hole in holes:
        if hole.object_id != span.object_id:
            continue
        pieces = [part for start, end in pieces for part in (
            ((start, min(end, hole.start)),) if hole.start > start else ()) + (
            ((max(start, hole.end), end),) if hole.end < end else ())
            if part[0] < part[1]]
    return [ByteSpan(span.object_id, start, end - start) for start, end in pieces]


def _footprint(connected, action, preserved, memory_keeping) -> tuple:
    """The tracked bytes the call ``action`` may change: every connected span
    minus its preserved spans and its own writes (and, for a memory-keeping
    call, all memory)."""
    call = action.operation_key
    holes = (*preserved.get(call, ()), *action.writes)
    return tuple(piece for span in connected
                 if not (call in memory_keeping and span.object_id.kind in _MEMORY_KINDS)
                 for piece in _subtract(span, holes))


def shadow_unit(unit, calls, preserved, memory_keeping):
    """The production unit with ``~chr`` / ``~chi`` actions after each call."""
    from .memory_ssa import _build_partition

    connected = _build_partition(unit).connected
    blocks = []
    for block in unit.blocks:
        actions = []
        for action in block.actions:
            actions.append(action)
            if action.operation_key in calls:
                spans = _footprint(connected, action, preserved, memory_keeping)
                if spans:
                    actions.append(LocalStorageAction(f"{action.operation_key}~chr", reads=spans))
                    actions.append(LocalStorageAction(f"{action.operation_key}~chi", writes=spans,
                                                      write_mode=MemoryWriteMode.KILL))
        blocks.append(replace(block, actions=tuple(actions)))
    return replace(unit, blocks=tuple(blocks))


def _reads_by_key(ssa):
    keys = [action.operation_key for action in ssa.actions]
    reads: dict = {}
    for read in ssa.reads:
        reads.setdefault(keys[read.action_id], []).append(
            (read.span, [(fragment.span, fragment.definition_ids) for fragment in read.fragments]))
    return reads, {join.join_definition_id: join.source_definition_ids for join in ssa.joins}


def _at(fragments, object_id, offset):
    for span, ids in fragments:
        if span.object_id == object_id and span.start <= offset < span.end:
            return ids
    return ()


def _identity(definition) -> tuple:
    return (definition.kind.value, definition.span.object_id, definition.span.start, definition.span.size,
            definition.operation_key, definition.write_ordinal)


def check(memory_unit, memory_ssa, effect_unit, calls, preserved, memory_keeping=frozenset(),
          public_rows=None, limit: int = 20, scope=None):
    """Mismatches (a)-(c), at most ``limit``; "skipped" above ``LIMIT``."""
    from .call_clobber import CallClobberRead, _EMPTY
    from .memory_ssa import _build_dense, _build_partition

    if memory_unit.effect_evidence_digest != effect_unit.effect_evidence_digest:
        return [("unit", "the memory unit is not this effect unit's")]
    calls = frozenset(calls)
    present = sum(1 for block in memory_unit.blocks for action in block.actions if action.operation_key in calls)
    if present * len(_build_partition(memory_unit).connected) > LIMIT:
        return "skipped"
    shadow = _build_dense(shadow_unit(memory_unit, calls, preserved, memory_keeping))
    shadow_reads, shadow_joins = _reads_by_key(shadow)
    production_reads, production_joins = _reads_by_key(memory_ssa)

    def production_origins(ids):
        found, pending, seen = set(), list(ids), set()
        while pending:
            step()
            item = pending.pop()
            if item not in seen:
                seen.add(item)
                if item in production_joins:
                    pending.extend(production_joins[item])
                else:
                    found.add(_identity(memory_ssa.definitions[item]))
        return found

    def shadow_closure(ids, object_id, offset):
        crossed, origins, pending, seen = set(), set(), list(ids), set()
        while pending:
            step()
            item = pending.pop()
            if item in seen:
                continue
            seen.add(item)
            if item in shadow_joins:
                pending.extend(shadow_joins[item])
                continue
            definition = shadow.definitions[item]
            key = definition.operation_key
            if definition.kind is MemoryDefinitionKind.KILL and key is not None and key.endswith("~chi"):
                call = key[:-len("~chi")]
                crossed.add(call)
                for _, fragments in shadow_reads.get(f"{call}~chr", ()):
                    pending.extend(_at(fragments, object_id, offset))
                continue
            origins.add(_identity(definition))
        return crossed, origins

    mismatches: list = []
    rows: list = []

    def compare(effect, state):
        """One effect's reads at ``state`` (call_clobber's) against the shadow."""
        spans, crossed_all = [], set()
        key = effect.operation_key
        shadow_rows = shadow_reads.get(key, [])
        production_rows = production_reads.get(key, [])
        for evidence in effect.reads:
            if type(evidence) is not ResolvedStorage:
                continue
            span = evidence.span
            shadow_row = next((fragments for read_span, fragments in shadow_rows if read_span == span), None)
            production_row = next((fragments for read_span, fragments in production_rows if read_span == span),
                                  None)
            if shadow_row is None or production_row is None:
                mismatches.append((key, span, "read not in both SSAs"))
                continue
            first = last = None
            for offset in range(span.start, span.end):
                if len(mismatches) >= limit:
                    return
                expected = state.calls_at((span.object_id, offset))
                crossed, origins = shadow_closure(_at(shadow_row, span.object_id, offset), span.object_id, offset)
                if set(expected) != crossed:
                    mismatches.append((key, span.object_id, offset, "calls", sorted(expected), sorted(crossed)))
                if production_origins(_at(production_row, span.object_id, offset)) != origins:
                    mismatches.append((key, span.object_id, offset, "origins"))
                if crossed:
                    first = offset if first is None else first
                    last = offset
                    crossed_all |= crossed
            if first is not None:
                spans.append(ByteSpan(span.object_id, first, last + 1 - first))
        if spans:
            rows.append(CallClobberRead(key, tuple(spans), tuple(sorted(crossed_all))))

    # a recorded dense replay of call_clobber's transfer, comparing as it goes
    blocks = {block.key: block for block in effect_unit.blocks}
    successors: dict = {key: [] for key in blocks}
    for block in effect_unit.blocks:
        for predecessor in block.predecessors:
            successors[predecessor].append(block.key)

    def transfer(block, state, comparing):
        for effect in block.effects:
            if comparing:
                compare(effect, state)
            key = effect.operation_key
            if key in calls:
                step(1 + len(state.bytes) + sum(span.size for span in preserved.get(key, ())))   # (its byte loops)
                state = state.called(key, preserved.get(key, ()), key in memory_keeping)
            for evidence in effect.writes:
                if type(evidence) is ResolvedStorage:
                    step(evidence.span.size)
                    state = state.written(evidence.span)
        return state

    in_states = {effect_unit.entry_block_key: _EMPTY}
    pending = {effect_unit.entry_block_key}
    while pending:
        step()
        key = min(pending)
        pending.remove(key)
        state = transfer(blocks[key], in_states[key], False)
        for successor in successors[key]:
            previous = in_states.get(successor)
            merged = state if previous is None else previous.meet(state)
            if merged != previous:
                in_states[successor] = merged
                pending.add(successor)
    for key in sorted(in_states):
        transfer(blocks[key], in_states[key], True)
        if len(mismatches) >= limit:
            return mismatches[:limit]
    if public_rows is not None and sorted(rows, key=lambda row: row.operation_key) != \
            sorted(public_rows, key=lambda row: row.operation_key):
        mismatches.append(("records", len(rows), len(public_rows)))
    if scope is not None:
        # (c) the calls crossed at each exit byte, for ``compare_terminals``
        terminals: dict = {}
        for state in shadow.observed_terminal_states:
            pending = [state.root_node_id] if state.root_node_id is not None else []
            while pending:
                step()
                node = shadow.state_nodes[pending.pop()]
                pending.extend(item for item in (node.left_node_id, node.right_node_id) if item is not None)
                for atom in shadow.atomic_spans[node.start_atom:node.stop_atom]:
                    for offset in range(atom.start, atom.end):
                        crossed, _ = shadow_closure(node.definition_ids, atom.object_id, offset)
                        if crossed:
                            terminals.setdefault((state.block_key, atom.object_id), {})[offset] = frozenset(crossed)
        TERMINALS[scope] = terminals
    return mismatches[:limit]


def compare_terminals(scope, crossed, dead_keys=frozenset(), limit: int = 20) -> None:
    """Check (c): ``_exit_crossings``' "call:" labels per exit byte against
    the shadow's (``TERMINALS``); kinds: "dead" (a call only on dead paths,
    which ``_exit_crossings`` drops), "tail" (a tail jump's), "other"."""
    shadow = TERMINALS.get(scope)
    if shadow is None:
        return
    universe = crossed.get("label_universe")
    found = []
    keys = {key for key in crossed if type(key) is tuple} | set(shadow)
    for key in sorted(keys, key=repr):
        block, object_id = key
        if object_id.kind is StorageObjectKind.FUNCTION_UNIQUE:
            continue
        production = crossed.get(key, {})
        mine = shadow.get(key, {})
        for offset in sorted(set(production) | set(mine)):
            labels = universe.decode(production.get(offset, 0)) if universe is not None else []
            expected = {label[len("call:"):] for label in labels if label.startswith("call:")}
            got = set(mine.get(offset, ()))
            if expected != got:
                extra = got ^ expected
                kind = "dead" if any(item.split("~", 1)[0] in dead_keys for item in extra) else \
                    "tail" if any(not item.endswith(("CALL", "CALLIND", "CALLOTHER")) for item in extra) else "other"
                found.append((block, object_id.kind.value, offset, kind, sorted(expected), sorted(got)))
                if len(found) >= limit:
                    TERMINAL_MISMATCHES[scope] = found
                    return
    TERMINAL_MISMATCHES[scope] = found
