"""Shadow chi memory SSA -- an equivalence check, never a consumer (design
``.census6/design_opaque_call_def.md`` round 3, first step).

An opaque call as a DEFINITION: after each call action of the production
memory unit the shadow inserts ``{call}~chr`` (reading the call's footprint:
every tracked span minus what the call is proven to preserve -- the bytes
``call_clobber`` adds it to) and ``{call}~chi`` (a KILL write of the same
spans). The reads of ``~chr`` are the pre-call reaching definitions per
fragment, so a chi definition's sources are byte-exact. The dense engine builds
the shadow SSA; production is untouched.

Per read byte of the production unit the check compares
(a) the calls met walking chi definitions back to their sources (JOINs and
    chis expanded, a visited set for loops) with ``call_clobber``'s byte state
    at that read (the calls executed since the byte was last written), and
(b) the ordinary definitions reached (ENTRY / data / kill writes, by canonical
    key) with the production SSA's reaching definitions (JOINs expanded).
``check`` returns the mismatches (empty: equivalent)."""

from __future__ import annotations

from dataclasses import replace

from .memory_contracts import LocalStorageAction, MemoryDefinitionKind, MemoryWriteMode
from .model import ResolvedStorage
from .resource_limits import step
from .span_geometry import ByteSpan, StorageObjectKind

_MEMORY_KINDS = (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)
# (function scope, mismatches or an error text) per normalization pass checked
# (``TDO_V2_CHI_SHADOW`` set): a measurement, read by tests and tools
RESULTS: list = []


# calls x footprint spans above which a function is skipped (reported as
# "skipped"): the shadow kills every tracked span at every call
LIMIT = 200_000


def record(scope, *args) -> None:
    try:
        RESULTS.append((scope, check(*args)))
    except Exception as error:   # (the shadow build itself failed: reported, never raised)
        RESULTS.append((scope, f"{type(error).__name__}: {error}"))


def _footprint(connected, call, preserved, memory_keeping) -> tuple:
    """The tracked bytes ``call`` may change: every connected span minus the
    call's preserved spans (and, for a memory-keeping call, all memory)."""
    kept = {}
    for span in preserved.get(call, ()):
        kept.setdefault(span.object_id, set()).update(range(span.start, span.end))
    found = []
    for span in connected:
        if call in memory_keeping and span.object_id.kind in _MEMORY_KINDS:
            continue
        skip = kept.get(span.object_id, ())
        start = None
        for offset in range(span.start, span.end + 1):
            inside = offset < span.end and offset not in skip
            if inside and start is None:
                start = offset
            elif not inside and start is not None:
                found.append(ByteSpan(span.object_id, start, offset - start))
                start = None
    return tuple(found)


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
                spans = _footprint(connected, action.operation_key, preserved, memory_keeping)
                if spans:
                    actions.append(LocalStorageAction(f"{action.operation_key}~chr", reads=spans))
                    actions.append(LocalStorageAction(f"{action.operation_key}~chi", writes=spans,
                                                      write_mode=MemoryWriteMode.KILL))
        blocks.append(replace(block, actions=tuple(actions)))
    return replace(unit, blocks=tuple(blocks))


def _byte_definitions(ssa):
    """(operation key -> [(read span, [(fragment span, definition ids)])]),
    join id -> source ids."""
    keys = [action.operation_key for action in ssa.actions]
    reads: dict = {}
    for read in ssa.reads:
        reads.setdefault(keys[read.action_id], []).append(
            (read.span, [(fragment.span, fragment.definition_ids) for fragment in read.fragments]))
    joins = {join.join_definition_id: join.source_definition_ids for join in ssa.joins}
    return reads, joins


def _at(fragments, object_id, offset):
    for span, ids in fragments:
        if span.object_id == object_id and span.start <= offset < span.end:
            return ids
    return ()


def _reference_calls(effect_unit, calls, preserved, memory_keeping) -> dict:
    """``call_clobber``'s byte state at each read: (operation key, object,
    offset) -> calls (dense engine, recorded)."""
    from .call_clobber import _EMPTY

    blocks = {block.key: block for block in effect_unit.blocks}
    successors: dict = {key: [] for key in blocks}
    for block in effect_unit.blocks:
        for predecessor in block.predecessors:
            successors[predecessor].append(block.key)

    def transfer(block, state, found):
        for effect in block.effects:
            if found is not None:
                for evidence in effect.reads:
                    if type(evidence) is ResolvedStorage:
                        span = evidence.span
                        for offset in range(span.start, span.end):
                            found[(effect.operation_key, span.object_id, offset)] = \
                                state.calls_at((span.object_id, offset))
            key = effect.operation_key
            if key in calls:
                state = state.called(key, preserved.get(key, ()), key in memory_keeping)
            for evidence in effect.writes:
                if type(evidence) is ResolvedStorage:
                    state = state.written(evidence.span)
        return state

    in_states = {effect_unit.entry_block_key: _EMPTY}
    pending = {effect_unit.entry_block_key}
    while pending:
        step()
        key = min(pending)
        pending.remove(key)
        state = transfer(blocks[key], in_states[key], None)
        for successor in successors[key]:
            previous = in_states.get(successor)
            merged = state if previous is None else previous.meet(state)
            if merged != previous:
                in_states[successor] = merged
                pending.add(successor)
    found: dict = {}
    for key in sorted(in_states):
        transfer(blocks[key], in_states[key], found)
    return found


def check(memory_unit, memory_ssa, effect_unit, calls, preserved, memory_keeping=frozenset(),
          limit: int = 20) -> list:
    """Mismatches between the shadow chi SSA and (a) call_clobber, (b) the
    production SSA's origins, per read byte; at most ``limit``."""
    from .memory_ssa import _build_dense

    from .memory_ssa import _build_partition

    calls = frozenset(calls)
    present = sum(1 for block in memory_unit.blocks for action in block.actions if action.operation_key in calls)
    if present * len(_build_partition(memory_unit).connected) > LIMIT:
        return "skipped"
    shadow = _build_dense(shadow_unit(memory_unit, calls, preserved, memory_keeping))
    shadow_reads, shadow_joins = _byte_definitions(shadow)
    production_reads, production_joins = _byte_definitions(memory_ssa)
    reference = _reference_calls(effect_unit, calls, preserved, memory_keeping)

    def production_origins(ids, object_id, offset):
        found, pending, seen = set(), list(ids), set()
        while pending:
            step()
            item = pending.pop()
            if item in seen:
                continue
            seen.add(item)
            if item in production_joins:
                pending.extend(production_joins[item])
            else:
                found.add(memory_ssa.definitions[item].canonical_key)
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
            origins.add(definition.canonical_key)
        return crossed, origins

    mismatches = []
    for key, rows in sorted(production_reads.items()):
        for span, fragments in rows:
            shadow_rows = [row for row in shadow_reads.get(key, ()) if row[0] == span]
            if len(shadow_rows) != 1:
                mismatches.append((key, span, "read not in the shadow"))
                continue
            for offset in range(span.start, span.end):
                crossed, origins = shadow_closure(_at(shadow_rows[0][1], span.object_id, offset),
                                                  span.object_id, offset)
                expected_calls = reference.get((key, span.object_id, offset))
                if expected_calls is not None and set(expected_calls) != crossed:
                    mismatches.append((key, span.object_id, offset, "calls", sorted(expected_calls), sorted(crossed)))
                expected = production_origins(_at(fragments, span.object_id, offset), span.object_id, offset)
                if expected != origins:
                    mismatches.append((key, span.object_id, offset, "origins", len(expected), len(origins)))
                if len(mismatches) >= limit:
                    return mismatches
    return mismatches
