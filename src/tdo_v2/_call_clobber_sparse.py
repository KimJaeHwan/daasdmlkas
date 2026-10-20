"""Sparse call-clobber analysis: same rows as ``call_clobber`` (dense).

Per byte, the dense analysis tracks the calls crossed since the byte was last
written. That is a gen/kill problem: a call that does not preserve the byte
is a gen of its key, a write covering the byte is a kill; within one effect
the reads come first, then the call, then the writes. Bytes with the same
(covering writes, preserving calls) behave identically, so one value is
solved per byte class with ``DominatorGraph.solve_gen_kill`` (union at joins,
empty at the entry); reads replay their block's events in effect order.
Only blocks reachable from the entry produce rows, as in the dense code.
"""

from __future__ import annotations

from bisect import bisect_right

from ._sparse_dataflow import DominatorGraph
from .label_sets import LabelUniverse
from .phases import count as phase_count, enabled as phases_enabled
from .model import ResolvedStorage
from .span_geometry import ByteSpan, StorageObjectKind

_MEMORY_KINDS = (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)


def derive_sparse(unit, calls: set[str], preserved: dict[str, tuple[ByteSpan, ...]],
                  memory_keeping: frozenset[str] = frozenset()):
    from .call_clobber import CallClobberRead

    graph = DominatorGraph(unit.entry_block_key, {block.key: block.predecessors for block in unit.blocks})
    blocks = [block for block in unit.blocks if block.key in graph.reachable]

    # -- byte segments per object and their signatures -------------------------
    write_spans: dict[object, list[tuple[int, int, tuple]]] = {}   # object -> (start, end, write id)
    preserve_spans: dict[object, list[tuple[int, int, str]]] = {}  # object -> (start, end, call)
    read_bytes: dict[object, set[int]] = {}
    for block in blocks:
        for position, effect in enumerate(block.effects):
            for evidence in effect.reads:
                if type(evidence) is ResolvedStorage:
                    span = evidence.span
                    read_bytes.setdefault(span.object_id, set()).update(range(span.start, span.end))
            for index, evidence in enumerate(effect.writes):
                if type(evidence) is ResolvedStorage:
                    span = evidence.span
                    write_spans.setdefault(span.object_id, []).append(
                        (span.start, span.end, (block.key, position, index)))
    for key, spans in preserved.items():
        if key in calls:
            for span in spans:
                preserve_spans.setdefault(span.object_id, []).append((span.start, span.end, key))

    class_of: dict[tuple, int] = {}       # (object, offset) -> class
    signatures: dict[tuple, int] = {}
    class_writes: list[frozenset] = []
    class_preserving: list[frozenset] = []
    for object_id, offsets in read_bytes.items():
        writes = write_spans.get(object_id, [])
        keeps = preserve_spans.get(object_id, [])
        points = sorted({p for s, e, _ in writes for p in (s, e)} | {p for s, e, _ in keeps for p in (s, e)})
        cache: dict[int, int] = {}
        for offset in sorted(offsets):
            segment = bisect_right(points, offset)
            index = cache.get(segment)
            if index is None:
                covering = frozenset(w for s, e, w in writes if s <= offset < e)
                keeping = frozenset(c for s, e, c in keeps if s <= offset < e)
                if object_id.kind in _MEMORY_KINDS:
                    keeping |= memory_keeping  # summarized calls proven to keep memory
                signature = (covering, keeping)
                index = signatures.get(signature)
                if index is None:
                    index = signatures[signature] = len(class_writes)
                    class_writes.append(covering)
                    class_preserving.append(keeping)
                cache[segment] = index
            class_of[(object_id, offset)] = index

    # -- events -----------------------------------------------------------------
    call_sites = [
        (block.key, position, effect.operation_key)
        for block in blocks
        for position, effect in enumerate(block.effects)
        if effect.operation_key in calls
    ]
    # the crossed calls as int bitsets over the call sites' keys (docs 25.31
    # B2; were frozensets of keys): the same sets, fixed points, pops and rows
    universe = LabelUniverse(key for _, _, key in call_sites)
    bit_of = universe.bit_of

    def events_of(index: int) -> dict[str, list[tuple[int, int, str | None]]]:
        """block -> ordered events (position, order, gen label or None for kill)."""
        events: dict[str, list] = {}
        keeping = class_preserving[index]
        for block_key, position, key in call_sites:
            if key not in keeping:
                events.setdefault(block_key, []).append((position, 0, bit_of[key]))
        for block_key, position, write in class_writes[index]:
            events.setdefault(block_key, []).append((position, 1 + write, None))
        for rows in events.values():
            # (position, order) never ties: one call per effect at order 0,
            # one kill per covering write at 1 + its ordinal
            rows.sort(key=lambda row: (row[0], row[1]))
        return events

    reads_by_class: dict[int, set[str]] = {}
    for block in blocks:
        for effect in block.effects:
            for evidence in effect.reads:
                if type(evidence) is ResolvedStorage:
                    span = evidence.span
                    for offset in range(span.start, span.end):
                        reads_by_class.setdefault(class_of[(span.object_id, offset)], set()).add(block.key)

    entry_values: dict[tuple[int, str], int] = {}
    class_events: dict[int, dict] = {}
    counting = phases_enabled()   # (K2 sizes, docs 25.31)
    replays = [0]
    if counting:
        phase_count("cc_classes", len(reads_by_class))
    for index, needed in reads_by_class.items():
        events = events_of(index)
        class_events[index] = events
        if counting:
            phase_count("cc_class_events", sum(len(rows) for rows in events.values()))
        transfers = {}
        for block_key, rows in events.items():
            kills = any(label is None for _, _, label in rows)
            last = max((i for i, (_, _, label) in enumerate(rows) if label is None), default=-1)
            after = 0
            for _, _, label in rows[last + 1:]:
                if label is not None:
                    after |= label
            gens = 0
            for _, _, label in rows:
                if label is not None:
                    gens |= label
            transfers[block_key] = (kills, after, gens)
        for block_key, value in graph.solve_gen_kill(transfers, needed, empty=0).items():
            entry_values[(index, block_key)] = value

    def value_at(index: int, block_key: str, position: int) -> int:
        value = entry_values[(index, block_key)]
        for event_position, _, label in class_events[index].get(block_key, ()):
            if event_position >= position:
                break
            replays[0] += 1
            value = 0 if label is None else value | label
        return value

    rows = []
    for block in sorted(blocks, key=lambda item: item.key):
        for position, effect in enumerate(block.effects):
            spans = []
            crossed = 0
            for evidence in effect.reads:
                if type(evidence) is not ResolvedStorage:
                    continue
                span = evidence.span
                dirty = []
                for offset in range(span.start, span.end):
                    found = value_at(class_of[(span.object_id, offset)], block.key, position)
                    if found:
                        dirty.append(offset)
                        crossed |= found
                if dirty:
                    spans.append(ByteSpan(span.object_id, dirty[0], dirty[-1] + 1 - dirty[0]))
            if spans:
                rows.append(CallClobberRead(effect.operation_key, tuple(spans), tuple(universe.decode(crossed))))
    if counting:
        phase_count("cc_value_at_replays", replays[0])
    return tuple(sorted(rows, key=lambda row: row.operation_key))
