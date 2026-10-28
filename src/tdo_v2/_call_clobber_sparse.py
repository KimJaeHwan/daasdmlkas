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
from heapq import heappop, heappush

from ._sparse_dataflow import DominatorGraph, batching, group_points, lanes_for, solve_lanes
from .label_sets import LabelUniverse
from .phases import count as phase_count, enabled as phases_enabled
from .model import ResolvedStorage
from .span_geometry import ByteSpan, StorageObjectKind

_MEMORY_KINDS = (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)



class _Covering:
    """The labels of the (start, end, label) spans covering an offset, for
    offsets asked in ascending order: spans enter at their start and leave
    at their end (a label may have several spans: counted)."""

    def __init__(self, spans) -> None:
        self.spans = sorted(spans, key=lambda span: span[0])
        self.next = 0
        self.ends: list = []    # heap of (end, entry number, label)
        self.count: dict = {}

    def at(self, offset: int) -> frozenset:
        while self.next < len(self.spans) and self.spans[self.next][0] <= offset:
            start, end, label = self.spans[self.next]
            heappush(self.ends, (end, self.next, label))
            self.count[label] = self.count.get(label, 0) + 1
            self.next += 1
        while self.ends and self.ends[0][0] <= offset:
            _, _, label = heappop(self.ends)
            left = self.count[label] - 1
            if left:
                self.count[label] = left
            else:
                del self.count[label]
        return frozenset(self.count)


def derive_sparse(unit, calls: set[str], preserved: dict[str, tuple[ByteSpan, ...]],
                  memory_keeping: frozenset[str] = frozenset(), observe=None):
    """``observe(effect, calls_at)`` (a measurement, docs 25.83): called per
    effect with reads, ``calls_at(object, offset)`` giving the calls crossed
    at that read byte; no effect on the rows."""
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
        # (docs 25.31 K3-t6) the spans covering the current offset, kept by a
        # sweep over the ascending offsets: the same sets as a scan of every span
        sweeps = (_Covering(writes), _Covering(keeps))
        for offset in sorted(offsets):
            segment = bisect_right(points, offset)
            index = cache.get(segment)
            if index is None:
                covering = sweeps[0].at(offset)
                keeping = sweeps[1].at(offset)
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
    index_of = universe.index_of   # events carry indices (label_sets)

    # the call events are the same for every class with the same keeping set:
    # built once per keeping set (block -> its calls' events, in position
    # order, and the call-only blocks' transfers); per class only the blocks
    # holding one of its kills get merged events of their own (docs 25.31
    # B2-c; per-class copies of every call event were 366 MB of the 30k scale
    # point's traced peak). Same events per block, same transfers, same solve.
    shared: dict = {}

    def calls_for(keeping):
        found = shared.get(keeping)
        if found is None:
            by_block: dict[str, list] = {}
            for block_key, position, key in call_sites:   # (blocks in order, positions ascending)
                if key not in keeping:
                    by_block.setdefault(block_key, []).append((position, 0, index_of[key]))
            transfers = {}
            for block_key, rows in by_block.items():
                gens = 0
                for _, _, label in rows:
                    gens |= 1 << label
                transfers[block_key] = (False, gens, gens)
            found = shared[keeping] = (by_block, transfers, sum(map(len, by_block.values())))
        return found

    def kill_events_of(index: int, calls_by_block) -> dict[str, list]:
        """block -> ordered events (position, order, gen label index or None
        for a kill) of the blocks where class ``index`` has a kill."""
        events: dict[str, list] = {}
        for block_key, position, write in class_writes[index]:
            events.setdefault(block_key, []).append((position, 1 + write, None))
        for block_key, rows in events.items():
            rows.extend(calls_by_block.get(block_key, ()))
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
    # the classes of one keeping set share every call event: solved together,
    # each in its own lane (docs 25.31 K3-t5; a class's transfers exist only
    # while its batch is solved)
    groups: dict = {}
    for index, needed in reads_by_class.items():
        calls_by_block, call_transfers, call_events = calls_for(class_preserving[index])
        events = kill_events_of(index, calls_by_block)
        class_events[index] = (calls_by_block, events)
        if counting:
            phase_count("cc_class_events", call_events + len(class_writes[index]))   # (calls + kills)
        groups.setdefault(class_preserving[index], []).append(index)

    def class_transfers(index):
        """A class's own rows (its kill blocks): the keeping set's call
        transfers are the batch's shared rows (K3-t5b)."""
        transfers = {}
        for block_key, rows in class_events[index][1].items():
            kills = any(label is None for _, _, label in rows)
            last = max((i for i, (_, _, label) in enumerate(rows) if label is None), default=-1)
            after = 0
            for _, _, label in rows[last + 1:]:
                if label is not None:
                    after |= 1 << label
            gens = 0
            for _, _, label in rows:
                if label is not None:
                    gens |= 1 << label
            transfers[block_key] = (kills, after, gens)
        return transfers

    width = len(universe.labels)
    for keeping, members in groups.items():
        union = set(calls_for(keeping)[1])
        for index in members:
            union.update(class_events[index][1])
        lanes = lanes_for(width, len(union), group_points(graph, union)) if len(members) > 1 and batching() else 1
        for first in range(0, len(members), lanes):
            batch = members[first:first + lanes]
            solved = solve_lanes(graph, [(class_transfers(index), reads_by_class[index]) for index in batch], width,
                                 calls_for(keeping)[1])
            for index, values in zip(batch, solved):
                for block_key, value in values.items():
                    entry_values[(index, block_key)] = value

    def value_at(index: int, block_key: str, position: int) -> int:
        value = entry_values[(index, block_key)]
        calls_by_block, kill_blocks = class_events[index]
        rows = kill_blocks.get(block_key)
        if rows is None:
            rows = calls_by_block.get(block_key, ())
        for event_position, _, label in rows:
            if event_position >= position:
                break
            replays[0] += 1
            value = 0 if label is None else value | (1 << label)
        return value

    rows = []
    for block in sorted(blocks, key=lambda item: item.key):
        for position, effect in enumerate(block.effects):
            if observe is not None and effect.reads:
                observe(effect, lambda object_id, offset, key=block.key, position=position: frozenset(
                    universe.decode(value_at(class_of[(object_id, offset)], key, position))))
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
