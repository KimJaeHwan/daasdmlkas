"""Sparse may-alias analysis: same rows as ``may_alias`` (dense).

Per memory-object byte, the dense analysis tracks the writes to *other*
objects (and unknown-address writes) executed since the byte was last
written. As a gen/kill problem, within one effect and in ``effect.writes``
order, a resolved write to object o kills the bytes of o it covers and --
unless every byte it writes is private frame -- gens its key into every
byte of every object that may alias o; then an unknown-address write gens
its key into every byte of every object. The pseudo-byte ``_ANY_WRITE``
(read by unknown-address reads) gens every tracked memory write and never
kills. Bytes with the same (object, covering writes) behave identically and
are solved once per class with ``DominatorGraph.solve_gen_kill``; reads
replay their block's events in effect order and apply the private-frame
filter (``& unknown_writers``) at read time, as the dense code does.
"""

from __future__ import annotations

from bisect import bisect_right

from ._sparse_dataflow import DominatorGraph
from .phases import count as phase_count, enabled as phases_enabled
from .model import ResolvedStorage
from .span_geometry import ByteSpan

_ANY = "any-write"


def derive_sparse(unit, objects, policy):
    from .may_alias import _UNCERTAIN, _row, _unknown_read, _unknown_write

    tracked = set(objects)
    graph = DominatorGraph(unit.entry_block_key, {block.key: block.predecessors for block in unit.blocks})
    blocks = [block for block in unit.blocks if block.key in graph.reachable]

    # object -> gen events (block, position, order, writer); kills per covering write
    object_gens: dict[object, list[tuple[str, int, int, str]]] = {item: [] for item in tracked}
    any_gens: list[tuple[str, int, int, str]] = []
    write_spans: dict[object, list[tuple[int, int, tuple]]] = {}
    read_bytes: dict[object, set[int]] = {}
    unknown_read_blocks: set[str] = set()
    for block in blocks:
        for position, effect in enumerate(block.effects):
            for evidence in effect.reads:
                if type(evidence) is ResolvedStorage and evidence.span.object_id in tracked:
                    span = evidence.span
                    read_bytes.setdefault(span.object_id, set()).update(range(span.start, span.end))
            if _unknown_read(effect):
                unknown_read_blocks.add(block.key)
            writer = effect.operation_key
            for index, evidence in enumerate(effect.writes):
                if type(evidence) is not ResolvedStorage or evidence.span.object_id not in tracked:
                    continue
                span = evidence.span
                order = 1 + index
                if writer not in policy.no_kill_writers:  # an uncertain destination kills nothing
                    write_spans.setdefault(span.object_id, []).append(
                        (span.start, span.end, (block.key, position, order)))
                private = all(policy.is_private(span.object_id, offset, writer, write=True)
                              for offset in range(span.start, span.end))
                for other in tracked:  # a private frame write reaches only wild objects
                    if policy.may_alias(other, span.object_id) and (not private or other in policy.wild_objects):
                        object_gens[other].append((block.key, position, order, writer))
                any_gens.append((block.key, position, order, writer))
            if _unknown_write(effect):
                order = 1 + len(effect.writes)
                for other in tracked:
                    object_gens[other].append((block.key, position, order, writer))
                any_gens.append((block.key, position, order, writer))
            if writer in policy.uncertain_writers:  # may have written anywhere, as the dense code
                order = 2 + len(effect.writes)
                for other in tracked:
                    object_gens[other].append((block.key, position, order, _UNCERTAIN + writer))
                any_gens.append((block.key, position, order, _UNCERTAIN + writer))

    # byte classes: (object, covering writes)
    class_of: dict[tuple, int] = {}
    signatures: dict[tuple, int] = {}
    class_object: list[object] = []
    class_kills: list[frozenset] = []
    for object_id, offsets in read_bytes.items():
        writes = write_spans.get(object_id, [])
        points = sorted({p for s, e, _ in writes for p in (s, e)})
        cache: dict[int, int] = {}
        for offset in sorted(offsets):
            segment = bisect_right(points, offset)
            index = cache.get(segment)
            if index is None:
                covering = frozenset(w for s, e, w in writes if s <= offset < e)
                signature = (object_id, covering)
                index = signatures.get(signature)
                if index is None:
                    index = signatures[signature] = len(class_object)
                    class_object.append(object_id)
                    class_kills.append(covering)
                cache[segment] = index
            class_of[(object_id, offset)] = index

    needed: dict[object, set[str]] = {}  # class index or _ANY -> blocks that read it
    for block in blocks:
        for effect in block.effects:
            for evidence in effect.reads:
                if type(evidence) is ResolvedStorage and evidence.span.object_id in tracked:
                    span = evidence.span
                    for offset in range(span.start, span.end):
                        needed.setdefault(class_of[(span.object_id, offset)], set()).add(block.key)
    if unknown_read_blocks:
        needed[_ANY] = unknown_read_blocks

    class_events: dict[object, dict[str, list]] = {}
    entry_values: dict[tuple, frozenset] = {}
    counting = phases_enabled()   # (K2 sizes, docs 25.31)
    replays = [0]
    if counting:
        phase_count("ma_classes", len(needed))
    for index, blocks_needed in needed.items():
        events: dict[str, list] = {}
        gens = any_gens if index is _ANY else object_gens[class_object[index]]
        for block_key, position, order, writer in gens:
            events.setdefault(block_key, []).append((position, order, writer))
        if index is not _ANY:
            for block_key, position, order in class_kills[index]:
                events.setdefault(block_key, []).append((position, order, None))
        for rows in events.values():
            rows.sort(key=lambda row: (row[0], row[1], row[2] is not None))
        class_events[index] = events
        if counting:
            phase_count("ma_class_events", sum(len(rows) for rows in events.values()))
        transfers = {}
        for block_key, rows in events.items():
            kills = any(label is None for _, _, label in rows)
            last = max((i for i, (_, _, label) in enumerate(rows) if label is None), default=-1)
            after = frozenset(label for _, _, label in rows[last + 1:] if label is not None)
            all_gens = frozenset(label for _, _, label in rows if label is not None)
            transfers[block_key] = (kills, after, all_gens)
        for block_key, value in graph.solve_gen_kill(transfers, blocks_needed).items():
            entry_values[(index, block_key)] = value

    def value_at(index, block_key: str, position: int) -> frozenset:
        value = entry_values[(index, block_key)]
        for event_position, _, label in class_events[index].get(block_key, ()):
            if event_position >= position:
                break
            replays[0] += 1
            value = frozenset() if label is None else value | {label}
        return value

    rows = []
    for block in sorted(blocks, key=lambda item: item.key):
        for position, effect in enumerate(block.effects):
            spans, writers = [], set()
            for evidence in effect.reads:
                if type(evidence) is not ResolvedStorage or evidence.span.object_id not in tracked:
                    continue
                span = evidence.span
                dirty = []
                for offset in range(span.start, span.end):
                    found = value_at(class_of[(span.object_id, offset)], block.key, position)
                    if policy.is_private(span.object_id, offset, effect.operation_key):
                        found = found & policy.unknown_writers
                    if found:
                        dirty.append(offset)
                        writers |= found
                if dirty:
                    spans.append(ByteSpan(span.object_id, dirty[0], dirty[-1] + 1 - dirty[0]))
            if spans:
                rows.append(_row(effect.operation_key, tuple(spans), writers))
            elif _unknown_read(effect):
                value = value_at(_ANY, block.key, position)
                if value:
                    rows.append(_row(effect.operation_key, (), value))
    if counting:
        phase_count("ma_value_at_replays", replays[0])
    return tuple(sorted(rows, key=lambda row: row.operation_key))
