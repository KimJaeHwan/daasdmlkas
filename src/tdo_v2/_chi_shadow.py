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
    at that read (a recorded dense replay of its transfer, same inputs; or,
    for the lazy sparse shadow by default, the sparse engine's own value
    per read byte through ``derive_sparse(observe=)``); a byte the reference
    does not know is a mismatch,
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
# each function checked (``TDO_V2_CHI_SHADOW`` set); read by tests and tools.
# Forward probes add (scope, "probe", load key, spans) entries, kept for the
# whole run (a diagnostic: never cleared here)
RESULTS: dict = {}
# function scope -> {(terminal block, object): {offset: calls}} of the shadow's
# exit states (nonempty sets only); TERMINAL_MISMATCHES: scope -> check (c)
# against ``function_summary._exit_crossings`` (``compare_terminals``)
TERMINALS: dict = {}
# function scope -> LazySparse.metrics (the sparse engine, ``TDO_V2_CHI_SHADOW=sparse``)
# plus the diagnostic work and milliseconds of the whole check ("build_ms": the shadow alone)
METRICS: dict = {}
TERMINAL_MISMATCHES: dict = {}
TERMINAL_KINDS: dict = {}
# calls x connected spans above which a function is skipped; diagnostic work bound
LIMIT = 200_000
WORK = 20_000_000


def record(scope, *args, exits: bool = True) -> None:
    """Check one pass of ``scope`` (``exits`` False: no check (c) capture --
    a forward probe's unit). ``TDO_V2_CHI_REFERENCE=dense``: the sparse
    shadow against the dense replay (no shared dominator code)."""
    import os
    import time

    TERMINALS.pop(scope, None)
    METRICS.pop(scope, None)
    engine ="sparse" if os.environ.get("TDO_V2_CHI_SHADOW") == "sparse" else "dense"
    reference = "dense" if engine == "dense" or os.environ.get("TDO_V2_CHI_REFERENCE") == "dense" else "sparse"
    started = time.perf_counter()
    try:
        with diagnostic(WORK) as ledger:
            RESULTS[scope] = check(*args, scope=scope, engine=engine, reference=reference, exits=exits)
        if scope in METRICS:
            METRICS[scope]["work"] = ledger.work if ledger is not None else 0
            METRICS[scope]["ms"] = round((time.perf_counter() - started) * 1000)
    except DiagnosticExhausted:
        RESULTS[scope] = "exhausted"
        if scope in METRICS:
            METRICS[scope]["exhausted"] = 1   # (partial: no work / ms)
    except Exception as error:   # (the shadow build itself failed: reported, never raised)
        import traceback

        frames = traceback.extract_tb(error.__traceback__)[-3:]
        where = " <- ".join(f"{frame.name}:{frame.lineno}" for frame in reversed(frames))
        RESULTS[scope] = f"{type(error).__name__}: {error} [{where}]"


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


def shadow_unit(unit, calls, preserved, memory_keeping, sources=True):
    """The production unit with ``~chr`` / ``~chi`` actions after each call
    (``sources`` False: the ``~chi`` KILLs only -- the lazy sparse engine
    computes a chi's sources itself, only where a read reaches it)."""
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
                    if sources:
                        actions.append(LocalStorageAction(f"{action.operation_key}~chr", reads=spans))
                    actions.append(LocalStorageAction(f"{action.operation_key}~chi", writes=spans,
                                                      write_mode=MemoryWriteMode.KILL))
        blocks.append(replace(block, actions=tuple(actions)))
    return replace(unit, blocks=tuple(blocks))


class LazySparse:
    """The shadow chi SSA in the sparse engine's style (docs 25.83 S2a): one
    value per atom class (``build_atom_classes``) on the dominator graph
    (``DominatorGraph.solve``: the class's whole phi fixed point, once, only
    for a class some read touches). What is lazy is a chi's SOURCES (the
    class's value just before it): computed only for the chis a read's value
    reaches, recursively, an overwrite stopping the walk -- an eager ``~chr``
    would compute them for every (chi, class) pair. Exits demand nothing
    (``exit_crossings`` is check (c)'s separate measurement, its sources
    counted apart).
    ``metrics``: classes, classes solved for reads / for exits only, chis,
    chi sources demanded by reads / eagerly / by exits, shadow JOIN points
    (phis with two or more definitions) vs the same classes solved without
    chis ("joins_chi_free", same units); "joins_production" (the production
    SSA's JOIN definitions, per read fragment) is another unit, kept only as
    context."""

    def __init__(self, unit, calls, preserved, memory_keeping, terminals=()):
        from ._memory_ssa_classes import build_atom_classes
        from ._sparse_dataflow import DominatorGraph
        from .memory_ssa import _build_partition, _raw_definitions

        shadow = shadow_unit(unit, calls, preserved, memory_keeping, sources=False)
        self.partition = partition = _build_partition(shadow)
        self.definitions = raw = _raw_definitions(shadow, partition.connected)
        write_ids = {(item.operation_key, item.write_ordinal): ordinal for ordinal, item in enumerate(raw)
                     if item.operation_key is not None}
        entry_of = {}
        for ordinal, item in enumerate(raw):
            if item.kind is MemoryDefinitionKind.ENTRY:
                entry_of.setdefault(item.span, ordinal)
        classes = build_atom_classes(shadow, partition, write_ids)
        self.class_of_atom = classes.class_of_atom
        self.entry = [frozenset((entry_of[partition.connected[item.connected]],)) for item in classes.classes]
        self.graph = DominatorGraph(shadow.entry_block_key, {block.key: block.predecessors
                                                            for block in shadow.blocks})
        self.actions = {}            # block -> [(operation key, reads, [(definition, classes)])]
        self.position = {}           # operation key -> (block, index)
        self.chi_at = {}             # chi definition -> (block, index)
        written_in = [set() for _ in classes.classes]
        chi_blocks = [set() for _ in classes.classes]
        self.last_write = {}
        plain_in = [set() for _ in classes.classes]   # (the chi-free twin: joins metric only)
        self.last_plain = {}
        read_points = [set() for _ in classes.classes]
        pairs = 0                    # (chi, class) pairs: the sources an eager ~chr computes
        for block in shadow.blocks:
            rows = []
            for index, action in enumerate(block.actions):
                step()
                self.position[action.operation_key] = (block.key, index)
                writes = []
                for ordinal, span in enumerate(action.writes):
                    definition = write_ids[(action.operation_key, ordinal)]
                    covered = self._classes(span)
                    writes.append((definition, covered))
                    for item in covered:
                        written_in[item].add(block.key)
                        self.last_write[(block.key, item)] = definition
                        if not action.operation_key.endswith("~chi"):
                            plain_in[item].add(block.key)
                            self.last_plain[(block.key, item)] = definition
                    if action.operation_key.endswith("~chi"):
                        self.chi_at[definition] = (block.key, index)
                        pairs += len(covered)
                        for item in covered:
                            chi_blocks[item].add(block.key)
                for span in action.reads:
                    for item in self._classes(span):
                        read_points[item].add((block.key, index))
                rows.append((action.operation_key, action.reads, writes))
            self.actions[block.key] = rows
        self.written_in, self.chi_blocks, self.terminals = written_in, chi_blocks, tuple(terminals)
        self.plain_in = plain_in
        self.entry_values: dict = {}
        self.sources: dict = {}      # (chi definition, class) -> definitions just before it
        self.joins = self.joins_chi_free = 0
        pending = []
        for item in range(len(classes.classes)):
            if read_points[item]:
                self._solve(item, {block for block, _ in read_points[item]})
                pending.extend((block, index, item) for block, index in read_points[item])
        solved = len({item for _, item in self.entry_values})
        while pending:   # the demand closure: chis a read's value reaches, then theirs
            step()
            block, index, item = pending.pop()
            for definition in self.value_before(block, index, item):
                if definition in self.chi_at and (definition, item) not in self.sources:
                    self.source_of(definition, item)
                    pending.append((*self.chi_at[definition], item))
        self.metrics = {"classes": len(classes.classes), "classes_solved": solved, "chis": len(self.chi_at),
                        "chi_sources": len(self.sources), "chi_sources_eager": pairs,
                        "joins_shadow": self.joins, "joins_chi_free": self.joins_chi_free}

    def _solve(self, item, needed) -> None:
        """Class ``item``'s entry values at ``needed``, its chis' blocks and
        the terminals (one fixed point: ``solve`` is independent of ``needed``,
        which only selects the blocks returned)."""
        joins = set()
        values = self.graph.solve(
            self.written_in[item], set(needed) | self.chi_blocks[item] | set(self.terminals),
            exit_of_write=lambda key: frozenset((self.last_write[(key, item)],)),
            entry_value=self.entry[item], capture_phi=lambda key, incoming: joins.add(key))
        self.joins += len(joins)
        # the same class solved without its chis: phi points (two or more
        # definitions) in the same units, so the two counts compare
        plain = set()
        self.graph.solve(self.plain_in[item], (), exit_of_write=lambda key: frozenset((self.last_plain[(key, item)],)),
                         entry_value=self.entry[item], capture_phi=lambda key, incoming: plain.add(key))
        self.joins_chi_free += len(plain)
        for key, value in values.items():
            self.entry_values[(key, item)] = value

    def source_of(self, definition, item) -> frozenset:
        """A chi's sources in class ``item`` (memoized)."""
        found = self.sources.get((definition, item))
        if found is None:
            found = self.sources[(definition, item)] = self.value_before(*self.chi_at[definition], item)
        return found

    def exit_crossings(self) -> dict:
        """Check (c)'s measurement: {(terminal block, object): {offset: calls}}
        (nonempty only) -- every class at every terminal, solving the classes
        no read touched; metrics ``classes_solved_exits`` / ``chi_sources_exits``
        count what this adds (never the read demand above)."""
        before_sources = len(self.sources)
        before_classes = len({item for _, item in self.entry_values})
        atoms_of: dict = {}
        for atom, item in enumerate(self.class_of_atom):
            atoms_of.setdefault(item, []).append(atom)
        found: dict = {}
        for item, atoms in sorted(atoms_of.items()):
            if not any((block, item) in self.entry_values for block in self.terminals):
                self._solve(item, ())
            for block in self.terminals:
                if (block, item) not in self.entry_values:
                    continue   # (unreachable)
                crossed = self._crossed(self.value_before(block, len(self.actions[block]), item), item)
                if not crossed:
                    continue
                for atom in atoms:
                    span = self.partition.atoms[atom]
                    target = found.setdefault((block, span.object_id), {})
                    for offset in range(span.start, span.end):
                        step()
                        target[offset] = crossed
        self.metrics["classes_solved_exits"] = len({item for _, item in self.entry_values}) - before_classes
        self.metrics["chi_sources_exits"] = len(self.sources) - before_sources
        return found

    def _crossed(self, values, item) -> frozenset:
        crossed, pending, seen = set(), list(values), set()
        while pending:
            step()
            definition = pending.pop()
            if definition in seen or definition not in self.chi_at:
                continue
            seen.add(definition)
            crossed.add(self.definitions[definition].operation_key[:-len("~chi")])
            pending.extend(self.source_of(definition, item))
        return frozenset(crossed)

    def _classes(self, span) -> list:
        start, stop = self.partition.covered_range(span)
        return sorted({self.class_of_atom[atom] for atom in range(start, stop)})

    def value_before(self, block, index, item) -> frozenset:
        """Class ``item``'s definitions just before action ``index`` of ``block``."""
        value = self.entry_values[(block, item)]
        for _, _, writes in self.actions[block][:index]:
            for definition, covered in writes:
                if item in covered:
                    value = frozenset((definition,))
        return value

    def closure(self, key, object_id, offset):
        """(calls crossed, ordinary definition identities) for one byte read
        by the action ``key``."""
        from bisect import bisect_right

        atoms = self.partition.by_object[object_id]
        item = self.class_of_atom[atoms.offset + bisect_right(atoms.starts, offset) - 1]
        block, index = self.position[key]
        crossed, origins, pending, seen = set(), set(), list(self.value_before(block, index, item)), set()
        while pending:
            step()
            definition = pending.pop()
            if definition in seen:
                continue
            seen.add(definition)
            if definition in self.chi_at:
                crossed.add(self.definitions[definition].operation_key[:-len("~chi")])
                pending.extend(self.source_of(definition, item))   # (demanded above already)
                continue
            origins.add(_identity(self.definitions[definition]))
        return crossed, origins


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
          public_rows=None, limit: int = 20, scope=None, engine: str = "dense", reference: str = "dense",
          exits: bool = True):
    """Mismatches (a)-(c), at most ``limit``; "skipped" above ``LIMIT`` (the
    dense engine). ``reference``: call_clobber's per-byte state from the
    sparse engine's rows pass (``observe``) or a dense replay."""
    from .call_clobber import CallClobberRead, _EMPTY
    from .memory_ssa import _build_dense, _build_partition

    if memory_unit.effect_evidence_digest != effect_unit.effect_evidence_digest:
        return [("unit", "the memory unit is not this effect unit's")]
    calls = frozenset(calls)
    present = sum(1 for block in memory_unit.blocks for action in block.actions if action.operation_key in calls)
    lazy = None
    if engine == "sparse":
        import time

        started = time.perf_counter()
        lazy = LazySparse(memory_unit, calls, preserved, memory_keeping,
                          memory_unit.observed_terminal_block_keys if exits else ())
        METRICS[scope] = lazy.metrics
        lazy.metrics["build_ms"] = round((time.perf_counter() - started) * 1000)
        lazy.metrics["joins_production"] = sum(1 for definition in memory_ssa.definitions
                                               if definition.kind is MemoryDefinitionKind.JOIN)
        shadow, shadow_reads, shadow_joins = None, {}, {}
    elif present * len(_build_partition(memory_unit).connected) > LIMIT:
        return "skipped"
    else:
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
            if (shadow_row is None and lazy is None) or production_row is None:
                mismatches.append((key, span, "read not in both SSAs"))
                continue
            first = last = None
            for offset in range(span.start, span.end):
                if len(mismatches) >= limit:
                    return
                expected = state.calls_at((span.object_id, offset))
                crossed, origins = lazy.closure(key, span.object_id, offset) if lazy is not None else \
                    shadow_closure(_at(shadow_row, span.object_id, offset), span.object_id, offset)
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

    def exits_and_records():
        if public_rows is not None and sorted(rows, key=lambda row: row.operation_key) != \
                sorted(public_rows, key=lambda row: row.operation_key):
            mismatches.append(("records", len(rows), len(public_rows)))
        if scope is not None and exits and lazy is not None:
            TERMINALS[scope] = lazy.exit_crossings()   # (c), for ``compare_terminals``
        elif scope is not None and exits:
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
                                terminals.setdefault((state.block_key, atom.object_id), {})[offset] = \
                                    frozenset(crossed)
            TERMINALS[scope] = terminals
        return mismatches[:limit]

    if lazy is not None and reference == "sparse":
        # the sparse call_clobber engine (production's) as the reference, per
        # read byte as it emits its rows (docs 25.83 S2a: no dense state)
        from ._call_clobber_sparse import derive_sparse

        class _At:
            def __init__(self, at):
                self.at = at

            def calls_at(self, item):
                return self.at(*item)

        derive_sparse(effect_unit, set(calls), preserved, frozenset(memory_keeping),
                      observe=lambda effect, at: compare(effect, _At(at)))
        return exits_and_records()

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
    return exits_and_records()


def compare_terminals(scope, crossed, dead_keys=frozenset(), limit: int = 20) -> None:
    """Check (c): ``_exit_crossings``' "call:" labels per exit byte against
    the shadow's (``TERMINALS``), every byte and every differing call
    classified on its own, by direction: "dead" (only the shadow has it and it
    is a call of a dead region, which ``_exit_crossings`` drops), "tail" (only
    ``_exit_crossings`` has it and it is no CALL / CALLIND / CALLOTHER: a tail
    jump), "dead-masked" (only ``_exit_crossings`` has this call and the
    shadow has a dead call there instead: the dead call's chi killed it in
    the SSA, ``_exit_crossings`` drops dead calls), else "other". ``TERMINAL_MISMATCHES[scope]``: the first ``limit``
    (byte, call) differences; ``TERMINAL_KINDS[scope]``: all of them counted
    ("exhausted": the diagnostic ledger ran out)."""
    shadow = TERMINALS.get(scope)
    if shadow is None:
        return
    try:
        with diagnostic(WORK):
            _compare_terminals(scope, shadow, crossed, dead_keys, limit)
    except DiagnosticExhausted:
        TERMINAL_MISMATCHES[scope] = [("exhausted",)]
        TERMINAL_KINDS[scope] = {"exhausted": 1}


def _compare_terminals(scope, shadow, crossed, dead_keys, limit) -> None:
    universe = crossed.get("label_universe")
    found, kinds = [], {}
    keys = {key for key in crossed if type(key) is tuple} | set(shadow)
    for key in sorted(keys, key=repr):
        block, object_id = key
        if object_id.kind is StorageObjectKind.FUNCTION_UNIQUE:
            continue
        production = crossed.get(key, {})
        mine = shadow.get(key, {})
        for offset in sorted(set(production) | set(mine)):
            step()
            labels = universe.decode(production.get(offset, 0)) if universe is not None else []
            expected = {label[len("call:"):] for label in labels if label.startswith("call:")}
            got = set(mine.get(offset, ()))
            for item in sorted(got ^ expected):
                if item in got:
                    kind = "dead" if item.split("~", 1)[0] in dead_keys else "other"
                elif not item.endswith(("CALL", "CALLIND", "CALLOTHER")):
                    kind = "tail"
                else:   # masked in the SSA by a dead call's chi (Astra r1's diamond: S2c)
                    kind = "dead-masked" if any(other.split("~", 1)[0] in dead_keys
                                                for other in got - expected) else "other"
                kinds[kind] = kinds.get(kind, 0) + 1
                if len(found) < limit:
                    found.append((block, object_id.kind.value, offset, kind, item, sorted(expected), sorted(got)))
    TERMINAL_MISMATCHES[scope] = found
    TERMINAL_KINDS[scope] = kinds
