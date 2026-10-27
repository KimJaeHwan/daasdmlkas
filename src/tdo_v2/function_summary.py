"""Function summaries for the interprocedural layer (docs/interprocedural_design.md, S0).

A summary is read off the finished intra-function graph; nothing about the
caller is used. For every observed terminal block it classifies each run of
the terminal memory state (registers, stack, pointer-relative objects,
globals):

* ``IDENTITY`` -- the run still holds the function-entry value of the same
  bytes (preserved).
* ``COMPUTED`` -- the value was defined inside the function; ``sources`` are
  the entry bytes it depends on (backward data slice of the terminal
  definitions down to ENTRY), ``entry_readers`` the operations that read
  entry memory on the way, ``debts`` the debt kinds reached.
* ``UNKNOWN`` -- a call (not preserving these bytes), an unknown-address
  write, or a write to another object that may alias these bytes executed
  after the last write on some path; the value may be anything those
  produced (``crossed`` names them).

A memory write whose *address* depends on an uncertain value (a read with
may-alias, unresolved-address or call-clobber debt) may land on bytes other
than its static object: it is listed in ``unknown_writers`` and treated like
an unknown-address write -- unless that debt reduces to alias conditions
(S3: "these read and write spans do not overlap"). Such a writer lands on its
static object when the conditions hold: it is an ordinary write here, and its
conditions are ``writer_conditions``, carried by every run that is not
IDENTITY/UNKNOWN; a caller that cannot decide them, or finds one failing,
treats the whole call as unknown (``call_summary_effects``).
* ``AFFINE`` -- reserved for the stack pointer (S2).

Bytes the function never touches do not appear in the terminal state; they
are untouched, i.e. preserved (an unknown-address writer is the exception:
see ``unknown_writers``).

``crossed`` is a gen/kill problem per byte (calls, aliasing writes and
unknown-address writes gen; writes covering the byte kill) solved with the
shared sparse solver at the exit of each terminal block.
"""

from __future__ import annotations

from .phases import count as phase_count, measured

from .resource_limits import limit

from .resource_limits import step

from dataclasses import dataclass, replace
from enum import StrEnum

from ._sparse_dataflow import DominatorGraph
from .constant_value import ExactConstant
from .graph_contracts import NodeKind
from .label_sets import LabelUniverse
from .memory_contracts import MemoryDefinitionKind
from .model import ResolvedStorage
from .span_geometry import ByteSpan, StorageObjectKind

FUNCTION_SUMMARY_VERSION = 1
_CALL_OPCODES = ("CALL", "CALLIND", "CALLOTHER")
_ADDRESS_UNCERTAIN = {"may_alias_read", "unresolved_memory_read", "call_clobber_read", "uncertain_write_read",
                      "open_condition", "opaque_call_write"}
# debt of a read a conditional uncertain-address writer may reach: for roots
# only -- a summary carries those writers' conditions on every claim already
_SUMMARY_TRANSPARENT = "uncertain_write_read"
_MEMORY_KINDS = (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)


class SummaryKind(StrEnum):
    IDENTITY = "identity"
    AFFINE = "affine"
    COMPUTED = "computed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class SummaryRun:
    span: ByteSpan                      # terminal bytes, in this function's storage objects
    kind: SummaryKind
    definitions: tuple[int, ...]        # terminal memory SSA definition ids
    writers: tuple[str, ...]            # operation keys of the defining writes (ENTRY: none)
    sources: tuple[ByteSpan, ...]       # entry bytes the value depends on (data)
    entry_readers: tuple[str, ...]      # operations that read entry memory on the way
    debts: tuple[str, ...]              # debt kinds reached by the backward slice
    crossed: tuple[str, ...]            # "call:<key>", "alias:<key>", "unknown:<key>" at the exit
    origins: tuple[str, ...] = ()       # source labels reached (``origin_labels`` of the function)
    # (read span, write span) pairs that must be disjoint for this value to be
    # as stated (conditional may-alias debts on the way, see ``SinkDemand``)
    conditions: tuple[tuple[ByteSpan, ByteSpan], ...] = ()
    # pointer value of a pointer-width COMPUTED run (``_pointer_values``):
    # ("nonstack",) -- an address of a block a call in the function allocated
    # (never a stack address); ("nonstack", N, nullable, labels) -- such a
    # block of N bytes (null too when nullable), resting on ``labels`` (docs
    # 25.79 3b: the caller keeps its accesses inside apart from the stack); ("same", entry span, null_is_fresh) -- the
    # value the entry bytes held (a copy, or, with null_is_fresh, a realloc
    # of it: a null entry value then means a new block); ("offset", entry
    # register span, c) -- the value that register held at entry + c (c
    # unsigned, wrapped; never the stack pointer: docs 25.80 R1); None: unknown
    value: tuple | None = None
    # Exact scalar bits at this run's full width, not pointer provenance.
    literal: ExactConstant | None = None


@dataclass(frozen=True, slots=True)
class ExitSummary:
    block_key: str
    runs: tuple[SummaryRun, ...]


@dataclass(frozen=True, slots=True)
class SinkDemand:
    """What one sink root of the function needs from its callers: the entry
    bytes its backward data slice reaches (``sources``), the debts on the way,
    the source labels reached inside, and whether the root itself is complete
    (bound, no debt). A caller projects it to its own values at the call."""

    label: str
    sources: tuple[ByteSpan, ...]
    debts: tuple[str, ...]
    origins: tuple[str, ...]
    complete: bool
    # (read span, write span) pairs in this function's objects: the root is
    # complete only if every pair is disjoint (a may-alias debt between two
    # exactly addressed objects, decided by a caller that knows both bases;
    # design S3). ``complete`` already holds every other gap.
    conditions: tuple[tuple[ByteSpan, ByteSpan], ...] = ()


@dataclass(frozen=True, slots=True)
class FunctionSummary:
    version: int
    exits: tuple[ExitSummary, ...]
    unknown_writers: tuple[str, ...]    # operations with unknown-address writes
    writer_objects: tuple[tuple[str, object], ...]  # (write operation, storage object it defines)
    # blocks that may leave the function other than by RETURN (tail jumps, also
    # conditional ones); a caller treats state leaving through them as UNKNOWN
    # until tail-call composition exists (design S1/S2)
    tail_exits: tuple[str, ...] = ()
    # every opaque or summarized call inside, with the bytes it is known to leave
    # unchanged: a byte the function never touches is preserved only if every
    # inner call preserves it too
    # (call key, register spans it preserves, whether it preserves all memory)
    # (call key, register spans it preserves, whether it preserves all memory
    # -- except, with the last flag, the stack below its call-time pointer)
    inner_calls: tuple[tuple[str, tuple[ByteSpan, ...], bool, bool], ...] = ()
    sink_demands: tuple[SinkDemand, ...] = ()
    # pointer-sized registers whose value at every normal exit is provably
    # "entry value + c" (the same c): ((offset, size), c). The stack pointer's
    # c tells a caller whether the call restores it (design S2, AFFINE).
    register_deltas: tuple[tuple[tuple[int, int], int], ...] = ()
    # exits left out as never reached: behind a software trap or a call that
    # never returns (named assumption debug-break-traps-do-not-return); a
    # function with no exit, no tail exit and some dead exit never returns
    dead_exits: tuple[str, ...] = ()
    # alias conditions of uncertain-address writers taken as landing on their
    # static objects (see the module docstring); every claim of the summary
    # holds only with them
    writer_conditions: tuple = ()
    # a value derived from the entry stack pointer may leave the function other
    # than in the stack pointer: in another register at a RETURN, or by an
    # escape inside (``may_alias.stack_values_out``); True when not known
    stack_values_out: bool = True
    # Bounded original-entry base/index address relations for relative objects.
    address_relations: tuple = ()


@measured("summarize")
def summarize_function(normalized, observation, origin_labels=None, sink_roots=(),
                       dead_ops=frozenset(), noreturn_jumps=frozenset()) -> FunctionSummary:
    """``origin_labels``: graph node -> source labels it carries (boundary
    origins of this function, e.g. a declared source call's write, or a
    summarized call's run that reached a source inside the callee).
    ``sink_roots``: (label, root nodes, bound and complete so far) per sink
    root of the function, its own or projected from callees; each becomes a
    ``SinkDemand``.
    ``dead_ops``: operation keys execution never continues past (software
    traps, ``debug-break-traps-do-not-return``); with calls proven never to
    return (``ProvenCallEffect.noreturn``) they cut the paths behind them:
    exits, calls and writes only reachable through one are left out.
    ``noreturn_jumps``: conditional jumps whose taken edge leaves the function
    for a function that never returns (``interprocedural._noreturn_jumps``):
    that edge is no tail exit; the fall-through path stays."""
    from .call_clobber import _preserved_stack_pointers
    from .may_alias import stack_values_out
    from .relative_memory import indexed_relations

    context = normalized.scopes.resolution_context

    ssa = normalized.memory_ssa
    graph = normalized.dependencies
    atoms = ssa.atomic_spans
    definitions = ssa.definitions
    definition_nodes = normalized.memory_graph.definition_nodes

    operation_of = _operation_nodes(graph)

    conditions_of = _alias_conditions(normalized)
    closure = _AncestorClosure(graph, operation_of, origin_labels or {}, conditions_of)

    def definition_slice(definition_id: int):
        """(entry source spans, entry-memory readers, debt labels, origins,
        alias conditions) of the backward data slice from one definition
        (same sets as ``BackwardSliceQuery`` + edge spans, computed for all
        nodes at once), as the closure's five int bitsets."""
        return closure.of(definition_nodes[definition_id])

    definition_slice.decode = closure.decode

    uncertain_conditions = _uncertain_address_writers(
        normalized, observation, context, operation_of, conditions_of)
    # writers whose address debt is conditional land on their static object
    # (the conditions travel with the summary); the others may land anywhere
    dead_keys, dead_exit = _dead_region(normalized, observation, dead_ops)
    # a writer only on dead paths never writes: its conditions are not needed
    conditional = {key: pairs for key, pairs in uncertain_conditions.items()
                   if pairs is not None and key.split("~", 1)[0] not in dead_keys}
    uncertain = {key for key in uncertain_conditions
                 if key not in conditional and key.split("~", 1)[0] not in dead_keys}
    writer_conditions = frozenset().union(*conditional.values()) if conditional else frozenset()
    tracer = _CopyTracer(normalized, observation, context, operation_of, conditions_of)
    crossed = _exit_crossings(normalized, observation, context, _preserved_stack_pointers, uncertain,
                              writer_conditions, dead_keys)
    inner_calls = crossed.pop("inner_calls", ())
    crossing_labels = crossed.pop("label_universe")

    exits = []
    nodes = ssa.state_nodes
    dead_exits = []
    for state in ssa.observed_terminal_states:
        if dead_exit(state.block_key):
            dead_exits.append(state.block_key)
            continue
        runs = []
        for node in _state_runs(nodes, state.root_node_id):
            for span in _object_spans(atoms, node.start_atom, node.stop_atom):
                runs.append(_classify(span, node.definition_ids, definitions, definition_slice,
                                      crossed.get((state.block_key, span.object_id), {}), uncertain,
                                      tracer, crossing_labels))
        exits.append(ExitSummary(state.block_key, tuple(runs)))
    writer_objects = sorted(
        {(item.operation_key, item.span.object_id) for item in definitions
         if item.operation_key is not None},
        key=lambda row: (row[0], row[1].kind.value, row[1].space_key),
    )
    exits = _pointer_values(normalized, observation, exits, tracer)
    exits = _offset_values(normalized, observation, exits)
    exits = _constant_values(normalized, observation, exits)
    # unknown-address writers (conditional ones are ordinary writes, above)
    # leave every root incomplete
    unconditional_writers = bool(crossed.get("unknown_writers", ()))
    # the stack pointer's delta is a claim like any other: it holds with the
    # writer conditions, which a caller decides (or drops every claim)
    register_deltas = _register_deltas(normalized, observation, exits)
    if writer_conditions:
        exits = [ExitSummary(item.block_key, tuple(
            run if run.kind in (SummaryKind.IDENTITY, SummaryKind.UNKNOWN)
            or run.span.object_id.kind is StorageObjectKind.FUNCTION_UNIQUE
            else replace(run, conditions=tuple(sorted(
                set(run.conditions) | writer_conditions,
                key=lambda pair: (pair[0].canonical_key, pair[1].canonical_key))))
            for run in item.runs)) for item in exits]
    demands = []
    for root in sink_roots:
        label, root_nodes, complete = root[:3]
        sources, debts, origins, conditions = set(), set(), set(), set(root[3] if len(root) > 3 else ())
        facts = [0, 0, 0, 0, 0]
        for node in root_nodes:
            for part, found in enumerate(closure.of(node)):
                facts[part] |= found
        found_sources, _, found_debts, found_origins, found_conditions = closure.decode(facts)
        sources |= set(found_sources)
        debts |= set(found_debts)
        origins |= set(found_origins)
        conditions |= set(found_conditions)
        conditions |= writer_conditions
        demands.append(SinkDemand(
            label, tuple(sorted(sources, key=lambda item: item.canonical_key)), tuple(sorted(debts)),
            tuple(sorted(origins)),
            # like the engine's local completeness: any unknown-address write in
            # the function leaves every root incomplete
            bool(complete) and not debts and not unconditional_writers,
            tuple(sorted(conditions, key=lambda pair: (pair[0].canonical_key, pair[1].canonical_key))),
        ))
    limit("summary_runs", sum(len(item.runs) for item in exits))
    return FunctionSummary(
        FUNCTION_SUMMARY_VERSION, tuple(exits), tuple(sorted(crossed.get("unknown_writers", ()))),
        tuple(writer_objects),
        tuple(key for key in _tail_exits(normalized, observation, noreturn_jumps) if not dead_exit(key)),
        inner_calls, tuple(demands),
        register_deltas,
        tuple(sorted(dead_exits)),
        tuple(sorted(writer_conditions, key=lambda pair: (pair[0].canonical_key, pair[1].canonical_key))),
        stack_values_out(normalized, observation),
        indexed_relations(normalized, observation, conditions_of),
    )


def _register_deltas(normalized, observation, exits) -> tuple:
    """((offset, size), c) for pointer-sized register runs equal to their own
    entry value + c at every exit (UNKNOWN runs -- e.g. crossing a call that
    may not restore them -- prove nothing; an exit not writing the bytes: 0)."""
    from .relative_memory import register_value_deltas

    candidates: dict = {}
    requests = set()
    for exit_summary in exits:
        for run in exit_summary.runs:
            # the evaluator follows definitions only: a value read through debt
            # (e.g. the stack pointer after a call not proven to restore it)
            # proves nothing
            if run.span.object_id.kind is StorageObjectKind.REGISTER_FILE and run.span.size in (4, 8) \
                    and run.kind is not SummaryKind.UNKNOWN and run.definitions \
                    and not run.debts and not run.conditions:
                candidates.setdefault((run.span.start, run.span.size), []).append(run)
                requests.update((definition, run.span) for definition in run.definitions)
    tails = _composed_tail_deltas(normalized, observation)
    for deltas_of_tail in tails.values():  # a thunk need not write the stack pointer itself
        for key in deltas_of_tail:
            candidates.setdefault(key, [])
    if not candidates:
        return ()
    values = register_value_deltas(normalized, observation, sorted(requests, key=repr))
    found = []
    for (start, size), runs in sorted(candidates.items()):
        deltas = set()
        for exit_summary in exits:
            extra = 0
            if exit_summary.block_key in tails:
                extra = tails[exit_summary.block_key].get((start, size), 0)
                if extra is None:
                    deltas.add(None)  # the target's stack pointer change is unknown
                    continue
            overlapping = [run for run in exit_summary.runs
                           if run.span.object_id.kind is StorageObjectKind.REGISTER_FILE
                           and run.span.start < start + size and start < run.span.end]
            if not overlapping:
                deltas.add(extra)  # not written on this exit
                continue
            if len(overlapping) != 1 or (overlapping[0].span.start, overlapping[0].span.size) != (start, size) \
                    or overlapping[0].kind is SummaryKind.UNKNOWN or overlapping[0].debts \
                    or overlapping[0].conditions:
                deltas.add(None)
                continue
            run = overlapping[0]
            deltas.update(
                None if values.get((definition, run.span)) is None else values[(definition, run.span)] + extra
                for definition in run.definitions
            )
        if len(deltas) == 1 and None not in deltas:
            found.append(((start, size), deltas.pop()))
    return tuple(found)


def _tail_exits(normalized, observation, noreturn_jumps=frozenset()) -> tuple[str, ...]:
    """Blocks leaving other than by RETURN, except tail jumps composed with the
    target's summary (``ProvenCallEffect.tail_stack``) and blocks with a local
    successor ending in a jump to a function that never returns
    (``noreturn_jumps``: that jump was their only way out)."""
    from .call_seeds import _operation_key
    from .pcode_blocks import build_pcode_block_graph

    composed = {key for key, effect in normalized.proven_call_effects if effect.tail_stack}
    graph = build_pcode_block_graph(observation, normalized.scopes.function.entry)
    instructions = {row.address: row for row in observation.instructions}
    found = []
    for block in graph.blocks:
        if not block.exits:
            continue
        row = instructions[block.instruction]
        if block.stop == 0:   # an instruction without p-code falling out of the function
            found.append(block.key)
            continue
        last = row.operations[block.stop - 1]
        last_key = _operation_key(row.address, block.stop - 1, last.opcode)
        if last_key in noreturn_jumps and block.successors:
            continue
        if last.opcode != "RETURN" and last_key not in composed:
            found.append(block.key)
    return tuple(sorted(found))


def _composed_tail_deltas(normalized, observation) -> dict:
    """Terminal block key -> {(offset, size): c} of its composed tail jump."""
    from .call_seeds import _operation_key
    from .pcode_blocks import build_pcode_block_graph

    composed = {key: effect for key, effect in normalized.proven_call_effects if effect.tail_stack}
    if not composed:
        return {}
    graph = build_pcode_block_graph(observation, normalized.scopes.function.entry)
    instructions = {row.address: row for row in observation.instructions}
    found = {}
    for block in graph.blocks:
        if not block.exits or block.stop == 0:
            continue
        row = instructions[block.instruction]
        effect = composed.get(_operation_key(row.address, block.stop - 1, row.operations[block.stop - 1].opcode))
        if effect is not None:
            found[block.key] = {(span.start, span.size): effect.tail_stack_delta for span in effect.tail_stack}
    return found


def _state_runs(nodes, root):
    """The runs of one serialized terminal state, ordered by atom."""
    found, pending = [], [root] if root is not None else []
    while pending:
        step()   # (budget: docs 25.30 K1c)
        node = nodes[pending.pop()]
        found.append(node)
        pending.extend(item for item in (node.left_node_id, node.right_node_id) if item is not None)
    return sorted(found, key=lambda node: node.start_atom)


class _LazySources:
    """A debt node's virtual writer sources, decoded on each iteration
    (ascending node id, as the sorted edge scan listed them)."""

    __slots__ = ("graph", "node")

    def __init__(self, graph, node) -> None:
        self.graph = graph
        self.node = node

    def __iter__(self):
        return iter(self.graph.virtual_sources(self.node))


class _AncestorClosure:
    """Per node, the union over its data ancestors (and itself) of: entry
    source spans (spans of OBSERVED_INPUT -> node edges), operations reading
    entry memory (directly or through MEMORY_JOINs), and MEMORY_DEBT labels.
    Control-dependence edges are not followed (data-only, like the default
    backward query). Strongly connected components share one value."""

    def __init__(self, graph, operation_of, origin_labels=None, conditions_of=None) -> None:
        from .graph import CONTROL_DEPENDENCE_EDGE

        self.graph = graph
        self.operation_of = operation_of
        self.predecessors: dict[int, list[int]] = {}
        own_sources: dict[int, set] = {}
        carriers: set[int] = set()
        for source, target, record in graph.physical_weighted_edges():
            if record.kind == CONTROL_DEPENDENCE_EDGE:
                continue
            self.predecessors.setdefault(target, []).append(source)
            if record.span is not None and graph.node(source).kind is NodeKind.OBSERVED_INPUT:
                own_sources.setdefault(target, set()).add(record.span)
                if record.span.object_id.kind in _MEMORY_KINDS:
                    carriers.add(source)
        # the virtual writer edges (docs 25.31 B2-b; no span, never control):
        # a debt's writers are read lazily, not expanded and kept; the dict
        # keeps the order the sorted edge scan gave it -- a target first
        # appears at its smallest source, ties by target -- since the JOIN
        # rounds below iterate it (their step() count depends on the order)
        debts = graph.virtual_debts()
        if debts:
            first = {target: sources[0] for target, sources in self.predecessors.items()}
            entries = dict(self.predecessors)
            for debt in debts:
                writers = graph.virtual_sources(debt)
                physical = entries.get(debt)
                if physical is None:
                    entries[debt] = _LazySources(graph, debt)
                    first[debt] = writers[0]
                else:   # (no physical edge enters a may-alias debt today; kept exact anyway)
                    entries[debt] = sorted(physical + writers)
                    first[debt] = min(first[debt], writers[0])
            self.predecessors = {target: entries[target]
                                 for target in sorted(first, key=lambda node: (first[node], node))}
        changed = True
        while changed:  # JOINs over entry memory carry it too
            step()   # (budget: docs 25.30 K1c)
            changed = False
            for node, sources in self.predecessors.items():
                if node not in carriers and graph.node(node).kind is NodeKind.MEMORY_JOIN \
                        and any(item in carriers for item in sources):
                    carriers.add(node)
                    changed = True
        self.own = {}
        for node in range(graph.node_count):
            if not graph.has_node(node):
                continue
            record = graph.node(node)
            readers = frozenset(
                (operation_of[node],)
            ) if node in operation_of and any(
                item in carriers for item in self.predecessors.get(node, ())
            ) else frozenset()
            debts = frozenset((record.label,)) if record.kind is NodeKind.MEMORY_DEBT \
                and record.label != _SUMMARY_TRANSPARENT else frozenset()
            conditions = (conditions_of or {}).get(node)
            if debts and conditions:  # a may-alias debt between two exact spans: conditional
                debts = frozenset()
            else:
                conditions = frozenset()
            origins = frozenset((origin_labels or {}).get(node, ()))
            self.own[node] = (frozenset(own_sources.get(node, ())), readers, debts, origins, conditions)
            if conditions:
                # a conditional may-alias debt is reached, not passed: with its
                # conditions holding its candidate writers did not write the
                # read bytes (their values do not flow); with one failing the
                # caller drops the call (``writer_conditions``, run conditions)
                self.predecessors[node] = []
        # the facts as int bitsets over five universes -- entry source spans,
        # entry-memory readers, debt labels, origins, alias-condition pairs --
        # built from the own facts, the only facts a value can hold (docs 25.31
        # B2-d1; were five frozensets per component); equal tuples interned
        keys = (lambda span: span.canonical_key, None, None, None,
                lambda pair: (pair[0].canonical_key, pair[1].canonical_key))
        self.universes = tuple(
            LabelUniverse((fact for own in self.own.values() for fact in own[part]), key=keys[part])
            for part in range(5))
        self.interned: dict = {}
        for node, own in self.own.items():
            facts = tuple(universe.mask(part) for universe, part in zip(self.universes, own))
            self.own[node] = self.interned.setdefault(facts, facts)
        self.value: dict[int, tuple] = {}
        self.members = 0   # set memberships materialized (structural limit "fact_members")

    def of(self, node: int):
        """The node's facts: five int bitsets (``decode`` turns an OR of such
        tuples into the five label lists)."""
        if node not in self.value:
            self._solve(node)
        return self.value[node]

    def decode(self, facts) -> tuple:
        return tuple(universe.decode(part) for universe, part in zip(self.universes, facts))

    def _solve(self, root: int) -> None:
        """Iterative Tarjan over predecessor edges: components are finished
        after all their ancestors, so values are unions of finished parts."""
        index: dict[int, int] = {}
        low: dict[int, int] = {}
        on_stack: set[int] = set()
        stack: list[int] = []
        counter = 0
        work = [(root, iter(self.predecessors.get(root, ())))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, children = work[-1]
            advanced = False
            for child in children:
                if child in self.value:
                    continue
                if child not in index:
                    index[child] = low[child] = counter
                    counter += 1
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, iter(self.predecessors.get(child, ()))))
                    advanced = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index[child])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                component = []
                while True:
                    item = stack.pop()
                    on_stack.discard(item)
                    component.append(item)
                    if item == node:
                        break
                members = set(component)
                parts = [0, 0, 0, 0, 0]
                empty = (0,) * 5
                for item in component:
                    for part, own in enumerate(self.own.get(item, empty)):
                        parts[part] |= own
                    for parent_node in self.predecessors.get(item, ()):
                        if parent_node in members:
                            continue
                        for part, found in enumerate(self.value[parent_node]):
                            parts[part] |= found
                value = tuple(parts)
                value = self.interned.setdefault(value, value)
                members = sum(part.bit_count() for part in value)
                self.members += members
                limit("fact_members", self.members)
                phase_count("fact_members", members, "summarize")
                for item in component:
                    self.value[item] = value


def _operation_nodes(graph) -> dict:
    """OPERATION node -> its operation key."""
    operation_of = {}
    for node in range(graph.node_count):
        if graph.has_node(node):
            record = graph.node(node)
            if record.kind is NodeKind.OPERATION and record.key.startswith("op:"):
                operation_of[node] = record.key[3:]
    return operation_of


@measured("uncertain_writers")
def uncertain_writers_of(normalized, observation) -> dict:
    """Write keys whose address rests on a read with debt -> the alias
    conditions under which they land on their static object (None: they may
    land anywhere). ``normalize`` feeds them back to ``may_alias``
    (``uncertain_writers``) until this no longer grows."""
    return _uncertain_address_writers(
        normalized, observation, normalized.scopes.resolution_context, _operation_nodes(normalized.dependencies),
        _alias_conditions(normalized))


def _alias_conditions(normalized) -> dict:
    """may-alias debt node -> frozenset of (read span, write span) pairs when
    the read has an exact address and every candidate writer writes exact
    spans (the debt holds only if some pair overlaps); other debt nodes absent.
    An unconditional uncertain-address writer (``MayAliasRead.uncertain``)
    makes the debt unconditional; conditional ones have nodes of their own
    (``NormalizedFunction.uncertain_nodes``, not here)."""
    from .memory_contracts import MemoryDefinitionKind as Kind

    spans_of: dict = {}
    for definition in normalized.memory_ssa.definitions:
        if definition.kind is Kind.DATA_WRITE and definition.operation_key is not None \
                and definition.span.object_id.kind in _MEMORY_KINDS:
            spans_of.setdefault(definition.operation_key, set()).add(definition.span)
    unknown = {
        effect.operation_key for effect in normalized.effects
        if effect.memory_write is not None or effect.unresolved_writes
    }
    uncertain = dict(getattr(normalized, "uncertain_writers", ()))
    graph = normalized.dependencies
    found = {}
    for row, node in zip(normalized.may_alias_reads, normalized.may_alias_nodes):
        if graph.node(node).label == _SUMMARY_TRANSPARENT:
            continue
        plain = row.writers if row.plain is None else row.plain
        if row.unknown_address or any(writer in unknown or writer not in spans_of for writer in plain) \
                or any(uncertain.get(writer) is None for writer in row.uncertain):
            continue
        found[node] = frozenset(
            (read, write) for read in row.spans for writer in plain for write in spans_of[writer]
        )
    # summarized runs holding only under pairs this function cannot decide
    found.update(dict(getattr(normalized, "open_nodes", ())))
    phase_count("alias_condition_pairs", sum(map(len, found.values())))
    return found


def _address_slice(graph, inputs, conditions_of) -> list:
    """Data nodes reaching an address operand. A conditional may-alias debt
    (``_alias_conditions``) is reached but not passed: with its conditions
    holding, its candidate writers did not write the read bytes, so their
    values do not shape the address; with one failing, the caller drops the
    whole call (``writer_conditions``)."""
    from .graph import CONTROL_DEPENDENCE_EDGE

    pending, seen = list(inputs), set()
    while pending:
        step()   # (budget: docs 25.30 K1c)
        node = pending.pop()
        if node in seen:
            continue
        seen.add(node)
        if node in conditions_of:
            continue
        pending.extend(
            int(source) for source, _, record in graph.in_edges(node)
            if record.kind != CONTROL_DEPENDENCE_EDGE
        )
    phase_count("address_slices", 1)   # (K2 sizes: one DFS per store per round, docs 25.31)
    phase_count("address_slice_visits", len(seen))
    return sorted(seen)


def _uncertain_address_writers(normalized, observation, context, operation_of, conditions_of=None) -> dict:
    """Memory STOREs whose address operand depends on a read with debt ->
    the alias conditions that debt reduces to (None: unconditional)."""
    from .normalize import _storage_ref
    from .storage import _resolve_validated_storage

    graph = normalized.dependencies
    node_of = {key: node for node, key in operation_of.items()}
    # conditional uncertain-writer debts count here with their writers' conditions
    conditions_of = {**(conditions_of or {}), **dict(getattr(normalized, "uncertain_nodes", ()))}
    stores = {}
    for instruction in observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            if operation.opcode == "STORE" and len(operation.inputs) == 3:
                key = f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}:{ordinal}:STORE"
                stores[key] = operation.inputs[1]
    found: dict = {}

    def add(key, conditions):
        if conditions is None or (key in found and found[key] is None):
            found[key] = None
        else:
            found[key] = found.get(key, frozenset()) | conditions

    def check(key, inputs):
        reachable = _address_slice(graph, inputs, conditions_of or {}) if inputs else ()
        debts = [item for item in reachable if graph.node(item).kind is NodeKind.MEMORY_DEBT
                 and graph.node(item).label in _ADDRESS_UNCERTAIN]
        if debts:
            conditions = frozenset()
            for item in debts:
                pairs = (conditions_of or {}).get(item)
                if pairs is None:
                    conditions = None
                    break
                conditions |= pairs
            add(key, conditions)

    # call-clobber debts sit on the reading operation without a span: the
    # row's spans say which of its register inputs a call may have changed
    clobbers: dict = {}
    for row, debt in zip(normalized.call_clobber_reads, normalized.call_clobber_nodes):
        clobbers.setdefault(row.operation_key, []).append((row.spans, debt))

    def operand_inputs(node, varnode):
        resolved = _resolve_validated_storage(_storage_ref(varnode), context)
        if type(resolved) is not ResolvedStorage:
            return None
        return [
            source for source, _, record in graph.in_edges(node)
            if record.span is not None and record.span.overlaps(resolved.span)
        ] + [
            debt for spans, debt in clobbers.get(operation_of.get(node), ())
            if any(span.overlaps(resolved.span) for span in spans)
        ]

    # call effect rows and rep element rows writing memory: their address is
    # an anchor -- a register read by their evaluation operation, or a
    # pointer slot read by a row (("mem", row key))
    anchors = {row: (evaluation, anchor) for row, evaluation, anchor in getattr(normalized, "call_anchors", ())}
    memory_writers = set()
    for definition in normalized.memory_ssa.definitions:
        key = definition.operation_key
        if key is None or definition.span.object_id.kind not in _MEMORY_KINDS:
            continue
        memory_writers.add(key)
        if key not in stores:
            continue
        address = stores[key]
        node = node_of.get(key)
        if node is None or address.kind.name == "CONSTANT":
            continue
        inputs = operand_inputs(node, address)
        if inputs is None:
            add(key, None)
            continue
        check(key, inputs)
    for key in sorted(memory_writers & set(anchors)):
        evaluation, anchor = anchors[key]
        def operand_at(evaluation, varnode):
            node = node_of.get(evaluation)
            return None if node is None else operand_inputs(node, varnode)

        inputs = _anchor_inputs(evaluation, anchor, operand_at, node_of.get)
        if inputs is None:
            add(key, None)
            continue
        check(key, inputs)
    return found


def _anchor_inputs(evaluation, reference, operand_inputs, node_of):
    """Address dependencies at one snapshot; a tuple is not always a load."""
    step()
    if type(reference) is not tuple:
        return operand_inputs(evaluation, reference)
    if len(reference) == 2 and reference[0] == "mem":
        node = node_of(reference[1])
        return None if node is None else [node]
    if len(reference) == 7 and reference[0] == "indexed":
        base = _anchor_inputs(evaluation, reference[1], operand_inputs, node_of)
        index = _anchor_inputs(evaluation, reference[2], operand_inputs, node_of)
        return None if base is None or index is None else list(dict.fromkeys((*base, *index)))
    return None


class _CopyTracer:
    """Follows a definition's value back through COPY, LOAD and STORE (same
    size, no debt on the loads, single reaching definitions) to an ENTRY
    definition: ``trace(definition, span)`` is the entry span the value of
    ``span`` was copied from, or None."""

    def __init__(self, normalized, observation, context, operation_of, conditional_debts=None) -> None:
        from .normalize import _storage_ref
        from .storage import _resolve_validated_storage

        self._resolve = lambda varnode: _resolve_validated_storage(_storage_ref(varnode), context)
        ssa = normalized.memory_ssa
        self.definitions = ssa.definitions
        keys = [action.operation_key for action in ssa.actions]
        self.reads: dict[str, list] = {}
        for read in ssa.reads:
            self.reads.setdefault(keys[read.action_id], []).append(read)
        self.operations = {
            f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:{operation.opcode}": operation
            for row in observation.instructions for ordinal, operation in enumerate(row.operations)
        }
        self.joins = {row.join_definition_id: row.source_definition_ids for row in ssa.joins}
        graph = normalized.dependencies
        node_of = {key: node for node, key in operation_of.items()}
        self.indebted = {
            key for key, node in node_of.items()
            if any(graph.node(item).kind is NodeKind.MEMORY_DEBT and graph.node(item).label != _SUMMARY_TRANSPARENT
                   for item in graph.predecessors(node))
        }
        # for ``origin``: debts other than conditional may-alias ones (S3 pairs
        # the run carries in its conditions and a caller decides)
        conditional = set(conditional_debts or ())
        self.hard_indebted = {
            key for key, node in node_of.items()
            if any(graph.node(item).kind is NodeKind.MEMORY_DEBT and item not in conditional
                   and graph.node(item).label != _SUMMARY_TRANSPARENT
                   for item in graph.predecessors(node))
        }

    def origin(self, definition_id: int, span: ByteSpan, depth: int = 0):
        """Where the value of ``span`` comes from, through exact copies:
        ("entry", entry span), ("row", call effect row key), ("join", the
        distinct origins of a join's sources) or None."""
        if depth > 64:
            return None
        definition = self.definitions[definition_id]
        if not definition.span.contains(span):
            return None
        if definition.kind is MemoryDefinitionKind.ENTRY:
            return ("entry", span)  # the entry value of these bytes (contained, checked above)
        if definition.kind is MemoryDefinitionKind.JOIN:
            found = {self.origin(source, span, depth + 1) for source in self.joins.get(definition_id, ())}
            if None in found or not found:
                return None
            return found.pop() if len(found) == 1 else ("join", frozenset(found))
        key = definition.operation_key
        if definition.kind is not MemoryDefinitionKind.DATA_WRITE or key is None or key in self.hard_indebted:
            return None
        if "~" in key and key not in self.operations:  # a call effect row
            return ("row", key) if definition.span == span else None
        operation = self.operations.get(key)
        if operation is None:
            return None
        if operation.opcode == "COPY" and len(operation.inputs) == 1:
            value = operation.inputs[0]
        elif operation.opcode == "STORE" and len(operation.inputs) == 3:
            value = operation.inputs[2]
        elif operation.opcode == "LOAD" and operation.output is not None:
            value = None
        else:
            return None
        if value is not None:
            if value.byte_size != definition.span.size or definition.span != span:
                return None
            resolved = self._resolve(value)
            if type(resolved) is not ResolvedStorage:
                return None
            source = resolved.span
        else:
            memory = [read.span for read in self.reads.get(key, ())
                      if read.span.object_id.kind in _MEMORY_KINDS and read.span.size == definition.span.size]
            if len(memory) != 1 or definition.span != span:
                return None
            source = memory[0]
        return self._read_origin(key, source, depth)

    def _read_origin(self, key, source, depth):
        for read in self.reads.get(key, ()):
            if read.span != source:
                continue
            if len(read.fragments) == 1 and read.fragments[0].span == source \
                    and len(read.fragments[0].definition_ids) == 1:
                return self.origin(read.fragments[0].definition_ids[0], source, depth + 1)
        return None

    def load_origin(self, reader: str, size: int):
        """The origin of the one memory read of ``size`` bytes row ``reader``
        makes (a call's pointer-slot load, ``normalize._proven_call_rows``)."""
        if reader in self.hard_indebted:
            return None
        memory = [read.span for read in self.reads.get(reader, ())
                  if read.span.object_id.kind in _MEMORY_KINDS and read.span.size == size]
        if len(memory) != 1:
            return None
        return self._read_origin(reader, memory[0], 0)

    def argument_origin(self, reader: str, argument):
        """The origin of register ``argument`` as read by row ``reader``."""
        if reader in self.hard_indebted:
            return None
        resolved = self._resolve(argument)
        if type(resolved) is not ResolvedStorage:
            return None
        return self._read_origin(reader, resolved.span, 0)

    def trace(self, definition_id: int, span: ByteSpan, depth: int = 0):
        if depth > 64:
            return None
        definition = self.definitions[definition_id]
        if definition.kind is MemoryDefinitionKind.ENTRY:
            return span if definition.span.contains(span) else None
        key = definition.operation_key
        operation = self.operations.get(key)
        if definition.kind is not MemoryDefinitionKind.DATA_WRITE or operation is None                 or key in self.indebted or not definition.span.contains(span):
            return None
        offset = span.start - definition.span.start
        if operation.opcode == "COPY" and len(operation.inputs) == 1:
            value = operation.inputs[0]
        elif operation.opcode == "STORE" and len(operation.inputs) == 3:
            value = operation.inputs[2]
        elif operation.opcode == "LOAD" and operation.output is not None:
            value = None
        else:
            return None
        if value is not None:
            if value.byte_size != definition.span.size:
                return None
            resolved = self._resolve(value)
            if type(resolved) is not ResolvedStorage:
                return None
            source = resolved.span
        else:
            memory = [read.span for read in self.reads.get(key, ())
                      if read.span.object_id.kind in _MEMORY_KINDS
                      and read.span.size == definition.span.size]
            if len(memory) != 1:
                return None
            source = memory[0]
        requested = ByteSpan(source.object_id, source.start + offset, span.size)
        for read in self.reads.get(key, ()):
            if read.span != source:
                continue
            for fragment in read.fragments:
                if fragment.span.contains(requested) and len(fragment.definition_ids) == 1:
                    return self.trace(fragment.definition_ids[0], requested, depth + 1)
        return None


def _dead_region(normalized, observation, dead_ops):
    """(operation keys never executed on a path to an exit, predicate on
    terminal block keys): paths are cut at ``dead_ops`` and at calls proven
    never to return; what the entry reaches only through a cut is dead, the
    cut operation and the rest of its block included."""
    from .call_seeds import _operation_key
    from .pcode_blocks import build_pcode_block_graph, instruction_key

    cuts = set(dead_ops) | {key for key, effect in normalized.proven_call_effects
                            if getattr(effect, "noreturn", False)}
    if not cuts:
        return frozenset(), lambda block_key: False
    graph = build_pcode_block_graph(observation, normalized.scopes.function.entry)
    rows = {row.address: row for row in observation.instructions}
    blocks = {block.key: block for block in graph.blocks}
    cut_at = {}
    for block in graph.blocks:
        row = rows[block.instruction]
        for ordinal in range(block.start, block.stop):
            if _operation_key(row.address, ordinal, row.operations[ordinal].opcode) in cuts:
                cut_at[block.key] = ordinal
                break
    reached, pending = set(), [graph.entry]
    while pending:
        step()   # (budget: docs 25.30 K1c)
        key = pending.pop()
        if key in reached or key not in blocks:
            continue
        reached.add(key)
        if key not in cut_at:
            pending.extend(blocks[key].successors)
    dead_points = set()
    for block in graph.blocks:
        start = block.start if block.key not in reached else cut_at.get(block.key)
        if start is None:
            continue
        dead_points.update((block.instruction, ordinal) for ordinal in range(start, block.stop))
    dead_keys = frozenset(
        _operation_key(row.address, ordinal, operation.opcode)
        for row in observation.instructions for ordinal, operation in enumerate(row.operations)
        if (row.address, ordinal) in dead_points
    )
    by_key = {instruction_key(row.address): row for row in observation.instructions}

    def dead_exit(block_key: str) -> bool:
        base, _, start = block_key.partition("#")
        row = by_key.get(base)
        if row is None or not row.operations:
            return False
        block = blocks.get(block_key)
        last = block.stop - 1 if block is not None else len(row.operations) - 1
        return (row.address, last) in dead_points

    return dead_keys, dead_exit


def _pointer_size(normalized) -> int | None:
    from ._scope_contracts import AddressSpaceClassV2, classify_address_space_v2

    sizes = {
        row.address_size_bits // 8 for row in normalized.scopes.program.evidence.address_spaces
        if row.classification_revision == 2 and row.addressable_unit_bytes == 1
        and classify_address_space_v2(row) is AddressSpaceClassV2.ADDRESS
    }
    return sizes.pop() if len(sizes) == 1 else None


def _constant_values(normalized, observation, exits) -> list:
    """Attach only finished-SSA, full-run, unanimously proven scalar values.

    Conditional alias claims keep their conditions; hard debt and crossings
    never become a literal. The projector admits only image-independent bits.
    """
    from . import relative_memory

    project = getattr(relative_memory, "definition_constants", None)
    if project is None:
        return exits
    requests = {
        (definition, run.span)
        for item in exits for run in item.runs
        if run.kind is SummaryKind.COMPUTED and not run.debts and not run.crossed
        and 1 <= run.span.size <= 16
        for definition in run.definitions
    }
    if not requests:
        return exits
    values = project(normalized, observation, requests)
    if values is None:
        return exits
    result = []
    for item in exits:
        runs = []
        for run in item.runs:
            literal = None
            if run.kind is SummaryKind.COMPUTED and not run.debts and not run.crossed and run.definitions:
                found = tuple(values.get((definition, run.span)) for definition in run.definitions)
                first = found[0]
                if type(first) is ExactConstant and first.byte_size == run.span.size \
                        and all(type(value) is ExactConstant and value == first for value in found):
                    literal = first
            runs.append(replace(run, literal=literal) if literal is not None else run)
        result.append(ExitSummary(item.block_key, tuple(runs)))
    return result


def _new_frame(normalized, observation):
    """(the stack object, its bias) -- the new frame lies below the bias --
    or None when the stack pointer is not identified."""
    from .may_alias import _stack_pointer, _unit_stub

    scopes = getattr(normalized, "scopes", None)
    if scopes is None:
        return None
    found = _stack_pointer(_unit_stub(scopes), observation, scopes.resolution_context,
                           scopes.program.evidence.address_spaces)
    return None if found is None else (found[0], found[1])


def _pointer_values(normalized, observation, exits, tracer) -> list:
    """Attach ``SummaryRun.value`` to pointer-width COMPUTED runs whose every
    terminal definition traces (``_CopyTracer.origin``: exact copies, no debt,
    single reaching definitions, equal at joins) to one origin: an entry span
    (a copy of it), a fresh call result or a callee run already proven
    nonstack (``("nonstack",)``), or a same-object call result (realloc) of a
    traced entry span (null is fresh) or of a nonstack value."""
    from dataclasses import replace as _replace

    size = _pointer_size(normalized)
    if size is None:
        return exits
    fresh_rows = frozenset(getattr(normalized, "fresh_rows", ()))
    same_rows = {row: (reader, argument) for row, reader, argument in getattr(normalized, "same_object_rows", ())}
    frame = _new_frame(normalized, observation)
    pointer_rows = dict(getattr(normalized, "pointer_rows", ()))
    proven = dict(normalized.proven_call_effects)
    # allocator windows (docs 25.79 3b): none from a function resizing any
    # block -- a declared or lowered same-object row (an alias of a resized
    # block would keep the old size)
    resizes = bool(same_rows) or any(effect.same_object_registers for effect in proven.values()) or any(
        row[0] in ("reg", "mem") and row[3] for row in pointer_rows.values())
    windows = {} if resizes else {
        row: (size, label is None, tuple(sorted({"allocator-results-are-fresh", *((label,) if label else ())})))
        for row, size, label in getattr(normalized, "fresh_window_rows", ())}
    if not resizes:
        for row, found in pointer_rows.items():
            if found[0] == "nonstack" and len(found) == 3:      # (result_nonstack, docs 25.75)
                windows.setdefault(row, (found[1], False, (found[2],)))
            elif found[0] == "nonstack" and len(found) == 4:    # (a callee's exported window)
                windows.setdefault(row, found[1:])

    def nested_same(row):
        """A callee run's ("same_reg" / "same_mem") value composed with this
        function's value of that register / memory at the call: the origin
        of what the staging row / pointer-slot load row read, or None. Any
        hard debt on the row, its staging row or any pointer-slot load of the
        call (a two-level load reads where an earlier load pointed) refuses."""
        found = pointer_rows.get(row)
        if found is None or found[0] not in ("reg", "mem") or row in tracer.hard_indebted:
            return None, False
        call = row.rsplit("~", 1)[0]
        if any(key.startswith(f"{call}~ld") for key in tracer.hard_indebted):
            return None, False
        if found[0] == "reg":
            _, reader, argument, flag, _ = found
            return tracer.argument_origin(reader, argument), flag
        _, reader, size, flag, _ = found
        return tracer.load_origin(reader, size), flag

    def nested_nonstack(row):
        base, _, index = row.rpartition("~")
        effect = proven.get(base)
        if effect is None or not index.isdigit():
            return False
        items = (*effect.runs, *effect.memory_runs)
        if int(index) >= len(items):
            return False
        value = getattr(items[int(index)], "value", None)
        return value is not None and value[0] == "nonstack"

    def value_of(origin, active=frozenset()):
        """``active``: the call rows being composed on this path -- a row
        reached again (a loop feeding a call its own result) is no value."""
        if origin is None:
            return None
        kind, item = origin
        if kind == "join":
            # equal values stay; a kept entry value joined with a realloc of it
            # is the same object, or -- for a null entry value -- null or a new
            # block (neither a stack address): ("same", span, null is fresh)
            values = {value_of(source, active) for source in item}
            if None in values:
                return None
            if len(values) == 1:
                return values.pop()
            if all(value[0] == "nonstack" for value in values):
                return join_nonstack(values)
            spans = {value[1] for value in values if value[0] == "same"}
            if len(spans) == 1 and all(value[0] == "same" for value in values):
                return ("same", spans.pop(), True)
            return None
        if kind == "entry":
            if item.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE and (
                    frame is None or (item.object_id == frame[0] and item.start < frame[1])):
                # a never-written byte of the new frame: stale, no entry value (docs 25.80 R0;
                # no stack pointer identified: any relative object may be the stack)
                return None
            return ("same", item, False)
        if item in windows:
            return ("nonstack", *windows[item])
        if item in fresh_rows or nested_nonstack(item):
            return ("nonstack",)
        if item in active:
            return None
        active = active | {item}
        if item in same_rows:
            reader, argument = same_rows[item]
            inner = tracer.argument_origin(reader, argument)
            found = value_of(inner, active)
            if found is None:
                return None
            if found[0] == "same":
                return ("same", found[1], True)
            return found[:1] if found[0] == "nonstack" else found   # (a resized block: no window)
        inner, flag = nested_same(item)
        if inner is not None:
            # a callee's same-object value of what this function passed: the
            # same object as that value's own origin (null may be a new block
            # if either step says so)
            found = value_of(inner, active)
            if found is None:
                return None
            if found[0] == "same":
                return ("same", found[1], found[2] or flag)
            return found[:1] if found[0] == "nonstack" else found   # (a resized block: no window)
        return None

    result = []
    for exit_summary in exits:
        runs = []
        for run in exit_summary.runs:
            value = None
            # an UNKNOWN run crossed only by aliasing writes may still be taken as
            # computed by the caller (``call_summary_effects._only_exported_aliasing``)
            computed = run.kind is SummaryKind.COMPUTED or (
                run.kind is SummaryKind.UNKNOWN and not run.debts and run.crossed
                and all(label.startswith("alias:") for label in run.crossed))
            if computed and run.span.size == size and run.definitions \
                    and run.span.object_id.kind is not StorageObjectKind.FUNCTION_UNIQUE:
                origins = {tracer.origin(definition, run.span) for definition in run.definitions}
                if len(origins) == 1:
                    value = value_of(origins.pop())
                elif None not in origins:  # several reaching definitions: a join
                    value = value_of(("join", frozenset(origins)))
                if value is not None and value[0] == "nonstack" and run.kind is not SummaryKind.COMPUTED:
                    value = ("nonstack",)   # (windows on computed runs only: docs 25.79 3b)
            runs.append(_replace(run, value=value) if value is not None else run)
        result.append(ExitSummary(exit_summary.block_key, tuple(runs)))
    return result


def _offset_values(normalized, observation, exits) -> list:
    """``("offset", entry register span, c)`` for pointer-width COMPUTED
    register runs no other value is stated for (docs 25.80 R1): every
    terminal definition evaluates to that one entry register's value + c --
    no debt, no condition, the same (span, c) for all of them."""
    from dataclasses import replace as _replace

    from .relative_memory import register_value_offsets

    size = _pointer_size(normalized)
    if size is None:
        return exits
    wanted = {}
    for exit_summary in exits:
        for run in exit_summary.runs:
            sources = tuple(span for span in run.sources
                            if span.object_id.kind is StorageObjectKind.REGISTER_FILE and span.size == size)
            if run.value is None and run.literal is None and run.kind is SummaryKind.COMPUTED \
                    and run.span.object_id.kind is StorageObjectKind.REGISTER_FILE and run.span.size == size \
                    and run.definitions and not run.debts and not run.conditions and not run.crossed and sources:
                wanted[run] = tuple((definition, run.span, sources) for definition in run.definitions)
    if not wanted:
        return exits
    found = register_value_offsets(normalized, observation,
                                   sorted({item for items in wanted.values() for item in items}, key=repr))
    result = []
    for exit_summary in exits:
        runs = []
        for run in exit_summary.runs:
            values = {found.get(item) for item in wanted.get(run, ())}
            if len(values) == 1 and None not in values:
                span, delta = values.pop()
                run = _replace(run, value=("offset", span, delta))
            runs.append(run)
        result.append(ExitSummary(exit_summary.block_key, tuple(runs)))
    return result


def join_nonstack(values) -> tuple:
    """Nonstack values of several paths or exits as one (docs 25.79 3b): all
    windowed -- the smallest window, nullable if any is, every label; any
    windowless -- ("nonstack",)."""
    values = list(values)
    if not values or any(len(value) != 4 for value in values):
        return ("nonstack",)
    return ("nonstack", min(value[1] for value in values), any(value[2] for value in values),
            tuple(sorted({label for value in values for label in value[3]})))


def _object_spans(atoms, start: int, stop: int):
    """Split an atom range into maximal contiguous spans of one object."""
    current = None
    for index in range(start, stop):
        atom = atoms[index]
        if current is not None and current.object_id == atom.object_id and current.end == atom.start:
            current = ByteSpan(current.object_id, current.start, atom.end - current.start)
        else:
            if current is not None:
                yield current
            current = atom
    if current is not None:
        yield current


def _classify(span, definition_ids, definitions, definition_slice, crossed_by_offset, uncertain,
              tracer=None, crossing_labels=None):
    if tracer is not None and definition_ids and all(
            tracer.trace(definition_id, span) == span for definition_id in definition_ids):
        # the value is the entry value of these very bytes, copied through
        # registers and memory (e.g. a callee-saved register pushed and popped)
        definition_ids_for_identity = definition_ids
    else:
        definition_ids_for_identity = None
    sources, readers, debts, writers, origins, conditions = set(), set(), set(), set(), set(), set()
    facts = [0, 0, 0, 0, 0]   # the closure's bitsets, decoded once below
    identity = True
    for definition_id in definition_ids:
        definition = definitions[definition_id]
        if definition.kind is MemoryDefinitionKind.ENTRY:
            if not definition.span.contains(span):
                identity = False
            sources.add(span)
            continue
        identity = False
        if definition.operation_key is not None:
            writers.add(definition.operation_key)
        for part, found in enumerate(definition_slice(definition_id)):
            facts[part] |= found
    found_sources, found_readers, found_debts, found_origins, found_conditions = definition_slice.decode(facts)
    sources |= set(found_sources)
    readers |= set(found_readers)
    debts |= set(found_debts)
    origins |= set(found_origins)
    conditions |= set(found_conditions)
    crossed_bits = 0   # (``_exit_crossings``' bitsets over ``crossing_labels``)
    for offset in range(span.start, span.end):
        crossed_bits |= crossed_by_offset.get(offset, 0)
    crossings = set(crossing_labels.decode(crossed_bits)) if crossed_bits else set()
    # a write whose address is uncertain may have missed these bytes: the
    # earlier value can survive, so the content is not known
    crossings |= {f"uncertain:{writer}" for writer in writers & uncertain}
    if crossings:
        kind = SummaryKind.UNKNOWN
    elif identity or definition_ids_for_identity is not None:
        kind = SummaryKind.IDENTITY
    else:
        kind = SummaryKind.COMPUTED
    return SummaryRun(
        span, kind, tuple(sorted(definition_ids)), tuple(sorted(writers)),
        tuple(sorted(sources, key=lambda item: item.canonical_key)), tuple(sorted(readers)),
        tuple(sorted(debts)), tuple(sorted(crossings)), tuple(sorted(origins)),
        tuple(sorted(conditions, key=lambda pair: (pair[0].canonical_key, pair[1].canonical_key))),
    )


def _live_gens_at_exit(graph, events, exit_block: str) -> int:
    """Gen labels live at the end of ``exit_block``: those with a path to the
    exit that crosses no kill. Walk blocks backwards from the exit; inside a
    block read events from the end until the first kill (and stop there).
    Events carry label indices; the result is their int bitset."""
    found = 0
    seen: set[str] = set()
    pending = [exit_block]
    while pending:
        step()   # (budget: docs 25.30 K1c)
        block = pending.pop()
        if block in seen or block not in graph.pre:
            continue
        seen.add(block)
        killed = False
        for _, _, label in reversed(events.get(block, ())):
            if label is None:
                killed = True
                break
            found |= 1 << label
        if not killed:
            pending.extend(graph.predecessors[block])
    return found


def _exit_crossings(normalized, observation, context, preserved_stack_pointers, uncertain,
                    writer_conditions=frozenset(), dead_keys=frozenset()):
    """(terminal block, object) -> {offset: crossed labels at the block exit}."""
    unit = normalized.memory_unit
    assumed = {key for key, _ in normalized.assumed_call_effects}
    effects_by_block: dict[str, list] = {block.key: [] for block in unit.blocks}
    for effect in normalized.effects:
        if effect.block_key in effects_by_block:
            effects_by_block[effect.block_key].append(effect)
    graph = DominatorGraph(unit.entry_block_key, {block.key: block.predecessors for block in unit.blocks})
    preserved = preserved_stack_pointers(observation, context)
    tails = set()
    for key, effect in normalized.proven_call_effects:
        if not effect.restores_stack:
            preserved.pop(key, None)  # the call shape's stack pointer is not restored
        if effect.tail_stack:
            tails.add(key)  # a composed tail jump: its stack pointer is composed by delta
            preserved[key] = tuple(preserved.get(key, ())) + effect.tail_stack
    memory_keeping = set()
    bounds = {key: (object_id, bound) for key, object_id, bound in normalized.call_below_bounds}
    below_calls = set()
    kept = dict(normalized.kept_call_memory)  # a model's memory runs (``normalize._kept_call_memory``)
    for key, effect in normalized.proven_call_effects:  # bytes a callee summary proves kept
        preserved[key] = tuple(preserved.get(key, ())) + tuple(effect.preserved) + tuple(kept.get(key, ()))
        if effect.preserves_memory and (not effect.clobbers_below or key in bounds):
            memory_keeping.add(key)
            if effect.clobbers_below:
                below_calls.add(key)

    calls, unknown, writes = [], [], {}       # gen sources / kills
    memory_writes = []                        # (block, position, order, object, key)
    unknown_writers = set()
    for block_key, effects in effects_by_block.items():
        for position, effect in enumerate(effects):
            key = effect.operation_key
            if key.split("~", 1)[0] in dead_keys:
                continue  # never executed on a path to an exit (``_dead_region``)
            if (key.rsplit(":", 1)[-1] in _CALL_OPCODES and key not in assumed) or key in tails:
                calls.append((block_key, position, key))
            for index, evidence in enumerate(effect.writes):
                if type(evidence) is ResolvedStorage:
                    span = evidence.span
                    writes.setdefault(span.object_id, []).append(
                        (span.start, span.end, (block_key, position, 1 + index)))
                    if span.object_id.kind in _MEMORY_KINDS:
                        memory_writes.append((block_key, position, 1 + index, span.object_id, key))
                        if key in uncertain:  # may land anywhere, after its own write
                            unknown.append((block_key, position, 1 + len(effect.writes), key))
                            unknown_writers.add(key)
            if effect.memory_write is not None or effect.unresolved_writes:
                unknown.append((block_key, position, 1 + len(effect.writes), key))
                unknown_writers.add(key)

    # the crossing labels as int bitsets (docs 25.31 B2-d2; were frozensets of
    # "call:" / "alias:" / "unknown:" strings): one universe, events carry
    # indices, per-offset values are ints decoded by ``_classify``
    crossing_labels = LabelUniverse(
        [f"call:{key}" for _, _, key in calls] + [f"alias:{row[4]}" for row in memory_writes]
        + [f"unknown:{row[3]}" for row in unknown])
    call_index = {key: crossing_labels.index_of[f"call:{key}"] for _, _, key in calls}
    alias_index = {row[4]: crossing_labels.index_of[f"alias:{row[4]}"] for row in memory_writes}
    unknown_index = {row[3]: crossing_labels.index_of[f"unknown:{row[3]}"] for row in unknown}

    # the named assumption the function was normalized under (``may_alias``):
    # constant addresses never alias its stack object
    stack = None
    if normalized.assumes_globals_disjoint_from_stack:
        from .may_alias import stack_object_of
        stack = stack_object_of(normalized.scopes, observation)

    private = getattr(normalized, "private_frame_writes", frozenset())
    wild = getattr(normalized, "wild_objects", frozenset())

    def may_alias(left, right) -> bool:
        if left == right:
            return False
        if stack is not None and {left.kind, right.kind} == {StorageObjectKind.ADDRESS_SPACE,
                                                               StorageObjectKind.FUNCTION_RELATIVE}                 and stack in (left, right):
            return False
        return not (left.kind is StorageObjectKind.ADDRESS_SPACE
                    and right.kind is StorageObjectKind.ADDRESS_SPACE)

    result: dict = {
        "label_universe": crossing_labels,
        "unknown_writers": unknown_writers,
        "inner_calls": tuple(sorted(
            (key, tuple(preserved.get(key, ())), key in memory_keeping, key in below_calls)
            for _, _, key in calls
        )),
    }
    ssa = normalized.memory_ssa
    terminal_objects: dict[str, dict] = {}
    for state in ssa.observed_terminal_states:
        offsets: dict = {}
        for node in _state_runs(ssa.state_nodes, state.root_node_id):
            for atom in ssa.atomic_spans[node.start_atom:node.stop_atom]:
                offsets.setdefault(atom.object_id, set()).update(range(atom.start, atom.end))
        terminal_objects[state.block_key] = offsets

    # writer conditions: (read span, write span) -- a write of exactly that
    # span by some operation does not reach the read bytes while they hold
    spans_by_writer: dict = {}
    for effect in normalized.effects:
        for evidence in effect.writes:
            if type(evidence) is ResolvedStorage and evidence.span.object_id.kind in _MEMORY_KINDS:
                spans_by_writer.setdefault(evidence.span, set()).add(effect.operation_key)
    excused_by: dict = {}
    for read, write in writer_conditions:
        for key in spans_by_writer.get(write, ()):
            excused_by.setdefault(read.object_id, []).append((read.start, read.end, key))
    cache: dict[tuple, frozenset] = {}
    for block_key, objects in terminal_objects.items():
        for object_id, offsets in objects.items():
            if object_id.kind is StorageObjectKind.FUNCTION_UNIQUE:
                continue
            spans = writes.get(object_id, [])
            keeps = [(span.start, span.end, key) for key, kept in preserved.items()
                     for span in kept if span.object_id == object_id]
            per_offset = {}
            for offset in sorted(offsets):
                covering = frozenset(w for s, e, w in spans if s <= offset < e)
                keeping = frozenset(k for s, e, k in keeps if s <= offset < e)
                if object_id.kind in _MEMORY_KINDS:
                    keeping |= memory_keeping
                    keeping -= {key for key in below_calls
                                if bounds[key][0] == object_id and offset < bounds[key][1]}
                # writes a writer condition (read span, write span) rules out
                # on these bytes: decided by the caller with the whole summary
                excused = frozenset(key for start, end, key in excused_by.get(object_id, ())
                                    if start <= offset < end)
                signature = (object_id, covering, keeping, block_key, excused)
                value = cache.get(signature)
                if value is None:
                    events: dict[str, list] = {}
                    for call_block, position, key in calls:
                        if key not in keeping:
                            events.setdefault(call_block, []).append((position, 0, call_index[key]))
                    if object_id.kind in _MEMORY_KINDS:
                        for write_block, position, order, other, key in memory_writes:
                            # a private frame write reaches no other object but a
                            # wild one (``may_alias.private_frame_writes``)
                            if may_alias(other, object_id) and key not in excused and (
                                    (key, other) not in private or object_id in wild):
                                events.setdefault(write_block, []).append((position, order, alias_index[key]))
                        for write_block, position, order, key in unknown:
                            events.setdefault(write_block, []).append((position, order, unknown_index[key]))
                    for write_block, position, order in covering:
                        events.setdefault(write_block, []).append((position, order, None))
                    for rows in events.values():
                        rows.sort(key=lambda row: (row[0], row[1], row[2] is not None))
                    value = _live_gens_at_exit(graph, events, block_key)
                    cache[signature] = value
                    # (K2 sizes: signatures x events, docs 25.31)
                    phase_count("exit_signatures", 1)
                    phase_count("exit_events", sum(map(len, events.values())))
                if value:
                    per_offset[offset] = value
                    phase_count("exit_crossed_labels", value.bit_count())
            result[(block_key, object_id)] = per_offset
    return result


__all__ = (
    "ExitSummary", "FUNCTION_SUMMARY_VERSION", "FunctionSummary", "SinkDemand", "SummaryKind",
    "SummaryRun",
    "summarize_function",
)
