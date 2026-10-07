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
an unknown-address write.
* ``AFFINE`` -- reserved for the stack pointer (S2).

Bytes the function never touches do not appear in the terminal state; they
are untouched, i.e. preserved (an unknown-address writer is the exception:
see ``unknown_writers``).

``crossed`` is a gen/kill problem per byte (calls, aliasing writes and
unknown-address writes gen; writes covering the byte kill) solved with the
shared sparse solver at the exit of each terminal block.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ._sparse_dataflow import DominatorGraph
from .graph_contracts import NodeKind
from .memory_contracts import MemoryDefinitionKind
from .model import ResolvedStorage
from .span_geometry import ByteSpan, StorageObjectKind

FUNCTION_SUMMARY_VERSION = 1
_CALL_OPCODES = ("CALL", "CALLIND", "CALLOTHER")
_ADDRESS_UNCERTAIN = {"may_alias_read", "unresolved_memory_read", "call_clobber_read"}
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


@dataclass(frozen=True, slots=True)
class ExitSummary:
    block_key: str
    runs: tuple[SummaryRun, ...]


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


def summarize_function(normalized, observation) -> FunctionSummary:
    from .call_clobber import _preserved_stack_pointers

    context = normalized.scopes.resolution_context

    ssa = normalized.memory_ssa
    graph = normalized.dependencies
    atoms = ssa.atomic_spans
    definitions = ssa.definitions
    definition_nodes = normalized.memory_graph.definition_nodes

    observed_edges: dict[int, list] = {}
    for source, target, record in graph.weighted_edges():
        if record.span is not None and graph.node(source).kind is NodeKind.OBSERVED_INPUT:
            observed_edges.setdefault(source, []).append((target, record.span))
    operation_of = {}
    for node in range(graph.node_count):
        if graph.has_node(node):
            record = graph.node(node)
            if record.kind is NodeKind.OPERATION and record.key.startswith("op:"):
                operation_of[node] = record.key[3:]

    closure = _AncestorClosure(graph, operation_of)

    def definition_slice(definition_id: int):
        """(entry source spans, entry-memory readers, debt labels) of the
        backward data slice from one definition (same sets as
        ``BackwardSliceQuery`` + edge spans, computed for all nodes at once)."""
        return closure.of(definition_nodes[definition_id])

    uncertain = _uncertain_address_writers(normalized, observation, context, operation_of)
    crossed = _exit_crossings(normalized, observation, context, _preserved_stack_pointers, uncertain)

    exits = []
    nodes = ssa.state_nodes
    for state in ssa.observed_terminal_states:
        runs = []
        for node in _state_runs(nodes, state.root_node_id):
            for span in _object_spans(atoms, node.start_atom, node.stop_atom):
                runs.append(_classify(span, node.definition_ids, definitions, definition_slice,
                                      crossed.get((state.block_key, span.object_id), {}), uncertain))
        exits.append(ExitSummary(state.block_key, tuple(runs)))
    writer_objects = sorted(
        {(item.operation_key, item.span.object_id) for item in definitions
         if item.operation_key is not None},
        key=lambda row: (row[0], row[1].kind.value, row[1].space_key),
    )
    return FunctionSummary(
        FUNCTION_SUMMARY_VERSION, tuple(exits), tuple(sorted(crossed.get("unknown_writers", ()))),
        tuple(writer_objects), _tail_exits(normalized, observation),
    )


def _tail_exits(normalized, observation) -> tuple[str, ...]:
    from .pcode_blocks import build_pcode_block_graph

    graph = build_pcode_block_graph(observation, normalized.scopes.function.entry)
    instructions = {row.address: row for row in observation.instructions}
    found = []
    for block in graph.blocks:
        if not block.exits:
            continue
        last = instructions[block.instruction].operations[block.stop - 1]
        if last.opcode != "RETURN":
            found.append(block.key)
    return tuple(sorted(found))


def _state_runs(nodes, root):
    """The runs of one serialized terminal state, ordered by atom."""
    found, pending = [], [root] if root is not None else []
    while pending:
        node = nodes[pending.pop()]
        found.append(node)
        pending.extend(item for item in (node.left_node_id, node.right_node_id) if item is not None)
    return sorted(found, key=lambda node: node.start_atom)


class _AncestorClosure:
    """Per node, the union over its data ancestors (and itself) of: entry
    source spans (spans of OBSERVED_INPUT -> node edges), operations reading
    entry memory (directly or through MEMORY_JOINs), and MEMORY_DEBT labels.
    Control-dependence edges are not followed (data-only, like the default
    backward query). Strongly connected components share one value."""

    def __init__(self, graph, operation_of) -> None:
        from .graph import CONTROL_DEPENDENCE_EDGE

        self.graph = graph
        self.operation_of = operation_of
        self.predecessors: dict[int, list[int]] = {}
        own_sources: dict[int, set] = {}
        carriers: set[int] = set()
        for source, target, record in graph.weighted_edges():
            if record.kind == CONTROL_DEPENDENCE_EDGE:
                continue
            self.predecessors.setdefault(target, []).append(source)
            if record.span is not None and graph.node(source).kind is NodeKind.OBSERVED_INPUT:
                own_sources.setdefault(target, set()).add(record.span)
                if record.span.object_id.kind in _MEMORY_KINDS:
                    carriers.add(source)
        changed = True
        while changed:  # JOINs over entry memory carry it too
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
            debts = frozenset((record.label,)) if record.kind is NodeKind.MEMORY_DEBT else frozenset()
            self.own[node] = (frozenset(own_sources.get(node, ())), readers, debts)
        self.value: dict[int, tuple] = {}

    def of(self, node: int):
        if node not in self.value:
            self._solve(node)
        return self.value[node]

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
                sources, readers, debts = set(), set(), set()
                for item in component:
                    own = self.own.get(item, (frozenset(), frozenset(), frozenset()))
                    sources |= own[0]
                    readers |= own[1]
                    debts |= own[2]
                    for parent_node in self.predecessors.get(item, ()):
                        if parent_node in members:
                            continue
                        found = self.value[parent_node]
                        sources |= found[0]
                        readers |= found[1]
                        debts |= found[2]
                value = (frozenset(sources), frozenset(readers), frozenset(debts))
                for item in component:
                    self.value[item] = value


def _uncertain_address_writers(normalized, observation, context, operation_of) -> set[str]:
    """Memory STOREs whose address operand depends on a read with debt."""
    from .normalize import _storage_ref
    from .storage import _resolve_validated_storage

    graph = normalized.dependencies
    node_of = {key: node for node, key in operation_of.items()}
    stores = {}
    for instruction in observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            if operation.opcode == "STORE" and len(operation.inputs) == 3:
                key = f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}:{ordinal}:STORE"
                stores[key] = operation.inputs[1]
    found = set()
    for definition in normalized.memory_ssa.definitions:
        key = definition.operation_key
        if key is None or key not in stores or definition.span.object_id.kind not in _MEMORY_KINDS:
            continue
        address = stores[key]
        node = node_of.get(key)
        if node is None or address.kind.name == "CONSTANT":
            continue
        resolved = _resolve_validated_storage(_storage_ref(address), context)
        if type(resolved) is not ResolvedStorage:
            found.add(key)
            continue
        inputs = [
            source for source, _, record in graph._graph.in_edges(node)
            if record.span is not None and record.span.overlaps(resolved.span)
        ]
        reachable = graph.backward_reachable(tuple(inputs)) if inputs else ()
        if any(graph.node(item).kind is NodeKind.MEMORY_DEBT
               and graph.node(item).label in _ADDRESS_UNCERTAIN for item in reachable):
            found.add(key)
    return found


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


def _classify(span, definition_ids, definitions, definition_slice, crossed_by_offset, uncertain):
    sources, readers, debts, writers = set(), set(), set(), set()
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
        found_sources, found_readers, found_debts = definition_slice(definition_id)
        sources |= found_sources
        readers |= found_readers
        debts |= found_debts
    crossings = set()
    for offset in range(span.start, span.end):
        crossings |= crossed_by_offset.get(offset, frozenset())
    # a write whose address is uncertain may have missed these bytes: the
    # earlier value can survive, so the content is not known
    crossings |= {f"uncertain:{writer}" for writer in writers & uncertain}
    if crossings:
        kind = SummaryKind.UNKNOWN
    elif identity:
        kind = SummaryKind.IDENTITY
    else:
        kind = SummaryKind.COMPUTED
    return SummaryRun(
        span, kind, tuple(sorted(definition_ids)), tuple(sorted(writers)),
        tuple(sorted(sources, key=lambda item: item.canonical_key)), tuple(sorted(readers)),
        tuple(sorted(debts)), tuple(sorted(crossings)),
    )


def _live_gens_at_exit(graph, events, exit_block: str) -> frozenset:
    """Gen labels live at the end of ``exit_block``: those with a path to the
    exit that crosses no kill. Walk blocks backwards from the exit; inside a
    block read events from the end until the first kill (and stop there)."""
    found: set = set()
    seen: set[str] = set()
    pending = [exit_block]
    while pending:
        block = pending.pop()
        if block in seen or block not in graph.pre:
            continue
        seen.add(block)
        killed = False
        for _, _, label in reversed(events.get(block, ())):
            if label is None:
                killed = True
                break
            found.add(label)
        if not killed:
            pending.extend(graph.predecessors[block])
    return frozenset(found)


def _exit_crossings(normalized, observation, context, preserved_stack_pointers, uncertain):
    """(terminal block, object) -> {offset: crossed labels at the block exit}."""
    unit = normalized.memory_unit
    assumed = {key for key, _ in normalized.assumed_call_effects}
    effects_by_block: dict[str, list] = {block.key: [] for block in unit.blocks}
    for effect in normalized.effects:
        if effect.block_key in effects_by_block:
            effects_by_block[effect.block_key].append(effect)
    graph = DominatorGraph(unit.entry_block_key, {block.key: block.predecessors for block in unit.blocks})
    preserved = preserved_stack_pointers(observation, context)

    calls, unknown, writes = [], [], {}       # gen sources / kills
    memory_writes = []                        # (block, position, order, object, key)
    unknown_writers = set()
    for block_key, effects in effects_by_block.items():
        for position, effect in enumerate(effects):
            key = effect.operation_key
            if key.rsplit(":", 1)[-1] in _CALL_OPCODES and key not in assumed:
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

    def may_alias(left, right) -> bool:
        if left == right:
            return False
        return not (left.kind is StorageObjectKind.ADDRESS_SPACE
                    and right.kind is StorageObjectKind.ADDRESS_SPACE)

    result: dict = {"unknown_writers": unknown_writers}
    ssa = normalized.memory_ssa
    terminal_objects: dict[str, dict] = {}
    for state in ssa.observed_terminal_states:
        offsets: dict = {}
        for node in _state_runs(ssa.state_nodes, state.root_node_id):
            for atom in ssa.atomic_spans[node.start_atom:node.stop_atom]:
                offsets.setdefault(atom.object_id, set()).update(range(atom.start, atom.end))
        terminal_objects[state.block_key] = offsets

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
                signature = (object_id, covering, keeping, block_key)
                value = cache.get(signature)
                if value is None:
                    events: dict[str, list] = {}
                    for call_block, position, key in calls:
                        if key not in keeping:
                            events.setdefault(call_block, []).append((position, 0, f"call:{key}"))
                    if object_id.kind in _MEMORY_KINDS:
                        for write_block, position, order, other, key in memory_writes:
                            if may_alias(other, object_id):
                                events.setdefault(write_block, []).append((position, order, f"alias:{key}"))
                        for write_block, position, order, key in unknown:
                            events.setdefault(write_block, []).append((position, order, f"unknown:{key}"))
                    for write_block, position, order in covering:
                        events.setdefault(write_block, []).append((position, order, None))
                    for rows in events.values():
                        rows.sort(key=lambda row: (row[0], row[1], row[2] is not None))
                    value = _live_gens_at_exit(graph, events, block_key)
                    cache[signature] = value
                if value:
                    per_offset[offset] = value
            result[(block_key, object_id)] = per_offset
    return result


__all__ = (
    "ExitSummary", "FUNCTION_SUMMARY_VERSION", "FunctionSummary", "SummaryKind", "SummaryRun",
    "summarize_function",
)
