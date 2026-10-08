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
    origins: tuple[str, ...] = ()       # source labels reached (``origin_labels`` of the function)
    # (read span, write span) pairs that must be disjoint for this value to be
    # as stated (conditional may-alias debts on the way, see ``SinkDemand``)
    conditions: tuple[tuple[ByteSpan, ByteSpan], ...] = ()


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


def summarize_function(normalized, observation, origin_labels=None, sink_roots=()) -> FunctionSummary:
    """``origin_labels``: graph node -> source labels it carries (boundary
    origins of this function, e.g. a declared source call's write, or a
    summarized call's run that reached a source inside the callee).
    ``sink_roots``: (label, root nodes, bound and complete so far) per sink
    root of the function, its own or projected from callees; each becomes a
    ``SinkDemand``."""
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

    conditions_of = _alias_conditions(normalized)
    closure = _AncestorClosure(graph, operation_of, origin_labels or {}, conditions_of)

    def definition_slice(definition_id: int):
        """(entry source spans, entry-memory readers, debt labels, origins,
        alias conditions) of the backward data slice from one definition
        (same sets as ``BackwardSliceQuery`` + edge spans, computed for all
        nodes at once)."""
        return closure.of(definition_nodes[definition_id])

    uncertain_conditions = _uncertain_address_writers(
        normalized, observation, context, operation_of, conditions_of)
    uncertain = set(uncertain_conditions)
    tracer = _CopyTracer(normalized, observation, context, operation_of)
    crossed = _exit_crossings(normalized, observation, context, _preserved_stack_pointers, uncertain)
    inner_calls = crossed.pop("inner_calls", ())

    exits = []
    nodes = ssa.state_nodes
    for state in ssa.observed_terminal_states:
        runs = []
        for node in _state_runs(nodes, state.root_node_id):
            for span in _object_spans(atoms, node.start_atom, node.stop_atom):
                runs.append(_classify(span, node.definition_ids, definitions, definition_slice,
                                      crossed.get((state.block_key, span.object_id), {}), uncertain,
                                      tracer))
        exits.append(ExitSummary(state.block_key, tuple(runs)))
    writer_objects = sorted(
        {(item.operation_key, item.span.object_id) for item in definitions
         if item.operation_key is not None},
        key=lambda row: (row[0], row[1].kind.value, row[1].space_key),
    )
    # unknown-address writers: an uncertain-address store whose address
    # depends only on conditional debts lands on its own object unless one of
    # those pairs overlaps; any other leaves every root incomplete
    unknown_writers = set(crossed.get("unknown_writers", ()))
    writer_conditions = set()
    unconditional_writers = False
    for writer in unknown_writers:
        found = uncertain_conditions.get(writer)
        if found is None:
            unconditional_writers = True
        else:
            writer_conditions |= found
    demands = []
    for root in sink_roots:
        label, root_nodes, complete = root[:3]
        sources, debts, origins, conditions = set(), set(), set(), set(root[3] if len(root) > 3 else ())
        for node in root_nodes:
            found_sources, _, found_debts, found_origins, found_conditions = closure.of(node)
            sources |= found_sources
            debts |= found_debts
            origins |= found_origins
            conditions |= found_conditions
        conditions |= writer_conditions
        demands.append(SinkDemand(
            label, tuple(sorted(sources, key=lambda item: item.canonical_key)), tuple(sorted(debts)),
            tuple(sorted(origins)),
            # like the engine's local completeness: any unknown-address write in
            # the function leaves every root incomplete
            bool(complete) and not debts and not unconditional_writers,
            tuple(sorted(conditions, key=lambda pair: (pair[0].canonical_key, pair[1].canonical_key))),
        ))
    return FunctionSummary(
        FUNCTION_SUMMARY_VERSION, tuple(exits), tuple(sorted(crossed.get("unknown_writers", ()))),
        tuple(writer_objects), _tail_exits(normalized, observation), inner_calls, tuple(demands),
        _register_deltas(normalized, observation, exits),
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


def _tail_exits(normalized, observation) -> tuple[str, ...]:
    """Blocks leaving other than by RETURN, except tail jumps composed with the
    target's summary (``ProvenCallEffect.tail_stack``)."""
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
        last = row.operations[block.stop - 1]
        if last.opcode != "RETURN" and _operation_key(row.address, block.stop - 1, last.opcode) not in composed:
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
        if not block.exits:
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

    def __init__(self, graph, operation_of, origin_labels=None, conditions_of=None) -> None:
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
            conditions = (conditions_of or {}).get(node)
            if debts and conditions:  # a may-alias debt between two exact spans: conditional
                debts = frozenset()
            else:
                conditions = frozenset()
            origins = frozenset((origin_labels or {}).get(node, ()))
            self.own[node] = (frozenset(own_sources.get(node, ())), readers, debts, origins, conditions)
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
                parts = [set(), set(), set(), set(), set()]
                empty = (frozenset(),) * 5
                for item in component:
                    for part, own in zip(parts, self.own.get(item, empty)):
                        part |= own
                    for parent_node in self.predecessors.get(item, ()):
                        if parent_node in members:
                            continue
                        for part, found in zip(parts, self.value[parent_node]):
                            part |= found
                value = tuple(frozenset(part) for part in parts)
                for item in component:
                    self.value[item] = value


def _alias_conditions(normalized) -> dict:
    """may-alias debt node -> frozenset of (read span, write span) pairs when
    the read has an exact address and every candidate writer writes exact
    spans (the debt holds only if some pair overlaps); other debt nodes absent."""
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
    found = {}
    for row, node in zip(normalized.may_alias_reads, normalized.may_alias_nodes):
        if row.unknown_address or any(writer in unknown or writer not in spans_of for writer in row.writers):
            continue
        found[node] = frozenset(
            (read, write) for read in row.spans for writer in row.writers for write in spans_of[writer]
        )
    return found


def _uncertain_address_writers(normalized, observation, context, operation_of, conditions_of=None) -> dict:
    """Memory STOREs whose address operand depends on a read with debt ->
    the alias conditions that debt reduces to (None: unconditional)."""
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
    found: dict = {}

    def add(key, conditions):
        if conditions is None or (key in found and found[key] is None):
            found[key] = None
        else:
            found[key] = found.get(key, frozenset()) | conditions

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
            add(key, None)
            continue
        inputs = [
            source for source, _, record in graph._graph.in_edges(node)
            if record.span is not None and record.span.overlaps(resolved.span)
        ]
        reachable = graph.backward_reachable(tuple(inputs)) if inputs else ()
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
    return found


class _CopyTracer:
    """Follows a definition's value back through COPY, LOAD and STORE (same
    size, no debt on the loads, single reaching definitions) to an ENTRY
    definition: ``trace(definition, span)`` is the entry span the value of
    ``span`` was copied from, or None."""

    def __init__(self, normalized, observation, context, operation_of) -> None:
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
        graph = normalized.dependencies
        node_of = {key: node for node, key in operation_of.items()}
        self.indebted = {
            key for key, node in node_of.items()
            if any(graph.node(item).kind is NodeKind.MEMORY_DEBT for item in graph.predecessors(node))
        }

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
              tracer=None):
    if tracer is not None and definition_ids and all(
            tracer.trace(definition_id, span) == span for definition_id in definition_ids):
        # the value is the entry value of these very bytes, copied through
        # registers and memory (e.g. a callee-saved register pushed and popped)
        definition_ids_for_identity = definition_ids
    else:
        definition_ids_for_identity = None
    sources, readers, debts, writers, origins, conditions = set(), set(), set(), set(), set(), set()
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
        found_sources, found_readers, found_debts, found_origins, found_conditions = \
            definition_slice(definition_id)
        sources |= found_sources
        readers |= found_readers
        debts |= found_debts
        origins |= found_origins
        conditions |= found_conditions
    crossings = set()
    for offset in range(span.start, span.end):
        crossings |= crossed_by_offset.get(offset, frozenset())
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
    for key, effect in normalized.proven_call_effects:  # bytes a callee summary proves kept
        preserved[key] = tuple(preserved.get(key, ())) + tuple(effect.preserved)
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

    # the named assumption the function was normalized under (``may_alias``):
    # constant addresses never alias its stack object
    stack = None
    if normalized.assumes_globals_disjoint_from_stack:
        from .may_alias import stack_object_of
        stack = stack_object_of(normalized.scopes, observation)

    def may_alias(left, right) -> bool:
        if left == right:
            return False
        if stack is not None and {left.kind, right.kind} == {StorageObjectKind.ADDRESS_SPACE,
                                                               StorageObjectKind.FUNCTION_RELATIVE}                 and stack in (left, right):
            return False
        return not (left.kind is StorageObjectKind.ADDRESS_SPACE
                    and right.kind is StorageObjectKind.ADDRESS_SPACE)

    result: dict = {
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
    "ExitSummary", "FUNCTION_SUMMARY_VERSION", "FunctionSummary", "SinkDemand", "SummaryKind",
    "SummaryRun",
    "summarize_function",
)
