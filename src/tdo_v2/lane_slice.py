"""Byte-lane-aware backward slices (docs section 25.6, B2a).

The dependency graph has one definition node per written varnode and one
operation node per p-code operation; plain reachability (``graph.
backward_reachable``) takes a read of 4 bytes of an 8-byte value as
depending on all 8 source bytes. ``lane_slice`` walks the same graph with a
demand per node:

* a definition node: the absolute storage bytes of its span that matter;
* an operation node: the byte indices of its result that matter (STORE: of
  the stored value), or FULL -- every input of the node (outputless calls,
  branches, call / rep rows, operations without an exact lane map, roots
  without spans).

Demands only grow (a worklist reprocesses a node when its demand grows), so
the walk terminates. Lane maps are the exact byte dependence of the listed
p-code operations, little-endian: COPY / INT_NEGATE (byte i <- i), LOAD
(value byte i <- dereferenced byte i of each candidate address; the address
operand: all bytes), STORE (stored byte j <- value byte j; address: all),
SUBPIECE by a constant, PIECE, INT_ZEXT, INT_SEXT (high bytes <- the top
input byte), INT_AND / INT_OR / INT_XOR (byte i <- byte i of both operands).
Everything else is FULL. A definition passes its bytes to its writer only
when the definition is exactly that writer's output (or a STORE's projected
destination); otherwise the writer is FULL. Debts are kept as node-level
reachability does: a reached operation reaches its debt predecessors, and
their predecessors are FULL. Data-only, as root origins are.

Every node reached here is reached by the node slice (a subset); every byte a
reached value depends on through these operations is reached (the lane
oracle checks this against concrete runs).
"""

from __future__ import annotations

from .resource_limits import step

from dataclasses import dataclass, field

from ._scope_contracts import VarnodeKindCode
from .graph_contracts import EdgeKind, NodeKind
from .memory_contracts import MemoryDefinitionKind
from .span_geometry import StorageObjectKind

FULL = None   # the demand "every input of this node"

_LANE_OPS = frozenset({"COPY", "INT_NEGATE", "LOAD", "STORE", "SUBPIECE", "PIECE", "INT_ZEXT", "INT_SEXT",
                       "INT_AND", "INT_OR", "INT_XOR"})
_DEBT_EDGES = frozenset({EdgeKind.UNRESOLVED_READ.value, EdgeKind.CALL_CLOBBER_READ.value,
                         EdgeKind.MAY_ALIAS_READ.value})
_MEMORY_OBJECTS = (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)


@dataclass
class LaneSlice:
    demands: dict = field(default_factory=dict)   # node -> FULL | frozenset of bytes
    nodes: frozenset = frozenset()
    # ``budget`` ran out (``operation_records``): the demands are not a fixed
    # point, ``frontier`` the nodes left unprocessed
    exhausted: bool = False
    frontier: frozenset = frozenset()

    def reaches(self, node) -> bool:
        return node in self.demands

    def definition_span(self, index, node):
        """The storage span of a definition node (None: not a definition)."""
        found = index.definition_of.get(node)
        return None if found is None else index.ssa.definitions[found].span

    def bytes_of(self, node):
        """Absolute bytes demanded of a definition node (FULL: all of it)."""
        return self.demands.get(node, frozenset())


class _Index:
    """The function's operations and memory SSA, keyed for the walk."""

    def __init__(self, normalized, unit):
        from .call_seeds import _operation_key
        from .normalize import _storage_ref
        from .model import ResolvedStorage
        from .storage import _resolve_validated_storage

        self.graph = normalized.dependencies
        ssa, bindings = normalized.memory_ssa, normalized.memory_graph
        self.ssa = ssa
        self.definition_of = {node: index for index, node in enumerate(bindings.definition_nodes)}
        self.action_of = {node: index for index, node in enumerate(bindings.action_nodes)}
        self.definition_node = bindings.definition_nodes
        self.reads = {}
        for read in ssa.reads:
            self.reads.setdefault(read.action_id, []).append(read)
        self.joins = {join.join_definition_id: join.source_definition_ids for join in ssa.joins}
        context = unit.scopes.resolution_context
        # the byte maps are little-endian: anything else widens to FULL
        language = unit.scopes.program.evidence.translation_namespace.language_id.split(":")
        self.little = len(language) > 1 and language[1] == "LE"
        self.operations = {}
        for instruction in unit.observation.instructions:
            for ordinal, operation in enumerate(instruction.operations):
                spans = []
                for varnode in (*operation.inputs, operation.output):
                    if varnode is None or varnode.kind not in (VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE,
                                                               VarnodeKindCode.ADDRESS):
                        spans.append(None)
                        continue
                    resolved = _resolve_validated_storage(_storage_ref(varnode), context)
                    spans.append(resolved.span if type(resolved) is ResolvedStorage else None)
                self.operations[_operation_key(instruction.address, ordinal, operation.opcode)] = (
                    operation, tuple(spans[:-1]), spans[-1])

    def operation(self, action_id):
        return self.operations.get(self.ssa.actions[action_id].operation_key)


def lane_index(normalized, unit) -> "_Index":
    """The function's operation / memory SSA index (reusable across slices)."""
    return _Index(normalized, unit)


def lane_slice(normalized, unit, seeds, index=None, ignore_debts=False, budget=None,
               byte_budget=None) -> LaneSlice:
    """``seeds``: (node, spans) -- spans: the absolute ByteSpans demanded of a
    definition node, or None / () for FULL. ``index``: ``lane_index``'s.
    ``ignore_debts``: never enter a MEMORY_DEBT node (seeds included), nor
    follow a read fragment a call may have changed (a call-clobber debt on
    that operation overlapping it: the value before the call reaches it only
    if the call did not change it) -- the paths that cross no debt
    (``origin_witnesses``). ``budget`` / ``byte_budget``: at most that many
    worklist steps / demanded bytes materialized (diagnostics); when one runs
    out the result is ``exhausted``."""
    index = index or _Index(normalized, unit)
    demands: dict = {}
    pending: list = []
    clobbered: dict = {}
    if ignore_debts:
        for row in getattr(normalized, "call_clobber_reads", ()):
            clobbered.setdefault(row.operation_key, []).extend(row.spans)

    materialized = [0]

    def add(node, demand):
        if ignore_debts and index.graph.node(node).kind is NodeKind.MEMORY_DEBT:
            return
        if node in demands:
            old = demands[node]
            if old is FULL:
                return
            if demand is FULL:
                demands[node] = FULL
            else:
                merged = old | demand
                if merged == old:
                    return
                demands[node] = merged
        else:
            demands[node] = demand
        pending.append(node)

    def over(cost):
        """Charge ``cost`` bytes about to be materialized: True when the
        byte budget would be exceeded (nothing is materialized then)."""
        if byte_budget is None:
            return False
        if materialized[0] + cost > byte_budget:
            materialized[0] = byte_budget + 1
            return True
        materialized[0] += cost
        return False

    for node, spans in seeds:
        if not spans or node not in index.definition_of:
            add(node, FULL)
            continue
        # the selector's bytes in the definition's own storage; a selector of
        # another object (a stack argument slot whose value is bound to the
        # temporary that holds it) or one not overlapping it: FULL
        definition = index.ssa.definitions[index.definition_of[node]]
        if over(definition.span.size + sum(span.size for span in spans)):
            pending.append(node)   # (left unprocessed: the frontier)
            break
        whole = _whole(definition.span)
        if any(span.object_id != definition.span.object_id or not (_whole(span) & whole) for span in spans):
            add(node, FULL)   # a selector with no known correspondence to this storage
            continue
        add(node, frozenset(byte for span in spans for byte in range(span.start, span.end)) & whole)
    steps = 0
    while pending:
        step()   # (budget: docs 25.30 K1c)
        if (budget is not None and steps >= budget) or (byte_budget is not None and materialized[0] > byte_budget) \
                or over(_cost(index, pending[-1])):
            return LaneSlice(demands, frozenset(demands), True, frozenset(pending))
        steps += 1
        node = pending.pop()
        demand = demands[node]
        if node in index.definition_of:
            _definition(index, node, demand, add)
        elif node in index.action_of:
            _operation(index, node, demand, add, clobbered)
        else:
            _other(index, node, add)
    return LaneSlice(demands, frozenset(demands))


def _whole(span):
    return frozenset(range(span.start, span.end))


def _cost(index, node) -> int:
    """Bytes processing ``node`` may materialize (a byte budget's charge): its
    span (a JOIN: and its sources' spans), or its reads' spans."""
    if node in index.definition_of:
        definition_id = index.definition_of[node]
        return index.ssa.definitions[definition_id].span.size + sum(
            index.ssa.definitions[source].span.size for source in index.joins.get(definition_id, ()))
    if node in index.action_of:
        return sum(read.span.size for read in index.reads.get(index.action_of[node], ()))
    return 0


def _definition(index, node, demand, add):
    definition_id = index.definition_of[node]
    definition = index.ssa.definitions[definition_id]
    span = definition.span
    wanted = _whole(span) if demand is FULL else demand & _whole(span)
    # debts (and any edge other than the definition's own data edges) of every
    # reached node: FULL, as node reachability keeps them
    for source, _, record in index.graph._graph.in_edges(node):
        if record.kind not in (EdgeKind.MEMORY_DEFINES.value, EdgeKind.MEMORY_JOIN_INPUT.value,
                               EdgeKind.CONTROL_DEPENDENCE.value):
            add(source, FULL)
    if definition.kind is MemoryDefinitionKind.ENTRY:
        return
    if definition.kind is MemoryDefinitionKind.JOIN:
        sources = index.joins.get(definition_id, ())
        covered_by_some = frozenset().union(*(
            wanted & _whole(index.ssa.definitions[source_id].span) for source_id in sources
            if index.ssa.definitions[source_id].span.object_id == span.object_id))
        if wanted - covered_by_some or any(index.ssa.definitions[source_id].span.object_id != span.object_id
                                           for source_id in sources):
            # a demanded byte no source covers (or a source of another
            # object): every source, FULL (conservative)
            for source_id in sources:
                add(index.definition_node[source_id], FULL)
            return
        for source_id in sources:
            covered = wanted & _whole(index.ssa.definitions[source_id].span)
            if covered:
                add(index.definition_node[source_id], covered)
        return
    # a write: its writer operation, as value bytes when the definition is
    # exactly that writer's output (or a STORE's destination)
    writers = [source for source, _, record in index.graph._graph.in_edges(node)
               if record.kind == EdgeKind.MEMORY_DEFINES.value]
    for writer in writers:
        precise = definition.kind is MemoryDefinitionKind.DATA_WRITE and index.little
        add(writer, _value_bytes(index, writer, span, wanted) if precise else FULL)


def _value_bytes(index, writer, span, wanted):
    """Value-byte demand of ``writer`` for the bytes ``wanted`` of its write
    ``span``, or FULL when the write is not exactly its output / destination."""
    action_id = index.action_of.get(writer)
    if action_id is None:
        return FULL
    found = index.operation(action_id)
    if found is None:
        return FULL
    operation, _, output = found
    if operation.opcode not in _LANE_OPS:
        return FULL
    if operation.opcode == "STORE":
        value = operation.inputs[2] if len(operation.inputs) > 2 else None
        if value is None or span.object_id.kind not in _MEMORY_OBJECTS or span.size != value.byte_size:
            return FULL
        return frozenset(byte - span.start for byte in wanted)
    if output is None or output != span:
        return FULL
    return frozenset(byte - span.start for byte in wanted)


def _operation(index, node, demand, add, clobbered=None):
    action_id = index.action_of[node]
    found = index.operation(action_id)
    reads = index.reads.get(action_id, ())
    changed = (clobbered or {}).get(index.ssa.actions[action_id].operation_key, ())
    operand_demands = None if demand is FULL or found is None or not index.little \
        else _operand_demands(found, demand)
    for read in reads:
        if operand_demands is None:
            wanted = None
        else:
            wanted = _read_demand(found, read, operand_demands)
        for fragment in read.fragments:
            if wanted is None:
                bytes_ = _whole(fragment.span)
            else:
                bytes_ = frozenset(read.span.start + offset for offset in wanted) & _whole(fragment.span)
            # ``ignore_debts``: not the bytes a call may have changed
            bytes_ -= frozenset(byte for span in changed if span.object_id == fragment.span.object_id
                                for byte in range(span.start, span.end))
            if not bytes_:
                continue
            for definition_id in fragment.definition_ids:
                add(index.definition_node[definition_id], bytes_)
    # debts and every other predecessor that is not one of its reads or a
    # constant input (CONTROL_DEPENDENCE: data-only)
    for source, _, record in index.graph._graph.in_edges(node):
        if record.kind not in (EdgeKind.MEMORY_READ.value, EdgeKind.VALUE_INPUT.value,
                               EdgeKind.CONTROL_DEPENDENCE.value):
            add(source, FULL)


def _other(index, node, add):
    """A debt or other node: every data predecessor, FULL."""
    for source, _, record in index.graph._graph.in_edges(node):
        if record.kind != EdgeKind.CONTROL_DEPENDENCE.value:
            add(source, FULL)


_ARITY = {"COPY": 1, "INT_NEGATE": 1, "LOAD": 2, "STORE": 3, "SUBPIECE": 2, "PIECE": 2, "INT_ZEXT": 1,
          "INT_SEXT": 1, "INT_AND": 2, "INT_OR": 2, "INT_XOR": 2}


def _operand_demands(found, demand):
    """{operand index or "mem": byte indices} demanded of each operand for the
    result bytes ``demand``; None: every operand fully (no exact map, or a
    shape the map does not hold for)."""
    operation = found[0]
    if operation.opcode not in _ARITY or len(operation.inputs) != _ARITY[operation.opcode]:
        return None
    output = operation.output
    sizes = [varnode.byte_size for varnode in operation.inputs]
    if operation.opcode != "STORE":
        if output is None:
            return None
        width = output.byte_size
        shapes = {
            "COPY": lambda: sizes[0] == width, "INT_NEGATE": lambda: sizes[0] == width, "LOAD": lambda: True,
            "SUBPIECE": lambda: sizes[0] >= width, "PIECE": lambda: sizes[0] + sizes[1] == width,
            "INT_ZEXT": lambda: sizes[0] <= width, "INT_SEXT": lambda: sizes[0] <= width,
            "INT_AND": lambda: sizes[0] == sizes[1] == width, "INT_OR": lambda: sizes[0] == sizes[1] == width,
            "INT_XOR": lambda: sizes[0] == sizes[1] == width,
        }
        if not shapes[operation.opcode]():
            return None
    return _mapped_demands(found, demand)


def _mapped_demands(found, demand):
    operation, inputs, output = found
    opcode = operation.opcode
    sizes = [varnode.byte_size for varnode in operation.inputs]
    if opcode not in _LANE_OPS:
        return None
    if opcode in ("COPY", "INT_NEGATE"):
        return {0: frozenset(byte for byte in demand if byte < sizes[0])}
    if opcode == "LOAD":
        found_demand = {"mem": frozenset(demand)}
        if demand:
            found_demand[1] = frozenset(range(sizes[1]))
        return found_demand
    if opcode == "STORE":
        found_demand = {2: frozenset(byte for byte in demand if byte < sizes[2])}
        if demand:
            found_demand[1] = frozenset(range(sizes[1]))
        return found_demand
    if opcode == "SUBPIECE":
        constant = operation.inputs[1]
        if constant.kind is not VarnodeKindCode.CONSTANT:
            return None
        shift = constant.coordinate.byte_offset
        return {0: frozenset(shift + byte for byte in demand if shift + byte < sizes[0])}
    if opcode == "PIECE":
        low = sizes[1]
        return {0: frozenset(byte - low for byte in demand if low <= byte < low + sizes[0]),
                1: frozenset(byte for byte in demand if byte < low)}
    if opcode == "INT_ZEXT":
        return {0: frozenset(byte for byte in demand if byte < sizes[0])}
    if opcode == "INT_SEXT":
        top = sizes[0] - 1
        return {0: frozenset(byte if byte < sizes[0] else top for byte in demand)}
    if opcode in ("INT_AND", "INT_OR", "INT_XOR"):
        return {0: frozenset(byte for byte in demand if byte < sizes[0]),
                1: frozenset(byte for byte in demand if byte < sizes[1])}
    return None


def _read_demand(found, read, operand_demands):
    """Byte offsets within ``read.span`` demanded of this read, or None (all):
    the explicit operands whose resolved varnode is the read span (registers,
    temporaries, memory operands -- all of them, if one storage is read twice);
    a LOAD's other memory read is its dereferenced memory ("mem"), and a
    memory read that matches an explicit operand may be both (union)."""
    operation, inputs, _ = found
    explicit = [position for position, span in enumerate(inputs) if span is not None and span == read.span]
    wanted = frozenset().union(*(operand_demands.get(position, frozenset()) for position in explicit))
    if operation.opcode == "LOAD" and read.span.object_id.kind in _MEMORY_OBJECTS:
        return wanted | operand_demands.get("mem", frozenset())
    return wanted if explicit else None


def reached_bytes(lanes: LaneSlice, normalized, kind=StorageObjectKind.REGISTER_FILE) -> frozenset:
    """Entry bytes (OBSERVED_INPUT definitions of ``kind``) the slice demands."""
    found = set()
    bindings = normalized.memory_graph
    for definition_id, node in enumerate(bindings.definition_nodes):
        if node not in lanes.demands:
            continue
        definition = normalized.memory_ssa.definitions[definition_id]
        if definition.kind is not MemoryDefinitionKind.ENTRY or definition.span.object_id.kind is not kind:
            continue
        demand = lanes.demands[node]
        found |= _whole(definition.span) if demand is FULL else demand & _whole(definition.span)
    return frozenset(found)


def is_node_subset(lanes: LaneSlice, normalized, seeds) -> bool:
    """The lane slice never reaches a node the data-only node slice misses."""
    reachable = set(normalized.dependencies.backward_reachable([node for node, _ in seeds]))
    return lanes.nodes <= reachable


__all__ = ("FULL", "LaneSlice", "is_node_subset", "lane_index", "lane_slice", "reached_bytes")
