"""Architect-owned materialization of accepted local-memory SSA relations."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .graph import RustworkxDependencyGraph
from .graph_contracts import EdgeKind, EdgeRecord, NodeId, NodeKind, NodeRecord
from .memory_contracts import LocalMemorySsaResult, MemoryDefinitionKind
from .model import ByteSpan, ResolvedStorage, StorageScopeId


@dataclass(frozen=True, slots=True)
class MemoryTransfer:
    """Audited, exact-fragment byte transfer; not a new SSA definition."""

    definition_id: int
    action_id: int
    span: ByteSpan
    call: str
    guard: str
    contract: str
    requires: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.definition_id) is not int or self.definition_id < 0:
            raise TypeError("transfer definition ID must be an exact non-negative int")
        if type(self.action_id) is not int or self.action_id < 0:
            raise TypeError("transfer action ID must be an exact non-negative int")
        if type(self.span) is not ByteSpan:
            raise TypeError("transfer span must be an exact ByteSpan")
        for value, label in ((self.call, "call"), (self.guard, "guard"),
                             (self.contract, "contract")):
            if type(value) is not str or not value:
                raise TypeError(f"transfer {label} must be a non-empty exact str")
        if type(self.requires) is not tuple or any(
            type(label) is not str or not label for label in self.requires
        ):
            raise TypeError("transfer requirements must be exact non-empty strings")
        if len(set(self.requires)) != len(self.requires) or self.contract not in self.requires:
            raise ValueError("transfer requirements must be unique and include its contract")


@dataclass(frozen=True, slots=True)
class MemoryGraphBindings:
    contract_version: int
    function_scope: StorageScopeId
    unit_digest: bytes
    definition_nodes: tuple[NodeId, ...]
    action_nodes: tuple[NodeId, ...]
    unresolved_read_nodes: tuple[NodeId, ...]
    unresolved_write_nodes: tuple[NodeId, ...]
    entry_bindings: tuple[tuple[NodeId, ResolvedStorage], ...]
    transfers: tuple[MemoryTransfer, ...] = ()
    transfer_nodes: tuple[NodeId, ...] = ()

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int:
            raise TypeError("binding contract version must be an exact int")
        if type(self.function_scope) is not StorageScopeId:
            raise TypeError("binding function scope must be exact")
        if type(self.unit_digest) is not bytes or len(self.unit_digest) != 32:
            raise TypeError("binding unit digest must be exact 32-byte evidence")
        for values, label in (
            (self.definition_nodes, "definition nodes"),
            (self.action_nodes, "action nodes"),
            (self.unresolved_read_nodes, "unresolved read nodes"),
            (self.unresolved_write_nodes, "unresolved write nodes"),
            (self.transfer_nodes, "transfer nodes"),
        ):
            if type(values) is not tuple or any(
                type(node) is not int or node < 0 for node in values
            ):
                raise TypeError(
                    f"{label} must be an exact tuple of non-negative integer node IDs"
                )
        if type(self.entry_bindings) is not tuple:
            raise TypeError("entry bindings must be an exact tuple")
        for binding in self.entry_bindings:
            if (
                type(binding) is not tuple
                or len(binding) != 2
                or type(binding[0]) is not int
                or binding[0] < 0
                or type(binding[1]) is not ResolvedStorage
            ):
                raise TypeError("entry bindings require exact node/storage pairs")
        if type(self.transfers) is not tuple or any(
            type(transfer) is not MemoryTransfer for transfer in self.transfers
        ):
            raise TypeError("binding transfers must be an exact tuple of MemoryTransfer")
        if len(self.transfers) != len(self.transfer_nodes):
            raise ValueError("transfer records and nodes must align")


def _materialize_local_memory_ssa(
    graph: RustworkxDependencyGraph,
    result: LocalMemorySsaResult,
    operation_nodes: dict[str, NodeId],
    transfers: tuple[MemoryTransfer, ...] = (),
) -> MemoryGraphBindings:
    if type(graph) is not RustworkxDependencyGraph:
        raise TypeError("memory graph materialization requires the exact graph backend")
    if type(result) is not LocalMemorySsaResult:
        raise TypeError("memory graph materialization requires an exact SSA result")
    if type(operation_nodes) is not dict or any(
        type(key) is not str or type(node) is not int
        for key, node in operation_nodes.items()
    ):
        raise TypeError("operation nodes require an exact str-to-int dictionary")

    expected_actions = tuple(action.operation_key for action in result.actions)
    if set(operation_nodes) != set(expected_actions):
        raise ValueError("operation mapping must exactly cover SSA actions")
    action_nodes = tuple(
        _operation_node(graph, operation_nodes, operation_key)
        for operation_key in expected_actions
    )
    _validate_transfers(result, transfers)
    namespace = (
        f"memory-v{result.contract_version}:{result.function_scope.digest.hex()}:"
        f"{result.unit_digest.hex()}"
    )
    definition_records = tuple(
        NodeRecord(
            f"memory:{namespace}:definition:{definition_id}",
            _definition_node_kind(definition.kind),
            _definition_label(definition.kind, definition.span.canonical_key),
        )
        for definition_id, definition in enumerate(result.definitions)
    )
    debt_records = tuple(
        NodeRecord(
            f"memory:{namespace}:unresolved:{direction}:"
            f"{occurrence.action_id}:{occurrence.occurrence_ordinal}",
            NodeKind.MEMORY_DEBT,
            f"unresolved_memory_{direction}",
        )
        for direction, occurrences in (
            ("read", result.unresolved_reads),
            ("write", result.unresolved_writes),
        )
        for occurrence in occurrences
    )
    transfer_records = tuple(
        _transfer_node_record(namespace, index, transfer)
        for index, transfer in enumerate(transfers)
    )
    if any(
        graph.node_for_key(record.key) is not None
        for record in (*definition_records, *debt_records, *transfer_records)
    ):
        raise ValueError("memory namespace collides with existing graph nodes")
    graph.claim_namespace(namespace)
    definition_nodes = tuple(graph.add_node(record) for record in definition_records)
    transfer_nodes = tuple(graph.add_node(record) for record in transfer_records)

    for join in result.joins:
        target = definition_nodes[join.join_definition_id]
        join_span = result.definitions[join.join_definition_id].span
        for occurrence, source_id in enumerate(join.source_definition_ids):
            graph.add_edge(
                definition_nodes[source_id],
                target,
                EdgeRecord(
                    EdgeKind.MEMORY_JOIN_INPUT,
                    occurrence=occurrence,
                    span=join_span,
                ),
            )

    for action_id, action in enumerate(result.actions):
        operation_node = action_nodes[action_id]
        for definition_id in action.write_definition_ids:
            definition = result.definitions[definition_id]
            graph.add_edge(
                operation_node,
                definition_nodes[definition_id],
                EdgeRecord(
                    EdgeKind.MEMORY_DEFINES,
                    operation=action.operation_key,
                    occurrence=definition.write_ordinal,
                    span=definition.span,
                ),
            )

    transfer_by_relation = {
        (transfer.definition_id, transfer.action_id, transfer.span): index
        for index, transfer in enumerate(transfers)
    }
    for definition_id, action_id, span in _distinct_read_relations(result):
        action = result.actions[action_id]
        index = transfer_by_relation.get((definition_id, action_id, span))
        if index is None:
            graph.add_edge(
                definition_nodes[definition_id], action_nodes[action_id],
                EdgeRecord(EdgeKind.MEMORY_READ, operation=action.operation_key, span=span),
            )
        else:
            transfer = transfers[index]
            node = transfer_nodes[index]
            graph.add_edge(
                definition_nodes[definition_id], node,
                EdgeRecord(EdgeKind.MEMORY_TRANSFER, operation=action.operation_key, span=span),
            )
            graph.add_edge(
                _operation_node(graph, operation_nodes, transfer.call), node,
                EdgeRecord(EdgeKind.MEMORY_TRANSFER, operation=transfer.call, span=span),
            )
            graph.add_edge(
                _operation_node(graph, operation_nodes, transfer.guard), node,
                EdgeRecord(EdgeKind.CONTROL_DEPENDENCE, operation=transfer.guard, span=span),
            )
            graph.add_edge(
                node, action_nodes[action_id],
                EdgeRecord(EdgeKind.MEMORY_READ, operation=action.operation_key, span=span),
            )

    unresolved_read_nodes: list[NodeId] = []
    unresolved_write_nodes: list[NodeId] = []
    debt_record_ordinal = 0
    for direction, occurrences in (
        ("read", result.unresolved_reads),
        ("write", result.unresolved_writes),
    ):
        for occurrence in occurrences:
            action = result.actions[occurrence.action_id]
            operation_node = action_nodes[occurrence.action_id]
            debt_node = graph.add_node(debt_records[debt_record_ordinal])
            debt_record_ordinal += 1
            if direction == "read":
                unresolved_read_nodes.append(debt_node)
            else:
                unresolved_write_nodes.append(debt_node)
            edge = EdgeRecord(
                EdgeKind(f"unresolved_{direction}"),
                operation=action.operation_key,
                occurrence=occurrence.occurrence_ordinal,
            )
            if direction == "read":
                graph.add_edge(debt_node, operation_node, edge)
            else:
                graph.add_edge(operation_node, debt_node, edge)

    entry_bindings = tuple(
        (definition_nodes[definition_id], ResolvedStorage(definition.span))
        for definition_id, definition in enumerate(result.definitions)
        if definition.kind is MemoryDefinitionKind.ENTRY
    )
    return MemoryGraphBindings(
        result.contract_version,
        result.function_scope,
        result.unit_digest,
        definition_nodes,
        action_nodes,
        tuple(unresolved_read_nodes),
        tuple(unresolved_write_nodes),
        entry_bindings,
        transfers,
        transfer_nodes,
    )


def _validate_materialized_local_memory_ssa(
    graph: RustworkxDependencyGraph,
    result: LocalMemorySsaResult,
    bindings: MemoryGraphBindings,
) -> None:
    if type(graph) is not RustworkxDependencyGraph:
        raise TypeError("memory topology validation requires the exact graph backend")
    if type(result) is not LocalMemorySsaResult:
        raise TypeError("memory topology validation requires an exact SSA result")
    if type(bindings) is not MemoryGraphBindings:
        raise TypeError("memory topology validation requires exact graph bindings")
    owned_nodes = (
        *bindings.definition_nodes,
        *bindings.unresolved_read_nodes,
        *bindings.unresolved_write_nodes,
        *bindings.transfer_nodes,
    )
    _validate_transfers(result, bindings.transfers)
    if len(bindings.transfer_nodes) != len(bindings.transfers):
        raise ValueError("transfer graph bindings must align with transfer records")
    namespace = (
        f"memory-v{result.contract_version}:{result.function_scope.digest.hex()}:"
        f"{result.unit_digest.hex()}"
    )
    actions = {action.operation_key: node for action, node in zip(
        result.actions, bindings.action_nodes, strict=True
    )}
    for index, (transfer, node) in enumerate(zip(
        bindings.transfers, bindings.transfer_nodes, strict=True
    )):
        if not graph.has_node(node) or graph.node(node) != _transfer_node_record(
            namespace, index, transfer
        ):
            raise ValueError("transfer binding does not match its graph node")
        for key in (transfer.call, transfer.guard):
            operation_node = actions[key]
            if not graph.has_node(operation_node) or (
                graph.node(operation_node).key != f"op:{key}"
                or graph.node(operation_node).kind is not NodeKind.OPERATION
            ):
                raise ValueError("transfer dependency must map to an OPERATION node")
    actual = graph.incident_edge_multiplicities(owned_nodes)
    expected = dict(Counter(_expected_memory_edges(result, bindings)))
    if actual != expected:
        raise ValueError("memory graph topology does not match the SSA result")


def _expected_memory_edges(
    result: LocalMemorySsaResult,
    bindings: MemoryGraphBindings,
) -> tuple[tuple[NodeId, NodeId, EdgeRecord], ...]:
    edges: list[tuple[NodeId, NodeId, EdgeRecord]] = []
    transfer_by_relation = {
        (transfer.definition_id, transfer.action_id, transfer.span): index
        for index, transfer in enumerate(bindings.transfers)
    }
    actions = {row.operation_key: binding for row, binding in zip(
        result.actions, bindings.action_nodes, strict=True
    )}
    for join in result.joins:
        target = bindings.definition_nodes[join.join_definition_id]
        join_span = result.definitions[join.join_definition_id].span
        for occurrence, source_id in enumerate(join.source_definition_ids):
            edges.append(
                (
                    bindings.definition_nodes[source_id],
                    target,
                    EdgeRecord(
                        EdgeKind.MEMORY_JOIN_INPUT,
                        occurrence=occurrence,
                        span=join_span,
                    ),
                )
            )
    for action_id, action in enumerate(result.actions):
        for definition_id in action.write_definition_ids:
            definition = result.definitions[definition_id]
            edges.append(
                (
                    bindings.action_nodes[action_id],
                    bindings.definition_nodes[definition_id],
                    EdgeRecord(
                        EdgeKind.MEMORY_DEFINES,
                        operation=action.operation_key,
                        occurrence=definition.write_ordinal,
                        span=definition.span,
                    ),
                )
            )
    for definition_id, action_id, span in _distinct_read_relations(result):
        action = result.actions[action_id]
        index = transfer_by_relation.get((definition_id, action_id, span))
        if index is None:
            edges.append((
                bindings.definition_nodes[definition_id], bindings.action_nodes[action_id],
                EdgeRecord(EdgeKind.MEMORY_READ, operation=action.operation_key, span=span),
            ))
        else:
            transfer = bindings.transfers[index]
            node = bindings.transfer_nodes[index]
            edges.extend((
                (bindings.definition_nodes[definition_id], node,
                 EdgeRecord(EdgeKind.MEMORY_TRANSFER, operation=action.operation_key, span=span)),
                (actions[transfer.call], node,
                 EdgeRecord(EdgeKind.MEMORY_TRANSFER, operation=transfer.call, span=span)),
                (actions[transfer.guard], node,
                 EdgeRecord(EdgeKind.CONTROL_DEPENDENCE, operation=transfer.guard, span=span)),
                (node, bindings.action_nodes[action_id],
                 EdgeRecord(EdgeKind.MEMORY_READ, operation=action.operation_key, span=span)),
            ))
    for direction, occurrences, debt_nodes in (
        ("read", result.unresolved_reads, bindings.unresolved_read_nodes),
        ("write", result.unresolved_writes, bindings.unresolved_write_nodes),
    ):
        for occurrence, debt_node in zip(occurrences, debt_nodes, strict=True):
            action = result.actions[occurrence.action_id]
            action_node = bindings.action_nodes[occurrence.action_id]
            edge = EdgeRecord(
                EdgeKind(f"unresolved_{direction}"),
                operation=action.operation_key,
                occurrence=occurrence.occurrence_ordinal,
            )
            endpoints = (
                (debt_node, action_node)
                if direction == "read"
                else (action_node, debt_node)
            )
            edges.append((*endpoints, edge))
    return tuple(edges)


def _validate_transfers(
    result: LocalMemorySsaResult, transfers: tuple[MemoryTransfer, ...]
) -> None:
    if type(transfers) is not tuple or any(
        type(transfer) is not MemoryTransfer for transfer in transfers
    ):
        raise TypeError("transfers must be an exact tuple of MemoryTransfer")
    relations = set(_distinct_read_relations(result))
    actions = {action.operation_key for action in result.actions}
    claimed: dict[int, list[ByteSpan]] = {}
    for transfer in transfers:
        relation = (transfer.definition_id, transfer.action_id, transfer.span)
        if relation not in relations:
            raise ValueError("transfer must name an exact SSA read fragment")
        if transfer.call not in actions or transfer.guard not in actions:
            raise ValueError("transfer call and guard must name SSA operations")
        for prior in claimed.setdefault(transfer.action_id, []):
            if transfer.span.overlaps(prior):
                raise ValueError("transfer fragments must not overlap at one read action")
        claimed[transfer.action_id].append(transfer.span)


def _transfer_node_record(
    namespace: str, index: int, transfer: MemoryTransfer
) -> NodeRecord:
    identity = (
        transfer.definition_id, transfer.action_id, transfer.span.canonical_key,
        transfer.call, transfer.guard, transfer.contract, transfer.requires,
    )
    return NodeRecord(
        f"memory:{namespace}:transfer:{index}", NodeKind.EFFECT,
        f"memory_transfer:{identity!r}",
    )


def _distinct_read_relations(
    result: LocalMemorySsaResult,
) -> tuple[tuple[int, int, ByteSpan], ...]:
    seen: set[tuple[int, int, tuple[str, ...]]] = set()
    relations: list[tuple[int, int, ByteSpan]] = []
    for read in result.reads:
        for fragment in read.fragments:
            key = (
                fragment.definition_ids[0],
                read.action_id,
                fragment.span.canonical_key,
            )
            if key not in seen:
                seen.add(key)
                relations.append(
                    (fragment.definition_ids[0], read.action_id, fragment.span)
                )
    return tuple(relations)


def _definition_node_kind(kind: MemoryDefinitionKind) -> NodeKind:
    if kind is MemoryDefinitionKind.ENTRY:
        return NodeKind.OBSERVED_INPUT
    if kind is MemoryDefinitionKind.JOIN:
        return NodeKind.MEMORY_JOIN
    return NodeKind.MEMORY_DEFINITION


def _definition_label(kind: MemoryDefinitionKind, span_key: tuple[str, ...]) -> str:
    return ":".join((kind.value, *span_key))


def _operation_node(
    graph: RustworkxDependencyGraph,
    operation_nodes: dict[str, NodeId],
    operation_key: str,
) -> NodeId:
    try:
        node = operation_nodes[operation_key]
    except KeyError as exc:
        raise ValueError(f"SSA action has no normalized operation: {operation_key}") from exc
    if not graph.has_node(node) or graph.node(node).kind is not NodeKind.OPERATION \
            or graph.node(node).key != f"op:{operation_key}":
        raise ValueError("SSA action must map to an existing OPERATION node")
    return node
