"""Architect-owned materialization of accepted local-memory SSA relations."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .graph import RustworkxDependencyGraph
from .graph_contracts import EdgeRecord, NodeId, NodeKind, NodeRecord
from .memory_contracts import LocalMemorySsaResult, MemoryDefinitionKind
from .model import ByteSpan, ResolvedStorage, StorageScopeId


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


def _materialize_local_memory_ssa(
    graph: RustworkxDependencyGraph,
    result: LocalMemorySsaResult,
    operation_nodes: dict[str, NodeId],
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
    if any(
        graph.node_for_key(record.key) is not None
        for record in (*definition_records, *debt_records)
    ):
        raise ValueError("memory namespace collides with existing graph nodes")
    graph.claim_namespace(namespace)
    definition_nodes = tuple(graph.add_node(record) for record in definition_records)

    for join in result.joins:
        target = definition_nodes[join.join_definition_id]
        join_span = result.definitions[join.join_definition_id].span
        for occurrence, source_id in enumerate(join.source_definition_ids):
            graph.add_edge(
                definition_nodes[source_id],
                target,
                EdgeRecord(
                    "memory_join_input",
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
                    "memory_defines",
                    operation=action.operation_key,
                    occurrence=definition.write_ordinal,
                    span=definition.span,
                ),
            )

    for definition_id, action_id, span in _distinct_read_relations(result):
        action = result.actions[action_id]
        graph.add_edge(
            definition_nodes[definition_id],
            action_nodes[action_id],
            EdgeRecord(
                "memory_read",
                operation=action.operation_key,
                span=span,
            ),
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
                f"unresolved_{direction}",
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
    )
    actual = graph.incident_edge_multiplicities(owned_nodes)
    expected = dict(Counter(_expected_memory_edges(result, bindings)))
    if actual != expected:
        raise ValueError("memory graph topology does not match the SSA result")


def _expected_memory_edges(
    result: LocalMemorySsaResult,
    bindings: MemoryGraphBindings,
) -> tuple[tuple[NodeId, NodeId, EdgeRecord], ...]:
    edges: list[tuple[NodeId, NodeId, EdgeRecord]] = []
    for join in result.joins:
        target = bindings.definition_nodes[join.join_definition_id]
        join_span = result.definitions[join.join_definition_id].span
        for occurrence, source_id in enumerate(join.source_definition_ids):
            edges.append(
                (
                    bindings.definition_nodes[source_id],
                    target,
                    EdgeRecord(
                        "memory_join_input",
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
                        "memory_defines",
                        operation=action.operation_key,
                        occurrence=definition.write_ordinal,
                        span=definition.span,
                    ),
                )
            )
    for definition_id, action_id, span in _distinct_read_relations(result):
        action = result.actions[action_id]
        edges.append(
            (
                bindings.definition_nodes[definition_id],
                bindings.action_nodes[action_id],
                EdgeRecord(
                    "memory_read",
                    operation=action.operation_key,
                    span=span,
                ),
            )
        )
    for direction, occurrences, debt_nodes in (
        ("read", result.unresolved_reads, bindings.unresolved_read_nodes),
        ("write", result.unresolved_writes, bindings.unresolved_write_nodes),
    ):
        for occurrence, debt_node in zip(occurrences, debt_nodes, strict=True):
            action = result.actions[occurrence.action_id]
            action_node = bindings.action_nodes[occurrence.action_id]
            edge = EdgeRecord(
                f"unresolved_{direction}",
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
    if not graph.has_node(node) or graph.node(node).kind is not NodeKind.OPERATION:
        raise ValueError("SSA action must map to an existing OPERATION node")
    return node
