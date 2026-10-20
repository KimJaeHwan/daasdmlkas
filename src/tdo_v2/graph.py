"""Deterministic Rustworkx graph facade used by V2 semantics."""

from __future__ import annotations

from .phases import count as phase_count
from .resource_limits import step

from collections import Counter
from typing import Iterable

import rustworkx as rx

from .graph_contracts import (
    DependencyGraph,
    EdgeKind,
    EdgeRecord,
    NodeId,
    NodeKind,
    NodeRecord,
)


CONTROL_DEPENDENCE_EDGE = EdgeKind.CONTROL_DEPENDENCE.value


class RustworkxDependencyGraph:
    """Integer-node graph with immutable payloads and stable key lookup."""

    def __init__(self) -> None:
        self._graph = rx.PyDiGraph(multigraph=True)
        self._nodes_by_key: dict[str, NodeId] = {}
        self._frozen = False
        self._claimed_namespaces: dict[str, None] = {}

    @property
    def node_count(self) -> int:
        return self._graph.num_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.num_edges()

    @property
    def is_frozen(self) -> bool:
        return self._frozen

    def add_node(self, record: NodeRecord) -> NodeId:
        if self._frozen:
            raise RuntimeError("graph is frozen")
        existing = self._nodes_by_key.get(record.key)
        if existing is not None:
            current = self.node(existing)
            if current != record:
                raise ValueError(f"node key reused with different payload: {record.key}")
            return existing
        node = int(self._graph.add_node(record))
        self._nodes_by_key[record.key] = node
        return node

    def node_for_key(self, key: str) -> NodeId | None:
        return self._nodes_by_key.get(key)

    def node(self, node: NodeId) -> NodeRecord:
        return self._graph[node]

    def has_node(self, node: NodeId) -> bool:
        return type(node) is int and self._graph.has_node(node)

    def claim_namespace(self, namespace: str) -> None:
        if self._frozen:
            raise RuntimeError("graph is frozen")
        if type(namespace) is not str or not namespace:
            raise TypeError("graph namespace must be a non-empty exact str")
        if namespace in self._claimed_namespaces:
            raise ValueError(f"graph namespace already materialized: {namespace}")
        self._claimed_namespaces[namespace] = None

    def add_edge(self, source: NodeId, target: NodeId, record: EdgeRecord) -> None:
        if self._frozen:
            raise RuntimeError("graph is frozen")
        if not self._graph.has_node(source) or not self._graph.has_node(target):
            raise KeyError("edge endpoint is not present")
        self._graph.add_edge(source, target, record)

    def freeze(self) -> None:
        self._frozen = True

    def copy(self) -> "RustworkxDependencyGraph":
        """An unfrozen copy with the same node ids (to extend it more than one way)."""
        other = RustworkxDependencyGraph.__new__(RustworkxDependencyGraph)
        other._graph = self._graph.copy()
        other._nodes_by_key = dict(self._nodes_by_key)
        other._frozen = False
        other._claimed_namespaces = dict(self._claimed_namespaces)
        return other

    def in_edges(self, node: NodeId):
        """(source, target, record) of the edges into ``node``, in the
        backend's order (rustworkx: reverse insertion) -- the one entry point
        for edge-level reads of a node (docs 25.31 B2-b)."""
        return self._graph.in_edges(node)

    def out_edges(self, node: NodeId):
        """(source, target, record) of the edges out of ``node``, in the
        backend's order."""
        return self._graph.out_edges(node)

    def predecessors(self, node: NodeId) -> tuple[NodeId, ...]:
        return tuple(sorted({int(item) for item in self._graph.predecessor_indices(node)}))

    def successors(self, node: NodeId) -> tuple[NodeId, ...]:
        return tuple(sorted({int(item) for item in self._graph.successor_indices(node)}))

    def backward_reachable(
        self,
        seeds: Iterable[NodeId],
        *,
        follow_control: bool = False,
    ) -> tuple[NodeId, ...]:
        """Nodes reaching ``seeds`` through data edges, plus control-dependence
        edges when ``follow_control`` is set (data-only is the default)."""
        pending = sorted(set(seeds), reverse=True)
        visited: set[NodeId] = set()
        ordered: list[NodeId] = []
        while pending:
            step()   # (budget: docs 25.30 K1c)
            node = pending.pop()
            if node in visited:
                continue
            if not self._graph.has_node(node):
                raise KeyError(f"unknown seed node: {node}")
            visited.add(node)
            ordered.append(node)
            if follow_control:
                predecessors = self.predecessors(node)
            else:
                predecessors = sorted({
                    int(source)
                    for source, _, record in self._graph.in_edges(node)
                    if record.kind != CONTROL_DEPENDENCE_EDGE
                })
            for predecessor in reversed(predecessors):
                if predecessor not in visited:
                    pending.append(predecessor)
        phase_count("backward_walks", 1)   # (K2 sizes: walks x reached nodes, docs 25.31)
        phase_count("backward_reached", len(ordered))
        return tuple(ordered)

    def weighted_edges(self) -> tuple[tuple[NodeId, NodeId, EdgeRecord], ...]:
        return tuple(
            sorted(
                (
                    (int(source), int(target), record)
                    for source, target, record in self._graph.weighted_edge_list()
                ),
                key=lambda item: (
                    item[0],
                    item[1],
                    item[2].kind,
                    item[2].operation or "",
                    -1 if item[2].occurrence is None else item[2].occurrence,
                    () if item[2].span is None else item[2].span.canonical_key,
                ),
            )
        )

    def incident_edge_multiplicities(
        self, nodes: Iterable[NodeId]
    ) -> dict[tuple[NodeId, NodeId, EdgeRecord], int]:
        owned = set(nodes)
        if any(
            type(node) is not int or not self._graph.has_node(node)
            for node in owned
        ):
            raise KeyError("incident edge query requires existing integer nodes")
        return dict(
            Counter(
                (int(source), int(target), record)
                for source, target, record in self._graph.weighted_edge_list()
                if source in owned or target in owned
            )
        )
