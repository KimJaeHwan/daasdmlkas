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


def _edge_order(item):
    """``weighted_edges``' sort key."""
    return (
        item[0],
        item[1],
        item[2].kind,
        item[2].operation or "",
        -1 if item[2].occurrence is None else item[2].occurrence,
        () if item[2].span is None else item[2].span.canonical_key,
    )


class VirtualWriters:
    """The writers of one may-alias materialization (docs 25.31 B2-b): a
    LabelUniverse of their operation keys, each index's operation node and
    its one MAY_ALIAS_WRITE record. A debt node's writer edges are an int
    bitset over it (``add_virtual_writers``) instead of physical edges."""

    __slots__ = ("universe", "nodes", "records")

    def __init__(self, universe, nodes, records) -> None:
        self.universe = universe
        self.nodes = tuple(nodes)
        self.records = tuple(records)


class RustworkxDependencyGraph:
    """Integer-node graph with immutable payloads and stable key lookup.

    May-alias writer edges (writer operation -> may_alias_read debt) may be
    held virtually: per debt node an int bitset over a ``VirtualWriters``
    table. Every edge-level read of the facade -- ``in_edges``,
    ``out_edges``, ``predecessors``, ``successors``, ``backward_reachable``,
    ``weighted_edges``, ``edge_count``, ``incident_edge_multiplicities`` --
    presents them as the physical edges they stand for: the same tuples,
    counts and, where the backend defines one, order (docs 25.31 B2-b)."""

    def __init__(self) -> None:
        self._graph = rx.PyDiGraph(multigraph=True)
        self._nodes_by_key: dict[str, NodeId] = {}
        self._frozen = False
        self._claimed_namespaces: dict[str, None] = {}
        self._virtual: dict[NodeId, tuple] = {}   # debt -> (VirtualWriters, bits)
        self._virtual_edges = 0
        self._virtual_out = None   # writer -> [(debt, record)], built on demand
        self._virtual_sources: set = set()   # nodes of the tables in use (a superset of the writers)
        self._virtual_tables: set = set()   # ids of the tables already in _virtual_sources

    @property
    def node_count(self) -> int:
        return self._graph.num_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.num_edges() + self._virtual_edges

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

    def add_virtual_writers(self, debt: NodeId, writers: VirtualWriters, bits: int) -> None:
        """The writer edges into ``debt``: one per set bit, standing for
        ``add_edge(writers.nodes[i], debt, writers.records[i])`` in ascending
        index order, added right after the debt node and before any other
        edge into it."""
        if self._frozen:
            raise RuntimeError("graph is frozen")
        if type(writers) is not VirtualWriters or type(bits) is not int or bits < 0:
            raise TypeError("virtual writers require a VirtualWriters table and a non-negative int")
        if not self._graph.has_node(debt) or debt in self._virtual or self._graph.in_degree(debt):
            raise ValueError("virtual writers go on a fresh debt node, once")
        if bits >> len(writers.nodes):
            raise ValueError("virtual writer bit outside the table")
        if not bits:
            return
        self._virtual[debt] = (writers, bits)
        self._virtual_edges += bits.bit_count()
        if id(writers) not in self._virtual_tables:   # (once per table, not per debt -- Astra)
            self._virtual_tables.add(id(writers))
            self._virtual_sources.update(writers.nodes)
        self._virtual_out = None

    def _virtual_in(self, node: NodeId) -> list:
        """The virtual edges into ``node`` in insertion (ascending index) order."""
        found = self._virtual.get(node)
        if found is None:
            return []
        writers, bits = found
        return [(writers.nodes[index], node, writers.records[index]) for index in writers.universe.indices(bits)]

    def _virtual_out_of(self, node: NodeId) -> list:
        if node not in self._virtual_sources:   # (no index for a node writing nothing virtually)
            return []
        if self._virtual_out is None:
            index: dict = {}
            for debt, (writers, bits) in self._virtual.items():
                for position in writers.universe.indices(bits):
                    index.setdefault(writers.nodes[position], []).append((debt, writers.records[position]))
            self._virtual_out = index
        return self._virtual_out.get(node, [])

    def freeze(self) -> None:
        self._frozen = True

    def copy(self) -> "RustworkxDependencyGraph":
        """An unfrozen copy with the same node ids (to extend it more than one way)."""
        other = RustworkxDependencyGraph.__new__(RustworkxDependencyGraph)
        other._graph = self._graph.copy()
        other._nodes_by_key = dict(self._nodes_by_key)
        other._frozen = False
        other._claimed_namespaces = dict(self._claimed_namespaces)
        other._virtual = dict(self._virtual)   # (values immutable)
        other._virtual_edges = self._virtual_edges
        other._virtual_sources = set(self._virtual_sources)
        other._virtual_tables = set(self._virtual_tables)
        other._virtual_out = None
        return other

    def in_edges(self, node: NodeId):
        """(source, target, record) of the edges into ``node``, in the
        backend's order (rustworkx: reverse insertion) -- the one entry point
        for edge-level reads of a node (docs 25.31 B2-b)."""
        edges = self._graph.in_edges(node)
        if node not in self._virtual:
            return edges
        # the virtual writer edges were inserted first: last in reverse order
        return [*edges, *reversed(self._virtual_in(node))]

    def out_edges(self, node: NodeId):
        """(source, target, record) of the edges out of ``node``, in the
        backend's order; a writer's virtual edges follow its physical ones
        (in debt order) -- no consumer depends on a writer's out-edge order."""
        edges = self._graph.out_edges(node)
        if not self._virtual:
            return edges
        virtual = self._virtual_out_of(node)
        if not virtual:
            return edges
        return [*edges, *((node, debt, record) for debt, record in virtual)]

    def predecessors(self, node: NodeId) -> tuple[NodeId, ...]:
        found = {int(item) for item in self._graph.predecessor_indices(node)}
        if node in self._virtual:
            found.update(source for source, _, _ in self._virtual_in(node))
        return tuple(sorted(found))

    def successors(self, node: NodeId) -> tuple[NodeId, ...]:
        found = {int(item) for item in self._graph.successor_indices(node)}
        if self._virtual:
            found.update(debt for debt, _ in self._virtual_out_of(node))
        return tuple(sorted(found))

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
                    for source, _, record in self.in_edges(node)
                    if record.kind != CONTROL_DEPENDENCE_EDGE
                })
            for predecessor in reversed(predecessors):
                if predecessor not in visited:
                    pending.append(predecessor)
        phase_count("backward_walks", 1)   # (K2 sizes: walks x reached nodes, docs 25.31)
        phase_count("backward_reached", len(ordered))
        return tuple(ordered)

    def _all_edges(self):
        yield from ((int(source), int(target), record) for source, target, record in self._graph.weighted_edge_list())
        for debt in self._virtual:
            yield from self._virtual_in(debt)

    def weighted_edges(self) -> tuple[tuple[NodeId, NodeId, EdgeRecord], ...]:
        return tuple(sorted(self._all_edges(), key=_edge_order))

    def physical_weighted_edges(self) -> tuple[tuple[NodeId, NodeId, EdgeRecord], ...]:
        """``weighted_edges`` without the virtual writer edges (same order)."""
        return tuple(sorted(
            ((int(source), int(target), record) for source, target, record in self._graph.weighted_edge_list()),
            key=_edge_order))

    def virtual_debts(self) -> tuple[NodeId, ...]:
        """The nodes with virtual writer edges into them."""
        return tuple(self._virtual)

    def virtual_sources(self, node: NodeId) -> list:
        """The sources of ``node``'s virtual writer edges, ascending node id
        (decoded on each call -- nothing retained)."""
        return sorted(source for source, _, _ in self._virtual_in(node))

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
                (source, target, record)
                for source, target, record in self._all_edges()
                if source in owned or target in owned
            )
        )
