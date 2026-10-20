"""Edge-level graph reads go through the RustworkxDependencyGraph facade
(docs 25.31 B2-b): no module outside graph.py touches the rustworkx graph
behind it, so the facade can present edges it does not store physically."""

import re

import pytest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RAW = re.compile(r"\._graph\b")


def test_no_raw_graph_access_outside_the_facade():
    offenders = []
    for root in ("src", "tests", "tools"):
        for path in sorted((REPO / root).rglob("*.py")):
            if path.name == "graph.py" and path.parent.name == "tdo_v2" or path.name == "test_graph_facade.py":
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if RAW.search(line) and "self._graph" not in line:
                    offenders.append(f"{path.relative_to(REPO)}:{number}: {line.strip()}")
    assert not offenders, "raw graph access:\n" + "\n".join(offenders)


def test_the_facade_returns_the_backend_order():
    from tdo_v2.graph import RustworkxDependencyGraph
    from tdo_v2.graph_contracts import EdgeKind, EdgeRecord, NodeKind, NodeRecord

    graph = RustworkxDependencyGraph()
    nodes = [graph.add_node(NodeRecord(f"n{index}", NodeKind.OPERATION, "op")) for index in range(5)]
    for source in nodes[1:]:
        graph.add_edge(source, nodes[0], EdgeRecord(EdgeKind.MAY_ALIAS_WRITE, operation=f"w{source}"))
    graph.add_edge(nodes[0], nodes[4], EdgeRecord(EdgeKind.MAY_ALIAS_READ, operation="r"))
    assert [source for source, _, _ in graph.in_edges(nodes[0])] == [4, 3, 2, 1]   # reverse insertion
    assert [target for _, target, _ in graph.out_edges(nodes[0])] == [4]


def _twin_graphs(seed):
    """The same random graph twice: writer -> debt edges physical in one,
    virtual in the other (B2-b2), plus ordinary edges added before and after."""
    import random

    from tdo_v2.graph import RustworkxDependencyGraph, VirtualWriters
    from tdo_v2.graph_contracts import EdgeKind, EdgeRecord, NodeKind, NodeRecord
    from tdo_v2.label_sets import LabelUniverse

    rng = random.Random(seed)
    physical, virtual = RustworkxDependencyGraph(), RustworkxDependencyGraph()
    count = rng.randint(3, 25)
    for graph in (physical, virtual):
        for index in range(count):
            graph.add_node(NodeRecord(f"n{index}", NodeKind.OPERATION, "op"))
    plain = [(rng.randrange(count), rng.randrange(count), rng.choice(
        [EdgeKind.CONTROL_DEPENDENCE, EdgeKind.MAY_ALIAS_READ])) for _ in range(rng.randint(0, 3 * count))]
    for graph in (physical, virtual):
        for source, target, kind in plain[: len(plain) // 2]:
            graph.add_edge(source, target, EdgeRecord(kind, operation=f"o{source}"))
    writers = sorted(rng.sample(range(count), rng.randint(1, count)), key=lambda node: f"0:{node:x}:STORE")
    keys = [f"0:{node:x}:STORE" for node in writers]
    universe = LabelUniverse(keys)
    node_of = dict(zip(keys, writers))
    table = VirtualWriters(universe, [node_of[key] for key in universe.labels],
                           [EdgeRecord(EdgeKind.MAY_ALIAS_WRITE, operation=key) for key in universe.labels])
    debts = []
    for number in range(rng.randint(1, 6)):
        hard = sorted(rng.sample(keys, rng.randint(1, len(keys))))
        read = rng.randrange(count)
        for graph in (physical, virtual):
            debt = graph.add_node(NodeRecord(f"debt{number}", NodeKind.MEMORY_DEBT, "may_alias_read"))
            if graph is physical:
                for key in hard:
                    graph.add_edge(node_of[key], debt, table.records[universe.index_of[key]])
            else:
                graph.add_virtual_writers(debt, table, universe.mask(hard))
            graph.add_edge(debt, read, EdgeRecord(EdgeKind.MAY_ALIAS_READ, operation="r"))
        debts.append(debt)
    late = bool(debts) and rng.random() < 0.5
    for graph in (physical, virtual):
        for source, target, kind in plain[len(plain) // 2:]:
            graph.add_edge(source, target, EdgeRecord(kind, operation=f"o{source}"))
        if late:   # a later physical edge into a debt
            graph.add_edge(0, debts[0], EdgeRecord(EdgeKind.MAY_ALIAS_READ, operation="late"))
    return physical, virtual


@pytest.mark.parametrize("seed", range(150))
def test_virtual_writer_edges_read_as_the_physical_ones(seed):
    physical, virtual = _twin_graphs(seed)
    for graph in (physical, virtual.copy()):
        assert graph.edge_count == physical.edge_count
    assert virtual.edge_count == physical.edge_count
    assert virtual.weighted_edges() == physical.weighted_edges()
    nodes = range(physical.node_count)
    for node in nodes:
        assert list(virtual.in_edges(node)) == list(physical.in_edges(node))
        assert sorted(virtual.out_edges(node), key=repr) == sorted(physical.out_edges(node), key=repr)
        assert virtual.predecessors(node) == physical.predecessors(node)
        assert virtual.successors(node) == physical.successors(node)
        for control in (False, True):
            assert virtual.backward_reachable((node,), follow_control=control) == \
                physical.backward_reachable((node,), follow_control=control)
    owned = list(nodes)[: len(nodes) // 2]
    assert virtual.incident_edge_multiplicities(owned) == physical.incident_edge_multiplicities(owned)


def test_a_debt_out_edge_query_builds_no_reverse_index():
    """Astra B2-b2 P2: out_edges / successors of a node writing nothing
    virtually must not expand every virtual edge into an index."""
    physical, virtual = _twin_graphs(7)
    debt = next(iter(virtual._virtual))
    assert list(virtual.out_edges(debt)) == list(physical.out_edges(debt))
    assert virtual.successors(debt) == physical.successors(debt)
    assert virtual._virtual_out is None
