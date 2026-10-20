"""Edge-level graph reads go through the RustworkxDependencyGraph facade
(docs 25.31 B2-b): no module outside graph.py touches the rustworkx graph
behind it, so the facade can present edges it does not store physically."""

import re
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
