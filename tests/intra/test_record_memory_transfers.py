"""Expression records retain the graph-owned conditional transfer boundary."""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from test_memory_graph import _case
from tdo_v2 import call_summary_effects
from tdo_v2._load_identity import definition_identity
from tdo_v2.graph_contracts import EdgeKind, EdgeRecord
from tdo_v2.memory_graph import _materialize_local_memory_ssa
from tdo_v2.operation_records import (
    Ineligible, Limits, _Builder, _StitchCut, eligibility, evaluate, evaluate_physical,
    render, select_expression, simplify_expression,
)


class _FragmentBuilder:
    """Only the existing _Builder._fragments seam, with real SSA and graph."""

    def __init__(self, graph, ssa, bindings):
        self.graph, self.ssa = graph, ssa
        self.normalized = SimpleNamespace(memory_graph=bindings)
        self.index = SimpleNamespace(
            definition_node=bindings.definition_nodes,
            transfer_of=dict(zip(bindings.transfer_nodes, bindings.transfers, strict=True)),
            transfer_node={(row.definition_id, row.action_id, row.span): node
                           for row, node in zip(bindings.transfers, bindings.transfer_nodes, strict=True)},
        )
        self.records = [
            {"id": 0, "kind": "op", "opcode": "STORE", "key": "a:store", "operands": [],
             "output": {"size": 4}},
            {"id": 1, "kind": "op", "opcode": "STORE", "key": "b:other", "operands": [],
             "output": {"size": 4}},
        ]
        self.id_of = {}
        self.expanding = set()
        self.limits = Limits()
        self.edges = 0

    _fragments = _Builder._fragments
    _named = _Builder._named

    def _definition_guarded(self, node, depth):
        definition = self.index.definition_node.index(node)
        return (0 if definition == 1 else 1), 0, False

    def _new(self, key, record):
        record["id"] = len(self.records)
        self.records.append(record)
        self.id_of[key] = record["id"]
        return record

    def _done(self, record):
        return None

    def _edge(self):
        self.edges += 1

    def _unexplored(self, node):
        return False


def _fragment_case(*, transfer=True):
    graph, ssa, operations, row, second = _case()
    bindings = _materialize_local_memory_ssa(graph, ssa, operations, (row,) if transfer else ())
    builder = _FragmentBuilder(graph, ssa, bindings)
    read = next(item for item in ssa.reads if item.action_id == row.action_id)
    return builder, read, row, second


def _transfer_record(builder, read):
    parts = builder._fragments(read, None, 0)
    first = builder.records[parts[0]["node"]]
    return first, parts


def _root(builder, transfer):
    return {"version": 15, "record": "root", "truncated": False,
            "demand_complete": True, "function": "1:1000", "nodes": builder.records,
            "root": [{"node": transfer["id"], "bytes": [0, transfer["size"]],
                      "at": [0, transfer["size"]]}]}


def test_exact_fragment_record_keeps_writer_call_guard_and_ordinary_neighbor():
    builder, read, row, second = _fragment_case()
    transfer, parts = _transfer_record(builder, read)
    assert transfer["kind"] == "memory_transfer" and transfer["size"] == row.span.size == 4
    assert transfer["span"] == list(row.span.canonical_key)
    assert transfer["source_definition"] == row.definition_id
    assert transfer["source_operation"] == "a:store"
    assert (transfer["reader"], transfer["call"], transfer["guard"]) == \
        ("e:load", "c:call", "d:guard")
    assert transfer["contract"] == row.contract and transfer["requires"] == list(row.requires)
    assert transfer["graph_nodes"]["transfer"] == {
        "id": builder.normalized.memory_graph.transfer_nodes[0],
        "key": builder.graph.node(builder.normalized.memory_graph.transfer_nodes[0]).key,
    }
    assert transfer["graph_nodes"]["source"]["id"] == \
        builder.normalized.memory_graph.definition_nodes[row.definition_id]
    assert transfer["graph_nodes"]["reader"]["id"] == \
        builder.normalized.memory_graph.action_nodes[row.action_id]
    assert transfer["graph_nodes"]["call"]["key"] == "op:c:call"
    assert transfer["graph_nodes"]["guard"]["key"] == "op:d:guard"
    assert transfer["parts"] == [{"node": 0, "bytes": [0, 4], "at": [0, 4]}]
    assert parts[0] == {"node": transfer["id"], "bytes": [0, 4], "at": [0, 4]}
    assert parts[1] == {"node": 1, "bytes": [0, 4], "at": [4, 8]}
    assert read.fragments[1].span == second
    assert builder._fragments(read, frozenset(range(4, 8)), 0)[0] == {"pruned": True, "at": [0, 4]}
    assert json.loads(json.dumps(transfer))["parts"] == transfer["parts"]


def test_without_transfer_preserves_original_direct_writer_parts():
    builder, read, _, _ = _fragment_case(transfer=False)
    parts = builder._fragments(read, None, 0)
    assert parts == [{"node": 0, "bytes": [0, 4], "at": [0, 4]},
                     {"node": 1, "bytes": [0, 4], "at": [4, 8]}]
    assert not any(node["kind"] == "memory_transfer" for node in builder.records)


def test_transfer_is_a_structural_expression_boundary_not_numeric_copy():
    builder, read, _, _ = _fragment_case()
    transfer, _ = _transfer_record(builder, read)
    record = _root(builder, transfer)
    assert eligibility(record) == "memory transfer"
    assert "memory transfer" in render(record)
    assert "contract=lifecycle-contract:resize" in render(record)
    selected = select_expression(record)
    assert transfer["id"] in selected["nodes"] and transfer["parts"][0]["node"] in selected["nodes"]
    view = simplify_expression(record, selected)
    assert view["proof"]["status"] == "partial" and view["graph"] is None
    assert view["original_graph_retained"]

    def unreadable(*args):
        raise AssertionError("numeric callback must not be read")

    with pytest.raises(Ineligible, match="memory transfer"):
        evaluate(record, unreadable)
    with pytest.raises(Ineligible, match="memory transfer"):
        evaluate_physical(record, unreadable)


def test_transfer_graph_topology_tamper_refused_at_record_boundary():
    builder, read, row, _ = _fragment_case()
    node = builder.normalized.memory_graph.transfer_nodes[0]
    builder.graph.add_edge(builder.normalized.memory_graph.definition_nodes[2], node,
                           EdgeRecord(EdgeKind.MEMORY_TRANSFER, operation="e:load", span=row.span))
    with pytest.raises(ValueError, match="graph-owned topology"):
        builder._fragments(read, None, 0)
    assert not any(item["kind"] == "memory_transfer" for item in builder.records)


def test_stale_contract_binding_is_not_a_record_authority():
    builder, read, row, _ = _fragment_case()
    stale = replace(row, requires=(row.contract, "changed-dependency"))
    bindings = replace(builder.normalized.memory_graph, transfers=(stale,))
    builder = _FragmentBuilder(builder.graph, builder.ssa, bindings)
    with pytest.raises(ValueError, match="graph owner"):
        builder._fragments(read, None, 0)
    assert not any(item["kind"] == "memory_transfer" for item in builder.records)


def test_original_success_edge_and_result_definition_witnesses_remain_serializable():
    builder, read, row, _ = _fragment_case()
    witness = definition_identity(builder.ssa.definitions[1])
    enriched = replace(row, success_edge=("d:guard", "success"),
                       failure_edge=("d:guard", "failure"), result_definitions=(witness,))
    graph, ssa, operations, _, _ = _case()
    bindings = _materialize_local_memory_ssa(graph, ssa, operations, (enriched,))
    builder = _FragmentBuilder(graph, ssa, bindings)
    read = next(item for item in ssa.reads if item.action_id == enriched.action_id)
    transfer, _ = _transfer_record(builder, read)
    assert transfer["success_edge"] == ["d:guard", "success"]
    assert transfer["failure_edge"] == ["d:guard", "failure"]
    assert transfer["result_definitions"] == [{
        "kind": witness[0].value, "operation": witness[1], "write_ordinal": witness[2],
        "block": witness[3], "span": list(witness[4].canonical_key),
    }]
    json.dumps(transfer)


def test_stitched_memory_output_does_not_match_distinct_indexed_bases(monkeypatch):
    """A different index expression cannot name the same callee memory object."""
    _, _, _, _, memory_span = _case()
    write = SimpleNamespace(anchor="entry", pointer=None, index=SimpleNamespace(register="rdi"),
                            space_id=1, displacement=0, size=4)
    other = SimpleNamespace(anchor="entry", pointer=None, index=SimpleNamespace(register="rsi"),
                            space_id=1, displacement=0, size=4)
    monkeypatch.setattr(call_summary_effects, "anchored_span", lambda *args, **kwargs: other)
    builder = SimpleNamespace(binding=SimpleNamespace(anchors={}))
    summary = SimpleNamespace(
        exits=(SimpleNamespace(runs=(SimpleNamespace(span=memory_span),)),),
        address_relations=(),
    )
    with pytest.raises(_StitchCut, match="run not exact"):
        _Builder._stitched_memory_output(builder, SimpleNamespace(write=write), summary, "instance")
