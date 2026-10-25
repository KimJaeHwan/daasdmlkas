"""Actual resize graph -> original operation-expression record integration.

Copied bytes retain their source STORE expression and explicit CALL/guard/
contract authority. A transfer is deliberately not an unconditional COPY:
numeric evaluation and local BV simplification remain unsupported/partial.
The original p-code/outcome oracle checks live in the unchanged base module.
"""

from copy import deepcopy
from dataclasses import replace

import pytest

from test_realloc_contents_binary import (
    GROW, SHRINK, PARTIAL, OPAQUE, POINTS, PATCH, BARRIER,
    binary, static_engine, static_results, _key, _copy_proofs, _payload_read,
)
from test_allocation_lifetime_binary import FUNCTION, REALLOC, _analyze
from test_forward_memory_footprints_binary import actual, REPO
from tdo_v2.lifecycle_contracts import load_lifecycle_contracts
from tdo_v2.operation_records import Ineligible, eligibility, evaluate, root_record, simplify_expression
from tdo_v2.query import BackwardSliceQuery


def _load_record(item, reader):
    normalized = item.normalized
    ssa, bindings = normalized.memory_ssa, normalized.memory_graph
    (action,) = [row for row in ssa.actions if row.operation_key == reader]
    assert action.write_definition_ids
    return root_record(normalized, item.unit,
        [(bindings.definition_nodes[identifier], (ssa.definitions[identifier].span,))
         for identifier in action.write_definition_ids])


def _load_node(record, reader):
    (node,) = [row for row in record["nodes"] if row.get("key") == reader and row.get("opcode") == "LOAD"]
    return node


def _memory_parts(record, reader):
    return [part for memory in _load_node(record, reader)["memory"] for part in memory["parts"]]


def _transfer_nodes(record):
    return [row for row in record["nodes"] if row["kind"] == "memory_transfer"]


def _assert_records_retain_transfers(item, reader, record):
    proofs = _copy_proofs(item, reader)
    transfers = _transfer_nodes(record)
    assert proofs and len(transfers) == len(proofs)
    normalized, ssa = item.normalized, item.normalized.memory_ssa
    parts = _memory_parts(record, reader)
    assert not record["truncated"] and record["demand_complete"]
    for proof in proofs:
        # Exact source, fragment, reader, CALL, and guard authority: metadata
        # about a different transfer is not interchangeable with this one.
        rows = [row for row in transfers if row["source_operation"] == proof.source[1]
                and row["size"] == proof.span.size]
        assert len(rows) == 1
        transfer = rows[0]
        assert transfer["contract"] == proof.contract and tuple(transfer["requires"]) == proof.requires
        assert transfer["reader"] == reader and transfer["call"] == proof.call
        assert transfer["guard"] == proof.outcome.guard
        raw = [row for row in normalized.memory_graph.transfers
               if ssa.actions[row.action_id].operation_key == reader and row.span == proof.span]
        assert len(raw) == 1
        index = normalized.memory_graph.transfers.index(raw[0])
        assert transfer["graph_nodes"]["transfer"]["id"] == normalized.memory_graph.transfer_nodes[index]
        definition = ssa.definitions[raw[0].definition_id]
        assert transfer["source_definition"] == raw[0].definition_id
        assert transfer["source_operation"] == definition.operation_key
        assert transfer["span"] == list(proof.span.canonical_key)
        expected_nodes = {
            "source": normalized.memory_graph.definition_nodes[raw[0].definition_id],
            "reader": normalized.memory_graph.action_nodes[raw[0].action_id],
            "call": normalized.dependencies.node_for_key("op:" + proof.call),
            "guard": normalized.dependencies.node_for_key("op:" + proof.outcome.guard),
            "transfer": normalized.memory_graph.transfer_nodes[index],
        }
        assert transfer["graph_nodes"] == {
            name: {"id": node, "key": normalized.dependencies.node(node).key}
            for name, node in expected_nodes.items()
        }
        assert transfer["success_edge"] == list(proof.outcome.success_edge)
        assert transfer["failure_edge"] == list(proof.outcome.failure_edge)
        assert transfer["result_definitions"] == [
            {"kind": kind.value, "operation": operation, "write_ordinal": ordinal,
             "block": block, "span": list(span.canonical_key)}
            for kind, operation, ordinal, block, span in proof.result_definitions
        ]
        assert transfer["result_definitions"]
        (source_part,) = transfer["parts"]
        producer = record["nodes"][source_part["node"]]
        assert producer["kind"] == "op" and producer["opcode"] == "STORE"
        assert producer["key"] == proof.source[1] and producer["operands"]
        assert source_part["at"] == [0, proof.span.size]
        start = proof.span.start - definition.span.start
        assert source_part["bytes"] == [start, start + proof.span.size]
        attached = [part for part in parts if part.get("node") == transfer["id"]]
        assert len(attached) == 1
        assert attached[0]["bytes"] == [0, proof.span.size]
        read = _payload_read(item, reader)
        offset = proof.span.start - read.span.start
        assert attached[0]["at"] == [offset, offset + proof.span.size]


@pytest.mark.parametrize("function", (GROW, SHRINK, PARTIAL))
def test_actual_writer_transfer_load_keeps_formula_and_byte_authority(binary, static_results, function):
    _, after = static_results
    item = after[function]
    reader = _key(POINTS[function][2], "LOAD")
    record = _load_record(item, reader)
    original = deepcopy(record)
    _assert_records_retain_transfers(item, reader, record)
    transfers = _transfer_nodes(record)
    assert sorted(row["size"] for row in transfers) == ([2, 4] if function == PARTIAL else [4, 4])
    if function == PARTIAL:
        parts = _memory_parts(record, reader)
        (patch,) = [part for part in parts if record["nodes"][part["node"]].get("key") == PATCH]
        assert patch["at"] == [2, 4] and patch["bytes"] == [0, 2]
        debts = [row for row in item.normalized.call_clobber_reads if row.operation_key == reader]
        assert len(debts) == 1 and sum(span.size for span in debts[0].spans) == 2
        assert debts[0].intervening_calls == (_key(POINTS[function][1], "CALL"),)
        assert _load_node(record, reader).get("debts")
    else:
        assert eligibility(record) == "memory transfer"
    # No unconditional value-copy interpretation through the new authority.
    assert eligibility(record) is not None
    with pytest.raises(Ineligible):
        evaluate(record, lambda *args: pytest.fail("unsupported transfer read an injected input"))
    view = simplify_expression(record)
    assert view["proof"]["status"] == "partial" and view["graph"] is None
    assert view["original_graph_retained"] and record == original


def test_actual_unknown_call_keeps_expression_debt_without_inventing_transfer(binary, static_results):
    _, after = static_results
    item, reader = after[OPAQUE], _key(POINTS[OPAQUE][2], "LOAD")
    record = _load_record(item, reader)
    assert not _transfer_nodes(record)
    assert _load_node(record, reader).get("debts") and eligibility(record) is not None
    debts = [row for row in item.normalized.call_clobber_reads if row.operation_key == reader]
    assert BARRIER in {call for row in debts for call in row.intervening_calls}
    before = deepcopy(record)
    assert simplify_expression(record)["proof"]["status"] == "partial"
    assert record == before


def test_original_suite09_transfer_retains_source_a_expression_and_independent_debts(actual, static_engine):
    contracts = load_lifecycle_contracts(REPO / "models/lifecycle/glibc_sysv64.json")
    weak = tuple(replace(row, contents="unknown") if row.kind == "resize" else row for row in contracts)
    before = _analyze(actual, weak)[FUNCTION]
    item = _analyze(actual, contracts)[FUNCTION]
    reader = "1b1:104a4e:0:LOAD"
    record = _load_record(item, reader)
    _assert_records_retain_transfers(item, reader, record)
    (transfer,) = _transfer_nodes(record)
    assert transfer["size"] == 4 and transfer["source_operation"] == "1b1:104a1d:1:STORE"
    assert transfer["call"] == REALLOC
    assert any(row.get("call") == "1b1:104a14:2:CALL" for row in record["nodes"])
    assert any(row["kind"] == "debt" for row in record["nodes"])
    assert eligibility(record) is not None
    snapshot = deepcopy(record)
    assert simplify_expression(record)["proof"]["status"] == "partial" and record == snapshot

    def debts(result):
        graph = result.normalized.dependencies
        query = BackwardSliceQuery().run(result.normalized, graph.node_for_key("op:" + reader))
        return {graph.node(node).key for node in query.reachable_unresolved_read_nodes}

    independent = {key for key in debts(before) if "104a14:2:CALL" in key}
    assert independent and independent <= debts(item)
