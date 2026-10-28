"""Call-clobber debt per (read, crossing call) (docs 25.83 S2d D2/D3'): one
node per pair, the call named by the key only (no edge from the call), public
completeness counting each read once, discharge per pair on the pair's rows."""

from dataclasses import replace

import pytest

from synthetic import CODE_BASE, RAX, RCX, RDI, FunctionBuilder, copy, program_units, reg
from tdo_v2.call_clobber import debt_identity, debt_pairs, rows_by_debt
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.integration.configured_call_clobber_discharge import CallClobberDischarger, DischargeKind
from tdo_v2.interprocedural import analyze_units
from tdo_v2.query import BackwardSliceQuery
from tdo_v2.query_contracts import effective_completeness, local_completeness

F, G = CODE_BASE + 0x900, CODE_BASE + 0xA00


def _two_calls():
    """rax = rdi; CALL f; CALL g; rcx = rax -- the last COPY crosses both."""
    builder = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RAX), reg(RDI)))
               .call(F).call(G)
               .ins(copy(reg(RCX), reg(RAX))).add_rsp(0x28).ret())
    (unit,) = program_units(builder)
    normalized = analyze_units([unit])["1:1000"].normalized
    pairs = [(row, call, node) for row, call, node in debt_pairs(normalized.call_clobber_reads,
                                                                  normalized.call_clobber_debts)
             if row.operation_key.endswith(":COPY") and len(row.intervening_calls) == 2]
    return normalized, pairs


def test_a_read_crossing_two_calls_has_a_debt_node_per_call():
    normalized, pairs = _two_calls()
    assert len(pairs) == 2
    (row, _, _), _ = pairs
    graph = normalized.dependencies
    reader = graph.node_for_key(f"op:{row.operation_key}")
    assert [call for _, call, _ in pairs] == list(row.intervening_calls)
    assert len({node for _, _, node in pairs}) == 2
    for _, call, node in pairs:
        record = graph.node(node)
        assert record.kind is NodeKind.MEMORY_DEBT and record.label == "call_clobber_read"
        assert record.key.endswith(f":{row.operation_key}|{call}")
        assert not graph.in_edges(node)   # (the call is named, never an input)
        assert [target for _, target, _ in graph.out_edges(node)] == [reader]


def test_the_debts_must_name_the_read_and_its_calls_in_order():
    normalized, pairs = _two_calls()
    index = normalized.call_clobber_reads.index(pairs[0][0])
    swapped = list(normalized.call_clobber_debts)
    swapped[index] = swapped[index][::-1]
    with pytest.raises(ValueError, match="does not match its read and call"):
        replace(normalized, call_clobber_debts=tuple(swapped))
    short = list(normalized.call_clobber_debts)
    short[index] = short[index][:1]
    with pytest.raises(ValueError, match="align with the read's calls"):
        replace(normalized, call_clobber_debts=tuple(short))


def test_completeness_counts_a_read_once_and_discharges_it_per_pair():
    normalized, pairs = _two_calls()
    (row, _, f_node), (_, _, g_node) = pairs
    graph = normalized.dependencies
    result = BackwardSliceQuery().run(normalized, graph.node_for_key(f"op:{row.operation_key}"))
    assert {f_node, g_node} <= set(result.reachable_unresolved_read_nodes)
    identity = debt_identity(normalized.call_clobber_reads, normalized.call_clobber_debts)
    plain = local_completeness((result,))
    counted = local_completeness((result,), identity)
    assert counted.reachable_unresolved_reads == plain.reachable_unresolved_reads - 1
    # the read stays a debt while either of its pairs does
    for discharged in (frozenset(), frozenset({f_node}), frozenset({g_node})):
        assert effective_completeness((result,), discharged, identity).reachable_unresolved_reads \
            == counted.reachable_unresolved_reads
    both = effective_completeness((result,), frozenset({f_node, g_node}), identity)
    assert both.reachable_unresolved_reads == counted.reachable_unresolved_reads - 1


def test_the_discharger_judges_each_row_once_per_discharge():
    normalized, pairs = _two_calls()
    rows, debts = normalized.call_clobber_reads, normalized.call_clobber_debts
    discharger = CallClobberDischarger.__new__(CallClobberDischarger)
    discharger._clobber_rows = {"f": rows_by_debt(rows, debts)}
    discharger._judged = {}
    judged = []
    discharger._discharge_read = lambda entry, read, context, active: judged.append(read) or (
        DischargeKind.PRESERVED,)
    found = discharger.discharge("f", ())
    assert {row.debt_node for row in found} == {node for nodes in debts for node in nodes}
    assert sorted(map(id, judged)) == sorted(map(id, rows))   # (two pair nodes, one judgement of their row)
    judged.clear()
    discharger.discharge("f", ())   # (a new discharge judges again)
    assert len(judged) == len(rows)
