"""Arbitrary cyclic expression structure is independent of value evaluation."""

import copy as copying
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from synthetic import CF, R8, R9, RAX, RBX, RCX, RDX, FunctionBuilder, add, const, copy, op, reg, tmp
from test_operation_records import _analyzed
from test_record_recurrence import _loop, _unsupported
from tdo_v2 import _record_cycles
from tdo_v2.lane_slice import lane_index
from tdo_v2.operation_records import Limits, eligibility, evaluate, render, run_records
from tdo_v2.pcode_blocks import build_pcode_block_graph
from tdo_v2.resource_limits import AnalysisBudgetExceeded


def _record(analyzed, register, size=8, **options):
    for record in run_records(analyzed.normalized, analyzed.unit, analyzed.summary, **options):
        place = record['place']
        if place['kind'] == 'register_file' and place['start'] == register and place['size'] >= size:
            return record
    raise KeyError(register)


def _graph(analyzed, register=RBX, **options):
    record = _record(analyzed, register, **options)
    return record, record['cycle_graph']


def _assert_original(record, graph, analyzed):
    cfg = build_pcode_block_graph(analyzed.unit.observation, analyzed.unit.scopes.function.entry)
    assert {row['key'] for row in graph['cfg']['blocks']} == {row.key for row in cfg.blocks}
    assert {(row['source'], row['target']) for row in graph['cfg']['edges']} == {
        (row.key, target) for row in cfg.blocks for target in row.successors}
    assert graph['coverage']['cfg_complete'] and graph['coverage']['ssa_cfg_matches']
    assert graph['coverage']['expression_complete'], graph['coverage']
    assert graph['evaluation'] == 'structural_only'
    lane = lane_index(analyzed.normalized, analyzed.unit)
    assert {row['reference']['id'] for row in graph['definitions']} == set(range(len(lane.ssa.definitions)))
    assert {row['reference']['id']: tuple(item['reference']['id'] for item in row['sources'])
            for row in graph['joins']} == lane.joins
    for join in graph['joins']:
        definition = lane.ssa.definitions[join['reference']['id']]
        assert join['read_block'] == definition.block_key
        assert join['span'] == list(definition.span.canonical_key)
    for state in graph['edge_states']:
        edge = graph['cfg']['edges'][state['edge']]
        original = [row for row in lane.ssa.flow_edges
                    if (row.predecessor_key, row.block_key) == (edge['source'], edge['target'])]
        assert state['evidence'] == ('captured' if original else 'not_captured')
        assert [(row['span'], row['definition_ids']) for row in state['facts']] == [
            (list(row.span.canonical_key), list(row.definition_ids)) for row in original]
        for fact in state['facts']:
            assert [row['reference']['id'] for row in fact['definitions']] == fact['definition_ids']
    ids = {node['id'] for node in record['nodes']}

    def references(value):
        if isinstance(value, dict):
            if 'node' in value and value['node'] is not None:
                assert value['node'] in ids
            for child in value.values():
                references(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                references(child)

    references(graph)
    assert json.loads(json.dumps(record))['cycle_graph']['cfg'] == graph['cfg']


@pytest.mark.parametrize('shape', ('multi_latch', 'nested', 'irreducible', 'horizontal'))
@pytest.mark.parametrize('engine', ('dense', 'sparse'))
def test_general_graph_does_not_reject_complex_cycle_shapes(monkeypatch, shape, engine):
    monkeypatch.setenv('TDO_V2_MEMORY_SSA_ENGINE', engine)
    analyzed = _analyzed(_unsupported(shape))
    record, graph = _graph(analyzed)
    _assert_original(record, graph, analyzed)
    if shape == 'nested':
        assert any(row['parent'] is not None for row in graph['cycle_hierarchy'])
    elif shape == 'irreducible':
        assert any(len(row['entry_points']) > 1 for row in graph['cycle_hierarchy'])
    elif shape == 'horizontal':
        assert sum(row['cyclic'] for row in graph['components']) == 2
        assert any(len(row['sources']) > 2 for row in graph['joins'])
    assert eligibility(record) == 'loop'


def test_function_entry_cycle_does_not_require_an_invented_external_predecessor():
    flag = tmp(0x400, 1)
    builder = (FunctionBuilder().label('top').cbranch('end', flag, op('INT_EQUAL', [reg(R9), const(0)], flag))
               .ins(add(reg(RAX), reg(RAX), const(1))).branch('top')
               .label('end').ins(copy(reg(RBX), reg(RAX))).ret())
    analyzed = _analyzed(builder)
    record, graph = _graph(analyzed)
    _assert_original(record, graph, analyzed)
    region = next(row for row in graph['cycle_hierarchy'] if row['parent'] is None)
    assert graph['cfg']['entry'] in region['entry_points'] and not region['entry_edges']


def test_absent_sparse_state_is_not_an_empty_or_singleton_state(monkeypatch):
    analyzed = _analyzed(_loop())
    original = _record_cycles.CycleIndex

    def without_flow(normalized, unit, index):
        view = copying.copy(index)
        view.ssa = replace(index.ssa, flow_edges=())
        return original(normalized, unit, view)

    monkeypatch.setattr(_record_cycles, 'CycleIndex', without_flow)
    record, graph = _graph(analyzed)
    assert graph['coverage']['expression_complete']
    assert graph['edge_states'] and all(row['evidence'] == 'not_captured' and row['facts'] == []
                                        for row in graph['edge_states'])
    assert graph['joins'] and eligibility(record) == 'loop'


def test_cycle_projection_does_not_change_an_unrelated_value_or_existing_nodes(monkeypatch):
    builder = (FunctionBuilder().ins(copy(reg(R8, 1), reg(RCX, 1))).label('top')
               .ins(add(reg(R9), reg(R9), const(1))).cbranch('top', reg(CF, 1)).ret())
    analyzed = _analyzed(builder)
    record, graph = _graph(analyzed, R8, size=1)
    assert graph['coverage']['expression_complete']
    monkeypatch.setattr(_record_cycles, 'publish_cycle_graph', lambda builder: None)
    original = _record(analyzed, R8, size=1)
    assert record['root'] == original['root']
    assert record['nodes'][:len(original['nodes'])] == original['nodes']
    assert eligibility(record) == eligibility(original)

    def entry(node):
        return 0x7f if isinstance(node, dict) and node.get('register', {}).get('offset') == RCX else None

    assert evaluate(record, entry) == evaluate(original, entry) == {0x7f}


@pytest.mark.parametrize('kind', ('nodes', 'edges', 'depth', 'demand_steps'))
def test_cycle_limits_are_explicit_and_never_change_the_primary_result(monkeypatch, kind):
    builder = (FunctionBuilder().ins(copy(reg(R8), const(13))).label('top')
               .ins(add(reg(R9), reg(R9), const(1))).cbranch('top', reg(CF, 1)).ret())
    analyzed = _analyzed(builder)
    for value in (1, 3, 8, 20):
        limits = Limits(**{kind: value})
        record, graph = _graph(analyzed, R8, limits=limits)
        with monkeypatch.context() as scope:
            scope.setattr(_record_cycles, 'publish_cycle_graph', lambda builder: None)
            original = _record(analyzed, R8, limits=limits)
        assert record['root'] == original['root']
        assert record['nodes'][:len(original['nodes'])] == original['nodes']
        assert record['truncated'] == original['truncated']
        assert eligibility(record) == eligibility(original)
        assert graph['coverage']['cfg_complete']
        ids = {node['id'] for node in record['nodes']}
        assert all(identifier in ids for identifier in graph.get('expression_nodes', ()))


def test_each_cyclic_predicate_is_per_visit_not_a_static_control_choice():
    analyzed = _analyzed(_loop())
    record, graph = _graph(analyzed)
    assert graph['predicates']
    for predicate in graph['predicates']:
        assert predicate['evaluation'] == 'per_visit_expression'
        assert predicate['operand']['parts'] and 'selection' not in predicate
        assert predicate['operation'] not in record.get('control', {}).get('decisions', {})


def test_text_view_exposes_every_original_edge_and_expression_definitions():
    record, graph = _graph(_analyzed(_unsupported('irreducible')))
    text = render(record)
    assert 'structural only' in text and 'per-visit ' in text
    for index, edge in enumerate(graph['cfg']['edges']):
        assert f"edge {index} {edge['source']} -> {edge['target']} [" in text
    for row in graph['definitions']:
        assert f"definition d{row['reference']['id']} = " in text
    assert 'not_captured' in text


def test_unknown_memory_occurrences_are_preserved_without_claiming_known_values():
    builder = (FunctionBuilder().ins(copy(reg(R8), const(13))).label('top')
               .ins(op('LOAD', [const(0x999), reg(RCX)], reg(RAX)),
                    op('STORE', [const(0x999), reg(RDX), reg(RAX)]))
               .cbranch('top', reg(CF, 1)).ret())
    analyzed = _analyzed(builder)
    record, graph = _graph(analyzed, R8)
    _assert_original(record, graph, analyzed)
    ssa = analyzed.normalized.memory_ssa
    assert len(ssa.unresolved_reads) == len(ssa.unresolved_writes) == 1
    unknowns = graph['coverage']['unknown_inputs']
    assert unknowns['unresolved_reads'] == unknowns['unresolved_writes'] == 1
    assert unknowns['projection_debt_nodes'] > 0
    assert graph['coverage']['numeric_evaluation'] == 'not_provided'
    assert [row['kind'] for row in graph['unresolved_accesses']] == ['read', 'write']
    for row, original in zip(graph['unresolved_accesses'], (*ssa.unresolved_reads, *ssa.unresolved_writes), strict=True):
        assert row['action_id'] == original.action_id
        assert row['operation'] == ssa.actions[original.action_id].operation_key
        assert row['occurrence_ordinal'] == original.occurrence_ordinal
        assert row['width'] == original.access.width
        assert row['address'] == _record_cycles._storage(original.access.address)
        assert row['raw_address'] == _record_cycles._storage(original.access.raw_address)
        assert row['node'] is not None
    text = render(record)
    assert 'unresolved read ' in text and 'unresolved write ' in text


def test_projection_rollback_retains_raw_unknown_inventory_without_dangling_nodes(monkeypatch):
    builder = (FunctionBuilder().ins(copy(reg(R8), const(13))).label('top')
               .ins(op('LOAD', [const(0x999), reg(RCX)], reg(RAX)))
               .cbranch('top', reg(CF, 1)).ret())
    analyzed = _analyzed(builder)
    original_materialize = _record_cycles._materialize

    def fail_after_materializing(graph, view, index):
        original_materialize(graph, view, index)
        raise ValueError('rollback injection')

    monkeypatch.setattr(_record_cycles, '_materialize', fail_after_materializing)
    record, graph = _graph(analyzed, R8)
    assert not graph['coverage']['expression_complete']
    assert graph['coverage']['expression_reason'] == 'rollback injection'
    assert all(not node.get('cycle_only') for node in record['nodes'])
    assert graph['operations'] == graph['definitions'] == graph['reads'] == graph['joins'] == []
    assert graph['unresolved_accesses'] and all(row['node'] is None for row in graph['unresolved_accesses'])
    assert graph['predicates'] and all(row['operand'] is None for row in graph['predicates'])
    assert all(not fact['definitions'] for row in graph['edge_states'] for fact in row['facts'])


def test_nested_outline_edge_scans_are_charged_to_existing_work_budget(monkeypatch):
    analyzed = _analyzed(_unsupported('nested'))
    index = _record_cycles.CycleIndex(analyzed.normalized, analyzed.unit, lane_index(analyzed.normalized, analyzed.unit))
    charges = []
    monkeypatch.setattr(_record_cycles, 'step', lambda amount=1: charges.append(amount))
    graph = index.outline(SimpleNamespace(path=()))
    edge_cost = 3 * len(graph['cfg']['edges'])
    for region in graph['cycle_hierarchy']:
        assert edge_cost + len(region['blocks']) in charges

    def exhausted(amount=1):
        if amount >= edge_cost:
            raise AnalysisBudgetExceeded('work')

    monkeypatch.setattr(_record_cycles, 'step', exhausted)
    with pytest.raises(AnalysisBudgetExceeded):
        index.outline(SimpleNamespace(path=()))
