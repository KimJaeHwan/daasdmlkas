"""Recurrence metadata describes original CFG/SSA edges, never loop execution."""

import copy as copying
import json
import sys
from dataclasses import replace
from types import SimpleNamespace

import pytest

from synthetic import (
    CF, R8, R9, RAX, RBX, RCX, RDX, RSI, FunctionBuilder, add, const, copy, op, ram, reg, tmp,
)
from test_operation_record_shapes import _branchy
from test_operation_records import _analyzed, _record
from tdo_v2._record_recurrence import RecurrenceIndex
from tdo_v2.lane_slice import lane_index
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.operation_records import Ineligible, Limits, eligibility, evaluate, run_records
from tdo_v2.resource_limits import AnalysisBudgetExceeded


def _loop(*, narrow_prefix=False, initialize=True):
    builder = FunctionBuilder()
    if narrow_prefix:
        builder.ins(copy(reg(RAX, 4), reg(RSI, 4)))
    if initialize:
        builder.ins(copy(reg(RAX), reg(RCX)))
    else:
        builder.ins(copy(reg(R9), reg(RCX)))  # real external predecessor, RAX remains ENTRY
    flag = tmp(0x300, 1)
    return (builder.label('header')
            .cbranch('exit', flag, op('INT_LESSEQUAL', [reg(RDX), reg(RAX)], flag))
            .ins(add(reg(RAX), reg(RAX), const(1))).branch('header')
            .label('exit').ins(copy(reg(RBX), reg(RAX))).ret())


def _index(builder):
    analyzed = _analyzed(builder)
    lane = lane_index(analyzed.normalized, analyzed.unit)
    return analyzed, lane, RecurrenceIndex(analyzed.normalized, analyzed.unit, lane)


def _joins(lane, register=RAX, size=8):
    return [identifier for identifier in lane.joins
            if lane.ssa.definitions[identifier].span.start == register
            and lane.ssa.definitions[identifier].span.size == size]


def _evidence_view(analyzed, lane, edges):
    """Redact diagnostic edge evidence, not the normalized SSA or its receipt."""
    view = copying.copy(lane)
    view.ssa = replace(lane.ssa, flow_edges=tuple(sorted(edges, key=lambda row: row.canonical_key)))
    return RecurrenceIndex(analyzed.normalized, analyzed.unit, view)


@pytest.mark.parametrize('engine', ('dense', 'dense-unchained', 'sparse'))
def test_original_header_edges_explain_header_body_and_exit_read_joins(monkeypatch, engine):
    monkeypatch.setenv('TDO_V2_MEMORY_SSA_ENGINE', engine)
    _, lane, index = _index(_loop())
    matches = [index.for_join(identifier) for identifier in _joins(lane)]
    assert len(matches) == 3 and all(reason is None for _, reason in matches)
    assert {match.read_block for match, _ in matches} == {'1:1004', '1:1008', '1:1010'}
    for match, _ in matches:
        assert match.header == '1:1004' and match.latch == '1:100c'
        assert lane.ssa.definitions[match.init_definition_id].operation_key == '1:1000:0:COPY'
        assert lane.ssa.definitions[match.transition_definition_id].operation_key == '1:1008:0:INT_ADD'
        assert match.init_edges and match.transition_edges
        for edges, predecessor, identifier in ((match.init_edges, '1:1000', match.init_definition_id),
                                                (match.transition_edges, '1:100c', match.transition_definition_id)):
            assert all(edge in lane.ssa.flow_edges and edge.block_key == match.header
                       and edge.predecessor_key == predecessor and edge.definition_ids == (identifier,)
                       for edge in edges)
        (condition,) = match.conditions
        assert condition.operation == '1:1004:1:CBRANCH'
        assert (condition.true_successor, condition.false_successor) == ('1:1010', '1:1008')
        assert match.exits == (('1:1004', '1:1010'),)
    (seed,) = index.condition_seeds()
    assert lane.graph.node(seed[0]).key == 'op:1:1004:1:CBRANCH' and seed[1] == ()


def test_serialized_recurrence_keeps_old_phi_and_existing_expression_references(monkeypatch):
    import tdo_v2._record_recurrence as module

    analyzed, lane, _ = _index(_loop())
    record = _record(analyzed, RBX)
    recurrences = [node for node in record['nodes'] if 'recurrence' in node]
    assert len(recurrences) >= 2 and not record['truncated']
    assert len({node['recurrence']['id'] for node in recurrences}) == 1
    assert any(node['recurrence']['read_block'] != node['recurrence']['header'] for node in recurrences)
    for node in recurrences:
        metadata = node['recurrence']
        assert metadata['evaluation'] == 'structural_only'
        assert metadata['scope'] == lane.ssa.function_scope.digest.hex()
        assert metadata['unit'] == lane.ssa.unit_digest.hex()
        for relation in (metadata['init'], metadata['transition']):
            assert relation['part'] in node['alternatives']
            reference = relation['definition_ref']
            assert reference == relation['part']['definition_ref']
            definition = lane.ssa.definitions[reference['id']]
            assert reference['operation'] == definition.operation_key
            assert reference['span'] == list(definition.span.canonical_key)
            assert metadata['span'] == list(lane.ssa.definitions[_joins(lane)[0]].span.canonical_key)
        (condition,) = metadata['conditions']
        assert condition['operand']['width'] == 1 and condition['operand']['parts']
        assert not condition['operand'].get('pruned') and not condition['operand'].get('unresolved')
        assert all(0 <= part['node'] < len(record['nodes']) for part in condition['operand']['parts'])
        producer = record['nodes'][condition['operand']['parts'][0]['node']]
        assert producer.get('key') == '1:1004:0:INT_LESSEQUAL'
        assert metadata['exits'] == [dict(predecessor='1:1004', successor='1:1010')]
    # No Python reference cycles or non-JSON evidence handles were introduced.
    assert json.loads(json.dumps(record))['nodes']
    for route in ('injected', 'stitched'):
        assert eligibility(record, route=route) == 'loop'
        with pytest.raises(Ineligible, match='loop'):
            evaluate(record, lambda node: 0, route=route)
    monkeypatch.setattr(module, 'annotate_recurrence', lambda *args: None)
    original = _record(analyzed, RBX)

    def old_alternatives(value):
        return [(node.get('span'), [(part.get('definition_ref'), part.get('loop'), part.get('bytes'), part.get('at'))
                                   for part in node['alternatives']])
                for node in value['nodes'] if node.get('reason') == 'join' and not node.get('condition_only')]

    assert old_alternatives(record) == old_alternatives(original)
    assert eligibility(original) == eligibility(record) == 'loop'


def test_entry_definition_is_an_initial_value_only_with_a_real_external_edge():
    _, lane, index = _index(_loop(initialize=False))
    match, reason = index.for_join(_joins(lane)[0])
    assert reason is None and lane.ssa.definitions[match.init_definition_id].kind is MemoryDefinitionKind.ENTRY
    assert all(edge.predecessor_key == '1:1000' for edge in match.init_edges)


def test_single_block_self_loop_preserves_the_original_branch_polarity():
    builder = FunctionBuilder().ins(copy(reg(RAX), reg(RCX)))
    builder.ins(add(reg(RAX), reg(RAX), const(1)), op('CBRANCH', [ram(0x1004), reg(CF, 1)]))
    builder.ins(copy(reg(RBX), reg(RAX))).ret()
    _, lane, index = _index(builder)
    matches = [index.for_join(identifier) for identifier in _joins(lane)]
    assert matches and all(reason is None for _, reason in matches)
    for match, _ in matches:
        assert match.header == match.latch == '1:1004'
        assert (match.conditions[0].true_successor, match.conditions[0].false_successor) == ('1:1004', '1:1008')
        assert match.exits == (('1:1004', '1:1008'),)


def test_function_entry_header_has_no_invented_initial_predecessor():
    flag = tmp(0x300, 1)
    builder = (FunctionBuilder().label('header')
               .cbranch('exit', flag, op('INT_LESSEQUAL', [reg(RDX), reg(RAX)], flag))
               .ins(add(reg(RAX), reg(RAX), const(1))).branch('header')
               .label('exit').ins(copy(reg(RBX), reg(RAX))).ret())
    _, lane, index = _index(builder)
    results = [index.for_join(identifier) for identifier in _joins(lane)]
    assert results and all(match is None and reason == 'no original initial predecessor' for match, reason in results)


def test_partitioned_original_flow_spans_must_cover_every_requested_byte():
    analyzed, lane, index = _index(_loop(narrow_prefix=True))
    identifier = _joins(lane)[0]
    match, reason = index.for_join(identifier)
    assert reason is None and len(match.init_edges) == len(match.transition_edges) == 2
    kept = [edge for edge in lane.ssa.flow_edges if edge is not match.init_edges[-1]]
    rejected = _evidence_view(analyzed, lane, kept)
    assert rejected.for_join(identifier) == (None, 'incomplete header flow span')


@pytest.mark.parametrize('change', ('missing', 'wrong_predecessor', 'wrong_sources'))
def test_missing_or_mismatched_header_evidence_never_guesses_the_union(change):
    analyzed, lane, index = _index(_loop())
    identifier = _joins(lane)[0]
    match, _ = index.for_join(identifier)
    edge = match.init_edges[0]
    if change == 'missing':
        edges = [row for row in lane.ssa.flow_edges if row is not edge]
    elif change == 'wrong_predecessor':
        edges = [replace(row, predecessor_key='1:1014') if row is edge else row for row in lane.ssa.flow_edges]
    else:
        edges = [replace(row, definition_ids=(match.transition_definition_id,)) if row is edge else row
                 for row in lane.ssa.flow_edges]
    found, reason = _evidence_view(analyzed, lane, edges).for_join(identifier)
    assert found is None and reason
    assert 'flow evidence' in reason or reason == 'header source union mismatch'


def _unsupported(shape):
    builder = FunctionBuilder().ins(copy(reg(RAX), reg(RCX)))
    if shape == 'multi_latch':
        return (builder.label('header').cbranch('exit', reg(R9, 1)).cbranch('right', reg(CF, 1))
                .ins(add(reg(RAX), reg(RAX), const(1))).branch('header')
                .label('right').ins(add(reg(RAX), reg(RAX), const(2))).branch('header')
                .label('exit').ins(copy(reg(RBX), reg(RAX))).ret())
    if shape == 'nested':
        return (builder.label('outer').cbranch('exit', reg(R9, 1))
                .label('inner').cbranch('after', reg(CF, 1))
                .ins(add(reg(RAX), reg(RAX), const(1))).branch('inner')
                .label('after').ins(add(reg(RAX), reg(RAX), const(2))).branch('outer')
                .label('exit').ins(copy(reg(RBX), reg(RAX))).ret())
    if shape == 'horizontal':
        return (builder.label('first').cbranch('second', reg(R9, 1))
                .ins(add(reg(RAX), reg(RAX), const(1))).branch('first')
                .label('second').cbranch('exit', reg(CF, 1))
                .ins(add(reg(RAX), reg(RAX), const(2))).branch('second')
                .label('exit').ins(copy(reg(RBX), reg(RAX))).ret())
    assert shape == 'irreducible'
    return (builder.cbranch('right', reg(CF, 1))
            .label('left').ins(add(reg(RAX), reg(RAX), const(1))).branch('right')
            .label('right').ins(add(reg(RAX), reg(RAX), const(2))).cbranch('left', reg(R9, 1))
            .ins(copy(reg(RBX), reg(RAX))).ret())


@pytest.mark.parametrize('shape,reason', (('multi_latch', 'multiple loop latches'),
                                       ('nested', 'nested cyclic region'),
                                       ('irreducible', 'irreducible cyclic region'),
                                       ('horizontal', 'multiple cyclic source regions')))
def test_complex_cycle_shapes_are_explicit_structural_fallbacks(shape, reason):
    analyzed, lane, index = _index(_unsupported(shape))
    results = [index.for_join(identifier) for identifier in _joins(lane)]
    assert results and any(match is None and why == reason for match, why in results)
    record = _record(analyzed, RBX)
    assert any(node.get('recurrence_fallback') == reason for node in record['nodes'])
    assert eligibility(record) == 'loop'


def test_an_acyclic_phi_has_no_recurrence_noise_even_with_an_unrelated_later_loop():
    builder = _branchy()
    builder._rows.pop()
    builder.label('later').ins(add(reg(R9), reg(R9), const(1))).cbranch('later', reg(CF, 1)).ret()
    analyzed, lane, index = _index(builder)
    for identifier in _joins(lane):
        assert index.for_join(identifier) == (None, None)
    record = _record(analyzed, R8)
    assert any(node.get('reason') == 'join' for node in record['nodes'])
    assert all('recurrence' not in node and 'recurrence_fallback' not in node for node in record['nodes'])


def test_cached_correspondence_and_resource_failures_use_the_existing_budget(monkeypatch):
    import tdo_v2._record_recurrence as module

    analyzed, lane, index = _index(_loop())
    identifier = _joins(lane)[0]
    expected = index.for_join(identifier)

    def exhausted(*args):
        raise AnalysisBudgetExceeded('work')

    monkeypatch.setattr(module, 'step', exhausted)
    assert index.for_join(identifier) is expected
    with pytest.raises(AnalysisBudgetExceeded):
        RecurrenceIndex(analyzed.normalized, analyzed.unit, lane)


def test_predicate_reentry_holder_is_removed_when_construction_is_aborted(monkeypatch):
    import tdo_v2.operation_records as records

    analyzed = _analyzed(_loop())
    original, entered = records._Builder._operands, []

    def abort(builder, node, action, operation, spans, depth):
        if operation.opcode == 'CBRANCH':
            entered.append(builder)
            assert builder._recurrence_operands
            raise AnalysisBudgetExceeded('work')
        return original(builder, node, action, operation, spans, depth)

    with monkeypatch.context() as patch:
        patch.setattr(records._Builder, '_operands', abort)
        with pytest.raises(AnalysisBudgetExceeded):
            _record(analyzed, RBX)
    assert entered and all(not builder._recurrence_operands for builder in entered)
    rebuilt = _record(analyzed, RBX)
    assert not rebuilt['truncated'] and any('recurrence' in node for node in rebuilt['nodes'])
    assert eligibility(rebuilt) == 'loop'


def test_record_node_edge_and_demand_limits_still_refuse_incomplete_values():
    analyzed = _analyzed(_loop())
    for limits in (Limits(nodes=3), Limits(edges=2), Limits(demand_steps=1)):
        records = run_records(analyzed.normalized, analyzed.unit, analyzed.summary, limits=limits)
        assert records
        selected = [record for record in records if record['place']['kind'] == 'register_file'
                    and record['place']['start'] == RBX]
        assert selected
        for record in selected:
            assert record['truncated'] or eligibility(record) is not None
            with pytest.raises(Ineligible):
                evaluate(record, lambda node: 0)


@pytest.mark.parametrize('change', ('entry', 'blocks', 'predecessors'))
def test_original_pcode_and_ssa_cfg_views_must_match_before_any_recurrence_claim(change):
    analyzed, lane, _ = _index(_loop())
    memory = analyzed.normalized.memory_unit
    blocks = list(memory.blocks)
    entry = memory.entry_block_key
    if change == 'entry':
        entry = '1:1004'
    elif change == 'blocks':
        blocks.pop()
    else:
        blocks = [SimpleNamespace(key=block.key, predecessors=()) if block.key == '1:1004' else block
                  for block in blocks]
    # Only the supplied diagnostic CFG view changes; no engine receipt is
    # minted or accepted for this deliberately inconsistent fixture.
    normalized = SimpleNamespace(dependencies=analyzed.normalized.dependencies,
                                 memory_unit=SimpleNamespace(entry_block_key=entry, blocks=tuple(blocks)))
    index = RecurrenceIndex(normalized, analyzed.unit, lane)
    assert index.for_join(_joins(lane)[0]) == (None, 'ssa cfg does not match original cfg')
    assert index.condition_seeds() == ()


def test_the_reused_dominator_fixed_point_charges_the_existing_work_budget(monkeypatch):
    import tdo_v2._sparse_dataflow as dataflow

    analyzed, lane, _ = _index(_loop())
    original = dataflow.step
    entered = []

    def limited(*args):
        if sys._getframe(1).f_code.co_name == '_immediate_dominators':
            entered.append(True)
            raise AnalysisBudgetExceeded('work')
        return original(*args)

    monkeypatch.setattr(dataflow, 'step', limited)
    with pytest.raises(AnalysisBudgetExceeded):
        RecurrenceIndex(analyzed.normalized, analyzed.unit, lane)
    assert entered


def test_constant_transition_keeps_the_original_acyclic_value_union(monkeypatch):
    """Loop control alone does not turn constant value alternatives cyclic.

    This is the old expression union, NOT execution or termination of while.
    The metadata must neither invent a trip count nor newly reject that union.
    """
    import tdo_v2._record_recurrence as module

    flag = tmp(0x300, 1)
    builder = (FunctionBuilder().ins(copy(reg(RAX), reg(RCX))).label('header')
               .cbranch('exit', flag, op('INT_EQUAL', [reg(R9), const(0)], flag))
               .ins(copy(reg(RAX), const(5))).branch('header')
               .label('exit').ins(copy(reg(RBX), reg(RAX))).ret())
    analyzed = _analyzed(builder)
    record = _record(analyzed, RBX)
    assert any('recurrence' in node for node in record['nodes'])
    monkeypatch.setattr(module, 'annotate_recurrence', lambda *args: None)
    original = _record(analyzed, RBX)

    def entry(node):
        return 13 if node.get('register', {}).get('offset') == RCX else None

    for route in ('injected', 'stitched'):
        assert eligibility(record, route=route) == eligibility(original, route=route) is None
        assert evaluate(record, entry, route=route) == evaluate(original, entry, route=route) == {13, 5}
