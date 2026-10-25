"""Local derived views never replace the common SSA/expression authority."""

import copy as copying
import json

import pytest

from synthetic import CF, R8, R9, RAX, RDI, RSI, RDX, RSP, FunctionBuilder, add, const, copy, load, op, reg, store, tmp
from test_operation_records import _analyzed, _record
from test_transition_records import _record as _loop_record
from tdo_v2._record_expression_views import ViewLimits, select_expression
from tdo_v2.operation_records import (Ineligible, attach_expression_view, eligibility, evaluate_expression_view,
                                    evaluate_loop_summary, evaluate_transition, render, simplify_expression)


def _simple():
    return _record(_analyzed(FunctionBuilder().ins(add(reg(RAX), reg(RDI), reg(RSI))).ret()), RAX)


def test_selection_retains_original_graph_and_shared_producer_bytes():
    record = _simple()
    before = copying.deepcopy(record)
    selected = select_expression(record)
    assert selected['nodes'] == [0, 1]
    assert record == before
    assert record['nodes'][1]['register']['size'] == 16
    # The two operand slices belong to ONE existing entry producer.
    assert record['nodes'][0]['operands'][0]['parts'][0]['node'] == 1
    assert select_expression(json.loads(json.dumps(record))) == selected


@pytest.mark.parametrize('change', ('gap', 'overlap', 'width', 'producer', 'placement'))
def test_selection_rejects_invalid_output_geometry(change):
    record = _simple()
    row = dict(name='x', width=8, parts=copying.deepcopy(record['root']))
    if change == 'gap':
        row['width'] = 9
    elif change == 'overlap':
        row['parts'] *= 2
    elif change == 'width':
        row['parts'][0]['bytes'][1] = 9
    elif change == 'producer':
        row['parts'][0]['node'] = 999
    else:
        row['parts'][0]['at'] = [1, 9]
    with pytest.raises(Ineligible):
        select_expression(record, [row])


def test_internal_byte_output_and_original_cycle_are_selectable_not_yet_numeric_claims():
    record = _simple()
    row = dict(name='byte', width=1, parts=[dict(node=1, bytes=[3, 4], at=[0, 1])])
    assert select_expression(record, [row])['nodes'] == [1]
    record = _loop_record(known=True)
    assert select_expression(record)['nodes']
    visit, = record['cycle_graph']['transitions']
    outcome = visit['outcomes'][0]
    selected = select_expression(record, [dict(name='next', width=8, parts=[outcome['updates'][0]['part']],
                                               guard=outcome['guard'])], namespace=visit['id'])
    assert selected['namespace'] == visit['id']
    assert selected['guards']


def test_selection_budgets_and_source_identity():
    record = _simple()
    with pytest.raises(Ineligible, match='limit'):
        select_expression(record, limits=ViewLimits(nodes=1))
    selected = select_expression(record)
    record['expression_views'] = [dict(id='other')]
    assert select_expression(record) == selected
    record['nodes'][0]['opcode'] = 'INT_SUB'
    assert select_expression(record)['source'] != selected['source']


def test_output_and_control_edges_and_guard_types_are_charged_before_memo_hits():
    record = _simple()
    outputs = [dict(name=name, width=1, parts=[dict(node=1, bytes=[0, 1], at=[0, 1])]) for name in ('a', 'b')]
    with pytest.raises(Ineligible, match='edge limit'):
        select_expression(record, outputs, limits=ViewLimits(nodes=2, edges=1))
    outputs[0]['guard'], outputs[1]['guard'] = 1, True
    with pytest.raises(Ineligible, match='guard'):
        select_expression(record, outputs)
    record['control']['decisions']['d'] = dict(operand=dict(width=1, parts=[dict(node=1, bytes=[0, 1], at=[0, 1])]))
    record['control']['nodes'].append(dict(decision='d', true=1, false=0))
    outputs = [dict(name='a', width=1, parts=[dict(node=1, bytes=[0, 1], at=[0, 1])], guard=2)]
    with pytest.raises(Ineligible, match='limit'):
        select_expression(record, outputs, limits=ViewLimits(nodes=2))


def _mba(width=8, shift=False):
    a, b, c = tmp(0x300, width), tmp(0x310, width), tmp(0x320, width)
    builder = (FunctionBuilder().ins(op('INT_XOR', [reg(RDI, width), reg(RSI, width)], a),
                                     op('INT_AND', [reg(RDI, width), reg(RSI, width)], b),
                                     op('INT_LEFT' if shift else 'INT_MULT', [b, const(1 if shift else 2, width)], c),
                                     add(reg(RAX, width), a, c)).ret())
    return _record(_analyzed(builder), RAX, width)


def _binding_values(record, view, registers):
    values = {}
    namespace = view['selection']['namespace']
    local = record if namespace == 'original' else next(
        row['record'] for row in record['cycle_graph']['transitions'] if row['id'] == namespace)
    for row in view['bindings']:
        node = local['nodes'][row['node']]
        descriptor = node['register']
        value = 0
        for index in range(row['width']):
            address = descriptor['offset'] + index
            value |= next(((item >> (8 * (address - base))) & 255 for base, item in registers.items()
                           if base <= address < base + 8), 0) << (8 * index)
        values[row['id']] = value
    return values


@pytest.mark.parametrize('width', (1, 2, 4, 8))
@pytest.mark.parametrize('shift', (False, True))
def test_mba_simplifies_and_preserves_exact_width_and_original_nodes(width, shift):
    record = _mba(width, shift)
    before = copying.deepcopy(record)
    view = simplify_expression(record)
    assert view['proof']['status'] == 'equivalent', view['proof']
    assert not any(row.get('op') in ('bvxor', 'bvand', 'bvmul', 'bvshl') for row in view['graph']['nodes'])
    for x, y in ((0, 1), (255, 1), ((1 << (width * 8)) - 1, 17), (0x1122334455667788, 0xf0e0d0c0b0a09080)):
        values = _binding_values(record, view, {RDI: x, RSI: y})
        actual = evaluate_expression_view(record, view, values, accept_unattributed_assumptions=True)
        assert actual['outputs']['root'] == (x + y) & ((1 << (width * 8)) - 1)
    attached = attach_expression_view(record, view)
    assert record == before
    assert {key: value for key, value in attached.items() if key != 'expression_views'} == before
    assert len(attached['expression_views']) == 1
    assert attach_expression_view(attached, view) == attached
    assert 'original graph retained' in render(attached)
    assert eligibility(attached) == eligibility(before)


def test_overlapping_original_producer_bytes_are_not_independent_inputs():
    record = _simple()
    outputs = [dict(name='wide', width=2, parts=[dict(node=1, bytes=[3, 5], at=[0, 2])]),
               dict(name='high', width=1, parts=[dict(node=1, bytes=[4, 5], at=[0, 1])])]
    view = simplify_expression(record, select_expression(record, outputs))
    assert len(view['bindings']) == 1
    result = evaluate_expression_view(record, view, {'n1': 0xabcd << 24}, accept_unattributed_assumptions=True)
    assert result['outputs'] == dict(wide=0xabcd, high=0xab)


class _Unreadable(dict):
    def get(self, *args):
        pytest.fail('view revalidation must finish before concrete input access')


@pytest.mark.parametrize('change', ('candidate', 'input', 'placement', 'source', 'namespace', 'guard', 'budget'))
def test_consumer_rebuilds_even_if_caller_recomputes_identity(change):
    from tdo_v2._record_expression_views import _identity
    record = _simple()
    view = simplify_expression(record)
    if change == 'candidate':
        view['graph']['nodes'][-1]['op'] = 'bvsub'
    elif change == 'input':
        view['bindings'][0]['width'] = 8
    elif change == 'placement':
        view['selection']['outputs'][0]['parts'][0]['bytes'] = [1, 9]
    elif change == 'source':
        record['nodes'][0]['opcode'] = 'INT_SUB'
    elif change == 'namespace':
        view['selection']['namespace'] = 'not-a-visit'
    elif change == 'guard':
        view['selection']['outputs'][0]['guard'] = 0
    else:
        view['selection']['limits']['solver_ms'] *= 100
    view['id'] = _identity(view)
    with pytest.raises(Ineligible):
        evaluate_expression_view(record, view, _Unreadable(), accept_unattributed_assumptions=True)


def test_refuted_candidate_and_unsatisfiable_domain_are_not_equivalence():
    record = _simple()
    view = simplify_expression(record)
    candidate = copying.deepcopy(view['graph'])
    candidate['nodes'][-1]['op'] = 'bvsub'
    wrong = simplify_expression(record, candidate=candidate)
    assert wrong['proof']['status'] == 'refuted'
    with pytest.raises(Ineligible, match='not equivalent'):
        attach_expression_view(record, wrong)
    binding = view['bindings'][0]['id']
    empty = simplify_expression(record, conditions=[dict(binding=binding, equals=0), dict(binding=binding, equals=1)])
    assert empty['proof']['status'] == 'inconsistent_domain'
    assert empty['proof']['mismatch'] == 'not_checked'
    with pytest.raises(Ineligible):
        evaluate_expression_view(record, empty, _Unreadable(), accept_unattributed_assumptions=True)


def test_unknown_solver_is_not_success(monkeypatch):
    import z3
    monkeypatch.setattr(z3.Solver, 'check', lambda *args: z3.unknown)
    view = simplify_expression(_simple())
    assert view['proof']['status'] == 'unproven'
    with pytest.raises(Ineligible):
        attach_expression_view(_simple(), view)


def test_unattributed_assumptions_require_explicit_opt_in():
    record = _simple()
    view = simplify_expression(record)
    with pytest.raises(Ineligible, match='unattributed'):
        evaluate_expression_view(record, view, _Unreadable())


@pytest.mark.parametrize('kind', ('division', 'memory', 'cycle', 'unknown_phi'))
def test_unsupported_frontiers_remain_partial_with_original_graph_intact(kind):
    if kind == 'division':
        record = _record(_analyzed(FunctionBuilder().ins(op('INT_DIV', [reg(RDI), reg(RSI)], reg(RAX))).ret()), RAX)
    elif kind == 'memory':
        record = _record(_analyzed(FunctionBuilder().ins(load(reg(RAX), reg(RDI))).ret()), RAX)
    elif kind == 'cycle':
        record = _loop_record(known=True)
    else:
        from test_operation_record_shapes import _branchy
        record = _record(_analyzed(_branchy()), RAX)
        for node in record['nodes']:
            if node['kind'] == 'phi':
                node.pop('condition', None)
                node.pop('guarded_sources', None)
    before = copying.deepcopy(record)
    view = simplify_expression(record)
    assert view['proof']['status'] == 'partial', view['proof']
    assert view['graph'] is None and view['original_graph_retained']
    assert record == before


@pytest.mark.parametrize('selector', (0, 1, 256))
def test_shared_branch_multioutput_onevisit_and_existing_loop_summary_unchanged(selector):
    from test_loop_summary_branches import _branch_loop
    from test_transition_records import _values
    record = _loop_record(_branch_loop(shared=True), known=True)
    visit, = record['cycle_graph']['transitions']
    outcome = visit['outcomes'][0]
    outputs = [dict(name=str(i), width=row['part']['at'][1], parts=[row['part']], guard=outcome['guard'])
               for i, row in enumerate(outcome['updates'])]
    selected = select_expression(record, outputs, namespace=visit['id'])
    view = simplify_expression(record, selected)
    assert view['proof']['status'] == 'equivalent', view['proof']
    values = _values(visit, **{str(RAX): 10, str(RDI): 20, str(RDX): 3,
                             str(RSI): 7, str(R9): selector, str(R8): 11})
    inputs = {row['id']: values[row['transition_input']] for row in view['bindings']}
    derived = evaluate_expression_view(record, view, inputs)
    raw = evaluate_transition(record, visit['id'], values)
    assert derived['outputs'] == {str(i): row['value'] for i, row in enumerate(raw['updates'])}
    attached = attach_expression_view(record, view)
    summary, = record['loop_summaries']
    assert evaluate_loop_summary(record, summary['id'], values) == evaluate_loop_summary(attached, summary['id'], values)
    assert record['cycle_graph'] == attached['cycle_graph'] and record['loop_summaries'] == attached['loop_summaries']


@pytest.mark.parametrize('opcode', ('COPY', 'INT_ZEXT', 'INT_SEXT', 'INT_NEGATE', 'INT_2COMP', 'BOOL_NEGATE',
                                    'POPCOUNT', 'INT_ADD', 'INT_SUB', 'INT_MULT', 'INT_AND', 'INT_OR', 'INT_XOR',
                                    'INT_LEFT', 'INT_RIGHT', 'INT_SRIGHT', 'SUBPIECE', 'PIECE', 'INT_EQUAL',
                                    'INT_NOTEQUAL', 'INT_LESS', 'INT_LESSEQUAL', 'INT_SLESS', 'INT_SLESSEQUAL',
                                    'INT_CARRY', 'INT_SCARRY', 'INT_SBORROW', 'BOOL_AND', 'BOOL_OR', 'BOOL_XOR'))
def test_bitvector_adapter_matches_existing_integer_semantics(opcode):
    import random
    import z3
    from tdo_v2._record_expression_bv import arithmetic
    from tdo_v2.operation_records import _compute
    unary = opcode in ('COPY', 'INT_ZEXT', 'INT_SEXT', 'INT_NEGATE', 'INT_2COMP', 'BOOL_NEGATE', 'POPCOUNT')
    rng = random.Random(53)
    for width in (1, 2, 4, 8):
        mask = (1 << (width * 8)) - 1
        pairs = [(0, 0), (mask, 1), (1 << (width * 8 - 1), mask), (mask, width * 8), (mask, 256)]
        pairs += [(rng.getrandbits(width * 8), rng.getrandbits(width * 8)) for _ in range(15)]
        for a, b in pairs:
            values = [a] if unary else [a, b & mask]
            expected = _compute(opcode, values, [width] * len(values), width) & mask
            observed = z3.simplify(arithmetic(opcode, [z3.BitVecVal(v, width * 8) for v in values], width * 8))
            assert observed.as_long() == expected, (opcode, width, values, observed, expected)


@pytest.mark.parametrize('opcode', ('INT_ADD', 'INT_SUB', 'INT_MULT', 'INT_NEGATE', 'INT_2COMP', 'INT_SEXT', 'INT_ZEXT'))
@pytest.mark.parametrize('output_width', (1, 2, 4))
def test_width_changes_match_original_compute_not_input_width_arithmetic(opcode, output_width):
    import z3
    from tdo_v2._record_expression_bv import arithmetic
    from tdo_v2.operation_records import _compute
    for a, b in ((255, 1), (16, 16), (128, 255), (0, 1)):
        values = [a, b] if opcode in ('INT_ADD', 'INT_SUB', 'INT_MULT') else [a]
        expected = _compute(opcode, values, [1] * len(values), output_width) & ((1 << (8 * output_width)) - 1)
        actual = z3.simplify(arithmetic(opcode, [z3.BitVecVal(v, 8) for v in values], 8 * output_width))
        assert actual.as_long() == expected


def test_consecutive_adds_roundtrip_shared_nary_simplifier_output():
    builder = FunctionBuilder().ins(add(reg(RAX), reg(RDI), reg(RSI)),
                                   add(reg(RAX), reg(RAX), reg(RDX))).ret()
    record = _record(_analyzed(builder), RAX)
    view = simplify_expression(record)
    assert view['proof']['status'] == 'equivalent', view['proof']
    assert any(row.get('op') == 'bvadd' and len(row['args']) == 3 for row in view['graph']['nodes'])
    assert evaluate_expression_view(record, view, _binding_values(record, view, {RDI: 1, RSI: 2, RDX: 3}),
                                    accept_unattributed_assumptions=True)['outputs']['root'] == 6


def test_simplifier_and_hypothesis_budgets_fail_closed():
    record = _mba()
    selected = select_expression(record, limits=ViewLimits(ast_nodes=1))
    assert simplify_expression(record, selected)['proof']['status'] == 'partial'
    selected = select_expression(record, limits=ViewLimits(ast_depth=1))
    assert simplify_expression(record, selected)['proof']['status'] == 'partial'
    record = _simple()
    selected = select_expression(record, limits=ViewLimits(conditions=1))
    conditions = [dict(binding='n1', equals=0)] * 2
    assert simplify_expression(record, selected, conditions=conditions)['proof']['status'] == 'partial'


def test_output_guards_are_conjunctive_not_a_union_of_unrelated_exits():
    record = _simple()
    outputs = [dict(name='a', width=8, parts=copying.deepcopy(record['root']), guard=1),
               dict(name='b', width=8, parts=copying.deepcopy(record['root']), guard=0)]
    view = simplify_expression(record, select_expression(record, outputs))
    assert view['proof']['status'] == 'inconsistent_domain'
