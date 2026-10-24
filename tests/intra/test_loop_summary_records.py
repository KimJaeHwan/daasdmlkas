"""Countdown translations preserve the authoritative SSA and one-visit view."""

import copy as copying
import json
import sys

import pytest

from synthetic import RAX, RBX, RCX, RDX, RDI, RSI, FunctionBuilder, add, const, copy, op, reg, tmp, load, store
from test_transition_records import _record, _values, _Unreadable
from tdo_v2 import _record_loop_summaries
from tdo_v2.operation_records import Ineligible, eligibility, evaluate_loop_summary, evaluate_transition, render


def _loop(*, value_width=8, counter_width=8, decrement=1, operator='INT_ADD', condition='INT_EQUAL',
          delta_register=RSI, address_changes=False, test_width=None, reversed_branch=False, extra_opcode=None):
    flag = tmp(0x300, 1)
    test = op(condition, [reg(RDX, test_width or counter_width), const(0, test_width or counter_width)], flag)
    builder = FunctionBuilder().ins(copy(reg(RAX, value_width), reg(RCX, value_width)))
    if reversed_branch:
        builder.label('header').cbranch('body', flag, test).branch('exit').label('body')
    else:
        builder.label('header').cbranch('exit', flag, test)
    if extra_opcode is not None:
        builder.ins(op(extra_opcode, [reg(RAX), reg(RSI)], tmp(0x440)))
    if address_changes:
        builder.ins(load(reg(RAX, value_width), reg(RDX)))
    else:
        builder.ins(op(operator, [reg(RAX, value_width), reg(delta_register, value_width)], reg(RAX, value_width)))
    return (builder.ins(op('INT_SUB', [reg(RDX, counter_width), const(decrement, counter_width)], reg(RDX, counter_width)))
            .branch('header').label('exit').ins(copy(reg(RBX), reg(RAX))).ret())


def _summary(record):
    summary, = record['loop_summaries']
    assert summary['complete'], summary
    return summary


def _evaluate(record, *, initial=10, delta=7, count=3, opt=False):
    summary = _summary(record)
    view, = record['cycle_graph']['transitions']
    return evaluate_loop_summary(record, summary['id'],
                                 _values(view, **{str(RAX): initial, str(RSI): delta, str(RDX): count}),
                                 accept_unattributed_assumptions=opt)


@pytest.mark.parametrize('count', (0, 1, 3, 255))
@pytest.mark.parametrize('initial,delta', ((0, 7), (0xffffffffffffffff, 1), (0x1122334455667788, 0x1000000000000001)))
def test_final_translation_matches_repeated_existing_one_visit(count, initial, delta):
    record = _record(_loop(), known=True)
    summary = _summary(record)
    view, = record['cycle_graph']['transitions']
    values = _values(view, **{str(RAX): initial, str(RSI): delta, str(RDX): count})
    result = evaluate_loop_summary(record, summary['id'], values)
    iterations = 0
    while True:
        visit = evaluate_transition(record, view['id'], values)
        if visit['kind'] == 'exit':
            break
        iterations += 1
        for update in visit['updates']:
            state, = [row for row in view['inputs'] if row['span'] == update['span']]
            values[state['id']] = update['value']
    assert iterations == result['iterations'] == count
    assert result['updates'] == visit['updates']
    assert result['terminal_visit'] == visit and eligibility(record) == 'loop'
    assert result['assumptions_complete'] and result['conditional_on_original_analysis']


@pytest.mark.parametrize('value_width,counter_width,count', ((1, 2, 256), (1, 8, (1 << 64) - 1),
                                                          (8, 1, 255), (2, 1, 0)))
def test_unsigned_iteration_count_is_not_truncated_to_accumulator_width(value_width, counter_width, count):
    record = _record(_loop(value_width=value_width, counter_width=counter_width), known=True)
    result = _evaluate(record, initial=0xfe, delta=7, count=count)
    assert result['iterations'] == count
    value, = [row for row in result['updates'] if int(row['span'][-2], 16) == RAX]
    assert value['value'] == (0xfe + count * 7) % (1 << (8 * value_width))


def test_zero_iterations_do_not_read_inactive_delta():
    record = _record(_loop(), known=True)
    summary, = record['loop_summaries']
    view, = record['cycle_graph']['transitions']
    values = _values(view, **{str(RAX): 10, str(RDX): 0})
    delta, = [row['id'] for row in view['inputs'] if int(row['span'][-2], 16) == RSI]

    class Inputs(dict):
        def get(self, key):
            assert key != delta, 'zero-visit must not ask for body delta'
            return super().get(key)

    result = evaluate_loop_summary(record, summary['id'], Inputs(values))
    assert result['iterations'] == 0 and not result['terminal_visit']['effects']


def test_each_required_boundary_value_is_captured_once_per_evaluation():
    record = _record(_loop(), known=True)
    view, = record['cycle_graph']['transitions']
    values = _values(view, **{str(RAX): 10, str(RSI): 7, str(RDX): 3})
    seen = set()

    class Inputs(dict):
        def get(self, key):
            assert key not in seen
            seen.add(key)
            return super().get(key)

    result = evaluate_loop_summary(record, _summary(record)['id'], Inputs(values))
    assert result['iterations'] == 3


def test_unattributed_assumptions_require_explicit_opt_in():
    record = _record(_loop())
    summary = _summary(record)
    with pytest.raises(Ineligible, match='unattributed'):
        evaluate_loop_summary(record, summary['id'], _Unreadable())
    result = _evaluate(record, opt=True)
    assert result['iterations'] == 3 and not result['assumptions_complete']


@pytest.mark.parametrize('change', ('delta', 'counter', 'width', 'edge', 'effect', 'proof', 'context', 'source'))
def test_summary_or_source_changes_are_rejected_before_input_access(change):
    record = _record(_loop(), known=True)
    summary = _summary(record)
    if change == 'delta':
        summary['updates'][0]['delta']['constant'] += 1
    elif change == 'counter':
        summary['counter']['input'] = 'not-a-state'
    elif change == 'width':
        summary['updates'][0]['width'] = 1
    elif change == 'edge':
        summary['exit_edge'] = summary['continue_edge']
    elif change == 'effect':
        summary['effect_template']['header_repetitions'] = 'n'
    elif change == 'proof':
        summary['derivation'].pop()
    elif change == 'context':
        summary['analysis_context'] = {}
    else:
        record['cycle_graph']['transitions'][0]['effects'] = [dict(kind='store')]
    with pytest.raises(Ineligible):
        evaluate_loop_summary(record, summary['id'], _Unreadable())


@pytest.mark.parametrize('kwargs,reason', (
    ({'decrement': 2}, 'exactly one'), ({'condition': 'INT_LESS'}, 'zero equality'),
    ({'test_width': 1}, 'partial-byte'), ({'delta_register': RDX}, 'mutable'),
    ({'operator': 'INT_XOR'}, 'nonlinear'), ({'address_changes': True}, 'one-visit view is incomplete'),
    ({'extra_opcode': 'INT_DIV'}, 'potentially partial'),
))
def test_unsupported_loops_are_partial_without_replacing_original_views(kwargs, reason):
    record = _record(_loop(**kwargs), known=True)
    row, = record['loop_summaries']
    assert not row['complete'] and reason in row['reason']
    assert 'cycle_graph' in record and record['cycle_graph']['coverage']['expression_complete']
    with pytest.raises(Ineligible, match='incomplete'):
        evaluate_loop_summary(record, row['id'], _Unreadable())


def test_rewrite_independently_rejects_mutable_addresses_even_when_output_is_linear():
    record = _record(_loop(), known=True)
    view = copying.deepcopy(record['cycle_graph']['transitions'][0])
    counter = _summary(record)['counter']['input']
    source = next(node for node in view['record']['nodes'] if node.get('transition_input') == counter)
    # A local negative rewrite fixture, not a claim of authentic raw evidence.
    # The public consumer independently rejects unregistered ops via v12 too.
    node = dict(id=len(view['record']['nodes']), kind='op', opcode='LOAD',
                operands=[dict(index=1, width=8, parts=[dict(node=source['id'], bytes=[0, 8], at=[0, 8])])])
    view['record']['nodes'].append(node)
    view['effects'].append(dict(kind='load', node=node['id'], guard=1))
    with pytest.raises(_record_loop_summaries._Partial, match='address varies'):
        _record_loop_summaries._derive(view, record['limits'])


def test_nonzero_true_branch_uses_original_polarity():
    record = _record(_loop(condition='INT_NOTEQUAL', reversed_branch=True), known=True)
    result = _evaluate(record)
    assert result['iterations'] == 3


def test_summary_does_not_mutate_original_graph_or_one_visit(monkeypatch):
    record = _record(_loop(), known=True)
    monkeypatch.setattr(_record_loop_summaries, 'publish_loop_summaries', lambda _: [])
    baseline = _record(_loop(), known=True)
    assert record['cycle_graph'] == baseline['cycle_graph']
    assert record['nodes'] == baseline['nodes'] and record['root'] == baseline['root']
    assert eligibility(record) == eligibility(baseline)


def test_json_roundtrip_and_render_preserve_formula_and_original_refs():
    record = json.loads(json.dumps(_record(_loop(), known=True)))
    assert _evaluate(record)['iterations'] == 3
    text = render(record)
    assert 'loop summary ' in text and 'original graph and one-visit retained' in text
    assert '_final = (' in text and 'mod 2^64' in text and 'derived translation rule' in text


@pytest.mark.parametrize('count', (-1, 1 << 64, True, None))
def test_unknown_or_out_of_width_counter_is_not_silently_an_iteration_count(count):
    record = _record(_loop(), known=True)
    with pytest.raises(Ineligible, match='input'):
        _evaluate(record, count=count)


def test_summary_limits_leave_original_graph_usable(monkeypatch):
    derive = _record_loop_summaries._derive
    monkeypatch.setattr(_record_loop_summaries, '_derive', lambda view, limits: derive(view, {**limits, 'edges': 1}))
    record = _record(_loop(), known=True)
    summary, = record['loop_summaries']
    assert not summary['complete'] and 'limit' in summary['reason']
    assert record['cycle_graph']['transitions'][0]['complete'] and eligibility(record) == 'loop'


def test_recursion_limit_restored_after_summary_success_or_failure():
    record = _record(_loop(), known=True)
    limit = sys.getrecursionlimit()
    _evaluate(record)
    assert sys.getrecursionlimit() == limit
    with pytest.raises(Ineligible):
        _evaluate(record, count=None)
    assert sys.getrecursionlimit() == limit
