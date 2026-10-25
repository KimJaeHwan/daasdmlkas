"""Invariant shared choices select translations, not independent output phis."""

import copy as copying
import json

import pytest

from synthetic import RAX, RBX, RCX, RDX, RDI, RSI, R8, R9, FunctionBuilder, const, copy, op, reg, tmp
from test_transition_records import _record, _values, _Unreadable
from tdo_v2.operation_records import Ineligible, evaluate_loop_summary, evaluate_transition


def _branch_loop(*, feedback=False, nested=False, shared=False):
    header, branch, inner = tmp(0x300, 1), tmp(0x310, 1), tmp(0x320, 1)
    builder = (FunctionBuilder().ins(copy(reg(RAX), reg(RCX)), copy(reg(RDI), const(0)))
               .label('header').cbranch('exit', header, op('INT_EQUAL', [reg(RDX), const(0)], header))
               .cbranch('yes', branch, op('INT_NOTEQUAL', [reg(RDX if feedback else R9), const(0)], branch))
               .ins(op('INT_ADD', [reg(RAX), reg(R8)], reg(RAX))))
    if shared:
        builder.ins(op('INT_ADD', [reg(RDI), reg(R8)], reg(RDI)))
    builder.branch('join').label('yes')
    if nested:
        builder.cbranch('inner', inner, op('INT_EQUAL', [reg(RSI), const(7)], inner))
        builder.ins(op('INT_ADD', [reg(RAX), const(3)], reg(RAX))).branch('join').label('inner')
    builder.ins(op('INT_ADD', [reg(RAX), reg(RSI)], reg(RAX)))
    if shared:
        builder.ins(op('INT_ADD', [reg(RDI), reg(RSI)], reg(RDI)))
    return (builder.label('join')
            .ins(op('INT_SUB', [reg(RDX), const(1)], reg(RDX))).branch('header')
            .label('exit').ins(copy(reg(RBX), reg(RAX))).ret())


@pytest.mark.parametrize('selector', (0, 1, 256))
@pytest.mark.parametrize('count', (0, 1, 9))
@pytest.mark.parametrize('nested', (False, True))
def test_invariant_choices_match_all_original_visits(selector, count, nested):
    record = json.loads(json.dumps(_record(_branch_loop(nested=nested), known=True)))
    summary, = record['loop_summaries']
    assert summary['complete'], summary
    assert summary['method'] == 'guarded_countdown_translation_v1'
    view, = record['cycle_graph']['transitions']
    values = _values(view, **{str(RAX): 0xfffffffffffffff8, str(RDX): count,
                              str(RSI): 7, str(R8): 11, str(R9): selector})
    result = evaluate_loop_summary(record, summary['id'], values)
    for _ in range(count):
        visit = evaluate_transition(record, view['id'], values)
        assert visit['kind'] == 'continue'
        for update in visit['updates']:
            state, = [row for row in view['inputs'] if row['span'] == update['span']]
            values[state['id']] = update['value']
    final = evaluate_transition(record, view['id'], values)
    assert final['updates'] == result['updates'] and final['kind'] == 'exit'
    assert result['iterations'] == count


@pytest.mark.parametrize('selector,count', ((0, 3), (1, 3), (None, 0)))
def test_inactive_selector_and_delta_are_not_demanded(selector, count):
    record = _record(_branch_loop(), known=True)
    summary, = record['loop_summaries']
    view, = record['cycle_graph']['transitions']
    values = _values(view, **{str(RAX): 10, str(RDX): count, str(R9): selector,
                              str(RSI): 7 if selector else None, str(R8): 11 if not selector else None})
    result = evaluate_loop_summary(record, summary['id'], values)
    assert result['iterations'] == count


def test_mutating_branch_condition_is_not_an_invariant_choice():
    record = _record(_branch_loop(feedback=True), known=True)
    summary, = record['loop_summaries']
    assert not summary['complete'] and 'mutable' in summary['reason']
    assert record['cycle_graph']['transitions'][0]['complete']


def test_inactive_nested_predicate_does_not_demand_its_unknown_selector():
    record = _record(_branch_loop(nested=True), known=True)
    summary, = record['loop_summaries']
    view, = record['cycle_graph']['transitions']
    values = _values(view, **{str(RAX): 10, str(RDX): 3, str(R9): 0, str(R8): 11})
    result = evaluate_loop_summary(record, summary['id'], values)
    assert len(result['selected_choices']) == 1
    assert next(row['value'] for row in result['updates'] if int(row['span'][-2], 16) == RAX) == 43


@pytest.mark.parametrize('selector,delta', ((0, 11), (256, 7)))
def test_two_tracked_outputs_share_one_original_choice(selector, delta):
    record = _record(_branch_loop(shared=True), known=True)
    summary, = record['loop_summaries']
    assert summary['complete'], summary
    view, = record['cycle_graph']['transitions']
    values = _values(view, **{str(RAX): 10, str(RDI): 20, str(RDX): 3,
                              str(R9): selector, str(R8): 11, str(RSI): 7})
    result = evaluate_loop_summary(record, summary['id'], values)
    assert len(result['selected_choices']) == 1
    actual = {int(row['span'][-2], 16): row['value'] for row in result['updates']}
    assert actual[RAX] == 10 + 3 * delta and actual[RDI] == 20 + 3 * delta


@pytest.mark.parametrize('change', ('choice', 'case', 'dependencies', 'evidence'))
def test_guarded_recipe_tamper_rejected_before_values(change):
    record = copying.deepcopy(_record(_branch_loop(), known=True))
    summary, = record['loop_summaries']
    assert summary['complete'], summary
    if change == 'choice':
        summary['cases'][0]['choices'][0]['value'] = not summary['cases'][0]['choices'][0]['value']
    elif change == 'case':
        summary['cases'].pop()
    elif change == 'dependencies':
        summary['invariant_decisions'] = {}
    else:
        summary['cases'][0]['derivation'].pop()
    with pytest.raises(Ineligible):
        evaluate_loop_summary(record, summary['id'], _Unreadable())
