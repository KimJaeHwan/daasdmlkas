"""STORE-only effects retain raw unknowns; scalar evidence is not relaxed."""

import copy as copying
import json

import pytest

from synthetic import RAX, RBX, RCX, RDX, RSI, FunctionBuilder, const, copy, load, op, reg, store, tmp
from test_transition_records import _record, _values, _Unreadable
from tdo_v2._record_write_effects import seal
from tdo_v2.operation_records import Ineligible, eligibility, evaluate_loop_summary, evaluate_transition, render


def _strided(*, stride=8, after=False, mutable=False, with_load=False, extra_store=False, extra_opcode=None):
    flag = tmp(0x300, 1)
    builder = (FunctionBuilder().ins(copy(reg(RAX), reg(RCX))).label('header')
               .cbranch('exit', flag, op('INT_EQUAL', [reg(RDX), const(0)], flag)))
    if with_load:
        builder.ins(load(reg(RBX), reg(RAX)))
    if extra_opcode:
        builder.ins(op(extra_opcode, [reg(RSI), const(0)], tmp(0x900)))
    if after:
        builder.ins(op('INT_ADD', [reg(RAX), const(stride)], reg(RAX)))
    builder.ins(store(reg(RAX), reg(RDX if mutable else RSI)))
    if extra_store:
        builder.ins(store(reg(RAX), reg(RSI)))
    if not after:
        builder.ins(op('INT_ADD', [reg(RAX), const(stride)], reg(RAX)))
    return (builder.ins(op('INT_SUB', [reg(RDX), const(1)], reg(RDX))).branch('header')
            .label('exit').ins(copy(reg(RBX), reg(RAX))).ret())


def _projection(record):
    original, = record['cycle_graph']['transitions']
    assert not original['complete'], 'ordinary RAM unknown must remain unknown'
    view, = record['write_effect_transitions']
    summary, = [row for row in record['loop_summaries'] if row['transition'] == view['id']]
    return view, summary


@pytest.mark.parametrize('after', (False, True))
@pytest.mark.parametrize('stride', (8, 16))
@pytest.mark.parametrize('count', (0, 1, 7))
def test_scalar_translation_and_parametric_original_store(after, stride, count):
    record = json.loads(json.dumps(_record(_strided(after=after, stride=stride), known=True)))
    view, summary = _projection(record)
    assert view['complete'] and summary['complete'], summary
    values = _values(view, **{str(RAX): 0x8000, str(RDX): count, str(RSI): 0x1122334455667788})
    result = evaluate_loop_summary(record, summary['id'], values)
    memory = result['memory_transform']
    assert memory['count'] == count and memory['stride'] == stride and memory['width'] == 8
    assert memory['first_address'] == (0x8000 + (stride if after else 0) if count else None)
    raw_effects = []
    for _ in range(count):
        visit = evaluate_transition(record, view['id'], values)
        raw_effects.extend(visit['effects'])
        for update in visit['updates']:
            state, = [row for row in view['inputs'] if row['span'] == update['span']]
            values[state['id']] = update['value']
    assert [(row['address'], row['width'], row['value']) for row in raw_effects] == [
        (memory['first_address'] + i * stride, memory['width'], memory['value']) for i in range(count)]
    assert result['updates'] == evaluate_transition(record, view['id'], values)['updates']
    assert record['cycle_graph']['unresolved_accesses'] and eligibility(record) is not None
    assert 'M_final = apply_STORE' in render(record)


def test_zero_writes_do_not_demand_value_or_out_of_range_first_address():
    record = _record(_strided(after=True), known=True)
    view, summary = _projection(record)
    values = _values(view, **{str(RAX): (1 << 64) - 1, str(RDX): 0})
    result = evaluate_loop_summary(record, summary['id'], values)
    assert result['memory_transform']['count'] == 0
    assert result['memory_transform']['first_address'] is None and result['memory_transform']['value'] is None


@pytest.mark.parametrize('after,base,count', ((False, (1 << 64) - 8, 1),
                                           (True, (1 << 64) - 16, 1), (True, (1 << 64) - 12, 1),
                                           (False, (1 << 64) - 20, 3)))
def test_pointer_or_store_byte_wrap_is_rejected(after, base, count):
    record = _record(_strided(after=after), known=True)
    view, summary = _projection(record)
    values = _values(view, **{str(RAX): base, str(RDX): count, str(RSI): 7})
    if after and base == (1 << 64) - 16:
        # Last byte may equal modulus-1, but pointer still remains in range.
        assert evaluate_loop_summary(record, summary['id'], values)['memory_transform']['first_address'] == base + 8
    else:
        with pytest.raises(Ineligible, match='wrap'):
            evaluate_loop_summary(record, summary['id'], values)


@pytest.mark.parametrize('kwargs,reason', (({'stride': 4}, 'overlapping'), ({'mutable': True}, 'value varies'),
                                         ({'with_load': True}, 'incomplete'), ({'extra_store': True}, 'incomplete'),
                                         ({'extra_opcode': 'INT_DIV'}, 'partial operation')))
def test_unsupported_memory_models_are_not_discharged(kwargs, reason):
    record = _record(_strided(**kwargs), known=True)
    _, summary = _projection(record)
    assert not summary['complete'] and reason in summary['reason'], summary
    with pytest.raises(Ineligible):
        evaluate_loop_summary(record, summary['id'], _Unreadable())


@pytest.mark.parametrize('change', ('offset', 'value', 'occurrence', 'effect', 'proof', 'RAM', 'scope', 'source'))
def test_store_projection_and_recipe_tamper_fail_before_inputs(change):
    record = copying.deepcopy(_record(_strided(), known=True))
    view, summary = _projection(record)
    if change in ('offset', 'value'):
        if change == 'offset':
            summary['memory_transform']['offset'] += 8
        else:
            summary['memory_transform']['value']['constant'] += 1
    elif change == 'occurrence':
        view['write_projection']['occurrences'][0]['occurrence_ordinal'] += 1
    elif change == 'effect':
        view['effects'].pop()
    elif change == 'proof':
        view['proofs'][0]['last_definition'] = -1
    elif change == 'RAM':
        view['inputs'][0]['span'][1] = 'address_space'
    elif change == 'scope':
        view['output_scope'] = 'all_RAM_resolved'
    else:
        record['cycle_graph']['unresolved_accesses'][0]['width'] += 1
    seal(record)  # Digests alone must not bypass correspondence checks.
    with pytest.raises(Ineligible):
        evaluate_loop_summary(record, summary['id'], _Unreadable())


def test_store_projection_failure_or_disable_never_changes_original_graph(monkeypatch):
    from tdo_v2 import _record_write_effects

    record = _record(_strided(), known=True)
    monkeypatch.setattr(_record_write_effects, 'publish', lambda *args: [])
    baseline = _record(_strided(), known=True)
    assert record['cycle_graph'] == baseline['cycle_graph']
    assert record['nodes'] == baseline['nodes'] and record['root'] == baseline['root']
    assert eligibility(record) == eligibility(baseline)


@pytest.mark.parametrize('change', ('action_out_of_bounds', 'action_other_operation', 'action_bool', 'resolved_value_not_pointer',
                                   'resolved_namespace'))
def test_original_store_inventory_internal_correspondence_even_after_resealing(change):
    record = _record(_strided(), known=True)
    view, summary = _projection(record)
    occurrence, = record['cycle_graph']['unresolved_accesses']
    if change == 'action_out_of_bounds':
        occurrence['action_id'] = 100000000
    elif change == 'action_other_operation':
        occurrence['action_id'] = 0
    elif change == 'action_bool':
        occurrence['action_id'] = True
    elif change == 'resolved_value_not_pointer':
        occurrence['address']['span'] = next(row['span'] for row in record['cycle_graph']['reads']
                                             if row['operation'] == occurrence['operation']
                                             and int(row['span'][-2], 16) == RSI)
    else:
        occurrence['address']['span'][3] = '0' * 64
    seal(record)
    with pytest.raises(Ineligible, match='STORE-only'):
        evaluate_loop_summary(record, summary['id'], _Unreadable())
