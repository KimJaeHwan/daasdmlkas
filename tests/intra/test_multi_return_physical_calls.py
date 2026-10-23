"""One shared original RETURN selection for memory and register projections."""

import copy as copying

import pytest

from record_oracle import entry_reader, final_register
from synthetic import R9, RAX, RBX, RCX, RDX, FunctionBuilder, add, const, copy, load, reg, store
from test_physical_call_records import (
    _assert_normal_return, _case, _execute, _record, _return_witness,
)
from test_nested_physical_calls import _execute as _nested_execute, _normal_returns
from tdo_v2.operation_records import Ineligible, eligibility, evaluate_physical


def _callee(*, entry=0x1800, wrong_stack=False):
    function = FunctionBuilder(entry=entry).push(RBX).sub_rsp(0x10).cbranch('other', reg(R9, 1))
    function.ins(load(reg(RAX), reg(RCX)), add(reg(RAX), reg(RAX), const(3)),
                 store(reg(RCX), reg(RAX))).add_rsp(0x10).pop(RBX).ret()
    function.label('other').ins(load(reg(RAX), reg(RCX)), add(reg(RAX), reg(RAX), const(9)),
                                store(reg(RCX), reg(RAX)))
    function.add_rsp(0x10)
    if not wrong_stack:
        function.pop(RBX)
    return function.ret()


@pytest.mark.parametrize('selector,expected', ((0, 15), (1, 21), (255, 21)))
def test_multiple_returns_select_original_memory_effect_and_actual_return(selector, expected):
    case = _case(callee=_callee())
    record = _record(case)
    (context,) = record['physical_calls'].values()
    assert len(context['returns']) == 2 and 'return' not in context
    vm = _execute(case, registers=((R9, selector),))
    _assert_normal_return(_return_witness(case, vm))
    assert final_register(vm, RAX, 8) == expected
    result = evaluate_physical(record, entry_reader(vm))
    assert result.value == expected and eligibility(record) == 'debt'
    (call,) = [row for row in result.evidence if row['kind'] == 'call']
    assert call['return'] == context['returns'][int(bool(selector))]['key']


def test_unselected_unbalanced_return_does_not_affect_the_valid_exit():
    case = _case(callee=_callee(wrong_stack=True))
    record = _record(case)
    good = _execute(case, registers=((R9, 0),))
    assert evaluate_physical(record, entry_reader(good)).value == 15
    bad = _execute(case, registers=((R9, 1),))
    # The interpreter can force its saved continuation; the real RETURN/SP
    # constraints remain authoritative and must reject that continuation.
    witness = _return_witness(case, bad)
    assert witness['ip'] != witness['expected_ip'] or witness['sp'] != witness['expected_sp']
    with pytest.raises(Ineligible):
        evaluate_physical(record, entry_reader(bad))


@pytest.mark.parametrize('guards', ((0, 0), (1, 1)))
def test_zero_or_multiple_reached_returns_are_not_an_output_union(guards):
    case = _case(callee=_callee())
    record = copying.deepcopy(_record(case))
    (context,) = record['physical_calls'].values()
    for returned, guard in zip(context['returns'], guards, strict=True):
        returned['guard'] = guard
    vm = _execute(case, registers=((R9, 0),))
    with pytest.raises(Ineligible):
        evaluate_physical(record, entry_reader(vm))


def test_two_multi_return_calls_have_distinct_decisions_and_memory_entries():
    caller = (FunctionBuilder().sub_rsp(0x28).ins(store(reg(RCX), reg(RDX)))
              .call(0x1800).ins(copy(reg(R9), const(1))).call(0x1800)
              .ins(load(reg(RAX), reg(RCX)), add(reg(RAX), reg(RAX), const(5))).add_rsp(0x28).ret())
    case = _case(caller, _callee())
    record = _record(case, '1:1014:1:INT_ADD')
    vm = _execute(case, registers=((R9, 0),))
    for call in case['item'].calls:
        _assert_normal_return(_return_witness(case, vm, call))
    assert len(record['physical_calls']) == 2
    assert len({decision['selection'] for decision in record['control']['decisions'].values()}) == 2
    assert final_register(vm, RAX, 8) == 24
    assert evaluate_physical(record, entry_reader(vm)).value == 24


def test_unknown_exit_condition_is_not_implicitly_chosen():
    case = _case(callee=_callee())
    record = _record(case)
    vm = _execute(case, registers=((R9, 0),))
    known = entry_reader(vm)

    def entry(node):
        if isinstance(node, dict) and 'register' in node:
            register = node['register']
            if register['offset'] <= R9 < register['offset'] + register['size']:
                return None
        return known(node)

    with pytest.raises(Ineligible):
        evaluate_physical(record, entry)


@pytest.mark.parametrize('selector,expected', ((0, 15), (1, 21)))
def test_register_export_and_return_use_the_same_original_exit(selector, expected):
    caller = (FunctionBuilder().sub_rsp(0x28).ins(store(reg(RCX), reg(RDX))).call(0x1800)
              .ins(add(reg(RAX), reg(RAX), const(5))).add_rsp(0x28).ret())
    case = _case(caller, _callee())
    record = _record(case, '1:100c:0:INT_ADD')
    vm = _execute(case, registers=((R9, selector),))
    _assert_normal_return(_return_witness(case, vm))
    assert final_register(vm, RAX, 8) == expected
    (context,) = record['physical_calls'].values()
    assert context['outputs'] and len(context['returns']) == 2
    phis = [node for node in record['nodes'] if node.get('instance') == context['id']
            and node.get('physical_context') == context['id'] and node.get('reason') == 'callee exits']
    assert phis
    assert all([record['nodes'][part['node']]['execution_guard'] for part in phi['alternatives']]
               == [returned['guard'] for returned in context['returns']] for phi in phis)
    assert evaluate_physical(record, entry_reader(vm)).value == expected


@pytest.mark.parametrize('mutation', ('order', 'guard', 'instance', 'target', 'stack'))
def test_multi_exit_export_cannot_disagree_with_its_original_return_selection(mutation):
    caller = (FunctionBuilder().sub_rsp(0x28).ins(store(reg(RCX), reg(RDX))).call(0x1800)
              .ins(add(reg(RAX), reg(RAX), const(5))).add_rsp(0x28).ret())
    case = _case(caller, _callee())
    record = copying.deepcopy(_record(case, '1:100c:0:INT_ADD'))
    (context,) = record['physical_calls'].values()
    phi = next(record['nodes'][output['part']['node']] for output in context['outputs']
               if record['nodes'][output['part']['node']].get('reason') == 'callee exits')
    if mutation == 'order':
        phi['alternatives'].reverse()
    elif mutation == 'guard':
        wrapper = record['nodes'][phi['alternatives'][0]['node']]
        wrapper['execution_guard'] = context['returns'][1]['guard']
    elif mutation == 'instance':
        phi['instance'] += '/unrelated-call'
    elif mutation == 'target':
        context['returns'][1]['expected_target'] += 1
    else:
        wrong = next(node['id'] for node in record['nodes']
                     if node['kind'] == 'const' and node['size'] == 8 and node['value'] == 5)
        context['returns'][1]['expected_stack'] = dict(
            width=8, parts=[dict(node=wrong, bytes=[0, 8], at=[0, 8])])
    vm = _execute(case, registers=((R9, 0),))
    with pytest.raises(Ineligible):
        evaluate_physical(record, entry_reader(vm))


@pytest.mark.parametrize('selector,expected', ((0, 17), (1, 23)))
def test_nested_multi_return_body_connects_register_result_and_later_memory(selector, expected):
    outer = (FunctionBuilder(entry=0x1800).sub_rsp(0x28).call(0x1a00)
             .ins(add(reg(RAX), reg(RAX), const(2)), store(reg(RCX), reg(RAX))).add_rsp(0x28).ret())
    case = _case(None, outer, _callee(entry=0x1a00))
    record = _record(case)
    assert len(record['physical_calls']) == 2
    assert sorted(len(context['returns']) for context in record['physical_calls'].values()) == [1, 2]
    vm = _nested_execute(case, registers=((R9, selector),))
    _normal_returns(case, vm, 2)
    assert final_register(vm, RAX, 8) == expected
    assert evaluate_physical(record, entry_reader(vm)).value == expected
