"""Conditional byte overlays reuse the original SSA/CFG selection."""

import copy as copying

import pytest

from record_oracle import entry_reader, final_register
from synthetic import R8, R9, RAX, RCX, RDX, RSP, FunctionBuilder, add, const, copy, load, op, reg, store, tmp
from test_partial_register_calls import VALUE, _partial_case
from test_physical_call_records import _case, _execute, _record
from tdo_v2.operation_records import Ineligible, Limits, eligibility, evaluate_physical

R10 = 0x90


def _two_arm_case(*, before=False, both=False):
    caller = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RDX), reg(RCX)))
    if before:
        caller.ins(copy(reg(RAX), const(0xdeadbeef)))
    caller.call(0x1800).cbranch('other', reg(R9, 1)).ins(copy(reg(RAX + 1, 1), const(0xbb, 1)))
    caller.branch('merge').label('other')
    if both:
        caller.ins(copy(reg(RAX + 1, 1), const(0xcc, 1)))
    caller.label('merge')
    key = f'1:{caller._address(len(caller._rows)):x}:0:INT_ADD'
    caller.ins(add(reg(RAX), reg(RAX), const(5))).add_rsp(0x28).ret()
    callee = (FunctionBuilder(entry=0x1800).ins(store(reg(RDX), const(VALUE)), load(reg(RAX), reg(RCX)),
                                              add(reg(RAX), reg(RAX), const(1))).ret())
    return _case(caller, callee), key


@pytest.mark.parametrize('before,both', ((True, False), (False, True), (True, True)))
@pytest.mark.parametrize('selector', (0, 1))
def test_pre_call_ssa_and_two_fresh_arms_do_not_replace_actual_call_bytes(before, both, selector):
    case, key = _two_arm_case(before=before, both=both)
    record = _record(case, key)
    vm = _execute(case, registers=((R9, selector),))
    assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8)
    assert any('physical_register_choice' in node for node in record['nodes'])


@pytest.mark.parametrize('mutation', ('before_to_retained', 'other_inventory', 'conflicting_phase'))
def test_original_call_boundary_inventory_cannot_reclassify_pre_call_ssa(mutation):
    case, key = _two_arm_case(before=True)
    record = _record(case, key)
    node = next(node for node in record['nodes'] if 'physical_register_choice' in node)
    choice = node['physical_register_choice']
    index = next(i for i, item in enumerate(choice['sources']) if item['kind'] == 'call')
    context = record['physical_calls'][choice['context']]
    if mutation == 'before_to_retained':
        choice['sources'][index]['kind'] = 'retained'
        node['alternatives'][index] = dict(choice['sources'][index]['original'])
    elif mutation == 'other_inventory':
        context['caller_register_writes'][0]['context'] = '1:unrelated:0:CALL'
    else:
        row = dict(context['caller_register_writes'][0], phase='after')
        context['caller_register_writes'].append(row)
    with pytest.raises(Ineligible):
        evaluate_physical(record, lambda _: pytest.fail('wrong call-boundary phase must fail before callbacks'))


@pytest.mark.parametrize('writes', (((0, 1, 0xaa),), ((1, 1, 0xbb),), ((0, 2, 0xccdd),),
                                    ((0, 1, 0xaa), (3, 1, 0xbb))))
@pytest.mark.parametrize('choice', (0, 1))
@pytest.mark.parametrize('staged', (False, 'direct'))
def test_conditional_partial_registers_preserve_original_phi_and_next_call(writes, choice, staged):
    case, key = _partial_case(writes, conditional=True, staged=staged)
    record = _record(case, key)
    before = copying.deepcopy(record)
    vm = _execute(case, registers=((R9, choice),))
    result = evaluate_physical(record, entry_reader(vm))
    assert result.value == final_register(vm, RAX, 8)
    assert record == before and eligibility(record) == 'debt'
    guarded = [node for node in record['nodes'] if 'physical_register_choice' in node]
    assert guarded
    for node in guarded:
        source = record['nodes'][node['physical_register_choice']['source']['node']]
        assert all(node.get(field) == source.get(field) for field in ('condition', 'choices', 'guarded_sources'))


@pytest.mark.parametrize('choice', (0, 1))
def test_unselected_new_byte_input_is_not_required(choice):
    case, key = _partial_case(((1, 1, 0),), conditional=True, unknown=True, fresh=R10)
    record = _record(case, key)
    vm = _execute(case, registers=((R9, choice), (R10, 0xbb)))
    known = entry_reader(vm)

    def entry(node):
        if isinstance(node, dict) and 'register' in node:
            span = node['register']
            if span['offset'] <= R10 < span['offset'] + span['size']:
                return None
        return known(node)

    if choice:
        assert evaluate_physical(record, entry).value == final_register(vm, RAX, 8)
    else:
        with pytest.raises(Ineligible):
            evaluate_physical(record, entry)


@pytest.mark.parametrize('comparison', (VALUE + 1, VALUE + 2))
def test_branch_predicate_can_read_the_actual_call_output(comparison):
    flag = tmp(0x980, 1)
    caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RDX), reg(RCX))).call(0x1800)
              .cbranch('skip', flag, op('INT_NOTEQUAL', [reg(RAX), const(comparison)], flag))
              .ins(copy(reg(RAX + 1, 1), const(0xbb, 1))).label('skip'))
    key = f'1:{caller._address(len(caller._rows)):x}:0:INT_ADD'
    caller.ins(add(reg(RAX), reg(RAX), const(5))).add_rsp(0x28).ret()
    callee = (FunctionBuilder(entry=0x1800).ins(store(reg(RDX), const(VALUE)), load(reg(RAX), reg(RCX)),
                                              add(reg(RAX), reg(RAX), const(1))).ret())
    case = _case(caller, callee)
    record = _record(case, key)
    vm = _execute(case)
    assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8)


@pytest.mark.parametrize('mutation', ('guards', 'source', 'range', 'call', 'alternatives', 'original', 'kind',
                                     'context', 'retained_to_call'))
def test_guarded_overlay_cannot_change_original_choice_or_fresh_ssa_bytes(mutation):
    case, key = _partial_case(((1, 1, 0xbb),), conditional=True)
    record = _record(case, key)
    node = next(node for node in record['nodes'] if 'physical_register_choice' in node)
    choice = node['physical_register_choice']
    if mutation == 'guards':
        node['guarded_sources']['guards'].reverse()
    elif mutation == 'source':
        choice['source']['node'] = node['id']
    elif mutation == 'range':
        choice['register_offset'] += 1
    elif mutation == 'call':
        choice['call'] = '1:dead:0:CALL'
    elif mutation == 'alternatives':
        node['alternatives'].reverse()
    elif mutation == 'original':
        choice['sources'][0]['original'] = dict(node['alternatives'][0])
    elif mutation == 'kind':
        next(item for item in choice['sources'] if item['kind'] == 'call')['kind'] = 'retained'
    elif mutation == 'context':
        choice['context'] = 'unknown'
    else:
        index = next(i for i, item in enumerate(choice['sources']) if item['kind'] == 'retained')
        call_index = next(i for i, item in enumerate(choice['sources']) if item['kind'] == 'call')
        choice['sources'][index]['kind'] = 'call'
        node['alternatives'][index] = dict(node['alternatives'][call_index])
    with pytest.raises(Ineligible):
        evaluate_physical(record, lambda _: pytest.fail('invalid overlay must fail before callbacks'))


def test_guarded_overlay_node_limits_do_not_leak_partial_alternatives():
    case, key = _partial_case(((1, 1, 0xbb),), conditional=True)
    complete = _record(case, key)
    vm = _execute(case, registers=((R9, 0),))
    successes = cuts = 0
    for nodes in range(1, len(complete['nodes']) + 12, 4):
        record = _record(case, key, limits=Limits(nodes=nodes))
        try:
            assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8)
            successes += 1
        except Ineligible:
            cuts += 1
    assert successes and cuts


@pytest.mark.parametrize('limit', ('depth', 'edges'))
def test_guarded_overlay_never_uses_a_cut_as_an_original_register_producer(limit):
    case, key = _two_arm_case(before=True, both=True)
    vm = _execute(case, registers=((R9, 0),))
    maximum = 24 if limit == 'depth' else 170
    for value in range(1, maximum, 1 if limit == 'depth' else 7):
        record = _record(case, key, limits=Limits(**{limit: value}))
        try:
            assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8)
        except Ineligible:
            pass


@pytest.mark.parametrize('target,condition', ((0, 0), (0, 1), (1, 0), (1, 1)))
def test_conditional_byte_and_ram_keep_the_same_indirect_call_target(monkeypatch, target, condition):
    from test_indirect_physical_calls import _case as indirect_case

    a, b = 0x1800, 0x1900
    t, u, i = tmp(0x100), tmp(0x180), tmp(0x200)
    caller = (FunctionBuilder().sub_rsp(0x48)
              .ins(copy(reg(RDX), reg(RSP)), copy(reg(R9), reg(RDX)),
                   add(t, reg(RSP), const(0x20)), store(t, const(a)),
                   add(u, reg(RSP), const(0x28)), store(u, const(b)))
              .ins(op('INT_AND', [reg(RCX), const(1)], i), op('INT_MULT', [i, const(8)], i),
                   add(i, i, reg(RSP)), add(i, i, const(0x20)), load(reg(RAX), i))
              .call_indirect(RAX).cbranch('skip', reg(R8, 1))
              .ins(copy(reg(RAX + 1, 1), const(0xbb, 1))).label('skip'))
    address = caller._address(len(caller._rows))
    key = f'1:{address:x}:1:INT_ADD'
    caller.ins(load(tmp(0x400), reg(RDX)), add(reg(RAX), reg(RAX), tmp(0x400))).add_rsp(0x48).ret()

    def callee(entry, value):
        return (FunctionBuilder(entry=entry).ins(store(reg(R9), const(value)), load(reg(RAX), reg(RDX)),
                                                add(reg(RAX), reg(RAX), const(1))).ret())

    values = (VALUE, 0x99887766aabbccdd)
    case = indirect_case(monkeypatch, caller=caller, a=callee(a, values[0]), b=callee(b, values[1]))
    record = _record(case, key)
    vm = _execute(case, registers=((RCX, target), (R8, condition)))
    interpreted = evaluate_physical(record, entry_reader(vm))
    assert interpreted.value == final_register(vm, RAX, 8)
    selected, = [row for row in interpreted.evidence if row['kind'] == 'target']
    assert selected['target'] == (a if target == 0 else b)
    writers = [source['writer'] for row in interpreted.evidence
               if row['kind'] == 'load' and row['key'] == f'1:{address:x}:0:LOAD' for source in row['sources']]
    assert writers and set(writers) == {f'1:{a if target == 0 else b:x}:0:STORE'}


@pytest.mark.parametrize('outer,inner', ((0, 0), (0, 1), (1, 0), (1, 1)))
def test_nested_byte_choices_keep_paired_writes_on_the_same_original_path(outer, inner):
    caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RDX), reg(RCX))).call(0x1800)
              .cbranch('outer', reg(R9, 1))
              .ins(copy(reg(RAX, 1), const(0xaa, 1)), copy(reg(RAX + 1, 1), const(0xcc, 1)))
              .branch('merge').label('outer').cbranch('merge', reg(R8, 1))
              .ins(copy(reg(RAX, 1), const(0xbb, 1)), copy(reg(RAX + 1, 1), const(0xdd, 1)))
              .label('merge'))
    key = f'1:{caller._address(len(caller._rows)):x}:0:INT_ADD'
    caller.ins(add(reg(RAX), reg(RAX), const(5))).add_rsp(0x28).ret()
    callee = (FunctionBuilder(entry=0x1800).ins(store(reg(RDX), const(VALUE)), load(reg(RAX), reg(RCX)),
                                              add(reg(RAX), reg(RAX), const(1))).ret())
    case = _case(caller, callee)
    record = _record(case, key)
    vm = _execute(case, registers=((R9, outer), (R8, inner)))
    result = evaluate_physical(record, entry_reader(vm))
    expected = VALUE + 1 if outer and inner else ((VALUE + 1) & ~0xffff) | (0xddbb if outer else 0xccaa)
    assert result.value == final_register(vm, RAX, 8) == expected + 5
    choices = [node for node in record['nodes'] if 'physical_register_choice' in node]
    assert len(choices) == 2
    assert choices[0]['guarded_sources'] == choices[1]['guarded_sources']
