"""Post-call register fragments keep their original SSA writes and byte order."""

import copy as copying

import pytest

from record_oracle import entry_reader, final_register
from synthetic import R9, RAX, RBX, RCX, RDX, RSP, FunctionBuilder, add, const, copy, load, op, reg, store, tmp
from test_physical_call_records import _case, _execute, _record
from tdo_v2.operation_records import Ineligible, Limits, eligibility, evaluate_physical


VALUE = 0x1122334455667788
MASK = (1 << 64) - 1


def _partial_case(writes=((0, 1, 0xaa),), *, staged=False, conditional=False, unknown=False, wide=8,
                  byte_input=False, other_operand=False, fresh=R9):
    caller = (FunctionBuilder().sub_rsp(0x28).ins(store(reg(RCX), const(7)), copy(reg(RDX), reg(RCX)))
              .call(0x1800))
    if conditional:
        caller.cbranch('skip', reg(R9, 1))
    for offset, size, value in writes:
        caller.ins(copy(reg(RAX + offset, size), reg(fresh, size) if unknown else const(value, size)))
    if conditional:
        caller.label('skip')
    if wide == 4:
        caller.ins(op('INT_ZEXT', [reg(RAX, 4)], reg(RAX)))
    if staged:
        if staged == 'copy':
            caller.ins(copy(reg(RCX), reg(RAX)))
        caller.call(0x1a00)
    key = f'1:{caller._address(len(caller._rows)):x}:0:INT_ADD'
    caller.ins(add(reg(RAX), reg(RAX), reg(R9) if other_operand else const(5))).add_rsp(0x28).ret()
    callee = (FunctionBuilder(entry=0x1800).push(RBX).sub_rsp(0x10)
              .ins(store(reg(RDX), const(VALUE)), load(reg(RAX), reg(RCX)),
                   add(reg(RAX), reg(RAX), const(1))))
    if byte_input:
        callee.ins(load(reg(R9, 1), reg(R9)))
    if other_operand:
        callee.ins(copy(reg(R9), reg(RAX)))
    callee.add_rsp(0x10).pop(RBX).ret()
    extra = ((FunctionBuilder(entry=0x1a00).ins(copy(reg(RAX), reg(RCX))) if staged == 'copy' else
              FunctionBuilder(entry=0x1a00).ins(add(reg(RAX), reg(RAX), const(1)))).ret(),) if staged else ()
    return _case(caller, callee, *extra), key


def _expected(writes):
    value = (VALUE + 1) & MASK
    for offset, size, replacement in writes:
        mask = ((1 << (8 * size)) - 1) << (8 * offset)
        value = (value & ~mask) | (replacement << (8 * offset))
    return (value + 5) & MASK


@pytest.mark.parametrize('writes', (
    ((0, 1, 0xaa),),       # AL
    ((1, 1, 0xbb),),       # AH: placement != producer byte offset
    ((0, 2, 0xccdd),),     # AX
    ((0, 1, 0xaa), (3, 1, 0xbb)),
    ((1, 1, 0xff), (1, 1, 0x12)),
    ((0, 4, 0xabcdef01),),  # raw four-byte write, without an invented zero-extension
))
def test_partial_register_writes_preserve_all_other_call_bytes(writes):
    case, key = _partial_case(writes)
    record = _record(case, key)
    vm = _execute(case)
    result = evaluate_physical(record, entry_reader(vm))
    assert result.value == final_register(vm, RAX, 8) == _expected(writes)
    assert eligibility(record) == 'debt'
    root = next(node for node in record['nodes'] if node.get('key') == key)
    operand = next(item for item in root['operands'] if item['index'] == 0)
    relation = operand['physical_register_fragments']
    replaced = {byte for item in relation['overrides'] for byte in range(item['offset'], item['offset'] + item['size'])}
    overwritten = {byte for offset, size, _ in writes for byte in range(offset, offset + size)}
    assert replaced == set(range(8)) - overwritten
    assert any(row['kind'] == 'register_fragments' for row in result.evidence)


def test_raw_zero_extension_writes_the_high_bytes_instead_of_reusing_a_call():
    case, key = _partial_case(((0, 4, 0xabcdef01),), wide=4)
    record = _record(case, key)
    vm = _execute(case)
    assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8) == 0xabcdef06
    root = next(node for node in record['nodes'] if node.get('key') == key)
    assert not any('physical_register_fragments' in item for item in root['operands'])


def test_overwriting_every_byte_does_not_depend_on_the_previous_call_result():
    case, key = _partial_case(((0, 4, 0xabcdef01), (4, 4, 0x76543210)))
    record = _record(case, key)
    vm = _execute(case)
    assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8) == 0x76543210abcdef06
    root = next(node for node in record['nodes'] if node.get('key') == key)
    assert not root.get('physical_call_debt_ids')


@pytest.mark.parametrize('staged', ('copy', 'direct'))
@pytest.mark.parametrize('writes', (((0, 1, 0xaa),), ((1, 1, 0xbb),), ((0, 2, 0xccdd),)))
def test_partial_register_value_can_feed_the_next_observed_call(staged, writes):
    case, key = _partial_case(writes, staged=staged)
    record = _record(case, key)
    vm = _execute(case)
    expected = _expected(writes) + (staged == 'direct')
    assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8) == expected


def test_unknown_new_byte_is_not_filled_from_the_old_callee():
    case, key = _partial_case(unknown=True)
    record = _record(case, key)
    vm = _execute(case, registers=((R9, 0xaa),))
    known = entry_reader(vm)

    def entry(node):
        if isinstance(node, dict) and 'register' in node:
            span = node['register']
            if span['offset'] <= R9 < span['offset'] + span['size']:
                return None
        return known(node)

    with pytest.raises(Ineligible):
        evaluate_physical(record, entry)


def test_retained_write_must_still_resolve_its_own_call_debt_and_memory_input():
    case, key = _partial_case(((1, 1, 0),), unknown=True, byte_input=True)
    record = _record(case, key)
    vm = _execute(case, registers=((R9, 0x72000000),))
    known = entry_reader(vm)
    assert evaluate_physical(record, known).value == final_register(vm, RAX, 8)
    retained = [piece for node in record['nodes'] for operand in node.get('operands', ())
                for piece in operand.get('physical_register_fragments', {}).get('retained', ())]
    assert retained
    producers = [node for node in record['nodes'] if node.get('key') == retained[0]['operation']]
    inputs = [part['node'] for node in producers for operand in node['operands'] for part in operand['parts']]
    assert any(node['id'] in inputs and node.get('debts') for node in record['nodes']), \
        'do not erase the retained COPY input debt'

    def entry(node):
        if isinstance(node, tuple) and node[0] == 'memory' and node[2] == 0x72000000:
            return None
        return known(node)

    with pytest.raises(Ineligible):
        evaluate_physical(record, entry)


@pytest.mark.parametrize('opaque', (False, True))
def test_intervening_unknown_call_or_userop_is_not_bypassed(opaque):
    caller = (FunctionBuilder().sub_rsp(0x28).ins(store(reg(RCX), const(7)), copy(reg(RDX), reg(RCX)))
              .call(0x1800).ins(copy(reg(RAX + 1, 1), const(0xbb, 1))))
    if opaque:
        caller.ins(op('CALLOTHER', [const(7)], reg(RAX + 1, 1)))
    else:
        caller.call(0x1a00)
    key = f'1:{caller._address(len(caller._rows)):x}:0:INT_ADD'
    caller.ins(add(reg(RAX), reg(RAX), const(5))).add_rsp(0x28).ret()
    callee = FunctionBuilder(entry=0x1800).ins(copy(reg(RAX), const(VALUE))).ret()
    extra = () if opaque else (FunctionBuilder(entry=0x1a00).ins(op('CALLOTHER', [const(7)], reg(RAX))).ret(),)
    case = _case(caller, callee, *extra)
    record = _record(case, key)
    root = next(node for node in record['nodes'] if node.get('key') == key)
    assert not root.get('physical_call_debt_ids')
    assert not any('physical_register_fragments' in operand for operand in root['operands'])
    with pytest.raises(Ineligible):
        evaluate_physical(record, lambda _: 0)


def test_one_operand_overlay_cannot_waive_another_register_operand_debt():
    case, key = _partial_case(((1, 1, 0xbb),), other_operand=True)
    record = _record(case, key)
    vm = _execute(case)
    assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8)
    root = next(node for node in record['nodes'] if node.get('key') == key)
    assert root['physical_call_debt_ids']
    assert 'physical_register_fragments' in root['operands'][0]
    assert 'physical_register' in root['operands'][1]
    debt = next(node for node in record['nodes'] if node['id'] == root['physical_call_debt_ids'][0])
    assert {span['start'] for span in debt['physical_spans']} == {RAX, R9}
    del root['operands'][1]['physical_register']
    with pytest.raises(Ineligible, match='coverage'):
        evaluate_physical(record, lambda _: pytest.fail('incomplete coverage must fail before callbacks'))


def test_partial_overlay_limit_cuts_do_not_leave_dangling_register_exports():
    case, key = _partial_case(((1, 1, 0xbb),))
    complete = _record(case, key)
    expected = final_register(_execute(case), RAX, 8)
    known = entry_reader(_execute(case))
    successes = cuts = 0
    for nodes in range(1, len(complete['nodes']) + 12, 3):
        record = _record(case, key, limits=Limits(nodes=nodes))
        ids = {node['id'] for node in record['nodes']}

        def inspect(value):
            if isinstance(value, dict):
                if 'node' in value:
                    assert value['node'] in ids
                for child in value.values():
                    inspect(child)
            elif isinstance(value, (tuple, list)):
                for child in value:
                    inspect(child)

        inspect(record)
        try:
            assert evaluate_physical(record, known).value == expected
            successes += 1
        except Ineligible:
            cuts += 1
    assert successes and cuts


def test_ah_fragments_and_memory_share_the_original_indirect_target(monkeypatch):
    from test_indirect_physical_calls import _case as indirect_case, _execute as indirect_execute

    a, b = 0x1800, 0x1900
    t, u, i = tmp(0x100), tmp(0x180), tmp(0x200)
    caller = (FunctionBuilder().sub_rsp(0x48)
              .ins(copy(reg(RDX), reg(RSP)), copy(reg(R9), reg(RDX)),
                   add(t, reg(RSP), const(0x20)), store(t, const(a)),
                   add(u, reg(RSP), const(0x28)), store(u, const(b)))
              .ins(op('INT_AND', [reg(RCX), const(1)], i), op('INT_MULT', [i, const(8)], i),
                   add(i, i, reg(RSP)), add(i, i, const(0x20)), load(reg(RAX), i))
              .call_indirect(RAX).ins(copy(reg(RAX + 1, 1), const(0xee, 1)))
              .ins(load(tmp(0x400), reg(RDX)), add(reg(RAX), reg(RAX), tmp(0x400)))
              .add_rsp(0x48).ret())

    def callee(entry, value):
        return (FunctionBuilder(entry=entry).ins(store(reg(R9), const(value)), load(reg(RAX), reg(RDX)),
                                                add(reg(RAX), reg(RAX), const(1))).ret())

    values = (VALUE, 0x99887766aabbccdd)
    case = indirect_case(monkeypatch, caller=caller, a=callee(a, values[0]), b=callee(b, values[1]))
    key = '1:1014:1:INT_ADD'
    record = _record(case, key)
    root = next(node for node in record['nodes'] if node.get('key') == key)
    relation = root['operands'][0]['physical_register_fragments']
    selector, = record['target_selectors'].values()
    assert len(relation['overrides']) == 2
    assert {piece['context'] for piece in relation['overrides']} == {selector['id']}
    for choice, value in enumerate(values):
        vm = indirect_execute(case, choice)
        interpreted = evaluate_physical(record, entry_reader(vm))
        expected = ((((value + 1) & MASK) & ~0xff00) | 0xee00) + value
        assert interpreted.value == final_register(vm, RAX, 8) == expected & MASK
        selected, = [row for row in interpreted.evidence if row['kind'] == 'target']
        assert selected['target'] == (a if choice == 0 else b)
        sources = [source['writer'] for row in interpreted.evidence
                   if row['kind'] == 'load' and row['key'] == '1:1014:0:LOAD' for source in row['sources']]
        assert sources and set(sources) == {f'1:{a if choice == 0 else b:x}:0:STORE'}


def test_ah_fragments_from_multiple_returns_share_one_original_exit():
    caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RDX), reg(RCX))).call(0x1800)
              .ins(copy(reg(RAX + 1, 1), const(0xbb, 1))))
    key = f'1:{caller._address(len(caller._rows)):x}:0:INT_ADD'
    caller.ins(add(reg(RAX), reg(RAX), const(5))).add_rsp(0x28).ret()
    values = (VALUE, 0x99887766aabbccdd)
    callee = FunctionBuilder(entry=0x1800).cbranch('other', reg(R9, 1))
    callee.ins(store(reg(RDX), const(values[0])), load(reg(RAX), reg(RCX))).ret()
    callee.label('other').ins(store(reg(RDX), const(values[1])), load(reg(RAX), reg(RCX))).ret()
    case = _case(caller, callee)
    record = _record(case, key)
    context, = record['physical_calls'].values()
    assert len(context['returns']) == 2
    for choice, value in enumerate(values):
        vm = _execute(case, registers=((R9, choice),))
        interpreted = evaluate_physical(record, entry_reader(vm))
        expected = ((value & ~0xff00) | 0xbb00) + 5
        assert interpreted.value == final_register(vm, RAX, 8) == expected & MASK
        call, = [row for row in interpreted.evidence if row['kind'] == 'call']
        assert call['return'] in vm.fixture_run.executed


@pytest.mark.parametrize('choice', (0, 1))
def test_a_mixed_phi_of_new_write_and_old_call_byte_uses_the_original_condition(choice):
    case, key = _partial_case(conditional=True)
    record = _record(case, key)
    vm = _execute(case, registers=((R9, choice),))
    interpreted = evaluate_physical(record, entry_reader(vm))
    assert interpreted.value == final_register(vm, RAX, 8)
    assert any('physical_register_choice' in node for node in record['nodes'])
    assert eligibility(record) == 'debt'


@pytest.mark.parametrize('mutation', ('offset', 'size', 'register', 'input', 'read', 'context', 'part',
                                     'original', 'gap', 'overlap', 'order', 'pruned', 'unresolved'))
def test_fragment_metadata_cannot_replace_new_ssa_bytes_or_unrelated_exports(mutation):
    case, key = _partial_case(((1, 1, 0xaa),))
    record = _record(case, key)
    root = next(node for node in record['nodes'] if node.get('key') == key)
    operand = next(item for item in root['operands'] if 'physical_register_fragments' in item)
    relation = operand['physical_register_fragments']
    first = relation['overrides'][0]
    if mutation == 'offset':
        first['offset'] += 1
    elif mutation == 'size':
        first['size'] += 1
    elif mutation == 'register':
        first['register_offset'] += 1
    elif mutation == 'input':
        relation['input'] = 1
    elif mutation == 'read':
        relation['read'] = '1:dead:0:COPY'
    elif mutation == 'context':
        first['context'] = 'unknown'
    elif mutation == 'part':
        first['part'] = dict(relation['parts'][1], at=[0, 1])
    elif mutation == 'original':
        relation['parts'][1] = dict(relation['parts'][0], at=[1, 2])
    elif mutation == 'gap':
        relation['overrides'].pop()
    elif mutation == 'overlap':
        relation['overrides'].append(copying.deepcopy(first))
    elif mutation == 'order':
        relation['overrides'].reverse()
    else:
        operand[mutation] = True

    def forbidden(_):
        pytest.fail('malformed fragment relation must fail before entry callbacks')

    with pytest.raises(Ineligible):
        evaluate_physical(record, forbidden)
