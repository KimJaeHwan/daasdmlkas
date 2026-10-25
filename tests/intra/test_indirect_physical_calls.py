"""Original-target CALLIND selections reuse existing SSA and raw byte overlays."""

import copy as copying

import pytest

from pcode_interpreter import Interpreter
from record_oracle import entry_reader, final_register
from synthetic import (
    CONST, RAM, REG, RAX, RCX, RDX, RSI, RSP, FunctionBuilder, add, const, copy,
    load, op, program_units, reg, store, tmp,
)
from test_physical_call_records import OPTIONS, _record
from tdo_v2.interprocedural import analyze_units
from tdo_v2.operation_records import Ineligible, Limits, evaluate_physical, render
from tdo_v2.summary_engine import run_assumptions


A, B, STACK = 0x1800, 0x1900, 0x70000000


def _caller(entry=0x1000):
    t, u, i = tmp(0x100), tmp(0x180), tmp(0x200)
    return (FunctionBuilder(entry=entry).sub_rsp(0x48)
            .ins(copy(reg(RDX), reg(RSP)), store(reg(RDX), reg(RSI)),
                 add(t, reg(RSP), const(0x20)), store(t, const(A)),
                 add(u, reg(RSP), const(0x28)), store(u, const(B)))
            .ins(op('INT_AND', [reg(RCX), const(1)], i), op('INT_MULT', [i, const(8)], i),
                 add(i, i, reg(RSP)), add(i, i, const(0x20)), load(reg(RAX), i))
            .call_indirect(RAX)
            .ins(load(tmp(0x400), reg(RDX)), add(reg(RAX), reg(RAX), tmp(0x400)))
            .add_rsp(0x48).ret())


def _callee(entry, increment):
    return (FunctionBuilder(entry=entry)
            .ins(load(reg(RAX), reg(RDX)), add(tmp(0x500), reg(RAX), const(increment)),
                 store(reg(RDX), tmp(0x500)), add(reg(RAX), reg(RAX), const(16 * increment)))
            .ret())


def _case(monkeypatch, *, caller=None, a=None, b=None, forward=True, options=None, extra=()):
    monkeypatch.setenv('TDO_V2_FORWARD', '1' if forward else '0')
    units = program_units(caller or _caller(), a or _callee(A, 1), b or _callee(B, 2), *extra)
    provenance = {}
    results = analyze_units(units, record_provenance=provenance, **(OPTIONS | (options or {})))
    return dict(item=results['1:1000'], results=results, provenance=provenance, assumptions=run_assumptions(results),
                program={(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units})


def _final(case, **options):
    item = case['item']
    key = next(action.operation_key for action in item.normalized.memory_ssa.actions
               if action.operation_key.endswith(':INT_ADD')
               and ':1010:' in action.operation_key)
    return _record(case, key, **options)


def _execute(case, selector=0, value=9):
    vm = Interpreter(case['item'].unit.observation, constant_space=CONST, seed=0, program=case['program'])
    for offset, content in ((RSP, STACK), (RCX, selector), (RSI, value)):
        vm.preset(REG, offset, 8, content)
    vm.preset(RAM, STACK, 8, 0x2000)
    run = vm.run()
    assert run.completed and not vm.opaque_opcodes
    return vm


def test_target_memory_and_register_outputs_share_the_original_selection(monkeypatch):
    case = _case(monkeypatch)
    record = _final(case)
    assert not record['truncated']
    assert len(record['target_selectors']) == 1
    selector, = record['target_selectors'].values()
    assert [candidate['value'] for candidate in selector['candidates']] == [A, B]
    assert 'original target' in render(record)
    assert sum(node.get('physical_call_push') == selector['id'] for node in record['nodes']) == 1
    for choice in (0, 1):
        vm = _execute(case, choice)
        interpreted = evaluate_physical(record, entry_reader(vm))
        expected = 35 if choice == 0 else 52
        assert interpreted.value == final_register(vm, RAX, 8) == expected
        assert interpreted.value not in (36, 51)
        selected, = [row for row in interpreted.evidence if row['kind'] == 'target']
        assert selected['target'] == (A if choice == 0 else B)
        writers = [source['writer'] for row in interpreted.evidence if row['kind'] == 'load'
                   and row['key'] == '1:1010:0:LOAD' for source in row['sources']]
        assert writers and set(writers) == {f'1:{A if choice == 0 else B:x}:2:STORE'}
        calls = [row for row in interpreted.evidence if row['kind'] == 'call']
        assert len(calls) == 1 and calls[0]['context'] == selected['context']


def test_forward_off_keeps_the_original_indirect_boundary_unknown(monkeypatch):
    case = _case(monkeypatch, forward=False)
    record = _final(case)
    assert not record['target_selectors']
    with pytest.raises(Ineligible):
        evaluate_physical(record, entry_reader(_execute(case)))


def test_missing_run_premises_do_not_claim_an_empty_requires_set(monkeypatch):
    case = _case(monkeypatch)
    del case['assumptions']
    record = _final(case)
    assert not record['target_selectors']
    assert any('explicit run assumptions' in reason for reason in record['physical_call_cuts'].values())
    with pytest.raises(Ineligible):
        evaluate_physical(record, entry_reader(_execute(case)))


def test_a_same_address_body_from_another_analysis_is_not_a_candidate(monkeypatch):
    case, other = _case(monkeypatch), _case(monkeypatch)
    provenance = case['provenance'][id(case['item'])][1]
    call, = case['item'].multi_calls
    provenance.sources[call] = ('summaries', (other['results']['1:1800'], case['results']['1:1900']))
    record = _final(case)
    assert not record['target_selectors']
    with pytest.raises(Ineligible):
        evaluate_physical(record, entry_reader(_execute(case)))


def test_a_single_proven_indirect_candidate_still_reads_its_target(monkeypatch):
    caller = (FunctionBuilder().sub_rsp(0x48)
              .ins(copy(reg(RDX), reg(RSP)), store(reg(RDX), reg(RSI)), copy(reg(RAX), const(A)))
              .ins().call_indirect(RAX)
              .ins(load(tmp(0x400), reg(RDX)), add(reg(RAX), reg(RAX), tmp(0x400)))
              .add_rsp(0x48).ret())
    case = _case(monkeypatch, caller=caller)
    record = _final(case)
    selector, = record['target_selectors'].values()
    assert [candidate['value'] for candidate in selector['candidates']] == [A]
    result = evaluate_physical(record, entry_reader(_execute(case)))
    assert result.value == 35


def test_unselected_unknown_inputs_and_wrong_return_are_not_required(monkeypatch):
    from synthetic import RDI

    b = FunctionBuilder(entry=B).ins(copy(reg(RAX), reg(RDI))).add_rsp(8).ret()
    case = _case(monkeypatch, b=b)
    record = _final(case)
    vm = _execute(case, selector=0)
    known = entry_reader(vm)

    def entry(node):
        if isinstance(node, dict) and 'register' in node and node['register']['offset'] <= RDI \
                < node['register']['offset'] + node['register']['size']:
            return None
        return known(node)

    assert evaluate_physical(record, entry).value == 35
    selector, = record['target_selectors'].values()
    other = record['physical_calls'][selector['candidates'][1]['context']]
    detached = copying.deepcopy(record)
    detached['root'] = [other['returns'][0]['stack']['parts'][0]]
    with pytest.raises(Ineligible, match='unreached'):
        evaluate_physical(detached, entry)


def test_nested_repeated_call_sites_keep_separate_shared_target_selections(monkeypatch):
    parent = (FunctionBuilder().sub_rsp(0x28).call(0x1a00).ins(copy(reg(RCX), const(1)))
              .call(0x1a00).ins(add(reg(RAX), reg(RAX), const(5))).add_rsp(0x28).ret())
    case = _case(monkeypatch, caller=parent, extra=(_caller(entry=0x1a00),))
    record = _record(case, '1:1010:0:INT_ADD')
    assert len(record['target_selectors']) == 2
    assert set(record['target_selectors']) == {
        '1:1004:2:CALL/1:1a0c:3:CALLIND', '1:100c:2:CALL/1:1a0c:3:CALLIND'}
    for choice in (0, 1):
        vm = _execute(case, selector=choice)
        result = evaluate_physical(record, entry_reader(vm))
        assert result.value == final_register(vm, RAX, 8) == 57
        selected = [row for row in result.evidence if row['kind'] == 'target']
        assert len(selected) == 2 and selected[0]['function'] == f'1:{A if choice == 0 else B:x}'
        assert selected[1]['function'] == '1:1900'


def test_a_broken_frame_premise_cannot_make_the_enum_override_actual_ram(monkeypatch):
    from test_forward_values import _table

    # The policy intentionally assumes this incoming pointer cannot hit the
    # new frame. Concrete execution contradicts that premise. The physical
    # target LOAD must still read the overwrite and reject the out-of-set C.
    caller = _table(store(reg(RDX), const(0x1a00)))
    case = _case(monkeypatch, caller=caller, a=FunctionBuilder(entry=A).ret(),
                 b=FunctionBuilder(entry=B).ret(), options=dict(assume_entry_values_not_frame=True),
                 extra=(FunctionBuilder(entry=0x1a00).ret(),))
    call, = case['item'].multi_calls
    item = case['item']
    # A root after CALLIND, with no synthetic call return injection.
    key = next(action.operation_key for action in item.normalized.memory_ssa.actions
               if action.operation_key.endswith(':INT_ADD') and ':1018:' in action.operation_key)
    record = _record(case, key)
    assert record['target_selectors']
    vm = Interpreter(item.unit.observation, constant_space=CONST, seed=0, program=case['program'])
    for offset, content in ((RSP, STACK), (RCX, 0), (RDX, STACK - 0x48 + 0x20)):
        vm.preset(REG, offset, 8, content)
    vm.preset(RAM, STACK, 8, 0x2000)
    assert vm.run().completed
    with pytest.raises(Ineligible, match='outside proven candidates'):
        evaluate_physical(record, entry_reader(vm))


@pytest.mark.parametrize('change', ('duplicate', 'missing', 'reorder', 'space', 'width', 'function',
                                  'parent', 'source', 'source_kind', 'source_space', 'source_offset',
                                  'requires', 'push', 'output'))
def test_selector_correspondences_are_checked_before_entry_reads(monkeypatch, change):
    record = _final(_case(monkeypatch))
    selector, = record['target_selectors'].values()
    group = record['physical_calls'][selector['id']]
    first = selector['candidates'][0]
    if change == 'duplicate':
        selector['candidates'].append(copying.deepcopy(first))
    elif change == 'missing':
        selector['candidates'].pop()
    elif change == 'reorder':
        selector['candidates'].reverse()
    elif change == 'space':
        selector['space'] += 1
    elif change == 'width':
        selector['width'] -= 1
    elif change == 'function':
        first['function'] = '1:dead'
    elif change == 'parent':
        record['physical_calls'][first['context']]['parent_context'] = selector['id']
    elif change == 'source':
        selector['source']['producer'] = '1:dead:0:COPY'
    elif change in ('source_kind', 'source_space', 'source_offset'):
        field = change.removeprefix('source_')
        selector['source'][field] = 'CONSTANT' if field == 'kind' else 999999
    elif change == 'requires':
        selector['requires'] = ['unreported-premise']
    elif change == 'push':
        record['physical_calls'][first['context']]['push'] = dict(group['push'], width=1)
    elif change == 'output':
        phi = next(node for node in record['nodes'] if node.get('reason') == 'physical call targets')
        phi['alternatives'].reverse()

    def forbidden(_):
        pytest.fail('invalid selector must be rejected before consulting inputs')

    with pytest.raises(Ineligible):
        evaluate_physical(record, forbidden)


def test_actual_table_bytes_not_the_proven_enum_choose_the_target(monkeypatch):
    case = _case(monkeypatch)
    record = _final(case)
    selector, = record['target_selectors'].values()
    # Force a known wrong original target expression; never let the enum
    # silently choose an alternative. The replacement remains same-width.
    target = selector['operand']['parts'][0]['node']
    node = record['nodes'][target]
    identifier = len(record['nodes'])
    record['nodes'].append(dict(id=identifier, kind='const', size=8, value=0x1a00, physical_only=True))
    node['operands'][0] = dict(index=0, width=8, role='value',
                              parts=[dict(node=identifier, bytes=[0, 8], at=[0, 8])])
    with pytest.raises(Ineligible, match='outside proven candidates'):
        evaluate_physical(record, entry_reader(_execute(case)))


def test_indirect_construction_limit_does_not_leave_partial_selectors(monkeypatch):
    case = _case(monkeypatch)
    refused = 0
    for count in (40, 60, 80):
        record = _final(case, limits=Limits(nodes=count))
        ids = {node['id'] for node in record['nodes']}
        for selector in record['target_selectors'].values():
            assert selector['id'] in record['physical_calls']
            assert all(candidate['context'] in record['physical_calls'] for candidate in selector['candidates'])
        for context in record['physical_calls'].values():
            assert context['push']['node'] in ids
            assert all(output['part']['node'] in ids for output in context['outputs'])
        try:
            evaluate_physical(record, entry_reader(_execute(case)))
        except Ineligible:
            refused += 1
    assert refused
