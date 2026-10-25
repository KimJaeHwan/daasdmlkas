"""Original ADDRESS operands participate in concrete physical byte overlays.

The existing admitted SSA and p-code interpreter remain the producer/oracle.
No original operand parts/debts are removed and no call return is injected.
These fixtures cover the global-memory COPY shape emitted by real x86 code,
including a global address that actually overlaps the entry stack.
"""

import copy as copying
from dataclasses import replace

import pytest

from pcode_interpreter import Interpreter
from record_oracle import entry_reader, final_register
from synthetic import (
    CONST, DATA_BASE, EXTERNAL, RAM, REG, R9, RAX, RBX, RCX, RDX, RSP,
    FunctionBuilder, const, copy, op, program_units, ram, reg, store, tmp,
)
from test_physical_call_records import (
    STACK, _assert_normal_return, _case, _record, _return_witness,
)
from tdo_v2._record_memory import evaluate_physical
from tdo_v2.operation_records import Ineligible, StitchContext, eligibility, root_record


GLOBAL = DATA_BASE


def _execute(case, *, stack=STACK, pointer=GLOBAL, value=7, saved=0x22,
             memory=(), registers=(), expected_opaque=()):
    vm = Interpreter(case['item'].unit.observation, constant_space=CONST, seed=0, program=case['program'])
    for offset, contents in ((RSP, stack), (RCX, pointer), (RDX, value), (RBX, saved), *registers):
        vm.preset(REG, offset, 8, contents)
    for address, size, contents in memory:
        vm.preset(RAM, address, size, contents)
    vm.preset(RAM, stack, 8, 0x2000)
    run = vm.run()
    assert run.completed and run.executed and vm.opaque_opcodes == set(expected_opaque)
    vm.fixture_run = run
    return vm


def _read_node(record, key):
    (node,) = [node for node in record['nodes'] if node.get('key') == key and node.get('kind') == 'op']
    return node


def _assert_read(operand, address, width=8):
    assert operand['parts'], 'the original SSA expression must remain in the record'
    source = operand['physical_read_source']
    assert {name: source[name] for name in ('space', 'address', 'width')} == dict(
        space=RAM, address=address, width=width)
    assert source['index'] == operand['index'] and source['operation']
    plan = operand['physical_read']
    assert plan['space'] == RAM and plan['address'] == address and plan['width'] == width
    assert plan['address_bits'] == 64 and plan['little_endian'] is True and plan['complete'] is True
    assert type(plan['guard']) is int and plan['events'] is not None


@pytest.mark.parametrize('stack,expected', ((STACK, 9), (GLOBAL + 8, 0x22)))
def test_direct_copy_observes_actual_stack_global_overlap(stack, expected):
    caller = FunctionBuilder().push(RBX).ins(copy(reg(RAX), ram(GLOBAL))).pop(RBX).ret()
    case = _case(caller, FunctionBuilder(entry=0x1800).ret())
    record = _record(case, '1:1004:0:COPY')
    ordinary = _record(case, '1:1004:0:COPY', physical=False)
    node = _read_node(record, '1:1004:0:COPY')
    _assert_read(node['operands'][0], GLOBAL)
    assert eligibility(record) == eligibility(ordinary) == 'debt'
    assert node['physical_read_debt_ids'] and set(node['physical_read_debt_ids']) <= set(node['debts'])
    vm = _execute(case, stack=stack, memory=((GLOBAL, 8, 9),))
    result = evaluate_physical(record, entry_reader(vm))
    assert result.value == final_register(vm, RAX, 8) == expected
    assert any(row.get('kind') == 'read' and row.get('key') == '1:1004:0:COPY' and row.get('input') == 0
               for row in result.evidence)


@pytest.mark.parametrize('second,expected', ((GLOBAL, 14), (GLOBAL + 8, 18)))
def test_two_address_operands_keep_each_original_read_and_byte_value(second, expected):
    caller = (FunctionBuilder().ins(store(reg(RCX), reg(RDX)))
              .ins(op('INT_ADD', [ram(GLOBAL), ram(second)], reg(RAX))).ret())
    case = _case(caller, FunctionBuilder(entry=0x1800).ret())
    record = _record(case, '1:1004:0:INT_ADD')
    node = _read_node(record, '1:1004:0:INT_ADD')
    assert len(node['operands']) == 2
    for operand, address in zip(node['operands'], (GLOBAL, second)):
        _assert_read(operand, address)
    assert node['physical_read_debt_ids']
    vm = _execute(case, memory=((GLOBAL, 8, 3), (GLOBAL + 8, 8, 11)))
    assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8) == expected


@pytest.mark.parametrize('active', (False, True))
def test_direct_read_skips_only_an_inactive_unknown_store(active):
    flag, value = tmp(0x300, 1), tmp(0x308)
    caller = (FunctionBuilder()
              .cbranch('read', flag, op('INT_EQUAL', [reg(R9), const(0)], flag))
              .ins(op('FLOAT_ADD', [reg(RDX), reg(RDX)], value), store(reg(RCX), value))
              .label('read').ins(copy(reg(RAX), ram(GLOBAL))).ret())
    case = _case(caller, FunctionBuilder(entry=0x1800).ret())
    record = _record(case, '1:1008:0:COPY')
    _assert_read(_read_node(record, '1:1008:0:COPY')['operands'][0], GLOBAL)
    vm = _execute(case, memory=((GLOBAL, 8, 9),), registers=((R9, int(active)),),
                  expected_opaque=('FLOAT_ADD',) if active else ())
    assert ('1:1004:1:STORE' in vm.fixture_run.executed) is active
    if active:
        with pytest.raises(Ineligible):
            evaluate_physical(record, entry_reader(vm))
    else:
        assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8) == 9


def test_direct_read_follows_a_return_verified_original_callee_store():
    caller = (FunctionBuilder().sub_rsp(0x28).call(0x1800)
              .ins(copy(reg(RAX), ram(GLOBAL))).add_rsp(0x28).ret())
    callee = (FunctionBuilder(entry=0x1800).push(RBX).sub_rsp(0x10)
              .ins(store(const(GLOBAL), reg(RDX))).add_rsp(0x10).pop(RBX).ret())
    case = _case(caller, callee)
    record = _record(case, '1:1008:0:COPY')
    ordinary = _record(case, '1:1008:0:COPY', physical=False)
    _assert_read(_read_node(record, '1:1008:0:COPY')['operands'][0], GLOBAL)
    assert record['physical_calls']
    assert eligibility(record) == eligibility(ordinary)
    vm = _execute(case, memory=((GLOBAL, 8, 9),))
    _assert_normal_return(_return_witness(case, vm))
    result = evaluate_physical(record, entry_reader(vm))
    assert result.value == final_register(vm, RAX, 8) == 7
    assert any(row.get('kind') == 'call' and row.get('call') == '1:1004:2:CALL'
               for row in result.evidence)


@pytest.mark.parametrize('mutation', ('space', 'address', 'width', 'guard', 'event_ref',
                                     'entry_context', 'source_address', 'missing_source', 'missing_plan'))
def test_malformed_direct_read_relation_refuses_without_laundering_original_debt(mutation):
    caller = (FunctionBuilder().ins(store(reg(RCX), reg(RDX)))
              .ins(copy(reg(RAX), ram(GLOBAL))).ret())
    case = _case(caller, FunctionBuilder(entry=0x1800).ret())
    record = _record(case, '1:1004:0:COPY')
    node = _read_node(record, '1:1004:0:COPY')
    _assert_read(node['operands'][0], GLOBAL)
    vm = _execute(case, memory=((GLOBAL, 8, 9),))
    assert evaluate_physical(record, entry_reader(vm)).value == 7
    bad = copying.deepcopy(record)
    operand = _read_node(bad, '1:1004:0:COPY')['operands'][0]
    plan = operand['physical_read']
    if mutation == 'space':
        plan['space'] = EXTERNAL
    elif mutation == 'address':
        plan['address'] += 1
    elif mutation == 'width':
        plan['width'] = 7
    elif mutation == 'guard':
        plan['guard'] = len(bad['control']['nodes']) + 10
    elif mutation == 'event_ref':
        (event,) = plan['events']
        event['node'] = len(bad['nodes']) + 10
    elif mutation == 'entry_context':
        plan['entry_context'] = 'absent-original-call'
    elif mutation == 'source_address':
        operand['physical_read_source']['address'] += 1
    elif mutation == 'missing_source':
        del operand['physical_read_source']
    elif mutation == 'missing_plan':
        del operand['physical_read']
    assert operand['parts'] == node['operands'][0]['parts']
    assert eligibility(bad) == eligibility(record) == 'debt'
    with pytest.raises(Ineligible):
        evaluate_physical(bad, entry_reader(vm))


def test_external_address_operand_is_not_fabricated_as_entry_ram():
    from tdo_v2.interprocedural import analyze_units

    unresolved = {**ram(0x100), 'space_id': EXTERNAL}
    caller = FunctionBuilder().ins(copy(reg(RAX), unresolved)).ret()
    (unit,) = program_units(caller)
    # This unresolved external ADDRESS is rejected at original scope
    # admission, before it could acquire an invented physical RAM plan.
    assert unit.observation is None
    provenance = {}
    assert analyze_units([unit], record_provenance=provenance) == {}
    assert not provenance


@pytest.mark.parametrize('displacement', (0, 2))
def test_same_operation_memory_input_precedes_its_same_or_overlapping_output(displacement):
    caller = FunctionBuilder().ins(copy(ram(GLOBAL + displacement, 4), ram(GLOBAL, 4))).ret()
    case = _case(caller, FunctionBuilder(entry=0x1800).ret())
    record = _record(case, '1:1000:0:COPY')
    node = _read_node(record, '1:1000:0:COPY')
    _assert_read(node['operands'][0], GLOBAL, 4)
    assert not node['operands'][0]['physical_read']['events'], 'this operation has not written yet'
    vm = _execute(case, memory=((GLOBAL, 8, 0x8877665544332211),))
    result = evaluate_physical(record, entry_reader(vm))
    assert result.value == 0x44332211
    stored = sum(vm._byte(RAM, GLOBAL + displacement + index)[0] << (8 * index) for index in range(4))
    assert stored == result.value
    reads = [row for row in result.evidence if row.get('kind') == 'read' and row.get('input') == 0]
    assert reads and all('writer' not in source for read in reads for source in read['sources'])


def test_direct_call_and_branch_destinations_remain_control_coordinates():
    caller = (FunctionBuilder().sub_rsp(0x28).call(0x1800).add_rsp(0x28)
              .branch('done').label('done').ins(copy(reg(RAX), const(7))).ret())
    case = _case(caller, FunctionBuilder(entry=0x1800).ret())
    item = case['item']
    keys = ('1:1004:2:CALL', '1:100c:0:BRANCH')
    seeds = [(item.normalized.dependencies.node_for_key('op:' + key), ()) for key in keys]
    assert all(node is not None for node, _ in seeds)
    record = root_record(item.normalized, item.unit, seeds, declared=item.declared,
                         provenance=case['provenance'][id(item)][1], stitch=StitchContext(case['provenance']),
                         physical_memory=True)
    for key, target in zip(keys, (0x1800, 0x1010)):
        (operand,) = _read_node(record, key)['operands']
        assert operand['role'] == 'target' and operand['value'] == target
        assert 'physical_read' not in operand and 'physical_read_source' not in operand


def test_debt_coverage_requires_every_original_row_span_not_one_supported_operand(monkeypatch):
    """Adversarial diagnostic-view unit test, not altered raw-program evidence.

    The legitimate SSA, observation and receipt remain unchanged. Only the
    builder's diagnostic debt-row view gains an uncovered real register span,
    so its all-span coverage gate must not authorize that complete debt ID.
    """
    import tdo_v2.operation_records as records

    caller = (FunctionBuilder().ins(store(reg(RCX), reg(RDX)))
              .ins(copy(reg(RAX), ram(GLOBAL))).ret())
    case = _case(caller, FunctionBuilder(entry=0x1800).ret())
    accepted = _record(case, '1:1004:0:COPY')
    assert _read_node(accepted, '1:1004:0:COPY')['physical_read_debt_ids']
    original = records._Builder.__init__
    changed = []

    def uncovered_span(builder, *args, **kwargs):
        original(builder, *args, **kwargs)
        register_span = next(definition.span for definition in builder.ssa.definitions
                             if definition.span.object_id.kind.value == 'register_file')
        for node, row in tuple(builder.debt_rows.items()):
            if row.operation_key == '1:1004:0:COPY' and row.spans:
                builder.debt_rows[node] = replace(row, spans=(*row.spans, register_span))
                changed.append(node)

    monkeypatch.setattr(records._Builder, '__init__', uncovered_span)
    rejected = _record(case, '1:1004:0:COPY')
    assert changed
    node = _read_node(rejected, '1:1004:0:COPY')
    _assert_read(node['operands'][0], GLOBAL)
    assert not node.get('physical_read_debt_ids') and node['debts']
    vm = _execute(case, memory=((GLOBAL, 8, 9),))
    with pytest.raises(Ineligible):
        evaluate_physical(rejected, entry_reader(vm))
