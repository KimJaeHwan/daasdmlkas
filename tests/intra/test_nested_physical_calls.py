"""Nested physical contexts checked against the existing raw-pcode VM.

The VM schedules saved continuations, so normal-output assertions separately
check every activation's actual RETURN target and post-RETURN stack value.
No calling convention, boundary-value injection or no-alias model is used.
"""

import copy as copying

import pytest

from record_oracle import entry_reader, final_register
from pcode_interpreter import Interpreter
from synthetic import (
    CONST, DATA_BASE, RAM, REG, RIP, R8, R9, RAX, RBX, RCX, RDX, RSI, RSP, FunctionBuilder,
    add, const, copy, load, op, ram, reg, store,
)
from test_physical_call_records import POINTER, STACK, _case, _record
from tdo_v2._record_memory import evaluate_physical
from tdo_v2.observed_call_state import observed_call_state_projections
from tdo_v2.operation_records import Ineligible, Limits, eligibility


OUTER, INNER, DEEPEST = 0x1800, 0x1a00, 0x1c00
OUTER_ENTRY, INNER_ENTRY = STACK - 0x30, STACK - 0x60


class _WitnessInterpreter(Interpreter):
    """Observe every actual CALL/RETURN; the existing VM runs semantics.

    Its public activation snapshots intentionally group nested calls into
    the outermost activation for dependency checking. These observations add
    no execution behavior, stack restoration or continuation interpretation.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.nested_witnesses, self.witness_stack = [], []

    def _execute(self, key, operation, run):
        jump = super()._execute(key, operation, run)

        def register(offset):
            return sum(self._bytes[(REG, offset + index)][0] << (8 * index) for index in range(8))

        if jump is not None and jump[0] == 'call':
            witness = dict(call=key, entered_stack=register(RSP))
            self.nested_witnesses.append(witness)
            self.witness_stack.append(witness)
        elif jump is not None and jump[0] == 'return' and self.witness_stack:
            self.witness_stack.pop().update(target=register(RIP), stack=register(RSP))
        return jump


def _execute(case, *, pointer=POINTER, value=7, saved=0x22, stack=STACK, registers=(), memory=(), expected_opaque=()):
    vm = _WitnessInterpreter(case['item'].unit.observation, constant_space=CONST, seed=0, program=case['program'],
                             resume_unvalidated_returns=True)  # (a VM: damaged returns run on)
    for offset, contents in ((RSP, stack), (RCX, pointer), (RDX, value), (RBX, saved), *registers):
        vm.preset(REG, offset, 8, contents)
    vm.preset(RAM, stack, 8, 0x2000)
    for space, address, width, contents in memory:
        vm.preset(space, address, width, contents)
    run = vm.run()
    assert run.completed and vm.opaque_opcodes == set(expected_opaque)
    assert not vm.witness_stack
    vm.fixture_run = run
    return vm


def _nested_case(*, root_calls=1, inner_calls=1, before=True, balanced=True,
                 register_result=False, conditional=False, skip_parent=False,
                 deepest=False, missing_inner=False):
    caller = FunctionBuilder().sub_rsp(0x28).ins(store(reg(RCX), reg(RDX)))
    if skip_parent:
        caller.cbranch('read', reg(R8, 1))
    for _ in range(root_calls):
        caller.call(OUTER)
    if skip_parent:
        caller.label('read')
    address = caller._address(len(caller._rows))
    if register_result:
        caller.ins(add(reg(RAX), reg(RAX), const(5)))
        key = f'1:{address:x}:0:INT_ADD'
    else:
        caller.ins(load(reg(RAX), reg(RCX)), add(reg(RAX), reg(RAX), const(5)))
        key = f'1:{address:x}:1:INT_ADD'
    caller.add_rsp(0x28).ret()
    outer = FunctionBuilder(entry=OUTER).push(RBX).sub_rsp(0x20)
    if before:
        outer.ins(load(reg(RAX), reg(RCX)), add(reg(RAX), reg(RAX), const(2)),
                  store(reg(RCX), reg(RAX)))
    if conditional:
        outer.cbranch('after', reg(R9, 1))
    for _ in range(inner_calls):
        outer.call(INNER)
    if conditional:
        outer.label('after')
    outer.ins(load(reg(RAX), reg(RCX)), add(reg(RAX), reg(RAX), const(3)),
              store(reg(RCX), reg(RAX))).add_rsp(0x20).pop(RBX).ret()
    inner = FunctionBuilder(entry=INNER).push(RSI).sub_rsp(0x10)
    extra = []
    if deepest:
        inner.call(DEEPEST)
        extra.append(FunctionBuilder(entry=DEEPEST).ins(
            load(reg(RAX), reg(RCX)), add(reg(RAX), reg(RAX), const(8)),
            store(reg(RCX), reg(RAX))).ret())
    inner.ins(load(reg(RAX), reg(RCX)), add(reg(RAX), reg(RAX), const(4)),
              store(reg(RCX), reg(RAX))).add_rsp(0x10)
    if balanced:
        inner.pop(RSI)
    inner.ret()
    if not missing_inner:
        extra.insert(0, inner)
    return _case(caller, outer, *extra), key


def _return_witnesses(case, vm):
    locations, projections = {}, {}
    for item in case['results'].values():
        for projection in observed_call_state_projections(item.unit.observation):
            projections[projection.call_operation_key] = projection
        for row in item.unit.observation.instructions:
            for ordinal, operation in enumerate(row.operations):
                if operation.opcode == 'CALL':
                    locations[f'{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:CALL'] = row
    found = []
    for witness in vm.nested_witnesses:
        call = witness['call']
        row, projection = locations[call], projections[call]
        assert row.fallthrough is not None
        found.append(dict(call=call, target=witness['target'],
                          expected_target=row.fallthrough.byte_offset,
                          stack=witness['stack'],
                          expected_stack=witness['entered_stack']
                          - projection.memory_transition.displacement_delta))
    return found


def _normal_returns(case, vm, count):
    found = _return_witnesses(case, vm)
    assert len(found) == count
    assert all(row['target'] == row['expected_target'] and row['stack'] == row['expected_stack'] for row in found)


@pytest.mark.parametrize('pointer,expected', (
    (POINTER, 21),
    (OUTER_ENTRY - 8, 48),  # caller data aliases the outer saved-RBX write
    (INNER_ENTRY - 8, 80),  # the inner saved-RSI write supersedes the outer value
    (OUTER_ENTRY - 12, 0x2200000015),  # partial overlap with the outer prologue
))
@pytest.mark.parametrize('register_result', (False, True))
def test_nested_body_memory_and_register_outputs_use_actual_parent_entry(pointer, expected, register_result):
    case, key = _nested_case(register_result=register_result)
    vm = _execute(case, pointer=pointer, registers=((RSI, 0x44),))
    _normal_returns(case, vm, 2)
    assert final_register(vm, RAX, 8) == expected
    record = _record(case, key)
    original = copying.deepcopy(record)
    result = evaluate_physical(record, entry_reader(vm))
    assert result.value == expected
    assert len(record['physical_calls']) == 2
    (parent,) = [identifier for identifier, context in record['physical_calls'].items()
                 if context.get('parent_context') is None]
    (child,) = [identifier for identifier, context in record['physical_calls'].items()
                if context.get('parent_context') == parent]
    assert child.startswith(parent + '/')
    assert len([row for row in result.evidence if row['kind'] == 'call']) == 2
    assert record == original and eligibility(record) == 'debt'


def test_nested_entry_falls_through_parent_entry_not_root_ram_callback():
    case, key = _nested_case(before=False)
    vm = _execute(case, registers=((RSI, 0x44),))
    _normal_returns(case, vm, 2)
    known = entry_reader(vm)

    def entry(node):
        if isinstance(node, tuple) and node[0] == 'memory' and node[1] == RAM and POINTER <= node[2] < POINTER + 8:
            pytest.fail('the original caller STORE supplies these bytes before both call entries')
        return known(node)

    assert final_register(vm, RAX, 8) == 19
    assert evaluate_physical(_record(case, key), entry).value == 19


@pytest.mark.parametrize('root_calls,inner_calls,expected,count', ((2, 1, 30, 4), (1, 2, 25, 3)))
def test_same_nested_helper_instances_have_separate_paths_and_memory_entries(root_calls, inner_calls, expected, count):
    case, key = _nested_case(root_calls=root_calls, inner_calls=inner_calls)
    vm = _execute(case, registers=((RSI, 0x44),))
    _normal_returns(case, vm, count)
    assert final_register(vm, RAX, 8) == expected
    record = _record(case, key)
    assert len(record['physical_calls']) == count
    children = [(identifier, context) for identifier, context in record['physical_calls'].items()
                if context.get('parent_context') is not None]
    assert len(children) == 2 and len({identifier for identifier, _ in children}) == 2
    if root_calls == 2:
        assert len({context['call'] for _, context in children}) == 1
        assert len({context['parent_context'] for _, context in children}) == 2
    assert evaluate_physical(record, entry_reader(vm)).value == expected


@pytest.mark.parametrize('pointer', (INNER_ENTRY, OUTER_ENTRY))
def test_nested_or_parent_return_address_damage_rejects_the_whole_transaction(pointer):
    case, key = _nested_case()
    vm = _execute(case, pointer=pointer, registers=((RSI, 0x44),))
    witnesses = _return_witnesses(case, vm)
    assert any(row['target'] != row['expected_target'] for row in witnesses)
    # The VM's saved-continuation scheduler is not a witness of normal return
    # after an actual RETURN operand was overwritten.
    with pytest.raises(Ineligible, match='return target mismatch'):
        evaluate_physical(_record(case, key), entry_reader(vm))


def test_unbalanced_nested_return_refuses_even_if_the_vm_schedules_a_continuation():
    case, key = _nested_case(balanced=False)
    vm = _execute(case, registers=((RSI, 0x44),))
    assert any(row['stack'] != row['expected_stack'] for row in _return_witnesses(case, vm))
    with pytest.raises(Ineligible):
        evaluate_physical(_record(case, key), entry_reader(vm))


def test_selected_nested_prologue_requires_its_store_value_even_when_output_does_not():
    case, key = _nested_case()
    vm = _execute(case, registers=((RSI, 0x44),))
    _normal_returns(case, vm, 2)
    known = entry_reader(vm)

    def entry(node):
        if isinstance(node, dict) and 'register' in node:
            span = node['register']
            if span['offset'] < RSI + 8 and RSI < span['offset'] + span['size']:
                return None
        return known(node)

    with pytest.raises(Ineligible, match='unknown physical inputs'):
        evaluate_physical(_record(case, key), entry)


def test_inactive_nested_call_does_not_require_its_prologue_values():
    case, key = _nested_case(conditional=True)
    vm = _execute(case, registers=((R9, 1), (RSI, 0x44)))
    _normal_returns(case, vm, 1)
    assert final_register(vm, RAX, 8) == 17
    known = entry_reader(vm)

    def entry(node):
        if isinstance(node, dict) and 'register' in node:
            span = node['register']
            if span['offset'] < RSI + 8 and RSI < span['offset'] + span['size']:
                pytest.fail('inactive nested body must not demand RSI')
        return known(node)

    assert evaluate_physical(_record(case, key), entry).value == 17


def test_unreached_parent_short_circuits_child_local_guard_and_detached_value():
    case, key = _nested_case(conditional=True, skip_parent=True)
    vm = _execute(case, registers=((R8, 1), (R9, 0), (RSI, 0x44)))
    _normal_returns(case, vm, 0)
    record = _record(case, key)
    known = entry_reader(vm)

    def entry(node):
        if isinstance(node, dict) and 'register' in node:
            span = node['register']
            if span['offset'] < R9 + 8 and R9 < span['offset'] + span['size']:
                pytest.fail('an unreached parent must short-circuit the child local predicate')
        return known(node)

    assert final_register(vm, RAX, 8) == evaluate_physical(record, entry).value == 12
    (child,) = [identifier for identifier, context in record['physical_calls'].items()
                if context.get('parent_context') is not None]
    (write,) = [node for node in record['nodes'] if node.get('physical_context') == child
                and node.get('opcode') == 'STORE' and node.get('key', '').endswith(':2:STORE')]
    detached = copying.deepcopy(record)
    detached['root'] = [{**record['root'][0], 'node': write['id'], 'bytes': [0, 8], 'at': [0, 8]}]
    with pytest.raises(Ineligible, match='unreached'):
        evaluate_physical(detached, entry)


@pytest.mark.parametrize('mutation', ('missing', 'self', 'cycle', 'type', 'body_call_owner', 'store_owner', 'load_entry'))
def test_nested_parent_forest_and_event_ownership_are_checked_before_entry(mutation):
    case, key = _nested_case()
    record = _record(case, key)
    (parent,) = [identifier for identifier, context in record['physical_calls'].items()
                 if context.get('parent_context') is None]
    (child,) = [identifier for identifier, context in record['physical_calls'].items()
                if context.get('parent_context') == parent]
    if mutation == 'missing':
        record['physical_calls'][child]['parent_context'] = 'missing'
    elif mutation == 'self':
        record['physical_calls'][child]['parent_context'] = child
    elif mutation == 'cycle':
        record['physical_calls'][parent]['parent_context'] = child
    elif mutation == 'type':
        record['physical_calls'][child]['parent_context'] = False
    elif mutation == 'body_call_owner':
        record['physical_calls'][child]['parent_context'] = None
    elif mutation == 'store_owner':
        (write,) = [node for node in record['nodes'] if node.get('physical_context') == child
                    and node.get('opcode') == 'STORE' and node.get('key', '').endswith(':2:STORE')]
        write['physical_context'] = parent
    else:
        node = next(node for node in record['nodes'] if node.get('physical_context') == child
                    and node.get('physical_memory'))
        node['physical_memory']['entry_context'] = parent

    def entry(_):
        pytest.fail('malformed context relations must be rejected before physical inputs')

    with pytest.raises(Ineligible):
        evaluate_physical(record, entry)


def test_three_analyzed_levels_use_existing_configured_call_depth():
    case, key = _nested_case(deepest=True)
    vm = _execute(case, registers=((RSI, 0x44),))
    _normal_returns(case, vm, 3)
    assert final_register(vm, RAX, 8) == 29
    record = _record(case, key, limits=Limits(call_depth=3))
    assert len(record['physical_calls']) == 3
    assert evaluate_physical(record, entry_reader(vm)).value == 29
    with pytest.raises(Ineligible):
        evaluate_physical(_record(case, key, limits=Limits(call_depth=2)), entry_reader(vm))


def test_final_synthetic_call_output_uses_an_inclusive_raw_call_prefix():
    case, _ = _nested_case(register_result=True)
    item = case['item']
    candidates = [(action, identifier) for action in item.normalized.memory_ssa.actions
                  if action.operation_key.partition('~')[2].isdigit()
                  for identifier in action.write_definition_ids
                  if item.normalized.memory_ssa.definitions[identifier].span.start == RAX]
    assert candidates
    action, identifier = candidates[-1]
    record = _record(case, action.operation_key)
    assert record['physical_effect_inventory'] is True
    assert any(event['kind'] == 'call' for event in record['physical_root_events'])
    vm = _execute(case, registers=((RSI, 0x44),))
    _normal_returns(case, vm, 2)
    # This selector is the value immediately after the call, before caller +5.
    assert evaluate_physical(record, entry_reader(vm)).value == 16


def _direct_write_case(address=DATA_BASE + 0x100, *, opcode='COPY', conditional=False, implicit_read=False):
    caller = (FunctionBuilder().sub_rsp(0x28).ins(store(reg(RCX), reg(RDX)))
              .call(OUTER).ins(load(reg(RAX), reg(RCX)), add(reg(RAX), reg(RAX), const(5)))
              .add_rsp(0x28).ret())
    outer = FunctionBuilder(entry=OUTER).push(RBX).sub_rsp(0x20).call(INNER)
    if not implicit_read:
        outer.ins(load(reg(RAX), reg(RCX)))
    outer.ins(add(reg(RAX), reg(RAX), const(3)), store(reg(RCX), reg(RAX)))
    outer.add_rsp(0x20).pop(RBX).ret()
    inner = FunctionBuilder(entry=INNER)
    if conditional:
        inner.cbranch('after', reg(R9, 1))
    if implicit_read:
        inner.ins(copy(reg(RAX), ram(address)))
    elif opcode == 'COPY':
        inner.ins(copy(ram(address), const(0x1122334455667788)))
    else:
        inner.ins(op(opcode, [reg(RDX), reg(RDX)], ram(address)))
    if conditional:
        inner.label('after')
    inner.ret()
    return _case(caller, outer, inner), '1:100c:1:INT_ADD'


@pytest.mark.parametrize('offset,expected', (
    (0, 0x1122334455667790), (1, 0x001122334455667f),
    (-1, 0x223344556677880f), (0x100, 15),
))
def test_nested_direct_ram_output_write_shares_the_store_byte_overlay(offset, expected):
    address = DATA_BASE + 0x100
    case, key = _direct_write_case(address)
    vm = _execute(case, pointer=address + offset)
    _normal_returns(case, vm, 2)
    assert final_register(vm, RAX, 8) == expected
    record = _record(case, key)
    events = [event for context in record['physical_calls'].values() for event in context['events']
              if event['kind'] == 'write']
    assert len(events) == 1 and events[0]['address'] == address and events[0]['width'] == 8
    result = evaluate_physical(record, entry_reader(vm))
    assert result.value == expected
    assert any(row['kind'] == 'write' and row['key'] == '1:1a00:0:COPY' for row in result.evidence)


def test_literal_ram_write_can_alias_the_nested_return_slot_and_must_not_be_ignored():
    stack = DATA_BASE + 0x800
    case, key = _direct_write_case(stack - 0x60)
    vm = _execute(case, stack=stack)
    assert any(row['target'] != row['expected_target'] for row in _return_witnesses(case, vm))
    with pytest.raises(Ineligible, match='return target mismatch'):
        evaluate_physical(_record(case, key), entry_reader(vm))


@pytest.mark.parametrize('active', (False, True))
def test_all_active_direct_write_values_are_required_even_when_result_never_reads_them(active):
    case, key = _direct_write_case(opcode='FLOAT_ADD', conditional=True)
    vm = _execute(case, registers=((R9, 0 if active else 1),),
                  expected_opaque=('FLOAT_ADD',) if active else ())
    _normal_returns(case, vm, 2)
    record = _record(case, key)
    if active:
        with pytest.raises(Ineligible):
            evaluate_physical(record, entry_reader(vm))
    else:
        assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8) == 15


@pytest.mark.parametrize('field', ('address', 'width', 'space', 'output_start', 'output_size'))
def test_direct_write_geometry_must_match_original_operation_before_entry(field):
    case, key = _direct_write_case()
    record = _record(case, key)
    (event,) = [event for context in record['physical_calls'].values() for event in context['events']
                if event['kind'] == 'write']
    writer = next(node for node in record['nodes'] if node['id'] == event['node'])
    if field.startswith('output_'):
        writer['output'][field.removeprefix('output_')] += 1
    else:
        event[field] += 1

    def entry(_):
        pytest.fail('inconsistent physical direct-write coordinates must fail before entry')

    with pytest.raises(Ineligible, match='direct-write relation'):
        evaluate_physical(record, entry)


def test_nested_literal_address_read_reuses_original_ssa_read_and_parent_overlay():
    case, key = _direct_write_case(implicit_read=True)
    vm = _execute(case, pointer=DATA_BASE + 0x100)
    _normal_returns(case, vm, 2)
    assert final_register(vm, RAX, 8) == 15
    record = _record(case, key)
    assert any(node.get('key') == '1:1a00:0:COPY' for node in record['nodes'])
    assert eligibility(record) == 'debt'
    result = evaluate_physical(record, entry_reader(vm))
    assert result.value == 15
    (read,) = [row for row in result.evidence if row['kind'] == 'read' and row['key'] == '1:1a00:0:COPY']
    assert {source['writer'] for source in read['sources']} == {'1:1004:0:STORE'}
    assert eligibility(record) == 'debt'
    changed = copying.deepcopy(record)
    (operand,) = [operand for node in changed['nodes'] if node.get('key') == '1:1a00:0:COPY'
                  for operand in node.get('operands', ()) if 'physical_read' in operand]
    del operand['physical_read']
    with pytest.raises(Ineligible):
        evaluate_physical(changed, entry_reader(vm))


@pytest.mark.parametrize('alias,expected', ((False, 41), (True, 7)))
def test_literal_ram_input_selects_concrete_store_alias_or_entry_bytes(alias, expected):
    address = DATA_BASE + 0x100
    caller = FunctionBuilder().ins(store(reg(RCX), reg(RDX))).ins(copy(reg(RAX), ram(address))).ret()
    case = _case(caller, FunctionBuilder(entry=OUTER).ret())
    vm = _execute(case, pointer=address if alias else POINTER, memory=((RAM, address, 8, 41),))
    assert final_register(vm, RAX, 8) == expected
    record = _record(case, '1:1004:0:COPY')
    assert eligibility(record) == 'debt'
    result = evaluate_physical(record, entry_reader(vm))
    assert result.value == expected
    assert any(row['kind'] == 'read' and row['preserved_debts'] for row in result.evidence)


@pytest.mark.parametrize('value,expected', ((0, 2), (1, 1)))
def test_literal_ram_condition_input_uses_the_same_guarded_overlay(value, expected):
    address = DATA_BASE + 0x100
    caller = (FunctionBuilder().ins(store(reg(RCX), reg(RDX)))
              .cbranch('yes', ram(address, 1)).ins(copy(reg(RAX), const(2))).branch('merge')
              .label('yes').ins(copy(reg(RAX), const(1)))
              .label('merge').ins(copy(reg(RAX), reg(RAX))).ret())
    case = _case(caller, FunctionBuilder(entry=OUTER).ret())
    vm = _execute(case, pointer=address, value=value)
    record = _record(case, '1:1014:0:COPY')
    assert final_register(vm, RAX, 8) == expected
    assert evaluate_physical(record, entry_reader(vm)).value == expected


@pytest.mark.parametrize('field', ('address', 'space', 'width', 'operation', 'index', 'context', 'guard', 'incomplete'))
def test_literal_read_geometry_and_owning_operation_are_checked_before_inputs(field):
    case, key = _direct_write_case(implicit_read=True)
    record = _record(case, key)
    (operand,) = [operand for node in record['nodes'] if node.get('key') == '1:1a00:0:COPY'
                  for operand in node.get('operands', ()) if 'physical_read' in operand]
    if field in ('address', 'space', 'width'):
        operand['physical_read'][field] += 1
    elif field == 'operation':
        operand['physical_read_source'][field] = '1:1a04:2:RETURN'
    elif field == 'index':
        operand['physical_read_source'][field] += 1
    elif field == 'context':
        operand['physical_read_source'][field] = None
    elif field == 'guard':
        operand['physical_read'][field] = 0
    else:
        operand['physical_read']['complete'] = False

    def entry(_):
        pytest.fail('inconsistent direct-read relation must fail before physical inputs')

    with pytest.raises(Ineligible):
        evaluate_physical(record, entry)


@pytest.mark.parametrize('alias,expected', ((False, 41), (True, 7)))
def test_direct_input_and_output_overlap_reads_strictly_before_the_same_operation(alias, expected):
    address = DATA_BASE + 0x100
    caller = (FunctionBuilder().ins(store(reg(RCX), reg(RDX)))
              .ins(copy(ram(address), ram(address))).ins(load(reg(RAX), const(address))).ret())
    case = _case(caller, FunctionBuilder(entry=OUTER).ret())
    vm = _execute(case, pointer=address if alias else POINTER, memory=((RAM, address, 8, 41),))
    record = _record(case, '1:1008:0:LOAD')
    result = evaluate_physical(record, entry_reader(vm))
    assert result.value == final_register(vm, RAX, 8) == expected
    reads = [row for row in result.evidence if row['kind'] == 'read']
    assert reads and not any(source.get('writer') == '1:1004:0:COPY'
                             for read in reads for source in read['sources'])
    (loaded,) = [row for row in result.evidence if row['kind'] == 'load']
    assert {source['writer'] for source in loaded['sources']} == {'1:1004:0:COPY'}


def test_missing_literal_read_entry_byte_is_not_a_partial_physical_result():
    address = DATA_BASE + 0x100
    caller = FunctionBuilder().ins(copy(reg(RAX), ram(address))).ret()
    case = _case(caller, FunctionBuilder(entry=OUTER).ret())
    vm = _execute(case, memory=((RAM, address, 8, 41),))
    known = entry_reader(vm)

    def entry(node):
        if node == ('memory', RAM, address + 3, 1):
            return None
        return known(node)

    with pytest.raises(Ineligible, match='unknown physical inputs'):
        evaluate_physical(_record(case, '1:1000:0:COPY'), entry)


def test_direct_plan_requires_an_existing_exact_memory_read_not_only_raw_address_kind():
    from tdo_v2._record_conditions import ConditionIndex
    from tdo_v2._record_memory import MemoryIndex
    from tdo_v2.lane_slice import lane_index

    address = DATA_BASE + 0x100
    caller = (FunctionBuilder().cbranch('yes', ram(address, 1)).ins(copy(reg(RAX), const(2))).ret()
              .label('yes').ins(copy(reg(RAX), const(1))).ret())
    case = _case(caller, FunctionBuilder(entry=OUTER).ret())
    item = case['item']
    index = lane_index(item.normalized, item.unit)
    conditions = ConditionIndex(item.normalized, item.unit, index)
    memory = MemoryIndex(item.normalized, item.unit, index, conditions)
    key = '1:1000:0:CBRANCH'
    assert memory.plan_direct(key, 0)[0] is None  # direct code destination is not a data read
    assert memory.plan_direct(key, 1)[0] is not None
    action_id = memory.actions[key]
    index.reads[action_id] = ()
    without_read = MemoryIndex(item.normalized, item.unit, index, conditions)
    assert without_read.plan_direct(key, 1) == (None, 'no existing exact physical memory read')


def test_only_exact_known_synthetic_output_rows_have_after_call_prefix_semantics():
    from tdo_v2._record_conditions import ConditionIndex
    from tdo_v2._record_memory import MemoryIndex
    from tdo_v2.lane_slice import lane_index

    case, _ = _nested_case(register_result=True)
    item = case['item']
    index = lane_index(item.normalized, item.unit)
    memory = MemoryIndex(item.normalized, item.unit, index, ConditionIndex(item.normalized, item.unit, index))
    inventory, reason = memory.inventory()
    assert inventory and reason is None
    call = next(iter(item.calls))
    for key in (call + '~in', call + '~sink', call + '~99999', call + '~u0'):
        assert memory.prefix(key)[0] is None
    for action in index.ssa.actions:
        if action.operation_key.startswith(call + '~') and not action.operation_key.partition('~')[2].isdigit():
            assert memory.prefix(action.operation_key)[0] is None
