"""Concrete physical direct-leaf CALL records, with original static debt kept.

These are scoped synthetic raw-pcode fixtures, not native binary execution.
The existing interpreter executes every caller/callee operation. Its RETURN
scheduler uses saved continuations, so the oracle also checks the activation's
actual loaded return IP and post-RET SP. A wrong return is never accepted as a
normal continuation merely because the interpreter reports completion.
"""

import copy as copying

import pytest

from pcode_interpreter import Interpreter
from record_oracle import entry_reader, final_register
from synthetic import (
    CONST, RAM, REG, RIP, R9, RAX, RBX, RCX, RDX, RSP, FunctionBuilder, add, const, copy,
    load, op, program_units, reg, store, tmp,
)
from tdo_v2._record_memory import evaluate_physical
from tdo_v2.interprocedural import analyze_units
from tdo_v2.observed_call_state import observed_call_state_projections
from tdo_v2.operation_records import Ineligible, Limits, StitchContext, eligibility, evaluate, root_record


ROOT, CALLEE, INNER = '1:1000', '1:1800', 0x1a00
STACK, POINTER = 0x70000000, 0x71000000
CALL_SP, CALLEE_SP = STACK - 0x28, STACK - 0x30
OPTIONS = dict(assume_import_slots_hold_exports=False, assume_globals_disjoint_from_stack=False,
               assume_entry_values_not_frame=False, assume_opaque_callees_leave_no_stack_addresses=False,
               private_frame_above=0)


def _caller():
    return (FunctionBuilder().sub_rsp(0x28).ins(store(reg(RCX), reg(RDX))).call(0x1800)
            .ins(load(reg(RAX), reg(RCX)), add(reg(RAX), reg(RAX), const(5)))
            .add_rsp(0x28).ret())


def _callee(increment=3, *, balanced=True, nested=False):
    function = FunctionBuilder(entry=0x1800).push(RBX).sub_rsp(0x10)
    if nested:
        function.sub_rsp(0x28).call(INNER).add_rsp(0x28)
    function.ins(load(reg(RAX), reg(RCX)), add(reg(RAX), reg(RAX), const(increment)),
                 store(reg(RCX), reg(RAX))).add_rsp(0x10)
    if balanced:
        function.pop(RBX)
    return function.ret()


def _case(caller=None, callee=None, *extra):
    units = program_units(caller or _caller(), callee or _callee(), *extra)
    provenance = {}
    results = analyze_units(units, record_provenance=provenance, **OPTIONS)
    for item in results.values():
        assert not item.declared and not item.inherited_assumptions
        assert not item.normalized.assumes_globals_disjoint_from_stack
        assert not item.normalized.assumes_entry_values_not_frame
        assert not item.normalized.assumes_opaque_callees_leave_no_stack_addresses
        assert not item.normalized.assumes_import_slots_hold_exports
    return dict(item=results[ROOT], callee=results[CALLEE], results=results, provenance=provenance,
                program={(unit.scopes.function.entry.space_id, unit.scopes.function.entry.byte_offset):
                         unit.observation for unit in units})


def _record(case, key='1:100c:1:INT_ADD', *, physical=True, limits=None, stitch=True):
    item = case['item']
    action = next(action for action in item.normalized.memory_ssa.actions if action.operation_key == key)
    assert action.write_definition_ids
    return root_record(item.normalized, item.unit,
                       [(item.normalized.memory_graph.definition_nodes[index],
                         (item.normalized.memory_ssa.definitions[index].span,))
                        for index in action.write_definition_ids],
                       declared=item.declared, provenance=case['provenance'][id(item)][1],
                       stitch=StitchContext(case['provenance']) if stitch else None,
                       physical_memory=physical, limits=limits)


def _execute(case, *, pointer=POINTER, value=7, saved=0x22, registers=(), expected_opaque=()):
    vm = Interpreter(case['item'].unit.observation, constant_space=CONST, seed=0, program=case['program'])
    for offset, contents in ((RSP, STACK), (RCX, pointer), (RDX, value), (RBX, saved), *registers):
        vm.preset(REG, offset, 8, contents)
    vm.preset(RAM, STACK, 8, 0x2000)  # caller's own outer return input
    run = vm.run()
    assert run.completed and run.executed and vm.opaque_opcodes == set(expected_opaque)
    vm.fixture_run = run
    return vm


def _return_witness(case, vm, call=None):
    """Read existing activation data, not the scheduler's forced continuation."""
    calls = [key for key, target in case['item'].calls.items() if target == CALLEE]
    if call is None:
        (call,) = calls
    assert call in calls
    (instruction,) = [row for row in case['item'].unit.observation.instructions
                      if any(f'{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:CALL' == call
                             for ordinal, operation in enumerate(row.operations) if operation.opcode == 'CALL')]
    assert instruction.fallthrough is not None
    (serial,) = [serial for serial, (key, _) in vm.activation_snapshots.items() if key == call]
    entry, returned = vm.activation_snapshots[serial][1], vm.activation_returns[serial]
    ret = case['callee'].unit.observation.instructions[-1]
    assert [operation.opcode for operation in ret.operations] == ['LOAD', 'INT_ADD', 'RETURN']
    assert ret.operations[0].output.coordinate.byte_offset == RIP
    assert ret.operations[2].inputs[0] == ret.operations[0].output
    assert ret.operations[1].output.coordinate.byte_offset == RSP

    def register(state, offset):
        return sum(state[(REG, offset + index)] << (8 * index) for index in range(8))

    assert register(entry, RSP) == CALLEE_SP
    return dict(ip=register(returned, RIP), expected_ip=instruction.fallthrough.byte_offset,
                sp=register(returned, RSP), expected_sp=CALL_SP)


def _assert_normal_return(witness):
    assert witness['ip'] == witness['expected_ip'] and witness['sp'] == witness['expected_sp']


def test_original_call_projection_retains_raw_push_and_return_operation_identities():
    case = _case()
    (projection,) = observed_call_state_projections(case['item'].unit.observation)
    assert projection.call_operation_key == '1:1008:2:CALL'
    assert projection.transient_operation_keys == ('1:1008:0:INT_SUB', '1:1008:1:STORE')
    assert projection.memory_transition.displacement_delta == -8
    assert projection.transient_coordinate.coordinate.byte_offset == 0x100c
    assert projection.transient_coordinate.selector.byte_size == 8
    item = case['item']
    assert all(item.normalized.dependencies.node_for_key('op:' + key) is not None
               for key in projection.transient_operation_keys)
    assert not set(projection.transient_operation_keys) & {
        action.operation_key for action in item.normalized.memory_ssa.actions}
    vm = _execute(case)
    _assert_normal_return(_return_witness(case, vm))


@pytest.mark.parametrize('pointer,increment,saved,expected', (
    (POINTER, 3, 0x22, 15),
    (CALLEE_SP - 8, 3, 0x22, 42),
    (CALLEE_SP, 0, 0x22, 0x1011),
    (CALLEE_SP - 4, 3, 0x22, 0x100c00000008),
))
def test_direct_leaf_physical_memory_matches_valid_original_caller_and_callee(
        pointer, increment, saved, expected):
    case = _case(callee=_callee(increment))
    ordinary = _record(case, physical=False)
    record = _record(case)
    assert eligibility(ordinary) == eligibility(record) == 'debt'
    assert record['physical_root_guard'] == 1 and not record['truncated']
    before = copying.deepcopy(record)
    vm = _execute(case, pointer=pointer, saved=saved)
    _assert_normal_return(_return_witness(case, vm))
    assert final_register(vm, RAX, 8) == expected
    interpreted = evaluate_physical(record, entry_reader(vm))
    assert interpreted.value == expected
    assert {'1:100c:0:LOAD', '1:1808:0:LOAD'} <= {
        row['key'] for row in interpreted.evidence if row['kind'] == 'load'}
    assert record == before and eligibility(record) == 'debt'
    with pytest.raises(Ineligible, match='debt'):
        evaluate(record, entry_reader(vm), route='stitched')


@pytest.mark.parametrize('pointer,saved,wrong_ip', (
    (CALLEE_SP, 0x22, 0x100f),
    (CALLEE_SP - 4, 0xffffffff00000022, 0x100d),
))
def test_changed_return_address_is_not_a_valid_normal_call_output(pointer, saved, wrong_ip):
    case = _case()
    vm = _execute(case, pointer=pointer, saved=saved)
    witness = _return_witness(case, vm)
    assert witness['ip'] == wrong_ip != witness['expected_ip']
    assert witness['sp'] == witness['expected_sp']
    # The interpreter still schedules the saved fallthrough. Its final RAX is
    # deliberately not used as a valid oracle for this changed RETURN.
    with pytest.raises(Ineligible):
        evaluate_physical(_record(case), entry_reader(vm))


def test_unbalanced_callee_stack_is_not_a_valid_normal_call_output():
    case = _case(callee=_callee(balanced=False))
    vm = _execute(case)
    witness = _return_witness(case, vm)
    assert witness['sp'] == CALLEE_SP != witness['expected_sp']
    assert witness['ip'] == 0x22 != witness['expected_ip']
    with pytest.raises(Ineligible):
        evaluate_physical(_record(case), entry_reader(vm))


def _register_result_case(*, bound_alias=False, partial_after_call=False):
    caller = FunctionBuilder().sub_rsp(0x28).ins(store(reg(RCX), const(7)))
    if bound_alias:
        caller.ins(copy(reg(RDX), reg(RCX)))
    caller.call(0x1800)
    if partial_after_call:
        caller.ins(copy(reg(RAX, 1), const(0xaa, 1)))
    key = f'1:{caller._address(len(caller._rows)):x}:0:INT_ADD'
    caller.ins(add(reg(RAX), reg(RAX), const(5))).add_rsp(0x28).ret()
    callee = (FunctionBuilder(entry=0x1800).push(RBX).sub_rsp(0x10)
              .ins(store(reg(RDX), const(41)), load(reg(RAX), reg(RCX)),
                   add(reg(RAX), reg(RAX), const(1))).add_rsp(0x10).pop(RBX).ret())
    return _case(caller, callee), key


@pytest.mark.parametrize('bound_alias,expected', ((False, 13), (True, 47)))
def test_call_register_read_uses_physical_body_even_without_an_ordinary_output_row(bound_alias, expected):
    case, key = _register_result_case(bound_alias=bound_alias)
    item = case['item']
    (call,) = item.calls
    rax_rows = [run for run in item.proven[call].runs for span in run.writes if span.start == RAX]
    assert bool(rax_rows) is not bound_alias
    assert key == ('1:1010:0:INT_ADD' if bound_alias else '1:100c:0:INT_ADD')
    record = _record(case, key)
    assert eligibility(record) == 'debt'
    (operation,) = [node for node in record['nodes'] if node.get('key') == key]
    (argument,) = [operand for operand in operation['operands'] if operand['index'] == 0]
    if bound_alias:
        assert 'physical_register' in argument
    else:
        assert 'physical_register' not in argument
        assert any(node.get('call') == call and node.get('physical_stitched') for node in record['nodes'])
    vm = _execute(case, registers=((RDX, POINTER + 0x100),))
    _assert_normal_return(_return_witness(case, vm))
    assert final_register(vm, RAX, 8) == expected
    assert evaluate_physical(record, entry_reader(vm)).value == expected
    assert eligibility(record) == 'debt'


@pytest.mark.parametrize('unknown', (RSP, RCX, RDX))
def test_unknown_physical_call_inputs_are_refused(unknown):
    case = _case()
    vm = _execute(case)
    _assert_normal_return(_return_witness(case, vm))
    known = entry_reader(vm)

    def entry(node):
        if isinstance(node, dict) and 'register' in node:
            span = node['register']
            if span['offset'] < unknown + 8 and unknown < span['offset'] + span['size']:
                return None
        return known(node)

    with pytest.raises(Ineligible):
        evaluate_physical(_record(case), entry)


def test_a_known_nested_call_retains_the_original_caller_memory_result():
    nested = FunctionBuilder(entry=INNER).ins(copy(reg(RAX), const(123))).ret()
    case = _case(_caller(), _callee(nested=True), nested)
    vm = _execute(case)
    _assert_normal_return(_return_witness(case, vm))
    assert final_register(vm, RAX, 8) == 15
    record = _record(case)
    assert len(record['physical_calls']) == 2
    assert evaluate_physical(record, entry_reader(vm)).value == 15


def test_without_an_exact_observed_call_projection_the_physical_call_is_refused():
    caller = _caller()
    # An additional identity write of SP keeps concrete execution identical,
    # but violates the existing exact one-SP-write projection contract.
    caller._rows[2].ops.insert(0, copy(reg(RSP), reg(RSP)))
    case = _case(caller)
    assert observed_call_state_projections(case['item'].unit.observation) == ()
    vm = _execute(case)
    _assert_normal_return(_return_witness(case, vm))
    assert final_register(vm, RAX, 8) == 15
    with pytest.raises(Ineligible):
        evaluate_physical(_record(case), entry_reader(vm))


def test_without_the_admitted_callee_context_the_physical_call_is_refused():
    case = _case()
    vm = _execute(case)
    _assert_normal_return(_return_witness(case, vm))
    with pytest.raises(Ineligible):
        evaluate_physical(_record(case, stitch=False), entry_reader(vm))


@pytest.mark.parametrize('kind', ('record', 'evaluation'))
def test_physical_call_limits_refuse_instead_of_returning_a_partial_value(kind):
    case = _case()
    vm = _execute(case)
    _assert_normal_return(_return_witness(case, vm))
    if kind == 'record':
        record = _record(case, limits=Limits(nodes=1))
        assert record['truncated']
        with pytest.raises(Ineligible):
            evaluate_physical(record, entry_reader(vm))
    else:
        with pytest.raises(Ineligible, match='limit'):
            evaluate_physical(_record(case), entry_reader(vm), max_steps=1)


@pytest.mark.parametrize('active', (False, True))
def test_leaf_transaction_cannot_ignore_an_active_unsupported_store_value_unrelated_to_return(active):
    flag, value = tmp(0x300, 1), tmp(0x900)
    caller = (FunctionBuilder().sub_rsp(0x28).ins(store(reg(RCX), reg(RDX))).call(0x1800)
              .ins(add(reg(RAX), reg(RAX), const(5))).add_rsp(0x28).ret())
    callee = (FunctionBuilder(entry=0x1800).push(RBX).sub_rsp(0x10)
              .cbranch('skip', flag, op('INT_EQUAL', [reg(R9), const(0)], flag))
              .ins(op('FLOAT_ADD', [reg(RDX), reg(RDX)], value), store(reg(RCX), value))
              .label('skip').ins(copy(reg(RAX), const(7)))
              .add_rsp(0x10).pop(RBX).ret())
    case = _case(caller, callee)
    vm = _execute(case, registers=((R9, int(active)),), expected_opaque=('FLOAT_ADD',) if active else ())
    _assert_normal_return(_return_witness(case, vm))
    assert ('1:180c:1:STORE' in vm.fixture_run.executed) is active
    record = _record(case, '1:100c:0:INT_ADD')
    assert any(node.get('key') == '1:180c:0:FLOAT_ADD' for node in record['nodes'])
    # The opaque operation is independently observed, not supplied a runtime
    # value to the physical evaluator. The transaction must refuse even though
    # the callee returns a literal and its caller never reads that STORE.
    if active:
        with pytest.raises(Ineligible):
            evaluate_physical(record, entry_reader(vm))
    else:
        assert final_register(vm, RAX, 8) == 12
        assert evaluate_physical(record, entry_reader(vm)).value == 12


@pytest.mark.parametrize('pointer,expected', ((POINTER, 18), (CALLEE_SP - 8, 45)))
def test_sequential_calls_use_each_actual_entry_memory_and_return_address(pointer, expected):
    caller = (FunctionBuilder().sub_rsp(0x28).ins(store(reg(RCX), reg(RDX)))
              .call(0x1800).call(0x1800)
              .ins(load(reg(RAX), reg(RCX)), add(reg(RAX), reg(RAX), const(5)))
              .add_rsp(0x28).ret())
    case = _case(caller)
    vm = _execute(case, pointer=pointer)
    assert len(case['item'].calls) == 2
    for call in case['item'].calls:
        _assert_normal_return(_return_witness(case, vm, call))
    assert final_register(vm, RAX, 8) == expected
    record = _record(case, '1:1010:1:INT_ADD')
    assert eligibility(record) == 'debt' and len(record['physical_calls']) == 2
    result = evaluate_physical(record, entry_reader(vm))
    assert result.value == expected
    calls = [row for row in result.evidence if row['kind'] == 'call']
    assert len(calls) == 2
    assert {row['call'] for row in calls} == set(case['item'].calls)
    assert {row['target'] for row in calls} == {0x100c, 0x1010}
    assert eligibility(record) == 'debt'


@pytest.mark.parametrize('mutation', ('selector', 'context', 'part'))
def test_exact_ordinary_call_output_requires_its_physical_selector_context_and_part(mutation):
    case, key = _register_result_case()
    vm = _execute(case, registers=((RDX, POINTER + 0x100),))
    _assert_normal_return(_return_witness(case, vm))
    record = _record(case, key)
    assert evaluate_physical(record, entry_reader(vm)).value == 13
    changed = copying.deepcopy(record)
    (call,) = [node for node in changed['nodes'] if node.get('physical_stitched')]
    (output,) = call['physical_stitched']
    if mutation == 'selector':
        output['output']['start'] += 1
    elif mutation == 'context':
        output['context'] = 'missing-context'
    else:
        output['part']['bytes'] = [1, 9]  # same width, outside the original 8-byte producer
    with pytest.raises(Ineligible):
        evaluate_physical(changed, entry_reader(vm))


@pytest.mark.parametrize('field,value', (('offset', 1), ('offset', False), ('size', 7), ('size', True)))
def test_named_physical_register_read_rejects_malformed_offsets_and_sizes(field, value):
    case, key = _register_result_case(bound_alias=True)
    vm = _execute(case, registers=((RDX, POINTER + 0x100),))
    _assert_normal_return(_return_witness(case, vm))
    record = _record(case, key)
    assert evaluate_physical(record, entry_reader(vm)).value == 47
    changed = copying.deepcopy(record)
    (override,) = [operand['physical_register'] for node in changed['nodes'] if node.get('key') == key
                   for operand in node['operands'] if 'physical_register' in operand]
    override[field] = value
    with pytest.raises(Ineligible):
        evaluate_physical(changed, entry_reader(vm))


def test_caller_partial_write_after_call_does_not_authorize_a_blanket_debt_override():
    case, key = _register_result_case(bound_alias=True, partial_after_call=True)
    vm = _execute(case, registers=((RDX, POINTER + 0x100),))
    _assert_normal_return(_return_witness(case, vm))
    assert key == '1:1014:0:INT_ADD' and final_register(vm, RAX, 8) == 175
    record = _record(case, key)
    assert eligibility(record) == 'debt'
    (root,) = [node for node in record['nodes'] if node.get('key') == key]
    assert not any('physical_register' in operand for operand in root['operands'])
    assert root.get('debts') and not root.get('physical_call_debt_ids')
    with pytest.raises(Ineligible):
        evaluate_physical(record, entry_reader(vm))


@pytest.mark.parametrize('named_register', (False, True))
def test_call_output_reference_must_match_the_unchanged_context_export(named_register):
    case, key = _register_result_case(bound_alias=named_register)
    vm = _execute(case, registers=((RDX, POINTER + 0x100),))
    _assert_normal_return(_return_witness(case, vm))
    record = _record(case, key)
    assert evaluate_physical(record, entry_reader(vm)).value == (47 if named_register else 13)
    changed = copying.deepcopy(record)
    registry = copying.deepcopy(changed['physical_calls'])
    constant = next(node['id'] for node in changed['nodes']
                    if node['kind'] == 'const' and node['size'] == 8 and node['value'] == 5)
    if named_register:
        (projection,) = [operand['physical_register'] for node in changed['nodes'] if node.get('key') == key
                         for operand in node['operands'] if 'physical_register' in operand]
    else:
        (projection,) = [output for node in changed['nodes'] for output in node.get('physical_stitched', ())]
    assert not any(output['part']['node'] == constant
                   for context in registry.values() for output in context['outputs'])
    # Replace the relation, not its shared part dict: the context's original
    # terminal export, named call and selector remain completely unchanged.
    projection['part'] = dict(node=constant, bytes=[0, 8], at=[0, 8])
    assert changed['physical_calls'] == registry
    with pytest.raises(Ineligible):
        evaluate_physical(changed, entry_reader(vm))
