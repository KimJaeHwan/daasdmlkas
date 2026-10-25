"""Actual UE 5.1.1 Core DLL p-code, not the cpp_like UE-named testbed.

TDO_UE_CORE_CONDITIONAL_BUNDLE: ten leaf exports of the exact DLL below.
TDO_UE_CORE_LEN_BUNDLE: a separate read-only export of FString::Len.
TDO_UE_CORE_MODEL_BUNDLE: the original eleven-function FString closure.
No hand/derived function models, boundary returns, branch flips or havoc.
Only physical entry register/RAM values are preset. This is p-code execution
comparison, NOT native Windows execution or proof for every DLL function.

The compound predicates below are the original DLL exports, not rebuilt C:
FName::IsEqual 180050e70 (four CBRANCHs after a field-select diamond),
FString::IsValidIndex 1800513a0 (negative-index exit, cmov, upper bound),
FDateTime::IsLeapYear 1803bbf50 (signed remainder and short circuits), and
FTextId::IsEmpty 180050e10 (two pointer-chain reads sharing a false exit).
Both final AL exit records are evaluated before the observed exit is used
as an assertion: an execution-selected constant alone is not condition
support.
"""

import os
from pathlib import Path

import pytest

from pcode_interpreter import Interpreter
from record_oracle import entry_reader
from summary_oracle import _exit_for
from tdo_v2._configured_bundle_reader import read_configured_bundle
from tdo_v2._scope_contracts import _mint_orchestrator_capability
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import _ObservedScopeProvider
from tdo_v2.interprocedural import analyze_units, function_key
from tdo_v2.normalize import NormalizedFunction
from tdo_v2.operation_records import Ineligible, Limits, eligibility, evaluate, root_record, run_records
from tdo_v2._record_memory import evaluate_physical
from tdo_v2.scope_identity import open_configured_extraction


SHA = 'fdea959764879bb55602c88a80a1adf6307b637c0c04f4b01f2e28c2fcb7b942'
COMPARE = '1b1:180048910'
EQUAL = '1b1:180050e70'
INIT, RESET, LEN = '1b1:1804b87d0', '1b1:1804c4be0', '1b1:1800567d0'
CTOR, DTOR, APPEND = '1b1:180037a80', '1b1:18003bc00', '1b1:1800f4fd0'
ENTRIES = {COMPARE, EQUAL, INIT, RESET, '1b1:180050e00', '1b1:180050e30',
           '1b1:180050e10', '1b1:180050e50', '1b1:1803bbf50', '1b1:1800513a0'}
ORIGINAL = {CTOR, DTOR, APPEND, '1b1:1801f1c40', '1b1:18010b8d0', '1b1:180bca600',
            '1b1:1800570d0', '1b1:18020a670', '1b1:18020afe0', '1b1:18035a2e0', '1b1:180100420'}
OPTIONS = dict(assume_globals_disjoint_from_stack=False, assume_entry_values_not_frame=False,
               assume_opaque_callees_leave_no_stack_addresses=False, private_frame_above=0)
STACK, LEFT, RIGHT, TEXT = 0x70000000, 0x71000000, 0x72000000, 0x73000000


def _load(variable, expected, *, allow_calls=False):
    value = os.environ.get(variable)
    if not value:
        pytest.skip(f'set {variable} to the actual Core DLL sealed generation')
    generation = Path(value)
    adapter = _ObservedScopeProvider(read_configured_bundle(admit_frozen_bundle(generation)))
    units = []
    with open_configured_extraction(adapter, _mint_orchestrator_capability()) as session:
        for unit in session.iter_scoped_functions():
            adapter.collect_function_roles()
            units.append(unit)
    assert {function_key(unit.scopes.function.entry) for unit in units} == expected
    assert all(unit.scopes.program.evidence.executable_sha256.hex() == SHA for unit in units)
    if not allow_calls:
        assert all(not any(op.opcode in ('CALL', 'CALLIND', 'CALLOTHER')
                           for row in unit.observation.instructions for op in row.operations) for unit in units)
    results = analyze_units(units, **OPTIONS)
    assert set(results) == expected and all(isinstance(row.normalized, NormalizedFunction) for row in results.values())
    spaces = units[0].scopes.program.evidence.address_spaces
    return dict(results=results,
                register=next(row.space_id for row in spaces if row.is_register_space),
                constant=next(row.space_id for row in spaces if row.is_constant_space),
                ram=next(row.space_id for row in spaces if row.is_loaded_memory_space),
                address_bits={row.space_id: row.address_size_bits for row in spaces if row.is_memory_space})


@pytest.fixture(scope='module')
def actual():
    return _load('TDO_UE_CORE_CONDITIONAL_BUNDLE', ENTRIES)


@pytest.fixture(scope='module')
def actual_len():
    return _load('TDO_UE_CORE_LEN_BUNDLE', {LEN})


@pytest.fixture(scope='module')
def actual_original():
    return _load('TDO_UE_CORE_MODEL_BUNDLE', ORIGINAL, allow_calls=True)


def _execute(case, item, registers=(), memory=(), seed=0, *, watch=()):
    vm = Interpreter(item.unit.observation, constant_space=case['constant'], seed=seed,
                     address_bits=case['address_bits'])
    vm.preset(case['register'], 0x20, 8, STACK)
    for offset, size, value in registers:
        vm.preset(case['register'], offset, size, value)
    for address, size, value in memory:
        vm.preset(case['ram'], address, size, value)
    vm.observed_writes = {}
    if watch:
        original_write = vm._write

        def observe(writer, space, offset, size, value):
            original_write(writer, space, offset, size, value)
            if writer in watch:
                vm.observed_writes.setdefault(writer, []).append(
                    (space, offset, size, value & ((1 << (size * 8)) - 1)))
        vm._write = observe
    run = vm.run()
    assert run.completed and run.executed and not vm.opaque_opcodes
    assert run.executed[-1].endswith(':RETURN')
    return vm, run


def _entry(case, vm):
    read = entry_reader(vm)

    def entry(node):
        if isinstance(node, dict) and 'register' in node:
            span = node['register']
            return read(('entry', case['register'], span['offset'], span['size']))
        return read(node)
    return entry


def _read(vm, space, address, size):
    return sum(vm._byte(space, address + byte)[0] << (8 * byte) for byte in range(size))


def _records(item):
    return run_records(item.normalized, item.unit, item.summary)


def _operation_record(item, key, **kwargs):
    action = next(row for row in item.normalized.memory_ssa.actions if row.operation_key == key)
    seeds = [(item.normalized.memory_graph.definition_nodes[identifier],
              (item.normalized.memory_ssa.definitions[identifier].span,))
             for identifier in action.write_definition_ids]
    if not seeds:
        node = item.normalized.dependencies.node_for_key('op:' + key)
        assert node is not None
        seeds = [(node, ())]
    return root_record(item.normalized, item.unit, seeds, **kwargs)


def _assert_final_boolean(case, item, vm, run, expected):
    records = [record for record in _records(item) if record['place']['kind'] == 'register_file'
               and record['place']['start'] == 0 and record['place']['size'] == 1]
    assert len(records) == 2 and len({record['exit'] for record in records}) == 2
    assert all(not record['truncated'] and type(record.get('execution_guard')) is int
               and record['control']['decisions'] for record in records)
    assert _read(vm, case['register'], 0, 1) == expected
    for route in ('injected', 'stitched'):
        values, accepted, excluded = set(), set(), set()
        # Do not preselect by the interpreter's actual exit.
        for record in records:
            try:
                values.update(evaluate(record, _entry(case, vm), route=route))
            except Ineligible as error:
                assert str(error) == 'no alternative', (record['exit'], route, str(error))
                excluded.add(record['exit'])
            else:
                accepted.add(record['exit'])
        assert values == {expected}
        actual_exit = _exit_for(item.summary, run.executed[-1])
        assert actual_exit is not None and accepted == {actual_exit.block_key}
        assert excluded == {record['exit'] for record in records} - accepted


def test_actual_fname_final_boolean_keeps_all_short_circuit_conditions(actual):
    item = actual['results'][EQUAL]
    observed = {}
    inputs = ((0, 0, 1, 2, 5, 5, 3, 9), (0, 1, 1, 2, 5, 5, 3, 9),
              (1, 0, 1, 2, 5, 5, 3, 9), (1, 1, 7, 7, 8, 9, 11, 11),
              (1, 1, 7, 7, 8, 9, 11, 12), (0, 1, 7, 7, 8, 9, 11, 11))
    for seed, (selector, number, a, b, da, db, na, nb) in enumerate(inputs):
        vm, run = _execute(actual, item,
                           ((8, 8, LEFT), (0x10, 8, RIGHT), (0x80, 1, selector), (0x88, 1, number)),
                           ((LEFT, 4, a), (RIGHT, 4, b), (LEFT + 8, 4, da), (RIGHT + 8, 4, db),
                            (LEFT + 4, 4, na), (RIGHT + 4, 4, nb)), seed)
        expected = int((a == b if selector == 1 else da == db) and (not number or na == nb))
        _assert_final_boolean(actual, item, vm, run, expected)
        for key, taken in run.branch_decisions:
            observed.setdefault(key, set()).add(taken)
    assert set(observed) == {'1b1:180050e74:1:CBRANCH', '1b1:180050e87:0:CBRANCH',
                             '1b1:180050e8c:0:CBRANCH', '1b1:180050e94:1:CBRANCH'}
    assert all(values == {True, False} for values in observed.values())


def test_actual_fstring_valid_index_composes_cmov_and_early_exit(actual):
    item = actual['results']['1b1:1800513a0']
    observed = {}
    for seed, (num, index) in enumerate(((0, 0), (1, 0), (2, 0), (2, 1),
                                         (8, 6), (8, 7), (8, 0xffffffff))):
        vm, run = _execute(actual, item, ((8, 8, LEFT), (0x10, 4, index)),
                           ((LEFT + 8, 4, num),), seed)
        expected = int(index < 0x80000000 and index < (num - 1 if num else 0))
        _assert_final_boolean(actual, item, vm, run, expected)
        for key, taken in run.branch_decisions:
            observed.setdefault(key, set()).add(taken)
    assert set(observed) == {'1b1:1800513a2:0:CBRANCH', '1b1:1800513af:3:CBRANCH',
                             '1b1:1800513b5:1:CBRANCH'}
    assert all(values == {True, False} for values in observed.values())


def test_actual_leap_year_composes_signed_arithmetic_and_short_circuits(actual):
    item = actual['results']['1b1:1803bbf50']
    observed = {}
    for seed, year in enumerate((1900, 2000, 2023, 2024, 2100, 2400, -400, -100, -4, -1, 0)):
        vm, run = _execute(actual, item, ((8, 4, year & 0xffffffff),), seed=seed)
        expected = int(year % 4 == 0 and (year % 100 != 0 or year % 400 == 0))
        _assert_final_boolean(actual, item, vm, run, expected)
        for key, taken in run.branch_decisions:
            observed.setdefault(key, set()).add(taken)
    assert set(observed) == {'1b1:1803bbf5a:1:CBRANCH', '1b1:1803bbf65:1:CBRANCH',
                             '1b1:1803bbf7f:1:CBRANCH', '1b1:1803bbf9c:1:CBRANCH'}
    assert all(values == {True, False} for values in observed.values())


def test_actual_text_id_short_circuit_loads_share_the_false_exit(actual):
    item = actual['results']['1b1:180050e10']
    observed = {}
    for seed, (first, second) in enumerate(((0, 0), (0, 65), (65, 0), (65, 66))):
        vm, run = _execute(actual, item, ((8, 8, LEFT),),
                           ((LEFT, 8, TEXT), (LEFT + 0x10, 8, TEXT + 0x100),
                            (TEXT, 2, first), (TEXT + 0x100, 2, second)), seed)
        _assert_final_boolean(actual, item, vm, run, int(first == 0 and second == 0))
        for key, taken in run.branch_decisions:
            observed.setdefault(key, set()).add(taken)
        if first:
            assert not any(key.startswith('1b1:180050e19:') for key in run.executed)
    assert set(observed) == {'1b1:180050e17:1:CBRANCH', '1b1:180050e21:1:CBRANCH'}
    assert all(values == {True, False} for values in observed.values())


def test_actual_fname_memory_comparison_shares_one_choice_across_six_outputs(actual):
    item = actual['results'][COMPARE]
    records = [record for record in _records(item) if any('condition' in node for node in record['nodes'])]
    assert len(records) == 6  # RAX and the five written condition flags, not six functions
    selections = {node['condition']['selection'] for record in records for node in record['nodes']
                  if 'condition' in node}
    assert len(selections) == 1
    assert all(node['condition']['decision'] == '1b1:180048914:1:CBRANCH'
               for record in records for node in record['nodes'] if 'condition' in node)
    assert any(node.get('opcode') == 'LOAD' for record in records for node in record['nodes'])
    observed = set()
    for seed, (a, b, na, nb) in enumerate(((10, 8, 3, 9), (10, 10, 3, 9), (0, 0, 8, 2), (1, 7, 0, 0))):
        vm, run = _execute(actual, item, ((8, 8, LEFT), (0x10, 8, RIGHT)),
                           ((LEFT, 4, a), (LEFT + 4, 4, na), (RIGHT, 4, b), (RIGHT + 4, 4, nb)), seed)
        (decision,) = [taken for key, taken in run.branch_decisions if key == '1b1:180048914:1:CBRANCH']
        observed.add(decision)
        exit_summary = _exit_for(item.summary, run.executed[-1])
        assert exit_summary is not None
        for record in records:
            assert record['exit'] == exit_summary.block_key and eligibility(record) is None
            span = record['place']
            actual_value = _read(vm, actual['register'], span['start'], span['size'])
            for route in ('injected', 'stitched'):
                assert evaluate(record, _entry(actual, vm), route=route) == {actual_value}
        assert _read(vm, actual['register'], 0, 4) == ((a - b) if a != b else na - nb) & 0xffffffff
    assert observed == {True, False}


def test_actual_fname_intermediate_join_keeps_the_selected_memory_fields(actual):
    item = actual['results'][EQUAL]
    # SETE AL reads the ZF JOIN before later short-circuit branches. Do not
    # claim the final whole-function exits have acquired path predicates.
    key = next(row.operation_key for row in item.normalized.memory_ssa.actions
               if row.operation_key.startswith('1b1:180050e82:') and row.write_definition_ids)
    record = _operation_record(item, key)
    phis = [node for node in record['nodes'] if 'condition' in node]
    assert phis and all(node['condition']['decision'] == '1b1:180050e74:1:CBRANCH' for node in phis)
    assert all(node['condition_evaluation'] == 'supported' for node in phis)
    for seed, selector in enumerate((0, 1)):
        vm, run = _execute(actual, item, ((8, 8, LEFT), (0x10, 8, RIGHT), (0x80, 1, selector), (0x88, 1, 0)),
                           ((LEFT, 4, 1), (RIGHT, 4, 2), (LEFT + 8, 4, 5), (RIGHT + 8, 4, 5)), seed, watch=(key,))
        assert key in run.executed
        expected = 1 if selector == 0 else 0
        assert vm.observed_writes[key] == [(actual['register'], 0, 1, expected)]
        # Later short-circuit code writes AL again: compare the record to
        # the observed intermediate root write, not the final AL by accident.
        observed = vm.observed_writes[key][0][3]
        for route in ('injected', 'stitched'):
            assert evaluate(record, _entry(actual, vm), route=route) == {observed}


@pytest.mark.parametrize('key,field,size,inputs', (
    ('1b1:180050e00', 8, 4, (0, 1, 2, 15)),       # FString::IsEmpty
    ('1b1:180050e50', 0, 4, (0, 1, 2, 15)),       # FTextRange::IsEmpty
))
def test_actual_straight_memory_predicates_do_not_need_a_branch_phi(actual, key, field, size, inputs):
    item = actual['results'][key]
    for seed, value in enumerate(inputs):
        memory = ((LEFT + field, size, value), (LEFT + 4, 4, 2))
        vm, run = _execute(actual, item, ((8, 8, LEFT),), memory, seed)
        expected = int(value <= 1) if key.endswith('50e00') else int(2 - value <= 0)
        record = next(row for row in _records(item) if row['place']['kind'] == 'register_file'
                      and row['place']['start'] == 0 and row['place']['size'] == 1)
        assert any(node.get('opcode') == 'LOAD' for node in record['nodes'])
        assert _read(vm, actual['register'], 0, 1) == expected
        assert evaluate(record, _entry(actual, vm)) == {expected}


def test_actual_pointer_chain_load_reaches_the_pointed_character(actual):
    item = actual['results']['1b1:180050e30']
    record = next(row for row in _records(item) if row['place']['kind'] == 'register_file'
                  and row['place']['start'] == 0 and row['place']['size'] == 1)
    assert sum(node.get('opcode') == 'LOAD' for node in record['nodes']) == 2
    for seed, character in enumerate((0, 65)):
        vm, _ = _execute(actual, item, ((8, 8, LEFT),), ((LEFT, 8, TEXT), (TEXT, 2, character)), seed)
        actual_value = _read(vm, actual['register'], 0, 1)
        assert actual_value == int(character == 0)
        assert evaluate(record, _entry(actual, vm)) == {actual_value}


def test_actual_mark_memory_writes_preserve_alias_uncertainty(actual):
    item = actual['results'][INIT]
    first = _operation_record(item, '1b1:1804b87d7:2:STORE')
    # Ghidra ordinal is selected from the original observation rather than
    # assuming that the x86 memory write is the first p-code operation.
    writes = [row.operation_key for row in item.normalized.memory_ssa.actions
              if row.operation_key.startswith('1b1:1804b87e3:') and row.operation_key.endswith(':STORE')]
    assert len(writes) == 1
    second = _operation_record(item, writes[0])
    assert eligibility(second) == 'debt'
    assert any(node.get('kind') == 'debt' for node in second['nodes'])
    for seed, (count, flags) in enumerate(((0, 0), (123, 2), (0x1122334455667788, 255))):
        vm, _ = _execute(actual, item, ((8, 8, LEFT), (0x10, 8, RIGHT)),
                         ((RIGHT + 0x98, 8, count), (RIGHT + 9, 1, flags)), seed)
        assert _read(vm, actual['ram'], LEFT + 8, 8) == count
        assert _read(vm, actual['ram'], LEFT, 1) == (flags >> 1) & 1
        assert evaluate(first, _entry(actual, vm)) == {count}
        with pytest.raises(Ineligible, match='debt'):
            evaluate(second, _entry(actual, vm))


def test_actual_mark_reset_has_both_real_memory_write_expressions(actual):
    item = actual['results'][RESET]
    writes = [row.operation_key for row in item.normalized.memory_ssa.actions if row.operation_key.endswith(':STORE')]
    assert len(writes) == 2
    records = [_operation_record(item, key) for key in writes]
    vm, run = _execute(actual, item, ((8, 8, LEFT),), ((LEFT, 1, 255), (LEFT + 8, 8, 123)))
    assert all(key in run.executed for key in writes)
    assert _read(vm, actual['ram'], LEFT, 1) == _read(vm, actual['ram'], LEFT + 8, 8) == 0
    assert all(evaluate(record, _entry(actual, vm)) == {0} for record in records)


def test_actual_fstring_len_preserves_the_original_cmov_predicate(actual_len):
    item = actual_len['results'][LEN]
    records = [row for row in _records(item) if row['place']['kind'] == 'register_file'
               and row['place']['start'] == 0 and any('condition' in node for node in row['nodes'])]
    assert len(records) == 1
    record = records[0]
    assert any(node.get('opcode') == 'LOAD' for node in record['nodes'])
    observed = set()
    for seed, num in enumerate((0, 1, 2, 15)):
        vm, run = _execute(actual_len, item, ((8, 8, LEFT),), ((LEFT + 8, 4, num),), seed)
        observed.update(taken for _, taken in run.branch_decisions)
        actual = _read(vm, actual_len['register'], 0, record['place']['size'])
        assert actual == (num - 1 if num else 0)
        for route in ('injected', 'stitched'):
            assert evaluate(record, _entry(actual_len, vm), route=route) == {actual}
    assert observed == {True, False}


def test_original_fstring_ctor_executes_both_real_zero_stores(actual_original):
    item = actual_original['results'][CTOR]
    writes = [row.operation_key for row in item.normalized.memory_ssa.actions if row.operation_key.endswith(':STORE')]
    assert len(writes) == 2
    records = [_operation_record(item, key) for key in writes]
    vm, run = _execute(actual_original, item, ((8, 8, LEFT),),
                       ((LEFT, 8, 123), (LEFT + 8, 8, 456)), watch=writes)
    assert all(key in run.executed for key in writes)
    assert _read(vm, actual_original['ram'], LEFT, 8) == _read(vm, actual_original['ram'], LEFT + 8, 8) == 0
    for key, record in zip(writes, records, strict=True):
        assert vm.observed_writes[key][0][3] == 0
        assert evaluate(record, _entry(actual_original, vm)) == {0}


def test_original_fstring_dtor_null_path_is_not_whole_function_condition_support(actual_original):
    item = actual_original['results'][DTOR]
    load = next(row.operation_key for row in item.normalized.memory_ssa.actions
                if row.operation_key.startswith('1b1:18003bc04:') and row.operation_key.endswith(':LOAD'))
    record = _operation_record(item, load)
    vm, run = _execute(actual_original, item, ((8, 8, LEFT),), ((LEFT, 8, 0),), watch=(load,))
    assert not any(key.endswith((':CALL', ':CALLIND')) for key in run.executed)
    assert run.branch_decisions and all(taken for _, taken in run.branch_decisions)
    from tdo_v2.call_seeds import _operation_key

    output = next(op.output for row in item.unit.observation.instructions for ordinal, op in enumerate(row.operations)
                  if _operation_key(row.address, ordinal, op.opcode) == load)
    assert vm.observed_writes[load] == [(output.coordinate.space_id, output.coordinate.byte_offset,
                                        output.byte_size, 0)]
    assert evaluate(record, _entry(actual_original, vm)) == {0}
    assert not any('condition' in node for row in _records(item) for node in row['nodes'])


def test_original_append_executes_real_buffer_writes_but_keeps_analysis_debt(actual_original):
    item = actual_original['results'][APPEND]
    addresses = ('1b1:1800f500b:', '1b1:1800f5078:', '1b1:1800f50d6:')
    writes = [row.operation_key for row in item.normalized.memory_ssa.actions
              if row.operation_key.startswith(addresses) and row.operation_key.endswith(':STORE')]
    assert len(writes) == 3
    records = [_operation_record(item, key) for key in writes]
    assert any(eligibility(record) == 'debt' for record in records)
    assert any(node.get('kind') == 'debt' for record in records for node in record['nodes'])
    for seed, num in enumerate((0, 1, 3)):
        vm, run = _execute(actual_original, item, ((8, 8, LEFT), (0x10, 2, 65)),
                           ((LEFT, 8, TEXT), (LEFT + 8, 4, num), (LEFT + 12, 4, 8),
                            (TEXT, 8, 0)), seed, watch=writes)
        assert all(key in run.executed for key in writes)
        assert not any(key.endswith((':CALL', ':CALLIND', ':CALLOTHER')) for key in run.executed)
        index = max(num - 1, 0)
        assert _read(vm, actual_original['ram'], LEFT + 8, 4) == max(num, 1) + 1
        assert _read(vm, actual_original['ram'], TEXT + index * 2, 2) == 65
        assert _read(vm, actual_original['ram'], TEXT + (index + 1) * 2, 2) == 0
        assert [row[0][3] for row in (vm.observed_writes[key] for key in writes)] == [max(num, 1) + 1, 65, 0]
        for record in records:
            if eligibility(record) == 'debt':
                with pytest.raises(Ineligible, match='debt'):
                    evaluate(record, _entry(actual_original, vm))


def test_actual_mark_physical_reads_follow_overlapping_real_stores(actual):
    item = actual['results'][INIT]
    first, load, last = '1b1:1804b87d7:2:STORE', '1b1:1804b87db:1:LOAD', '1b1:1804b87e3:1:STORE'
    ordinary = _operation_record(item, last)
    record = _operation_record(item, last, physical_memory=True)
    assert eligibility(ordinary) == eligibility(record) == 'debt'
    assert not record['truncated']
    assert any(node.get('kind') == 'debt' for node in record['nodes'])
    assert {node.get('key') for node in record['nodes']} >= {first, load, last}
    inputs = ((RIGHT, 0, 2, 1, None), (LEFT - 1, 0, 2, 0, 0),
              (LEFT - 1, 2, 0, 1, 0), (LEFT + 3, 2 << 32, 0, 1, 4))
    for seed, (right, count, flags, expected, byte_offset) in enumerate(inputs):
        vm, run = _execute(actual, item, ((8, 8, LEFT), (0x10, 8, right)),
                           ((right + 0x98, 8, count), (right + 9, 1, flags)), seed, watch=(last,))
        assert first in run.executed and load in run.executed
        assert vm.observed_writes[last] == [(actual['ram'], LEFT, 1, expected)]
        assert _read(vm, actual['ram'], LEFT, 1) == expected
        interpreted = evaluate_physical(record, _entry(actual, vm))
        assert interpreted.value == expected
        (read,) = [row for row in interpreted.evidence if row['kind'] == 'load' and row['key'] == load]
        if byte_offset is None:
            assert read['sources'] == [{'at': 0, 'entry': right + 9}]
        else:
            assert read['sources'] == [{'at': 0, 'writer': first, 'offset': byte_offset}]
        assert read['preserved_debts']
        with pytest.raises(Ineligible, match='debt'):
            evaluate(record, _entry(actual, vm))


@pytest.fixture(scope='module')
def append_physical_records(actual_original):
    item = actual_original['results'][APPEND]
    # The default writer-display cap cuts this whole-function diagnostic.
    # Retain its complete original writer inventory; this is not a new
    # nonalias or call-effect assumption and does not change the analysis.
    limits = Limits(writers=64, depth=512)
    keys = ('1b1:1800f500b:2:STORE', '1b1:1800f5078:3:STORE', '1b1:1800f50d6:3:STORE')
    records = {key: _operation_record(item, key, physical_memory=True, limits=limits) for key in keys}
    assert all(not record['truncated'] for record in records.values())
    assert all(eligibility(record) == 'debt' for record in records.values())
    assert all(any(node['kind'] == 'debt' for node in record['nodes']) for record in records.values())
    return records


@pytest.mark.parametrize('num', (0, 1, 3))
def test_original_append_physical_no_call_path_matches_all_three_store_values(
        actual_original, append_physical_records, num):
    case, records = actual_original, append_physical_records
    item = case['results'][APPEND]
    vm, run = _execute(case, item, ((8, 8, LEFT), (0x10, 2, 65)),
                       ((LEFT, 8, TEXT), (LEFT + 8, 4, num), (LEFT + 12, 4, 16), (TEXT, 8, 0)),
                       num, watch=records)
    assert not any(key.endswith((':CALL', ':CALLIND', ':CALLOTHER')) for key in run.executed)
    expected = ((LEFT + 8, 4, max(num, 1) + 1), (TEXT + 2 * max(num - 1, 0), 2, 65),
                (TEXT + 2 * (max(num - 1, 0) + 1), 2, 0))
    for (key, record), (address, size, value) in zip(records.items(), expected, strict=True):
        assert vm.observed_writes[key] == [(case['ram'], address, size, value)]
        assert _read(vm, case['ram'], address, size) == value
        interpreted = evaluate_physical(record, _entry(case, vm))
        assert interpreted.value == value
        assert any(row['kind'] == 'store' and row['key'] == key and row['address'] == address
                   and row['width'] == size and row['value'] == value for row in interpreted.evidence)
        assert any(row['kind'] == 'load' and row['preserved_debts'] for row in interpreted.evidence)
        with pytest.raises(Ineligible, match='debt'):
            evaluate(record, _entry(case, vm))


def test_original_append_zero_character_rejects_unexecuted_physical_store_roots(
        actual_original, append_physical_records):
    case, records = actual_original, append_physical_records
    item = case['results'][APPEND]
    vm, run = _execute(case, item, ((8, 8, LEFT), (0x10, 2, 0)),
                       ((LEFT, 8, TEXT), (LEFT + 8, 4, 3), (LEFT + 12, 4, 16),
                        (TEXT, 8, 0x1122334455667788)), watch=records)
    assert not vm.observed_writes
    assert not any(key.endswith((':CALL', ':CALLIND', ':CALLOTHER')) for key in run.executed)
    assert _read(vm, case['ram'], LEFT + 8, 4) == 3
    assert _read(vm, case['ram'], TEXT, 8) == 0x1122334455667788
    for record in records.values():
        with pytest.raises(Ineligible, match='physical root unreached or unknown'):
            evaluate_physical(record, _entry(case, vm))


def test_original_append_physical_object_aliases_the_real_prologue_stack_stores(
        actual_original, append_physical_records):
    """Raw entry input deliberately overlaps the callee's new frame.

    No entry-frame nonalias assumption is enabled. PUSH RBX replaces the
    initial Num=1 with 3 before the real object LOAD; PUSH RSI replaces its
    data pointer. This is p-code RAM semantics, not a valid-object-lifetime
    claim for every possible C++ FString owner.
    """
    case, records = actual_original, append_physical_records
    item = case['results'][APPEND]
    obj = STACK - 16
    vm, run = _execute(case, item,
                       ((8, 8, obj), (0x10, 2, 65), (0x18, 8, (16 << 32) | 3), (0x30, 8, TEXT)),
                       ((obj, 8, TEXT), (obj + 8, 4, 1), (obj + 12, 4, 16), (TEXT, 8, 0)),
                       watch=records)
    assert not any(key.endswith((':CALL', ':CALLIND', ':CALLOTHER')) for key in run.executed)
    expected = ((obj + 8, 4, 4), (TEXT + 4, 2, 65), (TEXT + 6, 2, 0))
    for (key, record), (address, size, value) in zip(records.items(), expected, strict=True):
        assert vm.observed_writes[key] == [(case['ram'], address, size, value)]
        assert _read(vm, case['ram'], address, size) == value
        interpreted = evaluate_physical(record, _entry(case, vm))
        assert interpreted.value == value
        if key == '1b1:1800f500b:2:STORE':
            (load,) = [row for row in interpreted.evidence if row['kind'] == 'load'
                       and row['key'] == '1b1:1800f4fe6:1:LOAD']
            assert load['sources'] == [dict(at=byte, writer='1b1:1800f4fd0:2:STORE', offset=byte)
                                       for byte in range(4)]
