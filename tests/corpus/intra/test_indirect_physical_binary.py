"""Sealed actual binaries: original CALLIND operand -> body -> final value/RAM.

These are extracted raw-pcode executions, not native executable runs.
"""

import os
from pathlib import Path

import pytest
from pcode_interpreter import Interpreter

from test_multi_target_memory_binary import (
    _actual_target, _entry, _execute, _load, _memory_pools, _operations, _value,
)
from test_physical_record_entry import NO_ASSUMPTIONS
from tdo_v2.operation_records import StitchContext, evaluate_physical, root_record
from tdo_v2.summary_engine import analyze_frozen_bundle_with_summaries, run_assumptions


REPO = Path(__file__).resolve().parents[3]


class _ObservedMemory(Interpreter):
    """Observe raw writes/LOADs, without graph/candidate-derived expectations."""

    def __init__(self, *args, **kwargs):
        self.raw_last_writers, self.raw_load_sources = {}, {}
        super().__init__(*args, **kwargs)

    def _write(self, writer, space, address, size, value):
        for offset in range(size):
            self.raw_last_writers[self._key(space, address + offset)] = (writer, offset)
        return super()._write(writer, space, address, size, value)

    def _execute(self, key, operation, run):
        if operation.opcode == 'LOAD':
            memory = operation.inputs[0].coordinate.byte_offset
            pointer = operation.inputs[1]
            address = (pointer.coordinate.byte_offset if pointer.kind.name == 'CONSTANT' else
                       self._peek(pointer.coordinate.space_id, pointer.coordinate.byte_offset, pointer.byte_size)[0])
            sources = []
            for offset in range(operation.output.byte_size):
                place = self._key(memory, address + offset)
                writer = self.raw_last_writers.get(place)
                sources.append({'at': offset, 'writer': writer[0], 'offset': writer[1]} if writer is not None
                               else {'at': offset, 'entry': place[1]})
            self.raw_load_sources.setdefault(key, []).append(sources)
        return super()._execute(key, operation, run)


def _all_load_byte_writers(vm, interpreted):
    checked = 0
    for evidence in interpreted.evidence:
        if evidence['kind'] != 'load':
            continue
        actual = vm.raw_load_sources.get(evidence['key'], ())
        assert len(actual) == 1, 'these real fixtures execute each original LOAD at most once'
        assert evidence['sources'] == actual[0], (evidence['key'], evidence['sources'], actual[0])
        checked += len(actual[0])
    assert checked
    return checked


def _physical(case, item, definition, span):
    return root_record(item.normalized, item.unit,
                       [(item.normalized.memory_graph.definition_nodes[definition], (span,))],
                       declared=item.declared, provenance=case['provenance'][id(item)][1],
                       stitch=StitchContext(case['provenance'], assumptions=run_assumptions(case['results'])),
                       physical_memory=True)


def _return_witness(case, vm, caller, call, function):
    (serial,) = [serial for serial, (key, _) in vm.activation_snapshots.items() if key == call]
    before, returned = vm.activation_snapshots[serial][1], vm.activation_returns[serial]
    instruction = next(row for row in caller.unit.observation.instructions
                       if call.startswith(f'{row.address.space_id:x}:{row.address.byte_offset:x}:'))
    callee = case['results'][function]
    returns = [(key, operation) for key, operation in _operations(callee)
               if operation.opcode == 'RETURN' and key in vm.fixture_run.executed]
    (return_key, ret), = returns
    ip = ret.inputs[0]
    register = case['ids'][1]
    stack = case['stack']
    value = lambda state, offset, size: sum(state[register, offset + index] << (8 * index)
                                           for index in range(size))
    assert value(returned, ip.coordinate.byte_offset, ip.byte_size) == instruction.fallthrough.byte_offset
    assert value(returned, stack.byte_offset, stack.byte_size) == (
        value(before, stack.byte_offset, stack.byte_size) + stack.byte_size)
    return return_key


def test_actual_multi_target_memory_has_one_selected_body_and_byte_writers(monkeypatch):
    case = _load('TDO_MULTI_TARGET_MEMORY_BUNDLE', monkeypatch)
    caller = case['results'][case['names']['case_multi_target_memory']]
    (call, _), = caller.multi_calls.items()
    (exit_summary,) = caller.summary.exits
    run = next(run for run in exit_summary.runs
               if run.span.object_id.kind.value == 'register_file' and run.span.start == 0)
    (definition,) = run.definitions
    from tdo_v2.span_geometry import ByteSpan

    record = _physical(case, caller, definition, ByteSpan(run.span.object_id, run.span.start, 4))
    selector, = record['target_selectors'].values()
    assert sum(node.get('physical_call_push') == selector['id'] for node in record['nodes']) == 1
    visited = set()
    for seed in range(12):
        pools = _memory_pools(seed)
        vm = _execute(case, caller, pools, seed, interpreter_type=_ObservedMemory)
        selected = _actual_target(vm, caller, call)
        visited.add(selected)
        interpreted = evaluate_physical(record, _entry(vm, case['ids'][1]))
        expected = (2 * pools[0x30] + (17 if pools[0x38] == 0 else 34)) & 0xffffffff
        assert interpreted.value == _value(vm, case['ids'][1], 0) == expected
        assert interpreted.value not in {(2 * pools[0x30] + n) & 0xffffffff for n in (18, 33)}
        target, = [row for row in interpreted.evidence if row['kind'] == 'target']
        assert target['function'] == selected
        _return_witness(case, vm, caller, call, selected)
        _all_load_byte_writers(vm, interpreted)
    assert visited == {candidate['function'] for candidate in selector['candidates']}


def test_compiled_indirect_target_keeps_both_original_return_paths(monkeypatch):
    case = _load('TDO_MULTI_RETURN_TARGET_BUNDLE', monkeypatch)
    caller = case['results'][case['names']['case_multi_return_target']]
    a = case['results'][case['names']['multi_return_a']]
    returns = {key for key, operation in _operations(a) if operation.opcode == 'RETURN'}
    assert len(returns) == 2, 'source-level returns alone do not establish the raw exit inventory'
    (call, _), = caller.multi_calls.items()
    (ex,) = caller.summary.exits
    run = next(run for run in ex.runs if run.span.object_id.kind.value == 'register_file' and run.span.start == 0)
    (definition,) = run.definitions
    from tdo_v2.span_geometry import ByteSpan

    record = _physical(case, caller, definition, ByteSpan(run.span.object_id, 0, 4))
    selector, = record['target_selectors'].values()
    visited, visited_returns = set(), set()
    for seed in range(12):
        pools = _memory_pools(seed)
        vm = _execute(case, caller, pools, seed, interpreter_type=_ObservedMemory)
        selected = _actual_target(vm, caller, call)
        visited.add(selected)
        returned = _return_witness(case, vm, caller, call, selected)
        if selected == a.key:
            visited_returns.add(returned)
        interpreted = evaluate_physical(record, _entry(vm, case['ids'][1]))
        x = pools[0x30]
        added = (19 if x & 1 else 41) if selected == a.key else 34
        assert interpreted.value == _value(vm, case['ids'][1], 0) == (2 * x + added) & 0xffffffff
        (witness,) = [row for row in interpreted.evidence if row['kind'] == 'call' and row['call'] == call]
        assert witness['return'] == returned
        _all_load_byte_writers(vm, interpreted)
    assert visited_returns == returns
    assert visited == {candidate['function'] for candidate in selector['candidates']}


@pytest.mark.parametrize('environment,abi', (
    ('TDO_DFB072_BUNDLE', 'sysv64'), ('TDO_DFB072_WINDOWS_X64_BUNDLE', 'win64'),
    ('TDO_DFB072_WINDOWS_X86_BUNDLE', 'x86-32'),
))
def test_actual_dfb072_formal_final_sink_matches_original_target_return_and_ram(monkeypatch, environment, abi):
    case = _load(environment, monkeypatch)
    import run_dfbench

    location = Path(os.environ[environment])
    run = analyze_frozen_bundle_with_summaries(
        location, naming_exporter_source=REPO / 'ghidra/GhidraV2CallNaming.java',
        boundary_provider=run_dfbench.boundary_provider(abi=abi),
        assume_readonly_image_constant=False, physical_memory_records=True, **NO_ASSUMPTIONS)
    (root,) = [root for root in run.roots if root.label == 'dfb_sink_int.arg0']
    record = root.explanation['record']
    caller = case['results'][case['names']['case_DFB072_function_pointer_table']]
    (call, targets), = caller.multi_calls.items()
    selector, = record['target_selectors'].values()
    assert {candidate['function'] for candidate in selector['candidates']} == set(targets)
    assert selector['requires'] == record['physical_assumptions'] == sorted(set(run.assumptions))
    source_functions = [case['results'][case['names'][name]] for name in ('dfb_source_A', 'dfb_source_C')]
    inputs = [{span for ex in source.summary.exits for output in ex.runs for span in output.sources
               if span.object_id.kind.value == 'address_space'} for source in source_functions]
    (source_input,) = inputs[0] & inputs[1]
    sink_call = next(key for key, function in caller.calls.items() if function == case['names']['dfb_sink_int'])
    visited = set()
    for seed, value in enumerate((0, 1, 9, 0x7fffffff, 0xffffffff, 0x80000000)):
        vm = _execute(case, caller, {case['stack'].byte_offset: 0x70000000}, seed,
                      memory_inputs=((source_input.object_id.space_key, source_input.start, source_input.size, value),),
                      interpreter_type=_ObservedMemory)
        interpreted = evaluate_physical(record, _entry(vm, case['ids'][1]))
        selected = _actual_target(vm, caller, call)
        visited.add(selected)
        target, = [row for row in interpreted.evidence if row['kind'] == 'target']
        assert target['function'] == selected
        _return_witness(case, vm, caller, call, selected)
        (snapshot,) = [state for key, state in vm.activation_snapshots.values() if key == sink_call]
        if abi == 'sysv64':
            place, offset = case['ids'][1], 0x38
        elif abi == 'win64':
            place, offset = case['ids'][1], 0x8
        else:
            place = source_input.object_id.space_key
            offset = sum(snapshot[case['ids'][1], case['stack'].byte_offset + index] << (8 * index)
                         for index in range(case['stack'].byte_size)) + case['stack'].byte_size
        actual = sum(snapshot[place, offset + index] << (8 * index) for index in range(4))
        expected = ((value + 1) + (1 if selected == case['names']['dfb_fp_table_target_A'] else 2)) & 0xffffffff
        assert interpreted.value == actual == expected
        assert any(row['kind'] in ('load', 'read') and row['address'] == source_input.start
                   for row in interpreted.evidence)
        _all_load_byte_writers(vm, interpreted)
    assert visited == set(targets)
