"""Opt-in real x64 DFB054 regression (not synthetic machine instructions).

TDO_DFBENCH054_BUNDLE must point at the sealed historical generation
c6edcb...309d1. Admission verifies the original and observation digests.
Only the raw observations are consumed: the historical naming-v1 sidecar
is NOT admitted as current naming-v2 evidence or used to infer an ABI.
Execution below is the existing raw-pcode interpreter, not native execution.
"""

import os
from pathlib import Path

import pytest

from tdo_v2._configured_bundle_reader import read_configured_bundle
from tdo_v2._scope_contracts import _mint_orchestrator_capability
from tdo_v2.call_expressions import RecordProvider
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import _ObservedScopeProvider
from tdo_v2.interprocedural import analyze_units, function_key
from tdo_v2.operation_records import evaluate, root_record
from tdo_v2.scope_identity import open_configured_extraction


GENERATION = 'c6edcb2c812de6b6b226bcd7a83c9d418e1858a21e56cbadffb7ef92d63109d1'
CASE, HELPER, SOURCE_A, SOURCE_B, SINK = (
    '1b1:104ec1', '1b1:104ea6', '1b1:10453b', '1b1:10454a', '1b1:104595',
)
POST_CALL_LOAD = '1b1:104f1d:1:LOAD'
MEMORY, REGISTER, SEED_ADDRESS = 433, 548, 0x109098


def load_case(path):
    """Admit the real extracted program and select five raw function bodies."""
    path = Path(path)
    assert path.name == GENERATION, 'this regression pins a specific binary/export'
    adapter = _ObservedScopeProvider(read_configured_bundle(admit_frozen_bundle(path)))
    units = {}
    with open_configured_extraction(adapter, _mint_orchestrator_capability()) as session:
        for unit in session.iter_scoped_functions():
            adapter.collect_function_roles()  # old naming intentionally not consumed
            if hasattr(unit.scopes.function, 'entry'):
                key = function_key(unit.scopes.function.entry)
                if key in (CASE, HELPER, SOURCE_A, SOURCE_B, SINK):
                    units[key] = unit
    assert len(units) == 5
    provider = RecordProvider()
    results = analyze_units(units.values(), record_provider=provider, assume_globals_disjoint_from_stack=True)
    caller = results[CASE]
    ssa = caller.normalized.memory_ssa
    action = next(row for row in ssa.actions if row.operation_key == POST_CALL_LOAD)
    seeds = [(caller.normalized.memory_graph.definition_nodes[d], (ssa.definitions[d].span,))
             for d in action.write_definition_ids]
    record = root_record(caller.normalized, caller.unit, seeds, provider=provider)
    return units, results, record


def execute_case(units, results, record, seeds):
    from pcode_interpreter import Interpreter

    observation = units[CASE].observation
    program = {(u.scopes.function.entry.space_id, u.scopes.function.entry.byte_offset): u.observation
               for u in units.values()}
    sink_places = {run.span for exit in results[SINK].summary.exits for run in exit.runs
                   if run.span.object_id.kind.value == 'address_space' and run.kind.value != 'identity'}
    assert len(sink_places) == 1
    sink_place = next(iter(sink_places))
    checked = []
    for seed in seeds:
        interpreter = Interpreter(observation, constant_space=48, seed=seed, program=program,
                                  havoc_calls=(REGISTER, 0x20, 8))
        # Entry SSA may coalesce adjacent untouched registers. Supply a full
        # concrete register file, including bytes this execution never reads.
        interpreter.preset(REGISTER, 0, 0x300, 0)
        interpreter.preset(REGISTER, 0x20, 8, 0x70000000)
        interpreter.preset(MEMORY, SEED_ADDRESS, 4, seed)
        # DFB_TOUCH_INT is XOR accumulation, not assignment.
        interpreter.preset(MEMORY, sink_place.start, sink_place.size, 0)
        run = interpreter.run()
        assert run.completed and not interpreter.opaque_opcodes

        def entry(node):
            if isinstance(node, tuple):
                _, space, offset, size = node
            elif 'register' in node:
                span = node['register']
                space, offset, size = span['space'], span['offset'], span['size']
            elif 'absolute' in node:
                span = node['absolute']
                space, offset, size = span['space'], span['address'], span['size']
            else:
                return None
            keys = [interpreter._key(space, offset + i) for i in range(size)]
            if not all(key in interpreter.entry_values for key in keys):
                return None
            return sum(interpreter.entry_values[key] << (8 * i) for i, key in enumerate(keys))

        values = evaluate(record, entry)  # no injected call-result callback
        concrete = sum(interpreter._byte(MEMORY, sink_place.start + i)[0] << (8 * i)
                       for i in range(sink_place.size))
        expected = (seed + 1) & 0xffffffff
        assert values == {concrete} == {expected}, (seed, values, concrete, expected)
        checked.append((seed, expected))
    return checked


def test_real_binary_outparam_store_reaches_post_call_load():
    path = os.environ.get('TDO_DFBENCH054_BUNDLE')
    if not path:
        pytest.skip('set TDO_DFBENCH054_BUNDLE to the pinned actual Ghidra Bundle')
    units, results, record = load_case(path)
    assert not record['truncated']
    assert not any(node['kind'] in ('debt', 'cut', 'unavailable') for node in record['nodes'])
    functions = {node.get('function') for node in record['nodes']}
    assert {CASE, HELPER, SOURCE_A} <= functions
    # The other call uses the SAME helper with another destination/source.
    assert SOURCE_B not in functions
    assert any(node['kind'] == 'op' and node['opcode'] == 'STORE' and node['function'] == HELPER
               for node in record['nodes'])
    import random
    seeds = [0, 1, 0x12345678, 0x7ffffffe, 0x7fffffff, 0xffffffff]
    seeds += [random.Random(i).getrandbits(32) for i in range(100)]
    assert len(execute_case(units, results, record, seeds)) == 106
