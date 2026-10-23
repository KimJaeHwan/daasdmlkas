"""Actual call-fed branch/switch predicates and selected stack STORE bytes.

The ordinary conservative expression union remains unchanged. This explicit
physical interpretation uses only root entry RAM/registers and the original
admitted code of every source/sink. It is not native binary execution.
"""

import pytest

from test_conditional_records_real import DFB010, DFB016, SOURCE_C, _entry, _execute, _load
from test_nested_physical_calls_real import SHA, STACK, _ActualWitnessInterpreter, _returns
from test_ue_core_conditional_records import _operation_record
from tdo_v2.operation_records import StitchContext, eligibility, evaluate_physical


SWITCH = '1b1:104793'


@pytest.fixture(scope='module')
def actual_control_calls():
    case = _load('TDO_CONDITIONAL_SUITE09_BUNDLE', (DFB010, DFB016, SWITCH), analysis_options=dict(
        assume_import_slots_hold_exports=False, assume_globals_disjoint_from_stack=False,
        assume_entry_values_not_frame=False, assume_opaque_callees_leave_no_stack_addresses=False,
        private_frame_above=0))
    assert case['image_sha'] == SHA
    assert all(not item.declared and not item.inherited_assumptions for item in case['results'].values())
    return case


@pytest.mark.parametrize('key,load', ((DFB010, '1b1:104740:1:LOAD'),
                                     (DFB016, '1b1:10488f:1:LOAD'),
                                     (SWITCH, '1b1:1047d1:1:LOAD')))
def test_actual_call_results_drive_branch_guards_and_selected_memory_writers(actual_control_calls, key, load):
    case = actual_control_calls
    item = case['results'][key]
    options = dict(declared=item.declared, provenance=case['provenance'][id(item)][1],
                   stitch=StitchContext(case['provenance']))
    record = _operation_record(item, load, physical_memory=True, **options)
    ordinary = _operation_record(item, load, **options)
    assert eligibility(record) == eligibility(ordinary)
    source = case['results'][SOURCE_C]
    (input_span,) = {span for exit_summary in source.summary.exits for run in exit_summary.runs
                    for span in run.sources if span.object_id.kind.value == 'address_space'}
    seen_writers = set()
    for seed, value in enumerate((0, 1, 2, 3, 9, 0x7fffffff, 0xffffffff, 0x80000000)):
        vm, run = _execute(case, item, ((0x20, 8, STACK),),
                           ((input_span.object_id.space_key, input_span.start, input_span.size, value),), seed,
                           interpreter_type=_ActualWitnessInterpreter)
        calls = _returns(case, vm)
        expected = (value + (1 if (value + 3) & 1 else 2)) & 0xffffffff
        if key == SWITCH:
            expected = (value + {0: 1, 1: 2}.get((value + 3) & 3, 3)) & 0xffffffff
        found = evaluate_physical(record, _entry(case, vm))
        assert found.value == expected
        prior = run.executed[:run.executed.index(load)]
        actual_calls = {operation for operation in prior if operation.endswith(':CALL')}
        assert actual_calls <= calls
        assert {event['call'] for event in found.evidence if event['kind'] == 'call'} == actual_calls
        (loaded,) = [event for event in found.evidence if event['kind'] == 'load' and event['key'] == load]
        actual = sum(vm._bytes[loaded['space'], loaded['address'] + byte][0] << (8 * byte)
                     for byte in range(loaded['width']))
        assert found.value == actual == expected
        for source_byte in loaded['sources']:
            writer = vm._bytes[loaded['space'], loaded['address'] + source_byte['at']][1]
            assert source_byte['writer'] == writer and source_byte['offset'] == source_byte['at']
            seen_writers.add(writer)
    assert len(seen_writers) == (3 if key == SWITCH else 2)
