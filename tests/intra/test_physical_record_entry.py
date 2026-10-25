"""Physical records are an opt-in diagnostic at the formal engine/CLI entry.

Synthetic p-code uses the existing admitted fixtures and interpreter, not
injected call results. The optional actual regression uses a fresh sealed
v2 naming Bundle; the older suite09/suite10 v1 sidecars cannot be submitted to
the current public naming decoder and are never rewritten by this test.
"""

import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from pcode_interpreter import Interpreter
from record_oracle import entry_reader
from synthetic import (
    CONST, RAM, REG, RBX, RCX, RDX, RSP, RAX, FunctionBuilder, add, boundary,
    const, copy, load, reg, store, summary_inputs,
)
from test_physical_call_records import _callee
from test_record_isolation import LIMIT_VARIABLES, _without_records, program
from tdo_v2 import resource_limits
from tdo_v2._record_memory import evaluate_physical
from tdo_v2.operation_records import Ineligible, eligibility
from tdo_v2.observed_call_state import observed_call_state_projections
from tdo_v2.summary_engine import analyze_observed_with_summaries


REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'tools' / 'graph_fidelity'))
sys.path.insert(0, str(REPO / 'tools' / 'bundle_export'))

NO_ASSUMPTIONS = dict(
    assume_boundary_call_effects=False, assume_globals_disjoint_from_stack=False,
    assume_direction_flag_clear=False, assume_win64_home_space_private=False,
    assume_debug_break_traps_do_not_return=False, assume_import_slots_hold_exports=False,
    assume_entry_values_not_frame=False, assume_opaque_callees_leave_no_stack_addresses=False,
    assume_same_result_functions=False, assume_accessor_result_separate=False,
    assume_accessor_private_state=False, assume_registered_handlers_not_observed=False,
)


@pytest.fixture(autouse=True)
def _clean_limits(monkeypatch):
    for name in LIMIT_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv('TDO_V2_INTERPROCEDURAL', raising=False)


@pytest.fixture(scope='module')
def leaf_program():
    caller = (FunctionBuilder().sub_rsp(0x28).ins(store(reg(RCX), reg(RDX))).call(0x1800)
              .ins(load(reg(RAX), reg(RCX)), add(reg(RAX), reg(RAX), const(5)),
                   copy(reg(RCX), reg(RAX))).call(0x1a00).add_rsp(0x28).ret())
    inputs = summary_inputs([caller, _callee(), FunctionBuilder(entry=0x1a00).ret()],
                            {0x1a00: 'capture'}, image=False)
    return inputs, boundary(sinks={'capture': 8})


def _run(inputs, provider, **options):
    return analyze_observed_with_summaries(
        inputs.program, inputs.evidences, image_info=inputs.image_info,
        readonly_image=inputs.readonly_image, boundary_provider=provider,
        **NO_ASSUMPTIONS, **options)


def _one_record(run):
    (root,) = [root for root in run.roots if root.label == 'capture.arg0']
    return root, root.explanation['record']


def _walk(value):
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk(item)


def test_opt_in_implies_records_without_changing_analysis(leaf_program):
    from semantic_snapshot import encode

    inputs, provider = leaf_program
    default = _run(inputs, provider)
    ordinary = _run(inputs, provider, operation_records=True)
    physical = _run(inputs, provider, physical_memory_records=True)
    assert default.roots and all('record' not in root.explanation for root in default.roots)
    assert _without_records(encode(ordinary)) == encode(default)
    assert _without_records(encode(physical)) == encode(default)
    ordinary_root, ordinary_record = _one_record(ordinary)
    physical_root, physical_record = _one_record(physical)
    assert not any(key.startswith('physical_') for item in _walk(ordinary_record) for key in item)
    assert physical_record['physical_effect_inventory']
    assert physical_record['physical_calls'], 'the public root is after the original direct leaf CALL'
    assert eligibility(physical_record) == eligibility(ordinary_record)
    assert physical_root.effective_completeness == ordinary_root.effective_completeness
    assert not physical.assumptions

    observation = inputs.evidences[0].unit.observation
    vm = Interpreter(observation, constant_space=CONST, seed=0,
                     program={(item.unit.scopes.function.entry.space_id,
                               item.unit.scopes.function.entry.byte_offset): item.unit.observation
                              for item in inputs.evidences})
    for offset, value in ((RSP, 0x70000000), (RCX, 0x71000000), (RDX, 7), (RBX, 0x22)):
        vm.preset(REG, offset, 8, value)
    vm.preset(RAM, 0x70000000, 8, 0x2000)
    execution = vm.run()
    assert execution.completed and not vm.opaque_opcodes
    # RETURN scheduling alone is not an oracle: inspect the actual leaf IP/SP.
    (serial,) = [serial for serial, (key, _) in vm.activation_snapshots.items() if key == '1:1008:2:CALL']
    returned = vm.activation_returns[serial]
    value = lambda offset: sum(returned[REG, offset + index] << (8 * index) for index in range(8))
    assert value(0x288) == 0x100c and value(RSP) == 0x70000000 - 0x28
    (sink_entry,) = [state for key, state in vm.activation_snapshots.values() if key == '1:1010:2:CALL']
    actual = sum(sink_entry[REG, RCX + index] << (8 * index) for index in range(8))
    assert evaluate_physical(physical_record, entry_reader(vm)).value == actual == 15
    with pytest.raises(Ineligible):
        evaluate_physical(physical_record, entry_reader(vm), max_steps=1)
    with pytest.raises(Ineligible):
        evaluate_physical(physical_record, lambda node: None)


@pytest.mark.parametrize('limits', ({}, {'TDO_V2_FUNCTION_WORK': 0.5},
                                  {'TDO_V2_RUN_WORK': 0.8}, {'TDO_V2_RECORD_WORK': 50}))
def test_physical_records_have_only_a_diagnostic_budget(program, monkeypatch, limits):
    from semantic_snapshot import encode

    fixture, inputs = program
    options = dict(boundary_provider=fixture.provider,
                   pcodeop_models=fixture.pcodeop_models(inputs.evidences))

    def run(physical):
        result = analyze_observed_with_summaries(
            inputs.program, inputs.evidences, image_info=inputs.image_info,
            readonly_image=inputs.readonly_image, physical_memory_records=physical, **options)
        last = resource_limits.last_run()
        return result, encode(result), last.work, {key: item.work for key, item in last.ledgers.items()}

    _, _, work, ledgers = run(False)
    for name, fraction in limits.items():
        amount = fraction if name == 'TDO_V2_RECORD_WORK' else max(
            1, int((work if name == 'TDO_V2_RUN_WORK' else max(ledgers.values())) * fraction))
        monkeypatch.setenv(name, str(amount))
    _, off, off_work, off_ledgers = run(False)
    on_run, on, on_work, on_ledgers = run(True)
    assert _without_records(on) == off
    assert (on_work, on_ledgers) == (off_work, off_ledgers)
    records = [root.explanation['record'] for root in on_run.roots if root.root_nodes]
    if not limits:
        assert records
    if 'TDO_V2_RECORD_WORK' in limits:
        assert any(record.get('cut') == 'diagnostic budget' for record in records)
    for root in on_run.roots:
        record = root.explanation.get('record', {})
        if 'completeness' in record:
            assert record['completeness']['complete'] == root.effective_completeness.complete


def test_unknown_call_in_public_root_fails_closed():
    caller = (FunctionBuilder().sub_rsp(0x28).ins(store(reg(RCX), reg(RDX))).call(0x1f00)
              .ins(load(reg(RAX), reg(RCX)), copy(reg(RCX), reg(RAX)))
              .call(0x1a00).add_rsp(0x28).ret())
    inputs = summary_inputs([caller, FunctionBuilder(entry=0x1a00).ret()], {0x1a00: 'capture'})
    provider = boundary(sinks={'capture': 8})
    _, ordinary = _one_record(_run(inputs, provider, operation_records=True))
    _, physical = _one_record(_run(inputs, provider, physical_memory_records=True))
    assert eligibility(physical) == eligibility(ordinary)
    assert any(event['key'] == '1:1008:2:CALL' and not event.get('context')
               for event in physical['physical_root_events'])

    def entry(node):
        if isinstance(node, tuple):
            return 0  # known function-entry RAM, never a call result
        if 'register' in node:
            row = node['register']
            values = {RSP: 0x70000000, RCX: 0x71000000, RDX: 7, RBX: 0x22}
            return sum(((values.get((row['offset'] + index) // 8 * 8, 0)
                         >> (8 * ((row['offset'] + index) % 8))) & 255) << (8 * index)
                       for index in range(row['size']))
        return 0 if 'absolute' in node else None

    with pytest.raises(Ineligible):
        evaluate_physical(physical, entry)


def test_frozen_entry_forwards_the_opt_in_after_admission(leaf_program, monkeypatch, tmp_path):
    """Admission is stubbed only here; the same genuine evidences run the engine."""
    import tdo_v2.integration.configured_bundle as configured
    import tdo_v2.summary_engine as engine

    inputs, provider = leaf_program

    @contextmanager
    def session(*args, **kwargs):
        yield SimpleNamespace(program_result=inputs.program, iter_functions=lambda: iter(inputs.evidences))

    monkeypatch.setattr(configured, 'admit_frozen_bundle', lambda path: path)
    monkeypatch.setattr(engine, 'open_observed_function_session', session)
    monkeypatch.setattr(engine, 'load_image_info', lambda path: None)
    exporter = tmp_path / 'exporter.java'
    exporter.write_text('fixture exporter binding')
    run = engine.analyze_frozen_bundle_with_summaries(
        tmp_path, naming_exporter_source=exporter, boundary_provider=provider,
        assume_readonly_image_constant=False, physical_memory_records=True, **NO_ASSUMPTIONS)
    _, record = _one_record(run)
    assert record['physical_calls'] and record['physical_effect_inventory']


@pytest.mark.parametrize('legacy', ('flag', 'environment'))
def test_cli_rejects_legacy_before_opening_the_bundle(monkeypatch, capsys, legacy):
    import run_dfbench

    argv = ['run_dfbench', '/not/an/admitted/bundle', '--physical-records']
    if legacy == 'flag':
        argv.append('--legacy-engine')
    else:
        monkeypatch.setenv('TDO_V2_INTERPROCEDURAL', 'legacy')
    monkeypatch.setattr(sys, 'argv', argv)
    with pytest.raises(SystemExit) as error:
        run_dfbench.main()
    assert error.value.code == 2
    message = capsys.readouterr().err
    assert '--physical-records' in message and 'summary engine' in message


@pytest.mark.parametrize('flags,records,physical', (((), False, False), (('--records',), True, False),
                                                (('--physical-records',), True, True)))
def test_cli_record_options_reach_engine_and_json(leaf_program, monkeypatch, tmp_path, flags, records, physical):
    import run_dfbench
    import tdo_v2.summary_engine as engine

    inputs, provider = leaf_program
    actual = _run(inputs, provider, operation_records=records, physical_memory_records=physical)
    received = {}

    def analyze(*args, **kwargs):
        received.update(kwargs)
        return actual

    monkeypatch.setattr(engine, 'analyze_frozen_bundle_with_summaries', analyze)
    monkeypatch.setattr(run_dfbench, 'abi_of', lambda generation: 'win64')
    monkeypatch.setattr(run_dfbench, 'selection_names', lambda generation: [])
    monkeypatch.setattr(run_dfbench, 'external_models', lambda *args: None)
    monkeypatch.setattr(run_dfbench, 'pcodeop_models', lambda: None)
    (tmp_path / 'manifest.json').write_text(json.dumps({'functions': []}))
    output = tmp_path / 'records.json'
    monkeypatch.setattr(sys, 'argv', ['run_dfbench', str(tmp_path), *flags, '--json', str(output)])
    assert run_dfbench.main() == 0
    assert received['physical_memory_records'] is physical and received['operation_records'] is records
    rows = json.loads(output.read_text())
    output_roots = [root for row in rows.values() for root in row['roots']]
    assert output_roots and all(('record' in root) is records for root in output_roots)
    if records:
        assert all(bool(root['record'].get('physical_calls')) is physical for root in output_roots)


@pytest.fixture
def actual_dfb072_public(monkeypatch):
    """Fresh original ELF; no sealed member or naming fact is transformed.

    tdo_testbed/src/cases_indirect.c:48-56, dfbench_sources_sinks.c:11-25.
    Caller1052b3: source_C CALL1052d1, source_A CALL1052dc, CALLIND1052f3,
    original sink CALL1052fd. The extra boundary queries its actual EDI4
    input BEFORE CALLIND, not a fabricated source result or the final sink.
    All configurable assumptions are false; actual input g_seed is varied.
    """
    import run_dfbench
    import tdo_v2.operation_records as records
    import tdo_v2.summary_engine as engine
    from tdo_v2.boundary import BoundaryKind, BoundaryMatch
    from tdo_v2.physical_state import PhysicalRegisterSlice

    location = os.environ.get('TDO_DFB072_BUNDLE')
    if not location:
        pytest.skip('set TDO_DFB072_BUNDLE to the fresh ELF v2 naming generation')
    generation = Path(location)
    # Pin the default target-resolution route: the final CALLIND is an
    # unsupported physical boundary, independently of optional forward analysis.
    monkeypatch.setenv('TDO_V2_FORWARD', '0')
    original_provider = run_dfbench.boundary_provider(abi='sysv64')

    class InputBoundary:
        def classify(self, call):
            if call.instruction_address == '1b1:1052f3:3:CALLIND':
                return (BoundaryMatch(BoundaryKind.SINK, 'capture.arg0'),)
            return original_provider.classify(call)

        def state(self, call, match):
            if match.label == 'capture.arg0':
                return (PhysicalRegisterSlice(0x38, 4),)
            return original_provider.state(call, match)

    results, calls = {}, []
    analyze, root_record = engine.analyze_units, records.root_record

    def capture_analysis(*args, **kwargs):
        result = analyze(*args, **kwargs)
        results.update(result)
        return result

    def capture_record(*args, **kwargs):
        record = root_record(*args, **kwargs)
        calls.append((record, args, kwargs))
        return record

    monkeypatch.setattr(engine, 'analyze_units', capture_analysis)
    monkeypatch.setattr(records, 'root_record', capture_record)
    options = dict(naming_exporter_source=REPO / 'ghidra' / 'GhidraV2CallNaming.java',
                   boundary_provider=InputBoundary(), assume_readonly_image_constant=False,
                   **NO_ASSUMPTIONS)
    ordinary = engine.analyze_frozen_bundle_with_summaries(generation, operation_records=True, **options)
    physical = engine.analyze_frozen_bundle_with_summaries(generation, physical_memory_records=True, **options)
    from semantic_snapshot import encode

    assert _without_records(encode(physical)) == _without_records(encode(ordinary))
    assert physical.assumptions == ordinary.assumptions
    # The unresolved indirect call's SP convention remains an explicit debt;
    # physical diagnostics must not erase it or add any analysis assumption.
    assert physical.assumptions == ('opaque-callees-restore-stack-pointer',)
    caller = results['1b1:1052b3']
    assert caller.unit.scopes.program.evidence.executable_sha256.hex() == (
        '759c776096d7454feadfbe92b4645b4a825450cce099b732363b1d9cc7238e29')
    assert caller.unit.scopes.function.observation_digest.hex() == (
        '765b59a1c3c0f22908559a8e4e3a7ec514b6c9e9c5bcf5f2de0c19a869332892')
    public_root, public = _one_record(physical)
    _, regular = _one_record(ordinary)
    assert eligibility(public) == eligibility(regular) == 'debt'
    assert public_root.root_nodes and public['physical_calls']
    (captured,) = [(args, kwargs) for record, args, kwargs in calls if record is public]
    assert captured[0][0] is caller.normalized and captured[1]['physical_memory'] is True
    direct = root_record(*captured[0], **captured[1])
    assert direct['physical_calls'] == public['physical_calls']
    assert direct['physical_root_events'] == public['physical_root_events']
    assert eligibility(direct) == eligibility(public)
    assert {event['key'] for event in public['physical_root_events']} == {
        '1b1:1052d1:2:CALL', '1b1:1052dc:2:CALL'}
    spaces = caller.unit.scopes.program.evidence.address_spaces
    register = next(space.space_id for space in spaces if space.is_register_space)
    constant = next(space.space_id for space in spaces if space.is_constant_space)
    inputs = [{span for exit in results[key].summary.exits for run in exit.runs for span in run.sources
               if span.object_id.kind.value == 'address_space'} for key in ('1b1:10453b', '1b1:104559')]
    (source_input,) = inputs[0] & inputs[1]
    assert source_input.start == 0x109098 and source_input.size == 4
    manifest = json.loads((generation / 'manifest.json').read_text())
    members = {row['id']: row['path'] for row in manifest['members']}
    blocks = [(row['space_id'], row['byte_start'], (generation / members[row['member_id']]).read_bytes())
              for row in manifest['blocks'] if row['is_initialized'] and row['member_id']]

    def image(space, address):
        for block_space, start, data in blocks:
            if space == block_space and start <= address < start + len(data):
                return data[address - start]
        return None

    return SimpleNamespace(caller=caller, results=results, direct=direct, public=public,
                           run=physical, register=register, constant=constant, image=image,
                           source_input=source_input,
                           address_bits={space.space_id: space.address_size_bits for space in spaces
                                         if space.is_memory_space})


def _actual_execution(case, initial):
    """Only program-entry registers/RAM change; every source body executes."""
    vm = Interpreter(case.caller.unit.observation, constant_space=case.constant, seed=0,
                     program={(item.unit.scopes.function.entry.space_id,
                               item.unit.scopes.function.entry.byte_offset): item.unit.observation
                              for item in case.results.values()}, image=case.image,
                     address_bits=case.address_bits)
    vm.preset(case.register, RSP, 8, 0x70000000)
    span = case.source_input
    vm.preset(span.object_id.space_key, span.start, span.size, initial)
    execution = vm.run()
    assert execution.completed and not vm.opaque_opcodes
    reader = entry_reader(vm)

    def entry(node):
        if isinstance(node, dict) and 'register' in node:
            row = node['register']
            return reader(('entry', case.register, row['offset'], row['size']))
        return reader(node)

    return vm, entry


def test_actual_public_pre_indirect_input_matches_direct_record_and_raw_return(actual_dfb072_public):
    case = actual_dfb072_public
    for initial in (0, 1, 9, 0x7fffffff, 0xffffffff, 0x80000000):
        vm, entry = _actual_execution(case, initial)
        (source_serial,) = [serial for serial, (key, _) in vm.activation_snapshots.items()
                           if key == '1b1:1052dc:2:CALL']
        entry_state = vm.activation_snapshots[source_serial][1]
        returned = vm.activation_returns[source_serial]
        ret = case.results['1b1:10453b'].unit.observation.instructions[-1]
        assert [operation.opcode for operation in ret.operations] == ['LOAD', 'INT_ADD', 'RETURN']
        assert ret.operations[0].output == ret.operations[2].inputs[0]
        ip = ret.operations[0].output.coordinate.byte_offset
        (call_instruction,) = [instruction for instruction in case.caller.unit.observation.instructions
                               if instruction.address.byte_offset == 0x1052dc]
        assert call_instruction.fallthrough is not None
        (projection,) = [row for row in observed_call_state_projections(case.caller.unit.observation)
                        if row.call_operation_key == '1b1:1052dc:2:CALL']

        def register(state, offset, size=8):
            return sum(state[case.register, offset + index] << (8 * index) for index in range(size))

        assert call_instruction.fallthrough.byte_offset == 0x1052e1
        assert register(returned, ip) == call_instruction.fallthrough.byte_offset
        assert register(returned, RSP) == register(entry_state, RSP) - projection.memory_transition.displacement_delta
        (indirect_entry,) = [state for key, state in vm.activation_snapshots.values()
                            if key == '1b1:1052f3:3:CALLIND']
        actual = register(indirect_entry, 0x38, 4)
        assert actual == register(returned, RAX, 4)
        assert actual == (initial + 1) & 0xffffffff
        public = evaluate_physical(case.public, entry)
        direct = evaluate_physical(case.direct, entry)
        assert public.value == direct.value == actual
        assert public.evidence == direct.evidence
        assert any(item.get('kind') == 'call' and item.get('call') == '1b1:1052dc:2:CALL'
                   for item in public.evidence)


def test_actual_final_indirect_sink_keeps_unsupported_effect_fail_closed(actual_dfb072_public):
    case = actual_dfb072_public
    (_, record), = [(root, root.explanation['record']) for root in case.run.roots
                   if root.label == 'dfb_sink_int.arg0']
    assert eligibility(record) == 'debt'
    assert any(event['key'] == '1b1:1052f3:3:CALLIND' and not event.get('context')
               for event in record['physical_root_events'])
    _, entry = _actual_execution(case, 9)
    with pytest.raises(Ineligible):
        evaluate_physical(record, entry)
