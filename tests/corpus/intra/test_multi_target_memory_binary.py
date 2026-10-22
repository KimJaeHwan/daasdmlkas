"""Opt-in actual-binary checks of register and memory outputs of CALLIND.

TDO_MULTI_TARGET_MEMORY_BUNDLE names a sealed export of multi_target_memory.c
(export its case and both writers). TDO_DFB072_BUNDLE names a sealed export of
the existing case_DFB072_function_pointer_table and its actual call closure.
TDO_DFB072_WINDOWS_X64_BUNDLE and TDO_DFB072_WINDOWS_X86_BUNDLE select the
corresponding additional PE exports; these do not identify historical runs.
The existing p-code interpreter executes every callee body. No call result,
external-source value, or expected provenance is injected into the engine.
DFB072's shared writable source global is varied as program-entry memory
test input; both source bodies execute with that input on every run.
"""

import json
import os
from pathlib import Path

import pytest

from pcode_interpreter import Interpreter
from program_oracle import _place, check_program
from record_oracle import entry_reader
from synthetic import RAX, RDI, RSI, RSP
from tdo_v2._configured_bundle_reader import read_configured_bundle
from tdo_v2._scope_contracts import _mint_orchestrator_capability
from tdo_v2.call_summary_effects import anchored_span
from tdo_v2.image_info import load_image_info
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import _ObservedScopeProvider
from tdo_v2.interprocedural import analyze_units
from tdo_v2.normalize import NormalizedFunction
from tdo_v2.observed_call_state import observed_call_state_projections
from tdo_v2.operation_records import StitchContext, evaluate, root_record
from tdo_v2.scope_identity import open_configured_extraction
from tdo_v2.span_geometry import ByteSpan


def _load(environment, monkeypatch):
    path = os.environ.get(environment)
    if not path:
        pytest.skip(f"set {environment} to a sealed actual-binary generation")
    generation = Path(path)
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    adapter = _ObservedScopeProvider(read_configured_bundle(admit_frozen_bundle(generation)))
    units = []
    with open_configured_extraction(adapter, _mint_orchestrator_capability()) as session:
        for unit in session.iter_scoped_functions():
            adapter.collect_function_roles()
            units.append(unit)
    assert units
    spaces = units[0].scopes.program.evidence.address_spaces
    ids = tuple(next(row.space_id for row in spaces if getattr(row, flag))
                for flag in ("is_constant_space", "is_register_space", "is_unique_space"))
    provenance = {}
    results = analyze_units(units, record_provenance=provenance,
                            assume_globals_disjoint_from_stack=True)
    assert all(isinstance(item.normalized, NormalizedFunction) for item in results.values())
    image_info = load_image_info(generation)
    assert image_info is not None, "export with the current exporter, including sealed image facts"
    names = {row.name.removeprefix("_"): f"{row.space_id:x}:{row.byte_offset:x}"
             for row in image_info.exports}
    manifest = json.loads((generation / "manifest.json").read_text())
    members = {row["id"]: row["path"] for row in manifest["members"]}
    blocks = [(row["space_id"], row["byte_start"],
               (generation / members[row["member_id"]]).read_bytes())
              for row in manifest["blocks"] if row["is_initialized"] and row["member_id"]]

    def image(space, address):
        for block_space, start, data in blocks:
            if space == block_space and start <= address < start + len(data):
                return data[address - start]
        return None

    projections = observed_call_state_projections(units[0].observation)
    assert projections, "the selected actual case must contain an observed call shape"
    stack = projections[0].memory_transition.caller_base
    assert all(row.memory_transition.caller_base == stack for row in projections)
    return dict(results=results, names=names, provenance=provenance, ids=ids, image=image, stack=stack,
                image_format=image_info.executable_format, image_info=image_info,
                program={(u.scopes.function.entry.space_id, u.scopes.function.entry.byte_offset): u.observation
                         for u in units},
                address_bits={row.space_id: row.address_size_bits for row in spaces if row.is_memory_space})


@pytest.fixture
def memory_binary(monkeypatch):
    return _load("TDO_MULTI_TARGET_MEMORY_BUNDLE", monkeypatch)


@pytest.fixture(params=("TDO_DFB072_BUNDLE", "TDO_DFB072_WINDOWS_X64_BUNDLE", "TDO_DFB072_WINDOWS_X86_BUNDLE"))
def dfb072_binary(request, monkeypatch):
    return _load(request.param, monkeypatch)


def _operations(item):
    return [(f"{ins.address.space_id:x}:{ins.address.byte_offset:x}:{index}:{operation.opcode}", operation)
            for ins in item.unit.observation.instructions for index, operation in enumerate(ins.operations)]


def _record(case, item, definition, width=None, span=None):
    span = span or item.normalized.memory_ssa.definitions[definition].span
    if width is not None:
        assert width <= span.size
        span = ByteSpan(span.object_id, span.start, width)
    node = item.normalized.memory_graph.definition_nodes[definition]
    return root_record(item.normalized, item.unit, [(node, (span,))], declared=item.declared,
                       provenance=case["provenance"][id(item)][1], stitch=StitchContext(case["provenance"]))


def _action_record(case, item, operation_key):
    action = next(row for row in item.normalized.memory_ssa.actions if row.operation_key == operation_key)
    (definition,) = action.write_definition_ids
    return _record(case, item, definition)


def _record_bodies(case, record, opcode, targets):
    keys = {node["key"] for node in record["nodes"]
            if node["kind"] == "op" and node.get("opcode") == opcode}
    return {target for target in targets
            if any(key in keys for key, _ in _operations(case["results"][target]))}


def _entry(vm, register):
    """Use the existing record oracle with the actual Bundle's register id."""
    read = entry_reader(vm)

    def entry(node):
        if isinstance(node, dict) and "register" in node:
            row = node["register"]
            return read(("entry", register, row["offset"], row["size"]))
        return read(node)

    return entry


def _execute(case, item, pools, seed=0, *, memory_inputs=()):
    constant, register, _ = case["ids"]
    vm = Interpreter(item.unit.observation, constant_space=constant, seed=seed, program=case["program"],
                     image=case["image"], address_bits=case["address_bits"])
    for offset, value in pools.items():
        vm.preset(register, offset, case["stack"].byte_size, value)
    for space, address, size, value in memory_inputs:
        vm.preset(space, address, size, value)
    run = vm.run()
    assert run.completed and run.executed and not vm.opaque_opcodes
    return vm


def _value(vm, space, address, size=4):
    return sum(vm._byte(space, address + index)[0] << (8 * index) for index in range(size))


def _actual_target(vm, item, call):
    operation = next(operation for key, operation in _operations(item) if key == call)
    pointer = operation.inputs[0]
    (state,) = [state for key, state in vm.activation_snapshots.values() if key == call]
    address = sum(state[(pointer.coordinate.space_id, pointer.coordinate.byte_offset + index)] << (8 * index)
                  for index in range(pointer.byte_size))
    return f"{item.unit.scopes.function.entry.space_id:x}:{address:x}"


def _memory_pools(seed):
    values = (0, 1, 9, 0x7fffffff, 0xffffffff, 0x80000000)
    return {RSP: 0x70000000, RDI: seed & 1, RSI: values[seed // 2]}


def test_actual_memory_writers_and_following_load_match_program_oracle(memory_binary):
    case = memory_binary
    caller = case["results"][case["names"]["case_multi_target_memory"]]
    targets = {case["names"]["multi_memory_a"], case["names"]["multi_memory_b"]}
    (call, members), = caller.multi_calls.items()
    assert set(members) == targets
    effect = caller.proven[call]
    assert effect.memory_runs and not effect.unknown_memory
    report = check_program(caller.normalized, caller.unit.observation, case["program"], seeds=range(12),
                           register_pools=_memory_pools, spaces=case["ids"], image=case["image"],
                           address_bits=case["address_bits"], external_abi="sysv64")
    assert report.runs == 12 and report.through_calls and not report.unsupported
    assert not report.silent and not report.covered_by_debt
    assert report.place_checked and report.place_checked == report.place_covered
    assert not report.place_unlocated_only and not report.place_failed and not report.place_no_activation
    visited = set()
    for seed in range(12):
        pools = _memory_pools(seed)
        vm = _execute(case, caller, pools, seed)
        visited.add(_actual_target(vm, caller, call))
        expected = (2 * pools[RSI] + (17 if pools[RDI] == 0 else 34)) & 0xffffffff
        assert _value(vm, case["ids"][1], RAX) == expected
    assert visited == targets


def test_actual_memory_records_keep_both_stores_and_correlate_call_outputs(memory_binary):
    case = memory_binary
    caller = case["results"][case["names"]["case_multi_target_memory"]]
    targets = {case["names"]["multi_memory_a"], case["names"]["multi_memory_b"]}
    operations = _operations(caller)
    call_index = next(index for index, (_, operation) in enumerate(operations) if operation.opcode == "CALLIND")
    load_key = next(key for key, operation in operations[call_index + 1:]
                    if operation.opcode == "LOAD" and operation.output.byte_size == 4)
    loaded = _action_record(case, caller, load_key)
    (exit_summary,) = caller.summary.exits
    run = next(run for run in exit_summary.runs
               if run.span.object_id.kind.value == "register_file" and run.span.start == RAX)
    (definition,) = run.definitions
    final = _record(case, caller, definition, width=4)
    for record in (loaded, final):
        assert not record["truncated"]
        assert _record_bodies(case, record, "STORE", targets) == targets
        assert _record_bodies(case, record, "INT_ADD", targets) == targets
        pairs = [node for node in record["nodes"] if node.get("reason") == "call targets and exits"]
        assert pairs and all({choice["function"] for choice in node["choices"]} == targets for node in pairs)
    for seed in range(12):
        pools = _memory_pools(seed)
        vm = _execute(case, caller, pools, seed)
        read = _entry(vm, case["ids"][1])
        trace = set()
        x = pools[RSI]
        assert evaluate(loaded, read, route="stitched", trace=trace) == {(x + n) & 0xffffffff for n in (1, 2)}
        assert trace
        values = evaluate(final, read, route="stitched")
        assert values == {(2 * x + n) & 0xffffffff for n in (17, 34)}
        assert not values & {(2 * x + n) & 0xffffffff for n in (18, 33)}
        assert _value(vm, case["ids"][1], RAX) in values


def test_actual_dfb072_record_reaches_both_return_expressions(dfb072_binary):
    case = dfb072_binary
    caller = case["results"][case["names"]["case_DFB072_function_pointer_table"]]
    targets = {case["names"]["dfb_fp_table_target_A"], case["names"]["dfb_fp_table_target_B"]}
    (call, members), = caller.multi_calls.items()
    assert set(members) == targets
    # The queried benchmark flow is the return expression. Win64 also spills
    # its parameter into the observed stack home slot; that compiler spill
    # is accounted for separately from the explicit output-pointer fixture.
    if case["image_format"].startswith("Portable Executable") and case["stack"].byte_size == 8:
        (home,) = caller.proven[call].memory_runs
        assert home.write.anchor is not None
        assert (home.write.anchor.start, home.write.anchor.size, home.write.displacement, home.write.size) == (
            case["stack"].byte_offset, case["stack"].byte_size, case["stack"].byte_size, 4)
    else:
        assert not caller.proven[call].memory_runs
    sink = case["names"]["dfb_sink_int"]
    sink_call = next(key for key, target in caller.calls.items() if target == sink)
    # Query the actual four-byte reads staged before the sink. This follows
    # the sink body's own dependencies: SysV's register, Win64's register,
    # and Win32's stack slot all use the same observed-state path.
    arguments = {}
    for read in caller.normalized.memory_ssa.reads:
        action = caller.normalized.memory_ssa.actions[read.action_id]
        base, separator, tag = action.operation_key.partition("~")
        if base != sink_call or not separator or not tag.startswith(("in", "ld")) or read.span.size != 4:
            continue
        assert len(read.fragments) == 1 and len(read.fragments[0].definition_ids) == 1
        definition = read.fragments[0].definition_ids[0]
        record = _record(case, caller, definition, span=read.span)
        if _record_bodies(case, record, "INT_ADD", targets) == targets:
            arguments.setdefault(read.span, record)
    (argument, record), = arguments.items()
    assert not record["truncated"]
    assert _record_bodies(case, record, "INT_ADD", targets) == targets
    source = case["results"][case["names"]["dfb_source_A"]]
    source_call = next(key for key, target in caller.calls.items() if target == source.key)
    (source_output,) = [run.span for exit_summary in source.summary.exits for run in exit_summary.runs
                        if run.span.object_id.kind.value == "register_file" and run.span.size >= 4
                        and run.kind.value == "computed"
                        and any(span.object_id.kind.value == "address_space" for span in run.sources)]
    selector_source = case["results"][case["names"]["dfb_source_C"]]
    shared_inputs = [
        {span for exit_summary in item.summary.exits for run in exit_summary.runs for span in run.sources
         if span.object_id.kind.value == "address_space"}
        for item in (source, selector_source)
    ]
    (source_input,) = shared_inputs[0] & shared_inputs[1]
    input_space = source_input.object_id.space_key
    block = case["image_info"].block_at(input_space, source_input.start, source_input.size)
    assert block is not None and block.write and block.read
    visited = set()
    for seed, initial in enumerate((0, 1, 9, 0x7fffffff, 0xffffffff, 0x80000000)):
        vm = _execute(case, caller, {case["stack"].byte_offset: 0x70000000}, seed,
                      memory_inputs=((input_space, source_input.start, source_input.size, initial),))
        visited.add(_actual_target(vm, caller, call))
        trace = set()
        values = evaluate(record, _entry(vm, case["ids"][1]), route="stitched", trace=trace)
        assert trace
        # Compare the sink's actual entry bytes, with its source bodies executed.
        snapshots = [state for call_key, state in vm.activation_snapshots.values() if call_key == sink_call]
        (state,) = snapshots
        if argument.object_id.kind.value == "register_file":
            place = case["ids"][1], argument.start, argument.size
        else:
            anchored = anchored_span(argument, caller.anchors)
            assert anchored is not None
            place = _place(anchored, {}, vm.entry_values, case["ids"][1], moduli=vm._moduli)
        assert place is not None
        space, address, size = place
        actual = sum(state[(space, address + index)] << (8 * index) for index in range(size))
        assert actual in values
        (source_serial,) = [serial for serial, (key, _) in vm.activation_snapshots.items() if key == source_call]
        returned = vm.activation_returns[source_serial]
        x = sum(returned[(case["ids"][1], source_output.start + index)] << (8 * index) for index in range(4))
        assert values == {(x + n) & 0xffffffff for n in (1, 2)}
    assert visited == targets
