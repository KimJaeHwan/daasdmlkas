"""Actual diamond conditions and branch-correlated memory output records.

Set TDO_CONDITIONAL_SUITE09_BUNDLE to the admitted generation containing
DFB010/016, and TDO_CONDITIONAL_SUITE10_BUNDLE to the generation containing
tv2c650_store_selected_lane. Local evidence used to prepare these checks:

* tdo_testbed/src/cases_control_flow.c:3 and :64; suite09_fresh_x64_baseline_39,
  dfbench_win_core, generation c6edcb2c812de6b6b226bcd7a83c9d418e1858a21e56cbadffb7ef92d63109d1.
  DFB010: 10472c -> 10472e/104738 -> 104740 (LOAD [rbp-4]).
  DFB016: 10487b -> 10487d/104887 -> 10488f (LOAD [rbp-4]).
* tdo_testbed_UE/cpp_like/src/cases_fusion.cpp:1714;
  suite10_full_x64_capability_baseline_171, tv2_cpp_like, generation
  cddea32fb84d188522eca9f9584d784d5c9eca86cc72d711a67808c445d903f1.
  Helper 1096a0: 1096bc -> 1096be/1096cc -> 1096d8. The arms store
  entry-RDI+4 at 1096c7 and entry-RDI+8 at 1096d5, respectively.
* The same suite10 generation contains cases_fusion.cpp:803,
  tv2c622_pick_writer, at 1081c0: 1081c9 -> 1081cb/1081d9 -> 1081e7.
  Both arms STORE eight bytes to [entry-RSP-16], then LOAD them at 1081e7.

DFB010/016 are negative controls: their arms call source bodies, so branch
selection explicitly falls back to the original alternatives. The two leaf
helpers are the supported actual branch-selection cases.

Names select pinned actual observations only. The existing interpreter runs
all source/sink bodies; varying their shared global is program-entry input,
not an injected source result. The helper's two entry fields are also inputs.
"""

import json
import os
from pathlib import Path

import pytest

from pcode_interpreter import Interpreter
from record_oracle import entry_reader
from tdo_v2._configured_bundle_reader import read_configured_bundle
from tdo_v2._scope_contracts import _mint_orchestrator_capability
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import _ObservedScopeProvider
from tdo_v2.interprocedural import _direct_calls, analyze_units, function_key
from tdo_v2.normalize import NormalizedFunction
from tdo_v2.operation_records import StitchContext, evaluate, root_record, run_records
from tdo_v2.pcode_blocks import build_pcode_block_graph
from tdo_v2.scope_identity import open_configured_extraction


DFB010, DFB016, HELPER, PICKER = "1b1:104715", "1b1:104862", "1b1:1096a0", "1b1:1081c0"
SOURCE_C, SINK = "1b1:104559", "1b1:104595"
DIGESTS = {
    DFB010: "2ccfe67d4e2896e11ad0bc200b238623921ed738cc2c5c0ecbfa76348a886b0f",
    DFB016: "80c227a0ce01d56ad645c768cbe05b99066af4496a4ac88b5ccaf4b4a46be2d5",
    HELPER: "b3c99ab53ec1546a97e843403dec23349275f5287dbf596a122dc09d0ad73dfb",
    PICKER: "5b4a06f945896c3b3b42208789130f68687848be5ef1399d6adb3d2db9be9cae",
}


def _load(environment, roots):
    value = os.environ.get(environment)
    if not value:
        pytest.skip(f"set {environment} to the actual sealed generation")
    generation = Path(value)
    adapter = _ObservedScopeProvider(read_configured_bundle(admit_frozen_bundle(generation)))
    units = {}
    with open_configured_extraction(adapter, _mint_orchestrator_capability()) as session:
        for unit in session.iter_scoped_functions():
            adapter.collect_function_roles()
            units[function_key(unit.scopes.function.entry)] = unit
    for key in roots:
        assert units[key].scopes.function.observation_digest.hex() == DIGESTS[key]
    selected, pending = set(), list(roots)
    while pending:
        key = pending.pop()
        if key in selected:
            continue
        selected.add(key)
        pending.extend(_direct_calls(units[key], units).values())
    provenance = {}
    results = analyze_units([units[key] for key in sorted(selected)], record_provenance=provenance,
                            assume_globals_disjoint_from_stack=True)
    assert all(isinstance(item.normalized, NormalizedFunction) for item in results.values())
    evidence = units[roots[0]].scopes.program.evidence
    register = next(row.space_id for row in evidence.address_spaces if row.is_register_space)
    constant = next(row.space_id for row in evidence.address_spaces if row.is_constant_space)
    manifest = json.loads((generation / "manifest.json").read_text())
    members = {row["id"]: row["path"] for row in manifest["members"]}
    blocks = [(row["space_id"], row["byte_start"], (generation / members[row["member_id"]]).read_bytes())
              for row in manifest["blocks"] if row["is_initialized"] and row["member_id"]]

    def image(space, address):
        for block_space, start, data in blocks:
            if space == block_space and start <= address < start + len(data):
                return data[address - start]
        return None

    return dict(results=results, provenance=provenance, register=register, constant=constant, image=image,
                program={(units[key].scopes.function.entry.space_id, units[key].scopes.function.entry.byte_offset):
                         units[key].observation for key in selected},
                address_bits={row.space_id: row.address_size_bits for row in evidence.address_spaces
                              if row.is_memory_space})


@pytest.fixture(scope="module")
def actual_suite09():
    return _load("TDO_CONDITIONAL_SUITE09_BUNDLE", (DFB010, DFB016))


@pytest.fixture(scope="module")
def actual_suite10():
    return _load("TDO_CONDITIONAL_SUITE10_BUNDLE", (HELPER, PICKER))


def _entry(case, vm, *, node_base=None):
    read = entry_reader(vm)

    def entry(node):
        if isinstance(node, dict) and "register" in node:
            span = node["register"]
            return read(("entry", case["register"], span["offset"], span["size"]))
        if isinstance(node, dict) and node_base is not None and "place" in node:
            place = node["place"]
            if place.get("displacement") in (4, 8):
                return read(("memory", place["space"], node_base + place["displacement"], place["size"]))
        return read(node)

    return entry


def _execute(case, item, registers=(), memory=(), seed=0):
    vm = Interpreter(item.unit.observation, constant_space=case["constant"], seed=seed,
                     program=case["program"], image=case["image"], address_bits=case["address_bits"])
    for offset, size, value in registers:
        vm.preset(case["register"], offset, size, value)
    for space, address, size, value in memory:
        vm.preset(space, address, size, value)
    run = vm.run()
    assert run.completed and run.executed and not vm.opaque_opcodes
    return vm, run


def _guarded(record, item, decision, merge, true_successor, false_successor):
    assert not record["truncated"]
    phis = [node for node in record["nodes"] if node["kind"] == "phi" and "condition" in node
            and (node["condition"]["decision"] == decision
                 or node["condition"]["decision"].startswith(decision + ":"))]
    assert phis, (decision, [(node.get("reason"), node.get("condition_fallback"))
                            for node in record["nodes"] if node["kind"] == "phi"])
    ssa = item.normalized.memory_ssa
    for phi in phis:
        condition = phi["condition"]
        assert condition["merge"] == merge
        assert (condition["true_successor"], condition["false_successor"]) == (true_successor, false_successor)
        assert condition["selection"].startswith(f"cfg/{ssa.function_scope.digest.hex()}/{ssa.unit_digest.hex()}/")
        assert condition["operand"]["width"] == 1 and condition["operand"]["parts"]
        assert phi["choices"] == [True, False] and len(phi["alternatives"]) == 2
        assert phi["condition_evaluation"] == "supported"
        for alternative in phi["alternatives"]:
            reference = alternative["definition_ref"]
            definition = ssa.definitions[reference["id"]]
            assert reference == dict(id=reference["id"], scope=ssa.function_scope.digest.hex(),
                                     unit=ssa.unit_digest.hex(), kind=definition.kind.value,
                                     operation=definition.operation_key, write_ordinal=definition.write_ordinal,
                                     span=list(definition.span.canonical_key))
    return {phi["condition"]["selection"] for phi in phis}


@pytest.mark.parametrize("key,decision,merge,true_successor,false_successor,load,stores", (
    (DFB010, "1b1:10472c", "1b1:104740", "1b1:104738", "1b1:10472e", "1b1:104740:1:LOAD",
     {"1b1:104733:2:STORE", "1b1:10473d:2:STORE"}),
    (DFB016, "1b1:10487b", "1b1:10488f", "1b1:104887", "1b1:10487d", "1b1:10488f:1:LOAD",
     {"1b1:104882:2:STORE", "1b1:10488c:2:STORE"}),
))
def test_actual_arm_calls_keep_unconditioned_alternatives(actual_suite09, key, decision, merge,
                                                         true_successor, false_successor, load, stores):
    case = actual_suite09
    item = case["results"][key]
    graph = build_pcode_block_graph(item.unit.observation, item.unit.scopes.function.entry)
    assert graph.unsupported is None
    branch = next(block for block in graph.blocks if block.key == decision)
    assert set(branch.successors) == {true_successor, false_successor}
    action = next(action for action in item.normalized.memory_ssa.actions if action.operation_key == load)
    (definition,) = action.write_definition_ids
    span = item.normalized.memory_ssa.definitions[definition].span
    record = root_record(item.normalized, item.unit,
                         [(item.normalized.memory_graph.definition_nodes[definition], (span,))],
                         declared=item.declared, provenance=case["provenance"][id(item)][1],
                         stitch=StitchContext(case["provenance"]))
    assert not record["truncated"]
    phis = [node for node in record["nodes"] if node["kind"] == "phi"
            and node.get("condition_fallback") == "call on path"]
    assert phis and all("condition" not in node and len(node["alternatives"]) == 2 for node in phis)
    assert all("definition_ref" in part for node in phis for part in node["alternatives"])
    operations = {node.get("key"): node.get("opcode") for node in record["nodes"] if node["kind"] == "op"}
    assert operations[load] == "LOAD" and all(operations[key] == "STORE" for key in stores)
    source = case["results"][SOURCE_C]
    (input_span,) = {span for exit_summary in source.summary.exits for run in exit_summary.runs
                    for span in run.sources if span.object_id.kind.value == "address_space"}
    sink_call = next(call for call, target in item.calls.items() if target == SINK)
    observed = set()
    for seed, value in enumerate((0, 1, 9, 0x7fffffff, 0xffffffff, 0x80000000)):
        vm, run = _execute(case, item, ((0x20, 8, 0x70000000),),
                           ((input_span.object_id.space_key, input_span.start, input_span.size, value),), seed)
        (taken,) = [taken for call, taken in run.branch_decisions if call.startswith(decision + ":")]
        observed.add(bool(taken))
        (state,) = [state for call, state in vm.activation_snapshots.values() if call == sink_call]
        # The selected actual sink body copies these four entry bytes (RDI).
        actual = sum(state[(case["register"], 0x38 + index)] << (8 * index) for index in range(4))
        values = evaluate(record, _entry(case, vm), route="stitched")
        assert values == {(value + delta) & 0xffffffff for delta in (1, 2)}
        assert actual in values
    assert observed == {True, False}


def test_actual_call_free_diamond_keeps_its_join_load_condition(actual_suite10):
    case = actual_suite10
    item = case["results"][PICKER]
    assert not item.calls
    key = "1b1:1081e7:1:LOAD"
    action = next(action for action in item.normalized.memory_ssa.actions if action.operation_key == key)
    (definition,) = action.write_definition_ids
    span = item.normalized.memory_ssa.definitions[definition].span
    assert span.size == 8
    record = root_record(item.normalized, item.unit,
                         [(item.normalized.memory_graph.definition_nodes[definition], (span,))])
    _guarded(record, item, "1b1:1081c9", "1b1:1081e7", "1b1:1081d9", "1b1:1081cb")
    operations = {node.get("key"): node.get("opcode") for node in record["nodes"] if node["kind"] == "op"}
    assert operations[key] == "LOAD"
    assert all(operations[store] == "STORE" for store in ("1b1:1081d2:2:STORE", "1b1:1081e0:2:STORE"))
    observed = set()
    for seed, selector in enumerate((0, 1, 9, 0x7fffffff, 0xffffffff, 0x80000000)):
        vm, run = _execute(case, item, ((0x20, 8, 0x70000000), (0x38, 4, selector)), seed=seed)
        (taken,) = [taken for key, taken in run.branch_decisions if key.startswith("1b1:1081c9:")]
        observed.add(bool(taken))
        # The join LOAD is immediately copied to the actual return register.
        actual = sum(vm._byte(case["register"], index)[0] << (8 * index) for index in range(8))
        for route in ("injected", "stitched"):
            assert evaluate(record, _entry(case, vm), route=route) == {actual}
    assert observed == {True, False}


def test_actual_two_field_exit_records_share_one_decision(actual_suite10):
    case = actual_suite10
    item = case["results"][HELPER]
    records = {record["place"]["start"] - (1 << 64): record
               for record in run_records(item.normalized, item.unit, item.summary)
               if record["place"]["kind"] == "function_relative" and record["place"]["size"] == 4
               and record["place"]["start"] - (1 << 64) in (4, 8)}
    assert set(records) == {4, 8}
    identities = [_guarded(record, item, "1b1:1096bc", "1b1:1096d8", "1b1:1096cc", "1b1:1096be")
                  for record in records.values()]
    assert identities[0] == identities[1] and len(identities[0]) == 1
    node = 0x71000000
    observed = set()
    for seed, selector in enumerate((0, 1, 2, 3)):
        vm, run = _execute(case, item,
                           ((0x20, 8, 0x70000000), (0x38, 8, node), (0x30, 4, 7), (0x10, 4, selector)),
                           ((433, node + 4, 4, 11), (433, node + 8, 4, 29)), seed)
        (taken,) = [taken for key, taken in run.branch_decisions if key.startswith("1b1:1096bc:")]
        observed.add(bool(taken))
        read = _entry(case, vm, node_base=node)
        actual_pair = []
        for displacement in (4, 8):
            actual = sum(vm._byte(433, node + displacement + index)[0] << (8 * index) for index in range(4))
            actual_pair.append(actual)
            for route in ("injected", "stitched"):
                assert evaluate(records[displacement], read, route=route) == {actual}
        assert tuple(actual_pair) == ((11, 7) if selector % 2 == 0 else (7, 29))
    assert observed == {True, False}
