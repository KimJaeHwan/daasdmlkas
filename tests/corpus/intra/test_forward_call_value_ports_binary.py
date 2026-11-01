"""Original DFB071 body-to-global callback transport, not debt-free completion.

Only five original bodies are analyzed. With the default stack/global policy
the recovered scalar candidate must NOT authorize the indirect call: its two
original memory alternatives remain. The named separation mode is a distinct,
explicitly conditional comparison, not evidence for the default mode.
"""

import json
import os
from pathlib import Path

import pytest

from tdo_v2._call_value_ports import scalar_call_rows
from tdo_v2.configured_naming_contracts import NamingBindingExpectation
from tdo_v2.forward import forward_facts
from tdo_v2.image_info import load_image_info
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.interprocedural import _callind_sites, _indirect_targets, analyze_units, function_key
from tdo_v2.relative_memory import constant_values


GENERATION = "516591db9d11293c0f0b16323bb276fe9f6dd78a68fa322727d80c05d8e0b376"
IMAGE_SHA = "0bfee71aa95c232b11aeff9c519a74f2165a8b43c4206e73d54bbdaa003fd2ae"
NAMING_SHA = "32cad70d5e9ffeb9f161828a594b89054990a9007984bbdba2ddad5c30ab6e4a"
CASE, REGISTER, TARGET = "1b1:14000280b", "1b1:1400027d9", "1b1:1400027ef"
CALL = "1b1:140002825:2:CALL"
INDIRECT, SNAPSHOT = "1b1:140002842:3:CALLIND", "1b1:140002842:0:COPY"
GLOBAL, READS = 0x14000d120, ("1b1:14000282a:0:COPY", "1b1:140002836:0:COPY")
PINS = {
    CASE: (55, "9832016fd6ed82b5d23a4e18103c4f0fc2212f41d4c852917182ccdd6de11fe5"),
    REGISTER: (104, "3c6e97508b7f922fa6b49a39dd1d0986beddcab0a9f7bdad46236ff7466bc611"),
    TARGET: (105, "2c54d24858f506b4f401c3e86d6a677a48e9d40ad611154d6b2da9a786474285"),
    "1b1:1400019d0": (75, "7263cffceb0c4a4860e85c0c12818f40d2c352f23ff7c639e946dfd0ff2966f3"),
    "1b1:140001a27": (76, "4b2fbad5fdff39b84dcdf0b1293d187b692845fd39154f35cd9aa036f18ef33e"),
}


@pytest.fixture(scope="module")
def actual():
    location = os.environ.get("TDO_LOADED_POINTER_DATA")
    if not location:
        pytest.skip("set TDO_LOADED_POINTER_DATA to the original sealed Suite09 data")
    generation = Path(location) / "tdo_bundles3/v2-win-debug-full" / GENERATION
    for key, (index, _) in PINS.items():
        names = json.loads((generation / f"call-names-{index:06d}.json").read_bytes())
        assert names["exporter_source_sha256"] == NAMING_SHA and names["ghidra_version"] == "12.0.4"
        assert names["transport"]["function_entry"]["byte_offset"] == int(key.split(":")[1], 16)
        if key == CASE:
            aliases = {alias["value"] for call in names["calls"] for target in call["targets"]
                       for alias in target["aliases"]}
            assert {"dfb_source_A", "dfb_register_callback"} <= aliases
    binding = NamingBindingExpectation(bytes.fromhex(NAMING_SHA), "12.0.4")
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        units = {function_key(row.unit.scopes.function.entry): row.unit for row in session.iter_functions()
                 if function_key(row.unit.scopes.function.entry) in PINS}
    assert set(units) == set(PINS)
    for key, unit in units.items():
        assert unit.scopes.function.observation_digest.hex() == PINS[key][1]
        assert unit.scopes.program.evidence.executable_sha256.hex() == IMAGE_SHA
    info = load_image_info(generation)
    assert info is not None
    return units, info


def _analyze(actual, monkeypatch, engine, forward, *, separation):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_FORWARD", "1" if forward else "0")
    units, info = actual
    results = analyze_units(tuple(units.values()), image_info=info,
                            assume_globals_disjoint_from_stack=separation)
    assert set(results) == set(PINS)
    assert all(not result.declared for result in results.values())
    return results


def _link(normalized, producer, consumer, width):
    ssa, graph = normalized.memory_ssa, normalized.dependencies
    action = next(i for i, action in enumerate(ssa.actions) if action.operation_key == consumer)
    fragments = [(fragment, identifier) for read in ssa.reads if read.action_id == action
                 for fragment in read.fragments for identifier in fragment.definition_ids
                 if ssa.definitions[identifier].operation_key == producer]
    assert sum(fragment.span.size for fragment, _ in fragments) == width
    for fragment, identifier in fragments:
        definition = normalized.memory_graph.definition_nodes[identifier]
        assert any(target == definition and edge.kind == "memory_defines"
                   for _, target, edge in graph.out_edges(graph.node_for_key("op:" + producer)))
        assert any(target == graph.node_for_key("op:" + consumer) and edge.kind == "memory_read"
                   and edge.span == fragment.span for _, target, edge in graph.out_edges(definition))


def _original_transport(item):
    normalized = item.normalized
    effect = dict(normalized.proven_call_effects)[CALL]
    run, = [run for run in effect.memory_runs if run.write.span is not None
            and run.write.span.start == GLOBAL]
    assert run.write.size == 8 and run.value[0] == "same_reg"
    assert run.value[1].start == 8 and run.value[1].size == 8 and run.value[2] is False
    assert not run.conditions and not effect.writer_conditions
    port = scalar_call_rows(normalized)[CALL + "~2"]
    assert port.width == 8 and port.row[:2] == ("reg", CALL + "~in2")
    assert dict(normalized.call_value_inputs)[CALL + "~in2"] == 2
    _link(normalized, "1b1:140002822:0:COPY", CALL + "~in2", 8)
    _link(normalized, CALL + "~in2", CALL + "~2", 1)
    for reader in READS:
        _link(normalized, CALL + "~2", reader, 8)
    _link(normalized, READS[1], SNAPSHOT, 8)
    call, copy, value = next(_callind_sites(item.unit))
    assert (call, copy) == (INDIRECT, SNAPSHOT)
    request = copy, value
    assert constant_values(normalized, item.unit.observation, [request], addresses=True) == {
        request: int(TARGET.split(":")[1], 16)}


@pytest.mark.parametrize("engine", ("sparse", "dense"))
@pytest.mark.parametrize("forward", (False, True))
def test_default_policy_recovers_callback_candidate_without_clearing_original_global_aliases(actual, monkeypatch,
                                                                                            engine, forward):
    results = _analyze(actual, monkeypatch, engine, forward, separation=False)
    item = results[CASE]
    _original_transport(item)
    normalized, graph = item.normalized, item.normalized.dependencies
    assert INDIRECT not in item.calls and INDIRECT not in item.multi_calls
    assert not _indirect_targets(item, results)
    assert not any(fact.operation == INDIRECT for fact in forward_facts(normalized, item.unit))
    for reader in READS:
        claim, debt = next((claim, node) for claim, node in zip(normalized.may_alias_reads,
                                                              normalized.may_alias_nodes)
                           if claim.operation_key == reader)
        assert set(claim.writers) == {CALL + "~3", CALL + "~push"}
        assert debt in graph.backward_reachable((graph.node_for_key("op:" + reader),))
    assert all(label != "globals-disjoint-from-stack" for label, _, _ in normalized.premise_uses)


@pytest.mark.parametrize("engine", ("sparse", "dense"))
@pytest.mark.parametrize("forward", (False, True))
def test_named_stack_global_separation_is_a_distinct_conditional_callback_resolution(actual, monkeypatch,
                                                                                  engine, forward):
    results = _analyze(actual, monkeypatch, engine, forward, separation=True)
    item = results[CASE]
    _original_transport(item)
    normalized = item.normalized
    assert item.calls[INDIRECT] == TARGET
    assert dict(normalized.proven_call_effects)[INDIRECT].callee == TARGET
    assert not any(row.operation_key in READS for row in normalized.may_alias_reads)
    fact, = [fact for fact in forward_facts(normalized, item.unit) if fact.operation == INDIRECT]
    assert fact.claim.single_number() == int(TARGET.split(":")[1], 16)
    assert "globals-disjoint-from-stack" in fact.requires
    assert any(label == "globals-disjoint-from-stack" for label, _, _ in normalized.premise_uses)
