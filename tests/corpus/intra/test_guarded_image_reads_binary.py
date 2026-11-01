"""Original Suite09 DFB201 guarded table, not whole-function completeness.

Set TDO_LOADED_POINTER_DATA to the transported tdo_data_2026-10-30 directory.
Only DFB201 is normalized. The original PE, observation and naming producer
are pinned; no instruction, observation, branch or image byte is replaced.
The existing unresolved and may-alias debts must survive the additive graph.
"""

from collections import Counter
import json
import os
from pathlib import Path

import pytest

from test_loop_memory_read_from_binary import _place
from tdo_v2.configured_naming_contracts import NamingBindingExpectation
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.image_info import ReadOnlyImage, load_image_info
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction


GENERATION = "516591db9d11293c0f0b16323bb276fe9f6dd78a68fa322727d80c05d8e0b376"
IMAGE_SHA = "0bfee71aa95c232b11aeff9c519a74f2165a8b43c4206e73d54bbdaa003fd2ae"
NAMING_SHA = "32cad70d5e9ffeb9f161828a594b89054990a9007984bbdba2ddad5c30ab6e4a"
OBSERVATION = "d39cd113eb457f1dfea76003aa90e47b65f59a1f9dd68e3ee8df46aa6c08544e"
ENTRY, TABLE, MEMORY = 0x140002ec6, 0x140007ff0, 0x1b1
GUARD = "1b1:140002ee0:2:CBRANCH"
GUARD_LOAD, INDEX_LOAD = "1b1:140002edc:1:LOAD", "1b1:140002ee2:1:LOAD"
TABLE_LOAD = "1b1:140002ef4:2:LOAD"
SUCCESS = ("1b1:140002ee0", "1b1:140002ee2")
VALUES = (0xffffaf15, 0xffffaf26, 0xffffaf33, 0xffffaf44, 0xffffaf59)
TARGETS = (0x140002f05, 0x140002f16, 0x140002f23, 0x140002f34, 0x140002f49)


@pytest.fixture(scope="module")
def actual():
    location = os.environ.get("TDO_LOADED_POINTER_DATA")
    if not location:
        pytest.skip("set TDO_LOADED_POINTER_DATA to the sealed original Suite09 data")
    generation = Path(location) / "tdo_bundles3/v2-win-debug-full" / GENERATION
    names = json.loads((generation / "call-names-000074.json").read_bytes())
    # The transported Windows Bundle sealed CRLF producer bytes. Bind to
    # those original bytes explicitly; never rewrite the current producer.
    assert names["exporter_source_sha256"] == NAMING_SHA
    assert names["ghidra_version"] == "12.0.4"
    binding = NamingBindingExpectation(bytes.fromhex(NAMING_SHA), "12.0.4")
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        unit = next(row.unit for row in session.iter_functions()
                    if row.unit.scopes.function.entry.byte_offset == ENTRY)
    assert unit.scopes.function.observation_digest.hex() == OBSERVATION
    assert unit.scopes.program.evidence.executable_sha256.hex() == IMAGE_SHA
    assert unit.scopes.program.evidence.translation_namespace.language_id == "x86:LE:64:default"
    info = load_image_info(generation)
    assert info is not None
    readonly = ReadOnlyImage(generation, info)
    return unit, info, readonly


def _actions(normalized):
    return {action.operation_key: i for i, action in enumerate(normalized.memory_ssa.actions)}


def _operations(unit):
    return {f"{ins.address.space_id:x}:{ins.address.byte_offset:x}:{i}:{op.opcode}": op
            for ins in unit.observation.instructions for i, op in enumerate(ins.operations)}


def _state_read(normalized, key):
    action = _actions(normalized)[key]
    read, = [row for row in normalized.memory_ssa.reads if row.action_id == action
             and row.span.object_id.kind.value == "function_relative"]
    assert read.span.size == 4
    return read


def _original_chain(normalized):
    """Check actual SSA value edges, not control/alias paths between op keys."""
    ssa, graph, actions = normalized.memory_ssa, normalized.dependencies, _actions(normalized)
    chain = (TABLE_LOAD, "1b1:140002ef4:3:COPY", "1b1:140002ef4:4:INT_ZEXT",
             "1b1:140002ef7:0:INT_SEXT", "1b1:140002f00:2:INT_ADD", "1b1:140002f03:0:BRANCHIND")
    for producer, consumer in zip(chain, chain[1:]):
        identifier, = ssa.actions[actions[producer]].write_definition_ids
        source = normalized.memory_graph.definition_nodes[identifier]
        assert any(t == source and edge.kind == "memory_defines"
                   for _, t, edge in graph.out_edges(graph.node_for_key("op:" + producer)))
        fragments = [fragment for read in ssa.reads if read.action_id == actions[consumer]
                     for fragment in read.fragments if identifier in fragment.definition_ids]
        assert fragments
        for fragment in fragments:
            assert any(t == graph.node_for_key("op:" + consumer) and edge.kind == "memory_read"
                       and edge.span == fragment.span for _, t, edge in graph.out_edges(source))


def _edge_multiset(graph):
    return Counter((graph.node(source).key, graph.node(target).key, edge)
                   for source, target, edge in graph.weighted_edges())


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_original_five_guarded_table_candidates_and_value_chain(actual, monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    unit, info, readonly = actual
    normalized = FunctionNormalizer().normalize(unit, readonly_image=readonly)
    assert isinstance(normalized, NormalizedFunction)
    binding = normalized.memory_graph.image_reads
    assert binding is not None
    row, = binding.plan.reads
    assert row.operation_key == TABLE_LOAD and row.guard == GUARD
    assert row.success_edge == SUCCESS
    assert INDEX_LOAD in row.reloads
    assert len(row.candidates) == len(binding.candidate_nodes) == len(binding.source_nodes) == len(binding.constant_nodes) == 5
    assert tuple(candidate.selector for candidate in row.candidates) == tuple(range(5))
    assert tuple(candidate.value for candidate in row.candidates) == VALUES
    operations, ssa, graph = _operations(unit), normalized.memory_ssa, normalized.dependencies
    actions = _actions(normalized)
    assert row.output_span == _place(operations[TABLE_LOAD].output, unit)
    address = _place(operations[TABLE_LOAD].inputs[1], unit)
    assert ssa.definitions[row.address_definition_id].operation_key == "1b1:140002ef4:1:INT_ADD"
    assert ssa.definitions[row.address_definition_id].span == address
    selector = ssa.definitions[row.selector_definition_id]
    assert selector.span.contains(row.selector_span) and row.selector_span.size == 4
    assert selector.operation_key in (GUARD_LOAD, "1b1:140002edc:2:COPY")
    # Guard and index are two original LOADs, not a fictional single COPY.
    first, second = (_state_read(normalized, key) for key in (GUARD_LOAD, INDEX_LOAD))
    assert first.span == second.span
    assert ssa.actions[actions[GUARD_LOAD]].write_definition_ids != ssa.actions[actions[INDEX_LOAD]].write_definition_ids
    guard_instruction = next(ins for ins in unit.observation.instructions if ins.address.byte_offset == 0x140002ee0)
    assert guard_instruction.fallthrough.byte_offset == 0x140002ee2
    assert tuple(target.byte_offset for target in guard_instruction.flow_targets) == (0x140002f55,)
    # The branch is !(unsigned(state)<4 || state-4==0): success is <=4.
    assert operations["1b1:140002edc:3:INT_LESS"].inputs[1].coordinate.byte_offset == 4
    assert operations["1b1:140002edc:5:INT_SUB"].inputs[1].coordinate.byte_offset == 4
    assert operations["1b1:140002ee0:0:BOOL_OR"].opcode == "BOOL_OR"
    assert operations["1b1:140002ee0:1:BOOL_NEGATE"].opcode == "BOOL_NEGATE"
    assert operations["1b1:140002ee5:0:INT_MULT"].inputs[1].coordinate.byte_offset == 4
    base, = operations["1b1:140002eed:0:COPY"].inputs
    assert base.kind.name == "CONSTANT" and base.coordinate.byte_offset == TABLE
    for candidate, node, source, constant in zip(row.candidates, binding.candidate_nodes, binding.source_nodes,
                                                  binding.constant_nodes, strict=True):
        span = candidate.span
        assert span.object_id.kind.value == "address_space" and span.object_id.space_key == MEMORY
        assert span.start == TABLE + 4 * candidate.selector and span.size == 4
        block = info.block_at(MEMORY, span.start, span.size)
        assert block.read and not block.write and not block.volatile and block.initialized
        assert readonly.value(MEMORY, span.start, span.size) == candidate.value
        assert graph.node(node).kind is graph.node(source).kind is NodeKind.EFFECT
        assert graph.node(source).label == "readonly_image_bytes"
        assert graph.node(constant).kind is NodeKind.CONSTANT
        constant_space = next(space.space_id for space in unit.scopes.program.evidence.address_spaces
                              if space.is_constant_space)
        assert constant == graph.node_for_key(f"constant:constant:{constant_space:x}:{candidate.value:x}:4")
        assert any(s == constant and edge.kind == "guarded_image_value" and edge.span == span
                   for s, _, edge in graph.in_edges(source))
        assert any(s == source and edge.kind == "guarded_image_value" and edge.span == span
                   for s, _, edge in graph.in_edges(node))
        assert any(t == graph.node_for_key("op:" + TABLE_LOAD) and edge.kind == "guarded_image_read"
                   and edge.span == row.output_span for _, t, edge in graph.out_edges(node))
        assert any(s == normalized.memory_graph.definition_nodes[row.selector_definition_id]
                   and edge.kind == "guarded_image_selector" and edge.span == row.selector_span
                   for s, _, edge in graph.in_edges(node))
        assert any(s == graph.node_for_key("op:" + GUARD) and edge.kind == "guarded_image_witness"
                   for s, _, edge in graph.in_edges(node))
        assert any(s == normalized.memory_graph.definition_nodes[row.address_definition_id]
                   and edge.kind == "guarded_image_witness" for s, _, edge in graph.in_edges(node))
        for reload in row.reloads:
            assert any(s == graph.node_for_key("op:" + reload) and edge.kind == "guarded_image_witness"
                       for s, _, edge in graph.in_edges(node))
        signed = int.from_bytes(candidate.value.to_bytes(4, "little"), "little", signed=True)
        assert TABLE + signed == TARGETS[candidate.selector]
    indirect = next(ins for ins in unit.observation.instructions if ins.address.byte_offset == 0x140002f03)
    assert indirect.fallthrough is None
    assert tuple(target.byte_offset for target in indirect.flow_targets) == TARGETS
    _original_chain(normalized)


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_readonly_off_has_no_table_value_authority_and_original_debts_survive(actual, monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    unit, _, readonly = actual
    off = FunctionNormalizer().normalize(unit)
    on = FunctionNormalizer().normalize(unit, readonly_image=readonly)
    assert isinstance(off, NormalizedFunction) and isinstance(on, NormalizedFunction)
    assert off.memory_graph.image_reads is None and on.memory_graph.image_reads is not None
    assert on.memory_ssa == off.memory_ssa and on.memory_unit == off.memory_unit
    assert on.may_alias_reads == off.may_alias_reads and on.call_clobber_reads == off.call_clobber_reads
    assert any(off.memory_ssa.actions[row.action_id].operation_key == TABLE_LOAD for row in off.memory_ssa.unresolved_reads)
    assert any(row.operation_key == TABLE_LOAD and row.unknown_address for row in off.may_alias_reads)
    assert not any(edge.kind.startswith("guarded_image_") for _, _, edge in off.dependencies.weighted_edges())
    assert not (_edge_multiset(off.dependencies) - _edge_multiset(on.dependencies))
    _original_chain(off)
    _original_chain(on)
