"""All tracked call-state bytes share existing SSA definitions and arenas."""

from dataclasses import replace

import pytest

from memory_units import OBJECTS
from test_call_register_snapshots import CALL, _engines, _reg, _unit, _write
from tdo_v2 import memory_ssa
from tdo_v2.call_entry_graph import state_sources
from tdo_v2.memory_contracts import LocalMemoryBlock, LocalStorageAction, MemoryDefinitionKind
from tdo_v2.span_geometry import ByteSpan


def test_memory_snapshot_preserves_partial_writes_kills_and_original_terminal_ids():
    memory = ByteSpan(OBJECTS[2], 0x4000, 8)
    unit = _unit(LocalMemoryBlock('entry', (), (
        _write('whole', memory), _write('partial', ByteSpan(memory.object_id, memory.start + 2, 2)),
        _write('kill', ByteSpan(memory.object_id, memory.start + 6, 1), kill=True),
        LocalStorageAction(CALL), _write('later', memory),
    )), terminals=('entry',))
    result = _engines(unit)
    (state,) = result.call_memory_states
    parts = state_sources(result, state, memory)
    assert [part.span.size for part in parts] == [2, 2, 2, 1, 1]
    assert [result.definitions[part.definition_ids[0]].operation_key for part in parts] == \
           ['whole', 'partial', 'whole', 'kill', 'whole']
    assert result.definitions[parts[3].definition_ids[0]].kind is MemoryDefinitionKind.KILL
    original = memory_ssa._call_boundaries
    try:
        memory_ssa._call_boundaries = lambda unit: {}
        baseline = _engines(unit)
    finally:
        memory_ssa._call_boundaries = original
    assert replace(result, call_register_snapshots=(), call_memory_states=(), call_state_nodes=()) == baseline


def test_branch_loop_memory_sources_reuse_raw_defs_without_new_joins():
    memory = ByteSpan(OBJECTS[2], 0x4000, 8)
    unit = _unit(
        LocalMemoryBlock('entry', (), (_write('initial', memory),)),
        LocalMemoryBlock('loop', ('entry', 'loop'), (LocalStorageAction(CALL), _write('back', memory))),
    )
    result = _engines(unit)
    (state,) = result.call_memory_states
    (part,) = state_sources(result, state, memory)
    assert {result.definitions[index].operation_key for index in part.definition_ids} == {'initial', 'back'}
    assert not result.reads and not result.joins and not result.flow_edges


def test_identical_call_states_share_roots_and_absent_bytes_remain_absent():
    memory = ByteSpan(OBJECTS[2], 0x4000, 8)
    unit = _unit(LocalMemoryBlock('entry', (), (
        _write('value', memory), LocalStorageAction(CALL), LocalStorageAction('1:1200:0:CALLIND'),
    )))
    result = _engines(unit)
    first, second = result.call_memory_states
    assert first.root_node_id == second.root_node_id
    assert len(result.call_state_nodes) == 1
    assert first.root_node_id == 0  # a real root ID, never the empty-state sentinel
    assert state_sources(result, first, _reg()) == ()
    assert state_sources(result, first, ByteSpan(memory.object_id, 0x5000, 8)) == ()


def test_call_state_validation_rejects_missing_roots_wrong_phase_and_orphan_nodes():
    result = _engines(_unit(LocalMemoryBlock('entry', (), (_write('value', _reg()), LocalStorageAction(CALL)))))
    (state,) = result.call_memory_states
    with pytest.raises(ValueError, match='out of range'):
        replace(result, call_memory_states=(replace(state, root_node_id=len(result.call_state_nodes)),))
    with pytest.raises(ValueError, match='boundaries must agree'):
        replace(result, call_memory_states=(replace(state, first_action_key=CALL + '~wrong'),))
    with pytest.raises(ValueError, match='reachable'):
        replace(result, call_memory_states=())


def test_persistent_observation_updates_partial_rewrites_but_never_fills_atom_gaps():
    memory = ByteSpan(OBJECTS[2], 0x4000, 8)
    distant = ByteSpan(OBJECTS[2], 0x4100, 1)
    unit = _unit(LocalMemoryBlock('entry', (), (
        _write('whole', memory), _write('distant', distant), LocalStorageAction(CALL),
        _write('partial', ByteSpan(memory.object_id, memory.start + 2, 2)),
        _write('second', ByteSpan(memory.object_id, memory.start + 2, 1), kill=True),
        LocalStorageAction('1:1200:0:CALLIND'), _write('not-observed', memory),
    )), terminals=('entry',))
    result = _engines(unit)
    first, second = result.call_memory_states
    assert {result.definitions[index].operation_key for part in state_sources(result, first, memory)
            for index in part.definition_ids} == {'whole'}
    parts = state_sources(result, second, memory)
    assert [part.span.size for part in parts] == [2, 1, 1, 4]
    assert [result.definitions[part.definition_ids[0]].operation_key for part in parts] == \
           ['whole', 'second', 'partial', 'whole']
    assert state_sources(result, second, ByteSpan(memory.object_id, 0x4080, 1)) == ()
    assert {result.definitions[index].operation_key for part in state_sources(result, second, distant)
            for index in part.definition_ids} == {'distant'}
    assert all(result.definitions[index].operation_key != 'not-observed'
               for node in result.call_state_nodes for index in node.definition_ids)


def test_many_call_states_share_paths_instead_of_copying_the_whole_state():
    atoms, calls = 128, 16
    actions = [_write(f'initial-{index}', ByteSpan(OBJECTS[2], 0x4000 + 8 * index, 8))
               for index in range(atoms)]
    for index in range(calls):
        actions.extend((_write(f'update-{index}', ByteSpan(OBJECTS[2], 0x4000 + 8 * index, 8)),
                        LocalStorageAction(f'1:{0x10000 + index:x}:0:CALL')))
    result = _engines(_unit(LocalMemoryBlock('entry', (), tuple(actions))))
    assert len(result.call_memory_states) == calls
    assert len(result.call_state_nodes) <= atoms + calls * atoms.bit_length()
    assert all(node.stop_atom == node.start_atom + 1 for node in result.call_state_nodes)


def test_units_without_calls_do_not_construct_the_observation_arena(monkeypatch):
    def forbidden(*args):
        raise AssertionError('a call-free unit must not seed an observer')

    monkeypatch.setattr(memory_ssa, '_CallStateArena', forbidden)
    result = _engines(_unit(LocalMemoryBlock('entry', (), (_write('value', _reg()),)), terminals=('entry',)))
    assert not result.call_state_nodes and not result.call_memory_states


def test_zero_atom_call_states_pin_none_not_node_zero():
    result = _engines(_unit(LocalMemoryBlock('entry', (), (
        LocalStorageAction(CALL), LocalStorageAction('1:1200:0:CALLIND'),
    )), terminals=('entry',)))
    assert not result.atomic_spans and not result.call_state_nodes
    assert len(result.call_memory_states) == 2
    assert all(state.root_node_id is None for state in result.call_memory_states)


def test_multiple_block_seeds_reuse_the_original_loop_union_without_demanding_joins():
    memory = ByteSpan(OBJECTS[2], 0x4000, 4)
    unit = _unit(
        LocalMemoryBlock('entry', (), (_write('initial', memory), LocalStorageAction(CALL))),
        LocalMemoryBlock('left', ('entry',), (_write('left-byte', ByteSpan(memory.object_id, 0x4002, 1)),)),
        LocalMemoryBlock('right', ('entry',), ()),
        LocalMemoryBlock('merge', ('left', 'right', 'merge'), (
            LocalStorageAction('1:1200:0:CALLIND'), _write('back-byte', ByteSpan(memory.object_id, 0x4001, 1)),
        )),
    )
    result = _engines(unit)
    first, merged = result.call_memory_states
    assert {result.definitions[index].operation_key for part in state_sources(result, first, memory)
            for index in part.definition_ids} == {'initial'}
    sources = {part.span.start: {result.definitions[index].operation_key for index in part.definition_ids}
               for part in state_sources(result, merged, memory)}
    assert sources[0x4001] == {'initial', 'back-byte'}
    assert sources[0x4002] == {'initial', 'left-byte'}
    assert not result.joins and not result.reads and not result.flow_edges
