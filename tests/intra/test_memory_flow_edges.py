"""Predecessor evidence observes the existing memory SSA fixed point only."""

from dataclasses import replace
from unittest.mock import patch

import pytest

from memory_units import FUNCTION_SCOPE, OBJECTS
from tdo_v2 import memory_ssa
from tdo_v2._sparse_dataflow import DominatorGraph
from tdo_v2.memory_contracts import (
    LOCAL_MEMORY_CONTRACT_VERSION, LocalMemoryBlock, LocalMemoryUnit,
    LocalStorageAction, MemoryDefinitionKind, MemoryFlowEdge, MemoryWriteMode,
)
from tdo_v2.model import ByteSpan


SPAN = ByteSpan(OBJECTS[0], 0, 8)


def _write(key, span=SPAN, mode=MemoryWriteMode.DATA):
    return LocalStorageAction(key, writes=(span,), write_mode=mode)


def _read(key, span=SPAN):
    return LocalStorageAction(key, reads=(span,))


def _unit(blocks, terminals=("merge",)):
    return LocalMemoryUnit(LOCAL_MEMORY_CONTRACT_VERSION, FUNCTION_SCOPE, "entry", tuple(blocks),
                           terminals, effect_evidence_digest=b"\x04" * 32)


def _nested():
    return _unit((
        LocalMemoryBlock("entry", (), (_write("prefix"),)),
        LocalMemoryBlock("left", ("entry",), (_write("left-write"),)),
        LocalMemoryBlock("right", ("entry",), ()),
        LocalMemoryBlock("right-write", ("right",), (_write("right-write"),)),
        LocalMemoryBlock("right-keep", ("right",), ()),
        LocalMemoryBlock("merge", ("left", "right-write", "right-keep"), (_read("result"),)),
    ))


@pytest.fixture(params=("dense", "dense-unchained", "sparse"))
def engine(request):
    return memory_ssa._ENGINES[request.param]


def _operations(result, definitions):
    return tuple(result.definitions[i].operation_key for i in definitions)


def test_nested_three_way_flow_uses_existing_final_definition_ids(engine):
    result = engine(_nested())
    assert result.contract_version == LOCAL_MEMORY_CONTRACT_VERSION == 3
    assert [(edge.span, edge.predecessor_key, edge.block_key,
             _operations(result, edge.definition_ids)) for edge in result.flow_edges] == [
        (SPAN, "left", "merge", ("left-write",)),
        (SPAN, "right-keep", "merge", ("prefix",)),
        (SPAN, "right-write", "merge", ("right-write",)),
    ]
    assert len(result.joins) == 1
    assert set(result.joins[0].source_definition_ids) == {
        i for edge in result.flow_edges for i in edge.definition_ids
    }


def test_sequential_partial_kill_retains_each_predecessors_raw_union(engine):
    low = ByteSpan(SPAN.object_id, 0, 4)
    high = ByteSpan(SPAN.object_id, 4, 4)
    unit = _unit((
        LocalMemoryBlock("entry", (), ()),
        LocalMemoryBlock("left", ("entry",), (_write("left-write"),)),
        LocalMemoryBlock("right", ("entry",), (_write("right-write"),)),
        LocalMemoryBlock("first", ("left", "right"), ()),
        LocalMemoryBlock("kill", ("first",), (_write("kill-write", low, MemoryWriteMode.KILL),)),
        LocalMemoryBlock("keep", ("first",), ()),
        LocalMemoryBlock("merge", ("kill", "keep"), (_read("result"),)),
    ))
    result = engine(unit)
    second = [edge for edge in result.flow_edges if edge.block_key == "merge"]
    assert [(edge.span, edge.predecessor_key, _operations(result, edge.definition_ids))
            for edge in second] == [
        (low, "keep", ("left-write", "right-write")),
        (low, "kill", ("kill-write",)),
    ]
    assert result.definitions[second[1].definition_ids[0]].kind is MemoryDefinitionKind.KILL
    assert {edge.span for edge in result.flow_edges if edge.block_key == "first"} == {low, high}


def test_flow_spans_do_not_bridge_disjoint_parts_of_one_atom_class(engine):
    middle = ByteSpan(SPAN.object_id, 2, 2)
    unit = _unit((
        LocalMemoryBlock("entry", (), (_write("middle", middle),)),
        LocalMemoryBlock("left", ("entry",), (_write("left-write"),)),
        LocalMemoryBlock("right", ("entry",), (_write("right-write"),)),
        LocalMemoryBlock("merge", ("left", "right"), (_read("result"),)),
    ))
    result = engine(unit)
    assert len(result.flow_edges) == 6
    assert {edge.span for edge in result.flow_edges} == {
        ByteSpan(SPAN.object_id, 0, 2), middle, ByteSpan(SPAN.object_id, 4, 4),
    }
    # Read fragmentation still coalesces equal values across atom classes.
    assert len(result.joins) == 1
    assert result.definitions[result.joins[0].join_definition_id].span == SPAN


def test_entry_backedge_has_no_invented_external_predecessor(engine):
    unit = _unit((
        LocalMemoryBlock("entry", ("body",), (_read("loop-read"),)),
        LocalMemoryBlock("body", ("entry",), (_write("loop-write"),)),
        LocalMemoryBlock("merge", ("entry",), (_read("result"),)),
    ))
    result = engine(unit)
    assert [(edge.predecessor_key, edge.block_key, _operations(result, edge.definition_ids))
            for edge in result.flow_edges] == [("body", "entry", ("loop-write",))]
    assert any(result.definitions[i].kind is MemoryDefinitionKind.ENTRY
               for join in result.joins for i in join.source_definition_ids)


def test_unambiguous_and_unsolved_classes_have_no_flow_rows(engine):
    unit = _unit((
        LocalMemoryBlock("entry", (), (_write("prefix"),)),
        LocalMemoryBlock("left", ("entry",), ()),
        LocalMemoryBlock("right", ("entry",), ()),
        LocalMemoryBlock("merge", ("left", "right"), (_read("result"),)),
    ))
    assert engine(unit).flow_edges == ()
    unused = _unit((
        LocalMemoryBlock("entry", (), ()),
        LocalMemoryBlock("left", ("entry",), (_write("left-write"),)),
        LocalMemoryBlock("right", ("entry",), (_write("right-write"),)),
        LocalMemoryBlock("merge", ("left", "right"), ()),
    ), terminals=())
    assert engine(unused).flow_edges == ()


def test_optional_capture_does_not_change_any_original_ssa_field():
    unit = _nested()
    expected = memory_ssa._ENGINES["sparse"](unit)
    solve = DominatorGraph.solve

    def without_capture(self, writes, needed, *, exit_of_write, entry_value, capture_phi=None):
        return solve(self, writes, needed, exit_of_write=exit_of_write, entry_value=entry_value)

    with patch.object(DominatorGraph, "solve", without_capture):
        original = memory_ssa._ENGINES["sparse"](unit)
    assert original.flow_edges == ()
    assert replace(expected, flow_edges=()) == original
    with patch.object(memory_ssa, "_dense_flow_edges", return_value=()):
        assert memory_ssa._ENGINES["dense"](unit) == original


def test_flow_edge_contract_rejects_noncanonical_and_nonraw_evidence():
    result = memory_ssa._ENGINES["sparse"](_nested())
    edge = result.flow_edges[0]
    with pytest.raises(ValueError, match="sorted and unique"):
        replace(result, flow_edges=(edge, edge))
    with pytest.raises(ValueError, match="raw definitions"):
        replace(result, flow_edges=(replace(edge, definition_ids=(result.joins[0].join_definition_id,)),))
    with pytest.raises(ValueError, match="atomic spans"):
        replace(result, flow_edges=(replace(edge, span=ByteSpan(SPAN.object_id, 1, 2)),))
    with pytest.raises(ValueError, match="at least one"):
        MemoryFlowEdge(SPAN, "left", "merge", ())
