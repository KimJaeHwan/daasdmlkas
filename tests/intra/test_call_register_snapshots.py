"""Call-boundary observations reuse raw SSA state, without adding reads/JOINs."""

from dataclasses import replace

import pytest

from memory_units import FUNCTION_SCOPE, OBJECTS, random_unit
from synthetic import RAX, RCX, RSP, FunctionBuilder, add, const, program_units, reg
from tdo_v2 import memory_ssa
from tdo_v2.interprocedural import analyze_units
from tdo_v2.memory_contracts import (
    LOCAL_MEMORY_CONTRACT_VERSION, CallBoundaryRegisterState, LocalMemoryBlock, LocalMemoryUnit,
    LocalStorageAction, MemoryDefinitionKind, MemoryWriteMode, RegisterStateFragment,
)
from tdo_v2.span_geometry import ByteSpan


CALL = "1:1100:2:CALL"


def _reg(start=0, size=8):
    return ByteSpan(OBJECTS[0], start, size)


def _write(key, span, *, kill=False):
    return LocalStorageAction(key, writes=(span,),
                              write_mode=MemoryWriteMode.KILL if kill else MemoryWriteMode.DATA)


def _unit(*blocks, terminals=()):
    return LocalMemoryUnit(LOCAL_MEMORY_CONTRACT_VERSION, FUNCTION_SCOPE, "entry", tuple(blocks),
                           terminals, effect_evidence_digest=b"\x03" * 32)


def _engines(unit):
    results = [memory_ssa._ENGINES[name](unit) for name in ("dense", "dense-unchained", "sparse")]
    assert results[0] == results[1] == results[2]
    return results[0]


def _sources(result, state, byte):
    fragment = next(item for item in state.fragments if item.span.start <= byte < item.span.end)
    return {result.definitions[identifier].operation_key for identifier in fragment.definition_ids}


def test_snapshot_is_before_the_first_staging_action_and_preserves_partial_writes_and_kills():
    unique, memory = ByteSpan(OBJECTS[1], 0, 8), ByteSpan(OBJECTS[2], 0x4000, 8)
    unit = _unit(LocalMemoryBlock("entry", (), (
        _write("full", _reg()), _write("partial", _reg(2, 2)), _write("kill", _reg(6, 1), kill=True),
        _write("memory", memory), _write(f"{CALL}~in0", unique),
        _write(f"{CALL}~0", _reg()), LocalStorageAction(CALL),
    )), terminals=("entry",))
    result = _engines(unit)
    (state,) = result.call_register_snapshots
    assert (state.boundary_key, state.block_key, state.first_action_key) == (CALL, "entry", f"{CALL}~in0")
    assert all(fragment.span.object_id == OBJECTS[0] for fragment in state.fragments)
    assert {_sources(result, state, byte).pop() for byte in (0, 1, 4, 5, 7)} == {"full"}
    assert _sources(result, state, 2) == _sources(result, state, 3) == {"partial"}
    assert _sources(result, state, 6) == {"kill"}
    assert not result.joins and not result.reads
    assert all(identifier < len(result.definitions) for fragment in state.fragments
               for identifier in fragment.definition_ids)


def test_ambiguous_snapshot_retains_raw_sources_without_demanding_a_join_or_read():
    unit = _unit(
        LocalMemoryBlock("entry", (), ()),
        LocalMemoryBlock("left", ("entry",), (_write("left-value", _reg()),)),
        LocalMemoryBlock("right", ("entry",), (_write("right-value", _reg()),)),
        LocalMemoryBlock("merge", ("left", "right"), (LocalStorageAction(f"{CALL}~ld0"),
                                                       _write(f"{CALL}~0", _reg()), LocalStorageAction(CALL))),
    )
    result = _engines(unit)
    (state,) = result.call_register_snapshots
    assert state.block_key == "merge" and state.first_action_key == f"{CALL}~ld0"
    assert _sources(result, state, 0) == {"left-value", "right-value"}
    assert not result.joins and not result.reads and not result.flow_edges
    assert all(result.definitions[identifier].kind is not MemoryDefinitionKind.JOIN
               for fragment in state.fragments for identifier in fragment.definition_ids)

    # The complete old result, including raw definitions and flow edges, is
    # identical when only the additive observation is disabled.
    original = memory_ssa._call_boundaries
    try:
        memory_ssa._call_boundaries = lambda unit: {}
        baseline = _engines(unit)
    finally:
        memory_ssa._call_boundaries = original
    assert replace(result, call_register_snapshots=()) == baseline


def test_loop_snapshot_observes_the_existing_fixed_point_before_the_local_write():
    unit = _unit(
        LocalMemoryBlock("entry", (), (_write("initial", _reg()),)),
        LocalMemoryBlock("loop", ("entry", "loop"),
                         (LocalStorageAction(f"{CALL}~in0"), LocalStorageAction(CALL), _write("back", _reg()))),
    )
    result = _engines(unit)
    (state,) = result.call_register_snapshots
    assert _sources(result, state, 0) == {"initial", "back"}
    assert not result.joins and not result.reads


def test_each_call_group_observes_its_own_boundary_and_untracked_bytes_remain_absent():
    second = "1:1200:0:CALLIND"
    unit = _unit(LocalMemoryBlock("entry", (), (
        _write("initial", _reg()), LocalStorageAction(f"{CALL}~in0"),
        _write(f"{CALL}~0", _reg(0, 2), kill=True), LocalStorageAction(CALL),
        LocalStorageAction(f"{second}~in0"), LocalStorageAction(second),
    )))
    result = _engines(unit)
    first, last = result.call_register_snapshots
    assert first.boundary_key == CALL and last.boundary_key == second
    assert _sources(result, first, 0) == {"initial"}
    assert _sources(result, last, 0) == {f"{CALL}~0"}
    assert _sources(result, last, 2) == {"initial"}
    assert {byte for fragment in last.fragments for byte in range(fragment.span.start, fragment.span.end)} == set(range(8))


def test_a_boundary_with_no_tracked_registers_is_explicitly_empty():
    unit = _unit(LocalMemoryBlock("entry", (), (
        _write("memory", ByteSpan(OBJECTS[2], 0x4000, 8)), LocalStorageAction(CALL),
        LocalStorageAction("1:1200:0:CALLOTHER"),
    )))
    result = _engines(unit)
    assert result.call_register_snapshots == (CallBoundaryRegisterState(CALL, "entry", CALL, ()),)


def test_boundary_contract_rejects_nonregisters_joins_bad_sources_and_missing_actions():
    with pytest.raises(TypeError, match="register ByteSpan"):
        RegisterStateFragment(ByteSpan(OBJECTS[2], 0, 8), (0,))
    overlapping = tuple(sorted((RegisterStateFragment(_reg(0, 8), (0,)),
                                RegisterStateFragment(_reg(0x10, 1), (0,)),
                                RegisterStateFragment(_reg(2, 1), (0,))),
                               key=lambda item: item.span.canonical_key))
    with pytest.raises(ValueError, match="must not overlap"):
        CallBoundaryRegisterState(CALL, "entry", CALL, overlapping)
    unit = _unit(
        LocalMemoryBlock("entry", (), ()),
        LocalMemoryBlock("left", ("entry",), (_write("left-value", _reg()),)),
        LocalMemoryBlock("right", ("entry",), (_write("right-value", _reg()),)),
        LocalMemoryBlock("merge", ("left", "right"), (LocalStorageAction("read", reads=(_reg(),)),
                                                       LocalStorageAction(CALL))),
    )
    result = _engines(unit)
    (state,) = result.call_register_snapshots
    join = next(identifier for identifier, definition in enumerate(result.definitions)
                if definition.kind is MemoryDefinitionKind.JOIN)
    for identifiers, reason in (((join,), "raw definitions only"), ((len(result.definitions),), "out of range")):
        changed = replace(state, fragments=(RegisterStateFragment(_reg(), identifiers),))
        with pytest.raises(ValueError, match=reason):
            replace(result, call_register_snapshots=(changed,))
    with pytest.raises(ValueError, match="first action must exist"):
        replace(result, call_register_snapshots=(replace(state, first_action_key=f"{CALL}~absent"),))


def test_engines_agree_on_call_boundaries_in_random_partial_overlap_loop_units():
    for seed in range(80):
        original = random_unit(seed)
        blocks = []
        for serial, block in enumerate(original.blocks):
            position = serial % (len(block.actions) + 1)
            call = LocalStorageAction(f"1:{0x100000 + serial:x}:0:CALLIND")
            blocks.append(replace(block, actions=(*block.actions[:position], call, *block.actions[position:])))
        result = _engines(replace(original, blocks=tuple(blocks)))
        assert len(result.call_register_snapshots) == len(blocks)


def test_normalized_call_captures_before_staging_not_the_raw_call_marker(monkeypatch):
    monkeypatch.setenv(memory_ssa.MEMORY_SSA_CROSSCHECK_ENV, "dense")
    caller = FunctionBuilder().sub_rsp(0x28).call(0x1800).add_rsp(0x28).ret()
    callee = FunctionBuilder(entry=0x1800).ins(add(reg(RAX), reg(RCX), const(1))).ret()
    analyzed = analyze_units(program_units(caller, callee))["1:1000"]
    (state,) = analyzed.normalized.memory_ssa.call_register_snapshots
    assert state.boundary_key == "1:1004:2:CALL"
    # The return-IP summary also reads entry memory. That load must precede
    # the run-input temporaries, and the snapshot must precede both stages.
    assert state.first_action_key == "1:1004:2:CALL~ld0"
    assert state.block_key == "1:1004"
    block = next(block for block in analyzed.normalized.memory_unit.blocks
                 if block.key == state.block_key)
    actions = [action.operation_key for action in block.actions]
    assert actions[0] == state.first_action_key
    assert actions.index(state.first_action_key) < actions.index(f"{state.boundary_key}~in0")
    assert actions.index(f"{state.boundary_key}~in0") < actions.index(f"{state.boundary_key}~0")
    assert actions.index(f"{state.boundary_key}~0") < actions.index(state.boundary_key)
    assert _sources(analyzed.normalized.memory_ssa, state, RAX) == {None}
    assert _sources(analyzed.normalized.memory_ssa, state, RSP) == {"1:1000:2:INT_SUB"}
