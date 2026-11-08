"""Absolute self re-entry, non-exit snapshots, and lossless CFG refusals."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from synthetic import (
    CODE_BASE, RAX, RCX, RDX, RSP, ZF, FunctionBuilder, _Instruction, _Provider,
    add, const, copy, op, ram, reg, sub, summary_inputs, tmp,
)
from tdo_v2._scope_contracts import _mint_orchestrator_capability
from tdo_v2._scope_envelope import open_configured_extraction
from tdo_v2.call_summary_effects import summary_noreturn
from tdo_v2.function_summary import summarize_function
from tdo_v2.memory_contracts import ObservedTerminalMemoryState
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction, NormalizationFailureReason, UnresolvedNormalizedFunction
from tdo_v2.pcode_blocks import build_pcode_block_graph


def _unit(builder, transform=None):
    raw = builder.to_json()
    if transform is not None:
        transform(raw)
    function = SimpleNamespace(arch=builder.arch, entry=builder.entry, to_json=lambda: raw)
    with open_configured_extraction(_Provider([function]), _mint_orchestrator_capability()) as envelope:
        (unit,) = envelope.iter_scoped_functions()
    return unit


def _terminal_self(raw):
    row = raw["instructions"][-1]
    row["flow_targets"] = []
    row["flow_type"]["is_jump"] = False
    row["flow_type"]["is_terminal"] = True


def test_conditional_absolute_self_is_an_observed_successor_not_relative_zero():
    builder = FunctionBuilder().label("again").cbranch("again", reg(ZF, 1)).ret()
    unit = _unit(builder)
    graph = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
    assert graph.unsupported is None
    assert graph.blocks[0].successors == ("1:1000", "1:1004")
    assert type(FunctionNormalizer().normalize(unit)) is NormalizedFunction


def test_nonlast_absolute_conditional_self_carries_register_and_unique_values():
    from graph_oracle import check, check_control

    loop_address = CODE_BASE + 4
    builder = FunctionBuilder().ins(copy(tmp(0x300), reg(RAX))).ins(
        add(reg(RAX), reg(RAX), tmp(0x300)),
        copy(tmp(0x300), reg(RCX)),
        sub(reg(RCX), reg(RCX), const(1)),
        op("INT_NOTEQUAL", [reg(RCX), const(0)], tmp(0x200, 1)),
        op("CBRANCH", [ram(loop_address), tmp(0x200, 1)]),
        copy(reg(RDX), tmp(0x300)),
    ).ret()

    def conditional_flow(raw):
        row = raw["instructions"][1]
        row["flow_targets"] = [dict(row["address"])]
        row["flow_type"].update(is_flow=True, is_jump=True, is_conditional=True)

    unit = _unit(builder, conditional_flow)
    n = FunctionNormalizer().normalize(unit)
    assert type(n) is NormalizedFunction
    blocks = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
    assert blocks.unsupported is None
    assert blocks.blocks[1].successors == ("1:1004", "1:1004#5")
    assert blocks.blocks[2].successors == ("1:1008",)
    assert all(n.dependencies.node_for_key(f"op:1:1004:{ordinal}:{opcode}") is not None
               for ordinal, (opcode, _, _) in enumerate(builder._rows[1].ops))
    pools = lambda seed: {RAX: seed + 2, RCX: (1, 2, 4)[seed % 3], RSP: 0x7000_0000}
    report = check(n, unit.observation, seeds=range(6), register_pools=pools)
    assert report.runs == 6 and not report.silent and not report.covered_by_debt
    assert check_control(n, unit.observation, seeds=range(6), register_pools=pools) == []


def test_absolute_unconditional_self_retains_the_real_loop_without_an_exit():
    unit = _unit(FunctionBuilder().label("again").branch("again"))
    n = FunctionNormalizer().normalize(unit)
    assert type(n) is NormalizedFunction
    graph = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
    assert graph.blocks[0].successors == ("1:1000",)
    assert not n.memory_ssa.exit_states
    summary = summarize_function(n, unit.observation)
    assert not summary.exits and not summary_noreturn(summary)


def test_observed_terminal_self_has_a_complete_nonexit_snapshot_not_a_return():
    builder = FunctionBuilder().ins(copy(reg(RAX), reg(RCX))).label("halt").branch("halt")
    unit = _unit(builder, _terminal_self)
    n = FunctionNormalizer().normalize(unit)
    assert type(n) is NormalizedFunction
    graph = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
    halt = graph.blocks[-1]
    assert halt.successors == (halt.key,) and not halt.exits
    (state,) = n.memory_ssa.observed_terminal_states
    assert state.block_key == "1:1004" and state.is_exit is False
    assert state.root_node_id is not None and n.memory_ssa.atomic_spans
    assert not n.memory_ssa.exit_states
    n.memory_ssa.validate_terminal_roles(n.memory_unit)
    summary = summarize_function(n, unit.observation)
    assert not summary.exits and not summary.dead_exits and not summary_noreturn(summary)


def test_real_return_and_nonexit_observation_do_not_merge_into_return_projection():
    builder = FunctionBuilder().cbranch("halt", reg(ZF, 1)).ret().label("halt").branch("halt")
    unit = _unit(builder, _terminal_self)
    n = FunctionNormalizer().normalize(unit)
    assert len(n.memory_ssa.observed_terminal_states) == 2
    assert [state.block_key for state in n.memory_ssa.exit_states] == ["1:1004"]
    summary = summarize_function(n, unit.observation)
    assert [row.block_key for row in summary.exits] == ["1:1004"]
    assert not summary_noreturn(summary)


def test_snapshot_role_and_root_cannot_be_promoted_or_truncated():
    builder = FunctionBuilder().ins(copy(reg(RAX), reg(RCX))).label("halt").branch("halt")
    n = FunctionNormalizer().normalize(_unit(builder, _terminal_self))
    state, = n.memory_ssa.observed_terminal_states
    with pytest.raises(TypeError, match="exact bool"):
        ObservedTerminalMemoryState(state.block_key, state.root_node_id, 1)
    forged = replace(n.memory_ssa, observed_terminal_states=(replace(state, is_exit=True),))
    with pytest.raises(ValueError, match="exit role"):
        forged.validate_terminal_roles(n.memory_unit)
    with pytest.raises(ValueError, match="complete terminal-state root"):
        replace(n.memory_ssa, observed_terminal_states=(replace(state, root_node_id=None),))


def test_disconnected_refusal_preserves_all_original_instructions_and_edges():
    builder = FunctionBuilder().ins(copy(reg(RAX), reg(RCX))).ret(realistic=False)
    builder._rows.extend([_Instruction([copy(reg(RCX), reg(RAX))]),
                          _Instruction([op("RETURN", [reg(RAX)])], "return")])
    unit = _unit(builder)
    n = FunctionNormalizer().normalize(unit)
    assert type(n) is UnresolvedNormalizedFunction
    assert n.reason is NormalizationFailureReason.DISCONNECTED_OBSERVED_CFG
    control = n.observed_control
    assert control.observation is unit.observation
    assert control.cfg.node_count == 4 and control.cfg.edge_count == 2
    assert control.entry_reachable == ("1:1000", "1:1004")
    assert control.unreachable == ("1:1008", "1:100c")
    assert len(control.weak_components) == 2
    assert not hasattr(n, "memory_ssa")
    with pytest.raises(RuntimeError, match="frozen"):
        control.cfg.add_node(control.cfg.node(0))


def test_public_summary_run_retains_a_disconnected_failure_and_its_original_cfg():
    from tdo_v2.boundary_rules import SymbolBoundaryProvider
    from tdo_v2.summary_engine import analyze_observed_with_summaries

    builder = FunctionBuilder().ret(realistic=False)
    builder._rows.extend([_Instruction([copy(reg(RCX), reg(RAX))]),
                          _Instruction([op("RETURN", [reg(RAX)])], "return")])
    inputs = summary_inputs([builder], image=False)
    run = analyze_observed_with_summaries(
        inputs.program, inputs.evidences, boundary_provider=SymbolBoundaryProvider(()))
    assert run.failed_functions == (("1:1000", "disconnected_observed_cfg", ""),)
    assert not run.roots
    ((key, control),) = run.refused_control_graphs
    assert key == "1:1000" and control.observation is inputs.evidences[0].unit.observation
    assert control.cfg.node_count == 3 and control.cfg.edge_count == 1
    assert control.entry_reachable == ("1:1000",)
    assert control.unreachable == ("1:1004", "1:1008")


def test_missing_observed_fallthrough_is_retained_not_connected_to_next_instruction():
    builder = FunctionBuilder().ins(copy(reg(RAX), reg(RCX))).ret(realistic=False)

    def gap(raw):
        raw["instructions"][0]["fallthrough"]["byte_offset"] = CODE_BASE + 1

    unit = _unit(builder, gap)
    n = FunctionNormalizer().normalize(unit)
    assert n.reason is NormalizationFailureReason.DISCONNECTED_OBSERVED_CFG
    control = n.observed_control
    assert control.cfg.edge_count == 0 and control.unreachable == ("1:1004",)
    assert [(a.byte_offset, b.byte_offset) for a, b in control.outside_observed_successors] == [
        (CODE_BASE, CODE_BASE + 1)]
