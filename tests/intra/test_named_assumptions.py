"""The assumption registry (``tdo_v2.assumptions``) and the two named
assumptions win64-home-space-callee-private and debug-break-traps-do-not-return.

Each assumption test shows the claim is load-bearing: off, the result stays
unsure; on, it is exact and the oracle finds nothing missed; and a run that
violates the assumption is caught by the oracle (so the assumption, not luck,
is what the result rests on).
"""

import inspect
from pathlib import Path

import test_graph_fidelity as fidelity
from graph_oracle import check
from program_oracle import check_program
from synthetic import (
    CODE_BASE, R8, R9, RAX, RBX, RCX, RDX, REG, RSI, RSP, FunctionBuilder, add, const, load, op,
    operation_node_at, program_units, reg, slice_from, store, tmp,
)
from tdo_v2.assumptions import REGISTRY, render_markdown, switches
from tdo_v2.interprocedural import analyze_units
from tdo_v2.normalize import FunctionNormalizer

HELPER = CODE_BASE + 0x800
HAVOC = (REG, RSP, 8)
SWI = 16


# -- the registry ---------------------------------------------------------------

def test_docs_are_generated_from_the_registry():
    docs = Path(__file__).resolve().parents[2] / "docs" / "assumptions.md"
    assert docs.read_text(encoding="utf-8").replace("\r\n", "\n") == render_markdown()


def test_every_switch_is_an_engine_parameter():
    from tdo_v2.summary_engine import analyze_frozen_bundle_with_summaries

    parameters = inspect.signature(analyze_frozen_bundle_with_summaries).parameters
    for item in switches():
        assert item.parameter in parameters, item.name
        assert item.flag and item.flag.startswith("--no-" if item.default else "--assume-")
    assert len({item.name for item in REGISTRY}) == len(REGISTRY)


# -- win64-home-space-callee-private ----------------------------------------------

def _spilling(escape=False):
    """spill this (rcx) to the home slot [entry+8]; *this = rsi through a
    reload; r9 = *(reload this). With ``escape`` the function first passes
    the home slot's address to an opaque call."""
    t = tmp(0x100)
    builder = FunctionBuilder().ins(add(t, reg(RSP), const(8)), store(t, reg(RCX)))
    if escape:
        builder.sub_rsp(0x28).ins(add(reg(RDX), reg(RSP), const(0x30))).call(CODE_BASE + 0xF00).add_rsp(0x28)
    return (builder
            .ins(add(t, reg(RSP), const(8)), load(reg(RAX), t))
            .ins(store(reg(RAX), reg(RSI)))
            .ins(add(t, reg(RSP), const(8)), load(reg(RAX), t))
            .ins(load(reg(R9), reg(RAX)))
            .ret())


def _final_load(function, builder):
    return slice_from(function, operation_node_at(function, len(builder._rows) - 2, 0))


def _normalize(builder, above):
    (unit,) = program_units(builder)
    return FunctionNormalizer().normalize(unit, private_frame_above=above), unit.observation


def _pools(this):
    return lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000, RCX: this}


def test_home_space_is_private_under_the_assumption():
    builder = _spilling()
    off, _ = _normalize(builder, 0)
    assert not _final_load(off, builder).is_complete
    on, observation = _normalize(builder, 0x28)
    reload = _final_load(on, builder)
    assert reload.is_complete and set(range(RSI, RSI + 8)) <= reload.register_bytes
    report = check(on, observation, seeds=range(4), register_pools=_pools(0x6000_0000))
    assert report.runs and report.silent == []


def test_an_escaped_home_slot_is_not_private():
    builder = _spilling(escape=True)
    on, _ = _normalize(builder, 0x28)
    assert not _final_load(on, builder).is_complete


def test_violating_the_assumption_is_caught():
    """this = the home slot's own address: the store overwrites the spilled
    pointer; under the assumption the engine misses it, and the oracle says so."""
    builder = _spilling()
    on, observation = _normalize(builder, 0x28)
    report = check(on, observation, seeds=range(4), register_pools=_pools(0x7000_0008))
    assert report.silent


# -- debug-break-traps-do-not-return ----------------------------------------------

def _checked_helper():
    """if (rsi & 1) int 3;  *rcx = rdx; return."""
    return (FunctionBuilder(entry=HELPER)
            .cbranch("trap", reg(RSI, 1))
            .ins(store(reg(RCX), reg(RDX)))
            .ret()
            .label("trap").ins(op("CALLOTHER", [const(SWI, 4), const(3, 4)], None))
            .ret())


def _trapping_helper():
    return FunctionBuilder(entry=HELPER).ins(op("CALLOTHER", [const(SWI, 4), const(0x29, 4)], None)).ret()


def _caller():
    """kept = rbx; helper(&slot); r9 = kept; r8 = slot."""
    t = tmp(0x100)
    return (FunctionBuilder().sub_rsp(0x48)
            .ins(add(t, reg(RSP), const(0x38)), store(t, reg(RBX)))
            .ins(add(reg(RCX), reg(RSP), const(0x30)))
            .call(HELPER)
            .ins(add(t, reg(RSP), const(0x38)), load(reg(R9), t))
            .ins(add(t, reg(RSP), const(0x30)), load(reg(R8), t))
            .add_rsp(0x48).ret())


def _analyze(helper, traps):
    from tdo_v2.pcodeop_models import PcodeOpModel

    units = program_units(_caller(), helper)
    namespace = units[0].scopes.program.evidence.translation_namespace
    model = PcodeOpModel("x86-markers", 1, frozenset({(namespace.language_id, namespace.major_version,
                                                        namespace.minor_version)}), {}, {SWI: frozenset({3, 0x29})})
    results = analyze_units(units, pcodeop_models=(model,), assume_debug_break_traps_do_not_return=traps)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    return results, program


def _check(results, program):
    analyzed = results["1:1000"]
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    return check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=range(6),
                         register_pools=pools, havoc_calls=HAVOC)


def test_a_check_failure_trap_does_not_spoil_the_summary():
    off, _ = _analyze(_checked_helper(), traps=False)
    (effect,) = off["1:1000"].proven.values()
    assert not effect.preserves_memory
    on, program = _analyze(_checked_helper(), traps=True)
    summary = on[f"1:{HELPER:x}"].summary
    assert summary.dead_exits and summary.exits
    (effect,) = on["1:1000"].proven.values()
    assert effect.preserves_memory
    function = on["1:1000"].normalized
    kept = slice_from(function, operation_node_at(function, 4, 1))
    assert kept.is_complete and set(range(RBX, RBX + 8)) <= kept.register_bytes
    assert _check(on, program).silent == []


def test_a_function_ending_only_in_traps_never_returns():
    on, _ = _analyze(_trapping_helper(), traps=True)
    (effect,) = on["1:1000"].proven.values()
    assert effect.noreturn
    assert on["1:1000"].summary.dead_exits
