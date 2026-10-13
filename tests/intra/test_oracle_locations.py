"""The oracles check WHERE a memory run writes, not only that its writer is listed.

``summary_oracle.check_summary``: a memory byte the function wrote must lie in
a run (of that writer) whose place, at this run's entry values, holds it.
``program_oracle.check_program``: a byte a call wrote must lie in a run of
that call whose place, evaluated just before the call, holds it -- reaching
some other memory run of the same call is not enough. Each oracle must catch
a summary whose runs are shifted by 8 bytes, which the writer-only checks
accepted.
"""

import dataclasses

import test_graph_fidelity as fidelity
from program_oracle import check_program
from summary_oracle import check_summary
import pytest

from pcode_interpreter import Dependency, Interpreter
from synthetic import (
    CODE_BASE, CONST, R8, RAM, RAX, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const, load,
    normalize_with_observation, program_units, reg, store, tmp,
)
from tdo_v2.function_summary import summarize_function
from tdo_v2.interprocedural import analyze_units
from tdo_v2.span_geometry import ByteSpan, StorageObjectKind

LEAF, OTHER = CODE_BASE + 0x800, CODE_BASE + 0xA00
POOLS = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}  # noqa: E731


def _check_with_moved_runs(monkeypatch, functions, delta, drop=False, mutate_call=None, no_inputs=False,
                           private_frame_above=0):
    """``check_program`` of the first function with every memory run of the
    summarized calls (or only of the call to ``mutate_call``) moved by
    ``delta`` bytes (``drop``: removed, the call still claiming to keep the
    rest of memory)."""
    import tdo_v2.interprocedural as interprocedural
    from tdo_v2.call_summary_effects import derive_proven_call_effect

    def changed(summary, callee, *args, **kwargs):
        effect = derive_proven_call_effect(summary, callee, *args, **kwargs)
        if mutate_call is not None and callee != f"1:{mutate_call:x}":
            return effect
        if drop:
            return dataclasses.replace(effect, memory_runs=effect.memory_runs[1:])
        if no_inputs:
            return dataclasses.replace(effect, memory_runs=tuple(
                dataclasses.replace(run, reads=(), loads=()) for run in effect.memory_runs))
        moved = tuple(dataclasses.replace(run, write=dataclasses.replace(
            run.write, displacement=run.write.displacement + delta)) for run in effect.memory_runs)
        return dataclasses.replace(effect, memory_runs=moved)

    monkeypatch.setattr(interprocedural, "derive_proven_call_effect", changed)
    units = program_units(*functions)
    results = analyze_units(units, private_frame_above=private_frame_above)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    analyzed = results["1:1000"]
    return check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=range(4),
                         register_pools=POOLS, havoc_calls=(REG, RSP, 8), private_frame_above=private_frame_above)


def _shifted(summary, delta):
    """``summary`` with every non-register run moved by ``delta`` bytes."""
    def move(run):
        if run.span.object_id.kind is StorageObjectKind.REGISTER_FILE:
            return run
        span = ByteSpan(run.span.object_id, run.span.start + delta, run.span.size)
        return dataclasses.replace(run, span=span)

    return dataclasses.replace(summary, exits=tuple(
        dataclasses.replace(item, runs=tuple(move(run) for run in item.runs)) for item in summary.exits))


def test_summary_oracle_checks_the_place_of_a_memory_run():
    """*(rsi) = rdx: the run is at [rsi_entry, +8); moved by 8 it no longer holds the bytes."""
    function, observation = normalize_with_observation(
        FunctionBuilder().ins(store(reg(RSI), reg(RDI))).ret())
    summary = summarize_function(function, observation)
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}  # noqa: E731
    right = check_summary(summary, observation, seeds=range(4), register_pools=pools)
    assert right.violations == [] and right.place_covered > 0 and right.place_unlocated_only == 0
    wrong = check_summary(_shifted(summary, 8), observation, seeds=range(4), register_pools=pools)
    assert any(row[0] == "write outside its run" for row in wrong.violations)


def test_program_oracle_checks_the_place_of_a_call_run(monkeypatch):
    """leaf: *(rdi + 8) = rsi; *(rdi + 16) = rsi. The caller reads 16 bytes at
    its local + 8. With the call's runs moved by 8 (claiming +16 and +24), the
    reader still reaches a memory run of the call (+16) and the value's input
    (rsi) -- accepted by a writer-only check -- but no run holds the bytes at +8."""
    import tdo_v2.interprocedural as interprocedural
    from tdo_v2.call_summary_effects import derive_proven_call_effect

    t = tmp(0x100)
    leaf = (FunctionBuilder(entry=LEAF)
            .ins(add(t, reg(RDI), const(8)), store(t, reg(RSI)))
            .ins(add(t, reg(RDI), const(16)), store(t, reg(RSI))).ret())
    caller = (FunctionBuilder().sub_rsp(0x40).ins(add(reg(RDI), reg(RSP), const(0)))
              .call(LEAF)
              .ins(add(t, reg(RSP), const(8)), load(tmp(0x200, 16), t))
              .add_rsp(0x40).ret())

    def analyze(delta):
        def shifted_effect(*args, **kwargs):
            effect = derive_proven_call_effect(*args, **kwargs)
            moved = tuple(dataclasses.replace(run, write=dataclasses.replace(
                run.write, displacement=run.write.displacement + delta)) for run in effect.memory_runs)
            return dataclasses.replace(effect, memory_runs=moved)

        monkeypatch.setattr(interprocedural, "derive_proven_call_effect", shifted_effect)
        units = program_units(caller, leaf)
        results = analyze_units(units)
        program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
        analyzed = results["1:1000"]
        assert analyzed.proven and next(iter(analyzed.proven.values())).memory_runs
        return check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=range(4),
                             register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                             havoc_calls=(REG, RSP, 8))

    right = analyze(0)
    assert right.silent == [] and right.place_covered > 0 and right.place_unlocated_only == 0
    wrong = analyze(8)
    assert wrong.silent, "a run moved by 8 bytes must not cover the bytes it no longer holds"


def _local_outparam():
    """leaf: *(rdi + 8) = rsi; *(rdi + 16) = rsi; the caller reads 16 bytes at its local + 8."""
    t = tmp(0x100)
    leaf = (FunctionBuilder(entry=LEAF)
            .ins(add(t, reg(RDI), const(8)), store(t, reg(RSI)))
            .ins(add(t, reg(RDI), const(16)), store(t, reg(RSI))).ret())
    caller = (FunctionBuilder().sub_rsp(0x40).ins(add(reg(RDI), reg(RSP), const(0)))
              .call(LEAF).ins(add(t, reg(RSP), const(8)), load(tmp(0x200, 16), t))
              .add_rsp(0x40).ret())
    return caller, leaf


@pytest.mark.parametrize("delta", [1, -1, 16, -8])
def test_any_moved_run_is_caught(monkeypatch, delta):
    report = _check_with_moved_runs(monkeypatch, _local_outparam(), delta)
    assert report.silent, delta


def test_a_run_anchored_on_the_callee_stack_pointer():
    """leaf: [rsp + 8] = rcx (the caller's [rsp] -- above the return address);
    the place is evaluated at the callee's entry, after the push."""
    t = tmp(0x100)
    leaf = FunctionBuilder(entry=LEAF).ins(add(t, reg(RSP), const(8)), store(t, reg(RCX))).ret()
    caller = (FunctionBuilder().sub_rsp(0x40).call(LEAF).ins(load(reg(RAX), reg(RSP)))
              .add_rsp(0x40).ret())
    units = program_units(caller, leaf)
    results = analyze_units(units)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    analyzed = results["1:1000"]
    assert next(iter(analyzed.proven.values())).memory_runs
    report = check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=range(4),
                           register_pools=POOLS, havoc_calls=(REG, RSP, 8))
    assert report.silent == [] and report.place_covered > 0


@pytest.mark.parametrize("delta", [8, -8])
def test_a_moved_stack_anchored_run_is_caught(monkeypatch, delta):
    t = tmp(0x100)
    leaf = FunctionBuilder(entry=LEAF).ins(add(t, reg(RSP), const(8)), store(t, reg(RCX))).ret()
    caller = (FunctionBuilder().sub_rsp(0x40).call(LEAF).ins(load(reg(RAX), reg(RSP)))
              .add_rsp(0x40).ret())
    report = _check_with_moved_runs(monkeypatch, (caller, leaf), delta)
    assert report.silent


def test_an_input_written_by_an_earlier_call_is_placed(monkeypatch):
    """A: *(rdi+8) = *(rdi+16) = rsi; B: rax = *(rdi+8) + *(rdi+16); the
    caller keeps B's result. A's runs moved by 8 must not explain B's input
    at +8 (the writer-only check of earlier calls accepted it)."""
    t, u = tmp(0x100), tmp(0x108)
    first = (FunctionBuilder(entry=LEAF)
             .ins(add(t, reg(RDI), const(8)), store(t, reg(RSI)))
             .ins(add(t, reg(RDI), const(16)), store(t, reg(RSI))).ret())
    second = (FunctionBuilder(entry=OTHER)
              .ins(add(t, reg(RDI), const(8)), load(u, t))
              .ins(add(t, reg(RDI), const(16)), load(reg(RAX), t))
              .ins(add(reg(RAX), reg(RAX), u)).ret())
    caller = (FunctionBuilder().sub_rsp(0x40).ins(add(reg(RDI), reg(RSP), const(0))).call(LEAF)
              .ins(add(reg(RDI), reg(RSP), const(0))).call(OTHER).ins(add(reg(RBX), reg(RAX), const(0)))
              .add_rsp(0x40).ret())
    right = _check_with_moved_runs(monkeypatch, (caller, first, second), 0)
    assert right.silent == [] and right.covered_by_debt == []
    wrong = _check_with_moved_runs(monkeypatch, (caller, first, second), 8, mutate_call=LEAF)
    assert wrong.silent or wrong.covered_by_debt


def test_a_write_outside_the_footprint_of_a_preserving_call_is_caught(monkeypatch):
    """The call keeps claiming ``preserves_memory`` with one of its runs dropped."""
    right = _check_with_moved_runs(monkeypatch, _local_outparam(), 0)
    assert right.silent == [] and right.footprint_checked > 0
    wrong = _check_with_moved_runs(monkeypatch, _local_outparam(), 0, drop=True)
    assert any(reason == "write outside the call's footprint" for _, reason in wrong.silent)


def test_memory_addresses_wrap_at_the_address_width():
    """*(rcx) = rdx with rcx = 2**64 - 4 writes bytes 2**64-4 .. 2**64-1 and 0 .. 3."""
    function = FunctionBuilder().ins(store(reg(RCX), reg(RDX))).ins(load(reg(RAX), const(0, 8))).ret()
    observation = normalize_with_observation(function)[1]
    interpreter = Interpreter(observation, constant_space=CONST, seed=0)
    interpreter.preset(REG, RCX, 8, (1 << 64) - 4)
    run = interpreter.run()
    store_key = next(key for key in run.executed if key.endswith("STORE"))
    load_key = next(key for key in run.executed if key.endswith("LOAD"))
    assert Dependency(load_key, RAM, 0, store_key) in run.dependencies
    assert Dependency(load_key, RAM, 3, store_key) in run.dependencies
