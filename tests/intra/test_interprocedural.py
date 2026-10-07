"""Interprocedural S1a: callee summaries as proven register effects at call sites.

Checked against concrete runs that execute the callees for real
(``program_oracle.check_program``): every def->use read by the caller is a
graph path, values computed inside a call reach their caller-level inputs,
and nothing is silently missed.
"""

import random

import pytest

import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    CODE_BASE, R8, R9, RAX, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const,
    copy, program_units, reg, slice_op,
)
from tdo_v2.interprocedural import analyze_units

LEAF, MIDDLE = CODE_BASE + 0x800, CODE_BASE + 0x600
HAVOC = (REG, RSP, 8)


def _analyze(*functions):
    units = program_units(*functions)
    results = analyze_units(units)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units
               if hasattr(unit.scopes.function, "entry")}
    return results, program


def _check(results, program, key="1:1000", seeds=range(6), pools=None):
    analyzed = results[key]
    pools = pools or (lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000})
    return check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=seeds,
                         register_pools=pools, havoc_calls=HAVOC)


def _entry_registers(function, opcode, index=0):
    return slice_op(function, opcode, index).register_bytes


def test_value_flows_through_a_call_and_preserved_registers_stay_exact():
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    caller = (FunctionBuilder().ins(copy(reg(RDI), reg(RSI))).call(LEAF)
              .ins(copy(reg(RCX), reg(RAX))).ins(copy(reg(R9), reg(RBX))).ret())
    results, program = _analyze(caller, leaf)
    function = results["1:1000"].normalized
    assert set(range(RSI, RSI + 8)) <= _entry_registers(function, "COPY", 2)  # rcx <- rax <- rdi <- rsi
    r9 = _entry_registers(function, "COPY", 3)
    assert set(range(RBX, RBX + 8)) <= r9
    assert not [row for row in function.call_clobber_reads  # registers: no call debt left
                if any(span.object_id.kind.value == "register_file" for span in row.spans)]
    report = _check(results, program)
    assert report.runs and report.through_calls and report.silent == []


def test_selected_argument_only():
    """dfb_returns_third(x, y, z): the result depends on the third argument only."""
    leaf = FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), reg(RDX))).ins(copy(reg(RCX), reg(RDI))).ret()
    caller = FunctionBuilder().call(LEAF).ins(copy(reg(R9), reg(RAX))).ret()
    results, _ = _analyze(caller, leaf)
    sources = _entry_registers(results["1:1000"].normalized, "COPY", 1)
    assert set(range(RDX, RDX + 8)) <= sources and not sources & set(range(RDI, RDI + 8))


def test_opaque_call_inside_the_callee_stays_debt():
    leaf = FunctionBuilder(entry=LEAF).call(CODE_BASE + 0x4000).ret()  # unknown target
    caller = FunctionBuilder().call(LEAF).ins(copy(reg(R9), reg(RAX))).ret()
    results, program = _analyze(caller, leaf)
    assert results["1:1000"].normalized.call_clobber_reads
    assert _check(results, program).silent == []


def test_nested_calls_compose():
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(R8), const(2))).ret()
    middle = FunctionBuilder(entry=MIDDLE).ins(copy(reg(R8), reg(RDI))).call(LEAF).ret()
    caller = FunctionBuilder().ins(copy(reg(RDI), reg(RSI))).call(MIDDLE).ins(copy(reg(R9), reg(RAX))).ret()
    results, program = _analyze(caller, middle, leaf)
    assert set(range(RSI, RSI + 8)) <= _entry_registers(results["1:1000"].normalized, "COPY", 2)
    report = _check(results, program)
    assert report.through_calls and report.silent == []


def _random_body(rng, builder, calls=(), stack_ops=True):
    """``stack_ops``: free push/pop. Callees keep the stack balanced: the call
    shape assumes the callee restores the stack pointer (checking that is the
    S2 stack-pointer summary)."""
    labels = []
    for index in range(rng.randint(2, 10)):
        if index and rng.random() < 0.15:
            labels.append(f"L{index}")
            builder.label(labels[-1])
        kind = rng.random()
        if calls and kind < 0.2:
            builder.call(rng.choice(calls))
        elif kind < 0.55:
            builder.ins(fidelity._random_value_op(rng))
        elif kind < 0.85:
            builder.ins(*fidelity._random_memory_ops(rng))
        elif kind < 0.9:
            builder.ins(*fidelity._cmov(rng))
        elif stack_ops:
            builder.push(rng.choice(fidelity.REGS)) if rng.random() < 0.5 else builder.pop(
                rng.choice(fidelity.REGS))
        else:
            builder.ins(fidelity._random_value_op(rng))
    if labels and rng.random() < 0.4:
        builder.cbranch(rng.choice(labels), reg(rng.choice((fidelity.ZF, fidelity.CF)), 1))
    return builder.ret(realistic=True)


@pytest.mark.parametrize("chunk", range(4))
def test_random_programs_have_no_silent_misses(chunk):
    silent, through, runs = [], 0, 0
    for seed in range(chunk * 40, (chunk + 1) * 40):
        rng = random.Random(90_000 + seed)
        leaf = _random_body(rng, FunctionBuilder(entry=LEAF), stack_ops=False)
        middle = _random_body(rng, FunctionBuilder(entry=MIDDLE), calls=(LEAF,), stack_ops=False)
        caller = _random_body(rng, FunctionBuilder(), calls=(LEAF, MIDDLE))
        try:
            results, program = _analyze(caller, middle, leaf)
        except AssertionError:
            continue
        for key in ("1:1000", f"1:{MIDDLE:x}"):
            if type(results[key].normalized).__name__ != "NormalizedFunction":
                continue
            report = _check(results, program, key=key)
            runs += report.runs
            through += report.through_calls
            silent += [(seed, key, item) for item in report.silent]
    assert runs > 0 and through > 0
    assert silent == [], silent[:3]
