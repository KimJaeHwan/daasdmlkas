"""Operation records (docs 25.28): shapes, and the evaluation oracle -- an
eligible record of a summary run evaluates, with a concrete run's entry
values, to the register's final bytes."""

import random

import pytest

import test_graph_fidelity as fidelity
from record_oracle import check_records
from synthetic import (
    CF, R8, R9, RAX, RBX, RCX, RDI, RDX, RSI, RSP, ZF, FunctionBuilder, add, const, copy, load, op,
    program_units, reg, store, tmp,
)
from tdo_v2.interprocedural import analyze_units
from tdo_v2.operation_records import eligibility, render, run_records

REGS = (RAX, RCX, RDX, RBX, RSI, RDI, R8, R9)


def _analyzed(builder):
    return analyze_units(program_units(builder))["1:1000"]


def _record(analyzed, register, size=8):
    for record in run_records(analyzed.normalized, analyzed.unit, analyzed.summary):
        place = record["place"]
        if place["kind"] == "register_file" and place["start"] == register and place["size"] >= size:
            return record
    raise KeyError(register)


def _value_function(rng):
    """Register arithmetic, partial writes, stack spills and reloads, and a
    conditional move -- no pointer from the entry state (no alias debt)."""
    builder = FunctionBuilder().sub_rsp(0x40)
    slot = tmp(0x180)
    for index in range(rng.randint(3, 14)):
        kind = rng.random()
        if kind < 0.55:
            builder.ins(fidelity._random_value_op(rng))
        elif kind < 0.7:
            offset = rng.choice((0, 8, 0x10, 0x18))
            size = rng.choice((1, 4, 8))
            builder.ins(add(slot, reg(RSP), const(offset)), store(slot, reg(rng.choice(REGS), size)))
        elif kind < 0.85:
            offset = rng.choice((0, 8, 0x10, 0x18))
            size = rng.choice((1, 4, 8))
            builder.ins(add(slot, reg(RSP), const(offset)), load(reg(rng.choice(REGS), size), slot))
        else:
            next_address = 0x1000 + 4 * (len(builder._rows) + 1)
            builder.ins(*fidelity._cmov(rng, next_address if rng.random() < 0.5 else None))
    return builder.add_rsp(0x40).ret()


def _pools(seed):
    rng = random.Random(seed)
    values = {register: rng.getrandbits(64) for register in REGS}
    values[RSP] = 0x7000_0000
    values[ZF], values[CF] = rng.randrange(2), rng.randrange(2)
    return values


@pytest.mark.parametrize("chunk", range(4))
def test_records_of_value_functions_evaluate_to_the_final_registers(chunk):
    evaluated = 0
    for number in range(chunk * 25, chunk * 25 + 25):
        rng = random.Random(number)
        analyzed = _analyzed(_value_function(rng))
        report = check_records(analyzed, seeds=range(3), register_pools=_pools)
        assert report.failures == [], (number, report.failures[:3])
        evaluated += report.evaluated
    assert evaluated >= 300, evaluated


@pytest.mark.parametrize("chunk", range(4))
def test_records_of_random_functions_never_contradict_a_run(chunk):
    """Aliasing pointers, loops, branches: most records are skipped (debts,
    loops), but none that is evaluated may miss the concrete value."""
    evaluated = 0
    skipped = 0
    for number in range(chunk * 25, chunk * 25 + 25):
        rng = random.Random(1000 + number)
        analyzed = _analyzed(fidelity._random_function(rng))
        report = check_records(analyzed, seeds=range(3), register_pools=fidelity._inputs_with_bounded_loop)
        assert report.failures == [], (number, report.failures[:3])
        evaluated += report.evaluated
        skipped += sum(report.skipped.values())
    assert evaluated >= 20 and skipped, (evaluated, skipped)
