"""Declared models of external functions (``summary_store``, models/external).

Programs call "imported" library functions through a thunk address that the
image facts (``image_info``) bind to an import name; the interpreter runs
them with their real C semantics (``Interpreter(externals=…)``), and the
program oracle checks the caller's graph against those runs: every value
through the call reaches its caller-level inputs, nothing is silently missed.
"""

import random
from pathlib import Path

import pytest

import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    CODE_BASE, DATA_BASE, R8, R9, RAX, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const,
    copy, load, operation_node_at, program_units, reg, slice_from, store, tmp,
)
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import load_external_models, load_model_file

MODELS = sorted((Path(__file__).resolve().parents[2] / "models" / "external").glob("*.json"))
THUNKS = {name: CODE_BASE + 0xE00 + 0x10 * index
          for index, name in enumerate(("memcpy", "memset", "strlen", "malloc", "free"))}
HAVOC = (REG, RSP, 8)


def _image():
    return ImageInfo("synthetic", (), tuple(
        ImportedSymbol("CRT", name, None, (), ((1, address),)) for name, address in THUNKS.items()
    ), (), ())


def _analyze(*functions, models=True):
    units = program_units(*functions)
    results = analyze_units(
        units, image_info=_image(),
        external_models=load_external_models(MODELS, "x86:LE:64:default", "win64") if models else None,
    )
    return results


def _check(results, key="1:1000", seeds=range(6), pools=None):
    analyzed = results[key]
    pools = pools or (lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000})
    return check_program(analyzed.normalized, analyzed.unit.observation, {}, seeds=seeds,
                         register_pools=pools, havoc_calls=HAVOC,
                         externals={(1, address): name for name, address in THUNKS.items()})


def test_model_files_load():
    for path in MODELS:
        model = load_model_file(path)
        assert model.entries and model.stack_delta == 8


def _memcpy_caller(count_register_constant=True):
    """src = rbx at [DATA+0x40]; memcpy(dst = rsp+0x20, src, 8); r9 = dst."""
    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x40)
               .ins(store(const(DATA_BASE + 0x40), reg(RBX)))
               .ins(add(reg(RCX), reg(RSP), const(0x20)))
               .ins(copy(reg(RDX), const(DATA_BASE + 0x40))))
    if count_register_constant:
        builder.ins(copy(reg(R8), const(8)))
    else:
        builder.ins(copy(reg(R8), reg(RSI)))   # count only known at run time
    return (builder.call(THUNKS["memcpy"])
            .ins(add(t, reg(RSP), const(0x20)), load(reg(R9), t))
            .add_rsp(0x40).ret())


def test_memcpy_with_a_constant_count_is_exact():
    results = _analyze(_memcpy_caller())
    item = results["1:1000"]
    ((call, label),) = item.declared.items()
    assert label == "external-model:crt-win64/memcpy@v1"
    effect = item.proven[call]
    assert effect.preserves_memory and len(effect.memory_runs) == 1
    function = item.normalized
    read = slice_from(function, operation_node_at(function, 6, 1))
    assert set(range(RBX, RBX + 8)) <= read.register_bytes
    assert read.is_complete
    report = _check(results, pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000})
    assert report.through_calls and report.silent == []


def test_memcpy_with_an_unknown_count_keeps_no_memory():
    results = _analyze(_memcpy_caller(count_register_constant=False))
    effect = next(iter(results["1:1000"].proven.values()))
    assert not effect.preserves_memory and not effect.memory_runs
    function = results["1:1000"].normalized
    assert not slice_from(function, operation_node_at(function, 6, 1)).is_complete
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000, RSI: seed % 9}
    assert _check(results, pools=pools).silent == []


def test_without_models_the_call_stays_opaque():
    results = _analyze(_memcpy_caller(), models=False)
    assert not results["1:1000"].proven and not results["1:1000"].declared


def test_volatile_registers_are_unknown_and_preserved_ones_exact():
    builder = (FunctionBuilder().ins(copy(reg(RDI), reg(RSI))).ins(copy(reg(R9), reg(RBX)))
               .ins(add(reg(RCX), reg(RSP), const(0)))
               .call(THUNKS["free"])
               .ins(copy(reg(RAX), reg(RDI))).ins(copy(reg(RCX), reg(R9))).ret())
    results = _analyze(builder)
    function = results["1:1000"].normalized
    kept = slice_from(function, operation_node_at(function, 4))
    clobbered = slice_from(function, operation_node_at(function, 5))
    assert kept.is_complete and set(range(RSI, RSI + 8)) <= kept.register_bytes
    assert not clobbered.is_complete
    assert _check(results).silent == []


def _random_caller(rng):
    t = tmp(0x100)
    builder = FunctionBuilder().sub_rsp(0x60)
    for _ in range(rng.randint(1, 3)):
        slot = rng.choice((0x20, 0x28, 0x30, 0x38))
        builder.ins(add(t, reg(RSP), const(slot)), store(t, reg(rng.choice((RBX, RSI, RDI)))))
    name = rng.choice(("memcpy", "memset", "strlen", "malloc", "free"))
    builder.ins(add(reg(RCX), reg(RSP), const(rng.choice((0x20, 0x28, 0x30)))))
    builder.ins(copy(reg(RDX), const(DATA_BASE + rng.choice((0, 8, 0x40)))) if rng.random() < 0.7
                else add(reg(RDX), reg(RSP), const(rng.choice((0x28, 0x38)))))
    builder.ins(copy(reg(R8), const(rng.choice((1, 4, 8, 12, 16)))) if rng.random() < 0.7
                else copy(reg(R8), reg(RSI)))
    builder.call(THUNKS[name])
    for _ in range(rng.randint(1, 3)):
        slot = rng.choice((0x20, 0x24, 0x28, 0x30, 0x38, 0x3C))
        builder.ins(add(t, reg(RSP), const(slot)), load(reg(rng.choice((R9, RAX, RCX))), t))
    builder.ins(copy(reg(R8), reg(rng.choice((RAX, RDI, RBX, RCX)))))
    return builder.add_rsp(0x60).ret()


@pytest.mark.parametrize("chunk", range(3))
def test_random_external_calls_have_no_silent_misses(chunk):
    silent, through, runs = [], 0, 0
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000, RSI: seed % 20}
    for seed in range(chunk * 50, (chunk + 1) * 50):
        results = _analyze(_random_caller(random.Random(33_000 + seed)))
        assert results["1:1000"].declared
        report = _check(results, seeds=range(4), pools=pools)
        runs += report.runs
        through += report.through_calls
        silent += [(seed, item) for item in report.silent]
    assert runs and through
    assert silent == [], silent[:3]
