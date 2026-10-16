"""The program oracle runs modeled externals with the binary's convention
(``Interpreter(external_abi=...)``): a System V binary's memcpy takes rdi,
rsi, rdx and returns rdi. Run with the win64 convention, the oracle reported
silent misses the engine did not have (zlib: 256 bytes, docs 25.29)."""

from pathlib import Path

import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    CODE_BASE, DATA_BASE, R8, R9, RAX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const, copy, load,
    program_units, reg,
)
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import load_external_models

MODELS = sorted((Path(__file__).resolve().parents[2] / "models" / "external").glob("*.json"))
MEMCPY = CODE_BASE + 0xE00
HAVOC = (REG, RSP, 8)


def _memcpy_caller():
    """memcpy(dst = rsp+0x20, src = DATA, 8); r8 = the returned pointer (as
    zlib's caller copies it); r9 = its first qword (the copied bytes)."""
    builder = (FunctionBuilder().sub_rsp(0x48)
               .ins(add(reg(RDI), reg(RSP), const(0x20)))
               .ins(copy(reg(RSI), const(DATA_BASE + 0x40)))
               .ins(copy(reg(RDX), const(8)))
               .call(MEMCPY)
               .ins(copy(reg(R8), reg(RAX)))
               .ins(load(reg(R9), reg(RAX)))
               .add_rsp(0x48).ret())
    image = ImageInfo("synthetic", (), (ImportedSymbol("libc.so.6", "memcpy", None, (), ((1, MEMCPY),)),), (), ())
    results = analyze_units(program_units(builder), image_info=image,
                            external_models=load_external_models(MODELS, "x86:LE:64:default", "sysv64"))
    return results["1:1000"]


def _silent(analyzed, abi):
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    report = check_program(analyzed.normalized, analyzed.unit.observation, {}, seeds=range(4),
                           register_pools=pools, havoc_calls=HAVOC,
                           externals={(1, MEMCPY): "memcpy"}, external_abi=abi)
    assert report.runs and report.through_calls
    return report.silent


def test_a_sysv_memcpy_runs_with_the_sysv_convention():
    analyzed = _memcpy_caller()
    ((call, label),) = analyzed.declared.items()
    assert label.startswith("external-model:crt-sysv64/memcpy@")
    assert _silent(analyzed, "sysv64") == []


def test_the_win64_convention_on_a_sysv_binary_reports_misses_the_engine_does_not_have():
    """The oracle defect itself: rax taken from rcx, as win64 returns dst."""
    assert _silent(_memcpy_caller(), "win64")


def test_the_lane_oracle_runs_externals_with_the_given_convention_too():
    """``measure_program --models --lanes`` passes the binary's convention to
    the lane oracle as well (Astra, step A review 2)."""
    from lane_oracle import check_lanes

    analyzed = _memcpy_caller()
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    report = check_lanes(analyzed.normalized, analyzed.unit, seeds=range(4), register_pools=pools,
                         havoc_calls=HAVOC, reg_space=REG, externals={(1, MEMCPY): "memcpy"},
                         external_abi="sysv64")
    assert report.checked and report.missing == []
