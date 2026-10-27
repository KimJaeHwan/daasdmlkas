"""Shadow chi memory SSA (docs 25.83): opaque calls as definitions whose
sources are the pre-call definitions per fragment reproduce call_clobber's
calls crossed and the production SSA's origins, byte by byte."""

import pytest

from synthetic import (
    CODE_BASE, DATA_BASE, R8, R9, RAX, RBX, RCX, RDX, RSI, RSP, FunctionBuilder, add, const, copy, load, op,
    program_units, reg, store, tmp,
)
from tdo_v2 import _chi_shadow
from tdo_v2.interprocedural import analyze_units

OPAQUE_A, OPAQUE_B = CODE_BASE + 0xE00, CODE_BASE + 0xE10
T, FLAG = tmp(0x100), tmp(0x300, 1)


@pytest.fixture(autouse=True)
def shadow(monkeypatch):
    monkeypatch.setenv("TDO_V2_CHI_SHADOW", "1")
    _chi_shadow.RESULTS.clear()
    _chi_shadow.TERMINAL_MISMATCHES.clear()
    yield
    _chi_shadow.RESULTS.clear()
    _chi_shadow.TERMINAL_MISMATCHES.clear()


def _checked(builder):
    analyze_units(program_units(builder))
    assert _chi_shadow.RESULTS
    for scope, found in _chi_shadow.RESULTS.items():
        assert found == [], found
    assert _chi_shadow.TERMINAL_MISMATCHES   # (check (c) ran)
    for scope, found in _chi_shadow.TERMINAL_MISMATCHES.items():
        assert found == [], found


def _frame(builder, offset, value):
    return builder.ins(add(T, reg(RSP), const(offset)), store(T, value))


def _read(builder, offset, out=R9, width=8):
    return builder.ins(add(T, reg(RSP), const(offset)), load(reg(out, width), T))


def test_two_calls_in_one_block():
    builder = _frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI)).call(OPAQUE_A)
    builder = _frame(_read(builder, 0x10), 0x18, reg(RDX)).call(OPAQUE_B)
    _checked(_read(_read(builder, 0x10, RBX), 0x18).add_rsp(0x48).ret())


def test_a_partial_overwrite_between_calls():
    """CALL A; [0x10..0x18) = rdx; CALL B; read: B only on the rewritten bytes."""
    builder = _frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI)).call(OPAQUE_A)
    builder = _frame(builder, 0x10, reg(RDX, 4)).call(OPAQUE_B)
    _checked(_read(builder, 0x10).add_rsp(0x48).ret())


def test_a_branch_and_a_loop():
    builder = _frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI))
    builder.cbranch("skip", FLAG, op("INT_EQUAL", [reg(RCX), const(0)], FLAG)).call(OPAQUE_A).label("skip")
    builder.label("top")
    builder = _read(builder, 0x10).call(OPAQUE_B)
    builder = _frame(builder, 0x18, reg(R8))
    builder.cbranch("top", FLAG, op("INT_EQUAL", [reg(RDX), const(0)], FLAG))
    _checked(_read(_read(builder, 0x10, RBX), 0x18).add_rsp(0x48).ret())


def test_globals_and_registers():
    builder = (FunctionBuilder().sub_rsp(0x28).ins(store(const(DATA_BASE + 0x40), reg(RBX)))
               .ins(copy(reg(RAX), reg(RSI))).call(OPAQUE_A)
               .ins(load(reg(R9), const(DATA_BASE + 0x40)), copy(reg(RDX), reg(RAX))).add_rsp(0x28).ret())
    _checked(builder)


def test_a_user_op_output_is_written_after_its_clobber():
    """rax = CALLOTHER(rsi); r9 = rax: the op's own output is no clobbered byte
    (call_clobber: reads, then the call, then the op's writes)."""
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(op("CALLOTHER", [const(7, 4), reg(RSI)], reg(RAX)))
               .ins(copy(reg(R9), reg(RAX))).add_rsp(0x28).ret())
    _checked(builder)
