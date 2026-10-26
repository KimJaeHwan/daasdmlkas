"""A callee's indexed read of its entry stack (``[SP + RDX]``) may read the
return address the CALL just pushed. The persistent SSA removes that push
(``observed_call_state``), so the caller must not bind such a read to the
pre-call bytes underneath: the read is checked against the push overlay like
an indexed access's base and index inputs (Astra, merge review of the
forward-memory branch: a complete slice missed the real dependency)."""

import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    CODE_BASE, RAX, RBX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const, copy, load, program_units, reg,
    store, sub, tmp,
)
from tdo_v2.interprocedural import analyze_units

CALLEE = CODE_BASE + 0x800


def _program():
    t = tmp(0x100)
    caller = FunctionBuilder().ins(copy(reg(RDX), const(0)), sub(t, reg(RSP), const(8)), store(t, const(0x1400)))
    after = caller._address(len(caller._rows) + 3)   # (the call below is the third row from here)
    caller = (caller.ins(store(const(after + 0x3000), reg(RSI)))
              .ins(store(const(0x1400 + 0x3000), reg(RDI)))
              .call(CALLEE)
              .ins(add(t, reg(RAX), const(0x3000)), load(reg(RBX), t))
              .ret())
    callee = FunctionBuilder(entry=CALLEE).ins(add(tmp(0x200), reg(RSP), reg(RDX)), load(reg(RAX), tmp(0x200))).ret()
    return caller, callee, after


def test_an_indexed_read_of_the_pushed_return_address_is_not_the_pre_call_value():
    caller, callee, _ = _program()
    units = program_units(caller, callee)
    analyzed = analyze_units(units)["1:1000"]
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    report = check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=range(6),
                           register_pools=pools, havoc_calls=(REG, RSP, 8))
    assert report.checked and report.silent == [], report.silent[:4]
