"""A value read from memory must not feed an address before the read's
reaching definition is settled (census round 2, Astra): the function sets
slot = &x, then rewrites slot = &y through a pointer whose address resolves
only in a later projection pass; p = *slot (directly, or as a callee's
returned value); *p = rsi writes y, not x (``relative_memory.settle_pending``)."""

import pytest

import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    CODE_BASE, R9, RAX, RBX, RCX, RDX, REG, RSI, RSP, FunctionBuilder, add, const, load,
    operation_node_at, program_units, reg, slice_from, store, tmp,
)
from tdo_v2.interprocedural import analyze_units

HELPER = CODE_BASE + 0x800
HAVOC = (REG, RSP, 8)


def _program(through_call):
    helper = FunctionBuilder(entry=HELPER).ins(load(reg(RAX), reg(RCX))).ret()
    t, u = tmp(0x100), tmp(0x200)
    caller = (FunctionBuilder().sub_rsp(0x80)
              .ins(add(t, reg(RSP), const(0x48)), store(t, reg(RBX)))                          # y = rbx
              .ins(add(t, reg(RSP), const(0x20)), add(u, reg(RSP), const(0x40)), store(t, u))  # slot = &x
              .ins(add(t, reg(RSP), const(0x28)), add(u, reg(RSP), const(0x20)), store(t, u))  # pslot = &slot
              .ins(add(t, reg(RSP), const(0x30)), add(u, reg(RSP), const(0x28)), store(t, u))  # ppslot = &pslot
              .ins(add(t, reg(RSP), const(0x30)), load(reg(RDX), t))
              .ins(load(reg(RDX), reg(RDX)))
              .ins(add(u, reg(RSP), const(0x48)), store(reg(RDX), u))                          # slot = &y
              .ins(add(reg(RCX), reg(RSP), const(0x20))))
    if through_call:
        caller.call(HELPER)                                                                    # rax = *slot
    else:
        caller.ins(load(reg(RAX), reg(RCX)))
    (caller.ins(store(reg(RAX), reg(RSI)))                                                     # y = rsi
           .ins(add(t, reg(RSP), const(0x48)), load(reg(R9), t))                               # r9 = y
           .add_rsp(0x80).ret())
    return (caller, helper) if through_call else (caller,)


@pytest.mark.parametrize("through_call", [False, True])
def test_a_slot_rewritten_through_a_late_address_is_not_missed(through_call):
    units = program_units(*_program(through_call))
    analyzed = analyze_units(units)["1:1000"]
    function = analyzed.normalized
    reload = slice_from(function, operation_node_at(function, 11, 1))
    assert set(range(RSI, RSI + 8)) <= reload.register_bytes or not reload.is_complete
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    report = check_program(function, analyzed.unit.observation, program, seeds=range(6),
                           register_pools=pools, havoc_calls=HAVOC)
    assert report.silent == []
