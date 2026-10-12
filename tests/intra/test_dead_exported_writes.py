"""A dead store to an exported object (census RC-A8): the callee writes
*rdx = rdi, then *rcx = rsi and *rcx = r8 -- the first *rcx write is dead
(covered by the second on every path), so it is in no run, but it still
may alias *rdx. Had it landed on *rdx, the covering write lands there too,
and that one is exported: the caller's may-alias of it covers the overlap,
so the callee's summary stays usable."""

import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    CODE_BASE, R8, R9, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const, load,
    operation_node_at, program_units, reg, slice_from, store, tmp,
)
from tdo_v2.interprocedural import analyze_units

CALLEE = CODE_BASE + 0x800
HAVOC = (REG, RSP, 8)


def _callee():
    return (FunctionBuilder(entry=CALLEE)
            .ins(store(reg(RDX), reg(RDI)))
            .ins(store(reg(RCX), reg(RSI)))
            .ins(store(reg(RCX), reg(R8)))
            .ret())


def _caller(same):
    """b = rbx; callee(&a or &b, &b); r9 = b."""
    t = tmp(0x100)
    first = 0x38 if same else 0x30
    return (FunctionBuilder().sub_rsp(0x48)
            .ins(add(t, reg(RSP), const(0x38)), store(t, reg(RBX)))
            .ins(add(reg(RCX), reg(RSP), const(first)))
            .ins(add(reg(RDX), reg(RSP), const(0x38)))
            .call(CALLEE)
            .ins(add(t, reg(RSP), const(0x38)), load(reg(R9), t))
            .add_rsp(0x48).ret())


def _run(same):
    units = program_units(_caller(same), _callee())
    results = analyze_units(units)
    analyzed = results["1:1000"]
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    report = check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=range(6),
                           register_pools=pools, havoc_calls=HAVOC)
    function = analyzed.normalized
    return slice_from(function, operation_node_at(function, 5, 1)), results, report


def test_a_dead_store_does_not_spoil_the_summary():
    reload, _, report = _run(same=False)
    assert reload.is_complete and set(range(RDI, RDI + 8)) <= reload.register_bytes
    assert not set(range(RSI, RSI + 8)) & reload.register_bytes
    assert report.silent == []


def test_a_dead_store_on_the_same_object_is_still_seen():
    """&a == &b: b ends as r8 (the covering write), which the caller's
    may-alias of the exported write reaches."""
    reload, _, report = _run(same=True)
    assert set(range(R8, R8 + 8)) <= reload.register_bytes
    assert report.silent == []
