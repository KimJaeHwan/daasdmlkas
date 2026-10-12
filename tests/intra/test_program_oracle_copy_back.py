"""The program oracle itself (census round 4, Astra): a callee-saved register
pushed and popped through memory keeps its pre-call writer in the
interpreter (exact copy sources through COPY / LOAD / STORE), so the oracle
needs no trust in preservation claims -- and still catches a false one."""

import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    CODE_BASE, R9, RAX, RBX, REG, RSI, RSP, FunctionBuilder, copy, operation_node_at, program_units, reg,
    slice_from,
)
from tdo_v2.interprocedural import analyze_units

KEEPER, CONSUMER = CODE_BASE + 0x800, CODE_BASE + 0xA00


def _keeper(clobber=False):
    builder = FunctionBuilder(entry=KEEPER).push(RBX).pop(RBX)
    if clobber:
        builder.ins(copy(reg(RBX), reg(RSI)))
    return builder.ret()


def _program(clobber=False):
    consumer = FunctionBuilder(entry=CONSUMER).ins(copy(reg(RAX), reg(RBX))).ret()
    caller = (FunctionBuilder().sub_rsp(0x28)
              .call(KEEPER)
              .call(CONSUMER)
              .ins(copy(reg(R9), reg(RAX)))                                                  # instruction 3
              .add_rsp(0x28).ret())
    return caller, _keeper(clobber), consumer


def _check(observed):
    units = program_units(*_program())
    analyzed = analyze_units(units)["1:1000"]
    function = analyzed.normalized
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in observed}
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    report = check_program(function, analyzed.unit.observation, program, seeds=range(4), register_pools=pools,
                           havoc_calls=(REG, RSP, 8))
    return function, report


def test_a_push_and_pop_through_memory_is_no_false_miss():
    function, report = _check(program_units(*_program()))
    reload = slice_from(function, operation_node_at(function, 3, 0))
    assert reload.is_complete and set(range(RBX, RBX + 8)) <= reload.register_bytes
    assert report.runs and report.silent == [] and report.covered_by_debt == []


def test_a_false_preservation_claim_is_caught():
    """The engine analyzed keeper as push/pop; the program run then also sets
    rbx = rsi: r9 = rsi, which the (now wrong) graph does not reach."""
    _, report = _check(program_units(*_program(clobber=True)))
    assert report.runs and report.silent
