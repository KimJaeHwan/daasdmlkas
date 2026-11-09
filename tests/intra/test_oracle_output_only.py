"""The program oracle runs output-only user ops by its OWN table (pcode_interpreter.ORACLE_OUTPUT_ONLY), not the
engine's (Astra review round 4): a refined result keeps ordinary operand provenance across a call, flags kept by
the op are not attributed to it, and an engine refinement the oracle does not share shows up as a miss."""

import pytest

import test_graph_fidelity as fidelity
from pcode_interpreter import ORACLE_OUTPUT_ONLY
from program_oracle import check_program
from synthetic import (
    CODE_BASE, RAX, REG, RSI, RSP, ZF, FunctionBuilder, const, copy, op, program_units, reg,
)
from tdo_v2.interprocedural import analyze_units

CALLEE = CODE_BASE + 0x800
XMM0, XMM1 = reg(0x1200, 16), reg(0x1240, 16)
PSHUFLW = op("CALLOTHER", [const(157, 4), XMM0, XMM1, const(0x1B, 8)], XMM0)
TABLE = ORACLE_OUTPUT_ONLY[("x86:LE:64:default", 4, 6)]


def _check(caller, *others, table=TABLE):
    units = program_units(caller, *others)
    analyzed = analyze_units(units)["1:1000"]
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    return check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=range(4),
                         register_pools=pools, havoc_calls=(REG, RSP, 8), output_only_userops=table)


def test_a_refined_result_read_by_the_caller_keeps_operand_provenance():
    callee = FunctionBuilder(entry=CALLEE).ins(copy(XMM1, reg(RSI, 16))).ins(PSHUFLW).ret()
    caller = FunctionBuilder().sub_rsp(0x28).call(CALLEE).ins(copy(reg(RAX), reg(0x1200, 8))).add_rsp(0x28).ret()
    report = _check(caller, callee)
    assert report.runs and report.silent == []


@pytest.mark.parametrize("shared", (True, False))
def test_flags_kept_across_the_op_and_an_unshared_refinement_is_caught(shared):
    caller = (FunctionBuilder().ins(copy(reg(ZF, 1), const(1, 1))).ins(PSHUFLW)
              .ins(copy(reg(RAX, 1), reg(ZF, 1))).ret())
    report = _check(caller, table=TABLE if shared else {})
    assert report.runs
    if shared:
        assert report.silent == [] and report.covered_by_debt == []
    else:   # the engine keeps ZF across pshuflw; an oracle without the entry havocs it: a visible disagreement
        assert report.silent or report.covered_by_debt


@pytest.mark.parametrize("ops, expected", (
    ([PSHUFLW], True),
    ([op("CALLOTHER", [const(157, 4), XMM1, XMM1, const(0x1B, 8)], XMM0)], False),   # destination not first
    ([op("CALLOTHER", [const(483, 4), reg(0x1200, 32), reg(0x1240, 32)], {"kind_code": 3, "space_id": 3,
                                                                           "byte_offset": 0x500, "byte_size": 32})],
     True),                                                                           # vpcmpeqw: a temporary
    ([op("CALLOTHER", [const(483, 4), reg(0x1200, 32), reg(0x1240, 32)], reg(0x1200, 32))], False),
))
def test_the_oracle_table_checks_operand_shape_independently(ops, expected):
    # (Astra review round 5) output kind and the destination-first relation, not sizes only
    from pcode_interpreter import Interpreter

    unit, = program_units(FunctionBuilder().ins(*ops).ret())
    operation = unit.observation.instructions[0].operations[0]
    probe = Interpreter.__new__(Interpreter)
    probe._output_only_userops = TABLE
    assert Interpreter._output_only(probe, operation.inputs, operation.output) is expected
