"""A callee returning an entry register's value + c (docs 25.80 R1): its
summary states ("offset", span, c) and the caller takes its own value of that
register + c -- no atom of the call's, so the row needs no
pre-escape-values-do-not-address-the-new-frame. Never for the callee's stack
pointer (directly or copied: its entry value is the caller's minus the push),
never for other arithmetic (an XOR may rebuild a frame address)."""

import pytest

from synthetic import (
    CODE_BASE, R9, RAX, RCX, RDI, RDX, RSI, RSP, FunctionBuilder, add, const, copy, load, op, program_units, reg,
    store, tmp,
)
from test_constant_summary_values import REGISTERS, _run, _template
from tdo_v2.interprocedural import analyze_units
from tdo_v2.span_geometry import ByteSpan
from tdo_v2.summary_templates import TemplateError, instantiate

CALLEE = CODE_BASE + 0x800
T = tmp(0x100)


def _callee(*body):
    return FunctionBuilder(entry=CALLEE).ins(*body).ret()


def _run_value(callee):
    results = analyze_units(program_units(FunctionBuilder().call(CALLEE).ret(), callee))
    summary = results[f"1:{CALLEE:x}"].summary
    return {run.value for item in summary.exits for run in item.runs
            if run.span.object_id.kind.value == "register_file" and run.span.start == RAX and run.span.size == 8}


def test_an_entry_register_plus_a_constant_is_stated():
    (value,) = _run_value(_callee(add(reg(RAX), reg(RCX), const(8))))
    assert value[0] == "offset" and value[1].start == RCX and value[1].size == 8 and value[2] == 8


@pytest.mark.parametrize("body", [
    (add(reg(RAX), reg(RSP), const(8)),),                                   # lea rax, [rsp + 8]
    (copy(reg(RDX), reg(RSP)), add(reg(RAX), reg(RDX), const(16))),         # the stack pointer copied
    (op("INT_XOR", [reg(RCX), const(5)], reg(RAX)),),                       # other arithmetic
    (add(T, reg(RCX), const(0)), load(reg(RAX), T)),                        # a memory read
])
def test_no_relation_for_the_stack_pointer_or_other_values(body):
    assert not any(value is not None and value[0] == "offset" for value in _run_value(_callee(*body)))


def _caller():
    """[rsp + 0x10] = 0; rcx = [rdi]; rax = callee(rcx); [rax] = rsi;
    r9 = [rsp + 0x10] (a frame read the write through rax must not reach)."""
    return (FunctionBuilder().sub_rsp(0x28).ins(add(T, reg(RSP), const(0x10)), store(T, const(0, 8)))
            .ins(load(reg(RCX), reg(RDI))).call(CALLEE)
            .ins(store(reg(RAX), reg(RSI)))
            .ins(add(T, reg(RSP), const(0x10)), load(reg(R9), T)).add_rsp(0x28).ret())


def test_the_call_row_needs_no_pre_escape_assumption():
    """rcx + 8: the write's address is the caller's own value + 8 (the base
    rule keeps it out of the frame); rcx ^ 5: the call row's value, kept out
    only by pre-escape-values-do-not-address-the-new-frame."""
    offset = analyze_units(program_units(_caller(), _callee(add(reg(RAX), reg(RCX), const(8)))))["1:1000"]
    xor = analyze_units(program_units(_caller(), _callee(op("INT_XOR", [reg(RCX), const(5)], reg(RAX)))))["1:1000"]
    assert not any("~" in key for key in offset.normalized.pre_escape_definitions)
    assert not offset.normalized.assumes_pre_escape_values_not_frame
    assert any("CALL~" in key for key in xor.normalized.pre_escape_definitions)
    builder = _caller()
    rows = builder._rows
    write = next(f"1:{builder.entry + builder.stride * index:x}:0:STORE" for index, row in enumerate(rows)
                 if row.ops and row.ops[-1][0] == "STORE" and row.ops[-1][1][-1] == reg(RSI))
    read = next(f"1:{builder.entry + builder.stride * index:x}:1:LOAD" for index, row in enumerate(rows)
                if row.ops and row.ops[-1][0] == "LOAD" and row.ops[-1][2] == reg(R9))
    for item in (offset, xor):   # (the write reaches the frame read in neither)
        assert not any(write in row.writers for row in item.normalized.may_alias_reads if row.operation_key == read)


def test_template_round_trip_and_refusals():
    value = ("offset", ByteSpan(REGISTERS, RCX, 8), 8)
    raw = _template(_run(literal=None, value=value))
    summary, _ = instantiate(raw, "test", REGISTERS, 1)
    assert summary.exits[0].runs[0].value == value
    for bad in (-1, 1 << 64, True):
        broken = _template(_run(literal=None, value=value))
        broken["exits"][0]["runs"][0]["value"][2] = bad
        with pytest.raises(TemplateError):
            instantiate(broken, "test", REGISTERS, 1)


def test_an_activation_seed_gives_no_relation():
    """Under an activation (rdx = rcx + 8 seeded), rax = rdx states no offset:
    the seed relates entry values for that activation only."""
    from tdo_v2._activation_entry import ActivationEntry, using_entry
    from tdo_v2.function_summary import _offset_values

    results = analyze_units(program_units(FunctionBuilder().call(CALLEE).ret(), _callee(copy(reg(RAX), reg(RDX)))))
    item = results[f"1:{CALLEE:x}"]
    normalized = item.normalized
    register = next(run.span.object_id for exit_summary in item.summary.exits for run in exit_summary.runs
                    if run.span.object_id.kind.value == "register_file")
    seed = ActivationEntry(normalized.memory_ssa.function_scope, ("caller", "call"),
                           ((ByteSpan(register, RDX, 8), ByteSpan(register, RCX, 8), 8),), (), ("proof",))
    with using_entry(seed):
        exits = _offset_values(normalized, item.unit.observation, item.summary.exits)
    assert not any(run.value is not None and run.value[0] == "offset" for exit_summary in exits
                   for run in exit_summary.runs)
