"""Use-after-return candidates (docs 25.80 R2/R3): a report of where a value
derived from the entry stack pointer may leave the function -- with its
offset from the entry stack pointer when exact -- never a claim."""

from synthetic import DATA_BASE, RAX, RCX, RSP, FunctionBuilder, add, const, copy, op, program_units, ram, reg
from tdo_v2.interprocedural import analyze_units
from tdo_v2.may_alias import stack_leaks


def _leaks(builder):
    item = analyze_units(program_units(builder))["1:1000"]
    return stack_leaks(item.normalized, item.unit.observation)


def test_a_frame_address_stored_to_a_global_is_reported_with_its_offset():
    builder = FunctionBuilder().sub_rsp(0x28).ins(add(reg(RAX), reg(RSP), const(0x10)),
                                                  copy(ram(DATA_BASE + 0x40), reg(RAX))).add_rsp(0x28).ret()
    leaks = _leaks(builder)
    # (rax still holds it at the RETURN: reported too)
    assert [(kind, offset) for _, kind, offset in leaks] == [("store", -0x28 + 0x10), ("return", None)]


def test_a_returned_frame_address_is_reported():
    builder = FunctionBuilder().sub_rsp(0x28).ins(add(reg(RAX), reg(RSP), const(0x10))).add_rsp(0x28).ret()
    assert [kind for _, kind, _ in _leaks(builder)] == ["return"]


def test_a_function_keeping_no_stack_address_reports_nothing():
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RAX), reg(RCX)),
                                                  copy(ram(DATA_BASE + 0x40), reg(RAX))).add_rsp(0x28).ret()
    assert _leaks(builder) == ()


def test_another_memory_output_has_no_offset():
    """ram[x] = rsp ^ 8 (a memory output of another operation): reported,
    with no offset (the written value is the result, not an input)."""
    builder = FunctionBuilder().sub_rsp(0x28).ins(op("INT_XOR", [reg(RSP), const(8)], ram(DATA_BASE + 0x40)))
    builder.add_rsp(0x28).ret()
    assert [(kind, offset) for _, kind, offset in _leaks(builder)] == [("store", None)]
