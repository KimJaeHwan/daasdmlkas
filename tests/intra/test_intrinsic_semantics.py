"""Value-rule proofs; ISA side-effect and translator identity are separate obligations."""

import pytest
import z3

from tdo_v2.intrinsic_semantics import packed_equality_semantics


SIGNATURE = dict(language=("x86:LE:64:default", 4, 6), userop_index=483,
                 userop_name="vpcmpeqw_avx2", input_byte_sizes=(32, 32), output_byte_size=32)


def _rule():
    rule = packed_equality_semantics(**SIGNATURE)
    assert rule is not None
    return rule


def _lower(left, right):
    return _rule().lower(left, right, extract=lambda value, hi, lo: z3.Extract(hi, lo, value),
                         equal=lambda a, b: a == b, select=z3.If, constant=z3.BitVecVal,
                         concat=lambda lanes, bits: z3.Concat(*lanes))


def _unsat(claim):
    solver = z3.Solver()
    solver.set(timeout=10000)
    solver.add(claim)
    assert solver.check() == z3.unsat


def test_lowering_equals_independent_bit_level_isa_reference_for_all_inputs():
    left, right = z3.BitVecs("left right", 256)
    # Reference assigns each result bit from equality of every input bit in
    # its 16-bit word. It does not use the implementation's lane iteration,
    # lane extraction, lane constants, or dependency projection.
    result_bits = []
    for bit in range(255, -1, -1):
        word_start = bit & ~15
        equal_word = z3.And(*(z3.Extract(i, i, left) == z3.Extract(i, i, right)
                              for i in range(word_start, word_start + 16)))
        result_bits.append(z3.If(equal_word, z3.BitVecVal(1, 1), z3.BitVecVal(0, 1)))
    _unsat(_lower(left, right) != z3.Concat(*result_bits))


@pytest.mark.parametrize("lane", range(16))
def test_output_byte_has_only_its_two_operand_word_lanes(lane):
    left, right, disturbance = z3.BitVecs("left right disturbance", 256)
    output_byte = lane * 2 + 1
    assert _rule().input_byte_ranges(output_byte, 1) == ((0, lane * 2, 2), (1, lane * 2, 2))
    inside = 0xffff << (lane * 16)
    outside = ((1 << 256) - 1) ^ inside
    def result(a, b):
        return z3.Extract(output_byte * 8 + 7, output_byte * 8, _lower(a, b))
    _unsat(result(left, right) != result(left ^ (disturbance & outside), right))
    _unsat(result(left, right) != result(left, right ^ (disturbance & outside)))
    # Either byte of either operand word can affect this one output byte.
    for operand in (0, 1):
        for byte_in_word in (0, 1):
            bit = 1 << (lane * 16 + byte_in_word * 8)
            changed = (left ^ bit, right) if operand == 0 else (left, right ^ bit)
            solver = z3.Solver()
            solver.add(result(left, right) != result(*changed))
            assert solver.check() == z3.sat


@pytest.mark.parametrize("byte", range(32))
def test_concrete_evaluation_matches_lowering_and_detects_each_lane_byte(byte):
    left = int.from_bytes(bytes(range(32)), "little")
    right = left ^ (1 << (byte * 8))
    expected = ((1 << 256) - 1) ^ (0xffff << ((byte // 2) * 16))
    assert _rule().evaluate(left, right) == expected
    assert z3.simplify(_lower(z3.BitVecVal(left, 256), z3.BitVecVal(right, 256))).as_long() == expected


def test_zero_and_all_ones_inputs_and_multi_lane_range():
    full = (1 << 256) - 1
    assert _rule().evaluate(0, 0) == full
    assert _rule().evaluate(full, full) == full
    assert _rule().evaluate(0, full) == 0
    assert _rule().input_byte_ranges(1, 2) == ((0, 0, 4), (1, 0, 4))
    assert _rule().input_byte_ranges(0, 32) == ((0, 0, 32), (1, 0, 32))


@pytest.mark.parametrize("field,value", [
    ("language", ("x86:LE:32:default", 4, 6)), ("language", ("x86:LE:64:default", 4, 7)),
    ("language", ("x86:LE:64:default", True, 6)), ("language", ["x86:LE:64:default", 4, 6]),
    ("userop_index", 482), ("userop_index", True), ("userop_name", "vpcmpeqw_avx"),
    ("userop_name", ""), ("input_byte_sizes", (16, 16)), ("input_byte_sizes", (32,)),
    ("input_byte_sizes", (4, 32, 32)), ("input_byte_sizes", [32, 32]),
    ("output_byte_size", 16), ("output_byte_size", True),
])
def test_unknown_identity_or_shape_refuses(field, value):
    assert packed_equality_semantics(**{**SIGNATURE, field: value}) is None


@pytest.mark.parametrize("start,size", [(-1, 1), (0, 0), (32, 1), (31, 2), (True, 1), (0, True)])
def test_invalid_byte_projection_refuses(start, size):
    with pytest.raises(ValueError):
        _rule().input_byte_ranges(start, size)


@pytest.mark.parametrize("value", [-1, 1 << 256, True, 1.0])
def test_no_operand_width_truncation(value):
    with pytest.raises(ValueError):
        _rule().evaluate(value, 0)
    with pytest.raises(ValueError):
        _rule().evaluate(0, value)
