"""Adversarial checks of exact identities used by bitwise pointer expressions.

Use actual validated operations and the memory SSA projector. These tests
exercise identity admission and metadata, not a second symbolic evaluator.
"""

from dataclasses import replace

import pytest

from synthetic import RAM, RDI, RDX, RSP, FunctionBuilder, const, normalize_with_observation, op, reg, store, tmp
from tdo_v2.opaque_values import OpaqueValueEvidenceResolver
from tdo_v2.relative_memory import ImageBaseTracking, _final_projector, _operation_key


BITWISE = ("INT_AND", "INT_OR", "INT_XOR")
SHIFTS = ("INT_RIGHT", "INT_SRIGHT")


def _projector(*operations):
    builder = FunctionBuilder()
    for operation in operations:
        builder.ins(operation)
    builder.ret()
    normalized, observation = normalize_with_observation(builder)
    projector = _final_projector(normalized, observation)
    rows = [(_operation_key(instruction.address, ordinal, operation), operation)
            for instruction in observation.instructions[:-1]
            for ordinal, operation in enumerate(instruction.operations)]
    return projector, rows


def _expression(opcode, left, right, size=8):
    projector, ((key, operation),) = _projector(op(opcode, [left, right], tmp(0x100, size)))
    return projector, projector._bitwise_expression(key, operation, size)


@pytest.mark.parametrize("opcode", SHIFTS)
@pytest.mark.parametrize("size,value", ((1, 0x81), (4, 0x80000001), (8, 0x8000000000000001)))
@pytest.mark.parametrize("count_kind", ("zero", "last", "width", "past-width", "huge"))
def test_constant_shift_folding_uses_pcode_counts_not_isa_count_mask(opcode, size, value, count_kind):
    bits = 8 * size
    count = {"zero": 0, "last": bits - 1, "width": bits,
             "past-width": bits + 1, "huge": (1 << 63) - 1}[count_kind]
    _, expression = _expression(opcode, const(value, size), const(count, 8), size)
    number = value - (1 << bits) if opcode == "INT_SRIGHT" else value
    expected = (number >> min(count, bits)) & ((1 << bits) - 1)
    assert expression is not None and not expression.atoms
    assert expression.displacement == expected and expression.byte_size == size


@pytest.mark.parametrize("opcode,expected", (("INT_RIGHT", 0), ("INT_SRIGHT", 0xff)))
def test_shift_count_is_unsigned_at_its_own_width(opcode, expected):
    # 0xff in a one-byte count is 255, not -1 or the x86 count 7.
    _, expression = _expression(opcode, const(0x80, 1), const(0xff, 1), 1)
    assert expression is not None and expression.displacement == expected


@pytest.mark.parametrize("opcode", SHIFTS)
@pytest.mark.parametrize("count_size", (1, 4, 8))
def test_shift_count_may_have_a_different_width(opcode, count_size):
    _, expression = _expression(opcode, const(0x80000001, 4), const(1, count_size), 4)
    assert expression is not None and not expression.atoms
    assert expression.displacement == (0xc0000000 if opcode == "INT_SRIGHT" else 0x40000000)


@pytest.mark.parametrize("opcode", SHIFTS)
@pytest.mark.parametrize("count_size", (1, 4, 8))
def test_nonconstant_count_uses_the_actual_count_read_and_width(opcode, count_size):
    projector, expression = _expression(opcode, reg(RDI), reg(RDX, count_size))
    assert expression is not None and len(expression.atoms) == 1
    object_id = projector._relative_object(expression, RAM, width=1)
    assert object_id in projector.wild_objects


@pytest.mark.parametrize("opcode", BITWISE + SHIFTS)
def test_left_input_width_must_match_result(opcode):
    _, expression = _expression(opcode, const(0x80, 4), const(1, 8), 8)
    assert expression is None


@pytest.mark.parametrize("opcode", BITWISE)
def test_bitwise_right_input_width_must_match_result(opcode):
    _, expression = _expression(opcode, reg(RDI, 8), const(0xff, 4), 8)
    assert expression is None


@pytest.mark.parametrize("opcode", ("INT_XOR", "INT_SUB", "BOOL_XOR"))
def test_self_cancellation_does_not_bypass_result_width_validation(opcode):
    projector, ((key, operation),) = _projector(op(opcode, [reg(RDI, 4), reg(RDI, 4)], tmp(0x100, 8)))
    assert projector._expression_for_operation(key, operation, 0, 8) is None


@pytest.mark.parametrize("opcode,expected", (("INT_AND", 0x05), ("INT_OR", 0xaf), ("INT_XOR", 0xaa)))
def test_constant_bitwise_values_remain_exact_without_index_mode(monkeypatch, opcode, expected):
    monkeypatch.setenv("TDO_V2_INDEX_ADDRESSES", "0")
    _, expression = _expression(opcode, const(0xa5, 1), const(0x0f, 1), 1)
    assert expression is not None and not expression.atoms
    assert expression.displacement == expected


def test_equal_expressions_share_an_atom_but_opcode_mask_width_and_order_do_not():
    shapes = (("INT_AND", reg(RDI), const(0xff), 8),
              ("INT_OR", reg(RDI), const(0xff), 8),
              ("INT_AND", reg(RDI), const(0x7f), 8),
              ("INT_AND", const(0xff), reg(RDI), 8),
              ("INT_AND", reg(RDI, 4), const(0xff, 4), 4),
              ("INT_AND", reg(RDI), const(0xff), 8))
    projector, rows = _projector(*(op(code, [left, right], tmp(0x100 * (index + 1), size))
                                  for index, (code, left, right, size) in enumerate(shapes)))
    expressions = [projector._bitwise_expression(key, operation, size)
                   for (key, operation), (_, _, _, size) in zip(rows, shapes)]
    assert all(expression is not None for expression in expressions)
    assert expressions[0] == expressions[-1]
    assert len({expression.atoms for expression in expressions[:-1]}) == 5


class _SameTokenProvider:
    def identity_token(self, translation_namespace, operation):
        return "INT_AND"


def test_builtin_atom_domain_is_separate_from_a_provider_using_the_same_token():
    projector, ((key, operation),) = _projector(op("INT_AND", [reg(RDI), const(0xff)], tmp(0x100)))
    builtin = projector._bitwise_expression(key, operation, 8)
    projector._opaque_values = OpaqueValueEvidenceResolver(_SameTokenProvider())
    # The provider certifies a different, otherwise unhandled deterministic
    # operation with the same input expressions and even the same text token.
    provider = projector._expression_for_operation(key, replace(operation, opcode="INT_DIV"), 0, 8)
    assert builtin is not None and provider is not None
    assert builtin.atoms != provider.atoms


@pytest.mark.parametrize("opcode", BITWISE + SHIFTS)
def test_index_switch_refuses_nonconstant_identity(monkeypatch, opcode):
    monkeypatch.setenv("TDO_V2_INDEX_ADDRESSES", "0")
    _, expression = _expression(opcode, reg(RDI), const(1))
    assert expression is None


@pytest.mark.parametrize("opcode", BITWISE + SHIFTS)
@pytest.mark.parametrize("source", (RDI, RSP))
def test_bitwise_entry_addresses_are_wild_and_preserve_stack_derivation(opcode, source):
    projector, expression = _expression(opcode, reg(source), const(0xff))
    assert expression is not None and len(expression.atoms) == 1
    atom = expression.atoms[0][0]
    assert atom in projector._boundary
    object_id = projector._relative_object(expression, RAM, width=1)
    assert object_id in projector.wild_objects
    assert projector._is_stack_derived(atom) is (source == RSP)
    assert object_id not in projector.fresh_objects
    assert object_id not in projector.nonstack_objects
    assert not projector.nonstack_spans


@pytest.mark.parametrize("opcode", BITWISE + SHIFTS)
@pytest.mark.parametrize("symbolic", (False, True))
def test_image_dependency_survives_constant_and_symbolic_bit_operations(opcode, symbolic):
    projector, ((key, operation),) = _projector(
        op(opcode, [reg(RDI) if symbolic else const(0x80), const(0x2000)], tmp(0x100)))
    tracking = ImageBaseTracking(((0x2000, 0x2fff),),
                                 lambda address, length, value: value == 0x2000)
    with tracking as found:
        expression = projector._bitwise_expression(key, operation, 8)
        assert expression is not None and expression.image is None
        if symbolic:
            projector._relative_object(expression, RAM, width=1)
            assert projector._ssa.function_scope.digest in found


def test_unknown_input_operation_is_not_upgraded_to_a_bitwise_identity():
    unknown, masked = tmp(0x100), tmp(0x200)
    projector, rows = _projector(op("INT_DIV", [reg(RDI), reg(RDX)], unknown),
                                 op("INT_AND", [unknown, const(0xff)], masked),
                                 store(reg(RDI), masked))
    key, operation = rows[1]
    assert projector._bitwise_expression(key, operation, 8) is None
