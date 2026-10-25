"""Proven whole register copies retain exact low-byte SUBPIECE semantics."""

from dataclasses import replace

import pytest

from synthetic import (
    RAX, RBX, RDX, RSP, FunctionBuilder, const, copy, load, op, program_units, reg, tmp,
)
from tdo_v2.interprocedural import analyze_units
from tdo_v2.relative_memory import _AddressExpression, _configured_projector, single_execution_keys
from tdo_v2.pcode_blocks import build_pcode_block_graph
from tdo_v2.span_geometry import ByteSpan


@pytest.fixture(autouse=True)
def forward_metadata(monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")


def _fixture(value=None, *, overwrite=False, fragmented=False, split_low=False):
    builder = FunctionBuilder().sub_rsp(0x28)
    if value is not None:
        builder.ins(copy(reg(RBX), const(value)))
    if fragmented:
        builder.ins(copy(reg(RBX, 4), const(0x12345678, 4)))
    if split_low:
        builder.ins(copy(reg(RBX, 1), const(0xA5, 1)))
    builder.call(0x1800)
    if overwrite:
        builder.ins(copy(reg(RAX, 1), const(0xA5, 1)))
    builder.ins(op("INT_SEXT", [reg(RAX, 4)], tmp(0x100)), load(reg(RDX), tmp(0x100)))
    builder.add_rsp(0x28).ret()
    callee = FunctionBuilder(entry=0x1800).ins(copy(reg(RAX), reg(RBX))).ret()
    results = analyze_units(program_units(builder, callee))
    result = results["1:1000"]
    normalized, unit = result.normalized, result.unit
    inputs = normalized.forward_inputs
    operations = {f"{row.address.space_id:x}:{row.address.byte_offset:x}:{i}:{operation.opcode}": operation
                  for row in unit.observation.instructions for i, operation in enumerate(row.operations)}
    projector = _configured_projector(
        inputs.effect_unit, unit.observation, inputs.context, inputs.address_spaces, normalized.memory_ssa,
        operations, "x86:LE:64:default", pointer_rows=dict(normalized.pointer_rows),
        once_keys=single_execution_keys(unit.observation, build_pcode_block_graph(unit.observation,
                                       unit.scopes.function.entry)))
    ((identifier, definition),) = [(i, d) for i, d in enumerate(normalized.memory_ssa.definitions)
                                if d.operation_key in dict(normalized.pointer_rows) and d.span.start == RAX
                                and d.span.size == 8]
    return result, projector, identifier, definition, ByteSpan(definition.span.object_id, RAX, 4)


@pytest.mark.parametrize("value", (0, 1, 0xFFFFFFFF, 0x100000000, 0x1234567887654321, 0xFFFFFFFFFFFFFFFF))
def test_a_constant_low_part_is_exact_and_high_nonzero_low_zero_is_not_fresh(value):
    _, projector, identifier, definition, low = _fixture(value)
    value_expression = projector._expression_for_definition(identifier, low)
    assert value_expression == _AddressExpression((), value & 0xFFFFFFFF, 4)
    assert not projector._fresh_atoms and not projector._nonstack_atoms
    assert projector._expression_for_definition(identifier, definition.span).displacement == value


def test_a_symbolic_low_part_is_the_existing_exact_subpiece_not_a_resized_pointer():
    _, projector, identifier, definition, low = _fixture()
    full = projector._expression_for_definition(identifier, definition.span)
    assert full is not None and full.byte_size == 8 and full.atoms
    expected = projector._boundary_expression("subpiece", full, 4)
    assert projector._expression_for_definition(identifier, low) == expected
    assert expected.byte_size == 4 and expected.atoms != full.atoms
    assert not projector._fresh_atoms and not projector._nonstack_atoms


@pytest.mark.parametrize("width", (1, 2, 4))
def test_known_low_bytes_do_not_require_a_value_for_the_separate_unknown_high_part(width):
    _, projector, identifier, definition, low = _fixture(fragmented=True)
    row = projector._pointer_rows[definition.operation_key]
    assert projector._expression_for_input(row[1], row[2]) is None
    value = projector._expression_for_definition(identifier, replace(low, size=width))
    assert value == _AddressExpression((), 0x12345678 & ((1 << (8 * width)) - 1), width)
    assert not projector._fresh_atoms and not projector._nonstack_atoms


def test_a_split_low_input_is_not_treated_as_one_original_low_definition():
    _, projector, identifier, _, low = _fixture(fragmented=True, split_low=True)
    assert projector._expression_for_definition(identifier, low) is None


def test_template_derivation_keeps_the_existing_conservative_projection():
    from tdo_v2.relative_memory import IMAGE_BASE_TRACKING

    _, projector, _, definition, low = _fixture(fragmented=True)
    assert projector._preserved_register_low(definition, low) is not None
    token = IMAGE_BASE_TRACKING.set(object())
    try:
        assert projector._preserved_register_low(definition, low) is None
    finally:
        IMAGE_BASE_TRACKING.reset(token)


@pytest.mark.parametrize("change", ("BE", "offset", "too-wide", "fresh", "input-width", "mem", "nonstack",
                                    "same-result", "no-index-addresses"))
def test_unproven_slice_contracts_are_refused(change, monkeypatch):
    _, projector, _, definition, low = _fixture()
    key = definition.operation_key
    row = projector._pointer_rows[key]
    if change == "BE":
        projector._translation_namespace = "x86:BE:64:default"
    elif change == "offset":
        low = replace(low, start=low.start + 1)
    elif change == "too-wide":
        low = replace(low, size=16)
    elif change == "fresh":
        projector._pointer_rows[key] = (*row[:3], True, row[4])
    elif change == "input-width":
        projector._pointer_rows[key] = (*row[:2], replace(row[2], byte_size=4), *row[3:])
    elif change == "no-index-addresses":
        monkeypatch.setenv("TDO_V2_INDEX_ADDRESSES", "0")
    else:
        projector._pointer_rows[key] = (change.replace("-", "_"), *row[1:])
    assert projector._preserved_register_low(definition, low) is None


def test_a_partial_overwrite_is_not_replaced_by_the_preserved_whole_register():
    result, projector, _, _, _ = _fixture(0x1122334455667788, overwrite=True)
    operation_key, operation = next((key, op) for key, op in projector._operations.items()
                                    if op.opcode == "INT_SEXT")
    # Two actual reaching definitions (the new byte and the old upper bytes):
    # the projector may refuse but must not resurrect the old low32 constant.
    assert projector._expression_for_input(operation_key, operation.inputs[0]) is None
    (read,) = [read for read in result.normalized.memory_ssa.reads
               if result.normalized.memory_ssa.actions[read.action_id].operation_key == operation_key]
    assert len(read.fragments) == 2


def test_existing_program_oracle_keeps_the_calls_real():
    from program_oracle import check_program
    from synthetic import REG

    caller = (FunctionBuilder().sub_rsp(0x28).call(0x1800)
              .ins(op("INT_ZEXT", [reg(RAX, 4)], reg(RDX)))
              .add_rsp(0x28).ret())
    callee = FunctionBuilder(entry=0x1800).ins(copy(reg(RAX), reg(RBX))).ret()
    units = program_units(caller, callee)
    result = analyze_units(units)["1:1000"]
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    report = check_program(result.normalized, result.unit.observation, program, seeds=range(8),
                           register_pools=lambda seed: {RSP: 0x70000000, RBX: 0x100000000 + seed},
                           havoc_calls=(REG, RSP, 8))
    assert report.runs == 8 and not report.silent and not report.unsupported and report.checked
