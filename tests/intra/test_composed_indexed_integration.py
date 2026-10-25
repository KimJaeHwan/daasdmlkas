"""Independent branch features cannot erase index or whole-literal meaning."""
from dataclasses import replace

import pytest

from synthetic import R8, RDI, RDX, RSI, FunctionBuilder, program_units
from tdo_v2.call_summary_effects import (AnchoredSpan, IndexedOffset, ProvenCallEffect,
                                        ProvenMemoryRun, _compose_fixed_memory)
from tdo_v2.constant_value import ExactConstant
from tdo_v2.interprocedural import _register_file
from tdo_v2.span_geometry import ByteSpan


def _effect():
    (unit,) = program_units(FunctionBuilder().ret())
    registers, _ = _register_file(unit.observation, unit.scopes.resolution_context)
    write = AnchoredSpan(ByteSpan(registers, RDX, 8), 0, 8, 1)
    run = ProvenMemoryRun(write, (ByteSpan(registers, RSI, 8),), (), False)
    return ProvenCallEffect("original", (), (), memory_runs=(run,), preserves_memory=True), registers


@pytest.mark.parametrize("other_index", (None, RDI, R8))
def test_indexed_member_never_promoted_to_fixed_bytes(other_index):
    effect, registers = _effect()
    (run,) = effect.memory_runs
    index = IndexedOffset(ByteSpan(registers, R8, 8), None, "identity", 0, 1)
    first = replace(effect, memory_runs=(replace(run, write=replace(run.write, index=index)),))
    second = effect if other_index is None else replace(effect, memory_runs=(replace(
        run, write=replace(run.write, index=replace(index, register=ByteSpan(registers, other_index, 8)))),))
    sources = {}
    assert _compose_fixed_memory(effect, ((0, first), (1, second)), sources) is effect
    assert not sources


def test_unpromoted_indexed_original_run_is_not_replaced_by_fixed_grid():
    effect, registers = _effect()
    (run,) = effect.memory_runs
    index = IndexedOffset(ByteSpan(registers, R8, 8), None, "identity", 0, 1)
    indexed = replace(run, write=replace(run.write, index=index))
    original = replace(effect, memory_runs=(indexed,))
    merged = _compose_fixed_memory(original, ((0, effect), (1, effect)))
    assert indexed in merged.memory_runs
    assert any(row.write.index is None for row in merged.memory_runs)


def test_partial_replacement_drops_whole_width_literal_and_pointer_claim():
    effect, _ = _effect()
    (run,) = effect.memory_runs
    literal = ExactConstant(8, 0x8877665544332211)
    original = replace(effect, memory_runs=(replace(run, literal=literal, value=("nonstack",)),))
    four = replace(effect, memory_runs=(replace(run, write=replace(run.write, size=4)),))
    merged = _compose_fixed_memory(original, ((0, four), (1, four)))
    tail = next(row for row in merged.memory_runs if row.write.displacement == 4)
    assert tail.write.size == 4 and tail.literal is None and tail.value is None
    assert original.memory_runs[0].literal == literal  # Input remains unchanged.
