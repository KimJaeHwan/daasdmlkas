"""Narrow, versioned value semantics for independently identified user ops.

This module is not a CALLOTHER purity inference.  A caller must authenticate
the index/name mapping against the translator and separately justify the ISA
instruction's output-only effect.  Value equivalence alone proves neither.
The original observed operation and its operand dependencies must survive
any integration of these rules into a normalized graph.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PackedEqualitySemantics:
    """Little-endian packed equality, each equal lane producing all one bits.

    ``lower`` is backend-parametric: extract(value, high_bit, low_bit),
    equal(left, right), select(condition, yes, no), constant(value, bits),
    concat(high_to_low_values, lane_bits).  No backend may silently truncate
    input widths: the caller supplies exactly ``vector_byte_size`` bytes.
    """

    semantic_id: str
    vector_byte_size: int
    lane_byte_size: int

    def __post_init__(self):
        if not isinstance(self.semantic_id, str) or not self.semantic_id:
            raise ValueError("semantic identity must be nonempty")
        if type(self.vector_byte_size) is not int or type(self.lane_byte_size) is not int \
                or self.lane_byte_size <= 0 or self.vector_byte_size <= 0 \
                or self.vector_byte_size % self.lane_byte_size:
            raise ValueError("packed lanes must partition the vector")

    def lower(self, left, right, *, extract, equal, select, constant, concat):
        bits = self.lane_byte_size * 8
        lanes = []
        for low in range(0, self.vector_byte_size * 8, bits):
            same = equal(extract(left, low + bits - 1, low), extract(right, low + bits - 1, low))
            lanes.append(select(same, constant((1 << bits) - 1, bits), constant(0, bits)))
        return concat(tuple(reversed(lanes)), bits)

    def evaluate(self, left: int, right: int) -> int:
        bound = 1 << (8 * self.vector_byte_size)
        if any(type(value) is not int or not 0 <= value < bound for value in (left, right)):
            raise ValueError("operands must be unsigned vectors of the declared width")

        def concat(lanes, bits):
            result = 0
            for lane in lanes:
                result = (result << bits) | lane
            return result

        return self.lower(left, right,
                          extract=lambda value, hi, lo: (value >> lo) & ((1 << (hi - lo + 1)) - 1),
                          equal=lambda a, b: a == b, select=lambda condition, a, b: a if condition else b,
                          constant=lambda value, bits: value, concat=concat)

    def input_byte_ranges(self, output_start: int, output_size: int) -> tuple[tuple[int, int, int], ...]:
        """(operand ordinal, start byte, size) covering the requested result.

        Operand ordinals exclude CALLOTHER's user-op index.  Both source lanes
        are needed even for one requested output byte.  This is a dependency
        projection, never authorization to discard surrounding memory debts.
        """
        if type(output_start) is not int or type(output_size) is not int or output_start < 0 \
                or output_size <= 0 or output_start + output_size > self.vector_byte_size:
            raise ValueError("output request must be a nonempty contained byte interval")
        first = output_start // self.lane_byte_size * self.lane_byte_size
        end = ((output_start + output_size - 1) // self.lane_byte_size + 1) * self.lane_byte_size
        return ((0, first, end - first), (1, first, end - first))


_VPCMPEQW_AVX2 = PackedEqualitySemantics("x86-vpcmpeqw-avx2-le256-v1", 32, 2)


def packed_equality_semantics(*, language: tuple[str, int, int], userop_index: int,
                              userop_name: str, input_byte_sizes: tuple[int, ...],
                              output_byte_size: int) -> PackedEqualitySemantics | None:
    """Select only a known translation signature, not an arbitrary userop.

    ``userop_name`` must come from independently authenticated translation
    evidence; guessing it from this registry does not meet that obligation.
    The observer must also validate CALLOTHER's constant-index operand and
    its actual input/output storage shape before applying the value rule.
    """
    if type(language) is not tuple or len(language) != 3 or type(language[0]) is not str \
            or any(type(value) is not int for value in language[1:]) \
            or type(userop_index) is not int or type(userop_name) is not str \
            or type(input_byte_sizes) is not tuple or any(type(value) is not int for value in input_byte_sizes) \
            or type(output_byte_size) is not int:
        return None
    if language == ("x86:LE:64:default", 4, 6) and userop_index == 483 \
            and userop_name == "vpcmpeqw_avx2" and input_byte_sizes == (32, 32) and output_byte_size == 32:
        return _VPCMPEQW_AVX2
    return None
