"""Original micro-CFG range coverage, not a mnemonic-specific loop rule."""

import pytest

from synthetic import FunctionBuilder, RAX, RCX, RDX, RSP, add, const, copy, op, program_units, reg, store, tmp
from tdo_v2._guarded_ranges import copy_read_ranges
from tdo_v2.forward import Interval, Value, _transfer, forward_facts
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction


def _scan(*, shift="INT_RIGHT", compare="INT_NOTEQUAL", seed=31, count_size=4, extra=()):
    counter, shifted, flag, zero = tmp(0x100, count_size), tmp(0x110, 4), tmp(0x120, 1), tmp(0x130, 1)
    # The bypass and successful-shift edges must BOTH cover the exit value.
    rows = [copy(counter, const(seed, count_size)),
            op("INT_EQUAL", [reg(RCX, 4), const(0, 4)], zero),
            op("CBRANCH", [const(6 + len(extra), 4), zero]),
            op(shift, [reg(RCX, 4), counter], shifted),
            op(compare, [shifted, const(0, 4)], flag),
            op("CBRANCH", [const(3, 4), flag]),
            op("INT_SUB", [counter, const(1, count_size)], counter),
            op("BRANCH", [const((1 << 32) - 4, 4)]),
            *extra, copy(reg(RAX, count_size), counter)]
    return rows, counter


def _unit(**options):
    rows, counter = _scan(**options)
    unit, = program_units(FunctionBuilder().ins(*rows).ret())
    return unit, counter, f"1:1000:{len(rows) - 1}:COPY"


def test_every_exit_is_covered_without_unrolling_a_counter_loop():
    unit, _, key = _unit()
    assert next(bound for (operation, _), bound in copy_read_ranges(unit).items() if operation == key) == (0, 31)


@pytest.mark.parametrize("options", ({"shift": "INT_SRIGHT"}, {"compare": "INT_EQUAL"}))
def test_signed_shift_and_wrong_branch_polarity_are_not_bounds(options):
    unit, _, _ = _unit(**options)
    assert not copy_read_ranges(unit)


def test_other_incoming_constant_is_included_not_discarded():
    unit, _, key = _unit(seed=255)
    assert next(bound for (operation, _), bound in copy_read_ranges(unit).items() if operation == key) == (0, 255)


@pytest.mark.parametrize("write", (copy(tmp(0x100, 4), reg(RDX, 4)), copy(tmp(0x101, 1), const(0, 1))))
def test_full_or_partial_write_after_the_guard_refuses_the_old_count(write):
    unit, _, _ = _unit(extra=(write,))
    assert not copy_read_ranges(unit)


def test_a_call_after_the_guard_is_not_a_preservation_premise():
    unit, _, _ = _unit(extra=(op("CALLOTHER", [const(999, 4)]),))
    assert not copy_read_ranges(unit)


def test_changed_analysis_operation_excludes_the_entire_instruction():
    unit, _, _ = _unit()
    assert not copy_read_ranges(unit, ("1:1000:0:COPY",))


def test_an_unbounded_incoming_value_cannot_be_dropped():
    rows, counter = _scan()
    rows[0] = copy(counter, reg(RDX, 4))
    unit, = program_units(FunctionBuilder().ins(*rows).ret())
    assert not copy_read_ranges(unit)


def test_jumping_into_the_predicate_producer_does_not_read_a_new_shift_result():
    rows, _ = _scan()
    rows[2] = op("CBRANCH", [const(2, 4), tmp(0x130, 1)])
    unit, = program_units(FunctionBuilder().ins(*rows).ret())
    assert not copy_read_ranges(unit)


def test_optional_work_cap_refuses_a_bound_without_changing_the_input(monkeypatch):
    import tdo_v2._guarded_ranges as guarded
    unit, _, _ = _unit()
    monkeypatch.setattr(guarded, "MAX_WORK", 0)
    assert not guarded.copy_read_ranges(unit)


def test_all_incoming_paths_keep_the_original_count_width():
    unit, _, key = _unit(count_size=1, seed=255)
    assert next(bound for (operation, _), bound in copy_read_ranges(unit).items() if operation == key) == (0, 255)


def test_equal_false_edge_proves_the_nonzero_shift():
    counter, shifted, flag, zero = tmp(0x100, 4), tmp(0x110, 4), tmp(0x120, 1), tmp(0x130, 1)
    rows = [copy(counter, const(31, 4)), op("INT_EQUAL", [reg(RCX, 4), const(0, 4)], zero),
            op("CBRANCH", [const(7, 4), zero]), op("INT_RIGHT", [reg(RCX, 4), counter], shifted),
            op("INT_EQUAL", [shifted, const(0, 4)], flag), op("CBRANCH", [const(2, 4), flag]),
            op("BRANCH", [const(3, 4)]), op("INT_SUB", [counter, const(1, 4)], counter),
            op("BRANCH", [const((1 << 32) - 5, 4)]), copy(reg(RAX, 4), counter)]
    unit, = program_units(FunctionBuilder().ins(*rows).ret())
    assert next(bound for (key, _), bound in copy_read_ranges(unit).items() if key == "1:1000:9:COPY") == (0, 31)


def test_uncovered_cycle_after_a_guard_is_not_a_same_visit_certificate():
    unit, _, _ = _unit(extra=(op("CBRANCH", [const(0, 4), reg(RDX, 1)]),))
    assert not copy_read_ranges(unit)


def test_flow_override_refuses_the_original_internal_edges():
    class Override(FunctionBuilder):
        def to_json(self):
            raw = super().to_json()
            raw["instructions"][0]["flow_type"]["is_override"] = True
            return raw
    rows, _ = _scan()
    unit, = program_units(Override().ins(*rows).ret())
    assert not copy_read_ranges(unit)


def test_range_is_used_by_existing_forward_and_preserves_the_raw_graph(monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    rows, _ = _scan()
    address = tmp(0x500)
    builder = (FunctionBuilder().ins(*rows)
               .ins(op("INT_XOR", [reg(RAX, 4), const(28, 4)], reg(RAX, 4)),
                    op("INT_RIGHT", [reg(RAX, 4), const(2, 4)], reg(RAX, 4)),
                    op("INT_ZEXT", [reg(RAX, 4)], reg(RAX)))
               .ins(add(address, reg(RSP), reg(RAX)), store(address, reg(RDX, 1))).ret())
    unit, = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    assert isinstance(normalized, NormalizedFunction)
    fact, = [row for row in forward_facts(normalized, unit) if row.operation == "1:1008:1:STORE"]
    assert not fact.claim.is_top
    base, interval = fact.claim.items[0]
    assert base == ("entry", RSP, 8) and (interval.lo, interval.hi) == (0, 7)
    for ordinal, operation in enumerate(unit.observation.instructions[0].operations):
        assert normalized.dependencies.node_for_key(f"op:1:1000:{ordinal}:{operation.opcode}") is not None


@pytest.mark.parametrize("bits", (8, 16, 32, 64))
def test_xor_low_bit_hull_is_sound_without_enumerating_the_domain(bits):
    for high in (0, 3, 31, (1 << bits) - 1):
        for literal in (0, 1, 28, (1 << bits) - 1):
            a = Value(bits, ((("abs",), Interval(0, high, 1, bits)),))
            result = _transfer("INT_XOR", [a, Value.number(literal, bits)], [bits // 8] * 2, bits // 8)
            bound = result.numeric()
            assert bound is not None
            for sample in (0, high // 2, high):
                assert bound.contains(sample ^ literal)
