"""Record condition selection proves CFG paths against existing raw SSA IDs."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from synthetic import (
    CF, R8, R9, RAX, RBX, RCX, RDI, RDX, RSI, FunctionBuilder, add, const, copy,
    load, op, program_units, ram, reg, store, tmp,
)
from test_operation_record_shapes import _branchy
from test_operation_records import _analyzed
from tdo_v2._record_conditions import ConditionIndex
from tdo_v2.lane_slice import lane_index
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.resource_limits import AnalysisBudgetExceeded


def _index(builder):
    analyzed = _analyzed(builder)
    lane = lane_index(analyzed.normalized, analyzed.unit)
    return analyzed, lane, ConditionIndex(analyzed.normalized, analyzed.unit, lane)


def _join(lane, register=RAX, size=8, block=None):
    found = [(definition_id, definition) for definition_id, definition in enumerate(lane.ssa.definitions)
             if definition.kind is MemoryDefinitionKind.JOIN and definition.span.start == register
             and definition.span.size == size and (block is None or definition.block_key == block)]
    assert found
    return found[0]


def _operations(lane, match):
    return tuple(lane.ssa.definitions[source].operation_key for source in match.sources)


def _cmov(*, prefix=False, address=False):
    builder = FunctionBuilder()
    if prefix:
        builder.ins(copy(reg(RAX), reg(RBX)))
    next_address = 0x1000 + 4 * (len(builder._rows) + 1)
    builder.ins(op("BOOL_NEGATE", [reg(CF, 1)], tmp(0x300, 1)),
                op("CBRANCH", [ram(next_address) if address else const(2, 1), tmp(0x300, 1)]),
                copy(reg(RAX), reg(RDX)))
    return builder.ins(copy(reg(R8), reg(RAX))).ret()


def test_instruction_diamond_orders_the_raw_sources_by_branch_polarity():
    analyzed, lane, conditions = _index(_branchy())
    definition_id, definition = _join(lane)
    match, reason = conditions.for_join(definition_id)
    assert reason is None
    assert (match.decision_key, match.merge_key) == ("1:1000:1:CBRANCH", "1:1010")
    assert (match.true_successor, match.false_successor) == ("1:100c", "1:1004")
    assert _operations(lane, match) == ("1:100c:0:INT_ADD", "1:1004:0:INT_ADD")
    assert frozenset(match.sources) == frozenset(lane.joins[definition_id])
    assert analyzed.normalized.dependencies.node(match.branch_node).key == "op:1:1000:1:CBRANCH"
    assert lane.ssa.actions[match.branch_action_id].operation_key == match.decision_key
    assert conditions.for_sources(definition.span, lane.joins[definition_id], definition.block_key) == (match, None)


def test_a_scalar_constant_predicate_has_an_existing_branch_action():
    builder = FunctionBuilder().cbranch("true", const(1, 1))
    builder.ins(copy(reg(RAX), reg(RSI))).branch("join")
    builder.label("true").ins(copy(reg(RAX), reg(RDI)))
    builder.label("join").ins(copy(reg(R8), reg(RAX))).ret()
    _, lane, conditions = _index(builder)
    match, reason = conditions.for_join(_join(lane)[0])
    assert reason is None
    assert lane.operation(match.branch_action_id)[0].inputs[1].coordinate.byte_offset == 1


def test_successor_address_order_does_not_determine_true_and_false():
    builder = FunctionBuilder().cbranch("true", reg(CF, 1))
    builder.label("true").ins(copy(reg(RAX), reg(RDI))).branch("join")
    builder.ins(copy(reg(RAX), reg(RSI))).branch("join")
    builder.label("join").ins(copy(reg(R8), reg(RAX))).ret()
    original = builder.to_json

    def to_json():
        raw = original()
        raw["instructions"][0]["fallthrough"] = builder._coordinate(0x100c)
        return raw

    builder.to_json = to_json
    _, lane, conditions = _index(builder)
    match, reason = conditions.for_join(_join(lane)[0])
    assert reason is None and match.true_successor < match.false_successor
    assert _operations(lane, match) == ("1:1004:0:COPY", "1:100c:0:COPY")


@pytest.mark.parametrize("address", (False, True))
@pytest.mark.parametrize("prefix", (False, True))
def test_cmov_preserves_only_the_proven_entry_or_predecision_definition(address, prefix):
    _, lane, conditions = _index(_cmov(prefix=prefix, address=address))
    match, reason = conditions.for_join(_join(lane)[0])
    assert reason is None
    first, second = (lane.ssa.definitions[source] for source in match.sources)
    assert first.kind is (MemoryDefinitionKind.DATA_WRITE if prefix else MemoryDefinitionKind.ENTRY)
    if prefix:
        assert first.operation_key == "1:1000:0:COPY"
    assert second.operation_key.endswith(":2:COPY")
    assert match.true_successor == match.merge_key
    assert match.false_successor.endswith("#2")


def test_signed_relative_cbranch_uses_its_own_ordinal_and_next_instruction():
    # The entry jumps forward to ordinal 3; its negative true edge reaches
    # ordinal 1, which jumps straight out. This is acyclic despite the
    # negative relative destination.
    builder = (FunctionBuilder().ins(
        op("BRANCH", [const(3, 1)]), copy(reg(RAX), reg(RDI)), op("BRANCH", [const(5, 1)]),
        op("CBRANCH", [const(0xfe, 1), reg(CF, 1)]), copy(reg(RAX), reg(RSI)),
        op("BRANCH", [const(2, 1)]), copy(reg(RAX), reg(RBX)))
        .ins(copy(reg(R8), reg(RAX))).ret())
    _, lane, conditions = _index(builder)
    match, reason = conditions.for_join(_join(lane)[0])
    assert reason is None
    assert (match.decision_key, match.merge_key) == ("1:1000:3:CBRANCH", "1:1004")
    assert (match.true_successor, match.false_successor) == ("1:1000#1", "1:1000#4")
    assert _operations(lane, match) == ("1:1000:1:COPY", "1:1000:4:COPY")


def test_actual_merge_can_precede_the_join_read_block():
    builder = FunctionBuilder().cbranch("true", reg(CF, 1))
    builder.ins(copy(reg(RAX), reg(RSI))).branch("merge")
    builder.label("true").ins(copy(reg(RAX), reg(RDI)))
    builder.label("merge").ins(copy(reg(R9), reg(RBX))).ins(add(reg(R9), reg(R9), const(1)))
    builder.ins(copy(reg(R8), reg(RAX))).ret()
    _, lane, conditions = _index(builder)
    definition_id, definition = _join(lane)
    match, reason = conditions.for_join(definition_id)
    assert reason is None and match.merge_key == "1:1010"
    assert definition.block_key == "1:1018" and definition.block_key != match.merge_key


def test_a_join_read_precedes_the_same_operations_write():
    builder = _branchy()
    builder._rows[-2].ops = [copy(reg(RAX), reg(RAX))]
    _, lane, conditions = _index(builder)
    definition_id, definition = _join(lane)
    match, reason = conditions.for_join(definition_id)
    assert reason is None
    assert conditions.for_sources(definition.span, lane.joins[definition_id], definition.block_key) \
        == (None, "write after merge")
    assert conditions.for_sources(definition.span, lane.joins[definition_id], definition.block_key,
                                   read_operation_key="1:1010:0:COPY") == (match, None)


def test_writes_after_the_join_read_do_not_erase_its_condition_mapping():
    builder = _branchy()
    builder._rows[-2].ops.append(copy(reg(RAX), reg(RBX)))
    _, lane, conditions = _index(builder)
    definition_id, definition = _join(lane)
    assert conditions.for_join(definition_id)[1] is None
    assert conditions.for_sources(definition.span, lane.joins[definition_id], definition.block_key) \
        == (None, "write after merge")


def test_summary_exit_alternatives_need_no_synthetic_ssa_join():
    builder = FunctionBuilder().cbranch("join", reg(CF, 1))
    builder.ins(copy(reg(RAX), reg(RDI))).label("join").ret()
    analyzed, lane, conditions = _index(builder)
    run = next(run for exit in analyzed.summary.exits for run in exit.runs if run.span.start == RAX)
    assert len(run.definitions) == 2 and not lane.joins
    match, reason = conditions.for_sources(run.span, run.definitions, analyzed.summary.exits[0].block_key)
    assert reason is None
    assert lane.ssa.definitions[match.sources[0]].kind is MemoryDefinitionKind.ENTRY
    assert lane.ssa.definitions[match.sources[1]].operation_key == "1:1004:0:COPY"


def test_a_partial_join_is_supported_only_for_its_covered_bytes():
    builder = FunctionBuilder().cbranch("true", reg(CF, 1))
    builder.ins(copy(reg(RAX, 4), reg(RSI, 4))).branch("join")
    builder.label("true").ins(copy(reg(RAX), reg(RDI)))
    builder.label("join").ins(copy(reg(R8), reg(RAX))).ret()
    _, lane, conditions = _index(builder)
    definition_id, definition = _join(lane, size=4)
    match, reason = conditions.for_join(definition_id)
    assert reason is None and match is not None
    whole = replace(definition.span, size=8)
    assert conditions.for_sources(whole, lane.joins[definition_id], definition.block_key) == (None, "unsupported source")


def test_a_relevant_write_between_merge_and_read_rejects_old_sources():
    builder = _branchy()
    # Build another real read after a full overwrite, leaving the earlier
    # JOIN in place so its sources can be challenged against the later read.
    builder._rows.pop()
    builder.ins(copy(reg(RAX), reg(RBX))).ins(copy(reg(R9), reg(RAX))).ret()
    _, lane, conditions = _index(builder)
    definition_id, definition = _join(lane)
    assert conditions.for_sources(definition.span, lane.joins[definition_id], "1:1018") == (None, "write after merge")


def test_an_entry_alternative_must_not_hide_a_predecision_overwrite():
    builder = FunctionBuilder().ins(copy(reg(R9), reg(RAX))).ins(copy(reg(RAX), reg(RBX)))
    builder.ins(op("CBRANCH", [const(2, 1), reg(CF, 1)]), copy(reg(RAX), reg(RDX)))
    builder.ins(copy(reg(R8), reg(RAX))).ret()
    _, lane, conditions = _index(builder)
    definition_id, definition = _join(lane)
    source = next(source for source in lane.joins[definition_id]
                  if lane.ssa.definitions[source].operation_key == "1:1008:1:COPY")
    entry = next(source for source, item in enumerate(lane.ssa.definitions)
                 if item.kind is MemoryDefinitionKind.ENTRY and item.span.contains(definition.span))
    assert conditions.for_sources(definition.span, (entry, source), definition.block_key) == (None, "source mismatch")


def test_an_unrelated_earlier_branch_does_not_prove_a_preserved_prefix():
    builder = FunctionBuilder().cbranch("first_join", reg(CF, 1))
    builder.ins(copy(reg(R9), reg(RBX))).label("first_join")
    builder.ins(op("CBRANCH", [const(2, 1), reg(CF, 1)]), copy(reg(RAX), reg(RDX)))
    builder.ins(copy(reg(R8), reg(RAX))).ret()
    _, lane, conditions = _index(builder)
    assert conditions.for_join(_join(lane)[0]) == (None, "no straight entry prefix")


def test_nested_arm_branches_keep_the_same_two_raw_sources_unordered():
    builder = FunctionBuilder().cbranch("outer_true", reg(CF, 1))
    builder.cbranch("inner_join", reg(CF, 1)).ins(copy(reg(R9), reg(RBX)))
    builder.label("inner_join").ins(copy(reg(RAX), reg(RSI))).branch("join")
    builder.label("outer_true").ins(copy(reg(RAX), reg(RDI)))
    builder.label("join").ins(copy(reg(R8), reg(RAX))).ret()
    _, lane, conditions = _index(builder)
    definition_id, _ = _join(lane)
    assert len(lane.joins[definition_id]) == 2
    assert conditions.for_join(definition_id) == (None, "no simple diamond")


@pytest.mark.parametrize("conditional", (False, True))
def test_pcode_destinations_must_exactly_match_the_existing_cfg_successors(conditional):
    analyzed, lane, _ = _index(_branchy())
    observation = analyzed.unit.observation
    ordinal = 0 if conditional else 2
    row = observation.instructions[ordinal]
    operation = row.operations[-1]
    destination = replace(operation.inputs[0], coordinate=replace(operation.inputs[0].coordinate,
                                                                  byte_offset=0x1004))
    changed = replace(operation, inputs=(destination, *operation.inputs[1:]))
    row = replace(row, operations=(*row.operations[:-1], changed))
    observation = replace(observation, instructions=tuple(
        row if index == ordinal else original for index, original in enumerate(observation.instructions)))
    unit = SimpleNamespace(observation=observation, scopes=analyzed.unit.scopes)
    conditions = ConditionIndex(analyzed.normalized, unit, lane)
    assert conditions.for_join(_join(lane)[0]) == (None, "no simple diamond")


def test_a_partial_final_arm_write_cannot_use_an_earlier_full_write_as_its_source():
    builder = FunctionBuilder().cbranch("true", reg(CF, 1))
    builder.ins(copy(reg(RAX), reg(RSI))).ins(copy(reg(RAX, 1), reg(RCX, 1))).branch("join")
    builder.label("true").ins(copy(reg(RAX), reg(RDI)))
    builder.label("join").ins(copy(reg(R8), reg(RAX))).ret()
    _, lane, conditions = _index(builder)
    whole = next(item.span for item in lane.ssa.definitions if item.operation_key == "1:1004:0:COPY")
    full = tuple(source for source, item in enumerate(lane.ssa.definitions)
                 if item.operation_key in ("1:1004:0:COPY", "1:1010:0:COPY"))
    assert conditions.for_sources(whole, full, "1:1014") == (None, "partial last write")


def test_an_arm_call_falls_back_even_when_both_later_writes_are_known():
    builder = FunctionBuilder().cbranch("true", reg(CF, 1))
    builder.call(0x1f00).ins(copy(reg(RAX), reg(RSI))).branch("join")
    builder.label("true").ins(copy(reg(RAX), reg(RDI)))
    builder.label("join").ins(copy(reg(R8), reg(RAX))).ret()
    _, lane, conditions = _index(builder)
    assert conditions.for_join(_join(lane)[0]) == (None, "call on path")


def test_an_unresolved_arm_write_falls_back_even_when_the_value_is_overwritten():
    builder = FunctionBuilder().cbranch("true", reg(CF, 1))
    builder.ins(op("INT_MULT", [reg(RDX), reg(RBX)], tmp(0x200)), store(tmp(0x200), reg(RSI)))
    builder.ins(copy(reg(RAX), reg(RSI))).branch("join")
    builder.label("true").ins(copy(reg(RAX), reg(RDI)))
    builder.label("join").ins(copy(reg(R8), reg(RAX))).ret()
    _, lane, conditions = _index(builder)
    assert conditions.for_join(_join(lane)[0]) == (None, "unresolved access on path")


def test_a_predicate_with_alias_debt_does_not_select_sources():
    builder = FunctionBuilder().ins(store(reg(RDX), reg(RBX))).ins(load(tmp(0x200, 1), reg(RDI)))
    builder.cbranch("true", tmp(0x200, 1))
    builder.ins(copy(reg(RAX), reg(RSI))).branch("join")
    builder.label("true").ins(copy(reg(RAX), reg(RDI)))
    builder.label("join").ins(copy(reg(R8), reg(RAX))).ret()
    _, lane, conditions = _index(builder)
    assert conditions.for_join(_join(lane)[0]) == (None, "condition debt")


def test_a_source_with_alias_debt_is_not_made_conditional_proof():
    builder = FunctionBuilder().ins(store(reg(RDX), reg(RBX))).cbranch("true", reg(CF, 1))
    builder.ins(load(reg(RAX), reg(RDI))).branch("join")
    builder.label("true").ins(copy(reg(RAX), reg(RSI)))
    builder.label("join").ins(copy(reg(R8), reg(RAX))).ret()
    _, lane, conditions = _index(builder)
    assert conditions.for_join(_join(lane)[0]) == (None, "source debt")


def test_a_cycle_anywhere_in_the_function_keeps_all_joins_unselected():
    builder = _branchy()
    builder._rows.pop()
    builder.label("loop").ins(add(reg(R9), reg(R9), const(1))).cbranch("loop", reg(CF, 1)).ret()
    _, lane, conditions = _index(builder)
    assert conditions.for_join(_join(lane)[0]) == (None, "cyclic cfg")


def test_condition_results_are_cached_and_resource_failures_propagate(monkeypatch):
    import tdo_v2._record_conditions as module

    analyzed, lane, conditions = _index(_branchy())
    definition_id, _ = _join(lane)
    expected = conditions.for_join(definition_id)

    def exhausted(*args):
        raise AnalysisBudgetExceeded("work")

    monkeypatch.setattr(module, "step", exhausted)
    assert conditions.for_join(definition_id) is expected
    with pytest.raises(AnalysisBudgetExceeded):
        ConditionIndex(analyzed.normalized, analyzed.unit, lane)


def test_general_guards_do_not_reinterpret_an_unknown_read_as_a_block_exit():
    _, lane, conditions = _index(_branchy())
    definition_id, definition = _join(lane)
    assert conditions.guarded_sources(definition.span, lane.joins[definition_id], definition.block_key,
                                      'not-an-observed-read') == (None, 'read operation is not in block')
