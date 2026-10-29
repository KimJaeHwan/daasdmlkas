"""Qualified user-op bytes reach original graph and evaluable records."""

from copy import deepcopy

import pytest

from synthetic import RAX, FunctionBuilder, const, copy, op, reg, tmp
from test_operation_records import _analyzed, _record
from tdo_v2.lane_slice import lane_index, lane_slice, reached_bytes
from tdo_v2.operation_records import Ineligible, eligibility, evaluate


LEFT, RIGHT = 0x1200, 0x1240


def _example(index=483, operand_width=32, output_width=32):
    result = tmp(0x18000, output_width)
    return _analyzed(FunctionBuilder().ins(
        op("CALLOTHER", [const(index, 4), reg(LEFT, operand_width), reg(RIGHT, operand_width)], result),
        op("SUBPIECE", [result, const(9, 4)], reg(RAX, 1))).ret())


def _entry(node):
    place = node.get("register", {})
    offset, size = place.get("offset"), place.get("size")
    for base, value in ((LEFT, 0), (RIGHT, 1 << 64)):
        if offset is not None and base <= offset and offset + size <= base + 32:
            return (value >> ((offset - base) * 8)) & ((1 << (size * 8)) - 1)
    return None


def test_lane_slice_and_record_keep_original_intrinsic_and_precise_input_bytes():
    analyzed = _example()
    norm = analyzed.normalized
    record = _record(analyzed, RAX, 1)
    userop, = [row for row in record["nodes"] if row.get("opcode") == "CALLOTHER"]
    assert userop["key"] == "1:1000:0:CALLOTHER"
    assert userop["intrinsic"]["userop_name"] == "vpcmpeqw_avx2"
    assert userop["intrinsic"]["semantic_id"] == "x86-vpcmpeqw-avx2-le256-v1"
    assert [operand["index"] for operand in userop["operands"]] == [0, 1, 2]
    assert not norm.assumed_call_effects
    graph_node = norm.dependencies.node_for_key("op:1:1000:0:CALLOTHER")
    assert norm.dependencies.node(graph_node).semantic_identity == userop["intrinsic"]["semantic_id"]
    assert eligibility(record) is None
    assert evaluate(record, _entry) == {0}
    index = lane_index(norm, analyzed.unit)
    definition_id = next(i for i, value in enumerate(norm.memory_ssa.definitions)
                         if value.operation_key == "1:1000:1:SUBPIECE")
    definition = norm.memory_ssa.definitions[definition_id]
    sliced = lane_slice(norm, analyzed.unit,
                        [(index.definition_node[definition_id], (definition.span,))], index=index)
    assert reached_bytes(sliced, norm) == frozenset((LEFT + 8, LEFT + 9, RIGHT + 8, RIGHT + 9))
    assert graph_node in sliced.nodes


@pytest.mark.parametrize("change", [
    lambda row: row.pop("intrinsic"),
    lambda row: row["intrinsic"].update(userop_name="unknown"),
    lambda row: row["intrinsic"].update(evidence_id="unverified"),
    lambda row: row["intrinsic"].update(language=["x86:LE:64:default", 4, 7]),
    lambda row: row["operands"][0].update(value=484),
    lambda row: row["operands"][0].update(role="value"),
    lambda row: row["operands"][1].update(width=16),
    lambda row: row["operands"][2].update(index=1),
    lambda row: row["operands"][0].update(index=False),
    lambda row: row["operands"][1].update(width=32.0),
    lambda row: row["output"].update(size=32.0),
    lambda row: row["output"].update(size=16),
])
def test_record_signature_mutations_remain_unsupported(change):
    record = deepcopy(_record(_example(), RAX, 1))
    userop = next(row for row in record["nodes"] if row.get("opcode") == "CALLOTHER")
    change(userop)
    assert eligibility(record) == "unsupported CALLOTHER"
    with pytest.raises(Ineligible):
        evaluate(record, _entry)


def test_supported_intrinsic_metadata_never_hides_existing_debt():
    record = deepcopy(_record(_example(), RAX, 1))
    userop = next(row for row in record["nodes"] if row.get("opcode") == "CALLOTHER")
    userop["debts"] = [999]
    assert eligibility(record) == "debt"
    with pytest.raises(Ineligible):
        evaluate(record, _entry)


def test_refined_userop_keeps_opaque_prior_writer_debt_in_actual_graph():
    result = tmp(0x18000, 32)
    analyzed = _analyzed(FunctionBuilder().ins(op("CALLOTHER", [const(999, 4)]))
        .ins(op("CALLOTHER", [const(483, 4), reg(LEFT, 32), reg(RIGHT, 32)], result),
             op("SUBPIECE", [result, const(9, 4)], reg(RAX, 1))).ret())
    record = _record(analyzed, RAX, 1)
    userop = next(row for row in record["nodes"] if row.get("intrinsic"))
    assert userop["debts"]
    assert eligibility(record) == "debt"
    assert any(row.operation_key == "1:1004:0:CALLOTHER"
               and row.intervening_calls == ("1:1000:0:CALLOTHER",)
               for row in analyzed.normalized.call_clobber_reads)


@pytest.mark.parametrize("options", [dict(index=484), dict(operand_width=16), dict(output_width=16)])
def test_unknown_observed_userop_never_gains_intrinsic_metadata(options):
    analyzed = _example(**options)
    assert not analyzed.normalized.intrinsic_refinements
    record = _record(analyzed, RAX, 1)
    userop = next(row for row in record["nodes"] if row.get("opcode") == "CALLOTHER")
    assert "intrinsic" not in userop
    assert eligibility(record) is not None


def _helper(entry, index):
    result = tmp(0x18000, 32)
    return FunctionBuilder(entry=entry).ins(
        op("CALLOTHER", [const(index, 4), reg(LEFT, 32), reg(RIGHT, 32)], result),
        op("SUBPIECE", [result, const(9, 4)], reg(RAX, 1))).ret()


@pytest.mark.parametrize("userop,restored", [(483, True), (484, False)])
def test_callee_stack_restoration_is_derived_from_body_not_assumed(userop, restored):
    from synthetic import RSP, program_units
    from tdo_v2.interprocedural import analyze_units
    leaf = 0x1800
    caller = FunctionBuilder().call(leaf).ret()
    results = analyze_units(program_units(caller, _helper(leaf, userop)),
                            assume_entry_values_not_frame=False,
                            assume_globals_disjoint_from_stack=False,
                            assume_opaque_callees_leave_no_stack_addresses=False,
                            private_frame_above=0, assume_debug_break_traps_do_not_return=False)
    helper = results["1:1800"]
    assert (dict(helper.summary.register_deltas).get((RSP, 8)) == 8) is restored
    effect, = results["1:1000"].proven.values()
    assert effect.restores_stack is restored
    assert not helper.normalized.assumed_call_effects
    if not restored:
        assert helper.summary.inner_calls
        assert any(run.debts for exit in helper.summary.exits for run in exit.runs
                   if run.span.start == RSP and run.span.size == 8)


@pytest.mark.parametrize("userop,restored", [(483, True), (484, False)])
def test_saved_summary_reuses_proven_stack_fact_and_keeps_unknown_intrinsic_debt(tmp_path, userop, restored):
    import json
    from synthetic import RSP
    from test_summary_templates import F, _client
    caller = lambda target: FunctionBuilder().call(target).ret()
    direct = _client(tmp_path, caller, _helper(F, userop), template=False)
    cached = _client(tmp_path, caller, _helper(F, userop), template=True)
    original_effect, = direct.proven.values()
    cached_effect, = cached.proven.values()
    assert original_effect.restores_stack is restored
    assert cached_effect.restores_stack is restored
    template = json.loads((tmp_path / "derived.json").read_text())["entries"][0]["summary"]
    deltas = {tuple(place): delta for place, delta in template["register_deltas"]}
    assert (deltas.get((RSP, 8)) == 8) is restored
    if not restored:
        assert template["inner_calls"]
        assert any("call_clobber_read" in run["debts"] for exit in template["exits"] for run in exit["runs"])
    assert "derived-model-runtime-matches" in cached.inherited_assumptions
    assert not any(label.startswith("pcodeop-model:") for label in cached.inherited_assumptions)
