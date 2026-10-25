"""Operation records (docs 25.28): the shapes of records, and the checker
rejecting corrupted ones."""

import copy as copying
import random

import pytest

from record_oracle import check_records
from synthetic import (
    R8, R9, RAX, RBX, RCX, RDI, RDX, RSI, RSP, FunctionBuilder, add, const, copy, load, op, program_units,
    reg, store, tmp,
)
from test_operation_records import _analyzed, _record, _value_function
from tdo_v2.interprocedural import analyze_units
from tdo_v2.operation_records import Ineligible, Limits, eligibility, evaluate, render, root_record, run_records


def _nodes(record, kind=None, opcode=None):
    return [node for node in record["nodes"]
            if (kind is None or node["kind"] == kind) and (opcode is None or node.get("opcode") == opcode)]


def _branchy():
    """rax = rdx == 0 ? rsi + 2 : rdi + 1; r8 = rax."""
    flag = tmp(0x300, 1)
    builder = FunctionBuilder()
    builder.cbranch("other", flag, op("INT_EQUAL", [reg(RDX), const(0)], flag))
    builder.ins(add(reg(RAX), reg(RDI), const(1))).branch("join")
    builder.label("other").ins(add(reg(RAX), reg(RSI), const(2)))
    builder.label("join").ins(copy(reg(R8), reg(RAX))).ret()
    return builder


def _branch_pools(seed):
    return {RDX: seed % 2, RDI: 0x10, RSI: 0x20, RSP: 0x7000_0000}


def test_a_partial_write_makes_an_operand_of_two_fragments():
    """al = cl, then rdx = rax + 1: the operand rax is byte 0 of the COPY and
    bytes 1..7 of the entry value, in order."""
    builder = (FunctionBuilder().ins(copy(reg(RAX, 1), reg(RCX, 1)))
               .ins(add(reg(RDX), reg(RAX), const(1))).ret())
    record = _record(_analyzed(builder), RDX)
    (add_node,) = _nodes(record, "op", "INT_ADD")
    parts = add_node["operands"][0]["parts"]
    assert [part["at"] for part in parts] == [[0, 1], [1, 8]]
    producers = [record["nodes"][part["node"]] for part in parts]
    assert producers[0]["opcode"] == "COPY" and producers[1]["kind"] == "entry"
    text = render(record)
    assert "rax[1:8]" in text and "rcx[0:1]" in text


def test_x_op_x_reads_one_definition_twice():
    record = _record(_analyzed(FunctionBuilder().ins(add(reg(RDX), reg(RSI), reg(RSI))).ret()), RDX)
    (node,) = _nodes(record, "op", "INT_ADD")
    assert node["operands"][0]["parts"] == node["operands"][1]["parts"]


def test_load_and_store_keep_address_and_value_roles():
    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x20)
               .ins(add(t, reg(RSP), const(8)), store(t, reg(RDI)))
               .ins(add(t, reg(RSP), const(8)), load(reg(RAX), t)).add_rsp(0x20).ret())
    record = _record(_analyzed(builder), RAX)
    (loaded,) = _nodes(record, "op", "LOAD")
    (stored,) = _nodes(record, "op", "STORE")
    assert [operand["role"] for operand in loaded["operands"]] == ["space", "address"]
    assert [operand["role"] for operand in stored["operands"]] == ["space", "address", "value"]
    assert record["nodes"][loaded["memory"][0]["parts"][0]["node"]] is stored
    assert eligibility(record) is None


def test_a_join_is_a_phi_of_alternatives():
    analyzed = _analyzed(_branchy())
    record = _record(analyzed, R8)
    (phi,) = _nodes(record, "phi")
    assert len(phi["alternatives"]) == 2 and eligibility(record) is None
    report = check_records(analyzed, seeds=range(4), register_pools=_branch_pools, records=[record])
    assert report.evaluated == 4 and report.failures == []


def test_a_loop_carried_value_is_a_back_reference_and_never_evaluated():
    flag = tmp(0x300, 1)
    builder = FunctionBuilder().label("top")
    builder.ins(add(reg(RAX), reg(RAX), reg(RBX)), op("INT_SUB", [reg(R9), const(1)], reg(R9)))
    builder.cbranch("top", flag, op("INT_NOTEQUAL", [reg(R9), const(0)], flag))
    builder.ins(copy(reg(R8), reg(RAX))).ret()
    record = _record(_analyzed(builder), R8)
    assert any(part.get("loop") for node in record["nodes"]
               for part in (*node.get("alternatives", ()),
                            *(p for operand in node.get("operands", ()) for p in operand.get("parts", ()))))
    assert eligibility(record) == "loop"


def test_a_summarized_call_is_one_node_with_its_decision_facts():
    leaf = FunctionBuilder(entry=0x1800).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    caller = (FunctionBuilder().sub_rsp(0x28).call(0x1800).ins(copy(reg(R8), reg(RAX)))
              .add_rsp(0x28).ret())
    analyzed = analyze_units(program_units(caller, leaf))["1:1000"]
    record = _record(analyzed, R8)
    (call,) = _nodes(record, "call")
    assert call["callee"] == "1:1800" and call["source"] == "summary" and call["row"] == "0"
    assert call["facts"]["restores_stack"] and call["facts"]["preserves_memory"]
    assert [item["role"] for item in call["inputs"]] == ["value"]
    assert not any("~in" in node.get("key", "") for node in record["nodes"])   # staging folded in
    assert eligibility(record) is None
    with pytest.raises(Ineligible, match="unknown inputs"):
        evaluate(record, lambda node: 0)        # a call output is needed
    found = evaluate(record, lambda node: 0, call=lambda node, part: 0x77)
    assert found == {0x77}


def test_a_may_alias_debt_lists_its_writers():
    builder = (FunctionBuilder().ins(store(reg(RDI), reg(RBX)))
               .ins(load(reg(RAX), reg(RSI))).ins(store(reg(RDX), reg(RCX))).ret())
    record = _record(_analyzed(builder), RAX)
    debts = _nodes(record, "debt")
    assert [debt["debt"] for debt in debts] == ["may_alias_read"]
    writers = [record["nodes"][item["node"]] for item in debts[0]["from"]]
    assert [node["opcode"] for node in writers] == ["STORE"]
    assert eligibility(record) == "debt"


def test_limits_cut_the_record():
    analyzed = _analyzed(_value_function(random.Random(3)))
    records = run_records(analyzed.normalized, analyzed.unit, analyzed.summary, limits=Limits(nodes=2))
    cut = [record for record in records if record["truncated"]]
    assert cut and all(eligibility(record) == "truncated" for record in cut)


def test_the_demand_budget_truncates_the_record():
    analyzed = _analyzed(_value_function(random.Random(3)))
    records = run_records(analyzed.normalized, analyzed.unit, analyzed.summary,
                          limits=Limits(demand_steps=1))
    assert any(record["truncated"] and not record["demand_complete"] for record in records)


def test_origins_mark_the_nodes_the_engine_labels():
    analyzed = _analyzed(FunctionBuilder().ins(add(reg(RAX), reg(RDI), const(1))).ret())
    normalized = analyzed.normalized
    run = next(run for item in analyzed.summary.exits for run in item.runs if run.span.start == RAX)
    (definition,) = run.definitions
    node = normalized.memory_graph.definition_nodes[definition]
    entry = next(index for index, item in enumerate(normalized.memory_ssa.definitions)
                 if item.kind.value == "entry" and item.span.object_id.kind.value == "register_file"
                 and item.span.start <= RDI < item.span.end)
    record = root_record(normalized, analyzed.unit, [(node, (run.span,))],
                         origins={normalized.memory_graph.definition_nodes[entry]: {"src.rdi"}})
    assert any(item.get("origins") == ["src.rdi"] for item in record["nodes"])
    assert "src.rdi" in render(record)


def test_rep_rows_and_overrides():
    from test_rep_strings import _function

    def records_of(builder):
        analyzed = _analyzed(builder)
        return run_records(analyzed.normalized, analyzed.unit, analyzed.summary)

    proven = records_of(_function(3)[0])
    nodes = [node for record in proven for node in record["nodes"]]
    assert any(node.get("rep_iteration") for node in nodes)
    assert any(node["kind"] == "override" for node in nodes)
    assert "rep" in {eligibility(record) for record in proven}
    unknown = records_of(_function(("reg", R9))[0])
    assert "unproven rep" in {eligibility(record) for record in unknown}
    # the count register at an unproven site: its "ends 0" override is not
    # taken (the block is no proven rep block)
    (count,) = [record for record in unknown if record["place"]["start"] == RCX and record["place"]["size"] == 8]
    assert eligibility(count) == "unproven rep"


def test_bytes_no_result_depends_on_are_pruned_and_evaluated_as_zero():
    """rdx = PIECE(eax, ecx); r8d = SUBPIECE(rdx, 0): eax (the high half) is
    pruned, yet the record evaluates."""
    builder = (FunctionBuilder().ins(op("PIECE", [reg(RAX, 4), reg(RCX, 4)], reg(RDX)))
               .ins(op("SUBPIECE", [reg(RDX), const(0, 4)], reg(R8, 4))).ret())
    analyzed = _analyzed(builder)
    record = _record(analyzed, R8, 4)
    (piece,) = _nodes(record, "op", "PIECE")
    assert piece["operands"][0].get("pruned")
    pools = lambda seed: {RAX: 0x1111 * (seed + 1), RCX: 0x2222 * (seed + 3), RSP: 0x7000_0000}
    report = check_records(analyzed, seeds=range(4), register_pools=pools, records=[record])
    assert report.evaluated == 4 and report.failures == []


def test_a_load_through_a_join_of_a_store_and_entry_memory_evaluates():
    """[rsp+8] = rdi on one path only; rax = [rsp+8] after the join: the
    entry alternative is read at the LOAD's concrete address (Antigravity
    implementation review 1, P1-3)."""
    flag, t = tmp(0x300, 1), tmp(0x100)
    builder = FunctionBuilder().sub_rsp(0x20)
    builder.cbranch("join", flag, op("INT_EQUAL", [reg(RDX), const(0)], flag))
    builder.ins(add(t, reg(RSP), const(8)), store(t, reg(RDI)))
    builder.label("join").ins(add(t, reg(RSP), const(8)), load(reg(RAX), t)).add_rsp(0x20).ret()
    analyzed = _analyzed(builder)
    record = _record(analyzed, RAX)
    (loaded,) = _nodes(record, "op", "LOAD")
    assert record["nodes"][loaded["memory"][0]["parts"][0]["node"]]["kind"] == "phi"
    pools = lambda seed: {RDX: seed % 2, RDI: 0x1234 + seed, RSP: 0x7000_0000}
    report = check_records(analyzed, seeds=range(6), register_pools=pools, records=[record])
    assert report.evaluated == 6 and report.failures == []


def test_debts_of_a_calls_staged_inputs_are_on_the_call_node():
    """rdi passed to a summarized call after an opaque call: the read of rdi
    (in the folded ~in row) has call-clobber debt -- shown on the call node
    (P1-1)."""
    leaf = FunctionBuilder(entry=0x1800).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    caller = (FunctionBuilder().sub_rsp(0x28).call(0x1F00).call(0x1800).ins(copy(reg(R8), reg(RAX)))
              .add_rsp(0x28).ret())
    analyzed = analyze_units(program_units(caller, leaf))["1:1000"]
    record = _record(analyzed, R8)
    calls = [node for node in _nodes(record, "call") if node["callee"] == "1:1800"]
    assert calls and calls[0].get("debts")
    assert {record["nodes"][debt]["debt"] for debt in calls[0]["debts"]} == {"call_clobber_read"}
    assert eligibility(record) == "debt"


def test_incomplete_roots_and_run_facts_are_shown():
    assert eligibility({"record": "root", "completeness": {"complete": False}, "nodes": [], "root": []}) \
        == "root incomplete"
    assert eligibility({"record": "root", "nodes": [], "root": [{"node": 0, "whole": True}]}) == "whole-node root"
    text = render({"record": "summary run", "function": "1:1000", "span": "register:rax", "run_kind": "unknown",
                   "crossed": ["call:1:1004:2:CALL"], "nodes": [{"id": 0, "kind": "const", "value": 7, "size": 8}],
                   "root": [{"node": 0, "bytes": [0, 8], "at": [0, 8]}]})
    assert "kind=unknown" in text.splitlines()[0] and "crossed=call:1:1004:2:CALL" in text.splitlines()[0]


def test_two_outputs_of_one_call_row_stay_distinct():
    """The callee sets rax = rdi + 1 and rbx = rdi + 2 (one run: the same
    inputs); rcx = rax - rbx: the two parts name their outputs (Astra
    implementation review 1, P1-1)."""
    leaf = (FunctionBuilder(entry=0x1800).ins(add(reg(RAX), reg(RDI), const(1)))
            .ins(add(reg(RBX), reg(RDI), const(2))).ret())
    caller = (FunctionBuilder().sub_rsp(0x28).call(0x1800)
              .ins(op("INT_SUB", [reg(RAX), reg(RBX)], reg(RCX))).add_rsp(0x28).ret())
    analyzed = analyze_units(program_units(caller, leaf))["1:1000"]
    record = _record(analyzed, RCX)
    (sub_node,) = _nodes(record, "op", "INT_SUB")
    outputs = [operand["parts"][0]["output"]["start"] for operand in sub_node["operands"]]
    assert outputs == [RAX, RBX]
    values = {RAX: 11, RBX: 12}
    found = evaluate(record, lambda node: None, call=lambda node, part: values[part["output"]["start"]])
    assert found == {(11 - 12) % (1 << 64)}


def test_a_root_of_several_selectors_is_never_one_value():
    record = {"record": "root", "nodes": [{"id": 0, "kind": "const", "value": 1, "size": 8}],
              "root": [{"node": 0, "bytes": [0, 8], "at": [0, 8], "span": "register:rax"},
                       {"node": 0, "bytes": [0, 8], "at": [0, 8], "span": "register:rbx"}]}
    assert eligibility(record) == "several selectors"


def test_a_long_chain_is_cut_at_the_depth_limit_not_by_python():
    """200 dependent operations (Astra: a 180-operation chain raised
    RecursionError at logical depth ~165, before the default limit 256): the
    whole chain is recorded; a lower limit cuts it with a "depth" cut."""
    builder = FunctionBuilder()
    for _ in range(200):
        builder.ins(add(reg(RAX), reg(RAX), const(1)))
    analyzed = _analyzed(builder.ret())
    record = _record(analyzed, RAX)
    assert not record["truncated"] and len(_nodes(record, "op", "INT_ADD")) == 200
    shallow = [item for item in run_records(analyzed.normalized, analyzed.unit, analyzed.summary,
                                            limits=Limits(depth=50))
               if item["place"]["start"] == RAX and item["place"]["size"] == 8]
    assert [node["reason"] for node in shallow[0]["nodes"] if node["kind"] == "cut"] == ["depth"]
    assert eligibility(shallow[0]) == "truncated"


def test_a_node_limit_leaves_well_formed_nodes():
    leaf = FunctionBuilder(entry=0x1800).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    caller = (FunctionBuilder().sub_rsp(0x28).call(0x1800).ins(copy(reg(R8), reg(RAX)))
              .add_rsp(0x28).ret())
    analyzed = analyze_units(program_units(caller, leaf))["1:1000"]
    for nodes in range(1, 6):
        for record in run_records(analyzed.normalized, analyzed.unit, analyzed.summary, limits=Limits(nodes=nodes)):
            render(record)   # never a KeyError
            if record["truncated"]:
                assert eligibility(record) in ("truncated", "cut")


def test_an_alternative_that_cannot_be_evaluated_leaves_no_result():
    """rax = rdx == 0 ? 17 : rsi with rsi unknown: the known alternative alone
    (17) is no result (Astra implementation review 2, P1)."""
    flag = tmp(0x300, 1)
    builder = FunctionBuilder()
    builder.cbranch("other", flag, op("INT_EQUAL", [reg(RDX), const(0)], flag))
    builder.ins(copy(reg(RAX), const(17))).branch("join")
    builder.label("other").ins(copy(reg(RAX), reg(RSI)))
    builder.label("join").ins(copy(reg(R8), reg(RAX))).ret()
    record = _record(_analyzed(builder), R8)
    with pytest.raises(Ineligible, match="unknown inputs"):
        evaluate(record, lambda node: None)
    # The input also fixes RDX=0: the now-recorded predicate selects RSI.
    assert evaluate(record, lambda node: 5 << (8 * (RSI - node["register"]["offset"]))) == {5}


def test_root_parts_of_one_selector_must_not_overlap():
    record = {"record": "root", "nodes": [{"id": 0, "kind": "const", "value": 1, "size": 8}],
              "root": [{"node": 0, "bytes": [0, 8], "at": [0, 8], "span": "register:rax"},
                       {"node": 0, "bytes": [0, 4], "at": [0, 4], "span": "register:rax"}]}
    assert eligibility(record) == "overlapping root parts"


def test_the_byte_budget_is_checked_before_a_seed_is_materialized():
    from tdo_v2.lane_slice import lane_slice

    analyzed = _analyzed(FunctionBuilder().ins(add(reg(RAX), reg(RDI), const(1))).ret())
    run = next(run for item in analyzed.summary.exits for run in item.runs if run.span.start == RAX)
    node = analyzed.normalized.memory_graph.definition_nodes[run.definitions[0]]
    lanes = lane_slice(analyzed.normalized, analyzed.unit, [(node, (run.span,))], byte_budget=4)
    assert lanes.exhausted and node not in lanes.demands and node in lanes.frontier
    assert not lane_slice(analyzed.normalized, analyzed.unit, [(node, (run.span,))], byte_budget=10_000).exhausted


def test_the_byte_budget_accumulates_over_seeds():
    """Several seeds each within the budget, together over it (Astra
    implementation review 3, P2): exhausted."""
    from tdo_v2.lane_slice import lane_slice

    builder = FunctionBuilder()
    for register in (RAX, RCX, RDX, RBX, R8):
        builder.ins(add(reg(register), reg(RDI), const(1)))
    analyzed = _analyzed(builder.ret())
    seeds = [(analyzed.normalized.memory_graph.definition_nodes[run.definitions[0]], (run.span,))
             for item in analyzed.summary.exits for run in item.runs
             if run.span.object_id.kind.value == "register_file" and run.span.size == 8
             and run.span.start in (RAX, RCX, RDX, RBX, R8)]
    assert len(seeds) == 5
    assert lane_slice(analyzed.normalized, analyzed.unit, seeds, byte_budget=40).exhausted
    assert not lane_slice(analyzed.normalized, analyzed.unit, seeds, byte_budget=100_000).exhausted


def test_a_deep_record_evaluates_without_python_recursion_errors():
    """250 dependent additions: built whole (depth 256) and evaluated at the
    default Python limit (Astra implementation review 3, P2)."""
    import sys

    builder = FunctionBuilder()
    for _ in range(250):
        builder.ins(add(reg(RAX), reg(RAX), const(1)))
    previous = sys.getrecursionlimit()
    sys.setrecursionlimit(20000)   # the analysis itself (not under test here)
    try:
        analyzed = _analyzed(builder.ret())
    finally:
        sys.setrecursionlimit(previous)
    record = _record(analyzed, RAX)
    assert not record["truncated"] and eligibility(record) is None
    assert evaluate(record, lambda node: 7 if node["register"]["offset"] == RAX else 0) == {7 + 250}


def test_the_demand_byte_budget_truncates_the_record():
    analyzed = _analyzed(_value_function(random.Random(3)))
    records = run_records(analyzed.normalized, analyzed.unit, analyzed.summary, limits=Limits(demand_bytes=1))
    assert any(record["truncated"] and not record["demand_complete"] for record in records)


# -- the checker rejects wrong records ----------------------------------------------

def _subtraction():
    builder = (FunctionBuilder().ins(op("INT_SUB", [reg(RDI), reg(RSI)], reg(RAX)))
               .ins(op("INT_XOR", [reg(RAX), const(0x5A)], reg(RAX))).ret())
    analyzed = _analyzed(builder)
    return analyzed, _record(analyzed, RAX)


def _failures(analyzed, record):
    pools = lambda seed: {RDI: 0x1000 + seed, RSI: 7 * seed + 1, RSP: 0x7000_0000}
    report = check_records(analyzed, seeds=range(4), register_pools=pools, records=[record])
    assert report.evaluated == 4
    return len(report.failures)


def test_the_checker_passes_the_record_and_rejects_corrupted_ones():
    analyzed, record = _subtraction()
    assert _failures(analyzed, record) == 0
    swapped = copying.deepcopy(record)
    (node,) = _nodes(swapped, "op", "INT_SUB")
    first, second = node["operands"][0]["parts"], node["operands"][1]["parts"]
    node["operands"][0]["parts"], node["operands"][1]["parts"] = second, first
    assert _failures(analyzed, swapped) == 4
    wrong = copying.deepcopy(record)
    (constant,) = _nodes(wrong, "const")
    constant["value"] ^= 1
    assert _failures(analyzed, wrong) == 4
    shifted = copying.deepcopy(record)
    (node,) = _nodes(shifted, "op", "INT_SUB")
    part = node["operands"][1]["parts"][0]
    part["bytes"] = [part["bytes"][0] + 1, part["bytes"][1] + 1]   # the wrong bytes of the producer
    assert _failures(analyzed, shifted) == 4


def test_the_checker_rejects_a_phi_missing_the_taken_alternative():
    analyzed = _analyzed(_branchy())
    record = copying.deepcopy(_record(analyzed, R8))
    (phi,) = _nodes(record, "phi")
    phi["alternatives"] = phi["alternatives"][:1]
    report = check_records(analyzed, seeds=range(4), register_pools=_branch_pools, records=[record])
    assert report.evaluated == 0 and report.skipped == {"condition choice mismatch": 4}
    # Old v2 unconditional alternatives still exercise the missing-value
    # check; v3's malformed conditional choice is refused before evaluation.
    phi.pop("condition")
    phi.pop("choices")
    report = check_records(analyzed, seeds=range(4), register_pools=_branch_pools, records=[record])
    assert report.evaluated == 4 and len(report.failures) == 2


# The opt-in physical view interprets actual byte addresses. Ordinary record
# eligibility and the engine's original alias/call debts remain unchanged.
def _physical_analyzed(builder):
    return analyze_units(program_units(builder), assume_entry_values_not_frame=False,
                         assume_opaque_callees_leave_no_stack_addresses=False,
                         assume_globals_disjoint_from_stack=False)["1:1000"]


def _physical_record(analyzed, key, *, physical_memory=True):
    action = next(action for action in analyzed.normalized.memory_ssa.actions if action.operation_key == key)
    return root_record(analyzed.normalized, analyzed.unit,
                       [(analyzed.normalized.memory_graph.definition_nodes[identifier],
                         (analyzed.normalized.memory_ssa.definitions[identifier].span,))
                        for identifier in action.write_definition_ids], physical_memory=physical_memory)


@pytest.mark.parametrize("delta", (-24, -20, -16, 0x100))
def test_physical_load_interprets_prologue_overlap_without_a_no_alias_assumption(delta):
    from pcode_interpreter import Interpreter
    from record_oracle import entry_reader, final_register
    from synthetic import REG
    from tdo_v2._record_memory import evaluate_physical

    builder = (FunctionBuilder().push(RBX).push(RSI)
               .ins(add(tmp(0x100), reg(RCX), const(8)), load(reg(RAX), tmp(0x100)))
               .pop(RSI).pop(RBX).ret())
    analyzed = _physical_analyzed(builder)
    record = _physical_record(analyzed, "1:1008:1:LOAD")
    assert eligibility(record) == "debt"
    debt_ids = [node["id"] for node in record["nodes"] if node["kind"] == "debt"]
    vm = Interpreter(analyzed.unit.observation, constant_space=0, seed=3)
    for offset, value in ((RSP, 0x70000000), (RCX, 0x70000000 + delta),
                          (RBX, 0x1122334455667788), (RSI, 0xaabbccddeeff0011)):
        vm.preset(REG, offset, 8, value)
    run = vm.run()
    assert run.completed
    result = evaluate_physical(record, entry_reader(vm))
    assert result.value == final_register(vm, RAX, 8)
    assert any(item["kind"] == "load" and item["preserved_debts"] for item in result.evidence)
    assert [node["id"] for node in record["nodes"] if node["kind"] == "debt"] == debt_ids
    assert eligibility(record) == "debt"
    with pytest.raises(Ineligible, match="debt"):
        evaluate(record, entry_reader(vm))


def test_physical_overlay_orders_definite_partial_writes_with_aliasing_stores():
    from pcode_interpreter import Interpreter
    from record_oracle import entry_reader, final_register
    from synthetic import REG
    from tdo_v2._record_memory import evaluate_physical

    builder = (FunctionBuilder().ins(store(reg(RSI), reg(RBX)))
               .ins(store(reg(RDI), reg(RCX, 1))).ins(load(reg(RAX), reg(RDI))).ret())
    analyzed = _physical_analyzed(builder)
    record = _physical_record(analyzed, "1:1008:0:LOAD")
    assert eligibility(record) == "debt"
    vm = Interpreter(analyzed.unit.observation, constant_space=0, seed=5)
    for offset, value in ((RSP, 0x70000000), (RSI, 0x4000), (RDI, 0x4000),
                          (RBX, 0x1122334455667788), (RCX, 0xaa)):
        vm.preset(REG, offset, 8, value)
    assert vm.run().completed
    result = evaluate_physical(record, entry_reader(vm))
    assert result.value == final_register(vm, RAX, 8) == 0x11223344556677aa
    (load_evidence,) = [item for item in result.evidence if item["kind"] == "load"]
    assert load_evidence["sources"][0]["writer"] == "1:1004:0:STORE"
    assert all(source["writer"] == "1:1000:0:STORE" for source in load_evidence["sources"][1:])


def test_physical_symbolic_pointer_write_preserves_the_unknown_writer_diagnostic():
    from pcode_interpreter import Interpreter
    from record_oracle import entry_reader, final_register
    from synthetic import REG
    from tdo_v2._record_memory import evaluate_physical

    builder = (FunctionBuilder().ins(op("INT_MULT", [reg(RSI), reg(RBX)], tmp(0x200)),
                                    store(tmp(0x200), reg(R8)))
               .ins(load(tmp(0x100), reg(RDI))).ins(store(tmp(0x100), reg(RCX, 2)))
               .ins(load(reg(RAX, 2), reg(RDX))).ret())
    analyzed = _physical_analyzed(builder)
    assert "1:1008:0:STORE" in analyzed.summary.unknown_writers
    record = _physical_record(analyzed, "1:100c:0:LOAD")
    assert eligibility(record) == "debt"
    vm = Interpreter(analyzed.unit.observation, constant_space=0, seed=7)
    for offset, value in ((RSP, 0x70000000), (RSI, 1), (RDI, 0x4000),
                          (RBX, 0x4000), (R8, 0x4100), (RCX, 0x1234), (RDX, 0x4100)):
        vm.preset(REG, offset, 8, value)
    assert vm.run().completed
    result = evaluate_physical(record, entry_reader(vm))
    assert result.value == final_register(vm, RAX, 2) == 0x1234
    assert "1:1008:0:STORE" in analyzed.summary.unknown_writers
    assert eligibility(record) == "debt"


def test_physical_inactive_call_is_skipped_and_an_active_call_or_unknown_guard_is_refused():
    from pcode_interpreter import Interpreter
    from record_oracle import entry_reader, final_register
    from synthetic import CF, DATA_BASE, RAM, REG
    from tdo_v2._record_memory import evaluate_physical

    builder = (FunctionBuilder().cbranch("read", reg(CF, 1)).call(0x1f00)
               .label("read").ins(load(reg(RAX), const(DATA_BASE))).ret())
    analyzed = _physical_analyzed(builder)
    record = _physical_record(analyzed, "1:1008:0:LOAD")
    assert eligibility(record) == "debt"
    vm = Interpreter(analyzed.unit.observation, constant_space=0, seed=9)
    vm.preset(REG, RSP, 8, 0x70000000)
    vm.preset(REG, CF, 1, 1)
    vm.preset(RAM, DATA_BASE, 8, 0xabcdef)
    run = vm.run()
    assert run.completed and not any(key.endswith(":CALL") for key in run.executed)
    assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8)
    vm.preset(REG, CF, 1, 0)
    with pytest.raises(Ineligible, match="call|memory event"):
        evaluate_physical(record, entry_reader(vm))
    with pytest.raises(Ineligible):
        evaluate_physical(record, lambda node: None)


def test_physical_overlay_wraps_each_byte_in_the_original_address_space():
    from pcode_interpreter import Interpreter
    from record_oracle import entry_reader, final_register
    from synthetic import RAM, REG
    from tdo_v2._record_memory import evaluate_physical

    builder = (FunctionBuilder().ins(store(reg(RSI), reg(RBX)))
               .ins(load(reg(RAX), reg(RDI))).ret())
    analyzed = _physical_analyzed(builder)
    record = _physical_record(analyzed, "1:1004:0:LOAD")
    vm = Interpreter(analyzed.unit.observation, constant_space=0, seed=11, address_bits={RAM: 64})
    for offset, value in ((RSP, 0x70000000), (RSI, (1 << 64) - 4),
                          (RDI, (1 << 64) - 2), (RBX, 0x1122334455667788)):
        vm.preset(REG, offset, 8, value)
    vm.preset(RAM, 4, 2, 0xbbaa)
    assert vm.run().completed
    result = evaluate_physical(record, entry_reader(vm))
    assert result.value == final_register(vm, RAX, 8) == 0xbbaa112233445566
    assert [source.get("offset") for source in result.evidence[-1]["sources"]] == [2, 3, 4, 5, 6, 7, None, None]


@pytest.mark.parametrize("taken", (0, 1))
def test_physical_overlay_uses_the_actual_store_arm_and_only_demands_its_address(taken):
    from pcode_interpreter import Interpreter
    from record_oracle import entry_reader, final_register
    from synthetic import CF, REG
    from tdo_v2._record_memory import evaluate_physical

    builder = FunctionBuilder().cbranch("right", reg(CF, 1))
    builder.ins(store(reg(RSI), reg(RBX))).branch("read")
    builder.label("right").ins(store(reg(RDI), reg(RCX, 1)))
    builder.label("read").ins(load(reg(RAX), reg(RDX))).ret()
    analyzed = _physical_analyzed(builder)
    record = _physical_record(analyzed, "1:1010:0:LOAD")
    vm = Interpreter(analyzed.unit.observation, constant_space=0, seed=13)
    for offset, value in ((RSP, 0x70000000), (RSI, 0x4000), (RDI, 0x4000), (RDX, 0x4000),
                          (RBX, 0x1122334455667788), (RCX, 0xaa)):
        vm.preset(REG, offset, 8, value)
    vm.preset(REG, CF, 1, taken)
    assert vm.run().completed
    reader = entry_reader(vm)
    assert evaluate_physical(record, reader).value == final_register(vm, RAX, 8)
    missing_right = lambda node: None if isinstance(node, dict) and node.get("register", {}).get("offset") == RDI else reader(node)
    if taken:
        with pytest.raises(Ineligible, match="unknown physical inputs"):
            evaluate_physical(record, missing_right)
    else:
        assert evaluate_physical(record, missing_right).value == final_register(vm, RAX, 8)
    with pytest.raises(Ineligible, match="physical work limit"):
        evaluate_physical(record, reader, max_steps=1)


def test_physical_store_without_a_load_still_refuses_an_executed_call_prefix():
    from pcode_interpreter import Interpreter
    from record_oracle import entry_reader
    from synthetic import CF, DATA_BASE, REG
    from tdo_v2._record_memory import evaluate_physical

    builder = (FunctionBuilder().cbranch("write", reg(CF, 1)).call(0x1f00)
               .label("write").ins(store(const(DATA_BASE), const(0x1234, 2))).ret())
    analyzed = _physical_analyzed(builder)
    record = _physical_record(analyzed, "1:1008:0:STORE")
    assert not _nodes(record, "op", "LOAD")
    vm = Interpreter(analyzed.unit.observation, constant_space=0, seed=17)
    vm.preset(REG, RSP, 8, 0x70000000)
    vm.preset(REG, CF, 1, 1)
    assert vm.run().completed
    reader = entry_reader(vm)
    assert evaluate_physical(record, reader).value == 0x1234
    incomplete = copying.deepcopy(record)
    incomplete.pop("physical_effect_inventory")
    with pytest.raises(Ineligible, match="root inventory"):
        evaluate_physical(incomplete, reader)
    vm.preset(REG, CF, 1, 0)
    with pytest.raises(Ineligible, match="root memory event"):
        evaluate_physical(record, reader)


@pytest.mark.parametrize("mutation", ("truncated", "demand", "reversed choices", "duplicate choices"))
def test_physical_evaluation_refuses_an_incomplete_or_malformed_selection_contract_before_entry(mutation):
    from synthetic import CF
    from tdo_v2._record_memory import evaluate_physical

    builder = FunctionBuilder().cbranch("right", reg(CF, 1))
    builder.ins(copy(reg(RAX), const(7))).branch("read")
    builder.label("right").ins(copy(reg(RAX), const(99)))
    builder.label("read").ins(copy(reg(R8), reg(RAX))).ret()
    record = _physical_record(_physical_analyzed(builder), "1:1010:0:COPY")
    assert evaluate_physical(record, lambda node: 0).value == 7
    corrupted = copying.deepcopy(record)
    if mutation == "truncated":
        corrupted["truncated"] = True
    elif mutation == "demand":
        corrupted["demand_complete"] = False
    else:
        (phi,) = _nodes(corrupted, "phi")
        phi["choices"] = [False, True] if mutation == "reversed choices" else [True, True]
    requested = []
    with pytest.raises(Ineligible):
        evaluate_physical(corrupted, lambda node: requested.append(node) or 0)
    assert not requested


@pytest.mark.parametrize("source_kind", ("unsupported", "debt"))
def test_physical_only_nonoverlapping_writer_does_not_change_static_value_eligibility(source_kind):
    from synthetic import DATA_BASE, RAM
    from tdo_v2._record_memory import evaluate_physical

    read_address, value = DATA_BASE + 0x80, 0x1122334455667788
    if source_kind == "unsupported":
        builder = FunctionBuilder().ins(op("FLOAT_ADD", [reg(RBX), reg(RSI)], tmp(0x100)))
        auxiliary_key, root_key = "1:1000:0:FLOAT_ADD", "1:1008:0:LOAD"
    else:
        builder = (FunctionBuilder().ins(store(const(DATA_BASE + 0x20), reg(RBX)))
                   .ins(load(tmp(0x100), reg(RDI))))
        auxiliary_key, root_key = "1:1004:0:LOAD", "1:100c:0:LOAD"
    builder.ins(store(const(DATA_BASE), tmp(0x100))).ins(load(reg(RAX), const(read_address))).ret()
    analyzed = _physical_analyzed(builder)
    ordinary = _physical_record(analyzed, root_key, physical_memory=False)
    physical = _physical_record(analyzed, root_key)
    assert not any(node.get("key") == auxiliary_key for node in ordinary["nodes"])
    (auxiliary,) = [node for node in physical["nodes"] if node.get("key") == auxiliary_key]
    assert auxiliary.get("physical_only") is True
    if source_kind == "debt":
        assert auxiliary["debts"]
        assert all(physical["nodes"][identifier].get("physical_only") for identifier in auxiliary["debts"])
    assert eligibility(ordinary) is eligibility(physical) is None

    def read_entry(node):
        # The actual entry RAM bytes are known. Neither the disjoint STORE's
        # value expression nor its register inputs are needed for this LOAD.
        assert isinstance(node, tuple) and node[:2] == ("memory", RAM)
        _, _, address, size = node
        assert read_address <= address < address + size <= read_address + 8
        return (value >> (8 * (address - read_address))) & ((1 << (8 * size)) - 1)

    assert evaluate(ordinary, read_entry) == evaluate(physical, read_entry) == {value}
    result = evaluate_physical(physical, read_entry)
    assert result.value == value
    assert not any(item["kind"] == "store" for item in result.evidence)
    assert result.evidence[-1]["sources"] == [{"at": byte, "entry": read_address + byte} for byte in range(8)]


@pytest.mark.parametrize("reason", ("unsupported", "debt"))
def test_a_forged_physical_only_flag_cannot_hide_actual_value_nodes_from_eligibility(reason):
    if reason == "unsupported":
        builder = FunctionBuilder().ins(op("FLOAT_ADD", [reg(RBX), reg(RSI)], reg(RAX))).ret()
        key, expected = "1:1000:0:FLOAT_ADD", "unsupported FLOAT_ADD"
    else:
        builder = (FunctionBuilder().ins(store(reg(RSI), reg(RBX)))
                   .ins(load(reg(RAX), reg(RDI))).ret())
        key, expected = "1:1004:0:LOAD", "debt"
    record = _physical_record(_physical_analyzed(builder), key)
    assert eligibility(record) == expected
    forged = copying.deepcopy(record)
    for node in forged["nodes"]:
        node["physical_only"] = True
    assert eligibility(forged) == expected
    with pytest.raises(Ineligible, match=expected):
        evaluate(forged, lambda node: 0)
