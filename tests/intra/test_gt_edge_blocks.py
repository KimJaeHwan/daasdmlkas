"""(G-T G1, docs 25.101) Conditional jumps leaving the function: outcome edge blocks.

A ``jcc other_function`` whose fallthrough stays local gets a taken-outcome
edge block in the p-code block graph (no operations, no successors, an exit);
its source block no longer exits. In G1 nothing is composed on the edge: it is
a tail exit at its own key, with no exit state, and the summary otherwise
matches the old one. A conditional jump leaving the function in any other
shape keeps an unknown exit at its own block -- forced from the p-code target
even when the observed flow omits it.
"""

import pathlib
import re

import dataclasses

import pytest

from synthetic import (
    CODE_BASE, RAX, RCX, RSP, ZF, FunctionBuilder, analyze_summaries, boundary, const, copy,
    normalize_with_observation, program_units, ram, reg,
)
from tdo_v2.function_summary import summarize_function
from tdo_v2.interprocedural import analyze_units
from tdo_v2.model import StorageObjectId
from tdo_v2.pcode_blocks import build_pcode_block_graph, escaping_branches, outcome_of, terminator
from tdo_v2.register_delta_proofs import derive_register_delta_proof
from tdo_v2.span_geometry import ByteSpan, StorageObjectKind

OUTSIDE = CODE_BASE + 0x800   # an address outside the function


def _escaping(*, flow_targets=True):
    """ECX = 1; jcc OUTSIDE (ZF); ECX = 2; ret -- the jcc rewritten to leave."""
    builder = (FunctionBuilder(entry=CODE_BASE)
               .ins(copy(reg(RCX, 4), const(1, 4)))
               .cbranch("done", reg(ZF, 1))
               .ins(copy(reg(RCX, 4), const(2, 4)))
               .label("done")
               .ret())
    raw = builder.to_json()
    row = raw["instructions"][1]
    (branch,) = [item for item in row["operations"] if item["opcode"] == "CBRANCH"]
    branch["inputs"][0] = ram(OUTSIDE)
    row["flow_targets"] = [{"space_id": branch["inputs"][0]["space_id"], "byte_offset": OUTSIDE}] \
        if flow_targets else []
    builder.to_json = lambda raw=raw: raw
    return builder


def _graph(builder):
    function, observation = normalize_with_observation(builder)
    return build_pcode_block_graph(observation, function.scopes.function.entry), observation


def test_escaping_conditional_jump_gets_a_taken_edge_block():
    graph, observation = _graph(_escaping())
    rows = {row.address: row for row in observation.instructions}
    (edge,) = [block for block in graph.blocks if block.edge is not None]
    source = next(block for block in graph.blocks if block.key == edge.edge.source)
    assert edge.key == f"{source.key}>{edge.edge.ordinal}t"
    assert edge.start == edge.stop == edge.edge.ordinal + 1 and edge.successors == () and edge.exits
    assert edge.edge.outcome == "taken" and edge.edge.target.byte_offset == OUTSIDE
    assert terminator(edge, rows[edge.instruction]) is None
    assert not source.exits and edge.key in source.successors and len(source.successors) == 2
    (fallthrough,) = [key for key in source.successors if key != edge.key]
    assert outcome_of(graph, source.key, edge.key, rows) == "taken"
    assert outcome_of(graph, source.key, fallthrough, rows) == "fallthrough"
    assert graph.unmaterialized == ()


def test_uncomposed_edge_is_a_tail_exit_without_exit_state():
    builder = _escaping()
    function, observation = normalize_with_observation(builder)
    summary = summarize_function(function, observation)
    graph = build_pcode_block_graph(observation, function.scopes.function.entry)
    (edge,) = [block.key for block in graph.blocks if block.edge is not None]
    assert summary.tail_exits == (edge,)
    assert len(summary.exits) == 1 and summary.exits[0].block_key != edge   # the RET only
    assert edge not in summary.dead_exits


def test_observed_flow_without_the_target_still_exits():
    """An empty flow-target list used to make the escape vanish (the block's
    exits came from the observed targets only): the p-code target forces an
    unknown exit at the jump's own block."""
    graph, observation = _graph(_escaping(flow_targets=False))
    assert not any(block.edge is not None for block in graph.blocks)
    (site,) = graph.unmaterialized
    assert site[2] == "observed flow disagrees"
    source = next(block for block in graph.blocks if block.instruction == site[0])
    assert source.exits and source.successors
    function, observation = normalize_with_observation(_escaping(flow_targets=False))
    summary = summarize_function(function, observation)
    assert summary.tail_exits == (source.key,)


def test_call_flagged_escape_is_materialized_before_the_landing_pad_check():
    """A jcc Ghidra flags as a call (not a jump), its fallthrough listed as a
    flow target: that "landing pad" is the fallthrough itself -- the row gets
    its edge block before the call landing-pad refusal (review r1, Astra; the
    old order refused the whole graph). The synthetic provider's call evidence
    cannot carry a call-flagged jcc, so the flags and the listed fallthrough
    are set on the validated observation directly."""
    function, observation = normalize_with_observation(_escaping())
    row = observation.instructions[1]
    listed = dataclasses.replace(row, flow_targets=tuple(sorted(
        {*row.flow_targets, row.fallthrough}, key=lambda item: (item.space_id, item.byte_offset))))
    flagged = dataclasses.replace(listed, flow=dataclasses.replace(row.flow, is_call=True, is_jump=False))
    for shaped in (listed, flagged):
        instructions = (*observation.instructions[:1], shaped, *observation.instructions[2:])
        graph = build_pcode_block_graph(dataclasses.replace(observation, instructions=instructions),
                                        function.scopes.function.entry)
        assert graph.unsupported is None
        (edge,) = [block for block in graph.blocks if block.edge is not None]
        source = next(block for block in graph.blocks if block.key == edge.edge.source)
        fallthrough = f"{row.fallthrough.space_id:x}:{row.fallthrough.byte_offset:x}"
        assert source.successors == tuple(sorted((fallthrough, edge.key))) and not source.exits


def test_an_edge_behind_a_cut_is_dead_not_a_tail_exit():
    """A cut (a noreturn call, a trap) before the jcc: its edge block is never
    reached -- no tail exit, as the jcc's block was not before (review r1)."""
    builder = _escaping()
    function, observation = normalize_with_observation(builder)
    first = observation.instructions[0]
    cut = f"{first.address.space_id:x}:{first.address.byte_offset:x}:0:{first.operations[0].opcode}"
    summary = summarize_function(function, observation, dead_ops=frozenset({cut}))
    assert summary.tail_exits == () and summary.exits == ()


def _split_escape():
    """One instruction: CBRANCH OUTSIDE (ZF); ECX = 3 -- an escaping jump that is
    not the instruction's last operation (internal flow: no edge block)."""
    builder = (FunctionBuilder(entry=CODE_BASE)
               .ins(copy(reg(RCX, 4), const(1, 4)))
               .ins(copy(reg(RCX, 4), const(2, 4)), copy(reg(RCX, 4), const(3, 4)))
               .ret())
    raw = builder.to_json()
    row = raw["instructions"][1]
    first = row["operations"][0]
    row["operations"][0] = {"ordinal": 0, "opcode": "CBRANCH", "inputs": [ram(OUTSIDE), reg(ZF, 1)],
                            "output_present": False, "output": None}
    row["flow_targets"] = [{"space_id": ram(OUTSIDE)["space_id"], "byte_offset": OUTSIDE}]
    row["flow_type"] = {**row["flow_type"], "is_flow": True, "is_jump": True, "is_conditional": True}
    builder.to_json = lambda raw=raw: raw
    return builder, first


def test_a_split_escape_is_listed_and_keeps_its_unknown_exit():
    builder, _ = _split_escape()
    graph, observation = _graph(builder)
    rows = {row.address: row for row in observation.instructions}
    assert not any(block.edge is not None for block in graph.blocks)
    (site,) = graph.unmaterialized
    assert site[1:] == (0, "not the last operation")
    source = next(block for block in graph.blocks if block.instruction == site[0] and block.start == 0)
    assert source.exits
    (next_segment,) = [key for key in source.successors if key.endswith("#1")]
    assert outcome_of(graph, source.key, next_segment, rows) == "fallthrough"


def test_legacy_conditional_noreturn_cut_lands_on_the_edge_block():
    """The abort-model conditional jump (test_noreturn_models) is an eligible
    row: its edge block is the dead edge, the summary is the old one."""
    from test_noreturn_models import _caller, _guarded, _analyze

    results = _analyze(_guarded(), _caller())
    helper = results["1:1000"]
    graph = build_pcode_block_graph(helper.unit.observation, helper.unit.scopes.function.entry)
    (edge,) = [block for block in graph.blocks if block.edge is not None]
    assert edge.key == "1:1008>0t"
    assert helper.summary.tail_exits == () and len(helper.summary.exits) == 1
    assert edge.key not in helper.summary.dead_exits


def _leave(builder, index):
    """Rewrite the CBRANCH of instruction ``index`` to jump to OUTSIDE (and list
    OUTSIDE as its only observed flow target)."""
    raw = builder.to_json()
    row = raw["instructions"][index]
    (branch,) = [item for item in row["operations"] if item["opcode"] == "CBRANCH"]
    branch["inputs"][0] = ram(OUTSIDE)
    row["flow_targets"] = [{"space_id": branch["inputs"][0]["space_id"], "byte_offset": OUTSIDE}]
    builder.to_json = lambda raw=raw: raw
    return builder


def test_escaping_branches_name_each_ineligible_shape():
    """The inventory's reason per shape (review r1): only the eligible shape
    has no reason; flow override, S1 continuation evidence, a fallthrough that
    is not local and a disagreeing observed flow each name themselves."""
    _, observation = _graph(_escaping())
    local = {row.address for row in observation.instructions}
    row = observation.instructions[1]
    ((ordinal, target, reason),) = escaping_branches(row, local, frozenset())
    assert (ordinal, target.byte_offset, reason) == (len(row.operations) - 1, OUTSIDE, None)
    stray = dataclasses.replace(row.flow_targets[0], byte_offset=OUTSIDE + 0x40)
    shapes = (
        (dataclasses.replace(row, flow=dataclasses.replace(row.flow, is_override=True)), frozenset(), "flow override"),
        (row, frozenset({row.address}), "S1 continuation evidence"),
        (dataclasses.replace(row, fallthrough=None), frozenset(), "fallthrough not local"),
        (dataclasses.replace(row, flow_targets=(*row.flow_targets, stray)), frozenset(), "observed flow disagrees"),
    )
    for shaped, exit_rows, expected in shapes:
        assert [item[2] for item in escaping_branches(shaped, local, exit_rows)] == [expected]


def test_root_diagnostics_list_escaping_branches():
    """The diagnostic row per escaping jump: its edge block, or why there is none."""
    empty = boundary({}, {})
    run = analyze_summaries([_escaping()], empty, root_diagnostics=True)
    (row,) = run.diagnostics["functions"]["1:1000"]["escaping_branches"]
    assert row["edge"] == "1:1004>0t" and row["reason"] is None and row["site"] == "1:1004:0:CBRANCH"
    run = analyze_summaries([_split_escape()[0]], empty, root_diagnostics=True)
    (row,) = run.diagnostics["functions"]["1:1000"]["escaping_branches"]
    assert row["edge"] is None and row["site"] == "1:1004:0:CBRANCH"
    assert row["reason"] == "escaping-branch-not-materialized:not the last operation"


def _framed(*, escape):
    builder = (FunctionBuilder(entry=CODE_BASE).sub_rsp(0x20)
               .cbranch("done", reg(ZF, 1))
               .ins(copy(reg(RCX, 4), const(2, 4)))
               .label("done").add_rsp(0x20).ret())
    return _leave(builder, 1) if escape else builder


def test_register_delta_proof_refuses_an_uncomposed_edge():
    """An edge block carries no exit state: the independent SP proof refuses,
    as it refused the escaping jump's own block before G1."""
    for escape in (False, True):
        unit = analyze_units(program_units(_framed(escape=escape)))["1:1000"].unit
        span = ByteSpan(StorageObjectId(StorageObjectKind.REGISTER_FILE, unit.scopes.program.scope, 0), RSP, 8)
        proof = derive_register_delta_proof(unit, span, {}, {})
        assert (proof is None) == escape


@pytest.mark.parametrize("engine", ("dense", "dense-unchained", "sparse"))
def test_a_loop_leaving_through_the_abort_edge_names_it_as_a_loop_exit(monkeypatch, engine):
    """The legacy conditional import-noreturn jump keeps its function resolved
    (its edge is a dead edge, not a tail exit), so the recurrence index decodes
    S -> E today: the edge block is the taken outcome and a loop exit (review
    r2, Fable), in every memory SSA engine."""
    from test_noreturn_models import ABORT, FLAG, _JumpsToAbort, _analyze
    from test_record_recurrence import _joins
    from tdo_v2._record_recurrence import RecurrenceIndex
    from tdo_v2.lane_slice import lane_index
    from synthetic import RBX, RDX, add, op, tmp

    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    flag = tmp(0x308, 1)
    builder = (_JumpsToAbort(conditional={2})
               .ins(copy(reg(RAX), reg(RCX)))
               .label("header")
               .cbranch("exit", flag, op("INT_LESSEQUAL", [reg(RDX), reg(RAX)], flag))
               .ins(op("INT_NOTEQUAL", [reg(RAX), const(0x99)], FLAG), op("CBRANCH", [ram(ABORT), FLAG]))
               .ins(add(reg(RAX), reg(RAX), const(1))).branch("header")
               .label("exit").ins(copy(reg(RBX), reg(RAX))).ret())
    helper = _analyze(builder)["1:1000"]
    assert helper.summary.tail_exits == ()
    lane = lane_index(helper.normalized, helper.unit)
    index = RecurrenceIndex(helper.normalized, helper.unit, lane)
    matches = [index.for_join(identifier) for identifier in _joins(lane)]
    assert matches and all(reason is None for _, reason in matches)
    for match, _ in matches:
        assert match.header == "1:1004"
        assert match.exits == (("1:1004", "1:1014"), ("1:1008", "1:1008>1t"))
        outcomes = {condition.operation: (condition.true_successor, condition.false_successor)
                    for condition in match.conditions}
        assert outcomes == {"1:1004:1:CBRANCH": ("1:1014", "1:1008"),
                            "1:1008:1:CBRANCH": ("1:1008>1t", "1:100c")}



def test_a_loop_left_only_through_the_edge_gets_its_first_terminal():
    """Zero-to-one terminal (design r6 section 3): a loop whose only way out
    is the escaping jump had no exit state (the jump's block kept a local
    successor); its edge block is now the one exit state -- what the
    universal "every exit" readers of integration read, structurally like a
    real dead terminal. The summary still has no exit state, only the tail."""
    builder = _leave(FunctionBuilder(entry=CODE_BASE).label("top").ins(copy(reg(RCX, 4), const(1, 4)))
                     .cbranch("top", reg(ZF, 1)).branch("top"), 1)
    function, observation = normalize_with_observation(builder)
    assert [state.block_key for state in function.memory_ssa.exit_states] == ["1:1004>0t"]
    summary = summarize_function(function, observation)
    assert summary.tail_exits == ("1:1004>0t",) and summary.exits == () and summary.dead_exits == ()


def test_dead_return_and_frontier_precedence_beside_an_edge_block():
    """Classification precedence is unchanged by an edge block: behind a cut
    the RETURN is a dead exit, the targetless ``jmp rax`` stays a frontier
    (unknown transfer) state, and the edge block before the cut stays a tail
    exit -- never a dead exit, never an exit state."""
    builder = _leave(FunctionBuilder(entry=CODE_BASE).ins(copy(reg(RCX, 4), const(1, 4)))
                     .cbranch("s", reg(ZF, 1))
                     .ins(copy(reg(RCX, 4), const(2, 4)))
                     .cbranch("s", reg(ZF, 1)).ins(copy(reg(RAX), const(7))).ret()
                     .label("s").jump_indirect(reg(RAX)), 1)
    function, observation = normalize_with_observation(builder)
    cut_row = observation.instructions[2]
    cut = f"{cut_row.address.space_id:x}:{cut_row.address.byte_offset:x}:0:{cut_row.operations[0].opcode}"
    for dead_ops, exits, dead in ((frozenset(), ["1:1014"], ()), (frozenset({cut}), [], ("1:1014",))):
        summary = summarize_function(function, observation, dead_ops=dead_ops)
        assert summary.tail_exits == ("1:1004>0t",)
        assert [row.block_key for row in summary.exits] == exits and summary.dead_exits == dead
        assert [(row.site, row.block) for row in summary.unknown_transfers] == [("control:1:1000:1:1018", "1:1018")]


@pytest.mark.parametrize("mode", ("1", "sparse", "sparse-dense-reference"))
def test_chi_dense_and_lazy_agree_on_an_edge_block(monkeypatch, mode):
    """The shadow chi check builds one crossing entry per terminal, edge block
    included (a call crosses into E): dense and lazy agree on every read and
    terminal, and E never reaches the summary's exit states."""
    from synthetic import R9, RSI, add, load, store, tmp
    from tdo_v2 import _chi_shadow

    monkeypatch.setenv("TDO_V2_CHI_SHADOW", mode.split("-")[0])
    if mode.endswith("reference"):
        monkeypatch.setenv("TDO_V2_CHI_REFERENCE", "dense")
    states = (_chi_shadow.RESULTS, _chi_shadow.TERMINALS, _chi_shadow.TERMINAL_MISMATCHES, _chi_shadow.METRICS,
              _chi_shadow.TERMINAL_KINDS, _chi_shadow.LAZY)
    for state in states:
        state.clear()
    slot = tmp(0x100)
    builder = (FunctionBuilder(entry=CODE_BASE).sub_rsp(0x48).ins(add(slot, reg(RSP), const(0x10)), store(slot, reg(RSI)))
               .call(CODE_BASE + 0xE00).cbranch("done", reg(ZF, 1))
               .ins(add(slot, reg(RSP), const(0x10)), load(reg(R9), slot)).label("done").add_rsp(0x48).ret())
    rows = builder.to_json()["instructions"]
    jump = next(index for index, row in enumerate(rows) if any(item["opcode"] == "CBRANCH" for item in row["operations"]))
    try:
        result = analyze_units(program_units(_leave(builder, jump)))["1:1000"]
        assert result.summary.tail_exits == ("1:100c>0t",)
        assert [row.block_key for row in result.summary.exits] == ["1:1018"]
        assert _chi_shadow.RESULTS and all(found == [] for found in _chi_shadow.RESULTS.values())
        assert _chi_shadow.TERMINAL_MISMATCHES and all(found == [] for found in _chi_shadow.TERMINAL_MISMATCHES.values())
        (terminals,) = _chi_shadow.TERMINALS.values()
        assert {item[0] for item in terminals} == {"1:100c>0t", "1:1018"}
    finally:
        for state in states:
            state.clear()


def test_a_branch_to_a_non_address_destination_fails_safe_to_an_unknown_exit():
    """p-code gives a direct branch a CONSTANT (relative) or an ADDRESS
    destination; nothing in validation pins that, so any other kind is read as
    leaving (as ``_split`` reads it): an unknown exit at the jump's own block,
    no edge block, listed with its reason (review r2, Fable P3-4)."""
    from tdo_v2._scope_contracts import VarnodeKindCode

    function, observation = normalize_with_observation(_escaping())
    row = observation.instructions[1]
    branch = row.operations[-1]
    destination = dataclasses.replace(branch.inputs[0], kind=VarnodeKindCode.REGISTER,
                                      coordinate=dataclasses.replace(branch.inputs[0].coordinate, space_id=2,
                                                                     byte_offset=0x10))
    shaped = dataclasses.replace(row, operations=(*row.operations[:-1],
                                                  dataclasses.replace(branch, inputs=(destination, *branch.inputs[1:]))))
    # (review r3) also with no observed flow target: only the p-code reading keeps the exit
    for listed in (shaped, dataclasses.replace(shaped, flow_targets=())):
        instructions = (*observation.instructions[:1], listed, *observation.instructions[2:])
        graph = build_pcode_block_graph(dataclasses.replace(observation, instructions=instructions),
                                        function.scopes.function.entry)
        assert not any(block.edge is not None for block in graph.blocks)
        source = next(block for block in graph.blocks if block.instruction == row.address)
        assert source.exits
        assert graph.unmaterialized == ((row.address, len(row.operations) - 1, "destination not an address"),)

# lint (design r4 section 6): terminator interpretation -- reading
# ``operations[block.stop - 1]`` as what ends a block -- goes through
# ``pcode_blocks.terminator``; the reads left are allowed by name, each
# safe because it never sees an edge block (or checks ``edge`` first).
_ALLOWED_STOP_READS = {
    "control_dependence.py": 4,      # decisions: blocks with >= 2 successors (an edge block has none)
    "_record_conditions.py": 3,      # relative-target arithmetic + decision keys of real CBRANCH blocks
    "_record_recurrence.py": 1,      # decision key of a real CBRANCH block (after terminator())
    "_record_transitions.py": 1,     # decision key after reading the block's own operation slice
    "register_delta_proofs.py": 2,   # tail BRANCH inside the operation loop; exit check after the edge test
    "_guarded_image_reads.py": 1,    # dominator ancestors (an edge block dominates nothing)
    "_guarded_ranges.py": 1,         # predecessor arithmetic, instructions with internal flow only
    "function_summary.py": 1,        # dead_exit, after its edge test
}


def test_terminator_reads_are_named():
    root = pathlib.Path(__file__).resolve().parents[2] / "src" / "tdo_v2"
    found = {}
    for path in sorted(root.rglob("*.py")):
        if path.name == "pcode_blocks.py":
            continue
        count = len(re.findall(r"\.stop - 1\b", path.read_text(encoding="utf-8")))
        if count:
            found[path.name] = count
    assert found == _ALLOWED_STOP_READS
