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


def _escaping(*, flow_targets=True, is_call=False, listed_fallthrough=False):
    """ECX = 1; jcc OUTSIDE (ZF); ECX = 2; ret -- the jcc rewritten to leave.
    ``is_call``: Ghidra's call flag on the jcc (and no jump flag);
    ``listed_fallthrough``: the fallthrough listed as a flow target too."""
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
    row["flow_type"] = {**row["flow_type"], "is_call": is_call}
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
    its edge block before the call landing-pad refusal (review r1, Astra). The
    synthetic provider's call evidence cannot carry a call-flagged jcc, so the
    flag is set on the validated observation directly."""
    import dataclasses

    function, observation = normalize_with_observation(_escaping(listed_fallthrough=True))
    row = observation.instructions[1]
    flagged = dataclasses.replace(row, flow=dataclasses.replace(row.flow, is_call=True, is_jump=False))
    rows = (*observation.instructions[:1], flagged, *observation.instructions[2:])
    for instructions in (observation.instructions, rows):
        graph = build_pcode_block_graph(dataclasses.replace(observation, instructions=instructions),
                                        function.scopes.function.entry)
        assert graph.unsupported is None
        assert sum(block.edge is not None for block in graph.blocks) == 1


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
