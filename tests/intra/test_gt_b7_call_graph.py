"""G3b-7: observable intra-function paths agree across the graph and Bundle consumers."""

import pytest

from synthetic import CODE_BASE, RAX, RCX, FunctionBuilder, const, copy, load, normalize_with_observation, op, program_units, ram, reg
from test_gt_b1_tail_fact import _flag
from tdo_v2.call_seeds import seed_function_calls, seed_tail_calls
from tdo_v2.control_projection import control_successor_coordinates, project_observed_control_graph
from tdo_v2.pcode_blocks import build_pcode_block_graph, control_exits, tail_transfers


OUT = CODE_BASE + 0x800


def _graph_views(builder):
    normalized, observation = normalize_with_observation(builder)
    entry = normalized.scopes.function.entry
    graph = build_pcode_block_graph(observation, entry)
    assert graph.unsupported is None
    cfg = normalized.cfg
    view = project_observed_control_graph(normalized.scopes, observation, cfg)
    topology = {cfg.node(node).label: tuple(cfg.node(s).label for s in cfg.successors(node))
                for node in range(cfg.node_count)}
    return (topology, graph, view.entry_reachable, view.outside_observed_successors,
            normalized.terminal_cuts.block_keys, dict(tail_transfers(observation, entry)))


def test_local_branch_to_entry_is_a_loop_and_has_no_tail_naming_row():
    def builder(flag):
        b = FunctionBuilder().label("top").ins(copy(reg(RAX), const(1))).branch("top")
        return _flag(b, 1, call=flag)

    (unit,) = program_units(builder(False))
    assert seed_tail_calls(unit) == ()
    # (G3b-7 r2) a call-flagged branch into the own body still has no naming
    # contract: today's exporter aborts on it and the seed rule matches that
    # (the producer change is G3b-7b). The graph rules below hold either way.
    (unit,) = program_units(builder(True))
    with pytest.raises(ValueError, match="own body"):
        seed_tail_calls(unit)
    views = _graph_views(builder(False))
    assert views == _graph_views(builder(True))
    topology, graph, reached, outside, cuts, tails = views
    assert topology["1:1004"] == ("1:1000",) and not graph.blocks[-1].exits
    assert reached == ("1:1000", "1:1004") and outside == cuts == () and tails == {}


def test_recursive_call_to_entry_keeps_the_entry_edge():
    """(r6; Astra r4 P2 / r5 Q2) the exporter merges landing pads into the
    listing, so a listed entry may be a pad as well as the recursive callee:
    the edge stays (a possible exceptional back edge), never a tail."""
    def builder(flag):
        b = FunctionBuilder().ins(copy(reg(RCX), const(2))).call(CODE_BASE).ret()
        return _flag(b, 1, call=flag)

    for flag in (False, True):
        (unit,) = program_units(builder(flag))
        (call,) = seed_function_calls(unit).callsites
        assert call.target.coordinate == unit.scopes.function.entry
    views = _graph_views(builder(False))
    assert views == _graph_views(builder(True))
    topology, graph, _, outside, cuts, tails = views
    assert topology["1:1004"] == ("1:1000", "1:1008")
    assert not graph.blocks[1].exits and outside == () and cuts == ("1:1008",) and tails == {}


@pytest.mark.parametrize("flag", [False, True])
def test_a_call_then_branch_to_entry_cannot_become_a_terminal(flag):
    b = FunctionBuilder().label("top").ins(copy(reg(RAX), const(1))).branch("top")
    b._rows[-1].ops.append(op("CALL", [ram(OUT)]))
    (unit,) = program_units(_flag(b, 1, call=flag))
    obs, entry = unit.observation, unit.scopes.function.entry
    addresses = {row.address for row in obs.instructions}
    assert control_successor_coordinates(obs.instructions[1], local_addresses=addresses, function_entry=entry) == (entry,)
    graph = build_pcode_block_graph(obs, entry)
    assert graph.unsupported == "a call with landing pads that does not end in its call"
    assert not tail_transfers(obs, entry)


def test_postcall_copy_without_a_pad_keeps_fallthrough_without_an_exit():
    def builder(flag):
        b = FunctionBuilder().call(OUT)
        b._rows[-1].ops.append(copy(reg(RAX), const(7)))
        return _flag(b.ret(), 0, call=flag)

    views = _graph_views(builder(False))
    assert views == _graph_views(builder(True))
    assert views[0]["1:1000"] == ("1:1004",) and not views[1].blocks[0].exits


@pytest.mark.parametrize("flag", [False, True])
def test_an_external_naming_seed_still_requires_the_exporter_flag(flag):
    (unit,) = program_units(_flag(FunctionBuilder().tail_call(OUT), 0, call=flag))
    assert bool(seed_tail_calls(unit)) is flag
    (tail,) = tail_transfers(unit.observation, unit.scopes.function.entry).values()
    assert tail.kind == "branch" and tail.target.byte_offset == OUT


@pytest.mark.parametrize("flag", [False, True])
def test_a_user_operation_does_not_explain_away_an_outside_target(flag):
    b = FunctionBuilder().call(OUT)
    b._rows[-1].ops[:] = [op("CALLOTHER", [const(42, 4)])]
    (unit,) = program_units(_flag(b.ret(), 0, call=flag))
    graph = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
    assert graph.unsupported is None
    assert graph.blocks[0].exits and graph.blocks[0].successors == ("1:1004",)
    assert not tail_transfers(unit.observation, unit.scopes.function.entry)


@pytest.mark.parametrize("split", [False, True])
def test_an_outside_target_of_a_user_operation_cannot_be_moved_past_another_operation(split):
    b = FunctionBuilder().call(OUT)
    b._rows[-1].ops[:] = [op("CALLOTHER", [const(42, 4)]), copy(reg(RAX), const(1))]
    if split:
        b._rows[-1].ops.insert(0, op("CBRANCH", [const(2, 4), reg(RCX, 1)]))
    (unit,) = program_units(b.ret())
    graph = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
    reason = "an opaque operation may leave a split instruction" if split else "an opaque operation may leave before the row ends"
    assert graph.unsupported == reason


@pytest.mark.parametrize("flag", [False, True])
@pytest.mark.parametrize("split", [False, True])
def test_an_unexplained_outside_target_cannot_skip_a_call_to_another_destination(flag, split):
    b = FunctionBuilder().call(OUT + 0x100).ret()
    b._rows[0].ops[:] = [op("CALL", [ram(OUT)]), copy(reg(RAX), const(1))]
    if split:
        b._rows[0].ops.insert(0, op("CBRANCH", [const(2), reg(RCX, 1)]))
    (unit,) = program_units(_flag(b, 0, call=flag))
    graph = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
    assert graph.unsupported == ("a call may leave a split instruction" if split else "a call may leave before the row ends")


def test_a_relative_branch_does_not_turn_a_known_direct_callee_into_an_external_cfg_exit():
    b = FunctionBuilder().call(OUT).ret()
    b._rows[0].ops[:] = [op("CBRANCH", [const(2), reg(RCX, 1)]), op("CALL", [ram(OUT)]), copy(reg(RAX), const(1))]
    topology, graph, _, outside, _, _ = _graph_views(b)
    assert topology["1:1000"] == ("1:1004",) and outside == ()
    assert not any(block.exits for block in graph.blocks if block.key != "1:1004")


@pytest.mark.parametrize("flag", [False, True])
def test_pcode_keeps_an_unlisted_local_taken_edge_in_both_graphs(flag):
    b = FunctionBuilder().cbranch("taken", reg(RCX, 1)).ret().label("taken").ins(copy(reg(RAX), const(7))).ret()
    _flag(b, 0, call=flag)
    raw = b.to_json

    def unlisted():
        data = raw()
        data["instructions"][0]["flow_targets"] = []
        return data

    b.to_json = unlisted
    topology, graph, reached, _, _, _ = _graph_views(b)
    assert topology["1:1000"] == graph.blocks[0].successors == ("1:1004", "1:1008")
    assert "1:1008" in reached


def test_a_split_branch_run_on_one_path_cannot_disappear_from_the_instruction_cfg():
    b = FunctionBuilder().ins(op("CBRANCH", [const(2), reg(RCX, 1)]), op("BRANCH", [ram(CODE_BASE + 8)]),
                              copy(reg(RAX), const(7))).ret().ret()
    (unit,) = program_units(b)
    graph = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
    assert graph.unsupported == "a reachable split branch is missing from the instruction successors"


def _skipped_transfer(opcode, operand, flag):
    builder = FunctionBuilder().call(OUT).ins(load(reg(RAX), reg(RCX))).ret()
    builder._rows[0].ops[:] = [op("BRANCH", [const(2)]), op(opcode, [operand])]
    return _flag(builder, 0, call=flag)


@pytest.mark.parametrize("flag", [False, True])
@pytest.mark.parametrize("opcode,operand", [("CALL", ram(OUT)), ("CALLIND", reg(RAX))])
def test_an_unreachable_native_call_has_no_action_for_its_required_seed(flag, opcode, operand):
    from tdo_v2.interprocedural import analyze_units

    (unit,) = program_units(_skipped_transfer(opcode, operand, flag))
    observation, entry = unit.observation, unit.scopes.function.entry
    addresses = {row.address for row in observation.instructions}
    successors = control_successor_coordinates(observation.instructions[0], local_addresses=addresses,
                                               function_entry=entry)
    assert {target.byte_offset for target in successors} == {CODE_BASE + 4, OUT}
    assert build_pcode_block_graph(observation, entry).unsupported == "an unreachable native call has no pre-SSA action"
    assert not tail_transfers(observation, entry)
    assert analyze_units([unit])["1:1000"].normalized.reason == "unsupported_intra_instruction_flow"


@pytest.mark.parametrize("flag", [False, True])
@pytest.mark.parametrize("opcode,operand", [("CALLOTHER", const(42, 4)), ("BRANCHIND", reg(RAX))])
def test_a_skipped_transfer_leaves_an_unexplained_departure_before_the_row(flag, opcode, operand):
    from test_gt_b3_tail_memory_events import _events, _index
    from test_return_relations import _certs, _of

    builder = _skipped_transfer(opcode, operand, flag)
    topology, graph, _, outside, _, tails = _graph_views(builder)
    assert topology["1:1000"] == ("1:1004",)
    assert [(source.byte_offset, target.byte_offset) for source, target in outside] == [(CODE_BASE, OUT)]
    assert not graph.blocks[0].exits and not tails
    (unit,) = program_units(builder)
    exits = control_exits(unit.observation, unit.scopes.function.entry)
    assert exits.may_leave["1:1000"] == ("1:1000", ("1:1000:0:BRANCH",))
    _, memory, _ = _index(builder, [])
    assert _events(memory.prefix("1:1004:0:LOAD")) == [("call", "1:1000~leave")]
    assert memory.plan("1:1004:0:LOAD")[0] is not None
    certificate = _of(_certs(builder))
    assert certificate.status == "unknown" and not certificate.closed


def test_a_callind_without_an_operand_cannot_explain_a_listed_outside_target():
    b = FunctionBuilder().call(OUT).ret()
    b._rows[0].ops[:] = [op("CALLIND", []), copy(reg(RAX), const(1))]
    (unit,) = program_units(b)
    graph = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
    assert graph.unsupported == "a call may leave before the row ends"


# -- design r2 (.census6/design_gt_g3b567_r2.md) ------------------------------------------------


def test_an_address_form_conditional_skip_never_hides_the_call_explaining_its_target():
    """(R7-2, Fable r1 P2-1) ``CBRANCH ram(next), cc; CALL ram(OUT)``: the
    fallthrough path reaches the call, so OUT is the call's -- no outside
    successor, no refusal (r1 refused "a call may leave ...")."""
    for flag in (False, True):
        b = FunctionBuilder().call(OUT).ret()
        b._rows[0].ops[:] = [op("CBRANCH", [ram(CODE_BASE + 4), reg(RCX, 1)]), op("CALL", [ram(OUT)])]
        _flag(b, 0, call=flag)
        (unit,) = program_units(b)
        assert build_pcode_block_graph(unit.observation, unit.scopes.function.entry).unsupported is None
        (row, *_) = unit.observation.instructions
        local = {item.address for item in unit.observation.instructions}
        assert all(target.byte_offset != OUT for target in control_successor_coordinates(
            row, local_addresses=local, function_entry=unit.scopes.function.entry))


def test_a_branch_destination_is_never_explained_by_a_call_to_the_same_address():
    """(R7-2) ``CBRANCH ram(OUT), cc; CALL ram(OUT)``: the taken branch leaves
    to OUT without calling -- OUT stays an instruction successor."""
    b = FunctionBuilder().call(OUT).ret()
    b._rows[0].ops[:] = [op("CBRANCH", [ram(OUT), reg(RCX, 1)]), op("CALL", [ram(OUT)])]
    (unit,) = program_units(b)
    (row, *_) = unit.observation.instructions
    local = {item.address for item in unit.observation.instructions}
    assert any(target.byte_offset == OUT for target in control_successor_coordinates(
        row, local_addresses=local, function_entry=unit.scopes.function.entry))


@pytest.mark.parametrize("selector, listed_kept", [
    ("other", True),      # Astra r1 P1-1: COPY RAX, OUT; CALLIND RAX listing OUT+0x100
    ("same", False),      # the row proves the listed target
    ("unproven", False),  # selector not proven by the row: a callee candidate
])
def test_a_callind_explains_only_what_its_row_proves_for_the_selector(selector, listed_kept):
    listed = OUT + 0x100
    b = FunctionBuilder().call(listed).ret()
    if selector == "unproven":
        b._rows[0].ops[:] = [op("CALLIND", [reg(RAX)])]
    else:
        value = OUT if selector == "other" else listed
        b._rows[0].ops[:] = [copy(reg(RAX), const(value)), op("CALLIND", [reg(RAX)])]
    for flag in (False, True):
        _flag(b, 0, call=flag)
        (unit,) = program_units(b)
        entry = unit.scopes.function.entry
        graph = build_pcode_block_graph(unit.observation, entry)
        assert graph.unsupported is None
        (row, *_) = unit.observation.instructions
        local = {item.address for item in unit.observation.instructions}
        kept = any(target.byte_offset == listed for target in control_successor_coordinates(
            row, local_addresses=local, function_entry=entry))
        assert kept == listed_kept
        assert graph.blocks[0].exits == listed_kept
        exits = control_exits(unit.observation, entry)
        assert ("1:1000" in exits.non_return_exits) == listed_kept
        # (r5) a contradicted listing gives no position evidence: may_leave too
        assert ("1:1000" in exits.may_leave) == listed_kept


@pytest.mark.parametrize("shape", ["partial", "internal_flow", "call_between"])
def test_a_selector_the_row_does_not_prove_explains_any_listed_target(shape):
    """(R7-3, Fable r2 P2-B) the row's last writer must be a COPY of a constant
    to exactly the selector, with no internal flow and no call-like operation
    in between (``final_target_index``); otherwise the CALLIND explains every
    listed target (never a constant from a skipped / partial / clobbered write)."""
    listed = OUT + 0x100
    b = FunctionBuilder().call(listed).ret()
    ops = [copy(reg(RAX), const(OUT))]
    if shape == "partial":
        ops.append(copy(reg(RAX, 1), const(0x55, 1)))
    elif shape == "internal_flow":
        # (Astra r3 P3) the skippable last COPY disagrees with the listing: a
        # proof trusting it would keep the listed target
        ops.append(op("CBRANCH", [const(2), reg(RCX, 1)]))
        ops.append(copy(reg(RAX), const(OUT + 0x200)))
    else:
        ops.append(op("CALLOTHER", [const(0x10, 4)]))
    b._rows[0].ops[:] = [*ops, op("CALLIND", [reg(RAX)])]
    (unit,) = program_units(b)
    (row, *_) = unit.observation.instructions
    local = {item.address for item in unit.observation.instructions}
    successors = control_successor_coordinates(row, local_addresses=local, function_entry=unit.scopes.function.entry)
    expected_kept = shape == "call_between"   # (a CALLOTHER in the row explains nothing at all)
    assert any(target.byte_offset == listed for target in successors) == expected_kept


def test_a_user_operation_after_the_call_keeps_the_call_target_a_successor():
    """(R7-2, Fable r2 P2-A) ``CALL ram(X); CALLOTHER``: a user op may transfer
    (r13-r15), anywhere in the row -- X is not explained away."""
    b = FunctionBuilder().call(OUT).ret()
    b._rows[0].ops[:] = [op("CALL", [ram(OUT)]), op("CALLOTHER", [const(0x10, 4)])]
    (unit,) = program_units(b)
    (row, *_) = unit.observation.instructions
    local = {item.address for item in unit.observation.instructions}
    assert any(target.byte_offset == OUT for target in control_successor_coordinates(
        row, local_addresses=local, function_entry=unit.scopes.function.entry))


def test_a_flow_override_callind_explains_no_listed_target():
    """(G3b-7 r3, Fable P3-2) an override row's listing follows the overridden
    semantics, not the raw p-code: the listed outside target stays."""
    listed = OUT + 0x100
    b = FunctionBuilder().call(listed).ret()
    b._rows[0].ops[:] = [op("CALLIND", [reg(RAX)])]
    original = b.to_json

    def overridden():
        raw = original()
        raw["instructions"][0]["flow_type"] = {**raw["instructions"][0]["flow_type"], "is_override": True}
        return raw
    b.to_json = overridden
    (unit,) = program_units(b)
    (row, *_) = unit.observation.instructions
    assert row.flow.is_override
    local = {item.address for item in unit.observation.instructions}
    assert any(target.byte_offset == listed for target in control_successor_coordinates(
        row, local_addresses=local, function_entry=unit.scopes.function.entry))


def test_a_flow_override_direct_call_explains_no_listed_target():
    """(G3b-7 r4, Astra r3 P1) the override rule holds for a direct CALL too."""
    b = FunctionBuilder().call(OUT).ret()
    original = b.to_json

    def overridden():
        raw = original()
        raw["instructions"][0]["flow_type"] = {**raw["instructions"][0]["flow_type"], "is_override": True}
        return raw
    b.to_json = overridden
    (unit,) = program_units(b)
    entry = unit.scopes.function.entry
    (row, *_) = unit.observation.instructions
    local = {item.address for item in unit.observation.instructions}
    assert any(target.byte_offset == OUT for target in control_successor_coordinates(
        row, local_addresses=local, function_entry=entry))
    graph = build_pcode_block_graph(unit.observation, entry)
    assert graph.unsupported is not None or graph.blocks[0].exits


def test_an_unproven_callind_listing_the_entry_keeps_it():
    """(G3b-7 r4, Astra r3 P2) the exporter may merge a landing pad at the
    entry into the listing: an unproven CALLIND does not explain it away."""
    b = FunctionBuilder().ins(copy(reg(RAX), const(1))).call(CODE_BASE).ret()
    b._rows[1].ops[:] = [op("CALLIND", [reg(RCX)])]
    (unit,) = program_units(b)
    entry = unit.scopes.function.entry
    row = unit.observation.instructions[1]
    local = {item.address for item in unit.observation.instructions}
    assert entry in control_successor_coordinates(row, local_addresses=local, function_entry=entry)


def test_an_override_row_never_recovers_its_raw_branch_edge():
    """(Astra r7) a raw BRANCH to a local address on a flow-override row whose
    listing names only an outside target: the raw edge is not recovered --
    the override, not the operand, decides where the row goes."""
    b = FunctionBuilder().branch("epilogue").ins(copy(reg(RAX), const(1))).label("epilogue").ret()
    original = b.to_json

    def overridden():
        raw = original()
        raw["instructions"][0]["flow_type"] = {**raw["instructions"][0]["flow_type"], "is_override": True}
        raw["instructions"][0]["flow_targets"] = [dict(raw["instructions"][0]["address"], byte_offset=OUT)]
        return raw
    b.to_json = overridden
    (unit,) = program_units(b)
    row = unit.observation.instructions[0]
    local = {item.address for item in unit.observation.instructions}
    assert row.flow.is_override
    successors = control_successor_coordinates(row, local_addresses=local, function_entry=unit.scopes.function.entry)
    assert all(target.byte_offset != CODE_BASE + 8 for target in successors)
