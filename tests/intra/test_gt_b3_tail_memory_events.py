"""(G-T G3b-3, docs 25.108; design r16-r18) Tail sites and control exits as physical-memory events.

A function with a memory-writing composed tail no longer refuses its whole
physical inventory ("unrepresented memory event"): a BRANCH / BRANCHIND tail
is a call boundary at its raw point, every outcome edge block ``E`` one keyed
``site~edge`` (edge blocks rank after every real block), and the tail's staged
writes sit behind that event. A row listing a flow target its p-code does not
reach gets a ``<row>~leave`` boundary before its first operation (a memory
event inside such a row refuses the index). Physical callee contexts refuse a
callee with any non-RETURN exit (by the graph). A tail site's staged rows run
once by their execution block.

Fixtures are those of ``.census6/cob/g3b3_probe.py`` (the measured tables of
design r16-r18).
"""
import copy as _copy

import pytest
from synthetic import (
    CODE_BASE, RAX, RBX, RCX, RDI, RDX, RSI, R9, ZF, FunctionBuilder, add, const, copy, load, op, program_units, ram,
    reg, store,
)
from test_gt_conditional_tails import _to

from tdo_v2._record_conditions import ConditionIndex
from tdo_v2._record_memory import MemoryIndex
from tdo_v2.interprocedural import analyze_units, function_key_of
from tdo_v2.lane_slice import lane_index
from tdo_v2.pcode_blocks import control_exits

MIDDLE, TARGET, OUT = CODE_BASE, CODE_BASE + 0x800, CODE_BASE + 0xC00


def _mem_target():
    return FunctionBuilder(entry=TARGET).ins(store(reg(RDI), reg(RSI))).ret()


def _reg_target():
    return FunctionBuilder(entry=TARGET).ins(add(reg(RAX), reg(RDI), const(1))).ret()


def _edit(builder, index, change):
    raw = _copy.deepcopy(builder.to_json())
    change(raw["instructions"][index], raw)
    builder.to_json = lambda raw=raw: raw
    return builder


def _start(with_store):
    builder = FunctionBuilder(entry=MIDDLE)
    if with_store:
        builder.ins(store(reg(RCX), reg(RDX)))
    else:
        builder.ins(copy(reg(RCX), reg(RDX)))
    return builder


def _load_tail(builder):
    return builder.ins(load(reg(R9), reg(RBX))).ret()


def _coord(address):
    return {"space_id": 1, "byte_offset": address}


def cb(with_store, target):
    b = _start(with_store).cbranch("x", reg(ZF, 1)).ins(load(reg(R9), reg(RBX))).label("x").ret()
    return _to(b, 1, TARGET), [target()]


def branch_tail(with_store, target, flagged):
    b = _start(with_store).ins(load(reg(R9), reg(RBX))).tail_call(TARGET)

    def change(row, raw):
        row["operations"][-1]["opcode"] = "BRANCH"
        row["flow_type"]["is_call"] = flagged
        row["flow_type"]["is_jump"] = not flagged
    b = _edit(b, 2, change)
    return b, [target()]


def a_branch_exits_with_successor(with_store):
    b = _start(with_store).ins(op("BRANCH", [ram(OUT)]))
    b = _load_tail(b)

    def change(row, raw):
        row["fallthrough_present"] = True
        row["fallthrough"] = _coord(MIDDLE + 8)
        row["flow_targets"] = [_coord(MIDDLE + 8)]
        row["flow_type"].update(is_flow=True, is_jump=True, is_unconditional=True, has_fallthrough=True)
    return _edit(b, 1, change), []


def b_branchind_fallthrough(with_store):
    b = _start(with_store).ins(op("BRANCHIND", [reg(RAX)]))
    b = _load_tail(b)

    def change(row, raw):
        row["fallthrough_present"] = True
        row["fallthrough"] = _coord(MIDDLE + 8)
        row["flow_targets"] = []
        row["flow_type"].update(is_flow=True, is_jump=True, is_computed=True, has_fallthrough=True)
    return _edit(b, 1, change), []


def c_leaving_cbranch_no_edge(with_store):
    b = _start(with_store).cbranch("x", reg(ZF, 1)).ins(load(reg(R9), reg(RBX))).label("x").ret()
    b = _to(b, 1, OUT)

    def change(row, raw):
        row["flow_targets"] = []
    return _edit(b, 1, change), []


def d_branch_next_nonlocal_listed(with_store, flagged):
    b = _start(with_store).ins(op("BRANCH", [ram(MIDDLE + 8)]))
    b = _load_tail(b)

    def change(row, raw):
        row["fallthrough_present"] = False
        row["fallthrough"] = None
        row["flow_targets"] = [_coord(MIDDLE + 8), _coord(OUT)]
        row["flow_type"].update(is_flow=True, is_jump=not flagged, is_call=flagged, is_unconditional=True,
                                has_fallthrough=False)
    return _edit(b, 1, change), []


def f_split_local_branch_nonlocal_listed(with_store, last="BRANCH"):
    """one instruction: CBRANCH +2 (relative, skips the COPY); COPY rax = 1; BRANCH next (or CBRANCH next on zf),
    the row listing next and a non-local target."""
    ends = op("BRANCH", [ram(MIDDLE + 8)]) if last == "BRANCH" else op("CBRANCH", [ram(MIDDLE + 8), reg(ZF, 1)])
    b = _start(with_store).ins(op("CBRANCH", [const(2, 8), reg(ZF, 1)]), copy(reg(RAX), const(1)), ends)
    b = _load_tail(b)

    def change(row, raw):
        row["fallthrough_present"] = last != "BRANCH"
        row["fallthrough"] = _coord(MIDDLE + 8) if last != "BRANCH" else None
        row["flow_targets"] = [_coord(MIDDLE + 8), _coord(OUT)]
        row["flow_type"].update(is_flow=True, is_jump=True, is_conditional=last != "BRANCH",
                                is_unconditional=last == "BRANCH", has_fallthrough=last != "BRANCH")
    return _edit(b, 1, change), []


def g_split_cbranch_distinct(with_store, final=True):
    """(r16 review, Astra P2-1) distinct successors: final -- CBRANCH +2; COPY; CBRANCH [next+4] (fallthrough next);
    non-final -- CBRANCH [next+4]; COPY (the CBRANCH is not last). The row lists next+4 and a non-local target."""
    if final:
        ops = (op("CBRANCH", [const(2, 8), reg(ZF, 1)]), copy(reg(RAX), const(1)),
               op("CBRANCH", [ram(MIDDLE + 12), reg(ZF, 1)]))
    else:
        ops = (op("CBRANCH", [ram(MIDDLE + 12), reg(ZF, 1)]), copy(reg(RAX), const(1)))
    b = _start(with_store).ins(*ops)
    b = _load_tail(b)

    def change(row, raw):
        row["fallthrough_present"] = True
        row["fallthrough"] = _coord(MIDDLE + 8)
        row["flow_targets"] = [_coord(MIDDLE + 12), _coord(OUT)]
        row["flow_type"].update(is_flow=True, is_jump=True, is_conditional=True, has_fallthrough=True)
    return _edit(b, 1, change), []


def h_split_relative_only(with_store):
    """(r16 review, Fable P2) CBRANCH +2; COPY; COPY -- relative branches only, falls through; the row lists OUT."""
    b = _start(with_store).ins(op("CBRANCH", [const(2, 8), reg(ZF, 1)]), copy(reg(RAX), const(1)),
                               copy(reg(RDX), const(2)))
    b = _load_tail(b)

    def change(row, raw):
        row["flow_targets"] = [_coord(OUT)]
        row["flow_type"].update(is_flow=True, is_jump=True, is_conditional=True, has_fallthrough=True)
    return _edit(b, 1, change), []


def i_oplless_row_listing_out(with_store, flagged):
    """(r16 review, Fable P2) a plain COPY row listing only OUT, call-flagged or not."""
    b = _start(with_store).ins(copy(reg(RAX), const(1)))
    b = _load_tail(b)

    def change(row, raw):
        row["flow_targets"] = [_coord(OUT)]
        row["flow_type"].update(is_flow=True, is_call=flagged, is_jump=not flagged, has_fallthrough=True)
    return _edit(b, 1, change), []


def j_split_with_inrow_load(with_store):
    """(r16 review, Fable P2) CBRANCH +2; LOAD r9 = [rbx]; BRANCH next -- a LOAD in a later segment of the row; the
    row lists next and OUT."""
    b = _start(with_store).ins(op("CBRANCH", [const(2, 8), reg(ZF, 1)]), load(reg(R9), reg(RBX)),
                               op("BRANCH", [ram(MIDDLE + 8)]))
    b = b.ins(copy(reg(RAX), const(1))).ret()

    def change(row, raw):
        row["fallthrough_present"] = False
        row["fallthrough"] = None
        row["flow_targets"] = [_coord(MIDDLE + 8), _coord(OUT)]
        row["flow_type"].update(is_flow=True, is_jump=True, is_unconditional=True, has_fallthrough=False)
    return _edit(b, 1, change), []


def k_unreachable_op(with_store, middle):
    """(r17 review, Astra P2-2) BRANCH +2; <middle>; COPY -- the middle operation is unreachable; lists OUT."""
    b = _start(with_store).ins(op("BRANCH", [const(2, 8)]), middle, copy(reg(RAX), const(1)))
    b = _load_tail(b)

    def change(row, raw):
        row["flow_targets"] = [_coord(OUT)]
        row["flow_type"].update(is_flow=True, is_jump=True, has_fallthrough=True)
    return _edit(b, 1, change), []


def l_first_op_load_flagged(with_store, split=False):
    """A row starting in a LOAD which lists OUT; the split variant can model the in-row boundary."""
    operations = [load(reg(R9), reg(RBX))]
    if split:
        operations.append(op("CBRANCH", [const(2, 4), reg(ZF, 1)]))
    b = _start(with_store).ins(*operations, copy(reg(RAX), const(1)))
    b = b.ins(copy(reg(RDX), const(2))).ret()

    def change(row, raw):
        row["flow_targets"] = [_coord(OUT)]
        row["flow_type"].update(is_flow=True, is_call=True, has_fallthrough=True)
    return _edit(b, 1, change), []


def m_inrow_store(with_store):
    """(r17 review, Fable P2-1) split CBRANCH +2; STORE [rdi] = rsi; BRANCH next, lists next + OUT."""
    b = _start(with_store).ins(op("CBRANCH", [const(2, 8), reg(ZF, 1)]), store(reg(RDI), reg(RSI)),
                               op("BRANCH", [ram(MIDDLE + 8)]))
    b = _load_tail(b)

    def change(row, raw):
        row["fallthrough_present"] = False
        row["fallthrough"] = None
        row["flow_targets"] = [_coord(MIDDLE + 8), _coord(OUT)]
        row["flow_type"].update(is_flow=True, is_jump=True, is_unconditional=True, has_fallthrough=False)
    return _edit(b, 1, change), []


def n_branch_out1_lists_out2(with_store):
    """(r17 review, Fable P2-3 / P3) terminal BRANCH OUT listing OUT and OUT2 (no fact: extra listed target)."""
    b = _start(with_store).ins(load(reg(R9), reg(RBX))).ins(op("BRANCH", [ram(OUT)]))

    def change(row, raw):
        row["fallthrough_present"] = False
        row["fallthrough"] = None
        row["flow_targets"] = [_coord(OUT), _coord(OUT + 0x40)]
        row["flow_type"].update(is_flow=True, is_jump=True, is_unconditional=True, has_fallthrough=False)
    b._rows[-1].kind = "branch"
    b._labels["__never"] = 0
    b._rows[-1].target = "__never"
    return _edit(b, 2, change), []


def e_recovered_switch(with_store):
    b = (_start(with_store).ins(op("BRANCHIND", [reg(RAX)])).label("p").ins(load(reg(R9), reg(RBX))).ret()
         .label("q").ins(load(reg(R9), reg(RDI))).ret())

    def change(row, raw):
        row["fallthrough_present"] = False
        row["fallthrough"] = None
        row["flow_targets"] = [_coord(MIDDLE + 8), _coord(MIDDLE + 16)]
        row["flow_type"].update(is_flow=True, is_jump=True, is_computed=True, is_unconditional=True,
                                has_fallthrough=False)
    return _edit(b, 1, change), []


def _index(builder, extra=()):
    units = program_units(builder, *extra)
    item = analyze_units(units)[function_key_of(1, MIDDLE)]
    index = lane_index(item.normalized, item.unit)
    conditions = ConditionIndex(item.normalized, item.unit, index)
    return item, MemoryIndex(item.normalized, item.unit, index, conditions), conditions


def _events(found):
    value, reason = found
    return reason if value is None else [(event.kind, event.key) for event in value]


SITE, LEAVE = "1:1004:0:CBRANCH", "1:1004~leave"

# shape -> (builder, the -S inventory, the prefix of the LOAD at 1:1008, whether that LOAD is planned)
CASES = {
    "T1 memory cbranch tail": (lambda: cb(False, _mem_target), [("call", f"{SITE}~edge")], [], True),
    "T2 register cbranch tail": (lambda: cb(False, _reg_target), [("call", f"{SITE}~edge")], [], True),
    "R-f1 split BRANCH next": (lambda: f_split_local_branch_nonlocal_listed(False), [("call", LEAVE)],
                               [("call", LEAVE)], True),
    "R-g1 split final CBRANCH": (lambda: g_split_cbranch_distinct(False), [("call", LEAVE)], [("call", LEAVE)], True),
    "R-g2 split non-final CBRANCH": (lambda: g_split_cbranch_distinct(False, False), [("call", LEAVE)],
                                     [("call", LEAVE)], True),
    "R-h relative only": (lambda: h_split_relative_only(False), [("call", LEAVE)], [("call", LEAVE)], True),
    "R-i1 flagged COPY row": (lambda: i_oplless_row_listing_out(False, True), "unsupported control transfer",
                              "unsupported control transfer", False),
    "R-k1 unreachable CALLOTHER": (lambda: k_unreachable_op(False, op("CALLOTHER", [const(0x10, 4)])),
                                   [("call", LEAVE)], [("call", LEAVE)], True),
    "R-k2 unreachable BRANCH OUT": (lambda: k_unreachable_op(False, op("BRANCH", [ram(OUT)])),
                                    [("call", LEAVE)], [("call", LEAVE)], True),
    "R-a exits + successor": (lambda: a_branch_exits_with_successor(False), "unsupported control transfer",
                              "unsupported control transfer", False),
    "R-b BRANCHIND + fallthrough": (lambda: b_branchind_fallthrough(False), "unsupported control transfer",
                                    "unsupported control transfer", False),
    "R-c leaving CBRANCH no edge": (lambda: c_leaving_cbranch_no_edge(False), "cfg branch targets differ",
                                    "cfg branch targets differ", False),
    "R-d1 BRANCH next flagged": (lambda: d_branch_next_nonlocal_listed(False, True),
                                 "unsupported control transfer", "unsupported control transfer", False),
    "R-d2 BRANCH next unflagged": (lambda: d_branch_next_nonlocal_listed(False, False),
                                   "unsupported control transfer", "unsupported control transfer", False),
    "R-f0 degenerate CBRANCH": (lambda: f_split_local_branch_nonlocal_listed(False, "CBRANCH"),
                                "cfg branch targets differ", "cfg branch targets differ", False),
    "R-i2 COPY row unflagged": (lambda: i_oplless_row_listing_out(False, False), "unsupported control transfer",
                                "unsupported control transfer", False),
    "R-m in-row STORE": (lambda: m_inrow_store(False), "memory event in a row that may leave",
                         "memory event in a row that may leave", False),
    "R-e recovered switch": (lambda: e_recovered_switch(False), [], [], False),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_each_shape_gets_its_designed_inventory(name):
    build, inventory, prefix, planned = CASES[name]
    builder, extra = build()
    _, memory, _ = _index(builder, extra)
    assert _events(memory.inventory()) == inventory
    assert _events(memory.prefix("1:1008:0:LOAD")) == prefix
    assert (memory.plan("1:1008:0:LOAD")[0] is not None) is planned


@pytest.mark.parametrize("flagged", [False, True])
def test_a_memory_writing_branch_tail_is_a_boundary_with_its_rows_behind_it(flagged):
    """T3 (was: "unrepresented memory event"): the raw BRANCH is the event --
    by the fact, flagged or not; a LOAD before it sees nothing; a staged
    row's prefix holds the event."""
    builder, extra = branch_tail(False, _mem_target, flagged)
    _, memory, _ = _index(builder, extra)
    assert _events(memory.inventory()) == [("call", "1:1008:0:BRANCH")]
    assert _events(memory.prefix("1:1004:0:LOAD")) == []
    assert memory.plan("1:1004:0:LOAD")[0] is not None
    assert _events(memory.prefix("1:1008:0:BRANCH~0")) == [("call", "1:1008:0:BRANCH")]


def test_a_register_only_unflagged_branch_tail_gains_its_boundary():
    builder, extra = branch_tail(False, _reg_target, False)
    _, memory, _ = _index(builder, extra)
    assert _events(memory.inventory()) == [("call", "1:1008:0:BRANCH")]


def test_edge_blocks_rank_last_and_their_rows_follow_the_tail_event():
    """The fallthrough LOAD (and the RETURN's) never see the edge event; it
    follows every real block's; its own prefix excludes it, a staged row's
    prefix includes it."""
    builder, extra = cb(True, _mem_target)
    _, memory, _ = _index(builder, extra)
    assert _events(memory.inventory()) == [("store", "1:1000:0:STORE"), ("call", f"{SITE}~edge")]
    real = max(point[0] for key, point in memory._points.items() if not key.endswith("~edge"))
    assert memory._points[f"{SITE}~edge"] == (real + 1, 0)
    for load_key in ("1:1008:0:LOAD", "1:100c:0:LOAD"):
        assert _events(memory.prefix(load_key)) == [("store", "1:1000:0:STORE")]
    assert _events(memory.prefix(f"{SITE}~edge")) == [("store", "1:1000:0:STORE")]
    assert _events(memory.prefix(f"{SITE}~0")) == [("store", "1:1000:0:STORE"), ("call", f"{SITE}~edge")]


def test_an_escape_edge_without_an_effect_still_gets_its_event():
    """``jz OUT`` (no function there): no effect placed, the edge still is a
    boundary (an unknown continuation) -- unplaced: no node, no action."""
    builder = _start(False).cbranch("x", reg(ZF, 1)).ins(load(reg(R9), reg(RBX))).label("x").ret()
    item, memory, _ = _index(_to(builder, 1, OUT))
    assert SITE not in item.proven
    (event,) = memory.inventory()[0]
    assert event.key == f"{SITE}~edge" and event.kind == "call" and event.node is None and event.action_id is None


@pytest.mark.parametrize("builder, load_key", [
    (lambda: j_split_with_inrow_load(False), "1:1004:1:LOAD"),
    (lambda: l_first_op_load_flagged(False, split=True), "1:1004:0:LOAD"),
])
def test_an_operation_inside_a_may_leave_row_sees_its_boundary(builder, load_key):
    """The leave event sits before the row's first operation: an in-row
    LOAD, ordinal 0 included, sees it (r17 review)."""
    built, extra = builder()
    _, memory, _ = _index(built, extra)
    assert memory._points[LEAVE][1] == -1 and memory._points[LEAVE] < memory._points[load_key]
    assert _events(memory.prefix(load_key)) == [("call", LEAVE)]
    assert _events(memory.prefix(LEAVE)) == []


def test_an_unsplit_load_row_with_a_listed_outside_target_is_refused():
    builder, extra = l_first_op_load_flagged(False)
    _, memory, _ = _index(builder, extra)
    assert _events(memory.prefix("1:1004:0:LOAD")) == "unsupported control transfer"


def _row_leaving(targets, leaves_to):
    """A terminal row ``BRANCH leaves_to`` listing ``targets`` (after a LOAD)."""
    b = _start(False).ins(load(reg(R9), reg(RBX))).ins(op("BRANCH", [ram(leaves_to)]))
    b._rows[-1].kind, b._rows[-1].target, b._labels["never"] = "branch", "never", 0

    def change(row, raw):
        row["fallthrough_present"], row["fallthrough"] = False, None
        row["flow_targets"] = [_coord(target) for target in targets]
        row["flow_type"].update(is_flow=True, is_jump=True, is_unconditional=True, has_fallthrough=False)
        row["operations"] = row["operations"][:1]
    return _edit(b, 2, change)


def test_a_listed_target_is_explained_per_target():
    """``BRANCH OUT`` listing OUT: explained, not may-leave; listing OUT and
    OUT2: OUT2 unexplained -- may-leave (a non-RETURN exit either way)."""
    for targets, may_leave in (([OUT], False), ([OUT, OUT + 0x40], True)):
        units = program_units(_row_leaving(targets, OUT))
        exits = control_exits(units[0].observation, units[0].scopes.function.entry)
        assert bool(exits.may_leave) is may_leave, targets
        assert "1:1008" in exits.non_return_exits


def test_a_call_in_a_may_leave_row_refuses_the_index():
    """``CALL t1`` listing t1 and OUT2: OUT2 unexplained -- the CALL's own
    boundary is an event inside the row: refused (r18 final fixes)."""
    b = _start(False).call(TARGET).ins(load(reg(R9), reg(RBX))).ret()

    def change(row, raw):
        row["flow_targets"] = [_coord(TARGET), _coord(OUT + 0x40)]
    built = _edit(b, 1, change)
    _, memory, _ = _index(built, [_reg_target()])
    assert memory.inventory() == (None, "unsupported control transfer")


def test_rows_whose_listed_targets_are_reached_are_not_may_leave():
    """A BRANCH tail and a CALL listing their own destinations."""
    builder, _ = branch_tail(False, _reg_target, False)
    units = program_units(builder, _reg_target())
    assert not control_exits(units[0].observation, units[0].scopes.function.entry).may_leave
    b = _start(False).call(TARGET).ins(load(reg(R9), reg(RBX))).ret()
    units = program_units(b, _reg_target())
    assert not control_exits(units[0].observation, units[0].scopes.function.entry).may_leave


def test_physical_event_skips_rows_and_maps_an_edge_to_its_site(monkeypatch):
    from types import SimpleNamespace

    from tdo_v2 import _record_calls
    from tdo_v2._record_memory import MemoryEvent

    seen = []
    monkeypatch.setattr(_record_calls, "context", lambda builder, base: seen.append(base))
    builder = SimpleNamespace(_projections={}, _transitions=None)
    for key in (LEAVE, "1:1004~exit"):
        assert _record_calls.physical_event(builder, MemoryEvent(key, "call", 1, None, None, None, None)) is None
    assert seen == []
    event = MemoryEvent(f"{SITE}~edge", "call", 1, None, None, None, None)
    assert _record_calls.physical_event(builder, event) is None
    assert seen == [SITE]


# -- physical callee contexts (design r18 section 2) --------------------------------


def test_a_callee_with_a_may_leave_row_is_refused():
    """A composed callee whose COPY row (call-flagged) lists a target its
    p-code does not reach: its control may leave other than at a RETURN --
    refused by the graph (was: admitted, ``done.proven`` holds no tail)."""
    from test_physical_call_records import _caller as _physical_caller, _case, _record

    callee = FunctionBuilder(entry=0x1800).ins(copy(reg(RAX), const(7))).ret()

    def change(row, raw):
        row["flow_targets"] = [_coord(0x1c00)]
        row["flow_type"].update(is_flow=True, is_call=True, has_fallthrough=True)
    case = _case(_physical_caller(), _edit(callee, 0, change))
    assert case["callee"].proven == {} or not any("BRANCH" in key for key in case["callee"].proven)
    cuts = _record(case).get("physical_call_cuts", {})
    assert cuts == {"1:1008:2:CALL": "physical call requires one analyzed body"}, cuts
    unit = case["callee"].unit
    assert control_exits(unit.observation, unit.scopes.function.entry).non_return_exits


# -- single execution (design r17 section 3) --------------------------------------------


def _graph(builder):
    from tdo_v2.pcode_blocks import build_pcode_block_graph

    unit = program_units(builder)[0]
    return unit.observation, build_pcode_block_graph(unit.observation, unit.scopes.function.entry)


def test_a_loops_edge_block_runs_once_with_no_once_only_raw_operation():
    """``top: jz TARGET; rax += 1; jmp top``: every real block is on the loop,
    the edge block on none -- it alone is single-execution."""
    from tdo_v2.relative_memory import single_execution_blocks, single_execution_keys

    builder = (FunctionBuilder(entry=MIDDLE).label("top").cbranch("x", reg(ZF, 1))
               .ins(add(reg(RAX), reg(RAX), const(1))).label("x").branch("top"))
    observation, graph = _graph(_to(builder, 0, TARGET))
    assert single_execution_keys(observation, graph) == frozenset()
    blocks, reason = single_execution_blocks(observation, graph)
    assert blocks == {"1:1000>0t"} and reason == "no once-only raw operation"


def test_an_uncertified_indirect_exit_keeps_every_block_out():
    from tdo_v2.relative_memory import single_execution_blocks

    builder = (FunctionBuilder(entry=MIDDLE).cbranch("x", reg(ZF, 1)).ins(add(reg(RAX), reg(RAX), const(1)))
               .label("x").jump_indirect(reg(RAX)))
    observation, graph = _graph(_to(builder, 0, TARGET))
    assert single_execution_blocks(observation, graph) == (frozenset(), "uncertified indirect flow")


def test_a_tail_row_runs_once_by_its_execution_block():
    """``_runs_once``: a conditional tail's row by its edge block (its raw
    CBRANCH may loop); a raw key by itself; no edge block -- by the base."""
    from tdo_v2.relative_memory import _Projector

    projector = object.__new__(_Projector)
    projector._once, projector._once_blocks = frozenset({"1:1008:0:BRANCH"}), frozenset({"1:1000>0t"})
    projector._tail_sites = frozenset({"1:1000:0:CBRANCH", "1:1008:0:BRANCH"})
    assert projector._runs_once("1:1000:0:CBRANCH~0") and projector._runs_once("1:1000:0:CBRANCH~edge")
    assert not projector._runs_once("1:1000:0:CBRANCH")            # (the raw branch in the loop)
    assert projector._runs_once("1:1008:0:BRANCH~1")
    projector._once_blocks = frozenset()
    assert not projector._runs_once("1:1000:0:CBRANCH~0")
    projector._tail_sites = frozenset()
    projector._once_blocks = frozenset({"1:1000>0t"})
    assert not projector._runs_once("1:1000:0:CBRANCH~0")         # (not a tail site: no edge identity)


@pytest.mark.parametrize("flagged", [False, True])
def test_a_branch_without_a_fact_is_no_boundary_whatever_its_flag(flagged):
    """``BRANCH OUT`` listing OUT and OUT2 (no fact: an extra listed target):
    the call flag adds no boundary at the BRANCH (design r12-r13: graph facts
    only) -- the row is may-leave, its only event the ``~leave`` boundary."""
    built = _row_leaving([OUT, OUT + 0x40], OUT)
    if flagged:
        built = _edit(built, 2, lambda row, raw: row["flow_type"].update(is_call=True, is_jump=False))
    _, memory, _ = _index(built)
    assert _events(memory.inventory()) == [("call", "1:1008~leave")]


# -- review r1 (Astra P2-2, Fable P2-3): integration pins ------------------------------


def test_normalize_hands_a_loops_tail_rows_to_the_projector_as_once(monkeypatch):
    """memset shape ``top: jz TARGET; ...; jmp top`` (no raw operation runs
    once): normalize passes ``tail_sites`` and the edge block in
    ``once_blocks`` with ``once_keys`` set (atoms on), the projector keeps the
    edge block, and the staged row's definition is an atom while the raw
    CBRANCH is not once."""
    from tdo_v2 import relative_memory

    captured = []
    original = relative_memory._configured_projector

    def spy(*args, **kwargs):
        projector = original(*args, **kwargs)
        captured.append((kwargs, projector))
        return projector
    monkeypatch.setattr(relative_memory, "_configured_projector", spy)
    middle = (FunctionBuilder(entry=MIDDLE).label("top").cbranch("x", reg(ZF, 1))
              .ins(add(reg(RDX), reg(RDX), const(1))).ins(store(reg(RDX), reg(RCX))).label("x").branch("top"))
    target = FunctionBuilder(entry=TARGET).ins(load(reg(RAX), reg(RCX))).ret()
    analyze_units(program_units(_to(middle, 0, TARGET), target))
    site, edge = "1:1000:0:CBRANCH", "1:1000>0t"
    found = [(kwargs, projector) for kwargs, projector in captured
             if site in kwargs.get("tail_sites", ()) and kwargs.get("once_keys") is not None]
    assert found, [sorted(kwargs) for kwargs, _ in captured]
    kwargs, projector = found[-1]
    assert kwargs["once_keys"] == frozenset() and edge in kwargs["once_blocks"]
    assert edge in projector._once_blocks
    assert projector._runs_once(f"{site}~0") and not projector._runs_once(site)
    (definition,) = [row for row in projector._ssa.definitions
                     if row.operation_key == f"{site}~0" and row.span.start == RAX and row.span.size == 8]
    assert projector._definition_atom(definition, definition.span) is not None


def _physical_middle():
    """At 0x1000: [rcx] = rdx; jz 0x1800 (composed: [rdi] = rsi); rax = [rcx] + 5; ret."""
    builder = (FunctionBuilder().sub_rsp(0x28).ins(store(reg(RCX), reg(RDX))).cbranch("x", reg(ZF, 1))
               .ins(load(reg(RAX), reg(RCX)), add(reg(RAX), reg(RAX), const(5))).label("x").add_rsp(0x28).ret())
    return _to(builder, 2, 0x1800)


def test_a_fallthrough_root_beside_a_memory_writing_tail_gets_a_physical_plan_and_evaluates():
    """End to end (was: "unrepresented memory event" fallback): the
    fallthrough LOAD's physical plan holds the earlier STORE only (the edge
    ranks last) and the record evaluates to the raw-pcode run's value."""
    from record_oracle import entry_reader, final_register
    from test_physical_call_records import _case, _execute, _record

    from tdo_v2._record_memory import evaluate_physical

    callee = FunctionBuilder(entry=0x1800).ins(store(reg(RDI), reg(RSI))).add_rsp(0x28).ret()
    case = _case(_physical_middle(), callee)
    record = _record(case, "1:100c:1:INT_ADD")
    loads = [node for node in record["nodes"] if node.get("physical_memory") is not None]
    assert loads and not any(node.get("physical_memory_fallback") for node in record["nodes"])
    vm = _execute(case, registers=((ZF, 0),))
    assert evaluate_physical(record, entry_reader(vm)).value == final_register(vm, RAX, 8)


def test_a_staged_tail_root_records_the_g3b4_cut():
    """A root on the tail's staged row: its prefix holds the ``site~edge``
    event, whose context is cut with the G3b-4 reason (checked first)."""
    from test_physical_call_records import _case, _record

    callee = FunctionBuilder(entry=0x1800).ins(store(reg(RDI), reg(RSI))).add_rsp(0x28).ret()
    case = _case(_physical_middle(), callee)
    site = "1:1008:0:CBRANCH"
    assert site in case["item"].proven
    keys = [action.operation_key for action in case["item"].normalized.memory_ssa.actions
            if action.operation_key.startswith(site + "~") and action.write_definition_ids]
    assert keys, [action.operation_key for action in case["item"].normalized.memory_ssa.actions]
    record = _record(case, keys[0])
    assert "physical context through a tail at the root" in record.get("physical_call_cuts", {}).values(), \
        record.get("physical_call_cuts")
    assert any(event.get("key") == f"{site}~edge" for event in record.get("physical_root_events", ()))


def test_an_active_tail_boundary_refuses_evaluation():
    """(review r2, Astra P3) The staged tail root's record on a run that took
    the tail is refused. Today the first refusal is the root's own reach -- a
    staged row has no physical root guard ("physical root unreached or
    unknown"); behind it, its ``site~edge`` root event carries no context (the
    evaluator's "active or unknown physical root memory event" check)."""
    from record_oracle import entry_reader
    from test_physical_call_records import _case, _execute, _record

    from tdo_v2._record_memory import evaluate_physical
    from tdo_v2.operation_records import Ineligible

    callee = FunctionBuilder(entry=0x1800).ins(store(reg(RDI), reg(RSI))).add_rsp(0x28).ret()
    case = _case(_physical_middle(), callee)
    site = "1:1008:0:CBRANCH"
    key = next(action.operation_key for action in case["item"].normalized.memory_ssa.actions
               if action.operation_key.startswith(site + "~") and action.write_definition_ids)
    record = _record(case, key)
    (event,) = [item for item in record["physical_root_events"] if item.get("key") == f"{site}~edge"]
    assert event["kind"] == "call" and event.get("context") is None
    vm = _execute(case, registers=((ZF, 1),))
    with pytest.raises(Ineligible, match="physical root unreached or unknown"):
        evaluate_physical(record, entry_reader(vm))
