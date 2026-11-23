"""G3b-7b: the exporter's "no static exception handler" fact (x64 PE) restores
the call rule for a call row's listed entry.

The exporter writes ``exception_handlers: "none"`` only when it proved from the
image's exception directory that no handler covers any frame PC of the function
(docs 25.115). The engine derives ``()`` pad sets for the call rows; with them a
listed entry is decided by ``call_explains``' ordinary rule (R7-8 kept it a
successor because the merged listing cannot tell a pad from the callee)."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest

from synthetic import CODE_BASE, RAX, RCX, FunctionBuilder, const, copy, op, program_units, ram, reg, tmp
from test_call_fallthrough_contract import PINNED_OLD_DIGEST, _callee, _caller, _unit
from test_gt_b7_call_graph import _graph_views
from tdo_v2._scope_contracts import AddressCoordinate, ValidatedFunctionObservation, ValidatedInstruction
from tdo_v2._scope_observation import _ObservationDefects, _exception_handlers_none
from tdo_v2._scope_raw import parse_raw_json
from tdo_v2._scope_wire import _observation_digest, _observation_preimage
from tdo_v2.control_projection import control_successor_coordinates
from tdo_v2.pcode_blocks import build_pcode_block_graph

OUT = CODE_BASE + 0x800


def _with(builder, value="none", edit=None):
    """``builder`` whose function JSON carries ``exception_handlers: value``
    and, as the exporter writes with it, every row's ISA ``length``."""
    original = builder.to_json

    def to_json():
        raw = original()
        raw["exception_handlers"] = value
        for row in raw["instructions"]:
            row.setdefault("length", builder.stride)
        if edit is not None:
            edit(raw)
        return raw

    builder.to_json = to_json
    return builder


def _recursive():
    return FunctionBuilder().ins(copy(reg(RCX), const(2))).call(CODE_BASE).ret()


def _successors(builder, row=1):
    (unit,) = program_units(builder)
    observation, entry = unit.observation, unit.scopes.function.entry
    local = {item.address for item in observation.instructions}
    return entry, control_successor_coordinates(observation.instructions[row], local_addresses=local,
                                                 function_entry=entry)


# -- contract -----------------------------------------------------------------------------------------------

def test_none_is_admitted_and_gives_every_call_row_an_empty_pad_set():
    (unit,) = program_units(_with(_recursive()))
    observation = unit.observation
    assert observation.exception_handlers_none
    assert [row.exception_targets for row in observation.instructions] == [None, (), None]
    (old,) = program_units(_recursive())
    assert not old.observation.exception_handlers_none
    assert all(row.exception_targets is None for row in old.observation.instructions)


@pytest.mark.parametrize("value", ["some", "", "None", 1, None, True, ["none"]])
def test_any_other_value_is_refused(value):
    (unit,) = program_units(_with(_recursive(), value))
    assert unit.observation is None


def test_a_duplicate_key_is_refused():
    defects = _ObservationDefects()
    raw = parse_raw_json('{"exception_handlers": "none", "exception_handlers": "none"}')
    assert _exception_handlers_none(raw, defects) is False and defects.duplicate


def test_the_row_pad_sets_follow_the_function_fact_both_ways():
    (unit,) = program_units(_with(_recursive()))
    observation = unit.observation
    assert not observation.call_fallthrough_isa   # (checked before the S1 early return)
    with pytest.raises(ValueError, match="exception handlers fact"):
        replace(observation, exception_handlers_none=False)
    (plain,) = program_units(_recursive())
    rows = list(plain.observation.instructions)
    rows[1] = replace(rows[1], exception_targets=())
    with pytest.raises(ValueError, match="exception handlers fact"):
        ValidatedFunctionObservation(tuple(rows))
    rows = list(observation.instructions)
    rows[1] = replace(rows[1], exception_targets=None)
    with pytest.raises(ValueError, match="exception handlers fact"):
        ValidatedFunctionObservation(tuple(rows), exception_handlers_none=True)


def test_a_row_pad_set_is_checked_on_its_own():
    (unit,) = program_units(_recursive())
    copy_row, call_row, _ = unit.observation.instructions
    with pytest.raises(ValueError, match="call row"):
        replace(copy_row, exception_targets=())
    with pytest.raises(ValueError, match="listed flow targets"):
        replace(call_row, exception_targets=(AddressCoordinate(call_row.address.space_id, OUT),))
    with pytest.raises(TypeError):
        replace(call_row, exception_targets=[])


# -- digest -------------------------------------------------------------------------------------------------

def test_an_observation_without_the_fact_hashes_as_before():
    observation = _unit(_caller(FunctionBuilder()), _callee()).observation
    assert not observation.exception_handlers_none
    preimage = _observation_preimage(observation)
    assert b"tdo-v2-exception-handlers" not in preimage
    assert sha256(preimage).digest() == _observation_digest(observation)
    assert _observation_digest(observation).hex() == PINNED_OLD_DIGEST


def test_the_fact_changes_the_digest_on_both_paths():
    observation = _unit(_with(_caller(FunctionBuilder())), _callee()).observation
    assert observation.exception_handlers_none
    preimage = _observation_preimage(observation)
    assert b"tdo-v2-exception-handlers-none-v1" in preimage
    assert sha256(preimage).digest() == _observation_digest(observation)
    assert _observation_digest(observation).hex() != PINNED_OLD_DIGEST


# -- the rule -----------------------------------------------------------------------------------------------

def test_a_recursive_call_explains_its_entry_under_the_fact():
    without = _graph_views(_recursive())
    assert without[0]["1:1004"] == ("1:1000", "1:1008")   # (R7-8 unchanged)
    topology, graph, _, outside, _, tails = _graph_views(_with(_recursive()))
    assert topology["1:1004"] == ("1:1008",)
    assert not graph.blocks[1].exits and outside == () and tails == {}


def _callind(builder, ops, listed=CODE_BASE):
    """Row 1 becomes ``ops`` (ending in CALLIND) listing ``listed``."""
    builder._rows[1].ops[:] = ops
    return builder


@pytest.mark.parametrize("selector, explained", [
    (CODE_BASE, True),          # proven selector = entry
    (CODE_BASE + 4, False),     # proven selector elsewhere: the listed entry stays
    (CODE_BASE + 1, False),     # an odd (Thumb-style) selector never equals the entry
])
def test_a_proven_callind_explains_only_its_selector(selector, explained):
    ops = [copy(tmp(0x400, 8), const(selector, 8)), op("CALLIND", [tmp(0x400, 8)])]
    entry, successors = _successors(_with(_callind(_recursive(), ops)))
    assert (entry not in successors) is explained


def test_an_unproven_callind_explains_the_entry_under_the_fact():
    ops = [op("CALLIND", [reg(RCX)])]
    entry, successors = _successors(_callind(_recursive(), ops))
    assert entry in successors   # (without the fact: R7-8)
    entry, successors = _successors(_with(_callind(_recursive(), ops)))
    assert entry not in successors


def test_an_override_row_keeps_the_entry_under_the_fact():
    def edit(raw):
        raw["instructions"][1]["flow_type"] = {**raw["instructions"][1]["flow_type"], "is_override": True}
    entry, successors = _successors(_with(_recursive(), edit=edit))
    assert entry in successors


@pytest.mark.parametrize("extra", ["cbranch", "callother"])
def test_a_row_that_may_transfer_otherwise_keeps_the_entry(extra):
    b = _recursive()
    ops = b._rows[1].ops
    if extra == "cbranch":
        ops.insert(0, op("CBRANCH", [ram(CODE_BASE), reg(RCX, 1)]))   # names the entry itself
    else:
        ops.append(op("CALLOTHER", [const(0x10, 4)]))
    entry, successors = _successors(_with(b))
    assert entry in successors


def test_two_calls_in_one_row_explain_their_own_targets():
    b = _recursive()
    b._rows[1].ops.insert(0, op("CALL", [ram(OUT)]))

    def edit(raw):
        raw["instructions"][1]["flow_targets"] = sorted(
            raw["instructions"][1]["flow_targets"] + [{"space_id": raw["entry"]["space_id"], "byte_offset": OUT}],
            key=lambda item: item["byte_offset"])
    entry, successors = _successors(_with(b, edit=edit))
    assert entry not in successors and not any(target.byte_offset == OUT for target in successors)


def test_an_interrupt_shaped_row_keeps_the_entry():
    ops = [op("CALLOTHER", [const(0x10, 4)], tmp(0x400, 8)), op("CALLIND", [tmp(0x400, 8)])]
    entry, successors = _successors(_with(_callind(_recursive(), ops)))
    assert entry in successors


# -- split rows (P4) ----------------------------------------------------------------------------------------

def _split_recursive():
    b = _recursive()
    b._rows[1].ops.insert(0, op("CBRANCH", [const(len(b._rows[1].ops) + 1), reg(RCX, 1)]))
    return b


def test_a_split_row_skipping_its_recursive_call_is_admitted_under_the_fact():
    (unit,) = program_units(_split_recursive())
    assert build_pcode_block_graph(unit.observation, unit.scopes.function.entry).unsupported is not None
    topology, graph, _, outside, _, _ = _graph_views(_with(_split_recursive()))
    assert graph.unsupported is None
    assert "1:1000" not in topology["1:1004"] and outside == ()
    assert not any("1:1000" in block.successors for block in graph.blocks if block.key != "1:1000")


def test_an_absolute_branch_to_the_entry_stays_placed_in_a_split_row():
    b = _recursive()
    b._rows[1].ops.insert(0, op("CBRANCH", [ram(CODE_BASE), reg(RCX, 1)]))
    topology, graph, _, _, _, _ = _graph_views(_with(b))
    assert graph.unsupported is None
    assert "1:1000" in topology["1:1004"]
    assert any("1:1000" in block.successors for block in graph.blocks if block.key.startswith("1:1004"))


def test_an_entry_fallthrough_of_a_split_call_row_stays_an_edge():
    """``e: copy; jmp c; c: jcc skip; call e`` laid out ``c`` first, so the call
    row's fallthrough is the entry: the edge is the fallthrough's."""
    def edit(raw):
        row = raw["instructions"][0]
        row["operations"] = [
            {"ordinal": 0, "opcode": "CBRANCH", "inputs": [const(2), reg(RCX, 1)], "output_present": False,
             "output": None},
            {"ordinal": 1, "opcode": "CALL", "inputs": [ram(CODE_BASE + 4)], "output_present": False,
             "output": None}]
        row["flow_targets"] = [{"space_id": raw["entry"]["space_id"], "byte_offset": CODE_BASE + 4}]
        row["flow_type"] = {**row["flow_type"], "is_flow": True, "is_call": True}
        raw["entry"] = {**raw["entry"], "byte_offset": CODE_BASE + 4}
    for value in (None, "none"):
        built = FunctionBuilder().label("c").ins(copy(reg(RAX), const(0))).ins(copy(reg(RAX), const(1))).branch("c")
        if value is None:
            original = built.to_json

            def plain(original=original):
                raw = original()
                edit(raw)
                return raw
            built.to_json = plain
        else:
            built = _with(built, edit=edit)
        (unit,) = program_units(built)
        graph = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
        if value is None:
            assert graph.unsupported is not None
        else:
            assert graph.unsupported is None
            assert any("1:1004" in block.successors for block in graph.blocks if block.key.startswith("1:1000"))


def test_a_split_row_still_places_every_other_listed_local_target():
    """(P4) only the call-explained entry is exempt: a listed local address no
    branch of a split row places is refused as before, fact or not."""
    for value in (None, "none"):
        b = FunctionBuilder().ins(op("CBRANCH", [const(2), reg(RCX, 1)]), copy(reg(RAX), const(1))).ret()

        def edit(raw):
            raw["instructions"][0]["flow_targets"] = [raw["instructions"][1]["address"]]
        if value is None:
            original = b.to_json
            b.to_json = lambda original=original: (lambda raw: (edit(raw), raw)[1])(original())
        else:
            b = _with(b, edit=edit)
        (unit,) = program_units(b)
        graph = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
        assert graph.unsupported == "flow targets the instruction's branches do not place"


# -- the fact contradicts a call row without its ISA fallthrough (r5) ---------------------------------------

def _drop_fallthrough(raw):
    row = raw["instructions"][1]
    row["fallthrough_present"], row["fallthrough"] = False, None


def _move_fallthrough(raw):
    row = raw["instructions"][1]
    row["length"] = 4
    row["fallthrough"] = {**row["fallthrough"], "byte_offset": row["fallthrough"]["byte_offset"] + 4}


@pytest.mark.parametrize("edit", [_drop_fallthrough, _move_fallthrough])
def test_a_call_row_without_its_isa_fallthrough_contradicts_the_fact(edit):
    """(Astra r5 P2) the exporter proves the fact only with every call row
    keeping its ISA return PC as fallthrough: a Bundle claiming the fact with
    a missing or moved fallthrough is refused (without the fact: admitted)."""
    plain = _recursive().ins(copy(reg(RAX), const(0))).ret()
    original = plain.to_json
    plain.to_json = lambda: (lambda raw: (edit(raw), raw)[1])(original())
    (unit,) = program_units(plain)
    assert unit.observation is not None
    built = _with(_recursive().ins(copy(reg(RAX), const(0))).ret(), edit=edit)
    (unit,) = program_units(built)
    assert unit.observation is None


def test_a_kind_4_exit_must_name_the_isa_return_pc():
    """(Astra r6 P1) an S1 kind-4 exit stands for the call's ISA continuation:
    one naming another address contradicts the fact (the call at 0x1004
    returns to 0x1008, not to the unmapped 0x900000)."""
    from test_call_fallthrough_contract import CALL, UNMAPPED, Patched, _branchy, _exit, _fall_into
    from tdo_v2._scope_contracts import CONTINUATION_BOUNDARY
    def builder():
        return Patched(exits=[_exit(CALL, UNMAPPED, CONTINUATION_BOUNDARY, None)], edit=_fall_into(UNMAPPED, row=1))
    assert _unit(_branchy(builder()), _callee()).observation is not None   # (without the fact: S1 as before)
    assert _unit(_branchy(_with(builder())), _callee()).observation is None


def test_a_kind_4_exit_naming_a_row_of_the_function_contradicts_the_fact():
    """(Fable / Astra r7 P1) a kind-4 exit at the ISA return PC that is a row
    of the function (0x1008, the ret) with no fallthrough kept on the call
    row: that row's return edge would hide behind the fact."""
    from test_call_fallthrough_contract import CALL, Patched, _branchy, _exit
    from tdo_v2._scope_contracts import CONTINUATION_BOUNDARY

    def drop(raw):
        row = raw["instructions"][1]
        row["fallthrough_present"], row["fallthrough"] = False, None

    def builder():
        return Patched(exits=[_exit(CALL, CALL + 4, CONTINUATION_BOUNDARY, None)], edit=drop)
    assert _unit(_branchy(_with(builder())), _callee()).observation is None


def test_a_computed_jump_contradicts_the_fact():
    """(Astra r7 P1) the exporter never proves the fact for a function with a
    BRANCHIND row: one under it is refused."""
    b = FunctionBuilder().ins(copy(reg(RAX), const(1))).call(OUT).ret()
    b._rows[2].ops[:] = [op("BRANCHIND", [reg(RAX)])]
    assert program_units(b)[0].observation is not None   # (without the fact)
    assert program_units(_with(b))[0].observation is None


def test_exit_element_types_are_checked_first():
    """(Astra r7 P3) a malformed exit element is a TypeError, not an AttributeError."""
    (unit,) = program_units(_with(_recursive()))
    with pytest.raises(TypeError, match="exact tuple"):
        ValidatedFunctionObservation(unit.observation.instructions, True, (object(),), True)


def test_a_kind_4_exit_at_the_isa_return_pc_keeps_the_fact():
    """A call ending the code block: its ISA continuation 0x2000 is outside
    program memory, an S1 kind-4 exit, and the fact stands."""
    from test_call_fallthrough_contract import Patched, _exit
    from tdo_v2._scope_contracts import CONTINUATION_BOUNDARY
    end = CODE_BASE + 0x1000

    def edit(raw):
        raw["instructions"].pop()   # (the ret past the block)
        call = raw["instructions"][-1]
        call["fallthrough"] = {**call["fallthrough"], "byte_offset": end}
    builder = Patched(entry=end - 12, exits=[_exit(end - 4, end, CONTINUATION_BOUNDARY, None)], edit=edit)
    builder.cbranch("c", reg(RCX, 1)).ret().label("c").call(OUT).ret()
    unit = _unit(_with(builder), _callee(OUT))
    assert unit.observation is not None and unit.observation.exception_handlers_none
    assert unit.observation.instructions[-1].fallthrough is None


def test_a_call_row_without_a_length_contradicts_the_fact():
    """(Astra r6 P2) the exporter writes every row's length with the fact."""
    def edit(raw):
        raw["instructions"][1].pop("length")
    assert program_units(_with(_recursive(), edit=edit))[0].observation is None
    (unit,) = program_units(_with(_recursive()))
    rows = list(unit.observation.instructions)
    rows[1] = replace(rows[1], length=None)
    with pytest.raises(ValueError, match="records its length"):
        ValidatedFunctionObservation(tuple(rows), exception_handlers_none=True)


def test_a_row_the_call_gate_excludes_needs_no_fallthrough():
    """(Fable r6 P2) a call row also holding RETURN (Ghidra's INT3 shape) never
    explains a target: no fallthrough is required of it under the fact."""
    b = FunctionBuilder().ins(copy(reg(RAX), const(1))).call(OUT).ret()
    b._rows[1].ops[:] = [op("CALLOTHER", [const(3, 4)], tmp(0x400, 8)), op("CALLIND", [tmp(0x400, 8)]),
                         op("RETURN", [const(0, 8)])]

    def edit(raw):
        row = raw["instructions"][1]
        row["fallthrough_present"], row["fallthrough"], row["flow_targets"] = False, None, []
        raw["instructions"].pop()
    (unit,) = program_units(_with(b, edit=edit))
    assert unit.observation is not None and unit.observation.exception_handlers_none
