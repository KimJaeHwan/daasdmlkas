"""(G-T G3b-1, docs 25.104) One tail fact and what rests on it.

``pcode_blocks.tail_transfers`` is the one rule for "this jump leaves the
function" -- tail calls, import tails and noreturn jumps all read it, never an
instruction-local rule or Ghidra's call flag. The program stack pointer also
comes from return shapes (a closure without call shapes composes its tails),
the edge blocks of dead conditional tails hold no exit facts, a call-like row
with landing pads must end in its call whatever its flag says, and an exiting
BRANCH proves a register delta only as an admitted tail.
"""

from dataclasses import replace

from synthetic import (
    CODE_BASE, RAX, RCX, RDI, RSP, ZF, FunctionBuilder, add, const, copy, op, program_units, ram, reg, store, tmp,
)
from test_gt_conditional_tails import MIDDLE, TARGET, _caller, _edge_of, _target, _to
from test_import_call_shapes import SLOT, _WithLandingPad
from tdo_v2.interprocedural import analyze_units, function_key_of
from tdo_v2.pcode_blocks import build_pcode_block_graph, tail_transfers


def _flag(builder, row, *, call):
    """Instruction ``row`` with Ghidra's call flag set or cleared (``is_jump``
    flipped with it: the two are exclusive)."""
    original = builder.to_json

    def to_json():
        raw = original()
        item = raw["instructions"][row]
        item["flow_type"] = {**item["flow_type"], "is_call": call, "is_jump": not call}
        return raw

    builder.to_json = to_json
    return builder


def _site(unit):
    """The conditional-tail site key of the unit's first CBRANCH."""
    for row in unit.observation.instructions:
        for ordinal, operation in enumerate(row.operations):
            if operation.opcode == "CBRANCH":
                return f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:CBRANCH"
    raise AssertionError("no CBRANCH")


def _graph(builder):
    (unit,) = program_units(builder)
    return build_pcode_block_graph(unit.observation, unit.scopes.function.entry)


# -- landing pads by code facts (design r15 A) -----------------------------------


def _call_then_copy(*, call):
    builder = _WithLandingPad(1, "pad").sub_rsp(0x28).call(CODE_BASE + 0x800)
    builder._rows[-1].ops.append(copy(reg(RAX), ram(SLOT)))
    builder = builder.ins(copy(reg(RCX), const(1))).label("pad").call_indirect(RAX).add_rsp(0x28).ret()
    return _flag(builder, 1, call=call)


def test_an_unflagged_call_with_a_landing_pad_and_operations_after_it_is_unsupported():
    for call in (True, False):
        assert _graph(_call_then_copy(call=call)).unsupported == \
            "a call with landing pads that does not end in its call", call


def test_an_unflagged_landing_pad_that_is_also_the_fallthrough_still_counts():
    for call in (True, False):
        builder = _WithLandingPad(1, "pad").sub_rsp(0x28).call(CODE_BASE + 0x800)
        builder._rows[-1].ops.append(copy(reg(RAX), ram(SLOT)))
        builder = _flag(builder.label("pad").call_indirect(RAX).add_rsp(0x28).ret(), 1, call=call)
        assert _graph(builder).unsupported is not None, call


def test_an_unflagged_callother_row_with_a_landing_pad_is_unsupported():
    for call in (True, False):
        builder = _WithLandingPad(1, "pad").sub_rsp(0x28).call(CODE_BASE + 0x800)
        builder._rows[-1].ops[:] = [op("CALLOTHER", [const(1, 4)]), copy(reg(RAX), ram(SLOT))]
        builder = builder.ins(copy(reg(RCX), const(1))).label("pad").call_indirect(RAX).add_rsp(0x28).ret()
        assert _graph(_flag(builder, 1, call=call)).unsupported is not None, call


def test_an_unflagged_split_call_whose_branch_places_its_pad_is_unsupported():
    """``CBRANCH pad; COPY; CALL`` with ``pad`` listed: the split path accepts
    the pad (the CBRANCH places it), yet the CALL's exceptional edge to it is
    not modelled -- refused with or without the call flag (Astra r14 P1-2)."""
    flag = tmp(0x300, 1)
    for call in (True, False):
        builder = _WithLandingPad(1, "pad").sub_rsp(0x28).call(CODE_BASE + 0x800)
        pad = CODE_BASE + 2 * builder.stride
        builder._rows[-1].ops[:0] = [op("INT_NOTEQUAL", [reg(RCX), const(0)], flag),
                                     op("CBRANCH", [ram(pad), flag]), copy(reg(RCX), const(1))]
        builder = builder.label("pad").ins(copy(reg(RAX), ram(SLOT))).call_indirect(RAX).add_rsp(0x28).ret()
        assert _graph(_flag(builder, 1, call=call)).unsupported == "a split call with landing pads", call


def test_a_call_like_row_ending_in_a_conditional_tail_with_a_pad_is_refused_before_its_edge_block():
    """``CALL x; CBRANCH out`` whose observed flow lists only ``out`` and its
    fallthrough -- edge-eligible -- with the fallthrough a landing pad of the
    call: the call-like row is refused before any edge block is made, flag or
    not (r15 final fixes); a flag-only pure CBRANCH keeps its edge."""
    flag = tmp(0x300, 1)
    out = CODE_BASE + 0x900
    for call in (True, False):
        builder = (FunctionBuilder().ins(op("CALL", [ram(CODE_BASE + 0x800)]),
                                         op("INT_NOTEQUAL", [reg(RCX), const(0)], flag),
                                         op("CBRANCH", [ram(out), flag]))
                   .ins(copy(reg(RCX), const(1))).ret())
        original = builder.to_json

        def to_json(original=original, call=call):
            raw = original()
            row = raw["instructions"][0]
            row["flow_targets"] = sorted([{"space_id": row["address"]["space_id"], "byte_offset": out},
                                          dict(row["fallthrough"])], key=lambda item: item["byte_offset"])
            row["flow_type"] = {**row["flow_type"], "is_call": call, "is_jump": not call}
            return raw

        builder.to_json = to_json
        assert _graph(builder).unsupported == "a call with landing pads that does not end in its call", call
        pure = FunctionBuilder().cbranch("next", reg(ZF, 1)).label("next").ins(copy(reg(RCX), const(1))).ret()
        pure = _to(pure, 0, out)
        original_pure = pure.to_json

        def flagged(original_pure=original_pure):
            raw = original_pure()
            row = raw["instructions"][0]
            row["flow_targets"] = sorted([*row["flow_targets"], dict(row["fallthrough"])],
                                         key=lambda item: item["byte_offset"])
            row["flow_type"] = {**row["flow_type"], "is_call": True, "is_jump": False}
            return raw

        pure.to_json = flagged
        graph = _graph(pure)
        assert graph.unsupported is None and any(block.edge is not None for block in graph.blocks)


# -- the fact --------------------------------------------------------------------


def test_the_fact_names_all_three_kinds():
    middle = _to(FunctionBuilder(entry=MIDDLE).cbranch("done", reg(ZF, 1)).ins(copy(reg(RAX), const(7)))
                 .label("done").tail_call(TARGET), None, TARGET)
    (unit,) = program_units(middle)
    facts = tail_transfers(unit.observation, unit.scopes.function.entry)
    assert sorted(item.kind for item in facts.values()) == ["branch", "cbranch"]
    (cbranch,) = [item for item in facts.values() if item.kind == "cbranch"]
    assert cbranch.edge == _edge_of(_site(unit)) and cbranch.target.byte_offset == TARGET
    (jump,) = program_units(FunctionBuilder().jump_indirect(ram(SLOT)))
    assert [item.kind for item in tail_transfers(jump.observation, jump.scopes.function.entry).values()] == \
        ["branchind"]


def test_a_call_flag_never_makes_a_branchind_fact_out_of_an_entry_target():
    """``BRANCHIND`` whose only observed target is the entry (a loop back to
    it): flagged, the entry edge is dropped and the block exits; the fact
    reads the row's targets and admits none either way (design r14 B)."""
    for call in (True, False):
        builder = FunctionBuilder().ins(copy(reg(RAX), const(1))).jump_indirect(reg(RAX))
        original = builder.to_json

        def to_json(original=original, call=call):
            raw = original()
            row = raw["instructions"][-1]
            row["flow_targets"] = [{"space_id": raw["instructions"][0]["address"]["space_id"],
                                    "byte_offset": raw["instructions"][0]["address"]["byte_offset"]}]
            row["flow_type"] = {**row["flow_type"], "is_call": call, "is_jump": not call}
            return raw

        builder.to_json = to_json
        (unit,) = program_units(builder)
        assert tail_transfers(unit.observation, unit.scopes.function.entry) == {}, call


# -- the program stack pointer from return shapes ----------------------------------


def test_a_closure_without_call_shapes_composes_its_conditional_tail():
    """memset analysed alone: the function and its tail target, no call
    anywhere -- the return shapes name the stack pointer, the tail composes."""
    middle = _to(FunctionBuilder(entry=MIDDLE).cbranch("done", reg(ZF, 1)).ins(copy(reg(RAX), const(7)))
                 .label("done").ret(), None, TARGET)
    units = program_units(middle, _target())
    item = analyze_units(units)[function_key_of(1, MIDDLE)]
    site = _site(units[0])
    assert item.proven[site].tail_stack
    assert item.summary.tail_exits == ()
    assert dict(item.summary.register_deltas)[(RSP, 8)] == 8


def test_a_return_without_the_terminal_flag_still_has_a_return_shape():
    from tdo_v2.may_alias import _return_shape

    builder = FunctionBuilder().ret()
    original = builder.to_json

    def to_json():
        raw = original()
        raw["instructions"][-1]["flow_type"]["is_terminal"] = False
        return raw

    builder.to_json = to_json
    (unit,) = program_units(builder)
    row = unit.observation.instructions[-1]
    assert not row.flow.is_terminal
    assert _return_shape(row) is not None


def test_a_self_tail_recursion_without_call_shapes_reaches_a_fixpoint():
    """``f: jz f_body_end; ...; jmp f`` -- an SCC through a tail jump with a
    RET shape only: the program stack pointer gives the bottom hypothesis."""
    entry = CODE_BASE + 0x400
    body = (FunctionBuilder(entry=entry).cbranch("out", reg(ZF, 1)).ins(add(reg(RCX), reg(RCX), const(1)))
            .tail_call(entry).label("out").ret())
    units = program_units(body)
    item = analyze_units(units)[function_key_of(1, entry)]
    assert item.summary is not None


# -- dead edge sites (design r11 1.5, r13 5) -----------------------------------------


def test_a_dead_edge_blocks_rows_and_crossing_are_dropped():
    """The edge block's staged rows of a site whose edge is dead (here: the
    legacy noreturn cut applied, as ``_call_activation`` re-summarises with
    it) are dead for exit facts: the live composed edge crosses the target
    (``inner_calls`` names the site), the dead one does not."""
    from tdo_v2.function_summary import summarize_function

    middle = _to(FunctionBuilder(entry=MIDDLE).cbranch("done", reg(ZF, 1)).ins(copy(reg(RAX), const(7)))
                 .label("done").ret(), None, TARGET)
    units = program_units(middle, _target())
    item = analyze_units(units)[function_key_of(1, MIDDLE)]
    site = _site(units[0])
    assert item.proven[site].tail_stack
    assert site in {row[0] for row in item.summary.inner_calls}
    dead = summarize_function(item.normalized, units[0].observation, noreturn_jumps=frozenset({site}))
    assert site not in {row[0] for row in dead.inner_calls}


def test_the_raw_conditional_branch_is_never_dead_by_its_site():
    from tdo_v2.function_summary import staged_dead

    site = "1:1600:0:CBRANCH"
    assert staged_dead(site + "~u0", frozenset(), frozenset({site}))
    assert staged_dead(site + "~edge", frozenset(), frozenset({site}))
    assert not staged_dead(site, frozenset(), frozenset({site}))
    assert staged_dead(site, frozenset({site}), frozenset())


# -- register delta proofs (design r12 1.2b, r14 D) ------------------------------------


def test_an_exiting_branch_the_fact_refuses_proves_no_delta():
    """A tail ``jmp T`` whose observed flow also lists another target: the fact
    refuses it, so a well-formed effect at its key proves nothing (the same
    effect on the agreeing jump does)."""
    from test_gt_tail_facts import _thunk
    from tdo_v2.model import StorageObjectId
    from tdo_v2.register_delta_proofs import derive_register_delta_proof
    from tdo_v2.span_geometry import ByteSpan, StorageObjectKind

    target = CODE_BASE + 0x800
    results = analyze_units(program_units(FunctionBuilder().tail_call(target), FunctionBuilder(entry=target).ret(),
                                          FunctionBuilder(entry=CODE_BASE + 0xc00).call(CODE_BASE).ret()))
    item = results[function_key_of(1, CODE_BASE)]
    span = ByteSpan(StorageObjectId(StorageObjectKind.REGISTER_FILE, item.unit.scopes.program.scope, 0), RSP, 8)
    assert derive_register_delta_proof(item.unit, span, item.proven, {}) is not None
    (refused,) = program_units(_thunk(FunctionBuilder().tail_call(target), terminal=True, call=True,
                                      extra_target=CODE_BASE + 0x900))
    assert tail_transfers(refused.observation, refused.scopes.function.entry) == {}
    span = replace(span, object_id=StorageObjectId(StorageObjectKind.REGISTER_FILE, refused.scopes.program.scope, 0))
    assert derive_register_delta_proof(refused, span, item.proven, {}) is None


# -- physical call context (design r11 1.6) ---------------------------------------------


def test_a_physical_call_context_refuses_a_callee_with_a_branch_tail():
    from test_physical_call_records import _caller as _physical_caller, _case, _record

    callee = FunctionBuilder(entry=0x1800).ins(copy(reg(RCX), reg(RDI))).tail_call(0x1a00)
    target = FunctionBuilder(entry=0x1a00).ins(add(reg(RAX), reg(RCX), const(1))).ret()
    case = _case(_physical_caller(), callee, target)
    assert any(key.endswith(":BRANCH") for key in case["callee"].proven)
    cuts = _record(case).get("physical_call_cuts", {})
    assert any(reason == "physical callee has a tail" for reason in cuts.values()), cuts
