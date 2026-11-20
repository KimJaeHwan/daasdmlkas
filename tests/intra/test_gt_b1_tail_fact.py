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
    assert any(reason == "physical callee has a non-RETURN exit" for reason in cuts.values()), cuts


# -- review r1 pins -------------------------------------------------------------------


def _row(builder, index, change):
    """Instruction ``index`` of ``builder``'s JSON passed through ``change``."""
    original = builder.to_json

    def to_json():
        raw = original()
        change(raw, raw["instructions"][index])
        return raw

    builder.to_json = to_json
    return builder


def _free_image():
    from test_import_tail_jumps import ABORT, FREE
    from tdo_v2.image_info import ImageInfo, ImportedSymbol

    return ImageInfo("synthetic", (), (ImportedSymbol("CRT", "free", None, (), ((1, FREE),)),
                                       ImportedSymbol("CRT", "abort", None, (), ((1, ABORT),)),
                                       ImportedSymbol("LIB.DLL", "f", None, ((1, SLOT),), ())), (), ())


def _imports(builder):
    from tdo_v2.interprocedural import import_call_sites

    (unit,) = program_units(builder)
    return {key: symbol.name for key, symbol in import_call_sites(unit, _free_image()).items()}


def test_an_override_marked_import_tail_is_refused_with_a_reason():
    """``jmp free`` flagged as a flow override: the fact refuses it -- no model,
    an unknown tail exit, and a per-site reason (review r1 Astra P2)."""
    from test_import_tail_jumps import FREE, MODELS
    from tdo_v2.summary_store import load_external_models

    def override(raw, row):
        row["flow_type"]["is_override"] = True

    jump = _row(FunctionBuilder().sub_rsp(0x28).add_rsp(0x28).tail_call(FREE), -1, override)
    assert _imports(jump) == {}
    other = FunctionBuilder(entry=CODE_BASE + 0x400).sub_rsp(0x28).call(CODE_BASE + 0x800).add_rsp(0x28).ret()
    item = analyze_units(program_units(jump, other), image_info=_free_image(),
                         external_models=load_external_models(MODELS, "x86:LE:64:default", "win64"))["1:1000"]
    assert not item.proven and item.summary.tail_exits
    ((site, reason),) = item.refused_models.items()
    assert site.endswith(":BRANCH") and "flow override" in reason and "/free@" in reason.split(":")[1]


def test_an_import_tail_on_an_unreachable_row_is_not_bound():
    from test_import_tail_jumps import FREE

    assert _imports(FunctionBuilder().ret().tail_call(FREE)) == {}


def test_a_non_final_branch_to_an_import_thunk_is_now_bound():
    """``CBRANCH +2; BRANCH free; BRANCH free``: the first BRANCH ends a split
    segment that leaves -- a "branch" fact the old last-operation rule missed
    (gate class 6 gain)."""
    from test_import_tail_jumps import FREE

    flag = tmp(0x300, 1)
    builder = FunctionBuilder().tail_call(FREE)
    builder._rows[-1].ops[:0] = [op("INT_NOTEQUAL", [reg(RCX), const(0)], flag), op("CBRANCH", [const(2, 4), flag]),
                                 op("BRANCH", [ram(FREE)])]
    assert set(_imports(builder)) == {f"1:{CODE_BASE:x}:2:BRANCH", f"1:{CODE_BASE:x}:3:BRANCH"}


def test_a_slot_tail_with_a_local_observed_target_is_not_bound():
    plain = FunctionBuilder().ins(copy(reg(RCX), const(1))).jump_indirect(ram(SLOT))
    assert list(_imports(plain).values()) == ["f"]

    def local(raw, row):
        row["flow_targets"] = [dict(raw["instructions"][0]["address"])]

    assert _imports(_row(FunctionBuilder().ins(copy(reg(RCX), const(1))).jump_indirect(ram(SLOT)), -1, local)) == {}


def test_a_successor_bearing_conditional_jump_without_an_edge_block_is_a_tail_exit():
    """``jz T`` flagged as a flow override has no edge block (never a tail
    fact); handed to the summary as a noreturn jump anyway, its block stays a
    tail exit -- the old successor-bearing skip is gone (r15 final fixes)."""
    from tdo_v2.function_summary import summarize_function

    def override(raw, row):
        row["flow_type"]["is_override"] = True

    middle = _row(_to(FunctionBuilder(entry=MIDDLE).cbranch("done", reg(ZF, 1)).ins(copy(reg(RAX), const(7)))
                      .label("done").ret(), None, TARGET), 0, override)
    units = program_units(middle, _target())
    site = _site(units[0])
    assert site not in tail_transfers(units[0].observation, units[0].scopes.function.entry)
    item = analyze_units(units)[function_key_of(1, MIDDLE)]
    block = f"1:{MIDDLE:x}"
    assert block in item.summary.tail_exits
    assert block in summarize_function(item.normalized, units[0].observation,
                                       noreturn_jumps=frozenset({site})).tail_exits


def test_a_dead_edge_site_is_dead_in_the_exit_loop_too():
    """(review r1 Fable P2-1) one decision: an edge whose site is a dead edge
    site has no exit state, even when its effect composes -- never a composed
    exit with its rows dropped."""
    from tdo_v2.function_summary import summarize_function

    middle = _to(FunctionBuilder(entry=MIDDLE).cbranch("done", reg(ZF, 1)).ins(copy(reg(RAX), const(7)))
                 .label("done").ret(), None, TARGET)
    units = program_units(middle, _target())
    item = analyze_units(units)[function_key_of(1, MIDDLE)]
    site = _site(units[0])
    assert _edge_of(site) in {state.block_key for state in item.summary.exits}
    dead = summarize_function(item.normalized, units[0].observation, noreturn_jumps=frozenset({site}))
    assert _edge_of(site) not in {state.block_key for state in dead.exits}
    assert _edge_of(site) not in dead.tail_exits


def test_a_bundle_noreturn_edge_has_no_exit_state():
    from test_conditional_summaries import _int3
    from tdo_v2.pcodeop_models import PcodeOpModel

    middle = _to(FunctionBuilder(entry=MIDDLE).cbranch("done", reg(ZF, 1)).ins(copy(reg(RAX), const(7)))
                 .label("done").ret(), None, TARGET)
    units = program_units(middle, FunctionBuilder(entry=TARGET).ins(_int3()).ret())
    namespace = units[0].scopes.program.evidence.translation_namespace
    model = PcodeOpModel("x86-markers", 1, frozenset({(namespace.language_id, namespace.major_version,
                                                        namespace.minor_version)}), {}, {16: frozenset({3})})
    item = analyze_units(units, pcodeop_models=(model,), assume_debug_break_traps_do_not_return=True)[
        function_key_of(1, MIDDLE)]
    site = _site(units[0])
    assert item.proven[site].noreturn
    assert item.summary.dead_exits == (_edge_of(site),)
    assert _edge_of(site) not in {state.block_key for state in item.summary.exits}
    assert site not in {row[0] for row in item.summary.inner_calls}


def test_the_tail_fact_cache_is_by_identity_and_skips_test_doubles():
    from types import SimpleNamespace

    (unit,) = program_units(FunctionBuilder().ins(copy(reg(RAX), const(1))).tail_call(CODE_BASE + 0x900))
    entry = unit.scopes.function.entry
    first = tail_transfers(unit.observation, entry)
    assert tail_transfers(unit.observation, entry) is first and len(first) == 1
    double = SimpleNamespace(instructions=list(unit.observation.instructions), fallthrough_exits=())
    assert len(tail_transfers(double, entry)) == 1
    double.instructions[-1] = unit.observation.instructions[0]   # (mutated in place: no jump left)
    assert tail_transfers(double, entry) == {}


def test_disagreeing_call_and_return_shapes_give_no_program_stack():
    """The tail target returns through rbp (``rip = *(rbp); rbp += 8;
    RETURN rip``), the source through rsp: two stack pointers -- none is
    taken, the conditional tail is not composed."""
    from synthetic import RBP, RIP, load

    middle = _to(FunctionBuilder(entry=MIDDLE).cbranch("done", reg(ZF, 1)).ins(copy(reg(RAX), const(7)))
                 .label("done").ret(), None, TARGET)
    target = FunctionBuilder(entry=TARGET).ins(add(reg(RAX), reg(RDI), const(1))).ins(
        load(reg(RIP), reg(RBP)), add(reg(RBP), reg(RBP), const(8)), op("RETURN", [reg(RIP)]))
    units = program_units(middle, target)
    item = analyze_units(units)[function_key_of(1, MIDDLE)]
    site = _site(units[0])
    effect = item.proven.get(site)
    assert effect is None or not effect.tail_stack
    assert item.summary is not None and _edge_of(site) in item.summary.tail_exits


def test_a_mutual_tail_recursion_without_call_shapes_composes():
    """``f: jz out; rcx += 1; jmp g; out: ret`` and ``g: jmp f`` -- an SCC
    through tail jumps, RET shapes only: the program stack pointer gives the
    bottom hypothesis and both tails compose (review r1: a real SCC)."""
    f_entry, g_entry = CODE_BASE + 0x400, CODE_BASE + 0x600
    f = (FunctionBuilder(entry=f_entry).cbranch("out", reg(ZF, 1)).ins(add(reg(RCX), reg(RCX), const(1)))
         .tail_call(g_entry).label("out").ret())
    g = FunctionBuilder(entry=g_entry).tail_call(f_entry)
    results = analyze_units(program_units(f, g))
    for entry in (f_entry, g_entry):
        item = results[function_key_of(1, entry)]
        tails = [effect for key, effect in item.proven.items() if key.endswith(":BRANCH")]
        assert tails and all(effect.tail_stack for effect in tails), entry
        assert item.summary is not None and item.summary.tail_exits == (), entry


def test_a_refused_conditional_noreturn_import_keeps_its_reason_with_a_bundle_body_there():
    """(review r2 Astra P2) ``jz abort`` flagged as a flow override (no edge
    block, no fact): the legacy cut is not taken and the site keeps a reason --
    also when a Bundle function sits at the thunk address."""
    from test_import_tail_jumps import ABORT, MODELS
    from tdo_v2.summary_store import load_external_models

    def override(raw, row):
        row["flow_type"]["is_override"] = True

    for body in (None, FunctionBuilder(entry=ABORT).ret()):
        middle = _row(_to(FunctionBuilder(entry=MIDDLE).sub_rsp(0x28).cbranch("done", reg(ZF, 1))
                          .ins(copy(reg(RAX), const(7))).label("done").add_rsp(0x28).ret(), None, ABORT), 1, override)
        units = program_units(middle, *((body,) if body is not None else ()))
        item = analyze_units(units, image_info=_free_image(),
                             external_models=load_external_models(MODELS, "x86:LE:64:default", "win64"))[
            function_key_of(1, MIDDLE)]
        site = _site(units[0])
        assert site not in item.proven and site not in item.declared, body
        assert "flow override" in item.refused_models.get(site, ""), (body, item.refused_models)


def test_a_dead_edge_drops_its_staged_writers_conditions():
    """(review r2 Astra P3) ``*rdi = rdx; jz T; ret`` where T stores through a
    pointer it loads (``rcx = *rsi; *rcx = 7``): the staged writer's alias
    conditions are writer conditions while the edge is live, and none once the
    edge is dead -- the conditional-set filter is observable."""
    from synthetic import RDX, RSI, load
    from tdo_v2.function_summary import summarize_function

    middle = _to(FunctionBuilder(entry=MIDDLE).ins(store(reg(RDI), reg(RDX))).cbranch("done", reg(ZF, 1))
                 .label("done").ret(), None, TARGET)
    target = FunctionBuilder(entry=TARGET).ins(load(reg(RCX), reg(RSI))).ins(store(reg(RCX), const(7, 8))).ret()
    units = program_units(middle, target)
    item = analyze_units(units)[function_key_of(1, MIDDLE)]
    site = _site(units[0])
    assert item.proven[site].tail_stack
    dead = summarize_function(item.normalized, units[0].observation, noreturn_jumps=frozenset({site}))
    assert dead.writer_conditions == ()
