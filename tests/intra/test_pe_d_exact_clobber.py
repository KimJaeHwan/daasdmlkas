"""PE-d (S3 design r18, amendment 7): call-clobber discharge proves the right
bytes through the exit. A preservation certificate must cover every claimed
byte at every exit, including calls after the last candidate definition."""

import pytest

from synthetic import (
    CODE_BASE, RAX, RBP, RBX, RCX, RSP, FunctionBuilder, analyze_program, boundary, const, copy, op, reg,
)

MAIN, SOURCE, SINK, HELPER, OPAQUE = (CODE_BASE, CODE_BASE + 0x800, CODE_BASE + 0xA00, CODE_BASE + 0xC00,
                                      CODE_BASE + 0xE00)
PROVIDER = boundary({"source": 4}, {"sink": 4})


def _source():
    return (FunctionBuilder(entry=SOURCE).push(RBP).ins(copy(reg(RBP), reg(RSP)))
            .ins(copy(reg(RAX, 4), const(7, 4))).pop(RBP).ret())


def _main():
    """RBX = source(); helper(); sink(EBX)."""
    return (FunctionBuilder(entry=MAIN).call(SOURCE).ins(copy(reg(RBX, 4), reg(RAX, 4))).call(HELPER)
            .ins(copy(reg(RCX, 4), reg(RBX, 4))).call(SINK).ret())


def _complete(helper):
    functions = {"main": _main(), "source": _source(), "helper": helper,
                 "sink": FunctionBuilder(entry=SINK).ret()}
    return analyze_program(functions, PROVIDER)[("main", "sink.arg0")].is_effectively_complete


@pytest.mark.parametrize("after", ("opaque call", "syscall"))
def test_a_clobber_after_the_restore_denies_preservation(after):
    """push rbx; rbx = 0; pop rbx; <call>; ret -- the restore is the last write,
    but the call after it may change RBX: no certificate (amendment 7's test)."""
    helper = FunctionBuilder(entry=HELPER).push(RBX).ins(copy(reg(RBX), const(0))).pop(RBX)
    if after == "opaque call":
        helper.call(OPAQUE)
    else:
        helper.ins(op("CALLOTHER", [const(5, 4)]))
    assert not _complete(helper.ret())


LEAF = CODE_BASE + 0x900


def _complete_with(helper, *extra):
    functions = {"main": _main(), "source": _source(), "helper": helper,
                 "sink": FunctionBuilder(entry=SINK).ret(), **{f"extra{i}": body for i, body in enumerate(extra)}}
    return analyze_program(functions, PROVIDER)[("main", "sink.arg0")].is_effectively_complete


def test_the_restore_after_the_last_call_keeps_preservation():
    """push rbx; call leaf (analysed, keeps everything); rbx = 0; pop rbx; ret --
    the restore follows every call: the certificate stands (control)."""
    helper = (FunctionBuilder(entry=HELPER).push(RBX).call(LEAF).ins(copy(reg(RBX), const(0))).pop(RBX).ret())
    assert _complete_with(helper, FunctionBuilder(entry=LEAF).ret())


def test_an_analysed_call_after_the_restore_that_keeps_rbx_keeps_preservation():
    """push rbx; rbx = 0; pop rbx; call leaf (keeps RBX); ret: the call after the
    restore is proven not to change RBX -- the certificate stands."""
    helper = (FunctionBuilder(entry=HELPER).push(RBX).ins(copy(reg(RBX), const(0))).pop(RBX).call(LEAF).ret())
    assert _complete_with(helper, FunctionBuilder(entry=LEAF).ret())


@pytest.mark.parametrize("after", ("opaque call", "syscall", "none"))
def test_a_must_write_needs_no_clobber_after_the_write(after):
    """source: eax = 7; <call>; ret -- the callee's last write of EAX is not its
    value at the exit when a call after it may change EAX (amendment 7)."""
    source = FunctionBuilder(entry=SOURCE).ins(copy(reg(RAX, 4), const(7, 4)))
    if after == "opaque call":
        source.call(OPAQUE)
    elif after == "syscall":
        source.ins(op("CALLOTHER", [const(5, 4)]))
    main = FunctionBuilder(entry=MAIN).call(SOURCE).ins(copy(reg(RCX, 4), reg(RAX, 4))).call(SINK).ret()
    functions = {"main": main, "source": source.ret(), "sink": FunctionBuilder(entry=SINK).ret()}
    complete = analyze_program(functions, PROVIDER)[("main", "sink.arg0")].is_effectively_complete
    assert complete is (after == "none")


@pytest.mark.parametrize("after", ("opaque call", "syscall"))
def test_the_summary_engine_keeps_no_rbx_across_a_later_call(after):
    """The summary path (callee effects from summaries) on the same shape:
    push rbx; rbx = 0; pop rbx; <call>; ret keeps no RBX either."""
    from synthetic import analyze_summaries

    helper = FunctionBuilder(entry=HELPER).push(RBX).ins(copy(reg(RBX), const(0))).pop(RBX)
    if after == "opaque call":
        helper.call(OPAQUE)
    else:
        helper.ins(op("CALLOTHER", [const(5, 4)]))
    names = {SOURCE: "source", SINK: "sink", HELPER: "helper"}
    run = analyze_summaries([_main(), _source(), helper.ret(), FunctionBuilder(entry=SINK).ret()], PROVIDER,
                            names=names)
    (root,) = [item for item in run.roots if item.label == "sink.arg0" and item.function_byte_offset == MAIN]
    assert not root.is_effectively_complete


def _writes_rbx_on_one_path():
    from synthetic import ZF

    return (FunctionBuilder(entry=LEAF).cbranch("out", reg(ZF, 1)).ins(copy(reg(RBX), const(5)))
            .label("out").ret())


def _writes_rbx_differently_per_exit():
    from synthetic import ZF

    return (FunctionBuilder(entry=LEAF).cbranch("other", reg(ZF, 1)).ins(copy(reg(RBX), const(5))).ret()
            .label("other").ins(copy(reg(RBX), const(6))).ret())


def _joins_rbx_at_one_exit():
    from synthetic import ZF

    return (FunctionBuilder(entry=LEAF).cbranch("other", reg(ZF, 1)).ins(copy(reg(RBX), const(5)))
            .branch("out").label("other").ins(copy(reg(RBX), const(6))).label("out").ret())


@pytest.mark.parametrize("leaf", (_writes_rbx_on_one_path, _writes_rbx_differently_per_exit, _joins_rbx_at_one_exit))
def test_a_callee_writing_rbx_on_some_path_does_not_keep_it(leaf):
    """Fable PE-d r1 P1-1: push rbx; rbx = 0; pop rbx; call g; ret where g writes
    RBX on one path, differently per exit, or joins two writes -- g does not
    keep RBX (no write shared by every exit is no proof of "untouched")."""
    helper = (FunctionBuilder(entry=HELPER).push(RBX).ins(copy(reg(RBX), const(0))).pop(RBX).call(LEAF).ret())
    assert not _complete_with(helper, leaf())


def test_a_call_after_the_restore_on_one_exit_only_denies_preservation():
    """Fable PE-d r1 P2-1: two exits, only one of them calls after the restore."""
    from synthetic import ZF

    helper = (FunctionBuilder(entry=HELPER).push(RBX).ins(copy(reg(RBX), const(0))).pop(RBX)
              .cbranch("plain", reg(ZF, 1)).call(OPAQUE).ret().label("plain").ret())
    assert not _complete(helper)


@pytest.mark.parametrize("leave", ("tail", "jump"))
def test_an_unresolved_continuation_after_the_restore_denies_preservation(leave):
    """Astra PE-d r1 P1-2: push rbx; rbx = 0; pop rbx; then a tail jump to an
    opaque function, or an unresolved indirect jump -- no certificate."""
    from synthetic import RDX

    helper = FunctionBuilder(entry=HELPER).push(RBX).ins(copy(reg(RBX), const(0))).pop(RBX)
    helper = helper.tail_call(OPAQUE) if leave == "tail" else helper.jump_indirect(reg(RDX))
    assert not _complete(helper)


@pytest.mark.parametrize("leave", ("tail", "jump"))
def test_an_unresolved_continuation_after_a_write_denies_must_write(leave):
    from synthetic import RDX

    source = FunctionBuilder(entry=SOURCE).ins(copy(reg(RAX, 4), const(7, 4)))
    source = source.tail_call(OPAQUE) if leave == "tail" else source.jump_indirect(reg(RDX))
    main = FunctionBuilder(entry=MAIN).call(SOURCE).ins(copy(reg(RCX, 4), reg(RAX, 4))).call(SINK).ret()
    functions = {"main": main, "source": source, "sink": FunctionBuilder(entry=SINK).ret()}
    assert not analyze_program(functions, PROVIDER)[("main", "sink.arg0")].is_effectively_complete


@pytest.mark.parametrize("depth, certified", ((5, True), (40, False)))
def test_a_long_chain_of_keeping_callees_is_bounded(depth, certified):
    """Astra PE-d r1 P2: a chain of untouching callees deeper than the bound
    (MAX_FRAME_DEPTH) withholds the certificate instead of recursing without
    limit; a short chain is certified (control)."""
    entries = [CODE_BASE + 0x100 + 0x10 * index for index in range(depth)]   # (inside the code block)
    chain = [FunctionBuilder(entry=entry).call(entries[index + 1]).ret() if index + 1 < depth
             else FunctionBuilder(entry=entry).ret() for index, entry in enumerate(entries)]
    helper = (FunctionBuilder(entry=HELPER).push(RBX).ins(copy(reg(RBX), const(0))).pop(RBX).call(entries[0]).ret())
    assert _complete_with(helper, *chain) is certified


def test_an_untouching_callee_that_calls_an_opaque_function_keeps_nothing():
    """push rbx; rbx = 0; pop rbx; call leaf; ret with leaf: call opaque; ret --
    the leaf never writes RBX, but its own opaque call may: no certificate."""
    helper = (FunctionBuilder(entry=HELPER).push(RBX).ins(copy(reg(RBX), const(0))).pop(RBX).call(LEAF).ret())
    assert not _complete_with(helper, FunctionBuilder(entry=LEAF).call(OPAQUE).ret())


class _ListedJump(FunctionBuilder):
    """Its BRANCHIND lists the next instruction, a local ``ret`` (a jump table
    inside the function), and also an address outside it (``outside``)."""

    outside = False

    def to_json(self):
        document = super().to_json()
        rows = document["instructions"]
        for index, row in enumerate(rows):
            if any(item["opcode"] == "BRANCHIND" for item in row["operations"]):
                local = dict(rows[index + 1]["address"])
                targets = [local]
                if self.outside:
                    targets.append({**local, "byte_offset": OPAQUE})
                row["flow_targets"] = targets
        return document


@pytest.mark.parametrize("outside", (False, True))
def test_a_jump_table_inside_the_callee_keeps_the_certificate(outside):
    """Fable PE-d r2 P2-1 / Astra r3 P3: a BRANCHIND whose listed targets are
    all inside the function does not leave it (certificate kept); one listing
    the local ``ret`` and an outside target as well does (no certificate)."""
    from synthetic import RDX

    helper = _ListedJump(entry=HELPER)
    helper.outside = outside
    helper.push(RBX).ins(copy(reg(RBX), const(0))).pop(RBX).jump_indirect(reg(RDX))
    helper.ret()
    assert _complete(helper) is (not outside)


INNER, WRITER = CODE_BASE + 0x880, CODE_BASE + 0x8C0


@pytest.mark.parametrize("inner_shape", ("ret", "tail", "conditional_tail"))
def test_a_tail_jump_in_an_inner_call_voids_the_frame_proof(inner_shape):
    """Astra PE-d r2 P1-2 / r3 P3: push rbx; call inner; rbx = 0; pop rbx; ret
    with inner returning (certificate), tail-jumping to a writer of [rsp + 8]
    always, or on one path while the other returns -- the saved copy may be
    overwritten: no certificate. The conditional inner keeps a return token,
    so its frame is built and only the open-control check refuses it."""
    from synthetic import R8, ZF, add, store, tmp

    t = tmp(0x100)
    helper = FunctionBuilder(entry=HELPER).push(RBX).call(INNER).ins(copy(reg(RBX), const(0)))
    helper = helper.pop(RBX).ret()
    inner = FunctionBuilder(entry=INNER).ins(copy(reg(RCX), const(1)))   # (no pure thunk)
    if inner_shape == "conditional_tail":
        inner = inner.cbranch("leave", reg(ZF, 1)).ret().label("leave").tail_call(WRITER)
    else:
        inner = inner.ret() if inner_shape == "ret" else inner.tail_call(WRITER)
    writer = FunctionBuilder(entry=WRITER).ins(add(t, reg(RSP), const(8)), store(t, reg(R8))).ret()
    assert _complete_with(helper, inner, writer) is (inner_shape == "ret")


def test_a_recorded_fallthrough_exit_is_open_control():
    """Astra PE-d r2 P1-1: a row whose fallthrough leaves the function (a
    recorded ``fallthrough_exits`` row) -- the exit check does not model what
    runs after it."""
    from types import SimpleNamespace
    from tdo_v2.integration.configured_call_clobber_discharge import CallClobberDischarger

    discharger = CallClobberDischarger.__new__(CallClobberDischarger)
    discharger._open_control_cache = {}
    observation = SimpleNamespace(instructions=(), fallthrough_exits=(object(),))
    from tdo_v2._scope_contracts import AddressCoordinate
    import tdo_v2.pcode_blocks as blocks

    entry = AddressCoordinate(1, 0x1000)
    view = SimpleNamespace(analysis=SimpleNamespace(evidence=SimpleNamespace(unit=SimpleNamespace(
        observation=observation, scopes=SimpleNamespace(function=SimpleNamespace(entry=entry))))), operations={})
    import tdo_v2.interprocedural as ip
    original, original_exits = ip._tail_jumps, blocks.control_exits
    try:
        ip._tail_jumps = lambda unit: frozenset()
        blocks.control_exits = lambda observation, entry: SimpleNamespace(non_return_exits=(), may_leave={})
        assert discharger._open_control(entry, view)
        discharger._open_control_cache.clear()
        observation.fallthrough_exits = ()
        assert not discharger._open_control(entry, view)
    finally:
        ip._tail_jumps = original
        blocks.control_exits = original_exits


@pytest.mark.parametrize("long_first", (True, False))
def test_the_depth_cut_does_not_depend_on_root_order(long_first):
    """Astra PE-d r2 P2-1 / r3 P2-4: a root over a chain deeper than the bound
    and a root over a short part of the same chain: the short one is certified
    and the long one is not, whichever is decided first (results resting on
    the cut are not memoized; a cut False is reused only with no more budget)."""
    depth = 18
    entries = [CODE_BASE + 0x100 + 0x10 * index for index in range(depth)]
    chain = [FunctionBuilder(entry=entry).call(entries[index + 1]).ret() if index + 1 < depth
             else FunctionBuilder(entry=entry).ret() for index, entry in enumerate(entries)]
    long_helper = (FunctionBuilder(entry=HELPER).push(RBX).ins(copy(reg(RBX), const(0))).pop(RBX)
                   .call(entries[0]).ret())
    short_helper = (FunctionBuilder(entry=LEAF).push(RBX).ins(copy(reg(RBX), const(0))).pop(RBX)
                    .call(entries[15]).ret())   # (the node just above the cut)
    second = CODE_BASE + 0x600

    def root_function(entry, helper):
        return (FunctionBuilder(entry=entry).call(SOURCE).ins(copy(reg(RBX, 4), reg(RAX, 4))).call(helper)
                .ins(copy(reg(RCX, 4), reg(RBX, 4))).call(SINK).ret())

    first, then = (HELPER, LEAF) if long_first else (LEAF, HELPER)
    rest = {"source": _source(), "helper": long_helper, "short": short_helper, "sink": FunctionBuilder(entry=SINK).ret(),
            **{f"c{i}": body for i, body in enumerate(chain)}}
    functions = {"main": root_function(MAIN, first), "second": root_function(second, then), **rest}
    if not long_first:
        functions = {"second": functions["second"], "main": functions["main"], **rest}
    roots = analyze_program(functions, PROVIDER)
    long_root, short_root = ("main", "second") if long_first else ("second", "main")
    assert not roots[(long_root, "sink.arg0")].is_effectively_complete   # (beyond the bound: withheld)
    assert roots[(short_root, "sink.arg0")].is_effectively_complete


# -- Astra PE-d r3 complete list ---------------------------------------------------------------

@pytest.mark.parametrize("shape", ("ret", "tail", "conditional_tail", "conditional_override"))
def test_an_outparam_writer_with_a_tail_is_no_must_write(shape):
    """Astra r3 P1-3: the writer stores EDX through RCX, then returns (complete),
    or tail-jumps to another store through RCX -- always, or on one path while
    the other returns (no OUTPARAM_MUST_WRITTEN). The conditional shapes keep a
    return token, so the frame is built and only the open-control check of
    the out-parameter route refuses them."""
    import test_outparam_discharge as out
    from synthetic import R8, RDX, ZF, store

    builder = _OverrideBranch if shape == "conditional_override" else FunctionBuilder
    writer = builder(entry=out.WRITER).ins(store(reg(RCX), reg(RDX, 4)))
    other = FunctionBuilder(entry=out.OTHER).ins(store(reg(RCX), reg(R8, 4))).ret()
    if shape.startswith("conditional"):
        writer = writer.cbranch("leave", reg(ZF, 1)).ret().label("leave").tail_call(out.OTHER)
    else:
        writer = writer.ret() if shape == "ret" else writer.tail_call(out.OTHER)
    functions = {"main": out._main(before=(out._source_into_rdx,)), "source": out._source(),
                 "source2": out._source(out.SOURCE2), "writer": writer, "other": other,
                 "sink": FunctionBuilder(entry=out.SINK).ret()}
    provider = boundary({"source": 4, "source2": 4}, {"sink": 4}, assume_call_effect=True)
    root = analyze_program(functions, provider, assume_boundary_call_effects=True)[("main", "sink.arg0")]
    assert root.is_effectively_complete is (shape == "ret")


class _OverrideBranch(FunctionBuilder):
    """Its terminal jump to another function is an override branch (Ghidra's
    flow override), which ``_tail_jumps`` does not take for a tail."""

    def to_json(self):
        document = super().to_json()
        for row in document["instructions"]:
            if row["flow_type"].get("is_call") and row["flow_type"].get("is_terminal"):
                row["flow_type"]["is_override"] = True
        return document


WRITES_RBX = CODE_BASE + 0x8C0


@pytest.mark.parametrize("route", ("preserved", "must_write"))
def test_an_override_branch_after_the_restore_or_the_write_is_open_control(route):
    """Astra r3 P1-2: the block graph's exit facts (``control_exits``) catch a
    departure ``_tail_jumps`` leaves out."""
    writer = FunctionBuilder(entry=WRITES_RBX).ins(copy(reg(RBX), const(9)), copy(reg(RAX, 4), const(9, 4))).ret()
    if route == "preserved":
        helper = _OverrideBranch(entry=HELPER)
        helper.push(RBX).ins(copy(reg(RBX), const(0))).pop(RBX).tail_call(WRITES_RBX)
        try:
            assert not _complete_with(helper, writer)
        except Exception as error:   # (admission may refuse the shape: no certificate either)
            assert "override" in str(error).lower() or "flow" in str(error).lower(), error
        return
    source = _OverrideBranch(entry=SOURCE)
    source.ins(copy(reg(RAX, 4), const(7, 4))).tail_call(WRITES_RBX)
    main = FunctionBuilder(entry=MAIN).call(SOURCE).ins(copy(reg(RCX, 4), reg(RAX, 4))).call(SINK).ret()
    functions = {"main": main, "source": source, "writer": writer, "sink": FunctionBuilder(entry=SINK).ret()}
    try:
        assert not analyze_program(functions, PROVIDER)[("main", "sink.arg0")].is_effectively_complete
    except Exception as error:
        assert "override" in str(error).lower() or "flow" in str(error).lower(), error


@pytest.mark.parametrize("conditional", (False, True))
def test_a_replacement_write_must_hold_on_every_exit(conditional):
    """Astra r3 P1-1: helper: eax = source() + 1; [if (zf) eax = [rsi]]; ret --
    the replacement route needs the write to be the sole terminal value."""
    from synthetic import RSI, ZF, add, load

    helper = (FunctionBuilder(entry=HELPER).sub_rsp(0x28).call(SOURCE)
              .ins(add(reg(RAX, 4), reg(RAX, 4), const(1, 4))))
    if conditional:
        helper.cbranch("done", reg(ZF, 1)).ins(load(reg(RAX, 4), reg(RSI))).label("done")
    helper.add_rsp(0x28).ret()
    main = FunctionBuilder(entry=MAIN).call(HELPER).ins(copy(reg(RCX, 4), reg(RAX, 4))).call(SINK).ret()
    functions = {"main": main, "source": _source(), "helper": helper, "sink": FunctionBuilder(entry=SINK).ret()}
    assert analyze_program(functions, PROVIDER)[("main", "sink.arg0")].is_effectively_complete is (not conditional)


def test_a_cut_false_is_reused_only_with_no_more_budget():
    """Astra r3 P2-4 / Fable r3 P2-1, the cache contract itself: a False that a
    guard decided is kept with its budget; the same question in the same
    context is answered from it with no more budget, and computed again with
    more; an answer with no cut below it is memoized; a question met again
    while being answered (a cycle) is a cut False."""
    from tdo_v2.integration.configured_call_clobber_discharge import CallClobberDischarger

    discharger = CallClobberDischarger.__new__(CallClobberDischarger)
    discharger._cut_events, discharger._cut_budgets = 0, {}
    cache, calls, active = {}, [], (("caller", "read"),)

    def cut():
        calls.append("cut")
        discharger._cut_events += 1   # (a guard below decided)
        return False

    def proved():
        calls.append("proved")
        return True

    assert discharger._cached("keeps", cache, "q", 3, active, cut) is False
    assert "q" not in cache   # (resting on a cut: not memoized)
    assert discharger._cached("keeps", cache, "q", 3, active, proved) is False   # (no more budget: reused)
    assert discharger._cached("keeps", cache, "q", 2, active, proved) is False
    assert calls == ["cut"]
    assert discharger._cached("keeps", cache, "q", 4, (("other", "read"),), proved) is True   # (another context)
    del cache["q"]
    assert discharger._cached("keeps", cache, "q", 4, active, proved) is True   # (more budget: computed again)
    assert calls == ["cut", "proved", "proved"] and cache["q"] is True
    assert discharger._cached("keeps", cache, "q", 1, active, cut) is True   # (memoized: no cut below it)

    def cycle():
        return discharger._cached("keeps", cache, "loop", 5, active, cycle)

    before = discharger._cut_events
    assert discharger._cached("keeps", cache, "loop", 5, active, cycle) is False
    assert discharger._cut_events > before and "loop" not in cache


@pytest.mark.parametrize("long_first", (True, False))
def test_a_frame_proof_cut_does_not_depend_on_root_order(long_first):
    """Astra r3 P2-4, second case: a saved copy across a call (push rbx; call cK;
    rbx = 0; pop rbx; ret) needs the frame proof of the whole chain below cK.
    The long root (from c0) is cut at the depth bound; the short root calls
    c13 with its slot at the same offset in c13's frame as on the long chain
    (sub rsp, 8 * 13), so it asks the very frame question the long root
    answered False under the cut. Short complete, long not, in both orders
    (on e69a30b the memoized cut False failed the short root)."""
    depth, short_at = 18, 13
    entries = [CODE_BASE + 0x100 + 0x10 * index for index in range(depth)]
    chain = [FunctionBuilder(entry=entry).call(entries[index + 1]).ret() if index + 1 < depth
             else FunctionBuilder(entry=entry).ret() for index, entry in enumerate(entries)]
    long_helper = (FunctionBuilder(entry=HELPER).push(RBX).call(entries[0]).ins(copy(reg(RBX), const(0)))
                   .pop(RBX).ret())
    short_helper = (FunctionBuilder(entry=LEAF).push(RBX).sub_rsp(8 * short_at).call(entries[short_at])
                    .ins(copy(reg(RBX), const(0))).add_rsp(8 * short_at).pop(RBX).ret())
    second = CODE_BASE + 0x600

    def root_function(entry, helper):
        return (FunctionBuilder(entry=entry).call(SOURCE).ins(copy(reg(RBX, 4), reg(RAX, 4))).call(helper)
                .ins(copy(reg(RCX, 4), reg(RBX, 4))).call(SINK).ret())

    first, then = (HELPER, LEAF) if long_first else (LEAF, HELPER)
    rest = {"source": _source(), "helper": long_helper, "short": short_helper, "sink": FunctionBuilder(entry=SINK).ret(),
            **{f"c{i}": body for i, body in enumerate(chain)}}
    functions = {"main": root_function(MAIN, first), "second": root_function(second, then), **rest}
    if not long_first:
        functions = {"second": functions["second"], "main": functions["main"], **rest}
    roots = analyze_program(functions, PROVIDER)
    long_root, short_root = ("main", "second") if long_first else ("second", "main")
    assert not roots[(long_root, "sink.arg0")].is_effectively_complete
    assert roots[(short_root, "sink.arg0")].is_effectively_complete
