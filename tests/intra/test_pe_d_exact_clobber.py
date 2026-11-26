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
    """Its BRANCHIND lists the next instruction (a jump table inside the
    function), or an address outside it (``outside``)."""

    outside = False

    def to_json(self):
        document = super().to_json()
        rows = document["instructions"]
        for index, row in enumerate(rows):
            if any(item["opcode"] == "BRANCHIND" for item in row["operations"]):
                target = dict(rows[index + 1]["address"])
                if self.outside:
                    target["byte_offset"] = OPAQUE
                row["flow_targets"] = [target]
        return document


@pytest.mark.parametrize("outside", (False, True))
def test_a_jump_table_inside_the_callee_keeps_the_certificate(outside):
    """Fable PE-d r2 P2-1: a BRANCHIND whose listed targets are all inside the
    function does not leave it (certificate kept); one listing an outside
    target does (no certificate)."""
    from synthetic import RDX

    helper = _ListedJump(entry=HELPER)
    helper.outside = outside
    helper.push(RBX).ins(copy(reg(RBX), const(0))).pop(RBX).jump_indirect(reg(RDX))
    helper.ret()
    try:
        complete = _complete(helper)
    except Exception as error:   # (a shape admission refuses is no certificate either)
        assert outside, error
        return
    assert complete is (not outside)


INNER, WRITER = CODE_BASE + 0x880, CODE_BASE + 0x8C0


def test_a_tail_jump_in_an_inner_call_voids_the_frame_proof():
    """Astra PE-d r2 P1-2: push rbx; call inner; pop rbx; ret with inner tail-jumping
    to a writer of [rsp + 8] -- the saved copy may be overwritten: no certificate."""
    from synthetic import R8, add, store, tmp

    t = tmp(0x100)
    helper = FunctionBuilder(entry=HELPER).push(RBX).call(INNER).ins(copy(reg(RBX), const(0)))
    helper = helper.pop(RBX).ret()
    inner = FunctionBuilder(entry=INNER).ins(copy(reg(RCX), const(1))).tail_call(WRITER)   # (no pure thunk)
    writer = FunctionBuilder(entry=WRITER).ins(add(t, reg(RSP), const(8)), store(t, reg(R8))).ret()
    assert not _complete_with(helper, inner, writer)


def test_a_recorded_fallthrough_exit_is_open_control():
    """Astra PE-d r2 P1-1: a row whose fallthrough leaves the function (a
    recorded ``fallthrough_exits`` row) -- the exit check does not model what
    runs after it."""
    from types import SimpleNamespace
    from tdo_v2.integration.configured_call_clobber_discharge import CallClobberDischarger

    discharger = CallClobberDischarger.__new__(CallClobberDischarger)
    discharger._open_control_cache = {}
    observation = SimpleNamespace(instructions=(), fallthrough_exits=(object(),))
    view = SimpleNamespace(analysis=SimpleNamespace(evidence=SimpleNamespace(unit=SimpleNamespace(
        observation=observation, scopes=None))), operations={})
    from tdo_v2._scope_contracts import AddressCoordinate

    entry = AddressCoordinate(1, 0x1000)
    import tdo_v2.interprocedural as ip
    original = ip._tail_jumps
    try:
        ip._tail_jumps = lambda unit: frozenset()
        assert discharger._open_control(entry, view)
        discharger._open_control_cache.clear()
        observation.fallthrough_exits = ()
        assert not discharger._open_control(entry, view)
    finally:
        ip._tail_jumps = original


def test_the_depth_cut_does_not_depend_on_root_order():
    """Astra PE-d r2 P2-1: a root over a chain deeper than the bound, decided
    first, must not leave a later root over a short part of the same chain
    uncertified (results resting on the cut are not memoized)."""
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

    functions = {"main": root_function(MAIN, HELPER), "second": root_function(second, LEAF), "source": _source(),
                 "helper": long_helper, "short": short_helper, "sink": FunctionBuilder(entry=SINK).ret(),
                 **{f"c{i}": body for i, body in enumerate(chain)}}
    roots = analyze_program(functions, PROVIDER)
    assert not roots[("main", "sink.arg0")].is_effectively_complete   # (beyond the bound: withheld)
    assert roots[("second", "sink.arg0")].is_effectively_complete
