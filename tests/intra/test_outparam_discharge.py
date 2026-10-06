"""P0-3d: caller stack slots written through a pointer argument (outparam).

main: sub rsp,0x28; [prepare]; RCX = RSP+0x20; writer(); ECX = [RSP+0x20]; sink()

The slot read after ``writer`` carries call debt. It is discharged only when
an origin proof names the writer's store W, W is the writer's last write to
those bytes on every exit, no other writer store can alias them, and W's
value is fully explained (callee debt discharged; caller-provided registers
complete with reported origins).
"""

from synthetic import (
    CODE_BASE, R8, RAX, RBP, RCX, RDX, RSP, ZF,
    FunctionBuilder, add, analyze_program, boundary, const, copy, load, op, reg,
    store, tmp,
)

MAIN, SOURCE, SOURCE2, SINK, WRITER, OTHER = (
    CODE_BASE, CODE_BASE + 0x800, CODE_BASE + 0x900, CODE_BASE + 0xA00,
    CODE_BASE + 0xC00, CODE_BASE + 0xE00,
)
T = tmp(0x100)
PROVIDER = boundary({"source": 4, "source2": 4}, {"sink": 4})


def _source(entry=SOURCE):
    return (
        FunctionBuilder(entry=entry)
        .push(RBP).ins(copy(reg(RBP), reg(RSP)))
        .ins(copy(reg(RAX, 4), const(7, 4)))
        .pop(RBP).ret()
    )


def _main(*, pointer_offset=0x20, read_size=4, before=()):
    builder = FunctionBuilder(entry=MAIN).sub_rsp(0x28)
    for step in before:
        step(builder)
    return (
        builder
        .ins(add(reg(RCX), reg(RSP), const(pointer_offset)))
        .call(WRITER)
        .ins(add(T, reg(RSP), const(0x20)), load(reg(RCX, read_size), T))
        .call(SINK)
        .add_rsp(0x28)
        .ret()
    )


def _source_into_rdx(builder):
    builder.call(SOURCE).ins(copy(reg(RDX, 4), reg(RAX, 4)))


def _root(writer, *, main=None, extra=None):
    functions = {
        "main": main or _main(before=(_source_into_rdx,)),
        "source": _source(),
        "source2": _source(SOURCE2),
        "writer": writer,
        "sink": FunctionBuilder(entry=SINK).ret(),
    }
    functions.update(extra or {})
    return analyze_program(functions, PROVIDER)[("main", "sink.arg0")]


def _writer(*ops):
    builder = FunctionBuilder(entry=WRITER)
    for item in ops:
        builder.ins(*item) if isinstance(item, list) else item(builder)
    return builder.ret()


def test_outparam_from_caller_source_is_discharged():
    root = _root(_writer([store(reg(RCX), reg(RDX, 4))]))
    assert root.reached_origin_labels == ("source.ret",)
    assert not root.is_locally_complete
    assert root.is_effectively_complete


def test_outparam_constant_has_no_proof_and_stays_incomplete():
    root = _root(_writer([store(reg(RCX), const(5, 4))]), main=_main())
    assert not root.is_effectively_complete


def test_outparam_written_on_one_path_only_is_not_discharged():
    writer = (
        FunctionBuilder(entry=WRITER)
        .cbranch("out", reg(ZF, 1))
        .ins(store(reg(RCX), reg(RDX, 4)))
        .label("out")
        .ret()
    )
    assert not _root(writer).is_effectively_complete


def test_outparam_then_store_through_another_pointer_is_not_discharged():
    writer = _writer([store(reg(RCX), reg(RDX, 4))], [store(reg(R8), const(0, 4))])
    assert not _root(writer).is_effectively_complete


def test_outparam_then_call_that_writes_the_caller_slot_is_not_discharged():
    # writer entry SP = main slot - 0x28 + ... ; OTHER's entry SP = writer's - 8,
    # main's slot is writer +0x28 = OTHER +0x30.
    writer = _writer([store(reg(RCX), reg(RDX, 4))], lambda b: b.call(OTHER))
    other = (
        FunctionBuilder(entry=OTHER)
        .ins(add(T, reg(RSP), const(0x30)), store(T, const(0, 4)))
        .ret()
    )
    assert not _root(writer, extra={"other": other}).is_effectively_complete


def test_outparam_then_call_that_keeps_its_own_frame_is_discharged():
    writer = _writer([store(reg(RCX), reg(RDX, 4))], lambda b: b.call(OTHER))
    other = (
        FunctionBuilder(entry=OTHER)
        .ins(add(T, reg(RSP), const(-0x10 & 0xFFFFFFFFFFFFFFFF)), store(T, const(0, 4)))
        .ret()
    )
    assert _root(writer, extra={"other": other}).is_effectively_complete


def test_partial_coverage_is_not_discharged():
    """RCX = slot+4; writer writes 4 bytes there; main reads the slot's 8 bytes."""
    main = _main(pointer_offset=0x24, read_size=8, before=(_source_into_rdx,))
    root = _root(_writer([store(reg(RCX), reg(RDX, 4))]), main=main)
    assert not root.is_effectively_complete


def test_pointer_moved_to_another_register_stays_incomplete_in_v1():
    """writer: RAX = RCX; R8 = RDX; *(RAX) = R8.

    Sound but conservative: the proof chain does not explain this shape yet,
    so the debt stays. A future version may discharge it.
    """
    writer = _writer([copy(reg(R8, 4), reg(RDX, 4))], [copy(reg(RAX), reg(RCX))],
                     [store(reg(RAX), reg(R8, 4))])
    root = _root(writer)
    assert root.reached_origin_labels == ("source.ret",)
    assert not root.is_effectively_complete


def test_two_origin_value_is_not_claimed_complete_without_full_explanation():
    """*out = RDX + R8 where R8 comes from a second source: both must be explained."""

    def two_sources(builder):
        builder.call(SOURCE).ins(copy(reg(RDX, 4), reg(RAX, 4)))
        builder.push(RDX).call(SOURCE2).pop(RDX).ins(copy(reg(R8, 4), reg(RAX, 4)))

    writer = _writer(
        [op("INT_ADD", [reg(RDX, 4), reg(R8, 4)], reg(RAX, 4))],
        [store(reg(RCX), reg(RAX, 4))],
    )
    root = _root(writer, main=_main(before=(two_sources,)))
    if root.is_effectively_complete:
        assert set(root.reached_origin_labels) == {"source.ret", "source2.ret"}


def test_recursive_writer_is_not_discharged():
    writer = (
        FunctionBuilder(entry=WRITER)
        .ins(store(reg(RCX), reg(RDX, 4)))
        .cbranch("done", reg(ZF, 1))
        .call(WRITER)
        .label("done")
        .ret()
    )
    assert not _root(writer).is_effectively_complete
