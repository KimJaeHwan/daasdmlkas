"""Never-written bytes of the new frame (below the entry stack pointer) hold
whatever an older frame left there -- possibly a stack address (docs 25.80
R0): a value loaded from them is stack-derived, never an entry value, so an
access through it is wild and reaches the frame."""

from synthetic import R9, RAX, RDI, RSP, FunctionBuilder, add, const, load, program_units, reg, store, tmp
from tdo_v2.interprocedural import analyze_units

T = tmp(0x100)


def _key(builder, index, ordinal, opcode):
    return f"1:{builder.entry + builder.stride * index:x}:{ordinal}:{opcode}"


def _reaches(prelude) -> bool:
    """[rsp + 0x18] = 0; prelude (rax = a pointer); [rax] = rdi; r9 = [rsp + 0x18]:
    whether the write through rax is among the frame read's writers."""
    builder = FunctionBuilder().sub_rsp(0x28).ins(add(T, reg(RSP), const(0x18)), store(T, const(0, 8)))
    prelude(builder)
    write = _key(builder, len(builder._rows), 0, "STORE")
    builder.ins(store(reg(RAX), reg(RDI)))
    read = _key(builder, len(builder._rows), 1, "LOAD")
    builder.ins(add(T, reg(RSP), const(0x18)), load(reg(R9), T)).add_rsp(0x28).ret()
    analyzed = analyze_units(program_units(builder))["1:1000"]
    return any(write in row.writers for row in analyzed.normalized.may_alias_reads if row.operation_key == read)


def test_a_pointer_loaded_from_a_never_written_frame_slot_reaches_the_frame():
    assert _reaches(lambda builder: builder.ins(add(T, reg(RSP), const(0x20)), load(reg(RAX, 8), T)))


def test_a_partly_written_slot_is_still_stale():
    """[rsp + 0x20] = 1 (four bytes); rax = [rsp + 0x20] (eight)."""
    assert _reaches(lambda builder: builder.ins(add(T, reg(RSP), const(0x20)), store(T, const(1, 4)))
                    .ins(add(T, reg(RSP), const(0x20)), load(reg(RAX, 8), T)))


def test_an_entry_pointer_argument_stays_kept_out():
    """rax = rdi (an entry value): the base assumption keeps the frame private."""
    from synthetic import copy
    assert not _reaches(lambda builder: builder.ins(copy(reg(RAX), reg(RDI))))


def test_a_join_of_a_stale_and_a_written_slot_is_stale():
    """One path leaves [rsp + 0x20] alone, the other writes its two halves."""
    from synthetic import RSI, op, tmp as _tmp
    flag = _tmp(0x300, 1)

    def prelude(builder):
        builder.cbranch("skip", flag, op("INT_EQUAL", [reg(RSI), const(0)], flag))
        builder.ins(add(T, reg(RSP), const(0x20)), store(T, const(1, 4)))
        builder.ins(add(T, reg(RSP), const(0x24)), store(T, const(2, 4)))
        builder.label("skip").ins(add(T, reg(RSP), const(0x20)), load(reg(RAX, 8), T))
    assert _reaches(prelude)


def test_a_spilled_stale_value_partly_overwritten_stays_stale():
    """rax = [rsp + 0x20] (stale); [rsp + 0x10] = rax; [rsp + 0x10] = 1 (four
    bytes); rax = [rsp + 0x10] (eight: four stale bytes left)."""
    def prelude(builder):
        builder.ins(add(T, reg(RSP), const(0x20)), load(reg(RAX, 8), T))
        builder.ins(add(T, reg(RSP), const(0x10)), store(T, reg(RAX)))
        builder.ins(add(T, reg(RSP), const(0x10)), store(T, const(1, 4)))
        builder.ins(add(T, reg(RSP), const(0x10)), load(reg(RAX, 8), T))
    assert _reaches(prelude)


def test_a_callee_returning_a_stale_slot_states_no_entry_value():
    """callee: rax = [rsp - 8]; ret -- not "the caller's value of that slot"."""
    from synthetic import CODE_BASE
    callee_entry = CODE_BASE + 0x800
    callee = FunctionBuilder(entry=callee_entry).ins(add(T, reg(RSP), const(-8 & (1 << 64) - 1)),
                                                     load(reg(RAX), T)).ret()
    results = analyze_units(program_units(FunctionBuilder().call(callee_entry).ret(), callee))
    summary = results[f"1:{callee_entry:x}"].summary
    assert not any(run.value is not None and run.value[0] == "same" for item in summary.exits for run in item.runs
                   if run.span.object_id.kind.value == "register_file" and run.span.start == RAX)
