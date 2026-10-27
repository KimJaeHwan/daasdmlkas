"""A stack address held in the function's own private frame is not an escape
(docs 25.78): until it really leaves -- reloaded and stored elsewhere, or any
call / user op while a slot may be held -- the frame stays private, so a
frame read sees no write through an entry pointer. Loads that may read a held
slot (the slot itself, a stack-derived address, a wild or unresolved base, a
constant address without globals-disjoint-from-stack) yield stack-derived
values; such a reload is never a pre-escape value."""

import json

from synthetic import (
    NO_CALLBACKS, CODE_BASE, DATA_BASE, R9, RAX, RCX, RDI, RDX, RSP, FunctionBuilder, add, const, copy, load,
    program_units, reg, store, tmp,
)
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import load_external_models

GET, TOUCH = CODE_BASE + 0xE00, CODE_BASE + 0xE10
T, T2 = tmp(0x100), tmp(0x108)
ENTRIES = [
    {"name": "Get", "registers": [{"write": [RAX, 8], "from": [[RCX, 8]],
                                   "loads": [{"base": [RCX, 8], "disp": 0, "size": 8}]}],
     "memory": [], **NO_CALLBACKS, "other_memory": "preserved", "observes": [[RCX, 8]]},
    {"name": "Touch", "registers": [], "memory": [], **NO_CALLBACKS, "other_memory": "preserved", "observes": []},
]


def _analyze(tmp_path, builder, **options):
    raw = {"format_version": 1, "kind": "declared", "id": "held-test", "version": 1,
           "language_id": "x86:LE:64:default", "abi_tag": "win64", "stack_pointer": [RSP, 8], "stack_delta": 8,
           "preserved": [[24, 8], [40, 8], [48, 8], [56, 8]], "entries": ENTRIES}
    path = tmp_path / "held.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    image = ImageInfo("synthetic", (), tuple(
        ImportedSymbol("CORE", name, None, (), ((1, thunk),)) for name, thunk in (("Get", GET), ("Touch", TOUCH))),
        (), ())
    return analyze_units(program_units(builder), image_info=image,
                         external_models=load_external_models([path], "x86:LE:64:default", "win64"),
                         **options)["1:1000"]


def _key(builder, index, ordinal, opcode):
    return f"1:{builder.entry + builder.stride * index:x}:{ordinal}:{opcode}"


def _frame_write_reaches_entry_read(analyzed, builder) -> bool:
    """The write through rcx among the may-alias writers of the frame read
    (``_tail``)."""
    rows = builder._rows
    write = next(_key(builder, index, 0, "STORE") for index, row in enumerate(rows) if row.ops[-1][0] == "STORE"
                 and row.ops[-1][1][-1] == reg(RDI))
    read = _key(builder, len(rows) - 3, 1, "LOAD")
    return any(write in row.writers for row in analyzed.normalized.may_alias_reads if row.operation_key == read)


def _spill(builder):
    """[rsp + 8] = rsp + 0x20: a frame address held in the frame."""
    return builder.ins(add(T, reg(RSP), const(0x20)), add(T2, reg(RSP), const(8)), store(T2, T))


def _tail(builder):
    """[rcx] = rdi (a write through an entry pointer); r9 = [rsp + 0x18] (a frame read)."""
    return (builder.ins(store(reg(RCX), reg(RDI)))
            .ins(add(T2, reg(RSP), const(0x18)), load(reg(R9), T2)).add_rsp(0x28).ret())


def test_a_frame_address_held_in_the_frame_keeps_the_frame_private(tmp_path):
    builder = _tail(_spill(FunctionBuilder().sub_rsp(0x28)))
    assert not _frame_write_reaches_entry_read(_analyze(tmp_path, builder), builder)


def test_reloaded_and_stored_to_a_global_it_escapes(tmp_path):
    builder = _spill(FunctionBuilder().sub_rsp(0x28))
    builder.ins(add(T2, reg(RSP), const(8)), load(reg(RDX), T2)).ins(store(const(DATA_BASE + 0x40), reg(RDX)))
    builder = _tail(builder)
    assert _frame_write_reaches_entry_read(_analyze(tmp_path, builder), builder)


def test_a_write_after_a_held_store_is_private_as_before(tmp_path):
    """The write side keeps the held store as its escape (as before docs
    25.78): [rsp + 0x18] = rdi after the spill is a private frame write
    although the later Touch() escapes (x86-32 pushes a stack argument, then
    calls -- every write before the call would otherwise reach an escape)."""
    builder = _spill(FunctionBuilder().sub_rsp(0x28))
    write = _key(builder, len(builder._rows), 1, "STORE")
    builder.ins(add(T2, reg(RSP), const(0x18)), store(T2, reg(RDI))).call(TOUCH).add_rsp(0x28).ret()
    analyzed = _analyze(tmp_path, builder)
    assert write in {key for key, _ in analyzed.normalized.private_frame_writes}


def test_a_call_while_a_slot_is_held_escapes(tmp_path):
    """A callee reads its caller's frame through its own stack pointer."""
    builder = _tail(_spill(FunctionBuilder().sub_rsp(0x28)).call(TOUCH))
    assert _frame_write_reaches_entry_read(_analyze(tmp_path, builder), builder)


def test_a_reloaded_held_address_stored_elsewhere_escapes(tmp_path):
    """rdx = [rsp + 8] (the held slot) stored to a global -> escape."""
    builder = _spill(FunctionBuilder().sub_rsp(0x28))
    builder.ins(add(T2, reg(RSP), const(8)), load(reg(RDX), T2)).ins(store(const(DATA_BASE + 0x40), reg(RDX)))
    builder = _tail(builder)
    assert _frame_write_reaches_entry_read(_analyze(tmp_path, builder), builder)


def test_an_exact_frame_load_outside_the_held_bytes_is_not_stack_derived(tmp_path):
    """rax = [rsp + 0x20] (an exactly resolved frame byte nothing holds) stored
    to a global: no escape (Fable, impl review: precision)."""
    builder = _spill(FunctionBuilder().sub_rsp(0x28))
    builder.ins(add(T2, reg(RSP), const(0x20)), load(reg(RAX), T2)).ins(store(const(DATA_BASE + 0x40), reg(RAX)))
    builder = _tail(builder)
    assert not _frame_write_reaches_entry_read(_analyze(tmp_path, builder), builder)


def test_a_store_through_a_tainted_reload_still_reaches_frame_reads(tmp_path):
    """p = Get() before the spill; rax = [p] -- a wild base may read the held
    slot (tainted); [rax] = rdi, then [rsp + 0x18] read: the store through rax
    stays a writer of the frame read -- item 1 would un-wild rax's object
    without the tainted-load exclusion (Fable, impl review)."""
    builder = FunctionBuilder().sub_rsp(0x28).call(GET).ins(copy(reg(RDX), reg(RAX)))
    builder = _spill(builder)
    builder.ins(load(reg(RAX), reg(RDX))).ins(store(reg(RAX), reg(RDI)))
    builder.ins(add(T2, reg(RSP), const(0x18)), load(reg(R9), T2)).add_rsp(0x28).ret()
    analyzed = _analyze(tmp_path, builder)
    rows = builder._rows
    write = _key(builder, len(rows) - 4, 0, "STORE")
    read = _key(builder, len(rows) - 3, 1, "LOAD")
    assert any(write in row.writers for row in analyzed.normalized.may_alias_reads if row.operation_key == read)


def test_a_load_through_a_wild_base_while_held_is_stack_derived(tmp_path):
    """p = Get() before the spill (a wild base that may reach the held slot):
    [p] stored to a global -> escape (Astra)."""
    builder = FunctionBuilder().sub_rsp(0x28).call(GET).ins(copy(reg(RDX), reg(RAX)))
    builder = _spill(builder)
    builder.ins(load(reg(RAX), reg(RDX))).ins(store(const(DATA_BASE + 0x40), reg(RAX)))
    builder = _tail(builder)
    assert _frame_write_reaches_entry_read(_analyze(tmp_path, builder), builder)


def test_a_constant_address_load_needs_globals_disjoint(tmp_path):
    """[K] -- K might be the held slot unless globals-disjoint-from-stack."""
    def build():
        builder = _spill(FunctionBuilder().sub_rsp(0x28))
        builder.ins(load(reg(RAX), const(DATA_BASE + 0x80))).ins(store(const(DATA_BASE + 0x40), reg(RAX)))
        return _tail(builder)
    builder = build()
    assert _frame_write_reaches_entry_read(_analyze(tmp_path, builder), builder)
    builder = build()
    assert not _frame_write_reaches_entry_read(
        _analyze(tmp_path, builder, assume_globals_disjoint_from_stack=True), builder)


def test_a_reload_of_a_held_slot_is_a_tainted_load(tmp_path, monkeypatch):
    """rdx = [rsp + 8] reloads the held frame address: the taint pass marks it
    (``_Escape.tainted_loads``), so item 1 never takes it as a value no escape
    precedes (Fable); the escapes of the final normalization show it."""
    from tdo_v2.may_alias import _stack_escapes

    monkeypatch.setenv("TDO_V2_FORWARD", "1")   # (the normalization keeps its escape inputs)
    builder = _spill(FunctionBuilder().sub_rsp(0x28))
    builder.ins(add(T2, reg(RSP), const(8)), load(reg(RDX), T2))
    builder = _tail(builder)
    analyzed = _analyze(tmp_path, builder)
    reload = _key(builder, 2, 1, "LOAD")
    inputs = analyzed.normalized.forward_inputs
    _, escape, _, _ = _stack_escapes(
        inputs.effect_unit, inputs.observation, inputs.context, inputs.address_spaces, inputs.quiet_calls,
        dict(inputs.observed_calls), inputs.escaping_calls, inputs.opaque_calls,
        held=(inputs.assumed_calls, frozenset(), inputs.wild_objects, inputs.private_frame_above,
              inputs.assume_globals_disjoint_from_stack))
    assert reload in escape.tainted_loads and escape.private_read(reload)
    assert reload not in analyzed.normalized.pre_escape_definitions


def test_a_conditional_exit_while_held_escapes(tmp_path):
    """A conditional jump out of the function (to code that can read the
    held slot through its stack pointer) is an escape (Astra)."""
    from synthetic import op, ram

    flag = tmp(0x300, 1)
    builder = _spill(FunctionBuilder().sub_rsp(0x28))
    builder.ins(op("INT_EQUAL", [reg(RDX), const(0)], flag), op("CBRANCH", [ram(CODE_BASE + 0x900), flag]))
    builder = _tail(builder)
    assert _frame_write_reaches_entry_read(_analyze(tmp_path, builder), builder)
