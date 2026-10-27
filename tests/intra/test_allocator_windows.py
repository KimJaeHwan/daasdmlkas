"""Allocator size contracts (docs 25.79): a fresh row's size, proven at the
call, gives the calling function a nonstack window [p, p + size) -- but a
nullable allocator's only where a null test of p dominates the access
(register-only chain, two distinct successors, the non-null side entered only
from the test); a never_null entry (a declared, switchable assumption) needs
none. Pre-escape-values is off here so only the window keeps the push apart."""

import json

import pytest

import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    NO_CALLBACKS, CODE_BASE, DATA_BASE, R9, RAX, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const,
    copy, load, op, program_units, ram, reg, store, tmp,
)
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import ModelError, load_external_models

ALLOC, ALLOC_NN, CALLOC, TOUCH, RESIZE = (CODE_BASE + 0xE00 + 0x10 * index for index in range(5))
NEVER_NULL = "alloc-test:never-null"
T, FLAG = tmp(0x100), tmp(0x300, 1)


def _entries():
    fresh = {"write": [RAX, 8], "from": [], "fresh": True, "extent": {"reg": [RCX, 8]}}
    return [
        {"name": "Alloc", "registers": [fresh], "memory": [], **NO_CALLBACKS, "other_memory": "preserved",
         "observes": []},
        {"name": "AllocNN", "registers": [fresh], "memory": [], **NO_CALLBACKS, "other_memory": "preserved",
         "observes": [], "never_null": {"rests_on": NEVER_NULL}},
        {"name": "Calloc", "registers": [{**fresh, "extent": {"product": [[RCX, 8], [RDX, 8]]}}], "memory": [],
         **NO_CALLBACKS, "other_memory": "preserved", "observes": []},
        {"name": "Touch", "registers": [], "memory": [], **NO_CALLBACKS, "other_memory": "preserved",
         "observes": []},
        {"name": "Resize", "registers": [{"write": [RAX, 8], "from": [[RCX, 8], [RDX, 8]],
                                          "same_object_as": [RCX, 8]}], "memory": [], **NO_CALLBACKS,
         "other_memory": "preserved", "observes": [[RCX, 8]]},
    ]


def _models(tmp_path, entries=None):
    raw = {"format_version": 1, "kind": "declared", "id": "alloc-test", "version": 1,
           "language_id": "x86:LE:64:default", "abi_tag": "win64", "stack_pointer": [RSP, 8], "stack_delta": 8,
           "preserved": [[24, 8], [40, 8], [48, 8], [56, 8]], "entries": entries or _entries(),
           "declares_assumptions": [{"id": "never-null", "statement": "AllocNN never returns null.",
                                     "fails_when": "It does."}]}
    path = tmp_path / "alloc.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return load_external_models([path], "x86:LE:64:default", "win64")


def _analyze(tmp_path, builder, entries=None, **options):
    image = ImageInfo("synthetic", (), tuple(
        ImportedSymbol("CORE", name, None, (), ((1, thunk),))
        for name, thunk in (("Alloc", ALLOC), ("AllocNN", ALLOC_NN), ("Calloc", CALLOC), ("Touch", TOUCH),
                            ("Resize", RESIZE))), (), ())
    return analyze_units(program_units(builder), image_info=image, external_models=_models(tmp_path, entries),
                         **{"assume_pre_escape_values_not_frame": False, **options})["1:1000"]


def _program(allocator=ALLOC, size=32, offset=8, guard=True, calloc_rdx=None, resize=None):
    """rcx = size; p = allocator(); rbx = p; [if p == 0 return;] [rbx =
    Resize(rbx, resize);] Touch() -- a push; r9 = [rbx + offset]."""
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), const(size)))
    if calloc_rdx is not None:
        builder.ins(copy(reg(RDX), const(calloc_rdx)))
    builder.call(allocator).ins(copy(reg(RBX), reg(RAX)))
    if guard:
        builder.cbranch("out", FLAG, op("INT_EQUAL", [reg(RAX), const(0)], FLAG))
    if resize is not None:
        builder.ins(copy(reg(RCX), reg(RBX)), copy(reg(RDX), const(resize))).call(RESIZE).ins(copy(reg(RBX), reg(RAX)))
    builder.call(TOUCH).ins(add(T, reg(RBX), const(offset)), load(reg(R9), T))
    return builder.label("out").add_rsp(0x28).ret()


def _pushed(analyzed, builder) -> bool:
    index = next(index for index, row in enumerate(builder._rows) if row.ops and row.ops[-1][0] == "LOAD")
    key = f"1:{builder.entry + builder.stride * index:x}:1:LOAD"
    return any(writer.endswith("~push") for row in analyzed.normalized.may_alias_reads
               if row.operation_key == key for writer in row.writers)


def test_a_null_tested_block_is_kept_apart_from_the_push(tmp_path):
    builder = _program()
    analyzed = _analyze(tmp_path, builder)
    assert not _pushed(analyzed, builder)
    assert "allocator-results-are-fresh" in analyzed.normalized.nonstack_labels


def test_without_the_null_test_the_push_may_reach(tmp_path):
    builder = _program(guard=False)
    assert _pushed(_analyze(tmp_path, builder), builder)


@pytest.mark.parametrize("offset", [32, -8 & (1 << 64) - 1])
def test_an_access_outside_the_block_keeps_the_push(tmp_path, offset):
    builder = _program(offset=offset)
    assert _pushed(_analyze(tmp_path, builder), builder)


def test_a_never_null_allocator_needs_no_test_and_its_label_switches_it_off(tmp_path):
    builder = _program(allocator=ALLOC_NN, guard=False)
    analyzed = _analyze(tmp_path, builder)
    assert not _pushed(analyzed, builder)
    assert NEVER_NULL in analyzed.normalized.nonstack_labels
    builder = _program(allocator=ALLOC_NN, guard=False)
    assert _pushed(_analyze(tmp_path, builder, disabled_model_assumptions=(NEVER_NULL,)), builder)


def test_a_resized_block_keeps_no_window(tmp_path):
    """p' = Resize(p, 4) is p's object (same_object_as) but may be smaller
    than the window: the window is refused, the relation kept."""
    builder = _program(resize=4)
    assert _pushed(_analyze(tmp_path, builder), builder)


def test_a_null_test_through_memory_is_no_guard(tmp_path):
    """global = p; [rdi] = 1 (may overwrite global); rdx = global; if rdx == 0
    return: the tested value is not p's."""
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), const(32))).call(ALLOC)
    builder.ins(copy(reg(RBX), reg(RAX)), copy(ram(DATA_BASE + 0x40), reg(RAX)), store(reg(RDI), const(1)),
                copy(reg(RDX), ram(DATA_BASE + 0x40)))
    builder.cbranch("out", FLAG, op("INT_EQUAL", [reg(RDX), const(0)], FLAG))
    builder.call(TOUCH).ins(add(T, reg(RBX), const(8)), load(reg(R9), T)).label("out").add_rsp(0x28).ret()
    assert _pushed(_analyze(tmp_path, builder), builder)


def test_a_join_with_a_resized_block_keeps_no_window(tmp_path):
    """p = AllocNN(32); rbx = rsi ? Resize(p, 4) : AllocNN(32); Touch(); [rbx + 8]."""
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), const(32))).call(ALLOC_NN)
    builder.ins(copy(reg(RBX), reg(RAX)))
    builder.cbranch("other", FLAG, op("INT_EQUAL", [reg(RSI), const(0)], FLAG))
    builder.ins(copy(reg(RCX), reg(RBX)), copy(reg(RDX), const(4))).call(RESIZE).ins(copy(reg(RBX), reg(RAX)))
    builder.branch("join").label("other").ins(copy(reg(RCX), const(32))).call(ALLOC_NN)
    builder.ins(copy(reg(RBX), reg(RAX))).label("join")
    builder.call(TOUCH).ins(add(T, reg(RBX), const(8)), load(reg(R9), T)).add_rsp(0x28).ret()
    assert _pushed(_analyze(tmp_path, builder), builder)


def test_a_block_resized_in_a_loop_keeps_no_window(tmp_path):
    """p = AllocNN(32); loop: r9 = [p + 8]; Touch(); p = Resize(p, 4)."""
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), const(32))).call(ALLOC_NN)
    builder.ins(copy(reg(RBX), reg(RAX))).label("top").ins(add(T, reg(RBX), const(8)), load(reg(R9), T))
    builder.call(TOUCH).ins(copy(reg(RCX), reg(RBX)), copy(reg(RDX), const(4))).call(RESIZE)
    builder.ins(copy(reg(RBX), reg(RAX))).cbranch("top", FLAG, op("INT_EQUAL", [reg(RSI), const(0)], FLAG))
    builder.add_rsp(0x28).ret()
    assert _pushed(_analyze(tmp_path, builder), builder)


def test_an_unproven_size_gives_no_window(tmp_path):
    builder = FunctionBuilder().sub_rsp(0x28).call(ALLOC).ins(copy(reg(RBX), reg(RAX)))   # rcx: unknown
    builder.cbranch("out", FLAG, op("INT_EQUAL", [reg(RAX), const(0)], FLAG))
    builder.call(TOUCH).ins(add(T, reg(RBX), const(8)), load(reg(R9), T)).label("out").add_rsp(0x28).ret()
    assert _pushed(_analyze(tmp_path, builder), builder)


@pytest.mark.parametrize("rdx, pushed", [(4, False), (0, True), ((1 << 62), True)])
def test_calloc_takes_the_product_without_overflow(tmp_path, rdx, pushed):
    """8 * 4 = 32 bytes: [p+8] inside; 8 * 0: no window; 8 * 2^62 overflows."""
    builder = _program(allocator=CALLOC, size=8, calloc_rdx=rdx)
    assert _pushed(_analyze(tmp_path, builder), builder) is pushed


def test_allocator_results_off_gives_no_window(tmp_path):
    builder = _program()
    analyzed = _analyze(tmp_path, builder, disabled_model_assumptions=("allocator-results-are-fresh",))
    assert "allocator-results-are-fresh" not in analyzed.normalized.nonstack_labels
    assert not any("/Alloc@" in label for label in analyzed.declared.values())   # (the entry is not applied)


@pytest.mark.parametrize("change", [
    {"never_null": {"rests_on": "other:never-null"}},
    {"never_null": True},
    {"registers": [{"write": [RAX, 8], "from": [], "extent": {"reg": [RCX, 8]}}]},
    {"registers": [{"write": [RAX, 8], "from": [], "fresh": True, "extent": 0}]},
])
def test_malformed_extents_are_load_errors(tmp_path, change):
    entries = _entries()
    entries[1] = {**entries[1], **change}
    with pytest.raises(ModelError):
        _models(tmp_path, entries)


def test_the_oracle_finds_nothing_silent_with_a_real_allocator(tmp_path):
    builder = _program()
    analyzed = _analyze(tmp_path, builder)
    (alloc,) = program_units(FunctionBuilder(entry=ALLOC).ins(copy(reg(RAX), const(0x6000_0000))).ret())
    (touch,) = program_units(FunctionBuilder(entry=TOUCH).ret())
    report = check_program(analyzed.normalized, analyzed.unit.observation,
                           {(1, ALLOC): alloc.observation, (1, TOUCH): touch.observation}, seeds=range(4),
                           register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                           havoc_calls=(REG, RSP, 8))
    assert report.silent == []


def test_the_oracle_catches_an_allocator_returning_the_stack(tmp_path):
    """An "allocator" returning its caller's stack pointer (rsp + 8 at its
    entry): [p + 0x10] is the frame slot the caller wrote, inside the window
    -- the contract, not luck, kept them apart, and the oracle sees it."""
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), const(0x40))).call(ALLOC)
    builder.ins(copy(reg(RBX), reg(RAX))).cbranch("out", FLAG, op("INT_EQUAL", [reg(RAX), const(0)], FLAG))
    builder.ins(add(T, reg(RSP), const(0x10)), store(T, reg(RDI)))
    builder.ins(add(T, reg(RBX), const(0x10)), load(reg(R9), T)).label("out").add_rsp(0x28).ret()
    analyzed = _analyze(tmp_path, builder)
    assert "allocator-results-are-fresh" in analyzed.normalized.nonstack_labels
    (alloc,) = program_units(FunctionBuilder(entry=ALLOC).ins(add(reg(RAX), reg(RSP), const(8))).ret())
    report = check_program(analyzed.normalized, analyzed.unit.observation, {(1, ALLOC): alloc.observation},
                           seeds=range(4),
                           register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                           havoc_calls=(REG, RSP, 8))
    assert report.silent != []
