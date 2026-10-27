"""pre-escape-values-do-not-address-the-new-frame (docs 25.77): a value the
function obtains -- loaded, or a call's plain result -- at an operation no
stack escape precedes holds no address of its new frame, nor does an access
built from such values with a displacement: private frame writes (the
CALLs' pushes) do not reach objects on it. Reported with the operations taken;
switchable; never for values after an escape, scaled addresses, realloc /
same-object values; a callee breaking it is caught by the oracle."""

import json
import sys

import pytest

import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    NO_CALLBACKS, CODE_BASE, DATA_BASE, R9, RAX, RBP, RBX, RCX, RDX, REG, RSP, FunctionBuilder, add, const, copy, load,
    op, operation_node_at, program_units, reg, slice_from, store, tmp,
)
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import load_external_models

GET, TOUCH, MOVE, CLOBBER = CODE_BASE + 0xE00, CODE_BASE + 0xE10, CODE_BASE + 0xE20, CODE_BASE + 0xE30
LABEL = "pre-escape-values-do-not-address-the-new-frame"
T, T2 = tmp(0x100), tmp(0x108)
ENTRIES = [
    # rax = [rcx]: a call result that is not the input (no same_object)
    {"name": "Get", "registers": [{"write": [RAX, 8], "from": [[RCX, 8]],
                                   "loads": [{"base": [RCX, 8], "disp": 0, "size": 8}]}],
     "memory": [], **NO_CALLBACKS, "other_memory": "preserved", "observes": [[RCX, 8]]},
    {"name": "Touch", "registers": [], "memory": [], **NO_CALLBACKS, "other_memory": "preserved", "observes": []},
    {"name": "Move", "registers": [{"write": [RAX, 8], "from": [[RCX, 8]], "same_object_as": [RCX, 8]}],
     "memory": [],
     **NO_CALLBACKS, "other_memory": "preserved", "observes": [[RCX, 8]]},
    # *rcx = a value the call makes (an out-parameter): a later load of it reads the call's own value
    {"name": "Clobber", "registers": [], "memory": [{"write": {"base": [RCX, 8], "disp": 0, "size": 8}, "from": []}],
     **NO_CALLBACKS, "other_memory": "preserved", "observes": [[RCX, 8]]},
]


def _models(tmp_path):
    raw = {"format_version": 1, "kind": "declared", "id": "pre-escape-test", "version": 1,
           "language_id": "x86:LE:64:default", "abi_tag": "win64", "stack_pointer": [RSP, 8], "stack_delta": 8,
           "preserved": [[24, 8], [40, 8], [48, 8], [56, 8]], "entries": ENTRIES}
    path = tmp_path / "pre.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return load_external_models([path], "x86:LE:64:default", "win64")


def _analyze(tmp_path, builder, **options):
    image = ImageInfo("synthetic", (), tuple(
        ImportedSymbol("CORE", name, None, (), ((1, thunk),))
        for name, thunk in (("Get", GET), ("Touch", TOUCH), ("Move", MOVE), ("Clobber", CLOBBER))), (), ())
    return analyze_units(program_units(builder), image_info=image, external_models=_models(tmp_path),
                         **options)["1:1000"]


def _read(analyzed, builder):
    """The last instruction before add_rsp / ret: (address, load)."""
    index = len(builder._rows) - 3
    return slice_from(analyzed.normalized, operation_node_at(analyzed.normalized, index, 1))


def _pushed(analyzed, builder) -> bool:
    """A CALL's push is among the may-alias writers of that read."""
    key = f"1:{builder.entry + builder.stride * (len(builder._rows) - 3):x}:1:LOAD"
    return any(writer.endswith("~push") for row in analyzed.normalized.may_alias_reads
               if row.operation_key == key for writer in row.writers)


def _loaded(*before):
    """rbx = rcx; ``before``; Clobber(rcx) -- *rcx = the call's value (an
    out-parameter); rbp = [rbx] -- a pointer loaded from memory; Touch() -- a
    push; r9 = [rbp + 0x10]."""
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), reg(RCX)))
    for row in before:
        builder.ins(*row)
    return (builder.call(CLOBBER).ins(load(reg(RBP), reg(RBX))).call(TOUCH)
            .ins(add(T, reg(RBP), const(0x10)), load(reg(R9), T)).add_rsp(0x28).ret())


def test_a_pointer_loaded_before_any_escape_is_kept_apart_from_the_push(tmp_path):
    builder = _loaded()
    analyzed = _analyze(tmp_path, builder)
    assert not _pushed(analyzed, builder)
    normalized = analyzed.normalized
    assert normalized.assumes_pre_escape_values_not_frame
    assert normalized.pre_escape_definitions


@pytest.mark.parametrize("off", [{"assume_pre_escape_values_not_frame": False},
                                 {"assume_entry_values_not_frame": False}])
def test_switched_off_the_push_may_reach_the_read(tmp_path, off):
    builder = _loaded()
    analyzed = _analyze(tmp_path, builder, **off)
    assert _pushed(analyzed, builder)
    assert not analyzed.normalized.assumes_pre_escape_values_not_frame


def test_a_pointer_loaded_after_an_escape_stays_wild(tmp_path):
    """The frame's address stored to a global first: memory may hold it."""
    builder = _loaded((add(T2, reg(RSP), const(0x10)), store(const(DATA_BASE + 0x40), T2)))
    analyzed = _analyze(tmp_path, builder)
    assert _pushed(analyzed, builder)


def test_a_result_of_a_non_escaping_call_is_kept_apart(tmp_path):
    builder = (FunctionBuilder().sub_rsp(0x28).call(GET).ins(copy(reg(RBP), reg(RAX))).call(TOUCH)
               .ins(add(T, reg(RBP), const(0x10)), load(reg(R9), T)).add_rsp(0x28).ret())
    analyzed = _analyze(tmp_path, builder)
    assert not _pushed(analyzed, builder)
    assert any(key.endswith(":CALL~0") for key in analyzed.normalized.pre_escape_definitions)


def test_a_result_of_a_non_escaping_call_keeps_the_push_when_off(tmp_path):
    builder = (FunctionBuilder().sub_rsp(0x28).call(GET).ins(copy(reg(RBP), reg(RAX))).call(TOUCH)
               .ins(add(T, reg(RBP), const(0x10)), load(reg(R9), T)).add_rsp(0x28).ret())
    analyzed = _analyze(tmp_path, builder, assume_pre_escape_values_not_frame=False)
    assert _pushed(analyzed, builder)


def test_a_result_of_a_call_given_a_frame_address_stays_wild(tmp_path):
    """rcx = rsp + 0x10 at the call: the call is an escape (it observes rcx)."""
    builder = (FunctionBuilder().sub_rsp(0x28).ins(add(reg(RCX), reg(RSP), const(0x10))).call(GET)
               .ins(copy(reg(RBP), reg(RAX))).call(TOUCH)
               .ins(add(T, reg(RBP), const(0x10)), load(reg(R9), T)).add_rsp(0x28).ret())
    analyzed = _analyze(tmp_path, builder)
    assert _pushed(analyzed, builder)


def test_a_realloc_like_value_stays_wild(tmp_path):
    """rbp = Move(Get()) -- the same object as an eligible call result: excluded."""
    builder = (FunctionBuilder().sub_rsp(0x28).call(GET).ins(copy(reg(RCX), reg(RAX))).call(MOVE)
               .ins(copy(reg(RBP), reg(RAX))).call(TOUCH)
               .ins(add(T, reg(RBP), const(0x10)), load(reg(R9), T)).add_rsp(0x28).ret())
    analyzed = _analyze(tmp_path, builder)
    assert _pushed(analyzed, builder)


def test_a_declared_same_object_result_stays_wild_even_unlowered(tmp_path, monkeypatch):
    """Move declaring same_object_as rcx without rcx among its reads: the
    relation is not lowered, yet its result is no value of the call's own
    (Astra, impl review)."""
    entries = [dict(entry) for entry in ENTRIES]
    entries[2] = {**entries[2], "registers": [{"write": [RAX, 8], "from": [], "same_object_as": [RCX, 8]}]}
    monkeypatch.setattr(sys.modules[__name__], "ENTRIES", entries)
    builder = (FunctionBuilder().sub_rsp(0x28).call(GET).ins(copy(reg(RCX), reg(RAX))).call(MOVE)
               .ins(copy(reg(RBP), reg(RAX))).call(TOUCH)
               .ins(add(T, reg(RBP), const(0x10)), load(reg(R9), T)).add_rsp(0x28).ret())
    analyzed = _analyze(tmp_path, builder)
    assert _pushed(analyzed, builder)


def test_a_scaled_index_on_a_loaded_pointer_stays_wild(tmp_path):
    builder = (FunctionBuilder().sub_rsp(0x28).call(GET).ins(copy(reg(RBP), reg(RAX))).call(TOUCH)
               .ins(op("INT_MULT", [reg(RDX), const(8)], T2))
               .ins(add(T, reg(RBP), T2), load(reg(R9), T)).add_rsp(0x28).ret())
    analyzed = _analyze(tmp_path, builder)
    assert _pushed(analyzed, builder)


def test_the_label_is_reported_by_the_run(tmp_path):
    from tdo_v2.summary_engine import run_assumptions

    builder = _loaded()
    image = ImageInfo("synthetic", (), tuple(
        ImportedSymbol("CORE", name, None, (), ((1, thunk),))
        for name, thunk in (("Get", GET), ("Touch", TOUCH), ("Move", MOVE), ("Clobber", CLOBBER))), (), ())
    results = analyze_units(program_units(builder), image_info=image, external_models=_models(tmp_path))
    assert LABEL in run_assumptions(results)


def _oracle(analyzed, getter):
    (get,) = program_units(getter)
    (touch,) = program_units(FunctionBuilder(entry=TOUCH).ret())
    return check_program(analyzed.normalized, analyzed.unit.observation,
                         {(1, GET): get.observation, (1, TOUCH): touch.observation}, seeds=range(4),
                         register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                         havoc_calls=(REG, RSP, 8))


def test_the_oracle_finds_nothing_silent_on_ordinary_runs(tmp_path):
    builder = (FunctionBuilder().sub_rsp(0x28).call(GET).ins(copy(reg(RBP), reg(RAX))).call(TOUCH)
               .ins(add(T, reg(RBP), const(0x10)), load(reg(R9), T)).add_rsp(0x28).ret())
    analyzed = _analyze(tmp_path, builder)
    assert _oracle(analyzed, FunctionBuilder(entry=GET).ins(load(reg(RAX), reg(RCX))).ret()).silent == []


def test_the_oracle_catches_a_callee_returning_its_callers_frame(tmp_path):
    """Get returning rsp + 8 -- its caller's stack pointer at the call: the
    read [rax - 8] after Touch() is then the return address Touch's CALL
    pushed. The assumption, not luck, keeps the push out of it."""
    builder = (FunctionBuilder().sub_rsp(0x28).call(GET).ins(copy(reg(RBP), reg(RAX))).call(TOUCH)
               .ins(add(T, reg(RBP), const(-8 & (1 << 64) - 1)), load(reg(R9), T)).add_rsp(0x28).ret())
    analyzed = _analyze(tmp_path, builder)
    assert not _pushed(analyzed, builder)
    breaking = FunctionBuilder(entry=GET).ins(add(reg(RAX), reg(RSP), const(8))).ret()
    assert _oracle(analyzed, breaking).silent != []
