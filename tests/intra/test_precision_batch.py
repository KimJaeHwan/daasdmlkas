"""The backward engine's small precision batch (docs 25.27): a LOAD through a
bare once-join atom reads each candidate place; longjmp / __stack_chk_fail
never return. (Import-slot binding reporting: test_external_models.)"""

import json
from pathlib import Path

from synthetic import (
    CODE_BASE, R8, R9, RAX, RBX, RCX, RDI, RDX, RSI, FunctionBuilder, add, const, copy, load, op, operation_node_at,
    program_units, reg, slice_from, store, tmp,
)
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import load_external_models, load_model_file

MODELS = sorted((Path(__file__).resolve().parents[2] / "models" / "external").glob("*.json"))
FLAG = tmp(0x300, 1)
T = tmp(0x100)


def _joined_load():
    """p = [rdi] (rbx: a loaded pointer -- its places have expressions only
    once definition atoms are on, so the join below becomes a once-join
    atom); [p] = A (r8d); [p+16] = B (esi); rax = rdx == 0 ? p : p + 8;
    r9d = [rax]."""
    builder = FunctionBuilder()
    builder.ins(load(reg(RBX), reg(RDI)))
    builder.ins(store(reg(RBX), reg(R8, 4)))
    builder.ins(add(T, reg(RBX), const(16)), store(T, reg(RSI, 4)))
    builder.cbranch("other", FLAG, op("INT_EQUAL", [reg(RDX), const(0)], FLAG))
    builder.ins(copy(reg(RAX), reg(RBX))).branch("join")
    builder.label("other").ins(add(reg(RAX), reg(RBX), const(8)))
    builder.label("join").ins(load(reg(R9, 4), reg(RAX)))
    return builder.ret()


def test_a_load_through_a_once_join_reads_each_candidate_place(monkeypatch):
    # in the atom stage rax's join becomes a once-join atom; the LOAD must
    # read its two candidate places (p, p+8) at every projection, never the
    # one wild index object (a later retry hides the difference in the end)
    from tdo_v2 import relative_memory

    seen = []
    original = relative_memory._Projector._candidate_expressions_for_input

    def spy(self, operation_key, varnode):
        found = original(self, operation_key, varnode)
        if found is not None and operation_key.endswith(":LOAD"):
            seen.append(tuple(self._once_join(item) for item in found))
        return found

    monkeypatch.setattr(relative_memory._Projector, "_candidate_expressions_for_input", spy)
    builder = _joined_load()
    function = analyze_units(program_units(builder))["1:1000"].normalized
    assert (False, False) in seen and (True,) not in seen
    read = slice_from(function, operation_node_at(function, len(builder._rows) - 2, 0))
    assert read.reaches(R8, 4) and not read.reaches(RSI, 4)


def test_a_store_through_a_once_join_keeps_the_atom():
    """[rax] = r9d through the join: the write's place is one of two -- it
    may land on [p] or not (no candidate is a definite overwrite), so a
    later read of [p] still reaches both A and the stored value."""
    builder = FunctionBuilder()
    builder.ins(load(reg(RBX), reg(RDI)))
    builder.ins(store(reg(RBX), reg(R8, 4)))
    builder.cbranch("other", FLAG, op("INT_EQUAL", [reg(RDX), const(0)], FLAG))
    builder.ins(copy(reg(RAX), reg(RBX))).branch("join")
    builder.label("other").ins(add(reg(RAX), reg(RBX), const(8)))
    builder.label("join").ins(store(reg(RAX), reg(RSI, 4)))
    builder.ins(load(reg(R9, 4), reg(RBX)))
    builder.ret()
    function = analyze_units(program_units(builder))["1:1000"].normalized
    read = slice_from(function, operation_node_at(function, len(builder._rows) - 2, 0))
    assert read.reaches(R8, 4) and read.reaches(RSI, 4)


def test_a_candidate_place_rewritten_after_the_join_is_read_as_rewritten():
    """[p+16] = B, then after the join [p+8] = C (rcx): the LOAD through the
    join (p or p+8) reads A or C -- the candidate place's value at the LOAD,
    not at the join."""
    builder = FunctionBuilder()
    builder.ins(load(reg(RBX), reg(RDI)))
    builder.ins(store(reg(RBX), reg(R8, 4)))
    builder.ins(add(T, reg(RBX), const(8)), store(T, reg(RSI, 4)))
    builder.cbranch("other", FLAG, op("INT_EQUAL", [reg(RDX), const(0)], FLAG))
    builder.ins(copy(reg(RAX), reg(RBX))).branch("join")
    builder.label("other").ins(add(reg(RAX), reg(RBX), const(8)))
    builder.label("join").ins(add(T, reg(RBX), const(8)), store(T, reg(RCX, 4)))
    builder.ins(load(reg(R9, 4), reg(RAX)))
    builder.ret()
    function = analyze_units(program_units(builder))["1:1000"].normalized
    read = slice_from(function, operation_node_at(function, len(builder._rows) - 2, 0))
    assert read.reaches(R8, 4) and read.reaches(RCX, 4) and not read.reaches(RSI, 4)


def test_noreturn_models_for_longjmp_and_stack_chk_fail():
    entries = {(model.file_id, entry.name): entry for path in MODELS for model in [load_model_file(path)]
               for entry in model.entries}
    assert entries[("crt-win64", "longjmp")].noreturn and entries[("crt-win64", "longjmp")].observes == ((8, 8),)
    assert entries[("crt-sysv64", "longjmp")].noreturn and entries[("crt-sysv64", "longjmp")].observes == ((56, 8),)
    assert entries[("crt-sysv64", "__stack_chk_fail")].noreturn
    assert entries[("crt-sysv64", "__stack_chk_fail")].observes == ()


def test_a_call_of_longjmp_ends_its_path():
    thunk = CODE_BASE + 0xE00
    image = ImageInfo("synthetic", (), (ImportedSymbol("CRT", "longjmp", None, (), ((1, thunk),)),), (), ())
    builder = FunctionBuilder().sub_rsp(0x28).call(thunk).ins(copy(reg(RAX), reg(RBX))).add_rsp(0x28).ret()
    analyzed = analyze_units(program_units(builder), image_info=image,
                             external_models=load_external_models(MODELS, "x86:LE:64:default", "win64"))["1:1000"]
    (effect,) = analyzed.proven.values()
    assert effect.noreturn and analyzed.declared and next(iter(analyzed.declared.values())).startswith(
        "external-model:crt-win64/longjmp@")
