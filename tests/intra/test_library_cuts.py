"""Analyzing a library itself, cut at functions that have an ``internal``
model (``analyze_units(own_library=...)``): the cut function is not analyzed;
direct calls and tail jumps to it take the model, reported with
library-internal-model-cuts."""

import json
from pathlib import Path

from synthetic import (
    CODE_BASE, R9, RAX, RBX, RCX, FunctionBuilder, copy, operation_node_at, program_units, reg, slice_from,
)
from tdo_v2.image_info import ExportedSymbol, ImageInfo
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import load_external_models

HELPER = CODE_BASE + 0x800
MANGLED = "?Helper@@YA_K_K@Z"


def _models(tmp_path, internal=True):
    entry = {"name": "Helper", "original_names": [MANGLED], "registers": [{"write": [0, 8], "from": [[8, 8]]}],
             "memory": [], "other_memory": "preserved"}
    if internal:
        entry["internal"] = True
    raw = {"format_version": 1, "kind": "declared", "id": "synth", "version": 1,
           "language_id": "x86:LE:64:default", "abi_tag": "win64", "libraries": ["SYNTH.DLL"],
           "stack_pointer": [32, 8], "stack_delta": 8, "preserved": [[24, 8], [40, 8], [48, 8], [56, 8]],
           "entries": [entry]}
    path = Path(tmp_path) / "synth.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return load_external_models([path], "x86:LE:64:default", "win64")


def _helper():
    """The real body: rax = rbx (the model says rax = rcx -- distinguishable)."""
    return FunctionBuilder(entry=HELPER).ins(copy(reg(RAX), reg(RBX))).ret()


def _analyze(tmp_path, caller, internal=True, own_library="synth.dll"):
    info = ImageInfo("synthetic", (), (), (ExportedSymbol(1, HELPER, MANGLED, True),), ())
    return analyze_units(program_units(caller, _helper()), image_info=info,
                         external_models=_models(tmp_path, internal), own_library=own_library)


def _caller():
    return (FunctionBuilder().sub_rsp(0x28)
            .call(HELPER)
            .ins(copy(reg(R9), reg(RAX)))                                                    # instruction 2
            .add_rsp(0x28).ret())


def test_a_call_to_an_internal_model_is_cut(tmp_path):
    results = _analyze(tmp_path, _caller())
    assert f"1:{HELPER:x}" not in results          # the body is not analyzed
    caller = results["1:1000"]
    assert list(caller.declared.values()) == ["external-model:synth/Helper@v1"]
    assert caller.inherited_assumptions == {"library-internal-model-cuts"}
    reload = slice_from(caller.normalized, operation_node_at(caller.normalized, 2, 0))
    assert set(range(RCX, RCX + 8)) <= reload.register_bytes          # the model's rax = rcx
    assert not set(range(RBX, RBX + 8)) & reload.register_bytes


def test_without_internal_or_outside_the_library_nothing_is_cut(tmp_path):
    for internal, own in ((False, "synth.dll"), (True, "other.dll"), (True, None)):
        results = _analyze(tmp_path, _caller(), internal=internal, own_library=own)
        assert f"1:{HELPER:x}" in results and not results["1:1000"].declared
        reload = slice_from(results["1:1000"].normalized, operation_node_at(results["1:1000"].normalized, 2, 0))
        assert set(range(RBX, RBX + 8)) <= reload.register_bytes     # the real body


def test_a_tail_jump_to_an_internal_model_is_cut(tmp_path):
    """wrapper: jmp Helper; the program's other function calls it normally
    (the call shapes say which register is the stack pointer)."""
    wrapper_entry = CODE_BASE + 0xA00
    wrapper = FunctionBuilder(entry=wrapper_entry).tail_call(HELPER)
    info = ImageInfo("synthetic", (), (), (ExportedSymbol(1, HELPER, MANGLED, True),), ())
    results = analyze_units(program_units(_caller(), wrapper, _helper()), image_info=info,
                            external_models=_models(tmp_path), own_library="SYNTH.DLL")
    assert f"1:{HELPER:x}" not in results
    tail = results[f"1:{wrapper_entry:x}"]
    assert list(tail.declared.values()) == ["external-model:synth/Helper@v1"]
    assert tail.summary is not None and not tail.summary.tail_exits     # composed through the model
    # a thunk touching no memory: the model's clobbering below its stack pointer
    # reaches nothing tracked (``normalize._stackless_tail_bounds``)
    assert all(keeps for _, _, keeps, _ in tail.summary.inner_calls)


def test_an_indirect_call_with_a_constant_cut_target_takes_the_model(tmp_path):
    """rdx = &Helper; call rdx: the constant target is a cut function -- the call
    takes its model like a direct call (Fable, step-2 review)."""
    from synthetic import RDX, const

    caller = (FunctionBuilder().sub_rsp(0x28)
              .ins(copy(reg(RDX), const(HELPER)))
              .call_indirect(RDX)
              .ins(copy(reg(R9), reg(RAX)))                                                  # instruction 3
              .add_rsp(0x28).ret())
    results = _analyze(tmp_path, caller)
    analyzed = results["1:1000"]
    assert list(analyzed.declared.values()) == ["external-model:synth/Helper@v1"]
    reload = slice_from(analyzed.normalized, operation_node_at(analyzed.normalized, 3, 0))
    assert set(range(RCX, RCX + 8)) <= reload.register_bytes


def test_a_thunk_moving_its_stack_pointer_gets_no_stackless_bound(tmp_path):
    """thunk: add rsp, 0x20; jmp Helper -- Helper's frame lies below the raised
    stack pointer, over the caller's bytes: a value the caller keeps at
    [rsp+0x10] may be overwritten (Astra, step-2 review)."""
    from synthetic import RBP, RSP, add, const, load, store, tmp

    thunk_entry = CODE_BASE + 0xA00
    thunk = FunctionBuilder(entry=thunk_entry).add_rsp(0x20).tail_call(HELPER)
    t = tmp(0x100)
    # the reload goes through rbp (preserved by the model), not the stack
    # pointer the thunk leaves moved
    caller = (FunctionBuilder().sub_rsp(0x48)
              .ins(copy(reg(RBP), reg(RSP)))
              .ins(add(t, reg(RBP), const(0x10)), store(t, reg(RBX)))
              .call(thunk_entry)
              .ins(add(t, reg(RBP), const(0x10)), load(reg(R9), t))                         # instruction 4
              .add_rsp(0x48).ret())
    info = ImageInfo("synthetic", (), (), (ExportedSymbol(1, HELPER, MANGLED, True),), ())
    results = analyze_units(program_units(caller, thunk, _helper()), image_info=info,
                            external_models=_models(tmp_path), own_library="SYNTH.DLL")
    function = results["1:1000"].normalized
    reload = slice_from(function, operation_node_at(function, 4, 1))
    assert not reload.is_complete
