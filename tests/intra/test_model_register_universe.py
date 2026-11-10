"""A declared model leaves every register byte it does not list (written or
``preserved``) unknown -- across the whole program register file, not just
the bytes the calling function happens to use (docs: design r6 I-1, Astra
round 3 P1-A). A model's unknown runs were cut at the caller's own register
limit while the call effect was derived up to the program's, so a byte past
the caller's limit read as preserved; a GPR-only wrapper then exported it as
kept to its own callers (``FunctionSummary.inner_calls``)."""

import json

import pytest

from synthetic import (
    CODE_BASE, RAX, RBX, RCX, FunctionBuilder, const, copy, operation_node_at, program_units, reg, slice_from,
)
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import load_external_models

LEAF = CODE_BASE + 0xE00     # the imported, modelled function
WRAPPER = CODE_BASE          # GPR-only: calls LEAF
CALLER = CODE_BASE + 0x400   # writes a vector register, calls WRAPPER, reads it
XMM0 = 0x1200                # (Ghidra x86-64: past every GPR and flag byte)

MODEL = {
    "format_version": 1, "kind": "declared", "id": "universe-probe", "version": 1,
    "language_id": "x86:LE:64:default", "abi_tag": "win64",
    "notes": "test only: keeps RBX; every other unlisted register byte is unknown",
    "stack_pointer": [0x20, 8], "stack_delta": 8, "preserved": [[RBX, 8]],
    "entries": [{
        "name": "probe_leaf", "notes": "rax = rcx",
        "registers": [{"write": [RAX, 8], "from": [[RCX, 8]]}], "memory": [],
        "callbacks": "none", "callbacks_evidence": "test model", "frees": "none", "other_memory": "preserved",
    }],
}


def _analyze(tmp_path, *functions):
    path = tmp_path / "universe_probe.json"
    path.write_text(json.dumps(MODEL))
    image = ImageInfo("synthetic", (), (ImportedSymbol("PROBE", "probe_leaf", None, (), ((1, LEAF),)),), (), ())
    return analyze_units(program_units(*functions), image_info=image,
                         external_models=load_external_models([path], "x86:LE:64:default", "win64"))


def _wrapper():
    return FunctionBuilder().sub_rsp(0x28).call(LEAF).add_rsp(0x28).ret()


def _caller():
    """(builder, index of the instruction reading XMM0 after the call)"""
    builder = (FunctionBuilder(entry=CALLER)
               .ins(copy(reg(XMM0, 8), const(5)))
               .sub_rsp(0x28).call(WRAPPER).add_rsp(0x28))
    index = len(builder._rows)
    return builder.ins(copy(reg(RAX), reg(XMM0, 8))).ret(), index


def _bytes(spans):
    return {offset for span in spans for offset in range(span.start, span.end)}


def test_a_model_call_keeps_only_its_listed_bytes_up_to_the_program_limit(tmp_path):
    results = _analyze(tmp_path, _wrapper(), _caller()[0])
    (effect,) = results[f"1:{WRAPPER:x}"].proven.values()
    kept = _bytes(effect.preserved)
    assert set(range(RBX, RBX + 8)) <= kept
    # the wrapper never touches XMM0, but the program does: the model does not list it
    assert not kept & set(range(XMM0, XMM0 + 8))
    # every kept byte is one the model lists: preserved, written (RAX), the stack pointer
    listed = set(range(RBX, RBX + 8)) | set(range(RAX, RAX + 8)) | set(range(0x20, 0x28))
    assert kept <= listed


def test_a_model_keeps_exactly_the_vector_bytes_it_lists(tmp_path):
    # the model lists XMM0's low 8 bytes only: bytes 8..16 stay unknown
    MODEL_PARTIAL = {**MODEL, "preserved": [[RBX, 8], [XMM0, 8]]}
    path = tmp_path / "partial.json"
    path.write_text(json.dumps(MODEL_PARTIAL))
    image = ImageInfo("synthetic", (), (ImportedSymbol("PROBE", "probe_leaf", None, (), ((1, LEAF),)),), (), ())
    caller = (FunctionBuilder(entry=CALLER)
              .ins(copy(reg(XMM0, 16), const(5, 16)))
              .sub_rsp(0x28).call(WRAPPER).add_rsp(0x28))
    low = len(caller._rows)
    caller = caller.ins(copy(reg(RAX), reg(XMM0, 8)))
    high = len(caller._rows)
    caller = caller.ins(copy(reg(RCX), reg(XMM0 + 8, 8))).ret()
    results = analyze_units(program_units(_wrapper(), caller), image_info=image,
                            external_models=load_external_models([path], "x86:LE:64:default", "win64"))
    function = results[f"1:{CALLER:x}"].normalized
    assert slice_from(function, operation_node_at(function, low, 0, entry=CALLER)).is_complete
    assert not slice_from(function, operation_node_at(function, high, 0, entry=CALLER)).is_complete


def test_a_gpr_only_wrapper_does_not_export_an_unlisted_vector_byte_as_kept(tmp_path):
    caller, index = _caller()
    results = _analyze(tmp_path, _wrapper(), caller)
    function = results[f"1:{CALLER:x}"].normalized
    found = slice_from(function, operation_node_at(function, index, 0, entry=CALLER))
    assert not found.is_complete   # XMM0 after the call: unknown (the model does not keep it)



# -- the same through a derived template (the library analyzed once, its
# summary consumed by another program): the library's GPR-only F calls the
# modelled G; another library function uses XMM0, so the library's register
# limit covers it; F's template must not list XMM0 as kept by G

LIBRARY = "SYNTH.DLL"
F = CODE_BASE + 0x800
G = CODE_BASE + 0xE00          # the library's import of OTHER.DLL!G
H = CODE_BASE + 0xA00          # another library function: uses XMM0
THUNK = CODE_BASE + 0xF00      # the client's import of SYNTH.DLL!F
WIN64 = ("x86:LE:64:default", "win64")


def _hand(tmp_path):
    raw = {**MODEL, "id": "universe-hand", "libraries": ["OTHER.DLL"],
           "entries": [{**MODEL["entries"][0], "name": "G", "original_names": ["?G@@YAXXZ"]}]}
    path = tmp_path / "hand.json"
    path.write_text(json.dumps(raw))
    return path


def _derive(tmp_path, *, vector_user=True):
    from synthetic import CODE_BASE as LOW, DATA_BASE, DATA_SIZE
    from tdo_v2.image_info import ExportedSymbol
    from tdo_v2.relative_memory import ImageBaseTracking
    from tdo_v2.summary_templates import build_file

    hand = _hand(tmp_path)
    models = load_external_models([hand], *WIN64)
    info = ImageInfo("synthetic", (), (ImportedSymbol("OTHER.DLL", "G", "?G@@YAXXZ", (), ((1, G),)),),
                     (ExportedSymbol(1, F, "F", True),), ())
    library = FunctionBuilder(entry=F).sub_rsp(0x28).call(G).add_rsp(0x28).ret()
    other = FunctionBuilder(entry=H).ins(copy(reg(XMM0, 8), const(7))).ret()
    image = (LOW, DATA_BASE + DATA_SIZE)
    with ImageBaseTracking((image,), lambda address, length, value: image[0] <= value <= image[1]) as found:
        results = analyze_units(program_units(library, *((other,) if vector_user else ())), image_info=info, external_models=models,
                                own_library=LIBRARY)
    raw, refused = build_file(results, [(f"1:{F:x}", "F", ["F"])], file_id="universe-derived", version=1,
                              library=LIBRARY, external_models=models, pcodeop_models=None,
                              private_frame_above=0, base_dependent=found)
    assert not refused, refused
    path = tmp_path / "derived.json"
    path.write_text(json.dumps(raw))
    return hand, path


@pytest.mark.parametrize("vector_user", [True, False])
def test_a_derived_template_does_not_keep_an_unlisted_vector_byte(tmp_path, vector_user):
    # vector_user False: only the consumer uses XMM0 (the template's kept mask
    # leaves a byte past the producer's registers unknown)
    hand, derived = _derive(tmp_path, vector_user=vector_user)
    builder = (FunctionBuilder()
               .ins(copy(reg(XMM0, 8), const(5)))
               .sub_rsp(0x28).call(THUNK).add_rsp(0x28))
    index = len(builder._rows)
    builder = builder.ins(copy(reg(RAX), reg(XMM0, 8))).ret()
    info = ImageInfo("synthetic", (), (ImportedSymbol(LIBRARY, "F", "F", (), ((1, THUNK),)),), (), ())
    results = analyze_units(program_units(builder), image_info=info,
                            external_models=load_external_models([hand, derived], *WIN64))
    analyzed = results["1:1000"]
    assert any(label.startswith("derived-model:universe-derived/F@v1#") for label in analyzed.declared.values())
    function = analyzed.normalized
    assert not slice_from(function, operation_node_at(function, index, 0)).is_complete


def test_a_lone_tail_jump_thunk_to_a_model_keeps_no_unlisted_vector_byte(tmp_path):
    # ``jmp LEAF`` alone (no register of its own: the program's register file
    # is its fallback) -- the shape of an import thunk
    thunk = FunctionBuilder(entry=CODE_BASE + 0x200).tail_call(LEAF)
    builder = (FunctionBuilder(entry=CALLER)
               .ins(copy(reg(XMM0, 8), const(5)))
               .sub_rsp(0x28).call(CODE_BASE + 0x200).add_rsp(0x28))
    index = len(builder._rows)
    builder = builder.ins(copy(reg(RAX), reg(XMM0, 8))).ret()
    results = _analyze(tmp_path, thunk, builder)
    caller = results[f"1:{CALLER:x}"]
    assert caller.proven, "the thunk call has an effect"
    function = caller.normalized
    assert not slice_from(function, operation_node_at(function, index, 0, entry=CALLER)).is_complete
