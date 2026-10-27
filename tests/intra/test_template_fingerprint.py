"""A change of what the engine derives must bump ``ENGINE_SEMANTICS_VERSION``.

A derived template (``summary_templates``) is applied only by an engine of
the versions it records; a change that alters derived summaries without a
version bump leaves every template derived before it applied as if still
right -- it happened (docs 25.74: the push definition, §25.73, left the
shipped UE template stale). This test derives templates of fixed synthetic
library functions (the engine's main shapes, with models, cuts, accessors,
indirect calls) -- forward analysis off and on, every other ``TDO_V2_*``
switch at its default -- and compares each case with
``template_fingerprint.json``: per case the digest of its INPUT (the
synthetic program generator, the case's program, models and options) and of
its OUTPUT (template entries, the source fields a run checks, refusal
kinds; diagnostic wording and producer data excluded).

* same versions, same input, another output: FAIL -- bump
  ENGINE_SEMANTICS_VERSION (summary_templates.py), re-derive models/derived
  (docs 25.74), then refresh;
* other versions, a changed input, a new case: FAIL until refreshed.

Refresh: ``TDO_V2_REFRESH_TEMPLATE_FINGERPRINT=1`` rewrites the record and
skips -- refused while the versions are unchanged and a case with an
unchanged input has another output (the mistake this test exists for), and
while a shipped template (models/derived) records other versions. A pure
reordering of a summary's objects also changes an output: bump then too."""

import hashlib
import json
import os
from pathlib import Path

import pytest

from synthetic import (
    NO_CALLBACKS,
    CODE_BASE, DATA_BASE, DATA_SIZE, FunctionBuilder, R8, R9, RAX, RBX, RCX, RDX, RSI, RSP, add, const, copy, load,
    op, program_units, reg, store, tmp,
)
from tdo_v2.function_summary import FUNCTION_SUMMARY_VERSION
from tdo_v2.image_info import ExportedSymbol, ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.relative_memory import ImageBaseTracking
from tdo_v2.summary_store import load_external_models
from tdo_v2.summary_templates import ENGINE_SEMANTICS_VERSION, TEMPLATE_VERSION, build_file

REPO = Path(__file__).resolve().parents[2]
RECORD = Path(__file__).with_name("template_fingerprint.json")
GENERATOR = Path(__file__).with_name("synthetic.py")
WIN64 = ("x86:LE:64:default", "win64")
LIBRARY = "SYNTH.DLL"
F = CODE_BASE + 0x800       # the exported function
HELPER = CODE_BASE + 0xA00  # a library-internal callee
G, ABORT, GETOBJ = CODE_BASE + 0xF00, CODE_BASE + 0xF10, CODE_BASE + 0xF20   # import thunks
IMAGE = (CODE_BASE, DATA_BASE + DATA_SIZE)
T, T2, FLAG = tmp(0x200), tmp(0x208), tmp(0x300, 1)
SLOT = {"base": [RCX, 8], "disp": 0, "size": 8}
# what the analysed library imports (OTHER.DLL) and its own internal model
OTHER = {
    "format_version": 1, "kind": "declared", "id": "fingerprint-other", "version": 1,
    "language_id": WIN64[0], "abi_tag": WIN64[1], "libraries": ["OTHER.DLL"],
    "stack_pointer": [RSP, 8], "stack_delta": 8, "preserved": [[24, 8], [40, 8], [48, 8], [56, 8]],
    "declares_assumptions": [{"id": "obj-off-stack", "statement": "GetObj results are off the stack.",
                              "fails_when": "A stack object is returned."}],
    "entries": [
        {"name": "G", "original_names": ["?G@@YA_KPEA_K_K@Z"], "other_memory": "preserved", **NO_CALLBACKS,
         "registers": [{"write": [RAX, 8], "from": [[RCX, 8]]}],
         "memory": [{"write": {"base": [RCX, 8], "disp": 0, "size": 8}, "from": [[RDX, 8]]}]},
        {"name": "Abort", "original_names": ["?Abort@@YAXXZ"], "registers": [], "memory": [], "noreturn": True,
         "observes": [], **NO_CALLBACKS, "other_memory": "preserved"},
        {"name": "GetObj", "original_names": ["?GetObj@@YAPEAXPEAX@Z"], "other_memory": "preserved",
         **NO_CALLBACKS, "observes": [[RCX, 8]],
         "registers": [{"write": [RAX, 8], "from": [[RCX, 8]], "loads": [SLOT]}], "memory": [],
         "same_result": {"result": [RAX, 8], "inputs": [], "reads": [SLOT]},
         "result_nonstack": {"result": [RAX, 8], "extent": 0x40, "rests_on": "fingerprint-other:obj-off-stack"}},
    ]}
OWN = {
    "format_version": 1, "kind": "declared", "id": "fingerprint-own", "version": 1,
    "language_id": WIN64[0], "abi_tag": WIN64[1], "libraries": [LIBRARY],
    "stack_pointer": [RSP, 8], "stack_delta": 8, "preserved": [[24, 8], [40, 8], [48, 8], [56, 8]],
    "entries": [{"name": "H", "original_names": ["?H@@YA_K_K@Z"], "internal": True, "other_memory": "preserved",
                 **NO_CALLBACKS, "registers": [{"write": [RAX, 8], "from": [[RCX, 8]]}], "memory": []}]}
IMPORTS = tuple(ImportedSymbol("OTHER.DLL", name.strip("?").split("@")[0], name, (), ((1, thunk),))
                for name, thunk in (("?G@@YA_KPEA_K_K@Z", G), ("?Abort@@YAXXZ", ABORT),
                                    ("?GetObj@@YAPEAXPEAX@Z", GETOBJ)))


def _helper():
    """[rcx + 8] = rdx; rax = rcx."""
    return (FunctionBuilder(entry=HELPER).ins(add(T, reg(RCX), const(8)), store(T, reg(RDX)))
            .ins(copy(reg(RAX), reg(RCX))).ret())


def _cases():
    """name -> (the library's functions, F first; analysis options)."""
    loop = (FunctionBuilder(entry=F).ins(copy(reg(RAX), const(0)))
            .label("top").ins(load(T2, reg(RDX)), op("INT_ADD", [reg(RAX), T2], reg(RAX)))
            .ins(add(reg(RDX), reg(RDX), const(8)), op("INT_SUB", [reg(RCX), const(1)], reg(RCX)))
            .cbranch("top", FLAG, op("INT_NOTEQUAL", [reg(RCX), const(0)], FLAG)).ret())
    join = (FunctionBuilder(entry=F)
            .cbranch("else", FLAG, op("INT_NOTEQUAL", [reg(RCX), const(0)], FLAG))
            .ins(copy(reg(RAX), reg(RDX))).branch("end")
            .label("else").ins(load(reg(RAX), reg(RSI)))
            .label("end").ret())
    model_calls = (FunctionBuilder(entry=F).sub_rsp(0x28)
                   .cbranch("go", FLAG, op("INT_NOTEQUAL", [reg(RCX), const(0)], FLAG))
                   .call(ABORT)
                   .label("go").ins(copy(reg(RCX), reg(RDX))).call(G)
                   .ins(load(reg(RAX), reg(RDX))).add_rsp(0x28).ret())
    return {
        "copy_and_anchored_store": ([FunctionBuilder(entry=F).ins(copy(reg(RAX), reg(RCX)))
                                     .ins(store(reg(RDX), reg(RSI))).ret()], {}),
        "frame_and_spill": ([FunctionBuilder(entry=F).sub_rsp(0x28)
                             .ins(add(T, reg(RSP), const(8)), store(T, reg(RCX)))
                             .ins(add(T, reg(RSP), const(8)), load(reg(RAX), T))
                             .ins(store(reg(RDX), reg(RAX))).add_rsp(0x28).ret()], {}),
        "call_with_push": ([FunctionBuilder(entry=F).sub_rsp(0x28).ins(copy(reg(R8), reg(RCX))).call(HELPER)
                            .ins(add(T, reg(R8), const(8)), load(reg(RAX), T)).add_rsp(0x28).ret(), _helper()], {}),
        "globals_and_image_address": ([FunctionBuilder(entry=F).ins(store(const(DATA_BASE + 0x10), reg(RCX)))
                                       .ins(load(reg(RAX), const(DATA_BASE + 0x20)))
                                       .ins(store(reg(RDX), const(DATA_BASE + 0x30))).ret()], {}),
        "loop": ([loop], {}),
        "join": ([join], {}),
        "pointer_chain": ([FunctionBuilder(entry=F).ins(add(T, reg(RCX), const(8)), load(T2, T))
                           .ins(add(T, T2, const(0x10)), load(reg(RAX), T)).ret()], {}),
        "literals": ([FunctionBuilder(entry=F).ins(store(reg(RCX), const(0x1234)))
                      .ins(copy(reg(RAX), const(0x5678))).ret()], {}),
        # (Astra / Fable review: alias conditions, models and noreturn, internal
        # cuts, opaque indirect calls, scaled indexes, stack values out, accessors)
        "alias_conditions": ([FunctionBuilder(entry=F).ins(store(reg(RCX), reg(RDX)))
                              .ins(load(reg(RAX), reg(R8))).ret()], {}),
        "model_calls_and_noreturn": ([model_calls], {}),
        "internal_cut": ([FunctionBuilder(entry=F).sub_rsp(0x28).call(HELPER).add_rsp(0x28).ret(), _helper()], {}),
        "opaque_indirect_call": ([FunctionBuilder(entry=F).sub_rsp(0x28).ins(load(reg(RAX), reg(RCX)))
                                  .call_indirect(RAX).ins(load(reg(RAX), reg(RDX))).add_rsp(0x28).ret()], {}),
        "scaled_index": ([FunctionBuilder(entry=F).ins(op("INT_MULT", [reg(RDX), const(8)], T2))
                          .ins(add(T, reg(RCX), T2), load(reg(RAX), T)).ret()], {}),
        "returns_stack_address": ([FunctionBuilder(entry=F).sub_rsp(0x28).ins(add(reg(RAX), reg(RSP), const(8)))
                                   .add_rsp(0x28).ret()], {}),
        "accessor": ([FunctionBuilder(entry=F).sub_rsp(0x28).ins(copy(reg(RBX), reg(RCX))).call(GETOBJ)
                      .ins(add(T, reg(RAX), const(0x30)), load(reg(R9), T)).ins(copy(reg(RAX), reg(R9)))
                      .add_rsp(0x28).ret()], {"assume_same_result_functions": True}),
    }


def _relocates(address, length, value):
    return IMAGE[0] <= value <= IMAGE[1]


def _input_digest(builders, options) -> str:
    rows = [(builder.entry, repr(builder._rows), sorted(builder._labels.items())) for builder in builders]
    text = json.dumps([rows, OTHER, OWN, repr(sorted(options.items()))], sort_keys=True)
    # (line endings normalized: a CRLF and an LF checkout are one input -- Astra)
    generator = GENERATOR.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(generator + text.encode("utf-8")).hexdigest()


def _output_digest(tmp_path, name, builders, options) -> str:
    paths = []
    for model in (OTHER, OWN):
        path = tmp_path / f"{model['id']}.json"
        path.write_text(json.dumps(model), encoding="utf-8")
        paths.append(path)
    models = load_external_models(paths, *WIN64)
    exports = (ExportedSymbol(1, F, name, True), ExportedSymbol(1, HELPER, "?H@@YA_K_K@Z", True))
    info = ImageInfo("synthetic", (), IMPORTS, exports if name == "internal_cut" else exports[:1], ())
    with ImageBaseTracking((IMAGE,), _relocates) as found:
        results = analyze_units(program_units(*builders), image_info=info, external_models=models,
                                own_library=LIBRARY, private_frame_above=0x28, **options)
    raw, refused = build_file(results, [(f"1:{F:x}", name, [name])], file_id="fingerprint", version=1,
                              library=LIBRARY, external_models=models, pcodeop_models=None,
                              private_frame_above=0x28, base_dependent=found, traps=True)
    # (the run's checks: models, assumptions, parameters, language, declarations;
    # not the versions -- the record --, the synthetic binary's identity or producer)
    source = {key: value for key, value in raw["source"].items()
              if key not in ("engine", "sha256", "image_base", "library", "kind", "producer")}
    content = {"entries": raw["entries"], "source": source,
               "refused": {key: getattr(value, "kind", None) for key, value in refused.items()}}
    return hashlib.sha256(json.dumps(content, sort_keys=True).encode("utf-8")).hexdigest()


@pytest.fixture
def pinned(monkeypatch):
    """Every engine switch at its default (a shell's TDO_V2_* must not poison
    the record); forward set per digest."""
    for key in list(os.environ):
        if key.startswith("TDO_V2_") and key != "TDO_V2_REFRESH_TEMPLATE_FINGERPRINT":
            monkeypatch.delenv(key)
    return monkeypatch


def test_derived_templates_change_only_with_a_semantics_version_bump(tmp_path, pinned):
    versions = {"summary_version": FUNCTION_SUMMARY_VERSION, "template_version": TEMPLATE_VERSION,
                "semantics_version": ENGINE_SEMANTICS_VERSION}
    cases = {}
    for name, (builders, options) in _cases().items():
        outputs = {}
        for forward in ("0", "1"):
            pinned.setenv("TDO_V2_FORWARD", forward)
            directory = tmp_path / f"{name}-{forward}"
            directory.mkdir()
            outputs[f"forward_{forward}"] = _output_digest(directory, name, builders, options)
        cases[name] = {"input": _input_digest(builders, options), **outputs}
    recorded = json.loads(RECORD.read_text(encoding="utf-8")) if RECORD.exists() else {}
    same_versions = recorded.get("versions") == versions
    changed = sorted(name for name, case in cases.items() if name in recorded.get("cases", {})
                     and recorded["cases"][name]["input"] == case["input"] and recorded["cases"][name] != case)
    if os.environ.get("TDO_V2_REFRESH_TEMPLATE_FINGERPRINT") == "1":
        if same_versions and changed:
            pytest.fail(f"derived templates of {changed} changed but the versions did not: bump "
                        "ENGINE_SEMANTICS_VERSION (summary_templates.py) and re-derive models/derived first")
        stale = [path.name for path in sorted((REPO / "models" / "derived").glob("*.json"))
                 if json.loads(path.read_text(encoding="utf-8"))["source"]["engine"] != versions]
        if stale:
            pytest.fail(f"re-derive {stale} first: they record other engine versions (docs 25.74)")
        RECORD.write_text(json.dumps({"versions": versions, "cases": cases}, indent=1, sort_keys=True) + "\n",
                          encoding="utf-8")
        pytest.skip("template fingerprint refreshed")
    assert same_versions, (f"engine versions {versions} differ from the record {recorded.get('versions')}: refresh "
                           "the fingerprint (TDO_V2_REFRESH_TEMPLATE_FINGERPRINT=1)")
    assert not changed, (
        f"derived templates of {changed} changed without an ENGINE_SEMANTICS_VERSION bump: bump it "
        "(summary_templates.py), re-derive models/derived (docs 25.74), then refresh the fingerprint "
        "(TDO_V2_REFRESH_TEMPLATE_FINGERPRINT=1)")
    assert cases == recorded["cases"], ("the cases or their inputs changed (the test or synthetic.py): refresh the "
                                        "fingerprint (TDO_V2_REFRESH_TEMPLATE_FINGERPRINT=1)")
