"""Assumptions a model file declares (``declares_assumptions``, label
``<file id>:<id>``) and the registry labels model rows rest on
(``summary_store``): every label resolves in the run's catalog, one file id
names one file, a typo is an error, each can be switched off
(``disabled_model_assumptions``) and then the entries resting on it are not
applied; the engine source names no library."""

import json
import re
from pathlib import Path

import pytest

from synthetic import NO_CALLBACKS, CODE_BASE, R9, RAX, FunctionBuilder, copy, program_units, reg
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import _model_cuts, analyze_units
from tdo_v2.summary_store import (
    ExternalModels, ModelError, assumption_catalog, load_external_models, load_model_file, model_paths,
)

REPO = Path(__file__).resolve().parents[2]
BUILTIN = REPO / "models" / "external"
WIN64 = ("x86:LE:64:default", "win64")
TRUSTED = {"id": "trusted", "statement": "The tool is right.", "fails_when": "The tool is wrong."}


def _file(directory, name, entries, *, file_id="decl-test", declares=(TRUSTED,), assumptions=None):
    raw = {"format_version": 1, "kind": "declared", "id": file_id, "version": 1,
           "language_id": WIN64[0], "abi_tag": WIN64[1], "stack_pointer": [32, 8], "stack_delta": 8,
           "preserved": [[24, 8], [40, 8], [48, 8], [56, 8]], "entries": entries,
           "declares_assumptions": list(declares)}
    if assumptions is not None:
        raw["source"] = {"kind": "hand", "assumptions": assumptions}
    path = Path(directory) / name
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def _identity(name, assumptions=()):
    """rax = rcx; no memory."""
    return {"name": name, "registers": [{"write": [0, 8], "from": [[8, 8]]}], "memory": [],
            **NO_CALLBACKS, "other_memory": "preserved", "assumptions": list(assumptions)}


def _run(models, name, **options):
    """A function calling the import ``name`` through a thunk: (declared labels,
    inherited assumptions) of the caller."""
    thunk = CODE_BASE + 0xF00
    builder = FunctionBuilder().sub_rsp(0x28).call(thunk).ins(copy(reg(R9), reg(RAX))).add_rsp(0x28).ret()
    info = ImageInfo("synthetic", (), (ImportedSymbol("TOOL", name, None, (), ((1, thunk),)),), (), ())
    analyzed = analyze_units(program_units(builder), image_info=info, external_models=models, **options)["1:1000"]
    return set(analyzed.declared.values()), analyzed.inherited_assumptions


# -- declarations ------------------------------------------------------------------

def test_a_declared_assumption_is_reported_and_switched_off_by_its_label(tmp_path):
    path = _file(tmp_path, "decl.json", [_identity("tool_identity", ["decl-test:trusted"])])
    models = load_external_models([path], *WIN64)
    (model_file,) = models.files
    assert model_file.declares == (("decl-test:trusted", "The tool is right.", "The tool is wrong."),)
    assert assumption_catalog(models) == {"decl-test:trusted": ("decl-test", "The tool is right.",
                                                                "The tool is wrong.")}
    declared, inherited = _run(models, "tool_identity")
    assert declared == {"external-model:decl-test/tool_identity@v1"} and inherited == {"decl-test:trusted"}
    declared, inherited = _run(models, "tool_identity", disabled_model_assumptions=("decl-test:trusted",))
    assert declared == set() and inherited == set()   # not applied: the call stays opaque


def test_a_typo_label_is_an_error_never_an_unswitchable_assumption(tmp_path):
    """``decl-tst:trusted`` (no such file) used to be accepted as a free
    namespaced label -- then switching off ``decl-test:trusted`` left it on."""
    path = _file(tmp_path, "decl.json", [_identity("tool_identity", ["decl-tst:trusted"])])
    models = load_external_models([path], *WIN64)
    with pytest.raises(ModelError, match="decl-tst:trusted, which no loaded model file declares"):
        assumption_catalog(models)
    with pytest.raises(ModelError, match="no loaded model file declares"):
        _run(models, "tool_identity")


def test_switching_off_an_unknown_label_is_an_error(tmp_path):
    models = load_external_models([_file(tmp_path, "decl.json", [_identity("tool_identity")])], *WIN64)
    for label in ("decl-test:trustd", "globals-disjoint-from-stack", "lock-markers-have-no-data-effect"):
        with pytest.raises(ModelError, match="no model assumption"):
            _run(models, "tool_identity", disabled_model_assumptions=(label,))


@pytest.mark.parametrize("raw,match", [
    ({"id": "Bad_Id"}, "id must be"),
    ({"id": "external-model"}, "id must be"),
    ({"declares_assumptions": [TRUSTED, TRUSTED]}, "declared twice"),
    ({"declares_assumptions": [{"id": "x", "statement": "s"}]}, "declares_assumptions lists"),
    ({"source": {"kind": "hand", "assumptions": ["nonsense"]}}, "neither a registered assumption"),
])
def test_malformed_declarations_are_load_errors(tmp_path, raw, match):
    path = _file(tmp_path, "decl.json", [_identity("tool_identity")])
    data = {**json.loads(path.read_text(encoding="utf-8")), **raw}
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ModelError, match=match):
        load_model_file(path)


def test_one_file_id_names_one_file_across_the_run(tmp_path):
    """The run's models and a binding's models share one namespace: the same
    file twice is one, two different files with one id are an error."""
    first = load_external_models([_file(tmp_path, "a.json", [_identity("one")])], *WIN64)
    (tmp_path / "b").mkdir()
    same = load_external_models([_file(tmp_path / "b", "a.json", [_identity("one")])], *WIN64)
    assert assumption_catalog(first, same) == assumption_catalog(first)
    other = load_external_models([_file(tmp_path / "b", "a.json", [_identity("two")])], *WIN64)
    with pytest.raises(ModelError, match="two model files have the id decl-test"):
        assumption_catalog(first, other)


def test_a_derived_template_resting_on_an_undeclared_label_is_refused_not_an_error(tmp_path):
    """A stale template loads (the run goes on) and is refused."""
    from tdo_v2.summary_templates import refusal

    raw = json.loads((REPO / "models" / "derived" / "ue_core_win64_fstring.json").read_text(encoding="utf-8"))
    raw["source"]["assumptions"] = [*raw["source"]["assumptions"], "gone-file:x"]
    path = tmp_path / "stale.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    model = load_model_file(path)
    entry = model.entries[0]
    assert entry.refusal is None
    models = load_external_models(model_paths(BUILTIN), *WIN64)
    reason = refusal(model, entry, external_models=models, pcodeop_models=None, private_frame_above=0)
    assert reason is not None and "gone-file:x" in reason
    raw["source"]["assumptions"] = [*raw["source"]["assumptions"][:-1], "a-label-no-engine-knows"]
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert "does not know" in load_model_file(path).entries[0].refusal


def test_a_template_records_what_a_declaration_only_file_states(tmp_path):
    """A label only a binding's model file declares: the template records its
    statement; the same label stating something else refuses the template
    (the recorded model files' digests cover their own declarations)."""
    from tdo_v2.summary_templates import refusal

    raw = json.loads((REPO / "models" / "derived" / "ue_core_win64_fstring.json").read_text(encoding="utf-8"))
    raw["source"]["assumptions"] = [*raw["source"]["assumptions"], "decl-test:trusted"]
    raw["source"]["declarations"] = {"decl-test:trusted": [TRUSTED["statement"], TRUSTED["fails_when"]]}
    path = tmp_path / "t.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    model = load_model_file(path)
    models = load_external_models(model_paths(BUILTIN), *WIN64)
    reasons = []
    for statement in (TRUSTED["statement"], "Something else."):
        (tmp_path / f"b{len(reasons)}").mkdir()
        bound = load_external_models([_file(tmp_path / f"b{len(reasons)}", "b.json", [], declares=(
            {**TRUSTED, "statement": statement},))], *WIN64)
        reasons.append(refusal(model, model.entries[0], external_models=models, pcodeop_models=None,
                               private_frame_above=0, catalog=assumption_catalog(models, bound)))
    assert "another statement" not in reasons[0] and reasons[1] == "derived under another statement of decl-test:trusted"
    raw["source"]["declarations"] = {"decl-test:trusted": ["only one"]}
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ModelError, match="source.declarations"):
        load_model_file(path)


def test_labels_resolve_across_the_run_and_binding_files(tmp_path):
    """A run model resting on a binding file's declaration and the reverse
    both resolve -- in the run's catalog, in a derivation's recorded
    declarations and in the link cache profile (Astra, impl round 3)."""
    from tdo_v2.linking import profile

    (tmp_path / "run").mkdir()
    (tmp_path / "bound").mkdir()
    run = load_external_models([_file(tmp_path / "run", "r.json", [_identity("one", ["bound-test:trusted"])],
                                      file_id="run-test")], *WIN64)
    bound = load_external_models([_file(tmp_path / "bound", "b.json", [_identity("two", ["run-test:trusted"])],
                                        file_id="bound-test")], *WIN64)
    assert set(assumption_catalog(run, bound)) == {"run-test:trusted", "bound-test:trusted"}
    raw = profile(switches={}, pcodeop_models=None, models=run, language_id=WIN64[0], abi_tag=WIN64[1],
                  provider_identity={}, evidence=None, catalog_models=(bound,))
    assert raw["declarations"] == [["bound-test:trusted", TRUSTED["statement"], TRUSTED["fails_when"]]]


# -- labels from rows ----------------------------------------------------------------

FRESH, FREE, REALLOC = "allocator-results-are-fresh", "no-use-after-free", "no-use-of-old-pointer-after-realloc"


def test_rows_carry_the_assumptions_they_rest_on():
    model = load_model_file(BUILTIN / "crt_win64.json")
    labels = {entry.name: set(entry.inherited) & {FRESH, FREE, REALLOC} for entry in model.entries}
    assert labels["malloc"] == {FRESH, FREE}
    assert labels["free"] == {FREE}
    assert labels["realloc"] == {FRESH, FREE, REALLOC}
    assert labels["memcpy"] == set()
    ue = {entry.name: set(entry.inherited) & {FRESH, FREE, REALLOC}
          for entry in load_model_file(BUILTIN / "ue_core_win64.json").entries}
    assert ue["FMemory::Malloc"] == {FRESH, FREE} and ue["FMemory::Free"] == {FREE}
    assert ue["FMemory::Realloc"] == {FRESH, FREE, REALLOC} and ue["FMemory::QuantizeSize"] == set()


def test_switching_off_no_use_after_free_leaves_malloc_opaque():
    models = load_external_models(model_paths(BUILTIN), *WIN64)
    declared, inherited = _run(models, "malloc")
    assert any(label.startswith("external-model:crt-win64/malloc@") for label in declared)
    assert {FRESH, FREE} <= inherited
    declared, inherited = _run(models, "malloc", disabled_model_assumptions=(FREE,))
    assert declared == set() and not inherited & {FRESH, FREE}


def test_switching_off_library_internal_cuts_cuts_nothing(tmp_path):
    """An own-library run with library-internal-model-cuts off analyses the
    internal function's body; its caller takes no model."""
    from test_library_cuts import HELPER, _caller, _helper, _models
    from tdo_v2.image_info import ExportedSymbol

    info = ImageInfo("synthetic", (), (), (ExportedSymbol(1, HELPER, "?Helper@@YA_K_K@Z", True),), ())
    for off, cut in (((), True), (("library-internal-model-cuts",), False)):
        results = analyze_units(program_units(_caller(), _helper()), image_info=info,
                                external_models=_models(tmp_path), own_library="synth.dll",
                                disabled_model_assumptions=off)
        assert (f"1:{HELPER:x}" not in results) is cut
        assert bool(results["1:1000"].declared) is cut
    assert _model_cuts({"1:1000": None}, None, ExternalModels(()), "LIB.DLL", {"library-internal-model-cuts"}) == {}


# -- no library in the engine --------------------------------------------------------

def test_the_engine_source_names_no_library():
    """What one library's models rest on is declared by its model file."""
    words = re.compile(r"unreal|fmemory|fname|gmalloc|glog|ue-core|ue_core|ue4|uobject|tobjectptr", re.I)
    found = [f"{path.relative_to(REPO)}:{number}" for path in sorted((REPO / "src" / "tdo_v2").rglob("*.py"))
             for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1) if words.search(line)]
    assert found == []
