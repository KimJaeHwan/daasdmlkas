"""Model provenance and extra model directories (``summary_store``): models
written by hand, derived from the library code, or supplied by another tool
all load the same way; each use reports its provenance and the assumptions the
model rests on; two models for one import are an error unless one file
explicitly replaces the other (``overrides``)."""

import json
from pathlib import Path

import pytest

from synthetic import NO_CALLBACKS, CODE_BASE, R9, RAX, RCX, FunctionBuilder, copy, reg
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import ModelError, load_external_models, load_model_file, model_paths

BUILTIN = Path(__file__).resolve().parents[2] / "models" / "external"
WIN64 = ("x86:LE:64:default", "win64")


def _file(directory, name, entries, source=None, overrides=None, file_id="supplied-test"):
    raw = {"format_version": 1, "kind": "declared", "id": file_id, "version": 1,
           "language_id": WIN64[0], "abi_tag": WIN64[1], "stack_pointer": [32, 8], "stack_delta": 8,
           "preserved": [[24, 8], [40, 8], [48, 8], [56, 8]], "entries": entries,
           # (what the supplying tool's models rest on, declared by the file)
           "declares_assumptions": [{"id": "tool-trusted", "statement": "The supplying tool's models are right.",
                                     "fails_when": "The tool is wrong."}]}
    if source is not None:
        raw["source"] = source
    if overrides is not None:
        raw["overrides"] = overrides
    path = Path(directory) / name
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def _identity(name):
    """rax = rcx; no memory."""
    return {"name": name, "registers": [{"write": [0, 8], "from": [[8, 8]]}], "memory": [],
            **NO_CALLBACKS, "other_memory": "preserved"}


SUPPLIED = {"kind": "external", "tool": "other-analyzer", "version": "1.0", "assumptions": ["supplied-test:tool-trusted"]}


def test_hand_models_keep_their_labels():
    (memcpy_file,) = [load_model_file(path) for path in BUILTIN.glob("crt_win64.json")]
    entry = next(item for item in memcpy_file.entries if item.name == "memcpy")
    assert entry.source_kind == "hand" and entry.label == f"external-model:crt-win64/memcpy@v{memcpy_file.version}"
    assert entry.labels == (entry.label,)


def test_a_supplied_model_is_used_and_reported(tmp_path, monkeypatch):
    _file(tmp_path, "supplied.json", [_identity("tool_identity")], SUPPLIED)
    monkeypatch.setenv("TDO_V2_MODEL_DIRS", str(tmp_path))
    models = load_external_models(model_paths(BUILTIN), *WIN64)
    found = models.lookup("tool_identity")
    assert found is not None
    _, entry = found
    assert entry.label == "supplied-model:supplied-test/tool_identity@v1"
    assert entry.labels == (entry.label, "supplied-test:tool-trusted")
    thunk = CODE_BASE + 0xF00
    builder = (FunctionBuilder().sub_rsp(0x28)
               .call(thunk)
               .ins(copy(reg(R9), reg(RAX)))
               .add_rsp(0x28).ret())
    from synthetic import program_units

    info = ImageInfo("synthetic", (), (ImportedSymbol("TOOL", "tool_identity", None, (), ((1, thunk),)),), (), ())
    results = analyze_units(program_units(builder), image_info=info, external_models=models)
    analyzed = results["1:1000"]
    assert entry.label in analyzed.declared.values()
    assert analyzed.inherited_assumptions == {"supplied-test:tool-trusted"}


def test_two_models_for_one_import_are_an_error(tmp_path):
    _file(tmp_path, "supplied.json", [_identity("memcpy")], SUPPLIED)
    models = load_external_models(model_paths(BUILTIN, [tmp_path]), *WIN64)
    with pytest.raises(ModelError, match="several models"):
        models.lookup("memcpy")


def test_an_explicit_override_replaces_a_model(tmp_path):
    _file(tmp_path, "supplied.json", [_identity("memcpy")], SUPPLIED, overrides=["crt-win64/memcpy"])
    models = load_external_models(model_paths(BUILTIN, [tmp_path]), *WIN64)
    _, entry = models.lookup("memcpy")
    assert entry.label == "supplied-model:supplied-test/memcpy@v1"


def test_a_bad_source_is_refused(tmp_path):
    path = _file(tmp_path, "bad.json", [_identity("x")], {"kind": "magic"})
    with pytest.raises(ModelError, match="source"):
        load_model_file(path)
    path = _file(tmp_path, "bad2.json", [_identity("x")], {"kind": "external", "assumptions": "not-a-list"})
    with pytest.raises(ModelError, match="assumptions"):
        load_model_file(path)


def test_a_missing_model_directory_is_an_error(tmp_path):
    with pytest.raises(ModelError, match="not found"):
        model_paths(BUILTIN, [tmp_path / "absent"])


# -- validation (review of step 1: Fable, Astra) ------------------------------------

def _load(tmp_path, *files):
    for index, (entries, source, overrides, file_id) in enumerate(files):
        _file(tmp_path, f"m{index}.json", entries, source, overrides, file_id)
    return load_external_models(model_paths(BUILTIN, [tmp_path]), *WIN64)


def test_an_override_cycle_is_an_error(tmp_path):
    with pytest.raises(ModelError, match="cycle"):
        _load(tmp_path, ([_identity("x")], SUPPLIED, ["b/x"], "a"), ([_identity("x")], SUPPLIED, ["a/x"], "b"))


def test_an_override_of_nothing_or_of_itself_is_an_error(tmp_path):
    with pytest.raises(ModelError, match="no loaded file"):
        _load(tmp_path, ([_identity("x")], SUPPLIED, ["crt-win64/no_such_function"], "a"))
    path = _file(tmp_path, "self.json", [_identity("x")], SUPPLIED, ["self/x"], "self")
    with pytest.raises(ModelError, match="own entries"):
        load_model_file(path)


def test_duplicate_file_ids_are_an_error(tmp_path):
    with pytest.raises(ModelError, match="not unique"):
        _load(tmp_path, ([_identity("x")], SUPPLIED, None, "crt-win64"))


def test_a_directory_given_twice_is_read_once(tmp_path):
    _file(tmp_path, "supplied.json", [_identity("tool_identity")], SUPPLIED)
    paths = model_paths(BUILTIN, [tmp_path, tmp_path, BUILTIN])
    assert len(paths) == len(set(path.resolve() for path in paths))
    load_external_models(paths, *WIN64).lookup("memcpy")


def test_assumption_labels_and_derived_identity_are_checked(tmp_path):
    path = _file(tmp_path, "bad.json", [_identity("x")], {"kind": "external", "assumptions": ["made-up"]})
    with pytest.raises(ModelError, match="neither a registered"):
        load_model_file(path)
    path = _file(tmp_path, "d.json", [_identity("x")], {"kind": "derived", "library": "CORE.DLL"})
    with pytest.raises(ModelError, match="sha256"):
        load_model_file(path)
    path = _file(tmp_path, "d2.json", [_identity("x")], {"kind": "derived", "library": "CORE.DLL",
                                                          "sha256": "ab" * 32}, file_id="core-derived")
    (entry,) = load_model_file(path).entries
    assert entry.label == "derived-model:core-derived/x@v1#abababababab"


def test_a_model_needing_a_disabled_assumption_is_not_applied(tmp_path, monkeypatch):
    needs = {"kind": "external", "tool": "t", "assumptions": ["direction-flag-clear"]}
    _file(tmp_path, "needs.json", [_identity("tool_identity")], needs)
    models = load_external_models(model_paths(BUILTIN, [tmp_path]), *WIN64)
    thunk = CODE_BASE + 0xF00
    builder = (FunctionBuilder().sub_rsp(0x28).call(thunk).ins(copy(reg(R9), reg(RAX))).add_rsp(0x28).ret())
    from synthetic import program_units

    info = ImageInfo("synthetic", (), (ImportedSymbol("TOOL", "tool_identity", None, (), ((1, thunk),)),), (), ())
    off = analyze_units(program_units(builder), image_info=info, external_models=models)["1:1000"]
    assert not off.declared
    on = analyze_units(program_units(builder), image_info=info, external_models=models,
                       assume_direction_flag_clear=True)["1:1000"]
    assert on.declared and on.inherited_assumptions == {"direction-flag-clear"}
