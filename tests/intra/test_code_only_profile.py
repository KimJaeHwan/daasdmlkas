"""The code-only profile (``tdo_v2.code_only_profile``, design r9 I0a): one
forced assumption vector over a whole run, only pinned derived templates as
models (no hand model of any kind), and an allowlist of the labels a
consumed template may rest on."""

import json

import pytest

from synthetic import (
    NO_CALLBACKS, CODE_BASE, DATA_BASE, DATA_SIZE, R9, RAX, RBX, RCX, RSP, FunctionBuilder, add, const, copy, load,
    operation_node_at, program_units, reg, slice_from, store, tmp,
)
from tdo_v2.assumptions import switches
from tdo_v2.code_only_profile import (
    MANIFEST_FORMAT, ON, CodeOnlyProfile, ProfileError, forced_arguments, load_build_manifest, required_off,
    switch_vector,
)
from tdo_v2.image_info import ExportedSymbol, ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.relative_memory import ImageBaseTracking
from tdo_v2.summary_engine import run_assumptions
from tdo_v2.summary_store import ExternalModels, load_external_models, load_model_file
from tdo_v2.summary_templates import TemplateRefused, build_file

WIN64 = ("x86:LE:64:default", "win64")
LIBRARY = "SYNTH.DLL"
F = CODE_BASE + 0x800
THUNK = CODE_BASE + 0xF00
IMAGE = (CODE_BASE, DATA_BASE + DATA_SIZE)


def _leaf():
    """F: rax = [rcx] (one load), return -- a GetLastError-like leaf."""
    return FunctionBuilder(entry=F).ins(load(reg(RAX), reg(RCX))).ret()


def _library_sha(body=None):
    units = program_units(body or _leaf())
    return units[0].scopes.program.evidence.executable_sha256.hex()


def _profile(sha=None):
    return CodeOnlyProfile(*WIN64, ((LIBRARY, sha or _library_sha()),))


def _derive(tmp_path, profile, *, models=ExternalModels(()), name="derived.json", **options):
    info = ImageInfo("synthetic", (), (), (ExportedSymbol(1, F, "F", True),), ())
    with ImageBaseTracking((IMAGE,), lambda address, length, value: IMAGE[0] <= value <= IMAGE[1]) as found:
        results = analyze_units(program_units(_leaf()), image_info=info, external_models=models,
                                own_library=LIBRARY, code_only_profile=profile, **options)
    raw, refused = build_file(results, [(f"1:{F:x}", "F", ["F"])], file_id="synth-derived", version=1,
                              library=LIBRARY, external_models=models, pcodeop_models=None,
                              private_frame_above=0, base_dependent=found, code_only=profile)
    assert not refused, refused
    path = tmp_path / name
    path.write_text(json.dumps(raw))
    return path, raw


def _caller(target):
    """[rsp+0x30] = rbx; call; r9 = [rsp+0x30] (kept); rbx read after (preserved)."""
    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x48)
               .ins(add(t, reg(RSP), const(0x30)), store(t, reg(RBX)))
               .call(target))
    index = len(builder._rows)
    return builder.ins(copy(reg(R9), reg(RBX))).add_rsp(0x48).ret(), index


def _consume(profile, models, **options):
    builder, index = _caller(THUNK)
    info = ImageInfo("synthetic", (), (ImportedSymbol(LIBRARY, "F", "F", (), ((1, THUNK),)),), (), ())
    analyzed = analyze_units(program_units(builder), image_info=info, external_models=models,
                             code_only_profile=profile, **options)["1:1000"]
    function = analyzed.normalized
    return analyzed, slice_from(function, operation_node_at(function, index, 0))


# -- the vector


def test_the_vector_names_every_registry_switch_and_keeps_only_environment_facts_on():
    vector = switch_vector()
    assert set(vector) == {row.name for row in switches()}
    assert {name for name, on in vector.items() if on} == set(ON) == {
        "readonly-image-data-is-constant", "import-slots-hold-their-exports", "external-models"}
    assert set(forced_arguments()) == {row.parameter for row in switches() if row.name != "external-models"}
    assert {"direction-flag-clear", "win64-home-space-callee-private", "opaque-callees-restore-stack-pointer",
            "globals-disjoint-from-stack", "debug-break-traps-do-not-return",
            "library-internal-model-cuts"} <= required_off()


def test_a_run_switch_left_on_is_an_error():
    with pytest.raises(ProfileError, match="still on"):
        _profile("0" * 64).check_disabled(required_off() - {"direction-flag-clear"})


def _uses_globals_disjoint():
    """[rsp+8] = rbx; [global] = rax; r9 = [rsp+8]: the global store and the
    stack read are separated only by globals-disjoint-from-stack."""
    t, g = tmp(0x100), tmp(0x200)
    return (FunctionBuilder().sub_rsp(0x28)
            .ins(add(t, reg(RSP), const(8)), store(t, reg(RBX)))
            .ins(copy(g, const(DATA_BASE + 0x40)), store(g, reg(RAX)))
            .ins(add(t, reg(RSP), const(8)), load(reg(R9), t))
            .add_rsp(0x28).ret())


def test_the_profile_overrides_the_switches_a_caller_asks_for():
    asked = dict(assume_globals_disjoint_from_stack=True, assume_entry_values_not_frame=True,
                 assume_direction_flag_clear=True, private_frame_above=0x28)
    plain = analyze_units(program_units(_uses_globals_disjoint()), **asked)
    assert "globals-disjoint-from-stack" in run_assumptions(plain)
    profiled = analyze_units(program_units(_uses_globals_disjoint()), code_only_profile=_profile("0" * 64), **asked)
    assert "globals-disjoint-from-stack" not in run_assumptions(profiled)


# -- deriving and consuming


def test_a_leaf_template_derived_and_consumed_under_the_profile_keeps_its_preservation(tmp_path):
    profile = _profile()
    path, raw = _derive(tmp_path, profile)   # (bootstrap: no model file at all, the ABI tag from the profile)
    assert raw["abi_tag"] == "win64" and raw["source"]["models"] == []
    assert raw["source"]["code_only_switches"] == switch_vector()
    models = profile.admit(load_external_models([path], *WIN64))
    analyzed, kept = _consume(profile, models)
    assert any(label.startswith("derived-model:synth-derived/F@v1#") for label in analyzed.declared.values())
    (effect,) = analyzed.proven.values()
    assert any(span.start <= RBX < span.end for span in effect.preserved)
    assert kept.is_complete and RBX in {offset & ~7 for offset in kept.register_bytes}


def test_a_template_of_a_file_the_build_does_not_pin_is_not_applicable(tmp_path):
    path, _ = _derive(tmp_path, _profile())
    other = _profile("1" * 64)   # another build of the library
    models = other.admit(load_external_models([path], *WIN64))
    assert models.files == ()
    analyzed, kept = _consume(other, models)
    assert not analyzed.declared and not kept.is_complete


def test_a_template_derived_outside_the_profile_is_refused(tmp_path):
    profile = _profile()
    info = ImageInfo("synthetic", (), (), (ExportedSymbol(1, F, "F", True),), ())
    with ImageBaseTracking((IMAGE,), lambda address, length, value: IMAGE[0] <= value <= IMAGE[1]) as found:
        results = analyze_units(program_units(_leaf()), image_info=info, own_library=LIBRARY)
    hand = tmp_path / "hand.json"
    hand.write_text(json.dumps({"format_version": 1, "kind": "declared", "id": "synth-hand", "version": 1,
                                "language_id": WIN64[0], "abi_tag": WIN64[1], "libraries": ["OTHER.DLL"],
                                "stack_pointer": [32, 8], "stack_delta": 8, "preserved": [],
                                "entries": [{"name": "G", "original_names": ["G"], "registers": [], "memory": [],
                                             **NO_CALLBACKS, "other_memory": "preserved"}]}))
    # (a plain derivation needs a model file for its ABI tag: give it one, as today's runs do)
    models = load_external_models([hand], *WIN64)
    raw, refused = build_file(results, [(f"1:{F:x}", "F", ["F"])], file_id="synth-derived", version=1,
                              library=LIBRARY, external_models=models, pcodeop_models=None, private_frame_above=0,
                              base_dependent=found)
    assert not refused and "code_only_switches" not in raw["source"]
    raw["source"]["models"] = []   # (its hand dependency dropped: the vector alone refuses it)
    path = tmp_path / "plain.json"
    path.write_text(json.dumps(raw))
    analyzed, kept = _consume(profile, profile.admit(load_external_models([path], *WIN64)))
    assert not analyzed.declared and not kept.is_complete
    assert any("another assumption vector" in reason for reason in analyzed.refused_models.values())


def test_a_template_resting_on_a_label_outside_the_allowlist_is_refused(tmp_path):
    profile = _profile()
    path, raw = _derive(tmp_path, profile)
    raw["source"]["assumptions"] = [*raw["source"]["assumptions"], "globals-disjoint-from-stack"]
    path.write_text(json.dumps(raw))
    analyzed, kept = _consume(profile, profile.admit(load_external_models([path], *WIN64)))
    assert not analyzed.declared and not kept.is_complete
    assert any("rests on globals-disjoint-from-stack" in reason for reason in analyzed.refused_models.values())


def test_a_derivation_resting_on_a_label_outside_the_allowlist_is_refused():
    profile = _profile()
    info = ImageInfo("synthetic", (), (), (ExportedSymbol(1, F, "F", True),), ())
    with ImageBaseTracking((IMAGE,), lambda address, length, value: IMAGE[0] <= value <= IMAGE[1]) as found:
        results = analyze_units(program_units(_uses_globals_disjoint()), image_info=info, own_library=LIBRARY,
                                assume_globals_disjoint_from_stack=True)
    with pytest.raises(TemplateRefused, match="code-only profile: the derivation rests on"):
        build_file(results, [("1:1000", "F", ["F"])], file_id="x", version=1, library=LIBRARY,
                   external_models=ExternalModels(()), pcodeop_models=None, private_frame_above=0,
                   base_dependent=found, code_only=profile)


# -- inputs the profile does not take


def _hand_file(tmp_path):
    path = tmp_path / "hand.json"
    path.write_text(json.dumps({"format_version": 1, "kind": "declared", "id": "synth-hand", "version": 1,
                                "language_id": WIN64[0], "abi_tag": WIN64[1], "libraries": [LIBRARY],
                                "stack_pointer": [32, 8], "stack_delta": 8, "preserved": [[24, 8]],
                                "entries": [{"name": "F", "original_names": ["F"], "registers": [], "memory": [],
                                             **NO_CALLBACKS, "other_memory": "preserved"}]}))
    return path


def test_a_hand_model_file_is_an_error(tmp_path):
    profile = _profile()
    models = load_external_models([_hand_file(tmp_path)], *WIN64)
    with pytest.raises(ProfileError, match="hand model file"):
        profile.admit(models)
    with pytest.raises(ProfileError, match="hand model file"):
        _consume(profile, models)


@pytest.mark.parametrize("option", ["model_bindings", "lifecycle_contracts", "assumption_declarations"])
def test_hand_model_inputs_are_errors(option):
    with pytest.raises(ProfileError, match="hand models"):
        _profile("0" * 64).analysis_options({option: (object(),)})


def test_test_only_boundaries_are_errors():
    with pytest.raises(ProfileError, match="test-only"):
        _profile("0" * 64).analysis_options({"declared_boundaries": {"1:1000": object()}})


def test_profile_models_come_from_the_given_directories_only(tmp_path, monkeypatch):
    profile = _profile()
    directory = tmp_path / "dir"
    directory.mkdir()
    _derive(directory, profile)
    assert [item.file_id for item in profile.load_models([directory]).files] == ["synth-derived"]
    monkeypatch.setenv("TDO_V2_MODEL_DIRS", str(directory))
    with pytest.raises(ProfileError, match="TDO_V2_MODEL_DIRS"):
        profile.load_models([directory])
    monkeypatch.delenv("TDO_V2_MODEL_DIRS")
    _hand_file(directory)
    with pytest.raises(ProfileError, match="hand model file"):
        profile.load_models([directory])


def test_the_build_manifest(tmp_path):
    path = tmp_path / "build.json"
    path.write_text(json.dumps({"format": MANIFEST_FORMAT, "language_id": WIN64[0], "abi_tag": WIN64[1],
                                "libraries": {"synth.dll": "a" * 64}}))
    profile = load_build_manifest(path)
    assert profile.library_sha("SYNTH.DLL") == "a" * 64 and len(profile.digest) == 64
    path.write_text(json.dumps({"format": MANIFEST_FORMAT, "language_id": WIN64[0], "abi_tag": WIN64[1],
                                "libraries": {"synth.dll": "A" * 64}}))
    with pytest.raises(ProfileError):
        load_build_manifest(path)


def test_a_template_file_keeps_the_recorded_vector(tmp_path):
    path, _ = _derive(tmp_path, _profile())
    model_file = load_model_file(path)
    assert model_file.source_field("code_only_switches") == switch_vector()
