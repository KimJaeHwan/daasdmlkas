"""Model callbacks / frees (docs 25.33, forward step 0): every model file of
this repository declares what user code its functions run and what they free;
an entry running registered handlers rests on the named assumption
registered-handlers-are-not-observed (reported per use, switchable); an entry
declaring nothing, or invoking a code pointer, is loaded but never applied."""

import copy
import json
from pathlib import Path

import pytest

from synthetic import CODE_BASE, RAX, RCX, RSP, FunctionBuilder, add, const, copy as move, program_units, reg
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import ModelError, load_external_models, load_model_file

REPO = Path(__file__).resolve().parents[2]
DECLARED = sorted([*(REPO / "models" / "external").glob("*.json"), *(REPO / "models" / "bound").glob("*.json")])
LABEL = "registered-handlers-are-not-observed"
MALLOC = CODE_BASE + 0xE00


def test_every_repository_model_declares_callbacks_and_frees():
    assert DECLARED
    for path in DECLARED:
        raw = json.loads(path.read_text(encoding="utf-8"))
        for item in raw["entries"]:
            assert {"callbacks", "callbacks_evidence", "frees"} <= set(item), (path.name, item["name"])
            assert item["callbacks_evidence"].strip(), (path.name, item["name"])
        model = load_model_file(path)
        for entry in model.entries:
            assert entry.frees is not None and entry.refusal is None, (path.name, entry.name)
            assert (LABEL in entry.inherited) == bool(entry.callbacks_registered), (path.name, entry.name)


def test_entries_running_registered_handlers_are_the_audited_ones():
    """The audit's result (a change here is a model change to review)."""
    found = {(load_model_file(path).file_id, entry.name) for path in DECLARED
             for entry in load_model_file(path).entries if entry.callbacks_registered}
    assert found == {
        ("crt-win64", "abort"), ("crt-win64", "longjmp"), ("crt-win64", "malloc"), ("crt-win64", "realloc"),
        ("crt-win64", "free"),
        ("crt-sysv64", "abort"), ("crt-sysv64", "longjmp"), ("crt-sysv64", "__stack_chk_fail"),
        ("crt-sysv64", "malloc"), ("crt-sysv64", "free"), ("crt-sysv64", "realloc"),
        ("ue-core-win64", "FMemory::Malloc"), ("ue-core-win64", "FMemory::Free"),
        ("ue-core-win64", "FMemory::QuantizeSize"), ("ue-core-win64", "FMemory::Realloc"),
        ("ue-core-win64", "FDebug::CheckVerifyFailedImpl"), ("ue-core-win64", "UE4Array_Private::OnInvalidArrayNum"),
        ("ue-core-win64", "FName::FName(const WIDECHAR*, EFindName)"),
        ("ue-core-win64", "FName::FName(const ANSICHAR*, EFindName)"),
        ("tv2-tobjectptr", "ResolveHandle"), ("tv2-tobjectptr", "TrackAccess"),
    }
    frees = {(load_model_file(path).file_id, entry.name): entry.frees for path in DECLARED
             for entry in load_model_file(path).entries if entry.frees}
    assert frees == {("crt-win64", "free"): ((8, 8),), ("crt-win64", "realloc"): ((8, 8),),
                     ("crt-sysv64", "free"): ((56, 8),), ("crt-sysv64", "realloc"): ((56, 8),),
                     ("ue-core-win64", "FMemory::Free"): ((8, 8),), ("ue-core-win64", "FMemory::Realloc"): ((8, 8),)}


def _variant(tmp_path, change):
    raw = json.loads((REPO / "models" / "external" / "crt_win64.json").read_text(encoding="utf-8"))
    raw = copy.deepcopy(raw)
    entry = next(item for item in raw["entries"] if item["name"] == "memcpy")
    change(entry)
    path = tmp_path / "crt_win64.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


@pytest.mark.parametrize("change, message", [
    (lambda e: e.pop("callbacks_evidence"), "go together"),
    (lambda e: e.update(callbacks_evidence=" "), "names the audit"),
    (lambda e: e.update(callbacks={}), "is \"none\" or"),
    (lambda e: e.update(callbacks={"registered": []}), "empty callbacks"),
    (lambda e: e.update(callbacks={"calls": ["x"]}), "is \"none\" or"),
    (lambda e: e.update(frees=[]), "frees is"),
    (lambda e: e.update(frees="all"), "frees is"),
    (lambda e: e.update(callbacks={"registered": ["h"], "invokes": ""}), "invokes lists"),
    (lambda e: e.update(callbacks={"registered": ["h"], "invokes": None}), "invokes lists"),
    (lambda e: e.update(callbacks={"registered": None}), "registered lists"),
])
def test_malformed_declarations_are_rejected(tmp_path, change, message):
    with pytest.raises(ModelError, match=message):
        load_model_file(_variant(tmp_path, change))


def test_undeclared_and_invoking_entries_are_never_applied(tmp_path):
    def undeclared(entry):
        for key in ("callbacks", "callbacks_evidence", "frees"):
            entry.pop(key)

    (entry,) = [e for e in load_model_file(_variant(tmp_path, undeclared)).entries if e.name == "memcpy"]
    assert entry.refusal and "not declared" in entry.refusal
    (entry,) = [e for e in load_model_file(_variant(tmp_path, lambda e: e.update(
        callbacks={"invokes": [[8, 8]]}))).entries if e.name == "memcpy"]
    assert entry.refusal and "invokes" in entry.refusal and entry.callbacks_invokes == ((8, 8),)


def _malloc_program(models, **options):
    caller = (FunctionBuilder().sub_rsp(0x28).ins(move(reg(RCX), const(0x40))).call(MALLOC)
              .ins(add(reg(RAX), reg(RAX), const(8))).add_rsp(0x28).ret())
    image = ImageInfo("synthetic", (), (ImportedSymbol("CRT", "malloc", None, (), ((1, MALLOC),)),), (), ())
    return analyze_units(program_units(caller), image_info=image,
                         external_models=load_external_models(models, "x86:LE:64:default", "win64"),
                         **options)["1:1000"]


def test_a_registered_handler_entry_reports_the_assumption_and_is_switchable():
    models = sorted((REPO / "models" / "external").glob("*.json"))
    on = _malloc_program(models)
    ((call, label),) = on.declared.items()
    assert label == "external-model:crt-win64/malloc@v7"
    assert LABEL in on.inherited_assumptions
    off = _malloc_program(models, assume_registered_handlers_not_observed=False)
    assert off.declared == {} and LABEL not in off.inherited_assumptions
    assert off.refused_models[call] == \
        f"external-model:crt-win64/malloc@v7: rests on {LABEL}, switched off in this run"


@pytest.mark.parametrize("change, reason", [
    (lambda e: [e.pop(key) for key in ("callbacks", "callbacks_evidence", "frees")], "not declared"),
    (lambda e: e.update(callbacks={"invokes": [[8, 8]]}), "invokes callbacks"),
])
def test_a_refused_entry_is_not_applied_at_a_call(tmp_path, change, reason):
    raw = json.loads((REPO / "models" / "external" / "crt_win64.json").read_text(encoding="utf-8"))
    change(next(item for item in raw["entries"] if item["name"] == "malloc"))
    path = tmp_path / "crt_win64.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    item = _malloc_program([path])
    assert item.declared == {}
    ((call, why),) = item.refused_models.items()
    assert why.startswith("external-model:crt-win64/malloc@v7: ") and reason in why


def test_a_pure_entry_does_not_rest_on_it():
    models = sorted((REPO / "models" / "external").glob("*.json"))
    (entry,) = [e for e in load_model_file(models[[p.name for p in models].index("crt_win64.json")]).entries
                if e.name == "memcpy"]
    assert LABEL not in entry.inherited and entry.callbacks_registered == () and entry.frees == ()


def test_the_ue_entries_keep_their_own_assumptions_too():
    model = load_model_file(REPO / "models" / "external" / "ue_core_win64.json")
    entry = next(e for e in model.entries if e.name == "FDebug::CheckVerifyFailedImpl")
    assert {"ue-core-win64:diagnostics-no-reentrant-callback", LABEL} <= set(entry.inherited)


def test_the_switch_is_registered():
    from tdo_v2.assumptions import by_name

    item = by_name(LABEL)
    assert item.kind == "switch" and item.default is True
    assert item.parameter == "assume_registered_handlers_not_observed"
