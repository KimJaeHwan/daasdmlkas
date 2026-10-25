"""Typed lifecycle records and explicit, strict profile loading."""

import json
from dataclasses import FrozenInstanceError
from dataclasses import replace
from pathlib import Path

import pytest

from tdo_v2.lifecycle_contracts import (LifecycleContract, LifecycleContractError,
                                        load_lifecycle_contracts)
from tdo_v2.image_info import ImportedSymbol
from tdo_v2.summary_store import load_model_file


CRT = Path(__file__).resolve().parents[2] / "models" / "external" / "crt_win64.json"
SYSV = Path(__file__).resolve().parents[2] / "models" / "external" / "crt_sysv64.json"
SYSV_PROFILE = Path(__file__).resolve().parents[2] / "models" / "lifecycle" / "glibc_sysv64.json"
REFERENCE = "https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/malloc"
GLIBC_RESIZE = "https://sourceware.org/glibc/manual/latest/html_node/Changing-Block-Size.html"
GLIBC_REPLACEMENT = "https://sourceware.org/glibc/manual/latest/html_node/Replacing-malloc.html"


@pytest.fixture(scope="module")
def model():
    return load_model_file(CRT)


def _entry(model, name):
    return next(entry for entry in model.entries if entry.name == name)


def _contract(model, contract_kind, **changes):
    fields = dict(
        contract_id="audited-crt-lifecycle", version=1,
        model_id=f"{model.file_id}/{contract_kind}", model_digest=model.digest,
        kind=contract_kind, result=None, pointer=None, size=None, count=None,
        nullable=True, failure="unknown", zero_size="unknown",
        inplace="unknown", moved="unknown", owned_footprint=False,
        references=(REFERENCE,), symbol_names=(),
    )
    if contract_kind == "allocate":
        fields.update(model_id=f"{model.file_id}/malloc", result=(0, 8), size=(8, 8),
                      symbol_names=("malloc",))
    elif contract_kind == "release":
        fields.update(model_id=f"{model.file_id}/free", pointer=(8, 8), symbol_names=("free",))
    elif contract_kind == "resize":
        fields.update(model_id=f"{model.file_id}/realloc", result=(0, 8), pointer=(8, 8), size=(16, 8),
                      symbol_names=("realloc",))
    fields.update(changes)
    return LifecycleContract(**fields)


@pytest.mark.parametrize("kind,name", (("allocate", "malloc"), ("release", "free"),
                                      ("resize", "realloc")))
def test_matches_original_model_physical_ports(model, kind, name):
    contract = _contract(model, kind)
    entry = _entry(model, name)
    assert contract.matches(model, entry)
    assert contract.model_id == entry.model_id
    assert contract.canonical_digest == _contract(model, kind).canonical_digest
    assert len(contract.canonical_digest) == 64
    assert contract.label == (f"lifecycle-contract:{contract.contract_id}@v{contract.version}#"
                              f"{contract.canonical_digest}")


def test_model_identity_and_original_row_are_required(model):
    entry = _entry(model, "malloc")
    contract = _contract(model, "allocate")
    assert not contract.matches(replace(model, digest="0" * 64), entry)
    assert not contract.matches(model, replace(entry, fresh=()))
    assert not contract.matches(replace(model, entries=(*model.entries, entry)), entry)
    assert not replace(contract, model_id=f"{model.file_id}/free").matches(model, entry)
    assert not replace(contract, result=(1, 8)).matches(model, entry)


def test_original_frees_and_same_object_pairs_must_agree(model):
    release = _contract(model, "release")
    resize = _contract(model, "resize")
    free = _entry(model, "free")
    realloc = _entry(model, "realloc")
    assert not replace(release, pointer=(9, 8)).matches(model, free)
    assert not replace(resize, pointer=(9, 8)).matches(model, realloc)
    assert not resize.matches(model, replace(realloc, same_object=()))
    assert not resize.matches(model, replace(realloc, frees=((8, 8), (16, 8))))
    assert not replace(resize, result=(1, 8)).matches(model, realloc)


def test_model_alias_does_not_verify_the_actual_call_symbol_or_size_ports(model):
    malloc = _entry(model, "malloc")
    assert "calloc" in malloc.names
    # Both port descriptions match one model row. The consumer must inspect
    # the actual import symbol before using either size/count interpretation.
    malloc_shape = _contract(model, "allocate", size=(8, 8), count=None, symbol_names=("malloc",))
    calloc_shape = _contract(model, "allocate", size=(16, 8), count=(8, 8), symbol_names=("calloc",))
    assert malloc_shape.matches(model, malloc)
    assert calloc_shape.matches(model, malloc)
    assert not replace(malloc_shape, symbol_names=("realloc",)).matches(model, malloc)
    assert malloc_shape.canonical_digest != calloc_shape.canonical_digest
    malloc_import = ImportedSymbol("CRT", "malloc", None, (), ())
    calloc_import = ImportedSymbol("CRT", "calloc", None, (), ())
    assert malloc_shape.matches_symbol(malloc_import)
    assert not malloc_shape.matches_symbol(calloc_import)
    assert calloc_shape.matches_symbol(calloc_import)
    assert not calloc_shape.matches_symbol(malloc_import)
    # A separate original name is authoritative, even if the display name
    # happens to match another whitelisted export.
    renamed_import = ImportedSymbol("CRT", "malloc", "calloc", (), ())
    assert not malloc_shape.matches_symbol(renamed_import)
    assert calloc_shape.matches_symbol(renamed_import)


def test_empty_symbol_whitelist_is_inert(model):
    entry = _entry(model, "malloc")
    contract = _contract(model, "allocate", symbol_names=())
    assert not contract.matches(model, entry)
    assert not contract.matches_symbol(ImportedSymbol("CRT", "malloc", None, (), ()))


def test_provenance_changes_when_outcome_or_reference_changes(model):
    contract = _contract(model, "resize", failure="retain", zero_size="release",
                         inplace="retain", moved="replace", nullable=False,
                         owned_footprint=True)
    assert contract.matches(model, _entry(model, "realloc"))
    for changed in (replace(contract, nullable=True),
                    replace(contract, failure="unknown"),
                    replace(contract, references=(REFERENCE + "#remarks",)),
                    replace(contract, symbol_names=("_realloc",))):
        assert changed.canonical_digest != contract.canonical_digest
        assert changed.label != contract.label
    assert replace(contract, model_digest=model.digest.upper()).canonical_digest == contract.canonical_digest


def test_format_two_copy_prefix_is_distinct_and_only_a_resize_content_claim(model):
    old = _contract(model, "resize")
    explicit_unknown = replace(old, format_version=2, version=2, contents="unknown")
    prefix = replace(explicit_unknown, contents="preserve-prefix")
    assert prefix.matches(model, _entry(model, "realloc"))
    assert prefix.contents == "preserve-prefix" and prefix.format_version == 2
    assert prefix.canonical_digest != explicit_unknown.canonical_digest
    assert prefix.canonical_digest != old.canonical_digest
    assert replace(old, format_version=2).canonical_digest != old.canonical_digest
    assert prefix.label == f"lifecycle-contract:{prefix.contract_id}@v2#{prefix.canonical_digest}"
    # This field does not change the value/address relation in the original
    # model; a consumer must still prove positive success and both extents.
    assert (prefix.result, prefix.pointer, prefix.size) == (old.result, old.pointer, old.size)
    for kind in ("allocate", "release"):
        with pytest.raises(ValueError):
            _contract(model, kind, format_version=2, version=2, contents="preserve-prefix")
    with pytest.raises(ValueError):
        replace(old, contents="preserve-prefix")  # format 1 cannot opt in implicitly
    with pytest.raises(ValueError):
        replace(prefix, size=None)
    with pytest.raises(ValueError):
        replace(prefix, version=1)


@pytest.mark.parametrize("changes,error", (
    ({"version": 0}, ValueError),
    ({"version": True}, ValueError),
    ({"model_digest": "xyz"}, ValueError),
    ({"kind": "reallocate"}, ValueError),
    ({"result": (0, 0)}, ValueError),
    ({"result": (0, 17)}, ValueError),
    ({"result": (True, 8)}, TypeError),
    ({"result": [0, 8]}, TypeError),
    ({"nullable": 0}, TypeError),
    ({"failure": "success"}, ValueError),
    ({"format_version": True}, ValueError),
    ({"format_version": 3}, ValueError),
    ({"contents": "copy-all"}, ValueError),
    ({"contents": None}, ValueError),
    ({"zero_size": "retain"}, ValueError),
    ({"inplace": "move"}, ValueError),
    ({"moved": "retain"}, ValueError),
    ({"count": (16, 8), "size": None}, ValueError),
    ({"owned_footprint": True, "size": None}, ValueError),
    ({"references": ()}, ValueError),
    ({"references": ("not a URL",)}, ValueError),
    ({"references": (REFERENCE, REFERENCE)}, ValueError),
    ({"symbol_names": ["malloc"]}, TypeError),
    ({"symbol_names": ("",)}, ValueError),
    ({"symbol_names": ("malloc", "malloc")}, ValueError),
))
def test_rejects_malformed_contract_fields(model, changes, error):
    with pytest.raises(error):
        _contract(model, "allocate", **changes)


def test_kind_specific_port_and_outcome_conflicts_fail(model):
    with pytest.raises(ValueError):
        _contract(model, "allocate", pointer=(8, 8))
    with pytest.raises(ValueError):
        _contract(model, "release", result=(0, 8))
    with pytest.raises(ValueError):
        _contract(model, "resize", pointer=None)
    with pytest.raises(ValueError):
        _contract(model, "allocate", moved="replace")
    with pytest.raises(ValueError):
        _contract(model, "allocate", zero_size="release")
    with pytest.raises(ValueError):
        _contract(model, "release", nullable=False)
    with pytest.raises(ValueError):
        _contract(model, "release", owned_footprint=True)


def test_selected_glibc_profile_matches_only_its_original_sysv_model_and_symbols():
    file = load_model_file(SYSV)
    contracts = load_lifecycle_contracts(SYSV_PROFILE)
    assert file.file_id == "crt-sysv64"
    assert file.digest == "df8349043fbeb418f7c60be3eee276efc231ac3845e3b25b249b8d78ddc54c4f"
    assert tuple(contract.kind for contract in contracts) == ("allocate", "release", "resize")
    assert tuple(contract.format_version for contract in contracts) == (2, 2, 2)
    assert tuple(contract.contents for contract in contracts) == (
        "unknown", "unknown", "preserve-prefix")
    assert tuple(contract.version for contract in contracts) == (1, 1, 2)
    assert tuple(contract.symbol_names for contract in contracts) == (("malloc",), ("free",), ("realloc",))
    assert all(contract.nullable and contract.model_digest == file.digest for contract in contracts)
    assert tuple(contract.owned_footprint for contract in contracts) == (True, False, True)
    assert tuple((contract.result, contract.pointer, contract.size) for contract in contracts) == (
        ((0, 8), None, (56, 8)),
        (None, (56, 8), None),
        ((0, 8), (56, 8), (48, 8)),
    )
    malloc, free, realloc = contracts
    assert (realloc.failure, realloc.zero_size, realloc.inplace, realloc.moved) == (
        "retain", "unknown", "retain", "replace")
    assert realloc.label.startswith("lifecycle-contract:glibc-sysv64-realloc@v2#")
    # Official GNU manual: moved realloc copies old contents; allocator
    # replacement/interposition remains an independent runtime assumption.
    assert GLIBC_RESIZE in realloc.references and GLIBC_REPLACEMENT in realloc.references
    for contract in contracts:
        entry = next(entry for entry in file.entries if entry.model_id == contract.model_id)
        assert contract.matches(file, entry)
        assert not contract.matches(replace(file, digest="0" * 64), entry)
        assert contract.matches_symbol(ImportedSymbol("libc.so.6", contract.symbol_names[0], None, (), ()))
        assert not contract.matches_symbol(ImportedSymbol("libc.so.6", "calloc", None, (), ()))
        assert contract.label.endswith(contract.canonical_digest)
        with pytest.raises(FrozenInstanceError):
            contract.kind = "release"
    assert "calloc" in next(entry for entry in file.entries if entry.model_id == malloc.model_id).names
    assert all(reference.startswith("https://sourceware.org/glibc/manual/")
               for contract in contracts for reference in contract.references)
    assert len({reference for contract in contracts for reference in contract.references}) == 4


def _selected_profile_raw():
    return json.loads(SYSV_PROFILE.read_text(encoding="utf-8"))


def _historical_format_one_raw():
    raw = _selected_profile_raw()
    raw["format_version"] = 1
    for row in raw["contracts"]:
        row.pop("contents")
    raw["contracts"][2]["version"] = 1
    return raw


def test_historical_format_one_payload_and_digests_remain_unchanged(tmp_path):
    old = _load_modified_profile(tmp_path, _historical_format_one_raw())
    assert tuple(contract.format_version for contract in old) == (1, 1, 1)
    assert tuple(contract.contents for contract in old) == ("unknown",) * 3
    assert tuple(contract.canonical_digest for contract in old) == (
        "b471fc3c8001200cf31cab124c2bfa80104428111bac1db8fabf3278e8682bf7",
        "af9a3c0a6739b46c080ead22cba3ebbde074f81c5281b332063b2252cac111b7",
        "50780a190291c34effc97639c91cfee57df56ed2a743ea69570b0d51f70be502",
    )
    assert replace(old[2], contents="unknown").canonical_digest == old[2].canonical_digest
    assert old[2].canonical_digest != load_lifecycle_contracts(SYSV_PROFILE)[2].canonical_digest


def _load_modified_profile(tmp_path, value):
    path = tmp_path / "selected-lifecycle.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return load_lifecycle_contracts(path)


@pytest.mark.parametrize("mutation", (
    lambda raw: raw.update(unexpected=True),
    lambda raw: raw.pop("contracts"),
    lambda raw: raw.update(format_version=True),
    lambda raw: raw.update(format_version=3),
    lambda raw: raw.update(format_version=1),  # format 1 rejects new contents fields
    lambda raw: raw.update(contracts=[]),
    lambda raw: raw.update(contracts={}),
    lambda raw: raw["contracts"][0].update(unexpected=True),
    lambda raw: raw["contracts"][0].pop("contents"),
    lambda raw: raw["contracts"][0].update(contents="preserve-prefix"),
    lambda raw: raw["contracts"][1].update(contents="preserve-prefix"),
    lambda raw: raw["contracts"][2].update(contents="copy-all"),
    lambda raw: raw["contracts"][2].update(version=1),
    lambda raw: raw["contracts"][0].pop("symbol_names"),
    lambda raw: raw["contracts"][0].update(result=[0]),
    lambda raw: raw["contracts"][0].update(result=[0, True]),
    lambda raw: raw["contracts"][0].update(nullable=1),
    lambda raw: raw["contracts"][0].update(model_digest="0"),
    lambda raw: raw["contracts"][0].update(references=[]),
    lambda raw: raw["contracts"][0].update(symbol_names=[]),
    lambda raw: raw["contracts"][0].update(symbol_names=["malloc", "malloc"]),
    lambda raw: raw["contracts"].append(dict(raw["contracts"][0])),
    lambda raw: raw["contracts"].append({**raw["contracts"][0],
                                         "contract_id": "another-id"}),
))
def test_strict_loader_rejects_bad_schema_or_duplicate_profiles(tmp_path, mutation):
    raw = _selected_profile_raw()
    mutation(raw)
    with pytest.raises(LifecycleContractError):
        _load_modified_profile(tmp_path, raw)


def test_strict_loader_rejects_duplicate_json_keys_and_non_json_numbers(tmp_path):
    path = tmp_path / "duplicate-key.json"
    path.write_text('{"format_version":1,"format_version":1,"contracts":[]}', encoding="utf-8")
    with pytest.raises(LifecycleContractError, match="duplicate lifecycle JSON key"):
        load_lifecycle_contracts(path)
    path.write_text('{"format_version":NaN,"contracts":[]}', encoding="utf-8")
    with pytest.raises(LifecycleContractError, match="non-JSON lifecycle value"):
        load_lifecycle_contracts(path)
    path.write_text('{"format_version":1,', encoding="utf-8")
    with pytest.raises(LifecycleContractError, match="malformed lifecycle JSON"):
        load_lifecycle_contracts(path)


def test_wrong_but_well_formed_model_digest_loads_inertly_and_cannot_match(tmp_path):
    raw = _selected_profile_raw()
    raw["contracts"][0]["model_digest"] = "0" * 64
    contracts = _load_modified_profile(tmp_path, raw)
    file = load_model_file(SYSV)
    malloc = next(entry for entry in file.entries if entry.name == "malloc")
    assert not contracts[0].matches(file, malloc)


def test_profile_file_is_not_loaded_without_an_explicit_opt_in():
    from synthetic import FunctionBuilder, program_units
    from tdo_v2.interprocedural import analyze_units

    result = analyze_units(program_units(FunctionBuilder().ret(realistic=False)))
    item = result["1:1000"]
    assert item.allocation_contracts == () and item.allocation_models == ()
