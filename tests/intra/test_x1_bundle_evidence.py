"""X-1a (design_x1 r3 4.1 / 4.2, r4 4.2; code review r1 P1-3 / P1-4): a real headless export with the X-1 exporter.

``TDO_X1_EXPORTED_BUNDLE`` names a generation exported by ``tools/bundle_export/export_bundle.py`` with this
tree's exporter (default: the clang-x64-O0 corpus binary, ``--entry 433 1057856``; skipped when absent). The
exporter scanned its locked program inside the export session and sealed the v2 evidence as the last member.
The engine's normal admission verifies it through the admitted snapshot -- bound v2, the sealed original's
executable SHA-256, the verifiable listing digest recomputed from the sealed observations and block bytes, the
S3 applicability of the original and the sealed RSP -- and only that path binds the evidence to the Bundle's
seal. Changing one loaded byte, one override fact, the evidence's executable SHA-256 or the seal breaks it; a
function that stops declaring the profile is refused alone."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from tdo_v2._configured_bundle_reader import read_configured_bundle
from tdo_v2._scope_contracts import PRODUCER_PROFILE_X1, _mint_orchestrator_capability
from tdo_v2.integration.configured_bundle import BundleAdmissionError, admit_frozen_bundle
from tdo_v2.integration.observed_function_session import _ObservedScopeProvider
from tdo_v2.scope_identity import open_configured_extraction
from tdo_v2.stack_evidence import Coverage, authority, bundle_stack_evidence

SOURCE = Path(os.environ.get(
    "TDO_X1_EXPORTED_BUNDLE",   # (exported 2026-11-27 from the clang-x64-O0 corpus binary, --entry 433 1057856)
    "/root/x1_export_test/bbf32f69d8f8d2a3d11d4053b9875512a4425d6b203ffa99be0e182a89ecf637"))


@pytest.fixture
def generation(tmp_path):
    if not SOURCE.is_dir():
        pytest.skip("set TDO_X1_EXPORTED_BUNDLE to a generation exported by this tree's exporter")
    target = tmp_path / SOURCE.name
    shutil.copytree(SOURCE, target)
    for path in [target, *target.iterdir()]:
        path.chmod(0o750 if path.is_dir() else 0o640)
    return target


def _manifest(generation: Path) -> dict:
    return json.loads((generation / "manifest.json").read_text())


def _path(generation: Path, manifest: dict, member_id: str) -> Path:
    return generation / next(item["path"] for item in manifest["members"] if item["id"] == member_id)


def _reseal(generation: Path, manifest: dict) -> None:
    data = json.dumps(manifest, separators=(",", ":")).encode()
    (generation / "manifest.json").write_bytes(data)
    seal = json.loads((generation / "seal.json").read_text())
    seal["manifest_size"], seal["manifest_sha256"] = len(data), hashlib.sha256(data).hexdigest()
    (generation / "seal.json").write_text(json.dumps(seal, separators=(",", ":")))


def _replace_member(generation: Path, manifest: dict, member_id: str, data: bytes) -> str:
    row = next(item for item in manifest["members"] if item["id"] == member_id)
    old = row["sha256"]
    (generation / row["path"]).write_bytes(data)
    row["size"], row["sha256"] = len(data), hashlib.sha256(data).hexdigest()
    return old


def _replace_observation(generation: Path, manifest: dict, index: int, edit) -> None:
    """Edit one function observation and rebind its naming / effect sidecars to the new member digest."""
    row = manifest["functions"][index]
    path = _path(generation, manifest, row["observation_member"])
    observation = json.loads(path.read_text())
    edit(observation)
    old = _replace_member(generation, manifest, row["observation_member"], json.dumps(observation).encode())
    new = next(item["sha256"] for item in manifest["members"] if item["id"] == row["observation_member"])
    for sidecar in (row["call_names_member"], row["call_effects_member"]):
        data = _path(generation, manifest, sidecar).read_bytes().replace(old.encode(), new.encode())
        _replace_member(generation, manifest, sidecar, data)


def _observations(generation: Path) -> list:
    adapter = _ObservedScopeProvider(read_configured_bundle(admit_frozen_bundle(generation)))
    with open_configured_extraction(adapter, _mint_orchestrator_capability()) as session:
        result = []
        for unit in session.iter_scoped_functions():
            adapter.collect_function_roles()
            result.append(unit.observation)
    return result


def test_the_exported_bundle_is_profiled_and_admitted(generation):
    manifest = _manifest(generation)
    assert manifest["producer_profile"] == PRODUCER_PROFILE_X1
    assert manifest["members"][-1]["id"] == manifest["stack_switch_evidence_member"]
    observations = _observations(generation)
    assert observations and all(item is not None and item.producer_profile == PRODUCER_PROFILE_X1
                                for item in observations)


def test_admission_verifies_and_binds_the_sealed_evidence(generation):
    item = bundle_stack_evidence(generation)
    seal = hashlib.sha256((generation / "manifest.json").read_bytes()).hexdigest()
    original = next(row for row in _manifest(generation)["members"] if row["id"] == "original")
    assert item.version == 2 and item.bound and item.verified and item.seal == seal
    assert item.executable_sha256 == original["sha256"]
    assert item.applicable is False   # (an ELF: S3's predicate is PE32+ / AMD64 only -> read by s3-off)
    assert item.rsp_verified and item.stack_pointer[2] == 8 and item.language_x86_64
    assert authority([item])[0] is (not item.switches)   # (s3-off as v4)
    coverage = {item.executable_sha256: Coverage(seal=seal)}
    assert authority([item], policy="s3-on", images=(item.executable_sha256,),
                     seals={item.executable_sha256: seal}, coverage=coverage)[0] is (not item.switches)


def test_a_changed_loaded_byte_is_refused_at_admission(generation):
    manifest = _manifest(generation)
    observation = json.loads(_path(generation, manifest, manifest["functions"][0]["observation_member"]).read_text())
    row = observation["instructions"][0]["address"]
    block = next(item for item in manifest["blocks"] if item.get("member_id") and item["space_id"] == row["space_id"]
                 and item["byte_start"] <= row["byte_offset"] < item["byte_start"] + item["byte_size"])
    data = bytearray(_path(generation, manifest, block["member_id"]).read_bytes())
    data[row["byte_offset"] - block["byte_start"]] ^= 0xFF
    _replace_member(generation, manifest, block["member_id"], bytes(data))
    _reseal(generation, manifest)
    with pytest.raises(BundleAdmissionError, match="listing digest"):
        bundle_stack_evidence(generation)


def test_a_changed_override_fact_is_refused_at_admission(generation):
    manifest = _manifest(generation)
    _replace_observation(generation, manifest, 0,
                         lambda raw: raw["instructions"][0]["override"].update(length_overridden=True))
    _reseal(generation, manifest)
    with pytest.raises(BundleAdmissionError, match="listing digest"):
        bundle_stack_evidence(generation)


def test_evidence_of_another_executable_is_refused_at_admission(generation):
    manifest = _manifest(generation)
    member = manifest["stack_switch_evidence_member"]
    evidence = json.loads(_path(generation, manifest, member).read_text())
    evidence["executable_sha256"] = "0" * 64
    _replace_member(generation, manifest, member, json.dumps(evidence).encode())
    _reseal(generation, manifest)
    with pytest.raises(BundleAdmissionError, match="another executable"):
        bundle_stack_evidence(generation)


def test_another_seal_is_not_this_bundles(generation):
    item = bundle_stack_evidence(generation)   # (inapplicable, verified: the seal is checked first -- r2 P1-1)
    allowed, reasons = authority([item], policy="s3-on", images=(item.executable_sha256,),
                                 seals={item.executable_sha256: "0" * 64})
    assert not allowed and any("not bound to the run's verified Bundle" in reason for reason in reasons)


def test_a_function_that_stops_declaring_the_profile_is_refused_alone(generation):
    """r3 part 1: the reader refuses a function whose observation does not declare the Bundle's profile (its
    rows keep their fields, so the sealed evidence still verifies)."""
    manifest = _manifest(generation)
    _replace_observation(generation, manifest, 0, lambda raw: raw.pop("producer_profile"))
    _reseal(generation, manifest)
    observations = _observations(generation)
    assert observations[0] is None


@pytest.mark.parametrize("change", ("a loaded byte", "an override fact", "the executable"))
def test_frozen_admission_itself_refuses_bad_evidence(generation, change):
    """Astra X-1a r2 P1-4: ``admit_frozen_bundle`` verifies before returning a snapshot -- no provider opened."""
    manifest = _manifest(generation)
    if change == "a loaded byte":
        observation = json.loads(_path(generation, manifest, manifest["functions"][0]["observation_member"]).read_text())
        row = observation["instructions"][0]["address"]
        block = next(item for item in manifest["blocks"] if item.get("member_id")
                     and item["space_id"] == row["space_id"]
                     and item["byte_start"] <= row["byte_offset"] < item["byte_start"] + item["byte_size"])
        data = bytearray(_path(generation, manifest, block["member_id"]).read_bytes())
        data[row["byte_offset"] - block["byte_start"]] ^= 0xFF
        _replace_member(generation, manifest, block["member_id"], bytes(data))
    elif change == "an override fact":
        _replace_observation(generation, manifest, 0,
                             lambda raw: raw["instructions"][0]["override"].update(fallthrough_overridden=True))
    else:
        member = manifest["stack_switch_evidence_member"]
        evidence = json.loads(_path(generation, manifest, member).read_text())
        evidence["executable_sha256"] = "0" * 64
        _replace_member(generation, manifest, member, json.dumps(evidence).encode())
    _reseal(generation, manifest)
    with pytest.raises(BundleAdmissionError, match="stack-switch evidence"):
        admit_frozen_bundle(generation)


def test_admission_reads_each_block_once(generation, monkeypatch):
    """Astra X-1a r2 P2-6 / r3 #6: frozen admission reads only the row slices of the blocks (bytes read bounded
    by the blocks), never hashes a member a second time, and reads only the original's headers."""
    from tdo_v2.integration import configured_bundle

    sliced, hashed = [], []
    read_slice, hash_member = configured_bundle._read_slice, configured_bundle._hash_member

    def counting_slice(generation_fd, record, offset, length):
        data = read_slice(generation_fd, record, offset, length)
        sliced.append((record.handle.member_id, len(data)))
        return data

    def counting_hash(generation_fd, record, member):
        hashed.append(member.member_id)
        return hash_member(generation_fd, record, member)

    monkeypatch.setattr(configured_bundle, "_read_slice", counting_slice)
    monkeypatch.setattr(configured_bundle, "_hash_member", counting_hash)
    provider = read_configured_bundle(admit_frozen_bundle(generation))
    try:
        assert provider.stack_switch_evidence().verified
    finally:
        provider.close()
    manifest = _manifest(generation)
    sizes = {row["member_id"]: row["byte_size"] for row in manifest["blocks"] if row.get("member_id")}
    block_bytes = sum(size for member, size in sliced if member in sizes)
    assert hashed == []   # (the frozen path checked every member already)
    assert 0 < block_bytes <= sum(sizes.values())
    original = next(row["size"] for row in manifest["members"] if row["id"] == "original")
    assert sum(size for member, size in sliced if member == "original") < original
