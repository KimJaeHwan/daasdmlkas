"""X-1a (design_x1 r3 part 1 amendment): the Bundle-level producer profile is atomic.

A copy of a real sealed Bundle (the clang-x64-O0 corpus generation; skipped where it is absent) is edited and
resealed: the manifest declares ``producer_profile`` with its sealed ``stack_switch_evidence_member`` in the last
role slot, and every function observation declares the same profile with the per-row fields. Anything less --
a profile without its evidence member, an evidence member out of its slot, an unknown profile, or a function
observation that does not declare the Bundle's profile -- is a defect: admission fails, or that function is
refused. A legacy Bundle (no profile) admits as before."""

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

SOURCE = Path(os.environ.get(
    "TDO_X1_PROFILE_BUNDLE",
    "/root/tdo_bundles3/corpus/clang-x64-O0/dff1d959f1084aef660507e8cf5fcf3492e591e0f976a5fa56133dae9e8db642"))
EVIDENCE = {"format": "tdo-v2-stack-switch-evidence", "version": 2, "fixture": True}


@pytest.fixture
def generation(tmp_path):
    if not SOURCE.is_dir():
        pytest.skip(f"no sealed Bundle at {SOURCE}")
    target = tmp_path / SOURCE.name
    shutil.copytree(SOURCE, target)
    for path in [target, *target.iterdir()]:
        path.chmod(0o750 if path.is_dir() else 0o640)
    return target


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _member(manifest: dict, member_id: str) -> dict:
    return next(row for row in manifest["members"] if row["id"] == member_id)


def _rewrite(generation: Path, manifest: dict, member_id: str, data: bytes) -> str:
    """Replace one member's bytes; returns the old SHA-256."""
    row = _member(manifest, member_id)
    old = row["sha256"]
    (generation / row["path"]).write_bytes(data)
    row["size"], row["sha256"] = len(data), _sha(data)
    return old


def _reseal(generation: Path, manifest: dict) -> None:
    data = json.dumps(manifest, separators=(",", ":")).encode()
    (generation / "manifest.json").write_bytes(data)
    seal = json.loads((generation / "seal.json").read_text())
    seal["manifest_size"], seal["manifest_sha256"] = len(data), _sha(data)
    (generation / "seal.json").write_text(json.dumps(seal, separators=(",", ":")))


def _declare(generation: Path, *, functions=True, skip=None, evidence=True, slot="last", profile=PRODUCER_PROFILE_X1):
    """Edit the copy into a profiled Bundle (or a defective variant) and reseal it."""
    manifest = json.loads((generation / "manifest.json").read_text())
    if functions:
        for index, row in enumerate(manifest["functions"]):
            if index == skip:
                continue
            member = _member(manifest, row["observation_member"])
            observation = json.loads((generation / member["path"]).read_text())
            observation["producer_profile"] = PRODUCER_PROFILE_X1
            for instruction in observation["instructions"]:
                instruction["override"] = {"flow_override": "NONE", "fallthrough_overridden": False,
                                           "length_overridden": False, "override_references": []}
                instruction["recorded_landing_pads"] = []
            old = _rewrite(generation, manifest, row["observation_member"],
                           json.dumps(observation, separators=(",", ":")).encode())
            new = _member(manifest, row["observation_member"])["sha256"]
            for sidecar in (row["call_names_member"], row["call_effects_member"]):
                path = generation / _member(manifest, sidecar)["path"]
                _rewrite(generation, manifest, sidecar, path.read_bytes().replace(old.encode(), new.encode()))
    if evidence:
        data = json.dumps(EVIDENCE).encode()
        (generation / "stack-switch-evidence.json").write_bytes(data)
        record = {"id": "stack-switch-evidence", "path": "stack-switch-evidence.json", "size": len(data),
                  "sha256": _sha(data)}
        if slot == "last":
            manifest["members"].append(record)
        else:
            manifest["members"].insert(2, record)
        manifest["stack_switch_evidence_member"] = "stack-switch-evidence"
    if profile is not None:
        manifest["producer_profile"] = profile
    _reseal(generation, manifest)


def _observations(generation: Path) -> list:
    adapter = _ObservedScopeProvider(read_configured_bundle(admit_frozen_bundle(generation)))
    result = []
    with open_configured_extraction(adapter, _mint_orchestrator_capability()) as session:
        for unit in session.iter_scoped_functions():
            adapter.collect_function_roles()
            result.append(unit.observation)
    return result


def test_a_legacy_bundle_admits_as_before(generation):
    observations = _observations(generation)
    assert observations and all(item is not None and item.producer_profile is None for item in observations)


def test_a_full_profile_with_placeholder_evidence_is_refused(generation):
    """Astra X-1a r1 P1-3: normal admission verifies the sealed evidence -- a structurally complete profile
    whose evidence member is a placeholder is refused (the real-export positive case is in
    test_x1_bundle_evidence)."""
    _declare(generation)
    with pytest.raises(BundleAdmissionError, match="stack-switch evidence"):
        _observations(generation)


@pytest.mark.parametrize("variant", ("no evidence member", "evidence out of its slot", "unknown profile",
                                     "evidence without profile"))
def test_a_partial_bundle_profile_is_refused(generation, variant):
    if variant == "no evidence member":
        _declare(generation, evidence=False)
    elif variant == "evidence out of its slot":
        _declare(generation, slot="early")
    elif variant == "unknown profile":
        _declare(generation, profile="x1-producer-v0")
    else:
        _declare(generation, functions=False, profile=None)
    with pytest.raises(BundleAdmissionError):
        _observations(generation)


def test_a_profiled_function_in_a_legacy_bundle_is_refused(generation):
    _declare(generation, evidence=False, profile=None)
    observations = _observations(generation)
    assert observations and all(item is None for item in observations)


def test_a_format_1_bundle_reads_as_before(generation, tmp_path):
    """Astra X-1a r1 P1-1: the profile check lives on the shared provider -- a format-1 Bundle (made here from the
    corpus generation: observations only) reads through the compatibility provider with the same observation
    digests as the format-2 admission."""
    from tdo_v2._configured_bundle_reader import read_configured_bundle_v1_compatibility
    from tdo_v2._scope_wire import _observation_digest
    from tdo_v2.integration.configured_bundle import ConfiguredBundleCapture

    expected = [_observation_digest(item) for item in _observations(generation)]
    manifest = json.loads((generation / "manifest.json").read_text())
    root = tmp_path / "v1root"
    root.mkdir(mode=0o750)
    with ConfiguredBundleCapture(root) as capture:
        target = capture.published_path
        target.mkdir(mode=0o750)
        keep = {"original", "program", *(row["member_id"] for row in manifest["blocks"] if row.get("member_id")),
                *(row["observation_member"] for row in manifest["functions"])}
        members = [row for row in manifest["members"] if row["id"] in keep]
        for row in members:
            shutil.copy2(generation / row["path"], target / row["path"])
            (target / row["path"]).chmod(0o640)
        v1 = {"schema_version": 1, "generation_id": capture.generation_hex, "original_member_id": "original",
              "program_member_id": "program", "members": members, "blocks": manifest["blocks"],
              "functions": [{"id": row["id"], "member_id": row["observation_member"]}
                            for row in manifest["functions"]]}
        data = json.dumps(v1, separators=(",", ":")).encode()
        (target / "manifest.json").write_bytes(data)
        (target / "seal.json").write_text(json.dumps(
            {"schema_version": 1, "generation_id": capture.generation_hex, "manifest_size": len(data),
             "manifest_sha256": _sha(data)}, separators=(",", ":")))
        for path in (target / "manifest.json", target / "seal.json"):
            path.chmod(0o640)
        provider = read_configured_bundle_v1_compatibility(capture.admit_published_v1_compatibility())
        with open_configured_extraction(provider, _mint_orchestrator_capability()) as session:
            digests = [None if unit.observation is None else _observation_digest(unit.observation)
                       for unit in session.iter_scoped_functions()]
    assert digests == expected and all(item is not None for item in digests)


def test_live_admission_refuses_placeholder_evidence(generation, tmp_path):
    """Astra X-1a r2 P1-4: the live path verifies before returning a snapshot and receipt."""
    from tdo_v2.integration.configured_bundle import ConfiguredBundleCapture

    _declare(generation)
    root = tmp_path / "liveroot"
    root.mkdir(mode=0o750)
    with ConfiguredBundleCapture(root) as capture:
        target = capture.published_path
        shutil.copytree(generation, target)
        for path in [target, *target.iterdir()]:
            path.chmod(0o750 if path.is_dir() else 0o640)
        manifest = json.loads((target / "manifest.json").read_text())
        manifest["generation_id"] = capture.generation_hex
        data = json.dumps(manifest, separators=(",", ":")).encode()
        (target / "manifest.json").write_bytes(data)
        seal = json.loads((target / "seal.json").read_text())
        seal.update(generation_id=capture.generation_hex, manifest_size=len(data), manifest_sha256=_sha(data))
        (target / "seal.json").write_text(json.dumps(seal, separators=(",", ":")))
        with pytest.raises(BundleAdmissionError, match="stack-switch evidence"):
            capture.admit_published_with_receipt()
