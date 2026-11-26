"""X-1a (design_x1 r3 4.1 / 4.2, r4 4.2): a real headless export with the X-1 exporter.

``TDO_X1_EXPORTED_BUNDLE`` names a generation exported by ``tools/bundle_export/export_bundle.py`` with this
tree's exporter (skipped when unset or absent). The exporter scanned its locked program inside the export
session and sealed the v2 evidence as the last member; the engine admits the Bundle (every function declares
the producer profile), reads the evidence bound to the Bundle's seal, and recomputes the verifiable part of the
listing digest from the sealed observations and block members. Changing one loaded byte, one override fact or
the seal breaks the binding."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from tdo_v2._configured_bundle_reader import read_configured_bundle
from tdo_v2._scope_contracts import PRODUCER_PROFILE_X1, _mint_orchestrator_capability
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import _ObservedScopeProvider
from tdo_v2.scope_identity import open_configured_extraction
from tdo_v2.stack_evidence import Coverage, EvidenceError, authority, bundle_stack_evidence

SOURCE = Path(os.environ.get(
    "TDO_X1_EXPORTED_BUNDLE",   # (exported 2026-11-27 from the clang-x64-O0 corpus binary, --entry 433 1057856)
    "/root/x1_export_test/149c1cb8c70d3933c0fa74009fbf01d4fa7391d071db8cccd30376fe8e3141f3"))


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


def _reseal(generation: Path, manifest: dict) -> None:
    data = json.dumps(manifest, separators=(",", ":")).encode()
    (generation / "manifest.json").write_bytes(data)
    seal = json.loads((generation / "seal.json").read_text())
    seal["manifest_size"], seal["manifest_sha256"] = len(data), hashlib.sha256(data).hexdigest()
    (generation / "seal.json").write_text(json.dumps(seal, separators=(",", ":")))


def _replace_member(generation: Path, manifest: dict, member_id: str, data: bytes) -> None:
    row = next(item for item in manifest["members"] if item["id"] == member_id)
    (generation / row["path"]).write_bytes(data)
    row["size"], row["sha256"] = len(data), hashlib.sha256(data).hexdigest()


def test_the_exported_bundle_is_profiled_and_admitted(generation):
    manifest = _manifest(generation)
    assert manifest["producer_profile"] == PRODUCER_PROFILE_X1
    assert manifest["members"][-1]["id"] == manifest["stack_switch_evidence_member"]
    adapter = _ObservedScopeProvider(read_configured_bundle(admit_frozen_bundle(generation)))
    with open_configured_extraction(adapter, _mint_orchestrator_capability()) as session:
        observations = []
        for unit in session.iter_scoped_functions():
            adapter.collect_function_roles()
            observations.append(unit.observation)
    assert observations and all(item is not None and item.producer_profile == PRODUCER_PROFILE_X1
                                for item in observations)


def test_the_sealed_evidence_is_bound_and_verified(generation):
    item = bundle_stack_evidence(generation)
    seal = hashlib.sha256((generation / "manifest.json").read_bytes()).hexdigest()
    assert item.version == 2 and item.bound and item.seal == seal
    assert authority([item])[0] is (not item.switches)   # (s3-off as v4)
    covered = frozenset(row.site for row in item.kernel_transfers if row.kind == "covered")
    traps = frozenset(row.site for row in item.kernel_transfers if row.kind == "trap")
    allowed, reasons = authority([item], policy="s3-on", images=(item.executable_sha256,),
                                 seals={item.executable_sha256: seal},
                                 coverage={item.executable_sha256: Coverage(covered, traps)})
    assert allowed is (not item.on_switches and all(row.kind in ("covered", "trap") for row in item.kernel_transfers))


def test_a_changed_loaded_byte_breaks_the_binding(generation):
    manifest = _manifest(generation)
    observation = json.loads((generation / next(
        item["path"] for item in manifest["members"]
        if item["id"] == manifest["functions"][0]["observation_member"])).read_text())
    row = observation["instructions"][0]["address"]
    block = next(item for item in manifest["blocks"] if item.get("member_id") and item["space_id"] == row["space_id"]
                 and item["byte_start"] <= row["byte_offset"] < item["byte_start"] + item["byte_size"])
    path = generation / next(item["path"] for item in manifest["members"] if item["id"] == block["member_id"])
    data = bytearray(path.read_bytes())
    index = row["byte_offset"] - block["byte_start"]
    data[index] ^= 0xFF
    _replace_member(generation, manifest, block["member_id"], bytes(data))
    _reseal(generation, manifest)
    with pytest.raises(EvidenceError):
        bundle_stack_evidence(generation)


def test_a_changed_override_fact_breaks_the_binding(generation):
    manifest = _manifest(generation)
    member = manifest["functions"][0]["observation_member"]
    path = generation / next(item["path"] for item in manifest["members"] if item["id"] == member)
    observation = json.loads(path.read_text())
    observation["instructions"][0]["override"]["length_overridden"] = True
    _replace_member(generation, manifest, member, json.dumps(observation).encode())
    _reseal(generation, manifest)
    with pytest.raises(EvidenceError):
        bundle_stack_evidence(generation)


def test_another_seal_is_not_this_bundles(generation):
    item = bundle_stack_evidence(generation)
    allowed, reasons = authority([item], policy="s3-on", seals={item.executable_sha256: "0" * 64})
    assert not allowed and any("not bound to the run's verified Bundle" in reason for reason in reasons)
