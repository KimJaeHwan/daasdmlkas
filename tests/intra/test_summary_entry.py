"""The summary engine's in-memory entry (docs 25.30 K2):
``analyze_observed_with_summaries`` on the SAME admitted evidence and image
inputs gives the same EngineRun as ``analyze_frozen_bundle_with_summaries``
(witnesses, records, projected sinks, assumptions, failure roots included)."""

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _generation():
    # (a Bundle with sealed image facts: the image inputs are part of the comparison)
    root = Path("/root/tdo_bundles3/v3-win32-release-full")
    found = sorted(path for path in root.glob("*/") if path.is_dir()) if root.is_dir() else []
    return found[0] if found else None


@pytest.mark.skipif(_generation() is None, reason="v3-win32-release-full Bundle not exported here")
def test_the_observed_entry_equals_the_bundle_entry():
    sys.path.insert(0, str(REPO / "tools" / "bundle_export"))
    sys.path.insert(0, str(REPO / "tools" / "graph_fidelity"))
    import run_dfbench
    from semantic_snapshot import encode
    from tdo_v2 import summary_engine
    from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
    from tdo_v2.image_info import ReadOnlyImage, load_image_info
    from tdo_v2.integration.configured_bundle import admit_frozen_bundle
    from tdo_v2.integration.observed_function_session import open_observed_function_session
    from hashlib import sha256

    generation = _generation()
    exporter = REPO / "ghidra" / "GhidraV2CallNaming.java"
    options = dict(boundary_provider=run_dfbench.boundary_provider(False, run_dfbench.abi_of(generation)),
                   pcodeop_models=run_dfbench.pcodeop_models(), external_models=run_dfbench.external_models(generation),
                   origin_witnesses=True, operation_records=True)
    expected = summary_engine.analyze_frozen_bundle_with_summaries(
        generation, naming_exporter_source=exporter, **options)
    binding = NamingBindingExpectation(sha256(exporter.read_bytes()).digest(), CALL_NAMING_GHIDRA_VERSION)
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        program = session.program_result
        evidences = list(session.iter_functions())   # (materialized on the session's own thread)
        image_info = load_image_info(generation)
        found = summary_engine.analyze_observed_with_summaries(
            program, evidences, image_info=image_info,
            readonly_image=ReadOnlyImage(generation, image_info) if image_info is not None else None,
            **options)
    assert encode(found) == encode(expected)
    assert expected.roots   # (a non-vacuous comparison)
