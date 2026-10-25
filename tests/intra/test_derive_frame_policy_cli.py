"""Expose the existing derivation policy without changing its default."""

import importlib.util
import json
from pathlib import Path

import pytest


@pytest.mark.parametrize("flags,expected", (((), True), (("--no-assume-entry-values-not-frame",), False)))
def test_cli_passes_the_requested_frame_policy_to_the_existing_deriver(tmp_path, monkeypatch, flags, expected):
    location = Path(__file__).resolve().parents[2] / "tools" / "derive_models" / "derive_models.py"
    spec = importlib.util.spec_from_file_location("frame_policy_derive_cli", location)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    called = []

    def derive(*args, **options):
        called.append((args, options))
        return {"entries": []}, {}, []

    monkeypatch.setattr(module, "derive_library", derive)
    output = tmp_path / "models" / "requested.json"
    args = [str(tmp_path / "sealed-generation"), "--library", "CORE.DLL", "--export", "ctor",
            "--id", "derived-core-test", "--version", "7", "--private-frame-above", "0x28",
            "-o", str(output), *flags]
    assert module.main(args) == 0
    assert len(called) == 1
    positional, options = called[0]
    assert positional[1:] == ("CORE.DLL", ["ctor"])
    assert options["entry_values_not_frame"] is expected
    assert options["private_frame_above"] == 0x28  # derive_library deactivates this when frame is OFF
    assert options["version"] == 7 and options["file_id"] == "derived-core-test"
    assert json.loads(output.read_text()) == {"entries": []}


def test_unknown_frame_policy_flag_is_not_silently_accepted(tmp_path):
    location = Path(__file__).resolve().parents[2] / "tools" / "derive_models" / "derive_models.py"
    spec = importlib.util.spec_from_file_location("invalid_frame_policy_derive_cli", location)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with pytest.raises(SystemExit) as error:
        module.main(["generation", "--library", "CORE.DLL", "--export", "ctor", "--id", "test",
                     "-o", str(tmp_path / "out.json"), "--entry-values-not-frame=0"])
    assert error.value.code == 2
    assert not (tmp_path / "out.json").exists()
