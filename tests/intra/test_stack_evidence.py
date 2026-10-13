"""Whole-program stack-switch evidence (``tdo_v2.stack_evidence``): the file
format, and when globals-disjoint-from-stack may be taken."""

import json
from pathlib import Path

import pytest

from tdo_v2.stack_evidence import EvidenceError, assumption_allowed, load_stack_evidence

CORE = "fdea959764879bb55602c88a80a1adf6307b637c0c04f4b01f2e28c2fcb7b942"
PLUGIN = "2b17d005adcde0e25673aaf58e3bd39423e0ff24965f2782b5a33345cb691c0c"


def _file(directory, name, sha, switches=(), functions=10, **changes):
    raw = {"format": "tdo-v2-stack-switch-evidence", "version": 1, "detector": "stack-switch-coefficient-v3",
           "executable_sha256": sha, "program": f"/libs/{name}", "language": "x86:LE:64:default",
           "stack_pointer": "RSP", "functions_scanned": functions, "instructions_scanned": 100,
           "instructions_outside_functions": 3, "call_preserved": ["RBX", "RBP", "R12", "R13", "R14", "R15"],
           "exceptions": ["loaded-and-call-result-values-hold-no-stack-pointer", "user-ops-change-only-their-output",
                          "calls-preserve-the-common-nonvolatile-registers"],
           "switches": [{"function": "180001000", "instruction": address, "ordinal": 1, "opcode": "COPY"}
                        for address in switches]}
    raw.update(changes)
    path = Path(directory) / f"{name}.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def test_clean_evidence_allows_the_assumption(tmp_path):
    core = load_stack_evidence(_file(tmp_path, "CORE", CORE))
    assert core.clean and "no switch" in core.describe()
    allowed, lines = assumption_allowed([core], requested=True, require_for=CORE)
    assert allowed and len(lines) == 1


def test_a_switch_in_any_evidence_withdraws_it(tmp_path):
    """A library's switch matters to the program too (one process)."""
    plugin = load_stack_evidence(_file(tmp_path, "PLUGIN", PLUGIN))
    core = load_stack_evidence(_file(tmp_path, "CORE", CORE, switches=["180002000"]))
    allowed, lines = assumption_allowed([plugin, core], requested=True)
    assert not allowed and "withdrawn" in lines[-1] and "CORE" in lines[-1]


def test_a_derivation_needs_the_librarys_own_evidence(tmp_path):
    plugin = load_stack_evidence(_file(tmp_path, "PLUGIN", PLUGIN))
    allowed, lines = assumption_allowed([plugin], requested=True, require_for=CORE)
    assert not allowed and "no whole-program stack evidence" in lines[-1]
    assert assumption_allowed([], requested=True, require_for=CORE)[0] is False


def test_not_requested_is_never_taken(tmp_path):
    core = load_stack_evidence(_file(tmp_path, "CORE", CORE))
    assert assumption_allowed([core], requested=False)[0] is False


def test_an_empty_scan_is_not_clean(tmp_path):
    assert not load_stack_evidence(_file(tmp_path, "CORE", CORE, functions=0)).clean
    assert not load_stack_evidence(_file(tmp_path, "CORE", CORE, instructions_scanned=0)).clean


def test_the_java_scanner_writes_the_detector_this_engine_accepts():
    """GhidraV2StackSwitchScan.DETECTOR and stack_evidence.DETECTORS move together."""
    import re

    from tdo_v2.stack_evidence import DETECTORS

    source = (Path(__file__).resolve().parents[2] / "ghidra" / "GhidraV2StackSwitchScan.java").read_text(
        encoding="utf-8")
    assert re.search(r'DETECTOR = "([^"]+)"', source).group(1) == DETECTORS[-1]


@pytest.mark.parametrize("change", [{"format": "other"}, {"detector": "stack-switch-coefficient-v2"},
                                    {"exceptions": []}, {"call_preserved": "RBX"},
                                    {"executable_sha256": "xyz"}, {"functions_scanned": -1},
                                    {"extra": 1}, {"version": True}, {"language": 5}])
def test_malformed_evidence_is_rejected(tmp_path, change):
    with pytest.raises(EvidenceError):
        load_stack_evidence(_file(tmp_path, "CORE", CORE, **change))
