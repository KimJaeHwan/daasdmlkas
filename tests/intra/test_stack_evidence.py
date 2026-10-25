"""Whole-program stack-switch evidence (``tdo_v2.stack_evidence``): the file
format, and when globals-disjoint-from-stack may be taken."""

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from tdo_v2.stack_evidence import (
    CONSERVATIVE_EXCEPTIONS, DETECTORS, EXCEPTIONS, EvidenceError, assumption_allowed, load_stack_evidence,
)

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


def test_conservative_v4_evidence_has_no_language_preservation(tmp_path):
    item = load_stack_evidence(_file(
        tmp_path, "CORE", CORE, detector=DETECTORS[-1], call_preserved=[],
        exceptions=list(CONSERVATIVE_EXCEPTIONS)))
    assert item.clean and item.call_preserved == ()
    assert "conservative unknown post-call registers" in item.describe()
    assert assumption_allowed([item], requested=True, require_for=CORE)[0]


def test_legacy_v3_keeps_its_declared_names_and_exceptions(tmp_path):
    item = load_stack_evidence(_file(tmp_path, "CORE", CORE))
    assert item.detector == DETECTORS[0]
    assert item.call_preserved == ("RBX", "RBP", "R12", "R13", "R14", "R15")
    assert "legacy declared preservation RBX,RBP,R12,R13,R14,R15" in item.describe()
    assert "proof" not in item.describe()


@pytest.mark.parametrize("changes", (
    {"detector": DETECTORS[-1]},  # v3 evidence cannot just be relabeled v4
    {"detector": DETECTORS[-1], "call_preserved": [], "exceptions": list(EXCEPTIONS)},
    {"detector": DETECTORS[-1], "call_preserved": ["RBX"], "exceptions": list(CONSERVATIVE_EXCEPTIONS)},
    {"detector": DETECTORS[0], "exceptions": list(CONSERVATIVE_EXCEPTIONS)},
    {"detector": DETECTORS[-1], "call_preserved": [], "exceptions": list(reversed(CONSERVATIVE_EXCEPTIONS))},
))
def test_evidence_modes_cannot_borrow_each_others_assumptions(tmp_path, changes):
    with pytest.raises(EvidenceError):
        load_stack_evidence(_file(tmp_path, "CORE", CORE, **changes))


def _java_member(source, signature):
    """Compile actual scanner helpers, not a Python reimplementation."""
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def test_java_conservative_call_state_first_partial_and_join_reads(tmp_path):
    """Execute the scanner's coefficient-state helpers without Ghidra.

    This harness supplies storage coordinates and assertions only, not a
    p-code interpreter or a separate detector.
    """
    if shutil.which("javac") is None or shutil.which("java") is None:
        pytest.skip("Java compiler/runtime unavailable")
    source = (Path(__file__).resolve().parents[2] / "ghidra" / "GhidraV2StackSwitchScan.java").read_text()
    helpers = "\n".join(_java_member(source, signature) for signature in (
        "private record Loc(", "private static boolean conservativeMode(",
        "private Integer readLocation(", "private void write(",
        "private void afterCall(", "private Map<Loc, Integer> merge(", "private Map<Loc, Integer> initialState(",
    ))
    harness = """import java.util.*;
public class StackScanStateTest {
    private static final Integer UNKNOWN = null;
    private static final Loc UNKNOWN_REGISTERS = new Loc(Integer.MIN_VALUE, 0, 0);
    private Loc stack = new Loc(1, 32, 8);
    private final List<Loc> preserved = new ArrayList<>();
    private boolean conservative = true;
    static void check(boolean ok) { if (!ok) throw new AssertionError(); }
""" + helpers + """
    public static void main(String[] args) {
        StackScanStateTest scanner = new StackScanStateTest();
        check(conservativeMode("conservative") && !conservativeMode("legacy-v3"));
        try { conservativeMode("v4"); throw new AssertionError(); }
        catch (IllegalArgumentException expected) { }
        Loc rbx = new Loc(1, 24, 8), rcx = new Loc(1, 8, 8), rax = new Loc(1, 0, 8);
        Loc al = new Loc(1, 0, 1), ah = new Loc(1, 1, 1), eax = new Loc(1, 0, 4);
        Loc unique = new Loc(2, 0, 8);
        check(scanner.readLocation(scanner.initialState(false), rax) == null);
        check(scanner.readLocation(scanner.initialState(false), scanner.stack) == 1);
        check(scanner.readLocation(scanner.initialState(true), rax) == 0);
        Map<Loc, Integer> initial = new HashMap<>();
        initial.put(scanner.stack, 1);
        initial.put(rbx, 1);
        initial.put(rcx, 0);
        initial.put(unique, 1);
        Map<Loc, Integer> state = new HashMap<>(initial);
        scanner.afterCall(state);
        check(scanner.readLocation(state, rbx) == null); // common nonvolatile too
        check(scanner.readLocation(state, rcx) == null); // previous explicit zero
        check(scanner.readLocation(state, rax) == null); // first read after call
        check(scanner.readLocation(state, eax) == null); // first partial read
        check(scanner.readLocation(state, scanner.stack) == 1);
        check(scanner.readLocation(state, unique) == 1); // original pre-call temporary
        scanner.write(state, al, 0);
        check(scanner.readLocation(state, al) == 0);
        check(scanner.readLocation(state, ah) == null);
        check(scanner.readLocation(state, rax) == null); // partial zero is not full zero
        scanner.write(state, rax, 0);
        check(scanner.readLocation(state, eax) == 0); // covered explicit write
        scanner.write(state, rax, 1);
        scanner.write(state, al, 0);
        check(scanner.readLocation(state, rax) == null); // surviving bytes unknown
        check(scanner.readLocation(state, al) == 0);
        Map<Loc, Integer> called = new HashMap<>(initial);
        scanner.afterCall(called);
        Map<Loc, Integer> joined = scanner.merge(initial, called);
        check(scanner.readLocation(joined, rbx) == null);
        check(scanner.readLocation(joined, rax) == null); // absent on both paths
        scanner.write(called, rax, 0);
        Map<Loc, Integer> zeroJoined = scanner.merge(initial, called);
        check(scanner.readLocation(zeroJoined, rax) == 0); // exactly zero on both paths
        scanner.conservative = false;
        check(scanner.readLocation(scanner.initialState(false), rax) == 0);
        scanner.preserved.add(rbx);
        state = new HashMap<>(initial);
        scanner.afterCall(state);
        check(scanner.readLocation(state, rbx) == 1); // explicit legacy behavior
        check(scanner.readLocation(state, rax) == 0);
    }
}
"""
    path = tmp_path / "StackScanStateTest.java"
    path.write_text(harness)
    subprocess.run(["javac", str(path)], check=True, capture_output=True, text=True, timeout=30)
    subprocess.run(["java", "-cp", str(tmp_path), "StackScanStateTest"],
                   check=True, capture_output=True, text=True, timeout=30)
    # Both function and outside regions use the selected mode and call transfer.
    assert 'private boolean conservative = true;' in source
    assert 'case "--mode" -> conservative = conservativeMode(args[index + 1]);' in source
    assert 'evidence.put("detector", conservative ? DETECTOR : LEGACY_DETECTOR);' in source
    assert 'evidence.put("exceptions", conservative ? EXCEPTIONS : LEGACY_EXCEPTIONS);' in source
    assert 'preservedNames = conservative ? List.of()' in source
    assert 'afterCall(state);' in source and 'merged = merge(known, state);' in source
    assert 'scan(null, outside, "(outside functions)", listing, switches)' in source
    assert 'initialState(entry != null && start.equals(entry))' in source


@pytest.mark.parametrize("change", [{"format": "other"}, {"detector": "stack-switch-coefficient-v2"},
                                    {"exceptions": []}, {"call_preserved": "RBX"},
                                    {"executable_sha256": "xyz"}, {"functions_scanned": -1},
                                    {"extra": 1}, {"version": True}, {"language": 5}])
def test_malformed_evidence_is_rejected(tmp_path, change):
    with pytest.raises(EvidenceError):
        load_stack_evidence(_file(tmp_path, "CORE", CORE, **change))
