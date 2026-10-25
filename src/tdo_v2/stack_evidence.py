"""Whole-program stack-switch evidence (design section 24.1, decision 6).

The named assumption globals-disjoint-from-stack (a constant address never
falls in the stack) fails for a process whose code runs on a stack placed in
static data (fibers, coroutines on a static buffer). The engine withdraws it
when a function it analyzes switches its stack
(``interprocedural.program_switches_stack``) -- but a Bundle holds a closure
of selected functions, no evidence about the rest of the binary.

``ghidra/GhidraV2StackSwitchScan.java`` scans EVERY function of a program
analyzed in a Ghidra project (and the instructions outside functions) with
the same MUST rule -- the stack coefficient: a write of the stack pointer with
anything but "the stack pointer + a number" is a switch
(``may_alias.stack_switches``) -- and writes an evidence file (format
``tdo-v2-stack-switch-evidence``): the program's executable SHA-256, how much
was scanned (functions, instructions -- those outside every function too)
and every switch found.

``assumption_allowed``: with evidence files given, the assumption holds only
if none of them shows a switch (a library's switch matters too: it runs in the
same process); a library derivation may take it only with clean evidence for
that very library (``tools/derive_models``). A clean scan is no proof: bytes
Ghidra never disassembled, and binaries not scanned, are outside it -- reported.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

FORMAT = "tdo-v2-stack-switch-evidence"
# the detector rule versions this engine accepts (the newest last; equal to
# GhidraV2StackSwitchScan.DETECTOR). v3 remains explicitly legacy evidence:
# it assumes language-wide nonvolatile preservation, unlike conservative v4.
DETECTORS = ("stack-switch-coefficient-v3", "stack-switch-coefficient-v4")
_FIELDS = {"format", "version", "detector", "executable_sha256", "program", "language", "stack_pointer",
           "functions_scanned", "instructions_scanned", "instructions_outside_functions", "switches",
           "call_preserved", "exceptions"}
# what a clean scan rests on besides finding no switch (the reported assumption
# stack-switch-check-exceptions): exactly these, in this order
EXCEPTIONS = ("loaded-and-call-result-values-hold-no-stack-pointer", "user-ops-change-only-their-output",
              "calls-preserve-the-common-nonvolatile-registers")
CONSERVATIVE_EXCEPTIONS = EXCEPTIONS[:2]


class EvidenceError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class StackEvidence:
    path: str
    digest: str                      # sha256 of the evidence file
    executable_sha256: str
    program: str
    call_preserved: tuple
    detector: str
    functions_scanned: int
    instructions_scanned: int
    instructions_outside_functions: int
    switches: tuple                  # (function, instruction, ordinal, opcode) per switch

    @property
    def clean(self) -> bool:
        return not self.switches and self.functions_scanned > 0 and self.instructions_scanned > 0

    def describe(self) -> str:
        found = f"{len(self.switches)} switch(es)" if self.switches else "no switch"
        calls = (f"legacy declared preservation {','.join(self.call_preserved)}"
                 if self.detector == DETECTORS[0] else "conservative unknown post-call registers")
        return (f"{self.program} (sha256 {self.executable_sha256[:12]}): {self.functions_scanned} functions, "
                f"{self.instructions_scanned} instructions scanned ({self.instructions_outside_functions} of them "
                f"outside functions); {found} [{self.detector}; {calls}; "
                f"exceptions: stack-switch-check-exceptions]")


def load_stack_evidence(path) -> StackEvidence:
    data = Path(path).read_bytes()
    try:
        raw = json.loads(data.decode("utf-8"))
    except ValueError as error:
        raise EvidenceError(f"{path}: not JSON") from error
    if type(raw) is not dict or set(raw) != _FIELDS or raw["format"] != FORMAT             or type(raw["version"]) is not int or raw["version"] != 1:
        raise EvidenceError(f"{path}: not a {FORMAT} file (version 1)")
    if any(type(raw[key]) is not str or not raw[key] for key in ("program", "language", "stack_pointer")):
        raise EvidenceError(f"{path}: program / language / stack_pointer")
    if type(raw["call_preserved"]) is not list or any(type(item) is not str for item in raw["call_preserved"]):
        raise EvidenceError(f"{path}: call_preserved")
    if raw["detector"] not in DETECTORS:
        raise EvidenceError(f"{path}: detector {raw['detector']!r} is not one this engine knows {DETECTORS}")
    exceptions = EXCEPTIONS if raw["detector"] == DETECTORS[0] else CONSERVATIVE_EXCEPTIONS
    if raw["exceptions"] != list(exceptions):
        raise EvidenceError(f"{path}: exceptions must be exactly {list(exceptions)}")
    if raw["detector"] == DETECTORS[-1] and raw["call_preserved"]:
        raise EvidenceError(f"{path}: conservative v4 call_preserved must be empty")
    sha = raw["executable_sha256"]
    if type(sha) is not str or len(sha) != 64 or any(item not in "0123456789abcdef" for item in sha):
        raise EvidenceError(f"{path}: executable_sha256")
    counts = [raw[key] for key in ("functions_scanned", "instructions_scanned", "instructions_outside_functions")]
    if any(type(item) is not int or item < 0 for item in counts) or type(raw["switches"]) is not list:
        raise EvidenceError(f"{path}: counts / switches")
    switches = []
    for row in raw["switches"]:
        if type(row) is not dict or not {"function", "instruction", "ordinal", "opcode"} <= set(row)                 or type(row["ordinal"]) is not int                 or any(type(row[key]) is not str for key in ("function", "instruction", "opcode")):
            raise EvidenceError(f"{path}: switch rows")
        switches.append((row["function"], row["instruction"], row["ordinal"], row["opcode"]))
    return StackEvidence(str(path), hashlib.sha256(data).hexdigest(), sha, str(raw["program"]),
                         tuple(raw["call_preserved"]), raw["detector"], *counts, tuple(switches))


def assumption_allowed(evidences, *, requested: bool, require_for: str | None = None) -> tuple[bool, list[str]]:
    """(whether globals-disjoint-from-stack may be taken, report lines).
    ``requested``: the run asks for it; ``require_for``: an executable SHA-256
    whose own clean evidence is required (a library derivation) -- without it
    the assumption is not taken."""
    lines = [item.describe() for item in evidences]
    if not requested:
        return False, lines
    dirty = [item for item in evidences if not item.clean]
    if dirty:
        return False, lines + [f"globals-disjoint-from-stack withdrawn: stack switch evidence in "
                               f"{', '.join(item.program for item in dirty)}"]
    if require_for is not None and not any(item.executable_sha256 == require_for for item in evidences):
        return False, lines + ["globals-disjoint-from-stack not taken: no whole-program stack evidence for "
                               f"{require_for[:12]}"]
    return True, lines


__all__ = ("DETECTORS", "EvidenceError", "FORMAT", "StackEvidence", "assumption_allowed", "load_stack_evidence")
