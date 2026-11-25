"""G1 producer-guard fields (design r1 s6, r2 s6, r3 s8, r4 s8): the S1 guard
condition recomputed from the Bundle's inputs, kept apart from whether the guard
fired when the Bundle was produced (never decidable from the Bundle).

The guard reproduced is the exporter's ``cpuDependentLength`` (G3b-7b r9g / r9e,
Astra r10-r12; main 18a5f5e ghidra/GhidraV2BundleExport.java): on x86-64 a
function loses S1 when one of its rows is a control transfer -- the prototype's
flow is a jump / call / terminal, or the row holds a CALL / CALLIND op -- whose
leading prefix bytes (legacy prefixes and REX) contain 66 or repeat a byte,
scanned up to the first non-prefix byte. This branch's exporter (engine base
50f28f8) predates that guard.

The Bundle carries the row's p-code but not the prototype's flow (the exported
flow type includes overrides). The prototype's jump / call / terminal flags come
from the same constructor p-code, so "is a control transfer" is read from the
row's p-code where it decides (``transfers``); a transfer row is decided by the
prefix scan. Only verified bytes are scanned.

Pure functions over plain data (Rust-port surface).
"""

from __future__ import annotations

REVISION = "cpuDependentLength G3b-7b r9g (main 18a5f5e exporter)"
LONG_MODE = "x86:LE:64:default"
LEGACY_PREFIXES = frozenset((0x66, 0xF0, 0x67, 0xF2, 0xF3, 0x2E, 0x3E, 0x26, 0x36, 0x64, 0x65))
FIRED_AT_PRODUCTION = "unobserved"   # (the Bundle does not say which exporter guards ran)
UNOBSERVED = "unobserved"


def _is_prefix(value: int) -> bool:
    return value in LEGACY_PREFIXES or 0x40 <= value <= 0x4F


def prefix_scan(data: bytes, length: int | None):
    """True when the prefix run holds 66 or a repeated byte, False when it ends
    without, None when the verified bytes end before it decides."""
    seen = set()
    end = len(data) if length is None else min(length, len(data))
    for value in data[:end]:
        if not _is_prefix(value):
            return False
        if value == 0x66 or value in seen:
            return True
        seen.add(value)
    if length is not None and len(data) >= length:
        return False   # (the whole instruction is prefixes without a repeat: the exporter's loop ends false)
    return None


SKIP_PATTERNS = ("rep", "cmov")              # (lifting.identify: intra-instruction skips, r4 s1)
BRANCH_PATTERNS = ("jmp", "jcc", "call $+5")   # (identified real transfers whose target may be start / next)


def transfers(facts: dict, lift=None):
    """Whether the row is a control transfer for the prototype's flow: True / False / "unobserved".

    CALL / CALLIND / BRANCHIND / RETURN are transfers; BRANCH / CBRANCH to a constant
    destination (a p-code relative index) are not. A BRANCH / CBRANCH to an address is
    a transfer only when that is decidable: the lift table (premise
    stock-ghidra-translator) identifies a jmp / jcc / call $+5, or the target is
    neither the row's start nor its next address (which needs the length). The rep /
    cmov patterns transfer nothing (the exporter: "a 16-bit CMOVcc ... transfers
    nothing"); any other case -- no lift, an unidentified or other pattern, a missing
    length -- is "unobserved". A row without a transfer op whose exported flow bits
    still say call / jump / terminal (a call fixup may have replaced the p-code) is
    "unobserved" too (Fable impl r1 P3)."""
    flow = facts.get("flow") or {}
    says_transfer = bool(flow.get("is_call") or flow.get("is_jump") or flow.get("is_terminal"))
    if lift is not None and lift.pattern in SKIP_PATTERNS:
        # (a cmov / rep row whose exported flow bits still say transfer: a fixup may have changed it)
        return UNOBSERVED if says_transfer else False
    start = facts.get("address")
    length = facts.get("length")
    nxt = None if length is None or start is None else start + length
    doubt = False
    found = False
    for op in facts.get("ops", ()):
        if op["opcode"] in ("CALL", "CALLIND", "BRANCHIND", "RETURN"):
            return True
        if op["opcode"] not in ("BRANCH", "CBRANCH"):
            continue
        target = (op.get("inputs") or [None])[0]
        if target is not None and target.get("kind") == "CONSTANT":
            continue
        found = True
        if lift is not None and lift.pattern in BRANCH_PATTERNS:
            return True
        offset = None if target is None else target.get("offset")
        if nxt is not None and offset is not None and offset not in (start, nxt):
            return True
        doubt = True
    if doubt or found or says_transfer:
        return UNOBSERVED
    return False


def row_condition(facts: dict, verified: bytes, lift=None):
    """The recomputed per-row condition: True / False / "unobserved"."""
    moves = transfers(facts, lift)
    if moves is False:
        return False
    scan = prefix_scan(verified, facts.get("length"))
    if scan is False:
        return False
    if scan is None or moves == UNOBSERVED:
        return UNOBSERVED
    return True


def function_condition(language: str, conditions: list):
    """The function's recomputed condition: the guard applies only on x86-64."""
    if language != LONG_MODE:
        return False
    if any(item is True for item in conditions):
        return True
    if any(item == UNOBSERVED for item in conditions):
        return UNOBSERVED
    return False
