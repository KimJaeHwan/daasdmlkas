"""TBR G1 on X-1 producer Bundles: per-row override verdicts (design .census6/design_tbr_g1_x1_r1.md with the r2 /
r3 deltas, closed 2026-11-26; implementation review r1 fixes).

G1 attests EFFECTS only: on every attribute it compares (and the exported target set T) the exported row equals
what the bytes encode, so no override -- reported or not -- changed those values. It never attests that the
producer's override report is complete (an effect-free override reference is invisible): the verdict is
``effect_attested``, and what it discharges is TDO's decision (r1 s0, options a / b).

One code per row G1 compared (r2 s5): ``A`` effect_attested, ``S`` / ``I`` effect_attested with the syscall /
interrupt a3 exemption (OS-contract model), ``C`` contradicted, ``U`` unobserved, ``O`` override_present. A row
never compared (``*``) has no code; when its report is present it gets a ``star`` detail. A C / U / O row that used
a pin carries ``exempt`` (the pin's code), so its premises stay visible.

Pure functions of plain row facts, the comparison result, the lift, the ballot and the verified bytes
(Rust-reproducible).
"""

from __future__ import annotations

import copy

import compare
import lifting

SCHEMA = "tbr-producer-override-1"
PROFILE_X1 = "x1-producer-v1"
OS_CONTRACT = "kernel-boundary-contract"     # (S3 r16 1.2 item 5: the named OS-contract model / switch)
REPORT_PREMISE = "producer-override-report"
CODES = {"A": "effect_attested", "S": "effect_attested", "I": "effect_attested", "C": "contradicted",
         "U": "unobserved", "O": "override_present"}
DETAIL_CODES = frozenset("CUO")
REQUIRED = tuple(compare.COMPARED) + ("T",)
MODE_CONSTANT = tuple(compare.MODE_CONSTANT)        # equal: neutral (not an observation); differing: disagree
F_NAMES = tuple("F." + bit for bit in compare.F_BITS)
# exact shapes only (r3 s3 = S3 r16 1.2 item 2), bound to the verified bytes (impl r1 Astra P1-2); the exemption is
# a3 under the OS-contract model. `core_unobserved`: what G1's own comparison leaves unobserved for the shape (the
# -1 / -2 exceptions the reader allows on an S / I row); the pin supplies those values inside the verdict only
EXEMPTIONS = {
    "S": {"pattern": "syscall", "bytes": "0F 05", "attribute": "a3", "premise": OS_CONTRACT,
          "reason": "whether the OS returns after syscall is not observable",
          "core_unobserved": ["a3", "a4", "a5", "a6", "a8", "a9", "a10"] + list(F_NAMES)},
    "I": {"pattern": "interrupt", "bytes": "CD ib", "attribute": "a3", "premise": OS_CONTRACT,
          "reason": "whether the OS returns after an interrupt is not observable",
          "core_unobserved": ["a3", "a4"] + list(F_NAMES)},
}
# listing bits pinned from real rows (r2 s3): every lone-CALLOTHER row of the ntdll Bundle (16) and the userop test
# Bundle (syscall 0F 05, sysenter 0F 34) exports the plain rows' bits; every exact swi + CALLIND pair (ntdll int 29h
# x125, int 2Ch x18; userop test int 01h) exports these call / computed bits; no flow targets, fallthrough = next
PINNED_BITS = {
    "syscall": dict(lifting.LISTING_BITS["none"]),
    "interrupt": {"has_fallthrough": True, "is_call": True, "is_jump": False, "is_terminal": False,
                  "is_computed": True, "is_conditional": False, "is_flow": True, "is_unconditional": True},
}
# T (r2 s2, r3 s2): no-target patterns whose exported flow_targets were empty on every real row (ntdll: plain
# 104,671, internal 732, cmov 711, rep 23, ret 1,550, int pair 145; userop test: syscall), with the voter form each
# pin stands for (impl r1 Astra P1-3: every voter in both modes must report that form and no target). Direct
# targets need every voter's own report (`target_derivation == "decoder"`); XED's targets are computed by G1 at
# the operand width, so direct-target T stays unobserved with the current voters (closed design r3 s2)
PINNED_E = {"plain": "none", "internal": "none", "cmov": "none", "rep": "none", "ret": "ret_near",
            "syscall": "syscall", "interrupt": "int_n"}
DIRECT_E = ("call", "jcc", "jmp")
SPEC = {"required": list(REQUIRED), "codes": CODES, "exemptions": EXEMPTIONS, "mode_constant": list(MODE_CONSTANT),
        "pinned_e": PINNED_E, "direct_e": list(DIRECT_E), "pinned_bits": PINNED_BITS,
        "t_rule": "E: both modes one voter form; direct target: every voter decoder-reported and equal; no target: "
                  "pinned pattern whose voter form all voters report. non-call: flow_targets == E and no external; "
                  "call: external or flow_targets != E u pads -> disagree, pads -> unobserved, else confirmed"}


def present(report: dict) -> bool:
    return report["flow_override"] != "NONE" or report["fallthrough_overridden"] or report["length_overridden"] \
        or bool(report["references"])


def kinds(report: dict) -> list:
    out = []
    if report["flow_override"] != "NONE":
        out.append("flow:" + report["flow_override"])
    if report["fallthrough_overridden"]:
        out.append("fallthrough")
    if report["length_overridden"]:
        out.append("length")
    out.extend(sorted(f"reference:{item['type']}:{'primary' if item['primary'] else 'non-primary'}"
                      for item in report["references"]))
    return out


def _voters(ballot: dict) -> list:
    return list(ballot["intel"]) + list(ballot["amd"])


def consensus_length(ballot: dict | None):
    if ballot is None:
        return None
    voters = _voters(ballot)
    lengths = {v.length for v in voters if v.status == "ok"}
    return lengths.pop() if len(lengths) == 1 and all(v.status == "ok" for v in voters) else None


def consensus_flow(ballot: dict | None):
    if ballot is None:
        return None
    voters = _voters(ballot)
    flows = {v.flow for v in voters}
    return flows.pop() if len(flows) == 1 and all(v.status == "ok" for v in voters) else None


def target_check(facts: dict, lift, ballot: dict) -> tuple:
    """(state, reason): T, the exported normal target set against the voters (r2 s2, r3 s2, impl r1 P1-3)."""
    if facts.get("external_flow_targets") is None:
        return "unobserved", "no producer-profile target fields"
    voters = _voters(ballot)
    flow = consensus_flow(ballot)
    if flow is None:
        return "unobserved", "the voters / modes disagree on the form (or one failed)"
    if any(v.indirect for v in voters):
        return "unobserved", "indirect or computed target"
    pattern = None if lift is None else lift.pattern
    targets = {v.target for v in voters}
    space = facts["space"]
    if targets == {None}:
        if PINNED_E.get(pattern) != flow:
            return "unobserved", f"E of the {pattern} form is not pinned for the voters' form {flow}"
        expected = set()
    else:
        if pattern not in DIRECT_E:
            return "unobserved", f"E of the {pattern} form is not pinned"
        if None in targets or len(targets) != 1 or any(v.target_derivation != "decoder" for v in voters):
            return "unobserved", "not every voter reports the target itself (XED's target is computed by G1)"
        expected = {(space, targets.pop())}
    exported = {tuple(item) for item in facts["flow_target_coords"]}
    pads = {tuple(item) for item in facts.get("recorded_landing_pads") or ()}
    external = facts["external_flow_targets"]
    if not facts["has_call_op"]:
        if exported == expected and external == 0:
            return "confirmed", None
        return "disagree", "exported targets differ from the bytes (non-call row)"
    if external != 0 or exported != expected | pads:
        return "disagree", "exported targets differ from the bytes and the recorded pads (call row)"
    if pads:
        return "unobserved", "call row with recorded landing pads: a normal target equal to a pad is not excluded"
    return "confirmed", None


def pinned_code(lift, ballot: dict | None, window: bytes | None) -> str | None:
    """The exemption code of an exact pinned shape (impl r1 Astra P1-2): the lift's exact shape, the voters'
    consensus form and length, and the verified bytes 0F 05 / CD <vector> with the lift's own vector."""
    if lift is None or lift.pattern not in ("syscall", "interrupt") or ballot is None or not window:
        return None
    if consensus_length(ballot) != 2 or len(window) < 2:
        return None
    flow = consensus_flow(ballot)
    if lift.pattern == "syscall":
        return "S" if flow == "syscall" and window[:2] == b"\x0f\x05" else None
    vector = lift.pinned.get("a10", (None, None))[1]
    vectors = {v.int_vector for v in _voters(ballot)}
    if flow == "int_n" and vectors == {vector} and window[0] == 0xCD and window[1] == vector:
        return "I"
    return None


def _state(name: str, item: dict, facts: dict, ballot: dict) -> str:
    """confirmed / neutral / unobserved / disagree of one raw attribute (r2 s4 table; impl r1 Astra P2-1: the
    provenance first, then the state)."""
    if name == "a2" and item.get("provenance"):
        return "unobserved"                     # (a2 derived via A4, whatever the comparison said)
    if name == "a4" and facts.get("fallthrough") is None and facts.get("exit"):
        return "unobserved"                     # (a4 rebuilt from an S1 exit, whatever the comparison said)
    state = item["state"]
    if state == "applied":
        return "neutral" if name in MODE_CONSTANT else "confirmed"
    if state == "not_applicable":
        return "neutral"
    if state in ("unobserved", "withheld"):
        return "unobserved"
    if item.get("kind") == "ghidra-internal-inconsistency":
        # (the listing attribute itself must differ from the consensus: for a2, the exported length)
        length = consensus_length(ballot)
        if length is None or facts.get("length") is None:
            return "unobserved"
        return "disagree" if facts["length"] != length else "unobserved"
    return "disagree"


def _pinned_state(name: str, code: str, facts: dict, ballot: dict, lift) -> str:
    """An attribute G1's own comparison leaves unobserved for the shape, from the pin (r2 s3, impl r1 P1-4)."""
    pattern = EXEMPTIONS[code]["pattern"]
    if name == "a4":
        length = consensus_length(ballot)
        if facts.get("fallthrough") is None:
            return "unobserved" if facts.get("exit") else "disagree"
        actual = (facts.get("fallthrough_space", facts["space"]), facts["fallthrough"])
        return "confirmed" if actual == (facts["space"], facts["address"] + length) else "disagree"
    if name.startswith("F."):
        bit = name[2:]
        if facts["flow"][bit] != PINNED_BITS[pattern][bit]:
            return "disagree"
        return "neutral" if name in MODE_CONSTANT else "confirmed"
    # a5 / a6 / a8 / a9 / a10 of the syscall shape: the lift's pinned values against every voter's value
    values = {repr(compare.voter_values(v, facts["address"]).get(name)) for v in _voters(ballot)}
    if len(values) != 1:
        return "unobserved"
    expected = lift.pinned.get(name)
    voter = compare.voter_values(_voters(ballot)[0], facts["address"]).get(name)
    if expected is None and voter is None:
        return "neutral"
    return "confirmed" if expected == voter else "disagree"


def row_verdict(facts: dict, result: dict | None, lift, ballot: dict | None, window: bytes | None = None):
    """(code or None, detail or None) of one profile row; (None, None) for a ``*`` row without a reported override;
    None for a row without a report (not a profile row)."""
    report = facts.get("override")
    if report is None:
        return None
    star = result is None or not result.get("attributes")
    if star:
        if present(report):
            return None, {"star": True, "kinds": kinds(report), "effect": {"unobserved": ["*"]}}
        return None, None
    code = pinned_code(lift, ballot, window)
    pinned = set(EXEMPTIONS[code]["core_unobserved"]) - {"a3"} if code else set()
    disagree, unobserved = [], []
    for name in compare.COMPARED:
        if code and name == "a3":
            continue                                    # (the exemption: OS-contract model)
        if name in pinned:
            state = _pinned_state(name, code, facts, ballot, lift)
        else:
            state = _state(name, result["attributes"].get(name, {"state": "unobserved"}), facts, ballot)
        if state == "disagree":
            disagree.append(name)
        elif state == "unobserved":
            unobserved.append(name)
    t_state, _ = target_check(facts, lift, ballot)
    if t_state == "disagree":
        disagree.append("T")
    elif t_state == "unobserved":
        unobserved.append("T")
    exempt = {"exempt": code} if code else {}
    if present(report):
        return "O", {"kinds": kinds(report), "effect": {"disagree": disagree, "unobserved": unobserved}, **exempt}
    if disagree:
        return "C", {"disagree": disagree, **exempt}
    if unobserved:
        return "U", {"unobserved": unobserved, **exempt}
    return (code or "A"), None


def g3b7b_row(facts: dict, ballot: dict | None, window: bytes | None, lift) -> dict:
    """Per-row inputs of the g3b7b estimate (impl r1 Astra P2-3): whether the prototype falls through (voters'
    consensus form; the pinned shapes by their pinned bits), whether it is a call row (CALL / CALLIND p-code or a
    call form), the reported kinds and Ghidra's own fallthrough / length."""
    flow = consensus_flow(ballot)
    if flow in ("none", "jcc", "call_near", "call_far"):
        isa_fallthrough = True
    elif flow in ("jmp_near", "jmp_far", "ret_near", "ret_far", "iret", "ud", "sysret"):
        isa_fallthrough = False
    elif pinned_code(lift, ballot, window):
        isa_fallthrough = True                  # (the pinned bits: has_fallthrough)
    else:
        isa_fallthrough = None
    report = facts.get("override")
    return {"isa_fallthrough": isa_fallthrough, "call_row": bool(facts.get("has_call_op"))
            or flow in ("call_near", "call_far"), "kinds": [] if report is None else kinds(report),
            "consensus_length": consensus_length(ballot)}


def header_block(profile, engine_source: dict) -> dict:
    return {"schema": SCHEMA, "profile": profile, "spec": copy.deepcopy(SPEC),
            "omitted": "none: one code per compared row", "engine_source": dict(engine_source)}
