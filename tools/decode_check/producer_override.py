"""TBR G1 on X-1 producer Bundles: per-row override verdicts (design .census6/design_tbr_g1_x1_r1.md with the r2 /
r3 deltas, closed 2026-11-26).

G1 attests EFFECTS only: on every attribute it compares (and the exported target set T) the exported row equals
what the bytes encode, so no override -- reported or not -- changed those values. It never attests that the
producer's override report is complete (an effect-free override reference is invisible): the verdict is
``effect_attested``, and what it discharges is TDO's decision (r1 s0, options a / b).

One code per row G1 compared (r2 s5): ``A`` effect_attested, ``S`` / ``I`` effect_attested with the syscall /
interrupt a3 exemption (OS-contract model), ``C`` contradicted, ``U`` unobserved, ``O`` override_present. A row
never compared (``*``) has no code; when its report is present it gets a ``star`` detail.

Pure functions of plain row facts, the comparison result, the lift and the ballot (Rust-reproducible).
"""

from __future__ import annotations

import copy

import compare
import lifting

SCHEMA = "tbr-producer-override-1"
PROFILE_X1 = "x1-producer-v1"
OS_CONTRACT = "kernel-boundary-contract"     # (S3 r16 1.2 item 5: the named OS-contract model / switch)
CODES = {"A": "effect_attested", "S": "effect_attested", "I": "effect_attested", "C": "contradicted",
         "U": "unobserved", "O": "override_present"}
DETAIL_CODES = frozenset("CUO")
REQUIRED = tuple(compare.COMPARED) + ("T",)
MODE_CONSTANT = tuple(compare.MODE_CONSTANT)        # equal: neutral (not an observation); differing: disagree
# exact shapes only (r3 s3 = S3 r16 1.2 item 2); the exemption is a3 under the OS-contract model
EXEMPTIONS = {
    "S": {"pattern": "syscall", "attribute": "a3", "premise": OS_CONTRACT,
          "reason": "whether the OS returns after syscall is not observable"},
    "I": {"pattern": "interrupt", "attribute": "a3", "premise": OS_CONTRACT,
          "reason": "whether the OS returns after an interrupt is not observable"},
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
# 104,671, internal 732, cmov 711, rep 23, ret 1,550, int pair 145; userop test: syscall); direct-target patterns
# whose rows export exactly the decoded target (ntdll: call 6,316, jcc 15,366, jmp 6,151)
PINNED_E = ("plain", "internal", "cmov", "rep", "ret", "syscall", "interrupt")
DIRECT_E = ("call", "jcc", "jmp")
SPEC = {"required": list(REQUIRED), "codes": CODES, "exemptions": EXEMPTIONS, "mode_constant": list(MODE_CONSTANT),
        "pinned_e": list(PINNED_E), "direct_e": list(DIRECT_E), "pinned_bits": PINNED_BITS,
        "t_rule": "non-call: flow_targets == E and no external; call: external or flow_targets != E u pads -> "
                  "disagree, pads -> unobserved, else confirmed"}


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


def _consensus_length(ballot: dict):
    voters = list(ballot["intel"]) + list(ballot["amd"])
    lengths = {v.length for v in voters if v.status == "ok"}
    return lengths.pop() if len(lengths) == 1 and all(v.status == "ok" for v in voters) else None


def target_check(facts: dict, lift, ballot: dict) -> tuple:
    """(state, reason): T, the exported normal target set against the voters (r2 s2, r3 s2)."""
    if facts.get("external_flow_targets") is None:
        return "unobserved", "no producer-profile target fields"
    voters = list(ballot["intel"]) + list(ballot["amd"])
    if any(v.status != "ok" for v in voters):
        return "unobserved", "not every voter decoded the row in both modes"
    if len({v.flow for v in voters}) != 1:
        return "unobserved", "the voters / modes disagree on the form"
    if any(v.indirect for v in voters):
        return "unobserved", "indirect or computed target"
    pattern = None if lift is None else lift.pattern
    targets = {v.target for v in voters}
    space = facts["space"]
    if targets == {None}:
        if pattern not in PINNED_E:
            return "unobserved", f"E of the {pattern} form is not pinned"
        expected = set()
    else:
        # (only decoder-reported targets are evidence: XED's target is G1's own computation at the operand width,
        #  never counted; iced and Zydis report in both modes, and every report must agree)
        reported = [v for v in voters if v.target_derivation == "decoder"]
        values = {v.target for v in reported}
        if None in values or len(values) != 1 or {(v.voter, v.amd) for v in reported} < {
                ("iced", False), ("zydis", False), ("iced", True), ("zydis", True)}:
            return "unobserved", "no agreeing decoder-reported target"
        targets = values
        if pattern not in DIRECT_E:
            return "unobserved", f"E of the {pattern} form is not pinned"
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


def _pinned(lift, result: dict) -> str | None:
    """The exemption code of an exact pinned shape, when the voters agree with the lift's a10 (a10 applied)."""
    if lift is None or lift.pattern not in ("syscall", "interrupt"):
        return None
    if result["attributes"].get("a10", {}).get("state") != "applied":
        return None
    return "S" if lift.pattern == "syscall" else "I"


def _state(name: str, item: dict, facts: dict, ballot: dict) -> str:
    """confirmed / neutral / unobserved / disagree of one raw attribute (r2 s4 table)."""
    state = item["state"]
    if state == "applied":
        if name in MODE_CONSTANT:
            return "neutral"
        if name == "a2" and item.get("provenance"):
            return "unobserved"                 # (a2 derived via A4)
        if name == "a4" and facts.get("fallthrough") is None:
            return "unobserved"                 # (a4 rebuilt from an S1 exit)
        return "confirmed"
    if state == "not_applicable":
        return "neutral"
    if state in ("unobserved", "withheld"):
        return "unobserved"
    if item.get("kind") == "ghidra-internal-inconsistency":
        length = _consensus_length(ballot)
        if length is None:
            return "unobserved"
        where = lifting.continuation(facts)
        if facts.get("length") != length or where != (facts["space"], facts["address"] + length):
            return "disagree"
        return "unobserved"
    return "disagree"


def _pinned_state(name: str, code: str, facts: dict, ballot: dict) -> str:
    pattern = EXEMPTIONS[code]["pattern"]
    if name == "a4":
        length = _consensus_length(ballot)
        if length is None:
            return "unobserved"
        if facts.get("fallthrough") is None:
            return "unobserved" if facts.get("exit") else "disagree"
        actual = (facts.get("fallthrough_space", facts["space"]), facts["fallthrough"])
        return "confirmed" if actual == (facts["space"], facts["address"] + length) else "disagree"
    bit = name[2:]
    if facts["flow"][bit] != PINNED_BITS[pattern][bit]:
        return "disagree"
    return "neutral" if name in MODE_CONSTANT else "confirmed"


def row_verdict(facts: dict, result: dict | None, lift, ballot: dict | None) -> tuple | None:
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
    code = _pinned(lift, result)
    disagree, unobserved = [], []
    for name in compare.COMPARED:
        if code and name == "a3":
            continue                                    # (the exemption: OS-contract model)
        item = result["attributes"].get(name, {"state": "unobserved"})
        if code and (name == "a4" or name.startswith("F.")):
            state = _pinned_state(name, code, facts, ballot)
        else:
            state = _state(name, item, facts, ballot)
        if state == "disagree":
            disagree.append(name)
        elif state == "unobserved":
            unobserved.append(name)
    t_state, _ = target_check(facts, lift, ballot)
    if t_state == "disagree":
        disagree.append("T")
    elif t_state == "unobserved":
        unobserved.append("T")
    if present(report):
        return "O", {"kinds": kinds(report), "effect": {"disagree": disagree, "unobserved": unobserved}}
    if disagree:
        return "C", {"disagree": disagree}
    if unobserved:
        return "U", {"unobserved": unobserved}
    return (code or "A"), None


def header_block(profile, engine_source: dict) -> dict:
    return {"schema": SCHEMA, "profile": profile, "spec": copy.deepcopy(SPEC),
            "omitted": "none: one code per compared row", "engine_source": dict(engine_source)}
