"""The pure comparison core of G1 decode_check (design r1 s4 / s5, r2 s2 / s5,
r3 s2-s4 / s7, r4 s1 / s3 / s5): Ghidra row facts + the lift + the decode window
+ the voters' results -> one state per attribute and a row aggregate.

No engine objects and no decoder objects beyond ``decoders.Decoded`` values, so
the same function can be reproduced elsewhere (Rust) from the same inputs.

States: ``applied``, ``unobserved`` (no verdict), ``not_applicable``,
``withheld`` (kind ``decoder-disagreement`` / ``amd-disagreement`` /
``vendor``), ``unrecognized`` (kind ``ghidra-analysis-override`` /
``cause-unknown`` / ``ghidra-decode-suspect`` / ``ghidra-internal-inconsistency``).
"""

from __future__ import annotations

from lifting import LISTING_BITS, continuation as _continuation

NA = ("n/a",)   # a value meaning "the attribute does not apply to this instruction"
TABLE_DEPENDENT = ("a3", "a5", "a6", "a7", "a8", "a9", "a10", "a11a", "a11b", "a11c", "a12", "target_operand_bits")
F_BITS = ("has_fallthrough", "is_call", "is_jump", "is_terminal", "is_computed", "is_conditional", "is_flow",
          "is_unconditional")
PRECEDENCE = ("unobserved", "withheld:decoder-disagreement", "withheld:amd-disagreement", "withheld:vendor",
              "unrecognized:ghidra-internal-inconsistency", "unrecognized:ghidra-analysis-override",
              "unrecognized:cause-unknown", "unrecognized:ghidra-decode-suspect", "applied")


def _mask(bits):
    return (1 << bits) - 1


def voter_values(decoded, va: int) -> dict:
    """The normalised voter-side value of every attribute (r2 s2, r3 s3 / s4, r4 s3)."""
    if decoded.status == "invalid":
        return {"a1": False}
    flow = decoded.flow
    nxt = va + decoded.length
    near_call = flow == "call_near"
    os_kinds = ("int3", "int_n", "int1", "into", "syscall", "sysenter", "hlt", "xabort", "xend", "xbegin")
    if flow in ("none", "jcc"):
        role = "sequential"
    elif flow in ("call_near", "call_far"):
        role = "call-continuation"
    elif flow in ("jmp_near", "jmp_far", "ret_near", "ret_far", "iret", "ud", "sysret"):
        role = "none"
    else:
        role = None   # OS / interrupt dependent: not observable
    values = {
        "a1": True,
        "a2": decoded.length,
        "a3": role if role is not None else ("unobservable", flow),
        "a4": nxt if role in ("sequential", "call-continuation") else (NA if role == "none" else ("unobservable",)),
        "a5": decoded.target if decoded.target is None or not decoded.target_ip_bits
        or decoded.target_ip_bits >= 64 or decoded.target >> decoded.target_ip_bits == 0
        else ("voter-conflict", decoded.voter, decoded.target, decoded.target_ip_bits),   # (r4 s3: no agreement)
        "a6": "near" if near_call else ("far" if flow == "call_far" else "none"),
        "a8": "direct" if decoded.target is not None else ("indirect" if decoded.indirect else "none"),
        "a9": {"ret_near": "near_imm" if decoded.ret_imm is not None else "near", "ret_far": "far",
               "iret": "iret"}.get(flow,
                                                                                                          "none"),
        "a10": {"int3": ("int", 3), "int_n": ("int", decoded.int_vector), "int1": ("int1",), "into": ("into",),
                "ud": ("invalid-opcode",), "syscall": ("syscall",), "sysenter": ("sysenter",)}.get(flow, ("none",)),
    }
    if near_call:
        width = decoded.operand_bits or 64
        values["a7"] = (width, nxt & _mask(width))
        values["a11b"] = width // 8
        values["a11a"] = decoded.stack_bits or 64
    elif flow == "ret_near":
        values["a11b"] = (decoded.operand_bits or 64) // 8
        values["a11a"] = decoded.stack_bits or 64
    if decoded.counter:
        values["a12"] = decoded.address_bits
    if flow in ("call_near", "jmp_near"):
        # A11c (Astra impl r4 s3): memory -> its effective-address width; register / direct -> not applicable;
        # a voter that cannot tell -> not observable
        kind = getattr(decoded, "target_kind", "unknown")
        values["a11c"] = decoded.address_bits if kind == "memory" else NA if kind in ("register", "direct") \
            else ("unobservable", "target operand kind unknown")
    if decoded.indirect and flow in ("call_near", "jmp_near"):
        values["target_operand_bits"] = decoded.target_ip_bits
    form = None
    if flow == "none":
        form = "none"
    elif near_call:
        form = "call_indirect" if decoded.indirect else "call_direct"
    elif flow == "jmp_near":
        form = "jmp_indirect" if decoded.indirect else "jmp_direct"
    elif flow == "jcc":
        form = "jcc"
    elif flow == "ret_near":
        form = "ret"
    if form is not None:
        for bit, value in LISTING_BITS[form].items():
            values["F." + bit] = value
    if flow in os_kinds:
        values["os_kind"] = flow
    return values


COMPARED = ("a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "a11a", "a11b", "a11c", "a12",
            "target_operand_bits") + tuple("F." + bit for bit in F_BITS)
# attributes the 64-bit mode fixes on the voter side (not read from the bytes): kept, marked, never counted as
# observed agreement in the dependents (Fable impl r2 P3-1)
MODE_CONSTANT = ("a11a", "F.is_flow")
LEGACY_PREFIXES = frozenset((0x66, 0xF0, 0x67, 0xF2, 0xF3, 0x2E, 0x3E, 0x26, 0x36, 0x64, 0x65))


def _prefix_run(data: bytes) -> bytes:
    out = bytearray()
    for value in data:
        if value not in LEGACY_PREFIXES and not 0x40 <= value <= 0x4F:
            break
        out.append(value)
    return bytes(out)


def claimed_length(facts: dict, lift, s1: bool, native_call: bool):
    """Ghidra's claimed length: the exported one, else the r3 s2 derivation via A4."""
    values, _ = ghidra_values(facts, lift, s1, native_call)
    return values.get("a2")


def ghidra_values(facts: dict, lift, s1: bool, native_call: bool,
                  unverified_reason: str | None = None) -> tuple[dict, dict]:
    """(values, unobserved reasons) of the Ghidra side. ``lift`` None: the
    translation premise is off -> table-dependent attributes unobserved."""
    start = facts["address"]
    values, reasons = {"a1": True}, {}
    where = _continuation(facts)
    own = where is not None and where[0] == facts.get("space")
    continuation = where[1] if own else None
    # A4: the listing continuation (or the S1 exit target) in the row's own space; another space never agrees
    values["a4"] = NA if where is None else continuation if own else ("other-space", where[0], where[1])
    # A2: the exported length; else via A4 only for a native call in an S1 function (r3 s2)
    if facts["length"] is not None:
        values["a2"] = facts["length"]
    elif s1 and native_call and lift is not None and lift.pattern in ("call", "call indirect") \
            and continuation is not None:
        values["a2"] = continuation - start
        values["a2_provenance"] = "via A4"
    else:
        reasons["a2"] = "no ghidra length"
    if lift is None:
        for name in TABLE_DEPENDENT + tuple("F." + bit for bit in F_BITS):
            reasons[name] = unverified_reason or "translation-unverified (the stock-ghidra-translator premise is off)"
        return values, reasons
    for name, value in lift.values.items():
        values[name] = value
    for name, reason in lift.unobserved.items():
        reasons[name] = reason
    if lift.pattern in ("rep", "cmov", "branch-self", "interrupt", "fault", "transactional", "userop",
                        "unidentified"):
        for bit in F_BITS:
            reasons.setdefault("F." + bit, f"listing bits of the {lift.pattern} form are not pinned")
    else:
        for bit in F_BITS:
            values["F." + bit] = facts["flow"][bit]
    return values, reasons


def _vote(results: list, name: str):
    """(state-or-None, value) over one mode's voters for one attribute."""
    seen = set()
    for result in results:
        if name not in result:
            seen.add(("absent",))
        else:
            seen.add(result[name] if not isinstance(result[name], list) else tuple(result[name]))
    return seen


def compare_row(facts: dict, lift, window: dict, ballot: dict, *, s1: bool, native_call: bool,
                premise: bool, unverified_reason: str | None = None) -> dict:
    """One row: {"attributes": {name: {...}}, "state": aggregate, "kind": ..., "window": ...}."""
    va = facts["address"]
    out = {"attributes": {}, "window": {**{k: v for k, v in window.items() if k != "bytes"},
                                        "hex": window.get("bytes", b"").hex()}}
    if window.get("unobserved"):
        out["state"], out["reason"] = "unobserved", window["unobserved"]
        return out
    verified = window["verified"]
    intel, amd = ballot["intel"], ballot["amd"]
    voters = list(intel) + list(amd)
    # failures and the verified-bytes rule (r1 s3): every consumed byte and Ghidra's claimed range verified
    failures = [f"{d.voter}/{'amd' if d.amd else 'intel'}: {d.status}" for d in voters
                if d.status in ("no_more_data", "error")]
    consumed = max([d.length for d in voters if d.status == "ok"] + [0])
    if any(d.status == "ok" and d.length > verified for d in voters):
        failures.append("a voter consumed unverified bytes")
    claimed = claimed_length(facts, lift if premise else None, s1, native_call)
    if claimed is not None and claimed > verified:
        failures.append("Ghidra's claimed range is not verified")
    if failures:
        out["state"], out["reason"] = "unobserved", "; ".join(failures)
        return out
    # relocations touching consumed bytes (r2 s4, r3 s5)
    for start, size, kind in window.get("relocations", ()):
        if start >= max(consumed, claimed or 0):
            continue
        if kind != "DIR64":
            out["state"], out["reason"] = "unobserved", f"relocation type {kind} over the instruction"
            return out
        inside = all(any(field[0] <= start and start + size <= field[0] + field[1] for field in d.value_fields)
                     for d in voters if d.status == "ok")
        if not inside:
            out["state"], out["reason"] = "unobserved", "relocation over instruction encoding"
            out["suspect_pattern"] = "relocation over instruction encoding"
            return out
    intel_values = [voter_values(d, va) for d in intel]
    amd_values = [voter_values(d, va) for d in amd]
    ghidra, reasons = ghidra_values(facts, lift if premise else None, s1, native_call, unverified_reason)
    if ghidra.get("a11c") not in (None, NA):
        if 0x67 in _prefix_run(window["bytes"]) and ghidra["a11c"] == 64:
            # (address-size override without an extension in the p-code: the width is not recoverable, r2 s1)
            reasons["a11c"] = "address-size override: effective-address width not recoverable from the p-code"
    names = list(COMPARED[:-len(F_BITS)]) + \
        ["F." + bit for bit in F_BITS]
    for name in names:
        out["attributes"][name] = _attribute(name, ghidra, reasons, intel_values, amd_values, facts)
    if ghidra.get("a2_provenance"):
        out["attributes"]["a2"]["provenance"] = "via A4 (counted once)"
    # length and continuation of Ghidra itself disagreeing, where a contract requires equality (r4 s5)
    where = _continuation(facts)
    expected = (facts.get("space"), va + facts["length"]) if facts["length"] is not None else None
    if expected is not None and where is not None and s1 and native_call and where != expected:
        inconsistency = {"state": "unrecognized", "kind": "ghidra-internal-inconsistency",
                         "ghidra": facts["length"], "expected": list(expected), "continuation": list(where)}
        if out["attributes"]["a2"]["state"] in ("applied", "unrecognized", "not_applicable"):
            out["attributes"]["a2"] = inconsistency
        else:   # (a withheld / unobserved A2 outranks it: keep it, note the inconsistency, r1 s5 precedence)
            out["attributes"]["a2"]["also"] = inconsistency
    for name in MODE_CONSTANT:
        if out["attributes"][name]["state"] == "applied":
            out["attributes"][name]["provenance"] = "mode-constant"
    out["state"] = _aggregate(out["attributes"])
    return out


def _attribute(name, ghidra, reasons, intel_values, amd_values, facts) -> dict:
    if name in reasons:
        return {"state": "unobserved", "reason": reasons[name]}
    if name not in ghidra:
        # neither side has the attribute for this instruction -> not applicable; only the voters have
        # it -> the Ghidra value is missing (unobserved)
        if all(name not in values for values in intel_values + amd_values):
            return {"state": "not_applicable"}
        return {"state": "unobserved", "reason": "no Ghidra value"}
    all_invalid = all(not values.get("a1", True) for values in intel_values + amd_values)
    if name != "a1" and all_invalid:
        return {"state": "not_applicable", "reason": "every voter: invalid encoding"}
    intel = _vote(intel_values, name)
    amd = _vote(amd_values, name)
    if any(value[0] == "unobservable" for value in intel | amd if isinstance(value, tuple) and value):
        return {"state": "unobserved", "reason": f"{name} not observable for this instruction kind"}
    if len(intel) > 1:
        return {"state": "withheld", "kind": "decoder-disagreement", "intel": sorted(map(repr, intel))}
    if len(amd) > 1:
        return {"state": "withheld", "kind": "amd-disagreement", "amd": sorted(map(repr, amd))}
    (intel_value,), (amd_value,) = tuple(intel), tuple(amd)
    if intel_value != amd_value:
        return {"state": "withheld", "kind": "vendor", "intel": repr(intel_value), "amd": repr(amd_value)}
    value = ghidra[name]
    voter_value = intel_value
    if voter_value == ("absent",):
        voter_value = None if name in ("a5",) else NA
    if value is None and voter_value in (None, NA) or value == NA and voter_value in (None, NA, ("absent",)):
        return {"state": "not_applicable"}
    if value == voter_value or (isinstance(value, tuple) and tuple(value) == voter_value):
        return {"state": "applied", "value": _plain(value)}
    kind = "ghidra-decode-suspect"
    if name in ("a3", "a4") or name.startswith("F."):
        kind = "ghidra-analysis-override" if facts["flow"]["is_override"] else "cause-unknown"
    return {"state": "unrecognized", "kind": kind, "ghidra": _plain(value), "voters": _plain(voter_value)}


def _plain(value):
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def _aggregate(attributes: dict) -> str:
    """Row state, precedence of r1 s5 / r2 s5; applied only if every applicable
    attribute was compared and agrees."""
    keys = set()
    for item in attributes.values():
        state = item["state"]
        if state == "not_applicable":
            continue
        keys.add(state if state in ("applied", "unobserved") else f"{state}:{item['kind']}")
    for key in PRECEDENCE:
        if key in keys:
            return key
    return "applied" if keys else "not_applicable"
