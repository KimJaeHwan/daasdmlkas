"""TBR ISA facts step 3: per-row facts F1-F7 (design .census6/design_tbr_isa_facts_r3.md s1-s5; the 2b
classification of .census6/design_tbr_isa_ordinary_r3.md).

``row_facts`` is a pure function of one row's verified window, its G1 ballot and the pinned tables. It writes
only what is specific to the row:
- the per-voter values;
- the XED profile results;
- the encoding discriminators: port-I/O access width, CALL rel32 zero, NOTRACK, BND;
- FS / GS accesses;
- Intel / AMD differences;
- the split decision.

Table content (conditions, f3 tags, f6 outputs, CET / MPX, class conditions) is referenced through the row's
basis key. ``table_facts`` resolves it from the same pinned tables, and the reader (evidence.py) merges both
before it ever answers "no condition" (step 3 review r1 P1).
"""

from __future__ import annotations

import copy
import hashlib
import json

import isa_tables

FACT_SCHEMA = "tbr-isa-facts-1"
KINDS = ("F1", "F2", "F2p", "F3", "F4", "F5", "F6", "F7")
OMITTED_BASIS = "ordinary:plain"          # a row absent from the list: derived-ordinary plain, nothing row-specific
TABLE_SOURCED = ("F2", "F2p", "F3", "F4", "F6", "F7")     # F1 and F5 come from the voters alone
FIXED_BASES = ("unclassified", "partial", "disagree")
# the voter x condition capability matrix (design r3 s2, 2b r1 s4); XED profiles are one decoder, never voters
CAPABILITY = {
    "CPL0": {"iced": "must_be_cpl0", "zydis": "IS_PRIVILEGED", "xed": "RING0"},
    "IOPL": {"iced": "is_privileged (without must_be_cpl0)", "zydis": "not_provided", "xed": "not_provided"},
    "OS_GATED": {"iced": "may_require_cpl0", "zydis": "not_provided", "xed": "not_provided"},
    "system_flags": {"iced": "IF, AC", "zydis": "all", "xed": "all"},
    "features": {"iced": "cpuid_features", "zydis": "isa_set", "xed": "isa_set (+ profiles xed:baseline / xed:all)"},
    "fs_gs_segments": {"iced": "used memory", "zydis": "operands", "xed": "memory operands (FS / GS overrides only)"},
    "operand_kinds": {"iced": "name + non-GPR kinds (pinned conventions)", "zydis": "exact", "xed": "exact + iform"},
    "profiles": {"xed:g1": "voter setting", "xed:baseline": "profile, not a voter", "xed:all": "profile, not a voter"}}
TRANSFER_FLOWS = frozenset(("int3", "int_n", "int1", "into", "syscall", "sysenter", "sysret", "hlt", "xbegin",
                            "xabort", "xend", "ud", "iret", "ret_far", "call_far", "jmp_far"))
# Intel / AMD attributes (r1 P1-4: agreement inside each mode first); targets only where the decoder reports them
F5_FIELDS = ("status", "length", "flow", "operand_bits", "target_ip_bits", "ret_imm")
INDIRECT_KEYS = ("CALL_NEAR_INDIRECT", "JMP_NEAR_INDIRECT")
SEGMENT_PREFIXES = frozenset((0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65))
# ordinary class flags carry row-specific conditions (step 3 review r2, Astra P1-3): flag -> kind, or out of scope
CLASS_FLAG_KINDS = {"mxcsr_inputs": "F6", "writes_mxcsr_status": "F3", "explicit_mmx_operand": "F3"}
CLASS_FLAG_OUT_OF_SCOPE = ("simd_fp_exceptions", "alignment", "masked_write")


def header_block(tables, profiles: dict) -> dict:
    """The evidence-2 header section for ISA facts (design r3 s5): schema, kinds, the omitted-row basis, the
    capability matrix, the four table digests and the XED profiles (chip names, ISA-set digests)."""
    profile_view = {}
    for name, item in profiles.items():
        sets = item.get("isa_sets")
        profile_view[name] = {"chip": item.get("chip"), "isa_sets_sha256":
                              None if sets is None else hashlib.sha256("\n".join(sets).encode()).hexdigest()}
    return {"schema": FACT_SCHEMA, "kinds": list(KINDS), "omitted_row_basis": OMITTED_BASIS,
            "capability": CAPABILITY, "tables": dict(tables.digests), "profiles": profile_view}


def block_digest(block: dict) -> str:
    return hashlib.sha256(isa_tables.canonical_bytes(block)).hexdigest()


def premise_names(block: dict) -> dict:
    """The named premises a reader needs for negatives (design r3 s2, 2b r1 s8), bound to this header."""
    digest = block_digest(block)
    return {"detection": {kind: f"isa-{kind}-detection-complete:{digest}" for kind in KINDS},
            "ordinary": f"isa-ordinary-rule:{block['tables']['ordinary']}"}


def basis_known(tables, basis: str) -> bool:
    """A basis the pinned tables can resolve (r1 P2-2)."""
    if basis in FIXED_BASES:
        return True
    kind, _, key = basis.partition(":")
    if kind == "cited":
        return tables.entry(key) is not None
    if kind == "split":
        return any(split["id"] == key for split in tables.splits["splits"])
    if kind == "ordinary":
        return key in tables.ordinary["classes"]
    return False


def table_facts(tables, basis: str) -> tuple:
    """({kind: table content}, out_of_scope, {kind: unverified reason}) behind a basis (r1 P1): cited entry; split =
    the split entry plus the union of its main and fallback entries; ordinary = the class. Data-dependent faults are
    out of scope (s3 end, s0): returned apart, never a kind's condition. A table note that a vendor behaviour is
    still to be checked is no fact (r2 Astra P1-2): it is returned as unverified. Everything returned is a copy,
    never the pinned tables' own objects (r2 Astra P2-3)."""
    kinds, out_of_scope, unverified = {}, [], {}

    def add(kind, name, value):
        if value:
            kinds.setdefault(kind, {})[name] = copy.deepcopy(value)

    def entry(key, prefix=""):
        item = tables.entry(key) or {}
        add("F2", prefix + "f2", item.get("f2"))
        add("F2", prefix + "access_width", item.get("access_width"))
        if item.get("f2_meaning"):
            add("F2p", prefix + "f2_meaning", {item["f2_meaning"]: tables.conditions["f2_meanings"][item["f2_meaning"]]})
        add("F3", prefix + "f3", item.get("f3"))
        add("F3", prefix + "cet", item.get("cet"))
        add("F3", prefix + "state_dependent", item.get("state_dependent"))
        add("F3", prefix + "state_effect", item.get("state_effect"))
        add("F4", prefix + "f4", item.get("f4"))
        if item.get("mpx"):
            add("F4", prefix + "mpx", tables.conditions["mpx_effects"][item["mpx"]]["rule"])
        f5 = dict(item.get("f5") or {})
        if "unverified" in f5:
            unverified.setdefault("F5", "table: " + f5.pop("unverified"))
        add("F5", prefix + "f5", f5)
        add("F6", prefix + "f6", item.get("f6"))
        add("F6", prefix + "undefined_outputs", item.get("undefined_outputs"))
        add("F7", prefix + "f7", item.get("f7"))
        out_of_scope.extend(item.get("data_faults", ()))

    kind, _, key = basis.partition(":")
    if kind == "cited":
        entry(key)
    elif kind == "split":
        split = next(s for s in tables.splits["splits"] if s["id"] == key)
        add("F4", "split", {name: split[name] for name in ("id", "main", "fallback", "feature")
                            if name in split} | ({"enabled": split["enabled"]} if "enabled" in split else {}))
        entry(split["main"], "main.")
        entry(split["fallback"], "fallback.")
    elif kind == "ordinary":
        klass = tables.ordinary["classes"][key]
        add("F2", "class_conditions", klass.get("conditions"))
        add("F3", "class_state_dependent", klass.get("state_dependent"))
        add("F5", "class_f5", klass.get("f5"))              # (r2 Fable P1: FXSAVE / FXRSTOR Intel / AMD differences)
        add("F6", "class_effects", klass.get("effects"))
        add("F6", "class_f6", klass.get("f6"))
        out_of_scope.extend(klass.get("data_faults", ()))
    return kinds, list(out_of_scope), unverified


def row_table_facts(tables, basis: str, facts: dict) -> tuple:
    """The table side of one row (r2 Astra P1-3): the basis's table facts, plus the split the row's F4 identified
    from the XED profiles (its main and fallback entries, for every kind) and the row's ordinary class flags."""
    kinds, out_of_scope, unverified = table_facts(tables, basis) if basis not in FIXED_BASES else ({}, [], {})
    split = (facts.get("F4") or {}).get("split") or {}
    other = "split:" + str(split.get("split"))
    if split.get("source") == "split_table" and other != basis and basis_known(tables, other):
        more, scope, why = table_facts(tables, other)
        for kind, values in more.items():
            kinds.setdefault(kind, {}).update({"split." + name: value for name, value in values.items()})
        out_of_scope += [item for item in scope if item not in out_of_scope]
        for kind, reason in why.items():
            unverified.setdefault(kind, reason)
    flags = facts.get("class_flags") or {}
    meanings = tables.ordinary.get("flag_meanings", {})
    for name, kind in CLASS_FLAG_KINDS.items():
        if flags.get(name):
            kinds.setdefault(kind, {})["class_flags." + name] = copy.deepcopy(flags[name])
    for name in CLASS_FLAG_OUT_OF_SCOPE:
        if flags.get(name):
            out_of_scope.append(f"{name}: {meanings.get(name, name)}")
    return kinds, out_of_scope, unverified


def _privilege(votes: dict) -> dict:
    iced, zydis, xed = votes["iced"].extra, votes["zydis"].extra, votes["xed"].extra
    return {"iced": {"must_be_cpl0": iced.get("must_be_cpl0"), "is_privileged": iced.get("is_privileged"),
                     "may_require_cpl0": iced.get("may_require_cpl0")},
            "zydis": {"IS_PRIVILEGED": zydis.get("privileged_attribute")},
            "xed": {"RING0": xed.get("privileged_attribute")}}


def _f1(votes: dict, profiles: dict, checked_length: int) -> tuple:
    """(F1 fact, unobserved reason) -- r1 P1-3: a profile that could not read the row (no_more_data / error) or
    read beyond the bytes G1 checked leaves F1 unobserved instead of becoming invalid_for_chip."""
    voters = {name: {"status": v.status, "error": v.extra.get("error", "")} for name, v in votes.items()}
    views = {name: {"status": v.status, "error": v.extra.get("error", ""), "mnemonic": v.mnemonic, "length": v.length}
             for name, v in profiles.items()}
    fact = {"voters": voters, "profiles": views}
    if any(view["status"] in ("no_more_data", "error") for view in views.values()):
        return fact, "an XED profile could not read the row"
    if any(view["status"] == "ok" and view["length"] > checked_length for view in views.values()):
        return fact, "an XED profile read beyond the bytes G1 checked"
    every = list(voters.values()) + list(views.values())
    if all(item["status"] == "ok" for item in every):
        fact["class"] = "valid"
    elif all(item["status"] == "invalid" and item["error"] != "INVALID_FOR_CHIP" for item in every):
        fact["class"] = "invalid_encoding"
    elif views["xed:baseline"]["status"] == "invalid" and views["xed:all"]["status"] == "ok" and all(
            v["status"] == "ok" for v in voters.values()) and all(
            view["status"] in ("ok", "invalid") for view in views.values()):
        fact["class"] = "invalid_for_chip"   # the baseline REJECTS what the all-features chip and every voter accept
    else:
        fact["class"] = "mixed"
    return fact, None


def _split(tables, basis: str, profiles: dict, window: bytes, decode_without, checked_length: int) -> tuple:
    """(split decision or None, unobserved reason). Profile and single-feature read failures, and reads beyond
    the bytes G1 checked, are handled before any decision (r2 Astra P1-1)."""
    base, full = profiles["xed:baseline"], profiles["xed:all"]
    if basis.startswith("split:"):
        return {"source": "split_table", "split": basis.split(":", 1)[1]}, None
    if any(p.status in ("no_more_data", "error") for p in (base, full)):
        return None, "an XED profile could not read the row"
    if any(p.status == "ok" and p.length > checked_length for p in (base, full)):
        return None, "an XED profile read beyond the bytes G1 checked"
    if not (base.status == "ok" and full.status == "ok" and base.length == full.length and base.flow == full.flow
            and base.mnemonic != full.mnemonic):
        return None, None
    keys = {isa_tables.lookup(tables, base, window), isa_tables.lookup(tables, full, window)}
    known = tables.same_split(keys) if None not in keys else None
    if known:
        return {"source": "split_table", "split": known["id"], "baseline": base.mnemonic, "all": full.mnemonic}, None
    feature = full.extra.get("isa_set", "")
    single = decode_without(feature, window) if feature else None
    if single is not None and single.status in ("no_more_data", "error"):
        return None, "the single-feature XED run could not read the row"
    if single is not None and single.status == "ok" and single.length > checked_length:
        return None, "the single-feature XED run read beyond the bytes G1 checked"
    if single is not None and single.status == "ok" and (single.mnemonic, single.length, single.flow) == (
            base.mnemonic, base.length, base.flow):
        return {"source": "single_feature_run", "deciding_feature": feature, "baseline": base.mnemonic,
                "all": full.mnemonic}, None
    return {"source": "profiles", "split_feature_unknown": True, "baseline": base.mnemonic,
            "all": full.mnemonic}, None


def _field(vote, field):
    """A decoder's value for an F5 field, or None when it does not report it (iced width 0, a computed target, any
    field but the status of a decode that failed: its fields are defaults, not reports)."""
    if field == "status":
        return vote.status
    if vote.status != "ok":
        return None
    if field == "target":
        return vote.target if vote.target is not None and vote.target_derivation == "decoder" else None
    value = getattr(vote, field)
    if field in ("operand_bits", "target_ip_bits") and value == 0:
        return None
    return value


def _f5(ballot: dict) -> tuple:
    """Intel / AMD differences (review r1 P1-4), per decoder that runs in both modes (iced, Zydis; XED is Intel
    only), so the decoders' own conventions (Zydis 8 vs XED 32 for byte operands) never meet. A field differs when
    every decoder that reports it in both modes changes it (r2 Astra P1-2: a value reported in one mode only is
    no difference); some changing and some not leaves F5 unobserved."""
    intel = dict(zip(("iced", "zydis", "xed"), ballot["intel"]))
    amd = dict(zip(("iced", "zydis"), ballot["amd"]))
    if any(v.status == "error" for v in amd.values()):
        return None, "an AMD-mode decode failed"
    differences, undecided = {}, []
    for field in F5_FIELDS + ("target",):
        changes = {}
        for name in ("iced", "zydis"):
            left, right = _field(intel[name], field), _field(amd[name], field)
            if left is None or right is None:
                continue
            changes[name] = (left, right)
        changed = [name for name, (left, right) in changes.items() if left != right]
        if changed and len(changed) == len(changes):
            differences[field] = {name: {"intel": left, "amd": right} for name, (left, right) in changes.items()}
        elif changed:
            undecided.append(field)
    if undecided:
        return None, f"the AMD-mode decoders disagree on whether {undecided} change"
    return (differences or None), None


def _f7(tables, votes: dict) -> tuple:
    """r1 P2-1: voters must agree on every FS / GS access (segment, role, read, write, conditional read / write);
    an explicit access also on its operand index (r2 Astra P2-2)."""
    views = {}
    for name, vote in votes.items():
        if not vote.extra.get("memory_complete", False) or vote.extra.get("mem_overflow"):
            return None, f"{name}: memory evidence incomplete"
        accesses = isa_tables.memory_evidence(tables, vote)
        views[name] = sorted((m["segment"], m["role"], _operand(m), m["read"], m["write"], m["cond_read"],
                              m["cond_write"]) for m in accesses if m["segment"] in ("fs", "gs"))
    if len({tuple(view) for view in views.values()}) != 1:
        return None, "voters disagree on the FS / GS accesses"
    accesses = views["xed"]
    if not accesses:
        return None, None
    out = []
    for s, role, index, r, w, cr, cw in accesses:
        item = {"segment": s, "role": role, "read": r, "write": w, "cond_read": cr, "cond_write": cw}
        if role == "explicit":
            item["operand_index"] = None if index < 0 else index
        out.append(item)
    return out, None


def _operand(access: dict) -> int:
    """The operand index of an explicit access (-1: not reported); implicit accesses have none."""
    index = access.get("operand_index")
    return index if access["role"] == "explicit" and isinstance(index, int) else -1


def _discriminators(tables, basis: str, window: bytes, votes: dict) -> tuple:
    """r1 P1-2: what the shared basis does not fix, read from the verified encoding -> (facts, unobserved). r2
    Astra P1-5: the port-I/O width follows the effective prefixes (a REX only immediately before the opcode) and
    must be the width every voter reports; F2 + F3 (BND) and 3E with another segment prefix (NOTRACK) depend on
    prefix order and are left unobserved."""
    prefixes, opcode, _, rex = isa_tables.encoding_view(window)
    out, unobserved = {}, {}
    key = basis.split(":", 1)[1] if basis.startswith("cited:") else None
    entry = tables.entry(key) if key else None
    width = (entry or {}).get("access_width")
    if width:
        if "fixed" in width:
            out.setdefault("F2", {})["access_width"] = width["fixed"]
        elif opcode.hex().upper() in width["byte_opcodes"]:
            out.setdefault("F2", {})["access_width"] = 1
        else:
            word = not rex & 0x08 and int(width["word_prefix"], 16) in prefixes
            expected = 2 if word else width["default"]
            reported = sorted({v.operand_bits for v in votes.values()})
            if reported == [expected * 8]:
                out.setdefault("F2", {})["access_width"] = expected
            else:
                unobserved["F2"] = f"port-I/O width: the voters report {reported} bits, the prefixes give {expected * 8}"
    if key == "CALL_NEAR":
        index = 0
        while index < len(window) and (window[index] in isa_tables.LEGACY_PREFIXES or 0x40 <= window[index] <= 0x4F):
            index += 1
        if index + 5 <= len(window) and window[index] == 0xE8:
            rel32 = int.from_bytes(window[index + 1:index + 5], "little", signed=True)
            out.setdefault("F3", {})["rel32_is_zero"] = rel32 == 0
    if key in INDIRECT_KEYS:
        segments = {p for p in prefixes if p in SEGMENT_PREFIXES}
        if 0x3E in segments and len(segments) > 1:
            unobserved["F3"] = "3E with another segment prefix: NOTRACK depends on prefix order (not decided)"
        else:
            out.setdefault("F3", {})["notrack_prefix"] = 0x3E in segments
    if entry and entry.get("mpx"):
        if 0xF2 in prefixes and 0xF3 in prefixes:
            unobserved["F4"] = "both F2 and F3 prefixes: BND depends on prefix order (not decided)"
        else:
            out.setdefault("F4", {})["bnd_prefix"] = 0xF2 in prefixes
    return out, unobserved


def row_facts(tables, ballot: dict, window: bytes, *, redecode, decode_profile, decode_without) -> dict:
    """{"basis", "facts", "unobserved"(, "keys")} for one byte-verified row (design r3 s5: computed only from G1's
    verified window). ``ballot`` = decoders.ballot(window); the callables re-decode the same window."""
    votes = dict(zip(("iced", "zydis", "xed"), ballot["intel"]))
    classified = isa_tables.classify(tables, votes, window, redecode)
    result = classified["result"]
    if result == "cited":
        basis = "cited:" + classified["key"]
    elif result == "cited_split":
        basis = "split:" + classified["split"]
    elif result == "derived_ordinary":
        basis = "ordinary:" + classified["class"]
    else:
        basis = {"table_lookup_disagree": "disagree", "partial_lookup": "partial"}.get(result, "unclassified")
    facts, unobserved = {}, {}
    row = {"basis": basis, "facts": facts, "unobserved": unobserved}
    if basis in ("partial", "disagree"):
        row["keys"] = dict(classified.get("keys", {}))           # (r1 P2-3: which voter found which entry)
    if basis in FIXED_BASES:
        reason = "; ".join(classified.get("reasons", [])) or result
        for kind in TABLE_SOURCED:
            unobserved[kind] = f"no table basis ({reason})"[:300]
    checked_length = max([v.length for v in votes.values() if v.status == "ok"] + [0])
    profiles = {name: decode_profile(name, window) for name in ("xed:g1", "xed:baseline", "xed:all")}
    f1, why = _f1(votes, profiles, checked_length)
    if why:
        unobserved["F1"] = why
        unobserved.setdefault("F4", why)        # (r2 Astra P1-1: no profile split can be decided either)
    if f1.get("class") != "valid" or len({p["mnemonic"] for p in f1["profiles"].values()}) > 1:
        facts["F1"] = f1
    ok = all(v.status == "ok" for v in votes.values())
    entry = tables.entry(basis.split(":", 1)[1]) if basis.startswith("cited:") else None
    if ok:
        privilege = _privilege(votes)
        raw = [privilege["iced"]["must_be_cpl0"], privilege["zydis"]["IS_PRIVILEGED"], privilege["xed"]["RING0"]]
        cpl0 = [value for value in raw if isinstance(value, bool)]          # (r1 P2-3: None is not a vote)
        signals = any(cpl0) or privilege["iced"]["is_privileged"] or privilege["iced"]["may_require_cpl0"]
        table_cpl0 = bool(entry and entry.get("f2", {}).get("enable")
                          and all("CPL=0" in alt for alt in entry["f2"]["enable"]))
        if signals or (entry and "f2" in entry):
            f2 = {"voters": privilege, "ring0_candidate": any(cpl0) or table_cpl0}
            if len(set(cpl0)) > 1:
                f2["voters_disagree"] = "conflict"
            if len(cpl0) < len(raw):
                f2["not_provided"] = [name for name, value in zip(("iced", "zydis", "xed"), raw)
                                      if not isinstance(value, bool)]
            if entry is not None and cpl0 and table_cpl0 != all(cpl0):
                f2["table_vs_voter"] = {"table_requires_cpl0": table_cpl0, "voters": raw}
            facts["F2"] = f2
        if not cpl0 and not (entry and "f2" in entry):
            unobserved.setdefault("F2", "no voter provided a CPL0 bit")         # (r2 Fable P2-2)
        flows = {name: (v.flow, v.extra.get("flow_detail"), v.int_vector) for name, v in votes.items()}
        # (targets only where the decoder itself reports them: G1's XED target is computed at the operand width)
        targets = {v.target for v in votes.values() if v.target is not None and v.target_derivation == "decoder"}
        if (entry and "f3" in entry) or any(f[0] in TRANSFER_FLOWS for f in flows.values()):
            if len(set(flows.values())) != 1 or len(targets) > 1:
                unobserved["F3"] = "voters disagree on the continuation"
            else:
                flow, detail, vector = flows["xed"]
                f3 = {"flow": flow, "flow_detail": detail}
                if vector is not None:
                    f3["vector"] = vector
                if flow == "xbegin":
                    if targets:
                        f3["abort_target"] = f"{targets.pop():x}"
                    else:
                        unobserved["F3"] = "no decoder-reported abort target"
                facts["F3"] = f3
        split, why = _split(tables, basis, profiles, window, decode_without, checked_length)
        if why:
            unobserved.setdefault("F4", why)
        # (r2 Astra P1-4: the voters' features on every row the ordinary rule does not cover, table f4 or not)
        if split or not basis.startswith("ordinary:"):
            f4 = {"features": {"iced": votes["iced"].extra.get("cpuid_features"),
                               "zydis": votes["zydis"].extra.get("isa_set"), "xed": votes["xed"].extra.get("isa_set")}}
            if split:
                f4["split"] = split
            facts["F4"] = f4
        if split and split["source"] != "split_table" and basis not in FIXED_BASES:
            for kind in TABLE_SOURCED:          # (the baseline-profile form has no table entry behind this basis)
                if kind != "F4":
                    unobserved.setdefault(kind, f"the baseline profile decodes {split['baseline']}, outside the tables")
        values, why = _discriminators(tables, basis, window, votes)
        for kind, value in values.items():
            facts.setdefault(kind, {}).update(value)
        for kind, reason in why.items():
            unobserved.setdefault(kind, reason)
        f7, why = _f7(tables, votes)
        if why:
            unobserved["F7"] = why
        elif f7:
            facts.setdefault("F7", {})["accesses"] = f7
        if basis.startswith("ordinary:") and classified.get("flags"):
            flags = classified["flags"]
            if basis != "ordinary:plain" or any(flags.get(k) for k in ("simd_fp_exceptions", "writes_mxcsr_status",
                                                                        "explicit_mmx_operand", "alignment",
                                                                        "masked_write")) or flags.get("mxcsr_inputs"):
                facts["class_flags"] = flags
    else:
        for kind in ("F2", "F2p", "F3", "F7"):
            unobserved.setdefault(kind, "not every Intel voter decoded the row")
    f5, why = _f5(ballot)
    if why:
        unobserved["F5"] = why
    elif f5:
        facts["F5"] = f5
    return row


def listed(row: dict) -> bool:
    """Whether a row must be written (a row absent from the list reads as OMITTED_BASIS, nothing row-specific)."""
    return row["basis"] != OMITTED_BASIS or bool(row["facts"]) or bool(row["unobserved"])


def canonical_row(space: int, offset: int, row: dict) -> dict:
    out = {"space": space, "offset": f"{offset:x}", "basis": row["basis"],
           "facts": json.loads(json.dumps(row["facts"], sort_keys=True)),
           "unobserved": dict(sorted(row["unobserved"].items()))}
    if "keys" in row:
        out["keys"] = dict(sorted(row["keys"].items()))
    return out
