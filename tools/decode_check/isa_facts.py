"""TBR ISA facts step 3: per-row facts F1-F7 (design .census6/design_tbr_isa_facts_r3.md s1-s5; the 2b
classification of .census6/design_tbr_isa_ordinary_r3.md).

``row_facts`` is a pure function of one row's verified window, its G1 ballot and the pinned tables. It writes
only what is specific to the row:
- the per-voter values;
- the XED profile results;
- FS / GS accesses;
- Intel / AMD differences;
- the split decision.

Table content (conditions, f3 tags, f6 outputs, CET / MPX, class conditions) is referenced through the row's
basis key, so a reader resolves it from the same pinned tables. Nothing here is a verdict: the reader
(evidence.py) states the premises a negative needs.
"""

from __future__ import annotations

import hashlib
import json

import isa_tables

FACT_SCHEMA = "tbr-isa-facts-1"
KINDS = ("F1", "F2", "F2p", "F3", "F4", "F5", "F6", "F7")
OMITTED_BASIS = "ordinary:plain"          # a row absent from the list: derived-ordinary plain, nothing row-specific
TABLE_SOURCED = ("F2", "F2p", "F3", "F4", "F6", "F7")
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
F5_FIELDS = ("status", "length", "flow", "target", "target_ip_bits")


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


def _privilege(votes: dict) -> dict:
    iced, zydis, xed = votes["iced"].extra, votes["zydis"].extra, votes["xed"].extra
    return {"iced": {"must_be_cpl0": iced.get("must_be_cpl0"), "is_privileged": iced.get("is_privileged"),
                     "may_require_cpl0": iced.get("may_require_cpl0")},
            "zydis": {"IS_PRIVILEGED": zydis.get("privileged_attribute")},
            "xed": {"RING0": xed.get("privileged_attribute")}}


def _f1(votes: dict, profiles: dict) -> dict:
    voters = {name: {"status": v.status, "error": v.extra.get("error", "")} for name, v in votes.items()}
    views = {name: {"status": v.status, "error": v.extra.get("error", ""), "mnemonic": v.mnemonic}
             for name, v in profiles.items()}
    every = list(voters.values()) + list(views.values())
    if all(item["status"] == "ok" for item in every):
        klass = "valid"
    elif all(item["status"] == "invalid" and item["error"] != "INVALID_FOR_CHIP" for item in every):
        klass = "invalid_encoding"
    elif views["xed:all"]["status"] == "ok" and all(v["status"] == "ok" for v in voters.values()):
        klass = "invalid_for_chip"   # a profile rejects what the all-features chip and every voter accept
    else:
        klass = "mixed"
    return {"class": klass, "voters": voters, "profiles": views}


def _split(tables, basis: str, profiles: dict, window: bytes, decode_without) -> dict | None:
    base, full = profiles["xed:baseline"], profiles["xed:all"]
    if basis.startswith("split:"):
        return {"source": "split_table", "split": basis.split(":", 1)[1]}
    if not (base.status == "ok" and full.status == "ok" and base.length == full.length
            and base.mnemonic != full.mnemonic):
        return None
    keys = {isa_tables.lookup(tables, base, window), isa_tables.lookup(tables, full, window)}
    known = tables.same_split(keys) if None not in keys else None
    if known:
        return {"source": "split_table", "split": known["id"], "baseline": base.mnemonic, "all": full.mnemonic}
    feature = full.extra.get("isa_set", "")
    single = decode_without(feature, window) if feature else None
    if single is not None and single.status == "ok" and single.mnemonic == base.mnemonic:
        return {"source": "single_feature_run", "deciding_feature": feature, "baseline": base.mnemonic,
                "all": full.mnemonic}
    return {"source": "profiles", "split_feature_unknown": True, "baseline": base.mnemonic, "all": full.mnemonic}


def _f5(ballot: dict) -> tuple:
    intel = dict(zip(("iced", "zydis", "xed"), ballot["intel"]))
    amd = dict(zip(("iced", "zydis"), ballot["amd"]))
    if any(v.status == "error" for v in amd.values()):
        return None, "an AMD-mode decode failed"
    differences = {}
    for name, vote in amd.items():
        diff = {field: [getattr(intel[name], field), getattr(vote, field)] for field in F5_FIELDS
                if getattr(intel[name], field) != getattr(vote, field)}
        if diff:
            differences[name] = diff
    return (differences or None), None


def _f7(tables, votes: dict) -> tuple:
    views = {}
    for name, vote in votes.items():
        if not vote.extra.get("memory_complete", False) or vote.extra.get("mem_overflow"):
            return None, f"{name}: memory evidence incomplete"
        accesses = isa_tables.memory_evidence(tables, vote)
        views[name] = sorted((m["segment"], m["read"], m["write"], m["conditional"]) for m in accesses
                             if m["segment"] in ("fs", "gs"))
    if len({tuple(view) for view in views.values()}) != 1:
        return None, "voters disagree on the FS / GS accesses"
    accesses = views["xed"]
    if not accesses:
        return None, None
    return [{"segment": s, "read": r, "write": w, "conditional": c} for s, r, w, c in accesses], None


def row_facts(tables, ballot: dict, window: bytes, *, redecode, decode_profile, decode_without) -> dict:
    """{"basis", "facts", "unobserved"} for one byte-verified row (design r3 s5: computed only from G1's verified
    window). ``ballot`` = decoders.ballot(window); the callables re-decode the same window."""
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
    if not basis.startswith(("cited:", "split:", "ordinary:")):
        reason = "; ".join(classified.get("reasons", [])) or result
        for kind in TABLE_SOURCED:
            unobserved[kind] = f"no table basis ({reason})"[:300]
    profiles = {name: decode_profile(name, window) for name in ("xed:g1", "xed:baseline", "xed:all")}
    f1 = _f1(votes, profiles)
    if f1["class"] != "valid" or len({p["mnemonic"] for p in f1["profiles"].values()}) > 1:
        facts["F1"] = f1
    ok = all(v.status == "ok" for v in votes.values())
    entry = tables.entry(basis.split(":", 1)[1]) if basis.startswith("cited:") else None
    if ok:
        privilege = _privilege(votes)
        cpl0 = [privilege["iced"]["must_be_cpl0"], privilege["zydis"]["IS_PRIVILEGED"], privilege["xed"]["RING0"]]
        signals = any(cpl0) or privilege["iced"]["is_privileged"] or privilege["iced"]["may_require_cpl0"]
        table_cpl0 = bool(entry and entry.get("f2", {}).get("enable")
                          and all("CPL=0" in alt for alt in entry["f2"]["enable"]))
        if signals or (entry and "f2" in entry):
            f2 = {"voters": privilege, "ring0_candidate": any(cpl0) or table_cpl0}
            if len(set(cpl0)) > 1:
                f2["voters_disagree"] = "conflict"
            if entry is not None and table_cpl0 != all(cpl0):
                f2["table_vs_voter"] = {"table_requires_cpl0": table_cpl0, "voters": cpl0}
            facts["F2"] = f2
        if entry and "f2_meaning" in entry:
            facts["F2p"] = {"meaning": entry["f2_meaning"]}
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
        split = _split(tables, basis, profiles, window, decode_without)
        if split or (entry and "f4" in entry) or not basis.startswith("ordinary:"):
            f4 = {"features": {"iced": votes["iced"].extra.get("cpuid_features"),
                               "zydis": votes["zydis"].extra.get("isa_set"), "xed": votes["xed"].extra.get("isa_set")}}
            if split:
                f4["split"] = split
            facts["F4"] = f4
        f7, why = _f7(tables, votes)
        if why:
            unobserved["F7"] = why
        elif f7:
            facts["F7"] = {"accesses": f7}
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
    return {"basis": basis, "facts": facts, "unobserved": unobserved}


def listed(row: dict) -> bool:
    """Whether a row must be written (a row absent from the list reads as OMITTED_BASIS, nothing row-specific)."""
    return row["basis"] != OMITTED_BASIS or bool(row["facts"]) or bool(row["unobserved"])


def canonical_row(space: int, offset: int, row: dict) -> dict:
    return {"space": space, "offset": f"{offset:x}", "basis": row["basis"],
            "facts": json.loads(json.dumps(row["facts"], sort_keys=True)), "unobserved": dict(sorted(row["unobserved"].items()))}
