"""TBR ISA facts 2b: generate the ordinary-form allowlist candidates (design .census6/design_tbr_isa_ordinary_r3.md,
= r2 + r1). The rule only GENERATES; the result is reviewed and pinned in ``isa_ordinary_x64.json`` (entries /
dropped). Input: the pinned XED catalogue dump (``decoders/xed_catalogue.c``), the hand-maintained sections of
``isa_ordinary_x64.json`` (base lists, allowed categories, class table) and the condition table (cited keys are
never candidates: r2 A1).

    python isa_ordinary_gen.py <xed_catalogue.tsv> [--write]

Without --write it prints the candidates grouped for review; with --write it rewrites the generated sections.
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

_HERE = Path(__file__).resolve().parent
ORDINARY = _HERE / "isa_ordinary_x64.json"
CONDITIONS = _HERE / "isa_conditions_x64.json"

# iced / Zydis condition-code spelling vs XED (Jcc / CMOVcc / SETcc share it)
ICED_CC = {"Z": "E", "NZ": "NE", "NB": "AE", "NBE": "A", "NL": "GE", "NLE": "G"}
CC_PREFIXES = ("CMOV", "SET")
X87_NOWAIT = {"FNINIT", "FNCLEX", "FNSTSW", "FNSTCW", "FNSTENV", "FNSAVE"}
# SDM Vol. 2 exception classes as XED names them: SIMD FP exceptions (and MXCSR read / status write) for Type 2 / 3
# and the MMX FP conversions; Type 1 / 2 / 4 legacy-SSE memory operands may need 16-byte alignment, Type 4M
# (unaligned moves MOVUPS / MOVUPD / MOVDQU) do not.
FP_EXCEPTIONS = {"SSE_TYPE_2", "SSE_TYPE_3", "MMX_FP", "MMX_FP_16ALIGN"}
ALIGNED = {"SSE_TYPE_1", "SSE_TYPE_2", "SSE_TYPE_4", "MMX_FP_16ALIGN"}
KNOWN_EXCEPTIONS = {"INVALID", "MMX_MEM", "MMX_FP", "MMX_FP_16ALIGN", "MMX_NOFP", "SSE_TYPE_1", "SSE_TYPE_2",
                    "SSE_TYPE_3", "SSE_TYPE_4", "SSE_TYPE_4M", "SSE_TYPE_5", "SSE_TYPE_7"}
STRING_REP = ("REP_", "REPE_", "REPNE_")


def read_catalogue(path: Path) -> list:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        iclass, category, extension, isa_set, ring0, exception, sig, sreg = line.split("\t")
        rows.append({"iclass": iclass, "category": category, "extension": extension, "isa_set": isa_set,
                     "ring0": ring0 == "1", "exception": exception, "sig": "" if sig == "-" else sig,
                     "sreg": sreg == "1"})
    return rows


def form_base(iclass: str) -> tuple:
    """(name the other decoders use, effective rep, lock) for a XED iclass."""
    rep = ""
    for prefix, kind in (("REPNE_", "repne"), ("REPE_", "rep"), ("REP_", "rep")):
        if iclass.startswith(prefix):
            iclass, rep = iclass[len(prefix):], kind
            break
    lock = iclass.endswith("_LOCK")
    if lock:
        iclass = iclass[: -len("_LOCK")]
    return iclass, rep, lock


def aliases(base: str) -> dict:
    """iced / Zydis names for a XED base name (upper case)."""
    names = {"iced": {base}, "zydis": {base}}
    for prefix in CC_PREFIXES:
        if base.startswith(prefix) and base[len(prefix):] in ICED_CC:
            names["iced"] = {prefix + ICED_CC[base[len(prefix):]]}
    special = {"MOVSD_XMM": "MOVSD", "CMPSD_XMM": "CMPSD"}
    if base in special:
        names["iced"] = names["zydis"] = {special[base]}
    if base == "XLAT":
        names["iced"] = {"XLATB"}
    if base == "FWAIT":
        names["iced"] = {"WAIT"}
    return {voter: sorted(items) for voter, items in names.items()}


def classify_form(row: dict) -> tuple:
    """(class, flags) or (None, reason)."""
    iclass, extension, exception, sig = row["iclass"], row["extension"], row["exception"], row["sig"]
    if exception not in KNOWN_EXCEPTIONS:
        return None, f"exception class {exception} not stated"
    fp = exception in FP_EXCEPTIONS
    flags = {"simd_fp_exceptions": fp, "reads_mxcsr": fp, "writes_mxcsr_status": fp,
             "explicit_mmx_operand": "m" in sig, "alignment": "M" in sig and exception in ALIGNED}
    if row["isa_set"] == "SSE2MMX":
        return None, "SSE2 on MMX registers: OSFXSR dependence not stated"
    if iclass in ("FXSAVE", "FXSAVE64"):
        return "fxsave", flags
    if iclass in ("FXRSTOR", "FXRSTOR64"):
        return "fxrstor", flags
    if iclass in ("LDMXCSR", "STMXCSR"):
        return "mxcsr", flags
    if extension == "X87":
        return ("fwait" if iclass == "FWAIT" else "x87_nowait" if iclass in X87_NOWAIT else "x87"), flags
    if extension == "MMX":
        return "mmx", flags
    if extension in ("SSE", "SSE2"):
        if "m" in sig:
            return "mmx_sse", flags
        if "x" in sig or exception != "INVALID":   # XMM forms, and SSE forms reading memory (CVTSD2SI r, m64 ...)
            return ("sse_fp" if fp else "sse_int"), flags
        return "plain", flags              # exception INVALID, no XMM / MMX operand: fences, MOVNTI, PREFETCHh
    return "plain", flags


def generate(rows: list, ordinary: dict, cited: set) -> tuple:
    base = set(ordinary["base_isa_sets"])
    allowed = set(ordinary["allowed_categories"])
    prefetch_isa = set(ordinary.get("prefetch_isa_sets", ()))
    reviewed = {item["iclass"]: item["reason"] for item in ordinary.get("reviewed_drops", ())}
    widths = {name: item["widths"] for name, item in ordinary.get("width_limits", {}).items()}
    entries, dropped = {}, {}
    for row in rows:
        why = None
        name, rep, lock = form_base(row["iclass"])
        if row["isa_set"] not in base:
            continue                                       # (not a base form: never a candidate, no listing)
        if row["category"] not in allowed:
            why = f"category {row['category']}"
        elif row["category"] == "PREFETCH" and row["isa_set"] not in prefetch_isa:
            why = "prefetch outside SSE_PREFETCH"
        elif row["ring0"]:
            why = "RING0 attribute"
        elif row["sreg"]:
            why = "segment-register operand"
        elif row["iclass"] in cited or name in cited:
            why = "cited in the condition table"
        elif row["iclass"] in reviewed:
            why = "reviewed: " + reviewed[row["iclass"]]
        key = (row["iclass"], row["extension"], row["isa_set"], row["sig"])
        if why:
            dropped.setdefault(key, {"iclass": row["iclass"], "extension": row["extension"],
                                     "isa_set": row["isa_set"], "sig": row["sig"], "reason": why})
            continue
        klass, flags = classify_form(row)
        if klass is None:
            dropped.setdefault(key, {"iclass": row["iclass"], "extension": row["extension"],
                                     "isa_set": row["isa_set"], "sig": row["sig"], "reason": flags})
            continue
        entry = {"iclass": row["iclass"], "extension": row["extension"], "isa_set": row["isa_set"],
                 "sig": row["sig"], "exception": row["exception"], "class": klass, "flags": flags,
                 "names": aliases(name), "rep": rep, "lock": lock, "widths": widths.get(row["iclass"])}
        if key in entries and (entries[key]["class"], entries[key]["flags"]) != (klass, flags):
            entries.pop(key)
            dropped[key] = {"iclass": row["iclass"], "extension": row["extension"], "isa_set": row["isa_set"],
                            "sig": row["sig"], "reason": "one form, two classes"}
            continue
        if key not in dropped:
            entries[key] = entry
    order = lambda item: (item["iclass"], item["extension"], item["isa_set"], item["sig"])
    return sorted(entries.values(), key=order), sorted(dropped.values(), key=order)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("catalogue", type=Path)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    ordinary = json.loads(ORDINARY.read_text(encoding="utf-8"))
    cited = set(json.loads(CONDITIONS.read_text(encoding="utf-8"))["entries"])
    entries, dropped = generate(read_catalogue(args.catalogue), ordinary, cited)
    by_class = collections.defaultdict(list)
    for entry in entries:
        by_class[entry["class"]].append(entry)
    for klass in sorted(by_class):
        names = sorted({e["iclass"] for e in by_class[klass]})
        print(f"{klass} ({len(by_class[klass])} forms, {len(names)} iclasses): {' '.join(names)}")
    reasons = collections.Counter(item["reason"] for item in dropped)
    print("dropped:", dict(reasons))
    for item in dropped:
        if item["reason"] not in ("cited in the condition table",):
            print("  drop", item["iclass"], item["extension"], item["isa_set"], item["sig"], "--", item["reason"])
    if args.write:
        ordinary["entries"] = entries
        ordinary["generated_drops"] = dropped
        ORDINARY.write_text(json.dumps(ordinary, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        print("written", ORDINARY)


if __name__ == "__main__":
    main()
