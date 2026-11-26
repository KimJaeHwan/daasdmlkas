"""TBR ISA facts: the versioned data files and the per-row form classification.

Designs: .census6/design_tbr_isa_facts_r3.md (step 2) and .census6/design_tbr_isa_ordinary_r3.md (2b, = r2 + r1).

- ``isa_conditions_x64.json``: the ISA condition table (r3 s1 layer 2), every entry citing its reference entry;
- ``iclass_map_x64.json``: per-voter mnemonic -> canonical key (r3 s1: per-voter lookup);
- ``isa_splits_x64.json``: feature-dependent encodings with their deciding feature and fallback (r3 s3 F4);
- ``isa_ordinary_x64.json``: the reviewed ordinary-form allowlist, base lists, classes (2b).

``load()`` validates them together and digests each over canonical bytes (header binding).
``lookup(vote, window)`` is one voter's cited lookup (``None``: absent for that voter).
``classify(tables, votes, window)`` combines the three Intel voters: cited first; only when every cited lookup
is absent, the ordinary allowlist with the per-voter tests of 2b r1 s4 (A-F). Nothing here is a verdict: TDO uses
a derived-ordinary result only under the premise ``isa-ordinary-rule`` (2b r1 s8).
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

_HERE = Path(__file__).resolve().parent
FILES = {"conditions": "isa_conditions_x64.json", "map": "iclass_map_x64.json", "splits": "isa_splits_x64.json",
         "ordinary": "isa_ordinary_x64.json"}
SCHEMAS = {"conditions": "tbr-isa-conditions-2", "map": "tbr-iclass-map-2", "splits": "tbr-isa-splits-2",
           "ordinary": "tbr-isa-ordinary-1"}
VOTERS = ("iced", "zydis", "xed")
LEGACY_PREFIXES = frozenset((0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65))
ENTRY_FIELDS = frozenset(("cite", "f2", "f2_meaning", "f3", "f4", "f5", "f6", "f7", "cet", "mpx", "access_width",
                          "state_dependent", "state_effect", "data_faults", "undefined_outputs", "split",
                          "split_member", "note"))
WHEN_FIELDS = frozenset(("operand_bits", "flow", "counter", "target_kind", "opcode", "modrm_reg", "prefix", "modrm"))
F7_FIELDS = frozenset(("writes_base", "writes_state", "when"))
# the evidence each voter must report for the ordinary tests (missing -> the test fails, never passes; impl r1 P1-2)
REQUIRED_EVIDENCE = {
    "xed": ("op_sig", "rep", "lock", "isa_set", "privileged_attribute", "rflags_read", "rflags_written",
            "sreg_operand", "category", "memory"),
    "zydis": ("op_sig", "rep", "lock", "isa_set", "privileged_attribute", "rflags_read", "rflags_written",
              "sreg_operand", "category", "memory"),
    "iced": ("op_sig", "rep", "lock", "cpuid_features", "must_be_cpl0", "is_privileged", "may_require_cpl0",
             "rflags_read", "rflags_written", "sreg_operand", "category", "is_input_output", "memory")}
CET_CONDITIONS = frozenset(("CET_SS", "CET_IBT"))
RFLAGS = {"TF": 1 << 8, "IF": 1 << 9, "IOPL": 3 << 12, "NT": 1 << 14, "RF": 1 << 16, "VM": 1 << 17, "AC": 1 << 18,
          "VIF": 1 << 19, "VIP": 1 << 20, "ID": 1 << 21}
SIG_KEEP = frozenset("mxykcfsMA")   # operand kinds that tell forms apart across voters (g / i / r conventions differ)


class TableError(ValueError):
    """The data files are malformed or inconsistent (the tables are then unusable as a whole)."""


def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class Tables:
    conditions: dict
    map: dict
    splits: dict
    ordinary: dict
    digests: dict      # {name: sha256 of canonical bytes}
    index: dict        # (iclass, extension, isa_set, sig) -> allowlist entry

    def entry(self, key: str) -> dict | None:
        return self.conditions["entries"].get(key)

    def split_of(self, key: str) -> dict | None:
        """The split whose main or fallback is `key` (the first; a fallback such as NOP serves several)."""
        for split in self.splits["splits"]:
            if key in (split["main"], split["fallback"]):
                return split
        return None

    def same_split(self, keys) -> dict | None:
        """The split whose {main, fallback} covers every key of `keys` (two or more distinct keys)."""
        keys = set(keys)
        if len(keys) < 2:
            return None
        for split in self.splits["splits"]:
            if keys <= {split["main"], split["fallback"]}:
                return split
        return None


def _load_json(name: str, root: Path) -> dict:
    return json.loads((root / FILES[name]).read_text(encoding="utf-8"))


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise TableError(message)


def validate(conditions: dict, mapping: dict, splits: dict, ordinary: dict | None = None) -> None:
    """Schema and cross-file consistency (a malformed table is never partly used)."""
    named = (("conditions", conditions), ("map", mapping), ("splits", splits)) + (
        (("ordinary", ordinary),) if ordinary is not None else ())
    for name, data in named:
        _check(data.get("schema") == SCHEMAS[name], f"{name}: schema is not {SCHEMAS[name]}")
    vocabulary = set(conditions["conditions"])
    documents = set(conditions["documents"])
    tags = set(conditions["f3_tags"])
    sources = set(conditions["f6_sources"])
    meanings = conditions.get("f2_meanings", {})
    expressions = set(conditions.get("cet_expressions", {}))
    mpx = set(conditions.get("mpx_effects", {}))
    entries = conditions["entries"]
    split_ids = {split["id"] for split in splits["splits"]}
    for key, entry in entries.items():
        _check(key == key.upper(), f"conditions: key {key} is not upper case")
        _check(set(entry) <= ENTRY_FIELDS, f"conditions: {key} has unknown fields {sorted(set(entry) - ENTRY_FIELDS)}")
        _check(bool(entry.get("cite")), f"conditions: {key} has no citation")
        for cite in entry["cite"]:
            _check(cite.get("doc") in documents and cite.get("entry"), f"conditions: {key} citation {cite}")
        for alternative in entry.get("f2", {}).get("enable", []):
            _check(bool(alternative), f"conditions: {key} has an empty f2 alternative")
            for name in alternative:
                _check(name in vocabulary, f"conditions: {key} uses unknown condition {name}")
        for name in entry.get("f2", {}):
            _check(name in ("enable", "effect_by_alternative"), f"conditions: {key} f2 field {name}")
        if "f2_meaning" in entry:
            _check(entry["f2_meaning"] in meanings, f"conditions: {key} f2_meaning {entry['f2_meaning']}")
        for tag in entry.get("f3", {}).get("tags", []):
            _check(tag in tags, f"conditions: {key} f3 tag {tag}")
        for output in entry.get("f6", []):
            _check(output.get("source") in sources, f"conditions: {key} f6 source {output}")
            if output["source"] == "constant":
                _check("value" in output, f"conditions: {key} f6 constant without a value")
        for item in entry.get("cet", []):
            _check(isinstance(item, dict) and item.get("name") in CET_CONDITIONS, f"conditions: {key} cet {item}")
            _check(set(item) <= {"name", "when", "unless"}, f"conditions: {key} cet fields {item}")
            for part in ("when", "unless"):
                if part in item:
                    _check(item[part] in expressions, f"conditions: {key} cet {part} {item[part]!r} unknown")
        if "mpx" in entry:
            _check(entry["mpx"] in mpx, f"conditions: {key} mpx {entry['mpx']}")
        for item in entry.get("undefined_outputs", []):
            _check(isinstance(item, dict) and item.get("output"), f"conditions: {key} undefined_outputs {item}")
        if "split" in entry:
            _check(entry["split"] in split_ids, f"conditions: {key} names unknown split {entry['split']}")
        _check(set(entry.get("f7", {})) <= F7_FIELDS, f"conditions: {key} f7 fields {sorted(entry.get('f7', {}))}")
    for meaning, item in meanings.items():
        _check(bool(item.get("cite")) and bool(item.get("outputs")), f"conditions: f2 meaning {meaning}")
        for output in item["outputs"]:
            for name in output.get("loaded_when", []):
                _check(name in vocabulary, f"conditions: f2 meaning {meaning} uses unknown condition {name}")
    seen_rules = {}
    for index, rule in enumerate(mapping["rules"]):
        where = f"map: rule {index}"
        _check(set(rule) <= {"voters", "mnemonic", "when", "key"}, f"{where} has unknown fields")
        _check(set(rule.get("voters", VOTERS)) <= set(VOTERS), f"{where} names an unknown voter")
        _check(bool(rule.get("mnemonic")) and all(m == m.upper() for m in rule["mnemonic"]), f"{where} mnemonics")
        _check(set(rule.get("when", {})) <= WHEN_FIELDS, f"{where} has unknown when fields")
        _check(rule["key"] != "=" or "*" not in rule["mnemonic"], f"{where}: key = with mnemonic *")
        keys = rule["mnemonic"] if rule["key"] == "=" else [rule["key"]]
        for key in keys:
            _check(key in entries, f"{where}: key {key} is not in the condition table")
        for voter in rule.get("voters", VOTERS):          # (the same selector must not give two keys)
            for mnemonic in rule["mnemonic"]:
                selector = (voter, mnemonic, json.dumps(rule.get("when", {}), sort_keys=True))
                key = mnemonic if rule["key"] == "=" else rule["key"]
                _check(seen_rules.setdefault(selector, key) == key, f"{where}: selector {selector} gives two keys")
    _check_overlaps(mapping["rules"])
    for split in splits["splits"]:
        for role in ("main", "fallback"):
            _check(split[role] in entries, f"splits: {split['id']} {role} {split[role]} is not in the condition table")
        _check(bool(split.get("feature")) and bool(split.get("cite")), f"splits: {split['id']} feature / cite")
    for item in splits["prefix_splits"] + splits["no_split"]:
        _check(bool(item.get("cite")) and bool(item.get("vector")), f"splits: {item['id']} cite / vector")
    if ordinary is not None:
        _validate_ordinary(ordinary, entries)


def _check_overlaps(rules: list) -> None:
    """Rules for the same voter and named mnemonic that give different keys (impl r1 P2-4) are rejected when
    (1) both list opcodes / ModRM values and the lists intersect, or (2) an earlier rule is at least as general
    as a later one, so the later rule can never be reached. Specific-then-general ordering is allowed. The "*"
    rules select by flow (the three jcc groups, reviewed as a set) and are not compared with named mnemonics."""
    lists = ("opcode", "modrm", "modrm_reg")

    def intersect(name, left, right):
        if name == "opcode":
            return any(x.startswith(y) or y.startswith(x) for x in left for y in right)
        return bool(set(left) & set(right))

    def covers(general, specific):                 # every field of `general` holds whenever `specific` holds
        for name, value in general.items():
            if name not in specific:
                return False
            other = specific[name]
            if name in lists:
                if name == "opcode":
                    if not all(any(o.startswith(g) for g in value) for o in other):
                        return False
                elif not set(other) <= set(value):
                    return False
            elif isinstance(value, list):
                if not set(other) <= set(value):
                    return False
            elif value != other:
                return False
        return True

    mnemonics = sorted({m for rule in rules for m in rule["mnemonic"] if m != "*"})
    for voter in VOTERS:
        for mnemonic in mnemonics:
            chosen = [(i, r) for i, r in enumerate(rules)
                      if voter in r.get("voters", VOTERS) and mnemonic in r["mnemonic"]]
            for x, (i, a) in enumerate(chosen):
                for j, b in chosen[x + 1:]:
                    key_a = mnemonic if a["key"] == "=" else a["key"]
                    key_b = mnemonic if b["key"] == "=" else b["key"]
                    if key_a == key_b:
                        continue
                    wa, wb = a.get("when", {}), b.get("when", {})
                    shared = [n for n in lists if n in wa and n in wb]
                    others_equal = all(wa.get(n) == wb.get(n) for n in set(wa) | set(wb) if n not in lists)
                    if shared and others_equal and all(intersect(n, wa[n], wb[n]) for n in shared):
                        _check(False, f"map: rules {i} and {j} select the same {shared} for {voter} {mnemonic}: "
                                      f"{key_a} / {key_b}")
                    _check(not covers(wa, wb), f"map: rule {j} ({key_b}) is shadowed by rule {i} ({key_a}) "
                                               f"for {voter} {mnemonic}")


def _validate_ordinary(ordinary: dict, cited: dict) -> None:
    classes = ordinary["classes"]
    for name, klass in classes.items():
        _check(bool(klass.get("cite")), f"ordinary: class {name} has no citation")
    _check(set(ordinary["system_flags"]["bits"]) <= set(RFLAGS), "ordinary: unknown system flag")
    seen = set()
    for entry in ordinary["entries"]:
        key = (entry["iclass"], entry["extension"], entry["isa_set"], entry["sig"])
        _check(key not in seen, f"ordinary: duplicate entry {key}")
        seen.add(key)
        _check(entry["class"] in classes, f"ordinary: {key} unknown class {entry['class']}")
        _check(entry["isa_set"] in ordinary["base_isa_sets"], f"ordinary: {key} ISA set outside the base level")
        _check(entry["iclass"] not in cited, f"ordinary: {key} is also cited in the condition table")
        _check(set(entry["names"]) == {"iced", "zydis"}, f"ordinary: {key} names")
        limit = ordinary.get("width_limits", {}).get(entry["iclass"])
        _check(limit is None or entry.get("widths") == limit["widths"], f"ordinary: {key} widths differ from width_limits")


def load(root: Path | None = None) -> Tables:
    root = root or _HERE
    data = {name: _load_json(name, root) for name in FILES}
    validate(data["conditions"], data["map"], data["splits"], data["ordinary"])
    digests = {name: hashlib.sha256(canonical_bytes(item)).hexdigest() for name, item in data.items()}
    index = {(e["iclass"], e["extension"], e["isa_set"], e["sig"]): e for e in data["ordinary"]["entries"]}
    return Tables(data["conditions"], data["map"], data["splits"], data["ordinary"], digests, index)


# -- one voter's cited lookup ----------------------------------------------------------------------

def opcode_view(window: bytes) -> tuple:
    """(legacy prefixes, opcode bytes, ModRM or None) of a legacy / REX encoded instruction; VEX / EVEX / XOP
    encodings give empty opcode bytes (no map rule qualifies them by opcode)."""
    index, prefixes = 0, []
    while index < len(window) and (window[index] in LEGACY_PREFIXES or 0x40 <= window[index] <= 0x4F):
        if window[index] in LEGACY_PREFIXES:   # (a REX followed by a legacy prefix is ignored, not the opcode)
            prefixes.append(window[index])
        index += 1
    if index >= len(window) or window[index] in (0xC4, 0xC5, 0x62, 0x8F):
        return tuple(prefixes), b"", None
    if window[index] == 0x0F:
        length = 3 if index + 1 < len(window) and window[index + 1] in (0x38, 0x3A) else 2
    else:
        length = 1
    opcode = bytes(window[index:index + length])
    modrm = window[index + length] if index + length < len(window) else None
    return tuple(prefixes), opcode, modrm


def _when_holds(when: dict, vote, view) -> bool:
    prefixes, opcode, modrm = view
    for name, wanted in when.items():
        if name == "operand_bits" and vote.operand_bits != wanted:
            return False
        if name == "flow" and vote.flow != wanted:
            return False
        if name == "counter" and bool(vote.counter) != wanted:
            return False
        if name == "target_kind" and vote.target_kind not in wanted:
            return False
        if name == "opcode" and not any(opcode.startswith(bytes.fromhex(item)) for item in wanted):
            return False
        if name == "modrm_reg" and (modrm is None or (modrm >> 3) & 7 not in wanted):
            return False
        if name == "prefix" and int(wanted, 16) not in prefixes:
            return False
        if name == "modrm" and (modrm is None or modrm not in {int(item, 16) for item in wanted}):
            return False
    return True


def lookup(tables: Tables, vote, window: bytes) -> str | None:
    """One voter's canonical key for its decode of `window` (an ok vote), or None when absent."""
    if vote.status != "ok":
        return None
    mnemonic = vote.mnemonic.upper()
    view = opcode_view(window)
    for rule in tables.map["rules"]:
        if vote.voter not in rule.get("voters", VOTERS):
            continue
        if mnemonic not in rule["mnemonic"] and "*" not in rule["mnemonic"]:
            continue
        if _when_holds(rule.get("when", {}), vote, view):
            return mnemonic if rule["key"] == "=" else rule["key"]
    return None


# -- the per-row classification (2b) ---------------------------------------------------------------

def _norm_sig(sig: str) -> str:
    return "".join(kind for kind in sig if kind in SIG_KEEP)


def _system_mask(tables: Tables, voter: str) -> int:
    capability = tables.ordinary["system_flags"]["capability"][voter]
    bits = tables.ordinary["system_flags"]["bits"] if capability == "all" else capability
    mask = 0
    for name in bits:
        mask |= RFLAGS[name]
    return mask


def _voter_failures(tables: Tables, entry: dict, vote, window: bytes) -> list:
    """The 2b r1 s4 tests (A-F) one voter fails for `entry`, from its own evidence: [(test, detail), ...]."""
    ordinary, extra, voter = tables.ordinary, vote.extra, vote.voter
    missing = [name for name in REQUIRED_EVIDENCE[voter] if name not in extra]
    if missing:
        return [("evidence", f"missing {missing}")]
    failures = []
    # A: form (name / alias, operand kinds, effective REP / LOCK, address and operand width). XED and Zydis share
    # the operand-kind convention and must match the entry exactly; iced lists implicit accumulator / count /
    # string registers as operands, so its check is the name plus the non-GPR, non-immediate kinds.
    if voter in ("xed", "zydis"):
        if extra["op_sig"] != entry["sig"]:
            failures.append(("A", f"operand kinds {extra['op_sig']!r} != {entry['sig']!r}"))
    if voter == "zydis" and vote.mnemonic.upper() not in entry["names"]["zydis"]:
        failures.append(("A", f"name {vote.mnemonic} not in {entry['names']['zydis']}"))
    if voter == "iced":
        if vote.mnemonic.upper() not in entry["names"][voter]:
            failures.append(("A", f"name {vote.mnemonic} not in {entry['names'][voter]}"))
        own = _norm_sig(extra.get("op_sig", ""))
        if voter == "iced" and entry["iclass"] == "XLAT":
            own = own.replace("M", "")                 # (iced lists XLAT's implicit [RBX + AL] as an operand)
        if own != _norm_sig(entry["sig"]):
            failures.append(("A", f"operand kinds {own!r} != {_norm_sig(entry['sig'])!r}"))
    if extra.get("rep", "") != entry["rep"]:
        failures.append(("A", f"rep {extra.get('rep')!r} != {entry['rep']!r}"))
    if bool(extra.get("lock")) != entry["lock"]:
        failures.append(("A", f"lock {extra.get('lock')} != {entry['lock']}"))
    if ("M" in entry["sig"] or "A" in entry["sig"] or extra.get("memory")) and vote.address_bits != 64:
        failures.append(("A", f"address width {vote.address_bits}"))
    if entry.get("widths"):
        # XED and Zydis must report the width; iced reports 0 for many forms (not provided, not a pass on its own)
        if voter in ("xed", "zydis") and not vote.operand_bits:
            failures.append(("A", "operand width not reported"))
        elif vote.operand_bits and vote.operand_bits not in entry["widths"]:
            failures.append(("A", f"operand width {vote.operand_bits} not in {entry['widths']}"))
    # B: base ISA level
    if voter == "iced":
        outside = sorted(set(extra.get("cpuid_features", ())) - set(ordinary["base_cpuid_features_iced"]))
        if outside or "cpuid_features" not in extra:
            failures.append(("B", f"features outside the base: {outside}"))
    elif extra.get("isa_set") not in ordinary["base_isa_sets"]:
        failures.append(("B", f"ISA set {extra.get('isa_set')}"))
    # C: privilege
    if voter == "iced":
        if extra.get("must_be_cpl0") or extra.get("is_privileged") or extra.get("may_require_cpl0"):
            failures.append(("C", "iced privilege flag"))
    elif extra.get("privileged_attribute"):
        failures.append(("C", "privileged attribute"))
    # D: system flags (per-voter capability)
    touched = (extra["rflags_read"] | extra["rflags_written"]) & _system_mask(tables, voter)
    if touched:
        failures.append(("D", f"system flags {touched:#x}"))
    # E: segment-register operand
    if extra.get("sreg_operand"):
        failures.append(("E", "segment-register operand"))
    # F: kind
    if voter == "iced":
        if extra.get("category") not in ordinary["iced_flow_controls"] or extra.get("is_input_output"):
            failures.append(("F", f"flow control {extra.get('category')}"))
    elif extra.get("category") not in ordinary["allowed_categories"]:
        failures.append(("F", f"category {extra.get('category')}"))
    return failures


def classify(tables: Tables, votes: dict, window: bytes) -> dict:
    """One compared row: cited / cited_split / table_lookup_disagree / partial_lookup / derived_ordinary /
    unclassified, with per-voter evidence and the digests applied (2b r2 G)."""
    out = {"digests": dict(tables.digests), "voters": {}}
    missing = [name for name in VOTERS if name not in votes or votes[name].status != "ok"]
    cited = {name: (lookup(tables, votes[name], window) if name not in missing else None) for name in VOTERS}
    for name in VOTERS:
        out["voters"][name] = {"cited": cited[name]}
    if missing:
        out.update(result="unclassified", reasons=[f"{name}: no ok vote" for name in missing],
                   keys={name: key for name, key in cited.items() if name not in missing})
        return out
    present = {key for key in cited.values() if key}
    if present:
        if None in cited.values():
            out.update(result="partial_lookup", keys=cited)
        elif len(present) == 1:
            out.update(result="cited", key=present.pop())
        elif tables.same_split(present):
            out.update(result="cited_split", split=tables.same_split(present)["id"], keys=cited)
        else:
            out.update(result="table_lookup_disagree", keys=cited)
        return out
    xed = votes["xed"]
    key = (xed.mnemonic.upper(), xed.extra.get("extension"), xed.extra.get("isa_set"), xed.extra.get("op_sig"))
    entry = tables.index.get(key)
    if entry is None:
        reasons = [f"xed: no allowlist entry for {key}"]
        if key[2] not in tables.ordinary["base_isa_sets"]:
            reasons.append(f"xed B: ISA set {key[2]} outside the base level")
        out.update(result="unclassified", reasons=reasons)
        return out
    prefixes = opcode_view(window)[0]
    reasons = []
    if (0xF2 in prefixes or 0xF3 in prefixes) and not entry["rep"] and entry["extension"] not in ("SSE", "SSE2"):
        reasons.append("an F2 / F3 prefix on a non-string, non-SSE form (ignored or HLE)")
    for name in VOTERS:
        failures = _voter_failures(tables, entry, votes[name], window)
        out["voters"][name]["failures"] = [f"{test}: {detail}" for test, detail in failures]
        reasons += [f"{name} {test}: {detail}" for test, detail in failures]
    if reasons:
        out.update(result="unclassified", reasons=reasons, entry=_entry_id(entry))
    else:
        flags = dict(entry["flags"])
        width_flags = entry.get("width_flags", {}).get(str(xed.operand_bits))
        if width_flags is not None:
            if votes["zydis"].operand_bits != xed.operand_bits:
                out.update(result="unclassified", reasons=["width-dependent flags: XED / Zydis widths differ"],
                           entry=_entry_id(entry))
                return out
            flags.update(width_flags)
        out.update(result="derived_ordinary", entry=_entry_id(entry), **{"class": entry["class"]}, flags=flags)
    return out


def _entry_id(entry: dict) -> dict:
    return {name: entry[name] for name in ("iclass", "extension", "isa_set", "sig")}
