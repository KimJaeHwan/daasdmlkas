"""TBR ISA facts: the versioned data files and the per-row form classification.

Designs: .census6/design_tbr_isa_facts_r3.md (step 2) and .census6/design_tbr_isa_ordinary_r3.md (2b, = r2 + r1).

- ``isa_conditions_x64.json``: the ISA condition table (r3 s1 layer 2), every entry citing its reference entry;
- ``iclass_map_x64.json``: per-voter mnemonic -> canonical key (r3 s1: per-voter lookup);
- ``isa_splits_x64.json``: feature-dependent encodings with their deciding feature and fallback (r3 s3 F4);
- ``isa_ordinary_x64.json``: the reviewed ordinary-form allowlist, base lists, classes (2b).

``load()`` validates them together and digests each over canonical bytes (header binding).
``lookup(vote, window)`` is one voter's cited lookup (``None``: absent for that voter).
``classify(tables, votes, window, redecode)`` combines the three Intel voters: the evidence is validated and the
XED vote bound to the bytes (``redecode`` = ``decoders.xed_redecode``; without it the row is unclassified); then cited
first; only when every cited lookup is absent, the ordinary allowlist with the per-voter tests of 2b r1 s4 (A-F).
Nothing here is a verdict: TDO uses a derived-ordinary result only under the premise ``isa-ordinary-rule``
(2b r1 s8).
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
WHEN_FIELDS = frozenset(("operand_bits", "flow", "counter", "target_kind", "opcode", "modrm_reg", "prefix", "modrm",
                         "prefixes_only", "rex_b", "rex_w", "prefixes_exact", "no_rex"))
LIST_FIELDS = ("opcode", "modrm", "modrm_reg", "target_kind", "prefixes_only", "prefixes_exact")
HEX_FIELDS = ("opcode", "modrm", "prefixes_only", "prefixes_exact")
MEMORY_ENTRY_TYPES = {"segment": str, "read": bool, "write": bool, "role": str, "cond_read": bool, "cond_write": bool,
                      "conditional": bool}
F7_FIELDS = frozenset(("writes_base", "writes_state", "when"))
# the evidence each voter must report for the ordinary tests (missing -> the test fails, never passes; impl r1 P1-2)
REQUIRED_EVIDENCE = {
    "xed": ("op_sig", "rep", "lock", "isa_set", "privileged_attribute", "rflags_read", "rflags_written",
            "sreg_operand", "category", "memory", "iform"),
    "zydis": ("op_sig", "rep", "lock", "isa_set", "privileged_attribute", "rflags_read", "rflags_written",
              "sreg_operand", "category", "memory"),
    "iced": ("op_sig", "rep", "lock", "cpuid_features", "must_be_cpl0", "is_privileged", "may_require_cpl0",
             "rflags_read", "rflags_written", "sreg_operand", "category", "is_input_output", "memory")}
# value types of that evidence (impl r2 P1-1: a present field of the wrong type is missing evidence too)
EVIDENCE_TYPES = {"op_sig": str, "rep": str, "lock": bool, "isa_set": str, "privileged_attribute": bool,
                  "rflags_read": int, "rflags_written": int, "sreg_operand": bool, "category": str, "memory": list,
                  "cpuid_features": list, "must_be_cpl0": bool, "is_privileged": bool, "may_require_cpl0": bool,
                  "is_input_output": bool, "iform": str}
SIG_KINDS = frozenset("gmxykscfMAir")
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
        _check(set(entry.get("f5", {})) <= {"amd", "intel", "unverified"}, f"conditions: {key} f5 fields")
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
        _check(set(rule) <= {"voters", "mnemonic", "when", "key", "fallback"}, f"{where} has unknown fields")
        _check(set(rule.get("voters", VOTERS)) <= set(VOTERS), f"{where} names an unknown voter")
        _check(bool(rule.get("mnemonic")) and all(m == m.upper() for m in rule["mnemonic"]), f"{where} mnemonics")
        _check(set(rule.get("when", {})) <= WHEN_FIELDS, f"{where} has unknown when fields")
        _check("*" not in rule["mnemonic"], f"{where}: wildcard mnemonics are not allowed (impl r3 P2-1)")
        when = rule.get("when", {})
        for name in HEX_FIELDS:
            for item in when.get(name, ()):
                _check(_canonical_hex(item), f"{where}: {name} value {item!r} is not canonical upper-case hex")
        if "prefix" in when:
            _check(_canonical_hex(when["prefix"]), f"{where}: prefix {when['prefix']!r} is not canonical hex")
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


def _canonical_hex(text) -> bool:
    return isinstance(text, str) and len(text) % 2 == 0 and len(text) > 0 and all(c in "0123456789ABCDEF" for c in text)


def _prefix_sets_meet(a: dict, b: dict) -> bool:
    """Can one prefix sequence satisfy the prefix constraints of both rules (prefix / prefixes_only /
    prefixes_exact)? Different required prefixes can co-occur (impl r3 P2-1)."""
    for x, y in ((a, b), (b, a)):
        if "prefixes_exact" in x:
            exact = set(x["prefixes_exact"])
            if "prefixes_exact" in y and list(x["prefixes_exact"]) != list(y["prefixes_exact"]):
                return False
            if "prefixes_only" in y and not exact <= set(y["prefixes_only"]):
                return False
            if "prefix" in y and y["prefix"] not in exact:
                return False
        if "prefixes_only" in x and "prefix" in y and y["prefix"] not in x["prefixes_only"]:
            return False
    return True


def _rex_meet(a: dict, b: dict) -> bool:
    for x, y in ((a, b), (b, a)):
        if x.get("no_rex") and (y.get("rex_b") or y.get("rex_w")):
            return False
    return True


def _fields_overlap(a: dict, b: dict) -> bool:
    """Can one vote satisfy both `when` dicts? A field only one side constrains never separates them; exact ModRM
    and ModRM.reg constraints are compared against each other."""
    if not _prefix_sets_meet(a, b) or not _rex_meet(a, b):
        return False
    for name in set(a) | set(b):
        if name not in a or name not in b or name in ("prefix", "prefixes_only", "prefixes_exact", "no_rex"):
            continue
        left, right = a[name], b[name]
        if name == "opcode":
            if not any(x.startswith(y) or y.startswith(x) for x in left for y in right):
                return False
        elif name in LIST_FIELDS:
            if not set(left) & set(right):
                return False
        elif left != right:
            return False
    if "modrm" in a and "modrm_reg" in b and not any((int(m, 16) >> 3) & 7 in b["modrm_reg"] for m in a["modrm"]):
        return False
    if "modrm" in b and "modrm_reg" in a and not any((int(m, 16) >> 3) & 7 in a["modrm_reg"] for m in b["modrm"]):
        return False
    return True


def _covers(general: dict, specific: dict) -> bool:
    """Every vote that satisfies `specific` also satisfies `general` (unsure -> False)."""
    for name, value in general.items():
        if name == "modrm_reg" and "modrm_reg" not in specific and "modrm" in specific:
            if not all((int(m, 16) >> 3) & 7 in value for m in specific["modrm"]):
                return False
            continue
        if name == "prefix" and "prefix" not in specific and value in specific.get("prefixes_exact", ()):
            continue
        if name == "prefixes_only" and "prefixes_exact" in specific and "prefixes_only" not in specific:
            if not set(specific["prefixes_exact"]) <= set(value):
                return False
            continue
        if name not in specific:
            return False
        other = specific[name]
        if name == "opcode":
            if not all(any(o.startswith(g) for g in value) for o in other):
                return False
        elif name == "prefixes_exact":
            if list(other) != list(value):
                return False
        elif name in LIST_FIELDS:
            if not set(other) <= set(value):
                return False
        elif value != other:
            return False
    return True


def _check_overlaps(rules: list) -> None:
    """Two rules that one vote can satisfy and that give different keys are rejected (impl r1 P2-4, r2 P2-3,
    r3 P2-1), with one exception: a later rule marked `fallback` that covers an earlier, more specific rule
    (specific first, then the general default). Every rule names its mnemonics (no wildcard), so the check
    sees exactly what the lookup sees."""
    def mnemonics_meet(a, b):
        return bool(set(a["mnemonic"]) & set(b["mnemonic"]))

    for i, a in enumerate(rules):
        for j in range(i + 1, len(rules)):
            b = rules[j]
            if not set(a.get("voters", VOTERS)) & set(b.get("voters", VOTERS)) or not mnemonics_meet(a, b):
                continue
            for mnemonic in sorted(set(a["mnemonic"]) & set(b["mnemonic"])):
                key_a = mnemonic if a["key"] == "=" else a["key"]
                key_b = mnemonic if b["key"] == "=" else b["key"]
                if key_a == key_b:
                    continue
                wa, wb = a.get("when", {}), b.get("when", {})
                if not _fields_overlap(wa, wb):
                    continue
                if b.get("fallback") and _covers(wb, wa):
                    continue
                _check(False, f"map: rules {i} ({key_a}) and {j} ({key_b}) can select the same vote ({mnemonic})")


def _validate_ordinary(ordinary: dict, cited: dict) -> None:
    classes = ordinary["classes"]
    for name, klass in classes.items():
        _check(bool(klass.get("cite")), f"ordinary: class {name} has no citation")
        _check(all(set(item) == {"condition", "intel", "amd"} for item in klass.get("f5", ())),
               f"ordinary: class {name} f5 items need condition / intel / amd")
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
    """(legacy prefixes, opcode bytes, ModRM or None): see encoding_view."""
    return encoding_view(window)[:3]


def encoding_view(window: bytes) -> tuple:
    """(legacy prefixes, opcode bytes, ModRM or None, REX or 0) of a legacy / REX encoded instruction; VEX / EVEX /
    XOP encodings give empty opcode bytes (no map rule qualifies them by opcode). Only a REX immediately before the
    opcode is effective; a REX followed by a legacy prefix is ignored."""
    index, prefixes, rex = 0, [], 0
    while index < len(window) and (window[index] in LEGACY_PREFIXES or 0x40 <= window[index] <= 0x4F):
        if window[index] in LEGACY_PREFIXES:
            prefixes.append(window[index])
            rex = 0
        else:
            rex = window[index]
        index += 1
    if index >= len(window) or window[index] in (0xC4, 0xC5, 0x62, 0x8F):
        return tuple(prefixes), b"", None, rex
    if window[index] == 0x0F:
        length = 3 if index + 1 < len(window) and window[index + 1] in (0x38, 0x3A) else 2
    else:
        length = 1
    opcode = bytes(window[index:index + length])
    modrm = window[index + length] if index + length < len(window) else None
    return tuple(prefixes), opcode, modrm, rex


def _when_holds(when: dict, vote, view) -> bool:
    prefixes, opcode, modrm, rex = view
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
        if name == "prefixes_only" and not set(prefixes) <= {int(item, 16) for item in wanted}:
            return False
        if name == "rex_b" and bool(rex & 1) != wanted:
            return False
        if name == "rex_w" and bool(rex & 8) != wanted:
            return False
        if name == "prefixes_exact" and list(prefixes) != [int(item, 16) for item in wanted]:
            return False
        if name == "no_rex" and wanted and rex:
            return False
    return True


def lookup(tables: Tables, vote, window: bytes) -> str | None:
    """One voter's canonical key for its decode of `window` (an ok vote), or None when absent."""
    if vote.status != "ok":
        return None
    mnemonic = vote.mnemonic.upper()
    view = encoding_view(window)
    for rule in tables.map["rules"]:
        if vote.voter not in rule.get("voters", VOTERS):
            continue
        if mnemonic not in rule["mnemonic"]:
            continue
        if _when_holds(rule.get("when", {}), vote, view):
            return mnemonic if rule["key"] == "=" else rule["key"]
    return None


# -- the per-row classification (2b) ---------------------------------------------------------------

def _norm_sig(sig: str) -> str:
    return "".join(kind for kind in sig if kind in SIG_KEEP)


def evidence_problems(vote) -> list:
    """Why a voter's evidence cannot be used (empty when usable): required fields, types, list elements,
    memory entries (impl r3 P1-2). Checked before any lookup uses the evidence."""
    extra, voter = vote.extra, vote.voter
    problems = []
    if not isinstance(extra, dict):
        return ["evidence is not a mapping"]
    for name in REQUIRED_EVIDENCE.get(voter, ()):
        value = extra.get(name, None)
        wanted = EVIDENCE_TYPES[name]
        if name not in extra or not isinstance(value, wanted) or (wanted is int and isinstance(value, bool)):
            problems.append(f"{name} missing or mistyped")
    if isinstance(extra.get("op_sig"), str) and not set(extra["op_sig"]) <= SIG_KINDS:
        problems.append(f"unknown operand kind in {extra['op_sig']!r}")
    if isinstance(extra.get("cpuid_features"), list) and not all(isinstance(f, str) for f in extra["cpuid_features"]):
        problems.append("cpuid_features elements are not names")
    for item in extra.get("memory", ()) if isinstance(extra.get("memory"), list) else ():
        if not isinstance(item, dict) or any(not isinstance(item.get(key), kind) for key, kind in MEMORY_ENTRY_TYPES.items()):
            problems.append("a memory entry is malformed")
            break
    if not isinstance(vote.mnemonic, str) or not isinstance(vote.operand_bits, int):
        problems.append("mnemonic / operand width missing")
    return problems


def memory_evidence(tables: Tables, vote) -> list:
    """The voter's memory accesses with the reviewed per-access semantics applied (impl r3 P2-3): a masked write
    (MASKMOVDQU / MASKMOVQ) is conditional even when the decoder reports a plain write."""
    accesses = [dict(item) for item in vote.extra.get("memory", ())]
    masked = tables.conditions.get("memory_semantics", {}).get("masked_write", {})
    if vote.mnemonic.upper() in masked.get("mnemonics", {}).get(vote.voter, ()):
        for item in accesses:
            if item["write"]:
                item["cond_write"] = item["conditional"] = True
                item["semantics"] = "masked_write"
    return accesses


def _iced_convention(tables: Tables, window: bytes, entry_sig: str, iced_sig: str) -> bool:
    """A pinned (encoding, XED signature, iced signature) convention pair (impl r2 P1-1)."""
    _, opcode, modrm, _ = encoding_view(window)
    for pair in tables.ordinary["iced_operand_conventions"]["pairs"]:
        if pair["xed"] != entry_sig or pair["iced"] != iced_sig:
            continue
        if not any(opcode == bytes.fromhex(item) for item in pair["opcodes"]):
            continue
        if "modrm" in pair and (modrm is None or modrm not in {int(item, 16) for item in pair["modrm"]}):
            continue
        return True
    return False


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
    problems = evidence_problems(vote)
    if problems:
        return [("evidence", "; ".join(problems))]
    failures = []
    # A: form (name / alias, operand kinds, effective REP / LOCK, address and operand width). XED and Zydis share
    # the operand-kind convention and must match the entry exactly; iced lists implicit accumulator / count /
    # string registers as operands, so its check is the name plus the non-GPR, non-immediate kinds.
    if voter in ("xed", "zydis"):
        if extra["op_sig"] != entry["sig"]:
            failures.append(("A", f"operand kinds {extra['op_sig']!r} != {entry['sig']!r}"))
    if voter == "xed" and extra.get("iform") not in entry.get("iforms", ()):
        failures.append(("A", f"iform {extra.get('iform')!r} not in the entry"))
    if voter == "zydis" and vote.mnemonic.upper() not in entry["names"]["zydis"]:
        failures.append(("A", f"name {vote.mnemonic} not in {entry['names']['zydis']}"))
    if voter == "iced":
        if vote.mnemonic.upper() not in entry["names"][voter]:
            failures.append(("A", f"name {vote.mnemonic} not in {entry['names'][voter]}"))
        if extra["op_sig"] != entry["sig"] and not _iced_convention(tables, window, entry["sig"], extra["op_sig"]):
            failures.append(("A", f"operand kinds {extra['op_sig']!r} != {entry['sig']!r} (no pinned iced convention)"))
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


def classify(tables: Tables, votes: dict, window: bytes, redecode=None) -> dict:
    """One compared row: cited / cited_split / table_lookup_disagree / partial_lookup / derived_ordinary /
    unclassified, with per-voter evidence and the digests applied (2b r2 G).

    `redecode(window)` (``decoders.xed_redecode``) re-decodes the verified window with the XED G1 setting; the
    XED vote must equal it (status, mnemonic, length, operand kinds, iform), which binds the evidence to the bytes
    (impl r3 P1-1). Without it the row is unclassified (no byte binding). Scope: only the XED vote is bound here;
    the iced and Zydis votes rely on the pipeline decoding the same verified window (decode_check.ballot) --
    re-check this if another input path ever feeds classify."""
    out = {"digests": dict(tables.digests), "voters": {}}
    bad = {name: evidence_problems(votes[name]) for name in VOTERS
           if name in votes and votes[name].status == "ok" and evidence_problems(votes[name])}
    if bad:
        out.update(result="unclassified",
                   reasons=[f"{name} evidence: {problem}" for name, problems in bad.items() for problem in problems])
        return out
    if "xed" in votes and votes["xed"].status == "ok":
        if redecode is None:
            out.update(result="unclassified", reasons=["no byte binding (no XED re-decode of the verified window)"])
            return out
        fresh, xed = redecode(window), votes["xed"]
        same = (fresh.status == xed.status and fresh.mnemonic == xed.mnemonic and fresh.length == xed.length
                and fresh.extra.get("op_sig") == xed.extra.get("op_sig")
                and fresh.extra.get("iform") == xed.extra.get("iform"))
        if not same:
            out.update(result="unclassified", reasons=["XED evidence does not match the verified bytes"])
            return out
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
        if entry.get("width_flags"):
            widths = {name: votes[name].operand_bits for name in VOTERS}
            chosen = entry["width_flags"].get(str(widths["xed"]))
            agree = widths["xed"] == widths["zydis"] and widths["iced"] in (0, widths["xed"])
            if chosen is None or not agree:
                out.update(result="unclassified", entry=_entry_id(entry),
                           reasons=[f"width-dependent flags: widths {widths} do not select one listed width"])
                return out
            flags.update(chosen)
        out.update(result="derived_ordinary", entry=_entry_id(entry), **{"class": entry["class"]}, flags=flags)
    return out


def _entry_id(entry: dict) -> dict:
    return {name: entry[name] for name in ("iclass", "extension", "isa_set", "sig")}
