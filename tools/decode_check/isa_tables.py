"""TBR ISA facts step 2: the three versioned data files (design .census6/design_tbr_isa_facts_r3.md).

- ``isa_conditions_x64.json``: the ISA condition table (s1 layer 2), every entry citing its reference entry;
- ``iclass_map_x64.json``: per-voter mnemonic -> canonical key (s1: per-voter lookup);
- ``isa_splits_x64.json``: feature-dependent encodings with their deciding feature and fallback (s3 F4).

``load()`` validates them together and gives each a digest over canonical bytes (s5 header binding).
``lookup(vote, window)`` is one voter's lookup; ``None`` means the form is absent for that voter.
Nothing here decides a fact: the computation (step 3) combines the lookups of all voters.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

_HERE = Path(__file__).resolve().parent
FILES = {"conditions": "isa_conditions_x64.json", "map": "iclass_map_x64.json", "splits": "isa_splits_x64.json"}
SCHEMAS = {"conditions": "tbr-isa-conditions-1", "map": "tbr-iclass-map-1", "splits": "tbr-isa-splits-1"}
VOTERS = ("iced", "zydis", "xed")
LEGACY_PREFIXES = frozenset((0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65))
ENTRY_FIELDS = frozenset(("cite", "f2", "f2_meaning", "f3", "f4", "f5", "f6", "f7", "cet", "access_width",
                          "state_dependent", "data_faults", "split", "split_member", "note"))
WHEN_FIELDS = frozenset(("operand_bits", "flow", "target_kind", "opcode", "modrm_reg"))
CET_CONDITIONS = frozenset(("CET_SS", "CET_IBT"))


class TableError(ValueError):
    """The data files are malformed or inconsistent (the tables are then unusable as a whole)."""


def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class Tables:
    conditions: dict
    map: dict
    splits: dict
    digests: dict      # {"conditions" | "map" | "splits": sha256 of canonical bytes}

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


def validate(conditions: dict, mapping: dict, splits: dict) -> None:
    """Schema and cross-file consistency (design r3 s5: a malformed table is never partly used)."""
    for name, data in (("conditions", conditions), ("map", mapping), ("splits", splits)):
        _check(data.get("schema") == SCHEMAS[name], f"{name}: schema is not {SCHEMAS[name]}")
    vocabulary = set(conditions["conditions"])
    documents = set(conditions["documents"])
    tags = set(conditions["f3_tags"])
    sources = set(conditions["f6_sources"])
    meanings = conditions.get("f2_meanings", {})
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
        for name in entry.get("cet", []):
            _check(name in CET_CONDITIONS, f"conditions: {key} cet {name}")
        if "split" in entry:
            _check(entry["split"] in split_ids, f"conditions: {key} names unknown split {entry['split']}")
    for meaning, item in meanings.items():
        _check(bool(item.get("cite")) and bool(item.get("outputs")), f"conditions: f2 meaning {meaning}")
        for output in item["outputs"]:
            for name in output.get("loaded_when", []):
                _check(name in vocabulary, f"conditions: f2 meaning {meaning} uses unknown condition {name}")
    for index, rule in enumerate(mapping["rules"]):
        where = f"map: rule {index}"
        _check(set(rule) <= {"voters", "mnemonic", "when", "key"}, f"{where} has unknown fields")
        _check(set(rule.get("voters", VOTERS)) <= set(VOTERS), f"{where} names an unknown voter")
        _check(bool(rule.get("mnemonic")) and all(m == m.upper() for m in rule["mnemonic"]), f"{where} mnemonics")
        _check(set(rule.get("when", {})) <= WHEN_FIELDS, f"{where} has unknown when fields")
        keys = rule["mnemonic"] if rule["key"] == "=" else [rule["key"]]
        for key in keys:
            _check(key in entries, f"{where}: key {key} is not in the condition table")
    for split in splits["splits"]:
        for role in ("main", "fallback"):
            _check(split[role] in entries, f"splits: {split['id']} {role} {split[role]} is not in the condition table")
        _check(bool(split.get("feature")) and bool(split.get("cite")), f"splits: {split['id']} feature / cite")
    for item in splits["prefix_splits"] + splits["no_split"]:
        _check(bool(item.get("cite")) and bool(item.get("vector")), f"splits: {item['id']} cite / vector")


def load(root: Path | None = None) -> Tables:
    root = root or _HERE
    conditions, mapping, splits = (_load_json(name, root) for name in ("conditions", "map", "splits"))
    validate(conditions, mapping, splits)
    digests = {name: hashlib.sha256(canonical_bytes(data)).hexdigest()
               for name, data in (("conditions", conditions), ("map", mapping), ("splits", splits))}
    return Tables(conditions, mapping, splits, digests)


# -- one voter's lookup ----------------------------------------------------------------------------

def opcode_view(window: bytes) -> tuple:
    """(legacy prefixes, opcode bytes, ModRM or None) of a legacy / REX encoded instruction; VEX / EVEX / XOP
    encodings give empty opcode bytes (no map rule qualifies them by opcode)."""
    index, prefixes = 0, []
    while index < len(window) and window[index] in LEGACY_PREFIXES:
        prefixes.append(window[index])
        index += 1
    if index < len(window) and 0x40 <= window[index] <= 0x4F:
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
    _, opcode, modrm = view
    for name, wanted in when.items():
        if name == "operand_bits" and vote.operand_bits != wanted:
            return False
        if name == "flow" and vote.flow != wanted:
            return False
        if name == "target_kind" and vote.target_kind not in wanted:
            return False
        if name == "opcode" and not any(opcode.startswith(bytes.fromhex(item)) for item in wanted):
            return False
        if name == "modrm_reg" and (modrm is None or (modrm >> 3) & 7 not in wanted):
            return False
    return True


def lookup(tables: Tables, vote, window: bytes) -> str | None:
    """One voter's canonical key for its decode of `window` (an ok vote), or None when absent."""
    if vote.status != "ok":
        return None
    mnemonic = vote.mnemonic.upper()
    view = opcode_view(window)
    for rule in tables.map["rules"]:
        if vote.voter not in rule.get("voters", VOTERS) or mnemonic not in rule["mnemonic"]:
            continue
        if _when_holds(rule.get("when", {}), vote, view):
            return mnemonic if rule["key"] == "=" else rule["key"]
    return None
