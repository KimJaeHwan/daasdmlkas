"""G1 decode evidence for the engine: `g1-decode-evidence-1` (design .census6/design_g1_engine_evidence_r3.md,
closed: Astra final specification g1_evidence_astra4.md, Fable APPROVE g1_evidence_fable4.md) and
`g1-decode-evidence-2` = -1 plus the ISA facts (design .census6/design_tbr_isa_facts_r3.md s5; isa_facts.py).

Two halves, plain functions over plain data (Rust-port surface):
- the writer (``build``), used by ``decode_check.py --evidence-out``;
- a reference reader (``parse`` / ``accept`` / ``Evidence``) implementing the design's reading rules exactly
  (header checks, coverage, the six-step read, fact decision and premises). The engine reader is TDO work; this
  one is its executable specification and the tests' oracle.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re

import compare

SCHEMA = "g1-decode-evidence-1"
SCHEMA2 = "g1-decode-evidence-2"
SCHEMA3 = "g1-decode-evidence-3"            # (design_tbr_g1_x1 r1-r3: -2 + producer_override)
SCHEMA4 = "g1-decode-evidence-4"            # (design_tbr_g2_common_facts_r5 s8: -3 + common_facts verdicts)
OVERRIDE_STATUS = ("checked", "not_reported")   # or "failed:<reason>"
ISA_STATUS = ("checked", "not_run")         # or "failed:<reason>"
CONSUMERS_VERSION = "consumers-2"
# consumer -> row-selection rule -> attributes read (design s4); object keys sorted, array order as given
CONSUMERS_2 = {
    "call_seed": {"seed_op": ["a1", "a4", "a5", "a6", "a8"]},
    "plain_push": {"direct_call_op": ["a1", "a4", "a6", "a7"]},
    "push_projection": {"call_op": ["a1", "F.is_call", "a3", "a4", "a11b", "a7"]},
    "push_relation": {"call_op": ["a1", "F.is_call", "a3", "a4", "a11b", "a7"]},
    "resolved_transfer_site": {"branchind_op": ["a1", "a8", "a5"]},
    "return_shape": {"return_op": ["a1", "a11b"]},
    "s1": {"native_call": ["a1", "a2", "a3", "a4", "a6", "a8", "F.is_call"], "s1_exit_source": ["a1", "a4"]},
    "unknown_transfer_site": {"branchind_op": ["a1", "a8", "a5"]},
}
CONSUMERS_DIGEST = "5374e29006ccee4fd463f258e368e45c248cee659679e31c0ddc5e2c8cfe2d9e"   # (design s4, 500 bytes)
DISAGREEMENT_KINDS = ("withheld:decoder-disagreement", "withheld:amd-disagreement", "withheld:vendor",
                      "unrecognized:ghidra-decode-suspect", "unrecognized:cause-unknown",
                      "unrecognized:ghidra-analysis-override", "unrecognized:ghidra-internal-inconsistency")
TRUST_PREMISE = "g1-evidence-from-allowlisted-build"
DECODE_PREMISE = "TBR-G1-decode"
TABLE_DEPENDENT = tuple(compare.TABLE_DEPENDENT) + tuple("F." + bit for bit in compare.F_BITS)
HEX = re.compile(r"^(0|[1-9a-f][0-9a-f]*)$")
U64 = 1 << 64


def consumers_bytes(table: dict = CONSUMERS_2) -> bytes:
    return json.dumps(table, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def consumers_digest(table: dict = CONSUMERS_2) -> str:
    return hashlib.sha256(consumers_bytes(table)).hexdigest()


def render(space: int, offset: int) -> str:
    return f"{space:x}:{offset:x}"


def rows_digest(coordinates) -> str:
    """SHA-256 of the integer-sorted, unique ``space:offset`` lines, each followed by \\n (design s7)."""
    lines = "".join(render(space, offset) + "\n" for space, offset in sorted(set(coordinates)))
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def tool_digest(repo: Path) -> str:
    """SHA-256 over ``<relative path>\\0<sha256>\\n`` for the pinned file list, sorted by path (design s7)."""
    files = sorted(set(repo.glob("tools/decode_check/*.py")) | set(repo.glob("tools/decode_check/decoders/*.c"))
                   | set(repo.glob("tools/decode_check/decoders/*.h"))
                   | set(repo.glob("tools/decode_check/build_decoders.sh")) | set(repo.glob("tools/bundle_lint/*.py")))
    lines = []
    for path in sorted(files, key=lambda item: item.relative_to(repo).as_posix()):
        lines.append(f"{path.relative_to(repo).as_posix()}\0{hashlib.sha256(path.read_bytes()).hexdigest()}\n")
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


# -- writer ------------------------------------------------------------------------------------

def exception_of(states: dict) -> dict | None:
    """The exception attributes of one processed row from its ``dependents.attribute_states`` value (``+``
    confirmed names, ``~`` kinds): ``*`` alone for a never-compared row; else every compared attribute not
    confirmed, with ``state:kind`` -- a compared attribute without a state is written as unobserved (producer
    completeness, design s3). None when every compared attribute is confirmed."""
    if "*" in states:
        return {"*": "unobserved"}
    kinds = states.get("~", {})
    confirmed = states.get("+", frozenset())
    out = {}
    for name in compare.COMPARED:
        if name in confirmed:
            continue
        state = states.get(name, "unobserved")
        out[name] = f"{state}:{kinds[name]}" if name in kinds and state != "unobserved" else state
    return out or None


def build(*, bundle: dict, producer: dict, mapping: dict, premises: list, table_applied: bool,
          global_reason, functions: list, isa: dict | None = None, override: dict | None = None,
          common: dict | None = None) -> dict:
    """The evidence document. ``functions``: [{"function_id", "observation_sha256", "rows": [(space, offset)],
    "states": {(space, offset): attribute_states}}] -- every processed row of the function.

    ``isa`` (schema -2): {"header": isa_facts.header_block(...), "functions": {function_id: {"status": {kind:
    "checked" | "not_run" | "failed:<r>"}, "rows": {(space, offset): isa_facts.row_facts(...)}}}}; only rows with
    something to say are written (isa_facts.listed), sorted by (space, offset)."""
    body = []
    if global_reason is None:
        for function in sorted(functions, key=lambda item: item["function_id"]):
            rows = sorted(set(function["rows"]))
            exceptions = []
            for space, offset in rows:
                attributes = exception_of(function["states"].get((space, offset), {"*": "unobserved"}))
                if attributes is not None:
                    exceptions.append({"space": space, "offset": f"{offset:x}", "attributes": attributes})
            item = {"function_id": function["function_id"], "observation_sha256": function["observation_sha256"],
                    "rows_total": len(rows), "rows_digest": rows_digest(rows), "exceptions": exceptions}
            if isa is not None:
                import isa_facts

                mine = isa["functions"].get(function["function_id"], {})
                status = mine.get("status") or {kind: "not_run" for kind in isa_facts.KINDS}
                listed = [isa_facts.canonical_row(space, offset, row)
                          for (space, offset), row in sorted(mine.get("rows", {}).items()) if isa_facts.listed(row)]
                item["isa_facts"] = {"status": dict(sorted(status.items())), "rows": listed}
            if override is not None:
                item["producer_override"] = _override_section(override["functions"].get(function["function_id"]),
                                                             rows, function["states"])
            body.append(item)
    schema = SCHEMA if isa is None else SCHEMA2 if override is None else SCHEMA3 if common is None else SCHEMA4
    document = {"schema": schema, "bundle": bundle, "producer": producer,
                "mapping": mapping, "premises": sorted(premises), "translation": {"table_applied": table_applied},
                "compared_attributes": list(compare.COMPARED), "mode_constant": list(compare.MODE_CONSTANT),
                "consumers": {"version": CONSUMERS_VERSION, "digest": consumers_digest()},
                "global_reason": global_reason, "functions": body}
    if isa is not None:
        document["isa_facts"] = isa["header"]
    if override is not None:
        document["producer_override"] = override["header"]
    if common is not None:
        document["common_facts"] = common
    return document


def _override_section(entry, rows, states) -> dict:
    """``{status, codes, details}``: one code per compared row in (space, offset) order, a detail per C / U / O row
    and per star row (design_tbr_g1_x1 r2 s5, r3 s5)."""
    if entry is None or entry["status"] != "checked":     # (a function without verdicts: never not_reported)
        return {"status": "failed:no-verdicts" if entry is None else entry["status"], "codes": "", "details": []}
    compared = [where for where in rows if "*" not in states.get(where, {"*": "unobserved"})]
    codes = "".join(entry["codes"][where] for where in compared)
    details = []
    for (space, offset), detail in sorted(entry["details"].items()):
        details.append({"space": space, "offset": f"{offset:x}", **detail})
    return {"status": "checked", "codes": codes, "details": details}


def dumps(document: dict) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def allowlist_entry(document: dict) -> dict:
    """The allowlist entry an engine would pin for the build that wrote ``document`` (design s2): the producer
    tuple without the recorded-only fields, with the exact compared / mode-constant sets."""
    producer = {k: v for k, v in document["producer"].items() if k not in ("diagnosis_engine", "naming_source_sha256")}
    entry = {"producer": producer, "compared_attributes": list(document["compared_attributes"]),
             "mode_constant": list(document["mode_constant"])}
    if "isa_facts" in document:      # (schema -2: the fact schema, capability, table digests and profiles too)
        entry["isa_facts"] = document["isa_facts"]
    if "producer_override" in document:   # (schema -3: the fixed spec and the imported engine, not the profile)
        entry["producer_override"] = {k: v for k, v in document["producer_override"].items() if k != "profile"}
    return entry


# -- reference reader --------------------------------------------------------------------------

class Rejected(Exception):
    """The whole file is rejected (the run continues as without it, reason recorded)."""


def _pairs(items):
    seen = {}
    for key, value in items:
        if key in seen:
            raise Rejected(f"duplicate JSON key {key!r}")
        seen[key] = value
    return seen


def _constant(name):
    raise Rejected(f"non-finite number {name}")


def parse(raw: bytes) -> dict:
    """Strict JSON (design s7): UTF-8, duplicate keys and NaN / Infinity rejected."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Rejected(f"not UTF-8: {error}") from None
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except ValueError as error:
        raise Rejected(f"not JSON: {error}") from None


def _keys(value, expected, where):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise Rejected(f"{where}: keys {sorted(value) if isinstance(value, dict) else type(value).__name__} "
                       f"!= {sorted(expected)}")


def _u64(value, where, limit=U64):
    if type(value) is not int or not 0 <= value < limit:
        raise Rejected(f"{where}: not an unsigned integer below {limit}")


def _offset(value, where):
    if not isinstance(value, str) or not HEX.match(value) or int(value, 16) >= U64:
        raise Rejected(f"{where}: offset must be a lower-case hex string below 2^64")
    return int(value, 16)


class Evidence:
    """An accepted file against one admitted Bundle view (the engine's own facts):
    ``bundle = {"generation_id", "manifest_sha256", "original_sha256",
                "functions": {function_id: {"observation_sha256", "rows": set((space, offset)), "kept": bool}}}``."""

    def __init__(self, document: dict, bundle: dict, tables=None) -> None:
        if tables is None and document.get("isa_facts") is not None:
            import isa_tables

            tables = isa_tables.load()          # (r2 Astra P2-1: the pinned tables by default)
        self.document, self.bundle, self.tables = document, bundle, tables
        self.global_reason = document["global_reason"]
        self.premises = set(document["premises"]) | {TRUST_PREMISE}
        self.table_applied = document["translation"]["table_applied"]
        self.compared = set(document["compared_attributes"])
        self.mode_constant = set(document["mode_constant"])
        self.entries = {entry["function_id"]: entry for entry in document["functions"]}
        self.exceptions = {}
        for entry in document["functions"]:
            for item in entry["exceptions"]:
                self.exceptions[(entry["function_id"], item["space"], int(item["offset"], 16))] = item["attributes"]
        self.status = {fid: self._coverage(fid) for fid in bundle["functions"]}
        self.isa_header = document.get("isa_facts")
        self.override_header = document.get("producer_override")
        self.override_sections = {entry["function_id"]: entry["producer_override"] for entry in document["functions"]
                                  if "producer_override" in entry}
        self._override_cache = {}
        self.isa_status, self.isa_rows = {}, {}
        for entry in document["functions"]:
            if "isa_facts" in entry:
                self.isa_status[entry["function_id"]] = entry["isa_facts"]["status"]
                for row in entry["isa_facts"]["rows"]:
                    self.isa_rows[(entry["function_id"], row["space"], int(row["offset"], 16))] = row

    def _coverage(self, fid):
        info = self.bundle["functions"][fid]
        if self.global_reason is not None:
            return "global"
        if not info.get("kept", True):
            return "ignored_duplicate_entry"
        entry = self.entries.get(fid)
        if entry is None:
            return "absent"
        if entry["observation_sha256"] != info["observation_sha256"]:
            return "observation_mismatch"
        if entry["rows_total"] != len(info["rows"]):
            return "rows_total_mismatch"
        if entry["rows_digest"] != rows_digest(info["rows"]):
            return "rows_digest_mismatch"
        return "covered"

    def coverage(self) -> dict:
        """covered / total and the not-covered counts by reason (design s6)."""
        counts = {}
        for status in self.status.values():
            counts[status] = counts.get(status, 0) + 1
        return {"covered": counts.get("covered", 0), "total": len(self.status),
                "not_covered": {k: v for k, v in counts.items() if k != "covered"},
                "global_reason": self.global_reason}

    def read(self, fid: str, space: int, offset: int, attribute: str) -> str:
        """The six-step read (design s5): ``confirmed``, ``unobserved`` or a disagreement ``state:kind``."""
        if self.status.get(fid) != "covered":                                         # 1
            return "unobserved"
        if (space, offset) not in self.bundle["functions"][fid]["rows"]:              # 2
            return "unobserved"
        exception = self.exceptions.get((fid, space, offset))
        if exception is not None and "*" in exception:                                # 3
            return "unobserved"
        if exception is not None and attribute in exception:                          # 4
            return exception[attribute]
        if (not self.table_applied and attribute in TABLE_DEPENDENT) or attribute not in self.compared \
                or attribute in self.mode_constant:                                   # 5
            return "unobserved"
        return "confirmed"                                                            # 6


    def isa(self, fid: str, space: int, offset: int, kind: str, premises: set) -> dict:
        """One ISA fact kind of one row (design r3 s2 / s4, 2b r1 s8): ``{"state": "fact", "value", "basis"}``,
        ``{"state": "negative", "basis", "premises"}`` (no listed condition, usable only because the named
        premises are held) or ``{"state": "unobserved", "reason"}``."""
        import isa_facts

        if self.isa_header is None:
            return {"state": "unobserved", "reason": "no ISA facts in this file (schema -1)"}
        # (review r1 P1: the basis key is resolved from the reader's pinned tables, which must be the file's)
        if self.tables is None or dict(self.tables.digests) != self.isa_header["tables"]:
            return {"state": "unobserved", "reason": "the reader's tables are not the file's (digest mismatch)"}
        if self._never_compared(fid, space, offset):
            return {"state": "unobserved", "reason": "row not covered or never compared"}
        status = self.isa_status.get(fid, {}).get(kind)
        if status != "checked":
            return {"state": "unobserved", "reason": f"status {status}"}
        row = self.isa_rows.get((fid, space, offset))
        basis = row["basis"] if row else self.isa_header["omitted_row_basis"]
        facts = copy.deepcopy(row["facts"]) if row else {}
        # (r2 Astra P1-3: the split the row identified and its class flags join the basis's table facts)
        table, out_of_scope, unverified = isa_facts.row_table_facts(self.tables, basis, facts)
        if row and kind in row["unobserved"]:
            return {"state": "unobserved", "reason": row["unobserved"][kind], "value": facts.get(kind),
                    "basis": basis}
        row_value = facts.get(kind)
        flags = {"class_flags": facts["class_flags"]} if facts.get("class_flags") else {}
        if row_value or table.get(kind):
            return {"state": "fact", "basis": basis, "row": row_value, "table": table.get(kind),
                    "out_of_scope": out_of_scope, **flags}
        if kind in unverified:
            return {"state": "unobserved", "reason": unverified[kind], "basis": basis}
        if kind in isa_facts.TABLE_KINDS and basis in isa_facts.FIXED_BASES:    # (r3 Astra P1-1: F5 too)
            return {"state": "unobserved", "reason": f"basis {basis}"}
        names = isa_facts.premise_names(self.isa_header)
        needed = {names["detection"][kind]}
        if kind in isa_facts.TABLE_KINDS and basis.startswith("ordinary:"):
            needed.add(names["ordinary"])
        if needed <= set(premises):
            return {"state": "negative", "basis": basis, "premises": sorted(needed), "out_of_scope": out_of_scope}
        return {"state": "unobserved", "reason": "missing premises " + ", ".join(sorted(needed - set(premises)))}

    def override(self, fid: str, space: int, offset: int) -> dict:
        """The producer-override verdict of one row (design_tbr_g1_x1 r1-r3): ``{"verdict": "effect_attested",
        "exemption", "premises"}`` / ``override_present`` (kinds, effect) / ``contradicted`` / ``unobserved`` /
        ``not_reported``. effect_attested is an effect attestation only, never the report's completeness. A verdict
        that used a pin (S / I, or ``exempt`` on C / U / O) returns the exemption and the OS-contract premise."""
        import producer_override as po

        if self.override_header is None:
            return {"verdict": "unobserved", "reason": "no override section (schema -1 / -2)"}
        section = self.override_sections.get(fid)
        if section is None or self.status.get(fid) != "covered":
            return {"verdict": "unobserved", "reason": "function not covered"}
        if section["status"] == "not_reported":
            return {"verdict": "not_reported", "reason": "the Bundle declares no producer profile"}
        if section["status"] != "checked":
            return {"verdict": "unobserved", "reason": f"status {section['status']}"}
        index = self._override_index(fid)
        where = (space, offset)
        if where not in index["rows"]:
            return {"verdict": "unobserved", "reason": "not a row of the function"}
        item = index["details"].get(where)
        if self._never_compared(fid, space, offset):
            if item is not None and item.get("star"):
                return {"verdict": "override_present", "kinds": list(item["kinds"]), "effect": dict(item["effect"])}
            return {"verdict": "unobserved", "reason": "row never compared"}
        code = index["codes"][where]
        base = sorted({"decoder-matches-cpu", "stock-ghidra-translator", TRUST_PREMISE})
        if code in po.DETAIL_CODES:
            out = {"verdict": po.CODES[code], **{k: v for k, v in item.items() if k not in ("space", "offset", "exempt")}}
            if "exempt" in item:
                out["exemption"] = po.EXEMPTIONS[item["exempt"]]
                out["premises"] = sorted(set(base) | {po.EXEMPTIONS[item["exempt"]]["premise"]})
            return out
        # (r3 s5: before A / S / I, the required list must be inside the compared attributes, the spec the fixed
        #  one, the translation table applied, the file's profile set)
        if not set(po.REQUIRED) - {"T"} <= self.compared \
                or self.override_header["spec"] != json.loads(json.dumps(po.SPEC)) or not self.table_applied \
                or self.override_header["profile"] is None:
            return {"verdict": "unobserved", "reason": "the required comparisons did not all run"}
        premises = sorted(set(base) | ({po.EXEMPTIONS[code]["premise"]} if code in po.EXEMPTIONS else set()))
        return {"verdict": "effect_attested", "exemption": po.EXEMPTIONS.get(code), "premises": premises}

    def _override_index(self, fid: str) -> dict:
        """(impl r1 P2-5) coordinate -> code / detail, built once per function."""
        cached = self._override_cache.get(fid)
        if cached is None:
            section = self.override_sections[fid]
            rows = sorted(self.bundle["functions"][fid]["rows"])
            compared = [where for where in rows if not self._never_compared(fid, *where)]
            cached = {"rows": set(rows), "codes": dict(zip(compared, section["codes"])),
                      "details": {(item["space"], int(item["offset"], 16)): item for item in section["details"]}}
            self._override_cache[fid] = cached
        return cached

    def _never_compared(self, fid, space, offset) -> bool:
        if self.status.get(fid) != "covered" or (space, offset) not in self.bundle["functions"][fid]["rows"]:
            return True
        exception = self.exceptions.get((fid, space, offset))
        return exception is not None and "*" in exception


def decide(reads: list, level: str, evidence_premises: set) -> dict:
    """A fact's decision from its reads' results (design s5): keep / withhold, and the decode premises."""
    disagreements = [item for item in reads if item in DISAGREEMENT_KINDS]
    unobserved = [item for item in reads if item == "unobserved"]
    confirmed = [item for item in reads if item == "confirmed"]
    if disagreements:
        return {"keep": False, "premises": set(), "cause": "disagreement"}
    if unobserved and level == "B":
        return {"keep": False, "premises": set(), "cause": "unobserved"}
    if not reads or not confirmed:
        return {"keep": True, "premises": {DECODE_PREMISE}, "confirmed_by_g1": False}
    if unobserved:
        return {"keep": True, "premises": set(evidence_premises) | {DECODE_PREMISE}, "confirmed_by_g1": False}
    return {"keep": True, "premises": set(evidence_premises), "confirmed_by_g1": True}


HEADER_KEYS = ("schema", "bundle", "producer", "mapping", "premises", "translation", "compared_attributes",
               "mode_constant", "consumers", "global_reason", "functions")
PRODUCER_KEYS = ("decode_check_revision", "tool_digest", "decoders", "voters", "rules", "lift_table",
                 "diagnosis_engine", "naming_source_sha256")


def accept(document: dict, bundle: dict, allowlist: list, *, consumers_version: str = CONSUMERS_VERSION,
           digest: str = CONSUMERS_DIGEST, tables=None) -> Evidence:
    """Every header, body and coverage-precondition check of design s2 / s3 / s5 / s7; raises Rejected."""
    schema = document.get("schema") if isinstance(document, dict) else None
    pinned = None
    if schema in (SCHEMA2, SCHEMA3, SCHEMA4):
        _keys(document, HEADER_KEYS + ("isa_facts",) + (("producer_override",) if schema in (SCHEMA3, SCHEMA4) else ())
              + (("common_facts",) if schema == SCHEMA4 else ()), "header")
        _check_isa_header(document["isa_facts"])                 # (r2 Fable P2-1: the header before the rows)
        if tables is None:
            import isa_tables

            tables = isa_tables.load()                           # (r2 Astra P2-1: the pinned tables by default)
        # basis keys are checked only against the file's own tables; other tables make every isa() unobserved
        pinned = tables if dict(tables.digests) == document["isa_facts"]["tables"] else None
    else:
        _keys(document, HEADER_KEYS, "header")
        if schema != SCHEMA:
            raise Rejected(f"schema {schema!r}")
    if schema == SCHEMA4:
        _check_common_facts(document["common_facts"])
    if schema in (SCHEMA3, SCHEMA4):
        _check_override_header(document["producer_override"])
        # (impl r2 Astra P1-2: the Bundle's profile is checked once, also for a file with no functions)
        if not isinstance(bundle, dict) or "producer_profile" not in bundle:
            raise Rejected("-3 needs the Bundle view's producer_profile")
        if document["producer_override"]["profile"] != bundle["producer_profile"]:
            raise Rejected("producer_override profile differs from the Bundle's")
    _keys(document["bundle"], ("generation_id", "manifest_sha256", "original_sha256"), "bundle")
    for name in ("generation_id", "manifest_sha256", "original_sha256"):
        if document["bundle"][name] != bundle[name]:
            raise Rejected(f"bundle.{name} does not match the admitted Bundle")
    _keys(document["producer"], PRODUCER_KEYS, "producer")
    _keys(document["mapping"], ("format", "mapping_id"), "mapping")
    entry = allowlist_entry(document)
    if entry not in allowlist:
        raise Rejected("producer / compared_attributes / mode_constant not in the allowlist")
    _keys(document["translation"], ("table_applied",), "translation")
    table_applied = document["translation"]["table_applied"]
    if type(table_applied) is not bool:
        raise Rejected("translation.table_applied is not a boolean")
    premises = document["premises"]
    if not isinstance(premises, list) or not all(isinstance(item, str) for item in premises) \
            or len(set(premises)) != len(premises):
        raise Rejected("premises must be a list of distinct strings")
    if "decoder-matches-cpu" not in premises:
        raise Rejected("required premise decoder-matches-cpu missing")
    if table_applied and "stock-ghidra-translator" not in premises:
        raise Rejected("table_applied requires the premise stock-ghidra-translator")
    _keys(document["consumers"], ("version", "digest"), "consumers")
    if document["consumers"]["version"] != consumers_version or document["consumers"]["digest"] != digest:
        raise Rejected("consumers version / digest differ from the engine's table")
    global_reason = document["global_reason"]
    if global_reason is not None and not isinstance(global_reason, str):
        raise Rejected("global_reason must be null or a string")
    functions = document["functions"]
    if not isinstance(functions, list):
        raise Rejected("functions is not a list")
    if global_reason is not None and functions:
        raise Rejected("global_reason with row evidence")
    compared = set(document["compared_attributes"])
    ids = [item.get("function_id") if isinstance(item, dict) else None for item in functions]
    if len(set(ids)) != len(ids):
        raise Rejected("duplicate function_id")
    if ids != sorted(ids):
        raise Rejected("functions not sorted by function_id")
    for item in functions:
        _keys(item, ("function_id", "observation_sha256", "rows_total", "rows_digest", "exceptions")
              + (("isa_facts",) if schema in (SCHEMA2, SCHEMA3, SCHEMA4) else ())
              + (("producer_override",) if schema in (SCHEMA3, SCHEMA4) else ()), "function")
        fid = item["function_id"]
        if fid not in bundle["functions"]:
            raise Rejected(f"function {fid} is not in the Bundle")
        _u64(item["rows_total"], f"{fid}.rows_total")
        coordinates = []
        for exception in item["exceptions"]:
            keys = set(exception)
            if not {"space", "offset", "attributes"} <= keys <= {"space", "offset", "attributes", "reason"}:
                raise Rejected(f"{fid}: exception keys {sorted(keys)}")
            _u64(exception["space"], f"{fid}.space", 1 << 32)
            offset = _offset(exception["offset"], fid)
            if "reason" in exception and not isinstance(exception["reason"], str):
                raise Rejected(f"{fid}: reason must be a string")
            attributes = exception["attributes"]
            if not isinstance(attributes, dict) or not attributes:
                raise Rejected(f"{fid}: empty exception")
            if "*" in attributes and (len(attributes) != 1 or attributes["*"] != "unobserved"):
                raise Rejected(f"{fid}: '*' must stand alone as unobserved")
            for name, state in attributes.items():
                if name != "*" and name not in compared:
                    raise Rejected(f"{fid}: unknown attribute {name!r}")
                if state != "unobserved" and state not in DISAGREEMENT_KINDS:
                    raise Rejected(f"{fid}: unknown state / kind {state!r}")
            coordinates.append((exception["space"], offset))
        if len(set(coordinates)) != len(coordinates):
            raise Rejected(f"{fid}: duplicate exception coordinate")
        if coordinates != sorted(coordinates):
            raise Rejected(f"{fid}: exceptions not sorted by (space, offset)")
        rows = bundle["functions"][fid]["rows"]
        outside = [render(*c) for c in coordinates if c not in rows]
        if outside:
            raise Rejected(f"{fid}: exception coordinates outside the function's rows: {outside[:3]}")
        if schema in (SCHEMA2, SCHEMA3, SCHEMA4):
            never = {c for c, e in zip(coordinates, item["exceptions"]) if "*" in e["attributes"]}
            _check_isa(item["isa_facts"], fid, rows, never, pinned)
        if schema in (SCHEMA3, SCHEMA4):
            exceptions = {coordinate: exception["attributes"]
                          for coordinate, exception in zip(coordinates, item["exceptions"])}
            _check_override(item["producer_override"], fid, rows, never, bundle["functions"][fid], exceptions,
                            bundle["producer_profile"])
    return Evidence(document, bundle, tables)


def _check_common_facts(block) -> None:
    """G2 r5 s8: the -4 section's shape; binding to a facts file is checked by ``bind_common_facts``."""
    import common_facts as cf

    _keys(block, ("schema", "rule_version", "facts_sha256", "row_set_sha256", "fields", "rows"), "common_facts")
    if block["schema"] != cf.VERDICT_SCHEMA or block["rule_version"] != cf.RULE_VERSION \
            or block["fields"] != list(cf.FIELDS):
        raise Rejected("common_facts schema / rule / fields differ from the reader's")
    if not isinstance(block["rows"], list):
        raise Rejected("common_facts rows is not a list")
    seen = []
    for row in block["rows"]:
        if not isinstance(row, dict) or set(row) != {"id", "observation", "codes"} \
                or not isinstance(row["codes"], str) or len(row["codes"]) != len(cf.FIELDS) \
                or set(row["codes"]) - set("cxun"):
            raise Rejected("common_facts row shape")
        seen.append((row["id"], row["observation"]))
    if seen != sorted(set(seen)):
        raise Rejected("common_facts rows duplicated or not sorted")


def bind_common_facts(document: dict, facts_document: dict) -> dict:
    """The -4 verdicts bound to a facts file (s8 binding): facts digest, row-set digest and the row set itself must
    match, else Rejected. Returns {(id, observation): {field: state}}."""
    import common_facts as cf

    block = document["common_facts"]
    if block["facts_sha256"] != cf.digest(facts_document):
        raise Rejected("common_facts bound to another facts file")
    if block["row_set_sha256"] != cf.row_set_digest(facts_document["rows"]):
        raise Rejected("common_facts row set differs from the facts file")
    rows = {(row["id"], row["observation"]) for row in facts_document["rows"]}
    if {(row["id"], row["observation"]) for row in block["rows"]} != rows:
        raise Rejected("common_facts rows differ from the facts file")
    names = {"c": "confirmed", "x": "contradicted", "u": "unobserved", "n": "not_applicable"}
    return {(row["id"], row["observation"]): {field: names[code] for field, code in zip(cf.FIELDS, row["codes"])}
            for row in block["rows"]}


def _check_override_header(block) -> None:
    import producer_override as po

    _keys(block, ("schema", "profile", "spec", "omitted", "engine_source"), "producer_override")
    if block["schema"] != po.SCHEMA or block["spec"] != json.loads(json.dumps(po.SPEC)):
        raise Rejected("producer_override schema / spec differ from the reader's")
    if block["profile"] is not None and block["profile"] != po.PROFILE_X1:
        raise Rejected("producer_override profile unknown")
    _keys(block["engine_source"], ("package", "digest", "revision", "dirty"), "producer_override.engine_source")


def _check_override(section, fid, rows, never, view, exceptions, profile) -> None:
    """r2 s5 / r3 s5, impl r1 Astra P1-1: codes cover exactly the compared rows; one detail per C / U / O code and
    per star row; fields as the code says; and against the Bundle's own view (mandatory for -3): the status matches
    the view's profile, ``O`` <=> a reported override on compared rows, star details <=> a reported override on
    never-compared rows, and an A / S / I row has no G1 exception beyond the attributes its pin allows."""
    import producer_override as po

    _keys(section, ("status", "codes", "details"), f"{fid}.producer_override")
    status, codes, details = section["status"], section["codes"], section["details"]
    if status not in OVERRIDE_STATUS and not (isinstance(status, str) and status.startswith("failed:")):
        raise Rejected(f"{fid}: producer_override status {status!r}")
    if not isinstance(codes, str) or not isinstance(details, list):
        raise Rejected(f"{fid}: producer_override codes / details types")
    if "override_report" not in view:
        raise Rejected(f"{fid}: -3 needs the Bundle view's per-row override reports")
    reports = view["override_report"]
    if status == "not_reported" and (profile is not None or reports is not None):
        raise Rejected(f"{fid}: not_reported on a Bundle that declares a producer profile")
    if status != "checked":
        if codes or details:
            raise Rejected(f"{fid}: producer_override codes / details without status checked")
        return
    # (impl r2 Astra P1-1 / P1-2) per row, from the Bundle alone: {"present": the reported override (a real bool),
    # "pin": producer_override.shape_code -- "S" / "I" / None from the original bytes, p-code and length}
    if profile is None or not isinstance(reports, dict) or set(reports) != set(rows) or not all(
            isinstance(report, dict) and set(report) == {"present", "pin"} and type(report["present"]) is bool
            and report["pin"] in (None, "S", "I") for report in reports.values()):
        raise Rejected(f"{fid}: status checked without the Bundle's profile and a {{present, pin}} report per row")
    compared = [where for where in sorted(rows) if where not in never]
    if len(codes) != len(compared) or set(codes) - set(po.CODES):
        raise Rejected(f"{fid}: producer_override codes do not cover the compared rows")
    position = dict(zip(compared, codes))
    seen = []
    star = set()
    for item in details:
        if not isinstance(item, dict) or "space" not in item or "offset" not in item:
            raise Rejected(f"{fid}: producer_override detail shape")
        _u64(item["space"], f"{fid}.override space", 1 << 32)
        where = (item["space"], _offset(item["offset"], fid))
        if where not in rows:
            raise Rejected(f"{fid}: producer_override detail outside the function's rows")
        seen.append(where)
        fields = set(item) - {"space", "offset"}
        if item.get("star"):
            if where not in never or fields != {"star", "kinds", "effect"} or item["star"] is not True \
                    or item["effect"] != {"unobserved": ["*"]} or not _strings(item["kinds"], nonempty=True):
                raise Rejected(f"{fid}: producer_override star detail")
            star.add(where)
            continue
        if where in never:
            raise Rejected(f"{fid}: producer_override detail at a never-compared row without star")
        code = position[where]
        if code not in po.DETAIL_CODES:
            raise Rejected(f"{fid}: producer_override detail on code {code}")
        if "exempt" in item:
            if not isinstance(item["exempt"], str) or item["exempt"] not in po.EXEMPTIONS:
                raise Rejected(f"{fid}: producer_override exempt {item['exempt']!r}")
            fields = fields - {"exempt"}
        if code == "C" and (fields != {"disagree"} or not _strings(item["disagree"], nonempty=True, within=po.REQUIRED)):
            raise Rejected(f"{fid}: producer_override C detail")
        if code == "U" and (fields != {"unobserved"}
                            or not _strings(item["unobserved"], nonempty=True, within=po.REQUIRED)):
            raise Rejected(f"{fid}: producer_override U detail")
        if code == "O":
            effect = item.get("effect")
            if fields != {"kinds", "effect"} or not _strings(item["kinds"], nonempty=True) \
                    or not isinstance(effect, dict) or set(effect) != {"disagree", "unobserved"} \
                    or not _strings(effect["disagree"], within=po.REQUIRED) \
                    or not _strings(effect["unobserved"], within=po.REQUIRED):
                raise Rejected(f"{fid}: producer_override O detail")
    if seen != sorted(set(seen)):
        raise Rejected(f"{fid}: producer_override details duplicated or not sorted")
    needing = {where for where, code in position.items() if code in po.DETAIL_CODES}
    if needing != set(seen) - star:
        raise Rejected(f"{fid}: producer_override details do not match the C / U / O codes")
    details_at = {(item["space"], int(item["offset"], 16)): item for item in details}
    for where, code in position.items():
        if (code == "O") != reports[where]["present"]:
            raise Rejected(f"{fid}: producer_override code {code} at {render(*where)} contradicts the Bundle's report")
        # (impl r2 Astra P1-1) S / I and a C / U / O `exempt` exactly where the Bundle-side shape is, and nowhere else
        pin = code if code in po.EXEMPTIONS else details_at.get(where, {}).get("exempt")
        if pin != reports[where]["pin"]:
            raise Rejected(f"{fid}: producer_override pin {pin!r} at {render(*where)} differs from the Bundle's shape "
                           f"{reports[where]['pin']!r}")
        exception = exceptions.get(where)
        if code == "A" and exception is not None:
            raise Rejected(f"{fid}: effect_attested at {render(*where)} with a G1 exception")
        if code in po.EXEMPTIONS and exception is not None and (
                not set(exception) <= set(po.EXEMPTIONS[code]["core_unobserved"])
                or any(state != "unobserved" for state in exception.values())):
            raise Rejected(f"{fid}: {code} at {render(*where)} with a G1 exception its pin does not allow")
    if {where for where in never if reports[where]["present"]} != star:
        raise Rejected(f"{fid}: producer_override star details do not match the Bundle's reported overrides")


def _strings(value, nonempty=False, within=None) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value) and (bool(value) or not nonempty) \
        and (within is None or set(value) <= set(within))


def _check_isa_header(block) -> None:
    import isa_facts

    _keys(block, ("schema", "kinds", "omitted_row_basis", "capability", "tables", "profiles"), "isa_facts")
    if block["schema"] != isa_facts.FACT_SCHEMA or block["kinds"] != list(isa_facts.KINDS):
        raise Rejected("isa_facts schema / kinds differ from the reader's")
    if block["omitted_row_basis"] != isa_facts.OMITTED_BASIS:
        raise Rejected("isa_facts omitted_row_basis differs from the reader's")
    _keys(block["tables"], ("conditions", "map", "splits", "ordinary"), "isa_facts.tables")


FLAG_TYPES = {"mxcsr_inputs": list, "simd_fp_exceptions": bool, "writes_mxcsr_status": bool,
              "explicit_mmx_operand": bool, "alignment": bool, "masked_write": bool}


def _check_row_shapes(row, fid, tables) -> None:
    """r3 Astra P2-3: what the reader dereferences is checked at acceptance -- every fact is an object, every
    unobserved reason a string, the F4 split and the class flags well formed, a split-table id in the pinned
    tables (when the digests match)."""
    import isa_facts

    if not all(isinstance(value, dict) for value in row["facts"].values()) \
            or not all(isinstance(reason, str) for reason in row["unobserved"].values()):
        raise Rejected(f"{fid}: isa_facts fact values must be objects, reasons strings")
    split = row["facts"].get("F4", {}).get("split")
    if split is not None:
        if not isinstance(split, dict) or not isinstance(split.get("source"), str):
            raise Rejected(f"{fid}: isa_facts F4 split must be an object with a source")
        if split["source"] == "split_table":
            if not isinstance(split.get("split"), str):
                raise Rejected(f"{fid}: isa_facts F4 split_table needs a split id")
            if tables is not None and not isa_facts.basis_known(tables, "split:" + split["split"]):
                raise Rejected(f"{fid}: isa_facts F4 split {split['split']!r} is not in the pinned tables")
    flags = row["facts"].get("class_flags")
    if flags is not None:
        if not set(flags) <= set(FLAG_TYPES) or not all(isinstance(flags[name], FLAG_TYPES[name]) for name in flags):
            raise Rejected(f"{fid}: isa_facts class_flags fields")
        if not all(isinstance(item, str) for item in flags.get("mxcsr_inputs", [])):
            raise Rejected(f"{fid}: isa_facts class_flags mxcsr_inputs")


def _check_keys(row, fid, tables) -> None:
    """r2 Astra P2-1: partial / disagree rows name each voter's entry (or null) as classify found them."""
    keys = row.get("keys")
    voters = ("iced", "zydis", "xed")
    if not isinstance(keys, dict) or set(keys) != set(voters) \
            or not all(value is None or isinstance(value, str) for value in keys.values()):
        raise Rejected(f"{fid}: isa_facts keys must map iced / zydis / xed to an entry key or null")
    found = [value for value in keys.values() if value is not None]
    if row["basis"] == "partial" and not 0 < len(found) < len(voters):
        raise Rejected(f"{fid}: isa_facts partial keys need some but not all voters")
    if row["basis"] == "disagree" and (len(found) != len(voters) or len(set(found)) < 2):
        raise Rejected(f"{fid}: isa_facts disagree keys need every voter and two entries")
    if tables is not None and any(tables.entry(value) is None for value in found):
        raise Rejected(f"{fid}: isa_facts keys name an entry outside the pinned tables")


def _check_isa(section, fid, rows, never, tables=None) -> None:
    """Design r3 s5: the section is mandatory; a coordinate outside the rows, a duplicate, a fact on a never-compared
    (*) row, an unknown kind or status rejects the file."""
    import isa_facts

    _keys(section, ("status", "rows"), f"{fid}.isa_facts")
    if set(section["status"]) != set(isa_facts.KINDS):
        raise Rejected(f"{fid}: isa_facts status must name every kind")
    for kind, state in section["status"].items():
        if state not in ISA_STATUS and not (isinstance(state, str) and state.startswith("failed:")):
            raise Rejected(f"{fid}: isa_facts status {kind}={state!r}")
    if not isinstance(section["rows"], list):
        raise Rejected(f"{fid}: isa_facts rows is not a list")
    coordinates = []
    for row in section["rows"]:
        if not isinstance(row, dict) or not {"space", "offset", "basis", "facts", "unobserved"} <= set(row) \
                <= {"space", "offset", "basis", "facts", "unobserved", "keys"}:
            raise Rejected(f"{fid}: isa_facts row keys")
        _u64(row["space"], f"{fid}.isa space", 1 << 32)
        where = (row["space"], _offset(row["offset"], fid))
        if where not in rows:
            raise Rejected(f"{fid}: isa_facts row {render(*where)} outside the function's rows")
        if where in never:                     # (r2 Astra P2-1: a listed basis alone would carry table facts)
            raise Rejected(f"{fid}: isa_facts on a never-compared row {render(*where)}")
        if not isinstance(row["basis"], str) or not isinstance(row["facts"], dict) \
                or not isinstance(row["unobserved"], dict):
            raise Rejected(f"{fid}: isa_facts row types")
        if row["basis"] not in isa_facts.FIXED_BASES and not row["basis"].startswith(("cited:", "split:", "ordinary:")):
            raise Rejected(f"{fid}: isa_facts basis {row['basis']!r}")
        if tables is not None and not isa_facts.basis_known(tables, row["basis"]):
            raise Rejected(f"{fid}: isa_facts basis {row['basis']!r} is not in the pinned tables")
        if "keys" in row and row["basis"] not in ("partial", "disagree"):
            raise Rejected(f"{fid}: isa_facts keys only on partial / disagree rows")
        if row["basis"] in ("partial", "disagree"):
            _check_keys(row, fid, tables)
        unknown = (set(row["facts"]) - set(isa_facts.KINDS) - {"class_flags"}) | (set(row["unobserved"]) - set(isa_facts.KINDS))
        if unknown:
            raise Rejected(f"{fid}: isa_facts unknown kinds {sorted(unknown)}")
        _check_row_shapes(row, fid, tables)
        coordinates.append(where)
    if len(set(coordinates)) != len(coordinates) or coordinates != sorted(coordinates):
        raise Rejected(f"{fid}: isa_facts rows duplicated or not sorted")
