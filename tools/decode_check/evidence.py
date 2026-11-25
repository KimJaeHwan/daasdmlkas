"""G1 decode evidence for the engine: `g1-decode-evidence-1` (design .census6/design_g1_engine_evidence_r3.md,
closed: Astra final specification g1_evidence_astra4.md, Fable APPROVE g1_evidence_fable4.md).

Two halves, plain functions over plain data (Rust-port surface):
- the writer (``build``), used by ``decode_check.py --evidence-out``;
- a reference reader (``parse`` / ``accept`` / ``Evidence``) implementing the design's reading rules exactly
  (header checks, coverage, the six-step read, fact decision and premises). The engine reader is TDO work; this
  one is its executable specification and the tests' oracle.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

import compare

SCHEMA = "g1-decode-evidence-1"
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
          global_reason, functions: list) -> dict:
    """The evidence document. ``functions``: [{"function_id", "observation_sha256", "rows": [(space, offset)],
    "states": {(space, offset): attribute_states}}] -- every processed row of the function."""
    body = []
    if global_reason is None:
        for function in sorted(functions, key=lambda item: item["function_id"]):
            rows = sorted(set(function["rows"]))
            exceptions = []
            for space, offset in rows:
                attributes = exception_of(function["states"].get((space, offset), {"*": "unobserved"}))
                if attributes is not None:
                    exceptions.append({"space": space, "offset": f"{offset:x}", "attributes": attributes})
            body.append({"function_id": function["function_id"], "observation_sha256": function["observation_sha256"],
                         "rows_total": len(rows), "rows_digest": rows_digest(rows), "exceptions": exceptions})
    return {"schema": SCHEMA, "bundle": bundle, "producer": producer, "mapping": mapping,
            "premises": sorted(premises), "translation": {"table_applied": table_applied},
            "compared_attributes": list(compare.COMPARED), "mode_constant": list(compare.MODE_CONSTANT),
            "consumers": {"version": CONSUMERS_VERSION, "digest": consumers_digest()},
            "global_reason": global_reason, "functions": body}


def dumps(document: dict) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def allowlist_entry(document: dict) -> dict:
    """The allowlist entry an engine would pin for the build that wrote ``document`` (design s2): the producer
    tuple without the recorded-only fields, with the exact compared / mode-constant sets."""
    producer = {k: v for k, v in document["producer"].items() if k not in ("diagnosis_engine", "naming_source_sha256")}
    return {"producer": producer, "compared_attributes": list(document["compared_attributes"]),
            "mode_constant": list(document["mode_constant"])}


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

    def __init__(self, document: dict, bundle: dict) -> None:
        self.document, self.bundle = document, bundle
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
           digest: str = CONSUMERS_DIGEST) -> Evidence:
    """Every header, body and coverage-precondition check of design s2 / s3 / s5 / s7; raises Rejected."""
    _keys(document, HEADER_KEYS, "header")
    if document["schema"] != SCHEMA:
        raise Rejected(f"schema {document['schema']!r}")
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
        _keys(item, ("function_id", "observation_sha256", "rows_total", "rows_digest", "exceptions"), "function")
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
    return Evidence(document, bundle)
