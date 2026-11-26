"""G1 decode_check driver: one Bundle -> mapping rows and decode rows (design r0-r4).

The engine is reached only through G0's diagnosis pass (``diagnose.diagnose``,
engine_api); the rest is tool code: the file mapping (pe_map / elf_map), the
decode window built from verified bytes only, the three voters, the pure core
(compare.compare_row).
"""

from __future__ import annotations

from bisect import bisect_right
import json
from pathlib import Path
import sys

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent / "bundle_lint"))

import compare  # noqa: E402
import decoders  # noqa: E402
import dependents  # noqa: E402
import elf_map  # noqa: E402
import guards  # noqa: E402
import lifting  # noqa: E402
import pe_map  # noqa: E402
from report import Row  # noqa: E402

LANGUAGE = "x86:LE:64:default"


def parse_original(data: bytes):
    """The original's file mapping by its own magic: PE32+ (pe_map) or ELF64 (elf_map).
    Both expose ok / why / format / rules / image_base / fixed_base / ranges / at(offset) /
    header_fields / relocations / written / mapping_id, offsets counted from image_base."""
    if data[:2] == b"MZ":
        return pe_map.parse(data)
    if data[:4] == b"\x7fELF":
        return elf_map.parse(data)
    return pe_map.parse(b"")   # (not an MZ image: ok False, an indeterminate mapping)


class Intervals:
    """Disjoint sorted [start, end) pieces of labelled ranges that may overlap (labels joined)."""

    def __init__(self, ranges) -> None:
        bounds = sorted({point for start, end, _ in ranges for point in (start, end)})
        by_start = sorted(ranges)
        pieces = []
        active = []
        cursor = 0
        for left, right in zip(bounds, bounds[1:]):
            while cursor < len(by_start) and by_start[cursor][0] <= left:
                active.append(by_start[cursor])
                cursor += 1
            active = [item for item in active if item[1] > left]
            labels = sorted({item[2] for item in active})
            if not labels:
                continue
            if pieces and pieces[-1][1] == left and pieces[-1][2] == labels:
                pieces[-1][1] = right
            else:
                pieces.append([left, right, labels])
        self.pieces = pieces
        self.starts = [piece[0] for piece in pieces]

    def find(self, point: int):
        index = bisect_right(self.starts, point) - 1
        if index >= 0 and point < self.pieces[index][1]:
            return self.pieces[index]
        return None

    def next_start(self, point: int) -> float:
        index = bisect_right(self.starts, point)
        return self.starts[index] if index < len(self.starts) else float("inf")


class Image:
    """The Bundle's sealed blocks and the original's file mapping, byte by byte."""

    def __init__(self, generation: Path, mapping, base: int, original: bytes) -> None:
        manifest = json.loads((generation / "manifest.json").read_bytes())
        paths = {row["id"]: row["path"] for row in manifest["members"]}
        self.blocks = []
        for row in manifest["blocks"]:
            data = None if row["member_id"] is None else (generation / paths[row["member_id"]]).read_bytes()
            self.blocks.append((row, data))
        self.mapping, self.base, self.original = mapping, base, original
        written = mapping.written.ranges if mapping.written else []
        self.written = Intervals([(base + start, base + end, label) for start, end, label in written])
        relocations = mapping.relocations.ranges if mapping.relocations else []
        self.relocations = [(base + start, base + end, label) for start, end, label in relocations]

    def sealed(self, va: int, space=None):
        """The sealed byte at ``va`` of the row's own address space (``space`` None: any space -- tests only)."""
        for row, data in self.blocks:
            if data is not None and (space is None or row.get("space_id") == space) \
                    and row["byte_start"] <= va < row["byte_start"] + row["byte_size"]:
                return data[va - row["byte_start"]]
        return None

    def verified_byte(self, va: int, space=None):
        """(byte, None) when the sealed byte equals the loader's byte, else (None, reason)."""
        sealed = self.sealed(va, space)
        if sealed is None:
            return None, "no sealed byte"
        written = self.written.find(va)
        if written is not None:
            return None, f"loader / runtime written range ({', '.join(written[2])})"
        mapped = self.mapping.at(va - self.base) if self.mapping.ok else None
        if mapped is None:
            return None, "outside the file mapping"
        if mapped.kind == "ambiguous":
            return None, f"ambiguous range ({mapped.why})"
        if mapped.kind == "zero":
            return (0, None) if sealed == 0 else (None, "zero-fill range with a non-zero sealed byte")
        file_byte = self.original[mapped.file_offset + (va - self.base - mapped.start)]
        return (sealed, None) if sealed == file_byte else (None, "sealed byte differs from the file")

    def window(self, va: int, space=None) -> dict:
        data = bytearray()
        reason = "15 bytes"
        for offset in range(decoders.MAX_LENGTH):
            value, why = self.verified_byte(va + offset, space)
            if value is None:
                reason = why
                break
            data.append(value)
        relocations = [(start - va, end - start, label) for start, end, label in self.relocations
                       if start < va + decoders.MAX_LENGTH and end > va]
        return {"bytes": bytes(data), "verified": len(data), "stop": reason, "relocations": relocations}


def _next_range_start(mapping, offset: int) -> float:
    return min((item.start for item in mapping.ranges if item.start > offset), default=float("inf"))


def compare_block(image: Image, row: dict, data: bytes) -> dict:
    """Byte counts of one sealed block against the mapping, range by range
    (written bytes are the loader's: counted, not compared)."""
    counts = {"equal": 0, "differs": 0, "zero_mismatch": 0, "ambiguous": 0, "outside": 0, "written": 0}
    first_difference = None
    mapping, base = image.mapping, image.base
    start, end = row["byte_start"], row["byte_start"] + row["byte_size"]
    cursor = start
    while cursor < end:
        written = image.written.find(cursor)
        if written is not None:
            take = min(written[1], end) - cursor
            counts["written"] += take
            cursor += take
            continue
        limit = min(end, image.written.next_start(cursor))
        mapped = mapping.at(cursor - base) if mapping.ok else None
        if mapped is None:
            following = _next_range_start(mapping, cursor - base) + base if mapping.ok else float("inf")
            take = int(min(limit, following)) - cursor
            counts["outside"] += take
            cursor += take
            continue
        take = int(min(limit, base + mapped.end)) - cursor
        sealed = data[cursor - start:cursor - start + take]
        if mapped.kind == "ambiguous":
            counts["ambiguous"] += take
        elif mapped.kind == "zero":
            zeros = sealed.count(0)
            counts["equal"] += zeros
            counts["zero_mismatch"] += take - zeros
        else:
            offset = mapped.file_offset + (cursor - base - mapped.start)
            file_bytes = image.original[offset:offset + take]
            if file_bytes == sealed:
                counts["equal"] += take
            else:
                for index, (a, b) in enumerate(zip(file_bytes.ljust(take, b"\0"), sealed)):
                    if a == b:
                        counts["equal"] += 1
                    else:
                        counts["differs"] += 1
                        first_difference = first_difference or cursor + index
        cursor += take
    return {**counts, "first_difference": first_difference}


def mapping_rows(image: Image) -> list[Row]:
    rows = []
    mapping = image.mapping
    detail = {"format": mapping.format, "rules": mapping.rules, "mapping_id": mapping.mapping_id,
              "fields": mapping.header_fields, "relocations": mapping.relocations.state,
              "written": mapping.written.state, "load_bias": image.base - mapping.image_base}
    if mapping.written.why:
        detail["written_why"] = mapping.written.why
    rows.append(Row("mapping", "original", "bundle", "evaluated", "applied" if mapping.ok else "unsupported", "lint",
                    {**detail, "why": mapping.why} if not mapping.ok else detail))
    for index, (row, data) in enumerate(image.blocks):
        key = f"#{index}/{row['space_id']:x}:{row['byte_start']:x}"
        excluded = row["is_external"] or row["is_overlay"] or not row["is_initialized"] or row["is_mapped"] \
            or not row["is_loaded"]
        if excluded:
            rows.append(Row("mapping", "block", key, "evaluated", "not_applicable", "lint", {"block": row["id"]}))
            continue
        counts = compare_block(image, row, data)
        detail = {"block": row["id"], **counts}
        if counts["differs"] or counts["zero_mismatch"] or counts["outside"]:
            rows.append(Row("mapping", "block", key, "evaluated", "unrecognized", "lint", detail))
        elif counts["ambiguous"] or not counts["equal"]:
            rows.append(Row("mapping", "block", key, "unobserved", None, "lint", detail))
        else:
            rows.append(Row("mapping", "block", key, "evaluated", "applied", "lint", detail))
    return rows


def global_reason(mapping, base: int, language: str) -> str | None:
    if language != LANGUAGE:
        return f"language {language} is not {LANGUAGE}"
    if not mapping.ok:
        return f"no usable file mapping ({mapping.why})"
    if mapping.fixed_base and mapping.image_base != base:
        which = "preferred" if mapping.format == "pe" else "linked (ET_EXEC)"
        return f"Bundle image base {base:#x} != file image base {mapping.image_base:#x}: not at the {which} base"
    if mapping.relocations.state == "indeterminate":
        return f"relocation ranges indeterminate ({mapping.relocations.why})"
    if mapping.written.state == "indeterminate":
        return f"loader-written ranges indeterminate ({mapping.written.why})"
    return None


STATE_TO_ROW = {"applied": ("evaluated", "applied"), "not_applicable": ("evaluated", "not_applicable"),
                "unobserved": ("unobserved", None)}


def decode_rows(image: Image, functions: list, premise: bool, reason: str | None, full: bool = False,
                states: dict | None = None, language: str = LANGUAGE, unverified_reason: str | None = None,
                isa=None, override=None) -> list[Row]:
    """Decode rows; ``states`` (when given) receives ``(function id, address) ->
    dependents.attribute_states(result)`` for the dependents table. ``isa`` (when given) is called as
    ``isa(function_id, space, address, verified window bytes, ballot)`` for every row G1 compared (ISA facts
    step 3: facts only from the bytes G1 verified, design r3 s5). ``override`` (when given) is called as
    ``override(function_id, facts, result, lift, ballot, window bytes)`` for every row, ``result`` None for a row
    never compared (design_tbr_g1_x1 r1-r3)."""
    rows = []
    states = {} if states is None else states
    for function in functions:
        conditions = {}
        own = {(row["space"], row["address"]) for row in function["rows"]}
        for facts in function["rows"]:
            key = f"{function['function_id']}/{facts['space']:x}:{facts['address']:x}"
            where = (facts["space"], facts["address"])
            states[(function["function_id"], *where)] = {"*": "unobserved"}
            conditions[where] = guards.UNOBSERVED
            x1 = None
            if facts.get("override") is not None:
                # (design_tbr_g1_x1 r3 s5: S3 computes these from the Bundle; G1 reports them in its text report,
                #  on every row, early returns included -- impl r2 Astra P3)
                where_ft = None if facts["fallthrough"] is None else (facts.get("fallthrough_space", facts["space"]),
                                                                     facts["fallthrough"])
                x1 = {"exit_listed": facts["exit"] is not None, "in_function": where_ft in own}
            if reason is not None:
                rows.append(Row("decode", "row", key, "unobserved", None, "lint",
                                {"reason": reason} | ({"x1": x1} if x1 else {})))
                if override is not None:
                    override(function["function_id"], facts, None, None, None, None)
                continue
            window = image.window(facts["address"], facts["space"])
            lift = lifting.identify(facts) if premise else None
            conditions[where] = guards.row_condition(facts, window["bytes"], lift)
            if not window["bytes"]:
                rows.append(Row("decode", "row", key, "unobserved", None, "lint",
                                {"reason": f"no verified byte at the row start ({window['stop']})"}
                                | ({"x1": x1} if x1 else {})))
                if override is not None:
                    override(function["function_id"], facts, None, lift, None, None)
                continue
            ballot = decoders.ballot(window["bytes"], facts["address"])
            result = compare.compare_row(facts, lift, window, ballot, s1=function["s1"],
                                         native_call=facts["native_call"], premise=premise,
                                         unverified_reason=unverified_reason)
            states[(function["function_id"], *where)] = dependents.attribute_states(result)
            if isa is not None and "*" not in states[(function["function_id"], *where)]:
                isa(function["function_id"], facts["space"], facts["address"], window["bytes"], ballot)
            if override is not None:
                override(function["function_id"], facts, result, lift, ballot, window["bytes"])
            state = result["state"]
            detail = {"window": result["window"], "lift": None if lift is None else lift.pattern, "s1": function["s1"]}
            if conditions[where] is not False:
                detail["guard"] = {"recomputed": conditions[where],
                                   "fired_at_production": guards.FIRED_AT_PRODUCTION}
            if full or state != "applied":
                # (an applied row keeps only its window and lift: every attribute agreed; the report of a
                # large DLL would otherwise be gigabytes)
                detail["attributes"] = result.get("attributes", {})
                detail["votes"] = {mode: [d.as_json() for d in ballot[mode]] for mode in ("intel", "amd")}
            if x1:
                detail["x1"] = x1
            if "reason" in result:
                detail["reason"] = result["reason"]
            if "suspect_pattern" in result:
                detail["suspect_pattern"] = result["suspect_pattern"]
            if state in STATE_TO_ROW:
                run_state, verdict = STATE_TO_ROW[state]
            else:
                kind_state, kind = state.split(":", 1)
                run_state, verdict = "evaluated", kind_state
                detail["kind"] = kind
            rows.append(Row("decode", "row", key, run_state, verdict, "lint", detail))
        rows.append(guard_row(function, conditions, language))
    return rows


def guard_row(function: dict, conditions: dict, language: str) -> Row:
    """The function's S1 guard (r3 s8 / r4 s8): ``withheld`` when the recomputed
    condition is true (the guard would withhold S1), ``applied`` when false,
    ``unobserved`` when undecided. Whether it fired at production stays unobserved;
    the observed S1 presence is reported beside it, never used to infer firing."""
    value = guards.function_condition(language, list(conditions.values()))
    detail = {"recomputed": value, "fired_at_production": guards.FIRED_AT_PRODUCTION,
              "s1_observed": bool(function["s1"]), "revision": guards.REVISION}
    rows_of = [f"{space:x}:{offset:x}" for (space, offset), item in conditions.items() if item is not False]
    if rows_of:
        detail["rows"] = rows_of[:5]
        detail["rows_count"] = len(rows_of)
    if value is True:
        return Row("decode", "s1_guard", function["function_id"], "evaluated", "withheld", "lint", detail)
    if value is False:
        return Row("decode", "s1_guard", function["function_id"], "evaluated", "applied", "lint", detail)
    return Row("decode", "s1_guard", function["function_id"], "unobserved", None, "lint", detail)


def suspect_rows(rows: list[Row]) -> list[Row]:
    """The Ghidra decode suspect list: compared attributes with a Ghidra-only
    disagreement, grouped by the leading instruction bytes (r1 s5, r3 s7)."""
    groups = {}
    for row in rows:
        if row.layer != "decode" or row.check != "row":
            continue
        for name, item in row.detail.get("attributes", {}).items():
            if item.get("kind") != "ghidra-decode-suspect":
                continue
            data = bytes.fromhex(row.detail["window"].get("hex", ""))[:4].hex() or "?"
            groups.setdefault((data, name), []).append(row.key)
    return [Row("decode", "suspect", f"{pattern}/{name}", "evaluated", "unrecognized", "lint",
                {"count": len(keys), "examples": keys[:5]}) for (pattern, name), keys in sorted(groups.items())]
