"""G1 decode_check driver: one Bundle -> mapping rows and decode rows (design r0-r4).

The engine is reached only through G0's diagnosis pass (``diagnose.diagnose``,
engine_api); the rest is tool code: the file mapping (pe_map), the decode
window built from verified bytes only, the three voters, the pure core
(compare.compare_row).
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent / "bundle_lint"))

import compare  # noqa: E402
import decoders  # noqa: E402
import lifting  # noqa: E402
import pe_map  # noqa: E402
from report import Row  # noqa: E402

LANGUAGE = "x86:LE:64:default"


class Image:
    """The Bundle's sealed blocks and the original's file mapping, byte by byte."""

    def __init__(self, generation: Path, pe: pe_map.PeImage, base: int, original: bytes) -> None:
        manifest = json.loads((generation / "manifest.json").read_bytes())
        paths = {row["id"]: row["path"] for row in manifest["members"]}
        self.blocks = []
        for row in manifest["blocks"]:
            data = None if row["member_id"] is None else (generation / paths[row["member_id"]]).read_bytes()
            self.blocks.append((row, data))
        self.pe, self.base, self.original = pe, base, original
        written = pe.written.ranges if pe.written else []
        self.written = [(base + start, base + end, label) for start, end, label in written]
        relocations = pe.relocations.ranges if pe.relocations else []
        self.relocations = [(base + start, base + end, label) for start, end, label in relocations]

    def sealed(self, va: int):
        for row, data in self.blocks:
            if data is not None and row["byte_start"] <= va < row["byte_start"] + row["byte_size"]:
                return data[va - row["byte_start"]]
        return None

    def verified_byte(self, va: int):
        """(byte, None) when the sealed byte equals the loader's byte, else (None, reason)."""
        sealed = self.sealed(va)
        if sealed is None:
            return None, "no sealed byte"
        for start, end, label in self.written:
            if start <= va < end:
                return None, f"loader / runtime written range ({label})"
        mapped = self.pe.at(va - self.base)
        if mapped is None:
            return None, "outside the file mapping"
        if mapped.kind == "ambiguous":
            return None, f"ambiguous range ({mapped.why})"
        if mapped.kind == "zero":
            return (0, None) if sealed == 0 else (None, "zero-fill range with a non-zero sealed byte")
        file_byte = self.original[mapped.file_offset + (va - self.base - mapped.start)]
        return (sealed, None) if sealed == file_byte else (None, "sealed byte differs from the file")

    def window(self, va: int) -> dict:
        data = bytearray()
        reason = "15 bytes"
        for offset in range(decoders.MAX_LENGTH):
            value, why = self.verified_byte(va + offset)
            if value is None:
                reason = why
                break
            data.append(value)
        relocations = [(start - va, end - start, label) for start, end, label in self.relocations
                       if start < va + decoders.MAX_LENGTH and end > va]
        return {"bytes": bytes(data), "verified": len(data), "stop": reason, "relocations": relocations}


def mapping_rows(image: Image) -> list[Row]:
    rows = []
    pe = image.pe
    detail = {"rules": pe_map.RULES, "mapping_id": pe.mapping_id, "fields": pe.header_fields,
              "relocations": pe.relocations.state, "written": pe.written.state}
    rows.append(Row("mapping", "original", "bundle", "evaluated", "applied" if pe.ok else "unsupported", "lint",
                    {**detail, "why": pe.why} if not pe.ok else detail))
    for index, (row, data) in enumerate(image.blocks):
        key = f"#{index}/{row['space_id']:x}:{row['byte_start']:x}"
        excluded = row["is_external"] or row["is_overlay"] or not row["is_initialized"] or row["is_mapped"] \
            or not row["is_loaded"]
        if excluded:
            rows.append(Row("mapping", "block", key, "evaluated", "not_applicable", "lint", {"block": row["id"]}))
            continue
        counts = {"equal": 0, "differs": 0, "zero_mismatch": 0, "ambiguous": 0, "outside": 0}
        first_difference = None
        for offset in range(row["byte_size"]):
            va = row["byte_start"] + offset
            mapped = pe.at(va - image.base) if pe.ok else None
            if mapped is None:
                counts["outside"] += 1
            elif mapped.kind == "ambiguous":
                counts["ambiguous"] += 1
            elif mapped.kind == "zero":
                if data[offset] == 0:
                    counts["equal"] += 1
                else:
                    counts["zero_mismatch"] += 1
            else:
                file_byte = image.original[mapped.file_offset + (va - image.base - mapped.start)]
                if file_byte == data[offset]:
                    counts["equal"] += 1
                else:
                    counts["differs"] += 1
                    first_difference = first_difference or va
        detail = {"block": row["id"], **counts, "first_difference": first_difference}
        if counts["differs"] or counts["zero_mismatch"] or counts["outside"]:
            rows.append(Row("mapping", "block", key, "evaluated", "unrecognized", "lint", detail))
        elif counts["ambiguous"]:
            rows.append(Row("mapping", "block", key, "unobserved", None, "lint", detail))
        else:
            rows.append(Row("mapping", "block", key, "evaluated", "applied", "lint", detail))
    return rows


def global_reason(pe: pe_map.PeImage, base: int, language: str) -> str | None:
    if language != LANGUAGE:
        return f"language {language} is not {LANGUAGE}"
    if not pe.ok:
        return f"no usable file mapping ({pe.why})"
    if pe.image_base != base:
        return f"Bundle image base {base:#x} != file ImageBase {pe.image_base:#x}: not at the preferred base"
    if pe.relocations.state == "indeterminate":
        return f"relocation ranges indeterminate ({pe.relocations.why})"
    if pe.written.state == "indeterminate":
        return f"loader-written ranges indeterminate ({pe.written.why})"
    return None


STATE_TO_ROW = {"applied": ("evaluated", "applied"), "not_applicable": ("evaluated", "not_applicable"),
                "unobserved": ("unobserved", None)}


def decode_rows(image: Image, functions: list, premise: bool, reason: str | None) -> list[Row]:
    rows = []
    for function in functions:
        for facts in function["rows"]:
            key = f"{function['function_id']}/{facts['space']:x}:{facts['address']:x}"
            if reason is not None:
                rows.append(Row("decode", "row", key, "unobserved", None, "lint", {"reason": reason}))
                continue
            window = image.window(facts["address"])
            if not window["bytes"]:
                rows.append(Row("decode", "row", key, "unobserved", None, "lint",
                                {"reason": f"no verified byte at the row start ({window['stop']})"}))
                continue
            ballot = decoders.ballot(window["bytes"], facts["address"])
            lift = lifting.identify(facts) if premise else None
            result = compare.compare_row(facts, lift, window, ballot, s1=function["s1"],
                                         native_call=facts["native_call"], premise=premise)
            state = result["state"]
            detail = {"window": result["window"], "lift": None if lift is None else lift.pattern,
                      "attributes": result.get("attributes", {}), "s1": function["s1"],
                      "votes": {mode: [d.as_json() for d in ballot[mode]] for mode in ("intel", "amd")}}
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
    return rows


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
