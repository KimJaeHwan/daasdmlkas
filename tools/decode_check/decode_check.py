#!/usr/bin/env python3
"""G1 ``decode_check``: original-file mapping (L7) + independent-decoder cross-check
(L2) of one sealed Bundle whose original is PE32+ (AMD64) or ELF64 (x86-64)
(design .census6/design_g1_decode_check_r0..r4.md; ELF: elf_map.RULES).
POSIX / WSL; decoders from build_decoders.sh ($G1_DECODERS).

    PYTHONPATH=src python3 tools/decode_check/decode_check.py <generation> --out report.json
        [--assume-stock-ghidra-translator] [--naming-source ghidra/GhidraV2CallNaming.java]

Scope (stated in the report header): only Ghidra-listed rows (L5); 64-bit long
mode; `decoder-matches-cpu` stays the named premise for what decoders cannot
show; instruction meaning beyond the compared attributes is not compared.
Without --assume-stock-ghidra-translator the lift table does not apply (the
Bundle carries no compiled-SLEIGH identity): table-dependent attributes are
unobserved, A1 and an explicit A2 (and the listing continuation A4) compared.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent / "bundle_lint"))

import check  # noqa: E402
import decoders  # noqa: E402
import dependents  # noqa: E402
import guards  # noqa: E402
import lifting  # noqa: E402
from report import Row, dumps  # noqa: E402

REVISION = 2
G1_LAYERS = ("mapping", "decode")
# (reserved for TBR part A3 / C1 -- decoder read / write sets vs p-code, execution differential:
#  .census6/design_tbr_semantics_r2.md) its own revision; never counted as G1 applied
RESERVED_LAYERS = {"semantics": {"revision": None, "status": "reserved (TBR A3 / C1); not produced by G1; "
                                 "never counted in G1 counts"}}
SCOPE = ("only Ghidra-listed rows are checked (L5); 64-bit long mode only (no compatibility-mode switches); "
         "decoder agreement is not a proof of CPU behaviour (premise decoder-matches-cpu); vendor agreement covers "
         "only what the decoders model; instruction meaning beyond the compared attributes (mnemonic, data effects, "
         "registers written) is not compared; whether a producer guard fired cannot be decided from the Bundle")


def _offset(coordinate_text: str) -> int:
    """``space:offset[:...]`` (G0 coordinate / operation key text) -> the byte offset."""
    return int(coordinate_text.split(":")[1], 16)


def baseline_of(claim, raw, function_keys, superseded) -> dict:
    """The engine facts G0 reports for one function, reduced to plain data for the
    dependents table (r2 s6): calls (naming, push projection / relation, plain push),
    S1 exits, BRANCHIND sites, return shapes."""
    import ops_layer

    calls = {}
    for row in ops_layer.call_rows(claim, function_keys):
        op = row.key.split("/", 1)[1]
        item = calls.setdefault(op, {"op": op, "address": _offset(op), "opcode": op.rsplit(":", 1)[1], "facts": {}})
        item["facts"]["naming" if row.check == "call" else row.check] = row.verdict
    exits = [{"source": _offset(row.detail["source"]), "target": _offset(row.detail["target"])}
             for row in ops_layer.exit_rows(claim, raw, function_keys, superseded) if row.verdict != "unrecognized"]
    # (site key control:<entry>:<space>:<offset>; the entry itself contains ':')
    branchind = [{"site": row.key.split("/", 1)[1], "address": int(row.key.rsplit(":", 1)[1], 16),
                  "unknown_transfer": row.detail["unknown_transfer"]}
                 for row in ops_layer.branchind_rows(claim, raw, superseded)]
    returns = [{"op": row.key.split("/", 1)[1], "address": _offset(row.key.split("/", 1)[1]),
                "return_shape": row.verdict} for row in ops_layer.return_rows(claim)]
    return {"calls": list(calls.values()), "exits": exits, "branchind": branchind, "returns": returns}


def collect(generation: Path, naming_source: Path) -> dict:
    """The G0 diagnosis pass, reduced to plain facts (functions, language, base,
    and per function the G0 baseline facts the dependents table reads)."""
    import diagnose
    import engine_api
    import ops_layer

    found = {"functions": [], "language": None, "image_base": None}

    def keep(diagnosis):
        program = diagnosis.program_value
        if program is None or not diagnosis.program.get("ok"):
            return
        evidence = program.evidence
        found["language"] = evidence.translation_namespace.language_id
        found["image_base"] = evidence.image_base.byte_offset
        function_keys = {claim.entry for claim in diagnosis.claims if claim.entry}
        last = {claim.entry: claim for claim in diagnosis.claims if claim.evidence is not None}
        for claim in diagnosis.claims:
            if claim.evidence is None:
                continue
            observation = claim.unit.observation
            exits = {row.source: row for row in getattr(observation, "fallthrough_exits", ())}
            rows = []
            for instruction in observation.instructions:
                facts = lifting.row_facts(instruction, exits.get(instruction.address))
                facts["native_call"] = engine_api.is_native_call(instruction)
                rows.append(facts)
            try:
                raw = ops_layer._raw_observation(generation, claim)
                baseline = baseline_of(claim, raw, function_keys, last.get(claim.entry) is not claim)
                baseline_error = None
            except Exception as error:   # (one function's baseline never stops the report)
                baseline, baseline_error = None, f"{type(error).__qualname__}: {error}"
            found["functions"].append({"function_id": claim.function_id, "entry": claim.entry,
                                       "s1": bool(getattr(observation, "call_fallthrough_isa", False)),
                                       "rows": rows, "baseline": baseline, "baseline_error": baseline_error})

    diagnosis = diagnose.diagnose(generation, naming_source, keep=keep)
    found["admission"] = diagnosis.admission
    return found


def dependents_rows(functions: list, states: dict, reason: str | None, full: bool, header: dict) -> list[Row]:
    """Layer ``dependents`` (r1-r4 s6). Without --full only the would-block rows are
    kept; the per-consumer summary in the header counts every unit."""
    header["dependents"] = {"consumers": {name: {"unit": unit, "reads": reads, "status": status, "design": ref}
                                          for name, (unit, reads, status, ref) in dependents.CONSUMERS.items()},
                            "undetermined": dependents.UNDETERMINED,
                            "rows": "every unit" if full else "would-block units only (the summary counts every unit)"}
    if reason is not None:
        header["dependents"]["summary"] = None
        return [Row("dependents", "table", "program", "unobserved", None, "lint", {"reason": reason})]
    out, judged = [], []
    for function in functions:
        if function["baseline"] is None:
            out.append(Row("dependents", "baseline", function["function_id"], "error", None, "lint",
                           {"reason": function["baseline_error"]}))
            continue
        mine = {facts["address"]: states.get((function["function_id"], facts["address"]), {"*": "unobserved"})
                for facts in function["rows"]}
        for consumer, key, run_state, verdict, detail in dependents.function_rows(function, mine):
            judged.append((consumer, key, run_state, verdict, detail))
            if full or detail["would_block"]:
                out.append(Row("dependents", consumer, key, run_state, verdict, "lint", detail))
    header["dependents"]["summary"] = dependents.summary(judged)
    return out


def run(generation: Path, naming_source: Path, premise: bool, full: bool = False) -> tuple[dict, list]:
    facts = collect(generation, naming_source)
    manifest = json.loads((generation / "manifest.json").read_bytes())
    original_path = next(row["path"] for row in manifest["members"] if row["id"] == manifest["original_member_id"])
    original = (generation / original_path).read_bytes()
    mapping = check.parse_original(original)
    header = {"tool": "decode_check", "revision": REVISION, "generation": generation.name,
              "premises": ["decoder-matches-cpu"] + ([lifting.TRANSLATION_PREMISE] if premise else []),
              "lift_table": {k: v for k, v in lifting.TABLE.items() if k != "allowed_prefix"} | {
                  "allowed_prefix": sorted(lifting.TABLE["allowed_prefix"])},
              "decoders": decoders.manifest(), "voters": {"intel": list(decoders.INTEL_VOTERS),
                                                          "amd": list(decoders.AMD_VOTERS)},
              "scope": SCOPE, "PYTHONHASHSEED": "0", "layers": {"g1": list(G1_LAYERS), "derived": ["dependents"],
                                                              "reserved": RESERVED_LAYERS}}
    if not facts["admission"].get("ok"):
        return header, [Row("mapping", "original", "bundle", "unobserved", None, "lint",
                            {"reason": "the Bundle is not admitted", "admission": facts["admission"]})]
    base = facts["image_base"]
    if base is None:
        return header, [Row("mapping", "original", "bundle", "unobserved", None, "lint",
                            {"reason": "the program scope is not constructed"})]
    image = check.Image(generation, mapping, base, original)
    rows = check.mapping_rows(image)
    reason = check.global_reason(mapping, base, facts["language"] or "")
    states = {}
    rows.extend(check.decode_rows(image, facts["functions"], premise, reason, full, states, facts["language"] or ""))
    rows.extend(check.suspect_rows(rows))
    rows.extend(dependents_rows(facts["functions"], states, reason, full, header))
    header["mapping"] = {"format": mapping.format, "rules": mapping.rules, "mapping_id": mapping.mapping_id,
                         "load_bias": base - mapping.image_base}
    header["mapping_id"] = mapping.mapping_id
    header["global_reason"] = reason
    # (r3 s8) the guard inputs known once per export; firing at production is never decidable from a Bundle
    header["guard"] = {"revision": guards.REVISION, "fired_at_production": guards.FIRED_AT_PRODUCTION,
                       "format": mapping.format, "machine": mapping.header_fields.get("machine",
                                                                                  mapping.header_fields.get("e_machine")),
                       "language": facts["language"], "language_agrees": (facts["language"] or "") == check.LANGUAGE}
    header["counts"] = g1_counts(rows)
    return header, rows


def g1_counts(rows: list) -> dict:
    """G1's own counts: layers ``mapping`` and ``decode`` only. ``dependents`` is
    derived from them, and ``semantics`` (reserved, TBR) is never counted here."""
    out = {}
    for row in rows:
        if row.layer not in G1_LAYERS:
            continue
        name = f"{row.layer}/{row.check}"
        state = row.verdict if row.run_state == "evaluated" else row.run_state
        out.setdefault(name, {})
        out[name][state] = out[name].get(state, 0) + 1
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("generation", type=Path)
    parser.add_argument("--out", type=Path, default=Path("decode_check_report.json"))
    parser.add_argument("--naming-source", type=Path,
                        default=_HERE.parents[1] / "ghidra" / "GhidraV2CallNaming.java")
    parser.add_argument("--assume-stock-ghidra-translator", action="store_true",
                        help="named premise: the Bundle's p-code comes from the stock Ghidra 12.0.4 translator")
    parser.add_argument("--full", action="store_true", help="keep every attribute and vote of applied rows too")
    args = parser.parse_args(argv)
    if not args.generation.is_dir() or not args.naming_source.is_file():
        print("decode_check: the generation directory and the naming source must exist", file=sys.stderr)
        return 2
    header, rows = run(args.generation, args.naming_source, args.assume_stock_ghidra_translator, args.full)
    args.out.write_text(dumps(header, rows), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
