#!/usr/bin/env python3
"""G1 ``decode_check``: original-file mapping (L7) + independent-decoder cross-check
(L2) of one sealed Bundle (design .census6/design_g1_decode_check_r0..r4.md).
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
import lifting  # noqa: E402
import pe_map  # noqa: E402
from report import Row, dumps  # noqa: E402

REVISION = 1
SCOPE = ("only Ghidra-listed rows are checked (L5); 64-bit long mode only (no compatibility-mode switches); "
         "decoder agreement is not a proof of CPU behaviour (premise decoder-matches-cpu); vendor agreement covers "
         "only what the decoders model; instruction meaning beyond the compared attributes (mnemonic, data effects, "
         "registers written) is not compared; whether a producer guard fired cannot be decided from the Bundle")


def collect(generation: Path, naming_source: Path) -> dict:
    """The G0 diagnosis pass, reduced to plain facts (functions, language, base)."""
    import diagnose
    import engine_api

    found = {"functions": [], "language": None, "image_base": None}

    def keep(diagnosis):
        program = diagnosis.program_value
        if program is None or not diagnosis.program.get("ok"):
            return
        evidence = program.evidence
        found["language"] = evidence.translation_namespace.language_id
        found["image_base"] = evidence.image_base.byte_offset
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
            found["functions"].append({"function_id": claim.function_id, "entry": claim.entry,
                                       "s1": bool(getattr(observation, "call_fallthrough_isa", False)),
                                       "rows": rows})

    diagnosis = diagnose.diagnose(generation, naming_source, keep=keep)
    found["admission"] = diagnosis.admission
    return found


def run(generation: Path, naming_source: Path, premise: bool) -> tuple[dict, list]:
    facts = collect(generation, naming_source)
    manifest = json.loads((generation / "manifest.json").read_bytes())
    original_path = next(row["path"] for row in manifest["members"] if row["id"] == manifest["original_member_id"])
    original = (generation / original_path).read_bytes()
    pe = pe_map.parse(original)
    header = {"tool": "decode_check", "revision": REVISION, "generation": generation.name,
              "premises": ["decoder-matches-cpu"] + ([lifting.TRANSLATION_PREMISE] if premise else []),
              "lift_table": {k: v for k, v in lifting.TABLE.items() if k != "allowed_prefix"} | {
                  "allowed_prefix": sorted(lifting.TABLE["allowed_prefix"])},
              "decoders": decoders.manifest(), "voters": {"intel": list(decoders.INTEL_VOTERS),
                                                          "amd": list(decoders.AMD_VOTERS)},
              "scope": SCOPE, "PYTHONHASHSEED": "0"}
    if not facts["admission"].get("ok"):
        return header, [Row("mapping", "original", "bundle", "unobserved", None, "lint",
                            {"reason": "the Bundle is not admitted", "admission": facts["admission"]})]
    base = facts["image_base"]
    if base is None:
        return header, [Row("mapping", "original", "bundle", "unobserved", None, "lint",
                            {"reason": "the program scope is not constructed"})]
    image = check.Image(generation, pe, base, original)
    rows = check.mapping_rows(image)
    reason = check.global_reason(pe, base, facts["language"] or "")
    rows.extend(check.decode_rows(image, facts["functions"], premise, reason))
    rows.extend(check.suspect_rows(rows))
    header["mapping_id"] = pe.mapping_id
    header["global_reason"] = reason
    return header, rows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("generation", type=Path)
    parser.add_argument("--out", type=Path, default=Path("decode_check_report.json"))
    parser.add_argument("--naming-source", type=Path,
                        default=_HERE.parents[1] / "ghidra" / "GhidraV2CallNaming.java")
    parser.add_argument("--assume-stock-ghidra-translator", action="store_true",
                        help="named premise: the Bundle's p-code comes from the stock Ghidra 12.0.4 translator")
    args = parser.parse_args(argv)
    if not args.generation.is_dir() or not args.naming_source.is_file():
        print("decode_check: the generation directory and the naming source must exist", file=sys.stderr)
        return 2
    header, rows = run(args.generation, args.naming_source, args.assume_stock_ghidra_translator)
    args.out.write_text(dumps(header, rows), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
