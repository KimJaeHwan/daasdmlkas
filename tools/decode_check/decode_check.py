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
import evidence  # noqa: E402
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
         "registers written) is not compared; whether a producer guard fired cannot be decided from the Bundle; the "
         "continuation compared is the no-fault one: faults (memory access, privilege, CPU feature availability) are not "
         "compared -- privileged / OS-gated userops are never pinned as no-flow, and per-row privilege / feature facts are "
         "the TBR to-do 'ISA fact annotations'")


def _offset(coordinate_text: str) -> tuple:
    """``space:offset[:...]`` (G0 coordinate / operation key text) -> ``(space, offset)``: rows of
    different address spaces never share a key (Astra impl r2 P1-2)."""
    space, offset = coordinate_text.split(":")[:2]
    return int(space, 16), int(offset, 16)


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
    branchind = [{"site": row.key.split("/", 1)[1], "address": _offset(":".join(row.key.rsplit(":", 2)[-2:])),
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
        found["language_version"] = (evidence.translation_namespace.major_version,
                                     evidence.translation_namespace.minor_version)
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
                                       "producer_profile": getattr(observation, "producer_profile", None),
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
        mine = {(facts["space"], facts["address"]):
                states.get((function["function_id"], facts["space"], facts["address"]), {"*": "unobserved"})
                for facts in function["rows"]}
        for consumer, key, run_state, verdict, detail in dependents.function_rows(function, mine):
            judged.append((consumer, key, run_state, verdict, detail))
            if full or detail["would_block"]:
                out.append(Row("dependents", consumer, key, run_state, verdict, "lint", detail))
    header["dependents"]["summary"] = dependents.summary(judged)
    return out


class IsaCollector:
    """ISA facts step 3: computes isa_facts.row_facts for every row G1 compared (check.decode_rows calls it with
    the verified window and the ballot) and keeps the per-function status (design r3 s2 / s5)."""

    def __init__(self) -> None:
        import isa_tables

        self.tables = isa_tables.load()
        self.functions = {}

    def __call__(self, fid, space, address, window, ballot) -> None:
        import isa_facts

        entry = self.functions.setdefault(fid, {"status": {kind: "checked" for kind in isa_facts.KINDS}, "rows": {}})
        try:
            row = isa_facts.row_facts(
                self.tables, ballot, window,
                redecode=lambda data: decoders.xed_redecode(data, address),
                decode_profile=lambda name, data: decoders.decode_profile(name, data, address),
                decode_without=lambda isa_set, data: decoders.decode_without(isa_set, data, address))
        except Exception as error:          # (one failing row fails the function's status, never the run)
            entry["status"] = {kind: f"failed:{type(error).__name__}: {error}"[:200] for kind in isa_facts.KINDS}
            return
        entry["rows"][(space, address)] = row

    def block(self, facts: dict | None = None, states: dict | None = None) -> dict:
        """The evidence-2 ISA block. With the G1 facts / states, ``checked`` is verified (review r1 P2-1): the rows
        G1 compared (not '*') must be exactly the rows this collector processed, else failed:row-set-mismatch."""
        import isa_facts

        if facts is not None and states is not None:
            for function in facts["functions"]:
                fid = function["function_id"]
                compared = {(row["space"], row["address"]) for row in function["rows"]
                            if "*" not in states.get((fid, row["space"], row["address"]), {"*": "unobserved"})}
                entry = self.functions.get(fid)
                processed = set(entry["rows"]) if entry else set()
                if compared != processed and (entry is None or all(v == "checked" for v in entry["status"].values())):
                    self.functions[fid] = {"status": {kind: "failed:row-set-mismatch" for kind in isa_facts.KINDS},
                                           "rows": {}}
        return {"header": isa_facts.header_block(self.tables, decoders.profile_catalogue()),
                "functions": self.functions}


class OverrideCollector:
    """design_tbr_g1_x1 r1-r3: one verdict code per compared profile row (producer_override.row_verdict) and the
    star details; ``block`` verifies the coded rows against the rows G1 compared (failed:row-set-mismatch)."""

    def __init__(self, declared) -> None:
        self.declared = declared            # the manifest's producer_profile (None: a legacy Bundle)
        self.functions = {}

    def __call__(self, fid, facts, result, lift, ballot) -> None:
        import producer_override

        entry = self.functions.setdefault(fid, {"codes": {}, "details": {}, "error": None})
        try:
            verdict = producer_override.row_verdict(facts, result, lift, ballot)
        except Exception as error:          # (one failing row fails the function's status, never the run)
            entry["error"] = f"failed:{type(error).__name__}: {error}"[:200]
            return
        if verdict is None:
            return
        code, detail = verdict
        where = (facts["space"], facts["address"])
        if code is not None:
            entry["codes"][where] = code
        if detail is not None:
            entry["details"][where] = detail

    def block(self, facts: dict, states: dict, engine_source: dict) -> dict:
        import producer_override

        functions = {}
        for function in facts["functions"]:
            fid = function["function_id"]
            entry = self.functions.get(fid, {"codes": {}, "details": {}, "error": None})
            compared = sorted((row["space"], row["address"]) for row in function["rows"]
                              if "*" not in states.get((fid, row["space"], row["address"]), {"*": "unobserved"}))
            out = {"status": "checked", "codes": {}, "details": {}}
            if function.get("producer_profile") is None:
                out["status"] = "failed:parser-without-profile" if self.declared is not None else "not_reported"
            elif entry["error"]:
                out["status"] = entry["error"]
            elif sorted(entry["codes"]) != compared:
                out["status"] = "failed:row-set-mismatch"
            else:
                out["codes"], out["details"] = dict(entry["codes"]), dict(entry["details"])
            functions[fid] = out
        return {"header": producer_override.header_block(self.declared, engine_source), "functions": functions}


def engine_source() -> dict:
    """The TDO tree G1 imported for admission and parsing (design_tbr_g1_x1 r1 s5 / s7): the digest of the imported
    ``tdo_v2`` package and its git revision when known -- not wt_lint/src unless that is what was imported."""
    import hashlib
    import subprocess

    import tdo_v2

    package = Path(tdo_v2.__file__).resolve().parent
    files = sorted(package.rglob("*.py"))
    digest = hashlib.sha256("".join(
        f"{path.relative_to(package.parent).as_posix()}\0{hashlib.sha256(path.read_bytes()).hexdigest()}\n"
        for path in files).encode("utf-8")).hexdigest()
    try:
        revision = subprocess.run(["git", "-C", str(package), "rev-parse", "HEAD"], capture_output=True, text=True,
                                  timeout=30).stdout.strip() or None
        dirty = bool(subprocess.run(["git", "-C", str(package), "status", "--porcelain", "--", "."],
                                    capture_output=True, text=True, timeout=60).stdout.strip())
    except (OSError, subprocess.SubprocessError):
        revision, dirty = None, None
    if revision is None:
        dirty = None                        # (git did not answer: neither the revision nor its state is known)
    return {"package": "tdo_v2", "digest": digest, "revision": revision, "dirty": dirty}


def write_evidence(path: Path, generation: Path, naming_source: Path, manifest: dict, original: bytes, mapping,
                   facts: dict, states: dict, use_table: bool, reason, isa: dict | None = None,
                   override: dict | None = None) -> None:
    """``g1-decode-evidence-1`` (design .census6/design_g1_engine_evidence_r3.md, s2 / s3 / s7); with ``isa``
    ``g1-decode-evidence-2`` (design .census6/design_tbr_isa_facts_r3.md s5)."""
    import hashlib

    seal = json.loads((generation / "seal.json").read_bytes())
    members = {row["id"]: row for row in manifest["members"]}
    observation = {row["id"]: members[row["observation_member"]]["sha256"] for row in manifest["functions"]}
    # (design_tbr_g1_x1 r1 s5: the engine G1 actually imported, not wt_lint/src)
    engine_digest = engine_source()["digest"]
    document = evidence.build(
        bundle={"generation_id": seal["generation_id"], "manifest_sha256": seal["manifest_sha256"],
                "original_sha256": hashlib.sha256(original).hexdigest()},
        producer={"decode_check_revision": REVISION, "tool_digest": evidence.tool_digest(_HERE.parents[1]),
                  "decoders": decoders.manifest(),
                  "voters": {"intel": list(decoders.INTEL_VOTERS), "amd": list(decoders.AMD_VOTERS)},
                  "rules": mapping.rules, "lift_table": lifting.TABLE["id"],
                  "diagnosis_engine": {"source_digest": engine_digest},
                  "naming_source_sha256": hashlib.sha256(naming_source.read_bytes()).hexdigest()},
        mapping={"format": mapping.format, "mapping_id": mapping.mapping_id},
        premises=["decoder-matches-cpu"] + ([lifting.TRANSLATION_PREMISE] if use_table else []),
        table_applied=use_table, global_reason=reason,
        functions=[{"function_id": function["function_id"], "observation_sha256": observation[function["function_id"]],
                    "rows": [(row["space"], row["address"]) for row in function["rows"]],
                    "states": {(row["space"], row["address"]): states.get((function["function_id"], row["space"],
                                                                           row["address"]), {"*": "unobserved"})
                               for row in function["rows"]}}
                   for function in facts["functions"]],
        isa=isa, override=override)
    path.write_bytes(evidence.dumps(document))


def run(generation: Path, naming_source: Path, premise: bool, full: bool = False,
        evidence_out: Path | None = None, isa_facts: bool = False,
        producer_override: bool = False) -> tuple[dict, list]:
    facts = collect(generation, naming_source)
    manifest = json.loads((generation / "manifest.json").read_bytes())
    original_path = next(row["path"] for row in manifest["members"] if row["id"] == manifest["original_member_id"])
    original = (generation / original_path).read_bytes()
    mapping = check.parse_original(original)
    header = {"tool": "decode_check", "revision": REVISION, "generation": generation.name,
              "premises": ["decoder-matches-cpu"] + ([lifting.TRANSLATION_PREMISE] if premise else []),
              "lift_table": {k: v for k, v in lifting.TABLE.items() if k not in ("allowed_prefix", "no_flow_userops")} | {
                  "allowed_prefix": sorted(lifting.TABLE["allowed_prefix"]),
                  "no_flow_userops_count": len(lifting.TABLE["no_flow_userops"])},
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
    # r4 s2: the table applies only when the premise is on AND the Bundle's own identity fields match it
    identity = lifting.table_identity(facts["language"] or "", *(facts.get("language_version") or (None, None)))
    use_table = premise and identity["state"] != "mismatch"
    unverified = None
    if premise and not use_table:
        unverified = f"translation identity mismatch ({identity['checks']['language']}): the table does not apply"
    elif not premise:
        unverified = "translation-unverified (no compiled-SLEIGH digest in the Bundle; premise " \
                     f"{lifting.TRANSLATION_PREMISE} off)"
    header["translation_identity"] = {**identity, "premise": premise, "table_applied": use_table}
    states = {}
    # (design_tbr_g1_x1: schema -3 = -2 + the producer-override verdicts; always with the ISA facts)
    collector = IsaCollector() if (isa_facts or producer_override) and evidence_out is not None else None
    verdicts = OverrideCollector(manifest.get("producer_profile")) if producer_override else None
    rows.extend(check.decode_rows(image, facts["functions"], use_table, reason, full, states, facts["language"] or "",
                                  unverified, isa=collector, override=verdicts))
    override_block = None
    if verdicts is not None:
        override_block = verdicts.block(facts, states, engine_source())
        for function in facts["functions"]:
            function["override"] = override_block["functions"][function["function_id"]]
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
    if evidence_out is not None:
        write_evidence(evidence_out, generation, naming_source, manifest, original, mapping, facts, states, use_table,
                       reason, None if collector is None else collector.block(facts, states), override_block)
        header["evidence_out"] = str(evidence_out)
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
    parser.add_argument("--isa-facts", action="store_true",
                        help="write g1-decode-evidence-2: the evidence file plus the per-row ISA facts")
    parser.add_argument("--producer-override", action="store_true",
                        help="write g1-decode-evidence-3: -2 plus the per-row producer-override verdicts (X-1)")
    parser.add_argument("--evidence-out", type=Path, default=None,
                        help="also write the engine evidence file g1-decode-evidence-1 (outside the Bundle)")
    args = parser.parse_args(argv)
    if not args.generation.is_dir() or not args.naming_source.is_file():
        print("decode_check: the generation directory and the naming source must exist", file=sys.stderr)
        return 2
    header, rows = run(args.generation, args.naming_source, args.assume_stock_ghidra_translator, args.full,
                       args.evidence_out, args.isa_facts, args.producer_override)
    args.out.write_text(dumps(header, rows), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
