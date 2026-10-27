#!/usr/bin/env python3
"""Run the TDO_v2 engine on a DataFlowBench Bundle (WSL).

Default: the summary engine (``tdo_v2.summary_engine``: bottom-up callee
summaries, external models, named assumptions listed in the output).
``--legacy-engine`` (or ``TDO_V2_INTERPROCEDURAL=legacy``) runs the older
``tdo_v2.engine.analyze_frozen_bundle`` per-root completion instead.

Boundary table (x86-64, Ghidra language x86:LE:64:default, register
space offsets RAX=0x0, RCX=0x8, RDI=0x38). The first-argument register
depends on the ABI, chosen from the Bundle's original binary (``abi_of``):
PE -> Windows x64 (RCX), ELF -> System V (RDI). 32-bit x86 passes arguments
on the stack, which these register rules cannot express: unsupported.
  sources dfb_source_A/B/C, dfb_source_long_A  -> EAX  (0x0, 4)  label "<name>.ret"
  source  dfb_source_buf_A                      -> RAX  (0x0, 8)
  sinks   dfb_sink_int, dfb_sink_long           -> ECX/EDI (4)    label "<name>.arg0"
  sinks   dfb_sink_ptr, dfb_sink_buf            -> RCX/RDI (8)
The engine resolves a SOURCE selector in the callee's own view at its end,
so the source function must be inside the Bundle (the exporter's call
closure includes it); a SINK selector is resolved in the caller before the
call.

Root functions are named from the exporter selection order recorded in
<output-root>.logs/<gen>.command.json (function-%06d i == i-th --function-name).

  ~/venvs/tdo/bin/python tools/bundle_export/run_dfbench.py <generation> \
      --expected /mnt/d/01_gitproject/09_tdo_testbed/manifests/cases_manifest.json       --binary dfbench_win_core
"""

from __future__ import annotations

import argparse
import os
import json
from pathlib import Path
import sys
import time
import traceback

REPO = Path(__file__).resolve().parents[2]
SOURCES = {"dfb_source_A": 4, "dfb_source_B": 4, "dfb_source_C": 4,
           "dfb_source_long_A": 4, "dfb_source_buf_A": 8}
SINKS = {"dfb_sink_int": 4, "dfb_sink_long": 4, "dfb_sink_ptr": 8, "dfb_sink_buf": 8}


FIRST_ARGUMENT = {"win64": 0x8, "sysv64": 0x38}  # RCX / RDI
LANGUAGES = {"win64": "x86:LE:64:default", "sysv64": "x86:LE:64:default", "x86-32": "x86:LE:32:default"}
X86_ESP = 0x10


def abi_of(generation: Path) -> str:
    """'win64' (PE32+), 'sysv64' (ELF64) or 'x86-32' (PE32 / ELF32, cdecl:
    arguments on the stack) from the Bundle's original binary."""
    manifest = json.loads((generation / "manifest.json").read_text(encoding="utf-8"))
    paths = {row["id"]: row["path"] for row in manifest["members"]}
    head = (generation / paths[manifest["original_member_id"]]).read_bytes()[:0x400]
    if head[:2] == b"MZ":
        pe = int.from_bytes(head[0x3C:0x40], "little")
        machine = int.from_bytes(head[pe + 4:pe + 6], "little")
        return "x86-32" if machine == 0x14C else "win64"
    if head[:4] == b"ELF":
        return "x86-32" if head[4] == 1 else "sysv64"
    raise ValueError(f"unknown executable format: {head[:4]!r}")


def boundary_provider(assume_call_effect: bool = False, abi: str = "win64"):
    """``assume_call_effect``: TEST-ONLY declared source/sink call effects.
    x86-32: the result is EAX (64-bit results EDX:EAX are not modelled) and
    the first argument is the stack slot at the call (``[ESP]`` before the
    return-address push); the TEST-ONLY assumption does not model memory
    state, so 32-bit sinks stay ordinary calls in that mode."""
    from tdo_v2.boundary import BoundaryKind
    from tdo_v2.boundary_rules import BoundaryRule, SymbolBoundaryProvider
    from tdo_v2.physical_state import PhysicalMemorySlice, PhysicalRegisterSlice

    language = LANGUAGES[abi]
    wide = abi != "x86-32"
    rules = [BoundaryRule(name, language, BoundaryKind.SOURCE, f"{name}.ret",
                          (PhysicalRegisterSlice(0x0, size if wide else 4),), assume_call_effect)
             for name, size in SOURCES.items()]
    for name, size in SINKS.items():
        if wide:
            state = (PhysicalRegisterSlice(FIRST_ARGUMENT[abi], size),)
        else:
            state = (PhysicalMemorySlice(PhysicalRegisterSlice(X86_ESP, 4), 0, 4),)
        rules.append(BoundaryRule(name, language, BoundaryKind.SINK, f"{name}.arg0", state,
                                  assume_call_effect))
    return SymbolBoundaryProvider(tuple(rules))


def external_models(generation: Path, extra_dirs=()):
    """Models (models/external, then ``--model-dir`` directories and
    TDO_V2_MODEL_DIRS) for this Bundle's language and ABI."""
    from tdo_v2.summary_store import load_external_models, model_paths

    return load_external_models(model_paths(REPO / "models" / "external", extra_dirs),
                                LANGUAGES[abi_of(generation)], abi_of(generation))


def pcodeop_models():
    """Declared CALLOTHER semantics (models/pcodeops); each use is labelled."""
    from tdo_v2.pcodeop_models import load_pcodeop_models

    return load_pcodeop_models(sorted((REPO / "models" / "pcodeops").glob("*.json")))


def selection_names(generation: Path) -> list[str]:
    command = generation.parent.parent / (generation.parent.name + ".logs") / \
        f"{generation.name}.command.json"
    if not command.is_file():
        return []
    argv = json.loads(command.read_text(encoding="utf-8"))["command"]
    return [argv[i + 1] for i, a in enumerate(argv) if a == "--function-name"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("generation", type=Path)
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--binary", default="dfbench_win_core",
                        help="case filter when --expected is cases_manifest.json")
    parser.add_argument("--json", type=Path)
    parser.add_argument("--records", action="store_true",
                        help="operation records per root: the p-code operations each root's value went through "
                             "(diagnostics, docs 25.28; in --json, and printed for the expected cases)")
    parser.add_argument("--physical-records", action="store_true",
                        help="include opt-in physical memory/call evidence in operation records "
                             "(implies --records; summary engine only; diagnostics, not analysis assumptions)")
    parser.add_argument("--witnesses", action="store_true",
                        help="origin witnesses per root: why each label is reported (diagnostics, docs 25.19)")
    parser.add_argument("--model-dir", type=Path, action="append", default=[],
                        help="extra directory of model files (repeatable; also TDO_V2_MODEL_DIRS)")
    parser.add_argument("--legacy-engine", action="store_true",
                        help="the older engine (tdo_v2.engine per-root interprocedural completion) "
                             "instead of the default summary engine")
    parser.add_argument("--summaries", action="store_true",
                        help="(default; kept for compatibility) the summary engine")
    parser.add_argument("--stack-evidence", type=Path, action="append", default=[],
                        help="whole-program stack-switch evidence (ghidra/GhidraV2StackSwitchScan.java) of "
                             "the program or a library it runs with (repeatable): a switch in any of them "
                             "withdraws globals-disjoint-from-stack")
    parser.add_argument("--link", action="append", default=[], metavar="LIBRARY=DLL",
                        help="link the program with the real code of this library (repeatable; design section "
                             "24): its called exports without a model get templates derived from the user's "
                             "prepared Ghidra project (--ghidra-project), cached in --link-cache")
    parser.add_argument("--ghidra-project", type=Path,
                        help="the prepared Ghidra project (.gpr) holding the linked libraries, imported and "
                             "analyzed by the user (tools/bundle_export/README.md)")
    parser.add_argument("--link-folder", default="/libs",
                        help="the project folder holding the libraries (Ghidra's -loader-libraryDestinationFolder)")
    parser.add_argument("--link-cache", type=Path, default=Path.home() / "tdo_link_cache")
    parser.add_argument("--link-refresh", action="store_true",
                        help="derive every linked export again (after re-analyzing a library in Ghidra)")
    parser.add_argument("--link-dry-run", action="store_true",
                        help="report what linking would derive (and use the cache), derive nothing")
    parser.add_argument("--link-max-mem", default="10G", help="Ghidra heap for the linking export and scan")
    parser.add_argument("--binding", action="append", default=[], type=Path,
                        help="a model binding file for this binary's unexported functions (docs 25.20 F)")
    parser.add_argument("--assume-boundary-effects", action="store_true",
                        help="TEST-ONLY special condition: declared source/sink call effects")
    parser.add_argument("--no-model-assumption", dest="model_assumptions_off", action="append", default=[],
                        metavar="LABEL",
                        help="switch off a model assumption: <file id>:<id> a model file declares, or a "
                             "registry model assumption (docs/assumptions.md); entries resting on it are not "
                             "applied (repeatable; also TDO_V2_NO_MODEL_ASSUMPTIONS=a,b)")
    # every engine-wide named assumption comes from the registry (on by default:
    # --no-... or <ENV>=0 turns it off; off by default: --assume-... turns it
    # on; see docs/assumptions.md)
    from tdo_v2.assumptions import switches

    for item in switches():
        parser.add_argument(item.flag, dest=item.parameter, action="store_false" if item.default else "store_true",
                            help=f"{'drop' if item.default else 'take'} the named assumption {item.name}: "
                                 f"{item.statement} (fails when: {item.fails_when})")
    args = parser.parse_args()
    legacy = args.legacy_engine or os.environ.get("TDO_V2_INTERPROCEDURAL") == "legacy"
    if args.physical_records and legacy:
        parser.error("--physical-records requires the summary engine (not --legacy-engine or TDO_V2_INTERPROCEDURAL=legacy)")
    if args.physical_records:
        args.records = True
    args.model_assumptions_off += [item.strip() for item in os.environ.get("TDO_V2_NO_MODEL_ASSUMPTIONS", "").split(",")
                                   if item.strip()]
    if args.model_assumptions_off and legacy:
        parser.error("--no-model-assumption requires the summary engine")
    for item in switches():
        if item.env and os.environ.get(item.env) == "0":
            setattr(args, item.parameter, False)
    if args.assume_boundary_effects:
        print("[run] TEST-ONLY ASSUMPTION: source/sink call effects are declared, not observed")
    from tdo_v2.engine import analyze_frozen_bundle
    from tdo_v2.stack_evidence import assumption_allowed, load_stack_evidence
    from tdo_v2.summary_store import load_binding_file

    evidence = [load_stack_evidence(path) for path in args.stack_evidence]
    if evidence:
        allowed, lines = assumption_allowed(evidence, requested=args.assume_globals_disjoint_from_stack)
        for line in lines:
            print(f"[run] stack evidence: {line}")
    elif args.assume_globals_disjoint_from_stack:
        print("[run] globals-disjoint-from-stack: withdrawal checks the Bundle's functions only "
              "(no whole-program stack evidence given: --stack-evidence)")

    linker = None
    if args.link:
        if args.legacy_engine or args.ghidra_project is None or not args.external_models:
            raise SystemExit("--link needs the summary engine, external models and --ghidra-project")
        sys.path.insert(0, str(REPO / "tools" / "derive_models"))
        from derive_models import derive_library
        from link_provider import GhidraLinkProvider
        from tdo_v2.linking import Linker, LinkTarget

        provider = GhidraLinkProvider(args.ghidra_project, args.link_cache, folder=args.link_folder,
                                      model_dirs=args.model_dir, max_mem=args.link_max_mem,
                                      log=lambda line: print(line, flush=True))
        linker = Linker([LinkTarget.parse(item) for item in args.link], args.link_cache, provider,
                        derive_library, refresh=args.link_refresh, dry_run=args.link_dry_run,
                        log=lambda line: print(line, flush=True))

    generation = args.generation
    print(f"[run] ABI {abi_of(generation)} (boundary argument register)")
    manifest = json.loads((generation / "manifest.json").read_text(encoding="utf-8"))
    names = selection_names(generation)
    by_entry = {}
    for index, row in enumerate(manifest["functions"]):
        entry = json.loads(
            (generation / f"{row['observation_member']}.json").read_text())["entry"]
        key = (entry["space_id"], entry["byte_offset"])
        by_entry[key] = names[index] if index < len(names) else row["id"]

    started = time.time()
    try:
        if not legacy:
            from tdo_v2.summary_engine import analyze_frozen_bundle_with_summaries
            print("[run] interprocedural: callee summaries")
            models = external_models(generation, args.model_dir) if args.external_models else None
            bindings = tuple(load_binding_file(path) for path in args.binding)
            run = analyze_frozen_bundle_with_summaries(
                generation,
                naming_exporter_source=REPO / "ghidra" / "GhidraV2CallNaming.java",
                boundary_provider=boundary_provider(args.assume_boundary_effects,
                                                    abi_of(generation)),
                assume_boundary_call_effects=args.assume_boundary_effects,
                external_models=models,
                pcodeop_models=pcodeop_models(),  # not imported functions: --no-external-models keeps them
                stack_evidence=tuple(evidence),
                linker=linker,
                origin_witnesses=args.witnesses,
                operation_records=args.records,
                physical_memory_records=args.physical_records,
                model_bindings=bindings,
                disabled_model_assumptions=tuple(args.model_assumptions_off),
                **{item.parameter: getattr(args, item.parameter) for item in switches()
                   if item.parameter != "external_models"},
            )
            print(f"[run] assumptions applied: {list(run.assumptions) or 'none'}")
            from tdo_v2.summary_store import ExternalModels, assumption_catalog

            # what each assumption a model file declares states (registry ones: docs/assumptions.md)
            catalog = assumption_catalog(models or ExternalModels(()), *(item.models for item in bindings))
            for label in run.assumptions:
                if label in catalog:
                    _, statement, fails_when = catalog[label]
                    print(f"[run]   {label}: {statement} (fails when: {fails_when})")
            if args.model_assumptions_off:
                print(f"[run] model assumptions switched off: {sorted(set(args.model_assumptions_off))}")
            from tdo_v2.summary_engine import LANE_DIAGNOSTICS
            print(f"[run] lane origins (docs 25.6): {LANE_DIAGNOSTICS}")
            from tdo_v2.relative_memory import INDEX_DIAGNOSTICS, index_addresses
            print(f"[run] index addresses (docs 25.8): {'on' if index_addresses() else 'off'}, "
                  f"index objects {len(INDEX_DIAGNOSTICS['index_objects'])}, "
                  f"seam refusals {INDEX_DIAGNOSTICS['seam_refusals']}")
            if linker is not None:
                for line in linker.report.lines:
                    print(f"[link] {line}")
                for evidence_file in linker.report.evidence_files:
                    print(f"[link] stack evidence: {load_stack_evidence(evidence_file).describe()}")
                counts = {}
                for row in linker.report.rows:
                    counts[row.status] = counts.get(row.status, 0) + 1
                print(f"[link] imports: {counts}")
                # applied = used at some call of this run (its label is among the run's assumptions)
                linked_rows = [row for row in linker.report.rows if row.status in ("derived", "cached")]
                unused = [row.name for row in linked_rows if not any(
                    label.startswith(f"derived-model:{row.file_id}/") for label in run.assumptions)]
                print(f"[link] templates applied in this run: {len(linked_rows) - len(unused)} of {len(linked_rows)}"
                      + (f"; not applied (see refused models): {unused}" if unused else ""))
        else:
            print("[run] legacy engine (per-root interprocedural completion)")
            run = analyze_frozen_bundle(
                generation,
                naming_exporter_source=REPO / "ghidra" / "GhidraV2CallNaming.java",
                boundary_provider=boundary_provider(args.assume_boundary_effects,
                                                    abi_of(generation)),
                include_explanations=False,
                assume_boundary_call_effects=args.assume_boundary_effects,
            )
    except Exception as exc:  # noqa: BLE001
        print("".join(traceback.format_exception(exc)), file=sys.stderr)
        return 2
    print(f"[run] {len(run.roots)} roots in {time.time() - started:.1f}s")
    results: dict[str, dict[str, object]] = {}
    for root in run.roots:
        name = by_entry.get((root.function_space_id, root.function_byte_offset),
                            f"{root.function_byte_offset:#x}")
        row = results.setdefault(name, {"roots": []})
        row["roots"].append({
            "label": root.label, "occurrence": root.occurrence_ordinal,
            "origins": list(root.reached_origin_labels),
            "local": list(root.local_origin_labels),
            "interprocedural": list(root.interprocedural_origin_labels),
            "complete": getattr(root, "is_locally_complete", None),
            "effective": getattr(root, "is_effectively_complete", None),
            **({"witnesses": {key: value for key, value in root.explanation.items() if key != "record"}}
               if args.witnesses and root.explanation else {}),
            **({"record": root.explanation["record"]} if args.records and "record" in root.explanation else {}),
        })
    if args.expected:
        expected = json.loads(args.expected.read_text(encoding="utf-8"))
        cases = expected["cases"]
        if "binaries" in expected:  # the manifest (expected/*.json may be stale)
            cases = [c for c in cases if c["binary"] == args.binary]
        tally = {"PASS": 0, "FAIL": 0, "MISSING": 0}
        for case in cases:
            got = results.get(case["function"])
            anchor = f"{case['anchor']['callee']}.arg{case['anchor']['arg_index']}"
            # 09 manifests: expected/forbidden_sources; 10 UE (v2): data + global sources
            want = case.get("expected_sources",
                            case.get("expected_data_sources", []) + case.get("expected_global_sources", []))
            forbid = case.get("forbidden_sources", case.get("forbidden_data_sources", []))
            if got is None:
                verdict, origins = "MISSING", set()
            else:
                origins = {o for r in got["roots"] if r["label"] == anchor
                           for o in r["origins"]}
                ok = set(want) <= origins and not (set(forbid) & origins)
                verdict = "PASS" if ok else "FAIL"
            tally[verdict] += 1
            print(f"  {case['id']} {verdict:7} got={sorted(origins)} want={want} forbid={forbid}")
            for line in _witness_lines(got, anchor) if args.witnesses and got else ():
                print("      " + line)
            for line in _record_lines(got, anchor) if args.records and got else ():
                print("      " + line)
        print("[run]", tally)
    if args.json:
        # atomically: a failed run leaves no partial artifact (docs 25.30 K1c-3)
        partial = args.json.with_name(args.json.name + ".partial")
        partial.write_text(json.dumps(results, indent=1), encoding="utf-8")
        partial.replace(args.json)
    return 0


def _record_lines(got, anchor, limit=60) -> list:
    """The rendered operation records of a case's roots (docs 25.28)."""
    from tdo_v2.operation_records import render

    lines = []
    for root in got["roots"]:
        if root["label"] == anchor and "record" in root:
            text = render(root["record"]).splitlines()
            lines.extend(text[:limit] + ([f"... {len(text) - limit} more lines (--json)"] if len(text) > limit else []))
    return lines


def _witness_lines(got, anchor) -> list:
    """Text lines for a case's root labels with no debt-free path (docs 25.19)."""
    lines = []
    for root in got["roots"]:
        if root["label"] != anchor or "witnesses" not in root:
            continue
        for label, item in root["witnesses"].get("origin_witnesses", {}).items():
            if item["has_debt_free_path"]:
                continue
            for witness in item["witnesses"]:
                where = (f"{witness['writer']} -> {witness['reader']}" if witness["kind"] == "may_alias"
                         else ", ".join(witness.get("sites", ())))
                why = witness["condition"] or f"(no condition: {witness.get('reason') or 'not an alias transfer'})"
                callee = " (callee)" if witness.get("provenance") == "callee" else ""
                lines.append(f"{label} via {witness['kind']}{callee} {where}: {why}")
            if item["truncated"]:
                lines.append(f"{label}: more witnesses not shown")
    return lines


if __name__ == "__main__":
    sys.exit(main())
