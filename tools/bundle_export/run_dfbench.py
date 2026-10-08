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


def external_models(generation: Path):
    """Declared models (models/external) for this Bundle's language and ABI."""
    from tdo_v2.summary_store import load_external_models

    return load_external_models(sorted((REPO / "models" / "external").glob("*.json")),
                                LANGUAGES[abi_of(generation)], abi_of(generation))


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
    parser.add_argument("--legacy-engine", action="store_true",
                        help="the older engine (tdo_v2.engine per-root interprocedural completion) "
                             "instead of the default summary engine")
    parser.add_argument("--summaries", action="store_true",
                        help="(default; kept for compatibility) the summary engine")
    parser.add_argument("--assume-boundary-effects", action="store_true",
                        help="TEST-ONLY special condition: declared source/sink call effects")
    parser.add_argument("--no-assume-globals-not-stack", dest="assume_globals_not_stack",
                        action="store_false",
                        help="drop the named assumption (summary engine, on by default): constant "
                             "addresses never alias the stack; it is withdrawn automatically when a "
                             "function switches stacks. Use for firmware / custom static stacks")
    parser.add_argument("--no-external-models", dest="external_models", action="store_false",
                        help="do not apply the declared models of imported functions "
                             "(models/external/*.json; each one used is a named assumption)")
    parser.add_argument("--no-assume-readonly-image", dest="assume_readonly_image",
                        action="store_false",
                        help="drop the named assumption (summary engine, on by default): read-only "
                             "image memory keeps its image value (section permissions from the binary; "
                             "no VirtualProtect-style rewriting at run time). Use for packed or "
                             "protected binaries")
    args = parser.parse_args()
    if os.environ.get("TDO_V2_ASSUME_READONLY_IMAGE") == "0":
        args.assume_readonly_image = False
    if os.environ.get("TDO_V2_EXTERNAL_MODELS") == "0":
        args.external_models = False
    if os.environ.get("TDO_V2_ASSUME_GLOBALS_NOT_STACK") == "0":
        args.assume_globals_not_stack = False
    if args.assume_boundary_effects:
        print("[run] TEST-ONLY ASSUMPTION: source/sink call effects are declared, not observed")
    from tdo_v2.engine import analyze_frozen_bundle

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
        legacy = args.legacy_engine or os.environ.get("TDO_V2_INTERPROCEDURAL") == "legacy"
        if not legacy:
            from tdo_v2.summary_engine import analyze_frozen_bundle_with_summaries
            print("[run] interprocedural: callee summaries")
            run = analyze_frozen_bundle_with_summaries(
                generation,
                naming_exporter_source=REPO / "ghidra" / "GhidraV2CallNaming.java",
                boundary_provider=boundary_provider(args.assume_boundary_effects,
                                                    abi_of(generation)),
                assume_boundary_call_effects=args.assume_boundary_effects,
                assume_globals_disjoint_from_stack=args.assume_globals_not_stack,
                external_models=external_models(generation) if args.external_models else None,
                assume_readonly_image_constant=args.assume_readonly_image,
            )
            print(f"[run] assumptions applied: {list(run.assumptions) or 'none'}")
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
            if got is None:
                verdict, origins = "MISSING", set()
            else:
                origins = {o for r in got["roots"] if r["label"] == anchor
                           for o in r["origins"]}
                ok = set(case["expected_sources"]) <= origins and \
                    not (set(case["forbidden_sources"]) & origins)
                verdict = "PASS" if ok else "FAIL"
            tally[verdict] += 1
            print(f"  {case['id']} {verdict:7} got={sorted(origins)} "
                  f"want={case['expected_sources']} forbid={case['forbidden_sources']}")
        print("[run]", tally)
    if args.json:
        args.json.write_text(json.dumps(results, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
