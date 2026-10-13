"""Derive models from a library's own code (design section 23, step 3).

    derive_models.py <library Bundle generation> --library UNREALEDITOR-CORE.DLL \
        --export '??0FString@@QEAA@XZ' [--export ...] --id ue-core-derived -o models/derived/x.json

Analyzes the exported functions' call closure in the library's Bundle once
(``analyze_units(own_library=...)``: functions with an ``internal`` hand model
are cut, the exported targets themselves are kept), under
``relative_memory.ImageBaseTracking`` and with read-only image folding off,
and writes their summaries as a ``"kind": "summary"`` model file
(``summary_templates``). Programs then load it like any model directory
(``run_dfbench --model-dir``); each use reports ``derived-model:...`` and the
assumptions of the derivation run. Functions that cannot be exported are
listed with the reason.

Analysis settings match the summary engine's defaults (Windows x64 home space
0x28, debug-break traps do not return); ``--assume-globals-disjoint-from-stack``
derives under that opt-in assumption too (templates are then applied only in
runs that make it as well).
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from hashlib import sha256
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tools" / "bundle_export"))


def _producer(generation: Path) -> dict:
    """Recorded with the templates (never compared): the engine revision and
    the Bundle's manifest identity."""
    import subprocess

    try:
        revision = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True,
                                  check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "-C", str(REPO), "status", "--porcelain", "--", "src"],
                                    capture_output=True, text=True, check=True).stdout.strip())
    except (OSError, subprocess.CalledProcessError):
        revision, dirty = "unknown", False
    return {"tool": "tools/derive_models", "engine_revision": revision + ("+dirty" if dirty else ""),
            "bundle": generation.name}


def image_ranges(info, space_id: int) -> tuple:
    """(start, end) of every memory block in the image's space -- no layout
    heuristic: a block Ghidra adds (its thread data block) only makes more
    numbers count as image addresses (more refusals, never fewer)."""
    return tuple(sorted((block.start, block.start + block.size) for block in info.blocks
                        if block.space_id == space_id))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("generation", type=Path)
    parser.add_argument("--library", required=True)
    parser.add_argument("--export", action="append", required=True, help="mangled export name (repeat)")
    parser.add_argument("--id", required=True, help="model file id")
    parser.add_argument("--version", type=int, default=1)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--model-dir", action="append", default=[], type=Path)
    parser.add_argument("--assume-globals-disjoint-from-stack", action="store_true")
    args = parser.parse_args(argv)

    import run_dfbench
    from tdo_v2._scope_results import ConstructedFunctionScope
    from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
    from tdo_v2.image_info import load_image_info
    from tdo_v2.integration.configured_bundle import admit_frozen_bundle
    from tdo_v2.integration.observed_function_session import open_observed_function_session
    from tdo_v2 import interprocedural as ip
    from tdo_v2.relative_memory import ImageBaseTracking
    from tdo_v2.summary_templates import build_file

    binding = NamingBindingExpectation(sha256((REPO / "ghidra" / "GhidraV2CallNaming.java").read_bytes()).digest(),
                                       CALL_NAMING_GHIDRA_VERSION)
    units, failures = [], collections.Counter()
    with open_observed_function_session(admit_frozen_bundle(args.generation), naming_binding=binding) as session:
        adapter = session._provider_adapter
        for unit in session._envelope.iter_scoped_functions():
            adapter.collect_function_roles()   # the session protocol: one role collection per unit
            if type(unit.scopes.function) is ConstructedFunctionScope and unit.observation is not None:
                units.append(unit)
            else:
                failures[unit.scopes.function.stage.name] += 1
    info = load_image_info(args.generation)
    models = run_dfbench.external_models(args.generation, args.model_dir)
    pcodeops = run_dfbench.pcodeop_models()
    library = args.library.upper()
    by_key = {ip.function_key(unit.scopes.function.entry): unit for unit in units}
    exports = {}
    for export in info.exports:
        if export.name in args.export:
            exports.setdefault(export.name, ip.function_key_of(export.space_id, export.byte_offset))
    missing = sorted(set(args.export) - set(exports))
    targets = {key for key in exports.values() if key in by_key}
    # the targets' closure, cut at internal models (the targets themselves kept)
    cuts = ip._model_cuts({key: unit for key, unit in by_key.items() if key not in targets},
                          info, models, library, set())
    kept = {key: unit for key, unit in by_key.items() if key not in cuts}
    calls = {key: ip._direct_calls(unit, kept) for key, unit in kept.items()}
    reach, pending = set(), list(targets)
    while pending:
        key = pending.pop()
        if key in reach or key not in kept:
            continue
        reach.add(key)
        pending.extend(calls[key].values())
    # program-wide facts from every function of the library, not only the closure
    globals_disjoint = args.assume_globals_disjoint_from_stack and not ip.program_switches_stack(by_key.values())
    selected = [by_key[key] for key in sorted(reach | set(cuts))]
    ranges = image_ranges(info, units[0].scopes.program.evidence.image_base.space_id)
    print(f"closure {len(reach)} functions + {len(cuts)} cut; image blocks "
          + ", ".join(f"{start:#x}-{end:#x}" for start, end in ranges), flush=True)
    from tdo_v2.image_info import ReadOnlyImage
    from tdo_v2.summary_templates import image_provenance

    image = ReadOnlyImage(args.generation, info)
    space = units[0].scopes.program.evidence.image_base.space_id
    relocates = image_provenance(lambda address, size: image.value(space, address, size),
                                 [(offset, size) for space_id, offset, size in info.relocations if space_id == space])
    tracking = ImageBaseTracking(ranges, relocates)
    with tracking as found:
        results = ip.analyze_units(selected, image_info=info, external_models=models, pcodeop_models=pcodeops,
                                   private_frame_above=0x28, assume_debug_break_traps_do_not_return=True,
                                   assume_globals_disjoint_from_stack=globals_disjoint,
                                   own_library=library, keep_uncut=frozenset(targets))
    rows = [(exports[name], name, [name]) for name in args.export if name in exports]
    raw, refused = build_file(results, rows, file_id=args.id, version=args.version, library=library,
                              external_models=models, pcodeop_models=pcodeops, private_frame_above=0x28,
                              base_dependent=found, traps=True, producer=_producer(args.generation),
                              notes=f"Derived by tools/derive_models from {args.generation.name}.")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(raw, indent=1) + "\n", encoding="utf-8")
    print(f"constants: {len(tracking.proofs[True])} proven image addresses, {len(tracking.proofs[False])} "
          f"fixed numbers, {len(tracking.proofs[None])} not understood (possibly base-dependent)")
    print(f"wrote {len(raw['entries'])} templates to {args.output}")
    for name, reason in sorted(refused.items()):
        print(f"refused {name}: {reason}")
    for name in missing:
        print(f"not exported by the Bundle: {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
