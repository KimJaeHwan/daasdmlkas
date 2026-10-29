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
0x28, debug-break traps do not return). globals-disjoint-from-stack is taken
only with ``--stack-evidence``: a clean whole-program scan of THIS library
(ghidra/GhidraV2StackSwitchScan.java over the analyzed program in the Ghidra
project; ``tdo_v2.stack_evidence``) -- a library Bundle holds a closure, no
evidence about the rest (design section 24.1). Templates derived with it apply
only in runs that make it too; without it they apply in any run.
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

from tdo_v2.resource_limits import analysis_entry  # noqa: E402


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
    from tdo_v2.relative_memory import index_addresses

    return {"tool": "tools/derive_models", "engine_revision": revision + ("+dirty" if dirty else ""),
            "bundle": generation.name, "index_addresses": index_addresses()}


def image_ranges(info, space_id: int) -> tuple:
    """(start, end) of every memory block in the image's space -- no layout
    heuristic: a block Ghidra adds (its thread data block) only makes more
    numbers count as image addresses (more refusals, never fewer)."""
    return tuple(sorted((block.start, block.start + block.size) for block in info.blocks
                        if block.space_id == space_id))


_DEFAULT = object()


@analysis_entry
def derive_library(generation: Path, library: str, export_names, *, file_id: str, version: int = 1,
                   model_dirs=(), models=None, pcodeops=_DEFAULT, stack_evidence=(), private_frame_above: int = 0x28,
                   traps: bool = True, assume_globals_disjoint: bool = True, direction_flag: bool = False,
                   import_slots: bool = False, per_export: bool = False, log=print,
                   entry_values_not_frame: bool = True, same_result: bool = False,
                   accessor_separate: bool = False, opaque_no_stack: bool = True, pre_escape: bool = True,
                   registered_handlers: bool = True, accessor_private_state: bool = False,
                   model_assumptions_off=(), catalog_models=(), opaque_restores_sp: bool = True):
    """(model file dict, {export name: refusal reason}, export names the
    Bundle does not export) -- the templates of ``export_names`` of the
    library Bundle at ``generation``, derived with the given analysis
    settings (those of the program run that will apply them: linking passes
    its own; ``summary_templates.refusal`` compares them) and stack evidence.
    ``models`` / ``pcodeops``: the ``ExternalModels`` and p-code op models to
    derive with (else those of the Bundle's language in models/external and
    ``model_dirs``, and models/pcodeops; ``pcodeops=None`` is none at all).
    ``assume_globals_disjoint``: whether the run that applies the templates
    makes globals-disjoint-from-stack (taken only with clean evidence of this
    library); ``direction_flag``: direction-flag-clear (off by default, as
    before: the templates then do not rest on it).
    ``per_export``: each export analyzed alone -- its own closure and the
    cut functions it reaches -- and returned as its own file ({name: file
    dict} in place of the one file): a template then never depends on which
    other exports were derived with it (linking caches per export).
    ``model_assumptions_off``: model assumptions switched off
    (``interprocedural.analyze_units`` ``disabled_model_assumptions``);
    ``catalog_models``: more model files declaring labels (the program run's
    bindings, ``assumption_declarations``)."""
    import run_dfbench
    from tdo_v2._scope_results import ConstructedFunctionScope
    from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
    from tdo_v2.image_info import ReadOnlyImage, load_image_info
    from tdo_v2.integration.configured_bundle import admit_frozen_bundle
    from tdo_v2.integration.observed_function_session import open_observed_function_session
    from tdo_v2 import interprocedural as ip
    from tdo_v2.assumptions import disabled
    from tdo_v2.relative_memory import ImageBaseTracking
    from tdo_v2.stack_evidence import assumption_allowed, load_stack_evidence
    from tdo_v2.summary_templates import build_file, image_provenance

    generation = Path(generation)
    if not entry_values_not_frame:
        private_frame_above = 0   # the home-space extension is inactive without its base assumption
    binding = NamingBindingExpectation(sha256((REPO / "ghidra" / "GhidraV2CallNaming.java").read_bytes()).digest(),
                                       CALL_NAMING_GHIDRA_VERSION)
    units, failures = [], collections.Counter()
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        adapter = session._provider_adapter
        for unit in session._envelope.iter_scoped_functions():
            adapter.collect_function_roles()   # the session protocol: one role collection per unit
            if type(unit.scopes.function) is ConstructedFunctionScope and unit.observation is not None:
                units.append(unit)
            else:
                failures[unit.scopes.function.stage.name] += 1
    info = load_image_info(generation)
    if models is None:
        models = run_dfbench.external_models(generation, model_dirs)
    if pcodeops is _DEFAULT:
        pcodeops = run_dfbench.pcodeop_models()
    library = library.upper()
    names = list(export_names)
    by_key = {ip.function_key(unit.scopes.function.entry): unit for unit in units}
    exports = {}
    for export in info.exports:
        if export.name in names:
            exports.setdefault(export.name, ip.function_key_of(export.space_id, export.byte_offset))
    missing = sorted(set(names) - set(exports))
    space = units[0].scopes.program.evidence.image_base.space_id
    ranges = image_ranges(info, space)
    log("image blocks " + ", ".join(f"{start:#x}-{end:#x}" for start, end in ranges))
    image = ReadOnlyImage(generation, info)
    relocates = image_provenance(lambda address, size: image.value(space, address, size),
                                 [(offset, size) for space_id, offset, size in info.relocations if space_id == space],
                                 language_id=units[0].scopes.program.evidence.translation_namespace.language_id)
    evidence = [load_stack_evidence(path) for path in stack_evidence]
    sha = units[0].scopes.program.evidence.executable_sha256.hex()
    globals_disjoint, lines = assumption_allowed(evidence, requested=assume_globals_disjoint and bool(evidence),
                                                 require_for=sha)
    for line in lines:
        log(f"stack evidence: {line}")
    producer = {**_producer(generation), "stack_evidence": [
        {"file": item.digest, "summary": item.describe()} for item in evidence]}

    def derive(group):
        """build_file's (file dict, refused) for the exports ``group``."""
        targets = {exports[name] for name in group if exports[name] in by_key}
        # the targets' closure, cut at internal models (the targets themselves kept)
        # (switched off as ``analyze_units`` below will find them)
        off = disabled(globals_disjoint=globals_disjoint, readonly_image=False, direction_flag=direction_flag,
                       entry_values_not_frame=entry_values_not_frame, home_space=bool(private_frame_above),
                       opaque_no_stack=opaque_no_stack, traps=traps, import_slots=import_slots, pre_escape=pre_escape,
                       same_result=same_result, accessor_separate=accessor_separate,
                       accessor_private_state=accessor_private_state, registered_handlers=registered_handlers,
                       model_assumptions_off=model_assumptions_off, opaque_restores_sp=opaque_restores_sp)
        cuts = ip._model_cuts({key: unit for key, unit in by_key.items() if key not in targets},
                              info, models, library, off)
        kept = {key: unit for key, unit in by_key.items() if key not in cuts}
        reach, reached_cuts, pending = set(), set(), list(targets)
        while pending:
            key = pending.pop()
            if key in cuts:
                reached_cuts.add(key)
            if key in reach or key not in kept:
                continue
            reach.add(key)
            pending.extend(ip._direct_calls(kept[key], by_key).values())
        if not per_export:
            reached_cuts = set(cuts)   # as before (the one shipped file)
        selected = [by_key[key] for key in sorted(reach | reached_cuts)]
        log(f"{', '.join(group) if per_export else 'closure'}: {len(reach)} functions + {len(reached_cuts)} cut")
        tracking = ImageBaseTracking(ranges, relocates)
        with tracking as found:
            results = ip.analyze_units(selected, image_info=info, external_models=models, pcodeop_models=pcodeops,
                                       private_frame_above=private_frame_above,
                                       assume_debug_break_traps_do_not_return=traps,
                                       assume_direction_flag_clear=direction_flag,
                                       assume_globals_disjoint_from_stack=globals_disjoint,
                                       assume_import_slots_hold_exports=import_slots,
                                       assume_entry_values_not_frame=entry_values_not_frame,
                                       assume_opaque_callees_leave_no_stack_addresses=opaque_no_stack,
                                       assume_opaque_callees_restore_stack_pointer=opaque_restores_sp,
                                       assume_pre_escape_values_not_frame=pre_escape,
                                       assume_same_result_functions=same_result,
                                       assume_accessor_result_separate=accessor_separate,
                                       assume_registered_handlers_not_observed=registered_handlers,
                                       assume_accessor_private_state=accessor_private_state,
                                       disabled_model_assumptions=tuple(model_assumptions_off),
                                       assumption_declarations=tuple(catalog_models),
                                       own_library=library, keep_uncut=frozenset(targets))
        log(f"constants: {len(tracking.proofs[True])} proven image addresses, {len(tracking.proofs[False])} "
            f"fixed numbers, {len(tracking.proofs[None])} not understood (possibly base-dependent)")
        rows = [(exports[name], name, [name]) for name in group]
        return build_file(results, rows, file_id=file_id, version=version, library=library,
                          catalog_models=tuple(catalog_models),
                          external_models=models, pcodeop_models=pcodeops,
                          private_frame_above=private_frame_above, base_dependent=found, traps=traps,
                          producer=producer, notes=f"Derived by tools/derive_models from {generation.name}.")

    present = [name for name in names if name in exports]
    if not per_export:
        raw, refused = derive(present)
        return raw, refused, missing
    files, refused = {}, {}
    from tdo_v2.summary_templates import Refusal

    from tdo_v2.resource_limits import run_exhausted

    for name in present:
        if run_exhausted():   # the run's budget ran out: no further derivation (retried next run)
            refused[name] = Refusal("run budget exhausted", "transient")
            continue
        if exports[name] not in by_key:   # exported, but its function was not admitted
            refused[name] = Refusal("not analyzed", "infrastructure")
            continue
        try:
            raw, refusals = derive([name])
        except MemoryError:   # the process state: the run fails, never one export
            raise
        except Exception as error:  # noqa: BLE001 -- this export only; never stored by linking
            refused[name] = Refusal(f"derivation failed: {type(error).__name__}: {error}", "transient")
            continue
        refused.update(refusals)
        if raw["entries"]:
            files[name] = raw
    return files, refused, missing


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split(chr(10) + chr(10))[0])
    parser.add_argument("generation", type=Path)
    parser.add_argument("--library", required=True)
    parser.add_argument("--export", action="append", required=True, help="mangled export name (repeat)")
    parser.add_argument("--id", required=True, help="model file id")
    parser.add_argument("--version", type=int, default=1)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--model-dir", action="append", default=[], type=Path)
    parser.add_argument("--stack-evidence", action="append", default=[], type=Path,
                        help="whole-program stack-switch evidence of the library (and others it runs with)")
    parser.add_argument("--private-frame-above", type=lambda text: int(text, 0), default=0x28,
                        help="as the program run that applies the templates (Win64 home space: 0x28; none: 0)")
    parser.add_argument("--no-assume-entry-values-not-frame", dest="entry_values_not_frame", action="store_false",
                        help="derive without the entry-value/frame assumption (also disables its home-space extension)")
    parser.add_argument("--no-traps", dest="traps", action="store_false",
                        help="derive without debug-break-traps-do-not-return")
    parser.add_argument("--assume-same-result-functions", dest="same_result", action="store_true",
                        help="derive under same-result-functions (docs 25.20)")
    parser.add_argument("--assume-accessor-result-separate", dest="accessor_separate", action="store_true",
                        help="derive under accessor-result-separate (docs 25.20)")
    parser.add_argument("--no-assume-pre-escape-values-not-frame", dest="pre_escape", action="store_false",
                        help="derive without pre-escape-values-do-not-address-the-new-frame (docs 25.77)")
    parser.add_argument("--no-model-assumption", dest="model_assumptions_off", action="append", default=[],
                        metavar="LABEL", help="derive with this model assumption switched off (repeat)")
    args = parser.parse_args(argv)
    raw, refused, missing = derive_library(
        args.generation, args.library, args.export, file_id=args.id, version=args.version,
        model_dirs=args.model_dir, stack_evidence=args.stack_evidence,
        private_frame_above=args.private_frame_above, traps=args.traps, same_result=args.same_result,
        accessor_separate=args.accessor_separate, entry_values_not_frame=args.entry_values_not_frame,
        model_assumptions_off=tuple(args.model_assumptions_off), pre_escape=args.pre_escape)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(raw, indent=1) + chr(10), encoding="utf-8")
    print(f"wrote {len(raw['entries'])} templates to {args.output}")
    for name, reason in sorted(refused.items()):
        print(f"refused {name}: {reason}")
    for name in missing:
        print(f"not exported by the Bundle: {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
