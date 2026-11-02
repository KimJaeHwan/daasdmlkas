"""Premise recording completeness per switch (Stage 2b-P P-c5, docs 25.91;
design ``.census6/design_premise_2bp_r5.md`` D).

For a registry switch S: one run with every switch at its default (ON; a
default-off switch S and the switches it needs are turned on for it) and one
with S off. Every claim that changes must list S in the ON run's UNPADDED
support of that claim (recorded uses and producer dependencies only,
``producer_support`` / ``return_relations.certificate_supports``):

* data claims -- a function's summary, its normalized graph and alias facts
  (the semantic encoding, without the policy inputs or use records), its
  admitted call effects, its published roots -- in its producer closure;
* its continuation certificate (status, closure, which exits are proven) in
  the continuation support; its exits' SP deltas in the SP support.

Where it does not, S's padding cannot be removed yet: the row is "missing".
The published (padded) set is counted alongside. ``external-models`` is
selected by a premise of a loaded external model file (an entry, its
declarations, a binding to it) -- what switching it off withdraws.

Withdrawal recomputes everything (a fresh OFF run, design r4 answer 4): the
invalidation SELECTION is checked -- every changed claim selected (= not
missing), selected-unchanged counted (over-selection is sound) -- and a
function only the OFF run has must be reached by a selected ON function
(else "off-only unattributed"). Rejection of stale models / templates resting
on S: ``tests/intra/test_premise_acceptance.py``.

usage: premise_acceptance.py GENERATION [--switch NAME ...] [--forward 0|1]
       [--binding FILE ...] [--out FILE]
A measurement, not the default gate (design r5 D5).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
for path in (REPO / "src", REPO / "tools" / "bundle_export", REPO / "tools" / "graph_fidelity"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

DATA_CLAIMS = ("summary", "graph", "effects", "roots")
CLAIMS = (*DATA_CLAIMS, "continuation", "sp")
# the accessor switches are measured in one configuration: all three on
# (a binding's accessor model needs every policy it declares), then only the
# measured one off
ACCESSOR = ("same-result-functions", "accessor-result-separate", "accessor-private-state")
PREREQUISITES = {name: ACCESSOR for name in ACCESSOR}


def _graph(normalized):
    """The normalized function's semantic encoding without what only feeds
    or reports premises: the policy switches in force and the use records
    (``premise_uses`` is excluded by the snapshot contract)."""
    from semantic_snapshot import _digest, encode

    encoded = encode(normalized)
    if isinstance(encoded, dict):
        encoded = {key: value for key, value in encoded.items()
                   if not (key.startswith(("assumes_", "assumed_")) and key != "assumed_call_effects")}
    return _digest(encoded)


def claims(results: dict, certificates: dict, roots=()) -> dict:
    """key -> claim kind -> a comparable value."""
    from semantic_snapshot import _digest, encode

    by_function: dict = {}
    for root in roots:
        by_function.setdefault(f"{root.function_space_id:x}:{root.function_byte_offset:x}", []).append(root)
    found = {}
    for key, item in results.items():
        certificate = certificates.get(key)
        found[key] = {
            "summary": _digest(encode(item.summary)) if item.summary is not None else None,
            "graph": _graph(item.normalized),
            "effects": _digest(encode(item.proven)),
            "roots": _digest(encode(sorted(by_function.get(key, ()),
                                           key=lambda row: (row.label, row.occurrence_ordinal)))),
            "continuation": None if certificate is None else (
                certificate.status, certificate.closed,
                tuple(sorted((row.key, row.kind, row.proven) for row in certificate.exits))),
            "sp": None if certificate is None else tuple(sorted((row.key, row.sp_delta) for row in certificate.exits)),
        }
    return found


def code_reader(readonly_image, results):
    """Instruction bytes for the AArch64 PAC scan, read from the Bundle's
    sealed image (None when the run has none)."""
    if readonly_image is None:
        return None
    spaces = {instruction.address.space_id for item in results.values() if item.unit.observation is not None
              for instruction in item.unit.observation.instructions}
    if len(spaces) != 1:
        return None
    (space,) = spaces

    def read(address, size):
        value = readonly_image.value(space, address, size)
        return None if value is None else value.to_bytes(size, "little")
    return read


def certificates_of(results: dict, reader=None) -> dict:
    from tdo_v2.call_seeds import _operation_key
    from tdo_v2.return_relations import PAC_SPEC_12_0_4, program_certificates

    functions = {}
    for key, item in results.items():
        targets = dict(item.calls)
        for instruction in item.unit.observation.instructions if item.unit.observation is not None else ():
            for index, operation in enumerate(instruction.operations):
                if operation.opcode in ("CALL", "CALLIND", "BRANCH", "BRANCHIND") and instruction.flow.is_call:
                    targets.setdefault(_operation_key(instruction.address, index, operation.opcode), None)
        functions[key] = (item.normalized, item.unit.observation, item.unit.scopes, targets, item.summary,
                          item.inherited_assumptions)
    # (the Bundles are exported by Ghidra 12.0.4: its pinned PAC table)
    return program_certificates(functions, code_reader=reader, pac_spec=PAC_SPEC_12_0_4)


def withdrawn_by(name: str, models, bindings=()) -> frozenset | None:
    """The premise ids switching ``name`` off withdraws, when it is not a
    single label (``external-models``: every loaded external model file's
    entries and declarations, and every binding with its bound models --
    the OFF run takes neither); None: the label itself."""
    if name != "external-models":
        return None
    found = set()
    for files in (() if models is None else models.files,
                  *(getattr(binding.models, "files", ()) for binding in bindings)):
        for item in files:
            found.update(entry.label for entry in item.entries)
            found.update(label for label, _, _ in item.declares)
    for binding in bindings:
        found.update(f"bound-model:{binding.binding_id}@{rva:#x}#{binding.digest[:12]}" for rva, _, _ in binding.rows)
    return frozenset(found)


def selected(label: str, premises, withdrawn=None) -> bool:
    if withdrawn is not None:
        wrapper = "accessor-state-preserved-by:"
        return any(item.id in withdrawn or (item.id.startswith(wrapper) and item.id[len(wrapper):] in withdrawn)
                   for item in premises)
    return any(item.id == label for item in premises)


def check(label: str, on: dict, off: dict, supports: dict, producers: dict, withdrawn=None,
          off_results=None) -> dict:
    """``supports``: key -> CertificateSupport of the ON run; ``producers``:
    key -> ProducerClosure of the ON run; ``off_results``: the OFF run's
    results (functions only it has must be reached by a selected one)."""
    changed, missing, padded_only, over = [], [], [], 0
    chosen = set()
    for key in sorted(on):
        before, after = on[key], off.get(key)
        support = supports.get(key)
        for kind in CLAIMS:
            if kind in DATA_CLAIMS:
                unpadded = producers[key].premises if key in producers else frozenset()
                published = producers[key].published if key in producers else frozenset()
            elif kind == "continuation":
                unpadded = support.continuation_unpadded.premises if support else frozenset()
                published = support.continuation.premises if support else frozenset()
            else:
                unpadded = support.sp_unpadded.premises if support and support.sp_unpadded else frozenset()
                published = support.sp.premises if support and support.sp else frozenset()
            hit = selected(label, unpadded, withdrawn)
            if hit:
                chosen.add(key)
            now = None if after is None else after[kind]
            if before[kind] == now:
                over += hit
                continue
            changed.append((key, kind))
            if not hit:
                missing.append((key, kind))
                if selected(label, published, withdrawn):
                    padded_only.append((key, kind))
    # a function only the OFF run has: reached from a selected ON function
    # through the OFF run's call / multi-call edges (transitively)
    edges = {caller: {*item.calls.values(), *(member for members in item.multi_calls.values() for member in members)}
             for caller, item in (off_results or {}).items()}
    reached, pending = set(), [key for key in chosen if key in edges]
    while pending:
        caller = pending.pop()
        for target in edges.get(caller, ()):
            if target not in reached:
                reached.add(target)
                pending.append(target)
    unattributed = [key for key in sorted(set(off) - set(on)) if key not in reached]
    by_kind: dict = {}
    for _, kind in changed:
        by_kind[kind] = by_kind.get(kind, 0) + 1
    return {"changed": len(changed), "changed_by_kind": by_kind, "missing": len(missing),
            "covered_only_by_padding": len(padded_only), "selected_unchanged": over,
            "off_only": len(set(off) - set(on)), "off_only_unattributed": unattributed[:40],
            "missing_rows": missing[:60]}


def run(generation: Path, options: dict, models, bindings=()):
    import run_dfbench
    from tdo_v2 import summary_engine

    captured = {}
    original = summary_engine.analyze_units

    def capture(*args, **kwargs):
        captured["results"] = original(*args, **kwargs)
        captured["readonly_image"] = kwargs.get("readonly_image")
        return captured["results"]

    summary_engine.analyze_units = capture
    try:
        engine_run = summary_engine.analyze_frozen_bundle_with_summaries(
            generation, naming_exporter_source=REPO / "ghidra" / "GhidraV2CallNaming.java",
            boundary_provider=run_dfbench.boundary_provider(False, run_dfbench.abi_of(generation)),
            external_models=models, pcodeop_models=run_dfbench.pcodeop_models(), model_bindings=tuple(bindings),
            **options)
    finally:
        summary_engine.analyze_units = original
    return engine_run, captured.get("results", {}), captured.get("readonly_image")


def main() -> int:
    import run_dfbench
    from tdo_v2.assumptions import switches
    from tdo_v2.premises import PremiseResolver
    from tdo_v2.producer_support import producer_supports
    from tdo_v2.return_relations import certificate_supports
    from tdo_v2.summary_store import load_binding_file

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("generation", type=Path)
    parser.add_argument("--switch", action="append", default=[])
    parser.add_argument("--forward", choices=("0", "1"), default=os.environ.get("TDO_V2_FORWARD", "1"))
    parser.add_argument("--binding", action="append", default=[], type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    os.environ["TDO_V2_FORWARD"] = args.forward

    rows = {item.name: item for item in switches() if item.parameter}
    unknown = [name for name in args.switch if name not in rows]
    if unknown:
        parser.error(f"not a switch with a run parameter: {', '.join(unknown)}")
    chosen = [rows[name] for name in args.switch] if args.switch else [item for item in rows.values()
                                                                      if item.default]
    defaults = {item.parameter: item.default for item in rows.values() if item.parameter != "external_models"}
    models = run_dfbench.external_models(args.generation)
    bindings = tuple(load_binding_file(path) for path in args.binding)
    report = {"generation": str(args.generation), "forward": args.forward,
              "bindings": [{"path": str(item), "digest": binding.digest} for item, binding in
                           zip(args.binding, bindings)],
              "switches": {}}
    baselines: dict = {}
    for item in chosen:
        # the ON baseline: defaults, with a default-off S (and what it needs) on
        base = dict(defaults)
        for name in (item.name, *PREREQUISITES.get(item.name, ())):
            if rows[name].parameter != "external_models":
                base[rows[name].parameter] = True
        token = tuple(sorted(base.items()))
        if token not in baselines:
            started = time.time()
            engine_run, results, image = run(args.generation, base, models, bindings)
            resolver = PremiseResolver(model_sets=() if models is None else (models,), bindings=bindings,
                                       pcodeop_models=tuple(run_dfbench.pcodeop_models() or ()))
            reader = code_reader(image, results)
            certificates = certificates_of(results, reader)
            supports = certificate_supports(certificates, results, resolver, run_bridge=engine_run.assumptions)
            _, producers = producer_supports(results, resolver, run_bridge=engine_run.assumptions)
            # (that the ON run really exercised the accessor policies: its same-result atoms)
            atoms = sum(1 for result in results.values() if getattr(result.normalized, "same_result_uses", ()))
            baselines[token] = (claims(results, certificates, engine_run.roots), supports, producers, reader,
                                resolver.identity, round(time.time() - started, 1), len(results), atoms)
        on, supports, producers, reader, identity, seconds, count, accessor_atoms = baselines[token]
        started = time.time()
        options, off_models, off_bindings = dict(base), models, bindings
        if item.parameter == "external_models":
            off_models, off_bindings = None, ()   # (a binding needs the run's models: withdrawn with them)
        else:
            options[item.parameter] = False
        off_run, off_results, _ = run(args.generation, options, off_models, off_bindings)
        off = claims(off_results, certificates_of(off_results, reader), off_run.roots)
        found = check(item.name, on, off, supports, producers, withdrawn_by(item.name, models, bindings),
                      off_results)
        report["switches"][item.name] = {**found, "functions": count, "resolver": identity,
                                         "accessor_atoms": accessor_atoms,
                                         "on_seconds": seconds, "seconds": round(time.time() - started, 1),
                                         "baseline": {key: value for key, value in base.items() if value}}
        print(f"{item.name}: changed {found['changed']} {found['changed_by_kind']}, missing {found['missing']} "
              f"(padding covers {found['covered_only_by_padding']}), selected-unchanged "
              f"{found['selected_unchanged']}, off-only {found['off_only']} "
              f"(unattributed {len(found['off_only_unattributed'])})", flush=True)
    if args.out:
        args.out.write_text(json.dumps(report, indent=1, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
