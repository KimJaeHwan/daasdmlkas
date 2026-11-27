"""Semantic snapshots: everything an analysis run decides, for behavior-
preserving refactors (docs 25.30, step A-5 phase 0). WSL.

usage:
  semantic_snapshot.py dump <generation> <out.json.gz> [--config default|off|accessor|legacy] [--binding FILE]
  semantic_snapshot.py compare <a.json.gz> <b.json.gz>
  semantic_snapshot.py manifest <directory>            # check every expected artifact is present and whole

``dump`` runs the summary engine as ``run_dfbench`` does (boundary table,
models, switches of the configuration), capturing the ``analyze_units``
results, and serializes per function: the normalized function (every field
but its inputs), the summary, every other ``AnalyzedFunction`` field; per
root: identity, root nodes, local / effective completeness, origins,
explanation; run level: assumptions, failed functions, lane / index
diagnostics; and input digests. The serializer walks values explicitly and
raises on any type it does not handle; the top-level types' fields are a
coverage contract (a field neither encoded nor excluded with a reason fails
the dump). Sequences keep order and duplicates; only sets / frozensets and
dicts with non-string keys are sorted (by their encoded form).

``compare`` reports, per section, the first differing path; exit status 1 on
any difference, 2 on a missing / truncated / failed artifact.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
from contextvars import ContextVar
import dataclasses
import enum
import gzip
import hashlib
import json
import os
import sys
import time
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tools" / "bundle_export"))

SNAPSHOT_VERSION = 1

# -- coverage contract ----------------------------------------------------------
# type name -> (encoded fields, {excluded field: reason}); every dataclass field
# of these types must be in one of the two
CONTRACT = {
    "LocalReadPlan": (None, {"_proof": "process-local derivation authority and original input pins;"
                                         " public local read byte ports remain encoded"}),
    "GuardedImagePlan": (None, {"_proof": "process-local derivation authority; original input identities"
                                             " are pinned, public alternatives remain encoded"}),
    "LoopMemoryPlan": (None, {"_proof": "process-local derivation authority and immutable input pins;"
                                          " public family/access evidence is encoded, never re-authorized by JSON"}),
    "NormalizedFunction": (None, {"document": "input (the function document)",
                                  "scopes": "input (scope bundle)",
                                  "forward_inputs": "forward-on derivation inputs (docs 25.33 F4a); None when off",
                                  "address_atom_origins": "paired comparison diagnostics for address expressions",
                                  "call_clobber_contract": "inputs of the call-clobber rows (docs 25.84); the rows,"
                                                           " debts and roots they decide remain encoded",
                                  "premise_uses": "2b-P use records (docs 25.91): which named assumptions the"
                                                  " encoded decisions used -- reporting, checked by tests"}),
    "UnresolvedNormalizedFunction": (None, {"scopes": "input (scope bundle)"}),
    "ObservedControlGraph": (None, {"observation": "original validated input; digest and complete CFG remain encoded"}),
    "ObservedFunctionAdmissionFailure": (None, {"unit": "refused input; sealed member identity and reason remain encoded"}),
    "AnalyzedFunction": (None, {
        "unit": "input (the scoped unit)",
        "normalization_options": "frozen replay inputs; effects/graph outputs are encoded separately",
        "normalization_context": "runtime policy/reader inputs, not a portable analysis output",
        "summary_inputs": "original control-cut derivation inputs; summary outputs remain encoded",
        "allocation_models": "exact original model/symbol bindings; lifecycle verdicts remain encoded",
        "allocation_contracts": "opt-in labelled lifecycle input contracts, not analysis outputs",
        "replay_feedback": "captured alias/extent feedback inputs; final effects/conditions are encoded",
        "activation_witness": "original caller/callee input pins; context graph and preserved spans remain encoded",
        "activation_inputs": "identity-based invalidation pins of the original inputs",
        "consumed": "2b-P exact producer instances (analysis objects); the effects they produced remain encoded",
        "entry_relations": "physical entry overlay pins exact analysis instances; original state roots remain encoded",
        "multi_candidates": "U2a control-context edges (reporting only); multi_calls remains encoded",
        "vetoed_models": "B' declined model cuts' labels (reporting only); EngineRun.control_sites remains encoded",
    }),
    "FunctionSummary": (None, {"premise_uses": "2b-P use records (docs 25.91) -- reporting, checked by tests"}),
    "ProvenCallEffect": (None, {}),
    "RootSlice": (None, {}),
    "EngineRun": (None, {"supports": "2b-P premise report (docs 25.91): which premises the encoded results"
                                      " rest on -- reporting, checked by tests",
                         "diagnostics": "opt-in per-root blocker diagnostics (root_diagnostics) -- reporting"
                                        " only, built after the results; checked by tests"}),
}


# fields added after the first baselines: omitted while at this value, so
# older snapshots stay comparable (a non-default value is encoded and differs)
ADDED_FIELDS = {
    "ObservedTerminalMemoryState": {"is_exit": True},
    "ReadSourcePart": {"writer": None},
    "LocalReadFrom": {"complete": True},
    "EngineRun": {"failed_functions": (), "control_contexts": (), "control_exemptions": (), "fault_report": (),
                  "control_sites": (), "admission_failures": (), "refused_control_graphs": ()},
    # U2a (docs 25.93): control obligations, conditional bindings
    "LocalCompleteness": {"control_obligations": (), "conditional_roots": 0},
    "AnalyzedFunction": {"failure_detail": "", "superseded": None, "multi_calls": {}, "activations": {},
                         "fault_decisions": (),
                         "call_memory_decisions": (), "activation_rejections": {}, "allocation_lifetimes": (),
                         "lifetime_models": ()},
    "NormalizedFunction": {"activation_entry": None, "forward_memory_proofs": (), "forward_memory_requires": (),
                           "address_atom_origins": (),
                           "load_value_proofs": (), "nonstack_spans": frozenset(), "intrinsic_refinements": (),
                           "assumes_opaque_callees_restore_stack_pointer": True,
                           "fault_cuts": (), "fault_reachable": False,
                           # (U2b, docs 25.95: conditional summaries)
                           "control_exempt": (), "site_reachable": False, "callee_support": ()},
    "RootSlice": {"inherited_incomplete": False},
    "UnresolvedNormalizedFunction": {"assumes_opaque_callees_restore_stack_pointer": True, "observed_control": None},
    "CallMemoryDecision": {"evidence": ()},
    "MemoryGraphBindings": {"transfers": (), "transfer_nodes": (), "loop_memory": None, "image_reads": None,
                            "local_reads": None},
    "LoopMemoryPlan": {"read_from": ()},
    "LoopMemoryGraph": {"read_from_nodes": (), "read_from_source_nodes": ()},
    "LoopMemoryReadFrom": {"requires_backedge": False},
    # (fields of the forward-memory / expression branch, 2026-10-23..26)
    "FunctionSummary": {"address_relations": (), "independent_delta_proofs": (),
                        # (the fault premise, F1: off by default)
                        "fault_outcomes": (), "fault_references": (), "fault_reachable": False,
                        # (U2b, docs 25.95: conditional summaries)
                        "unknown_transfers": (), "control_support": (), "site_reachable": False},
    "LocalMemorySsaResult": {"call_register_snapshots": (), "flow_edges": (),
                             "call_state_nodes": (), "call_memory_states": ()},
    "SummaryRun": {"literal": None},
    "ProvenRunEffect": {"literal": None},
    "ProvenMemoryRun": {"literal": None},
    "AnchoredSpan": {"index": None},
    "CallProvenance": {"memory_sources": {}},
    # (the owner's independent register-delta proofs, semantics 25-28): provenance
    # fields -- the deltas / restoration they justify remain encoded
    "ProvenCallEffect": {"register_delta_proofs": (), "control_sites": ()},
    "NodeRecord": {"semantic_identity": None},
}

# fields renamed after the first baselines: encoded under the old name as the
# old value, so older snapshots stay comparable -- (old name, projection).
# ProvenCallEffect.stack_restoration (docs 25.85) replaced restores_stack:
# the snapshot compares its boolean projection (restored = PROVEN), not the
# DISPROVEN / UNKNOWN distinction
RENAMED_FIELDS = {
    "ProvenCallEffect": {"stack_restoration": ("restores_stack", lambda value: value.value == "proven")},
    # FunctionSummary.version 2 (docs 25.89) only adds independent_delta_proofs,
    # itself projected at its default: compared as format 1 (any later format differs)
    "FunctionSummary": {"version": ("version", lambda value: 1 if value == 2 else value)},
}

# identity / authority tokens with no content (each is a unique object; only
# its presence is semantic)
TOKENS = {"_BoundSsaIdentity"}


class Unhandled(TypeError):
    pass


_BASE_GRAPH_EXPORT = ContextVar("tdo_base_graph_export", default=False)

# (X-1b paired comparison, design_x1b_method_r3 C) lossless encoding for paired
# dumps: renamed fields keep their own name and full value (e.g. the stack
# restoration verdict, not its boolean projection) and the reporting fields
# premise_uses / supports are encoded; ordinary snapshots are unchanged
_LOSSLESS = ContextVar("tdo_snapshot_lossless", default=False)
LOSSLESS_INCLUDED = {"premise_uses", "supports", "address_atom_origins"}


def encode_base_graph(value, path="$"):
    """Opt-in lossless graph payload without expanding virtual writer edges.

    Ordinary semantic snapshots keep their original encoding. This export
    retains original node IDs, physical multiedges and one shared writer
    table per identity; bit i means table.nodes[i] -> debt with records[i].
    It is a stored observation, not a portable authority/SSA receipt.
    """
    token = _BASE_GRAPH_EXPORT.set(True)
    try:
        return encode(value, path)
    finally:
        _BASE_GRAPH_EXPORT.reset(token)


def _compact_graph(graph, path):
    tables, indexes, debts = [], {}, []
    for debt in sorted(graph.virtual_debts()):
        writers, bits = graph.virtual_writers(debt)
        identity = id(writers)
        if identity not in indexes:
            indexes[identity] = len(tables)
            tables.append({"labels": encode(writers.universe.labels, path + ".writer_labels"),
                "nodes": list(writers.nodes),
                "records": [encode(record, path + ".writer_records") for record in writers.records]})
        debts.append({"debt": debt, "table": indexes[identity], "bits_hex": format(bits, "x")})
    physical = graph.physical_weighted_edges()
    return {"representation": "physical+virtual-writers-v1", "node_count": graph.node_count,
        "logical_edge_count": graph.edge_count,
        "nodes": [[index, encode(graph.node(index), f"{path}.nodes[{index}]")] for index in range(graph.node_count)],
        "physical_edges": [[source, target, encode(record, path + ".physical_edges")]
                           for source, target, record in physical],
        "virtual_writer_tables": tables, "virtual_writer_debts": debts}


def _check_contract(value, path):
    name = type(value).__name__
    if name not in CONTRACT:
        return None
    encoded, excluded = CONTRACT[name]
    names = [field.name for field in dataclasses.fields(value)]
    known = set(excluded) | (set(encoded) if encoded is not None else set(names) - set(excluded))
    missing = [field for field in names if field not in known]
    stale = [field for field in excluded if field not in names]
    if missing or stale:
        raise Unhandled(f"{path}: coverage contract of {name}: unclassified {missing}, stale exclusions {stale}")
    return set(excluded)


def encode(value, path="$"):
    """The canonical JSON-ready form of ``value`` (raises ``Unhandled``)."""
    from tdo_v2.graph import RustworkxDependencyGraph

    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        return {"float": repr(value)}
    if isinstance(value, enum.Enum):
        return {"enum": f"{type(value).__name__}.{value.name}"}
    if type(value) is bytes:
        return {"bytes": value.hex()}
    if type(value) is RustworkxDependencyGraph:
        if _BASE_GRAPH_EXPORT.get():
            return _compact_graph(value, path)
        return {
            "nodes": [encode(value.node(index), f"{path}.nodes[{index}]") for index in range(value.node_count)],
            "edges": [[source, target, encode(record, f"{path}.edges")]
                      for source, target, record in value.weighted_edges()],
        }
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        excluded = _check_contract(value, path) or set()
        added = ADDED_FIELDS.get(type(value).__name__, {})
        renamed = RENAMED_FIELDS.get(type(value).__name__, {})
        if _LOSSLESS.get():
            excluded, renamed = excluded - LOSSLESS_INCLUDED, {}

        def named(field):
            old = renamed.get(field.name)
            if old is None:
                return field.name, encode(getattr(value, field.name), f"{path}.{field.name}")
            return old[0], encode(old[1](getattr(value, field.name)), f"{path}.{old[0]}")

        return {"type": type(value).__name__, **dict(
            named(field)
            for field in dataclasses.fields(value) if field.name not in excluded
            and not (field.name in added and getattr(value, field.name) == added[field.name])
        )}
    if type(value) in (tuple, list):
        return [encode(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if type(value) in (set, frozenset):
        items = [encode(item, f"{path}{{}}") for item in value]
        return {"set": sorted(items, key=_canonical)}
    if type(value) is dict:
        if all(type(key) is str for key in value):
            return {"dict": {key: encode(item, f"{path}[{key!r}]") for key, item in sorted(value.items())}}
        items = [[encode(key, f"{path}<key>"), encode(item, f"{path}[...]")] for key, item in value.items()]
        return {"items": sorted(items, key=lambda pair: _canonical(pair[0]))}
    if type(value).__name__ == "NodeId" or isinstance(value, int):   # (int subclasses)
        return int(value)
    if type(value).__name__ in TOKENS:
        return {"token": type(value).__name__}
    raise Unhandled(f"{path}: unhandled type {type(value).__module__}.{type(value).__qualname__}")


def _canonical(encoded) -> str:
    return json.dumps(encoded, sort_keys=True, separators=(",", ":"))


def _digest(encoded) -> str:
    return hashlib.sha256(_canonical(encoded).encode()).hexdigest()


# -- dump -------------------------------------------------------------------------

def _run(generation: Path, config: str, bindings):
    import run_dfbench
    from tdo_v2 import summary_engine
    from tdo_v2.assumptions import switches
    from tdo_v2.summary_store import load_binding_file

    captured = {}
    original = summary_engine.analyze_units

    def capture(*args, **kwargs):
        captured["results"] = original(*args, **kwargs)
        return captured["results"]

    options = {item.parameter: item.default for item in switches() if item.parameter != "external_models"}
    models = run_dfbench.external_models(generation)
    if config == "off":
        options = {name: False for name in options}
        # (kept on: the legacy "off" baselines predate this switch and stay
        # comparable; its OFF behaviour is tested directly -- 2b-P B6)
        options["assume_opaque_callees_restore_stack_pointer"] = True
        models = None
    elif config == "accessor":
        options.update(assume_same_result_functions=True, assume_accessor_result_separate=True,
                       assume_accessor_private_state=True)
    summary_engine.analyze_units = capture
    try:
        run = summary_engine.analyze_frozen_bundle_with_summaries(
            generation, naming_exporter_source=REPO / "ghidra" / "GhidraV2CallNaming.java",
            boundary_provider=run_dfbench.boundary_provider(False, run_dfbench.abi_of(generation)),
            external_models=models, pcodeop_models=run_dfbench.pcodeop_models(),
            model_bindings=tuple(load_binding_file(path) for path in bindings), **options)
    finally:
        summary_engine.analyze_units = original
    return run, captured.get("results", {}), options, models


def _run_legacy(generation: Path):
    """The legacy engine (``engine.analyze_frozen_bundle``), its normalized
    functions captured from ``FunctionNormalizer.normalize``."""
    import run_dfbench
    from tdo_v2 import engine
    from tdo_v2.interprocedural import function_key
    from tdo_v2.normalize import FunctionNormalizer

    captured = {}
    original = FunctionNormalizer.normalize

    def capture(self, value, *args, **kwargs):
        result = original(self, value, *args, **kwargs)
        captured.setdefault(function_key(value.scopes.function.entry), []).append(result)
        return result

    FunctionNormalizer.normalize = capture
    try:
        run = engine.analyze_frozen_bundle(
            generation, naming_exporter_source=REPO / "ghidra" / "GhidraV2CallNaming.java",
            boundary_provider=run_dfbench.boundary_provider(False, run_dfbench.abi_of(generation)),
            include_explanations=False)
    finally:
        FunctionNormalizer.normalize = original
    return run, captured


def _bundle_digests(generation: Path) -> dict:
    """(X-1b) the input's manifest and seal digests, recorded by paired dumps."""
    return {name: hashlib.sha256((generation / file).read_bytes()).hexdigest()
            for name, file in (("manifest_sha256", "manifest.json"), ("seal_sha256", "seal.json"))}


def dump(generation: Path, out: Path, config: str, bindings=(), paired: bool = False) -> int:
    """``paired`` (X-1b, design_x1b_method_r3 B / C): every section encoded
    losslessly, the run's supports and control records added, the input's
    manifest / seal digests in ``meta`` -- for ``compare --pair`` / ``--paired``."""
    from tdo_v2.relative_memory import CAPTURE_ADDRESS_ATOM_ORIGINS

    token = _LOSSLESS.set(paired)
    origins = CAPTURE_ADDRESS_ATOM_ORIGINS.set(paired)
    try:
        return _dump(generation, out, config, bindings, paired)
    finally:
        CAPTURE_ADDRESS_ATOM_ORIGINS.reset(origins)
        _LOSSLESS.reset(token)


def _dump(generation: Path, out: Path, config: str, bindings, paired: bool) -> int:
    from tdo_v2.relative_memory import INDEX_DIAGNOSTICS
    from tdo_v2.summary_engine import LANE_DIAGNOSTICS

    started = time.time()
    if config == "legacy":
        run, normalized = _run_legacy(generation)
        sections = {f"function:{key}:normalized[{index}]": encode(item, f"{key}[{index}]")
                    for key, items in sorted(normalized.items()) for index, item in enumerate(items)}
        sections.update({f"root:{index}": encode(root, f"roots[{index}]") for index, root in enumerate(run.roots)})
        sections["run:assumptions"] = encode(run.assumptions, "assumptions")
        if getattr(run, "base_premises", ()):
            sections["run:base_premises"] = encode(run.base_premises, "base_premises")
        meta = {"snapshot_version": SNAPSHOT_VERSION, "generation": generation.name, "config": config,
                "bindings": [], "options": None, "models": None, "python": sys.version.split()[0],
                "seconds": round(time.time() - started, 1)}
        if paired:
            meta.update(paired=True, **_bundle_digests(generation))
            if getattr(run, "supports", None):
                sections["run:supports"] = encode(run.supports, "supports")
        return _write(out, meta, sections, f"{len(normalized)} functions, {len(run.roots)} roots")
    run, results, options, models = _run(generation, config, bindings)
    functions = {}
    for key, item in sorted(results.items()):
        normalized = encode(item.normalized, f"{key}.normalized")
        analyzed = encode(item, f"{key}")
        analyzed.pop("normalized", None)
        summary = analyzed.pop("summary", None)
        functions[key] = {"normalized": normalized, "summary": summary, "analyzed": analyzed}
    roots = [encode(root, f"roots[{index}]") for index, root in enumerate(run.roots)]
    run_level = {
        "assumptions": encode(run.assumptions, "assumptions"),
        **({"base_premises": encode(run.base_premises, "base_premises")}
           if getattr(run, "base_premises", ()) else {}),
        "failed_functions": encode(getattr(run, "failed_functions", ()), "failed_functions"),
        # Scope refusals have no admitted entry/summary; do not lose their
        # sealed member identity when functions/roots happen to be empty.
        **({"admission_failures": encode(run.admission_failures, "admission_failures")}
           if getattr(run, "admission_failures", ()) else {}),
        **({"refused_control_graphs": encode(run.refused_control_graphs, "refused_control_graphs")}
           if getattr(run, "refused_control_graphs", ()) else {}),
        # (U2a: only when a function has a control context)
        **({"control_contexts": encode(run.control_contexts, "control_contexts")}
           if getattr(run, "control_contexts", ()) else {}),
        **({"control_exemptions": encode(run.control_exemptions, "control_exemptions")}
           if getattr(run, "control_exemptions", ()) else {}),
        "lane_diagnostics": encode(dict(LANE_DIAGNOSTICS), "lane"),
        "index_diagnostics": encode(dict(INDEX_DIAGNOSTICS), "index"),
        # (X-1b paired dumps: the premise report and the run-level control records)
        **({"supports": encode(run.supports, "supports")} if paired and getattr(run, "supports", ()) else {}),
        **({"control_sites": encode(run.control_sites, "control_sites")}
           if paired and getattr(run, "control_sites", ()) else {}),
        **({"fault_report": encode(run.fault_report, "fault_report")}
           if paired and getattr(run, "fault_report", ()) else {}),
    }
    meta = {
        "snapshot_version": SNAPSHOT_VERSION, "generation": generation.name, "config": config,
        "bindings": [Path(path).name for path in bindings],
        # (a switch added after the baselines is recorded only off its default)
        "options": encode({name: value for name, value in options.items()
                           if not (name == "assume_opaque_callees_restore_stack_pointer" and value)
                           and not (name in ("assume_faults_end_execution", "assume_stock_ghidra_translator")
                                    and not value)}, "options"),
        "models": [[item.file_id, item.digest] for item in models.files] if models is not None else None,
        "python": sys.version.split()[0], "seconds": round(time.time() - started, 1),
    }
    if paired:
        meta.update(paired=True, **_bundle_digests(generation))
    sections = {f"function:{key}:{part}": data for key, item in functions.items() for part, data in item.items()}
    sections.update({f"root:{index}": root for index, root in enumerate(roots)})
    sections.update({f"run:{name}": data for name, data in run_level.items()})
    if os.environ.get("TDO_V2_FORWARD") == "1":
        # forward value facts (docs 25.33 F0): nothing in the engine reads them;
        # recorded only when asked, so forward-off snapshots stay as they were
        from tdo_v2.forward import context_facts, forward_facts
        from tdo_v2.image_info import ReadOnlyImage, load_image_info
        from tdo_v2.normalize import NormalizedFunction

        info = load_image_info(generation)
        readonly = ReadOnlyImage(generation, info)             if info is not None and (options or {}).get("assume_readonly_image_constant") else None
        for key, item in sorted(results.items()):
            if type(item.normalized) is NormalizedFunction:
                labels = (*run.assumptions, *item.inherited_assumptions, *item.declared.values())
                sections[f"forward:{key}"] = encode(forward_facts(
                    item.normalized, item.unit, readonly_image=readonly, assumptions=labels), f"{key}.forward")
        sections["forward-context"] = encode(context_facts(
            results, readonly_image=readonly,
            assumptions=lambda key, item: (*run.assumptions, *item.inherited_assumptions, *item.declared.values())),
            "forward-context")
        meta["forward"] = "F2a"
    return _write(out, meta, sections, f"{len(functions)} functions, {len(roots)} roots")


def _write(out: Path, meta, sections, what) -> int:
    document = {"meta": meta, "complete": True,
                "digests": {name: _digest(data) for name, data in sections.items()}, "sections": sections}
    out.parent.mkdir(parents=True, exist_ok=True)
    partial = out.with_name(out.name + ".partial")
    with gzip.open(partial, "wt", encoding="utf-8") as handle:
        json.dump(document, handle, sort_keys=True, separators=(",", ":"))
    partial.replace(out)   # (a crash leaves no artifact that looks whole)
    print(f"[snapshot] {meta['generation']} {meta['config']}: {what}, {meta['seconds']} s -> {out}")
    return 0


# -- compare ----------------------------------------------------------------------

def _load(path: Path):
    try:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, EOFError, json.JSONDecodeError) as error:
        raise SystemExit(f"[compare] {path}: unreadable ({error})") from None
    if not document.get("complete"):
        raise SystemExit(f"[compare] {path}: incomplete")
    return document


def _first_difference(a, b, path="$"):
    if type(a) is not type(b):
        return path, a, b
    if isinstance(a, dict):
        for key in sorted(set(a) | set(b)):
            if key not in a or key not in b:
                return f"{path}.{key}", a.get(key, "<absent>"), b.get(key, "<absent>")
            found = _first_difference(a[key], b[key], f"{path}.{key}")
            if found:
                return found
        return None
    if isinstance(a, list):
        for index, (left, right) in enumerate(zip(a, b)):
            found = _first_difference(left, right, f"{path}[{index}]")
            if found:
                return found
        if len(a) != len(b):
            return f"{path}.length", len(a), len(b)
        return None
    return None if a == b else (path, a, b)


def _check_pair(a, b, pair) -> str | None:
    """(X-1b, design_x1b_method_r3 B) both snapshots are paired dumps of exactly
    the inputs the pair record names."""
    for side, document in (("left", a), ("right", b)):
        meta = document["meta"]
        if not meta.get("paired"):
            return f"{side} is not a paired dump"
        for name in ("manifest_sha256", "seal_sha256"):
            if meta.get(name) != pair[side][name]:
                return f"{side} {name} {meta.get(name)} is not the pair's {pair[side][name]}"
    return None


def load_pair(path: Path, name: str) -> dict:
    record = json.loads(path.read_text())["pairs"][name]
    return {"left": record["left"], "right": record["right"]}


def compare(left: Path, right: Path, pair: dict | None = None, projected: bool = False) -> int:
    if pair is not None:
        return _compare_pair(left, right, pair, projected)
    if projected:
        print("[compare] --paired needs --pair")
        return 2
    a, b = _load(left), _load(right)
    return _compare_sections(left, right, a, b) if _same_inputs(a, b, None) else 2


def _same_inputs(a, b, pair):
    if pair is not None:
        problem = _check_pair(a, b, pair)
        if problem:
            print(f"[compare] pair check: {problem}")
            return False
    for name in ("generation", "config", "bindings", "options", "models"):
        if name == "generation" and pair is not None:
            continue   # (a verified pair: the inputs are named by their digests)
        if a["meta"].get(name) != b["meta"].get(name):
            print(f"[compare] input differs: {name}: {a['meta'].get(name)} vs {b['meta'].get(name)}")
            return False
    if pair is None and a["meta"].get("manifest_sha256") and b["meta"].get("manifest_sha256") and \
            a["meta"]["manifest_sha256"] != b["meta"]["manifest_sha256"]:
        print("[compare] input differs: manifest_sha256 (a reused generation id; use --pair)")
        return False
    return True


def _compare_pair(left, right, pair, projected):
    with PairedComparison() as comparison:
        return comparison.compare(left, right, pair, projected)


class PairedComparison(ExitStack):
    """Reuse decoded indexes and disk-backed projections within one frozen run."""

    def __init__(self):
        super().__init__()
        self.inputs = {}
        self.projections = {}
        self.projection_failures = {}
        self.validated = set()

    def _open(self, path):
        from snapshot_sections import open_snapshot

        if path not in self.inputs:
            self.inputs[path] = self.enter_context(open_snapshot(path))
        return self.inputs[path]

    def _prepare(self, path, projected):
        from tempfile import TemporaryFile

        from paired_projection import Ambiguous, project_snapshot
        from snapshot_sections import Sections

        snapshot = self.inputs[path]
        if projected:
            if path in self.projection_failures:
                raise Ambiguous(self.projection_failures[path])
            if path not in self.projections:
                with ExitStack() as attempt:
                    sections = Sections(attempt.enter_context(TemporaryFile()))
                    try:
                        digests = project_snapshot(snapshot, sections)
                    except Ambiguous as error:
                        self.projection_failures[path] = str(error)
                        raise
                    self.enter_context(attempt.pop_all())
                    self.projections[path] = {**snapshot, "sections": sections, "digests": digests}
                    self.validated.add(path)
            return self.projections[path]
        if path not in self.validated:
            # Decode one section at a time for syntax validation, including
            # sections with equal stored digests.
            for name in snapshot["sections"]:
                snapshot["sections"][name]
            self.validated.add(path)
        return snapshot

    def compare(self, left, right, pair, projected=False):
        from paired_projection import Ambiguous

        try:
            a, b = self._open(left), self._open(right)
            if not _same_inputs(a, b, pair):
                return 2
            return _compare_sections(left, right, self._prepare(left, projected), self._prepare(right, projected))
        except Ambiguous as error:
            print(f"[compare] {left.name} vs {right.name}: projection incomplete: {error}")
            return 2
        except (OSError, EOFError, ValueError, zlib.error) as error:
            print(f"[compare] unreadable pair: {error}")
            return 2


def _compare_sections(left, right, a, b):
    differences = 0
    for name in sorted(set(a["digests"]) | set(b["digests"])):
        if a["digests"].get(name) == b["digests"].get(name):
            continue
        differences += 1
        if name not in a["sections"] or name not in b["sections"]:
            print(f"[compare] {name}: only in {'right' if name not in a['sections'] else 'left'}")
            continue
        left_sections, right_sections = a["sections"], b["sections"]
        found = (left_sections.first_difference(name, right_sections) if hasattr(left_sections, "first_difference")
                 else _first_difference(left_sections[name], right_sections[name]))
        if found:
            path, x, y = found
            print(f"[compare] {name}: first difference at {path}: {str(x)[:200]} | {str(y)[:200]}")
        else:
            print(f"[compare] {name}: section digests differ without a JSON value difference")
        if differences >= 20:
            print("[compare] ... (more differences not shown)")
            break
    print(f"[compare] {left.name} vs {right.name}: {'identical' if not differences else f'{differences} sections differ'}"
          f" ({len(a['digests'])} sections)")
    return 1 if differences else 0


def manifest(directory: Path, expected: list[str]) -> int:
    status = 0
    for name in expected:
        path = directory / name
        if not path.exists():
            print(f"[manifest] missing {name}")
            status = 2
            continue
        try:
            _load(path)
        except SystemExit as error:
            print(error)
            status = 2
    print(f"[manifest] {directory}: {'complete' if not status else 'INCOMPLETE'} ({len(expected)} expected)")
    return status


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("dump")
    one.add_argument("generation", type=Path)
    one.add_argument("out", type=Path)
    one.add_argument("--config", default="default", choices=("default", "off", "accessor", "legacy"))
    one.add_argument("--binding", action="append", default=[], type=Path)
    one.add_argument("--paired-sections", action="store_true",
                     help="X-1b: lossless sections + supports + input digests (for compare --pair / --paired)")
    two = sub.add_parser("compare")
    two.add_argument("left", type=Path)
    two.add_argument("right", type=Path)
    two.add_argument("--pair", nargs=2, metavar=("PAIRS_JSON", "NAME"),
                     help="X-1b: compare a verified pair (left / right inputs named by manifest and seal digests)")
    two.add_argument("--paired", action="store_true", help="X-1b: the coordinate projection (needs --pair)")
    three = sub.add_parser("manifest")
    three.add_argument("directory", type=Path)
    three.add_argument("expected", nargs="+")
    args = parser.parse_args()
    if args.command == "dump":
        return dump(args.generation, args.out, args.config, args.binding, args.paired_sections)
    if args.command == "compare":
        pair = load_pair(Path(args.pair[0]), args.pair[1]) if args.pair else None
        return compare(args.left, args.right, pair, args.paired)
    return manifest(args.directory, args.expected)


if __name__ == "__main__":
    raise SystemExit(main())
