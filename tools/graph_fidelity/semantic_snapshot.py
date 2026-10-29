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
import dataclasses
import enum
import gzip
import hashlib
import json
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tools" / "bundle_export"))

SNAPSHOT_VERSION = 1

# -- coverage contract ----------------------------------------------------------
# type name -> (encoded fields, {excluded field: reason}); every dataclass field
# of these types must be in one of the two
CONTRACT = {
    "NormalizedFunction": (None, {"document": "input (the function document)",
                                  "scopes": "input (scope bundle)",
                                  "forward_inputs": "forward-on derivation inputs (docs 25.33 F4a); None when off",
                                  "call_clobber_contract": "inputs of the call-clobber rows (docs 25.84); the rows,"
                                                           " debts and roots they decide remain encoded"}),
    "UnresolvedNormalizedFunction": (None, {"scopes": "input (scope bundle)"}),
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
    }),
    "FunctionSummary": (None, {}),
    "ProvenCallEffect": (None, {}),
    "RootSlice": (None, {}),
    "EngineRun": (None, {}),
}


# fields added after the first baselines: omitted while at this value, so
# older snapshots stay comparable (a non-default value is encoded and differs)
ADDED_FIELDS = {
    "EngineRun": {"failed_functions": ()},
    "AnalyzedFunction": {"failure_detail": "", "superseded": None, "multi_calls": {}, "activations": {},
                         "call_memory_decisions": (), "activation_rejections": {}, "allocation_lifetimes": (),
                         "lifetime_models": ()},
    "NormalizedFunction": {"activation_entry": None, "forward_memory_proofs": (), "forward_memory_requires": (),
                           "load_value_proofs": (), "nonstack_spans": frozenset()},
    "RootSlice": {"inherited_incomplete": False},
    "CallMemoryDecision": {"evidence": ()},
    "MemoryGraphBindings": {"transfers": (), "transfer_nodes": ()},
    # (fields of the forward-memory / expression branch, 2026-10-23..26)
    "FunctionSummary": {"address_relations": ()},
    "LocalMemorySsaResult": {"call_register_snapshots": (), "flow_edges": ()},
    "SummaryRun": {"literal": None},
    "ProvenRunEffect": {"literal": None},
    "ProvenMemoryRun": {"literal": None},
    "AnchoredSpan": {"index": None},
    "CallProvenance": {"memory_sources": {}},
}

# identity / authority tokens with no content (each is a unique object; only
# its presence is semantic)
TOKENS = {"_BoundSsaIdentity"}


class Unhandled(TypeError):
    pass


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
        return {
            "nodes": [encode(value.node(index), f"{path}.nodes[{index}]") for index in range(value.node_count)],
            "edges": [[source, target, encode(record, f"{path}.edges")]
                      for source, target, record in value.weighted_edges()],
        }
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        excluded = _check_contract(value, path) or set()
        added = ADDED_FIELDS.get(type(value).__name__, {})
        return {"type": type(value).__name__, **{
            field.name: encode(getattr(value, field.name), f"{path}.{field.name}")
            for field in dataclasses.fields(value) if field.name not in excluded
            and not (field.name in added and getattr(value, field.name) == added[field.name])
        }}
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


def dump(generation: Path, out: Path, config: str, bindings=()) -> int:
    from tdo_v2.relative_memory import INDEX_DIAGNOSTICS
    from tdo_v2.summary_engine import LANE_DIAGNOSTICS

    started = time.time()
    if config == "legacy":
        run, normalized = _run_legacy(generation)
        sections = {f"function:{key}:normalized[{index}]": encode(item, f"{key}[{index}]")
                    for key, items in sorted(normalized.items()) for index, item in enumerate(items)}
        sections.update({f"root:{index}": encode(root, f"roots[{index}]") for index, root in enumerate(run.roots)})
        sections["run:assumptions"] = encode(run.assumptions, "assumptions")
        meta = {"snapshot_version": SNAPSHOT_VERSION, "generation": generation.name, "config": config,
                "bindings": [], "options": None, "models": None, "python": sys.version.split()[0],
                "seconds": round(time.time() - started, 1)}
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
        "failed_functions": encode(getattr(run, "failed_functions", ()), "failed_functions"),
        "lane_diagnostics": encode(dict(LANE_DIAGNOSTICS), "lane"),
        "index_diagnostics": encode(dict(INDEX_DIAGNOSTICS), "index"),
    }
    meta = {
        "snapshot_version": SNAPSHOT_VERSION, "generation": generation.name, "config": config,
        "bindings": [Path(path).name for path in bindings],
        "options": encode(options, "options"),
        "models": [[item.file_id, item.digest] for item in models.files] if models is not None else None,
        "python": sys.version.split()[0], "seconds": round(time.time() - started, 1),
    }
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


def compare(left: Path, right: Path) -> int:
    a, b = _load(left), _load(right)
    differences = 0
    for name in ("generation", "config", "bindings", "options", "models"):
        if a["meta"].get(name) != b["meta"].get(name):
            print(f"[compare] input differs: {name}: {a['meta'].get(name)} vs {b['meta'].get(name)}")
            return 2
    for name in sorted(set(a["digests"]) | set(b["digests"])):
        if a["digests"].get(name) == b["digests"].get(name):
            continue
        differences += 1
        if name not in a["sections"] or name not in b["sections"]:
            print(f"[compare] {name}: only in {'right' if name not in a['sections'] else 'left'}")
            continue
        path, x, y = _first_difference(a["sections"][name], b["sections"][name])
        print(f"[compare] {name}: first difference at {path}: {str(x)[:200]} | {str(y)[:200]}")
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
    two = sub.add_parser("compare")
    two.add_argument("left", type=Path)
    two.add_argument("right", type=Path)
    three = sub.add_parser("manifest")
    three.add_argument("directory", type=Path)
    three.add_argument("expected", nargs="+")
    args = parser.parse_args()
    if args.command == "dump":
        return dump(args.generation, args.out, args.config, args.binding)
    if args.command == "compare":
        return compare(args.left, args.right)
    return manifest(args.directory, args.expected)


if __name__ == "__main__":
    raise SystemExit(main())
