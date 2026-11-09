#!/usr/bin/env python3
"""Run a source / sink query (query.json) over one exported Bundle (WSL / POSIX).

The question is data, not engine code: each rule names a call target as the
Bundle's call naming reports it (an import such as ``strlen`` through its PLT
stub, an export, a FUN_ name), whether it is a source (the value it returns) or
a sink (a value it receives), and where that value lives at the call --
a register or bytes at an address held in a register. Registers may be given
by name (``"x0"``, ``"rdx"``): they are resolved against the Bundle's own
exported register table (an ISA fact), never against a calling convention.

query.json -- a list of rules (or {"rules": [...]}):

  {"target_name": "strlen", "kind": "sink", "label": "strlen.string",
   "physical_state": [{"base": {"register": "x0"}, "displacement": 0, "byte_size": 1}]}
  {"target_name": "getenv", "kind": "source", "label": "getenv.ret",
   "physical_state": [{"register": "x0"}]}

  physical_state rows: {"register": NAME[, "byte_size": N]} or
  {"byte_offset": OFF, "byte_size": N} (a register slice), or
  {"base": <register row>, "displacement": D, "byte_size": N} (memory at base + D).
  "language_id" defaults to the Bundle's language. Sources: register state only
  (the engine attaches source labels to registers); a memory source is refused.

Output (--out, default ./tdo_query_result.json): every root with its origins
and completeness, the run's assumptions, failed functions, and the call target
names the run classified with how many times each was classified (a count of
classification calls, not of unique call sites). An incomplete root's origins
are candidates, not a proof; with failed functions, an empty origin list does
not prove absence.

Example:
  PYTHONPATH=src python3 tools/analyze_bundle/analyze_query.py /root/tdo_bundles_so/libyolo/<generation> \
      --query query.json --out /tmp/libyolo_result.json
  (--list-calls: no rules, only report which call targets the Bundle has)
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import time

from tdo_v2.resource_limits import analysis_entry

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "bundle_export"))


def program_evidence(generation: Path):
    """The Bundle's verified program evidence (language, register table)."""
    from hashlib import sha256

    from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
    from tdo_v2.integration.configured_bundle import admit_frozen_bundle
    from tdo_v2.integration.observed_function_session import open_observed_function_session
    from tdo_v2.scope_identity import ConstructedProgramScope

    binding = NamingBindingExpectation(sha256((REPO / "ghidra/GhidraV2CallNaming.java").read_bytes()).digest(),
                                       CALL_NAMING_GHIDRA_VERSION)
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        program = session.program_result
        if type(program) is not ConstructedProgramScope:
            raise ValueError("Bundle program scope is unresolved")
        return program.evidence


def _register(row: dict, table: dict):
    from tdo_v2.physical_state import PhysicalRegisterSlice

    if "register" in row:
        name = row["register"]
        if name in table:   # the exact name first
            offset, size = table[name]
        else:               # then a case-insensitive match, only when unambiguous
            found = {value for key, value in table.items() if key.lower() == name.lower()}
            if len(found) != 1:
                raise ValueError(f"register {name!r} is not (or not unambiguously) in the Bundle's register table")
            offset, size = found.pop()
        return PhysicalRegisterSlice(offset, int(row.get("byte_size", size)))
    return PhysicalRegisterSlice(int(row["byte_offset"]), int(row["byte_size"]))


def _state(row: dict, table: dict):
    from tdo_v2.physical_state import PhysicalMemorySlice

    if "base" in row:
        return PhysicalMemorySlice(_register(row["base"], table), int(row.get("displacement", 0)),
                                   int(row["byte_size"]))
    return _register(row, table)


def load_rules(path: Path, evidence) -> tuple:
    from tdo_v2.boundary import BoundaryKind
    from tdo_v2.boundary_rules import BoundaryRule

    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data["rules"] if isinstance(data, dict) else data
    table = {}
    if evidence.register_evidence is not None:
        for register in evidence.register_evidence.registers:
            table[register.name] = (register.byte_offset, register.byte_size)
    for row in rows:
        # the engine attaches source labels to register state only
        # (summary_engine source boundaries): a memory source would be accepted
        # and silently never attached
        if row["kind"] == "source" and any("base" in item for item in row["physical_state"]):
            raise ValueError(f"source {row['label']!r}: only register sources are supported (no 'base' selector)")
    language = evidence.translation_namespace.language_id
    return tuple(BoundaryRule(row["target_name"], row.get("language_id", language), BoundaryKind(row["kind"]),
                              row["label"], tuple(_state(item, table) for item in row["physical_state"]),
                              bool(row.get("assume_call_effect", False)))
                 for row in rows)


class RecordingProvider:
    """The query's provider, also recording every call target it is asked about."""

    def __init__(self, inner) -> None:
        self.inner = inner
        self.seen: Counter = Counter()

    def classify(self, call):
        self.seen.update(call.target_names or ("<unnamed>",))
        return self.inner.classify(call)

    def state(self, call, match):
        return self.inner.state(call, match)

    def __getattr__(self, name):
        return getattr(self.inner, name)


def _base_index(snapshot):
    """Small publication metadata, never a claim that pending graphs exist."""
    return {"format": "tdo-base-graphs-v1", "program_scope": snapshot.program.scope.digest.hex(),
        "executable_sha256": snapshot.program.evidence.executable_sha256.hex(),
        "policy": asdict(snapshot.policy), "policy_digest": snapshot.policy.digest,
        "requested_policy": asdict(snapshot.requested_policy),
        "expected_keys": list(snapshot.expected_keys), "pending": list(snapshot.pending),
        "local_pass_finished": snapshot.local_pass_finished, "entry_links_finished": snapshot.entry_links_finished,
        "counts": {"graphs": len(snapshot.graphs), "normalization_failures": len(snapshot.failures),
                   "admission_failures": len(snapshot.admission_failures), "pending": len(snapshot.pending)},
        "stop": snapshot.stop, "admission_failures": [
            {"generation_id": item.generation_id.hex(), "function_id": item.function_id,
             "observation_member_id": item.observation_member_id,
             "observation_sha256": item.observation_sha256.hex(), "stage": item.stage, "reason": item.reason}
            for item in snapshot.admission_failures],
        "limitation": "Opaque-call local SSA and physical entry edges; not return effects, preservation or memory read-from proof"}


def _write_base_index(index, out_path):
    """Publish a complete index atomically, without replacing an old result."""
    out_path = Path(out_path)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=out_path.parent,
                                     prefix=out_path.name + ".", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(index, stream, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.link(temporary, out_path)  # exclusive, atomic commit on the same filesystem
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass  # an orphan temporary index must not invalidate a committed artifact


@analysis_entry
def write_base_graph_result(snapshot, out_path):
    """Persist actual graphs one function at a time, then atomically index.

    The opt-in semantic serializer retains compressed shared virtual-writer
    tables, original node IDs, physical multiedges, CFG and SSA definitions.
    Only one function/entry relation is encoded at once; no expanded virtual
    writer cross-product or second whole-program graph is built.
    """
    from tdo_v2.base_graph import BaseGraphSnapshot
    from tdo_v2.resource_limits import checkpoint
    import shutil

    sys.path.insert(0, str(REPO / "tools/graph_fidelity"))
    from semantic_snapshot import encode_base_graph

    if type(snapshot) is not BaseGraphSnapshot:
        raise TypeError("base graph export requires an exact publication snapshot")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        raise FileExistsError(out_path)
    directory = Path(tempfile.mkdtemp(prefix=out_path.name + ".graphs-", dir=out_path.parent))
    index = _base_index(snapshot)
    index.update(graphs={}, failures={}, graph_payloads_written=True)

    def record(path):
        digest = sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1 << 20):
                digest.update(chunk)
        return {"path": str(path.relative_to(out_path.parent)), "sha256": digest.hexdigest(), "bytes": path.stat().st_size}

    try:
        for key, graph in sorted(snapshot.graphs.items()):
            checkpoint()
            path = directory / ("function-" + sha256(key.encode()).hexdigest() + ".json.gz")
            with gzip.open(path, "wt", encoding="utf-8") as stream:
                stream.write('{"function":')
                json.dump(key, stream)
                stream.write(',"observation_digest":')
                json.dump(graph.unit.scopes.function.observation_digest.hex(), stream)
                stream.write(',"normalized":')
                json.dump(encode_base_graph(graph.normalized), stream, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":"))
                stream.write(',"entry_relations":[')
                for ordinal, relation in enumerate(graph.entry_relations):
                    checkpoint()
                    if ordinal:
                        stream.write(",")
                    metadata = {"call": relation.call, "target": relation.target, "context": list(relation.context),
                        "body_role": relation.body_role, "frontier": list(relation.frontier),
                        "state": encode_base_graph(relation.state), "projection": encode_base_graph(relation.projection)}
                    # Stream actual edge records separately from relation metadata.
                    text = json.dumps(metadata, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
                    stream.write(text[:-1] + ',"edges":[')
                    for edge_index, edge in enumerate(relation.edges()):
                        if edge_index:
                            stream.write(",")
                        json.dump(encode_base_graph(edge), stream, ensure_ascii=False, allow_nan=False,
                                  separators=(",", ":"))
                    stream.write("]}")
                stream.write("]}")
            index["graphs"][key] = record(path)
        for key, failure in sorted(snapshot.failures.items()):
            checkpoint()
            path = directory / ("failure-" + sha256(key.encode()).hexdigest() + ".json.gz")
            with gzip.open(path, "wt", encoding="utf-8") as stream:
                json.dump({"function": key, "reason": failure.reason.value, "detail": failure.detail,
                    "normalized": encode_base_graph(failure.normalized)}, stream, ensure_ascii=False,
                    allow_nan=False, separators=(",", ":"))
            index["failures"][key] = record(path)
        checkpoint()
        _write_base_index(index, out_path)
    except BaseException:
        # A signal can arrive immediately after the atomic link succeeded.
        # Preserve referenced payloads once an index exists; even a competing
        # index warrants an orphan directory rather than destructive cleanup.
        if not out_path.exists():
            shutil.rmtree(directory)  # only this call's fresh, unpublished artifacts
        raise
    return index


def _base_graphs_only(args):
    from tdo_v2.base_graph import build_frozen_bundle_graphs
    from tdo_v2.resource_limits import AnalysisCancelled

    handles = []
    try:
        snapshot = build_frozen_bundle_graphs(args.generation,
            naming_exporter_source=REPO / "ghidra/GhidraV2CallNaming.java", on_publication=handles.append)
    except (AnalysisCancelled, KeyboardInterrupt):
        # Cancellation is not permission for a potentially huge automatic
        # export. The API caller can query/export its own handle explicitly.
        if handles:
            index = _base_index(handles[0].snapshot)
            index.update(graph_payloads_written=False, available_graph_keys=list(handles[0].snapshot.graphs),
                         artifact_note="Cancelled: metadata only; in-memory graphs were not saved")
            args.out.parent.mkdir(parents=True, exist_ok=True)
            _write_base_index(index, args.out)
        return 130
    index = write_base_graph_result(snapshot, args.out)
    print(f"{len(index['graphs'])} base graphs, {len(index['failures'])} typed refusals, "
          f"{len(snapshot.admission_failures)} admission refusals, {len(snapshot.pending)} pending -> {args.out}")
    return 0 if snapshot.local_pass_finished and snapshot.entry_links_finished else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("generation", type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--query", type=Path)
    mode.add_argument("--list-calls", action="store_true", help="no rules: only report the call targets")
    mode.add_argument("--base-graphs-only", action="store_true", help="strict opaque-call graphs; no query, models or summary pass")
    parser.add_argument("--out", type=Path, default=Path("tdo_query_result.json"))
    parser.add_argument("--forward", choices=("0", "1"), help="default 1 (or TDO_V2_FORWARD)")
    parser.add_argument("--function-seconds", help="default 60 (or TDO_V2_FUNCTION_SECONDS)")
    parser.add_argument("--run-seconds", help="default 1800 (or TDO_V2_RUN_SECONDS)")
    args = parser.parse_args()

    # an explicit option wins over the environment; the environment over the default
    for name, value, default in (("TDO_V2_FORWARD", args.forward, "1"),
                                 ("TDO_V2_FUNCTION_SECONDS", args.function_seconds, "60"),
                                 ("TDO_V2_RUN_SECONDS", args.run_seconds, "1800")):
        if value is not None:
            os.environ[name] = value
        else:
            os.environ.setdefault(name, default)
    if args.base_graphs_only:
        return _base_graphs_only(args)

    import run_dfbench
    from tdo_v2.boundary_rules import SymbolBoundaryProvider
    from tdo_v2.summary_engine import analyze_frozen_bundle_with_summaries
    evidence = program_evidence(args.generation)
    rules = load_rules(args.query, evidence) if args.query else ()
    provider = RecordingProvider(SymbolBoundaryProvider(rules))
    started = time.time()
    run = analyze_frozen_bundle_with_summaries(
        args.generation, naming_exporter_source=REPO / "ghidra/GhidraV2CallNaming.java",
        boundary_provider=provider, external_models=run_dfbench.external_models(args.generation),
        pcodeop_models=run_dfbench.pcodeop_models(), origin_witnesses=True, operation_records=False,
        retain_admission_failures=True)
    # (2b-P P-c4) the premises each root's function rests on, by kind, and what
    # keeps them unestablished; "unpadded": recorded uses only
    supports = {int(row.function.split(":")[1], 16): row for row in run.supports}

    def premises(offset):
        row = supports.get(offset)
        if row is None:
            return None
        return {"published": dict(row.published), "unpadded": dict(row.unpadded),
                "obligations": list(row.obligations), "established": row.established}

    roots = [{"function": hex(root.function_byte_offset), "label": root.label,
              "occurrence": root.occurrence_ordinal, "origins": root.reached_origin_labels,
              "complete": root.is_effectively_complete,
              "local_completeness": asdict(root.local_completeness),
              "effective_completeness": asdict(root.effective_completeness),
              "inherited_incomplete": root.inherited_incomplete, "explanation": root.explanation,
              "premises": premises(root.function_byte_offset)}
             for root in run.roots]
    admission_failures = [
        {"generation_id": item.generation_id.hex(), "function_id": item.function_id,
         "observation_member_id": item.observation_member_id,
         "observation_sha256": item.observation_sha256.hex(), "stage": item.stage, "reason": item.reason}
        for item in run.admission_failures]
    refused_control_graphs = [
        {"function": key, "observation_digest": control.observation_digest.hex(), "normalized": False,
         "nodes": control.cfg.node_count, "edges": control.cfg.edge_count,
         "entry_reachable": control.entry_reachable, "unreachable": control.unreachable,
         "weak_components": control.weak_components,
         "outside_observed_successors": [
             {"source": asdict(source), "target": asdict(target)}
             for source, target in control.outside_observed_successors]}
        for key, control in run.refused_control_graphs]
    result = {"generation": str(args.generation), "sha256": run.executable_sha256,
              "language_id": evidence.translation_namespace.language_id,
              "seconds": round(time.time() - started, 1), "rules": [asdict(rule) for rule in rules],
              "assumptions": run.assumptions, "failed_functions": run.failed_functions, "roots": roots,
              "admission_failures_count": len(admission_failures), "admission_failures": admission_failures,
              "refused_control_graphs": refused_control_graphs,
              "call_targets": dict(provider.seen.most_common())}
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(f"{len(roots)} roots, {sum(root['complete'] for root in roots)} complete, "
          f"{len(admission_failures)} admission refusals, "
          f"{len(run.failed_functions)} failed functions, "
          f"{sum(not row.established for row in run.supports)} functions with unestablished premises, "
          f"{len(provider.seen)} call targets, "
          f"{result['seconds']} s -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
