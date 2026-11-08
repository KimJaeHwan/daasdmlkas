"""Base sealed-facade publication, cancellation and lossless product export.

Synthetic sealed transports reuse the existing lease/scope fixtures; these
tests do not replace the Bundle reader's own format/hash admission tests.
"""

from collections import Counter
import gzip
from hashlib import sha256
import json
from pathlib import Path

import pytest

from synthetic import (FunctionBuilder, RAX, RCX, RDX, _Instruction, const, copy, op,
                       program_units, reg)
from test_observed_admission_outcomes import _SealedProvider, _provider, _session
from tdo_v2.base_graph import BaseGraphPublication, build_frozen_bundle_graphs
from tdo_v2.normalize import FunctionNormalizer
from tdo_v2 import resource_limits


REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def clean_limits(monkeypatch):
    monkeypatch.setenv("TDO_V2_ANALYSIS_WORKER", "0")
    for name in ("FUNCTION_WORK", "RUN_WORK", "FUNCTION_SECONDS", "RUN_SECONDS", "RUN_RSS_MB"):
        monkeypatch.delenv("TDO_V2_" + name, raising=False)
    try:
        yield
    finally:
        # The CLI cancellation test intentionally sets the process-wide flag.
        # Direct normalizer tests do not start a new run to reset it.
        resource_limits._CANCEL.clear()


@pytest.fixture
def tools(monkeypatch):
    monkeypatch.syspath_prepend(str(REPO / "tools/bundle_export"))
    monkeypatch.syspath_prepend(str(REPO / "tools/analyze_bundle"))
    monkeypatch.syspath_prepend(str(REPO / "tools/graph_fidelity"))
    import analyze_query
    import semantic_snapshot

    return analyze_query, semantic_snapshot


def _frozen(monkeypatch, tmp_path, provider=None):
    from tdo_v2.integration import configured_bundle, observed_function_session

    provider = provider or _provider()
    closed = []
    original_close = provider.close

    def close():
        closed.append(True)
        original_close()

    monkeypatch.setattr(provider, "close", close)
    session, _ = _session(monkeypatch, provider)
    monkeypatch.setattr(configured_bundle, "admit_frozen_bundle", lambda path: object())
    monkeypatch.setattr(observed_function_session, "open_observed_function_session", lambda *a, **k: session)
    source = tmp_path / "naming.java"
    source.write_bytes(b"synthetic naming source")
    return session, closed, source


def _pair():
    return (FunctionBuilder().ins(copy(reg(RCX), const(23))).call(0x1800).ret(),
            FunctionBuilder(entry=0x1800).ins(copy(reg(RAX), reg(RCX))).ret())


def _logical_edges(payload):
    edges = list(payload["physical_edges"])
    for row in payload["virtual_writer_debts"]:
        table, bits = payload["virtual_writer_tables"][row["table"]], int(row["bits_hex"], 16)
        for index, source in enumerate(table["nodes"]):
            if bits & (1 << index):
                edges.append([source, row["debt"], table["records"][index]])
    return Counter(json.dumps(edge, sort_keys=True) for edge in edges)


@pytest.mark.parametrize("mode", ["mixed", "all-refused"])
def test_frozen_facade_keeps_scope_refusals_and_closed_session_graphs(monkeypatch, tmp_path, tools, mode):
    provider = _provider()
    if mode == "all-refused":
        provider.functions = [provider.functions[1]]
    session, closed, source = _frozen(monkeypatch, tmp_path, provider)
    handles = []
    saved = build_frozen_bundle_graphs(tmp_path, naming_exporter_source=source, on_publication=handles.append)
    assert closed and handles[0].snapshot == saved
    assert saved.local_pass_finished and saved.entry_links_finished and saved.stop == "finished"
    assert len(saved.graphs) == (2 if mode == "mixed" else 0)
    assert len(saved.admission_failures) == 1 and not saved.failures and not saved.pending
    failure, = saved.admission_failures
    assert failure.unit.observation is None and failure.observation_member_id.startswith("function-")
    index = tools[0].write_base_graph_result(saved, tmp_path / "refusals.json")
    assert index["counts"]["admission_failures"] == 1
    assert index["counts"]["normalization_failures"] == 0
    assert index["counts"]["graphs"] == (2 if mode == "mixed" else 0)
    assert "unit" not in index["admission_failures"][0] and "entry" not in index["admission_failures"][0]
    with pytest.raises(RuntimeError, match="not active"):
        session.iter_functions()
    if saved.graphs:
        graph = saved.graphs["1:1000"]
        node = graph.normalized.dependencies.node_for_key("op:1:1000:0:COPY")
        assert graph.query(node).reachable_nodes


def test_frozen_callback_real_cancel_preserves_completed_graph_and_query(monkeypatch, tmp_path, tools):
    session, closed, source = _frozen(monkeypatch, tmp_path, _SealedProvider(list(_pair())))
    normalize = FunctionNormalizer.normalize
    handles = []

    def cancel(self, unit, **options):
        if unit.scopes.function.entry.byte_offset == 0x1800:
            resource_limits._CANCEL.set()
            resource_limits.checkpoint()
        return normalize(self, unit, **options)

    monkeypatch.setattr(FunctionNormalizer, "normalize", cancel)
    with pytest.raises(resource_limits.AnalysisCancelled):
        build_frozen_bundle_graphs(tmp_path, naming_exporter_source=source, on_publication=handles.append)
    assert closed
    saved = handles[0].snapshot
    assert saved.stop == "cancelled" and list(saved.graphs) == ["1:1000"]
    assert saved.pending == ("1:1800",) and not saved.local_pass_finished and not saved.entry_links_finished
    # An explicit caller request starts a fresh export entry after cancellation;
    # it stores only the completed graph, never invents the pending function.
    index = tools[0].write_base_graph_result(saved, tmp_path / "explicit-partial.json")
    assert index["counts"] == dict(graphs=1, normalization_failures=0, admission_failures=0, pending=1)
    assert index["pending"] == ["1:1800"] and not index["entry_links_finished"]
    with pytest.raises(RuntimeError, match="not active"):
        session.iter_outcomes()
    graph = saved.graphs["1:1000"]
    assert graph.query(graph.normalized.dependencies.node_for_key("op:1:1000:0:COPY")).reachable_nodes


def test_product_export_preserves_original_nodes_logical_edges_ssa_and_entry_edges(tmp_path, tools):
    query, serializer = tools
    saved = BaseGraphPublication(program_units(*_pair())).build()
    out = tmp_path / "index.json"
    index = query.write_base_graph_result(saved, out)
    assert json.loads(out.read_text()) == index
    assert index["graph_payloads_written"] and index["entry_links_finished"]
    for key, graph in saved.graphs.items():
        path = tmp_path / index["graphs"][key]["path"]
        with gzip.open(path, "rt") as stream:
            payload = json.load(stream)
        for name in ("dependencies", "cfg"):
            original = getattr(graph.normalized, name)
            encoded = payload["normalized"][name]
            assert encoded["nodes"] == [[i, serializer.encode(original.node(i))] for i in range(original.node_count)]
            assert _logical_edges(encoded) == Counter(json.dumps([a, b, serializer.encode(e)], sort_keys=True)
                                                      for a, b, e in original.weighted_edges())
            assert encoded["logical_edge_count"] == original.edge_count
        assert payload["normalized"]["memory_ssa"] == serializer.encode(graph.normalized.memory_ssa)
        for exported, relation in zip(payload["entry_relations"], graph.entry_relations, strict=True):
            assert exported["edges"] == serializer.encode(relation.edges())
            assert exported["context"] == list(relation.context)
    assert saved.graphs["1:1000"].entry_edges()
    with pytest.raises(FileExistsError):
        query.write_base_graph_result(saved, out)


def test_virtual_export_shares_tables_and_never_expands_facade_edges(monkeypatch, tools):
    from test_graph_facade import _twin_graphs

    _, serializer = tools
    _, graph = _twin_graphs(7)
    graph.freeze()
    ordinary = serializer.encode(graph)
    expected = Counter(json.dumps(row, sort_keys=True) for row in ordinary["edges"])
    with monkeypatch.context() as patch:
        patch.setattr(graph, "weighted_edges", lambda: (_ for _ in ()).throw(AssertionError("virtual expansion")))
        compact = serializer.encode_base_graph(graph)
    assert len(compact["virtual_writer_tables"]) == 1
    assert len(compact["virtual_writer_debts"]) > 1
    assert _logical_edges(compact) == expected
    assert serializer.encode(graph) == ordinary  # opt-in mode did not change existing snapshots


def test_export_preserves_a_cfg_refusal_not_a_success_graph(tmp_path, tools):
    query, serializer = tools
    builder = FunctionBuilder().ret(realistic=False)
    builder._rows.extend([_Instruction([copy(reg(RCX), reg(RDX))]),
                          _Instruction([op("RETURN", [reg(RAX)])], "return")])
    saved = BaseGraphPublication(program_units(builder)).build()
    assert not saved.graphs and list(saved.failures) == ["1:1000"]
    index = query.write_base_graph_result(saved, tmp_path / "failed.json")
    with gzip.open(tmp_path / index["failures"]["1:1000"]["path"], "rt") as stream:
        payload = json.load(stream)
    assert payload["reason"] == "disconnected_observed_cfg"
    control = saved.failures["1:1000"].normalized.observed_control
    assert _logical_edges(payload["normalized"]["observed_control"]["cfg"]) == Counter(
        json.dumps([a, b, serializer.encode(e)], sort_keys=True) for a, b, e in control.cfg.weighted_edges())


def test_export_failure_does_not_publish_an_index_or_leave_a_false_complete_artifact(monkeypatch, tmp_path, tools):
    query, _ = tools
    saved = BaseGraphPublication(program_units(*_pair())).build()

    def fail(*args):
        raise OSError("atomic index commit failed")

    monkeypatch.setattr(query, "_write_base_index", fail)
    out = tmp_path / "failed-index.json"
    with pytest.raises(OSError, match="atomic index"):
        query.write_base_graph_result(saved, out)
    assert not out.exists() and not list(tmp_path.glob("failed-index.json.graphs-*"))
    graph = saved.graphs["1:1000"]
    assert graph.query(graph.normalized.dependencies.node_for_key("op:1:1000:0:COPY")).reachable_nodes


def test_export_interrupted_after_index_commit_keeps_every_referenced_payload(monkeypatch, tmp_path, tools):
    query, _ = tools
    saved = BaseGraphPublication(program_units(*_pair())).build()
    original_link = query.os.link

    def link_then_interrupt(source, target):
        original_link(source, target)
        raise KeyboardInterrupt("after atomic index commit")

    monkeypatch.setattr(query.os, "link", link_then_interrupt)
    out = tmp_path / "committed.json"
    with pytest.raises(KeyboardInterrupt, match="after atomic index"):
        query.write_base_graph_result(saved, out)
    index = json.loads(out.read_text())
    assert set(index["graphs"]) == set(saved.graphs)
    for key, row in index["graphs"].items():
        path = tmp_path / row["path"]
        assert path.stat().st_size == row["bytes"]
        assert sha256(path.read_bytes()).hexdigest() == row["sha256"]
        with gzip.open(path, "rt") as stream:
            assert json.load(stream)["function"] == key


def test_cli_base_mode_does_not_query_models_or_summaries(monkeypatch, tmp_path, tools):
    query, _ = tools
    import run_dfbench
    from tdo_v2 import summary_engine

    def forbidden(*args, **kwargs):
        raise AssertionError("query/model/summary path entered")

    _frozen(monkeypatch, tmp_path, _SealedProvider(list(_pair())))
    monkeypatch.setattr(query, "program_evidence", forbidden)
    monkeypatch.setattr(run_dfbench, "external_models", forbidden)
    monkeypatch.setattr(run_dfbench, "pcodeop_models", forbidden)
    monkeypatch.setattr(summary_engine, "analyze_frozen_bundle_with_summaries", forbidden)
    out = tmp_path / "base.json"
    monkeypatch.setattr("sys.argv", ["analyze_query", str(tmp_path), "--base-graphs-only", "--out", str(out)])
    assert query.main() == 0
    assert len(json.loads(out.read_text())["graphs"]) == 2


@pytest.mark.parametrize("other", ["--list-calls", "--query"])
def test_cli_base_mode_is_mutually_exclusive(monkeypatch, tmp_path, tools, other):
    query, _ = tools
    argv = ["analyze_query", str(tmp_path), "--base-graphs-only", other]
    if other == "--query":
        argv.append(str(tmp_path / "query.json"))
    monkeypatch.setattr("sys.argv", argv)
    with pytest.raises(SystemExit) as error:
        query.main()
    assert error.value.code == 2


def test_cli_cancel_writes_metadata_not_an_automatic_bulk_export(monkeypatch, tmp_path, tools):
    query, _ = tools
    _frozen(monkeypatch, tmp_path, _SealedProvider(list(_pair())))
    normalize = FunctionNormalizer.normalize

    def cancel(self, unit, **options):
        if unit.scopes.function.entry.byte_offset == 0x1800:
            resource_limits._CANCEL.set()
            resource_limits.checkpoint()
        return normalize(self, unit, **options)

    monkeypatch.setattr(FunctionNormalizer, "normalize", cancel)
    monkeypatch.setattr(query, "write_base_graph_result", lambda *a: pytest.fail("cancel must not bulk export"))
    out = tmp_path / "cancel.json"
    monkeypatch.setattr("sys.argv", ["analyze_query", str(tmp_path), "--base-graphs-only", "--out", str(out)])
    assert query.main() == 130
    index = json.loads(out.read_text())
    assert index["stop"] == "cancelled" and not index["graph_payloads_written"]
    assert index["available_graph_keys"] == ["1:1000"] and index["pending"] == ["1:1800"]
    assert not list(tmp_path.glob("cancel.json.graphs-*"))
