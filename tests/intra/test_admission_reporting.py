"""Public reports must not turn scope/CFG refusals into an empty success.

The tools are exercised against real synthetic engine outcomes. No private
observations or inferred entries are serialized for refused scope members.
"""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from synthetic import FunctionBuilder, RAX, RCX, _Instruction, copy, op, reg, summary_inputs
from test_observed_admission_outcomes import _provider, _session
from tdo_v2.boundary_rules import SymbolBoundaryProvider
from tdo_v2.engine import EngineRun
from tdo_v2 import summary_engine


REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def reporting_tools(monkeypatch):
    monkeypatch.syspath_prepend(str(REPO / "tools/bundle_export"))
    monkeypatch.syspath_prepend(str(REPO / "tools/analyze_bundle"))
    monkeypatch.syspath_prepend(str(REPO / "tools/graph_fidelity"))
    import analyze_query
    import semantic_snapshot

    monkeypatch.setenv("TDO_V2_FORWARD", "0")
    return analyze_query, semantic_snapshot


def _run(monkeypatch, mode):
    provider = _provider()
    if mode == "all-refused":
        provider.functions = [provider.functions[1]]
    elif mode == "zero-refusal":
        provider.functions = [provider.functions[0], provider.functions[2]]
    session, _ = _session(monkeypatch, provider)
    with session:
        program, outcomes = session.program_result, list(session.iter_outcomes())
    captured = {}
    original = summary_engine.analyze_units

    def capture(*args, **options):
        captured.update(original(*args, **options))
        return captured

    monkeypatch.setattr(summary_engine, "analyze_units", capture)
    run = summary_engine.analyze_observed_with_summaries(
        program, outcomes, boundary_provider=SymbolBoundaryProvider(()))
    return program, run, captured


def _query(monkeypatch, tmp_path, tool, program, run):
    import run_dfbench

    monkeypatch.setattr(tool, "program_evidence", lambda path: program.evidence)
    monkeypatch.setattr(summary_engine, "analyze_frozen_bundle_with_summaries", lambda *a, **k: run)
    monkeypatch.setattr(run_dfbench, "external_models", lambda path: None)
    monkeypatch.setattr(run_dfbench, "pcodeop_models", lambda: ())
    destination = tmp_path / "query-result.json"
    monkeypatch.setattr("sys.argv", ["analyze_query", str(tmp_path), "--list-calls", "--out", str(destination)])
    assert tool.main() == 0
    return json.loads(destination.read_text())


def _snapshot(monkeypatch, tool, tmp_path, run, results):
    captured = {}
    monkeypatch.setattr(tool, "_run", lambda *a, **k: (run, results, {}, None))

    def write(out, meta, sections, label):
        captured.update(sections)
        return 0

    monkeypatch.setattr(tool, "_write", write)
    assert tool.dump(tmp_path, tmp_path / "snapshot.json.gz", "off") == 0
    # No default=str escape hatch: actual snapshot sections must be JSON
    # primitives, including the graph/identity encodings of refused inputs.
    assert json.loads(json.dumps(captured, allow_nan=False)) == captured
    return captured


def _failure_metadata(failure):
    return dict(generation_id=failure.generation_id.hex(), function_id=failure.function_id,
        observation_member_id=failure.observation_member_id,
        observation_sha256=failure.observation_sha256.hex(), stage=failure.stage, reason=failure.reason)


@pytest.mark.parametrize("mode", ["mixed", "all-refused"])
def test_query_reports_scope_refusals_separately_without_inventing_an_entry(
        monkeypatch, tmp_path, capsys, reporting_tools, mode):
    tool, _ = reporting_tools
    program, run, results = _run(monkeypatch, mode)
    assert len(results) == (2 if mode == "mixed" else 0)
    failure, = run.admission_failures
    report = _query(monkeypatch, tmp_path, tool, program, run)
    assert report["admission_failures_count"] == 1
    assert report["admission_failures"] == [_failure_metadata(failure)]
    assert report["failed_functions"] == [] and report["roots"] == []
    assert "entry" not in report["admission_failures"][0]
    assert "1 admission refusals" in capsys.readouterr().out


@pytest.mark.parametrize("mode", ["mixed", "all-refused"])
def test_snapshot_preserves_scope_refusals_at_run_level(
        monkeypatch, tmp_path, reporting_tools, mode):
    _, tool = reporting_tools
    _, run, results = _run(monkeypatch, mode)
    sections = _snapshot(monkeypatch, tool, tmp_path, run, results)
    expected = tool.encode(run.admission_failures, "admission_failures")
    assert json.loads(json.dumps(expected, allow_nan=False)) == expected
    assert sections["run:admission_failures"] == expected
    encoded_failure, = sections["run:admission_failures"]
    assert encoded_failure["function_id"] == run.admission_failures[0].function_id
    assert "unit" not in encoded_failure and "entry" not in encoded_failure


def test_zero_refusal_snapshot_remains_identical_to_legacy_default_run_fields(
        monkeypatch, tmp_path, reporting_tools):
    _, tool = reporting_tools
    run = EngineRun("scope", "executable", ())
    legacy = SimpleNamespace(roots=(), assumptions=(), failed_functions=())
    old = _snapshot(monkeypatch, tool, tmp_path, legacy, {})
    new = _snapshot(monkeypatch, tool, tmp_path, run, {})
    assert new == old
    assert "run:admission_failures" not in new
    assert "run:refused_control_graphs" not in new


def test_query_program_metadata_is_available_even_with_no_admitted_function(
        monkeypatch, tmp_path, reporting_tools):
    from tdo_v2.integration import configured_bundle, observed_function_session

    tool, _ = reporting_tools
    program, run, _ = _run(monkeypatch, "all-refused")
    assert run.admission_failures

    class ProgramOnlySession:
        program_result = program

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def iter_functions(self):
            raise AssertionError("reporting metadata must not depend on strict function admission")

    monkeypatch.setattr(configured_bundle, "admit_frozen_bundle", lambda path: object())
    monkeypatch.setattr(observed_function_session, "open_observed_function_session", lambda *a, **k: ProgramOnlySession())
    assert tool.program_evidence(tmp_path) == program.evidence


def test_query_program_metadata_refuses_an_unresolved_program_without_function_iteration(
        monkeypatch, tmp_path, reporting_tools):
    from tdo_v2.integration import configured_bundle, observed_function_session
    from tdo_v2.scope_identity import UnresolvedProgramScope

    tool, _ = reporting_tools
    provider = _provider()
    provider.snapshot_complete = lambda: False
    session, _ = _session(monkeypatch, provider)
    with session:
        program = session.program_result
    assert type(program) is UnresolvedProgramScope

    class UnresolvedSession:
        program_result = program

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def iter_functions(self):
            raise AssertionError("an unresolved program must not iterate functions")

    monkeypatch.setattr(configured_bundle, "admit_frozen_bundle", lambda path: object())
    monkeypatch.setattr(observed_function_session, "open_observed_function_session", lambda *a, **k: UnresolvedSession())
    with pytest.raises(ValueError, match="program scope is unresolved"):
        tool.program_evidence(tmp_path)


@pytest.mark.parametrize("channel", ["query", "snapshot"])
def test_refused_cfg_is_marked_in_query_and_preserved_in_snapshot(
        monkeypatch, tmp_path, reporting_tools, channel):
    query, snapshot = reporting_tools
    builder = FunctionBuilder().ret(realistic=False)
    builder._rows.extend([_Instruction([copy(reg(RCX), reg(RAX))]),
                          _Instruction([op("RETURN", [reg(RAX)])], "return")])
    inputs = summary_inputs([builder], image=False)
    captured = {}
    original = summary_engine.analyze_units

    def capture(*args, **options):
        captured.update(original(*args, **options))
        return captured

    monkeypatch.setattr(summary_engine, "analyze_units", capture)
    run = summary_engine.analyze_observed_with_summaries(
        inputs.program, inputs.evidences, boundary_provider=SymbolBoundaryProvider(()))
    (key, control), = run.refused_control_graphs
    assert run.failed_functions and not run.admission_failures
    if channel == "query":
        report = _query(monkeypatch, tmp_path, query, inputs.program, run)
        (row,) = report["refused_control_graphs"]
        assert report["admission_failures_count"] == 0
        assert row == dict(function=key, observation_digest=control.observation_digest.hex(),
            normalized=False, nodes=3, edges=1, entry_reachable=["1:1000"],
            unreachable=["1:1004", "1:1008"], weak_components=[["1:1000"], ["1:1004", "1:1008"]],
            outside_observed_successors=[])
    else:
        sections = _snapshot(monkeypatch, snapshot, tmp_path, run, captured)
        expected = snapshot.encode(run.refused_control_graphs, "refused_control_graphs")
        assert json.loads(json.dumps(expected, allow_nan=False)) == expected
        assert sections["run:refused_control_graphs"] == expected
        assert "run:admission_failures" not in sections
