"""G0 ``tools/bundle_lint``: report rows, sealed fixtures, pipeline children.

Admission needs POSIX (owner / mode checks, ``fcntl``); those tests skip on
Windows. The fixtures are synthetic (``tools/bundle_lint/_sealed.py``).
"""

import json
import os
from pathlib import Path
import sys

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "bundle_lint"))

import report  # noqa: E402

posix = pytest.mark.skipif(os.name != "posix", reason="Bundle admission is POSIX-only")


# -- report rows -------------------------------------------------------------------------

def test_closed_sets_reject_unknown_states_and_lint_refusals():
    report.Row("pipeline", "stop", "k", "evaluated", "applied", "engine")
    with pytest.raises(ValueError):
        report.Row("pipeline", "stop", "k", "running")
    with pytest.raises(ValueError):
        report.Row("pipeline", "stop", "k", "evaluated", "refused", "lint")
    with pytest.raises(ValueError):
        report.Row("pipeline", "stop", "k", "not_run", "applied")
    with pytest.raises(ValueError):
        report.Row("pipeline", "stop", "k", "evaluated")


def test_row_keys_source_rows_by_index_validated_by_operation_key():
    assert report.source_row_key("function-000001", 3) == "function-000001/#3"
    assert report.operation_row_key("function-000001", (0x1007, 2, "CALL")) == "function-000001/0x1007:0x2:CALL"
    with pytest.raises(ValueError):
        report.source_row_key("function-000001", -1)


def test_duplicate_rows_are_refused_and_expect_compares_listed_fields():
    row = report.Row("operations", "s1_exit", "f/#0", "evaluated", "applied", "lint", {"kind": 2})
    with pytest.raises(ValueError):
        report.dumps({}, [row, row])
    actual = json.loads(report.dumps({}, [row]))
    assert report.compare({"rows": [row.as_json()]}, actual) == []
    changed = report.Row("operations", "s1_exit", "f/#0", "evaluated", "applied", "lint", {"kind": 4})
    assert report.compare({"rows": [changed.as_json()]}, actual) == ["('operations', 's1_exit', 'f/#0'): detail.kind 4 != 2"]
    missing = report.Row("operations", "s1_exit", "f/#1", "not_run")
    assert report.compare({"rows": [missing.as_json()]}, actual) == ["missing row ('operations', 's1_exit', 'f/#1')"]


# -- sealed fixture + pipeline children -----------------------------------------------

@pytest.fixture
def sealed(tmp_path):
    import _sealed

    os.chmod(tmp_path, 0o755)
    return _sealed, tmp_path


@posix
def test_reference_pair_runs_on_all_three_paths_with_the_engine_worker(sealed):
    import children

    _sealed, root = sealed
    gen = _sealed.write(root, _sealed.two_function_bundle())
    results = {path: children.run_path(path, gen, _sealed.NAMING_SOURCE, timeout=300) for path in children.PATHS}
    for path in ("summary", "summary-retain"):
        out = results[path]
        assert out["run_state"] == "evaluated" and out["completed"], out
        assert out["supports_count"] == len(out["supported_functions"])   # (Fable r6 P3-2)
        assert out["succeeded"] == ["1:1000", "1:1800"] and out["failed_functions"] == []
        assert out["worker"]["PYTHONHASHSEED"] == "0"
        assert out["worker"]["env_TDO_V2_ANALYSIS_WORKER"] == os.environ.get("TDO_V2_ANALYSIS_WORKER")
    graph = results["base_graph"]
    assert (graph["stop"], graph["pending"], graph["failures"], graph["entry_links_finished"]) == \
        ("finished", [], {}, True)


@posix
def test_a_broken_seal_stops_every_path_before_functions(sealed):
    import children

    _sealed, root = sealed
    bundle = _sealed.two_function_bundle(overrides={"seal.json": b'{"schema_version":2}'})
    gen = _sealed.write(root, bundle)
    for path in children.PATHS:
        out = children.run_path(path, gen, _sealed.NAMING_SOURCE, timeout=300)
        assert out["run_state"] == "evaluated" and out["completed"] is False, out
        assert out["exception"]["class"].endswith("BundleAdmissionError")


def test_a_child_timeout_is_reported_with_elapsed_time(tmp_path):
    import children

    script = tmp_path / "sleep.py"
    script.write_text("import time; time.sleep(30)\n")
    out = children.spawn(script, [], timeout=0.5)
    assert out["run_state"] == "timeout" and out["elapsed"] >= 0.5


# -- diagnosis pass: stop predictions (r4 section 2, r6 section 7) -------------------

def _lint_rows(sealed, bundle):
    import lint

    _sealed, root = sealed
    gen = _sealed.write(root, bundle)
    header, rows, diag = lint.run(gen, _sealed.NAMING_SOURCE, timeout=300, summary=True, options={})
    return {row.ident(): row for row in rows}, header, diag


def _f1(_sealed):
    s = _sealed
    a = s.Function("A", s.observation(0x1000, [s.plain(0x1000, 7, ("COPY", [s.const(23)], s.reg(s.RCX))),
                                               s.ret(0x1007)]))
    b = s.Function("B", s.observation(0x9000, [s.ret(0x9000)]))          # (entry outside memory: scope refusal)
    c = s.Function("C", s.observation(0x1800, [s.ret(0x1800)]))
    return s.Bundle([a, b, c], overrides={"call-names-000002": b"{"})   # (naming JSON error)


@posix
def test_f1_strict_stops_at_the_scope_refusal_retain_and_base_graph_at_the_naming_error(sealed):
    rows, _, _ = _lint_rows(sealed, _f1(sealed[0]))
    assert rows[("transport", "function_scope", "function-000001")].verdict == "refused"
    assert rows[("transport", "naming", "function-000001")].run_state == "not_reached"
    assert rows[("transport", "naming", "function-000002")].verdict == "refused"
    stops = {path: rows[("pipeline", "stop", path)] for path in ("summary", "summary-retain", "base_graph")}
    assert all(row.run_state == "evaluated" and row.verdict == "applied" for row in stops.values()), stops
    assert stops["summary"].detail["predicted"]["index"] == 1
    assert stops["summary-retain"].detail["predicted"]["index"] == 2
    assert stops["base_graph"].detail["predicted"]["index"] == 2
    for path in stops:
        completion = rows[("pipeline", "completion", path)]
        assert (completion.verdict, completion.detail["analysed"]) == ("refused", 0)


@posix
def test_f2_invalid_image_info_stops_both_summaries_before_functions_base_graph_finishes(sealed):
    _sealed = sealed[0]
    rows, _, _ = _lint_rows(sealed, _sealed.two_function_bundle(overrides={"image-info": b'{"schema":"bad"}'}))
    assert rows[("transport", "image_info", "bundle")].verdict == "refused"
    for path in ("summary", "summary-retain"):
        stop = rows[("pipeline", "stop", path)]
        assert stop.verdict == "applied" and stop.detail["predicted"]["stage"] == "image_info"
    graph = rows[("pipeline", "completion", "base_graph")]
    assert graph.verdict == "applied"
    assert (graph.detail["stop"], graph.detail["pending"], graph.detail["failures"],
            graph.detail["entry_links_finished"]) == ("finished", [], {}, True)


@posix
def test_writable_block_turns_readonly_folding_off(sealed):
    _sealed = sealed[0]
    rows, _, _ = _lint_rows(sealed, _sealed.two_function_bundle(blocks=[_sealed.Block(write=True)]))
    assert rows[("transport", "readonly_block", "1:1000")].verdict == "not_applicable"


def test_a_mismatched_stop_is_an_error_not_a_verdict():
    import diagnose

    predicted = {"stage": "function", "index": 1, "class": "builtins.ValueError", "message": "x"}
    child = {"run_state": "evaluated", "completed": False,
             "exception": {"class": "builtins.ValueError", "message": "y"}}
    assert diagnose.check_stop(predicted, child)[:2] == ("error", None)
    assert diagnose.check_stop(None, child)[:2] == ("error", None)
    assert diagnose.check_stop(None, {"run_state": "timeout"})[:2] == ("timeout", None)
