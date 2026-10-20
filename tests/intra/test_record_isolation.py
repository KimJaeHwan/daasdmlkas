"""Operation records are diagnostics (docs 25.28; 25.31 C9-0): built after
every root's completeness is final, under their own budget -- with records
on, every other field of the run equals the records-off run, also when
function / run work limits cut the analysis; a record's completeness is the
root's final one; the ``diagnostic`` context charges no analysis ledger."""

import sys
from pathlib import Path

import pytest

from tdo_v2 import resource_limits
from tdo_v2.resource_limits import DiagnosticExhausted, activation, diagnostic, logical_work, run_analysis, step

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "intra"))
sys.path.insert(0, str(REPO / "tools" / "graph_fidelity"))

LIMIT_VARIABLES = ("TDO_V2_FUNCTION_WORK", "TDO_V2_FUNCTION_SECONDS", "TDO_V2_RUN_WORK", "TDO_V2_RUN_SECONDS",
                   "TDO_V2_RUN_RSS_MB", "TDO_V2_REPORTING_SECONDS", "TDO_V2_RECORD_WORK",
                   *(f"TDO_V2_LIMIT_{name.upper()}" for name in resource_limits.STRUCTURES))


@pytest.fixture(autouse=True)
def _no_limits(monkeypatch):
    for name in LIMIT_VARIABLES:
        monkeypatch.delenv(name, raising=False)


# -- the diagnostic context ------------------------------------------------------

def test_diagnostic_units_charge_no_analysis_ledger(monkeypatch):
    monkeypatch.setenv("TDO_V2_RUN_WORK", "100")
    monkeypatch.setenv("TDO_V2_FUNCTION_WORK", "50")

    def body():
        with activation("f"):
            for _ in range(10):
                step()
            before = logical_work()
            with diagnostic(None):
                for _ in range(10_000):   # far over both analysis limits
                    step()
                assert logical_work() == before
                with activation("g"):   # (no ledger inside a diagnostic)
                    step(500)
            for _ in range(10):
                step()
        run = resource_limits.current_run()
        return run.work, run.ledgers["f"].work, "g" in run.ledgers, run.diagnostic_work

    work, function_work, g_ledger, diagnostic_work = run_analysis(body)
    assert (work, function_work, g_ledger) == (21, 21, False)   # (+1: the activation unit)
    assert diagnostic_work == 10_500


def test_a_diagnostic_over_its_own_budget_is_cut_alone(monkeypatch):
    def body():
        with activation("f"):
            step(5)
            with pytest.raises(DiagnosticExhausted):
                with diagnostic(1000):
                    for _ in range(2000):
                        step()
            step(5)
        run = resource_limits.current_run()
        return run.work, run.exhausted

    assert run_analysis(body) == (11, None)


# -- records on / off ----------------------------------------------------------------

@pytest.fixture(scope="module")
def program():
    import scale_fixtures
    import synthetic

    fixture = scale_fixtures.realistic(1500, 0)
    inputs = synthetic.summary_inputs(fixture.functions, fixture.names, layout=fixture.layout,
                                      data=fixture.data, image=True)
    return fixture, inputs


def _run(program, records):
    from semantic_snapshot import encode
    from tdo_v2.summary_engine import analyze_observed_with_summaries

    fixture, inputs = program
    run = analyze_observed_with_summaries(
        inputs.program, inputs.evidences, image_info=inputs.image_info, readonly_image=inputs.readonly_image,
        boundary_provider=fixture.provider, pcodeop_models=fixture.pcodeop_models(inputs.evidences),
        operation_records=records)
    last = resource_limits.last_run()
    return run, encode(run), last.work, {key: item.work for key, item in last.ledgers.items()}


def _without_records(value):
    if isinstance(value, dict):
        return {key: _without_records(item) for key, item in value.items() if key != "record"}
    if isinstance(value, list):
        return [_without_records(item) for item in value]
    return value


@pytest.mark.parametrize("limits", [{}, {"TDO_V2_FUNCTION_WORK": 0.3}, {"TDO_V2_FUNCTION_WORK": 0.7},
                                    {"TDO_V2_RUN_WORK": 0.5}, {"TDO_V2_RUN_WORK": 0.9},
                                    {"TDO_V2_RECORD_WORK": 50}])
def test_records_change_no_other_result(program, monkeypatch, limits):
    _, _, total, ledgers = _run(program, False)
    for name, fraction in limits.items():
        if name == "TDO_V2_RECORD_WORK":
            monkeypatch.setenv(name, str(fraction))
        else:
            base = total if name == "TDO_V2_RUN_WORK" else max(ledgers.values())
            monkeypatch.setenv(name, str(max(1, int(base * fraction))))
    off_run, off, off_work, off_ledgers = _run(program, False)
    on_run, on, on_work, on_ledgers = _run(program, True)
    assert _without_records(on) == off
    assert (on_work, on_ledgers) == (off_work, off_ledgers)
    records = [root.explanation.get("record") for root in on_run.roots if root.root_nodes]
    assert all(records)   # (a run budget may leave no root with nodes)
    if not limits:
        assert records
    for root in on_run.roots:
        record = root.explanation.get("record")
        if record and "completeness" in record:   # the root's final completeness
            assert record["completeness"]["complete"] == root.effective_completeness.complete
    if "TDO_V2_RECORD_WORK" in limits:
        assert any(record.get("cut") == "diagnostic budget" for record in records)
