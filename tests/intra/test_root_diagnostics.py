"""Per-function / per-root blocker diagnostics (``root_diagnostics``, P1a).

``EngineRun.diagnostics`` names the already-computed facts a root rests on:
F0 status, F1 call inventory (target, effect, stack restoration), F2 unresolved
writers and per-call effect rows, F4 the summary's sink demands with their
debts, R3 operation-bound candidates, R4 the callee demand of a projected root.
Contract: built after reporting under its own diagnostic budget -- every other
output and every run / function work ledger equals the option-off run (C1, C2),
also when analysis limits or the diagnostic budget cut; deterministic across
hash seeds (C4); a builder error never breaks the run.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from synthetic import (
    CODE_BASE, DATA_BASE, RAX, RCX, RDX, REG, ZF,
    FunctionBuilder, analyze_summaries, boundary, const, copy, load, op, reg, store, tmp,
)

from tdo_v2 import resource_limits
from tdo_v2.write_classes import WILD, WriterClasses

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "graph_fidelity"))

MAIN, G, SINK, OPAQUE = CODE_BASE, CODE_BASE + 0x400, CODE_BASE + 0xA00, CODE_BASE + 0xC00
NAMES = {SINK: "sink", OPAQUE: "opaque"}
REGISTER_SINK = boundary({}, {"sink": 8})
LIMIT_VARIABLES = ("TDO_V2_FUNCTION_WORK", "TDO_V2_FUNCTION_SECONDS", "TDO_V2_RUN_WORK", "TDO_V2_RUN_SECONDS",
                   "TDO_V2_RUN_RSS_MB", "TDO_V2_REPORTING_SECONDS", "TDO_V2_RECORD_WORK",
                   "TDO_V2_DIAGNOSTIC_WORK", "TDO_V2_DIAGNOSTIC_ITEMS",
                   *(f"TDO_V2_LIMIT_{name.upper()}" for name in resource_limits.STRUCTURES))


@pytest.fixture(autouse=True)
def _no_limits(monkeypatch):
    for name in LIMIT_VARIABLES:
        monkeypatch.delenv(name, raising=False)


def _key(entry):
    return f"1:{entry:x}"


def _ram_write():
    """``[rdx * rcx] = rax`` -- a STORE to RAM the projection cannot place."""
    return (op("INT_MULT", [reg(RDX), reg(RCX)], tmp(0x180)), store(tmp(0x180), reg(RAX)))


def _wild_write():
    """``STORE(register space, rdx) = rax`` -- a write the may-alias analysis does not track."""
    return (op("STORE", [const(REG), reg(RDX), reg(RAX)]),)


def _callee():
    """G: ``[rdx*rcx] = rax; rcx = [global]; call sink`` -- its sink demand is
    incomplete (the load may read the unknown write)."""
    return FunctionBuilder(entry=G).sub_rsp(0x28).ins(*_ram_write()) \
        .ins(load(reg(RCX), const(DATA_BASE + 0x40))).call(SINK).add_rsp(0x28).ret()


def _caller():
    """MAIN: ``call G; call opaque; rcx = rax; call sink; <wild write>`` -- a
    projected root through G, an opaque call, an own root, a WILD writer."""
    return FunctionBuilder(entry=MAIN).sub_rsp(0x28).call(G).call(OPAQUE).ins(copy(reg(RCX), reg(RAX))) \
        .call(SINK).ins(*_wild_write()).add_rsp(0x28).ret()


def _run(*functions, **options):
    return analyze_summaries([*functions, FunctionBuilder(entry=SINK).ret()], REGISTER_SINK, names=NAMES,
                             **options)


def _run_with_results(monkeypatch, *functions, **options):
    """The run and the AnalyzedFunctions it published (captured, not re-derived)."""
    from tdo_v2 import summary_engine

    captured = {}
    original = summary_engine.analyze_units

    def capture(*args, **kwargs):
        captured["results"] = original(*args, **kwargs)
        return captured["results"]

    monkeypatch.setattr(summary_engine, "analyze_units", capture)
    return _run(*functions, **options), captured["results"]


def _call(record, entry):
    (row,) = [row for row in record["calls"] if (row["target"] or {}).get("function") == _key(entry)]
    return row


# -- off by default; the sidecar -------------------------------------------------------

def test_off_by_default_and_not_encoded():
    from semantic_snapshot import encode

    assert _run(_caller(), _callee()).diagnostics is None
    run = _run(_caller(), _callee(), root_diagnostics=True)
    assert run.diagnostics["version"] == 1 and run.diagnostics["phase"] == "P1a"
    assert "diagnostics" not in encode(run)
    json.dumps(run.diagnostics)   # (JSON-ready)


# -- the 2026-11-11 chain, link by link ----------------------------------------------------

def test_the_chain_reads_call_writer_demand_and_projection(monkeypatch):
    run, results = _run_with_results(monkeypatch, _caller(), _callee(), root_diagnostics=True)
    functions = run.diagnostics["functions"]
    caller, callee = functions[_key(MAIN)], functions[_key(G)]
    assert caller["status"] == callee["status"] == "normalized"
    # F1: the call to G is proven (with its demand), the opaque call has no effect
    to_g = _call(caller, G)
    assert to_g["effect"] == "proven" and to_g["stack"] == "proven" and to_g["sink_demands"] == 1
    (opaque,) = [row for row in caller["calls"] if row["target"] is None]
    assert opaque["effect"] == "none" and opaque["stack"] == "assumed"
    assert caller["calls_summary"] == {"total": 3, "proven": 2, "assumed": 0, "none": 1}
    # F2: the caller's WILD writer blocks; the callee's RAM writer does not
    assert [(row["class"], row["blocks_function_data_completeness"]) for row in caller["writers"]] == \
        [(WILD, True)]
    assert [(row["class"], row["blocks_function_data_completeness"]) for row in callee["writers"]] == \
        [("ram", False)]
    (rows,) = [row for row in caller["call_rows"] if row["call"] == to_g["call"]]
    assert rows["derived"] == len(rows["derived_rows"]) and all(
        row.startswith(to_g["call"] + "~") for row in rows["derived_rows"])
    # F4: the callee's demand is incomplete; its debts are the summary's own
    (demand,) = callee["demands"]
    assert demand["complete"] is False
    assert demand["debts"] == list(results[_key(G)].summary.sink_demands[0].debts) and demand["debts"]
    # R4: the projected root of MAIN names the call and the lowered demand
    (projected,) = [root for root in run.diagnostics["roots"] if "projected" in root]
    assert projected["function"] == _key(MAIN) and projected["inherited"] is True
    assert projected["projected"]["call"] == to_g["call"]
    assert projected["projected"]["lowered_complete"] is False
    assert projected["projected"]["projected_complete"] is False
    assert projected["projected"]["materialized"] is True
    assert projected["projected"]["source_demand"] == "unavailable"


def test_an_opaque_calls_stack_is_unknown_without_the_premise():
    run = _run(_caller(), _callee(), root_diagnostics=True, assume_opaque_callees_restore_stack_pointer=False)
    (opaque,) = [row for row in run.diagnostics["functions"][_key(MAIN)]["calls"] if row["target"] is None]
    assert opaque["effect"] == "none" and opaque["stack"] == "unknown"


def test_writer_classes_match_the_engine_and_counts_reconcile(monkeypatch):
    run, results = _run_with_results(monkeypatch, _caller(), _callee(), root_diagnostics=True)
    for item in results.values():
        record = run.diagnostics["functions"][item.key]
        classes = WriterClasses(item.normalized.scopes, item.unit.observation)
        assert [row["class"] for row in record["writers"]] == [
            classes.classify(row["op"]) for row in record["writers"]]
        assert record["writers_summary"]["total"] == len(item.normalized.memory_graph.unresolved_write_nodes)
    _reconcile(run)


def _reconcile(run):
    """Per root with nodes: F2's writer total is the root's function-wide
    count, and the R3 candidates are its unbound count (no TEST-ONLY exception)."""
    roots = sorted(run.roots, key=lambda root: (root.function_space_id, root.function_byte_offset, root.label,
                                                root.occurrence_ordinal))
    diagnostics = run.diagnostics["roots"]
    assert len(diagnostics) == len(roots)
    for root, record in zip(roots, diagnostics):
        assert (record["label"], record["occurrence"]) == (root.label, root.occurrence_ordinal)
        assert record["complete"] == root.effective_completeness.complete
        assert record["inherited"] == root.inherited_incomplete
        function = run.diagnostics["functions"][record["function"]]
        if not root.root_nodes or not isinstance(function.get("writers"), list):
            continue
        completeness = root.effective_completeness
        assert function["writers_summary"]["total"] == completeness.function_unresolved_writes
        if function["writers_summary"]["wild"]:
            assert not completeness.complete
        candidates = record.get("unbound", {}).get("candidates", [])
        assert len(candidates) == completeness.unbound_roots


# -- R3: operation-bound candidates ----------------------------------------------------------

def test_an_unbound_root_names_its_operation_candidate():
    """rcx = 7; call opaque; if (zf) goto ok; ud2; ok: call sink -- the opaque
    call is a barrier: the root binds to the sink call's consume event."""
    main = FunctionBuilder(entry=MAIN).sub_rsp(0x28).ins(copy(reg(RCX), const(7))).call(OPAQUE) \
        .cbranch("ok", reg(ZF, 1)).ud2().label("ok").call(SINK).add_rsp(0x28).ret()
    run = _run(main, root_diagnostics=True)
    (root,) = [root for root in run.diagnostics["roots"] if root["function"] == _key(MAIN)]
    assert root["unbound"]["cause"] == "unavailable"
    (candidate,) = root["unbound"]["candidates"]
    assert candidate["op"].endswith(":CALL") and "exception" not in candidate
    (calls,) = [row["call"] for row in run.diagnostics["functions"][_key(MAIN)]["calls"]
                if (row["target"] or {}).get("function") == _key(SINK)]
    assert candidate["op"] == calls
    _reconcile(run)


# -- F0: failures ------------------------------------------------------------------------------

def test_a_failed_function_is_reported_with_its_failure_roots(monkeypatch):
    monkeypatch.setenv("TDO_V2_LIMIT_GRAPH_NODES", "40")
    run = _run(_caller(), _callee(), root_diagnostics=True)
    failed = {key: reason for key, reason, _ in run.failed_functions}
    assert failed, "the limit should fail a function"
    for key, reason in failed.items():
        record = run.diagnostics["functions"][key]
        assert record["status"] == f"failed:{reason}"
        assert record["calls"] == "unavailable" or isinstance(record["calls"], list)
    for root in run.diagnostics["roots"]:
        if root["function"] in failed and root.get("unbound") == "unavailable":
            assert root["projected"] == "unavailable"


# -- C1 / C2: on and off -------------------------------------------------------------------------

@pytest.fixture(scope="module")
def program():
    import scale_fixtures
    import synthetic

    fixture = scale_fixtures.realistic(1500, 0)
    inputs = synthetic.summary_inputs(fixture.functions, fixture.names, layout=fixture.layout,
                                      data=fixture.data, image=True)
    return fixture, inputs


def _scaled(program, diagnostics, records=False):
    from semantic_snapshot import encode
    from tdo_v2.summary_engine import analyze_observed_with_summaries

    fixture, inputs = program
    run = analyze_observed_with_summaries(
        inputs.program, inputs.evidences, image_info=inputs.image_info, readonly_image=inputs.readonly_image,
        boundary_provider=fixture.provider, pcodeop_models=fixture.pcodeop_models(inputs.evidences),
        operation_records=records, root_diagnostics=diagnostics)
    last = resource_limits.last_run()
    return run, encode(run), last.work, {key: item.work for key, item in last.ledgers.items()}


@pytest.mark.parametrize("limits", [{}, {"TDO_V2_FUNCTION_WORK": 0.3}, {"TDO_V2_FUNCTION_WORK": 0.7},
                                    {"TDO_V2_RUN_WORK": 0.5}, {"TDO_V2_RUN_WORK": 0.9},
                                    {"TDO_V2_DIAGNOSTIC_WORK": 20}, {"TDO_V2_DIAGNOSTIC_ITEMS": 1}])
@pytest.mark.parametrize("records", [False, True])
def test_diagnostics_change_no_other_result(program, monkeypatch, limits, records):
    _, _, total, ledgers = _scaled(program, False)
    for name, value in limits.items():
        if name.startswith("TDO_V2_DIAGNOSTIC"):
            monkeypatch.setenv(name, str(value))
        else:
            base = total if name == "TDO_V2_RUN_WORK" else max(ledgers.values())
            monkeypatch.setenv(name, str(max(1, int(base * value))))
    off_run, off, off_work, off_ledgers = _scaled(program, False, records)
    on_run, on, on_work, on_ledgers = _scaled(program, True, records)
    assert on == off
    assert (on_work, on_ledgers) == (off_work, off_ledgers)
    assert off_run.diagnostics is None and "error" not in on_run.diagnostics
    if "TDO_V2_DIAGNOSTIC_WORK" in limits:
        assert any(row["reason"] == "work" for row in on_run.diagnostics["truncated"])
    elif not limits or records:
        assert not any(row["reason"] == "work" for row in on_run.diagnostics["truncated"])
    if "TDO_V2_DIAGNOSTIC_ITEMS" in limits:
        assert any(row["reason"] == "items" for row in on_run.diagnostics["truncated"])
        for record in on_run.diagnostics["functions"].values():
            if isinstance(record.get("calls"), list):
                assert len(record["calls"]) <= 1
                if record["calls_summary"]["total"] > 1:
                    assert record["calls_total"] == record["calls_summary"]["total"]
    if not limits:
        _reconcile(on_run)


def test_a_builder_error_leaves_the_run_unchanged(program, monkeypatch):
    from tdo_v2 import root_diagnostics

    _, off, off_work, off_ledgers = _scaled(program, False)

    def broken(self, key, failure):
        raise KeyError("boom")

    monkeypatch.setattr(root_diagnostics._Builder, "function", broken)
    run, on, on_work, on_ledgers = _scaled(program, True)
    assert (on, on_work, on_ledgers) == (off, off_work, off_ledgers)
    assert run.diagnostics == {"version": 1, "phase": "P1a", "error": "KeyError: 'boom'"}


# -- C4: deterministic across hash seeds ---------------------------------------------------------

_SEEDED = """
import json, sys
sys.path[:0] = [{src!r}, {intra!r}, {tools!r}]
import scale_fixtures, synthetic
from tdo_v2.summary_engine import analyze_observed_with_summaries
fixture = scale_fixtures.realistic(600, 1)
inputs = synthetic.summary_inputs(fixture.functions, fixture.names, layout=fixture.layout, data=fixture.data,
                                  image=True)
run = analyze_observed_with_summaries(inputs.program, inputs.evidences, image_info=inputs.image_info,
    readonly_image=inputs.readonly_image, boundary_provider=fixture.provider,
    pcodeop_models=fixture.pcodeop_models(inputs.evidences), root_diagnostics=True)
print(json.dumps(run.diagnostics))
"""


@pytest.mark.parametrize("items", [None, "1"])
def test_the_report_is_the_same_under_any_hash_seed(items):
    script = _SEEDED.format(src=str(REPO / "src"), intra=str(REPO / "tests" / "intra"), tools=str(REPO / "tools" / "graph_fidelity"))
    outputs = []
    for seed in ("0", "1"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        env.pop("TDO_V2_DIAGNOSTIC_ITEMS", None)
        if items is not None:
            env["TDO_V2_DIAGNOSTIC_ITEMS"] = items
        found = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True,
                               check=True, cwd=REPO)
        outputs.append(found.stdout)
    assert outputs[0] == outputs[1]
    report = json.loads(outputs[0])
    assert report["functions"] and report["roots"] and "error" not in report
    if items is not None:
        assert any(row["reason"] == "items" for row in report["truncated"])
