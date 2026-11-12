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
    assert projected["projected"]["target"] == {"function": _key(G)}
    assert (projected["projected"]["demand_index"], projected["projected"]["label"]) == (0, "sink.arg0")
    assert projected["projected"]["demand_index_space"] == "lowered-effect"
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




# -- regressions of the code review (Astra round 1) -------------------------------------------

def test_an_opaque_tail_call_is_in_the_inventory():
    """rcx = 7; jmp sink -- a tail call the engine seeded, with no resolved target."""
    main = FunctionBuilder(entry=MAIN).ins(copy(reg(RCX), const(7))).tail_call(SINK)
    run = analyze_summaries([main], REGISTER_SINK, names=NAMES, root_diagnostics=True)
    (row,) = run.diagnostics["functions"][_key(MAIN)]["calls"]
    assert row["call"].endswith(":BRANCH") and row["tail"] is True
    assert row["effect"] == "none" and row["stack"] == "unknown" and row["target"] is None


def test_a_callee_that_moves_the_stack_pointer_is_disproven():
    """G: add rsp, 8; ret -- its exit leaves another known delta."""
    callee = FunctionBuilder(entry=G).add_rsp(8).ret()
    main = FunctionBuilder(entry=MAIN).sub_rsp(0x28).call(G).ins(copy(reg(RCX), const(7))).call(SINK) \
        .add_rsp(0x28).ret()
    run = _run(main, callee, root_diagnostics=True)
    assert _call(run.diagnostics["functions"][_key(MAIN)], G)["stack"] == "disproven"


def test_a_test_only_declared_boundary_shows_its_label():
    """The summary engine carries a TEST-ONLY declared boundary as a proven
    effect with a declared label (never ``assumed_call_effects``): F1 shows the
    label next to the target; ``_unbound_roots``' exception cannot apply, so
    no candidate is marked and the counts still reconcile."""
    source = CODE_BASE + 0x800
    provider = boundary({"source": 4}, {"sink": 4}, assume_call_effect=True)
    main = (FunctionBuilder(entry=MAIN).call(source).cbranch("zero", reg(ZF, 1)).ins(copy(reg(RCX, 4), reg(RAX, 4)))
            .branch("join").label("zero").ins(copy(reg(RCX, 4), const(0, 4))).label("join").call(SINK).ret())
    bodies = [main, FunctionBuilder(entry=source).ins(copy(reg(RAX, 4), const(7, 4))).ret(),
              FunctionBuilder(entry=SINK).ret()]
    run = analyze_summaries(bodies, provider, names={SINK: "sink", source: "source"}, root_diagnostics=True,
                            assume_boundary_call_effects=True)
    calls = run.diagnostics["functions"][_key(MAIN)]["calls"]
    assert {row["target"]["model"] for row in calls} == {"test-only-boundary:source.ret",
                                                         "test-only-boundary:sink.arg0"}
    (root,) = [root for root in run.diagnostics["roots"] if root["function"] == _key(MAIN)]
    assert all("exception" not in candidate for candidate in root["unbound"]["candidates"])
    _reconcile(run)


def test_item_caps_reach_demands_and_keep_their_indices(monkeypatch):
    monkeypatch.setenv("TDO_V2_DIAGNOSTIC_ITEMS", "1")
    run = _run(_caller(), _callee(), root_diagnostics=True)
    caller = run.diagnostics["functions"][_key(MAIN)]
    assert caller["demands_summary"]["total"] == 2 and caller["demands_total"] == 2
    assert [row["index"] for row in caller["demands"]] == [0]
    rows = {row["where"]: row for row in run.diagnostics["truncated"] if row["reason"] == "items"}
    assert rows["functions.demands"]["total"] >= 2 and rows["functions.demands"]["shown"] >= 1


def _cut_lists(report):
    """Lists in the kept records that carry ``<name>_total`` (a cap cut them)."""
    found = 0
    stack = [report["functions"], report["roots"]]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            found += sum(1 for key in value if key.endswith("_total"))
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
    return found


def test_every_work_cut_is_a_clean_truncation(monkeypatch):
    """Any work allowance -- also one that cuts before the first function --
    gives tables, never an error; item rows count only kept records."""
    full = _run(_caller(), _callee(), root_diagnostics=True).diagnostics
    assert full["truncated"] == []
    monkeypatch.setenv("TDO_V2_DIAGNOSTIC_ITEMS", "1")
    seen = set()
    for work in (1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610):
        monkeypatch.setenv("TDO_V2_DIAGNOSTIC_WORK", str(work))
        report = _run(_caller(), _callee(), root_diagnostics=True).diagnostics
        assert "error" not in report, report
        cut = [row for row in report["truncated"] if row["reason"] == "work"]
        items = [row for row in report["truncated"] if row["reason"] == "items"]
        assert sum(row["lists"] for row in items) == _cut_lists(report)
        assert all(row["total"] is None for row in cut)
        if cut:
            seen.add((len(report["functions"]), len(report["roots"])))
            # the cut report is a prefix of the full one, in canonical order
            assert list(report["functions"]) == list(full["functions"])[:len(report["functions"])]
            assert [(r["function"], r["label"], r["occurrence"]) for r in report["roots"]] == \
                [(r["function"], r["label"], r["occurrence"]) for r in full["roots"]][:len(report["roots"])]
            if cut[0]["where"] == "functions":
                assert {"where": "roots", "reason": "work", "shown": 0, "total": None} in cut
    assert (0, 0) in seen and len(seen) > 1


def test_writers_carry_a_stable_identity():
    run = _run(_caller(), _callee(), root_diagnostics=True)
    for record in run.diagnostics["functions"].values():
        for row in record["writers"]:
            assert row["id"] == f"{row['op']}#{row['occurrence']}"


# -- C1 / C2: on and off -------------------------------------------------------------------------

def _semantic(monkeypatch, analyze):
    """(run, encoded run, premise report, encoded summaries, run work, ledgers,
    results) of one analysis: what C1 and C2 compare."""
    from semantic_snapshot import encode
    from tdo_v2 import summary_engine

    captured = {}
    original = summary_engine.analyze_units

    def capture(*args, **kwargs):
        captured["results"] = original(*args, **kwargs)
        return captured["results"]

    monkeypatch.setattr(summary_engine, "analyze_units", capture)
    try:
        run = analyze()
    finally:
        monkeypatch.setattr(summary_engine, "analyze_units", original)
    last = resource_limits.last_run()
    results = captured["results"]
    summaries = {key: encode(item.summary) for key, item in sorted(results.items())}
    return (run, encode(run), run.supports, summaries, last.work,
            {key: item.work for key, item in last.ledgers.items()}, results)


def _same(on, off):
    """C1 + C2: every encoded output, the premise report (not encoded), every
    published summary, the run and every function work ledger."""
    assert on[1] == off[1]
    assert on[2] == off[2]
    assert on[3] == off[3]
    assert (on[4], on[5]) == (off[4], off[5])


def _bodies(name):
    return {
        "chain": lambda: (_caller(), _callee()),
        "unbound": lambda: (FunctionBuilder(entry=MAIN).sub_rsp(0x28).ins(copy(reg(RCX), const(7))).call(OPAQUE)
                            .cbranch("ok", reg(ZF, 1)).ud2().label("ok").call(SINK).add_rsp(0x28).ret(),),
        "tail": lambda: (FunctionBuilder(entry=MAIN).ins(copy(reg(RCX), const(7))).tail_call(SINK),),
        "disproven": lambda: (FunctionBuilder(entry=MAIN).sub_rsp(0x28).call(G).ins(copy(reg(RCX), const(7)))
                              .call(SINK).add_rsp(0x28).ret(), FunctionBuilder(entry=G).add_rsp(8).ret()),
        "limited": lambda: (_caller(), _callee()),
    }[name]()


@pytest.mark.parametrize("name", ["chain", "unbound", "tail", "disproven", "limited"])
def test_small_programs_are_unchanged(monkeypatch, name):
    if name == "limited":
        monkeypatch.setenv("TDO_V2_LIMIT_GRAPH_NODES", "40")
    off = _semantic(monkeypatch, lambda: _run(*_bodies(name)))
    on = _semantic(monkeypatch, lambda: _run(*_bodies(name), root_diagnostics=True))
    _same(on, off)
    assert off[0].diagnostics is None and "error" not in on[0].diagnostics


@pytest.fixture(scope="module")
def program():
    import scale_fixtures
    import synthetic

    fixture = scale_fixtures.realistic(1500, 0)
    inputs = synthetic.summary_inputs(fixture.functions, fixture.names, layout=fixture.layout,
                                      data=fixture.data, image=True)
    return fixture, inputs


def _scaled(monkeypatch, program, diagnostics, records=False):
    from tdo_v2.summary_engine import analyze_observed_with_summaries

    fixture, inputs = program
    return _semantic(monkeypatch, lambda: analyze_observed_with_summaries(
        inputs.program, inputs.evidences, image_info=inputs.image_info, readonly_image=inputs.readonly_image,
        boundary_provider=fixture.provider, pcodeop_models=fixture.pcodeop_models(inputs.evidences),
        operation_records=records, root_diagnostics=diagnostics))


@pytest.mark.parametrize("limits", [{}, {"TDO_V2_FUNCTION_WORK": 0.3}, {"TDO_V2_FUNCTION_WORK": 0.7},
                                    {"TDO_V2_RUN_WORK": 0.5}, {"TDO_V2_RUN_WORK": 0.9},
                                    {"TDO_V2_DIAGNOSTIC_WORK": 20}, {"TDO_V2_DIAGNOSTIC_ITEMS": 1}])
@pytest.mark.parametrize("records", [False, True])
def test_diagnostics_change_no_other_result(program, monkeypatch, limits, records):
    base = _scaled(monkeypatch, program, False)
    for name, value in limits.items():
        if name.startswith("TDO_V2_DIAGNOSTIC"):
            monkeypatch.setenv(name, str(value))
        else:
            size = base[4] if name == "TDO_V2_RUN_WORK" else max(base[5].values())
            monkeypatch.setenv(name, str(max(1, int(size * value))))
    off = _scaled(monkeypatch, program, False, records)
    on = _scaled(monkeypatch, program, True, records)
    _same(on, off)
    run, results = on[0], on[6]
    assert off[0].diagnostics is None and "error" not in run.diagnostics
    truncated = run.diagnostics["truncated"]
    if "TDO_V2_DIAGNOSTIC_WORK" in limits:
        assert any(row["reason"] == "work" for row in truncated)
    else:
        assert not any(row["reason"] == "work" for row in truncated)
        # F0: every failure -- a late one over a published normalization included
        for key, reason, _ in run.failed_functions:
            assert run.diagnostics["functions"][key]["status"] == f"failed:{reason}"
        assert set(run.diagnostics["functions"]) == set(results)
    if "TDO_V2_DIAGNOSTIC_ITEMS" in limits:
        assert any(row["reason"] == "items" for row in truncated)
        for record in run.diagnostics["functions"].values():
            if isinstance(record.get("calls"), list):
                assert len(record["calls"]) <= 1
                if record["calls_summary"]["total"] > 1:
                    assert record["calls_total"] == record["calls_summary"]["total"]
    if not limits:
        _reconcile(run)


def test_a_builder_error_leaves_the_run_unchanged(program, monkeypatch):
    from tdo_v2 import root_diagnostics

    off = _scaled(monkeypatch, program, False)

    def broken(self, key, failure):
        raise KeyError("boom")

    monkeypatch.setattr(root_diagnostics._Builder, "function", broken)
    on = _scaled(monkeypatch, program, True)
    _same(on, off)
    assert on[0].diagnostics == {"version": 1, "phase": "P1a", "error": "KeyError: 'boom'"}


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


@pytest.mark.parametrize("limits", [{}, {"TDO_V2_DIAGNOSTIC_ITEMS": "1"}, {"TDO_V2_DIAGNOSTIC_WORK": "300"},
                                    {"TDO_V2_DIAGNOSTIC_WORK": "2500"},
                                    {"TDO_V2_DIAGNOSTIC_ITEMS": "1", "TDO_V2_DIAGNOSTIC_WORK": "2500"}])
def test_the_report_is_the_same_under_any_hash_seed(limits):
    script = _SEEDED.format(src=str(REPO / "src"), intra=str(REPO / "tests" / "intra"),
                            tools=str(REPO / "tools" / "graph_fidelity"))
    outputs = []
    for seed in ("0", "1"):
        env = {key: value for key, value in os.environ.items() if not key.startswith("TDO_V2_DIAGNOSTIC")}
        env.update(limits, PYTHONHASHSEED=seed)
        found = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True,
                               check=True, cwd=REPO)
        outputs.append(found.stdout)
    assert outputs[0] == outputs[1]
    report = json.loads(outputs[0])
    assert "error" not in report
    if "TDO_V2_DIAGNOSTIC_ITEMS" in limits:
        assert any(row["reason"] == "items" for row in report["truncated"])
    if "TDO_V2_DIAGNOSTIC_WORK" in limits:
        assert any(row["reason"] == "work" for row in report["truncated"])
        if limits["TDO_V2_DIAGNOSTIC_WORK"] == "2500":   # (a cut after some functions; the whole report is 2663 units)
            assert report["functions"]
    else:
        assert report["functions"] and report["roots"]


# -- Astra round 2 ------------------------------------------------------------------------------------

def test_the_writer_classifier_is_charged_before_it_reads_the_address_spaces(monkeypatch):
    """Every address-space row the classifier scans is charged first: the
    last diagnostic charge before ``memory_space_ids`` covers them."""
    from tdo_v2 import root_diagnostics, write_classes

    charges = []
    original_charge = root_diagnostics._Builder.charge
    original_spaces = write_classes.memory_space_ids
    scanned = []

    def charge(n):
        charges.append(n)
        original_charge(n)

    def spaces(scopes):
        if charges:   # (the analysis classifies too, before the diagnostics start)
            scanned.append((len(scopes.program.evidence.address_spaces), charges[-1]))
        return original_spaces(scopes)

    monkeypatch.setattr(root_diagnostics._Builder, "charge", staticmethod(charge))
    monkeypatch.setattr(write_classes, "memory_space_ids", spaces)
    _run(_caller(), _callee(), root_diagnostics=True)
    assert scanned and all(charged >= max(1, size) for size, charged in scanned)


def test_multi_target_members_are_listed_and_capped(monkeypatch):
    """call [table + (rcx & 1) * 8] -- resolved to two members (forward on)."""
    from test_multi_target_calls import A, B, _returns, _table

    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    run = _run(_table(), _returns(A, 1), _returns(B, 2), root_diagnostics=True)
    (row,) = [row for row in run.diagnostics["functions"][_key(MAIN)]["calls"] if row["call"].endswith(":CALLIND")]
    assert row["target"] == {"members": [_key(A), _key(B)]} and row["effect"] == "proven"
    monkeypatch.setenv("TDO_V2_DIAGNOSTIC_ITEMS", "1")
    run = _run(_table(), _returns(A, 1), _returns(B, 2), root_diagnostics=True)
    (row,) = [row for row in run.diagnostics["functions"][_key(MAIN)]["calls"] if row["call"].endswith(":CALLIND")]
    assert row["target"] == {"members": [_key(A)], "members_total": 2}
    rows = {row["where"]: row for row in run.diagnostics["truncated"] if row["reason"] == "items"}
    assert rows["functions.calls.members"] == {"where": "functions.calls.members", "reason": "items", "lists": 1,
                                               "shown": 1, "total": 2}


# -- Fable final review ----------------------------------------------------------------------------

def _two_sinks(entry):
    """``rcx = 1; call sink; rcx = 2; call sink`` -- two demands with one label."""
    return FunctionBuilder(entry=entry).sub_rsp(0x28).ins(copy(reg(RCX), const(1))).call(SINK) \
        .ins(copy(reg(RCX), const(2))).call(SINK).add_rsp(0x28).ret()


def test_demands_with_one_label_keep_their_own_indices():
    main = FunctionBuilder(entry=MAIN).sub_rsp(0x28).call(G).add_rsp(0x28).ret()
    run = _run(main, _two_sinks(G), root_diagnostics=True)
    assert [(row["index"], row["label"]) for row in run.diagnostics["functions"][_key(G)]["demands"]] == \
        [(0, "sink.arg0"), (1, "sink.arg0")]
    projected = [root["projected"] for root in run.diagnostics["roots"] if "projected" in root]
    assert sorted(row["demand_index"] for row in projected) == [0, 1]
    assert all(row["target"] == {"function": _key(G)} and row["label"] == "sink.arg0" for row in projected)


def test_a_multi_target_calls_demand_index_is_not_a_callee_index(monkeypatch):
    """Both members have one demand (F4 index 0 each); the composed effect
    concatenates them, so R4's lowered-effect indices are 0 and 1 -- the join
    to F4 is by target and label, never by index."""
    from test_multi_target_calls import A, B, _table

    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    member = lambda entry, value: FunctionBuilder(entry=entry).sub_rsp(0x28).ins(copy(reg(RCX), const(value))) \
        .call(SINK).add_rsp(0x28).ret()
    run = _run(_table(), member(A, 1), member(B, 2), root_diagnostics=True)
    functions = run.diagnostics["functions"]
    assert [row["index"] for row in functions[_key(A)]["demands"]] == [0]
    assert [row["index"] for row in functions[_key(B)]["demands"]] == [0]
    projected = [root["projected"] for root in run.diagnostics["roots"]
                 if root["function"] == _key(MAIN) and "projected" in root]
    assert sorted(row["demand_index"] for row in projected) == [0, 1]
    assert all(row["target"] == {"members": [_key(A), _key(B)]} for row in projected)
