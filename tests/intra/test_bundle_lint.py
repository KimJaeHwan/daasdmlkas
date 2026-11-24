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
    found = {row.ident(): row for row in rows}
    assert len(found) == len(rows), "duplicate report rows"   # (Astra impl r3: never mask duplicates)
    return found, header, diag


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
    assert rows[("transport", "readonly_block", "#0/1:1000")].verdict == "not_applicable"


def test_a_mismatched_stop_is_an_error_not_a_verdict():
    import diagnose

    predicted = {"stage": "function", "index": 1, "class": "builtins.ValueError", "message": "x"}
    child = {"run_state": "evaluated", "completed": False,
             "exception": {"class": "builtins.ValueError", "message": "y"}}
    assert diagnose.check_stop(predicted, child)[:2] == ("error", None)
    assert diagnose.check_stop(None, child)[:2] == ("error", None)
    assert diagnose.check_stop(None, {"run_state": "timeout"})[:2] == ("timeout", None)


# -- layer 2: operations ------------------------------------------------------------

def _exit(source, target, kind, function):
    import _sealed as s

    return {"source": s.coord(source), "target": s.coord(target), "kind": kind,
            "function": None if function is None else s.coord(function)}


def _layer2_bundle(_sealed, *, exit_kind=2, pads=True):
    s = _sealed
    # A: call B with a listed local landing pad (0x100a, also reached by the jump at 0x1005)
    call_targets = [0x1800, 0x100A] if pads else [0x1800]
    a = s.Function("A", s.observation(0x1000, [
        s.call(0x1000, 0x1800, targets=call_targets),
        s.row(0x1005, 5, s.ops(("BRANCH", [s.ram(0x100A)], None)),
              s.flow(is_flow=True, is_jump=True, is_unconditional=True), None, [0x100A]),
        s.ret(0x100A)]))
    b = s.Function("B", s.observation(0x1800, [
        s.plain(0x1800, 2, ("CALLOTHER", [s.const(16, 4), s.const(3, 4)], None)),   # int3 (x86.json trap)
        s.ret(0x1802)]))
    function = 0x1800 if exit_kind == 2 else None
    # E falls through into B's entry (S1 exit kind 2, function B)
    e = s.Function("E", s.observation(0x17F0, [s.plain(0x17F0, 3, ("COPY", [s.reg(s.RCX)], s.reg(s.RAX))),
                                               s.plain(0x17F3, 13, ("COPY", [s.reg(s.RCX)], s.reg(s.RDX)))],
                                      exits=[_exit(0x17F3, 0x1800, exit_kind, function)]))
    return s.Bundle([a, e, b])


@posix
def test_layer2_registers_calls_pads_exits_and_callother(sealed):
    _sealed = sealed[0]
    rows, _, _ = _lint_rows(sealed, _layer2_bundle(_sealed))
    assert rows[("operations", "stack_register", "program")].detail["name"] == "RSP"
    assert rows[("operations", "link_register", "program")].verdict == "not_applicable"   # (x86: none)
    call = rows[("operations", "call", "function-000000/1:1000:2:CALL")]
    assert call.verdict == "applied" and call.detail["aliases"] == ["B"]
    for check in ("push_projection", "plain_push", "push_relation"):
        assert rows[("operations", check, "function-000000/1:1000:2:CALL")].verdict == "applied"
    assert call.detail["landing_pads"] == ["1:100a"]
    assert rows[("operations", "fixed_register", "RSP@interprocedural._plain_push_call")].verdict == "applied"
    exit_row = rows[("operations", "s1_exit", "function-000001/#0")]
    assert (exit_row.detail["kind"], exit_row.detail["function"], exit_row.detail["reach_edge"]) == (2, "1:1800", True)
    trap = rows[("operations", "callother_model_match", "function-000002/1:1800:0:CALLOTHER")]
    assert trap.verdict == "applied" and trap.detail["trap_match"] and trap.detail["index"] == 16


@posix
def test_variant5_kind4_exit_loses_the_reach_edge_and_variant6_drops_a_pad(sealed):
    _sealed, root = sealed
    import lint

    rows = {}
    for name, bundle in (("k4", _layer2_bundle(_sealed, exit_kind=4)), ("nopad", _layer2_bundle(_sealed, pads=False))):
        sub = root / name
        sub.mkdir(mode=0o755)
        gen = _sealed.write(sub, bundle)
        rows[name] = {row.ident(): row for row in lint.run(gen, _sealed.NAMING_SOURCE, timeout=300, summary=False,
                                                            options={})[1]}
    exit_row = rows["k4"][("operations", "s1_exit", "function-000001/#0")]
    assert (exit_row.detail["kind"], exit_row.detail["function"], exit_row.detail["reach_edge"]) == (4, None, False)
    call = rows["nopad"][("operations", "call", "function-000000/1:1000:2:CALL")]
    assert call.detail["landing_pads"] == [] and call.verdict == "applied"
    assert rows["nopad"][("operations", "plain_push", "function-000000/1:1000:2:CALL")].verdict == "applied"


# -- layer 3: features ----------------------------------------------------------------

def _run_lint(sealed, bundle, name="g", **kw):
    import lint

    _sealed, root = sealed
    sub = root / name
    sub.mkdir(mode=0o755)
    gen = _sealed.write(sub, bundle)
    options = kw.pop("options", {})
    header, rows, diag = lint.run(gen, _sealed.NAMING_SOURCE, timeout=300, summary=kw.pop("summary", True),
                                  options=options)
    found = {row.ident(): row for row in rows}
    assert len(found) == len(rows), "duplicate report rows"
    return found, header


def _slot_bundle(_sealed, *, write=False, imported=False):
    """F reads the pointer slot at 0x1f00 and loads through it."""
    s = _sealed
    data = bytearray(b"\xcc" * 0x1000)
    data[0xF00:0xF08] = (0x1E00).to_bytes(8, "little")
    f = s.Function("F", s.observation(0x1000, [
        s.plain(0x1000, 7, ("COPY", [s.ram(0x1F00)], s.reg(s.RAX))),
        s.plain(0x1007, 3, ("LOAD", [s.const(s.RAM), s.reg(s.RAX)], s.reg(s.RCX))),
        s.ret(0x100A)]))
    bundle = s.Bundle([f], blocks=[s.Block(data=bytes(data), write=write)])
    if imported:
        bundle.image_info = {"schema": "tdo-v2-image-info-1", "executable_format": "Raw Binary",
                             "block_permissions": [{"block_id": "block-000000", "name": ".text", "read": True,
                                                    "write": write, "execute": True, "volatile": False}],
                             "imports": [{"library": "KERNEL32.DLL", "name": "Sleep", "original_name": None,
                                          "slots": [s.coord(0x1F00)], "thunks": []}],
                             "exports": [], "relocations": []}
    return bundle


@posix
def test_readonly_slot_use_is_recorded_per_address_and_disappears_on_a_writable_block(sealed):
    _sealed = sealed[0]
    ro, _ = _run_lint(sealed, _slot_bundle(_sealed), "ro", summary=False, options={"lint_normalize": True})
    rw, _ = _run_lint(sealed, _slot_bundle(_sealed, write=True), "rw", summary=False,
                      options={"lint_normalize": True})
    assert ro[("features", "standalone_normalize", "function-000000")].verdict == "applied"
    assert ("features", "readonly_use", "function-000000/1:1f00") in ro
    assert not any(ident[1] == "readonly_use" for ident in rw)


@posix
def test_standalone_import_slot_context_is_set_and_used(sealed):
    _sealed = sealed[0]
    on, _ = _run_lint(sealed, _slot_bundle(_sealed, imported=True), "on", summary=False,
                      options={"lint_normalize": True})
    off, _ = _run_lint(sealed, _slot_bundle(_sealed, imported=True), "off", summary=False,
                       options={"lint_normalize": True, "assume_import_slots_hold_exports": False})
    assert on[("features", "standalone_context", "program")].detail["import_slots_context"] is True
    assert off[("features", "standalone_context", "program")].detail["import_slots_context"] is False
    assert on[("features", "standalone_normalize", "function-000000")].detail["import_slots"] is True
    assert off[("features", "standalone_normalize", "function-000000")].detail["import_slots"] is False


@posix
def test_stack_identification_is_compared_by_register_not_object_id(sealed):
    _sealed = sealed[0]
    ref, _ = _run_lint(sealed, _sealed.two_function_bundle(), "ref", summary=False)
    row = ref[("features", "stack_pointer", "function-000000")]
    assert row.verdict == "applied"
    assert (row.detail["register_offset"], row.detail["register_size"]) == (_sealed.RSP, 8)
    assert "object" not in json.dumps(row.detail)


@posix
def test_trap_application_is_unobserved_with_models_and_not_run_without(sealed):
    _sealed = sealed[0]
    models = [str(REPO / "models" / "pcodeops" / "x86.json")]
    with_models, _ = _run_lint(sealed, _layer2_bundle(_sealed), "m", options={"pcodeop_models": models})
    without, _ = _run_lint(sealed, _layer2_bundle(_sealed), "n")
    key = ("features", "trap_application", "function-000002/1:1800:0:CALLOTHER")
    assert with_models[key].run_state == "unobserved"
    assert without[key].run_state == "not_run"


@posix
def test_deep_chain_lint_child_matches_the_public_entry(sealed):
    """r6 s1: the child keeps the engine's worker -- no analysis_depth failure
    that the public entry would not have."""
    import children
    from tdo_v2.boundary import NullBoundaryProvider
    from tdo_v2.summary_engine import analyze_frozen_bundle_with_summaries

    s, root = sealed
    depth = 1500
    rows = [s.plain(0x1000, 7, ("COPY", [s.ram(0x1F00)], s.reg(s.RAX)))]
    for index in range(depth):
        rows.append(s.plain(0x1007 + 4 * index, 4, ("INT_ADD", [s.reg(s.RAX), s.const(8)], s.reg(s.RAX))))
    end = 0x1007 + 4 * depth
    rows.append(s.plain(end, 3, ("LOAD", [s.const(s.RAM), s.reg(s.RAX)], s.reg(s.RCX))))
    rows.append(s.ret(end + 3))
    bundle = s.Bundle([s.Function("D", s.observation(0x1000, rows))],
                      blocks=[s.Block(start=0x1000, data=b"\xcc" * 0x3000)])
    bundle.blocks[0].data = bytes(0x0F00) + (0x1E00).to_bytes(8, "little") + bytes(0x3000 - 0x0F08)
    gen = s.write(root, bundle)
    child = children.run_path("summary", gen, s.NAMING_SOURCE, timeout=600)
    direct = analyze_frozen_bundle_with_summaries(gen, naming_exporter_source=s.NAMING_SOURCE,
                                                  boundary_provider=NullBoundaryProvider())
    assert child["completed"], child
    assert direct.failed_functions == () and child["failed_functions"] == []   # (no analysis_depth on either side)
    assert child["succeeded"] == ["1:1000"]


# -- variants (mutate.py) -------------------------------------------------------------

def _variant(sealed, variant, bundle=None, **kw):
    import lint
    import mutate

    _sealed, root = sealed
    base = root / "base"
    if not base.exists():
        base.mkdir(mode=0o755)
        _sealed.write(base, bundle or _sealed.two_function_bundle())
    source = next(base.iterdir())
    out = root / variant
    out.mkdir(mode=0o755)
    note = mutate.mutate(source, out, variant, **kw)
    rows = lint.run(Path(note["generation"]), _sealed.NAMING_SOURCE, timeout=300, summary=kw.pop("summary", True),
                    options={})[1]
    base_rows = lint.run(source, _sealed.NAMING_SOURCE, timeout=300, summary=False, options={})[1]
    return {row.ident(): row for row in rows}, {row.ident(): row for row in base_rows}, note


SITE = "1:1007:2:CALL"
CALL_KEY = ("operations", "call", "function-000000/" + SITE)


@posix
def test_variant1_seal_digit_refuses_admission_only(sealed):
    rows, _, _ = _variant(sealed, "seal")
    assert rows[("transport", "admission", "bundle")].verdict == "refused"
    assert not any(ident[0] == "operations" for ident in rows)


@posix
def test_variant2_call_ordinal_refuses_the_function_names_and_stops_the_pipeline(sealed):
    rows, _, _ = _variant(sealed, "call-ordinal", function_id="function-000000")
    assert rows[("transport", "naming", "function-000000")].verdict == "refused"
    assert rows[("transport", "naming", "function-000001")].verdict == "applied"
    for path in ("summary", "summary-retain", "base_graph"):
        stop = rows[("pipeline", "stop", path)]
        assert stop.verdict == "applied" and stop.detail["predicted"]["index"] == 0, stop


@posix
@pytest.mark.parametrize("variant", ["call-pattern", "call-swap"])
def test_variants3_and_4_lose_both_recognisers_and_the_relation_but_keep_names(sealed, variant):
    rows, base, note = _variant(sealed, variant, function_id="function-000000", site=SITE)
    for check in ("push_projection", "plain_push", "push_relation"):
        assert base[("operations", check, CALL_KEY[2])].verdict == "applied"
        assert rows[("operations", check, CALL_KEY[2])].verdict == "unrecognized"   # (r1 s2 / r2 s7)
    assert rows[CALL_KEY].verdict == "applied" and rows[CALL_KEY].detail["aliases"] == ["B"]
    assert rows[("transport", "naming", "function-000000")].verdict == "applied"
    # independent SP evidence in the same function (its RET): identification unchanged (r5 s2, r6 s6)
    stack = ("features", "stack_pointer", "function-000000")
    assert rows[stack].verdict == base[stack].verdict == "applied" and rows[stack].detail == base[stack].detail
    assert note.get("meaning_change", False) is (variant == "call-swap")


@posix
def test_variant3b_reshape_moves_the_call_key_and_names_follow(sealed):
    rows, base, note = _variant(sealed, "call-reshape", function_id="function-000000", site=SITE)
    moved = ("operations", "call", "function-000000/1:1007:3:CALL")
    assert CALL_KEY in base and CALL_KEY not in rows and moved in rows
    for check in ("push_projection", "plain_push", "push_relation"):
        assert rows[("operations", check, moved[2])].verdict == "unrecognized"
        assert ("operations", check, CALL_KEY[2]) not in rows
    assert rows[moved].verdict == "applied" and rows[moved].detail["aliases"] == ["B"]


@posix
def test_variant_refuses_a_source_row_that_is_not_a_push_call(sealed):
    import mutate

    with pytest.raises(mutate.VariantError):
        _variant(sealed, "call-pattern", function_id="function-000001", site="1:1800:0:COPY")


@posix
def test_mutate_exit_kind4_and_drop_pad_match_the_fixture_variants(sealed):
    _sealed = sealed[0]
    rows, base, _ = _variant(sealed, "exit-kind4", bundle=_layer2_bundle(_sealed), function_id="function-000001",
                             index=0)
    key = ("operations", "s1_exit", "function-000001/#0")
    assert (base[key].detail["kind"], base[key].detail["reach_edge"]) == (2, True)
    assert (rows[key].detail["kind"], rows[key].detail["function"], rows[key].detail["reach_edge"]) == (4, None, False)
    rows, base, note = _variant(sealed, "drop-pad", function_id="function-000000", site="1:1000:2:CALL")
    call = ("operations", "call", "function-000000/1:1000:2:CALL")
    assert base[call].detail["landing_pads"] == ["1:100a"] and rows[call].detail["landing_pads"] == []


@posix
def test_expect_catches_legal_name_loss(sealed, tmp_path):
    """r2 (Astra P3): RESOLVED_NAMED -> RESOLVED_UNNAMED and a lost alias pass the
    decoder; only the detail comparison of --expect shows them."""
    import lint

    _sealed, root = sealed
    reports = {}
    for name, named in (("named", True), ("unnamed", False)):
        bundle = _sealed.two_function_bundle()
        bundle.functions[1].named = named
        sub = root / name
        sub.mkdir(mode=0o755)
        gen = _sealed.write(sub, bundle)
        out = tmp_path / f"{name}.json"
        lint.main([str(gen), "--no-summary", "--out", str(out)])
        reports[name] = json.loads(out.read_text())
    expect = {"rows": [row for row in reports["named"]["rows"] if row["check"] == "call"]}
    diffs = report.compare(expect, reports["unnamed"])
    assert any("detail.aliases ['B'] != []" in line for line in diffs), diffs
    assert any("detail.resolution 'RESOLVED_NAMED' != 'RESOLVED_UNNAMED'" in line for line in diffs), diffs
    assert report.compare(expect, reports["named"]) == []


# -- guard tests: the engine internals bundle_lint drives (diagnose / layers) ----------

@posix
def test_guard_session_internals_used_by_the_diagnosis_pass():
    import inspect

    from tdo_v2.integration import observed_function_session as session

    slots = session.ObservedFunctionSession.__slots__
    for name in ("_provider_adapter", "_envelope", "_iterator_claimed", "_generation_id"):
        assert name in slots, name
    assert callable(session.ObservedFunctionSession._decode_function)
    assert callable(session._ObservedScopeProvider.collect_function_roles)
    source = inspect.getsource(session._ObservedFunctionIterator.__next__)
    # strict iteration decodes every unit; outcomes keep scope refusals -- the stop rules diagnose.predict mirrors
    assert "self._outcomes and type(unit.scopes.program) is ConstructedProgramScope" in source
    assert 'raise ValueError("observed function scope could not be constructed")' in \
        inspect.getsource(session.ObservedFunctionSession._decode_function)


@posix
def test_guard_standalone_context_matches_the_summary_run():
    """r6 s4: StandaloneContext sets the context variables analyze_units sets
    (EFFECTIVE_OFF is the code-only profile's, not a normalisation input) and
    activates import slots as _analyze_units does."""
    import inspect
    import re

    from tdo_v2 import interprocedural, summary_engine

    source = inspect.getsource(interprocedural.analyze_units)
    assert set(re.findall(r"(\w+)\.set\(", source)) == {
        "IMPORT_SLOTS", "ENTRY_VALUES_NOT_FRAME", "OPAQUE_NO_STACK_ADDRESSES", "PRE_ESCAPE_NOT_FRAME",
        "OPAQUE_RESTORES_SP", "EFFECTIVE_OFF"}
    inner = inspect.getsource(interprocedural._analyze_units)
    assert "IMPORT_SLOTS.get().active = assume_globals_disjoint_from_stack" in inner
    assert "if assume_globals_disjoint_from_stack and program_switches_stack(functions.values()):" in inner
    entry = inspect.getsource(summary_engine.analyze_frozen_bundle_with_summaries)
    assert "ReadOnlyImage(generation_path, image_info)" in entry
    assert "if assume_readonly_image_constant and image_info is not None else None" in entry


@posix
def test_guard_layer_helpers_exist():
    from tdo_v2.integration.configured_target_resolution import _selected_resolved_target  # noqa: F401
    from tdo_v2.interprocedural import _plain_push_call, _program_memory_space  # noqa: F401
    from tdo_v2.may_alias import _stack_pointer, _unit_stub  # noqa: F401
    from tdo_v2.pcode_blocks import _landing_pads  # noqa: F401


@posix
def test_partial_completion_under_a_fixed_run_budget_is_counted_on_both_summary_paths(sealed):
    """r5 s5: success = unique supports.function keys minus failed_functions keys;
    strict and retain report the same (key, reason, detail) under PYTHONHASHSEED=0."""
    import children

    s, root = sealed
    functions = []
    for index in range(6):
        entry = 0x1000 + 0x100 * index
        rows = [s.plain(entry + 3 * k, 3, ("INT_ADD", [s.reg(s.RAX), s.reg(s.RCX)], s.reg(s.RAX))) for k in range(20)]
        rows.append(s.ret(entry + 60))
        functions.append(s.Function(f"F{index}", s.observation(entry, rows)))
    gen = s.write(root, s.Bundle(functions))
    full = children.run_path("summary", gen, s.NAMING_SOURCE, timeout=300)
    assert full["completed"] and full["failed_functions"] == [] and full["work"] > 0
    env = dict(os.environ, TDO_V2_RUN_WORK=str(full["work"] // 2))
    results = [children.run_path(path, gen, s.NAMING_SOURCE, timeout=300, env=env)
               for path in ("summary", "summary-retain", "summary")]
    keys = sorted(f"1:{0x1000 + 0x100 * index:x}" for index in range(6))
    assert full["supported_functions"] == keys and full["succeeded"] == keys
    for out in results:
        assert out["completed"], out
        assert out["supported_functions"] == keys   # (independent of supports: the fixture's own keys)
        assert out["supports_count"] == len(out["supported_functions"])
        failed = {key for key, _, _ in out["failed_functions"]}
        assert {reason for _, reason, _ in out["failed_functions"]} == {"analysis_run_budget"}
        assert out["succeeded"] == sorted(set(out["supported_functions"]) - failed)
        assert failed   # (how many fail depends on where the budget runs out; the count identity is the check)
    assert results[0]["failed_functions"] == results[1]["failed_functions"] == results[2]["failed_functions"]



# -- implementation review r1 fixtures (Fable / Astra) ------------------------------------

@posix
def test_retain_with_a_scope_refusal_is_withheld_not_applied(sealed):
    s = sealed[0]
    a = s.Function("A", s.observation(0x1000, [s.ret(0x1000)]))
    b = s.Function("B", s.observation(0x9000, [s.ret(0x9000)]))     # (scope refusal)
    c = s.Function("C", s.observation(0x1800, [s.ret(0x1800)]))
    rows, _ = _run_lint(sealed, s.Bundle([a, b, c]), "refusal")
    retain = rows[("pipeline", "completion", "summary-retain")]
    assert retain.verdict == "withheld" and "admission refusals" in retain.detail["why"]
    graph = rows[("pipeline", "completion", "base_graph")]
    assert graph.verdict == "withheld" and "admission refusals" in graph.detail["why"]
    assert rows[("pipeline", "stop", "summary")].verdict == "applied"
    # the refused function's own rows, keyed by array index
    assert rows[("operations", "source_row", "function-000001/#0")].detail["address"] == "1:9000"


@posix
def test_base_graph_function_failure_is_withheld(sealed, monkeypatch):
    s = sealed[0]
    monkeypatch.setenv("TDO_V2_FUNCTION_WORK", "1")
    rows, _ = _run_lint(sealed, s.two_function_bundle(), "budget", summary=False)
    graph = rows[("pipeline", "completion", "base_graph")]
    assert graph.detail["failures"] and graph.verdict == "withheld", graph
    assert "failed functions" in graph.detail["why"]


@posix
def test_duplicate_entries_stop_base_graph_and_withhold_the_summaries(sealed):
    s = sealed[0]
    a1 = s.Function("A", s.observation(0x1000, [s.ret(0x1000)]))
    a2 = s.Function("A2", s.observation(0x1000, [s.plain(0x1000, 3, ("COPY", [s.reg(s.RCX)], s.reg(s.RAX))),
                                                 s.ret(0x1003)]))
    rows, _ = _run_lint(sealed, s.Bundle([a1, a2]), "dup")
    stop = rows[("pipeline", "stop", "base_graph")]
    assert stop.verdict == "applied" and stop.detail["predicted"]["stage"] == "publication"
    for path in ("summary", "summary-retain"):
        completion = rows[("pipeline", "completion", path)]
        assert completion.verdict == "withheld" and "duplicate entries" in completion.detail["why"], completion


@posix
def test_call_ordinal_variant_digests_are_exact(sealed):
    """r3 s4: the re-sealed sidecar's row and content digests are the engine's own."""
    import mutate
    from tdo_v2.configured_naming_contracts import CapturedNamingRow, CapturedNamingSidecar

    rows, _, note = _variant(sealed, "call-ordinal", function_id="function-000000")
    generation = Path(note["generation"])
    manifest = json.loads((generation / "manifest.json").read_bytes())
    naming = json.loads((generation / "call-names-000000.json").read_bytes())
    assert naming["calls"][0]["operation_ordinal"] == 3
    typed = tuple(CapturedNamingRow(*mutate._typed_naming_row(raw), bytes.fromhex(raw["row_digest"]))
                  for raw in naming["calls"])   # (raises on a wrong row digest)
    CapturedNamingSidecar(bytes.fromhex(naming["exporter_source_sha256"]), typed,
                          bytes.fromhex(naming["semantic_content_digest"]))   # (raises on a wrong content digest)
    member = next(row for row in manifest["members"] if row["id"] == "call-names-000000")
    import hashlib
    assert member["sha256"] == hashlib.sha256((generation / "call-names-000000.json").read_bytes()).hexdigest()


@posix
def test_trap_index_with_another_operand_is_not_applicable(sealed):
    s = sealed[0]
    f = s.Function("F", s.observation(0x1000, [s.plain(0x1000, 2, ("CALLOTHER", [s.const(16, 4), s.const(0x80, 4)],
                                                                   None)), s.ret(0x1002)]))
    rows, _ = _run_lint(sealed, s.Bundle([f]), "int80", summary=False)
    row = rows[("operations", "callother_model_match", "function-000000/1:1000:0:CALLOTHER")]
    assert row.verdict == "not_applicable" and not row.detail["trap_match"] and "no_model" not in row.detail


@posix
def test_standalone_home_space_follows_the_summary_rule(sealed):
    s = sealed[0]
    pe = s.two_function_bundle()
    pe.image_info = {"schema": "tdo-v2-image-info-1", "executable_format": "Portable Executable (PE)",
                     "block_permissions": [{"block_id": "block-000000", "name": ".text", "read": True,
                                            "write": False, "execute": True, "volatile": False}],
                     "imports": [], "exports": [], "relocations": []}
    rows_pe, _ = _run_lint(sealed, pe, "pe", summary=False, options={"lint_normalize": True})
    rows_raw, _ = _run_lint(sealed, s.two_function_bundle(), "raw", summary=False, options={"lint_normalize": True})
    assert rows_pe[("features", "standalone_context", "program")].detail["private_frame_above"] == 0x28
    assert rows_raw[("features", "standalone_context", "program")].detail["private_frame_above"] == 0


def test_expect_reports_a_missing_detail_key_even_when_null_is_expected():
    expected = report.Row("operations", "s1_exit", "f/#0", "evaluated", "not_applicable", "lint", {"function": None})
    actual = report.Row("operations", "s1_exit", "f/#0", "evaluated", "not_applicable", "lint", {"kind": 4})
    diffs = report.compare({"rows": [expected.as_json()]}, json.loads(report.dumps({}, [actual])))
    assert diffs == ["('operations', 's1_exit', 'f/#0'): detail.function None missing"]


@posix
def test_drop_pad_refuses_a_plain_branch_target(sealed):
    import mutate

    with pytest.raises(mutate.VariantError):
        _variant(sealed, "drop-pad", bundle=_layer2_bundle(sealed[0]), function_id="function-000000",
                 site="1:1005:0:BRANCH")


@posix
def test_guard_engine_rules_the_lint_mirrors():
    import inspect

    from tdo_v2 import control_context, image_info, interprocedural, summary_engine

    assert "0x28 if assume_win64_home_space_private and assume_entry_values_not_frame" in \
        inspect.getsource(summary_engine._analyze_session)
    assert "if block is None or not block.initialized or block.write or block.volatile or not block.read:" in \
        inspect.getsource(image_info.ReadOnlyImage.value)
    assert "if exit_row.function is not None and function_key(exit_row.function) in keys:" in \
        inspect.getsource(control_context)
    assert "(rsp.coordinate.byte_offset, rsp.byte_size) == (0x20, 8)" in inspect.getsource(interprocedural._plain_push_call)
    assert interprocedural._X64_RIP[0] == 0x288


@posix
def test_observation_parse_failure_is_reported_apart_from_a_scope_refusal(sealed):
    """r3 s2: an unparsable observation is a transport failure that stops every
    path (role capture), not a per-function scope refusal; later functions are
    never claimed."""
    s = sealed[0]
    a = s.Function("A", s.observation(0x1000, [s.ret(0x1000)]))
    b = s.Function("B", s.observation(0x1800, [s.ret(0x1800)]))
    c = s.Function("C", s.observation(0x9000, [s.ret(0x9000)]))     # (would be a scope refusal)
    rows, _ = _run_lint(sealed, s.Bundle([a, b, c], overrides={"function-000001": b"{"}), "parse")
    fatal = rows[("transport", "scoped_iterator", "bundle")]
    assert fatal.verdict == "refused" and fatal.detail["index"] == 1
    assert ("transport", "function_scope", "function-000001") not in rows
    assert ("transport", "function_scope", "function-000002") not in rows
    for path in ("summary", "summary-retain", "base_graph"):
        stop = rows[("pipeline", "stop", path)]
        assert stop.verdict == "applied" and stop.detail["predicted"]["stage"] == "transport"


@posix
def test_a_shared_instruction_gives_one_row_per_function(sealed):
    s = sealed[0]
    shared = [s.plain(0x1004, 3, ("COPY", [s.reg(s.RCX)], s.reg(s.RAX))), s.call(0x1007, 0x1800), s.ret(0x100C)]
    a = s.Function("A", s.observation(0x1000, [s.plain(0x1000, 4, ("COPY", [s.const(1)], s.reg(s.RCX))), *shared]))
    a2 = s.Function("A2", s.observation(0x1004, shared))
    b = s.Function("B", s.observation(0x1800, [s.ret(0x1800)]))
    rows, _ = _run_lint(sealed, s.Bundle([a, a2, b]), "shared", summary=False)
    assert ("operations", "call", "function-000000/1:1007:2:CALL") in rows
    assert ("operations", "call", "function-000001/1:1007:2:CALL") in rows



# -- implementation review r2 fixtures (Astra / Fable) ------------------------------------

@posix
def test_a_malformed_source_address_is_reported_not_fatal(sealed):
    s = sealed[0]
    a = s.Function("A", s.observation(0x1000, [s.ret(0x1000)]))
    bad = s.observation(0x1800, [s.ret(0x1800)])
    bad["instructions"][0]["address"] = {}
    rows, _ = _run_lint(sealed, s.Bundle([a, s.Function("B", bad)]), "malformed")
    assert rows[("transport", "function_scope", "function-000001")].verdict == "refused"
    assert rows[("operations", "source_row", "function-000001/#0")].detail["address"].startswith("malformed:")
    assert rows[("pipeline", "completion", "base_graph")].run_state == "evaluated"


@posix
def test_callind_push_is_recognised_and_plain_push_is_direct_only(sealed):
    s = sealed[0]
    callind = s.row(0x1000, 5, s.ops(("INT_SUB", [s.reg(s.RSP), s.const(8)], s.reg(s.RSP)),
                                     ("STORE", [s.const(s.RAM), s.reg(s.RSP), s.const(0x1005)], None),
                                     ("CALLIND", [s.reg(s.RAX)], None)), s.CALL_FLOW, 0x1005, [])
    f = s.Function("F", s.observation(0x1000, [callind, s.ret(0x1005)]))
    rows, _ = _run_lint(sealed, s.Bundle([f]), "callind", summary=False)
    key = "function-000000/1:1000:2:CALLIND"
    assert rows[("operations", "push_projection", key)].verdict == "applied"
    assert rows[("operations", "push_relation", key)].verdict == "applied"
    assert rows[("operations", "plain_push", key)].verdict == "not_applicable"


@posix
def test_branchind_unknown_transfer_follows_the_engine_predicate(sealed):
    s = sealed[0]
    jump = s.flow(is_flow=True, is_jump=True, is_computed=True, is_unconditional=True)
    # BRANCHIND with no listed target but a fallthrough; and BRANCHIND followed by a COPY
    first = s.row(0x1000, 2, s.ops(("BRANCHIND", [s.reg(s.RAX)], None)), jump, 0x1002, [])
    second = s.row(0x1002, 2, s.ops(("BRANCHIND", [s.reg(s.RAX)], None), ("COPY", [s.reg(s.RCX)], s.reg(s.RDX))),
                   jump, 0x1004, [])
    f = s.Function("F", s.observation(0x1000, [first, second, s.ret(0x1004)]))
    rows, _ = _run_lint(sealed, s.Bundle([f]), "branchind", summary=False)
    found = {ident: row for ident, row in rows.items() if ident[1] == "branchind"}
    assert rows[("transport", "function_scope", "function-000000")].verdict == "applied"
    assert len(found) == 2, found
    assert all(row.verdict == "withheld" and row.detail["unknown_transfer"] for row in found.values())


@posix
def test_drop_pad_with_a_repeated_pad_shrinks_the_validated_set(sealed):
    s = sealed[0]
    bundle = _layer2_bundle(s)
    bundle.functions[0].observation["instructions"][0]["flow_targets"].append(s.coord(0x100A))
    rows, base, note = _variant(sealed, "drop-pad", bundle=bundle, function_id="function-000000",
                                site="1:1000:2:CALL")
    call = ("operations", "call", "function-000000/1:1000:2:CALL")
    assert base[call].detail["landing_pads"] == ["1:100a"] and rows[call].detail["landing_pads"] == []


@posix
def test_a_variant_refused_by_its_source_conditions_writes_nothing(sealed):
    """No validated pad besides the fallthrough: refused before the copy (a
    failure after the copy is renamed .failed[.N]: see the unreachable test)."""
    import mutate

    _sealed, root = sealed
    with pytest.raises(mutate.VariantError, match="no validated landing pad"):
        _variant(sealed, "drop-pad", function_id="function-000000", site="1:1007:2:CALL")   # (no pad)
    assert list((root / "drop-pad").iterdir()) == []


@posix
def test_duplicate_entry_s1_edges_come_from_the_kept_member_only(sealed):
    s = sealed[0]
    first = s.Function("E1", s.observation(0x17F0, [s.plain(0x17F0, 3, ("COPY", [s.reg(s.RCX)], s.reg(s.RAX))),
                                                    s.plain(0x17F3, 13, ("COPY", [s.reg(s.RCX)], s.reg(s.RDX)))],
                                           exits=[_exit(0x17F3, 0x1800, 2, 0x1800)]))
    last = s.Function("E2", s.observation(0x17F0, [s.ret(0x17F0)]))
    b = s.Function("B", s.observation(0x1800, [s.ret(0x1800)]))
    rows, _ = _run_lint(sealed, s.Bundle([first, last, b]), "dups1", summary=False, options={"lint_normalize": True})
    exit_row = rows[("operations", "s1_exit", "function-000000/#0")]
    assert exit_row.detail["reach_edge"] is False and exit_row.detail["superseded_by_duplicate_entry"]
    assert ("features", "standalone_normalize", "function-000000") in rows      # (every member normalised)
    assert rows[("features", "standalone_normalize", "function-000000")].detail.get("superseded_by_duplicate_entry")


@posix
def test_guard_session_step_order_and_helpers():
    import inspect

    from tdo_v2 import isa_identity
    from tdo_v2.integration import observed_function_session as session
    from tdo_v2.integration.configured_bundle import _safe_name  # noqa: F401

    source = inspect.getsource(session.ObservedFunctionSession._decode_function)
    order = [source.index(text) for text in ("seeds = seed_function_calls(unit)", "tails = seed_tail_calls(unit)",
                                             "naming = decode_configured_naming(")]
    assert order == sorted(order)
    nxt = inspect.getsource(session._ObservedFunctionIterator.__next__)
    assert nxt.index("unit = next(self._scoped)") < nxt.index("captured = adapter.collect_function_roles()")
    for table in ("_STACK_REGISTERS", "_LINK_REGISTERS", "_PROGRAM_COUNTERS"):
        assert isinstance(getattr(isa_identity, table), dict)


def test_guard_engine_language_literals_are_inventoried():
    """Convention keys (r1 s5): language-id literals in the engine, counted per
    file. A new literal (or file) fails here until it is modelled (ops_layer
    FIXED_OFFSETS / convention rows) or listed in the README."""
    import re

    pattern = re.compile(r"[\"'](x86|AARCH64|ARM)[:\"']")
    src = REPO / "src" / "tdo_v2"
    found = {path.relative_to(src).as_posix(): len(pattern.findall(path.read_text(encoding="utf-8")))
             for path in src.rglob("*.py")}
    assert {name: count for name, count in found.items() if count} == LANGUAGE_LITERALS


LANGUAGE_LITERALS = {
    "code_only_profile.py": 2, "fault_premise.py": 2, "integration/configured_dynamic_alias_explanation.py": 1,
    "integration/configured_finite_byte_kernel.py": 1, "integration/configured_finite_context_scheduler.py": 1,
    "interprocedural.py": 1, "intrinsic_refinements.py": 2, "intrinsic_semantics.py": 1, "isa_identity.py": 7,
    "linking.py": 2, "may_alias.py": 2, "operation_records.py": 1, "return_relations.py": 3, "summary_engine.py": 1,
    "summary_store.py": 1, "summary_templates.py": 1,
}



# -- implementation review r3 fixtures (Astra / Fable) ------------------------------------

@posix
def test_drop_pad_refuses_when_the_pad_code_would_become_unreachable(sealed):
    import mutate

    s, root = sealed
    a = s.Function("A", s.observation(0x1000, [
        s.call(0x1000, 0x1800, targets=[0x1800, 0x1010]),
        s.ret(0x1005),
        s.plain(0x1010, 4, ("COPY", [s.reg(s.RCX)], s.reg(s.RAX))),
        s.row(0x1014, 2, s.ops(("BRANCH", [s.ram(0x1010)], None)),
              s.flow(is_flow=True, is_jump=True, is_unconditional=True), None, [0x1010])]))
    b = s.Function("B", s.observation(0x1800, [s.ret(0x1800)]))
    base = root / "base"
    base.mkdir(mode=0o755)
    source = s.write(base, s.Bundle([a, b]))
    out = root / "out"
    out.mkdir(mode=0o755)
    for _ in range(2):   # (a second failure gets a fresh name; nothing is deleted)
        with pytest.raises(mutate.VariantError, match="reachable from the entry"):
            mutate.mutate(source, out, "drop-pad", function_id="function-000000", site="1:1000:2:CALL")
    assert sorted(path.name[len(source.name):] for path in out.iterdir()) == [".failed", ".failed.1"]


def _aarch64_bundle(s, *, pc=True):
    pc_off, sp_off, x30 = 0x0, 0x8, 0x4000 + 8 * 30
    registers = (("sp", sp_off), ("x30", x30)) + ((("pc", pc_off),) if pc else ())
    program = s.program(registers=registers, language=("AARCH64:LE:64:v8A", 1, 6))
    call_flow = s.CALL_FLOW
    push = s.row(0x1000, 4, s.ops(("INT_SUB", [s.reg(sp_off), s.const(8)], s.reg(sp_off)),
                                  ("STORE", [s.const(s.RAM), s.reg(sp_off), s.const(0x1004)], None),
                                  ("CALL", [s.ram(0x1800)], None)), call_flow, 0x1004, [0x1800])
    bl = s.row(0x1004, 4, s.ops(("INT_ADD", [s.const(0x1004), s.const(4)], s.reg(x30)),
                                ("CALL", [s.ram(0x1800)], None)), call_flow, 0x1008, [0x1800])
    ret = s.row(0x1008, 4, s.ops(("COPY", [s.reg(x30)], s.reg(pc_off)), ("RETURN", [s.reg(pc_off)], None)),
                s.RET_FLOW)
    b = s.Function("B", s.observation(0x1800, [s.row(0x1800, 4, s.ops(("RETURN", [s.reg(x30)], None)),
                                                     s.RET_FLOW)]))
    return s.Bundle([s.Function("A", s.observation(0x1000, [push, bl, ret])), b], program=program)


@posix
def test_aarch64_push_is_reported_and_link_needs_its_evidence(sealed):
    s = sealed[0]
    rows, _ = _run_lint(sealed, _aarch64_bundle(s), "a64", summary=False)
    assert rows[("transport", "function_scope", "function-000000")].verdict == "applied"
    push_key, bl_key = "function-000000/1:1000:2:CALL", "function-000000/1:1004:1:CALL"
    assert rows[("operations", "push_projection", push_key)].verdict == "applied"   # (never hidden)
    assert rows[("operations", "push_projection", bl_key)].verdict == "not_applicable"   # (no flood)
    assert rows[("operations", "plain_push", push_key)].verdict == "not_applicable"   # (x86-64 literal shape)
    assert rows[("operations", "link_relation", bl_key)].verdict == "applied"
    no_pc, _ = _run_lint(sealed, _aarch64_bundle(s, pc=False), "a64nopc", summary=False)
    assert no_pc[("operations", "link_relation", bl_key)].verdict == "withheld"


@posix
def test_duplicate_image_info_rows_get_distinct_keys(sealed):
    s = sealed[0]
    bundle = s.two_function_bundle(blocks=[s.Block(start=0x1000), s.Block(start=0x2000, data=b"\0" * 0x100)])
    row = {"block_id": "block-000000", "name": ".text", "read": True, "write": False, "execute": True,
           "volatile": False}
    bundle.image_info = {"schema": "tdo-v2-image-info-1", "executable_format": "Raw Binary",
                         "block_permissions": [row, dict(row)], "imports": [], "exports": [], "relocations": []}
    rows, _ = _run_lint(sealed, bundle, "dupinfo", summary=False)
    assert rows[("transport", "image_info", "bundle")].verdict == "applied"
    assert ("transport", "readonly_block", "#0/1:1000") in rows and ("transport", "readonly_block", "#1/1:1000") in rows


@posix
def test_branchind_through_an_import_slot_is_exempted_in_the_final_column(sealed):
    s = sealed[0]
    jump = s.row(0x1000, 6, s.ops(("BRANCHIND", [s.ram(0x1F00)], None)),
                 s.flow(is_flow=True, is_jump=True, is_computed=True, is_terminal=True, is_unconditional=True))
    bundle = s.Bundle([s.Function("F", s.observation(0x1000, [jump]))])
    bundle.image_info = {"schema": "tdo-v2-image-info-1", "executable_format": "Raw Binary",
                         "block_permissions": [{"block_id": "block-000000", "name": ".text", "read": True,
                                                "write": False, "execute": True, "volatile": False}],
                         "imports": [{"library": "KERNEL32.DLL", "name": "ExitProcess", "original_name": None,
                                      "slots": [s.coord(0x1F00)], "thunks": []}],
                         "exports": [], "relocations": []}
    rows, _ = _run_lint(sealed, bundle, "imptail")
    key = "function-000000/control:1:1000:1:1000"
    assert rows[("operations", "branchind", key)].verdict == "withheld"
    final = rows[("pipeline", "branchind_final", key)]
    assert (final.run_state, final.verdict, final.detail["final"]) == ("evaluated", "applied", "exempted"), final
    assert final.detail["exemptions"]


@posix
def test_f2_standalone_is_not_reached_like_the_summaries(sealed):
    s = sealed[0]
    rows, _ = _run_lint(sealed, s.two_function_bundle(overrides={"image-info": b'{"schema":"bad"}'}), "f2n",
                        summary=False, options={"lint_normalize": True})
    assert rows[("features", "standalone_context", "program")].run_state == "not_reached"
    assert not any(ident[1] == "standalone_normalize" for ident in rows)


@posix
def test_exit_kind4_refuses_an_exit_without_a_reach_edge(sealed):
    import mutate

    s = sealed[0]
    bundle = _layer2_bundle(s)
    bundle.functions = [bundle.functions[0], bundle.functions[1]]   # (B dropped: the exit's function is absent)
    bundle.functions[0].observation["instructions"][0]["flow_targets"] = [s.coord(0x1800)]
    with pytest.raises(mutate.VariantError):
        _variant(sealed, "exit-kind4", bundle=bundle, function_id="function-000001", index=0)


@posix
def test_superseded_mark_lands_on_the_normalize_row(sealed):
    """Through feature_layer.rows(): a replaced member with a read-only use gets the
    mark on its standalone_normalize row only (Fable r3 P2-1, Astra r4 P3)."""
    s = sealed[0]
    first = _slot_bundle(s).functions[0]
    second = s.Function("F2", s.observation(0x1000, [s.ret(0x1000)]))
    bundle = _slot_bundle(s)
    bundle.functions = [first, second]
    rows, _ = _run_lint(sealed, bundle, "mark", summary=False, options={"lint_normalize": True})
    assert rows[("features", "standalone_normalize", "function-000000")].detail.get("superseded_by_duplicate_entry")
    assert not rows[("features", "readonly_use", "function-000000/1:1f00")].detail
    assert "superseded_by_duplicate_entry" not in rows[("features", "standalone_normalize", "function-000001")].detail



# -- implementation review r4 (Astra fix specs adopted) ------------------------------------

@posix
def test_drop_pad_refuses_an_instruction_with_two_calls(sealed):
    import mutate

    s = sealed[0]
    two = s.row(0x1000, 5, s.ops(("INT_SUB", [s.reg(s.RSP), s.const(8)], s.reg(s.RSP)),
                                 ("STORE", [s.const(s.RAM), s.reg(s.RSP), s.const(0x1005)], None),
                                 ("CALL", [s.ram(0x1800)], None), ("CALL", [s.ram(0x1800)], None)),
                s.CALL_FLOW, 0x1005, [0x1800, 0x100A])
    jump = s.row(0x1005, 5, s.ops(("BRANCH", [s.ram(0x100A)], None)),
                 s.flow(is_flow=True, is_jump=True, is_unconditional=True), None, [0x100A])
    bundle = s.Bundle([s.Function("A", s.observation(0x1000, [two, jump, s.ret(0x100A)])),
                       s.Function("B", s.observation(0x1800, [s.ret(0x1800)]))])
    with pytest.raises(mutate.VariantError, match="only call"):
        _variant(sealed, "drop-pad", bundle=bundle, function_id="function-000000", site="1:1000:2:CALL")


@posix
def test_drop_pad_accepts_a_pad_reached_by_a_branch_operand_only(sealed):
    s = sealed[0]
    bundle = _layer2_bundle(s)
    bundle.functions[0].observation["instructions"][1]["flow_targets"] = []   # (BRANCH lists no target)
    rows, base, _ = _variant(sealed, "drop-pad", bundle=bundle, function_id="function-000000",
                             site="1:1000:2:CALL")
    call = ("operations", "call", "function-000000/1:1000:2:CALL")
    assert base[call].detail["landing_pads"] == ["1:100a"] and rows[call].detail["landing_pads"] == []


@posix
def test_branchind_final_of_a_replaced_member_is_not_reached(sealed):
    s = sealed[0]
    jump = s.flow(is_flow=True, is_jump=True, is_computed=True, is_terminal=True, is_unconditional=True)
    first = s.Function("F1", s.observation(0x1000, [s.row(0x1000, 2, s.ops(("BRANCHIND", [s.reg(s.RAX)], None)),
                                                          jump)]))
    last = s.Function("F2", s.observation(0x1000, [s.ret(0x1000)]))
    rows, _ = _run_lint(sealed, s.Bundle([first, last]), "dupbi")
    key = "function-000000/control:1:1000:1:1000"
    assert rows[("operations", "branchind", key)].verdict == "withheld"
    final = rows[("pipeline", "branchind_final", key)]
    assert (final.run_state, final.verdict) == ("not_reached", None) and "final" not in final.detail, final


@posix
def test_a_non_finite_number_in_a_refused_member_keeps_the_report_strict_json(sealed, tmp_path):
    import lint

    s, root = sealed
    bad = s.observation(0x1800, [s.ret(0x1800)])
    data = s.dumps(bad).replace(b'"opcode":"RETURN"', b'"opcode":1e400')
    bundle = s.Bundle([s.Function("A", s.observation(0x1000, [s.ret(0x1000)])), s.Function("B", bad)],
                      overrides={"function-000001": data})
    sub = root / "nan"
    sub.mkdir(mode=0o755)
    gen = s.write(sub, bundle)
    out = tmp_path / "r.json"
    assert lint.main([str(gen), "--no-summary", "--out", str(out)]) == 0

    def refuse(name):
        raise ValueError(name)

    report_json = json.loads(out.read_text(), parse_constant=refuse)
    rows = {(r["layer"], r["check"], r["key"]): r for r in report_json["rows"]}
    assert rows[("transport", "function_scope", "function-000001")]["verdict"] == "refused"
    assert rows[("operations", "source_row", "function-000001/#0")]["detail"]["opcodes"][2] is None


@posix
def test_exit_kind4_refuses_a_replaced_member_and_a_remaining_direct_call(sealed):
    import mutate

    s = sealed[0]
    dup = _layer2_bundle(s)
    dup.functions.insert(2, s.Function("E2", s.observation(0x17F0, [s.ret(0x17F0)])))   # (replaces E)
    with pytest.raises(mutate.VariantError):
        _variant(sealed, "exit-kind4", bundle=dup, function_id="function-000001", index=0)


@posix
def test_exit_kind4_refuses_when_a_direct_call_keeps_the_edge(sealed):
    import mutate

    s = sealed[0]
    bundle = _layer2_bundle(s)
    e = bundle.functions[1].observation
    e["instructions"][0] = s.call(0x17F0, 0x1800, length=3)
    e["instructions"][0]["fallthrough"] = s.coord(0x17F3)
    e["instructions"][0]["operations"][1]["inputs"][2] = s.const(0x17F3)
    with pytest.raises(mutate.VariantError):
        _variant(sealed, "exit-kind4", bundle=bundle, function_id="function-000001", index=0)


@posix
@pytest.mark.parametrize("variant", ["call-pattern", "call-reshape", "call-swap"])
def test_call_variants_refuse_when_the_push_is_the_only_sp_evidence(sealed, variant):
    import mutate

    s = sealed[0]
    bare_ret = s.row(0x100C, 1, s.ops(("RETURN", [s.reg(s.RIP)], None)), s.RET_FLOW)
    a = s.Function("A", s.observation(0x1000, [s.plain(0x1000, 7, ("COPY", [s.const(23)], s.reg(s.RCX))),
                                               s.call(0x1007, 0x1800), bare_ret]))
    bundle = s.Bundle([a, s.Function("B", s.observation(0x1800, [s.ret(0x1800)]))])
    with pytest.raises(mutate.VariantError, match="stack identification"):
        _variant(sealed, variant, bundle=bundle, function_id="function-000000", site=SITE)


@posix
def test_unknown_isa_push_projection_and_return_shape_rows(sealed):
    s = sealed[0]
    bundle = s.two_function_bundle(program=s.program(language=("custom:LE:64:test", 1, 0)))
    rows, _ = _run_lint(sealed, bundle, "custom", summary=False)
    if rows[("transport", "program", "bundle")].verdict != "applied":
        pytest.fail("the custom language program is refused")
    assert rows[("operations", "push_projection", "function-000000/" + SITE)].verdict == "applied"
    ref, _ = _run_lint(sealed, s.two_function_bundle(), "rets", summary=False)
    assert ref[("operations", "return_shape", "function-000000/1:100c:2:RETURN")].verdict == "applied"
    bare = s.two_function_bundle()
    bare.functions[1].observation["instructions"][1] = s.row(0x1803, 1, s.ops(("RETURN", [s.reg(s.RIP)], None)),
                                                             s.RET_FLOW)
    rows_bare, _ = _run_lint(sealed, bare, "bare", summary=False)
    assert rows_bare[("operations", "return_shape", "function-000001/1:1803:0:RETURN")].verdict == "unrecognized"


@posix
def test_resource_failures_are_errors(sealed, monkeypatch):
    import children
    import diagnose
    import layers
    import lint
    from tdo_v2 import image_info
    from tdo_v2.resource_limits import BoundExceeded

    s, root = sealed
    gen = s.write(root, s.two_function_bundle())

    def boom(path):
        raise MemoryError("synthetic")

    monkeypatch.setattr(image_info, "load_image_info", boom)
    found = diagnose.diagnose(gen, s.NAMING_SOURCE)
    row = next(r for r in layers.transport_rows(found) if r.check == "image_info")
    assert (row.run_state, row.verdict) == ("error", None)
    error = children._error(BoundExceeded("synthetic"))
    assert error["resource"] is True
    child = {"run_state": "evaluated", "completed": False, "exception": error}
    rows = {r.ident(): r for r in lint.pipeline_rows({"claims": []}, {"summary": None}, {"summary": child})}
    assert rows[("pipeline", "completion", "summary")].run_state == "error"
    assert rows[("pipeline", "stop", "summary")].run_state == "error"


@posix
def test_standalone_not_reached_when_the_program_is_refused(sealed):
    s = sealed[0]
    bundle = s.two_function_bundle(program=s.program(image_base=0x1004))
    rows, _ = _run_lint(sealed, bundle, "noprog", summary=False, options={"lint_normalize": True})
    assert rows[("transport", "program", "bundle")].verdict == "refused"
    assert rows[("features", "standalone_context", "program")].run_state == "not_reached"


def test_cli_refuses_a_missing_naming_source(tmp_path):
    import lint

    assert lint.main([str(tmp_path), "--naming-source", str(tmp_path / "missing.java"),
                      "--out", str(tmp_path / "r.json")]) == 2



# -- implementation review r5 (Astra fix specs adopted; Fable r4) ------------------------

@posix
def test_drop_pad_never_picks_the_fallthrough_even_with_an_extra_field(sealed):
    s = sealed[0]
    bundle = _layer2_bundle(s)
    targets = bundle.functions[0].observation["instructions"][0]["flow_targets"]
    targets.append({**s.coord(0x1005), "ignored": 1})   # (the fallthrough, listed with an ignored key)
    rows, base, note = _variant(sealed, "drop-pad", bundle=bundle, function_id="function-000000",
                                site="1:1000:2:CALL")
    assert note["dropped"] == "1:100a"
    call = ("operations", "call", "function-000000/1:1000:2:CALL")
    assert "1:1005" in rows[call].detail["flow_targets"]


@posix
def test_drop_pad_refuses_a_pad_that_is_another_functions_entry(sealed):
    import mutate

    s = sealed[0]
    bundle = _layer2_bundle(s)
    bundle.functions[0].observation["instructions"][1]["flow_targets"] = []   # (pad reached by the operand only)
    bundle.functions.append(s.Function("C", s.observation(0x100A, [s.ret(0x100A)])))
    with pytest.raises(mutate.VariantError, match="inter-function"):
        _variant(sealed, "drop-pad", bundle=bundle, function_id="function-000000", site="1:1000:2:CALL")


@posix
def test_call_pattern_keeps_the_constant_width_and_refuses_a_narrow_one(sealed):
    import mutate

    s = sealed[0]
    rows, base, note = _variant(sealed, "call-pattern", function_id="function-000000", site=SITE)
    observation = json.loads((Path(note["generation"]) / "function-000000.json").read_bytes())
    constant = observation["instructions"][1]["operations"][0]["inputs"][1]
    assert (constant["byte_offset"], constant["byte_size"]) == ((1 << 64) - 8, 8)
    narrow = s.two_function_bundle()
    narrow.functions[0].observation["instructions"][1]["operations"][0]["inputs"][1] = s.const(8, 1)
    sealed[1].joinpath("narrow").mkdir(mode=0o755)
    source = s.write(sealed[1] / "narrow", narrow)
    out = sealed[1] / "narrow_out"
    out.mkdir(mode=0o755)
    with pytest.raises(mutate.VariantError):
        mutate.mutate(source, out, "call-pattern", function_id="function-000000", site=SITE)


@posix
def test_call_ordinal_refuses_when_a_path_stops_before_the_target(sealed):
    import mutate

    s = sealed[0]
    bundle = s.two_function_bundle(overrides={"call-names-000000": b"{"})
    bundle.functions[1].observation["instructions"].insert(0, s.call(0x17F0, 0x1000, length=5))
    bundle.functions[1].observation["entry"] = s.coord(0x17F0)
    bundle.functions[1].observation["instructions"][1] = s.plain(0x17F5, 3, ("COPY", [s.reg(s.RCX)], s.reg(s.RAX)))
    bundle.functions[1].observation["instructions"][0]["fallthrough"] = s.coord(0x17F5)
    bundle.functions[1].observation["instructions"][0]["operations"][1]["inputs"][2] = s.const(0x17F5)
    bundle.functions[1].observation["instructions"][2] = s.ret(0x17F8)
    root = sealed[1]
    (root / "co").mkdir(mode=0o755)
    source = s.write(root / "co", bundle)
    (root / "co_out").mkdir(mode=0o755)
    with pytest.raises(mutate.VariantError):
        mutate.mutate(source, root / "co_out", "call-ordinal", function_id="function-000001")


@posix
def test_exit_kind4_refuses_when_a_resolved_callind_keeps_the_edge(sealed):
    import mutate

    s = sealed[0]
    # (Ghidra's ``call rax``: the target copied first, then the push and CALLIND of the copy)
    callind = s.row(0x17E7, 5, s.ops(("COPY", [s.reg(s.RAX)], s.unique(0x100)),
                                     ("INT_SUB", [s.reg(s.RSP), s.const(8)], s.reg(s.RSP)),
                                     ("STORE", [s.const(s.RAM), s.reg(s.RSP), s.const(0x17EC)], None),
                                     ("CALLIND", [s.unique(0x100)], None)), s.CALL_FLOW, 0x17EC, [])
    e = s.Function("E", s.observation(0x17E0, [s.plain(0x17E0, 7, ("COPY", [s.const(0x1800)], s.reg(s.RAX))),
                                               callind, s.plain(0x17EC, 20, ("COPY", [s.reg(s.RCX)], s.reg(s.RDX)))],
                                      exits=[_exit(0x17EC, 0x1800, 2, 0x1800)]))
    b = s.Function("B", s.observation(0x1800, [s.ret(0x1800)]))
    with pytest.raises(mutate.VariantError):
        _variant(sealed, "exit-kind4", bundle=s.Bundle([e, b]), function_id="function-000000", index=0)


def test_a_diagnosis_resource_failure_makes_completion_an_error_and_keeps_the_childs_keys():
    import lint

    diagnosis = {"claims": [{"scope": "constructed", "naming": "error", "entry": "1:1000",
                             "naming_error": {"class": "builtins.MemoryError", "message": "", "resource": True}}]}
    child = {"run_state": "evaluated", "completed": True, "supports_count": 1, "supported_functions": ["1:1000"],
             "succeeded": ["1:1000"], "failed_functions": [], "admission_failures": [], "assumptions": [],
             "control_exemptions": [], "fault_report": [], "control_sites": []}
    rows = {r.ident(): r for r in lint.pipeline_rows(diagnosis, {"summary": None}, {"summary": child})}
    completion = rows[("pipeline", "completion", "summary")]
    assert (completion.run_state, completion.verdict) == ("error", None)
    assert completion.detail["succeeded"] == ["1:1000"]


def test_site_states_follow_reach_not_a_blanket_rule():
    import feature_layer
    import lint
    import report as r

    done = {"run_state": "evaluated", "completed": True, "failed_functions": [], "control_exemptions": [],
            "control_sites": [["control:1:1000:1:1000", "import-tail-reentry", "1:1000", "()"]], "fault_report": []}
    rep_row = r.Row("operations", "rep_site", "f/1:1000", "evaluated", "applied", "engine",
                    {"superseded_by_duplicate_entry": True})
    (row,) = feature_layer.trap_application_rows([rep_row], {"summary": done}, {})
    assert row.run_state == "not_reached"
    boom = {"run_state": "evaluated", "completed": False,
            "exception": {"class": "tdo_v2.resource_limits.BoundExceeded", "message": "x", "resource": True}}
    assert feature_layer.site_state({"summary": boom}, False)[0] == "error"
    branch = r.Row("operations", "branchind", "f/control:1:1000:1:1000", "evaluated", "withheld", "engine",
                   {"unknown_transfer": True})
    (final,) = lint.branchind_final_rows([branch], {"summary": done})
    assert (final.run_state, final.verdict, final.detail["final"]) == ("evaluated", "withheld", "import-tail-reentry")
    (error,) = lint.branchind_final_rows([branch], {"summary": boom})
    assert (error.run_state, error.verdict) == ("error", None)


@posix
def test_site_rows_read_retain_when_strict_stopped(sealed):
    s = sealed[0]
    jump = s.flow(is_flow=True, is_jump=True, is_computed=True, is_terminal=True, is_unconditional=True)
    a = s.Function("A", s.observation(0x1000, [s.ret(0x1000)]))
    b = s.Function("B", s.observation(0x9000, [s.ret(0x9000)]))   # (scope refusal: strict stops)
    c = s.Function("C", s.observation(0x1800, [s.row(0x1800, 2, s.ops(("BRANCHIND", [s.reg(s.RAX)], None)), jump)]))
    rows, _ = _run_lint(sealed, s.Bundle([a, b, c]), "retainsite")
    final = rows[("pipeline", "branchind_final", "function-000002/control:1:1800:1:1800")]
    assert final.run_state == "evaluated" and final.detail["run"] == "summary-retain", final


@posix
@pytest.mark.parametrize("first_writable", [True, False])
def test_readonly_block_rows_follow_the_row_the_engine_selects(sealed, first_writable):
    s = sealed[0]
    bundle = s.two_function_bundle(blocks=[s.Block(start=0x1000), s.Block(start=0x2000, data=bytes(0x100))])
    rows_info = [{"block_id": "block-000000", "name": ".text", "read": True, "write": write, "execute": True,
                  "volatile": False} for write in (first_writable, not first_writable)]
    bundle.image_info = {"schema": "tdo-v2-image-info-1", "executable_format": "Raw Binary",
                         "block_permissions": rows_info, "imports": [], "exports": [], "relocations": []}
    rows, _ = _run_lint(sealed, bundle, f"sel{first_writable}", summary=False)
    first, second = rows[("transport", "readonly_block", "#0/1:1000")], rows[("transport", "readonly_block", "#1/1:1000")]
    assert first.verdict == ("not_applicable" if first_writable else "applied")
    assert (second.run_state, second.detail["selected_row"]) == ("not_reached", 0)
