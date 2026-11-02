"""2b-P P-c2 (design r5 B): a published result's support closes over the exact
analysis instances it consumed -- never the latest result of a key -- with
recorded uses kept apart from policy padding and bridges, and every unknown
label or missing producer an obligation of whatever reaches it."""

from dataclasses import replace

import pytest

from synthetic import CODE_BASE, DATA_BASE, RAX, RCX, RSP, FunctionBuilder, add, const, copy, load, program_units, reg, \
    store
from tdo_v2.interprocedural import AnalyzedFunction, _Hypothesis, analyze_units
from tdo_v2.premises import PremiseResolver, registry_premise
from tdo_v2.producer_support import producer_supports

MAIN, LEAF, OTHER = 0x1000, CODE_BASE + 0x800, CODE_BASE + 0x900
GLOBALS = registry_premise("globals-disjoint-from-stack")


def _leaf(entry=LEAF):
    """A global write: decided apart from the stack only under globals-disjoint."""
    return FunctionBuilder(entry=entry).ins(store(const(DATA_BASE + 0x40), const(1, 8))).ret()


def _plain(entry=LEAF):
    return FunctionBuilder(entry=entry).ins(copy(reg(RAX), const(1))).ret()


def _caller(*targets, entry=MAIN):
    body = FunctionBuilder(entry=entry).sub_rsp(0x28)
    for target in targets:
        body.call(target)
    return body.add_rsp(0x28).ret()


def _key(entry):
    return f"1:{entry:x}"


def _premise_ids(closure):
    return {premise.id for premise in closure.premises}


def test_a_callers_closure_carries_the_consumed_summarys_uses_exactly():
    results = analyze_units(program_units(_caller(LEAF), _leaf()), assume_globals_disjoint_from_stack=True)
    caller, leaf = results[_key(MAIN)], results[_key(LEAF)]
    (call,) = caller.consumed
    assert caller.consumed[call] == (leaf,) and caller.consumed[call][0] is leaf
    supports, closures = producer_supports(results, PremiseResolver())
    assert "globals-disjoint-from-stack" in {use.premise.id for use in supports[f"{_key(LEAF)}#0"].uses}
    assert supports[f"{_key(MAIN)}#0"].depends == (f"{_key(LEAF)}#0",)
    assert any(use.premise == GLOBALS and use.at.startswith(f"{_key(LEAF)}#0/")
               for use in closures[_key(MAIN)].uses)
    assert closures[_key(MAIN)].established


def test_recording_is_kept_whether_or_not_operation_records_are_on():
    provenance: dict = {}
    on = analyze_units(program_units(_caller(LEAF), _leaf()), record_provenance=provenance)
    off = analyze_units(program_units(_caller(LEAF), _leaf()))
    assert provenance and on[_key(MAIN)].consumed and off[_key(MAIN)].consumed
    assert off[_key(MAIN)].consumed[next(iter(off[_key(MAIN)].consumed))] == (off[_key(LEAF)],)


def test_policy_padding_is_published_but_never_an_unpadded_use():
    """A switch in force that no decision used is in the published set only
    (design r5 D1: acceptance checks the unpadded set)."""
    results = analyze_units(program_units(_caller(LEAF), _plain()), assume_globals_disjoint_from_stack=True)
    _, closures = producer_supports(results, PremiseResolver())
    closure = closures[_key(MAIN)]
    assert GLOBALS in closure.published and GLOBALS not in closure.premises


def test_an_unknown_label_is_an_obligation_of_every_consumer():
    results = analyze_units(program_units(_caller(LEAF), _leaf()), assume_globals_disjoint_from_stack=True)
    leaf = results[_key(LEAF)]
    leaf.normalized = replace(leaf.normalized, premise_uses=(*leaf.normalized.premise_uses,
                                                             ("no-such-premise", "normalize", "1:1:0:STORE")))
    supports, closures = producer_supports(results, PremiseResolver())
    assert supports[f"{_key(LEAF)}#0"].unknown == ("no-such-premise",)
    assert "no-such-premise" in closures[_key(MAIN)].obligations
    assert not closures[_key(MAIN)].established and not closures[_key(LEAF)].established


def test_an_undischarged_hypothesis_fails_closed_through_its_consumers():
    results = analyze_units(program_units(_caller(MAIN + 0x100), _caller(LEAF, entry=MAIN + 0x100), _plain()))
    middle, top = results[_key(MAIN + 0x100)], results[_key(MAIN)]
    (call,) = middle.consumed
    middle.consumed = {call: (_Hypothesis(_key(LEAF)),)}
    supports, closures = producer_supports(results, PremiseResolver())
    assert supports[f"{_key(MAIN + 0x100)}#0"].missing
    assert not closures[_key(MAIN + 0x100)].established and not closures[_key(MAIN)].established
    assert closures[_key(LEAF)].established


def test_a_superseded_instance_still_consumed_keeps_its_own_uses():
    """A later failure replaces the published callee; its callers consumed the
    earlier instance -- that instance, not the latest result, is the producer."""
    results = analyze_units(program_units(_caller(LEAF), _leaf()), assume_globals_disjoint_from_stack=True)
    old = results[_key(LEAF)]
    results[_key(LEAF)] = AnalyzedFunction(old.key, old.unit, old.normalized, None, old.calls, superseded=old)
    results[_key(LEAF)].normalized = replace(old.normalized, premise_uses=())
    supports, closures = producer_supports(results, PremiseResolver())
    assert f"{_key(LEAF)}#1" in supports and supports[f"{_key(MAIN)}#0"].depends == (f"{_key(LEAF)}#1",)
    assert GLOBALS in closures[_key(MAIN)].premises
    assert GLOBALS not in closures[_key(LEAF)].premises


def test_a_verified_recursion_round_consumes_its_own_members():
    """f <-> g with a verified fixpoint: each consumed hypothesis is the
    discharging round's published member; the SCC shares one support."""
    first = (FunctionBuilder(entry=MAIN).sub_rsp(0x28).ins(store(const(DATA_BASE + 0x40), const(1, 8)))
             .cbranch("out", reg(RCX, 1)).call(MAIN + 0x100).label("out").add_rsp(0x28).ret())
    second = _caller(MAIN, entry=MAIN + 0x100)
    results = analyze_units(program_units(first, second), assume_globals_disjoint_from_stack=True)
    f, g = results[_key(MAIN)], results[_key(MAIN + 0x100)]
    assert not f.recursion_unresolved and not g.recursion_unresolved
    assert next(iter(f.consumed.values())) == (g,) and next(iter(f.consumed.values()))[0] is g
    assert next(iter(g.consumed.values()))[0] is f
    _, closures = producer_supports(results, PremiseResolver())
    assert closures[_key(MAIN)].uses == closures[_key(MAIN + 0x100)].uses
    assert GLOBALS in closures[_key(MAIN + 0x100)].premises


def test_every_composition_member_is_a_producer(monkeypatch):
    from test_multi_target_calls import A, B, ROOT, _analyze, _returns, _table

    results, _ = _analyze(monkeypatch, _table(), _returns(A, 1), _returns(B, 2))
    item = results[ROOT]
    (call,) = item.multi_calls
    assert item.consumed[call] == (results["1:1800"], results["1:1900"])
    supports, _ = producer_supports(results, PremiseResolver())
    assert set(supports[f"{ROOT}#0"].depends) >= {"1:1800#0", "1:1900#0"}


def test_an_activation_context_and_its_caller_analysis_are_producers(monkeypatch):
    from test_call_activation_lifetime import _run
    from test_external_models import MODELS
    from tdo_v2.summary_store import load_external_models

    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    models = load_external_models(MODELS, "x86:LE:64:default", "win64")
    result, points = _run(models)
    caller = result["1:1000"]
    context = caller.activations[points["outer"]]
    assert caller.consumed[points["outer"]] == (context,) and caller.consumed[points["outer"]][0] is context
    supports, closures = producer_supports(result, PremiseResolver(model_sets=(models,)))
    (name,) = [name for name, support in supports.items() if name != f"{caller.key}#0"
               and name.startswith(f"{context.key}#") and support.depends
               and any(other.startswith(f"{caller.key}#") for other in support.depends)]
    assert context.activation_witness[0] is not caller   # (the analysis its entry state came from)
    assert f"{caller.key}#0" not in supports[name].depends
    assert closures[caller.key].established, closures[caller.key].obligations


def test_an_accepted_lifecycle_refinement_consumes_the_callee_results_it_read(monkeypatch):
    from test_allocation_calls import _caller as allocation_caller, _contracts, _helper, _run as run
    from test_allocation_lifetime import without_allocator_windows
    from test_external_models import MODELS
    from tdo_v2.summary_store import load_external_models

    for name, value in (("TDO_V2_DATAFLOW_ENGINE", "sparse"), ("TDO_V2_MEMORY_SSA_ENGINE", "sparse"),
                        ("TDO_V2_FORWARD", "1")):
        monkeypatch.setenv(name, value)
    models = without_allocator_windows(load_external_models(MODELS, "x86:LE:64:default", "win64"))
    body, _ = allocation_caller()
    results = run(models, body, _helper(), _contracts(models, release=True))
    item = results["1:1000"]
    assert item.normalized.forward_memory_proofs
    peers = item.consumed.get("~lifecycle", ())
    assert peers and all(type(peer) is AnalyzedFunction for peer in peers)
    assert {peer.key for peer in peers} == {"1:1600"}


def _lifecycle(monkeypatch, helper_kind="quiet", extra=()):
    from test_allocation_calls import _caller as allocation_caller, _contracts, _helper
    from test_allocation_lifetime import without_allocator_windows
    from test_external_models import MODELS, _image
    from tdo_v2.summary_store import load_external_models

    for name, value in (("TDO_V2_DATAFLOW_ENGINE", "sparse"), ("TDO_V2_MEMORY_SSA_ENGINE", "sparse"),
                        ("TDO_V2_FORWARD", "1")):
        monkeypatch.setenv(name, value)
    models = without_allocator_windows(load_external_models(MODELS, "x86:LE:64:default", "win64"))
    body, _ = allocation_caller()
    units = program_units(body, _helper(helper_kind), *extra)
    results = analyze_units(units, image_info=_image(), external_models=models,
                            lifecycle_contracts=_contracts(models, release=True), private_frame_above=40,
                            assume_globals_disjoint_from_stack=True, assume_entry_values_not_frame=False,
                            assume_opaque_callees_leave_no_stack_addresses=False)
    return results, models


def test_a_lifecycle_refinement_keeps_the_nested_callee_results_it_read(monkeypatch):
    """Astra pc2 r1 P2-1: 1000 -> 1600 -> 1700; the allocation proof reads the
    nested callee's result. Even when 1600 itself kept no edge to 1700, 1000's
    closure reaches 1700 through the lifecycle reads."""
    leaf = FunctionBuilder(0x1700).sub_rsp(0x28)
    from synthetic import RCX
    from test_external_models import THUNKS
    leaf.ins(copy(reg(RCX), const(0))).call(THUNKS["free"]).add_rsp(0x28).ret()
    results, models = _lifecycle(monkeypatch, "opaque", (leaf,))
    item = results["1:1000"]
    if not item.normalized.forward_memory_proofs:
        pytest.skip("this helper shape is not refined (no lifecycle reads to keep)")
    peers = {peer.key for peer in item.consumed.get("~lifecycle", ())}
    assert {"1:1600", "1:1700"} <= peers, peers
    results["1:1600"].consumed = {}
    deep = results["1:1700"]
    deep.normalized = replace(deep.normalized, premise_uses=(*deep.normalized.premise_uses,
                                                             ("no-such-premise", "normalize", "1:1700:0:CALL")))
    _, closures = producer_supports(results, PremiseResolver(model_sets=(models,)))
    assert "no-such-premise" in closures["1:1000"].obligations


def test_forward_stage_run_union_labels_are_bridges_not_unpadded_uses(monkeypatch):
    """Astra pc2 r1 P2-2: a lifecycle acceptance records the plan's requires,
    which carry the run union (globals-disjoint here, decided nowhere) --
    published, never an unpadded use."""
    results, models = _lifecycle(monkeypatch)
    item = results["1:1000"]
    assert item.normalized.forward_memory_proofs
    assert ("globals-disjoint-from-stack", "refinement", item.key) in item.normalized.premise_uses
    _, closures = producer_supports(results, PremiseResolver(model_sets=(models,)))
    closure = closures["1:1000"]
    assert GLOBALS in closure.published
    # no forward-stage record of a run-union label is an unpadded use (a
    # precise normalize / summary use elsewhere may still list it)
    assert not [use for use in closure.uses if use.stage in ("refinement", "activation", "resolution")
                and use.premise.id == "globals-disjoint-from-stack"], closure.uses


def test_removing_a_consumption_edge_removes_the_producers_uses():
    """(the closure follows recorded edges only: a mutation dropping the edge
    shows up -- P-c5's completeness check relies on this)"""
    results = analyze_units(program_units(_caller(LEAF), _leaf()), assume_globals_disjoint_from_stack=True)
    producer = f"{_key(LEAF)}#0/"
    _, closures = producer_supports(results, PremiseResolver())
    assert any(use.at.startswith(producer) for use in closures[_key(MAIN)].uses)
    results[_key(MAIN)].consumed = {}
    _, closures = producer_supports(results, PremiseResolver())
    assert not any(use.at.startswith(producer) for use in closures[_key(MAIN)].uses)


def test_the_engine_run_reports_each_functions_premises_by_kind():
    """P-c4: EngineRun.supports -- per function, published and unpadded
    premises by kind and the obligations; the run union stays as it was."""
    from synthetic import analyze_summaries, boundary

    run = analyze_summaries([_caller(LEAF), _leaf()], boundary({}, {}), assume_globals_disjoint_from_stack=True)
    rows = {row.function: row for row in run.supports}
    assert set(rows) == {_key(MAIN), _key(LEAF)}
    caller = rows[_key(MAIN)]
    assert caller.established and "globals-disjoint-from-stack" in dict(caller.unpadded)["assumption"]
    assert "globals-disjoint-from-stack" in dict(caller.published)["assumption"]
    assert "globals-disjoint-from-stack" in run.assumptions


def test_the_premise_report_is_not_encoded_in_snapshots():
    from synthetic import analyze_summaries, boundary
    from tools.graph_fidelity.semantic_snapshot import encode

    run = analyze_summaries([_caller(LEAF), _leaf()], boundary({}, {}), assume_globals_disjoint_from_stack=True)
    assert run.supports and "supports" not in encode(run)


def test_a_run_synthesized_bridge_is_published_with_its_switch():
    """Astra pc4 r1 P2-1: stack-switch-check-exceptions comes with
    globals-disjoint-from-stack (run_assumptions): published, not unpadded."""
    from synthetic import analyze_summaries, boundary

    run = analyze_summaries([_caller(LEAF), _leaf()], boundary({}, {}), assume_globals_disjoint_from_stack=True)
    assert "stack-switch-check-exceptions" in run.assumptions
    for row in run.supports:
        if "globals-disjoint-from-stack" in dict(row.published).get("assumption", ()):
            assert "stack-switch-check-exceptions" in dict(row.published)["assumption"]
            assert "stack-switch-check-exceptions" not in dict(row.unpadded).get("assumption", ())


def test_iterator_bindings_reach_the_report(tmp_path):
    """Astra pc4 r1 P2-2: an iterator of bindings is materialized once -- the
    applied bound-model label is authenticated in the report."""
    from synthetic import boundary, summary_inputs
    from test_same_result_models import _binding, _bound_program, _models
    from tdo_v2.summary_engine import analyze_observed_with_summaries

    inputs = summary_inputs(list(_bound_program()), image=False)
    binding = _binding(tmp_path, [item.unit for item in inputs.evidences])
    run = analyze_observed_with_summaries(
        inputs.program, inputs.evidences, image_info=inputs.image_info, readonly_image=inputs.readonly_image,
        boundary_provider=boundary({}, {}), model_bindings=iter((binding,)), external_models=_models(tmp_path),
        assume_same_result_functions=True, assume_accessor_result_separate=True, assume_accessor_private_state=True)
    bound = [label for row in run.supports for label in dict(row.published).get("model", ())
             if label.startswith("bound-model:")]
    assert bound, run.supports
    assert all(row.established for row in run.supports), [row.obligations for row in run.supports]


def test_the_report_checks_the_reporting_deadline():
    """Astra pc4 r1 P2-3: building the report calls its tick per step."""
    from tdo_v2.producer_support import function_premises

    results = analyze_units(program_units(_caller(LEAF), _leaf()))
    ticks = []
    function_premises(results, PremiseResolver(), tick=lambda: ticks.append(1))
    assert len(ticks) >= 2 * len(results)


def test_the_report_stops_at_the_deadline_while_grouping():
    """Astra pc4 r2 P2 / pc5 r1 P3: one published function -- after the
    closures and its row's own check, only the grouping's checks remain; a
    deadline falling there stops the report (it would not without them)."""
    from tdo_v2.producer_support import function_premises, producer_closures

    results = analyze_units(program_units(_leaf()), assume_globals_disjoint_from_stack=True)
    assert len(results) == 1
    counted = []
    producer_closures(results, PremiseResolver(), tick=lambda: counted.append(1))
    calls = []

    def tick():
        calls.append(1)
        if len(calls) > len(counted) + 1:   # (past the closures and the row's check)
            raise TimeoutError("reporting deadline")

    with pytest.raises(TimeoutError):
        function_premises(results, PremiseResolver(), tick=tick)
