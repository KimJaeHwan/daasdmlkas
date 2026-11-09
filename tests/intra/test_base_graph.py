"""Generic SSA publication is independent from summary proof transactions."""

from dataclasses import FrozenInstanceError, replace

import pytest

from synthetic import (AARCH64, X64, X86_32, DATA_BASE, FunctionBuilder, RAX, RCX, RDX, RSP,
                       const, copy, load, program_units, ram, reg, store, tmp)
from tdo_v2.base_graph import BaseGraphPolicy, BaseGraphPublication, _policy
from tdo_v2.graph_contracts import NodeRecord, NodeKind
from tdo_v2.interprocedural import analyze_units
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction
from tdo_v2.resource_limits import AnalysisCancelled
from tdo_v2.span_geometry import StorageObjectKind


def _units(arch=X64):
    caller = FunctionBuilder(arch=arch).ins(copy(reg(RCX, arch.pointer), const(23, arch.pointer))).call(0x1800).ret()
    leaf = FunctionBuilder(entry=0x1800, arch=arch).ins(copy(reg(RAX, arch.pointer), reg(RCX, arch.pointer))).ret()
    return program_units(caller, leaf)


def _nodes(graph):
    return tuple(graph.node(index) for index in range(graph.node_count))


@pytest.mark.parametrize("arch", (X64, X86_32, AARCH64))
def test_base_reuses_exact_raw_normalizer_with_no_query_or_summary(arch):
    units = _units(arch)
    publication = BaseGraphPublication(units)
    result = publication.build()
    assert result.stop == "finished" and result.local_pass_finished and result.entry_links_finished
    assert not result.pending and not result.failures and len(result.graphs) == 2
    assert result.policy == BaseGraphPolicy() and len(result.policy.digest) == 64
    with _policy(result.policy):
        for unit in units:
            key = f"{unit.scopes.function.entry.space_id:x}:{unit.scopes.function.entry.byte_offset:x}"
            actual = result.graphs[key].normalized
            expected = FunctionNormalizer().normalize(unit)
            assert type(actual) is NormalizedFunction
            assert actual.memory_ssa == expected.memory_ssa
            assert actual.call_clobber_reads == expected.call_clobber_reads
            assert actual.may_alias_reads == expected.may_alias_reads
            for name in ("cfg", "dependencies"):
                left, right = getattr(actual, name), getattr(expected, name)
                assert _nodes(left) == _nodes(right)
                assert left.weighted_edges() == right.weighted_edges()
            assert not actual.proven_call_effects and not actual.assumed_call_effects
            assert not actual.fault_cuts and not actual.callee_support and actual.activation_entry is None
    with pytest.raises(RuntimeError, match="single-use"):
        publication.build()


def test_entry_edges_use_the_original_base_ssa_and_distinct_call_contexts():
    units = program_units(
        FunctionBuilder().ins(copy(reg(RCX), const(23))).call(0x1800).call(0x1800).ret(),
        FunctionBuilder(entry=0x1800).ins(copy(reg(RAX), reg(RCX))).tail_call(0x1f00))
    result = BaseGraphPublication(units).build()
    owner, leaf = result.graphs["1:1000"], result.graphs["1:1800"]
    first, second = owner.entry_relations
    assert first.context != second.context
    assert first._normalized is owner.normalized and first._body_normalized is leaf.normalized
    assert first.body_role == "generic-entry-body"
    assert first._callee.summary is None and first._caller.summary is None
    assert not first._caller.proven and not first._caller.consumed and not first._caller.activations
    edges = first.edges()
    edge = next(row for row in edges if row.kind == "call-entry-register" and row.destination_span.start == RCX)
    original = owner.normalized.dependencies.node_for_key("op:1:1000:0:COPY")
    assert original in owner.normalized.dependencies.backward_reachable((edge.caller_node,))
    reader = leaf.normalized.dependencies.node_for_key("op:1:1800:0:COPY")
    assert edge.callee_node in leaf.normalized.dependencies.backward_reachable((reader,))
    # The second CALL's unknown modification is still an obligation.
    assert any(row.frontier for row in second.bindings())


def test_memory_bridge_keeps_writer_alias_obligations_and_raw_node_ids():
    units = program_units(
        FunctionBuilder().ins(copy(ram(DATA_BASE, 8), reg(RDX))).call(0x1800).ret(),
        FunctionBuilder(entry=0x1800).ins(copy(reg(RAX), ram(DATA_BASE, 8))).ret())
    result = BaseGraphPublication(units).build()
    (relation,) = result.graphs["1:1000"].entry_relations
    binding = next(row for row in relation.bindings() if row.span.object_id.kind is StorageObjectKind.ADDRESS_SPACE
                   and row.span.start == DATA_BASE)
    assert binding.sources and binding.caller_place.start == DATA_BASE
    assert "memory content requires original writer/alias conditions" in binding.frontier
    assert all(result.graphs["1:1000"].normalized.memory_ssa.definitions[identifier].operation_key == "1:1000:0:COPY"
               for source in binding.sources for identifier in source.definition_ids)


def test_recursive_base_is_finite_and_does_not_invent_returns_or_tail_edges():
    units = program_units(FunctionBuilder().call(0x1800).ret(),
                          FunctionBuilder(entry=0x1800).label("loop").call(0x1800).branch("loop"))
    result = BaseGraphPublication(units).build()
    leaf = result.graphs["1:1800"]
    assert len(leaf.entry_relations) == 1
    assert leaf.entry_relations[0]._body_normalized is leaf.normalized
    assert not leaf.normalized.proven_call_effects


def test_old_snapshots_are_immutable_and_new_bridges_do_not_change_local_graphs(monkeypatch):
    publication = BaseGraphPublication(_units())
    original = publication._connect_entries
    captured = []

    def connect():
        captured.append(publication.snapshot)
        original()

    monkeypatch.setattr(publication, "_connect_entries", connect)
    result = publication.build()
    before = captured[0]
    assert before.local_pass_finished and not before.entry_links_finished
    assert not before.graphs["1:1000"].entry_relations
    assert result.graphs["1:1000"].entry_relations
    assert before.graphs["1:1000"].normalized is result.graphs["1:1000"].normalized
    with pytest.raises(TypeError):
        result.graphs["invented"] = result.graphs["1:1000"]
    with pytest.raises(FrozenInstanceError):
        result.graphs["1:1000"].normalized = None
    with pytest.raises(RuntimeError, match="frozen"):
        result.graphs["1:1000"].normalized.dependencies.add_node(NodeRecord("fake", NodeKind.CONSTANT, "fake"))
    relation = result.graphs["1:1000"].entry_relations[0]
    with pytest.raises(TypeError):
        relation._caller.calls[relation.call] = "1:1f00"
    relation._caller.normalized = result.graphs["1:1800"].normalized
    with pytest.raises(ValueError, match="source instance changed"):
        relation.bindings()


def test_cancel_in_second_normalization_preserves_first_and_keeps_pending(monkeypatch):
    units = _units()
    publication = BaseGraphPublication(units)
    normalize = FunctionNormalizer.normalize
    from tdo_v2 import resource_limits

    def cancel(self, unit, **options):
        if unit is units[1]:
            resource_limits._CANCEL.set()
            resource_limits.checkpoint()
        return normalize(self, unit, **options)

    monkeypatch.setattr(FunctionNormalizer, "normalize", cancel)
    with pytest.raises((AnalysisCancelled, KeyboardInterrupt)):  # (Linux worker: KeyboardInterrupt)
        publication.build()
    saved = publication.snapshot
    assert saved.stop == "cancelled" and len(saved.graphs) == 1
    assert saved.pending == ("1:1800",) and not saved.local_pass_finished and not saved.entry_links_finished
    base = saved.graphs["1:1000"]
    graph = base.normalized.dependencies
    query = base.query(graph.node_for_key("op:1:1000:0:COPY"))
    assert query.reachable_nodes


def test_cancel_during_bridge_keeps_all_local_graphs_without_partial_revision(monkeypatch):
    import tdo_v2.call_entry_graph as bridges
    publication = BaseGraphPublication(_units())

    def cancel(adapters, **options):
        next(iter(adapters.values())).entry_relations = ("must not publish",)
        raise AnalysisCancelled()

    monkeypatch.setattr(bridges, "connect_call_entries", cancel)
    with pytest.raises((AnalysisCancelled, KeyboardInterrupt)):  # (Linux worker: KeyboardInterrupt)
        publication.build()
    saved = publication.snapshot
    assert saved.local_pass_finished and len(saved.graphs) == 2
    assert not saved.entry_links_finished and not saved.pending
    assert all(not item.entry_relations for item in saved.graphs.values())


def test_later_real_proof_budget_failure_cannot_discard_base_graphs(monkeypatch):
    import tdo_v2.interprocedural as proofs
    from tdo_v2.resource_limits import charge, last_run

    monkeypatch.setenv("TDO_V2_FUNCTION_WORK", "5000")
    units = _units()
    publication = BaseGraphPublication(units)
    seen = []

    def expensive(*args, **options):
        seen.append(publication.snapshot)
        charge(10000)  # existing real resource ledger; not a forged failure

    monkeypatch.setattr(proofs, "summarize_function", expensive)
    result = analyze_units(units, base_graphs=publication)
    saved = publication.snapshot
    assert len(saved.graphs) == 2 and saved.entry_links_finished
    assert seen and all(snapshot.graphs[key].normalized is saved.graphs[key].normalized
                        for snapshot in seen for key in saved.graphs)
    assert any(type(item.normalized) is not NormalizedFunction for item in result.values())
    ledgers = last_run().ledgers
    assert all(("base-graph", unit.scopes.function.scope) in ledgers for unit in units)
    assert all(("function", unit.scopes.function.scope) in ledgers for unit in units)
    assert all(ledgers[("base-graph", unit.scopes.function.scope)].work < 5000 for unit in units)


def test_later_cancellation_propagates_without_erasing_the_base(monkeypatch):
    import tdo_v2.interprocedural as proofs
    units = _units()
    publication = BaseGraphPublication(units)

    def cancel(*args, **options):
        assert publication.snapshot.entry_links_finished
        raise AnalysisCancelled()

    monkeypatch.setattr(proofs, "_analyze_units", cancel)
    with pytest.raises((AnalysisCancelled, KeyboardInterrupt)):  # (Linux worker: KeyboardInterrupt)
        analyze_units(units, base_graphs=publication)
    assert len(publication.snapshot.graphs) == 2
    assert publication.snapshot.graphs["1:1000"].entry_relations[0].edges()


def test_real_base_run_limit_preserves_completed_graph_and_pending_keys(monkeypatch):
    from tdo_v2.resource_limits import charge
    monkeypatch.setenv("TDO_V2_RUN_WORK", "5000")
    units = _units()
    publication = BaseGraphPublication(units)
    normalize = FunctionNormalizer.normalize

    def expensive(self, unit, **options):
        if unit is units[1]:
            charge(10000)
        return normalize(self, unit, **options)

    monkeypatch.setattr(FunctionNormalizer, "normalize", expensive)
    saved = publication.build()
    assert saved.stop == "run:work" and len(saved.graphs) == 1
    assert not saved.failures and saved.pending == ("1:1800",)
    assert not saved.local_pass_finished and not saved.entry_links_finished


def test_real_base_function_limit_does_not_stop_other_function_graphs(monkeypatch):
    from tdo_v2.resource_limits import charge
    monkeypatch.setenv("TDO_V2_FUNCTION_WORK", "5000")
    units = _units()
    normalize = FunctionNormalizer.normalize

    def expensive(self, unit, **options):
        if unit is units[0]:
            charge(10000)
        return normalize(self, unit, **options)

    monkeypatch.setattr(FunctionNormalizer, "normalize", expensive)
    saved = BaseGraphPublication(units).build()
    assert saved.stop == "finished" and saved.local_pass_finished and saved.entry_links_finished
    assert set(saved.graphs) == {"1:1800"} and not saved.pending
    assert saved.failures["1:1000"].reason.value == "analysis_budget"
    assert saved.failures["1:1000"].detail == "function:work"


def test_policy_and_instance_inputs_are_exact_and_ambient_activation_is_masked():
    from tdo_v2._activation_entry import ActivationEntry, using_entry
    from tdo_v2.call_clobber import OPAQUE_RESTORES_SP
    from tdo_v2.relative_memory import IMAGE_BASE_TRACKING, IMPORT_SLOTS

    units = _units()
    publication = BaseGraphPublication(units)
    source = next(item.span for item in FunctionNormalizer().normalize(units[0]).memory_ssa.definitions
                  if item.kind is MemoryDefinitionKind.ENTRY
                  and item.span.object_id.kind is StorageObjectKind.REGISTER_FILE)
    state = ActivationEntry(units[0].scopes.function.scope, ("caller", "call"), ((source, source, 4),), (), ())
    fake_imports = object()
    imported = IMPORT_SLOTS.set(fake_imports)
    tracked = IMAGE_BASE_TRACKING.set(object())
    restores = OPAQUE_RESTORES_SP.set(True)
    try:
        with using_entry(state):
            result = publication.build()
            assert all(item.normalized.activation_entry is None for item in result.graphs.values())
            assert all(not item.normalized.assumes_opaque_callees_restore_stack_pointer for item in result.graphs.values())
            assert IMPORT_SLOTS.get() is fake_imports and OPAQUE_RESTORES_SP.get() is True
    finally:
        IMPORT_SLOTS.reset(imported)
        IMAGE_BASE_TRACKING.reset(tracked)
        OPAQUE_RESTORES_SP.reset(restores)
    with pytest.raises(ValueError, match="different input instances"):
        publication.require_inputs(tuple(replace(unit) for unit in units))
    with pytest.raises(ValueError, match="duplicate"):
        BaseGraphPublication((units[0], units[0]))
    with pytest.raises(TypeError, match="exact bools"):
        BaseGraphPolicy(assume_direction_flag_clear=1)
    assert BaseGraphPolicy(assume_direction_flag_clear=True).digest != BaseGraphPolicy().digest


def test_lazy_entry_queries_restore_issuing_policy_under_foreign_image_and_import_context():
    from synthetic import add
    from tdo_v2.relative_memory import IMAGE_BASE_TRACKING, IMPORT_SLOTS
    units = program_units(
        FunctionBuilder().sub_rsp(0x28).ins(add(tmp(0x100), reg(RSP), const(0x10)),
                                          store(tmp(0x100), reg(RDX))).call(0x1800).add_rsp(0x28).ret(),
        FunctionBuilder(entry=0x1800).ins(add(tmp(0x100), reg(RSP), const(0x18)),
                                        load(reg(RAX), tmp(0x100))).ret())
    result = BaseGraphPublication(units).build()
    relation = result.graphs["1:1000"].entry_relations[0]
    imports, tracker = object(), object()
    first = IMPORT_SLOTS.set(imports)
    second = IMAGE_BASE_TRACKING.set(tracker)
    try:
        # The very first query builds a lazy projector after admission closed.
        bindings, edges = relation.bindings(), relation.edges()
        assert any(row.caller_place is not None and row.sources for row in bindings)
        assert IMPORT_SLOTS.get() is imports and IMAGE_BASE_TRACKING.get() is tracker
    finally:
        IMPORT_SLOTS.reset(first)
        IMAGE_BASE_TRACKING.reset(second)
    assert bindings == relation.bindings() and edges == relation.edges()
    relation._index.query_context = lambda: _policy(BaseGraphPolicy(assume_direction_flag_clear=True))
    with pytest.raises(ValueError, match="source instance changed"):
        relation.bindings()


def test_unfinished_base_handle_cannot_silently_start_optional_proof(monkeypatch):
    import tdo_v2.interprocedural as proofs
    units = _units()
    publication = BaseGraphPublication(units)
    publication._started = True

    def must_not_run(*args, **options):
        pytest.fail("proof started with unfinished base publication")

    monkeypatch.setattr(proofs, "_analyze_units", must_not_run)
    with pytest.raises(ValueError, match="did not finish"):
        analyze_units(units, base_graphs=publication)


@pytest.mark.parametrize("name", ("assumes_globals_disjoint_from_stack", "assumes_entry_values_not_frame",
    "assumes_opaque_callees_leave_no_stack_addresses", "assumes_pre_escape_values_not_frame",
    "assumes_opaque_callees_restore_stack_pointer", "assumed_direction_flag_clear",
    "assumes_import_slots_hold_exports", "assumes_readonly_image_constant"))
def test_wrapper_cannot_relabel_a_policy_dependent_graph_as_strict(name):
    graph = BaseGraphPublication(_units()).build().graphs["1:1000"]
    with pytest.raises(ValueError, match="outside its policy"):
        replace(graph, normalized=replace(graph.normalized, **{name: True}))


def test_wrapper_refuses_configured_call_effects_and_allows_unused_enabled_policy():
    graph = BaseGraphPublication(_units()).build().graphs["1:1000"]
    # Force a candidate's metadata as an untrusted wrapper input. Configured
    # authority is forbidden even with no public proven/assumed effects.
    candidate = replace(graph.normalized)
    object.__setattr__(candidate, "configured_call_effects", object())
    with pytest.raises(ValueError, match="not base graphs"):
        replace(graph, normalized=candidate)
    allowed = replace(graph, policy=BaseGraphPolicy(assume_direction_flag_clear=True))
    assert not allowed.normalized.assumed_direction_flag_clear  # enabled is not used
