"""Original Suite09 DFB031: useful, explicitly contract-relative byte proofs.

No source return, memory opcode, or actual allocator body is substituted.
The optional audited profile is a trusted external contract, not a proof of
the linked allocator's implementation. Later sink/free debts remain open.
"""

from dataclasses import replace

import pytest

from test_forward_memory_footprints_binary import actual, REPO
import run_dfbench
from tdo_v2._allocation_lifetime import AllocationAnalysis
from tdo_v2._allocation_memory import ExistingStackRange
from tdo_v2.forward import probe
from tdo_v2.interprocedural import analyze_units
from tdo_v2.lifecycle_contracts import load_lifecycle_contracts
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.model import ResolvedStorage
from tdo_v2.query import BackwardSliceQuery


FUNCTION = "1b1:1049f6"
CALLEES = ("1b1:10453b", "1b1:10454a", "1b1:104559")
MALLOC, REALLOC = "1b1:104a04:2:CALL", "1b1:104a3a:2:CALL"
HEAP_STORES = {"1b1:104a1d:1:STORE", "1b1:104a2c:1:STORE"}
SAVED_RBP, READ_RBP, READ_RBX = "1b1:1049f6:2:STORE", "1b1:104a6d:1:LOAD", "1b1:104a69:1:LOAD"
SINK, FREE = "1b1:104a52:2:CALL", "1b1:104a5e:2:CALL"


def _analyze(actual, contracts):
    return analyze_units(
        [actual["units"][key] for key in (FUNCTION, *CALLEES)],
        image_info=actual["image_info"], readonly_image=actual["readonly"],
        external_models=run_dfbench.external_models(actual["generation"]),
        lifecycle_contracts=contracts,
        assume_entry_values_not_frame=False,
        assume_opaque_callees_leave_no_stack_addresses=False,
    )


@pytest.fixture(params=("sparse", "dense"))
def engine(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)


def _read(item, key):
    ssa = item.normalized.memory_ssa
    return next(read for read in ssa.reads if ssa.actions[read.action_id].operation_key == key
                and read.span.object_id.kind.value == "function_relative")


def _calls(item, key):
    return {call for debt in item.normalized.call_clobber_reads if debt.operation_key == key
            for call in debt.intervening_calls}


def test_original_nonnull_realloc_closes_only_its_own_two_stack_ranges(actual, engine):
    assert actual["units"][FUNCTION].scopes.function.observation_digest.hex() == \
        "cba0a7f69d8104e4d2ecfdbcbe8a514cc1c6dfb2da6aecda9898b382ff1200e9"
    contracts = load_lifecycle_contracts(REPO / "models/lifecycle/glibc_sysv64.json")
    before = _analyze(actual, ())[FUNCTION]
    results = _analyze(actual, contracts)
    item, normalized = results[FUNCTION], results[FUNCTION].normalized
    for reader in (READ_RBX, READ_RBP):
        assert REALLOC in _calls(before, reader)
        assert REALLOC not in _calls(item, reader)
        assert {SINK, FREE} <= _calls(item, reader)
    assert {(row.demand.reader, row.demand.call) for row in item.call_memory_decisions
            if row.reason == "live-owned-allocation-disjoint-stack"} == {
                (READ_RBP, REALLOC), (READ_RBX, REALLOC)}
    assert not item.proven[REALLOC].preserves_memory
    analysis = AllocationAnalysis(item, readonly_image=actual["readonly"], results=results)
    pointer = analysis.argument(REALLOC, analysis.contracts[REALLOC].pointer)
    assert not pointer.unknown and len(pointer.targets) == 1
    (target,) = pointer.targets
    assert target.allocation.event == MALLOC and target.offset == 0
    assert analysis.extent(target.allocation)[0] == 8
    assert analysis.lifetime(pointer, REALLOC).live
    assert HEAP_STORES <= {proof.writer for proof in normalized.forward_memory_proofs}
    assert all(proof.write_fact.live for proof in normalized.forward_memory_proofs if proof.writer in HEAP_STORES)
    # Closing the independent pre-CALL snapshot now permits one original
    # four-byte copy proof. Its result-prefix authority also separates the
    # two original return-address pushes and the result-pointer spill. This
    # is an exact three-writer set, not permission to waive other bytes/CALLs.
    (copied,) = normalized.forward_inputs.read_separations.copy_proofs
    assert copied.call == REALLOC and copied.reader == "1b1:104a4e:0:LOAD"
    assert copied.source[1] == "1b1:104a1d:1:STORE" and copied.span == _read(item, copied.reader).span
    assert (copied.offset, copied.span.size, copied.old_size, copied.new_size) == (0, 4, 8, 16)
    assert copied.input_lifetime.live and copied.writer_lifetime.live
    extra = [proof for proof in normalized.forward_memory_proofs if proof.writer not in HEAP_STORES]
    stack_offsets = {"1b1:104a27:2:CALL~push": -48, REALLOC + "~push": -48,
                     "1b1:104a3f:2:STORE": -32}
    assert len(extra) == 3 and {proof.writer for proof in extra} == set(stack_offsets)
    effects = {effect.operation_key: effect for effect in normalized.effects}
    for proof in extra:
        assert proof.read == copied.reader and proof.span == copied.span
        assert proof.write_fact == (REALLOC, "resize-result-owned-prefix")
        assert type(proof.read_fact) is tuple and len(proof.read_fact) == 2
        old, current = proof.read_fact
        assert type(old) is ExistingStackRange and type(current) is ExistingStackRange
        assert old.allocation == target.allocation and current.allocation.event == REALLOC
        assert current.allocation.function == FUNCTION and current.allocation.context == target.allocation.context
        assert current.allocation.result == analysis.contracts[REALLOC].result
        assert current.allocation.contract == analysis.contracts[REALLOC].canonical_digest
        (writer_span,) = [row.span for row in effects[proof.writer].writes
                          if type(row) is ResolvedStorage and row.span.object_id.kind.value == "function_relative"]
        assert old.span == current.span == writer_span and writer_span.size == 8
        assert writer_span.start - old.upper == stack_offsets[proof.writer]
        assert old.lower <= writer_span.start < writer_span.end <= old.upper
        assert current.lower <= writer_span.start < writer_span.end <= current.upper
    assert all(any(label.startswith("lifecycle-contract:") for label in row.requires)
               for row in item.call_memory_decisions)
    assert set(normalized.forward_memory_requires) <= set(item.inherited_assumptions)

    # The original graph keeps the complete eight-byte saved-RBP writer.
    # Its read still has other CALL debt: a real edge is not a completeness claim.
    ssa, graph = normalized.memory_ssa, normalized.dependencies
    read = _read(item, READ_RBP)
    assert read.span.size == 8 and len(read.fragments) == 1
    (identifier,) = read.fragments[0].definition_ids
    definition = ssa.definitions[identifier]
    assert definition.operation_key == SAVED_RBP and definition.kind is MemoryDefinitionKind.DATA_WRITE
    source = graph.node_for_key("op:" + SAVED_RBP)
    destination = graph.node_for_key("op:" + READ_RBP)
    memory = normalized.memory_graph.definition_nodes[identifier]
    assert any(target == memory and edge.kind == "memory_defines" and edge.span == read.span
               for _, target, edge in graph.out_edges(source))
    assert any(origin == memory and edge.kind == "memory_read" and edge.span == read.span
               for origin, _, edge in graph.in_edges(destination))
    query = BackwardSliceQuery().run(normalized, destination)
    assert source in query.reachable_nodes and memory in query.reachable_nodes
    assert query.reachable_unresolved_read_nodes
    found, requires = probe(normalized, READ_RBP, (read.span,))
    assert found[read.span] is None  # Later free/sink must not disappear.
    assert set(normalized.forward_memory_requires) <= set(requires)


def test_actual_missing_owned_extent_or_disabled_forward_keeps_original_debt(actual, engine, monkeypatch):
    contracts = load_lifecycle_contracts(REPO / "models/lifecycle/glibc_sysv64.json")
    weak = tuple(replace(row, owned_footprint=False) if row.kind == "allocate" else row for row in contracts)
    item = _analyze(actual, weak)[FUNCTION]
    assert REALLOC in _calls(item, READ_RBP)
    assert not any(proof.writer in HEAP_STORES for proof in item.normalized.forward_memory_proofs)
    monkeypatch.setenv("TDO_V2_FORWARD", "0")
    item = _analyze(actual, contracts)[FUNCTION]
    assert REALLOC in _calls(item, READ_RBP)
    assert not item.allocation_lifetimes and not item.call_memory_decisions


def test_public_observed_entry_accepts_only_explicit_profile_and_reports_its_dependencies(actual, monkeypatch):
    from hashlib import sha256
    from tdo_v2 import summary_engine
    from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
    from tdo_v2.integration.configured_bundle import admit_frozen_bundle
    from tdo_v2.integration.observed_function_session import open_observed_function_session
    from tdo_v2.interprocedural import function_key
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", "sparse")
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", "sparse")
    source = REPO / "ghidra/GhidraV2CallNaming.java"
    # This fixture was exported with the LF producer; other frozen fixtures
    # use CRLF. Select its exact known producer without relaxing admission.
    producer = sha256(source.read_bytes().replace(b"\r\n", b"\n")).digest()
    assert producer.hex() == "69a175c7154ea56bc02f96ba00249e9701048e771dc4170745eb7411d9d54e5b"
    binding = NamingBindingExpectation(producer, CALL_NAMING_GHIDRA_VERSION)
    with open_observed_function_session(admit_frozen_bundle(actual["generation"]), naming_binding=binding) as session:
        scope = session.program_result
        evidences = [row for row in session.iter_functions()
                     if function_key(row.unit.scopes.function.entry) in {FUNCTION, *CALLEES}]
    contracts = load_lifecycle_contracts(REPO / "models/lifecycle/glibc_sysv64.json")
    run = summary_engine.analyze_observed_with_summaries(
        scope, evidences, image_info=actual["image_info"], readonly_image=actual["readonly"],
        boundary_provider=run_dfbench.boundary_provider(False, "sysv64"),
        external_models=run_dfbench.external_models(actual["generation"]),
        lifecycle_contracts=contracts, assume_entry_values_not_frame=False,
        assume_opaque_callees_leave_no_stack_addresses=False)
    assert not run.failed_functions
    assert any(label.startswith("lifecycle-contract:glibc-sysv64-malloc@") for label in run.assumptions)
    assert any(label.startswith("lifecycle-contract:glibc-sysv64-realloc@") for label in run.assumptions)
    assert "registered-handlers-are-not-observed" in run.assumptions
