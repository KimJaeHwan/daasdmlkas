"""DFB031 copied payload range, not source-A or whole-function completeness.

The original ELF/source helpers and four-function bounded analysis are reused.
An explicitly loaded glibc profile is a trusted external contract, not actual
allocator implementation evidence. Source-A's independent debts stay open.
"""

from dataclasses import replace

from test_allocation_lifetime_binary import FUNCTION, MALLOC, REALLOC, _analyze
from test_forward_memory_footprints_binary import actual, REPO
from test_realloc_contents_binary import (
    _assert_transfer_graph, _call_debts, _copy_proofs, _payload_read, static_engine,
)
from tdo_v2._allocation_lifetime import AllocationAnalysis
from tdo_v2._load_identity import definition_identity
from tdo_v2.forward import probe
from tdo_v2.lifecycle_contracts import load_lifecycle_contracts
from tdo_v2.query import BackwardSliceQuery


WRITER, READER = "1b1:104a1d:1:STORE", "1b1:104a4e:0:LOAD"
OTHER_WRITER, POST_CALL_SPILL = "1b1:104a2c:1:STORE", "1b1:104a3f:2:STORE"


def test_original_dfb031_prefix_snapshot_and_transfer_leave_source_a_debt(actual, static_engine):
    assert actual["units"][FUNCTION].scopes.function.observation_digest.hex() == \
        "cba0a7f69d8104e4d2ecfdbcbe8a514cc1c6dfb2da6aecda9898b382ff1200e9"
    contracts = load_lifecycle_contracts(REPO / "models/lifecycle/glibc_sysv64.json")
    weak = tuple(replace(row, contents="unknown") if row.kind == "resize" else row for row in contracts)
    before = _analyze(actual, weak)[FUNCTION]
    results = _analyze(actual, contracts)
    item = results[FUNCTION]
    assert REALLOC in _call_debts(before, READER) and not _copy_proofs(before, READER)
    assert any(row.operation_key == READER and POST_CALL_SPILL in row.plain
               for row in before.normalized.may_alias_reads)
    assert REALLOC not in _call_debts(item, READER) and not item.proven[REALLOC].preserves_memory
    assert not any(row.operation_key == READER and POST_CALL_SPILL in row.plain
                   for row in item.normalized.may_alias_reads)
    (proof,) = _copy_proofs(item, READER)
    assert proof.source[1] == WRITER and proof.source[1] != OTHER_WRITER
    assert proof.offset == 0 and proof.span.size == 4 and proof.old_size == 8 and proof.new_size == 16
    assert proof.input_lifetime.live and proof.result_definitions and proof.outcome.definitions
    assert proof.outcome.success_edge != proof.outcome.failure_edge
    assert proof.contract in proof.requires and set(proof.snapshot_requires) <= set(proof.requires)
    assert set(proof.requires) <= set(item.inherited_assumptions)

    normalized = item.normalized
    read = _payload_read(item, READER)
    assert read.span.size == 4 and len(read.fragments) == 1
    (identifier,) = read.fragments[0].definition_ids
    assert definition_identity(normalized.memory_ssa.definitions[identifier]) == proof.source
    analysis = AllocationAnalysis(item, readonly_image=actual["readonly"], results=results)
    pointer = analysis.argument(REALLOC, analysis.contracts[REALLOC].pointer)
    assert not pointer.unknown and {target.allocation.event for target in pointer.targets} == {MALLOC}
    # Independently re-read the pre-CALL snapshot: no retrospective target
    # LOAD/transfer may provide the old source's own definition.
    snapshot, snapshot_labels = probe(normalized, analysis.first(REALLOC), (proof.span,))
    assert snapshot[proof.span] == identifier and set(snapshot_labels) <= set(proof.requires)
    found, labels = probe(normalized, READER, (read.span,))
    assert found[read.span] == identifier and proof.contract in labels
    _assert_transfer_graph(item, (proof,))

    def unresolved_payload_keys(result):
        graph = result.normalized.dependencies
        query = BackwardSliceQuery().run(result.normalized, graph.node_for_key("op:" + READER))
        return {graph.node(node).key for node in query.reachable_unresolved_read_nodes}

    remaining = unresolved_payload_keys(item)
    source_a_before = {key for key in unresolved_payload_keys(before) if "104a14:2:CALL" in key}
    assert source_a_before and source_a_before <= remaining
    assert remaining  # Not a whole-function/source-A completeness assertion.
