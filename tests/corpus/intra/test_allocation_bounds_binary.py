"""Original UE wide allocation accesses cannot borrow a point-only claim.

Uses the existing TDO_UE_TRACE_BUNDLE and TDO_UE_STACK_EVIDENCE fixtures.
No allocation extent is supplied or inferred by this test. In particular,
the original eight-byte STORE at buffer+8 is not declared inside a block.
This is a static conservative-debt regression, not an assertion that any
chosen concrete execution overlaps its valid native allocation and stack.
"""

import pytest

from test_callee_preserved_low_binary import R002, _projector, _trace_run, trace
from tdo_v2.graph_contracts import NodeKind


FIRST_STORE, SECOND_STORE = "1b1:180006099:1:STORE", "1b1:180006230:1:STORE"
FIRST_READ, SECOND_READ = "1b1:1800060c2:1:LOAD", "1b1:180006257:1:LOAD"
RESIZE_RESULT = "1b1:180006053:2:CALL~6"
R002_DIGEST = "7330f59944e14a30c0bc8b23cb0a8cea9742678fbbfc9a571e6bac8b56997d21"


@pytest.fixture(scope="module")
def allocation_trace(trace):
    assert trace["units"][R002].scopes.function.observation_digest.hex() == R002_DIGEST
    with pytest.MonkeyPatch.context() as patch:
        return _trace_run(trace, patch, True)


def test_original_r002_resize_lifetime_debt_cannot_supply_an_eight_byte_extent(allocation_trace):
    _, roots, results = allocation_trace
    item = results[R002]
    _, operations = _projector(item)
    assert operations[FIRST_STORE].inputs[2].byte_size == 8
    assert operations[SECOND_STORE].inputs[2].byte_size == 8
    # Lifetime uncertainty now blocks the old ResizeGrow pointer export;
    # neither a missing relation nor fresh provenance is extent evidence.
    normalized = item.normalized
    assert RESIZE_RESULT not in dict(normalized.pointer_rows)
    graph = normalized.dependencies
    upstream = set(graph.backward_reachable((graph.node_for_key("op:" + FIRST_STORE),)))
    assert any("1b1:180006053:2:CALL" in row.intervening_calls and node in upstream
               for row, node in zip(normalized.call_clobber_reads, normalized.call_clobber_nodes))
    assert dict(normalized.uncertain_writers)[FIRST_STORE] is None
    assert roots[R002].effective_completeness.reachable_unresolved_reads > 0
    assert not roots[R002].is_effectively_complete


@pytest.mark.parametrize("writer,reader", ((FIRST_STORE, FIRST_READ), (SECOND_STORE, SECOND_READ)))
def test_original_unbounded_wide_store_keeps_its_stack_alias_or_condition(allocation_trace, writer, reader):
    _, _, results = allocation_trace
    normalized = results[R002].normalized
    rows = [(row, node) for row, node in zip(normalized.may_alias_reads, normalized.may_alias_nodes)
            if row.operation_key == reader and writer in row.writers]
    assert rows, "an allocation point is not proof that all bytes of this wide STORE avoid the stack"
    graph = normalized.dependencies
    target, source = graph.node_for_key(f"op:{reader}"), graph.node_for_key(f"op:{writer}")
    assert target is not None and source is not None
    predecessors = set(graph.predecessors(target))
    conditions = dict(normalized.uncertain_writers)
    for row, node in rows:
        assert node in predecessors and graph.node(node).kind is NodeKind.MEMORY_DEBT
        if source not in graph.predecessors(node):
            # A conditional address is not a silent non-alias result. Its
            # existing uncertain-writer obligation must reach the real LOAD.
            assert writer in row.uncertain and conditions.get(writer)
            assert any(extra in predecessors for extra, _ in normalized.uncertain_nodes)
