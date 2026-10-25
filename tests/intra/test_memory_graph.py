"""Exact, architect-owned materialization of conditional memory transfers."""

from dataclasses import replace

import pytest

from tdo_v2.graph import RustworkxDependencyGraph
from tdo_v2.graph_contracts import EdgeKind, EdgeRecord, NodeKind, NodeRecord
from tdo_v2.memory_contracts import (
    LOCAL_MEMORY_CONTRACT_VERSION, LocalMemoryBlock, LocalMemoryUnit,
    LocalStorageAction, MemoryWriteMode,
)
from tdo_v2.memory_graph import (
    MemoryTransfer, _materialize_local_memory_ssa,
    _validate_materialized_local_memory_ssa,
)
from tdo_v2.memory_ssa import build_local_memory_ssa
from tdo_v2.span_geometry import (
    ByteSpan, StorageObjectId, StorageObjectKind, StorageScopeId,
    StorageScopeKind,
)


def _case():
    function = StorageScopeId(StorageScopeKind.FUNCTION, b"\x01" * 32)
    program = StorageScopeId(StorageScopeKind.PROGRAM, b"\x02" * 32)
    obj = StorageObjectId(StorageObjectKind.ADDRESS_SPACE, program, 1)
    first, second = ByteSpan(obj, 0, 4), ByteSpan(obj, 4, 4)
    actions = (
        LocalStorageAction("a:store", writes=(first,), write_mode=MemoryWriteMode.DATA),
        LocalStorageAction("b:other", writes=(second,), write_mode=MemoryWriteMode.DATA),
        LocalStorageAction("c:call"),
        LocalStorageAction("d:guard"),
        LocalStorageAction("e:load", reads=(ByteSpan(obj, 0, 8),)),
    )
    unit = LocalMemoryUnit(
        LOCAL_MEMORY_CONTRACT_VERSION, function, "block",
        (LocalMemoryBlock("block", (), actions),), ("block",),
        effect_evidence_digest=b"\x03" * 32,
    )
    ssa = build_local_memory_ssa(unit)
    graph = RustworkxDependencyGraph()
    operations = {
        action.operation_key: graph.add_node(NodeRecord(
            f"op:{action.operation_key}", NodeKind.OPERATION, action.operation_key
        )) for action in ssa.actions
    }
    transfer = MemoryTransfer(
        1, 4, first, "c:call", "d:guard", "lifecycle-contract:resize",
        ("lifecycle-contract:resize", "guard:non-null"),
    )
    return graph, ssa, operations, transfer, second


def test_exact_fragment_uses_transfer_while_other_fragment_remains_direct():
    graph, ssa, operations, transfer, second = _case()
    bindings = _materialize_local_memory_ssa(graph, ssa, operations, (transfer,))
    _validate_materialized_local_memory_ssa(graph, ssa, bindings)
    assert bindings.transfers == (transfer,)
    assert len(bindings.transfer_nodes) == 1
    node = bindings.transfer_nodes[0]
    assert graph.node(node).kind is NodeKind.EFFECT
    expected = {
        (bindings.definition_nodes[1], node, EdgeKind.MEMORY_TRANSFER.value),
        (operations["c:call"], node, EdgeKind.MEMORY_TRANSFER.value),
        (operations["d:guard"], node, EdgeKind.CONTROL_DEPENDENCE.value),
        (node, operations["e:load"], EdgeKind.MEMORY_READ.value),
        (bindings.definition_nodes[2], operations["e:load"], EdgeKind.MEMORY_READ.value),
    }
    actual = {(source, target, edge.kind) for source, target, edge in graph.weighted_edges()}
    assert expected <= actual
    assert (bindings.definition_nodes[1], operations["e:load"], EdgeKind.MEMORY_READ.value) not in actual
    assert any(edge.span == second for source, target, edge in graph.weighted_edges()
               if source == bindings.definition_nodes[2] and target == operations["e:load"])
    assert bindings.definition_nodes[1] in graph.backward_reachable((operations["e:load"],))


def test_without_opt_in_retains_original_ssa_read_edges():
    graph, ssa, operations, transfer, _ = _case()
    bindings = _materialize_local_memory_ssa(graph, ssa, operations)
    assert not bindings.transfers and not bindings.transfer_nodes
    assert (bindings.definition_nodes[1], operations["e:load"],
            EdgeRecord(EdgeKind.MEMORY_READ, operation="e:load", span=transfer.span)) \
        in graph.weighted_edges()
    _validate_materialized_local_memory_ssa(graph, ssa, bindings)


@pytest.mark.parametrize("change", (
    {"definition_id": 0}, {"action_id": 3},
    {"span": None}, {"span": "not-a-span"},
    {"call": "missing"}, {"guard": "missing"},
))
def test_transfer_requires_an_exact_fragment_and_existing_operations(change):
    graph, ssa, operations, transfer, _ = _case()
    if change.get("span") is None and "span" in change:
        with pytest.raises(TypeError):
            replace(transfer, **change)
        return
    if change.get("span") == "not-a-span":
        with pytest.raises(TypeError):
            replace(transfer, **change)
        return
    with pytest.raises(ValueError):
        _materialize_local_memory_ssa(graph, ssa, operations, (replace(transfer, **change),))
    assert graph.node_count == len(operations)


@pytest.mark.parametrize("change", (
    {"contract": ""}, {"contract": 42}, {"requires": ["label"]},
    {"requires": ("guard",)}, {"requires": ("lifecycle-contract:resize", 1)},
    {"requires": ("lifecycle-contract:resize", "lifecycle-contract:resize")},
))
def test_transfer_certificate_fields_are_typed_and_bound(change):
    _, _, _, transfer, _ = _case()
    with pytest.raises((TypeError, ValueError)):
        replace(transfer, **change)


def test_duplicate_or_missing_fragment_refused_before_graph_mutation():
    graph, ssa, operations, transfer, _ = _case()
    with pytest.raises(ValueError, match="overlap"):
        _materialize_local_memory_ssa(graph, ssa, operations, (transfer, transfer))
    assert graph.node_count == len(operations)
    wrong = replace(transfer, span=ByteSpan(transfer.span.object_id, 1, 2))
    with pytest.raises(ValueError, match="exact SSA read fragment"):
        _materialize_local_memory_ssa(graph, ssa, operations, (wrong,))


def test_topology_owns_transfer_edges_and_record_identity():
    graph, ssa, operations, transfer, _ = _case()
    bindings = _materialize_local_memory_ssa(graph, ssa, operations, (transfer,))
    _validate_materialized_local_memory_ssa(graph, ssa, bindings)
    extra = graph.copy()
    extra.add_edge(operations["a:store"], bindings.transfer_nodes[0],
                   EdgeRecord(EdgeKind.MEMORY_TRANSFER, operation="a:store"))
    with pytest.raises(ValueError, match="topology"):
        _validate_materialized_local_memory_ssa(extra, ssa, bindings)
    with pytest.raises(ValueError, match="transfer binding"):
        _validate_materialized_local_memory_ssa(
            graph, ssa, replace(bindings, transfers=(replace(
                transfer, requires=("lifecycle-contract:resize", "changed")),))
        )
    with pytest.raises(ValueError, match="transfer binding"):
        _validate_materialized_local_memory_ssa(
            graph, ssa, replace(bindings, transfer_nodes=(bindings.definition_nodes[1],))
        )
