"""Architect-owned immutable backward-query contracts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .graph_contracts import NodeId


@dataclass(frozen=True, slots=True)
class SliceResult:
    seed: NodeId
    reachable_nodes: tuple[NodeId, ...]
    observed_input_nodes: tuple[NodeId, ...]
    constant_nodes: tuple[NodeId, ...]
    reachable_unresolved_read_nodes: tuple[NodeId, ...]
    function_unresolved_write_nodes: tuple[NodeId, ...]

    @property
    def is_complete(self) -> bool:
        return not (
            self.reachable_unresolved_read_nodes
            or self.function_unresolved_write_nodes
        )


@dataclass(frozen=True, slots=True)
class LocalCompleteness:
    """Debt visible to the root's own backward slice.

    ``complete`` is False when any reachable read or any write in the root's
    function remains unresolved. It says nothing about callers or callees;
    an empty origin set with ``complete=False`` is not evidence of absence.
    """

    complete: bool
    reachable_unresolved_reads: int
    function_unresolved_writes: int
    # roots bound to a call's consume event with no data inputs: the sink's
    # argument state is not represented, so nothing can be claimed complete
    unbound_roots: int = 0


def local_completeness(
    results: tuple[SliceResult, ...], identity: Mapping[NodeId, NodeId] | None = None
) -> LocalCompleteness:
    """Merge the local slices of one root occurrence (one per root node).

    ``identity`` maps a debt node to the debt it counts as: a call-clobber
    node per (read, call) counts as its read's one debt (docs 25.83 S2d)."""
    if not results or any(type(row) is not SliceResult for row in results):
        raise TypeError("local completeness requires exact SliceResult rows")
    identity = identity or {}
    reads = {identity.get(node, node) for row in results for node in row.reachable_unresolved_read_nodes}
    writes = {node for row in results for node in row.function_unresolved_write_nodes}
    return LocalCompleteness(
        all(row.is_complete for row in results), len(reads), len(writes)
    )


def effective_completeness(
    results: tuple[SliceResult, ...], discharged_nodes: frozenset[NodeId],
    identity: Mapping[NodeId, NodeId] | None = None,
) -> LocalCompleteness:
    """Local completeness after removing debt nodes discharged by evidence (a
    read counted by ``identity`` stays while any of its nodes does)."""
    local = local_completeness(results, identity)
    if type(discharged_nodes) is not frozenset:
        raise TypeError("discharged nodes must be an exact frozenset")
    identity = identity or {}
    reads = {
        identity.get(node, node)
        for row in results
        for node in row.reachable_unresolved_read_nodes
        if node not in discharged_nodes
    }
    return LocalCompleteness(
        not reads and local.function_unresolved_writes == 0,
        len(reads),
        local.function_unresolved_writes,
    )
