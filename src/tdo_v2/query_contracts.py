"""Architect-owned immutable backward-query contracts."""

from __future__ import annotations

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


def local_completeness(results: tuple[SliceResult, ...]) -> LocalCompleteness:
    """Merge the local slices of one root occurrence (one per root node)."""
    if not results or any(type(row) is not SliceResult for row in results):
        raise TypeError("local completeness requires exact SliceResult rows")
    reads = {node for row in results for node in row.reachable_unresolved_read_nodes}
    writes = {node for row in results for node in row.function_unresolved_write_nodes}
    return LocalCompleteness(
        all(row.is_complete for row in results), len(reads), len(writes)
    )


def effective_completeness(
    results: tuple[SliceResult, ...], discharged_nodes: frozenset[NodeId]
) -> LocalCompleteness:
    """Local completeness after removing debt nodes discharged by evidence."""
    local = local_completeness(results)
    if type(discharged_nodes) is not frozenset:
        raise TypeError("discharged nodes must be an exact frozenset")
    reads = {
        node
        for row in results
        for node in row.reachable_unresolved_read_nodes
        if node not in discharged_nodes
    }
    return LocalCompleteness(
        not reads and local.function_unresolved_writes == 0,
        len(reads),
        local.function_unresolved_writes,
    )
