"""Architect-owned immutable backward-query contracts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace

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
    # roots bound to a call's consume event (no exact definition of the sink's
    # argument state): nothing can be claimed complete
    unbound_roots: int = 0
    # unknown control transfers the root rests on (U2a, docs 25.93): the site
    # keys ``control:<function>:<instruction>`` of the control context of the
    # root's function (``control:unavailable:<function>`` where none could be
    # computed) -- the root is the observed graph's answer, true only if no
    # such transfer resumes
    control_obligations: tuple[str, ...] = ()
    # roots bound on an incomplete successor graph (the sink's own state read
    # through ``conditional_state_definition``)
    conditional_roots: int = 0

    def __post_init__(self) -> None:
        if self.complete and (self.control_obligations or self.conditional_roots):
            raise ValueError("a root resting on an unknown control transfer is never complete")


def local_completeness(
    results: tuple[SliceResult, ...], identity: Mapping[NodeId, NodeId] | None = None,
    blocking_writes: frozenset | None = None,
) -> LocalCompleteness:
    """Merge the local slices of one root occurrence (one per root node).

    ``identity`` maps a debt node to the debt it counts as: a call-clobber
    node per (read, call) counts as its read's one debt (docs 25.83 S2d).
    ``blocking_writes`` (the summary engine, B' docs 25.96): the unresolved
    writes that still block completeness function-wide (the WILD ones); the
    others reach the root only through its read debts or a refused binding,
    and their function owns a memory-writes site. None: every one blocks."""
    if not results or any(type(row) is not SliceResult for row in results):
        raise TypeError("local completeness requires exact SliceResult rows")
    identity = identity or {}
    reads = {identity.get(node, node) for row in results for node in row.reachable_unresolved_read_nodes}
    writes = {node for row in results for node in row.function_unresolved_write_nodes}
    if blocking_writes is None:
        complete = all(row.is_complete for row in results)
    else:
        complete = not any(row.reachable_unresolved_read_nodes for row in results) \
            and not writes & blocking_writes
    return LocalCompleteness(complete, len(reads), len(writes))


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


def with_control(completeness: LocalCompleteness, obligations=(), conditional_roots: int = 0) -> LocalCompleteness:
    """``completeness`` resting also on ``obligations`` (control site keys)
    and, with ``conditional_roots``, bound on an incomplete successor graph:
    never complete then (U2a, docs 25.93)."""
    keys = tuple(sorted(set(completeness.control_obligations) | set(obligations)))
    conditional = max(completeness.conditional_roots, conditional_roots)
    if keys == completeness.control_obligations and conditional == completeness.conditional_roots:
        return completeness
    return replace(completeness, complete=completeness.complete and not keys and not conditional,
                   control_obligations=keys, conditional_roots=conditional)
