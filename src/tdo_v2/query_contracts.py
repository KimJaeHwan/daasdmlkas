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
