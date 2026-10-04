"""Demand-driven intrafunction backward slicing."""

from __future__ import annotations

from .graph_contracts import NodeId, NodeKind
from .normalize import NormalizedFunction
from .memory_contracts import LocalMemorySsaResult
from .memory_graph import MemoryGraphBindings
from .query_contracts import SliceResult


class BackwardSliceQuery:
    """Traverse only dependencies already proven by normalization."""

    def run(self, function: NormalizedFunction, seed: NodeId) -> SliceResult:
        if type(function) is not NormalizedFunction:
            raise TypeError("backward query requires an exact NormalizedFunction")
        if type(function.memory_ssa) is not LocalMemorySsaResult or type(
            function.memory_graph
        ) is not MemoryGraphBindings:
            raise TypeError("approved backward query requires SSA-backed normalization")
        reachable = function.dependencies.backward_reachable((seed,))
        observed = tuple(
            node
            for node in reachable
            if function.dependencies.node(node).kind is NodeKind.OBSERVED_INPUT
        )
        constants = tuple(
            node
            for node in reachable
            if function.dependencies.node(node).kind is NodeKind.CONSTANT
        )
        unresolved_read_set = set(function.memory_graph.unresolved_read_nodes)
        unresolved_reads = tuple(
            node
            for node in reachable
            if node in unresolved_read_set
        )
        return SliceResult(
            seed=seed,
            reachable_nodes=reachable,
            observed_input_nodes=observed,
            constant_nodes=constants,
            reachable_unresolved_read_nodes=unresolved_reads,
            function_unresolved_write_nodes=function.memory_graph.unresolved_write_nodes,
        )
