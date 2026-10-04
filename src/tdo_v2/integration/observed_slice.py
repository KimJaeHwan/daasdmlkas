"""Backward queries rooted in externally labelled physical storage."""

from __future__ import annotations

from dataclasses import dataclass

from ..normalize import NormalizedFunction
from ..observed_boundary_projection import (
    ObservedBoundaryNode,
    ObservedBoundaryProjection,
)
from ..query import BackwardSliceQuery
from ..query_contracts import SliceResult


@dataclass(frozen=True, slots=True)
class ObservedBoundarySlice:
    root: ObservedBoundaryNode
    result: SliceResult
    reached_origins: tuple[ObservedBoundaryNode, ...]

    @property
    def reached_origin_labels(self) -> tuple[str, ...]:
        return tuple(sorted({item.label for item in self.reached_origins}))


def run_observed_boundary_slices(
    function: NormalizedFunction,
    boundaries: ObservedBoundaryProjection,
    /,
) -> tuple[ObservedBoundarySlice, ...]:
    if type(function) is not NormalizedFunction:
        raise TypeError("observed slicing requires an exact normalized function")
    if type(boundaries) is not ObservedBoundaryProjection:
        raise TypeError("observed slicing requires an exact boundary projection")
    query = BackwardSliceQuery()
    rows = []
    for root in boundaries.query_roots:
        result = query.run(function, root.node)
        reachable = set(result.reachable_nodes)
        origins = tuple(
            item for item in boundaries.report_origins if item.node in reachable
        )
        rows.append(ObservedBoundarySlice(root, result, origins))
    return tuple(rows)


__all__ = ("ObservedBoundarySlice", "run_observed_boundary_slices")
