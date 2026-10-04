"""Boundary labels attached to observed physical storage nodes."""

from __future__ import annotations

from dataclasses import dataclass

from .boundary import BoundaryKind
from .graph_contracts import NodeId
from .model import ByteSpan


@dataclass(frozen=True, slots=True)
class ObservedBoundaryNode:
    """One external label bound to an observed graph node and physical spans."""

    kind: BoundaryKind
    label: str
    node: NodeId
    occurrence_ordinal: int
    fragment_ordinal: int
    physical_spans: tuple[ByteSpan, ...] = ()

    def __post_init__(self) -> None:
        if type(self.kind) is not BoundaryKind:
            raise TypeError("observed boundary kind must be exact")
        if type(self.label) is not str or not self.label:
            raise TypeError("observed boundary label must be non-empty text")
        for value, name in (
            (self.node, "node"),
            (self.occurrence_ordinal, "occurrence ordinal"),
            (self.fragment_ordinal, "fragment ordinal"),
        ):
            if type(value) is not int or value < 0:
                raise TypeError(f"observed boundary {name} must be non-negative")
        if type(self.physical_spans) is not tuple or any(
            type(item) is not ByteSpan for item in self.physical_spans
        ):
            raise TypeError("observed boundary physical spans must be exact")
        if tuple(
            sorted(self.physical_spans, key=lambda item: item.canonical_key)
        ) != self.physical_spans:
            raise ValueError("observed boundary physical spans must be sorted")
        if len({item.canonical_key for item in self.physical_spans}) != len(
            self.physical_spans
        ):
            raise ValueError("observed boundary physical spans must be unique")


@dataclass(frozen=True, slots=True)
class ObservedBoundaryProjection:
    """External boundary labels for one normalized function."""

    nodes: tuple[ObservedBoundaryNode, ...]

    def __post_init__(self) -> None:
        if type(self.nodes) is not tuple or any(
            type(item) is not ObservedBoundaryNode for item in self.nodes
        ):
            raise TypeError("observed boundary nodes must be an exact tuple")

    @property
    def query_roots(self) -> tuple[ObservedBoundaryNode, ...]:
        return tuple(item for item in self.nodes if item.kind is BoundaryKind.SINK)

    @property
    def report_origins(self) -> tuple[ObservedBoundaryNode, ...]:
        return tuple(item for item in self.nodes if item.kind is BoundaryKind.SOURCE)


EMPTY_OBSERVED_BOUNDARIES = ObservedBoundaryProjection(())


__all__ = (
    "EMPTY_OBSERVED_BOUNDARIES",
    "ObservedBoundaryNode",
    "ObservedBoundaryProjection",
)
