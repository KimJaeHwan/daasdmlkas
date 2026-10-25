"""Architect-owned immutable dependency-graph contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable, Protocol

from .model import ByteSpan


NodeId = int


class NodeKind(StrEnum):
    INSTRUCTION = "instruction"
    OBSERVED_INPUT = "observed_input"
    CONSTANT = "constant"
    OPERATION = "operation"
    MEMORY_DEFINITION = "memory_definition"
    MEMORY_JOIN = "memory_join"
    MEMORY_DEBT = "memory_debt"
    EFFECT = "effect"


@dataclass(frozen=True, slots=True)
class NodeRecord:
    key: str
    kind: NodeKind
    label: str

    def __post_init__(self) -> None:
        if type(self.key) is not str or not self.key:
            raise TypeError("node key must be a non-empty exact str")
        if type(self.kind) is not NodeKind:
            raise TypeError("node kind must be an exact NodeKind")
        if type(self.label) is not str:
            raise TypeError("node label must be an exact str")


class EdgeKind(StrEnum):
    """Closed vocabulary of dependency-graph edge kinds."""

    CONTROL = "control"                          # CFG successor (cfg graph)
    VALUE_INPUT = "value_input"                  # constant -> operation input
    MEMORY_DEFINES = "memory_defines"            # operation -> memory definition
    MEMORY_READ = "memory_read"                  # definition -> reading operation
    MEMORY_TRANSFER = "memory_transfer"          # preserved byte source/CALL -> transfer
    MEMORY_JOIN_INPUT = "memory_join_input"      # definition -> JOIN
    UNRESOLVED_READ = "unresolved_read"          # debt -> reading operation
    UNRESOLVED_WRITE = "unresolved_write"        # writing operation -> debt
    CALL_CLOBBER_READ = "call_clobber_read"      # call clobber debt -> read
    MAY_ALIAS_WRITE = "may_alias_write"          # possible writer -> may-alias debt
    MAY_ALIAS_READ = "may_alias_read"            # may-alias debt -> read
    CONTROL_DEPENDENCE = "control_dependence"    # decision -> dependent operation


_EDGE_KINDS = frozenset(item.value for item in EdgeKind)
# each kind's own value str: str() of a StrEnum member makes a new str per
# record (docs 25.31 B0-7: 80 MB of the 30k scale point's MAY_ALIAS_WRITE records)
_KIND_VALUES = {item: item.value for item in EdgeKind}


@dataclass(frozen=True, slots=True)
class EdgeRecord:
    kind: str  # an EdgeKind value; stored as plain str for serialization
    operation: str | None = None
    occurrence: int | None = None
    span: ByteSpan | None = None

    def __post_init__(self) -> None:
        if self.kind not in _EDGE_KINDS:
            raise TypeError(f"edge kind must be an EdgeKind: {self.kind!r}")
        if type(self.kind) is not str:
            object.__setattr__(self, "kind", _KIND_VALUES[self.kind])
        if self.operation is not None and type(self.operation) is not str:
            raise TypeError("edge operation must be an exact str or None")
        if self.occurrence is not None and (
            type(self.occurrence) is not int or self.occurrence < 0
        ):
            raise TypeError("edge occurrence must be a non-negative exact int or None")
        if self.span is not None and type(self.span) is not ByteSpan:
            raise TypeError("edge span must be an exact ByteSpan or None")


class DependencyGraph(Protocol):
    def add_node(self, record: NodeRecord) -> NodeId: ...

    def add_edge(self, source: NodeId, target: NodeId, record: EdgeRecord) -> None: ...

    def predecessors(self, node: NodeId) -> tuple[NodeId, ...]: ...

    def backward_reachable(self, seeds: Iterable[NodeId]) -> tuple[NodeId, ...]: ...
