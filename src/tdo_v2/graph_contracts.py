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
    VALUE_VERSION = "value_version"
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


@dataclass(frozen=True, slots=True)
class EdgeRecord:
    kind: str
    operation: str | None = None
    occurrence: int | None = None
    span: ByteSpan | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not str or not self.kind:
            raise TypeError("edge kind must be a non-empty exact str")
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
