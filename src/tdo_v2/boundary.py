"""Boundary-provider contract; core semantics do not know test names."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .physical_state import PhysicalStateSlice


class BoundaryKind(StrEnum):
    SOURCE = "source"
    SINK = "sink"


@dataclass(frozen=True, slots=True)
class CallBoundary:
    function_name: str
    instruction_address: str
    target_names: tuple[str, ...]
    language_id: str = ""


@dataclass(frozen=True, slots=True)
class BoundaryMatch:
    kind: BoundaryKind
    label: str


class BoundaryProvider(Protocol):
    def classify(self, call: CallBoundary) -> tuple[BoundaryMatch, ...]: ...

    def state(
        self,
        call: CallBoundary,
        match: BoundaryMatch,
    ) -> tuple[PhysicalStateSlice, ...]: ...


class NullBoundaryProvider:
    def classify(self, call: CallBoundary) -> tuple[BoundaryMatch, ...]:
        return ()

    def state(
        self,
        call: CallBoundary,
        match: BoundaryMatch,
    ) -> tuple[PhysicalStateSlice, ...]:
        return ()
