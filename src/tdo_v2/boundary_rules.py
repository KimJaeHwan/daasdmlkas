"""Declarative, benchmark-neutral source and sink boundary policy."""

from __future__ import annotations

from dataclasses import dataclass

from .boundary import BoundaryKind, BoundaryMatch, CallBoundary
from .physical_state import PhysicalStateSlice


@dataclass(frozen=True, slots=True)
class BoundaryRule:
    target_name: str
    language_id: str
    kind: BoundaryKind
    label: str
    physical_state: tuple[PhysicalStateSlice, ...]

    def __post_init__(self) -> None:
        if not self.target_name or not self.language_id or not self.label:
            raise ValueError("boundary rule needs target, language, and label")
        if type(self.kind) is not BoundaryKind or not self.physical_state:
            raise ValueError("boundary rule needs a kind and observed state")


class SymbolBoundaryProvider:
    """Apply caller-supplied observations; never infer ABI register roles."""

    def __init__(self, rules: tuple[BoundaryRule, ...]) -> None:
        if type(rules) is not tuple or any(type(row) is not BoundaryRule for row in rules):
            raise TypeError("boundary rules must be an exact tuple of BoundaryRule")
        keys = [(row.target_name, row.language_id, row.kind, row.label) for row in rules]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate boundary rule")
        self._rules = rules

    def classify(self, call: CallBoundary) -> tuple[BoundaryMatch, ...]:
        matches = {
            BoundaryMatch(row.kind, row.label)
            for row in self._rules
            if row.language_id == call.language_id
            and row.target_name in call.target_names
        }
        return tuple(sorted(matches, key=lambda row: (row.kind.value, row.label)))

    def state(
        self, call: CallBoundary, match: BoundaryMatch
    ) -> tuple[PhysicalStateSlice, ...]:
        states = {
            row.physical_state
            for row in self._rules
            if row.language_id == call.language_id
            and row.target_name in call.target_names
            and row.kind is match.kind
            and row.label == match.label
        }
        if len(states) > 1:
            raise ValueError("boundary aliases disagree on physical state")
        return next(iter(states), ())


__all__ = ("BoundaryRule", "SymbolBoundaryProvider")
