"""Declarative, benchmark-neutral source and sink boundary policy."""

from __future__ import annotations

from dataclasses import dataclass

from .assumed_call_effects import AssumedCallEffect
from .boundary import BoundaryKind, BoundaryMatch, CallBoundary
from .physical_state import PhysicalRegisterSlice, PhysicalStateSlice


@dataclass(frozen=True, slots=True)
class BoundaryRule:
    target_name: str
    language_id: str
    kind: BoundaryKind
    label: str
    physical_state: tuple[PhysicalStateSlice, ...]
    # TEST-ONLY special condition: declare that this boundary call writes only
    # its source output (sink: nothing) and preserves all other state. Used
    # only when the engine is also run with assume_boundary_call_effects=True.
    assume_call_effect: bool = False

    def __post_init__(self) -> None:
        if not self.target_name or not self.language_id or not self.label:
            raise ValueError("boundary rule needs target, language, and label")
        if type(self.kind) is not BoundaryKind or not self.physical_state:
            raise ValueError("boundary rule needs a kind and observed state")
        if type(self.assume_call_effect) is not bool:
            raise TypeError("assume_call_effect must be an exact bool")


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

    def assumed_call_effect(
        self, call: CallBoundary, match: BoundaryMatch
    ) -> AssumedCallEffect | None:
        """TEST-ONLY declared effect of a matched boundary call, if a rule opts in."""
        rows = {
            row
            for row in self._rules
            if row.language_id == call.language_id
            and row.target_name in call.target_names
            and row.kind is match.kind
            and row.label == match.label
            and row.assume_call_effect
        }
        if len(rows) != 1:
            return None
        (row,) = rows
        if any(type(item) is not PhysicalRegisterSlice for item in row.physical_state):
            return None  # memory states are not modelled by the assumption
        if row.kind is BoundaryKind.SINK:
            return AssumedCallEffect(row.label, (), row.physical_state)
        if any(type(item) is not PhysicalRegisterSlice for item in row.physical_state):
            return None  # memory outputs are not modelled by the assumption
        return AssumedCallEffect(row.label, row.physical_state)


__all__ = ("BoundaryRule", "SymbolBoundaryProvider")
