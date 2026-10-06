"""Assumed (declared) effects of boundary calls -- a TEST-ONLY special condition.

The engine never infers what a call does: an opaque call carries
``call_clobber_read`` debt. For testing, a caller may *declare* that a
source/sink boundary call writes exactly the listed registers and leaves every
other register and all memory unchanged. Normalization then models the call
as those strong register writes, so the function body between boundaries can
be checked and sliced as if it were call-free.

This is an assumption supplied by the caller, not observed evidence. It is off
by default (``analyze_frozen_bundle(assume_boundary_call_effects=False)``) and
must only be enabled knowingly, e.g. on benchmark binaries whose source/sink
functions are known to have no other effects. Results produced with it must
be reported as relying on the assumption.
"""

from __future__ import annotations

from dataclasses import dataclass

from .physical_state import PhysicalRegisterSlice


@dataclass(frozen=True, slots=True)
class AssumedCallEffect:
    """A declared boundary call: reads ``reads``, writes ``writes``, preserves
    all other state (a sink reads its argument registers and writes nothing)."""

    label: str
    writes: tuple[PhysicalRegisterSlice, ...]
    reads: tuple[PhysicalRegisterSlice, ...] = ()

    def __post_init__(self) -> None:
        if type(self.label) is not str or not self.label:
            raise TypeError("assumed call effect requires a boundary label")
        if type(self.writes) is not tuple or any(
            type(row) is not PhysicalRegisterSlice for row in self.writes
        ):
            raise TypeError("assumed call writes must be exact register slices")
        if type(self.reads) is not tuple or any(
            type(row) is not PhysicalRegisterSlice for row in self.reads
        ):
            raise TypeError("assumed call reads must be exact register slices")


__all__ = ("AssumedCallEffect",)
