"""Evidence checks for bounded configured external transfers."""

from __future__ import annotations

from ..external_summary import ExternalTransferModel
from ..physical_state import PhysicalStateResolver, PhysicalValueResolver
from .configured_physical_state import _FunctionPhysicalStateBackend


def exact_external_transfer_extent(
    view,
    model: ExternalTransferModel,
    before_position: int,
) -> int | None:
    """Return one exact observed byte extent, or reject the transfer."""
    if model.extent is None:
        return None
    backend = _FunctionPhysicalStateBackend(view)
    span = PhysicalStateResolver(backend).resolve(model.extent, before_position)
    value_ids = PhysicalValueResolver(backend).resolve(
        model.extent,
        before_position,
    )
    if span is None or len(value_ids) != 1:
        return None
    values = view.integer_values_for_definition(value_ids[0], span)
    if values is None or len(values) != 1:
        return None
    extent = next(iter(values))
    return extent if extent > 0 else None


__all__ = ["exact_external_transfer_extent"]
