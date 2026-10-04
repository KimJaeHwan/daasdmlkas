"""Physical-storage contracts for optional external-call summaries."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .physical_state import (
    PhysicalMemorySlice,
    PhysicalRegisterSlice,
    PhysicalStateSlice,
)


class ExternalTransferKind(StrEnum):
    OBSERVED_MEMORY_COPY = "observed_memory_copy"
    OBSERVED_VALUE_TO_MEMORY = "observed_value_to_memory"


@dataclass(frozen=True, slots=True)
class ExternalTransferModel:
    model_id: str
    kind: ExternalTransferKind
    destination_pointer: PhysicalStateSlice
    source: PhysicalStateSlice
    extent: PhysicalStateSlice | None = None

    def __post_init__(self) -> None:
        if type(self.model_id) is not str or not self.model_id:
            raise TypeError("external transfer model ID must be non-empty exact text")
        if type(self.kind) is not ExternalTransferKind:
            raise TypeError("external transfer kind must be exact")
        if type(self.destination_pointer) not in (
            PhysicalRegisterSlice,
            PhysicalMemorySlice,
        ):
            raise TypeError("external destination pointer must be an exact physical slice")
        if type(self.source) not in (PhysicalRegisterSlice, PhysicalMemorySlice):
            raise TypeError("external source must be an exact physical slice")
        if self.extent is not None and type(self.extent) not in (
            PhysicalRegisterSlice,
            PhysicalMemorySlice,
        ):
            raise TypeError("external transfer extent must be an exact physical slice")
        if (
            self.extent is not None
            and self.kind is not ExternalTransferKind.OBSERVED_MEMORY_COPY
        ):
            raise ValueError("only observed memory copies may carry an extent")


@dataclass(frozen=True, slots=True)
class ExternalCallbackInput:
    caller_value: PhysicalStateSlice
    callback_value: PhysicalStateSlice

    def __post_init__(self) -> None:
        if type(self.caller_value) not in (PhysicalRegisterSlice, PhysicalMemorySlice):
            raise TypeError("callback caller value must be an exact physical slice")
        if type(self.callback_value) not in (PhysicalRegisterSlice, PhysicalMemorySlice):
            raise TypeError("callback input value must be an exact physical slice")
        if self.caller_value.byte_size != self.callback_value.byte_size:
            raise ValueError("callback storage correspondence must preserve byte size")


@dataclass(frozen=True, slots=True)
class ExternalCallbackModel:
    model_id: str
    callback_pointer: PhysicalStateSlice
    inputs: tuple[ExternalCallbackInput, ...]

    def __post_init__(self) -> None:
        if type(self.model_id) is not str or not self.model_id:
            raise TypeError("external callback model ID must be non-empty exact text")
        if type(self.callback_pointer) not in (
            PhysicalRegisterSlice,
            PhysicalMemorySlice,
        ):
            raise TypeError("external callback pointer must be an exact physical slice")
        if type(self.inputs) is not tuple or any(
            type(item) is not ExternalCallbackInput for item in self.inputs
        ):
            raise TypeError("external callback inputs must be an exact tuple")
        _reject_overlapping_callback_inputs(self.inputs, side="caller")
        _reject_overlapping_callback_inputs(self.inputs, side="callback")


def _physical_slices_overlap(
    left: PhysicalStateSlice,
    right: PhysicalStateSlice,
) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) is PhysicalRegisterSlice:
        return _intervals_overlap(
            left.byte_offset,
            left.byte_size,
            right.byte_offset,
            right.byte_size,
        )
    if left.base != right.base:
        return False
    return _intervals_overlap(
        left.displacement,
        left.byte_size,
        right.displacement,
        right.byte_size,
    )


def _intervals_overlap(
    left_start: int,
    left_size: int,
    right_start: int,
    right_size: int,
) -> bool:
    return left_start < right_start + right_size and right_start < left_start + left_size


def _reject_overlapping_callback_inputs(
    inputs: tuple[ExternalCallbackInput, ...],
    *,
    side: str,
) -> None:
    slices = tuple(
        item.caller_value if side == "caller" else item.callback_value
        for item in inputs
    )
    for index, left in enumerate(slices):
        if any(_physical_slices_overlap(left, right) for right in slices[index + 1 :]):
            raise ValueError(
                f"external callback {side} inputs must not overlap physical storage"
            )


@dataclass(frozen=True, slots=True)
class ExternalCallBoundary:
    function_name: str
    instruction_address: str
    target_names: tuple[str, ...]
    language_id: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.function_name, "external caller"),
            (self.instruction_address, "external call instruction"),
            (self.language_id, "external call language"),
        ):
            if type(value) is not str or not value:
                raise TypeError(f"{label} must be non-empty exact text")
        if type(self.target_names) is not tuple or any(
            type(item) is not str or not item for item in self.target_names
        ):
            raise TypeError("external target names must be an exact text tuple")


class ExternalSummaryProvider(Protocol):
    def summarize(
        self, call: ExternalCallBoundary
    ) -> tuple[ExternalTransferModel, ...]: ...

    def callbacks(
        self, call: ExternalCallBoundary
    ) -> tuple[ExternalCallbackModel, ...]: ...


class NullExternalSummaryProvider:
    def summarize(
        self, call: ExternalCallBoundary
    ) -> tuple[ExternalTransferModel, ...]:
        return ()

    def callbacks(
        self, call: ExternalCallBoundary
    ) -> tuple[ExternalCallbackModel, ...]:
        return ()
