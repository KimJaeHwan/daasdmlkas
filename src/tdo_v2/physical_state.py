"""Architecture-neutral contracts for resolving exact physical call state."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .scope_identity import AddressCoordinate
from .span_geometry import ByteSpan


@dataclass(frozen=True, slots=True)
class PhysicalRegisterSlice:
    byte_offset: int
    byte_size: int

    def __post_init__(self) -> None:
        if type(self.byte_offset) is not int or self.byte_offset < 0:
            raise TypeError("physical register offset must be a non-negative exact int")
        if type(self.byte_size) is not int or self.byte_size <= 0:
            raise TypeError("physical register size must be a positive exact int")


@dataclass(frozen=True, slots=True)
class PhysicalMemorySlice:
    base: PhysicalRegisterSlice
    displacement: int
    byte_size: int

    def __post_init__(self) -> None:
        if type(self.base) is not PhysicalRegisterSlice:
            raise TypeError("physical memory base must be an exact register slice")
        if type(self.displacement) is not int:
            raise TypeError("physical memory displacement must be an exact int")
        if type(self.byte_size) is not int or self.byte_size <= 0:
            raise TypeError("physical memory size must be a positive exact int")


PhysicalStateSlice = PhysicalRegisterSlice | PhysicalMemorySlice


@dataclass(frozen=True, slots=True)
class PhysicalMemoryCoordinate:
    """One exact program coordinate observed in a physical memory slice."""

    selector: PhysicalMemorySlice
    coordinate: AddressCoordinate

    def __post_init__(self) -> None:
        if type(self.selector) is not PhysicalMemorySlice:
            raise TypeError("physical coordinate location must be an exact memory slice")
        if type(self.coordinate) is not AddressCoordinate:
            raise TypeError("physical coordinate value must be exact")


@dataclass(frozen=True, slots=True)
class PhysicalMemoryTransition:
    """One proven affine relation between callee and caller physical memory."""

    callee_base: PhysicalRegisterSlice
    caller_base: PhysicalRegisterSlice
    displacement_delta: int

    def __post_init__(self) -> None:
        if type(self.callee_base) is not PhysicalRegisterSlice:
            raise TypeError("callee transition base must be an exact register slice")
        if type(self.caller_base) is not PhysicalRegisterSlice:
            raise TypeError("caller transition base must be an exact register slice")
        if type(self.displacement_delta) is not int:
            raise TypeError("physical transition displacement must be an exact int")

    def project(self, selector: PhysicalMemorySlice) -> PhysicalMemorySlice | None:
        if type(selector) is not PhysicalMemorySlice:
            raise TypeError("physical transition requires an exact memory slice")
        if selector.base != self.callee_base:
            return None
        return PhysicalMemorySlice(
            self.caller_base,
            selector.displacement + self.displacement_delta,
            selector.byte_size,
        )


class PhysicalStateBackend(Protocol):
    """Supply evidence-backed spans without assigning ABI roles."""

    def register_span(self, selector: PhysicalRegisterSlice) -> ByteSpan | None: ...

    def memory_candidates(
        self,
        selector: PhysicalMemorySlice,
        before_position: int,
    ) -> tuple[ByteSpan, ...]: ...


class PhysicalValueBackend(Protocol):
    """Supply evidence-backed opaque value-definition identities."""

    def value_ids(
        self,
        selector: PhysicalStateSlice,
        before_position: int,
    ) -> tuple[int, ...]: ...


@dataclass(frozen=True, slots=True)
class PhysicalStateResolver:
    """Resolve selectors only when observed storage has one exact meaning."""

    backend: PhysicalStateBackend

    def resolve(
        self,
        selector: PhysicalStateSlice,
        before_position: int,
    ) -> ByteSpan | None:
        if type(before_position) is not int or before_position < 0:
            raise TypeError("physical state position must be a non-negative exact int")
        if type(selector) is PhysicalRegisterSlice:
            span = self.backend.register_span(selector)
            if span is not None and type(span) is not ByteSpan:
                raise TypeError("physical register resolution must return an exact span")
            return span
        if type(selector) is not PhysicalMemorySlice:
            raise TypeError("physical state selector must be exact")
        candidates = self.backend.memory_candidates(selector, before_position)
        if type(candidates) is not tuple or any(
            type(item) is not ByteSpan for item in candidates
        ):
            raise TypeError("physical memory candidates must be an exact span tuple")
        unique = frozenset(candidates)
        return next(iter(unique)) if len(unique) == 1 else None

    def resolve_all(
        self,
        selectors: tuple[PhysicalStateSlice, ...],
        before_position: int,
    ) -> tuple[ByteSpan, ...]:
        if type(selectors) is not tuple or any(
            type(item) not in (PhysicalRegisterSlice, PhysicalMemorySlice)
            for item in selectors
        ):
            raise TypeError("physical state must be an exact selector tuple")
        resolved = tuple(self.resolve(selector, before_position) for selector in selectors)
        if any(span is None for span in resolved):
            return ()
        spans = frozenset(resolved)
        if len(spans) != len(resolved):
            return ()
        return tuple(sorted(spans, key=lambda item: item.canonical_key))


@dataclass(frozen=True, slots=True)
class PhysicalValueResolver:
    """Resolve selectors to value definitions without assigning physical meaning."""

    backend: PhysicalValueBackend

    def resolve(
        self,
        selector: PhysicalStateSlice,
        before_position: int,
    ) -> tuple[int, ...]:
        if type(before_position) is not int or before_position < 0:
            raise TypeError("physical value position must be a non-negative exact int")
        if type(selector) not in (PhysicalRegisterSlice, PhysicalMemorySlice):
            raise TypeError("physical value selector must be exact")

        value_ids = self.backend.value_ids(selector, before_position)
        if type(value_ids) is not tuple or any(
            type(value_id) is not int or value_id < 0 for value_id in value_ids
        ):
            raise TypeError(
                "physical value IDs must be an exact non-negative int tuple"
            )
        return tuple(sorted(frozenset(value_ids)))

    def resolve_all(
        self,
        selectors: tuple[PhysicalStateSlice, ...],
        before_position: int,
    ) -> tuple[int, ...]:
        if type(before_position) is not int or before_position < 0:
            raise TypeError("physical value position must be a non-negative exact int")
        if type(selectors) is not tuple or any(
            type(item) not in (PhysicalRegisterSlice, PhysicalMemorySlice)
            for item in selectors
        ):
            raise TypeError("physical values require an exact selector tuple")

        resolved = tuple(self.resolve(selector, before_position) for selector in selectors)
        if any(not value_ids for value_ids in resolved):
            return ()

        seen: set[int] = set()
        for value_ids in resolved:
            if seen.intersection(value_ids):
                return ()
            seen.update(value_ids)
        return tuple(sorted(seen))
