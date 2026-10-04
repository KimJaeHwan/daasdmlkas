"""Small observed-effect vocabulary for normalized Low-PCode."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from .model import (
    ByteSpan,
    NonStorage,
    ResolvedStorage,
    StorageObjectKind,
    StorageRef,
    StorageScopeId,
    StorageScopeKind,
    UnresolvedStorage,
)


StorageEvidence = StorageRef | ResolvedStorage | UnresolvedStorage | NonStorage


EFFECT_DECODE_CONTRACT_VERSION = 3


class EffectKind(StrEnum):
    READ = "read"
    WRITE = "write"
    COPY = "copy"
    KILL = "kill"
    JOIN = "join"
    UNKNOWN_WRITE = "unknown_write"
    CALL = "call"
    BRANCH = "branch"


@dataclass(frozen=True, slots=True)
class UnresolvedMemoryAccess:
    address: StorageEvidence | None
    width: int
    raw_address: StorageRef | None = None

    def __post_init__(self) -> None:
        if self.address is not None and not any(
            type(self.address) is candidate
            for candidate in (StorageRef, ResolvedStorage, UnresolvedStorage, NonStorage)
        ):
            raise TypeError("memory access address must be exact storage evidence or None")
        if type(self.width) is not int:
            raise TypeError("memory access width must be an exact int")
        if self.width <= 0:
            raise ValueError("memory access width must be positive")
        if self.raw_address is not None and type(self.raw_address) is not StorageRef:
            raise TypeError("raw memory address must be an exact StorageRef or None")


@dataclass(frozen=True, slots=True)
class ObservedEffect:
    operation_key: str
    kind: EffectKind
    reads: tuple[StorageEvidence, ...] = ()
    writes: tuple[StorageEvidence, ...] = ()
    memory_read: UnresolvedMemoryAccess | None = None
    memory_write: UnresolvedMemoryAccess | None = None
    call_targets: tuple[str, ...] = ()
    block_key: str | None = None
    unresolved_reads: tuple[UnresolvedMemoryAccess, ...] = ()
    unresolved_writes: tuple[UnresolvedMemoryAccess, ...] = ()

    def __post_init__(self) -> None:
        if type(self.operation_key) is not str or not self.operation_key:
            raise TypeError("effect operation key must be a non-empty exact str")
        if type(self.kind) is not EffectKind:
            raise TypeError("effect kind must be an exact EffectKind")
        for values in (
            self.reads,
            self.writes,
            self.call_targets,
            self.unresolved_reads,
            self.unresolved_writes,
        ):
            if type(values) is not tuple:
                raise TypeError("effect collections must be exact tuples")
        for value in (*self.reads, *self.writes):
            if not any(
                type(value) is candidate
                for candidate in (StorageRef, ResolvedStorage, UnresolvedStorage, NonStorage)
            ):
                raise TypeError("effect storage evidence must use exact contract values")
        if any(type(target) is not str for target in self.call_targets):
            raise TypeError("call targets must be exact strings")
        for access in (self.memory_read, self.memory_write):
            if access is not None and type(access) is not UnresolvedMemoryAccess:
                raise TypeError("memory effects must be exact unresolved access records")
        for access in (*self.unresolved_reads, *self.unresolved_writes):
            if type(access) is not UnresolvedMemoryAccess:
                raise TypeError(
                    "unresolved effect collections require exact access records"
                )
        if self.block_key is not None and (
            type(self.block_key) is not str or not self.block_key
        ):
            raise TypeError("effect block key must be a non-empty exact str or None")


@dataclass(frozen=True, slots=True)
class ObservedEffectBlock:
    key: str
    predecessors: tuple[str, ...]
    effects: tuple[ObservedEffect, ...]

    def __post_init__(self) -> None:
        _require_nonempty_string(self.key, "effect block key")
        if type(self.predecessors) is not tuple:
            raise TypeError("effect block predecessors must be an exact tuple")
        for predecessor in self.predecessors:
            _require_nonempty_string(predecessor, "effect predecessor key")
        if len(set(self.predecessors)) != len(self.predecessors):
            raise ValueError("effect block predecessors must not contain duplicates")
        if type(self.effects) is not tuple or any(
            type(effect) is not ObservedEffect for effect in self.effects
        ):
            raise TypeError("effect blocks require an exact tuple of ObservedEffect")
        if any(effect.block_key != self.key for effect in self.effects):
            raise ValueError("every effect must name its containing block exactly")


@dataclass(frozen=True, slots=True)
class ObservedEffectUnit:
    contract_version: int
    function_scope: StorageScopeId
    entry_block_key: str
    blocks: tuple[ObservedEffectBlock, ...]
    observed_terminal_block_keys: tuple[str, ...] = ()
    effect_evidence_digest: bytes = field(kw_only=True)

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int:
            raise TypeError("effect contract version must be an exact int")
        if self.contract_version != EFFECT_DECODE_CONTRACT_VERSION:
            raise ValueError("unsupported effect-decode contract version")
        if type(self.function_scope) is not StorageScopeId:
            raise TypeError("effect units require an exact StorageScopeId")
        if self.function_scope.kind is not StorageScopeKind.FUNCTION:
            raise TypeError("effect units require a function scope")
        _require_nonempty_string(self.entry_block_key, "effect entry block key")
        if type(self.blocks) is not tuple or any(
            type(block) is not ObservedEffectBlock for block in self.blocks
        ):
            raise TypeError("effect units require an exact tuple of effect blocks")
        if not self.blocks:
            raise ValueError("effect units require at least one block")

        keys = tuple(block.key for block in self.blocks)
        if len(set(keys)) != len(keys):
            raise ValueError("effect block keys must be unique")
        known = set(keys)
        if self.entry_block_key not in known:
            raise ValueError("effect entry block key must name an existing block")
        if any(
            predecessor not in known
            for block in self.blocks
            for predecessor in block.predecessors
        ):
            raise ValueError("every effect predecessor must name an existing block")
        if type(self.observed_terminal_block_keys) is not tuple or any(
            type(key) is not str or not key
            for key in self.observed_terminal_block_keys
        ):
            raise TypeError("observed terminal block keys must be an exact string tuple")
        if (
            tuple(sorted(set(self.observed_terminal_block_keys)))
            != self.observed_terminal_block_keys
        ):
            raise ValueError("observed terminal block keys must be sorted and unique")
        if any(key not in known for key in self.observed_terminal_block_keys):
            raise ValueError("observed terminal block keys must name existing blocks")
        _require_effect_evidence_digest(self.effect_evidence_digest)

        operation_keys = tuple(
            effect.operation_key for block in self.blocks for effect in block.effects
        )
        if len(set(operation_keys)) != len(operation_keys):
            raise ValueError("effect operation keys must be unique within a unit")
        self._validate_reachability()
        self._validate_projectable_effects()

    def _validate_reachability(self) -> None:
        successors = {block.key: set() for block in self.blocks}
        for block in self.blocks:
            for predecessor in block.predecessors:
                successors[predecessor].add(block.key)
        pending = [self.entry_block_key]
        reached: set[str] = set()
        while pending:
            key = pending.pop()
            if key in reached:
                continue
            reached.add(key)
            pending.extend(successors[key] - reached)
        if reached != set(successors):
            raise ValueError("every effect block must be reachable from the observed entry")

    def _validate_projectable_effects(self) -> None:
        for block in self.blocks:
            for effect in block.effects:
                if any(
                    type(value) is UnresolvedStorage
                    for value in (*effect.reads, *effect.writes)
                ):
                    raise ValueError(
                        "unresolved storage requires width-preserving sideband evidence"
                    )
                self._validate_direct_sideband(effect)
                concrete_writes = tuple(
                    value.span
                    for value in effect.writes
                    if type(value) is ResolvedStorage
                )
                _require_disjoint_spans(concrete_writes)
                self._validate_function_unique_scopes(effect)
                if effect.kind is EffectKind.KILL:
                    concrete_or_raw_reads = any(
                        type(value) in (ResolvedStorage, StorageRef)
                        for value in effect.reads
                    )
                    if not concrete_writes:
                        raise ValueError(
                            "explicit kill requires at least one concrete write"
                        )
                    if (
                        concrete_or_raw_reads
                        or effect.unresolved_reads
                        or effect.memory_read is not None
                    ):
                        raise ValueError("explicit kill cannot consume storage reads")

    @staticmethod
    def _validate_direct_sideband(effect: ObservedEffect) -> None:
        for access in (*effect.unresolved_reads, *effect.unresolved_writes):
            if type(access.address) is not UnresolvedStorage:
                raise ValueError(
                    "direct unresolved sideband requires unresolved result evidence"
                )
            if type(access.raw_address) is not StorageRef:
                raise ValueError(
                    "direct unresolved sideband requires an exact raw coordinate"
                )
            if access.width != access.raw_address.size:
                raise ValueError(
                    "direct unresolved sideband width must match the raw storage size"
                )

    def _validate_function_unique_scopes(self, effect: ObservedEffect) -> None:
        spans: list[ByteSpan] = [
            value.span
            for value in (*effect.reads, *effect.writes)
            if type(value) is ResolvedStorage
        ]
        for access in (
            *effect.unresolved_reads,
            *effect.unresolved_writes,
            effect.memory_read,
            effect.memory_write,
        ):
            if access is not None and type(access.address) is ResolvedStorage:
                spans.append(access.address.span)
        if any(
            span.object_id.kind in (
                StorageObjectKind.FUNCTION_UNIQUE,
                StorageObjectKind.FUNCTION_RELATIVE,
            )
            and span.object_id.scope != self.function_scope
            for span in spans
        ):
            raise ValueError(
                "function-local effect evidence must use the unit function scope"
            )


def _require_nonempty_string(value: object, label: str) -> None:
    if type(value) is not str:
        raise TypeError(f"{label} must be an exact str")
    if not value:
        raise ValueError(f"{label} must not be empty")


def _require_effect_evidence_digest(value: object) -> None:
    if type(value) is not bytes:
        raise TypeError("effect evidence digest must be exact bytes")
    if len(value) != 32:
        raise ValueError("effect evidence digest must contain exactly 32 bytes")
    if value == bytes(32):
        raise ValueError("effect evidence digest cannot use the zero sentinel")


def _require_disjoint_spans(spans: tuple[ByteSpan, ...]) -> None:
    ordered = sorted(
        spans,
        key=lambda span: (span.object_id, span.start, span.end),
    )
    for left, right in zip(ordered, ordered[1:]):
        if left.overlaps(right):
            raise ValueError("resolved writes in one effect must be pairwise disjoint")
