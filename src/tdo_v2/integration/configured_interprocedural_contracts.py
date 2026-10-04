"""Immutable contracts for configured interprocedural slice completion."""

from __future__ import annotations

from dataclasses import dataclass

from .._scope_contracts import AddressCoordinate
from ..model import ByteSpan
from ..normalize import NormalizedFunction
from ..observed_boundary_projection import ObservedBoundaryProjection
from .observed_function_session import ObservedFunctionEvidence
from .observed_slice import ObservedBoundarySlice


@dataclass(frozen=True, slots=True)
class ConfiguredFunctionAnalysis:
    """One selected function and its exact local analysis products."""

    evidence: ObservedFunctionEvidence
    normalized: NormalizedFunction
    boundaries: ObservedBoundaryProjection
    slices: tuple[ObservedBoundarySlice, ...]

    def __post_init__(self) -> None:
        if type(self.evidence) is not ObservedFunctionEvidence:
            raise TypeError("configured analysis requires exact observed evidence")
        if type(self.normalized) is not NormalizedFunction:
            raise TypeError("configured analysis requires exact normalization")
        if type(self.boundaries) is not ObservedBoundaryProjection:
            raise TypeError("analysis requires exact observed boundaries")
        if type(self.slices) is not tuple or any(
            type(item) is not ObservedBoundarySlice for item in self.slices
        ):
            raise TypeError("configured analysis requires exact local slices")

    @property
    def entry(self) -> AddressCoordinate:
        return self.evidence.seeds.function_entry


@dataclass(frozen=True, slots=True)
class InterproceduralTransferProof:
    """One exact call boundary crossed by a storage-state transfer."""

    caller_scope_digest: bytes
    call_operation_key: str
    callee_entry: AddressCoordinate
    callee_scope_digest: bytes
    callee_write_operation_key: str
    target_span: ByteSpan
    pointer_dereferences: int

    def __post_init__(self) -> None:
        for value, name in (
            (self.caller_scope_digest, "caller scope"),
            (self.callee_scope_digest, "callee scope"),
        ):
            if type(value) is not bytes or len(value) != 32:
                raise TypeError(f"{name} must be exact 32-byte evidence")
        if type(self.callee_entry) is not AddressCoordinate:
            raise TypeError("callee entry must be an exact coordinate")
        for value, name in (
            (self.call_operation_key, "call operation key"),
            (self.callee_write_operation_key, "callee write operation key"),
        ):
            if type(value) is not str or not value:
                raise TypeError(f"{name} must be non-empty exact text")
        if type(self.target_span) is not ByteSpan:
            raise TypeError("interprocedural target must be an exact byte span")
        if type(self.pointer_dereferences) is not int or self.pointer_dereferences < 0:
            raise TypeError("pointer dereference count must be non-negative")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (
            self.caller_scope_digest,
            self.call_operation_key,
            self.callee_entry.space_id,
            self.callee_entry.byte_offset,
            self.callee_scope_digest,
            self.callee_write_operation_key,
            self.target_span.canonical_key,
            self.pointer_dereferences,
        )


@dataclass(frozen=True, slots=True)
class InterproceduralOriginProof:
    """One origin carried through one or more exact storage transfers."""

    label: str
    origin_entry: AddressCoordinate
    origin_scope_digest: bytes
    origin_node: int
    caller_scope_digest: bytes
    call_operation_key: str
    callee_entry: AddressCoordinate
    callee_scope_digest: bytes
    callee_write_operation_key: str
    target_span: ByteSpan
    pointer_dereferences: int
    prior_transfers: tuple[InterproceduralTransferProof, ...] = ()

    def __post_init__(self) -> None:
        if type(self.label) is not str or not self.label:
            raise TypeError("interprocedural origin label must be non-empty text")
        for value, name in (
            (self.origin_entry, "origin entry"),
            (self.callee_entry, "callee entry"),
        ):
            if type(value) is not AddressCoordinate:
                raise TypeError(f"{name} must be an exact coordinate")
        for value, name in (
            (self.origin_scope_digest, "origin scope"),
            (self.caller_scope_digest, "caller scope"),
            (self.callee_scope_digest, "callee scope"),
        ):
            if type(value) is not bytes or len(value) != 32:
                raise TypeError(f"{name} must be exact 32-byte evidence")
        if type(self.origin_node) is not int or self.origin_node < 0:
            raise TypeError("origin node must be a non-negative exact int")
        for value, name in (
            (self.call_operation_key, "call operation key"),
            (self.callee_write_operation_key, "callee write operation key"),
        ):
            if type(value) is not str or not value:
                raise TypeError(f"{name} must be non-empty exact text")
        if type(self.target_span) is not ByteSpan:
            raise TypeError("interprocedural target must be an exact byte span")
        if type(self.pointer_dereferences) is not int or self.pointer_dereferences < 0:
            raise TypeError("pointer dereference count must be non-negative")
        if type(self.prior_transfers) is not tuple or any(
            type(item) is not InterproceduralTransferProof
            for item in self.prior_transfers
        ):
            raise TypeError("prior transfers must be an exact proof tuple")
        if len({item.canonical_key for item in self.prior_transfers}) != len(
            self.prior_transfers
        ):
            raise ValueError("prior transfers must be unique")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (
            self.label,
            self.origin_entry.space_id,
            self.origin_entry.byte_offset,
            self.origin_node,
            self.call_operation_key,
            self.callee_entry.space_id,
            self.callee_entry.byte_offset,
            self.callee_write_operation_key,
            self.target_span.canonical_key,
            self.pointer_dereferences,
            tuple(item.canonical_key for item in self.prior_transfers),
        )

    @property
    def final_transfer(self) -> InterproceduralTransferProof:
        return InterproceduralTransferProof(
            self.caller_scope_digest,
            self.call_operation_key,
            self.callee_entry,
            self.callee_scope_digest,
            self.callee_write_operation_key,
            self.target_span,
            self.pointer_dereferences,
        )


@dataclass(frozen=True, slots=True)
class ObservedCallByteReplacement:
    """Conditional event-to-read byte version, not a legacy SSA mutation."""

    proof: InterproceduralOriginProof
    reader_operation_key: str
    reader_node: int
    read_span: ByteSpan
    superseded_definition_nodes: tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self.proof) is not InterproceduralOriginProof:
            raise TypeError("call-byte replacement requires exact origin proof")
        if type(self.reader_operation_key) is not str or not self.reader_operation_key:
            raise TypeError("call-byte replacement requires reader operation key")
        if type(self.reader_node) is not int or self.reader_node < 0:
            raise TypeError("call-byte replacement requires reader node")
        if type(self.read_span) is not ByteSpan:
            raise TypeError("call-byte replacement requires exact read span")
        if (type(self.superseded_definition_nodes) is not tuple
                or not self.superseded_definition_nodes
                or any(type(node) is not int or node < 0
                       for node in self.superseded_definition_nodes)
                or tuple(sorted(set(self.superseded_definition_nodes)))
                != self.superseded_definition_nodes):
            raise TypeError("call-byte replacement requires sorted definition nodes")
        if not self.proof.target_span.contains(self.read_span):
            raise ValueError("call-byte proof does not cover reader bytes")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (
            self.proof.canonical_key,
            self.reader_operation_key,
            self.reader_node,
            self.read_span.canonical_key,
            self.superseded_definition_nodes,
        )


@dataclass(frozen=True, slots=True)
class ObservedDynamicAliasReplacement:
    """Certified conditional STORE-to-LOAD version, not local SSA authority."""

    store_operation_key: str
    load_operation_key: str
    store_node: int
    load_node: int
    unresolved_read_node: int
    width: int
    relative_offsets: tuple[int, ...]

    def __post_init__(self) -> None:
        if (type(self.store_operation_key) is not str or not self.store_operation_key
                or type(self.load_operation_key) is not str or not self.load_operation_key):
            raise TypeError("dynamic alias requires exact operation keys")
        if (any(type(node) is not int or node < 0 for node in (
                self.store_node, self.load_node, self.unresolved_read_node))
                or type(self.width) is not int or self.width <= 0):
            raise TypeError("dynamic alias requires valid nodes and width")
        if (type(self.relative_offsets) is not tuple
                or not self.relative_offsets
                or any(type(offset) is not int for offset in self.relative_offsets)
                or tuple(sorted(set(self.relative_offsets))) != self.relative_offsets):
            raise TypeError("dynamic alias requires bounded sorted offsets")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (
            self.store_operation_key, self.load_operation_key,
            self.store_node, self.load_node, self.unresolved_read_node,
            self.width, self.relative_offsets,
        )


@dataclass(frozen=True, slots=True)
class InterproceduralSliceCompletion:
    root_node: int
    proofs: tuple[InterproceduralOriginProof, ...]
    call_byte_replacements: tuple[ObservedCallByteReplacement, ...] = ()
    dynamic_alias_replacements: tuple[ObservedDynamicAliasReplacement, ...] = ()

    def __post_init__(self) -> None:
        if type(self.root_node) is not int or self.root_node < 0:
            raise TypeError("completed root node must be a non-negative exact int")
        if type(self.proofs) is not tuple or any(
            type(item) is not InterproceduralOriginProof for item in self.proofs
        ):
            raise TypeError("interprocedural proofs must be an exact tuple")
        if tuple(sorted(self.proofs, key=lambda item: item.canonical_key)) != self.proofs:
            raise ValueError("interprocedural proofs must be canonically sorted")
        if len({item.canonical_key for item in self.proofs}) != len(self.proofs):
            raise ValueError("interprocedural proofs must be unique")
        if (type(self.call_byte_replacements) is not tuple
                or any(type(item) is not ObservedCallByteReplacement
                       for item in self.call_byte_replacements)):
            raise TypeError("call-byte replacements must be an exact tuple")
        if tuple(sorted(self.call_byte_replacements,
                        key=lambda item: item.canonical_key)) != self.call_byte_replacements:
            raise ValueError("call-byte replacements must be sorted")
        if len({item.canonical_key for item in self.call_byte_replacements}) != len(
            self.call_byte_replacements
        ):
            raise ValueError("call-byte replacements must be unique")
        proof_keys = {item.canonical_key for item in self.proofs}
        if any(item.proof.canonical_key not in proof_keys
               for item in self.call_byte_replacements):
            raise ValueError("call-byte replacement lacks completed proof")
        if (type(self.dynamic_alias_replacements) is not tuple
                or any(type(item) is not ObservedDynamicAliasReplacement
                       for item in self.dynamic_alias_replacements)
                or tuple(sorted(self.dynamic_alias_replacements,
                                key=lambda item: item.canonical_key))
                != self.dynamic_alias_replacements
                or len({item.canonical_key for item in self.dynamic_alias_replacements})
                != len(self.dynamic_alias_replacements)):
            raise TypeError("dynamic alias replacements require a unique sorted tuple")

    @property
    def reached_origin_labels(self) -> tuple[str, ...]:
        return tuple(sorted({item.label for item in self.proofs}))


__all__ = [
    "ConfiguredFunctionAnalysis",
    "InterproceduralOriginProof",
    "ObservedCallByteReplacement",
    "ObservedDynamicAliasReplacement",
    "InterproceduralSliceCompletion",
    "InterproceduralTransferProof",
]
