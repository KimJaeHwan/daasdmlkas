"""Architect-owned evidence for observed internal-CFG terminal cuts."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json

from .model import StorageScopeId, StorageScopeKind
from .scope_identity import AddressCoordinate, InstructionFlowEvidence


@dataclass(frozen=True, slots=True)
class ObservedTerminalCut:
    instruction_address: AddressCoordinate
    block_key: str
    fallthrough: AddressCoordinate | None
    flow_targets: tuple[AddressCoordinate, ...]
    flow: InstructionFlowEvidence

    def __post_init__(self) -> None:
        if type(self.instruction_address) is not AddressCoordinate:
            raise TypeError("terminal-cut instruction address must be exact")
        if type(self.block_key) is not str or not self.block_key:
            raise TypeError("terminal-cut block key must be a non-empty exact str")
        if self.fallthrough is not None and type(self.fallthrough) is not AddressCoordinate:
            raise TypeError("terminal-cut fallthrough must be exact or None")
        if type(self.flow_targets) is not tuple or any(
            type(item) is not AddressCoordinate for item in self.flow_targets
        ):
            raise TypeError("terminal-cut flow targets must be an exact tuple")
        if tuple(sorted(set(self.flow_targets))) != self.flow_targets:
            raise ValueError("terminal-cut flow targets must be sorted and unique")
        if type(self.flow) is not InstructionFlowEvidence:
            raise TypeError("terminal-cut flow evidence must be exact")

    @property
    def canonical_key(self) -> tuple[int, int]:
        return (
            self.instruction_address.space_id,
            self.instruction_address.byte_offset,
        )


@dataclass(frozen=True, slots=True)
class FunctionTerminalCuts:
    program_scope: StorageScopeId
    function_scope: StorageScopeId
    observation_digest: bytes
    sites: tuple[ObservedTerminalCut, ...]
    canonical_digest: bytes = field(init=False)

    def __post_init__(self) -> None:
        _require_scope(self.program_scope, StorageScopeKind.PROGRAM, "terminal-cut program")
        _require_scope(self.function_scope, StorageScopeKind.FUNCTION, "terminal-cut function")
        _require_digest(self.observation_digest, "terminal-cut observation")
        if type(self.sites) is not tuple or any(
            type(item) is not ObservedTerminalCut for item in self.sites
        ):
            raise TypeError("terminal-cut sites must be an exact tuple")
        keys = tuple(site.canonical_key for site in self.sites)
        if tuple(sorted(set(keys))) != keys:
            raise ValueError("terminal-cut sites must be sorted and unique")
        block_keys = tuple(site.block_key for site in self.sites)
        if len(set(block_keys)) != len(block_keys):
            raise ValueError("terminal-cut block keys must be unique")
        digest = hashlib.sha256(
            json.dumps(
                _payload(self), ensure_ascii=True, separators=(",", ":")
            ).encode("ascii")
        ).digest()
        object.__setattr__(self, "canonical_digest", digest)

    @property
    def block_keys(self) -> tuple[str, ...]:
        return tuple(sorted(site.block_key for site in self.sites))


def _payload(value: FunctionTerminalCuts) -> list[object]:
    return [
        "tdo-v2-observed-terminal-cuts-v1",
        [value.program_scope.kind.value, value.program_scope.digest.hex()],
        [value.function_scope.kind.value, value.function_scope.digest.hex()],
        value.observation_digest.hex(),
        [
            [
                [site.instruction_address.space_id, site.instruction_address.byte_offset],
                site.block_key,
                None
                if site.fallthrough is None
                else [site.fallthrough.space_id, site.fallthrough.byte_offset],
                [[item.space_id, item.byte_offset] for item in site.flow_targets],
                [
                    site.flow.is_flow,
                    site.flow.has_fallthrough,
                    site.flow.is_call,
                    site.flow.is_jump,
                    site.flow.is_terminal,
                    site.flow.is_computed,
                    site.flow.is_conditional,
                    site.flow.is_unconditional,
                    site.flow.is_override,
                ],
            ]
            for site in value.sites
        ],
    ]


def _require_scope(value: object, kind: StorageScopeKind, label: str) -> None:
    if type(value) is not StorageScopeId or value.kind is not kind:
        raise TypeError(f"{label} scope must be an exact {kind.value} scope")


def _require_digest(value: object, label: str) -> None:
    if type(value) is not bytes:
        raise TypeError(f"{label} digest must be exact bytes")
    if len(value) != 32:
        raise ValueError(f"{label} digest must contain exactly 32 bytes")


__all__ = ("FunctionTerminalCuts", "ObservedTerminalCut")
