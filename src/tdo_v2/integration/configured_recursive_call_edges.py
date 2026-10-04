"""Verified direct-call edges for complete observed frame inventories.

This unwired result binds call targets only. It proves no frame privacy,
transport, non-escape, or permission to suppress configured events.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..call_contracts import CallOperationKind, DirectCallTarget, FunctionCallSeedUnit
from ..call_seeds import _operation_key
from ..configured_naming_contracts import (
    CapturedNamingSidecar,
    NamingOpcode,
    NamingResolutionState,
)
from ..scope_identity import VarnodeKindCode
from .configured_interprocedural_contracts import ConfiguredFunctionAnalysis
from .configured_recursive_frame_inventory import (
    RecursiveFrameInventory,
    build_recursive_frame_inventory,
)
from .configured_recursive_frame_separation import CallerSuppliedCallEdge
from .configured_target_resolution import _selected_resolved_target


class DirectCallEdgeDebtReason(StrEnum):
    INCOMPLETE_INVENTORY = "incomplete_inventory"
    MISSING_OR_AMBIGUOUS_CALL = "missing_or_ambiguous_call"
    UNSUPPORTED_TARGET = "unsupported_target"
    TARGET_MISMATCH = "target_mismatch"
    EVIDENCE_MISMATCH = "evidence_mismatch"
    RESOURCE_BOUND = "resource_bound"


class VerifiedDirectCallEdgesIncomplete(RuntimeError):
    def __init__(self, reason: DirectCallEdgeDebtReason, detail: str) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason.value}: {detail}")


@dataclass(frozen=True, slots=True)
class VerifiedDirectCallEdges:
    """Closed, exact edge inventory for the supplied program analyses."""

    program_scope_digest: bytes
    edges: tuple[CallerSuppliedCallEdge, ...]


def _debt(reason: DirectCallEdgeDebtReason, detail: str) -> None:
    raise VerifiedDirectCallEdgesIncomplete(reason, detail)


def verify_direct_call_edges(
    analyses: tuple[ConfiguredFunctionAnalysis, ...],
    inventories: tuple[RecursiveFrameInventory, ...],
    /,
    *,
    max_functions: int = 64,
    max_calls: int = 256,
    max_operations: int = 4096,
    max_inventory_steps: int = 16384,
) -> VerifiedDirectCallEdges:
    """Replay inventories and bind every token to one raw direct internal CALL.

    A resolved thunk chain is unsupported here: the raw ADDRESS operand must
    equal the selected terminal target coordinate itself.
    """
    if (type(analyses) is not tuple or any(type(row) is not ConfiguredFunctionAnalysis for row in analyses)
            or type(inventories) is not tuple or any(type(row) is not RecursiveFrameInventory for row in inventories)):
        raise TypeError("direct-call verification requires exact analysis and inventory tuples")
    limits = (max_functions, max_calls, max_operations, max_inventory_steps)
    if any(type(limit) is not int or limit < 1 for limit in limits):
        raise ValueError("direct-call limits must be positive exact integers")
    if len(analyses) > max_functions or len(inventories) > max_functions:
        _debt(DirectCallEdgeDebtReason.RESOURCE_BOUND, "function limit")
    if not analyses:
        _debt(DirectCallEdgeDebtReason.INCOMPLETE_INVENTORY, "no function analyses")
    if len(analyses) != len(inventories):
        _debt(DirectCallEdgeDebtReason.INCOMPLETE_INVENTORY, "analysis/inventory count")

    by_scope = {}
    program_digest = None
    total_calls = 0
    total_operations = 0
    for analysis in analyses:
        evidence = analysis.evidence
        scopes = evidence.unit.scopes
        seeds = evidence.seeds
        naming = evidence.naming
        if (type(seeds) is not FunctionCallSeedUnit or type(naming) is not CapturedNamingSidecar
                or analysis.normalized.scopes is not scopes
                or analysis.normalized.call_seeds != seeds
                or not analysis.normalized.dependencies.is_frozen
                or seeds.function_scope != scopes.function.scope
                or seeds.program_scope != scopes.program.scope
                or seeds.observation_digest != scopes.function.observation_digest
                or seeds.function_entry != scopes.function.entry
                or evidence.unit.observation is None):
            _debt(DirectCallEdgeDebtReason.EVIDENCE_MISMATCH, "analysis identity or call evidence")
        current_program = scopes.program.scope.digest
        if program_digest is None:
            program_digest = current_program
        elif current_program != program_digest:
            _debt(DirectCallEdgeDebtReason.EVIDENCE_MISMATCH, "mixed program scopes")
        scope = scopes.function.scope.digest
        if scope in by_scope:
            _debt(DirectCallEdgeDebtReason.EVIDENCE_MISMATCH, "duplicate function scope")
        by_scope[scope] = analysis
        total_calls += len(seeds.callsites)
        total_operations += sum(len(row.operations) for row in evidence.unit.observation.instructions)
    if total_calls > max_calls or total_operations > max_operations:
        _debt(DirectCallEdgeDebtReason.RESOURCE_BOUND, "call or raw-operation limit")

    inventory_by_scope = {}
    for inventory in inventories:
        scope = inventory.function_scope_digest
        if scope in inventory_by_scope:
            _debt(DirectCallEdgeDebtReason.INCOMPLETE_INVENTORY, "duplicate frame inventory")
        inventory_by_scope[scope] = inventory
    if set(inventory_by_scope) != set(by_scope):
        _debt(DirectCallEdgeDebtReason.INCOMPLETE_INVENTORY, "missing or foreign frame inventory")

    by_entry = {}
    for scope, analysis in by_scope.items():
        if analysis.entry in by_entry:
            _debt(DirectCallEdgeDebtReason.EVIDENCE_MISMATCH, "ambiguous callee entry")
        by_entry[analysis.entry] = scope

    edges = []
    for scope, analysis in sorted(by_scope.items()):
        inventory = inventory_by_scope[scope]
        replay = build_recursive_frame_inventory(analysis, max_steps=max_inventory_steps)
        if not replay.complete:
            reason = (DirectCallEdgeDebtReason.RESOURCE_BOUND if any(
                debt.reason.value == "budget_exhausted" for debt in replay.debts
            ) else DirectCallEdgeDebtReason.INCOMPLETE_INVENTORY)
            _debt(reason, "replayed frame inventory is incomplete")
        if inventory != replay:
            _debt(DirectCallEdgeDebtReason.EVIDENCE_MISMATCH, "frame inventory differs from replay")
        seeds = analysis.evidence.seeds.callsites
        names = analysis.evidence.naming.rows
        if len(seeds) != len(names):
            _debt(DirectCallEdgeDebtReason.MISSING_OR_AMBIGUOUS_CALL, "seed/naming count")
        seed_by_key = {}
        name_by_key = {}
        for seed in seeds:
            if seed.operation_key in seed_by_key:
                _debt(DirectCallEdgeDebtReason.MISSING_OR_AMBIGUOUS_CALL, "duplicate call seed")
            seed_by_key[seed.operation_key] = seed
        for name in names:
            key = _operation_key(name.instruction, name.operation_ordinal, name.opcode.value)
            if key in name_by_key:
                _debt(DirectCallEdgeDebtReason.MISSING_OR_AMBIGUOUS_CALL, "duplicate naming row")
            name_by_key[key] = name
        raw_by_key = {}
        for instruction in analysis.evidence.unit.observation.instructions:
            for ordinal, operation in enumerate(instruction.operations):
                if operation.opcode not in {"CALL", "CALLIND"}:
                    continue
                key = _operation_key(instruction.address, ordinal, operation.opcode)
                if key in raw_by_key:
                    _debt(DirectCallEdgeDebtReason.MISSING_OR_AMBIGUOUS_CALL, "duplicate raw call")
                raw_by_key[key] = (instruction, ordinal, operation)
        tokens = inventory.call_tokens
        token_keys = [row.call_operation_key for row in tokens]
        if (len(set(token_keys)) != len(token_keys)
                or set(token_keys) != set(seed_by_key)
                or set(token_keys) != set(name_by_key)
                or set(token_keys) != set(raw_by_key)):
            _debt(DirectCallEdgeDebtReason.MISSING_OR_AMBIGUOUS_CALL, "call/token/seed/naming closure")
        for key in sorted(token_keys):
            seed = seed_by_key[key]
            name = name_by_key[key]
            instruction, ordinal, raw = raw_by_key[key]
            if (seed.locator.instruction != instruction.address
                    or seed.locator.operation_ordinal != ordinal
                    or seed.locator.function_scope != analysis.evidence.unit.scopes.function.scope
                    or seed.inputs != raw.inputs or seed.explicit_output != raw.output
                    or name.instruction != instruction.address or name.operation_ordinal != ordinal
                    or name.selector != (raw.inputs[0] if raw.inputs else None)):
                _debt(DirectCallEdgeDebtReason.EVIDENCE_MISMATCH, "call locator or selector")
            if (raw.opcode != "CALL" or seed.kind is not CallOperationKind.DIRECT
                    or name.opcode is not NamingOpcode.CALL
                    or len(raw.inputs) != 1 or raw.inputs[0].kind is not VarnodeKindCode.ADDRESS
                    or type(seed.target) is not DirectCallTarget
                    or name.resolution.state not in {
                        NamingResolutionState.RESOLVED_NAMED,
                        NamingResolutionState.RESOLVED_UNNAMED,
                    }):
                _debt(DirectCallEdgeDebtReason.UNSUPPORTED_TARGET, "indirect or unresolved call")
            target = _selected_resolved_target(name)
            if target is None or target.is_external or target.is_thunk:
                _debt(DirectCallEdgeDebtReason.UNSUPPORTED_TARGET, "external or unresolved target")
            coordinate = raw.inputs[0].coordinate
            if coordinate != seed.target.coordinate or coordinate != target.coordinate:
                _debt(DirectCallEdgeDebtReason.TARGET_MISMATCH, "raw, seed, and named target differ")
            callee_scope = by_entry.get(coordinate)
            if callee_scope is None:
                _debt(DirectCallEdgeDebtReason.UNSUPPORTED_TARGET, "target has no supplied analysis")
            edges.append(CallerSuppliedCallEdge(scope, key, callee_scope))
    assert program_digest is not None
    return VerifiedDirectCallEdges(program_digest, tuple(edges))


__all__ = [
    "DirectCallEdgeDebtReason", "VerifiedDirectCallEdgesIncomplete",
    "VerifiedDirectCallEdges", "verify_direct_call_edges",
]
