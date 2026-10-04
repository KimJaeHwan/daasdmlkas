"""Unwired raw memory-effect coverage for a configured function.

This is an observation ledger, not a CFG reachability, execution, alias,
privacy, transport, or event-suppression certificate. Unsupported raw shapes
remain typed debt.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..call_seeds import _operation_key
from ..scope_identity import AddressCoordinate, VarnodeKindCode
from .configured_interprocedural_contracts import ConfiguredFunctionAnalysis
from .configured_recursive_frame_inventory import (
    CallTokenObservation,
    FrameMemoryAccess,
    RecursiveFrameInventory,
    ReturnTokenObservation,
    build_recursive_frame_inventory,
)


class AllEffectDebtReason(StrEnum):
    FRAME_INCOMPLETE = "frame_incomplete"
    REPLAY_MISMATCH = "replay_mismatch"
    UNKNOWN_OPCODE = "unknown_opcode"
    UNSUPPORTED_SHAPE = "unsupported_shape"
    UNSUPPORTED_ADDRESS_ROLE = "unsupported_address_role"
    RESOURCE_BOUND = "resource_bound"


@dataclass(frozen=True, slots=True)
class AllEffectDebt:
    reason: AllEffectDebtReason
    operation_key: str


class DirectEffectKind(StrEnum):
    READ = "read"
    WRITE = "write"


@dataclass(frozen=True, slots=True)
class DirectAddressEffect:
    operation_key: str
    opcode: str
    kind: DirectEffectKind
    operand_ordinal: int  # input index, or -1 for output
    coordinate: AddressCoordinate
    byte_size: int

    @property
    def stop(self) -> int:
        return self.coordinate.byte_offset + self.byte_size


@dataclass(frozen=True, slots=True)
class RecursiveAllEffectInventory:
    function_scope_digest: bytes
    observation_digest: bytes
    memory_unit_digest: bytes
    frame_accesses: tuple[FrameMemoryAccess, ...]
    call_tokens: tuple[CallTokenObservation, ...]
    return_tokens: tuple[ReturnTokenObservation, ...]
    direct_address_effects: tuple[DirectAddressEffect, ...]
    debts: tuple[AllEffectDebt, ...]

    @property
    def complete(self) -> bool:
        """Raw role coverage only; no reachability, alias, or suppression authority."""
        return not self.debts

    def require_complete(self) -> None:
        if self.debts:
            raise RecursiveAllEffectInventoryIncomplete(self)


class RecursiveAllEffectInventoryIncomplete(RuntimeError):
    def __init__(self, inventory: RecursiveAllEffectInventory) -> None:
        self.inventory = inventory
        super().__init__("observed all-effect inventory is incomplete")


# (exact input count, output required, selector indices). The selector is a
# control/address-space operand and never a direct ADDRESS data read. CALL's
# additional raw arguments are not admitted by this narrow Low-Pcode ledger.
_RULES: dict[str, tuple[int, bool, frozenset[int]]] = {}
for _opcode in (
    "COPY", "CAST", "INT_ZEXT", "INT_SEXT", "INT_2COMP", "INT_NEGATE",
    "BOOL_NEGATE", "FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", "FLOAT_CEIL",
    "FLOAT_FLOOR", "FLOAT_ROUND", "FLOAT_NAN", "INT2FLOAT", "FLOAT2FLOAT",
    "TRUNC", "POPCOUNT", "LZCOUNT",
):
    _RULES[_opcode] = (1, True, frozenset())
for _opcode in (
    "INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM",
    "INT_SREM", "INT_AND", "INT_OR", "INT_XOR", "INT_LEFT", "INT_RIGHT",
    "INT_SRIGHT", "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS",
    "INT_LESSEQUAL", "INT_SLESSEQUAL", "INT_CARRY", "INT_SCARRY",
    "INT_SBORROW", "BOOL_XOR", "BOOL_AND", "BOOL_OR", "FLOAT_ADD",
    "FLOAT_SUB", "FLOAT_MULT", "FLOAT_DIV", "FLOAT_EQUAL", "FLOAT_NOTEQUAL",
    "FLOAT_LESS", "FLOAT_LESSEQUAL", "PIECE", "SUBPIECE", "PTRSUB",
):
    _RULES[_opcode] = (2, True, frozenset())
_RULES.update({
    "PTRADD": (3, True, frozenset()),
    "LOAD": (2, True, frozenset({0})),
    "STORE": (3, False, frozenset({0})),
    "BRANCH": (1, False, frozenset({0})),
    "CBRANCH": (2, False, frozenset({0})),
    "BRANCHIND": (1, False, frozenset({0})),
    "CALL": (1, False, frozenset({0})),
    "CALLIND": (1, False, frozenset({0})),
    "RETURN": (1, False, frozenset({0})),
})


def build_recursive_all_effect_inventory(
    analysis: ConfiguredFunctionAnalysis,
    frame_inventory: RecursiveFrameInventory,
    /,
    *,
    max_operations: int = 4096,
    max_direct_effects: int = 4096,
    max_inventory_steps: int = 16384,
) -> RecursiveAllEffectInventory:
    """Replay frame evidence and classify every raw operation and ADDRESS role."""
    if type(analysis) is not ConfiguredFunctionAnalysis or type(frame_inventory) is not RecursiveFrameInventory:
        raise TypeError("all-effect inventory requires exact analysis and frame inventory")
    if any(type(value) is not int or value < 1 for value in
           (max_operations, max_direct_effects, max_inventory_steps)):
        raise ValueError("all-effect limits must be positive exact integers")
    replay = build_recursive_frame_inventory(analysis, max_steps=max_inventory_steps)
    debts: list[AllEffectDebt] = []
    if frame_inventory != replay:
        debts.append(AllEffectDebt(AllEffectDebtReason.REPLAY_MISMATCH, ""))
    if not replay.complete:
        debts.extend(AllEffectDebt(AllEffectDebtReason.FRAME_INCOMPLETE, row.operation_key)
                     for row in replay.debts)
    direct: list[DirectAddressEffect] = []
    operation_count = 0
    exhausted = False
    for instruction in analysis.evidence.unit.observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            key = _operation_key(instruction.address, ordinal, operation.opcode)
            operation_count += 1
            if operation_count > max_operations:
                if not exhausted:
                    debts.append(AllEffectDebt(AllEffectDebtReason.RESOURCE_BOUND, key))
                    exhausted = True
                continue
            rule = _RULES.get(operation.opcode)
            if rule is None:
                debts.append(AllEffectDebt(AllEffectDebtReason.UNKNOWN_OPCODE, key))
                continue
            count, output_required, selectors = rule
            if len(operation.inputs) != count or (operation.output is not None) != output_required:
                debts.append(AllEffectDebt(AllEffectDebtReason.UNSUPPORTED_SHAPE, key))
                continue
            # LOAD/STORE space selectors must be literal, and direct call and
            # branch selectors must really denote an observed control target.
            if operation.opcode in {"LOAD", "STORE"} and operation.inputs[0].kind is not VarnodeKindCode.CONSTANT:
                debts.append(AllEffectDebt(AllEffectDebtReason.UNSUPPORTED_ADDRESS_ROLE, key))
                continue
            if operation.opcode in {"CALL", "BRANCH", "CBRANCH"} and operation.inputs[0].kind is not VarnodeKindCode.ADDRESS:
                debts.append(AllEffectDebt(AllEffectDebtReason.UNSUPPORTED_ADDRESS_ROLE, key))
                continue
            if operation.opcode in {"CALLIND", "BRANCHIND", "RETURN"} and operation.inputs[0].kind is VarnodeKindCode.ADDRESS:
                debts.append(AllEffectDebt(AllEffectDebtReason.UNSUPPORTED_ADDRESS_ROLE, key))
                continue
            for input_ordinal, varnode in enumerate(operation.inputs):
                if varnode.kind is VarnodeKindCode.ADDRESS and input_ordinal not in selectors:
                    if len(direct) >= max_direct_effects:
                        debts.append(AllEffectDebt(AllEffectDebtReason.RESOURCE_BOUND, key))
                    else:
                        direct.append(DirectAddressEffect(key, operation.opcode,
                            DirectEffectKind.READ, input_ordinal, varnode.coordinate, varnode.byte_size))
            if operation.output is not None and operation.output.kind is VarnodeKindCode.ADDRESS:
                if len(direct) >= max_direct_effects:
                    debts.append(AllEffectDebt(AllEffectDebtReason.RESOURCE_BOUND, key))
                else:
                    direct.append(DirectAddressEffect(key, operation.opcode,
                        DirectEffectKind.WRITE, -1, operation.output.coordinate, operation.output.byte_size))
    return RecursiveAllEffectInventory(
        replay.function_scope_digest, replay.observation_digest, replay.memory_unit_digest,
        replay.accesses, replay.call_tokens, replay.return_tokens, tuple(direct),
        tuple(sorted(set(debts), key=lambda row: (row.operation_key, row.reason.value))),
    )


__all__ = (
    "AllEffectDebtReason", "AllEffectDebt", "DirectEffectKind", "DirectAddressEffect",
    "RecursiveAllEffectInventory", "RecursiveAllEffectInventoryIncomplete",
    "build_recursive_all_effect_inventory",
)
