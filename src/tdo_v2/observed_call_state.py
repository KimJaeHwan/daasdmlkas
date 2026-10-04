"""Translate exact low-pcode call effects into physical-state projections."""

from __future__ import annotations

from dataclasses import dataclass

from ._scope_contracts import (
    ValidatedFunctionObservation,
    ValidatedInstruction,
    ValidatedOperation,
    VarnodeKindCode,
)
from .call_seeds import _operation_key
from .effects import ObservedEffectBlock, ObservedEffectUnit
from .physical_state import (
    PhysicalMemoryCoordinate,
    PhysicalMemorySlice,
    PhysicalMemoryTransition,
    PhysicalRegisterSlice,
)


@dataclass(frozen=True, slots=True)
class ObservedCallStateProjection:
    """A call transition justified by operations in one observed instruction."""

    call_operation_key: str
    transient_operation_keys: tuple[str, ...]
    memory_transition: PhysicalMemoryTransition
    transient_coordinate: PhysicalMemoryCoordinate

    def __post_init__(self) -> None:
        if type(self.call_operation_key) is not str or not self.call_operation_key:
            raise TypeError("call projection key must be non-empty exact text")
        if (
            type(self.transient_operation_keys) is not tuple
            or not self.transient_operation_keys
            or any(type(item) is not str or not item for item in self.transient_operation_keys)
            or self.call_operation_key in self.transient_operation_keys
            or len(set(self.transient_operation_keys)) != len(self.transient_operation_keys)
        ):
            raise ValueError("transient operation keys must be a distinct exact tuple")
        if type(self.memory_transition) is not PhysicalMemoryTransition:
            raise TypeError("call projection requires an exact memory transition")
        if type(self.transient_coordinate) is not PhysicalMemoryCoordinate:
            raise TypeError("call projection requires an exact transient coordinate")

    def project_memory(
        self, selector: PhysicalMemorySlice
    ) -> PhysicalMemorySlice | None:
        return self.memory_transition.project(selector)


def observed_call_state_projections(
    observation: ValidatedFunctionObservation,
) -> tuple[ObservedCallStateProjection, ...]:
    """Recognize only fully evidenced call-local physical state transitions."""
    if type(observation) is not ValidatedFunctionObservation:
        raise TypeError("call-state projection requires an exact observation")
    rows = []
    for instruction in observation.instructions:
        keyed_operations = tuple(
            (
                _operation_key(instruction.address, ordinal, operation.opcode),
                ordinal,
                operation,
            )
            for ordinal, operation in enumerate(instruction.operations)
        )
        projection = _observed_call_state_projection(instruction, keyed_operations)
        if projection is not None:
            rows.append(projection)
    return tuple(rows)


def observed_call_preserves_register(
    observation: ValidatedFunctionObservation,
    call_operation_key: str,
    selector: PhysicalRegisterSlice,
) -> bool:
    """Prove identity only when the call instruction has no overlapping write."""
    if type(observation) is not ValidatedFunctionObservation:
        raise TypeError("register preservation requires an exact observation")
    if type(call_operation_key) is not str or not call_operation_key:
        raise TypeError("call operation key must be non-empty exact text")
    if type(selector) is not PhysicalRegisterSlice:
        raise TypeError("register preservation requires an exact register slice")

    matches = []
    for instruction in observation.instructions:
        keyed = tuple(
            (
                _operation_key(instruction.address, ordinal, operation.opcode),
                operation,
            )
            for ordinal, operation in enumerate(instruction.operations)
        )
        if any(key == call_operation_key for key, _ in keyed):
            matches.append((instruction, keyed))
    if len(matches) != 1 or not matches[0][0].flow.is_call:
        return False
    _, keyed = matches[0]
    for _, operation in keyed:
        output = operation.output
        if output is None or output.kind is not VarnodeKindCode.REGISTER:
            continue
        output_start = output.coordinate.byte_offset
        output_end = output_start + output.byte_size
        selector_end = selector.byte_offset + selector.byte_size
        if output_start < selector_end and selector.byte_offset < output_end:
            return False
    return True


def project_persistent_call_state(
    unit: ObservedEffectUnit,
    observation: ValidatedFunctionObservation,
) -> ObservedEffectUnit:
    """Remove call-local transient effects using the same physical projection."""
    if type(unit) is not ObservedEffectUnit:
        raise TypeError("call-state projection requires an exact effect unit")
    if type(observation) is not ValidatedFunctionObservation:
        raise TypeError("call-state projection requires an exact observation")

    effect_keys = {
        effect.operation_key for block in unit.blocks for effect in block.effects
    }
    removed = {
        operation_key
        for projection in observed_call_state_projections(observation)
        if all(key in effect_keys for key in projection.transient_operation_keys)
        for operation_key in projection.transient_operation_keys
    }
    if not removed:
        return unit
    return ObservedEffectUnit(
        unit.contract_version,
        unit.function_scope,
        unit.entry_block_key,
        tuple(
            ObservedEffectBlock(
                block.key,
                block.predecessors,
                tuple(
                    effect
                    for effect in block.effects
                    if effect.operation_key not in removed
                ),
            )
            for block in unit.blocks
        ),
        unit.observed_terminal_block_keys,
        effect_evidence_digest=unit.effect_evidence_digest,
    )


def _observed_call_state_projection(
    instruction: ValidatedInstruction,
    keyed_operations: tuple[tuple[str, int, ValidatedOperation], ...],
) -> ObservedCallStateProjection | None:
    if not instruction.flow.is_call or instruction.fallthrough is None:
        return None
    calls = tuple(
        row for row in keyed_operations if row[2].opcode in {"CALL", "CALLIND"}
    )
    if len(calls) != 1:
        return None
    call_key, call_ordinal, _ = calls[0]
    candidates = []
    for adjust_key, adjust_ordinal, adjust in keyed_operations:
        if (
            adjust_ordinal >= call_ordinal
            or adjust.opcode != "INT_SUB"
            or adjust.output is None
            or adjust.output.kind is not VarnodeKindCode.REGISTER
            or len(adjust.inputs) != 2
            or adjust.inputs[0] != adjust.output
            or adjust.inputs[1].kind is not VarnodeKindCode.CONSTANT
            or adjust.inputs[1].coordinate.byte_offset != adjust.output.byte_size
        ):
            continue
        matching_stores = tuple(
            store_key
            for store_key, store_ordinal, store in keyed_operations
            if (
                adjust_ordinal < store_ordinal < call_ordinal
                and store.opcode == "STORE"
                and len(store.inputs) == 3
                and store.inputs[0].kind is VarnodeKindCode.CONSTANT
                and store.inputs[0].coordinate.byte_offset == instruction.address.space_id
                and store.inputs[1] == adjust.output
                and store.inputs[2].kind is VarnodeKindCode.CONSTANT
                and store.inputs[2].coordinate.byte_offset
                == instruction.fallthrough.byte_offset
                and store.inputs[2].byte_size == adjust.output.byte_size
            )
        )
        if len(matching_stores) != 1:
            continue
        register = PhysicalRegisterSlice(
            adjust.output.coordinate.byte_offset,
            adjust.output.byte_size,
        )
        candidates.append(
            ObservedCallStateProjection(
                call_key,
                (adjust_key, matching_stores[0]),
                PhysicalMemoryTransition(
                    register,
                    register,
                    -adjust.output.byte_size,
                ),
                PhysicalMemoryCoordinate(
                    PhysicalMemorySlice(
                        register,
                        -adjust.output.byte_size,
                        adjust.output.byte_size,
                    ),
                    instruction.fallthrough,
                ),
            )
        )
    return candidates[0] if len(candidates) == 1 else None
