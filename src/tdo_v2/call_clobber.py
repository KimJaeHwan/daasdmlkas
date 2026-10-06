"""Demand-driven debt for storage that an unknown call may have overwritten.

The local normalizer has no evidence about what an opaque CALL, CALLIND, or
CALLOTHER writes, so pre-call definitions would otherwise flow through the
call as if the callee preserved every register and every byte of memory.

A forward byte-level analysis tracks, per program point, which bytes are
*clean*: written after the most recent call on every path (or never crossed a
call). A read of a byte that is not clean, and not covered by an evidenced
exemption, gets a ``call_clobber_read`` debt. Pre-call definitions stay
reachable, so the slice still reports them, but it is no longer complete.

Exemptions are proved from the observation, never from an ABI:

* the stack-pointer register, identified per call instruction by the
  observed ``r = r - size; STORE r <- return address; CALL`` shape
  (``observed_call_state``), whenever every call in the function has it;
* the function's own stack object (``FUNCTION_RELATIVE`` on that register's
  entry value), when no stack-derived value escapes the function: it is never
  stored to memory, copied to another register, or passed to CALLOTHER.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._scope_contracts import (
    ValidatedFunctionObservation,
    ValidatedOperation,
    VarnodeKindCode,
)
from .call_seeds import _operation_key
from .effects import EffectKind, ObservedEffectUnit
from .model import (
    ResolvedStorage,
    StorageObjectId,
    StorageObjectKind,
    StorageRef,
    StorageResolutionContext,
    VarnodeKind,
)
from .observed_call_state import observed_call_state_projections
from .relative_memory import _function_relative_object_id
from .span_geometry import ByteSpan
from .storage import _resolve_validated_storage

CALL_CLOBBER_CONTRACT_VERSION = 1

_CALL_OPCODES = frozenset({"CALL", "CALLIND", "CALLOTHER"})
# Boolean results cannot carry a pointer value.
_BOOLEAN_OPCODES = frozenset({
    "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL",
    "INT_SLESSEQUAL", "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
    "BOOL_NEGATE", "BOOL_XOR", "BOOL_AND", "BOOL_OR",
    "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL",
    "FLOAT_NAN",
})
_NON_VALUE_OPCODES = frozenset({
    "LOAD", "STORE", "BRANCH", "CBRANCH", "BRANCHIND", "RETURN",
    "CALL", "CALLIND",
})


@dataclass(frozen=True, slots=True)
class CallClobberRead:
    """One read whose bytes may come from before an unevidenced call."""

    operation_key: str
    spans: tuple[ByteSpan, ...]

    def __post_init__(self) -> None:
        if type(self.operation_key) is not str or not self.operation_key:
            raise TypeError("call-clobber read requires an exact operation key")
        if (
            type(self.spans) is not tuple
            or not self.spans
            or any(type(span) is not ByteSpan for span in self.spans)
        ):
            raise TypeError("call-clobber read requires exact byte spans")


@dataclass(frozen=True, slots=True)
class _Clean:
    """Bytes that cannot hold a value from before the most recent call."""

    objects: frozenset[StorageObjectId]
    bytes: frozenset[tuple[StorageObjectId, int]]

    def holds(self, object_id: StorageObjectId, offset: int) -> bool:
        return object_id in self.objects or (object_id, offset) in self.bytes

    def meet(self, other: "_Clean") -> "_Clean":
        objects = self.objects & other.objects
        candidates = self.bytes | other.bytes
        return _Clean(
            objects,
            frozenset(
                item
                for item in candidates
                if item[0] not in objects
                and self.holds(*item)
                and other.holds(*item)
            ),
        )

    def written(self, span: ByteSpan) -> "_Clean":
        if span.object_id in self.objects:
            return self
        return _Clean(
            self.objects,
            self.bytes | {(span.object_id, offset) for offset in range(span.start, span.end)},
        )


# ``None`` means no call has been crossed on any path: everything is clean.
_State = _Clean | None


def derive_call_clobber_reads(
    unit: ObservedEffectUnit,
    observation: ValidatedFunctionObservation,
    context: StorageResolutionContext,
    address_space_id: int | None,
) -> tuple[CallClobberRead, ...]:
    """Return reads that may observe storage written by an unevidenced call."""
    if type(unit) is not ObservedEffectUnit:
        raise TypeError("call-clobber analysis requires an exact effect unit")
    if type(observation) is not ValidatedFunctionObservation:
        raise TypeError("call-clobber analysis requires an exact observation")
    if type(context) is not StorageResolutionContext:
        raise TypeError("call-clobber analysis requires an exact storage context")

    operations = {
        _operation_key(instruction.address, ordinal, operation.opcode): operation
        for instruction in observation.instructions
        for ordinal, operation in enumerate(instruction.operations)
    }
    calls = {key for key, operation in operations.items() if operation.opcode in _CALL_OPCODES}
    if not calls:
        return ()
    after_call = _after_call_state(operations, observation, context, address_space_id, unit)

    blocks = {block.key: block for block in unit.blocks}
    successors: dict[str, list[str]] = {key: [] for key in blocks}
    for block in unit.blocks:
        for predecessor in block.predecessors:
            successors[predecessor].append(block.key)

    in_states: dict[str, _State] = {unit.entry_block_key: None}
    pending = [unit.entry_block_key]
    while pending:
        key = min(pending)
        pending.remove(key)
        state = _transfer(blocks[key], in_states[key], calls, after_call, None)
        for successor in sorted(successors[key]):
            if successor not in in_states:
                in_states[successor] = state
            else:
                merged = _meet(in_states[successor], state)
                if merged == in_states[successor]:
                    continue
                in_states[successor] = merged
            if successor not in pending:
                pending.append(successor)

    rows: list[CallClobberRead] = []
    for key in sorted(in_states):
        _transfer(blocks[key], in_states[key], calls, after_call, rows)
    return tuple(sorted(rows, key=lambda row: row.operation_key))


def _meet(left: _State, right: _State) -> _State:
    if left is None:
        return right
    if right is None:
        return left
    return left.meet(right)


def _transfer(block, state: _State, calls, after_call: _Clean, rows) -> _State:
    for effect in block.effects:
        if state is not None and rows is not None:
            crossed = []
            for evidence in effect.reads:
                if type(evidence) is not ResolvedStorage:
                    continue
                span = evidence.span
                dirty = [
                    offset
                    for offset in range(span.start, span.end)
                    if not state.holds(span.object_id, offset)
                ]
                if dirty:
                    crossed.append(ByteSpan(span.object_id, dirty[0], dirty[-1] + 1 - dirty[0]))
            if crossed:
                rows.append(CallClobberRead(effect.operation_key, tuple(crossed)))
        if effect.operation_key in calls or effect.kind is EffectKind.CALL:
            state = after_call
        if state is not None:
            for evidence in effect.writes:
                if type(evidence) is ResolvedStorage:
                    state = state.written(evidence.span)
    return state


def _after_call_state(operations, observation, context, address_space_id, unit) -> _Clean:
    """What every call in this function is evidenced to leave unchanged."""
    call_keys = {
        key for key, operation in operations.items() if operation.opcode in {"CALL", "CALLIND"}
    }
    projections = observed_call_state_projections(observation)
    registers = {
        (
            row.memory_transition.caller_base.byte_offset,
            row.memory_transition.caller_base.byte_size,
        )
        for row in projections
        if row.call_operation_key in call_keys
    }
    evidenced = {row.call_operation_key for row in projections}
    if (
        len(registers) != 1
        or call_keys - evidenced
        or any(operation.opcode == "CALLOTHER" for operation in operations.values())
    ):
        return _Clean(frozenset(), frozenset())
    ((offset, size),) = registers
    resolved = _resolve_validated_storage(
        StorageRef(VarnodeKind.REGISTER, "", offset, size, space_id=_register_space(operations)),
        context,
    )
    if type(resolved) is not ResolvedStorage:
        return _Clean(frozenset(), frozenset())
    stack_pointer = resolved.span
    clean = _Clean(frozenset(), frozenset()).written(stack_pointer)
    if address_space_id is not None and not _stack_escapes(operations, offset, size):
        stack_object = _function_relative_object_id(
            unit.function_scope, stack_pointer, address_space_id
        )
        clean = _Clean(frozenset({stack_object}), clean.bytes)
    return clean


def _register_space(operations) -> int | None:
    for operation in operations.values():
        for varnode in (*operation.inputs, operation.output):
            if varnode is not None and varnode.kind is VarnodeKindCode.REGISTER:
                return varnode.coordinate.space_id
    return None


def _stack_escapes(operations: dict[str, ValidatedOperation], offset: int, size: int) -> bool:
    """Flow-insensitive: can a stack-derived value leave register-local use?"""
    stack_space = None
    for operation in operations.values():
        for varnode in (*operation.inputs, operation.output):
            if (
                varnode is not None
                and varnode.kind is VarnodeKindCode.REGISTER
                and varnode.coordinate.byte_offset == offset
                and varnode.byte_size == size
            ):
                stack_space = varnode.coordinate.space_id
    if stack_space is None:
        return True
    stack_bytes = {(stack_space, offset + index) for index in range(size)}
    tainted = set(stack_bytes)

    def touches(varnode) -> bool:
        return varnode is not None and any(
            (varnode.coordinate.space_id, varnode.coordinate.byte_offset + index) in tainted
            for index in range(varnode.byte_size)
        )

    changed = True
    while changed:
        changed = False
        for operation in operations.values():
            output = operation.output
            if (
                output is None
                or operation.opcode in _NON_VALUE_OPCODES
                or operation.opcode in _BOOLEAN_OPCODES
                or output.kind not in (VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE)
                or not any(touches(item) for item in operation.inputs)
            ):
                continue
            new = {
                (output.coordinate.space_id, output.coordinate.byte_offset + index)
                for index in range(output.byte_size)
            } - tainted
            if new:
                tainted |= new
                changed = True

    for operation in operations.values():
        if operation.opcode == "STORE" and len(operation.inputs) == 3 and touches(operation.inputs[2]):
            return True
        if operation.opcode == "CALLOTHER" and any(touches(item) for item in operation.inputs):
            return True
    # A copy in any other register (frame pointer, argument) is an escape.
    return any(
        space == stack_space and (space, byte) not in stack_bytes
        for space, byte in tainted
    )


__all__ = (
    "CALL_CLOBBER_CONTRACT_VERSION",
    "CallClobberRead",
    "derive_call_clobber_reads",
)
