"""Demand-driven debt for storage that an unknown call may have overwritten.

The local normalizer has no evidence about what an opaque CALL, CALLIND, or
CALLOTHER writes, so pre-call definitions would otherwise flow through the
call as if the callee preserved every register and every byte of memory.

A forward byte-level analysis tracks, per program point and byte, the set of
calls executed since the byte was last written on some path. A read of a byte
with a non-empty set gets a ``call_clobber_read`` debt that names those
intervening calls. Pre-call definitions stay reachable, so the slice still
reports them, but it is no longer complete. Discharging the debt needs
evidence about the named callees and belongs to the interprocedural layer.

The only local exemption is the stack-pointer register of a call whose
instruction has the observed ``r = r - size; STORE r <- return address; CALL``
shape (``observed_call_state``). Memory gets no local exemption: a callee can
reach the caller's whole frame through its own stack pointer without any
pointer escaping, so frame preservation needs callee-side evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._scope_contracts import ValidatedFunctionObservation, VarnodeKindCode
from .call_seeds import _operation_key
from .effects import EffectKind, ObservedEffectUnit
from .model import (
    ResolvedStorage,
    StorageObjectId,
    StorageRef,
    StorageResolutionContext,
    VarnodeKind,
)
from .observed_call_state import observed_call_state_projections
from .span_geometry import ByteSpan
from .storage import _resolve_validated_storage

CALL_CLOBBER_CONTRACT_VERSION = 2

_CALL_OPCODES = frozenset({"CALL", "CALLIND", "CALLOTHER"})


@dataclass(frozen=True, slots=True)
class CallClobberRead:
    """One read whose bytes may come from before the named calls."""

    operation_key: str
    spans: tuple[ByteSpan, ...]
    intervening_calls: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.operation_key) is not str or not self.operation_key:
            raise TypeError("call-clobber read requires an exact operation key")
        if (
            type(self.spans) is not tuple
            or not self.spans
            or any(type(span) is not ByteSpan for span in self.spans)
        ):
            raise TypeError("call-clobber read requires exact byte spans")
        if (
            type(self.intervening_calls) is not tuple
            or not self.intervening_calls
            or any(type(key) is not str or not key for key in self.intervening_calls)
            or tuple(sorted(set(self.intervening_calls))) != self.intervening_calls
        ):
            raise TypeError("intervening calls must be a sorted, distinct tuple of keys")


_Byte = tuple[StorageObjectId, int]


@dataclass(frozen=True, slots=True)
class _State:
    """Calls crossed since the last write, per byte; ``default`` for untracked bytes."""

    default: frozenset[str]
    bytes: dict[_Byte, frozenset[str]]

    def calls_at(self, item: _Byte) -> frozenset[str]:
        return self.bytes.get(item, self.default)

    def meet(self, other: "_State") -> "_State":
        default = self.default | other.default
        merged = {}
        for item in self.bytes.keys() | other.bytes.keys():
            calls = self.calls_at(item) | other.calls_at(item)
            if calls != default:
                merged[item] = calls
        return _State(default, merged)

    def called(self, key: str, preserved: tuple[ByteSpan, ...]) -> "_State":
        default = self.default | {key}
        crossed = {item: calls | {key} for item, calls in self.bytes.items()}
        state = _State(default, {item: calls for item, calls in crossed.items() if calls != default})
        for span in preserved:
            state = state._restore(span, self)
        return state

    def written(self, span: ByteSpan) -> "_State":
        updated = dict(self.bytes)
        for offset in range(span.start, span.end):
            if self.default:
                updated[(span.object_id, offset)] = frozenset()
            else:
                updated.pop((span.object_id, offset), None)
        return _State(self.default, updated)

    def _restore(self, span: ByteSpan, before: "_State") -> "_State":
        """The call is evidenced to leave ``span`` exactly as it was."""
        updated = dict(self.bytes)
        for offset in range(span.start, span.end):
            item = (span.object_id, offset)
            calls = before.calls_at(item)
            if calls == self.default:
                updated.pop(item, None)
            else:
                updated[item] = calls
        return _State(self.default, updated)


_EMPTY = _State(frozenset(), {})


def derive_call_clobber_reads(
    unit: ObservedEffectUnit,
    observation: ValidatedFunctionObservation,
    context: StorageResolutionContext,
    *,
    assumed_calls: frozenset[str] = frozenset(),
) -> tuple[CallClobberRead, ...]:
    """Return reads that may observe storage written by an unevidenced call.

    ``assumed_calls`` (TEST-ONLY) are boundary calls with a declared effect:
    their declared writes are ordinary writes and they clobber nothing else.
    """
    if type(unit) is not ObservedEffectUnit:
        raise TypeError("call-clobber analysis requires an exact effect unit")
    if type(observation) is not ValidatedFunctionObservation:
        raise TypeError("call-clobber analysis requires an exact observation")
    if type(context) is not StorageResolutionContext:
        raise TypeError("call-clobber analysis requires an exact storage context")

    opcodes = {
        _operation_key(instruction.address, ordinal, operation.opcode): operation.opcode
        for instruction in observation.instructions
        for ordinal, operation in enumerate(instruction.operations)
    }
    calls = {
        key for key, opcode in opcodes.items() if opcode in _CALL_OPCODES
    } - set(assumed_calls)
    if not calls:
        return ()
    preserved = _preserved_stack_pointers(observation, context)

    blocks = {block.key: block for block in unit.blocks}
    successors: dict[str, list[str]] = {key: [] for key in blocks}
    for block in unit.blocks:
        for predecessor in block.predecessors:
            successors[predecessor].append(block.key)

    in_states: dict[str, _State] = {unit.entry_block_key: _EMPTY}
    pending = {unit.entry_block_key}
    while pending:
        key = min(pending)
        pending.remove(key)
        state = _transfer(blocks[key], in_states[key], calls, preserved, None)
        for successor in successors[key]:
            previous = in_states.get(successor)
            merged = state if previous is None else previous.meet(state)
            if merged != previous:
                in_states[successor] = merged
                pending.add(successor)

    rows: list[CallClobberRead] = []
    for key in sorted(in_states):
        _transfer(blocks[key], in_states[key], calls, preserved, rows)
    return tuple(sorted(rows, key=lambda row: row.operation_key))


def _transfer(block, state: _State, calls, preserved, rows) -> _State:
    for effect in block.effects:
        if rows is not None:
            spans = []
            crossed: set[str] = set()
            for evidence in effect.reads:
                if type(evidence) is not ResolvedStorage:
                    continue
                span = evidence.span
                dirty = []
                for offset in range(span.start, span.end):
                    found = state.calls_at((span.object_id, offset))
                    if found:
                        dirty.append(offset)
                        crossed |= found
                if dirty:
                    spans.append(ByteSpan(span.object_id, dirty[0], dirty[-1] + 1 - dirty[0]))
            if spans:
                rows.append(CallClobberRead(
                    effect.operation_key, tuple(spans), tuple(sorted(crossed))
                ))
        key = effect.operation_key
        if key in calls:
            state = state.called(key, preserved.get(key, ()))
        for evidence in effect.writes:
            if type(evidence) is ResolvedStorage:
                state = state.written(evidence.span)
    return state


def _preserved_stack_pointers(observation, context) -> dict[str, tuple[ByteSpan, ...]]:
    """Per call, the stack-pointer register its observed call/ret shape restores."""
    preserved = {}
    for row in observed_call_state_projections(observation):
        base = row.memory_transition.caller_base
        space_id = _register_space_id(observation)
        if space_id is None:
            continue
        resolved = _resolve_validated_storage(
            StorageRef(
                VarnodeKind.REGISTER, "", base.byte_offset, base.byte_size,
                space_id=space_id,
            ),
            context,
        )
        if type(resolved) is ResolvedStorage:
            preserved[row.call_operation_key] = (resolved.span,)
    return preserved


def _register_space_id(observation) -> int | None:
    spaces = {
        varnode.coordinate.space_id
        for instruction in observation.instructions
        for operation in instruction.operations
        for varnode in (*operation.inputs, operation.output)
        if varnode is not None and varnode.kind is VarnodeKindCode.REGISTER
    }
    return spaces.pop() if len(spaces) == 1 else None


__all__ = (
    "CALL_CLOBBER_CONTRACT_VERSION",
    "CallClobberRead",
    "derive_call_clobber_reads",
)
