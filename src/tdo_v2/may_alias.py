"""Demand-driven debt for memory reads that a write to another object may alias.

Relative-memory projection gives each distinct address base its own storage
object (``relative_memory``), and the SSA treats distinct objects as disjoint.
That is exact within one object but silently assumes that, e.g., ``*(RDI)``
and ``*(RSI)``, or ``*(RDI)`` and a global, never overlap.

A forward byte-level analysis tracks, per object byte, the writes to *other*
objects executed since the byte was last written. A read of a byte with such
writes gets a ``may_alias_read`` debt whose graph edges run from each
candidate writer to the debt and on to the read, so the written values stay
reachable as possible origins while the slice is marked incomplete.

No-alias is proved only from the function's own observation:

* two constant addresses in the same space are one object (exact already);
* bytes of the function's own frame strictly below its entry stack pointer
  cannot be reached through any other base while no stack-derived value
  escapes. The stack pointer is the register restored by the observed
  ``r' = *(r); r = r + size; RETURN r'`` shape (or the observed call shape).
  A stack-derived value escapes when it is stored to memory, passed to
  CALLOTHER, or copied to another register in a function that makes calls.

Accesses whose address could not be projected at all are modelled as an
unknown object: an unknown-address write may overwrite every byte of every
object (private frame bytes included, since a non-affine address may still
be derived from the stack pointer), and an unknown-address read may observe
any memory write executed before it. Both stay unresolved debt as well.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._scope_contracts import (
    AddressSpaceEvidence,
    ValidatedFunctionObservation,
    VarnodeKindCode,
)
from .call_seeds import _operation_key
from .effects import ObservedEffectUnit
from .model import (
    ResolvedStorage,
    StorageObjectId,
    StorageObjectKind,
    StorageRef,
    StorageResolutionContext,
    VarnodeKind,
)
from ._sparse_dataflow import run_dataflow
from .observed_call_state import observed_call_state_projections
from .relative_memory import _function_relative_object_id
from .span_geometry import ByteSpan
from .storage import _resolve_validated_storage

MAY_ALIAS_CONTRACT_VERSION = 1

_MEMORY_KINDS = frozenset({StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE})
_BOOLEAN_OPCODES = frozenset({
    "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL",
    "INT_SLESSEQUAL", "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
    "BOOL_NEGATE", "BOOL_XOR", "BOOL_AND", "BOOL_OR",
    "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL", "FLOAT_NAN",
})
_NON_VALUE_OPCODES = frozenset({
    "LOAD", "STORE", "BRANCH", "CBRANCH", "BRANCHIND", "RETURN", "CALL", "CALLIND",
})


@dataclass(frozen=True, slots=True)
class MayAliasRead:
    """One read whose bytes another object's write may have overwritten."""

    operation_key: str
    spans: tuple[ByteSpan, ...]
    writers: tuple[str, ...]
    unknown_address: bool = False  # the read's own address is unknown; spans empty

    def __post_init__(self) -> None:
        if type(self.operation_key) is not str or not self.operation_key:
            raise TypeError("may-alias read requires an exact operation key")
        if (
            type(self.spans) is not tuple
            or bool(self.spans) == self.unknown_address
            or any(type(span) is not ByteSpan for span in self.spans)
        ):
            raise TypeError("may-alias read requires exact byte spans unless its address is unknown")
        if (
            type(self.writers) is not tuple
            or not self.writers
            or tuple(sorted(set(self.writers))) != self.writers
        ):
            raise TypeError("may-alias writers must be a sorted, distinct tuple")


@dataclass(frozen=True, slots=True)
class _ObjectState:
    default: frozenset[str]
    bytes: dict[int, frozenset[str]]

    def at(self, offset: int) -> frozenset[str]:
        return self.bytes.get(offset, self.default)


_EMPTY_OBJECT = _ObjectState(frozenset(), {})


class _Policy:
    def __init__(self, stack_object: StorageObjectId | None, bias: int, escapes: bool) -> None:
        self.stack_object = stack_object
        self.bias = bias
        self.private = stack_object is not None and not escapes
        self.unknown_writers: frozenset[str] = frozenset()

    def is_private(self, object_id: StorageObjectId, offset: int) -> bool:
        """A byte of this function's own frame no other base can reach."""
        return self.private and object_id == self.stack_object and offset < self.bias

    def may_alias(self, left: StorageObjectId, right: StorageObjectId) -> bool:
        if left == right:
            return False  # one object: the SSA is byte-exact
        if left.kind is StorageObjectKind.ADDRESS_SPACE and right.kind is StorageObjectKind.ADDRESS_SPACE:
            return False  # different spaces
        return True


def derive_may_alias_reads(
    unit: ObservedEffectUnit,
    observation: ValidatedFunctionObservation,
    context: StorageResolutionContext,
    address_spaces: tuple[AddressSpaceEvidence, ...],
    *,
    assumed_calls: frozenset[str] = frozenset(),
) -> tuple[MayAliasRead, ...]:
    """Return memory reads that a write through another base may have overwritten.

    ``assumed_calls`` (TEST-ONLY) are boundary calls declared to touch only
    their listed registers; they cannot observe a stack pointer copy.
    """
    if type(unit) is not ObservedEffectUnit:
        raise TypeError("may-alias analysis requires an exact effect unit")
    if type(observation) is not ValidatedFunctionObservation:
        raise TypeError("may-alias analysis requires an exact observation")
    if type(context) is not StorageResolutionContext:
        raise TypeError("may-alias analysis requires an exact storage context")

    objects = sorted(
        {
            evidence.span.object_id
            for block in unit.blocks
            for effect in block.effects
            for evidence in (*effect.reads, *effect.writes)
            if type(evidence) is ResolvedStorage
            and evidence.span.object_id.kind in _MEMORY_KINDS
        },
        key=lambda item: (item.kind.value, item.scope.digest, item.space_key),
    )
    unknown_writers = frozenset(
        effect.operation_key
        for block in unit.blocks
        for effect in block.effects
        if _unknown_write(effect)
    )
    has_unknown_read = any(_unknown_read(effect) for block in unit.blocks for effect in block.effects)
    if len(objects) < 2 and not unknown_writers and not has_unknown_read:
        return ()
    policy = _stack_policy(unit, observation, context, address_spaces, assumed_calls)
    policy.unknown_writers = unknown_writers
    return run_dataflow(
        "may-alias", {"dense": _dense_rows, "sparse": _sparse_rows}, DEFAULT_ENGINE,
        unit, objects, policy,
    )


DEFAULT_ENGINE = "sparse"  # verified identical to "dense" (docs section 14)


def _sparse_rows(unit, objects, policy) -> tuple[MayAliasRead, ...]:
    from ._may_alias_sparse import derive_sparse

    return derive_sparse(unit, objects, policy)


def _dense_rows(unit, objects, policy) -> tuple[MayAliasRead, ...]:
    """Reference engine: the whole per-byte state through every block."""
    blocks = {block.key: block for block in unit.blocks}
    successors: dict[str, list[str]] = {key: [] for key in blocks}
    for block in unit.blocks:
        for predecessor in block.predecessors:
            successors[predecessor].append(block.key)
    start = {item: _EMPTY_OBJECT for item in objects}
    start[_ANY_WRITE] = frozenset()  # every memory write executed so far
    in_states: dict[str, dict] = {unit.entry_block_key: start}
    pending = {unit.entry_block_key}
    while pending:
        key = min(pending)
        pending.remove(key)
        state = _transfer(blocks[key], in_states[key], objects, policy, None)
        for successor in successors[key]:
            previous = in_states.get(successor)
            merged = state if previous is None else _meet(previous, state)
            if merged != previous:
                in_states[successor] = merged
                pending.add(successor)

    rows: list[MayAliasRead] = []
    for key in sorted(in_states):
        _transfer(blocks[key], in_states[key], objects, policy, rows)
    return tuple(sorted(rows, key=lambda row: row.operation_key))


def _meet(left: dict, right: dict) -> dict:
    merged = {_ANY_WRITE: left[_ANY_WRITE] | right[_ANY_WRITE]}
    for item, a in left.items():
        if item is _ANY_WRITE:
            continue
        b = right[item]
        default = a.default | b.default
        offsets = a.bytes.keys() | b.bytes.keys()
        values = {offset: a.at(offset) | b.at(offset) for offset in offsets}
        merged[item] = _ObjectState(
            default, {offset: value for offset, value in values.items() if value != default}
        )
    return merged


def _transfer(block, state: dict, objects, policy: _Policy, rows) -> dict:
    for effect in block.effects:
        if rows is not None:
            spans, writers = [], set()
            for evidence in effect.reads:
                if type(evidence) is not ResolvedStorage or evidence.span.object_id not in state:
                    continue
                span = evidence.span
                dirty = []
                for offset in range(span.start, span.end):
                    found = state[span.object_id].at(offset)
                    if policy.is_private(span.object_id, offset):
                        found = found & policy.unknown_writers
                    if found:
                        dirty.append(offset)
                        writers |= found
                if dirty:
                    spans.append(ByteSpan(span.object_id, dirty[0], dirty[-1] + 1 - dirty[0]))
            if spans:
                rows.append(MayAliasRead(effect.operation_key, tuple(spans), tuple(sorted(writers))))
            elif _unknown_read(effect) and state[_ANY_WRITE]:
                rows.append(MayAliasRead(
                    effect.operation_key, (), tuple(sorted(state[_ANY_WRITE])), unknown_address=True
                ))
        for evidence in effect.writes:
            if type(evidence) is not ResolvedStorage or evidence.span.object_id not in state:
                continue
            state = _written(state, evidence.span, effect.operation_key, objects, policy)
            state[_ANY_WRITE] = state[_ANY_WRITE] | {effect.operation_key}
        if _unknown_write(effect):
            state = _written_anywhere(state, effect.operation_key, objects)
    return state


_ANY_WRITE = object()


def _unknown_read(effect) -> bool:
    return effect.memory_read is not None or bool(effect.unresolved_reads)


def _unknown_write(effect) -> bool:
    return effect.memory_write is not None or bool(effect.unresolved_writes)


def _written_anywhere(state: dict, writer: str, objects) -> dict:
    """An unknown-address write: every byte of every object may now hold it."""
    updated = dict(state)
    for item in objects:
        current = updated[item]
        updated[item] = _ObjectState(
            current.default | {writer},
            {offset: writers | {writer} for offset, writers in current.bytes.items()},
        )
    updated[_ANY_WRITE] = updated[_ANY_WRITE] | {writer}
    return updated


def _written(state: dict, span: ByteSpan, writer: str, objects, policy: _Policy) -> dict:
    updated = dict(state)
    own = state[span.object_id]
    cleared = dict(own.bytes)
    for offset in range(span.start, span.end):
        if own.default:
            cleared[offset] = frozenset()
        else:
            cleared.pop(offset, None)
    updated[span.object_id] = _ObjectState(own.default, cleared)
    if all(policy.is_private(span.object_id, offset) for offset in range(span.start, span.end)):
        return updated  # a private frame write cannot reach any other object
    for other in objects:
        if not policy.may_alias(other, span.object_id):
            continue
        current = updated[other]
        updated[other] = _ObjectState(
            current.default | {writer},
            {offset: calls | {writer} for offset, calls in current.bytes.items()},
        )
    return updated


# -- stack identity and escape ---------------------------------------------------

def _stack_policy(unit, observation, context, address_spaces, assumed_calls=frozenset()) -> _Policy:
    registers = set()
    space_ids = set()
    for row in observed_call_state_projections(observation):
        base = row.memory_transition.caller_base
        registers.add((base.byte_offset, base.byte_size))
    for instruction in observation.instructions:
        shape = _return_shape(instruction)
        if shape is not None:
            registers.add(shape[0])
            space_ids.add(shape[1])
    for instruction in observation.instructions:
        for operation in instruction.operations:
            if operation.opcode in ("LOAD", "STORE") and operation.inputs:
                selector = operation.inputs[0]
                if selector.kind is VarnodeKindCode.CONSTANT:
                    space_ids.add(selector.coordinate.byte_offset)
    register_space = _register_space_id(observation)
    spaces = {row.space_id: row for row in address_spaces}
    if len(registers) != 1 or register_space is None or len(space_ids) != 1:
        return _Policy(None, 0, True)
    ((offset, size),) = registers
    (space_id,) = space_ids
    space = spaces.get(space_id)
    resolved = _resolve_validated_storage(
        StorageRef(VarnodeKind.REGISTER, "", offset, size, space_id=register_space), context
    )
    if space is None or type(resolved) is not ResolvedStorage:
        return _Policy(None, 0, True)
    stack_object = _function_relative_object_id(unit.function_scope, resolved.span, space_id)
    return _Policy(
        stack_object,
        1 << space.address_size_bits,
        _stack_escapes(observation, register_space, offset, size, assumed_calls, unit.entry_block_key),
    )


def _return_shape(instruction):
    """``r' = *(r); r = r + size; RETURN r'`` -> ((r offset, r size), space id)."""
    operations = instruction.operations
    if len(operations) != 3 or not instruction.flow.is_terminal:
        return None
    load, restore, ret = operations
    if (
        load.opcode != "LOAD" or restore.opcode != "INT_ADD" or ret.opcode != "RETURN"
        or load.output is None or len(load.inputs) != 2 or len(restore.inputs) != 2
        or load.inputs[0].kind is not VarnodeKindCode.CONSTANT
        or load.inputs[1].kind is not VarnodeKindCode.REGISTER
        or restore.output != load.inputs[1] or restore.inputs[0] != load.inputs[1]
        or restore.inputs[1].kind is not VarnodeKindCode.CONSTANT
        or restore.inputs[1].coordinate.byte_offset != load.output.byte_size
        or ret.inputs != (load.output,)
    ):
        return None
    pointer = load.inputs[1]
    return (
        (pointer.coordinate.byte_offset, pointer.byte_size),
        load.inputs[0].coordinate.byte_offset,
    )


def _register_space_id(observation) -> int | None:
    spaces = {
        varnode.coordinate.space_id
        for instruction in observation.instructions
        for operation in instruction.operations
        for varnode in (*operation.inputs, operation.output)
        if varnode is not None and varnode.kind is VarnodeKindCode.REGISTER
    }
    return spaces.pop() if len(spaces) == 1 else None


def _stack_escapes(observation, register_space: int, offset: int, size: int,
                   assumed_calls=frozenset(), entry_key: str | None = None) -> bool:
    """Flow-sensitive: can a stack-derived value reach another base?

    Forward over the p-code block graph (``pcode_blocks``), tracking which register and
    temporary bytes hold a stack-derived value at each point. It escapes when
    such a value is stored to memory, passed to CALLOTHER, or held in a
    register other than the stack pointer at a call that is not a declared
    (TEST-ONLY assumed) boundary call. ``push rbp`` before ``mov rbp, rsp``
    therefore stores the caller's RBP, not a stack address.
    """
    from .pcode_blocks import build_pcode_block_graph, instruction_key

    instructions = {row.address: row for row in observation.instructions}
    if not instructions:
        return True
    stack_bytes = frozenset((register_space, offset + index) for index in range(size))
    entry = next(
        (address for address in instructions if instruction_key(address) == entry_key),
        min(instructions),
    )
    graph = build_pcode_block_graph(observation, entry)
    if graph.unsupported is not None:
        return True
    blocks = {block.key: block for block in graph.blocks}

    def bytes_of(varnode):
        return {
            (varnode.coordinate.space_id, varnode.coordinate.byte_offset + index)
            for index in range(varnode.byte_size)
        }

    def transfer(block, state, check):
        row = instructions[block.instruction]
        tainted = set(state)
        for ordinal in range(block.start, block.stop):
            operation = row.operations[ordinal]
            touches = lambda varnode: varnode is not None and bool(bytes_of(varnode) & tainted)
            key = _operation_key(row.address, ordinal, operation.opcode)
            if check:
                if operation.opcode == "STORE" and len(operation.inputs) == 3 and touches(operation.inputs[2]):
                    return None
                if operation.opcode == "CALLOTHER" and any(touches(item) for item in operation.inputs):
                    return None
                if (
                    operation.opcode in ("CALL", "CALLIND")
                    and key not in assumed_calls
                    and any(item[0] == register_space for item in tainted - stack_bytes)
                ):
                    return None  # every register is visible to a callee
            output = operation.output
            if output is None or output.kind not in (VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE):
                continue
            produced = (
                operation.opcode not in _NON_VALUE_OPCODES
                and operation.opcode not in _BOOLEAN_OPCODES
                and any(touches(item) for item in operation.inputs)
            )
            written = bytes_of(output)
            tainted -= written
            if produced:
                tainted |= written
        return frozenset(tainted)

    order = {block.key: index for index, block in enumerate(graph.blocks)}
    in_states = {graph.entry: stack_bytes}
    pending = {graph.entry}
    while pending:
        key = min(pending, key=order.__getitem__)
        pending.remove(key)
        out = transfer(blocks[key], in_states[key], False)
        for target in blocks[key].successors:
            if target not in blocks:
                continue
            merged = out | in_states.get(target, frozenset())
            if merged != in_states.get(target):
                in_states[target] = merged
                pending.add(target)
    return any(
        transfer(blocks[key], state, True) is None
        for key, state in in_states.items()
    )


__all__ = ("MAY_ALIAS_CONTRACT_VERSION", "MayAliasRead", "derive_may_alias_reads")
