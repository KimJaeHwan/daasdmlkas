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
  cannot be reached through any other base before a stack-derived value
  escapes. The stack pointer is the register restored by the observed
  ``r' = *(r); r = r + size; RETURN r'`` shape (or the observed call shape).
  A stack-derived value escapes when it is stored to memory, passed to
  CALLOTHER, or held in another register at a call. Escape is per program
  point: a read is private while no path from the entry to it passes an
  escape, a frame write while no path from it reaches one (afterwards
  another base may read the bytes it wrote).

Named assumption ``assume_globals_disjoint_from_stack`` (off here, on by
default in the summary engine; reported by callers): constant addresses never fall in the stack -- the function's own
frame or its callers' frames (the stack object anchored at the entry stack
pointer). True for ordinary programs, whose stacks are mapped outside the
image; false for stacks placed in static data (fibers on a static buffer,
firmware). ``stack_switches`` detects functions that load the stack pointer
from something other than the stack itself, so callers can withdraw it.

Accesses whose address could not be projected at all are modelled as an
unknown object: an unknown-address write may overwrite every byte of every
object (private frame bytes included, since a non-affine address may still
be derived from the stack pointer), and an unknown-address read may observe
any memory write executed before it. Both stay unresolved debt as well.

``fresh_objects`` (based on one block a modeled allocator returned, the
model's assumption): disjoint from constant addresses, the stack and other
fresh blocks (no use after free). Any other base may point into it -- even
an entry register value, which an opaque call may have replaced.
``nonstack_objects`` (a callee's summary states the base never addresses the
stack, ``relative_memory`` pointer rows): disjoint from the stack only.

``wild_objects`` (``relative_memory`` definition atoms: a call's result, a
loaded pointer) are exact objects whose base may still point anywhere, the
private frame included: their writes reach private frame bytes, and private
frame writes reach them, like unknown-address accesses.
"""

from __future__ import annotations

from .phases import count as phase_count, enabled as phases_enabled, measured

from .resource_limits import step

from bisect import bisect_left
from contextvars import ContextVar
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
    # writers that reached the read as uncertain-address writers
    # (``uncertain_writers`` of ``derive_may_alias_reads``) and those that
    # reached it as ordinary writes (None: all -- rows built elsewhere)
    uncertain: tuple[str, ...] = ()
    plain: tuple[str, ...] | None = None

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


@dataclass(frozen=True, slots=True)
class _Escape:
    """Per operation key: ``escaped`` -- some path from the entry to the
    operation passes an escape (the operation itself included); ``reaches`` --
    some path from the operation reaches an escape (itself included). Keys the
    observation does not know count as both."""

    known: frozenset[str]
    escaped: frozenset[str]
    reaches: frozenset[str]

    @staticmethod
    def _base(key: str) -> str:
        return key.split("~", 1)[0]  # a summarized call effect runs at its call

    def private_read(self, key: str) -> bool:
        base = self._base(key)
        return base in self.known and base not in self.escaped

    def private_write(self, key: str) -> bool:
        base = self._base(key)
        return base in self.known and base not in self.reaches


# Named assumption entry-values-do-not-address-the-new-frame (``assumptions``):
# set per run by ``interprocedural.analyze_units``; unset = on (direct callers,
# tests). Off: no byte is private.
ENTRY_VALUES_NOT_FRAME: ContextVar = ContextVar("ENTRY_VALUES_NOT_FRAME", default=True)
# Named assumption opaque-callees-leave-no-stack-addresses (docs 25.29): set per
# run by ``interprocedural.analyze_units``; unset = on. Off: every opaque call
# (no proven effect, not a TEST-ONLY assumed boundary) is a stack escape.
OPAQUE_NO_STACK_ADDRESSES: ContextVar = ContextVar("OPAQUE_NO_STACK_ADDRESSES", default=True)


class _Policy:
    def __init__(self, stack_object: StorageObjectId | None, bias: int,
                 escape: _Escape | None = None, globals_disjoint: bool = False,
                 private_above: int = 0, escape_without_opaque: _Escape | None = None) -> None:
        self.stack_object = stack_object
        self.bias = bias
        # named assumption win64-home-space-callee-private: the return slot and
        # home space above the entry stack pointer are this function's own
        self.private_above = private_above
        self.escape = escape if stack_object is not None else None
        self.globals_disjoint = globals_disjoint and stack_object is not None
        # writers a private frame read still sees: unknown-address writes and
        # writes to wild objects
        self.unknown_writers: frozenset[str] = frozenset()
        self.uncertain_writers: frozenset[str] = frozenset()
        self.no_kill_writers: frozenset[str] = frozenset()
        self.wild_objects: frozenset = frozenset()
        self.fresh_objects: frozenset = frozenset()
        self.nonstack_objects: frozenset = frozenset()
        # the private-frame rule decided some byte private (the assumption
        # entry-values-do-not-address-the-new-frame was used)
        self.private_used = False
        # opaque-callees-leave-no-stack-addresses: the escapes were the opaque
        # calls escapes too (``escape_without_opaque``); a byte decided private
        # only because they are not used the assumption (``opaque_used``)
        self.escape_without_opaque = escape_without_opaque if stack_object is not None else None
        self.opaque_used = False
        # accessor-result-separate (docs 25.20 D): (result object, start, end,
        # slot span, the slot's call) -- ``excluded``; ``ran(call, writer)``:
        # the call has run whenever the writer does
        self.separations: tuple = ()
        self.ran = None

    def excluded(self, span: ByteSpan, other: StorageObjectId, writer: str) -> frozenset:
        """Bytes of ``other`` a write of ``span`` by ``writer`` cannot reach
        under accessor-result-separate: the slot bytes, for a write lying
        wholly inside a result's [start, end); the result's [start, end), for
        a write lying wholly inside a slot. A write extending beyond either is
        not separated; nor is any write the slot's call may not have run
        before (the contract covers the calls the activation runs: a slot of
        a call on another path names no handle)."""
        found = set()
        for result, start, end, slot, call in self.separations:
            if self.ran is None or not self.ran(call, writer):
                continue
            if span.object_id == result and other == slot.object_id and start <= span.start and span.end <= end:
                found.update(range(slot.start, slot.end))
            if span.object_id == slot.object_id and other == result and slot.contains(span):
                found.update(range(start, end))
        return frozenset(found)

    def is_private(self, object_id: StorageObjectId, offset: int, key: str, *, write: bool = False) -> bool:
        """A byte of this function's own frame no other base can reach at
        ``key`` (a read), or at any point after ``key`` (a write) -- the
        named assumption entry-values-do-not-address-the-new-frame."""
        if self.escape is None or object_id != self.stack_object or offset >= self.bias + self.private_above:
            return False
        private = self.escape.private_write(key) if write else self.escape.private_read(key)
        if private:
            self.private_used = True
            other = self.escape_without_opaque
            if other is not None and not (other.private_write(key) if write else other.private_read(key)):
                self.opaque_used = True
        return private

    def may_alias(self, left: StorageObjectId, right: StorageObjectId) -> bool:
        if left == right:
            return False  # one object: the SSA is byte-exact
        for fresh, other in ((left, right), (right, left)):
            if fresh in self.fresh_objects and (
                other.kind is StorageObjectKind.ADDRESS_SPACE or other == self.stack_object
                or other in self.fresh_objects
            ):
                return False  # ASSUMPTION (the allocator model): a new block
        for nonstack, other in ((left, right), (right, left)):
            if nonstack in self.nonstack_objects and other == self.stack_object:
                return False  # the callee summary: never a stack address
        if left.kind is StorageObjectKind.ADDRESS_SPACE and right.kind is StorageObjectKind.ADDRESS_SPACE:
            return False  # different spaces
        if self.globals_disjoint and (
            (left.kind is StorageObjectKind.ADDRESS_SPACE and right == self.stack_object)
            or (right.kind is StorageObjectKind.ADDRESS_SPACE and left == self.stack_object)
        ):
            return False  # ASSUMPTION: a constant address is never a stack address
        return True


@measured("may_alias")
def derive_may_alias_reads(
    unit: ObservedEffectUnit,
    observation: ValidatedFunctionObservation,
    context: StorageResolutionContext,
    address_spaces: tuple[AddressSpaceEvidence, ...],
    *,
    assumed_calls: frozenset[str] = frozenset(),
    assume_globals_disjoint_from_stack: bool = False,
    wild_objects: frozenset = frozenset(),
    observed_calls: dict | None = None,
    fresh_objects: frozenset = frozenset(),
    nonstack_objects: frozenset = frozenset(),
    private_above: int = 0,
    uncertain_writers: frozenset = frozenset(),
    no_kill_writers: frozenset = frozenset(),
    uses: list | None = None,
    separations: tuple = (),
    escaping_calls: frozenset = frozenset(),
    opaque_calls: frozenset = frozenset(),
    opaque_uses: list | None = None,
    escape_memo: "EscapeMemo | None" = None,
) -> tuple[MayAliasRead, ...]:
    """Return memory reads that a write through another base may have overwritten.

    ``assumed_calls`` (TEST-ONLY) are boundary calls declared to touch only
    their listed registers; they cannot observe a stack pointer copy.
    ``assume_globals_disjoint_from_stack``: the opt-in assumption above.
    ``uncertain_writers``: write keys whose resolved address rests on a read
    with debt (``function_summary.uncertain_writers_of``): besides their
    ordinary effect they may have written any byte of any object, private
    frame bytes included -- every read they may reach gets them as
    ``MayAliasRead.uncertain`` (later exact writes kill that only where they
    definitely overwrite the bytes). ``no_kill_writers`` (the unconditional
    ones): their own write is no definite overwrite of its static bytes either
    -- earlier writers stay possible there. ``separations``: the
    accessor-result-separate pairs (``relative_memory.accessor_separations``);
    with any, the dense engine (it keeps per-byte states). ``escaping_calls``:
    calls that are stack escapes whatever registers are tainted
    (``ProvenCallEffect.escapes_stack``), assumed or quiet ones included.
    ``opaque_calls``: calls with no proven effect (not TEST-ONLY assumed):
    escapes too when opaque-callees-leave-no-stack-addresses is off; when on,
    ``opaque_uses`` records whether a byte was decided private only because
    they are not.
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
    uncertain = frozenset(
        effect.operation_key for block in unit.blocks for effect in block.effects
        if effect.operation_key in uncertain_writers
    )
    if len(objects) < 2 and not unknown_writers and not has_unknown_read and not uncertain:
        return ()
    policy = _stack_policy(unit, observation, context, address_spaces, assumed_calls,
                           assume_globals_disjoint_from_stack, observed_calls, private_above, escaping_calls,
                           opaque_calls, escape_memo)
    wild = frozenset(item for item in objects if item in wild_objects)
    policy.wild_objects = wild
    policy.fresh_objects = frozenset(item for item in objects if item in fresh_objects)
    policy.nonstack_objects = frozenset(item for item in objects if item in nonstack_objects)
    policy.uncertain_writers = uncertain
    policy.no_kill_writers = frozenset(no_kill_writers) & uncertain
    policy.unknown_writers = unknown_writers | frozenset(
        effect.operation_key
        for block in unit.blocks
        for effect in block.effects
        for evidence in effect.writes
        if type(evidence) is ResolvedStorage and evidence.span.object_id in wild
    ) | frozenset(_UNCERTAIN + key for key in uncertain)
    policy.separations = tuple(separations)
    if policy.separations:
        policy.ran = _ran_before(unit)
        rows = _dense_rows(unit, objects, policy)   # the sparse engine gens whole objects
    else:
        rows = run_dataflow(
            "may-alias", {"dense": _dense_rows, "sparse": _sparse_rows}, DEFAULT_ENGINE,
            unit, objects, policy,
        )
    if phases_enabled():   # (K2 sizes: rows x writers, docs 25.31)
        phase_count("ma_rows", len(rows))
        phase_count("ma_row_writers", sum(len(row.writers) for row in rows))
        phase_count("ma_row_uncertain", sum(len(row.uncertain) for row in rows))
    if uses is not None:   # ``uses``: whether the private-frame rule decided a byte
        uses.append(policy.private_used)
    if opaque_uses is not None:
        opaque_uses.append(policy.opaque_used)
    return rows


def _ran_before(unit):
    """``ran(call, writer)``: every path to effect ``writer`` runs the call
    operation ``call`` first -- the writer is one of the call's own rows, or
    the call's block dominates the writer's (earlier in one block)."""
    from ._sparse_dataflow import DominatorGraph

    graph = DominatorGraph(unit.entry_block_key, {block.key: block.predecessors for block in unit.blocks})
    position = {}
    for block in unit.blocks:
        for index, effect in enumerate(block.effects):
            position.setdefault(effect.operation_key, (block.key, index))

    def ran(call: str, writer: str) -> bool:
        if writer.split("~", 1)[0] == call:
            return True
        here, there = position.get(writer), position.get(call)
        if here is None or there is None or here[0] not in graph.reachable or there[0] not in graph.reachable:
            return False
        if here[0] == there[0]:
            return there[1] < here[1]
        return graph._dominates(there[0], here[0])

    return ran


def private_frame_writes(
    unit, observation, context, address_spaces, *, assumed_calls=frozenset(),
    observed_calls=None, private_above=0, uses: list | None = None, escaping_calls=frozenset(),
    opaque_calls=frozenset(), opaque_uses: list | None = None, escape_memo: "EscapeMemo | None" = None,
) -> frozenset:
    """(write operation key, object) pairs whose written bytes are all private
    frame bytes at the write (``_Policy.is_private``): such a write reaches
    no other object but a wild one -- for function summaries, which use the
    same rule (``function_summary._exit_crossings``)."""
    policy = _stack_policy(unit, observation, context, address_spaces, assumed_calls, False, observed_calls,
                           private_above, escaping_calls, opaque_calls, escape_memo)
    found = set()
    for block in unit.blocks:
        for effect in block.effects:
            for evidence in effect.writes:
                if type(evidence) is not ResolvedStorage or evidence.span.object_id.kind not in _MEMORY_KINDS:
                    continue
                span = evidence.span
                if all(policy.is_private(span.object_id, offset, effect.operation_key, write=True)
                       for offset in range(span.start, span.end)):
                    found.add((effect.operation_key, span.object_id))
    if uses is not None:
        uses.append(policy.private_used)
    if opaque_uses is not None:
        opaque_uses.append(policy.opaque_used)
    return frozenset(found)


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
        step()   # (budget: docs 25.30 K1c)
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
                    if policy.is_private(span.object_id, offset, effect.operation_key):
                        found = found & policy.unknown_writers
                    if found:
                        dirty.append(offset)
                        writers |= found
                if dirty:
                    spans.append(ByteSpan(span.object_id, dirty[0], dirty[-1] + 1 - dirty[0]))
            if spans:
                rows.append(_row(effect.operation_key, tuple(spans), writers))
            elif _unknown_read(effect) and state[_ANY_WRITE]:
                rows.append(_row(effect.operation_key, (), state[_ANY_WRITE]))
        for evidence in effect.writes:
            if type(evidence) is not ResolvedStorage or evidence.span.object_id not in state:
                continue
            state = _written(state, evidence.span, effect.operation_key, objects, policy)
            state[_ANY_WRITE] = state[_ANY_WRITE] | {effect.operation_key}
        if _unknown_write(effect):
            state = _written_anywhere(state, effect.operation_key, objects)
        if effect.operation_key in policy.uncertain_writers:
            state = _written_anywhere(state, _UNCERTAIN + effect.operation_key, objects)
    return state


# label prefix of an uncertain-address writer's "may have written anywhere" gen
_UNCERTAIN = "?"


def _row(operation_key: str, spans: tuple, labels) -> MayAliasRead:
    """The row of a read reached by ``labels`` (writer keys; ``_UNCERTAIN``
    marks the gen of an uncertain-address writer)."""
    plain = {label for label in labels if not label.startswith(_UNCERTAIN)}
    uncertain = {label[len(_UNCERTAIN):] for label in labels if label.startswith(_UNCERTAIN)}
    return MayAliasRead(
        operation_key, spans, tuple(sorted(plain | uncertain)), unknown_address=not spans,
        uncertain=tuple(sorted(uncertain)), plain=tuple(sorted(plain)),
    )


_ANY_WRITE = object()


def _unknown_read(effect) -> bool:
    return effect.memory_read is not None or bool(effect.unresolved_reads)


def _unknown_write(effect) -> bool:
    return effect.memory_write is not None or bool(effect.unresolved_writes)


def _written_anywhere(state: dict, writer: str, objects) -> dict:
    """An unknown-address write: every byte of every object may now hold it."""
    updated = dict(state)
    if phases_enabled():
        phase_count("ma_written_anywhere_bytes", sum(len(state[item].bytes) for item in objects))
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
    if writer not in policy.no_kill_writers:
        own = state[span.object_id]
        cleared = dict(own.bytes)
        for offset in range(span.start, span.end):
            if own.default:
                cleared[offset] = frozenset()
            else:
                cleared.pop(offset, None)
        updated[span.object_id] = _ObjectState(own.default, cleared)
    private = all(policy.is_private(span.object_id, offset, writer, write=True)
                  for offset in range(span.start, span.end))
    for other in objects:
        # a private frame write reaches no other object but a wild one
        if not policy.may_alias(other, span.object_id) or (private and other not in policy.wild_objects):
            continue
        current = updated[other]
        excluded = policy.excluded(span, other, writer) if policy.separations else frozenset()
        values = {offset: calls | {writer} for offset, calls in current.bytes.items() if offset not in excluded}
        values.update({offset: current.at(offset) for offset in excluded})   # (kept as they were)
        updated[other] = _ObjectState(current.default | {writer}, values)
    return updated


# -- stack identity and escape ---------------------------------------------------

class EscapeMemo:
    """The stack escapes of one normalization (docs 25.31 B0-4): they depend
    neither on the uncertain writers its fixed point grows nor on the policy
    flags, so every round shares one computation. Held for one (effect unit,
    observation, context, address spaces) by identity -- other inputs are
    computed uncached; a hit replays the computation's work units one by one
    (the same units, quantum boundaries and exhaustion point)."""

    def __init__(self, unit, observation, context, address_spaces) -> None:
        self.held = (unit, observation, context, address_spaces)
        self.found: dict = {}

    def holds(self, unit, observation, context, address_spaces) -> bool:
        return all(left is right for left, right in zip(self.held, (unit, observation, context, address_spaces)))


def _stack_policy(unit, observation, context, address_spaces, assumed_calls=frozenset(),
                  globals_disjoint=False, observed_calls=None, private_above=0,
                  escaping_calls=frozenset(), opaque_calls=frozenset(), memo: EscapeMemo | None = None) -> _Policy:
    key = None
    if memo is not None and memo.holds(unit, observation, context, address_spaces):
        key = (frozenset(assumed_calls), None if observed_calls is None else frozenset(observed_calls.items()),
               frozenset(escaping_calls), frozenset(opaque_calls),
               ENTRY_VALUES_NOT_FRAME.get(), OPAQUE_NO_STACK_ADDRESSES.get())
        cached = memo.found.get(key)
        if cached is not None:
            found, escape, without, pops = cached
            for _ in range(pops):
                step()
            return _policy_of(found, escape, without, globals_disjoint, private_above)
    found, escape, without, pops = _stack_escapes(unit, observation, context, address_spaces, assumed_calls,
                                                  observed_calls, escaping_calls, opaque_calls)
    if key is not None:
        memo.found[key] = (found, escape, without, pops)
    return _policy_of(found, escape, without, globals_disjoint, private_above)


def _policy_of(found, escape, without, globals_disjoint, private_above) -> _Policy:
    if found is None:
        return _Policy(None, 0)
    stack_object, bias, _, _, _ = found
    return _Policy(stack_object, bias, escape, globals_disjoint, private_above, without)


def _stack_escapes(unit, observation, context, address_spaces, assumed_calls, observed_calls, escaping_calls,
                   opaque_calls) -> tuple:
    """(the stack pointer found, the escapes, the escapes without
    opaque-callees-leave-no-stack-addresses, the work units charged)."""
    found = _stack_pointer(unit, observation, context, address_spaces)
    if found is None:
        return None, None, None, 0
    _, _, register_space, offset, size = found
    if not ENTRY_VALUES_NOT_FRAME.get():
        # entry-values-do-not-address-the-new-frame off: no private bytes
        return found, None, None, 0
    opaque = frozenset(opaque_calls) - frozenset(escaping_calls)
    if not OPAQUE_NO_STACK_ADDRESSES.get():
        # opaque-callees-leave-no-stack-addresses off: each opaque call escapes
        escaping_calls, opaque = frozenset(escaping_calls) | opaque, frozenset()
    pops = [0]
    escape = _stack_escape(observation, register_space, offset, size, assumed_calls, unit.entry_block_key,
                           observed_calls, escaping_calls, pops=pops)
    # (with the assumption on: the escapes it removes, for per-use reporting)
    without = _stack_escape(observation, register_space, offset, size, assumed_calls, unit.entry_block_key,
                            observed_calls, frozenset(escaping_calls) | opaque, pops=pops) if opaque else None
    return found, escape, without, pops[0]


def _stack_pointer(unit, observation, context, address_spaces):
    """(stack object, bias, register space, register offset, size) or None."""
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
        return None
    ((offset, size),) = registers
    (space_id,) = space_ids
    space = spaces.get(space_id)
    resolved = _resolve_validated_storage(
        StorageRef(VarnodeKind.REGISTER, "", offset, size, space_id=register_space), context
    )
    if space is None or type(resolved) is not ResolvedStorage:
        return None
    stack_object = _function_relative_object_id(unit.function_scope, resolved.span, space_id)
    return stack_object, 1 << space.address_size_bits, register_space, offset, size


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


def _stack_taint(observation, register_space: int, offset: int, size: int,
                 assumed_calls=frozenset(), entry_key: str | None = None, observed_calls=None,
                 escaping_calls=frozenset(), returning: set | None = None, pops: list | None = None):
    """Forward over the p-code block graph (``pcode_blocks``), tracking which
    register and temporary bytes hold a stack-derived value at each point.

    Returns (operation keys per reached block, block successors, escape keys,
    switch keys), or None when the graph is unsupported. An operation escapes
    when it stores a stack-derived value to memory (a STORE, or any operation
    with a memory output), passes one to CALLOTHER, or
    is a call that is not a declared (TEST-ONLY assumed) boundary call while a
    register other than the stack pointer holds one (every register is
    visible to a callee; ``observed_calls``: call key -> the register byte
    offsets a call may use as an address or keep, when that is declared --
    then only those count), or is one of ``escaping_calls`` (a call that may
    leave a stack-derived value in an output, which this forward pass does not
    follow: an escape whatever is tainted). ``returning`` collects the
    RETURNs reached with a register other than the stack pointer holding a
    stack-derived value; ``pops`` ([0]) counts the worklist pops (one work
    unit each). ``push rbp`` before ``mov rbp, rsp`` therefore
    stores the caller's RBP, not a stack address. A switch writes the stack
    pointer with a value not derived from it (``mov rsp, [x]``).
    """
    from .pcode_blocks import build_pcode_block_graph, instruction_key

    instructions = {row.address: row for row in observation.instructions}
    if not instructions:
        return None
    stack_bytes = frozenset((register_space, offset + index) for index in range(size))
    entry = next(
        (address for address in instructions if instruction_key(address) == entry_key),
        min(instructions),
    )
    graph = build_pcode_block_graph(observation, entry)
    if graph.unsupported is not None:
        return None
    blocks = {block.key: block for block in graph.blocks}

    # the tainted bytes as one int per state over the (space, byte) pairs the
    # graph's varnodes touch (docs 25.31 B0-6; were frozensets of pairs, one
    # per block -- 277 MB at the 10k scale point): the same sets, so the same
    # fixed point, worklist pops and answers
    bit_of: dict = {}
    masks: dict = {}

    def mask_of(varnode) -> int:
        location = (varnode.coordinate.space_id, varnode.coordinate.byte_offset, varnode.byte_size)
        found = masks.get(location)
        if found is None:
            found = 0
            for index in range(varnode.byte_size):
                pair = (location[0], location[1] + index)
                bit = bit_of.get(pair)
                if bit is None:
                    bit = bit_of[pair] = len(bit_of)
                found |= 1 << bit
            masks[location] = found
        return found

    stack_mask = 0
    for pair in sorted(stack_bytes):
        bit_of[pair] = len(bit_of)
        stack_mask |= 1 << bit_of[pair]
    for block in graph.blocks:
        row = instructions[block.instruction]
        for ordinal in range(block.start, block.stop):
            operation = row.operations[ordinal]
            for varnode in (*operation.inputs, operation.output):
                if varnode is not None:
                    mask_of(varnode)
    register_mask = 0
    for (space, _), bit in bit_of.items():
        if space == register_space:
            register_mask |= 1 << bit
    observed_masks: dict = {}

    def observed_mask(key) -> int:
        """The register bytes a call may observe (all of them unless declared)."""
        found = observed_masks.get(key)
        if found is None:
            observed = (observed_calls or {}).get(key)
            if observed is None:
                found = register_mask
            else:
                found = 0
                for (space, byte), bit in bit_of.items():
                    if space == register_space and byte in observed:
                        found |= 1 << bit
            observed_masks[key] = found
        return found

    def transfer(block, state, escapes, switches):
        row = instructions[block.instruction]
        tainted = state
        for ordinal in range(block.start, block.stop):
            operation = row.operations[ordinal]
            touches = lambda varnode: varnode is not None and bool(mask_of(varnode) & tainted)
            key = _operation_key(row.address, ordinal, operation.opcode)
            if escapes is not None and (
                (operation.opcode == "STORE" and len(operation.inputs) == 3 and touches(operation.inputs[2]))
                or (operation.opcode == "CALLOTHER" and any(touches(item) for item in operation.inputs))
                or key in escaping_calls
                # a direct memory output (``COPY ram[x], rsp``) is a store too
                or (operation.output is not None
                    and operation.output.kind not in (VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE)
                    and any(touches(item) for item in operation.inputs))
                or (
                    operation.opcode in ("CALL", "CALLIND")
                    and key not in assumed_calls
                    and bool(tainted & ~stack_mask & observed_mask(key))
                )
            ):
                escapes.add(key)
            if returning is not None and escapes is not None and operation.opcode == "RETURN" \
                    and bool(tainted & ~stack_mask & register_mask):
                returning.add(key)
            output = operation.output
            if output is None or output.kind not in (VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE):
                continue
            produced = (
                operation.opcode not in _NON_VALUE_OPCODES
                and operation.opcode not in _BOOLEAN_OPCODES
                and any(touches(item) for item in operation.inputs)
            )
            written = mask_of(output)
            if switches is not None and written & stack_mask and not produced:
                switches.add(key)
            tainted &= ~written
            if produced:
                tainted |= written
        return tainted

    order = {block.key: index for index, block in enumerate(graph.blocks)}
    in_states = {graph.entry: stack_mask}
    pending = {graph.entry}
    while pending:
        step()   # (budget: docs 25.30 K1c)
        if pops is not None:
            pops[0] += 1   # (the units charged, replayed by an escape memo hit)
        key = min(pending, key=order.__getitem__)
        pending.remove(key)
        out = transfer(blocks[key], in_states[key], None, None)
        for target in blocks[key].successors:
            if target not in blocks:
                continue
            merged = out | in_states.get(target, 0)
            if merged != in_states.get(target):
                in_states[target] = merged
                pending.add(target)
    escapes: set[str] = set()
    switches: set[str] = set()
    for key, state in in_states.items():
        transfer(blocks[key], state, escapes, switches)
    keys = {}
    for block in graph.blocks:
        if block.key in in_states:
            row = instructions[block.instruction]
            keys[block.key] = [
                _operation_key(row.address, ordinal, row.operations[ordinal].opcode)
                for ordinal in range(block.start, block.stop)
            ]
    successors = {
        key: [target for target in blocks[key].successors if target in keys] for key in keys
    }
    return keys, successors, escapes, switches


def _flagged(keys, edges, escapes, reverse: bool) -> set[str]:
    """Operation keys an escape precedes (``reverse``: follows) on some path,
    the escape itself included: forward (backward) may-reachability."""
    entering: set[str] = set()   # blocks reached along ``edges`` from an escaping block
    work = [block for block, sequence in keys.items() if any(key in escapes for key in sequence)]
    leaving = set(work)
    while work:
        block = work.pop()
        for target in edges[block]:
            if target not in entering:
                entering.add(target)
                if target not in leaving:
                    leaving.add(target)
                    work.append(target)
    flagged: set[str] = set()
    for block, sequence in keys.items():
        seen = block in entering
        for key in (reversed(sequence) if reverse else sequence):
            seen = seen or key in escapes
            if seen:
                flagged.add(key)
    return flagged


def _stack_escape(observation, register_space: int, offset: int, size: int,
                  assumed_calls=frozenset(), entry_key: str | None = None, observed_calls=None,
                  escaping_calls=frozenset(), pops: list | None = None) -> _Escape:
    """Where a stack-derived value may have escaped (``_Escape``)."""
    taint = _stack_taint(observation, register_space, offset, size, assumed_calls, entry_key, observed_calls,
                         escaping_calls, pops=pops)
    if taint is None:
        return _Escape(frozenset(), frozenset(), frozenset())  # nothing private
    keys, successors, escapes, _ = taint
    predecessors: dict[str, list[str]] = {block: [] for block in keys}
    for block, targets in successors.items():
        for target in targets:
            predecessors[target].append(block)
    known = frozenset(key for sequence in keys.values() for key in sequence)
    return _Escape(
        known,
        frozenset(_flagged(keys, successors, escapes, reverse=False)),
        frozenset(_flagged(keys, predecessors, escapes, reverse=True)),
    )


def stack_values_out(normalized, observation) -> bool:
    """Whether a value derived from the function's entry stack pointer may
    leave it other than in the stack pointer (``_stack_taint`` over its own
    p-code): a register other than the stack pointer holding one at a RETURN,
    or an escape inside (a store or user op of one, a call while a register
    holds one). True when the stack pointer or the block graph is not
    identified. A value kept in memory is a store (an escape) whether or not
    it is read back."""
    scopes = normalized.scopes
    stub = _unit_stub(scopes)
    found = _stack_pointer(stub, observation, scopes.resolution_context, scopes.program.evidence.address_spaces)
    if found is None:
        return True
    _, _, register_space, offset, size = found
    returning: set = set()
    taint = _stack_taint(observation, register_space, offset, size, entry_key=stub.entry_block_key,
                         returning=returning)
    return taint is None or bool(taint[2]) or bool(returning)


def stack_object_of(scopes, observation) -> StorageObjectId | None:
    """The stack object (anchored at the entry stack pointer) of a scoped
    function, as the may-alias policy identifies it, or None."""
    found = _stack_pointer(
        _unit_stub(scopes), observation, scopes.resolution_context,
        scopes.program.evidence.address_spaces,
    )
    return None if found is None else found[0]


def _unit_stub(scopes):
    """What the stack-pointer identification reads of an effect unit."""
    from types import SimpleNamespace
    from .normalize import _coordinate_key

    return SimpleNamespace(
        function_scope=scopes.function.scope, entry_block_key=_coordinate_key(scopes.function.entry),
    )


@measured("stack_switch_check")
def stack_switches(unit, observation, context, address_spaces, program_stack=None,
                   call_preserved=()) -> tuple[str, ...]:
    """Operations that may set the stack pointer to something other than
    "the stack pointer + a number" (a stack switch: ``mov rsp, [x]``). The
    stack pointer is the function's own (call / return shapes) or, without
    those (a lone jump), ``program_stack``: (register offset, size) of the
    program's; with neither, a function touching registers is "unchecked".
    The check withdraws an assumption: it must not miss a switch (MUST
    analysis, ``_coefficient_switches``; ``call_preserved``: register
    (offset, size) a callee keeps, ``CALL_PRESERVED``)."""
    from .pcode_blocks import instruction_key

    if not any(instruction_key(row.address) == unit.entry_block_key for row in observation.instructions):
        # the entry is not observed (or nothing is): what runs first is unknown
        return ("unchecked",)
    found = _stack_pointer(unit, observation, context, address_spaces)
    register_space = _register_space_id(observation)
    touched = any(varnode is not None and varnode.kind is VarnodeKindCode.REGISTER
                  for instruction in observation.instructions for operation in instruction.operations
                  for varnode in (*operation.inputs, operation.output))
    if found is not None:
        _, _, register_space, offset, size = found
    elif program_stack is not None and register_space is not None:
        offset, size = program_stack
    else:
        return ("unchecked",) if touched else ()
    return _coefficient_switches(observation, register_space, offset, size, unit.entry_block_key,
                                 call_preserved)


# registers both x86-64 ABIs (Windows, System V) have a callee preserve; a
# call keeps what they hold (the stack pointer itself: the call shape)
# (x86-32: ebx, ebp, esi, edi -- every 32-bit x86 convention). Part of the
# reported assumption stack-switch-check-exceptions.
CALL_PRESERVED = {"x86:LE:64": ((0x18, 8), (0x28, 8), (0xA0, 8), (0xA8, 8), (0xB0, 8), (0xB8, 8)),
                  "x86:LE:32": ((0xC, 4), (0x14, 4), (0x18, 4), (0x1C, 4))}
# the largest alignment ``and rsp, -2**k`` keeps as "the stack pointer + a number"
MAX_STACK_ALIGNMENT = 1 << 12


def _coefficient_switches(observation, register_space: int, offset: int, size: int, entry_key,
                          call_preserved=()) -> tuple[str, ...]:
    """Forward MUST analysis over the p-code block graph of each register or
    temporary's STACK COEFFICIENT: 1 -- "the stack pointer + a number" on
    every path, 0 -- no stack pointer in it, None -- anything else (a join of
    both, a product, a part of the pointer). A write of the stack pointer with
    a coefficient other than 1 is a switch. Transfer: COPY keeps; INT_ADD /
    INT_SUB add and subtract (only 0 and 1 survive: rsp - rsp = 0); INT_AND
    of 1 with an alignment mask -2**k (k <= 12) keeps it (``and rsp,-16``),
    with any other mask gives None; LOAD gives 0 (a restore from memory is
    flagged; a loaded number used to adjust the stack pointer is taken as no
    stack pointer -- stack-switch-check-exceptions); every
    other operation is 0 from inputs all 0, else None; a CALL / CALLIND keeps
    only the stack pointer and the call-preserved registers (the rest hold what
    the callee left: 0 -- a call's result used to adjust the stack pointer is
    taken as no stack pointer); a CALLOTHER defines just its output, if any
    (both: stack-switch-check-exceptions). A location read whole as it was
    written gets its coefficient; one overlapping part of a non-zero entry is
    None. Instructions no path from the entry reaches are checked from the
    entry state (the stack pointer is the stack pointer everywhere). An entry
    missing from the observation is "unchecked"."""
    from .pcode_blocks import build_pcode_block_graph, instruction_key

    instructions = {row.address: row for row in observation.instructions}
    if not instructions:
        return ()
    stack = (register_space, offset, size)
    preserved = {(register_space, start, width) for start, width in call_preserved}
    entry = next((address for address in instructions if instruction_key(address) == entry_key), None)
    if entry is None:
        # the entry is not observed: what runs before the observed code is unknown
        return ("unchecked",)
    switches: set[str] = set()
    covered: set = set()
    for start in [entry] + sorted(instructions):
        if start in covered:
            continue
        graph = build_pcode_block_graph(observation, start)
        if graph.unsupported is not None:
            return ("unchecked",)
        covered.update(block.instruction for block in graph.blocks)
        switches |= _coefficient_pass(graph, instructions, stack, preserved)
    return tuple(sorted(switches))


def _coefficient_pass(graph, instructions, stack, preserved) -> set:
    blocks = {block.key: block for block in graph.blocks}

    def location(varnode):
        return (varnode.coordinate.space_id, varnode.coordinate.byte_offset, varnode.byte_size)

    def overlaps(a, b):
        return a[0] == b[0] and a[1] < b[1] + b[2] and b[1] < a[1] + a[2]

    # the overlap table, once per pass (docs 25.31 B0-3; was a scan of the
    # whole state per read and write): the keys a state can hold -- the stack
    # pointer and the REGISTER / UNIQUE outputs -- and, per location read or
    # written, those of them it overlaps
    held = {stack}
    used = {stack}
    for block in graph.blocks:
        row = instructions[block.instruction]
        for ordinal in range(block.start, block.stop):
            operation = row.operations[ordinal]
            output = operation.output
            if output is not None and output.kind in (VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE):
                held.add(location(output))
                used.add(location(output))
            used.update(location(item) for item in operation.inputs if item.kind is not VarnodeKindCode.CONSTANT)
    spaces: dict = {}
    for key in held:
        spaces.setdefault(key[0], []).append(key)
    for members in spaces.values():
        members.sort(key=lambda item: (item[1], item[2]))
    widest = {space: max(item[2] for item in members) for space, members in spaces.items()}
    starts = {space: [item[1] for item in members] for space, members in spaces.items()}
    over: dict = {}
    for key in used:
        members = spaces.get(key[0], ())
        if not members:
            over[key] = ()
            continue
        low = bisect_left(starts[key[0]], key[1] - widest[key[0]] + 1)
        high = bisect_left(starts[key[0]], key[1] + key[2])
        over[key] = tuple(other for other in members[low:high] if overlaps(key, other))

    def read(state, varnode):
        if varnode.kind is VarnodeKindCode.CONSTANT:
            return 0
        key = location(varnode)
        if key in state:
            return state[key]
        return None if any(state.get(other, 0) != 0 for other in over[key]) else 0

    def write(state, key, value):
        for other in [other for other in over[key] if other in state]:
            covered = key[1] <= other[1] and other[1] + other[2] <= key[1] + key[2]
            if covered:
                del state[other]
            else:
                # bytes of a non-zero entry survive the partial write: that
                # location no longer holds a whole coefficient (``mov al, 0``)
                state[other] = None
        if value != 0:
            state[key] = value
        elif key in state:
            del state[key]

    def coefficient(operation, state):
        opcode = operation.opcode
        values = [read(state, item) for item in operation.inputs]
        if opcode == "COPY" and values:
            return values[0]
        if opcode in ("INT_ADD", "INT_SUB") and len(values) == 2:
            if None in values:
                return None
            total = values[0] + values[1] if opcode == "INT_ADD" else values[0] - values[1]
            return total if total in (0, 1) else None
        if opcode == "INT_AND" and len(values) == 2:
            for index in (0, 1):
                mask = operation.inputs[1 - index]
                if mask.kind is VarnodeKindCode.CONSTANT and values[index] is not None:
                    if values[index] == 0:
                        return 0
                    low = (1 << (8 * mask.byte_size)) - mask.coordinate.byte_offset   # 2**k for -2**k
                    return 1 if 0 < low <= MAX_STACK_ALIGNMENT and low & (low - 1) == 0 else None
        if opcode == "LOAD" or opcode in _BOOLEAN_OPCODES:
            return 0
        return 0 if all(value == 0 for value in values) else None

    kept_keys: dict = {}

    def wholly_kept(key) -> bool:
        """Whether ``key`` lies wholly inside a call-preserved register."""
        found = kept_keys.get(key)
        if found is None:
            found = kept_keys[key] = any(key[1] >= kept[1] and key[1] + key[2] <= kept[1] + kept[2]
                                         for kept in preserved)
        return found

    def transfer(block, state, switches):
        row = instructions[block.instruction]
        state = dict(state)
        for ordinal in range(block.start, block.stop):
            operation = row.operations[ordinal]
            if operation.opcode in ("CALL", "CALLIND"):
                # a user op (CALLOTHER) defines just its output, if any
                for key in [key for key in state if key[0] == stack[0] and key != stack
                            and not wholly_kept(key)]:
                    del state[key]
            output = operation.output
            if output is None or output.kind not in (VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE):
                continue
            value = coefficient(operation, state)
            key = location(output)
            if overlaps(key, stack):
                if switches is not None and not (key == stack and value == 1):
                    switches.add(_operation_key(row.address, ordinal, operation.opcode))
                # the stack pointer stays the stack pointer after any write of it
                # (a switch is reported where it happens)
                write(state, key, 1)
                write(state, stack, 1)
                continue
            write(state, key, value)
        return state

    def merge(a, b):
        merged = {}
        for key in set(a) | set(b):
            left, right = a.get(key, 0), b.get(key, 0)
            value = left if left == right else None
            if value != 0:
                merged[key] = value
        return merged

    order = {block.key: index for index, block in enumerate(graph.blocks)}
    in_states = {graph.entry: {stack: 1}}
    pending = {graph.entry}
    while pending:
        step()   # (budget: docs 25.30 K1c)
        key = min(pending, key=order.__getitem__)
        pending.remove(key)
        out = transfer(blocks[key], in_states[key], None)
        for target in blocks[key].successors:
            if target not in blocks:
                continue
            merged = out if target not in in_states else merge(out, in_states[target])
            if merged != in_states.get(target):
                in_states[target] = merged
                pending.add(target)
    switches: set[str] = set()
    for key, state in in_states.items():
        transfer(blocks[key], state, switches)
    return switches


__all__ = ("MAY_ALIAS_CONTRACT_VERSION", "MayAliasRead", "derive_may_alias_reads", "stack_object_of",
           "stack_switches")
