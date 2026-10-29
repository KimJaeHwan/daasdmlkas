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

from contextvars import ContextVar

from .phases import count as phase_count, enabled as phases_enabled, measured

from .resource_limits import step

from dataclasses import dataclass

from ._scope_contracts import ValidatedFunctionObservation, VarnodeKindCode
from .call_seeds import _operation_key
from .effects import EffectKind, ObservedEffectUnit
from .model import (
    ResolvedStorage,
    StorageObjectKind,
    StorageObjectId,
    StorageRef,
    StorageResolutionContext,
    VarnodeKind,
)
from ._sparse_dataflow import run_dataflow
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


def rows_by_node(rows, nodes) -> dict:
    """Debt node -> EVERY row it stands for: a copy proof splits a reader's row
    per span / run of calls (``subtract_copy_clobbers``) and the parts keep the
    reader's one node, so a node is judged on all of them, never the last."""
    found: dict = {}
    for row, node in zip(rows, nodes, strict=True):
        found.setdefault(node, []).append(row)
    return {node: tuple(parts) for node, parts in found.items()}


def spans_by_node(rows, nodes) -> dict:
    """Debt node -> the spans its read may have lost to a call (all its rows')."""
    return {node: tuple(span for row in parts for span in row.spans)
            for node, parts in rows_by_node(rows, nodes).items()}


# call-clobber debt per (reader, call) (docs 25.83 S2d): ``debts[i]`` holds
# the pair nodes of ``rows[i]``, aligned with its ``intervening_calls``; a
# pair node stands for every row of its reader the call crosses

def rows_by_debt(rows, debts) -> dict:
    """Pair node -> the rows it stands for (a copy proof splits one reader's row)."""
    found: dict = {}
    for row, nodes in zip(rows, debts, strict=True):
        for node in dict.fromkeys(nodes):
            found.setdefault(node, []).append(row)
    return {node: tuple(parts) for node, parts in found.items()}


def spans_by_debt(rows, debts) -> dict:
    """Pair node -> the spans of its rows."""
    return {node: tuple(span for row in parts for span in row.spans)
            for node, parts in rows_by_debt(rows, debts).items()}


def debt_pairs(rows, debts) -> tuple:
    """(row, call, pair node) for every row and each of its calls."""
    return tuple((row, call, node) for row, nodes in zip(rows, debts, strict=True)
                 for call, node in zip(row.intervening_calls, nodes, strict=True))


def debt_calls(rows, debts) -> dict:
    """Pair node -> its call."""
    return {node: call for _, call, node in debt_pairs(rows, debts)}


def debt_nodes(debts) -> tuple:
    """Every pair node, once, in order."""
    return tuple(dict.fromkeys(node for nodes in debts for node in nodes))


def debt_identity(rows, debts) -> dict:
    """Pair node -> its reader's first pair node: the debt identity public
    completeness counts by (one per reader, as before the pairs)."""
    first: dict = {}
    found: dict = {}
    for row, nodes in zip(rows, debts, strict=True):
        for node in nodes:
            found[node] = first.setdefault(row.operation_key, node)
    return found


_Byte = tuple[StorageObjectId, int]


_MEMORY_KINDS = frozenset({StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE})


@dataclass(frozen=True, slots=True)
class _State:
    """Calls crossed since the last write, per byte; ``default`` for untracked
    bytes, ``memory_default`` (when set) for untracked memory bytes."""

    default: frozenset[str]
    bytes: dict[_Byte, frozenset[str]]
    memory_default: frozenset[str] | None = None

    def _default_for(self, item: _Byte) -> frozenset[str]:
        if self.memory_default is not None and item[0].kind in _MEMORY_KINDS:
            return self.memory_default
        return self.default

    def calls_at(self, item: _Byte) -> frozenset[str]:
        return self.bytes.get(item, self._default_for(item))

    def _compact(self, default, memory_default, values) -> "_State":
        if memory_default == default:
            memory_default = None
        state = _State(default, {}, memory_default)
        return _State(default, {
            item: calls for item, calls in values.items() if calls != state._default_for(item)
        }, memory_default)

    def meet(self, other: "_State") -> "_State":
        default = self.default | other.default
        memory_default = (self.memory_default if self.memory_default is not None else self.default) | (
            other.memory_default if other.memory_default is not None else other.default)
        merged = {
            item: self.calls_at(item) | other.calls_at(item)
            for item in self.bytes.keys() | other.bytes.keys()
        }
        return self._compact(default, memory_default, merged)

    def called(self, key: str, preserved: tuple[ByteSpan, ...], keeps_memory: bool = False) -> "_State":
        """``keeps_memory``: a summarized call proven to change no memory byte
        other than its (separately written) memory runs."""
        memory = self.memory_default if self.memory_default is not None else self.default
        default = self.default | {key}
        memory_default = memory if keeps_memory else memory | {key}
        crossed = {
            item: calls if keeps_memory and item[0].kind in _MEMORY_KINDS else calls | {key}
            for item, calls in self.bytes.items()
        }
        state = self._compact(default, memory_default, crossed)
        for span in preserved:
            state = state._restore(span, self)
        return state

    def written(self, span: ByteSpan) -> "_State":
        updated = dict(self.bytes)
        for offset in range(span.start, span.end):
            item = (span.object_id, offset)
            if self._default_for(item):
                updated[item] = frozenset()
            else:
                updated.pop(item, None)
        return _State(self.default, updated, self.memory_default)

    def _restore(self, span: ByteSpan, before: "_State") -> "_State":
        """The call is evidenced to leave ``span`` exactly as it was."""
        updated = dict(self.bytes)
        for offset in range(span.start, span.end):
            item = (span.object_id, offset)
            calls = before.calls_at(item)
            if calls == self._default_for(item):
                updated.pop(item, None)
            else:
                updated[item] = calls
        return _State(self.default, updated, self.memory_default)


_EMPTY = _State(frozenset(), {})


@measured("call_clobber")
def derive_call_clobber_reads(
    unit: ObservedEffectUnit,
    observation: ValidatedFunctionObservation,
    context: StorageResolutionContext,
    *,
    assumed_calls: frozenset[str] = frozenset(),
    proven_preserved: dict[str, tuple[ByteSpan, ...]] | None = None,
    memory_keeping: frozenset[str] = frozenset(),
    unrestored_stack_calls: frozenset[str] = frozenset(),
    calls: frozenset[str] | None = None,
) -> tuple[CallClobberRead, ...]:
    """Return reads that may observe storage written by an unevidenced call.

    ``assumed_calls`` (TEST-ONLY) are boundary calls with a declared effect:
    their declared writes are ordinary writes and they clobber nothing else.
    ``proven_preserved`` / ``memory_keeping``: register bytes, and for the listed
    calls all memory, that a callee summary proves the call leaves unchanged.
    ``unrestored_stack_calls``: summarized calls whose callee is not proven to
    restore the stack pointer -- the call shape's exemption does not apply.
    """
    if type(unit) is not ObservedEffectUnit:
        raise TypeError("call-clobber analysis requires an exact effect unit")
    if type(observation) is not ValidatedFunctionObservation:
        raise TypeError("call-clobber analysis requires an exact observation")
    if type(context) is not StorageResolutionContext:
        raise TypeError("call-clobber analysis requires an exact storage context")

    calls, preserved = clobber_inputs(observation, context, assumed_calls, proven_preserved,
                                      unrestored_stack_calls, calls)
    if not calls:
        return ()
    rows = run_dataflow(
        "call-clobber", {"dense": _dense_rows, "sparse": _sparse_rows}, DEFAULT_ENGINE,
        unit, calls, preserved, frozenset(memory_keeping) & calls,
    )
    if phases_enabled():   # (K2 sizes: reads x intervening calls, docs 25.31)
        phase_count("cc_calls", len(calls))
        phase_count("cc_rows", len(rows))
        phase_count("cc_intervening_calls", sum(len(row.intervening_calls) for row in rows))
    return rows


# Named assumption opaque-callees-restore-stack-pointer (``assumptions``): on, an
# unproven call with the observed call shape keeps its stack pointer; off, only
# a callee summary proving the restoration does (2b-P B6)
OPAQUE_RESTORES_SP: ContextVar[bool] = ContextVar("opaque_restores_sp", default=True)


def clobber_inputs(observation, context, assumed_calls=frozenset(), proven_preserved=None,
                   unrestored_stack_calls=frozenset(), calls=None, uses: list | None = None) -> tuple:
    """(the clobbering call keys, call key -> the spans it leaves unchanged):
    the inputs of ``derive_call_clobber_reads`` -- shared with the shadow chi
    check (``_chi_shadow``) so both see one exemption contract. ``calls``:
    ``CallExemptions.calls`` (else every call operation not assumed)."""
    if calls is None:
        opcodes = {
            _operation_key(instruction.address, ordinal, operation.opcode): operation.opcode
            for instruction in observation.instructions
            for ordinal, operation in enumerate(instruction.operations)
        }
        calls = {
            key for key, opcode in opcodes.items() if opcode in _CALL_OPCODES
        } - set(assumed_calls)
    preserved = _preserved_stack_pointers(observation, context)
    for key in unrestored_stack_calls:
        preserved.pop(key, None)
    for key in [key for key in preserved if key not in (proven_preserved or {})]:
        # an unproven callee: its stack pointer is kept only under the assumption
        if not OPAQUE_RESTORES_SP.get():
            preserved.pop(key)
        elif uses is not None:
            uses.append(key)
    for key, spans in (proven_preserved or {}).items():
        # bytes a callee summary proves unchanged (or rewrites just before the call)
        preserved[key] = tuple(preserved.get(key, ())) + tuple(spans)
    return frozenset(calls), preserved


@dataclass(frozen=True, slots=True)
class CallExemptions:
    """The raw call exemption contract of one normalization (docs 25.83 S2c),
    read by its three views -- normalize (call_clobber / the chi records), a
    forward probe, ``function_summary._exit_crossings`` -- each keeping its own
    below-bound semantics:

    ``calls``: call-operation keys with an effect in the unit, not assumed
    (crossings happen only at effects); ``proven``: call -> the bytes a
    callee summary proves unchanged plus a model's kept memory runs;
    ``unrestored``: calls whose shape's stack pointer is not restored;
    ``memory_keeping``: preserves memory and clobbers nothing below;
    ``below``: call -> (stack object, bound) of a below-bound call;
    ``below_keeping``: preserves memory, clobbers below, has a bound (the
    exits' extra memory keepers, subtracted below the bound there)."""

    calls: frozenset
    proven: dict
    unrestored: frozenset
    memory_keeping: frozenset
    below: dict
    below_keeping: frozenset

    def clobber_preserved(self, unit) -> dict:
        """normalize's / a probe's view: ``proven`` plus, for a below-bound
        call, every tracked memory byte of ``unit`` except its stack below
        the bound (a union: ``_memory_spans_except_below``)."""
        from .normalize import _memory_spans_except_below

        preserved = {key: tuple(spans) for key, spans in self.proven.items()}
        for key, (object_id, bound) in self.below.items():
            preserved[key] = preserved.get(key, ()) + tuple(_memory_spans_except_below(unit, object_id, bound))
        return preserved


def call_exemptions(effect_keys, assumed_calls, proven_call_effects, kept=None, below_bounds=(),
                    *, intrinsic_calls=frozenset()) -> CallExemptions:
    """``CallExemptions`` from the parts every view already holds:
    ``proven_call_effects`` call -> its proven effect row, ``kept`` call -> a
    model's kept memory spans, ``below_bounds`` (call, object, bound) rows."""
    kept = kept or {}
    rows = dict(proven_call_effects)
    below = {key: (object_id, bound) for key, object_id, bound in below_bounds}
    return CallExemptions(
        # Qualified output-only ISA intrinsics retain their original explicit
        # reads/writes, but are not opaque calls. This same exclusion must be
        # used by normalization, forward probes, chi and summary crossings.
        calls=frozenset(key for key in effect_keys if key.rsplit(":", 1)[-1] in _CALL_OPCODES)
              - set(assumed_calls) - set(intrinsic_calls),
        proven={key: tuple(row.preserved) + tuple(kept.get(key, ())) for key, row in rows.items()},
        unrestored=frozenset(key for key, row in rows.items() if not row.restores_stack),
        memory_keeping=frozenset(key for key, row in rows.items() if row.preserves_memory and not row.clobbers_below),
        below=below,
        below_keeping=frozenset(key for key, row in rows.items()
                                if row.preserves_memory and row.clobbers_below and key in below),
    )


DEFAULT_ENGINE = "sparse"  # verified identical to "dense" (docs section 14)


def _sparse_rows(unit, calls, preserved, memory_keeping=frozenset()) -> tuple[CallClobberRead, ...]:
    from ._call_clobber_sparse import derive_sparse

    return derive_sparse(unit, calls, preserved, memory_keeping)


def _dense_rows(unit, calls, preserved, memory_keeping=frozenset()) -> tuple[CallClobberRead, ...]:
    """Reference engine: the whole per-byte state through every block."""
    blocks = {block.key: block for block in unit.blocks}
    successors: dict[str, list[str]] = {key: [] for key in blocks}
    for block in unit.blocks:
        for predecessor in block.predecessors:
            successors[predecessor].append(block.key)

    in_states: dict[str, _State] = {unit.entry_block_key: _EMPTY}
    pending = {unit.entry_block_key}
    while pending:
        step()   # (budget: docs 25.30 K1c)
        key = min(pending)
        pending.remove(key)
        state = _transfer(blocks[key], in_states[key], calls, preserved, None, memory_keeping)
        for successor in successors[key]:
            previous = in_states.get(successor)
            merged = state if previous is None else previous.meet(state)
            if merged != previous:
                in_states[successor] = merged
                pending.add(successor)

    rows: list[CallClobberRead] = []
    for key in sorted(in_states):
        _transfer(blocks[key], in_states[key], calls, preserved, rows, memory_keeping)
    return tuple(sorted(rows, key=lambda row: row.operation_key))


def _transfer(block, state: _State, calls, preserved, rows, memory_keeping=frozenset()) -> _State:
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
            state = state.called(key, preserved.get(key, ()), key in memory_keeping)
        for evidence in effect.writes:
            if type(evidence) is ResolvedStorage:
                state = state.written(evidence.span)
    return state


def _preserved_stack_pointers(observation, context) -> dict[str, tuple[ByteSpan, ...]]:
    """Per call, the stack-pointer register its observed call/ret shape restores."""
    preserved = {}
    space_id = _register_space_id(observation)  # one scan of the function, not one per call
    if space_id is None:
        return preserved
    for row in observed_call_state_projections(observation):
        base = row.memory_transition.caller_base
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
