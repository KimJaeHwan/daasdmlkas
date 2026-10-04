"""Unwired observed frame inventory for temporary configured compatibility.

Intervals are symbolic ENTRY-relative offsets, not disjointness, non-escape,
normal-return, or transport certificates. No configured event is removed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..call_seeds import _operation_key
from ..memory_contracts import MemoryDefinitionKind
from ..model import ByteSpan, ResolvedStorage
from ..observed_call_state import observed_call_state_projections
from ..scope_identity import AddressCoordinate, VarnodeKindCode
from ..storage import _resolve_validated_storage
from .configured_function_view import _FunctionView
from .configured_interprocedural_contracts import ConfiguredFunctionAnalysis
from .configured_value_domain import storage_ref


class FrameInventoryDebtReason(StrEnum):
    UNRESOLVED_ACCESS = "unresolved_access"
    CALL_TRANSITION_UNAVAILABLE = "call_transition_unavailable"
    RETURN_TRANSITION_UNAVAILABLE = "return_transition_unavailable"
    BUDGET_EXHAUSTED = "budget_exhausted"


@dataclass(frozen=True, slots=True)
class FrameInventoryDebt:
    reason: FrameInventoryDebtReason
    operation_key: str


@dataclass(frozen=True, slots=True)
class EntryRelativeInterval:
    anchor_definition_id: int
    anchor_span: ByteSpan
    address_space_id: int
    offset: int
    byte_size: int

    @property
    def stop(self) -> int:
        return self.offset + self.byte_size


@dataclass(frozen=True, slots=True)
class FrameMemoryAccess:
    operation_key: str
    opcode: str
    interval: EntryRelativeInterval | None


@dataclass(frozen=True, slots=True)
class CallTokenObservation:
    call_operation_key: str
    adjust_operation_key: str
    store_operation_key: str
    interval: EntryRelativeInterval
    before_offset: int
    continuation: AddressCoordinate


@dataclass(frozen=True, slots=True)
class ReturnTokenObservation:
    return_operation_key: str
    load_operation_key: str
    restore_operation_key: str
    interval: EntryRelativeInterval
    after_offset: int


@dataclass(frozen=True, slots=True)
class RecursiveFrameInventory:
    function_scope_digest: bytes
    observation_digest: bytes
    memory_unit_digest: bytes
    accesses: tuple[FrameMemoryAccess, ...]
    call_tokens: tuple[CallTokenObservation, ...]
    return_tokens: tuple[ReturnTokenObservation, ...]
    debts: tuple[FrameInventoryDebt, ...]

    @property
    def complete(self) -> bool:
        """Only inventory coverage; never a frame-privacy or transport proof."""
        return not self.debts

    def require_complete(self) -> None:
        if self.debts:
            raise RecursiveFrameInventoryIncomplete(self)


class RecursiveFrameInventoryIncomplete(RuntimeError):
    def __init__(self, inventory: RecursiveFrameInventory) -> None:
        self.inventory = inventory
        super().__init__("observed recursive-frame inventory is incomplete")


class _Unresolved(Exception):
    pass


class _Budget(Exception):
    pass


class _AffineResolver:
    """Exact full-width COPY/literal-affine SSA chains; every join must agree."""

    def __init__(self, view, max_steps):
        self.view = view
        self.remaining = max_steps
        self.cache = {}
        self.active = set()

    def input(self, key, varnode, *, before=False):
        storage = _resolve_validated_storage(
            storage_ref(varnode), self.view.analysis.evidence.unit.scopes.resolution_context
        )
        if type(storage) is not ResolvedStorage:
            raise _Unresolved
        resolved = self.view.definition_for_input(key, varnode)
        if resolved is None and before:
            # Transient call operations have no retained SSA read. Require one
            # exact state with no competing/partial may-write; never just pick
            # the last textual definition or use a register-role table.
            block = self.view.operation_blocks.get(key)
            if block is None:
                raise _Unresolved
            pending = list(self.view._successors.get(block, ()))
            visited = set()
            while pending:
                candidate = pending.pop()
                if candidate == block:
                    # Textual order cannot recover state across a back-edge.
                    raise _Unresolved
                if candidate not in visited:
                    visited.add(candidate)
                    pending.extend(self.view._successors.get(candidate, ()))
            writes = []
            for ordinal, definition in enumerate(self.view.memory.definitions):
                self.remaining -= 1
                if self.remaining < 0:
                    raise _Budget
                if definition.kind is MemoryDefinitionKind.ENTRY:
                    continue
                if definition.operation_key is None:
                    continue
                if definition.span.overlaps(storage.span) and self.view.may_precede(
                    definition.operation_key, key
                ):
                    writes.append((ordinal, definition))
            latest = [
                (ordinal, definition)
                for ordinal, definition in writes
                if self.view.definitely_precedes(definition.operation_key, key)
                and definition.span.contains(storage.span)
                and all(
                    other_id == ordinal
                    or self.view.definitely_precedes(other.operation_key, definition.operation_key)
                    for other_id, other in writes
                )
            ]
            if len(latest) == 1:
                resolved = (latest[0][0], storage.span)
            elif not writes:
                entries = [
                    ordinal for ordinal, definition in enumerate(self.view.memory.definitions)
                    if definition.kind is MemoryDefinitionKind.ENTRY
                    and definition.span.contains(storage.span)
                ]
                if len(entries) == 1:
                    resolved = (entries[0], storage.span)
        if resolved is None:
            raise _Unresolved
        return self.definition(*resolved)

    def definition(self, ordinal, span):
        key = (ordinal, span)
        if key in self.cache:
            return self.cache[key]
        if key in self.active:
            raise _Unresolved
        self.remaining -= 1
        if self.remaining < 0:
            raise _Budget
        self.active.add(key)
        try:
            definition = self.view.memory.definitions[ordinal]
            if not definition.span.contains(span):
                raise _Unresolved
            if definition.kind is MemoryDefinitionKind.ENTRY:
                result = (ordinal, span, 0)
            elif definition.kind is MemoryDefinitionKind.JOIN:
                sources = self.view._join_sources.get(ordinal, ())
                if not sources:
                    raise _Unresolved
                values = {self.definition(source, span) for source in sources}
                if len(values) != 1:
                    raise _Unresolved
                result = values.pop()
            elif definition.kind is MemoryDefinitionKind.DATA_WRITE:
                operation = self.view.operation(definition.operation_key)
                if operation is None or operation.output is None:
                    raise _Unresolved
                output = _resolve_validated_storage(
                    storage_ref(operation.output),
                    self.view.analysis.evidence.unit.scopes.resolution_context,
                )
                if type(output) is not ResolvedStorage or output.span != span:
                    raise _Unresolved
                inputs = operation.inputs
                if operation.opcode in {"COPY", "CAST"} and len(inputs) == 1:
                    if inputs[0].byte_size != span.size:
                        raise _Unresolved
                    result = self.input(definition.operation_key, inputs[0])
                elif operation.opcode in {"INT_ADD", "INT_SUB"} and len(inputs) == 2:
                    pointer, literal = inputs
                    if operation.opcode == "INT_ADD" and pointer.kind is VarnodeKindCode.CONSTANT:
                        pointer, literal = literal, pointer
                    if (
                        literal.kind is not VarnodeKindCode.CONSTANT
                        or literal.byte_size != span.size or pointer.byte_size != span.size
                    ):
                        raise _Unresolved
                    delta = literal.coordinate.byte_offset
                    modulus = 1 << (span.size * 8)
                    if not 0 <= delta < modulus:
                        raise _Unresolved
                    if delta >= modulus // 2:
                        delta -= modulus
                    anchor, anchor_span, offset = self.input(definition.operation_key, pointer)
                    result = (anchor, anchor_span, offset + (delta if operation.opcode == "INT_ADD" else -delta))
                else:
                    raise _Unresolved
            else:
                raise _Unresolved
            self.cache[key] = result
            return result
        finally:
            self.active.remove(key)


def build_recursive_frame_inventory(
    analysis: ConfiguredFunctionAnalysis, /, *, max_steps: int = 16384
) -> RecursiveFrameInventory:
    """Inventory raw accesses, including call transients absent from local SSA.

    Offsets describe literal affine expressions only. They do not prove that
    concrete machine addresses avoid modular wrap or belong to private frames.
    """
    if type(analysis) is not ConfiguredFunctionAnalysis:
        raise TypeError("frame inventory requires an exact configured analysis")
    if type(max_steps) is not int or max_steps < 1:
        raise ValueError("frame inventory budget must be a positive exact integer")
    if (
        analysis.normalized.scopes is not analysis.evidence.unit.scopes
        or not analysis.normalized.dependencies.is_frozen
    ):
        raise ValueError("frame inventory evidence and normalization must match")
    view = _FunctionView(analysis)
    resolver = _AffineResolver(view, max_steps)
    projections = {row.call_operation_key: row for row in observed_call_state_projections(view.observation)}
    accesses, calls, returns, debts = [], [], [], []

    def debt(reason, key):
        debts.append(FrameInventoryDebt(reason, key))

    def interval(key, operation, *, before=False, delta=0):
        if len(operation.inputs) != (2 if operation.opcode == "LOAD" else 3):
            raise _Unresolved
        selector, pointer = operation.inputs[:2]
        if selector.kind is not VarnodeKindCode.CONSTANT:
            raise _Unresolved
        width = operation.output.byte_size if operation.opcode == "LOAD" and operation.output is not None else operation.inputs[2].byte_size if operation.opcode == "STORE" else None
        if width is None:
            raise _Unresolved
        anchor, span, offset = resolver.input(key, pointer, before=before)
        return EntryRelativeInterval(anchor, span, selector.coordinate.byte_offset, offset + delta, width)

    def disjoint_storage(left, right):
        context = analysis.evidence.unit.scopes.resolution_context
        left = _resolve_validated_storage(storage_ref(left), context)
        right = _resolve_validated_storage(storage_ref(right), context)
        return type(left) is ResolvedStorage and type(right) is ResolvedStorage and not left.span.overlaps(right.span)

    for instruction in view.observation.instructions:
        keyed = tuple((_operation_key(instruction.address, ordinal, operation.opcode), operation)
                      for ordinal, operation in enumerate(instruction.operations))
        transient = {}
        for key, operation in keyed:
            if operation.opcode not in {"CALL", "CALLIND"}:
                continue
            projection = projections.get(key)
            try:
                if projection is None or len(keyed) != 3:
                    raise _Unresolved
                (adjust_key, adjust), (store_key, store), (call_key, _) = keyed
                if (adjust_key, store_key) != projection.transient_operation_keys or call_key != key:
                    raise _Unresolved
                # The structural projector's candidates must also be an
                # uninterrupted three-operation sequence in this first slice.
                access = interval(call_key, store, before=True,
                                  delta=projection.memory_transition.displacement_delta)
                transient[store_key] = access
                calls.append(CallTokenObservation(key, adjust_key, store_key, access,
                             access.offset - projection.memory_transition.displacement_delta,
                             instruction.fallthrough))
            except (_Unresolved, _Budget, RecursionError) as error:
                debt(FrameInventoryDebtReason.BUDGET_EXHAUSTED if isinstance(error, (_Budget, RecursionError))
                     else FrameInventoryDebtReason.CALL_TRANSITION_UNAVAILABLE, key)
        local_accesses = {}
        for key, operation in keyed:
            if operation.opcode not in {"LOAD", "STORE"}:
                continue
            try:
                access = transient[key] if key in transient else interval(key, operation)
            except (_Unresolved, _Budget, RecursionError) as error:
                access = None
                debt(FrameInventoryDebtReason.BUDGET_EXHAUSTED if isinstance(error, (_Budget, RecursionError))
                     else FrameInventoryDebtReason.UNRESOLVED_ACCESS, key)
            accesses.append(FrameMemoryAccess(key, operation.opcode, access))
            local_accesses[key] = access
        for key, operation in keyed:
            if operation.opcode != "RETURN":
                continue
            if len(keyed) == 3:
                (load_key, load), (restore_key, restore), (_, ret) = keyed
                access = local_accesses.get(load_key)
                if (
                    access is not None and load.opcode == "LOAD" and load.output is not None
                    and restore.opcode == "INT_ADD" and len(restore.inputs) == 2
                    and restore.output == load.inputs[1] == restore.inputs[0]
                    and restore.inputs[1].kind is VarnodeKindCode.CONSTANT
                    and restore.inputs[1].coordinate.byte_offset == load.output.byte_size
                    and restore.inputs[1].byte_size == load.inputs[1].byte_size == load.output.byte_size
                    and ret.inputs == (load.output,)
                    and disjoint_storage(load.output, load.inputs[1])
                    and instruction.flow.is_terminal and instruction.fallthrough is None
                ):
                    returns.append(ReturnTokenObservation(key, load_key, restore_key, access,
                                                          access.stop))
                    continue
            debt(FrameInventoryDebtReason.RETURN_TRANSITION_UNAVAILABLE, key)
    return RecursiveFrameInventory(
        view.scope_digest, analysis.evidence.unit.scopes.function.observation_digest,
        view.memory.unit_digest, tuple(accesses), tuple(calls), tuple(returns),
        tuple(sorted(set(debts), key=lambda row: (row.operation_key, row.reason.value))),
    )


__all__ = (
    "FrameInventoryDebtReason", "FrameInventoryDebt", "EntryRelativeInterval",
    "FrameMemoryAccess", "CallTokenObservation", "ReturnTokenObservation",
    "RecursiveFrameInventory", "RecursiveFrameInventoryIncomplete",
    "build_recursive_frame_inventory",
)
