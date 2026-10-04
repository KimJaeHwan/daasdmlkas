"""Unwired local read coverage for temporary configured compatibility.

This checks ordinary negative-offset LOADs in one observed activation only.
It does not cover child-call effects, aliasing, escape, concrete address wrap,
frame privacy, or permission to suppress an event.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..memory_contracts import MemoryDefinitionKind
from ..model import ByteSpan
from ..relative_memory import _function_relative_object_id
from .configured_function_view import _FunctionView
from .configured_interprocedural_contracts import ConfiguredFunctionAnalysis
from .configured_recursive_frame_inventory import (
    CallTokenObservation,
    EntryRelativeInterval,
    FrameInventoryDebtReason,
    FrameMemoryAccess,
    RecursiveFrameInventory,
    ReturnTokenObservation,
    build_recursive_frame_inventory,
)


class LocalReadCoverageDebtReason(StrEnum):
    INCOMPLETE_INVENTORY = "incomplete_inventory"
    INVENTORY_MISMATCH = "inventory_mismatch"
    UNRESOLVED_READ = "unresolved_read"
    NON_DATA_WRITE = "non_data_write"
    PARTIAL_OR_AMBIGUOUS = "partial_or_ambiguous"
    STORE_MISMATCH = "store_mismatch"
    NOT_DEFINITE_BEFORE = "not_definite_before"
    RESOURCE_BOUND = "resource_bound"


class RecursiveLocalReadCoverageIncomplete(RuntimeError):
    def __init__(self, reason: LocalReadCoverageDebtReason, operation_key: str = "") -> None:
        self.reason = reason
        self.operation_key = operation_key
        super().__init__(f"{reason.value}: {operation_key}")


@dataclass(frozen=True, slots=True)
class CoveredLocalRead:
    load_operation_key: str
    store_operation_key: str
    read_ordinal: int
    definition_id: int
    memory_span: ByteSpan
    load_interval: EntryRelativeInterval
    store_interval: EntryRelativeInterval


@dataclass(frozen=True, slots=True)
class RecursiveLocalReadCoverage:
    function_scope_digest: bytes
    observation_digest: bytes
    memory_unit_digest: bytes
    reads: tuple[CoveredLocalRead, ...]
    bookkeeping_load_keys: tuple[str, ...]
    nonnegative_load_keys: tuple[str, ...]
    scope: str = "ordinary_negative_loads_only; no child-effect, alias, escape or privacy claim"


def _debt(reason, operation_key=""):
    raise RecursiveLocalReadCoverageIncomplete(reason, operation_key)


def _validate_interval(value):
    if (
        type(value) is not EntryRelativeInterval
        or type(value.anchor_definition_id) is not int
        or value.anchor_definition_id < 0
        or type(value.anchor_span) is not ByteSpan
        or type(value.address_space_id) is not int
        or value.address_space_id < 0
        or type(value.offset) is not int
        or type(value.byte_size) is not int
        or value.byte_size <= 0
    ):
        _debt(LocalReadCoverageDebtReason.INVENTORY_MISMATCH)
    try:
        value.anchor_span.__post_init__()
        value.anchor_span.object_id.__post_init__()
        value.anchor_span.object_id.scope.__post_init__()
    except (TypeError, ValueError):
        _debt(LocalReadCoverageDebtReason.INVENTORY_MISMATCH)


def _validate_inventory(inventory):
    for value in (
        inventory.function_scope_digest, inventory.observation_digest, inventory.memory_unit_digest
    ):
        if type(value) is not bytes or len(value) != 32:
            _debt(LocalReadCoverageDebtReason.INVENTORY_MISMATCH)
    if type(inventory.debts) is not tuple or inventory.debts:
        _debt(LocalReadCoverageDebtReason.INCOMPLETE_INVENTORY)
    for rows, row_type in (
        (inventory.accesses, FrameMemoryAccess),
        (inventory.call_tokens, CallTokenObservation),
        (inventory.return_tokens, ReturnTokenObservation),
    ):
        if type(rows) is not tuple or any(type(row) is not row_type for row in rows):
            _debt(LocalReadCoverageDebtReason.INVENTORY_MISMATCH)
        for row in rows:
            _validate_interval(row.interval)
    if any(
        type(row.operation_key) is not str or not row.operation_key
        or type(row.opcode) is not str or row.opcode not in ("LOAD", "STORE")
        for row in inventory.accesses
    ):
        _debt(LocalReadCoverageDebtReason.INVENTORY_MISMATCH)
    if any(type(row.before_offset) is not int for row in inventory.call_tokens) or any(
        type(row.after_offset) is not int for row in inventory.return_tokens
    ):
        _debt(LocalReadCoverageDebtReason.INVENTORY_MISMATCH)
    for rows, fields in (
        (inventory.call_tokens, ("call_operation_key", "adjust_operation_key", "store_operation_key")),
        (inventory.return_tokens, ("return_operation_key", "load_operation_key", "restore_operation_key")),
    ):
        if any(type(getattr(row, field)) is not str or not getattr(row, field) for row in rows for field in fields):
            _debt(LocalReadCoverageDebtReason.INVENTORY_MISMATCH)


def _covers(store, load):
    return (
        store.anchor_definition_id == load.anchor_definition_id
        and store.anchor_span == load.anchor_span
        and store.address_space_id == load.address_space_id
        and store.offset <= load.offset and load.stop <= store.stop
    )


def check_recursive_local_read_coverage(
    analysis: ConfiguredFunctionAnalysis,
    inventory: RecursiveFrameInventory,
    /,
    *,
    max_accesses: int = 4096,
    max_ssa_records: int = 16384,
    max_steps: int = 65536,
) -> RecursiveLocalReadCoverage:
    """Require one exact local STORE definition for every scoped LOAD.

    A proper subrange LOAD is supported when its one reaching DATA_WRITE and
    corresponding STORE cover every requested byte. Combining partial stores,
    ENTRY/JOIN definitions, unresolved reads, and may-before order is rejected.
    RETURN-token LOADs and nonnegative LOADs are explicitly listed outside this
    check's scope. Successful coverage does not prove absence of child writes.
    """
    if type(analysis) is not ConfiguredFunctionAnalysis or type(inventory) is not RecursiveFrameInventory:
        raise TypeError("local read coverage requires exact analysis and frame inventory")
    if any(type(limit) is not int or limit <= 0 for limit in (max_accesses, max_ssa_records, max_steps)):
        raise ValueError("local read coverage limits must be positive exact integers")
    if type(inventory.accesses) is not tuple:
        _debt(LocalReadCoverageDebtReason.INVENTORY_MISMATCH)
    if len(inventory.accesses) > max_accesses:
        _debt(LocalReadCoverageDebtReason.RESOURCE_BOUND)
    if type(inventory.call_tokens) is not tuple or type(inventory.return_tokens) is not tuple:
        _debt(LocalReadCoverageDebtReason.INVENTORY_MISMATCH)
    if len(inventory.call_tokens) + len(inventory.return_tokens) > max_accesses:
        _debt(LocalReadCoverageDebtReason.RESOURCE_BOUND)
    _validate_inventory(inventory)
    normalized = analysis.normalized
    memory = normalized.memory_ssa
    unit = normalized.memory_unit
    observation = analysis.evidence.unit.observation
    if (
        memory is None or unit is None or observation is None
        or normalized.scopes is not analysis.evidence.unit.scopes
        or not normalized.dependencies.is_frozen
        or inventory.function_scope_digest != normalized.scopes.function.scope.digest
        or inventory.observation_digest != normalized.scopes.function.observation_digest
        or inventory.memory_unit_digest != memory.unit_digest
        or unit.canonical_digest != memory.unit_digest
    ):
        _debt(LocalReadCoverageDebtReason.INVENTORY_MISMATCH)
    operation_count = sum(len(row.operations) for row in observation.instructions)
    record_count = (
        len(memory.actions) + len(memory.definitions) + len(memory.reads)
        + sum(len(read.fragments) for read in memory.reads)
        + len(memory.unresolved_reads) + len(memory.unresolved_writes)
        + len(memory.atomic_spans) + len(memory.state_nodes) + len(memory.observed_terminal_states)
        + len(memory.joins) + sum(len(join.source_definition_ids) for join in memory.joins)
        + len(unit.blocks) + sum(len(block.predecessors) for block in unit.blocks)
    )
    if len(inventory.accesses) > max_accesses or record_count > max_ssa_records or operation_count > max_steps:
        _debt(LocalReadCoverageDebtReason.RESOURCE_BOUND)
    try:
        memory.__post_init__()
        normalized.__post_init__()
    except (TypeError, ValueError):
        _debt(LocalReadCoverageDebtReason.INVENTORY_MISMATCH)

    # Inventory objects are ordinary frozen records, not an admission receipt.
    # Replay before trusting omitted loads or claimed bookkeeping exclusions.
    reproduced = build_recursive_frame_inventory(analysis, max_steps=max_steps)
    if not reproduced.complete:
        _debt(
            LocalReadCoverageDebtReason.RESOURCE_BOUND
            if any(row.reason is FrameInventoryDebtReason.BUDGET_EXHAUSTED for row in reproduced.debts)
            else LocalReadCoverageDebtReason.INCOMPLETE_INVENTORY
        )
    if reproduced != inventory:
        _debt(LocalReadCoverageDebtReason.INVENTORY_MISMATCH)
    view = _FunctionView(analysis)
    accesses = {row.operation_key: row for row in inventory.accesses}
    if len(accesses) != len(inventory.accesses):
        _debt(LocalReadCoverageDebtReason.INVENTORY_MISMATCH)
    actions = {row.operation_key: ordinal for ordinal, row in enumerate(memory.actions)}
    reads = {}
    for read in memory.reads:
        reads.setdefault((read.action_id, read.span), []).append(read)
    unresolved_reads = {row.action_id for row in memory.unresolved_reads}
    unresolved_writes = {row.action_id for row in memory.unresolved_writes}
    bookkeeping = {row.load_operation_key for row in inventory.return_tokens}
    token_stores = {row.store_operation_key for row in inventory.call_tokens}
    covered, outside = [], []
    remaining = max_steps
    for load in sorted(inventory.accesses, key=lambda row: row.operation_key):
        if load.opcode != "LOAD" or load.operation_key in bookkeeping:
            continue
        interval = load.interval
        if interval.offset >= 0:
            outside.append(load.operation_key)
            continue
        remaining -= 1
        if remaining < 0:
            _debt(LocalReadCoverageDebtReason.RESOURCE_BOUND, load.operation_key)
        if interval.stop > 0:
            _debt(LocalReadCoverageDebtReason.PARTIAL_OR_AMBIGUOUS, load.operation_key)
        bits = view.space_bits.get(interval.address_space_id)
        if bits is None or interval.anchor_span.size * 8 != bits:
            _debt(LocalReadCoverageDebtReason.UNRESOLVED_READ, load.operation_key)
        start = (1 << bits) + interval.offset
        if start < 0:
            _debt(LocalReadCoverageDebtReason.UNRESOLVED_READ, load.operation_key)
        span = ByteSpan(
            _function_relative_object_id(memory.function_scope, interval.anchor_span, interval.address_space_id),
            start, interval.byte_size,
        )
        action_id = actions.get(load.operation_key)
        if action_id is None or action_id in unresolved_reads:
            _debt(LocalReadCoverageDebtReason.UNRESOLVED_READ, load.operation_key)
        candidates = reads.get((action_id, span), ())
        if len(candidates) != 1:
            _debt(LocalReadCoverageDebtReason.PARTIAL_OR_AMBIGUOUS, load.operation_key)
        read = candidates[0]
        if len(read.fragments) != 1 or read.fragments[0].span != span or len(read.fragments[0].definition_ids) != 1:
            _debt(LocalReadCoverageDebtReason.PARTIAL_OR_AMBIGUOUS, load.operation_key)
        definition_id = read.fragments[0].definition_ids[0]
        definition = memory.definitions[definition_id]
        if definition.kind is not MemoryDefinitionKind.DATA_WRITE:
            _debt(LocalReadCoverageDebtReason.NON_DATA_WRITE, load.operation_key)
        store = accesses.get(definition.operation_key)
        store_id = actions.get(definition.operation_key)
        if (
            store is None or store.opcode != "STORE" or store_id is None
            or store.operation_key in token_stores or store_id in unresolved_writes
            or not _covers(store.interval, interval)
            or not definition.span.contains(span)
            or definition_id not in memory.actions[store_id].write_definition_ids
        ):
            _debt(LocalReadCoverageDebtReason.STORE_MISMATCH, load.operation_key)
        write_action = view.storage_actions.get(store.operation_key)
        if (
            write_action is None or definition.write_ordinal is None
            or definition.write_ordinal >= len(write_action.writes)
            or write_action.writes[definition.write_ordinal] != definition.span
        ):
            _debt(LocalReadCoverageDebtReason.STORE_MISMATCH, load.operation_key)
        if not view.definitely_precedes(store.operation_key, load.operation_key):
            _debt(LocalReadCoverageDebtReason.NOT_DEFINITE_BEFORE, load.operation_key)
        covered.append(CoveredLocalRead(
            load.operation_key, store.operation_key, read.read_ordinal, definition_id,
            span, interval, store.interval,
        ))
    return RecursiveLocalReadCoverage(
        inventory.function_scope_digest, inventory.observation_digest, inventory.memory_unit_digest,
        tuple(covered), tuple(sorted(bookkeeping)), tuple(outside),
    )


__all__ = (
    "LocalReadCoverageDebtReason", "RecursiveLocalReadCoverageIncomplete",
    "CoveredLocalRead", "RecursiveLocalReadCoverage", "check_recursive_local_read_coverage",
)
