"""Architect-owned contracts for deterministic local byte-range SSA."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json

from .effects import UnresolvedMemoryAccess
from .model import (
    ByteSpan,
    NonStorage,
    ResolvedStorage,
    StorageObjectKind,
    StorageRef,
    StorageScopeId,
    StorageScopeKind,
    UnresolvedStorage,
)


LOCAL_MEMORY_CONTRACT_VERSION = 3


class MemoryWriteMode(StrEnum):
    DATA = "data"
    KILL = "kill"


class MemoryDefinitionKind(StrEnum):
    ENTRY = "entry"
    DATA_WRITE = "data_write"
    KILL = "kill"
    JOIN = "join"


@dataclass(frozen=True, slots=True)
class LocalStorageAction:
    operation_key: str
    reads: tuple[ByteSpan, ...] = ()
    writes: tuple[ByteSpan, ...] = ()
    unresolved_reads: tuple[UnresolvedMemoryAccess, ...] = ()
    unresolved_writes: tuple[UnresolvedMemoryAccess, ...] = ()
    write_mode: MemoryWriteMode | None = None

    def __post_init__(self) -> None:
        _require_nonempty_string(self.operation_key, "operation key")
        _require_exact_tuple(self.reads, ByteSpan, "action reads")
        _require_exact_tuple(self.writes, ByteSpan, "action writes")
        _require_exact_tuple(
            self.unresolved_reads, UnresolvedMemoryAccess, "unresolved reads"
        )
        _require_exact_tuple(
            self.unresolved_writes, UnresolvedMemoryAccess, "unresolved writes"
        )
        if self.write_mode is not None and type(self.write_mode) is not MemoryWriteMode:
            raise TypeError("write mode must be an exact MemoryWriteMode or None")
        if bool(self.writes) != (self.write_mode is not None):
            raise ValueError("write mode must be present exactly when concrete writes exist")
        if self.write_mode is MemoryWriteMode.KILL and (
            self.reads or self.unresolved_reads
        ):
            raise ValueError("kill actions cannot consume concrete or unresolved reads")
        ordered_writes = sorted(
            self.writes,
            key=lambda span: (span.object_id, span.start, span.end),
        )
        for left, right in zip(ordered_writes, ordered_writes[1:]):
            if left.overlaps(right):
                raise ValueError("concrete writes in one action must be pairwise disjoint")


@dataclass(frozen=True, slots=True)
class LocalMemoryBlock:
    key: str
    predecessors: tuple[str, ...]
    actions: tuple[LocalStorageAction, ...]

    def __post_init__(self) -> None:
        _require_nonempty_string(self.key, "block key")
        if type(self.predecessors) is not tuple:
            raise TypeError("block predecessors must be an exact tuple")
        for predecessor in self.predecessors:
            _require_nonempty_string(predecessor, "predecessor key")
        if len(set(self.predecessors)) != len(self.predecessors):
            raise ValueError("block predecessors must not contain duplicates")
        _require_exact_tuple(self.actions, LocalStorageAction, "block actions")


@dataclass(frozen=True, slots=True)
class LocalMemoryUnit:
    contract_version: int
    function_scope: StorageScopeId
    entry_block_key: str
    blocks: tuple[LocalMemoryBlock, ...]
    observed_terminal_block_keys: tuple[str, ...] = ()
    effect_evidence_digest: bytes = field(kw_only=True)

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int:
            raise TypeError("contract version must be an exact int")
        if self.contract_version != LOCAL_MEMORY_CONTRACT_VERSION:
            raise ValueError("unsupported local-memory contract version")
        if type(self.function_scope) is not StorageScopeId:
            raise TypeError("function scope must be an exact StorageScopeId")
        if self.function_scope.kind is not StorageScopeKind.FUNCTION:
            raise TypeError("local-memory units require a function scope")
        _require_nonempty_string(self.entry_block_key, "entry block key")
        _require_exact_tuple(self.blocks, LocalMemoryBlock, "unit blocks")
        if not self.blocks:
            raise ValueError("local-memory unit must contain at least one block")

        keys = tuple(block.key for block in self.blocks)
        if len(set(keys)) != len(keys):
            raise ValueError("block keys must be unique")
        known = set(keys)
        if self.entry_block_key not in known:
            raise ValueError("entry block key must name an existing block")
        if any(
            predecessor not in known
            for block in self.blocks
            for predecessor in block.predecessors
        ):
            raise ValueError("every predecessor must name an existing block")
        if type(self.observed_terminal_block_keys) is not tuple or any(
            type(key) is not str or not key
            for key in self.observed_terminal_block_keys
        ):
            raise TypeError("observed terminal block keys must be an exact string tuple")
        if (
            tuple(sorted(set(self.observed_terminal_block_keys)))
            != self.observed_terminal_block_keys
        ):
            raise ValueError("observed terminal block keys must be sorted and unique")
        if any(key not in known for key in self.observed_terminal_block_keys):
            raise ValueError("observed terminal block keys must name existing blocks")
        _require_effect_evidence_digest(self.effect_evidence_digest)

        action_keys = tuple(
            action.operation_key for block in self.blocks for action in block.actions
        )
        if len(set(action_keys)) != len(action_keys):
            raise ValueError("operation keys must be unique within a unit")
        self._validate_reachability()
        self._validate_function_unique_scopes()

    @property
    def canonical_digest(self) -> bytes:
        encoded = json.dumps(
            _unit_payload(self),
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
        return hashlib.sha256(encoded).digest()

    def _validate_reachability(self) -> None:
        successors = {block.key: set() for block in self.blocks}
        for block in self.blocks:
            for predecessor in block.predecessors:
                successors[predecessor].add(block.key)
        pending = [self.entry_block_key]
        reached: set[str] = set()
        while pending:
            key = pending.pop()
            if key in reached:
                continue
            reached.add(key)
            pending.extend(successors[key] - reached)
        if reached != set(successors):
            raise ValueError("every block must be reachable from the observed entry")

    def _validate_function_unique_scopes(self) -> None:
        for block in self.blocks:
            for action in block.actions:
                unresolved_spans = tuple(
                    access.address.span
                    for access in (*action.unresolved_reads, *action.unresolved_writes)
                    if type(access.address) is ResolvedStorage
                )
                for span in (*action.reads, *action.writes, *unresolved_spans):
                    if (
                        span.object_id.kind in (
                            StorageObjectKind.FUNCTION_UNIQUE,
                            StorageObjectKind.FUNCTION_RELATIVE,
                        )
                        and span.object_id.scope != self.function_scope
                    ):
                        raise ValueError(
                            "function-local spans must use the unit function scope"
                        )


@dataclass(frozen=True, slots=True)
class MemoryDefinition:
    kind: MemoryDefinitionKind
    span: ByteSpan
    block_key: str | None = None
    operation_key: str | None = None
    write_ordinal: int | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not MemoryDefinitionKind:
            raise TypeError("definition kind must be an exact MemoryDefinitionKind")
        if type(self.span) is not ByteSpan:
            raise TypeError("definition span must be an exact ByteSpan")
        if self.kind in (MemoryDefinitionKind.ENTRY, MemoryDefinitionKind.JOIN):
            _require_nonempty_string(self.block_key, "definition block key")
            if self.operation_key is not None or self.write_ordinal is not None:
                raise ValueError("entry and join definitions cannot name a write")
        else:
            if self.block_key is not None:
                raise ValueError("write definitions cannot name a block")
            _require_nonempty_string(self.operation_key, "definition operation key")
            _require_nonnegative_int(self.write_ordinal, "write ordinal")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        rank = {
            MemoryDefinitionKind.ENTRY: 0,
            MemoryDefinitionKind.DATA_WRITE: 1,
            MemoryDefinitionKind.KILL: 2,
            MemoryDefinitionKind.JOIN: 3,
        }[self.kind]
        return (
            rank,
            self.block_key or "",
            self.operation_key or "",
            -1 if self.write_ordinal is None else self.write_ordinal,
            self.span.canonical_key,
        )


@dataclass(frozen=True, slots=True)
class MemoryActionResult:
    operation_key: str
    write_definition_ids: tuple[int, ...]

    def __post_init__(self) -> None:
        _require_nonempty_string(self.operation_key, "action-result operation key")
        _require_id_tuple(self.write_definition_ids, "action write definition IDs")


@dataclass(frozen=True, slots=True)
class MemoryJoinInput:
    join_definition_id: int
    source_definition_ids: tuple[int, ...]

    def __post_init__(self) -> None:
        _require_nonnegative_int(self.join_definition_id, "join definition ID")
        _require_id_tuple(self.source_definition_ids, "join source definition IDs")
        if len(self.source_definition_ids) < 2:
            raise ValueError("join input requires at least two source definitions")


@dataclass(frozen=True, slots=True)
class MemoryReadFragment:
    span: ByteSpan
    definition_ids: tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self.span) is not ByteSpan:
            raise TypeError("read fragment span must be an exact ByteSpan")
        _require_id_tuple(self.definition_ids, "read fragment definition IDs")
        if len(self.definition_ids) != 1:
            raise ValueError("each read fragment must reference exactly one definition")


@dataclass(frozen=True, slots=True)
class MemoryReadResolution:
    action_id: int
    read_ordinal: int
    span: ByteSpan
    fragments: tuple[MemoryReadFragment, ...]

    def __post_init__(self) -> None:
        _require_nonnegative_int(self.action_id, "read action ID")
        _require_nonnegative_int(self.read_ordinal, "read ordinal")
        if type(self.span) is not ByteSpan:
            raise TypeError("read span must be an exact ByteSpan")
        _require_exact_tuple(self.fragments, MemoryReadFragment, "read fragments")
        if not self.fragments:
            raise ValueError("a concrete read must contain at least one fragment")
        _require_sorted_unique(
            self.fragments,
            key=lambda fragment: fragment.span.canonical_key,
            label="read fragments",
        )
        for fragment in self.fragments:
            if not self.span.contains(fragment.span):
                raise ValueError("read fragments must be contained by the read span")
        ordered = sorted(self.fragments, key=lambda item: item.span.start)
        cursor = self.span.start
        for fragment in ordered:
            if fragment.span.start != cursor:
                raise ValueError("read fragments must exactly and contiguously cover the read")
            cursor = fragment.span.end
        if cursor != self.span.end:
            raise ValueError("read fragments must exactly and contiguously cover the read")


@dataclass(frozen=True, slots=True)
class MemoryUnresolvedOccurrence:
    action_id: int
    occurrence_ordinal: int
    access: UnresolvedMemoryAccess

    def __post_init__(self) -> None:
        _require_nonnegative_int(self.action_id, "unresolved action ID")
        _require_nonnegative_int(self.occurrence_ordinal, "unresolved occurrence ordinal")
        if type(self.access) is not UnresolvedMemoryAccess:
            raise TypeError("unresolved occurrence requires an exact access record")


@dataclass(frozen=True, slots=True)
class MemoryStateNode:
    """One immutable run-tree node over the canonical atomic-span index."""

    start_atom: int
    stop_atom: int
    definition_ids: tuple[int, ...]
    left_node_id: int | None = None
    right_node_id: int | None = None

    def __post_init__(self) -> None:
        _require_nonnegative_int(self.start_atom, "state-node start atom")
        _require_nonnegative_int(self.stop_atom, "state-node stop atom")
        if self.start_atom >= self.stop_atom:
            raise ValueError("state-node atom range must be positive")
        _require_id_tuple(self.definition_ids, "state-node definition IDs")
        if not self.definition_ids:
            raise ValueError("state nodes require at least one reaching definition")
        for value, label in (
            (self.left_node_id, "left state-node ID"),
            (self.right_node_id, "right state-node ID"),
        ):
            if value is not None:
                _require_nonnegative_int(value, label)


@dataclass(frozen=True, slots=True)
class ObservedTerminalMemoryState:
    block_key: str
    root_node_id: int | None

    def __post_init__(self) -> None:
        _require_nonempty_string(self.block_key, "observed terminal block key")
        if self.root_node_id is not None:
            _require_nonnegative_int(self.root_node_id, "terminal-state root node ID")


@dataclass(frozen=True, slots=True)
class LocalMemorySsaResult:
    contract_version: int
    function_scope: StorageScopeId
    unit_digest: bytes
    atomic_spans: tuple[ByteSpan, ...]
    actions: tuple[MemoryActionResult, ...]
    definitions: tuple[MemoryDefinition, ...]
    joins: tuple[MemoryJoinInput, ...]
    reads: tuple[MemoryReadResolution, ...]
    unresolved_reads: tuple[MemoryUnresolvedOccurrence, ...]
    unresolved_writes: tuple[MemoryUnresolvedOccurrence, ...]
    state_nodes: tuple[MemoryStateNode, ...] = ()
    observed_terminal_states: tuple[ObservedTerminalMemoryState, ...] = ()

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int:
            raise TypeError("result contract version must be an exact int")
        if self.contract_version != LOCAL_MEMORY_CONTRACT_VERSION:
            raise ValueError("unsupported result contract version")
        if type(self.function_scope) is not StorageScopeId:
            raise TypeError("result function scope must be exact")
        if self.function_scope.kind is not StorageScopeKind.FUNCTION:
            raise TypeError("result requires a function scope")
        if type(self.unit_digest) is not bytes:
            raise TypeError("unit digest must be exact bytes")
        if len(self.unit_digest) != 32:
            raise ValueError("unit digest must contain exactly 32 bytes")
        _require_exact_tuple(self.atomic_spans, ByteSpan, "atomic spans")
        _require_exact_tuple(self.actions, MemoryActionResult, "action results")
        _require_exact_tuple(self.definitions, MemoryDefinition, "definitions")
        _require_exact_tuple(self.joins, MemoryJoinInput, "join inputs")
        _require_exact_tuple(self.reads, MemoryReadResolution, "read resolutions")
        _require_exact_tuple(
            self.unresolved_reads, MemoryUnresolvedOccurrence, "unresolved reads"
        )
        _require_exact_tuple(
            self.unresolved_writes, MemoryUnresolvedOccurrence, "unresolved writes"
        )
        _require_exact_tuple(self.state_nodes, MemoryStateNode, "memory state nodes")
        _require_exact_tuple(
            self.observed_terminal_states,
            ObservedTerminalMemoryState,
            "observed terminal memory states",
        )
        self._validate_canonical_order()
        self._validate_relations()

    @property
    def has_unresolved_debt(self) -> bool:
        return bool(self.unresolved_reads or self.unresolved_writes)

    def _validate_canonical_order(self) -> None:
        _require_sorted_unique(
            self.atomic_spans,
            key=_atomic_span_order_key,
            label="atomic spans",
        )
        for left, right in zip(self.atomic_spans, self.atomic_spans[1:]):
            if left.object_id == right.object_id and left.end > right.start:
                raise ValueError("atomic spans must form a non-overlapping partition")
        _require_sorted_unique(
            self.actions,
            key=lambda action: action.operation_key,
            label="action results",
        )
        _require_sorted_unique(
            self.definitions,
            key=lambda definition: definition.canonical_key,
            label="definitions",
        )
        _require_sorted_unique(
            self.joins,
            key=lambda join: join.join_definition_id,
            label="join inputs",
        )
        _require_sorted_unique(
            self.reads,
            key=lambda read: (read.action_id, read.read_ordinal),
            label="read resolutions",
        )
        for values, label in (
            (self.unresolved_reads, "unresolved reads"),
            (self.unresolved_writes, "unresolved writes"),
        ):
            _require_sorted_unique(
                values,
                key=lambda item: (item.action_id, item.occurrence_ordinal),
                label=label,
            )
        _require_sorted_unique(
            self.observed_terminal_states,
            key=lambda item: item.block_key,
            label="observed terminal memory states",
        )

    def _validate_relations(self) -> None:
        definition_count = len(self.definitions)
        action_count = len(self.actions)
        joins_by_id = {item.join_definition_id: item for item in self.joins}
        join_definition_ids = {
            definition_id
            for definition_id, definition in enumerate(self.definitions)
            if definition.kind is MemoryDefinitionKind.JOIN
        }
        if join_definition_ids != set(joins_by_id):
            raise ValueError("every JOIN definition requires one exact join relation")
        for action in self.actions:
            for definition_id in action.write_definition_ids:
                _require_id_in_range(definition_id, definition_count, "action definition")
                definition = self.definitions[definition_id]
                if definition.kind not in (
                    MemoryDefinitionKind.DATA_WRITE,
                    MemoryDefinitionKind.KILL,
                ) or definition.operation_key != action.operation_key:
                    raise ValueError("action write IDs must name its concrete writes")
        for join in self.joins:
            _require_id_in_range(join.join_definition_id, definition_count, "join")
            if self.definitions[join.join_definition_id].kind is not MemoryDefinitionKind.JOIN:
                raise ValueError("join relation must target a JOIN definition")
            for source_id in join.source_definition_ids:
                _require_id_in_range(source_id, definition_count, "join source")
                if self.definitions[source_id].kind is MemoryDefinitionKind.JOIN:
                    raise ValueError("join sources must be raw definitions")
        demanded_join_ids: set[int] = set()
        for read in self.reads:
            _require_id_in_range(read.action_id, action_count, "read action")
            for fragment in read.fragments:
                definition_id = fragment.definition_ids[0]
                _require_id_in_range(definition_id, definition_count, "read definition")
                is_join = self.definitions[definition_id].kind is MemoryDefinitionKind.JOIN
                if is_join != (definition_id in joins_by_id):
                    raise ValueError("read JOIN references require one exact join relation")
                if is_join:
                    demanded_join_ids.add(definition_id)
        if demanded_join_ids != join_definition_ids:
            raise ValueError("JOIN definitions may exist only when demanded by a read")
        for occurrence in (*self.unresolved_reads, *self.unresolved_writes):
            _require_id_in_range(occurrence.action_id, action_count, "unresolved action")
        self._validate_state_arena()

    def _validate_state_arena(self) -> None:
        atom_count = len(self.atomic_spans)
        contiguous_run_ends = _contiguous_run_ends(self.atomic_spans)
        subtree_bounds: list[tuple[int, int]] = []
        for node_id, node in enumerate(self.state_nodes):
            if node.stop_atom > atom_count:
                raise ValueError("state-node atom range is outside the partition")
            for child_id, side in (
                (node.left_node_id, "left"),
                (node.right_node_id, "right"),
            ):
                if child_id is not None and child_id >= node_id:
                    raise ValueError(f"{side} state-node ID must precede its parent")
            if node.stop_atom > contiguous_run_ends[node.start_atom]:
                raise ValueError(
                    "state-node atoms must form one contiguous storage-object range"
                )
            first = self.atomic_spans[node.start_atom]
            last = self.atomic_spans[node.stop_atom - 1]
            covered = ByteSpan(first.object_id, first.start, last.end - first.start)
            for definition_id in node.definition_ids:
                _require_id_in_range(
                    definition_id, len(self.definitions), "state-node definition"
                )
                definition = self.definitions[definition_id]
                if definition.kind is MemoryDefinitionKind.JOIN:
                    raise ValueError("terminal state nodes retain raw definitions only")
                if not definition.span.contains(covered):
                    raise ValueError("state-node definitions must cover the node range")
            left_start = node.start_atom
            right_stop = node.stop_atom
            if node.left_node_id is not None:
                left_start, left_stop = subtree_bounds[node.left_node_id]
                if left_stop != node.start_atom:
                    raise ValueError(
                        "left state subtree must end exactly at its parent run"
                    )
            if node.right_node_id is not None:
                right_start, right_stop = subtree_bounds[node.right_node_id]
                if right_start != node.stop_atom:
                    raise ValueError(
                        "right state subtree must start exactly at its parent run"
                    )
            subtree_bounds.append((left_start, right_stop))
        for state in self.observed_terminal_states:
            if state.root_node_id is None:
                if atom_count:
                    raise ValueError(
                        "non-empty atomic partitions require a complete terminal-state root"
                    )
                continue
            _require_id_in_range(
                state.root_node_id,
                len(self.state_nodes),
                "terminal-state root node",
            )
            if subtree_bounds[state.root_node_id] != (0, atom_count):
                raise ValueError(
                    "each terminal-state root must exactly cover the atomic partition"
                )
        reachable: set[int] = set()
        pending = [
            state.root_node_id
            for state in self.observed_terminal_states
            if state.root_node_id is not None
        ]
        while pending:
            node_id = pending.pop()
            if node_id in reachable:
                continue
            reachable.add(node_id)
            node = self.state_nodes[node_id]
            pending.extend(
                child
                for child in (node.left_node_id, node.right_node_id)
                if child is not None
            )
        if reachable != set(range(len(self.state_nodes))):
            raise ValueError("memory state nodes must be reachable from terminal roots")


def _contiguous_run_ends(spans: tuple[ByteSpan, ...]) -> tuple[int, ...]:
    """Return the exclusive maximal contiguous-object end for every atom."""

    if not spans:
        return ()
    ends = [0] * len(spans)
    ends[-1] = len(spans)
    for index in range(len(spans) - 2, -1, -1):
        current = spans[index]
        successor = spans[index + 1]
        if (
            current.object_id == successor.object_id
            and current.end == successor.start
        ):
            ends[index] = ends[index + 1]
        else:
            ends[index] = index + 1
    return tuple(ends)


def _atomic_span_order_key(span: ByteSpan) -> tuple[object, ...]:
    object_id = span.object_id
    return (
        object_id.kind.value,
        object_id.scope.kind.value,
        object_id.scope.digest,
        object_id.space_key,
        span.start,
        span.size,
    )


def _unit_payload(unit: LocalMemoryUnit) -> list[object]:
    blocks = []
    for block in sorted(unit.blocks, key=lambda item: item.key):
        actions = []
        for action in block.actions:
            actions.append(
                [
                    action.operation_key,
                    [list(span.canonical_key) for span in action.reads],
                    [list(span.canonical_key) for span in action.writes],
                    [_access_key(access) for access in action.unresolved_reads],
                    [_access_key(access) for access in action.unresolved_writes],
                    None if action.write_mode is None else action.write_mode.value,
                ]
            )
        blocks.append([block.key, sorted(block.predecessors), actions])
    return [
        "local-memory-unit-v3",
        unit.function_scope.digest.hex(),
        unit.effect_evidence_digest.hex(),
        unit.entry_block_key,
        blocks,
        list(unit.observed_terminal_block_keys),
    ]


def _access_key(access: UnresolvedMemoryAccess) -> list[object]:
    return [
        _evidence_key(access.address),
        access.width,
        None if access.raw_address is None else _storage_ref_key(access.raw_address),
    ]


def _evidence_key(value: object) -> list[object] | None:
    if value is None:
        return None
    if type(value) is StorageRef:
        return ["raw", *_storage_ref_key(value)]
    if type(value) is ResolvedStorage:
        return ["resolved", *value.span.canonical_key]
    if type(value) is UnresolvedStorage:
        return ["unresolved", value.reason.value]
    if type(value) is NonStorage:
        return ["non_storage"]
    raise TypeError("unsupported storage evidence in canonical input")


def _storage_ref_key(value: StorageRef) -> list[object]:
    return [
        value.kind.value,
        value.space,
        value.offset,
        value.size,
        value.register_name,
        value.space_id,
    ]


def _require_nonempty_string(value: object, label: str) -> None:
    if type(value) is not str:
        raise TypeError(f"{label} must be an exact str")
    if not value:
        raise ValueError(f"{label} must not be empty")


def _require_effect_evidence_digest(value: object) -> None:
    if type(value) is not bytes:
        raise TypeError("effect evidence digest must be exact bytes")
    if len(value) != 32:
        raise ValueError("effect evidence digest must contain exactly 32 bytes")
    if value == bytes(32):
        raise ValueError("effect evidence digest cannot use the zero sentinel")


def _require_exact_tuple(value: object, item_type: type, label: str) -> None:
    if type(value) is not tuple:
        raise TypeError(f"{label} must be an exact tuple")
    if any(type(item) is not item_type for item in value):
        raise TypeError(f"{label} must contain exact {item_type.__name__} values")


def _require_nonnegative_int(value: object, label: str) -> None:
    if type(value) is not int:
        raise TypeError(f"{label} must be an exact int")
    if value < 0:
        raise ValueError(f"{label} must be non-negative")


def _require_id_tuple(value: object, label: str) -> None:
    if type(value) is not tuple:
        raise TypeError(f"{label} must be an exact tuple")
    for item in value:
        _require_nonnegative_int(item, label)
    if tuple(sorted(set(value))) != value:
        raise ValueError(f"{label} must be sorted and unique")


def _require_sorted_unique(values, *, key, label: str) -> None:
    keys = tuple(key(value) for value in values)
    if tuple(sorted(set(keys))) != keys:
        raise ValueError(f"{label} must be canonically sorted and unique")


def _require_id_in_range(value: int, count: int, label: str) -> None:
    if value >= count:
        raise ValueError(f"{label} ID is out of range")
