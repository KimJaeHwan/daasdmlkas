"""Deterministic local byte-range reaching definitions."""

from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass
import heapq
import os
from typing import Callable

from ._memory_ssa_state import (
    DefinitionSetPool as _DefinitionSetPool,
    EMPTY_STATE as _EMPTY_STATE,
    IdSet as _IdSet,
    Run as _Run,
    State as _State,
    iter_runs as _iter_runs,
    iter_runs_from as _iter_runs_from,
    make_state as _make_state,
    mask as _mask,
    overlay as _overlay,
    replace as _replace,
    subtract as _difference,
    union as _union,
)
from .memory_contracts import (
    LOCAL_MEMORY_CONTRACT_VERSION,
    LocalMemorySsaResult,
    LocalMemoryUnit,
    MemoryActionResult,
    MemoryDefinition,
    MemoryDefinitionKind,
    MemoryJoinInput,
    MemoryReadFragment,
    MemoryReadResolution,
    MemoryStateNode,
    MemoryUnresolvedOccurrence,
    MemoryWriteMode,
    ObservedTerminalMemoryState,
)
from .model import ByteSpan, StorageObjectId


@dataclass(frozen=True, slots=True)
class _ObjectAtoms:
    offset: int
    starts: tuple[int, ...]
    spans: tuple[ByteSpan, ...]


@dataclass(frozen=True, slots=True)
class _Partition:
    atoms: tuple[ByteSpan, ...]
    connected: tuple[ByteSpan, ...]
    by_object: dict[StorageObjectId, _ObjectAtoms]

    def covered_range(self, span: ByteSpan) -> tuple[int, int]:
        indexed = self.by_object[span.object_id]
        first = bisect_left(indexed.starts, span.start)
        cursor = span.start
        position = first
        while position < len(indexed.spans):
            atom = indexed.spans[position]
            if atom.start != cursor or atom.end > span.end:
                break
            cursor = atom.end
            position += 1
            if cursor == span.end:
                return indexed.offset + first, indexed.offset + position
        raise AssertionError("partition does not exactly cover an observed span")


def _dense_states(unit, partition, write_ids, entry_state, pool, *, compress_chains=True):
    """Least fixed point of the dense dataflow: (in_states, out_states) per block."""
    blocks = {block.key: block for block in unit.blocks}
    transfers = {
        key: _compile_transfer(block, partition, write_ids, pool)
        for key, block in blocks.items()
    }
    successors: dict[str, list[str]] = {key: [] for key in blocks}
    for block in unit.blocks:
        for predecessor in block.predecessors:
            successors[predecessor].append(block.key)
    successors = {key: tuple(sorted(values)) for key, values in successors.items()}

    # Solve on straight-line chains (a block whose only predecessor has it as
    # the only successor joins that predecessor's chain), then expand. The
    # in-state of a chain member is exactly its predecessor's out-state, so the
    # least fixed point is unchanged; only the worklist is shorter.
    chains = (
        _straight_line_chains(unit, blocks, successors)
        if compress_chains
        else {key: [key] for key in sorted(blocks)}
    )
    chain_transfers = {}
    for leader, members in chains.items():
        state = _EMPTY_STATE
        for key in members:
            for action in blocks[key].actions:
                state = _apply_writes(state, action, partition, write_ids, pool)
        chain_transfers[leader] = state
    chain_successors = {leader: successors[members[-1]] for leader, members in chains.items()}

    in_states = {key: _EMPTY_STATE for key in chains}
    in_states[unit.entry_block_key] = entry_state
    out_states = {key: _overlay(in_states[key], chain_transfers[key]) for key in chains}
    pending_deltas = {
        key: state for key, state in out_states.items() if state.root is not None
    }
    pending = sorted(pending_deltas)
    heapq.heapify(pending)
    queued = set(pending)

    while pending:
        block_key = heapq.heappop(pending)
        queued.remove(block_key)
        delta = pending_deltas.pop(block_key)
        for successor in chain_successors[block_key]:
            old_in = in_states[successor]
            input_delta = _difference(delta, old_in)
            if input_delta.root is None:
                continue
            new_in = _union(old_in, input_delta)
            in_states[successor] = new_in
            output_delta = _mask(input_delta, chain_transfers[successor])
            if output_delta.root is None:
                continue
            old_out = out_states[successor]
            output_delta = _difference(output_delta, old_out)
            if output_delta.root is None:
                continue
            new_out = _union(old_out, output_delta)
            out_states[successor] = new_out
            pending_deltas[successor] = _union(
                pending_deltas.get(successor, _EMPTY_STATE), output_delta
            )
            if successor not in queued:
                heapq.heappush(pending, successor)
                queued.add(successor)

    for leader, members in chains.items():
        state = in_states[leader]
        for key in members:
            in_states[key] = state
            state = _overlay(state, transfers[key])
            out_states[key] = state
    return in_states, out_states


def _straight_line_chains(unit, blocks, successors) -> dict[str, list[str]]:
    """leader -> member keys (leader first) of maximal straight-line chains."""
    predecessors = {key: tuple(set(block.predecessors)) for key, block in blocks.items()}

    def inner(key):
        if key == unit.entry_block_key or len(predecessors[key]) != 1:
            return False
        (predecessor,) = predecessors[key]
        return predecessor != key and successors[predecessor] == (key,)

    chains: dict[str, list[str]] = {}
    assigned: set[str] = set()

    def grow(leader):
        members = [leader]
        assigned.add(leader)
        while len(successors[members[-1]]) == 1:
            (following,) = successors[members[-1]]
            if following in assigned or not inner(following):
                break
            members.append(following)
            assigned.add(following)
        chains[leader] = members

    for key in sorted(blocks):
        if not inner(key):
            grow(key)
    for key in sorted(blocks):  # cycles made only of chain members (unreachable)
        if key not in assigned:
            grow(key)
    return chains


MEMORY_SSA_ENGINE_ENV = "TDO_V2_MEMORY_SSA_ENGINE"
MEMORY_SSA_CROSSCHECK_ENV = "TDO_V2_MEMORY_SSA_CROSSCHECK"
_ENGINES: dict[str, Callable[[LocalMemoryUnit], LocalMemorySsaResult]] = {}


class MemorySsaEngineMismatch(AssertionError):
    """Two memory SSA engines produced different results for one unit."""


def register_memory_ssa_engine(
    name: str, builder: Callable[[LocalMemoryUnit], LocalMemorySsaResult]
) -> None:
    """Make an engine selectable by name (``MEMORY_SSA_ENGINE_ENV`` /
    ``MEMORY_SSA_CROSSCHECK_ENV``); every engine must produce the canonical
    least-fixed-point result, identical to ``dense``."""
    if type(name) is not str or not name:
        raise TypeError("memory SSA engine name must be a non-empty str")
    _ENGINES[name] = builder


def memory_ssa_engine_names() -> tuple[str, ...]:
    return tuple(sorted(_ENGINES))


def build_local_memory_ssa(unit: LocalMemoryUnit) -> LocalMemorySsaResult:
    """Build the canonical least-fixed-point result for one frozen unit.

    The engine is ``dense`` unless ``TDO_V2_MEMORY_SSA_ENGINE`` names another
    registered engine. With ``TDO_V2_MEMORY_SSA_CROSSCHECK=<engine>`` the unit
    is also built by that engine and any difference raises
    ``MemorySsaEngineMismatch`` naming the first differing fields (equivalence
    harness for alternative engines; off by default).
    """
    if type(unit) is not LocalMemoryUnit:
        raise TypeError("local memory SSA requires an exact LocalMemoryUnit")
    result = _engine(os.environ.get(MEMORY_SSA_ENGINE_ENV) or "dense")(unit)
    other = os.environ.get(MEMORY_SSA_CROSSCHECK_ENV)
    if other:
        expected = _engine(other)(unit)
        if result != expected:
            from .memory_ssa_compare import memory_ssa_differences

            raise MemorySsaEngineMismatch(
                f"memory SSA engines disagree ({os.environ.get(MEMORY_SSA_ENGINE_ENV) or 'dense'}"
                f" vs {other}): " + "; ".join(memory_ssa_differences(result, expected))
            )
    return result


def _engine(name: str) -> Callable[[LocalMemoryUnit], LocalMemorySsaResult]:
    try:
        return _ENGINES[name]
    except KeyError:
        raise ValueError(
            f"unknown memory SSA engine {name!r}; known: {', '.join(memory_ssa_engine_names())}"
        ) from None


def _build_dense(unit: LocalMemoryUnit, *, compress_chains: bool = True) -> LocalMemorySsaResult:
    """Dense engine: every block carries the whole state. ``compress_chains``
    solves on straight-line chains (same result; ``dense-unchained`` is the
    one-block-per-node reference)."""
    if type(unit) is not LocalMemoryUnit:
        raise TypeError("local memory SSA requires an exact LocalMemoryUnit")

    partition = _build_partition(unit)
    raw_definitions = _raw_definitions(unit, partition.connected)
    write_ids = {
        (definition.operation_key, definition.write_ordinal): ordinal
        for ordinal, definition in enumerate(raw_definitions)
        if definition.operation_key is not None
    }
    writes_by_action: dict[str, list[int]] = {}
    for (operation_key, _), definition_id in write_ids.items():
        writes_by_action.setdefault(operation_key, []).append(definition_id)
    entry_ids = {
        definition.span: ordinal
        for ordinal, definition in enumerate(raw_definitions)
        if definition.kind is MemoryDefinitionKind.ENTRY
    }

    pool = _DefinitionSetPool()
    entry_state = _entry_state(partition, entry_ids, pool)
    blocks = {block.key: block for block in unit.blocks}
    in_states, out_states = _dense_states(
        unit, partition, write_ids, entry_state, pool, compress_chains=compress_chains
    )

    action_keys = sorted(
        action.operation_key for block in unit.blocks for action in block.actions
    )
    action_ids = {key: ordinal for ordinal, key in enumerate(action_keys)}
    join_sources: dict[MemoryDefinition, _IdSet] = {}
    pending_reads = []

    for block_key in sorted(blocks):
        block = blocks[block_key]
        state = in_states[block_key]
        for action in block.actions:
            for read_ordinal, read_span in enumerate(action.reads):
                start, stop = partition.covered_range(read_span)
                fragments = _read_fragments(state, start, stop, partition.atoms)
                for fragment_span, definitions in fragments:
                    if len(definitions) < 2:
                        continue
                    join = MemoryDefinition(
                        MemoryDefinitionKind.JOIN,
                        fragment_span,
                        block_key=block_key,
                    )
                    previous = join_sources.setdefault(join, definitions)
                    if previous != definitions:
                        raise AssertionError(
                            "one final JOIN identity has conflicting inputs"
                        )
                pending_reads.append(
                    (
                        block_key,
                        action_ids[action.operation_key],
                        read_ordinal,
                        read_span,
                        fragments,
                    )
                )
            state = _apply_writes(state, action, partition, write_ids, pool)

    definitions = tuple(
        sorted((*raw_definitions, *join_sources), key=lambda item: item.canonical_key)
    )
    definition_ids = {
        definition: ordinal for ordinal, definition in enumerate(definitions)
    }
    joins = tuple(
        sorted(
            (
                MemoryJoinInput(
                    definition_ids[join],
                    tuple(
                        sorted(
                            definition_ids[raw_definitions[source]]
                            for source in sources
                        )
                    ),
                )
                for join, sources in join_sources.items()
            ),
            key=lambda item: item.join_definition_id,
        )
    )

    reads: list[MemoryReadResolution] = []
    for block_key, action_id, read_ordinal, span, fragments in pending_reads:
        result_fragments: list[MemoryReadFragment] = []
        for fragment_span, sources in fragments:
            if len(sources) == 1:
                definition_id = definition_ids[raw_definitions[next(iter(sources))]]
            else:
                join = MemoryDefinition(
                    MemoryDefinitionKind.JOIN,
                    fragment_span,
                    block_key=block_key,
                )
                definition_id = definition_ids[join]
            result_fragments.append(
                MemoryReadFragment(fragment_span, (definition_id,))
            )
        reads.append(
            MemoryReadResolution(
                action_id,
                read_ordinal,
                span,
                tuple(
                    sorted(
                        result_fragments,
                        key=lambda item: item.span.canonical_key,
                    )
                ),
            )
        )

    actions = tuple(
        MemoryActionResult(
            key,
            tuple(
                sorted(
                    definition_ids[raw_definitions[raw_id]]
                    for raw_id in writes_by_action.get(key, ())
                )
            ),
        )
        for key in action_keys
    )
    unresolved_reads: list[MemoryUnresolvedOccurrence] = []
    unresolved_writes: list[MemoryUnresolvedOccurrence] = []
    for block in unit.blocks:
        for action in block.actions:
            action_id = action_ids[action.operation_key]
            unresolved_reads.extend(
                MemoryUnresolvedOccurrence(action_id, ordinal, access)
                for ordinal, access in enumerate(action.unresolved_reads)
            )
            unresolved_writes.extend(
                MemoryUnresolvedOccurrence(action_id, ordinal, access)
                for ordinal, access in enumerate(action.unresolved_writes)
            )

    raw_to_final = tuple(definition_ids[item] for item in raw_definitions)
    state_nodes, terminal_states = _serialize_terminal_states(
        unit.observed_terminal_block_keys,
        out_states,
        raw_to_final,
        definitions,
    )

    return LocalMemorySsaResult(
        LOCAL_MEMORY_CONTRACT_VERSION,
        unit.function_scope,
        unit.canonical_digest,
        partition.atoms,
        actions,
        definitions,
        joins,
        tuple(sorted(reads, key=lambda item: (item.action_id, item.read_ordinal))),
        tuple(
            sorted(
                unresolved_reads,
                key=lambda item: (item.action_id, item.occurrence_ordinal),
            )
        ),
        tuple(
            sorted(
                unresolved_writes,
                key=lambda item: (item.action_id, item.occurrence_ordinal),
            )
        ),
        state_nodes,
        terminal_states,
    )


register_memory_ssa_engine("dense", _build_dense)
register_memory_ssa_engine(
    "dense-unchained", lambda unit: _build_dense(unit, compress_chains=False)
)


def _serialize_terminal_states(
    terminal_keys: tuple[str, ...],
    out_states: dict[str, _State],
    raw_to_final: tuple[int, ...],
    definitions: tuple[MemoryDefinition, ...],
) -> tuple[tuple[MemoryStateNode, ...], tuple[ObservedTerminalMemoryState, ...]]:
    nodes: list[MemoryStateNode] = []
    interned: dict[tuple[object, ...], int] = {}
    encoded: dict[int, int] = {}
    terminal_states: list[ObservedTerminalMemoryState] = []
    canonical_roots = []  # keeps rebuilt trees alive: ``encoded`` is keyed by id()

    for block_key in terminal_keys:
        root = out_states[block_key].root
        if root is None:
            terminal_states.append(ObservedTerminalMemoryState(block_key, None))
            continue
        # Serialize a canonical shape: the balanced tree rebuilt from the run
        # sequence, so the nodes depend only on the state's content and not on
        # the order of the operations (solver strategy) that produced it.
        root = _make_state(_iter_runs(root)).root
        canonical_roots.append(root)

        stack = [(root, False)]
        while stack:
            node, expanded = stack.pop()
            identity = id(node)
            if identity in encoded:
                continue
            if not expanded:
                stack.append((node, True))
                if node.right is not None and id(node.right) not in encoded:
                    stack.append((node.right, False))
                if node.left is not None and id(node.left) not in encoded:
                    stack.append((node.left, False))
                continue

            public_ids = tuple(
                raw_to_final[raw_id] for raw_id in node.run.definitions
            )
            if any(
                definitions[definition_id].kind is MemoryDefinitionKind.JOIN
                for definition_id in public_ids
            ):
                raise AssertionError("terminal states cannot contain JOIN definitions")
            key = (
                node.run.start,
                node.run.stop,
                public_ids,
                None if node.left is None else encoded[id(node.left)],
                None if node.right is None else encoded[id(node.right)],
            )
            node_id = interned.get(key)
            if node_id is None:
                node_id = len(nodes)
                nodes.append(MemoryStateNode(*key))
                interned[key] = node_id
            encoded[identity] = node_id

        terminal_states.append(
            ObservedTerminalMemoryState(block_key, encoded[id(root)])
        )

    return tuple(nodes), tuple(terminal_states)


def _object_key(object_id: StorageObjectId) -> tuple[object, ...]:
    return (
        object_id.kind.value,
        object_id.scope.kind.value,
        object_id.scope.digest,
        object_id.space_key,
    )


def _build_partition(unit: LocalMemoryUnit) -> _Partition:
    events: dict[StorageObjectId, dict[int, int]] = {}
    for block in unit.blocks:
        for action in block.actions:
            for span in (*action.reads, *action.writes):
                object_events = events.setdefault(span.object_id, {})
                object_events[span.start] = object_events.get(span.start, 0) + 1
                object_events[span.end] = object_events.get(span.end, 0) - 1

    atoms: list[ByteSpan] = []
    connected: list[ByteSpan] = []
    by_object: dict[StorageObjectId, _ObjectAtoms] = {}
    for object_id in sorted(events, key=_object_key):
        points = sorted(events[object_id])
        active = 0
        object_atoms: list[ByteSpan] = []
        for ordinal, point in enumerate(points[:-1]):
            active += events[object_id][point]
            next_point = points[ordinal + 1]
            if active:
                object_atoms.append(ByteSpan(object_id, point, next_point - point))
        offset = len(atoms)
        atoms.extend(object_atoms)
        by_object[object_id] = _ObjectAtoms(
            offset, tuple(atom.start for atom in object_atoms), tuple(object_atoms)
        )
        for atom in object_atoms:
            if (
                connected
                and connected[-1].object_id == object_id
                and connected[-1].end == atom.start
            ):
                previous = connected[-1]
                connected[-1] = ByteSpan(
                    object_id, previous.start, atom.end - previous.start
                )
            else:
                connected.append(atom)
    return _Partition(tuple(atoms), tuple(connected), by_object)


def _raw_definitions(
    unit: LocalMemoryUnit, connected: tuple[ByteSpan, ...]
) -> tuple[MemoryDefinition, ...]:
    definitions = [
        MemoryDefinition(
            MemoryDefinitionKind.ENTRY,
            span,
            block_key=unit.entry_block_key,
        )
        for span in connected
    ]
    for block in unit.blocks:
        for action in block.actions:
            kind = (
                MemoryDefinitionKind.DATA_WRITE
                if action.write_mode is MemoryWriteMode.DATA
                else MemoryDefinitionKind.KILL
            )
            definitions.extend(
                MemoryDefinition(
                    kind,
                    span,
                    operation_key=action.operation_key,
                    write_ordinal=ordinal,
                )
                for ordinal, span in enumerate(action.writes)
            )
    return tuple(sorted(definitions, key=lambda item: item.canonical_key))


def _entry_state(
    partition: _Partition,
    entry_ids: dict[ByteSpan, int],
    pool: _DefinitionSetPool,
) -> _State:
    runs = []
    for span in partition.connected:
        start, stop = partition.covered_range(span)
        runs.append(_Run(start, stop, pool.intern((entry_ids[span],))))
    return _make_state(runs)


def _apply_writes(state, action, partition, write_ids, pool) -> _State:
    for ordinal, span in enumerate(action.writes):
        start, stop = partition.covered_range(span)
        state = _replace(
            state,
            start,
            stop,
            pool.intern((write_ids[(action.operation_key, ordinal)],)),
        )
    return state


def _compile_transfer(block, partition, write_ids, pool) -> _State:
    state = _EMPTY_STATE
    for action in block.actions:
        state = _apply_writes(state, action, partition, write_ids, pool)
    return state


def _read_fragments(
    state: _State, start: int, stop: int, atoms: tuple[ByteSpan, ...]
) -> tuple[tuple[ByteSpan, _IdSet], ...]:
    fragments: list[tuple[ByteSpan, _IdSet]] = []
    cursor = start
    for run in _iter_runs_from(state.root, start):
        if cursor >= stop or run.start >= stop:
            break
        fragment_start = max(cursor, run.start)
        fragment_stop = min(stop, run.stop)
        if fragment_start != cursor:
            raise AssertionError("concrete read reached an empty raw state")
        first_atom = atoms[fragment_start]
        last_atom = atoms[fragment_stop - 1]
        span = ByteSpan(
            first_atom.object_id,
            first_atom.start,
            last_atom.end - first_atom.start,
        )
        fragments.append((span, run.definitions))
        cursor = fragment_stop
    if cursor != stop:
        raise AssertionError("concrete read reached an empty raw state")
    return tuple(fragments)
