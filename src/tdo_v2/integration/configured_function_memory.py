"""Byte-range memory behavior for one configured function view."""

from __future__ import annotations

from typing import Callable

from .._scope_contracts import ValidatedVarnode, VarnodeKindCode
from ..call_seeds import _operation_key
from ..memory_contracts import MemoryDefinition, MemoryDefinitionKind
from ..model import ByteSpan, ResolvedStorage, StorageObjectId, StorageObjectKind
from ..relative_memory import _function_relative_object_id
from ..storage import _resolve_validated_storage
from .configured_interprocedural_records import PointerPath as _PointerPath
from .configured_memory_projection import definition_ids_covering_span as _definition_ids_covering_span
from .configured_value_domain import (
    compose_pointer_path as _compose_pointer_path,
    pointer_path_head as _pointer_path_head,
    storage_ref as _storage_ref,
)

class _FunctionMemoryViewMixin:
    def effective_access_span(
        self,
        operation_key: str,
        fallback: ByteSpan,
        *,
        read: bool,
    ) -> ByteSpan | None:
        """Prefer one unambiguous typed coordinate over a reconstructed span."""
        exact = getattr(
            self,
            "operation_exact_read_spans" if read else "operation_exact_write_spans",
            {},
        ).get(operation_key)
        if exact is None:
            return fallback
        if exact.size != fallback.size:
            return None
        if (
            fallback.object_id.kind is StorageObjectKind.ADDRESS_SPACE
            and fallback != exact
        ):
            return None
        return exact

    def definition_access_spans(
        self,
        definition: MemoryDefinition,
    ) -> tuple[ByteSpan, ...]:
        """Expose raw and exact aliases only when their relation is unambiguous."""
        if definition.operation_key is None:
            return (definition.span,)
        exact = getattr(self, "operation_exact_write_spans", {}).get(
            definition.operation_key
        )
        effective = self.effective_access_span(
            definition.operation_key,
            definition.span,
            read=False,
        )
        if effective is None:
            return ()
        if exact is None or effective == definition.span:
            return (effective,)
        return tuple(
            sorted(
                {definition.span, effective},
                key=lambda item: item.canonical_key,
            )
        )

    def definition_for_input(
        self, operation_key: str, varnode: ValidatedVarnode
    ) -> tuple[int, ByteSpan] | None:
        resolved = _resolve_validated_storage(
            _storage_ref(varnode),
            self.analysis.evidence.unit.scopes.resolution_context,
        )
        if type(resolved) is not ResolvedStorage:
            return None
        definition_id = self.definition_for_span(operation_key, resolved.span)
        if definition_id is None:
            return None
        return definition_id, resolved.span

    def definition_for_span(
        self, operation_key: str, span: ByteSpan
    ) -> int | None:
        action_id = self.action_ids.get(operation_key)
        if action_id is None:
            return None
        reads = tuple(
            read
            for read in self.memory.reads
            if read.action_id == action_id and read.span == span
        )
        if len(reads) != 1 or len(reads[0].fragments) != 1:
            return None
        fragment = reads[0].fragments[0]
        if fragment.span != span or len(fragment.definition_ids) != 1:
            return None
        return fragment.definition_ids[0]

    def materialize_path(
        self,
        path: _PointerPath,
        *,
        before_position: int,
        target_size: int,
        address_space_id: int,
    ) -> ByteSpan | None:
        current = _PointerPath(
            path.anchor_definition_id,
            path.anchor_byte_offset,
            path.offsets,
            path.byte_size,
            address_space_id,
        )
        while len(current.offsets) > 1:
            pointer_span = self._direct_span(
                _pointer_path_head(current), current.byte_size, address_space_id
            )
            if pointer_span is None:
                return None
            definition = self._latest_definition(pointer_span, before_position)
            if definition is None:
                return None
            loaded = self.pointer_for_definition(definition, pointer_span)
            if loaded is None:
                return None
            remaining = current.offsets[1:]
            current = _compose_pointer_path(loaded, remaining, address_space_id)
        return self._direct_span(current, target_size, address_space_id)

    def resolve_local_pointer_prefix(
        self,
        path: _PointerPath,
        *,
        before_position: int,
        address_space_id: int,
    ) -> _PointerPath:
        """Consume only dereferences proven by earlier local SSA writes."""
        current = _PointerPath(
            path.anchor_definition_id,
            path.anchor_byte_offset,
            path.offsets,
            path.byte_size,
            address_space_id,
        )
        while len(current.offsets) > 1:
            pointer_span = self._direct_span(
                _pointer_path_head(current), current.byte_size, address_space_id
            )
            if pointer_span is None:
                break
            definition = self._latest_definition(pointer_span, before_position)
            if definition is None:
                break
            loaded = self.pointer_for_definition(definition, pointer_span)
            if loaded is None:
                break
            current = _compose_pointer_path(
                loaded, current.offsets[1:], address_space_id
            )
        return current

    def _direct_span(
        self, path: _PointerPath, target_size: int, address_space_id: int
    ) -> ByteSpan | None:
        if len(path.offsets) != 1:
            return None
        bits = self.space_bits.get(address_space_id)
        if bits is None:
            return None
        anchor = self.memory.definitions[path.anchor_definition_id]
        if anchor.kind is not MemoryDefinitionKind.ENTRY:
            return None
        object_id = self._relative_object(
            path.anchor_definition_id,
            path.anchor_byte_offset,
            path.byte_size,
            address_space_id,
            path.offsets[0],
        )
        if object_id is None:
            return None
        start = (1 << bits) + path.offsets[0]
        if start < 0:
            return None
        return ByteSpan(object_id, start, target_size)

    def _relative_object(
        self,
        anchor_definition_id: int,
        anchor_byte_offset: int,
        anchor_byte_size: int,
        address_space_id: int,
        displacement: int,
    ) -> StorageObjectId | None:
        key = (
            anchor_definition_id,
            anchor_byte_offset,
            anchor_byte_size,
            address_space_id,
            displacement,
        )
        cached = self._relative_object_cache.get(key)
        if cached is not None:
            return cached
        candidates = set()
        for operation_key, (_, operation) in self.operations.items():
            if operation.opcode not in {"LOAD", "STORE"} or len(operation.inputs) < 2:
                continue
            selector = operation.inputs[0]
            if (
                selector.kind is not VarnodeKindCode.CONSTANT
                or selector.coordinate.byte_offset != address_space_id
            ):
                continue
            paths = self.pointer_candidates_for_input(
                operation_key, operation.inputs[1]
            )
            if not any(
                len(path.offsets) == 1
                and path.anchor_definition_id == anchor_definition_id
                and path.anchor_byte_offset == anchor_byte_offset
                and path.offsets[0] == displacement
                for path in paths
            ):
                continue
            width = (
                operation.output.byte_size
                if operation.opcode == "LOAD" and operation.output is not None
                else operation.inputs[2].byte_size
                if operation.opcode == "STORE" and len(operation.inputs) == 3
                else None
            )
            if width is None:
                continue
            span = self._relative_access_span(
                operation_key,
                read=operation.opcode == "LOAD",
                byte_size=width,
            )
            if span is not None:
                candidates.add(span.object_id)
        anchor = self.memory.definitions[anchor_definition_id]
        if (
            anchor.kind is not MemoryDefinitionKind.ENTRY
            or anchor_byte_offset < 0
            or anchor_byte_size <= 0
            or anchor_byte_offset + anchor_byte_size > anchor.span.size
        ):
            return None
        anchor_span = ByteSpan(
            anchor.span.object_id,
            anchor.span.start + anchor_byte_offset,
            anchor_byte_size,
        )
        derived = _function_relative_object_id(
            self.memory.function_scope,
            anchor_span,
            address_space_id,
        )
        result = derived if not candidates or candidates == {derived} else None
        if result is not None:
            self._relative_object_cache[key] = result
        return result

    def _relative_access_span(
        self, operation_key: str, *, read: bool, byte_size: int
    ) -> ByteSpan | None:
        action = self.storage_actions.get(operation_key)
        if action is None:
            return None
        spans = action.reads if read else action.writes
        candidates = tuple(
            span
            for span in spans
            if span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE
            and span.size == byte_size
        )
        return candidates[0] if len(candidates) == 1 else None

    def _latest_definition(
        self, span: ByteSpan, before_position: int
    ) -> int | None:
        row = self.latest_definition(span, before_position)
        return None if row is None else row[1]

    def latest_definition(
        self, span: ByteSpan, before_position: int
    ) -> tuple[int, int] | None:
        before_key = next(
            (
                operation_key
                for operation_key, (position, _) in self.operations.items()
                if position == before_position
            ),
            None,
        )
        if before_key is None:
            return None
        candidates = []
        for definition_id, definition in enumerate(self.memory.definitions):
            if (
                definition.kind is not MemoryDefinitionKind.DATA_WRITE
                or not any(
                    candidate.contains(span)
                    for candidate in self.definition_access_spans(definition)
                )
            ):
                continue
            position = self.position(definition.operation_key)
            if (
                position is not None
                and self.definitely_precedes(definition.operation_key, before_key)
            ):
                candidates.append((position, definition_id, definition.operation_key))
        if not candidates:
            return None
        latest = tuple(
            row
            for row in candidates
            if not any(
                row[2] != other[2]
                and self.definitely_precedes(row[2], other[2])
                for other in candidates
            )
        )
        return (latest[0][0], latest[0][1]) if len(latest) == 1 else None

    def state_definition(self, span: ByteSpan, before_position: int) -> int | None:
        """Return the one observed definition holding a span before a call."""
        local = self.latest_definition(span, before_position)
        if local is not None:
            return local[1]
        before_key = next(
            (
                operation_key
                for operation_key, (position, _) in self.operations.items()
                if position == before_position
            ),
            None,
        )
        if before_key is None:
            return None
        if any(
            definition.kind is MemoryDefinitionKind.DATA_WRITE
            and definition.operation_key is not None
            and any(
                candidate.contains(span)
                for candidate in self.definition_access_spans(definition)
            )
            and self.may_precede(definition.operation_key, before_key)
            for definition in self.memory.definitions
        ):
            return None
        entries = tuple(
            definition_id
            for definition_id, definition in enumerate(self.memory.definitions)
            if definition.kind is MemoryDefinitionKind.ENTRY
            and definition.span.contains(span)
        )
        return entries[0] if len(entries) == 1 else None

    def source_origin_definition_ids(
        self, physical_spans: tuple[ByteSpan, ...]
    ) -> tuple[int, ...]:
        """Find terminal definitions for explicitly selected physical bytes."""
        if not physical_spans:
            return ()
        states = self.memory.observed_terminal_states
        if not states or any(state.root_node_id is None for state in states):
            return ()
        terminal_maps = tuple(
            self._terminal_definition_map(state.root_node_id) for state in states
        )
        result = set()
        for requested in physical_spans:
            definition_ids = tuple(
                _definition_ids_covering_span(mapping, requested)
                for mapping in terminal_maps
            )
            if (
                not definition_ids
                or not definition_ids[0]
                or any(item != definition_ids[0] for item in definition_ids[1:])
            ):
                return ()
            if any(
                self.memory.definitions[definition_id].kind
                is not MemoryDefinitionKind.DATA_WRITE
                or not self.memory.definitions[definition_id].span.contains(requested)
                for definition_id in definition_ids[0]
            ):
                return ()
            result.update(definition_ids[0])
        return tuple(sorted(result))

    def terminal_data_writes(self) -> tuple[tuple[int, ByteSpan], ...]:
        """Return terminal writes shared exactly by every observed exit."""
        rows = []
        for definition_id, span in self._shared_terminal_writes():
            definition = self.memory.definitions[definition_id]
            effective = self.effective_access_span(
                definition.operation_key,
                span,
                read=False,
            )
            if effective is not None and effective.object_id.kind in (
                StorageObjectKind.REGISTER_FILE,
                StorageObjectKind.ADDRESS_SPACE,
            ):
                rows.append((definition_id, effective))
        return tuple(
            sorted(set(rows), key=lambda item: (item[1].canonical_key, item[0]))
        )

    def terminal_data_write_cover(self, definition_id: int, requested_span: ByteSpan, *,
                                  charge: Callable[[int], None]) -> tuple[
                                      tuple[str, int, tuple[tuple[int, ByteSpan, tuple[int, ...]], ...]], ...] | None:
        """Derive complete native terminal ownership for one actual raw output.

        This demand-specific receipt neither modifies terminal discovery nor
        establishes source DATA. Budget failures deliberately propagate.
        """
        if type(definition_id) is not int or type(requested_span) is not ByteSpan or not callable(charge):
            raise TypeError("terminal cover requires exact definition/span and a charge callback")
        charge(1)
        memory = self.memory
        exits, atoms, nodes = memory.observed_terminal_states, memory.atomic_spans, memory.state_nodes
        if (not exits or len(exits) > 32 or not atoms or len(atoms) > 4096
                or not nodes or len(nodes) > 8192 or not 0 <= definition_id < len(memory.definitions)
                or requested_span.object_id.kind is not StorageObjectKind.REGISTER_FILE
                or not 0 < requested_span.size <= 64):
            return None
        memberships = 0
        for node in nodes:
            charge(1)
            memberships += len(node.definition_ids)
            if memberships > 8192 or not node.definition_ids:
                return None
            charge(len(node.definition_ids))
            if any(type(item) is not int or not 0 <= item < len(memory.definitions) for item in node.definition_ids):
                return None
        definition = memory.definitions[definition_id]
        operation = self.operation(definition.operation_key)
        if (definition.kind is not MemoryDefinitionKind.DATA_WRITE or operation is None
                or operation.output is None or definition.span != requested_span):
            return None
        raw = _resolve_validated_storage(_storage_ref(operation.output),
                                         self.analysis.evidence.unit.scopes.resolution_context)
        if type(raw) is not ResolvedStorage or raw.span != requested_span:
            return None
        actions = []
        for index, action in enumerate(memory.actions):
            charge(1)
            if action.operation_key == definition.operation_key:
                actions.append(index)
        if len(actions) != 1 or definition_id not in memory.actions[actions[0]].write_definition_ids:
            return None
        effect = self.storage_actions.get(definition.operation_key)
        if effect is None or requested_span not in effect.writes or effect.unresolved_writes:
            return None
        returns = {}
        for instruction in self.observation.instructions:
            charge(1)
            terminal = instruction.flow is not None and instruction.flow.is_terminal
            if terminal and (not instruction.operations or instruction.operations[-1].opcode != "RETURN"):
                return None
            if (instruction.flow is None or instruction.flow.is_computed
                    and not instruction.flow.is_call and not instruction.flow_targets):
                return None
            for ordinal, operation in enumerate(instruction.operations):
                charge(1)
                if operation.opcode == "RETURN":
                    key = _operation_key(instruction.address, ordinal, operation.opcode)
                    block = self.operation_blocks.get(key)
                    if not terminal or ordinal != len(instruction.operations) - 1 or block is None or block in returns:
                        return None
                    returns[block] = key
        if len(returns) != len(exits):
            return None
        selected, cursor = [], requested_span.start
        charge(len(atoms))
        for atom_id, atom in enumerate(atoms):
            if atom.overlaps(requested_span):
                if not requested_span.contains(atom):
                    return None
                selected.append((atom_id, atom))
        for _, atom in sorted(selected, key=lambda row: row[1].start):
            charge(1)
            if atom.start != cursor:
                return None
            cursor = atom.end
        if cursor != requested_span.end:
            return None
        result, seen_blocks = [], set()
        for exit in exits:
            charge(1)
            root = exit.root_node_id
            if (exit.block_key not in returns or exit.block_key in seen_blocks
                    or type(root) is not int or not 0 <= root < len(nodes)):
                return None
            seen_blocks.add(exit.block_key)
            owners, seen, pending = {}, set(), [root]
            while pending:
                node_id = pending.pop()
                charge(1)
                if type(node_id) is not int or not 0 <= node_id < len(nodes) or node_id in seen:
                    return None
                seen.add(node_id)
                node = nodes[node_id]
                if (type(node.start_atom) is not int or type(node.stop_atom) is not int
                        or not 0 <= node.start_atom < node.stop_atom <= len(atoms)):
                    return None
                charge(len(node.definition_ids))
                for atom_id in range(node.start_atom, node.stop_atom):
                    charge(1)
                    if atom_id in owners:
                        return None
                    owners[atom_id] = node.definition_ids
                for child in (node.left_node_id, node.right_node_id):
                    if child is not None:
                        pending.append(child)
            if len(owners) != len(atoms):
                return None
            receipt = []
            for atom_id, atom in selected:
                charge(1)
                if owners.get(atom_id) != (definition_id,):
                    return None
                receipt.append((atom_id, atom, (definition_id,)))
            charge(1)
            result.append((exit.block_key, root, tuple(receipt)))
        charge(len(result))
        return tuple(sorted(result, key=lambda row: row[0]))

    def terminal_coordinate_writes(self) -> tuple[tuple[int, ByteSpan], ...]:
        """Return exact program coordinates written on every observed exit."""
        return tuple(
            row
            for row in self.terminal_data_writes()
            if row[1].object_id.kind is StorageObjectKind.ADDRESS_SPACE
        )

    def _shared_terminal_writes(self) -> tuple[tuple[int, ByteSpan], ...]:
        states = self.memory.observed_terminal_states
        if not states or any(state.root_node_id is None for state in states):
            return ()
        terminal_maps = tuple(
            self._terminal_definition_map(state.root_node_id) for state in states
        )
        first = terminal_maps[0]
        rows = []
        for span, definition_ids in first.items():
            if any(mapping.get(span) != definition_ids for mapping in terminal_maps[1:]):
                continue
            rows.extend(
                (definition_id, span)
                for definition_id in definition_ids
                if self.memory.definitions[definition_id].kind
                is MemoryDefinitionKind.DATA_WRITE
            )
        return tuple(
            sorted(set(rows), key=lambda item: (item[1].canonical_key, item[0]))
        )

    def physical_read_spans_after(
        self, operation_key: str, written_span: ByteSpan
    ) -> tuple[ByteSpan, ...]:
        """Return later exact physical reads contained in a callee write."""
        result = set()
        for read in self.memory.reads:
            read_key = self.memory.actions[read.action_id].operation_key
            if not self.definitely_precedes(operation_key, read_key):
                continue
            for fragment in read.fragments:
                if (
                    not written_span.contains(fragment.span)
                    or len(fragment.definition_ids) != 1
                ):
                    continue
                result.add(fragment.span)
        return tuple(sorted(result, key=lambda item: item.canonical_key))

    def terminal_transfer_spans(
        self, operation_key: str, terminal_span: ByteSpan
    ) -> tuple[ByteSpan, ...]:
        """Keep an exact terminal write even when the caller never rereads it."""
        if terminal_span.object_id.kind is not StorageObjectKind.REGISTER_FILE:
            return (terminal_span,)
        result = {terminal_span}
        result.update(self.physical_read_spans_after(operation_key, terminal_span))
        return tuple(sorted(result, key=lambda item: item.canonical_key))

    def _terminal_definition_map(self, root_node_id: int) -> dict[ByteSpan, tuple[int, ...]]:
        result = {}
        pending = [root_node_id]
        while pending:
            node = self.memory.state_nodes[pending.pop()]
            for atom in range(node.start_atom, node.stop_atom):
                result[self.memory.atomic_spans[atom]] = node.definition_ids
            pending.extend(
                child
                for child in (node.left_node_id, node.right_node_id)
                if child is not None
            )
        return result


__all__ = ["_FunctionMemoryViewMixin"]
