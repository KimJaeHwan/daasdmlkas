"""Bounded observed indirect STORE/LOAD equality for a diagnostic graph only.

The certificate uses exact SSA definitions for address equality and a separate
may-value offset bound for self-alias exclusion. Failure means unknown, not
absence of a memory dependence.
"""

from __future__ import annotations

from ..call_contracts import DirectCallTarget
from ..call_seeds import _operation_key
from .._scope_contracts import VarnodeKindCode
from ..memory_contracts import MemoryDefinitionKind
from ..model import StorageObjectKind
from ..scope_identity import ConstructedProgramScope, TranslationNamespace
from .._scope_wire import _derive_program_scope
from .configured_call_byte_explanation import _observed_predecessors, _site
from .configured_function_view import _FunctionView
from .configured_interprocedural_contracts import ObservedDynamicAliasReplacement
from .configured_recursive_frame_inventory import build_recursive_frame_inventory


MAX_ALIAS_INSTRUCTIONS = 4096
MAX_ALIAS_PAIRS = 4096
MAX_EXPRESSION_DEPTH = 64
MAX_OFFSET_VALUES = 32
MAX_STRAIGHT_INSTRUCTIONS = 64
_MEMORY_KINDS = frozenset((
    StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE,
))
_COMMUTATIVE = frozenset(("INT_ADD", "INT_MULT", "INT_AND", "INT_OR", "INT_XOR"))


class _AddressResolver:
    def __init__(self, view: _FunctionView, views=None, allowed_store=None) -> None:
        self.view = view
        self.views = views
        self.allowed_store = allowed_store
        self.active: set[tuple[object, ...]] = set()

    def _guard(self, key, depth):
        if depth > MAX_EXPRESSION_DEPTH or key in self.active:
            return False
        self.active.add(key)
        return True

    def _data_read(self, operation_key: str, width: int):
        action_id = self.view.action_ids.get(operation_key)
        if action_id is None:
            return None
        rows = tuple(
            read for read in self.view.memory.reads
            if read.action_id == action_id
            and read.span.object_id.kind in _MEMORY_KINDS
            and read.span.size == width
            and len(read.fragments) == 1
            and read.fragments[0].span == read.span
        )
        if len(rows) != 1 or not self._stable_data_read(operation_key, rows[0]):
            return None
        return rows[0]

    def _stable_data_read(self, operation_key, read):
        definition_id = read.fragments[0].definition_ids[0]
        definition = self.view.memory.definitions[definition_id]
        if (definition.kind is not MemoryDefinitionKind.DATA_WRITE
                or definition.operation_key is None):
            return False
        between = _linear_between(self.view, definition.operation_key, operation_key)
        if between is None:
            return False
        for key in between:
            operation = self.view.operation(key)
            if operation.opcode == "CALL":
                if not self._call_preserves_read(key, operation_key, read.span):
                    return False
            elif operation.opcode in ("CALLIND", "CALLOTHER"):
                return False
            action = self.view.storage_actions.get(key)
            if action is None:
                if not self._safe_call_preparation(key, operation_key, read.span, between):
                    return False
                continue
            if action.unresolved_writes and key != self.allowed_store:
                return False
            for written in action.writes:
                if written.object_id.kind in (
                    StorageObjectKind.REGISTER_FILE,
                    StorageObjectKind.FUNCTION_UNIQUE,
                ):
                    continue
                if (written.object_id != read.span.object_id
                        or written.overlaps(read.span)):
                    return False
        return True

    def _safe_call_preparation(self, key, read_key, protected_span, between):
        site = _site(self.view, key)
        if site is None:
            return False
        instruction, ordinal = site
        calls = tuple(
            _operation_key(instruction.address, index, operation.opcode)
            for index, operation in enumerate(instruction.operations)
            if operation.opcode == "CALL"
        )
        if (len(calls) != 1 or calls[0] not in between
                or ordinal >= len(instruction.operations) - 1
                or not self._call_preserves_read(calls[0], read_key, protected_span)):
            return False
        operation = instruction.operations[ordinal]
        if operation.opcode == "STORE":
            inventory = build_recursive_frame_inventory(self.view.analysis)
            return any(token.call_operation_key == calls[0]
                       and token.store_operation_key == key
                       for token in inventory.call_tokens)
        if operation.output is None:
            return False
        if operation.output.kind is not VarnodeKindCode.REGISTER:
            return True
        registers = _pointer_register_spans(
            self.view, read_key, self.view.operation(read_key).inputs[1]
        )
        if registers is None:
            return False
        start = operation.output.coordinate.byte_offset
        stop = start + operation.output.byte_size
        return all(stop <= span.start or span.end <= start for span in registers)

    def _call_preserves_read(self, call_key, read_key, protected_span):
        if self.views is None or protected_span.object_id.kind is not StorageObjectKind.FUNCTION_RELATIVE:
            return False
        targets = self.view.operation_flow_targets.get(call_key, ())
        if len(targets) != 1:
            return False
        callee = self.views.get(targets[0])
        if type(callee) is not _FunctionView:
            return False
        seeds = tuple(seed for seed in self.view.analysis.evidence.seeds.callsites
                      if seed.operation_key == call_key)
        if (len(seeds) != 1 or type(seeds[0].target) is not DirectCallTarget
                or seeds[0].target.coordinate != callee.analysis.entry):
            return False
        caller_inventory = build_recursive_frame_inventory(self.view.analysis)
        callee_inventory = build_recursive_frame_inventory(callee.analysis)
        if not callee_inventory.complete or callee_inventory.call_tokens:
            return False
        tokens = tuple(row for row in caller_inventory.call_tokens
                       if row.call_operation_key == call_key)
        accesses = tuple(row for row in caller_inventory.accesses
                         if row.operation_key == read_key and row.opcode == "LOAD")
        if len(tokens) != 1 or len(accesses) != 1 or accesses[0].interval is None:
            return False
        token, protected = tokens[0].interval, accesses[0].interval
        if (token.anchor_definition_id != protected.anchor_definition_id
                or token.anchor_span != protected.anchor_span
                or token.address_space_id != protected.address_space_id
                or protected.byte_size != protected_span.size
                or any(abs(value) >= (1 << 31) for value in (
                    token.offset, token.stop, protected.offset, protected.stop,
                ))):
            return False
        for access in callee_inventory.accesses:
            if access.opcode != "STORE":
                continue
            interval = access.interval
            if (interval is None
                    or interval.address_space_id != protected.address_space_id
                    or abs(interval.offset) >= (1 << 31)
                    or abs(interval.stop) >= (1 << 31)):
                return False
            start = token.offset + interval.offset
            if start < protected.stop and protected.offset < start + interval.byte_size:
                return False
        pointer = self.view.operation(read_key).inputs[1]
        registers = _pointer_register_spans(self.view, read_key, pointer)
        return registers is not None and all(
            _callee_preserves_register(callee, span) for span in registers
        )

    def signature(self, key, varnode, depth=0):
        if varnode.kind in (VarnodeKindCode.CONSTANT, VarnodeKindCode.ADDRESS):
            return (("literal", varnode.kind.value, varnode.coordinate.space_id,
                     varnode.coordinate.byte_offset, varnode.byte_size), frozenset())
        resolved = self.view.definition_for_input(key, varnode)
        if resolved is None:
            return None
        return self._signature_definition(*resolved, depth + 1)

    def _signature_definition(self, definition_id, span, depth):
        marker = ("signature", definition_id, span.canonical_key)
        if not self._guard(marker, depth):
            return None
        try:
            definition = self.view.memory.definitions[definition_id]
            if not definition.span.contains(span):
                return None
            if definition.kind is MemoryDefinitionKind.ENTRY:
                return (("entry", definition_id, span.canonical_key), frozenset())
            if definition.kind is not MemoryDefinitionKind.DATA_WRITE:
                return None
            key = definition.operation_key
            operation = self.view.operation(key)
            if operation is None:
                return None
            if operation.opcode == "LOAD" and operation.output is not None:
                read = self._data_read(key, operation.output.byte_size)
                if read is None:
                    return None
                return (("load", read.span.canonical_key,
                         read.fragments[0].definition_ids), frozenset((key,)))
            if operation.opcode == "STORE" and len(operation.inputs) == 3:
                return self.signature(key, operation.inputs[2], depth + 1)
            if operation.opcode in ("COPY", "CAST") and len(operation.inputs) == 1:
                return self.signature(key, operation.inputs[0], depth + 1)
            if operation.opcode in ("INT_ZEXT", "INT_SEXT") and len(operation.inputs) == 1:
                child = self.signature(key, operation.inputs[0], depth + 1)
                if child is None:
                    return None
                return ((operation.opcode, span.size, child[0]), child[1])
            if operation.opcode in _COMMUTATIVE and len(operation.inputs) == 2:
                left = self.signature(key, operation.inputs[0], depth + 1)
                right = self.signature(key, operation.inputs[1], depth + 1)
                if left is None or right is None:
                    return None
                children = tuple(sorted((left[0], right[0]), key=repr))
                return ((operation.opcode, span.size, children), left[1] | right[1])
            if operation.opcode == "INT_SUB" and len(operation.inputs) == 2:
                left = self.signature(key, operation.inputs[0], depth + 1)
                right = self.signature(key, operation.inputs[1], depth + 1)
                if left is None or right is None:
                    return None
                return ((operation.opcode, span.size, left[0], right[0]),
                        left[1] | right[1])
            return None
        finally:
            self.active.remove(marker)

    def values(self, key, varnode, depth=0):
        modulus = 1 << (varnode.byte_size * 8)
        if varnode.kind in (VarnodeKindCode.CONSTANT, VarnodeKindCode.ADDRESS):
            return frozenset((varnode.coordinate.byte_offset % modulus,))
        resolved = self.view.definition_for_input(key, varnode)
        if resolved is None:
            return None
        return self._values_definition(*resolved, depth + 1)

    def _values_definition(self, definition_id, span, depth):
        definition = self.view.memory.definitions[definition_id]
        if definition.span != span:
            if (not definition.span.contains(span)
                    or definition.span.start != span.start):
                return None
            whole = self._values_definition(definition_id, definition.span, depth + 1)
            return (None if whole is None else frozenset(
                value % (1 << (span.size * 8)) for value in whole
            ))
        marker = ("values", definition_id, span.canonical_key)
        if not self._guard(marker, depth):
            return None
        try:
            if definition.kind is not MemoryDefinitionKind.DATA_WRITE:
                return None
            key = definition.operation_key
            operation = self.view.operation(key)
            if operation is None:
                return None
            opcode = operation.opcode
            if opcode == "LOAD" and operation.output is not None:
                read = self._data_read(key, operation.output.byte_size)
                return (None if read is None else self._values_definition(
                    read.fragments[0].definition_ids[0], read.span, depth + 1
                ))
            if opcode == "STORE" and len(operation.inputs) == 3:
                return self.values(key, operation.inputs[2], depth + 1)
            if opcode in ("COPY", "CAST") and len(operation.inputs) == 1:
                return self.values(key, operation.inputs[0], depth + 1)
            if opcode in ("INT_ZEXT", "INT_SEXT") and len(operation.inputs) == 1:
                source = operation.inputs[0]
                values = self.values(key, source, depth + 1)
                if values is None:
                    return None
                source_modulus = 1 << (source.byte_size * 8)
                target_modulus = 1 << (span.size * 8)
                if opcode == "INT_ZEXT":
                    return frozenset(value % source_modulus for value in values)
                sign = source_modulus >> 1
                return frozenset(((value - source_modulus if value & sign else value)
                                  % target_modulus) for value in values)
            if opcode in ("INT_AND", "INT_ADD", "INT_SUB", "INT_MULT") and len(operation.inputs) == 2:
                left = self.values(key, operation.inputs[0], depth + 1)
                right = self.values(key, operation.inputs[1], depth + 1)
                if opcode == "INT_AND" and (left is None) != (right is None):
                    known = right if left is None else left
                    if known is not None and len(known) == 1:
                        mask = next(iter(known)) % (1 << (span.size * 8))
                        if mask.bit_count() <= 4:
                            values = [0]
                            for bit in (1 << i for i in range(mask.bit_length()) if mask & (1 << i)):
                                values += [value | bit for value in values]
                            return frozenset(values)
                if left is None or right is None or len(left) * len(right) > MAX_OFFSET_VALUES:
                    return None
                arithmetic = {
                    "INT_AND": lambda a, b: a & b,
                    "INT_ADD": lambda a, b: a + b,
                    "INT_SUB": lambda a, b: a - b,
                    "INT_MULT": lambda a, b: a * b,
                }[opcode]
                result = frozenset(arithmetic(a, b) % (1 << (span.size * 8))
                                   for a in left for b in right)
                return result if len(result) <= MAX_OFFSET_VALUES else None
            return None
        finally:
            self.active.remove(marker)

    def affine(self, key, varnode, depth=0):
        """Return (symbolic base, bounded signed offsets), or unknown."""
        if depth > MAX_EXPRESSION_DEPTH or varnode.byte_size != 8:
            return None
        values = self.values(key, varnode, depth + 1)
        if values is not None and len(values) <= MAX_OFFSET_VALUES:
            modulus = 1 << 64
            offsets = frozenset(value - modulus if value >= (modulus >> 1) else value
                                for value in values)
            if all(abs(offset) < (1 << 31) for offset in offsets):
                return None, offsets
            return None
        resolved = self.view.definition_for_input(key, varnode)
        if resolved is not None:
            definition = self.view.memory.definitions[resolved[0]]
            if definition.kind is MemoryDefinitionKind.DATA_WRITE:
                operation = self.view.operation(definition.operation_key)
                if operation is not None and operation.opcode in ("COPY", "CAST"):
                    return self.affine(definition.operation_key, operation.inputs[0], depth + 1)
                if operation is not None and operation.opcode == "INT_ADD" and len(operation.inputs) == 2:
                    left = self.affine(definition.operation_key, operation.inputs[0], depth + 1)
                    right = self.affine(definition.operation_key, operation.inputs[1], depth + 1)
                    if left is None or right is None or left[0] is not None and right[0] is not None:
                        return None
                    offsets = frozenset(a + b for a in left[1] for b in right[1])
                    if (len(offsets) <= MAX_OFFSET_VALUES
                            and all(abs(value) < (1 << 31) for value in offsets)):
                        return left[0] if left[0] is not None else right[0], offsets
                    return None
        signature = self.signature(key, varnode, depth + 1)
        return None if signature is None else (signature[0], frozenset((0,)))


def _linear_between(view, first_key, last_key):
    """Return intervening raw operations on one unique fallthrough chain."""
    first_site = _site(view, first_key)
    last_site = _site(view, last_key)
    if first_site is None or last_site is None:
        return None
    first, first_ordinal = first_site
    last, last_ordinal = last_site
    by_address = {row.address: row for row in view.observation.instructions}
    current = first
    visited = set()
    between = []
    for step in range(MAX_STRAIGHT_INSTRUCTIONS):
        if current.address in visited:
            return None
        visited.add(current.address)
        start = first_ordinal + 1 if step == 0 else 0
        end = last_ordinal if current.address == last.address else len(current.operations)
        if end < start:
            return None
        between.extend(
            _operation_key(current.address, ordinal, current.operations[ordinal].opcode)
            for ordinal in range(start, end)
        )
        if current.address == last.address:
            return tuple(between)
        if (current.flow is not None and (
                current.flow.is_terminal or current.flow.is_computed
                or current.flow.is_conditional or current.flow.is_jump)):
            return None
        successor = by_address.get(current.fallthrough)
        if (successor is None or _observed_predecessors(view, successor.address)
                != (current.address,)):
            return None
        current = successor
    return None


def _pointer_register_spans(view, key, varnode, depth=0):
    """Read registers in this instruction's pointer expression, never ABI roles."""
    if depth > MAX_EXPRESSION_DEPTH:
        return None
    if varnode.kind is VarnodeKindCode.CONSTANT:
        return ()
    resolved = view.definition_for_input(key, varnode)
    if resolved is None:
        return None
    if varnode.kind is VarnodeKindCode.REGISTER:
        return (resolved[1],)
    definition = view.memory.definitions[resolved[0]]
    if definition.kind is not MemoryDefinitionKind.DATA_WRITE:
        return None
    site = _site(view, definition.operation_key)
    reader_site = _site(view, key)
    if site is None or reader_site is None or site[0].address != reader_site[0].address:
        return None
    operation = view.operation(definition.operation_key)
    if (operation is None or operation.opcode not in (
            "COPY", "CAST", "INT_ADD", "INT_SUB", "INT_MULT",
            "INT_ZEXT", "INT_SEXT")):
        return None
    result = []
    for input_value in operation.inputs:
        spans = _pointer_register_spans(view, definition.operation_key,
                                        input_value, depth + 1)
        if spans is None:
            return None
        result.extend(spans)
    return tuple(sorted(set(result), key=lambda span: span.canonical_key))


def _callee_preserves_register(callee, span):
    terminal = tuple(
        definition_id for definition_id, target in callee.terminal_data_writes()
        if target == span
    )
    if len(terminal) != 1:
        return False
    active = set()

    def trace(definition_id, requested, depth):
        marker = (definition_id, requested.canonical_key)
        if depth > MAX_EXPRESSION_DEPTH or marker in active:
            return False
        active.add(marker)
        try:
            definition = callee.memory.definitions[definition_id]
            if definition.kind is MemoryDefinitionKind.ENTRY:
                return definition.span.contains(requested) and requested == span
            if (definition.kind is not MemoryDefinitionKind.DATA_WRITE
                    or definition.span != requested):
                return False
            key = definition.operation_key
            operation = callee.operation(key)
            if operation is None:
                return False
            if operation.opcode in ("COPY", "CAST") and len(operation.inputs) == 1:
                parent = callee.definition_for_input(key, operation.inputs[0])
                return parent is not None and trace(*parent, depth + 1)
            if operation.opcode == "STORE" and len(operation.inputs) == 3:
                parent = callee.definition_for_input(key, operation.inputs[2])
                return parent is not None and trace(*parent, depth + 1)
            if operation.opcode == "LOAD" and operation.output is not None:
                action_id = callee.action_ids.get(key)
                reads = tuple(
                    read for read in callee.memory.reads
                    if read.action_id == action_id
                    and read.span.object_id.kind in _MEMORY_KINDS
                    and read.span.size == operation.output.byte_size
                    and len(read.fragments) == 1
                    and read.fragments[0].span == read.span
                )
                return (len(reads) == 1 and trace(
                    reads[0].fragments[0].definition_ids[0], reads[0].span,
                    depth + 1,
                ))
            return False
        finally:
            active.remove(marker)

    return trace(terminal[0], span, 0)


def _same_space(store, load) -> bool:
    return (
        len(store.inputs) == 3 and len(load.inputs) >= 2
        and store.inputs[0].kind is VarnodeKindCode.CONSTANT
        and load.inputs[0].kind is VarnodeKindCode.CONSTANT
        and store.inputs[0] == load.inputs[0]
    )


def _straight_continuation(view, store_key, load_key) -> bool:
    store_site = _site(view, store_key)
    load_site = _site(view, load_key)
    if store_site is None or load_site is None:
        return False
    first, store_ordinal = store_site
    last, load_ordinal = load_site
    if first.address == last.address:
        return False
    by_address = {row.address: row for row in view.observation.instructions}
    current = first
    visited = set()
    for step in range(MAX_STRAIGHT_INSTRUCTIONS):
        if current.address in visited:
            return False
        visited.add(current.address)
        start = store_ordinal + 1 if step == 0 else 0
        end = load_ordinal if current.address == last.address else len(current.operations)
        if any(operation.opcode in ("STORE", "CALL", "CALLIND", "CALLOTHER")
               for operation in current.operations[start:end]):
            return False
        if current.address == last.address:
            return True
        if (current.flow is not None and (
                current.flow.is_terminal or current.flow.is_computed
                or current.flow.is_conditional or current.flow.is_jump)):
            return False
        successor = by_address.get(current.fallthrough)
        if (successor is None or _observed_predecessors(view, successor.address)
                != (current.address,)):
            return False
        current = successor
    return False


def _disjoint_offsets(left, left_width, right, right_width) -> bool:
    return all(a + left_width <= b or b + right_width <= a
               for a in left for b in right)


def certify_dynamic_aliases(
    view: _FunctionView, reachable_nodes: frozenset[int], views=None,
) -> tuple[ObservedDynamicAliasReplacement, ...]:
    """Find only exact, bounded unresolved LOADs with a must-version STORE."""
    if type(view) is not _FunctionView or type(reachable_nodes) is not frozenset:
        raise TypeError("dynamic alias certificate requires exact view and closure")
    if (len(view.observation.instructions) > MAX_ALIAS_INSTRUCTIONS
            or len(view.memory.unresolved_reads) * len(view.memory.unresolved_writes)
            > MAX_ALIAS_PAIRS):
        return ()
    result = []
    for read, debt_node in zip(
        view.memory.unresolved_reads, view.memory_graph.unresolved_read_nodes,
        strict=True,
    ):
        load_key = view.memory.actions[read.action_id].operation_key
        load_node = view.memory_graph.action_nodes[read.action_id]
        load = view.operation(load_key)
        if (load_node not in reachable_nodes or load is None
                or load.opcode != "LOAD" or load.output is None
                or load.output.byte_size != read.access.width):
            continue
        candidates = []
        for write in view.memory.unresolved_writes:
            store_key = view.memory.actions[write.action_id].operation_key
            store = view.operation(store_key)
            if (store is None or store.opcode != "STORE"
                    or write.access.width != read.access.width
                    or store.inputs[2].byte_size != read.access.width
                    or not _same_space(store, load)
                    or not _straight_continuation(view, store_key, load_key)):
                continue
            resolver = _AddressResolver(view, views, store_key)
            load_signature = resolver.signature(load_key, load.inputs[1])
            load_affine = resolver.affine(load_key, load.inputs[1])
            if load_signature is None or load_affine is None:
                continue
            store_signature = resolver.signature(store_key, store.inputs[1])
            store_affine = resolver.affine(store_key, store.inputs[1])
            if (store_signature is None or store_signature[0] != load_signature[0]
                    or store_affine is None or store_affine != load_affine):
                continue
            for component_key in sorted(load_signature[1]):
                if view.position(component_key) <= view.position(store_key):
                    continue
                operation = view.operation(component_key)
                if operation is None or operation.opcode != "LOAD" or operation.output is None:
                    break
                address = resolver.affine(component_key, operation.inputs[1])
                if (address is None or address[0] != store_affine[0]
                        or not _disjoint_offsets(
                            store_affine[1], read.access.width,
                            address[1], operation.output.byte_size,
                        )):
                    break
            else:
                candidates.append(ObservedDynamicAliasReplacement(
                    store_key, load_key,
                    view.memory_graph.action_nodes[write.action_id], load_node,
                    debt_node, read.access.width,
                    tuple(sorted(store_affine[1])),
                ))
        if len(candidates) == 1:
            result.append(candidates[0])
    return tuple(sorted(result, key=lambda row: row.canonical_key))


def dynamic_alias_reachable_nodes(
    view: _FunctionView,
    original: frozenset[int],
    replacements: tuple[ObservedDynamicAliasReplacement, ...],
) -> frozenset[int]:
    """Add only original-graph predecessors of certified STORE nodes."""
    reached = set(original)
    pending = list(replacements)
    while pending:
        remaining = []
        changed = False
        for row in pending:
            if row.load_node not in reached:
                remaining.append(row)
                continue
            previous = len(reached)
            reached.update(view.normalized.dependencies.backward_reachable((row.store_node,)))
            changed |= len(reached) != previous
        if not changed:
            break
        pending = remaining
    return frozenset(reached)


def finite_index_transport_claim(view, edge, root_node, *, work=None, action_keys=None, reads_by_action=None):
    """Derive a bounded claim locator; this diagnostic receipt is not proof."""
    if (type(view) is not _FunctionView or type(edge) is not dict
            or edge.get("kind") != "conditional_dynamic_memory_transfer"
            or type(root_node) is not int or root_node < 0
            or len(view.memory.actions) > 2048):
        return None
    if work is None:
        work = [100000]
    def pay(amount):
        if work[0] < amount:
            return False
        work[0] -= amount
        return True
    if action_keys is None:
        if not pay(len(view.memory.actions)):
            return None
        action_keys = {node: view.memory.actions[action].operation_key
                       for action, node in enumerate(view.memory_graph.action_nodes)}
    if reads_by_action is None:
        if not pay(len(view.memory.reads)):
            return None
        reads_by_action = {}
        for read in view.memory.reads:
            if read.span.object_id.kind in _MEMORY_KINDS:
                reads_by_action.setdefault(read.action_id, []).append(read)
    store_key, load_key = action_keys.get(edge.get("source")), action_keys.get(edge.get("target"))
    store, load = view.operation(store_key), view.operation(load_key)
    if (store is None or load is None or store.opcode != "STORE"
            or load.opcode != "LOAD" or edge.get("operation_key") != load_key
            or not _same_space(store, load)):
        return None
    # Raw locators deliberately retain candidate histories across effects.
    # This is not a memory-state proof: the checker must authenticate every
    # CALL and possible alias before any retained lineage becomes authority.
    if len(view.observation.instructions) > 64 or len(view.operations) > 2048:
        return None
    operation_count = len(view.operations)
    if not pay(operation_count * (operation_count.bit_length() + 2) + 2 * len(view.observation.instructions)):
        return None
    ordered = sorted(view.operations, key=view.position)
    if not ordered or _linear_between(view, ordered[0], load_key) is None:
        return None
    state, memory, extensions = {}, {}, {}
    namespace_checked = None
    def scalar_namespace():
        nonlocal namespace_checked
        if namespace_checked is not None:
            return namespace_checked
        program = view.analysis.evidence.unit.scopes.program
        namespace_checked = False
        if type(program) is not ConstructedProgramScope:
            return False
        namespace = program.evidence.translation_namespace
        if (type(namespace) is not TranslationNamespace or namespace.language_id != "x86:LE:64:default"
                or len(program.evidence.address_spaces) > 4096
                or not pay(8 + len(program.evidence.address_spaces))):
            return False
        try:
            namespace.__post_init__()
            namespace_checked = _derive_program_scope(program.evidence) == program.scope
        except (TypeError, ValueError):
            return False
        return namespace_checked
    store_pointer = load_pointer = None
    def identity(value):
        return (value.kind, value.coordinate.space_id, value.coordinate.byte_offset, value.byte_size)
    def value_of(value):
        ident = identity(value)
        if value.kind in (VarnodeKindCode.CONSTANT, VarnodeKindCode.ADDRESS):
            return (("literal", value.coordinate.byte_offset % (1 << (8 * value.byte_size)), value.byte_size), frozenset(), frozenset(), 0, frozenset())
        if ident in state:
            return state[ident]
        if value.kind is VarnodeKindCode.REGISTER and value.byte_size == 4 and value.coordinate.byte_offset % 8 == 0:
            if not pay(len(extensions)):
                return (("unknown_subspan", ident), frozenset(), frozenset(), 0, frozenset(("budget",)))
            candidates = [data for full, (source, data) in extensions.items()
                          if full in state and full[:3] == ident[:3] and full[3] == 8 and source == ident]
            if len(candidates) == 1 and scalar_namespace():
                return candidates[0]
            if candidates:
                return (("unknown_subspan", ident), frozenset(), frozenset(), 0, frozenset(("namespace",)))
        return (("entry", ident), frozenset(), frozenset(), 0, frozenset())
    for key in ordered:
        operation = view.operation(key)
        opcode = operation.opcode
        values = [value_of(v) for v in operation.inputs]
        if not pay(1 + len(values)):
            return None
        if opcode == "STORE" and len(values) == 3:
            address = (values[0][0], values[1][0], operation.inputs[2].byte_size)
            memory[address] = (key, values[2])
            if key == store_key:
                store_pointer = values[1]
            continue
        if opcode == "LOAD" and len(values) == 2 and operation.output is not None:
            if key == load_key:
                load_pointer = values[1]
                break
            address = (values[0][0], values[1][0], operation.output.byte_size)
            prior = memory.get(address)
            if prior is None:
                output = (("unknown_load", key), frozenset(), frozenset(), 0, frozenset((key,)))
            else:
                writer, data = prior
                output = (data[0], data[1], data[2] | {(writer, key)}, data[3], data[4])
        elif opcode == "CALL":
            # Only a candidate locator crosses this occurrence. No effect is
            # certified here, including implicit token or register effects.
            if operation.output is not None:
                return None
            continue
        elif opcode in ("COPY", "CAST", "INT_ZEXT", "INT_SEXT", "INT_AND", "INT_ADD", "INT_SUB", "INT_MULT") and operation.output is not None:
            masks = frozenset().union(*(v[1] for v in values))
            saved = frozenset().union(*(v[2] for v in values))
            unknown = frozenset().union(*(v[4] for v in values))
            if opcode == "INT_AND":
                literals = [v for v in operation.inputs if v.kind is VarnodeKindCode.CONSTANT]
                if len(literals) == 1 and (literals[0].coordinate.byte_offset % (1 << (8 * operation.output.byte_size))).bit_count() <= 4:
                    masks |= {key}
                else:
                    masks, saved = frozenset(), frozenset()
                    unknown |= {key}
            expression = values[0][0] if opcode in ("COPY", "CAST") and len(values) == 1 else (opcode, operation.output.byte_size, tuple(v[0] for v in values))
            depth = 1 + max((v[3] for v in values), default=0)
            if depth > 64:
                return None
            output = (expression, masks, saved, depth, unknown)
        elif operation.output is not None and opcode not in ("CALLIND", "CALLOTHER", "INDIRECT", "MULTIEQUAL"):
            action = view.storage_actions.get(key)
            if action is None or not pay(len(action.writes)):
                return None
            if (operation.output.kind not in (VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE)
                    or action.unresolved_writes or len(action.writes) != 1
                    or any(span.object_id.kind not in (StorageObjectKind.REGISTER_FILE, StorageObjectKind.FUNCTION_UNIQUE)
                           for span in action.writes)):
                return None
            # An admitted pure output may be unrelated to the address demand.
            # Its actual output overwrites the locator and carries explicit
            # unknown debt through every later supported expression.
            output = (("unsupported_value", key), frozenset(), frozenset(), 0, frozenset((key,)))
        else:
            return None
        written = identity(operation.output)
        if not pay(len(state)):
            return None
        for existing in tuple(state):
            if existing[:2] == written[:2] and existing[2] < written[2] + written[3] and written[2] < existing[2] + existing[3]:
                del state[existing]
                extensions.pop(existing, None)
        state[written] = output
        if (opcode == "INT_ZEXT" and len(operation.inputs) == 1
                and operation.inputs[0].kind is VarnodeKindCode.REGISTER
                and operation.output.kind is VarnodeKindCode.REGISTER
                and operation.inputs[0].byte_size == 4 and operation.output.byte_size == 8
                and identity(operation.inputs[0])[:3] == written[:3]
                and len(values[0][1]) == 1 and not values[0][4]):
            extensions[written] = (identity(operation.inputs[0]), values[0])
    if (store_pointer is None or load_pointer is None or store_pointer[4] or load_pointer[4]
            or store_pointer[0] != load_pointer[0]):
        return None
    masks = store_pointer[1] | load_pointer[1]
    saved = store_pointer[2] | load_pointer[2]
    if len(masks) != 1:
        return None
    # Several reloads may name the same saved version. The marker selects the
    # one used after the dynamic STORE, while preserving unique STORE lineage.
    saved_stores = {writer for writer, _ in saved}
    later_reads = {(writer, reader) for writer, reader in saved
                   if view.position(store_key) < view.position(reader) < view.position(load_key)}
    if len(saved_stores) != 1 or len(later_reads) != 1:
        return None
    saved_store, saved_load = next(iter(later_reads))
    saved_operation = view.operation(saved_load)
    saved_action = view.action_ids.get(saved_load)
    inventory_reads = reads_by_action.get(saved_action, ())
    if not pay(len(inventory_reads)):
        return None
    full_reads = [read for read in inventory_reads
                  if read.span.object_id.kind in _MEMORY_KINDS
                  and read.span.size == saved_operation.output.byte_size
                  and len(read.fragments) == 1 and read.fragments[0].span == read.span]
    if len(full_reads) > 1:
        return None
    mask_key = next(iter(masks))
    if not view.position(mask_key) < view.position(saved_store) < view.position(store_key):
        return None
    if not pay(13):
        return None
    return {"kind": "conditional_finite_index_memory_transport", "version": 1,
            "function_scope": view.analysis.evidence.unit.scopes.function.scope.digest.hex(),
            "store_operation_key": store_key, "store_action_node": edge["source"],
            "load_operation_key": load_key, "load_action_node": edge["target"],
            "index_definition_operation_key": mask_key,
            "saved_index_store_operation_key": saved_store,
            "saved_index_load_operation_key": saved_load,
            "edge_source_node": edge["source"], "edge_target_node": edge["target"],
            "root_node": root_node}


__all__ = ("certify_dynamic_aliases", "dynamic_alias_reachable_nodes", "finite_index_transport_claim")
