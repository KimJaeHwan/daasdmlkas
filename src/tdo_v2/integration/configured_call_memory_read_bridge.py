"""Bounded temporary compatibility STORE-to-leaf-LOAD physical witnesses.

Only straight caller prefixes and closed straight leaf callees are supported.
Pointer equality and content preservation are separate checks. Different
symbolic anchors never establish disjointness, and no calling roles are used.
Pointer state is restricted to registers/function temporaries and the raw
COPY, literal INT_ADD/INT_SUB, LOAD, STORE, CALL and RETURN vocabulary.
"""

from dataclasses import dataclass
from enum import StrEnum
import json

from ..call_contracts import DirectCallTarget
from ..call_seeds import _operation_key
from ..memory_contracts import MemoryDefinitionKind, MemoryWriteMode
from ..model import ByteSpan, ResolvedStorage, StorageObjectKind
from ..observed_call_state import observed_call_state_projections
from ..scope_identity import AddressCoordinate, VarnodeKindCode
from ..storage import _resolve_validated_storage
from .configured_function_view import _FunctionView
from .configured_interprocedural_contracts import ConfiguredFunctionAnalysis
from .configured_path_wire import span_fact, wire
from .configured_value_domain import storage_ref


class MemoryReadBridgeStatus(StrEnum):
    VERIFIED_MAY = "VERIFIED_MAY"
    PARTIAL = "PARTIAL"


@dataclass(frozen=True, slots=True)
class MemoryReadBridgeLimits:
    operations: int = 2048
    steps: int = 16384
    expression_depth: int = 64
    access_bytes: int = 64
    map_entries: int = 128
    map_bytes: int = 1024

    def __post_init__(self):
        if any(type(value) is not int or value <= 0
               for value in (self.operations, self.steps, self.expression_depth, self.access_bytes,
                             self.map_entries, self.map_bytes)):
            raise ValueError("bridge limits require positive exact integers")


@dataclass(frozen=True, slots=True)
class AffinePointerValue:
    width_bits: int
    anchor_scope: bytes | None
    anchor_node: int | None
    anchor_span: ByteSpan | None
    offset: int
    derivation: tuple[str, ...]

    @property
    def anchor(self):
        return self.width_bits, self.anchor_scope, self.anchor_node, self.anchor_span

    def report(self):
        return {"width_bits": self.width_bits,
                "anchor_scope": None if self.anchor_scope is None else self.anchor_scope.hex(),
                "anchor_node": self.anchor_node, "anchor_span": span_fact(self.anchor_span),
                "modular_offset": self.offset, "derivation": list(self.derivation)}


@dataclass(frozen=True, slots=True)
class PointerEntryBinding:
    node: int
    span: ByteSpan
    value: AffinePointerValue


@dataclass(frozen=True, slots=True)
class MemoryWriteAudit:
    scope: bytes
    operation_key: str
    address_space_id: int
    pointer: AffinePointerValue
    byte_size: int


@dataclass(frozen=True, slots=True)
class PointerMemoryEvent:
    scope: bytes
    operation_key: str
    kind: str
    address_space_id: int | None
    pointer: AffinePointerValue | None
    byte_size: int
    value: AffinePointerValue | None
    invalidated_entries: tuple[tuple[bytes, str], ...]
    reason: str

    def report(self):
        return {"scope": self.scope.hex(), "operation_key": self.operation_key, "kind": self.kind,
                "address_space_id": self.address_space_id,
                "pointer": None if self.pointer is None else self.pointer.report(),
                "byte_size": self.byte_size, "value": None if self.value is None else self.value.report(),
                "invalidated_entries": [{"scope": scope.hex(), "operation_key": key}
                                        for scope, key in self.invalidated_entries], "reason": self.reason}


@dataclass(frozen=True, slots=True)
class PriorLeafCallWitness:
    callee_scope: bytes
    callee_observation_digest: bytes
    call_operation_key: str
    return_operation_key: str
    continuation: AddressCoordinate
    return_value: AffinePointerValue
    entry_bindings: tuple[PointerEntryBinding, ...]

    def report(self):
        return {"callee_scope": self.callee_scope.hex(), "callee_observation_digest": self.callee_observation_digest.hex(),
                "call_operation_key": self.call_operation_key, "return_operation_key": self.return_operation_key,
                "continuation": {"space_id": self.continuation.space_id, "byte_offset": self.continuation.byte_offset},
                "return_value": self.return_value.report(),
                "entry_bindings": [{"node": row.node, "span": span_fact(row.span), "value": row.value.report()}
                                   for row in self.entry_bindings]}


@dataclass(frozen=True, slots=True)
class CallMemoryReadBridgeWitness:
    caller_scope: bytes
    callee_scope: bytes
    caller_observation_digest: bytes
    callee_observation_digest: bytes
    call_operation_key: str
    store_operation_key: str
    load_operation_key: str
    source_definition_node: int
    target_load_action_node: int
    source_span: ByteSpan
    address_space_id: int
    byte_size: int
    store_pointer: AffinePointerValue
    load_pointer: AffinePointerValue
    entry_bindings: tuple[PointerEntryBinding, ...]
    operation_transcript: tuple[tuple[bytes, str], ...]
    write_audit: tuple[MemoryWriteAudit, ...]
    prior_leaf_calls: tuple[PriorLeafCallWitness, ...] = ()
    pointer_memory_events: tuple[PointerMemoryEvent, ...] = ()
    prefix_mode: bool = False

    def report(self):
        result = {"kind": "observed_leaf_call_memory_read_bridge",
                "version": 3 if self.prefix_mode else 2 if self.prior_leaf_calls else 1,
                "premise": "configured-observed-shared-state-v1",
                "caller_scope": self.caller_scope.hex(), "callee_scope": self.callee_scope.hex(),
                "caller_observation_digest": self.caller_observation_digest.hex(),
                "callee_observation_digest": self.callee_observation_digest.hex(),
                "call_operation_key": self.call_operation_key,
                "store_operation_key": self.store_operation_key, "load_operation_key": self.load_operation_key,
                "source_definition_node": self.source_definition_node,
                "target_load_action_node": self.target_load_action_node,
                "source_span": span_fact(self.source_span), "address_space_id": self.address_space_id,
                "byte_size": self.byte_size, "store_pointer": self.store_pointer.report(),
                "load_pointer": self.load_pointer.report(),
                "entry_bindings": [{"node": row.node, "span": span_fact(row.span),
                                    "value": row.value.report()} for row in self.entry_bindings],
                "operation_transcript": [{"scope": scope.hex(), "operation_key": key}
                                         for scope, key in self.operation_transcript],
                "write_audit": [{"scope": row.scope.hex(), "operation_key": row.operation_key,
                                 "address_space_id": row.address_space_id, "pointer": row.pointer.report(),
                                 "byte_size": row.byte_size} for row in self.write_audit]}
        if self.prior_leaf_calls or self.prefix_mode:
            result["prior_leaf_calls"] = [row.report() for row in self.prior_leaf_calls]
            result["pointer_memory_events"] = [row.report() for row in self.pointer_memory_events]
        return result


@dataclass(frozen=True, slots=True)
class CallMemoryReadBridgeResult:
    status: MemoryReadBridgeStatus
    witness: CallMemoryReadBridgeWitness | None
    gaps: tuple[str, ...]
    work_units: int = 0


class _Gap(Exception):
    pass


def _need(condition, code):
    if not condition:
        raise _Gap(code)


class _Budget:
    def __init__(self, limits, *, inspection=False, charge_state_scans=False):
        self.limits, self.used = limits, 0
        self.inspection = inspection
        self.charge_state_scans = charge_state_scans

    def prepay(self, amount):
        if self.charge_state_scans and amount:
            self.used += amount
            _need(self.used <= self.limits.steps, "bridge_budget_exhausted")

    def count(self):
        self.used += 1
        _need(self.used <= self.limits.steps, "bridge_budget_exhausted")

    def inspect(self):
        if self.inspection:
            self.count()


@dataclass(frozen=True, slots=True)
class _DirectRamAccess:
    """Private authenticated access only; confers no preservation authority."""
    scope: bytes
    operation_key: str
    input_index: int | None
    span: ByteSpan
    address_space_id: int
    pointer: AffinePointerValue
    byte_size: int
    action_id: int
    read_ordinal: int | None
    fragments: tuple[tuple[ByteSpan, tuple[int, ...]], ...]
    write_definition_id: int | None


def _direct_ram_access(view, operation_key, budget, *, input_index=None):
    """Authenticate a raw direct RAM operand without enabling legacy replay.

    ``input_index=None`` selects the output. All scans/copies are prepaid even
    for a legacy _Budget whose optional state-scan charging is disabled.
    """
    _need(type(view) is _FunctionView and type(budget) is _Budget
          and type(operation_key) is str and bool(operation_key)
          and (input_index is None or type(input_index) is int and input_index >= 0),
          "direct_ram_request_malformed")
    try:
        return _authenticate_direct_ram_access(view, operation_key, budget, input_index)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        raise _Gap("direct_ram_evidence_malformed") from None


def _authenticate_direct_ram_access(view, key, budget, input_index):
    def charge(amount):
        budget.used += amount
        _need(budget.used <= budget.limits.steps, "bridge_budget_exhausted")

    charge(1)
    _need(view.normalized.scopes is view.analysis.evidence.unit.scopes,
          "function_observation_mismatch")
    instructions = view.analysis.evidence.unit.observation.instructions
    charge(len(instructions))
    _need(len(instructions) <= budget.limits.operations, "operation_budget_exhausted")
    operations, raw_count = [], 0
    for instruction in instructions:
        charge(len(instruction.operations))
        raw_count += len(instruction.operations)
        _need(raw_count <= budget.limits.operations, "operation_budget_exhausted")
        for ordinal, operation in enumerate(instruction.operations):
            if _operation_key(instruction.address, ordinal, operation.opcode) == key:
                operations.append(operation)
    _need(len(operations) == 1 and view.operation(key) == operations[0],
          "direct_ram_operation_unavailable")
    operation = operations[0]
    charge(len(operation.inputs))
    _need(input_index is None or input_index < len(operation.inputs),
          "direct_ram_operand_unavailable")
    operand = operation.output if input_index is None else operation.inputs[input_index]
    _need(operand is not None and operand.kind is VarnodeKindCode.ADDRESS,
          "direct_ram_operand_unavailable")
    descriptors = view.analysis.evidence.unit.scopes.program.evidence.address_spaces
    charge(len(descriptors))
    spaces = [row for row in descriptors if row.space_id == operand.coordinate.space_id]
    _need(len(spaces) == 1 and spaces[0].is_memory_space
          and spaces[0].addressable_unit_bytes == 1, "direct_ram_space_unavailable")
    width, start, size = spaces[0].address_size_bits, operand.coordinate.byte_offset, operand.byte_size
    _need(type(width) is int and 1 <= width <= 64 and type(start) is int
          and type(size) is int and 0 < size <= min(64, budget.limits.access_bytes)
          and 0 <= start < 1 << width and start + size <= 1 << width,
          "direct_ram_width_or_range_unavailable")
    resolved = _resolve_validated_storage(storage_ref(operand),
        view.analysis.evidence.unit.scopes.resolution_context)
    _need(type(resolved) is ResolvedStorage, "direct_ram_span_unavailable")
    span = resolved.span
    _need(span.object_id.kind is StorageObjectKind.ADDRESS_SPACE
          and span.object_id.scope == view.analysis.evidence.unit.scopes.program.scope
          and span.object_id.space_key == operand.coordinate.space_id
          and span.start == start and span.size == size, "direct_ram_span_mismatch")
    blocks = view.normalized.memory_unit.blocks
    charge(len(blocks))
    effects = []
    for block in blocks:
        charge(len(block.actions))
        effects.extend(row for row in block.actions if row.operation_key == key)
    _need(len(effects) == 1 and view.storage_actions.get(key) == effects[0],
          "direct_ram_effect_unavailable")
    effect = effects[0]
    charge(len(effect.reads) + len(effect.writes) + len(effect.unresolved_reads)
           + len(effect.unresolved_writes) + len(view.memory.actions))
    actions = [(index, row) for index, row in enumerate(view.memory.actions) if row.operation_key == key]
    _need(len(actions) == 1, "direct_ram_action_unavailable")
    action_id, action = actions[0]
    fragments, read_ordinal, definition_id = (), None, None
    if input_index is None:
        _need(effect.writes == (span,) and effect.write_mode is MemoryWriteMode.DATA
              and not effect.unresolved_writes, "direct_ram_write_effect_mismatch")
        charge(len(view.memory.definitions) + len(action.write_definition_ids))
        definitions = [(index, row) for index, row in enumerate(view.memory.definitions)
                       if row.operation_key == key]
        _need(len(definitions) == 1, "direct_ram_write_definition_unavailable")
        definition_id, definition = definitions[0]
        _need(definition.kind is MemoryDefinitionKind.DATA_WRITE and definition.span == span
              and definition.write_ordinal == 0 and action.write_definition_ids == (definition_id,),
              "direct_ram_write_definition_mismatch")
    else:
        _need(not effect.unresolved_reads and effect.reads.count(span) == 1,
              "direct_ram_read_effect_mismatch")
        read_ordinal = effect.reads.index(span)
        charge(len(view.memory.reads))
        reads = [row for row in view.memory.reads
                 if row.action_id == action_id and row.read_ordinal == read_ordinal]
        _need(len(reads) == 1 and reads[0].span == span, "direct_ram_read_unavailable")
        read = reads[0]
        charge(len(read.fragments))
        _need(bool(read.fragments) and len(read.fragments) <= size,
              "direct_ram_fragment_inventory_mismatch")
        cursor, rows = start, []
        for fragment in read.fragments:
            charge(len(fragment.definition_ids) + 1)
            _need(type(fragment.span) is ByteSpan and span.contains(fragment.span)
                  and fragment.span.start == cursor and len(fragment.definition_ids) == 1,
                  "direct_ram_fragment_inventory_mismatch")
            identifier = fragment.definition_ids[0]
            _need(type(identifier) is int and 0 <= identifier < len(view.memory.definitions)
                  and view.memory.definitions[identifier].span.contains(fragment.span),
                  "direct_ram_fragment_definition_mismatch")
            rows.append((fragment.span, fragment.definition_ids))
            cursor = fragment.span.end
        _need(cursor == span.end, "direct_ram_fragment_inventory_mismatch")
        fragments = tuple(rows)
    charge(12 + len(fragments))
    return _DirectRamAccess(view.scope_digest, key, input_index, span, operand.coordinate.space_id,
        AffinePointerValue(width, None, None, None, start, ()), size, action_id,
        read_ordinal, fragments, definition_id)


def _view(value, maximum, *, budget=None):
    if type(value) is _FunctionView:
        value = value.analysis
    if type(value) is not ConfiguredFunctionAnalysis:
        raise TypeError("memory bridge requires exact admitted function analyses or views")
    _need(value.normalized.scopes is value.evidence.unit.scopes, "function_observation_mismatch")
    instructions = value.evidence.unit.observation.instructions
    if budget is not None:
        for row in instructions:
            budget.count()
            for _ in row.operations:
                budget.count()
    _need(len(instructions) <= maximum and sum(len(row.operations) for row in instructions) <= maximum,
          "operation_budget_exhausted")
    if budget is not None:
        budget.prepay(value.normalized.dependencies.node_count + value.normalized.dependencies.edge_count
                      + len(value.normalized.memory_ssa.definitions)
                      + len(value.normalized.memory_ssa.actions) + len(value.normalized.memory_ssa.reads))
        if budget.charge_state_scans:
            _prepay_view_control(value, budget.prepay)
    return _FunctionView(value)


def _prepay_view_control(analysis, charge):
    """Prepay the existing dominator constructor before its growing set work.

    Forward predecessor order settles in one pass plus the final unchanged
    pass. Otherwise each changing pass removes at least one of N*N possible
    memberships; the deliberately conservative bound covers its fixed point.
    """
    blocks = analysis.normalized.memory_unit.blocks
    size = len(blocks)
    charge(1 + 3 * size)
    indices = {block.key: index for index, block in enumerate(blocks)}
    predecessor_count = sum(len(block.predecessors) for block in blocks)
    charge(1 + predecessor_count)
    forward = all(indices[predecessor] < index
                  for index, block in enumerate(blocks) for predecessor in block.predecessors)
    passes = 2 if forward else size * size + 1
    # Initial/final N-sized sets and each pass's copies, intersections,
    # unions, equality scans and bounded map bookkeeping.
    charge(1 + 2 * size * size + passes * size * (4 * size + predecessor_count + 1))


def _prepay_graph_edges(graph, charge):
    """Pay eager raw-list, keyed tuple, sort and final tuple work first."""
    edges = graph.edge_count
    charge(1 + edges * (4 + max(1, edges.bit_length())))


def _ordered(view, stop_key, *, leaf=False, prior_call_keys=(), read_stop=False, budget=None):
    rows = {}
    for row in view.observation.instructions:
        if budget is not None:
            budget.count()
        rows[row.address] = row
    current, seen, result = view.analysis.entry, set(), []
    while current in rows and current not in seen:
        seen.add(current)
        if budget is not None:
            budget.count()
        instruction = rows[current]
        flow = instruction.flow
        _need(flow is not None and not flow.is_computed and not flow.is_jump
              and not flow.is_conditional and not flow.is_override, "control_shape_unproven")
        _need(not leaf or not flow.is_call, "callee_not_leaf")
        for ordinal, operation in enumerate(instruction.operations):
            if budget is not None:
                budget.count()
            key = _operation_key(instruction.address, ordinal, operation.opcode)
            result.append((key, operation))
            if key == stop_key and not leaf:
                if read_stop:
                    _need(operation.opcode == "LOAD" and not flow.is_call, "target_load_not_admitted")
                    return tuple(result)
                _need(flow.is_call and ordinal == len(instruction.operations) - 1, "call_context_mismatch")
                return tuple(result)
            if key in prior_call_keys:
                _need(not leaf and flow.is_call and ordinal == len(instruction.operations) - 1,
                      "call_context_mismatch")
                continue
            _need(operation.opcode not in {"CALL", "CALLIND", "CALLOTHER", "BRANCH", "CBRANCH", "BRANCHIND"},
                  "callee_not_leaf" if leaf else "intervening_control_unproven")
            _need(operation.opcode != "RETURN" or (leaf and flow.is_terminal
                  and ordinal == len(instruction.operations) - 1), "control_shape_unproven")
        if flow.is_terminal:
            _need(leaf and instruction.fallthrough is None and instruction.operations
                  and instruction.operations[-1].opcode == "RETURN" and seen == set(rows),
                  "normal_return_frontier_unproven")
            return tuple(result)
        _need(flow.has_fallthrough and (not flow.is_call or any(
            _operation_key(instruction.address, i, op.opcode) in prior_call_keys
            for i, op in enumerate(instruction.operations))) and instruction.fallthrough is not None,
              "control_shape_unproven")
        following = instruction.fallthrough
        predecessors = []
        for row in rows.values():
            if budget is not None:
                budget.count()
            if row.fallthrough == following or (not row.flow.is_call and following in row.flow_targets):
                predecessors.append(row.address)
        _need(predecessors == [current], "caller_order_unproven")
        current = following
    raise _Gap("control_escape_or_cycle")


class _Replay:
    def __init__(self, view, budget, transport=None):
        self.view, self.budget, self.transport = view, budget, transport
        self.state, self.written, self.bindings = {}, [], []
        self._written_set = set()
        for instruction in view.observation.instructions:
            budget.inspect()
            for _ in instruction.operations:
                budget.inspect()
        self.transients = {key for projection in observed_call_state_projections(view.observation)
                           for key in projection.transient_operation_keys}

    def _record_write(self, span):
        if getattr(self.budget, "charge_state_scans", False):
            self.budget.prepay(2)
            if span in self._written_set:
                return
            self._written_set.add(span)
        self.written.append(span)

    def span(self, node):
        resolved = _resolve_validated_storage(storage_ref(node),
            self.view.analysis.evidence.unit.scopes.resolution_context)
        _need(type(resolved) is ResolvedStorage, "pointer_storage_unavailable")
        _need(resolved.span.object_id.kind in {StorageObjectKind.REGISTER_FILE, StorageObjectKind.FUNCTION_UNIQUE},
              "pointer_memory_storage_unsupported")
        return resolved.span

    def get(self, span):
        self.budget.count()
        _need(1 <= span.size <= 8, "pointer_width_unsupported")
        if span in self.state:
            value = self.state[span]
            _need(value is not None, "pointer_value_unproven")
            return value
        self.budget.prepay(len(self.written))
        _need(not any(row.overlaps(span) for row in self.written), "pointer_width_or_join_unproven")
        entries = []
        for i, row in enumerate(self.view.memory.definitions):
            self.budget.count()
            if row.kind is MemoryDefinitionKind.ENTRY and row.span.contains(span):
                entries.append((i, row))
        _need(len(entries) == 1, "pointer_entry_unavailable")
        node = self.view.memory_graph.definition_nodes[entries[0][0]]
        if self.transport is not None:
            value = self.transport.get(span)
            self.bindings.append(PointerEntryBinding(node, span, value))
        else:
            value = AffinePointerValue(span.size * 8, self.view.scope_digest, node, span, 0, ())
            self.bindings.append(PointerEntryBinding(node, span, value))
        self.state[span] = value
        return value

    def value(self, node):
        if node.kind is VarnodeKindCode.CONSTANT:
            _need(1 <= node.byte_size <= 8 and node.coordinate.byte_offset < 1 << (8 * node.byte_size),
                  "pointer_literal_width_unsupported")
            return AffinePointerValue(8 * node.byte_size, None, None, None, node.coordinate.byte_offset, ())
        return self.get(self.span(node))

    def access(self, operation):
        _need(len(operation.inputs) == (3 if operation.opcode == "STORE" else 2)
              and operation.inputs[0].kind is VarnodeKindCode.CONSTANT, "memory_selector_unavailable")
        space = operation.inputs[0].coordinate.byte_offset
        evidence = self.view.analysis.evidence.unit.scopes.program.evidence.address_spaces
        self.budget.prepay(len(evidence))
        descriptors = [row for row in evidence if row.space_id == space]
        _need(len(descriptors) == 1 and descriptors[0].is_memory_space
              and descriptors[0].addressable_unit_bytes == 1, "memory_space_unavailable")
        pointer = self.value(operation.inputs[1])
        _need(pointer.width_bits == descriptors[0].address_size_bits, "address_width_mismatch")
        size = operation.inputs[2].byte_size if operation.opcode == "STORE" else operation.output.byte_size if operation.output else 0
        _need(0 < size <= min(1 << pointer.width_bits, self.budget.limits.access_bytes), "memory_width_unsupported")
        return space, pointer, size

    def step(self, key, operation):
        self.budget.count()
        _need(operation.opcode in {"COPY", "INT_ADD", "INT_SUB", "LOAD", "STORE", "CALL", "RETURN"},
              "unknown_memory_effect")
        effect = self.view.storage_actions.get(key)
        _need(effect is not None or key in self.transients, "operation_effect_unavailable")
        self.budget.prepay(0 if effect is None else len(effect.writes))
        if operation.opcode not in {"STORE", "CALL"}:
            _need(effect is None or not effect.unresolved_writes, "unknown_memory_effect")
            _need(effect is None or not any(write.object_id.kind in {
                StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE
            } for write in effect.writes), "non_store_memory_write_unproven")
        if operation.output is None:
            return
        span, value = self.span(operation.output), None
        inputs = operation.inputs
        if operation.opcode == "COPY" and len(inputs) == 1 and inputs[0].byte_size == span.size:
            try:
                value = self.value(inputs[0])
            except _Gap as gap:
                if str(gap) == "bridge_budget_exhausted":
                    raise
        elif operation.opcode in {"INT_ADD", "INT_SUB"} and len(inputs) == 2:
            left, literal = inputs
            if operation.opcode == "INT_ADD" and left.kind is VarnodeKindCode.CONSTANT:
                left, literal = literal, left
            if literal.kind is VarnodeKindCode.CONSTANT and left.byte_size == literal.byte_size == span.size:
                base, delta = self.value(left), literal.coordinate.byte_offset
                _need(delta < 1 << base.width_bits, "pointer_literal_width_unsupported")
                value = AffinePointerValue(base.width_bits, base.anchor_scope, base.anchor_node,
                    base.anchor_span, (base.offset + (delta if operation.opcode == "INT_ADD" else -delta))
                    % (1 << base.width_bits), base.derivation)
        if value is not None:
            _need(len(value.derivation) < self.budget.limits.expression_depth, "expression_budget_exhausted")
            self.budget.prepay(len(value.derivation) + 1)
            value = AffinePointerValue(value.width_bits, value.anchor_scope, value.anchor_node,
                                      value.anchor_span, value.offset, value.derivation + (key,))
        self.budget.prepay(2 * len(self.state))
        self.state = {existing: old for existing, old in self.state.items() if not existing.overlaps(span)}
        self.state[span] = value
        self._record_write(span)


def _pieces(pointer, size):
    modulus, start = 1 << pointer.width_bits, pointer.offset
    return ((start, start + size),) if start + size <= modulus else ((start, modulus), (0, start + size - modulus))


def _covers(outer, outer_size, inner, inner_size):
    return outer.anchor == inner.anchor and all(any(a <= c and d <= b for a, b in _pieces(outer, outer_size))
                                               for c, d in _pieces(inner, inner_size))


_UNAVAILABLE_VALUE = {"pointer_value_unproven", "pointer_width_or_join_unproven",
                      "pointer_entry_unavailable", "activation_unique_entry_unavailable"}


def _pure_shape(operation):
    """Explicit pure P-code shapes; their output bits remain unknown."""
    inputs, output, opcode = operation.inputs, operation.output, operation.opcode
    if output is None or not 1 <= output.byte_size <= 8 or any(not 1 <= row.byte_size <= 8 for row in inputs):
        return False
    widths, size = tuple(row.byte_size for row in inputs), output.byte_size
    if opcode in {"INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL",
                  "INT_CARRY", "INT_SCARRY", "INT_SBORROW"}:
        return len(widths) == 2 and widths[0] == widths[1] and size == 1
    if opcode in {"BOOL_XOR", "BOOL_AND", "BOOL_OR"}:
        return widths == (1, 1) and size == 1
    if opcode == "BOOL_NEGATE":
        return widths == (1,) and size == 1
    if opcode in {"INT_ZEXT", "INT_SEXT"}:
        return len(widths) == 1 and size >= widths[0]
    if opcode in {"INT_MULT", "INT_AND", "INT_OR", "INT_XOR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT"}:
        return widths == (size, size)
    if opcode in {"INT_NEGATE", "INT_2COMP"}:
        return widths == (size,)
    if opcode in {"POPCOUNT", "LZCOUNT"}:
        return len(widths) == 1
    if opcode == "PIECE":
        return len(widths) == 2 and size == sum(widths)
    if opcode == "SUBPIECE":
        return len(widths) == 2 and inputs[1].kind is VarnodeKindCode.CONSTANT and size <= widths[0] \
            and inputs[1].coordinate.byte_offset <= widths[0] - size
    return False


class _SavedValues:
    def __init__(self, budget):
        self.budget, self.entries, self.events = budget, [], []

    def store(self, replay, key, operation, access):
        self.budget.count()
        retained, invalidated, reason = [], [], "known_address"
        for old in self.entries:
            self.budget.count()
            same = access is not None and old[0][0] == access[0] and old[0][1].anchor == access[1].anchor
            overlap = same and any(a < d and c < b for a, b in _pieces(old[0][1], old[0][2])
                                   for c, d in _pieces(access[1], access[2]))
            if not same or overlap:
                invalidated.append(old[2])
                reason = "unknown_alias" if not same else "overlap"
            else:
                retained.append(old)
        self.entries = retained
        value = None
        if access is not None and operation.inputs[2].byte_size <= 8:
            try:
                value = replay.value(operation.inputs[2])
            except _Gap as gap:
                if str(gap) not in _UNAVAILABLE_VALUE:
                    raise
        if value is not None:
            _need(value.width_bits == access[2] * 8, "saved_value_width_mismatch")
            self.budget.prepay(len(retained))
            _need(len(retained) < self.budget.limits.map_entries and
                  sum(row[0][2] for row in retained) + access[2] <= self.budget.limits.map_bytes,
                  "saved_value_map_budget_exhausted")
            self.entries.append((access, value, (replay.view.scope_digest, key)))
        self.budget.prepay(len(invalidated) * 2)
        self.events.append(PointerMemoryEvent(replay.view.scope_digest, key,
            "write" if access is not None else "invalidate", access[0] if access is not None else None,
            access[1] if access is not None else None, operation.inputs[2].byte_size, value,
            tuple(sorted(set(invalidated))), reason if access is not None else "unknown_address"))

    def load(self, replay, key, access):
        self.budget.count()
        matches = []
        for old in self.entries:
            self.budget.count()
            if old[0][0] == access[0] and old[0][1].anchor == access[1].anchor \
                    and old[0][1].offset == access[1].offset and old[0][2] == access[2]:
                matches.append(old[1])
        _need(len(matches) <= 1, "saved_value_ambiguous")
        value = matches[0] if matches else None
        self.events.append(PointerMemoryEvent(replay.view.scope_digest, key, "read", *access, value, (),
                                              "exact_saved_value" if value is not None else "unavailable"))
        return value


class _PriorReplay(_Replay):
    def __init__(self, view, budget, saved, transport=None):
        super().__init__(view, budget, transport)
        self.saved = saved

    def get(self, span):
        _need(not (self.transport is not None and span.object_id.kind is StorageObjectKind.FUNCTION_UNIQUE
                   and span not in self.state), "activation_unique_entry_unavailable")
        return super().get(span)

    def _unknown_output(self, operation):
        span = self.span(operation.output)
        self.budget.prepay(2 * len(self.state))
        self.state = {old: value for old, value in self.state.items() if not old.overlaps(span)}
        self.state[span] = None
        self._record_write(span)

    def store_access(self, operation):
        _need(len(operation.inputs) == 3 and operation.inputs[0].kind is VarnodeKindCode.CONSTANT,
              "memory_selector_unavailable")
        self.budget.prepay(len(self.view.analysis.evidence.unit.scopes.program.evidence.address_spaces))
        descriptors = [row for row in self.view.analysis.evidence.unit.scopes.program.evidence.address_spaces
                       if row.space_id == operation.inputs[0].coordinate.byte_offset]
        _need(len(descriptors) == 1 and descriptors[0].is_memory_space and descriptors[0].addressable_unit_bytes == 1,
              "memory_space_unavailable")
        _need(operation.inputs[1].byte_size * 8 == descriptors[0].address_size_bits, "address_width_mismatch")
        _need(0 < operation.inputs[2].byte_size <= min(1 << descriptors[0].address_size_bits,
                                                     self.budget.limits.access_bytes), "memory_width_unsupported")
        try:
            return self.access(operation)
        except _Gap as gap:
            if str(gap) not in _UNAVAILABLE_VALUE:
                raise
            return None

    def step(self, key, operation):
        if _pure_shape(operation):
            self.budget.count()
            effect = self.view.storage_actions.get(key)
            self.budget.prepay(0 if effect is None else len(effect.writes))
            _need(effect is not None and not effect.unresolved_writes and not any(
                span.object_id.kind in {StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE}
                for span in effect.writes), "unknown_memory_effect")
            self._unknown_output(operation)
            return
        access, restored = None, None
        if operation.opcode == "LOAD":
            access = self.access(operation)
            restored = self.saved.load(self, key, access)
        try:
            super().step(key, operation)
        except _Gap as gap:
            shaped = operation.output is not None and (
                operation.opcode == "COPY" and len(operation.inputs) == 1
                and operation.inputs[0].byte_size == operation.output.byte_size or
                operation.opcode in {"INT_ADD", "INT_SUB"} and len(operation.inputs) == 2
                and all(row.byte_size == operation.output.byte_size for row in operation.inputs))
            if str(gap) not in _UNAVAILABLE_VALUE or not shaped:
                raise
            self._unknown_output(operation)
        if restored is not None:
            _need(restored.width_bits == operation.output.byte_size * 8, "saved_value_width_mismatch")
            _need(len(restored.derivation) < self.budget.limits.expression_depth, "expression_budget_exhausted")
            self.budget.prepay(len(restored.derivation) + 1)
            self.state[self.span(operation.output)] = AffinePointerValue(restored.width_bits, restored.anchor_scope,
                restored.anchor_node, restored.anchor_span, restored.offset, restored.derivation + (key,))

    def return_registers(self):
        parent = self.transport
        self.budget.prepay(len(self.written))
        writes = [span for span in self.written if span.object_id.kind is StorageObjectKind.REGISTER_FILE]
        self.budget.prepay((len(parent.state) + len(self.state)) * (len(writes) + 2) + len(writes))
        parent.state = {span: value for span, value in parent.state.items()
                        if not any(span.overlaps(write) for write in writes)}
        parent.state.update({span: value for span, value in self.state.items()
                             if span.object_id.kind is StorageObjectKind.REGISTER_FILE
                             and any(span.overlaps(write) for write in writes)})
        if getattr(self.budget, "charge_state_scans", False):
            for span in writes:
                parent._record_write(span)
        else:
            parent.written.extend(writes)


def _bound_call(caller, callee, key, *, budget=None):
    calls = []
    for row in caller.analysis.evidence.seeds.callsites:
        if budget is not None:
            budget.count()
        if row.operation_key == key:
            calls.append(row)
    _need(len(calls) == 1 and type(calls[0].target) is DirectCallTarget
          and calls[0].target.coordinate == callee.analysis.entry, "call_target_mismatch")
    call = caller.operation(key)
    _need(call is not None and call.opcode == "CALL" and call.output is None and len(call.inputs) == 1
          and call.inputs[0].kind is VarnodeKindCode.ADDRESS and call.inputs[0].coordinate == callee.analysis.entry
          and caller.operation_flow_targets.get(key) == (callee.analysis.entry,), "call_context_mismatch")


def _execute_prior(caller, leaf, key, parent, operations, audit, transcript, *, protected=None,
                   selected_store_key=None):
    _bound_call(caller, leaf, key, budget=parent.budget if parent.budget.inspection else None)
    def instruction_for(view, operation_key):
        for row in view.observation.instructions:
            parent.budget.inspect()
            for ordinal, operation in enumerate(row.operations):
                parent.budget.inspect()
                if _operation_key(row.address, ordinal, operation.opcode) == operation_key:
                    return row
        raise _Gap("operation_context_unavailable")
    call_instruction = instruction_for(caller, key)
    continuation = call_instruction.fallthrough
    _need(continuation is not None and continuation.space_id == call_instruction.address.space_id
          == leaf.analysis.entry.space_id, "prior_return_space_mismatch")
    child = _PriorReplay(leaf, parent.budget, parent.saved, parent)
    returned, return_key = None, None
    for op_key, operation in operations:
        transcript.append((leaf.scope_digest, op_key))
        if operation.opcode == "STORE":
            access = child.store_access(operation)
            if op_key == selected_store_key:
                _need(access is not None, "source_store_pointer_unproven")
                protected = access
            elif protected is not None:
                _need(access is not None, "intervening_alias_unproven")
                _preserved(protected, access)
            if access is not None:
                audit.append(MemoryWriteAudit(leaf.scope_digest, op_key, *access))
            child.saved.store(child, op_key, operation, access)
        if operation.opcode == "RETURN":
            _need(len(operation.inputs) == 1, "prior_return_operand_unproven")
            instruction = instruction_for(leaf, op_key)
            _need(instruction.address.space_id == continuation.space_id, "prior_return_space_mismatch")
            returned, return_key = child.value(operation.inputs[0]), op_key
            _need(returned.anchor_scope is None and returned.anchor_node is None and returned.anchor_span is None
                  and returned.offset == continuation.byte_offset
                  and returned.width_bits == leaf.space_bits.get(continuation.space_id), "prior_continuation_unproven")
        child.step(op_key, operation)
    _need(returned is not None, "prior_continuation_unproven")
    child.return_registers()
    record = PriorLeafCallWitness(leaf.scope_digest, leaf.analysis.evidence.unit.scopes.function.observation_digest,
                                 key, return_key, continuation, returned, tuple(child.bindings))
    return (record, protected) if selected_store_key is not None else record


@dataclass(frozen=True, slots=True)
class DescendantRegisterEgressWitness:
    """Canonical immutable physical receipt; reports never share cached lists."""
    receipt_bytes: bytes
    source_span: ByteSpan
    read_span: ByteSpan

    def report(self):
        return json.loads(self.receipt_bytes)


@dataclass(frozen=True, slots=True)
class DescendantRegisterEgressResult:
    status: MemoryReadBridgeStatus
    witness: DescendantRegisterEgressWitness | None
    gaps: tuple[str, ...]
    work_units: int = 0


@dataclass(frozen=True, slots=True)
class InnerSourceMemoryEgressWitness:
    receipt_bytes: bytes
    source_span: ByteSpan
    read_span: ByteSpan
    store_span: ByteSpan
    load_span: ByteSpan

    def report(self):
        return json.loads(self.receipt_bytes)


@dataclass(frozen=True, slots=True)
class InnerSourceMemoryEgressResult:
    status: MemoryReadBridgeStatus
    witness: InnerSourceMemoryEgressWitness | None
    gaps: tuple[str, ...]
    work_units: int = 0


def _span_publication_nodes(span):
    return 1 if span is None else 7


def _pointer_publication_nodes(value):
    if value is None:
        return 1
    return 6 + _span_publication_nodes(value.anchor_span) + len(value.derivation)


def _binding_publication_nodes(binding):
    return 2 + _span_publication_nodes(binding.span) + _pointer_publication_nodes(binding.value)


def _event_publication_nodes(event):
    # The independently reported event includes the invocation ordinal.
    return (9 + _pointer_publication_nodes(event.pointer) + _pointer_publication_nodes(event.value)
            + 3 * len(event.invalidated_entries))


class _DescendantPublicationWork:
    """Exact bounded encoder node visits, accumulated beside receipt creation.

    The fixed receipt has one dictionary, sixteen scalars, two six-field
    spans and six lists. Repeated nested occurrences are counted separately;
    no receipt tree is traversed solely to calculate publication work.
    """
    def __init__(self, child_count):
        self.nodes = 37 + child_count

    def operation(self, register_span):
        self.nodes += 4 + 5 + (0 if register_span is None else _span_publication_nodes(register_span))

    def event(self, event):
        self.nodes += _event_publication_nodes(event)

    def invocation(self, return_value, binding_nodes):
        self.nodes += 14 + _pointer_publication_nodes(return_value) + binding_nodes

    def caller_bindings(self, binding_nodes):
        self.nodes += binding_nodes


def _descendant_ordered(view, budget, stop_key=None):
    """New straight nested mode; legacy CALL/LOAD-stop ordering is unchanged."""
    rows = {}
    for row in view.observation.instructions:
        budget.count()
        _need(row.address not in rows, "instruction_identity_ambiguous")
        _need(row.flow is not None, "control_shape_unproven")
        rows[row.address] = row
    predecessors_by_address = {}
    if budget.charge_state_scans:
        for row in rows.values():
            budget.prepay(2 + len(row.flow_targets))
            following = set() if row.flow.is_call else set(row.flow_targets)
            if row.fallthrough is not None:
                following.add(row.fallthrough)
            budget.prepay(len(following))
            for address in following:
                predecessors_by_address.setdefault(address, []).append(row.address)
    current, seen, result = view.analysis.entry, set(), []
    while current in rows and current not in seen:
        budget.count()
        seen.add(current)
        instruction = rows[current]
        flow = instruction.flow
        _need(flow is not None and not any((flow.is_jump, flow.is_computed, flow.is_conditional, flow.is_override)),
              "control_shape_unproven")
        _need(flow.is_call == any(op.opcode in {"CALL", "CALLIND", "CALLOTHER"} for op in instruction.operations),
              "call_context_mismatch")
        for ordinal, operation in enumerate(instruction.operations):
            budget.count()
            key = _operation_key(current, ordinal, operation.opcode)
            result.append((key, operation))
            if key == stop_key:
                _need(not flow.is_call and operation.opcode not in {"CALL", "CALLIND", "CALLOTHER", "RETURN"},
                      "target_read_not_data")
                return tuple(result)
            if operation.opcode in {"CALL", "CALLIND", "CALLOTHER"}:
                _need(operation.opcode == "CALL" and flow.is_call
                      and ordinal == len(instruction.operations) - 1, "call_context_mismatch")
            else:
                _need(operation.opcode not in {"BRANCH", "CBRANCH", "BRANCHIND"}, "control_shape_unproven")
            if operation.opcode == "RETURN":
                _need(stop_key is None and flow.is_terminal and ordinal == len(instruction.operations) - 1,
                      "control_shape_unproven")
        if flow.is_terminal:
            _need(stop_key is None and instruction.fallthrough is None and instruction.operations
                  and instruction.operations[-1].opcode == "RETURN" and seen == set(rows),
                  "normal_return_frontier_unproven")
            return tuple(result)
        _need(flow.has_fallthrough and instruction.fallthrough is not None, "control_shape_unproven")
        following = instruction.fallthrough
        if budget.charge_state_scans:
            budget.prepay(1 + len(predecessors_by_address.get(following, ())))
            predecessors = predecessors_by_address.get(following, ())
        else:
            predecessors = []
            for row in rows.values():
                budget.count()
                if row.fallthrough == following or (not row.flow.is_call and following in row.flow_targets):
                    predecessors.append(row.address)
        _need(predecessors == [current], "caller_order_unproven")
        current = following
    raise _Gap("control_escape_or_cycle")


def _descendant_raw_output(replay, key, operation):
    """Validate real raw output effects, not synthesized CALL write events."""
    replay.budget.count()
    opcode, inputs, output = operation.opcode, operation.inputs, operation.output
    shaped = (_pure_shape(operation) or
              opcode == "COPY" and len(inputs) == 1 and output is not None
              and inputs[0].byte_size == output.byte_size or
              opcode in {"INT_ADD", "INT_SUB"} and len(inputs) == 2 and output is not None
              and all(row.byte_size == output.byte_size for row in inputs) or
              opcode == "LOAD" and len(inputs) == 2 and output is not None or
              opcode == "STORE" and len(inputs) == 3 and output is None or
              opcode in {"CALL", "RETURN"} and len(inputs) == 1 and output is None)
    _need(shaped, "unknown_memory_effect")
    span = None if output is None else replay.span(output)
    _need(span is None or 0 < span.size <= replay.budget.limits.access_bytes, "register_width_unsupported")
    effect = replay.view.storage_actions.get(key)
    if opcode != "CALL":
        _need(effect is not None or key in replay.transients, "operation_effect_unavailable")
        if effect is not None:
            _need(not effect.unresolved_writes or opcode == "STORE", "unknown_memory_effect")
            for write in effect.writes:
                replay.budget.count()
                if write.object_id.kind in {StorageObjectKind.REGISTER_FILE, StorageObjectKind.FUNCTION_UNIQUE}:
                    _need(span is not None and span.contains(write), "unexplained_storage_write")
                else:
                    _need(opcode == "STORE", "non_store_memory_write_unproven")
            if span is not None:
                _need(span in effect.writes, "raw_output_effect_unavailable")
    return span


def _descendant_data_operand(view, key, operation, index, budget):
    _need(type(index) is int and 0 <= index < len(operation.inputs), "read_operand_unavailable")
    _need(operation.opcode not in {"LOAD", "CALL", "CALLIND", "CALLOTHER", "RETURN", "BRANCH", "CBRANCH", "BRANCHIND"}
          and (operation.opcode != "STORE" or index == 2), "target_read_not_data")
    resolved = _resolve_validated_storage(storage_ref(operation.inputs[index]),
                                         view.analysis.evidence.unit.scopes.resolution_context)
    _need(type(resolved) is ResolvedStorage and resolved.span.object_id.kind is StorageObjectKind.REGISTER_FILE,
          "read_register_unavailable")
    matches = []
    for read in view.memory.reads:
        budget.count()
        if view.memory.actions[read.action_id].operation_key == key and read.span == resolved.span:
            for fragment in read.fragments:
                budget.count()
                if fragment.span == resolved.span:
                    matches.append(read)
    _need(len(matches) == 1, "read_fragment_unavailable")
    return resolved.span, view.memory_graph.action_nodes[matches[0].action_id]


def certify_descendant_register_egress(caller, wrapper, outer_call_key, descendant_call_keys,
                                     descendant_definition_key, caller_read_key, *, read_operand_index=0,
                                     invocation_analyses=(), limits=None, charge_state_scans=False):
    return _certify_descendant_egress(caller, wrapper, outer_call_key, descendant_call_keys,
        descendant_definition_key, caller_read_key, read_operand_index=read_operand_index,
        invocation_analyses=invocation_analyses, limits=limits, charge_state_scans=charge_state_scans)


def certify_inner_source_memory_egress(caller, writer, outer_call_key, descendant_call_keys,
                                     source_definition_key, writer_read_key, store_key, caller_load_key, *,
                                     read_operand_index=0, invocation_analyses=(), limits=None):
    """Inner-memory attempts alone default to the ADR68 20,000-step ceiling."""
    if any(type(key) is not str or not key for key in (store_key, caller_load_key)):
        raise TypeError("inner memory egress requires exact STORE/LOAD keys")
    return _certify_descendant_egress(caller, writer, outer_call_key, descendant_call_keys,
        source_definition_key, writer_read_key, read_operand_index=read_operand_index,
        invocation_analyses=invocation_analyses, limits=limits, charge_state_scans=True,
        inner_memory_keys=(store_key, caller_load_key))


def _certify_descendant_egress(caller, wrapper, outer_call_key, descendant_call_keys,
                                     descendant_definition_key, caller_read_key, *, read_operand_index=0,
                                     invocation_analyses=(), limits=None, charge_state_scans=False,
                                     inner_memory_keys=None):
    """Complete bounded observed unwind, independent of any source claim."""
    if limits is not None and type(limits) is not MemoryReadBridgeLimits:
        raise TypeError("egress limits must be exact")
    if type(charge_state_scans) is not bool:
        raise TypeError("state scan charging requires an exact boolean")
    if (type(descendant_call_keys) is not tuple or not 1 <= len(descendant_call_keys) <= 2
            or any(type(k) is not str or not k for k in
                   (outer_call_key, *descendant_call_keys, descendant_definition_key, caller_read_key))
            or type(read_operand_index) is not int or read_operand_index < 0):
        raise TypeError("descendant egress requires exact keys and operand")
    if type(invocation_analyses) is not tuple or any(type(a) is not ConfiguredFunctionAnalysis for a in invocation_analyses):
        raise TypeError("invocation inventory requires exact admitted analyses")
    inner = inner_memory_keys is not None
    defaults = MemoryReadBridgeLimits(steps=20000) if inner else MemoryReadBridgeLimits()
    budget = _Budget(limits or defaults, inspection=True,
                     charge_state_scans=charge_state_scans)
    result_type = InnerSourceMemoryEgressResult if inner else DescendantRegisterEgressResult
    publication = _DescendantPublicationWork(len(descendant_call_keys)) if charge_state_scans and not inner else None
    try:
        budget.count()
        _need(all(getattr(budget.limits, name) <= getattr(defaults, name) for name in
                  ("operations", "steps", "expression_depth", "access_bytes", "map_entries", "map_bytes")),
              "descendant_limits_unsupported")
        caller, wrapper = (_view(a, budget.limits.operations, budget=budget) for a in (caller, wrapper))
        inventory, views = {}, {wrapper.analysis.entry: wrapper}
        for analysis in invocation_analyses:
            budget.count()
            _need(analysis.entry not in inventory, "invocation_entry_ambiguous")
            inventory[analysis.entry] = analysis
        _need(wrapper.analysis.entry not in inventory or inventory[wrapper.analysis.entry] == wrapper.analysis,
              "wrapper_inventory_mismatch")
        inventory[wrapper.analysis.entry] = wrapper.analysis
        targets = {}
        def target(view, key):
            identity = view.analysis.entry, key
            if charge_state_scans:
                budget.prepay(1)
                if identity in targets:
                    return targets[identity]
            matches = []
            for seed in view.analysis.evidence.seeds.callsites:
                budget.count()
                if seed.operation_key == key:
                    matches.append(seed)
            _need(len(matches) == 1 and type(matches[0].target) is DirectCallTarget, "call_target_mismatch")
            entry = matches[0].target.coordinate
            _need(entry in inventory, "callee_body_unavailable")
            if entry not in views:
                views[entry] = _view(inventory[entry], budget.limits.operations, budget=budget)
            body = views[entry]
            _need(body.analysis.evidence.unit.scopes.program == caller.analysis.evidence.unit.scopes.program,
                  "program_context_mismatch")
            _bound_call(view, body, key, budget=budget)
            if charge_state_scans:
                budget.prepay(1)
                targets[identity] = body
            return body
        _bound_call(caller, wrapper, outer_call_key, budget=budget)
        chain = [wrapper]
        for key in descendant_call_keys:
            chain.append(target(chain[-1], key))
        descendant = chain[-1]
        definitions = []
        for i, row in enumerate(descendant.memory.definitions):
            budget.count()
            if row.kind is MemoryDefinitionKind.DATA_WRITE and row.operation_key == descendant_definition_key:
                definitions.append((i, row))
        _need(len(definitions) == 1, "descendant_definition_unavailable")
        definition_id, definition = definitions[0]
        operation = descendant.operation(descendant_definition_key)
        _need(operation is not None and operation.output is not None
              and definition.span.object_id.kind is StorageObjectKind.REGISTER_FILE,
              "descendant_register_definition_unavailable")
        source_resolved = _resolve_validated_storage(storage_ref(operation.output),
                        descendant.analysis.evidence.unit.scopes.resolution_context)
        _need(type(source_resolved) is ResolvedStorage and source_resolved.span == definition.span,
              "descendant_source_identity_mismatch")
        source_node = descendant.memory_graph.definition_nodes[definition_id]
        source_action = descendant.memory_graph.action_nodes[descendant.action_ids[descendant_definition_key]]
        defining_edge = False
        if charge_state_scans:
            _prepay_graph_edges(descendant.normalized.dependencies, budget.prepay)
        for a, b, edge in descendant.normalized.dependencies.weighted_edges():
            budget.count()
            if (a == source_action and b == source_node and edge.kind == "memory_defines"
                    and edge.operation == descendant_definition_key and edge.span == definition.span):
                defining_edge = True
        _need(defining_edge, "descendant_defining_edge_unavailable")
        root_ops = _descendant_ordered(caller, budget, inner_memory_keys[1] if inner else caller_read_key)
        reader_view = wrapper if inner else caller
        reader = reader_view.operation(caller_read_key)
        _need(reader is not None, "read_operation_unavailable")
        read_span, read_node = _descendant_data_operand(reader_view, caller_read_key, reader, read_operand_index, budget)
        _need(definition.span.contains(read_span), "read_bytes_not_contained")
        store_definition = store_node = store_action = load_span = load_node = None
        if inner:
            store_key, load_key = inner_memory_keys
            matches = []
            for index, row in enumerate(wrapper.memory.definitions):
                budget.count()
                if row.kind is MemoryDefinitionKind.DATA_WRITE and row.operation_key == store_key:
                    matches.append((index, row))
            _need(len(matches) == 1 and wrapper.operation(store_key) is not None
                  and wrapper.operation(store_key).opcode == "STORE", "source_definition_unavailable")
            store_id, store_definition = matches[0]
            _need(store_definition.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE,
                  "egress_relative_memory_required")
            store_node = wrapper.memory_graph.definition_nodes[store_id]
            store_action = wrapper.memory_graph.action_nodes[wrapper.action_ids[store_key]]
            _prepay_graph_edges(wrapper.normalized.dependencies, budget.prepay)
            defining = False
            for a, b, edge in wrapper.normalized.dependencies.weighted_edges():
                budget.count()
                if (a == store_action and b == store_node and edge.kind == "memory_defines"
                        and edge.operation == store_key and edge.span == store_definition.span):
                    defining = True
            _need(defining, "store_defining_edge_unavailable")
            loads = []
            for row in caller.memory.reads:
                budget.count()
                if (caller.memory.actions[row.action_id].operation_key == load_key
                        and row.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE):
                    loads.append(row)
            _need(len(loads) == 1 and caller.operation(load_key) is not None
                  and caller.operation(load_key).opcode == "LOAD", "egress_read_span_unavailable")
            load_span = loads[0].span
            load_node = caller.memory_graph.action_nodes[loads[0].action_id]
        schedules = {}
        def schedule(view):
            if view.analysis.entry not in schedules:
                schedules[view.analysis.entry] = _descendant_ordered(view, budget)
            return schedules[view.analysis.entry]
        # A known later raw output in this same straight body is already a
        # conclusive failure. Do not replay an identical whole outer prefix to
        # discover that failure for every earlier candidate definition.
        after_source = False
        def early_output(view, op):
            if op.output is None:
                return
            resolved = _resolve_validated_storage(storage_ref(op.output), view.analysis.evidence.unit.scopes.resolution_context)
            if type(resolved) is ResolvedStorage:
                _need(not resolved.span.overlaps(definition.span), "descendant_register_clobbered")
        for key, op in schedule(descendant):
            budget.count()
            if after_source:
                early_output(descendant, op)
                if op.opcode == "CALL":
                    _need(len(chain) < 3, "recursive_or_depth_unsupported")
                    body = target(descendant, key)
                    _need(body.analysis.entry not in {v.analysis.entry for v in chain}
                          and body.analysis.entry != caller.analysis.entry, "recursive_or_depth_unsupported")
                    for _, body_operation in schedule(body):
                        budget.count()
                        _need(body_operation.opcode not in {"CALL", "CALLIND", "CALLOTHER"}, "nonchain_body_not_leaf")
                        early_output(body, body_operation)
            if key == descendant_definition_key:
                after_source = True
        _need(after_source, "descendant_definition_unavailable")
        saved = _SavedValues(budget)
        root = _PriorReplay(caller, budget, saved)
        transcript, audit, records, event_rows = [], [], [], []
        protected, selected, executed, wrapper_ordinal = None, None, 0, None
        reader_seen, store_access, load_access = False, None, None
        memory_audit = []
        instruction_indices = {}
        def instruction(view, key):
            if charge_state_scans:
                identity = view.analysis.entry
                budget.prepay(1)
                if identity not in instruction_indices:
                    index = {}
                    for row in view.observation.instructions:
                        budget.prepay(1 + 2 * len(row.operations))
                        for ordinal, op in enumerate(row.operations):
                            index[_operation_key(row.address, ordinal, op.opcode)] = row
                    instruction_indices[identity] = index
                _need(key in instruction_indices[identity], "operation_context_unavailable")
                return instruction_indices[identity][key]
            for row in view.observation.instructions:
                budget.count()
                for ordinal, op in enumerate(row.operations):
                    budget.count()
                    if _operation_key(row.address, ordinal, op.opcode) == key:
                        return row
            raise _Gap("operation_context_unavailable")
        def run(replay, operations, ordinal, depth, active, selected_level=None):
            nonlocal protected, selected, executed, wrapper_ordinal
            nonlocal reader_seen, store_access, load_access
            returned = None
            for key, op in operations:
                budget.count()
                executed += 1
                _need(executed <= budget.limits.operations, "operation_budget_exhausted")
                output = _descendant_raw_output(replay, key, op)
                budget.prepay(16)
                transcript.append({"invocation_ordinal": ordinal, "scope": replay.view.scope_digest.hex(), "operation_key": key})
                writes = [] if output is None or output.object_id.kind is not StorageObjectKind.REGISTER_FILE else [span_fact(output)]
                audit.append({"invocation_ordinal": ordinal, "scope": replay.view.scope_digest.hex(), "operation_key": key, "writes": writes})
                if publication is not None:
                    publication.operation(output if writes else None)
                is_source = selected_level == len(descendant_call_keys) and key == descendant_definition_key
                is_reader = (selected_level == 0 if inner else ordinal == 0) and key == caller_read_key
                is_store = inner and selected_level == 0 and key == inner_memory_keys[0]
                is_load = inner and ordinal == 0 and key == inner_memory_keys[1]
                if inner and is_reader:
                    _need(selected is not None and protected is not None and not reader_seen,
                          "inner_source_reader_order_unproven")
                    reader_seen = True
                    protected = None
                if protected is not None and output is not None and not is_reader:
                    _need(not output.overlaps(protected), "descendant_register_clobbered")
                if is_source:
                    _need(protected is None and output == definition.span, "descendant_source_identity_mismatch")
                before_events = len(saved.events)
                if op.opcode == "STORE":
                    access = replay.store_access(op)
                    if inner:
                        if is_store:
                            _need(reader_seen and store_access is None and access is not None,
                                  "inner_source_store_order_unproven")
                            _need(access[2] == store_definition.span.size, "egress_access_width_mismatch")
                            store_access = access
                        elif store_access is not None and load_access is None:
                            _need(access is not None, "intervening_alias_unproven")
                            _preserved(store_access, access)
                        budget.prepay(20 + (0 if access is None else len(access[1].derivation)))
                        memory_audit.append({"invocation_ordinal": ordinal, "scope": replay.view.scope_digest.hex(),
                            "operation_key": key, "address_space_id": op.inputs[0].coordinate.byte_offset,
                            "pointer": None if access is None else access[1].report(),
                            "byte_size": op.inputs[2].byte_size})
                    saved.store(replay, key, op, access)
                if is_load:
                    _need(store_access is not None and wrapper_ordinal is not None,
                          "inner_source_load_order_unproven")
                    load_access = replay.access(op)
                    _need(load_access is not None and load_access[2] == load_span.size,
                          "egress_access_width_mismatch")
                if op.opcode == "RETURN":
                    returned = key, replay.value(op.inputs[0])
                replay.step(key, op)
                budget.prepay(len(saved.events) - before_events)
                for event in saved.events[before_events:]:
                    budget.prepay(20 + len(event.invalidated_entries) * 3
                                  + (0 if event.pointer is None else len(event.pointer.derivation))
                                  + (0 if event.value is None else len(event.value.derivation)))
                    event_rows.append({"invocation_ordinal": ordinal, **event.report()})
                    if publication is not None:
                        publication.event(event)
                if is_source:
                    protected, selected = definition.span, ordinal
                if op.opcode != "CALL":
                    continue
                body = target(replay.view, key)
                _need(body.analysis.entry not in active and depth < 3, "recursive_or_depth_unsupported")
                next_level = None
                if ordinal == 0 and key == outer_call_key:
                    next_level = 0
                elif selected_level is not None and selected_level < len(descendant_call_keys) and key == descendant_call_keys[selected_level]:
                    next_level = selected_level + 1
                    _need(body.analysis.entry == chain[next_level].analysis.entry, "descendant_chain_mismatch")
                body_ops = schedule(body)
                if next_level is None:
                    for _, body_operation in body_ops:
                        budget.count()
                        _need(body_operation.opcode not in {"CALL", "CALLIND", "CALLOTHER"}, "nonchain_body_not_leaf")
                _need(len(records) < 8, "invocation_count_unsupported")
                child_ordinal = len(records) + 1
                records.append(None)
                if ordinal == 0 and key == outer_call_key:
                    wrapper_ordinal = child_ordinal
                continuation = instruction(replay.view, key).fallthrough
                _need(continuation is not None and continuation.space_id == body.analysis.entry.space_id,
                      "prior_return_space_mismatch")
                child = _PriorReplay(body, budget, saved, replay)
                ret = run(child, body_ops, child_ordinal, depth + 1,
                          active | {body.analysis.entry}, next_level)
                _need(ret is not None, "prior_continuation_unproven")
                return_key, value = ret
                _need(value.anchor == (value.width_bits, None, None, None)
                      and value.offset == continuation.byte_offset
                      and value.width_bits == body.space_bits.get(continuation.space_id), "prior_continuation_unproven")
                _need(instruction(body, return_key).address.space_id == continuation.space_id, "prior_return_space_mismatch")
                child.return_registers()
                budget.prepay(len(child.bindings))
                binding_work, binding_nodes = 0, 0
                for binding in child.bindings:
                    binding_work += 20 + len(binding.value.derivation)
                    if publication is not None:
                        binding_nodes += _binding_publication_nodes(binding)
                budget.prepay(24 + len(value.derivation) + binding_work)
                record = PriorLeafCallWitness(body.scope_digest, body.analysis.evidence.unit.scopes.function.observation_digest,
                    key, return_key, continuation, value, tuple(child.bindings)).report()
                records[child_ordinal - 1] = {"invocation_ordinal": child_ordinal,
                    "parent_invocation_ordinal": ordinal, "depth": depth + 1,
                    "caller_scope": replay.view.scope_digest.hex(),
                    "caller_observation_digest": replay.view.analysis.evidence.unit.scopes.function.observation_digest.hex(),
                    **record}
                if publication is not None:
                    publication.invocation(value, binding_nodes)
            return returned
        run(root, root_ops, 0, 0, frozenset({caller.analysis.entry}))
        _need(selected is not None and wrapper_ordinal is not None, "selected_descendant_invocation_unavailable")
        if inner:
            _need(reader_seen and store_access is not None and load_access is not None
                  and store_access[0] == load_access[0]
                  and _covers(store_access[1], store_access[2], load_access[1], load_access[2]),
                  "pointer_alias_unproven")
            _need(store_access[1].anchor_scope == caller.scope_digest
                  and store_access[1].anchor_node is not None
                  and load_access[1].anchor == store_access[1].anchor,
                  "egress_caller_entry_anchor_required")
        continuation = instruction(caller, outer_call_key).fallthrough
        addresses = []
        after = False
        for key, _ in root_ops:
            if after:
                coordinate = instruction(caller, key).address
                if coordinate not in addresses:
                    addresses.append(coordinate)
            if key == outer_call_key:
                after = True
        _need(addresses and addresses[0] == continuation and len(addresses) <= 32,
              "outer_continuation_budget_exhausted")
        budget.prepay(len(root.bindings))
        binding_work, binding_nodes = 0, 0
        for binding in root.bindings:
            binding_work += 20 + len(binding.value.derivation)
            if publication is not None:
                binding_nodes += _binding_publication_nodes(binding)
        budget.prepay(40 + len(descendant_call_keys) + binding_work)
        if publication is not None:
            publication.caller_bindings(binding_nodes)
        if inner:
            budget.prepay(180 + len(store_access[1].derivation) + len(load_access[1].derivation))
            receipt = {"kind": "observed_inner_source_memory_egress", "version": 1,
                "premise": "configured-observed-shared-state-v1",
                "caller_scope": caller.scope_digest.hex(),
                "caller_observation_digest": caller.analysis.evidence.unit.scopes.function.observation_digest.hex(),
                "writer_scope": wrapper.scope_digest.hex(),
                "writer_observation_digest": wrapper.analysis.evidence.unit.scopes.function.observation_digest.hex(),
                "source_scope": descendant.scope_digest.hex(),
                "source_observation_digest": descendant.analysis.evidence.unit.scopes.function.observation_digest.hex(),
                "outer_call_operation_key": outer_call_key,
                "descendant_call_operation_keys": list(descendant_call_keys),
                "selected_writer_invocation_ordinal": wrapper_ordinal,
                "selected_source_invocation_ordinal": selected,
                "source_endpoint": {"operation_key": descendant_definition_key,
                    "definition_node": source_node, "action_node": source_action, "span": span_fact(definition.span)},
                "writer_reader": {"operation_key": caller_read_key, "action_node": read_node,
                    "operand_index": read_operand_index, "span": span_fact(read_span)},
                "store_endpoint": {"operation_key": inner_memory_keys[0], "definition_node": store_node,
                    "action_node": store_action, "span": span_fact(store_definition.span)},
                "load_endpoint": {"operation_key": inner_memory_keys[1], "action_node": load_node,
                    "span": span_fact(load_span)},
                "memory_transfer": {"address_space_id": store_access[0], "store_byte_size": store_access[2],
                    "load_byte_size": load_access[2], "store_pointer": store_access[1].report(),
                    "load_pointer": load_access[1].report()},
                "caller_entry_bindings": [{"node": b.node, "span": span_fact(b.span), "value": b.value.report()}
                                          for b in root.bindings],
                "operation_transcript": transcript, "invocations": records,
                "register_write_audit": audit, "pointer_memory_events": event_rows,
                "memory_write_audit": memory_audit}
            # Pay for publication before encoding; each container expansion is
            # charged before allocating its worklist entries.
            pending = [receipt]
            while pending:
                budget.count()
                row = pending.pop()
                if type(row) is dict:
                    budget.prepay(len(row) + 1)
                    pending.extend(row.values())
                elif type(row) is list:
                    budget.prepay(len(row) + 1)
                    pending.extend(row)
            witness = InnerSourceMemoryEgressWitness(wire(receipt), definition.span, read_span,
                                                     store_definition.span, load_span)
            return result_type(MemoryReadBridgeStatus.VERIFIED_MAY, witness, (), budget.used)
        receipt = {"kind": "observed_descendant_register_egress", "version": 1,
            "premise": "configured-observed-shared-state-v1",
            "caller_scope": caller.scope_digest.hex(), "caller_observation_digest": caller.analysis.evidence.unit.scopes.function.observation_digest.hex(),
            "wrapper_scope": wrapper.scope_digest.hex(), "wrapper_observation_digest": wrapper.analysis.evidence.unit.scopes.function.observation_digest.hex(),
            "descendant_scope": descendant.scope_digest.hex(), "descendant_observation_digest": descendant.analysis.evidence.unit.scopes.function.observation_digest.hex(),
            "outer_call_operation_key": outer_call_key, "descendant_call_operation_keys": list(descendant_call_keys),
            "source_write_operation_key": descendant_definition_key, "target_read_operation_key": caller_read_key,
            "target_read_operand_index": read_operand_index, "source_definition_node": source_node,
            "target_read_action_node": read_node, "source_span": span_fact(definition.span), "read_span": span_fact(read_span),
            "selected_invocation_ordinal": selected,
            "caller_entry_bindings": [{"node": b.node, "span": span_fact(b.span), "value": b.value.report()} for b in root.bindings],
            "operation_transcript": transcript, "invocations": records, "register_write_audit": audit,
            "pointer_memory_events": event_rows}
        if publication is not None:
            budget.prepay(publication.nodes)
        witness = DescendantRegisterEgressWitness(wire(receipt), definition.span, read_span)
        return DescendantRegisterEgressResult(MemoryReadBridgeStatus.VERIFIED_MAY, witness, (), budget.used)
    except _Gap as gap:
        return result_type(MemoryReadBridgeStatus.PARTIAL, None, (str(gap),), budget.used)


def certify_call_memory_read_bridge(caller, callee, call_key, store_key, load_key, *, limits=None,
                                   prior_leaf_analyses=(), prefix_leaf_analyses=None):
    """Mint from admitted observations; report transcripts are never inputs."""
    if limits is not None and type(limits) is not MemoryReadBridgeLimits:
        raise TypeError("bridge limits must be exact")
    if any(type(key) is not str or not key for key in (call_key, store_key, load_key)):
        raise TypeError("bridge operation keys must be nonempty exact strings")
    if type(prior_leaf_analyses) is not tuple or any(type(row) is not ConfiguredFunctionAnalysis
                                                   for row in prior_leaf_analyses):
        raise TypeError("prior leaf analyses require an exact tuple of admitted analyses")
    if prefix_leaf_analyses is not None and (type(prefix_leaf_analyses) is not tuple or any(
            type(row) is not ConfiguredFunctionAnalysis for row in prefix_leaf_analyses)):
        raise TypeError("prefix leaf analyses require an exact tuple of admitted analyses")
    if prefix_leaf_analyses is not None and prior_leaf_analyses:
        raise TypeError("prefix inventory and legacy prior modes are mutually exclusive")
    try:
        budget = _Budget(limits or MemoryReadBridgeLimits(), inspection=True)
        budget.count()
        _need(callee is not None, "callee_body_unavailable")
        caller = _view(caller, budget.limits.operations, budget=budget)
        callee = _view(callee, budget.limits.operations, budget=budget)
        _need(caller.analysis.evidence.unit.scopes.program == callee.analysis.evidence.unit.scopes.program,
              "program_context_mismatch")
        _need(caller.analysis.entry != callee.analysis.entry, "recursive_call_unsupported")
        _bound_call(caller, callee, call_key, budget=budget)
        prefix_mode = prefix_leaf_analyses is not None
        earlier, invocations = (), {}
        if prefix_mode:
            leaves = {}
            for analysis in prefix_leaf_analyses:
                budget.count()
                _need(analysis.entry not in leaves, "leaf_entry_ambiguous")
                leaves[analysis.entry] = analysis
            allowed = []
            for key, (_, operation) in caller.operations.items():
                budget.count()
                if key != call_key and operation.opcode in {"CALL", "CALLIND", "CALLOTHER"}:
                    allowed.append(key)
            caller_ops = _ordered(caller, call_key, prior_call_keys=allowed, budget=budget)
            calls = []
            for key, operation in caller_ops:
                budget.count()
                if key != call_key and operation.opcode in {"CALL", "CALLIND", "CALLOTHER"}:
                    calls.append(key)
            _need(len(calls) <= 8, "leaf_call_count_unsupported")
            earlier = tuple(calls)
            for key in earlier:
                seeds = []
                for seed in caller.analysis.evidence.seeds.callsites:
                    budget.count()
                    if seed.operation_key == key:
                        seeds.append(seed)
                _need(len(seeds) == 1 and type(seeds[0].target) is DirectCallTarget, "call_target_mismatch")
                entry = seeds[0].target.coordinate
                _need(entry != caller.analysis.entry, "recursive_call_unsupported")
                _need(entry in leaves, "callee_body_unavailable")
                prior = _view(leaves[entry], budget.limits.operations, budget=budget)
                _need(prior.analysis.evidence.unit.scopes.program == caller.analysis.evidence.unit.scopes.program,
                      "program_context_mismatch")
                _bound_call(caller, prior, key, budget=budget)
                invocations[key] = prior, _ordered(prior, None, leaf=True, budget=budget)
        else:
            _need(len(prior_leaf_analyses) <= 1, "prior_leaf_count_unsupported")
        if not prefix_mode and prior_leaf_analyses:
            _need(store_key in caller.operations, "source_store_not_admitted")
            calls = []
            for key, (position, operation) in caller.operations.items():
                budget.count()
                if (operation.opcode in {"CALL", "CALLIND", "CALLOTHER"} and key != call_key
                        and position < caller.operations[store_key][0]):
                    calls.append(key)
            earlier = tuple(calls)
            _need(len(earlier) <= 1, "prior_leaf_count_unsupported")
            if earlier:
                prior = _view(prior_leaf_analyses[0], budget.limits.operations, budget=budget)
                _need(prior.analysis.evidence.unit.scopes.program == caller.analysis.evidence.unit.scopes.program,
                      "program_context_mismatch")
                _need(prior.analysis.entry != caller.analysis.entry, "recursive_call_unsupported")
                _bound_call(caller, prior, earlier[0], budget=budget)
                invocations[earlier[0]] = prior, _ordered(prior, None, leaf=True, budget=budget)
        if not prefix_mode:
            caller_ops = _ordered(caller, call_key, prior_call_keys=earlier, budget=budget)
        callee_ops = _ordered(callee, load_key, leaf=True, budget=budget)
        _need(len(caller_ops) + len(callee_ops) + sum(len(operations) for _, operations in invocations.values())
              <= budget.limits.operations, "operation_budget_exhausted")
        saved = _SavedValues(budget) if earlier or prefix_mode else None
        replay = _Replay(caller, budget) if saved is None else _PriorReplay(caller, budget, saved)
        source, audit, transcript, prior_records = None, [], [], []
        for key, operation in caller_ops:
            transcript.append((caller.scope_digest, key))
            if operation.opcode == "STORE":
                access = replay.access(operation) if saved is None else replay.store_access(operation)
                if access is not None:
                    audit.append(MemoryWriteAudit(caller.scope_digest, key, *access))
                if key == store_key:
                    _need(access is not None, "source_store_pointer_unproven")
                    source = access
                elif source is not None:
                    _need(access is not None, "intervening_alias_unproven")
                    _preserved(source, access)
                if saved is not None:
                    saved.store(replay, key, operation, access)
            replay.step(key, operation)
            if key in earlier:
                if not prefix_mode:
                    _need(source is None, "prior_call_after_source_store")
                prior, operations = invocations[key]
                prior_records.append(_execute_prior(caller, prior, key, replay, operations, audit, transcript,
                                                    protected=source if prefix_mode else None))
        _need(source is not None, "source_store_not_admitted")
        definitions = []
        for i, row in enumerate(caller.memory.definitions):
            budget.count()
            if (row.kind is MemoryDefinitionKind.DATA_WRITE and row.operation_key == store_key
                    and row.span.size == source[2]):
                definitions.append((i, row))
        _need(len(definitions) == 1, "source_definition_unavailable")
        definition_id, definition = definitions[0]
        target, target_action = None, callee.action_ids.get(load_key)
        child = _Replay(callee, budget, replay) if saved is None else _PriorReplay(callee, budget, saved, replay)
        for key, operation in callee_ops:
            transcript.append((callee.scope_digest, key))
            if key == load_key:
                _need(operation.opcode == "LOAD" and target_action is not None, "target_load_not_admitted")
                target = child.access(operation)
                child.step(key, operation)
                break
            if operation.opcode == "STORE":
                access = child.access(operation) if saved is None else child.store_access(operation)
                _need(access is not None, "intervening_alias_unproven")
                audit.append(MemoryWriteAudit(callee.scope_digest, key, *access))
                _preserved(source, access)
                if saved is not None:
                    saved.store(child, key, operation, access)
            child.step(key, operation)
        _need(target is not None and source[0] == target[0]
              and _covers(source[1], source[2], target[1], target[2]), "pointer_alias_unproven")
        witness = CallMemoryReadBridgeWitness(caller.scope_digest, callee.scope_digest,
            caller.analysis.evidence.unit.scopes.function.observation_digest,
            callee.analysis.evidence.unit.scopes.function.observation_digest,
            call_key, store_key, load_key, caller.memory_graph.definition_nodes[definition_id],
            callee.memory_graph.action_nodes[target_action], definition.span, source[0], target[2],
            source[1], target[1], tuple(child.bindings), tuple(transcript), tuple(audit),
            tuple(prior_records), () if saved is None else tuple(saved.events), prefix_mode)
        return CallMemoryReadBridgeResult(MemoryReadBridgeStatus.VERIFIED_MAY, witness, (), budget.used)
    except _Gap as gap:
        return CallMemoryReadBridgeResult(MemoryReadBridgeStatus.PARTIAL, None, (str(gap),), budget.used)


def _preserved(source, write):
    _need(source[0] == write[0] and source[1].anchor == write[1].anchor, "intervening_alias_unproven")
    _need(not any(a < d and c < b for a, b in _pieces(source[1], source[2])
                  for c, d in _pieces(write[1], write[2])), "intervening_memory_overwrite")


@dataclass(frozen=True, slots=True)
class LocalCallMemoryPreservationWitness:
    caller_scope: bytes
    caller_observation_digest: bytes
    store_operation_key: str
    load_operation_key: str
    source_definition_node: int
    target_load_action_node: int
    source_span: ByteSpan
    read_span: ByteSpan
    address_space_id: int
    byte_size: int
    store_pointer: AffinePointerValue
    load_pointer: AffinePointerValue
    caller_entry_bindings: tuple[PointerEntryBinding, ...]
    operation_transcript: tuple[tuple[bytes, str], ...]
    write_audit: tuple[MemoryWriteAudit, ...]
    prior_leaf_calls: tuple[PriorLeafCallWitness, ...]
    pointer_memory_events: tuple[PointerMemoryEvent, ...]
    full_read_span: ByteSpan | None = None
    read_fragments: tuple[tuple[ByteSpan, tuple[int, ...]], ...] = ()
    fragment_byte_offset: int = 0

    def __post_init__(self):
        if (self.full_read_span is not None and type(self.full_read_span) is not ByteSpan
                or type(self.read_fragments) is not tuple
                or type(self.fragment_byte_offset) is not int or self.fragment_byte_offset < 0):
            raise TypeError("fragment receipt requires exact immutable fields")
        for row in self.read_fragments:
            if (type(row) is not tuple or len(row) != 2 or type(row[0]) is not ByteSpan
                    or type(row[1]) is not tuple or not row[1]
                    or any(type(node) is not int or node < 0 for node in row[1])):
                raise TypeError("fragment inventory requires immutable spans and definition nodes")

    def report(self):
        report = {"kind": "observed_local_call_memory_preservation", "version": 1,
                "premise": "configured-observed-shared-state-v1",
                "caller_scope": self.caller_scope.hex(),
                "caller_observation_digest": self.caller_observation_digest.hex(),
                "store_operation_key": self.store_operation_key, "load_operation_key": self.load_operation_key,
                "source_definition_node": self.source_definition_node,
                "target_load_action_node": self.target_load_action_node,
                "source_span": span_fact(self.source_span), "read_span": span_fact(self.read_span),
                "address_space_id": self.address_space_id, "byte_size": self.byte_size,
                "store_pointer": self.store_pointer.report(), "load_pointer": self.load_pointer.report(),
                "caller_entry_bindings": [{"node": row.node, "span": span_fact(row.span),
                                            "value": row.value.report()} for row in self.caller_entry_bindings],
                "operation_transcript": [{"scope": scope.hex(), "operation_key": key}
                                         for scope, key in self.operation_transcript],
                "write_audit": [{"scope": row.scope.hex(), "operation_key": row.operation_key,
                                 "address_space_id": row.address_space_id, "pointer": row.pointer.report(),
                                 "byte_size": row.byte_size} for row in self.write_audit],
                "prior_leaf_calls": [row.report() for row in self.prior_leaf_calls],
                "pointer_memory_events": [row.report() for row in self.pointer_memory_events]}
        if self.full_read_span is not None:
            report.update(version=2, full_read_span=span_fact(self.full_read_span),
                          read_fragments=[{"span": span_fact(span), "definitions": list(nodes)}
                                          for span, nodes in self.read_fragments],
                          fragment_byte_offset=self.fragment_byte_offset)
        return report


@dataclass(frozen=True, slots=True)
class LocalCallMemoryPreservationResult:
    status: MemoryReadBridgeStatus
    witness: LocalCallMemoryPreservationWitness | None
    gaps: tuple[str, ...]
    work_units: int = 0


@dataclass(frozen=True, slots=True)
class CallMemoryEgressWitness:
    caller_scope: bytes
    callee_scope: bytes
    caller_observation_digest: bytes
    callee_observation_digest: bytes
    call_operation_key: str
    store_operation_key: str
    load_operation_key: str
    source_definition_node: int
    target_load_action_node: int
    source_span: ByteSpan
    read_span: ByteSpan
    address_space_id: int
    byte_size: int
    store_pointer: AffinePointerValue
    load_pointer: AffinePointerValue
    caller_entry_bindings: tuple[PointerEntryBinding, ...]
    operation_transcript: tuple[tuple[bytes, str], ...]
    write_audit: tuple[MemoryWriteAudit, ...]
    prior_leaf_calls: tuple[PriorLeafCallWitness, ...]
    writer_return: PriorLeafCallWitness
    pointer_memory_events: tuple[PointerMemoryEvent, ...]
    continuation_leaf_calls: tuple[PriorLeafCallWitness, ...] = ()
    continuation_mode: bool = False

    def report(self):
        report = {"kind": "observed_leaf_call_memory_egress", "version": 2 if self.continuation_mode else 1,
                "premise": "configured-observed-shared-state-v1",
                "caller_scope": self.caller_scope.hex(), "callee_scope": self.callee_scope.hex(),
                "caller_observation_digest": self.caller_observation_digest.hex(),
                "callee_observation_digest": self.callee_observation_digest.hex(),
                "call_operation_key": self.call_operation_key, "store_operation_key": self.store_operation_key,
                "load_operation_key": self.load_operation_key,
                "source_definition_node": self.source_definition_node,
                "target_load_action_node": self.target_load_action_node,
                "source_span": span_fact(self.source_span), "read_span": span_fact(self.read_span),
                "address_space_id": self.address_space_id, "byte_size": self.byte_size,
                "store_pointer": self.store_pointer.report(), "load_pointer": self.load_pointer.report(),
                "caller_entry_bindings": [{"node": row.node, "span": span_fact(row.span), "value": row.value.report()}
                                          for row in self.caller_entry_bindings],
                "operation_transcript": [{"scope": scope.hex(), "operation_key": key}
                                         for scope, key in self.operation_transcript],
                "write_audit": [{"scope": row.scope.hex(), "operation_key": row.operation_key,
                                 "address_space_id": row.address_space_id, "pointer": row.pointer.report(),
                                 "byte_size": row.byte_size} for row in self.write_audit],
                "prior_leaf_calls": [row.report() for row in self.prior_leaf_calls],
                "writer_return": self.writer_return.report(),
                "pointer_memory_events": [row.report() for row in self.pointer_memory_events]}
        if self.continuation_mode:
            report["continuation_leaf_calls"] = [row.report() for row in self.continuation_leaf_calls]
        return report


@dataclass(frozen=True, slots=True)
class CallMemoryEgressResult:
    status: MemoryReadBridgeStatus
    witness: CallMemoryEgressWitness | None
    gaps: tuple[str, ...]
    work_units: int = 0


def _egress_structure_work(witness, budget):
    """Bound the v2 nested wire structures before any report serialization."""
    def pointer(value):
        budget.count()
        _need(len(value.derivation) <= budget.limits.expression_depth, "expression_budget_exhausted")
        for _ in value.derivation:
            budget.count()
    def bindings(rows):
        _need(len(rows) <= budget.limits.operations, "operation_budget_exhausted")
        for row in rows:
            budget.count()
            pointer(row.value)
    pointer(witness.store_pointer)
    pointer(witness.load_pointer)
    bindings(witness.caller_entry_bindings)
    for row in (*witness.prior_leaf_calls, witness.writer_return, *witness.continuation_leaf_calls):
        budget.count()
        pointer(row.return_value)
        bindings(row.entry_bindings)
    for rows in (witness.operation_transcript, witness.write_audit, witness.pointer_memory_events):
        _need(len(rows) <= budget.limits.operations, "operation_budget_exhausted")
        for row in rows:
            budget.count()
            if type(row) is MemoryWriteAudit:
                pointer(row.pointer)
            elif type(row) is PointerMemoryEvent:
                if row.pointer is not None:
                    pointer(row.pointer)
                if row.value is not None:
                    pointer(row.value)
                _need(len(row.invalidated_entries) <= budget.limits.map_entries, "saved_map_budget_exhausted")
                for _ in row.invalidated_entries:
                    budget.count()


def certify_call_memory_egress(caller, writer, call_key, store_key, load_key, *, prefix_leaf_analyses=(),
                               continuation_leaf_analyses=None, limits=None):
    """Replay a complete writer and its caller continuation; derive no origins."""
    if limits is not None and type(limits) is not MemoryReadBridgeLimits:
        raise TypeError("egress limits must be exact")
    if any(type(key) is not str or not key for key in (call_key, store_key, load_key)):
        raise TypeError("egress keys require nonempty exact strings")
    if type(prefix_leaf_analyses) is not tuple or any(type(row) is not ConfiguredFunctionAnalysis
                                                     for row in prefix_leaf_analyses):
        raise TypeError("egress inventory requires an exact analyses tuple")
    continuation_mode = continuation_leaf_analyses is not None
    if continuation_mode and (type(continuation_leaf_analyses) is not tuple or any(
            type(row) is not ConfiguredFunctionAnalysis for row in continuation_leaf_analyses)):
        raise TypeError("egress continuation inventory requires an exact analyses tuple")
    effective_limits = limits or MemoryReadBridgeLimits()
    if continuation_mode:
        defaults = MemoryReadBridgeLimits()
        effective_limits = MemoryReadBridgeLimits(**{name: min(getattr(effective_limits, name), getattr(defaults, name))
            for name in ("operations", "steps", "expression_depth", "access_bytes", "map_entries", "map_bytes")})
    budget = _Budget(effective_limits, inspection=True)
    try:
        budget.count()
        _need(writer is not None, "callee_body_unavailable")
        caller = _view(caller, budget.limits.operations, budget=budget)
        writer = _view(writer, budget.limits.operations, budget=budget)
        _need(caller.analysis.evidence.unit.scopes.program == writer.analysis.evidence.unit.scopes.program,
              "program_context_mismatch")
        _need(caller.analysis.entry != writer.analysis.entry, "recursive_call_unsupported")
        _bound_call(caller, writer, call_key, budget=budget)
        inventory = {}
        for analysis in prefix_leaf_analyses:
            budget.count()
            _need(analysis.entry not in inventory, "leaf_entry_ambiguous")
            inventory[analysis.entry] = analysis
        continuation_inventory = {}
        for analysis in continuation_leaf_analyses or ():
            budget.count()
            _need(analysis.entry not in continuation_inventory, "leaf_entry_ambiguous")
            if analysis.entry in inventory:
                before = inventory[analysis.entry].evidence.unit.scopes.function
                after = analysis.evidence.unit.scopes.function
                _need(before == after, "leaf_observation_mismatch")
            continuation_inventory[analysis.entry] = analysis
        allowed = []
        for key, (_, operation) in caller.operations.items():
            budget.count()
            if operation.opcode in {"CALL", "CALLIND", "CALLOTHER"}:
                allowed.append(key)
        prefix = _ordered(caller, load_key, prior_call_keys=allowed, read_stop=True, budget=budget)
        calls, continuation, after_writer = [], set(), False
        for key, operation in prefix:
            budget.count()
            if after_writer:
                continuation.add(caller.instruction_operation_keys[key])
                _need(len(continuation) <= 32, "egress_continuation_budget_exhausted")
            if key == call_key:
                after_writer = True
            if operation.opcode in {"CALL", "CALLIND", "CALLOTHER"}:
                calls.append(key)
        if not continuation_mode:
            _need(calls and calls[-1] == call_key, "egress_call_after_writer_unsupported")
        _need(calls.count(call_key) == 1, "egress_writer_call_unavailable")
        writer_index = calls.index(call_key)
        prior_keys, continuation_keys = calls[:writer_index], calls[writer_index + 1:]
        if continuation_mode:
            _need(bool(continuation_keys), "egress_continuation_call_required")
        else:
            _need(not continuation_keys, "egress_call_after_writer_unsupported")
        _need(len(calls) <= 9, "leaf_call_count_unsupported")
        writer_ops = _ordered(writer, None, leaf=True, budget=budget)
        invocations, raw_count = {}, len(prefix) + len(writer_ops)
        for key in prior_keys + continuation_keys:
            seeds = []
            for seed in caller.analysis.evidence.seeds.callsites:
                budget.count()
                if seed.operation_key == key:
                    seeds.append(seed)
            _need(len(seeds) == 1 and type(seeds[0].target) is DirectCallTarget, "call_target_mismatch")
            entry = seeds[0].target.coordinate
            _need(entry != caller.analysis.entry, "recursive_call_unsupported")
            phase_inventory = inventory if key in prior_keys else continuation_inventory
            _need(entry in phase_inventory, "callee_body_unavailable")
            leaf = _view(phase_inventory[entry], budget.limits.operations, budget=budget)
            _need(leaf.analysis.evidence.unit.scopes.program == caller.analysis.evidence.unit.scopes.program,
                  "program_context_mismatch")
            _bound_call(caller, leaf, key, budget=budget)
            operations = _ordered(leaf, None, leaf=True, budget=budget)
            raw_count += len(operations)
            _need(raw_count <= budget.limits.operations, "operation_budget_exhausted")
            invocations[key] = leaf, operations
        _need(raw_count <= budget.limits.operations, "operation_budget_exhausted")
        definitions = []
        for index, definition in enumerate(writer.memory.definitions):
            budget.count()
            if definition.kind is MemoryDefinitionKind.DATA_WRITE and definition.operation_key == store_key:
                definitions.append((index, definition))
        _need(len(definitions) == 1 and writer.operation(store_key) is not None
              and writer.operation(store_key).opcode == "STORE", "source_definition_unavailable")
        definition_id, definition = definitions[0]
        _need(definition.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE, "egress_relative_memory_required")
        reads = []
        for read in caller.memory.reads:
            budget.count()
            if (caller.memory.actions[read.action_id].operation_key == load_key
                    and read.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE):
                reads.append(read)
        _need(len(reads) == 1, "egress_read_span_unavailable")
        read = reads[0]
        replay = _PriorReplay(caller, budget, _SavedValues(budget))
        source, target, returned, audit, transcript, records, continuation_records = None, None, None, [], [], [], []
        for key, operation in prefix:
            transcript.append((caller.scope_digest, key))
            if operation.opcode == "STORE":
                access = replay.store_access(operation)
                if source is not None:
                    _need(access is not None, "intervening_alias_unproven")
                    _preserved(source, access)
                if access is not None:
                    audit.append(MemoryWriteAudit(caller.scope_digest, key, *access))
                replay.saved.store(replay, key, operation, access)
            if key == load_key:
                target = replay.access(operation)
            replay.step(key, operation)
            if key == call_key:
                returned, source = _execute_prior(caller, writer, key, replay, writer_ops, audit, transcript,
                                                  selected_store_key=store_key)
                _need(source is not None, "source_store_not_admitted")
            elif key in invocations:
                leaf, operations = invocations[key]
                record = _execute_prior(caller, leaf, key, replay, operations, audit, transcript,
                                        protected=source if key in continuation_keys else None)
                (continuation_records if key in continuation_keys else records).append(record)
        _need(source is not None and target is not None and returned is not None
              and source[0] == target[0] and _covers(source[1], source[2], target[1], target[2]),
              "pointer_alias_unproven")
        _need(source[1].anchor_scope == caller.scope_digest and source[1].anchor_node is not None,
              "egress_caller_entry_anchor_required")
        _need(definition.span.size == source[2] and read.span.size == target[2], "egress_access_width_mismatch")
        witness = CallMemoryEgressWitness(caller.scope_digest, writer.scope_digest,
            caller.analysis.evidence.unit.scopes.function.observation_digest,
            writer.analysis.evidence.unit.scopes.function.observation_digest, call_key, store_key, load_key,
            writer.memory_graph.definition_nodes[definition_id], caller.memory_graph.action_nodes[read.action_id],
            definition.span, read.span, source[0], target[2], source[1], target[1], tuple(replay.bindings),
            tuple(transcript), tuple(audit), tuple(records), returned, tuple(replay.saved.events),
            tuple(continuation_records), continuation_mode)
        if continuation_mode:
            _egress_structure_work(witness, budget)
        return CallMemoryEgressResult(MemoryReadBridgeStatus.VERIFIED_MAY, witness, (), budget.used)
    except _Gap as gap:
        return CallMemoryEgressResult(MemoryReadBridgeStatus.PARTIAL, None, (str(gap),), budget.used)


def certify_local_call_memory_preservation(caller, store_key, load_key, *, leaf_analyses=(), limits=None,
                                          fragment_span=None):
    """Prove preservation of one authentic local edge, without deriving origins."""
    if limits is not None and type(limits) is not MemoryReadBridgeLimits:
        raise TypeError("bridge limits must be exact")
    if fragment_span is not None and type(fragment_span) is not ByteSpan:
        raise TypeError("fragment span must be an exact ByteSpan")
    if any(type(key) is not str or not key for key in (store_key, load_key)):
        raise TypeError("preservation operation keys must be nonempty exact strings")
    if type(leaf_analyses) is not tuple or any(type(row) is not ConfiguredFunctionAnalysis
                                              for row in leaf_analyses):
        raise TypeError("leaf analyses require an exact tuple of admitted analyses")
    effective_limits = limits or MemoryReadBridgeLimits()
    if fragment_span is not None:
        defaults = MemoryReadBridgeLimits()
        effective_limits = MemoryReadBridgeLimits(**{name: min(getattr(effective_limits, name), getattr(defaults, name))
            for name in ("operations", "steps", "expression_depth", "access_bytes", "map_entries", "map_bytes")})
    try:
        budget = _Budget(effective_limits, inspection=True)
        budget.count()
        caller = _view(caller, budget.limits.operations, budget=budget)
        leaves = {}
        for row in leaf_analyses:
            budget.count()
            _need(row.entry not in leaves, "leaf_entry_ambiguous")
            leaves[row.entry] = row
        load = caller.operation(load_key)
        store = caller.operation(store_key)
        _need(load is not None and load.opcode == "LOAD" and load.output is not None
              and load_key in caller.action_ids, "target_load_not_admitted")
        if fragment_span is not None:
            _need(0 < load.output.byte_size <= budget.limits.access_bytes, "memory_width_unsupported")
        _need(store is not None and store.opcode == "STORE" and len(store.inputs) == 3,
              "source_store_not_admitted")
        calls = []
        for key, (_, op) in caller.operations.items():
            budget.count()
            if op.opcode in {"CALL", "CALLIND", "CALLOTHER"}:
                calls.append(key)
        prefix = _ordered(caller, load_key, prior_call_keys=calls, read_stop=True, budget=budget)
        call_keys, source_seen = [], False
        for key, op in prefix:
            budget.count()
            source_seen |= key == store_key and key != load_key
            if op.opcode in {"CALL", "CALLIND", "CALLOTHER"}:
                call_keys.append(key)
        _need(source_seen, "source_store_order_unproven")
        _need(len(call_keys) <= 8, "leaf_call_count_unsupported")
        invocations, raw_count = {}, len(prefix)
        for key in call_keys:
            callsites = []
            for row in caller.analysis.evidence.seeds.callsites:
                budget.count()
                if row.operation_key == key:
                    callsites.append(row)
            _need(len(callsites) == 1 and type(callsites[0].target) is DirectCallTarget, "call_target_mismatch")
            entry = callsites[0].target.coordinate
            _need(entry != caller.analysis.entry, "recursive_call_unsupported")
            _need(entry in leaves, "callee_body_unavailable")
            leaf = _view(leaves[entry], budget.limits.operations, budget=budget)
            _need(leaf.analysis.evidence.unit.scopes.program == caller.analysis.evidence.unit.scopes.program,
                  "program_context_mismatch")
            _bound_call(caller, leaf, key, budget=budget)
            operations = _ordered(leaf, None, leaf=True, budget=budget)
            raw_count += len(operations)
            _need(raw_count <= budget.limits.operations, "operation_budget_exhausted")
            invocations[key] = leaf, operations
        definitions = []
        for i, row in enumerate(caller.memory.definitions):
            budget.count()
            if (row.kind is MemoryDefinitionKind.DATA_WRITE and row.operation_key == store_key
                    and row.span.size == store.inputs[2].byte_size):
                definitions.append((i, row))
        _need(len(definitions) == 1, "source_definition_unavailable")
        definition_id, definition = definitions[0]
        source_node = caller.memory_graph.definition_nodes[definition_id]
        action_id = caller.action_ids[load_key]
        target_node = caller.memory_graph.action_nodes[action_id]
        edges = []
        for source, target, edge in caller.normalized.dependencies.weighted_edges():
            budget.count()
            if (source == source_node and target == target_node and edge.kind == "memory_read"
                    and edge.operation == load_key and edge.span is not None
                    and (fragment_span is None or edge.span == fragment_span)):
                edges.append(edge)
        for row in caller.memory.unresolved_reads:
            budget.count()
            _need(row.action_id != action_id, "target_read_unresolved")
        _need(len(edges) == 1, "local_memory_read_edge_unavailable")
        read_span = edges[0].span
        full_read_span, read_fragments, fragment_byte_offset = None, (), 0
        if fragment_span is None:
            _need(read_span.size == load.output.byte_size and definition.span.contains(read_span),
                  "full_load_span_unproven")
        else:
            reads = []
            for read in caller.memory.reads:
                budget.count()
                if (read.action_id == action_id and read.span.contains(read_span)
                        and read.span.size == load.output.byte_size):
                    reads.append(read)
            _need(len(reads) == 1, "full_read_span_unavailable")
            read = reads[0]
            _need(read.span != read_span and definition.span.contains(read_span), "proper_fragment_unproven")
            _need(len(read.fragments) <= load.output.byte_size, "full_read_partition_unproven")
            for _ in read.fragments:
                budget.count()  # Charge the bounded inventory before sorting it.
            inventory, selected, cursor = [], 0, read.span.start
            for fragment in sorted(read.fragments, key=lambda row: row.span.start):
                _need(read.span.contains(fragment.span) and fragment.span.start == cursor,
                      "full_read_partition_unproven")
                nodes = []
                for definition_index in fragment.definition_ids:
                    budget.count()
                    _need(type(definition_index) is int and 0 <= definition_index < len(caller.memory.definitions),
                          "read_fragment_definition_unavailable")
                    sibling = caller.memory.definitions[definition_index]
                    _need(sibling.span.contains(fragment.span), "read_fragment_definition_span_mismatch")
                    nodes.append(caller.memory_graph.definition_nodes[definition_index])
                _need(bool(nodes) and len(set(nodes)) == len(nodes), "read_fragment_definition_unavailable")
                selected += fragment.span == read_span and source_node in nodes
                inventory.append((fragment.span, tuple(nodes)))
                cursor = fragment.span.end
            _need(cursor == read.span.end and selected == 1, "full_read_partition_unproven")
            full_read_span, read_fragments = read.span, tuple(inventory)
            fragment_byte_offset = read_span.start - read.span.start
            budget.count()  # Exact modular byte projection is additional admitted work.
        saved = _SavedValues(budget)
        replay = _PriorReplay(caller, budget, saved)
        source, target, audit, transcript, prior_records = None, None, [], [], []
        for key, operation in prefix:
            transcript.append((caller.scope_digest, key))
            if operation.opcode == "STORE":
                access = replay.store_access(operation)
                if key == store_key:
                    _need(access is not None, "source_store_pointer_unproven")
                    source = access
                elif source is not None:
                    _need(access is not None, "intervening_alias_unproven")
                    _preserved(source, access)
                if access is not None:
                    audit.append(MemoryWriteAudit(caller.scope_digest, key, *access))
                saved.store(replay, key, operation, access)
            if key == load_key:
                target = replay.access(operation)
            replay.step(key, operation)
            if key in invocations:
                leaf, operations = invocations[key]
                prior_records.append(_execute_prior(caller, leaf, key, replay, operations, audit,
                                                    transcript, protected=source))
        _need(source is not None and target is not None, "pointer_alias_unproven")
        projected = target[1]
        projected_size = target[2]
        if fragment_span is not None:
            projected = AffinePointerValue(target[1].width_bits, target[1].anchor_scope,
                target[1].anchor_node, target[1].anchor_span,
                (target[1].offset + fragment_byte_offset) % (1 << target[1].width_bits), target[1].derivation)
            projected_size = read_span.size
        _need(source[0] == target[0] and _covers(source[1], source[2], projected, projected_size),
              "pointer_alias_unproven")
        modulus = 1 << source[1].width_bits
        _need((projected.offset - source[1].offset) % modulus
              == (read_span.start - definition.span.start) % modulus,
              "physical_read_displacement_mismatch")
        witness = LocalCallMemoryPreservationWitness(caller.scope_digest,
            caller.analysis.evidence.unit.scopes.function.observation_digest, store_key, load_key,
            source_node, target_node, definition.span, read_span, source[0], target[2], source[1], target[1],
            tuple(replay.bindings), tuple(transcript), tuple(audit), tuple(prior_records), tuple(saved.events),
            full_read_span, read_fragments, fragment_byte_offset)
        return LocalCallMemoryPreservationResult(MemoryReadBridgeStatus.VERIFIED_MAY, witness, (), budget.used)
    except _Gap as gap:
        return LocalCallMemoryPreservationResult(MemoryReadBridgeStatus.PARTIAL, None, (str(gap),), budget.used)
