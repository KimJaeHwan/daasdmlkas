"""Narrow must-overwrite certificate for an observed direct CALL continuation.

This does not mutate local SSA or claim ABI result/argument roles. It only
certifies a conditional diagnostic replacement of stale local read edges.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..call_contracts import DirectCallTarget
from ..call_seeds import _operation_key
from ..memory_contracts import MemoryDefinitionKind
from ..model import ByteSpan, ResolvedStorage, StorageObjectKind
from ..storage import _resolve_validated_storage
from .configured_value_domain import storage_ref
from .configured_interprocedural_contracts import InterproceduralTransferProof
from .configured_function_view import _FunctionView
from .configured_interprocedural_records import WriteEvent


MAX_CERTIFICATE_INSTRUCTIONS = 4096
MAX_CONTINUATION_HOPS = 32
_CONTROL_OPCODES = frozenset({
    "CALL", "CALLIND", "CALLOTHER", "RETURN", "BRANCH", "BRANCHIND",
    "CBRANCH",
})


@dataclass(frozen=True, slots=True)
class CallByteCoverReplacement:
    original_transfer: InterproceduralTransferProof
    reader_operation_key: str
    reader_node: int
    demanded_span: ByteSpan
    source_definition_id: int
    terminal_cover: tuple[tuple[str, int, tuple[tuple[int, ByteSpan, tuple[int, ...]], ...]], ...]
    superseded_fragments: tuple[tuple[ByteSpan, tuple[int, ...]], ...]

    def __post_init__(self):
        if (type(self.original_transfer) is not InterproceduralTransferProof or type(self.reader_operation_key) is not str
                or type(self.reader_node) is not int or type(self.source_definition_id) is not int
                or type(self.demanded_span) is not ByteSpan or type(self.terminal_cover) is not tuple
                or type(self.superseded_fragments) is not tuple):
            raise TypeError("call-byte cover fields must be exact immutable identities")
        for exit in self.terminal_cover:
            if (type(exit) is not tuple or len(exit) != 3 or type(exit[0]) is not str
                    or type(exit[1]) is not int or type(exit[2]) is not tuple):
                raise TypeError("terminal cover exits must be immutable native identities")
            for atom in exit[2]:
                if (type(atom) is not tuple or len(atom) != 3 or type(atom[0]) is not int
                        or type(atom[1]) is not ByteSpan or type(atom[2]) is not tuple
                        or any(type(item) is not int for item in atom[2])):
                    raise TypeError("terminal cover atoms must be immutable native identities")
        for fragment in self.superseded_fragments:
            if (type(fragment) is not tuple or len(fragment) != 2 or type(fragment[0]) is not ByteSpan
                    or type(fragment[1]) is not tuple or any(type(item) is not int for item in fragment[1])):
                raise TypeError("superseded fragments must be immutable graph identities")


def certify_call_byte_cover_replacement(caller, callee, event, read, reachable_nodes, *, charge):
    """Cover one full authentic caller operand using a narrow terminal hint."""
    if (type(caller) is not _FunctionView or type(callee) is not _FunctionView
            or type(event) is not WriteEvent or type(reachable_nodes) is not frozenset or not callable(charge)):
        raise TypeError("call-byte cover requires exact observed views and a charge callback")
    charge(1)
    if (len(caller.observation.instructions) > MAX_CERTIFICATE_INSTRUCTIONS
            or len(callee.observation.instructions) > MAX_CERTIFICATE_INSTRUCTIONS
            or event.caller_scope_digest != caller.scope_digest or event.callee_scope_digest != callee.scope_digest
            or event.callee_entry != callee.analysis.entry or event.pointer_dereferences != 0
            or event.target_path is not None):
        return None
    admitted = False
    for candidate in caller.memory.reads:
        charge(1)
        admitted |= candidate is read
    if not admitted or type(read.action_id) is not int or not 0 <= read.action_id < len(caller.memory.actions):
        return None
    action = caller.memory.actions[read.action_id]
    reader_key, demand = action.operation_key, read.span
    reader_node = caller.memory_graph.action_nodes[read.action_id]
    if (reader_node not in reachable_nodes or demand.object_id.kind is not StorageObjectKind.REGISTER_FILE
            or not 0 < demand.size <= 64 or not demand.contains(event.target_span) or event.target_span == demand
            or caller.effective_access_span(reader_key, demand, read=True) != demand):
        return None
    operation = caller.operation(reader_key)
    if operation is None or operation.opcode in {
            "LOAD", "CALL", "CALLIND", "CALLOTHER", "RETURN", "BRANCH", "CBRANCH", "BRANCHIND"}:
        return None
    operands = operation.inputs
    if operation.opcode == "STORE":
        if len(operands) != 3:
            return None
        operands = operands[2:]
    raw_operands = []
    for operand in operands:
        charge(1)
        raw = _resolve_validated_storage(storage_ref(operand), caller.analysis.evidence.unit.scopes.resolution_context)
        if type(raw) is ResolvedStorage and raw.span == demand:
            raw_operands.append(raw.span)
    if len(raw_operands) != 1:
        return None
    for unresolved in caller.memory.unresolved_reads:
        charge(1)
        if unresolved.action_id == read.action_id:
            return None
    sources = []
    for definition_id, definition in enumerate(callee.memory.definitions):
        charge(1)
        if (definition.operation_key == event.callee_write_operation_key
                and definition.kind is MemoryDefinitionKind.DATA_WRITE and definition.span == demand):
            sources.append(definition_id)
    if len(sources) != 1:
        return None
    source_id = sources[0]
    cover = callee.terminal_data_write_cover(source_id, demand, charge=charge)
    if cover is None:
        return None
    charge(len(callee.memory.observed_terminal_states) * (
        1 + len(callee.memory.state_nodes) + 2 * len(callee.memory.atomic_spans)
        + sum(len(node.definition_ids) for node in callee.memory.state_nodes)))
    terminal_rows = callee.terminal_data_writes()
    candidates, hints = [], []
    for definition_id, span in terminal_rows:
        charge(1)
        definition = callee.memory.definitions[definition_id]
        if definition.operation_key == event.callee_write_operation_key:
            if span.contains(demand):
                candidates.append(definition_id)
            if span == event.target_span:
                hints.append(definition_id)
    if candidates or len(hints) != 1:
        return None
    if hints[0] != source_id:
        return None
    source = callee.memory.definitions[source_id]
    if source.kind is not MemoryDefinitionKind.DATA_WRITE or not source.span.contains(event.target_span):
        return None
    if not all(any(atom == event.target_span and ids == (source_id,)
                                   for _, atom, ids in fragments) for _, _, fragments in cover):
        return None
    fragments, cursor = [], demand.start
    if len(read.fragments) > demand.size:
        return None
    charge(len(read.fragments))
    for fragment in sorted(read.fragments, key=lambda row: row.span.start):
        if not demand.contains(fragment.span) or fragment.span.start != cursor:
            return None
        old_nodes = []
        for definition_id in fragment.definition_ids:
            charge(1)
            if type(definition_id) is not int or not 0 <= definition_id < len(caller.memory.definitions):
                return None
            definition = caller.memory.definitions[definition_id]
            if (not definition.span.contains(fragment.span) or definition.kind is not MemoryDefinitionKind.ENTRY
                    and (definition.kind is not MemoryDefinitionKind.DATA_WRITE or definition.operation_key is None
                         or not caller.definitely_precedes(definition.operation_key, event.call_operation_key))):
                return None
            old_nodes.append(caller.memory_graph.definition_nodes[definition_id])
        if not old_nodes or len(set(old_nodes)) != len(old_nodes):
            return None
        fragments.append((fragment.span, tuple(sorted(old_nodes))))
        cursor = fragment.span.end
    if cursor != demand.end:
        return None
    # Existing continuation scans are charged at their bounded worst-case work
    # before invocation; their legacy semantics and outputs remain unchanged.
    for view in (caller, callee):
        charge(len(view.observation.instructions) or 1)
        for instruction in view.observation.instructions:
            charge(len(instruction.operations) or 1)
    call_site, reader_site = _site(caller, event.call_operation_key), _site(caller, reader_key)
    if call_site is None or reader_site is None:
        return None
    call_instruction, call_ordinal = call_site
    reader_instruction, reader_ordinal = reader_site
    call = call_instruction.operations[call_ordinal]
    if (call.opcode != "CALL" or call_ordinal != len(call_instruction.operations) - 1
            or call_instruction.flow is None or not call_instruction.flow.is_call
            or call_instruction.flow_targets != (callee.analysis.entry,) or caller.analysis.entry == callee.analysis.entry
            or event.call_position != caller.position(event.call_operation_key)):
        return None
    seeds = []
    for seed in caller.analysis.evidence.seeds.callsites:
        charge(1)
        if seed.operation_key == event.call_operation_key:
            seeds.append(seed)
    if len(seeds) != 1 or type(seeds[0].target) is not DirectCallTarget or seeds[0].target.coordinate != callee.analysis.entry:
        return None
    charge(MAX_CONTINUATION_HOPS * (1 + len(caller.observation.instructions)))
    for instruction in caller.observation.instructions:
        charge(MAX_CONTINUATION_HOPS * (1 + len(instruction.operations)))
    if not _unique_stable_continuation(caller, call_instruction, reader_instruction, demand):
        return None
    for ordinal in range(reader_ordinal):
        charge(1)
        operation = reader_instruction.operations[ordinal]
        effect = caller.storage_actions.get(_operation_key(reader_instruction.address, ordinal, operation.opcode))
        if (operation.opcode in {"CALL", "CALLIND", "CALLOTHER"} or effect is None
                or effect.unresolved_writes or any(write.overlaps(demand) for write in effect.writes)):
            return None
    charge(1 + len(fragments) + sum(1 + len(nodes) for _, nodes in fragments)
           + sum(1 + sum(1 + len(ids) for _, _, ids in rows) for _, _, rows in cover))
    return CallByteCoverReplacement(event.transfer, reader_key, reader_node, demand, source_id, cover, tuple(fragments))


def certify_call_byte_replacement(
    caller: _FunctionView,
    callee: _FunctionView,
    event: WriteEvent,
    read,
    fragment,
    reachable_nodes: frozenset[int],
) -> tuple[int, tuple[int, ...]] | None:
    """Return (reader node, old definition nodes) only for a must-write cut.

    `None` means no replacement, never an empty source or a negative proof.
    The admitted observed CFG and shared-state model are explicit premises.
    """
    if (type(caller) is not _FunctionView or type(callee) is not _FunctionView
            or type(event) is not WriteEvent
            or type(reachable_nodes) is not frozenset):
        raise TypeError("call-byte certificate requires exact observed views")
    if (len(caller.observation.instructions) > MAX_CERTIFICATE_INSTRUCTIONS
            or len(callee.observation.instructions) > MAX_CERTIFICATE_INSTRUCTIONS):
        return None
    action = caller.memory.actions[read.action_id]
    reader_key = action.operation_key
    reader_node = caller.memory_graph.action_nodes[read.action_id]
    span = fragment.span
    if (reader_node not in reachable_nodes
            or span.object_id.kind is not StorageObjectKind.REGISTER_FILE
            or event.pointer_dereferences != 0
            or event.target_path is not None
            or not event.target_span.contains(span)
            or caller.effective_access_span(reader_key, span, read=True) != span):
        return None
    if not any(
        definition.operation_key == event.callee_write_operation_key
        and terminal_span.contains(span)
        for definition_id, terminal_span in callee.terminal_data_writes()
        for definition in (callee.memory.definitions[definition_id],)
    ):
        return None
    terminals = tuple(
        instruction for instruction in callee.observation.instructions
        if instruction.flow is not None and instruction.flow.is_terminal
    )
    if (not terminals or len(terminals) != len(callee.memory.observed_terminal_states)
            or any(not instruction.operations
                   or instruction.operations[-1].opcode != "RETURN"
                   for instruction in terminals)):
        return None

    call_site = _site(caller, event.call_operation_key)
    reader_site = _site(caller, reader_key)
    if call_site is None or reader_site is None:
        return None
    call_instruction, call_ordinal = call_site
    reader_instruction, reader_ordinal = reader_site
    call_operation = call_instruction.operations[call_ordinal]
    if (call_operation.opcode != "CALL"
            or call_ordinal != len(call_instruction.operations) - 1
            or call_instruction.flow is None
            or not call_instruction.flow.is_call
            or call_instruction.flow_targets != (event.callee_entry,)
            or callee.analysis.entry == caller.analysis.entry):
        return None
    seeds = tuple(
        seed for seed in caller.analysis.evidence.seeds.callsites
        if seed.operation_key == event.call_operation_key
    )
    if (len(seeds) != 1 or type(seeds[0].target) is not DirectCallTarget
            or seeds[0].target.coordinate != event.callee_entry
            or callee.analysis.entry != event.callee_entry):
        return None
    if not _unique_stable_continuation(
        caller, call_instruction, reader_instruction, span,
    ):
        return None
    for ordinal in range(reader_ordinal):
        operation = reader_instruction.operations[ordinal]
        key = _operation_key(reader_instruction.address, ordinal, operation.opcode)
        intervening = caller.storage_actions.get(key)
        if (operation.opcode in {"CALL", "CALLIND", "CALLOTHER"}
                or intervening is None
                or any(write.overlaps(span) for write in intervening.writes)
                or intervening.unresolved_writes):
            return None

    old_nodes = []
    for definition_id in fragment.definition_ids:
        definition = caller.memory.definitions[definition_id]
        if (definition.kind is not MemoryDefinitionKind.ENTRY
                and (definition.kind is not MemoryDefinitionKind.DATA_WRITE
                     or definition.operation_key is None
                     or not caller.definitely_precedes(
                         definition.operation_key, event.call_operation_key
                     ))):
            return None
        old_nodes.append(caller.memory_graph.definition_nodes[definition_id])
    if not old_nodes:
        return None
    return reader_node, tuple(sorted(set(old_nodes)))


def _site(view: _FunctionView, operation_key: str):
    for instruction in view.observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            if _operation_key(instruction.address, ordinal, operation.opcode) == operation_key:
                return instruction, ordinal
    return None


def _observed_predecessors(view: _FunctionView, target):
    addresses = {row.address for row in view.observation.instructions}
    predecessors = set()
    for instruction in view.observation.instructions:
        if instruction.fallthrough == target:
            predecessors.add(instruction.address)
        # A CALL's target is not an intra-function jump predecessor. Keep its
        # observed caller fallthrough, but do not let an unrelated CALLIND's
        # unknown callee poison an earlier read. This does not certify bytes
        # across that call; the protected continuation still forbids calls.
        if instruction.flow is not None and instruction.flow.is_call:
            continue
        if (instruction.flow is not None and instruction.flow.is_computed
                and not instruction.flow_targets):
            return ()
        if target in instruction.flow_targets and target in addresses:
            predecessors.add(instruction.address)
    return tuple(sorted(predecessors))


def _unique_stable_continuation(view, call_instruction, reader_instruction, span):
    """Admit only a bounded, uniquely entered, non-clobbering fallthrough."""
    by_address = {
        instruction.address: instruction
        for instruction in view.observation.instructions
    }
    if len(by_address) != len(view.observation.instructions):
        return False
    current = call_instruction
    seen = {current.address}
    for _ in range(MAX_CONTINUATION_HOPS):
        following = current.fallthrough
        if following is None or following in seen:
            return False
        next_instruction = by_address.get(following)
        if (next_instruction is None
                or _observed_predecessors(view, following) != (current.address,)):
            return False
        if next_instruction.address == reader_instruction.address:
            return True
        flow = next_instruction.flow
        if (flow is None or not flow.has_fallthrough
                or flow.is_call or flow.is_jump or flow.is_terminal
                or flow.is_computed or flow.is_conditional or flow.is_override
                or next_instruction.flow_targets):
            return False
        for ordinal, operation in enumerate(next_instruction.operations):
            if operation.opcode in _CONTROL_OPCODES:
                return False
            key = _operation_key(next_instruction.address, ordinal, operation.opcode)
            effect = view.storage_actions.get(key)
            if (effect is None or effect.unresolved_writes
                    or any(write.overlaps(span) for write in effect.writes)):
                return False
        seen.add(next_instruction.address)
        current = next_instruction
    return False


__all__ = ("certify_call_byte_replacement", "certify_call_byte_cover_replacement", "CallByteCoverReplacement")
