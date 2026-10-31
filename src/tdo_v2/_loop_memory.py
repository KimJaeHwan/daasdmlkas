"""Occurrence-qualified affine memory effects over the ORIGINAL SSA.

These are weak graph relations, NOT exact storage objects or read-from facts.
S(k) denotes the induction bytes at a particular header visit, initialized
by the complete original entry edge. It is never an activation-wide atom.
No trip count, buffer extent, non-aliasing or successful access is inferred.
"""

from collections import deque
from dataclasses import dataclass, field

from ._scope_contracts import AddressSpaceClassV2, VarnodeKindCode, classify_address_space_v2
from ._ssa_cycles import SsaCycleIndex
from .memory_contracts import MemoryDefinitionKind, MemoryFlowEdge
from .model import ByteSpan, ResolvedStorage, StorageObjectKind, StorageRef, StorageScopeId, VarnodeKind
from .resource_limits import step
from .storage import _resolve_validated_storage


@dataclass(frozen=True, slots=True)
class LoopMemoryFamily:
    header: str
    latch: str
    preheader: str
    blocks: tuple[str, ...]
    span: ByteSpan
    entry_edges: tuple[MemoryFlowEdge, ...]
    backedge_edges: tuple[MemoryFlowEdge, ...]
    transition_definition_id: int
    stride: int
    address_bits: int

    def __post_init__(self):
        if any(type(key) is not str or not key for key in (self.header, self.latch, self.preheader)) \
                or type(self.blocks) is not tuple or not self.blocks or len(set(self.blocks)) != len(self.blocks) \
                or any(type(key) is not str or not key for key in self.blocks) \
                or self.header not in self.blocks or self.latch not in self.blocks or self.preheader in self.blocks:
            raise ValueError("loop family requires distinct original entry/backedge evidence")
        if type(self.span) is not ByteSpan or self.span.object_id.kind is not StorageObjectKind.REGISTER_FILE \
                or type(self.address_bits) is not int or self.address_bits != 8 * self.span.size \
                or type(self.stride) is not int or not 0 < self.stride < 1 << self.address_bits \
                or type(self.transition_definition_id) is not int or self.transition_definition_id < 0:
            raise ValueError("loop family requires a full-width modular induction")
        for edges, source in ((self.entry_edges, self.preheader), (self.backedge_edges, self.latch)):
            if type(edges) is not tuple or not edges or any(type(row) is not MemoryFlowEdge
                    or row.predecessor_key != source or row.block_key != self.header for row in edges):
                raise ValueError("loop family edges must name its original entry and backedge")


@dataclass(frozen=True, slots=True)
class LoopMemoryAccess:
    family_index: int
    operation_key: str
    direction: str
    space_id: int
    width: int
    offset: int
    address_span: ByteSpan
    address_definition_id: int

    def __post_init__(self):
        if self.direction not in ("read", "write") or type(self.operation_key) is not str or not self.operation_key \
                or any(type(value) is not int or value < 0 for value in
                       (self.family_index, self.space_id, self.offset, self.address_definition_id)) \
                or type(self.width) is not int or self.width <= 0 or type(self.address_span) is not ByteSpan:
            raise ValueError("loop memory access requires exact original operation/address references")


_DERIVATION_AUTHORITY = object()


@dataclass(frozen=True, slots=True)
class _Derivation:
    authority: object
    ssa: object
    inputs: tuple
    payload: tuple


@dataclass(frozen=True, slots=True)
class LoopMemoryPlan:
    function_scope: StorageScopeId
    unit_digest: bytes
    families: tuple[LoopMemoryFamily, ...]
    accesses: tuple[LoopMemoryAccess, ...]
    # Process-local authority, not a serializable proof or an independent
    # re-derivation. Immutable SSA/input identities and the entire public
    # payload are pinned without copying their graphs or memory states.
    _proof: _Derivation | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        _check_origin(self)
        if type(self.function_scope) is not StorageScopeId or type(self.unit_digest) is not bytes \
                or len(self.unit_digest) != 32 or type(self.families) is not tuple or not self.families \
                or any(type(row) is not LoopMemoryFamily for row in self.families) \
                or type(self.accesses) is not tuple or not self.accesses \
                or any(type(row) is not LoopMemoryAccess for row in self.accesses):
            raise TypeError("loop memory plan requires exact bound SSA evidence")
        if len({(row.header, row.span) for row in self.families}) != len(self.families) \
                or len({(row.operation_key, row.direction) for row in self.accesses}) != len(self.accesses):
            raise ValueError("loop family/access identities must be unique")
        for row in self.accesses:
            if row.family_index >= len(self.families):
                raise ValueError("loop access must reference its own family")
            family = self.families[row.family_index]
            if row.address_span.size * 8 != family.address_bits or row.offset >= 1 << family.address_bits:
                raise ValueError("loop access width/offset must match its family")


def derive_loop_memory(memory, ssa, observation, entry, context, address_spaces):
    """Describe supported unresolved raw LOAD/STOREs without changing SSA.

    One full-span induction write per iteration, a single entry/backedge and
    a DAG between visits are deliberately required. Unsupported cases retain
    their original unresolved access, not a guessed recurrence.
    """
    if not ssa.joins or not (ssa.unresolved_reads or ssa.unresolved_writes):
        return None
    index = _Index(memory, ssa, observation, entry, context)
    if not index.cyclic or not index.ssa_matches or index.cfg.unsupported is not None:
        return None
    families, accesses, admitted = [], [], {}
    spaces = {row.space_id: row for row in address_spaces}
    occurrences = (("read", ssa.unresolved_reads), ("write", ssa.unresolved_writes))
    for direction, rows in occurrences:
        for row in rows:
            step()
            key = ssa.actions[row.action_id].operation_key
            operation = index.raw.get(key)
            if operation is None or operation.opcode != ("LOAD" if direction == "read" else "STORE") \
                    or len(operation.inputs) != (2 if direction == "read" else 3) \
                    or operation.inputs[0].kind is not VarnodeKindCode.CONSTANT:
                continue
            width = operation.output.byte_size if direction == "read" and operation.output is not None \
                else operation.inputs[2].byte_size if direction == "write" else None
            space = spaces.get(operation.inputs[0].coordinate.byte_offset)
            if width is None or space is None or space.addressable_unit_bytes != 1 \
                    or space.classification_revision != 2 or classify_address_space_v2(space) is not AddressSpaceClassV2.ADDRESS \
                    or operation.inputs[1].byte_size * 8 != space.address_size_bits:
                continue
            address = index.reference(key, operation.inputs[1])
            region = index.region_of.get(index.locations.get(key))
            if address is None or region is None or row.access.width != width \
                    or type(row.access.address) is not ResolvedStorage or row.access.address.span != address[1]:
                continue
            matches = []
            for span in index.candidates(address):
                proof = index.proof(region, span)
                if proof is not None:
                    form = proof.form(*address)
                    if form is not None and form[0] == 1:
                        matches.append((proof.family, form[1]))
            if len(matches) != 1:
                continue
            family, offset = matches[0]
            identity = (family.header, family.span)
            if identity not in admitted:
                admitted[identity] = len(families)
                families.append(family)
            accesses.append(LoopMemoryAccess(admitted[identity], key, direction,
                space.space_id, width, offset, address[1], address[0]))
    if not accesses:
        return None
    payload = ssa.function_scope, ssa.unit_digest, tuple(families), tuple(accesses)
    return LoopMemoryPlan(*payload, _proof=_Derivation(_DERIVATION_AUTHORITY, ssa,
        (memory, observation, entry, context, address_spaces), payload))


def _check_origin(plan, ssa=None):
    proof = plan._proof
    if type(proof) is not _Derivation or proof.authority is not _DERIVATION_AUTHORITY \
            or proof.payload != (plan.function_scope, plan.unit_digest, plan.families, plan.accesses) \
            or ssa is not None and proof.ssa is not ssa:
        raise ValueError("loop memory requires the unchanged derive result and original SSA identity")


def validate_loop_memory(plan, ssa):
    """Bind every weak relation to this exact SSA; never grant a read-from."""
    if plan is None:
        return
    if type(plan) is not LoopMemoryPlan or plan.function_scope != ssa.function_scope or plan.unit_digest != ssa.unit_digest:
        raise ValueError("loop memory plan must belong to this SSA function and unit")
    _check_origin(plan, ssa)
    wanted = {edge for family in plan.families for edge in (*family.entry_edges, *family.backedge_edges)}
    flows = {edge for edge in ssa.flow_edges if edge in wanted}
    for family in plan.families:
        if any(edge not in flows for edge in (*family.entry_edges, *family.backedge_edges)):
            raise ValueError("loop memory must retain original predecessor flow evidence")
        for edges in (family.entry_edges, family.backedge_edges):
            position, identifiers = family.span.start, None
            for edge in sorted(edges, key=lambda row: row.span.start):
                start, end = max(edge.span.start, family.span.start), min(edge.span.end, family.span.end)
                current = frozenset(edge.definition_ids)
                if start != position or end <= start or not current or identifiers is not None and current != identifiers:
                    raise ValueError("loop entry/backedge must cover one complete SSA value")
                position, identifiers = end, current
            if position != family.span.end:
                raise ValueError("loop entry/backedge must cover the entire induction span")
        if family.transition_definition_id >= len(ssa.definitions):
            raise ValueError("loop transition is outside the SSA")
        transition = ssa.definitions[family.transition_definition_id]
        if transition.kind is not MemoryDefinitionKind.DATA_WRITE or transition.span != family.span \
                or {d for edge in family.backedge_edges for d in edge.definition_ids} != {family.transition_definition_id}:
            raise ValueError("loop backedge must retain the full induction transition")
    actions = {row.operation_key: i for i, row in enumerate(ssa.actions)}
    unresolved = {(direction, row.action_id): row.access for direction, rows in
                  (("read", ssa.unresolved_reads), ("write", ssa.unresolved_writes)) for row in rows}
    selected = {actions.get(row.operation_key) for row in plan.accesses}
    references = {(row.action_id, fragment.span, d) for row in ssa.reads if row.action_id in selected for fragment in row.fragments
                  for d in fragment.definition_ids}
    for access in plan.accesses:
        action = actions.get(access.operation_key)
        original = unresolved.get((access.direction, action))
        if original is None or original.width != access.width or type(original.address) is not ResolvedStorage \
                or original.address.span != access.address_span \
                or (action, access.address_span, access.address_definition_id) not in references:
            raise ValueError("loop access must retain its original unresolved address operand")


class _Index(SsaCycleIndex):
    def __init__(self, memory, ssa, observation, entry, context):
        super().__init__(memory, ssa, observation, entry, include_flow=False)
        self.context = context
        if not self.cyclic or not self.ssa_matches or self.cfg.unsupported is not None:
            return
        self.actions = {row.operation_key: i for i, row in enumerate(ssa.actions)}
        self.reads = {}
        for row in ssa.reads:
            token = row.action_id, row.span
            self.reads[token] = row if token not in self.reads else None
        self.joins = {row.join_definition_id: row.source_definition_ids for row in ssa.joins}
        self.positions = {action.operation_key: (block.key, i)
                          for block in memory.blocks for i, action in enumerate(block.actions)}
        # Raw CALL effects may change a register without an explicit SSA
        # output. No ABI or hidden-preservation assumption is added here.
        self.barrier_blocks = {self.locations[key] for key, operation in self.raw.items()
                               if operation.opcode in ("CALL", "CALLIND", "CALLOTHER")}
        self.region_of = {key: number for number, members in enumerate(self.cyclic) for key in members}
        for flow in ssa.flow_edges:
            step()
            if flow.block_key in self.region_of:
                self.flow_by_edge.setdefault((flow.predecessor_key, flow.block_key), []).append(flow)
        self.proofs, self.regions = {}, {}

    def span(self, value):
        kind = {VarnodeKindCode.REGISTER: VarnodeKind.REGISTER,
                VarnodeKindCode.UNIQUE: VarnodeKind.UNIQUE}.get(value.kind)
        if kind is None:
            return None
        reference = StorageRef(kind, "", value.coordinate.byte_offset, value.byte_size,
                               space_id=value.coordinate.space_id)
        resolved = _resolve_validated_storage(reference, self.context)
        return resolved.span if type(resolved) is ResolvedStorage else None

    def reference(self, key, value):
        span = self.span(value)
        read = self.reads.get((self.actions.get(key), span))
        if read is None or len(read.fragments) != 1:
            return None
        fragment = read.fragments[0]
        if fragment.span != span or len(fragment.definition_ids) != 1:
            return None
        return fragment.definition_ids[0], span, key

    def operands(self, definition, span):
        operation = self.raw.get(definition.operation_key)
        if definition.kind is not MemoryDefinitionKind.DATA_WRITE or definition.span != span \
                or operation is None or operation.output is None or self.span(operation.output) != span \
                or operation.opcode not in ("COPY", "INT_ADD", "INT_SUB") \
                or len(operation.inputs) != (1 if operation.opcode == "COPY" else 2) \
                or any(value.byte_size != span.size for value in operation.inputs):
            return None
        operands = []
        for value in operation.inputs:
            if value.kind is VarnodeKindCode.CONSTANT:
                operands.append((0, value.coordinate.byte_offset % (1 << (8 * span.size))))
            else:
                reference = self.reference(definition.operation_key, value)
                if reference is None:
                    return None
                operands.append(reference)
        return operation.opcode, tuple(operands)

    def candidates(self, address):
        pending, visited, spans = [address], set(), set()
        while pending:
            identifier, span, consumer = pending.pop()
            token = identifier, span
            if token in visited:
                continue
            step()
            visited.add(token)
            definition = self.ssa.definitions[identifier]
            if definition.kind is MemoryDefinitionKind.JOIN:
                if span.object_id.kind is StorageObjectKind.REGISTER_FILE:
                    spans.add(span)
                pending.extend((source, span, consumer) for source in self.joins[identifier])
            else:
                recipe = self.operands(definition, span)
                if recipe is not None:
                    pending.extend(item for item in recipe[1] if len(item) == 3)
        return tuple(sorted(spans, key=lambda span: span.canonical_key))

    def region(self, number):
        if number in self.regions:
            return self.regions[number]
        members = frozenset(self.cyclic[number])
        if self.barrier_blocks & members:
            self.regions[number] = None
            return None
        heads = {key for key in members if key == self.cfg.entry or self.predecessors[key] - members}
        result = None
        if len(heads) == 1:
            header, = heads
            before, back = self.predecessors[header] - members, self.predecessors[header] & members
            if len(before) == len(back) == 1:
                preheader, = before
                latch, = back
                degree = {key: len(self.predecessors[key] & members) - int(key == header) for key in members}
                pending, count = deque(key for key in members if degree[key] == 0), 0
                while pending:
                    step()
                    key = pending.popleft()
                    count += 1
                    for target in self.blocks[key].successors:
                        if target in members and (key, target) != (latch, header):
                            degree[target] -= 1
                            if degree[target] == 0:
                                pending.append(target)
                if count == len(members):
                    result = header, latch, preheader, members
        self.regions[number] = result
        return result

    def edge(self, source, target, span):
        rows = tuple(row for row in self.flow_by_edge.get((source, target), ()) if row.span.overlaps(span))
        position, identifiers = span.start, None
        for row in sorted(rows, key=lambda row: row.span.start):
            step()
            start, end = max(span.start, row.span.start), min(span.end, row.span.end)
            current = frozenset(row.definition_ids)
            if start != position or end <= start or not current or identifiers is not None and current != identifiers:
                return None
            position, identifiers = end, current
        if position != span.end or identifiers is None or any(
                not self.ssa.definitions[d].span.contains(span) for d in identifiers):
            return None
        return rows, identifiers

    def proof(self, region, span):
        token = region, span
        if token in self.proofs:
            return self.proofs[token]
        self.proofs[token] = None
        loop = self.region(region)
        if loop is None:
            return None
        header, latch, preheader, members = loop
        initial, back = self.edge(preheader, header, span), self.edge(latch, header, span)
        if initial is None or back is None or len(back[1]) != 1 or initial[1] & back[1]:
            return None
        if any(self.locations.get(self.ssa.definitions[d].operation_key) in members
               or self.ssa.definitions[d].kind not in (MemoryDefinitionKind.ENTRY, MemoryDefinitionKind.DATA_WRITE)
               for d in initial[1]):
            return None
        writes = []
        for identifier, definition in enumerate(self.ssa.definitions):
            step()
            if definition.kind in (MemoryDefinitionKind.DATA_WRITE, MemoryDefinitionKind.KILL) \
                    and definition.span.overlaps(span) \
                    and self.positions.get(definition.operation_key, (None,))[0] in members:
                writes.append(identifier)
        if len(writes) != 1 or frozenset(writes) != back[1] or self.ssa.definitions[writes[0]].span != span:
            return None
        proof = _Proof(self, loop, span, initial, back, writes[0])
        transition = proof.form(writes[0], span, self.ssa.definitions[writes[0]].operation_key)
        if transition is None or transition[0] != 1 or transition[1] == 0:
            return None
        proof.family = LoopMemoryFamily(header, latch, preheader, tuple(sorted(members)), span,
            initial[0], back[0], writes[0], transition[1], 8 * span.size)
        self.proofs[token] = proof
        return proof


class _Proof:
    def __init__(self, index, loop, span, initial, back, transition):
        self.index, self.loop, self.span = index, loop, span
        self.sources = initial[1] | back[1]
        self.transition = index.ssa.definitions[transition].operation_key
        self.modulus = 1 << (8 * span.size)
        self.cache, self.family = {}, None
        header, latch, _, members = loop
        update_block = index.positions[self.transition][0]
        pending, self.after = list(index.blocks[update_block].successors), set()
        while pending:
            key = pending.pop()
            if key not in members or (update_block, key) == (latch, header) or key in self.after:
                continue
            step()
            self.after.add(key)
            pending.extend(target for target in index.blocks[key].successors if (key, target) != (latch, header))

    def before_update(self, consumer):
        point, update = self.index.positions.get(consumer), self.index.positions[self.transition]
        if point is None or point[0] not in self.loop[3]:
            return False
        return point[1] <= update[1] if point[0] == update[0] else point[0] not in self.after

    def form(self, identifier, span, consumer):
        """Iterative SSA expression walk; no recursion or path combinations."""
        root = identifier, span, consumer
        pending, active, recipes = [(root, False)], set(), {}
        while pending:
            token, finish = pending.pop()
            if token in self.cache:
                continue
            step()
            identifier, requested, at = token
            definition = self.index.ssa.definitions[identifier]
            if finish:
                opcode, operands = recipes.pop(token)
                values = [item if len(item) == 2 else self.cache.get(item) for item in operands]
                result = None
                if all(value is not None for value in values):
                    if opcode == "JOIN":
                        result = values[0] if values and all(value == values[0] for value in values) else None
                    elif opcode == "COPY":
                        result = values[0]
                    else:
                        sign = 1 if opcode == "INT_ADD" else -1
                        result = tuple((a + sign * b) % self.modulus for a, b in zip(*values, strict=True))
                active.remove(token)
                self.cache[token] = result
                continue
            if token in active:
                self.cache[token] = None
                continue
            if requested.size != self.span.size or definition.span != requested:
                self.cache[token] = None
                continue
            if definition.kind is MemoryDefinitionKind.JOIN:
                sources = self.index.joins[identifier]
                if requested == self.span and frozenset(sources) == self.sources and self.before_update(at):
                    self.cache[token] = (1, 0)
                    continue
                recipe = "JOIN", tuple((source, requested, at) for source in sources)
            else:
                recipe = self.index.operands(definition, requested)
            if recipe is None:
                self.cache[token] = None
                continue
            active.add(token)
            recipes[token] = recipe
            pending.append((token, True))
            pending.extend((item, False) for item in reversed(recipe[1]) if len(item) == 3 and item not in self.cache)
        return self.cache.get(root)
