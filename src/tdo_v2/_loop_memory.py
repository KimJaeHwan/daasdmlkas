"""Occurrence-qualified affine memory effects over the ORIGINAL SSA.

Families/accesses are weak relations, NOT exact physical storage objects.
Issued read_from fragments separately guarantee the same-visit last writer
conditional on that original reader executing successfully in this model.
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
    latches: tuple[str, ...]
    preheader: str
    blocks: tuple[str, ...]
    span: ByteSpan
    entry_edges: tuple[MemoryFlowEdge, ...]
    backedge_edges: tuple[MemoryFlowEdge, ...]
    transition_definition_ids: tuple[int, ...]
    stride: int
    address_bits: int

    def __post_init__(self):
        if any(type(key) is not str or not key for key in (self.header, self.preheader)) \
                or type(self.latches) is not tuple or not self.latches \
                or any(type(key) is not str or not key for key in self.latches) \
                or tuple(sorted(set(self.latches))) != self.latches \
                or type(self.blocks) is not tuple or not self.blocks or len(set(self.blocks)) != len(self.blocks) \
                or any(type(key) is not str or not key for key in self.blocks) \
                or self.header not in self.blocks or not set(self.latches) <= set(self.blocks) \
                or self.preheader in self.blocks:
            raise ValueError("loop family requires distinct original entry/backedge evidence")
        if type(self.span) is not ByteSpan or self.span.object_id.kind is not StorageObjectKind.REGISTER_FILE \
                or type(self.address_bits) is not int or self.address_bits != 8 * self.span.size \
                or type(self.stride) is not int or not 0 < self.stride < 1 << self.address_bits \
                or type(self.transition_definition_ids) is not tuple or not self.transition_definition_ids \
                or any(type(identifier) is not int or identifier < 0 for identifier in self.transition_definition_ids) \
                or tuple(sorted(set(self.transition_definition_ids))) != self.transition_definition_ids:
            raise ValueError("loop family requires a full-width modular induction")
        for edges, sources in ((self.entry_edges, {self.preheader}), (self.backedge_edges, set(self.latches))):
            if type(edges) is not tuple or not edges or any(type(row) is not MemoryFlowEdge
                    or row.predecessor_key not in sources or row.block_key != self.header for row in edges) \
                    or {row.predecessor_key for row in edges} != sources:
                raise ValueError("loop family edges must name its original entry and backedge")

    @property
    def latch(self):
        """Legacy singleton view; never select an arbitrary backedge."""
        return self.latches[0] if len(self.latches) == 1 else None

    @property
    def transition_definition_id(self):
        """Legacy singleton view; all transitions live in the plural field."""
        return self.transition_definition_ids[0] if len(self.transition_definition_ids) == 1 else None


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


@dataclass(frozen=True, slots=True)
class LoopMemoryReadFrom:
    """Last-writer bytes conditional on this reader's successful same visit.

    The source is the STORE value operand at writer(k), not a fixed value of
    its static SSA definition. This is not an exact physical ByteSpan read.
    """

    writer_access: int
    reader_access: int
    write_offset: int
    read_offset: int
    width: int
    source_definition_id: int | None
    source_span: ByteSpan | None
    constant: tuple[int, int, int] | None
    output_span: ByteSpan
    visit_delta: int = 0

    def __post_init__(self):
        if any(type(value) is not int or value < 0 for value in
               (self.writer_access, self.reader_access, self.write_offset, self.read_offset)) \
                or type(self.width) is not int or self.width <= 0 \
                or type(self.visit_delta) is not int or self.visit_delta != 0 \
                or type(self.output_span) is not ByteSpan or self.output_span.size != self.width:
            raise ValueError("loop read-from requires same-visit byte fragments")
        if self.constant is not None:
            if type(self.constant) is not tuple or len(self.constant) != 3 \
                    or any(type(value) is not int or value < 0 for value in self.constant) \
                    or self.constant[2] < self.write_offset + self.width \
                    or self.source_definition_id is not None or self.source_span is not None:
                raise ValueError("loop read-from constant must retain the original value operand")
        elif type(self.source_definition_id) is not int or self.source_definition_id < 0 \
                or type(self.source_span) is not ByteSpan or self.source_span.size != self.width:
            raise ValueError("loop read-from must name the STORE value's original SSA bytes")

    @property
    def value_offset(self):
        return self.write_offset

    @property
    def output_offset(self):
        return self.read_offset


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
    read_from: tuple[LoopMemoryReadFrom, ...] = ()
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
        if type(self.read_from) is not tuple or any(type(row) is not LoopMemoryReadFrom for row in self.read_from):
            raise TypeError("loop read-from must retain typed issued fragments")
        for row in self.read_from:
            if max(row.writer_access, row.reader_access) >= len(self.accesses):
                raise ValueError("loop read-from must name its own accesses")
            writer, reader = self.accesses[row.writer_access], self.accesses[row.reader_access]
            if writer.direction != "write" or reader.direction != "read" \
                    or writer.family_index != reader.family_index or writer.space_id != reader.space_id \
                    or row.write_offset + row.width > writer.width or row.read_offset + row.width > reader.width:
                raise ValueError("loop read-from byte fragments must belong to one family and space")


def derive_loop_memory(memory, ssa, observation, entry, context, address_spaces, namespace):
    """Describe supported unresolved raw LOAD/STOREs without changing SSA.

    Exactly one full-span induction write on every header-return path, a
    single entry and a DAG between visits are deliberately required. Each
    backedge must carry the same modular stride. Unsupported cases retain
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
    from ._loop_memory_reads import derive_read_from

    families, accesses = tuple(families), tuple(accesses)
    read_from = derive_read_from(index, memory, families, accesses, namespace)
    payload = ssa.function_scope, ssa.unit_digest, families, accesses, read_from
    return LoopMemoryPlan(*payload, _proof=_Derivation(_DERIVATION_AUTHORITY, ssa,
        (memory, observation, entry, context, address_spaces, namespace), payload))


def _check_origin(plan, ssa=None):
    proof = plan._proof
    if type(proof) is not _Derivation or proof.authority is not _DERIVATION_AUTHORITY \
            or proof.payload != (plan.function_scope, plan.unit_digest, plan.families, plan.accesses, plan.read_from) \
            or ssa is not None and proof.ssa is not ssa:
        raise ValueError("loop memory requires the unchanged derive result and original SSA identity")


def validate_loop_memory(plan, ssa):
    """Bind issued relations to this SSA; never grant an exact physical read."""
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
        groups = (family.entry_edges, *(tuple(edge for edge in family.backedge_edges
                  if edge.predecessor_key == latch) for latch in family.latches))
        for edges in groups:
            position, identifiers = family.span.start, None
            for edge in sorted(edges, key=lambda row: row.span.start):
                start, end = max(edge.span.start, family.span.start), min(edge.span.end, family.span.end)
                current = frozenset(edge.definition_ids)
                if start != position or end <= start or not current or identifiers is not None and current != identifiers:
                    raise ValueError("loop entry/backedge must cover one complete SSA value")
                position, identifiers = end, current
            if position != family.span.end:
                raise ValueError("loop entry/backedge must cover the entire induction span")
        if any(identifier >= len(ssa.definitions) for identifier in family.transition_definition_ids):
            raise ValueError("loop transition is outside the SSA")
        if any(ssa.definitions[identifier].kind is not MemoryDefinitionKind.DATA_WRITE
                or ssa.definitions[identifier].span != family.span for identifier in family.transition_definition_ids) \
                or {d for edge in family.backedge_edges for d in edge.definition_ids} != set(family.transition_definition_ids):
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
    for row in plan.read_from:
        if row.source_definition_id is not None and (
                row.source_definition_id >= len(ssa.definitions)
                or not ssa.definitions[row.source_definition_id].span.contains(row.source_span)):
            raise ValueError("loop read-from value bytes must belong to the original SSA")


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
        self.memory_blocks = {block.key: block for block in memory.blocks}
        # Raw CALL effects may change a register without an explicit SSA
        # output. No ABI or hidden-preservation assumption is added here.
        self.barrier_blocks = {self.locations[key] for key, operation in self.raw.items()
                               if operation.opcode in ("CALL", "CALLIND", "CALLOTHER")}
        self.region_of = {key: number for number, members in enumerate(self.cyclic) for key in members}
        for flow in ssa.flow_edges:
            step()
            if flow.block_key in self.region_of:
                self.flow_by_edge.setdefault((flow.predecessor_key, flow.block_key), []).append(flow)
        self.proofs, self.regions, self.orders = {}, {}, {}

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
            if len(before) == 1 and back:
                preheader, = before
                predecessors = {key: tuple(sorted(self.predecessors[key] & members))
                                if key != header else () for key in members}
                degree = {key: len(rows) for key, rows in predecessors.items()}
                pending, order = deque(sorted(key for key in members if degree[key] == 0)), []
                while pending:
                    step()
                    key = pending.popleft()
                    order.append((key, predecessors[key]))
                    for target in self.blocks[key].successors:
                        step()
                        if target in members and target != header:
                            degree[target] -= 1
                            if degree[target] == 0:
                                pending.append(target)
                if len(order) == len(members) and order[0][0] == header:
                    result = header, tuple(sorted(back)), preheader, members
                    self.orders[number] = tuple(order)
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
        header, latches, preheader, members = loop
        initial = self.edge(preheader, header, span)
        backs = tuple(self.edge(latch, header, span) for latch in latches)
        if initial is None or any(back is None for back in backs):
            return None
        transitions = frozenset(identifier for back in backs for identifier in back[1])
        if initial[1] & transitions:
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
        if not writes or frozenset(writes) != transitions or any(
                self.ssa.definitions[identifier].span != span
                or self.ssa.definitions[identifier].kind is not MemoryDefinitionKind.DATA_WRITE for identifier in writes):
            return None
        proof = _Proof(self, loop, span, initial[1] | transitions, writes, self.orders[region])
        if any(proof.exit_counts[latch] != (1, 1) for latch in latches):
            return None
        forms = tuple(proof.form(identifier, span, self.ssa.definitions[identifier].operation_key)
                      for identifier in writes)
        transition = forms[0]
        if transition is None or transition[0] != 1 or transition[1] == 0 \
                or any(form != transition for form in forms):
            return None
        proof.family = LoopMemoryFamily(header, latches, preheader, tuple(sorted(members)), span,
            initial[0], tuple(edge for back in backs for edge in back[0]), tuple(writes), transition[1], 8 * span.size)
        self.proofs[token] = proof
        return proof


class _Proof:
    def __init__(self, index, loop, span, sources, transitions, order):
        self.index, self.loop, self.span = index, loop, span
        self.sources = sources
        self.modulus = 1 << (8 * span.size)
        self.cache, self.family = {}, None
        updates = {index.ssa.definitions[identifier].operation_key for identifier in transitions}
        self.before_counts, self.exit_counts = {}, {}
        for key, predecessors in order:
            step(1 + len(predecessors))
            lo = min((self.exit_counts[p][0] for p in predecessors), default=0)
            hi = max((self.exit_counts[p][1] for p in predecessors), default=0)
            for action in index.memory_blocks[key].actions:
                step()
                self.before_counts[action.operation_key] = lo, hi
                if action.operation_key in updates:
                    lo, hi = min(2, lo + 1), min(2, hi + 1)
            self.exit_counts[key] = lo, hi

    def before_update(self, consumer):
        # JOINs are reaching-definition sets at a read, not header phi nodes.
        # Only a use before every path's update denotes this visit's S(k).
        return self.before_counts.get(consumer) == (0, 0)

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
