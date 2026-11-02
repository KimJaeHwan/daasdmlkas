"""Graph-owned read byte ports: conditional image values or local last writes.

These never establish address validity, allocation lifetime, or absence of
faults. Raw SSA/debt nodes remain; consumers replace only a fully covered
LOAD memory value and its now-inactive memory alternatives. Address and
source-value uncertainties remain independent prerequisites.
"""

from dataclasses import dataclass, field
from hashlib import sha256

from ._guarded_image_reads import _Index, _Refused, validate_guarded_image_reads
from ._memory_corridor import write_free_corridor
from ._scope_contracts import VarnodeKindCode, AddressSpaceClassV2, classify_address_space_v2
from .memory_contracts import MemoryDefinitionKind
from .model import ByteSpan, StorageObjectKind
from .resource_limits import step


@dataclass(frozen=True, slots=True)
class ReadSourcePart:
    source_definition_id: int | None
    source_span: ByteSpan | None
    constant: tuple[int, int, int] | None
    value_offset: int
    output_offset: int
    width: int
    writer: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class LocalReadFrom:
    writer: str
    reader: str
    output_span: ByteSpan
    parts: tuple[ReadSourcePart, ...]
    corridor: tuple[str, ...]
    address_witnesses: tuple[int, ...]
    address_ports: tuple = ()  # first use, second use, register bytes, preservation corridor
    complete: bool = field(default=True, repr=False)


_AUTHORITY = object()


@dataclass(frozen=True, slots=True)
class LocalReadPlan:
    function_scope: object
    unit_digest: bytes
    reads: tuple[LocalReadFrom, ...]
    _proof: tuple = field(default=(), repr=False, compare=False)

    def __post_init__(self):
        validate_local_reads(self)


def validate_local_reads(plan, ssa=None, *, normalized=None):
    if plan is None:
        return
    if type(plan) is not LocalReadPlan or len(plan._proof) != 4 \
            or plan._proof[0] is not _AUTHORITY \
            or plan._proof[3] != (plan.function_scope, plan.unit_digest, plan.reads) \
            or ssa is not None and plan._proof[1] is not ssa:
        raise ValueError("local reads require unchanged original SSA and derivation")
    if normalized is not None:
        inputs = plan._proof[2]
        excluded = frozenset(dict(normalized.operation_overrides)) | frozenset(dict(normalized.intrinsic_refinements))
        if inputs[0] is not normalized.memory_unit or inputs[6] != normalized.call_clobber_reads \
                or inputs[7] != excluded:
            raise ValueError("local reads require unchanged memory, call debts and operation policies")


_PURE = frozenset(("COPY", "CAST", "INT_ADD", "INT_SUB", "INT_MULT", "INT_AND", "INT_OR", "INT_XOR",
                   "INT_NEGATE", "INT_2COMP", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_ZEXT", "INT_SEXT",
                   "PIECE", "SUBPIECE"))


class _Address:
    """Exact structural pure DAG identity; unknown LOAD results are opaque leaves.

    No JOIN unfolding, guessed aliases, name equality or range equality.
    Every operand-use is checked against its own original call-clobber spans.
    """
    def __init__(self, index):
        self.index, self.cache, self.active, self.used = index, {}, set(), set()
        self.port_cache = {}
        self.work = 0

    def charge(self):
        step()
        self.work += 1
        if self.work > 1024:
            raise _Refused()  # Port-dependent shared DAGs are deliberately not def-ID cached.

    def operand(self, key, varnode):
        self.charge()
        if not 0 < varnode.byte_size <= 16:
            raise _Refused()
        if varnode.kind is VarnodeKindCode.CONSTANT:
            return ("const", varnode.byte_size, varnode.coordinate.byte_offset % (1 << (8 * varnode.byte_size)))
        span = self.index.span(varnode)
        if key not in self.index.excluded and span is not None \
                and span.object_id.kind is StorageObjectKind.REGISTER_FILE \
                and any(span.overlaps(s) for s in self.index.clobbered.get(key, ())):
            read = self.index.reads.get((self.index.actions.get(key), span))
            if read is None:
                raise _Refused()
            self.used.update(i for f in read.fragments for i in f.definition_ids)
            # This is NOT the old SSA/ENTRY value. It is opaque current
            # register state at this exact use; equality needs another proof.
            return ("use", key, span)
        fragments = self.index.fragments(key, span)
        parts, cursor = [], span.start
        for f in fragments:
            identifier = f.definition_ids[0]
            definition = self.index.ssa.definitions[identifier]
            if f.span.start != cursor or not definition.span.contains(f.span):
                raise _Refused()
            term = self.definition(identifier)
            if definition.span != f.span:
                term = ("slice", term, f.span.start - definition.span.start, f.span.size)
            parts.append(term)
            cursor = f.span.end
        if cursor != span.end:
            raise _Refused()
        return parts[0] if len(parts) == 1 else ("pieces", span.size, tuple(parts))

    def definition(self, identifier):
        self.charge()
        self.used.add(identifier)
        if identifier in self.cache:
            return self.cache[identifier]
        if identifier in self.active or len(self.active) >= 64 or len(self.cache) >= 256:
            raise _Refused()
        d = self.index.ssa.definitions[identifier]
        key, span = d.operation_key, d.span
        raw = self.index.raw.get(key)
        if key in self.index.excluded:
            raise _Refused()
        if d.kind is MemoryDefinitionKind.ENTRY and span.object_id.kind is StorageObjectKind.REGISTER_FILE:
            term = ("entry", identifier, span)
        elif d.kind is MemoryDefinitionKind.DATA_WRITE and raw is not None and raw.output is not None \
                and self.index.span(raw.output) == span:
            if raw.opcode == "LOAD":
                term = ("load", identifier, span)
            elif raw.opcode in _PURE:
                self.active.add(identifier)
                try:
                    operands = tuple(self.operand(key, v) for v in raw.inputs)
                    term = operands[0] if raw.opcode in ("COPY", "CAST") and len(operands) == 1 \
                        and raw.inputs[0].byte_size == span.size else (raw.opcode, span.size, operands)
                finally:
                    self.active.remove(identifier)
            else:
                raise _Refused()
        else:
            raise _Refused()
        if not _has_port(term, self.port_cache):
            self.cache[identifier] = term
        return term


def _has_port(term, memo):
    if not isinstance(term, tuple):
        return False
    token = id(term)
    if token not in memo:
        step()
        # Retain the tuple too: use-dependent definitions are not cached and
        # their ids must not be reused during this address derivation.
        memo[token] = (term, bool(term) and term[0] == "use" or any(_has_port(t, memo) for t in term))
    return memo[token][1]


def _shape(term, memo=None):
    """Bounded DAG fingerprint for candidate lookup, NEVER equality proof.

    Nested tuple hashing itself expands shared ADD(x,x) DAGs exponentially.
    Hash each tuple once, with fixed-size child digests instead.
    """
    if memo is None:
        memo = {}
    if isinstance(term, tuple):
        token = id(term)
        if token in memo:
            return memo[token]
        step()
        if len(memo) >= 2048:
            raise _Refused()
        if term and term[0] == "use":
            children = (term[0], term[2])
        else:
            children = term
        memo[token] = sha256(b"tuple" + len(children).to_bytes(4, "big")
                            + b"".join(_shape(t, memo) for t in children)).digest()
        return memo[token]
    return sha256((type(term).__name__ + ":" + repr(term)).encode()).digest()


def _same_address(left, right, index, dom, ports, memo=None):
    if memo is None:
        memo = {}
    token = id(left), id(right)
    if token in memo:
        return memo[token]
    step()
    if len(memo) >= 2048:
        return False
    if isinstance(left, tuple) and isinstance(right, tuple) \
            and left and right and left[0] == "use" and right[0] == "use":
        # (Each tag against "use" alone: left[0] == right[0] would compare two
        # whole shared sub-DAGs with tuple equality, outside the memo.)
        if left[2] != right[2]:
            return False
        if left[1] == right[1]:
            return True
        corridor = write_free_corridor(index, left[1], right[1], dom, register_span=left[2])
        if corridor is None:
            return False
        ports.append((left[1], right[1], left[2], corridor))
        memo[token] = True
        return True
    if isinstance(left, tuple) and isinstance(right, tuple):
        result = len(left) == len(right) and all(_same_address(a, b, index, dom, ports, memo)
                                                for a, b in zip(left, right, strict=True))
    else:
        result = left == right
    memo[token] = result
    return result


def derive_local_read_sources(memory, ssa, observation, entry, context, address_spaces, namespace,
                              clobbered=(), excluded=frozenset()):
    if namespace.language_id.split(":")[1:2] != ["LE"]:
        return None
    # No index/CFG solve for the common no-STORE/no-LOAD case.
    codes = {op.opcode for ins in observation.instructions for op in ins.operations}
    if not {"LOAD", "STORE"} <= codes:
        return None
    from ._sparse_dataflow import DominatorGraph
    from ._loop_memory_reads import _value_sources

    index = _Index(memory, ssa, observation, entry, context, frozenset(), clobbered, excluded)
    if not index.ssa_matches or index.cfg.unsupported is not None:
        return None
    dom = DominatorGraph(index.cfg.entry, index.predecessors)
    spaces = {s.space_id: s for s in address_spaces}
    # Retain at most 64 structural writer signatures. They only identify
    # candidates; each reader still requires its own complete corridor proof.
    writers, result, attempts = {}, [], 0
    recent, fragment_attempts, fragment_misses = [], 0, 0
    for action in ssa.actions:
        step()
        key = action.operation_key
        raw = index.raw.get(key)
        if key in excluded or raw is None or raw.opcode not in ("LOAD", "STORE") \
                or len(raw.inputs) != (2 if raw.opcode == "LOAD" else 3) \
                or raw.inputs[0].kind is not VarnodeKindCode.CONSTANT:
            continue
        space = spaces.get(raw.inputs[0].coordinate.byte_offset)
        width = raw.output.byte_size if raw.opcode == "LOAD" and raw.output is not None \
            else raw.inputs[2].byte_size if raw.opcode == "STORE" else 0
        if space is None or space.addressable_unit_bytes != 1 \
                or classify_address_space_v2(space) is not AddressSpaceClassV2.ADDRESS \
                or raw.inputs[1].byte_size * 8 != space.address_size_bits or not 0 < width <= 32:
            continue
        try:
            tree = _Address(index)
            term = tree.operand(key, raw.inputs[1])
            signature = (space.space_id, width, _shape(term))
        except _Refused:
            continue
        if raw.opcode == "STORE":
            recent.append((key, space.space_id, term, tuple(sorted(tree.used))))
            if len(recent) > 64:
                del recent[0]
            if len(writers) < 64 or signature in writers:
                rows = writers.setdefault(signature, [])
                rows.append((key, term, tuple(sorted(tree.used))))
                if len(rows) > 8:
                    del rows[0]
            continue
        for writer, before, writer_witnesses in reversed(writers.get(signature, ())):
            attempts += 1
            if attempts > 128:
                break
            corridor = write_free_corridor(index, writer, key, dom)
            output = index.span(raw.output)
            if corridor is None or output is None:
                continue
            ports = []
            if not _same_address(before, term, index, dom, ports):
                continue
            value = index.raw[writer].inputs[2]
            if value.kind is VarnodeKindCode.CONSTANT:
                parts = (ReadSourcePart(None, None, (value.coordinate.space_id,
                    value.coordinate.byte_offset, value.byte_size), 0, 0, width),)
            else:
                value_span = index.span(value)
                if value_span is None or any(value_span.overlaps(span)
                        for span in index.clobbered.get(writer, ())):
                    continue  # A source operand-use changed by a CALL is not its old SSA value.
                parts = tuple(ReadSourcePart(identifier, span, None, offset, offset, span.size)
                              for identifier, span, offset in _value_sources(index, writer, value))
            cursor = 0
            for part in parts:
                if part.output_offset != cursor:
                    break
                cursor += part.width
            if cursor != width:
                continue
            result.append(LocalReadFrom(writer, key, output, parts, corridor,
                                        tuple(sorted(set(writer_witnesses) | tree.used)), tuple(ports)))
            break
        else:
            if recent and fragment_attempts < 128 and fragment_misses < 16:
                from ._local_memory_fragments import derive_fragments
                row, spent = derive_fragments(index, dom, key, term, space, recent,
                                              tuple(sorted(tree.used)), 128 - fragment_attempts)
                fragment_attempts += spent
                fragment_misses += spent == 0
                if row is not None:
                    result.append(row)
    if not result:
        return None
    payload = ssa.function_scope, ssa.unit_digest, tuple(result)
    inputs = memory, observation, entry, context, address_spaces, namespace, clobbered, excluded
    return LocalReadPlan(*payload, _proof=(_AUTHORITY, ssa, inputs, payload))


@dataclass(frozen=True, slots=True)
class ReadSource:
    image: object
    local: LocalReadFrom | None
    output_span: ByteSpan
    inactive_debts: tuple[int, ...]


def read_sources(normalized):
    """Validated complete read ports; no global debt deletion or new SSA."""
    binding, ssa = normalized.memory_graph, normalized.memory_ssa
    if binding is None or ssa is None:
        return {}
    images, locals_ = binding.image_reads, binding.local_reads
    result = {}
    for plan, kind in ((images.plan if images else None, "image"), (locals_.plan if locals_ else None, "local")):
        if plan is None:
            continue
        if kind == "image":
            validate_guarded_image_reads(plan, ssa, normalized=normalized)
        else:
            validate_local_reads(plan, ssa, normalized=normalized)
        for row in plan.reads:
            if kind == "local" and not row.complete:
                continue  # Partial graph facts never deactivate a whole LOAD's debts.
            key = row.operation_key if kind == "image" else row.reader
            result[key] = ReadSource(row if kind == "image" else None, row if kind == "local" else None,
                                     row.output_span, ())
    if not result:
        return result
    debts = {key: set() for key in result}
    for row, node in zip(ssa.unresolved_reads, binding.unresolved_read_nodes, strict=True):
        key = ssa.actions[row.action_id].operation_key
        if key in debts:
            debts[key].add(node)
    for rows, nodes in ((normalized.may_alias_reads, normalized.may_alias_nodes),):
        for row, node in zip(rows, nodes, strict=True):
            if row.operation_key in debts and (row.unknown_address or all(s.object_id.kind in (
                    StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE) for s in row.spans)):
                debts[row.operation_key].add(node)
    call_spans = {}
    for row, nodes in zip(normalized.call_clobber_reads, normalized.call_clobber_debts, strict=True):
        if row.operation_key in result:
            by_node = call_spans.setdefault(row.operation_key, {})
            for node in nodes:
                by_node.setdefault(node, []).extend(row.spans)
    for key, source in tuple(result.items()):
        for node, spans in call_spans.get(key, {}).items():
            if spans and all(s.object_id.kind in (StorageObjectKind.ADDRESS_SPACE,
                                                  StorageObjectKind.FUNCTION_RELATIVE) for s in spans):
                debts[key].add(node)
        result[key] = ReadSource(source.image, source.local, source.output_span, tuple(sorted(debts[key])))
    return result


def read_source(normalized, key):
    return read_sources(normalized).get(key)
