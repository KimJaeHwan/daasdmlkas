"""Conditional finite image reads over ORIGINAL SSA operand uses.

One original branch restricts one scalar selector. Only a COMPLETE finite
domain is issued, with each selector/address/image-value alternative intact.
These are additional graph relations, not execution, new SSA, or debt removal.
"""

from dataclasses import dataclass, field

from ._scope_contracts import AddressSpaceClassV2, VarnodeKindCode, classify_address_space_v2
from ._ssa_cycles import SsaCycleIndex
from .memory_contracts import MemoryDefinitionKind
from .model import ByteSpan, ResolvedStorage, StorageObjectKind
from .resource_limits import step


@dataclass(frozen=True, slots=True)
class ImageReadCandidate:
    selector: int
    span: ByteSpan
    value: int


@dataclass(frozen=True, slots=True)
class GuardedImageRead:
    operation_key: str
    guard: str
    success_edge: tuple[str, str]
    selector_definition_id: int
    selector_span: ByteSpan
    reloads: tuple[str, ...]
    reload_corridors: tuple[tuple[str, ...], ...]
    address_definition_id: int
    output_span: ByteSpan
    constant_space_id: int
    candidates: tuple[ImageReadCandidate, ...]


_AUTHORITY = object()


@dataclass(frozen=True, slots=True)
class _Derivation:
    authority: object
    ssa: object
    inputs: tuple
    payload: tuple


@dataclass(frozen=True, slots=True)
class GuardedImagePlan:
    function_scope: object
    unit_digest: bytes
    reads: tuple[GuardedImageRead, ...]
    _proof: _Derivation | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        validate_guarded_image_reads(self)


def validate_guarded_image_reads(plan, ssa=None, *, normalized=None):
    if plan is None:
        return
    if type(plan) is not GuardedImagePlan:
        raise TypeError("image reads require an exact issued plan")
    proof = plan._proof
    if type(proof) is not _Derivation \
            or proof.authority is not _AUTHORITY \
            or proof.payload != (plan.function_scope, plan.unit_digest, plan.reads) \
            or ssa is not None and proof.ssa is not ssa:
        raise ValueError("guarded image reads require the unchanged derivation and original SSA")
    if normalized is not None:
        inputs = proof.inputs
        excluded = frozenset(dict(normalized.operation_overrides)) | frozenset(dict(normalized.intrinsic_refinements))
        if inputs[0] is not normalized.memory_unit or inputs[7] != normalized.wild_objects \
                or inputs[8] != normalized.call_clobber_reads or inputs[9] != excluded \
                or normalized.assumes_readonly_image_constant is not True:
            raise ValueError("image reads require unchanged memory, call debts and operation policies")


class _Refused(Exception):
    pass


class _Budget:
    """Per-function solver budget in addition to normal analysis step limits:
    at most ``QUERIES`` checks of at most ``RLIMIT`` z3 resource units each.
    Deterministic -- no wall-clock limit: the same input gets the same answers
    whatever the host load (a time-out made results load-dependent, e.g. a
    gate test that failed only under load). ``unknown`` stays a refusal."""

    QUERIES, RLIMIT = 64, 20_000

    def __init__(self):
        self.queries, self.attempts = 0, 0

    def check(self, solver):
        step()
        if self.queries >= self.QUERIES:
            raise _Refused()
        solver.set(rlimit=self.RLIMIT, random_seed=0)
        self.queries += 1
        return solver.check()


_MAX_NODES, _MAX_COST = 4096, 8192


def _admissible(z3, *expressions):
    """A deterministic shape and cost limit before any solver call (Astra review:
    z3 accounts bit-blasting sparsely -- multiplier chains took seconds within
    rlimit). Constants copied through temporaries are folded first
    (``z3.simplify``), so a scaled index stays a product by a numeral. Refused
    (None): a multiplication with two or more non-constant factors, more than
    ``_MAX_NODES`` distinct nodes, or a weighted bit-blast cost above
    ``_MAX_COST`` -- a product by a constant costs width x its one bits (width
    for a power of two), a shift by a symbolic amount width x log2(width), an
    addition or comparison width per operand, anything else 1. Calibrated on
    z3 4.16.0: cost 8192 is about 0.04 s per check; bounds checks, masks,
    scaled indexes and small switches cost under 400. Otherwise the simplified
    expressions (the same formulas) are returned for solving."""
    import math

    simplified = tuple(z3.simplify(expression) for expression in expressions)
    seen, stack, total = set(), list(simplified), 0
    shifts = (z3.Z3_OP_BSHL, z3.Z3_OP_BLSHR, z3.Z3_OP_BASHR)
    linear = (z3.Z3_OP_BADD, z3.Z3_OP_BSUB, z3.Z3_OP_ULT, z3.Z3_OP_ULEQ, z3.Z3_OP_UGT, z3.Z3_OP_UGEQ,
              z3.Z3_OP_SLT, z3.Z3_OP_SLEQ, z3.Z3_OP_SGT, z3.Z3_OP_SGEQ)
    while stack:
        expression = stack.pop()
        identifier = expression.get_id()
        if identifier in seen:
            continue
        seen.add(identifier)
        if len(seen) > _MAX_NODES:
            return None
        if not z3.is_app(expression):
            continue
        children = expression.children()
        stack.extend(children)
        width = expression.size() if z3.is_bv(expression) else             children[0].size() if children and z3.is_bv(children[0]) else 1
        if z3.is_app_of(expression, z3.Z3_OP_BMUL):
            constants = [child.as_long() for child in children if z3.is_bv_value(child)]
            if len(children) - len(constants) >= 2:
                return None
            constant = constants[0] if constants else 0
            total += width if constant & (constant - 1) == 0 else width * bin(constant).count("1")
        elif any(z3.is_app_of(expression, kind) for kind in shifts):
            total += width if z3.is_bv_value(children[1]) else width * max(1, math.ceil(math.log2(width)))
        elif any(z3.is_app_of(expression, kind) for kind in linear):
            total += width * max(1, len(children) - 1)
        else:
            total += 1
        if total > _MAX_COST:
            return None
    step()
    return simplified


def derive_guarded_image_reads(memory, ssa, observation, entry, context, address_spaces,
                               namespace, readonly_image, wild_objects=frozenset(), clobbered=(),
                               excluded=frozenset()):
    if readonly_image is None \
            or namespace.language_id.split(":")[1:2] != ["LE"] \
            or not any(op.opcode == "CBRANCH" for ins in observation.instructions for op in ins.operations) \
            or not any(op.opcode == "LOAD" and len(op.inputs) == 2
                       and op.inputs[1].kind is not VarnodeKindCode.CONSTANT
                       for ins in observation.instructions for op in ins.operations):
        return None
    # Local import: functions with no candidate guarded image LOAD pay no SMT import cost.
    import z3
    from ._record_expression_bv import arithmetic
    from ._sparse_dataflow import DominatorGraph
    from .forward import MAX_CANDIDATES
    from .operation_records import Ineligible

    index = _Index(memory, ssa, observation, entry, context, wild_objects, clobbered, excluded)
    if not index.ssa_matches or index.cfg.unsupported is not None:
        return None
    dom = DominatorGraph(index.cfg.entry, index.predecessors)
    spaces = {row.space_id: row for row in address_spaces}
    budget, found = _Budget(), []
    for action in ssa.actions:
        step()
        key = action.operation_key
        operation = index.raw.get(key)
        if key in excluded or operation is None or operation.opcode != "LOAD" or operation.output is None \
                or len(operation.inputs) != 2 or operation.inputs[0].kind is not VarnodeKindCode.CONSTANT:
            continue
        space = spaces.get(operation.inputs[0].coordinate.byte_offset)
        if space is None or classify_address_space_v2(space) is not AddressSpaceClassV2.ADDRESS \
                or space.addressable_unit_bytes != 1 or operation.inputs[1].byte_size * 8 != space.address_size_bits \
                or not 0 < operation.output.byte_size <= 32:
            continue
        try:
            address_id = index.exact_reference(key, operation.inputs[1])
            output = index.span(operation.output)
            if output is None:
                continue
        except _Refused:
            continue
        # Only dominator ancestors can supply an unavoidable original guard.
        block_key = index.locations[key]
        ancestor = block_key
        for _ in range(64):
            step()
            block = index.blocks[ancestor]
            raw = index.instructions[block.instruction].operations
            guard = raw[block.stop - 1] if block.stop else None
            if guard is not None and guard.opcode == "CBRANCH" and len(guard.inputs) == 2 \
                    and guard.inputs[0].kind is not VarnodeKindCode.CONSTANT and len(block.successors) == 2:
                target = guard.inputs[0].coordinate
                taken = f"{target.space_id:x}:{target.byte_offset:x}"
                success = [s for s in block.successors if s != index.cfg.entry
                           and index.predecessors[s] == {ancestor}
                           and dom._dominates(s, block_key)]
                if taken in block.successors and len(success) == 1:
                    budget.attempts += 1
                    if budget.attempts > 16:
                        return _plan(ssa, found, memory, observation, entry, context,
                                     address_spaces, namespace, readonly_image, wild_objects, clobbered, excluded)
                    guard_key = next(k for k in index.keys[ancestor] if index.raw.get(k) is guard)
                    try:
                        tree = _Tree(index, dom, z3, arithmetic)
                        condition = tree.operand(guard_key, guard.inputs[1])
                        if tree.root is None:
                            raise _Refused()
                        tree.address_phase = True
                        address = tree.definition(address_id)
                        admitted = _admissible(z3, condition, address)
                        if admitted is None:
                            raise _Refused()
                        condition, address = admitted
                        solver = z3.Solver()
                        solver.add((condition != 0) if success[0] == taken else (condition == 0))
                        selectors = []
                        while True:
                            outcome = budget.check(solver)
                            if outcome == z3.unsat:
                                break
                            if outcome != z3.sat or len(selectors) == MAX_CANDIDATES:
                                raise _Refused()
                            number = solver.model().eval(tree.symbol, model_completion=True).as_long()
                            selectors.append(number)
                            solver.add(tree.symbol != number)
                        if not selectors:
                            raise _Refused()
                        candidates = []
                        for number in sorted(selectors):
                            step()
                            absolute = z3.simplify(z3.substitute(address, (tree.symbol,
                                z3.BitVecVal(number, tree.symbol.size()))))
                            if not z3.is_bv_value(absolute):
                                raise _Refused()
                            offset = absolute.as_long()
                            if offset + output.size > 1 << space.address_size_bits:
                                raise _Refused()
                            span = index.image_span(space.space_id, offset, output.size)
                            value = readonly_image.value(space.space_id, offset, output.size)
                            if type(value) is not int or not 0 <= value < 1 << (output.size * 8):
                                raise _Refused()
                            candidates.append(ImageReadCandidate(number, span, value))
                        identifier, selector = tree.root
                        found.append(GuardedImageRead(key, guard_key, (ancestor, success[0]), identifier,
                            selector, tuple(sorted(tree.reloads)),
                            tuple(tree.reloads[k] for k in sorted(tree.reloads)), address_id, output,
                            operation.inputs[0].coordinate.space_id, tuple(candidates)))
                        break
                    except (_Refused, Ineligible):
                        pass
            parent = dom.idom.get(ancestor)
            if parent is None or parent == ancestor:
                break
            ancestor = parent
    return _plan(ssa, found, memory, observation, entry, context, address_spaces,
                 namespace, readonly_image, wild_objects, clobbered, excluded)


def _plan(ssa, rows, *inputs):
    if not rows:
        return None
    payload = ssa.function_scope, ssa.unit_digest, tuple(rows)
    return GuardedImagePlan(*payload, _proof=_Derivation(_AUTHORITY, ssa, inputs, payload))


class _Index(SsaCycleIndex):
    def __init__(self, memory, ssa, observation, entry, context, wild, clobbered, excluded):
        super().__init__(memory, ssa, observation, entry, include_flow=False)
        self.context, self.wild, self.excluded = context, wild, excluded
        self.clobbered = {}
        for row in clobbered:
            self.clobbered.setdefault(row.operation_key, []).extend(row.spans)
        self.actions = {row.operation_key: i for i, row in enumerate(ssa.actions)}
        self.reads = {}
        for row in ssa.reads:
            token = row.action_id, row.span
            if token not in self.reads:
                self.reads[token] = row
            elif self.reads[token] is not None and self.reads[token].fragments != row.fragments:
                self.reads[token] = None
            # ADD(x,x) has two read ordinals but exactly the same pre-write
            # bytes. Only identical original fragments are interchangeable.
        self.memory = {block.key: block for block in memory.blocks}
        self.keys = {key: tuple(row.operation_key for row in block.actions) for key, block in self.memory.items()}

    def span(self, varnode):
        from .relative_memory import _storage_ref
        from .storage import _resolve_validated_storage
        found = _resolve_validated_storage(_storage_ref(varnode), self.context)
        if type(found) is ResolvedStorage and found.span.object_id.kind in (
                StorageObjectKind.REGISTER_FILE, StorageObjectKind.FUNCTION_UNIQUE):
            return found.span
        return None

    def fragments(self, key, span):
        if span is None or key in self.excluded \
                or any(span.overlaps(other) for other in self.clobbered.get(key, ())):
            raise _Refused()
        row = self.reads.get((self.actions.get(key), span))
        if row is None or any(len(f.definition_ids) != 1 for f in row.fragments):
            raise _Refused()
        return row.fragments

    def exact_reference(self, key, varnode):
        span = self.span(varnode)
        fragments = self.fragments(key, span)
        if len(fragments) != 1 or fragments[0].span != span \
                or self.ssa.definitions[fragments[0].definition_ids[0]].span != span:
            raise _Refused()
        return fragments[0].definition_ids[0]

    def image_span(self, space, offset, size):
        from .model import StorageRef, VarnodeKind
        from .storage import _resolve_validated_storage
        found = _resolve_validated_storage(StorageRef(VarnodeKind.ADDRESS, "", offset, size, space_id=space), self.context)
        if type(found) is not ResolvedStorage:
            raise _Refused()
        return found.span

    def memory_span(self, key):
        action = self.memory[self.locations[key]].actions[self.keys[self.locations[key]].index(key)]
        spans = [s for s in action.reads if s.object_id.kind in (
            StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)]
        if len(spans) != 1 or spans[0].object_id in self.wild or action.unresolved_reads:
            raise _Refused()
        return spans[0]

    def unchanged_reload(self, source, target, dom):
        if self.memory_span(source) != self.memory_span(target):
            raise _Refused()
        # One projected span is not one address: a CALL before the loads may
        # change each address register independently (its call debts). The
        # original address operand-uses themselves must be structurally equal.
        from ._memory_read_sources import _Address, _same_address
        terms, ports = [_Address(self).operand(key, self.raw[key].inputs[1]) for key in (source, target)], []
        if not _same_address(*terms, self, dom, ports):
            raise _Refused()
        from ._memory_corridor import write_free_corridor
        evidence = write_free_corridor(self, source, target, dom)
        if evidence is None:
            raise _Refused()
        return tuple(sorted(set(evidence).union(*(port[3] for port in ports))))


class _Tree:
    def __init__(self, index, dom, z3, arithmetic):
        self.index, self.dom, self.z3, self.arithmetic = index, dom, z3, arithmetic
        self.cache, self.active, self.reloads = {}, set(), {}
        self.root = self.symbol = None
        self.address_phase = False

    def operand(self, key, varnode):
        step()
        if not 0 < varnode.byte_size <= 32:
            raise _Refused()
        if varnode.kind is VarnodeKindCode.CONSTANT:
            return self.z3.BitVecVal(varnode.coordinate.byte_offset, 8 * varnode.byte_size)
        span = self.index.span(varnode)
        fragments = self.index.fragments(key, span)
        result, cursor = self.z3.BitVecVal(0, span.size * 8), span.start
        for fragment in fragments:
            identifier = fragment.definition_ids[0]
            source = self.index.ssa.definitions[identifier].span
            if fragment.span.start != cursor or not source.contains(fragment.span):
                raise _Refused()
            value = self.definition(identifier)
            offset = fragment.span.start - source.start
            value = self.z3.Extract((offset + fragment.span.size) * 8 - 1, offset * 8, value)
            from ._record_expression_bv import resize
            result |= resize(value, span.size * 8) << (8 * (fragment.span.start - span.start))
            cursor = fragment.span.end
        if cursor != span.end:
            raise _Refused()
        return result

    def definition(self, identifier):
        step()
        if identifier in self.cache:
            return self.cache[identifier]
        if identifier in self.active or len(self.active) >= 64 or len(self.cache) >= 256:
            raise _Refused()
        definition = self.index.ssa.definitions[identifier]
        span, key = definition.span, definition.operation_key
        if key in self.index.excluded:
            raise _Refused()
        if not 0 < span.size <= 32 or span.object_id.kind not in (
                StorageObjectKind.REGISTER_FILE, StorageObjectKind.FUNCTION_UNIQUE):
            raise _Refused()
        operation = self.index.raw.get(key)
        boundary = definition.kind is MemoryDefinitionKind.ENTRY and span.object_id.kind is StorageObjectKind.REGISTER_FILE
        if definition.kind is MemoryDefinitionKind.DATA_WRITE and operation is not None \
                and operation.opcode == "LOAD" and self.index.span(operation.output) == span:
            boundary = True
        if boundary:
            if self.root is None:
                if self.address_phase:
                    raise _Refused()
                self.root = identifier, span
                self.symbol = self.z3.BitVec("image_selector", span.size * 8)
                if key is not None:
                    self.reloads[key] = ()
            elif self.root != (identifier, span):
                original = self.index.ssa.definitions[self.root[0]].operation_key
                if not self.address_phase or original is None or key is None \
                        or self.index.raw[original].opcode != "LOAD" or operation is None \
                        or operation.opcode != "LOAD" or span.size != self.root[1].size:
                    raise _Refused()
                self.reloads[key] = self.index.unchanged_reload(original, key, self.dom)
            result = self.symbol
        else:
            if definition.kind is not MemoryDefinitionKind.DATA_WRITE or operation is None \
                    or operation.output is None or self.index.span(operation.output) != span:
                raise _Refused()
            self.active.add(identifier)
            try:
                result = self.arithmetic(operation.opcode,
                    [self.operand(key, v) for v in operation.inputs], span.size * 8)
            finally:
                self.active.remove(identifier)
        self.cache[identifier] = result
        return result
