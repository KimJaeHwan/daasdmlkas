"""Conservative exact-address projection for indirect Low-PCode memory."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib

from ._scope_contracts import (
    AddressSpaceClassV2,
    AddressSpaceEvidence,
    ValidatedFunctionObservation,
    ValidatedOperation,
    ValidatedVarnode,
    VarnodeKindCode,
    classify_address_space_v2,
)
from .call_seeds import _operation_key as _numeric_operation_key
from .effects import ObservedEffect, ObservedEffectBlock, ObservedEffectUnit
from .effect_decode import decode_effect_unit
from .memory_contracts import LocalMemorySsaResult, MemoryDefinitionKind
from .model import (
    NonStorage,
    ResolvedStorage,
    StorageObjectId,
    StorageObjectKind,
    StorageRef,
    StorageResolutionContext,
    VarnodeKind,
)
from .opaque_values import (
    NullOpaqueValueEvidenceProvider,
    OpaqueValueEvidenceProvider,
    OpaqueValueEvidenceResolver,
)
from .span_geometry import ByteSpan
from .storage import _resolve_validated_storage


@dataclass(frozen=True, slots=True)
class _AddressExpression:
    atoms: tuple[tuple[int, int], ...]
    displacement: int
    byte_size: int
    # with ``IMAGE_BASE_TRACKING`` on: 1 -- an address in the image (moves
    # with its load base), 0 -- no image address in it, None -- may depend on
    # the load base otherwise (masked, two addresses, a number in the image
    # range not proven to relocate, a cancellation)
    image: int | None = 0


# Deriving summaries for reuse as models (``summary_templates``): a constant
# is an image address -- it moves with the library's load base -- only when
# its instruction proves it (``relocates``: a relocation entry or a
# RIP-relative displacement there yields it); any other number in the image
# (end included) may or may not move. When set, a function whose analysis
# takes a number that may depend on the load base as a fact -- an exact place
# relative to an entry value, an absolute place, an extent, a stack delta, a
# null test -- is recorded in ``found`` (its function scope digest) and cannot
# be exported. Off (None) everywhere else: no effect on analysis.
from contextvars import ContextVar

IMAGE_BASE_TRACKING: ContextVar = ContextVar("IMAGE_BASE_TRACKING", default=None)

# Named assumption import-slots-hold-their-exports (docs section 25.2 B): set
# by ``interprocedural.analyze_units`` for one run. A pointer-sized read of a
# whole import slot (``image_info.imports[*].slots``) whose entry value is
# read (nothing in the function writes it) is the address the import resolves
# to: one atom per imported symbol, the same value wherever and whenever it is
# read. A one-byte access AT that address (displacement 0, independent of the
# image base) is in image-backed static storage of a loaded module: never the
# stack (with globals-disjoint-from-stack, ``active``), never a private frame.
# No claim about wider accesses or other displacements (no extent evidence),
# fresh blocks, or other imports.
IMPORT_SLOTS: ContextVar = ContextVar("IMPORT_SLOTS", default=None)


class ImportSlots:
    """``image_info``'s import slots for one ``analyze_units`` run.
    ``active``: the run also takes globals-disjoint-from-stack (else the
    property gives nothing and is not used). ``used``: function scopes whose
    analysis read an import slot this way (reported; recorded when the value
    is evaluated, so a provisional evaluation may over-report -- never under).
    Only an ENTRY definition qualifies: a write the function makes to the slot
    (definite or summarized) gives another definition and nothing is assumed;
    an unknown-address write before the read leaves the ENTRY definition with
    its debt, and the assumption (no write changes the slot) covers it.
    Two slots of one import give one atom; two imports never get a
    disjointness claim (an export alias or a forwarder may be one address):
    their objects may alias, as may ``[p]`` and ``[p + c]``."""

    def __init__(self, image_info) -> None:
        self.slots = {
            (space_id, offset): (row.library.upper(), row.original_name or row.name)
            for row in (image_info.imports if image_info is not None else ())
            for space_id, offset in row.slots
        }
        self.active = False
        self.used: set = set()

    def atom(self, space_id: int, offset: int) -> int | None:
        symbol = self.slots.get((space_id, offset)) if self.active else None
        if symbol is None:
            return None
        return _digest_ints(b"import-slot-value-v1", tuple(
            int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest()[:8], "big") for text in symbol))


class ImageBaseTracking:
    """``with ImageBaseTracking(ranges, relocates) as found:`` -- see above.
    ``ranges``: (start, end) of every memory block of the image;
    ``relocates(instruction address, length or None, value)``: True -- the
    instruction's encoding proves ``value`` an image address, False -- a fixed
    number, None -- not understood (``summary_templates.image_provenance``);
    ``relocates`` None: nothing understood.
    ``lengths``: instruction address -> length (from its fallthrough; filled
    by ``interprocedural.analyze_units``) -- an instruction of unknown length
    proves nothing."""

    def __init__(self, ranges, relocates=None) -> None:
        self.ranges, self.relocates, self.found = tuple(ranges), relocates, set()
        self.lengths: dict = {}
        self.proofs = {True: set(), False: set(), None: set()}   # (instruction, value) by provenance

    def in_image(self, value: int) -> bool:
        return any(start <= value <= end for start, end in self.ranges)

    def provenance(self, instruction: int | None, value: int):
        """True / False / None as ``relocates`` (``length`` None when unknown)."""
        found = None if instruction is None or self.relocates is None             else self.relocates(instruction, self.lengths.get(instruction), value)
        self.proofs[found].add((instruction, value))
        return found

    def coefficient(self, instruction: int | None, value: int) -> int | None:
        """1: a proven image address (in the image range or not -- ``&end + 8``);
        0: a fixed number outside the image; None: otherwise."""
        found = self.provenance(instruction, value)
        if found is True:
            return 1
        return 0 if found is False and not self.in_image(value) else None

    def __enter__(self):
        self._token = IMAGE_BASE_TRACKING.set(self)
        return self.found

    def __exit__(self, *_):
        IMAGE_BASE_TRACKING.reset(self._token)


def import_object_ids(scope, atom: int, space_id: int) -> tuple:
    """The objects a function builds on an import atom: the one accessed AT the
    import's address (import-static, nonstack) and the one of any other
    displacement (``_Projector._relative_object``) -- anchorable on the slot
    (``interprocedural._relative_anchors``)."""
    return (
        StorageObjectId(StorageObjectKind.FUNCTION_RELATIVE, scope,
                        _digest_ints(b"import-static-v1", (atom, space_id))),
        StorageObjectId(StorageObjectKind.FUNCTION_RELATIVE, scope,
                        _digest_ints(b"relative-address-space-v1", (_address_atom_key(((atom, 1),)), space_id))),
    )


def _instruction_of(operation_key) -> int | None:
    """The instruction address of a p-code operation key (not a call row)."""
    if not operation_key or "~" in operation_key:
        return None
    parts = operation_key.split(":")
    return int(parts[1], 16) if len(parts) >= 2 else None


def _image_of_constant(value: int, operation_key=None) -> int | None:
    tracking = IMAGE_BASE_TRACKING.get()
    if tracking is None:
        return 0
    return tracking.coefficient(_instruction_of(operation_key), value)


def _sum_images(left, right) -> int | None:
    """{0, 1, None}: an image address plus a number is one; two addresses,
    or anything unknown, are not (no arithmetic cancels a coefficient)."""
    if left == 0 or right == 0:
        return right if left == 0 else left
    return None


def _difference_image(left, right) -> int | None:
    """``left - right``: subtracting a number keeps ``left``; subtracting an
    address -- even from one, ``&end - &start`` -- is taken as unknown (a
    scalar equal to an address cancels nothing, Astra)."""
    return left if right == 0 else None


def _opaque_image(*expressions) -> int | None:
    """A non-affine operation: base-dependent when any input is."""
    return 0 if all(item.image == 0 for item in expressions) else None


def _note_base_dependent(scope) -> None:
    tracking = IMAGE_BASE_TRACKING.get()
    if tracking is not None:
        tracking.found.add(scope.digest)


def _note_fact(scope, expression, address=False) -> None:
    """``expression``'s number becomes a fact (a place, a count, an offset, a
    null test): base-dependent unless it holds no image base -- or, as an
    absolute address (``address``, no atoms), exactly one (an image address
    is an image address under any base)."""
    if expression.image == 0 or (address and not expression.atoms and expression.image == 1):
        return
    _note_base_dependent(scope)


_KIND_MAP = {
    VarnodeKindCode.CONSTANT: VarnodeKind.CONSTANT,
    VarnodeKindCode.REGISTER: VarnodeKind.REGISTER,
    VarnodeKindCode.UNIQUE: VarnodeKind.UNIQUE,
    VarnodeKindCode.ADDRESS: VarnodeKind.ADDRESS,
    VarnodeKindCode.STORAGE: VarnodeKind.STORAGE,
    VarnodeKindCode.OPAQUE: VarnodeKind.UNKNOWN,
}


def project_function_relative_memory(
    unit: ObservedEffectUnit,
    observation: ValidatedFunctionObservation,
    context: StorageResolutionContext,
    address_spaces: tuple[AddressSpaceEvidence, ...],
    first_pass: LocalMemorySsaResult,
    opaque_value_provider: OpaqueValueEvidenceProvider | None = None,
    translation_namespace: str = "",
    anchored_accesses: dict | None = None,
    readonly_image=None,
    operation_overrides: dict | None = None,
    once_keys: frozenset | None = None,
    wild_objects: set | None = None,
    fresh_keys: frozenset = frozenset(),
    same_object: dict | None = None,
    fresh_objects: set | None = None,
    pointer_rows: dict | None = None,
    nonstack_objects: set | None = None,
    once_blocks: frozenset | None = None,
    settle_pending: bool = True,
    blocked_reads: frozenset = frozenset(),
    used_reads: dict | None = None,
) -> ObservedEffectUnit:
    """Resolve provably equal indirect addresses, preserving all other debt.

    ``settle_pending``: a value read from memory where a write without an
    address yet may reach the read is not used: once that write resolves, the
    read's reaching definition may change, and a projection made from the
    provisional one would never be revisited. ``False`` (the caller's last
    stage, ``normalize``) uses such values: the writes still pending are then
    permanent unknown writers, which every later read may alias (debt).

    ``used_reads`` collects (read operation key, width) -> the values read from
    memory that projections used; ``normalize`` checks them against the final
    state (``stale_reads``) and projects again with the failing reads in
    ``blocked_reads`` (never used).

    ``once_keys``: operation keys executed at most once per activation
    (``single_execution_keys``). A value with no address expression that a
    call (its effect rows) or a LOAD among them defines is fixed for the rest
    of the activation, so it becomes an atom of its own (``_definition_atom``):
    accesses through it form one object, exact within itself and may-alias
    with every other. Such a value may point anywhere, the private stack
    frame included (a callee can return a pointer into it); the objects built
    on these atoms are added to ``wild_objects`` for ``may_alias`` -- except
    ``fresh_keys``: call effect rows writing a register the call is declared
    to set to a newly allocated block (``ProvenCallEffect.fresh_registers``).

    ``same_object``: call effect row key -> (key of the row reading the call's
    arguments, argument varnode) for results declared to address the same
    object as that argument (``ProvenCallEffect.same_object_registers``): the
    result's address expression is the argument's (a constant argument, e.g.
    realloc(NULL, n), makes it a fresh block instead).

    ``fresh_objects`` collects, for ``may_alias``, the objects based on
    exactly one fresh atom.

    ``pointer_rows``: call effect row key -> the pointer value a callee
    summary states for it (``normalize._proven_call_rows``): ("nonstack",) --
    a nonstack definition atom (once per activation, as definition atoms;
    ``nonstack_objects``: disjoint from the stack only); ("reg", input row,
    register varnode, null_is_fresh) / ("mem", load row, width,
    null_is_fresh) -- the caller's value there at the call, substituted (a
    null value with null_is_fresh is a nonstack atom).

    ``anchored_accesses``: effect key -> (evaluation operation key, anchor
    register varnode, displacement, width, address space id) for summarized
    call effects whose memory is "callee entry value of a register +
    displacement": the anchor is evaluated once, at the evaluation operation
    (which reads it), like an address operand."""
    if type(unit) is not ObservedEffectUnit:
        raise TypeError("relative-memory projection requires an exact effect unit")
    if type(observation) is not ValidatedFunctionObservation:
        raise TypeError("relative-memory projection requires an exact observation")
    if type(context) is not StorageResolutionContext:
        raise TypeError("relative-memory projection requires an exact storage context")
    if type(address_spaces) is not tuple or any(
        type(row) is not AddressSpaceEvidence for row in address_spaces
    ):
        raise TypeError("relative-memory projection requires exact address-space evidence")
    if type(first_pass) is not LocalMemorySsaResult:
        raise TypeError("relative-memory projection requires an exact first-pass SSA")
    if type(translation_namespace) is not str:
        raise TypeError("translation namespace must be exact text")
    if (
        first_pass.function_scope != unit.function_scope
        or first_pass.unit_digest != decode_effect_unit(unit).canonical_digest
    ):
        raise ValueError("first-pass SSA belongs to different effect evidence")

    operations = {
        _operation_key(instruction.address, ordinal, operation): operation
        for instruction in observation.instructions
        for ordinal, operation in enumerate(instruction.operations)
    }
    # rep string sites (``normalize._rep_overrides``): what the evaluator sees
    # for their one-iteration operations (None: unknown)
    operations.update(operation_overrides or {})
    projector = _configured_projector(
        unit, observation, context, address_spaces, first_pass, operations, translation_namespace,
        opaque_value_provider=opaque_value_provider, readonly_image=readonly_image, once_keys=once_keys,
        fresh_keys=fresh_keys, same_object=same_object, pointer_rows=pointer_rows, once_blocks=once_blocks,
    )
    if settle_pending:
        projector._unsettled = _unsettled_reads(unit)
    projector._blocked = blocked_reads
    projector.used_reads = used_reads
    if wild_objects is not None:
        projector.wild_objects = wild_objects
    if fresh_objects is not None:
        projector.fresh_objects = fresh_objects
    if nonstack_objects is not None:
        projector.nonstack_objects = nonstack_objects
    # Writes of one summarized call that bind to overlapping caller bytes: the
    # callee took its objects as distinct, so their order there is unknown here
    # (caller passed one object twice) -- they stay unresolved (debt). An
    # anchored write landing on a global the same call writes directly (an
    # exact row) stays unresolved too: the row order says nothing.
    blocked: set[str] = set()
    by_call: dict[str, list] = {}
    fixed: dict[str, list] = {}
    for block in unit.blocks:
        for effect in block.effects:
            anchored = (anchored_accesses or {}).get(effect.operation_key)
            if anchored is not None and effect.memory_write is not None:
                spans = projector.project_anchored(*anchored)
                if spans:
                    by_call.setdefault(effect.operation_key.split("~")[0], []).append(
                        (effect.operation_key, spans[0]))
            elif "~" in effect.operation_key:
                fixed.setdefault(effect.operation_key.split("~")[0], []).extend(
                    item.span for item in effect.writes
                    if type(item) is ResolvedStorage and item.span.object_id.kind is StorageObjectKind.ADDRESS_SPACE)
    for call, rows in by_call.items():
        for index, (key, span) in enumerate(rows):
            if any(span.overlaps(other) for other in fixed.get(call, ())):
                blocked.add(key)
            for other_key, other in rows[index + 1:]:
                if span.overlaps(other):
                    blocked.update((key, other_key))
    changed = False
    blocks: list[ObservedEffectBlock] = []
    for block in unit.blocks:
        effects = []
        for effect in block.effects:
            operation = operations.get(effect.operation_key)
            anchored = (anchored_accesses or {}).get(effect.operation_key)
            if effect.operation_key in blocked:
                projected = None
            elif anchored is not None and (effect.memory_read is not None or effect.memory_write is not None):
                projected = projector.project_anchored(*anchored)
            else:
                projected = (
                    None
                    if operation is None
                    else projector.project_access(effect, operation)
                )
            if projected is None:
                effects.append(effect)
                continue
            if effect.memory_read is not None:
                # A read may depend on every feasible address alternative.
                effects.append(
                    replace(
                        effect,
                        reads=effect.reads + tuple(
                            ResolvedStorage(span) for span in projected
                        ),
                        memory_read=None,
                    )
                )
            elif effect.memory_write is not None:
                # Local SSA writes are definite; an alternative-address write
                # must remain unresolved until may-write semantics exist.
                if len(projected) != 1:
                    raise AssertionError("an alternative-address write must retain debt")
                effects.append(
                    replace(
                        effect,
                        writes=effect.writes + (ResolvedStorage(projected[0]),),
                        memory_write=None,
                    )
                )
            else:
                effects.append(effect)
                continue
            changed = True
        blocks.append(ObservedEffectBlock(block.key, block.predecessors, tuple(effects)))
    if not changed:
        return unit
    return ObservedEffectUnit(
        unit.contract_version,
        unit.function_scope,
        unit.entry_block_key,
        tuple(blocks),
        unit.observed_terminal_block_keys,
        effect_evidence_digest=unit.effect_evidence_digest,
    )


# definition atoms on (``project_function_relative_memory``); tests turn them off
DEFINITION_ATOMS = True
_VALUE_KINDS = frozenset({StorageObjectKind.REGISTER_FILE, StorageObjectKind.FUNCTION_UNIQUE})


def single_execution_keys(observation, block_graph, straight=frozenset()) -> frozenset:
    """Operation keys of blocks on no cycle of ``block_graph`` (the p-code
    block graph the memory SSA uses, intra-instruction flow included): each
    runs at most once per activation. Empty when the graph may miss an edge
    (unsupported flow, or a BRANCHIND with targets outside the observation:
    a jump table could close a loop). ``straight`` instructions (rep sites)
    repeat inside one block and are excluded."""
    if block_graph.unsupported is not None:
        return frozenset()
    instructions = {row.address: row for row in observation.instructions}
    blocks = {block.key: block for block in block_graph.blocks}
    for block in blocks.values():
        last = instructions[block.instruction].operations[block.stop - 1] if block.stop else None
        if last is not None and last.opcode == "BRANCHIND" and block.exits:
            return frozenset()
    cyclic = _cyclic_blocks({key: [item for item in block.successors if item in blocks]
                             for key, block in blocks.items()})
    found = set()
    for key, block in blocks.items():
        if key in cyclic or block.instruction in straight:
            continue
        row = instructions[block.instruction]
        for ordinal in range(block.start, block.stop):
            found.add(_operation_key(row.address, ordinal, row.operations[ordinal]))
    return frozenset(found)


def _unsettled_reads(unit):
    """Predicate on operation keys: a write of ``unit`` without an address yet
    (``memory_write``) may execute before the operation (earlier in its block,
    or in a block that reaches the operation's block); None when no write is
    pending."""
    successors: dict = {block.key: set() for block in unit.blocks}
    for block in unit.blocks:
        for predecessor in block.predecessors:
            successors.setdefault(predecessor, set()).add(block.key)
    first_pending: dict = {}
    position: dict = {}
    for block in unit.blocks:
        for index, effect in enumerate(block.effects):
            position.setdefault(effect.operation_key, (block.key, index))
            if effect.memory_write is not None and block.key not in first_pending:
                first_pending[block.key] = index
    if not first_pending:
        return None
    late, pending = set(), [item for key in first_pending for item in successors.get(key, ())]
    while pending:
        key = pending.pop()
        if key not in late:
            late.add(key)
            pending.extend(successors.get(key, ()))

    def unsettled(operation_key: str) -> bool:
        at = position.get(operation_key)
        if at is None:
            return True
        block_key, index = at
        return block_key in late or index > first_pending.get(block_key, index)

    return unsettled


def single_execution_blocks(observation, block_graph, straight=frozenset()) -> frozenset:
    """Block keys of ``single_execution_keys`` (joins at their entries run once)."""
    keys = single_execution_keys(observation, block_graph, straight)
    if not keys:
        return frozenset()
    rows = {row.address: row for row in observation.instructions}
    return frozenset(
        block.key for block in block_graph.blocks if block.stop > block.start
        if _operation_key(block.instruction, block.start, rows[block.instruction].operations[block.start]) in keys
    )


def _cyclic_blocks(successors: dict) -> set:
    """Nodes on some cycle (a strongly connected component of two or more
    nodes, or a self loop); iterative Tarjan."""
    index, low, on_stack, stack, cyclic = {}, {}, set(), [], set()
    counter = 0
    for root in successors:
        if root in index:
            continue
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        work = [(root, iter(successors[root]))]
        while work:
            node, children = work[-1]
            advanced = False
            for child in children:
                if child not in index:
                    index[child] = low[child] = counter
                    counter += 1
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, iter(successors[child])))
                    advanced = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index[child])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                component = []
                while True:
                    item = stack.pop()
                    on_stack.discard(item)
                    component.append(item)
                    if item == node:
                        break
                if len(component) > 1 or node in successors[node]:
                    cyclic.update(component)
    return cyclic


def _final_projector(normalized, observation) -> "_Projector":
    scopes = normalized.scopes
    operations = {
        _operation_key(instruction.address, ordinal, operation): operation
        for instruction in observation.instructions
        for ordinal, operation in enumerate(instruction.operations)
    }
    operations.update(dict(normalized.operation_overrides))
    return _Projector(
        scopes.resolution_context, scopes.program.evidence.address_spaces, normalized.memory_ssa,
        operations, OpaqueValueEvidenceResolver(NullOpaqueValueEvidenceProvider()),
        scopes.program.evidence.translation_namespace.language_id,
    )


def stack_offset_at(memory_ssa, observation, scopes, operation_key, varnode, stack_span) -> int | None:
    """The value of ``varnode`` (the stack pointer) read by ``operation_key``
    as an offset from its own entry value, or None."""
    operations = {
        _operation_key(instruction.address, ordinal, operation): operation
        for instruction in observation.instructions
        for ordinal, operation in enumerate(instruction.operations)
    }
    projector = _Projector(
        scopes.resolution_context, scopes.program.evidence.address_spaces, memory_ssa, operations,
        OpaqueValueEvidenceResolver(NullOpaqueValueEvidenceProvider()),
        scopes.program.evidence.translation_namespace.language_id,
    )
    expression = projector._expression_for_input(operation_key, varnode)
    if expression is None or expression.atoms != ((_stable_storage_key(stack_span), 1),):
        return None
    _note_fact(memory_ssa.function_scope, expression)
    return _signed_wrap(expression.displacement, expression.byte_size)


def expressions_at(memory_ssa, observation, scopes, requests, overrides=None, blocked=frozenset(),
                   used=None) -> dict:
    """``requests``: (operation key, input varnode). Returns request ->
    (has atoms, displacement, is exactly the entry value of that varnode's
    storage) for the varnode's value at that operation, or None.
    ``blocked`` / ``used``: as ``blocked_reads`` / ``used_reads`` of
    ``project_function_relative_memory`` (checked with ``bare=True``)."""
    operations = {
        _operation_key(instruction.address, ordinal, operation): operation
        for instruction in observation.instructions
        for ordinal, operation in enumerate(instruction.operations)
    }
    operations.update(overrides or {})
    projector = _Projector(
        scopes.resolution_context, scopes.program.evidence.address_spaces, memory_ssa, operations,
        OpaqueValueEvidenceResolver(NullOpaqueValueEvidenceProvider()),
        scopes.program.evidence.translation_namespace.language_id,
    )
    projector._blocked = blocked
    projector.used_reads = used
    found = {}
    for operation_key, varnode in requests:
        expression = projector._expression_for_input(operation_key, varnode)
        if expression is None:
            found[(operation_key, varnode)] = None
            continue
        span = projector._resolved_span(varnode)
        entry = span is not None and expression.atoms == ((_stable_storage_key(span), 1),)             and expression.displacement == 0
        _note_fact(memory_ssa.function_scope, expression)
        found[(operation_key, varnode)] = (
            bool(expression.atoms), _unsigned_wrap(expression.displacement, expression.byte_size), entry)
    return found


def _configured_projector(unit, observation, context, address_spaces, ssa, operations, translation_namespace,
                          *, opaque_value_provider=None, readonly_image=None, once_keys=None,
                          fresh_keys=frozenset(), same_object=None, pointer_rows=None, once_blocks=None):
    projector = _Projector(
        context,
        address_spaces,
        ssa,
        operations,
        OpaqueValueEvidenceResolver(
            NullOpaqueValueEvidenceProvider()
            if opaque_value_provider is None
            else opaque_value_provider
        ),
        translation_namespace,
        readonly_image,
        once_keys if DEFINITION_ATOMS else None,
        fresh_keys,
        same_object,
        pointer_rows,
    )
    projector._once_blocks = (once_blocks or frozenset()) if DEFINITION_ATOMS and once_keys else frozenset()
    return projector


def stale_reads(effect_unit, observation, context, address_spaces, memory_ssa, used, *, bare=False,
                translation_namespace="", operation_overrides=None, **projector_options) -> frozenset:
    """Read operation keys of ``used`` (see ``project_function_relative_memory``)
    whose value differs on the final state: re-evaluated on ``memory_ssa``
    with nothing pending, every value used earlier must be the same."""
    if not used:
        return frozenset()
    operations = {
        _operation_key(instruction.address, ordinal, operation): operation
        for instruction in observation.instructions
        for ordinal, operation in enumerate(instruction.operations)
    }
    operations.update(operation_overrides or {})
    if bare:
        projector = _Projector(context, address_spaces, memory_ssa, operations,
                               OpaqueValueEvidenceResolver(NullOpaqueValueEvidenceProvider()),
                               translation_namespace)
    else:
        projector = _configured_projector(effect_unit, observation, context, address_spaces, memory_ssa,
                                          operations, translation_namespace, **projector_options)
    failed = set()
    for (operation_key, byte_size), values in used.items():
        final = projector._expression_from_memory_read(operation_key, byte_size)
        if any(value != final for value in values):
            failed.add(operation_key)
    return frozenset(failed)


def project_anchored_after(normalized, observation, requests) -> dict:
    """``requests``: (evaluation key, anchor register varnode, displacement,
    width, space id) on the final memory SSA. Returns request -> the exact
    span in this function's objects, or None."""
    projector = _final_projector(normalized, observation)
    found = {}
    for request in requests:
        spans = projector.project_anchored(*request)
        found[request] = None if not spans else spans[0]
    return found


def constant_values(normalized, observation, requests, addresses=False) -> dict:
    """``requests``: (operation key, input varnode). Returns request -> the
    constant the varnode provably holds at that operation (no atoms; the
    final memory SSA's single reaching definition chain); others absent.
    ``addresses``: the values are used as addresses (a call target), so an
    address in the image is base-independent (``IMAGE_BASE_TRACKING``)."""
    projector = _final_projector(normalized, observation)
    found = {}
    for operation_key, varnode in requests:
        expression = projector._expression_for_input(operation_key, varnode)
        if expression is not None and not expression.atoms:
            if expression.image not in (0, 1) or (expression.image and not addresses):
                _note_base_dependent(normalized.memory_ssa.function_scope)
            found[(operation_key, varnode)] = _unsigned_wrap(expression.displacement, expression.byte_size)
    return found


def register_value_deltas(normalized, observation, requests) -> dict:
    """``requests``: (definition id, register span) of the final memory SSA.
    Returns request -> c when the definition's value is exactly "entry value of
    that same span + c" (signed), by the address-expression evaluator; other
    requests are absent. Used for the stack-pointer summary (AFFINE)."""
    projector = _final_projector(normalized, observation)
    found = {}
    for definition_id, span in requests:
        expression = projector._expression_for_definition(definition_id, span)
        if expression is not None and expression.atoms == ((_stable_storage_key(span), 1),) \
                and expression.byte_size == span.size:
            if expression.image != 0:
                _note_base_dependent(normalized.memory_ssa.function_scope)
            found[(definition_id, span)] = _signed_wrap(expression.displacement, span.size)
    return found


class _Projector:
    def __init__(
        self,
        context,
        address_spaces,
        first_pass,
        operations,
        opaque_values,
        translation_namespace,
        readonly_image=None,
        once_keys=None,
        fresh_keys=frozenset(),
        same_object=None,
        pointer_rows=None,
    ) -> None:
        self._context = context
        self._spaces = {row.space_id: row for row in address_spaces}
        self._ssa = first_pass
        self._operations = operations
        self._opaque_values = opaque_values
        self._translation_namespace = translation_namespace
        # named assumption readonly-image-data-is-constant (``image_info``):
        # entry contents of read-only image memory are its image bytes
        self._readonly = readonly_image
        self._once = once_keys or frozenset()
        self._definition_atoms: set[int] = set()   # wild ones
        self._fresh = fresh_keys
        self._same_object = same_object or {}
        self._fresh_atoms: set[int] = set()
        self.fresh_objects: set = set()
        self._pointer_rows = pointer_rows or {}
        self._once_blocks: frozenset = frozenset()
        # reader operation key -> whether a pending write may reach it
        # (``settle_pending``); None: nothing pending
        self._unsettled = None
        self._blocked: frozenset = frozenset()
        self.used_reads: dict | None = None
        self._nonstack_atoms: set[int] = set()
        self._import_atoms: set[int] = set()   # import-slots-hold-their-exports (``IMPORT_SLOTS``)
        self.nonstack_objects: set = set()
        self.wild_objects: set = set()
        self._action_ids = {
            action.operation_key: action_id
            for action_id, action in enumerate(first_pass.actions)
        }
        self._join_sources = {
            row.join_definition_id: row.source_definition_ids
            for row in first_pass.joins
        }
        self._cache: dict[tuple[int, ByteSpan], _AddressExpression | None] = {}
        self._active: set[tuple[int, ByteSpan]] = set()

    def project_access(
        self,
        effect: ObservedEffect,
        operation: ValidatedOperation,
    ) -> tuple[ByteSpan, ...] | None:
        operation_key = effect.operation_key
        if operation.opcode not in {"LOAD", "STORE"} or len(operation.inputs) < 2:
            return None
        selector = operation.inputs[0]
        if selector.kind is not VarnodeKindCode.CONSTANT:
            return None
        space = self._spaces.get(selector.coordinate.byte_offset)
        if (
            space is None
            or space.classification_revision != 2
            or space.addressable_unit_bytes != 1
            or classify_address_space_v2(space) is not AddressSpaceClassV2.ADDRESS
        ):
            return None
        if operation.opcode == "LOAD":
            addresses = self._candidate_expressions_for_input(
                operation_key, operation.inputs[1]
            )
        else:
            address = self._expression_for_input(
                operation_key, operation.inputs[1]
            )
            addresses = (address,) if address is not None else None
        if addresses is None or any(
            address.byte_size * 8 != space.address_size_bits
            for address in addresses
        ):
            return None
        width = (
            operation.output.byte_size
            if operation.opcode == "LOAD" and operation.output is not None
            else operation.inputs[2].byte_size
            if operation.opcode == "STORE" and len(operation.inputs) > 2
            else None
        )
        access = effect.memory_read if operation.opcode == "LOAD" else effect.memory_write
        if width is None or not self._matches_observed_access(
            effect,
            operation,
            access,
            width,
        ):
            return None
        spans = []
        for address in addresses:
            if not address.atoms:
                _note_fact(self._ssa.function_scope, address, address=True)
                object_id = StorageObjectId(
                    StorageObjectKind.ADDRESS_SPACE,
                    self._context.program_scope,
                    space.space_id,
                )
                start = _unsigned_wrap(address.displacement, address.byte_size)
                if start + width > 1 << space.address_size_bits:
                    return None
            else:
                object_id = self._relative_object(address, space.space_id, width=width)
                start = (1 << space.address_size_bits) + address.displacement
                if start < 0:
                    return None
            spans.append(ByteSpan(object_id, start, width))
        return tuple(sorted(set(spans), key=lambda span: span.canonical_key))

    def project_anchored(
        self,
        evaluation_key: str,
        anchor: ValidatedVarnode,
        displacement: int,
        width: int,
        space_id: int,
    ) -> tuple[ByteSpan, ...] | None:
        """The bytes at (value of ``anchor`` read by ``evaluation_key``) +
        ``displacement``, in this function's objects (one exact address only)."""
        space = self._spaces.get(space_id)
        if (
            space is None
            or space.classification_revision != 2
            or space.addressable_unit_bytes != 1
            or classify_address_space_v2(space) is not AddressSpaceClassV2.ADDRESS
        ):
            return None
        if type(anchor) is tuple:  # ("mem", key of the row reading the pointer slot)
            address = self._expression_from_memory_read(anchor[1], space.address_size_bits // 8)
        else:
            address = self._expression_for_input(evaluation_key, anchor)
        if address is None or address.byte_size * 8 != space.address_size_bits:
            return None
        if not address.atoms:
            _note_fact(self._ssa.function_scope, address, address=True)
            object_id = StorageObjectId(
                StorageObjectKind.ADDRESS_SPACE, self._context.program_scope, space.space_id,
            )
            start = _unsigned_wrap(address.displacement + displacement, address.byte_size)
            if start + width > 1 << space.address_size_bits:
                return None
        else:
            object_id = self._relative_object(address, space.space_id, displacement, width)
            start = (1 << space.address_size_bits) + address.displacement + displacement
            if start < 0:
                return None
        return (ByteSpan(object_id, start, width),)

    def _relative_object(self, address, space_id, extra: int = 0, width: int | None = None) -> StorageObjectId:
        """``extra``: a displacement added to ``address`` by the caller;
        ``width``: the access's byte size (None: not an access)."""
        if len(address.atoms) == 1 and address.atoms[0][1] == 1 and address.atoms[0][0] in self._import_atoms \
                and address.displacement + extra == 0 and address.image == 0 and width == 1:
            # one byte AT the import's address -- the one byte the image is
            # known to hold there (no extent evidence); a displacement that
            # moves with the image base is not "at" it under another base
            # an access AT an import's address: image-backed static storage
            # (import-slots-hold-their-exports) -- its own object, never the stack
            object_id = import_object_ids(self._ssa.function_scope, address.atoms[0][0], space_id)[0]
            self.nonstack_objects.add(object_id)
            return object_id
        # (an import atom with another displacement or width gets the ordinary
        # object below: it may alias the stack -- but, not being wild, no
        # private frame)
        if address.image != 0:
            # an offset from an entry value (or another atom) that moves with
            # the image base: exact here, wrong under another load address
            _note_base_dependent(self._ssa.function_scope)
        object_id = StorageObjectId(
            StorageObjectKind.FUNCTION_RELATIVE,
            self._ssa.function_scope,
            _digest_ints(b"relative-address-space-v1", (_address_atom_key(address.atoms), space_id)),
        )
        if any(atom in self._definition_atoms for atom, _ in address.atoms):
            self.wild_objects.add(object_id)
        if len(address.atoms) == 1 and address.atoms[0][1] == 1 and address.atoms[0][0] in self._fresh_atoms:
            self.fresh_objects.add(object_id)
        if len(address.atoms) == 1 and address.atoms[0][1] == 1 and address.atoms[0][0] in self._nonstack_atoms:
            self.nonstack_objects.add(object_id)
        return object_id

    def _definition_atom(self, definition, requested_span, fresh=False,
                         nonstack=False) -> _AddressExpression | None:
        """A value defined once per activation by a call (its summarized or
        modeled effect rows) or by a LOAD, exactly at its own width: an atom
        keyed by that definition (never by its inputs -- two calls with the
        same arguments may return different values). A value a call wrote
        without stating it (a ``~u`` row) is such an atom too, a wild one:
        stores through it are uncertain-address writers ("opaque_call_write"
        is address-uncertain, ``function_summary._ADDRESS_UNCERTAIN``)."""
        key = definition.operation_key
        if key is None or definition.span != requested_span:
            return None
        base = key.split("~", 1)[0]
        if base not in self._once or (requested_span.object_id.kind not in _VALUE_KINDS
                                      and not nonstack and not fresh):
            return None
        if "~" in key:
            if base.rsplit(":", 1)[-1] not in ("CALL", "CALLIND"):
                return None
        else:
            operation = self._operations.get(key)
            if operation is None or operation.opcode != "LOAD":
                return None
        if self._unsettled is not None:
            # a value whose memory read waits for a pending write waits too: not
            # an atom of its own now and the read's value later (``settle_pending``)
            row = self._pointer_rows.get(key)
            reader = row[1] if row is not None and row[0] == "mem" else key if "~" not in key else None
            if reader is not None and self._unsettled(reader):
                return None
        if self._blocked:
            row = self._pointer_rows.get(key)
            reader = row[1] if row is not None and row[0] == "mem" else key if "~" not in key else None
            if reader in self._blocked:
                return None  # a value read from memory that failed validation: no identity
        atom = _digest_ints(b"definition-atom-v1", (*key.encode("utf-8"), _stable_storage_key(requested_span)))
        if nonstack and not fresh:
            self._nonstack_atoms.add(atom)
        elif key not in self._fresh and not fresh:
            self._definition_atoms.add(atom)
        else:
            self._fresh_atoms.add(atom)
        return _AddressExpression(((atom, 1),), 0, requested_span.size)

    def _pointer_row(self, definition, requested_span) -> _AddressExpression | None:
        """The address a call effect row holds by its callee's summary
        (``pointer_rows``), or None."""
        row = self._pointer_rows[definition.operation_key]
        if row[0] == "nonstack":
            return self._definition_atom(definition, requested_span, nonstack=True)
        if row[0] == "reg":
            _, reader, argument, null_is_fresh, unique = row
            value = self._expression_for_input(reader, argument)
        else:
            _, reader, width, null_is_fresh, unique = row
            value = self._expression_from_memory_read(reader, width)
        if value is None or value.byte_size != requested_span.size:
            return None
        if not value.atoms and null_is_fresh:
            _note_fact(self._ssa.function_scope, value)
        if not value.atoms and null_is_fresh and _unsigned_wrap(value.displacement, value.byte_size) == 0:
            # realloc(NULL) inside the callee: a new block -- fresh when it is the
            # call's only pointer value (two values could name one block)
            return self._definition_atom(definition, requested_span, nonstack=not unique, fresh=unique)
        return value

    def _stable_definition_key(self, definition_id: int) -> int:
        definition = self._ssa.definitions[definition_id]
        text = f"{definition.kind.name}|{definition.operation_key or ''}|{definition.block_key or ''}"
        return _digest_ints(b"definition-key-v1", (*text.encode("utf-8"), _stable_storage_key(definition.span)))

    def _is_null(self, expression) -> bool:
        if not expression.atoms:
            _note_fact(self._ssa.function_scope, expression)
        return not expression.atoms and _unsigned_wrap(expression.displacement, expression.byte_size) == 0

    def _is_nonstack(self, expression) -> bool:
        return len(expression.atoms) == 1 and expression.atoms[0][1] == 1 and (
            expression.atoms[0][0] in self._nonstack_atoms or expression.atoms[0][0] in self._fresh_atoms)

    def _candidate_expressions_for_input(
        self,
        operation_key: str,
        varnode: ValidatedVarnode,
    ) -> tuple[_AddressExpression, ...] | None:
        singular = self._expression_for_input(operation_key, varnode)
        if singular is not None:
            return (singular,)
        span = self._resolved_span(varnode)
        if span is None:
            return None
        action_id = self._action_ids.get(operation_key)
        if action_id is None:
            return None
        definition_ids = {
            fragment.definition_ids[0]
            for read in self._ssa.reads
            if read.action_id == action_id and read.span == span
            for fragment in read.fragments
        }
        if len(definition_ids) != 1:
            return None
        return self._candidate_expressions_for_definition(
            next(iter(definition_ids)), span, frozenset()
        )

    def _candidate_expressions_for_definition(
        self,
        definition_id: int,
        requested_span: ByteSpan,
        active: frozenset[int],
    ) -> tuple[_AddressExpression, ...] | None:
        if definition_id in active:
            return None
        definition = self._ssa.definitions[definition_id]
        if not definition.span.contains(requested_span):
            return None
        if definition.kind is not MemoryDefinitionKind.JOIN:
            expression = self._expression_for_definition(definition_id, requested_span)
            return (expression,) if expression is not None else None
        candidates: set[_AddressExpression] = set()
        sources = self._join_sources.get(definition_id, ())
        if not sources:
            return None
        for source_id in sources:
            resolved = self._candidate_expressions_for_definition(
                source_id, requested_span, active | {definition_id}
            )
            if resolved is None:
                return None
            candidates.update(resolved)
            if len(candidates) > 8:
                return None
        return tuple(sorted(
            candidates,
            key=lambda item: (item.atoms, item.displacement, item.byte_size),
        ))

    def _matches_observed_access(
        self,
        effect: ObservedEffect,
        operation: ValidatedOperation,
        access,
        width: int,
    ) -> bool:
        if access is None or access.width != width:
            return False
        if operation.opcode == "LOAD":
            if effect.memory_write is not None or operation.output is None:
                return False
        elif effect.memory_read is not None or len(operation.inputs) != 3:
            return False
        raw_address = _storage_ref(operation.inputs[1])
        if access.raw_address != raw_address:
            return False
        return access.address == _resolve_validated_storage(raw_address, self._context)

    def _expression_for_input(
        self,
        operation_key: str,
        varnode: ValidatedVarnode,
    ) -> _AddressExpression | None:
        if varnode.kind is VarnodeKindCode.CONSTANT:
            value = _unsigned_wrap(varnode.coordinate.byte_offset, varnode.byte_size)
            return _AddressExpression((), value, varnode.byte_size, _image_of_constant(value, operation_key))
        span = self._resolved_span(varnode)
        if span is None:
            return None
        action_id = self._action_ids.get(operation_key)
        if action_id is None:
            return None
        definition_ids = {
            fragment.definition_ids[0]
            for read in self._ssa.reads
            if read.action_id == action_id and read.span == span
            for fragment in read.fragments
        }
        if len(definition_ids) != 1:
            return None
        definition_id = next(iter(definition_ids))
        definition = self._ssa.definitions[definition_id]
        if not definition.span.contains(span):
            return None
        return self._expression_for_definition(definition_id, span)

    def _expression_for_definition(
        self,
        definition_id: int,
        requested_span: ByteSpan,
    ) -> _AddressExpression | None:
        cache_key = (definition_id, requested_span)
        if cache_key in self._cache:
            return self._cache[cache_key]
        if cache_key in self._active:
            return None
        definition = self._ssa.definitions[definition_id]
        if not definition.span.contains(requested_span):
            self._cache[cache_key] = None
            return None
        self._active.add(cache_key)
        result: _AddressExpression | None
        constant = None
        imports = IMPORT_SLOTS.get()
        space = self._spaces.get(requested_span.object_id.space_key)
        import_atom = None
        if imports is not None and definition.kind is MemoryDefinitionKind.ENTRY \
                and requested_span.object_id.kind is StorageObjectKind.ADDRESS_SPACE \
                and space is not None and requested_span.size * 8 == space.address_size_bits:
            import_atom = imports.atom(requested_span.object_id.space_key, requested_span.start)
        if import_atom is not None:
            # the whole slot's entry value: the address its import resolves to
            self._import_atoms.add(import_atom)
            imports.used.add(self._ssa.function_scope)
            result = _AddressExpression(((import_atom, 1),), 0, requested_span.size)
            self._active.discard(cache_key)
            self._cache[cache_key] = result
            return result
        if definition.kind is MemoryDefinitionKind.ENTRY and self._readonly is not None \
                and requested_span.object_id.kind is StorageObjectKind.ADDRESS_SPACE:
            constant = self._readonly.value(requested_span.object_id.space_key, requested_span.start,
                                            requested_span.size)
        if constant is not None:
            # image bytes: may hold relocated addresses (base-dependent)
            result = _AddressExpression((), constant, requested_span.size,
                                        None if IMAGE_BASE_TRACKING.get() is not None else 0)
        elif definition.kind is MemoryDefinitionKind.ENTRY:
            result = _AddressExpression(
                ((_stable_storage_key(requested_span), 1),),
                0,
                requested_span.size,
            )
        elif definition.kind is MemoryDefinitionKind.DATA_WRITE:
            if definition.span != requested_span:
                operation = self._operations.get(definition.operation_key)
                result = self._partial_zero_extension(
                    definition.operation_key, operation, definition.span,
                    requested_span,
                )
            else:
                operation = self._operations.get(definition.operation_key)
                result = self._expression_for_operation(
                    definition.operation_key,
                    operation,
                    definition_id,
                    definition.span.size,
                )
        elif definition.kind is MemoryDefinitionKind.JOIN:
            candidates = tuple(
                self._expression_for_definition(source_id, requested_span)
                for source_id in self._join_sources.get(definition_id, ())
            )
            result = (
                candidates[0]
                if candidates
                and candidates[0] is not None
                and all(item == candidates[0] for item in candidates[1:])
                else None
            )
            if result is None and candidates and definition.block_key in self._once_blocks \
                    and definition.span == requested_span and all(
                        item is not None and (self._is_null(item) or self._is_nonstack(item))
                        for item in candidates) and not all(self._is_null(item) for item in candidates):
                # null or a non-stack block on every path into a block run once:
                # a non-stack value fixed for the activation. Keyed by the
                # sources, not the block: joins of the same definitions at two
                # blocks run once pick the same one (the activation's path).
                # Sources by stable identity: SSA ids change between passes
                sources = sorted(self._stable_definition_key(source_id)
                                 for source_id in self._join_sources.get(definition_id, ()))
                atom = _digest_ints(b"join-nonstack-v3", (*sources, _stable_storage_key(requested_span)))
                self._nonstack_atoms.add(atom)
                result = _AddressExpression(((atom, 1),), 0, requested_span.size)
        else:
            result = None
        if result is None and definition.kind is MemoryDefinitionKind.DATA_WRITE \
                and definition.operation_key in self._same_object and definition.span == requested_span:
            reader, argument = self._same_object[definition.operation_key]
            value = self._expression_for_input(reader, argument)
            if value is not None and value.atoms and value.byte_size == requested_span.size:
                result = value
            elif value is not None and not value.atoms:
                _note_fact(self._ssa.function_scope, value)
                # realloc(NULL, n) is a new block; another constant stays that address
                result = (self._definition_atom(definition, requested_span, fresh=True)
                          if _unsigned_wrap(value.displacement, value.byte_size) == 0 else value)
        if result is None and definition.kind is MemoryDefinitionKind.DATA_WRITE \
                and definition.operation_key in self._pointer_rows and definition.span == requested_span:
            result = self._pointer_row(definition, requested_span)
        if result is None and definition.kind is MemoryDefinitionKind.DATA_WRITE:
            result = self._definition_atom(definition, requested_span)
        self._active.remove(cache_key)
        self._cache[cache_key] = result
        return result

    def _constant_written(self, operation_key, operation, byte_size):
        value = None
        if operation.opcode == "STORE" and len(operation.inputs) == 3 and operation.inputs[2].byte_size == byte_size:
            value = self._expression_for_input(operation_key, operation.inputs[2])
        elif operation.opcode == "COPY" and len(operation.inputs) == 1 and operation.inputs[0].byte_size == byte_size:
            value = self._expression_for_input(operation_key, operation.inputs[0])
        if value is None or value.atoms:
            return None
        return value

    def _partial_zero_extension(
        self,
        operation_key: str | None,
        operation: ValidatedOperation | None,
        written_span: ByteSpan,
        requested_span: ByteSpan,
    ) -> _AddressExpression | None:
        # Without a trusted endian/layout match, a subspan of a wider write
        # cannot be interpreted as the low-order bits of its result.
        language_parts = self._translation_namespace.split(":")
        if operation is not None and operation_key is not None and len(language_parts) >= 2 \
                and language_parts[1] == "LE" and written_span.object_id == requested_span.object_id \
                and written_span.contains(requested_span):
            # a constant written value: its little-endian bytes
            written = self._constant_written(operation_key, operation, written_span.size)
            if written is not None:
                whole = _unsigned_wrap(written.displacement, written.byte_size)
                shift = 8 * (requested_span.start - written_span.start)
                return _AddressExpression(
                    (), (whole >> shift) & ((1 << (8 * requested_span.size)) - 1), requested_span.size,
                    _opaque_image(written))
        if (
            operation_key is None
            or operation is None
            or operation.opcode != "INT_ZEXT"
            or len(operation.inputs) != 1
            or operation.output is None
            or len(language_parts) < 2
            or language_parts[1] != "LE"
            or self._resolved_span(operation.output) != written_span
            or written_span.object_id != requested_span.object_id
            or written_span.start != requested_span.start
            or operation.inputs[0].byte_size != requested_span.size
            or not written_span.contains(requested_span)
        ):
            return None
        value = self._expression_for_input(operation_key, operation.inputs[0])
        if value is None or value.atoms:
            return None
        return _AddressExpression(
            (), _unsigned_wrap(value.displacement, value.byte_size),
            requested_span.size, _opaque_image(value),
        )

    def _expression_for_operation(
        self,
        operation_key: str | None,
        operation: ValidatedOperation | None,
        definition_id: int,
        byte_size: int,
    ) -> _AddressExpression | None:
        if operation_key is None or operation is None:
            return None
        if (
            operation.opcode == "STORE"
            and len(operation.inputs) == 3
            and operation.inputs[2].byte_size == byte_size
        ):
            return self._expression_for_input(operation_key, operation.inputs[2])
        if operation.output is None or operation.output.byte_size != byte_size:
            return None
        if operation.opcode == "COPY" and len(operation.inputs) == 1:
            value = self._expression_for_input(operation_key, operation.inputs[0])
            return value if value is not None and value.byte_size == byte_size else None
        if operation.opcode == "INT_ZEXT" and len(operation.inputs) == 1:
            value = self._expression_for_input(operation_key, operation.inputs[0])
            if (
                value is not None
                and not value.atoms
                and value.byte_size < byte_size
            ):
                return _AddressExpression(
                    (), _unsigned_wrap(value.displacement, value.byte_size), byte_size, _opaque_image(value)
                )
        if operation.opcode == "LOAD" and len(operation.inputs) >= 2:
            return self._expression_from_memory_read(operation_key, byte_size)
        if operation.opcode in ("INT_XOR", "INT_SUB", "BOOL_XOR") and len(operation.inputs) == 2 \
                and operation.inputs[0] == operation.inputs[1]:
            return _AddressExpression((), 0, byte_size)  # x ^ x, x - x (``normalize``)
        if operation.opcode in ("INT_AND", "INT_OR", "INT_XOR") and len(operation.inputs) == 2:
            left, right = (self._expression_for_input(operation_key, item) for item in operation.inputs)
            if left is not None and right is not None and not left.atoms and not right.atoms:
                a = _unsigned_wrap(left.displacement, left.byte_size)
                b = _unsigned_wrap(right.displacement, right.byte_size)
                value = a & b if operation.opcode == "INT_AND" else a | b if operation.opcode == "INT_OR" else a ^ b
                return _AddressExpression((), _unsigned_wrap(value, byte_size), byte_size,
                                          _opaque_image(left, right))
        if operation.opcode == "SUBPIECE" and len(operation.inputs) == 2 \
                and operation.inputs[1].kind is VarnodeKindCode.CONSTANT:
            value = self._expression_for_input(operation_key, operation.inputs[0])
            if value is not None and not value.atoms:
                shift = 8 * operation.inputs[1].coordinate.byte_offset
                return _AddressExpression(
                    (), (_unsigned_wrap(value.displacement, value.byte_size) >> shift) & ((1 << (8 * byte_size)) - 1),
                    byte_size, _opaque_image(value))
        if operation.opcode == "INT_SEXT" and len(operation.inputs) == 1:
            value = self._expression_for_input(operation_key, operation.inputs[0])
            if value is not None and not value.atoms and value.byte_size < byte_size:
                return _AddressExpression(
                    (), _unsigned_wrap(_signed_wrap(value.displacement, value.byte_size), byte_size), byte_size,
                    _opaque_image(value),
                )
        if operation.opcode == "INT_MULT" and len(operation.inputs) == 2:
            left, right = (self._expression_for_input(operation_key, item) for item in operation.inputs)
            if left is not None and right is not None and not left.atoms and not right.atoms \
                    and left.byte_size == right.byte_size == byte_size:
                return _AddressExpression((), _unsigned_wrap(left.displacement * right.displacement, byte_size),
                                          byte_size, _opaque_image(left, right))
        if operation.opcode == "INT_LEFT" and len(operation.inputs) == 2:
            value = self._expression_for_input(operation_key, operation.inputs[0])
            shift = self._expression_for_input(operation_key, operation.inputs[1])
            if (
                value is not None
                and shift is not None
                and not value.atoms
                and not shift.atoms
                and value.byte_size == byte_size
            ):
                amount = _unsigned_wrap(shift.displacement, shift.byte_size)
                result = (
                    0
                    if amount >= byte_size * 8
                    else _unsigned_wrap(value.displacement << amount, byte_size)
                )
                return _AddressExpression((), result, byte_size, _opaque_image(value, shift))
        if operation.opcode == "INT_ADD" and len(operation.inputs) == 2:
            expressions = tuple(
                self._expression_for_input(operation_key, item)
                for item in operation.inputs
            )
            if all(
                item is not None and item.byte_size == byte_size
                for item in expressions
            ):
                combined = _add_address_expressions(*expressions, byte_size)
                if combined is not None:
                    return combined
            constants = [item for item in operation.inputs if _is_sized_constant(item, byte_size)]
            values = [item for item in operation.inputs if item.kind is not VarnodeKindCode.CONSTANT]
            if len(constants) == 1 and len(values) == 1:
                base = self._expression_for_input(operation_key, values[0])
                if base is not None and base.byte_size == byte_size:
                    return _AddressExpression(
                        base.atoms,
                        _address_wrap(
                            base,
                            base.displacement + _signed_constant(constants[0]),
                            byte_size,
                        ),
                        byte_size,
                        _sum_images(base.image, _image_of_constant(
                            _unsigned_wrap(constants[0].coordinate.byte_offset, byte_size), operation_key)),
                    )
            return None
        if (
            operation.opcode == "INT_SUB"
            and len(operation.inputs) == 2
        ):
            left = self._expression_for_input(operation_key, operation.inputs[0])
            right = self._expression_for_input(operation_key, operation.inputs[1])
            if (
                left is not None
                and right is not None
                and left.byte_size == byte_size
                and right.byte_size == byte_size
            ):
                combined = _subtract_address_expressions(left, right, byte_size)
                if combined is not None:
                    return combined
            if not _is_sized_constant(operation.inputs[1], byte_size):
                return None
            base = self._expression_for_input(operation_key, operation.inputs[0])
            if base is not None and base.byte_size == byte_size:
                image = _image_of_constant(_unsigned_wrap(operation.inputs[1].coordinate.byte_offset, byte_size),
                                           operation_key)
                return _AddressExpression(
                    base.atoms,
                    _address_wrap(
                        base,
                        base.displacement - _signed_constant(operation.inputs[1]),
                        byte_size,
                    ),
                    byte_size,
                    _difference_image(base.image, image),
                )
            return None
        token = self._opaque_values.resolve(
            self._translation_namespace,
            operation,
        )
        if token is None:
            return None
        inputs = tuple(
            self._expression_for_input(operation_key, item)
            for item in operation.inputs
        )
        if any(item is None for item in inputs):
            return None
        return _AddressExpression(
            ((_opaque_atom_key(token, inputs, byte_size), 1),),
            0,
            byte_size,
            _opaque_image(*inputs),
        )

    def _expression_from_memory_read(
        self,
        operation_key: str,
        byte_size: int,
    ) -> _AddressExpression | None:
        action_id = self._action_ids.get(operation_key)
        if action_id is None:
            return None
        if self._unsettled is not None and self._unsettled(operation_key):
            return None  # a pending write may still redefine these bytes (``settle_pending``)
        if operation_key in self._blocked:
            return None
        value = self._memory_read_value(operation_key, byte_size, action_id)
        if value is not None and self.used_reads is not None:
            self.used_reads.setdefault((operation_key, byte_size), set()).add(value)
        return value

    def _memory_read_value(self, operation_key, byte_size, action_id):
        reads = tuple(
            read
            for read in self._ssa.reads
            if read.action_id == action_id
            and read.span.size == byte_size
            and read.span.object_id.kind
            in {StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE}
        )
        if len(reads) != 1 or len(reads[0].fragments) != 1:
            return None
        fragment = reads[0].fragments[0]
        if fragment.span != reads[0].span or len(fragment.definition_ids) != 1:
            return None
        return self._expression_for_definition(
            fragment.definition_ids[0],
            fragment.span,
        )

    def _resolved_span(self, varnode: ValidatedVarnode) -> ByteSpan | None:
        resolved = _resolve_validated_storage(_storage_ref(varnode), self._context)
        return resolved.span if type(resolved) is ResolvedStorage else None


def _storage_ref(value: ValidatedVarnode) -> StorageRef:
    return StorageRef(
        _KIND_MAP[value.kind],
        "",
        value.coordinate.byte_offset,
        value.byte_size,
        space_id=value.coordinate.space_id,
    )


def _operation_key(address, ordinal: int, operation: ValidatedOperation) -> str:
    return _numeric_operation_key(address, ordinal, operation.opcode)


def _is_sized_constant(value: ValidatedVarnode, byte_size: int) -> bool:
    return value.kind is VarnodeKindCode.CONSTANT and value.byte_size == byte_size


def _signed_constant(value: ValidatedVarnode) -> int:
    return _signed_wrap(value.coordinate.byte_offset, value.byte_size)


def _signed_wrap(value: int, byte_size: int) -> int:
    modulus = 1 << (byte_size * 8)
    unsigned = value % modulus
    sign = modulus >> 1
    return unsigned - modulus if unsigned >= sign else unsigned


def _unsigned_wrap(value: int, byte_size: int) -> int:
    return value % (1 << (byte_size * 8))


def _address_wrap(base: _AddressExpression, value: int, byte_size: int) -> int:
    if not base.atoms:
        return _unsigned_wrap(value, byte_size)
    return _signed_wrap(value, byte_size)


def _add_address_expressions(
    left: _AddressExpression,
    right: _AddressExpression,
    byte_size: int,
) -> _AddressExpression | None:
    atoms = _merge_atoms(left.atoms, right.atoms)
    base = _AddressExpression(atoms, 0, byte_size)
    return _AddressExpression(
        atoms,
        _address_wrap(base, left.displacement + right.displacement, byte_size),
        byte_size,
        _sum_images(left.image, right.image),
    )


def _subtract_address_expressions(
    left: _AddressExpression,
    right: _AddressExpression,
    byte_size: int,
) -> _AddressExpression | None:
    atoms = _merge_atoms(
        left.atoms,
        tuple((atom, -coefficient) for atom, coefficient in right.atoms),
    )
    base = _AddressExpression(atoms, 0, byte_size)
    return _AddressExpression(
        atoms,
        _address_wrap(base, left.displacement - right.displacement, byte_size),
        byte_size,
        _difference_image(left.image, right.image),
    )


def _merge_atoms(*groups: tuple[tuple[int, int], ...]) -> tuple[tuple[int, int], ...]:
    merged: dict[int, int] = {}
    for group in groups:
        for atom, coefficient in group:
            merged[atom] = merged.get(atom, 0) + coefficient
    return tuple(sorted((atom, value) for atom, value in merged.items() if value))


def _address_atom_key(atoms: tuple[tuple[int, int], ...]) -> int:
    values = [len(atoms)]
    for atom, coefficient in atoms:
        values.extend((atom, coefficient))
    return _digest_ints(b"relative-address-atoms-v1", tuple(values))


def _function_relative_object_id(
    function_scope,
    anchor_span: ByteSpan,
    address_space_id: int,
) -> StorageObjectId:
    """Reproduce the exact object identity for one physical affine base."""
    atom = _stable_storage_key(anchor_span)
    return StorageObjectId(
        StorageObjectKind.FUNCTION_RELATIVE,
        function_scope,
        _digest_ints(
            b"relative-address-space-v1",
            (_address_atom_key(((atom, 1),)), address_space_id),
        ),
    )


def _opaque_atom_key(token: str, inputs, byte_size: int) -> int:
    digest = hashlib.sha256()
    _digest_field(digest, b"opaque-address-atom-v1")
    _digest_field(digest, token.encode("utf-8"))
    _digest_integer(digest, byte_size)
    for item in inputs:
        assert item is not None
        _digest_integer(digest, _address_atom_key(item.atoms))
        _digest_integer(digest, item.displacement)
        _digest_integer(digest, item.byte_size)
    return int.from_bytes(digest.digest(), "big")


def _stable_storage_key(span: ByteSpan) -> int:
    kind = {
        StorageObjectKind.REGISTER_FILE: 0,
        StorageObjectKind.ADDRESS_SPACE: 1,
        StorageObjectKind.FUNCTION_UNIQUE: 2,
        StorageObjectKind.FUNCTION_RELATIVE: 3,
    }[span.object_id.kind]
    scope_kind = 0 if span.object_id.scope.kind.value == "program" else 1
    values = (
        kind,
        scope_kind,
        int.from_bytes(span.object_id.scope.digest, "big"),
        span.object_id.space_key,
        span.start,
        span.size,
    )
    return _digest_ints(b"relative-storage-atom-v1", values)


def _digest_ints(domain: bytes, values: tuple[int, ...]) -> int:
    digest = hashlib.sha256()
    _digest_field(digest, domain)
    for value in values:
        _digest_integer(digest, value)
    return int.from_bytes(digest.digest(), "big")


def _digest_integer(digest, value: int) -> None:
    sign = b"+" if value >= 0 else b"-"
    magnitude = abs(value)
    encoded = magnitude.to_bytes(max(1, (magnitude.bit_length() + 7) // 8), "big")
    _digest_field(digest, sign + encoded)


def _digest_field(digest, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


__all__ = ("project_function_relative_memory",)
