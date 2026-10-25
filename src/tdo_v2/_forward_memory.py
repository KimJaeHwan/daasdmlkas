"""Consume baseline forward address facts at exact memory read occurrences.

No new value analysis or reaching-definition solve: a plan holds the original
normalization and its full claims. It can authorize only a plain STORE label
at a resolved LOAD byte, never an uncertain/unknown effect or an object policy.
"""

from __future__ import annotations

from dataclasses import dataclass

from .resource_limits import step
from .span_geometry import ByteSpan, StorageObjectKind

MAX_PROOFS = 64
MAX_ACCESS_BYTES = 16


class RefinementRefused(Exception):
    """This optional replay cannot use the frozen baseline evidence."""


def _freeze(value):
    if isinstance(value, dict):
        return tuple(sorted((key, _freeze(item)) for key, item in value.items()))
    if isinstance(value, (tuple, list)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set):
        return frozenset(value)
    return value


def _signature(options):
    from .may_alias import ENTRY_VALUES_NOT_FRAME, OPAQUE_NO_STACK_ADDRESSES

    # Image readers belong to this exact run; never compare by an image name.
    options = {"opaque_value_provider": None, **options}
    return (_freeze({key: value for key, value in options.items() if key != "readonly_image"}),
            id(options.get("readonly_image")), ENTRY_VALUES_NOT_FRAME.get(), OPAQUE_NO_STACK_ADDRESSES.get())


@dataclass(frozen=True, slots=True)
class ReadSeparation:
    read: str
    writer: str
    span: ByteSpan
    read_fact: object
    write_fact: object


@dataclass(frozen=True, slots=True)
class MemoryRefinement:
    unit: object
    baseline: object
    signature: tuple
    proofs: tuple[ReadSeparation, ...]
    requires: tuple[str, ...]
    options: tuple
    source: object
    assumptions: tuple[str, ...]

    def bind(self, unit, options):
        if unit is not self.unit or unit.observation is not self.baseline.forward_inputs.observation \
                or _signature(options) != self.signature:
            raise RefinementRefused("normalization inputs changed")
        self.verify()
        return self.proofs

    def verify(self):
        if self.source.unit is not self.unit or self.source.normalized is not self.baseline:
            raise RefinementRefused("original analysis changed")
        expected = prepare_memory_refinement(self.source, dict(self.options), assumptions=self.assumptions)
        if expected is None or expected.signature != self.signature or expected.proofs != self.proofs \
                or expected.requires != self.requires:
            raise RefinementRefused("baseline address evidence changed")


def _offsets(fact, width):
    """Finite full-width offsets; modular byte sets commute with any base."""
    from .forward import MAX_CANDIDATES

    claim = fact.claim
    if fact.context or fact.input != 1 or claim.bits != 64 or len(claim.items) != 1:
        return None
    base, interval = claim.items[0]
    if len(base) != 3 or base[0] != "entry" or base[2] * 8 != claim.bits \
            or not interval.signed or interval.bits != claim.bits or not 0 < width <= MAX_ACCESS_BYTES:
        return None
    if interval.hi < interval.lo or (not interval.single and interval.stride <= 0):
        return None
    count = 1 if interval.single else (interval.hi - interval.lo) // interval.stride + 1
    if not 0 < count <= MAX_CANDIDATES:
        return None
    mask = (1 << claim.bits) - 1
    step(count * width)
    return base, frozenset((offset + byte) & mask
                           for offset in range(interval.lo, interval.hi + 1, interval.stride or 1)
                           for byte in range(width))


def prepare_memory_refinement(result, options, *, assumptions=()):
    """A plan from N0 only, or None. No fact from its replay is accepted here."""
    from .forward import forward_facts
    from ._scope_contracts import VarnodeKindCode
    from .model import ResolvedStorage
    from .normalize import NormalizedFunction
    from .summary_engine import run_assumptions

    normalized, unit = result.normalized, result.unit
    if type(normalized) is not NormalizedFunction or normalized.forward_inputs is None \
            or normalized.forward_memory_proofs or not normalized.may_alias_reads:
        return None
    original = {}
    for instruction in unit.observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            step()
            if operation.opcode in ("LOAD", "STORE"):
                original[f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}:"
                         f"{ordinal}:{operation.opcode}"] = operation
    overrides = dict(normalized.operation_overrides)
    spaces = {space.space_id: space for space in normalized.forward_inputs.address_spaces}
    candidates = [row for row in normalized.may_alias_reads
                  if row.operation_key in original and original[row.operation_key].opcode == "LOAD"
                  and row.plain and not row.unknown_address]
    if not candidates:
        return None
    assumptions = tuple(sorted(set(assumptions) | set(run_assumptions(
        {result.key: result}, readonly_image=options.get("readonly_image"),
        home_space=options.get("private_frame_above", 0)))))
    facts = {fact.operation: fact for fact in forward_facts(
        normalized, unit, readonly_image=options.get("readonly_image"), assumptions=assumptions)}
    effects = {effect.operation_key: effect for block in normalized.forward_inputs.effect_unit.blocks
               for effect in block.effects}
    proofs = []
    for row in candidates:
        load, read_fact = original[row.operation_key], facts.get(row.operation_key)
        if read_fact is None or row.operation_key in overrides or load.output is None:
            continue
        space = spaces.get(load.inputs[0].coordinate.byte_offset)
        if load.inputs[0].kind is not VarnodeKindCode.CONSTANT or space is None \
                or not space.is_memory_space or space.address_size_bits != 64:
            continue
        size = load.output.byte_size
        left = _offsets(read_fact, size)
        if left is None or load.inputs[1].byte_size * 8 != read_fact.claim.bits:
            continue
        reads = [evidence.span for evidence in effects[row.operation_key].reads
                 if type(evidence) is ResolvedStorage and evidence.span.object_id.kind in
                 (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)]
        # One complete original memory read. Register operands are not the target.
        if len(reads) != 1 or reads[0].size != size:
            continue
        for writer in row.plain:
            step()
            store, write_fact = original.get(writer), facts.get(writer)
            # A selector is the memory-space ID, not an address operand.
            # Ghidra can encode the same ID with different constant widths.
            if store is None or store.opcode != "STORE" or writer in overrides or write_fact is None \
                    or store.inputs[0].kind is not VarnodeKindCode.CONSTANT \
                    or store.inputs[0].coordinate.byte_offset != space.space_id \
                    or write_fact.function != read_fact.function \
                    or write_fact.function != result.key or store.inputs[1].byte_size * 8 != write_fact.claim.bits:
                continue
            effect = effects.get(writer)
            writes = [] if effect is None else [e.span for e in effect.writes if type(e) is ResolvedStorage
                       and e.span.object_id.kind in (StorageObjectKind.ADDRESS_SPACE,
                                                    StorageObjectKind.FUNCTION_RELATIVE)]
            # Extra/unknown effects cannot be justified by this one raw STORE.
            if effect is None or len(writes) != 1 or effect.memory_write is not None \
                    or effect.unresolved_writes or writes[0].size != store.inputs[2].byte_size:
                continue
            right = _offsets(write_fact, store.inputs[2].byte_size)
            if right is None or left[0] != right[0] or left[1] & right[1]:
                continue
            proofs.append(ReadSeparation(row.operation_key, writer, reads[0], read_fact, write_fact))
            if len(proofs) > MAX_PROOFS:
                return None  # local optional cap: keep the complete original result
    if not proofs:
        return None
    requires = tuple(sorted(set(assumptions) | {label for proof in proofs
                            for fact in (proof.read_fact, proof.write_fact) for label in fact.requires}))
    return MemoryRefinement(unit, normalized, _signature(options), tuple(proofs), requires, tuple(options.items()),
                            result, assumptions)


def exclusions_for(plan, effect_unit):
    """Validate full baseline claims, then waive original resolved bytes only."""
    from .model import ResolvedStorage

    if type(plan) is not MemoryRefinement:
        raise RefinementRefused("a validated baseline plan is required")
    plan.verify()
    if effect_unit.function_scope != plan.unit.scopes.function.scope:
        raise RefinementRefused("activation changed")
    effects = {effect.operation_key: effect for block in effect_unit.blocks for effect in block.effects}
    found = {}
    for proof in plan.proofs:
        step()
        read, writer = effects.get(proof.read), effects.get(proof.writer)
        if type(proof) is not ReadSeparation or read is None or writer is None \
                or ResolvedStorage(proof.span) not in read.reads:
            raise RefinementRefused("original read occurrence changed")
        for offset in range(proof.span.start, proof.span.end):
            step()
            found.setdefault((proof.read, proof.span.object_id, offset), set()).add(proof.writer)
    return {key: frozenset(value) for key, value in found.items()}
