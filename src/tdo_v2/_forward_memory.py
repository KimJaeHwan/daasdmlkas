"""Consume baseline forward address facts at exact memory read occurrences.

No new value analysis or reaching-definition solve: a plan holds the original
normalization and its full claims. Address claims authorize plain STORE labels
at exact LOAD bytes; separate sealed lifecycle claims can discharge one CALL
at exact reader bytes or connect a conditional resize-copy fragment. None of
these claims grants an object-wide policy or clears unrelated unknown effects.
"""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
from contextvars import ContextVar

from .resource_limits import step
from .span_geometry import ByteSpan, StorageObjectKind

MAX_PROOFS = 64
MAX_ACCESS_BYTES = 16
_VERIFIED = ContextVar("tdo_memory_refinement_verification", default=None)


@contextmanager
def verification_session():
    """Deduplicate derivations only inside one synchronous analysis/replay.

    No cache survives its owner operation. Every hit still rechecks source
    and peer pins; mutable caller state is never trusted by object ID alone.
    """
    if _VERIFIED.get() is not None:
        yield
        return
    token = _VERIFIED.set({})
    try:
        yield
    finally:
        _VERIFIED.reset(token)


class RefinementRefused(Exception):
    """This optional replay cannot use the frozen baseline evidence."""


def _freeze(value):
    if isinstance(value, dict):
        # Condition maps can use immutable AnchoredSpan pairs as keys. Their
        # equality matters; imposing an ordering on those keys is invalid.
        return frozenset((key, _freeze(item)) for key, item in value.items())
    if isinstance(value, (tuple, list)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set):
        return frozenset(value)
    return value


def _signature(options):
    from .may_alias import ENTRY_VALUES_NOT_FRAME, OPAQUE_NO_STACK_ADDRESSES
    from ._activation_entry import ACTIVE_ENTRY

    # Image readers belong to this exact run; never compare by an image name.
    options = {"opaque_value_provider": None, **options}
    return (_freeze({key: value for key, value in options.items() if key != "readonly_image"}),
            id(options.get("readonly_image")), ENTRY_VALUES_NOT_FRAME.get(), OPAQUE_NO_STACK_ADDRESSES.get(),
            id(ACTIVE_ENTRY.get()))


def _verification_source_pin(item):
    """Snapshot all mutable analysis fields read by these derivations.

    Units/normalized SSA and model records are frozen accepted inputs. Maps,
    inherited dependencies and superseded run inputs are copied by value.
    The mutable import-slot policy is checked by _policy before every hit.
    """
    from ._call_activation import _source_signature
    runtime = ()
    if len(item.normalization_context) == 7:
        _, _, imports, _, image, _, _ = item.normalization_context
        runtime = (None if imports is None else (imports.active, _freeze(imports.slots)),
                   None if image is None else (image.ranges, _freeze(image.lengths), id(image.relocates)))
    return (_source_signature(item), item.key, _freeze(item.calls), _freeze(item.multi_calls),
            _freeze(item.declared), _freeze(item.proven), frozenset(item.inherited_assumptions),
            _freeze(item.summary_inputs), item.summary, item.recursion_unresolved, runtime,
            None if item.superseded is None else _verification_source_pin(item.superseded))


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
    evidence_kind: str = "address"
    peers: tuple = ()
    contracts: tuple = ()
    peer_signatures: tuple = ()
    call_effects: tuple = ()
    call_decisions: tuple = ()
    copy_proofs: tuple = ()

    def bind(self, unit, options):
        if unit is not self.unit or unit.observation is not self.baseline.forward_inputs.observation \
                or _signature(options) != self.signature:
            raise RefinementRefused("normalization inputs changed")
        self.verify()
        return self.proofs

    def verify(self):
        with verification_session():
            self._verify()

    def _verify(self):
        if self.source.unit is not self.unit or self.source.normalized is not self.baseline:
            raise RefinementRefused("original analysis changed")
        from ._call_activation import _source_signature, _policy
        import os
        from .relative_memory import index_addresses, DEFINITION_ATOMS
        cache, pin = None, None
        if self.evidence_kind in ("allocation", "allocation-call", "realloc-copy"):
            with _policy(self.source):
                pass
            for _, peer in self.peers:
                if getattr(peer.normalized, "forward_inputs", None) is not None:
                    with _policy(peer):
                        pass
            pin = (_verification_source_pin(self.source),
                   tuple((key, _verification_source_pin(item)) for key, item in self.peers),
                   _signature(dict(self.options)), os.environ.get("TDO_V2_FORWARD"), index_addresses(), DEFINITION_ATOMS)
            prior = self.baseline.forward_inputs.read_separations
            if prior is not None:
                prior.verify()  # A parent hit cannot hide a changed earlier batch.
            cache = _VERIFIED.get()
            cached = cache.get(id(self))
            if cached is not None and cached[0] is self and cached[1] == pin:
                return
        if self.evidence_kind in ("allocation", "allocation-call", "realloc-copy"):
            from ._allocation_memory import prepare_allocation_refinement, prepare_allocation_call_refinement
            from ._call_activation import _source_signature
            if self.contracts != self.source.allocation_contracts:
                raise RefinementRefused("lifecycle contract input changed")
            if self.peer_signatures != tuple((key, _source_signature(item)) for key, item in self.peers):
                raise RefinementRefused("lifecycle peer snapshot changed")
            if self.evidence_kind == "realloc-copy":
                from ._realloc_contents import prepare_realloc_contents
                expected = prepare_realloc_contents(self.source, results=dict(self.peers))
            else:
                expected = (prepare_allocation_refinement(self.source, dict(self.options),
                        results=dict(self.peers), assumptions=self.assumptions) if self.evidence_kind == "allocation"
                        else prepare_allocation_call_refinement(self.source, results=dict(self.peers)))
        elif self.evidence_kind == "address":
            expected = prepare_memory_refinement(self.source, dict(self.options), assumptions=self.assumptions)
        else:
            raise RefinementRefused("unsupported sealed memory proof kind")
        if expected is None or expected.signature != self.signature or expected.proofs != self.proofs \
                or expected.options != self.options \
                or expected.requires != self.requires or expected.call_effects != self.call_effects \
                or expected.call_decisions != self.call_decisions or expected.copy_proofs != self.copy_proofs:
            raise RefinementRefused("baseline address evidence changed")
        if cache is not None:
            cache[id(self)] = self, pin


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
        exact_read = read is not None and ResolvedStorage(proof.span) in read.reads
        contained_read = plan.evidence_kind == "realloc-copy" and read is not None and any(
            type(row) is ResolvedStorage and row.span.object_id == proof.span.object_id
            and row.span.start <= proof.span.start < proof.span.end <= row.span.end for row in read.reads)
        if type(proof) is not ReadSeparation or read is None or writer is None \
                or not (exact_read or contained_read):
            raise RefinementRefused("original read occurrence changed")
        for offset in range(proof.span.start, proof.span.end):
            step()
            found.setdefault((proof.read, proof.span.object_id, offset), set()).add(proof.writer)
    return {key: frozenset(value) for key, value in found.items()}
