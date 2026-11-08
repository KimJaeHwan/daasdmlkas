"""Consume baseline forward address facts at exact memory read occurrences.

No new value analysis or reaching-definition solve: a plan holds the original
normalization and its full claims. Address claims authorize plain STORE labels
at exact LOAD bytes; separate sealed lifecycle claims can discharge one CALL
at exact reader bytes or connect a conditional resize-copy fragment. None of
these claims grants an object-wide policy or clears unrelated unknown effects.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from contextlib import contextmanager
from contextvars import ContextVar

from .resource_limits import step
from .span_geometry import ByteSpan, StorageObjectId, StorageObjectKind

MAX_PROOFS = 64
MAX_ACCESS_BYTES = 16
MAX_READ_ADDRESSES = 64
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
    from .may_alias import ENTRY_VALUES_NOT_FRAME, OPAQUE_NO_STACK_ADDRESSES, PRE_ESCAPE_NOT_FRAME
    from ._activation_entry import ACTIVE_ENTRY

    # Image readers belong to this exact run; never compare by an image name.
    options = {"opaque_value_provider": None, **options}
    return (_freeze({key: value for key, value in options.items() if key != "readonly_image"}),
            id(options.get("readonly_image")), ENTRY_VALUES_NOT_FRAME.get(), OPAQUE_NO_STACK_ADDRESSES.get(),
            PRE_ESCAPE_NOT_FRAME.get(), id(ACTIVE_ENTRY.get()))


def _verification_source_pin(item):
    """Snapshot all mutable analysis fields read by these derivations.

    Units/normalized SSA and model records are frozen accepted inputs. Maps,
    inherited dependencies and superseded run inputs are copied by value.
    The mutable import-slot policy is checked by _policy before every hit.
    """
    from ._call_activation import _source_signature
    runtime = ()
    if len(item.normalization_context) == 9:
        _, _, imports, _, image, _, _, _, _ = item.normalization_context
        runtime = (None if imports is None else (imports.active, _freeze(imports.slots)),
                   None if image is None else (image.ranges, _freeze(image.lengths), id(image.relocates)))
    return (_source_signature(item), item.key, _freeze(item.calls), _freeze(item.multi_calls),
            _freeze(item.declared), _freeze(item.proven), frozenset(item.inherited_assumptions),
            _freeze(item.summary_inputs), item.summary, item.recursion_unresolved, runtime,
            None if item.superseded is None else _verification_source_pin(item.superseded))


def _address_verification_pin(plan):
    """Current inputs of the optional address derivation, never its result.

    Frozen accepted SSA/model records retain their exact identities. Mutable
    option/ForwardInputs maps and import policies are copied by value. An
    arbitrary image/provider has no content-generation receipt: do not cache
    it. Every lookup still checks current fault authority and source policy.
    """
    import os
    from ._activation_entry import ACTIVE_ENTRY
    from ._call_activation import _policy
    from .call_clobber import OPAQUE_RESTORES_SP
    from .forward import ForwardInputs
    from .relative_memory import DEFINITION_ATOMS, IMAGE_BASE_TRACKING, IMPORT_SLOTS, ImportSlots, index_addresses

    source, normalized = plan.source, plan.baseline
    options = dict(plan.options)
    if not hasattr(source, "normalization_context") or len(source.normalization_context) != 9 \
            or options.get("readonly_image") is not None or options.get("opaque_value_provider") is not None \
            or IMAGE_BASE_TRACKING.get() is not None or source.normalization_context[4] is not None \
            or type(normalized.forward_inputs) is not ForwardInputs:
        return None
    captured_imports = source.normalization_context[2]
    imports = IMPORT_SLOTS.get()
    if any(value is not None and type(value) is not ImportSlots for value in (imports, captured_imports)):
        return None
    # This is deliberately before the cache lookup, including a warm hit.
    # _source_signature inside the source pin revalidates once/fault receipts.
    with _policy(source):
        pass
    if not normalized.dependencies.is_frozen or not normalized.cfg.is_frozen:
        return None
    from ._memory_read_sources import read_sources

    try:
        ports = _freeze(read_sources(normalized))  # Recheck original read-port authority, not a new solve.
    except (TypeError, ValueError) as error:
        raise RefinementRefused("source read-port authority changed") from error
    inputs = normalized.forward_inputs
    input_values = tuple((field.name, _freeze(getattr(inputs, field.name))) for field in fields(inputs))
    normalized_values = tuple((field.name, _freeze(getattr(normalized, field.name))) for field in fields(normalized))
    claims = tuple((field.name, _freeze(getattr(plan, field.name))) for field in fields(plan)
                   if field.name not in ("unit", "baseline", "source", "peers"))
    return ("address", _verification_source_pin(source),
            tuple((key, _verification_source_pin(peer)) for key, peer in plan.peers),
            id(plan.unit), id(plan.unit.observation), id(normalized), id(inputs),
            id(normalized.memory_ssa), id(normalized.memory_unit), id(normalized.memory_graph),
            normalized_values, input_values, ports, claims, _signature(options),
            os.environ.get("TDO_V2_FORWARD"), index_addresses(), DEFINITION_ATOMS,
            OPAQUE_RESTORES_SP.get(), id(ACTIVE_ENTRY.get()),
            None if imports is None else (id(imports), imports.active, _freeze(imports.slots)))


@dataclass(frozen=True, slots=True)
class ReadSeparation:
    read: str
    writer: str
    span: ByteSpan
    read_fact: object
    write_fact: object


@dataclass(frozen=True, slots=True)
class ReadAddressProjection:
    """All possible starts of one LOAD, not a contiguous or selected read."""
    read: str
    spans: tuple[ByteSpan, ...]
    read_fact: object


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
    snapshot_demands: tuple = ()
    address_reads: tuple[ReadAddressProjection, ...] = ()

    def bind(self, unit, options):
        if unit is not self.unit or unit.observation is not self.baseline.forward_inputs.observation \
                or _signature(options) != self.signature:
            raise RefinementRefused("normalization inputs changed")
        self.verify()
        return self.proofs

    def verify(self):
        with verification_session():
            cache = _VERIFIED.get()
            active = ("address-active", id(self))
            if self.evidence_kind != "address":
                self._verify()  # Keep the existing lifecycle cache and contract unchanged.
                return
            if active in cache:
                raise RefinementRefused("cyclic address baseline verification")
            cache[active] = self
            try:
                self._verify()
            finally:
                del cache[active]

    def _verify(self):
        if self.snapshot_demands and self.evidence_kind != "allocation-snapshot":
            raise RefinementRefused("snapshot demands require their independent proof kind")
        if self.address_reads and self.evidence_kind != "address":
            raise RefinementRefused("read projections require their independent address proof kind")
        if self.source.unit is not self.unit or self.source.normalized is not self.baseline:
            raise RefinementRefused("original analysis changed")
        from ._call_activation import _source_signature, _policy
        import os
        from .relative_memory import index_addresses, DEFINITION_ATOMS
        cache, pin = None, None
        if self.evidence_kind in ("allocation", "allocation-call", "realloc-copy", "allocation-snapshot"):
            with _policy(self.source):
                pass
            for _, peer in self.peers:
                if getattr(peer.normalized, "forward_inputs", None) is not None:
                    with _policy(peer):
                        pass
            pin = (_verification_source_pin(self.source),
                   tuple((key, _verification_source_pin(item)) for key, item in self.peers),
                   _signature(dict(self.options)), os.environ.get("TDO_V2_FORWARD"), index_addresses(), DEFINITION_ATOMS,
                   self.snapshot_demands)
            prior = self.baseline.forward_inputs.read_separations
            if prior is not None:
                prior.verify()  # A parent hit cannot hide a changed earlier batch.
            cache = _VERIFIED.get()
            cached = cache.get(id(self))
            if cached is not None and cached[0] is self and cached[1] == pin:
                return
        if self.evidence_kind in ("allocation", "allocation-call", "realloc-copy", "allocation-snapshot"):
            from ._allocation_memory import prepare_allocation_refinement, prepare_allocation_call_refinement
            from ._call_activation import _source_signature
            if self.contracts != self.source.allocation_contracts:
                raise RefinementRefused("lifecycle contract input changed")
            if self.peer_signatures != tuple((key, _source_signature(item)) for key, item in self.peers):
                raise RefinementRefused("lifecycle peer snapshot changed")
            if self.evidence_kind == "allocation-snapshot":
                from ._realloc_contents import prepare_old_allocation_snapshot
                expected = prepare_old_allocation_snapshot(self.source, self.snapshot_demands, results=dict(self.peers))
            elif self.evidence_kind == "realloc-copy":
                from ._realloc_contents import prepare_realloc_contents
                expected = prepare_realloc_contents(self.source, results=dict(self.peers))
            else:
                expected = (prepare_allocation_refinement(self.source, dict(self.options),
                        results=dict(self.peers), assumptions=self.assumptions) if self.evidence_kind == "allocation"
                        else prepare_allocation_call_refinement(self.source, results=dict(self.peers)))
        elif self.evidence_kind == "address":
            # In particular, a frozen receipt cannot hide current fault
            # revocation merely because its public value still compares equal.
            if hasattr(self.source, "normalization_options"):
                _source_signature(self.source)
            prior = self.baseline.forward_inputs.read_separations
            if prior is not None:
                if type(prior) is not MemoryRefinement:
                    raise RefinementRefused("address baseline requires an issued memory plan")
                prior.verify()  # A warm address hit cannot bypass an earlier batch.
            pin = _address_verification_pin(self)
            if pin is not None:
                cache = _VERIFIED.get()
                cached = cache.get(id(self))
                if cached is not None and cached[0] is self and cached[1] == pin:
                    return
            expected = prepare_memory_refinement(self.source, dict(self.options), assumptions=self.assumptions)
        else:
            raise RefinementRefused("unsupported sealed memory proof kind")
        if expected is None or expected.signature != self.signature or expected.proofs != self.proofs \
                or expected.options != self.options \
                or expected.assumptions != self.assumptions \
                or expected.requires != self.requires or expected.call_effects != self.call_effects \
                or expected.call_decisions != self.call_decisions or expected.copy_proofs != self.copy_proofs \
                or expected.snapshot_demands != self.snapshot_demands or expected.address_reads != self.address_reads:
            raise RefinementRefused("baseline address evidence changed")
        if cache is not None:
            if self.evidence_kind == "address" and _address_verification_pin(self) != pin:
                raise RefinementRefused("address inputs changed during verification")
            cache[id(self)] = self, pin


def _offsets(fact, width, bits):
    """Finite full-width offsets; modular byte sets commute with any base.
    ``bits``: the memory space's address width (the claim must have it)."""
    from .forward import MAX_CANDIDATES

    claim = fact.claim
    if fact.context or fact.input != 1 or claim.bits != bits or len(claim.items) != 1:
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


def _raw_unresolved_store(effect, store, context):
    """One original STORE's unresolved access, never an unknown effect policy.

    The forward fact describes its possible address bytes only. Keep the raw
    memory write and all summary unknown-writer evidence; a separation can
    waive this occurrence solely at the independently proven reader bytes.
    """
    from .effects import EffectKind, UnresolvedMemoryAccess
    from .model import ResolvedStorage, UnresolvedStorage
    from .normalize import _storage_ref
    from .storage import _resolve_validated_storage

    if effect is None or store.opcode != "STORE" or len(store.inputs) != 3 or store.output is not None \
            or effect.kind is not EffectKind.UNKNOWN_WRITE or effect.writes or effect.call_targets \
            or effect.memory_read is not None or effect.unresolved_reads or effect.unresolved_writes:
        return False
    raw = tuple(_storage_ref(value) for value in store.inputs[1:])
    resolved = tuple(_resolve_validated_storage(value, context) for value in raw)
    if any(type(value) is UnresolvedStorage for value in resolved):
        return False
    reads = tuple(value for value in resolved if type(value) is ResolvedStorage)
    return effect.reads == reads and effect.memory_write == UnresolvedMemoryAccess(
        resolved[0], store.inputs[2].byte_size, raw[0])


def _load_shape(effect, load, context, *, projected=False):
    """Exact raw LOAD dependencies; existing projected memory reads only."""
    from .effects import EffectKind, UnresolvedMemoryAccess
    from .model import ResolvedStorage, UnresolvedStorage
    from .normalize import _storage_ref
    from .storage import _resolve_validated_storage

    if effect is None or load.opcode != "LOAD" or len(load.inputs) != 2 or load.output is None \
            or effect.kind is not EffectKind.READ or effect.call_targets or effect.memory_write is not None \
            or effect.unresolved_reads or effect.unresolved_writes:
        return False
    raw = _storage_ref(load.inputs[1])
    address = _resolve_validated_storage(raw, context)
    output = _resolve_validated_storage(_storage_ref(load.output), context)
    if type(address) is UnresolvedStorage or type(output) is not ResolvedStorage \
            or effect.writes != (output,):
        return False
    reads = (address,) if type(address) is ResolvedStorage else ()
    if effect.memory_read is not None:
        return effect.reads == reads and effect.memory_read == UnresolvedMemoryAccess(
            address, load.output.byte_size, raw)
    memory = effect.reads[len(reads):]
    return projected and effect.reads[:len(reads)] == reads and bool(memory) and all(
        type(row) is ResolvedStorage and row.span.size == load.output.byte_size
        and row.span.object_id.kind in (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)
        for row in memory)


def _absolute_read(fact, load, space, context):
    """Conservative finite modulo domain, without assuming image contents.

    Refuse a full/large domain or any candidate crossing the address-space
    seam; never truncate candidates or widen the original LOAD's value width.
    """
    from ._scope_contracts import AddressSpaceClassV2, classify_address_space_v2

    bits, width = space.address_size_bits, load.output.byte_size
    claim = fact.claim
    if fact.context or fact.input != 1 or claim.bits != bits or len(claim.items) != 1 \
            or bits not in (32, 64) or load.inputs[1].byte_size * 8 != bits \
            or not 0 < width <= MAX_ACCESS_BYTES or space.classification_revision != 2 \
            or space.addressable_unit_bytes != 1 \
            or classify_address_space_v2(space) is not AddressSpaceClassV2.ADDRESS:
        return None
    base, interval = claim.items[0]
    if base != ("abs",) or interval.signed or interval.bits != bits \
            or not 0 <= interval.lo <= interval.hi < 1 << bits \
            or not interval.single and interval.stride <= 0:
        return None
    count = 1 if interval.single else (interval.hi - interval.lo) // interval.stride + 1
    if not 0 < count <= MAX_READ_ADDRESSES:
        return None
    starts = range(interval.lo, interval.hi + 1, interval.stride or 1)
    object_id = StorageObjectId(StorageObjectKind.ADDRESS_SPACE, context.program_scope, space.space_id)
    step(count * width)
    spans = tuple(ByteSpan(object_id, start, width) for start in starts if start + width <= 1 << bits)
    return spans if len(spans) == count else None


def prepare_memory_refinement(result, options, *, assumptions=()):
    """A plan from N0 only, or None. No fact from its replay is accepted here."""
    from .forward import forward_facts
    from ._scope_contracts import VarnodeKindCode
    from .model import ResolvedStorage
    from .normalize import NormalizedFunction
    from .summary_engine import run_assumptions

    normalized, unit = result.normalized, result.unit
    if type(normalized) is not NormalizedFunction or normalized.forward_inputs is None \
            or normalized.forward_memory_proofs \
            or getattr(normalized.forward_inputs.read_separations, "address_reads", ()):
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
    assumptions = tuple(sorted(set(assumptions) | set(run_assumptions(
        {result.key: result}, readonly_image=options.get("readonly_image"),
        home_space=options.get("private_frame_above", 0)))))
    facts = {fact.operation: fact for fact in forward_facts(
        normalized, unit, readonly_image=options.get("readonly_image"), assumptions=assumptions)}
    effects = {effect.operation_key: effect for block in normalized.forward_inputs.effect_unit.blocks
               for effect in block.effects}
    address_reads = []
    for key, load in original.items():
        fact = facts.get(key)
        if load.opcode != "LOAD" or key in overrides or fact is None or fact.function != result.key \
                or len(load.inputs) != 2 or load.output is None \
                or load.inputs[0].kind is not VarnodeKindCode.CONSTANT \
                or not _load_shape(effects.get(key), load, normalized.forward_inputs.context, projected=True):
            continue
        space = spaces.get(load.inputs[0].coordinate.byte_offset)
        spans = None if space is None else _absolute_read(fact, load, space, normalized.forward_inputs.context)
        if spans is None:
            continue
        old = tuple(row.span for row in effects[key].reads if type(row) is ResolvedStorage
                    and row.span.object_id.kind in (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE))
        if effects[key].memory_read is None and old == spans:
            continue
        address_reads.append(ReadAddressProjection(key, spans, fact))
        if len(address_reads) > MAX_PROOFS:
            return None
    proofs = []
    for row in candidates:
        load, read_fact = original[row.operation_key], facts.get(row.operation_key)
        if read_fact is None or row.operation_key in overrides or load.output is None:
            continue
        space = spaces.get(load.inputs[0].coordinate.byte_offset)
        if load.inputs[0].kind is not VarnodeKindCode.CONSTANT or space is None \
                or not space.is_memory_space or space.address_size_bits not in (32, 64):
            continue
        # one width per site: space bits == address operand bits == both claims' bits
        bits = space.address_size_bits
        size = load.output.byte_size
        left = _offsets(read_fact, size, bits)
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
            if store is None or store.opcode != "STORE" or len(store.inputs) != 3 \
                    or writer in overrides or write_fact is None \
                    or store.inputs[0].kind is not VarnodeKindCode.CONSTANT \
                    or store.inputs[0].coordinate.byte_offset != space.space_id \
                    or write_fact.function != read_fact.function \
                    or write_fact.function != result.key or store.inputs[1].byte_size * 8 != write_fact.claim.bits:
                continue
            effect = effects.get(writer)
            writes = [] if effect is None else [e.span for e in effect.writes if type(e) is ResolvedStorage
                       and e.span.object_id.kind in (StorageObjectKind.ADDRESS_SPACE,
                                                    StorageObjectKind.FUNCTION_RELATIVE)]
            resolved_store = effect is not None and len(writes) == 1 and effect.memory_write is None \
                and not effect.unresolved_writes and writes[0].size == store.inputs[2].byte_size
            # An exact raw unknown STORE may carry a finite may-write footprint.
            # It still has no definite write span and remains unknown everywhere
            # except the reader bytes certified below. Extra effects are refused.
            if not resolved_store and not _raw_unresolved_store(
                    effect, store, normalized.forward_inputs.context):
                continue
            right = _offsets(write_fact, store.inputs[2].byte_size, bits)
            if right is None or left[0] != right[0] or left[1] & right[1]:
                continue
            proofs.append(ReadSeparation(row.operation_key, writer, reads[0], read_fact, write_fact))
            if len(proofs) > MAX_PROOFS:
                return None  # local optional cap: keep the complete original result
    if not proofs and not address_reads:
        return None
    requires = tuple(sorted(set(assumptions) | {label for proof in proofs
                            for fact in (proof.read_fact, proof.write_fact) for label in fact.requires}
                            | {label for proof in address_reads for label in proof.read_fact.requires}))
    return MemoryRefinement(unit, normalized, _signature(options), tuple(proofs), requires, tuple(options.items()),
                            result, assumptions, address_reads=tuple(address_reads))


def exclusions_for(plan, effect_unit):
    """Validate full baseline claims, then waive original resolved bytes only."""
    from .model import ResolvedStorage

    if type(plan) is not MemoryRefinement:
        raise RefinementRefused("a validated baseline plan is required")
    plan.verify()
    if effect_unit.function_scope != plan.unit.scopes.function.scope:
        raise RefinementRefused("activation changed")
    effects = {effect.operation_key: effect for block in effect_unit.blocks for effect in block.effects}
    original = {effect.operation_key: effect for block in plan.baseline.forward_inputs.effect_unit.blocks
                for effect in block.effects} if plan.evidence_kind == "address" else {}
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
        baseline_writer = original.get(proof.writer)
        if baseline_writer is not None and baseline_writer.memory_write is not None \
                and writer != baseline_writer:
            raise RefinementRefused("original unresolved STORE effect changed")
        for offset in range(proof.span.start, proof.span.end):
            step()
            found.setdefault((proof.read, proof.span.object_id, offset), set()).add(proof.writer)
    return {key: frozenset(value) for key, value in found.items()}
