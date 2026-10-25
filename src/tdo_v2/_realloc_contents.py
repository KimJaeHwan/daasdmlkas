"""Query-local successful resize byte lineage over the ORIGINAL memory SSA.

An audited copy-prefix contract is independent of ``same_object`` projection.
The latter only locates candidate SSA fragments; a result/guard, a clean
pre-CALL snapshot and byte ownership are independently required here. No
allocator name, fixture address, new SSA definition or whole-CALL preservation
is introduced. Old aliases cannot consume a new-result certificate.
"""
from dataclasses import dataclass, replace

from ._allocation_lifetime import AllocationAnalysis, AllocationRef, identity_operand
from ._allocation_outcomes import _result, successful_resize
from ._forward_memory import MemoryRefinement, ReadSeparation, RefinementRefused, _signature
from ._load_identity import definition_identity
from .memory_contracts import MemoryDefinitionKind
from .model import ByteSpan, ResolvedStorage
from .resource_limits import step
from .span_geometry import StorageObjectKind


@dataclass(frozen=True, slots=True)
class ResizeCopy:
    call: str
    reader: str
    span: ByteSpan
    source: tuple
    offset: int
    result_definitions: tuple
    input_lifetime: object
    writer_lifetime: object
    snapshot_requires: tuple
    old_size: int
    new_size: int
    outcome: object
    contract: str
    requires: tuple


def _address(analysis, key, value, active=frozenset()):
    """Original full-width resize result + exact constant byte displacement."""
    witnesses = []
    direct = _result(analysis, key, value, active, witnesses)
    if direct is not None:
        return direct, 0, tuple(dict.fromkeys(witnesses))
    span = analysis.span(value)
    identifier = None if span is None or span.size != 8 else analysis.read_definition(key, span)
    if identifier is None or identifier in active:
        return None
    definition = analysis.ssa.definitions[identifier]
    operation = analysis.ops.get(definition.operation_key)
    if definition.kind is not MemoryDefinitionKind.DATA_WRITE or definition.span != span or operation is None:
        return None
    active = active | {identifier}
    witness = definition_identity(definition)
    transport = identity_operand(operation)
    if transport is not None:
        found = _address(analysis, definition.operation_key, transport, active)
    elif operation.opcode in ("INT_ADD", "INT_SUB"):
        from ._scope_contracts import VarnodeKindCode
        found = None
        for ordinal, operand in enumerate(operation.inputs):
            if operand.kind is not VarnodeKindCode.CONSTANT or operand.byte_size != 8 \
                    or operation.opcode == "INT_SUB" and ordinal != 1:
                continue
            raw = operand.coordinate.byte_offset
            delta = raw - (1 << 64) if raw >= 1 << 63 else raw
            if operation.opcode == "INT_SUB":
                delta = -delta
            base = _address(analysis, definition.operation_key, operation.inputs[1 - ordinal], active)
            if base is not None:
                found = base[0], base[1] + delta, base[2]
                break
    elif operation.opcode == "STORE" and operation.inputs[2].byte_size == 8:
        found = _address(analysis, definition.operation_key, operation.inputs[2], active)
    elif operation.opcode == "LOAD" and operation.output.byte_size == 8:
        reads = [row for row in analysis.reads.get(analysis.actions.get(definition.operation_key), ())
                 if row.span.object_id.kind in (StorageObjectKind.FUNCTION_RELATIVE, StorageObjectKind.ADDRESS_SPACE)]
        found = None
        if len(reads) == 1 and reads[0].span.size == 8:
            source = analysis.read_definition(definition.operation_key, reads[0].span)
            if source is not None and source not in active:
                row = analysis.ssa.definitions[source]
                store = analysis.ops.get(row.operation_key)
                if row.kind is MemoryDefinitionKind.DATA_WRITE and row.span == reads[0].span \
                        and store is not None and store.opcode == "STORE" and store.inputs[2].byte_size == 8:
                    found = _address(analysis, row.operation_key, store.inputs[2], active | {source})
                    if found is not None:
                        found = found[0], found[1], (*found[2], definition_identity(row))
    else:
        found = None
    return None if found is None else (found[0], found[1], tuple(dict.fromkeys((*found[2], witness))))


def _memory_span(effect, direction):
    if effect is None or getattr(effect, "memory_" + direction) is not None \
            or getattr(effect, "unresolved_" + direction + "s"):
        return None
    values = [row.span for row in getattr(effect, direction + "s") if type(row) is ResolvedStorage
              and row.span.object_id.kind in (StorageObjectKind.FUNCTION_RELATIVE, StorageObjectKind.ADDRESS_SPACE)]
    return values[0] if len(values) == 1 else None


def _raw_access(analysis, key, operation, effect, direction):
    """One original admitted 64-bit memory access, not an effect override."""
    from ._scope_contracts import VarnodeKindCode
    selector = operation.inputs[0]
    space = next((space for space in analysis.item.unit.scopes.program.evidence.address_spaces
                  if space.space_id == selector.coordinate.byte_offset), None)
    width = operation.output.byte_size if direction == "read" else operation.inputs[2].byte_size
    span = _memory_span(effect, direction)
    if key in dict(analysis.normalized.operation_overrides) or selector.kind is not VarnodeKindCode.CONSTANT \
            or space is None or not space.is_memory_space or space.address_size_bits != 64 \
            or operation.inputs[1].byte_size != 8 or span is None or span.size != width or not 0 < width <= 16:
        return None
    return span


def _stack_exclusions(analysis, call, reader, read_span, old, requires):
    """Both in-place OLD ownership and moved NEW ownership vs active stack.

    A future STORE's whole span must already be active at BOTH old birth and
    resize. This intentionally refuses retired stack, red-zone and arbitrary
    SP-relative offsets instead of generalizing freshness to all addresses.
    """
    from ._allocation_memory import stack_range
    rows = [row for row in analysis.normalized.may_alias_reads if row.operation_key == reader]
    if any(row.unknown_address or row.uncertain or row.plain is None for row in rows):
        return None
    effects = {row.operation_key: row for row in analysis.normalized.effects}
    original = analysis.ops[reader]
    ref = AllocationRef(analysis.item.key, analysis.context, call,
                        analysis.contracts[call].result, "single", analysis.contracts[call].canonical_digest)
    proofs = []
    for writer in sorted({writer for row in rows for writer in row.plain}):
        step()
        store = analysis.ops.get(writer)
        span = None if store is None or store.opcode != "STORE" else _raw_access(
            analysis, writer, store, effects.get(writer), "write")
        if store is None or store.opcode != "STORE" or span is None \
                or span.size != store.inputs[2].byte_size or writer in dict(analysis.normalized.operation_overrides) \
                or store.inputs[0].kind != original.inputs[0].kind \
                or store.inputs[0].coordinate.byte_offset != original.inputs[0].coordinate.byte_offset:
            return None
        before = stack_range(analysis, old, span)
        current = stack_range(analysis, ref, span)
        if before is None or current is None:
            return None
        requires.update(before.requires)
        requires.update(current.requires)
        proofs.append(ReadSeparation(reader, writer, read_span, (before, current), (call, "resize-result-owned-prefix")))
    return tuple(proofs)


def prepare_realloc_contents(item, *, results=None):
    """Build a sealed batch from an independent, already accepted source N0."""
    from ._call_activation import _policy, _source_signature
    from .forward import probe
    if not item.allocation_contracts or item.normalized.forward_inputs is None:
        return None
    # Replaying an unrelated load-identity solve would silently lose its
    # precision. This stage runs BEFORE that optional layer in refined_one.
    if item.normalized.load_value_proofs:
        return None
    with _policy(item):
        options = dict(item.normalization_options)
        analysis = AllocationAnalysis(item, readonly_image=options.get("readonly_image"), results=results)
        prior = item.normalized.forward_inputs.read_separations
        if prior is not None:
            prior.verify()
        effects = {row.operation_key: row for row in item.normalized.effects}
        proofs = list(item.normalized.forward_memory_proofs)
        copies, requires = [], set(analysis.requires) | set(item.normalized.forward_memory_requires)
        overrides = dict(item.normalized.operation_overrides)
        for key, load in analysis.ops.items():
            step()
            if load.opcode != "LOAD" or key in overrides or key not in analysis.once or load.output is None:
                continue
            read_span = _raw_access(analysis, key, load, effects.get(key), "read")
            if read_span is None:
                continue
            address = _address(analysis, key, load.inputs[1])
            if address is None:
                continue
            call, offset, definitions = address
            contract = analysis.contracts[call]
            if getattr(contract, "contents", "unknown") != "preserve-prefix" or not contract.owned_footprint \
                    or call not in analysis.once or offset < 0:
                continue
            outcome = successful_resize(analysis, call, key)
            if not outcome:
                continue
            if any(identity[1] in overrides for identity in (*definitions, *outcome.definitions)):
                continue
            pointer = analysis.argument(call, contract.pointer)
            life = analysis.lifetime(pointer, call)
            if not life.live or pointer.unknown or len(pointer.targets) != 1:
                continue
            (target,) = pointer.targets
            old = target.allocation
            if target.offset != 0 or old.function != item.key or old.context != analysis.context \
                    or old.occurrence != "single" or not analysis.contracts[old.event].owned_footprint:
                continue
            old_size, used = analysis.extent(old)
            new_size = outcome.size
            if old_size is None:
                continue
            # No intervening unknown CALL is retrospectively made preserving.
            debts = [row for row in item.normalized.call_clobber_reads if row.operation_key == key]
            if any(set(row.intervening_calls) - {call} for row in debts):
                continue
            local_requires = set(requires) | set(life.requires) | set(used) | set(outcome.requires) | {contract.label}
            exclusions = _stack_exclusions(analysis, call, key, read_span, old, local_requires)
            if exclusions is None:
                continue
            added = []
            for read in analysis.reads.get(analysis.actions.get(key), ()):
                if read.span != read_span:
                    continue
                for fragment in read.fragments:
                    step()
                    if len(fragment.definition_ids) != 1:
                        continue
                    identifier = fragment.definition_ids[0]
                    source = analysis.ssa.definitions[identifier]
                    writer = analysis.ops.get(source.operation_key)
                    start = offset + fragment.span.start - read_span.start
                    if source.kind is not MemoryDefinitionKind.DATA_WRITE or writer is None or writer.opcode != "STORE" \
                            or source.span.object_id != fragment.span.object_id \
                            or not source.span.start <= fragment.span.start < fragment.span.end <= source.span.end \
                            or start < 0 or start + fragment.span.size > min(old_size, new_size):
                        continue
                    if _raw_access(analysis, source.operation_key, writer,
                                   effects.get(source.operation_key), "write") != source.span:
                        continue
                    access = analysis.access(source.operation_key)
                    if access is None or len(access.pointer.targets) != 1:
                        continue
                    (stored,) = access.pointer.targets
                    if stored.allocation != old or stored.offset + fragment.span.start - source.span.start != start:
                        continue
                    snapshot, labels = probe(item.normalized, analysis.first(call), (fragment.span,))
                    if snapshot[fragment.span] != identifier:
                        continue
                    claims = tuple(sorted(local_requires | set(access.requires) | set(labels)))
                    added.append(ResizeCopy(call, key, fragment.span, definition_identity(source), start,
                        definitions, life, access, tuple(labels), old_size, new_size, outcome, contract.label, claims))
            if added:
                copies.extend(added)
                requires.update(label for proof in added for label in proof.requires)
                for separation in exclusions:
                    # The successful result owns only approved prefix bytes,
                    # not the entire raw LOAD (which may cross its extent).
                    for copied in added:
                        proof = replace(separation, span=copied.span)
                        if not any((old.read, old.writer, old.span) == (proof.read, proof.writer, proof.span) for old in proofs):
                            proofs.append(proof)
            if len(copies) > 64 or len(proofs) > 128:
                return None
        if not copies:
            return None
        peers = tuple(sorted((results or {}).items()))
        return MemoryRefinement(item.unit, item.normalized, _signature(options), tuple(proofs), tuple(sorted(requires)),
            tuple(options.items()), item, (), "realloc-copy", peers, item.allocation_contracts,
            tuple((key, _source_signature(peer)) for key, peer in peers), copy_proofs=tuple(dict.fromkeys(copies)))


def transfers_for(plan, ssa):
    """Bind exact original fragments; graph ownership remains in memory_graph."""
    from .memory_graph import MemoryTransfer
    if plan is None or not plan.copy_proofs:
        return ()
    plan.verify()
    identifiers = {definition_identity(row): index for index, row in enumerate(ssa.definitions)}
    actions = {row.operation_key: index for index, row in enumerate(ssa.actions)}
    result = []
    for proof in plan.copy_proofs:
        identifier = identifiers.get(proof.source)
        action = actions.get(proof.reader)
        matches = [(read.action_id, fragment.span) for read in ssa.reads if read.action_id == action
                   for fragment in read.fragments if fragment.span == proof.span and fragment.definition_ids == (identifier,)]
        if identifier is None or action is None or not matches:
            raise RefinementRefused("resize snapshot/read fragment changed during replay")
        result.append(MemoryTransfer(identifier, action, proof.span, proof.call, proof.outcome.guard,
                                     proof.contract, proof.requires))
    return tuple(result)


def subtract_copy_clobbers(plan, rows):
    """One byte consumer used by BOTH normalization and the forward probe."""
    from dataclasses import replace
    if plan is None or not plan.copy_proofs:
        return rows
    plan.verify()
    out = []
    for row in rows:
        for span in row.spans:
            matches = [proof for proof in plan.copy_proofs if proof.reader == row.operation_key
                       and proof.span.overlaps(span)]
            if not matches:
                out.append(replace(row, spans=(span,)))
                continue
            boundaries = sorted({span.start, span.end} | {bound for proof in matches
                for bound in (max(span.start, proof.span.start), min(span.end, proof.span.end))})
            runs = []
            for start, stop in zip(boundaries, boundaries[1:]):
                step()
                removed = {proof.call for proof in matches if proof.span.start <= start < proof.span.end}
                calls = tuple(call for call in row.intervening_calls if call not in removed)
                if not calls:
                    continue
                if runs and runs[-1][1] == start and runs[-1][2] == calls:
                    runs[-1] = runs[-1][0], stop, calls
                else:
                    runs.append((start, stop, calls))
            out.extend(replace(row, spans=(ByteSpan(span.object_id, start, stop - start),), intervening_calls=calls)
                       for start, stop, calls in runs)
    return tuple(out)
