"""Physical register and memory projection for configured analysis."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .._scope_contracts import VarnodeKindCode
from ..model import ByteSpan, StorageObjectId, StorageObjectKind
from ..observed_call_state import observed_call_state_projections
from ..resource_limits import step
from ..physical_state import (
    PhysicalMemorySlice,
    PhysicalRegisterSlice,
    PhysicalStateResolver,
    PhysicalValueFragment,
    PhysicalStoreReceipt,
)
from .configured_function_view import _FunctionView

MAX_PHYSICAL_VALUE_FRAGMENTS = 128


def _memory_relation(view, definition, span, width, space, displacement=0):
    """One non-wrapping interval in the observed address space's modulus.

    Affine peeling accumulates mathematical offsets, not machine addresses:
    ``base + 2**bits + 8`` aliases ``base + 8``. Compare every request and
    STORE in the same coordinates. A seam-crossing or mixed-width interval
    needs a split proof, which this single-STORE receipt does not provide.
    """
    bits = view.space_bits.get(space)
    if bits is None or span.size * 8 != bits:
        return None
    modulus = 1 << bits
    if width > modulus:
        return None
    relation = view.canonical_physical_affine_relation(definition, span, displacement)
    if relation is None:
        return None
    root, root_span, offset = relation
    offset %= modulus
    if offset + width > modulus:
        return None
    return root, root_span, offset


def _register_span(view, selector):
    register_spaces = tuple(
        row
        for row in view.analysis.evidence.unit.scopes.program.evidence.address_spaces
        if row.is_register_space
    )
    if len(register_spaces) != 1:
        return None
    return ByteSpan(
        StorageObjectId(
            StorageObjectKind.REGISTER_FILE,
            view.analysis.evidence.unit.scopes.program.scope,
            0,
        ),
        selector.byte_offset,
        selector.byte_size,
    )

@dataclass(frozen=True, slots=True)
class _FunctionPhysicalStateBackend:
    view: _FunctionView

    def register_span(self, selector: PhysicalRegisterSlice) -> ByteSpan | None:
        return _register_span(self.view, selector)

    def memory_candidates(
        self,
        selector: PhysicalMemorySlice,
        before_position: int,
    ) -> tuple[ByteSpan, ...]:
        base_span = _register_span(self.view, selector.base)
        if base_span is None:
            return ()
        definition_id = self.view.state_definition(base_span, before_position)
        if definition_id is None:
            return ()
        paths = self.view.complete_physical_pointer_candidates(
            definition_id,
            base_span,
        )
        candidates = set()
        for path in paths:
            spans = tuple(self.view._direct_span(path.with_offset(selector.displacement),
                                                selector.byte_size, space)
                          for space in self.view.loaded_memory_space_ids)
            # Never turn a mixed complete/unsupported pointer alternative
            # into an apparently unique physical address by dropping a path.
            if not spans or any(span is None for span in spans):
                return ()
            candidates.update(spans)
        return tuple(sorted(candidates, key=lambda item: item.canonical_key))

    def value_fragments(self, selector, before_position) -> tuple[PhysicalValueFragment, ...]:
        """Return current SSA bytes without widening a subrange to its value."""
        if type(selector) is PhysicalRegisterSlice:
            span = self.register_span(selector)
            definition = None if span is None else self.view.state_definition(span, before_position)
            if definition is not None and self.view.memory.definitions[definition].span.contains(span):
                return (PhysicalValueFragment(definition, span),)
            return () if span is None else _materialized_value_fragments(self.view, span, before_position)
        if type(selector) is not PhysicalMemorySlice:
            raise TypeError("physical value selector must be exact")
        candidates = self.memory_candidates(selector, before_position)
        if len(candidates) == 1:
            definition = self.view.state_definition(candidates[0], before_position)
            if definition is not None and self.view.memory.definitions[definition].span.contains(candidates[0]):
                return (PhysicalValueFragment(definition, candidates[0]),)
            fragments = _materialized_value_fragments(self.view, candidates[0], before_position)
            if fragments:
                return fragments
        return _relational_memory_value_fragments(self.view, selector, before_position)

    def value_ids(
        self,
        selector: PhysicalRegisterSlice | PhysicalMemorySlice,
        before_position: int,
    ) -> tuple[int, ...]:
        if type(selector) is PhysicalRegisterSlice:
            span = self.register_span(selector)
            definition_id = (
                None
                if span is None
                else self.view.state_definition(span, before_position)
            )
            return () if definition_id is None else (definition_id,)
        if type(selector) is not PhysicalMemorySlice:
            raise TypeError("physical value selector must be exact")

        candidates = self.memory_candidates(selector, before_position)
        materialized_ids = ()
        if len(candidates) == 1:
            definition_id = self.view.state_definition(
                candidates[0],
                before_position,
            )
            if definition_id is not None:
                materialized_ids = (definition_id,)

        relational_ids = _relational_memory_value_definition_ids(
            self.view,
            selector,
            before_position,
        )
        if materialized_ids:
            return materialized_ids
        return relational_ids if len(relational_ids) == 1 else ()

def _relational_memory_value_definition_ids(view, selector, before_position):
    """Compatibility IDs: never silently expose a wider value as a slice."""
    return tuple(fragment.definition_id for fragment in
                 _relational_memory_value_fragments(view, selector, before_position, subranges=False))


def _materialized_value_fragments(view, requested, before_position):
    """An exact current cover in original SSA atoms, never widened definitions.

    Keep the state barrier on every piece. In particular a definition covering
    the whole request is not reused across a later partial overwrite.
    """
    pieces = sorted((atom.intersection(requested) for atom in view.memory.atomic_spans
                     if atom.overlaps(requested)), key=lambda span: span.start)
    if not pieces or len(pieces) > MAX_PHYSICAL_VALUE_FRAGMENTS:
        return ()
    cursor, fragments = requested.start, []
    for piece in pieces:
        step()
        if piece.start != cursor:
            return ()
        definition = view.state_definition(piece, before_position)
        if definition is None or not view.memory.definitions[definition].span.contains(piece):
            return ()
        if (fragments and fragments[-1].definition_id == definition
                and fragments[-1].source_span.end == piece.start):
            old = fragments[-1].source_span
            fragments[-1] = PhysicalValueFragment(definition, ByteSpan(old.object_id, old.start, old.size + piece.size))
        else:
            fragments.append(PhysicalValueFragment(definition, piece))
        cursor = piece.end
    return tuple(fragments) if cursor == requested.end else ()


def _relational_memory_value_fragments(view, selector, before_position, *, subranges=True):
    """Compose current STORE receipts at observed byte boundaries only.

    Each piece must independently pass the original dominance, source and
    interference checks. No partial cover is published as a complete demand.
    The definition-only compatibility API retains its single-value contract.
    """
    single = _single_store_value_fragments(view, selector, before_position, subranges=subranges)
    if single or not subranges:
        return single
    base = _register_span(view, selector.base)
    definition = None if base is None else view.state_definition(base, before_position)
    spaces = tuple(getattr(view, "loaded_memory_space_ids", ()))
    if definition is None or len(spaces) != 1:
        return ()
    relation = _memory_relation(view, definition, base, selector.byte_size, spaces[0], selector.displacement)
    if relation is None:
        return ()
    start, end = relation[2], relation[2] + selector.byte_size
    boundaries = {start, end}
    for key, (position, operation) in view.operations.items():
        step()
        if position >= before_position or operation.opcode != "STORE" or len(operation.inputs) != 3:
            continue
        space = operation.inputs[0]
        if space.kind is not VarnodeKindCode.CONSTANT or space.coordinate.byte_offset != spaces[0]:
            continue
        pointer = view._observed_input_definition(key, operation.inputs[1])
        store = None if pointer is None else _memory_relation(
            view, *pointer, operation.inputs[2].byte_size, spaces[0])
        if store is None or store[:2] != relation[:2]:
            continue
        lo, hi = max(start, store[2]), min(end, store[2] + operation.inputs[2].byte_size)
        if lo < hi:
            boundaries.update((lo, hi))
        if len(boundaries) > MAX_PHYSICAL_VALUE_FRAGMENTS + 1:
            return ()
    ordered = sorted(boundaries)
    if len(ordered) <= 2:
        return ()  # the original single-STORE proof already refused this range
    fragments = []
    for lo, hi in zip(ordered, ordered[1:]):
        step()
        piece = replace(selector, displacement=selector.displacement + lo - start, byte_size=hi - lo)
        found = _single_store_value_fragments(view, piece, before_position)
        if not found:
            return ()
        fragment, = found
        # The current public fragment has no general target-lane field. Keep
        # repeated source-byte demands refused rather than losing multiplicity.
        if any(old.definition_id == fragment.definition_id and old.source_span.overlaps(fragment.source_span)
               for old in fragments):
            return ()
        fragments.append(fragment)
    return tuple(fragments)


def _single_store_value_fragments(view, selector, before_position, *, subranges=True):
    """Resolve a current STORE's exact source bytes by an affine receipt.

    The one-writer, dominance and intervening-call/write checks remain in
    force. This is deliberately not a branch-union or loop-unrolling rule.
    """
    loaded_spaces = tuple(getattr(view, "loaded_memory_space_ids", ()))
    if len(loaded_spaces) != 1:
        return ()
    loaded_space = loaded_spaces[0]
    base_span = _register_span(view, selector.base)
    if base_span is None:
        return ()
    base_definition = view.state_definition(base_span, before_position)
    if base_definition is None:
        return ()
    target_relation = _memory_relation(
        view,
        base_definition,
        base_span,
        selector.byte_size,
        loaded_space,
        selector.displacement,
    )
    before_keys = tuple(
        operation_key
        for operation_key, (position, _) in view.operations.items()
        if position == before_position
    )
    if target_relation is None or len(before_keys) != 1:
        return ()
    before_key = before_keys[0]
    observation = getattr(view, "observation", None)
    transient_keys = (
        frozenset()
        if observation is None
        else frozenset(
            operation_key
            for projection in observed_call_state_projections(observation)
            for operation_key in projection.transient_operation_keys
        )
    )

    matches = []
    for operation_key, (position, operation) in view.operations.items():
        if (
            position >= before_position
            or operation.opcode != "STORE"
            or len(operation.inputs) != 3
            or operation.inputs[2].byte_size < selector.byte_size
            or (not subranges and operation.inputs[2].byte_size != selector.byte_size)
            or not view.definitely_precedes(operation_key, before_key)
        ):
            continue
        address_space = operation.inputs[0]
        if (
            address_space.kind is not VarnodeKindCode.CONSTANT
            or address_space.coordinate.byte_offset != loaded_space
        ):
            continue
        store_pointer = view._observed_input_definition(
            operation_key,
            operation.inputs[1],
        )
        store_relation = (
            None
            if store_pointer is None
            else _memory_relation(view, *store_pointer, operation.inputs[2].byte_size, loaded_space)
        )
        if store_relation is None or store_relation[:2] != target_relation[:2]:
            continue
        displacement = target_relation[2] - store_relation[2]
        store_width = operation.inputs[2].byte_size
        if displacement < 0 or displacement + selector.byte_size > store_width:
            continue
        language = view.analysis.evidence.unit.scopes.program.evidence.translation_namespace.language_id.split(":")
        if store_width != selector.byte_size and (len(language) < 2 or language[1] != "LE"):
            continue  # byte-lane source projection is qualified for LE only
        source = view.definition_for_input(operation_key, operation.inputs[2])
        if source is None:
            continue
        source_span = ByteSpan(source[1].object_id, source[1].start + displacement, selector.byte_size)
        if not view.memory.definitions[source[0]].span.contains(source_span):
            continue
        matches.append(
            (
                position,
                operation_key,
                source[0],
                address_space.coordinate.byte_offset,
                source_span,
                store_relation[2],
                store_width,
            )
        )

    if len({row[3] for row in matches}) != 1:
        return ()

    latest = tuple(
        row
        for row in matches
        if not any(
            row[1] != other[1]
            and view.definitely_precedes(row[1], other[1])
            for other in matches
        )
    )
    if len(latest) != 1:
        return ()
    candidate = latest[0]
    target_root, target_span, target_offset = target_relation
    # the same barrier as the materialized lookup (Stage 0.1 R1a A3): no call,
    # CALLOTHER included, and no memory write this scan cannot relate
    between = view.keys_between(candidate[1], before_key)
    if between is None:
        return ()
    for operation_key in between:
        operation = view.operations[operation_key][1]
        if operation_key in transient_keys:
            continue
        if operation.opcode != "STORE" or len(operation.inputs) != 3:
            continue
        address_space = operation.inputs[0]
        if (
            address_space.kind is not VarnodeKindCode.CONSTANT
            or address_space.coordinate.byte_offset != loaded_space
        ):
            continue
        store_pointer = view._observed_input_definition(
            operation_key,
            operation.inputs[1],
        )
        store_relation = (
            None
            if store_pointer is None
            else _memory_relation(view, *store_pointer, operation.inputs[2].byte_size, loaded_space)
        )
        if store_relation is None:
            return ()
        store_root, store_span, store_offset = store_relation
        if store_root != target_root or store_span != target_span:
            return ()
        store_size = operation.inputs[2].byte_size
        if (
            store_offset < target_offset + selector.byte_size
            and target_offset < store_offset + store_size
        ):
            return ()
    receipt = PhysicalStoreReceipt(candidate[1], before_key, before_position, loaded_space,
                                   target_root, target_span, target_offset, selector.byte_size,
                                   candidate[5], candidate[6], candidate[4], tuple(between))
    return (PhysicalValueFragment(candidate[2], candidate[4], receipt),)

def _boundary_state_spans(provider, boundary, match, view, position):
    selectors = provider.state(boundary, match)
    return PhysicalStateResolver(_FunctionPhysicalStateBackend(view)).resolve_all(
        selectors,
        position,
    )

def _physical_state_span(view, selector, before_position):
    return PhysicalStateResolver(_FunctionPhysicalStateBackend(view)).resolve(
        selector,
        before_position,
    )

def _physical_state_spans(view, selector, before_position):
    span = _physical_state_span(view, selector, before_position)
    return () if span is None else (span,)

__all__ = [
    "_FunctionPhysicalStateBackend",
    "_register_span",
    "_relational_memory_value_definition_ids",
]
