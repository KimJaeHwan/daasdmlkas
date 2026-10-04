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
) -> ObservedEffectUnit:
    """Resolve provably equal indirect addresses, preserving all other debt."""
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
    projector = _Projector(
        context,
        address_spaces,
        first_pass,
        operations,
        OpaqueValueEvidenceResolver(
            NullOpaqueValueEvidenceProvider()
            if opaque_value_provider is None
            else opaque_value_provider
        ),
        translation_namespace,
    )
    changed = False
    blocks: list[ObservedEffectBlock] = []
    for block in unit.blocks:
        effects = []
        for effect in block.effects:
            operation = operations.get(effect.operation_key)
            projected = (
                None
                if operation is None
                else projector.project_access(effect, operation)
            )
            if projected is None:
                effects.append(effect)
                continue
            relative = ResolvedStorage(projected)
            if effect.memory_read is not None:
                effects.append(
                    replace(
                        effect,
                        reads=effect.reads + (relative,),
                        memory_read=None,
                    )
                )
            elif effect.memory_write is not None:
                effects.append(
                    replace(
                        effect,
                        writes=effect.writes + (relative,),
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


class _Projector:
    def __init__(
        self,
        context,
        address_spaces,
        first_pass,
        operations,
        opaque_values,
        translation_namespace,
    ) -> None:
        self._context = context
        self._spaces = {row.space_id: row for row in address_spaces}
        self._ssa = first_pass
        self._operations = operations
        self._opaque_values = opaque_values
        self._translation_namespace = translation_namespace
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
    ) -> ByteSpan | None:
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
        address = self._expression_for_input(operation_key, operation.inputs[1])
        if address is None or address.byte_size * 8 != space.address_size_bits:
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
        if not address.atoms:
            object_id = StorageObjectId(
                StorageObjectKind.ADDRESS_SPACE,
                self._context.program_scope,
                space.space_id,
            )
            start = _unsigned_wrap(address.displacement, address.byte_size)
            if start + width > 1 << space.address_size_bits:
                return None
        else:
            object_id = StorageObjectId(
                StorageObjectKind.FUNCTION_RELATIVE,
                self._ssa.function_scope,
                _digest_ints(
                    b"relative-address-space-v1",
                    (_address_atom_key(address.atoms), space.space_id),
                ),
            )
            start = (1 << space.address_size_bits) + address.displacement
            if start < 0:
                return None
        return ByteSpan(object_id, start, width)

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
            return _AddressExpression(
                (),
                _unsigned_wrap(varnode.coordinate.byte_offset, varnode.byte_size),
                varnode.byte_size,
            )
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
        if definition.kind is MemoryDefinitionKind.ENTRY:
            result = _AddressExpression(
                ((_stable_storage_key(requested_span), 1),),
                0,
                requested_span.size,
            )
        elif definition.kind is MemoryDefinitionKind.DATA_WRITE:
            if definition.span != requested_span:
                result = None
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
        else:
            result = None
        self._active.remove(cache_key)
        self._cache[cache_key] = result
        return result

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
        if operation.opcode == "LOAD" and len(operation.inputs) >= 2:
            return self._expression_from_memory_read(operation_key, byte_size)
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
                return _AddressExpression((), result, byte_size)
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
                return _AddressExpression(
                    base.atoms,
                    _address_wrap(
                        base,
                        base.displacement - _signed_constant(operation.inputs[1]),
                        byte_size,
                    ),
                    byte_size,
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
        )

    def _expression_from_memory_read(
        self,
        operation_key: str,
        byte_size: int,
    ) -> _AddressExpression | None:
        action_id = self._action_ids.get(operation_key)
        if action_id is None:
            return None
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
