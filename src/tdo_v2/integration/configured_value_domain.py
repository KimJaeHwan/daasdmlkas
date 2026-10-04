"""Finite value and pointer-path primitives for configured analysis."""

from __future__ import annotations

from .._scope_contracts import AddressCoordinate, ValidatedVarnode, VarnodeKindCode
from ..model import StorageRef, VarnodeKind
from .configured_interprocedural_records import PointerPath


FINITE_VALUE_LIMIT = 64


def compose_pointer_path(
    base: PointerPath,
    suffix_offsets: tuple[int, ...],
    address_space_id: int | None,
) -> PointerPath:
    if not suffix_offsets:
        return base
    return PointerPath(
        base.anchor_definition_id,
        base.anchor_byte_offset,
        base.offsets[:-1]
        + (base.offsets[-1] + suffix_offsets[0],)
        + tuple(suffix_offsets[1:]),
        base.byte_size,
        address_space_id if address_space_id is not None else base.address_space_id,
    )


def pointer_path_head(path: PointerPath) -> PointerPath:
    return PointerPath(
        path.anchor_definition_id,
        path.anchor_byte_offset,
        (path.offsets[0],),
        path.byte_size,
        path.address_space_id,
    )


def storage_ref(value: ValidatedVarnode) -> StorageRef:
    kinds = {
        VarnodeKindCode.CONSTANT: VarnodeKind.CONSTANT,
        VarnodeKindCode.REGISTER: VarnodeKind.REGISTER,
        VarnodeKindCode.UNIQUE: VarnodeKind.UNIQUE,
        VarnodeKindCode.ADDRESS: VarnodeKind.ADDRESS,
        VarnodeKindCode.STORAGE: VarnodeKind.STORAGE,
        VarnodeKindCode.OPAQUE: VarnodeKind.UNKNOWN,
    }
    return StorageRef(
        kinds[value.kind],
        "",
        value.coordinate.byte_offset,
        value.byte_size,
        space_id=value.coordinate.space_id,
    )


def signed_constant(value: ValidatedVarnode) -> int:
    modulus = 1 << (value.byte_size * 8)
    unsigned = value.coordinate.byte_offset % modulus
    sign = modulus >> 1
    return unsigned - modulus if unsigned >= sign else unsigned


def merge_finite_value_sets(values) -> frozenset[int] | None:
    if not values or any(value is None for value in values):
        return None
    merged = frozenset(item for value in values for item in value)
    return merged if 0 < len(merged) <= FINITE_VALUE_LIMIT else None


def merge_finite_coordinate_sets(
    values,
) -> frozenset[AddressCoordinate] | None:
    if not values or any(value is None for value in values):
        return None
    merged = frozenset(item for value in values for item in value)
    return merged if 0 < len(merged) <= FINITE_VALUE_LIMIT else None


def combine_finite_integer_values(opcode, left, right, byte_size):
    if left is None or right is None or len(left) * len(right) > FINITE_VALUE_LIMIT:
        return None
    modulus = 1 << (byte_size * 8)
    bit_width = byte_size * 8
    operations = {
        "INT_ADD": lambda lhs, rhs: lhs + rhs,
        "INT_SUB": lambda lhs, rhs: lhs - rhs,
        "INT_MULT": lambda lhs, rhs: lhs * rhs,
        "INT_LEFT": lambda lhs, rhs: 0 if rhs >= bit_width else lhs << rhs,
        "INT_AND": lambda lhs, rhs: lhs & rhs,
        "INT_OR": lambda lhs, rhs: lhs | rhs,
        "INT_XOR": lambda lhs, rhs: lhs ^ rhs,
    }
    operation = operations[opcode]
    result = frozenset(operation(lhs, rhs) % modulus for lhs in left for rhs in right)
    return result if len(result) <= FINITE_VALUE_LIMIT else None


def signed_width_value(value: int, byte_size: int) -> int:
    modulus = 1 << (byte_size * 8)
    unsigned = value % modulus
    sign = modulus >> 1
    return unsigned - modulus if unsigned >= sign else unsigned


def sign_extend(value: int, source_bits: int, target_bits: int) -> int:
    source_modulus = 1 << source_bits
    source_unsigned = value % source_modulus
    source_sign = source_modulus >> 1
    signed = (
        source_unsigned - source_modulus
        if source_unsigned >= source_sign
        else source_unsigned
    )
    return signed % (1 << target_bits)


def pointer_path_sort_key(path: PointerPath) -> tuple[object, ...]:
    return (
        path.anchor_definition_id,
        path.anchor_byte_offset,
        path.offsets,
        path.byte_size,
        -1 if path.address_space_id is None else path.address_space_id,
    )


__all__ = [
    "FINITE_VALUE_LIMIT",
    "combine_finite_integer_values",
    "compose_pointer_path",
    "merge_finite_coordinate_sets",
    "merge_finite_value_sets",
    "pointer_path_head",
    "pointer_path_sort_key",
    "sign_extend",
    "signed_constant",
    "signed_width_value",
    "storage_ref",
]
