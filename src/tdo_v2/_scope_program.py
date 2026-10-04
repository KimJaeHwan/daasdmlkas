"""Structured program-coordinate validation over committed numeric spaces."""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass

from ._scope_contracts import (
    AddressCoordinate,
    AddressSpaceEvidence,
    CommittedMemoryRun,
    TranslationNamespace,
    U64_LIMIT,
    VarnodeKindCode,
)
from ._scope_raw import RawObject, _FieldState, _field


@dataclass(frozen=True, slots=True)
class _ProgramValidation:
    duplicate_program: bool
    missing_translation: bool
    invalid_translation: bool
    duplicate_coordinate: bool
    incomplete_spaces: bool
    invalid_spaces: bool
    conflicting_spaces: bool
    missing_image_base: bool
    invalid_image_base: bool
    classification_revision: int | None
    namespace: TranslationNamespace | None
    spaces: tuple[AddressSpaceEvidence, ...]
    image_base: AddressCoordinate | None


@dataclass(frozen=True, slots=True)
class _AddressSpaceParse:
    row: AddressSpaceEvidence | None = None
    duplicate: bool = False
    incomplete: bool = False
    invalid: bool = False


@dataclass(frozen=True, slots=True)
class _TranslationParse:
    namespace: TranslationNamespace | None = None
    duplicate: bool = False
    missing: bool = False
    invalid: bool = False


@dataclass(frozen=True, slots=True)
class _CoordinateParse:
    coordinate: AddressCoordinate | None = None
    duplicate: bool = False
    missing: bool = False
    invalid: bool = False


class _AddressSpaceIndex:
    __slots__ = ("_run_starts", "_runs", "_spaces")

    def __init__(
        self,
        spaces: tuple[AddressSpaceEvidence, ...],
        runs: tuple[CommittedMemoryRun, ...],
    ) -> None:
        self._spaces = {row.space_id: row for row in spaces}
        grouped: dict[int, list[CommittedMemoryRun]] = {}
        for run in runs:
            grouped.setdefault(run.space_id, []).append(run)
        self._runs = {
            space_id: tuple(sorted(rows, key=lambda row: row.byte_start))
            for space_id, rows in grouped.items()
        }
        self._run_starts = {
            space_id: tuple(row.byte_start for row in rows)
            for space_id, rows in self._runs.items()
        }

    def memory_coordinate(
        self,
        coordinate: AddressCoordinate,
        size: int = 1,
        *,
        require_run_start: bool = False,
    ) -> bool:
        row = self._spaces.get(coordinate.space_id)
        if row is None or not _space_matches(row, VarnodeKindCode.ADDRESS):
            return False
        if type(size) is not int or size <= 0:
            return False
        end = coordinate.byte_offset + size
        if end > U64_LIMIT or end > _space_capacity(row):
            return False
        return self._committed_extent(
            coordinate,
            end,
            require_run_start=require_run_start,
        )

    def contains(self, space_id: int) -> bool:
        return space_id in self._spaces

    def kind_matches(self, space_id: int, kind: VarnodeKindCode) -> bool:
        row = self._spaces.get(space_id)
        return row is not None and _space_matches(row, kind)

    def varnode(self, kind: VarnodeKindCode, coordinate: AddressCoordinate, size: int) -> bool:
        row = self._spaces.get(coordinate.space_id)
        if row is None or not _space_matches(row, kind):
            return False
        return self.varnode_extent(kind, coordinate, size)

    def varnode_extent(self, kind: VarnodeKindCode, coordinate: AddressCoordinate, size: int) -> bool:
        row = self._spaces.get(coordinate.space_id)
        if row is None:
            return False
        if type(size) is not int or size <= 0:
            return False
        if kind is VarnodeKindCode.CONSTANT:
            return coordinate.byte_offset < (1 << min(64, 8 * size))
        capacity = _space_capacity(row)
        if coordinate.byte_offset >= capacity or size > capacity:
            return False
        if kind is VarnodeKindCode.OPAQUE and row.has_signed_offset is True:
            half = capacity // 2
            signed_start = (
                coordinate.byte_offset
                if coordinate.byte_offset < half
                else coordinate.byte_offset - capacity
            )
            return signed_start + size <= half
        end = coordinate.byte_offset + size
        if end > U64_LIMIT or end > capacity:
            return False
        if kind is VarnodeKindCode.ADDRESS:
            return self._committed_extent(
                coordinate,
                coordinate.byte_offset + 1,
            )
        if kind is VarnodeKindCode.STORAGE:
            return self._committed_extent(coordinate, end)
        return True

    def _committed_extent(
        self,
        coordinate: AddressCoordinate,
        end: int,
        *,
        require_run_start: bool = False,
    ) -> bool:
        runs = self._runs.get(coordinate.space_id, ())
        starts = self._run_starts.get(coordinate.space_id, ())
        position = bisect_right(starts, coordinate.byte_offset) - 1
        if position < 0:
            return False
        run = runs[position]
        if require_run_start:
            return coordinate.byte_offset == run.byte_start
        return run.byte_start <= coordinate.byte_offset and end <= run.byte_end


def _validate_program_candidate(
    raw: object,
    spaces_complete: object,
    runs: tuple[CommittedMemoryRun, ...],
) -> _ProgramValidation:
    duplicate_program = False
    duplicate_coordinate = False
    missing_translation = False
    invalid_translation = False
    incomplete_spaces = type(spaces_complete) is not bool or spaces_complete is not True
    invalid_spaces = False
    conflicting_spaces = False
    missing_image = False
    invalid_image = False
    namespace = None
    classification_revision: int | None = 1
    spaces: tuple[AddressSpaceEvidence, ...] = ()
    image = None

    if type(raw) is not RawObject:
        invalid_translation = True
        invalid_spaces = True
        invalid_image = True
    else:
        revision_field = _field(raw, "address_space_classification_revision")
        if revision_field.state is _FieldState.DUPLICATE:
            duplicate_program = True
            classification_revision = None
        elif revision_field.state is _FieldState.MISSING:
            classification_revision = 1
        elif type(revision_field.value) is int and revision_field.value == 2:
            classification_revision = 2
        else:
            invalid_spaces = True
            classification_revision = None

        translation_field = _field(raw, "translation_namespace")
        if translation_field.state is _FieldState.DUPLICATE:
            duplicate_program = True
        elif translation_field.state is _FieldState.MISSING:
            missing_translation = True
        else:
            result = _parse_translation(translation_field.value)
            namespace = result.namespace
            duplicate_program |= result.duplicate
            missing_translation |= result.missing
            invalid_translation |= result.invalid

        spaces_field = _field(raw, "address_spaces")
        if spaces_field.state is _FieldState.DUPLICATE:
            duplicate_coordinate = True
        elif spaces_field.state is _FieldState.MISSING:
            incomplete_spaces = True
        elif type(spaces_field.value) is not tuple:
            invalid_spaces = True
        else:
            parsed: list[AddressSpaceEvidence] = []
            for item in spaces_field.value:
                result = _parse_address_space(item, classification_revision)
                duplicate_coordinate |= result.duplicate
                incomplete_spaces |= result.incomplete
                invalid_spaces |= result.invalid
                if result.row is not None:
                    parsed.append(result.row)
            spaces = tuple(parsed)
            by_id: dict[int, AddressSpaceEvidence] = {}
            for row in spaces:
                previous = by_id.get(row.space_id)
                if previous is not None and previous != row:
                    conflicting_spaces = True
                by_id[row.space_id] = row

        image_field = _field(raw, "image_base")
        if image_field.state is _FieldState.DUPLICATE:
            duplicate_coordinate = True
        elif image_field.state is _FieldState.MISSING:
            missing_image = True
        else:
            result = _parse_coordinate(image_field.value)
            image = result.coordinate
            duplicate_coordinate |= result.duplicate
            missing_image |= result.missing
            invalid_image |= result.invalid

    if image is not None and not invalid_spaces and not conflicting_spaces:
        unique_spaces = tuple({row.space_id: row for row in spaces}.values())
        invalid_image = not _AddressSpaceIndex(unique_spaces, runs).memory_coordinate(
            image, require_run_start=True
        )
    return _ProgramValidation(
        duplicate_program,
        missing_translation,
        invalid_translation,
        duplicate_coordinate,
        incomplete_spaces,
        invalid_spaces,
        conflicting_spaces,
        missing_image,
        invalid_image,
        classification_revision,
        namespace,
        spaces,
        image,
    )


def _parse_translation(value: object) -> _TranslationParse:
    names = ("language_id", "major_version", "minor_version")
    if type(value) is not RawObject:
        return _TranslationParse(invalid=True)
    fields = tuple(_field(value, name) for name in names)
    duplicate = any(item.state is _FieldState.DUPLICATE for item in fields)
    missing = any(item.state is _FieldState.MISSING for item in fields)
    if duplicate or missing:
        return _TranslationParse(duplicate=duplicate, missing=missing)
    try:
        return _TranslationParse(namespace=TranslationNamespace(*(item.value for item in fields)))
    except (TypeError, ValueError):
        return _TranslationParse(invalid=True)


def _parse_address_space(
    value: object,
    classification_revision: int | None,
) -> _AddressSpaceParse:
    legacy_names = (
        "space_id",
        "address_size_bits",
        "addressable_unit_bytes",
        "is_constant_space",
        "is_register_space",
        "is_unique_space",
        "is_memory_space",
        "is_overlay_space",
        "is_external_space",
    )
    revision_names = (
        "is_loaded_memory_space",
        "is_non_loaded_memory_space",
        "has_signed_offset",
    )
    if type(value) is not RawObject:
        return _AddressSpaceParse(invalid=True)
    fields = tuple(_field(value, name) for name in legacy_names)
    duplicate = any(item.state is _FieldState.DUPLICATE for item in fields)
    incomplete = any(item.state is _FieldState.MISSING for item in fields)
    revision_fields = tuple(_field(value, name) for name in revision_names)
    duplicate |= any(item.state is _FieldState.DUPLICATE for item in revision_fields)
    if classification_revision == 1:
        invalid = any(item.state is not _FieldState.MISSING for item in revision_fields)
        if duplicate or incomplete or invalid:
            return _AddressSpaceParse(
                duplicate=duplicate,
                incomplete=incomplete,
                invalid=invalid,
            )
        constructor_fields = fields
    elif classification_revision == 2:
        incomplete |= any(item.state is _FieldState.MISSING for item in revision_fields)
        if duplicate or incomplete:
            return _AddressSpaceParse(duplicate=duplicate, incomplete=incomplete)
        constructor_fields = (*fields, *revision_fields[:2], revision_fields[2])
    else:
        return _AddressSpaceParse(duplicate=duplicate, invalid=True)
    if duplicate or incomplete:
        return _AddressSpaceParse(duplicate=duplicate, incomplete=incomplete)
    try:
        return _AddressSpaceParse(
            row=AddressSpaceEvidence(*(item.value for item in constructor_fields))
        )
    except (TypeError, ValueError):
        return _AddressSpaceParse(invalid=True)


def _parse_coordinate(value: object) -> _CoordinateParse:
    names = ("space_id", "byte_offset")
    if type(value) is not RawObject:
        return _CoordinateParse(invalid=True)
    fields = tuple(_field(value, name) for name in names)
    duplicate = any(item.state is _FieldState.DUPLICATE for item in fields)
    missing = any(item.state is _FieldState.MISSING for item in fields)
    if duplicate or missing:
        return _CoordinateParse(duplicate=duplicate, missing=missing)
    try:
        return _CoordinateParse(coordinate=AddressCoordinate(fields[0].value, fields[1].value))
    except (TypeError, ValueError):
        return _CoordinateParse(invalid=True)


def _space_capacity(row: AddressSpaceEvidence) -> int:
    return row.addressable_unit_bytes * (1 << row.address_size_bits)


def _space_matches(row: AddressSpaceEvidence, kind: VarnodeKindCode) -> bool:
    if kind is VarnodeKindCode.OPAQUE:
        return row.classification_revision == 2 and not any(
            _space_matches(row, concrete)
            for concrete in (
                VarnodeKindCode.CONSTANT,
                VarnodeKindCode.REGISTER,
                VarnodeKindCode.UNIQUE,
                VarnodeKindCode.ADDRESS,
            )
        )
    expected_constant = kind is VarnodeKindCode.CONSTANT
    expected_register = kind is VarnodeKindCode.REGISTER
    expected_unique = kind is VarnodeKindCode.UNIQUE
    expected_memory = kind in (VarnodeKindCode.ADDRESS, VarnodeKindCode.STORAGE)
    if not any((expected_constant, expected_register, expected_unique, expected_memory)):
        return False
    if (
        row.is_constant_space is not expected_constant
        or row.is_register_space is not expected_register
        or row.is_unique_space is not expected_unique
        or row.is_memory_space is not expected_memory
        or row.is_overlay_space
        or row.is_external_space
    ):
        return False
    if row.classification_revision == 1:
        return True
    if expected_memory:
        return (
            row.is_loaded_memory_space is True
            and row.is_non_loaded_memory_space is False
            and row.has_signed_offset is False
        )
    return (
        row.is_loaded_memory_space is False
        and row.is_non_loaded_memory_space is False
    )
