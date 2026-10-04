"""Duplicate-preserving raw JSON evidence without semantic coercion."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import json


@dataclass(frozen=True, slots=True)
class RawMember:
    name: str
    value: object

    def __post_init__(self) -> None:
        if type(self.name) is not str:
            raise TypeError("raw member name must be an exact str")


@dataclass(frozen=True, slots=True)
class RawObject:
    members: tuple[RawMember, ...]

    def __post_init__(self) -> None:
        if type(self.members) is not tuple or any(
            type(member) is not RawMember for member in self.members
        ):
            raise TypeError("raw object members must be an exact RawMember tuple")


class _FieldState(StrEnum):
    MISSING = "missing"
    PRESENT = "present"
    DUPLICATE = "duplicate"


@dataclass(frozen=True, slots=True)
class _RawField:
    state: _FieldState
    value: object | None = None


def parse_raw_json(value: str | bytes) -> RawObject:
    if type(value) is bytes:
        try:
            value = value.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("raw JSON must be strict UTF-8") from exc
    if type(value) is not str:
        raise TypeError("raw JSON input must be exact str or bytes")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("raw JSON must be strict UTF-8") from exc

    def object_pairs(pairs: list[tuple[str, object]]) -> RawObject:
        return RawObject(tuple(RawMember(name, _freeze_raw(item)) for name, item in pairs))

    def reject_nonfinite(token: str) -> object:
        raise ValueError(f"non-finite JSON number is not allowed: {token}")

    try:
        parsed = json.loads(
            value,
            object_pairs_hook=object_pairs,
            parse_constant=reject_nonfinite,
        )
    except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
        raise ValueError("invalid raw JSON") from exc
    parsed = _freeze_raw(parsed)
    if type(parsed) is not RawObject:
        raise ValueError("raw JSON root must be an object")
    return parsed


def _freeze_raw(value: object) -> object:
    if type(value) is list:
        return tuple(_freeze_raw(item) for item in value)
    return value


def _field(raw: object, name: str) -> _RawField:
    if type(raw) is not RawObject:
        return _RawField(_FieldState.MISSING)
    matches = tuple(member.value for member in raw.members if member.name == name)
    if not matches:
        return _RawField(_FieldState.MISSING)
    if len(matches) != 1:
        return _RawField(_FieldState.DUPLICATE)
    return _RawField(_FieldState.PRESENT, matches[0])


def _has_duplicate(raw: object, names: tuple[str, ...]) -> bool:
    return any(_field(raw, name).state is _FieldState.DUPLICATE for name in names)
