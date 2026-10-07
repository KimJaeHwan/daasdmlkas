"""Readable differences between two ``LocalMemorySsaResult`` values.

Used by the memory SSA engine cross-check (``memory_ssa``) and by tests: an
alternative engine must reproduce the dense result exactly, and a mismatch
must say which field, which element, and how it differs, so the fault is
attributable without re-deriving it by hand.
"""

from __future__ import annotations

from dataclasses import fields

from .memory_contracts import LocalMemorySsaResult


def memory_ssa_differences(
    actual: LocalMemorySsaResult, expected: LocalMemorySsaResult, *, limit: int = 5
) -> tuple[str, ...]:
    """Up to ``limit`` descriptions of differing fields (empty when equal)."""
    if type(actual) is not LocalMemorySsaResult or type(expected) is not LocalMemorySsaResult:
        raise TypeError("memory SSA comparison requires exact results")
    found: list[str] = []
    for field in fields(LocalMemorySsaResult):
        left, right = getattr(actual, field.name), getattr(expected, field.name)
        if left == right:
            continue
        found.append(f"{field.name}: {_describe(left, right)}")
        if len(found) >= limit:
            break
    return tuple(found)


def _describe(left: object, right: object) -> str:
    if type(left) is tuple and type(right) is tuple:
        if len(left) != len(right):
            first = next(
                (index for index, (a, b) in enumerate(zip(left, right)) if a != b),
                min(len(left), len(right)),
            )
            return f"length {len(left)} != {len(right)}, first difference at [{first}]: " + _pair(
                left[first] if first < len(left) else "<missing>",
                right[first] if first < len(right) else "<missing>",
            )
        index = next(index for index, (a, b) in enumerate(zip(left, right)) if a != b)
        count = sum(1 for a, b in zip(left, right) if a != b)
        return f"{count} element(s) differ, first at [{index}]: " + _pair(left[index], right[index])
    return _pair(left, right)


def _pair(left: object, right: object) -> str:
    return f"{_short(left)} != {_short(right)}"


def _short(value: object, size: int = 300) -> str:
    text = repr(value)
    return text if len(text) <= size else text[:size] + "..."


__all__ = ("memory_ssa_differences",)
