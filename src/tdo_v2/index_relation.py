"""Relations between two index-addressed accesses (docs 25.2 C.3).

An access is (address form, byte size): the address is a linear form over
the integers read modulo ``M`` = 2^bits (the address space's width),

    address = constant + sum(coefficient_i * atom_i)   (mod M)

An atom is a value identity (two forms name the same atom only when it is
the same value -- the caller decides that); it may carry an integer range
[low, high] (what the operation that produced it guarantees: SEXT from w bits
gives [-2^(w-1), 2^(w-1) - 1], ZEXT [0, 2^w - 1]); one without a range takes
any value.

The bytes of access 1 are [a1, a1 + s1) and those of access 2 [a2, a2 + s2),
both modulo M; they overlap iff a1 - a2 = t (mod M) for some t in the window
W = [-(s1 - 1), s2 - 1].

``relation`` returns
- ``Exact(d)``: every coefficient cancels: a1 - a2 = d (mod M) always;
- ``DISJOINT``: no value of the atoms makes the bytes overlap, proven by
  (i) congruence: with g = gcd(M, every remaining coefficient), a1 - a2 is
  always the constant difference modulo g; no t in W with that residue -> no
  overlap; or (ii) an integer interval [A, B] of a1 - a2 before the modulo
  (every remaining atom has a range): no multiple of M in
  [A - max W, B - min W] -> no overlap at any wrap position;
- ``MAY`` otherwise.
No relation is ever drawn from two atoms being "in the same group"."""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd


@dataclass(frozen=True, slots=True)
class Atom:
    """A value identity with an optional integer range (inclusive)."""

    key: object
    low: int | None = None
    high: int | None = None

    def __post_init__(self) -> None:
        if (self.low is None) != (self.high is None):
            raise ValueError("an atom range needs both ends")
        if self.low is not None and self.low > self.high:
            raise ValueError("an empty atom range")


@dataclass(frozen=True, slots=True)
class Form:
    """constant + sum(coefficient * atom) modulo 2^bits; terms keyed by atom."""

    bits: int
    constant: int
    terms: tuple[tuple[Atom, int], ...] = ()

    @staticmethod
    def of(bits: int, constant: int, terms=()) -> "Form":
        modulus = 1 << bits
        merged: dict = {}
        atoms: dict = {}
        for atom, coefficient in terms:
            if atom.key in atoms and atoms[atom.key] != atom:
                raise ValueError("one atom key with two ranges")
            atoms[atom.key] = atom
            merged[atom.key] = (merged.get(atom.key, 0) + coefficient) % modulus
        kept = tuple(sorted(((atoms[key], value) for key, value in merged.items() if value),
                            key=lambda item: repr(item[0].key)))
        return Form(bits, constant % modulus, kept)

    def minus(self, other: "Form") -> "Form":
        if self.bits != other.bits:
            raise ValueError("forms of different widths")
        return Form.of(self.bits, self.constant - other.constant,
                       self.terms + tuple((atom, -coefficient) for atom, coefficient in other.terms))

    def value(self, values: dict) -> int:
        return (self.constant + sum(coefficient * values[atom.key] for atom, coefficient in self.terms)) \
            % (1 << self.bits)


@dataclass(frozen=True, slots=True)
class Exact:
    difference: int   # a1 - a2 modulo M

    def overlaps(self, size1: int, size2: int, bits: int) -> bool:
        modulus = 1 << bits
        return any((self.difference - t) % modulus == 0 for t in range(-(size1 - 1), size2))


DISJOINT = "disjoint"
MAY = "may"


def _signed(value: int, modulus: int) -> int:
    """The representative of ``value`` mod ``modulus`` nearest to zero."""
    value %= modulus
    return value - modulus if value > modulus // 2 else value


def relation(first: Form, size1: int, second: Form, size2: int):
    """``Exact(d)`` / ``DISJOINT`` / ``MAY`` for access (first, size1) against
    (second, size2); sizes are byte counts in [1, M]."""
    if first.bits != second.bits:
        raise ValueError("accesses of different address widths")
    bits = first.bits
    modulus = 1 << bits
    if not (1 <= size1 <= modulus and 1 <= size2 <= modulus):
        raise ValueError("access sizes out of range")
    difference = first.minus(second)
    if not difference.terms:
        return Exact(difference.constant)
    if size1 + size2 - 1 >= modulus:
        return MAY   # the window covers every residue
    window_low, window_high = -(size1 - 1), size2 - 1
    # (i) congruence
    g = modulus
    for _, coefficient in difference.terms:
        g = gcd(g, coefficient)
    residue = difference.constant % g
    if not any((t - residue) % g == 0 for t in range(window_low, window_high + 1)):
        return DISJOINT
    # (ii) integer interval of the difference before the modulo
    if all(atom.low is not None for atom, _ in difference.terms):
        low = high = _signed(difference.constant, modulus)
        for atom, coefficient in difference.terms:
            k = _signed(coefficient, modulus)
            ends = (k * atom.low, k * atom.high)
            low += min(ends)
            high += max(ends)
        # a multiple of M in [low - window_high, high - window_low]?
        start, end = low - window_high, high - window_low
        if -((-start) // modulus) > end // modulus:
            return DISJOINT
    return MAY


__all__ = ["Atom", "DISJOINT", "Exact", "Form", "MAY", "relation"]
