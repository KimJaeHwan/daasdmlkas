"""``tdo_v2.index_relation`` (docs 25.2 C.3): every claim checked against all
atom values on small address widths, plus named families."""

import itertools
import random

import pytest

from tdo_v2.index_relation import DISJOINT, MAY, Atom, Exact, Form, relation


def _overlap(first, size1, second, size2, values, bits):
    modulus = 1 << bits
    a1, a2 = first.value(values), second.value(values)
    bytes1 = {(a1 + index) % modulus for index in range(size1)}
    return any((a2 + index) % modulus in bytes1 for index in range(size2))


def _values(atoms, bits):
    """Every assignment of the atoms (an unranged atom: every residue)."""
    domains = [range(atom.low, atom.high + 1) if atom.low is not None else range(1 << bits) for atom in atoms]
    for combination in itertools.product(*domains):
        yield {atom.key: value for atom, value in zip(atoms, combination)}


def _check(first, size1, second, size2):
    bits = first.bits
    found = relation(first, size1, second, size2)
    atoms = list({atom.key: atom for atom, _ in first.terms + second.terms}.values())
    truly_disjoint = True
    for values in _values(atoms, bits):
        overlap = _overlap(first, size1, second, size2, values, bits)
        truly_disjoint &= not overlap
        if found is DISJOINT:
            assert not overlap, (first, size1, second, size2, values)
        elif type(found) is Exact:
            assert (first.value(values) - second.value(values)) % (1 << bits) == found.difference
            assert overlap == found.overlaps(size1, size2, bits)
    return found, truly_disjoint


def _random_atom(rng, key, bits):
    kind = rng.choice(("free", "sext", "zext", "range"))
    if kind == "free":
        return Atom(key)
    if kind == "sext":
        width = rng.randint(1, bits - 1)
        return Atom(key, -(1 << (width - 1)), (1 << (width - 1)) - 1)
    if kind == "zext":
        width = rng.randint(1, bits - 1)
        return Atom(key, 0, (1 << width) - 1)
    low = rng.randint(-(1 << bits), 1 << bits)
    return Atom(key, low, low + rng.randint(0, 1 << (bits - 1)))


@pytest.mark.parametrize("bits", [3, 4, 5])
@pytest.mark.parametrize("chunk", range(4))
def test_every_claim_holds_for_every_atom_value(bits, chunk):
    rng = random.Random(bits * 100 + chunk)
    modulus = 1 << bits
    counts = {"exact": 0, "disjoint": 0, "may": 0, "may_but_disjoint": 0}
    for _ in range(400):
        atoms = [_random_atom(rng, name, bits) for name in "xy"[:rng.randint(1, 2)]]
        shared = rng.random() < 0.5

        def form():
            terms = [(atom, rng.choice((1, 2, 4, 8, 12, 16, 24, rng.randrange(modulus)))) for atom in atoms
                     if rng.random() < 0.8]
            return Form.of(bits, rng.randrange(modulus), terms)

        first = form()
        second = Form.of(bits, rng.randrange(modulus), first.terms) if shared else form()
        size1, size2 = rng.randint(1, min(8, modulus)), rng.randint(1, min(8, modulus))
        found, truly_disjoint = _check(first, size1, second, size2)
        if type(found) is Exact:
            counts["exact"] += 1
        elif found is DISJOINT:
            counts["disjoint"] += 1
        else:
            counts["may"] += 1
            counts["may_but_disjoint"] += truly_disjoint
    assert counts["exact"] and counts["disjoint"] and counts["may"]


def test_fields_of_a_struct_array_with_two_indexes_are_disjoint():
    """a[i].f0 (4 bytes at 16i) vs a[j].f8 (4 bytes at 16j + 8): disjoint for
    every i, j by congruence; the same field of two indexes may overlap."""
    i, j = Atom("i"), Atom("j")
    f0 = Form.of(64, 0x1000, [(i, 16)])
    f8 = Form.of(64, 0x1008, [(j, 16)])
    assert relation(f0, 4, f8, 4) is DISJOINT
    assert relation(f0, 4, Form.of(64, 0x1000, [(j, 16)]), 4) is MAY
    assert relation(f0, 8, f8, 4) is DISJOINT
    assert relation(f0, 9, f8, 4) is MAY


def test_the_same_index_gives_an_exact_difference():
    i = Atom("i", -(1 << 31), (1 << 31) - 1)
    element = Form.of(64, 0x2000, [(i, 8)])
    assert relation(Form.of(64, 0x2004, [(i, 8)]), 4, element, 8) == Exact(4)
    assert Exact(4).overlaps(4, 8, 64)
    assert not Exact(8).overlaps(4, 8, 64)


def test_a_constant_near_the_wrap_is_not_taken_as_disjoint():
    """Astra's counterexample family: the interval argument must count every
    wrap position (a constant plus the access width crossing 2^64)."""
    bits = 64
    modulus = 1 << bits
    i = Atom("i", 0, 3)
    first = Form.of(bits, modulus - 2, [(i, 1)])   # bytes at 2^64 - 2 + i
    second = Form.of(bits, 0, [])                  # bytes at 0
    found = relation(first, 4, second, 1)
    assert found is MAY
    # exhaustive over the range: indeed overlaps for i = 0, 1 (wrapping bytes)
    assert any(_overlap(first, 4, second, 1, {"i": value}, bits) for value in range(4))


def test_interval_disjointness_on_sign_extended_indexes():
    """base + i (i a sign-extended byte: [-128, 127]) vs base + 0x200: the
    difference lies in [-0x280, -0x181] -- disjoint for 8-byte accesses."""
    i = Atom("i", -128, 127)
    assert relation(Form.of(64, 0x1000, [(i, 1)]), 8, Form.of(64, 0x1200, []), 8) is DISJOINT
    assert relation(Form.of(64, 0x1000, [(i, 1)]), 8, Form.of(64, 0x1080, []), 8) is MAY


def test_inconsistent_atoms_are_refused():
    with pytest.raises(ValueError):
        Form.of(8, 0, [(Atom("i", 0, 3), 1), (Atom("i", 0, 4), 1)])
    with pytest.raises(ValueError):
        Atom("i", 3, 2)
