"""Atom classes for the sparse memory SSA (docs section 9).

The memory SSA lattice has no coupling between atoms: a write replaces the
definition set of exactly the atoms it covers, reads and joins look at atoms
independently, and every atom of one connected span starts with the same
ENTRY definition. Two atoms with the same signature

    (connected span, set of writes covering the atom)

therefore hold the same reaching-definition set at every program point. A
class is the set of atoms sharing one signature; the sparse engine solves
one value per class instead of one per atom.

``check_atom_classes`` verifies the claim against the dense engine (every
block entry, every point between actions, every block exit).
"""

from __future__ import annotations

from dataclasses import dataclass

from ._memory_ssa_state import iter_runs
from .resource_limits import step


@dataclass(frozen=True, slots=True)
class AtomClass:
    atoms: tuple[int, ...]       # partition atom indices, ascending
    connected: int               # index into partition.connected (shared ENTRY definition)
    writers: tuple[int, ...]     # raw definition ids of the writes covering these atoms


@dataclass(frozen=True, slots=True)
class AtomClasses:
    classes: tuple[AtomClass, ...]   # ordered by first atom
    class_of_atom: tuple[int, ...]   # atom index -> class index


def build_atom_classes(unit, partition, write_ids) -> AtomClasses:
    count = len(partition.atoms)
    connected_of = [-1] * count
    for index, span in enumerate(partition.connected):
        start, stop = partition.covered_range(span)
        step(1 + stop - start)   # (budget: docs 25.30 K1c; every inner loop here, D5')
        for atom in range(start, stop):
            connected_of[atom] = index
    if -1 in connected_of:
        raise AssertionError("an atom lies outside every connected span")
    writers: list[list[int]] = [[] for _ in range(count)]
    for block in unit.blocks:
        for action in block.actions:
            for ordinal, span in enumerate(action.writes):
                start, stop = partition.covered_range(span)
                step(1 + stop - start)
                definition = write_ids[(action.operation_key, ordinal)]
                for atom in range(start, stop):
                    writers[atom].append(definition)
    by_signature: dict[tuple, list[int]] = {}
    for atom in range(count):
        step(1 + len(writers[atom]))
        signature = (connected_of[atom], tuple(sorted(writers[atom])))
        by_signature.setdefault(signature, []).append(atom)
    groups = sorted(by_signature.items(), key=lambda item: item[1][0])
    classes = tuple(
        AtomClass(tuple(atoms), signature[0], signature[1]) for signature, atoms in groups
    )
    class_of_atom = [0] * count
    for index, atom_class in enumerate(classes):
        for atom in atom_class.atoms:
            class_of_atom[atom] = index
    return AtomClasses(classes, tuple(class_of_atom))


def atom_values(state, count: int) -> list:
    """Definition set (IdSet or None) per atom of one dense state."""
    values = [None] * count
    for run in iter_runs(state.root):
        for atom in range(run.start, run.stop):
            values[atom] = run.definitions
    return values


def check_atom_classes(unit) -> AtomClasses:
    """Build the classes and assert, against the dense engine, that all atoms
    of a class hold the same definition set at every program point."""
    from .memory_ssa import (
        _apply_writes, _build_partition, _dense_states, _entry_state, _raw_definitions,
    )
    from ._memory_ssa_state import DefinitionSetPool
    from .memory_contracts import MemoryDefinitionKind

    partition = _build_partition(unit)
    raw_definitions = _raw_definitions(unit, partition.connected)
    write_ids = {
        (definition.operation_key, definition.write_ordinal): ordinal
        for ordinal, definition in enumerate(raw_definitions)
        if definition.operation_key is not None
    }
    entry_ids = {
        definition.span: ordinal
        for ordinal, definition in enumerate(raw_definitions)
        if definition.kind is MemoryDefinitionKind.ENTRY
    }
    classes = build_atom_classes(unit, partition, write_ids)
    pool = DefinitionSetPool()
    in_states, out_states = _dense_states(
        unit, partition, write_ids, _entry_state(partition, entry_ids, pool), pool
    )
    count = len(partition.atoms)

    def check(state, where):
        values = atom_values(state, count)
        for atom_class in classes.classes:
            first = values[atom_class.atoms[0]]
            for atom in atom_class.atoms[1:]:
                if values[atom] != first:
                    raise AssertionError(
                        f"atom class split at {where}: atoms {atom_class.atoms[0]} and {atom}"
                    )

    for block in unit.blocks:
        state = in_states[block.key]
        check(state, f"{block.key} entry")
        for action in block.actions:
            state = _apply_writes(state, action, partition, write_ids, pool)
            check(state, f"after {action.operation_key}")
        check(out_states[block.key], f"{block.key} exit")
    return classes


__all__ = ("AtomClass", "AtomClasses", "atom_values", "build_atom_classes", "check_atom_classes")
