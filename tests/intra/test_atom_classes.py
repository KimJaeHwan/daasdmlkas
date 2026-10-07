"""Atom classes (sparse memory SSA, step 2): atoms with the same signature
(connected span, covering writes) hold the same definition set everywhere."""

import dataclasses
import random

import pytest

from memory_units import random_unit
from synthetic import normalize_with_observation
from test_graph_fidelity import _random_function
from tdo_v2 import memory_ssa
from tdo_v2._memory_ssa_classes import build_atom_classes, check_atom_classes
from tdo_v2.memory_ssa import _build_partition, _raw_definitions


@pytest.mark.parametrize("chunk", range(4))
def test_classes_hold_one_value_on_random_units(chunk):
    for seed in range(chunk * 150, (chunk + 1) * 150):
        check_atom_classes(random_unit(seed))


def test_classes_hold_one_value_through_normalization(monkeypatch):
    def checked(unit):
        check_atom_classes(unit)
        return memory_ssa._ENGINES["dense"](unit)

    memory_ssa.register_memory_ssa_engine("dense-classcheck", checked)
    try:
        monkeypatch.setenv(memory_ssa.MEMORY_SSA_ENGINE_ENV, "dense-classcheck")
        for seed in range(60):
            normalize_with_observation(_random_function(random.Random(50_000 + seed)))
    finally:
        memory_ssa._ENGINES.pop("dense-classcheck")


def test_classes_partition_the_atoms_by_signature():
    for seed in range(100):
        unit = random_unit(seed)
        partition = _build_partition(unit)
        raw = _raw_definitions(unit, partition.connected)
        write_ids = {(d.operation_key, d.write_ordinal): i for i, d in enumerate(raw)
                     if d.operation_key is not None}
        classes = build_atom_classes(unit, partition, write_ids)
        atoms = sorted(atom for item in classes.classes for atom in item.atoms)
        assert atoms == list(range(len(partition.atoms)))
        signatures = [(item.connected, item.writers) for item in classes.classes]
        assert len(set(signatures)) == len(signatures)


def test_a_wrong_grouping_is_detected():
    """The checker must fail when atoms with different writers share a class."""
    from tdo_v2 import _memory_ssa_classes as module

    original = module.build_atom_classes

    def merged(unit, partition, write_ids):
        classes = original(unit, partition, write_ids)
        by_connected = {}
        for item in classes.classes:
            by_connected.setdefault(item.connected, []).append(item)
        groups = tuple(
            module.AtomClass(tuple(sorted(a for c in items for a in c.atoms)), connected, ())
            for connected, items in by_connected.items()
        )
        return dataclasses.replace(classes, classes=groups)

    module.build_atom_classes = merged
    try:
        failures = 0
        for seed in range(100):
            try:
                check_atom_classes(random_unit(seed))
            except AssertionError:
                failures += 1
        assert failures > 0
    finally:
        module.build_atom_classes = original
