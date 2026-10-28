"""V2's work is what it charges (docs 25.83 D5', Astra r3): the inner loops
of the atom classes, the dominator graph and the demand closure are charged
per element, and a join's union is built once."""

import time

from memory_units import random_unit
from tdo_v2 import _chi_shadow
from tdo_v2._memory_ssa_classes import build_atom_classes
from tdo_v2._sparse_dataflow import DominatorGraph
from tdo_v2.memory_ssa import _build_partition, _raw_definitions
from tdo_v2.resource_limits import bounded


def _units(body):
    with bounded("test", 10**12) as bound:
        result = body()
    return bound.work, result


def test_atom_classes_charge_their_coverage_and_writers():
    for seed in range(40):
        unit = random_unit(seed)
        partition = _build_partition(unit)
        raw = _raw_definitions(unit, partition.connected)
        write_ids = {(item.operation_key, item.write_ordinal): ordinal for ordinal, item in enumerate(raw)
                     if item.operation_key is not None}
        work, _ = _units(lambda: build_atom_classes(unit, partition, write_ids))
        covered = sum(stop - start for span in partition.connected
                      for start, stop in (partition.covered_range(span),))
        appended = sum(stop - start for block in unit.blocks for action in block.actions for span in action.writes
                       for start, stop in (partition.covered_range(span),))
        assert work >= covered + appended + len(partition.atoms)


def _fan(width):
    """entry -> b0..b(width-1) -> join"""
    predecessors = {"entry": ()}
    for index in range(width):
        predecessors[f"b{index:05}"] = ("entry",)
    predecessors["join"] = tuple(f"b{index:05}" for index in range(width))
    return predecessors


def test_a_wide_join_is_one_union_charged_by_its_members():
    """20000 writing predecessors, one definition each: the join's value is
    built once (copying per predecessor was quadratic), charged by its
    members."""
    width = 20000
    graph = DominatorGraph("entry", _fan(width))
    writes = {f"b{index:05}" for index in range(width)}
    start = time.perf_counter()
    work, values = _units(lambda: graph.solve(writes, {"join"}, exit_of_write=lambda key: frozenset((key,)),
                                              entry_value=frozenset(("entry",))))
    assert time.perf_counter() - start < 2.0
    assert values["join"] == frozenset(writes)
    assert work >= width


def test_nearest_point_walks_are_charged(monkeypatch):
    """Every candidate a nearest-point lookup rejects is a unit."""
    graph = DominatorGraph("entry", _fan(300))
    rejected = []
    original = DominatorGraph._dominates

    def counted(self, upper, lower):
        found = original(self, upper, lower)
        if not found:
            rejected.append(1)
        return found

    monkeypatch.setattr(DominatorGraph, "_dominates", counted)
    writes = {f"b{index:05}" for index in range(0, 300, 2)}
    needed = {f"b{index:05}" for index in range(1, 300, 2)} | {"join"}
    work, _ = _units(lambda: graph.solve(writes, needed, exit_of_write=lambda key: frozenset((key,)),
                                         entry_value=frozenset(("entry",))))
    assert rejected and work >= len(rejected)


def test_the_frontier_walks_are_charged():
    """A ladder c1 -> c2 -> ... -> cn, every ci also -> join: the frontier walk
    from ci climbs i - 1 dominators (~n^2 / 2 hops for n frontier entries)."""
    width = 300
    predecessors = {"c00000": ()}
    for index in range(1, width):
        predecessors[f"c{index:05}"] = (f"c{index - 1:05}",)
    predecessors["join"] = tuple(f"c{index:05}" for index in range(width))
    work, graph = _units(lambda: DominatorGraph("c00000", predecessors))
    hops = sum(range(width))
    assert graph.idom["join"] == "c00000" and work >= hops


def test_the_demand_closure_charges_every_definition_it_inspects(monkeypatch):
    """Every definition of every value the closure walks is a unit."""
    from test_chi_records import _branchy, _producer_inputs

    memory_unit, _, calls, preserved, keeping = _producer_inputs(_branchy(), monkeypatch)
    inspected = []
    original = _chi_shadow.LazySparse.value_before

    def counted(self, block, index, item):
        value = original(self, block, index, item)
        inspected.append(len(value))
        return value

    monkeypatch.setattr(_chi_shadow.LazySparse, "value_before", counted)
    work, _ = _units(lambda: _chi_shadow.LazySparse(memory_unit, frozenset(calls), preserved, frozenset(keeping)))
    assert inspected and work >= sum(inspected)
