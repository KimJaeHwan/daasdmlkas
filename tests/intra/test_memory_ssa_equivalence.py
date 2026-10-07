"""Memory SSA engine equivalence harness.

Every registered engine must reproduce the ``dense`` result exactly (same
definitions, JOIN identities and sources, read fragments, unresolved
occurrences, terminal states). Checked on random units (``memory_units``),
through normalization of random functions (the cross-check switch), and the
harness itself must report a planted difference precisely.
"""

import dataclasses
import random

import pytest

from memory_units import random_unit
from synthetic import RAX, RDI, FunctionBuilder, load, normalize_with_observation, reg
from test_graph_fidelity import _random_function, _rep_movsb
from tdo_v2 import memory_ssa
from tdo_v2.memory_ssa import (
    MEMORY_SSA_CROSSCHECK_ENV, MEMORY_SSA_ENGINE_ENV, MemorySsaEngineMismatch,
    build_local_memory_ssa, memory_ssa_engine_names, register_memory_ssa_engine,
)
from tdo_v2.memory_ssa_compare import memory_ssa_differences

ALTERNATIVES = tuple(name for name in memory_ssa_engine_names() if name != "dense")


@pytest.mark.parametrize("engine", ALTERNATIVES)
@pytest.mark.parametrize("chunk", range(4))
def test_engines_agree_on_random_units(engine, chunk):
    dense = memory_ssa._ENGINES["dense"]
    other = memory_ssa._ENGINES[engine]
    for seed in range(chunk * 150, (chunk + 1) * 150):
        unit = random_unit(seed)
        expected, actual = dense(unit), other(unit)
        assert actual == expected, (seed, memory_ssa_differences(actual, expected))


@pytest.mark.parametrize("engine", ALTERNATIVES)
def test_engines_agree_through_normalization(engine, monkeypatch):
    """Every unit built while normalizing (including relative-memory
    re-projection passes) is cross-checked."""
    monkeypatch.setenv(MEMORY_SSA_CROSSCHECK_ENV, engine)
    for seed in range(60):  # the seeds test_graph_fidelity uses (valid functions)
        normalize_with_observation(_random_function(random.Random(50_000 + seed)))
    for shape in ("ghidra", "relative"):  # in-instruction loop (p-code sub-blocks)
        normalize_with_observation(
            FunctionBuilder().ins(*_rep_movsb(shape)).ins(load(reg(RAX, 1), reg(RDI))).ret()
        )


def test_crosscheck_reports_the_first_difference(monkeypatch):
    def broken(unit):
        result = dataclasses.replace(memory_ssa._ENGINES["dense"](unit))
        object.__setattr__(result, "reads", result.reads[:-1])  # past validation
        return result

    register_memory_ssa_engine("broken-for-test", broken)
    try:
        monkeypatch.setenv(MEMORY_SSA_CROSSCHECK_ENV, "broken-for-test")
        unit = next(u for u in map(random_unit, range(100)) if memory_ssa._ENGINES["dense"](u).reads)
        with pytest.raises(MemorySsaEngineMismatch, match=r"reads: length \d+ != \d+"):
            build_local_memory_ssa(unit)
    finally:
        memory_ssa._ENGINES.pop("broken-for-test")


def test_engine_selection(monkeypatch):
    unit = random_unit(3)
    monkeypatch.setenv(MEMORY_SSA_ENGINE_ENV, "dense-unchained")
    assert build_local_memory_ssa(unit) == memory_ssa._ENGINES["dense"](unit)
    monkeypatch.setenv(MEMORY_SSA_ENGINE_ENV, "no-such-engine")
    with pytest.raises(ValueError, match="unknown memory SSA engine"):
        build_local_memory_ssa(unit)
