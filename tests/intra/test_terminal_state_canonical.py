"""Terminal memory states serialize by content, not by run-tree shape.

The solver keeps states as persistent balanced trees whose shape depends on
the order of operations. ``_serialize_terminal_states`` must emit the same
nodes for the same run sequence, so solver changes cannot change the result.
"""

import random

from tdo_v2._memory_ssa_state import (
    DefinitionSetPool, EMPTY_STATE, Run, iter_runs, make_state, replace, union,
)
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.memory_ssa import _serialize_terminal_states


def _runs(rng, pool, count):
    runs, position = [], 0
    for _ in range(count):
        length = rng.randint(1, 4)
        runs.append(Run(position, position + length, pool.intern(rng.sample(range(6), rng.randint(1, 2)))))
        position += length
    return runs


def test_same_runs_different_shapes_serialize_identically():
    kinds = type("D", (), {"kind": MemoryDefinitionKind.DATA_WRITE})
    definitions = tuple(kinds() for _ in range(6))
    for seed in range(200):
        rng = random.Random(seed)
        pool = DefinitionSetPool()
        runs = _runs(rng, pool, rng.randint(1, 40))
        balanced = make_state(runs)
        # the same content built by repeated replace/union in a random order
        built = EMPTY_STATE
        for run in rng.sample(runs, len(runs)):
            built = replace(built, run.start, run.stop, run.definitions) if rng.random() < 0.5 \
                else union(built, make_state([run]))
        assert [(r.start, r.stop, r.definitions) for r in iter_runs(built.root)] == \
               [(r.start, r.stop, r.definitions) for r in iter_runs(balanced.root)]
        first = _serialize_terminal_states(("t",), {"t": balanced}, tuple(range(6)), definitions)
        second = _serialize_terminal_states(("t",), {"t": built}, tuple(range(6)), definitions)
        assert first == second
