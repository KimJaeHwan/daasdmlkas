"""The sparse gen/kill solver equals a plain whole-graph fixed point."""

import random

import pytest

from tdo_v2._sparse_dataflow import DominatorGraph


def _random_graph(rng):
    count = rng.randint(1, 30)
    keys = [f"b{index:02d}" for index in range(count)]
    predecessors = {key: set() for key in keys}
    for index in range(1, count):
        if rng.random() < 0.9:
            predecessors[keys[index]].add(keys[rng.randrange(index)])  # mostly reachable
    for _ in range(rng.randint(0, count)):
        predecessors[rng.choice(keys)].add(rng.choice(keys))  # back edges, self loops, entry
    transfers = {}
    for key in keys:
        if rng.random() < 0.35:
            events = [("kill", None) if rng.random() < 0.3 else ("gen", f"g{rng.randrange(8)}")
                      for _ in range(rng.randint(1, 3))]
            kills = any(kind == "kill" for kind, _ in events)
            last = max((i for i, (kind, _) in enumerate(events) if kind == "kill"), default=-1)
            after = frozenset(label for kind, label in events[last + 1:] if kind == "gen")
            gens = frozenset(label for kind, label in events if kind == "gen")
            transfers[key] = (kills, after, gens)
    return keys, {k: tuple(sorted(v)) for k, v in predecessors.items()}, transfers


def _dense(keys, predecessors, transfers):
    successors = {key: [] for key in keys}
    for key, sources in predecessors.items():
        for source in sources:
            successors[source].append(key)
    value_in = {keys[0]: frozenset()}
    pending = [keys[0]]
    while pending:
        key = pending.pop()
        row = transfers.get(key)
        out = value_in[key] if row is None else (row[1] if row[0] else value_in[key] | row[2])
        for target in successors[key]:
            merged = out | value_in.get(target, frozenset())
            if target not in value_in or merged != value_in[target]:
                value_in[target] = merged
                pending.append(target)
    return value_in


@pytest.mark.parametrize("chunk", range(4))
def test_sparse_gen_kill_equals_dense(chunk):
    for seed in range(chunk * 500, (chunk + 1) * 500):
        rng = random.Random(seed)
        keys, predecessors, transfers = _random_graph(rng)
        graph = DominatorGraph(keys[0], predecessors)
        expected = _dense(keys, predecessors, transfers)
        assert set(expected) == set(graph.reachable), seed
        assert graph.solve_gen_kill(transfers, keys) == expected, seed
