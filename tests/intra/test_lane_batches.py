"""Batched per-class gen/kill solves (docs 25.31 K3-t5): each lane of a
packed solve equals that class's own ``solve_gen_kill`` -- random graphs
with joins, loops, unreachable blocks, kill blocks off the shared gens."""

import random

import pytest

from tdo_v2._sparse_dataflow import DominatorGraph, lanes_for, solve_lanes


def _graph(rng, size):
    keys = [f"b{index}" for index in range(size)]
    predecessors = {key: [] for key in keys}
    for index in range(1, size):
        predecessors[keys[index]].append(keys[rng.randrange(index)])   # a tree from b0
        for _ in range(rng.randrange(3)):
            predecessors[keys[index]].append(rng.choice(keys))   # joins, loops
    if size > 3:
        predecessors[keys[-1]] = [keys[-2]]   # (b_{n-2} may be unreachable...)
        predecessors[keys[-2]] = [keys[-1]]   # (...a two-block cycle off the entry)
    return keys, DominatorGraph(keys[0], {key: tuple(value) for key, value in predecessors.items()})


def _problems(rng, keys, width, classes):
    gens_blocks = rng.sample(keys, max(1, len(keys) // 2))
    shared = {key: rng.getrandbits(width) for key in gens_blocks}
    problems = []
    for _ in range(classes):
        transfers = {key: (False, value, value) for key, value in shared.items()}
        for key in rng.sample(keys, rng.randrange(1, min(4, len(keys) + 1))):   # kill blocks, on or off the gens
            gens = shared.get(key, 0) | rng.getrandbits(width)
            transfers[key] = (True, gens & rng.getrandbits(width), gens)
        problems.append((transfers, set(rng.sample(keys, rng.randrange(1, len(keys))))))
    return problems


@pytest.mark.parametrize("seed", range(40))
def test_each_lane_is_its_own_solve(seed):
    rng = random.Random(4_000 + seed)
    keys, graph = _graph(rng, rng.randrange(2, 30))
    width = rng.choice((1, 7, 8, 9, 64, 130))
    problems = _problems(rng, keys, width, rng.randrange(2, 12))
    alone = [graph.solve_gen_kill(transfers, needed, empty=0) for transfers, needed in problems]
    assert solve_lanes(graph, problems, width) == alone


def test_lane_count_is_bounded(monkeypatch):
    """The packed ints of a batch fit LANE_BUDGET_BYTES: lanes * (4 bytes per
    30-bit digit, + slack) * ints, ints = 2 * blocks + 5 * points + 2."""
    from tdo_v2._sparse_dataflow import LANE_BUDGET_BYTES, MAX_LANES

    assert lanes_for(10, 10, 20) == MAX_LANES
    for width, blocks, points in ((20_000, 400, 800), (8192, 2048, 4096), (200_000, 1, 1), (300, 5800, 6000)):
        lanes = lanes_for(width, blocks, points)
        ints = 2 * blocks + 5 * points + 2
        digits = 4 * -(-8 * ((width + 7) // 8) // 30) + 4
        assert lanes == 1 or lanes * digits * ints + 64 * ints <= LANE_BUDGET_BYTES
    assert lanes_for(10 ** 9, 10 ** 6, 10 ** 6) == 1
    monkeypatch.setenv("TDO_V2_LANE_BATCH", "0")
    assert lanes_for(10, 10, 20) == 1


@pytest.mark.parametrize("seed", range(40))
def test_shared_rows_are_each_classs_too(seed):
    """``shared`` rows (the keeping set's / owner's gens) plus each class's
    own rows (its kill blocks, overriding): each lane equals the class's
    solve over the merged transfers (docs 25.31 K3-t5b)."""
    rng = random.Random(9_000 + seed)
    keys, graph = _graph(rng, rng.randrange(2, 30))
    width = rng.choice((1, 7, 8, 9, 64, 130))
    shared = {key: (False, value, value) for key in rng.sample(keys, max(1, len(keys) // 2))
              for value in (rng.getrandbits(width),)}
    problems = []
    for _ in range(rng.randrange(2, 12)):
        own = {}
        for key in rng.sample(keys, rng.randrange(1, min(4, len(keys) + 1))):
            gens = shared.get(key, (False, 0, 0))[2] | rng.getrandbits(width)
            own[key] = (True, gens & rng.getrandbits(width), gens) if rng.random() < 0.8 else (False, gens, gens)
        problems.append((own, set(rng.sample(keys, rng.randrange(1, len(keys))))))
    alone = [graph.solve_gen_kill({**shared, **own}, needed, empty=0) for own, needed in problems]
    assert solve_lanes(graph, problems, width, shared) == alone
    assert solve_lanes(graph, problems[:1], width, shared) == alone[:1]
