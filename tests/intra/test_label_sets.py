"""Label sets as int bitsets (docs 25.31 B2): decode / mask round trips, and
solve_gen_kill gives the same values and work units on ints as on frozensets."""

import random

import pytest

from tdo_v2 import resource_limits
from tdo_v2._sparse_dataflow import DominatorGraph
from tdo_v2.label_sets import LabelUniverse


@pytest.mark.parametrize("seed", range(50))
def test_decode_is_the_inverse_of_mask(seed):
    rng = random.Random(seed)
    labels = [f"0:{rng.randrange(1 << 20):x}:{rng.randrange(9)}:STORE" for _ in range(rng.randint(0, 3000))]
    universe = LabelUniverse(labels)
    for _ in range(20):
        chosen = set(rng.sample(universe.labels, rng.randint(0, len(universe.labels)))) if universe.labels else set()
        bits = universe.mask(chosen | {"not-in-the-universe"})
        assert universe.decode(bits) == sorted(chosen)
        assert bin(bits).count("1") == len(chosen)


def test_the_empty_set():
    universe = LabelUniverse(["a", "b"])
    assert universe.mask([]) == 0 and universe.decode(0) == []
    empty = LabelUniverse([])
    assert empty.labels == () and empty.mask(["a"]) == 0 and empty.decode(0) == []


def test_single_labels_and_the_highest_bit():
    one = LabelUniverse(["only"])
    assert one.decode(one.mask(["only"])) == ["only"]
    universe = LabelUniverse(f"k{index:05d}" for index in range(40000))
    last = universe.labels[-1]
    assert universe.decode(universe.bit(last)) == [last]
    assert universe.decode(universe.bit(universe.labels[0]) | universe.bit(last)) == [universe.labels[0], last]


def _counted(function):
    """(result, step() calls) -- steps counted by patching the module's step."""
    import tdo_v2._sparse_dataflow as module

    calls = [0]
    original = module.step

    def counting(n=1):
        calls[0] += n

    module.step = counting
    try:
        return function(), calls[0]
    finally:
        module.step = original


@pytest.mark.parametrize("seed", range(200))
def test_solve_gen_kill_on_ints_equals_frozensets(seed):
    rng = random.Random(seed)
    count = rng.randint(1, 14)
    keys = [f"b{index:02d}" for index in range(count)]
    predecessors = {key: [] for key in keys}
    for _ in range(rng.randint(count - 1, 3 * count)):
        source, target = rng.choice(keys), rng.choice(keys[1:] or keys)
        predecessors[target].append(source)
    unreachable = rng.random() < 0.3   # some blocks without a path from the entry
    for index in range(1, count):   # otherwise every block reachable
        if not (unreachable and index == count - 1):
            predecessors[keys[index]].append(keys[rng.randrange(index)])
    if rng.random() < 0.3:   # a back edge into the entry
        predecessors[keys[0]].append(rng.choice(keys))
    graph = DominatorGraph(keys[0], {key: tuple(values) for key, values in predecessors.items()})
    labels = [f"w{index}" for index in range(rng.randint(1, 40))]
    universe = LabelUniverse(labels)
    transfers_sets, transfers_bits = {}, {}
    for key in rng.sample(keys, rng.randint(0, count)):
        kills = rng.random() < 0.4
        after = frozenset(rng.sample(labels, rng.randint(0, len(labels))))
        gens = after | frozenset(rng.sample(labels, rng.randint(0, len(labels)))) if not kills else \
            frozenset(rng.sample(labels, rng.randint(0, len(labels)))) | after
        transfers_sets[key] = (kills, after, gens)
        transfers_bits[key] = (kills, universe.mask(after), universe.mask(gens))
    needed = set(rng.sample(keys, rng.randint(1, count)))
    sets, sets_steps = _counted(lambda: graph.solve_gen_kill(transfers_sets, needed))
    bits, bits_steps = _counted(lambda: graph.solve_gen_kill(transfers_bits, needed, empty=0))
    assert sets_steps == bits_steps
    assert {key: frozenset(universe.decode(value)) for key, value in bits.items()} == sets
