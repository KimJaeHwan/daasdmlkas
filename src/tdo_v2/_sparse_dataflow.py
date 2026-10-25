"""Sparse dataflow over a block graph: dominator tree, dominance frontiers,
nearest-dominating-point queries, and sparse evaluation (Choi, Cytron and
Ferrante) of per-class problems.

Shared by the sparse memory SSA (``_memory_ssa_sparse``) and the sparse
call-clobber / may-alias analyses.
"""

from __future__ import annotations

from .resource_limits import checkpoint, step

import os
from bisect import bisect_right
from collections import deque

DATAFLOW_ENGINE_ENV = "TDO_V2_DATAFLOW_ENGINE"          # dense | sparse (call-clobber, may-alias)
LANE_BATCH_ENV = "TDO_V2_LANE_BATCH"                    # "0": one class per solve (the oracle)
MAX_LANES = 64
# the packed values of one batch: kill and gen ints per transfer block and a
# value per point (about four lane-wide ints per transfer block) -- at most
# this many bytes, else fewer lanes (one: the plain per-class solve)
LANE_BUDGET_BYTES = 64 << 20
DATAFLOW_CROSSCHECK_ENV = "TDO_V2_DATAFLOW_CROSSCHECK"  # second engine to compare with


class DataflowEngineMismatch(AssertionError):
    """Two engines of one forward analysis produced different rows."""


def run_dataflow(kind: str, engines: dict, default: str, *args, **kwargs):
    """Run analysis ``kind`` with the selected engine; with the cross-check
    variable set, also run the named engine and require identical rows."""
    name = os.environ.get(DATAFLOW_ENGINE_ENV) or default
    if name not in engines:
        raise ValueError(f"unknown {kind} engine {name!r}; known: {', '.join(sorted(engines))}")
    result = engines[name](*args, **kwargs)
    other = os.environ.get(DATAFLOW_CROSSCHECK_ENV)
    if other:
        if other not in engines:
            raise ValueError(f"unknown {kind} engine {other!r}; known: {', '.join(sorted(engines))}")
        expected = engines[other](*args, **kwargs)
        if result != expected:
            index = next(
                (i for i, (a, b) in enumerate(zip(result, expected)) if a != b),
                min(len(result), len(expected)),
            )
            left = repr(result[index])[:400] if index < len(result) else "<missing>"
            right = repr(expected[index])[:400] if index < len(expected) else "<missing>"
            raise DataflowEngineMismatch(
                f"{kind} engines disagree ({name} vs {other}): {len(result)} vs "
                f"{len(expected)} rows, first difference at [{index}]: {left} != {right}"
            )
    return result


class DominatorGraph:
    """Dominator tree, dominance frontiers and nearest-dominator queries of a
    block graph, restricted to the blocks reachable from the entry."""

    def __init__(self, entry: str, predecessors: dict[str, tuple[str, ...]]) -> None:
        self.entry = entry
        successors: dict[str, list[str]] = {key: [] for key in predecessors}
        for key, sources in predecessors.items():
            for source in set(sources):
                successors[source].append(key)
        all_successors = {key: tuple(sorted(values)) for key, values in successors.items()}
        reachable, pending = set(), [entry]
        while pending:
            step()   # (budget: docs 25.30 K1c)
            node = pending.pop()
            if node not in reachable:
                reachable.add(node)
                pending.extend(all_successors[node])
        self.reachable = frozenset(reachable)
        self.predecessors = {
            key: tuple(sorted(item for item in set(predecessors[key]) if item in reachable))
            for key in reachable
        }
        self.successors = {key: all_successors[key] for key in reachable}
        order = self._reverse_postorder()
        self.idom = self._immediate_dominators(order)
        self.frontier = self._frontiers()
        self._number_tree()

    def _reverse_postorder(self) -> list[str]:
        order, seen = [], {self.entry}
        stack = [(self.entry, iter(self.successors[self.entry]))]
        while stack:
            node, children = stack[-1]
            for child in children:
                if child not in seen:
                    seen.add(child)
                    stack.append((child, iter(self.successors[child])))
                    break
            else:
                stack.pop()
                order.append(node)
        order.reverse()
        return order

    def _immediate_dominators(self, order: list[str]) -> dict[str, str | None]:
        rank = {node: index for index, node in enumerate(order)}
        idom: dict[str, str] = {self.entry: self.entry}

        def intersect(left, right):
            while left != right:
                while rank[left] > rank[right]:
                    left = idom[left]
                while rank[right] > rank[left]:
                    right = idom[right]
            return left

        changed = True
        while changed:
            step()   # (budget: docs 25.30 K1c)
            changed = False
            for node in order[1:]:
                processed = [item for item in self.predecessors[node] if item in idom]
                candidate = processed[0]
                for item in processed[1:]:
                    candidate = intersect(item, candidate)
                if idom.get(node) != candidate:
                    idom[node] = candidate
                    changed = True
        result: dict[str, str | None] = dict(idom)
        result[self.entry] = None
        return result

    def _frontiers(self) -> dict[str, set[str]]:
        frontier: dict[str, set[str]] = {node: set() for node in self.successors}
        for node, sources in self.predecessors.items():
            if len(sources) < 2 and node != self.entry:
                continue
            for source in sources:
                runner = source
                while runner is not None and runner != self.idom[node]:
                    frontier[runner].add(node)
                    runner = self.idom[runner]
        return frontier

    def _number_tree(self) -> None:
        children: dict[str, list[str]] = {node: [] for node in self.successors}
        for node, parent in self.idom.items():
            if parent is not None:
                children[parent].append(node)
        self.pre: dict[str, int] = {}
        self.post: dict[str, int] = {}
        counter = 0
        stack = [(self.entry, False)]
        while stack:
            step()   # (budget: docs 25.30 K1c)
            node, done = stack.pop()
            if done:
                self.post[node] = counter
                counter += 1
                continue
            self.pre[node] = counter
            counter += 1
            stack.append((node, True))
            for child in sorted(children[node], reverse=True):
                stack.append((child, False))

    def _dominates(self, upper: str, lower: str) -> bool:
        return self.pre[upper] <= self.pre[lower] and self.post[lower] <= self.post[upper]

    def solve(self, writes: set[str], needed: set[str], *, exit_of_write, entry_value, capture_phi=None):
        """Entry value of one class at every block in ``needed``.

        Optional ``capture_phi(block, predecessor_values)`` sees the final
        out-values of real predecessors at phi points whose union has at
        least two definitions. It observes this solve's fixed point only;
        no extra states or reaching-definition computation are introduced.
        The external ENTRY value has no synthetic predecessor edge.
        """
        phis = {self.entry}
        pending = list(writes)
        while pending:  # iterated dominance frontier of the writing blocks
            step()   # (budget: docs 25.30 K1c)
            node = pending.pop()
            for item in self.frontier[node]:
                if item not in phis:
                    phis.add(item)
                    pending.append(item)
        points = sorted(writes | phis, key=self.pre.__getitem__)
        point_pre = [self.pre[item] for item in points]

        def nearest(node: str) -> str:
            """Nearest dominator-or-self of ``node`` among the points."""
            position = bisect_right(point_pre, self.pre[node]) - 1
            while not self._dominates(points[position], node):
                position -= 1  # entry dominates everything, so this stops
            return points[position]

        phi_value: dict[str, frozenset] = {item: frozenset() for item in phis}

        def exit_value(node: str) -> frozenset:
            point = nearest(node)
            return exit_of_write(point) if point in writes else phi_value[point]

        sources = {item: [nearest(pred) for pred in self.predecessors[item]] for item in phis}
        dependents: dict[str, set[str]] = {}
        for item, points_in in sources.items():
            for point in points_in:
                if point in phis and point not in writes:
                    dependents.setdefault(point, set()).add(item)
        pending = deque(sorted(phis, key=self.pre.__getitem__))   # FIFO (docs 25.31 B0-5)
        queued = set(pending)
        while pending:
            step()   # (budget: docs 25.30 K1c)
            item = pending.popleft()
            queued.discard(item)
            value = entry_value if item == self.entry else frozenset()
            for point in sources[item]:
                value |= exit_of_write(point) if point in writes else phi_value[point]
            if value != phi_value[item]:
                phi_value[item] = value
                for dependent in dependents.get(item, ()):
                    if dependent not in queued:
                        queued.add(dependent)
                        pending.append(dependent)

        if capture_phi is not None:
            for node in sorted(phis):
                step()
                if len(phi_value[node]) < 2:
                    continue
                incoming = []
                for predecessor in self.predecessors[node]:
                    step()
                    incoming.append((predecessor, exit_value(predecessor)))
                capture_phi(node, tuple(incoming))

        result = {}
        for node in needed:
            if node in phis:
                result[node] = phi_value[node]
            else:
                result[node] = exit_value(self.idom[node])
        return result


    def phis_of(self, blocks) -> set[str]:
        """The entry plus the iterated dominance frontier of ``blocks``."""
        phis = {self.entry}
        pending = [item for item in blocks if item in self.pre]
        while pending:
            step()   # (budget: docs 25.30 K1c)
            node = pending.pop()
            for item in self.frontier[node]:
                if item not in phis:
                    phis.add(item)
                    pending.append(item)
        return phis

    def nearest_in(self, points) -> "callable":
        """``nearest(node)``: the nearest dominator-or-self of ``node`` among
        ``points`` (which must contain the entry)."""
        ordered = sorted(points, key=self.pre.__getitem__)
        keys = [self.pre[item] for item in ordered]

        def nearest(node: str) -> str:
            position = bisect_right(keys, self.pre[node]) - 1
            while not self._dominates(ordered[position], node):
                position -= 1  # the entry dominates everything, so this stops
            return ordered[position]

        return nearest

    def solve_gen_kill_lanes(self, transfers: dict, needed) -> dict:
        """``solve_gen_kill`` over lane-packed int bitsets (``solve_lanes``):
        ``transfers[block] = (kill_mask, gens)``, a block exits with ``(in &
        ~kill_mask) | gens``; union at joins, 0 at the entry. Returns the
        entry value of every reachable block in ``needed``."""
        phis = self.phis_of(transfers)
        points = phis | {item for item in transfers if item in self.pre}
        nearest = self.nearest_in(points)
        sources = {
            item: (
                [nearest(pred) for pred in self.predecessors[item]]
                if item in phis
                else [nearest(self.idom[item])]
            )
            for item in points
        }
        dependents: dict[str, set[str]] = {}
        for item, upstream in sources.items():
            for point in upstream:
                dependents.setdefault(point, set()).add(item)
        value_in = {item: 0 for item in points}

        def value_out(point: str) -> int:
            row = transfers.get(point)
            if row is None:
                return value_in[point]
            kill, gens = row
            return (value_in[point] & ~kill) | gens

        pending = deque(sorted(points, key=self.pre.__getitem__))
        queued = set(pending)
        while pending:
            step()   # (budget: docs 25.30 K1c)
            item = pending.popleft()
            queued.discard(item)
            value = 0
            for point in sources[item]:
                value |= value_out(point)
            if value != value_in[item]:
                before = value_out(item)
                value_in[item] = value
                if value_out(item) != before:
                    for dependent in dependents.get(item, ()):
                        if dependent not in queued:
                            queued.add(dependent)
                            pending.append(dependent)
        result = {}
        exits: dict = {}   # (one packed exit value per point, shared by the blocks it reaches)
        for node in needed:
            if node not in self.pre:
                continue
            if node in points:
                result[node] = value_in[node]
                continue
            point = nearest(node)
            found = exits.get(point)
            if found is None:
                found = exits[point] = value_out(point)
            result[node] = found
        checkpoint()   # (the solve's values still alive)
        return result

    def solve_gen_kill(self, transfers: dict, needed, empty=frozenset()) -> dict:
        """Least fixed point of one per-class gen/kill problem (union at joins,
        empty at the entry), evaluated sparsely. ``empty``: the empty value --
        frozenset() for sets of labels, 0 for int bitsets (``label_sets``).

        ``transfers[block] = (kills, gens_after_last_kill, all_gens)`` for the
        blocks with events: a killing block exits with the gens after its last
        kill, any other block with ``in | all_gens``; blocks without events pass
        their value through. Returns the entry value of every block in
        ``needed`` (reachable blocks only).
        """
        phis = self.phis_of(transfers)
        points = phis | {item for item in transfers if item in self.pre}
        nearest = self.nearest_in(points)
        sources = {
            item: (
                [nearest(pred) for pred in self.predecessors[item]]
                if item in phis
                else [nearest(self.idom[item])]
            )
            for item in points
        }
        dependents: dict[str, set[str]] = {}
        for item, upstream in sources.items():
            for point in upstream:
                dependents.setdefault(point, set()).add(item)
        value_in = {item: empty for item in points}

        def value_out(point: str):
            row = transfers.get(point)
            if row is None:
                return value_in[point]
            kills, after_kill, gens = row
            return after_kill if kills else value_in[point] | gens

        pending = deque(sorted(points, key=self.pre.__getitem__))   # FIFO (docs 25.31 B0-5)
        queued = set(pending)
        while pending:
            step()   # (budget: docs 25.30 K1c)
            item = pending.popleft()
            queued.discard(item)
            value = empty
            for point in sources[item]:
                value |= value_out(point)
            if value != value_in[item]:
                before = value_out(item)
                value_in[item] = value
                if value_out(item) != before:
                    for dependent in dependents.get(item, ()):
                        if dependent not in queued:
                            queued.add(dependent)
                            pending.append(dependent)
        result = {}
        for node in needed:
            if node not in self.pre:
                continue
            result[node] = value_in[node] if node in points else value_out(nearest(node))
        return result


def lanes_for(width: int, blocks: int, points: int) -> int:
    """How many classes over a ``width``-label universe one packed solve
    takes when every batch of the group has at most ``blocks`` transfer
    blocks (the union over the group) and ``points`` solver points (their
    IDF and themselves): a kill and a gen int per block, five values per
    point (the results share the points' exit values), CPython digits (4 bytes per
    30 bits) and an int header each -- within
    ``LANE_BUDGET_BYTES``, at most ``MAX_LANES``; 1: the plain per-class solve."""
    if os.environ.get(LANE_BATCH_ENV) == "0":
        return 1
    # (per point: value_in, the loop's value, ``before``, an exit and a temporary)
    ints = 2 * blocks + 5 * points + 2
    room = LANE_BUDGET_BYTES - 64 * ints
    lane_bits = 8 * max(1, (width + 7) // 8)
    per_lane = (4 * -(-lane_bits // 30) + 4) * ints   # (CPython: 4 bytes per 30-bit digit, +1 digit of slack)
    return max(1, min(MAX_LANES, room // per_lane)) if room > 0 else 1


def batching() -> bool:
    """Whether per-class solves may be batched (``LANE_BATCH_ENV`` != "0");
    off: no batch sizing either -- exactly the per-class path and its work."""
    return os.environ.get(LANE_BATCH_ENV) != "0"


def group_points(graph: DominatorGraph, blocks) -> int:
    """The solver points of any batch whose transfer blocks are among
    ``blocks``: an upper bound for ``lanes_for``."""
    phis = graph.phis_of(blocks)
    return len(phis | {item for item in blocks if item in graph.pre})


def solve_lanes(graph: DominatorGraph, problems: list, width: int, shared=None) -> list:
    """The entry values of several per-class gen/kill problems over the same
    graph -- ``problems``: [(transfers, needed)] in ``solve_gen_kill``'s
    form, values int bitsets over a ``width``-label universe; ``shared``:
    transfers every class has besides its own (a class's transfers are
    ``shared`` overridden by its own rows) -- solved in one packed solve,
    class i in bits [i*W, (i+1)*W) (W: ``width`` rounded up to whole
    bytes). Lanes never mix (``& ~kill``, ``|``, ``==`` are bitwise); a
    class's extra points (another class's transfer blocks) carry its
    identity transfer, so each lane is that class's ``solve_gen_kill``
    result (docs 25.31 K3-t5). A shared row no class overrides is packed
    once and replicated across the lanes (K3-t5b). Returns one {block:
    value} per problem."""
    from .resource_limits import checkpoint

    shared = shared or {}
    if len(problems) == 1:
        own, needed = problems[0]
        transfers = dict(shared)
        transfers.update(own)
        return [graph.solve_gen_kill(transfers, needed, empty=0)]
    lane_bytes = max(1, (width + 7) // 8)
    lane_bits = 8 * lane_bytes
    full = (1 << lane_bits) - 1
    lanes = len(problems)
    overridden: dict = {}
    for own, _ in problems:
        for key in own:
            overridden.setdefault(key, None)
    packed = {}
    for key, (kills, after, all_gens) in shared.items():
        if key in overridden:
            continue
        value = after if kills else all_gens
        kill = int.from_bytes(full.to_bytes(lane_bytes, "little") * lanes, "little") if kills else 0
        packed[key] = (kill, int.from_bytes(value.to_bytes(lane_bytes, "little") * lanes, "little")
                       if value else 0)
    for key in overridden:
        kill = 0
        gens = bytearray(lane_bytes * lanes)
        base = shared.get(key)
        for lane, (own, _) in enumerate(problems):
            row = own.get(key, base)
            if row is None:
                continue   # (identity for this class)
            kills, after, all_gens = row
            value = after if kills else all_gens
            if kills:
                kill |= full << (lane * lane_bits)
            if value:
                gens[lane * lane_bytes:(lane + 1) * lane_bytes] = value.to_bytes(lane_bytes, "little")
        packed[key] = (kill, int.from_bytes(gens, "little"))
    checkpoint()
    needed: set = set()
    for _, wanted in problems:
        needed.update(wanted)
    values = graph.solve_gen_kill_lanes(packed, needed)
    checkpoint()   # (packed and the solve's values still alive)
    del packed
    found = []
    for lane, (_, wanted) in enumerate(problems):
        shift = lane * lane_bits
        found.append({block: (values[block] >> shift) & full for block in wanted if block in values})
    checkpoint()
    return found


__all__ = (
    "DATAFLOW_CROSSCHECK_ENV",
    "DATAFLOW_ENGINE_ENV",
    "DataflowEngineMismatch",
    "DominatorGraph",
    "LANE_BATCH_ENV",
    "batching",
    "group_points",
    "lanes_for",
    "run_dataflow",
    "solve_lanes",
)
