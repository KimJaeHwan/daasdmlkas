"""Sparse dataflow over a block graph: dominator tree, dominance frontiers,
nearest-dominating-point queries, and sparse evaluation (Choi, Cytron and
Ferrante) of per-class problems.

Shared by the sparse memory SSA (``_memory_ssa_sparse``) and the sparse
call-clobber / may-alias analyses.
"""

from __future__ import annotations

import os
from bisect import bisect_right

DATAFLOW_ENGINE_ENV = "TDO_V2_DATAFLOW_ENGINE"          # dense | sparse (call-clobber, may-alias)
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

    def solve(self, writes: set[str], needed: set[str], *, exit_of_write, entry_value):
        """Entry value of one class at every block in ``needed``."""
        phis = {self.entry}
        pending = list(writes)
        while pending:  # iterated dominance frontier of the writing blocks
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
        pending = sorted(phis, key=self.pre.__getitem__)
        queued = set(pending)
        while pending:
            item = pending.pop(0)
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

    def solve_gen_kill(self, transfers: dict, needed) -> dict[str, frozenset]:
        """Least fixed point of one per-class gen/kill problem (union at joins,
        empty at the entry), evaluated sparsely.

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
        value_in = {item: frozenset() for item in points}

        def value_out(point: str) -> frozenset:
            row = transfers.get(point)
            if row is None:
                return value_in[point]
            kills, after_kill, gens = row
            return after_kill if kills else value_in[point] | gens

        pending = sorted(points, key=self.pre.__getitem__)
        queued = set(pending)
        while pending:
            item = pending.pop(0)
            queued.discard(item)
            value = frozenset()
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


__all__ = (
    "DATAFLOW_CROSSCHECK_ENV",
    "DATAFLOW_ENGINE_ENV",
    "DataflowEngineMismatch",
    "DominatorGraph",
    "run_dataflow",
)
