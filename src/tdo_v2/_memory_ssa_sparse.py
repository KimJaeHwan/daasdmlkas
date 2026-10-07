"""Sparse memory SSA engine (docs section 9): one value per atom class.

Same result as the dense engine (``memory_ssa._build_dense``), computed per
atom class (``_memory_ssa_classes``) on a sparse evaluation graph instead of
carrying the whole state through every block:

* A block that writes class c leaves it holding {last such write in the
  block}; any other block passes c through unchanged.
* phi points of c are the entry block and the iterated dominance frontier of
  the blocks writing c (Cytron et al.). The value at a phi is the ENTRY
  definition (entry block only) plus the union of its predecessors' exit
  values; phi values are solved to the least fixed point (loops).
* Any other point reads the value of its nearest dominating write or phi
  block (Choi, Cytron and Ferrante): a block's exit value of c is {last
  write} if it writes c, else the value at its nearest dominator-or-self in
  P = writes U phis; its entry value is the phi value if it is a phi of c,
  else the exit value of its nearest strict dominator in P.

Only the entry values a read or a terminal block needs are materialized;
reads replay their block's writes in action order, and fragments, JOINs and
terminal states are assembled by the shared ``memory_ssa._assemble``.
"""

from __future__ import annotations

from bisect import bisect_right

from ._memory_ssa_classes import build_atom_classes
from ._memory_ssa_state import DefinitionSetPool, Run, make_state
from .memory_contracts import LocalMemorySsaResult, LocalMemoryUnit, MemoryDefinitionKind
from .model import ByteSpan


def build_sparse_local_memory_ssa(unit: LocalMemoryUnit) -> LocalMemorySsaResult:
    from .memory_ssa import _assemble, _build_partition, _raw_definitions

    if type(unit) is not LocalMemoryUnit:
        raise TypeError("local memory SSA requires an exact LocalMemoryUnit")
    partition = _build_partition(unit)
    raw_definitions = _raw_definitions(unit, partition.connected)
    write_ids = {
        (definition.operation_key, definition.write_ordinal): ordinal
        for ordinal, definition in enumerate(raw_definitions)
        if definition.operation_key is not None
    }
    writes_by_action: dict[str, list[int]] = {}
    for (operation_key, _), definition_id in write_ids.items():
        writes_by_action.setdefault(operation_key, []).append(definition_id)
    entry_of_connected = {
        index: next(
            ordinal for ordinal, definition in enumerate(raw_definitions)
            if definition.kind is MemoryDefinitionKind.ENTRY and definition.span == span
        )
        for index, span in enumerate(partition.connected)
    }
    classes = build_atom_classes(unit, partition, write_ids)
    class_of_atom = classes.class_of_atom
    blocks = {block.key: block for block in unit.blocks}
    graph = _DominatorGraph(unit)

    # what each action writes / reads, as classes
    def classes_in(span: ByteSpan) -> list[int]:
        start, stop = partition.covered_range(span)
        return sorted({class_of_atom[atom] for atom in range(start, stop)})

    action_writes: dict[str, list[tuple[int, list[int]]]] = {}  # op -> [(definition, classes)]
    last_write: dict[tuple[str, int], int] = {}                  # (block, class) -> definition
    written_in: list[set[str]] = [set() for _ in classes.classes]
    read_in: list[set[str]] = [set() for _ in classes.classes]
    for block in unit.blocks:
        for action in block.actions:
            for span in action.reads:
                for index in classes_in(span):
                    read_in[index].add(block.key)
            rows = []
            for ordinal, span in enumerate(action.writes):
                definition = write_ids[(action.operation_key, ordinal)]
                covered = classes_in(span)
                rows.append((definition, covered))
                for index in covered:
                    last_write[(block.key, index)] = definition
                    written_in[index].add(block.key)
            action_writes[action.operation_key] = rows

    terminals = tuple(unit.observed_terminal_block_keys)
    entry_values: dict[str, dict[int, frozenset]] = {key: {} for key in blocks}
    for index, atom_class in enumerate(classes.classes):
        entry = frozenset((entry_of_connected[atom_class.connected],))
        needed = read_in[index] | set(terminals)
        if not needed:
            continue
        values = graph.solve(
            written_in[index], needed,
            exit_of_write=lambda key, index=index: frozenset((last_write[(key, index)],)),
            entry_value=entry,
        )
        for key, value in values.items():
            entry_values[key][index] = value

    pool = DefinitionSetPool()
    interned: dict[frozenset, object] = {}

    def idset(value: frozenset):
        found = interned.get(value)
        if found is None:
            found = interned[value] = pool.intern(sorted(value))
        return found

    atoms = partition.atoms

    def fragments(start: int, stop: int, current: dict[int, frozenset], key: str):
        rows = []
        run_start, run_value = start, None
        for atom in range(start, stop):
            index = class_of_atom[atom]
            value = current.get(index)
            if value is None:
                value = entry_values[key][index]
            if run_value is not None and value != run_value:
                rows.append(_fragment(atoms, run_start, atom, idset(run_value)))
                run_start = atom
            run_value = value
        rows.append(_fragment(atoms, run_start, stop, idset(run_value)))
        return tuple(rows)

    def block_reads(block):
        current: dict[int, frozenset] = {}
        for action in block.actions:
            yield [
                fragments(*partition.covered_range(span), current, block.key)
                for span in action.reads
            ]
            for definition, covered in action_writes[action.operation_key]:
                value = frozenset((definition,))
                for index in covered:
                    current[index] = value

    terminal_out_states = {}
    for key in terminals:
        runs = []
        for atom in range(len(atoms)):
            index = class_of_atom[atom]
            definition = last_write.get((key, index))
            value = frozenset((definition,)) if definition is not None else entry_values[key][index]
            runs.append(Run(atom, atom + 1, idset(value)))
        terminal_out_states[key] = make_state(runs)

    return _assemble(
        unit, partition, raw_definitions, writes_by_action, blocks, block_reads,
        terminal_out_states,
    )


def _fragment(atoms, start: int, stop: int, definitions):
    first, last = atoms[start], atoms[stop - 1]
    return ByteSpan(first.object_id, first.start, last.end - first.start), definitions


class _DominatorGraph:
    """Dominator tree, dominance frontiers and nearest-dominator queries of a
    unit's block graph (every block is reachable from the entry)."""

    def __init__(self, unit: LocalMemoryUnit) -> None:
        self.entry = unit.entry_block_key
        self.predecessors = {block.key: tuple(sorted(set(block.predecessors))) for block in unit.blocks}
        successors: dict[str, list[str]] = {key: [] for key in self.predecessors}
        for key, sources in self.predecessors.items():
            for source in sources:
                successors[source].append(key)
        self.successors = {key: tuple(sorted(values)) for key, values in successors.items()}
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
        if len(order) != len(self.successors):
            raise AssertionError("sparse memory SSA requires every block reachable")
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


__all__ = ("build_sparse_local_memory_ssa",)
