"""Compare dynamic dependencies from the interpreter with the static graph."""

from __future__ import annotations

from dataclasses import dataclass, field

from pcode_interpreter import Entry, Interpreter, Unsupported
from synthetic import CONST, REG, UNIQUE, slice_from
from tdo_v2.graph_contracts import NodeKind


@dataclass
class Report:
    runs: int = 0
    unsupported: int = 0
    checked: int = 0
    silent: list = field(default_factory=list)    # missing and the slice claims complete
    covered_by_debt: list = field(default_factory=list)  # missing but the slice is incomplete


def check(function, observation, *, seeds=range(8), register_pools=None,
          spaces=(CONST, REG, UNIQUE)) -> Report:
    """Run the observation concretely and check every dynamic dependency.

    ``spaces`` are the (constant, register, unique) space ids of the program.
    """
    const_space, reg_space, unique_space = spaces
    report = Report()
    graph = function.dependencies
    cache = {}

    def static(reader):
        if reader not in cache:
            node = graph.node_for_key(f"op:{reader}")
            cache[reader] = None if node is None else slice_from(function, node)
        return cache[reader]

    for seed in seeds:
        interpreter = Interpreter(observation, constant_space=const_space, seed=seed)
        for register, value in (register_pools(seed) if register_pools else {}).items():
            interpreter.preset(reg_space, register, 8, value)
        try:
            run = interpreter.run()
        except Unsupported:
            report.unsupported += 1
            continue
        report.runs += 1
        for dependency in sorted(run.dependencies, key=repr):
            result = static(dependency.reader)
            report.checked += 1
            if result is None:
                report.silent.append((dependency, "reader operation has no graph node"))
                continue
            if _covered(function, graph, result, dependency, reg_space, unique_space):
                continue
            # Stricter than "the slice is incomplete somewhere": a missing writer
            # is only excused while the graph has no evidence model for it yet;
            # every such case is reported and must trend to zero.
            bucket = report.covered_by_debt if not result.is_complete else report.silent
            bucket.append((dependency, "writer not reached"))
    return report


def _covered(function, graph, result, dependency, reg_space=REG, unique_space=UNIQUE) -> bool:
    reachable = set(result.result.reachable_nodes)
    writer = dependency.writer
    if isinstance(writer, str):
        if writer == dependency.reader:
            return True
        node = graph.node_for_key(f"op:{writer}")
        return node is not None and node in reachable
    assert isinstance(writer, Entry)
    if writer.space_id == reg_space:
        return result.reaches(writer.offset, 1)
    if writer.space_id == unique_space:
        return False  # a temporary read before any write: the graph cannot explain it
    # Memory entry state: an entry memory input must be reached, or the reader's
    # address is unknown (direct unresolved-read debt: any entry byte is possible).
    return (
        any(graph.node(node).kind is NodeKind.OBSERVED_INPUT for node in reachable)
        and bool(result.memory_bytes)
    ) or _direct_debt(graph, dependency.reader, "unresolved_memory_read")


def _direct_debt(graph, reader: str, label: str) -> bool:
    node = graph.node_for_key(f"op:{reader}")
    return node is not None and any(
        graph.node(predecessor).kind is NodeKind.MEMORY_DEBT
        and graph.node(predecessor).label == label
        for predecessor in graph.predecessors(node)
    )


def check_control(function, observation, *, seeds=range(4), register_pools=None,
                  spaces=(CONST, REG, UNIQUE)) -> list:
    """Flip test: inverting a branch's first decision may only change the
    execution of operations reachable from it through control-dependence edges.

    Returns the violations (branch, operation) found.
    """
    const_space, reg_space, _ = spaces
    graph = function.dependencies
    controlled = {}

    def reach(decision):
        if decision not in controlled:
            start = graph.node_for_key(f"op:{decision}")
            seen, pending = set(), [start]
            while pending:
                node = pending.pop()
                for _, target, record in graph._graph.out_edges(node):
                    if record.kind == "control_dependence" and target not in seen:
                        seen.add(target)
                        pending.append(target)
            controlled[decision] = {graph.node(node).key[3:] for node in seen}
        return controlled[decision]

    def execute(seed, flip=None):
        interpreter = Interpreter(observation, constant_space=const_space, seed=seed, flip=flip)
        for register, value in (register_pools(seed) if register_pools else {}).items():
            interpreter.preset(reg_space, register, 8, value)
        return interpreter.run()

    violations = []
    for seed in seeds:
        try:
            base = execute(seed)
        except Unsupported:
            continue
        for decision in dict.fromkeys(key for key, _ in base.branch_decisions):
            try:
                flipped = execute(seed, flip=decision)
            except Unsupported:
                continue
            if not (base.completed and flipped.completed):
                continue
            # Only attribute differences to this branch when every other
            # branch decided the same way (data changes can steer later branches).
            others = lambda run: [row for row in run.branch_decisions if row[0] != decision]
            if others(base) != others(flipped):
                continue
            changed = set(base.executed) ^ set(flipped.executed)
            missing = changed - reach(decision) - {decision}
            violations.extend((decision, key) for key in sorted(missing))
    return violations

