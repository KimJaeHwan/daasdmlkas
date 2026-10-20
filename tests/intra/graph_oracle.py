"""Compare dynamic dependencies from the interpreter with the static graph."""

from __future__ import annotations

from dataclasses import dataclass, field

from pcode_interpreter import Dependency, Entry, Interpreter, Unsupported
from synthetic import CONST, REG, UNIQUE, slice_from
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.observed_call_state import observed_call_state_projections


@dataclass
class Report:
    runs: int = 0
    unsupported: int = 0
    unsupported_reasons: dict = field(default_factory=dict)
    opaque_opcodes: set = field(default_factory=set)
    checked: int = 0
    silent: list = field(default_factory=list)    # missing and the slice claims complete
    covered_by_debt: list = field(default_factory=list)  # missing but the slice is incomplete


def check(function, observation, *, seeds=range(8), register_pools=None,
          spaces=(CONST, REG, UNIQUE), havoc_calls=None, image=None,
          assumed_calls=None) -> Report:
    """Run the observation concretely and check every dynamic dependency.

    ``spaces`` are the (constant, register, unique) space ids of the program.
    """
    const_space, reg_space, unique_space = spaces
    report = Report()
    graph = function.dependencies
    cache = {}
    # The call instruction's own push of the return address is undone by the
    # callee's ret; the engine removes these transient operations on purpose.
    transient = {
        key
        for row in observed_call_state_projections(observation)
        for key in row.transient_operation_keys
    }

    def static(reader):
        if reader not in cache:
            node = _node(graph, reader)
            cache[reader] = None if node is None else slice_from(function, node)
        return cache[reader]

    for seed in seeds:
        interpreter = Interpreter(observation, constant_space=const_space, seed=seed,
                                  havoc_calls=havoc_calls, image=image,
                                  assumed_calls=assumed_calls)
        for register, value in (register_pools(seed) if register_pools else {}).items():
            interpreter.preset(reg_space, register, 8, value)
        try:
            run = interpreter.run()
        except Unsupported as error:
            report.unsupported += 1
            reason = str(error)
            report.unsupported_reasons[reason] = report.unsupported_reasons.get(reason, 0) + 1
            continue
        finally:
            report.opaque_opcodes |= interpreter.opaque_opcodes
        report.runs += 1
        for dependency in sorted(run.dependencies, key=repr):
            if dependency.reader in transient:
                continue
            if dependency.writer in transient:
                dependency = Dependency(
                    dependency.reader, dependency.space_id, dependency.offset,
                    _call_of(dependency.writer),
                )
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


def _node(graph, key):
    """The graph node of an operation; a rep element ``<key>~e<i>`` the graph
    does not model element-wise (count unproven) is its element-0 operation."""
    node = graph.node_for_key(f"op:{key}")
    if node is None and "~e" in key:
        node = graph.node_for_key(f"op:{key.split('~e')[0]}")
    return node


def _covered(function, graph, result, dependency, reg_space=REG, unique_space=UNIQUE) -> bool:
    reachable = set(result.result.reachable_nodes)
    writer = dependency.writer
    if isinstance(writer, str):
        if writer == dependency.reader:
            return True
        node = _node(graph, writer)
        if node is not None and node in reachable:
            return True
        # bytes an opaque call may have produced (or its transient return-address
        # push left behind): the reader must carry call debt, or -- for memory --
        # read through an address the graph declares unknown (any byte possible)
        if writer.rsplit(":", 1)[1] in ("CALL", "CALLIND", "CALLOTHER"):
            return _direct_debt(graph, dependency.reader, "call_clobber_read") or (
                dependency.space_id not in (reg_space, unique_space)
                and _memory_address_unknown(graph, dependency.reader)
            )
        # a memory byte read through an address that a call may have changed
        return dependency.space_id not in (reg_space, unique_space) and _memory_address_unknown(
            graph, dependency.reader
        )
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
    ) or _memory_address_unknown(graph, dependency.reader)


def _memory_address_unknown(graph, reader: str) -> bool:
    """The reader's memory address is not statically certain: unresolved, or
    computed (directly or upstream) from storage an opaque call may have changed,
    so the static object may not be the bytes actually accessed."""
    if _direct_debt(graph, reader, "unresolved_memory_read") or _direct_debt(
        graph, reader, "call_clobber_read"
    ):
        return True
    node = graph.node_for_key(f"op:{reader}")
    if node is None:
        return False
    operands = [
        source
        for source, _, record in graph.in_edges(node)
        if record.kind == "memory_read"
        and record.span is not None
        and record.span.object_id.kind.value in ("register_file", "function_unique")
    ]
    return any(
        graph.node(item).kind is NodeKind.MEMORY_DEBT
        and graph.node(item).label in ("call_clobber_read", "opaque_call_write")
        for item in graph.backward_reachable(operands)
    ) if operands else False


def _direct_debt(graph, reader: str, label: str) -> bool:
    node = graph.node_for_key(f"op:{reader}")
    return node is not None and any(
        graph.node(predecessor).kind is NodeKind.MEMORY_DEBT
        and graph.node(predecessor).label == label
        for predecessor in graph.predecessors(node)
    )


def check_control(function, observation, *, seeds=range(4), register_pools=None,
                  spaces=(CONST, REG, UNIQUE), havoc_calls=None, image=None,
                  assumed_calls=None) -> list:
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
                for _, target, record in graph.out_edges(node):
                    if record.kind == "control_dependence" and target not in seen:
                        seen.add(target)
                        pending.append(target)
            controlled[decision] = {graph.node(node).key[3:] for node in seen}
        return controlled[decision]

    def execute(seed, flip=None):
        interpreter = Interpreter(observation, constant_space=const_space, seed=seed, flip=flip,
                                  havoc_calls=havoc_calls, image=image,
                                  assumed_calls=assumed_calls)
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


def _call_of(transient_key: str) -> str:
    """A transient push belongs to the CALL that ends its instruction."""
    space, address, _, _ = transient_key.split(":")
    return f"{space}:{address}:2:CALL"

