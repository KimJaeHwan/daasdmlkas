"""Graph fidelity across calls (interprocedural S1).

Runs the caller with its callees executed for real (``Interpreter(program=…)``)
and checks the caller's graph:

* every dynamic def->use whose reader is a caller operation is a backward
  path (as ``graph_oracle.check``); a byte written inside a call activation is
  attributed to the call and is covered by the call's proven run effect that
  writes it (node ``op:<call>~<i>``), or by call-clobber debt on the reader;
* a byte the call wrote as unknown memory (``~u<j>`` rows, an
  "opaque_call_write" debt each) is covered when the reader's slice reaches
  such a row: its value is declared unknown, so no input is required;
* when it is covered by a proven run effect, every caller-level input the
  activation computed that byte from must be reached by the reader's
  backward slice too (``Run.call_reads``): a caller operation's node, an
  entry register byte, or entry memory (or an address-unknown debt).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from graph_oracle import _covered, _direct_debt, _memory_address_unknown, _node
from pcode_interpreter import Dependency, Entry, Interpreter, Unsupported
from synthetic import CONST, REG, UNIQUE, slice_from
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.observed_call_state import observed_call_state_projections
from tdo_v2.span_geometry import StorageObjectKind


@dataclass
class ProgramReport:
    runs: int = 0
    unsupported: int = 0
    checked: int = 0
    through_calls: int = 0
    silent: list = field(default_factory=list)
    covered_by_debt: list = field(default_factory=list)


def _proven_runs(function):
    """call key -> [(node, register offsets written | None for a memory run)]."""
    found = {}
    graph = function.dependencies
    for call, effect in function.proven_call_effects:
        for index, run in enumerate(effect.runs):
            node = graph.node_for_key(f"op:{call}~{index}")
            offsets = {
                offset for span in run.writes
                if span.object_id.kind is StorageObjectKind.REGISTER_FILE
                for offset in range(span.start, span.end)
            }
            found.setdefault(call, []).append((node, offsets))
        for index, _ in enumerate(effect.memory_runs, start=len(effect.runs)):
            found.setdefault(call, []).append((graph.node_for_key(f"op:{call}~{index}"), None))
    return found


def _opaque_rows(function):
    """call key -> nodes of its unknown-memory rows (``~u<j>``)."""
    graph = function.dependencies
    return {
        call: [graph.node_for_key(f"op:{call}~u{index}") for index in range(len(effect.unknown_memory))]
        for call, effect in function.proven_call_effects if effect.unknown_memory
    }


def _all_opaque(graph, reader, rows) -> bool:
    """Every memory definition the reader's operation reads directly is
    written by one of ``rows`` (a call's ``~u`` rows) alone -- no join of
    several reaching writes."""
    if not rows:
        return False
    node = _node(graph, reader)
    if node is None:
        return False
    definitions = [
        source for source, _, record in graph._graph.in_edges(node)
        if record.span is not None
        and record.span.object_id.kind in (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)
    ]
    if not definitions:
        return False
    for definition in definitions:
        writers = graph._graph.in_edges(definition)
        if not writers or any(record.kind != "memory_defines" or writer not in rows
                              for writer, _, record in writers):
            return False
    return True


def _covering_runs(proven, writer, space, offset, reachable, reg_space):
    """Reached proven run nodes of call ``writer`` that may have written the byte:
    register runs writing that register byte; for memory, any memory run (the
    dynamic address is not mapped to a static object here)."""
    return [node for node, offsets in proven.get(writer, ())
            if node in reachable and ((offsets is not None and offset in offsets)
                                      if space == reg_space else offsets is None)]


def check_program(function, observation, program, *, seeds=range(6), register_pools=None,
                  spaces=(CONST, REG, UNIQUE), havoc_calls=None, image=None,
                  externals=None, no_effect_userops=frozenset()) -> ProgramReport:
    """``program``: callee entry (space, offset) -> observation."""
    const_space, reg_space, unique_space = spaces
    report = ProgramReport()
    graph = function.dependencies
    caller_operations = {
        f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:{operation.opcode}"
        for row in observation.instructions
        for ordinal, operation in enumerate(row.operations)
    }
    transient = {
        key for row in observed_call_state_projections(observation) for key in row.transient_operation_keys
    }
    proven = _proven_runs(function)
    opaque = _opaque_rows(function)
    cache = {}

    def static(reader):
        if reader not in cache:
            node = _node(graph, reader)
            cache[reader] = None if node is None else slice_from(function, node)
        return cache[reader]

    for seed in seeds:
        interpreter = Interpreter(observation, constant_space=const_space, seed=seed,
                                  havoc_calls=havoc_calls, image=image, program=program,
                                  externals=externals, no_effect_userops=no_effect_userops)
        for register, value in (register_pools(seed) if register_pools else {}).items():
            interpreter.preset(reg_space, register, 8, value)
        try:
            run = interpreter.run()
        except Unsupported:
            report.unsupported += 1
            continue
        report.runs += 1
        for dependency in sorted(run.dependencies, key=repr):
            if dependency.reader.split("~e")[0] not in caller_operations or dependency.reader in transient:
                continue
            result = static(dependency.reader)
            report.checked += 1
            if result is None:
                report.silent.append((dependency, "reader operation has no graph node"))
                continue
            writer = dependency.writer
            if isinstance(writer, str) and dependency.space_id not in (reg_space, unique_space) \
                    and not result.is_complete and _all_opaque(graph, dependency.reader, opaque.get(writer, ())):
                # a byte the call wrote with a value it does not state: debt.
                # Only when every memory byte the reader reads is one of that
                # call's unknown-memory rows (the dynamic byte is not mapped to
                # a static one: a wider read also taking other bytes keeps the
                # usual checks); a complete slice stays a silent miss below
                report.through_calls += 1
                continue
            if isinstance(writer, str) and writer in proven and dependency.space_id != unique_space:
                reachable = set(result.result.reachable_nodes)
                runs = _covering_runs(proven, writer, dependency.space_id, dependency.offset,
                                      reachable, reg_space)
                if runs:
                    report.through_calls += 1
                    for tag in run.call_reads.get(
                            (dependency.reader, dependency.space_id, dependency.offset), ()):
                        if not _input_reached(tag, function, graph, result, reachable,
                                              dependency.reader, reg_space, unique_space, proven):
                            # excused only while the slice admits a gap (debt), as in graph_oracle
                            bucket = report.covered_by_debt if not result.is_complete else report.silent
                            bucket.append((dependency, "call input not reached", tag))
                    continue
            if isinstance(writer, str) and writer in proven:
                tags = run.call_reads.get((dependency.reader, dependency.space_id, dependency.offset), ())
                same = [tag for tag in tags if tag[0] == "ext"
                        and (tag[2], tag[3]) == (dependency.space_id, dependency.offset)]
                reached_runs = _covering_runs(proven, writer, dependency.space_id, dependency.offset,
                                              set(result.result.reachable_nodes), reg_space)
                if same and not reached_runs:
                    # the call copied the byte's own pre-call value back (e.g. a
                    # callee-saved register pushed and popped) and its summary
                    # says the byte is preserved (IDENTITY, value-checked by the
                    # summary oracle): the real writer is the pre-call one
                    earlier = same[0][1]
                    if isinstance(earlier, str) and earlier in proven:
                        # an earlier summarized call that also kept the byte: the
                        # same preservation edge, already accepted for that call
                        continue
                    dependency = Dependency(dependency.reader, dependency.space_id,
                                            dependency.offset, earlier)
            if _covered(function, graph, result, dependency, reg_space, unique_space):
                continue
            bucket = report.covered_by_debt if not result.is_complete else report.silent
            bucket.append((dependency, "writer not reached"))
    return report


def _input_reached(tag, function, graph, result, reachable, reader, reg_space, unique_space,
                   proven) -> bool:
    kind = tag[0]
    if kind == "call":
        return False  # an opaque call inside the callee: the run should not be proven
    _, writer, space, offset = tag
    if isinstance(writer, Entry):
        if space == reg_space:
            return result.reaches(offset, 1)
        return (any(graph.node(node).kind is NodeKind.OBSERVED_INPUT for node in reachable)
                and bool(result.memory_bytes)) or _memory_address_unknown(graph, reader)
    node = _node(graph, writer)
    if node is not None and node in reachable:
        return True
    if writer in proven and _covering_runs(proven, writer, space, offset, reachable, reg_space):
        return True  # an earlier call's proven run wrote it
    # a byte an earlier call wrote: covered by that call's proven runs or debt
    return _covered(function, graph, result, Dependency(reader, space, offset, writer),
                    reg_space, unique_space)


def check_sink_demands(analyzed, program, sinks, *, seeds=range(6), register_pools=None,
                       spaces=(CONST, REG, UNIQUE), havoc_calls=None) -> ProgramReport:
    """Sink roots projected through calls (``AnalyzedFunction.projected_sinks``).

    Every sink call executed inside an activation of a call of this function
    must have a projected root at that call, and every caller-level input its
    argument bytes were computed from must be reached by the root's backward
    slice -- unless the root admits a gap (incomplete)."""
    const_space, reg_space, unique_space = spaces
    function, observation = analyzed.normalized, analyzed.unit.observation
    graph = function.dependencies
    proven = _proven_runs(function)
    roots: dict = {}
    for call, _, _, nodes, complete in analyzed.projected_sinks:
        roots.setdefault(call, []).append((nodes, complete))
    report = ProgramReport()
    for seed in seeds:
        interpreter = Interpreter(observation, constant_space=const_space, seed=seed,
                                  havoc_calls=havoc_calls, program=program, sinks=sinks)
        for register, value in (register_pools(seed) if register_pools else {}).items():
            interpreter.preset(reg_space, register, 8, value)
        try:
            run = interpreter.run()
        except Unsupported:
            report.unsupported += 1
            continue
        report.runs += 1
        for call, tags in run.sink_reads:
            report.checked += 1
            candidates = roots.get(call, ())
            if not candidates:
                report.silent.append((call, "sink inside the call has no projected root"))
                continue
            report.through_calls += 1
            for tag in sorted(tags, key=repr):
                reached, admits_gap = False, False
                for nodes, complete in candidates:
                    for node in nodes:
                        result = slice_from(function, node)
                        reachable = set(result.result.reachable_nodes)
                        admits_gap = admits_gap or not (complete and result.is_complete)
                        if tag[0] != "call" and _input_reached(
                                tag, function, graph, result, reachable, call, reg_space,
                                unique_space, proven):
                            reached = True
                if not reached:
                    bucket = report.covered_by_debt if admits_gap else report.silent
                    bucket.append((call, "sink input not reached", tag))
    return report
