"""Graph fidelity across calls (interprocedural S1).

Runs the caller with its callees executed for real (``Interpreter(program=…)``)
and checks the caller's graph:

* every dynamic def->use whose reader is a caller operation is a backward
  path (as ``graph_oracle.check``); a byte written inside a call activation is
  attributed to the call and is covered by the call's proven run effect that
  writes it (node ``op:<call>~<i>``), or by call-clobber debt on the reader.
  A memory run covers the byte only when its place, evaluated from the values
  just before that activation (``AnchoredSpan``: global bytes, entry register
  + displacement, or the pointer stored at a place + displacement), contains
  the byte; a run whose place cannot be evaluated (a value the snapshot does
  not have) still covers it and is counted in ``ProgramReport.unlocated``;
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
    # bytes a summarized call wrote and the caller read, checked against the
    # places of the call's memory runs (at that activation's callee entry):
    place_checked: int = 0
    place_covered: int = 0           # a reached run's place holds the byte
    place_unlocated_only: int = 0    # only runs whose place could not be evaluated
    place_failed: int = 0            # no run holds it ...
    place_failed_debt: int = 0       # ... and a debt of the reader explains it
    place_no_activation: int = 0     # the writing activation was not recorded (checked as unlocated)
    # bytes left written by activations of calls claiming ``preserves_memory``
    footprint_checked: int = 0
    footprint_unlocated: int = 0     # outside every evaluable place, some place not evaluable
    # ... outside the footprint of a call whose model leaves out library-private
    # writes (accessor-private-state): not checkable here; a byte the caller
    # reads stays checked as a dependency (its place and inputs) -- only an
    # input that is a call the interpreter havocked inside it (a resolver the
    # contract constrains, arbitrary here) counts here instead
    private_unchecked: int = 0
    # same-result atoms (same-result-functions, docs 25.20): activations of
    # calls whose results share one atom must return equal results
    same_result_checked: int = 0     # atoms with two or more activations in a run
    same_result_violations: list = field(default_factory=list)
    # obligations the run cannot check independently: write-backs that
    # changed the slot (the same class by contract, docs 25.20 H)
    same_result_unchecked: int = 0


def _proven_runs(function):
    """call key -> [(node, register offsets written | None for a memory run,
    the memory run's ``AnchoredSpan`` | None)]."""
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
            found.setdefault(call, []).append((node, offsets, None))
        for index, run in enumerate(effect.memory_runs, start=len(effect.runs)):
            found.setdefault(call, []).append((graph.node_for_key(f"op:{call}~{index}"), None, run.write))
    return found


def _place(anchored, snapshot, entry_values, reg_space, depth=0, moduli=None):
    """(space, start, size) of an ``AnchoredSpan`` evaluated with the byte
    values just before the call (``snapshot``, else the entry values), or
    None; addresses modulo each space's width (``moduli``)."""
    moduli = moduli or {}

    def value(space, start, size):
        found = 0
        for index in range(size):
            key = (space, (start + index) % moduli[space]) if space in moduli else (space, start + index)
            byte = snapshot.get(key, entry_values.get(key))
            if byte is None:
                return None
            found |= byte << (8 * index)
        return found

    if anchored.span is not None:
        return anchored.space_id, anchored.displacement % moduli.get(anchored.space_id, 1 << 64), anchored.size
    if anchored.anchor is not None:
        base = value(reg_space, anchored.anchor.start, anchored.anchor.size)
        width = anchored.anchor.size
    elif anchored.pointer is not None and depth < 4:
        slot = _place(anchored.pointer, snapshot, entry_values, reg_space, depth + 1, moduli)
        if slot is None:
            return None
        base = value(*slot)
        width = slot[2]
    else:
        return None
    if base is None:
        return None
    return anchored.space_id, (base + anchored.displacement) % (1 << (8 * width)), anchored.size


def _contains(place, space, offset, modulus=1 << 64) -> bool:
    """The byte at ``offset`` lies in ``place`` -- (space, start, size), the
    start already reduced modulo the address width (``_place``); the
    interpreter's byte offsets are reduced the same way."""
    found_space, start, size = place
    return found_space == space and (offset - start) % modulus < size


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
        source for source, _, record in graph.in_edges(node)
        if record.span is not None
        and record.span.object_id.kind in (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)
    ]
    if not definitions:
        return False
    for definition in definitions:
        writers = graph.in_edges(definition)
        if not writers or any(record.kind != "memory_defines" or writer not in rows
                              for writer, _, record in writers):
            return False
    return True


def _covering_runs(proven, writer, space, offset, reachable, reg_space, located=None):
    """Reached proven run nodes of call ``writer`` that may have written the byte:
    register runs writing that register byte; for memory, the memory runs
    ``located`` accepts (``AnchoredSpan`` -> True: its place holds the byte,
    False: it does not, None: the place cannot be evaluated); without
    ``located`` (no activation known) any memory run."""
    found = []
    for node, offsets, anchored in proven.get(writer, ()):
        if node not in reachable:
            continue
        if space == reg_space:
            if offsets is not None and offset in offsets:
                found.append(node)
        elif offsets is None and (located is None or located(anchored) is not False):
            found.append(node)
    return found


def check_program(function, observation, program, *, seeds=range(6), register_pools=None,
                  spaces=(CONST, REG, UNIQUE), havoc_calls=None, image=None,
                  externals=None, no_effect_userops=frozenset(), private_frame_above=0,
                  address_bits=None, external_abi="win64") -> ProgramReport:
    """``program``: callee entry (space, offset) -> observation.
    ``external_abi``: the convention the modeled externals run with
    (``Interpreter.external_abi``: the binary's, "win64" or "sysv64").
    ``private_frame_above``: the callee home space the analysis took as
    callee-private (``win64-home-space-callee-private``: 0x28), left out of
    the footprint check with the callee's own frame and return address."""
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
    effects = dict(function.proven_call_effects)
    # a bound model keeps its preserved registers across the calls its body
    # makes (the ABI of its contract): calls the interpreter havocks inside it
    # leave them (``Interpreter.abi_calls``)
    # (the registers it keeps, not the ones it writes: ``preserved`` also
    # lists the bytes its runs write, placed before the CALL)
    abi_calls = {
        call: frozenset(byte for span in effect.preserved
                        if span.object_id.kind is StorageObjectKind.REGISTER_FILE
                        for byte in range(span.start, span.end))
        - frozenset(byte for run in effect.runs for span in run.writes
                    if span.object_id.kind is StorageObjectKind.REGISTER_FILE
                    for byte in range(span.start, span.end))
        for call, effect in effects.items() if effect.omits_private_writes
    }
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
                                  externals=externals, no_effect_userops=no_effect_userops,
                                  address_bits=address_bits, abi_calls=abi_calls,
                                  external_abi=external_abi)
        for register, value in (register_pools(seed) if register_pools else {}).items():
            interpreter.preset(reg_space, register, 8, value)
        try:
            run = interpreter.run()
        except Unsupported:
            report.unsupported += 1
            continue
        report.runs += 1
        places = _Places(interpreter, reg_space)
        _check_footprints(report, interpreter, effects, places, havoc_calls, private_frame_above)
        _check_same_results(report, interpreter, function, effects, reg_space)
        for dependency in sorted(run.dependencies, key=repr):
            if dependency.reader.split("~e")[0] not in caller_operations or dependency.reader in transient:
                continue
            result = static(dependency.reader)
            report.checked += 1
            if result is None:
                report.silent.append((dependency, "reader operation has no graph node"))
                continue
            writer = dependency.writer
            memory = dependency.space_id not in (reg_space, unique_space)
            serials = run.reader_activations.get(
                (dependency.reader, dependency.space_id, dependency.offset), {}).get(writer, {None})
            moved = run.reader_moved.get((dependency.reader, dependency.space_id, dependency.offset))
            # placed where its writer wrote it (an allocator model moved it since)
            placed = dependency if moved is None else Dependency(dependency.reader, *moved, writer)
            if isinstance(writer, str) and memory and not result.is_complete \
                    and _all_opaque(graph, dependency.reader, opaque.get(writer, ())) \
                    and places.held(effects[writer].unknown_memory, serials, placed) is not False:
                # a byte the call wrote with a value it does not state, at a
                # place that holds it: debt. Only when every memory byte the
                # reader reads is one of that call's unknown-memory rows (a
                # wider read also taking other bytes keeps the usual checks);
                # a complete slice stays a silent miss below
                report.through_calls += 1
                continue
            if isinstance(writer, str) and writer in proven and dependency.space_id != unique_space:
                reachable = set(result.result.reachable_nodes)
                if not memory:
                    runs = _covering_runs(proven, writer, dependency.space_id, dependency.offset,
                                          reachable, reg_space)
                else:
                    runs = places.covering(proven, writer, serials, placed, reachable, report)
                if runs:
                    report.through_calls += 1
                    for tag in run.call_reads.get(
                            (dependency.reader, dependency.space_id, dependency.offset), ()):
                        if tag[0] == "call" and effects[writer].omits_private_writes:
                            # a value of a call the interpreter havocked inside an
                            # activation whose model's contract constrains it (a
                            # resolver): not checkable -- the byte's place and its
                            # other inputs are checked as usual
                            report.private_unchecked += 1
                            continue
                        if not _input_reached(tag, function, graph, result, reachable, dependency.reader,
                                              reg_space, unique_space, proven, places, report):
                            # excused only while the slice admits a gap (debt), as in graph_oracle
                            bucket = report.covered_by_debt if not result.is_complete else report.silent
                            bucket.append((dependency, "call input not reached", tag))
                    continue
                tags = run.call_reads.get((dependency.reader, dependency.space_id, dependency.offset), ())
                same = [tag for tag in tags if tag[0] == "ext"
                        and (tag[2], tag[3]) == (dependency.space_id, dependency.offset)]
                if same:
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
                elif memory:
                    # no run of the call holds the byte: only a debt the reader
                    # carries (call clobber, unknown address) explains it --
                    # reaching the call's other runs or node does not
                    if (_clobbered_by(function, dependency.reader, writer)
                            or _memory_address_unknown(graph, dependency.reader)
                            or _open_condition_of(graph, reachable, writer)):
                        report.place_failed_debt += 1
                        continue
                    bucket = report.covered_by_debt if not result.is_complete else report.silent
                    bucket.append((dependency, "write outside its run"))
                    continue
            if _covered(function, graph, result, dependency, reg_space, unique_space):
                continue
            bucket = report.covered_by_debt if not result.is_complete else report.silent
            bucket.append((dependency, "writer not reached"))
    return report


def _check_same_results(report, interpreter, function, effects, reg_space) -> None:
    """Every outermost activation of the calls whose result rows share a
    same-result atom returned the same bytes there (an assumption violation
    otherwise -- counted apart from silent misses)."""
    by_atom: dict = {}
    uses = getattr(function, "same_result_uses", ())
    used = {identity for _, identity, _, _ in uses}
    # every write-back of an accessor whose keys the function used: a class a
    # later key may inherit, whether or not that call's own result is used
    for call, effect in effects.items():
        if effect.same_result is None or not effect.same_result[6] or effect.same_result[1] not in used:
            continue
        for serial, (key, entry) in interpreter.activation_snapshots.items():
            returned = interpreter.activation_returns.get(serial)
            place = _place(effect.same_result[4], entry, interpreter.entry_values, reg_space,
                           moduli=interpreter._moduli)
            if key != call or returned is None or place is None:
                continue
            space, start, size = place
            before = [entry.get((space, start + index), interpreter.entry_values.get((space, start + index)))
                      for index in range(size)]
            if before != [returned.get((space, start + index)) for index in range(size)]:
                report.same_result_unchecked += 1
    for row, _, _, atom in uses:
        call = row.rsplit("~", 1)[0]
        result = effects[call].same_result[2]
        for serial, (key, _) in interpreter.activation_snapshots.items():
            returned = interpreter.activation_returns.get(serial)
            if key != call or returned is None:
                continue
            if _havocked(interpreter, serial, reg_space, result):
                report.same_result_unchecked += 1   # an arbitrary resolver: not the contract's
                continue
            value = tuple(returned.get((reg_space, result.start + index)) for index in range(result.size))
            by_atom.setdefault(atom, []).append((call, serial, value))
    _check_separations(report, interpreter, effects, uses, reg_space)
    for atom, seen in by_atom.items():
        if len(seen) < 2:
            continue
        report.same_result_checked += 1
        if len({value for _, _, value in seen}) != 1:
            report.same_result_violations.append((atom, seen))


def _havocked(interpreter, serial, reg_space, span) -> bool:
    """The register bytes ``span`` an activation returned rest on a call the
    interpreter havocked inside it (an arbitrary value, not the contract's)."""
    tags = interpreter.activation_return_tags.get(serial, {})
    return any(tag[0] == "call" for index in range(span.size)
               for tag in tags.get((reg_space, span.start + index), ()))


def _check_separations(report, interpreter, effects, uses, reg_space) -> None:
    """accessor-result-separate: no activation's [result, result + N) holds a
    byte of any activation's read slot, per accessor (an assumption violation
    otherwise) -- the calls the run executed."""
    used = {identity for _, identity, _, _ in uses}
    results: dict = {}
    slots: dict = {}
    for call, effect in effects.items():
        same = effect.same_result
        if same is None or len(same) < 8 or same[7] is None or same[1] not in used:
            continue
        for serial, (key, entry) in interpreter.activation_snapshots.items():
            returned = interpreter.activation_returns.get(serial)
            if key != call or returned is None:
                continue
            value = [returned.get((reg_space, same[2].start + index)) for index in range(same[2].size)]
            if _havocked(interpreter, serial, reg_space, same[2]):
                value = [None]   # an arbitrary resolver's result: its slot still counts
            place = _place(same[4], entry, interpreter.entry_values, reg_space, moduli=interpreter._moduli)
            if None not in value:
                results.setdefault(same[1], []).append(
                    (sum(byte << (8 * index) for index, byte in enumerate(value)), same[7], same[4].space_id))
            if place is not None:
                slots.setdefault(same[1], []).append(place)
    for identity, found in results.items():
        for value, extent, space in found:
            modulus = interpreter._moduli.get(space, 1 << 64)
            for slot_space, start, size in slots.get(identity, ()):
                if slot_space == space and any((start + index - value) % modulus < extent for index in range(size)):
                    report.same_result_violations.append(("separation", identity, value, start))


def _clobbered_by(function, reader, call) -> bool:
    """The reader carries call-clobber debt naming ``call`` (its bytes may be
    what that call left): a debt of another call does not explain them."""
    return any(row.operation_key == reader and call in row.intervening_calls
               for row in function.call_clobber_reads)


def _open_condition_of(graph, reachable, call) -> bool:
    """The slice reaches an "open_condition" debt of one of ``call``'s runs:
    alias pairs the caller could not decide -- when one fails, the callee's
    writes may land elsewhere (a pointer it reads may be one it wrote)."""
    marker = f":{call}~"
    return any(graph.node(node).label == "open_condition" and marker in graph.node(node).key for node in reachable)


class _Places:
    """Places of a call's runs, evaluated per activation from the values at
    the callee's entry (``Interpreter.activation_snapshots``)."""

    def __init__(self, interpreter, reg_space):
        self.interpreter, self.reg_space = interpreter, reg_space

    def holds(self, place, space, offset):
        """``place`` holds the byte, modulo the space's address width."""
        return place is not None and _contains(place, space, offset, self.interpreter._moduli.get(space, 1 << 64))

    def place(self, anchored, serial):
        snapshot = self.interpreter.activation_snapshots.get(serial)
        if snapshot is None or anchored is None:
            return None
        return _place(anchored, snapshot[1], self.interpreter.entry_values, self.reg_space,
                      moduli=self.interpreter._moduli)

    def held(self, anchored_spans, serials, dependency):
        """For every activation: some span holds the byte (True), none of the
        evaluable ones does and none is unevaluable (False), else None."""
        verdict = True
        for serial in serials:
            found = [self.place(item, serial) for item in anchored_spans]
            if any(self.holds(place, dependency.space_id, dependency.offset) for place in found):
                continue
            if any(place is None for place in found):
                verdict = None
                continue
            return False
        return verdict

    def covering(self, proven, writer, serials, dependency, reachable, report):
        """Reached memory runs of ``writer`` holding the byte for every
        activation the reader read it from ([] when some activation has none)."""
        report.place_checked += 1
        runs, unlocated_only = [], False
        for serial in serials:
            if self.interpreter.activation_snapshots.get(serial) is None:
                report.place_no_activation += 1   # its runs cannot be placed: unlocated below
            holding, unlocated = [], []
            for node, offsets, anchored in proven.get(writer, ()):
                if node not in reachable or offsets is not None:
                    continue
                place = self.place(anchored, serial)
                if place is None:
                    unlocated.append(node)
                elif self.holds(place, dependency.space_id, dependency.offset):
                    holding.append(node)
            if not holding and not unlocated:
                report.place_failed += 1
                return []
            unlocated_only = unlocated_only or not holding
            runs.extend(holding or unlocated)
        if unlocated_only:
            report.place_unlocated_only += 1
        else:
            report.place_covered += 1
        return runs


def _check_footprints(report, interpreter, effects, places, havoc_calls, private_frame_above):
    """Every memory byte an activation of a call claiming ``preserves_memory``
    left written lies in one of its memory runs or unknown-memory places --
    except the callee's own frame below its entry stack pointer, the return
    address slot and the callee-private home space above it."""
    if havoc_calls is None:
        return
    reg_space, sp_offset, sp_size = havoc_calls
    for serial, written in interpreter.activation_writes.items():
        call, snapshot = interpreter.activation_snapshots[serial]
        effect = effects.get(call)
        if effect is None or not effect.preserves_memory:
            continue
        values = [snapshot.get((reg_space, sp_offset + index), interpreter.entry_values.get(
            (reg_space, sp_offset + index))) for index in range(sp_size)]
        entry_sp = None if None in values else sum(byte << (8 * index) for index, byte in enumerate(values))
        lowest = interpreter.activation_min_sp.get(serial, entry_sp)
        modulus = 1 << (8 * sp_size)
        spans = [run.write for run in effect.memory_runs] + list(effect.unknown_memory)
        evaluated = [places.place(item, serial) for item in spans]
        for space, offset in written:
            if space not in interpreter._moduli:   # memory spaces only (LOAD / STORE targets)
                continue
            if entry_sp is not None and lowest is not None:
                # the callee frames ([lowest stack pointer, entry)) and the return
                # address -- with the home space, [entry, entry + private_frame_above)
                if (offset - lowest) % modulus < (entry_sp - lowest) % modulus + max(8, private_frame_above):
                    continue
            report.footprint_checked += 1
            if any(places.holds(place, space, offset) for place in evaluated):
                continue
            if any(place is None for place in evaluated):
                report.footprint_unlocated += 1
                continue
            if effect.omits_private_writes:
                report.private_unchecked += 1
                continue
            report.silent.append((("footprint", call, space, offset), "write outside the call's footprint"))


def _input_reached(tag, function, graph, result, reachable, reader, reg_space, unique_space,
                   proven, places=None, report=None) -> bool:
    kind = tag[0]
    if kind == "call":
        return False  # an opaque call inside the callee: the run should not be proven
    _, writer, space, offset, serial = tag
    if isinstance(writer, Entry):
        if space == reg_space:
            return result.reaches(offset, 1)
        return (any(graph.node(node).kind is NodeKind.OBSERVED_INPUT for node in reachable)
                and bool(result.memory_bytes)) or _memory_address_unknown(graph, reader)
    node = _node(graph, writer)
    if writer in proven:
        # a byte an earlier summarized call wrote: one of its runs (reached,
        # holding the byte at that activation) or a debt -- not its node alone
        if space == reg_space:
            if _covering_runs(proven, writer, space, offset, reachable, reg_space):
                return True
        elif places is not None and report is not None:
            if places.covering(proven, writer, {serial}, Dependency(reader, space, offset, writer),
                               reachable, report):
                return True
        elif _covering_runs(proven, writer, space, offset, reachable, reg_space):
            return True
        return _clobbered_by(function, reader, writer) or (
            space not in (reg_space, unique_space) and _memory_address_unknown(graph, reader))
    if node is not None and node in reachable:
        return True
    # a byte an earlier (unsummarized) call wrote: covered by debt
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
            places = _Places(interpreter, reg_space)
            for tag in sorted(tags, key=repr):
                reached, admits_gap = False, False
                for nodes, complete in candidates:
                    for node in nodes:
                        result = slice_from(function, node)
                        reachable = set(result.result.reachable_nodes)
                        admits_gap = admits_gap or not (complete and result.is_complete)
                        if tag[0] != "call" and _input_reached(
                                tag, function, graph, result, reachable, call, reg_space,
                                unique_space, proven, places, report):
                            reached = True
                if not reached:
                    bucket = report.covered_by_debt if admits_gap else report.silent
                    bucket.append((call, "sink input not reached", tag))
    return report
