"""Check a static function summary against concrete runs (S0: dynamic ⊆ static).

Every completed run is executed with provenance tracking. At the exit the run
left through, every byte the run wrote is compared with the summary run that
covers it:

* a register byte must be covered by a register run; a memory byte by a run
  whose writers include the operation that last wrote it **and whose place,
  evaluated at this run's entry values, holds that byte** (a run whose place
  cannot be evaluated -- an object no entry value locates -- still covers it
  and is counted in ``unlocated``) -- or the function must list that
  operation as an unknown-address writer; a call's transient return-address
  push is skipped: its bytes are dead below the stack pointer;
* an ``IDENTITY`` run must still hold the entry value;
* unless the run is ``UNKNOWN``, every provenance element must be explained:
  ("reg", r) by a register source byte r; ("mem", reader) by ``entry_readers``
  or by an address-unknown debt; ("call", key) by a call crossing or a
  call-clobber debt.

A summary with ``writer_conditions`` claims nothing when one of them fails
(its callers then take the call as unknown): a run where the concrete entry
addresses of a pair overlap, or cannot be located, is skipped
(``conditional_skips``); every other run is checked in full.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pcode_interpreter import Entry, Interpreter, Unsupported
from synthetic import CONST, REG, UNIQUE
from tdo_v2.function_summary import SummaryKind
from tdo_v2.observed_call_state import observed_call_state_projections
from tdo_v2.span_geometry import StorageObjectKind

_ADDRESS_UNKNOWN = {"unresolved_memory_read", "may_alias_read", "call_clobber_read", "opaque_call_write"}


@dataclass
class SummaryReport:
    runs: int = 0
    unsupported: int = 0
    checked: int = 0
    violations: list = field(default_factory=list)
    conditional_skips: int = 0
    # memory bytes checked against the places (at this run's entry values) of
    # the runs listing their writer, or of UNKNOWN runs of its objects:
    place_checked: int = 0
    place_covered: int = 0           # a run's place holds the byte
    place_unlocated_only: int = 0    # only runs whose place could not be evaluated
    place_failed: int = 0            # none holds it (a violation)


class _Locator:
    """Places of summary spans at one run's entry values: global bytes, objects
    based on an entry register, and objects based on a pointer the entry
    memory held at (base + d) -- two levels, d any constant of the function
    (or 0). Independent of the engine's anchors: every candidate base is
    rebuilt from entry values and matched by object identity."""

    _LEVELS = 2

    def __init__(self, interpreter, observation, register_object, reg_space, spaces):
        self.interpreter, self.register_object = interpreter, register_object
        self.reg_space, self.spaces = reg_space, spaces
        self.displacements = sorted({0} | {
            _signed(varnode.coordinate.byte_offset, varnode.byte_size)
            for row in observation.instructions for operation in row.operations
            for varnode in operation.inputs
            if varnode.kind.name == "CONSTANT" and abs(_signed(varnode.coordinate.byte_offset, varnode.byte_size)) < 1 << 20
        })
        self.bases: dict = {}   # scope -> {object id: (space, base value)}
        # entry memory the run read, 8 bytes at a time: a slot at (base + d)
        # whose d is not a literal (base + 0x120 + 0xe0) is still a candidate
        present = {key for key in interpreter.entry_values if key[0] in spaces}
        self.slots = {(space, address) for space, address in present
                      if all((space, (address + index) % interpreter._moduli.get(space, 1 << 64)) in present
                             for index in range(8))}

    def _value(self, space, address):
        modulus = self.interpreter._moduli.get(space, 1 << 64)
        values = [self.interpreter.entry_values.get((space, (address + index) % modulus)) for index in range(8)]
        return None if None in values else sum(byte << (8 * index) for index, byte in enumerate(values))

    def _objects(self, scope):
        if scope in self.bases:
            return self.bases[scope]
        from tdo_v2.relative_memory import _function_relative_object_id
        from tdo_v2.span_geometry import ByteSpan

        found, level = {}, []
        for offset in range(0, 0x400, 8):
            value = self._value(self.reg_space, offset)
            if value is None:
                continue
            anchor = ByteSpan(self.register_object, offset, 8)
            for space in self.spaces:
                object_id = _function_relative_object_id(scope, anchor, space)
                found.setdefault(object_id, (space, value))
                level.append((object_id, space, value))
        for _ in range(self._LEVELS):
            following = []
            for base_object, space, base in level:
                modulus = self.interpreter._moduli.get(space, 1 << 64)
                read = {(address - base + (modulus >> 1)) % modulus - (modulus >> 1)
                        for slot_space, address in self.slots if slot_space == space}
                for displacement in sorted(set(self.displacements) | {d for d in read if abs(d) < 1 << 20}):
                    pointer = self._value(space, base + displacement)
                    if pointer is None:
                        continue
                    slot = ByteSpan(base_object, (1 << 64) + displacement, 8)
                    object_id = _function_relative_object_id(scope, slot, space)
                    if object_id not in found:
                        found[object_id] = (space, pointer)
                        following.append((object_id, space, pointer))
            level = following
        self.bases[scope] = found
        return found

    def place(self, span):
        """(space, start, size) of ``span`` at the entry values, or None."""
        object_id = span.object_id
        size = span.end - span.start
        if object_id.kind is StorageObjectKind.ADDRESS_SPACE:
            return object_id.space_key, span.start, size
        if object_id.kind is not StorageObjectKind.FUNCTION_RELATIVE or self.register_object is None:
            return None
        base = self._objects(object_id.scope).get(object_id)
        if base is None:
            return None
        space, value = base
        return space, (value + span.start - (1 << 64)) % self.interpreter._moduli.get(space, 1 << 64), size


def _signed(value: int, size: int) -> int:
    bits = 8 * size
    return value - (1 << bits) if value >> (bits - 1) & 1 else value


def _holds(place, space, offset, modulus=1 << 64) -> bool:
    return place[0] == space and (offset - place[1]) % modulus < place[2]


def _writer_conditions_hold(summary, locator) -> bool:
    if locator.register_object is None:
        return False
    for read, write in summary.writer_conditions:
        left, right = locator.place(read), locator.place(write)
        if left is None or right is None:
            return False
        # overlap modulo the address width
        modulus = locator.interpreter._moduli.get(left[0], 1 << 64)
        if left[0] == right[0] and ((right[1] - left[1]) % modulus < left[2]
                                    or (left[1] - right[1]) % modulus < right[2]):
            return False
    return True


def _exit_for(summary, last_operation: str):
    space, address, ordinal = last_operation.split(":")[:3]
    instruction = f"{space}:{address}"
    best = None
    for item in summary.exits:
        base, _, start = item.block_key.partition("#")
        if base == instruction and int(start or 0) <= int(ordinal):
            if best is None or int(start or 0) > int(best.block_key.partition("#")[2] or 0):
                best = item
    return best


def _memory_spaces(observation):
    return sorted({
        operation.inputs[0].coordinate.byte_offset
        for row in observation.instructions for operation in row.operations
        if operation.opcode in ("LOAD", "STORE") and operation.inputs
    })


def check_summary(summary, observation, *, seeds=range(6), register_pools=None,
                  spaces=(CONST, REG, UNIQUE), havoc_calls=None, image=None,
                  address_bits=None) -> SummaryReport:
    const_space, reg_space, unique_space = spaces
    report = SummaryReport()
    unknown_writers = set(summary.unknown_writers)
    # a call's return-address push is undone by the callee's ret; the bytes it
    # leaves below the stack pointer are dead (the engine removes the push)
    transient = {
        key for row in observed_call_state_projections(observation)
        for key in row.transient_operation_keys
    }
    for seed in seeds:
        interpreter = Interpreter(observation, constant_space=const_space, seed=seed,
                                  havoc_calls=havoc_calls, image=image, track_provenance=True,
                                  address_bits=address_bits)
        for register, value in (register_pools(seed) if register_pools else {}).items():
            interpreter.preset(reg_space, register, 8, value)
        try:
            run = interpreter.run()
        except Unsupported:
            report.unsupported += 1
            continue
        if not run.completed or not run.executed:
            continue
        register_object = next((r.span.object_id for item in summary.exits for r in item.runs
                                if r.span.object_id.kind is StorageObjectKind.REGISTER_FILE), None)
        locator = _Locator(interpreter, observation, register_object, reg_space, _memory_spaces(observation))
        if summary.writer_conditions and not _writer_conditions_hold(summary, locator):
            report.conditional_skips += 1
            continue
        exit_summary = _exit_for(summary, run.executed[-1])
        last_instruction = ":".join(run.executed[-1].split(":")[:2])
        if any(key.partition("#")[0] == last_instruction for key in summary.tail_exits):
            report.runs += 1  # left through a tail jump: UNKNOWN for callers in S0
            continue
        if exit_summary is None:
            report.violations.append(("no exit summary", run.executed[-1]))
            continue
        report.runs += 1
        register_runs = [r for r in exit_summary.runs
                         if r.span.object_id.kind is StorageObjectKind.REGISTER_FILE]
        places: dict = {}

        def classify(runs, space, offset):
            """(runs whose place holds the byte, runs whose place is unknown)."""
            holding, unlocated = [], []
            for item in runs:
                if item.span not in places:
                    places[item.span] = locator.place(item.span)
                where = places[item.span]
                if where is None:
                    unlocated.append(item)
                elif _holds(where, space, offset, interpreter._moduli.get(space, 1 << 64)):
                    holding.append(item)
            return holding, unlocated

        by_writer: dict[str, list] = {}
        for item in exit_summary.runs:
            for writer in item.writers:
                by_writer.setdefault(writer, []).append(item)
        for (space, offset), (value, writer, tags) in interpreter.final_bytes().items():
            if space == unique_space or space == const_space:
                continue
            report.checked += 1
            if space == reg_space:
                covering = [r for r in register_runs if r.span.start <= offset < r.span.end]
            else:
                if writer in unknown_writers or writer in transient:
                    continue
                listed = by_writer.get(writer, [])
                report.place_checked += 1
                holding, unlocated = classify(listed, space, offset)
                if not holding:
                    # a write the summary lost to a later uncertain-address write
                    # of the same object: covered by an UNKNOWN run of that
                    # object whose place holds the byte
                    objects = {obj for key, obj in summary.writer_objects if key == writer}
                    unknown_holding, unknown_unlocated = classify(
                        [r for r in exit_summary.runs
                         if r.kind is SummaryKind.UNKNOWN and r.span.object_id in objects], space, offset)
                    if unknown_holding:
                        report.place_covered += 1
                        continue
                    if not unlocated and not unknown_unlocated:
                        report.place_failed += 1
                        report.violations.append(("write outside its run" if listed
                                                  else "write missing from summary", space, offset, writer))
                        continue
                    report.place_unlocated_only += 1
                    if not unlocated:
                        continue   # only an UNKNOWN run whose place is unknown: nothing more to check
                    covering = unlocated
                else:
                    report.place_covered += 1
                    covering = holding
            if not covering:
                report.violations.append(("write missing from summary", space, offset, writer))
                continue
            item = covering[0]
            if item.kind is SummaryKind.UNKNOWN or item.conditions:
                continue  # conditional values are decided, and checked, at call sites
            if item.kind is SummaryKind.IDENTITY:
                if value != interpreter.entry_values.get((space, offset)):
                    report.violations.append(("identity broken", space, offset, writer))
                continue
            register_sources = {
                byte for source in item.sources
                if source.object_id.kind is StorageObjectKind.REGISTER_FILE
                for byte in range(source.start, source.end)
            }
            address_unknown = bool(_ADDRESS_UNKNOWN & set(item.debts))
            for tag in tags:
                kind, detail = tag
                if kind == "reg" and detail not in register_sources:
                    report.violations.append(("register source missing", space, offset, writer, detail))
                elif kind == "mem" and detail not in item.entry_readers and not address_unknown:
                    report.violations.append(("memory source missing", space, offset, writer, detail))
                elif kind == "call" and f"call:{detail}" not in item.crossed \
                        and not {"call_clobber_read", "opaque_call_write"} & set(item.debts):
                    report.violations.append(("call effect missing", space, offset, writer, detail))
    return report
