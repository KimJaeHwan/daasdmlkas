"""Check a static function summary against concrete runs (S0: dynamic ⊆ static).

Every completed run is executed with provenance tracking. At the exit the run
left through, every byte the run wrote is compared with the summary run that
covers it:

* a register byte must be covered by a register run; a memory byte by a run
  whose writers include the operation that last wrote it (or the function
  must list that operation as an unknown-address writer; a call's transient
  return-address push is skipped: its bytes are dead below the stack pointer);
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

_ADDRESS_UNKNOWN = {"unresolved_memory_read", "may_alias_read", "call_clobber_read"}


@dataclass
class SummaryReport:
    runs: int = 0
    unsupported: int = 0
    checked: int = 0
    violations: list = field(default_factory=list)
    conditional_skips: int = 0


def _located(span, interpreter, register_object, reg_space, spaces):
    """(space, start) of a summary span at this run's entry values, or None:
    relative objects based on an entry register, or on a pointer the entry
    memory held next to one (one level)."""
    from tdo_v2.relative_memory import _function_relative_object_id
    from tdo_v2.span_geometry import ByteSpan

    object_id = span.object_id
    if object_id.kind is StorageObjectKind.ADDRESS_SPACE:
        return object_id.space_key, span.start
    if object_id.kind is not StorageObjectKind.FUNCTION_RELATIVE or register_object is None:
        return None

    def entry_value(space, address):
        values = [interpreter.entry_values.get((space, address + index)) for index in range(8)]
        return None if None in values else sum(byte << (8 * index) for index, byte in enumerate(values))

    bases = []   # (anchor span, its value)
    for offset in range(0, 0x400, 8):
        value = entry_value(reg_space, offset)
        if value is not None:
            bases.append((ByteSpan(register_object, offset, 8), value))
    for anchor, value in bases:
        for space in spaces:
            if _function_relative_object_id(object_id.scope, anchor, space) == object_id:
                return space, (value + span.start - (1 << 64)) % (1 << 64)
    for anchor, value in bases:
        for space in spaces:
            base_object = _function_relative_object_id(object_id.scope, anchor, space)
            for displacement in range(-0x100, 0x100):
                slot = ByteSpan(base_object, (1 << 64) + displacement, 8)
                if _function_relative_object_id(object_id.scope, slot, space) != object_id:
                    continue
                pointer = entry_value(space, (value + displacement) % (1 << 64))
                if pointer is None:
                    return None
                return space, (pointer + span.start - (1 << 64)) % (1 << 64)
    return None


def _writer_conditions_hold(summary, interpreter, reg_space, spaces) -> bool:
    register_object = next((run.span.object_id for item in summary.exits for run in item.runs
                            if run.span.object_id.kind is StorageObjectKind.REGISTER_FILE), None)
    if register_object is None:
        return False
    for read, write in summary.writer_conditions:
        left = _located(read, interpreter, register_object, reg_space, spaces)
        right = _located(write, interpreter, register_object, reg_space, spaces)
        if left is None or right is None:
            return False
        if left[0] == right[0] and left[1] < right[1] + write.size and right[1] < left[1] + read.size:
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
                  spaces=(CONST, REG, UNIQUE), havoc_calls=None, image=None) -> SummaryReport:
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
                                  havoc_calls=havoc_calls, image=image, track_provenance=True)
        for register, value in (register_pools(seed) if register_pools else {}).items():
            interpreter.preset(reg_space, register, 8, value)
        try:
            run = interpreter.run()
        except Unsupported:
            report.unsupported += 1
            continue
        if not run.completed or not run.executed:
            continue
        if summary.writer_conditions and not _writer_conditions_hold(
                summary, interpreter, reg_space, _memory_spaces(observation)):
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
                covering = by_writer.get(writer, [])
            if not covering:
                # a write the summary lost to a later uncertain-address write of
                # the same object: covered when that object's content is UNKNOWN
                objects = {obj for key, obj in summary.writer_objects if key == writer}
                if any(r.kind is SummaryKind.UNKNOWN and r.span.object_id in objects
                       for r in exit_summary.runs):
                    continue
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
                        and "call_clobber_read" not in item.debts:
                    report.violations.append(("call effect missing", space, offset, writer, detail))
    return report
