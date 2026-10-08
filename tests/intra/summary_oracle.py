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
