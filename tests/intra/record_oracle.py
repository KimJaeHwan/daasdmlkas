"""Evaluation oracle for operation records (docs 25.28).

Runs a function concretely (``pcode_interpreter``) and evaluates the records
of its summary's register runs at the exit the run left through, with the
run's own entry values: an eligible record must allow the register's final
bytes (alternatives: the set of values its phis allow). Ineligible records
are counted per reason; register runs only (memory places need locating).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from pcode_interpreter import Interpreter, Unsupported
from summary_oracle import _exit_for
from synthetic import CONST, REG
from tdo_v2.operation_records import Ineligible, evaluate, run_records


@dataclass
class RecordReport:
    evaluated: int = 0
    skipped: Counter = field(default_factory=Counter)
    failures: list = field(default_factory=list)
    runs: int = 0


def entry_reader(interpreter):
    """``evaluate``'s ``entry``: bytes the run read before writing them."""
    values = interpreter.entry_values

    def read(space, offset, size):
        """Entry bytes; a byte the run never read has no bearing on the run:
        any fixed value (a byte it wrote first: 0; one it never touched: the
        interpreter's own lazily drawn entry byte)."""
        found = 0
        for index in range(size):
            key = interpreter._key(space, offset + index)
            byte = values.get(key)
            if byte is None:
                byte = 0 if key in interpreter._bytes else interpreter._byte(*key)[0]
            found |= byte << (8 * index)
        return found

    def entry(node):
        if type(node) is tuple:
            _, space, address, size = node
            return read(space, address, size)
        if "register" in node:
            register = node["register"]
            return read(REG, register["offset"], register["size"])
        if "absolute" in node:
            memory = node["absolute"]
            return read(memory["space"], memory["address"], memory["size"])
        return None

    return entry


def final_register(interpreter, offset, size):
    value = 0
    for index in range(size):
        value |= interpreter._byte(REG, offset + index)[0] << (8 * index)
    return value


def check_records(analyzed, *, seeds=range(6), register_pools=None, records=None) -> RecordReport:
    summary = analyzed.summary
    observation = analyzed.unit.observation
    records = records if records is not None else run_records(analyzed.normalized, analyzed.unit, summary)
    report = RecordReport()
    for seed in seeds:
        interpreter = Interpreter(observation, constant_space=CONST, seed=seed)
        for register, value in (register_pools(seed) if register_pools else {}).items():
            interpreter.preset(REG, register, 8, value)
        try:
            run = interpreter.run()
        except Unsupported:
            report.skipped["interpreter"] += 1
            continue
        if not run.completed or not run.executed:
            continue
        exit_summary = _exit_for(summary, run.executed[-1])
        if exit_summary is None:
            continue
        report.runs += 1
        entry = entry_reader(interpreter)
        for record in records:
            if record.get("exit") != exit_summary.block_key or record["place"]["kind"] != "register_file":
                continue
            try:
                values = evaluate(record, entry)
            except Ineligible as reason:
                report.skipped[reason.args[0]] += 1
                continue
            place = record["place"]
            concrete = final_register(interpreter, place["start"], place["size"])
            report.evaluated += 1
            if concrete not in values:
                report.failures.append((seed, record["span"], concrete, sorted(values)[:4]))
    return report


__all__ = ("RecordReport", "check_records", "entry_reader", "final_register")
