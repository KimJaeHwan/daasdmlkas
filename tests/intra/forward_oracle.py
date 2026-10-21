"""Concrete oracle for forward value facts (docs 25.33, F0).

Runs a function with the p-code interpreter and records the concrete value of
every fact's subject (an operation's input) each time the operation executes;
every recorded value must be one the fact allows, with the run's own entry
values for entry bases (``tdo_v2.forward.concretizes``) -- the analysed
activation's executions only (a recursive activation has its own entries). A run the interpreter
cannot finish still checks the values recorded up to where it stopped.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pcode_interpreter import Interpreter, Unsupported
from synthetic import CONST, REG
from tdo_v2.forward import concretizes
from tdo_v2._scope_contracts import VarnodeKindCode


class _Recording(Interpreter):
    def __init__(self, *args, subjects, **kwargs):
        super().__init__(*args, **kwargs)
        self.subjects, self.seen = subjects, {}

    def _execute(self, key, operation, run):
        index = self.subjects.get(key)
        # the analysed activation only (a recursive one has its own entry
        # values) -- its call instructions included: the interpreter enters
        # the callee's activation before running the call instruction itself
        outermost = not self._activations or (
            len(self._activations) == 1 and self._activations[0][1].split(":")[:2] == key.split(":")[:2])
        if index is not None and len(operation.inputs) > index and outermost:
            varnode = operation.inputs[index]
            if varnode.kind is VarnodeKindCode.CONSTANT:
                value = varnode.coordinate.byte_offset & ((1 << (8 * varnode.byte_size)) - 1)
            else:
                value = self._peek(varnode.coordinate.space_id, varnode.coordinate.byte_offset, varnode.byte_size)[0]
            self.seen.setdefault(key, []).append(value)
        return super()._execute(key, operation, run)


@dataclass
class ForwardReport:
    runs: int = 0
    checked: int = 0          # (fact, concrete value) pairs checked
    skipped: int = 0
    failures: list = field(default_factory=list)


def check_forward(unit, facts, *, seeds=range(6), register_pools=None, const_space=CONST, reg_space=REG,
                  **interpreter_options) -> ForwardReport:
    """``interpreter_options``: further ``Interpreter`` keywords (a Bundle's
    havoc_calls, image, program, externals ...)."""
    report = ForwardReport()
    by_key = {fact.operation: fact for fact in facts}
    subjects = {fact.operation: fact.input for fact in facts}
    for seed in seeds:
        interpreter = _Recording(unit.observation, constant_space=const_space, seed=seed, subjects=subjects,
                                 **interpreter_options)
        for register, value in (register_pools(seed) if register_pools else {}).items():
            interpreter.preset(reg_space, register, 8, value)
        try:
            interpreter.run()
            report.runs += 1
        except Unsupported:
            # (the run stopped at an operation the interpreter does not model,
            # e.g. a call: every value recorded before it is still real)
            report.skipped += 1
        values = interpreter.entry_values

        def entry(offset, size):
            found = 0
            for index in range(size):
                key = interpreter._key(reg_space, offset + index)
                byte = values.get(key)
                if byte is None:
                    byte = 0 if key in interpreter._bytes else interpreter._byte(*key)[0]
                found |= byte << (8 * index)
            return found

        for key, seen in interpreter.seen.items():
            fact = by_key[key]
            for concrete in seen:
                report.checked += 1
                if not concretizes(fact.claim, concrete, entry):
                    report.failures.append((seed, key, concrete, fact.claim))
    return report
