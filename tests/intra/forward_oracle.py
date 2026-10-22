"""Concrete oracle for forward value facts (docs 25.33, F0).

Runs a function with the p-code interpreter and records the concrete value of
every fact's subject (an operation's input) each time the operation executes;
every recorded value must be one the fact allows, with the run's own entry
values for entry bases (``tdo_v2.forward.concretizes``) -- the analysed
activation's executions only (a recursive activation has its own entries). A run the interpreter
cannot finish still checks the values recorded up to where it stopped.

A context fact (F2a, ``Fact.context`` = (caller key, call key)) is checked on the callee's
executions inside the activation that call entered directly from the analysed
activation (program mode), with the analysed activation's entry values.
Facts no run reached are counted apart (``unexercised``). The interpreter
opens an activation only for a call: a function that tail-jumps into itself
re-enters at the same depth, with the outer entry values (a possible false
failure, as for the analysed activation's own facts).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pcode_interpreter import Interpreter, Unsupported
from synthetic import CONST, REG
from tdo_v2.forward import concretizes
from tdo_v2._scope_contracts import VarnodeKindCode


class _Recording(Interpreter):
    def __init__(self, *args, subjects, contexts=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.subjects, self.contexts, self.seen = subjects, contexts or {}, {}

    def _execute(self, key, operation, run):
        # the activation the call entered directly -- its own call instructions
        # included (the interpreter enters their callee first, as above)
        if self.contexts and (len(self._activations) == 1 or (
                len(self._activations) == 2 and self._activations[1][1].split(":")[:2] == key.split(":")[:2])):
            call = self._activations[0][1]
            index = self.contexts.get((call, key))
            # (not the call instruction itself at depth 1: it runs in the analysed
            # activation; at depth 2 that address is the callee's own call, Astra F2a round 1)
            own = len(self._activations) == 1 and key.split(":")[:2] == call.split(":")[:2]
            if index is not None and len(operation.inputs) > index and not own:
                self.seen.setdefault((call, key), []).append(self._subject_value(operation.inputs[index]))
        index = self.subjects.get(key)
        # the analysed activation only (a recursive one has its own entry
        # values) -- its call instructions included: the interpreter enters
        # the callee's activation before running the call instruction itself
        outermost = not self._activations or (
            len(self._activations) == 1 and self._activations[0][1].split(":")[:2] == key.split(":")[:2])
        if index is not None and len(operation.inputs) > index and outermost:
            self.seen.setdefault(key, []).append(self._subject_value(operation.inputs[index]))
        return super()._execute(key, operation, run)

    def _subject_value(self, varnode):
        if varnode.kind is VarnodeKindCode.CONSTANT:
            return varnode.coordinate.byte_offset & ((1 << (8 * varnode.byte_size)) - 1)
        return self._peek(varnode.coordinate.space_id, varnode.coordinate.byte_offset, varnode.byte_size)[0]


@dataclass
class ForwardReport:
    runs: int = 0
    checked: int = 0          # (fact, concrete value) pairs checked
    skipped: int = 0
    failures: list = field(default_factory=list)
    unexercised: int = 0      # facts no run reached


def check_forward(unit, facts, *, seeds=range(6), register_pools=None, const_space=CONST, reg_space=REG,
                  **interpreter_options) -> ForwardReport:
    """``interpreter_options``: further ``Interpreter`` keywords (a Bundle's
    havoc_calls, image, program, externals ...)."""
    report = ForwardReport()
    # (``facts``: the analysed function's own and its context facts -- the
    # caller key of a context is that function)
    by_key = {(fact.context[-1], fact.operation) if fact.context else fact.operation: fact for fact in facts}
    subjects = {fact.operation: fact.input for fact in facts if not fact.context}
    contexts = {(fact.context[-1], fact.operation): fact.input for fact in facts if fact.context}
    reached = set()
    for seed in seeds:
        interpreter = _Recording(unit.observation, constant_space=const_space, seed=seed, subjects=subjects,
                                 contexts=contexts, **interpreter_options)
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
            reached.add(key)
            for concrete in seen:
                report.checked += 1
                if not concretizes(fact.claim, concrete, entry):
                    report.failures.append((seed, key, concrete, fact.claim))
    report.unexercised = len(set(by_key) - reached)
    return report
