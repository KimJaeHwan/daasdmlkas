"""Unknown-address writers by destination (B', docs 25.96).

Every writer the function-wide completeness blockers count -- an unresolved
write of the memory SSA (``memory_graph.unresolved_write_nodes``) or an
unconditional unknown writer of a summary (``FunctionSummary.unknown_writers``,
uncertain writers included) -- is classified once from its RAW operation:

* RAM: a STORE whose space selector is a constant naming a program memory space
  (not the register, unique or constant space); a call effect's row
  (``<call>~...``) whose raw operation is a CALL / CALLIND / BRANCH /
  BRANCHIND -- the callee's unanchored memory write, by its producer;
* WILD: everything else -- a selector naming another space, a non-constant
  selector, a CALLOTHER or any other memory output, a raw StorageRef write.

A RAM writer's effect on a value is carried by the slice itself: a read it
may reach has a may-alias debt naming it, a definition it may overwrite is
refused by the state barrier. A WILD writer may reach storage the may-alias
analysis does not track (registers, temporaries): it keeps the function-wide
blocker. Either kind makes its function own ``control:<function>:memory-writes``
(``control_context``): the write may change where control goes.
"""

from __future__ import annotations

from ._scope_contracts import VarnodeKindCode

RAM = "ram"
WILD = "wild"
_CALL_OPCODES = frozenset({"CALL", "CALLIND", "BRANCH", "BRANCHIND"})


def memory_space_ids(scopes) -> frozenset:
    """The program's memory address spaces (a STORE selector naming one writes RAM)."""
    return frozenset(row.space_id for row in scopes.program.evidence.address_spaces
                     if row.is_memory_space and not row.is_register_space and not row.is_unique_space
                     and not row.is_constant_space)


def _operations(observation) -> dict:
    found = {}
    for row in observation.instructions:
        for ordinal, operation in enumerate(row.operations):
            found[(row.address.space_id, row.address.byte_offset, ordinal)] = operation
    return found


class WriterClasses:
    """``classify(operation key) -> RAM | WILD`` for one function (raw operations indexed once)."""

    def __init__(self, scopes, observation) -> None:
        self._spaces = memory_space_ids(scopes)
        self._operations = _operations(observation) if observation is not None else {}
        self._memo: dict = {}

    def classify(self, key: str) -> str:
        found = self._memo.get(key)
        if found is None:
            found = self._memo[key] = self._classify(key)
        return found

    def _classify(self, key: str) -> str:
        base, separator, _ = key.partition("~")
        try:
            space, offset, ordinal, opcode = base.split(":")
            operation = self._operations.get((int(space, 16), int(offset, 16), int(ordinal)))
        except ValueError:
            return WILD
        if operation is None or operation.opcode != opcode:
            return WILD
        if separator:
            return RAM if opcode in _CALL_OPCODES else WILD
        if opcode != "STORE" or not operation.inputs:
            return WILD
        selector = operation.inputs[0]
        if selector.kind is VarnodeKindCode.CONSTANT and selector.coordinate.byte_offset in self._spaces:
            return RAM
        return WILD


def unresolved_writers(normalized) -> tuple:
    """(operation key, graph node) of every unresolved write occurrence (SSA order)."""
    ssa = normalized.memory_ssa
    return tuple((ssa.actions[occurrence.action_id].operation_key, node)
                 for occurrence, node in zip(ssa.unresolved_writes, normalized.memory_graph.unresolved_write_nodes,
                                             strict=True))


def wild_write_nodes(normalized, observation) -> frozenset:
    """The unresolved-write nodes of WILD writers (the ones that still block completeness)."""
    classes = WriterClasses(normalized.scopes, observation)
    return frozenset(node for key, node in unresolved_writers(normalized) if classes.classify(key) == WILD)


__all__ = ("RAM", "WILD", "WriterClasses", "memory_space_ids", "unresolved_writers", "wild_write_nodes")
