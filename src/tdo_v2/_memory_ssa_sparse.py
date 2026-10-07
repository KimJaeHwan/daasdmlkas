"""Sparse memory SSA engine (docs section 9): one value per atom class.

Same result as the dense engine (``memory_ssa._build_dense``), computed per
atom class (``_memory_ssa_classes``) on a sparse evaluation graph instead of
carrying the whole state through every block:

* A block that writes class c leaves it holding {last such write in the
  block}; any other block passes c through unchanged.
* phi points of c are the entry block and the iterated dominance frontier of
  the blocks writing c (Cytron et al.). The value at a phi is the ENTRY
  definition (entry block only) plus the union of its predecessors' exit
  values; phi values are solved to the least fixed point (loops).
* Any other point reads the value of its nearest dominating write or phi
  block (Choi, Cytron and Ferrante): a block's exit value of c is {last
  write} if it writes c, else the value at its nearest dominator-or-self in
  P = writes U phis; its entry value is the phi value if it is a phi of c,
  else the exit value of its nearest strict dominator in P.

Only the entry values a read or a terminal block needs are materialized;
reads replay their block's writes in action order, and fragments, JOINs and
terminal states are assembled by the shared ``memory_ssa._assemble``.
"""

from __future__ import annotations

from ._memory_ssa_classes import build_atom_classes
from ._sparse_dataflow import DominatorGraph
from ._memory_ssa_state import DefinitionSetPool, Run, make_state
from .memory_contracts import LocalMemorySsaResult, LocalMemoryUnit, MemoryDefinitionKind
from .model import ByteSpan


def build_sparse_local_memory_ssa(unit: LocalMemoryUnit) -> LocalMemorySsaResult:
    from .memory_ssa import _assemble, _build_partition, _raw_definitions

    if type(unit) is not LocalMemoryUnit:
        raise TypeError("local memory SSA requires an exact LocalMemoryUnit")
    partition = _build_partition(unit)
    raw_definitions = _raw_definitions(unit, partition.connected)
    write_ids = {
        (definition.operation_key, definition.write_ordinal): ordinal
        for ordinal, definition in enumerate(raw_definitions)
        if definition.operation_key is not None
    }
    writes_by_action: dict[str, list[int]] = {}
    for (operation_key, _), definition_id in write_ids.items():
        writes_by_action.setdefault(operation_key, []).append(definition_id)
    entry_of_connected = {
        index: next(
            ordinal for ordinal, definition in enumerate(raw_definitions)
            if definition.kind is MemoryDefinitionKind.ENTRY and definition.span == span
        )
        for index, span in enumerate(partition.connected)
    }
    classes = build_atom_classes(unit, partition, write_ids)
    class_of_atom = classes.class_of_atom
    blocks = {block.key: block for block in unit.blocks}
    graph = DominatorGraph(
        unit.entry_block_key, {block.key: block.predecessors for block in unit.blocks}
    )
    if len(graph.pre) != len(blocks):
        raise AssertionError("sparse memory SSA requires every block reachable")

    # what each action writes / reads, as classes
    def classes_in(span: ByteSpan) -> list[int]:
        start, stop = partition.covered_range(span)
        return sorted({class_of_atom[atom] for atom in range(start, stop)})

    action_writes: dict[str, list[tuple[int, list[int]]]] = {}  # op -> [(definition, classes)]
    last_write: dict[tuple[str, int], int] = {}                  # (block, class) -> definition
    written_in: list[set[str]] = [set() for _ in classes.classes]
    read_in: list[set[str]] = [set() for _ in classes.classes]
    for block in unit.blocks:
        for action in block.actions:
            for span in action.reads:
                for index in classes_in(span):
                    read_in[index].add(block.key)
            rows = []
            for ordinal, span in enumerate(action.writes):
                definition = write_ids[(action.operation_key, ordinal)]
                covered = classes_in(span)
                rows.append((definition, covered))
                for index in covered:
                    last_write[(block.key, index)] = definition
                    written_in[index].add(block.key)
            action_writes[action.operation_key] = rows

    terminals = tuple(unit.observed_terminal_block_keys)
    entry_values: dict[str, dict[int, frozenset]] = {key: {} for key in blocks}
    for index, atom_class in enumerate(classes.classes):
        entry = frozenset((entry_of_connected[atom_class.connected],))
        needed = read_in[index] | set(terminals)
        if not needed:
            continue
        values = graph.solve(
            written_in[index], needed,
            exit_of_write=lambda key, index=index: frozenset((last_write[(key, index)],)),
            entry_value=entry,
        )
        for key, value in values.items():
            entry_values[key][index] = value

    pool = DefinitionSetPool()
    interned: dict[frozenset, object] = {}

    def idset(value: frozenset):
        found = interned.get(value)
        if found is None:
            found = interned[value] = pool.intern(sorted(value))
        return found

    atoms = partition.atoms

    def fragments(start: int, stop: int, current: dict[int, frozenset], key: str):
        rows = []
        run_start, run_value = start, None
        for atom in range(start, stop):
            index = class_of_atom[atom]
            value = current.get(index)
            if value is None:
                value = entry_values[key][index]
            if run_value is not None and value != run_value:
                rows.append(_fragment(atoms, run_start, atom, idset(run_value)))
                run_start = atom
            run_value = value
        rows.append(_fragment(atoms, run_start, stop, idset(run_value)))
        return tuple(rows)

    def block_reads(block):
        current: dict[int, frozenset] = {}
        for action in block.actions:
            yield [
                fragments(*partition.covered_range(span), current, block.key)
                for span in action.reads
            ]
            for definition, covered in action_writes[action.operation_key]:
                value = frozenset((definition,))
                for index in covered:
                    current[index] = value

    terminal_out_states = {}
    for key in terminals:
        runs = []
        for atom in range(len(atoms)):
            index = class_of_atom[atom]
            definition = last_write.get((key, index))
            value = frozenset((definition,)) if definition is not None else entry_values[key][index]
            runs.append(Run(atom, atom + 1, idset(value)))
        terminal_out_states[key] = make_state(runs)

    return _assemble(
        unit, partition, raw_definitions, writes_by_action, blocks, block_reads,
        terminal_out_states,
    )


def _fragment(atoms, start: int, stop: int, definitions):
    first, last = atoms[start], atoms[stop - 1]
    return ByteSpan(first.object_id, first.start, last.end - first.start), definitions


__all__ = ("build_sparse_local_memory_ssa",)
