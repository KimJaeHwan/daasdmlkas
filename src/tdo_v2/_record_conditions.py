"""Conservative branch selection for records, using the existing CFG and SSA.

This module never solves reaching definitions. A simple diamond orders the
already recorded alternatives. General acyclic control traces those same
raw definitions through existing write boundaries, cross-checks captured SSA
predecessor evidence, and proves a disjoint, complete Boolean correspondence.
It changes no definition, origin, debt, summary or engine verdict. Unsupported
shapes retain an unordered phi.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from ._scope_contracts import VarnodeKindCode
from .call_seeds import _operation_key
from .memory_contracts import MemoryDefinitionKind
from .pcode_blocks import build_pcode_block_graph, instruction_key
from .resource_limits import step

_CALLS = frozenset({"CALL", "CALLIND", "CALLOTHER"})


@dataclass(frozen=True, slots=True)
class ConditionMatch:
    decision_key: str
    merge_key: str
    true_successor: str
    false_successor: str
    sources: tuple[int, int]  # the existing definition IDs, in true/false order
    branch_node: int
    branch_action_id: int


@dataclass(frozen=True, slots=True)
class GuardedSources:
    """Existing raw SSA definitions paired with shared CFG Boolean guards.

    Guards select a definition only when this read/exit is reached. They
    are not a feasibility proof, and never introduce a new definition.
    """

    sources: tuple[int, ...]
    guards: tuple[int, ...]
    reach: int


class _UnsupportedGuard(Exception):
    pass


@dataclass(frozen=True, slots=True)
class _Diamond:
    decision: str
    merge: str
    true_successor: str
    false_successor: str
    true_arm: tuple[str, ...]
    false_arm: tuple[str, ...]
    decision_key: str
    branch_node: int
    branch_action_id: int


class ConditionIndex:
    """One function's reusable record-only CFG/SSA correspondence.

    ``index`` is the existing ``lane_index``. The diamond methods return
    ``(ConditionMatch, None)`` or ``(None, fallback_reason)``. ``for_sources``
    also accepts summary-exit alternatives that have no materialized JOIN.
    ``guarded_join``/``guarded_sources`` return a GuardedSources instead.
    ``reach_guard`` separately identifies whether a raw operation or exit
    executes. All guard references share this index's bounded Boolean DAG.
    Resource failures propagate to the record builder's existing limits.
    """

    def __init__(self, normalized, unit, index):
        self.normalized, self.unit, self.index = normalized, unit, index
        self.ssa, self.graph = index.ssa, normalized.dependencies
        self._cache, self._joins, self._join_reads, self._debts, self._prefixes = {}, {}, {}, {}, {}
        self._by_read, self._paths, self._writes, self._issues = {}, {}, {}, {}
        self._reason = None
        self.guard_nodes = [False, True]
        self.decisions = {}
        self._guard_intern, self._guard_apply_cache = {}, {}
        self._reach, self._guarded = {}, {}
        step(len(unit.observation.instructions) + sum(len(row.operations) for row in unit.observation.instructions))
        self.instructions = {row.address: row for row in unit.observation.instructions}
        cfg = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
        self.entry = cfg.entry
        self.blocks = {block.key: block for block in cfg.blocks}
        if cfg.unsupported is not None or not self.blocks:
            self._reason = "unsupported cfg"
            return
        self.predecessors = {key: set() for key in self.blocks}
        for block in cfg.blocks:
            step()
            for target in block.successors:
                step()
                self.predecessors[target].add(block.key)
        indegree = {key: len(value) for key, value in self.predecessors.items()}
        pending = deque(key for key, count in indegree.items() if count == 0)
        visited = 0
        self.order = []
        while pending:
            step()
            key = pending.popleft()
            self.order.append(key)
            visited += 1
            for target in self.blocks[key].successors:
                step()
                indegree[target] -= 1
                if indegree[target] == 0:
                    pending.append(target)
        if visited != len(self.blocks):
            self._reason = "cyclic cfg"
            return

        memory = {block.key: block for block in normalized.memory_unit.blocks}
        if memory.keys() != self.blocks.keys() or any(
            set(memory[key].predecessors) != self.predecessors[key] for key in self.blocks
        ):
            self._reason = "cfg/ssa blocks differ"
            return
        self.actions = {action.operation_key: action_id for action_id, action in enumerate(self.ssa.actions)}
        unresolved = {item.action_id for item in (*self.ssa.unresolved_reads, *self.ssa.unresolved_writes)}
        self._locations = {}
        for key, block in memory.items():
            step()
            writes = self._writes[key] = {}
            for position, action in enumerate(block.actions):
                step()
                self._locations[action.operation_key] = (key, position)
                action_id = self.actions.get(action.operation_key)
                if action_id is None:
                    self._reason = "missing ssa action"
                    return
                raw = index.operation(action_id)
                if raw is not None and raw[0].opcode in _CALLS:
                    self._issues.setdefault(key, []).append((position, "call on path"))
                if action_id in unresolved or action.unresolved_reads or action.unresolved_writes:
                    self._issues.setdefault(key, []).append((position, "unresolved access on path"))
                for definition_id in self.ssa.actions[action_id].write_definition_ids:
                    definition = self.ssa.definitions[definition_id]
                    writes.setdefault(definition.span.object_id, []).append((position, definition_id))

        for read in self.ssa.reads:
            step()
            operation = self.ssa.actions[read.action_id].operation_key
            location = self._locations[operation]
            for fragment in read.fragments:
                step()
                for definition_id in fragment.definition_ids:
                    if definition_id in index.joins:
                        old = self._join_reads.get(definition_id)
                        if old is None or location[1] < self._locations[old][1]:
                            self._join_reads[definition_id] = operation

        # Resolve p-code ordinals once; successor tuple order conveys no polarity.
        self._segments = {(block.instruction, ordinal): block.key for block in cfg.blocks
                          for ordinal in range(block.start, block.stop)}
        self._raw_blocks = {
            _operation_key(row.address, ordinal, row.operations[ordinal].opcode): key
            for (address, ordinal), key in self._segments.items()
            for row in (self.instructions[address],)
        }
        for block in cfg.blocks:
            step()
            row = self.instructions[block.instruction]
            if not block.stop or row.operations[block.stop - 1].opcode != "CBRANCH":
                continue
            diamond = self._diamond(block)
            if diamond is None:
                continue
            path, key = [], diamond.merge
            while key is not None:
                step()
                path.append(key)
                self._by_read.setdefault(key, []).append((diamond, len(path)))
                successors = self.blocks[key].successors
                key = successors[0] if len(successors) == 1 and len(self.predecessors[successors[0]]) == 1 \
                    and self._straight(self.blocks[key]) else None
            self._paths[diamond.decision] = tuple(path)

    # General acyclic control correspondence. The original diamond matcher
    # remains the compact, backwards-compatible fast path above. Boolean
    # nodes are hash-consed ordered decisions, not enumerated CFG paths.
    def _guard_node(self, decision, yes, no):
        if yes == no:
            return yes
        key = decision, yes, no
        if key not in self._guard_intern:
            step()
            if len(self.guard_nodes) >= 4096:
                raise _UnsupportedGuard("control DAG limit")
            self._guard_intern[key] = len(self.guard_nodes)
            self.guard_nodes.append(key)
        return self._guard_intern[key]

    def _boolean(self, opcode, left, right):
        if left > right:
            left, right = right, left
        key = opcode, left, right
        if key in self._guard_apply_cache:
            return self._guard_apply_cache[key]
        step()
        if left == right:
            return left
        if opcode == "and":
            if left == 0:
                return 0
            if left == 1:
                return right
        else:
            if left == 0:
                return right
            if left == 1:
                return 1
        a, b = self.guard_nodes[left], self.guard_nodes[right]
        decision = min((a[0], b[0]), key=self._decision_rank.__getitem__)
        ay, an = a[1:] if a[0] == decision else (left, left)
        by, bn = b[1:] if b[0] == decision else (right, right)
        result = self._guard_node(decision, self._boolean(opcode, ay, by), self._boolean(opcode, an, bn))
        self._guard_apply_cache[key] = result
        return result

    def _control(self):
        if self._reach or self._reason is not None:
            return
        from .control_dependence import _immediate_postdominators, _EXIT

        successors = {key: (*block.successors, _EXIT) if block.exits or not block.successors
                      else block.successors for key, block in self.blocks.items()}
        successors[_EXIT] = ()
        post = _immediate_postdominators(successors)
        self._decision_rank, self._edge_guards = {}, {}
        try:
            for rank, key in enumerate(self.order):
                step()
                block = self.blocks[key]
                row = self.instructions[block.instruction]
                operation = row.operations[block.stop - 1] if block.stop else None
                if operation is not None and operation.opcode == "CBRANCH":
                    if len(operation.inputs) != 2:
                        raise _UnsupportedGuard("invalid cbranch")
                    true, false = self._target(block, operation), self._fallthrough(block)
                    if (true is None or false is None or true == false or block.exits
                            or set(block.successors) != {true, false}):
                        raise _UnsupportedGuard("cfg branch targets differ")
                    decision = _operation_key(row.address, block.stop - 1, operation.opcode)
                    node, action = self.graph.node_for_key(f"op:{decision}"), self.actions.get(decision)
                    if node is None or action is None:
                        raise _UnsupportedGuard("missing branch action")
                    self.decisions[decision] = ConditionMatch(decision, post[key] or _EXIT, true, false,
                                                               (), node, action)
                    self._decision_rank[decision] = rank
                    self._edge_guards[key, true] = self._guard_node(decision, 1, 0)
                    self._edge_guards[key, false] = self._guard_node(decision, 0, 1)
                elif block.successors:
                    if not self._straight(block):
                        raise _UnsupportedGuard("unsupported control transfer")
                    self._edge_guards[key, block.successors[0]] = 1
            for key in self.order:
                value = int(key == self.entry)
                for previous in sorted(self.predecessors[key]):
                    value = self._boolean("or", value, self._boolean(
                        "and", self._reach[previous], self._edge_guards[previous, key]))
                self._reach[key] = value
        except (RecursionError, _UnsupportedGuard) as error:
            self._reason = str(error) if not isinstance(error, RecursionError) else "control DAG depth"
            self._reach.clear()

    def reach_guard(self, operation_or_block):
        """Guard for executing an observed operation/block, not its value.

        A caller must evaluate the original decision operands or explicitly
        retain uncertainty. A guard reference alone is no feasibility proof.
        """
        self._control()
        if self._reason is not None:
            return None, self._reason
        key = self._locations[operation_or_block][0] if operation_or_block in self._locations \
            else self._raw_blocks.get(operation_or_block, operation_or_block)
        return (self._reach[key], None) if key in self._reach else (None, "unknown control location")

    def guard_decisions(self, references):
        pending, found, seen = list(references), set(), set()
        while pending:
            reference = pending.pop()
            if reference in seen or reference < 2:
                continue
            seen.add(reference)
            decision, yes, no = self.guard_nodes[reference]
            found.add(decision)
            pending.extend((yes, no))
        return tuple(self.decisions[key] for key in sorted(found))

    def guarded_join(self, definition_id):
        definition = self.ssa.definitions[definition_id]
        return self.guarded_sources(definition.span, self.index.joins.get(definition_id, ()),
                                    definition.block_key, self._join_reads.get(definition_id))

    def guarded_sources(self, span, source_ids, read_block, read_operation=None):
        """Attach edge guards to the raw alternatives already chosen by SSA.

        We trace only these definitions, checking the SSA's predecessor
        evidence at merges and its existing ordered write boundaries. This
        does not solve a second reaching-definition problem or change SSA.
        """
        self._control()
        if self._reason is not None:
            return None, self._reason
        sources = tuple(source_ids)
        cache = span, sources, read_block, read_operation
        if cache in self._guarded:
            return self._guarded[cache]
        try:
            if not sources or any(not 0 <= source < len(self.ssa.definitions) for source in sources):
                raise _UnsupportedGuard("unknown definition")
            if any(self.ssa.definitions[source].kind not in (MemoryDefinitionKind.ENTRY, MemoryDefinitionKind.DATA_WRITE)
                   or not self.ssa.definitions[source].span.contains(span) for source in sources):
                raise _UnsupportedGuard("unsupported source")
            before = self._locations.get(read_operation) if read_operation is not None else None
            if read_operation is not None and (before is None or before[0] != read_block):
                raise _UnsupportedGuard("read operation is not in block")
            if read_block not in self.blocks:
                raise _UnsupportedGuard("unknown control location")
            evidence = getattr(self.ssa, "flow_edges", ())
            memo = {}

            def trace(source, key, stop=None):
                identity = source, key, stop
                if identity in memo:
                    return memo[identity]
                step()
                # This is a correspondence over SSA's value definitions,
                # not removal of a call/alias debt. A call on another path
                # need not discard a known later register definition. Any
                # actual KILL, partial write, debt or unresolved operand is
                # still retained by the original SSA/value record.
                last = None
                for position, identifier in self._writes[key].get(span.object_id, ()):
                    if stop is not None and position >= stop:
                        break
                    if self.ssa.definitions[identifier].span.overlaps(span):
                        last = identifier
                if last is not None:
                    definition = self.ssa.definitions[last]
                    if definition.kind is not MemoryDefinitionKind.DATA_WRITE:
                        raise _UnsupportedGuard("killed source")
                    if not definition.span.contains(span):
                        raise _UnsupportedGuard("partial last write")
                if last is not None:
                    result = self._reach[key] if last == source else 0
                elif key == self.entry:
                    definition = self.ssa.definitions[source]
                    result = int(definition.kind is MemoryDefinitionKind.ENTRY and definition.block_key == self.entry)
                else:
                    result = 0
                    for predecessor in sorted(self.predecessors[key]):
                        # Captured by the ORIGINAL SSA fixed point. No
                        # replacement source may be invented at a merge.
                        rows = [row for row in evidence if row.block_key == key
                                and row.predecessor_key == predecessor and row.span.overlaps(span)]
                        if rows and any(source not in row.definition_ids for row in rows):
                            continue
                        result = self._boolean("or", result, self._boolean(
                            "and", self._edge_guards[predecessor, key], trace(source, predecessor)))
                memo[identity] = result
                return result

            guards = tuple(trace(source, read_block, before[1] if before else None) for source in sources)
            reach = self._reach[read_block]
            union = 0
            for guard in guards:
                if guard == 0:
                    raise _UnsupportedGuard("source mismatch")
                if self._boolean("and", union, guard) != 0:
                    raise _UnsupportedGuard("overlapping source guards")
                union = self._boolean("or", union, guard)
            if union != reach:
                raise _UnsupportedGuard("incomplete source guards")
            result = GuardedSources(sources, guards, reach), None
        except (RecursionError, _UnsupportedGuard) as error:
            result = None, str(error) if not isinstance(error, RecursionError) else "control DAG depth"
        self._guarded[cache] = result
        return result

    def for_join(self, definition_id):
        if definition_id not in self._joins:
            step()
            if not 0 <= definition_id < len(self.ssa.definitions):
                found = None, "unknown definition"
            else:
                definition = self.ssa.definitions[definition_id]
                found = (None, "not a join") if definition.kind is not MemoryDefinitionKind.JOIN else self.for_sources(
                    definition.span, self.index.joins.get(definition_id, ()), definition.block_key,
                    read_operation_key=self._join_reads.get(definition_id),
                )
            self._joins[definition_id] = found
        return self._joins[definition_id]

    def for_sources(self, span, source_ids, read_block_key, read_operation_key=None):
        """Match alternatives at a block exit, or immediately before one
        existing read operation. A same-operation write follows its reads;
        ``for_join`` supplies that boundary from the SSA's read fragments."""
        sources = frozenset(source_ids)
        key = span, sources, read_block_key, read_operation_key
        if key not in self._cache:
            step()
            self._cache[key] = self._find(span, sources, read_block_key, read_operation_key)
        return self._cache[key]

    def _find(self, span, sources, read_block, read_operation):
        if self._reason is not None:
            return None, self._reason
        if len(sources) != 2 or any(not 0 <= source < len(self.ssa.definitions) for source in sources):
            return None, "source set is not two definitions"
        if any(self.ssa.definitions[source].kind not in (MemoryDefinitionKind.ENTRY, MemoryDefinitionKind.DATA_WRITE)
               or not self.ssa.definitions[source].span.contains(span) for source in sources):
            return None, "unsupported source"
        before = None
        if read_operation is not None:
            before = self._locations.get(read_operation)
            if before is None or before[0] != read_block:
                return None, "read operation is not in block"
        candidates = self._by_read.get(read_block, ())
        matches, reason = [], "no simple diamond"
        for diamond, stop in candidates:
            step()
            suffix = self._paths[diamond.decision][:stop]
            match, why = self._match(diamond, suffix, span, sources, before)
            if match is not None:
                matches.append(match)
            else:
                reason = why
        return (matches[0], None) if len(matches) == 1 else (None, "ambiguous diamond" if matches else reason)

    def _match(self, diamond, suffix, span, sources, before):
        if self._debt(diamond.branch_node):
            return None, "condition debt"
        last, issue = self._last_write(suffix, span, before)
        if issue is not None:
            return None, issue
        if last is not None:
            return None, "write after merge"
        selected = []
        for arm in (diamond.true_arm, diamond.false_arm):
            source, issue = self._last_write(arm, span)
            if issue is not None:
                return None, issue
            if source is None:
                prefix = self._prefix(diamond.decision)
                if prefix is None:
                    return None, "no straight entry prefix"
                source, issue = self._last_write(prefix, span)
                if issue is not None:
                    return None, issue
                if source is None:
                    entries = [item for item in sources if self.ssa.definitions[item].kind is MemoryDefinitionKind.ENTRY
                               and self.ssa.definitions[item].block_key == self.entry]
                    if len(entries) != 1:
                        return None, "no proven entry source"
                    source = entries[0]
            if source not in sources:
                return None, "source mismatch"
            definition = self.ssa.definitions[source]
            if definition.kind is MemoryDefinitionKind.DATA_WRITE:
                action = self.actions.get(definition.operation_key)
                if action is None or self._debt(self.index.definition_node[source]):
                    return None, "source debt"
            selected.append(source)
        if frozenset(selected) != sources:
            return None, "source mismatch"
        return ConditionMatch(diamond.decision_key, diamond.merge, diamond.true_successor,
                              diamond.false_successor, tuple(selected), diamond.branch_node,
                              diamond.branch_action_id), None

    def _last_write(self, path, span, before=None):
        last = None
        for key in path:
            step()
            stop = before[1] if before is not None and before[0] == key else None
            for position, issue in self._issues.get(key, ()):
                if stop is None or position < stop:
                    return None, issue
            for position, definition_id in self._writes[key].get(span.object_id, ()):
                step()
                if stop is not None and position >= stop:
                    break
                definition = self.ssa.definitions[definition_id]
                if definition.span.overlaps(span):
                    last = definition_id
        if last is not None:
            definition = self.ssa.definitions[last]
            if definition.kind is not MemoryDefinitionKind.DATA_WRITE:
                return None, "killed source"
            if not definition.span.contains(span):
                return None, "partial last write"
        return last, None

    def _prefix(self, decision):
        if decision not in self._prefixes:
            path, key = [], self.entry
            while True:
                step()
                path.append(key)
                if key == decision:
                    self._prefixes[decision] = tuple(path)
                    break
                block = self.blocks[key]
                if not self._straight(block) \
                        or self.predecessors[block.successors[0]] != {key}:
                    self._prefixes[decision] = None
                    break
                key = block.successors[0]
        return self._prefixes[decision]

    def _debt(self, node):
        if node not in self._debts:
            from .graph_contracts import NodeKind

            # Reuse the dependency graph's budgeted data-only reachability;
            # no record-specific reaching-definition analysis is introduced.
            self._debts[node] = any(self.graph.node(item).kind is NodeKind.MEMORY_DEBT
                                    for item in self.graph.backward_reachable((node,)))
        return self._debts[node]

    def _target(self, block, operation):
        if not operation.inputs:
            return None
        destination = operation.inputs[0]
        if destination.kind is VarnodeKindCode.CONSTANT:
            bits = 8 * destination.byte_size
            delta = destination.coordinate.byte_offset
            if delta & (1 << (bits - 1)):
                delta -= 1 << bits
            ordinal = block.stop - 1 + delta
            row = self.instructions[block.instruction]
            if ordinal == len(row.operations):
                # A relative target at the operation-count boundary leaves
                # the instruction, even when this branch ends an earlier
                # segment. Its false edge may instead enter that segment.
                return instruction_key(row.fallthrough) if row.fallthrough in self.instructions else None
            return self._segments.get((block.instruction, ordinal))
        return instruction_key(destination.coordinate) if destination.coordinate in self.instructions else None

    def _fallthrough(self, block):
        row = self.instructions[block.instruction]
        if block.stop < len(row.operations):
            return self._segments.get((block.instruction, block.stop))
        return instruction_key(row.fallthrough) if row.fallthrough in self.instructions else None

    def _straight(self, block):
        if block.exits or len(block.successors) != 1:
            return False
        row = self.instructions[block.instruction]
        last = row.operations[block.stop - 1] if block.stop else None
        if last is not None and last.opcode == "BRANCH":
            target = self._target(block, last)
        elif last is not None and last.opcode in ("CBRANCH", "BRANCHIND", "RETURN"):
            return False
        else:
            target = self._fallthrough(block)
        return target is not None and set(block.successors) == {target}

    def _arm(self, first, decision):
        path, key, previous = [], first, decision
        while self.predecessors[key] == {previous}:
            step()
            block = self.blocks[key]
            if not self._straight(block):
                return None
            path.append(key)
            previous, key = key, block.successors[0]
        return key, tuple(path), previous

    def _diamond(self, block):
        if block.exits or len(block.successors) != 2:
            return None
        row = self.instructions[block.instruction]
        operation = row.operations[block.stop - 1]
        if len(operation.inputs) != 2:
            return None
        true, false = self._target(block, operation), self._fallthrough(block)
        if true is None or false is None or true == false or set(block.successors) != {true, false}:
            return None
        left, right = self._arm(true, block.key), self._arm(false, block.key)
        if left is None or right is None or left[0] != right[0] or left[2] == right[2]:
            return None
        merge = left[0]
        if self.predecessors[merge] != {left[2], right[2]}:
            return None
        key = _operation_key(row.address, block.stop - 1, operation.opcode)
        node, action = self.graph.node_for_key(f"op:{key}"), self.actions.get(key)
        if node is None or action is None:
            return None
        return _Diamond(block.key, merge, true, false, left[1], right[1], key, node, action)


__all__ = ("ConditionIndex", "ConditionMatch", "GuardedSources")
