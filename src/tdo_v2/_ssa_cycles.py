"""Shared original-CFG/SSA structure; no execution or dataflow solve.

The expression-cycle view and occurrence-aware memory families use this same
budgeted finite index. Original edges and predecessor definition sets survive.
"""

from .call_seeds import _operation_key
from .pcode_blocks import build_pcode_block_graph
from .resource_limits import step


class SsaCycleIndex:
    def __init__(self, memory, ssa, observation, entry, *, include_flow=True):
        self.ssa = ssa
        self.instructions = {row.address: row for row in observation.instructions}
        step(len(self.instructions) + sum(len(row.operations) for row in self.instructions.values()))
        self.cfg = build_pcode_block_graph(observation, entry)
        self.blocks = {block.key: block for block in self.cfg.blocks}
        self.predecessors = {key: set() for key in self.blocks}
        self.raw, self.locations, self._segments = {}, {}, {}
        for block in self.cfg.blocks:
            step(1 + len(block.successors) + block.stop - block.start)
            for successor in block.successors:
                self.predecessors[successor].add(block.key)
            row = self.instructions[block.instruction]
            for ordinal in range(block.start, block.stop):
                operation = row.operations[ordinal]
                key = _operation_key(row.address, ordinal, operation.opcode)
                self.raw[key] = operation
                self.locations[key] = block.key
                self._segments[block.instruction, ordinal] = block.key
        self.components = tuple(self.sccs(frozenset(self.blocks)))
        self.cyclic = tuple(component for component in self.components if self.is_cyclic(component))
        self.ssa_matches = bool(memory is not None and memory.entry_block_key == self.cfg.entry
                                and {block.key for block in memory.blocks} == set(self.blocks))
        if self.ssa_matches:
            for block in memory.blocks:
                step(1 + len(block.predecessors))
                if set(block.predecessors) != self.predecessors[block.key]:
                    self.ssa_matches = False
                    break
        self.flow_by_edge = {}
        for flow in self.ssa.flow_edges if include_flow else ():
            step()
            self.flow_by_edge.setdefault((flow.predecessor_key, flow.block_key), []).append(flow)

    def is_cyclic(self, component):
        return len(component) > 1 or bool(component and component[0] in self.blocks[component[0]].successors)

    def sccs(self, members):
        """Iterative SCC walk on an induced subgraph, charged to work budget."""
        seen, order = set(), []
        for start in sorted(members):
            if start in seen:
                continue
            seen.add(start)
            stack = [(start, iter(self.blocks[start].successors))]
            while stack:
                step()
                key, targets = stack[-1]
                for target in targets:
                    step()
                    if target in members and target not in seen:
                        seen.add(target)
                        stack.append((target, iter(self.blocks[target].successors)))
                        break
                else:
                    order.append(key)
                    stack.pop()
        assigned = set()
        for start in reversed(order):
            if start in assigned:
                continue
            component, pending = [], [start]
            while pending:
                step()
                key = pending.pop()
                if key in assigned:
                    continue
                step(len(self.predecessors[key]))
                assigned.add(key)
                component.append(key)
                pending.extend(sorted((self.predecessors[key] & members) - assigned, reverse=True))
            yield tuple(sorted(component))
