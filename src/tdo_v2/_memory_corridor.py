"""Bounded, write-free ORIGINAL CFG corridors shared by read proofs."""

from .model import StorageObjectKind
from .resource_limits import step


def write_free_corridor(index, source, target, dom, *, register_span=None):
    start, stop = index.locations[source], index.locations[target]
    if not dom._dominates(start, stop):
        return None
    if register_span is not None:
        source_action = index.memory[start].actions[index.keys[start].index(source)]
        if any(register_span.overlaps(span) for span in source_action.writes):
            return None  # The first operation reads BEFORE it writes.
    corridor, pending = {stop}, [stop]
    while pending:
        step()
        block = pending.pop()
        if block != start:
            for pred in index.predecessors[block] - corridor:
                corridor.add(pred)
                pending.append(pred)
                if len(corridor) > 128:
                    return None
    if start not in corridor:
        return None
    indegree = {b: len(index.predecessors[b] & corridor) for b in corridor}
    ready, seen, evidence = sorted(b for b, n in indegree.items() if not n), 0, []
    while ready:
        block = ready.pop()
        seen += 1
        keys = index.keys[block]
        lo = keys.index(source) + 1 if block == start else 0
        hi = keys.index(target) if block == stop else len(keys)
        if lo > hi:
            return None
        for action in index.memory[block].actions[lo:hi]:
            step()
            raw = index.raw.get(action.operation_key)
            modified = (any(register_span.overlaps(s) for s in action.writes) if register_span is not None
                        else bool(action.unresolved_writes) or any(s.object_id.kind not in (
                            StorageObjectKind.REGISTER_FILE, StorageObjectKind.FUNCTION_UNIQUE) for s in action.writes))
            if action.operation_key in index.excluded or modified or raw is None \
                    or raw.opcode in ("CALL", "CALLIND", "CALLOTHER") \
                    or register_span is None and raw.opcode == "STORE":
                return None
            evidence.append(action.operation_key)
        for successor in index.blocks[block].successors:
            if successor in indegree:
                indegree[successor] -= 1
                if not indegree[successor]:
                    ready.append(successor)
    return tuple(sorted(evidence)) if seen == len(corridor) else None
