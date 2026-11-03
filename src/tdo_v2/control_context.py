"""Control contexts of a run's published results (U2a, docs 25.93).

An UNKNOWN TRANSFER site is a BRANCHIND without flow targets -- the
predicate of the state barrier's incomplete successor graph
(``configured_state_barrier._BarrierFacts.complete``). Execution may resume
anywhere after one, in its function or, by unwinding, in a caller; so the
control context of a function is the set of site keys of its own sites and of
every function it may reach: direct calls and tails, every target Ghidra
lists, every target the run resolved for a call and every candidate of a
multi-target resolution (data-independent; cycles included by construction).
A function whose context cannot be computed -- it failed, or has no
observation -- contributes ``control:unavailable:<function>`` to itself and to
every caller (unavailable is not empty). Callees outside the analysed set and
unresolved indirect calls contribute no key: their continuation is UNKNOWN by
the opaque-callee rule, the call-state stage's, not this one's -- and so does
a terminal ``jmp [__imp_X]`` the engine recognizes as a jump through an import
slot (``import_call_sites``) under import-slots-hold-their-exports: a tail
call to an import, the transfer ``call [__imp_X]; ret`` makes (``exempt``,
recorded by the caller; r6).

A pure function of the final results: computed once at publication
(``summary_engine.report``) and by the template export; no analysis product
reads it.
"""

from __future__ import annotations

from .interprocedural import function_key


def site_key(entry: str, address) -> str:
    return f"control:{entry}:{address.space_id:x}:{address.byte_offset:x}"


def unavailable_key(entry: str) -> str:
    return f"control:unavailable:{entry}"


def unknown_transfer_sites(entry: str, observation) -> frozenset:
    """Site keys of the function's own unknown transfers."""
    if observation is None:
        return frozenset()
    return frozenset(
        site_key(entry, row.address) for row in observation.instructions
        if not row.flow_targets and any(operation.opcode == "BRANCHIND" for operation in row.operations)
    )


def import_tail_sites(entry: str, unit, image_info) -> frozenset:
    """Site keys of the function's terminal jumps through an import slot
    (``interprocedural.import_call_sites``: the recognizer that binds import
    models at that jump) -- for a run under import-slots-hold-their-exports."""
    from .interprocedural import import_call_sites

    if image_info is None or not unknown_transfer_sites(entry, getattr(unit, "observation", None)):
        return frozenset()   # (no candidate: no p-code graph built for the recognizer)
    found = set()
    for key in import_call_sites(unit, image_info):
        space, offset, _, opcode = key.split(":")
        if opcode == "BRANCHIND":
            found.add(f"control:{entry}:{space}:{offset}")
    return frozenset(found)


def _edges(entry: str, item, keys) -> set:
    observation = getattr(item.unit, "observation", None)
    found = set()
    if observation is not None:
        for row in observation.instructions:
            for target in row.flow_targets:
                key = function_key(target)
                if key in keys:
                    found.add(key)
            for operation in row.operations:
                if operation.opcode == "CALL" and operation.inputs:
                    key = function_key(operation.inputs[0].coordinate)
                    if key in keys:
                        found.add(key)
    found.update(key for key in item.calls.values() if key in keys)
    for members in (*item.multi_calls.values(), *getattr(item, "multi_candidates", {}).values()):
        found.update(key for key in members if key in keys)
    found.discard(entry)
    return found


def control_contexts(results, failed, exempt=frozenset()) -> dict:
    """{function key: frozenset(site keys)} over the published results
    (``analyze_units`` items) and the failure map (function key -> anything):
    own sites united with every reachable function's; ``exempt``: site keys
    that are no unknown transfer (``import_tail_sites``)."""
    keys = set(results) | set(failed)
    own, edges = {}, {}
    for key in keys:
        item = results.get(key)
        observation = None if item is None else getattr(item.unit, "observation", None)
        found = set(unknown_transfer_sites(key, observation)) - set(exempt)
        if key in failed or observation is None:
            found.add(unavailable_key(key))
        own[key] = found
        edges[key] = set() if item is None else _edges(key, item, keys)
    return _closure(own, edges)


def _closure(own: dict, edges: dict) -> dict:
    """Reachability union per node: strongly connected components (iterative
    Tarjan), each component's union after its successors' (O(nodes + edges))."""
    index, low, stack, on_stack, component = {}, {}, [], set(), {}
    order = []   # components, successors first
    counter = 0
    for root in sorted(own):
        if root in index:
            continue
        work = [(root, iter(sorted(edges[root])))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, successors = work[-1]
            advanced = False
            for successor in successors:
                if successor not in index:
                    index[successor] = low[successor] = counter
                    counter += 1
                    stack.append(successor)
                    on_stack.add(successor)
                    work.append((successor, iter(sorted(edges[successor]))))
                    advanced = True
                    break
                if successor in on_stack:
                    low[node] = min(low[node], index[successor])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                members = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    members.append(member)
                    if member == node:
                        break
                for member in members:
                    component[member] = len(order)
                order.append(members)
    sets = []
    for members in order:   # (every successor component is already done)
        found = set()
        for member in members:
            found |= own[member]
            for successor in edges[member]:
                other = component[successor]
                if other != len(sets):
                    found |= sets[other]
        sets.append(frozenset(found))
    return {key: sets[component[key]] for key in own}

__all__ = ("control_contexts", "import_tail_sites", "site_key", "unavailable_key", "unknown_transfer_sites")
