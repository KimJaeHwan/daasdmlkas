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

Conditional summaries (U2b, docs 25.95): a function whose site context is
non-empty also gets ``continuation:<function>:*`` -- "every CALL / CALLIND in
the function and in every function it may reach returns to its observed next
instruction" -- the second condition every conditional claim rests on (a site
removed from a summary's exits exposes paths through opaque calls).
``site_reach`` is the static may-reach-a-site set that vetoes noreturn.
"""

from __future__ import annotations

from .interprocedural import function_key


def site_key(entry: str, address) -> str:
    return f"control:{entry}:{address.space_id:x}:{address.byte_offset:x}"


def unavailable_key(entry: str) -> str:
    return f"control:unavailable:{entry}"


def continuation_key(entry: str) -> str:
    return f"continuation:{entry}:*"


def continuation_owner(key: str) -> str | None:
    """The function of a ``continuation:<function>:*`` key (None: another key)."""
    if key.startswith("continuation:") and key.endswith(":*"):
        return key[len("continuation:"):-2]
    return None


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
    own sites united with every reachable function's, plus the function's
    ``continuation:<function>:*`` key when that is non-empty (U2b);
    ``exempt``: site keys that are no unknown transfer (``import_tail_sites``,
    discharged faults)."""
    own, edges = _graph(results, failed, exempt)
    return {key: keys | {continuation_key(key)} if keys else keys for key, keys in _closure(own, edges).items()}


def owner_reach(results, failed, owners) -> dict:
    """{function key: the functions of ``owners`` it may reach over the
    context edges, itself included} -- one closure (O(nodes + edges) set
    unions), for checking ``continuation:<P>:*`` scopes."""
    own, edges = _graph(results, failed, frozenset())
    owners = frozenset(owners)
    return _closure({key: {key} if key in owners else set() for key in own}, edges)


def _graph(results, failed, exempt) -> tuple[dict, dict]:
    keys = set(results) | set(failed)
    own, edges = {}, {}
    for key in keys:
        item = results.get(key)
        observation = None if item is None else getattr(item.unit, "observation", None)
        found = set(unknown_transfer_sites(key, observation)) - set(exempt)
        if key in failed or observation is None:
            found.add(unavailable_key(key))
        # (B', docs 25.96) every key its published summary rests on -- its
        # memory-writes site, vetoed-noreturn sites at its calls, unavailable /
        # model keys of its callees -- is its own: each reaches every ancestor
        summary = None if item is None else getattr(item, "summary", None)
        if summary is not None:
            found.update(site for site in summary.control_support if continuation_owner(site) is None)
        own[key] = found
        edges[key] = set() if item is None else _edges(key, item, keys)
    return own, edges


def memory_writer(unit, stack_registers=frozenset()) -> bool:
    """The function's own code writes memory (any STORE, any operation with a
    memory output) -- the static over-approximation of an unknown-address
    writer, decidable before any round (B', docs 25.96). Deliberately not
    syntactic about addresses: a register or temporary may be rewritten in
    part, at another offset, through another space; only the analysis decides
    where a write lands, and this predicate runs before it. It feeds the
    wildcard trigger of ``site_reach`` and D.3's cut veto only, where a wider
    set costs precision (a declined cut leaves a key), never soundness.
    ``stack_registers``: unused (kept for the callers)."""
    observation = getattr(unit, "observation", None)
    if observation is None:
        return True
    from ._scope_contracts import VarnodeKindCode

    return any(operation.opcode == "STORE"
               or operation.output is not None and operation.output.kind is VarnodeKindCode.ADDRESS
               for row in observation.instructions for operation in row.operations)


def static_writers(units: dict, models: dict, stack_registers=frozenset()) -> frozenset:
    """The static writers (B', docs 25.96), fixed before round 1: functions
    whose own code writes memory (``memory_writer``), that call a model
    (``models``: function key -> its model-bound calls; a model's memory
    effects are writes this function's call effects make), or that hold a
    wildcard transfer -- an indirect call or jump, a call outside ``units``:
    it may resolve to such a model in any later round, so its holder counts
    from the start and the set never changes between rounds. They trigger the
    wildcard reach of ``site_reach``; D.3 declines a cut in them."""
    from .fault_premise import observed_calls

    keys = frozenset(units)
    return frozenset(key for key, unit in units.items()
                     if memory_writer(unit, stack_registers) or models.get(key) or observed_calls(unit, keys)[1])


def site_reach(units: dict, exempt: dict, writers=frozenset()) -> frozenset:
    """The static may-reach-a-site set (U2b, docs 25.95), fixed before the
    first round: functions owning a site candidate that is not exempt
    (``exempt``: key -> import-tail site keys; a fault site counts whatever the
    fault premise discharges, its set only shrinks), every wildcard holder of
    the fault premise's observation graph (``fault_premise.observed_calls``:
    every CALLIND, every BRANCHIND -- an exempt import tail included --, every
    call outside ``units``, a function without observation) when any such
    owner exists, and every function reaching one of those over direct edges.
    No function in it is ever noreturn (``summary_noreturn``)."""
    from .fault_premise import observed_calls

    owners = {key for key, unit in units.items()
              if unknown_transfer_sites(key, getattr(unit, "observation", None)) - exempt.get(key, frozenset())}
    # (B', docs 25.96) a function with an unknown-address writer owns its key in
    # its summary's support, which every caller sees over a known edge before
    # its own summary (``summary_noreturn``); only the wildcard edges need this
    # static set -- triggered by a syntactic writer as by a site candidate
    if not owners and not writers:
        return frozenset()
    keys = frozenset(units)
    calls, wildcard = {}, set()
    for key, unit in units.items():
        calls[key], wild = observed_calls(unit, keys)
        if wild:
            wildcard.add(key)
    callers: dict = {}
    for caller, callees in calls.items():
        for callee in callees:
            callers.setdefault(callee, set()).add(caller)
    found = set(owners) | wildcard
    pending = list(found)
    while pending:
        node = pending.pop()
        for caller in callers.get(node, ()):
            if caller not in found:
                found.add(caller)
                pending.append(caller)
    return frozenset(found & keys)


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

__all__ = ("continuation_key", "continuation_owner", "control_contexts", "import_tail_sites", "memory_writer",
           "owner_reach",
           "site_key", "site_reach", "unavailable_key", "unknown_transfer_sites")
