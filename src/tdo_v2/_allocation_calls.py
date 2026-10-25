"""Caller-owned allocation/lifetime side facts across original physical ports.

This does not specialize a generic summary or claim that the CALL preserves
RAM. Only its lifecycle state transition is returned to the demanding query.
"""
from dataclasses import dataclass, replace

from .resource_limits import step
from .span_geometry import StorageObjectKind


@dataclass(frozen=True, slots=True)
class LifetimeCall:
    caller: str
    call: str
    callee: str
    context: tuple
    allocation: object
    input_states: tuple
    output_states: tuple
    ports: tuple
    evidence: object
    requires: tuple


def transfer_lifetime(parent, call, allocation, states):
    """One known nonrecursive call, all normal exits; otherwise no claim."""
    from ._allocation_lifetime import AllocationAnalysis, PointerFact, PointerTarget
    from ._call_activation import _policy
    from ._forward_memory import RefinementRefused
    from .observed_call_state import observed_call_state_projections
    key = call, allocation, tuple(sorted(states))
    if key in parent._call_states:
        return parent._call_states[key]
    target = parent.item.calls.get(call)
    callee = parent.results.get(target)
    if callee is None or target in parent.call_path or callee.summary is None \
            or callee.recursion_unresolved or callee.summary.tail_exits \
            or callee.unit.scopes.program != parent.item.unit.scopes.program \
            or parent.ops[call].opcode != "CALL" \
            or parent.readonly is not dict(callee.normalization_options).get("readonly_image"):
        return None
    shapes = [row for row in observed_call_state_projections(parent.item.unit.observation)
              if row.call_operation_key == call]
    if len(shapes) != 1 or shapes[0].memory_transition.displacement_delta != -8:
        return None
    # Independently reconstruct the CALL's input state, never the result of
    # this crossing. The original obligation guard refuses mutual recursion.
    tracked = PointerFact(targets=frozenset({PointerTarget(allocation)}), unknown=False,
                          requires=parent.requires)
    before = parent.lifetime(tracked, call)
    original_states = next((frozenset(values) for ref, values in before.states if ref == allocation), None)
    if original_states is None:
        return None
    initial = frozenset(states) | original_states
    try:
        with _policy(callee):
            child = AllocationAnalysis(callee, readonly_image=parent.readonly, results=parent.results,
                _parent=parent, _call=call, _entry_states=((allocation, initial),),
                _call_path=(*parent.call_path, target))
            ports = []
            # Only original full-width ENTRY read ports are demanded. Memory
            # ENTRY/partial/mixed reads are not silently seeded as pointers.
            for read in child.ssa.reads:
                step()
                if read.span.object_id.kind is not StorageObjectKind.REGISTER_FILE or read.span.size != 8 \
                        or len(read.fragments) != 1 or read.fragments[0].span != read.span \
                        or len(read.fragments[0].definition_ids) != 1:
                    continue
                identifier = read.fragments[0].definition_ids[0]
                from .memory_contracts import MemoryDefinitionKind
                if child.ssa.definitions[identifier].kind is not MemoryDefinitionKind.ENTRY:
                    continue
                fact = child.definition(identifier, read.span)
                if not fact.unknown and fact.targets:
                    ports.append((read.span, fact))
            evidence = child.lifetime(replace(tracked, requires=tracked.requires | frozenset(before.requires)), None)
    except RefinementRefused:
        return None
    final = next((values for ref, values in evidence.states if ref == allocation), ())
    if not final:
        final = ("unknown",)
    requires = tuple(sorted(set(evidence.requires) | set(before.requires)
                            | {label for _, fact in ports for label in fact.requires}))
    result = LifetimeCall(parent.item.key, call, target, child.context, allocation,
                          tuple(sorted(initial)), final, tuple(dict.fromkeys(ports)), evidence, requires)
    parent._call_states[key] = result
    return result
