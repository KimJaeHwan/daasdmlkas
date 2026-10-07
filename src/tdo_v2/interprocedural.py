"""Bottom-up interprocedural analysis over function summaries (S1a).

Functions are processed callees first (strongly connected components of the
direct-call graph in reverse topological order). Each function is
normalized with the proven effects of its direct calls to already-summarized
callees outside its own component (``call_summary_effects``), then
summarized from its own graph (``function_summary``), so nested calls
compose. Calls inside a component (recursion) and calls to unknown targets
stay opaque (call-clobber debt) -- design S5 handles recursion.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ._scope_contracts import VarnodeKindCode
from .call_seeds import _operation_key
from .call_summary_effects import ProvenCallEffect, derive_proven_call_effect
from .function_summary import FunctionSummary, summarize_function
from .model import ResolvedStorage
from .normalize import FunctionNormalizer, NormalizedFunction, _storage_ref
from .storage import _resolve_validated_storage


@dataclass
class AnalyzedFunction:
    key: str                                   # entry, "space:offset" hex
    unit: object
    normalized: object                         # NormalizedFunction | UnresolvedNormalizedFunction
    summary: FunctionSummary | None
    calls: dict[str, str] = field(default_factory=dict)          # call key -> callee key
    proven: dict[str, ProvenCallEffect] = field(default_factory=dict)


def function_key(coordinate) -> str:
    return f"{coordinate.space_id:x}:{coordinate.byte_offset:x}"


def analyze_units(units, *, assumed_call_effects=None) -> dict[str, AnalyzedFunction]:
    """``units``: ScopedFunctionUnit per function of one program.
    ``assumed_call_effects``: optional entry key -> TEST-ONLY declared effects."""
    from .call_clobber import _preserved_stack_pointers

    from ._scope_results import ConstructedFunctionScope

    functions = {
        function_key(unit.scopes.function.entry): unit for unit in units
        if type(unit.scopes.function) is ConstructedFunctionScope and unit.observation is not None
    }
    calls = {key: _direct_calls(unit, functions) for key, unit in functions.items()}
    order = _callee_first_components(calls)
    component_of = {key: index for index, component in enumerate(order) for key in component}
    results: dict[str, AnalyzedFunction] = {}
    for component in order:
        for key in sorted(component):
            unit = functions[key]
            observation = unit.observation
            context = unit.scopes.resolution_context
            proven = {}
            register_object, register_limit = _register_file(observation, context)
            if register_object is not None:
                stack_pointers = _preserved_stack_pointers(observation, context)
                for call_key, callee in calls[key].items():
                    done = results.get(callee)
                    if done is None or done.summary is None or component_of[callee] == component_of[key]:
                        continue
                    effect = derive_proven_call_effect(
                        done.summary, callee, register_object, register_limit,
                        excluded=tuple(stack_pointers.get(call_key, ())),
                    )
                    if effect is not None:
                        proven[call_key] = effect
            assumed = (assumed_call_effects or {}).get(key, {})
            proven = {call: effect for call, effect in proven.items() if call not in assumed}
            normalized = FunctionNormalizer().normalize(
                unit, assumed_call_effects=assumed, proven_call_effects=proven,
            )
            summary = (
                summarize_function(normalized, observation)
                if type(normalized) is NormalizedFunction else None
            )
            results[key] = AnalyzedFunction(key, unit, normalized, summary, calls[key], proven)
    return results


def _direct_calls(unit, functions) -> dict[str, str]:
    found = {}
    observation = unit.observation
    if observation is None:
        return found
    for instruction in observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            if operation.opcode != "CALL" or not operation.inputs:
                continue
            target = operation.inputs[0]
            if target.kind is not VarnodeKindCode.ADDRESS:
                continue
            callee = function_key(target.coordinate)
            if callee in functions:
                found[_operation_key(instruction.address, ordinal, operation.opcode)] = callee
    return found


def _callee_first_components(calls: dict[str, dict[str, str]]) -> list[set[str]]:
    """Tarjan SCCs of the call graph; each component after all its callees."""
    index, low, on_stack, stack, order = {}, {}, set(), [], []
    counter = 0
    for root in sorted(calls):
        if root in index:
            continue
        work = [(root, iter(sorted(set(calls[root].values()))))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, children = work[-1]
            advanced = False
            for child in children:
                if child not in index:
                    index[child] = low[child] = counter
                    counter += 1
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, iter(sorted(set(calls.get(child, {}).values())))))
                    advanced = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index[child])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
            if low[node] == index[node]:
                component = set()
                while True:
                    item = stack.pop()
                    on_stack.discard(item)
                    component.add(item)
                    if item == node:
                        break
                order.append(component)
    return order


def _register_file(observation, context):
    limit, object_id = 0, None
    for instruction in observation.instructions:
        for operation in instruction.operations:
            for varnode in (*operation.inputs, operation.output):
                if varnode is None or varnode.kind is not VarnodeKindCode.REGISTER:
                    continue
                limit = max(limit, varnode.coordinate.byte_offset + varnode.byte_size)
                if object_id is None:
                    resolved = _resolve_validated_storage(_storage_ref(varnode), context)
                    if type(resolved) is ResolvedStorage:
                        object_id = resolved.span.object_id
    return object_id, limit


__all__ = ("AnalyzedFunction", "analyze_units", "function_key")
