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
from .observed_call_state import observed_call_state_projections
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
    # FUNCTION_RELATIVE object -> (entry register span it is addressed from, space)
    anchors: dict = field(default_factory=dict)
    # graph node -> source labels it carries (declared or bound sources, and
    # summarized calls whose runs reach a source inside the callee)
    origins: dict = field(default_factory=dict)
    # sink roots projected from callees: (call key, demand index, label, root
    # nodes, complete) -- the function's own roots come from ``sink_roots``
    projected_sinks: list = field(default_factory=list)


def function_key(coordinate) -> str:
    return f"{coordinate.space_id:x}:{coordinate.byte_offset:x}"


def analyze_units(units, *, assumed_call_effects=None, extra_origins=None,
                  assume_globals_disjoint_from_stack=False, sink_roots=None) -> dict[str, AnalyzedFunction]:
    """``units``: ScopedFunctionUnit per function of one program.
    ``assumed_call_effects``: optional entry key -> TEST-ONLY declared effects.
    ``extra_origins(key, unit, normalized, calls)``: graph node -> source labels
    of the function's own boundaries (e.g. declared sources, calls to a source
    function); summarized runs that reach sources add theirs automatically.
    ``assume_globals_disjoint_from_stack``: the named opt-in assumption of
    ``may_alias``, applied only when ``program_switches_stack`` finds no
    function of the program loading its stack pointer from elsewhere.
    ``sink_roots(key, unit, normalized)``: (label, root nodes, bound) per sink
    root of the function's own boundaries. Each root, and each sink root
    projected from a summarized callee (``~sink<k>`` call effects), becomes a
    ``SinkDemand`` of the function's summary, so wrappers compose bottom-up."""
    from .call_clobber import _preserved_stack_pointers

    from ._scope_results import ConstructedFunctionScope

    functions = {
        function_key(unit.scopes.function.entry): unit for unit in units
        if type(unit.scopes.function) is ConstructedFunctionScope and unit.observation is not None
    }
    calls = {key: _direct_calls(unit, functions) for key, unit in functions.items()}
    if assume_globals_disjoint_from_stack and program_switches_stack(functions.values()):
        assume_globals_disjoint_from_stack = False
    files = [_register_file(unit.observation, unit.scopes.resolution_context) for unit in functions.values()]
    program_registers = (
        next((object_id for object_id, _ in files if object_id is not None), None),
        max((limit for _, limit in files), default=0),
    )
    # the program's stack pointer (the call shapes' base register), for tail jumps
    program_stack = {
        span for unit in functions.values()
        for spans in _preserved_stack_pointers(unit.observation, unit.scopes.resolution_context).values()
        for span in spans
    }

    def analyze(calls):
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
                if register_object is None:  # e.g. a thunk that is a lone tail jump
                    register_object, register_limit = program_registers
                if register_object is not None:
                    stack_pointers = _preserved_stack_pointers(observation, context)
                    shapes = {
                        row.call_operation_key: {
                            (row.memory_transition.caller_base.byte_offset,
                             row.memory_transition.caller_base.byte_size):
                            row.memory_transition.displacement_delta,
                        }
                        for row in observed_call_state_projections(observation)
                    }
                    for call_key, callee in calls[key].items():
                        done = results.get(callee)
                        if done is None or done.summary is None or component_of[callee] == component_of[key]:
                            continue
                        tail = call_key.endswith(":BRANCH")
                        if tail and len(program_stack) != 1:
                            continue  # no single stack pointer to compose through
                        effect = derive_proven_call_effect(
                            done.summary, callee, register_object, register_limit,
                            excluded=tuple(program_stack) if tail else tuple(stack_pointers.get(call_key, ())),
                            anchors=done.anchors,
                            stack_deltas=shapes.get(call_key, {}),
                            tail=tail,
                        )
                        if effect is not None:
                            proven[call_key] = effect
                assumed = (assumed_call_effects or {}).get(key, {})
                proven = {call: effect for call, effect in proven.items() if call not in assumed}
                normalized = FunctionNormalizer().normalize(
                    unit, assumed_call_effects=assumed, proven_call_effects=proven,
                    assume_globals_disjoint_from_stack=assume_globals_disjoint_from_stack,
                )
                origins: dict = {}
                projected: list = []
                roots: list = []
                if type(normalized) is NormalizedFunction:
                    origins = _run_origins(normalized)
                    for node, labels in (extra_origins(key, unit, normalized, calls[key]) if extra_origins else {}).items():
                        origins.setdefault(node, set()).update(labels)
                    roots = list(sink_roots(key, unit, normalized)) if sink_roots else []
                    for call, effect in normalized.proven_call_effects:
                        for index, demand in enumerate(effect.sink_demands):
                            nodes = run_definition_nodes(normalized, f"{call}~sink{index}")
                            for node in nodes:  # labels reached inside the callee
                                if demand.origins:
                                    origins.setdefault(node, set()).update(demand.origins)
                            projected.append((call, index, demand.label, nodes, demand.complete))
                            roots.append((demand.label, nodes, demand.complete))
                summary = (
                    summarize_function(normalized, observation, origins, roots)
                    if type(normalized) is NormalizedFunction else None
                )
                anchors = _relative_anchors(unit, normalized) if summary is not None else {}
                results[key] = AnalyzedFunction(key, unit, normalized, summary, calls[key], proven,
                                                anchors, origins, projected)
        return results

    # indirect calls with a provably constant target (a Bundle function): resolved
    # on the analyzed graphs, then analyzed as direct calls; repeat until the
    # resolved set is stable (each round re-checks every resolution)
    resolved: dict = {}
    for _ in range(1 + sum(1 for unit in functions.values() for _ in _callind_sites(unit))):
        results = analyze({key: {**calls[key], **resolved.get(key, {})} for key in calls})
        found = {
            key: targets for key, item in results.items()
            if (targets := _indirect_targets(item, functions))
        }
        if found == resolved:
            return results
        resolved = found
    return analyze(calls)  # not stable: no indirect resolution at all


def program_switches_stack(units) -> dict[str, tuple[str, ...]]:
    """Entry key -> operations that set the stack pointer to a value not
    derived from it (a stack switch: fibers, coroutines); empty for ordinary
    programs. A switching program may run on a stack in static data, so the
    globals-vs-stack assumption is withdrawn for all of it."""
    from .may_alias import _unit_stub, stack_switches

    found = {}
    for unit in units:
        program = unit.scopes.program
        rows = stack_switches(
            _unit_stub(unit.scopes), unit.observation, unit.scopes.resolution_context,
            program.evidence.address_spaces,
        )
        if rows:
            found[function_key(unit.scopes.function.entry)] = rows
    return found


def _direct_calls(unit, functions) -> dict[str, str]:
    found = {}
    observation = unit.observation
    if observation is None:
        return found
    for instruction in observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            tail = (  # an unconditional tail jump: the last operation of a terminal instruction
                operation.opcode == "BRANCH" and instruction.flow.is_terminal
                and ordinal == len(instruction.operations) - 1
            )
            if (operation.opcode != "CALL" and not tail) or not operation.inputs:
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


def _callind_sites(unit):
    """(CALLIND key, COPY key, register varnode) for Ghidra's ``call r`` shape
    ``COPY t <- r; ...; CALLIND t`` inside one instruction."""
    for instruction in unit.observation.instructions:
        operations = instruction.operations
        for ordinal, operation in enumerate(operations):
            if operation.opcode != "CALLIND" or not operation.inputs:
                continue
            for index in range(ordinal):
                copy = operations[index]
                if copy.opcode == "COPY" and copy.output == operation.inputs[0] \
                        and copy.inputs[0].kind is VarnodeKindCode.REGISTER:
                    yield (_operation_key(instruction.address, ordinal, "CALLIND"),
                           _operation_key(instruction.address, index, "COPY"), copy.inputs[0])


def _indirect_targets(item, functions) -> dict[str, str]:
    """CALLIND key -> Bundle function the call provably reaches: the target
    register's value at the call is a constant address (address-expression
    evaluator) of a function entry, and its backward slice reaches no debt."""
    from .graph_contracts import NodeKind
    from .relative_memory import constant_values

    normalized = item.normalized
    if type(normalized) is not NormalizedFunction:
        return {}
    sites = list(_callind_sites(item.unit))
    if not sites:
        return {}
    graph = normalized.dependencies
    values = constant_values(normalized, item.unit.observation, [(copy, varnode) for _, copy, varnode in sites])
    space = item.unit.scopes.function.entry.space_id
    found = {}
    for call, copy, varnode in sites:
        value = values.get((copy, varnode))
        callee = None if value is None else f"{space:x}:{value:x}"
        if callee not in functions:
            continue
        node = graph.node_for_key(f"op:{copy}")
        if node is None or any(graph.node(other).kind is NodeKind.MEMORY_DEBT
                               for other in graph.backward_reachable((node,))):
            continue
        found[call] = callee
    return found


def run_definition_nodes(normalized, run_key: str) -> list[int]:
    """Graph nodes of the definitions a summarized-call run effect writes."""
    from .memory_contracts import MemoryDefinitionKind

    return [
        normalized.memory_graph.definition_nodes[index]
        for index, definition in enumerate(normalized.memory_ssa.definitions)
        if definition.operation_key == run_key and definition.kind is MemoryDefinitionKind.DATA_WRITE
    ]


def _run_origins(normalized) -> dict:
    """Source labels carried by summarized runs (reached inside the callee)."""
    origins: dict = {}
    for call, effect in normalized.proven_call_effects:
        for index, run in enumerate((*effect.runs, *effect.memory_runs)):
            if run.origins:
                for node in run_definition_nodes(normalized, f"{call}~{index}"):
                    origins.setdefault(node, set()).update(run.origins)
    return origins


def _relative_anchors(unit, normalized) -> dict:
    """FUNCTION_RELATIVE objects of the function addressed from one entry
    register value (pointer-sized register spans the function uses, in every
    memory space it loads from or stores to): object -> (span, space id)."""
    from .relative_memory import _function_relative_object_id

    observation, context = unit.observation, unit.scopes.resolution_context
    spaces, registers = set(), set()
    for instruction in observation.instructions:
        for operation in instruction.operations:
            if operation.opcode in ("LOAD", "STORE") and operation.inputs                     and operation.inputs[0].kind is VarnodeKindCode.CONSTANT:
                spaces.add(operation.inputs[0].coordinate.byte_offset)
            for varnode in (*operation.inputs, operation.output):
                if varnode is not None and varnode.kind is VarnodeKindCode.REGISTER                         and varnode.byte_size in (4, 8):
                    resolved = _resolve_validated_storage(_storage_ref(varnode), context)
                    if type(resolved) is ResolvedStorage:
                        registers.add(resolved.span)
    # memory only a summarized call accesses (anchored on a register the
    # function itself may never mention, e.g. a pointer passed straight on)
    for _, effect in normalized.proven_call_effects:
        accesses = [load for run in effect.runs for load in run.loads]
        accesses += [item for run in effect.memory_runs for item in (run.write, *run.loads)]
        accesses += [load for demand in effect.sink_demands for load in demand.loads]
        for access in accesses:
            if access.anchor is not None:
                registers.add(access.anchor)
                spaces.add(access.space_id)
    candidates = {}
    for span in registers:
        for space_id in spaces:
            candidates[_function_relative_object_id(unit.scopes.function.scope, span, space_id)] = (
                span, space_id)
    used = {
        run.span.object_id for item in normalized.memory_ssa.atomic_spans for run in ()
    } | {atom.object_id for atom in normalized.memory_ssa.atomic_spans}
    return {object_id: row for object_id, row in candidates.items() if object_id in used}


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
