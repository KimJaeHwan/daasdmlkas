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
from dataclasses import replace

from .call_clobber import _register_space_id
from .model import ResolvedStorage
from .normalize import _program_register_space
from .span_geometry import ByteSpan
from .summary_store import model_effect
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
    # external calls bound to a declared model (``summary_store``): call key ->
    # assumption label
    declared: dict = field(default_factory=dict)
    # a member of a recursive SCC whose summaries did not reach a verified
    # fixpoint (``MAX_RECURSION_ROUNDS``): its intra-SCC calls stayed opaque
    recursion_unresolved: bool = False


def function_key(coordinate) -> str:
    return f"{coordinate.space_id:x}:{coordinate.byte_offset:x}"


def analyze_units(units, *, assumed_call_effects=None, extra_origins=None,
                  assume_globals_disjoint_from_stack=False, sink_roots=None,
                  image_info=None, external_models=None, readonly_image=None,
                  declared_boundaries=None, assume_direction_flag_clear=False) -> dict[str, AnalyzedFunction]:
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
    ``SinkDemand`` of the function's summary, so wrappers compose bottom-up.
    ``image_info`` + ``external_models``: calls to imported symbols (through a
    thunk or an import slot, ``image_info``) take the declared model of that
    name (``summary_store``); each use is a named assumption
    (``AnalyzedFunction.declared``).
    ``declared_boundaries``: entry key -> {call key: AssumedCallEffect}, the
    TEST-ONLY declared source/sink effects, applied as call effects of the
    same kind as summaries and models (writes exactly the declared registers
    from the declared reads, keeps every other byte, restores the stack
    pointer); labelled ``test-only-boundary:<label>``. (The legacy
    ``assumed_call_effects`` path normalizes them as raw call writes.)"""
    from .call_clobber import _preserved_stack_pointers

    from ._scope_results import ConstructedFunctionScope

    functions = {
        function_key(unit.scopes.function.entry): unit for unit in units
        if type(unit.scopes.function) is ConstructedFunctionScope and unit.observation is not None
    }
    calls = {key: _direct_calls(unit, functions) for key, unit in functions.items()}
    externals = {
        key: _external_sites(unit, image_info, external_models) if image_info and external_models else {}
        for key, unit in functions.items()
    }
    memory_space = _program_memory_space(next(iter(functions.values()))) if functions else None
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

        def site(key):
            unit = functions[key]
            observation, context = unit.observation, unit.scopes.resolution_context
            register_object, register_limit = _register_file(observation, context)
            if register_object is None:  # e.g. a thunk that is a lone tail jump
                register_object, register_limit = program_registers
            shapes = {
                row.call_operation_key: {
                    (row.memory_transition.caller_base.byte_offset,
                     row.memory_transition.caller_base.byte_size):
                    row.memory_transition.displacement_delta,
                }
                for row in observed_call_state_projections(observation)
            }
            return register_object, register_limit, _preserved_stack_pointers(observation, context), shapes

        def site_effect(key, call_key, summary, anchors, failed=(), callee=None):
            """The effect of one call site of ``key`` from a callee summary."""
            register_object, register_limit, stack_pointers, shapes = site(key)
            if register_object is None:
                return None
            tail = call_key.endswith(":BRANCH")
            if tail and len(program_stack) != 1:
                return None  # no single stack pointer to compose through
            return derive_proven_call_effect(
                summary, callee or calls[key][call_key], register_object, register_limit,
                excluded=tuple(program_stack) if tail else tuple(stack_pointers.get(call_key, ())),
                anchors=anchors,
                stack_deltas=shapes.get(call_key, {}),
                tail=tail,
                failed_conditions=frozenset(failed),
            )

        def boundaries_of(key):
            return (declared_boundaries or {}).get(key, {})

        def boundary_effect(key, call_key, declaration):
            """A TEST-ONLY declared boundary as a call effect (see above)."""
            from .function_summary import FUNCTION_SUMMARY_VERSION, ExitSummary, SummaryKind, SummaryRun

            register_object, _, _, shapes = site(key)
            if register_object is None:
                return None

            def span(row):
                return ByteSpan(register_object, row.byte_offset, row.byte_size)

            reads = tuple(sorted({span(row) for row in declaration.reads}, key=lambda item: item.canonical_key))
            runs = tuple(SummaryRun(span(row), SummaryKind.COMPUTED, (0,), ("declared",), reads, (), (), ())
                         for row in declaration.writes)
            if call_key.endswith(":BRANCH"):
                deltas = tuple(((item.start, item.size), item.size) for item in program_stack)
            else:
                deltas = tuple(((offset, size), -delta)
                               for (offset, size), delta in shapes.get(call_key, {}).items())
            summary = FunctionSummary(FUNCTION_SUMMARY_VERSION, (ExitSummary("declared", runs),), (), (),
                                      register_deltas=deltas)
            return site_effect(key, call_key, summary, {}, callee=f"test-only-boundary:{declaration.label}")

        def one(key, hypotheses):
            unit = functions[key]
            observation = unit.observation
            context = unit.scopes.resolution_context
            register_object, register_limit = _register_file(observation, context)
            if register_object is None:  # e.g. a thunk that is a lone tail jump
                register_object, register_limit = program_registers
            stack_pointers = _preserved_stack_pointers(observation, context)
            shapes = {
                row.call_operation_key: {
                    (row.memory_transition.caller_base.byte_offset,
                     row.memory_transition.caller_base.byte_size):
                    row.memory_transition.displacement_delta,
                }
                for row in observed_call_state_projections(observation)
            }
            assumed = (assumed_call_effects or {}).get(key, {})

            def derive(failed):
                proven = {}
                if register_object is None:
                    return proven
                for call_key, declaration in boundaries_of(key).items():
                    if call_key not in assumed:
                        effect = boundary_effect(key, call_key, declaration)
                        if effect is not None:
                            proven[call_key] = effect
                for call_key, callee in calls[key].items():
                    done = results.get(callee)
                    if call_key in assumed or call_key in proven:
                        continue
                    if component_of[callee] == component_of[key]:
                        # recursion: the SCC's current hypothesis (``solve``), or opaque
                        if hypotheses.get(call_key) is not None:
                            proven[call_key] = hypotheses[call_key]
                        continue
                    if done is None or done.summary is None:
                        continue
                    tail = call_key.endswith(":BRANCH")
                    if tail and len(program_stack) != 1:
                        continue  # no single stack pointer to compose through
                    effect = site_effect(key, call_key, done.summary, done.anchors, failed.get(call_key, ()))
                    if effect is not None:
                        proven[call_key] = effect
                register_space = _register_space_id(observation) or _program_register_space(unit)
                for call_key, (model_file, entry) in externals[key].items():
                    if call_key in proven or call_key in assumed or memory_space is None:
                        continue
                    effect = model_effect(
                        lambda summary, anchors, call_key=call_key: site_effect(
                            key, call_key, summary, anchors, callee=entry.label),
                        model_file, entry, register_object, register_limit, register_space, memory_space,
                        constants.get(call_key, {}),
                    )
                    if effect is None:
                        continue
                    missing = [slice_ for slice_ in entry.extent_registers()
                               if slice_ not in constants.get(call_key, {})]
                    if missing:
                        effect = replace(effect, extent_registers=tuple(
                            ByteSpan(register_object, offset, size) for offset, size in missing))
                    proven[call_key] = effect
                return proven

            # summarized values that hold only if alias conditions hold: the
            # caller decides them at the call; a pair it cannot prove disjoint
            # makes those bytes unknown and the function is normalized again
            # (the failed set only grows)
            failed: dict = {}
            constants: dict = {}   # external call -> extent register -> proven constant
            while True:
                proven = derive(failed)
                normalized = FunctionNormalizer().normalize(
                    unit, assumed_call_effects=assumed, proven_call_effects=proven,
                    assume_globals_disjoint_from_stack=assume_globals_disjoint_from_stack,
                    readonly_image=readonly_image,
                    assume_direction_flag_clear=assume_direction_flag_clear,
                )
                if type(normalized) is not NormalizedFunction:
                    break
                verdicts = _decide_conditions(unit, normalized, shapes, [
                    (call, f"cr{index}", run.conditions)
                    for call, effect in proven.items()
                    for index, run in enumerate((*effect.runs, *effect.memory_runs)) if run.conditions
                ])
                grown = _prove_extents(unit, normalized, proven, constants)
                for (call, tag), rows in verdicts.items():
                    effect = proven[call]
                    run = (*effect.runs, *effect.memory_runs)[int(tag[2:])]
                    for pair, verdict in zip(run.conditions, rows):
                        if verdict != "ok" and pair not in failed.get(call, set()):
                            failed.setdefault(call, set()).add(pair)
                            grown = True
                if not grown:
                    break
            origins: dict = {}
            projected: list = []
            roots: list = []
            if type(normalized) is NormalizedFunction:
                origins = _run_origins(normalized)
                for node, labels in (extra_origins(key, unit, normalized, calls[key]) if extra_origins else {}).items():
                    origins.setdefault(node, set()).update(labels)
                roots = list(sink_roots(key, unit, normalized)) if sink_roots else []
                decided = _decide_conditions(unit, normalized, shapes, [
                    (call, f"ck{index}", demand.conditions)
                    for call, effect in normalized.proven_call_effects
                    for index, demand in enumerate(effect.sink_demands) if demand.conditions
                ])
                for call, effect in normalized.proven_call_effects:
                    for index, demand in enumerate(effect.sink_demands):
                        nodes = run_definition_nodes(normalized, f"{call}~sink{index}")
                        for node in nodes:  # labels reached inside the callee
                            if demand.origins:
                                origins.setdefault(node, set()).update(demand.origins)
                        rows = decided.get((call, f"ck{index}"), ())
                        fails = any(verdict == "fail" for verdict in rows)
                        remaining = tuple(verdict for verdict in rows if verdict not in ("ok", "fail"))
                        complete = demand.complete and not fails
                        projected.append((call, index, demand.label, nodes, complete and not remaining))
                        roots.append((demand.label, nodes, complete, remaining))
            summary = (
                summarize_function(normalized, observation, origins, roots)
                if type(normalized) is NormalizedFunction else None
            )
            anchors = _relative_anchors(unit, normalized) if summary is not None else {}
            return AnalyzedFunction(key, unit, normalized, summary, calls[key], proven,
                                    anchors, origins, projected, declared={
                                        call: (f"test-only-boundary:{boundaries_of(key)[call].label}"
                                               if call in boundaries_of(key) else externals[key][call][1].label)
                                        for call in proven if call in externals[key] or call in boundaries_of(key)
                                    })

        def solve(component):
            """Recursion (design S5): every intra-SCC call starts from the
            optimistic hypothesis "returns doing nothing, restoring the stack
            pointer"; members are re-analyzed with the effects derived from
            the last round's summaries until those equal the hypotheses used.
            Only such a verified fixpoint is published (sound by induction on
            the depth of returning activations); otherwise intra-SCC calls
            stay opaque. Hypotheses keep no exact writes below the callee's
            entry stack pointer (its own frame, which re-projects deeper each
            round): such a call keeps no memory instead. Their sink demands are
            merged per label, and conditional values count as unknown."""
            sites = sorted(
                (key, call_key) for key in component for call_key, callee in calls[key].items()
                if callee in component
            )
            hypotheses = {}
            for key, call_key in sites:
                effect = site_effect(key, call_key, _bottom_summary(*site(key)[2:], call_key, program_stack),
                                     {})
                hypotheses[(key, call_key)] = effect
            for _ in range(MAX_RECURSION_ROUNDS):
                round_results = {
                    key: one(key, {call_key: effect for (owner, call_key), effect in hypotheses.items()
                                   if owner == key})
                    for key in sorted(component)
                }
                derived = {}
                for key, call_key in sites:
                    done = round_results[calls[key][call_key]]
                    derived[(key, call_key)] = None if done.summary is None else _recursive_hypothesis(
                        lambda failed: site_effect(key, call_key, done.summary, done.anchors, failed),
                        tuple(site(key)[2].get(call_key, ())) or tuple(program_stack),
                    )
                if derived == hypotheses:
                    return round_results
                hypotheses = derived
            fallback = {key: one(key, {}) for key in sorted(component)}
            for item in fallback.values():
                item.recursion_unresolved = True  # intra-SCC calls opaque (debt)
            return fallback

        for component in order:
            recursive = len(component) > 1 or any(
                callee == key for key in component for callee in calls[key].values())
            if recursive:
                results.update(solve(component))
            else:
                for key in sorted(component):
                    results[key] = one(key, {})
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


MAX_RECURSION_ROUNDS = 8


def _program_memory_space(unit) -> int | None:
    """The program's single loaded memory space (models address it)."""
    spaces = [row.space_id for row in unit.scopes.program.evidence.address_spaces
              if row.is_memory_space and row.is_loaded_memory_space and not row.is_overlay_space
              and not row.is_external_space]
    return spaces[0] if len(spaces) == 1 else None


def _external_sites(unit, image_info, external_models) -> dict:
    """Call key -> (model file, entry) for calls to imported symbols with a
    model: ``CALL`` of an import thunk, or ``CALLIND`` of a value copied from
    an import slot within the call instruction (``call [__imp_X]``)."""
    found = {}
    for instruction in unit.observation.instructions:
        operations = instruction.operations
        for ordinal, operation in enumerate(operations):
            if not operation.inputs:
                continue
            symbol = None
            target = operation.inputs[0]
            if operation.opcode == "CALL" and target.kind is VarnodeKindCode.ADDRESS:
                symbol = image_info.import_at_thunk(target.coordinate.space_id, target.coordinate.byte_offset)
            elif operation.opcode == "CALLIND":
                for copy in operations[:ordinal]:
                    if copy.opcode == "COPY" and copy.output == target \
                            and copy.inputs[0].kind is VarnodeKindCode.ADDRESS:
                        source = copy.inputs[0].coordinate
                        symbol = image_info.import_at_slot(source.space_id, source.byte_offset)
            if symbol is None:
                continue
            model = external_models.lookup(symbol.name)
            if model is not None:
                found[_operation_key(instruction.address, ordinal, operation.opcode)] = model
    return found


def _prove_extents(unit, normalized, proven, constants) -> bool:
    """Evaluate the ``~ext`` rows of model calls: a register proven constant at
    the call makes that model's variable-size effect exact (re-derive)."""
    from ._scope_contracts import AddressCoordinate, ValidatedVarnode
    from .relative_memory import constant_values

    register_space = _register_space_id(unit.observation) or _program_register_space(unit)
    requests = [
        (f"{call}~ext", ValidatedVarnode(VarnodeKindCode.REGISTER,
                                         AddressCoordinate(register_space, span.start), span.size), call, span)
        for call, effect in proven.items() for span in effect.extent_registers
    ]
    if not requests:
        return False
    values = constant_values(normalized, unit.observation, [(key, varnode) for key, varnode, _, _ in requests])
    grown = False
    for key, varnode, call, span in requests:
        value = values.get((key, varnode))
        if value is not None and (span.start, span.size) not in constants.get(call, {}):
            constants.setdefault(call, {})[(span.start, span.size)] = value
            grown = True
    return grown


def _bottom_summary(stack_pointers, shapes, call_key, program_stack):
    """The optimistic start for a recursive call site: one normal exit that
    writes nothing, with the stack pointer restored (undoing the call shape's
    push, or a pointer-sized ``ret`` for a tail jump)."""
    from .function_summary import FUNCTION_SUMMARY_VERSION, ExitSummary

    deltas = tuple(((offset, size), -delta) for (offset, size), delta in shapes.get(call_key, {}).items())
    if call_key.endswith(":BRANCH"):
        deltas = tuple(((span.start, span.size), span.size) for span in program_stack)
    return FunctionSummary(FUNCTION_SUMMARY_VERSION, (ExitSummary("bottom", ()),), (), (),
                           register_deltas=deltas)


def _recursive_hypothesis(derive, stack):
    """A derived effect usable as a recursion hypothesis: conditional values
    failed (they would need the caller's decision inside the fixpoint), sink
    demands merged per label (writes below the callee's entry stack pointer,
    which would re-project deeper each round, are already folded into
    ``clobbers_below`` by ``derive_proven_call_effect``)."""
    from dataclasses import replace
    from .call_summary_effects import ProvenSinkDemand

    failed: set = set()
    while True:
        effect = derive(failed)
        if effect is None:
            return None
        pairs = {pair for run in (*effect.runs, *effect.memory_runs) for pair in run.conditions}
        if not pairs - failed:
            break
        failed |= pairs
    merged: dict = {}
    for demand in effect.sink_demands:
        row = merged.get(demand.label)
        merged[demand.label] = demand if row is None else ProvenSinkDemand(
            demand.label,
            tuple(sorted(set(row.reads) | set(demand.reads), key=lambda span: span.canonical_key)),
            tuple(sorted(set(row.loads) | set(demand.loads), key=repr)),
            tuple(sorted(set(row.origins) | set(demand.origins))),
            row.complete and demand.complete,
            tuple(sorted(set(row.conditions) | set(demand.conditions), key=repr)),
        )
    return replace(effect, sink_demands=tuple(merged[label] for label in sorted(merged)))


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


def _decide_conditions(unit, normalized, shapes, pending) -> dict:
    """``pending``: (call, row tag, alias conditions) -- the anchored (read,
    write) pairs of a summarized run (``cr<i>``) or projected sink root
    (``ck<k>``). Returns (call, tag) -> one verdict per pair: "ok" (disjoint),
    "fail", or the pair as (span, span) in this function's objects (open: for
    this function's own callers to decide). Both sides are located once, at
    the call (the ``~<tag>`` row reads their anchors): the same object ->
    disjoint offsets are "ok", overlap fails; different objects -> "ok" when
    two address spaces, or a constant address and this function's stack under
    the named globals-vs-stack assumption; otherwise open. A side that cannot
    be located fails."""
    from ._scope_contracts import AddressCoordinate, ValidatedVarnode
    from .call_clobber import _register_space_id
    from .may_alias import stack_object_of
    from .normalize import _program_register_space
    from .relative_memory import project_anchored_after
    from .span_geometry import StorageObjectKind

    if not pending:
        return {}
    observation = unit.observation
    register_space = _register_space_id(observation) or _program_register_space(unit)

    def request(call, tag, side):
        displacement = side.displacement
        for (offset, size), delta in shapes.get(call, {}).items():
            if (side.anchor.start, side.anchor.size) == (offset, size):
                displacement += delta  # the callee's entry SP is after the push
        varnode = ValidatedVarnode(
            VarnodeKindCode.REGISTER, AddressCoordinate(register_space, side.anchor.start), side.anchor.size,
        )
        return (f"{call}~{tag}", varnode, displacement, side.size, side.space_id)

    requests = {
        request(call, tag, side)
        for call, tag, conditions in pending for pair in conditions for side in pair
        if side.anchor is not None
    }
    located = project_anchored_after(normalized, observation, sorted(requests, key=repr)) \
        if register_space is not None else {}
    stack = stack_object_of(unit.scopes, observation) if normalized.assumes_globals_disjoint_from_stack else None
    result = {}
    for call, tag, conditions in pending:
        rows = []
        for pair in conditions:
            left, right = [side.span if side.anchor is None else located.get(request(call, tag, side))
                           for side in pair]
            if left is None or right is None:
                rows.append("fail")
            elif left.object_id == right.object_id:
                rows.append("fail" if left.overlaps(right) else "ok")
            elif {left.object_id.kind, right.object_id.kind} == {StorageObjectKind.ADDRESS_SPACE}:
                rows.append("ok")  # two address spaces
            elif stack is not None and StorageObjectKind.ADDRESS_SPACE in (left.object_id.kind, right.object_id.kind) \
                    and stack in (left.object_id, right.object_id):
                rows.append("ok")  # ASSUMPTION globals-disjoint-from-stack
            else:
                rows.append((left, right))
        result[(call, tag)] = rows
    return result


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
    # pointers the function reads from entry memory (an object addressed from
    # the entry contents of a pointer-sized memory span)
    from .memory_contracts import MemoryDefinitionKind
    from .span_geometry import StorageObjectKind as Kind

    definitions = normalized.memory_ssa.definitions
    for read in normalized.memory_ssa.reads:
        if read.span.object_id.kind in (Kind.ADDRESS_SPACE, Kind.FUNCTION_RELATIVE) \
                and read.span.size in (4, 8) and any(
                    definitions[definition].kind is MemoryDefinitionKind.ENTRY
                    for fragment in read.fragments for definition in fragment.definition_ids):
            registers.add(read.span)
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
