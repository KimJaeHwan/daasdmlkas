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

from .phases import measured

import sys

from dataclasses import dataclass, field

from ._scope_contracts import VarnodeKindCode
from .call_seeds import _operation_key
from .call_summary_effects import (
    AnchoredSpan, ProvenCallEffect, derive_composed_call_effect, derive_proven_call_effect,
)
from .function_summary import FunctionSummary, summarize_function
from dataclasses import replace

from .call_clobber import _register_space_id
from .model import ResolvedStorage
from .resource_limits import AnalysisBudgetExceeded, activation, analysis_entry, checkpoint, run_exhausted
from .normalize import _program_register_space
from .span_geometry import ByteSpan
from .summary_store import model_effect
from .observed_call_state import observed_call_state_projections
from .pcodeop_models import no_effect_calls, trap_operations
from .normalize import (
    FunctionNormalizer, NormalizationFailureReason, NormalizedFunction, UnresolvedNormalizedFunction, _storage_ref,
)
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
    # assumption labels the models used here rest on (``ModelEntry.inherited``)
    inherited_assumptions: frozenset = frozenset()
    # a member of a recursive SCC whose summaries did not reach a verified
    # fixpoint (``MAX_RECURSION_ROUNDS``): its intra-SCC calls stayed opaque
    recursion_unresolved: bool = False
    # imports whose derived model (template) was not applied: call key -> why
    # (and "bound-model@<rva>" -> why a binding of this function was not applied)
    refused_models: dict = field(default_factory=dict)
    # a resource failure's detail ("function:depth", "function:work",
    # "run:time" ...; ``EngineRun.failed_functions``)
    failure_detail: str = ""
    # a failure published over a round-1 result after a run exhaustion
    # (docs 25.30 K1c-3): that round-1 result, whose summary its callers used --
    # its assumptions are still the run's (``summary_engine.run_assumptions``)
    superseded: object = None
    # calls taking a bound model (docs 25.20 F): call key -> (binding id, binding
    # file digest, rva, executable sha256, model label, model file digest)
    bound_calls: dict = field(default_factory=dict)
    # how it was derived (``summary_templates`` export prerequisites): TEST-ONLY
    # call effects given for it (``assumed_call_effects``, declared
    # boundaries, extra origins), and whether ``ImageBaseTracking`` was on
    test_only_inputs: bool = False
    image_tracked: bool = False
    # under ``ImageBaseTracking``: a direct memory operand in the image whose
    # instruction does not prove it relocates (an absolute place that may not
    # move with the library)
    image_unproven: bool = False
    # indirect calls proven to reach one of several functions (docs 25.33 F1b):
    # call key -> member function keys; their effect composes the members'
    # summaries (``derive_composed_call_effect``). Not in ``calls``: a consumer
    # that does not know this map sees an opaque indirect call
    multi_calls: dict = field(default_factory=dict)


def _import_slots_switched_on() -> bool:
    from .relative_memory import IMPORT_SLOTS

    return IMPORT_SLOTS.get() is not None


def _import_slots_active() -> bool:
    from .relative_memory import IMPORT_SLOTS

    return IMPORT_SLOTS.get() is not None and IMPORT_SLOTS.get().active


def function_key(coordinate) -> str:
    return f"{coordinate.space_id:x}:{coordinate.byte_offset:x}"



@dataclass(frozen=True)
class CallProvenance:
    """Operation records only (docs 25.31 C9-5), never part of a result: per
    call of one analysis instance, where its effect came from -- ("summary",
    the callee's AnalyzedFunction), ("recursive hypothesis", callee key),
    ("model" | "derived model" | "test-only-boundary", label) -- and every
    alias-condition decision: pairs dropped at derivation (``rejections``:
    (where, callee pair, "unlocatable" | "failed"); for a recursive
    hypothesis also its own derivation's rows and ("recursive hypothesis",
    anchored pair, "failed") per pair it failed by construction), the accumulated
    ``failed`` / ``opened`` sets, the last pass's run / writer verdicts
    (``final``: (call, "cr<i>" | "cw") -> verdicts in pair order) and the
    sink-demand pass (``sink``: (call, "ck<i>") -> verdicts)."""

    sources: dict
    rejections: dict
    failed: dict
    opened: dict
    final: dict
    sink: dict


@analysis_entry
def analyze_units(units, *, assume_import_slots_hold_exports=False, assume_entry_values_not_frame=True,
                  assume_opaque_callees_leave_no_stack_addresses=True,
                  **options) -> dict[str, "AnalyzedFunction"]:
    """``_analyze_units`` (below) under the named assumption
    import-slots-hold-their-exports when ``assume_import_slots_hold_exports``
    and ``image_info`` are given (``relative_memory.IMPORT_SLOTS``; it takes
    effect only where globals-disjoint-from-stack holds for the run), and
    entry-values-do-not-address-the-new-frame as ``assume_entry_values_not_frame``
    (``may_alias.ENTRY_VALUES_NOT_FRAME``, reset after the run), and
    opaque-callees-leave-no-stack-addresses likewise
    (``may_alias.OPAQUE_NO_STACK_ADDRESSES``)."""
    from .may_alias import ENTRY_VALUES_NOT_FRAME, OPAQUE_NO_STACK_ADDRESSES
    from .relative_memory import IMPORT_SLOTS, ImportSlots, reset_index_diagnostics

    reset_index_diagnostics()
    image_info = options.get("image_info")
    token = IMPORT_SLOTS.set(ImportSlots(image_info) if assume_import_slots_hold_exports and image_info else None)
    frame = ENTRY_VALUES_NOT_FRAME.set(bool(assume_entry_values_not_frame))
    opaque = OPAQUE_NO_STACK_ADDRESSES.set(bool(assume_opaque_callees_leave_no_stack_addresses))
    # the address-expression evaluation (``relative_memory``) follows a chain
    # of dependent values recursively: room for long chains; a function deeper
    # still fails alone (``NormalizationFailureReason.ANALYSIS_DEPTH``)
    previous = sys.getrecursionlimit()
    sys.setrecursionlimit(max(previous, ANALYSIS_RECURSION_LIMIT))
    try:
        return _analyze_units(units, **options)
    finally:
        sys.setrecursionlimit(previous)
        OPAQUE_NO_STACK_ADDRESSES.reset(opaque)
        ENTRY_VALUES_NOT_FRAME.reset(frame)
        IMPORT_SLOTS.reset(token)


ANALYSIS_RECURSION_LIMIT = 20000
# what fails one function (or one per-function check) alone: the recursion
# bound and a per-function budget; MemoryError fails the run (process state)
ANALYSIS_FAILURES = (RecursionError, AnalysisBudgetExceeded)


def _failure_reason(error) -> "NormalizationFailureReason":
    if isinstance(error, RecursionError):
        return NormalizationFailureReason.ANALYSIS_DEPTH
    if getattr(error, "scope", "function") == "run":
        return NormalizationFailureReason.ANALYSIS_RUN_BUDGET
    return NormalizationFailureReason.ANALYSIS_BUDGET


def _run_budget_failure(key, unit, calls) -> "AnalyzedFunction":
    """A function left unanalysed (or unpublished) by a run exhaustion."""
    from .resource_limits import current_run

    run = current_run()
    detail = f"run:{run.exhausted if run is not None and run.exhausted else 'unknown'}"
    return AnalyzedFunction(key, unit, UnresolvedNormalizedFunction(
        unit.scopes, NormalizationFailureReason.ANALYSIS_RUN_BUDGET), None, calls, failure_detail=detail)


def _failure_detail(error) -> str:
    """"function:depth", "function:work", "run:time" ... (``EngineRun.failed_functions``)."""
    if isinstance(error, RecursionError):
        return "function:depth"
    return f"{getattr(error, 'scope', 'function')}:{getattr(error, 'kind', 'unknown')}"


def _is_run_exhaustion(error) -> bool:
    return isinstance(error, AnalysisBudgetExceeded) and error.scope == "run"


def _resource_error(reason, detail: str) -> Exception:
    """A fresh exception of ``reason``'s kind (a recorded failure raised again)."""
    if reason is NormalizationFailureReason.ANALYSIS_DEPTH:
        return RecursionError(detail)
    kind = detail.split(":", 1)[1] if ":" in detail else "recorded"
    return AnalysisBudgetExceeded(kind, "recorded", scope="function")


def _ledger_key(unit):
    """A function's budget ledger: its scope identity (addresses repeat across
    nested library runs)."""
    return ("function", unit.scopes.function.scope)


class _Interrupted(Exception):
    """Run exhaustion inside ``analyze``: the components it published."""

    def __init__(self, results) -> None:
        super().__init__("run budget exhausted")
        self.results = results


@measured("analyze_units")
def _analyze_units(units, *, assumed_call_effects=None, extra_origins=None,
                  assume_globals_disjoint_from_stack=False, sink_roots=None,
                  image_info=None, external_models=None, readonly_image=None,
                  declared_boundaries=None, assume_direction_flag_clear=False,
                  pcodeop_models=None, private_frame_above=0,
                  assume_debug_break_traps_do_not_return=False,
                  own_library: str | None = None, keep_uncut=frozenset(),
                  assume_same_result_functions=False,
                  assume_accessor_result_separate=False,
                  assume_accessor_private_state=False, model_bindings=(),
                  record_provenance: dict | None = None,
                  assume_registered_handlers_not_observed=True) -> dict[str, AnalyzedFunction]:
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
    ``own_library``: the program is that library (e.g. "UNREALEDITOR-CORE.DLL");
    a function exported under a name an ``internal`` model entry of that library
    lists is cut -- not analyzed, its callers take the model (named assumption
    library-internal-model-cuts, reported with each use). ``keep_uncut``:
    function keys analyzed even so (functions whose own summary is wanted,
    ``summary_templates``).
    Derived models (templates) are applied like an in-Bundle callee's summary,
    with the same alias-condition feedback, when ``summary_templates.refusal``
    finds nothing against them in this run (``AnalyzedFunction.refused_models``).
    ``declared_boundaries``: entry key -> {call key: AssumedCallEffect}, the
    TEST-ONLY declared source/sink effects, applied as call effects of the
    same kind as summaries and models (writes exactly the declared registers
    from the declared reads, keeps every other byte, restores the stack
    pointer); labelled ``test-only-boundary:<label>``. (The legacy
    ``assumed_call_effects`` path normalizes them as raw call writes.)
    ``pcodeop_models``: declared CALLOTHER semantics (``pcodeop_models``):
    no-effect user ops are declared call effects reading and writing nothing,
    each use labelled in ``AnalyzedFunction.declared``.
    ``assume_same_result_functions``: the named assumption same-result-functions
    (docs 25.20): model entries with ``same_result`` / ``preserves_accessor_state``
    carry them into their call effects; reported where a call used them
    (``NormalizedFunction.same_result_uses``). ``assume_accessor_result_separate``:
    accessor-result-separate -- their ``result_separate_from_reads`` extents
    (``NormalizedFunction.accessor_separations``). ``assume_accessor_private_state``:
    accessor-private-state -- entries with ``omits_private_writes`` apply.
    ``model_bindings``: ``summary_store.ModelBinding`` files; the bound
    functions of this binary are cut (``_bound_cuts``) unless an assumption
    their entry rests on is off -- then their bodies are analyzed."""
    from .call_clobber import _preserved_stack_pointers

    from ._scope_results import ConstructedFunctionScope

    functions = {
        function_key(unit.scopes.function.entry): unit for unit in units
        if type(unit.scopes.function) is ConstructedFunctionScope and unit.observation is not None
    }
    if run_exhausted():
        # (finalization: nothing more is analysed -- docs 25.30 K1c-3)
        return {key: _run_budget_failure(key, unit, {}) for key, unit in functions.items()}
    # program-wide facts first (every function, cut ones included): they decide
    # which assumptions hold in this run, and so which models may be applied
    if assume_globals_disjoint_from_stack and program_switches_stack(functions.values()):
        assume_globals_disjoint_from_stack = False
    from .may_alias import ENTRY_VALUES_NOT_FRAME, OPAQUE_NO_STACK_ADDRESSES
    from .relative_memory import IMPORT_SLOTS

    if IMPORT_SLOTS.get() is not None:
        # an import's address is only worth "not the stack" under this assumption
        IMPORT_SLOTS.get().active = assume_globals_disjoint_from_stack
    # registry switches off in this run: a model resting on one is not applied
    disabled = {name for name, on in (
        ("globals-disjoint-from-stack", assume_globals_disjoint_from_stack),
        ("readonly-image-data-is-constant", readonly_image is not None),
        ("direction-flag-clear", assume_direction_flag_clear),
        ("entry-values-do-not-address-the-new-frame", ENTRY_VALUES_NOT_FRAME.get()),
        ("win64-home-space-callee-private", bool(private_frame_above) and ENTRY_VALUES_NOT_FRAME.get()),
        ("opaque-callees-leave-no-stack-addresses", OPAQUE_NO_STACK_ADDRESSES.get()),
        ("debug-break-traps-do-not-return", assume_debug_break_traps_do_not_return),
        # (the switch alone: binding a model at an import slot needs the slot to
        # hold the export's address, not globals-disjoint-from-stack -- the
        # non-stack inference keeps its own stronger gate, ``_import_slots_active``)
        ("import-slots-hold-their-exports", _import_slots_switched_on()),
        ("same-result-functions", assume_same_result_functions),
        ("accessor-result-separate", assume_accessor_result_separate),
        ("accessor-private-state", assume_accessor_private_state),
        ("registered-handlers-are-not-observed", assume_registered_handlers_not_observed),
    ) if not on}
    cuts = _model_cuts({key: unit for key, unit in functions.items() if key not in keep_uncut},
                       image_info, external_models, own_library, disabled) \
        if own_library and image_info and external_models else {}
    bound_refusals: dict = {}
    bound = _bound_cuts({key: unit for key, unit in functions.items() if key not in keep_uncut},
                        model_bindings, disabled, external_models, bound_refusals) if model_bindings else {}
    cuts = {**cuts, **{key: (model_file, entry) for key, (model_file, entry, _) in bound.items()}}
    from .relative_memory import IMAGE_BASE_TRACKING
    from .summary_templates import refusal as template_refusal

    namespace = next(iter(functions.values())).scopes.program.evidence.translation_namespace if functions else None
    language = None if namespace is None else (namespace.language_id, namespace.major_version, namespace.minor_version)
    image_tracked = IMAGE_BASE_TRACKING.get() is not None
    if image_tracked:
        IMAGE_BASE_TRACKING.get().lengths.update({
            instruction.address.byte_offset: instruction.fallthrough.byte_offset - instruction.address.byte_offset
            for unit in functions.values() for instruction in unit.observation.instructions
            if instruction.fallthrough is not None and instruction.fallthrough.space_id == instruction.address.space_id
            and 0 < instruction.fallthrough.byte_offset - instruction.address.byte_offset <= 15
        })

    refused_sites: dict = {}
    for key, reasons in bound_refusals.items():
        refused_sites.setdefault(key, {}).update(reasons)

    def usable(model_file, entry):
        if entry.refusal is not None:   # (undeclared callbacks / frees, invoked callbacks, engine version)
            return entry.refusal
        if entry.template is None:
            return None
        return template_refusal(model_file, entry, external_models=external_models, pcodeop_models=pcodeop_models,
                                private_frame_above=private_frame_above, language=language)

    program = dict(functions)   # every function of the program, cut ones included (program-wide facts)
    functions = {key: unit for key, unit in functions.items() if key not in cuts}
    calls = {key: _direct_calls(unit, functions) for key, unit in functions.items()}
    local_entries = frozenset((unit.scopes.function.entry.space_id, unit.scopes.function.entry.byte_offset)
                              for unit in program.values())
    externals = {
        key: {**(_external_sites(unit, image_info, external_models, disabled, usable,
                                 refused_sites.setdefault(key, {}), local_entries)
                 if image_info and external_models else {}), **_cut_sites(unit, cuts)}
        for key, unit in functions.items()
    }
    noreturn_jumps = {
        key: _noreturn_jumps(unit, image_info, external_models, calls[key], disabled, usable,
                             refused_sites.setdefault(key, {}))
        if image_info and external_models else {}
        for key, unit in functions.items()
    }
    memory_space = _program_memory_space(next(iter(functions.values()))) if functions else None
    files = [_register_file(unit.observation, unit.scopes.resolution_context) for unit in program.values()]
    program_registers = (
        next((object_id for object_id, _ in files if object_id is not None), None),
        max((limit for _, limit in files), default=0),
    )
    # the program's stack pointer (the call shapes' base register), for tail jumps
    program_stack = {
        span for unit in program.values()
        for spans in _preserved_stack_pointers(unit.observation, unit.scopes.resolution_context).values()
        for span in spans
    }

    # function key -> (NormalizationFailureReason, detail) of a resource
    # failure of that function (sticky; run exhaustion is never recorded here)
    resource_failures: dict = {}

    def analyze(calls, multi=None):
        multi = multi or {}
        # (multi-target members ordered before their callers, as callees)
        order = _callee_first_components({
            key: {**calls[key], **{f"{call}~m{index}": member for call, members in multi.get(key, {}).items()
                                   for index, member in enumerate(members)}}
            for key in calls})
        component_of = {key: index for index, component in enumerate(order) for key in component}
        recursive_keys = frozenset(key for component in order for key in component
                                   if len(component) > 1 or key in calls[key].values()
                                   or any(key in members for members in multi.get(key, {}).values()))
        results: dict[str, AnalyzedFunction] = {}

        sites_of: dict = {}
        instantiated: dict = {}

        def templates(entry, register_object, memory_space):
            """A template's summary at this program (fixed object ids)."""
            from .summary_templates import instantiate

            slot = (entry.label, register_object, memory_space)
            if slot not in instantiated:
                instantiated[slot] = instantiate(entry.template, entry.label, register_object, memory_space)
            return instantiated[slot]

        state_proofs: dict = {}   # callee key -> ``_state_proof`` (computed once)

        def site(key):
            """Call-site facts of ``key`` (fixed per function: computed once)."""
            if key not in sites_of:
                sites_of[key] = _site(key)
            return sites_of[key]

        def _site(key):
            unit = functions[key]
            observation, context = unit.observation, unit.scopes.resolution_context
            register_object, register_limit = _register_file(observation, context)
            if register_object is None:  # e.g. a thunk that is a lone tail jump
                register_object, register_limit = program_registers
            # every register byte the program uses: a thunk touching only a few
            # registers still passes the others through (preserved or unknown)
            register_limit = max(register_limit, program_registers[1])
            shapes = {
                row.call_operation_key: {
                    (row.memory_transition.caller_base.byte_offset,
                     row.memory_transition.caller_base.byte_size):
                    row.memory_transition.displacement_delta,
                }
                for row in observed_call_state_projections(observation)
            }
            return register_object, register_limit, _preserved_stack_pointers(observation, context), shapes

        def site_effect(key, call_key, summary, anchors, failed=(), callee=None, rejections=None):
            """The effect of one call site of ``key`` from a callee summary."""
            register_object, register_limit, stack_pointers, shapes = site(key)
            if register_object is None:
                return None
            tail = _is_tail(call_key)
            if tail and len(program_stack) != 1:
                return None  # no single stack pointer to compose through
            return derive_proven_call_effect(
                summary, callee or calls[key][call_key], register_object, register_limit,
                excluded=tuple(program_stack) if tail else tuple(stack_pointers.get(call_key, ())),
                anchors=anchors,
                stack_deltas=shapes.get(call_key, {}),
                tail=tail,
                failed_conditions=frozenset(failed),
                rejections=rejections,
            )

        def composed_effect(key, call_key, members, failed=()):
            """The effect of a call of ``key`` reaching one of ``members``
            (their summaries composed, ``derive_composed_call_effect``)."""
            register_object, register_limit, stack_pointers, shapes = site(key)
            if register_object is None or _is_tail(call_key):
                return None
            return derive_composed_call_effect(
                tuple((done.summary, done.anchors) for done in members),
                "targets:" + "|".join(done.key for done in members), register_object, register_limit,
                excluded=tuple(stack_pointers.get(call_key, ())), stack_deltas=shapes.get(call_key, {}),
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
            if _is_tail(call_key):
                deltas = tuple(((item.start, item.size), item.size) for item in program_stack)
            else:
                deltas = tuple(((offset, size), -delta)
                               for (offset, size), delta in shapes.get(call_key, {}).items())
            summary = FunctionSummary(FUNCTION_SUMMARY_VERSION, (ExitSummary("declared", runs),), (), (),
                                      register_deltas=deltas, stack_values_out=False)
            return site_effect(key, call_key, summary, {}, callee=f"test-only-boundary:{declaration.label}")

        # (operation records only, C9-5) (caller, call) -> the recursion
        # hypothesis in use: {"failed": pairs, "rejections": rows}
        hypothesis_notes: dict = {}

        def one(key, hypotheses):
            """``analyze_one``; a function whose dependent-value chains exceed
            the recursion bound (or whose budget runs out) is a typed failure
            of that function alone, sticky for the run: every later round
            (recursion, indirect targets) sees the same failure, never a retry."""
            if key not in resource_failures:
                try:
                    with activation(_ledger_key(functions[key])):
                        published = {} if record_provenance is not None else None
                        result, normalization_options = analyze_one(key, hypotheses, provenance=published)
                        if _forward_switched_on() and key not in recursive_keys:
                            from ._forward_memory import RefinementRefused, prepare_memory_refinement
                            from .summary_engine import run_assumptions

                            plan = prepare_memory_refinement(result, normalization_options, assumptions=run_assumptions(
                                {key: result}, readonly_image=readonly_image, home_space=private_frame_above))
                            if plan is not None:
                                pending = {} if record_provenance is not None else None
                                try:
                                    candidate, _ = analyze_one(key, hypotheses, refinement=plan, provenance=pending)
                                    if type(candidate.normalized) is NormalizedFunction and candidate.summary is not None:
                                        candidate.inherited_assumptions |= frozenset(plan.requires)
                                        result, published = candidate, pending
                                except RefinementRefused:
                                    pass  # keep N0 in its entirety, never combine replay artifacts
                        checkpoint()   # (limits checked before the result is published)
                        if record_provenance is not None:
                            record_provenance.update(published)
                        return result
                except ANALYSIS_FAILURES as error:
                    from .relative_memory import IMPORT_SLOTS

                    if IMPORT_SLOTS.get() is not None:   # (its analysis is discarded)
                        IMPORT_SLOTS.get().used.discard(functions[key].scopes.function.scope)
                    if _is_run_exhaustion(error):
                        raise   # (finalization: ``analyze`` publishes verified components only)
                    resource_failures[key] = (_failure_reason(error), _failure_detail(error))
            reason, detail = resource_failures[key]
            return AnalyzedFunction(key, functions[key], UnresolvedNormalizedFunction(
                functions[key].scopes, reason), None, calls[key], failure_detail=detail)

        def analyze_one(key, hypotheses, *, refinement=None, provenance=None):
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
            markers = no_effect_calls(unit, pcodeop_models) if pcodeop_models else {}
            assumed = {**markers, **(assumed_call_effects or {}).get(key, {})}

            # (operation records only, docs 25.31 C9-5: where each effect came from)
            sources: dict = {}
            rejections: dict = {}

            def derive(failed):
                proven = {}
                sources.clear()
                rejections.clear()
                if register_object is None:
                    return proven
                for call_key, declaration in boundaries_of(key).items():
                    if call_key not in assumed:
                        effect = boundary_effect(key, call_key, declaration)
                        if effect is not None:
                            proven[call_key] = effect
                            sources[call_key] = ("test-only-boundary", declaration.label)
                for call_key, callee in calls[key].items():
                    done = results.get(callee)
                    if call_key in assumed or call_key in proven:
                        continue
                    if component_of[callee] == component_of[key]:
                        # recursion: the SCC's current hypothesis (``solve``), or opaque
                        if hypotheses.get(call_key) is not None:
                            proven[call_key] = hypotheses[call_key]
                            sources[call_key] = ("recursive hypothesis", callee)
                            note = hypothesis_notes.get((key, call_key))
                            if note:   # (its derivation: every condition failed by construction)
                                rejections[call_key] = [*note["rejections"], *(
                                    ("recursive hypothesis", pair, "failed")
                                    for pair in sorted(note["failed"], key=repr))]
                        continue
                    if done is None or done.summary is None:
                        continue
                    tail = _is_tail(call_key)
                    if tail and len(program_stack) != 1:
                        continue  # no single stack pointer to compose through
                    effect = site_effect(key, call_key, done.summary, done.anchors, failed.get(call_key, ()),
                                         rejections=rejections.setdefault(call_key, [])
                                         if record_provenance is not None else None)
                    if effect is not None and call_key.endswith(":CALL") and not failed.get(call_key) \
                            and site(key)[3].get(call_key) == {(0x20, 8): -8} \
                            and int(call_key.split(":", 1)[0], 16) == memory_space \
                            and _plain_push_call(functions[key], call_key, memory_space) \
                            and effect.restores_stack and effect.preserves_memory \
                            and not (effect.noreturn or effect.memory_runs or effect.unknown_memory
                                     or effect.writer_conditions or effect.tail_stack):
                        if callee not in state_proofs:
                            try:
                                # (charged to the callee: a caller near its own limit
                                # does not decide the callee's proof)
                                with activation(_ledger_key(done.unit)):
                                    proof = _state_proof(done.unit, done.normalized)
                                    checkpoint()
                                    state_proofs[callee] = proof
                            except ANALYSIS_FAILURES as error:
                                if _is_run_exhaustion(error):
                                    raise
                                state_proofs[callee] = (_failure_reason(error), _failure_detail(error))
                        if type(state_proofs[callee]) is tuple:
                            # out of a resource: the function needing it fails (never a silent "no proof")
                            raise _resource_error(*state_proofs[callee])
                        if state_proofs[callee] is not None:
                            effect = replace(effect, state_proof=state_proofs[callee])
                    if effect is not None:
                        proven[call_key] = effect
                        sources[call_key] = ("summary", done)
                for call_key, members in multi.get(key, {}).items():
                    if call_key in assumed or call_key in proven \
                            or any(component_of[member] == component_of[key] for member in members):
                        continue   # (a member in the caller's SCC: opaque)
                    dones = [results.get(member) for member in members]
                    if any(done is None or done.summary is None for done in dones):
                        continue   # (a member failed or has no summary: opaque)
                    effect = composed_effect(key, call_key, dones, failed.get(call_key, ()))
                    if effect is not None:
                        proven[call_key] = effect
                        sources[call_key] = ("summaries", tuple(members))
                register_space = _register_space_id(observation) or _program_register_space(unit)
                for call_key, (model_file, entry) in externals[key].items():
                    if call_key in proven or call_key in assumed or memory_space is None:
                        continue
                    if entry.template is not None:
                        # a derived summary: the in-Bundle path, conditions decided here
                        summary, anchors = templates(entry, register_object, memory_space)
                        if _is_tail(call_key) and len(program_stack) != 1:
                            continue
                        effect = site_effect(key, call_key, summary, anchors, failed.get(call_key, ()),
                                             callee=entry.label,
                                             rejections=rejections.setdefault(call_key, [])
                                             if record_provenance is not None else None)
                        if effect is not None:
                            proven[call_key] = effect
                            sources[call_key] = ("derived model", entry.label)
                        continue
                    effect = model_effect(
                        lambda summary, anchors, call_key=call_key: site_effect(
                            key, call_key, summary, anchors, callee=entry.label),
                        model_file, entry, register_object, register_limit, register_space, memory_space,
                        constants.get(call_key, {}),
                    )
                    if effect is None:
                        continue
                    if "same-result-functions" not in disabled:
                        effect = _accessor_effect(effect, model_file, entry, register_object, memory_space,
                                                  "accessor-result-separate" not in disabled)
                    if "accessor-private-state" in entry.inherited:
                        effect = replace(effect, omits_private_writes=True)
                    # every extent register, proven or not: a constant taken is
                    # checked again on each state (``_prove_extents``)
                    slices = entry.extent_registers()
                    if slices:
                        effect = replace(effect, extent_registers=tuple(
                            ByteSpan(register_object, offset, size) for offset, size in slices))
                    proven[call_key] = effect
                    sources[call_key] = ("model", entry.label)
                for call_key in _unplaced_noreturn(unit, proven):
                    del proven[call_key]  # opaque: the cut would drop an observed edge
                return proven

            # summarized values that hold only if alias conditions hold: the
            # caller decides them at the call; a pair it cannot prove disjoint
            # makes those bytes unknown and the function is normalized again
            # (the failed set only grows)
            failed: dict = {}
            constants: dict = {}   # external call -> extent register -> proven constant
            rejected: set = set()  # (call, extent register) whose constant failed on a later state
            # run pairs this function cannot decide (both sides located in its own
            # objects): kept as conditions of its own (``open_condition`` debts),
            # sticky -- a pair later found failing, or located elsewhere, fails
            opened: dict = {}
            verdicts: dict = {}
            while True:
                proven = derive(failed)
                normalization_options = dict(
                    assumed_call_effects=assumed, proven_call_effects=proven,
                    assume_globals_disjoint_from_stack=assume_globals_disjoint_from_stack,
                    readonly_image=readonly_image,
                    assume_direction_flag_clear=assume_direction_flag_clear,
                    private_frame_above=private_frame_above,
                    open_conditions=opened,
                )
                normalized = FunctionNormalizer().normalize(
                    unit, **normalization_options, _forward_memory_plan=refinement)
                if type(normalized) is not NormalizedFunction:
                    break
                verdicts = _decide_conditions(unit, normalized, shapes, [
                    (call, f"cr{index}", run.conditions)
                    for call, effect in proven.items()
                    for index, run in enumerate((*effect.runs, *effect.memory_runs)) if run.conditions
                ] + [
                    (call, "cw", effect.writer_conditions)
                    for call, effect in proven.items() if effect.writer_conditions
                ])
                grown = _prove_extents(unit, normalized, proven, constants, rejected)
                for (call, tag), rows in verdicts.items():
                    effect = proven[call]
                    conditions = effect.writer_conditions if tag == "cw" else \
                        (*effect.runs, *effect.memory_runs)[int(tag[2:])].conditions
                    for pair, verdict in zip(conditions, rows):
                        if verdict == "ok" or pair in failed.get(call, set()):
                            continue
                        known = opened.get(call, {}).get(pair)
                        if tag != "cw" and verdict != "fail" and known in (None, verdict):
                            if known is None:
                                opened.setdefault(call, {})[pair] = verdict
                                grown = True
                            continue
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
            jumps = noreturn_jumps[key]
            summary = (
                summarize_function(normalized, observation, origins, roots,
                                   (trap_operations(unit, pcodeop_models)
                                    if assume_debug_break_traps_do_not_return and pcodeop_models else frozenset())
                                   | {jump for jump in jumps if jump.endswith(":BRANCH")},
                                   noreturn_jumps=frozenset(jump for jump in jumps if jump.endswith(":CBRANCH")))
                if type(normalized) is NormalizedFunction else None
            )
            anchors = _relative_anchors(unit, normalized) if summary is not None else {}
            result = AnalyzedFunction(key, unit, normalized, summary, calls[key], proven,
                                    anchors, origins, projected, declared={
                                        call: (f"test-only-boundary:{boundaries_of(key)[call].label}"
                                               if call in boundaries_of(key) else externals[key][call][1].label)
                                        for call in proven if call in externals[key] or call in boundaries_of(key)
                                    } | {call: effect.label for call, effect in markers.items()}
                                    | {jump: entry.label for jump, (_, entry) in jumps.items()},
                                    # (this function's own models and resolutions only: a
                                    # callee's labels are reported per run, run_assumptions)
                                    inherited_assumptions=frozenset(
                                        label for call in proven if call in externals[key]
                                        for label in externals[key][call][1].inherited)
                                    | {label for _, entry in jumps.values() for label in entry.inherited}
                                    | _same_result_labels(normalized),
                                    refused_models=dict(refused_sites.get(key, {})),
                                    bound_calls={call: bound[callee][2] for call, callee in _direct_calls(
                                        unit, bound).items() if call in proven},
                                    test_only_inputs=bool((assumed_call_effects or {}).get(key))
                                    or bool(boundaries_of(key)) or extra_origins is not None,
                                    image_tracked=image_tracked,
                                    image_unproven=image_tracked and _unproven_image_operands(unit),
                                    multi_calls={call: members for call, members in multi.get(key, {}).items()
                                                 if call in proven})
            if key in resolution_requires:   # (forward facts the resolutions of its calls rest on)
                result.inherited_assumptions = result.inherited_assumptions | resolution_requires[key]
            if provenance is not None:   # publish only after the whole selected analysis succeeds
                provenance[id(result)] = (result, CallProvenance(
                    sources={call: source for call, source in sources.items() if call in proven},
                    rejections={call: tuple(rows) for call, rows in rejections.items() if rows},
                    failed={call: frozenset(pairs) for call, pairs in failed.items()},
                    opened={call: dict(pairs) for call, pairs in opened.items()},
                    final={(call, tag): tuple(rows) for (call, tag), rows in verdicts.items()},
                    sink={(call, tag): tuple(rows) for (call, tag), rows in decided.items()}
                    if type(normalized) is NormalizedFunction else {},
                ))
            return result, normalization_options

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
            hypothesis_notes.clear()   # (the bottom hypotheses: no conditions)
            for _ in range(MAX_RECURSION_ROUNDS):
                round_results = {
                    key: one(key, {call_key: effect for (owner, call_key), effect in hypotheses.items()
                                   if owner == key})
                    for key in sorted(component)
                }
                derived = {}
                notes: dict = {}
                for key, call_key in sites:
                    done = round_results[calls[key][call_key]]
                    note = notes[(key, call_key)] = {} if record_provenance is not None else None
                    derived[(key, call_key)] = None if done.summary is None else _recursive_hypothesis(
                        lambda failed, rows=None: site_effect(key, call_key, done.summary, done.anchors, failed,
                                                              rejections=rows),
                        tuple(site(key)[2].get(call_key, ())) or tuple(program_stack),
                        note,
                    )
                if derived == hypotheses:
                    return round_results
                hypotheses = derived
                hypothesis_notes.clear()
                hypothesis_notes.update((where, note) for where, note in notes.items() if note)
            fallback = {key: one(key, {}) for key in sorted(component)}
            for item in fallback.values():
                item.recursion_unresolved = True  # intra-SCC calls opaque (debt)
            return fallback

        for index, component in enumerate(order):
            recursive = len(component) > 1 or any(
                callee == key for key in component for callee in calls[key].values())
            try:
                if recursive:
                    results.update(solve(component))
                else:
                    for key in sorted(component):
                        results[key] = one(key, {})
            except AnalysisBudgetExceeded as error:
                if not _is_run_exhaustion(error):
                    raise
                # finalization (docs 25.30 K1c-3): the components completed so far
                # rest on completed callees only; the interrupted one publishes
                # none of its members (they may rest on unverified hypotheses)
                for rest in order[index:]:
                    for key in rest:
                        results[key] = one(key, {}) if key in resource_failures else \
                            _run_budget_failure(key, functions[key], calls[key])
                raise _Interrupted(results) from None
        return results

    # indirect calls with a provably constant target (a Bundle function): resolved
    # on the analyzed graphs, then analyzed as direct calls; repeat until the
    # resolved set is stable (each round re-checks every resolution)
    # (a constant target that is a cut function takes its model, as a direct call)
    base_externals = {key: dict(sites) for key, sites in externals.items()}

    def use_externals(extra):
        externals.clear()
        externals.update({key: {**sites, **extra.get(key, {})} for key, sites in base_externals.items()})

    resolved: dict = {}
    resolved_cuts: dict = {}
    resolved_multi: dict = {}
    resolution_requires: dict = {}   # (key -> labels of the forward facts its resolutions rest on)
    forward = _forward_switched_on()
    rounds = 1 + (sum(1 for unit in functions.values() for instruction in unit.observation.instructions
                      for operation in instruction.operations if operation.opcode == "CALLIND")
                  if forward else sum(1 for unit in functions.values() for _ in _callind_sites(unit)))
    done = 0
    # round 1 resolves no indirect call: its results rest on no hypothesis --
    # what a run exhaustion in a later round publishes (docs 25.30 K1c-3)
    first = None

    def with_failures(published):
        """``published`` with every function failure recorded since (a failed
        function is never reported analysed; its round-1 summary its callers
        used rests on no hypothesis)."""
        found = dict(published)
        for key, (reason, detail) in resource_failures.items():
            if key in found:
                replaced = found[key] if type(found[key].normalized) is NormalizedFunction else found[key].superseded
                found[key] = AnalyzedFunction(key, functions[key], UnresolvedNormalizedFunction(
                    functions[key].scopes, reason), None, calls[key], failure_detail=detail, superseded=replaced)
        return found
    try:
        while done < rounds:
            done += 1
            use_externals(resolved_cuts)
            results = analyze({key: {**calls[key], **resolved.get(key, {})} for key in calls}, resolved_multi)
            if first is None:
                first = results
            found, found_cuts, found_multi, requires = {}, {}, {}, {}
            newly_failed = False
            for key, item in results.items():
                if key in resource_failures or type(item.normalized) is not NormalizedFunction:
                    continue   # (failed / refused: no targets; each function adds at most one round)
                try:
                    with activation(_ledger_key(item.unit)):
                        targets = _indirect_targets(item, program)
                        if forward:
                            several, labels = _forward_targets(item, functions, readonly_image)
                            for call, members in several.items():
                                if call in targets:
                                    continue
                                if len(members) == 1:
                                    targets[call] = members[0]
                                else:
                                    found_multi.setdefault(key, {})[call] = members
                                requires.setdefault(key, set()).update(labels[call])
                        checkpoint()
                except ANALYSIS_FAILURES as error:
                    if _is_run_exhaustion(error):
                        raise
                    # the function fails (sticky): one more round, its callers see an opaque call
                    resource_failures[key] = (_failure_reason(error), _failure_detail(error))
                    newly_failed = True
                    continue
                if direct := {call: target for call, target in targets.items() if target in functions}:
                    found[key] = direct
                if cut := {call: cuts[target] for call, target in targets.items() if target in cuts}:
                    found_cuts[key] = cut
            if found == resolved and found_cuts == resolved_cuts and found_multi == resolved_multi \
                    and not newly_failed:
                # (the resolutions recomputed on these results: their facts' labels too)
                for key, labels in requires.items():
                    results[key].inherited_assumptions = results[key].inherited_assumptions | frozenset(labels)
                return results
            if newly_failed:
                rounds += 1   # (one more round for the failure; each function fails once)
            resolved, resolved_cuts, resolved_multi = found, found_cuts, found_multi
            # (accumulated over the rounds: each round's results rest on every
            # earlier round's resolutions, so on their facts' labels too)
            for key, labels in requires.items():
                resolution_requires[key] = resolution_requires.get(key, frozenset()) | frozenset(labels)
        use_externals({})
        resolution_requires.clear()
        return analyze(calls)  # not stable: no indirect resolution at all
    except _Interrupted as stop:
        return stop.results if first is None else with_failures(first)
    except AnalysisBudgetExceeded as error:
        if not _is_run_exhaustion(error) or first is None:
            raise
        return with_failures(first)   # (round 1 finished; later rounds rest on unrevalidated resolutions)


MAX_RECURSION_ROUNDS = 8


def _bound_cuts(functions, bindings, disabled, external_models, refusals) -> dict:
    """Function key -> (model file, entry, provenance) for the functions
    ``bindings`` bind in this binary (docs 25.20 F): the binding's executable
    SHA-256 and language must be this program's, its ABI the run's (the ABI
    of the run's models -- a binding of this binary under another ABI, or a
    run without models to say, is an error); the function at image base + RVA
    must be one of the program's (else an error: a stale or wrong binding);
    two bindings of one function are an error; an entry resting on a
    switched-off assumption is not applied -- the body is analyzed, the
    reason recorded in ``refusals`` (function key -> {"bound-model@<rva>":
    why}). Each use adds the label bound-model:<binding id>@<rva>#<binding
    digest>; provenance: (binding id, binding digest, rva, executable sha256,
    model label, model file digest)."""
    from .summary_store import ModelError

    if not functions or not bindings:
        return {}
    evidence = next(iter(functions.values())).scopes.program.evidence
    sha = evidence.executable_sha256.hex()
    base = evidence.image_base
    abis = {item.abi_tag for item in external_models.files} if external_models is not None else set()
    found, seen = {}, set()
    for binding in bindings:
        if binding.executable_sha256 != sha or binding.language_id != evidence.translation_namespace.language_id:
            continue
        if abis != {binding.abi_tag}:
            raise ModelError(f"binding {binding.binding_id}: ABI {binding.abi_tag} is not this run's "
                             f"({', '.join(sorted(abis)) or 'no models given'})")
        for rva, model_id, _ in binding.rows:
            key = function_key_of(base.space_id, base.byte_offset + rva)
            if key not in functions:
                raise ModelError(f"binding {binding.binding_id}: no function at rva {rva:#x} of this binary")
            if key in seen:
                raise ModelError(f"binding {binding.binding_id}: rva {rva:#x} is bound twice")
            seen.add(key)
            model_file, entry = binding.entry(model_id)
            if entry.refusal is not None:
                refusals.setdefault(key, {})[f"bound-model@{rva:#x}"] = \
                    f"{entry.label}: {entry.refusal}: the body is analyzed"
                continue
            off = set(entry.inherited) & disabled
            if off:
                refusals.setdefault(key, {})[f"bound-model@{rva:#x}"] = \
                    f"{entry.label} rests on {', '.join(sorted(off))} (off): the body is analyzed"
                continue
            label = f"bound-model:{binding.binding_id}@{rva:#x}#{binding.digest[:12]}"
            found[key] = (model_file, replace(entry, inherited=(*entry.inherited, label)),
                          (binding.binding_id, binding.digest, rva, sha, entry.label, model_file.digest))
    return found


def _same_result_labels(normalized) -> set:
    """same-result-functions and each preserves_accessor_state claim a
    same-result atom of the function rests on (docs 25.20); a state kept by a
    body proof ("proof:<reason>", diagnostic only) rests on the premise
    accessor-hidden-state-in-memory (docs 25.26)."""
    uses = getattr(normalized, "same_result_uses", ())
    if not uses:
        return set()
    claims = {label for _, _, found, _ in uses for label in found}
    return {"same-result-functions"} | {f"accessor-state-preserved-by:{label}"
                                        for label in claims if not label.startswith("proof:")} \
        | ({"accessor-hidden-state-in-memory"} if any(label.startswith("proof:") for label in claims) else set()) \
        | ({"accessor-result-separate"} if getattr(normalized, "accessor_separations", ()) else set())


def _plain_push_call(unit, call_key, memory_space) -> bool:
    """The CALL instruction of ``call_key`` is exactly ``RSP = RSP - 8;
    STORE [RSP] <- its fall-through address (8 bytes, the program's memory);
    CALL`` -- nothing between the push and the call can move RSP or
    overwrite the pushed continuation (the state proof's return lands there)."""
    space, offset, _, _ = call_key.split(":")
    row = next((item for item in unit.observation.instructions
                if (item.address.space_id, item.address.byte_offset) == (int(space, 16), int(offset, 16))), None)
    if row is None or row.fallthrough is None or len(row.operations) != 3:
        return False
    adjust, push, call = row.operations
    rsp = adjust.output
    return (
        adjust.opcode == "INT_SUB" and rsp is not None and rsp.kind is VarnodeKindCode.REGISTER
        and (rsp.coordinate.byte_offset, rsp.byte_size) == (0x20, 8) and len(adjust.inputs) == 2
        and adjust.inputs[0] == rsp and adjust.inputs[1].kind is VarnodeKindCode.CONSTANT
        and adjust.inputs[1].coordinate.byte_offset == 8
        and push.opcode == "STORE" and len(push.inputs) == 3
        and push.inputs[0].kind is VarnodeKindCode.CONSTANT and push.inputs[0].coordinate.byte_offset == memory_space
        and push.inputs[1] == rsp and push.inputs[2].kind is VarnodeKindCode.CONSTANT
        and push.inputs[2].byte_size == 8 and push.inputs[2].coordinate.byte_offset == row.fallthrough.byte_offset
        and call.opcode == "CALL"
    )


_X64_GENERAL = ((0x00, 0x40), (0x80, 0xC0))          # rax..rdi, r8..r15 (not segments / FS, GS bases)
_X64_FLAGS = frozenset({0x200, 0x202, 0x204, 0x206, 0x207, 0x20B})   # CF PF AF ZF SF OF (not TF IF DF)
_X64_RIP = (0x288, 0x290)


def _state_proof(unit, normalized) -> str | None:
    """Why a call of this function keeps every accessor's hidden state, or
    None (docs 25.26; premise accessor-hidden-state-in-memory): x86-64 (v1);
    no STORE, CALL, CALLIND, CALLOTHER or BRANCHIND; every output a unique,
    a general register, an arithmetic flag or RIP; no instruction with
    internal p-code flow, calls or overrides; every flow target, branch
    target and fall-through inside the function; every RETURN the pop-return
    shape (``may_alias._return_shape``) whose LOAD reads at the entry stack
    pointer -- with no store, the caller's return address: the original
    continuation."""
    from .control_projection import control_successor_coordinates
    from .may_alias import _return_shape
    from .pcode_blocks import build_pcode_block_graph, has_internal_flow
    from .relative_memory import stack_offset_at

    observation = unit.observation
    evidence = unit.scopes.program.evidence
    if type(normalized) is not NormalizedFunction or observation is None or not observation.instructions \
            or not evidence.translation_namespace.language_id.startswith("x86:LE:64"):
        return None
    if build_pcode_block_graph(observation, unit.scopes.function.entry, frozenset()).unsupported is not None:
        return None
    registers = {row.space_id for row in evidence.address_spaces if row.is_register_space}
    uniques = {row.space_id for row in evidence.address_spaces if row.is_unique_space}
    memory_space = _program_memory_space(unit)
    if memory_space is None:
        return None

    def allowed(varnode) -> bool:
        space, start, size = varnode.coordinate.space_id, varnode.coordinate.byte_offset, varnode.byte_size
        if space in uniques:
            return True
        if space not in registers:
            return False
        return any(low <= start and start + size <= high for low, high in (*_X64_GENERAL, _X64_RIP)) \
            or all(byte in _X64_FLAGS for byte in range(start, start + size))

    local = {row.address for row in observation.instructions}
    returns = 0
    for row in observation.instructions:
        operations = row.operations
        if not operations or has_internal_flow(row) or row.flow.is_call or row.flow.is_override \
                or any(target not in local for target in row.flow_targets):
            return None
        for operation in operations:
            if operation.opcode in ("STORE", "CALL", "CALLIND", "CALLOTHER", "BRANCHIND"):
                return None
            if operation.output is not None and not allowed(operation.output):
                return None
        last = operations[-1]
        # the successors the p-code implies must be exactly the observed ones
        # the CFG (and so the callee's SSA) is built from
        if last.opcode == "RETURN":
            implied = set()
        elif last.opcode in ("BRANCH", "CBRANCH"):
            if last.inputs[0].kind is not VarnodeKindCode.ADDRESS or (
                    last.opcode == "CBRANCH" and row.fallthrough is None):
                return None
            implied = {last.inputs[0].coordinate} | ({row.fallthrough} if last.opcode == "CBRANCH" else set())
        elif row.fallthrough is None:
            return None
        else:
            implied = {row.fallthrough}
        if set(control_successor_coordinates(row)) != implied or not implied <= local:
            return None
        if last.opcode == "RETURN":
            if _return_shape(row) != ((0x20, 8), memory_space) or operations[0].output.byte_size != 8:
                return None   # the eight-byte pop return through RSP in the program's memory
            load = operations[0]
            stack = _resolve_validated_storage(_storage_ref(load.inputs[1]), unit.scopes.resolution_context)
            if load.inputs[1].coordinate.space_id not in registers or type(stack) is not ResolvedStorage \
                    or stack_offset_at(normalized.memory_ssa, observation, unit.scopes,
                                       _operation_key(row.address, 0, load.opcode), load.inputs[1], stack.span) != 0:
                return None
            returns += 1
    if not returns:
        return None
    entry = unit.scopes.function.entry
    return f"no calls, no stores, pop return at the entry stack pointer: {entry.space_id:x}:{entry.byte_offset:x}"


def _accessor_effect(effect, model_file, entry, register_object, memory_space, separate=False):
    """``effect`` with the entry's accessor claims (docs 25.20), under
    same-result-functions: its ``same_result`` and ``preserves_accessor_state``
    (``separate``: accessor-result-separate is on -- the extent too)."""
    if entry.same_result is not None:
        result, inputs, read, nonstack, write_back = entry.same_result
        effect = replace(effect, same_result=(
            entry.model_id, f"{entry.label}#{model_file.digest[:16]}", ByteSpan(register_object, *result),
            tuple(ByteSpan(register_object, *item) for item in inputs),
            AnchoredSpan(ByteSpan(register_object, *read.base), read.disp, read.size, memory_space), nonstack,
            write_back, entry.separate_extent if separate else None))
    if entry.preserves_accessor_state:
        effect = replace(effect, preserves_accessor_state=entry.preserves_accessor_state)
    return effect


def _program_memory_space(unit) -> int | None:
    """The program's single loaded memory space (models address it)."""
    spaces = [row.space_id for row in unit.scopes.program.evidence.address_spaces
              if row.is_memory_space and row.is_loaded_memory_space and not row.is_overlay_space
              and not row.is_external_space]
    return spaces[0] if len(spaces) == 1 else None


def _unproven_image_operands(unit) -> bool:
    """A data operand (ADDRESS varnode, not a branch or call target) neither
    proven an image address nor a fixed place outside the image by its
    instruction's encoding (``ImageBaseTracking.coefficient``)."""
    from .relative_memory import IMAGE_BASE_TRACKING

    tracking = IMAGE_BASE_TRACKING.get()
    for instruction in unit.observation.instructions:
        for operation in instruction.operations:
            flow = operation.opcode in ("BRANCH", "CBRANCH", "CALL", "BRANCHIND", "CALLIND")
            for index, varnode in enumerate((*operation.inputs, operation.output)):
                if varnode is None or varnode.kind is not VarnodeKindCode.ADDRESS or (flow and index == 0):
                    continue
                if tracking.coefficient(instruction.address.byte_offset, varnode.coordinate.byte_offset) is None:
                    return True
    return False


def _external_sites(unit, image_info, external_models, disabled=frozenset(), usable=None, refused=None,
                    local_functions=frozenset()) -> dict:
    """Call key -> (model file, entry) for calls to imported symbols with a
    model, at the import call shapes ``import_call_sites`` recognizes
    (``call [__imp_X]``, ``mov rax, [__imp_X]; call rax``, a terminal ``jmp
    [__imp_X]`` -- a tail call composed like ``BRANCH`` tails, ...). A model resting on an assumption
    switched off in this run (``disabled``) is not applied: the call stays
    opaque; so is one ``usable`` finds a reason against (put in ``refused``)."""
    found = {}
    for key, symbol in import_call_sites(unit, image_info, local_functions).items():
        model = external_models.lookup(symbol)
        if model is not None and (key.endswith(":CALLIND") or key.endswith(":BRANCHIND")):
            # bound through an import slot: the slot holds the export's address
            model = (model[0], replace(model[1], inherited=(*model[1].inherited, "import-slots-hold-their-exports")))
        if model is not None and model[1].noreturn and key.endswith(":BRANCH"):
            continue   # a jump to a function that never returns: ``_noreturn_jumps``
        if model is not None and set(model[1].inherited) & disabled:
            if refused is not None:
                off = ", ".join(sorted(set(model[1].inherited) & disabled))
                refused[key] = f"{model[1].label}: rests on {off}, switched off in this run"
            continue
        if model is not None:
            reason = usable(*model) if usable is not None else None
            if reason is not None:
                if refused is not None:
                    refused[key] = f"{model[1].label}: {reason}"
                continue
            found[key] = model
    return found


def _unplaced_noreturn(unit, proven) -> list:
    """Call / tail-jump keys whose effect never returns but whose instruction
    has an observed successor other than its own destination (and a call's
    fall-through) -- a landing pad, another jump target, inside the function
    or not: ``_dead_region`` would cut that edge too, so such an effect is
    not applied. (Validation leaves EXTERNAL-space targets out of
    ``flow_targets``: a ``jmp [slot]`` lists none.)"""
    from .control_projection import control_successor_coordinates

    observation = unit.observation
    rows = {(row.address.space_id, row.address.byte_offset): row for row in observation.instructions}
    local = {row.address for row in observation.instructions}
    entry = unit.scopes.function.entry
    found = []
    for key, effect in proven.items():
        if not effect.noreturn:
            continue
        space, offset, ordinal, opcode = key.split(":")
        row = rows.get((int(space, 16), int(offset, 16)))
        if row is None:
            continue
        operation = row.operations[int(ordinal)]
        kept = set()
        if opcode in ("BRANCH", "CALL") and operation.inputs                 and operation.inputs[0].kind is VarnodeKindCode.ADDRESS:
            kept.add(operation.inputs[0].coordinate)  # its own destination (an indirect one names a slot)
        if opcode in ("CALL", "CALLIND"):
            kept.add(row.fallthrough)  # the edge a call that never returns cuts
        observed = set(row.flow_targets) | set(
            control_successor_coordinates(row, local_addresses=local, function_entry=entry))
        if observed - kept:
            found.append(key)
    return found


def _noreturn_jumps(unit, image_info, external_models, calls, disabled=frozenset(), usable=None,
                    refused=None) -> dict:
    """Jump key -> (model file, entry) for a jump to an import thunk whose
    model never returns (``noreturn``, e.g. ``je abort``). Only shapes where
    the jump is the instruction's only way out of the function:
    - ``BRANCH``: the last operation of an instruction without internal flow,
      without a fall-through and whose observed flow targets are the thunk
      only, not a tail call to a Bundle function (``calls``, which composes
      the thunk's own summary) -- ``summarize_function`` cuts the path at it
      (``dead_ops``);
    - ``CBRANCH``: the last operation of an instruction without internal
      flow whose fall-through is in the function and whose observed flow
      targets are the thunk or in the function -- only its taken edge leaves,
      and never comes back (``summarize_function``'s ``noreturn_jumps``: not a
      tail exit; the fall-through path stays).
    The checks of ``_external_sites`` apply (switched-off assumptions,
    ``usable``)."""
    from .pcode_blocks import has_internal_flow

    observation = unit.observation
    if observation is None:
        return {}
    local = {row.address for row in observation.instructions}
    found = {}
    for row in observation.instructions:
        if not row.operations or has_internal_flow(row):
            continue
        ordinal = len(row.operations) - 1
        operation = row.operations[ordinal]
        if operation.opcode not in ("BRANCH", "CBRANCH") or not operation.inputs:
            continue
        target = operation.inputs[0]
        if target.kind is not VarnodeKindCode.ADDRESS or target.coordinate in local:
            continue
        key = _operation_key(row.address, ordinal, operation.opcode)
        if key in calls:
            continue
        if operation.opcode == "BRANCH" and (
                row.fallthrough is not None or any(item != target.coordinate for item in row.flow_targets)):
            continue
        if operation.opcode == "CBRANCH" and (
                row.fallthrough not in local
                or any(item != target.coordinate and item not in local for item in row.flow_targets)):
            continue
        symbol = image_info.import_at_thunk(target.coordinate.space_id, target.coordinate.byte_offset)
        model = external_models.lookup(symbol) if symbol is not None else None
        if model is None or not model[1].noreturn:
            continue
        if set(model[1].inherited) & disabled:
            if refused is not None:
                off = ", ".join(sorted(set(model[1].inherited) & disabled))
                refused[key] = f"{model[1].label}: rests on {off}, switched off in this run"
            continue
        reason = usable(*model) if usable is not None else None
        if reason is not None:
            if refused is not None:
                refused[key] = f"{model[1].label}: {reason}"
            continue
        found[key] = model
    return found


def import_call_sites(unit, image_info, local_functions=frozenset()) -> dict:
    """Call key -> imported symbol for the import call shapes the engine binds
    to models: ``CALL`` of an import thunk, a terminal ``BRANCH`` to one (``jmp
    free``: a tail call), ``CALLIND`` of a value copied from
    an import slot within the call instruction (``call [__imp_X]``), a
    terminal ``BRANCHIND`` through an import slot (``jmp [__imp_X]``), and a
    ``CALLIND`` of a register an import slot was loaded into on the only way
    into the call (``mov rax, [__imp_X]; call rax``, ``_slot_loaded_register``).
    ``local_functions``: entries (space id, offset) of the program's functions
    -- a jump to one of them is a tail call to that body (``_direct_calls``),
    never the import's model, even at an import thunk's address."""
    found = {}
    loaded = _slot_loaded_register(unit, image_info)
    for instruction in unit.observation.instructions:
        operations = instruction.operations
        for ordinal, operation in enumerate(operations):
            if not operation.inputs:
                continue
            symbol = None
            target = operation.inputs[0]
            key = _operation_key(instruction.address, ordinal, operation.opcode)
            if operation.opcode == "CALL" and target.kind is VarnodeKindCode.ADDRESS:
                symbol = image_info.import_at_thunk(target.coordinate.space_id, target.coordinate.byte_offset)
            elif operation.opcode == "BRANCH" and target.kind is VarnodeKindCode.ADDRESS \
                    and instruction.fallthrough is None and ordinal == len(operations) - 1 \
                    and all(item == target.coordinate for item in instruction.flow_targets) \
                    and (target.coordinate.space_id, target.coordinate.byte_offset) not in local_functions:
                # a terminal jmp to an import thunk outside the Bundle (a tail call;
                # a thunk that is a Bundle function is composed as its own summary)
                symbol = image_info.import_at_thunk(target.coordinate.space_id, target.coordinate.byte_offset)
            elif operation.opcode == "BRANCHIND" and target.kind is VarnodeKindCode.ADDRESS \
                    and instruction.fallthrough is None and ordinal == len(operations) - 1:
                symbol = image_info.import_at_slot(target.coordinate.space_id, target.coordinate.byte_offset)
            elif operation.opcode == "CALLIND":
                for copy in operations[:ordinal]:
                    if copy.opcode == "COPY" and copy.output == target \
                            and copy.inputs[0].kind is VarnodeKindCode.ADDRESS:
                        source = copy.inputs[0].coordinate
                        symbol = image_info.import_at_slot(source.space_id, source.byte_offset)
                if symbol is None:
                    symbol = loaded.get(key)
            if symbol is not None:
                found[key] = symbol
    return found


_CALL_OPCODES_ALL = ("CALL", "CALLIND", "CALLOTHER")


def _overlaps(varnode, other) -> bool:
    return varnode is not None and other is not None and varnode.kind is other.kind \
        and varnode.coordinate.space_id == other.coordinate.space_id \
        and varnode.coordinate.byte_offset < other.coordinate.byte_offset + other.byte_size \
        and other.coordinate.byte_offset < varnode.coordinate.byte_offset + varnode.byte_size


def _slot_loaded_register(unit, image_info) -> dict:
    """CALLIND key -> import for ``mov rax, [__imp_X]; call rax`` (the 09
    testbed's debug build calls its import DLL this way), on the engine's
    p-code block graph (``pcode_blocks``, the flow memory SSA uses):
    - the block B holding the CALLIND starts its instruction, is not the entry
      block and has exactly one predecessor block P (P is not B): every
      execution of the call comes from the end of P; P is a whole plain
      instruction falling through into B (``_plain_into``);
    - in B before the CALLIND: no call, and the target is the register R
      itself (no write overlapping R) or a temporary (``UNIQUE``; never
      memory, which a ``STORE`` may overwrite unnamed) whose last write is a
      COPY of R (no write overlapping R before that COPY);
    - in P: the last write overlapping R is a COPY of all of R from an import
      slot (P has no call that could change R with no output).
    Functions with a BRANCHIND (unknown targets) or an unsupported graph: none."""
    from .pcode_blocks import build_pcode_block_graph

    observation = unit.observation
    function = unit.scopes.function
    entry = getattr(function, "entry", None)
    if entry is None or any(operation.opcode == "BRANCHIND" for row in observation.instructions
                            for operation in row.operations):
        return {}
    graph = build_pcode_block_graph(observation, entry)
    if graph.unsupported is not None:
        return {}
    rows = {row.address: row for row in observation.instructions}
    predecessors: dict = {}
    for block in graph.blocks:
        for successor in block.successors:
            predecessors.setdefault(successor, []).append(block)
    found = {}
    for block in graph.blocks:
        row = rows[block.instruction]
        operations = row.operations[block.start:block.stop]
        for index, operation in enumerate(operations):
            if operation.opcode != "CALLIND" or not operation.inputs:
                continue
            target, prefix = operation.inputs[0], operations[:index]
            if any(item.opcode in _CALL_OPCODES_ALL for item in prefix):
                continue
            if target.kind is VarnodeKindCode.REGISTER:
                register, before = target, prefix
            elif target.kind is VarnodeKindCode.UNIQUE:
                # a temporary: only operations naming it write it (memory a
                # STORE may reach is not one)
                writes = [position for position, item in enumerate(prefix) if _overlaps(item.output, target)]
                if not writes:
                    continue
                last = prefix[writes[-1]]
                if last.opcode != "COPY" or last.output != target or last.inputs[0].kind is not VarnodeKindCode.REGISTER:
                    continue
                register, before = last.inputs[0], prefix[:writes[-1]]
            else:
                continue
            if any(_overlaps(item.output, register) for item in before):
                continue
            into = predecessors.get(block.key, [])
            if block.key == graph.entry or len(into) != 1 or into[0].key == block.key:
                continue
            source = into[0]
            if block.start != 0 or not _plain_into(rows[source.instruction], source, row.address):
                continue
            source_operations = rows[source.instruction].operations
            writes = [position for position, item in enumerate(source_operations) if _overlaps(item.output, register)]
            if not writes:
                continue
            last = source_operations[writes[-1]]
            if last.opcode != "COPY" or last.output != register or last.inputs[0].kind is not VarnodeKindCode.ADDRESS:
                continue
            slot = last.inputs[0].coordinate
            symbol = image_info.import_at_slot(slot.space_id, slot.byte_offset)
            if symbol is not None:
                found[_operation_key(row.address, block.start + index, operation.opcode)] = symbol
    return found


def _plain_into(source_row, source, call_address) -> bool:
    """P is a whole plain instruction that only falls through into the call
    instruction: no flow targets (no override, landing pad or jump), no flow
    override flag, not a call, and no branch, return or call operation -- so
    its operations all run, in order, before the call instruction, whatever
    the observed flow and the p-code would otherwise have to agree on."""
    return source.start == 0 and source.stop == len(source_row.operations) \
        and source_row.fallthrough == call_address and not source_row.flow_targets \
        and not source_row.flow.is_call and not source_row.flow.is_override \
        and not any(item.opcode in _CALL_OPCODES_ALL + ("BRANCH", "CBRANCH", "BRANCHIND", "RETURN")
                    for item in source_row.operations)


def _prove_extents(unit, normalized, proven, constants, rejected=None) -> bool:
    """Evaluate the ``~ext`` rows of model calls: a register proven constant at
    the call makes that model's variable-size effect exact (re-derive). The
    value must reach no debt (a write through another object or a call may
    have changed it); a constant taken earlier that this state no longer
    proves the same is withdrawn for good (``rejected``)."""
    from ._scope_contracts import AddressCoordinate, ValidatedVarnode
    from .normalize import _reaches_debt
    from .relative_memory import constant_values

    from .normalize import call_clobber_spans

    rejected = set() if rejected is None else rejected
    graph = normalized.dependencies
    clobbers = call_clobber_spans(normalized)
    context = unit.scopes.resolution_context

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
        slot = (span.start, span.size)
        value = values.get((key, varnode))
        if value is not None and _reaches_debt(graph, graph.node_for_key(f"op:{key}"), varnode, context,
                                               clobbers):
            value = None
        known = constants.get(call, {})
        if slot in known and known[slot] != value:
            del known[slot]  # the constant used before does not hold here
            rejected.add((call, slot))
            grown = True
        elif value is not None and slot not in known and (call, slot) not in rejected:
            constants.setdefault(call, {})[slot] = value
            grown = True
    return grown


def _is_tail(call_key: str) -> bool:
    """A tail jump site: ``BRANCH`` to a function, or ``BRANCHIND`` through an
    import slot (``_external_sites``)."""
    return call_key.endswith(":BRANCH") or call_key.endswith(":BRANCHIND")


def _bottom_summary(stack_pointers, shapes, call_key, program_stack):
    """The optimistic start for a recursive call site: one normal exit that
    writes nothing, with the stack pointer restored (undoing the call shape's
    push, or a pointer-sized ``ret`` for a tail jump). A call with no observed
    shape (its push kept as an operation) gets no delta: the caller cannot
    state the restore, the rounds find no fixpoint and the call stays opaque
    (sound; ``test_call_projection_shape``)."""
    from .function_summary import FUNCTION_SUMMARY_VERSION, ExitSummary

    deltas = tuple(((offset, size), -delta) for (offset, size), delta in shapes.get(call_key, {}).items())
    if _is_tail(call_key):
        deltas = tuple(((span.start, span.size), span.size) for span in program_stack)
    # (no stack-derived value out either: the rounds raise it like the rest)
    return FunctionSummary(FUNCTION_SUMMARY_VERSION, (ExitSummary("bottom", ()),), (), (),
                           register_deltas=deltas, stack_values_out=False)


def _recursive_hypothesis(derive, stack, notes=None):
    """A derived effect usable as a recursion hypothesis: conditional values
    and writer conditions failed (they would need the caller's decision inside
    the fixpoint), sink
    demands merged per label (writes below the callee's entry stack pointer,
    which would re-project deeper each round, are already folded into
    ``clobbers_below`` by ``derive_proven_call_effect``). ``notes`` (operation
    records only): set to the failed pairs and the last derivation's
    rejections (docs 25.31 C9-5)."""
    from dataclasses import replace
    from .call_summary_effects import ProvenSinkDemand

    failed: set = set()
    while True:
        rows = None if notes is None else []
        effect = derive(failed) if rows is None else derive(failed, rows)
        if notes is not None:
            notes.update(failed=frozenset(failed), rejections=tuple(rows))
        if effect is None:
            return None
        # writer conditions too: every claim of the effect rests on them
        pairs = {pair for run in (*effect.runs, *effect.memory_runs) for pair in run.conditions}             | set(effect.writer_conditions)
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


@measured("program_checks")
def program_switches_stack(units) -> dict[str, tuple[str, ...]]:
    """Entry key -> operations that may set the stack pointer to something
    other than "the stack pointer + a number" (a stack switch: fibers,
    coroutines;
    "unchecked" for a function that writes registers the check cannot tell
    apart); empty for ordinary programs. A switching program may run on a
    stack in static data, so the globals-vs-stack assumption is withdrawn for
    all of it. Functions without call or return shapes of their own are
    checked with the program's stack pointer (the call shapes' base register).
    These are the given units only: a Bundle holding part of a program is no
    evidence about the rest (``stack_evidence``)."""
    from .call_clobber import _preserved_stack_pointers
    from .may_alias import CALL_PRESERVED, _return_shape, _unit_stub, stack_switches

    units = list(units)
    # the program's stack pointer: the call shapes' base register, or the
    # register return shapes pop from
    pointers = {(span.start, span.size) for unit in units
                for spans in _preserved_stack_pointers(unit.observation, unit.scopes.resolution_context).values()
                for span in spans}
    pointers |= {shape[0] for unit in units for instruction in unit.observation.instructions
                 if (shape := _return_shape(instruction)) is not None}
    program_stack = next(iter(pointers)) if len(pointers) == 1 else None
    found = {}
    for unit in units:
        program = unit.scopes.program
        language = ":".join(program.evidence.translation_namespace.language_id.split(":")[:3])
        try:
            with activation(_ledger_key(unit)):
                rows = stack_switches(
                    _unit_stub(unit.scopes), unit.observation, unit.scopes.resolution_context,
                    program.evidence.address_spaces, program_stack, CALL_PRESERVED.get(language, ()),
                )
                checkpoint()
        except ANALYSIS_FAILURES as error:
            if _is_run_exhaustion(error):
                raise   # (a whole-program check left undone: the run fails)
            rows = ("unchecked",)   # a check that ran out of a resource is no evidence
        if rows:
            found[function_key(unit.scopes.function.entry)] = rows
    return found


def _model_cuts(functions, image_info, external_models, own_library, disabled) -> dict:
    """Function key -> (model file, entry with library-internal-model-cuts) for
    functions of ``own_library`` exported under a name an ``internal`` entry of
    a model file for that library lists."""
    from dataclasses import replace

    from .image_info import ImportedSymbol

    library = own_library.upper()
    names: dict = {}
    for export in image_info.exports:
        names.setdefault(function_key_of(export.space_id, export.byte_offset), []).append(export.name)
    found = {}
    for key in functions:
        for name in names.get(key, ()):
            model = external_models.lookup(ImportedSymbol(library, name, name, (), ()))
            if model is None or not model[1].internal or library not in model[0].libraries \
                    or set(model[1].inherited) & disabled or model[1].refusal is not None:
                continue
            model_file, entry = model
            found[key] = (model_file, replace(entry, inherited=(*entry.inherited, "library-internal-model-cuts")))
            break
    return found


def _cut_sites(unit, cuts) -> dict:
    """Call key -> model for direct calls and tail jumps to a cut function."""
    if not cuts:
        return {}
    return {call: cuts[callee] for call, callee in _direct_calls(unit, cuts).items()}


def function_key_of(space_id: int, byte_offset: int) -> str:
    return f"{space_id:x}:{byte_offset:x}"


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
    # a side located through a value with debt is not located: its address
    # could be another (the anchor read may have been changed)
    from .normalize import _reaches_debt, call_clobber_spans
    graph = normalized.dependencies
    clobbers = call_clobber_spans(normalized)
    located = {
        item: span for item, span in located.items()
        if span is not None and not _reaches_debt(
            graph, graph.node_for_key(f"op:{item[0]}"), item[1], unit.scopes.resolution_context, clobbers)
    }
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


def _forward_switched_on() -> bool:
    """Forward facts feed the indirect rounds (docs 25.33 F1b) only with
    ``TDO_V2_FORWARD=1``: off, the analysis is exactly as without them."""
    import os

    return os.environ.get("TDO_V2_FORWARD") == "1"


def _forward_targets(item, functions, readonly_image) -> tuple[dict, dict]:
    """CALLIND key -> the sorted Bundle functions a forward fact proves it
    reaches (every member an exact function entry, at most ``MAX_CANDIDATES``),
    with the fact's ``requires`` per call. Facts of the round's normalization
    (``forward.forward_facts``)."""
    from .forward import MAX_CANDIDATES, forward_facts

    normalized = item.normalized
    if type(normalized) is not NormalizedFunction or normalized.forward_inputs is None:
        return {}, {}
    space = item.unit.scopes.function.entry.space_id
    found, labels = {}, {}
    for fact in forward_facts(normalized, item.unit, readonly_image=readonly_image):
        if not fact.operation.endswith(":CALLIND") or fact.claim.is_top:
            continue
        members, ok = set(), True
        for base, interval in fact.claim.items:
            if base != ("abs",) or (interval.stride and (interval.hi - interval.lo) // interval.stride
                                    + 1 > MAX_CANDIDATES):
                ok = False
                break
            members.update(range(interval.lo, interval.hi + 1, interval.stride or 1))
        keys = sorted(f"{space:x}:{value:x}" for value in members)
        if ok and 0 < len(keys) <= MAX_CANDIDATES and all(key in functions for key in keys):
            found[fact.operation] = tuple(keys)
            labels[fact.operation] = frozenset(fact.requires)
    return found, labels


@measured("indirect_targets")
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
    values = constant_values(normalized, item.unit.observation, [(copy, varnode) for _, copy, varnode in sites],
                             addresses=True)
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
        accesses += list(effect.unknown_memory)
        accesses += [load for demand in effect.sink_demands for load in demand.loads]
        # both sides of the alias conditions the call carries (a side may be an
        # object only the condition mentions)
        accesses += [side for run in (*effect.runs, *effect.memory_runs) for pair in run.conditions
                     for side in pair]
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
    # objects built on an import slot's value (import-slots-hold-their-exports):
    # anchored on the slot as any pointer read from entry memory is
    from .relative_memory import IMPORT_SLOTS, import_object_ids

    imports = IMPORT_SLOTS.get()
    if imports is not None:
        pointer_bytes = {row.space_id: row.address_size_bits // 8
                         for row in unit.scopes.program.evidence.address_spaces}
        for span in registers:
            # the slot read whole at its space's pointer width (as the import
            # atom itself requires): a narrower read of it anchors nothing here
            if span.object_id.kind is not Kind.ADDRESS_SPACE                     or span.size != pointer_bytes.get(span.object_id.space_key):
                continue
            atom = imports.atom(span.object_id.space_key, span.start)
            if atom is None:
                continue
            for space_id in spaces:
                for object_id in import_object_ids(unit.scopes.function.scope, atom, space_id):
                    candidates.setdefault(object_id, (span, space_id))
    used = {atom.object_id for atom in normalized.memory_ssa.atomic_spans}
    # objects of the open conditions this function passes to its callers
    used |= {span.object_id for _, pairs in getattr(normalized, "open_nodes", ()) for pair in pairs
             for span in pair}
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
