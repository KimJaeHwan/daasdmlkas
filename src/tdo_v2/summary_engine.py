"""Bundle analysis on callee summaries (interprocedural S1c).

``analyze_frozen_bundle_with_summaries`` replaces the per-root interprocedural
completion of ``engine.analyze_frozen_bundle`` with the bottom-up summary
layer (``interprocedural.analyze_units``): every function is normalized with
the proven effects of its summarized callees, so a sink root's local slice
already reaches through calls. Source labels become origin nodes:

* a TEST-ONLY declared source call (``assume_boundary_call_effects``): the
  declared effect is a call effect like a summary or a model
  (``interprocedural`` ``declared_boundaries``, labelled
  ``test-only-boundary:<label>`` in ``EngineRun.assumptions``), so its run
  outputs carry the label as below;
* a call to a source function inside the Bundle: the summarized run outputs
  that write the source's state (its return register);
* a summarized call whose runs reached a source inside the callee: those run
  outputs (carried by the summaries).

``EngineRun.assumptions`` also lists "opaque-callees-restore-stack-pointer"
when some call's callee is not summarized (its stack pointer restore is the
call-shape rule, not proven).

``assume_globals_disjoint_from_stack`` (on by default) applies the named
assumption of ``may_alias`` (constant addresses never alias the stack) unless some
function switches its stack (``interprocedural.program_switches_stack``); the
run lists it in ``EngineRun.assumptions`` when it was applied.

Sink roots are bound as in the engine (call sites and tail calls); a sink
whose argument state has no exact graph definition is bound to the call
operation itself (an unbound, incomplete root -- never dropped). A sink root
inside a summarized callee (a sink wrapper, also nested) is projected to each
caller as a root at the call (``~sink<k>`` effect: the caller's values of the
entry bytes the callee root needs); it is complete only if the callee part
is.
"""

from __future__ import annotations

from .phases import phase

import os
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

from .boundary import BoundaryKind, BoundaryProvider, CallBoundary
from .call_seeds import _operation_key
from .configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from .engine import (
    EngineRun, RootSlice, _unbound_roots, _with_unbound, assumed_boundary_effects,
)
from .integration.configured_target_resolution import _selected_resolved_target
from .integration.observed_function_session import open_observed_function_session
from .interprocedural import (
    ANALYSIS_FAILURES, _failure_detail, _failure_reason, _is_run_exhaustion, _ledger_key, analyze_units,
    function_key, run_definition_nodes,
)
from .image_info import ReadOnlyImage, load_image_info
from .normalize import NormalizationFailureReason, NormalizedFunction
from .observed_call_state import observed_call_state_projections
from .pcodeop_models import trap_operations
from .physical_state import PhysicalRegisterSlice
from .span_geometry import StorageObjectKind
from .call_clobber import debt_identity
from .query_contracts import LocalCompleteness, local_completeness
from .resource_limits import (
    activation, analysis_entry, checkpoint, current_run, limit, reporting, run_exhausted, step,
)
from .scope_identity import ConstructedProgramScope


def _x86_64(evidences) -> bool:
    for item in evidences:
        return item.unit.scopes.program.evidence.translation_namespace.language_id.startswith("x86:LE:64")
    return False


def _tail_boundaries(evidence):
    """CallBoundary per tail jump of one function (as ``_bind_tail_call_sinks``)."""
    unit = evidence.unit
    entry = unit.scopes.function.entry
    language = unit.scopes.program.evidence.translation_namespace.language_id
    found = []
    for tail, naming in zip(evidence.tails, evidence.naming.tail_rows, strict=True):
        target = _selected_resolved_target(naming)
        aliases = tuple(sorted({alias.value for alias in (() if target is None else target.aliases)
                                if alias.policy_admissible}))
        found.append(CallBoundary(f"{entry.space_id:x}:{entry.byte_offset:x}", tail.operation_key, aliases,
                                  language))
    return found


def _boundaries(evidence):
    """(seed, CallBoundary) per call site of one function."""
    unit = evidence.unit
    entry = unit.scopes.function.entry
    caller = f"{entry.space_id:x}:{entry.byte_offset:x}"
    language = unit.scopes.program.evidence.translation_namespace.language_id
    rows = []
    for seed, naming in zip(evidence.seeds.callsites, evidence.naming.rows, strict=True):
        target = _selected_resolved_target(naming)
        aliases = tuple(sorted({
            alias.value for alias in (() if target is None else target.aliases)
            if alias.policy_admissible
        }))
        rows.append((seed, CallBoundary(caller, seed.operation_key, aliases, language)))
    return rows


@analysis_entry
def analyze_frozen_bundle_with_summaries(
    generation_path: str | Path,
    *,
    naming_exporter_source: str | Path,
    boundary_provider: BoundaryProvider,
    assume_boundary_call_effects: bool = False,
    assume_globals_disjoint_from_stack: bool = True,
    external_models=None,
    lifecycle_contracts=(),
    assume_readonly_image_constant: bool = True,
    assume_direction_flag_clear: bool = True,
    pcodeop_models=None,
    assume_win64_home_space_private: bool = True,
    assume_debug_break_traps_do_not_return: bool = True,
    stack_evidence=(),
    linker=None,
    assume_import_slots_hold_exports: bool = True,
    assume_entry_values_not_frame: bool = True,
    assume_opaque_callees_leave_no_stack_addresses: bool = True,
    assume_pre_escape_values_not_frame: bool = True,
    origin_witnesses: bool = False,
    operation_records: bool = False,
    physical_memory_records: bool = False,
    assume_same_result_functions: bool = False,
    assume_accessor_result_separate: bool = False,
    assume_accessor_private_state: bool = False,
    model_bindings=(),
    assume_registered_handlers_not_observed: bool = True,
    disabled_model_assumptions=(),
) -> EngineRun:
    """``assume_same_result_functions``: the named assumption
    same-result-functions (off by default; model entries with ``same_result``);
    ``assume_accessor_result_separate``: accessor-result-separate (off by
    default; their ``result_separate_from_reads`` extents);
    ``assume_accessor_private_state``: accessor-private-state (off by
    default); ``assume_registered_handlers_not_observed``:
    registered-handlers-are-not-observed (on by default: model entries
    declaring callbacks.registered apply); ``model_bindings``: ``summary_store.ModelBinding`` files for
    this binary's unexported functions (docs 25.20 F). ``disabled_model_assumptions``:
    model assumptions switched off (``interprocedural.analyze_units``).
    ``origin_witnesses``: put per-root origin witnesses (diagnostics,
    ``origin_witnesses``) in ``RootSlice.explanation``.
    ``operation_records``: put each root's operation record (diagnostics,
    ``operation_records``, docs 25.28) in ``RootSlice.explanation["record"]``.
    ``physical_memory_records``: include opt-in concrete physical memory and
    call evidence in those diagnostic records; implies ``operation_records``
    without changing summaries, assumptions or static eligibility.
    ``external_models``: declared models of imported functions
    (``summary_store.ExternalModels``), bound through the Bundle's sealed image
    facts (``image_info``); each model used is listed in ``EngineRun.assumptions``.
    ``stack_evidence``: whole-program stack-switch evidence (``stack_evidence``)
    for the program and the libraries it runs with: a switch in any of them
    withdraws globals-disjoint-from-stack (``stack_evidence.assumption_allowed``).
    ``linker``: ``linking.Linker`` -- called once with the functions and image
    facts before the analysis; it returns the model set with the linked
    libraries' templates and their stack evidence (joining ``stack_evidence``)."""
    from .integration.configured_boundary_demands import (
        _analyses_from_boundary_nodes, _direct_sink_boundary_nodes,
    )
    from .integration.configured_function_view import _FunctionView
    from .integration.configured_interprocedural_contracts import ConfiguredFunctionAnalysis
    from .integration.configured_interprocedural_slice import _bind_tail_call_sinks
    from .integration.configured_bundle import admit_frozen_bundle  # POSIX-only
    from .observed_boundary_projection import EMPTY_OBSERVED_BOUNDARIES, ObservedBoundaryNode

    binding = NamingBindingExpectation(
        sha256(Path(naming_exporter_source).read_bytes()).digest(), CALL_NAMING_GHIDRA_VERSION,
    )
    with open_observed_function_session(
        admit_frozen_bundle(generation_path), naming_binding=binding
    ) as session:
        program = session.program_result
        if type(program) is not ConstructedProgramScope:
            raise ValueError("Bundle program scope is unresolved")
        image_info = load_image_info(generation_path)
        readonly_image = (
            ReadOnlyImage(generation_path, image_info)
            if assume_readonly_image_constant and image_info is not None else None
        )
        return _analyze_session(
            program, list(session.iter_functions()), image_info, readonly_image,
            boundary_provider=boundary_provider,
            assume_boundary_call_effects=assume_boundary_call_effects,
            assume_globals_disjoint_from_stack=assume_globals_disjoint_from_stack,
            external_models=external_models,
            lifecycle_contracts=lifecycle_contracts,
            assume_direction_flag_clear=assume_direction_flag_clear,
            pcodeop_models=pcodeop_models,
            assume_win64_home_space_private=assume_win64_home_space_private,
            assume_debug_break_traps_do_not_return=assume_debug_break_traps_do_not_return,
            stack_evidence=stack_evidence,
            linker=linker,
            assume_import_slots_hold_exports=assume_import_slots_hold_exports,
            assume_entry_values_not_frame=assume_entry_values_not_frame,
            assume_opaque_callees_leave_no_stack_addresses=assume_opaque_callees_leave_no_stack_addresses,
            assume_pre_escape_values_not_frame=assume_pre_escape_values_not_frame,
            origin_witnesses=origin_witnesses,
            operation_records=operation_records,
            physical_memory_records=physical_memory_records,
            assume_same_result_functions=assume_same_result_functions,
            assume_accessor_result_separate=assume_accessor_result_separate,
            assume_accessor_private_state=assume_accessor_private_state,
            model_bindings=model_bindings,
            assume_registered_handlers_not_observed=assume_registered_handlers_not_observed,
            disabled_model_assumptions=disabled_model_assumptions,
        )


@analysis_entry
def analyze_observed_with_summaries(program, evidences, *, image_info=None, readonly_image=None,
    boundary_provider: BoundaryProvider,
    assume_boundary_call_effects: bool = False,
    assume_globals_disjoint_from_stack: bool = True,
    external_models=None,
    lifecycle_contracts=(),
    assume_direction_flag_clear: bool = True,
    pcodeop_models=None,
    assume_win64_home_space_private: bool = True,
    assume_debug_break_traps_do_not_return: bool = True,
    stack_evidence=(),
    linker=None,
    assume_import_slots_hold_exports: bool = True,
    assume_entry_values_not_frame: bool = True,
    assume_opaque_callees_leave_no_stack_addresses: bool = True,
    assume_pre_escape_values_not_frame: bool = True,
    origin_witnesses: bool = False,
    operation_records: bool = False,
    physical_memory_records: bool = False,
    assume_same_result_functions: bool = False,
    assume_accessor_result_separate: bool = False,
    assume_accessor_private_state: bool = False,
    model_bindings=(),
    assume_registered_handlers_not_observed: bool = True,
    disabled_model_assumptions=(),
) -> EngineRun:
    """The summary engine on already-admitted evidences (the in-memory path:
    synthetic programs, docs 25.30 K2) -- the same analysis as
    ``analyze_frozen_bundle_with_summaries`` after admission; ``image_info`` /
    ``readonly_image`` as that entry derives them from a Bundle (None: no
    image facts)."""
    return _analyze_session(
        program, list(evidences), image_info, readonly_image,
        boundary_provider=boundary_provider,
        assume_boundary_call_effects=assume_boundary_call_effects,
        assume_globals_disjoint_from_stack=assume_globals_disjoint_from_stack,
        external_models=external_models,
        lifecycle_contracts=lifecycle_contracts,
        assume_direction_flag_clear=assume_direction_flag_clear,
        pcodeop_models=pcodeop_models,
        assume_win64_home_space_private=assume_win64_home_space_private,
        assume_debug_break_traps_do_not_return=assume_debug_break_traps_do_not_return,
        stack_evidence=stack_evidence,
        linker=linker,
        assume_import_slots_hold_exports=assume_import_slots_hold_exports,
        assume_entry_values_not_frame=assume_entry_values_not_frame,
        assume_opaque_callees_leave_no_stack_addresses=assume_opaque_callees_leave_no_stack_addresses,
        assume_pre_escape_values_not_frame=assume_pre_escape_values_not_frame,
        origin_witnesses=origin_witnesses,
        operation_records=operation_records,
        physical_memory_records=physical_memory_records,
        assume_same_result_functions=assume_same_result_functions,
        assume_accessor_result_separate=assume_accessor_result_separate,
        assume_accessor_private_state=assume_accessor_private_state,
        model_bindings=model_bindings,
        assume_registered_handlers_not_observed=assume_registered_handlers_not_observed,
        disabled_model_assumptions=disabled_model_assumptions,
    )


def _analyze_session(program, evidences, image_info, readonly_image, *,
    boundary_provider: BoundaryProvider,
    assume_boundary_call_effects: bool = False,
    assume_globals_disjoint_from_stack: bool = True,
    external_models=None,
    lifecycle_contracts=(),
    assume_direction_flag_clear: bool = True,
    pcodeop_models=None,
    assume_win64_home_space_private: bool = True,
    assume_debug_break_traps_do_not_return: bool = True,
    stack_evidence=(),
    linker=None,
    assume_import_slots_hold_exports: bool = True,
    assume_entry_values_not_frame: bool = True,
    assume_opaque_callees_leave_no_stack_addresses: bool = True,
    assume_pre_escape_values_not_frame: bool = True,
    origin_witnesses: bool = False,
    operation_records: bool = False,
    physical_memory_records: bool = False,
    assume_same_result_functions: bool = False,
    assume_accessor_result_separate: bool = False,
    assume_accessor_private_state: bool = False,
    model_bindings=(),
    assume_registered_handlers_not_observed: bool = True,
    disabled_model_assumptions=(),
) -> EngineRun:
    """The post-admission body of the summary engine (unchanged)."""
    operation_records = operation_records or physical_memory_records
    from .integration.configured_boundary_demands import (
        _analyses_from_boundary_nodes, _direct_sink_boundary_nodes,
    )
    from .integration.configured_function_view import _FunctionView
    from .integration.configured_interprocedural_contracts import ConfiguredFunctionAnalysis
    from .integration.configured_interprocedural_slice import _bind_tail_call_sinks
    from .observed_boundary_projection import EMPTY_OBSERVED_BOUNDARIES, ObservedBoundaryNode

    if type(program) is not ConstructedProgramScope:
        raise ValueError("program scope is unresolved")
    evidences = list(evidences)
    by_key = {function_key(item.unit.scopes.function.entry): item for item in evidences}
    assumed = {
        key: assumed_boundary_effects(item, boundary_provider)
        for key, item in by_key.items()
    } if assume_boundary_call_effects else {}
    boundaries = {key: _boundaries(item) for key, item in by_key.items()}

    def own_sink_nodes(analysis, view):
        """ObservedBoundaryNode SINK rows of the function's own boundaries."""
        key = function_key(analysis.entry)
        rows: list = []
        for occurrence, (seed, boundary) in enumerate(boundaries[key]):
            position = view.position(seed.operation_key)
            if position is None:
                continue
            for match in boundary_provider.classify(boundary):
                if match.kind is BoundaryKind.SINK:
                    bound = _direct_sink_boundary_nodes(
                        view, match.label, seed.operation_key, position, occurrence,
                        boundary_provider.state(boundary, match),
                    )
                    if not bound:  # unrepresentable state: unbound root, not a lost one
                        node = analysis.normalized.dependencies.node_for_key(f"op:{seed.operation_key}")
                        bound = (ObservedBoundaryNode(BoundaryKind.SINK, match.label, node, occurrence, 0),)
                    rows.extend(bound)
        tails = {analysis.entry: []}
        _bind_tail_call_sinks((analysis,), {analysis.entry: view}, boundary_provider, tails)
        return rows + tails[analysis.entry]

    def sink_roots(key, unit, normalized):
        analysis = ConfiguredFunctionAnalysis(by_key[key], normalized, EMPTY_OBSERVED_BOUNDARIES, ())
        groups: dict = {}
        for row in own_sink_nodes(analysis, _FunctionView(analysis)):
            groups.setdefault((row.label, row.occurrence_ordinal), []).append(row.node)
        return [
            (label, tuple(sorted(set(group))), not _unbound_roots(normalized, group, label))
            for (label, _), group in sorted(groups.items())
        ]

    def source_matches(boundary):
        return [match for match in boundary_provider.classify(boundary)
                if match.kind is BoundaryKind.SOURCE]

    def extra_origins(key, unit, normalized, calls):
        origins: dict = {}
        proven = dict(normalized.proven_call_effects)
        for seed, boundary in boundaries[key]:
            for match in source_matches(boundary):
                call = seed.operation_key
                # summarized, modeled or TEST-ONLY declared: all are call effects
                state = {
                    offset for selector in boundary_provider.state(boundary, match)
                    if type(selector) is PhysicalRegisterSlice
                    for offset in range(selector.byte_offset, selector.byte_offset + selector.byte_size)
                }
                nodes = [
                    node
                    for index, run in enumerate(proven[call].runs)
                    if any(offset in state for span in run.writes
                           for offset in range(span.start, span.end))
                    for node in run_definition_nodes(normalized, f"{call}~{index}")
                ] if call in proven else []
                # state the call is not proven to write (an unsummarized or
                # partly opaque source): its later reads carry call-clobber
                # debt naming this call -- the debt is where the value may
                # come from, so it carries the label (the root stays unsure)
                nodes += [
                    node
                    for row, debts in zip(normalized.call_clobber_reads, normalized.call_clobber_debts)
                    for crossing, node in zip(row.intervening_calls, debts)
                    if crossing == call and any(
                        span.object_id.kind is StorageObjectKind.REGISTER_FILE
                        and any(offset in state for offset in range(span.start, span.end))
                        for span in row.spans
                    )
                ]
                for node in nodes:
                    origins.setdefault(node, set()).add(match.label)
        return origins

    # named assumption win64-home-space-callee-private: the Windows x64
    # convention only (a PE image of a 64-bit x86 language)
    home_space = 0x28 if assume_win64_home_space_private and assume_entry_values_not_frame \
        and image_info is not None             and image_info.executable_format.startswith("Portable Executable") and _x86_64(evidences) else 0
    from .stack_evidence import assumption_allowed

    if stack_evidence:
        assume_globals_disjoint_from_stack, _ = assumption_allowed(
            stack_evidence, requested=assume_globals_disjoint_from_stack)
    if linker is not None:
        from .interprocedural import program_switches_stack
        from .stack_evidence import load_stack_evidence

        # the linked templates are derived with the run's effective
        # settings: the program's own withdrawals first
        if assume_globals_disjoint_from_stack and program_switches_stack([item.unit for item in evidences]):
            assume_globals_disjoint_from_stack = False
        external_models, linked_evidence = linker(
            [item.unit for item in evidences], image_info, external_models=external_models,
            pcodeop_models=pcodeop_models, private_frame_above=home_space,
            traps=assume_debug_break_traps_do_not_return,
            globals_disjoint=assume_globals_disjoint_from_stack, direction_flag=assume_direction_flag_clear,
            import_slots=assume_import_slots_hold_exports, entry_values_not_frame=assume_entry_values_not_frame,
            opaque_no_stack=assume_opaque_callees_leave_no_stack_addresses,
            pre_escape=assume_pre_escape_values_not_frame,
            same_result=assume_same_result_functions, accessor_separate=assume_accessor_result_separate,
            registered_handlers=assume_registered_handlers_not_observed,
            accessor_private_state=assume_accessor_private_state,
            model_assumptions_off=tuple(disabled_model_assumptions),
            catalog_models=tuple(item.models for item in model_bindings))
        linked_evidence = tuple(load_stack_evidence(path) for path in linked_evidence)
        if linked_evidence:
            # a switch in a linked library withdraws the assumption for the run
            stack_evidence = (*stack_evidence, *linked_evidence)
            assume_globals_disjoint_from_stack, _ = assumption_allowed(
                stack_evidence, requested=assume_globals_disjoint_from_stack)
    # (operation records only, docs 25.31 C9-5: id(AnalyzedFunction) -> (it, CallProvenance))
    record_provenance: dict | None = {} if operation_records else None
    results = analyze_units(
        [item.unit for item in evidences], declared_boundaries=assumed, extra_origins=extra_origins,
        assume_globals_disjoint_from_stack=assume_globals_disjoint_from_stack,
        sink_roots=sink_roots,
        # the image facts serve models and the import-slot assumption
        # alike (every model use is guarded on external_models)
        image_info=image_info,
        external_models=external_models,
        lifecycle_contracts=lifecycle_contracts,
        pcodeop_models=pcodeop_models,
        readonly_image=readonly_image,
        assume_direction_flag_clear=assume_direction_flag_clear,
        private_frame_above=home_space,
        assume_debug_break_traps_do_not_return=assume_debug_break_traps_do_not_return,
        assume_import_slots_hold_exports=assume_import_slots_hold_exports,
        assume_entry_values_not_frame=assume_entry_values_not_frame,
        assume_opaque_callees_leave_no_stack_addresses=assume_opaque_callees_leave_no_stack_addresses,
        assume_pre_escape_values_not_frame=assume_pre_escape_values_not_frame,
        assume_same_result_functions=assume_same_result_functions,
        assume_accessor_result_separate=assume_accessor_result_separate,
        assume_accessor_private_state=assume_accessor_private_state,
        model_bindings=tuple(model_bindings),
        assume_registered_handlers_not_observed=assume_registered_handlers_not_observed,
        disabled_model_assumptions=tuple(disabled_model_assumptions),
        record_provenance=record_provenance,
    )
    assumptions = run_assumptions(results, readonly_image=readonly_image, home_space=home_space,
                                  traps=assume_debug_break_traps_do_not_return, pcodeop_models=pcodeop_models)
    preliminary = []
    failed: dict = {}   # function key -> (NormalizationFailureReason, detail)
    for key, item in by_key.items():
        if key not in results:
            # a function a model binding cuts (``interprocedural._bound_cuts``):
            # its callers take the model; it must hold no boundary of its own
            if any(boundary_provider.classify(boundary) for _, boundary in boundaries.get(key, ())) \
                    or any(boundary_provider.classify(boundary) for boundary in _tail_boundaries(item)):
                raise ValueError(f"function {key} is bound to a model but has source / sink calls")
            continue
        normalized = results[key].normalized
        if type(normalized) is not NormalizedFunction:
            # a typed refusal of an admitted function (a resource failure or
            # an unsupported shape): it fails alone -- its callers saw an
            # opaque call; its sink occurrences are failure roots (docs 25.30 K1c)
            failed[key] = (normalized.reason, results[key].failure_detail)
            continue
        preliminary.append(ConfiguredFunctionAnalysis(item, normalized, EMPTY_OBSERVED_BOUNDARIES, ()))
    nodes: dict = {}
    incomplete_roots: set = set()  # (entry, label, occurrence) of projected roots

    def bind(analysis):
        """The function's ObservedBoundaryNode rows (its origins, own sinks
        and projected roots)."""
        key = function_key(analysis.entry)
        rows = []
        view = _FunctionView(analysis)
        for fragment, (node, labels) in enumerate(sorted(results[key].origins.items())):
            for label in sorted(labels):
                rows.append(ObservedBoundaryNode(BoundaryKind.SOURCE, label, node, 0, fragment))
        rows.extend(own_sink_nodes(analysis, view))
        # projected roots: occurrences after the function's own call sites and tails
        base = len(analysis.evidence.seeds.callsites) + len(analysis.evidence.tails)
        for index, (call, _, label, root_nodes, complete) in enumerate(results[key].projected_sinks):
            occurrence = base + index
            if not root_nodes:  # the ~sink row did not materialize: bind the call
                root_nodes = [analysis.normalized.dependencies.node_for_key(f"op:{call}")]
                complete = False
            for fragment, node in enumerate(root_nodes):
                rows.append(ObservedBoundaryNode(BoundaryKind.SINK, label, node, occurrence, fragment))
            if not complete:
                incomplete_roots.add((analysis.entry, label, occurrence))
        return rows

    def function_roots(analysis):
        """The RootSlices of one bound function."""
        key = function_key(analysis.entry)
        unit = by_key[key].unit
        found = []
        for label, occurrence, root_nodes, results_for_root, node_labels in _raw_root_groups(
                analysis, nodes[analysis.entry]):
            unbound = _unbound_roots(analysis.normalized, root_nodes, label)
            completeness = _with_unbound(local_completeness(results_for_root, debt_identity(
                getattr(analysis.normalized, "call_clobber_reads", ()),
                getattr(analysis.normalized, "call_clobber_debts", ()))), unbound)
            inherited = (analysis.entry, label, occurrence) in incomplete_roots
            if inherited:
                # the callee part of a projected root is incomplete
                completeness = replace(completeness, complete=False)
            labels = _lane_origin_labels(analysis, unit, nodes[analysis.entry], label, occurrence, node_labels,
                                         lane_indexes)
            explanation = _witnesses(analysis, unit, nodes[analysis.entry], label, occurrence, labels,
                                     node_labels, lane_indexes, results[key].origins) \
                if origin_witnesses else {}
            from .integration.configured_physical_binding_graph import physical_binding_graph
            binding_graph = physical_binding_graph(analysis, nodes[analysis.entry], label, occurrence)
            if binding_graph:
                explanation["physical_binding_graph"] = binding_graph
            if operation_records:   # (built after the final completeness: ``_with_records``)
                record_inputs[(analysis.entry.space_id, analysis.entry.byte_offset, label, occurrence)] = (
                    analysis, unit, nodes[analysis.entry], results[key])
            found.append(RootSlice(
                analysis.entry.space_id, analysis.entry.byte_offset, label, occurrence, root_nodes,
                tuple(sorted(labels)),
                (), explanation, completeness, completeness, inherited,
            ))
            limit("output_items", len(found))
        return found

    # sink binding and root slicing per function: a function that runs out
    # of a resource there fails alone (its partial rows are dropped)
    analyses = []
    late: set = set()   # failed after the analysis: their summaries were used

    def fail_late(analysis, error):
        key = function_key(analysis.entry)
        failed[key] = (_failure_reason(error), _failure_detail(error))
        late.add(key)

    def run_budget(remaining):
        """Finalization: every function not yet done (docs 25.30 K1c-3)."""
        run = current_run()
        detail = f"run:{run.exhausted if run is not None and run.exhausted else 'unknown'}"
        for analysis in remaining:
            key = function_key(analysis.entry)
            failed[key] = (NormalizationFailureReason.ANALYSIS_RUN_BUDGET, detail)
            late.add(key)

    for index, analysis in enumerate(preliminary):
        if run_exhausted():
            run_budget(preliminary[index:])
            break
        try:
            with activation(_ledger_key(analysis.evidence.unit)), phase("binding"):
                rows = bind(analysis)
                bound = _analyses_from_boundary_nodes((analysis,), {analysis.entry: rows})
                checkpoint()   # (limits checked before the rows are kept)
                nodes[analysis.entry] = rows
                analyses.extend(bound)
        except ANALYSIS_FAILURES as error:
            nodes.pop(analysis.entry, None)
            incomplete_roots.difference_update(
                {row for row in incomplete_roots if row[0] == analysis.entry})
            if _is_run_exhaustion(error):
                run_budget(preliminary[index:])
                break
            fail_late(analysis, error)
    roots = []
    lane_indexes: dict = {}
    record_inputs: dict = {}   # (operation records, built after reporting)
    for key in LANE_DIAGNOSTICS:   # per run
        LANE_DIAGNOSTICS[key] = 0
    for index, analysis in enumerate(analyses):
        if run_exhausted():
            run_budget(analyses[index:])
            break
        try:
            with activation(_ledger_key(analysis.evidence.unit)), phase("roots"):
                found_roots = function_roots(analysis)
                checkpoint()
                roots.extend(found_roots)
        except ANALYSIS_FAILURES as error:
            lane_indexes.pop(id(analysis.normalized), None)
            if _is_run_exhaustion(error):
                run_budget(analyses[index:])
                break
            fail_late(analysis, error)

    def report():
        checkpoint()
        found = _dependents_incomplete(roots, late, results, by_key) if late else list(roots)
        checkpoint()
        for key in sorted(failed):
            found.extend(_failure_roots(by_key[key], boundaries[key], boundary_provider, failed[key][0]))
            checkpoint()
        run = EngineRun(
            program.scope.digest.hex(), program.evidence.executable_sha256.hex(), tuple(found),
            assumptions, tuple((key, failed[key][0].value, failed[key][1]) for key in sorted(failed)),
        )
        checkpoint()   # (never returned after the reporting deadline)
        return run

    with reporting(), phase("reporting"):   # (bounded: TDO_V2_REPORTING_SECONDS; no analysis)
        run = report()
    if operation_records:
        run = _with_records(run, record_inputs, record_provenance,
                            physical_memory_records=physical_memory_records)
    return run


def _with_records(run, record_inputs, provenance=None, *, physical_memory_records=False) -> "EngineRun":
    """Each root's operation record (diagnostics, docs 25.28), built after
    every root's completeness is final (late failures included) and under
    its own diagnostic budget (docs 25.31 C9-0): records charge no analysis
    ledger, so no analysis result depends on them; a record over
    TDO_V2_RECORD_WORK units is cut. Roots without nodes (failures) get none."""
    from .resource_limits import DiagnosticExhausted, diagnostic

    from .operation_records import StitchContext

    limit = os.environ.get("TDO_V2_RECORD_WORK")
    work = int(limit) if limit else None
    stitch = StitchContext(provenance, assumptions=run.assumptions) if provenance is not None else None
    roots = []
    for root in run.roots:
        inputs = record_inputs.get(
            (root.function_space_id, root.function_byte_offset, root.label, root.occurrence_ordinal))
        if inputs is None or not root.root_nodes:   # (a failure root: no record, even if its
            # function's roots were built before it failed -- Astra)
            roots.append(root)
            continue
        analysis, unit, rows, analyzed = inputs
        found = (provenance or {}).get(id(analyzed))
        calls = found[1] if found is not None and found[0] is analyzed else None
        try:
            with diagnostic(work):
                record = _root_record(analysis, unit, rows, root.label, root.occurrence_ordinal, analyzed,
                                      root.effective_completeness, calls, stitch,
                                      physical_memory_records=physical_memory_records)
        except DiagnosticExhausted:
            record = {"record": "root", "truncated": True, "cut": "diagnostic budget", "root": [], "nodes": []}
        # (the record before ``rests_on_failed``, the key order it had)
        explanation = {key: value for key, value in root.explanation.items() if key != "rests_on_failed"}
        explanation["record"] = record
        if "rests_on_failed" in root.explanation:
            explanation["rests_on_failed"] = root.explanation["rests_on_failed"]
        roots.append(replace(root, explanation=explanation))
    return replace(run, roots=tuple(roots))


def _dependents_incomplete(roots, failed, results, by_key) -> list:
    """Roots projected through a call whose callee reaches a function of
    ``failed`` (call graph of the run): incomplete, ``explanation["rests_on_failed"]``
    naming those functions -- a function that fails after its summary was used
    (sink binding / root slicing) takes its dependents with it. (One failing in
    the analysis itself was an opaque call to its callers: not listed here.)"""
    reach: dict = {}

    def reached(key) -> frozenset:
        """Failed functions ``key`` reaches (iterative: no recursion)."""
        if key not in reach:
            seen, pending = set(), [key]
            while pending:
                step()
                item = pending.pop()
                if item in seen or item not in results:
                    continue
                seen.add(item)
                pending.extend(results[item].calls.values())
                # (a call reaching one of several functions reaches every member)
                pending.extend(member for members in getattr(results[item], "multi_calls", {}).values()
                               for member in members)
            reach[key] = frozenset(seen & set(failed))
        return reach[key]

    found = []
    for root in roots:
        key = f"{root.function_space_id:x}:{root.function_byte_offset:x}"
        evidence = by_key[key]
        base = len(evidence.seeds.callsites) + len(evidence.tails)
        index = root.occurrence_ordinal - base
        projected = results[key].projected_sinks
        checkpoint()
        if 0 <= index < len(projected):
            call = projected[index][0]
            callees = (results[key].calls[call],) if call in results[key].calls \
                else getattr(results[key], "multi_calls", {}).get(call, ())
            failures = frozenset().union(*(reached(callee) for callee in callees))
            if failures:
                local = replace(root.local_completeness, complete=False)
                effective = replace(root.effective_completeness, complete=False)
                root = replace(root, local_completeness=local, effective_completeness=effective,
                               explanation={**root.explanation, "rests_on_failed": sorted(failures)},
                               inherited_incomplete=True)
        found.append(root)
    return found


def _failure_roots(evidence, boundaries, provider, reason) -> list:
    """Incomplete roots of a function that did not normalize -- out of a
    resource, or refused (``EngineRun.failed_functions``): one per syntactic sink occurrence -- a
    call site classified SINK (occurrence = its call-seed index) or a tail jump
    (call-seed count + tail index), numbered as a bound function's are and
    never compacted -- with no nodes, no origin labels and completeness false;
    ``explanation["failure"]`` names the reason. Occurrences outside the
    observation are skipped, as binding skips them."""
    unit = evidence.unit
    entry = unit.scopes.function.entry
    step(len(unit.observation.instructions) + 1)   # (the reporting deadline is checked)
    observed = {
        _operation_key(instruction.address, ordinal, operation.opcode)
        for instruction in unit.observation.instructions
        for ordinal, operation in enumerate(instruction.operations)
    }
    occurrences = [(occurrence, seed.operation_key, boundary)
                   for occurrence, (seed, boundary) in enumerate(boundaries)]
    base = len(evidence.seeds.callsites)
    occurrences += [(base + index, tail.operation_key, boundary)
                    for index, (tail, boundary) in enumerate(zip(evidence.tails, _tail_boundaries(evidence),
                                                                 strict=True))]
    incomplete = LocalCompleteness(False, 0, 0)
    found = []
    for occurrence, operation_key, boundary in occurrences:
        if operation_key not in observed:
            continue
        for label in sorted({match.label for match in provider.classify(boundary)
                             if match.kind is BoundaryKind.SINK}):
            found.append(RootSlice(entry.space_id, entry.byte_offset, label, occurrence, (), (), (),
                                   {"failure": reason.value}, incomplete, incomplete))
    return found


# the failures ``analyze_units`` reports as a function's resource failure
RESOURCE_REASONS = frozenset({NormalizationFailureReason.ANALYSIS_DEPTH, NormalizationFailureReason.ANALYSIS_BUDGET,
                              NormalizationFailureReason.ANALYSIS_RUN_BUDGET})

LANE_DIAGNOSTICS = {"roots": 0, "narrowed": 0, "not_subset": 0, "restored": 0}


def _witnesses(analysis, unit, rows, label, occurrence, labels, node_labels, indexes, origins) -> dict:
    """Origin witnesses of one root (diagnostics, ``origin_witnesses``); the
    traversal decided as ``_lane_origin_labels`` decides it."""
    import os

    from .lane_slice import lane_index, lane_slice
    from .origin_witnesses import labels_in_lanes, root_witnesses

    seeds = [(row.node, row.physical_spans) for row in rows
             if row.kind is BoundaryKind.SINK and row.label == label and row.occurrence_ordinal == occurrence]
    if not seeds or not labels:
        return {}
    if id(analysis.normalized) not in indexes:
        indexes[id(analysis.normalized)] = lane_index(analysis.normalized, unit)
    index = indexes[id(analysis.normalized)]
    traversal = "lane"
    if os.environ.get("TDO_V2_LANE_ORIGINS") == "0" \
            or not labels_in_lanes(lane_slice(analysis.normalized, unit, seeds, index), index, rows) <= node_labels:
        traversal = "node-fallback"
    return root_witnesses(analysis.normalized, unit, rows, seeds, labels, index, origins, traversal)


def _root_record(analysis, unit, rows, label, occurrence, analyzed, completeness, provenance=None,
                 stitch=None, *, physical_memory_records=False) -> dict:
    """The operation record of one root (diagnostics, ``operation_records``):
    seeded as ``_lane_origin_labels`` seeds its slice; SOURCE rows' labels as
    node origins."""
    from .operation_records import root_record

    seeds = [(row.node, row.physical_spans) for row in rows
             if row.kind is BoundaryKind.SINK and row.label == label and row.occurrence_ordinal == occurrence]
    origins: dict = {}
    for row in rows:
        if row.kind is BoundaryKind.SOURCE:
            origins.setdefault(row.node, set()).add(row.label)
    record = root_record(analysis.normalized, unit, seeds, origins=origins, declared=analyzed.declared,
                       completeness=completeness, provenance=provenance, stitch=stitch,
                       physical_memory=physical_memory_records)
    from .integration.configured_physical_binding_graph import physical_binding_graph
    bindings = physical_binding_graph(analysis, rows, label, occurrence)
    if bindings:
        record["physical_binding_graph"] = bindings
    return record


def _raw_root_groups(analysis, rows):
    """(label, occurrence, root nodes, slice results, node-slice origin labels)
    per raw sink occurrence. Every raw occurrence is a root with all its own
    nodes: canonicalization (one row per (kind, label, node)) drops a row whose
    node another occurrence already binds -- the whole group or part of it; such
    a node takes that other root's slice, or a fresh node query (labels: the
    SOURCE rows it reaches). A group missing nodes is counted ``restored``."""
    groups: dict = {}
    for local_slice in analysis.slices:
        groups.setdefault((local_slice.root.label, local_slice.root.occurrence_ordinal), []).append(local_slice)
    raw_groups: dict = {}
    for row in rows:
        if row.kind is BoundaryKind.SINK:
            raw_groups.setdefault((row.label, row.occurrence_ordinal), []).append(row)
    sliced = {item.root.node: item for item in analysis.slices}
    found = []
    for label, occurrence in sorted(set(groups) | set(raw_groups)):
        group = groups.get((label, occurrence), [])
        results = [item.result for item in group]
        node_labels = {origin for item in group for origin in item.reached_origin_labels}
        group_nodes = {item.root.node for item in group}
        extra = sorted({row.node for row in raw_groups.get((label, occurrence), ())} - group_nodes)
        for node in extra:
            if node in sliced:   # the same node's slice of another root
                results.append(sliced[node].result)
                node_labels |= set(sliced[node].reached_origin_labels)
                continue
            from .query import BackwardSliceQuery

            result = BackwardSliceQuery().run(analysis.normalized, node)
            results.append(result)
            reached = set(result.reachable_nodes)
            node_labels |= {row.label for row in rows if row.kind is BoundaryKind.SOURCE and row.node in reached}
        if extra:
            LANE_DIAGNOSTICS["restored"] += 1
        found.append((label, occurrence, tuple(sorted(group_nodes | set(extra))), tuple(results), node_labels))
    return found


def _lane_origin_labels(analysis, unit, rows, label, occurrence, node_labels, indexes=None) -> set:
    """A root's origin labels from the byte-lane slice (``lane_slice``, docs
    25.6 B2a): seeded with every raw sink row of the root (all fragments, with
    their physical spans); a SOURCE row with physical spans counts only if a
    demanded byte of its node lies in them, a spanless one (summary-derived
    origins) when its node is reached at all. Never more than the node slice
    gives (``node_labels``; a violation keeps those and is counted).
    TDO_V2_LANE_ORIGINS=0: the node slice's labels."""
    import os

    from .lane_slice import lane_index, lane_slice
    from .origin_witnesses import labels_in_lanes

    if os.environ.get("TDO_V2_LANE_ORIGINS") == "0":
        return set(node_labels)
    seeds = [(row.node, row.physical_spans) for row in rows
             if row.kind is BoundaryKind.SINK and row.label == label and row.occurrence_ordinal == occurrence]
    if not seeds:
        return set(node_labels)
    indexes = {} if indexes is None else indexes
    if id(analysis.normalized) not in indexes:
        indexes[id(analysis.normalized)] = lane_index(analysis.normalized, unit)
    index = indexes[id(analysis.normalized)]
    lanes = lane_slice(analysis.normalized, unit, seeds, index)
    # spans count only as bytes of the node's own storage (a row bound to an
    # operation node, or with spans of another object: as spanless)
    found = labels_in_lanes(lanes, index, rows)
    LANE_DIAGNOSTICS["roots"] += 1
    if not found <= node_labels:
        LANE_DIAGNOSTICS["not_subset"] += 1
        return set(node_labels)
    if found != node_labels:
        LANE_DIAGNOSTICS["narrowed"] += 1
    return found


def run_assumptions(results, *, readonly_image=None, home_space=0, traps=False, pcodeop_models=None) -> tuple:
    """Every assumption an ``analyze_units`` run rests on (``EngineRun.assumptions``)."""
    # a round-1 result replaced by a later failure: its callers used its summary
    results = {**results, **{f"{key}~superseded": item.superseded for key, item in results.items()
                             if getattr(item, "superseded", None) is not None}}
    # (its withdrawal check rests on stack-switch-check-exceptions)
    assumptions = ("globals-disjoint-from-stack", "stack-switch-check-exceptions") if any(
        getattr(item.normalized, "assumes_globals_disjoint_from_stack", False)
        for item in results.values()
    ) else ()
    # a call with the observed call shape whose callee is not summarized is
    # still taken to restore the stack pointer (the engine-wide call-shape
    # rule); summarized callees are checked (AFFINE) instead
    if any(
        row.call_operation_key not in item.proven
        for item in results.values()
        for row in observed_call_state_projections(item.unit.observation)
    ):
        assumptions += ("opaque-callees-restore-stack-pointer",)
    if readonly_image is not None:
        assumptions += ("readonly-image-data-is-constant",)
    if any(getattr(item.normalized, "assumes_import_slots_hold_exports", False) for item in results.values()):
        assumptions += ("import-slots-hold-their-exports",)
    if any(getattr(item.normalized, "assumes_entry_values_not_frame", False) for item in results.values()):
        # the private-frame rule decided some byte private; the home space
        # extends it (no private byte, no home-space byte)
        assumptions += ("entry-values-do-not-address-the-new-frame",)
        if home_space:
            assumptions += ("win64-home-space-callee-private",)
    # a byte decided private only because the opaque calls were not escapes
    if any(getattr(item.normalized, "assumes_opaque_callees_leave_no_stack_addresses", False)
           for item in results.values()):
        assumptions += ("opaque-callees-leave-no-stack-addresses",)
    # values no escape precedes taken as no address of the new frame (docs 25.77)
    if any(getattr(item.normalized, "assumes_pre_escape_values_not_frame", False) for item in results.values()):
        assumptions += ("pre-escape-values-do-not-address-the-new-frame",)
    # reported whenever a function has a trap the cut applies to: removing the
    # paths behind it can change a summary without leaving a dead exit
    if traps and pcodeop_models and any(trap_operations(item.unit, pcodeop_models) for item in results.values()):
        assumptions += ("debug-break-traps-do-not-return",)
    if any(getattr(item.normalized, "assumed_direction_flag_clear", False) for item in results.values()):
        # a rep string site whose direction flag is the function's entry value
        assumptions += ("direction-flag-clear",)
    return assumptions + tuple(sorted(
        {label for item in results.values() for label in item.declared.values()}
        | {label for item in results.values() for label in item.inherited_assumptions}))

__all__ = ("analyze_frozen_bundle_with_summaries",)
