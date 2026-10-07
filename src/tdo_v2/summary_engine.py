"""Bundle analysis on callee summaries (interprocedural S1c).

``analyze_frozen_bundle_with_summaries`` replaces the per-root interprocedural
completion of ``engine.analyze_frozen_bundle`` with the bottom-up summary
layer (``interprocedural.analyze_units``): every function is normalized with
the proven effects of its summarized callees, so a sink root's local slice
already reaches through calls. Source labels become origin nodes:

* a TEST-ONLY declared source call (``assume_boundary_call_effects``): its own
  write in the caller, as in the engine;
* a call to a source function inside the Bundle: the summarized run outputs
  that write the source's state (its return register);
* a summarized call whose runs reached a source inside the callee: those run
  outputs (carried by the summaries).

``assume_globals_disjoint_from_stack`` (on by default) applies the named
assumption of ``may_alias`` (constant addresses never alias the stack) unless some
function switches its stack (``interprocedural.program_switches_stack``); the
run lists it in ``EngineRun.assumptions`` when it was applied.

Sink roots are bound as in the engine (call sites and tail calls). A sink
reached only inside a callee (a sink wrapper) is a root of that callee; its
demand is not projected to callers yet (design S2/S3).
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from .boundary import BoundaryKind, BoundaryProvider, CallBoundary
from .configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from .engine import (
    EngineRun, RootSlice, _unbound_roots, _with_unbound, assumed_boundary_effects,
)
from .integration.configured_target_resolution import _selected_resolved_target
from .integration.observed_function_session import open_observed_function_session
from .interprocedural import analyze_units, function_key, run_definition_nodes
from .memory_contracts import MemoryDefinitionKind
from .normalize import NormalizedFunction
from .physical_state import PhysicalRegisterSlice
from .query_contracts import local_completeness
from .scope_identity import ConstructedProgramScope


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


def analyze_frozen_bundle_with_summaries(
    generation_path: str | Path,
    *,
    naming_exporter_source: str | Path,
    boundary_provider: BoundaryProvider,
    assume_boundary_call_effects: bool = False,
    assume_globals_disjoint_from_stack: bool = True,
) -> EngineRun:
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
        evidences = list(session.iter_functions())
        by_key = {function_key(item.unit.scopes.function.entry): item for item in evidences}
        assumed = {
            key: assumed_boundary_effects(item, boundary_provider)
            for key, item in by_key.items()
        } if assume_boundary_call_effects else {}
        boundaries = {key: _boundaries(item) for key, item in by_key.items()}

        def source_matches(boundary):
            return [match for match in boundary_provider.classify(boundary)
                    if match.kind is BoundaryKind.SOURCE]

        def extra_origins(key, unit, normalized, calls):
            origins: dict = {}
            declared = dict(normalized.assumed_call_effects)
            proven = dict(normalized.proven_call_effects)
            for seed, boundary in boundaries[key]:
                for match in source_matches(boundary):
                    call = seed.operation_key
                    if call in declared and declared[call].label == match.label:
                        nodes = [
                            normalized.memory_graph.definition_nodes[index]
                            for index, definition in enumerate(normalized.memory_ssa.definitions)
                            if definition.operation_key == call
                            and definition.kind is MemoryDefinitionKind.DATA_WRITE
                        ]
                    elif call in proven:
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
                        ]
                    else:
                        nodes = []
                    for node in nodes:
                        origins.setdefault(node, set()).add(match.label)
            return origins

        results = analyze_units(
            [item.unit for item in evidences], assumed_call_effects=assumed, extra_origins=extra_origins,
            assume_globals_disjoint_from_stack=assume_globals_disjoint_from_stack,
        )
        assumptions = ("globals-disjoint-from-stack",) if any(
            getattr(item.normalized, "assumes_globals_disjoint_from_stack", False)
            for item in results.values()
        ) else ()
        preliminary = []
        for key, item in by_key.items():
            normalized = results[key].normalized
            if type(normalized) is not NormalizedFunction:
                raise ValueError(f"function {key} does not normalize: {normalized.reason.value}")
            preliminary.append(ConfiguredFunctionAnalysis(item, normalized, EMPTY_OBSERVED_BOUNDARIES, ()))
        preliminary = tuple(preliminary)
        views = {analysis.entry: _FunctionView(analysis) for analysis in preliminary}
        nodes = {analysis.entry: [] for analysis in preliminary}
        for analysis in preliminary:
            key = function_key(analysis.entry)
            view = views[analysis.entry]
            for fragment, (node, labels) in enumerate(sorted(results[key].origins.items())):
                for label in sorted(labels):
                    nodes[analysis.entry].append(
                        ObservedBoundaryNode(BoundaryKind.SOURCE, label, node, 0, fragment))
            for occurrence, (seed, boundary) in enumerate(boundaries[key]):
                position = view.position(seed.operation_key)
                if position is None:
                    continue
                for match in boundary_provider.classify(boundary):
                    if match.kind is BoundaryKind.SINK:
                        nodes[analysis.entry].extend(_direct_sink_boundary_nodes(
                            view, match.label, seed.operation_key, position, occurrence,
                            boundary_provider.state(boundary, match),
                        ))
        _bind_tail_call_sinks(preliminary, views, boundary_provider, nodes)
        analyses = _analyses_from_boundary_nodes(preliminary, nodes)

        roots = []
        for analysis in analyses:
            groups: dict = {}
            for local_slice in analysis.slices:
                groups.setdefault((local_slice.root.label, local_slice.root.occurrence_ordinal), []).append(
                    local_slice)
            for (label, occurrence), group in sorted(groups.items()):
                root_nodes = tuple(sorted({item.root.node for item in group}))
                results_for_root = tuple(item.result for item in group)
                unbound = _unbound_roots(analysis.normalized, root_nodes)
                completeness = _with_unbound(local_completeness(results_for_root), unbound)
                roots.append(RootSlice(
                    analysis.entry.space_id, analysis.entry.byte_offset, label, occurrence, root_nodes,
                    tuple(sorted({origin for item in group for origin in item.reached_origin_labels})),
                    (), {}, completeness, completeness,
                ))
        return EngineRun(
            program.scope.digest.hex(), program.evidence.executable_sha256.hex(), tuple(roots),
            assumptions,
        )


__all__ = ("analyze_frozen_bundle_with_summaries",)
