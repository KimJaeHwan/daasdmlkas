"""Benchmark-neutral entry point for the configured Low-Pcode slice engine."""

from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path

from .assumed_call_effects import AssumedCallEffect
from .boundary import BoundaryProvider, CallBoundary
from .graph_contracts import NodeKind
from .integration.configured_target_resolution import _selected_resolved_target
from .configured_naming_contracts import (
    CALL_NAMING_GHIDRA_VERSION,
    NamingBindingExpectation,
)
from .external_summary import ExternalSummaryProvider
from .integration.configured_call_clobber_discharge import CallClobberDischarger
from .integration.configured_explanation_graph import (
    conditional_call_byte_overlay,
    root_local_explanation,
)
from .integration.configured_interprocedural_path_explanation import (
    conditional_source_paths,
)
from .integration.configured_interprocedural_slice import (
    build_observed_function_analyses,
    complete_configured_interprocedural_slices,
)
from .integration.observed_function_session import (
    ObservedFunctionEvidence,
    open_observed_function_session,
)
from .normalize import (
    FunctionNormalizer,
    NormalizationFailureReason,
    NormalizedFunction,
)
from .opaque_values import OpaqueValueEvidenceProvider
from .query_contracts import (
    LocalCompleteness,
    effective_completeness,
    local_completeness,
)
from .scope_identity import (
    AddressCoordinate,
    ConstructedFunctionScope,
    ConstructedProgramScope,
)


class UnresolvedBundleFunctionError(ValueError):
    """One Bundle function did not normalize; the run is not partial-reported.

    Callers of the failed function would otherwise lose its call edges
    silently, so the whole run fails with the typed reason instead.
    """

    def __init__(
        self,
        index: int,
        entry: AddressCoordinate | None,
        reason: NormalizationFailureReason,
    ) -> None:
        self.index = index
        self.entry = entry
        self.reason = reason
        where = (
            f" at {entry.space_id:x}:{entry.byte_offset:x}" if entry is not None else ""
        )
        super().__init__(
            f"Bundle function {index}{where} normalization is unresolved: "
            f"{reason.value}"
        )


@dataclass(frozen=True, slots=True)
class RootSlice:
    function_space_id: int
    function_byte_offset: int
    label: str
    occurrence_ordinal: int
    root_nodes: tuple[int, ...]
    local_origin_labels: tuple[str, ...]
    interprocedural_origin_labels: tuple[str, ...]
    explanation: dict[str, object]
    local_completeness: LocalCompleteness
    effective_completeness: LocalCompleteness

    @property
    def is_locally_complete(self) -> bool:
        return self.local_completeness.complete

    @property
    def is_effectively_complete(self) -> bool:
        """Local debt minus call-clobber debt discharged by callee evidence."""
        return self.effective_completeness.complete

    @property
    def reached_origin_labels(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.local_origin_labels) | set(self.interprocedural_origin_labels)))


@dataclass(frozen=True, slots=True)
class EngineRun:
    program_scope_digest: str
    executable_sha256: str
    roots: tuple[RootSlice, ...]


def analyze_frozen_bundle(
    generation_path: str | Path,
    *,
    naming_exporter_source: str | Path,
    boundary_provider: BoundaryProvider,
    external_provider: ExternalSummaryProvider | None = None,
    opaque_value_provider: OpaqueValueEvidenceProvider | None = None,
    include_explanations: bool = True,
    assume_boundary_call_effects: bool = False,
) -> EngineRun:
    """Analyze one admitted Bundle; report candidate paths and explicit gaps.

    ``assume_boundary_call_effects`` is a TEST-ONLY special condition (off by
    default): boundary calls whose rule sets ``assume_call_effect`` are
    normalized as writing only their declared output, so the code between
    source and sink is sliced as if it were call-free. Results then rely on
    that declaration, not on observed evidence.

    This is engine output, not an independent path-verification or corpus grade.
    Every function must normalize successfully; partial inventories never become
    apparently complete results.
    """
    if type(include_explanations) is not bool:
        raise TypeError("include_explanations must be an exact bool")
    if type(assume_boundary_call_effects) is not bool:
        raise TypeError("assume_boundary_call_effects must be an exact bool")
    exporter_digest = sha256(Path(naming_exporter_source).read_bytes()).digest()
    naming_binding = NamingBindingExpectation(
        exporter_digest, CALL_NAMING_GHIDRA_VERSION
    )
    from .integration.configured_bundle import admit_frozen_bundle  # POSIX-only

    snapshot = admit_frozen_bundle(generation_path)
    with open_observed_function_session(
        snapshot, naming_binding=naming_binding
    ) as session:
        program = session.program_result
        if type(program) is not ConstructedProgramScope:
            raise ValueError("Bundle program scope is unresolved")
        rows = []
        normalizer = FunctionNormalizer()
        for index, evidence in enumerate(session.iter_functions()):
            normalized = normalizer.normalize(
                evidence.unit,
                opaque_value_provider=opaque_value_provider,
                assumed_call_effects=(
                    assumed_boundary_effects(evidence, boundary_provider)
                    if assume_boundary_call_effects
                    else None
                ),
            )
            if type(normalized) is not NormalizedFunction:
                function = evidence.unit.scopes.function
                raise UnresolvedBundleFunctionError(
                    index,
                    function.entry
                    if type(function) is ConstructedFunctionScope
                    else None,
                    normalized.reason,
                )
            rows.append((evidence, normalized))
        roots = analyze_observed_functions(
            tuple(rows),
            boundary_provider,
            external_provider,
            include_explanations=include_explanations,
        )
        return EngineRun(
            program.scope.digest.hex(),
            program.evidence.executable_sha256.hex(),
            tuple(roots),
        )


def _unbound_roots(normalized: NormalizedFunction, root_nodes) -> int:
    """Roots bound to an operation (a call's consume event) with no data inputs:
    the boundary state is not represented in the graph at all."""
    graph = normalized.dependencies
    return sum(
        1
        for node in root_nodes
        if graph.node(node).kind is NodeKind.OPERATION
        and not graph.backward_reachable((node,))[1:]
    )


def _with_unbound(completeness: LocalCompleteness, unbound: int) -> LocalCompleteness:
    if not unbound:
        return completeness
    return replace(completeness, complete=False, unbound_roots=unbound)


def assumed_boundary_effects(
    evidence: ObservedFunctionEvidence, provider: BoundaryProvider
) -> dict[str, AssumedCallEffect]:
    """TEST-ONLY: declared effects of this function's boundary calls (opt-in rules)."""
    declare = getattr(provider, "assumed_call_effect", None)
    if declare is None:
        return {}
    language = evidence.unit.scopes.program.evidence.translation_namespace.language_id
    function = evidence.unit.scopes.function
    caller = f"{function.entry.space_id:x}:{function.entry.byte_offset:x}"
    effects = {}
    for seed, naming in zip(evidence.seeds.callsites, evidence.naming.rows, strict=True):
        target = _selected_resolved_target(naming)
        aliases = tuple(sorted({
            alias.value
            for alias in (() if target is None else target.aliases)
            if alias.policy_admissible
        }))
        boundary = CallBoundary(caller, seed.operation_key, aliases, language)
        declared = {
            effect
            for match in provider.classify(boundary)
            if (effect := declare(boundary, match)) is not None
        }
        if len(declared) == 1:
            effects[seed.operation_key] = declared.pop()
    return effects


def analyze_observed_functions(
    rows: tuple[tuple[ObservedFunctionEvidence, NormalizedFunction], ...],
    boundary_provider: BoundaryProvider,
    external_provider: ExternalSummaryProvider | None = None,
    *,
    include_explanations: bool = True,
) -> tuple[RootSlice, ...]:
    """Slice every boundary root of already-normalized observed functions."""
    analyses = build_observed_function_analyses(
        rows, boundary_provider, external_provider
    )
    completed = dict(
        complete_configured_interprocedural_slices(
            analyses, external_provider
        )
    )
    by_entry = {analysis.entry: analysis for analysis in analyses}
    discharger = CallClobberDischarger(analyses)
    roots = []
    for analysis in analyses:
        completion_by_node = {
            item.root_node: item for item in completed[analysis.entry]
        }
        groups = {}
        for local_slice in analysis.slices:
            key = (local_slice.root.label, local_slice.root.occurrence_ordinal)
            groups.setdefault(key, []).append(local_slice)
        for (label, occurrence), group in sorted(groups.items()):
            completions = tuple(
                completion_by_node[item.root.node] for item in group
            )
            proofs = tuple(
                sorted(
                    {
                        proof.canonical_key: proof
                        for completion in completions
                        for proof in completion.proofs
                    }.values(),
                    key=lambda item: item.canonical_key,
                )
            )
            local_labels = tuple(
                sorted({
                    origin
                    for item in group
                    for origin in item.reached_origin_labels
                })
            )
            reachable = tuple(
                sorted({
                    node
                    for item in group
                    for node in item.result.reachable_nodes
                })
            )
            root_nodes = tuple(sorted({item.root.node for item in group}))
            results = tuple(item.result for item in group)
            unbound = _unbound_roots(analysis.normalized, root_nodes)
            explanation: dict[str, object] = {}
            if include_explanations:
                explanation = root_local_explanation(
                    analysis.normalized, reachable, root_nodes, len(proofs)
                )
                proof_ordinals = {
                    proof.canonical_key: ordinal
                    for ordinal, proof in enumerate(proofs)
                }
                replacements = tuple(
                    sorted(
                        {
                            row.canonical_key: row
                            for completion in completions
                            for row in completion.call_byte_replacements
                        }.values(),
                        key=lambda item: item.canonical_key,
                    )
                )
                aliases = tuple(
                    sorted(
                        {
                            row.canonical_key: row
                            for completion in completions
                            for row in completion.dynamic_alias_replacements
                        }.values(),
                        key=lambda item: item.canonical_key,
                    )
                )
                overlay = conditional_call_byte_overlay(
                    analysis.normalized,
                    explanation,
                    replacements,
                    proof_ordinals,
                    aliases,
                )
                explanation["conditional_call_byte_overlay"] = overlay
                explanation["conditional_source_to_sink_paths"] = (
                    conditional_source_paths(
                        analysis,
                        proofs,
                        replacements,
                        overlay,
                        by_entry,
                    )
                )
            roots.append(
                RootSlice(
                    analysis.entry.space_id,
                    analysis.entry.byte_offset,
                    label,
                    occurrence,
                    root_nodes,
                    local_labels,
                    tuple(sorted({proof.label for proof in proofs})),
                    explanation,
                    _with_unbound(local_completeness(results), unbound),
                    _with_unbound(effective_completeness(
                        results,
                        frozenset(
                            row.debt_node
                            for row in discharger.discharge(
                                analysis.entry,
                                tuple(
                                    replacement
                                    for completion in completions
                                    for replacement in completion.call_byte_replacements
                                ),
                                proofs,
                                tuple(
                                    sorted(
                                        set(local_labels)
                                        | {proof.label for proof in proofs}
                                    )
                                ),
                            )
                        ),
                    ), unbound),
                )
            )
    return tuple(roots)


__all__ = (
    "EngineRun",
    "LocalCompleteness",
    "RootSlice",
    "UnresolvedBundleFunctionError",
    "analyze_frozen_bundle",
    "analyze_observed_functions",
    "assumed_boundary_effects",
    "local_completeness",
)
