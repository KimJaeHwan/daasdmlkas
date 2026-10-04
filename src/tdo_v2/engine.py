"""Benchmark-neutral entry point for the configured Low-Pcode slice engine."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from .boundary import BoundaryProvider
from .configured_naming_contracts import (
    CALL_NAMING_GHIDRA_VERSION,
    NamingBindingExpectation,
)
from .external_summary import ExternalSummaryProvider
from .integration.configured_bundle import admit_frozen_bundle
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
from .integration.observed_function_session import open_observed_function_session
from .normalize import FunctionNormalizer, NormalizedFunction
from .opaque_values import OpaqueValueEvidenceProvider
from .scope_identity import ConstructedProgramScope


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
) -> EngineRun:
    """Analyze one admitted Bundle; report candidate paths and explicit gaps.

    This is engine output, not an independent path-verification or corpus grade.
    Every function must normalize successfully; partial inventories never become
    apparently complete results.
    """
    if type(include_explanations) is not bool:
        raise TypeError("include_explanations must be an exact bool")
    exporter_digest = sha256(Path(naming_exporter_source).read_bytes()).digest()
    naming_binding = NamingBindingExpectation(
        exporter_digest, CALL_NAMING_GHIDRA_VERSION
    )
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
            )
            if type(normalized) is not NormalizedFunction:
                raise ValueError(
                    f"Bundle function {index} normalization is unresolved: "
                    f"{normalized.reason.value}"
                )
            rows.append((evidence, normalized))
        analyses = build_observed_function_analyses(
            tuple(rows), boundary_provider, external_provider
        )
        completed = dict(
            complete_configured_interprocedural_slices(
                analyses, external_provider
            )
        )
        by_entry = {analysis.entry: analysis for analysis in analyses}
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
                    )
                )
        return EngineRun(
            program.scope.digest.hex(),
            program.evidence.executable_sha256.hex(),
            tuple(roots),
        )


__all__ = ("EngineRun", "RootSlice", "analyze_frozen_bundle")
