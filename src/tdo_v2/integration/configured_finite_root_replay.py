"""Internal, bounded replay of one observed finite-recursive sink root.

This is diagnostic evidence only. It neither produces a public completion nor
grades a corpus row. The caller selects a physical root occurrence, while all
recursive selectors, premises, initial RAM eligibility and source cuts are
derived from the admitted observations.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..boundary import BoundaryKind, BoundaryProvider
from ..call_contracts import CallOperationKind, DirectCallTarget, FunctionCallSeedUnit
from ..call_seeds import _operation_key
from ..configured_naming_contracts import (
    CapturedNamingSidecar, NamingOpcode, NamingResolutionState,
)
from ..normalize import FunctionNormalizer, NormalizedFunction
from ..observed_boundary_projection import EMPTY_OBSERVED_BOUNDARIES
from ..scope_identity import VarnodeKindCode
from .configured_finite_context_cut_query import (
    CutQueryLimits, FiniteCutCandidates, FiniteCutIncomplete, FiniteMayDiagnostic,
    query_configured_finite_context_candidates,
    query_configured_finite_context_may_diagnostic,
)
from .configured_finite_context_inputs import (
    AbsolutePremiseRange, ConfiguredFiniteContextRequest, FiniteContextUnavailable,
    FiniteContextV2Limits, IsolatedStackPremise, RootPremiseBinding,
    SharedStatePremise, prepare_configured_symbolic_entry_request,
)
from .configured_finite_context_scheduler import (
    FiniteExpansion, FiniteSchedulerIncomplete, expand_configured_finite_context,
)
from .configured_interprocedural_contracts import ConfiguredFunctionAnalysis
from .configured_interprocedural_slice import build_observed_function_analyses
from .configured_recursive_all_effects import build_recursive_all_effect_inventory
from .configured_recursive_call_edges import (
    VerifiedDirectCallEdgesIncomplete, verify_direct_call_edges,
)
from .configured_recursive_frame_inventory import build_recursive_frame_inventory
from .configured_target_resolution import _selected_resolved_target
from .configured_recursive_selector_discovery import (
    CERTIFIED_WITNESS_V2, SelectorDiscoveryResult, SelectorDiscoveryStatus,
    discover_recursive_selectors,
)
from .observed_function_session import open_observed_function_session


class FiniteRootReplayDebtReason(StrEnum):
    INVALID_INPUT = "invalid_input"
    RESOURCE_BOUND = "resource_bound"
    OBSERVATION = "observation"
    ROOT = "root"
    CLOSURE = "closure"
    SELECTOR = "selector"
    PREMISE = "premise"
    REQUEST = "request"
    SCHEDULER = "scheduler"
    CUT = "cut"


class FiniteRootReplayIncomplete(RuntimeError):
    def __init__(self, reason: FiniteRootReplayDebtReason, detail: str):
        self.reason, self.detail = reason, detail
        super().__init__(f"{reason.value}: {detail}")


def _stop(reason: FiniteRootReplayDebtReason, detail: str):
    raise FiniteRootReplayIncomplete(reason, detail)


@dataclass(frozen=True, slots=True)
class RootOccurrence:
    function_scope_digest: bytes
    node: int
    occurrence_ordinal: int
    fragment_ordinal: int


@dataclass(frozen=True, slots=True)
class FiniteRootReplayLimits:
    inventory_functions: int = 4096
    inventory_instructions: int = 262144
    inventory_operations: int = 1048576
    inventory_calls: int = 65536
    functions: int = 64
    instructions: int = 4096
    operations: int = 4096
    calls: int = 256
    committed_runs: int = 4096


@dataclass(frozen=True, slots=True)
class FiniteRootReplayDiagnostic:
    root: RootOccurrence
    selector: SelectorDiscoveryResult
    request: ConfiguredFiniteContextRequest
    expansion: FiniteExpansion
    cuts: FiniteCutCandidates | FiniteMayDiagnostic
    bundle_container_identity: object | None
    program_scope_digest: bytes
    full_function_inventory: tuple[tuple[bytes, bytes], ...]
    selected_root_inventory: tuple[RootOccurrence, ...]
    closure_scopes: tuple[bytes, ...]
    provider: BoundaryProvider
    external_provider: object | None
    replay_limits: FiniteRootReplayLimits
    cut_limits: CutQueryLimits

    @property
    def diagnostic_only(self) -> bool:
        return True


def _check_limits(limits):
    defaults = FiniteRootReplayLimits()
    if type(limits) is not FiniteRootReplayLimits or any(
        type(getattr(limits, key)) is not int or not 0 < getattr(limits, key) <= getattr(defaults, key)
        for key in ("inventory_functions", "inventory_instructions",
                    "inventory_operations", "inventory_calls", "functions",
                    "instructions", "operations", "calls", "committed_runs")
    ):
        _stop(FiniteRootReplayDebtReason.RESOURCE_BOUND, "invalid replay preprocessing limits")


def _check_observation_budget(analyses, limits, *, full):
    function_cap = limits.inventory_functions if full else limits.functions
    instruction_cap = limits.inventory_instructions if full else limits.instructions
    operation_cap = limits.inventory_operations if full else limits.operations
    call_cap = limits.inventory_calls if full else limits.calls
    if type(analyses) is not tuple or not analyses or len(analyses) > function_cap:
        _stop(FiniteRootReplayDebtReason.RESOURCE_BOUND, "function observation count")
    instructions = operations = calls = 0
    for analysis in analyses:
        if type(analysis) is not ConfiguredFunctionAnalysis:
            _stop(FiniteRootReplayDebtReason.INVALID_INPUT, "exact observed analyses required")
        observation = analysis.evidence.unit.observation
        if observation is None:
            _stop(FiniteRootReplayDebtReason.OBSERVATION, "raw function observation absent")
        instructions += len(observation.instructions)
        if instructions > instruction_cap:
            _stop(FiniteRootReplayDebtReason.RESOURCE_BOUND, "raw instruction count")
        for instruction in observation.instructions:
            operations += len(instruction.operations)
            calls += sum(operation.opcode in {"CALL", "CALLIND"}
                         for operation in instruction.operations)
            if calls > call_cap:
                _stop(FiniteRootReplayDebtReason.RESOURCE_BOUND, "raw call count")
            if operations > operation_cap:
                _stop(FiniteRootReplayDebtReason.RESOURCE_BOUND, "raw operation count")


def _from_snapshot(snapshot, naming_binding, provider, external_provider, limits):
    if naming_binding is None:
        _stop(FiniteRootReplayDebtReason.INVALID_INPUT, "snapshot needs a naming binding")
    rows = []
    instructions = operations = calls = 0
    try:
        with open_observed_function_session(snapshot, naming_binding=naming_binding) as session:
            for evidence in session.iter_functions():
                if len(rows) >= limits.inventory_functions:
                    _stop(FiniteRootReplayDebtReason.RESOURCE_BOUND, "snapshot function count")
                observation = evidence.unit.observation
                if observation is None:
                    _stop(FiniteRootReplayDebtReason.OBSERVATION, "snapshot raw observation absent")
                instructions += len(observation.instructions)
                if instructions > limits.inventory_instructions:
                    _stop(FiniteRootReplayDebtReason.RESOURCE_BOUND, "snapshot instruction count")
                for instruction in observation.instructions:
                    operations += len(instruction.operations)
                    if operations > limits.inventory_operations:
                        _stop(FiniteRootReplayDebtReason.RESOURCE_BOUND, "snapshot operation count")
                    calls += sum(operation.opcode in {"CALL", "CALLIND"}
                                 for operation in instruction.operations)
                    if calls > limits.inventory_calls:
                        _stop(FiniteRootReplayDebtReason.RESOURCE_BOUND, "snapshot call count")
                normalized = FunctionNormalizer().normalize(evidence.unit)
                if type(normalized) is not NormalizedFunction:
                    _stop(FiniteRootReplayDebtReason.OBSERVATION, "function normalization incomplete")
                rows.append((evidence, normalized))
        # Construct full evidence without running boundary analysis on unrelated
        # functions. Only the root-reachable closure receives that analysis.
        return tuple(ConfiguredFunctionAnalysis(evidence, normalized,
                     EMPTY_OBSERVED_BOUNDARIES, ()) for evidence, normalized in rows)
    except (TypeError, ValueError, RuntimeError) as error:
        if type(error) is FiniteRootReplayIncomplete:
            raise
        _stop(FiniteRootReplayDebtReason.OBSERVATION,
              f"snapshot admission/normalization: {type(error).__name__}")


def _root_reachable_closure(analyses, root, limits):
    """Select from the full observed inventory, following every raw direct call."""
    by_scope = {}
    by_entry = {}
    program_digest = None
    for analysis in analyses:
        scopes = analysis.evidence.unit.scopes
        scope = scopes.function.scope.digest
        entry = analysis.entry
        if scope in by_scope or entry in by_entry:
            _stop(FiniteRootReplayDebtReason.CLOSURE, "duplicate function scope or entry")
        if program_digest is None:
            program_digest = scopes.program.scope.digest
        elif program_digest != scopes.program.scope.digest:
            _stop(FiniteRootReplayDebtReason.CLOSURE, "mixed program scopes")
        by_scope[scope] = analysis
        by_entry[entry] = scope
    if root.function_scope_digest not in by_scope:
        _stop(FiniteRootReplayDebtReason.ROOT, "root function is absent")

    reached = set()
    pending = [root.function_scope_digest]
    call_count = 0
    while pending:
        scope = pending.pop()
        if scope in reached:
            continue
        reached.add(scope)
        if len(reached) > limits.functions:
            _stop(FiniteRootReplayDebtReason.RESOURCE_BOUND, "selected closure function count")
        analysis = by_scope[scope]
        evidence = analysis.evidence
        seeds = evidence.seeds
        names = evidence.naming
        if (type(seeds) is not FunctionCallSeedUnit
                or type(names) is not CapturedNamingSidecar
                or seeds.program_scope != evidence.unit.scopes.program.scope
                or seeds.function_scope != evidence.unit.scopes.function.scope
                or seeds.observation_digest != evidence.unit.scopes.function.observation_digest
                or seeds.function_entry != analysis.entry
                or analysis.normalized.scopes is not evidence.unit.scopes
                or analysis.normalized.call_seeds != seeds):
            _stop(FiniteRootReplayDebtReason.CLOSURE, "selected call evidence mismatch")
        raw = {}
        for instruction in evidence.unit.observation.instructions:
            for ordinal, operation in enumerate(instruction.operations):
                if operation.opcode not in {"CALL", "CALLIND"}:
                    continue
                key = _operation_key(instruction.address, ordinal, operation.opcode)
                if key in raw:
                    _stop(FiniteRootReplayDebtReason.CLOSURE, "duplicate raw call")
                raw[key] = (instruction.address, ordinal, operation)
                call_count += 1
                if call_count > limits.calls:
                    _stop(FiniteRootReplayDebtReason.RESOURCE_BOUND, "selected closure call count")
        seed_by_key = {row.operation_key: row for row in seeds.callsites}
        name_by_key = {_operation_key(row.instruction, row.operation_ordinal,
                                     row.opcode.value): row for row in names.rows}
        if (len(seed_by_key) != len(seeds.callsites)
                or len(name_by_key) != len(names.rows)
                or set(raw) != set(seed_by_key) or set(raw) != set(name_by_key)):
            _stop(FiniteRootReplayDebtReason.CLOSURE, "raw/seed/naming call inventory mismatch")
        for key, (instruction, ordinal, operation) in raw.items():
            seed = seed_by_key[key]
            name = name_by_key[key]
            if (seed.locator.instruction != instruction
                    or seed.locator.operation_ordinal != ordinal
                    or seed.locator.function_scope != evidence.unit.scopes.function.scope
                    or seed.inputs != operation.inputs
                    or seed.explicit_output != operation.output
                    or name.instruction != instruction
                    or name.operation_ordinal != ordinal
                    or name.selector != (operation.inputs[0] if operation.inputs else None)):
                _stop(FiniteRootReplayDebtReason.CLOSURE, "direct call evidence mismatch")
            if (operation.opcode != "CALL" or seed.kind is not CallOperationKind.DIRECT
                    or name.opcode is not NamingOpcode.CALL
                    or len(operation.inputs) != 1
                    or operation.inputs[0].kind is not VarnodeKindCode.ADDRESS
                    or type(seed.target) is not DirectCallTarget
                    or name.resolution.state not in {
                        NamingResolutionState.RESOLVED_NAMED,
                        NamingResolutionState.RESOLVED_UNNAMED,
                    }):
                _stop(FiniteRootReplayDebtReason.CLOSURE, "unknown or indirect reached call")
            target = _selected_resolved_target(name)
            coordinate = operation.inputs[0].coordinate
            if (target is None or target.is_external or target.is_thunk
                    or coordinate != seed.target.coordinate
                    or coordinate != target.coordinate):
                _stop(FiniteRootReplayDebtReason.CLOSURE, "unresolved or conflicting reached target")
            callee = by_entry.get(coordinate)
            if callee is None:
                _stop(FiniteRootReplayDebtReason.CLOSURE, "reached target outside full observed inventory")
            if callee not in reached:
                pending.append(callee)
    selected = tuple(by_scope[scope] for scope in sorted(reached))
    _check_observation_budget(selected, limits, full=False)
    return selected, program_digest


def _select_root(analyses, coordinate):
    if (type(coordinate) is not RootOccurrence
            or type(coordinate.function_scope_digest) is not bytes
            or len(coordinate.function_scope_digest) != 32
            or any(type(getattr(coordinate, key)) is not int or getattr(coordinate, key) < 0
                   for key in ("node", "occurrence_ordinal", "fragment_ordinal"))):
        _stop(FiniteRootReplayDebtReason.INVALID_INPUT, "exact root occurrence required")
    selected = []
    for analysis in analyses:
        if analysis.evidence.unit.scopes.function.scope.digest != coordinate.function_scope_digest:
            continue
        for local_slice in analysis.slices:
            root = local_slice.root
            if (root.kind is BoundaryKind.SINK and root.node == coordinate.node
                    and root.occurrence_ordinal == coordinate.occurrence_ordinal
                    and root.fragment_ordinal == coordinate.fragment_ordinal):
                selected.append((analysis, local_slice))
    if len(selected) != 1:
        _stop(FiniteRootReplayDebtReason.ROOT, "root occurrence is absent or ambiguous")
    return selected[0]


def _premises(root_analysis, local_slice, induction, limits):
    program = root_analysis.evidence.unit.scopes.program
    runs = program._retained_committed_runs()
    if type(runs) is not tuple or len(runs) > limits.committed_runs:
        _stop(FiniteRootReplayDebtReason.RESOURCE_BOUND, "retained image run count")
    spaces = {access.interval.address_space_id
              for inventory in induction.inventories for access in inventory.accesses
              if access.interval is not None}
    if len(spaces) != 1:
        _stop(FiniteRootReplayDebtReason.PREMISE, "one observed RAM space required")
    space = next(iter(spaces))
    geometry = tuple(row for row in program.evidence.address_spaces
                     if row.space_id == space and row.is_memory_space)
    if len(geometry) != 1:
        _stop(FiniteRootReplayDebtReason.PREMISE, "observed RAM geometry unavailable")
    image = tuple(sorted({AbsolutePremiseRange(run.space_id, run.byte_start, run.byte_size)
                          for run in runs if run.space_id == space}))
    if not image:
        _stop(FiniteRootReplayDebtReason.PREMISE, "no retained loaded image ranges")
    absolute = tuple(sorted({AbsolutePremiseRange(effect.coordinate.space_id,
                            effect.coordinate.byte_offset, effect.byte_size)
                            for ledger in induction.effects
                            for effect in ledger.direct_address_effects}))
    root = local_slice.root
    binding = RootPremiseBinding(
        program.scope.digest, program.evidence.executable_sha256,
        program.evidence.loaded_memory_digest,
        root_analysis.evidence.unit.scopes.function.scope.digest,
        root_analysis.evidence.unit.scopes.function.observation_digest,
        root.node, root.occurrence_ordinal, root.fragment_ordinal,
        root.physical_spans, (), space,
        geometry[0].address_size_bits, geometry[0].addressable_unit_bytes,
    )
    return (SharedStatePremise(binding),
            IsolatedStackPremise(binding, induction.rank_context.modular_window,
                                 image, absolute))


def replay_selected_finite_root(
    evidence, root: RootOccurrence, provider: BoundaryProvider, /, *,
    naming_binding=None, external_provider=None,
    limits: FiniteRootReplayLimits = FiniteRootReplayLimits(),
    request_limits: FiniteContextV2Limits = FiniteContextV2Limits(
        induction_query_timeout_ms=5000),
    cut_limits: CutQueryLimits = CutQueryLimits(),
    may_diagnostic: bool = False,
) -> FiniteRootReplayDiagnostic:
    """Replay one coordinate from analyses or a consumed authenticated snapshot.

    A snapshot has already passed frozen-Bundle admission. This function never
    accepts a path, image bytes, a selector, or a precomputed expansion.
    """
    _check_limits(limits)
    if type(may_diagnostic) is not bool:
        _stop(FiniteRootReplayDebtReason.INVALID_INPUT, "exact may diagnostic flag required")
    bundle_identity = None
    if type(evidence) is tuple:
        if naming_binding is not None or external_provider is not None:
            _stop(FiniteRootReplayDebtReason.INVALID_INPUT,
                  "observed analyses cannot receive snapshot construction inputs")
        analyses = evidence
    else:
        analyses = _from_snapshot(evidence, naming_binding, provider, external_provider, limits)
        bundle_identity = evidence._inventory.container_identity
    _check_observation_budget(analyses, limits, full=True)
    if (type(root) is not RootOccurrence
            or type(root.function_scope_digest) is not bytes
            or len(root.function_scope_digest) != 32
            or any(type(getattr(root, key)) is not int or getattr(root, key) < 0
                   for key in ("node", "occurrence_ordinal", "fragment_ordinal"))):
        _stop(FiniteRootReplayDebtReason.INVALID_INPUT, "exact root occurrence required")
    selected, program_digest = _root_reachable_closure(analyses, root, limits)
    if bundle_identity is not None:
        rows = tuple((row.evidence, row.normalized) for row in selected)
        selected = build_observed_function_analyses(rows, provider, external_provider)
    root_analysis, local_slice = _select_root(selected, root)
    frames = tuple(build_recursive_frame_inventory(row) for row in selected)
    if any(not row.complete for row in frames):
        reason = (FiniteRootReplayDebtReason.RESOURCE_BOUND if any(
            debt.reason.value == "budget_exhausted"
            for frame in frames for debt in frame.debts)
            else FiniteRootReplayDebtReason.CLOSURE)
        _stop(reason, "frame inventory debt")
    effects = tuple(build_recursive_all_effect_inventory(row, frame)
                    for row, frame in zip(selected, frames, strict=True))
    if any(not row.complete for row in effects):
        reason = (FiniteRootReplayDebtReason.RESOURCE_BOUND if any(
            debt.reason.value == "resource_bound"
            for effect in effects for debt in effect.debts)
            else FiniteRootReplayDebtReason.CLOSURE)
        _stop(reason, "raw effect inventory debt")
    try:
        edges = verify_direct_call_edges(selected, frames)
    except VerifiedDirectCallEdgesIncomplete as error:
        reason = (FiniteRootReplayDebtReason.RESOURCE_BOUND
                  if error.reason.value == "resource_bound"
                  else FiniteRootReplayDebtReason.CLOSURE)
        _stop(reason, f"direct edges: {error.reason.value}")
    selector = discover_recursive_selectors(
        selected, frames, effects, edges, root.function_scope_digest,
        witness_policy=CERTIFIED_WITNESS_V2,
    )
    if (selector.status is not SelectorDiscoveryStatus.WITNESS_FOUND
            or selector.selected is None or selector.closure is None
            or selector.selected_identity_digest is None):
        _stop(FiniteRootReplayDebtReason.SELECTOR,
              f"discovery status: {selector.status.value}")
    induction = selector.closure
    shared, isolated = _premises(root_analysis, local_slice, induction, limits)
    try:
        request = prepare_configured_symbolic_entry_request(
            selected, root_analysis, local_slice, local_slice.root.physical_spans,
            induction, shared_state=shared, isolated_stack=isolated,
            initial_constraints=(), limits=request_limits,
        )
    except FiniteContextUnavailable as error:
        _stop(FiniteRootReplayDebtReason.REQUEST,
              f"{error.reason.value}: {error.detail}")
    try:
        expansion = expand_configured_finite_context(request)
    except FiniteSchedulerIncomplete as error:
        _stop(FiniteRootReplayDebtReason.SCHEDULER,
              f"{error.reason.value}: {error.detail}")
    try:
        query = (query_configured_finite_context_may_diagnostic if may_diagnostic
                 else query_configured_finite_context_candidates)
        cuts = query(request, expansion, provider, limits=cut_limits)
    except FiniteCutIncomplete as error:
        _stop(FiniteRootReplayDebtReason.CUT,
              f"{error.reason.value}: {error.detail}")
    full_inventory = tuple(sorted((row.evidence.unit.scopes.function.scope.digest,
                                   row.evidence.unit.scopes.function.observation_digest)
                                  for row in analyses))
    root_inventory = tuple(RootOccurrence(root.function_scope_digest, item.root.node,
                                         item.root.occurrence_ordinal,
                                         item.root.fragment_ordinal)
                           for item in root_analysis.slices if item.root.kind is BoundaryKind.SINK)
    return FiniteRootReplayDiagnostic(root, selector, request, expansion, cuts,
                                      bundle_identity, program_digest, full_inventory,
                                      root_inventory, tuple(sorted(row.evidence.unit.scopes.function.scope.digest
                                                                   for row in selected)),
                                      provider, external_provider, limits, cut_limits)
