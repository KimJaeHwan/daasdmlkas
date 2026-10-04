"""Dormant ADR-0040 inputs; neither profile is an origin certificate.

V1 binds exact initial bytes. V2 admits symbolic entry RAM only at replayed
direct READ ranges covered by retained initialized committed runs. Image ranges
remain an explicit environmental assertion; no diagnostic labels, old slice
reachability, or caller-provided depth authorize completion.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum, StrEnum
from hashlib import sha256
import json
from time import monotonic

from .._scope_contracts import AddressCoordinate
from .._scope_contracts import CommittedMemoryRun
from ..boundary import BoundaryKind
from ..call_observation_contracts import BoundLocalMemorySsa
from ..model import ByteSpan, StorageObjectKind
from .configured_interprocedural_contracts import ConfiguredFunctionAnalysis
from .configured_recursive_frame_base_certificate import SHARED_STATE_PROFILE, ISOLATED_STACK_PROFILE
from .configured_recursive_all_effects import DirectEffectKind
from .configured_recursive_induction_closure import (
    ConditionalInductionClosure, InductionClosureIncomplete,
    close_recursive_preservation_induction,
)
from .observed_slice import ObservedBoundarySlice


class FiniteContextDebtReason(StrEnum):
    INVALID_INPUT = "invalid_input"
    ROOT_MISMATCH = "root_mismatch"
    DEMAND_MISMATCH = "demand_mismatch"
    CLOSURE_MISMATCH = "closure_mismatch"
    PREMISE_MISMATCH = "premise_mismatch"
    REVISION_MISMATCH = "revision_mismatch"
    RESOURCE_BOUND = "resource_bound"
    CERTIFICATE_UNAVAILABLE = "certificate_unavailable"
    PUBLIC_WIRE_UNAVAILABLE = "public_wire_unavailable"


class FiniteContextUnavailable(RuntimeError):
    def __init__(self, reason: FiniteContextDebtReason, detail: str):
        self.reason, self.detail = reason, detail
        super().__init__(f"{reason.value}: {detail}")


def _stop(reason, detail):
    raise FiniteContextUnavailable(reason, detail)


@dataclass(frozen=True, slots=True)
class FiniteContextRevisions:
    request: str = "configured-finite-context-inputs-v1"
    proof: str = ConditionalInductionClosure.__dataclass_fields__["semantic_revision"].default
    compiler: str = "unavailable"
    query: str = "unavailable"
    source_endpoint: str = "unavailable"


@dataclass(frozen=True, slots=True)
class FiniteContextLimits:
    """Versioned ceilings, including reserved compiler/proof/report budgets.

Only preprocessing and proof replay execute here. Reserved budgets are bound
but are not claimed to have been checked by a nonexistent compiler.
"""
    revision: str = "configured-finite-context-limits-v1"
    functions: int = 64
    instructions: int = 4096
    operations: int = 4096
    call_edges: int = 256
    contexts: int = 1024
    cfg_paths: int = 128
    symbolic_state_bytes: int = 262144
    memory_events: int = 262144
    solver_queries: int = 10000
    solver_timeout_ms: int = 5000
    graph_nodes: int = 262144
    graph_edges: int = 524288
    origin_facts: int = 65536
    proof_nodes: int = 262144
    witness_length: int = 65536
    cache_bytes: int = 16777216
    report_bytes: int = 16777216
    payload_items: int = 1048576
    premise_ranges: int = 4096
    demand_bytes: int = 4096


@dataclass(frozen=True, slots=True)
class FiniteContextV2Limits(FiniteContextLimits):
    """Symbolic-entry ceilings; expression work is not a byte measurement.

    ``symbolic_state_bytes`` bounds the scheduler's explicitly accounted
    copied references, visited markers and query scratch, plus the kernel's
    own byte-accounted state ceilings. ``expression_work_nodes`` separately
    bounds constructed/reserved symbolic expression work. Neither is an RSS
    or native Z3 heap ceiling.
    """
    revision: str = "configured-finite-context-limits-v3"
    symbolic_state_bytes: int = 524288
    expression_work_nodes: int = 524288
    cache_bytes: int = 33554432
    induction_query_timeout_ms: int = 30000
    induction_replay_total_ms: int = 30000
    preparation_total_ms: int = 120000
    max_preparations: int = 8
    scheduler_solver_total_ms: int = 30000
    symbolic_entry_ranges: int = 4096
    symbolic_entry_bytes: int = 524288


@dataclass(frozen=True, slots=True)
class FiniteContextV2Revisions(FiniteContextRevisions):
    request: str = "configured-finite-context-inputs-v2"


@dataclass(frozen=True, slots=True)
class SymbolicEntryProfile:
    """Eligible entry RAM only; retained snapshot bytes are never equalities."""
    policy_revision: str
    program_scope_digest: bytes
    loaded_memory_digest: bytes
    address_space_id: int
    address_size_bits: int
    addressable_unit_bytes: int
    ranges: tuple[AbsolutePremiseRange, ...]
    covering_runs: tuple[CommittedMemoryRun, ...]


@dataclass(frozen=True, slots=True)
class InitialByteConstraint:
    """Conjunction of exact initial architectural byte equalities, not a seed replay."""
    span: ByteSpan
    value: bytes


@dataclass(frozen=True, order=True, slots=True)
class AbsolutePremiseRange:
    space_id: int
    start: int
    size: int


@dataclass(frozen=True, slots=True)
class RootPremiseBinding:
    program_scope_digest: bytes
    executable_sha256: bytes
    loaded_memory_digest: bytes
    root_scope_digest: bytes
    root_observation_digest: bytes
    root_node: int
    occurrence_ordinal: int
    fragment_ordinal: int
    demanded_spans: tuple[ByteSpan, ...]
    initial_constraints: tuple[InitialByteConstraint, ...]
    address_space_id: int
    address_size_bits: int = 64
    addressable_unit_bytes: int = 1


@dataclass(frozen=True, slots=True)
class SharedStatePremise:
    binding: RootPremiseBinding
    revision: str = SHARED_STATE_PROFILE
    register_and_ram_shared: bool = True
    unique_activation_local: bool = True
    observed_control_effects_only: bool = True
    unsupported_hidden_effects: str = "reject"


@dataclass(frozen=True, slots=True)
class IsolatedStackPremise:
    binding: RootPremiseBinding
    stack_relative_window: tuple[int, int]
    loaded_image_ranges: tuple[AbsolutePremiseRange, ...]
    absolute_effect_ranges: tuple[AbsolutePremiseRange, ...]
    revision: str = ISOLATED_STACK_PROFILE
    complete_root_descendant_token_footprint: bool = True
    loaded_image_inventory_asserted_complete: bool = True
    excludes_caller_provided_frame_pointers: bool = False


@dataclass(frozen=True, slots=True)
class ConfiguredFiniteContextRequest:
    analyses: tuple[ConfiguredFunctionAnalysis, ...]
    root_analysis: ConfiguredFunctionAnalysis
    local_slice: ObservedBoundarySlice
    demanded_spans: tuple[ByteSpan, ...]
    initial_constraints: tuple[InitialByteConstraint, ...]
    shared_state: SharedStatePremise
    isolated_stack: IsolatedStackPremise
    induction: ConditionalInductionClosure
    revisions: FiniteContextRevisions | FiniteContextV2Revisions
    limits: FiniteContextLimits | FiniteContextV2Limits
    input_digest: bytes
    symbolic_entry: SymbolicEntryProfile | None = None
    _preparation_budget: _V2PreparationBudget | None = field(default=None, compare=False, repr=False)

    def __reduce_ex__(self, protocol):
        raise TypeError("finite context requests retain invocation-local evidence")


class _V2PreparationBudget:
    """Invocation-local replay accounting; idle time does not consume budget."""
    __slots__ = ("replays", "elapsed_ms", "active_started")

    def __init__(self):
        self.replays = 0
        self.elapsed_ms = 0.0
        self.active_started = None

    def begin(self, limits):
        if self.active_started is not None:
            _stop(FiniteContextDebtReason.INVALID_INPUT, "concurrent v2 preparation")
        if self.replays >= limits.max_preparations:
            _stop(FiniteContextDebtReason.RESOURCE_BOUND, "v2 preparation replay count")
        if self.elapsed_ms >= limits.preparation_total_ms:
            _stop(FiniteContextDebtReason.RESOURCE_BOUND, "v2 preparation aggregate time")
        self.replays += 1
        self.active_started = monotonic()

    def induction_allowance(self, limits):
        if self.active_started is None:
            _stop(FiniteContextDebtReason.INVALID_INPUT, "unaccounted v2 preparation")
        remaining = limits.preparation_total_ms - self.elapsed_ms - (
            monotonic() - self.active_started) * 1000
        if remaining <= 0:
            _stop(FiniteContextDebtReason.RESOURCE_BOUND, "v2 preparation aggregate time")
        return max(1, min(limits.induction_replay_total_ms, int(remaining)))

    def finish(self, limits):
        self.elapsed_ms += (monotonic() - self.active_started) * 1000
        self.active_started = None
        if self.elapsed_ms > limits.preparation_total_ms:
            _stop(FiniteContextDebtReason.RESOURCE_BOUND, "v2 preparation aggregate time")


def _scope(analysis):
    return analysis.evidence.unit.scopes.function.scope.digest


def _canonical(value, budget, depth=0):
    """Bounded structural encoding; no repr(), pickle, or mutable payloads."""
    budget[0] -= 1
    if budget[0] < 0 or depth > 64:
        _stop(FiniteContextDebtReason.RESOURCE_BOUND, "identity payload item/depth budget")
    if value is None or type(value) in (bool, int, str):
        if type(value) is str and len(value) > 65536:
            _stop(FiniteContextDebtReason.RESOURCE_BOUND, "identity text budget")
        budget[1] -= len(value) * 6 if type(value) is str else 32
        if budget[1] < 0:
            _stop(FiniteContextDebtReason.RESOURCE_BOUND, "identity byte preflight")
        return value
    if type(value) is bytes:
        if len(value) > 262144:
            _stop(FiniteContextDebtReason.RESOURCE_BOUND, "identity byte budget")
        budget[1] -= 2 * len(value) + 16
        if budget[1] < 0:
            _stop(FiniteContextDebtReason.RESOURCE_BOUND, "identity byte preflight")
        return ["bytes", value.hex()]
    if isinstance(value, Enum):
        return [type(value).__module__, type(value).__qualname__, value.value]
    if type(value) is BoundLocalMemorySsa:
        value._validate()
        return ["live-bound-ssa", _canonical((value.unit, value.result), budget, depth + 1)]
    if type(value) is tuple:
        if len(value) > budget[0]:
            _stop(FiniteContextDebtReason.RESOURCE_BOUND, "identity tuple budget")
        return [_canonical(row, budget, depth + 1) for row in value]
    if is_dataclass(value) and not isinstance(value, type) and value.__dataclass_params__.frozen:
        return [type(value).__module__, type(value).__qualname__, [
            [field.name, _canonical(getattr(value, field.name), budget, depth + 1)]
            for field in fields(value)]]
    _stop(FiniteContextDebtReason.INVALID_INPUT,
          f"identity contains unsupported mutable/opaque payload: {type(value).__qualname__}")


def _normalization_payload(analysis, limits):
    normal = analysis.normalized
    if normal.scopes is not analysis.evidence.unit.scopes:
        _stop(FiniteContextDebtReason.CLOSURE_MISMATCH, "normalization scope is not retained evidence")
    graphs = []
    for graph in (normal.cfg, normal.dependencies):
        if not graph.is_frozen:
            _stop(FiniteContextDebtReason.CLOSURE_MISMATCH, "unfrozen normalization graph")
        if graph.node_count > limits.graph_nodes or graph.edge_count > limits.graph_edges:
            _stop(FiniteContextDebtReason.RESOURCE_BOUND, "normalization graph preflight")
        graphs.append((tuple(graph.node(i) for i in range(graph.node_count)), graph.weighted_edges()))
    # scopes are retained by identity above; the raw observation and snapshot
    # bind their content. The optional presentation document is not semantics.
    payload = tuple((field.name, getattr(normal, field.name)) for field in fields(normal)
                    if field.name not in {"document", "scopes", "cfg", "dependencies"})
    return (_scope(analysis), analysis.evidence.unit.scopes.program.evidence,
            analysis.evidence.unit.observation, analysis.evidence.seeds,
            tuple(graphs), payload, analysis.boundaries)


def _validate_limits(limits):
    default = (FiniteContextV2Limits() if type(limits) is FiniteContextV2Limits
               else FiniteContextLimits())
    if type(limits) is not type(default) or limits.revision != default.revision:
        _stop(FiniteContextDebtReason.REVISION_MISMATCH, "unsupported limit profile")
    for field in fields(default):
        if field.name == "revision":
            continue
        value = getattr(limits, field.name)
        if type(value) is not int or not 0 < value <= getattr(default, field.name):
            _stop(FiniteContextDebtReason.RESOURCE_BOUND, f"invalid/unsupported {field.name} ceiling")


def _symbolic_entry_profile(analyses, induction, program, space, limits):
    """Derive narrow initial RAM eligibility from replayed direct READs."""
    if type(limits) is not FiniteContextV2Limits:
        _stop(FiniteContextDebtReason.REVISION_MISMATCH, "symbolic entry needs v2 limits")
    reads = []
    for ledger in induction.effects:
        for effect in ledger.direct_address_effects:
            if effect.kind is DirectEffectKind.READ:
                if (effect.coordinate.space_id != space or effect.byte_size <= 0
                        or effect.coordinate.byte_offset + effect.byte_size > 1 << 64):
                    _stop(FiniteContextDebtReason.PREMISE_MISMATCH, "direct READ geometry differs")
                reads.append((effect.coordinate.byte_offset,
                              effect.coordinate.byte_offset + effect.byte_size))
                if len(reads) > limits.symbolic_entry_ranges:
                    _stop(FiniteContextDebtReason.RESOURCE_BOUND, "symbolic READ range count")
    if not reads:
        _stop(FiniteContextDebtReason.PREMISE_MISMATCH, "no replayed direct RAM READ")
    merged = []
    for start, end in sorted(reads):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    if sum(end - start for start, end in merged) > limits.symbolic_entry_bytes:
        _stop(FiniteContextDebtReason.RESOURCE_BOUND, "symbolic entry byte budget")
    runs = program._retained_committed_runs()
    if type(runs) is not tuple:
        _stop(FiniteContextDebtReason.PREMISE_MISMATCH, "retained committed runs unavailable")
    if len(runs) > limits.payload_items:
        _stop(FiniteContextDebtReason.RESOURCE_BOUND, "committed run count")
    initialized = sorted((run.byte_start, run.byte_end, run) for run in runs
                         if type(run) is CommittedMemoryRun and run.space_id == space
                         and run.is_initialized is True)
    covering = set()
    for start, end in merged:
        cursor = start
        for run_start, run_end, run in initialized:
            if run_end <= cursor:
                continue
            if run_start > cursor:
                break
            covering.add(run)
            cursor = max(cursor, run_end)
            if cursor >= end:
                break
        if cursor < end:
            _stop(FiniteContextDebtReason.PREMISE_MISMATCH,
                  "replayed direct READ lacks initialized committed-run coverage")
    if any(type(run) is not CommittedMemoryRun for run in runs):
        _stop(FiniteContextDebtReason.PREMISE_MISMATCH, "malformed committed runs")
    if any(row.evidence.unit.scopes.program._retained_committed_runs() != runs
           for row in analyses):
        _stop(FiniteContextDebtReason.CLOSURE_MISMATCH, "closure committed runs differ")
    geometry = tuple(row for row in program.evidence.address_spaces if row.space_id == space)
    if (len(geometry) != 1 or not geometry[0].is_memory_space
            or geometry[0].address_size_bits != 64
            or geometry[0].addressable_unit_bytes != 1):
        _stop(FiniteContextDebtReason.PREMISE_MISMATCH, "symbolic RAM geometry differs")
    return SymbolicEntryProfile("configured-direct-read-initialized-ram-v1",
        program.scope.digest, program.evidence.loaded_memory_digest,
        space, geometry[0].address_size_bits, geometry[0].addressable_unit_bytes,
        tuple(AbsolutePremiseRange(space, start, end - start) for start, end in merged),
        tuple(sorted(covering, key=lambda run: (run.space_id, run.byte_start, run.byte_size))))


def _ranges(rows, space, limits):
    if type(rows) is not tuple or len(rows) > limits.premise_ranges:
        _stop(FiniteContextDebtReason.RESOURCE_BOUND, "premise range preflight")
    for row in rows:
        if (type(row) is not AbsolutePremiseRange
                or any(type(value) is not int for value in (row.space_id, row.start, row.size))
                or row.space_id != space or row.start < 0 or row.size <= 0
                or row.start + row.size > 1 << 64):
            _stop(FiniteContextDebtReason.PREMISE_MISMATCH, "unsupported absolute range geometry")
    if rows != tuple(sorted(set(rows))):
        _stop(FiniteContextDebtReason.PREMISE_MISMATCH, "ranges must be canonical and unique")


def _prepare_configured_finite_context_request(
    analyses, root_analysis, local_slice, demanded_spans, induction, /, *,
    shared_state, isolated_stack, initial_constraints=(),
    revisions=FiniteContextRevisions(), limits=FiniteContextLimits(),
    _preparation_budget=None,
):
    """Replay a conditional input envelope; never authorize production completion."""
    _validate_limits(limits)
    v2 = type(limits) is FiniteContextV2Limits
    if (v2 and _preparation_budget is not None and type(_preparation_budget) is not _V2PreparationBudget
            or not v2 and _preparation_budget is not None):
        _stop(FiniteContextDebtReason.INVALID_INPUT, "invalid preparation accounting")
    if v2 and (_preparation_budget is None or _preparation_budget.active_started is None):
        _stop(FiniteContextDebtReason.INVALID_INPUT, "v2 preparation lacks accounting")
    expected_revisions = FiniteContextV2Revisions() if v2 else FiniteContextRevisions()
    if type(revisions) is not type(expected_revisions) or revisions != expected_revisions:
        _stop(FiniteContextDebtReason.REVISION_MISMATCH, "unsupported request/proof/compiler/query revision")
    if v2 and initial_constraints != ():
        _stop(FiniteContextDebtReason.PREMISE_MISMATCH,
              "symbolic entry cannot assert initial image byte equality")
    if type(analyses) is not tuple or not analyses or len(analyses) > limits.functions:
        _stop(FiniteContextDebtReason.RESOURCE_BOUND, "closure function preflight")
    if any(type(row) is not ConfiguredFunctionAnalysis for row in analyses):
        _stop(FiniteContextDebtReason.INVALID_INPUT, "exact configured analyses required")
    instructions = operations = graph_nodes = graph_edges = 0
    for analysis in analyses:
        observation = analysis.evidence.unit.observation
        if observation is None:
            _stop(FiniteContextDebtReason.CLOSURE_MISMATCH, "missing raw observation")
        instructions += len(observation.instructions)
        if instructions > limits.instructions:
            _stop(FiniteContextDebtReason.RESOURCE_BOUND, "instruction preflight")
        for instruction in observation.instructions:
            operations += len(instruction.operations)
            if operations > limits.operations:
                _stop(FiniteContextDebtReason.RESOURCE_BOUND, "operation preflight")
        for graph in (analysis.normalized.cfg, analysis.normalized.dependencies):
            graph_nodes += graph.node_count
            graph_edges += graph.edge_count
        if (graph_nodes > limits.graph_nodes or graph_edges > limits.graph_edges
                or len(analysis.boundaries.nodes) > limits.payload_items
                or len(analysis.slices) > limits.payload_items):
            _stop(FiniteContextDebtReason.RESOURCE_BOUND, "normalization/boundary preflight")
    if (not any(root_analysis is row for row in analyses)
            or type(local_slice) is not ObservedBoundarySlice
            or not any(local_slice is row for row in root_analysis.slices)
            or not any(local_slice.root is row for row in root_analysis.boundaries.query_roots)
            or local_slice.root.kind is not BoundaryKind.SINK):
        _stop(FiniteContextDebtReason.ROOT_MISMATCH, "exact retained slice and sink root required")
    root = local_slice.root
    if (not root.physical_spans or type(demanded_spans) is not tuple or not demanded_spans
            or any(type(span) is not ByteSpan for span in demanded_spans)
            or not root_analysis.normalized.dependencies.has_node(root.node)):
        _stop(FiniteContextDebtReason.DEMAND_MISMATCH, "nonempty observed root spans required")
    if len(demanded_spans) > limits.demand_bytes or sum(span.size for span in demanded_spans) > limits.demand_bytes:
        _stop(FiniteContextDebtReason.RESOURCE_BOUND, "root byte demand budget")
    if (demanded_spans != root.physical_spans
            or demanded_spans != tuple(sorted(set(demanded_spans), key=lambda row: row.canonical_key))
            or any(a.overlaps(b) for i, a in enumerate(demanded_spans) for b in demanded_spans[i + 1:])):
        _stop(FiniteContextDebtReason.DEMAND_MISMATCH, "demand must equal all canonical disjoint observed root spans")
    if type(induction) is not ConditionalInductionClosure:
        _stop(FiniteContextDebtReason.CERTIFICATE_UNAVAILABLE, "conditional induction record required")
    # Charge before iterating/sorting caller-supplied certificate containers.
    _canonical(induction, [limits.payload_items, limits.cache_bytes])
    if induction.root_scope_digest != _scope(root_analysis):
        _stop(FiniteContextDebtReason.ROOT_MISMATCH, "induction belongs to another root function")
    if type(initial_constraints) is not tuple or len(initial_constraints) > limits.demand_bytes:
        _stop(FiniteContextDebtReason.RESOURCE_BOUND, "initial constraint preflight")
    program = root_analysis.evidence.unit.scopes.program
    for constraint in initial_constraints:
        if (type(constraint) is not InitialByteConstraint or type(constraint.span) is not ByteSpan
                or type(constraint.value) is not bytes or len(constraint.value) != constraint.span.size
                or constraint.span.object_id.scope != program.scope
                or constraint.span.object_id.kind not in {StorageObjectKind.REGISTER_FILE, StorageObjectKind.ADDRESS_SPACE}
                or constraint.span.end > 1 << 64):
            _stop(FiniteContextDebtReason.INVALID_INPUT, "unsupported initial architectural byte constraint")
    if (sum(len(row.value) for row in initial_constraints) > limits.symbolic_state_bytes
            or initial_constraints != tuple(sorted(initial_constraints, key=lambda row: row.span.canonical_key))
            or any(a.span.overlaps(b.span) for i, a in enumerate(initial_constraints) for b in initial_constraints[i + 1:])):
        _stop(FiniteContextDebtReason.INVALID_INPUT, "initial constraints overlap, exceed budget, or are noncanonical")
    if type(shared_state) is not SharedStatePremise or type(isolated_stack) is not IsolatedStackPremise:
        _stop(FiniteContextDebtReason.PREMISE_MISMATCH, "full premise payloads required, not labels")
    for premise in (shared_state, isolated_stack):
        if (type(premise.binding) is not RootPremiseBinding
                or any(type(getattr(premise.binding, key)) is not int for key in (
                    "root_node", "occurrence_ordinal", "fragment_ordinal", "address_space_id",
                    "address_size_bits", "addressable_unit_bytes"))
                or any(type(getattr(premise.binding, key)) is not bytes for key in (
                    "program_scope_digest", "executable_sha256", "loaded_memory_digest",
                    "root_scope_digest", "root_observation_digest"))):
            _stop(FiniteContextDebtReason.PREMISE_MISMATCH, "malformed root premise binding")
    spaces = {row.interval.address_space_id for inv in induction.inventories for row in inv.accesses if row.interval is not None}
    if len(spaces) != 1:
        _stop(FiniteContextDebtReason.PREMISE_MISMATCH, "one observed RAM geometry required")
    space = next(iter(spaces))
    binding = RootPremiseBinding(program.scope.digest, program.evidence.executable_sha256,
        program.evidence.loaded_memory_digest, _scope(root_analysis),
        root_analysis.evidence.unit.scopes.function.observation_digest,
        root.node, root.occurrence_ordinal, root.fragment_ordinal, demanded_spans, initial_constraints, space)
    if (type(shared_state.binding) is not RootPremiseBinding or shared_state != SharedStatePremise(binding)
            or shared_state.register_and_ram_shared is not True
            or shared_state.unique_activation_local is not True
            or shared_state.observed_control_effects_only is not True
            or type(isolated_stack.binding) is not RootPremiseBinding or isolated_stack.binding != binding
            or isolated_stack.revision != ISOLATED_STACK_PROFILE
            or isolated_stack.complete_root_descendant_token_footprint is not True
            or isolated_stack.loaded_image_inventory_asserted_complete is not True
            or isolated_stack.excludes_caller_provided_frame_pointers is not False
            or isolated_stack.stack_relative_window != induction.rank_context.modular_window):
        _stop(FiniteContextDebtReason.PREMISE_MISMATCH, "premise binding/semantics differ from selected root")
    _ranges(isolated_stack.loaded_image_ranges, space, limits)
    _ranges(isolated_stack.absolute_effect_ranges, space, limits)
    expected_absolute = tuple(sorted({AbsolutePremiseRange(row.coordinate.space_id, row.coordinate.byte_offset, row.byte_size)
        for ledger in induction.effects for row in ledger.direct_address_effects}))
    if not isolated_stack.loaded_image_ranges or isolated_stack.absolute_effect_ranges != expected_absolute:
        _stop(FiniteContextDebtReason.PREMISE_MISMATCH, "missing image assertion or incomplete absolute-effect ranges")
    symbolic_entry = _symbolic_entry_profile(analyses, induction, program, space, limits) if v2 else None
    if v2:
        # The image inventory remains an isolated-stack premise, but a caller
        # assertion alone does not admit initial RAM: retained initialized
        # committed runs must cover each replayed direct READ interval.
        for eligible in symbolic_entry.ranges:
            cursor = eligible.start
            for image in isolated_stack.loaded_image_ranges:
                if image.start <= cursor < image.start + image.size:
                    cursor = min(eligible.start + eligible.size, image.start + image.size)
                    if cursor == eligible.start + eligible.size:
                        break
            if cursor != eligible.start + eligible.size:
                _stop(FiniteContextDebtReason.PREMISE_MISMATCH,
                      "symbolic READ is outside asserted loaded image")
    if (len(induction.verified_edges.edges) > limits.call_edges
            or induction.rank_context.maximum_context_expansions > limits.contexts
            or induction.solver_queries > limits.solver_queries
            or any(row.normal_path_count > limits.cfg_paths for row in induction.cases)):
        _stop(FiniteContextDebtReason.RESOURCE_BOUND, "edge/context/path/proof-query preflight")
    # Fixed replay ceilings are deliberately narrow. The caller cannot enlarge
    # solver work through a supplied certificate's limit tuple.
    replay_options = dict(max_queries=limits.solver_queries,
        solver_timeout_ms=(limits.induction_query_timeout_ms if v2 else limits.solver_timeout_ms))
    if v2:
        replay_options["solver_total_ms"] = _preparation_budget.induction_allowance(limits)
    try:
        replay = close_recursive_preservation_induction(
            analyses, induction.inventories, induction.effects, induction.verified_edges,
            induction.frame_step, induction.rank_context, induction.rank_register,
            shared_state_profile=SHARED_STATE_PROFILE, isolated_stack_profile=ISOLATED_STACK_PROFILE,
            **replay_options)
    except InductionClosureIncomplete as error:
        reason = (FiniteContextDebtReason.RESOURCE_BOUND if error.reason.value == "resource_bound"
                  else FiniteContextDebtReason.CERTIFICATE_UNAVAILABLE)
        _stop(reason, f"conditional induction replay: {error}")
    except (TypeError, ValueError, AttributeError, KeyError) as error:
        _stop(FiniteContextDebtReason.CLOSURE_MISMATCH, f"malformed retained proof input: {error}")
    if replay != induction:
        _stop(FiniteContextDebtReason.CLOSURE_MISMATCH, "conditional induction payload/revision/limits changed")
    ordered = tuple(sorted(analyses, key=_scope))
    if len({_scope(row) for row in ordered}) != len(ordered):
        _stop(FiniteContextDebtReason.CLOSURE_MISMATCH, "duplicate function scope")
    payload = (tuple(_normalization_payload(row, limits) for row in ordered),
        binding, shared_state, isolated_stack, induction, revisions, limits)
    if v2:
        payload += (symbolic_entry,)
    encoded = json.dumps(_canonical(payload, [limits.payload_items, limits.cache_bytes]), separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(encoded) > limits.cache_bytes:
        _stop(FiniteContextDebtReason.RESOURCE_BOUND, "request identity serialization budget")
    digest = sha256((b"configured-finite-context-inputs-v2\0" if v2
                     else b"configured-finite-context-inputs-v1\0") + encoded).digest()
    return ConfiguredFiniteContextRequest(ordered, root_analysis, local_slice, demanded_spans,
        initial_constraints, shared_state, isolated_stack, induction, revisions, limits, digest,
        symbolic_entry, _preparation_budget)


def prepare_configured_finite_context_request(*args, **kwargs):
    """Prepare the exact dormant request; malformed input is always typed debt."""
    limits = kwargs.get("limits", FiniteContextLimits())
    budget = None
    if type(limits) is FiniteContextV2Limits:
        _validate_limits(limits)
        budget = kwargs.get("_preparation_budget")
        if budget is None:
            budget = _V2PreparationBudget()
        if type(budget) is not _V2PreparationBudget:
            _stop(FiniteContextDebtReason.INVALID_INPUT, "invalid v2 preparation accounting")
        kwargs["_preparation_budget"] = budget
        budget.begin(limits)
    try:
        return _prepare_configured_finite_context_request(*args, **kwargs)
    except (TypeError, ValueError, AttributeError, KeyError, IndexError, OverflowError) as error:
        _stop(FiniteContextDebtReason.INVALID_INPUT, f"malformed finite-context envelope: {error}")
    finally:
        if budget is not None:
            budget.finish(limits)


def prepare_configured_symbolic_entry_request(*args, **kwargs):
    """Prepare a dormant v2 request with derived, initialized symbolic RAM."""
    kwargs.setdefault("revisions", FiniteContextV2Revisions())
    kwargs.setdefault("limits", FiniteContextV2Limits())
    return prepare_configured_finite_context_request(*args, **kwargs)


def replay_configured_finite_context_request(request):
    """Revalidate one retained v1/v2 request with its exact profile and budget."""
    if type(request) is not ConfiguredFiniteContextRequest:
        _stop(FiniteContextDebtReason.INVALID_INPUT, "exact finite-context request required")
    v2 = type(request.limits) is FiniteContextV2Limits
    if (v2 and (type(request.revisions) is not FiniteContextV2Revisions
                or type(request.symbolic_entry) is not SymbolicEntryProfile
                or type(request._preparation_budget) is not _V2PreparationBudget)):
        _stop(FiniteContextDebtReason.INVALID_INPUT, "incomplete v2 symbolic-entry request")
    if (not v2 and (type(request.limits) is not FiniteContextLimits
                    or type(request.revisions) is not FiniteContextRevisions
                    or request.symbolic_entry is not None
                    or request._preparation_budget is not None)):
        _stop(FiniteContextDebtReason.INVALID_INPUT, "incomplete v1 exact-byte request")
    replay = prepare_configured_finite_context_request(
        request.analyses, request.root_analysis, request.local_slice, request.demanded_spans,
        request.induction, shared_state=request.shared_state, isolated_stack=request.isolated_stack,
        initial_constraints=request.initial_constraints, revisions=request.revisions,
        limits=request.limits, _preparation_budget=request._preparation_budget)
    if replay.input_digest != request.input_digest or replay.symbolic_entry != request.symbolic_entry:
        _stop(FiniteContextDebtReason.CLOSURE_MISMATCH, "request payload changed after preparation")
    return replay


def stop_selected_finite_context_request(analyses, request, /):
    """Root-specific validation before any legacy view/cache work; always raises."""
    if type(request) is not ConfiguredFiniteContextRequest:
        _stop(FiniteContextDebtReason.INVALID_INPUT, "exact finite-context request required")
    if (type(analyses) is not tuple or len(analyses) > FiniteContextLimits().functions
            or any(type(row) is not ConfiguredFunctionAnalysis for row in analyses)):
        _stop(FiniteContextDebtReason.INVALID_INPUT, "exact bounded invocation analyses required")
    try:
        entries = tuple(row.entry for row in analyses)
    except (TypeError, ValueError, AttributeError, KeyError, IndexError, OverflowError) as error:
        _stop(FiniteContextDebtReason.INVALID_INPUT,
              f"malformed selected invocation evidence: {error}")
    if any(type(entry) is not AddressCoordinate for entry in entries):
        _stop(FiniteContextDebtReason.INVALID_INPUT,
              "selected invocation entries must be exact coordinates")
    if len(set(entries)) != len(analyses):
        _stop(FiniteContextDebtReason.CLOSURE_MISMATCH, "duplicate invocation entries")
    if (type(request.analyses) is not tuple or not request.analyses
            or len(request.analyses) > FiniteContextLimits().functions):
        _stop(FiniteContextDebtReason.INVALID_INPUT, "invalid retained request closure")
    if any(not any(row is retained for retained in analyses) for row in request.analyses):
        _stop(FiniteContextDebtReason.CLOSURE_MISMATCH, "request closure is not retained in this invocation")
    replay_configured_finite_context_request(request)
    _stop(FiniteContextDebtReason.PUBLIC_WIRE_UNAVAILABLE,
          "conditional request replayed; finite byte-state compiler and public conditional completion wire unavailable")
