"""Dormant, bounded discovery of physical selectors for recursive certificates.

The retained root scope is an input. Recursive scope and register selectors are
derived solely from the verified direct edges and observed raw operations.
This result is conditional diagnostic evidence, not production admission.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import Enum, StrEnum
from hashlib import sha256
import json
from time import monotonic

from ..call_seeds import _operation_key
from ..call_observation_contracts import BoundLocalMemorySsa
from ..physical_state import PhysicalRegisterSlice
from ..scope_identity import VarnodeKindCode
from .configured_interprocedural_contracts import ConfiguredFunctionAnalysis
from .configured_recursive_all_effects import (
    RecursiveAllEffectInventory, build_recursive_all_effect_inventory,
)
from .configured_recursive_call_edges import (
    DirectCallEdgeDebtReason, VerifiedDirectCallEdges, VerifiedDirectCallEdgesIncomplete,
    verify_direct_call_edges,
)
from .configured_recursive_frame_base_certificate import (
    FrameBaseCertificateIncomplete, FrameBaseDebtReason,
    InductiveFrameBaseCertificate, ISOLATED_STACK_PROFILE,
    SHARED_STATE_PROFILE, certify_inductive_frame_base,
)
from .configured_recursive_frame_inventory import (
    RecursiveFrameInventory, build_recursive_frame_inventory,
)
from .configured_recursive_induction_closure import (
    ConditionalInductionClosure, InductionClosureIncomplete, InductionDebtReason,
    close_recursive_preservation_induction,
)
from .configured_recursive_rank_context import (
    RankContextDebtReason, RankContextIncomplete,
    certify_root_rank_context,
)


REVISION = "configured-recursive-selector-discovery-v1"
CERTIFIED_WITNESS_V2 = "configured-recursive-certified-witness-v2"
_DEFAULT_CEILINGS = {
    "max_functions": 64, "max_operations": 4096,
    "max_operand_nodes": 32768, "max_evidence_rows": 16384,
    "max_edges": 256, "max_candidates": 256, "max_tuples": 4096,
    "max_replays": 8192, "total_ms": 120000, "max_rank": 32,
    "max_steps": 100000, "max_paths": 128, "max_queries": 10000,
    "solver_timeout_ms": 5000, "max_contexts": 1024,
    "max_graph_nodes": 100000, "max_graph_edges": 200000,
    "max_identity_items": 200000, "max_identity_bytes": 8388608,
}


class SelectorDiscoveryStatus(StrEnum):
    UNIQUE = "unique"
    WITNESS_FOUND = "witness_found"
    NO_CANDIDATE = "no_candidate"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"
    BUDGET = "budget"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class SelectorTuple:
    stack_pointer: PhysicalRegisterSlice
    frame_base: PhysicalRegisterSlice
    rank: PhysicalRegisterSlice


@dataclass(frozen=True, slots=True)
class SelectorCandidateDebt:
    selectors: SelectorTuple | None
    stage: str
    reason: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class SelectorDiscoveryResult:
    status: SelectorDiscoveryStatus
    root_scope_digest: bytes
    recursive_scope_digest: bytes | None
    candidate_universe_digest: bytes | None
    replay_identity_digest: bytes | None
    candidates: tuple[SelectorTuple, ...]
    certified: tuple[SelectorTuple, ...]
    eliminated: tuple[SelectorCandidateDebt, ...]
    unresolved: tuple[SelectorCandidateDebt, ...]
    attempted_tuples: int
    frame_replays: int
    rank_replays: int
    induction_replays: int
    evidence_replays: int
    closure: ConditionalInductionClosure | None = None
    witness_policy: str = REVISION
    selected: SelectorTuple | None = None  # minimum among completed certificates only
    selected_identity_digest: bytes | None = None

    @property
    def diagnostic_only(self) -> bool:
        return True


def _overlap(left: PhysicalRegisterSlice, right: PhysicalRegisterSlice) -> bool:
    return (left.byte_offset < right.byte_offset + right.byte_size
            and right.byte_offset < left.byte_offset + left.byte_size)


def _raw_operations(analysis: ConfiguredFunctionAnalysis):
    return {
        _operation_key(instruction.address, ordinal, operation.opcode): operation
        for instruction in analysis.evidence.unit.observation.instructions
        for ordinal, operation in enumerate(instruction.operations)
    }


def _register(node, size: int, space: int | None = None):
    return (node is not None and node.kind is VarnodeKindCode.REGISTER
            and node.byte_size == size
            and (space is None or node.coordinate.space_id == space))


def _token_sp(analyses, frames):
    """Intersect exact full-width CALL and RETURN register observations."""
    seen = set()
    for scope, analysis in analyses.items():
        raw = _raw_operations(analysis)
        frame = frames[scope]
        for token in frame.call_tokens:
            adjust = raw.get(token.adjust_operation_key)
            store = raw.get(token.store_operation_key)
            if (adjust is None or store is None or adjust.opcode != "INT_SUB"
                    or len(adjust.inputs) != 2 or not _register(adjust.output, 8)
                    or adjust.inputs[0] != adjust.output
                    or adjust.inputs[1].kind is not VarnodeKindCode.CONSTANT
                    or adjust.inputs[1].byte_size != 8
                    or adjust.inputs[1].coordinate.byte_offset != 8
                    or store.opcode != "STORE" or len(store.inputs) != 3
                    or store.inputs[1] != adjust.output
                    or token.interval.byte_size != 8):
                return None
            seen.add((adjust.output.coordinate.space_id, adjust.output.coordinate.byte_offset))
        for token in frame.return_tokens:
            load = raw.get(token.load_operation_key)
            restore = raw.get(token.restore_operation_key)
            if (load is None or restore is None or load.opcode != "LOAD"
                    or len(load.inputs) != 2 or restore.opcode != "INT_ADD"
                    or len(restore.inputs) != 2 or not _register(restore.output, 8)
                    or restore.inputs[0] != restore.output
                    or load.inputs[1] != restore.output
                    or restore.inputs[1].kind is not VarnodeKindCode.CONSTANT
                    or restore.inputs[1].byte_size != 8
                    or restore.inputs[1].coordinate.byte_offset != 8
                    or token.interval.byte_size != 8):
                return None
            seen.add((restore.output.coordinate.space_id, restore.output.coordinate.byte_offset))
    if len(seen) != 1:
        return None
    space, offset = next(iter(seen))
    return space, PhysicalRegisterSlice(offset, 8)


def _may_save_entry_frame_base(analysis, selector, register_space):
    """Overapproximate exact COPY/CAST ancestry into a raw stack STORE.

    The frame checker recognizes ENTRY only through width-preserving copies.
    Without even a static path from that entry register to a STORE value, a
    candidate cannot satisfy its mandatory observed save slot.
    """
    def identity(node):
        if node is None or node.byte_size != 8 or node.kind not in {
                VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE}:
            return None
        return (node.kind, node.coordinate.space_id, node.coordinate.byte_offset)

    links = {}
    stores = set()
    for instruction in analysis.evidence.unit.observation.instructions:
        for operation in instruction.operations:
            if operation.opcode in {"COPY", "CAST"} and len(operation.inputs) == 1:
                source, target = identity(operation.inputs[0]), identity(operation.output)
                if source is not None and target is not None:
                    links.setdefault(source, set()).add(target)
            if operation.opcode == "STORE" and len(operation.inputs) == 3:
                stores.add(identity(operation.inputs[2]))
    reached = set()
    pending = [(VarnodeKindCode.REGISTER, register_space, selector.byte_offset)]
    while pending:
        node = pending.pop()
        if node in reached:
            continue
        if node in stores:
            return True
        reached.add(node)
        pending.extend(links.get(node, set()) - reached)
    return False


def _may_write_recursive_rank(analysis, selector, register_space):
    return any(operation.output is not None
               and operation.output.kind is VarnodeKindCode.REGISTER
               and operation.output.coordinate.space_id == register_space
               and operation.output.coordinate.byte_offset < selector.byte_offset + selector.byte_size
               and selector.byte_offset < operation.output.coordinate.byte_offset + operation.output.byte_size
               for instruction in analysis.evidence.unit.observation.instructions
               for operation in instruction.operations)


class _IdentityBudget(Exception):
    pass


class _IdentityUnsupported(Exception):
    pass


def _canonical(value, budget, depth=0):
    """Bounded deterministic primitive/frozen-record encoding, with no repr."""
    budget[0] -= 1
    if budget[0] < 0 or depth > 64:
        raise _IdentityBudget
    if value is None or type(value) in (bool, int, str):
        budget[1] -= len(value) * 6 if type(value) is str else 32
        if budget[1] < 0:
            raise _IdentityBudget
        return value
    if type(value) is bytes:
        budget[1] -= 2 * len(value) + 16
        if budget[1] < 0:
            raise _IdentityBudget
        return ["bytes", value.hex()]
    if isinstance(value, Enum):
        return [type(value).__module__, type(value).__qualname__,
                _canonical(value.value, budget, depth + 1)]
    if type(value) is BoundLocalMemorySsa:
        value._validate()
        return ["live-bound-ssa", _canonical((value.unit, value.result), budget, depth + 1)]
    if type(value) is tuple:
        if len(value) > budget[0]:
            raise _IdentityBudget
        return [_canonical(item, budget, depth + 1) for item in value]
    if is_dataclass(value) and not isinstance(value, type) and value.__dataclass_params__.frozen:
        return [type(value).__module__, type(value).__qualname__, [
            [field.name, _canonical(getattr(value, field.name), budget, depth + 1)]
            for field in fields(value)]]
    raise _IdentityUnsupported(type(value).__qualname__)


def _digest(domain: bytes, payload, max_items: int, max_bytes: int):
    canonical = _canonical(payload, [max_items, max_bytes])
    encoded = json.dumps(canonical, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(encoded) > max_bytes:
        raise _IdentityBudget
    return sha256(domain + b"\0" + encoded).digest()


def _analysis_identity(analysis, frame, effect, graph_budget):
    normal = analysis.normalized
    graphs = []
    for graph in (normal.cfg, normal.dependencies):
        graph_budget[0] -= graph.node_count
        graph_budget[1] -= graph.edge_count
        if graph_budget[0] < 0 or graph_budget[1] < 0 or not graph.is_frozen:
            raise _IdentityBudget
        graphs.append((tuple(graph.node(index) for index in range(graph.node_count)),
                       tuple(graph.weighted_edges())))
    normalized_fields = tuple((field.name, getattr(normal, field.name))
                              for field in fields(normal)
                              if field.name not in {"document", "scopes", "cfg", "dependencies"})
    return (analysis.evidence.unit.scopes.program.evidence,
            analysis.evidence.unit.scopes.function.scope.digest,
            analysis.evidence.unit.observation, analysis.evidence.seeds,
            analysis.evidence.naming, tuple(graphs), normalized_fields,
            frame, effect)


def _selector_key(selector: SelectorTuple, register_space: int):
    """Physical ordering only among completed proof witnesses."""
    return (register_space,
            selector.stack_pointer.byte_offset, selector.stack_pointer.byte_size,
            selector.frame_base.byte_offset, selector.frame_base.byte_size,
            selector.rank.byte_offset, selector.rank.byte_size)


def _witness_digest(policy, replay, universe, selected, closure,
                    max_identity_items, max_identity_bytes):
    return _digest(b"tdo-recursive-selector-witness-v2",
                   (policy, replay, universe, selected, closure,
                    closure.rank_context.modular_window),
                   max_identity_items, max_identity_bytes)


def discover_recursive_selectors(
    analyses: tuple[ConfiguredFunctionAnalysis, ...],
    inventories: tuple[RecursiveFrameInventory, ...],
    effects: tuple[RecursiveAllEffectInventory, ...],
    verified_edges: VerifiedDirectCallEdges,
    root_scope_digest: bytes,
    /, *,
    max_functions: int = 64,
    max_operations: int = 4096,
    max_operand_nodes: int = 32768,
    max_evidence_rows: int = 16384,
    max_edges: int = 256,
    max_candidates: int = 256,
    max_tuples: int = 4096,
    max_replays: int = 8192,
    total_ms: int = 120000,
    max_rank: int = 32,
    max_steps: int = 100000,
    max_paths: int = 128,
    max_queries: int = 10000,
    solver_timeout_ms: int = 5000,
    max_contexts: int = 1024,
    max_graph_nodes: int = 100000,
    max_graph_edges: int = 200000,
    max_identity_items: int = 200000,
    max_identity_bytes: int = 8388608,
    witness_policy: str = REVISION,
) -> SelectorDiscoveryResult:
    """Exhaust a finite observed selector grammar and close each viable tuple.

    A definite failed obligation can eliminate a tuple. Unsupported evidence,
    solver uncertainty and a resource stop cannot eliminate one. V1 requires
    uniqueness across the entire bounded candidate universe. V2 selects one
    completed full-closure proof witness and retains candidate-local debt; its
    physical ordering does not assert that it is the least valid selector.
    The search never uses names, ABI offsets, source labels or expected answers.
    """
    counters = [0, 0, 0, 0, 0]

    def result(status, recursive=None, universe=None, replay=None, candidates=(),
               certified=(), eliminated=(), unresolved=(), closure=None,
               selected=None, selected_identity=None):
        return SelectorDiscoveryResult(status, root_scope_digest, recursive, universe,
                                       replay, tuple(candidates), tuple(certified),
                                       tuple(eliminated), tuple(unresolved), *counters, closure,
                                       witness_policy, selected, selected_identity)

    limits = {
        "max_functions": max_functions, "max_operations": max_operations,
        "max_operand_nodes": max_operand_nodes, "max_evidence_rows": max_evidence_rows,
        "max_edges": max_edges, "max_candidates": max_candidates,
        "max_tuples": max_tuples, "max_replays": max_replays,
        "total_ms": total_ms, "max_rank": max_rank,
        "max_steps": max_steps, "max_paths": max_paths,
        "max_queries": max_queries, "solver_timeout_ms": solver_timeout_ms,
        "max_contexts": max_contexts, "max_graph_nodes": max_graph_nodes,
        "max_graph_edges": max_graph_edges,
        "max_identity_items": max_identity_items,
        "max_identity_bytes": max_identity_bytes,
    }
    if (type(analyses) is not tuple or type(inventories) is not tuple
            or type(effects) is not tuple or type(verified_edges) is not VerifiedDirectCallEdges
            or type(root_scope_digest) is not bytes or len(root_scope_digest) != 32
            or any(type(value) is not int or value < 1 for value in limits.values())
            or type(witness_policy) is not str
            or witness_policy not in {REVISION, CERTIFIED_WITNESS_V2}):
        return result(SelectorDiscoveryStatus.INVALID)
    if any(value > _DEFAULT_CEILINGS[name] for name, value in limits.items()):
        return result(SelectorDiscoveryStatus.BUDGET)
    deadline = monotonic() + total_ms / 1000
    if len(analyses) > max_functions or len(inventories) > max_functions or len(effects) > max_functions:
        return result(SelectorDiscoveryStatus.BUDGET)
    if len(verified_edges.edges) > max_edges:
        return result(SelectorDiscoveryStatus.BUDGET)
    if (any(type(row) is not ConfiguredFunctionAnalysis for row in analyses)
            or any(type(row) is not RecursiveFrameInventory for row in inventories)
            or any(type(row) is not RecursiveAllEffectInventory for row in effects)):
        return result(SelectorDiscoveryStatus.INVALID)
    by_scope = {row.evidence.unit.scopes.function.scope.digest: row for row in analyses}
    frames = {row.function_scope_digest: row for row in inventories}
    ledgers = {row.function_scope_digest: row for row in effects}
    if (not by_scope or len(by_scope) != len(analyses) or len(frames) != len(inventories)
            or len(ledgers) != len(effects) or set(by_scope) != set(frames)
            or set(by_scope) != set(ledgers)
            or root_scope_digest not in by_scope
            or any(not row.complete for row in (*inventories, *effects,))
            or any(row.evidence.unit.scopes.program.scope.digest != verified_edges.program_scope_digest
                   for row in analyses)):
        return result(SelectorDiscoveryStatus.UNKNOWN, unresolved=(
            SelectorCandidateDebt(None, "closure", "incomplete or mismatched evidence"),))
    evidence_rows = sum(len(row.accesses) + len(row.call_tokens) + len(row.return_tokens)
                        for row in inventories) + sum(
                            len(row.frame_accesses) + len(row.call_tokens)
                            + len(row.return_tokens) + len(row.direct_address_effects)
                            for row in effects)
    if evidence_rows > max_evidence_rows:
        return result(SelectorDiscoveryStatus.BUDGET)
    raw_operation_count = 0
    raw_operand_count = 0
    for analysis in analyses:
        observation = analysis.evidence.unit.observation
        if observation is None:
            return result(SelectorDiscoveryStatus.UNKNOWN, unresolved=(
                SelectorCandidateDebt(None, "observation", "missing raw observation"),))
        for instruction in observation.instructions:
            raw_operation_count += len(instruction.operations)
            if raw_operation_count > max_operations:
                return result(SelectorDiscoveryStatus.BUDGET)
            for operation in instruction.operations:
                raw_operand_count += len(operation.inputs) + (operation.output is not None)
                if raw_operand_count > max_operand_nodes:
                    return result(SelectorDiscoveryStatus.BUDGET)
    # A zero-success search must still rest on replayed evidence; otherwise
    # forged inventory/edge records could manufacture a false NO_CANDIDATE.
    try:
        for scope in sorted(by_scope):
            if monotonic() >= deadline or counters[4] >= max_replays:
                return result(SelectorDiscoveryStatus.BUDGET)
            replay_frame = build_recursive_frame_inventory(by_scope[scope])
            counters[4] += 1
            if any(debt.reason.value == "budget_exhausted" for debt in replay_frame.debts):
                return result(SelectorDiscoveryStatus.BUDGET)
            if replay_frame != frames[scope] or not replay_frame.complete:
                return result(SelectorDiscoveryStatus.UNKNOWN, unresolved=(
                    SelectorCandidateDebt(None, "frame_inventory", "replay mismatch or debt"),))
            if monotonic() >= deadline or counters[4] >= max_replays:
                return result(SelectorDiscoveryStatus.BUDGET)
            replay_effect = build_recursive_all_effect_inventory(by_scope[scope], replay_frame)
            counters[4] += 1
            if any(debt.reason.value == "resource_bound" for debt in replay_effect.debts):
                return result(SelectorDiscoveryStatus.BUDGET)
            if replay_effect != ledgers[scope] or not replay_effect.complete:
                return result(SelectorDiscoveryStatus.UNKNOWN, unresolved=(
                    SelectorCandidateDebt(None, "effect_inventory", "replay mismatch or debt"),))
        if monotonic() >= deadline or counters[4] >= max_replays:
            return result(SelectorDiscoveryStatus.BUDGET)
        replay_edges = verify_direct_call_edges(analyses, inventories)
        counters[4] += 1
        if monotonic() >= deadline:
            return result(SelectorDiscoveryStatus.BUDGET)
        if replay_edges != verified_edges:
            return result(SelectorDiscoveryStatus.UNKNOWN, unresolved=(
                SelectorCandidateDebt(None, "direct_edges", "replay mismatch"),))
    except VerifiedDirectCallEdgesIncomplete as error:
        if error.reason is DirectCallEdgeDebtReason.RESOURCE_BOUND:
            return result(SelectorDiscoveryStatus.BUDGET)
        return result(SelectorDiscoveryStatus.UNKNOWN, unresolved=(
            SelectorCandidateDebt(None, "direct_edges", error.reason.value),))
    except (ValueError, TypeError) as error:
        return result(SelectorDiscoveryStatus.UNKNOWN, unresolved=(
            SelectorCandidateDebt(None, "evidence", type(error).__name__),))
    successors = {scope: set() for scope in by_scope}
    for edge in verified_edges.edges:
        if edge.caller_scope_digest not in successors or edge.callee_scope_digest not in successors:
            return result(SelectorDiscoveryStatus.UNKNOWN, unresolved=(
                SelectorCandidateDebt(None, "closure", "edge outside supplied analyses"),))
        successors[edge.caller_scope_digest].add(edge.callee_scope_digest)
    reached, pending = set(), [root_scope_digest]
    while pending:
        scope = pending.pop()
        if scope not in reached:
            reached.add(scope)
            pending.extend(successors[scope] - reached)
    self_edges = {edge.caller_scope_digest for edge in verified_edges.edges
                  if edge.caller_scope_digest == edge.callee_scope_digest}
    if reached != set(by_scope) or len(self_edges) != 1 or root_scope_digest in self_edges:
        return result(SelectorDiscoveryStatus.UNKNOWN, unresolved=(
            SelectorCandidateDebt(None, "closure", "root closure or self-recursion shape"),))
    recursive = next(iter(self_edges))
    register_nodes = []
    for scope in sorted(by_scope):
        observation = by_scope[scope].evidence.unit.observation
        for instruction in observation.instructions:
            for operation in instruction.operations:
                register_nodes.extend(node for node in
                    (*operation.inputs, *((operation.output,) if operation.output else ()))
                    if node.kind is VarnodeKindCode.REGISTER)
    sp_evidence = _token_sp(by_scope, frames)
    if sp_evidence is None:
        return result(SelectorDiscoveryStatus.UNKNOWN, recursive, unresolved=(
            SelectorCandidateDebt(None, "stack_pointer", "no common exact CALL/RETURN token register"),))
    register_space, sp = sp_evidence
    observed = {(node.coordinate.space_id, node.coordinate.byte_offset, node.byte_size)
                for node in register_nodes}
    # PhysicalRegisterSlice has no space field. A same-offset candidate in a
    # second space cannot be passed to the constituent certificate unambiguously.
    if any(space != register_space for space, _, _ in observed):
        return result(SelectorDiscoveryStatus.UNKNOWN, recursive, unresolved=(
            SelectorCandidateDebt(None, "register_space", "multiple physical REGISTER spaces"),))
    frame_candidates = sorted((PhysicalRegisterSlice(offset, 8)
                               for _, offset, size in observed if size == 8
                               and not _overlap(PhysicalRegisterSlice(offset, 8), sp)),
                              key=lambda item: item.byte_offset)
    rank_candidates = sorted((PhysicalRegisterSlice(offset, 4)
                              for _, offset, size in observed if size == 4
                              and not _overlap(PhysicalRegisterSlice(offset, 4), sp)),
                             key=lambda item: item.byte_offset)
    if len(frame_candidates) + len(rank_candidates) > max_candidates:
        return result(SelectorDiscoveryStatus.BUDGET, recursive)
    candidate_rows = []
    for frame in frame_candidates:
        for rank in rank_candidates:
            if _overlap(frame, rank):
                continue
            candidate_rows.append(SelectorTuple(sp, frame, rank))
            if len(candidate_rows) > max_tuples:
                return result(SelectorDiscoveryStatus.BUDGET, recursive)
    candidates = tuple(candidate_rows)
    try:
        graph_budget = [max_graph_nodes, max_graph_edges]
        identity = (witness_policy, tuple(sorted(limits.items())),
                    root_scope_digest, recursive,
                    tuple(_analysis_identity(by_scope[scope], frames[scope],
                                             ledgers[scope], graph_budget)
                          for scope in sorted(by_scope)), verified_edges,
                    SHARED_STATE_PROFILE, ISOLATED_STACK_PROFILE)
        replay_domain = (b"tdo-recursive-selector-replay-v1" if witness_policy == REVISION
                         else b"tdo-recursive-selector-replay-v2")
        universe_domain = (b"tdo-recursive-selector-universe-v1" if witness_policy == REVISION
                           else b"tdo-recursive-selector-universe-v2")
        replay_digest = _digest(replay_domain, identity,
                                max_identity_items, max_identity_bytes)
        universe = _digest(universe_domain,
                           (witness_policy, replay_digest, register_space, sp, candidates,
                            tuple(sorted(limits.items()))),
                           max_identity_items, max_identity_bytes)
    except _IdentityBudget:
        return result(SelectorDiscoveryStatus.BUDGET, recursive)
    except (_IdentityUnsupported, ValueError, TypeError) as error:
        return result(SelectorDiscoveryStatus.UNKNOWN, recursive, unresolved=(
            SelectorCandidateDebt(None, "identity", type(error).__name__),))
    if monotonic() >= deadline:
        return result(SelectorDiscoveryStatus.BUDGET, recursive, universe, replay_digest,
                      candidates)
    if not candidates:
        return result(SelectorDiscoveryStatus.NO_CANDIDATE, recursive, universe, replay_digest)
    certified, eliminated, unresolved = [], [], []
    certified_closures = {}
    unique_closure = None
    possible_saves = {frame: _may_save_entry_frame_base(
        by_scope[recursive], frame, register_space) for frame in frame_candidates}
    possible_rank_writes = {rank: _may_write_recursive_rank(
        by_scope[recursive], rank, register_space) for rank in rank_candidates}

    def budget():
        return monotonic() >= deadline or sum(counters[1:]) >= max_replays

    for candidate in candidates:
        if budget():
            return result(SelectorDiscoveryStatus.BUDGET, recursive, universe, replay_digest,
                          candidates, certified, eliminated, unresolved, unique_closure)
        counters[0] += 1
        # These are static necessary conditions of the constituent checker,
        # independent of its resource/unsupported outcomes. Frame ENTRY can
        # first enter a saved slot only through width-preserving COPY/CAST;
        # a strict smaller actual needs an overlapping raw recursive rank
        # write before the first self-call. Overapproximation keeps any
        # plausible candidate, including cross-instruction copy chains and
        # partial rank writes. It can create UNKNOWN, never false uniqueness.
        if not possible_saves[candidate.frame_base]:
            eliminated.append(SelectorCandidateDebt(candidate, "frame", "no_possible_entry_save"))
            continue
        if not possible_rank_writes[candidate.rank]:
            eliminated.append(SelectorCandidateDebt(candidate, "rank", "no_recursive_rank_write"))
            continue
        counters[1] += 1
        try:
            frame_step: InductiveFrameBaseCertificate = certify_inductive_frame_base(
                analyses, inventories, effects, verified_edges, recursive,
                candidate.frame_base, sp, shared_state_profile=SHARED_STATE_PROFILE,
                isolated_stack_profile=ISOLATED_STACK_PROFILE)
        except FrameBaseCertificateIncomplete as error:
            if error.reason is FrameBaseDebtReason.RESOURCE_BOUND:
                return result(SelectorDiscoveryStatus.BUDGET, recursive, universe, replay_digest,
                              candidates, certified, eliminated, unresolved)
            if error.reason is FrameBaseDebtReason.SAVE_RESTORE_GAP:
                eliminated.append(SelectorCandidateDebt(candidate, "frame", error.reason.value))
            else:
                unresolved.append(SelectorCandidateDebt(candidate, "frame", error.reason.value,
                                                        error.detail))
            continue
        if budget():
            return result(SelectorDiscoveryStatus.BUDGET, recursive, universe, replay_digest,
                          candidates, certified, eliminated, unresolved, unique_closure)
        counters[2] += 1
        try:
            rank_context = certify_root_rank_context(
                analyses, inventories, effects, verified_edges, frame_step,
                root_scope_digest, recursive, candidate.rank, candidate.frame_base, sp,
                shared_state_profile=SHARED_STATE_PROFILE,
                isolated_stack_profile=ISOLATED_STACK_PROFILE, max_rank=max_rank,
                max_steps=max_steps, max_paths=max_paths, max_queries=max_queries,
                solver_timeout_ms=solver_timeout_ms, max_contexts=max_contexts,
                solver_deadline=deadline)
        except RankContextIncomplete as error:
            if error.reason is RankContextDebtReason.RESOURCE_BOUND:
                return result(SelectorDiscoveryStatus.BUDGET, recursive, universe, replay_digest,
                              candidates, certified, eliminated, unresolved)
            if error.reason is RankContextDebtReason.GUARD_OR_ACTUAL:
                eliminated.append(SelectorCandidateDebt(candidate, "rank", error.reason.value))
            else:
                unresolved.append(SelectorCandidateDebt(candidate, "rank", error.reason.value,
                                                        error.detail))
            continue
        if budget():
            return result(SelectorDiscoveryStatus.BUDGET, recursive, universe, replay_digest,
                          candidates, certified, eliminated, unresolved, unique_closure)
        counters[3] += 1
        try:
            closure = close_recursive_preservation_induction(
                analyses, inventories, effects, verified_edges, frame_step,
                rank_context, candidate.rank, shared_state_profile=SHARED_STATE_PROFILE,
                isolated_stack_profile=ISOLATED_STACK_PROFILE, max_rank=max_rank,
                max_steps=max_steps, max_paths=max_paths, max_queries=max_queries,
                solver_timeout_ms=solver_timeout_ms, max_contexts=max_contexts,
                solver_total_ms=max(1, int((deadline - monotonic()) * 1000)))
        except InductionClosureIncomplete as error:
            if error.reason is InductionDebtReason.RESOURCE_BOUND:
                return result(SelectorDiscoveryStatus.BUDGET, recursive, universe, replay_digest,
                              candidates, certified, eliminated, unresolved)
            unresolved.append(SelectorCandidateDebt(candidate, "induction", error.reason.value,
                                                    error.detail))
            continue
        certified.append(candidate)
        certified_closures[candidate] = closure
        unique_closure = closure if len(certified) == 1 else None
    if monotonic() >= deadline:
        return result(SelectorDiscoveryStatus.BUDGET, recursive, universe, replay_digest,
                      candidates, certified, eliminated, unresolved)
    if witness_policy == CERTIFIED_WITNESS_V2 and certified:
        selected = min(certified, key=lambda item: _selector_key(item, register_space))
        selected_closure = certified_closures[selected]
        try:
            selected_identity = _witness_digest(
                witness_policy, replay_digest, universe, selected, selected_closure,
                max_identity_items, max_identity_bytes)
        except _IdentityBudget:
            return result(SelectorDiscoveryStatus.BUDGET, recursive, universe, replay_digest,
                          candidates, certified, eliminated, unresolved)
        except (_IdentityUnsupported, ValueError, TypeError) as error:
            unresolved.append(SelectorCandidateDebt(selected, "selected_identity",
                                                    type(error).__name__))
            return result(SelectorDiscoveryStatus.UNKNOWN, recursive, universe, replay_digest,
                          candidates, certified, eliminated, unresolved)
        if monotonic() >= deadline:
            return result(SelectorDiscoveryStatus.BUDGET, recursive, universe, replay_digest,
                          candidates, certified, eliminated, unresolved)
        return result(SelectorDiscoveryStatus.WITNESS_FOUND, recursive, universe,
                      replay_digest, candidates, certified, eliminated, unresolved,
                      selected_closure, selected, selected_identity)
    status = (SelectorDiscoveryStatus.AMBIGUOUS if len(certified) > 1 else
              SelectorDiscoveryStatus.UNKNOWN if unresolved else
              SelectorDiscoveryStatus.UNIQUE if certified else
              SelectorDiscoveryStatus.NO_CANDIDATE)
    return result(status, recursive, universe, replay_digest, candidates,
                  certified, eliminated, unresolved,
                  unique_closure if status is SelectorDiscoveryStatus.UNIQUE else None,
                  certified[0] if status is SelectorDiscoveryStatus.UNIQUE else None)


__all__ = ("REVISION", "CERTIFIED_WITNESS_V2", "SelectorDiscoveryStatus", "SelectorTuple", "SelectorCandidateDebt",
           "SelectorDiscoveryResult", "discover_recursive_selectors")
