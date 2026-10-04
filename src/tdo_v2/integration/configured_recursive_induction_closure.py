"""Unwired composition of conditional frame preservation and finite rank proofs.

This discharges child-return/preservation hypotheses by checked well-founded
induction. The two environmental/machine premises remain assumptions: the
existing records contain labels, not a validated production premise payload.
No origin, privacy, global nonescape or production-admission claim follows.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from time import monotonic

import z3

from ..call_seeds import _operation_key
from ..physical_state import PhysicalRegisterSlice
from ..scope_identity import VarnodeKindCode
from .configured_interprocedural_contracts import ConfiguredFunctionAnalysis
from .configured_recursive_all_effects import RecursiveAllEffectInventory
from .configured_recursive_call_edges import VerifiedDirectCallEdges
from .configured_recursive_frame_inventory import RecursiveFrameInventory
from .configured_recursive_frame_base_certificate import (
    FrameBaseCertificateIncomplete, InductiveFrameBaseCertificate,
    SHARED_STATE_PROFILE, ISOLATED_STACK_PROFILE, certify_inductive_frame_base,
)
from .configured_recursive_frame_separation import (
    RecursiveFrameSeparationIncomplete, check_symbolic_frame_separation,
)
from .configured_recursive_rank_context import (
    RootRankContextCertificate, RankContextIncomplete, _Interpreter, _fresh,
    certify_root_rank_context,
)


class InductionDebtReason(StrEnum):
    INVALID_INPUT = "invalid_input"
    EVIDENCE_MISMATCH = "evidence_mismatch"
    UNDISCHARGED_HYPOTHESIS = "undischarged_hypothesis"
    UNSUPPORTED_EFFECT = "unsupported_effect"
    ALIAS_OR_GEOMETRY = "alias_or_geometry"
    RESOURCE_BOUND = "resource_bound"
    SOLVER_UNKNOWN = "solver_unknown"


class InductionClosureIncomplete(RuntimeError):
    def __init__(self, reason: InductionDebtReason, detail: str):
        self.reason, self.detail = reason, detail
        super().__init__(f"{reason.value}: {detail}")


@dataclass(frozen=True, slots=True)
class InductionCase:
    function_scope_digest: bytes
    rank: int | None
    normal_path_count: int
    # Actual child ranks proved at every reached call, not caller assertions.
    child_ranks: tuple[tuple[str, tuple[int, ...]], ...]


@dataclass(frozen=True, slots=True)
class ConditionalInductionClosure:
    program_scope_digest: bytes
    root_scope_digest: bytes
    recursive_scope_digest: bytes
    # Exact replayed closure records, not a label-only or selected-function seal.
    inventories: tuple[RecursiveFrameInventory, ...]
    effects: tuple[RecursiveAllEffectInventory, ...]
    verified_edges: VerifiedDirectCallEdges
    frame_step: InductiveFrameBaseCertificate
    rank_context: RootRankContextCertificate
    rank_register: PhysicalRegisterSlice
    cases: tuple[InductionCase, ...]
    limits: tuple[tuple[str, int], ...]
    symbolic_steps: int
    solver_queries: int
    remaining_premises: tuple[str, ...]
    semantic_revision: str = "configured-recursive-induction-closure-v1"
    diagnostic_only: bool = True
    production_admission: bool = False
    proves_origins: bool = False
    proves_privacy: bool = False
    proves_global_nonescape: bool = False


def _debt(reason, detail):
    raise InductionClosureIncomplete(reason, detail)


def _require_stack_space(analysis, space_id):
    metadata = tuple(row for row in analysis.evidence.unit.scopes.program.evidence.address_spaces
                     if row.space_id == space_id)
    if (len(metadata) != 1 or not metadata[0].is_memory_space
            or metadata[0].address_size_bits != 64
            or metadata[0].addressable_unit_bytes != 1
            or metadata[0].is_overlay_space or metadata[0].is_external_space):
        _debt(InductionDebtReason.ALIAS_OR_GEOMETRY,
              "stack space lacks exact 64-bit byte-addressed RAM metadata")


class _InductionInterpreter(_Interpreter):
    """Use a child theorem only after it has been established bottom-up."""

    def __init__(self, *args, proved_helpers, proved_ranks, geometry, **kwargs):
        super().__init__(*args, **kwargs)
        self.proved_helpers = proved_helpers
        self.proved_ranks = proved_ranks
        self.geometry = geometry
        self.entry_fp = _fresh(64, "induction_entry_fp")
        self.child_ranks = {}

    def initial(self, *, recursive):
        state = super().initial(recursive=recursive)
        self._write_register(state, self.frame_base, self.entry_fp)
        return state

    def _call(self, state, instruction, ordinal, operation):
        key = _operation_key(instruction.address, ordinal, "CALL")
        edge, token = self.edges.get(key), self.tokens.get(key)
        shape = self.geometry.get((self.scope, key))
        if edge is None or token is None or shape is None:
            _debt(InductionDebtReason.EVIDENCE_MISMATCH, "missing replayed call geometry")
        # All caller ordinary storage is above this token. The child's own
        # [0,word) token is read-only; its writes and all descendant writes
        # are strictly below its ENTRY. Thus every retained caller byte is
        # untouched, including the shared call token. Never preserve a stale
        # byte below child ENTRY by treating activations as separate RAM.
        if any(offset < token.interval.offset for offset in state.frame):
            _debt(InductionDebtReason.ALIAS_OR_GEOMETRY,
                  "caller retained bytes enter a child's writable footprint")
        if edge.callee_scope_digest == self.recursive_scope:
            value = self._read_register(state, self.rank)
            candidates = tuple(sorted(self.proved_ranks))
            claim = z3.Or(*(value == z3.BitVecVal(n, value.size()) for n in candidates))
            self._prove(state, claim, "child rank has no already-proved return theorem")
            reached = tuple(n for n in candidates if self._sat(
                (*state.constraints, value == z3.BitVecVal(n, value.size()))))
            if not reached:
                _debt(InductionDebtReason.UNDISCHARGED_HYPOTHESIS, "empty child induction case")
            self.child_ranks.setdefault(key, set()).update(reached)
        elif edge.callee_scope_digest not in self.proved_helpers:
            _debt(InductionDebtReason.UNDISCHARGED_HYPOTHESIS,
                  "helper return/preservation theorem not established")
        super()._call(state, instruction, ordinal, operation)

    def checked_run(self, *, recursive, rank_value=None):
        paths = self.run(recursive=recursive,
                         rank_bounds=None if rank_value is None else (rank_value, rank_value))
        for path in paths:
            self._prove(path, self._read_register(path, self.frame_base) == self.entry_fp,
                        "normal return does not restore incoming frame-base bytes")
            # run() checked the exact incoming return token and SP+word on
            # every feasible exit. Its memory operations proved their raw
            # pointer equal to the inventory's entry-relative interval.
        return InductionCase(self.scope, rank_value, len(paths), tuple(
            (key, tuple(sorted(values))) for key, values in sorted(self.child_ranks.items())))


def close_recursive_preservation_induction(
    analyses: tuple[ConfiguredFunctionAnalysis, ...],
    inventories: tuple[RecursiveFrameInventory, ...],
    effects: tuple[RecursiveAllEffectInventory, ...],
    verified_edges: VerifiedDirectCallEdges,
    frame_step: InductiveFrameBaseCertificate,
    rank_context: RootRankContextCertificate,
    rank: PhysicalRegisterSlice,
    /, *, shared_state_profile: str, isolated_stack_profile: str,
    max_functions: int = 64, max_operations: int = 4096,
    max_varnode_bytes: int = 64, max_operand_bytes: int = 262144,
    max_rank: int = 32, max_steps: int = 100000, max_paths: int = 128,
    max_queries: int = 10000, solver_timeout_ms: int = 5000,
    max_contexts: int = 1024, solver_total_ms: int | None = None,
) -> ConditionalInductionClosure:
    """Close finite return/preservation induction, conditional on named premises.

Every helper is proved in call-DAG order; rank n uses only proved ranks < n.
The root is replayed last using these proved children. Neither constituent
flags nor supplied bounds are trusted: both constituents must replay equal.
"""
    limits_record = tuple(sorted({
        "max_functions": max_functions, "max_operations": max_operations,
        "max_varnode_bytes": max_varnode_bytes, "max_operand_bytes": max_operand_bytes,
        "max_rank": max_rank, "max_steps": max_steps, "max_paths": max_paths,
        "max_queries": max_queries, "solver_timeout_ms": solver_timeout_ms,
        "max_contexts": max_contexts,
        # Constituent frame replay has its own fixed internal step ceiling.
        "constituent_frame_max_steps": 16384,
        "constituent_frame_max_paths": 128,
        "constituent_inventory_max_steps": 16384,
        "constituent_effect_max_operations": 4096,
        "constituent_effect_max_direct_effects": 4096,
        "constituent_geometry_max_functions": 64,
        "constituent_geometry_max_accesses": 4096,
        "constituent_geometry_max_edges": 256,
    }.items()))
    if solver_total_ms is not None and (type(solver_total_ms) is not int or solver_total_ms < 1):
        _debt(InductionDebtReason.INVALID_INPUT, "invalid aggregate solver-time budget")
    if (type(analyses) is not tuple or not analyses
            or any(type(row) is not ConfiguredFunctionAnalysis for row in analyses)
            or type(inventories) is not tuple
            or any(type(row) is not RecursiveFrameInventory for row in inventories)
            or type(effects) is not tuple
            or any(type(row) is not RecursiveAllEffectInventory for row in effects)
            or type(verified_edges) is not VerifiedDirectCallEdges
            or type(frame_step) is not InductiveFrameBaseCertificate
            or type(rank_context) is not RootRankContextCertificate
            or type(rank) is not PhysicalRegisterSlice
            or any(type(value) is not int or value < 1 for _, value in limits_record)):
        _debt(InductionDebtReason.INVALID_INPUT, "invalid induction envelope")
    deadline = None if solver_total_ms is None else monotonic() + solver_total_ms / 1000

    def check_deadline():
        if deadline is not None and monotonic() >= deadline:
            _debt(InductionDebtReason.RESOURCE_BOUND, "aggregate induction replay time budget")
    if (shared_state_profile != SHARED_STATE_PROFILE
            or isolated_stack_profile != ISOLATED_STACK_PROFILE):
        _debt(InductionDebtReason.INVALID_INPUT, "exact named conditional premises required")
    if any(type(value) is not bytes or len(value) != 32 for value in (
            rank_context.root_scope_digest, rank_context.recursive_scope_digest,
            rank_context.program_scope_digest, frame_step.program_scope_digest,
            frame_step.recursive_scope_digest, verified_edges.program_scope_digest)):
        _debt(InductionDebtReason.INVALID_INPUT, "malformed scope identity")
    if len(analyses) > max_functions or len(inventories) > max_functions or len(effects) > max_functions:
        _debt(InductionDebtReason.RESOURCE_BOUND, "function preflight budget")
    operations, operand_bytes = 0, 0
    for analysis in analyses:
        observation = analysis.evidence.unit.observation
        if observation is None or len(observation.instructions) > max_operations:
            _debt(InductionDebtReason.RESOURCE_BOUND, "instruction preflight budget")
        for instruction in observation.instructions:
            operations += len(instruction.operations)
            if operations > max_operations:
                _debt(InductionDebtReason.RESOURCE_BOUND, "operation preflight budget")
            for operation in instruction.operations:
                if operation.opcode in {"LOAD", "STORE"}:
                    if not operation.inputs or operation.inputs[0].kind is not VarnodeKindCode.CONSTANT:
                        _debt(InductionDebtReason.ALIAS_OR_GEOMETRY, "unknown raw memory selector")
                    _require_stack_space(analysis, operation.inputs[0].coordinate.byte_offset)
                for node in (*operation.inputs, *((operation.output,) if operation.output else ())):
                    operand_bytes += node.byte_size
                    if node.byte_size > max_varnode_bytes or operand_bytes > max_operand_bytes:
                        _debt(InductionDebtReason.RESOURCE_BOUND, "varnode/operand-byte preflight budget")
    by_scope = {row.evidence.unit.scopes.function.scope.digest: row for row in analyses}
    frames = {row.function_scope_digest: row for row in inventories}
    ledgers = {row.function_scope_digest: row for row in effects}
    root, recursive = rank_context.root_scope_digest, rank_context.recursive_scope_digest
    if (len(by_scope) != len(analyses) or len(frames) != len(inventories)
            or len(ledgers) != len(effects) or set(by_scope) != set(frames)
            or set(by_scope) != set(ledgers) or root == recursive
            or root not in by_scope or recursive not in by_scope
            or frame_step.recursive_scope_digest != recursive):
        _debt(InductionDebtReason.EVIDENCE_MISMATCH, "incomplete or mismatched closure")
    frame_base, stack_pointer = frame_step.frame_base, frame_step.stack_pointer
    try:
        check_deadline()
        replay_step = certify_inductive_frame_base(
            analyses, inventories, effects, verified_edges, recursive, frame_base, stack_pointer,
            shared_state_profile=shared_state_profile, isolated_stack_profile=isolated_stack_profile)
        if replay_step != frame_step:
            _debt(InductionDebtReason.EVIDENCE_MISMATCH, "frame-step replay differs")
        check_deadline()
        replay_rank = certify_root_rank_context(
            analyses, inventories, effects, verified_edges, frame_step, root, recursive,
            rank, frame_base, stack_pointer, shared_state_profile=shared_state_profile,
            isolated_stack_profile=isolated_stack_profile, max_rank=max_rank,
            max_steps=max_steps, max_paths=max_paths, max_queries=max_queries,
            solver_timeout_ms=solver_timeout_ms, max_contexts=max_contexts,
            solver_deadline=deadline)
        check_deadline()
        if replay_rank != rank_context:
            _debt(InductionDebtReason.EVIDENCE_MISMATCH, "rank-context replay differs")
        geometry = check_symbolic_frame_separation(inventories, verified_edges.edges)
        geometry_map = {(row.caller_scope_digest, row.call_operation_key): row
                        for row in geometry.calls}
        # Full frame geometry is one common 64-bit byte-addressed space.
        spaces = {row.interval.address_space_id for inventory in inventories
                  for row in inventory.accesses if row.interval is not None}
        if len(spaces) != 1 or not 0 < rank_context.modular_window[1] - rank_context.modular_window[0] < 1 << 64:
            _debt(InductionDebtReason.ALIAS_OR_GEOMETRY, "missing modular injectivity")
        memory_space = next(iter(spaces))
        for analysis in analyses:
            _require_stack_space(analysis, memory_space)
        # Close the direct subtree before proving any helper. Extra disconnected
        # evidence cannot silently become an assumed helper theorem.
        successors = {scope: set() for scope in by_scope}
        for edge in verified_edges.edges:
            if edge.caller_scope_digest not in successors or edge.callee_scope_digest not in successors:
                _debt(InductionDebtReason.EVIDENCE_MISMATCH, "edge outside admitted closure")
            successors[edge.caller_scope_digest].add(edge.callee_scope_digest)
        reached, pending = set(), [root]
        while pending:
            scope = pending.pop()
            if scope not in reached:
                reached.add(scope)
                pending.extend(successors[scope] - reached)
        if reached != set(by_scope):
            _debt(InductionDebtReason.EVIDENCE_MISMATCH, "disconnected closure member")
        limits = {"steps": 0, "queries": 0, "max_steps": max_steps,
                  "max_paths": max_paths, "max_queries": max_queries,
                  "timeout_ms": solver_timeout_ms,
                  "solver_deadline": deadline}
        proved_helpers, proved_ranks, cases = set(), set(), []

        def interpreter(scope):
            return _InductionInterpreter(
                by_scope[scope], frames[scope], verified_edges.edges, root, recursive,
                rank, frame_base, stack_pointer, limits,
                proved_helpers=proved_helpers, proved_ranks=proved_ranks, geometry=geometry_map)

        remaining = set(by_scope) - {root, recursive}
        while remaining:
            ready = sorted(scope for scope in remaining if successors[scope] <= proved_helpers)
            if not ready:
                _debt(InductionDebtReason.UNDISCHARGED_HYPOTHESIS, "helper graph has an unproved cycle")
            for scope in ready:
                cases.append(interpreter(scope).checked_run(recursive=False))
                proved_helpers.add(scope)
                remaining.remove(scope)
        for n in range(max(rank_context.root_ranks) + 1):
            cases.append(interpreter(recursive).checked_run(recursive=True, rank_value=n))
            proved_ranks.add(n)
        cases.append(interpreter(root).checked_run(recursive=False))
        check_deadline()
    except (FrameBaseCertificateIncomplete, RankContextIncomplete,
            RecursiveFrameSeparationIncomplete) as error:
        reason = {"resource_bound": InductionDebtReason.RESOURCE_BOUND,
                  "solver_unknown": InductionDebtReason.SOLVER_UNKNOWN}.get(
                      error.reason.value, InductionDebtReason.UNDISCHARGED_HYPOTHESIS)
        _debt(reason, f"constituent/induction check: {error}")
    return ConditionalInductionClosure(
        verified_edges.program_scope_digest, root, recursive,
        tuple(frames[scope] for scope in sorted(frames)),
        tuple(ledgers[scope] for scope in sorted(ledgers)), verified_edges,
        frame_step, rank_context, rank, tuple(cases), limits_record,
        limits["steps"], limits["queries"], (shared_state_profile, isolated_stack_profile))


__all__ = ("InductionDebtReason", "InductionClosureIncomplete", "InductionCase",
           "ConditionalInductionClosure", "close_recursive_preservation_induction")
