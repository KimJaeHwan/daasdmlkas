"""Dormant, bounded raw-CFG expansion for one ADR-0040 prepared request.

This module produces only an internal physical-state graph. It does not answer
an origin query, lower legacy events, or authorize public completion.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from time import monotonic

import z3

from .._scope_contracts import AddressCoordinate, VarnodeKindCode
from ..call_seeds import _operation_key
from .configured_finite_byte_kernel import (
    ByteDefinition, FiniteByteKernel, KernelIncomplete, KernelLimits, MemoryEvent,
    RootTokenSeed, _ForkList,
)


SCHEDULER_REVISION = "configured-finite-context-scheduler-v1"
SYMBOLIC_SCHEDULER_REVISION = "configured-finite-context-scheduler-path-local-stack-v2"
from .configured_finite_context_inputs import (
    ConfiguredFiniteContextRequest, replay_configured_finite_context_request,
)


class SchedulerDebtReason(StrEnum):
    INVALID_REQUEST = "invalid_request"
    EVIDENCE_MISMATCH = "evidence_mismatch"
    UNSUPPORTED_CFG = "unsupported_cfg"
    CONTROL_MISMATCH = "control_mismatch"
    MISSING_NORMAL_EXIT = "missing_normal_exit"
    SOLVER_UNKNOWN = "solver_unknown"
    RESOURCE_BOUND = "resource_bound"
    KERNEL_STOP = "kernel_stop"


class FiniteSchedulerIncomplete(RuntimeError):
    def __init__(self, reason: SchedulerDebtReason, detail: str):
        self.reason, self.detail = reason, detail
        super().__init__(f"{reason.value}: {detail}")


def _stop(reason, detail):
    raise FiniteSchedulerIncomplete(reason, detail)


def _validate_control_output(operation):
    if (operation.opcode in {"CALL", "RETURN", "BRANCH", "CBRANCH"}
            and operation.output is not None):
        _stop(SchedulerDebtReason.EVIDENCE_MISMATCH,
              "observed control operation unexpectedly writes an output")


class _InfeasiblePath(Exception):
    """A fully checked path violates the admitted conditional premise."""


@dataclass(frozen=True, slots=True)
class OperationOccurrence:
    function_scope_digest: bytes
    instruction: AddressCoordinate
    operation_ordinal: int
    operation_key: str
    activation: tuple[int, ...]
    alternative_prefix: tuple[int, ...]
    definition_ids: tuple[int, ...]
    event_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class FinitePathExit:
    alternative: tuple[int, ...]
    operations: tuple[OperationOccurrence, ...]
    definitions: tuple[ByteDefinition, ...]
    events: tuple[MemoryEvent, ...]
    latest: tuple[tuple[tuple[str, int, int, tuple[int, ...]], int], ...]
    constraints: tuple[z3.BoolRef, ...]


@dataclass(frozen=True, slots=True)
class FiniteExpansion:
    scheduler_revision: str
    kernel_revision: str
    request_digest: bytes
    root_scope_digest: bytes
    root_token_seed: RootTokenSeed
    exits: tuple[FinitePathExit, ...]
    contexts: int
    solver_queries: int


@dataclass(frozen=True, slots=True)
class _Frame:
    scope: bytes
    occurrence: tuple[int, ...]
    entry_sp: z3.BitVecRef
    entry_offset: int
    expected_token: z3.BitVecRef
    continuation: AddressCoordinate | None
    caller_entry_offset: int | None
    caller_token_before: int | None
    entry_rank: z3.BitVecRef | None


@dataclass(frozen=True, slots=True)
class _Visit:
    marker: tuple[tuple[int, ...], AddressCoordinate]
    previous: _Visit | None


@dataclass(slots=True)
class _Path:
    kernel: FiniteByteKernel
    frames: tuple[_Frame, ...]
    pc: AddressCoordinate
    visited: _Visit | None
    constraints: tuple[z3.BoolRef, ...]
    alternative: tuple[int, ...]
    operations: _ForkList
    certified_contexts: int
    stack_intervals: frozenset[tuple[int, int]] = frozenset()


class _Scheduler:
    def __init__(self, request, kernel_limits):
        if type(request) is not ConfiguredFiniteContextRequest:
            _stop(SchedulerDebtReason.INVALID_REQUEST, "exact prepared request required")
        try:
            replay = replay_configured_finite_context_request(request)
        except Exception as error:
            _stop(SchedulerDebtReason.INVALID_REQUEST, f"request replay failed: {error}")
        if replay.input_digest != request.input_digest:
            _stop(SchedulerDebtReason.INVALID_REQUEST, "request digest changed")
        if any(row.evidence.unit.scopes.program.evidence.translation_namespace.language_id
               != "x86:LE:64:default" for row in request.analyses):
            _stop(SchedulerDebtReason.EVIDENCE_MISMATCH,
                  "finite byte compiler admits only observed x86 little-endian 64-bit language")
        self.request = request
        self.by_scope = {row.evidence.unit.scopes.function.scope.digest: row for row in request.analyses}
        self.instructions = {scope: {row.address: row for row in
            analysis.evidence.unit.observation.instructions}
            for scope, analysis in self.by_scope.items()}
        for analysis in request.analyses:
            scope = analysis.evidence.unit.scopes.function.scope.digest
            raw = self.instructions[scope]
            cfg = analysis.normalized.cfg
            if cfg.node_count != len(raw):
                _stop(SchedulerDebtReason.EVIDENCE_MISMATCH, "raw/normalized CFG node count")
            for instruction in raw.values():
                label = f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}"
                node = cfg.node_for_key(f"instruction:{label}")
                if node is None or cfg.node(node).label != label:
                    _stop(SchedulerDebtReason.EVIDENCE_MISMATCH, "raw instruction lacks normalized CFG node")
                observed = set()
                if instruction.fallthrough is not None:
                    observed.add(instruction.fallthrough)
                if not instruction.flow.is_call:
                    observed.update(instruction.flow_targets)
                else:
                    observed.update(target for target in instruction.flow_targets
                                    if target in raw and target != analysis.entry)
                expected = {target for target in observed if target in raw}
                actual = {cfg.node(successor).label for successor in cfg.successors(node)}
                if actual != {f"{target.space_id:x}:{target.byte_offset:x}" for target in expected}:
                    _stop(SchedulerDebtReason.EVIDENCE_MISMATCH, "raw/normalized CFG successor mismatch")
        self.edges = {(row.caller_scope_digest, row.call_operation_key): row
                      for row in request.induction.verified_edges.edges}
        self.tokens = {(row.function_scope_digest, token.call_operation_key): token
            for row in request.induction.inventories for token in row.call_tokens}
        self.returns = {(row.function_scope_digest, token.return_operation_key): token
            for row in request.induction.inventories for token in row.return_tokens}
        if (len(self.edges) != len(request.induction.verified_edges.edges)
                or len(self.tokens) != sum(len(row.call_tokens) for row in request.induction.inventories)
                or len(self.returns) != sum(len(row.return_tokens) for row in request.induction.inventories)):
            _stop(SchedulerDebtReason.EVIDENCE_MISMATCH, "duplicate call or return evidence")
        self.queries = 0
        self.solver_ms = 0.0
        self.contexts = 1
        self.paths = 1
        self.copy_bytes = 0
        self.query_scratch_bytes = 0
        self.expression_nodes = 0
        self.steps = 0
        self.instruction_steps = 0
        self.visit_bytes = 0
        self.reserved_nodes = 0
        self.reserved_edges = 0
        self.reserved_events = 0
        self.reserved_bytes = 0
        self.serial = 0
        self.isolation_pairs = 0
        self.kernel_limits = kernel_limits

    def _sat(self, constraints):
        self.queries += 1
        if self.queries > self.request.limits.solver_queries:
            _stop(SchedulerDebtReason.RESOURCE_BOUND, "aggregate solver-query budget")
        total_ms = (self.request.limits.scheduler_solver_total_ms
                    if self.request.symbolic_entry is not None
                    else self.request.limits.solver_timeout_ms)
        remaining_ms = total_ms - self.solver_ms
        if remaining_ms <= 0:
            _stop(SchedulerDebtReason.RESOURCE_BOUND, "aggregate solver-time budget")
        solver = z3.Solver()
        query_ms = (min(remaining_ms, self.request.limits.solver_timeout_ms)
                    if self.request.symbolic_entry is not None else remaining_ms)
        solver.set(timeout=max(1, int(query_ms)))
        solver.add(*constraints)
        started = monotonic()
        result = solver.check()
        self.solver_ms += (monotonic() - started) * 1000
        if self.solver_ms > total_ms:
            _stop(SchedulerDebtReason.RESOURCE_BOUND, "aggregate solver-time budget")
        if result == z3.unknown:
            _stop(SchedulerDebtReason.SOLVER_UNKNOWN, solver.reason_unknown())
        return result == z3.sat

    def _sat_extended(self, path, clause):
        # Tuple materialization for a query is ephemeral, but its maximum
        # live scratch must fit alongside the retained symbolic state.
        scratch = 8 * (len(path.constraints) + 1)
        if (self._state_accounted_bytes()
                + max(self.query_scratch_bytes, scratch)
                > self.request.limits.symbolic_state_bytes):
            _stop(SchedulerDebtReason.RESOURCE_BOUND, "solver-query scratch budget")
        self.query_scratch_bytes = max(self.query_scratch_bytes, scratch)
        return self._sat((*path.constraints, clause))

    def _equal(self, path, left, right, detail):
        self._expression(4)
        if left.size() != right.size() or self._sat_extended(path, left != right):
            _stop(SchedulerDebtReason.CONTROL_MISMATCH, detail)

    def _state_accounted_bytes(self):
        # V1's historical combined counter is preserved under its unchanged
        # revision. Only the V2 request with v3 limits separates work nodes.
        return (self.copy_bytes + self.visit_bytes
                + (0 if hasattr(self.request.limits, "expression_work_nodes")
                   else self.expression_nodes))

    def _expression(self, nodes):
        limit = getattr(self.request.limits, "expression_work_nodes",
                        self.request.limits.symbolic_state_bytes)
        if (self.expression_nodes + nodes > limit
                or (not hasattr(self.request.limits, "expression_work_nodes")
                    and self._state_accounted_bytes() + self.query_scratch_bytes + nodes
                    > self.request.limits.symbolic_state_bytes)):
            _stop(SchedulerDebtReason.RESOURCE_BOUND, "aggregate scheduler expression budget")
        self.expression_nodes += nodes

    def _join(self, rows):
        values = tuple(value for _, value in rows)
        self._expression(max(0, len(values) - 1))
        return z3.Concat(*reversed(values)) if len(values) > 1 else values[0]

    def _read(self, path, var):
        nodes = var.byte_size
        events = int(var.kind is VarnodeKindCode.ADDRESS)
        encoded = 256 * nodes + 128 * events
        limits = self.request.limits
        if (self.reserved_nodes + nodes > limits.graph_nodes
                or self.reserved_events + events > limits.memory_events
                or self.reserved_bytes + encoded > limits.cache_bytes):
            _stop(SchedulerDebtReason.RESOURCE_BOUND, "aggregate control-read budget")
        self.reserved_nodes += nodes
        self.reserved_events += events
        self.reserved_bytes += encoded
        # A control inspection can lazily create entry symbols or constants.
        self._expression(nodes)
        return self._join(path.kernel.read_bytes(var, occurrence=path.frames[-1].occurrence))

    def _stack(self, path, offset):
        keys = [("ram_sp", self.request.shared_state.binding.address_space_id, offset + i, ())
                for i in range(8)]
        if any(key not in path.kernel.cells for key in keys):
            _stop(SchedulerDebtReason.CONTROL_MISMATCH, "missing observed call/return token byte")
        return self._join(tuple((path.kernel.cells[key].node, path.kernel.cells[key].value)
                                for key in keys))

    def _fork(self, path):
        reserve = (path.kernel.fork_cost() + 8 * path.operations.pending_fork_refs + 256
                   + 8 * (len(path.constraints) + 1)
                   + 8 * (len(path.alternative) + 1) + 64)
        if (self._state_accounted_bytes()
                + self.query_scratch_bytes + reserve
                > self.request.limits.symbolic_state_bytes):
            _stop(SchedulerDebtReason.RESOURCE_BOUND,
                  f"aggregate state-copy budget: used={self.copy_bytes} next={reserve} "
                  f"limit={self.request.limits.symbolic_state_bytes} "
                  f"cells={len(path.kernel.cells)} defs={len(path.kernel.definitions)} "
                  f"events={len(path.kernel.events)} paths={self.paths}")
        self.copy_bytes += reserve
        path.operations, copied_operations = path.operations.fork_pair()
        return _Path(path.kernel.fork(), path.frames, path.pc, path.visited,
                     path.constraints, path.alternative, copied_operations,
                     path.certified_contexts, path.stack_intervals)

    def _admit_stack_interval(self, path, offset, size, admitted_absolute):
        """Constrain one actually accessed modular root-SP interval on this path."""
        interval = (offset, size)
        if interval in path.stack_intervals:
            return
        low, high = self.request.isolated_stack.stack_relative_window
        modulus = 1 << self.request.shared_state.binding.address_size_bits
        if size <= 0 or offset < low or offset + size > high:
            _stop(SchedulerDebtReason.EVIDENCE_MISMATCH,
                  "actual stack interval outside certified rank window")
        pairs = len(admitted_absolute)
        reserve = 8 * (len(path.constraints) + 1) + 16 * (len(path.stack_intervals) + 1)
        if (pairs > self.request.limits.graph_edges - self.isolation_pairs
                or 8 * pairs + reserve > self.request.limits.symbolic_state_bytes
                - self._state_accounted_bytes()
                - self.query_scratch_bytes):
            _stop(SchedulerDebtReason.RESOURCE_BOUND, "path-local interval/range preflight")
        self.isolation_pairs += pairs
        clauses = []
        root_sp = path.frames[0].entry_sp
        for row in admitted_absolute:
            if size + row.size - 1 >= modulus:
                raise _InfeasiblePath
            first = (row.start - (offset + size - 1)) % modulus
            last = (row.start + row.size - 1 - offset) % modulus
            self._expression(6)
            start, end = z3.BitVecVal(first, 64), z3.BitVecVal(last, 64)
            clauses.append((z3.Or(z3.ULT(root_sp, start), z3.UGT(root_sp, end))
                            if first <= last else
                            z3.And(z3.UGT(root_sp, end), z3.ULT(root_sp, start))))
        clause = z3.And(*clauses)
        self._expression(max(1, len(clauses)))
        if not self._sat_extended(path, clause):
            raise _InfeasiblePath
        # Extending both immutable path collections copies their references.
        if (self._state_accounted_bytes()
                + self.query_scratch_bytes + reserve
                > self.request.limits.symbolic_state_bytes):
            _stop(SchedulerDebtReason.RESOURCE_BOUND, "path-local constraint tuple budget")
        self.copy_bytes += reserve
        path.constraints = (*path.constraints, clause)
        path.stack_intervals = path.stack_intervals | {interval}

    def _visit(self, path, marker):
        self.instruction_steps += 1
        if self.instruction_steps > self.request.limits.instructions * self.request.limits.contexts:
            _stop(SchedulerDebtReason.RESOURCE_BOUND, "aggregate instruction-step budget")
        current = path.visited
        while current is not None:
            if current.marker == marker:
                _stop(SchedulerDebtReason.UNSUPPORTED_CFG, "observed CFG cycle")
            current = current.previous
        reserve = 80 + 8 * len(marker[0])
        if (self._state_accounted_bytes()
                + self.query_scratch_bytes + reserve
                > self.request.limits.symbolic_state_bytes):
            _stop(SchedulerDebtReason.RESOURCE_BOUND,
                  f"aggregate visited-state budget: copies={self.copy_bytes} "
                  f"visited={self.visit_bytes} "
                  f"scratch={self.query_scratch_bytes} next={reserve} "
                  f"limit={self.request.limits.symbolic_state_bytes}")
        self.visit_bytes += reserve
        path.visited = _Visit(marker, path.visited)

    def _record(self, path, frame, instruction, ordinal, opcode, before_nodes, before_events):
        if self.reserved_bytes + 192 > self.request.limits.cache_bytes:
            _stop(SchedulerDebtReason.RESOURCE_BOUND, "aggregate operation-ledger encoding budget")
        self.reserved_bytes += 192
        path.operations.append(OperationOccurrence(
            frame.scope, instruction.address, ordinal,
            _operation_key(instruction.address, ordinal, opcode), frame.occurrence,
            path.alternative, tuple(range(before_nodes, len(path.kernel.definitions))),
            tuple(range(before_events, len(path.kernel.events)))))

    def _step(self):
        self.steps += 1
        if self.steps > self.request.limits.operations * self.request.limits.contexts:
            _stop(SchedulerDebtReason.RESOURCE_BOUND, "aggregate execution budget")

    def _reserve_transfer(self, operation):
        # Conservative aggregate reservation before the kernel creates Z3
        # expressions, definition nodes, memory events, or graph encodings.
        input_width = sum(row.byte_size for row in operation.inputs)
        output_width = 0 if operation.output is None else operation.output.byte_size
        nodes = input_width + output_width + (operation.inputs[2].byte_size
            if operation.opcode == "STORE" and len(operation.inputs) == 3 else 0)
        if operation.opcode == "LOAD":
            # A policy-admitted but unread entry-RAM interval can create one
            # symbolic source definition per loaded byte before the output.
            nodes += output_width
        # A materialized output byte can depend on operand bytes, but merely
        # reading operands never creates graph edges. LOAD/STORE additionally
        # attach the observed pointer-byte address channel to each data byte.
        if operation.opcode == "LOAD" and len(operation.inputs) == 2:
            edges = output_width * (operation.inputs[1].byte_size + 1)
        elif operation.opcode == "STORE" and len(operation.inputs) == 3:
            edges = operation.inputs[2].byte_size * (operation.inputs[1].byte_size + 1)
        else:
            edges = output_width * sum(row.byte_size for row in operation.inputs
                                       if row.kind is not VarnodeKindCode.CONSTANT)
        events = (sum(row.kind is VarnodeKindCode.ADDRESS for row in operation.inputs)
                  + int(operation.opcode in {"LOAD", "STORE"})
                  + int(operation.output is not None
                        and operation.output.kind is VarnodeKindCode.ADDRESS))
        encoded = 256 * nodes + 96 * edges + 128 * events
        limits = self.request.limits
        if (self.reserved_nodes + nodes > limits.graph_nodes
                or self.reserved_edges + edges > limits.graph_edges
                or self.reserved_events + events > limits.memory_events
                or self.reserved_bytes + encoded > limits.cache_bytes):
            _stop(SchedulerDebtReason.RESOURCE_BOUND,
                  f"aggregate graph/event/encoding budget: "
                  f"nodes={self.reserved_nodes}+{nodes}/{limits.graph_nodes} "
                  f"edges={self.reserved_edges}+{edges}/{limits.graph_edges} "
                  f"events={self.reserved_events}+{events}/{limits.memory_events} "
                  f"bytes={self.reserved_bytes}+{encoded}/{limits.cache_bytes} "
                  f"opcode={operation.opcode} contexts={self.contexts} paths={self.paths}")
        self.reserved_nodes += nodes
        self.reserved_edges += edges
        self.reserved_events += events
        self.reserved_bytes += encoded
        # Conservative upper bound of the kernel's expression pre-reserve,
        # lazy entry bytes and materialized output/store definitions. A
        # post-transfer assertion below catches future opcode drift.
        arithmetic = {"INT_ADD", "INT_SUB", "INT_AND", "INT_OR", "INT_XOR",
                      "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS",
                      "INT_CARRY", "INT_SCARRY", "INT_SBORROW", "BOOL_NEGATE",
                      "BOOL_AND", "BOOL_OR", "BOOL_XOR", "INT_2COMP", "INT_NEGATE",
                      "POPCOUNT", "LZCOUNT", "INT_ZEXT", "INT_SEXT"}
        constants = sum(row.byte_size for row in operation.inputs
                        if row.kind is VarnodeKindCode.CONSTANT)
        if operation.opcode in arithmetic:
            joins = sum(max(0, row.byte_size - 1) for row in operation.inputs)
            core = (6 * 8 * operation.inputs[0].byte_size + 8
                    if operation.opcode in {"POPCOUNT", "LZCOUNT"} else 20)
            splits = output_width
        else:
            joins = core = splits = 0
        self._expression(constants + joins + core + splits + input_width
                         + output_width + (output_width if operation.opcode == "LOAD" else 0)
                         + (operation.inputs[2].byte_size
                            if operation.opcode == "STORE" and len(operation.inputs) == 3 else 0))

    def run(self):
        request = self.request
        root_scope = request.induction.root_scope_digest
        root_returns = tuple(token for (scope, _), token in self.returns.items() if scope == root_scope)
        if (not root_returns or any(token.interval.address_space_id != request.shared_state.binding.address_space_id
                or token.interval.offset != 0 or token.interval.byte_size != 8 or token.after_offset != 8
                for token in root_returns)):
            _stop(SchedulerDebtReason.EVIDENCE_MISMATCH, "root return observations disagree on [entry SP,+8) token")
        admitted_absolute = tuple(sorted(set(request.isolated_stack.loaded_image_ranges
                                             + request.isolated_stack.absolute_effect_ranges)))
        entry_ram = (() if request.symbolic_entry is None
                     else request.symbolic_entry.ranges)
        kernel = FiniteByteKernel(request, root_sp=request.induction.frame_step.stack_pointer,
                                  absolute_ranges=admitted_absolute,
                                  entry_ram_ranges=entry_ram,
                                  limits=self.kernel_limits)
        token_cells = kernel.seed_root_return_token(offset=0,
            space_id=request.shared_state.binding.address_space_id)
        self.expression_nodes = kernel.expression_nodes
        self.reserved_nodes = len(kernel.definitions)
        self.reserved_bytes = 256 * len(kernel.definitions)
        token = self._join(tuple((cell.node, cell.value) for cell in token_cells))
        sp = request.induction.frame_step.stack_pointer
        from .._scope_contracts import ValidatedVarnode
        sp_var = ValidatedVarnode(VarnodeKindCode.REGISTER,
            AddressCoordinate(kernel.register_space, sp.byte_offset), sp.byte_size)
        root = self.by_scope[root_scope]
        frame = _Frame(root_scope, (0,), self._join(kernel.read_bytes(sp_var, occurrence=(0,))),
                       0, token, None, None, None, None)
        rank = request.induction.rank_register
        rank_var = ValidatedVarnode(VarnodeKindCode.REGISTER,
            AddressCoordinate(kernel.register_space, rank.byte_offset), rank.byte_size)
        rank_context = request.induction.rank_context
        decrement_by_key = {row.call_operation_key: row.decrement
                            for row in rank_context.recursive_actuals}
        if request.symbolic_entry is None:
            # Preserve the historical v1 diagnostic's whole-window premise.
            low, high = request.isolated_stack.stack_relative_window
            modulus = 1 << request.shared_state.binding.address_size_bits
            separation = []
            for row in admitted_absolute:
                forbidden_size = (high - low) + row.size - 1
                if forbidden_size >= modulus:
                    _stop(SchedulerDebtReason.CONTROL_MISMATCH,
                          "no root SP can satisfy isolated-stack premise")
                first = (row.start - (high - 1)) % modulus
                last = (row.start + row.size - 1 - low) % modulus
                self._expression(6)
                start = z3.BitVecVal(first, 64)
                end = z3.BitVecVal(last, 64)
                if first <= last:
                    separation.append(z3.Or(z3.ULT(frame.entry_sp, start),
                                            z3.UGT(frame.entry_sp, end)))
                else:
                    separation.append(z3.And(z3.UGT(frame.entry_sp, end),
                                             z3.ULT(frame.entry_sp, start)))
            root_constraint_bytes = 8 * len(separation)
            if (self._state_accounted_bytes()
                    + self.query_scratch_bytes + root_constraint_bytes
                    > request.limits.symbolic_state_bytes):
                _stop(SchedulerDebtReason.RESOURCE_BOUND, "root premise tuple budget")
            self.copy_bytes += root_constraint_bytes
            separation = tuple(separation)
            if not self._sat(separation):
                _stop(SchedulerDebtReason.CONTROL_MISMATCH,
                      "isolated-stack premise has no feasible root SP")
        else:
            if request.initial_constraints or kernel.root_sp_value is not None:
                _stop(SchedulerDebtReason.EVIDENCE_MISMATCH,
                      "v2 requires an unconstrained symbolic root SP")
            separation = ()
        initial = _Path(kernel, (frame,), root.entry, None,
                        separation, (), _ForkList(), 1)
        if request.symbolic_entry is not None:
            try:
                self._admit_stack_interval(initial, 0, 8, admitted_absolute)
            except _InfeasiblePath:
                _stop(SchedulerDebtReason.CONTROL_MISMATCH,
                      "no root SP satisfies the actual root token interval")
        pending = [initial]
        exits = []
        while pending:
            path = pending.pop()
            frame = path.frames[-1]
            marker = (frame.occurrence, path.pc)
            instruction = self.instructions[frame.scope].get(path.pc)
            if instruction is None:
                _stop(SchedulerDebtReason.UNSUPPORTED_CFG, "missing instruction")
            self._visit(path, marker)
            next_pc = None
            for ordinal, operation in enumerate(instruction.operations):
                self._step()
                opcode = operation.opcode
                _validate_control_output(operation)
                key = _operation_key(instruction.address, ordinal, opcode)
                terminal = ordinal == len(instruction.operations) - 1
                before_nodes, before_events = len(path.kernel.definitions), len(path.kernel.events)
                if opcode == "CALL":
                    self._expression(64)
                    edge = self.edges.get((frame.scope, key))
                    observed = self.tokens.get((frame.scope, key))
                    if (not terminal or edge is None or observed is None or not instruction.flow.is_call
                            or instruction.fallthrough is None or observed.continuation != instruction.fallthrough
                            or len(operation.inputs) != 1 or operation.inputs[0].kind is not VarnodeKindCode.ADDRESS
                            or edge.callee_scope_digest not in self.by_scope
                            or operation.inputs[0].coordinate != self.by_scope[edge.callee_scope_digest].entry
                            or observed.interval.byte_size != 8):
                        _stop(SchedulerDebtReason.EVIDENCE_MISMATCH, "CALL edge, token, target or continuation")
                    child_offset = frame.entry_offset + observed.interval.offset
                    if request.symbolic_entry is not None:
                        try:
                            self._admit_stack_interval(path, child_offset, 8, admitted_absolute)
                        except _InfeasiblePath:
                            next_pc = False
                            break
                    self._equal(path, self._read(path, sp_var), frame.entry_sp + observed.interval.offset,
                                "CALL SP differs from observed token interval")
                    self._equal(path, self._stack(path, child_offset),
                                z3.BitVecVal(instruction.fallthrough.byte_offset, 64),
                                "CALL token differs from continuation")
                    child_rank = None
                    if edge.callee_scope_digest == rank_context.recursive_scope_digest:
                        child_rank = self._read(path, rank_var)
                        if frame.scope == root_scope:
                            allowed = z3.Or(*(child_rank == z3.BitVecVal(value, child_rank.size())
                                              for value in rank_context.root_ranks))
                            if self._sat_extended(path, z3.Not(allowed)):
                                _stop(SchedulerDebtReason.CONTROL_MISMATCH,
                                      "root pre-CALL rank outside replayed domain")
                        elif frame.scope == rank_context.recursive_scope_digest:
                            decrement = decrement_by_key.get(key)
                            if decrement is None or frame.entry_rank is None or decrement <= 0:
                                _stop(SchedulerDebtReason.EVIDENCE_MISMATCH,
                                      "recursive call lacks rank actual")
                            width = child_rank.size()
                            self._expression(4)
                            if self._sat_extended(path,
                                    z3.ULT(frame.entry_rank, z3.BitVecVal(decrement, width))):
                                _stop(SchedulerDebtReason.CONTROL_MISMATCH,
                                      "recursive rank underflow")
                            self._equal(path, child_rank,
                                frame.entry_rank - z3.BitVecVal(decrement, width),
                                "recursive pre-CALL rank differs from replayed decrement")
                        else:
                            _stop(SchedulerDebtReason.EVIDENCE_MISMATCH,
                                  "recursive callee reached from unsupported helper")
                    self.contexts += 1
                    path.certified_contexts += 1
                    if (self.contexts > request.limits.contexts
                            or path.certified_contexts > rank_context.maximum_context_expansions
                            or len(frame.occurrence) >= 32):
                        _stop(SchedulerDebtReason.RESOURCE_BOUND, "context/occurrence budget")
                    recursive_depth = sum(row.scope == rank_context.recursive_scope_digest
                                          for row in path.frames)
                    if (edge.callee_scope_digest == rank_context.recursive_scope_digest
                            and recursive_depth + 1
                            > rank_context.maximum_simultaneous_recursive_activations):
                        _stop(SchedulerDebtReason.RESOURCE_BOUND,
                              "certified recursive activation depth")
                    self.serial += 1
                    frame_copy = (160 + 8 * (len(path.frames) + 1)
                                  + 8 * (len(frame.occurrence) + 1))
                    if (self._state_accounted_bytes()
                            + self.query_scratch_bytes + frame_copy
                            > request.limits.symbolic_state_bytes):
                        _stop(SchedulerDebtReason.RESOURCE_BOUND, "aggregate frame-copy budget")
                    self.copy_bytes += frame_copy
                    child = _Frame(edge.callee_scope_digest, (*frame.occurrence, self.serial),
                        self._read(path, sp_var), child_offset,
                        z3.BitVecVal(instruction.fallthrough.byte_offset, 64),
                        instruction.fallthrough, frame.entry_offset, observed.before_offset,
                        child_rank)
                    self._record(path, frame, instruction, ordinal, opcode, before_nodes, before_events)
                    path.frames = (*path.frames, child)
                    next_pc = self.by_scope[edge.callee_scope_digest].entry
                    break
                if opcode == "RETURN":
                    self._expression(32)
                    observed = self.returns.get((frame.scope, key))
                    if (not terminal or observed is None or not instruction.flow.is_terminal
                            or instruction.fallthrough is not None or len(operation.inputs) != 1
                            or observed.interval.offset != 0 or observed.interval.byte_size != 8):
                        _stop(SchedulerDebtReason.MISSING_NORMAL_EXIT, "RETURN shape or observed token")
                    self._equal(path, self._read(path, operation.inputs[0]), frame.expected_token,
                                "RETURN target differs from entry token")
                    self._equal(path, self._read(path, sp_var), frame.entry_sp + observed.after_offset,
                                "RETURN SP differs from observed restoration")
                    if len(path.frames) == 1:
                        if len(exits) >= request.limits.cfg_paths:
                            _stop(SchedulerDebtReason.RESOURCE_BOUND, "exit path budget")
                        exit_bytes = (256 * len(path.kernel.definitions)
                                      + 128 * len(path.kernel.events)
                                      + 8 * len(path.operations))
                        if self.reserved_bytes + exit_bytes > request.limits.cache_bytes:
                            _stop(SchedulerDebtReason.RESOURCE_BOUND, "aggregate exit encoding budget")
                        self.reserved_bytes += exit_bytes
                        self._record(path, frame, instruction, ordinal, opcode, before_nodes, before_events)
                        exits.append(FinitePathExit(path.alternative, tuple(path.operations),
                            tuple(path.kernel.definitions),
                            tuple(path.kernel.events), tuple(sorted((key, cell.node)
                                for key, cell in path.kernel.cells.items())), path.constraints))
                        next_pc = False
                    else:
                        self._record(path, frame, instruction, ordinal, opcode, before_nodes, before_events)
                        frame_copy = 8 * (len(path.frames) - 1)
                        if (self._state_accounted_bytes()
                                + self.query_scratch_bytes + frame_copy
                                > request.limits.symbolic_state_bytes):
                            _stop(SchedulerDebtReason.RESOURCE_BOUND, "return-frame slice budget")
                        self.copy_bytes += frame_copy
                        path.frames = path.frames[:-1]
                        parent = path.frames[-1]
                        self._equal(path, self._read(path, sp_var),
                            parent.entry_sp + frame.caller_token_before,
                            "child RETURN did not restore caller SP")
                        next_pc = frame.continuation
                    break
                if opcode == "BRANCH":
                    if (not terminal or len(operation.inputs) != 1 or len(instruction.flow_targets) != 1
                            or not instruction.flow.is_jump or instruction.flow.has_fallthrough
                            or operation.inputs[0].coordinate != instruction.flow_targets[0]):
                        _stop(SchedulerDebtReason.UNSUPPORTED_CFG, "direct BRANCH shape")
                    next_pc = instruction.flow_targets[0]
                    self._record(path, frame, instruction, ordinal, opcode, before_nodes, before_events)
                    break
                if opcode == "CBRANCH":
                    if (not terminal or len(operation.inputs) != 2 or len(instruction.flow_targets) != 1
                            or instruction.fallthrough is None or not instruction.flow.is_conditional
                            or operation.inputs[0].coordinate != instruction.flow_targets[0]):
                        _stop(SchedulerDebtReason.UNSUPPORTED_CFG, "conditional BRANCH shape")
                    self._expression(8)
                    condition = self._read(path, operation.inputs[1]) != 0
                    self._record(path, frame, instruction, ordinal, opcode, before_nodes, before_events)
                    for choice, target, clause in ((0, instruction.fallthrough, z3.Not(condition)),
                                                   (1, instruction.flow_targets[0], condition)):
                        if self._sat_extended(path, clause):
                            self.paths += 1
                            if self.paths > request.limits.cfg_paths:
                                _stop(SchedulerDebtReason.RESOURCE_BOUND, "aggregate CFG path budget")
                            fork = self._fork(path)
                            fork.pc = target
                            fork.constraints = (*path.constraints, clause)
                            fork.alternative = (*path.alternative, choice)
                            pending.append(fork)
                    next_pc = False
                    break
                if opcode in {"CALLIND", "BRANCHIND"}:
                    _stop(SchedulerDebtReason.UNSUPPORTED_CFG, "indirect control")
                before_expressions = path.kernel.expression_nodes
                reserved_expressions = self.expression_nodes
                self._reserve_transfer(operation)
                try:
                    path.kernel.transfer(operation, occurrence=frame.occurrence,
                        operation_ordinal=ordinal,
                        stack_interval_guard=(
                            (lambda offset, size: self._admit_stack_interval(
                                path, offset, size, admitted_absolute))
                            if request.symbolic_entry is not None else None))
                except _InfeasiblePath:
                    next_pc = False
                    break
                if (path.kernel.expression_nodes - before_expressions
                        > self.expression_nodes - reserved_expressions):
                    _stop(SchedulerDebtReason.EVIDENCE_MISMATCH,
                          "kernel expression construction exceeded aggregate reservation")
                self._record(path, frame, instruction, ordinal, opcode, before_nodes, before_events)
            if next_pc is False:
                continue
            if next_pc is None:
                if instruction.flow.is_call or instruction.flow.is_jump or instruction.flow.is_terminal:
                    _stop(SchedulerDebtReason.UNSUPPORTED_CFG, "missing control operation")
                if instruction.fallthrough is None:
                    _stop(SchedulerDebtReason.MISSING_NORMAL_EXIT, "missing ordinary fallthrough")
                next_pc = instruction.fallthrough
            path.pc = next_pc
            pending.append(path)
        if not exits:
            _stop(SchedulerDebtReason.MISSING_NORMAL_EXIT, "no feasible root RETURN")
        return FiniteExpansion((SYMBOLIC_SCHEDULER_REVISION if request.symbolic_entry is not None
                                else SCHEDULER_REVISION), kernel.revision,
                               request.input_digest, root_scope, kernel.root_token_seed,
                               tuple(exits), self.contexts, self.queries)


def expand_configured_finite_context(request: ConfiguredFiniteContextRequest, /, *,
                                     kernel_limits: KernelLimits = KernelLimits()) -> FiniteExpansion:
    """Replay and expand every feasible raw normal path or raise typed debt."""
    try:
        return _Scheduler(request, kernel_limits).run()
    except KernelIncomplete as error:
        _stop(SchedulerDebtReason.KERNEL_STOP, f"{error.reason.value}: {error.detail}")
