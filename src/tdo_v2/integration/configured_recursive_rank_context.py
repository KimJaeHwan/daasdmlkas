"""Unwired root-context bitvector rank/depth diagnostic.

The checker symbolically interprets admitted raw P-code in one acyclic root
and one direct self-recursive function. A self call returns under the exact
conditional frame-base/parent-memory lemma; no origin, privacy, or production
completion follows from this result. Unknown raw semantics stop typed.
"""

from __future__ import annotations

from math import isfinite
from time import monotonic

from dataclasses import dataclass
from enum import StrEnum

import z3

from ..call_seeds import _operation_key
from ..physical_state import PhysicalRegisterSlice
from ..scope_identity import VarnodeKindCode
from .configured_interprocedural_contracts import ConfiguredFunctionAnalysis
from .configured_recursive_all_effects import (
    RecursiveAllEffectInventory, build_recursive_all_effect_inventory,
)
from .configured_recursive_call_edges import (
    VerifiedDirectCallEdges, VerifiedDirectCallEdgesIncomplete,
    verify_direct_call_edges,
)
from .configured_recursive_frame_base_certificate import (
    FrameBaseCertificateIncomplete, InductiveFrameBaseCertificate,
    ISOLATED_STACK_PROFILE, SHARED_STATE_PROFILE,
    _analyze_function, certify_inductive_frame_base,
)
from .configured_recursive_frame_inventory import (
    RecursiveFrameInventory, build_recursive_frame_inventory,
)


class RankContextDebtReason(StrEnum):
    INVALID_INPUT = "invalid_input"
    EVIDENCE_MISMATCH = "evidence_mismatch"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    UNSUPPORTED_CFG = "unsupported_cfg"
    UNKNOWN_MEMORY = "unknown_memory"
    ROOT_RANGE = "root_range"
    GUARD_OR_ACTUAL = "guard_or_actual"
    NORMAL_EXIT = "normal_exit"
    MODULAR_WINDOW = "modular_window"
    SOLVER_UNKNOWN = "solver_unknown"
    RESOURCE_BOUND = "resource_bound"


class RankContextIncomplete(RuntimeError):
    def __init__(self, reason: RankContextDebtReason, detail: str):
        self.reason, self.detail = reason, detail
        super().__init__(f"{reason.value}: {detail}")


@dataclass(frozen=True, slots=True)
class RankCallsiteFact:
    call_operation_key: str
    decrement: int


@dataclass(frozen=True, slots=True)
class RootRankContextCertificate:
    program_scope_digest: bytes
    root_scope_digest: bytes
    root_observation_digest: bytes
    recursive_scope_digest: bytes
    recursive_observation_digest: bytes
    root_ranks: tuple[int, ...]
    recursive_actuals: tuple[RankCallsiteFact, ...]
    maximum_simultaneous_recursive_activations: int
    maximum_context_expansions: int
    child_entry_shift: int
    recursive_subtree_window: tuple[int, int]
    modular_window: tuple[int, int]
    coarse_signed_rank_window_width: int
    shared_state_profile: str
    isolated_stack_profile: str
    conditional_on_child_normal_return: bool = True
    conditional_on_inductive_frame_step: bool = True
    proves_privacy: bool = False
    proves_origins: bool = False


def _debt(reason, detail):
    raise RankContextIncomplete(reason, detail)


def _split(value):
    return tuple(z3.Extract(8 * index + 7, 8 * index, value)
                 for index in range(value.size() // 8))


def _join(bytes_):
    return z3.Concat(*reversed(bytes_)) if len(bytes_) > 1 else bytes_[0]


def _fresh(width, prefix):
    return z3.FreshConst(z3.BitVecSort(width), prefix=prefix)


@dataclass
class _State:
    pc: object
    path: tuple[object, ...]
    constraints: tuple[z3.BoolRef, ...]
    registers: dict[int, z3.BitVecRef]
    unique: dict[int, z3.BitVecRef]
    frame: dict[int, z3.BitVecRef]
    absolute: dict[tuple[int, int], z3.BitVecRef]
    calls: tuple[tuple[str, z3.BitVecRef], ...]
    other_calls: tuple[str, ...]
    entry_token: z3.BitVecRef

    def fork(self, pc, condition):
        return _State(pc, self.path, self.constraints + (condition,),
                      self.registers.copy(), self.unique.copy(), self.frame.copy(),
                      self.absolute.copy(), self.calls, self.other_calls,
                      self.entry_token)


class _Interpreter:
    def __init__(self, analysis, inventory, edges, root_scope, recursive_scope,
                 rank, frame_base, stack_pointer, limits):
        self.analysis, self.inventory = analysis, inventory
        self.scope = analysis.evidence.unit.scopes.function.scope.digest
        self.root_scope, self.recursive_scope = root_scope, recursive_scope
        self.rank, self.frame_base, self.stack_pointer = rank, frame_base, stack_pointer
        self.limits = limits
        self.instructions = {row.address: row for row in analysis.evidence.unit.observation.instructions}
        self.accesses = {row.operation_key: row for row in inventory.accesses}
        self.tokens = {row.call_operation_key: row for row in inventory.call_tokens}
        self.returns = {row.return_operation_key: row for row in inventory.return_tokens}
        self.edges = {row.call_operation_key: row for row in edges
                      if row.caller_scope_digest == self.scope}
        self.register_space = self._register_space()
        self.memory_space = self._memory_space()
        self.entry_sp = _fresh(64, "entry_sp")
        self.entry_rank = _fresh(rank.byte_size * 8, "entry_rank")

    def _register_space(self):
        spaces = {node.coordinate.space_id
                  for row in self.instructions.values() for op in row.operations
                  for node in (*op.inputs, *((op.output,) if op.output else ()))
                  if node.kind is VarnodeKindCode.REGISTER
                  and node.coordinate.byte_offset == self.stack_pointer.byte_offset
                  and node.byte_size == self.stack_pointer.byte_size}
        if len(spaces) != 1:
            _debt(RankContextDebtReason.EVIDENCE_MISMATCH, "ambiguous physical register space")
        return next(iter(spaces))

    def _memory_space(self):
        spaces = {row.interval.address_space_id for row in self.inventory.accesses
                  if row.interval is not None}
        if len(spaces) != 1:
            _debt(RankContextDebtReason.EVIDENCE_MISMATCH, "ambiguous frame memory space")
        return next(iter(spaces))

    def initial(self, *, recursive):
        token = _fresh(64, "entry_return_token")
        state = _State(self.analysis.entry, (), (), {}, {}, {}, {}, (), (), token)
        self._write_register(state, self.stack_pointer, self.entry_sp)
        if recursive:
            self._write_register(state, self.rank, self.entry_rank)
        for index, byte in enumerate(_split(token)):
            state.frame[index] = byte
        return state

    def _sat(self, constraints):
        self.limits["queries"] += 1
        if self.limits["queries"] > self.limits["max_queries"]:
            _debt(RankContextDebtReason.RESOURCE_BOUND, "solver query budget")
        deadline = self.limits.get("solver_deadline")
        solver = z3.Solver()
        if deadline is None:
            solver.set(timeout=self.limits["timeout_ms"])
            solver.add(*constraints)
        else:
            solver.add(*constraints)
            remaining_ms = (deadline - monotonic()) * 1000
            if remaining_ms <= 0:
                _debt(RankContextDebtReason.RESOURCE_BOUND, "aggregate solver-time budget")
            solver.set(timeout=max(1, min(self.limits["timeout_ms"], int(remaining_ms))))
        answer = solver.check()
        if deadline is not None and monotonic() >= deadline:
            _debt(RankContextDebtReason.RESOURCE_BOUND, "aggregate solver-time budget")
        if answer == z3.unknown:
            _debt(RankContextDebtReason.SOLVER_UNKNOWN, solver.reason_unknown())
        return answer == z3.sat

    def _prove(self, state, claim, detail):
        if self._sat((*state.constraints, z3.Not(claim))):
            _debt(RankContextDebtReason.GUARD_OR_ACTUAL, detail)

    def _read_register(self, state, selector):
        for offset in range(selector.byte_offset, selector.byte_offset + selector.byte_size):
            state.registers.setdefault(offset, _fresh(8, f"reg_{offset}"))
        return _join(tuple(state.registers[offset]
                           for offset in range(selector.byte_offset,
                                               selector.byte_offset + selector.byte_size)))

    def _write_register(self, state, selector, value):
        if value.size() != selector.byte_size * 8:
            _debt(RankContextDebtReason.UNSUPPORTED_OPERATION, "register output width")
        for offset, byte in enumerate(_split(value)):
            state.registers[selector.byte_offset + offset] = byte

    def _read(self, state, node):
        kind = node.kind
        offset, size = node.coordinate.byte_offset, node.byte_size
        if size < 1 or size > 64:
            _debt(RankContextDebtReason.RESOURCE_BOUND, "varnode byte budget")
        if kind is VarnodeKindCode.CONSTANT:
            return z3.BitVecVal(offset, size * 8)
        if kind is VarnodeKindCode.REGISTER:
            if node.coordinate.space_id != self.register_space:
                _debt(RankContextDebtReason.UNSUPPORTED_OPERATION, "foreign register space")
            return self._read_register(state, PhysicalRegisterSlice(offset, size))
        if kind is VarnodeKindCode.UNIQUE:
            cells = tuple(state.unique.get((node.coordinate.space_id, offset + index))
                          for index in range(size))
            if any(cell is None for cell in cells):
                _debt(RankContextDebtReason.UNSUPPORTED_OPERATION, "uninitialized UNIQUE")
            return _join(cells)
        if kind is VarnodeKindCode.ADDRESS:
            cells = tuple(state.absolute.setdefault((node.coordinate.space_id, offset + index),
                                                    _fresh(8, "absolute_byte")) for index in range(size))
            return _join(cells)
        _debt(RankContextDebtReason.UNSUPPORTED_OPERATION, "unclassified varnode read")

    def _write(self, state, node, value):
        if node is None or value.size() != node.byte_size * 8:
            _debt(RankContextDebtReason.UNSUPPORTED_OPERATION, "raw output width")
        offset = node.coordinate.byte_offset
        if node.kind is VarnodeKindCode.REGISTER:
            if node.coordinate.space_id != self.register_space:
                _debt(RankContextDebtReason.UNSUPPORTED_OPERATION, "foreign register output")
            self._write_register(state, PhysicalRegisterSlice(offset, node.byte_size), value)
        elif node.kind is VarnodeKindCode.UNIQUE:
            for index, byte in enumerate(_split(value)):
                state.unique[(node.coordinate.space_id, offset + index)] = byte
        elif node.kind is VarnodeKindCode.ADDRESS:
            for index, byte in enumerate(_split(value)):
                state.absolute[(node.coordinate.space_id, offset + index)] = byte
        else:
            _debt(RankContextDebtReason.UNSUPPORTED_OPERATION, "unclassified varnode write")

    def _value(self, state, operation):
        opcode = operation.opcode
        inputs = tuple(self._read(state, node) for node in operation.inputs)
        output = operation.output
        if output is None:
            _debt(RankContextDebtReason.UNSUPPORTED_OPERATION, "missing value output")
        width = output.byte_size * 8
        if opcode in {"COPY", "CAST"} and len(inputs) == 1 and inputs[0].size() == width:
            result = inputs[0]
        elif opcode == "INT_ZEXT" and len(inputs) == 1 and inputs[0].size() < width:
            result = z3.ZeroExt(width - inputs[0].size(), inputs[0])
        elif opcode == "INT_SEXT" and len(inputs) == 1 and inputs[0].size() < width:
            result = z3.SignExt(width - inputs[0].size(), inputs[0])
        elif opcode in {"INT_ADD", "INT_SUB", "INT_AND", "INT_OR", "INT_XOR"} and len(inputs) == 2:
            a, b = inputs
            if a.size() != b.size() or a.size() != width:
                _debt(RankContextDebtReason.UNSUPPORTED_OPERATION, f"{opcode} width")
            result = {"INT_ADD": lambda: a+b, "INT_SUB": lambda: a-b,
                      "INT_AND": lambda: a&b, "INT_OR": lambda: a|b,
                      "INT_XOR": lambda: a^b}[opcode]()
        elif opcode in {"INT_LESS", "INT_SLESS", "INT_EQUAL", "INT_CARRY",
                        "INT_SCARRY", "INT_SBORROW"} and len(inputs) == 2 and width == 8:
            a, b = inputs
            if a.size() != b.size():
                _debt(RankContextDebtReason.UNSUPPORTED_OPERATION, "comparison width")
            total, diff = a+b, a-b
            sign_a, sign_b = z3.Extract(a.size()-1, a.size()-1, a), z3.Extract(b.size()-1,b.size()-1,b)
            sign_total, sign_diff = z3.Extract(total.size()-1,total.size()-1,total), z3.Extract(diff.size()-1,diff.size()-1,diff)
            predicate = {
                "INT_LESS": lambda: z3.ULT(a,b), "INT_SLESS": lambda: a<b,
                "INT_EQUAL": lambda: a==b, "INT_CARRY": lambda: z3.ULT(total,a),
                "INT_SCARRY": lambda: z3.And(sign_a==sign_b,sign_total!=sign_a),
                "INT_SBORROW": lambda: z3.And(sign_a!=sign_b,sign_diff!=sign_a),
            }[opcode]()
            result = z3.If(predicate,z3.BitVecVal(1,8),z3.BitVecVal(0,8))
        elif opcode == "BOOL_NEGATE" and len(inputs) == 1 and width == 8:
            result = z3.If(inputs[0]==0,z3.BitVecVal(1,8),z3.BitVecVal(0,8))
        elif opcode == "BOOL_AND" and len(inputs) == 2 and width == 8:
            result = z3.If(z3.And(inputs[0]!=0,inputs[1]!=0),z3.BitVecVal(1,8),z3.BitVecVal(0,8))
        elif opcode == "POPCOUNT" and len(inputs) == 1:
            if width < (inputs[0].size()+1).bit_length():
                _debt(RankContextDebtReason.UNSUPPORTED_OPERATION, "POPCOUNT output width")
            result = z3.Sum(tuple(z3.ZeroExt(width-1,z3.Extract(bit,bit,inputs[0]))
                                  for bit in range(inputs[0].size())))
        else:
            _debt(RankContextDebtReason.UNSUPPORTED_OPERATION, opcode)
        if result.size() != width:
            _debt(RankContextDebtReason.UNSUPPORTED_OPERATION, "value result width")
        self._write(state, output, z3.simplify(result))

    def _memory_access(self, state, key, operation):
        access = self.accesses.get(key)
        if access is None or access.interval is None:
            _debt(RankContextDebtReason.UNKNOWN_MEMORY, "unreplayed frame access")
        interval = access.interval
        if interval.address_space_id != self.memory_space:
            _debt(RankContextDebtReason.UNKNOWN_MEMORY, "memory space differs")
        if (len(operation.inputs) != (2 if operation.opcode == "LOAD" else 3)
                or operation.inputs[0].kind is not VarnodeKindCode.CONSTANT
                or operation.inputs[0].coordinate.byte_offset != self.memory_space):
            _debt(RankContextDebtReason.UNKNOWN_MEMORY, "memory selector/shape")
        pointer = self._read(state, operation.inputs[1])
        if pointer.size() != self.entry_sp.size():
            _debt(RankContextDebtReason.UNKNOWN_MEMORY, "pointer width")
        self._prove(state, pointer == self.entry_sp + z3.BitVecVal(interval.offset, 64),
                    "frame pointer differs from replayed interval")
        return interval

    def _load(self, state, key, operation):
        interval = self._memory_access(state, key, operation)
        if operation.output is None or operation.output.byte_size != interval.byte_size:
            _debt(RankContextDebtReason.UNKNOWN_MEMORY, "LOAD width")
        cells = tuple(state.frame.get(interval.offset + index) for index in range(interval.byte_size))
        if any(cell is None for cell in cells):
            _debt(RankContextDebtReason.UNKNOWN_MEMORY, "uninitialized frame LOAD")
        self._write(state, operation.output, _join(cells))

    def _store(self, state, key, operation):
        interval = self._memory_access(state, key, operation)
        value = self._read(state, operation.inputs[2])
        if value.size() != interval.byte_size * 8:
            _debt(RankContextDebtReason.UNKNOWN_MEMORY, "STORE width")
        for index, byte in enumerate(_split(value)):
            state.frame[interval.offset + index] = byte

    def _call(self, state, instruction, ordinal, operation):
        key = _operation_key(instruction.address, ordinal, "CALL")
        edge, token = self.edges.get(key), self.tokens.get(key)
        if (edge is None or token is None or not instruction.flow.is_call
                or instruction.fallthrough is None or len(operation.inputs) != 1
                or operation.inputs[0].kind is not VarnodeKindCode.ADDRESS
                or ordinal != len(instruction.operations)-1):
            _debt(RankContextDebtReason.EVIDENCE_MISMATCH, "CALL edge/token/flow")
        sp = self._read_register(state, self.stack_pointer)
        self._prove(state, sp == self.entry_sp + z3.BitVecVal(token.interval.offset,64),
                    "CALL stack shift")
        token_bytes = tuple(state.frame.get(token.interval.offset + index)
                            for index in range(token.interval.byte_size))
        if any(byte is None for byte in token_bytes):
            _debt(RankContextDebtReason.EVIDENCE_MISMATCH, "missing CALL token bytes")
        self._prove(state, _join(token_bytes) == z3.BitVecVal(instruction.fallthrough.byte_offset,64),
                    "CALL token differs from continuation")
        rank_value = self._read_register(state, self.rank)
        if edge.callee_scope_digest == self.recursive_scope:
            state.calls += ((key, rank_value),)
        else:
            state.other_calls += (key,)
        # CALL has no hidden clobber under the selected shared-state premise.
        # Exact child return and parent-local noninterference are the explicit
        # conditions of the replay-equal frame-base step.
        frame_base = self._read_register(state, self.frame_base)
        for offset in tuple(state.registers):
            state.registers[offset] = _fresh(8, "post_call_register")
        self._write_register(state, self.frame_base, frame_base)
        self._write_register(state, self.stack_pointer,
                             self.entry_sp + z3.BitVecVal(token.before_offset,64))
        state.absolute.clear()
        state.unique.clear()
        state.pc = instruction.fallthrough

    def run(self, *, recursive, rank_bounds=None):
        initial = self.initial(recursive=recursive)
        if rank_bounds is not None:
            low, high = rank_bounds
            initial.constraints = (self.entry_rank >= z3.BitVecVal(low,self.entry_rank.size()),
                                   self.entry_rank <= z3.BitVecVal(high,self.entry_rank.size()))
        pending, completed = [initial], []
        while pending:
            state = pending.pop()
            self.limits["steps"] += 1
            if self.limits["steps"] > self.limits["max_steps"] or len(pending)+len(completed)>self.limits["max_paths"]:
                _debt(RankContextDebtReason.RESOURCE_BOUND, "symbolic path budget")
            if not self._sat(state.constraints):
                continue
            if state.pc in state.path or state.pc not in self.instructions:
                _debt(RankContextDebtReason.UNSUPPORTED_CFG, "cycle or missing instruction")
            instruction = self.instructions[state.pc]
            state.path += (state.pc,)
            next_states = None
            for ordinal, operation in enumerate(instruction.operations):
                self.limits["steps"] += 1
                if self.limits["steps"] > self.limits["max_steps"]:
                    _debt(RankContextDebtReason.RESOURCE_BOUND, "raw operation budget")
                opcode = operation.opcode
                key = _operation_key(instruction.address, ordinal, opcode)
                if opcode == "LOAD":
                    self._load(state, key, operation)
                elif opcode == "STORE":
                    self._store(state, key, operation)
                elif opcode == "CALL":
                    self._call(state, instruction, ordinal, operation)
                    next_states = (state,)
                elif opcode == "BRANCH":
                    if (ordinal != len(instruction.operations)-1 or len(instruction.flow_targets)!=1
                            or not instruction.flow.is_jump or instruction.flow.has_fallthrough
                            or len(operation.inputs)!=1 or operation.inputs[0].coordinate!=instruction.flow_targets[0]):
                        _debt(RankContextDebtReason.UNSUPPORTED_CFG, "direct BRANCH shape")
                    state.pc = instruction.flow_targets[0]
                    next_states = (state,)
                elif opcode == "CBRANCH":
                    if (ordinal != len(instruction.operations)-1 or len(instruction.flow_targets)!=1
                            or instruction.fallthrough is None or not instruction.flow.is_conditional
                            or len(operation.inputs)!=2 or operation.inputs[0].coordinate!=instruction.flow_targets[0]):
                        _debt(RankContextDebtReason.UNSUPPORTED_CFG, "conditional BRANCH shape")
                    condition = self._read(state, operation.inputs[1]) != 0
                    taken = state.fork(instruction.flow_targets[0], condition)
                    fallthrough = state.fork(instruction.fallthrough, z3.Not(condition))
                    next_states = (taken, fallthrough)
                elif opcode == "RETURN":
                    if (ordinal != len(instruction.operations)-1 or key not in self.returns
                            or not instruction.flow.is_terminal or instruction.fallthrough is not None
                            or len(operation.inputs)!=1):
                        _debt(RankContextDebtReason.NORMAL_EXIT, "RETURN shape or token")
                    target = self._read(state, operation.inputs[0])
                    self._prove(state, target == state.entry_token, "RETURN target token")
                    self._prove(state, self._read_register(state,self.stack_pointer)
                                == self.entry_sp + z3.BitVecVal(self.returns[key].after_offset,64),
                                "RETURN stack restore")
                    next_states = ()
                    completed.append(state)
                elif opcode in {"CALLIND", "BRANCHIND"}:
                    _debt(RankContextDebtReason.UNSUPPORTED_CFG, "indirect control")
                else:
                    self._value(state, operation)
            if next_states is None:
                if instruction.flow.is_call or instruction.flow.is_jump or instruction.flow.is_terminal:
                    _debt(RankContextDebtReason.UNSUPPORTED_CFG, "missing control opcode")
                if instruction.fallthrough is None:
                    _debt(RankContextDebtReason.NORMAL_EXIT, "missing fallthrough")
                state.pc = instruction.fallthrough
                next_states = (state,)
            for item in next_states:
                item.unique.clear()
                pending.append(item)
        if not completed:
            _debt(RankContextDebtReason.NORMAL_EXIT, "no feasible normal exit")
        return tuple(completed)


def _all_possible_values(interpreter, paths, value_for_path, width, limit):
    values = set()
    for path in paths:
        value = value_for_path(path)
        if value.size() != width:
            _debt(RankContextDebtReason.GUARD_OR_ACTUAL, "rank byte width")
        for candidate in range(limit+1):
            if interpreter._sat((*path.constraints, value == z3.BitVecVal(candidate,width))):
                values.add(candidate)
        if interpreter._sat((*path.constraints, z3.UGT(value,z3.BitVecVal(limit,width)))):
            _debt(RankContextDebtReason.ROOT_RANGE, "root rank exceeds finite enumeration cap")
    return tuple(sorted(values))


def _full_frame_footprint(scope, frames, edges, recursive_scope, active):
    """Union every raw frame/token access along a nonrecursive call subtree."""
    if scope in active:
        _debt(RankContextDebtReason.MODULAR_WINDOW, "unhandled non-self call cycle")
    inventory = frames[scope]
    intervals = tuple(row.interval for row in inventory.accesses if row.interval is not None)
    if not intervals:
        _debt(RankContextDebtReason.MODULAR_WINDOW, "function has no raw frame intervals")
    low, high = min(row.offset for row in intervals), max(row.stop for row in intervals)
    tokens = {row.call_operation_key: row for row in inventory.call_tokens}
    for edge in edges:
        if edge.caller_scope_digest != scope or edge.callee_scope_digest == recursive_scope:
            continue
        token = tokens.get(edge.call_operation_key)
        if token is None or edge.callee_scope_digest not in frames:
            _debt(RankContextDebtReason.MODULAR_WINDOW, "call footprint lacks token/callee")
        child_low, child_high = _full_frame_footprint(
            edge.callee_scope_digest, frames, edges, recursive_scope,
            active | {scope})
        shift = token.interval.offset
        low, high = min(low, shift + child_low), max(high, shift + child_high)
    return low, high


def _nonrecursive_context_count(scope, edges, recursive_scope, active):
    """Count all observed direct callsites in a nonrecursive callee DAG."""
    if scope == recursive_scope or scope in active:
        _debt(RankContextDebtReason.UNSUPPORTED_CFG,
              "recursive edge in nonrecursive context subtree")
    total = 1
    for edge in edges:
        if edge.caller_scope_digest == scope:
            total += _nonrecursive_context_count(
                edge.callee_scope_digest, edges, recursive_scope, active | {scope})
    return total


def certify_root_rank_context(
    analyses: tuple[ConfiguredFunctionAnalysis, ...],
    inventories: tuple[RecursiveFrameInventory, ...],
    effects: tuple[RecursiveAllEffectInventory, ...],
    verified_edges: VerifiedDirectCallEdges,
    frame_step: InductiveFrameBaseCertificate,
    root_scope_digest: bytes,
    recursive_scope_digest: bytes,
    rank: PhysicalRegisterSlice,
    frame_base: PhysicalRegisterSlice,
    stack_pointer: PhysicalRegisterSlice,
    /, *, shared_state_profile: str, isolated_stack_profile: str,
    max_rank: int = 32, max_steps: int = 100000, max_paths: int = 128,
    max_queries: int = 10000, solver_timeout_ms: int = 5000,
    max_contexts: int = 1024, solver_deadline: float | None = None,
) -> RootRankContextCertificate:
    """Certify one finite root context; replay all premises and raw evidence."""
    def overlaps(left, right):
        return (left.byte_offset < right.byte_offset + right.byte_size
                and right.byte_offset < left.byte_offset + left.byte_size)

    if (type(analyses) is not tuple or not analyses
            or any(type(row) is not ConfiguredFunctionAnalysis for row in analyses)
            or type(inventories) is not tuple or type(effects) is not tuple
            or type(verified_edges) is not VerifiedDirectCallEdges
            or type(frame_step) is not InductiveFrameBaseCertificate
            or any(type(value) is not bytes or len(value)!=32
                   for value in (root_scope_digest,recursive_scope_digest))
            or any(type(value) is not PhysicalRegisterSlice
                   for value in (rank,frame_base,stack_pointer))
            or rank.byte_size != 4 or frame_base.byte_size != 8 or stack_pointer.byte_size != 8
            or any(overlaps(left,right) for left,right in
                   ((rank,frame_base),(rank,stack_pointer),(frame_base,stack_pointer)))
            or any(type(value) is not int or value < 1 for value in
                   (max_rank,max_steps,max_paths,max_queries,solver_timeout_ms,max_contexts))
            or max_rank > 1024
            or (solver_deadline is not None
                and (type(solver_deadline) is not float or not isfinite(solver_deadline)))):
        _debt(RankContextDebtReason.INVALID_INPUT, "rank context envelope")
    if shared_state_profile != SHARED_STATE_PROFILE or isolated_stack_profile != ISOLATED_STACK_PROFILE:
        _debt(RankContextDebtReason.INVALID_INPUT, "named premises mismatch")
    by_scope = {row.evidence.unit.scopes.function.scope.digest: row for row in analyses}
    frames = {row.function_scope_digest: row for row in inventories}
    ledgers = {row.function_scope_digest: row for row in effects}
    if (len(by_scope)!=len(analyses) or len(frames)!=len(inventories)
            or len(ledgers)!=len(effects) or set(by_scope)!=set(frames)!=set(ledgers)
            or root_scope_digest not in by_scope or recursive_scope_digest not in by_scope):
        _debt(RankContextDebtReason.EVIDENCE_MISMATCH, "analysis/ledger closure")
    for scope, analysis in by_scope.items():
        namespace = analysis.evidence.unit.scopes.program.evidence.translation_namespace
        if ":LE:" not in namespace.language_id:
            _debt(RankContextDebtReason.UNSUPPORTED_OPERATION,
                  "unproved little-endian raw varnode byte order")
        frame = build_recursive_frame_inventory(analysis)
        effect = build_recursive_all_effect_inventory(analysis,frame)
        if not frame.complete or not effect.complete or frame != frames[scope] or effect != ledgers[scope]:
            _debt(RankContextDebtReason.EVIDENCE_MISMATCH, "frame/effect replay")
    try:
        replay_edges = verify_direct_call_edges(analyses,inventories)
    except VerifiedDirectCallEdgesIncomplete as error:
        _debt(RankContextDebtReason.EVIDENCE_MISMATCH,str(error))
    if replay_edges != verified_edges:
        _debt(RankContextDebtReason.EVIDENCE_MISMATCH,"direct-edge replay")
    if any(edge.callee_scope_digest == recursive_scope_digest
           and edge.caller_scope_digest not in (root_scope_digest, recursive_scope_digest)
           for edge in verified_edges.edges):
        _debt(RankContextDebtReason.EVIDENCE_MISMATCH,
              "additional entry to recursive function")
    try:
        replay_step = certify_inductive_frame_base(
            analyses,inventories,effects,verified_edges,recursive_scope_digest,
            frame_base,stack_pointer,shared_state_profile=shared_state_profile,
            isolated_stack_profile=isolated_stack_profile)
    except FrameBaseCertificateIncomplete as error:
        _debt(RankContextDebtReason.EVIDENCE_MISMATCH,str(error))
    if replay_step != frame_step:
        _debt(RankContextDebtReason.EVIDENCE_MISMATCH,"conditional frame-base step replay")
    # Other root direct callees must also have observed normal exits and
    # frame-base restoration before their effects are abstracted at CALL.
    helper_steps = {row.function_scope_digest: row for row in frame_step.steps}
    helper_budget = {"analyses":by_scope,"inventories":frames,"steps":0,
                     "max_steps":max_steps,"max_paths":max_paths}
    for edge in verified_edges.edges:
        if edge.caller_scope_digest == root_scope_digest and edge.callee_scope_digest != recursive_scope_digest:
            try:
                _analyze_function(by_scope[edge.callee_scope_digest],frames[edge.callee_scope_digest],
                                  verified_edges.edges,recursive_scope_digest,frame_base,stack_pointer,
                                  next(iter({node.coordinate.space_id for row in
                                             by_scope[recursive_scope_digest].evidence.unit.observation.instructions
                                             for op in row.operations for node in op.inputs
                                             if node.kind is VarnodeKindCode.REGISTER
                                             and node.coordinate.byte_offset == stack_pointer.byte_offset})),
                                  helper_steps,set(),helper_budget)
            except (FrameBaseCertificateIncomplete, KeyError, StopIteration) as error:
                _debt(RankContextDebtReason.EVIDENCE_MISMATCH,f"root callee return: {error}")
    root_edges = [row for row in verified_edges.edges
                  if row.caller_scope_digest==root_scope_digest and row.callee_scope_digest==recursive_scope_digest]
    self_edges = [row for row in verified_edges.edges
                  if row.caller_scope_digest==recursive_scope_digest and row.callee_scope_digest==recursive_scope_digest]
    if len(root_edges)!=1 or not self_edges:
        _debt(RankContextDebtReason.EVIDENCE_MISMATCH,"root/self edge shape")
    limits = {"steps":0,"queries":0,"max_steps":max_steps,"max_paths":max_paths,
              "max_queries":max_queries,"timeout_ms":solver_timeout_ms,
              "solver_deadline":solver_deadline}
    root = _Interpreter(by_scope[root_scope_digest],frames[root_scope_digest],
                        verified_edges.edges,root_scope_digest,recursive_scope_digest,
                        rank,frame_base,stack_pointer,limits)
    root_paths = root.run(recursive=False)
    if any(len(path.calls)!=1 or path.calls[0][0]!=root_edges[0].call_operation_key
           for path in root_paths):
        _debt(RankContextDebtReason.ROOT_RANGE,"root path does not invoke one recursive entry")
    root_ranks = _all_possible_values(root,root_paths,lambda path:path.calls[0][1],rank.byte_size*8,max_rank)
    if not root_ranks or root_ranks[0] < 2:
        _debt(RankContextDebtReason.ROOT_RANGE,"root rank lacks positive guarded lower bound")
    recursive = _Interpreter(by_scope[recursive_scope_digest],frames[recursive_scope_digest],
                             verified_edges.edges,root_scope_digest,recursive_scope_digest,
                             rank,frame_base,stack_pointer,limits)
    paths = recursive.run(recursive=True,rank_bounds=(0,max(root_ranks)))
    calls_by_site = {edge.call_operation_key:set() for edge in self_edges}
    for path in paths:
        entry = recursive.entry_rank
        for key,actual in path.calls:
            if key not in calls_by_site:
                _debt(RankContextDebtReason.GUARD_OR_ACTUAL,"unlisted recursive edge")
            recursive._prove(path,entry>=z3.BitVecVal(2,entry.size()),"recursive call without n>1")
            one = entry-z3.BitVecVal(1,entry.size())
            two = entry-z3.BitVecVal(2,entry.size())
            first = not recursive._sat((*path.constraints,actual!=one))
            second = not recursive._sat((*path.constraints,actual!=two))
            if first == second:
                _debt(RankContextDebtReason.GUARD_OR_ACTUAL,"recursive actual is not a unique n-1/n-2")
            calls_by_site[key].add(1 if first else 2)
        if path.calls and len(path.calls)!=len(self_edges):
            _debt(RankContextDebtReason.GUARD_OR_ACTUAL,"recursive path omits a self-call")
    if sorted(next(iter(values)) for values in calls_by_site.values() if len(values)==1)!=list(range(1,len(self_edges)+1)):
        _debt(RankContextDebtReason.GUARD_OR_ACTUAL,"callsite actuals do not form the strict decrement set")
    if any(not values or len(values)!=1 for values in calls_by_site.values()):
        _debt(RankContextDebtReason.GUARD_OR_ACTUAL,"missing or path-dependent recursive actual")
    for n in range(max(root_ranks)+1):
        feasible = tuple(path for path in paths
                         if recursive._sat((*path.constraints,
                                            recursive.entry_rank==z3.BitVecVal(n,recursive.entry_rank.size()))))
        if not feasible:
            _debt(RankContextDebtReason.NORMAL_EXIT,"rank has no feasible normal-return path")
        expected_calls = 0 if n <= 1 else len(self_edges)
        if any(len(path.calls) != expected_calls for path in feasible):
            _debt(RankContextDebtReason.GUARD_OR_ACTUAL,
                  "guard permits the wrong self-call count for a rank")
    edge_by_key = {edge.call_operation_key: edge for edge in verified_edges.edges}
    def leaf_contexts(call_key):
        edge = edge_by_key[call_key]
        return _nonrecursive_context_count(
            edge.callee_scope_digest, verified_edges.edges, recursive_scope_digest, set())

    rank_contexts = {}
    for n in range(max(root_ranks)+1):
        feasible = tuple(path for path in paths if recursive._sat(
            (*path.constraints, recursive.entry_rank == z3.BitVecVal(n, recursive.entry_rank.size()))))
        rank_contexts[n] = max(
            1 + sum(leaf_contexts(key) for key in path.other_calls)
            + sum(rank_contexts[n - next(iter(calls_by_site[key]))]
                  for key, _ in path.calls)
            for path in feasible
        )
        if rank_contexts[n] > max_contexts:
            _debt(RankContextDebtReason.RESOURCE_BOUND,
                  "recursive context expansion exceeds budget")
    context_expansions = max(
        1 + sum(leaf_contexts(key) for key in path.other_calls) + rank_contexts[n]
        for path in root_paths for n in root_ranks
        if root._sat((*path.constraints,
                      path.calls[0][1] == z3.BitVecVal(n,rank.byte_size*8)))
    )
    if context_expansions > max_contexts:
        _debt(RankContextDebtReason.RESOURCE_BOUND,
              "root context expansion exceeds budget")
    shifts = {row.interval.offset for row in frames[recursive_scope_digest].call_tokens
              if row.call_operation_key in calls_by_site}
    if len(shifts)!=1:
        _debt(RankContextDebtReason.MODULAR_WINDOW,"self-call SP shift differs")
    shift = next(iter(shifts))
    if shift>=0:
        _debt(RankContextDebtReason.MODULAR_WINDOW,"self-call SP does not descend")
    activation_low, activation_high = _full_frame_footprint(
        recursive_scope_digest, frames, verified_edges.edges, recursive_scope_digest, set())
    if activation_high > stack_pointer.byte_size or activation_low >= 0:
        _debt(RankContextDebtReason.MODULAR_WINDOW,"recursive activation footprint shape")
    depth = max(root_ranks)
    recursive_window = ((depth-1)*shift+activation_low,activation_high)
    root_low, root_high = _full_frame_footprint(
        root_scope_digest, frames, verified_edges.edges, recursive_scope_digest, set())
    root_token = {row.call_operation_key:row for row in frames[root_scope_digest].call_tokens}
    token = root_token.get(root_edges[0].call_operation_key)
    if token is None:
        _debt(RankContextDebtReason.MODULAR_WINDOW,"root recursive call token missing")
    root_shift = token.interval.offset
    window = (min(root_low,root_shift+recursive_window[0]),
              max(root_high,root_shift+recursive_window[1]))
    # In the mutual induction, any signed nonnegative 32-bit rank has at
    # most 2^31 activations if both guarded child ranks strictly decrease.
    # Check the machine modular side condition before using the root-specific
    # five-deep bound; neither selected SP nor concrete replay is involved.
    coarse_recursive_low = ((1<<31)-1)*shift+activation_low
    coarse_window_width = max(root_high,root_shift+activation_high) - min(
        root_low,root_shift+coarse_recursive_low)
    if coarse_window_width >= 1<<64 or window[1]-window[0] >= 1<<64:
        _debt(RankContextDebtReason.MODULAR_WINDOW,"relative byte window aliases modulo 64 bits")
    return RootRankContextCertificate(
        verified_edges.program_scope_digest,root_scope_digest,
        by_scope[root_scope_digest].evidence.unit.scopes.function.observation_digest,
        recursive_scope_digest,
        by_scope[recursive_scope_digest].evidence.unit.scopes.function.observation_digest,
        root_ranks,tuple(RankCallsiteFact(key,next(iter(values)))
                         for key,values in sorted(calls_by_site.items())),
        depth,context_expansions,shift,recursive_window,window,coarse_window_width,
        shared_state_profile,isolated_stack_profile,
    )


__all__ = (
    "RankContextDebtReason","RankContextIncomplete","RankCallsiteFact",
    "RootRankContextCertificate","certify_root_rank_context",
)
