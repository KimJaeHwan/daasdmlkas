"""Unwired, conditional frame-base preservation step for observed direct calls.

This checks the no-self-call raw path shape and a self-call conditional
preservation step. It does not prove path feasibility, normal-return
availability, decreasing rank, termination, frame privacy, or permission to
omit a configured event. The named shared-state and stack/image separation
premises remain external conditions of this diagnostic result.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

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
from .configured_recursive_frame_inventory import (
    RecursiveFrameInventory, build_recursive_frame_inventory,
)
from .configured_recursive_local_reads import (
    RecursiveLocalReadCoverageIncomplete, check_recursive_local_read_coverage,
)
from .configured_recursive_frame_separation import (
    RecursiveFrameSeparationIncomplete, check_symbolic_frame_separation,
)


SHARED_STATE_PROFILE = "configured-observed-shared-state-v1"
ISOLATED_STACK_PROFILE = "conditional-isolated-stack-v1"


class FrameBaseDebtReason(StrEnum):
    INVALID_INPUT = "invalid_input"
    PREMISE_MISMATCH = "premise_mismatch"
    EVIDENCE_MISMATCH = "evidence_mismatch"
    INCOMPLETE_EFFECTS = "incomplete_effects"
    UNSUPPORTED_CFG = "unsupported_cfg"
    UNSUPPORTED_VALUE = "unsupported_value"
    SAVE_RESTORE_GAP = "save_restore_gap"
    FRAME_COLLISION = "frame_collision"
    UNKNOWN_CALLEE = "unknown_callee"
    RESOURCE_BOUND = "resource_bound"


class FrameBaseCertificateIncomplete(RuntimeError):
    def __init__(self, reason: FrameBaseDebtReason, detail: str):
        self.reason, self.detail = reason, detail
        super().__init__(f"{reason.value}: {detail}")


@dataclass(frozen=True, slots=True)
class FunctionPreservationStep:
    """Syntactic CFG exits conditional on all selected calls returning."""
    function_scope_digest: bytes
    save_offset: int
    normal_return_keys: tuple[str, ...]
    conditional_self_call_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class InductiveFrameBaseCertificate:
    """A conditional proof step, not an unconditional execution certificate."""
    program_scope_digest: bytes
    recursive_scope_digest: bytes
    frame_base: PhysicalRegisterSlice
    stack_pointer: PhysicalRegisterSlice
    protected_intervals: tuple[tuple[int, int], ...]
    steps: tuple[FunctionPreservationStep, ...]
    shared_state_profile: str
    isolated_stack_profile: str
    conditional_on_smaller_self_calls: bool = True
    conditional_on_child_normal_return: bool = True
    conditional_on_child_parent_memory_preservation: bool = True
    conditional_on_modular_window_bound: bool = True
    proves_termination: bool = False
    proves_privacy: bool = False
    proves_global_nonescape: bool = False


def _debt(reason: FrameBaseDebtReason, detail: str):
    raise FrameBaseCertificateIncomplete(reason, detail)


@dataclass(frozen=True)
class _Value:
    kind: str
    offset: int = 0


_UNKNOWN = _Value("unknown")
_ENTRY = _Value("entry")
_RETURN_TOKEN = _Value("return_token")


def _register_overlap(varnode, selector, space_id):
    return (varnode.kind is VarnodeKindCode.REGISTER
            and varnode.coordinate.space_id == space_id
            and varnode.coordinate.byte_offset < selector.byte_offset + selector.byte_size
            and selector.byte_offset < varnode.coordinate.byte_offset + varnode.byte_size)


def _signed_literal(varnode):
    bits = varnode.byte_size * 8
    raw = varnode.coordinate.byte_offset % (1 << bits)
    return raw - (1 << bits) if raw & (1 << (bits - 1)) else raw


def _analyze_function(analysis, inventory, edges, recursive_scope, frame_base,
                      stack_pointer, register_space, steps, active, budget):
    scope = analysis.evidence.unit.scopes.function.scope.digest
    if scope in steps:
        return
    if scope in active:
        _debt(FrameBaseDebtReason.UNKNOWN_CALLEE, "mutual recursion is outside this lemma")
    active.add(scope)
    edge_by_key = {row.call_operation_key: row for row in edges
                   if row.caller_scope_digest == scope}
    analyses = budget["analyses"]
    for edge in edge_by_key.values():
        if edge.callee_scope_digest == recursive_scope and scope != recursive_scope:
            _debt(FrameBaseDebtReason.UNKNOWN_CALLEE, "non-self edge enters recursive function")
        if edge.callee_scope_digest != recursive_scope:
            callee = analyses.get(edge.callee_scope_digest)
            if callee is None:
                _debt(FrameBaseDebtReason.UNKNOWN_CALLEE, "missing direct callee")
            _analyze_function(callee, budget["inventories"][edge.callee_scope_digest],
                              edges, recursive_scope, frame_base, stack_pointer,
                              register_space, steps, active, budget)
    active.remove(scope)

    observation = analysis.evidence.unit.observation
    by_address = {row.address: row for row in observation.instructions}
    if analysis.entry not in by_address:
        _debt(FrameBaseDebtReason.UNSUPPORTED_CFG, "entry is not observed")
    accesses = {row.operation_key: row for row in inventory.accesses}
    returns = {row.return_operation_key: row for row in inventory.return_tokens}
    calls = {row.call_operation_key: row for row in inventory.call_tokens}
    return_keys, self_calls, save_offsets = set(), set(), set()
    # Each path has its own register/unique/memory state. The sole special
    # value ENTRY denotes the incoming frame-base bytes; OFFSET denotes a
    # full-width entry-SP-relative address. No partial byte overlap is guessed.
    pending = [(analysis.entry, (), _ENTRY, _Value("offset", 0), {}, {},
                {(0, stack_pointer.byte_size): _RETURN_TOKEN}, None)]
    while pending:
        address, path, fp, sp, unique, registers, memory_values, save_offset = pending.pop()
        budget["steps"] += 1
        if budget["steps"] > budget["max_steps"] or len(pending) > budget["max_paths"]:
            _debt(FrameBaseDebtReason.RESOURCE_BOUND, "CFG path or operation budget")
        if address in path or address not in by_address:
            _debt(FrameBaseDebtReason.UNSUPPORTED_CFG, "cycle or missing successor")
        instruction = by_address[address]
        path = path + (address,)
        unique = unique.copy()
        registers = registers.copy()
        memory_values = memory_values.copy()

        def extra_value(table, node):
            exact = (node.coordinate.space_id, node.coordinate.byte_offset, node.byte_size)
            if exact in table:
                return table[exact]
            start, stop = node.coordinate.byte_offset, node.coordinate.byte_offset + node.byte_size
            if any(space == node.coordinate.space_id
                   and offset < stop and start < offset + size
                   and value.kind in {"entry", "offset", "tainted"}
                   for (space, offset, size), value in table.items()):
                return _Value("tainted")
            return _UNKNOWN

        def read(node):
            if node.kind is VarnodeKindCode.CONSTANT:
                return _Value("literal", _signed_literal(node))
            if _register_overlap(node, frame_base, register_space):
                if node.coordinate.byte_offset != frame_base.byte_offset or node.byte_size != frame_base.byte_size:
                    _debt(FrameBaseDebtReason.UNSUPPORTED_VALUE, "partial frame-base read")
                return fp
            if _register_overlap(node, stack_pointer, register_space):
                if node.coordinate.byte_offset != stack_pointer.byte_offset or node.byte_size != stack_pointer.byte_size:
                    _debt(FrameBaseDebtReason.UNSUPPORTED_VALUE, "partial stack-pointer read")
                return sp
            if node.kind is VarnodeKindCode.UNIQUE:
                return extra_value(unique, node)
            if node.kind is VarnodeKindCode.REGISTER:
                return extra_value(registers, node)
            return _UNKNOWN

        def write(node, value):
            nonlocal fp, sp
            if node is None:
                return
            if _register_overlap(node, frame_base, register_space):
                if node.coordinate.byte_offset != frame_base.byte_offset or node.byte_size != frame_base.byte_size:
                    _debt(FrameBaseDebtReason.UNSUPPORTED_VALUE, "partial frame-base write")
                fp = value
            elif _register_overlap(node, stack_pointer, register_space):
                if node.coordinate.byte_offset != stack_pointer.byte_offset or node.byte_size != stack_pointer.byte_size:
                    _debt(FrameBaseDebtReason.UNSUPPORTED_VALUE, "partial stack-pointer write")
                sp = value
            elif node.kind is VarnodeKindCode.UNIQUE:
                start, stop = node.coordinate.byte_offset, node.coordinate.byte_offset + node.byte_size
                for item in tuple(unique):
                    space, offset, size = item
                    if space == node.coordinate.space_id and offset < stop and start < offset + size:
                        if start <= offset and offset + size <= stop:
                            del unique[item]
                        elif unique[item].kind in {"entry", "offset", "tainted"}:
                            unique[item] = _Value("tainted")
                        else:
                            del unique[item]
                unique[(node.coordinate.space_id, node.coordinate.byte_offset, node.byte_size)] = value
            elif node.kind is VarnodeKindCode.REGISTER:
                start, stop = node.coordinate.byte_offset, node.coordinate.byte_offset + node.byte_size
                for item in tuple(registers):
                    space, offset, size = item
                    if space == node.coordinate.space_id and offset < stop and start < offset + size:
                        if start <= offset and offset + size <= stop:
                            del registers[item]
                        elif registers[item].kind in {"entry", "offset", "tainted"}:
                            registers[item] = _Value("tainted")
                        else:
                            del registers[item]
                registers[(node.coordinate.space_id, node.coordinate.byte_offset, node.byte_size)] = value
            elif node.kind is VarnodeKindCode.ADDRESS and value.kind in {"offset", "tainted"}:
                _debt(FrameBaseDebtReason.UNSUPPORTED_VALUE, "stack pointer escapes to absolute RAM")

        successor = None
        for ordinal, operation in enumerate(instruction.operations):
            budget["steps"] += 1
            if budget["steps"] > budget["max_steps"]:
                _debt(FrameBaseDebtReason.RESOURCE_BOUND, "raw operation budget")
            key = _operation_key(address, ordinal, operation.opcode)
            opcode = operation.opcode
            values = tuple(read(node) for node in operation.inputs)
            if opcode in {"COPY", "CAST"} and len(values) == 1:
                value = values[0]
                if (operation.output is None
                        or operation.output.byte_size != operation.inputs[0].byte_size):
                    value = (_Value("tainted") if value.kind in {"entry", "offset", "tainted"}
                             else _UNKNOWN)
                write(operation.output, value)
            elif opcode in {"INT_ADD", "INT_SUB"} and len(values) == 2:
                left, right = values
                value = _UNKNOWN
                widths_match = (operation.output is not None
                                and all(node.byte_size == operation.output.byte_size
                                        for node in operation.inputs))
                if widths_match and left.kind == "offset" and right.kind == "literal":
                    shift = right.offset if opcode == "INT_ADD" else -right.offset
                    value = _Value("offset", left.offset + shift)
                elif widths_match and opcode == "INT_ADD" and left.kind == "literal" and right.kind == "offset":
                    value = _Value("offset", left.offset + right.offset)
                elif left.kind in {"entry", "offset", "tainted"} or right.kind in {"entry", "offset", "tainted"}:
                    value = _Value("tainted")
                write(operation.output, value)
            elif opcode == "STORE":
                access = accesses.get(key)
                if access is None or access.interval is None or len(values) != 3:
                    _debt(FrameBaseDebtReason.INCOMPLETE_EFFECTS, "uncovered STORE")
                interval = access.interval
                if values[1] != _Value("offset", interval.offset):
                    _debt(FrameBaseDebtReason.UNSUPPORTED_VALUE, "STORE pointer differs from frame inventory")
                slot = (interval.offset, interval.stop)
                if values[2] == _ENTRY and interval.byte_size == frame_base.byte_size:
                    if save_offset is not None and save_offset != interval.offset:
                        _debt(FrameBaseDebtReason.SAVE_RESTORE_GAP, "multiple incoming frame-base slots")
                    save_offset = interval.offset
                    save_offsets.add(save_offset)
                if save_offset is not None and slot[0] < save_offset + frame_base.byte_size and save_offset < slot[1]:
                    if slot != (save_offset, save_offset + frame_base.byte_size):
                        _debt(FrameBaseDebtReason.SAVE_RESTORE_GAP, "partial save-slot overwrite")
                for old in tuple(memory_values):
                    if old[0] < slot[1] and slot[0] < old[1]:
                        if slot[0] <= old[0] and old[1] <= slot[1]:
                            del memory_values[old]
                        elif memory_values[old].kind in {"entry", "offset", "tainted"}:
                            memory_values[old] = _Value("tainted")
                        else:
                            del memory_values[old]
                memory_values[slot] = values[2]
            elif opcode == "LOAD":
                access = accesses.get(key)
                if access is None or access.interval is None or len(values) != 2:
                    _debt(FrameBaseDebtReason.INCOMPLETE_EFFECTS, "uncovered LOAD")
                interval = access.interval
                if values[1] != _Value("offset", interval.offset):
                    _debt(FrameBaseDebtReason.UNSUPPORTED_VALUE, "LOAD pointer differs from frame inventory")
                slot = (interval.offset, interval.stop)
                value = memory_values.get(slot, _UNKNOWN)
                if value is _UNKNOWN and any(
                    old[0] < slot[1] and slot[0] < old[1]
                    and item.kind in {"entry", "offset", "tainted"}
                    for old, item in memory_values.items()
                ):
                    value = _Value("tainted")
                write(operation.output, value)
            elif opcode == "CALL":
                edge = edge_by_key.get(key)
                token = calls.get(key)
                if (edge is None or token is None or ordinal != len(instruction.operations) - 1
                        or not instruction.flow.is_call or len(instruction.flow_targets) != 1
                        or len(operation.inputs) != 1
                        or operation.inputs[0].coordinate != instruction.flow_targets[0]
                        or token.continuation != instruction.fallthrough
                        or sp != _Value("offset", token.interval.offset)):
                    _debt(FrameBaseDebtReason.EVIDENCE_MISMATCH, "CALL edge/token/control mismatch")
                expected_token = _Value("literal", instruction.fallthrough.byte_offset)
                slot = (token.interval.offset, token.interval.stop)
                if (token.interval.byte_size != stack_pointer.byte_size
                        or memory_values.get(slot) != expected_token):
                    _debt(FrameBaseDebtReason.EVIDENCE_MISMATCH,
                          "CALL token bytes do not equal its normal continuation")
                if edge.callee_scope_digest == recursive_scope:
                    self_calls.add(key)
                elif edge.callee_scope_digest not in steps:
                    _debt(FrameBaseDebtReason.UNKNOWN_CALLEE, "callee preservation step is absent")
                # The child lemma preserves the incoming FP and every parent
                # ordinary byte. Its RETURN consumes the CALL token and
                # restores the caller's pre-token SP.
                sp = _Value("offset", token.before_offset)
                registers = {
                    key: (_Value("tainted") if value.kind in {"entry", "offset", "tainted"} else _UNKNOWN)
                    for key, value in registers.items()
                }
                successor = (instruction.fallthrough,)
            elif opcode == "RETURN":
                if (key not in returns or ordinal != len(instruction.operations) - 1
                        or not instruction.flow.is_terminal or instruction.fallthrough is not None
                        or len(values) != 1 or values[0] != _RETURN_TOKEN):
                    _debt(FrameBaseDebtReason.EVIDENCE_MISMATCH, "normal RETURN token missing")
                if sp != _Value("offset", returns[key].after_offset):
                    _debt(FrameBaseDebtReason.SAVE_RESTORE_GAP, "normal RETURN does not restore caller SP")
                if (fp != _ENTRY or save_offset is None
                        or memory_values.get((save_offset, save_offset + frame_base.byte_size)) != _ENTRY):
                    _debt(FrameBaseDebtReason.SAVE_RESTORE_GAP, "incoming frame-base bytes not restored")
                return_keys.add(key)
                successor = ()
            elif opcode == "BRANCH":
                if (ordinal != len(instruction.operations) - 1 or not instruction.flow.is_jump
                        or instruction.flow.has_fallthrough or len(instruction.flow_targets) != 1
                        or operation.inputs[0].coordinate != instruction.flow_targets[0]):
                    _debt(FrameBaseDebtReason.UNSUPPORTED_CFG, "unsupported direct branch")
                successor = instruction.flow_targets
            elif opcode == "CBRANCH":
                if (ordinal != len(instruction.operations) - 1 or not instruction.flow.is_jump
                        or not instruction.flow.is_conditional
                        or len(instruction.flow_targets) != 1
                        or instruction.fallthrough is None
                        or operation.inputs[0].coordinate != instruction.flow_targets[0]):
                    _debt(FrameBaseDebtReason.UNSUPPORTED_CFG, "unsupported conditional branch")
                successor = (instruction.fallthrough, *instruction.flow_targets)
            elif opcode in {"CALLIND", "BRANCHIND"}:
                _debt(FrameBaseDebtReason.UNSUPPORTED_CFG, "indirect control")
            else:
                # Operations outside the tracked projection may be ignored
                # only when they cannot produce stack-derived values that
                # later escape or replace either selected register.
                tainted = any(value.kind in {"offset", "entry", "tainted"}
                              for value in values)
                write(operation.output, _Value("tainted") if tainted else _UNKNOWN)
        if successor is None:
            if instruction.flow.is_call or instruction.flow.is_jump or instruction.flow.is_terminal:
                _debt(FrameBaseDebtReason.UNSUPPORTED_CFG, "flow opcode is missing")
            if instruction.fallthrough is None:
                _debt(FrameBaseDebtReason.UNSUPPORTED_CFG, "path has no normal exit")
            successor = (instruction.fallthrough,)
        if successor and not instruction.flow.has_fallthrough and instruction.fallthrough in successor:
            _debt(FrameBaseDebtReason.UNSUPPORTED_CFG, "flow predicates disagree")
        for target in successor:
            # UNIQUE storage is instruction-local in the retained raw model.
            pending.append((target, path, fp, sp, {}, registers, memory_values, save_offset))
    if not return_keys or len(save_offsets) != 1 or set(returns) != return_keys:
        _debt(FrameBaseDebtReason.SAVE_RESTORE_GAP, "save slot or normal-exit coverage incomplete")
    steps[scope] = FunctionPreservationStep(scope, next(iter(save_offsets)),
                                            tuple(sorted(return_keys)), tuple(sorted(self_calls)))


def certify_inductive_frame_base(
    analyses: tuple[ConfiguredFunctionAnalysis, ...],
    inventories: tuple[RecursiveFrameInventory, ...],
    effects: tuple[RecursiveAllEffectInventory, ...],
    verified_edges: VerifiedDirectCallEdges,
    recursive_scope_digest: bytes,
    frame_base: PhysicalRegisterSlice,
    stack_pointer: PhysicalRegisterSlice,
    /, *, shared_state_profile: str, isolated_stack_profile: str,
    max_steps: int = 16384, max_paths: int = 128,
) -> InductiveFrameBaseCertificate:
    """Prove base/step preservation of selected bytes under named premises.

    Self-call use is conditional on a future strict-decrease proof. No raw
    ABI names, source labels, selected stack address, or caller-supplied
    success assertion enters the proof.
    """
    if (type(analyses) is not tuple or not analyses
            or any(type(row) is not ConfiguredFunctionAnalysis for row in analyses)
            or type(inventories) is not tuple
            or any(type(row) is not RecursiveFrameInventory for row in inventories)
            or type(effects) is not tuple
            or any(type(row) is not RecursiveAllEffectInventory for row in effects)
            or type(verified_edges) is not VerifiedDirectCallEdges
            or type(recursive_scope_digest) is not bytes or len(recursive_scope_digest) != 32
            or type(frame_base) is not PhysicalRegisterSlice
            or type(stack_pointer) is not PhysicalRegisterSlice
            or frame_base == stack_pointer or frame_base.byte_size != stack_pointer.byte_size
            or frame_base.byte_size != 8
            or type(max_steps) is not int or max_steps < 1
            or type(max_paths) is not int or max_paths < 1):
        _debt(FrameBaseDebtReason.INVALID_INPUT, "invalid certificate envelope")
    if (shared_state_profile != SHARED_STATE_PROFILE
            or isolated_stack_profile != ISOLATED_STACK_PROFILE):
        _debt(FrameBaseDebtReason.PREMISE_MISMATCH, "named conditional premises required")
    by_scope = {row.evidence.unit.scopes.function.scope.digest: row for row in analyses}
    frames = {row.function_scope_digest: row for row in inventories}
    ledgers = {row.function_scope_digest: row for row in effects}
    if (len(by_scope) != len(analyses) or len(frames) != len(inventories)
            or len(ledgers) != len(effects)
            or set(by_scope) != set(frames) or set(by_scope) != set(ledgers)
            or recursive_scope_digest not in by_scope):
        _debt(FrameBaseDebtReason.EVIDENCE_MISMATCH, "function/effect closure mismatch")
    for scope, analysis in by_scope.items():
        replay = build_recursive_frame_inventory(analysis)
        effect_replay = build_recursive_all_effect_inventory(analysis, replay)
        if not replay.complete or not effect_replay.complete:
            _debt(FrameBaseDebtReason.INCOMPLETE_EFFECTS, "raw frame/effect coverage incomplete")
        if frames[scope] != replay or ledgers[scope] != effect_replay:
            _debt(FrameBaseDebtReason.EVIDENCE_MISMATCH, "frame/effect replay mismatch")
    try:
        edges = verify_direct_call_edges(analyses, inventories)
    except VerifiedDirectCallEdgesIncomplete as error:
        _debt(FrameBaseDebtReason.EVIDENCE_MISMATCH, str(error))
    if edges != verified_edges:
        _debt(FrameBaseDebtReason.EVIDENCE_MISMATCH, "direct-edge replay mismatch")
    try:
        coverage = check_recursive_local_read_coverage(
            by_scope[recursive_scope_digest], frames[recursive_scope_digest])
    except RecursiveLocalReadCoverageIncomplete as error:
        _debt(FrameBaseDebtReason.INCOMPLETE_EFFECTS, str(error))
    if coverage.nonnegative_load_keys:
        _debt(FrameBaseDebtReason.INCOMPLETE_EFFECTS, "uncovered ordinary LOAD")
    protected_intervals = tuple(sorted({(row.load_interval.offset, row.load_interval.stop)
                                        for row in coverage.reads}))
    if not protected_intervals:
        _debt(FrameBaseDebtReason.SAVE_RESTORE_GAP, "no observed protected local read")
    try:
        geometry = check_symbolic_frame_separation(inventories, verified_edges.edges)
    except RecursiveFrameSeparationIncomplete as error:
        _debt(FrameBaseDebtReason.FRAME_COLLISION, str(error))
    # The protected parent bytes cannot be a child's token or ordinary
    # memory: every direct child interval is below its caller's ordinary
    # floor. Descendants move monotonically downward. Check the concrete
    # one-hop inequalities here; the full rank/depth window is a later unit.
    if not any(row.caller_scope_digest == recursive_scope_digest
               for row in verified_edges.edges):
        _debt(FrameBaseDebtReason.INVALID_INPUT, "selected function has no direct child")
    for row in geometry.calls:
        if row.caller_scope_digest != recursive_scope_digest:
            continue
        for start, stop in protected_intervals:
            # Every descendant's highest byte is at most its entry token's
            # stop. A child can share its return token with this caller's
            # CALL token, but never with an ordinary protected local.
            if start < row.call_token_stop:
                _debt(FrameBaseDebtReason.FRAME_COLLISION,
                      "protected local is not above the child/descendant footprint")
    # The selected function's register space is observed, not an ABI role.
    observation = by_scope[recursive_scope_digest].evidence.unit.observation
    register_spaces = {node.coordinate.space_id
                       for instruction in observation.instructions
                       for operation in instruction.operations
                       for node in (*operation.inputs, *((operation.output,) if operation.output else ()))
                       if node.kind is VarnodeKindCode.REGISTER
                       and node.coordinate.byte_offset in {frame_base.byte_offset, stack_pointer.byte_offset}}
    if len(register_spaces) != 1:
        _debt(FrameBaseDebtReason.INVALID_INPUT, "selected physical register space is ambiguous")
    budget = {"analyses": by_scope, "inventories": frames,
              "steps": 0, "max_steps": max_steps, "max_paths": max_paths}
    steps = {}
    _analyze_function(by_scope[recursive_scope_digest], frames[recursive_scope_digest],
                      verified_edges.edges, recursive_scope_digest, frame_base,
                      stack_pointer, next(iter(register_spaces)), steps, set(), budget)
    saved = steps[recursive_scope_digest].save_offset
    if (saved, saved + frame_base.byte_size) not in protected_intervals:
        _debt(FrameBaseDebtReason.SAVE_RESTORE_GAP, "frame-base save slot lacks exact covered LOAD")
    return InductiveFrameBaseCertificate(
        verified_edges.program_scope_digest, recursive_scope_digest,
        frame_base, stack_pointer, protected_intervals,
        tuple(sorted(steps.values(), key=lambda row: row.function_scope_digest)),
        shared_state_profile, isolated_stack_profile,
    )


__all__ = (
    "FrameBaseDebtReason", "FrameBaseCertificateIncomplete",
    "FunctionPreservationStep", "InductiveFrameBaseCertificate",
    "SHARED_STATE_PROFILE", "ISOLATED_STACK_PROFILE", "certify_inductive_frame_base",
)
