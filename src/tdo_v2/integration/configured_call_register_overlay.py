"""Unwired conditional register definitions across raw direct self calls.

This is a diagnostic of syntactic register uses, not return transport, memory
SSA, frame privacy, a recursive summary, or production evidence. Each static
CFG path is retained separately, conditional on its calls continuing. Memory
reads and unselected call state stay explicitly opaque. Definition ``inputs``
are whole raw operand uses, not exact semantic byte-dependence assertions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .._scope_wire import _observation_digest
from ..call_contracts import DirectCallTarget
from ..call_seeds import _operation_key
from ..physical_state import PhysicalRegisterSlice
from ..scope_identity import AddressCoordinate, VarnodeKindCode
from .configured_interprocedural_contracts import ConfiguredFunctionAnalysis
from .configured_recursive_call_edges import VerifiedDirectCallEdges
from .configured_recursive_frame_separation import CallerSuppliedCallEdge


SHARED_STATE_PROFILE = "configured-observed-shared-state-v1"


class RegisterOverlayDebtReason(StrEnum):
    INVALID_INPUT = "invalid_input"
    EVIDENCE_MISMATCH = "evidence_mismatch"
    UNSUPPORTED_PROFILE = "unsupported_profile"
    UNSUPPORTED_CFG = "unsupported_cfg"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    UNSUPPORTED_ALIAS = "unsupported_alias"
    MISSING_DEFINITION = "missing_definition"
    RESOURCE_BOUND = "resource_bound"


class RegisterOverlayIncomplete(RuntimeError):
    def __init__(self, reason: RegisterOverlayDebtReason, detail: str):
        self.reason, self.detail = reason, detail
        super().__init__(f"{reason.value}: {detail}")


class RegisterDefinitionKind(StrEnum):
    ENTRY = "entry"
    RAW_WRITE = "raw_write"
    CALL_BOUNDARY = "conditional_call_boundary"
    UNMODELED_CALL = "unmodeled_call"
    MEMORY_READ = "opaque_memory_read"


@dataclass(frozen=True, slots=True)
class OverlayByteDefinition:
    id: int
    path_id: int
    kind: RegisterDefinitionKind
    operation_key: str
    space_id: int
    byte_offset: int
    inputs: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class OverlayRegisterRead:
    path_id: int
    operation_key: str
    input_ordinal: int
    role: str
    span: PhysicalRegisterSlice
    definitions: tuple[int, ...]  # Physical byte coordinate order, not value endian.


@dataclass(frozen=True, slots=True)
class OverlayPath:
    id: int
    instructions: tuple[AddressCoordinate, ...]
    exit_registers: tuple[tuple[int, int], ...]  # byte offset, definition ID


@dataclass(frozen=True, slots=True)
class OverlayLimitation:
    path_id: int
    operation_key: str
    reason: str


@dataclass(frozen=True, slots=True)
class CallRegisterOverlay:
    program_scope_digest: bytes
    function_scope_digest: bytes
    observation_digest: bytes
    memory_unit_digest: bytes
    profile_label: str
    register_space_id: int
    selected_spans: tuple[PhysicalRegisterSlice, ...]
    definitions: tuple[OverlayByteDefinition, ...]
    reads: tuple[OverlayRegisterRead, ...]
    paths: tuple[OverlayPath, ...]
    limitations: tuple[OverlayLimitation, ...]
    diagnostic_only: bool = True


def _debt(reason, detail):
    raise RegisterOverlayIncomplete(reason, detail)


_UNARY = frozenset(("COPY", "CAST", "INT_ZEXT", "INT_SEXT", "INT_2COMP",
                    "INT_NEGATE", "BOOL_NEGATE", "POPCOUNT", "LZCOUNT"))
_BINARY = frozenset(("INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV",
                     "INT_REM", "INT_SREM", "INT_AND", "INT_OR", "INT_XOR",
                     "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_EQUAL",
                     "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL",
                     "INT_SLESSEQUAL", "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
                     "BOOL_XOR", "BOOL_AND", "BOOL_OR", "PIECE", "SUBPIECE"))


def build_call_register_overlay(
    analysis: ConfiguredFunctionAnalysis,
    verified_edges: VerifiedDirectCallEdges,
    selected_spans: tuple[PhysicalRegisterSlice, ...],
    /,
    *,
    profile_label: str,
    max_operations: int = 4096,
    max_register_bytes: int = 512,
    max_paths: int = 64,
    max_steps: int = 16384,
    max_definitions: int = 65536,
    max_operand_bytes: int = 262144,
) -> CallRegisterOverlay:
    """Rebuild raw register reads, substituting conditional self-call outputs.

    Selected spans are caller-supplied diagnostic cuts, never result-port
    evidence. Other bytes become unknown at *every* call. Intraprocedural
    loops, computed/overridden control, missing edges and ambiguous register
    spaces abort typed. Acyclic branch/join paths remain separate, with an
    explicit feasibility limitation. LOAD/ADDRESS reads are opaque; STOREs
    are recorded as limitations and never forwarded to subsequent LOADs.
    """
    limits = (max_operations, max_register_bytes, max_paths, max_steps,
              max_definitions, max_operand_bytes)
    if (type(analysis) is not ConfiguredFunctionAnalysis
            or type(verified_edges) is not VerifiedDirectCallEdges
            or type(verified_edges.edges) is not tuple
            or any(type(row) is not CallerSuppliedCallEdge for row in verified_edges.edges)
            or type(selected_spans) is not tuple or not selected_spans
            or any(type(row) is not PhysicalRegisterSlice for row in selected_spans)
            or any(type(value) is not int or value < 1 for value in limits)):
        _debt(RegisterOverlayDebtReason.INVALID_INPUT, "invalid overlay envelope")
    if type(profile_label) is not str or profile_label != SHARED_STATE_PROFILE:
        _debt(RegisterOverlayDebtReason.UNSUPPORTED_PROFILE, "exact shared-state profile required")
    if len(verified_edges.edges) > max_operations or len(selected_spans) > max_register_bytes:
        _debt(RegisterOverlayDebtReason.RESOURCE_BOUND, "input inventory limit")
    evidence, normalized = analysis.evidence, analysis.normalized
    scopes, observation = evidence.unit.scopes, evidence.unit.observation
    if (observation is None or normalized.scopes is not scopes
            or normalized.call_seeds != evidence.seeds or evidence.seeds is None
            or normalized.memory_ssa is None or normalized.memory_unit is None
            or not normalized.dependencies.is_frozen
            or verified_edges.program_scope_digest != scopes.program.scope.digest):
        _debt(RegisterOverlayDebtReason.EVIDENCE_MISMATCH, "foreign or incomplete analysis")
    if len(observation.instructions) > max_operations:
        _debt(RegisterOverlayDebtReason.RESOURCE_BOUND, "instruction limit")
    operations = sum(len(row.operations) for row in observation.instructions)
    if operations > max_operations:
        _debt(RegisterOverlayDebtReason.RESOURCE_BOUND, "raw operation limit")
    if (_observation_digest(observation) != scopes.function.observation_digest
            or normalized.memory_unit.canonical_digest != normalized.memory_ssa.unit_digest):
        _debt(RegisterOverlayDebtReason.EVIDENCE_MISMATCH, "changed observation or memory identity")
    instructions = {row.address: row for row in observation.instructions}
    if len(instructions) != len(observation.instructions) or analysis.entry not in instructions:
        _debt(RegisterOverlayDebtReason.EVIDENCE_MISMATCH, "instruction identity")

    register_bytes, register_spaces = set(), set()
    operand_count = 0
    for instruction in observation.instructions:
        for operation in instruction.operations:
            for value in (*operation.inputs, *((operation.output,) if operation.output else ())):
                operand_count += value.byte_size
                if operand_count > max_operand_bytes:
                    _debt(RegisterOverlayDebtReason.RESOURCE_BOUND, "raw operand byte limit")
                if value.kind is VarnodeKindCode.REGISTER:
                    register_spaces.add(value.coordinate.space_id)
                    if value.byte_size > max_register_bytes:
                        _debt(RegisterOverlayDebtReason.RESOURCE_BOUND, "register width limit")
                    register_bytes.update(range(value.coordinate.byte_offset,
                                                value.coordinate.byte_offset + value.byte_size))
                    if len(register_bytes) > max_register_bytes:
                        _debt(RegisterOverlayDebtReason.RESOURCE_BOUND, "register byte limit")
    if len(register_spaces) != 1:
        _debt(RegisterOverlayDebtReason.UNSUPPORTED_ALIAS, "register space is not unique")
    register_space = next(iter(register_spaces))
    selected = set()
    for span in selected_spans:
        if (type(span.byte_offset) is not int or type(span.byte_size) is not int
                or span.byte_offset < 0 or span.byte_size < 1):
            _debt(RegisterOverlayDebtReason.INVALID_INPUT, "invalid register slice")
        if span.byte_size > max_register_bytes:
            _debt(RegisterOverlayDebtReason.RESOURCE_BOUND, "selected width limit")
        piece = set(range(span.byte_offset, span.byte_offset + span.byte_size))
        if not piece.issubset(register_bytes) or selected.intersection(piece):
            _debt(RegisterOverlayDebtReason.UNSUPPORTED_ALIAS, "unobserved or overlapping selected spans")
        selected.update(piece)

    scope = scopes.function.scope.digest
    local_edges = {}
    all_edge_keys = set()
    for edge in verified_edges.edges:
        edge.__post_init__()
        edge_key = (edge.caller_scope_digest, edge.call_operation_key)
        if edge_key in all_edge_keys:
            _debt(RegisterOverlayDebtReason.EVIDENCE_MISMATCH, "duplicate direct edge")
        all_edge_keys.add(edge_key)
        if edge.caller_scope_digest == scope:
            local_edges[edge.call_operation_key] = edge
    seeds = {row.operation_key: row for row in evidence.seeds.callsites}
    raw_calls, self_calls, successors = set(), set(), {}
    for address, instruction in sorted(instructions.items()):
        flow = instruction.flow
        if flow is None or flow.is_override or flow.is_computed:
            _debt(RegisterOverlayDebtReason.UNSUPPORTED_CFG, "missing or overridden/computed flow")
        control = []
        for ordinal, operation in enumerate(instruction.operations):
            key = _operation_key(address, ordinal, operation.opcode)
            opcode, count = operation.opcode, len(operation.inputs)
            if opcode in _UNARY | _BINARY:
                if count != (1 if opcode in _UNARY else 2) or operation.output is None:
                    _debt(RegisterOverlayDebtReason.UNSUPPORTED_OPERATION, key)
            elif opcode in {"LOAD", "STORE"}:
                if (count != (2 if opcode == "LOAD" else 3)
                        or (operation.output is not None) != (opcode == "LOAD")
                        or operation.inputs[0].kind is not VarnodeKindCode.CONSTANT):
                    _debt(RegisterOverlayDebtReason.UNSUPPORTED_OPERATION, key)
            elif opcode in {"CALL", "BRANCH", "CBRANCH", "RETURN"}:
                control.append((ordinal, operation))
                if operation.output is not None or count != (2 if opcode == "CBRANCH" else 1):
                    _debt(RegisterOverlayDebtReason.UNSUPPORTED_OPERATION, key)
                if opcode != "RETURN" and operation.inputs[0].kind is not VarnodeKindCode.ADDRESS:
                    _debt(RegisterOverlayDebtReason.UNSUPPORTED_CFG, "non-address control selector")
                if opcode == "CALL":
                    raw_calls.add(key)
                    seed, edge = seeds.get(key), local_edges.get(key)
                    target = operation.inputs[0].coordinate
                    if (seed is None or edge is None or type(seed.target) is not DirectCallTarget
                            or seed.target.coordinate != target or seed.inputs != operation.inputs
                            or seed.locator.instruction != address
                            or seed.locator.operation_ordinal != ordinal
                            or seed.locator.function_scope != scopes.function.scope
                            or seed.instruction_context.fallthrough != instruction.fallthrough
                            or (edge.callee_scope_digest == scope) != (target == analysis.entry)):
                        _debt(RegisterOverlayDebtReason.EVIDENCE_MISMATCH, f"direct edge mismatch: {key}")
                    if target == analysis.entry:
                        self_calls.add(key)
            else:
                _debt(RegisterOverlayDebtReason.UNSUPPORTED_OPERATION, key)
        if len(control) > 1 or control and control[0][0] != len(instruction.operations) - 1:
            _debt(RegisterOverlayDebtReason.UNSUPPORTED_CFG, "control operation is not sole final transfer")
        opcode = control[0][1].opcode if control else None
        target = control[0][1].inputs[0].coordinate if control else None
        if opcode == "CALL":
            if not flow.is_call or not flow.has_fallthrough or instruction.fallthrough is None or any(
                    item != target for item in instruction.flow_targets):
                _debt(RegisterOverlayDebtReason.UNSUPPORTED_CFG, "call continuation or exceptional edge")
            next_rows = (instruction.fallthrough,)
        elif opcode in {"BRANCH", "CBRANCH"}:
            if (not flow.is_jump or flow.is_conditional != (opcode == "CBRANCH")
                    or flow.has_fallthrough != (opcode == "CBRANCH")
                    or set(instruction.flow_targets) != {target}
                    or (instruction.fallthrough is not None) != (opcode == "CBRANCH")):
                _debt(RegisterOverlayDebtReason.UNSUPPORTED_CFG, "branch target/fallthrough mismatch")
            next_rows = (target,) + ((instruction.fallthrough,) if opcode == "CBRANCH" else ())
        elif opcode == "RETURN":
            if not flow.is_terminal or instruction.fallthrough is not None or instruction.flow_targets:
                _debt(RegisterOverlayDebtReason.UNSUPPORTED_CFG, "terminal has other successors")
            next_rows = ()
        else:
            if instruction.flow_targets or flow.is_call or flow.is_jump:
                _debt(RegisterOverlayDebtReason.UNSUPPORTED_CFG, "unrepresented control effect")
            next_rows = () if instruction.fallthrough is None else (instruction.fallthrough,)
        if any(row not in instructions for row in next_rows):
            _debt(RegisterOverlayDebtReason.UNSUPPORTED_CFG, "successor missing from observation")
        successors[address] = tuple(sorted(set(next_rows)))
    if raw_calls != set(local_edges) or raw_calls != set(seeds) or not self_calls:
        _debt(RegisterOverlayDebtReason.EVIDENCE_MISMATCH, "exact call inventory or self call absent")

    # Separate acyclic path states preserve correlations at joins. There is no
    # union-of-byte-definitions shortcut or implicit path-feasibility claim.
    pending, paths, steps = [(analysis.entry, ())], [], 0
    while pending:
        address, prefix = pending.pop()
        steps += len(prefix) + 1
        if steps > max_steps:
            _debt(RegisterOverlayDebtReason.RESOURCE_BOUND, "CFG path traversal limit")
        if address in prefix:
            _debt(RegisterOverlayDebtReason.UNSUPPORTED_CFG, "intraprocedural cycle")
        path = prefix + (address,)
        if successors[address]:
            pending.extend((target, path) for target in reversed(successors[address]))
        else:
            paths.append(path)
        if len(pending) + len(paths) > max_paths:
            _debt(RegisterOverlayDebtReason.RESOURCE_BOUND, "CFG alternative limit")

    definitions, reads, outputs, limitations = [], [], [], []
    operand_count = 0

    def define(path_id, kind, key, space, offset, inputs=()):
        nonlocal operand_count
        operand_count += len(inputs)
        if operand_count > max_operand_bytes:
            _debt(RegisterOverlayDebtReason.RESOURCE_BOUND, "operand-reference limit")
        if len(definitions) >= max_definitions:
            _debt(RegisterOverlayDebtReason.RESOURCE_BOUND, "definition limit")
        node = len(definitions)
        definitions.append(OverlayByteDefinition(node, path_id, kind, key, space, offset, inputs))
        return node

    for path_id, path in enumerate(sorted(paths)):
        state = {offset: define(path_id, RegisterDefinitionKind.ENTRY, "", register_space, offset)
                 for offset in sorted(register_bytes)}
        if len(paths) > 1:
            limitations.append(OverlayLimitation(path_id, "", "cfg_path_feasibility_unproved"))
        for address in path:
            unique = {}
            instruction = instructions[address]
            for ordinal, operation in enumerate(instruction.operations):
                steps += 1
                if steps > max_steps:
                    _debt(RegisterOverlayDebtReason.RESOURCE_BOUND, "interpreted operation limit")
                key, opcode = _operation_key(address, ordinal, operation.opcode), operation.opcode
                input_ids = []
                for index, value in enumerate(operation.inputs):
                    if index == 0 and opcode in {"CALL", "BRANCH", "CBRANCH", "LOAD", "STORE"}:
                        continue
                    operand_count += value.byte_size
                    if operand_count > max_operand_bytes:
                        _debt(RegisterOverlayDebtReason.RESOURCE_BOUND, "interpreted operand byte limit")
                    start, size = value.coordinate.byte_offset, value.byte_size
                    role = ("control" if opcode in {"CBRANCH", "RETURN"}
                            else "address" if opcode in {"LOAD", "STORE"} and index == 1 else "data")
                    if value.kind is VarnodeKindCode.REGISTER:
                        ids = tuple(state[offset] for offset in range(start, start + size))
                        reads.append(OverlayRegisterRead(path_id, key, index, role,
                                                        PhysicalRegisterSlice(start, size), ids))
                    elif value.kind is VarnodeKindCode.UNIQUE:
                        try:
                            ids = tuple(unique[(value.coordinate.space_id, offset)]
                                        for offset in range(start, start + size))
                        except KeyError:
                            _debt(RegisterOverlayDebtReason.MISSING_DEFINITION, f"unique byte: {key}")
                    elif value.kind is VarnodeKindCode.CONSTANT:
                        ids = ()
                    elif value.kind is VarnodeKindCode.ADDRESS:
                        limitations.append(OverlayLimitation(path_id, key, "opaque_memory_read"))
                        ids = tuple(define(path_id, RegisterDefinitionKind.MEMORY_READ, key,
                                           value.coordinate.space_id, offset)
                                    for offset in range(start, start + size))
                    else:
                        _debt(RegisterOverlayDebtReason.UNSUPPORTED_ALIAS, f"varnode kind: {key}")
                    input_ids.extend(ids)
                if opcode == "CALL":
                    limitations.append(OverlayLimitation(path_id, key, "normal_return_and_transport_unproved"))
                    for offset in sorted(state):
                        kind = (RegisterDefinitionKind.CALL_BOUNDARY
                                if key in self_calls and offset in selected
                                else RegisterDefinitionKind.UNMODELED_CALL)
                        state[offset] = define(path_id, kind, key, register_space, offset)
                    limitations.append(OverlayLimitation(path_id, key, "unselected_register_state_unmodeled"))
                elif operation.output is not None:
                    value = operation.output
                    if opcode == "LOAD":
                        limitations.append(OverlayLimitation(path_id, key, "opaque_memory_read"))
                    if value.kind is VarnodeKindCode.ADDRESS:
                        limitations.append(OverlayLimitation(path_id, key, "memory_write_not_forwarded"))
                        continue
                    if value.kind not in {VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE}:
                        _debt(RegisterOverlayDebtReason.UNSUPPORTED_ALIAS, f"output kind: {key}")
                    operand_ids = tuple(dict.fromkeys(input_ids))
                    for offset in range(value.coordinate.byte_offset,
                                        value.coordinate.byte_offset + value.byte_size):
                        node = define(path_id, RegisterDefinitionKind.MEMORY_READ if opcode == "LOAD"
                                      else RegisterDefinitionKind.RAW_WRITE, key,
                                      value.coordinate.space_id, offset, operand_ids)
                        if value.kind is VarnodeKindCode.REGISTER:
                            state[offset] = node
                        else:
                            unique[(value.coordinate.space_id, offset)] = node
                elif opcode == "STORE":
                    limitations.append(OverlayLimitation(path_id, key, "memory_write_not_forwarded"))
        outputs.append(OverlayPath(path_id, path, tuple(sorted(state.items()))))
    return CallRegisterOverlay(
        scopes.program.scope.digest, scope, scopes.function.observation_digest,
        normalized.memory_ssa.unit_digest, profile_label, register_space,
        tuple(sorted(selected_spans, key=lambda row: (row.byte_offset, row.byte_size))),
        tuple(definitions), tuple(reads), tuple(outputs), tuple(limitations),
    )


__all__ = (
    "SHARED_STATE_PROFILE", "CallRegisterOverlay", "OverlayByteDefinition",
    "OverlayRegisterRead", "OverlayPath", "OverlayLimitation",
    "RegisterDefinitionKind", "RegisterOverlayDebtReason", "RegisterOverlayIncomplete",
    "build_call_register_overlay",
)
