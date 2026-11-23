"""Architect-owned projection of typed flow evidence into terminal cuts."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass

from ._scope_contracts import CALL_GATE_EXCLUDING_OPCODES, AddressCoordinate, VarnodeKindCode
from ._scope_wire import _observation_digest
from .control_contracts import FunctionTerminalCuts, ObservedTerminalCut
from .graph import RustworkxDependencyGraph
from .graph_contracts import NodeKind
from .resource_limits import step
from .scope_identity import (
    ConstructedFunctionScope,
    ConstructedProgramScope,
    ScopeBundleResult,
    ValidatedFunctionObservation,
    ValidatedInstruction,
)


@dataclass(frozen=True, slots=True)
class ObservedControlGraph:
    """Lossless control observation of a refused function, not normalized SSA.

    ``cfg`` has every original instruction, including entry-unreachable
    islands. Outside successors remain numeric evidence, never invented local
    connectors. No method of this record issues a reachability/value proof.
    """

    observation_digest: bytes
    observation: ValidatedFunctionObservation
    cfg: RustworkxDependencyGraph
    entry_reachable: tuple[str, ...]
    unreachable: tuple[str, ...]
    weak_components: tuple[tuple[str, ...], ...]
    outside_observed_successors: tuple[tuple[AddressCoordinate, AddressCoordinate], ...]


def project_observed_control_graph(scopes, observation, cfg) -> ObservedControlGraph:
    """Annotate the existing instruction CFG without dropping any observation."""
    if type(scopes) is not ScopeBundleResult or type(scopes.function) is not ConstructedFunctionScope \
            or type(observation) is not ValidatedFunctionObservation \
            or type(cfg) is not RustworkxDependencyGraph or not cfg.is_frozen:
        raise TypeError("observed control graph requires exact constructed inputs and a frozen CFG")
    digest = _observation_digest(observation)
    if digest != scopes.function.observation_digest:
        raise ValueError("observed control graph does not match the function scope")
    known = {row.address for row in observation.instructions}
    nodes = {point: cfg.node_for_key(f"instruction:{_coordinate_key(point)}") for point in known}
    if None in nodes.values() or cfg.node_count != len(nodes):
        raise ValueError("observed control graph must retain exactly every instruction")
    labels = {node: _coordinate_key(point) for point, node in nodes.items()}
    outside = []
    for row in observation.instructions:
        step()
        targets = control_successor_coordinates(row, local_addresses=known, function_entry=scopes.function.entry)
        if set(cfg.successors(nodes[row.address])) != {nodes[target] for target in targets if target in known}:
            raise ValueError("observed control graph changed an original successor")
        outside.extend((row.address, target) for target in targets if target not in known)
    reached, pending = set(), [nodes[scopes.function.entry]] if scopes.function.entry in nodes else []
    while pending:
        step()
        node = pending.pop()
        if node not in reached:
            reached.add(node)
            pending.extend(cfg.successors(node))
    remaining, components = set(labels), []
    while remaining:
        part, pending = set(), [min(remaining)]
        while pending:
            step()
            node = pending.pop()
            if node not in part:
                part.add(node)
                pending.extend((set(cfg.successors(node)) | set(cfg.predecessors(node))) - part)
        remaining -= part
        components.append(tuple(sorted(labels[node] for node in part)))
    return ObservedControlGraph(
        digest, observation, cfg, tuple(sorted(labels[node] for node in reached)),
        tuple(sorted(labels[node] for node in set(labels) - reached)), tuple(sorted(components)),
        tuple(sorted(set(outside))),
    )


def project_observed_terminal_cuts(
    scopes: ScopeBundleResult,
    observation: ValidatedFunctionObservation,
    cfg: RustworkxDependencyGraph,
    /,
) -> FunctionTerminalCuts:
    if type(scopes) is not ScopeBundleResult:
        raise TypeError("terminal-cut projection requires an exact scope bundle")
    if type(observation) is not ValidatedFunctionObservation:
        raise TypeError("terminal-cut projection requires an exact observation")
    if type(cfg) is not RustworkxDependencyGraph or not cfg.is_frozen:
        raise TypeError("terminal-cut projection requires an exact frozen CFG")
    function = scopes.function
    program = scopes.program
    if type(function) is not ConstructedFunctionScope or type(program) is not ConstructedProgramScope:
        raise TypeError("terminal-cut projection requires constructed scopes")
    if _observation_digest(observation) != function.observation_digest:
        raise ValueError("terminal-cut observation does not match the function scope")

    known = {instruction.address for instruction in observation.instructions}
    sites: list[ObservedTerminalCut] = []
    for instruction in observation.instructions:
        node = cfg.node_for_key(f"instruction:{_coordinate_key(instruction.address)}")
        if node is None:
            raise ValueError("terminal-cut projection found a missing CFG instruction")
        record = cfg.node(node)
        if record.kind is not NodeKind.INSTRUCTION:
            raise ValueError("terminal-cut CFG node has the wrong exact kind")
        expected = {
            cfg.node_for_key(f"instruction:{_coordinate_key(target)}")
            for target in control_successor_coordinates(
                instruction,
                local_addresses=known,
                function_entry=function.entry,
            )
            if target in known
        }
        if None in expected or cfg.successors(node) != tuple(sorted(expected)):
            raise ValueError("typed flow evidence and normalized CFG disagree")
        if not expected:
            sites.append(
                ObservedTerminalCut(
                    instruction.address,
                    _coordinate_key(instruction.address),
                    instruction.fallthrough,
                    instruction.flow_targets,
                    instruction.flow,
                )
            )
    return FunctionTerminalCuts(
        program.scope,
        function.scope,
        function.observation_digest,
        tuple(sorted(sites, key=lambda site: site.canonical_key)),
    )


def call_like_instruction(instruction: ValidatedInstruction) -> bool:
    """A user operation may transfer control too; it never proves a callee."""
    return any(op.opcode in ("CALL", "CALLIND", "CALLOTHER") for op in instruction.operations)


def unlisted_local_branch_target(instruction, local_addresses):
    """One definite inter-instruction branch destination absent from exported flow.

    A self re-entry belongs to the split p-code graph (e.g. REP). It does
    not remove the exporter's terminal observation at this instruction.
    """
    if not instruction.operations or instruction.flow.is_override:
        return None   # (Astra r7: an override row goes where the override says, not the raw operand)
    branch = instruction.operations[-1]
    if branch.opcode not in ("BRANCH", "CBRANCH") or not branch.inputs:
        return None
    operand = branch.inputs[0]
    target = operand.coordinate
    if (operand.kind is not VarnodeKindCode.ADDRESS or target == instruction.address
            or target == instruction.fallthrough or target in instruction.flow_targets or target not in local_addresses):
        return None
    if any(op.opcode in ("BRANCH", "CBRANCH", "BRANCHIND", "RETURN") for op in instruction.operations[:-1]):
        return None
    return target


def _row_selector(instruction, index) -> int | None:
    """The value of operation ``index``'s (CALLIND) selector when the row proves
    it: a constant operand, or the operand's instruction-local producer
    (``final_target_index``: no internal flow, overlap-based last writer, no
    call-like operation in between) is a COPY of a constant to exactly that
    varnode. None: not proven by the row. (A constant is compared with the
    listed targets' byte offsets; a mismatch only keeps a listed target as a
    successor -- an extra exit, never a dropped one.)"""
    from .pcode_blocks import final_target_index   # (pcode_blocks imports this module)

    operations = instruction.operations
    selector = operations[index].inputs[0]
    if selector.kind is VarnodeKindCode.CONSTANT:
        return selector.coordinate.byte_offset
    producer = final_target_index(instruction, index)
    if producer is None:
        return None
    op = operations[producer]
    if (op.opcode == "COPY" and op.output == selector and len(op.inputs) == 1
            and op.inputs[0].kind is VarnodeKindCode.CONSTANT):
        return op.inputs[0].coordinate.byte_offset
    return None


def call_explains(instruction, index, target, function_entry=None) -> bool:
    """(G3b-7 r3/r4) May the CALL / CALLIND at ``index`` be the transfer that
    reaches the listed ``target``? One predicate for the successor function
    and ``control_exits``. On a flow override row the listing follows the
    overridden semantics, not the raw p-code: nothing is explained (Astra r3
    P1: a direct CALL too). An operand-less call explains nothing. A direct
    CALL explains its address operand. A CALLIND explains exactly a row-proven
    selector (in the row's own code space); an unproven selector explains any
    listed target -- the caller's gate leaves no other transfer -- except the
    function's entry, which the exporter may have merged as a landing pad
    (Astra r3 P2): that evidence stays a successor."""
    operation = instruction.operations[index]
    if len(operation.inputs) != 1 or instruction.flow.is_override:
        return False
    pads = getattr(instruction, "exception_targets", None)   # (test doubles carry rows only)
    if function_entry is not None and target == function_entry and (pads is None or target in pads):
        # (r6; Astra r4 P2 / r5 Q2) the exporter merges landing pads into the
        # listing: the entry may be a pad as well as a recursive callee, and
        # the merged listing cannot tell -- the edge stays (conservative).
        # (G3b-7b) a row whose pad set the exporter proved (no static
        # exception handler: ``()``) decides by the ordinary rule below.
        return False
    if operation.opcode == "CALL":
        return operation.inputs[0].kind is VarnodeKindCode.ADDRESS and operation.inputs[0].coordinate == target
    if operation.opcode != "CALLIND":
        return False
    value = _row_selector(instruction, index)
    if value is None:
        return True
    return target.byte_offset == value and target.space_id == instruction.address.space_id


def call_explained_targets(instruction, function_entry=None) -> frozenset:
    """The listed targets a call of the row explains (the row gate: no BRANCH /
    BRANCHIND / RETURN / CALLOTHER anywhere; never an address a BRANCH /
    CBRANCH of the row names). Shared by the successor function and the split
    placement check (G3b-7b)."""
    targets = instruction.flow_targets
    operations = instruction.operations
    if not targets or not call_like_instruction(instruction) or any(
            op.opcode in CALL_GATE_EXCLUDING_OPCODES for op in operations):
        return frozenset()
    explained = {target for index, op in enumerate(operations) if op.opcode in ("CALL", "CALLIND")
                 for target in targets if call_explains(instruction, index, target, function_entry)}
    explained -= {op.inputs[0].coordinate for op in operations
                  if op.opcode in ("BRANCH", "CBRANCH") and op.inputs
                  and op.inputs[0].kind is VarnodeKindCode.ADDRESS}
    return frozenset(explained)


def control_successor_coordinates(
    instruction: ValidatedInstruction,
    *,
    local_addresses: Collection[AddressCoordinate] | None = None,
    function_entry: AddressCoordinate | None = None,
) -> tuple[AddressCoordinate, ...]:
    """Separate listed call targets from instruction-level control successors.

    A direct CALL explains its own destination. A CALLIND explains the one
    address its row proves for the selector (``_row_selector``), else any
    listed target (a callee candidate: the row has no other transfer).
    Local non-entry targets remain possible landing pads. In a row holding a
    BRANCH / BRANCHIND / RETURN / CALLOTHER we cannot assign an observed
    target exclusively to a call (an unconditional or opaque transfer can
    make the call unreachable). A CBRANCH never does -- its fallthrough
    reaches the call -- but an address a BRANCH / CBRANCH of the row names is
    never explained by a call: the branch may leave there without calling
    (G3b-7 r2, R7-2 / R7-3). Kept successors include a branch to entry.
    """
    targets = set(instruction.flow_targets)
    explained = call_explained_targets(instruction, function_entry)
    if explained:
        targets = {target for target in targets
                   if (local_addresses is not None and target in local_addresses and target != function_entry)
                   or target not in explained}
    # An absolute local target of an unsplit branch is control evidence in its
    # own right. Split instructions must first establish which branches run.
    if local_addresses is not None:
        inferred = unlisted_local_branch_target(instruction, local_addresses)
        if inferred is not None:
            targets.add(inferred)
    if instruction.fallthrough is not None:
        targets.add(instruction.fallthrough)
    return tuple(sorted(targets))


def _coordinate_key(value) -> str:
    return f"{value.space_id:x}:{value.byte_offset:x}"
__all__ = ("ObservedControlGraph", "call_explains", "call_like_instruction", "control_successor_coordinates", "project_observed_control_graph",
           "project_observed_terminal_cuts")
