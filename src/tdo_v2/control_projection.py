"""Architect-owned projection of typed flow evidence into terminal cuts."""

from __future__ import annotations

from dataclasses import dataclass

from ._scope_contracts import AddressCoordinate
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


def control_successor_coordinates(
    instruction: ValidatedInstruction,
    *,
    local_addresses: set[AddressCoordinate] | None = None,
    function_entry: AddressCoordinate | None = None,
) -> tuple[AddressCoordinate, ...]:
    targets = set()
    if instruction.fallthrough is not None:
        targets.add(instruction.fallthrough)
    if not instruction.flow.is_call:
        targets.update(instruction.flow_targets)
    elif local_addresses is not None:
        targets.update(
            target
            for target in instruction.flow_targets
            if target in local_addresses and target != function_entry
        )
    return tuple(sorted(targets))


def _coordinate_key(value) -> str:
    return f"{value.space_id:x}:{value.byte_offset:x}"
__all__ = ("ObservedControlGraph", "control_successor_coordinates", "project_observed_control_graph",
           "project_observed_terminal_cuts")
