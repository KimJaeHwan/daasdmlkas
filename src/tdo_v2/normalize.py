"""Normalize one function without assigning ABI roles."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .call_effect_contracts import (
    FunctionCallEffectEvidence,
    RawCallPortRole,
    RawObservedCallPort,
    unavailable_call_effect_evidence,
)
from .call_contracts import FunctionCallSeedUnit
from .call_observation_contracts import (
    BoundLocalMemorySsa,
    FunctionCallObservations,
    PreSsaCallPortLayout,
    bind_call_observations,
    build_bound_local_memory_ssa,
    build_pre_ssa_call_port_layout,
)
from .call_seeds import (
    _operation_key as _numeric_operation_key,
    seed_function_calls,
)
from .configured_call_augmentation import augment_configured_call_effects_v4
from .configured_effect_contracts import ConfiguredFunctionCallEffectEvidenceV4
from .effect_decode import decode_effect_unit
from .control_contracts import FunctionTerminalCuts
from .control_projection import (
    control_successor_coordinates,
    project_observed_terminal_cuts,
)
from .effects import (
    EFFECT_DECODE_CONTRACT_VERSION,
    EffectKind,
    ObservedEffect,
    ObservedEffectBlock,
    ObservedEffectUnit,
    UnresolvedMemoryAccess,
)
from .graph import RustworkxDependencyGraph
from .graph_contracts import EdgeRecord, NodeId, NodeKind, NodeRecord
from .memory_contracts import (
    LocalMemorySsaResult,
    LocalMemoryUnit,
    MemoryDefinitionKind,
)
from .memory_graph import (
    MemoryGraphBindings,
    _materialize_local_memory_ssa,
    _validate_materialized_local_memory_ssa,
)
from .model import (
    FunctionDocument,
    NonStorage,
    ResolvedStorage,
    StorageRef,
    UnresolvedStorage,
    VarnodeKind,
)
from .scope_identity import (
    AddressCoordinate,
    ConstructedFunctionScope,
    ScopeBundleResult,
    ScopedFunctionUnit,
    ValidatedFunctionObservation,
    ValidatedInstruction,
    ValidatedOperation,
    ValidatedVarnode,
    VarnodeKindCode,
)
from .relative_memory import project_function_relative_memory
from .observed_call_state import project_persistent_call_state
from .opaque_values import OpaqueValueEvidenceProvider
from .storage import _resolve_validated_storage


@dataclass(frozen=True, slots=True)
class NormalizedFunction:
    document: FunctionDocument | None
    scopes: ScopeBundleResult | None
    cfg: RustworkxDependencyGraph
    dependencies: RustworkxDependencyGraph
    effects: tuple[ObservedEffect, ...]
    observed_inputs: tuple[object, ...]
    value_nodes: tuple[tuple[str, NodeId], ...]
    memory_ssa: LocalMemorySsaResult | None = None
    memory_graph: MemoryGraphBindings | None = None
    terminal_cuts: FunctionTerminalCuts | None = None
    call_seeds: FunctionCallSeedUnit | None = None
    call_effects: FunctionCallEffectEvidence | None = None
    configured_call_effects: ConfiguredFunctionCallEffectEvidenceV4 | None = None
    memory_unit: LocalMemoryUnit | None = None
    call_port_layout: PreSsaCallPortLayout | None = None
    call_observations: FunctionCallObservations | None = None
    configured_memory_binding: BoundLocalMemorySsa | None = None

    def __post_init__(self) -> None:
        if type(self.cfg) is not RustworkxDependencyGraph or type(
            self.dependencies
        ) is not RustworkxDependencyGraph:
            raise TypeError("normalized graphs must use the exact Rustworkx backend")
        if not self.cfg.is_frozen or not self.dependencies.is_frozen:
            raise ValueError("normalized graphs must be frozen")
        if (
            self.memory_ssa is not None
            and type(self.memory_ssa) is not LocalMemorySsaResult
        ):
            raise TypeError("memory SSA must be an exact LocalMemorySsaResult")
        if (
            self.memory_graph is not None
            and type(self.memory_graph) is not MemoryGraphBindings
        ):
            raise TypeError("memory graph must be exact MemoryGraphBindings")
        if (self.memory_ssa is None) != (self.memory_graph is None):
            raise ValueError("memory SSA and graph bindings must be present together")
        if type(self.scopes) is ScopeBundleResult and self.terminal_cuts is None:
            raise ValueError("scoped normalization requires exact terminal-cut evidence")
        if self.terminal_cuts is not None and type(self.terminal_cuts) is not FunctionTerminalCuts:
            raise TypeError("terminal cuts must be exact FunctionTerminalCuts or None")
        if self.terminal_cuts is not None:
            if (
                type(self.scopes) is not ScopeBundleResult
                or type(self.scopes.function) is not ConstructedFunctionScope
            ):
                raise TypeError("terminal cuts require exact constructed scopes")
            if self.terminal_cuts.function_scope != self.scopes.function.scope:
                raise ValueError("terminal cuts belong to a different normalized function")
            if self.terminal_cuts.program_scope != self.scopes.program.scope:
                raise ValueError("terminal cuts belong to a different normalized program")
            if self.terminal_cuts.observation_digest != self.scopes.function.observation_digest:
                raise ValueError("terminal cuts use different observation evidence")
            cfg_terminal_keys = tuple(
                sorted(
                    self.cfg.node(node).label
                    for node in range(self.cfg.node_count)
                    if self.cfg.node(node).kind is NodeKind.INSTRUCTION
                    and not self.cfg.successors(node)
                )
            )
            if self.terminal_cuts.block_keys != cfg_terminal_keys:
                raise ValueError("terminal cuts must exactly cover CFG terminal nodes")
            for site in self.terminal_cuts.sites:
                coordinate_key = (
                    f"{site.instruction_address.space_id:x}:"
                    f"{site.instruction_address.byte_offset:x}"
                )
                node = self.cfg.node_for_key(f"instruction:{coordinate_key}")
                if (
                    site.block_key != coordinate_key
                    or node is None
                    or self.cfg.node(node).kind is not NodeKind.INSTRUCTION
                    or self.cfg.node(node).label != coordinate_key
                    or self.cfg.successors(node)
                ):
                    raise ValueError("terminal-cut sites must map to exact CFG terminal nodes")
            if self.memory_ssa is not None and tuple(
                state.block_key for state in self.memory_ssa.observed_terminal_states
            ) != self.terminal_cuts.block_keys:
                raise ValueError("memory terminal states must align with terminal cuts")
        configured = self.configured_call_effects
        if configured is not None and type(
            configured
        ) is not ConfiguredFunctionCallEffectEvidenceV4:
            raise TypeError("configured call effects must be exact V4 evidence or None")
        legacy_call_artifacts = (
            self.call_effects,
            self.call_port_layout,
            self.call_observations,
        )
        if configured is None:
            if self.configured_memory_binding is not None:
                raise ValueError(
                    "neutral normalization cannot retain a configured SSA receipt"
                )
            call_artifacts = (
                self.call_seeds,
                *legacy_call_artifacts,
                self.memory_unit,
            )
            if any(item is not None for item in call_artifacts) and any(
                item is None for item in call_artifacts
            ):
                raise ValueError("call normalization artifacts must be present together")
            if type(self.scopes) is ScopeBundleResult and not all(
                item is not None for item in call_artifacts
            ):
                raise ValueError("scoped normalization requires exact call artifacts")
        else:
            if (
                self.call_seeds is None
                or self.memory_unit is None
                or type(self.configured_memory_binding) is not BoundLocalMemorySsa
            ):
                raise ValueError(
                    "configured normalization requires call seeds, memory, and an SSA receipt"
                )
            self.configured_memory_binding._validate()
            if (
                self.configured_memory_binding.unit is not self.memory_unit
                or self.configured_memory_binding.result is not self.memory_ssa
            ):
                raise ValueError(
                    "configured normalization must retain its exact SSA construction"
                )
            if any(item is not None for item in legacy_call_artifacts):
                raise ValueError(
                    "configured V4 normalization cannot retain legacy call bindings"
                )
        if self.call_seeds is not None:
            if type(self.call_seeds) is not FunctionCallSeedUnit:
                raise TypeError("call seeds must be an exact FunctionCallSeedUnit")
            if type(self.memory_unit) is not LocalMemoryUnit:
                raise TypeError("memory unit must be an exact LocalMemoryUnit")
            if type(self.scopes) is not ScopeBundleResult or type(
                self.scopes.function
            ) is not ConstructedFunctionScope:
                raise TypeError("call artifacts require exact constructed scopes")
            if (
                self.call_seeds.program_scope != self.scopes.program.scope
                or self.call_seeds.function_scope != self.scopes.function.scope
                or self.call_seeds.function_entry != self.scopes.function.entry
                or self.call_seeds.observation_digest
                != self.scopes.function.observation_digest
            ):
                raise ValueError("call seeds belong to different scoped evidence")
            assert self.memory_unit is not None
            expected_effect_digest = (
                configured.canonical_digest
                if configured is not None
                else self.call_effects.effect_evidence_digest
            )
            if self.memory_unit.function_scope != self.call_seeds.function_scope or (
                self.memory_unit.effect_evidence_digest != expected_effect_digest
            ):
                raise ValueError("memory unit belongs to different call evidence")
            if self.memory_ssa is None or self.memory_ssa.unit_digest != self.memory_unit.canonical_digest:
                raise ValueError("memory SSA belongs to a different pre-SSA unit")
            if configured is not None:
                configured._validate()
                if configured.seeds is not self.call_seeds:
                    raise ValueError(
                        "configured call effects must retain the exact seed unit"
                    )
            else:
                assert type(self.call_effects) is FunctionCallEffectEvidence
                assert type(self.call_port_layout) is PreSsaCallPortLayout
                assert type(self.call_observations) is FunctionCallObservations
                if self.call_effects.seeds is not self.call_seeds:
                    raise ValueError("call effects must retain the exact seed unit")
                if (
                    self.call_port_layout.seeds is not self.call_seeds
                    or self.call_port_layout.effects is not self.call_effects
                    or self.call_port_layout.memory_unit is not self.memory_unit
                ):
                    raise ValueError("call layout must retain exact upstream artifacts")
                if (
                    self.call_observations.seeds is not self.call_seeds
                    or self.call_observations.effects is not self.call_effects
                    or self.call_observations.layout is not self.call_port_layout
                    or self.call_observations.memory_binding.unit is not self.memory_unit
                    or self.call_observations.memory is not self.memory_ssa
                ):
                    raise ValueError("call observations must retain the exact artifact chain")
        if type(self.memory_ssa) is LocalMemorySsaResult:
            assert type(self.memory_graph) is MemoryGraphBindings
            if (
                self.memory_graph.contract_version != self.memory_ssa.contract_version
                or self.memory_graph.function_scope != self.memory_ssa.function_scope
                or self.memory_graph.unit_digest != self.memory_ssa.unit_digest
            ):
                raise ValueError("memory graph bindings belong to a different SSA result")
            if len(self.memory_graph.definition_nodes) != len(
                self.memory_ssa.definitions
            ) or len(self.memory_graph.action_nodes) != len(self.memory_ssa.actions):
                raise ValueError("memory graph bindings must align with SSA result IDs")
            if len(self.memory_graph.unresolved_read_nodes) != len(
                self.memory_ssa.unresolved_reads
            ) or len(self.memory_graph.unresolved_write_nodes) != len(
                self.memory_ssa.unresolved_writes
            ):
                raise ValueError("memory debt nodes must align with SSA occurrences")
            if self.observed_inputs != tuple(
                storage for _, storage in self.memory_graph.entry_bindings
            ):
                raise ValueError("observed inputs must align with ENTRY graph bindings")
            all_memory_nodes = (
                *self.memory_graph.definition_nodes,
                *self.memory_graph.action_nodes,
                *self.memory_graph.unresolved_read_nodes,
                *self.memory_graph.unresolved_write_nodes,
            )
            if len(set(all_memory_nodes)) != len(all_memory_nodes):
                raise ValueError("memory graph binding node IDs must be unique")
            namespace = (
                f"memory-v{self.memory_ssa.contract_version}:"
                f"{self.memory_ssa.function_scope.digest.hex()}:"
                f"{self.memory_ssa.unit_digest.hex()}"
            )
            for definition_id, definition in enumerate(self.memory_ssa.definitions):
                node = self.memory_graph.definition_nodes[definition_id]
                expected_kind = NodeKind.MEMORY_DEFINITION
                if definition.kind is MemoryDefinitionKind.ENTRY:
                    expected_kind = NodeKind.OBSERVED_INPUT
                elif definition.kind is MemoryDefinitionKind.JOIN:
                    expected_kind = NodeKind.MEMORY_JOIN
                if (
                    not self.dependencies.has_node(node)
                    or self.dependencies.node(node).kind is not expected_kind
                    or self.dependencies.node(node).key
                    != f"memory:{namespace}:definition:{definition_id}"
                ):
                    raise ValueError("definition binding does not match the SSA definition")
            for action, node in zip(
                self.memory_ssa.actions,
                self.memory_graph.action_nodes,
                strict=True,
            ):
                if (
                    not self.dependencies.has_node(node)
                    or self.dependencies.node(node).kind is not NodeKind.OPERATION
                    or self.dependencies.node(node).key != f"op:{action.operation_key}"
                ):
                    raise ValueError("action binding does not match the SSA action")
            for direction, occurrences, nodes in (
                (
                    "read",
                    self.memory_ssa.unresolved_reads,
                    self.memory_graph.unresolved_read_nodes,
                ),
                (
                    "write",
                    self.memory_ssa.unresolved_writes,
                    self.memory_graph.unresolved_write_nodes,
                ),
            ):
                for occurrence, node in zip(occurrences, nodes, strict=True):
                    expected_key = (
                        f"memory:{namespace}:unresolved:{direction}:"
                        f"{occurrence.action_id}:{occurrence.occurrence_ordinal}"
                    )
                    if (
                        not self.dependencies.has_node(node)
                        or self.dependencies.node(node).kind is not NodeKind.MEMORY_DEBT
                        or self.dependencies.node(node).key != expected_key
                    ):
                        raise ValueError(
                            "memory debt binding does not match the SSA occurrence"
                        )
            expected_entries = tuple(
                (
                    self.memory_graph.definition_nodes[definition_id],
                    ResolvedStorage(definition.span),
                )
                for definition_id, definition in enumerate(self.memory_ssa.definitions)
                if definition.kind is MemoryDefinitionKind.ENTRY
            )
            if self.memory_graph.entry_bindings != expected_entries:
                raise ValueError("ENTRY bindings must align with ENTRY definitions")
            _validate_materialized_local_memory_ssa(
                self.dependencies,
                self.memory_ssa,
                self.memory_graph,
            )

    def value_node(self, operation_key: str) -> NodeId | None:
        return dict(self.value_nodes).get(operation_key)


class NormalizationFailureReason(StrEnum):
    MISSING_VALIDATED_OBSERVATION = "missing_validated_observation"
    MISSING_CONSTRUCTED_FUNCTION_SCOPE = "missing_constructed_function_scope"
    ENTRY_NOT_IN_OBSERVATION = "entry_not_in_observation"
    DISCONNECTED_OBSERVED_CFG = "disconnected_observed_cfg"


@dataclass(frozen=True, slots=True)
class UnresolvedNormalizedFunction:
    scopes: ScopeBundleResult
    reason: NormalizationFailureReason

    def __post_init__(self) -> None:
        if type(self.scopes) is not ScopeBundleResult:
            raise TypeError("unresolved normalization must retain an exact scope bundle")
        if type(self.reason) is not NormalizationFailureReason:
            raise TypeError("normalization failure reason must be exact")


class FunctionNormalizer:
    def normalize(
        self,
        value: ScopedFunctionUnit,
        *,
        opaque_value_provider: OpaqueValueEvidenceProvider | None = None,
    ) -> NormalizedFunction | UnresolvedNormalizedFunction:
        if type(value) is not ScopedFunctionUnit:
            raise TypeError("normalization requires an exact ScopedFunctionUnit")
        if value.observation is None:
            return UnresolvedNormalizedFunction(
                value.scopes,
                NormalizationFailureReason.MISSING_VALIDATED_OBSERVATION,
            )
        function = value.scopes.function
        if type(function) is not ConstructedFunctionScope:
            return UnresolvedNormalizedFunction(
                value.scopes,
                NormalizationFailureReason.MISSING_CONSTRUCTED_FUNCTION_SCOPE,
            )
        admission_failure = _cfg_admission_failure(value.observation, function)
        if admission_failure is not None:
            return UnresolvedNormalizedFunction(value.scopes, admission_failure)
        return _ScopedNormalizer().normalize(
            value,
            opaque_value_provider=opaque_value_provider,
        )

    def normalize_configured(
        self,
        value: ScopedFunctionUnit,
        effects: ConfiguredFunctionCallEffectEvidenceV4,
        *,
        opaque_value_provider: OpaqueValueEvidenceProvider | None = None,
    ) -> NormalizedFunction | UnresolvedNormalizedFunction:
        if type(value) is not ScopedFunctionUnit:
            raise TypeError("configured normalization requires an exact ScopedFunctionUnit")
        if type(effects) is not ConfiguredFunctionCallEffectEvidenceV4:
            raise TypeError("configured normalization requires exact V4 call effects")
        effects._validate()
        if value.observation is None:
            return UnresolvedNormalizedFunction(
                value.scopes,
                NormalizationFailureReason.MISSING_VALIDATED_OBSERVATION,
            )
        function = value.scopes.function
        if type(function) is not ConstructedFunctionScope:
            return UnresolvedNormalizedFunction(
                value.scopes,
                NormalizationFailureReason.MISSING_CONSTRUCTED_FUNCTION_SCOPE,
            )
        admission_failure = _cfg_admission_failure(value.observation, function)
        if admission_failure is not None:
            return UnresolvedNormalizedFunction(value.scopes, admission_failure)
        return _ScopedNormalizer().normalize(
            value,
            effects,
            opaque_value_provider=opaque_value_provider,
        )


class _ScopedNormalizer:
    def normalize(
        self,
        unit: ScopedFunctionUnit,
        configured_call_effects: ConfiguredFunctionCallEffectEvidenceV4 | None = None,
        *,
        opaque_value_provider: OpaqueValueEvidenceProvider | None = None,
    ) -> NormalizedFunction:
        observation = unit.observation
        assert observation is not None
        context = unit.scopes.resolution_context
        function = unit.scopes.function
        assert type(function) is ConstructedFunctionScope
        observed_call_seeds = seed_function_calls(unit)
        if type(observed_call_seeds) is not FunctionCallSeedUnit:
            raise AssertionError("admitted scoped normalization requires exact call seeds")
        if configured_call_effects is not None:
            if configured_call_effects.seeds != observed_call_seeds:
                raise ValueError(
                    "configured call effects do not match the scoped observation"
                )
            call_seeds = configured_call_effects.seeds
        else:
            call_seeds = observed_call_seeds
        cfg = self._build_cfg(observation, function.entry)
        cfg.freeze()
        terminal_cuts = project_observed_terminal_cuts(unit.scopes, observation, cfg)
        dependencies = RustworkxDependencyGraph()
        effects: list[ObservedEffect] = []
        value_nodes: list[tuple[str, NodeId]] = []
        operation_nodes: dict[str, NodeId] = {}
        constant_inputs: dict[str, list[tuple[int, NodeId]]] = {}

        for instruction in sorted(observation.instructions, key=lambda item: item.address):
            for ordinal, operation in enumerate(instruction.operations):
                operation_key = _operation_key(instruction, ordinal, operation)
                operation_nodes[operation_key] = dependencies.add_node(
                    NodeRecord(f"op:{operation_key}", NodeKind.OPERATION, operation.opcode)
                )
                operation_node = operation_nodes[operation_key]
                effect = _scoped_effect(instruction, ordinal, operation, context)
                for input_ordinal, varnode in enumerate(operation.inputs):
                    if input_ordinal < _data_input_start(operation.opcode):
                        continue
                    if varnode.kind is VarnodeKindCode.OPAQUE:
                        continue
                    storage_ref = _storage_ref(varnode)
                    resolved = _resolve_validated_storage(storage_ref, context)
                    if type(resolved) is NonStorage:
                        storage_key = _storage_key(storage_ref, resolved)
                        constant_node = dependencies.add_node(
                            NodeRecord(
                                f"constant:{storage_key}",
                                NodeKind.CONSTANT,
                                storage_key,
                            )
                        )
                        constant_inputs.setdefault(operation_key, []).append(
                            (input_ordinal, constant_node)
                        )
                if (
                    operation.output is not None
                    and operation.output.kind is not VarnodeKindCode.OPAQUE
                ):
                    storage_ref = _storage_ref(operation.output)
                    resolved = _resolve_validated_storage(storage_ref, context)
                    if type(resolved) is not NonStorage:
                        storage_key = _storage_key(storage_ref, resolved)
                        node = dependencies.add_node(
                            NodeRecord(
                                f"value:{operation_key}:{storage_key}",
                                NodeKind.VALUE_VERSION,
                                storage_key,
                            )
                        )
                        dependencies.add_edge(
                            operation_node,
                            node,
                            EdgeRecord(kind="defines", operation=operation_key),
                        )
                        value_nodes.append((operation_key, node))
                effects.append(effect)

        call_effects = None
        if configured_call_effects is None:
            raw_call_ports = derive_raw_call_ports(call_seeds, context)
            call_effects = unavailable_call_effect_evidence(
                call_seeds,
                raw_ports=raw_call_ports,
            )

        predecessors = _cfg_predecessors(observation, function.entry)
        effects_by_block: dict[str, list[ObservedEffect]] = {
            _coordinate_key(instruction.address): []
            for instruction in sorted(
                observation.instructions,
                key=lambda item: item.address,
            )
        }
        for effect in effects:
            assert effect.block_key is not None
            effects_by_block[effect.block_key].append(effect)
        effect_unit = ObservedEffectUnit(
            EFFECT_DECODE_CONTRACT_VERSION,
            function.scope,
            _coordinate_key(function.entry),
            tuple(
                ObservedEffectBlock(
                    block_key,
                    tuple(sorted(predecessors[block_key])),
                    tuple(effects_by_block[block_key]),
                )
                for block_key in effects_by_block
            ),
            terminal_cuts.block_keys,
            effect_evidence_digest=(
                configured_call_effects.canonical_digest
                if configured_call_effects is not None
                else call_effects.effect_evidence_digest
            ),
        )
        if configured_call_effects is not None:
            effect_unit = augment_configured_call_effects_v4(
                effect_unit,
                configured_call_effects,
            )
        effect_unit = project_persistent_call_state(effect_unit, observation)
        memory_unit = decode_effect_unit(effect_unit)
        memory_binding = build_bound_local_memory_ssa(memory_unit)
        memory_ssa = memory_binding.result
        program = unit.scopes.program
        address_spaces = program.evidence.address_spaces
        while True:
            projected_effect_unit = project_function_relative_memory(
                effect_unit,
                observation,
                context,
                address_spaces,
                memory_ssa,
                opaque_value_provider=opaque_value_provider,
                translation_namespace=(
                    unit.scopes.program.evidence.translation_namespace.language_id
                ),
            )
            if projected_effect_unit is effect_unit:
                break
            effect_unit = projected_effect_unit
            memory_unit = decode_effect_unit(effect_unit)
            memory_binding = build_bound_local_memory_ssa(memory_unit)
            memory_ssa = memory_binding.result
        call_port_layout = None
        call_observations = None
        if call_effects is not None:
            call_port_layout = build_pre_ssa_call_port_layout(
                call_seeds,
                call_effects,
                memory_unit,
            )
            call_observations = bind_call_observations(
                call_seeds,
                call_effects,
                call_port_layout,
                memory_binding,
            )
        _materialize_constant_inputs(
            dependencies,
            memory_ssa,
            operation_nodes,
            constant_inputs,
        )
        memory_operation_nodes = {
            action.operation_key: operation_nodes[action.operation_key]
            for action in memory_ssa.actions
        }
        memory_graph = _materialize_local_memory_ssa(
            dependencies, memory_ssa, memory_operation_nodes
        )
        observed_inputs = tuple(storage for _, storage in memory_graph.entry_bindings)
        expected_entry_nodes = tuple(node for node, _ in memory_graph.entry_bindings)
        if any(
            dependencies.node(node).kind is not NodeKind.OBSERVED_INPUT
            for node in expected_entry_nodes
        ):
            raise AssertionError("ENTRY definitions must materialize as observed inputs")
        dependencies.freeze()
        return NormalizedFunction(
            document=None,
            scopes=unit.scopes,
            cfg=cfg,
            dependencies=dependencies,
            effects=tuple(
                effect for block in effect_unit.blocks for effect in block.effects
            ),
            observed_inputs=observed_inputs,
            value_nodes=tuple(value_nodes),
            memory_ssa=memory_ssa,
            memory_graph=memory_graph,
            terminal_cuts=terminal_cuts,
            call_seeds=call_seeds,
            call_effects=call_effects,
            configured_call_effects=configured_call_effects,
            memory_unit=memory_unit,
            call_port_layout=call_port_layout,
            call_observations=call_observations,
            configured_memory_binding=(
                memory_binding if configured_call_effects is not None else None
            ),
        )

    def _build_cfg(
        self,
        observation: ValidatedFunctionObservation,
        function_entry: AddressCoordinate,
    ) -> RustworkxDependencyGraph:
        graph = RustworkxDependencyGraph()
        nodes = {
            instruction.address: graph.add_node(
                NodeRecord(
                    f"instruction:{_coordinate_key(instruction.address)}",
                    NodeKind.INSTRUCTION,
                    _coordinate_key(instruction.address),
                )
            )
            for instruction in sorted(
                observation.instructions,
                key=lambda item: item.address,
            )
        }
        for instruction in sorted(
            observation.instructions,
            key=lambda item: item.address,
        ):
            for target_coordinate in control_successor_coordinates(
                instruction,
                local_addresses=set(nodes),
                function_entry=function_entry,
            ):
                target = nodes.get(target_coordinate)
                if target is not None:
                    graph.add_edge(
                        nodes[instruction.address],
                        target,
                        EdgeRecord(kind="control"),
                    )
        return graph


def _materialize_constant_inputs(
    graph: RustworkxDependencyGraph,
    memory_ssa: LocalMemorySsaResult,
    operation_nodes: dict[str, NodeId],
    constant_inputs: dict[str, list[tuple[int, NodeId]]],
) -> None:
    for action in memory_ssa.actions:
        definitions = tuple(
            memory_ssa.definitions[definition_id]
            for definition_id in action.write_definition_ids
        )
        if any(
            definition.kind is MemoryDefinitionKind.KILL
            for definition in definitions
        ):
            continue
        operation_node = operation_nodes[action.operation_key]
        for input_ordinal, constant_node in constant_inputs.get(
            action.operation_key, ()
        ):
            graph.add_edge(
                constant_node,
                operation_node,
                EdgeRecord(
                    kind="value_input",
                    operation=action.operation_key,
                    occurrence=input_ordinal,
                ),
            )


def _cfg_admission_failure(
    observation: ValidatedFunctionObservation,
    function: ConstructedFunctionScope,
) -> NormalizationFailureReason | None:
    entry_key = _coordinate_key(function.entry)
    known_coordinates = {
        instruction.address for instruction in observation.instructions
    }
    known = {_coordinate_key(coordinate) for coordinate in known_coordinates}
    if entry_key not in known:
        return NormalizationFailureReason.ENTRY_NOT_IN_OBSERVATION
    successors = {key: set() for key in known}
    for instruction in observation.instructions:
        source = _coordinate_key(instruction.address)
        targets = control_successor_coordinates(
            instruction,
            local_addresses=known_coordinates,
            function_entry=function.entry,
        )
        successors[source].update(
            _coordinate_key(target)
            for target in targets
            if _coordinate_key(target) in known
        )
    pending = [entry_key]
    reached: set[str] = set()
    while pending:
        block_key = pending.pop()
        if block_key in reached:
            continue
        reached.add(block_key)
        pending.extend(successors[block_key] - reached)
    if reached != known:
        return NormalizationFailureReason.DISCONNECTED_OBSERVED_CFG
    return None


def _cfg_predecessors(
    observation: ValidatedFunctionObservation,
    function_entry: AddressCoordinate,
) -> dict[str, set[str]]:
    known_coordinates = {
        instruction.address for instruction in observation.instructions
    }
    predecessors = {
        _coordinate_key(instruction.address): set()
        for instruction in observation.instructions
    }
    for instruction in observation.instructions:
        source = _coordinate_key(instruction.address)
        for target in control_successor_coordinates(
            instruction,
            local_addresses=known_coordinates,
            function_entry=function_entry,
        ):
            target_key = _coordinate_key(target)
            if target_key in predecessors:
                predecessors[target_key].add(source)
    return predecessors


_KIND_MAP = {
    VarnodeKindCode.CONSTANT: VarnodeKind.CONSTANT,
    VarnodeKindCode.REGISTER: VarnodeKind.REGISTER,
    VarnodeKindCode.UNIQUE: VarnodeKind.UNIQUE,
    VarnodeKindCode.ADDRESS: VarnodeKind.ADDRESS,
    VarnodeKindCode.STORAGE: VarnodeKind.STORAGE,
    VarnodeKindCode.OPAQUE: VarnodeKind.UNKNOWN,
}


def _storage_ref(value: ValidatedVarnode) -> StorageRef:
    return StorageRef(
        _KIND_MAP[value.kind],
        "",
        value.coordinate.byte_offset,
        value.byte_size,
        space_id=value.coordinate.space_id,
    )


def _storage_key(storage: StorageRef, resolved: object) -> str:
    if type(resolved) is ResolvedStorage:
        return ":".join(resolved.span.canonical_key)
    if type(resolved) is UnresolvedStorage:
        return f"unresolved:{resolved.reason.value}:{storage.stable_key}"
    return f"constant:{storage.space_id:x}:{storage.offset:x}:{storage.size:x}"


def _coordinate_key(value) -> str:
    return f"{value.space_id:x}:{value.byte_offset:x}"


def _operation_key(instruction, ordinal: int, operation) -> str:
    return _numeric_operation_key(
        instruction.address,
        ordinal,
        operation.opcode,
    )


def _scoped_effect(instruction, ordinal, operation, context) -> ObservedEffect:
    operation_key = _operation_key(instruction, ordinal, operation)
    block_key = _coordinate_key(instruction.address)
    resolved_inputs = tuple(
        _resolve_validated_storage(_storage_ref(varnode), context)
        for varnode in operation.inputs
    )
    input_start = _data_input_start(operation.opcode)
    data_inputs = operation.inputs[input_start:]
    resolved_data_inputs = resolved_inputs[input_start:]
    reads = tuple(
        value for value in resolved_data_inputs if type(value) is ResolvedStorage
    )
    unresolved_reads = tuple(
        UnresolvedMemoryAccess(value, raw.size, raw)
        for relative_ordinal, (raw, value) in enumerate(
            zip(
                (_storage_ref(varnode) for varnode in data_inputs),
                resolved_data_inputs,
                strict=True,
            )
        )
        if type(value) is UnresolvedStorage
        and not (
            operation.opcode in {"LOAD", "STORE"}
            and relative_ordinal == 1
            and data_inputs[relative_ordinal].kind is VarnodeKindCode.OPAQUE
        )
    )
    writes = ()
    unresolved_writes = ()
    if operation.output is not None:
        raw_output = _storage_ref(operation.output)
        resolved_output = _resolve_validated_storage(raw_output, context)
        if type(resolved_output) is ResolvedStorage:
            writes = (resolved_output,)
        elif type(resolved_output) is UnresolvedStorage:
            unresolved_writes = (
                UnresolvedMemoryAccess(resolved_output, raw_output.size, raw_output),
            )
    if operation.opcode == "LOAD":
        address = resolved_inputs[1] if len(resolved_inputs) > 1 else None
        raw_address = _storage_ref(operation.inputs[1]) if len(operation.inputs) > 1 else None
        width = operation.output.byte_size if operation.output is not None else 1
        return ObservedEffect(
            operation_key,
            EffectKind.READ,
            reads,
            writes,
            UnresolvedMemoryAccess(address, width, raw_address),
            block_key=block_key,
            unresolved_reads=unresolved_reads,
            unresolved_writes=unresolved_writes,
        )
    if operation.opcode == "STORE":
        address = resolved_inputs[1] if len(resolved_inputs) > 1 else None
        raw_address = _storage_ref(operation.inputs[1]) if len(operation.inputs) > 1 else None
        width = operation.inputs[2].byte_size if len(operation.inputs) > 2 else 1
        return ObservedEffect(
            operation_key,
            EffectKind.UNKNOWN_WRITE,
            reads,
            memory_write=UnresolvedMemoryAccess(address, width, raw_address),
            block_key=block_key,
            unresolved_reads=unresolved_reads,
            unresolved_writes=unresolved_writes,
        )
    if operation.opcode in {"CALL", "CALLIND"}:
        return ObservedEffect(
            operation_key,
            EffectKind.CALL,
            reads,
            writes,
            block_key=block_key,
            unresolved_reads=unresolved_reads,
            unresolved_writes=unresolved_writes,
        )
    if operation.opcode in {"BRANCH", "CBRANCH", "BRANCHIND", "RETURN"}:
        return ObservedEffect(
            operation_key,
            EffectKind.BRANCH,
            reads,
            writes,
            block_key=block_key,
            unresolved_reads=unresolved_reads,
            unresolved_writes=unresolved_writes,
        )
    kind = EffectKind.COPY if operation.opcode == "COPY" else EffectKind.WRITE
    return ObservedEffect(
        operation_key,
        kind,
        reads,
        writes,
        block_key=block_key,
        unresolved_reads=unresolved_reads,
        unresolved_writes=unresolved_writes,
    )


def derive_raw_call_ports(call_seeds, context) -> tuple[RawObservedCallPort, ...]:
    """Project only explicit Low-PCode call inputs and outputs to physical spans."""
    ports: list[RawObservedCallPort] = []
    for seed in call_seeds.callsites:
        raw_port_ordinal = 0
        for input_ordinal, varnode in enumerate(seed.inputs[1:], start=1):
            resolved = _resolve_validated_storage(_storage_ref(varnode), context)
            if type(resolved) is not ResolvedStorage:
                continue
            ports.append(
                RawObservedCallPort(
                    seed.occurrence,
                    RawCallPortRole.INPUT,
                    input_ordinal,
                    varnode,
                    resolved.span,
                    call_seeds.observation_digest,
                    raw_port_ordinal,
                )
            )
            raw_port_ordinal += 1
        if seed.explicit_output is None:
            continue
        resolved = _resolve_validated_storage(
            _storage_ref(seed.explicit_output), context
        )
        if type(resolved) is ResolvedStorage:
            ports.append(
                RawObservedCallPort(
                    seed.occurrence,
                    RawCallPortRole.OUTPUT,
                    None,
                    seed.explicit_output,
                    resolved.span,
                    call_seeds.observation_digest,
                    raw_port_ordinal,
                )
            )
    return tuple(ports)


def _data_input_start(opcode: str) -> int:
    return 1 if opcode in {"CALL", "CALLIND", "CALLOTHER"} else 0
