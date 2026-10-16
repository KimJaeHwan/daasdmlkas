"""Normalize one function without assigning ABI roles."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from .call_effect_contracts import (
    FunctionCallEffectEvidence,
    RawCallPortRole,
    RawObservedCallPort,
    unavailable_call_effect_evidence,
)
from .assumed_call_effects import AssumedCallEffect
from .call_summary_effects import ProvenCallEffect
from .call_clobber import CallClobberRead, _register_space_id, derive_call_clobber_reads
from .control_dependence import (
    CONTROL_DEPENDENCE_EDGE,
    ControlDependence,
    derive_control_dependences,
)
from .pcode_blocks import build_pcode_block_graph
from .rep_strings import MAX_REP_BYTES, rep_sites
from .may_alias import MayAliasRead, derive_may_alias_reads, private_frame_writes
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
from .graph_contracts import EdgeKind, EdgeRecord, NodeId, NodeKind, NodeRecord
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
from .span_geometry import ByteSpan, StorageObjectId, StorageObjectKind
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
from .relative_memory import (
    accessor_separations, project_function_relative_memory, single_execution_blocks, single_execution_keys,
    stale_reads,
)
from .observed_call_state import observed_call_state_projections, project_persistent_call_state
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
    call_clobber_reads: tuple[CallClobberRead, ...] = ()
    call_clobber_nodes: tuple[NodeId, ...] = ()
    may_alias_reads: tuple[MayAliasRead, ...] = ()
    may_alias_nodes: tuple[NodeId, ...] = ()
    control_dependences: tuple[ControlDependence, ...] = ()
    # TEST-ONLY: boundary calls normalized with a declared effect (see
    # assumed_call_effects); empty unless the caller explicitly opted in.
    assumed_call_effects: tuple[tuple[str, AssumedCallEffect], ...] = ()
    # call operation key -> effect proven from the callee's summary
    # (interprocedural layer); empty for a function normalized on its own
    proven_call_effects: tuple[tuple[str, ProvenCallEffect], ...] = ()
    # named opt-in assumption (``may_alias``): constant addresses never alias
    # the stack; results relying on this function's may-alias rows rely on it
    assumes_globals_disjoint_from_stack: bool = False
    # summarized calls that clobber the stack below their call-time pointer
    # (``ProvenCallEffect.clobbers_below``): (call key, stack object, first
    # offset kept); a call whose bound is unknown keeps no memory
    call_below_bounds: tuple[tuple[str, object, int], ...] = ()
    # named assumption readonly-image-data-is-constant was given (``image_info``)
    assumes_readonly_image_constant: bool = False
    # named assumption import-slots-hold-their-exports: an import slot's value
    # was taken as its import's address (``relative_memory.IMPORT_SLOTS``)
    assumes_import_slots_hold_exports: bool = False
    # named assumption entry-values-do-not-address-the-new-frame decided some
    # byte of this function's frame private (``may_alias._Policy.is_private``)
    assumes_entry_values_not_frame: bool = False
    # named assumption opaque-callees-leave-no-stack-addresses decided some
    # byte private (it would not be with the opaque calls as escapes)
    assumes_opaque_callees_leave_no_stack_addresses: bool = False
    # rep string sites made exact (``rep_strings``): (instruction key, count,
    # direction); the evaluator's overrides of their operations
    rep_blocks: tuple = ()
    operation_overrides: tuple = ()
    # named assumption direction-flag-clear was used (a rep site whose DF is
    # the function's entry value)
    assumed_direction_flag_clear: bool = False
    # may-alias facts the function summary reuses: (write key, object) pairs
    # writing private frame bytes only, and the wild objects (``may_alias``)
    private_frame_writes: frozenset = frozenset()
    wild_objects: frozenset = frozenset()
    # diagnostics only (``origin_witnesses``): a summarized memory run's
    # ``~in<i>`` row -> how many of its leading reads are the run's value
    # (the rest: its destination address), and the relative objects' atom
    # tuples / atom descriptions recorded by the projector
    call_value_inputs: tuple = ()
    address_objects: tuple = ()   # (object id, (atom tuple, space id))
    address_atoms: tuple = ()     # (atom, description)
    # call effect rows the function's own address facts rest on (pointer
    # values of its summary, ``function_summary._pointer_values``): rows of a
    # fresh result, and (row, input row, argument varnode) of same-object results
    fresh_rows: frozenset = frozenset()
    same_object_rows: tuple = ()
    # the pointer values of proven call effect rows (``_proven_call_rows``):
    # (row, ("reg", staging row, register varnode, null_is_fresh, unique) |
    # ("mem", load row, size, null_is_fresh, unique) | ("nonstack",))
    pointer_rows: tuple = ()
    # writes whose address rests on a read with debt -> conditions under which
    # they land on their static object (None: anywhere); ``may_alias`` gave
    # every read they may reach a debt (``function_summary.uncertain_writers_of``)
    uncertain_writers: tuple = ()
    # (call key, memory spans) a call not keeping memory keeps anyway: its
    # model's memory runs at an exactly known place (``_kept_call_memory``)
    kept_call_memory: tuple = ()
    # (result row, accessor identity, preserves_accessor_state claims, atom) of
    # each call result made a same-result atom (same-result-functions, docs 25.20)
    same_result_uses: tuple = ()
    # (result object, start, end, slot span): accessor-result-separate pairs
    # the may-alias analysis used (``relative_memory.accessor_separations``)
    accessor_separations: tuple = ()
    # (call effect / rep element row key, evaluation key, anchor) of rows
    # writing at an anchored address (``relative_memory.project_anchored``)
    call_anchors: tuple = ()
    # debt nodes ("uncertain_write_read") of reads that conditional
    # uncertain-address writers may reach: (node, the writers' conditions).
    # A root slice reaching one is incomplete (no caller decides them); a
    # function summary already carries those conditions on every claim
    # (``writer_conditions``) and passes these nodes
    uncertain_nodes: tuple = ()
    # debt nodes ("opaque_call_write") on the rows writing a call's unknown
    # memory (``ProvenCallEffect.unknown_memory``): unconditional
    opaque_nodes: tuple = ()
    # debt nodes ("open_condition") on summarized-run rows whose alias
    # conditions this function cannot decide: (node, (read span, write span)
    # pairs in this function's objects). Conditional (summaries carry the
    # pairs to the callers; roots are unsure)
    open_nodes: tuple = ()

    def __post_init__(self) -> None:
        if type(self.call_clobber_reads) is not tuple or any(
            type(row) is not CallClobberRead for row in self.call_clobber_reads
        ):
            raise TypeError("call-clobber reads must be an exact tuple")
        if type(self.call_clobber_nodes) is not tuple or len(
            self.call_clobber_nodes
        ) != len(self.call_clobber_reads):
            raise ValueError("call-clobber nodes must align with call-clobber reads")
        for row, node in zip(self.call_clobber_reads, self.call_clobber_nodes):
            record = self.dependencies.node(node)
            if (
                record.kind is not NodeKind.MEMORY_DEBT
                or record.label != "call_clobber_read"
                or not record.key.endswith(f":{row.operation_key}")
            ):
                raise ValueError("call-clobber node does not match its read")
        if type(self.may_alias_reads) is not tuple or any(
            type(row) is not MayAliasRead for row in self.may_alias_reads
        ):
            raise TypeError("may-alias reads must be an exact tuple")
        if type(self.may_alias_nodes) is not tuple or len(
            self.may_alias_nodes
        ) != len(self.may_alias_reads):
            raise ValueError("may-alias nodes must align with may-alias reads")
        for row, node in zip(self.may_alias_reads, self.may_alias_nodes):
            record = self.dependencies.node(node)
            if (
                record.kind is not NodeKind.MEMORY_DEBT
                or record.label not in ("may_alias_read", "uncertain_write_read")
                or not record.key.endswith((f":{row.operation_key}", f":{row.operation_key}:uncertain"))
            ):
                raise ValueError("may-alias node does not match its read")
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
            if self.memory_ssa is not None and not set(self.terminal_cuts.block_keys) <= {
                # a p-code sub-block key is "<instruction key>#<ordinal>"
                state.block_key.split("#")[0]
                for state in self.memory_ssa.observed_terminal_states
            }:
                raise ValueError("memory terminal states must cover the terminal cuts")
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


# call-local temporaries of proven call effects, far above any Ghidra unique offset
_CALL_EFFECT_TEMPORARY_BASE = 1 << 48


def _same_object_rows(proven_call_effects, observation) -> dict:
    """Call effect row -> (its input row, argument register varnode) for
    results declared to address the argument's object (``relative_memory``)."""
    space = _register_space_id(observation)
    found = {}
    if space is None:
        return found
    for key, effect in proven_call_effects.items():
        for write, source in effect.same_object_registers:
            for index, run in enumerate(effect.runs):
                if run.writes == (write,) and source in run.reads:
                    found[f"{key}~{index}"] = (f"{key}~in{index}", ValidatedVarnode(
                        VarnodeKindCode.REGISTER, AddressCoordinate(space, source.start), source.size))
    return found


def _opaque_calls(observation, proven_call_effects, assumed_call_effects) -> frozenset:
    """CALL / CALLIND operation keys with no proven effect that are no
    TEST-ONLY assumed boundary: their callees are opaque."""
    from .call_seeds import _operation_key

    return frozenset(
        key for instruction in observation.instructions
        for ordinal, operation in enumerate(instruction.operations)
        if operation.opcode in ("CALL", "CALLIND")
        for key in (_operation_key(instruction.address, ordinal, operation.opcode),)
        if key not in proven_call_effects and key not in assumed_call_effects
    )


def _rep_overrides(sites, plan, observation) -> dict:
    """Operation key -> the operation the address evaluator sees instead (None:
    unknown) for rep sites in a straight block: the count register ends 0;
    the pointer registers end advanced by direction * n * size once proven,
    unknown before; the element-0 access is unresolved until proven (n may be
    0). The data-dependency effects of these operations are unchanged."""
    found: dict = {}
    for address, site in sites.items():
        zero = ValidatedVarnode(VarnodeKindCode.CONSTANT, AddressCoordinate(site.constant_space, 0),
                                site.count.byte_size)
        found[site.count_def_key] = ValidatedOperation("COPY", (zero,), site.count)
        proven = plan.get(address)
        for key, add, register in ((site.destination_def_key, site.destination_add, site.destination),
                                   (site.source_def_key, site.source_add, site.source)):
            if key is None:
                continue
            if proven is None:
                found[key] = None
                continue
            count, direction = proven
            bits = 8 * register.byte_size
            delta = (direction * count * site.size - site.size) % (1 << bits)
            found[key] = ValidatedOperation(
                "INT_ADD",
                (add, ValidatedVarnode(VarnodeKindCode.CONSTANT, AddressCoordinate(site.constant_space, delta),
                                       register.byte_size)),
                register,
            )
        if proven is None or proven[0] == 0:
            for key in (site.load_key, site.store_key):
                if key is not None:
                    found[key] = None
    return found


def _reaches_debt(graph, node, varnode, context, clobbers=None) -> bool:
    """Whether the value ``varnode`` has at operation ``node`` depends on any
    debt (backward data slice of that input)."""
    labels = _debt_labels(graph, node, varnode, context, clobbers)
    return labels is None or bool(labels)


def call_clobber_spans(normalized) -> dict:
    """Call-clobber debt node -> the spans its read may have lost to a call."""
    return dict(zip(normalized.call_clobber_nodes, (row.spans for row in normalized.call_clobber_reads)))


def _row_reaches_debt(graph, node) -> bool:
    """Whether any value operation ``node`` reads depends on a debt."""
    from .function_summary import _address_slice

    inputs = [source for source, _, record in graph._graph.in_edges(node)
              if record.span is not None or graph.node(source).kind is NodeKind.MEMORY_DEBT]
    return any(graph.node(item).kind is NodeKind.MEMORY_DEBT for item in _address_slice(graph, inputs, {}))


def _debt_nodes(graph, node, varnode, context, clobbers=None):
    """The debt nodes the value ``varnode`` has at operation ``node`` depends
    on (None: cannot tell); see ``_debt_labels``."""
    from .function_summary import _address_slice

    if node is None:
        return None
    resolved = _resolve_validated_storage(_storage_ref(varnode), context)
    if type(resolved) is not ResolvedStorage:
        return None
    inputs = [
        source for source, _, record in graph._graph.in_edges(node)
        if (record.span is not None and record.span.overlaps(resolved.span))
        or (graph.node(source).kind is NodeKind.MEMORY_DEBT and (
            clobbers is None or source not in clobbers
            or any(span.overlaps(resolved.span) for span in clobbers[source])))
    ]
    return frozenset(item for item in _address_slice(graph, inputs, {})
                     if graph.node(item).kind is NodeKind.MEMORY_DEBT)


def _debt_labels(graph, node, varnode, context, clobbers=None):
    """Labels of the debts the value ``varnode`` has at operation ``node``
    depends on (None: cannot tell). Debts on the operation itself count (a
    call clobber sits there without a span; with ``clobbers`` -- see
    ``call_clobber_spans`` -- only one whose spans overlap ``varnode``)."""
    from .function_summary import _address_slice

    if node is None:
        return None
    resolved = _resolve_validated_storage(_storage_ref(varnode), context)
    if type(resolved) is not ResolvedStorage:
        return None
    inputs = [
        source for source, _, record in graph._graph.in_edges(node)
        if (record.span is not None and record.span.overlaps(resolved.span))
        or (graph.node(source).kind is NodeKind.MEMORY_DEBT and (
            clobbers is None or source not in clobbers
            or any(span.overlaps(resolved.span) for span in clobbers[source])))
    ]
    return frozenset(graph.node(item).label for item in _address_slice(graph, inputs, {})
                     if graph.node(item).kind is NodeKind.MEMORY_DEBT)


def _prove_rep_sites(sites, plan, memory_ssa, observation, scopes, overrides, assume_clear,
                     blocked=frozenset(), used=None) -> dict:
    """Sites whose count (at the instruction start) and direction become
    proven on the current SSA: address -> (n, direction, used the assumption)."""
    from .relative_memory import expressions_at

    pending = {address: site for address, site in sites.items() if address not in plan}
    if not pending:
        return {}
    requests = []
    for site in pending.values():
        requests.append((site.count_key, site.count))
        requests.append((site.direction_key, site.direction))
    values = expressions_at(memory_ssa, observation, scopes, requests, overrides, blocked, used)
    found = {}
    for address, site in pending.items():
        count = values.get((site.count_key, site.count))
        if count is None or count[0]:
            continue
        flag = values.get((site.direction_key, site.direction))
        if flag is None:
            continue
        atoms, value, entry = flag
        assumed = False
        if not atoms and value in (0, 1):
            direction = 1 if value == 0 else -1
        elif entry and assume_clear:
            direction, assumed = 1, True
        else:
            continue
        n = count[1]
        if n * site.size > MAX_REP_BYTES:
            continue
        found[address] = (n, direction, assumed)
    return found


def _rep_element_rows(site, proven, block_key, scope, context, temporaries):
    """Elements 1..n-1 of a proven rep site, in iteration order after the
    real element-0 LOAD/STORE: each reads its element through the site's
    element address (anchored at the real access, displaced by i * size)."""
    count, direction = proven
    rows: list[ObservedEffect] = []
    anchored: dict = {}

    def resolved(varnode):
        result = _resolve_validated_storage(_storage_ref(varnode), context)
        if type(result) is not ResolvedStorage:
            raise AssertionError("rep site varnodes must resolve")
        return result

    def temporary():
        span = ResolvedStorage(ByteSpan(
            StorageObjectId(StorageObjectKind.FUNCTION_UNIQUE, scope, 0),
            _CALL_EFFECT_TEMPORARY_BASE + 16 * len(temporaries), site.size,
        ))
        temporaries.append(span)
        return span

    for index in range(1, count):
        displacement = direction * index * site.size
        if site.load_key is not None:   # movs: v = [ts + d]; w = v; [td + d] = w
            key = f"{site.load_key}~e{index}"
            rows.append(ObservedEffect(
                key, EffectKind.COPY, reads=(resolved(site.source_temp),), writes=(resolved(site.load_output),),
                memory_read=UnresolvedMemoryAccess(None, site.size), block_key=block_key,
            ))
            anchored[key] = (site.load_key, site.source_temp, displacement, site.size, site.space_id)
            rows.append(ObservedEffect(
                f"{site.value_copy_key}~e{index}", EffectKind.COPY, reads=(resolved(site.load_output),),
                writes=(resolved(site.value),), block_key=block_key,
            ))
        key = f"{site.store_key}~e{index}"
        rows.append(ObservedEffect(
            key, EffectKind.COPY, reads=(resolved(site.destination_temp), resolved(site.value)), writes=(),
            memory_write=UnresolvedMemoryAccess(None, site.size), block_key=block_key,
        ))
        anchored[key] = (site.store_key, site.destination_temp, displacement, site.size, site.space_id)
    return rows, anchored


def _call_stack_span(call_key, proven, transitions, observation, context):
    """The caller's stack-pointer register span at a summarized call that
    clobbers below it (call shape base, or the tail jump's stack pointer)."""
    if not proven.clobbers_below:
        return None
    if proven.tail_stack:
        return proven.tail_stack[0]
    transition = transitions.get(call_key)
    space = _register_space_id(observation)
    if transition is None or space is None:
        return None
    base = transition.caller_base
    resolved = _resolve_validated_storage(
        StorageRef(VarnodeKind.REGISTER, "", base.byte_offset, base.byte_size, space_id=space), context)
    return resolved.span if type(resolved) is ResolvedStorage else None


def _kept_call_memory(proven_call_effects, memory_ssa, wild_objects, uncertain) -> dict:
    """Call key -> (memory spans, their run rows) the call keeps although it
    does not keep memory: the bytes an effect with ``memory_runs_final`` (an
    external model) writes in a memory run whose place memory SSA resolved
    exactly -- the run row's data writes all in one object (not wild), one
    contiguous range of the run's size, no unresolved write, the row not an
    uncertain-address writer (``uncertain``; the caller normalizes again when
    one becomes so) -- and whose run carries no condition (no alias or writer
    conditions) and does not keep old bytes. The rows sit just before the
    CALL (``_proven_call_rows``), so the call keeping those bytes leaves the
    run's value there."""
    action_of = {action.operation_key: action for action in memory_ssa.actions}
    unresolved = {memory_ssa.actions[item.action_id].operation_key for item in memory_ssa.unresolved_writes}
    found = {}
    for key, effect in proven_call_effects.items():
        if not effect.memory_runs_final or effect.preserves_memory or effect.writer_conditions:
            continue
        spans, rows = [], []
        for index, run in enumerate(effect.memory_runs):
            row = f"{key}~{len(effect.runs) + index}"
            action = action_of.get(row)
            if action is None or row in unresolved or row in uncertain or run.keeps_old or run.conditions:
                continue
            definitions = [memory_ssa.definitions[item] for item in action.write_definition_ids]
            if not definitions or any(item.kind is not MemoryDefinitionKind.DATA_WRITE for item in definitions):
                continue
            objects = {item.span.object_id for item in definitions}
            if len(objects) != 1 or objects & set(wild_objects):
                continue
            covered = sorted((item.span.start, item.span.end) for item in definitions)
            start, end = covered[0][0], covered[0][1]
            for low, high in covered[1:]:
                if low != end:
                    break
                end = high
            else:
                if end - start == run.write.size:
                    spans.append(ByteSpan(objects.pop(), start, end - start))
                    rows.append(row)
        if spans:
            found[key] = (tuple(spans), tuple(rows))
    return found


def _call_below_bounds(proven_call_effects, transitions, effect_unit, memory_ssa, observation, scopes,
                       context) -> tuple:
    """(call key, stack object, bound) for calls that clobber below the
    call-time stack pointer: bytes of this function's stack object at offsets
    below ``bound`` (the callee's entry stack pointer) may change."""
    from .may_alias import _stack_pointer, _unit_stub
    from .relative_memory import stack_offset_at

    # only calls that keep all other memory: a call that keeps none clobbers it all anyway
    keys = [key for key, row in proven_call_effects.items() if row.clobbers_below and row.preserves_memory]
    if not keys:
        return ()
    found = _stack_pointer(_unit_stub(scopes), observation, context, scopes.program.evidence.address_spaces)
    if found is None:
        return _stackless_tail_bounds(keys, proven_call_effects, effect_unit, memory_ssa, observation, scopes)
    stack_object, bias, register_space, offset, size = found
    rows = []
    for key in keys:
        span = _call_stack_span(key, proven_call_effects[key], transitions, observation, context)
        if span is None or (span.start, span.size) != (offset, size):
            continue
        varnode = ValidatedVarnode(VarnodeKindCode.REGISTER, AddressCoordinate(register_space, offset), size)
        displacement = stack_offset_at(memory_ssa, observation, scopes, f"{key}~sp", varnode, span)
        if displacement is None:
            continue
        transition = transitions.get(key)
        delta = 0 if proven_call_effects[key].tail_stack or transition is None else transition.displacement_delta
        rows.append((key, stack_object, bias + displacement + delta))
    return tuple(rows)


def _stackless_tail_bounds(keys, proven_call_effects, effect_unit, memory_ssa, observation, scopes=None) -> tuple:
    """A function with no stack-pointer shape of its own (a thunk ``jmp
    [__imp_X]``) that never writes the stack pointer (so at the jump it is the
    entry value) and whose effects touch no object based on it: the callee's
    clobbering below that pointer reaches nothing this function tracks --
    bound 0 (no byte below it)."""
    from .relative_memory import _function_relative_object_id

    spaces = {
        operation.inputs[0].coordinate.byte_offset
        for instruction in observation.instructions for operation in instruction.operations
        if operation.opcode in ("LOAD", "STORE") and operation.inputs
    } | {
        operation.inputs[0].coordinate.space_id
        for instruction in observation.instructions for operation in instruction.operations
        if operation.opcode == "BRANCHIND" and operation.inputs
        and operation.inputs[0].kind is VarnodeKindCode.ADDRESS
    }
    # a thunk ``jmp X`` touching no memory: the space of its jump / call targets,
    # when that is the program's one loaded memory space (where its stack lives
    # -- a separate code space would name no stack object)
    loaded = {
        row.space_id for row in (scopes.program.evidence.address_spaces if scopes is not None else ())
        if row.is_memory_space and row.is_loaded_memory_space and not row.is_overlay_space
        and not row.is_external_space
    }
    if len(loaded) == 1:
        spaces |= loaded & {
            operation.inputs[0].coordinate.space_id
            for instruction in observation.instructions for operation in instruction.operations
            if operation.opcode in ("BRANCH", "CALL") and operation.inputs
            and operation.inputs[0].kind is VarnodeKindCode.ADDRESS
        }
    touched = {
        evidence.span.object_id
        for block in effect_unit.blocks for effect in block.effects
        for evidence in (*effect.reads, *effect.writes) if type(evidence) is ResolvedStorage
    }
    rows = []
    for key in keys:
        effect = proven_call_effects[key]
        if not effect.tail_stack or not spaces:
            continue
        stack = effect.tail_stack[0]
        if any(type(evidence) is ResolvedStorage and evidence.span.overlaps(stack)
               for block in effect_unit.blocks for row in block.effects for evidence in row.writes):
            continue  # the stack pointer is written: at the jump it may not be the entry one
        objects = {_function_relative_object_id(memory_ssa.function_scope, effect.tail_stack[0], space)
                   for space in spaces}
        if objects & touched or any(effect.memory_write is not None or effect.memory_read is not None
                                    for block in effect_unit.blocks for effect in block.effects):
            continue  # stack bytes (or unknown addresses) are in play: no bound
        rows.append((key, min(objects, key=lambda item: item.space_key), 0))
    return tuple(rows)


def _memory_spans_except_below(effect_unit, object_id, bound) -> tuple:
    """Every memory span the function's effects touch, minus the stack bytes
    below ``bound``."""
    spans = set()
    for block in effect_unit.blocks:
        for effect in block.effects:
            for evidence in (*effect.reads, *effect.writes):
                if type(evidence) is not ResolvedStorage or evidence.span.object_id.kind not in (
                        StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE):
                    continue
                span = evidence.span
                if span.object_id == object_id and span.start < bound:
                    if span.end <= bound:
                        continue
                    span = ByteSpan(object_id, bound, span.end - bound)
                spans.add(span)
    return tuple(sorted(spans, key=lambda span: span.canonical_key))


def _program_register_space(unit) -> int | None:
    """The program's register space, for a function that names no register
    itself (a thunk that only jumps) but receives summarized call effects."""
    spaces = [row.space_id for row in unit.scopes.program.evidence.address_spaces if row.is_register_space]
    return spaces[0] if len(spaces) == 1 else None


_CALL_EFFECT_LABELS = {
    "": "CALL_EFFECT", "in": "CALL_EFFECT_INPUT", "ld": "CALL_EFFECT_LOAD", "sink": "CALL_EFFECT_SINK",
    "ck": "CALL_EFFECT_CHECK", "cr": "CALL_EFFECT_CHECK", "cw": "CALL_EFFECT_CHECK", "sp": "CALL_EFFECT_CHECK",
    "ext": "CALL_EFFECT_CHECK", "u": "CALL_EFFECT", "iu": "CALL_EFFECT_INPUT", "sr": "CALL_EFFECT_CHECK",
}


_CALL_OPCODES = frozenset({"CALL", "CALLIND", "CALLOTHER"})


def _accessor_states(observation, block_graph, entry_block, proven_call_effects, assumed_call_effects,
                     once_blocks) -> dict:
    """Accessor state tokens (docs 25.20 C3): call key of an accessor call
    (``ProvenCallEffect.same_result``) -> (its accessor's state before the
    call, the preserves_accessor_state claims that state rests on). Per
    accessor (model id) a forward must-dataflow over ``block_graph``: at entry
    ("entry",); a call leaves it unchanged when it is a call of an accessor
    (its own normalization, or another accessor -- independent under
    same-result-functions), declares ``preserves_accessor_state`` for it (a
    named claim, recorded), or is a user op declared to have no effect;
    every other call -- an opaque one, a summarized one, a model with a finite
    footprint -- makes it ("call", key) when its block runs once per
    activation, else no token (None). At a join the token survives only if
    every predecessor that reaches it has the identical token (greatest fixed
    point from the entry: a cycle without such a call keeps it); a block not
    reached from the entry has none."""
    domains = sorted({effect.same_result[0] for effect in proven_call_effects.values()
                      if effect.same_result is not None})
    if not domains or block_graph.unsupported is not None:
        return {}
    instructions = {row.address: row for row in observation.instructions}
    blocks = {block.key: block for block in block_graph.blocks}
    if entry_block not in blocks:
        return {}
    predecessors: dict = {key: [] for key in blocks}
    for block in blocks.values():
        for successor in block.successors:
            if successor in predecessors:
                predecessors[successor].append(block.key)
    calls = {}
    for key, block in blocks.items():
        row = instructions[block.instruction]
        calls[key] = [_operation_key(row, ordinal, row.operations[ordinal]) for ordinal in range(block.start, block.stop)
                      if row.operations[ordinal].opcode in _CALL_OPCODES]

    def meet(key, out):
        values = [out[item] for item in predecessors[key] if item in out]
        if key == entry_block:
            values.append((("entry",), frozenset()))
        if not values:
            return None
        tokens = {value[0] for value in values}
        if len(tokens) != 1 or None in tokens:
            return (None, frozenset())
        return (tokens.pop(), frozenset().union(*(value[1] for value in values)))

    found: dict = {}
    for domain in domains:
        def transfer(key, state, record=None):
            for call in calls[key]:
                effect = proven_call_effects.get(call)
                if record is not None and effect is not None and effect.same_result is not None \
                        and effect.same_result[0] == domain:
                    record[call] = state
                if effect is not None and effect.same_result is not None:
                    continue
                if effect is not None and effect.state_proof is not None:
                    # a body proven to change no memory and run no call (docs 25.26)
                    if state[0] is not None:
                        state = (state[0], state[1] | {f"proof:{effect.state_proof}"})
                    continue
                if effect is not None and (domain in effect.preserves_accessor_state
                                           or "*" in effect.preserves_accessor_state):
                    if state[0] is not None:
                        state = (state[0], state[1] | {effect.callee})
                    continue
                if call.endswith(":CALLOTHER") and call in assumed_call_effects:
                    continue   # a user op declared to have no effect
                state = ((("call", call) if key in once_blocks else None), frozenset())
            return state

        out: dict = {}
        pending = [entry_block]
        while pending:
            key = pending.pop()
            new = transfer(key, meet(key, out))
            if out.get(key) != new:
                out[key] = new
                pending.extend(item for item in blocks[key].successors if item in blocks)
        record: dict = {}
        for key in blocks:
            state = meet(key, out)
            if state is not None:
                transfer(key, state, record)
        found.update(record)
    return found


def _pending_write_keys(effect_unit) -> frozenset:
    """Keys of writes still without an address (``memory_write``)."""
    return frozenset(effect.operation_key for block in effect_unit.blocks for effect in block.effects
                     if effect.memory_write is not None)


def _proven_call_rows(call_key, proven, block_key, scope, register_space, transitions, temporaries,
                      stack_span=None, pointer_rows=None, value_inputs=None, accessor_state=None):
    """Effects of one summarized call (``call_summary_effects``), in order:
    ``~ld<j>`` loads of callee-entry memory, ``~in<i>`` gathering each run's
    inputs into a call-local temporary, ``~sink<k>`` gathering the inputs of
    each callee sink root (the projected root), ``~<i>`` the run outputs
    (register runs first, then memory runs), ``~u<j>`` the unknown memory (an
    "opaque_call_write" debt each, ``_materialize_opaque_call_writes``) at the
    address its ``~iu<j>`` row evaluates with the other inputs, before any
    output. An accessor call (``same_result``, docs 25.20) with a state token
    (``accessor_state``, ``_accessor_states``) also loads its read slot
    (``~ld<j>``) and reads its inputs, the slot's base register and that load
    in a ``~sr`` row -- the key its result's same-result atom is made from
    (a ("same_result", ...) pointer row, ``relative_memory._same_result_key``);
    its write-back run (``write_back``) gets a ("write_back", result row)
    pointer row: the slot class it leaves (``relative_memory._definition_class``).
    Anchored memory is projected later (``relative_memory``): returns the
    effects and their anchored accesses."""
    rows: list[ObservedEffect] = []
    anchored: dict = {}

    def temporary():
        span = ResolvedStorage(ByteSpan(
            StorageObjectId(StorageObjectKind.FUNCTION_UNIQUE, scope, 0),
            _CALL_EFFECT_TEMPORARY_BASE + 16 * len(temporaries), 1,
        ))
        temporaries.append(span)
        return span

    def anchor_varnode(anchor):
        return ValidatedVarnode(
            VarnodeKindCode.REGISTER, AddressCoordinate(register_space, anchor.start), anchor.size,
        )

    def displacement(access):
        # the callee's entry stack pointer is the caller's after the
        # return-address push of the observed call shape
        transition = transitions.get(call_key)
        if transition is not None and (
            access.anchor.start, access.anchor.size
        ) == (transition.caller_base.byte_offset, transition.caller_base.byte_size):
            return access.displacement + transition.displacement_delta
        return access.displacement

    loaded: dict = {}
    load_keys: dict = {}

    def base(access):
        """(anchor reads, anchored-access base) of an anchored access: a
        register, or ("mem", key of the ~ld row reading the pointer slot)."""
        if access.pointer is not None:
            slot = load(access.pointer)
            return (slot,), ("mem", load_keys[access.pointer]), access.displacement
        return (ResolvedStorage(access.anchor),), anchor_varnode(access.anchor), displacement(access)

    def load(access):
        if access in loaded:
            return loaded[access]
        if access.pointer is not None:
            reads, pointer, offset = base(access)
            key = f"{call_key}~ld{len(loaded)}"
            target = temporary()
            rows.append(ObservedEffect(
                key, EffectKind.COPY, reads=reads, writes=(target,),
                memory_read=UnresolvedMemoryAccess(None, access.size), block_key=block_key,
            ))
            anchored[key] = (key, pointer, offset, access.size, access.space_id)
            loaded[access], load_keys[access] = target, key
            return target
        key = f"{call_key}~ld{len(loaded)}"
        target = temporary()
        load_keys[access] = key
        if access.anchor is None:
            rows.append(ObservedEffect(
                key, EffectKind.COPY, reads=(ResolvedStorage(access.span),), writes=(target,),
                block_key=block_key,
            ))
        else:
            rows.append(ObservedEffect(
                key, EffectKind.COPY, reads=(ResolvedStorage(access.anchor),), writes=(target,),
                memory_read=UnresolvedMemoryAccess(None, access.size), block_key=block_key,
            ))
            anchored[key] = (key, anchor_varnode(access.anchor), displacement(access),
                             access.size, access.space_id)
        loaded[access] = target
        return target

    if proven.extent_registers:
        # reads the registers whose constant value would make a model's
        # variable-size effect exact (``interprocedural``)
        rows.append(ObservedEffect(
            f"{call_key}~ext", EffectKind.COPY,
            reads=tuple(ResolvedStorage(span) for span in proven.extent_registers),
            writes=(temporary(),), block_key=block_key,
        ))
    if proven.clobbers_below and stack_span is not None:
        # reads the stack pointer at the call: the clobbered region's bound
        rows.append(ObservedEffect(
            f"{call_key}~sp", EffectKind.COPY, reads=(ResolvedStorage(stack_span),),
            writes=(temporary(),), block_key=block_key,
        ))
    staged = []
    runs = [("register", run) for run in proven.runs] + [("memory", run) for run in proven.memory_runs]
    for index, (kind, run) in enumerate(runs):
        inputs = [ResolvedStorage(span) for span in run.reads] + [load(item) for item in run.loads]
        if kind == "memory":
            if run.keeps_old:
                inputs.append(load(run.write))
            if value_inputs is not None:
                # the leading reads are the run's value; the rest its destination
                # address (``origin_witnesses``)
                value_inputs[f"{call_key}~in{index}"] = len(inputs)
            if run.write.anchor is not None or run.write.pointer is not None:
                inputs.extend(base(run.write)[0])
        anchors = sorted({
            side.anchor for pair in run.conditions for side in pair if side.anchor is not None
        }, key=lambda span: span.canonical_key)
        if anchors:  # locates both sides of each alias condition at the call (``interprocedural``)
            rows.append(ObservedEffect(
                f"{call_key}~cr{index}", EffectKind.COPY,
                reads=tuple(ResolvedStorage(span) for span in anchors), writes=(temporary(),),
                block_key=block_key,
            ))
        stage_key = f"{call_key}~in{index}"
        target = temporary()
        rows.append(ObservedEffect(
            stage_key, EffectKind.COPY, reads=tuple(inputs), writes=(target,), block_key=block_key,
        ))
        staged.append((kind, run, stage_key, target))
    unknown_staged = []
    for index, access in enumerate(proven.unknown_memory):
        if access.anchor is None and access.pointer is None:
            unknown_staged.append((access, None, None))
            continue
        # the address at the call: evaluated before the outputs change its base
        stage_key = f"{call_key}~iu{index}"
        target = temporary()
        rows.append(ObservedEffect(
            stage_key, EffectKind.COPY, reads=tuple(base(access)[0]), writes=(target,), block_key=block_key,
        ))
        unknown_staged.append((access, stage_key, target))
    anchors = sorted({
        side.anchor for pair in proven.writer_conditions for side in pair if side.anchor is not None
    }, key=lambda span: span.canonical_key)
    if anchors:  # locates both sides of each writer condition at the call (``interprocedural``)
        rows.append(ObservedEffect(
            f"{call_key}~cw", EffectKind.COPY,
            reads=tuple(ResolvedStorage(span) for span in anchors), writes=(temporary(),),
            block_key=block_key,
        ))
    for index, demand in enumerate(proven.sink_demands):
        inputs = [ResolvedStorage(span) for span in demand.reads] + [load(item) for item in demand.loads]
        rows.append(ObservedEffect(
            f"{call_key}~sink{index}", EffectKind.COPY, reads=tuple(inputs), writes=(temporary(),),
            block_key=block_key,
        ))
        anchors = sorted({
            side.anchor for pair in demand.conditions for side in pair if side.anchor is not None
        }, key=lambda span: span.canonical_key)
        if anchors:
            # reads the anchor registers at the call, so the caller can locate
            # both sides of each alias condition (``interprocedural``)
            rows.append(ObservedEffect(
                f"{call_key}~ck{index}", EffectKind.COPY,
                reads=tuple(ResolvedStorage(span) for span in anchors), writes=(temporary(),),
                block_key=block_key,
            ))
    accessor = None
    if proven.same_result is not None and accessor_state is not None and pointer_rows is not None:
        _, identity, result, inputs, read, nonstack, write_back, extent = proven.same_result
        index = next((index for index, (kind, run, _, _) in enumerate(staged)
                      if kind == "register" and tuple(run.writes) == (result,)), None)
        written = next((index for index, (kind, run, _, _) in enumerate(staged)
                        if kind == "memory" and run.write == read), None) if write_back else None
        if index is not None:
            slot = load(read)
            spans = list(dict.fromkeys((*inputs, read.anchor)))
            rows.append(ObservedEffect(
                f"{call_key}~sr", EffectKind.COPY, reads=(*(ResolvedStorage(span) for span in spans), slot),
                writes=(temporary(),), block_key=block_key,
            ))
            accessor = (f"{call_key}~{index}", (
                "same_result", identity, f"{call_key}~sr", tuple(anchor_varnode(span) for span in inputs),
                anchor_varnode(read.anchor), displacement(read), load_keys[read], read.size, nonstack,
                accessor_state, extent, read.space_id), None if written is None else f"{call_key}~{written}")
    # a value that may be a new block is fresh only as the call's sole pointer value
    unique = sum(getattr(run, "value", None) is not None for _, run, _, _ in staged) == 1
    for index, (kind, run, stage_key, target) in enumerate(staged):
        key = f"{call_key}~{index}"
        value = getattr(run, "value", None)
        if pointer_rows is not None and value is not None:
            # the pointer value the callee's summary states (``relative_memory``)
            if value[0] == "nonstack":
                pointer_rows[key] = value
            elif value[0] == "same_reg":
                pointer_rows[key] = ("reg", stage_key, anchor_varnode(value[1]), value[2], unique)
            elif value[1] in load_keys:
                pointer_rows[key] = ("mem", load_keys[value[1]], value[1].size, value[2], unique)
        if accessor is not None and accessor[0] == key:
            pointer_rows[key] = accessor[1]
        if accessor is not None and accessor[2] == key:
            pointer_rows[key] = ("write_back", accessor[0])
        if kind == "register":
            writes = tuple(ResolvedStorage(span) for span in run.writes)
            rows.append(ObservedEffect(key, EffectKind.COPY, reads=(target,), writes=writes,
                                       block_key=block_key))
        elif run.write.anchor is None and run.write.pointer is None:
            rows.append(ObservedEffect(key, EffectKind.COPY, reads=(target,),
                                       writes=(ResolvedStorage(run.write.span),), block_key=block_key))
        else:
            rows.append(ObservedEffect(
                key, EffectKind.COPY, reads=(target,),
                memory_write=UnresolvedMemoryAccess(None, run.write.size), block_key=block_key,
            ))
            _, pointer, offset = base(run.write)
            anchored[key] = (stage_key, pointer, offset, run.write.size, run.write.space_id)
    for index, (access, stage_key, target) in enumerate(unknown_staged):
        key = f"{call_key}~u{index}"
        if stage_key is None:
            rows.append(ObservedEffect(key, EffectKind.COPY, reads=(), writes=(ResolvedStorage(access.span),),
                                       block_key=block_key))
            continue
        _, pointer, offset = base(access)
        rows.append(ObservedEffect(
            key, EffectKind.COPY, reads=(target,),
            memory_write=UnresolvedMemoryAccess(None, access.size), block_key=block_key,
        ))
        anchored[key] = (stage_key, pointer, offset, access.size, access.space_id)
    return rows, anchored


class NormalizationFailureReason(StrEnum):
    MISSING_VALIDATED_OBSERVATION = "missing_validated_observation"
    MISSING_CONSTRUCTED_FUNCTION_SCOPE = "missing_constructed_function_scope"
    ENTRY_NOT_IN_OBSERVATION = "entry_not_in_observation"
    DISCONNECTED_OBSERVED_CFG = "disconnected_observed_cfg"
    UNSUPPORTED_INTRA_INSTRUCTION_FLOW = "unsupported_intra_instruction_flow"
    # a chain of dependent values deeper than the analysis follows (Python's
    # recursion bound, ``interprocedural.ANALYSIS_RECURSION_LIMIT``): the
    # function is analyzed as not normalizing -- its callers see an opaque call
    ANALYSIS_DEPTH = "analysis_depth"


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
        assumed_call_effects: dict[str, AssumedCallEffect] | None = None,
        proven_call_effects: dict[str, ProvenCallEffect] | None = None,
        assume_globals_disjoint_from_stack: bool = False,
        readonly_image=None,
        assume_direction_flag_clear: bool = False,
        private_frame_above: int = 0,
        open_conditions: dict | None = None,
    ) -> NormalizedFunction | UnresolvedNormalizedFunction:
        """``assumed_call_effects`` (TEST-ONLY, opt-in): call operation key ->
        declared effect; see ``tdo_v2.assumed_call_effects``.
        ``open_conditions``: call key -> {anchored pair of a run condition ->
        (read span, write span) in this function's objects}: pairs this
        function cannot decide (``interprocedural``); the run rows carrying
        them get an "open_condition" debt with those pairs.
        ``proven_call_effects``: call operation key -> effect proven from the
        callee's summary (``tdo_v2.call_summary_effects``).
        ``assume_globals_disjoint_from_stack``: named opt-in assumption, see
        ``tdo_v2.may_alias``."""
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
        admission_failure = _cfg_admission_failure(
            value.observation, function
        ) or _intra_instruction_flow_failure(value.observation, function.entry)
        if admission_failure is not None:
            return UnresolvedNormalizedFunction(value.scopes, admission_failure)
        return _ScopedNormalizer().normalize(
            value,
            opaque_value_provider=opaque_value_provider,
            assumed_call_effects=assumed_call_effects or {},
            proven_call_effects=proven_call_effects or {},
            assume_globals_disjoint_from_stack=assume_globals_disjoint_from_stack,
            readonly_image=readonly_image,
            assume_direction_flag_clear=assume_direction_flag_clear,
            private_frame_above=private_frame_above,
            open_conditions=open_conditions or {},
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
        admission_failure = _cfg_admission_failure(
            value.observation, function
        ) or _intra_instruction_flow_failure(value.observation, function.entry)
        if admission_failure is not None:
            return UnresolvedNormalizedFunction(value.scopes, admission_failure)
        return _ScopedNormalizer().normalize(
            value,
            effects,
            opaque_value_provider=opaque_value_provider,
        )


class _Retry:
    """Normalize again with these memory reads blocked (``stale_reads``) and
    these rep sites left unexpanded (their count or direction proof failed)."""

    def __init__(self, failed: frozenset, sites: frozenset = frozenset(), bounds: frozenset = frozenset(),
                 uncertain: dict | None = None) -> None:
        self.failed = failed
        self.sites = sites
        self.bounds = bounds
        self.uncertain = uncertain or {}  # uncertain-address writers found (``_kept_call_memory``)


def _merge_uncertain(old: dict, new: dict) -> dict:
    merged = dict(old)
    for key, conditions in new.items():
        if key in merged and (merged[key] is None or conditions is None):
            merged[key] = None
        else:
            merged[key] = merged.get(key, frozenset()) | conditions if conditions is not None else None
    return merged


class _ScopedNormalizer:
    def normalize(
        self,
        unit: ScopedFunctionUnit,
        configured_call_effects: ConfiguredFunctionCallEffectEvidenceV4 | None = None,
        **options,
    ) -> NormalizedFunction:
        """Normalize to a fixed point of two facts: memory reads whose value a
        projection may not use (``_blocked_reads``, grows on validation
        failures) and uncertain-address writers (``_uncertain``: may-alias
        debts on every read they may reach; their debts can make more writes
        uncertain). Both only grow, so this ends."""
        from .function_summary import uncertain_writers_of

        blocked, sites, bounds, uncertain = frozenset(), frozenset(), frozenset(), {}
        while True:
            result = self._normalize_once(
                unit, configured_call_effects, _blocked_reads=blocked, _blocked_sites=sites,
                _blocked_bounds=bounds, _uncertain=uncertain, **options)
            if type(result) is _Retry:
                blocked |= result.failed
                sites |= result.sites
                bounds |= result.bounds
                uncertain = _merge_uncertain(uncertain, result.uncertain)
                continue
            reached = dict(result.uncertain_writers)  # its own fixed point (``_normalize_once``)
            merged = _merge_uncertain(reached, uncertain_writers_of(result, unit.observation))
            if merged == reached:
                return result
            uncertain = merged

    def _normalize_once(
        self,
        unit: ScopedFunctionUnit,
        configured_call_effects: ConfiguredFunctionCallEffectEvidenceV4 | None = None,
        *,
        opaque_value_provider: OpaqueValueEvidenceProvider | None = None,
        assumed_call_effects: dict[str, AssumedCallEffect] | None = None,
        proven_call_effects: dict[str, ProvenCallEffect] | None = None,
        assume_globals_disjoint_from_stack: bool = False,
        readonly_image=None,
        assume_direction_flag_clear: bool = False,
        private_frame_above: int = 0,
        _blocked_reads: frozenset = frozenset(),
        _blocked_sites: frozenset = frozenset(),
        _blocked_bounds: frozenset = frozenset(),
        _uncertain: dict | None = None,
        open_conditions: dict | None = None,
    ) -> NormalizedFunction | _Retry:
        """``_blocked_reads``: values read from memory that a projection may not
        use (``relative_memory.stale_reads``; set by the validation below).
        ``_uncertain``: uncertain-address writers (see ``normalize``)."""
        _uncertain = _uncertain or {}
        assumed_call_effects = dict(assumed_call_effects or {})
        proven_call_effects = dict(proven_call_effects or {})
        if any(
            type(key) is not str or type(row) is not ProvenCallEffect
            for key, row in proven_call_effects.items()
        ) or set(proven_call_effects) & set(assumed_call_effects):
            raise TypeError("proven call effects map distinct call keys to ProvenCallEffect")
        if any(
            type(key) is not str or type(row) is not AssumedCallEffect
            for key, row in assumed_call_effects.items()
        ):
            raise TypeError("assumed call effects map operation keys to AssumedCallEffect")
        observation = unit.observation
        if observation is None:
            raise AssertionError("scoped normalization requires an admitted observation")
        context = unit.scopes.resolution_context
        function = unit.scopes.function
        if type(function) is not ConstructedFunctionScope:
            raise AssertionError("scoped normalization requires a constructed function scope")
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
        # x86 rep movs/stos sites (``rep_strings``): one straight block each; the
        # element accesses appear once the count and direction are proven
        # (re-normalized here; the plan only grows)
        sites = rep_sites(observation)
        rep_plan: dict = {}
        rep_used: dict = {}  # memory values the rep proofs used (validated at the end)
        direction_assumed = False
        while True:
            dependencies = RustworkxDependencyGraph()
            effects: list[ObservedEffect] = []
            staged_temporaries: list = []
            anchored_call_accesses: dict = {}
            call_transitions = {
                row.call_operation_key: row.memory_transition
                for row in observed_call_state_projections(observation)
            } if proven_call_effects else {}
            operation_nodes: dict[str, NodeId] = {}
            constant_inputs: dict[str, list[tuple[int, NodeId]]] = {}

            block_graph = build_pcode_block_graph(observation, function.entry, frozenset(sites))
            if block_graph.unsupported is not None:
                raise AssertionError("admitted normalization has unsupported p-code flow")
            operation_blocks = {
                (block.instruction, ordinal): block.key
                for block in block_graph.blocks
                for ordinal in range(block.start, block.stop)
            }
            once_keys = single_execution_keys(observation, block_graph, frozenset(sites))
            once_blocks = single_execution_blocks(observation, block_graph, frozenset(sites))
            accessor_states = _accessor_states(observation, block_graph, _coordinate_key(function.entry),
                                               proven_call_effects, assumed_call_effects, once_blocks)
            wild_objects: set = set()
            fresh_objects: set = set()
            nonstack_objects: set = set()
            pointer_rows: dict = {}
            value_inputs: dict = {}
            address_metadata: dict = {"objects": {}, "atoms": {}}
            fresh_rows = frozenset(
                f"{key}~{index}"
                for key, effect in proven_call_effects.items() if effect.fresh_registers
                for index, run in enumerate(effect.runs)
                if run.writes and all(span in effect.fresh_registers for span in run.writes)
            )
            same_object_rows = _same_object_rows(proven_call_effects, observation)
            for instruction in sorted(observation.instructions, key=lambda item: item.address):
                for ordinal, operation in enumerate(instruction.operations):
                    operation_key = _operation_key(instruction, ordinal, operation)
                    operation_nodes[operation_key] = dependencies.add_node(
                        NodeRecord(f"op:{operation_key}", NodeKind.OPERATION, operation.opcode)
                    )
                    operation_node = operation_nodes[operation_key]
                    effect = _scoped_effect(instruction, ordinal, operation, context)
                    if operation_key in assumed_call_effects:
                        effect = _assumed_call_writes(
                            effect, assumed_call_effects[operation_key], operation, context,
                            _register_space_id(observation),
                        )
                    block_key = operation_blocks.get((instruction.address, ordinal))
                    if block_key is not None and block_key != effect.block_key:
                        # an operation in a p-code sub-block of an instruction with
                        # internal control flow (pcode_blocks)
                        effect = replace(effect, block_key=block_key)
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
                    if block_key is not None and operation_key in proven_call_effects:
                        # the callee's proven effects, placed just before the CALL so
                        # their writes survive it (the call preserves them, see
                        # call_clobber); every run reads the values at the call
                        rows, anchored = _proven_call_rows(
                            operation_key, proven_call_effects[operation_key], block_key,
                            function.scope, _register_space_id(observation) or _program_register_space(unit),
                            call_transitions, staged_temporaries,
                            _call_stack_span(operation_key, proven_call_effects[operation_key],
                                             call_transitions, observation, context),
                            pointer_rows, value_inputs, accessor_states.get(operation_key, (None,))[0],
                        )
                        for row in rows:
                            operation_nodes[row.operation_key] = dependencies.add_node(NodeRecord(
                                f"op:{row.operation_key}", NodeKind.OPERATION,
                                _CALL_EFFECT_LABELS[row.operation_key.rsplit("~", 1)[1].rstrip("0123456789")],
                            ))
                            effects.append(row)
                        anchored_call_accesses.update(anchored)
                    if block_key is not None:
                        effects.append(effect)  # operations in unreachable sub-blocks never run
                    site = sites.get(instruction.address)
                    if block_key is not None and site is not None and operation_key == site.store_key \
                            and instruction.address in rep_plan:
                        rows, anchored = _rep_element_rows(
                            site, rep_plan[instruction.address], block_key, function.scope, context,
                            staged_temporaries,
                        )
                        for row in rows:
                            operation_nodes[row.operation_key] = dependencies.add_node(NodeRecord(
                                f"op:{row.operation_key}", NodeKind.OPERATION, "REP_ELEMENT"))
                            effects.append(row)
                        anchored_call_accesses.update(anchored)

            call_effects = None
            if configured_call_effects is None:
                raw_call_ports = derive_raw_call_ports(call_seeds, context)
                call_effects = unavailable_call_effect_evidence(
                    call_seeds,
                    raw_ports=raw_call_ports,
                )

            predecessors: dict[str, set[str]] = {block.key: set() for block in block_graph.blocks}
            for block in block_graph.blocks:
                for successor in block.successors:
                    if successor in predecessors:
                        predecessors[successor].add(block.key)
            effects_by_block: dict[str, list[ObservedEffect]] = {
                block.key: [] for block in block_graph.blocks
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
                tuple(sorted(block.key for block in block_graph.blocks if not block.successors)),
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
            # Each productive pass resolves at least one unresolved access, so the
            # number of passes is bounded by those accesses (+1 for the fixed point).
            projection_budget = 3 + sum(
                (effect.memory_read is not None) + (effect.memory_write is not None)
                for block in effect_unit.blocks
                for effect in block.effects
            )
            # definition atoms (``relative_memory``) only fill what the ordinary
            # fixed point leaves without an address: first that fixed point,
            # then on to the next with them
            atoms_on = False
            used_reads: dict = {}  # memory values the projections used (validated at the end)
            # last stage: values behind writes still without an address are used
            # (``settle_pending``); undone if it gives one of those writes an address
            settle, settled_at = True, None
            while True:
                if projection_budget <= 0:
                    raise AssertionError("relative-memory projection did not reach a fixed point")
                projection_budget -= 1
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
                    anchored_accesses=anchored_call_accesses,
                    readonly_image=readonly_image,
                    operation_overrides=_rep_overrides(sites, rep_plan, observation),
                    once_keys=once_keys if atoms_on else None,
                    wild_objects=wild_objects,
                    fresh_keys=fresh_rows,
                    same_object=same_object_rows,
                    fresh_objects=fresh_objects,
                    pointer_rows=pointer_rows,
                    nonstack_objects=nonstack_objects,
                    once_blocks=once_blocks,
                    settle_pending=settle,
                    address_metadata=address_metadata,
                    blocked_reads=_blocked_reads,
                    used_reads=used_reads,
                )
                if projected_effect_unit is effect_unit:
                    # (accessor keys need atoms on even with nothing run once)
                    if not atoms_on and (once_keys or accessor_states):
                        atoms_on = True
                        continue
                    if settle:
                        pending = _pending_write_keys(effect_unit)
                        if not pending:
                            break
                        settle, settled_at = False, (effect_unit, memory_unit, memory_binding, memory_ssa, pending,
                                                     {key: set(values) for key, values in used_reads.items()},
                                                     [set(wild_objects), set(fresh_objects),
                                                      set(nonstack_objects)])
                        continue
                    if settled_at is not None and settled_at[4] - _pending_write_keys(effect_unit):
                        effect_unit, memory_unit, memory_binding, memory_ssa, _, used_reads, kept = settled_at
                        for current, before in zip((wild_objects, fresh_objects, nonstack_objects), kept):
                            current.clear()
                            current.update(before)
                    break
                effect_unit = projected_effect_unit
                memory_unit = decode_effect_unit(effect_unit)
                memory_binding = build_bound_local_memory_ssa(memory_unit)
                memory_ssa = memory_binding.result
            overrides_now = _rep_overrides(sites, rep_plan, observation)
            proven = _prove_rep_sites({address: site for address, site in sites.items()
                                       if address not in _blocked_sites},
                                      rep_plan, memory_ssa, observation, unit.scopes, overrides_now,
                                      assume_direction_flag_clear, _blocked_reads, rep_used)
            if not proven:
                break
            for address, (count, direction, assumed) in proven.items():
                rep_plan[address] = (count, direction)
                direction_assumed = direction_assumed or assumed
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
        below_bounds = tuple(row for row in _call_below_bounds(
            proven_call_effects, call_transitions, effect_unit, memory_ssa, observation, unit.scopes,
            context,
        ) if row[0] not in _blocked_bounds)
        proven_preserved = {key: row.preserved for key, row in proven_call_effects.items()}
        kept_memory = _kept_call_memory(proven_call_effects, memory_ssa, wild_objects, _uncertain)
        for key, (spans, _) in kept_memory.items():
            # a model's memory runs survive its clobber of the rest of memory
            proven_preserved[key] = tuple(proven_preserved[key]) + spans
        for key, object_id, bound in below_bounds:
            # keeps every memory byte this function tracks except its stack below the bound
            proven_preserved[key] = tuple(proven_preserved[key]) + _memory_spans_except_below(
                effect_unit, object_id, bound)
        call_clobber_reads = derive_call_clobber_reads(
            effect_unit, observation, context, assumed_calls=frozenset(assumed_call_effects),
            proven_preserved=proven_preserved,
            memory_keeping=frozenset(
                key for key, row in proven_call_effects.items()
                if row.preserves_memory and not row.clobbers_below
            ),
            unrestored_stack_calls=frozenset(
                key for key, row in proven_call_effects.items() if not row.restores_stack
            ),
        )
        call_clobber_nodes = _materialize_call_clobber_debt(
            dependencies,
            memory_ssa,
            call_clobber_reads,
            operation_nodes,
        )
        # summarized calls that never use a received register as an address
        # cannot observe a stack-pointer copy either
        quiet_calls = frozenset(assumed_call_effects) | frozenset(
            key for key, row in proven_call_effects.items() if not row.observes_registers
        )
        # an external model declaring the registers it observes
        observed_calls = {
            key: frozenset(offset for span in row.observed_registers for offset in range(span.start, span.end))
            for key, row in proven_call_effects.items()
            if row.observes_registers and row.observed_registers is not None
        }
        # calls that may leave a stack-pointer-derived value out of sight
        # (``ProvenCallEffect.escapes_stack``): stack escapes whatever is tainted
        escaping_calls = frozenset(key for key, row in proven_call_effects.items() if row.escapes_stack)
        # calls with no proven effect (opaque-callees-leave-no-stack-addresses)
        opaque_calls = _opaque_calls(observation, proven_call_effects, assumed_call_effects)
        frame_uses: list = []
        opaque_uses: list = []
        private_writes = private_frame_writes(
            effect_unit, observation, context, address_spaces,
            assumed_calls=quiet_calls, observed_calls=observed_calls, private_above=private_frame_above,
            uses=frame_uses, escaping_calls=escaping_calls, opaque_calls=opaque_calls, opaque_uses=opaque_uses,
        )
        # uncertain-address writers to their fixed point here: only the
        # may-alias rows and their debt nodes depend on them (a copy of the
        # graph so far per round), the rest of the normalization does not
        from types import SimpleNamespace

        from .function_summary import uncertain_writers_of

        # accessor-result-separate (docs 25.20 D): (result object, start, end,
        # slot span) pairs, from the keys used -- each validated below with them
        separations = accessor_separations(
            effect_unit, observation, context, address_spaces, memory_ssa, used_reads,
            translation_namespace=unit.scopes.program.evidence.translation_namespace.language_id,
            operation_overrides=_rep_overrides(sites, rep_plan, observation),
            opaque_value_provider=opaque_value_provider, readonly_image=readonly_image,
            once_keys=once_keys, fresh_keys=fresh_rows, same_object=same_object_rows,
            pointer_rows=pointer_rows, once_blocks=once_blocks,
        ) if any(type(key[0]) is tuple for key in used_reads) else ()
        open_nodes = _materialize_open_conditions(
            dependencies, memory_ssa, proven_call_effects, open_conditions or {}, operation_nodes)
        opaque_nodes = _materialize_opaque_call_writes(dependencies, memory_ssa, proven_call_effects,
                                                       operation_nodes)
        base = dependencies
        all_effects = tuple(effect for block in effect_unit.blocks for effect in block.effects)
        anchors = tuple(sorted(
            ((key, anchored[0], anchored[1]) for key, anchored in anchored_call_accesses.items()),
            key=lambda item: item[0]))
        while True:
            may_alias_reads = derive_may_alias_reads(
                effect_unit, observation, context, address_spaces,
                assumed_calls=quiet_calls,
                assume_globals_disjoint_from_stack=assume_globals_disjoint_from_stack,
                wild_objects=frozenset(wild_objects),
                fresh_objects=frozenset(fresh_objects),
                nonstack_objects=frozenset(nonstack_objects),
                observed_calls=observed_calls,
                escaping_calls=escaping_calls, opaque_calls=opaque_calls, opaque_uses=opaque_uses,
                private_above=private_frame_above,
                uncertain_writers=frozenset(_uncertain),
                no_kill_writers=frozenset(key for key, conditions in _uncertain.items() if conditions is None),
                uses=frame_uses, separations=separations,
            )
            dependencies = base.copy()
            may_alias_nodes, uncertain_nodes = _materialize_may_alias_debt(
                dependencies,
                memory_ssa,
                may_alias_reads,
                operation_nodes,
                _uncertain,
            )
            view = SimpleNamespace(
                dependencies=dependencies, memory_ssa=memory_ssa, effects=all_effects, scopes=unit.scopes,
                may_alias_reads=may_alias_reads, may_alias_nodes=may_alias_nodes,
                call_clobber_reads=call_clobber_reads, call_clobber_nodes=call_clobber_nodes,
                uncertain_writers=tuple(_uncertain.items()), uncertain_nodes=uncertain_nodes, call_anchors=anchors,
                open_nodes=open_nodes, opaque_nodes=opaque_nodes,
            )
            grown = _merge_uncertain(_uncertain, uncertain_writers_of(view, observation))
            if grown == _uncertain:
                break
            _uncertain = grown
        if any(set(rows) & set(_uncertain) for _, rows in kept_memory.values()):
            # a kept run's write turned out uncertain-address: its place may be
            # another, so the call keeps nothing there -- normalize again
            return _Retry(frozenset(), uncertain=_uncertain)
        # every value read from memory that an address, a definition atom or a rep
        # count was built on must be the value the final state gives that read
        # (no write that got its address later changed what reaches it); a rep
        # count also must carry no debt (a write through another object or a
        # call may have changed it, and the expansion has no condition to carry
        # that). Otherwise normalize again without those reads. (An address
        # built on a read with debt is an uncertain-address writer instead:
        # ``function_summary._uncertain_address_writers``.)
        debt_readers = {row.operation_key for row in call_clobber_reads} | {
            row.operation_key for row in may_alias_reads}
        failed = {key for key, _ in rep_used} & debt_readers
        failed |= stale_reads(
            effect_unit, observation, context, address_spaces, memory_ssa, used_reads,
            translation_namespace=unit.scopes.program.evidence.translation_namespace.language_id,
            operation_overrides=_rep_overrides(sites, rep_plan, observation),
            opaque_value_provider=opaque_value_provider, readonly_image=readonly_image,
            once_keys=once_keys, fresh_keys=fresh_rows, same_object=same_object_rows,
            pointer_rows=pointer_rows, once_blocks=once_blocks,
        )
        failed |= stale_reads(
            effect_unit, observation, context, address_spaces, memory_ssa, rep_used, bare=True,
            translation_namespace=unit.scopes.program.evidence.translation_namespace.language_id,
            operation_overrides=_rep_overrides(sites, rep_plan, observation),
        )
        # a same-result atom (docs 25.20) rests on its whole key: recomputed on
        # the final state above (``stale_reads``), and no debt on any value its
        # ``~sr`` row reads (inputs, slot base, slot load -- transitively)
        same_result_used = sorted({key[0] for key in used_reads if type(key[0]) is tuple})
        for _, _, reader in same_result_used:
            node = operation_nodes.get(reader)
            if node is None or _row_reaches_debt(dependencies, node):
                failed.add(reader)
        failed -= _blocked_reads
        # a rep expansion has no condition to carry: its count and direction
        # must reach no debt on the final graph (memory, call clobber,
        # unresolved -- also through registers a call may have changed); a
        # call-clobber debt on the direction flag alone is covered by
        # direction-flag-clear (DF clear when a call returns), reported as used
        failed_sites = set()
        for address in rep_plan:
            site = sites[address]
            if _reaches_debt(dependencies, operation_nodes.get(site.count_key), site.count, context):
                failed_sites.add(address)
                continue
            node = operation_nodes.get(site.direction_key)
            debts = _debt_nodes(dependencies, node, site.direction, context)
            if debts is None:
                failed_sites.add(address)
            elif debts:
                # direction-flag-clear: DF is 0 when a call returns -- the flag
                # is then 0 (forward) at the site only if every debt is a call
                # possibly changing DF itself (nothing assigned after it)
                flag = _resolve_validated_storage(_storage_ref(site.direction), context)
                spans = dict(zip(call_clobber_nodes, (row.spans for row in call_clobber_reads)))
                if assume_direction_flag_clear and rep_plan[address][1] == 1 \
                        and type(flag) is ResolvedStorage and all(
                            debt in spans and all(flag.span.contains(span) for span in spans[debt])
                            for debt in debts):
                    direction_assumed = True
                else:
                    failed_sites.add(address)
        failed_sites = frozenset(failed_sites)
        # a call's below-stack bound rests on its stack pointer at the call
        # (``~sp`` row): with debt there, that bound may be another
        failed_bounds = frozenset(
            key for key, _, _ in below_bounds
            if operation_nodes.get(f"{key}~sp") is not None
            and _row_reaches_debt(dependencies, operation_nodes[f"{key}~sp"])
        )
        if failed or failed_sites or failed_bounds:
            return _Retry(frozenset(failed), failed_sites, failed_bounds)
        control_dependences = derive_control_dependences(observation, function.entry)
        for row in control_dependences:
            dependencies.add_edge(
                operation_nodes[row.decision],
                operation_nodes[row.dependent],
                EdgeRecord(CONTROL_DEPENDENCE_EDGE, operation=row.decision),
            )
        for address, (count, _) in rep_plan.items():
            # element rows run once per iteration: like the loop body, they
            # depend on the count test
            site = sites[address]
            for index in range(1, count):
                for key in site.element_keys:
                    dependencies.add_edge(
                        operation_nodes[site.branch_key], operation_nodes[f"{key}~e{index}"],
                        EdgeRecord(CONTROL_DEPENDENCE_EDGE, operation=site.branch_key),
                    )
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
            call_clobber_reads=call_clobber_reads,
            call_clobber_nodes=call_clobber_nodes,
            may_alias_reads=may_alias_reads,
            may_alias_nodes=may_alias_nodes,
            control_dependences=control_dependences,
            assumed_call_effects=tuple(sorted(assumed_call_effects.items())),
            proven_call_effects=tuple(sorted(proven_call_effects.items())),
            assumes_globals_disjoint_from_stack=assume_globals_disjoint_from_stack,
            assumes_entry_values_not_frame=any(frame_uses),
            assumes_opaque_callees_leave_no_stack_addresses=any(opaque_uses),
            call_below_bounds=below_bounds,
            assumes_readonly_image_constant=readonly_image is not None,
            assumes_import_slots_hold_exports=_import_slots_used(memory_ssa),
            rep_blocks=tuple(sorted((_coordinate_key(address), count, direction)
                                    for address, (count, direction) in rep_plan.items())),
            operation_overrides=tuple(sorted(_rep_overrides(sites, rep_plan, observation).items())),
            assumed_direction_flag_clear=direction_assumed,
            private_frame_writes=private_writes,
            wild_objects=frozenset(wild_objects),
            fresh_rows=fresh_rows,
            same_object_rows=tuple(sorted(
                ((row, reader, argument) for row, (reader, argument) in same_object_rows.items()),
                key=lambda item: item[0])),
            pointer_rows=tuple(sorted(pointer_rows.items(), key=lambda item: item[0])),
            call_value_inputs=tuple(sorted(value_inputs.items())),
            address_objects=tuple(address_metadata["objects"].items()),
            address_atoms=tuple(address_metadata["atoms"].items()),
            uncertain_writers=tuple(sorted(
                ((key, conditions) for key, conditions in _uncertain.items()), key=lambda item: item[0])),
            call_anchors=anchors,
            uncertain_nodes=uncertain_nodes,
            open_nodes=open_nodes, opaque_nodes=opaque_nodes,
            kept_call_memory=tuple(sorted((key, spans) for key, (spans, _) in kept_memory.items())),
            accessor_separations=separations,
            same_result_uses=tuple(
                (row, pointer_rows[row][1], tuple(sorted(accessor_states[row.rsplit("~", 1)[0]][1])),
                 next(iter(values)))
                for (key, _), values in sorted(used_reads.items(), key=lambda item: repr(item[0]))
                if type(key) is tuple for _, row, _ in (key,)),
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
                        EdgeRecord(kind=EdgeKind.CONTROL),
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
                    kind=EdgeKind.VALUE_INPUT,
                    operation=action.operation_key,
                    occurrence=input_ordinal,
                ),
            )


def _assumed_call_writes(effect, assumed, operation, context, space_id):
    """TEST-ONLY: a declared boundary call strongly writes exactly its registers."""
    if operation.opcode in ("BRANCH", "CBRANCH", "BRANCHIND"):
        if assumed.writes:
            raise ValueError("a tail-called boundary cannot have declared writes")
    elif operation.opcode == "CALLOTHER":
        if assumed.writes or assumed.reads:  # only no-effect user ops (``pcodeop_models``)
            raise ValueError("a declared CALLOTHER has no reads or writes")
    elif operation.opcode not in ("CALL", "CALLIND"):
        raise ValueError("assumed call effects apply only to calls, tail calls and no-effect user ops")
    if space_id is None:
        raise ValueError("assumed call effects need one register space")
    def resolve(rows):
        spans = []
        for row in rows:
            resolved = _resolve_validated_storage(
                StorageRef(VarnodeKind.REGISTER, "", row.byte_offset, row.byte_size,
                           space_id=space_id),
                context,
            )
            if type(resolved) is not ResolvedStorage:
                raise ValueError("assumed call storage does not resolve to a register")
            spans.append(resolved)
        return tuple(spans)

    return replace(
        effect,
        reads=effect.reads + resolve(assumed.reads),
        writes=effect.writes + resolve(assumed.writes),
    )


def _intra_instruction_flow_failure(observation, entry) -> NormalizationFailureReason | None:
    """In-instruction p-code flow is modelled as p-code blocks (pcode_blocks);
    only shapes they cannot express are a typed failure."""
    if build_pcode_block_graph(observation, entry).unsupported is not None:
        return NormalizationFailureReason.UNSUPPORTED_INTRA_INSTRUCTION_FLOW
    return None


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


_KIND_MAP = {
    VarnodeKindCode.CONSTANT: VarnodeKind.CONSTANT,
    VarnodeKindCode.REGISTER: VarnodeKind.REGISTER,
    VarnodeKindCode.UNIQUE: VarnodeKind.UNIQUE,
    VarnodeKindCode.ADDRESS: VarnodeKind.ADDRESS,
    VarnodeKindCode.STORAGE: VarnodeKind.STORAGE,
    VarnodeKindCode.OPAQUE: VarnodeKind.UNKNOWN,
}


def _materialize_call_clobber_debt(
    dependencies: RustworkxDependencyGraph,
    memory_ssa: LocalMemorySsaResult,
    reads: tuple[CallClobberRead, ...],
    operation_nodes: dict[str, NodeId],
) -> tuple[NodeId, ...]:
    """One debt node per read that may observe an unevidenced call's write."""
    if not reads:
        return ()
    namespace = (
        f"call-clobber-v1:{memory_ssa.function_scope.digest.hex()}:"
        f"{memory_ssa.unit_digest.hex()}"
    )
    dependencies.claim_namespace(namespace)
    nodes = []
    for row in reads:
        node = dependencies.add_node(
            NodeRecord(
                f"{namespace}:{row.operation_key}",
                NodeKind.MEMORY_DEBT,
                "call_clobber_read",
            )
        )
        dependencies.add_edge(
            node,
            operation_nodes[row.operation_key],
            EdgeRecord(EdgeKind.CALL_CLOBBER_READ, operation=row.operation_key),
        )
        nodes.append(node)
    return tuple(nodes)


def _import_slots_used(memory_ssa) -> bool:
    from .relative_memory import IMPORT_SLOTS

    imports = IMPORT_SLOTS.get()
    return imports is not None and memory_ssa is not None and memory_ssa.function_scope in imports.used


def _materialize_open_conditions(dependencies, memory_ssa, proven_call_effects, open_conditions,
                                 operation_nodes) -> tuple:
    """An "open_condition" debt on each run row ``{call}~{i}`` whose run
    carries pairs of ``open_conditions``: (node, pairs) rows."""
    if not open_conditions:
        return ()
    namespace = f"open-condition-v1:{memory_ssa.function_scope.digest.hex()}:{memory_ssa.unit_digest.hex()}"
    dependencies.claim_namespace(namespace)
    found = []
    for call, effect in sorted(proven_call_effects.items()):
        located = open_conditions.get(call)
        if not located:
            continue
        for index, run in enumerate((*effect.runs, *effect.memory_runs)):
            pairs = frozenset(located[pair] for pair in run.conditions if pair in located)
            row = operation_nodes.get(f"{call}~{index}")
            if not pairs or row is None:
                continue
            node = dependencies.add_node(NodeRecord(f"{namespace}:{call}~{index}", NodeKind.MEMORY_DEBT,
                                                    "open_condition"))
            dependencies.add_edge(node, row, EdgeRecord(EdgeKind.MAY_ALIAS_READ, operation=f"{call}~{index}"))
            found.append((node, pairs))
    return tuple(found)


def _materialize_opaque_call_writes(dependencies, memory_ssa, proven_call_effects, operation_nodes) -> tuple:
    """An "opaque_call_write" debt on each ``{call}~u{j}`` row: the call wrote
    those bytes with a value its summary or model does not state."""
    keys = [f"{call}~u{index}" for call, effect in sorted(proven_call_effects.items())
            for index in range(len(effect.unknown_memory)) if f"{call}~u{index}" in operation_nodes]
    if not keys:
        return ()
    namespace = f"opaque-call-write-v1:{memory_ssa.function_scope.digest.hex()}:{memory_ssa.unit_digest.hex()}"
    dependencies.claim_namespace(namespace)
    nodes = []
    for key in keys:
        node = dependencies.add_node(NodeRecord(f"{namespace}:{key}", NodeKind.MEMORY_DEBT, "opaque_call_write"))
        dependencies.add_edge(node, operation_nodes[key], EdgeRecord(EdgeKind.CALL_CLOBBER_READ, operation=key))
        nodes.append(node)
    return tuple(nodes)


def _materialize_may_alias_debt(
    dependencies: RustworkxDependencyGraph,
    memory_ssa: LocalMemorySsaResult,
    reads: tuple[MayAliasRead, ...],
    operation_nodes: dict[str, NodeId],
    uncertain: dict | None = None,
) -> tuple[tuple[NodeId, ...], tuple]:
    """Writer -> debt -> read: possible writers stay reachable as origins.
    Returns (one node per read row, uncertain nodes). Conditional
    uncertain-address writers (``uncertain``: key -> conditions) get a node of
    their own, "uncertain_write_read", without writer edges (under their
    conditions they did not write there); when a row has nothing else, its
    node is that one."""
    uncertain = uncertain or {}
    if not reads:
        return (), ()
    namespace = (
        f"may-alias-v1:{memory_ssa.function_scope.digest.hex()}:"
        f"{memory_ssa.unit_digest.hex()}"
    )
    dependencies.claim_namespace(namespace)
    nodes, uncertain_nodes = [], []
    for row in reads:
        conditional = [writer for writer in row.uncertain if uncertain.get(writer) is not None]
        hard = [writer for writer in row.writers if writer not in conditional or (
            row.plain is not None and writer in row.plain)]
        if conditional:
            pairs = frozenset().union(*(uncertain[writer] for writer in conditional))
            extra = dependencies.add_node(NodeRecord(
                f"{namespace}:{row.operation_key}:uncertain", NodeKind.MEMORY_DEBT, "uncertain_write_read"))
            dependencies.add_edge(
                extra, operation_nodes[row.operation_key],
                EdgeRecord(EdgeKind.MAY_ALIAS_READ, operation=row.operation_key),
            )
            uncertain_nodes.append((extra, pairs))
            if not hard:
                nodes.append(extra)
                continue
        node = dependencies.add_node(
            NodeRecord(
                f"{namespace}:{row.operation_key}",
                NodeKind.MEMORY_DEBT,
                "may_alias_read",
            )
        )
        for writer in hard:
            dependencies.add_edge(
                operation_nodes[writer],
                node,
                EdgeRecord(EdgeKind.MAY_ALIAS_WRITE, operation=writer),
            )
        dependencies.add_edge(
            node,
            operation_nodes[row.operation_key],
            EdgeRecord(EdgeKind.MAY_ALIAS_READ, operation=row.operation_key),
        )
        nodes.append(node)
    return tuple(nodes), tuple(uncertain_nodes)


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


_SELF_CANCELLING = frozenset({"INT_XOR", "INT_SUB", "BOOL_XOR"})


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
    if operation.opcode in _SELF_CANCELLING and len(operation.inputs) == 2             and operation.inputs[0] == operation.inputs[1]             and operation.inputs[0].kind in (VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE):
        # ``xor edx, edx`` / ``sub eax, eax``: zero whatever the register
        # holds -- the result depends on no input (a call before it may have
        # clobbered the register without changing anything here)
        reads = ()
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
    # LOAD/STORE selectors and direct BRANCH/CBRANCH destinations are metadata;
    # the CBRANCH condition remains a data dependency. CALLIND retains its
    # existing call-boundary handling outside this call-free audit.
    return 1 if opcode in {
        "LOAD", "STORE", "CALL", "CALLIND", "CALLOTHER", "BRANCH", "CBRANCH"
    } else 0
