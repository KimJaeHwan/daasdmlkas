"""Internal retained root/source cuts over one complete finite expansion.

This is an exit-qualified candidate query, not an origin proof, cache key,
conditional completion, or public result. Every reached source endpoint must
bind to exact static and executed evidence before reverse traversal begins.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from collections import deque

from ..boundary import BoundaryKind, BoundaryMatch, BoundaryProvider, CallBoundary
from ..call_contracts import DirectCallTarget
from ..call_seeds import _operation_key
from ..memory_contracts import MemoryDefinitionKind
from ..model import StorageObjectKind
from ..physical_state import PhysicalRegisterSlice
from .._scope_contracts import VarnodeKindCode
from .configured_finite_byte_kernel import REVISION as KERNEL_REVISION
from .configured_finite_byte_kernel import SYMBOLIC_REVISION as SYMBOLIC_KERNEL_REVISION
from .configured_finite_context_inputs import (
    ConfiguredFiniteContextRequest, replay_configured_finite_context_request,
)
from .configured_finite_context_scheduler import (
    FiniteExpansion, FinitePathExit, OperationOccurrence, SCHEDULER_REVISION,
    SYMBOLIC_SCHEDULER_REVISION,
)
from .configured_target_resolution import _selected_resolved_target


REVISION = "configured-finite-context-cut-query-v2"
# Historical diagnostic identity only; v2 channel checks apply to both inputs.
LEGACY_REVISION = "configured-finite-context-cut-query-v1"
MAY_REVISION = "configured-finite-context-cut-may-diagnostic-v1"


class CutDebtReason(StrEnum):
    INVALID_INPUT = "invalid_input"
    IDENTITY_MISMATCH = "identity_mismatch"
    ROOT_BINDING = "root_binding"
    SOURCE_BINDING = "source_binding"
    MISSING_ENDPOINT = "missing_endpoint"
    AMBIGUOUS_ENDPOINT = "ambiguous_endpoint"
    RETURN_BYTE_MISMATCH = "return_byte_mismatch"
    LEDGER_MISMATCH = "ledger_mismatch"
    RESOURCE_BOUND = "resource_bound"
    UNSUPPORTED_CHANNEL = "unsupported_channel"
    ADDRESS_SOURCE = "address_source"
    CONTROL_SOURCE = "control_source"
    CONTROL_BINDING = "control_binding"


class FiniteCutIncomplete(RuntimeError):
    def __init__(self, reason: CutDebtReason, detail: str):
        self.reason, self.detail = reason, detail
        super().__init__(f"{reason.value}: {detail}")


def _stop(reason, detail):
    raise FiniteCutIncomplete(reason, detail)


@dataclass(frozen=True, slots=True)
class CutQueryLimits:
    exits: int = 128
    operations: int = 131072
    definitions: int = 262144
    events: int = 262144
    endpoints: int = 4096
    facts: int = 65536
    witness_length: int = 65536
    result_bytes: int = 16777216


@dataclass(frozen=True, slots=True)
class RootCallCut:
    alternative: tuple[int, ...]
    call_operation_key: str
    call_activation: tuple[int, ...]
    demanded_offsets: tuple[int, ...]
    byte_definition_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class SourceReturnCut:
    alternative: tuple[int, ...]
    label: str
    caller_scope_digest: bytes
    call_operation_key: str
    callee_scope_digest: bytes
    write_operation_key: str
    parent_activation: tuple[int, ...]
    child_activation: tuple[int, ...]
    return_operation_key: str
    selected_offsets: tuple[int, ...]
    byte_definition_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ReverseCandidate:
    alternative: tuple[int, ...]
    flow_kind: str  # EXACT_DATA or POTENTIAL_DATA; never public origin status
    sink_offset: int
    sink_definition_id: int
    source: SourceReturnCut
    source_offset: int
    source_definition_id: int
    witness_definition_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class FiniteCutCandidates:
    query_revision: str
    request_digest: bytes
    scheduler_revision: str
    kernel_revision: str
    root_cuts: tuple[RootCallCut, ...]
    source_cuts: tuple[SourceReturnCut, ...]
    candidates: tuple[ReverseCandidate, ...]
    diagnostic_only: bool = True


@dataclass(frozen=True, slots=True)
class MayReverseCandidate:
    """One occurrence-qualified inclusion route, never an exact origin claim."""

    alternative: tuple[int, ...]
    channel: str  # DATA_MAY, ADDRESS_MAY, or CONTROL_ENVELOPE
    confidence: str  # EXACT_DATA or POTENTIAL_DATA along the graph route
    address_crossing: bool
    sink_offset: int
    sink_definition_id: int
    source: SourceReturnCut
    source_offset: int
    source_definition_id: int
    witness_definition_ids: tuple[int, ...]
    guard_operation_key: str | None = None
    guard_activation: tuple[int, ...] | None = None
    guard_occurrence_index: int | None = None
    guard_definition_id: int | None = None


@dataclass(frozen=True, slots=True)
class FiniteMayDiagnostic:
    query_revision: str
    request_digest: bytes
    scheduler_revision: str
    kernel_revision: str
    root_cuts: tuple[RootCallCut, ...]
    source_cuts: tuple[SourceReturnCut, ...]
    candidates: tuple[MayReverseCandidate, ...]
    diagnostic_only: bool = True


@dataclass(frozen=True, slots=True)
class _CallBinding:
    caller_scope: bytes
    key: str
    callee_scope: bytes
    seed_ordinal: int
    boundary: CallBoundary
    matches: tuple


@dataclass(frozen=True, slots=True)
class _SourceStatic:
    binding: _CallBinding
    label: str
    write_key: str
    selector: PhysicalRegisterSlice
    write_ordinal: int
    register_space: int


class _Query:
    def __init__(self, request, expansion, provider, limits):
        if (type(request) is not ConfiguredFiniteContextRequest
                or type(expansion) is not FiniteExpansion
                or not callable(getattr(provider, "classify", None))
                or not callable(getattr(provider, "state", None))
                or type(limits) is not CutQueryLimits):
            _stop(CutDebtReason.INVALID_INPUT, "exact request, expansion, provider and limits required")
        try:
            replay = replay_configured_finite_context_request(request)
        except Exception as error:
            _stop(CutDebtReason.IDENTITY_MISMATCH, f"request replay failed: {error}")
        scheduler_revision, kernel_revision = (
            (SYMBOLIC_SCHEDULER_REVISION, SYMBOLIC_KERNEL_REVISION)
            if request.symbolic_entry is not None else (SCHEDULER_REVISION, KERNEL_REVISION))
        if (replay.input_digest != request.input_digest
                or expansion.request_digest != request.input_digest
                or expansion.root_scope_digest != request.induction.root_scope_digest
                or expansion.scheduler_revision != scheduler_revision
                or expansion.kernel_revision != kernel_revision
                or expansion.root_token_seed.request_digest != request.input_digest
                or expansion.root_token_seed.root_scope_digest != expansion.root_scope_digest
                or expansion.root_token_seed.role != "ENTRY_RAM_SP"):
            _stop(CutDebtReason.IDENTITY_MISMATCH, "expansion/request/seed revision or identity changed")
        defaults = CutQueryLimits()
        for name in CutQueryLimits.__dataclass_fields__:
            value = getattr(limits, name)
            if type(value) is not int or not 0 < value <= getattr(defaults, name):
                _stop(CutDebtReason.RESOURCE_BOUND, f"unsupported {name} limit")
        if (limits.exits > request.limits.cfg_paths
                or limits.definitions > request.limits.graph_nodes
                or limits.events > request.limits.memory_events
                or limits.facts > request.limits.origin_facts
                or limits.witness_length > request.limits.witness_length
                or limits.result_bytes > min(request.limits.cache_bytes,
                                             request.limits.report_bytes)):
            _stop(CutDebtReason.RESOURCE_BOUND, "query limit exceeds prepared request")
        if not expansion.exits or len(expansion.exits) > limits.exits:
            _stop(CutDebtReason.RESOURCE_BOUND, "exit preflight")
        operations = definitions = events = 0
        for exit_ in expansion.exits:
            if type(exit_) is not FinitePathExit:
                _stop(CutDebtReason.INVALID_INPUT, "exact exit rows required")
            operations += len(exit_.operations)
            definitions += len(exit_.definitions)
            events += len(exit_.events)
            if (operations > limits.operations or definitions > limits.definitions
                    or events > limits.events):
                _stop(CutDebtReason.RESOURCE_BOUND, "aggregate exit graph preflight")
        self.request, self.expansion, self.provider, self.limits = request, expansion, provider, limits
        self.by_scope = {row.evidence.unit.scopes.function.scope.digest: row
                         for row in request.analyses}
        self.raw_by_scope_key = {}
        for scope, analysis in self.by_scope.items():
            for instruction in analysis.evidence.unit.observation.instructions:
                for ordinal, operation in enumerate(instruction.operations):
                    key = _operation_key(instruction.address, ordinal, operation.opcode)
                    if (scope, key) in self.raw_by_scope_key:
                        _stop(CutDebtReason.LEDGER_MISMATCH, "duplicate retained raw operation key")
                    self.raw_by_scope_key[(scope, key)] = (instruction, ordinal, operation)
        self.edges = {(row.caller_scope_digest, row.call_operation_key): row.callee_scope_digest
                      for row in request.induction.verified_edges.edges}
        self.returns = {(inventory.function_scope_digest, row.return_operation_key)
                        for inventory in request.induction.inventories
                        for row in inventory.return_tokens}
        self.bindings = self._bind_calls()
        self.root_binding, self.root_offsets = self._bind_root()
        self.sources = self._bind_static_sources()
        if len(self.sources) > self.limits.endpoints:
            _stop(CutDebtReason.RESOURCE_BOUND, "static source endpoint budget")
        self.source_write_sites = frozenset((static.binding.callee_scope, static.write_key)
            for static in self.sources.values() if static is not None)
        self.facts = 0
        self.result_bytes = 0
        self.endpoint_count = 0

    def _charge(self, *, facts=0, result_bytes=0):
        if (self.facts + facts > self.limits.facts
                or self.result_bytes + result_bytes > self.limits.result_bytes):
            _stop(CutDebtReason.RESOURCE_BOUND, "aggregate fact/result budget")
        self.facts += facts
        self.result_bytes += result_bytes

    def _register_space(self):
        spaces = tuple(row.space_id for row in
                       self.request.root_analysis.evidence.unit.scopes.program.evidence.address_spaces
                       if row.is_register_space)
        if len(spaces) != 1:
            _stop(CutDebtReason.ROOT_BINDING, "one observed register space required")
        return spaces[0]

    def _provider_matches(self, boundary):
        try:
            matches = self.provider.classify(boundary)
        except Exception as error:
            _stop(CutDebtReason.SOURCE_BINDING, f"provider classification failed: {error}")
        if (type(matches) is not tuple
                or any(type(row) is not BoundaryMatch
                       or type(row.kind) is not BoundaryKind
                       or type(row.label) is not str or not row.label
                       for row in matches)):
            _stop(CutDebtReason.SOURCE_BINDING, "provider classification must be exact match tuple")
        if len(matches) > self.limits.endpoints:
            _stop(CutDebtReason.RESOURCE_BOUND, "provider classification budget")
        if len({(row.kind, row.label) for row in matches}) != len(matches):
            _stop(CutDebtReason.AMBIGUOUS_ENDPOINT, "duplicate provider classification")
        return matches

    def _provider_state(self, binding, match):
        try:
            return self.provider.state(binding.boundary, match)
        except Exception as error:
            _stop(CutDebtReason.SOURCE_BINDING, f"provider physical state failed: {error}")

    def _bind_calls(self):
        rows = {}
        for analysis in self.request.analyses:
            scope = analysis.evidence.unit.scopes.function.scope.digest
            seeds = analysis.evidence.seeds.callsites
            naming = analysis.evidence.naming
            if naming is None or len(seeds) != len(naming.rows):
                _stop(CutDebtReason.SOURCE_BINDING, "caller naming/seed inventory mismatch")
            for ordinal, (seed, named) in enumerate(zip(seeds, naming.rows, strict=True)):
                edge_scope = self.edges.get((scope, seed.operation_key))
                if edge_scope is None:
                    continue
                target = _selected_resolved_target(named)
                if (type(seed.target) is not DirectCallTarget or target is None
                        or target.is_external or edge_scope not in self.by_scope
                        or target.coordinate != self.by_scope[edge_scope].entry
                        or seed.target.coordinate != target.coordinate
                        or named.instruction != seed.locator.instruction
                        or named.operation_ordinal != seed.locator.operation_ordinal):
                    _stop(CutDebtReason.SOURCE_BINDING, "verified direct edge has no exact named seed")
                aliases = tuple(sorted({alias.value for alias in target.aliases
                                        if alias.policy_admissible}))
                boundary = CallBoundary(
                    f"{analysis.entry.space_id:x}:{analysis.entry.byte_offset:x}",
                    seed.operation_key, aliases,
                    analysis.evidence.unit.scopes.program.evidence.translation_namespace.language_id)
                matches = self._provider_matches(boundary)
                rows[(scope, seed.operation_key)] = _CallBinding(scope, seed.operation_key,
                    edge_scope, ordinal, boundary, matches)
        if set(rows) != set(self.edges):
            _stop(CutDebtReason.SOURCE_BINDING, "verified edge lacks bound direct call")
        return rows

    def _bind_root(self):
        request = self.request
        root = request.local_slice.root
        seeds = request.root_analysis.evidence.seeds.callsites
        if root.occurrence_ordinal >= len(seeds):
            _stop(CutDebtReason.ROOT_BINDING, "root occurrence lacks call seed")
        seed = seeds[root.occurrence_ordinal]
        binding = self.bindings.get((request.induction.root_scope_digest, seed.operation_key))
        if binding is None:
            _stop(CutDebtReason.ROOT_BINDING, "root sink lacks verified direct CALL")
        matches = tuple(row for row in binding.matches
                        if row.kind is BoundaryKind.SINK and row.label == root.label)
        if len(matches) != 1:
            _stop(CutDebtReason.ROOT_BINDING, "root sink is absent or ambiguous in provider")
        selectors = self._provider_state(binding, matches[0])
        if (type(selectors) is not tuple or len(selectors) != 1
                or type(selectors[0]) is not PhysicalRegisterSlice):
            _stop(CutDebtReason.ROOT_BINDING, "first slice needs one physical register selector")
        selector = selectors[0]
        demand = request.demanded_spans
        if (any(row.object_id.kind is not StorageObjectKind.REGISTER_FILE
                or row.object_id.scope != request.root_analysis.evidence.unit.scopes.program.scope
                for row in demand)
                or tuple(offset for row in demand for offset in range(row.start, row.end))
                != tuple(range(selector.byte_offset, selector.byte_offset + selector.byte_size))):
            _stop(CutDebtReason.ROOT_BINDING, "requested root bytes differ from provider selector")
        root_memory = request.root_analysis.normalized.memory_ssa
        if (root_memory is None
                or not any(action.operation_key == seed.operation_key
                           for action in root_memory.actions)):
            _stop(CutDebtReason.ROOT_BINDING, "root sink CALL lacks normalized action")
        return binding, tuple(range(selector.byte_offset,
                                    selector.byte_offset + selector.byte_size))

    def _bind_static_sources(self):
        by_site = {}
        register_space = self._register_space()
        for binding in self.bindings.values():
            callee = self.by_scope[binding.callee_scope]
            for match in binding.matches:
                if match.kind is not BoundaryKind.SOURCE:
                    continue
                origins = tuple(row for row in callee.boundaries.report_origins
                                if row.label == match.label
                                and row.occurrence_ordinal == binding.seed_ordinal)
                if not origins:
                    by_site[(binding.caller_scope, binding.key, match.label)] = None
                    continue
                if len(origins) != 1:
                    _stop(CutDebtReason.AMBIGUOUS_ENDPOINT,
                          "source call has multiple static terminal projections")
                selectors = self._provider_state(binding, match)
                if (type(selectors) is not tuple or len(selectors) != 1
                        or type(selectors[0]) is not PhysicalRegisterSlice):
                    _stop(CutDebtReason.SOURCE_BINDING, "source needs one physical return selector")
                selector = selectors[0]
                memory = callee.normalized.memory_ssa
                graph = callee.normalized.memory_graph
                if memory is None or graph is None:
                    _stop(CutDebtReason.SOURCE_BINDING, "source local memory SSA absent")
                indices = tuple(i for i, node in enumerate(graph.definition_nodes)
                                if node == origins[0].node)
                if len(indices) != 1:
                    _stop(CutDebtReason.SOURCE_BINDING, "source node is not one static definition")
                definition = memory.definitions[indices[0]]
                if (definition.kind is not MemoryDefinitionKind.DATA_WRITE
                        or definition.span.object_id.kind is not StorageObjectKind.REGISTER_FILE
                        or definition.span.start > selector.byte_offset
                        or definition.span.end < selector.byte_offset + selector.byte_size):
                    _stop(CutDebtReason.SOURCE_BINDING, "source is not a covering DATA_WRITE")
                raw = self.raw_by_scope_key.get((binding.callee_scope, definition.operation_key))
                if raw is None:
                    _stop(CutDebtReason.SOURCE_BINDING, "source write lacks one raw operation")
                _, ordinal, operation = raw
                output = operation.output
                if (output is None or output.kind is not VarnodeKindCode.REGISTER
                        or output.coordinate.space_id != register_space
                        or output.coordinate.byte_offset > selector.byte_offset
                        or output.coordinate.byte_offset + output.byte_size
                           < selector.byte_offset + selector.byte_size):
                    _stop(CutDebtReason.SOURCE_BINDING, "raw source output misses selected return bytes")
                key = (binding.caller_scope, binding.key, match.label)
                by_site[key] = _SourceStatic(binding, match.label, definition.operation_key,
                                             selector, ordinal, register_space)
        return by_site

    def _validate_exit(self, exit_):
        defs, events, operations = exit_.definitions, exit_.events, exit_.operations
        if any(row.node != i for i, row in enumerate(defs)):
            _stop(CutDebtReason.LEDGER_MISMATCH, "byte definition IDs are not contiguous")
        for row in defs:
            if any(kind not in {"DATA", "POTENTIAL_DATA", "ADDRESS"}
                   or not 0 <= target < row.node for kind, target in row.edges):
                _stop(CutDebtReason.LEDGER_MISMATCH, "invalid definition edge or channel")
        claimed_def, claimed_event = set(), set()
        initial_latest = {}
        prior_definition = prior_event = -1
        for row in operations:
            if type(row) is not OperationOccurrence:
                _stop(CutDebtReason.LEDGER_MISMATCH, "exact operation ledger required")
            raw = self.raw_by_scope_key.get((row.function_scope_digest, row.operation_key))
            if (raw is None or raw[0].address != row.instruction
                    or raw[1] != row.operation_ordinal
                    or not exit_.alternative[:len(row.alternative_prefix)]
                       == row.alternative_prefix):
                _stop(CutDebtReason.LEDGER_MISMATCH, "ledger operation differs from retained raw observation")
            for node in row.definition_ids:
                if (not 0 <= node < len(defs) or node in claimed_def
                        or node <= prior_definition
                        or (defs[node].operation_ordinal >= 0
                            and (defs[node].operation_ordinal != row.operation_ordinal
                                 or defs[node].occurrence != row.activation))):
                    _stop(CutDebtReason.LEDGER_MISMATCH, "definition does not bind operation occurrence")
                claimed_def.add(node)
                prior_definition = node
            for event in row.event_ids:
                if (not 0 <= event < len(events) or event in claimed_event
                        or event <= prior_event
                        or events[event].operation_ordinal != row.operation_ordinal
                        or events[event].occurrence != row.activation):
                    _stop(CutDebtReason.LEDGER_MISMATCH, "event does not bind operation occurrence")
                claimed_event.add(event)
                prior_event = event
        unclaimed = tuple(i for i in range(len(defs)) if i not in claimed_def)
        if (unclaimed != tuple(range(len(unclaimed)))
                or any(defs[i].operation_ordinal >= 0 for i in unclaimed)
                or len(claimed_event) != len(events)):
            _stop(CutDebtReason.LEDGER_MISMATCH, "unbound or late initial byte/event")
        for i in unclaimed:
            initial_latest[defs[i].storage] = i
        return initial_latest

    def _walk_calls(self, exit_):
        root_activation = (0,)
        stack = [root_activation]
        pending = None
        root_return_seen = False
        children, returns = {}, {}
        for index, row in enumerate(exit_.operations):
            if pending is not None:
                call_index, parent_activation, callee_scope = pending
                if (row.activation[:-1] != parent_activation
                        or len(row.activation) != len(parent_activation) + 1
                        or row.function_scope_digest != callee_scope):
                    _stop(CutDebtReason.LEDGER_MISMATCH, "CALL lacks executed child activation")
                children[call_index] = row.activation
                stack.append(row.activation)
                pending = None
            if row.activation != stack[-1]:
                _stop(CutDebtReason.LEDGER_MISMATCH, "operation outside current activation")
            opcode = row.operation_key.rsplit(":", 1)[-1]
            if opcode == "CALL":
                callee = self.edges.get((row.function_scope_digest, row.operation_key))
                if callee is None or index + 1 >= len(exit_.operations):
                    _stop(CutDebtReason.LEDGER_MISMATCH, "CALL lacks verified child edge")
                pending = (index, row.activation, callee)
            elif opcode == "RETURN":
                if (row.function_scope_digest, row.operation_key) not in self.returns:
                    _stop(CutDebtReason.LEDGER_MISMATCH, "RETURN lacks verified normal token")
                if len(stack) == 1:
                    if index != len(exit_.operations) - 1:
                        _stop(CutDebtReason.LEDGER_MISMATCH, "operations after root RETURN")
                    root_return_seen = True
                else:
                    if row.activation in returns:
                        _stop(CutDebtReason.LEDGER_MISMATCH, "duplicate child RETURN")
                    returns[row.activation] = index
                    stack.pop()
        if pending is not None or len(stack) != 1 or not root_return_seen:
            _stop(CutDebtReason.LEDGER_MISMATCH, "unterminated child activation")
        return children, returns

    def _cuts_for_exit(self, exit_, *, occurrence_guards=False):
        latest = self._validate_exit(exit_)
        children, returns = self._walk_calls(exit_)
        register_space = self._register_space()
        root_rows = []
        source_rows = []
        source_nodes = []
        guards = []
        source_for_child = {}
        write_by_activation_key = {}
        for index, row in enumerate(exit_.operations):
            for node in row.definition_ids:
                latest[exit_.definitions[node].storage] = node
            if (row.activation, row.operation_key) in write_by_activation_key:
                write_by_activation_key[(row.activation, row.operation_key)].append(row)
            elif (row.function_scope_digest, row.operation_key) in self.source_write_sites:
                write_by_activation_key[(row.activation, row.operation_key)] = [row]
            opcode = row.operation_key.rsplit(":", 1)[-1]
            if opcode == "CBRANCH" and not root_rows:
                guards.extend((row.operation_key, row.activation, index, node)
                              if occurrence_guards else (row.operation_key, row.activation, node)
                              for node in self._guard_nodes(row, latest))
            if opcode == "CALL" and row.function_scope_digest == self.root_binding.caller_scope \
                    and row.operation_key == self.root_binding.key and row.activation == (0,):
                self._charge(result_bytes=128 + 8 * len(self.root_offsets))
                ids = tuple(latest.get(("register", register_space, offset, ()))
                            for offset in self.root_offsets)
                if any(node is None for node in ids):
                    _stop(CutDebtReason.ROOT_BINDING, "pre-CALL sink byte has no definition")
                root_rows.append(RootCallCut(exit_.alternative, row.operation_key,
                    row.activation, self.root_offsets, ids))
            if opcode == "RETURN" and row.activation in source_for_child:
                for static, call_row in source_for_child.pop(row.activation):
                    if self.endpoint_count >= self.limits.endpoints:
                        _stop(CutDebtReason.RESOURCE_BOUND, "source endpoint budget")
                    self._charge(result_bytes=192 + 8 * static.selector.byte_size)
                    offsets = tuple(range(static.selector.byte_offset,
                                          static.selector.byte_offset + static.selector.byte_size))
                    nodes = tuple(latest.get(("register", static.register_space, offset, ()))
                                  for offset in offsets)
                    writes = write_by_activation_key.get((row.activation, static.write_key), ())
                    if len(writes) != 1:
                        _stop(CutDebtReason.RETURN_BYTE_MISMATCH,
                              "source static write absent or repeated in child activation")
                    write = writes[0]
                    if any(node is None or node not in write.definition_ids
                           or exit_.definitions[node].occurrence != row.activation
                           or exit_.definitions[node].operation_ordinal != static.write_ordinal
                           or exit_.definitions[node].storage !=
                              ("register", static.register_space, offset, ())
                           for offset, node in zip(offsets, nodes, strict=True)):
                        _stop(CutDebtReason.RETURN_BYTE_MISMATCH,
                              "selected child RETURN byte is not latest static source write")
                    self.endpoint_count += 1
                    cut = SourceReturnCut(exit_.alternative, static.label,
                        static.binding.caller_scope, static.binding.key,
                        static.binding.callee_scope, static.write_key,
                        call_row.activation, row.activation,
                        row.operation_key, offsets, nodes)
                    source_rows.append(cut)
                    source_nodes.append((cut, dict(zip(offsets, nodes, strict=True))))
            if opcode != "CALL":
                continue
            binding = self.bindings.get((row.function_scope_digest, row.operation_key))
            if binding is None:
                _stop(CutDebtReason.LEDGER_MISMATCH, "executed CALL lacks static binding")
            for match in binding.matches:
                if match.kind is not BoundaryKind.SOURCE:
                    continue
                static = self.sources.get((binding.caller_scope, binding.key, match.label))
                if static is None:
                    _stop(CutDebtReason.MISSING_ENDPOINT, "reached SOURCE lacks one static terminal")
                child = children.get(index)
                return_index = None if child is None else returns.get(child)
                if return_index is None or return_index <= index:
                    _stop(CutDebtReason.MISSING_ENDPOINT, "reached SOURCE lacks child normal RETURN")
                source_for_child.setdefault(child, []).append((static, row))
        if len(root_rows) != 1:
            _stop(CutDebtReason.ROOT_BINDING, "each feasible root exit needs one selected sink CALL")
        if tuple(sorted(latest.items())) != exit_.latest:
            _stop(CutDebtReason.LEDGER_MISMATCH, "replayed final latest state differs from expansion")
        if source_for_child:
            _stop(CutDebtReason.MISSING_ENDPOINT, "reached SOURCE child did not complete")
        return root_rows[0], tuple(source_rows), tuple(source_nodes), tuple(guards)

    def _guard_nodes(self, row, latest):
        """Bind a guard after any lazy entry-byte materialization, before its fork."""
        operation = self.raw_by_scope_key[(row.function_scope_digest, row.operation_key)][2]
        if len(operation.inputs) != 2 or operation.output is not None:
            _stop(CutDebtReason.CONTROL_BINDING, "unsupported CBRANCH input shape")
        guard = operation.inputs[1]
        self._charge(facts=guard.byte_size)
        if guard.kind is VarnodeKindCode.CONSTANT:
            return ()
        kinds = {VarnodeKindCode.REGISTER: "register", VarnodeKindCode.UNIQUE: "unique",
                 VarnodeKindCode.ADDRESS: "ram"}
        kind = kinds.get(guard.kind)
        if kind is None:
            _stop(CutDebtReason.CONTROL_BINDING, "unsupported branch guard storage")
        activation = row.activation if kind == "unique" else ()
        nodes = tuple(latest.get((kind, guard.coordinate.space_id,
                                 guard.coordinate.byte_offset + offset, activation))
                      for offset in range(guard.byte_size))
        if any(node is None for node in nodes):
            _stop(CutDebtReason.CONTROL_BINDING,
                  f"branch guard lacks latest physical byte: {row.operation_key} {row.activation}")
        return nodes

    def _check_control(self, exit_, guards, sources):
        # Every earlier branch is a conservative superset of the guards which
        # control a root-reaching operation, including constant-valued writes
        # absent from the DATA graph. No postdominator or independence claim is
        # made. Follow ADDRESS as well as DATA inside each guard's provenance.
        targets = {node: source for source, nodes in sources for node in nodes.values()}
        self._charge(facts=len(guards))
        pending = [(node, key, activation, None, 1) for key, activation, node in guards]
        visited = set()
        while pending:
            node, key, activation, parent, depth = pending.pop()
            if node in visited:
                continue
            self._charge(facts=1)
            visited.add(node)
            link = (node, parent)
            if node in targets:
                source = targets[node]
                _stop(CutDebtReason.CONTROL_SOURCE,
                      f"guard {key} {activation} reaches SOURCE {source.label!r} "
                      f"at {source.call_operation_key} {source.child_activation}; "
                      f"definition path {self._witness(link)}")
            for kind, predecessor in exit_.definitions[node].edges:
                if kind not in {"DATA", "POTENTIAL_DATA", "ADDRESS"}:
                    _stop(CutDebtReason.UNSUPPORTED_CHANNEL, "unmodeled guard dependency")
                if depth >= self.limits.witness_length:
                    _stop(CutDebtReason.RESOURCE_BOUND, "control witness length budget")
                self._charge(facts=1)
                pending.append((predecessor, key, activation, link, depth + 1))

    def _witness(self, link):
        witness = []
        while link is not None:
            # Bound scratch construction as well as stored/queued graph work.
            # All queue entries and their retained parent links are separately
            # precharged against this same aggregate fact bound.
            self._charge(facts=1)
            witness.append(link[0])
            link = link[1]
        return tuple(reversed(witness))

    def _reverse(self, exit_, root, sources):
        targets = {}
        for source, nodes in sources:
            for offset, node in nodes.items():
                targets.setdefault(node, []).append((source, offset))
        candidates = []
        for sink_offset, sink_node in zip(root.demanded_offsets,
                                          root.byte_definition_ids, strict=True):
            self._charge(facts=1)
            pending = [(sink_node, False, False, None, 1)]
            visited = set()
            while pending:
                node, potential, address, parent, depth = pending.pop()
                identity = (node, potential, address)
                if identity in visited:
                    continue
                self._charge(facts=1)
                visited.add(identity)
                witness_link = (node, parent)
                for source, source_offset in targets.get(node, ()):
                    if address:
                        _stop(CutDebtReason.ADDRESS_SOURCE,
                              f"sink byte {sink_offset} reaches SOURCE {source.label!r} "
                              f"through ADDRESS at {source.call_operation_key} "
                              f"{source.child_activation}; definition path "
                              f"{self._witness(witness_link)}")
                    bytes_needed = 192 + 8 * depth
                    self._charge(facts=1, result_bytes=bytes_needed)
                    candidates.append(ReverseCandidate(exit_.alternative,
                        "POTENTIAL_DATA" if potential else "EXACT_DATA",
                        sink_offset, sink_node, source, source_offset, node,
                        self._witness(witness_link)))
                for kind, predecessor in exit_.definitions[node].edges:
                    if kind not in {"DATA", "POTENTIAL_DATA", "ADDRESS"}:
                        _stop(CutDebtReason.UNSUPPORTED_CHANNEL, "unmodeled dependency channel")
                    if depth >= self.limits.witness_length:
                        _stop(CutDebtReason.RESOURCE_BOUND, "reverse witness length budget")
                    self._charge(facts=1)
                    pending.append((predecessor, potential or kind == "POTENTIAL_DATA",
                                    address or kind == "ADDRESS", witness_link, depth + 1))
        return tuple(candidates)

    def run(self):
        roots, sources, candidates = [], [], []
        for exit_ in self.expansion.exits:
            root, rows, nodes, guards = self._cuts_for_exit(exit_)
            self._check_control(exit_, guards, nodes)
            roots.append(root)
            sources.extend(rows)
            candidates.extend(self._reverse(exit_, root, nodes))
        return FiniteCutCandidates(REVISION, self.request.input_digest,
            self.expansion.scheduler_revision, self.expansion.kernel_revision,
            tuple(roots), tuple(sources), tuple(candidates))


def _source_order(source, offset):
    return (source.alternative, source.caller_scope_digest,
            source.call_operation_key, source.parent_activation,
            source.child_activation, source.label, source.write_operation_key,
            source.return_operation_key, offset)


def _may_order(candidate):
    return (candidate.alternative, candidate.sink_offset,
            candidate.channel, candidate.confidence, candidate.address_crossing,
            candidate.guard_occurrence_index if candidate.guard_occurrence_index is not None else -1,
            candidate.guard_definition_id if candidate.guard_definition_id is not None else -1,
            _source_order(candidate.source, candidate.source_offset),
            candidate.witness_definition_ids)


class _MayQuery(_Query):
    """Bounded broad may enumeration over the already admitted diagnostic graph."""

    def _source_relevance(self, exit_, targets):
        # Edges always point to lower definition IDs. This exact index only
        # prunes nodes with no path to any bound source cut in this exit.
        # The ledger's separate definition bound covers this preflight; charge
        # its index/edge scan against bounded scratch, not emitted origin facts.
        edge_count = sum(len(row.edges) for row in exit_.definitions)
        if edge_count > self.limits.definitions:
            _stop(CutDebtReason.RESOURCE_BOUND, "may relevance edge preflight")
        self._charge(result_bytes=len(exit_.definitions) + 8 * edge_count)
        reachable = [False] * len(exit_.definitions)
        for node, definition in enumerate(exit_.definitions):
            reachable[node] = (node in targets or any(reachable[predecessor]
                for _, predecessor in definition.edges))
        return tuple(reachable)

    def _enumerate_from(self, exit_, targets, *, sink_offset, sink_node,
                        guard=None, full_demand=None, relevance=None):
        if relevance is None:
            relevance = self._source_relevance(exit_, targets)
        if not relevance[sink_node]:
            return []
        # BFS plus sorted predecessor edges chooses the shortest, then lexical,
        # definition-ID witness for each (node, potential, address) state.
        pending = deque([(sink_node, False, False, None, 1)])
        self._charge(facts=1)  # queued frontier and its parent link
        visited = set()
        candidates = []
        while pending:
            node, potential, address, parent, depth = pending.popleft()
            identity = (node, potential, address)
            if identity in visited:
                continue
            self._charge(facts=1)
            visited.add(identity)
            link = (node, parent)
            for source, source_offset in targets.get(node, ()):
                channel = ("CONTROL_ENVELOPE" if guard is not None else
                           "ADDRESS_MAY" if address else "DATA_MAY")
                confidence = "POTENTIAL_DATA" if potential else "EXACT_DATA"
                demand = ((sink_offset, sink_node),) if full_demand is None else full_demand
                # Charge every stored row and witness scratch before materializing.
                self._charge(facts=len(demand),
                             result_bytes=len(demand) * (256 + 8 * depth))
                witness = self._witness(link)
                for offset, sink_definition in demand:
                    candidates.append(MayReverseCandidate(
                        exit_.alternative, channel, confidence, address,
                        offset, sink_definition, source, source_offset, node, witness,
                        *(guard if guard is not None else (None, None, None, None))))
            edges = sorted(exit_.definitions[node].edges,
                           key=lambda edge: (edge[1], edge[0]))
            for kind, predecessor in edges:
                if kind not in {"DATA", "POTENTIAL_DATA", "ADDRESS"}:
                    _stop(CutDebtReason.UNSUPPORTED_CHANNEL, "unmodeled may dependency channel")
                if not relevance[predecessor]:
                    continue
                if depth >= self.limits.witness_length:
                    _stop(CutDebtReason.RESOURCE_BOUND, "may witness length budget")
                self._charge(facts=1)  # queue entry, including retained parent link
                pending.append((predecessor, potential or kind == "POTENTIAL_DATA",
                                address or kind == "ADDRESS", link, depth + 1))
        return candidates

    def run(self):
        roots, sources, candidates = [], [], []
        for exit_ in self.expansion.exits:
            root, rows, nodes, guards = self._cuts_for_exit(
                exit_, occurrence_guards=True)
            self._charge(result_bytes=32 * sum(len(offset_nodes)
                                               for _, offset_nodes in nodes))
            targets = {}
            for source, offset_nodes in nodes:
                for offset, node in offset_nodes.items():
                    targets.setdefault(node, []).append((source, offset))
            for entries in targets.values():
                entries.sort(key=lambda item: _source_order(*item))
            relevance = self._source_relevance(exit_, targets)
            roots.append(root)
            sources.extend(rows)
            for sink_offset, sink_node in zip(root.demanded_offsets,
                                              root.byte_definition_ids, strict=True):
                candidates.extend(self._enumerate_from(exit_, targets,
                    sink_offset=sink_offset, sink_node=sink_node, relevance=relevance))
            for key, activation, occurrence_index, guard_node in guards:
                demand = tuple(zip(root.demanded_offsets,
                                   root.byte_definition_ids, strict=True))
                candidates.extend(self._enumerate_from(exit_, targets,
                    sink_offset=demand[0][0], sink_node=guard_node,
                    guard=(key, activation, occurrence_index, guard_node),
                    full_demand=demand, relevance=relevance))
        candidates.sort(key=_may_order)
        return FiniteMayDiagnostic(MAY_REVISION, self.request.input_digest,
            self.expansion.scheduler_revision, self.expansion.kernel_revision,
            tuple(roots), tuple(sources), tuple(candidates))


def query_configured_finite_context_candidates(request: ConfiguredFiniteContextRequest,
                                               expansion: FiniteExpansion,
                                               provider: BoundaryProvider, /, *,
                                               limits: CutQueryLimits = CutQueryLimits()
                                               ) -> FiniteCutCandidates:
    """Return only internal exit-qualified candidate paths, or typed debt."""
    return _Query(request, expansion, provider, limits).run()


def query_configured_finite_context_may_diagnostic(
        request: ConfiguredFiniteContextRequest,
        expansion: FiniteExpansion,
        provider: BoundaryProvider, /, *,
        limits: CutQueryLimits = CutQueryLimits()) -> FiniteMayDiagnostic:
    """Enumerate bounded inclusion candidates; this cannot authorize a PASS."""
    return _MayQuery(request, expansion, provider, limits).run()
