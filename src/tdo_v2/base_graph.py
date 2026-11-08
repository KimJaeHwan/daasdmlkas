"""Query-independent, opaque-call SSA publication before optional proofs.

This is the existing FunctionNormalizer, not another SSA or summary engine.
Only completed generic normalizations are published. CALL entry relations
are a separate immutable revision; neither their presence nor local SSA
readiness proves a return effect, memory preservation, or program coverage.
The caller owns the publication, so cancellation of later work cannot erase
already published graphs. No summary/activation candidate is a base graph.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import json
import sys
from types import MappingProxyType
from typing import Mapping

from .normalize import FunctionNormalizer, NormalizedFunction, UnresolvedNormalizedFunction
from .resource_limits import AnalysisBudgetExceeded, AnalysisCancelled, activation, analysis_entry, checkpoint
from .scope_identity import ConstructedFunctionScope, ConstructedProgramScope, ScopedFunctionUnit


@dataclass(frozen=True, slots=True)
class BaseGraphPolicy:
    """Explicit existing switches; strict defaults apply only to this API.

    In particular these are NOT the summary engine's default policies.
    No external model, readonly image, summary, fault/control cut, or caller
    activation is applied by the base pass.
    """

    assume_globals_disjoint_from_stack: bool = False
    assume_entry_values_not_frame: bool = False
    assume_opaque_callees_leave_no_stack_addresses: bool = False
    assume_pre_escape_values_not_frame: bool = False
    assume_opaque_callees_restore_stack_pointer: bool = False
    assume_direction_flag_clear: bool = False

    def __post_init__(self):
        if any(type(value) is not bool for value in asdict(self).values()):
            raise TypeError("base graph policies require exact bools")

    @property
    def digest(self):
        return sha256(json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@contextmanager
def _policy(policy):
    """Mask ambient proof/activation/import inputs, restore them on every exit."""
    from ._activation_entry import using_entry
    from .call_clobber import OPAQUE_RESTORES_SP
    from .may_alias import ENTRY_VALUES_NOT_FRAME, OPAQUE_NO_STACK_ADDRESSES, PRE_ESCAPE_NOT_FRAME
    from .relative_memory import IMAGE_BASE_TRACKING, IMPORT_SLOTS

    values = ((ENTRY_VALUES_NOT_FRAME, policy.assume_entry_values_not_frame),
              (OPAQUE_NO_STACK_ADDRESSES, policy.assume_opaque_callees_leave_no_stack_addresses),
              (PRE_ESCAPE_NOT_FRAME, policy.assume_pre_escape_values_not_frame),
              (OPAQUE_RESTORES_SP, policy.assume_opaque_callees_restore_stack_pointer),
              (IMPORT_SLOTS, None), (IMAGE_BASE_TRACKING, None))
    tokens = [(variable, variable.set(value)) for variable, value in values]
    try:
        with using_entry(None):
            yield
    finally:
        for variable, token in reversed(tokens):
            variable.reset(token)


@dataclass(frozen=True, slots=True)
class BaseFunctionGraph:
    key: str
    unit: object
    normalized: NormalizedFunction
    policy: BaseGraphPolicy
    entry_relations: tuple = ()

    def __post_init__(self):
        normalized = self.normalized
        if type(self.unit) is not ScopedFunctionUnit or type(normalized) is not NormalizedFunction \
                or normalized.scopes != self.unit.scopes or type(self.policy) is not BaseGraphPolicy:
            raise ValueError("base graph must retain its admitted unit, exact SSA and policy")
        if normalized.configured_call_effects is not None or normalized.proven_call_effects \
                or normalized.assumed_call_effects or normalized.activation_entry is not None \
                or normalized.fault_cuts or normalized.fault_reachable or normalized.control_exempt \
                or normalized.site_reachable or normalized.callee_support or normalized.open_nodes \
                or normalized.forward_memory_proofs or normalized.load_value_proofs \
                or normalized.forward_inputs is not None and normalized.forward_inputs.read_separations is not None:
            raise ValueError("summary, activation or refinement candidates are not base graphs")
        used = ((normalized.assumes_globals_disjoint_from_stack, self.policy.assume_globals_disjoint_from_stack),
                (normalized.assumes_entry_values_not_frame, self.policy.assume_entry_values_not_frame),
                (normalized.assumes_opaque_callees_leave_no_stack_addresses,
                 self.policy.assume_opaque_callees_leave_no_stack_addresses),
                (normalized.assumes_pre_escape_values_not_frame, self.policy.assume_pre_escape_values_not_frame),
                (normalized.assumes_opaque_callees_restore_stack_pointer,
                 self.policy.assume_opaque_callees_restore_stack_pointer),
                (normalized.assumed_direction_flag_clear, self.policy.assume_direction_flag_clear))
        if any(required and not allowed for required, allowed in used) \
                or normalized.assumes_import_slots_hold_exports or normalized.assumes_readonly_image_constant:
            raise ValueError("base graph depends on an assumption outside its policy")

    @analysis_entry
    def query(self, seed, *, include_control=False):
        """Reuse the existing local query, also after the producing run ended."""
        from .query import BackwardSliceQuery

        return BackwardSliceQuery().run(self.normalized, seed, include_control=include_control)

    @analysis_entry
    def entry_edges(self):
        """Original cross-instance entry edges; not a new interprocedural slice."""
        return tuple(edge for relation in self.entry_relations for edge in relation.edges())


@dataclass(frozen=True, slots=True)
class BaseGraphFailure:
    normalized: UnresolvedNormalizedFunction
    detail: str = ""

    @property
    def reason(self):
        return self.normalized.reason


@dataclass(frozen=True, slots=True)
class BaseGraphSnapshot:
    program: object
    policy: BaseGraphPolicy
    requested_policy: BaseGraphPolicy
    expected_keys: tuple[str, ...]
    graphs: Mapping[str, BaseFunctionGraph]
    failures: Mapping[str, BaseGraphFailure]
    admission_failures: tuple
    local_pass_finished: bool
    entry_links_finished: bool
    stop: str

    @property
    def pending(self):
        return tuple(key for key in self.expected_keys if key not in self.graphs and key not in self.failures)


class BaseGraphPublication:
    """One build's caller-owned publication; completed snapshots never mutate.

    Local graphs are published one function at a time, without graph copies.
    Entry overlays are published atomically after the local pass. If a run
    limit is reached, pending keys stay pending rather than becoming pretend
    normalized functions. Cancellation/MemoryError/invalid inputs propagate;
    the caller can still read ``snapshot`` on this exact handle.
    """

    def __init__(self, units, *, program=None, policy=BaseGraphPolicy(), admission_failures=()):
        from .integration.observed_function_session import ObservedFunctionAdmissionFailure
        from .interprocedural import function_key

        if type(policy) is not BaseGraphPolicy:
            raise TypeError("base graph policy must be exact")
        self._units = tuple(units)
        self._admission_failures = tuple(admission_failures)
        if program is None and self._units:
            program = self._units[0].scopes.program
        if type(program) is not ConstructedProgramScope:
            raise ValueError("base graph publication requires a constructed program")
        keys = []
        for unit in self._units:
            if type(unit) is not ScopedFunctionUnit or unit.scopes.program != program \
                    or type(unit.scopes.function) is not ConstructedFunctionScope or unit.observation is None:
                raise ValueError("base graph input must be an admitted function of this exact program")
            keys.append(function_key(unit.scopes.function.entry))
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate base graph function key")
        if any(type(item) is not ObservedFunctionAdmissionFailure or item.unit.scopes.program != program
               for item in self._admission_failures):
            raise ValueError("base graph admission refusal belongs to a different program")
        self._program, self._keys = program, tuple(keys)
        self._requested_policy = self._policy = policy
        self._graphs, self._failures = {}, {}
        self._started = self._local_done = self._links_done = False
        self._stop = "not-started"

    @property
    def snapshot(self):
        return BaseGraphSnapshot(self._program, self._policy, self._requested_policy, self._keys,
            MappingProxyType(dict(self._graphs)), MappingProxyType(dict(self._failures)),
            self._admission_failures, self._local_done, self._links_done, self._stop)

    def require_inputs(self, units):
        """An opt-in proof run must use these exact units, not equal surrogates."""
        units = tuple(units)
        if len(units) != len(self._units) or any(left is not right for left, right in zip(units, self._units)):
            raise ValueError("base graph publication belongs to different input instances")

    @analysis_entry
    def build(self):
        from .interprocedural import (ANALYSIS_FAILURES, ANALYSIS_RECURSION_LIMIT, _failure_detail,
                                     _failure_reason, program_switches_stack)
        from .phases import phase

        if self._started:
            raise RuntimeError("base graph publication is single-use")
        self._started, self._stop = True, "running"
        previous = sys.getrecursionlimit()
        sys.setrecursionlimit(max(previous, ANALYSIS_RECURSION_LIMIT))
        try:
            with _policy(self._policy), phase("base_graphs"):
                if self._policy.assume_globals_disjoint_from_stack and program_switches_stack(self._units):
                    self._policy = replace(self._policy, assume_globals_disjoint_from_stack=False)
                normalizer = FunctionNormalizer()
                for key, unit in zip(self._keys, self._units):
                    try:
                        # Separate from the proof function's cumulative ledger;
                        # the same overall run still pays for both phases.
                        with activation(("base-graph", unit.scopes.function.scope)):
                            normalized = normalizer.normalize(unit,
                                assume_globals_disjoint_from_stack=self._policy.assume_globals_disjoint_from_stack,
                                assume_direction_flag_clear=self._policy.assume_direction_flag_clear)
                            checkpoint()
                            if type(normalized) is NormalizedFunction:
                                self._graphs[key] = BaseFunctionGraph(key, unit, normalized, self._policy)
                            else:
                                self._failures[key] = BaseGraphFailure(normalized)
                    except ANALYSIS_FAILURES as error:
                        if isinstance(error, AnalysisBudgetExceeded) and error.scope == "run":
                            raise
                        self._failures[key] = BaseGraphFailure(UnresolvedNormalizedFunction(
                            unit.scopes, _failure_reason(error)), _failure_detail(error))
                self._local_done = True
                self._connect_entries()
                self._stop = "finished"
        except AnalysisBudgetExceeded as error:
            if error.scope != "run":
                self._stop = f"failed:{error.scope}:{error.kind}"
                raise
            self._stop = f"run:{error.kind}"
        except (AnalysisCancelled, KeyboardInterrupt):
            self._stop = "cancelled"
            raise
        except BaseException:
            self._stop = "failed"
            raise
        finally:
            sys.setrecursionlimit(previous)
        return self.snapshot

    def _connect_entries(self):
        """Reuse the existing bridge on private, non-producer adapters only."""
        from .call_entry_graph import connect_call_entries
        from .interprocedural import AnalyzedFunction, _relative_anchors
        from .phases import phase

        with phase("base_call_entries"):
            adapters = {}
            for key, graph in self._graphs.items():
                checkpoint()
                adapters[key] = AnalyzedFunction(key, graph.unit, graph.normalized, None,
                    calls=MappingProxyType({}), proven=MappingProxyType({}),
                    anchors=MappingProxyType(_relative_anchors(graph.unit, graph.normalized)),
                    consumed=MappingProxyType({}), activations=MappingProxyType({}))
            from functools import partial

            connect_call_entries(adapters, query_context=partial(_policy, self._policy))
            checkpoint()
            # No exposed graph or earlier snapshot is changed by this revision.
            self._graphs = {key: replace(self._graphs[key], entry_relations=item.entry_relations)
                            for key, item in adapters.items()}
            self._links_done = True


@analysis_entry
def build_observed_graphs(program, evidences, *, policy=BaseGraphPolicy(), publication=None):
    """Build all admitted local graphs; no sink/source query or model lookup."""
    from .integration.observed_function_session import ObservedFunctionAdmissionFailure, ObservedFunctionEvidence

    evidences = tuple(evidences)
    if any(type(item) not in (ObservedFunctionEvidence, ObservedFunctionAdmissionFailure) for item in evidences):
        raise TypeError("base graph observations require exact admitted evidence or sealed refusals")
    units = tuple(item.unit for item in evidences if type(item) is ObservedFunctionEvidence)
    refusals = tuple(item for item in evidences if type(item) is ObservedFunctionAdmissionFailure)
    if publication is None:
        publication = BaseGraphPublication(units, program=program, policy=policy, admission_failures=refusals)
    elif type(publication) is not BaseGraphPublication or publication._program != program \
            or publication._requested_policy != policy or publication._admission_failures != refusals:
        raise ValueError("base graph publication inputs changed")
    publication.require_inputs(units)
    return publication.build()


@analysis_entry
def build_frozen_bundle_graphs(generation_path, *, naming_exporter_source, policy=BaseGraphPolicy(),
                               on_publication=None):
    """The production sealed-Bundle path, without running summary proofs.

    ``on_publication(handle)`` transfers the caller-owned handle before any
    normalization. Its snapshot survives cancellation; the original exception
    still propagates. Admission failures before this point remain fatal.
    """
    from pathlib import Path
    from .configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
    from .integration.configured_bundle import admit_frozen_bundle
    from .integration.observed_function_session import (ObservedFunctionAdmissionFailure,
                                                         open_observed_function_session)

    if on_publication is not None and not callable(on_publication):
        raise TypeError("on_publication must be callable")
    binding = NamingBindingExpectation(sha256(Path(naming_exporter_source).read_bytes()).digest(),
                                      CALL_NAMING_GHIDRA_VERSION)
    with open_observed_function_session(admit_frozen_bundle(generation_path), naming_binding=binding) as session:
        program, evidences = session.program_result, tuple(session.iter_outcomes())
        publication = BaseGraphPublication(
            [item.unit for item in evidences if type(item) is not ObservedFunctionAdmissionFailure],
            program=program, policy=policy,
            admission_failures=[item for item in evidences if type(item) is ObservedFunctionAdmissionFailure])
        if on_publication is not None:
            on_publication(publication)
        return publication.build()


__all__ = ("BaseGraphPolicy", "BaseGraphPublication", "BaseGraphSnapshot", "BaseFunctionGraph",
           "BaseGraphFailure", "build_observed_graphs", "build_frozen_bundle_graphs")
