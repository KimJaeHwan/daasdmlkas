"""Architect-owned exact binding of neutral call ports to local-memory SSA."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import TypeAlias
from weakref import ReferenceType, WeakKeyDictionary, ref

from .call_contracts import (
    CALL_OBSERVATION_CONTRACT_VERSION,
    CallSiteSeed,
    FunctionCallSeedUnit,
)
from .call_effect_contracts import (
    CallEffectCompleteness,
    CallEffectDirection,
    CallEffectPort,
    CallEffectRecord,
    ConfiguredCallEffectPort,
    DirectionalCallEffectDebt,
    FunctionCallEffectEvidence,
    RawObservedCallPort,
)
from .memory_contracts import (
    LocalMemorySsaResult,
    LocalMemoryUnit,
    LocalStorageAction,
    MemoryDefinition,
    MemoryReadFragment,
    MemoryReadResolution,
)
from .memory_ssa import build_local_memory_ssa
from .model import ByteSpan


CALL_PORT_LAYOUT_CONTRACT_VERSION = 1
CALL_TRANSITION_CONTRACT_VERSION = 1


class _BoundSsaAuthority:
    __slots__ = ()


_BOUND_SSA_AUTHORITY = _BoundSsaAuthority()


class _BoundSsaIdentity:
    __slots__ = ("__weakref__",)

    def __init__(
        self,
        authority: _BoundSsaAuthority,
    ) -> None:
        if authority is not _BOUND_SSA_AUTHORITY:
            raise PermissionError("bound SSA identities are architect-owned")

    def __reduce_ex__(self, protocol: int):
        raise TypeError("bound SSA identities cannot be serialized")


def _make_bound_ssa_registry():
    registry: WeakKeyDictionary[
        _BoundSsaIdentity,
        tuple[
            ReferenceType[BoundLocalMemorySsa],
            LocalMemoryUnit,
            LocalMemorySsaResult,
        ],
    ] = WeakKeyDictionary()

    def register(
        identity: _BoundSsaIdentity,
        receipt: BoundLocalMemorySsa,
        unit: LocalMemoryUnit,
        result: LocalMemorySsaResult,
    ) -> None:
        registry[identity] = (ref(receipt), unit, result)

    def lookup(
        identity: _BoundSsaIdentity,
    ) -> tuple[
        ReferenceType[BoundLocalMemorySsa],
        LocalMemoryUnit,
        LocalMemorySsaResult,
    ] | None:
        return registry.get(identity)

    return register, lookup


_register_bound_ssa_identity, _lookup_bound_ssa_identity = _make_bound_ssa_registry()
del _make_bound_ssa_registry


@dataclass(frozen=True, slots=True, init=False, weakref_slot=True)
class BoundLocalMemorySsa:
    """Live exact-object receipt for one local-memory SSA construction."""

    unit: LocalMemoryUnit
    result: LocalMemorySsaResult
    _identity: _BoundSsaIdentity

    def _validate(self) -> None:
        _require_exact(self.unit, LocalMemoryUnit, "bound local-memory unit")
        _require_exact(self.result, LocalMemorySsaResult, "bound local-memory result")
        _require_exact(self._identity, _BoundSsaIdentity, "bound SSA identity")
        expected = _lookup_bound_ssa_identity(self._identity)
        if expected is None:
            raise ValueError("bound local-memory SSA identity is not registered")
        receipt_ref, expected_unit, expected_result = expected
        if (
            receipt_ref() is not self
            or self.unit is not expected_unit
            or self.result is not expected_result
        ):
            raise ValueError("bound local-memory SSA identity changed")
        if self.result.unit_digest != self.unit.canonical_digest:
            raise ValueError("bound local-memory result uses another unit")

    def __reduce_ex__(self, protocol: int):
        raise TypeError("bound local-memory SSA receipts cannot be serialized")


def build_bound_local_memory_ssa(
    unit: LocalMemoryUnit,
    /,
) -> BoundLocalMemorySsa:
    """Build SSA and retain the exact input/output identities in one live receipt."""
    _require_exact(unit, LocalMemoryUnit, "local-memory SSA binding unit")
    result = build_local_memory_ssa(unit)
    identity = _BoundSsaIdentity(_BOUND_SSA_AUTHORITY)
    value = object.__new__(BoundLocalMemorySsa)
    object.__setattr__(value, "unit", unit)
    object.__setattr__(value, "result", result)
    object.__setattr__(
        value,
        "_identity",
        identity,
    )
    _register_bound_ssa_identity(identity, value, unit, result)
    value._validate()
    return value


@dataclass(frozen=True, slots=True)
class PreSsaWriteSubspan:
    write_ordinal: int
    span: ByteSpan

    def __post_init__(self) -> None:
        _require_u64(self.write_ordinal, "pre-SSA write ordinal")
        _require_exact(self.span, ByteSpan, "pre-SSA write subspan")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (self.write_ordinal, self.span.canonical_key)


@dataclass(frozen=True, slots=True)
class PreSsaCallPortBinding:
    port: CallEffectPort
    action: LocalStorageAction
    read_ordinal: int | None
    write_subspans: tuple[PreSsaWriteSubspan, ...]

    def __post_init__(self) -> None:
        _require_port(self.port)
        _require_exact(self.action, LocalStorageAction, "pre-SSA call action")
        _require_exact_tuple(
            self.write_subspans,
            PreSsaWriteSubspan,
            "pre-SSA write subspans",
        )
        direction = _port_direction(self.port)
        if direction is CallEffectDirection.PRE_READ:
            _require_u64(self.read_ordinal, "pre-SSA read ordinal")
            if self.write_subspans:
                raise ValueError("pre-read layout cannot retain write subspans")
        elif self.read_ordinal is not None or not self.write_subspans:
            raise ValueError("post-write layout requires only write subspans")
        _require_strictly_increasing(
            (item.canonical_key for item in self.write_subspans),
            "pre-SSA write subspans",
        )
        if self.write_subspans:
            _validate_exact_span_cover(
                self.port.span,
                tuple(item.span for item in self.write_subspans),
            )

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (
            _port_digest(self.port),
            self.action.operation_key,
            -1 if self.read_ordinal is None else self.read_ordinal,
            tuple(item.canonical_key for item in self.write_subspans),
        )


@dataclass(frozen=True, slots=True, init=False)
class PreSsaCallPortLayout:
    contract_version: int
    seeds: FunctionCallSeedUnit
    effects: FunctionCallEffectEvidence
    memory_unit: LocalMemoryUnit
    bindings: tuple[PreSsaCallPortBinding, ...]

    @classmethod
    def _create(
        cls,
        seeds: FunctionCallSeedUnit,
        effects: FunctionCallEffectEvidence,
        memory_unit: LocalMemoryUnit,
        bindings: tuple[PreSsaCallPortBinding, ...],
    ) -> "PreSsaCallPortLayout":
        value = object.__new__(cls)
        object.__setattr__(value, "contract_version", CALL_PORT_LAYOUT_CONTRACT_VERSION)
        object.__setattr__(value, "seeds", seeds)
        object.__setattr__(value, "effects", effects)
        object.__setattr__(value, "memory_unit", memory_unit)
        object.__setattr__(value, "bindings", bindings)
        value._validate()
        return value

    def _validate(self) -> None:
        if self.contract_version != CALL_PORT_LAYOUT_CONTRACT_VERSION:
            raise ValueError("unsupported pre-SSA call-port layout version")
        _require_exact(self.seeds, FunctionCallSeedUnit, "pre-SSA call seeds")
        _require_exact(
            self.effects, FunctionCallEffectEvidence, "pre-SSA call effects"
        )
        _require_exact(self.memory_unit, LocalMemoryUnit, "pre-SSA memory unit")
        _require_exact_tuple(
            self.bindings, PreSsaCallPortBinding, "pre-SSA call-port bindings"
        )
        if self.effects.seeds is not self.seeds:
            raise ValueError("pre-SSA effects must retain the exact seed unit")
        if self.memory_unit.function_scope != self.seeds.function_scope:
            raise ValueError("pre-SSA memory and call seeds use different functions")
        if (
            self.memory_unit.effect_evidence_digest
            != self.effects.effect_evidence_digest
        ):
            raise ValueError("pre-SSA memory uses different call-effect evidence")
        expected_ports = _effect_ports(self.effects)
        if len(self.bindings) != len(expected_ports) or any(
            binding.port is not port
            for binding, port in zip(self.bindings, expected_ports, strict=True)
        ):
            raise ValueError("pre-SSA layout must bind every exact effect port once")
        _validate_pre_ssa_relations(self)

    @property
    def canonical_digest(self) -> bytes:
        return _digest(
            [
                "tdo-v2-pre-ssa-call-port-layout-v1",
                self.seeds.canonical_digest.hex(),
                self.effects.effect_evidence_digest.hex(),
                self.memory_unit.canonical_digest.hex(),
                [_pre_ssa_binding_payload(item) for item in self.bindings],
            ]
        )

    def __reduce_ex__(self, protocol: int):
        raise TypeError("pre-SSA call-port layouts cannot be serialized")


@dataclass(frozen=True, slots=True)
class CallReadFragmentBinding:
    read_ordinal: int
    fragment_ordinal: int
    definition_id: int
    fragment: MemoryReadFragment

    def __post_init__(self) -> None:
        _require_u64(self.read_ordinal, "call read ordinal")
        _require_u64(self.fragment_ordinal, "call read fragment ordinal")
        _require_u64(self.definition_id, "call read definition ID")
        _require_exact(self.fragment, MemoryReadFragment, "call read fragment")
        if self.fragment.definition_ids != (self.definition_id,):
            raise ValueError("call read fragment and definition ID disagree")

    @property
    def span(self) -> ByteSpan:
        return self.fragment.span

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (
            self.read_ordinal,
            self.fragment_ordinal,
            self.definition_id,
            self.span.canonical_key,
        )


@dataclass(frozen=True, slots=True)
class CallWriteSubspanBinding:
    write_ordinal: int
    definition_id: int
    definition: MemoryDefinition
    span: ByteSpan

    def __post_init__(self) -> None:
        _require_u64(self.write_ordinal, "call write ordinal")
        _require_u64(self.definition_id, "call write definition ID")
        _require_exact(self.definition, MemoryDefinition, "call write definition")
        _require_exact(self.span, ByteSpan, "call write binding span")
        if (
            self.definition.write_ordinal != self.write_ordinal
            or not self.definition.span.contains(self.span)
        ):
            raise ValueError("call write subspan does not match its definition")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (
            self.write_ordinal,
            self.definition_id,
            self.definition.canonical_key,
            self.span.canonical_key,
        )


@dataclass(frozen=True, slots=True, init=False)
class CallEffectPortBinding:
    port: CallEffectPort
    effect_evidence_digest: bytes
    memory_unit_digest: bytes
    action_id: int
    operation_key: str
    read_fragments: tuple[CallReadFragmentBinding, ...]
    write_subspans: tuple[CallWriteSubspanBinding, ...]

    @classmethod
    def _create(
        cls,
        port: CallEffectPort,
        effect_evidence_digest: bytes,
        memory_unit_digest: bytes,
        action_id: int,
        operation_key: str,
        read_fragments: tuple[CallReadFragmentBinding, ...],
        write_subspans: tuple[CallWriteSubspanBinding, ...],
    ) -> "CallEffectPortBinding":
        value = object.__new__(cls)
        object.__setattr__(value, "port", port)
        object.__setattr__(value, "effect_evidence_digest", effect_evidence_digest)
        object.__setattr__(value, "memory_unit_digest", memory_unit_digest)
        object.__setattr__(value, "action_id", action_id)
        object.__setattr__(value, "operation_key", operation_key)
        object.__setattr__(value, "read_fragments", read_fragments)
        object.__setattr__(value, "write_subspans", write_subspans)
        value._validate()
        return value

    def _validate(self) -> None:
        _require_port(self.port)
        _require_digest(self.effect_evidence_digest, "bound call effect digest")
        _require_digest(self.memory_unit_digest, "bound call memory digest")
        _require_u64(self.action_id, "bound call action ID")
        _require_text(self.operation_key, "bound call operation key")
        _require_exact_tuple(
            self.read_fragments, CallReadFragmentBinding, "call read fragments"
        )
        _require_exact_tuple(
            self.write_subspans, CallWriteSubspanBinding, "call write subspans"
        )
        if type(self.port) is ConfiguredCallEffectPort and (
            self.port.effect_evidence_digest != self.effect_evidence_digest
        ):
            raise ValueError("configured port and binding use different effect evidence")
        if _port_direction(self.port) is CallEffectDirection.PRE_READ:
            if not self.read_fragments or self.write_subspans:
                raise ValueError("pre-read binding requires only read fragments")
            _require_strictly_increasing(
                (item.canonical_key for item in self.read_fragments),
                "call read fragments",
            )
            _validate_exact_span_cover(
                self.port.span,
                tuple(item.span for item in self.read_fragments),
            )
        else:
            if self.read_fragments or not self.write_subspans:
                raise ValueError("post-write binding requires only write subspans")
            _require_strictly_increasing(
                (item.canonical_key for item in self.write_subspans),
                "call write subspans",
            )
            _validate_exact_span_cover(
                self.port.span,
                tuple(item.span for item in self.write_subspans),
            )

    @property
    def direction(self) -> CallEffectDirection:
        return _port_direction(self.port)

    @property
    def port_id(self) -> bytes:
        return _digest(
            [
                "tdo-v2-bound-call-port-v2",
                _port_variant_payload(self.port),
                self.direction.value,
                list(self.port.span.canonical_key),
                self.effect_evidence_digest.hex(),
                self.memory_unit_digest.hex(),
                self.action_id,
                self.operation_key,
                [item.canonical_key for item in self.read_fragments],
                [item.canonical_key for item in self.write_subspans],
            ]
        )

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return (self.port.canonical_key, self.port_id)


@dataclass(frozen=True, slots=True)
class MemoryActionRef:
    memory_unit_digest: bytes
    action_id: int

    def __post_init__(self) -> None:
        _require_digest(self.memory_unit_digest, "memory action unit digest")
        _require_u64(self.action_id, "memory action ID")


@dataclass(frozen=True, slots=True)
class ObservedCallTransition:
    occurrence_digest: bytes
    action: MemoryActionRef
    effect_evidence_digest: bytes
    pre_read_completeness: CallEffectCompleteness
    post_write_completeness: CallEffectCompleteness
    port_bindings: tuple[CallEffectPortBinding, ...]
    debts: tuple[DirectionalCallEffectDebt, ...]

    def __post_init__(self) -> None:
        _require_digest(self.occurrence_digest, "call transition occurrence")
        _require_exact(self.action, MemoryActionRef, "call memory action")
        _require_digest(self.effect_evidence_digest, "call transition effect digest")
        _require_exact(
            self.pre_read_completeness,
            CallEffectCompleteness,
            "call transition pre-read completeness",
        )
        _require_exact(
            self.post_write_completeness,
            CallEffectCompleteness,
            "call transition post-write completeness",
        )
        _require_exact_tuple(
            self.port_bindings, CallEffectPortBinding, "call port bindings"
        )
        _require_exact_tuple(self.debts, DirectionalCallEffectDebt, "call debts")
        if any(
            item.memory_unit_digest != self.action.memory_unit_digest
            or item.action_id != self.action.action_id
            or item.effect_evidence_digest != self.effect_evidence_digest
            for item in self.port_bindings
        ):
            raise ValueError("call transition bindings use foreign evidence")
        _require_strictly_increasing(
            (item.canonical_key for item in self.port_bindings),
            "call transition port bindings",
        )
        _require_strictly_increasing(
            (item.canonical_key for item in self.debts),
            "call transition debts",
        )
        if any(
            item.port.occurrence.occurrence_digest != self.occurrence_digest
            for item in self.port_bindings
        ):
            raise ValueError("call transition ports use another occurrence")
        if any(
            item.occurrence.occurrence_digest != self.occurrence_digest
            for item in self.debts
        ):
            raise ValueError("call transition debts use another occurrence")


@dataclass(frozen=True, slots=True)
class CallSiteObservation:
    seed: CallSiteSeed
    transition: ObservedCallTransition

    def __post_init__(self) -> None:
        _require_exact(self.seed, CallSiteSeed, "observed call seed")
        _require_exact(self.transition, ObservedCallTransition, "observed call transition")
        if self.transition.occurrence_digest != self.seed.occurrence.occurrence_digest:
            raise ValueError("call transition uses another occurrence")

    @property
    def canonical_key(self) -> tuple[object, ...]:
        return self.seed.canonical_key


@dataclass(frozen=True, slots=True, init=False)
class FunctionCallObservations:
    contract_version: int
    seeds: FunctionCallSeedUnit
    effects: FunctionCallEffectEvidence
    layout: PreSsaCallPortLayout
    memory_binding: BoundLocalMemorySsa
    callsites: tuple[CallSiteObservation, ...]

    @classmethod
    def _create(
        cls,
        seeds: FunctionCallSeedUnit,
        effects: FunctionCallEffectEvidence,
        layout: PreSsaCallPortLayout,
        memory_binding: BoundLocalMemorySsa,
        callsites: tuple[CallSiteObservation, ...],
    ) -> "FunctionCallObservations":
        value = object.__new__(cls)
        object.__setattr__(value, "contract_version", CALL_TRANSITION_CONTRACT_VERSION)
        object.__setattr__(value, "seeds", seeds)
        object.__setattr__(value, "effects", effects)
        object.__setattr__(value, "layout", layout)
        object.__setattr__(value, "memory_binding", memory_binding)
        object.__setattr__(value, "callsites", callsites)
        value._validate()
        return value

    def _validate(self) -> None:
        if self.contract_version != CALL_TRANSITION_CONTRACT_VERSION:
            raise ValueError("unsupported call-transition contract version")
        _require_exact(self.seeds, FunctionCallSeedUnit, "call-observation seeds")
        _require_exact(
            self.effects, FunctionCallEffectEvidence, "call-observation effects"
        )
        _require_exact(self.layout, PreSsaCallPortLayout, "call-observation layout")
        _require_exact(
            self.memory_binding,
            BoundLocalMemorySsa,
            "call-observation memory binding",
        )
        self.memory_binding._validate()
        _require_exact_tuple(self.callsites, CallSiteObservation, "call observations")
        if (
            self.effects.seeds is not self.seeds
            or self.layout.seeds is not self.seeds
            or self.layout.effects is not self.effects
        ):
            raise ValueError("call observations must retain exact upstream objects")
        if self.layout.memory_unit is not self.memory_binding.unit:
            raise ValueError("call observations use a foreign SSA construction")
        if len(self.callsites) != len(self.seeds.callsites) or any(
            site.seed is not seed
            for site, seed in zip(self.callsites, self.seeds.callsites, strict=True)
        ):
            raise ValueError("call observations must cover every exact seed once")
        _require_strictly_increasing(
            (site.canonical_key for site in self.callsites), "call observations"
        )
        self._validate_relations()

    def _validate_relations(self) -> None:
        action_ids = {
            action.operation_key: action_id
            for action_id, action in enumerate(self.memory.actions)
        }
        reads = {(item.action_id, item.read_ordinal): item for item in self.memory.reads}
        layouts_by_port = {id(item.port): item for item in self.layout.bindings}
        if len(layouts_by_port) != len(self.layout.bindings):
            raise ValueError("pre-SSA layout cannot repeat an exact port object")
        for site, seed, record in zip(
            self.callsites,
            self.seeds.callsites,
            self.effects.calls,
            strict=True,
        ):
            transition = site.transition
            try:
                action_id = action_ids[seed.operation_key]
            except KeyError as exc:
                raise ValueError("observed call action is absent from SSA") from exc
            if (
                transition.action.memory_unit_digest != self.memory.unit_digest
                or transition.action.action_id != action_id
                or transition.effect_evidence_digest
                != self.effects.effect_evidence_digest
            ):
                raise ValueError("observed call transition uses foreign evidence")
            if (
                transition.pre_read_completeness
                is not record.pre_read_completeness
                or transition.post_write_completeness
                is not record.post_write_completeness
            ):
                raise ValueError("observed call completeness differs from admitted effects")
            if len(transition.debts) != len(record.debts) or any(
                retained is not admitted
                for retained, admitted in zip(
                    transition.debts,
                    record.debts,
                    strict=True,
                )
            ):
                raise ValueError("observed call debts must retain exact admitted debt")
            if len(transition.port_bindings) != len(record.ports) or {
                id(binding.port) for binding in transition.port_bindings
            } != {id(port) for port in record.ports}:
                raise ValueError("observed call ports must exactly cover admitted ports")
            for binding in transition.port_bindings:
                try:
                    layout = layouts_by_port[id(binding.port)]
                except KeyError as exc:
                    raise ValueError("observed call port is absent from its layout") from exc
                if (
                    layout.port is not binding.port
                    or layout.action.operation_key != seed.operation_key
                    or binding.action_id != action_id
                    or binding.operation_key != seed.operation_key
                ):
                    raise ValueError("observed call binding uses another action")
                if layout.read_ordinal is not None:
                    try:
                        resolution = reads[(action_id, layout.read_ordinal)]
                    except KeyError as exc:
                        raise ValueError("observed call read is absent from SSA") from exc
                    if len(binding.read_fragments) != len(resolution.fragments) or any(
                        fragment.fragment is not expected
                        or fragment.definition_id != expected.definition_ids[0]
                        or fragment.read_ordinal != layout.read_ordinal
                        or fragment.fragment_ordinal != ordinal
                        for ordinal, (fragment, expected) in enumerate(
                            zip(
                                binding.read_fragments,
                                resolution.fragments,
                                strict=True,
                            )
                        )
                    ):
                        raise ValueError("observed call read fragments differ from SSA")
                    if binding.write_subspans:
                        raise ValueError("observed pre-read cannot retain write bindings")
                else:
                    expected_writes = tuple(
                        (
                            item.write_ordinal,
                            item.span,
                        )
                        for item in layout.write_subspans
                    )
                    retained_writes = tuple(
                        (item.write_ordinal, item.span)
                        for item in binding.write_subspans
                    )
                    if retained_writes != expected_writes or binding.read_fragments:
                        raise ValueError("observed call write slices differ from its layout")
                    for item in binding.write_subspans:
                        if (
                            item.definition_id >= len(self.memory.definitions)
                            or item.definition
                            is not self.memory.definitions[item.definition_id]
                        ):
                            raise ValueError(
                                "observed call write must retain an exact SSA definition"
                            )

    @property
    def program_scope(self):
        return self.seeds.program_scope

    @property
    def function_scope(self):
        return self.seeds.function_scope

    @property
    def function_entry(self):
        return self.seeds.function_entry

    @property
    def observation_digest(self) -> bytes:
        return self.seeds.observation_digest

    @property
    def seed_digest(self) -> bytes:
        return self.seeds.canonical_digest

    @property
    def memory_unit_digest(self) -> bytes:
        return self.memory.unit_digest

    @property
    def memory(self) -> LocalMemorySsaResult:
        return self.memory_binding.result

    @property
    def canonical_digest(self) -> bytes:
        return _digest(
            [
                "tdo-v2-call-observation-unit-v3",
                self.seeds.canonical_digest.hex(),
                self.effects.effect_evidence_digest.hex(),
                self.layout.canonical_digest.hex(),
                self.memory.unit_digest.hex(),
                [_site_payload(site) for site in self.callsites],
            ]
        )

    def __reduce_ex__(self, protocol: int):
        raise TypeError("bound call observations cannot be serialized")


def build_pre_ssa_call_port_layout(
    seeds: FunctionCallSeedUnit,
    effects: FunctionCallEffectEvidence,
    memory_unit: LocalMemoryUnit,
    /,
) -> PreSsaCallPortLayout:
    """Derive a total port-to-action layout from exact pre-SSA memory effects."""
    _require_exact(seeds, FunctionCallSeedUnit, "pre-SSA layout seeds")
    _require_exact(effects, FunctionCallEffectEvidence, "pre-SSA layout effects")
    _require_exact(memory_unit, LocalMemoryUnit, "pre-SSA layout memory")
    actions = {
        action.operation_key: action
        for block in memory_unit.blocks
        for action in block.actions
    }
    bindings: list[PreSsaCallPortBinding] = []
    for seed, record in zip(seeds.callsites, effects.calls, strict=True):
        try:
            action = actions[seed.operation_key]
        except KeyError as exc:
            raise ValueError("call seed has no exact pre-SSA action") from exc
        pre_ports = tuple(
            port
            for port in record.ports
            if _port_direction(port) is CallEffectDirection.PRE_READ
        )
        used_read_ordinals: set[int] = set()
        for port in pre_ports:
            read_ordinal = next(
                (
                    ordinal
                    for ordinal, span in enumerate(action.reads)
                    if ordinal not in used_read_ordinals and span == port.span
                ),
                None,
            )
            if read_ordinal is None:
                raise ValueError("call pre-read port has no exact action read")
            used_read_ordinals.add(read_ordinal)
            bindings.append(
                PreSsaCallPortBinding(port, action, read_ordinal, ())
            )
        post_ports = tuple(
            port
            for port in record.ports
            if _port_direction(port) is CallEffectDirection.POST_WRITE
        )
        for port in post_ports:
            subspans = []
            for write_ordinal, write_span in enumerate(action.writes):
                overlap = port.span.intersection(write_span)
                if overlap is None:
                    continue
                subspans.append(PreSsaWriteSubspan(write_ordinal, overlap))
            bindings.append(
                PreSsaCallPortBinding(
                    port,
                    action,
                    None,
                    tuple(subspans),
                )
            )
    return PreSsaCallPortLayout._create(seeds, effects, memory_unit, tuple(bindings))


def bind_call_observations(
    seeds: FunctionCallSeedUnit,
    effects: FunctionCallEffectEvidence,
    layout: PreSsaCallPortLayout,
    memory_binding: BoundLocalMemorySsa,
    /,
) -> FunctionCallObservations:
    """Bind a total pre-SSA port layout to exact reaching-definition artifacts."""
    _require_exact(seeds, FunctionCallSeedUnit, "bound call seeds")
    _require_exact(effects, FunctionCallEffectEvidence, "bound call effects")
    _require_exact(layout, PreSsaCallPortLayout, "bound call layout")
    _require_exact(
        memory_binding,
        BoundLocalMemorySsa,
        "bound call memory receipt",
    )
    memory_binding._validate()
    memory = memory_binding.result
    if layout.seeds is not seeds or layout.effects is not effects:
        raise ValueError("call binder requires exact retained pre-SSA inputs")
    if layout.memory_unit is not memory_binding.unit:
        raise ValueError("call binder received another local-memory construction")

    action_ids = {
        action.operation_key: action_id
        for action_id, action in enumerate(memory.actions)
    }
    reads = {(item.action_id, item.read_ordinal): item for item in memory.reads}
    definitions_by_write = {}
    for definition_id, definition in enumerate(memory.definitions):
        if definition.operation_key is not None:
            definitions_by_write[(definition.operation_key, definition.write_ordinal)] = (
                definition_id,
                definition,
            )

    bound_ports: list[CallEffectPortBinding] = []
    for item in layout.bindings:
        try:
            action_id = action_ids[item.action.operation_key]
        except KeyError as exc:
            raise ValueError("pre-SSA call action is absent from SSA") from exc
        read_fragments: tuple[CallReadFragmentBinding, ...] = ()
        write_subspans: tuple[CallWriteSubspanBinding, ...] = ()
        if item.read_ordinal is not None:
            try:
                resolution = reads[(action_id, item.read_ordinal)]
            except KeyError as exc:
                raise ValueError("pre-SSA call read is absent from SSA") from exc
            if resolution.span != item.port.span:
                raise ValueError("SSA read no longer matches its call port")
            read_fragments = tuple(
                CallReadFragmentBinding(
                    item.read_ordinal,
                    fragment_ordinal,
                    fragment.definition_ids[0],
                    fragment,
                )
                for fragment_ordinal, fragment in enumerate(resolution.fragments)
            )
        else:
            rows = []
            for subspan in item.write_subspans:
                try:
                    definition_id, definition = definitions_by_write[
                        (item.action.operation_key, subspan.write_ordinal)
                    ]
                except KeyError as exc:
                    raise ValueError("pre-SSA call write is absent from SSA") from exc
                if not definition.span.contains(subspan.span):
                    raise ValueError("SSA write does not contain its call-port subspan")
                rows.append(
                    CallWriteSubspanBinding(
                        subspan.write_ordinal,
                        definition_id,
                        definition,
                        subspan.span,
                    )
                )
            write_subspans = tuple(rows)
        bound_ports.append(
            CallEffectPortBinding._create(
                item.port,
                effects.effect_evidence_digest,
                memory.unit_digest,
                action_id,
                item.action.operation_key,
                read_fragments,
                write_subspans,
            )
        )

    bindings_by_occurrence: dict[bytes, list[CallEffectPortBinding]] = {
        seed.occurrence.occurrence_digest: [] for seed in seeds.callsites
    }
    for binding in bound_ports:
        bindings_by_occurrence[binding.port.occurrence.occurrence_digest].append(binding)
    sites = []
    for seed, record in zip(seeds.callsites, effects.calls, strict=True):
        action_id = action_ids[seed.operation_key]
        sites.append(
            CallSiteObservation(
                seed,
                ObservedCallTransition(
                    seed.occurrence.occurrence_digest,
                    MemoryActionRef(memory.unit_digest, action_id),
                    effects.effect_evidence_digest,
                    record.pre_read_completeness,
                    record.post_write_completeness,
                    tuple(
                        sorted(
                            bindings_by_occurrence[
                                seed.occurrence.occurrence_digest
                            ],
                            key=lambda item: item.canonical_key,
                        )
                    ),
                    record.debts,
                ),
            )
        )
    return FunctionCallObservations._create(
        seeds,
        effects,
        layout,
        memory_binding,
        tuple(sites),
    )


def _validate_pre_ssa_relations(layout: PreSsaCallPortLayout) -> None:
    actions = tuple(
        action for block in layout.memory_unit.blocks for action in block.actions
    )
    action_ids = {id(action) for action in actions}
    seed_by_occurrence = {seed.occurrence: seed for seed in layout.seeds.callsites}
    for binding in layout.bindings:
        seed = seed_by_occurrence[binding.port.occurrence]
        if id(binding.action) not in action_ids:
            raise ValueError("pre-SSA binding must retain an exact unit action")
        if binding.action.operation_key != seed.operation_key:
            raise ValueError("pre-SSA port is bound to another call action")
        action = binding.action
        if binding.read_ordinal is not None:
            if (
                binding.read_ordinal >= len(action.reads)
                or action.reads[binding.read_ordinal] != binding.port.span
            ):
                raise ValueError("pre-SSA read binding does not match the action")
        else:
            for item in binding.write_subspans:
                if (
                    item.write_ordinal >= len(action.writes)
                    or not action.writes[item.write_ordinal].contains(item.span)
                ):
                    raise ValueError("pre-SSA write binding does not match the action")


def _effect_ports(effects: FunctionCallEffectEvidence) -> tuple[CallEffectPort, ...]:
    return tuple(port for record in effects.calls for port in record.ports)


def _port_direction(port: CallEffectPort) -> CallEffectDirection:
    _require_port(port)
    return port.direction


def _port_digest(port: CallEffectPort) -> bytes:
    _require_port(port)
    return port.canonical_digest


def _port_variant_payload(port: CallEffectPort) -> list[object]:
    tag = "configured" if type(port) is ConfiguredCallEffectPort else "raw"
    return [tag, _port_digest(port).hex()]


def _pre_ssa_binding_payload(value: PreSsaCallPortBinding) -> list[object]:
    return [
        _port_digest(value.port).hex(),
        value.action.operation_key,
        value.read_ordinal,
        [
            [item.write_ordinal, list(item.span.canonical_key)]
            for item in value.write_subspans
        ],
    ]


def _site_payload(value: CallSiteObservation) -> list[object]:
    transition = value.transition
    return [
        value.seed.occurrence.occurrence_digest.hex(),
        transition.action.action_id,
        transition.pre_read_completeness.value,
        transition.post_write_completeness.value,
        [item.port_id.hex() for item in transition.port_bindings],
        [
            [
                item.direction.value,
                item.reason.value,
                item.slot_ordinal,
                item.authority_digest.hex(),
                item.evidence_digest.hex(),
            ]
            for item in transition.debts
        ],
    ]


def _validate_exact_span_cover(parent: ByteSpan, spans: tuple[ByteSpan, ...]) -> None:
    if not spans:
        raise ValueError("call-port binding cannot use an empty span cover")
    ordered = sorted(spans, key=lambda span: span.canonical_key)
    cursor = parent.start
    for span in ordered:
        if not parent.contains(span) or span.start != cursor:
            raise ValueError("call-port binding must be an exact gapless cover")
        cursor = span.end
    if cursor != parent.end:
        raise ValueError("call-port binding must cover the complete port")


def _require_port(value: object) -> None:
    if type(value) not in (ConfiguredCallEffectPort, RawObservedCallPort):
        raise TypeError("call port must use an exact closed-union variant")


def _require_exact(value: object, expected: type, label: str) -> None:
    if type(value) is not expected:
        raise TypeError(f"{label} must be an exact {expected.__name__}")


def _require_exact_tuple(value: object, expected: type, label: str) -> None:
    if type(value) is not tuple or any(type(item) is not expected for item in value):
        raise TypeError(f"{label} must be an exact {expected.__name__} tuple")


def _require_text(value: object, label: str) -> None:
    if type(value) is not str or not value:
        raise TypeError(f"{label} must be a nonempty exact str")


def _require_u64(value: object, label: str) -> None:
    if type(value) is not int:
        raise TypeError(f"{label} must be an exact int")
    if value < 0 or value >= 1 << 64:
        raise ValueError(f"{label} must fit unsigned 64-bit")


def _require_digest(value: object, label: str) -> None:
    if type(value) is not bytes:
        raise TypeError(f"{label} must be exact bytes")
    if len(value) != 32 or value == bytes(32):
        raise ValueError(f"{label} must be one nonzero SHA-256 digest")


def _require_strictly_increasing(values, label: str) -> None:
    marker = object()
    previous = marker
    for value in values:
        if previous is not marker and value <= previous:
            raise ValueError(f"{label} must be canonically sorted and unique")
        previous = value


def _direction_rank(value: CallEffectDirection) -> int:
    return 0 if value is CallEffectDirection.PRE_READ else 1


def _digest(payload: object) -> bytes:
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    ).digest()


__all__ = (
    "CALL_PORT_LAYOUT_CONTRACT_VERSION",
    "CALL_TRANSITION_CONTRACT_VERSION",
    "CallEffectPortBinding",
    "CallReadFragmentBinding",
    "CallSiteObservation",
    "CallWriteSubspanBinding",
    "FunctionCallObservations",
    "MemoryActionRef",
    "ObservedCallTransition",
    "PreSsaCallPortBinding",
    "PreSsaCallPortLayout",
    "PreSsaWriteSubspan",
    "bind_call_observations",
    "build_pre_ssa_call_port_layout",
)
