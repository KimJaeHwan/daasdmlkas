"""Allocation evidence consumed by the ORIGINAL byte-range exclusion path."""
from dataclasses import dataclass, replace

from ._allocation_lifetime import AllocationAnalysis
from ._call_activation import _single, _stack
from ._forward_memory import MemoryRefinement, ReadSeparation, _signature
from .resource_limits import step
from .span_geometry import ByteSpan


@dataclass(frozen=True, slots=True)
class ExistingStackRange:
    allocation: object
    span: ByteSpan
    lower: int
    upper: int
    requires: tuple


def stack_range(analysis, allocation, span):
    """Existing active frame at birth, NOT every SP-relative displacement.

    Freshness/owned-range contracts cannot license an arbitrary pointer+N
    exclusion. The whole requested byte range must predate the allocation
    inside the observed active frame, independently of that range's contents.
    The allocating CALL's own return-address slot (its observed push, just
    below the stack pointer at the call: ``normalize._push_row``) counts too
    -- not the caller's frame but the callee's: the owned-footprint contract
    is read as "the block is disjoint from memory live during the allocating
    call", and that slot holds the return address until the callee returns.
    """
    from .observed_call_state import observed_call_state_projections
    geometry = _stack(analysis.item)
    if geometry is None or span.object_id != geometry[0] or analysis.numeric.bind is None:
        return None
    obj, bias, _, offset, width = geometry
    if width != 8:
        return None
    register = analysis.port((offset, width))
    values, used = analysis.numeric.bind(allocation.event, (register,))
    before = _single(values[register], 64)   # (x64 only: C3)
    if before is None or before[0] != ("entry", offset, width):
        return None
    push = max((-row.memory_transition.displacement_delta
                for row in observed_call_state_projections(analysis.item.unit.observation)
                if row.call_operation_key == allocation.event
                and (row.memory_transition.caller_base.byte_offset, row.memory_transition.caller_base.byte_size)
                == (offset, width)), default=0)
    lower, upper = bias + before[1] - max(push, 0), bias
    if not 0 <= lower <= span.start or span.end > upper:
        return None
    requires = tuple(sorted(set(used) | set(analysis.numeric.labels)))
    return ExistingStackRange(allocation, span, lower, upper, requires)


def prepare_allocation_refinement(item, options, *, results=None, assumptions=()):
    """One independent batch. Previous batches remain recursively validated."""
    from .normalize import NormalizedFunction
    if not item.allocation_contracts or type(item.normalized) is not NormalizedFunction \
            or item.normalized.forward_inputs is None:
        return None
    from ._call_activation import _policy
    from ._call_activation import _source_signature
    from ._scope_contracts import VarnodeKindCode
    from .model import ResolvedStorage
    with _policy(item):
        analysis = AllocationAnalysis(item, readonly_image=options.get("readonly_image"), results=results)
        old = item.normalized.forward_inputs.read_separations
        if old is not None:
            old.verify()
        proofs = list(item.normalized.forward_memory_proofs)
        existing = {(proof.read, proof.writer, proof.span) for proof in proofs}
        effects = {row.operation_key: row for row in item.normalized.effects}
        overrides = dict(item.normalized.operation_overrides)
        spaces = {space.space_id: space for space in item.unit.scopes.program.evidence.address_spaces}
        added = False
        for row in item.normalized.may_alias_reads:
            load = analysis.ops.get(row.operation_key)
            effect = effects.get(row.operation_key)
            if row.unknown_address or row.operation_key in overrides or load is None or load.opcode != "LOAD" \
                    or effect is None or effect.memory_read is not None or effect.unresolved_reads \
                    or load.inputs[0].kind is not VarnodeKindCode.CONSTANT:
                continue
            space = spaces.get(load.inputs[0].coordinate.byte_offset)
            if space is None or not space.is_memory_space or space.address_size_bits != 64:
                continue
            reads = [value.span for value in effect.reads if type(value) is ResolvedStorage
                     and value.span.object_id.kind.value in ("address_space", "function_relative")]
            if len(reads) != 1 or load.output is None or reads[0].size != load.output.byte_size:
                continue
            for writer in row.plain:
                step()
                store = analysis.ops.get(writer)
                write_effect = effects.get(writer)
                if writer in overrides or store is None or store.opcode != "STORE" or write_effect is None \
                        or write_effect.memory_write is not None or write_effect.unresolved_writes \
                        or store.inputs[0].kind is not VarnodeKindCode.CONSTANT \
                        or store.inputs[0].coordinate.byte_offset != space.space_id:
                    continue
                writes = [value.span for value in write_effect.writes if type(value) is ResolvedStorage
                          and value.span.object_id.kind.value in ("address_space", "function_relative")]
                if len(writes) != 1 or writes[0].size != store.inputs[2].byte_size:
                    continue
                evidence = analysis.access(writer)
                if evidence is None:
                    continue
                for span in row.spans:
                    if span != reads[0] or (row.operation_key, writer, span) in existing:
                        continue
                    witnesses = [stack_range(analysis, target.allocation, span)
                                 for target in evidence.pointer.targets]
                    if not witnesses or any(witness is None for witness in witnesses):
                        continue
                    # Keep the standard ReadSeparation byte consumer, with a
                    # distinct immutable proof kind instead of numeric Fact.
                    proofs.append(ReadSeparation(row.operation_key, writer, span, tuple(witnesses), evidence))
                    existing.add((row.operation_key, writer, span))
                    added = True
                    if len(proofs) > 128:
                        return None
        if not added:
            return None
        requires = set(assumptions) | set(analysis.requires) | set(item.normalized.forward_memory_requires)
        for proof in proofs:
            if isinstance(proof.read_fact, tuple):
                for witness in proof.read_fact:
                    requires.update(witness.requires)
                requires.update(proof.write_fact.requires)
            else:
                requires.update(proof.read_fact.requires)
                requires.update(proof.write_fact.requires)
        peers = tuple(sorted((results or {}).items()))
        return MemoryRefinement(item.unit, item.normalized, _signature(options), tuple(proofs),
                                tuple(sorted(requires)), tuple(options.items()), item, tuple(assumptions),
                                "allocation", peers, item.allocation_contracts,
                                tuple((key, _source_signature(peer)) for key, peer in peers))


def prepare_allocation_call_refinement(item, *, results=None):
    """Close only independently proven CALL/range obligations on one N0."""
    from ._call_activation import _policy, _source_signature
    from ._call_memory import CallMemoryDecision, memory_demands
    from .normalize import _call_below_bounds
    from .observed_call_state import observed_call_state_projections
    from .normalize import NormalizedFunction
    if not item.allocation_contracts or type(item.normalized) is not NormalizedFunction \
            or item.normalized.forward_inputs is None:
        return None
    with _policy(item):
        analysis = AllocationAnalysis(item, readonly_image=dict(item.normalization_options).get("readonly_image"),
                                      results=results)
        prior = item.normalized.forward_inputs.read_separations
        if prior is not None:
            prior.verify()
        effects = dict(item.proven)
        transitions = {row.call_operation_key: row.memory_transition
                       for row in observed_call_state_projections(item.unit.observation)}
        bounds = {key: (obj, bound) for key, obj, bound in _call_below_bounds(
            effects, transitions, item.normalized.forward_inputs.effect_unit, item.normalized.memory_ssa,
            item.unit.observation, item.unit.scopes, item.unit.scopes.resolution_context, include_unpreserved=True)}
        decisions, life_of = [], {}
        for demand in memory_demands(item.normalized):
            step()
            contract = analysis.contracts.get(demand.call)
            effect = effects.get(demand.call)
            if contract is None or contract.kind != "resize" or not contract.owned_footprint or effect is None:
                continue
            file, entry, _ = analysis.models[demand.call]
            if not entry.keeps_other_memory or effect.memory_runs or effect.unknown_memory \
                    or effect.writer_conditions or effect.extent_registers or not effect.restores_stack \
                    or not effect.clobbers_below or effect.noreturn:
                continue
            if demand.call not in life_of:
                pointer = analysis.argument(demand.call, contract.pointer)
                life_of[demand.call] = analysis.lifetime(pointer, demand.call)
            life = life_of[demand.call]
            if not life.live or any(target.offset != 0 for target in life.pointer.targets):
                continue
            transition, bound = transitions.get(demand.call), bounds.get(demand.call)
            if transition is None or transition.displacement_delta != -8 or bound is None \
                    or demand.span.object_id != bound[0] or demand.span.start < bound[1] + 8:
                continue
            witnesses = tuple(stack_range(analysis, target.allocation, demand.span) for target in life.pointer.targets)
            if not witnesses or any(witness is None for witness in witnesses):
                continue
            requires = set(analysis.requires) | set(life.requires) | {contract.label, entry.label} | set(entry.inherited)
            requires.update(item.normalized.forward_memory_requires)
            for witness in witnesses:
                requires.update(witness.requires)
            decisions.append(CallMemoryDecision(demand, True, "live-owned-allocation-disjoint-stack",
                tuple(sorted(requires)), file.digest, entry.label, (life, *witnesses)))
        if not decisions:
            return None
        for decision in decisions:
            effect = effects[decision.demand.call]
            effects[decision.demand.call] = replace(effect, preserved=tuple(sorted(
                set(effect.preserved) | {decision.demand.span}, key=lambda span: span.canonical_key)))
        options = dict(item.normalization_options)
        options["proven_call_effects"] = effects
        requires = set(analysis.requires) | set(item.normalized.forward_memory_requires)
        requires.update(label for decision in decisions for label in decision.requires)
        peers = tuple(sorted((results or {}).items()))
        return MemoryRefinement(item.unit, item.normalized, _signature(options),
            item.normalized.forward_memory_proofs, tuple(sorted(requires)), tuple(options.items()), item, (),
            "allocation-call", peers, item.allocation_contracts,
            tuple((key, _source_signature(peer)) for key, peer in peers),
            tuple((call, effects[call]) for call in sorted({row.demand.call for row in decisions})), tuple(decisions))


def accepts_allocation_calls(plan, candidate, results):
    """The approved CALL must not establish its own original input proof."""
    plan.verify()
    analysis = AllocationAnalysis(candidate, readonly_image=dict(candidate.normalization_options).get("readonly_image"),
                                  results=results)
    for row in plan.call_decisions:
        life = row.evidence[0]
        contract = analysis.contracts.get(row.demand.call)
        if contract is None:
            return False
        pointer = analysis.argument(row.demand.call, contract.pointer)
        if (pointer.targets, pointer.nulls, pointer.unknown, pointer.definitions) != (
                life.pointer.targets, life.pointer.nulls, life.pointer.unknown, life.pointer.definitions):
            return False
        if analysis.lifetime(pointer, row.demand.call).states != life.states:
            return False
        if any(debt.operation_key == row.demand.reader and row.demand.call in debt.intervening_calls
               and any(span.overlaps(row.demand.span) for span in debt.spans)
               for debt in candidate.normalized.call_clobber_reads):
            return False
    return True
