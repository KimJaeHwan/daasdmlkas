"""Architect-owned projection from scoped Low-PCode to numeric call seeds."""

from __future__ import annotations

from .call_contracts import (
    CALL_OBSERVATION_CONTRACT_VERSION,
    CallOperationKind,
    CallSeedFailureReason,
    CallSiteLocator,
    CallSiteSeed,
    CallTargetFailureReason,
    DirectCallTarget,
    FunctionCallSeedResult,
    FunctionCallSeedUnit,
    IndirectCallTarget,
    InstructionFlowContext,
    UnresolvedCallTarget,
    UnresolvedFunctionCallSeeds,
    _mint_call_seed_permit,
    _seed_digest,
)
from ._scope_contracts import VarnodeKindCode
from ._scope_results import (
    ConstructedFunctionScope,
    ConstructedProgramScope,
    ScopedFunctionUnit,
)


__all__ = ("seed_function_calls",)


def seed_function_calls(unit: ScopedFunctionUnit, /) -> FunctionCallSeedResult:
    """Preserve explicit CALL/CALLIND facts without target or ABI inference."""
    if type(unit) is not ScopedFunctionUnit:
        raise TypeError("call seeding requires an exact ScopedFunctionUnit")
    if unit.observation is None:
        return UnresolvedFunctionCallSeeds(
            unit.scopes,
            CallSeedFailureReason.MISSING_VALIDATED_OBSERVATION,
        )
    program = unit.scopes.program
    function = unit.scopes.function
    if type(program) is not ConstructedProgramScope or type(function) is not ConstructedFunctionScope:
        return UnresolvedFunctionCallSeeds(
            unit.scopes,
            CallSeedFailureReason.MISSING_CONSTRUCTED_FUNCTION_SCOPE,
        )

    local_addresses = {
        instruction.address for instruction in unit.observation.instructions
    }
    callsites: list[CallSiteSeed] = []
    for instruction in unit.observation.instructions:
        call_targets = tuple(
            target
            for target in instruction.flow_targets
            if target not in local_addresses or target == function.entry
        )
        context = InstructionFlowContext(
            instruction.fallthrough,
            call_targets,
        )
        for ordinal, operation in enumerate(instruction.operations):
            if operation.opcode == "CALL":
                kind = CallOperationKind.DIRECT
            elif operation.opcode == "CALLIND":
                kind = CallOperationKind.INDIRECT
            else:
                continue
            target = _target(kind, operation.inputs)
            callsites.append(
                CallSiteSeed(
                    locator=CallSiteLocator(function.scope, instruction.address, ordinal),
                    operation_key=_operation_key(instruction.address, ordinal, operation.opcode),
                    kind=kind,
                    inputs=operation.inputs,
                    explicit_output=operation.output,
                    target=target,
                    instruction_context=context,
                )
            )

    callsites.sort(key=lambda site: site.canonical_key)
    frozen_callsites = tuple(callsites)
    digest = _seed_digest(
        program.scope,
        function.scope,
        function.entry,
        function.observation_digest,
        frozen_callsites,
    )
    permit = _mint_call_seed_permit(digest)
    try:
        return FunctionCallSeedUnit._create(
            CALL_OBSERVATION_CONTRACT_VERSION,
            program.scope,
            function.scope,
            function.entry,
            function.observation_digest,
            frozen_callsites,
            permit,
        )
    finally:
        permit.revoke()


def _target(kind: CallOperationKind, inputs: tuple):
    if not inputs:
        return UnresolvedCallTarget(CallTargetFailureReason.MISSING_SELECTOR)
    selector = inputs[0]
    if kind is CallOperationKind.INDIRECT:
        return IndirectCallTarget(selector)
    if selector.kind is VarnodeKindCode.ADDRESS:
        return DirectCallTarget(selector.coordinate)
    return UnresolvedCallTarget(
        CallTargetFailureReason.DIRECT_SELECTOR_NOT_ADDRESS,
        selector,
    )


def _operation_key(address, ordinal: int, opcode: str) -> str:
    return f"{address.space_id:x}:{address.byte_offset:x}:{ordinal}:{opcode}"
