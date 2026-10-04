"""The sole canonical wire-encoding and digest owner for scope construction."""

from __future__ import annotations

from hashlib import sha256
from typing import Callable

from ._scope_contracts import (
    AddressCoordinate,
    AddressSpaceEvidence,
    CommittedMemoryRun,
    FunctionScopeEvidence,
    InstructionDataReference,
    U64_LIMIT,
    ValidatedFunctionObservation,
    ValidatedInstruction,
    ValidatedOperation,
    ValidatedVarnode,
    VerifiedProgramSnapshotEvidence,
    require_bool,
    require_exact,
    require_u64,
)
from .model import StorageScopeId, StorageScopeKind


def _u64(value: int) -> bytes:
    require_u64(value, "encoded integer")
    return value.to_bytes(8, byteorder="big", signed=False)


def _bool(value: bool) -> bytes:
    require_bool(value, "encoded boolean")
    return b"\x01" if value else b"\x00"


def _bytes(value: bytes) -> bytes:
    if type(value) is not bytes:
        raise TypeError("encoded byte string must be exact bytes")
    if len(value) >= U64_LIMIT:
        raise ValueError("encoded byte string length exceeds unsigned 64-bit")
    return _u64(len(value)) + value


def _text(value: str) -> bytes:
    if type(value) is not str:
        raise TypeError("encoded text must be an exact str")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("encoded text must be strict UTF-8") from exc
    return _bytes(encoded)


def _coordinate(value: AddressCoordinate) -> bytes:
    require_exact(value, AddressCoordinate, "encoded coordinate")
    return _u64(value.space_id) + _u64(value.byte_offset)


def _program_scope_preimage(evidence: VerifiedProgramSnapshotEvidence) -> bytes:
    require_exact(evidence, VerifiedProgramSnapshotEvidence, "program evidence")
    namespace = evidence.translation_namespace
    if evidence.address_space_classification_revision == 2:
        return b"".join(
            (
                _text("tdo-v2-program-scope-v2"),
                _bytes(evidence.executable_sha256),
                _bytes(evidence.loaded_memory_digest),
                _coordinate(evidence.image_base),
                _text(namespace.language_id),
                _u64(namespace.major_version),
                _u64(namespace.minor_version),
                _u64(2),
                _u64(len(evidence.address_spaces)),
                *(_address_space_v2(row) for row in evidence.address_spaces),
            )
        )
    return b"".join(
        (
            _text("tdo-v2-program-scope-v1"),
            _bytes(evidence.executable_sha256),
            _bytes(evidence.loaded_memory_digest),
            _coordinate(evidence.image_base),
            _text(namespace.language_id),
            _u64(namespace.major_version),
            _u64(namespace.minor_version),
        )
    )


def _address_space_v2(value: AddressSpaceEvidence) -> bytes:
    require_exact(value, AddressSpaceEvidence, "revision-2 address space")
    if value.classification_revision != 2:
        raise ValueError("revision-2 preimage requires revision-2 address spaces")
    return b"".join(
        (
            _u64(value.space_id),
            _u64(value.address_size_bits),
            _u64(value.addressable_unit_bytes),
            _bool(value.has_signed_offset),
            _bool(value.is_constant_space),
            _bool(value.is_register_space),
            _bool(value.is_unique_space),
            _bool(value.is_memory_space),
            _bool(value.is_loaded_memory_space),
            _bool(value.is_non_loaded_memory_space),
            _bool(value.is_overlay_space),
            _bool(value.is_external_space),
        )
    )


def _function_scope_preimage(evidence: FunctionScopeEvidence) -> bytes:
    require_exact(evidence, FunctionScopeEvidence, "function evidence")
    return b"".join(
        (
            _text("tdo-v2-function-scope-v1"),
            _bytes(evidence.program_scope.digest),
            _coordinate(evidence.entry),
            _bytes(evidence.observation_digest),
        )
    )


def _derive_program_scope(evidence: VerifiedProgramSnapshotEvidence) -> StorageScopeId:
    return StorageScopeId(
        StorageScopeKind.PROGRAM,
        sha256(_program_scope_preimage(evidence)).digest(),
    )


def _derive_function_scope(evidence: FunctionScopeEvidence) -> StorageScopeId:
    return StorageScopeId(
        StorageScopeKind.FUNCTION,
        sha256(_function_scope_preimage(evidence)).digest(),
    )


class _LoadedMemoryDigestBuilder:
    __slots__ = ("_digest", "_open_bytes", "_remaining", "_runs_left")

    def __init__(self, run_count: int) -> None:
        require_u64(run_count, "memory run count")
        self._digest = sha256()
        self._digest.update(_text("tdo-v2-loaded-memory-v1"))
        self._digest.update(_u64(run_count))
        self._open_bytes = False
        self._remaining = 0
        self._runs_left = run_count

    def start_run(self, run: CommittedMemoryRun) -> None:
        require_exact(run, CommittedMemoryRun, "memory run")
        if self._open_bytes or self._runs_left == 0:
            raise RuntimeError("memory digest run sequencing is invalid")
        self._digest.update(_coordinate(AddressCoordinate(run.space_id, run.byte_start)))
        self._digest.update(_u64(run.byte_size))
        self._digest.update(_bool(run.is_initialized))
        self._runs_left -= 1
        if run.is_initialized:
            self._digest.update(_u64(run.byte_size))
            self._open_bytes = True
            self._remaining = run.byte_size

    def update_bytes(self, data: bytes) -> None:
        if not self._open_bytes:
            raise RuntimeError("memory digest has no initialized run awaiting bytes")
        if type(data) is not bytes or not data:
            raise TypeError("memory digest data must be non-empty exact bytes")
        if len(data) > self._remaining:
            raise ValueError("memory digest received too many bytes")
        self._digest.update(data)
        self._remaining -= len(data)
        if self._remaining == 0:
            self._open_bytes = False

    def finish(self) -> bytes:
        if self._open_bytes or self._runs_left:
            raise RuntimeError("memory digest stream is incomplete")
        return self._digest.digest()


def _validated_varnode_preimage(value: ValidatedVarnode) -> bytes:
    require_exact(value, ValidatedVarnode, "validated varnode")
    return b"".join(
        (
            _u64(value.kind.value),
            _coordinate(value.coordinate),
            _u64(value.byte_size),
        )
    )


def _validated_operation_preimage(value: ValidatedOperation) -> bytes:
    require_exact(value, ValidatedOperation, "validated operation")
    output = b"\x00"
    if value.output is not None:
        output = b"\x01" + _validated_varnode_preimage(value.output)
    return b"".join(
        (
            _text(value.opcode),
            _u64(len(value.inputs)),
            *(_validated_varnode_preimage(item) for item in value.inputs),
            output,
        )
    )


def _instruction_data_reference_preimage(value: InstructionDataReference) -> bytes:
    require_exact(value, InstructionDataReference, "instruction data reference")
    entry = b"\x00"
    if value.referenced_function_entry is not None:
        entry = b"\x01" + _coordinate(value.referenced_function_entry)
    return b"".join(
        (
            _coordinate(value.coordinate),
            _bool(value.is_read),
            _bool(value.is_write),
            entry,
        )
    )


def _validated_instruction_preimage(value: ValidatedInstruction) -> bytes:
    require_exact(value, ValidatedInstruction, "validated instruction")
    fallthrough = b"\x00"
    if value.fallthrough is not None:
        fallthrough = b"\x01" + _coordinate(value.fallthrough)
    pieces = [
            _coordinate(value.address),
            fallthrough,
            _u64(len(value.flow_targets)),
            *(_coordinate(item) for item in value.flow_targets),
            _validated_flow_preimage(value.flow),
            _u64(len(value.operations)),
            *(_validated_operation_preimage(item) for item in value.operations),
    ]
    if value.data_references:
        pieces.extend(
            (
                _text("tdo-v2-instruction-data-references-v2"),
                _u64(len(value.data_references)),
                *(
                    _instruction_data_reference_preimage(item)
                    for item in value.data_references
                ),
            )
        )
    return b"".join(pieces)


def _observation_preimage(value: ValidatedFunctionObservation) -> bytes:
    require_exact(value, ValidatedFunctionObservation, "validated observation")
    return b"".join(
        (
            _text("tdo-v2-function-observation-v2"),
            _u64(len(value.instructions)),
            *(_validated_instruction_preimage(item) for item in value.instructions),
        )
    )


def _observation_digest(value: ValidatedFunctionObservation) -> bytes:
    require_exact(value, ValidatedFunctionObservation, "validated observation")
    digest = sha256()
    digest.update(_text("tdo-v2-function-observation-v2"))
    digest.update(_u64(len(value.instructions)))
    _stream_observation(value, digest.update)
    return digest.digest()


def _stream_observation(
    value: ValidatedFunctionObservation,
    update: Callable[[bytes], object],
) -> None:
    for instruction in value.instructions:
        update(_coordinate(instruction.address))
        if instruction.fallthrough is None:
            update(b"\x00")
        else:
            update(b"\x01")
            update(_coordinate(instruction.fallthrough))
        update(_u64(len(instruction.flow_targets)))
        for target in instruction.flow_targets:
            update(_coordinate(target))
        update(_validated_flow_preimage(instruction.flow))
        update(_u64(len(instruction.operations)))
        for operation in instruction.operations:
            update(_text(operation.opcode))
            update(_u64(len(operation.inputs)))
            for varnode in operation.inputs:
                update(_validated_varnode_preimage(varnode))
            if operation.output is None:
                update(b"\x00")
            else:
                update(b"\x01")
                update(_validated_varnode_preimage(operation.output))
        if instruction.data_references:
            update(_text("tdo-v2-instruction-data-references-v2"))
            update(_u64(len(instruction.data_references)))
            for reference in instruction.data_references:
                update(_instruction_data_reference_preimage(reference))


def _validated_flow_preimage(value) -> bytes:
    flags = (
        value.is_flow,
        value.has_fallthrough,
        value.is_call,
        value.is_jump,
        value.is_terminal,
        value.is_computed,
        value.is_conditional,
        value.is_unconditional,
        value.is_override,
    )
    return bytes(int(flag) for flag in flags)
