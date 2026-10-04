"""Function-local evidence view used by configured interprocedural slicing."""

from __future__ import annotations

from .._scope_contracts import (
    AddressCoordinate,
    ValidatedInstruction,
    ValidatedOperation,
    ValidatedVarnode,
    VarnodeKindCode,
)
from ..call_seeds import _operation_key as _numeric_operation_key
from ..memory_contracts import MemoryDefinition, MemoryDefinitionKind
from ..model import ByteSpan, ResolvedStorage, StorageObjectId, StorageObjectKind
from ..storage import _resolve_validated_storage
from .configured_control_order import block_dominators as _block_dominators
from .configured_function_control import _FunctionControlOrderMixin
from .configured_function_memory import _FunctionMemoryViewMixin
from .configured_function_values import _FunctionValueProjectionMixin
from .configured_interprocedural_contracts import ConfiguredFunctionAnalysis
from .configured_interprocedural_records import (
    PointerPath as _PointerPath,
    WriteEvent as _WriteEvent,
)
from .configured_memory_projection import (
    definition_ids_covering_span as _definition_ids_covering_span,
)
from .configured_value_domain import (
    FINITE_VALUE_LIMIT as _FINITE_VALUE_LIMIT,
    combine_finite_integer_values as _combine_finite_integer_values,
    compose_pointer_path as _compose_pointer_path,
    merge_finite_coordinate_sets as _merge_finite_coordinate_sets,
    merge_finite_value_sets as _merge_finite_value_sets,
    pointer_path_head as _pointer_path_head,
    pointer_path_sort_key as _pointer_path_sort_key,
    sign_extend as _sign_extend,
    signed_constant as _signed_constant,
    signed_width_value as _signed_width_value,
    storage_ref as _storage_ref,
)

def _exact_memory_reference(
    instruction: ValidatedInstruction,
) -> tuple[int, AddressCoordinate, int, bool] | None:
    """Match one typed instruction reference to one P-Code memory access."""
    accesses = []
    for ordinal, operation in enumerate(instruction.operations):
        if operation.opcode == "LOAD" and operation.output is not None:
            accesses.append((ordinal, operation.output.byte_size, True))
        elif operation.opcode == "STORE" and len(operation.inputs) == 3:
            accesses.append((ordinal, operation.inputs[2].byte_size, False))
    if len(accesses) != 1:
        return None
    ordinal, byte_size, read = accesses[0]
    references = tuple(
        reference
        for reference in instruction.data_references
        if (
            reference.is_read
            and not reference.is_write
            if read
            else reference.is_write and not reference.is_read
        )
    )
    if len(references) != 1:
        return None
    return ordinal, references[0].coordinate, byte_size, read


class _FunctionView(
    _FunctionControlOrderMixin,
    _FunctionMemoryViewMixin,
    _FunctionValueProjectionMixin,
):
    def __init__(self, analysis: ConfiguredFunctionAnalysis) -> None:
        self.analysis = analysis
        self.normalized = analysis.normalized
        self.memory = analysis.normalized.memory_ssa
        self.memory_graph = analysis.normalized.memory_graph
        if self.memory is None or self.memory_graph is None:
            raise ValueError("interprocedural completion requires local-memory SSA")
        observation = analysis.evidence.unit.observation
        if observation is None:
            raise ValueError("interprocedural completion requires exact observation")
        self.observation = observation
        self.operations: dict[str, tuple[int, ValidatedOperation]] = {}
        self.operation_flow_targets: dict[str, tuple[AddressCoordinate, ...]] = {}
        self.operation_coordinate_references: dict[
            str, tuple[AddressCoordinate, ...]
        ] = {}
        self.operation_function_references: dict[
            str, tuple[AddressCoordinate, ...]
        ] = {}
        self.instruction_operation_keys: dict[str, tuple[str, ...]] = {}
        self.operation_exact_read_spans: dict[str, ByteSpan] = {}
        self.operation_exact_write_spans: dict[str, ByteSpan] = {}
        program_scope = analysis.evidence.unit.scopes.program.scope
        position = 0
        for instruction in observation.instructions:
            memory_reference = _exact_memory_reference(instruction)
            keyed_operations = tuple(
                (
                    _numeric_operation_key(
                        instruction.address, ordinal, operation.opcode
                    ),
                    ordinal,
                    operation,
                )
                for ordinal, operation in enumerate(instruction.operations)
            )
            instruction_keys = tuple(row[0] for row in keyed_operations)
            for key, ordinal, operation in keyed_operations:
                self.operations[key] = (position, operation)
                self.operation_flow_targets[key] = instruction.flow_targets
                self.instruction_operation_keys[key] = instruction_keys
                self.operation_coordinate_references[key] = tuple(
                    reference.coordinate
                    for reference in instruction.data_references
                    if not reference.is_read and not reference.is_write
                )
                self.operation_function_references[key] = tuple(
                    reference.referenced_function_entry
                    for reference in instruction.data_references
                    if not reference.is_read
                    and not reference.is_write
                    and reference.referenced_function_entry is not None
                )
                if memory_reference is not None and ordinal == memory_reference[0]:
                    _, coordinate, byte_size, read = memory_reference
                    span = ByteSpan(
                        StorageObjectId(
                            StorageObjectKind.ADDRESS_SPACE,
                            program_scope,
                            coordinate.space_id,
                        ),
                        coordinate.byte_offset,
                        byte_size,
                    )
                    target = (
                        self.operation_exact_read_spans
                        if read
                        else self.operation_exact_write_spans
                    )
                    target[key] = span
                position += 1
        self.action_ids = {
            action.operation_key: action_id
            for action_id, action in enumerate(self.memory.actions)
        }
        self.storage_actions = {
            action.operation_key: action
            for block in analysis.normalized.memory_unit.blocks
            for action in block.actions
        }
        self.operation_blocks = {
            action.operation_key: block.key
            for block in analysis.normalized.memory_unit.blocks
            for action in block.actions
        }
        self._dominators = _block_dominators(analysis.normalized.memory_unit)
        self._successors = {
            block.key: set() for block in analysis.normalized.memory_unit.blocks
        }
        for block in analysis.normalized.memory_unit.blocks:
            for predecessor in block.predecessors:
                self._successors[predecessor].add(block.key)
        self.space_bits = {
            row.space_id: row.address_size_bits
            for row in analysis.evidence.unit.scopes.program.evidence.address_spaces
        }
        self.loaded_memory_space_ids = tuple(
            sorted(
                row.space_id
                for row in analysis.evidence.unit.scopes.program.evidence.address_spaces
                if row.is_memory_space and row.is_loaded_memory_space
            )
        )
        self._pointer_cache: dict[tuple[int, int, int], _PointerPath | None] = {}
        self._pointer_active: set[tuple[int, int, int]] = set()
        self._constant_cache: dict[tuple[int, int, int], int | None] = {}
        self._constant_active: set[tuple[int, int, int]] = set()
        self._integer_values_cache: dict[
            tuple[int, int, int], frozenset[int] | None
        ] = {}
        self._integer_values_active: set[tuple[int, int, int]] = set()
        self._join_sources = {
            row.join_definition_id: row.source_definition_ids
            for row in self.memory.joins
        }
        self._pointer_candidates_cache: dict[
            tuple[int, int, int], tuple[_PointerPath, ...]
        ] = {}
        self._pointer_candidates_active: set[tuple[int, int, int]] = set()
        self._coordinate_cache: dict[
            tuple[int, int, int], AddressCoordinate | None
        ] = {}
        self._coordinate_active: set[tuple[int, int, int]] = set()
        self._coordinate_values_cache: dict[
            tuple[int, int, int], frozenset[AddressCoordinate] | None
        ] = {}
        self._coordinate_values_active: set[tuple[int, int, int]] = set()
        self._relative_object_cache: dict[
            tuple[int, int, int, int, int], StorageObjectId | None
        ] = {}

    @property
    def scope_digest(self) -> bytes:
        return self.analysis.evidence.unit.scopes.function.scope.digest

    def position(self, operation_key: str) -> int | None:
        row = self.operations.get(operation_key)
        return None if row is None else row[0]

    def operation(self, operation_key: str) -> ValidatedOperation | None:
        row = self.operations.get(operation_key)
        return None if row is None else row[1]



















































__all__ = ["_FunctionView", "_exact_memory_reference"]
