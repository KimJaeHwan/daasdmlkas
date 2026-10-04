"""Raw function observation projection with total defect collection."""

from __future__ import annotations

from dataclasses import dataclass

from ._scope_contracts import (
    AddressCoordinate,
    InstructionDataReference,
    InstructionFlowEvidence,
    MAX_CALL_CONTEXT_TARGET_REFERENCES,
    MAX_CALL_OCCURRENCES,
    MAX_DATA_REFERENCES_PER_INSTRUCTION,
    MAX_FLOW_TARGETS_PER_INSTRUCTION,
    MAX_FUNCTION_DATA_REFERENCES,
    MAX_FUNCTION_FLOW_TARGETS,
    MAX_FUNCTION_INSTRUCTIONS,
    MAX_FUNCTION_OPERATIONS,
    MAX_FUNCTION_VARNODES,
    MAX_OPCODE_ASCII_BYTES,
    MAX_OPERATION_INPUTS,
    ValidatedFunctionObservation,
    ValidatedInstruction,
    ValidatedOperation,
    ValidatedVarnode,
    VarnodeKindCode,
    _is_valid_opcode,
)
from ._scope_program import _AddressSpaceIndex, _parse_coordinate
from ._scope_raw import RawObject, _FieldState, _field, _has_duplicate
from ._scope_wire import _observation_digest


@dataclass(slots=True)
class _ObservationDefects:
    duplicate: bool = False
    invalid: bool = False
    incomplete: bool = False
    conflicting: bool = False
    operation_count: int = 0
    varnode_count: int = 0
    flow_target_count: int = 0
    data_reference_count: int = 0
    call_count: int = 0
    call_context_target_references: int = 0


@dataclass(frozen=True, slots=True)
class _FunctionValidation:
    duplicate_entry: bool
    missing_entry: bool
    invalid_entry: bool
    duplicate_observation: bool
    missing_observation: bool
    invalid_observation: bool
    incomplete_observation: bool
    conflicting_observation: bool
    entry: AddressCoordinate | None
    observation: ValidatedFunctionObservation | None
    observation_digest: bytes | None


def _validate_function_candidate(
    raw: object | None,
    index: _AddressSpaceIndex,
) -> _FunctionValidation:
    duplicate_entry = False
    missing_entry = False
    invalid_entry = False
    entry = None
    defects = _ObservationDefects()
    missing_observation = raw is None
    observation = None
    digest = None

    if raw is None:
        pass
    elif type(raw) is not RawObject:
        invalid_entry = True
        defects.invalid = True
    else:
        entry_field = _field(raw, "entry")
        if entry_field.state is _FieldState.DUPLICATE:
            duplicate_entry = True
        elif entry_field.state is _FieldState.MISSING:
            missing_entry = True
        else:
            result = _parse_coordinate(entry_field.value)
            entry = result.coordinate
            duplicate_entry |= result.duplicate
            missing_entry |= result.missing
            invalid_entry |= result.invalid
            if entry is not None and not index.memory_coordinate(entry):
                invalid_entry = True

        instructions_field = _field(raw, "instructions")
        if instructions_field.state is _FieldState.DUPLICATE:
            defects.duplicate = True
        elif instructions_field.state is _FieldState.MISSING:
            defects.incomplete = True
        elif type(instructions_field.value) is not tuple:
            defects.invalid = True
        elif len(instructions_field.value) > MAX_FUNCTION_INSTRUCTIONS:
            defects.invalid = True
        else:
            instructions = tuple(
                item
                for position, raw_instruction in enumerate(instructions_field.value)
                if (item := _parse_instruction(raw_instruction, position, index, defects))
                is not None
            )
            addresses = tuple(item.address for item in instructions)
            if len(set(addresses)) != len(addresses):
                defects.conflicting = True
            if not any((defects.duplicate, defects.invalid, defects.incomplete, defects.conflicting)):
                observation = ValidatedFunctionObservation(instructions)
                digest = _observation_digest(observation)

    return _FunctionValidation(
        duplicate_entry,
        missing_entry,
        invalid_entry,
        defects.duplicate,
        missing_observation,
        defects.invalid,
        defects.incomplete,
        defects.conflicting,
        entry,
        observation,
        digest,
    )


def _parse_instruction(
    raw: object,
    position: int,
    index: _AddressSpaceIndex,
    defects: _ObservationDefects,
) -> ValidatedInstruction | None:
    names = (
        "address",
        "fallthrough_present",
        "fallthrough",
        "flow_targets",
        "data_references",
        "flow_type",
        "operations",
    )
    if type(raw) is not RawObject:
        defects.invalid = True
        return None
    defects.duplicate |= _has_duplicate(raw, names)
    address = _coordinate_field(raw, "address", defects)
    if address is not None and not index.memory_coordinate(address):
        defects.invalid = True
    fallthrough = _optional_coordinate(raw, "fallthrough_present", "fallthrough", index, defects)
    targets = _flow_targets(raw, index, defects)
    data_references = _data_references(raw, index, defects)
    flow = _instruction_flow(raw, defects)
    operations_field = _field(raw, "operations")
    operations: tuple[ValidatedOperation, ...] = ()
    if operations_field.state is _FieldState.MISSING:
        defects.incomplete = True
    elif operations_field.state is _FieldState.DUPLICATE:
        defects.duplicate = True
    elif type(operations_field.value) is not tuple:
        defects.invalid = True
    elif len(operations_field.value) > (
        MAX_FUNCTION_OPERATIONS - defects.operation_count
    ):
        defects.invalid = True
    else:
        defects.operation_count += len(operations_field.value)
        operations = tuple(
            item
            for ordinal, raw_operation in enumerate(operations_field.value)
            if (item := _parse_operation(raw_operation, ordinal, index, defects)) is not None
        )
        call_count = sum(
            operation.opcode in ("CALL", "CALLIND") for operation in operations
        )
        context_references = call_count * len(targets)
        if call_count > MAX_CALL_OCCURRENCES - defects.call_count:
            defects.invalid = True
        else:
            defects.call_count += call_count
        if context_references > (
            MAX_CALL_CONTEXT_TARGET_REFERENCES
            - defects.call_context_target_references
        ):
            defects.invalid = True
        else:
            defects.call_context_target_references += context_references
    if address is None or flow is None:
        return None
    try:
        return ValidatedInstruction(
            address,
            fallthrough,
            targets,
            operations,
            flow,
            data_references,
        )
    except (TypeError, ValueError):
        defects.conflicting = True
        return None


def _parse_operation(
    raw: object,
    expected_ordinal: int,
    index: _AddressSpaceIndex,
    defects: _ObservationDefects,
) -> ValidatedOperation | None:
    names = ("ordinal", "opcode", "inputs", "output_present", "output")
    if type(raw) is not RawObject:
        defects.invalid = True
        return None
    defects.duplicate |= _has_duplicate(raw, names)
    ordinal = _field(raw, "ordinal")
    if ordinal.state is _FieldState.MISSING:
        defects.incomplete = True
    elif ordinal.state is _FieldState.DUPLICATE:
        defects.duplicate = True
    elif type(ordinal.value) is not int:
        if isinstance(ordinal.value, int):
            defects.conflicting = True
        else:
            defects.invalid = True
    elif not 0 <= ordinal.value < (1 << 64):
        defects.conflicting = True
    elif ordinal.value != expected_ordinal:
        defects.conflicting = True

    opcode_field = _field(raw, "opcode")
    opcode = None
    if opcode_field.state is _FieldState.MISSING:
        defects.incomplete = True
    elif opcode_field.state is _FieldState.DUPLICATE:
        defects.duplicate = True
    elif not _is_valid_opcode(opcode_field.value, MAX_OPCODE_ASCII_BYTES):
        defects.invalid = True
    else:
        opcode = opcode_field.value

    inputs_field = _field(raw, "inputs")
    inputs: tuple[ValidatedVarnode, ...] = ()
    if inputs_field.state is _FieldState.MISSING:
        defects.incomplete = True
    elif inputs_field.state is _FieldState.DUPLICATE:
        defects.duplicate = True
    elif type(inputs_field.value) is not tuple:
        defects.invalid = True
    elif len(inputs_field.value) > MAX_OPERATION_INPUTS or len(
        inputs_field.value
    ) > (MAX_FUNCTION_VARNODES - defects.varnode_count):
        defects.invalid = True
    else:
        defects.varnode_count += len(inputs_field.value)
        inputs = tuple(
            item
            for raw_varnode in inputs_field.value
            if (item := _parse_varnode(raw_varnode, index, defects)) is not None
        )
    output = _optional_varnode(raw, index, defects)
    if opcode is None:
        return None
    return ValidatedOperation(opcode, inputs, output)


def _parse_varnode(
    raw: object,
    index: _AddressSpaceIndex,
    defects: _ObservationDefects,
) -> ValidatedVarnode | None:
    names = ("kind_code", "space_id", "byte_offset", "byte_size")
    if type(raw) is not RawObject:
        defects.invalid = True
        return None
    defects.duplicate |= _has_duplicate(raw, names)
    fields = tuple(_field(raw, name) for name in names)
    duplicate = any(item.state is _FieldState.DUPLICATE for item in fields)
    missing = any(item.state is _FieldState.MISSING for item in fields)
    defects.duplicate |= duplicate
    defects.incomplete |= missing
    present = tuple(item for item in fields if item.state is _FieldState.PRESENT)
    invalid_present = any(
        type(item.value) is not int or not 0 <= item.value < (1 << 64)
        for item in present
    )
    defects.invalid |= invalid_present
    if duplicate or missing or invalid_present:
        return None
    try:
        kind = VarnodeKindCode(fields[0].value)
    except ValueError:
        defects.invalid = True
        return None
    if kind is VarnodeKindCode.UNKNOWN or fields[3].value == 0:
        defects.invalid = True
        return None
    coordinate = AddressCoordinate(fields[1].value, fields[2].value)
    if not index.contains(coordinate.space_id):
        defects.invalid = True
        return None
    kind_matches = index.kind_matches(coordinate.space_id, kind)
    extent_valid = index.varnode_extent(kind, coordinate, fields[3].value)
    if not kind_matches:
        defects.conflicting = True
    if not extent_valid:
        defects.invalid = True
    if not kind_matches or not extent_valid:
        return None
    return ValidatedVarnode(kind, coordinate, fields[3].value)


def _coordinate_field(raw: RawObject, name: str, defects: _ObservationDefects) -> AddressCoordinate | None:
    field = _field(raw, name)
    if field.state is _FieldState.MISSING:
        defects.incomplete = True
        return None
    if field.state is _FieldState.DUPLICATE:
        defects.duplicate = True
        return None
    return _observation_coordinate(field.value, defects)


def _optional_coordinate(
    raw: RawObject,
    marker_name: str,
    value_name: str,
    index: _AddressSpaceIndex,
    defects: _ObservationDefects,
) -> AddressCoordinate | None:
    marker = _field(raw, marker_name)
    value = _field(raw, value_name)
    if value.state is _FieldState.PRESENT and value.value is not None:
        defects.duplicate |= _nested_coordinate_duplicate(value.value)
    if marker.state is _FieldState.DUPLICATE or value.state is _FieldState.DUPLICATE:
        defects.duplicate = True
    if marker.state is _FieldState.MISSING or value.state is _FieldState.MISSING:
        defects.incomplete = True
    if marker.state is _FieldState.PRESENT and type(marker.value) is not bool:
        defects.invalid = True
    if (
        marker.state is not _FieldState.PRESENT
        or value.state is not _FieldState.PRESENT
        or type(marker.value) is not bool
    ):
        return None
    if marker.value is False:
        if value.value is not None:
            defects.conflicting = True
        return None
    if value.value is None:
        defects.conflicting = True
        return None
    coordinate = _observation_coordinate(value.value, defects)
    if coordinate is None:
        return None
    if not index.memory_coordinate(coordinate):
        defects.invalid = True
    return coordinate


def _flow_targets(
    raw: RawObject,
    index: _AddressSpaceIndex,
    defects: _ObservationDefects,
) -> tuple[AddressCoordinate, ...]:
    field = _field(raw, "flow_targets")
    if field.state is _FieldState.MISSING:
        defects.incomplete = True
        return ()
    if field.state is _FieldState.DUPLICATE:
        defects.duplicate = True
        return ()
    if type(field.value) is not tuple:
        defects.invalid = True
        return ()
    if len(field.value) > MAX_FLOW_TARGETS_PER_INSTRUCTION or len(
        field.value
    ) > (MAX_FUNCTION_FLOW_TARGETS - defects.flow_target_count):
        defects.invalid = True
        return ()
    defects.flow_target_count += len(field.value)
    targets: list[AddressCoordinate] = []
    for raw_target in field.value:
        target = _observation_coordinate(raw_target, defects)
        if target is not None:
            if not index.memory_coordinate(target):
                defects.invalid = True
            targets.append(target)
    return tuple(sorted(set(targets)))


def _data_references(
    raw: RawObject,
    index: _AddressSpaceIndex,
    defects: _ObservationDefects,
) -> tuple[AddressCoordinate, ...]:
    field = _field(raw, "data_references")
    if field.state is _FieldState.MISSING:
        return ()
    if field.state is _FieldState.DUPLICATE:
        defects.duplicate = True
        return ()
    if type(field.value) is not tuple:
        defects.invalid = True
        return ()
    if len(field.value) > MAX_DATA_REFERENCES_PER_INSTRUCTION or len(
        field.value
    ) > (MAX_FUNCTION_DATA_REFERENCES - defects.data_reference_count):
        defects.invalid = True
        return ()
    defects.data_reference_count += len(field.value)
    references: list[InstructionDataReference] = []
    for raw_reference in field.value:
        reference = _parse_data_reference(raw_reference, index, defects)
        if reference is not None:
            if not index.memory_coordinate(reference.coordinate):
                defects.invalid = True
            references.append(reference)
    return tuple(sorted(set(references)))


def _parse_data_reference(
    raw: object,
    index: _AddressSpaceIndex,
    defects: _ObservationDefects,
) -> InstructionDataReference | None:
    names = (
        "space_id",
        "byte_offset",
        "is_read",
        "is_write",
        "referenced_function_entry_present",
        "referenced_function_entry",
    )
    if type(raw) is not RawObject:
        defects.invalid = True
        return None
    defects.duplicate |= _has_duplicate(raw, names)
    coordinate = _observation_coordinate(raw, defects)
    read = _field(raw, "is_read")
    write = _field(raw, "is_write")
    for field in (read, write):
        if field.state is _FieldState.MISSING:
            defects.incomplete = True
        elif field.state is _FieldState.DUPLICATE:
            defects.duplicate = True
        elif type(field.value) is not bool:
            defects.invalid = True
    if (
        coordinate is None
        or read.state is not _FieldState.PRESENT
        or write.state is not _FieldState.PRESENT
        or type(read.value) is not bool
        or type(write.value) is not bool
    ):
        return None
    entry_marker = _field(raw, "referenced_function_entry_present")
    entry_value = _field(raw, "referenced_function_entry")
    if (
        entry_marker.state is _FieldState.MISSING
        and entry_value.state is _FieldState.MISSING
    ):
        entry = None
    else:
        entry = _optional_coordinate(
            raw,
            "referenced_function_entry_present",
            "referenced_function_entry",
            index,
            defects,
        )
    return InstructionDataReference(
        coordinate,
        read.value,
        write.value,
        entry,
    )


def _instruction_flow(
    raw: RawObject,
    defects: _ObservationDefects,
) -> InstructionFlowEvidence | None:
    field = _field(raw, "flow_type")
    if field.state is _FieldState.MISSING:
        defects.incomplete = True
        return None
    if field.state is _FieldState.DUPLICATE:
        defects.duplicate = True
        return None
    if type(field.value) is not RawObject:
        defects.invalid = True
        return None
    names = (
        "is_flow",
        "has_fallthrough",
        "is_call",
        "is_jump",
        "is_terminal",
        "is_computed",
        "is_conditional",
        "is_unconditional",
        "is_override",
    )
    defects.duplicate |= _has_duplicate(field.value, names)
    values: list[bool] = []
    for name in names:
        item = _field(field.value, name)
        if item.state is _FieldState.MISSING:
            defects.incomplete = True
            return None
        if item.state is _FieldState.DUPLICATE:
            defects.duplicate = True
            return None
        if type(item.value) is not bool:
            defects.invalid = True
            return None
        values.append(item.value)
    try:
        return InstructionFlowEvidence(*values)
    except (TypeError, ValueError):
        defects.conflicting = True
        return None


def _optional_varnode(
    raw: RawObject,
    index: _AddressSpaceIndex,
    defects: _ObservationDefects,
) -> ValidatedVarnode | None:
    marker = _field(raw, "output_present")
    value = _field(raw, "output")
    if value.state is _FieldState.PRESENT and value.value is not None:
        defects.duplicate |= _nested_varnode_duplicate(value.value)
        if defects.varnode_count >= MAX_FUNCTION_VARNODES:
            defects.invalid = True
            return None
        defects.varnode_count += 1
    if marker.state is _FieldState.DUPLICATE or value.state is _FieldState.DUPLICATE:
        defects.duplicate = True
    if marker.state is _FieldState.MISSING or value.state is _FieldState.MISSING:
        defects.incomplete = True
    if marker.state is _FieldState.PRESENT and type(marker.value) is not bool:
        defects.invalid = True
    if (
        marker.state is not _FieldState.PRESENT
        or value.state is not _FieldState.PRESENT
        or type(marker.value) is not bool
    ):
        return None
    if marker.value is False:
        if value.value is not None:
            defects.conflicting = True
        return None
    if value.value is None:
        defects.conflicting = True
        return None
    return _parse_varnode(value.value, index, defects)


def _observation_coordinate(
    value: object,
    defects: _ObservationDefects,
) -> AddressCoordinate | None:
    names = ("space_id", "byte_offset")
    if type(value) is not RawObject:
        defects.invalid = True
        return None
    fields = tuple(_field(value, name) for name in names)
    duplicate = any(field.state is _FieldState.DUPLICATE for field in fields)
    missing = any(field.state is _FieldState.MISSING for field in fields)
    invalid_present = any(
        type(field.value) is not int
        for field in fields
        if field.state is _FieldState.PRESENT
    )
    defects.duplicate |= duplicate
    defects.incomplete |= missing
    defects.invalid |= invalid_present
    if duplicate or missing or invalid_present:
        return None
    try:
        return AddressCoordinate(fields[0].value, fields[1].value)
    except (TypeError, ValueError):
        defects.invalid = True
        return None


def _nested_coordinate_duplicate(value: object) -> bool:
    return type(value) is RawObject and _has_duplicate(value, ("space_id", "byte_offset"))


def _nested_varnode_duplicate(value: object) -> bool:
    return type(value) is RawObject and _has_duplicate(
        value,
        ("kind_code", "space_id", "byte_offset", "byte_size"),
    )
