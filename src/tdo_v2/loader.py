"""Typed loader for the structured Low-PCode dump contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .model import (
    AddressSpace,
    ArchitectureFacts,
    CallTarget,
    FunctionDocument,
    Instruction,
    PcodeOperation,
    RegisterAlias,
    StorageRef,
    Varnode,
    VarnodeKind,
)


class LowPcodeFormatError(ValueError):
    """Raised when required structural fields are missing or malformed."""


class LowPcodeLoader:
    MIN_SCHEMA_VERSION = 6

    def load(self, path: str | Path) -> FunctionDocument:
        source = Path(path)
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LowPcodeFormatError(f"cannot load {source}: {exc}") from exc
        if not isinstance(payload, dict):
            raise LowPcodeFormatError("top-level Low-PCode document must be an object")
        return self.load_mapping(payload)

    def load_mapping(self, payload: Mapping[str, Any]) -> FunctionDocument:
        schema_version = _required_int(payload, "schema_version")
        if schema_version < self.MIN_SCHEMA_VERSION:
            raise LowPcodeFormatError(
                f"schema_version {schema_version} is older than {self.MIN_SCHEMA_VERSION}"
            )

        function_name = _required_text(payload, "function_name")
        start_address = _required_text(payload, "start_address")
        raw_instructions = payload.get("instructions")
        if not isinstance(raw_instructions, list):
            raise LowPcodeFormatError("instructions must be a list")

        instructions = tuple(self._instruction(item) for item in raw_instructions)
        metadata_identity = payload.get("metadata_identity")
        return FunctionDocument(
            schema_version=schema_version,
            dumper=_optional_text(payload.get("dumper")),
            function_name=function_name,
            start_address=start_address,
            architecture=self._architecture(payload.get("program")),
            instructions=instructions,
            metadata_identity=(
                dict(metadata_identity) if isinstance(metadata_identity, dict) else {}
            ),
        )

    def _instruction(self, raw: Any) -> Instruction:
        if not isinstance(raw, dict):
            raise LowPcodeFormatError("instruction entries must be objects")
        address = _required_text(raw, "address")
        low_pcode = raw.get("low_pcode")
        if not isinstance(low_pcode, list):
            raise LowPcodeFormatError(f"instruction {address} low_pcode must be a list")
        operations = tuple(
            self._operation(address, ordinal, operation)
            for ordinal, operation in enumerate(low_pcode)
        )
        flow_targets = tuple(
            text
            for item in _list(raw.get("flow_targets"))
            if (text := _optional_text(item)) is not None
        )
        call_targets = tuple(self._call_target(item) for item in _list(raw.get("call_targets")))
        return Instruction(
            address=address,
            length=_coerce_int(raw.get("length")) or 0,
            assembly=_optional_text(raw.get("assembly")),
            mnemonic=_optional_text(raw.get("mnemonic")),
            flow_type=_optional_text(raw.get("flow_type")),
            flow_targets=flow_targets,
            fallthrough=_optional_text(raw.get("fallthrough")),
            call_targets=call_targets,
            operations=operations,
        )

    def _operation(self, address: str, ordinal: int, raw: Any) -> PcodeOperation:
        if not isinstance(raw, dict):
            raise LowPcodeFormatError(f"instruction {address} operation must be an object")
        opcode = _required_text(raw, "opcode").upper()
        inputs = tuple(self._varnode(item) for item in _list(raw.get("inputs")))
        output_raw = raw.get("output")
        output = self._varnode(output_raw) if isinstance(output_raw, dict) else None
        return PcodeOperation(
            instruction_address=address,
            ordinal=ordinal,
            opcode=opcode,
            inputs=inputs,
            output=output,
            seqnum=_optional_text(raw.get("seqnum")),
        )

    def _varnode(self, raw: Any) -> Varnode:
        if not isinstance(raw, dict):
            raise LowPcodeFormatError("varnode must be an object")
        size = _coerce_int(raw.get("size"))
        if size is None or size <= 0:
            raise LowPcodeFormatError("varnode size must be positive")
        space = (_optional_text(raw.get("space")) or "unknown").rstrip(":")
        kind = _varnode_kind(raw, space)
        storage = StorageRef(
            kind=kind,
            space=space,
            offset=_coerce_int(raw.get("offset")),
            size=size,
            register_name=_optional_text(raw.get("register_name")),
        )
        return Varnode(
            storage=storage,
            address=_optional_text(raw.get("address")),
            raw_type=_optional_text(raw.get("type")),
        )

    def _call_target(self, raw: Any) -> CallTarget:
        if not isinstance(raw, dict):
            raise LowPcodeFormatError("call target must be an object")
        return CallTarget(
            name=_optional_text(raw.get("function_name")),
            entry=_optional_text(raw.get("entry") or raw.get("address")),
            resolved=bool(raw.get("resolved")),
            is_external=bool(raw.get("is_external")),
        )

    def _architecture(self, raw_program: Any) -> ArchitectureFacts:
        program = raw_program if isinstance(raw_program, dict) else {}
        architecture = program.get("architecture")
        architecture = architecture if isinstance(architecture, dict) else {}
        raw_registers = architecture.get("register_aliases") or program.get("registers") or []
        raw_spaces = architecture.get("address_spaces") or program.get("address_spaces") or []
        endian = architecture.get("endian") or program.get("endian")
        return ArchitectureFacts(
            language_id=_optional_text(program.get("language_id")),
            processor=_optional_text(program.get("processor")),
            compiler_spec_id=_optional_text(program.get("compiler_spec_id")),
            pointer_size=_coerce_int(
                architecture.get("default_pointer_size") or program.get("default_pointer_size")
            ),
            endian=_optional_text(endian),
            registers=tuple(
                alias
                for item in _list(raw_registers)
                if (alias := _register_alias(item)) is not None
            ),
            address_spaces=tuple(
                space for item in _list(raw_spaces) if (space := _address_space(item)) is not None
            ),
        )


def _varnode_kind(raw: Mapping[str, Any], space: str) -> VarnodeKind:
    if raw.get("is_constant") or space == "const":
        return VarnodeKind.CONSTANT
    if raw.get("is_register") or space == "register":
        return VarnodeKind.REGISTER
    if raw.get("is_unique") or space == "unique":
        return VarnodeKind.UNIQUE
    if raw.get("is_address"):
        return VarnodeKind.ADDRESS
    if space not in {"", "unknown"}:
        return VarnodeKind.STORAGE
    return VarnodeKind.UNKNOWN


def _register_alias(raw: Any) -> RegisterAlias | None:
    if not isinstance(raw, dict):
        return None
    name = _optional_text(raw.get("display") or raw.get("name"))
    canonical = _optional_text(raw.get("canonical") or raw.get("base_register") or name)
    offset = _coerce_int(raw.get("offset"))
    size = _coerce_int(raw.get("size_bytes"))
    if not name or not canonical or offset is None or not size:
        return None
    return RegisterAlias(
        name=name,
        canonical=canonical,
        offset=offset,
        size=size,
        least_significant_bit=_coerce_int(raw.get("least_significant_bit")) or 0,
    )


def _address_space(raw: Any) -> AddressSpace | None:
    if not isinstance(raw, dict):
        return None
    name = _optional_text(raw.get("name"))
    if not name:
        return None
    return AddressSpace(
        name=name,
        space_id=_first_int(raw.get("space_id"), raw.get("id")),
        address_size=_first_int(raw.get("address_size"), raw.get("size")),
        word_size=_first_int(raw.get("word_size"), raw.get("addressable_unit_size")),
        kind=_optional_text(raw.get("type") or raw.get("kind")),
    )


def _required_text(mapping: Mapping[str, Any], key: str) -> str:
    value = _optional_text(mapping.get(key))
    if value is None:
        raise LowPcodeFormatError(f"missing required text field: {key}")
    return value


def _required_int(mapping: Mapping[str, Any], key: str) -> int:
    value = _coerce_int(mapping.get(key))
    if value is None:
        raise LowPcodeFormatError(f"missing required integer field: {key}")
    return value


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _coerce_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().removesuffix("L")
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _first_int(*values: Any) -> int | None:
    for value in values:
        parsed = _coerce_int(value)
        if parsed is not None:
            return parsed
    return None


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
