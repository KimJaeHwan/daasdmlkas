"""Audited ISA refinements of version-qualified observed CALLOTHERs.

This is an extension of the translator semantics, not an ABI/environment
preservation assumption or a function-name model. The intrinsic computes
its explicit result only. Operand memory LOADs and architectural destination
writes stay in the original instruction's p-code and graph. Faulting paths
are not made returning by this rule (as with ordinary arithmetic semantics).

Registry evidence: Ghidra 12.0.4 GhidraV2ListUserOps independently exported
x86:LE:64:default 4.6 index483=vpcmpeqw_avx2; x86-64.sla SHA256
d5adc314e2278228b380d8f653b2b579fa4a65986bb1d39b095e461fd5432481.
Intel SDM253667-060US pp4-244..4-249 defines the VEX.256 word equality
result, destination-only register effect and unchanged flags. Ghidra's
avx2.sinc constructor performs the source LOAD and destination assignment
outside this value intrinsic. Unknown signatures always remain opaque.
"""
from __future__ import annotations

from dataclasses import dataclass

from ._scope_contracts import VarnodeKindCode
from .call_seeds import _operation_key
from .intrinsic_semantics import PackedEqualitySemantics, packed_equality_semantics

EVIDENCE_ID = "ghidra-x86-4.6-userops12.0.4/intel253667-060us-vpcmpeqw-v1"
# Verified by exporting the translator's table, never inferred from a binary
# address, function name, operand values, or the existence of an output.
_USEROP_NAMES = {("x86:LE:64:default", 4, 6): {483: "vpcmpeqw_avx2"}}


@dataclass(frozen=True, slots=True)
class IntrinsicRefinement:
    semantics: PackedEqualitySemantics
    language: tuple[str, int, int]
    userop_index: int
    userop_name: str

    def record(self):
        return {"semantic_id": self.semantics.semantic_id, "language": list(self.language),
                "userop_index": self.userop_index, "userop_name": self.userop_name,
                "input_byte_sizes": [self.semantics.vector_byte_size] * 2,
                "output_byte_size": self.semantics.vector_byte_size, "evidence_id": EVIDENCE_ID}


def semantics_from_record(record):
    """Validate a serialized semantic identity/signature; never trust its name alone."""
    keys = {"semantic_id", "language", "userop_index", "userop_name", "input_byte_sizes",
            "output_byte_size", "evidence_id"}
    if type(record) is not dict or set(record) != keys or record["evidence_id"] != EVIDENCE_ID \
            or type(record["language"]) is not list or type(record["input_byte_sizes"]) is not list:
        return None
    language = tuple(record["language"])
    if any(type(value) is not int for value in record["input_byte_sizes"]) \
            or len(language) != 3 or type(language[0]) is not str \
            or any(type(value) is not int for value in language[1:]) \
            or type(record["userop_index"]) is not int:
        return None
    name = _USEROP_NAMES.get(language, {}).get(record["userop_index"])
    if name is None or name != record["userop_name"]:
        return None
    rule = packed_equality_semantics(language=language, userop_index=record["userop_index"],
        userop_name=name, input_byte_sizes=tuple(record["input_byte_sizes"]),
        output_byte_size=record["output_byte_size"])
    return rule if rule is not None and rule.semantic_id == record["semantic_id"] else None


def refinements_for(unit):
    namespace = unit.scopes.program.evidence.translation_namespace
    language = (namespace.language_id, namespace.major_version, namespace.minor_version)
    names = _USEROP_NAMES.get(language, {})
    if not names or unit.observation is None:
        return {}
    # Storage kinds must agree with admitted address-space classifications.
    spaces = {space.space_id: space for space in unit.scopes.program.evidence.address_spaces}
    def storage(value, *, output=False):
        space = spaces.get(value.coordinate.space_id)
        return space is not None and (
            value.kind is VarnodeKindCode.UNIQUE and space.is_unique_space
            or not output and value.kind is VarnodeKindCode.REGISTER and space.is_register_space)
    found = {}
    for instruction in unit.observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            if operation.opcode != "CALLOTHER" or len(operation.inputs) != 3 \
                    or operation.output is None or not storage(operation.output, output=True):
                continue
            index, *arguments = operation.inputs
            space = spaces.get(index.coordinate.space_id)
            if index.kind is not VarnodeKindCode.CONSTANT or index.byte_size != 4 \
                    or space is None or not space.is_constant_space \
                    or not all(storage(value) for value in arguments):
                continue
            name = names.get(index.coordinate.byte_offset)
            if name is None:
                continue
            rule = packed_equality_semantics(language=language, userop_index=index.coordinate.byte_offset,
                userop_name=name, input_byte_sizes=tuple(value.byte_size for value in arguments),
                output_byte_size=operation.output.byte_size)
            if rule is not None:
                found[_operation_key(instruction.address, ordinal, operation.opcode)] = IntrinsicRefinement(
                    rule, language, index.coordinate.byte_offset, name)
    return found
