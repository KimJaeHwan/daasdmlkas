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

Legacy SSE2 PACKSSWB/PSHUFLW have separately audited output-only effects,
not value semantics. Ghidra 12.0.4 ia.sinc constructors at 7607..7608 and
8799 assign only XmmReg, with memory operand LOADs outside the user op.
The same SLA's exported table identifies 132=packsswb and 157=pshuflw.
Intel SDM Vol. 2 (325383), PACKSSWB/PACKSSDW and PSHUFLW, specifies the
destination-only result and unchanged flags. Translation language/version
is the runtime identity boundary, as for VPCMPEQW; the SLA hash above is
audit evidence, not an additional runtime binary-hash comparison. Unknown
values, unsupported forms and fault behavior are not inferred from this.
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
class OutputOnlySignature:
    """Audited state footprint; deliberately provides no evaluate/lane API."""

    effect_id: str
    userop_name: str
    input_byte_sizes: tuple[int, ...]
    output_byte_size: int


_OUTPUT_ONLY_EVIDENCE = "ghidra-x86-4.6-userops12.0.4/intel325383-sse2-output-only-v1"
_OUTPUT_ONLY = {("x86:LE:64:default", 4, 6): {
    132: OutputOnlySignature("x86-packsswb-le128-output-only-v1", "packsswb", (16, 16), 16),
    # Ghidra's legacy constructor passes the old destination too; its
    # immediate is an EIGHT-BYTE p-code constant, not an 8-bit varnode.
    157: OutputOnlySignature("x86-pshuflw-le128-output-only-v1", "pshuflw", (16, 16, 8), 16),
}}


@dataclass(frozen=True, slots=True)
class IntrinsicRefinement:
    semantics: PackedEqualitySemantics | None
    language: tuple[str, int, int]
    userop_index: int
    userop_name: str
    output_only: OutputOnlySignature | None = None

    def __post_init__(self):
        if (self.semantics is None) == (self.output_only is None):
            raise ValueError("an intrinsic requires exactly one value or output-only rule")

    @property
    def semantic_id(self):
        return self.output_only.effect_id if self.output_only is not None else self.semantics.semantic_id

    def record(self):
        if self.output_only is not None:
            return {"kind": "output-only", "effect_id": self.output_only.effect_id,
                    "language": list(self.language), "userop_index": self.userop_index,
                    "userop_name": self.userop_name,
                    "input_byte_sizes": list(self.output_only.input_byte_sizes),
                    "output_byte_size": self.output_only.output_byte_size,
                    "evidence_id": _OUTPUT_ONLY_EVIDENCE, "value_semantics": None}
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
    output_only = _OUTPUT_ONLY.get(language, {})
    if not (names or output_only) or unit.observation is None:
        return {}
    # Storage kinds must agree with admitted address-space classifications.
    spaces = {space.space_id: space for space in unit.scopes.program.evidence.address_spaces}
    def storage(value, *, output=False):
        space = spaces.get(value.coordinate.space_id)
        return space is not None and (
            value.kind is VarnodeKindCode.UNIQUE and space.is_unique_space
            or not output and value.kind is VarnodeKindCode.REGISTER and space.is_register_space)
    def xmm(value):
        return storage(value) and value.kind is VarnodeKindCode.REGISTER and value.byte_size == 16 \
            and value.coordinate.byte_offset in range(0x1200, 0x1600, 0x40)
    found = {}
    for instruction in unit.observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            if operation.opcode != "CALLOTHER" or not operation.inputs or operation.output is None:
                continue
            index, *arguments = operation.inputs
            space = spaces.get(index.coordinate.space_id)
            if index.kind is not VarnodeKindCode.CONSTANT or index.byte_size != 4 \
                    or space is None or not space.is_constant_space:
                continue
            effect = output_only.get(index.coordinate.byte_offset)
            if effect is not None:
                if tuple(value.byte_size for value in arguments) != effect.input_byte_sizes \
                        or operation.output.byte_size != effect.output_byte_size \
                        or not xmm(operation.output) or arguments[0] != operation.output \
                        or not (xmm(arguments[1]) or arguments[1].kind is VarnodeKindCode.UNIQUE
                                and storage(arguments[1])):
                    continue
                if effect.userop_name == "pshuflw":
                    immediate = arguments[2]
                    space = spaces.get(immediate.coordinate.space_id)
                    if immediate.kind is not VarnodeKindCode.CONSTANT or space is None \
                            or not space.is_constant_space or not 0 <= immediate.coordinate.byte_offset <= 255:
                        continue
                found[_operation_key(instruction.address, ordinal, operation.opcode)] = IntrinsicRefinement(
                    None, language, index.coordinate.byte_offset, effect.userop_name, effect)
                continue
            if len(arguments) != 2 or not storage(operation.output, output=True) \
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
