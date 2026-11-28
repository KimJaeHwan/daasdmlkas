"""Admit the standalone straight-line ARM64 producer to the local graph pass."""

from hashlib import sha256
import json
import re

from .._configured_bundle_reader import read_configured_bundle
from .._scope_contracts import ValidatedVarnode, VarnodeKindCode, _mint_orchestrator_capability
from ..base_graph import BaseGraphPolicy, BaseGraphPublication
from ..isa_identity import link_register, program_counter
from ..resource_limits import analysis_entry
from ..scope_identity import AddressCoordinate, ConstructedProgramScope, ConstructedFunctionScope, open_configured_extraction
from .configured_bundle import admit_frozen_bundle


LANGUAGE = "AARCH64:LE:64:v8A"
PROFILE = "tdo-arm64-pypcode-local-1"
RAM = 1
MAX_CODE_BYTES = 65536
RET = 0xD65F03C0
DIGEST_FIELDS = {"original_sha256", "sla_sha256", "language_sha256", "pspec_sha256", "lifter_sha256"}
LOCAL_OPERATIONS = frozenset(("COPY", "INT_ADD", "INT_SUB", "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
                              "INT_EQUAL", "INT_SLESS", "INT_ZEXT", "LOAD", "STORE"))


def instruction_form(word):
    if word == RET:
        return "ret"
    if word & 0x3F800000 == 0x11000000:
        return "sub" if word & (1 << 30) else "add"
    masked = word & 0xBFC00000
    return {0xB9000000: "str", 0xB9400000: "ldr"}.get(masked)


def language_id(profile_bytes):
    arch = LANGUAGE.rsplit(":", 1)[0]
    return f"{arch}:{PROFILE}-{sha256(profile_bytes).hexdigest()}"


def _profile_pairs(pairs):
    values = dict(pairs)
    if len(values) != len(pairs):
        raise ValueError("duplicate standalone producer profile fields")
    return values


def _read_profile(data):
    value = json.loads(data, object_pairs_hook=_profile_pairs)
    if (not isinstance(value, dict) or value.keys() != DIGEST_FIELDS | {"schema", "lifter_version", "context", "page_size"}
            or value["schema"] != PROFILE or value["context"] != f"{LANGUAGE} default"
            or type(value["page_size"]) is not int or value["page_size"] not in (4096, 16384, 65536)
            or not isinstance(value["lifter_version"], str) or not value["lifter_version"]
            or any(not isinstance(value[k], str) or not re.fullmatch("[0-9a-f]{64}", value[k])
                   for k in DIGEST_FIELDS)):
        raise ValueError("invalid standalone ARM64 producer profile")
    return value


def _code_bytes(provider, program, entry, size):
    # Reuse the pinned Bundle member verifier. The code bytes are bounded and
    # the only other block the producer emits is the image-base anchor.
    blocks = provider._inventory.blocks
    expected = [(entry.byte_offset, size)]
    base = program.evidence.image_base
    if entry != base:
        expected.insert(0, (base.byte_offset, 1))
    if (entry.space_id != RAM or base.space_id != RAM or entry.byte_offset % 4
            or not 4 <= size <= MAX_CODE_BYTES
            or [(b.byte_start, b.byte_size) for b in blocks] != expected
            or any(b.space_id != RAM or not b.is_loaded or not b.is_initialized or b.is_overlay
                   or b.is_external or b.is_mapped or b.member is None for b in blocks)):
        raise ValueError("standalone ARM64 Bundle must contain only its function and image-base anchor")
    return provider._snapshot.verified_bytes(
        provider._snapshot_claim, blocks[-1].member, max_bytes=MAX_CODE_BYTES
    )


def _register_node(register):
    if register is None:
        raise ValueError("standalone ARM64 RET requires exact PC and X30 register evidence")
    return ValidatedVarnode(VarnodeKindCode.REGISTER,
                            AddressCoordinate(register.space_id, register.byte_offset), register.byte_size)


def _require_local(unit, program, provider):
    if type(unit.scopes.function) is not ConstructedFunctionScope or unit.observation is None:
        raise ValueError("standalone ARM64 function scope was refused")
    obs = unit.observation
    if obs.call_fallthrough_isa or obs.fallthrough_exits or not obs.instructions:
        raise ValueError("standalone ARM64 analysis requires an ordinary local observation")
    entry = unit.scopes.function.entry
    code = _code_bytes(provider, program, entry, len(obs.instructions) * 4)
    pc = _register_node(program_counter(program.evidence))
    lr = _register_node(link_register(program.evidence))
    for index, row in enumerate(obs.instructions):
        last = index == len(obs.instructions) - 1
        flow = row.flow
        offset = entry.byte_offset + index * 4
        expected_next = None if last else AddressCoordinate(entry.space_id, offset + 4)
        ops = tuple(op.opcode for op in row.operations)
        form = instruction_form(int.from_bytes(code[index * 4:index * 4 + 4], "little"))
        if last:
            allowed = (form == "ret" and ops == ("COPY", "RETURN") and row.operations[0].inputs == (lr,)
                       and row.operations[0].output == pc and row.operations[1].inputs == (pc,)
                       and row.operations[1].output is None)
        else:
            memory = tuple(name for name in ops if name in ("LOAD", "STORE"))
            expected_memory = {"ldr": ("LOAD",), "str": ("STORE",)}.get(form, ())
            allowed = (form is not None and form != "ret" and bool(ops) and set(ops) <= LOCAL_OPERATIONS
                       and memory == expected_memory)
        if (row.address != AddressCoordinate(entry.space_id, offset) or row.length != 4
                or row.fallthrough != expected_next or row.flow_targets or row.data_references
                or flow.is_call or flow.is_jump or flow.is_computed or flow.is_conditional or flow.is_override
                or not flow.is_flow or not flow.is_unconditional or flow.is_terminal != last
                or flow.has_fallthrough != (not last) or not allowed):
            raise ValueError("standalone ARM64 analysis requires straight-line code and one terminal RET")


@analysis_entry
def build_standalone_arm64_graphs(generation_path):
    """Return fresh base graphs and the identity of their admitted producer Bundle."""
    provider = read_configured_bundle(admit_frozen_bundle(generation_path))
    try:
        binding = provider.container_identity
        profile_bytes = provider.call_interface_profile_bytes()
        profile = _read_profile(profile_bytes)
        with open_configured_extraction(provider, _mint_orchestrator_capability()) as envelope:
            program = envelope.program_result
            if (type(program) is not ConstructedProgramScope
                    or program.evidence.translation_namespace.language_id != language_id(profile_bytes)
                    or program.evidence.executable_sha256.hex() != profile["original_sha256"]):
                raise ValueError("standalone ARM64 profile and sealed program disagree")
            units = tuple(envelope.iter_scoped_functions())
            if len(units) != 1:
                raise ValueError("standalone ARM64 analysis requires exactly one function")
            _require_local(units[0], program, provider)
    finally:
        provider.close()
    return BaseGraphPublication(units, program=program, policy=BaseGraphPolicy()).build(), binding
