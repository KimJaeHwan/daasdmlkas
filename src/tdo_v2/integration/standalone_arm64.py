"""Admit standalone local ARM64 observations to the existing base graph pass."""

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
BRANCH_PROFILE = "tdo-arm64-pypcode-local-2"
RAM = 1
MAX_CODE_BYTES = 65536
RET = 0xD65F03C0
DIGEST_FIELDS = {"original_sha256", "sla_sha256", "language_sha256", "pspec_sha256", "lifter_sha256"}
LOCAL_OPERATIONS = frozenset(("COPY", "INT_ADD", "INT_SUB", "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
                              "INT_EQUAL", "INT_SLESS", "INT_ZEXT", "LOAD", "STORE"))


CMP_OPERATIONS = LOCAL_OPERATIONS | {"INT_LESSEQUAL", "INT_LEFT"}
BRANCH_FORMS = {"b", "b.cond", "cbz"}
CONDITION_NAMES = "eq ne cs cc mi pl vs vc hi ls ge lt gt le".split()


def instruction_form(word, branches=False):
    if branches:
        if word & 0x7F000000 == 0x34000000 and word & 31 != 31:
            return "cbz"
        if word & 0xFF000010 == 0x54000000 and word & 15 < len(CONDITION_NAMES):
            return "b.cond"
        if word & 0xFC000000 == 0x14000000:
            return "b"
        if word & 0x7F80001F == 0x7100001F:
            return "cmp"
    if word == RET:
        return "ret"
    if word & 0x3F800000 == 0x11000000:
        return "sub" if word & (1 << 30) else "add"
    masked = word & 0xBFC00000
    return {0xB9000000: "str", 0xB9400000: "ldr"}.get(masked)


def branch_target(form, word, address):
    bits, shift = (26, 0) if form == "b" else (19, 5)
    immediate = (word >> shift) & ((1 << bits) - 1)
    if immediate & (1 << (bits - 1)):
        immediate -= 1 << bits
    return address + (immediate << 2)


def local_successors(form, word, address, limit):
    next_address = None if form in ("b", "ret") else address + 4
    if form not in BRANCH_FORMS:
        return next_address, None
    target = branch_target(form, word, address)
    if not address < target < limit or target == next_address:
        raise ValueError(f"standalone ARM64 branch target is not a distinct forward local instruction at {address:#x}")
    return next_address, target


def language_id(profile_bytes):
    arch = LANGUAGE.rsplit(":", 1)[0]
    return f"{arch}:{_read_profile(profile_bytes)['schema']}-{sha256(profile_bytes).hexdigest()}"


def _profile_pairs(pairs):
    values = dict(pairs)
    if len(values) != len(pairs):
        raise ValueError("duplicate standalone producer profile fields")
    return values


def _read_profile(data):
    value = json.loads(data, object_pairs_hook=_profile_pairs)
    if (not isinstance(value, dict) or value.keys() != DIGEST_FIELDS | {"schema", "lifter_version", "context", "page_size"}
            or value["schema"] not in (PROFILE, BRANCH_PROFILE) or value["context"] != f"{LANGUAGE} default"
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


def _flag_predicates():
    n, z, c, v = ("NG", "ZR", "CY", "OV")
    negate = lambda flag: ("BOOL_NEGATE", flag)
    equal = ("INT_EQUAL", n, v)
    unequal = ("INT_NOTEQUAL", n, v)
    return (z, negate(z), c, negate(c), n, negate(n), v, negate(v),
            ("BOOL_AND", c, negate(z)), ("BOOL_OR", negate(c), z), equal, unequal,
            ("BOOL_AND", negate(z), equal), ("BOOL_OR", z, unequal))


CONDITION_PREDICATES = _flag_predicates()
_PREDICATE_OPERATIONS = {"BOOL_NEGATE": 1, "BOOL_AND": 2, "BOOL_OR": 2, "INT_EQUAL": 2, "INT_NOTEQUAL": 2}
_FLAG_NAMES = ("NG", "ZR", "CY", "OV")


def _constant(value, size):
    return ValidatedVarnode(VarnodeKindCode.CONSTANT, AddressCoordinate(0, value), size)


def _is_unique(value, size):
    return value is not None and value.kind is VarnodeKindCode.UNIQUE and value.byte_size == size


def _condition_cost(predicate):
    if isinstance(predicate, str):
        return 0
    return 1 + sum(_condition_cost(arg) for arg in predicate[1:])


def _branch_operations(form, word, target, ops, registers):
    opcode = "BRANCH" if form == "b" else "CBRANCH"
    destination = ValidatedVarnode(VarnodeKindCode.ADDRESS, target, 8)
    if not ops or ops[-1].opcode != opcode or ops[-1].output is not None:
        return False
    args = ops[-1].inputs
    if form == "b":
        return len(ops) == 1 and args == (destination,)
    if len(args) != 2 or args[0] != destination or args[1].byte_size != 1:
        return False
    if form == "cbz":
        width = 8 if word >> 31 else 4
        name = f"{'x' if width == 8 else 'w'}{word & 31}"
        source = registers.get(name)
        return (source is not None and source.byte_size == width and len(ops) == 2 and ops[0].opcode == "INT_EQUAL" and args[1].kind is VarnodeKindCode.UNIQUE
                and ops[0].inputs == (source, _constant(0, width)) and ops[0].output == args[1])
    expected = CONDITION_PREDICATES[word & 15]
    if len(ops) != 1 + _condition_cost(expected):
        return False
    values = {registers[name]: name for name in _FLAG_NAMES if name in registers and registers[name].byte_size == 1}
    for op in ops[:-1]:
        arity = _PREDICATE_OPERATIONS.get(op.opcode)
        output = op.output
        if (arity != len(op.inputs) or output is None or output.kind is not VarnodeKindCode.UNIQUE
                or output.byte_size != 1 or output in values or any(value not in values for value in op.inputs)):
            return False
        values[output] = (op.opcode, *(values[value] for value in op.inputs))
    return values.get(args[1]) == expected


def _compare_immediate(word, ops, registers):
    width = 8 if word >> 31 else 4
    rn = (word >> 5) & 31
    name = ("sp" if width == 8 else "wsp") if rn == 31 else f"{'x' if width == 8 else 'w'}{rn}"
    lhs = registers.get(name)
    shifted = bool(word & (1 << 22))
    if lhs is None or lhs.byte_size != width or len(ops) != 10 + shifted:
        return False
    literal = _constant((word >> 10) & 0xFFF, width)
    if shifted:
        shift, *ops = ops
        if (shift.opcode != "INT_LEFT" or shift.inputs != (literal, _constant(12, 4))
                or not _is_unique(shift.output, width)):
            return False
        literal = shift.output
    imm = ops[0].output
    result = ops[3].output
    if not _is_unique(imm, width) or not _is_unique(result, width) or imm == result:
        return False
    temps = {flag: registers.get("tmp" + flag) for flag in _FLAG_NAMES}
    flags = {flag: registers.get(flag) for flag in _FLAG_NAMES}
    flag_bytes = (*temps.values(), *flags.values())
    if (any(value is None or value.byte_size != 1 for value in flag_bytes)
            or len(set(flag_bytes)) != len(flag_bytes)
            or any(_covers_register_byte(lhs, flag) for flag in flag_bytes)):
        return False
    # Some SLEIGH constructors use the literal directly in flag ops. The
    # earlier COPY establishes the same typed operand in both cases.
    direct = (imm,) if shifted else (literal, imm)
    return (
        (ops[0].opcode, ops[0].inputs) == ("COPY", (literal,))
        and ops[1].opcode == "INT_LESSEQUAL" and ops[1].output == temps["CY"]
        and ops[1].inputs in tuple((arg, lhs) for arg in direct)
        and ops[2].opcode == "INT_SBORROW" and ops[2].output == temps["OV"]
        and ops[2].inputs in tuple((lhs, arg) for arg in direct)
        and (ops[3].opcode, ops[3].inputs) == ("INT_SUB", (lhs, imm))
        and (ops[4].opcode, ops[4].inputs, ops[4].output) == ("INT_SLESS", (result, _constant(0, width)), temps["NG"])
        and (ops[5].opcode, ops[5].inputs, ops[5].output) == ("INT_EQUAL", (result, _constant(0, width)), temps["ZR"])
        and all((op.opcode, op.inputs, op.output) == ("COPY", (temps[flag],), flags[flag])
                for op, flag in zip(ops[6:], _FLAG_NAMES))
    )


def _covers_register_byte(storage, byte):
    if storage is None or storage.kind is not VarnodeKindCode.REGISTER:
        return False
    start = storage.coordinate.byte_offset
    return (storage.coordinate.space_id == byte.coordinate.space_id
            and start <= byte.coordinate.byte_offset < start + storage.byte_size)


def _require_local(unit, program, provider, branches):
    if type(unit.scopes.function) is not ConstructedFunctionScope or unit.observation is None:
        raise ValueError("standalone ARM64 function scope was refused")
    obs = unit.observation
    if obs.call_fallthrough_isa or obs.fallthrough_exits or not obs.instructions:
        raise ValueError("standalone ARM64 analysis requires an ordinary local observation")
    entry = unit.scopes.function.entry
    code = _code_bytes(provider, program, entry, len(obs.instructions) * 4)
    pc = _register_node(program_counter(program.evidence))
    lr = _register_node(link_register(program.evidence))
    register_table = program.evidence.register_evidence
    registers = {r.name: _register_node(r) for r in register_table.registers} if branches else {}
    flags = tuple(registers.get(name) for name in _FLAG_NAMES) if branches else ()
    if any(flag is None or flag.byte_size != 1 for flag in flags) or len(set(flags)) != len(flags):
        raise ValueError("standalone ARM64 requires distinct architectural flag bytes")
    limit = entry.byte_offset + len(code)
    reachable = {entry.byte_offset}
    for index, row in enumerate(obs.instructions):
        last = index == len(obs.instructions) - 1
        flow = row.flow
        offset = entry.byte_offset + index * 4
        word = int.from_bytes(code[index * 4:index * 4 + 4], "little")
        form = instruction_form(word, branches)
        conditional = form in ("cbz", "b.cond")
        jump = form in BRANCH_FORMS
        next_address, target = local_successors(form, word, offset, limit)
        expected_next = None if next_address is None else AddressCoordinate(entry.space_id, next_address)
        targets = () if target is None else (AddressCoordinate(entry.space_id, target),)
        ops = tuple(op.opcode for op in row.operations)
        if last:
            allowed = (form == "ret" and ops == ("COPY", "RETURN") and row.operations[0].inputs == (lr,)
                       and row.operations[0].output == pc and row.operations[1].inputs == (pc,)
                       and row.operations[1].output is None)
        elif jump:
            allowed = _branch_operations(form, word, targets[0], row.operations, registers)
        elif form == "cmp":
            allowed = _compare_immediate(word, row.operations, registers)
        else:
            memory = tuple(name for name in ops if name in ("LOAD", "STORE"))
            expected_memory = {"ldr": ("LOAD",), "str": ("STORE",)}.get(form, ())
            allowed = (form is not None and form != "ret" and bool(ops)
                       and set(ops) <= LOCAL_OPERATIONS and memory == expected_memory
                       and not any(_covers_register_byte(op.output, flag)
                                   for op in row.operations for flag in flags))
        if (offset not in reachable or row.address != AddressCoordinate(entry.space_id, offset) or row.length != 4
                or row.fallthrough != expected_next or row.flow_targets != targets or row.data_references
                or flow.is_call or flow.is_jump != jump or flow.is_computed or flow.is_conditional != conditional
                or flow.is_override or not flow.is_flow or flow.is_unconditional == conditional
                or flow.is_terminal != last or flow.has_fallthrough != (expected_next is not None) or not allowed):
            message = ("requires supported local flow and one terminal RET" if branches
                       else "analysis requires straight-line code and one terminal RET")
            raise ValueError(f"standalone ARM64 {message} at {offset:#x}")
        if expected_next is not None:
            reachable.add(expected_next.byte_offset)
        reachable.update(coord.byte_offset for coord in targets)


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
            _require_local(units[0], program, provider, profile["schema"] == BRANCH_PROFILE)
    finally:
        provider.close()
    return BaseGraphPublication(units, program=program, policy=BaseGraphPolicy()).build(), binding
