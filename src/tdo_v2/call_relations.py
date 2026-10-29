"""What one call instruction proves about its own continuation (ARM64 Stage 2a,
``.census6/design_arm64_s2_r5.md`` section 2, docs 25.87).

A ``CallRelation`` states only facts of the call instruction's own p-code: the
continuation value it writes, where (the link location), the stack-pointer
displacement it applies before the callee runs (``delta``), and the order of
those setup effects. Nothing about the callee: whether it returns there, or
restores the stack pointer, is a ReturnRelation / certificate (Stage 2b).

Two recognizers, at most one matching a call instruction:
- push (x86): ``INT_SUB SP, w; STORE [SP] = fallthrough; CALL|CALLIND`` -- the
  existing projection (``observed_call_state``), link = the slot at callee-entry
  SP, delta = -w, transient ops = the adjust and the store;
- link (AArch64): ``[COPY pc = Rn;] INT_ADD|COPY x30 = inst_start + 4 (as
  constants); CALL|CALLIND`` -- link = the link register (``isa_identity``),
  delta = 0, no transient op: the link write is an ordinary persistent write.

ISOLATED PRODUCER: no analysis reads these relations yet -- in particular not
``observed_call_state_projections`` consumers, ``call_clobber`` stack
preservation or ``may_alias`` stack identity (Stage 2c / 3 add consumers one by
one, each with its own capability check).
"""

from __future__ import annotations

from dataclasses import dataclass

from ._scope_contracts import AddressCoordinate, VarnodeKindCode
from .call_seeds import _operation_key
from .isa_identity import RegisterCoordinate, link_register, program_counter, stack_register
from .observed_call_state import observed_call_state_projections

_CALLS = ("CALL", "CALLIND")


@dataclass(frozen=True, slots=True)
class LinkSlot:
    """The memory location a push call writes its continuation to: ``size``
    bytes at the callee-entry stack pointer, in ``space_id``."""

    space_id: int
    size: int


@dataclass(frozen=True, slots=True)
class CallRelation:
    call_key: str
    kind: str                                   # "push" | "link"
    sp: RegisterCoordinate                      # the validated architectural stack register
    link: RegisterCoordinate | LinkSlot         # where the continuation is written
    delta: int                                  # callee-entry SP - caller SP before the instruction
    continuation: AddressCoordinate             # the observed constant the instruction writes (= its fallthrough)
    relocation: str                             # "instruction-relative" (the ISA's next-instruction address,
                                                # moving with the code) | "unknown" (a bare constant)
    length: int                                 # continuation - the instruction's address
    entry_ordinal: int                          # the callee's entry state: before this p-code op (the call)
    setup_ops: tuple[str, ...]                  # the instruction's ops before the call, in order
    transient_ops: tuple[str, ...]              # ops the persistent unit drops (push only)


def call_relations(observation, scopes) -> dict[str, CallRelation]:
    """Call operation key -> its relation, for every call instruction one
    recognizer proves. Both need the validated stack register (exported
    register evidence): a push relation only when the projection's base IS
    that register (callee and caller side), never an arbitrary register the
    shape happened to move; without evidence there are no relations."""
    evidence = scopes.program.evidence
    sp = stack_register(evidence)
    if sp is None:
        return {}
    found: dict[str, CallRelation] = {}
    instructions = {(row.address.space_id, row.address.byte_offset): row for row in observation.instructions}
    for projection in observed_call_state_projections(observation):
        transition = projection.memory_transition
        if any((base.byte_offset, base.byte_size) != (sp.byte_offset, sp.byte_size)
               for base in (transition.caller_base, transition.callee_base)):
            continue
        key = projection.call_operation_key
        space, address, ordinal = key.split(":")[:3]
        instruction = instructions.get((int(space, 16), int(address, 16)))
        if instruction is None or instruction.fallthrough is None:
            continue
        # the projection's register slices carry no space: the adjustment's own
        # output must be the stack register itself (space, offset, width)
        adjust = instruction.operations[int(projection.transient_operation_keys[0].split(":")[2])]
        if adjust.output is None or not _is(adjust.output, sp):
            continue
        coordinate = projection.transient_coordinate.coordinate
        if coordinate != instruction.fallthrough:
            continue
        found[key] = CallRelation(
            key, "push", sp, LinkSlot(coordinate.space_id, projection.transient_coordinate.selector.byte_size),
            transition.displacement_delta, coordinate, "instruction-relative",
            coordinate.byte_offset - instruction.address.byte_offset, int(ordinal),
            tuple(_operation_key(instruction.address, index, op.opcode)
                  for index, op in enumerate(instruction.operations[:int(ordinal)])),
            projection.transient_operation_keys)
    link = link_register(evidence)
    pc = program_counter(evidence)
    if link is None or pc is None:
        return found
    for instruction in observation.instructions:
        relation = _link_relation(instruction, link, sp, pc)
        if relation is not None and relation.call_key not in found:
            found[relation.call_key] = relation
    return found


def _link_relation(instruction, link: RegisterCoordinate, sp: RegisterCoordinate,
                   pc: RegisterCoordinate) -> CallRelation | None:
    """The link recognizer: the instruction is a call (Ghidra flow) with a
    fallthrough; its last op a CALL / CALLIND; the op before it the one write
    of the link register; before that nothing (CALL) or exactly the target
    capture ``COPY pc = Rn`` of a CALLIND -- Rn a full-width register that is
    neither the stack pointer nor the program counter, the CALLIND reading
    that pc (so the target is read before the link write and nothing else
    moves the stack). The written value is the fallthrough: ``INT_ADD
    inst_start, length`` (instruction-relative) or a COPY of that constant
    (relocation unknown)."""
    operations = instruction.operations
    flow = instruction.flow
    fallthrough = instruction.fallthrough
    if not flow.is_call or not flow.has_fallthrough or fallthrough is None or len(operations) < 2:
        return None
    call = operations[-1]
    if call.opcode not in _CALLS:
        return None
    write = operations[-2]
    if write.output is None or not _is(write.output, link):
        return None
    start = instruction.address.byte_offset
    if write.opcode == "INT_ADD" and len(write.inputs) == 2 \
            and all(item.kind is VarnodeKindCode.CONSTANT for item in write.inputs):
        base, step = (item.coordinate.byte_offset for item in write.inputs)
        value = base + step
        relocation = "instruction-relative" if base == start else "unknown"
    elif write.opcode == "COPY" and len(write.inputs) == 1 and write.inputs[0].kind is VarnodeKindCode.CONSTANT:
        value = write.inputs[0].coordinate.byte_offset
        relocation = "unknown"
    else:
        return None
    if value % (1 << (8 * link.byte_size)) != fallthrough.byte_offset:
        return None
    before = operations[:-2]
    if call.opcode == "CALL":
        if before:
            return None
    else:
        if len(before) != 1:
            return None
        capture = before[0]
        if capture.opcode != "COPY" or capture.output is None or not _is(capture.output, pc) \
                or len(capture.inputs) != 1 or len(call.inputs) != 1 or not _is(call.inputs[0], pc):
            return None
        target = capture.inputs[0]
        if target.kind is not VarnodeKindCode.REGISTER or target.byte_size != pc.byte_size \
                or _overlaps(target, sp) or _overlaps(target, pc):
            return None
    keys = tuple(_operation_key(instruction.address, index, op.opcode) for index, op in enumerate(operations))
    return CallRelation(keys[-1], "link", sp, link, 0, fallthrough, relocation, fallthrough.byte_offset - start,
                        len(operations) - 1, keys[:-1], ())


def _overlaps(varnode, register: RegisterCoordinate) -> bool:
    return varnode.coordinate.space_id == register.space_id \
        and varnode.coordinate.byte_offset < register.byte_offset + register.byte_size \
        and register.byte_offset < varnode.coordinate.byte_offset + varnode.byte_size


def _is(varnode, register: RegisterCoordinate) -> bool:
    return varnode.kind is VarnodeKindCode.REGISTER and varnode.coordinate.space_id == register.space_id \
        and varnode.coordinate.byte_offset == register.byte_offset and varnode.byte_size == register.byte_size


__all__ = ["CallRelation", "LinkSlot", "call_relations"]
