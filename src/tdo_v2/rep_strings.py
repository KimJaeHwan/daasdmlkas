"""x86 ``rep movs*`` / ``rep stos*`` as one block effect.

Ghidra 12 lifts ``rep movsb`` (ia.sinc) as one instruction with internal flow::

    0 u  = INT_EQUAL C, 0              ; C = RCX/ECX
    1      CBRANCH <next instruction>, u
    2 C  = INT_SUB C, 1
    3 td = COPY DI
    4 a  = INT_ADD DI, size
    5 z  = INT_ZEXT DF
    6 m  = INT_MULT 2*size, z
    7 DI = INT_SUB a, m                ; DI += size - 2*size*DF
    [8..12: the same for SI -> ts]     ; movs only
    13 v = LOAD space, ts              ; movs only
    14 w = COPY v                      ; stos: w = COPY AL/AX/EAX/RAX
    15     STORE space, td, w
    16     BRANCH <this instruction>

``recognize`` accepts exactly this shape (any element size 1/2/4/8, either
register width) and returns a ``RepSite``; anything else (``repe``/``repne``,
other string ops, a different lifting) is None and keeps the generic
in-instruction loop. Normalization (``normalize``) then treats a site as one
straight block: until the count and direction are proven its register
updates and memory accesses are unknown (no weaker than the loop form); once
proven, the copy becomes ``n`` element accesses in iteration order.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._scope_contracts import VarnodeKindCode
from .call_seeds import _operation_key

MAX_REP_BYTES = 4096   # larger proven blocks keep the unknown form


@dataclass(frozen=True, slots=True)
class RepSite:
    address: object
    size: int                  # element bytes
    count: object              # RCX/ECX varnode
    destination: object        # RDI/EDI varnode
    source: object | None      # RSI/ESI varnode (movs) or None (stos)
    direction: object          # DF varnode
    space_id: int              # LOAD/STORE address space
    count_key: str             # INT_EQUAL reading the count at the instruction start
    count_def_key: str         # INT_SUB writing the decremented count
    direction_key: str         # INT_ZEXT reading DF
    destination_temp: object   # td: the element address (COPY DI)
    destination_def_key: str   # INT_SUB writing DI
    destination_add: object    # a: DI + size (read by the DI-writing op)
    source_temp: object | None
    source_def_key: str | None
    source_add: object | None
    load_key: str | None
    load_output: object | None
    value: object              # w: the stored value
    store_key: str
    store_ordinal: int
    constant_space: int        # the constant space of the site's own constants
    value_copy_key: str = ""   # COPY producing the stored value (w)
    branch_key: str = ""       # CBRANCH leaving when the count is 0

    @property
    def element_keys(self) -> tuple[str, ...]:
        """Operations repeated per element (iteration i >= 1 keyed ``~e<i>``):
        the load, the value copy (movs) and the store."""
        if self.load_key is None:
            return (self.store_key,)
        return (self.load_key, self.value_copy_key, self.store_key)

    @property
    def keys(self) -> tuple[str, ...]:
        return tuple(key for key in (self.count_def_key, self.destination_def_key, self.source_def_key,
                                     self.load_key, self.store_key) if key is not None)


def _const(varnode, value=None):
    return varnode.kind is VarnodeKindCode.CONSTANT and (
        value is None or varnode.coordinate.byte_offset == value)


def _same(left, right):
    return left == right


def _pointer_update(ops, index, register, flag):
    """ops[index:index+5] = td = COPY R; a = R + s; z = ZEXT DF; m = 2s*z; R = a - m.
    Returns (td, a, size, DF varnode, INT_SUB index) or None."""
    if index + 5 > len(ops):
        return None
    copy, add, zext, mult, sub = ops[index:index + 5]
    if register is None:
        if copy.opcode != "COPY" or len(copy.inputs) != 1 or copy.inputs[0].kind is not VarnodeKindCode.REGISTER:
            return None
        register = copy.inputs[0]
    if not (copy.opcode == "COPY" and copy.inputs == (register,) and copy.output is not None
            and copy.output.kind is VarnodeKindCode.UNIQUE):
        return None
    if not (add.opcode == "INT_ADD" and len(add.inputs) == 2 and add.inputs[0] == register
            and _const(add.inputs[1]) and add.output is not None):
        return None
    size = add.inputs[1].coordinate.byte_offset
    if size not in (1, 2, 4, 8):
        return None
    if not (zext.opcode == "INT_ZEXT" and len(zext.inputs) == 1 and zext.inputs[0].kind is VarnodeKindCode.REGISTER
            and zext.inputs[0].byte_size == 1 and (flag is None or zext.inputs[0] == flag) and zext.output is not None):
        return None
    if not (mult.opcode == "INT_MULT" and len(mult.inputs) == 2 and _const(mult.inputs[0], 2 * size)
            and mult.inputs[1] == zext.output and mult.output is not None):
        return None
    if not (sub.opcode == "INT_SUB" and sub.inputs == (add.output, mult.output) and sub.output == register):
        return None
    return copy.output, add.output, size, zext.inputs[0], register


def recognize(instruction) -> RepSite | None:
    ops = instruction.operations
    address = instruction.address
    if len(ops) not in (11, 17) or instruction.fallthrough is None:
        return None
    test, branch, decrement = ops[0], ops[1], ops[2]
    count = test.inputs[0] if test.inputs else None
    if not (test.opcode == "INT_EQUAL" and len(test.inputs) == 2 and count.kind is VarnodeKindCode.REGISTER
            and _const(test.inputs[1], 0) and test.output is not None):
        return None
    exit_target = branch.inputs[0] if branch.inputs else None
    if not (branch.opcode == "CBRANCH" and len(branch.inputs) == 2 and branch.inputs[1] == test.output
            and exit_target.kind is VarnodeKindCode.ADDRESS
            and (exit_target.coordinate.space_id, exit_target.coordinate.byte_offset)
            == (instruction.fallthrough.space_id, instruction.fallthrough.byte_offset)):
        return None
    if not (decrement.opcode == "INT_SUB" and decrement.inputs == (count, decrement.inputs[1])
            and _const(decrement.inputs[1], 1) and decrement.output == count):
        return None
    back = ops[-1]
    if not (back.opcode == "BRANCH" and len(back.inputs) == 1 and back.inputs[0].kind is VarnodeKindCode.ADDRESS
            and (back.inputs[0].coordinate.space_id, back.inputs[0].coordinate.byte_offset)
            == (address.space_id, address.byte_offset)):
        return None
    destination = _pointer_update(ops, 3, None, None)
    if destination is None:
        return None
    td, dst_add, size, flag, di = destination
    if di.byte_size != count.byte_size:
        return None

    def key(index):
        return _operation_key(address, index, ops[index].opcode)

    if len(ops) == 17:   # movs
        source = _pointer_update(ops, 8, None, flag)
        if source is None:
            return None
        ts, src_add, source_size, _, si = source
        load, copy, store = ops[13], ops[14], ops[15]
        if source_size != size or si.byte_size != di.byte_size or si == di:
            return None
        if not (load.opcode == "LOAD" and len(load.inputs) == 2 and _const(load.inputs[0])
                and load.inputs[1] == ts and load.output is not None and load.output.byte_size == size):
            return None
        if not (copy.opcode == "COPY" and copy.inputs == (load.output,) and copy.output is not None):
            return None
        store_index, value = 15, copy.output
        space = load.inputs[0].coordinate.byte_offset
        load_key, load_output = key(13), load.output
        source_fields = (ts, key(12), src_add)
    else:                # stos
        copy, store = ops[8], ops[9]
        if not (copy.opcode == "COPY" and len(copy.inputs) == 1 and copy.inputs[0].kind is VarnodeKindCode.REGISTER
                and copy.inputs[0].byte_size == size and copy.output is not None):
            return None
        store_index, value = 9, copy.output
        space = None
        load_key = load_output = si = None
        source_fields = (None, None, None)
    if not (store.opcode == "STORE" and len(store.inputs) == 3 and _const(store.inputs[0])
            and store.inputs[1] == td and store.inputs[2] == value and value.byte_size == size):
        return None
    store_space = store.inputs[0].coordinate.byte_offset
    if space is not None and space != store_space:
        return None
    return RepSite(
        address, size, count, di, si, flag, store_space, key(0), key(2), key(5), td, key(7), dst_add,
        *source_fields, load_key, load_output, value, key(store_index), store_index,
        decrement.inputs[1].coordinate.space_id, key(store_index - 1), key(1),
    )


def rep_sites(observation) -> dict:
    """Instruction address -> RepSite."""
    found = {}
    for instruction in observation.instructions:
        site = recognize(instruction)
        if site is not None:
            found[instruction.address] = site
    return found


__all__ = ("MAX_REP_BYTES", "RepSite", "recognize", "rep_sites")
