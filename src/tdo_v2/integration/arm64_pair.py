"""Check normal-completion effects of a single integer ARM64 pair instruction."""

from dataclasses import dataclass

from .._scope_contracts import AddressCoordinate, ValidatedVarnode, VarnodeKindCode


_MODES = {0x28800000: "post", 0x29000000: "offset", 0x29800000: "pre"}
_MASK64 = (1 << 64) - 1
PAIR_FORMS = frozenset(("stp", "ldp"))


@dataclass(frozen=True)
class PairForm:
    load: bool
    width: int
    mode: str
    displacement: int
    base: int
    registers: tuple[int, int]

    @property
    def mnemonic(self):
        return "ldp" if self.load else "stp"

    @property
    def base_name(self):
        return "sp" if self.base == 31 else f"x{self.base}"

    @property
    def register_names(self):
        prefix = "x" if self.width == 8 else "w"
        return tuple(prefix + ("zr" if number == 31 else str(number)) for number in self.registers)

    @property
    def access_offsets(self):
        first = 0 if self.mode == "post" else self.displacement
        return first, first + self.width


@dataclass(frozen=True)
class PairObservation:
    accesses: tuple[int, int]
    writeback: int | None


def decode_pair(word):
    # Match integer W/X ordinary pairs, excluding SIMD, LDPSW, STGP
    # and the no-allocate pair encodings.
    mode = _MODES.get(word & 0x7F800000)
    if mode is None:
        return None
    load = bool(word & (1 << 22))
    width = 8 if word >> 31 else 4
    base = (word >> 5) & 31
    registers = (word & 31, (word >> 10) & 31)
    if (load and registers[0] == registers[1]
            or mode != "offset" and base != 31 and base in registers):
        return None
    immediate = (word >> 15) & 127
    if immediate >= 64:
        immediate -= 128
    return PairForm(load, width, mode, immediate * width, base, registers)


def _overlap(left, right):
    return (left.kind is right.kind and left.coordinate.space_id == right.coordinate.space_id
            and left.coordinate.byte_offset < right.coordinate.byte_offset + right.byte_size
            and right.coordinate.byte_offset < left.coordinate.byte_offset + left.byte_size)


def verify_pair_register_file(registers, flags):
    """Validate storage identity before interpreting a row's register names."""
    wide = {name: registers.get(name) for name in ("sp", "pc", *(f"x{i}" for i in range(31)))}
    if any(value is None or value.kind is not VarnodeKindCode.REGISTER or value.byte_size != 8
           for value in wide.values()):
        return False
    for name, value in wide.items():
        if name == "pc":
            continue
        alias = registers.get("w" + (name if name == "sp" else name[1:]))
        if (alias is None or alias.kind is not VarnodeKindCode.REGISTER or alias.byte_size != 4
                or alias.coordinate != value.coordinate):
            return False
    spans = sorted((*wide.values(), *flags), key=lambda value: value.coordinate)
    return not any(_overlap(left, right) for left, right in zip(spans, spans[1:]))


def verify_pair(form, operations, registers, ram):
    """Bind raw effects using the admitted pair register file."""
    temporaries = sorted({op.output for op in operations
                          if op.output is not None and op.output.kind is VarnodeKindCode.UNIQUE},
                         key=lambda target: (target.coordinate, target.byte_size))
    if any(_overlap(left, right) for left, right in zip(temporaries, temporaries[1:])):
        return None
    base = registers[form.base_name]
    initial_base = (base, 0)
    values = {base: initial_base}
    sources = []
    expected_writes = {}
    for lane, (number, name) in enumerate(zip(form.registers, form.register_names)):
        if form.load:
            if number != 31:
                value = ("load", lane)
                expected_writes[registers[f"x{number}"]] = value if form.width == 8 else ("zext", value)
        elif number == 31:
            sources.append(0)
        else:
            source = registers.get(name)
            if (source is None or source.kind is not VarnodeKindCode.REGISTER or source.byte_size != form.width
                    or source.coordinate != registers[f"x{number}"].coordinate):
                return None
            values[source] = (source, 0)
            sources.append(values[source])
    if form.mode != "offset":
        expected_writes[base] = (base, form.displacement & _MASK64)
    allowed_addresses = tuple((base, offset & _MASK64) for offset in form.access_offsets)
    selector = ValidatedVarnode(VarnodeKindCode.CONSTANT, AddressCoordinate(0, ram), 8)
    opcode = "LOAD" if form.load else "STORE"
    accesses, written = [], {}

    for ordinal, op in enumerate(operations):
        args, output = op.inputs, op.output
        operands = tuple(arg.coordinate.byte_offset
                         if arg.kind is VarnodeKindCode.CONSTANT and arg.coordinate.space_id == 0
                         else values.get(arg) for arg in args)
        if None in operands:
            return None
        if op.opcode == opcode:
            lane = len(accesses)
            if (lane == 2 or len(args) != (2 if form.load else 3)
                    or args[0] != selector or args[1].byte_size != 8 or operands[1] != allowed_addresses[lane]):
                return None
            accesses.append(ordinal)
            if not form.load:
                if output is not None or args[2].byte_size != form.width or operands[2] != sources[lane]:
                    return None
                continue
            if output is None or output.kind is not VarnodeKindCode.UNIQUE or output.byte_size != form.width:
                return None
            value = ("load", lane)
        else:
            if output is None:
                return None
            if op.opcode == "COPY" and len(args) == 1 and args[0].byte_size == output.byte_size:
                value = operands[0]
            elif (op.opcode == "INT_ADD" and len(args) == 2
                  and output.byte_size == args[0].byte_size == args[1].byte_size == 8
                  and isinstance(operands[0], tuple) and operands[0][0] == base and type(operands[1]) is int):
                value = (base, (operands[0][1] + operands[1]) & _MASK64)
            elif (op.opcode == "INT_ZEXT" and len(args) == 1 and args[0].byte_size == 4
                  and output.byte_size == 8 and operands[0] in (("load", 0), ("load", 1))):
                value = ("zext", operands[0])
            else:
                return None
        if output.kind is VarnodeKindCode.REGISTER:
            if output in written or expected_writes.get(output) != value:
                return None
            written[output] = ordinal
        elif output.kind is not VarnodeKindCode.UNIQUE:
            return None
        values[output] = value

    if len(accesses) != 2 or written.keys() != expected_writes.keys():
        return None
    return PairObservation(tuple(accesses), written[base] if form.mode != "offset" else None)
