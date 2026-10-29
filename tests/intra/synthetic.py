"""In-memory synthetic program provider for intrafunction engine tests.

Builds a ``ScopedFunctionUnit`` through the real scope envelope
(``open_configured_extraction``) without a Bundle on disk, so the tests run on
any platform (the Bundle admission path is POSIX-only).

Functions are written with ``FunctionBuilder``: one ``ins(...)`` call per
machine instruction, labels for branch targets, and x86 style helpers for
prologue/epilogue so that every function ends with the stack LOAD of the
return address, as real Ghidra output does. ``arch=X86_32`` builds 32-bit x86
(Ghidra ``x86:LE:32:default``: 4-byte pointers and pushes, ESP 0x10, EIP
0x284 -- the offsets of a real Bundle); every function of a program shares one.
Approximations: LOAD / STORE space selectors stay 8-byte constants (Ghidra
emits both widths), flag helpers write no PF, images sit at low addresses.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from tdo_v2._scope_contracts import (
    FrozenMemoryBlockDescriptor,
    PositionedChunk,
    _mint_orchestrator_capability,
)
from tdo_v2._scope_envelope import open_configured_extraction
from tdo_v2._scope_raw import parse_raw_json
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.model import StorageObjectKind
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction
from tdo_v2.query import BackwardSliceQuery

# Space ids are arbitrary; only the classification flags matter.
CONST, RAM, REG, UNIQUE = 0, 1, 2, 3
EXTERNAL = 4  # Ghidra EXTERNAL space (imported symbols)

# Ghidra x86-64 register offsets.
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = (
    0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38,
)
R8, R9 = 0x80, 0x88
RIP = 0x288
CF, PF, ZF, SF, OF = 0x200, 0x202, 0x206, 0x207, 0x20B

# Ghidra x86-32 register offsets (x86:LE:32:default).
EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI = (
    0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C,
)
EIP = 0x284

# Ghidra AArch64 register offsets (AARCH64:LE:64:v8A, AARCH64instructions.sinc):
# pc, sp, the flags NG ZR CY OV, x0..x30 (w<n> = the low 4 bytes of x<n>).
PC, SP = 0x0, 0x8
NG, ZR, CY, OV = 0x100, 0x101, 0x102, 0x103
X = tuple(0x4000 + 8 * index for index in range(31))
X0, X1, X2, X3, X8, X19, X29, X30 = X[0], X[1], X[2], X[3], X[8], X[19], X[29], X[30]


@dataclass(frozen=True)
class Arch:
    """What the builder and the provider take from the target: the language,
    the pointer (and push) width, the address size, the stack and instruction
    pointers, and -- for a link-register ISA -- the register a call writes its
    return address to (a call then pushes nothing)."""

    language_id: str
    pointer: int
    sp: int
    ip: int
    link: int | None = None

    @property
    def address_bits(self) -> int:
        return 8 * self.pointer


X64 = Arch("x86:LE:64:default", 8, RSP, RIP)
X86_32 = Arch("x86:LE:32:default", 4, ESP, EIP)
AARCH64 = Arch("AARCH64:LE:64:v8A", 8, SP, PC, link=X30)

REGISTER_NAMES = {
    RAX: "RAX", RCX: "RCX", RDX: "RDX", RBX: "RBX", RSP: "RSP", RBP: "RBP",
    RSI: "RSI", RDI: "RDI", R8: "R8", R9: "R9", RIP: "RIP",
    CF: "CF", PF: "PF", ZF: "ZF", SF: "SF", OF: "OF",
}

CODE_BASE, CODE_SIZE = 0x1000, 0x1000
DATA_BASE, DATA_SIZE = 0x4000, 0x1000


@dataclass(frozen=True)
class Layout:
    """The synthetic image's memory blocks (docs 25.30 K2: large functions
    need a larger code block; the default is every existing test's)."""

    code_base: int = CODE_BASE
    code_size: int = CODE_SIZE
    data_base: int = DATA_BASE
    data_size: int = DATA_SIZE


DEFAULT_LAYOUT = Layout()
# 2M instructions at stride 4; data well above it
LARGE_LAYOUT = Layout(0x100000, 8 << 20, 0x1000000, 1 << 20)

# the callbacks / frees declaration every model entry carries (docs 25.33):
# test models run no user code and free nothing
NO_CALLBACKS = {"callbacks": "none", "callbacks_evidence": "test model", "frees": "none"}


# --------------------------------------------------------------------------
# Varnodes and P-code operations
# --------------------------------------------------------------------------

def const(value: int, size: int = 8) -> dict:
    return {"kind_code": 1, "space_id": CONST, "byte_offset": value, "byte_size": size}


def reg(offset: int, size: int = 8) -> dict:
    return {"kind_code": 2, "space_id": REG, "byte_offset": offset, "byte_size": size}


def tmp(offset: int, size: int = 8) -> dict:
    return {"kind_code": 3, "space_id": UNIQUE, "byte_offset": offset, "byte_size": size}


def ram(offset: int, size: int = 8) -> dict:
    return {"kind_code": 4, "space_id": RAM, "byte_offset": offset, "byte_size": size}


def op(opcode: str, inputs: list[dict], output: dict | None = None) -> tuple:
    return (opcode, inputs, output)


def copy(out: dict, value: dict) -> tuple:
    return op("COPY", [value], out)


def add(out: dict, left: dict, right: dict) -> tuple:
    return op("INT_ADD", [left, right], out)


def sub(out: dict, left: dict, right: dict) -> tuple:
    return op("INT_SUB", [left, right], out)


def load(out: dict, pointer: dict) -> tuple:
    return op("LOAD", [const(RAM), pointer], out)


def store(pointer: dict, value: dict) -> tuple:
    return op("STORE", [const(RAM), pointer, value])


# --------------------------------------------------------------------------
# Instruction-level builder
# --------------------------------------------------------------------------

_FLOW_KEYS = (
    "is_flow", "has_fallthrough", "is_call", "is_jump", "is_terminal",
    "is_computed", "is_conditional", "is_unconditional", "is_override",
)


def _flow(**flags) -> dict:
    return {key: bool(flags.get(key, False)) for key in _FLOW_KEYS}


@dataclass
class _Instruction:
    ops: list[tuple]
    kind: str = "plain"          # plain | cbranch | branch | call | tail | return
    target: str | None = None    # label for cbranch/branch
    condition: dict | None = None  # cbranch condition varnode
    call_target: int | None = None  # call destination address


@dataclass
class FunctionBuilder:
    entry: int = CODE_BASE
    stride: int = 4
    _rows: list[_Instruction] = field(default_factory=list)
    _labels: dict[str, int] = field(default_factory=dict)
    arch: Arch = X64

    def _sp(self) -> dict:
        return reg(self.arch.sp, self.arch.pointer)

    def _word(self, value: int) -> dict:
        return const(value, self.arch.pointer)

    # -- structure ---------------------------------------------------------
    def label(self, name: str) -> "FunctionBuilder":
        if name in self._labels:
            raise ValueError(f"duplicate label {name}")
        self._labels[name] = len(self._rows)
        return self

    def ins(self, *ops: tuple) -> "FunctionBuilder":
        self._rows.append(_Instruction(list(ops)))
        return self

    def cbranch(self, target: str, condition: dict, *pre: tuple) -> "FunctionBuilder":
        """``pre`` ops (e.g. the compare) run before the CBRANCH."""
        self._rows.append(_Instruction(list(pre), "cbranch", target, condition))
        return self

    def call(self, target: int) -> "FunctionBuilder":
        """x86 ``call imm``: push return address, then CALL. AArch64 ``bl``:
        x30 = inst_start + 4 (Ghidra: INT_ADD of two constants), then CALL."""
        index = len(self._rows)
        if self.arch.link is not None:
            self._rows.append(_Instruction(
                [self._link_write(index), op("CALL", [ram(target, self.arch.pointer)])], "call", call_target=target))
            return self
        self._rows.append(_Instruction(
            [
                sub(self._sp(), self._sp(), self._word(self.arch.pointer)),
                store(self._sp(), self._word(self._address(index + 1))),
                op("CALL", [ram(target, self.arch.pointer)]),
            ],
            "call",
            call_target=target,
        ))
        return self

    def call_indirect(self, register: int) -> "FunctionBuilder":
        """x86-64 ``call r``: Ghidra copies the target first, then pushes the
        return address and CALLINDs the copy. AArch64 ``blr xN``: pc = xN, then
        x30 = inst_start + 4, then CALLIND pc (the target is taken before the
        link write: ``blr x30`` calls the old x30)."""
        index = len(self._rows)
        width = self.arch.pointer
        if self.arch.link is not None:
            self._rows.append(_Instruction(
                [copy(reg(self.arch.ip, width), reg(register, width)), self._link_write(index),
                 op("CALLIND", [reg(self.arch.ip, width)])], "callind"))
            return self
        self._rows.append(_Instruction(
            [
                copy(tmp(0x400, width), reg(register, width)),
                sub(self._sp(), self._sp(), self._word(width)),
                store(self._sp(), self._word(self._address(index + 1))),
                op("CALLIND", [tmp(0x400, width)]),
            ],
            "callind",
        ))
        return self

    def _link_write(self, index: int) -> tuple:
        """x30 = inst_start + 4: every AArch64 instruction is 4 bytes, so the
        builder's stride must be too (else the fallthrough and the link differ)."""
        if self.stride != 4:
            raise ValueError("AArch64 instructions are 4 bytes: stride must be 4")
        width = self.arch.pointer
        return op("INT_ADD", [const(self._address(index), width), const(4, width)], reg(self.arch.link, width))

    def tail_call(self, target: int) -> "FunctionBuilder":
        """x86-64 tail call ``jmp target``: a BRANCH Ghidra flags as a call."""
        self._rows.append(_Instruction([op("BRANCH", [ram(target, self.arch.pointer)])], "tail",
                                       call_target=target))
        return self

    def branch(self, target: str) -> "FunctionBuilder":
        self._rows.append(_Instruction([], "branch", target))
        return self

    # -- x86-64 helpers ----------------------------------------------------
    def push(self, register: int) -> "FunctionBuilder":
        if self.arch.link is not None:
            raise ValueError("no push on a link-register ISA (use store / sub_rsp)")
        width = self.arch.pointer
        return self.ins(
            sub(self._sp(), self._sp(), self._word(width)),
            store(self._sp(), reg(register, width)),
        )

    def pop(self, register: int) -> "FunctionBuilder":
        if self.arch.link is not None:
            raise ValueError("no pop on a link-register ISA (use load / add_rsp)")
        width = self.arch.pointer
        return self.ins(
            load(reg(register, width), self._sp()),
            add(self._sp(), self._sp(), self._word(width)),
        )

    def sub_rsp(self, amount: int) -> "FunctionBuilder":
        """``sub rsp, imm`` (``sub esp`` on X86_32) including Ghidra's flag
        writes; AArch64 ``sub sp, sp, #imm`` sets no flags."""
        sp, amount_ = self._sp(), self._word(amount)
        if self.arch.link is not None:
            return self.ins(sub(sp, sp, amount_))
        return self.ins(
            op("INT_LESS", [sp, amount_], reg(CF, 1)),
            op("INT_SBORROW", [sp, amount_], reg(OF, 1)),
            sub(sp, sp, amount_),
            op("INT_SLESS", [sp, self._word(0)], reg(SF, 1)),
            op("INT_EQUAL", [sp, self._word(0)], reg(ZF, 1)),
        )

    def add_rsp(self, amount: int) -> "FunctionBuilder":
        sp, amount_ = self._sp(), self._word(amount)
        if self.arch.link is not None:
            return self.ins(add(sp, sp, amount_))
        return self.ins(
            op("INT_CARRY", [sp, amount_], reg(CF, 1)),
            op("INT_SCARRY", [sp, amount_], reg(OF, 1)),
            add(sp, sp, amount_),
            op("INT_SLESS", [sp, self._word(0)], reg(SF, 1)),
            op("INT_EQUAL", [sp, self._word(0)], reg(ZF, 1)),
        )

    def ret(self, *, realistic: bool = True, via: int | None = None) -> "FunctionBuilder":
        """x86 ``ret``: IP = *(SP); SP += pointer; RETURN IP. AArch64 ``ret``
        (``ret xN`` with ``via``): pc = x30 (xN); RETURN pc."""
        width = self.arch.pointer
        if self.arch.link is not None:
            source = self.arch.link if via is None else via
            self._rows.append(_Instruction(
                [copy(reg(self.arch.ip, width), reg(source, width)), op("RETURN", [reg(self.arch.ip, width)])],
                "return"))
            return self
        if via is not None:
            raise ValueError("ret via a register is AArch64 only")
        if realistic:
            ops = [
                load(reg(self.arch.ip, width), self._sp()),
                add(self._sp(), self._sp(), self._word(width)),
                op("RETURN", [reg(self.arch.ip, width)]),
            ]
        else:
            ops = [op("RETURN", [self._sp()])]
        self._rows.append(_Instruction(ops, "return"))
        return self

    # -- serialization -----------------------------------------------------
    def _address(self, index: int) -> int:
        return self.entry + index * self.stride

    def _coordinate(self, address: int) -> dict:
        return {"space_id": RAM, "byte_offset": address}

    def to_json(self) -> dict:
        if not self._rows or self._rows[-1].kind not in {"return", "branch", "tail"}:
            raise ValueError("function must end with ret(), branch() or tail_call()")
        rows = []
        for index, row in enumerate(self._rows):
            address = self._address(index)
            next_address = self._address(index + 1)
            ops = list(row.ops)
            targets: list[dict] = []
            fallthrough = row.kind in {"plain", "cbranch", "call", "callind"}
            if row.kind in {"cbranch", "branch"}:
                if row.target not in self._labels:
                    raise ValueError(f"unknown label {row.target}")
                target = self._address(self._labels[row.target])
                targets = [self._coordinate(target)]
                destination = ram(target, self.arch.pointer)
                if row.kind == "cbranch":
                    ops.append(op("CBRANCH", [destination, row.condition]))
                    flow = _flow(
                        is_flow=True, has_fallthrough=True, is_jump=True,
                        is_conditional=True,
                    )
                else:
                    ops.append(op("BRANCH", [destination]))
                    flow = _flow(is_flow=True, is_jump=True, is_unconditional=True)
            elif row.kind == "call":
                targets = [self._coordinate(row.call_target)]
                flow = _flow(
                    is_flow=True, has_fallthrough=True, is_call=True,
                    is_unconditional=True,
                )
            elif row.kind == "callind":
                flow = _flow(
                    is_flow=True, has_fallthrough=True, is_call=True, is_computed=True,
                    is_unconditional=True,
                )
            elif row.kind == "tail":
                targets = [self._coordinate(row.call_target)]
                flow = _flow(is_flow=True, is_call=True, is_terminal=True, is_unconditional=True)
            elif row.kind == "return":
                flow = _flow(is_flow=True, is_terminal=True, is_unconditional=True)
            else:
                flow = _flow(has_fallthrough=True)
            rows.append({
                "address": self._coordinate(address),
                "fallthrough_present": fallthrough,
                "fallthrough": self._coordinate(next_address) if fallthrough else None,
                "flow_targets": targets,
                "data_references": [],
                "flow_type": flow,
                "operations": [
                    {
                        "ordinal": ordinal,
                        "opcode": opcode,
                        "inputs": inputs,
                        "output_present": output is not None,
                        "output": output,
                    }
                    for ordinal, (opcode, inputs, output) in enumerate(ops)
                ],
            })
        return {"entry": self._coordinate(self.entry), "instructions": rows}


def straight(*instructions: list[tuple], realistic_return: bool = False) -> FunctionBuilder:
    """Straight-line function, one op list per instruction."""
    builder = FunctionBuilder()
    for ops in instructions:
        builder.ins(*ops)
    return builder.ret(realistic=realistic_return)


# --------------------------------------------------------------------------
# Program provider
# --------------------------------------------------------------------------

def _space(space_id, *, const=False, reg=False, unique=False, mem=False, external=False, bits=64):
    return {
        "space_id": space_id,
        "address_size_bits": bits,
        "addressable_unit_bytes": 1,
        "is_constant_space": const,
        "is_register_space": reg,
        "is_unique_space": unique,
        "is_memory_space": mem,
        "is_overlay_space": False,
        "is_external_space": external,
        "is_loaded_memory_space": mem,
        "is_non_loaded_memory_space": False,
        "has_signed_offset": False,
    }


@dataclass
class _Provider:
    functions: list[FunctionBuilder]
    layout: Layout = DEFAULT_LAYOUT
    code: bytes = b""
    data: bytes = b""
    # the exported ``register_evidence`` record (None: the export has none,
    # as every existing test's program -- its scope digests unchanged)
    registers: dict | None = None

    def __post_init__(self) -> None:
        self.code = self.code or b"\x90" * self.layout.code_size
        self.data = self.data or b"\x00" * self.layout.data_size
        arches = {function.arch for function in self.functions}
        if len(arches) > 1:
            raise ValueError("one program, one architecture")
        self.arch = arches.pop() if arches else X64

    def original_executable_size(self) -> int:
        return len(self.code) + len(self.data)

    def original_executable_chunks(self):
        # bounded chunks (a large layout), code then data, never concatenated
        position = 0
        for source in (self.code, self.data):
            for start in range(0, len(source), 1 << 20):
                piece = source[start:start + (1 << 20)]
                yield PositionedChunk(position, piece)
                position += len(piece)

    def memory_descriptors(self):
        return (
            FrozenMemoryBlockDescriptor(
                "code", RAM, self.layout.code_base, self.layout.code_size,
                True, True, False, False, False,
            ),
            FrozenMemoryBlockDescriptor(
                "data", RAM, self.layout.data_base, self.layout.data_size,
                True, True, False, False, False,
            ),
        )

    def read_exact(self, handle, offset, length):
        source = self.code if handle == "code" else self.data
        for start in range(offset, offset + length, 1 << 20):
            yield PositionedChunk(start, source[start:min(offset + length, start + (1 << 20))])

    def snapshot_complete(self) -> bool:
        return True

    def spaces_complete(self) -> bool:
        return True

    def program_candidate(self):
        candidate = self._program_candidate()
        if self.registers is not None:
            candidate["register_evidence"] = self.registers
        return parse_raw_json(json.dumps(candidate))

    def _program_candidate(self):
        return ({
            "address_space_classification_revision": 2,
            "translation_namespace": {
                "language_id": self.arch.language_id,
                "major_version": 4,
                "minor_version": 6,
            },
            "address_spaces": [
                _space(CONST, const=True),   # (Ghidra's constant space is 64-bit on x86-32 too)
                _space(RAM, mem=True, bits=self.arch.address_bits),
                _space(REG, reg=True, bits=self.arch.address_bits),
                _space(UNIQUE, unique=True, bits=self.arch.address_bits),
                _space(EXTERNAL, external=True, bits=self.arch.address_bits),
            ],
            "image_base": {"space_id": RAM, "byte_offset": self.layout.code_base},
        })

    def function_handles(self):
        return tuple(range(len(self.functions)))

    def observation_complete(self, handle) -> bool:
        return True

    def function_candidate(self, handle):
        return parse_raw_json(json.dumps(self.functions[handle].to_json()))

    def close(self) -> None:
        pass


def normalize_program(*functions: FunctionBuilder, layout: Layout = DEFAULT_LAYOUT) -> list[NormalizedFunction]:
    """Normalize several functions of one program (distinct ``entry`` values)."""
    entries = [function.entry for function in functions]
    if len(set(entries)) != len(entries):
        raise ValueError("program functions need distinct entries")
    provider = _Provider(list(functions), layout)
    with open_configured_extraction(
        provider, _mint_orchestrator_capability()
    ) as envelope:
        units = list(envelope.iter_scoped_functions())
    if len(units) != len(functions):
        raise AssertionError("expected one scoped unit per function")
    results = []
    for unit in units:
        result = FunctionNormalizer().normalize(unit)
        if type(result) is not NormalizedFunction:
            raise AssertionError(f"normalization unresolved: {result!r}")
        results.append(result)
    return results


def program_units(*functions: FunctionBuilder, layout: Layout = DEFAULT_LAYOUT, registers: dict | None = None) -> list:
    """Scoped units of several functions of one program (distinct ``entry``
    values); ``registers``: a ``register_evidence`` record to export
    (``register_evidence(arch)`` or a hand-made one)."""
    entries = [function.entry for function in functions]
    if len(set(entries)) != len(entries):
        raise ValueError("program functions need distinct entries")
    with open_configured_extraction(
        _Provider(list(functions), layout, registers=registers), _mint_orchestrator_capability()
    ) as envelope:
        return list(envelope.iter_scoped_functions())


def register_evidence(arch: "Arch") -> dict:
    """The register table the exporter writes for ``arch`` (a subset of the
    SLEIGH register file, with overlapping aliases), revision 1."""
    if arch is AARCH64:
        rows = [("pc", PC, 8), ("sp", SP, 8), ("wsp", SP, 4), ("NG", NG, 1), ("ZR", ZR, 1)]
        rows += [(f"x{index}", offset, 8) for index, offset in enumerate(X)]
        rows += [(f"w{index}", offset, 4) for index, offset in enumerate(X)]
    elif arch is X86_32:
        rows = [("EAX", EAX, 4), ("ECX", ECX, 4), ("EDX", EDX, 4), ("EBX", EBX, 4), ("ESP", ESP, 4),
                ("EBP", EBP, 4), ("ESI", ESI, 4), ("EDI", EDI, 4), ("EIP", EIP, 4), ("SP", ESP, 2)]
    else:
        rows = [(name, offset, 8) for offset, name in REGISTER_NAMES.items() if offset < 0x200]
        rows += [("ESP", RSP, 4), ("EAX", RAX, 4)]
    rows.sort(key=lambda row: (REG, row[1], row[2], row[0]))
    return {"revision": 1, "registers": [
        {"name": name, "space_id": REG, "byte_offset": offset, "byte_size": size} for name, offset, size in rows]}


def normalize_with_observation(function: FunctionBuilder, layout: Layout = DEFAULT_LAYOUT):
    """Return (NormalizedFunction, ValidatedFunctionObservation) for one function."""
    with open_configured_extraction(
        _Provider([function], layout), _mint_orchestrator_capability()
    ) as envelope:
        (unit,) = envelope.iter_scoped_functions()
    result = FunctionNormalizer().normalize(unit)
    if type(result) is not NormalizedFunction:
        raise AssertionError(f"normalization unresolved: {result!r}")
    return result, unit.observation


def normalize(function: FunctionBuilder) -> NormalizedFunction:
    (result,) = normalize_program(function)
    return result


# --------------------------------------------------------------------------
# Querying and judging
# --------------------------------------------------------------------------

def operation_nodes(function: NormalizedFunction, opcode: str) -> list[int]:
    graph = function.dependencies
    return [
        node
        for node in range(graph.node_count)
        if graph.has_node(node)
        and graph.node(node).kind is NodeKind.OPERATION
        and graph.node(node).label == opcode
    ]


def operation_node_at(function: NormalizedFunction, index: int, ordinal: int = 0,
                      entry: int = CODE_BASE, stride: int = 4) -> int:
    """OPERATION node of op ``ordinal`` in instruction ``index``."""
    address = entry + index * stride
    prefix = f"op:{RAM}:{address:x}:{ordinal}:"
    graph = function.dependencies
    for node in range(graph.node_count):
        record = graph.node(node)
        if record.kind is NodeKind.OPERATION and record.key.startswith(prefix):
            return node
    raise KeyError(prefix)


@dataclass(frozen=True)
class Slice:
    """Backward slice plus the exact ENTRY bytes it consumes."""

    result: object
    register_bytes: frozenset[int]
    memory_bytes: frozenset[tuple[str, int]]

    @property
    def is_complete(self) -> bool:
        return self.result.is_complete

    def reaches(self, register: int, size: int = 8) -> bool:
        return any(byte in self.register_bytes for byte in range(register, register + size))

    def registers(self) -> set[str]:
        names = set()
        for offset, name in REGISTER_NAMES.items():
            width = 1 if offset in {CF, PF, ZF, SF, OF} else 8
            if self.reaches(offset, width):
                names.add(name)
        return names

    def reaches_absolute(self, address: int, size: int = 8) -> bool:
        return any(
            kind == "address_space" and start in range(address, address + size)
            for kind, start in self.memory_bytes
        )


def slice_from(function: NormalizedFunction, seed: int) -> Slice:
    """Run the backward query and attribute reached ENTRY bytes by edge span.

    ENTRY definitions cover *connected* storage ranges (several registers can
    share one ENTRY node), so the bytes actually consumed are taken from the
    spans on edges leaving reached OBSERVED_INPUT nodes.
    """
    result = BackwardSliceQuery().run(function, seed)
    graph = function.dependencies
    reachable = set(result.reachable_nodes)
    observed = set(result.observed_input_nodes)
    register_bytes: set[int] = set()
    memory_bytes: set[tuple[str, int]] = set()
    for source, target, record in graph.weighted_edges():
        if source not in observed or target not in reachable or record.span is None:
            continue
        span = record.span
        kind = span.object_id.kind
        if kind is StorageObjectKind.REGISTER_FILE:
            register_bytes.update(range(span.start, span.end))
        elif kind is StorageObjectKind.ADDRESS_SPACE:
            memory_bytes.update(("address_space", b) for b in range(span.start, span.end))
        else:
            memory_bytes.update((kind.value, b) for b in range(span.start, span.end))
    return Slice(result, frozenset(register_bytes), frozenset(memory_bytes))


def slice_op(function: NormalizedFunction, opcode: str, index: int | None = None,
             code_base: int = CODE_BASE) -> Slice:
    """Slice from the only ``opcode`` operation, or the one in instruction ``index``."""
    seeds = operation_nodes(function, opcode)
    if index is not None:
        prefix = f"op:{RAM}:{code_base + index * 4:x}:"
        seeds = [node for node in seeds if function.dependencies.node(node).key.startswith(prefix)]
    (seed,) = seeds
    return slice_from(function, seed)


# --------------------------------------------------------------------------
# Whole-program (interprocedural) runs
# --------------------------------------------------------------------------

LANGUAGE = "x86:LE:64:default"


def _naming_for(unit, seeds, names: dict[int, str], tails=()):
    from tdo_v2.configured_naming_contracts import (
        CapturedNamingAlias, CapturedNamingResolution, CapturedNamingRow,
        CapturedNamingSidecar, CapturedNamingTarget, NamingAliasKind,
        NamingOpcode, NamingResolutionState, NamingSourceQuality,
        NamingUnresolvedReason, naming_content_digest, naming_row_digest,
        naming_target_digest,
    )
    from tdo_v2.call_contracts import CallOperationKind

    rows = []
    for seed in seeds.callsites:
        instruction = seed.locator.instruction
        ordinal = seed.locator.operation_ordinal
        if seed.kind is CallOperationKind.INDIRECT:
            opcode, selector = NamingOpcode.CALLIND, None
            resolution, targets = CapturedNamingResolution(NamingResolutionState.INDIRECT), ()
        else:
            opcode, selector = NamingOpcode.CALL, seed.inputs[0]
            address = selector.coordinate.byte_offset
            if address in names:
                aliases = (CapturedNamingAlias(
                    NamingAliasKind.SYMBOL, names[address], NamingSourceQuality.USER_DEFINED,
                ),)
                coordinate = selector.coordinate
                targets = (CapturedNamingTarget(
                    0, coordinate, False, False, aliases,
                    naming_target_digest(0, coordinate, False, False, aliases),
                ),)
                resolution = CapturedNamingResolution(
                    NamingResolutionState.RESOLVED_NAMED, terminal_target_ordinal=0
                )
            else:
                targets = ()
                resolution = CapturedNamingResolution(
                    NamingResolutionState.UNRESOLVED,
                    NamingUnresolvedReason.NO_EXACT_FUNCTION,
                )
        rows.append(CapturedNamingRow(
            instruction, ordinal, opcode, selector, resolution, targets,
            naming_row_digest(instruction, ordinal, opcode, selector, resolution, targets),
        ))
    rows = tuple(sorted(rows, key=lambda row: row.canonical_key))
    tail_rows = []
    for tail in tails:
        opcode = NamingOpcode(tail.opcode.value)
        selector = tail.selector
        if opcode is NamingOpcode.BRANCHIND:
            resolution, targets = CapturedNamingResolution(NamingResolutionState.INDIRECT), ()
        else:
            address = selector.coordinate.byte_offset
            aliases = (CapturedNamingAlias(
                NamingAliasKind.SYMBOL, names.get(address, f"fn_{address:x}"),
                NamingSourceQuality.USER_DEFINED,
            ),)
            targets = (CapturedNamingTarget(
                0, selector.coordinate, False, False, aliases,
                naming_target_digest(0, selector.coordinate, False, False, aliases),
            ),)
            resolution = CapturedNamingResolution(
                NamingResolutionState.RESOLVED_NAMED, terminal_target_ordinal=0
            )
        tail_rows.append(CapturedNamingRow(
            tail.instruction, tail.operation_ordinal, opcode, selector, resolution, targets,
            naming_row_digest(tail.instruction, tail.operation_ordinal, opcode, selector,
                              resolution, targets),
        ))
    tail_rows = tuple(tail_rows)
    exporter = b"\x11" * 32
    return CapturedNamingSidecar(
        exporter, rows, naming_content_digest(exporter, rows, tail_rows), tail_rows
    )


def boundary(sources: dict[str, int] = (), sinks: dict[str, int] = (), *,
             assume_call_effect: bool = False, arch: Arch = None):
    """SymbolBoundaryProvider: sources return in RAX bytes, sinks read RCX bytes
    -- on ``arch=AARCH64`` both in x0 (the harness's TEST-ONLY fixture, like the
    x86 table; no engine convention).

    ``assume_call_effect`` marks every rule with the TEST-ONLY declared effect.
    """
    from tdo_v2.boundary import BoundaryKind
    from tdo_v2.boundary_rules import BoundaryRule, SymbolBoundaryProvider
    from tdo_v2.physical_state import PhysicalRegisterSlice

    arch = arch or X64
    source_register, sink_register = (X0, X0) if arch is AARCH64 else (RAX, RCX)
    language = LANGUAGE if arch is X64 else arch.language_id
    rules = [
        BoundaryRule(name, language, BoundaryKind.SOURCE, f"{name}.ret",
                     (PhysicalRegisterSlice(source_register, size),), assume_call_effect)
        for name, size in dict(sources).items()
    ] + [
        BoundaryRule(name, language, BoundaryKind.SINK, f"{name}.arg0",
                     (PhysicalRegisterSlice(sink_register, size),), assume_call_effect)
        for name, size in dict(sinks).items()
    ]
    return SymbolBoundaryProvider(tuple(rules))


def analyze_program(functions: dict[str, FunctionBuilder], provider, *, layout: Layout = DEFAULT_LAYOUT,
                    assume_boundary_call_effects: bool = False, **kwargs):
    """Run ``engine.analyze_observed_functions`` on named synthetic functions."""
    from tdo_v2.call_seeds import seed_function_calls, seed_tail_calls
    from tdo_v2.engine import analyze_observed_functions, assumed_boundary_effects
    from tdo_v2.integration.observed_function_session import ObservedFunctionEvidence

    builders = list(functions.values())
    names = {builder.entry: name for name, builder in functions.items()}
    with open_configured_extraction(
        _Provider(builders, layout), _mint_orchestrator_capability()
    ) as envelope:
        units = list(envelope.iter_scoped_functions())
    rows = []
    for unit in units:
        seeds = seed_function_calls(unit)
        tails = seed_tail_calls(unit)
        evidence = ObservedFunctionEvidence(
            unit, seeds, _naming_for(unit, seeds, names, tails), tails
        )
        normalized = FunctionNormalizer().normalize(
            unit,
            assumed_call_effects=(
                assumed_boundary_effects(evidence, provider)
                if assume_boundary_call_effects else None
            ),
        )
        if type(normalized) is not NormalizedFunction:
            raise AssertionError(f"normalization unresolved: {normalized!r}")
        rows.append((evidence, normalized))
    roots = analyze_observed_functions(tuple(rows), provider, **kwargs)
    by_entry = {builder.entry: name for name, builder in functions.items()}
    return {
        (by_entry[root.function_byte_offset], root.label): root for root in roots
    }


def analyze_summaries(functions, provider, *, names=None, layout: Layout = DEFAULT_LAYOUT, data: bytes = b"",
                      image: bool = False, **options):
    """The summary engine (``summary_engine.analyze_observed_with_summaries``)
    on synthetic functions: ``functions`` -- FunctionBuilders (bodies);
    ``names`` -- address -> symbol for call targets, bodies or not (opaque
    named sources / sinks need no body); ``image`` -- PE image facts and a
    read-only image (``synthetic_image``); the EngineRun (every root
    occurrence kept)."""
    from tdo_v2.summary_engine import analyze_observed_with_summaries

    inputs = summary_inputs(functions, names, layout=layout, data=data, image=image)
    return analyze_observed_with_summaries(inputs.program, inputs.evidences, image_info=inputs.image_info,
                                           readonly_image=inputs.readonly_image, boundary_provider=provider,
                                           **options)


def synthetic_image(layout: Layout = DEFAULT_LAYOUT, data: bytes = b"", imports=()):
    """(ImageInfo, ReadOnlyImage) describing the synthetic image as a PE x64
    image (docs 25.30 K2): .text = the code block (r-x), .rdata = the first
    half of the data block (r--, initialized), .data = the second half (rw-);
    the read-only image backed by the provider's bytes."""
    from tdo_v2.image_info import BlockPermissions, ImageInfo, ReadOnlyImage

    data = data or b"\x00" * layout.data_size
    half = layout.data_size // 2
    blocks = (
        BlockPermissions(RAM, layout.code_base, layout.code_size, ".text", True, False, True, False, True),
        BlockPermissions(RAM, layout.data_base, half, ".rdata", True, False, False, False, True),
        BlockPermissions(RAM, layout.data_base + half, layout.data_size - half, ".data", True, True, False, False, True),
    )
    info = ImageInfo("Portable Executable (PE)", blocks, tuple(imports), (), ())
    image = ReadOnlyImage.from_bytes(info, {
        (RAM, layout.code_base): b"\x90" * layout.code_size,
        (RAM, layout.data_base): data[:half],
        (RAM, layout.data_base + half): data[half:],
    })
    return info, image


@dataclass
class SummaryInputs:
    program: object
    evidences: list
    image_info: object
    readonly_image: object


def summary_inputs(functions, names=None, *, layout: Layout = DEFAULT_LAYOUT, data: bytes = b"", image: bool = True,
                   imports=()) -> SummaryInputs:
    """Admitted program, evidences (built as ``analyze_program`` builds them,
    never pre-normalized) and image facts for ``analyze_observed_with_summaries``."""
    from tdo_v2.call_seeds import seed_function_calls, seed_tail_calls
    from tdo_v2.integration.observed_function_session import ObservedFunctionEvidence

    names = dict(names or {})
    with open_configured_extraction(
        _Provider(list(functions), layout, data=data), _mint_orchestrator_capability()
    ) as envelope:
        program = envelope.program_result
        units = list(envelope.iter_scoped_functions())
    evidences = []
    for unit in units:
        seeds = seed_function_calls(unit)
        tails = seed_tail_calls(unit)
        evidences.append(ObservedFunctionEvidence(unit, seeds, _naming_for(unit, seeds, names, tails), tails))
    info, readonly = synthetic_image(layout, data, imports) if image else (None, None)
    return SummaryInputs(program, evidences, info, readonly)
