"""In-memory synthetic program provider for intrafunction engine tests.

Builds a ``ScopedFunctionUnit`` through the real scope envelope
(``open_configured_extraction``) without a Bundle on disk, so the tests run on
any platform (the Bundle admission path is POSIX-only).

Functions are written with ``FunctionBuilder``: one ``ins(...)`` call per
machine instruction, labels for branch targets, and x86-64 style helpers for
prologue/epilogue so that every function ends with the stack LOAD of the
return address, as real Ghidra output does.
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

# Ghidra x86-64 register offsets.
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = (
    0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38,
)
R8, R9 = 0x80, 0x88
RIP = 0x288
CF, PF, ZF, SF, OF = 0x200, 0x202, 0x206, 0x207, 0x20B

REGISTER_NAMES = {
    RAX: "RAX", RCX: "RCX", RDX: "RDX", RBX: "RBX", RSP: "RSP", RBP: "RBP",
    RSI: "RSI", RDI: "RDI", R8: "R8", R9: "R9", RIP: "RIP",
    CF: "CF", PF: "PF", ZF: "ZF", SF: "SF", OF: "OF",
}

CODE_BASE, CODE_SIZE = 0x1000, 0x1000
DATA_BASE, DATA_SIZE = 0x4000, 0x1000


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
    kind: str = "plain"          # plain | cbranch | branch | call | return
    target: str | None = None    # label for cbranch/branch
    condition: dict | None = None  # cbranch condition varnode
    call_target: int | None = None  # call destination address


@dataclass
class FunctionBuilder:
    entry: int = CODE_BASE
    stride: int = 4
    _rows: list[_Instruction] = field(default_factory=list)
    _labels: dict[str, int] = field(default_factory=dict)

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
        """x86-64 ``call imm``: push return address, then CALL."""
        index = len(self._rows)
        self._rows.append(_Instruction(
            [
                sub(reg(RSP), reg(RSP), const(8)),
                store(reg(RSP), const(self._address(index + 1))),
                op("CALL", [ram(target)]),
            ],
            "call",
            call_target=target,
        ))
        return self

    def branch(self, target: str) -> "FunctionBuilder":
        self._rows.append(_Instruction([], "branch", target))
        return self

    # -- x86-64 helpers ----------------------------------------------------
    def push(self, register: int) -> "FunctionBuilder":
        return self.ins(
            sub(reg(RSP), reg(RSP), const(8)),
            store(reg(RSP), reg(register)),
        )

    def pop(self, register: int) -> "FunctionBuilder":
        return self.ins(
            load(reg(register), reg(RSP)),
            add(reg(RSP), reg(RSP), const(8)),
        )

    def sub_rsp(self, amount: int) -> "FunctionBuilder":
        """``sub rsp, imm`` including Ghidra's flag writes."""
        return self.ins(
            op("INT_LESS", [reg(RSP), const(amount)], reg(CF, 1)),
            op("INT_SBORROW", [reg(RSP), const(amount)], reg(OF, 1)),
            sub(reg(RSP), reg(RSP), const(amount)),
            op("INT_SLESS", [reg(RSP), const(0)], reg(SF, 1)),
            op("INT_EQUAL", [reg(RSP), const(0)], reg(ZF, 1)),
        )

    def add_rsp(self, amount: int) -> "FunctionBuilder":
        return self.ins(
            op("INT_CARRY", [reg(RSP), const(amount)], reg(CF, 1)),
            op("INT_SCARRY", [reg(RSP), const(amount)], reg(OF, 1)),
            add(reg(RSP), reg(RSP), const(amount)),
            op("INT_SLESS", [reg(RSP), const(0)], reg(SF, 1)),
            op("INT_EQUAL", [reg(RSP), const(0)], reg(ZF, 1)),
        )

    def ret(self, *, realistic: bool = True) -> "FunctionBuilder":
        """x86-64 ``ret``: RIP = *(RSP); RSP += 8; RETURN RIP."""
        if realistic:
            ops = [
                load(reg(RIP), reg(RSP)),
                add(reg(RSP), reg(RSP), const(8)),
                op("RETURN", [reg(RIP)]),
            ]
        else:
            ops = [op("RETURN", [reg(RSP)])]
        self._rows.append(_Instruction(ops, "return"))
        return self

    # -- serialization -----------------------------------------------------
    def _address(self, index: int) -> int:
        return self.entry + index * self.stride

    def _coordinate(self, address: int) -> dict:
        return {"space_id": RAM, "byte_offset": address}

    def to_json(self) -> dict:
        if not self._rows or self._rows[-1].kind not in {"return", "branch"}:
            raise ValueError("function must end with ret() or branch()")
        rows = []
        for index, row in enumerate(self._rows):
            address = self._address(index)
            next_address = self._address(index + 1)
            ops = list(row.ops)
            targets: list[dict] = []
            fallthrough = row.kind in {"plain", "cbranch", "call"}
            if row.kind in {"cbranch", "branch"}:
                if row.target not in self._labels:
                    raise ValueError(f"unknown label {row.target}")
                target = self._address(self._labels[row.target])
                targets = [self._coordinate(target)]
                destination = ram(target)
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

def _space(space_id, *, const=False, reg=False, unique=False, mem=False):
    return {
        "space_id": space_id,
        "address_size_bits": 64,
        "addressable_unit_bytes": 1,
        "is_constant_space": const,
        "is_register_space": reg,
        "is_unique_space": unique,
        "is_memory_space": mem,
        "is_overlay_space": False,
        "is_external_space": False,
        "is_loaded_memory_space": mem,
        "is_non_loaded_memory_space": False,
        "has_signed_offset": False,
    }


@dataclass
class _Provider:
    functions: list[FunctionBuilder]
    code: bytes = field(default=b"\x90" * CODE_SIZE)
    data: bytes = field(default=b"\x00" * DATA_SIZE)

    def original_executable_size(self) -> int:
        return len(self.code) + len(self.data)

    def original_executable_chunks(self):
        yield PositionedChunk(0, self.code + self.data)

    def memory_descriptors(self):
        return (
            FrozenMemoryBlockDescriptor(
                "code", RAM, CODE_BASE, CODE_SIZE,
                True, True, False, False, False,
            ),
            FrozenMemoryBlockDescriptor(
                "data", RAM, DATA_BASE, DATA_SIZE,
                True, True, False, False, False,
            ),
        )

    def read_exact(self, handle, offset, length):
        source = self.code if handle == "code" else self.data
        yield PositionedChunk(offset, source[offset:offset + length])

    def snapshot_complete(self) -> bool:
        return True

    def spaces_complete(self) -> bool:
        return True

    def program_candidate(self):
        return parse_raw_json(json.dumps({
            "address_space_classification_revision": 2,
            "translation_namespace": {
                "language_id": "x86:LE:64:default",
                "major_version": 4,
                "minor_version": 6,
            },
            "address_spaces": [
                _space(CONST, const=True),
                _space(RAM, mem=True),
                _space(REG, reg=True),
                _space(UNIQUE, unique=True),
            ],
            "image_base": {"space_id": RAM, "byte_offset": CODE_BASE},
        }))

    def function_handles(self):
        return tuple(range(len(self.functions)))

    def observation_complete(self, handle) -> bool:
        return True

    def function_candidate(self, handle):
        return parse_raw_json(json.dumps(self.functions[handle].to_json()))

    def close(self) -> None:
        pass


def normalize_program(*functions: FunctionBuilder) -> list[NormalizedFunction]:
    """Normalize several functions of one program (distinct ``entry`` values)."""
    entries = [function.entry for function in functions]
    if len(set(entries)) != len(entries):
        raise ValueError("program functions need distinct entries")
    provider = _Provider(list(functions))
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


def normalize_with_observation(function: FunctionBuilder):
    """Return (NormalizedFunction, ValidatedFunctionObservation) for one function."""
    with open_configured_extraction(
        _Provider([function]), _mint_orchestrator_capability()
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


def slice_op(function: NormalizedFunction, opcode: str, index: int | None = None) -> Slice:
    """Slice from the only ``opcode`` operation, or the one in instruction ``index``."""
    seeds = operation_nodes(function, opcode)
    if index is not None:
        prefix = f"op:{RAM}:{CODE_BASE + index * 4:x}:"
        seeds = [node for node in seeds if function.dependencies.node(node).key.startswith(prefix)]
    (seed,) = seeds
    return slice_from(function, seed)


# --------------------------------------------------------------------------
# Whole-program (interprocedural) runs
# --------------------------------------------------------------------------

LANGUAGE = "x86:LE:64:default"


def _naming_for(unit, seeds, names: dict[int, str]):
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
    exporter = b"\x11" * 32
    return CapturedNamingSidecar(exporter, rows, naming_content_digest(exporter, rows))


def boundary(sources: dict[str, int] = (), sinks: dict[str, int] = ()):
    """SymbolBoundaryProvider: sources return in RAX bytes, sinks read RCX bytes."""
    from tdo_v2.boundary import BoundaryKind
    from tdo_v2.boundary_rules import BoundaryRule, SymbolBoundaryProvider
    from tdo_v2.physical_state import PhysicalRegisterSlice

    rules = [
        BoundaryRule(name, LANGUAGE, BoundaryKind.SOURCE, f"{name}.ret",
                     (PhysicalRegisterSlice(RAX, size),))
        for name, size in dict(sources).items()
    ] + [
        BoundaryRule(name, LANGUAGE, BoundaryKind.SINK, f"{name}.arg0",
                     (PhysicalRegisterSlice(RCX, size),))
        for name, size in dict(sinks).items()
    ]
    return SymbolBoundaryProvider(tuple(rules))


def analyze_program(functions: dict[str, FunctionBuilder], provider, **kwargs):
    """Run ``engine.analyze_observed_functions`` on named synthetic functions."""
    from tdo_v2.call_seeds import seed_function_calls
    from tdo_v2.engine import analyze_observed_functions
    from tdo_v2.integration.observed_function_session import ObservedFunctionEvidence

    builders = list(functions.values())
    names = {builder.entry: name for name, builder in functions.items()}
    with open_configured_extraction(
        _Provider(builders), _mint_orchestrator_capability()
    ) as envelope:
        units = list(envelope.iter_scoped_functions())
    rows = []
    for unit in units:
        normalized = FunctionNormalizer().normalize(unit)
        if type(normalized) is not NormalizedFunction:
            raise AssertionError(f"normalization unresolved: {normalized!r}")
        seeds = seed_function_calls(unit)
        rows.append((
            ObservedFunctionEvidence(unit, seeds, _naming_for(unit, seeds, names)),
            normalized,
        ))
    roots = analyze_observed_functions(tuple(rows), provider, **kwargs)
    by_entry = {builder.entry: name for name, builder in functions.items()}
    return {
        (by_entry[root.function_byte_offset], root.label): root for root in roots
    }
