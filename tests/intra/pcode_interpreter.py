"""Concrete Low-Pcode interpreter used as an independent test oracle.

It executes a ``ValidatedFunctionObservation`` on concrete byte values and
records, for every executed operation, which earlier operation (or which
entry input) wrote each byte the operation read. The engine's graph must
cover every such dynamic dependency; ``tests/intra/test_graph_fidelity.py``
checks that.

Scope: call-free functions. CALL/CALLIND/CALLOTHER/BRANCHIND stop the run
(``Unsupported``). Unwritten registers and memory read as random but
consistent bytes owned by an ``Entry`` writer.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from tdo_v2._scope_contracts import VarnodeKindCode
from tdo_v2.call_seeds import _operation_key


class Unsupported(Exception):
    """The run reached an operation outside the oracle's call-free scope."""


@dataclass(frozen=True)
class Entry:
    """A byte nobody wrote during the run: the function's entry state."""

    space_id: int
    offset: int


@dataclass(frozen=True)
class Dependency:
    reader: str          # operation key
    space_id: int        # storage the reader read
    offset: int
    writer: object       # operation key (str) or Entry


@dataclass
class Run:
    executed: list[str] = field(default_factory=list)
    dependencies: set[Dependency] = field(default_factory=set)
    branch_decisions: list[tuple[str, bool]] = field(default_factory=list)
    completed: bool = False


_MASKS = {size: (1 << (8 * size)) - 1 for size in range(1, 17)}


def _signed(value: int, size: int) -> int:
    bits = 8 * size
    return value - (1 << bits) if value >> (bits - 1) & 1 else value


class Interpreter:
    def __init__(self, observation, *, constant_space: int, seed: int,
                 register_values: dict[int, int] | None = None,
                 max_steps: int = 4000, flip: str | None = None) -> None:
        self._instructions = {
            (row.address.space_id, row.address.byte_offset): row
            for row in observation.instructions
        }
        self._order = [
            (row.address.space_id, row.address.byte_offset) for row in observation.instructions
        ]
        self._constant_space = constant_space
        self._rng = random.Random(seed)
        self._bytes: dict[tuple[int, int], tuple[int, object]] = {}
        self._register_values = register_values or {}
        self._max_steps = max_steps
        self._flip = flip  # CBRANCH key whose first decision is inverted
        self._flipped = False

    # -- storage -------------------------------------------------------------
    def _byte(self, space_id: int, offset: int) -> tuple[int, object]:
        key = (space_id, offset)
        if key not in self._bytes:
            self._bytes[key] = (self._rng.randrange(256), Entry(space_id, offset))
        return self._bytes[key]

    def preset(self, space_id: int, offset: int, size: int, value: int) -> None:
        """Seed an entry value (little-endian) without making it a write."""
        for index in range(size):
            self._bytes[(space_id, offset + index)] = (
                (value >> (8 * index)) & 0xFF, Entry(space_id, offset + index)
            )

    def _read(self, reader: str, space_id: int, offset: int, size: int, run: Run) -> int:
        value = 0
        for index in range(size):
            byte, writer = self._byte(space_id, offset + index)
            run.dependencies.add(Dependency(reader, space_id, offset + index, writer))
            value |= byte << (8 * index)
        return value

    def _write(self, writer: str, space_id: int, offset: int, size: int, value: int) -> None:
        for index in range(size):
            self._bytes[(space_id, offset + index)] = ((value >> (8 * index)) & 0xFF, writer)

    def _value(self, reader: str, varnode, run: Run, *, data: bool = True) -> int:
        if varnode.kind is VarnodeKindCode.CONSTANT:
            return varnode.coordinate.byte_offset & _MASKS[varnode.byte_size]
        if not data:
            raise Unsupported("non-constant metadata operand")
        return self._read(reader, varnode.coordinate.space_id, varnode.coordinate.byte_offset,
                          varnode.byte_size, run)

    # -- execution -----------------------------------------------------------
    def run(self) -> Run:
        run = Run()
        location = self._order[0]
        steps = 0
        while True:
            instruction = self._instructions.get(location)
            if instruction is None:
                raise Unsupported(f"no instruction at {location}")
            next_location = (
                None if instruction.fallthrough is None
                else (instruction.fallthrough.space_id, instruction.fallthrough.byte_offset)
            )
            operations = instruction.operations
            index = 0
            while index < len(operations):
                steps += 1
                if steps > self._max_steps:
                    return run  # bounded: an incomplete run still yields valid dependencies
                operation = operations[index]
                key = _operation_key(instruction.address, index, operation.opcode)
                run.executed.append(key)
                jump = self._execute(key, operation, run)
                if jump is None:
                    index += 1
                    continue
                kind, target = jump
                if kind == "return":
                    run.completed = True
                    return run
                if kind == "relative":
                    index += target
                    if not 0 <= index <= len(operations):
                        raise Unsupported("relative branch leaves the instruction")
                    continue
                next_location = target
                break
            if next_location is None:
                raise Unsupported("fell off a terminal instruction")
            location = next_location

    def _execute(self, key: str, operation, run: Run):
        opcode = operation.opcode
        inputs = operation.inputs
        output = operation.output
        if opcode in ("CALL", "CALLIND", "CALLOTHER", "BRANCHIND"):
            raise Unsupported(opcode)
        if opcode == "RETURN":
            for item in inputs:
                self._value(key, item, run)
            return ("return", None)
        if opcode == "BRANCH":
            return self._destination(inputs[0])
        if opcode == "CBRANCH":
            taken = self._value(key, inputs[1], run) != 0
            if key == self._flip and not self._flipped:
                taken, self._flipped = not taken, True
            run.branch_decisions.append((key, taken))
            return self._destination(inputs[0]) if taken else None
        if opcode == "LOAD":
            space_id = inputs[0].coordinate.byte_offset
            address = self._value(key, inputs[1], run)
            value = self._read(key, space_id, address, output.byte_size, run)
            self._write(key, output.coordinate.space_id, output.coordinate.byte_offset,
                        output.byte_size, value)
            return None
        if opcode == "STORE":
            space_id = inputs[0].coordinate.byte_offset
            address = self._value(key, inputs[1], run)
            value = self._value(key, inputs[2], run)
            self._write(key, space_id, address, inputs[2].byte_size, value)
            return None
        values = [self._value(key, item, run) for item in inputs]
        result = self._compute(opcode, values, inputs, output)
        self._write(key, output.coordinate.space_id, output.coordinate.byte_offset,
                    output.byte_size, result & _MASKS[output.byte_size])
        return None

    def _destination(self, varnode):
        if varnode.kind is VarnodeKindCode.CONSTANT:
            return ("relative", _signed(varnode.coordinate.byte_offset, varnode.byte_size))
        return ("absolute", (varnode.coordinate.space_id, varnode.coordinate.byte_offset))

    @staticmethod
    def _compute(opcode, values, inputs, output) -> int:
        size = inputs[0].byte_size if inputs else output.byte_size
        a = values[0] if values else 0
        b = values[1] if len(values) > 1 else 0
        mask = _MASKS[size]
        if opcode == "COPY":
            return a
        if opcode == "INT_ADD":
            return a + b
        if opcode == "INT_SUB":
            return a - b
        if opcode == "INT_MULT":
            return a * b
        if opcode in ("INT_DIV", "INT_REM", "INT_SDIV", "INT_SREM"):
            if b == 0:
                raise Unsupported("division by zero")
            if opcode == "INT_DIV":
                return a // b
            if opcode == "INT_REM":
                return a % b
            sa, sb = _signed(a, size), _signed(b, size)
            quotient = abs(sa) // abs(sb) * (1 if (sa < 0) == (sb < 0) else -1)
            return quotient if opcode == "INT_SDIV" else sa - quotient * sb
        if opcode == "INT_AND":
            return a & b
        if opcode == "INT_OR":
            return a | b
        if opcode == "INT_XOR":
            return a ^ b
        if opcode == "INT_NEGATE":
            return ~a
        if opcode == "INT_2COMP":
            return -a
        if opcode == "INT_LEFT":
            return a << b if b < 8 * output.byte_size else 0
        if opcode == "INT_RIGHT":
            return a >> b
        if opcode == "INT_SRIGHT":
            return _signed(a, size) >> min(b, 8 * size)
        if opcode == "INT_ZEXT":
            return a
        if opcode == "INT_SEXT":
            return _signed(a, size)
        if opcode == "SUBPIECE":
            return a >> (8 * b)
        if opcode == "PIECE":
            return (a << (8 * inputs[1].byte_size)) | b
        if opcode == "POPCOUNT":
            return bin(a).count("1")
        if opcode == "INT_EQUAL":
            return int(a == b)
        if opcode == "INT_NOTEQUAL":
            return int(a != b)
        if opcode == "INT_LESS":
            return int(a < b)
        if opcode == "INT_LESSEQUAL":
            return int(a <= b)
        if opcode == "INT_SLESS":
            return int(_signed(a, size) < _signed(b, size))
        if opcode == "INT_SLESSEQUAL":
            return int(_signed(a, size) <= _signed(b, size))
        if opcode == "INT_CARRY":
            return int(a + b > mask)
        if opcode == "INT_SCARRY":
            total = _signed(a, size) + _signed(b, size)
            return int(not -(1 << (8 * size - 1)) <= total < (1 << (8 * size - 1)))
        if opcode == "INT_SBORROW":
            total = _signed(a, size) - _signed(b, size)
            return int(not -(1 << (8 * size - 1)) <= total < (1 << (8 * size - 1)))
        if opcode == "BOOL_NEGATE":
            return int(not a)
        if opcode == "BOOL_AND":
            return int(bool(a) and bool(b))
        if opcode == "BOOL_OR":
            return int(bool(a) or bool(b))
        if opcode == "BOOL_XOR":
            return int(bool(a) != bool(b))
        raise Unsupported(opcode)
