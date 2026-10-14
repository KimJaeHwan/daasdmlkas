"""Concrete Low-Pcode interpreter used as an independent test oracle.

It executes a ``ValidatedFunctionObservation`` on concrete byte values and
records, for every executed operation, which earlier operation (or which
entry input) wrote each byte the operation read. The engine's graph must
cover every such dynamic dependency; ``tests/intra/test_graph_fidelity.py``
checks that.

Scope: by default call-free functions; CALL/CALLIND/CALLOTHER/BRANCHIND stop
the run (``Unsupported``). With ``havoc_calls`` a call instead overwrites
every register the function mentions (except the stack pointer) with random
bytes owned by the call operation, and pops the return address; its memory
effects are not modelled. Unwritten registers and memory read as random but
consistent bytes owned by an ``Entry`` writer.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field

from tdo_v2._scope_contracts import VarnodeKindCode
from tdo_v2.call_seeds import _operation_key


# x86 swi (user op 16): int 3 and int 0x29 never resume (models/pcodeops/x86.json)
_TRAP_USEROPS = {16: frozenset({3, 0x29})}
_SELF_CANCELLING = frozenset({"INT_XOR", "INT_SUB", "BOOL_XOR"})

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
    # program mode: (caller reader, space, offset) -> the caller-level inputs
    # ("ext", writer, space, offset, serial) a call activation computed that
    # byte from, over every execution of the reader (``serial``: the outermost
    # activation that last wrote that input byte, None for a caller byte)
    call_reads: dict = field(default_factory=dict)
    # program mode with ``sinks``: (outermost call key, frozenset of caller-level
    # inputs) per sink call executed inside an activation (its argument bytes)
    sink_reads: list = field(default_factory=list)
    # program mode: (caller reader, space, offset) -> {writer call key: serials
    # of its outermost activations whose write of that byte the reader read}
    reader_activations: dict = field(default_factory=dict)
    # program mode: (caller reader, space, offset) -> (space, offset) the byte
    # had when its writer wrote it (an allocator model moved it since: realloc)
    reader_moved: dict = field(default_factory=dict)


class _Masks(dict):
    """size -> all-ones mask of that many bytes (any width: SIMD registers too)."""

    def __missing__(self, size):
        self[size] = (1 << (8 * size)) - 1
        return self[size]


_MASKS = _Masks()


def _signed(value: int, size: int) -> int:
    bits = 8 * size
    return value - (1 << bits) if value >> (bits - 1) & 1 else value


class Interpreter:
    def __init__(self, observation, *, constant_space: int, seed: int,
                 register_values: dict[int, int] | None = None,
                 max_steps: int = 4000, flip: str | None = None,
                 havoc_calls: tuple[int, int, int] | None = None,
                 image=None, assumed_calls: dict | None = None,
                 track_provenance: bool = False, program: dict | None = None,
                 sinks: tuple | None = None, externals: dict | None = None,
                 no_effect_userops: frozenset = frozenset(), address_bits: dict | None = None) -> None:
        """``havoc_calls`` = (register space, stack pointer offset, stack pointer size).

        ``track_provenance``: also record, per byte, the set of entry inputs its
        value was computed from (all operands of every operation on the way,
        addresses included): ("reg", offset) for an entry register byte,
        ("mem", reader) for entry memory read by operation ``reader``,
        ("call", key) for a byte a havoced/declared call produced.
        ``final_bytes()`` returns them with the entry values (function summaries).

        ``program``: callee entry (space, offset) -> observation. A CALL to one
        of them is executed for real (call, return); every write made inside
        the activation is attributed to the outermost CALL of the observed
        function, and remembers which caller-level bytes it was computed from
        (``Run.call_reads``).

        ``sinks`` = (sink targets {(space, offset)}, argument register (offset,
        size) slices): a CALL to a sink target inside an activation records the
        caller-level inputs of its argument bytes (``Run.sink_reads``)."""
        self._sinks = sinks
        # ``externals``: call target (space, offset) -> C library function name,
        # executed with its real semantics (win64 arguments) instead of havoc:
        # the oracle for declared external models (``summary_store``)
        self._externals = dict(externals or {})
        # CALLOTHER indices with no data effect (models/pcodeops: x86 LOCK/UNLOCK)
        self._no_effect_userops = frozenset(no_effect_userops)
        self._heap = 0x6000_0000
        self._instructions = {
            (row.address.space_id, row.address.byte_offset): row
            for row in observation.instructions
        }
        self._program = dict(program or {})
        for callee in self._program.values():
            for row in callee.instructions:
                self._instructions.setdefault((row.address.space_id, row.address.byte_offset), row)
        # ``call [slot]`` (COPY t <- slot; CALLIND t): a key in ``externals``
        # may also be an import slot address
        self._external_callind = {}
        for row in self._instructions.values():
            for ordinal, operation in enumerate(row.operations):
                if operation.opcode != "CALLIND" or not operation.inputs:
                    continue
                for copy in row.operations[:ordinal]:
                    source = copy.inputs[0] if copy.inputs else None
                    if copy.opcode == "COPY" and copy.output == operation.inputs[0]                             and source.kind is VarnodeKindCode.ADDRESS                             and (source.coordinate.space_id, source.coordinate.byte_offset) in self._externals:
                        self._external_callind[_operation_key(row.address, ordinal, "CALLIND")] =                             self._externals[(source.coordinate.space_id, source.coordinate.byte_offset)]
        # rep movs/stos sites (``tdo_v2.rep_strings``): iteration i >= 1 of their
        # element LOAD/STORE is keyed ``<key>~e<i>``, as the engine names them
        from tdo_v2.rep_strings import recognize
        self._rep = {address: site for address, row in self._instructions.items()
                     if (site := recognize(row)) is not None}
        self._rep_iteration = 0
        self._previous_location = None
        self._activations: list = []          # (return location, call key)
        self._activation_written: set = set()
        self._activation_serial = 0            # of the current / last outermost activation
        self._byte_activation: dict = {}       # byte -> serial of the activation that last wrote it
        # outermost activation (program callee, or external run by the caller)
        # serial -> (call key, byte values at its start {(space, offset): byte};
        # a byte missing there was not touched before: ``entry_values``)
        self.activation_snapshots: dict = {}
        self._byte_inputs: list = []
        # inside an activation: byte -> the one caller byte (an "ext" tag) its
        # value is an exact copy of, through COPY / LOAD / STORE moves only
        # (an address is not part of the value) -- ``_restore_identity_bytes``
        self._copy_source: dict = {}
        self._byte_copies: list = []   # per byte read by the current operation
        self._value_start = None       # LOAD / STORE: index of the first value byte read
        self._blocks: dict = {}   # external heap: block address -> size
        self._free: list = []     # freed block addresses, reused by the next allocation  # bytes written in the current outermost activation
        self._call_bytes: set = set()          # bytes last written by some activation
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
        self._havoc = havoc_calls
        self._image = image  # (space, address) -> byte | None: loaded image contents
        # TEST-ONLY declared boundary calls: key -> (reads, writes) register slices
        self._assumed = assumed_calls or {}
        self.opaque_opcodes: set[str] = set()
        self._stack_snapshot: list = []
        self._track = track_provenance or bool(program)
        self.provenance: dict[tuple[int, int], frozenset] = {}
        self.entry_values: dict[tuple[int, int], int] = {}
        self._operation_inputs: set = set()
        self._stack_provenance: list = []
        self._registers = sorted({
            (varnode.coordinate.space_id, varnode.coordinate.byte_offset, varnode.byte_size)
            for row in observation.instructions
            for operation in row.operations
            for varnode in (*operation.inputs, operation.output)
            if varnode is not None and varnode.kind is VarnodeKindCode.REGISTER
        })
        kinds = {
            (varnode.coordinate.space_id, varnode.kind)
            for row in observation.instructions
            for operation in row.operations
            for varnode in (*operation.inputs, operation.output)
            if varnode is not None
        }
        self._register_spaces = {space for space, kind in kinds if kind is VarnodeKindCode.REGISTER}
        self._unique_spaces = {space for space, kind in kinds if kind is VarnodeKindCode.UNIQUE}
        # memory addresses wrap at the declared width of their space
        # (``address_bits``: space -> bits, the Bundle's address-space
        # evidence; 64 when not given): byte keys are taken modulo it. Every
        # LOAD / STORE space is a memory space.
        address_bits = dict(address_bits or {})
        self._moduli = {}
        for row in self._instructions.values():
            for operation in row.operations:
                if operation.opcode in ("LOAD", "STORE") and len(operation.inputs) >= 2:
                    space = operation.inputs[0].coordinate.byte_offset
                    self._moduli[space] = 1 << address_bits.get(space, 64)
        for space, bits in address_bits.items():
            self._moduli.setdefault(space, 1 << bits)
        # outermost activation serial -> the bytes it left written (its footprint;
        # a byte restored to its pre-call writer is not one)
        self.activation_writes: dict = {}
        # bytes an allocator model released (freed / moved-from: dead under the
        # model's assumption) or moved (realloc copies: the same object's
        # contents): not writes of a footprint
        self._model_moved: set = set()
        # outermost activation serial -> the lowest stack pointer value seen
        # while it ran (callee frames below its entry: not its footprint)
        self.activation_min_sp: dict = {}
        # byte -> its state before the current outermost activation first wrote
        # it (provenance, call byte, writing activation): restored with the writer
        # when the activation only copied the byte back (``_restore_identity_bytes``)
        self._pre_activation: dict = {}
        # byte -> the (space, offset) it was written at, for bytes an allocator
        # model moved (realloc); dropped when the byte is written again
        self._relocated: dict = {}

    def _key(self, space_id: int, offset: int) -> tuple[int, int]:
        modulus = self._moduli.get(space_id)
        return (space_id, offset % modulus) if modulus else (space_id, offset)

    # -- storage -------------------------------------------------------------
    def _byte(self, space_id: int, offset: int) -> tuple[int, object]:
        key = self._key(space_id, offset)
        if key not in self._bytes:
            byte = None if self._image is None else self._image(*key)
            if byte is None:
                byte = self._rng.randrange(256)
            self._bytes[key] = (byte, Entry(*key))
            self.entry_values[key] = byte
        return self._bytes[key]

    def _ext(self, writer, key) -> tuple:
        """The caller-level input tag of a byte read inside an activation."""
        serial = self._byte_activation.get(key) if key in self._call_bytes else None
        return ("ext", writer, key[0], key[1], serial)

    def preset(self, space_id: int, offset: int, size: int, value: int) -> None:
        """Seed an entry value (little-endian) without making it a write."""
        for index in range(size):
            self._bytes[(space_id, offset + index)] = (
                (value >> (8 * index)) & 0xFF, Entry(space_id, offset + index)
            )
            self.entry_values[(space_id, offset + index)] = (value >> (8 * index)) & 0xFF

    def _read(self, reader: str, space_id: int, offset: int, size: int, run: Run) -> int:
        value = 0
        for index in range(size):
            byte, writer = self._byte(space_id, offset + index)
            key = self._key(space_id, offset + index)
            if not self._activations and not getattr(self, "_rep_internal", False):
                # a read inside a call activation belongs to the callee (with
                # recursion, its operation keys are the caller's own)
                run.dependencies.add(Dependency(reader, key[0], key[1], writer))
            value |= byte << (8 * index)
            if self._activations:
                if key in self._activation_written:
                    found = self.provenance.get(key, frozenset())
                    self._byte_copies.append(self._copy_source.get(key))
                elif space_id not in self._unique_spaces:
                    tag = self._ext(writer, key)
                    found = frozenset({tag})
                    self._byte_copies.append(tag)
                else:
                    found = frozenset()
                    self._byte_copies.append(None)
                self._operation_inputs |= found
                self._byte_inputs.append(found)  # per byte, for COPY
                continue
            if key in self._call_bytes:
                place = (reader, key[0], key[1])
                run.call_reads[place] = run.call_reads.get(place, frozenset()) | self.provenance.get(key, frozenset())
                run.reader_activations.setdefault(place, {}).setdefault(writer, set()).add(
                    self._byte_activation.get(key))
                if key in self._relocated:
                    run.reader_moved[place] = self._relocated[key]
            if self._track:
                if isinstance(writer, Entry):
                    if space_id in self._register_spaces:
                        self._operation_inputs.add(("reg", key[1]))
                    elif space_id not in self._unique_spaces:
                        self._operation_inputs.add(("mem", reader))
                else:
                    self._operation_inputs |= self.provenance.get(key, frozenset())
        return value

    def _restore_identity_bytes(self) -> None:
        """After an outermost activation: a byte it wrote whose provenance is
        exactly its own pre-call value (a callee-saved register pushed and
        popped, ``mov edx, edx``) keeps its pre-call writer -- by provenance,
        never by an equal value."""
        for key in self._activation_written:
            tags = self.provenance.get(key, frozenset())
            copied = self._copy_source.get(key)
            if len(tags) == 1:
                (tag,) = tags
            elif copied is not None:
                tag = copied  # a push and pop through memory: exact by value moves
            else:
                continue
            if tag[0] == "ext" and (tag[2], tag[3]) == key and key in self._call_bytes:
                self._bytes[key] = (self._bytes[key][0], tag[1])
                provenance, call_byte, serial, moved = self._pre_activation.get(key, (None, False, None, None))
                if moved is not None:
                    self._relocated[key] = moved
                if provenance is None:
                    self.provenance.pop(key, None)
                else:
                    self.provenance[key] = provenance
                if call_byte:
                    self._call_bytes.add(key)
                else:
                    self._call_bytes.discard(key)
                if serial is None:
                    self._byte_activation.pop(key, None)
                else:
                    self._byte_activation[key] = serial

    def _write(self, writer: str, space_id: int, offset: int, size: int, value: int) -> None:
        inside = bool(self._activations)
        operation = writer
        if inside:
            writer = self._activations[0][1]  # attributed to the outermost call
        keys = [self._key(space_id, offset + index) for index in range(size)]
        for index, key in enumerate(keys):
            if inside and key not in self._activation_written:
                self._pre_activation[key] = (self.provenance.get(key), key in self._call_bytes,
                                             self._byte_activation.get(key), self._relocated.get(key))
            self._bytes[key] = ((value >> (8 * index)) & 0xFF, writer)
            self._model_moved.discard(key)
            self._relocated.pop(key, None)
            if inside:
                self._activation_written.add(key)
                self._call_bytes.add(key)
                self._byte_activation[key] = self._activation_serial
            else:
                self._call_bytes.discard(key)
        if inside:
            if operation.rsplit(":", 1)[-1] in ("CALL", "CALLIND", "CALLOTHER") or operation in self._assumed:
                tags = frozenset({("call", operation)})
            else:
                tags = frozenset(self._operation_inputs)
            # a COPY moves byte i to byte i: its provenance is byte-exact
            exact = operation.endswith(":COPY") and len(self._byte_inputs) == size
            for index, key in enumerate(keys):
                self.provenance[key] = self._byte_inputs[index] if exact else tags
            # value moves keep the exact copy source of each byte (not the address)
            start = 0 if operation.endswith(":COPY") else self._value_start
            moved = start is not None and len(self._byte_copies) - start == size and (
                operation.endswith((":COPY", ":LOAD", ":STORE")))
            for index, key in enumerate(keys):
                if moved and self._byte_copies[start + index] is not None:
                    self._copy_source[key] = self._byte_copies[start + index]
                else:
                    self._copy_source.pop(key, None)
            return
        if self._track:
            if writer.rsplit(":", 1)[-1] in ("CALL", "CALLIND", "CALLOTHER") or writer in self._assumed:
                tags = frozenset({("call", writer)})
            else:
                tags = frozenset(self._operation_inputs)
            for key in keys:
                self.provenance[key] = tags

    def final_bytes(self):
        """(space, offset) -> (value, writer, provenance) of every byte the run wrote."""
        return {
            key: (byte, writer, self.provenance.get(key, frozenset()))
            for key, (byte, writer) in self._bytes.items()
            if not isinstance(writer, Entry)
        }

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
                # control left the observed function (tail jump): the run ends here
                run.completed = True
                return run
            next_location = (
                None if instruction.fallthrough is None
                else (instruction.fallthrough.space_id, instruction.fallthrough.byte_offset)
            )
            operations = instruction.operations
            if self._activations and self._havoc is not None:
                self._note_stack_pointer()
            site = self._rep.get(location)
            self._rep_iteration = self._rep_iteration + 1 if site is not None and location == self._previous_location                 else 0
            self._previous_location = location
            if self._havoc is not None and any(
                op.opcode in ("CALL", "CALLIND") for op in operations
            ):
                # the callee's ret restores the stack pointer of this instruction's start
                space_id, sp_offset, sp_size = self._havoc
                self._stack_snapshot = [
                    self._byte(space_id, sp_offset + i) for i in range(sp_size)
                ]
                self._stack_provenance = [
                    self.provenance.get((space_id, sp_offset + i)) for i in range(sp_size)
                ]
            call = self._program_call(instruction)
            if call is not None:
                # the whole call instruction (stack-pointer adjustment and
                # return-address push included) belongs to the activation, as the
                # engine models the call shape
                if not self._activations:
                    self._activation_written = set()
                    self._pre_activation = {}
                    self._copy_source = {}
                    self._call_stack_pointer = self._stack_pointer_snapshot()
                    self._snapshot(call)   # retaken at the callee's entry (below)
                self._activations.append((next_location, call))
            index = 0
            while index < len(operations):
                steps += 1
                if steps > self._max_steps:
                    return run  # bounded: an incomplete run still yields valid dependencies
                operation = operations[index]
                key = _operation_key(instruction.address, index, operation.opcode)
                # iteration i >= 1 of a rep site: the element operations are the
                # engine's ``~e<i>`` rows; the other operations' register flow
                # between iterations is summarized by the block (their last
                # iteration's outputs are what later code reads)
                self._rep_internal = False
                if site is not None and self._rep_iteration:
                    if key in site.element_keys:
                        key = f"{key}~e{self._rep_iteration}"
                    else:
                        self._rep_internal = True
                run.executed.append(key)
                if self._sinks is not None and self._activations:
                    self._record_sink(operation, run)
                self._operation_inputs = set()
                self._byte_inputs = []
                self._byte_copies = []
                self._value_start = None
                jump = self._execute(key, operation, run)
                if jump is None:
                    index += 1
                    continue
                kind, target = jump
                if kind == "call":  # into a function of the program (activation pushed above)
                    if len(self._activations) == 1:
                        # the callee's entry state (return address pushed): what
                        # its summary's places are relative to
                        self._snapshot(self._activations[0][1], again=True)
                    next_location = target
                    break
                if kind == "halt":   # a software trap: execution does not continue
                    return run
                if kind == "return":
                    if self._activations:
                        next_location, _ = self._activations.pop()
                        if not self._activations:
                            self._restore_call_stack_pointer()
                            self._restore_identity_bytes()
                            self._record_footprint()
                        break
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
                if any(op.opcode in ("CALL", "CALLIND") for op in operations):
                    # a call that does not return (no fallthrough): the run ends here
                    run.completed = True
                    return run
                raise Unsupported("fell off a terminal instruction")
            location = next_location

    def _execute(self, key: str, operation, run: Run):
        opcode = operation.opcode
        inputs = operation.inputs
        output = operation.output
        if key in self._assumed and self._havoc is not None:
            space_id = self._havoc[0]
            reads, writes = self._assumed[key]
            for offset, size in reads:
                self._read(key, space_id, offset, size, run)
            for offset, size in writes:
                self._write(key, space_id, offset, size, self._rng.getrandbits(8 * size))
            if opcode in ("BRANCH", "CBRANCH", "BRANCHIND"):
                pass  # a declared tail-called boundary: the jump itself still happens
            else:
                for index, item in enumerate(self._stack_snapshot):
                    self._bytes[(space_id, self._havoc[1] + index)] = item
                    self._restore_provenance(space_id, self._havoc[1] + index, index)
                return None
        if opcode == "CALL" and self._program and inputs \
                and inputs[0].kind is VarnodeKindCode.ADDRESS:
            target = (inputs[0].coordinate.space_id, inputs[0].coordinate.byte_offset)
            if target in self._program:
                return ("call", target)
        if opcode == "CALLIND" and self._program and inputs and self._activations \
                and self._activations[-1][1] == key:
            # pushed by the run loop (``_program_call``): the target is a program function
            target = (self._order[0][0], self._value(key, inputs[0], run))
            if target in self._program:
                return ("call", target)
        if opcode == "CALL" and self._externals and inputs \
                and inputs[0].kind is VarnodeKindCode.ADDRESS \
                and (inputs[0].coordinate.space_id, inputs[0].coordinate.byte_offset) in self._externals:
            self._run_external(
                self._externals[(inputs[0].coordinate.space_id, inputs[0].coordinate.byte_offset)], key)
            return None
        if opcode == "CALLIND" and key in self._external_callind:
            self._run_external(self._external_callind[key], key)
            return None
        if opcode == "CALLOTHER" and len(inputs) == 2                 and all(item.kind is VarnodeKindCode.CONSTANT for item in inputs)                 and inputs[1].coordinate.byte_offset in _TRAP_USEROPS.get(inputs[0].coordinate.byte_offset, ()):
            return ("halt", None)  # int 3 / int 0x29 (debug-break-traps-do-not-return)
        if opcode == "CALLOTHER" and output is None and len(inputs) == 1                 and inputs[0].kind is VarnodeKindCode.CONSTANT                 and inputs[0].coordinate.byte_offset in self._no_effect_userops:
            return None
        if opcode in ("CALL", "CALLIND", "CALLOTHER") and self._havoc is not None:
            for item in inputs[1:] if opcode != "CALLOTHER" else inputs:
                if item.kind is not VarnodeKindCode.CONSTANT:
                    self._value(key, item, run)
            self._havoc_registers(key, pop_return=opcode != "CALLOTHER")
            if opcode == "CALLOTHER" and output is not None:
                self._write(key, output.coordinate.space_id, output.coordinate.byte_offset,
                            output.byte_size, self._rng.getrandbits(8 * output.byte_size))
            return None
        if opcode == "BRANCHIND" and self._externals and self._havoc is not None and inputs                 and inputs[0].kind is VarnodeKindCode.ADDRESS                 and (inputs[0].coordinate.space_id, inputs[0].coordinate.byte_offset) in self._externals:
            # jmp [__imp_X]: the external runs; its ret pops this function's
            # return address, returning to this function's caller
            space_id, sp_offset, sp_size = self._havoc
            current = sum(self._byte(space_id, sp_offset + i)[0] << (8 * i) for i in range(sp_size))
            after = (current + 8) & ((1 << (8 * sp_size)) - 1)
            self._stack_snapshot = [((after >> (8 * i)) & 0xFF, key) for i in range(sp_size)]
            self._stack_provenance = [None] * sp_size
            self._run_external(
                self._externals[(inputs[0].coordinate.space_id, inputs[0].coordinate.byte_offset)], key)
            return ("return", None)
        if opcode == "BRANCHIND":
            target = self._value(key, inputs[0], run)
            space_id = self._order[0][0]
            run.branch_decisions.append((key, target))  # a jump-table choice is a decision too
            return ("absolute", (space_id, target))
        if opcode in ("CALL", "CALLIND", "CALLOTHER"):
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
            self._value_start = len(self._byte_copies)
            value = self._read(key, space_id, address, output.byte_size, run)
            self._write(key, output.coordinate.space_id, output.coordinate.byte_offset,
                        output.byte_size, value)
            return None
        if opcode == "STORE":
            space_id = inputs[0].coordinate.byte_offset
            address = self._value(key, inputs[1], run)
            self._value_start = len(self._byte_copies)
            value = self._value(key, inputs[2], run)
            self._write(key, space_id, address, inputs[2].byte_size, value)
            return None
        if opcode in _SELF_CANCELLING and len(inputs) == 2 and inputs[0] == inputs[1]                 and output is not None:
            # x ^ x, x - x: zero whatever x holds -- no dependency (``normalize``)
            self._write(key, output.coordinate.space_id, output.coordinate.byte_offset, output.byte_size, 0)
            return None
        values = [self._value(key, item, run) for item in inputs]
        try:
            result = self._compute(opcode, values, inputs, output)
        except Unsupported:
            if output is None:
                raise
            # Semantics unknown to the oracle: any deterministic function of the
            # inputs preserves the dependency structure, which is all we check.
            self.opaque_opcodes.add(opcode)
            digest = hashlib.sha256(repr((opcode, values)).encode()).digest()
            result = int.from_bytes(digest, "little")
        self._write(key, output.coordinate.space_id, output.coordinate.byte_offset,
                    output.byte_size, result & _MASKS[output.byte_size])
        return None

    def _havoc_registers(self, key: str, *, pop_return: bool) -> None:
        space_id, sp_offset, sp_size = self._havoc
        stack = set(range(sp_offset, sp_offset + sp_size))
        for space, offset, size in self._registers:
            if space != space_id:
                continue
            for byte in range(offset, offset + size):
                if byte not in stack:
                    self._write(key, space, byte, 1, self._rng.randrange(256))
        if pop_return:
            for index, item in enumerate(self._stack_snapshot):
                self._bytes[(space_id, sp_offset + index)] = item
                self._restore_provenance(space_id, sp_offset + index, index)

    # -- external library functions (oracle for declared models) ---------------
    _WIN64_PRESERVED = {0x18, 0x28, 0x30, 0x38, 0xA0, 0xA8, 0xB0, 0xB8}

    def _peek(self, space_id, offset, size):
        value, tags = 0, set()
        for index in range(size):
            byte, writer = self._byte(space_id, offset + index)
            value |= byte << (8 * index)
            key = self._key(space_id, offset + index)
            if key in self._call_bytes and self._activations:
                tags |= self.provenance.get(key, frozenset())
            else:
                tags.add(self._ext(writer, key))
        return value, tags

    def _put(self, writer, space_id, offset, size, value, tags):
        if self._activations:  # inside a Bundle callee: attributed to the outermost call
            writer = self._activations[0][1]
        for index in range(size):
            key = self._key(space_id, offset + index)
            if self._activations and key not in self._activation_written:
                self._pre_activation[key] = (self.provenance.get(key), key in self._call_bytes,
                                             self._byte_activation.get(key), self._relocated.get(key))
            self._bytes[key] = ((value >> (8 * index)) & 0xFF, writer)
            self._model_moved.discard(key)
            self._relocated.pop(key, None)
            self._call_bytes.add(key)
            if self._activations:
                self._activation_written.add(key)
            self._byte_activation[key] = self._activation_serial
            self.provenance[key] = frozenset(tags)

    def _snapshot(self, call, again: bool = False) -> None:
        """A new outermost activation of ``call`` (or, ``again``, the current
        one at its callee's entry): its serial and the byte values then."""
        if not again:
            self._activation_serial += 1
        self.activation_snapshots[self._activation_serial] = (
            call, {key: byte for key, (byte, _) in self._bytes.items()})

    def _note_stack_pointer(self) -> None:
        space_id, sp_offset, sp_size = self._havoc
        value = sum(self._byte(space_id, sp_offset + index)[0] << (8 * index) for index in range(sp_size))
        serial = self._activation_serial
        self.activation_min_sp[serial] = min(self.activation_min_sp.get(serial, value), value)

    def _record_footprint(self) -> None:
        serial = self._activation_serial
        self.activation_writes[serial] = frozenset(
            key for key in self._call_bytes
            if self._byte_activation.get(key) == serial and key not in self._model_moved)

    def _run_external(self, name: str, key: str) -> None:
        outermost = not self._activations
        if outermost:
            self._snapshot(key)
        elif self._havoc is not None:
            # inside an activation: its CALL pushed a return address below the
            # stack pointer seen at the instruction's start
            self._note_stack_pointer()
        try:
            self._run_external_body(name, key)
        finally:
            if outermost:
                self._record_footprint()

    def _run_external_body(self, name: str, key: str) -> None:
        reg = self._havoc[0]
        memory = self._order[0][0]
        rcx, rcx_tags = self._peek(reg, 0x08, 8)
        rdx, rdx_tags = self._peek(reg, 0x10, 8)
        r8, r8_tags = self._peek(reg, 0x80, 8)
        result, result_tags = None, set()
        if name in ("memcpy", "memmove", "memset"):
            count = r8 if r8 <= 4096 else 0
            if name == "memset":
                values = [(rdx & 0xFF, rdx_tags) for _ in range(count)]
            else:
                values = [self._peek(memory, rdx + index, 1) for index in range(count)]
                values = [(value, tags | rdx_tags) for value, tags in values]
            for index, (value, tags) in enumerate(values):
                self._put(key, memory, rcx + index, 1, value, tags | rcx_tags | r8_tags)
            result, result_tags = rcx, rcx_tags
        elif name == "strcpy":
            # copies src up to and including its NUL (at most 4096 bytes)
            for index in range(4096):
                value, tags = self._peek(memory, rdx + index, 1)
                self._put(key, memory, rcx + index, 1, value, tags | rdx_tags | rcx_tags)
                if value == 0:
                    break
            result, result_tags = rcx, rcx_tags
        elif name == "strlen":
            length, tags = 0, set(rcx_tags)
            while length < 4096:
                byte, byte_tags = self._peek(memory, rcx + length, 1)
                tags |= byte_tags
                if byte == 0:
                    break
                length += 1
            result, result_tags = length, tags
        elif name in ("malloc", "FMemory::Malloc"):
            # a freed block's address is reused first (the models assume no use
            # after free: a stale pointer would now reach the new block)
            result, result_tags = (self._free.pop() if self._free else self._heap), set()
            if result == self._heap:
                self._heap += 0x1000
            self._blocks[result] = rcx
        elif name in ("realloc", "FMemory::Realloc"):
            # always moves: copies min(old, new) bytes to a new block; the old
            # block's bytes are havocked (the model assumes it is not used again)
            size = rdx if rdx <= 0x1000 else 0
            new = self._heap
            self._heap += 0x1000
            old = self._blocks.pop(rcx, 0) if rcx else 0
            for index in range(min(old, size)):  # a move: each byte keeps its writer
                source, target = self._key(memory, rcx + index), self._key(memory, new + index)
                self._bytes[target] = self._byte(*source)
                if source in self._call_bytes:
                    self._call_bytes.add(target)
                    self.provenance[target] = self.provenance.get(source, frozenset())
                if source in self._byte_activation:   # moved bytes keep their writing activation
                    self._byte_activation[target] = self._byte_activation[source]
                self._model_moved.add(target)
                self._relocated[target] = self._relocated.get(source, source)
                if source in self._activation_written:
                    self._activation_written.add(target)
            for index in range(old):
                self._put(key, memory, rcx + index, 1, self._rng.randrange(256), {("call", key)})
                self._model_moved.add(self._key(memory, rcx + index))
            self._blocks[new] = size
            result, result_tags = new, set()
        elif name in ("free", "FMemory::Free"):
            if rcx in self._blocks:
                del self._blocks[rcx]
                self._free.append(rcx)
        elif name in ("FDebug::CheckVerifyFailedImpl", "UE4Array_Private::OnInvalidArrayNum"):
            pass  # no program-visible memory; volatile registers havocked below
        elif name == "FMemory::QuantizeSize":
            result, result_tags = (rcx + 15) & ~15, rcx_tags | rdx_tags
        else:
            raise Unsupported(f"no oracle for external {name}")
        # every volatile register is changed (the model leaves them unknown)
        for space, offset, size in self._registers:
            if space != reg:
                continue
            for byte in range(offset, offset + size):
                base = byte - byte % 8 if byte < 0x100 else byte
                if base in self._WIN64_PRESERVED or 0x20 <= byte < 0x28:
                    continue
                self._put(key, reg, byte, 1, self._rng.randrange(256), {("call", key)})
        if result is not None:
            self._put(key, reg, 0, 8, result, result_tags)
        sp_space, sp_offset, sp_size = self._havoc  # the callee's ret pops the return address
        for index, item in enumerate(self._stack_snapshot):
            self._bytes[(sp_space, sp_offset + index)] = item
            self._restore_provenance(sp_space, sp_offset + index, index)

    def _record_sink(self, operation, run: Run) -> None:
        targets, arguments = self._sinks
        if operation.opcode != "CALL" or not operation.inputs                 or operation.inputs[0].kind is not VarnodeKindCode.ADDRESS:
            return
        target = (operation.inputs[0].coordinate.space_id, operation.inputs[0].coordinate.byte_offset)
        if target not in targets:
            return
        space_id = self._havoc[0]
        tags = set()
        for offset, size in arguments:
            for index in range(size):
                key = (space_id, offset + index)
                if key in self._activation_written:
                    tags |= self.provenance.get(key, frozenset())
                else:
                    tags.add(self._ext(self._byte(*key)[1], key))
        run.sink_reads.append((self._activations[0][1], frozenset(tags)))

    def _program_call(self, instruction):
        """Key of the CALL in ``instruction`` whose target is a program function."""
        if not self._program:
            return None
        for ordinal, operation in enumerate(instruction.operations):
            if operation.opcode == "CALL" and operation.inputs                     and operation.inputs[0].kind is VarnodeKindCode.ADDRESS:
                target = (operation.inputs[0].coordinate.space_id, operation.inputs[0].coordinate.byte_offset)
                if target in self._program:
                    return _operation_key(instruction.address, ordinal, operation.opcode)
            if operation.opcode == "CALLIND" and operation.inputs:
                target = self._indirect_target(instruction, ordinal)
                if target in self._program:
                    return _operation_key(instruction.address, ordinal, operation.opcode)
        return None

    def _indirect_target(self, instruction, ordinal):
        """``COPY t <- r; ...; CALLIND t`` (Ghidra's ``call r``): the program
        location r holds now (read without recording a dependency)."""
        operand = instruction.operations[ordinal].inputs[0]
        for operation in instruction.operations[:ordinal]:
            if operation.opcode == "COPY" and operation.output == operand \
                    and operation.inputs[0].kind is VarnodeKindCode.REGISTER:
                source = operation.inputs[0]
                value = 0
                for index in range(source.byte_size):
                    byte, _ = self._byte(source.coordinate.space_id, source.coordinate.byte_offset + index)
                    value |= byte << (8 * index)
                return (self._order[0][0], value)
        return None

    def _stack_pointer_snapshot(self):
        """The stack pointer at the start of the call instruction (before its
        return-address push), as captured by the run loop."""
        if self._havoc is None or not self._stack_snapshot:
            return None
        space_id, sp_offset, sp_size = self._havoc
        return [
            ((space_id, sp_offset + i), self._stack_snapshot[i],
             self._stack_provenance[i] if i < len(self._stack_provenance) else None)
            for i in range(sp_size)
        ]

    def _restore_call_stack_pointer(self) -> None:
        """The callee's ret restores the caller's stack pointer: when the value
        is back to the pre-call value, so is its definition (the call shape
        preserves it). A different value is left attributed to the call."""
        snapshot = getattr(self, "_call_stack_pointer", None)
        if not snapshot or any(self._bytes[key][0] != item[0] for key, item, _ in snapshot):
            return
        for key, item, tags in snapshot:
            self._bytes[key] = item
            self._call_bytes.discard(key)
            if tags is None:
                self.provenance.pop(key, None)
            else:
                self.provenance[key] = tags

    def _restore_provenance(self, space_id: int, offset: int, index: int) -> None:
        if not self._track:
            return
        tags = self._stack_provenance[index] if index < len(self._stack_provenance) else None
        if tags is None:
            self.provenance.pop((space_id, offset), None)
        else:
            self.provenance[(space_id, offset)] = tags

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
                raise Unsupported("division by zero")  # value-free fallback applies
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
