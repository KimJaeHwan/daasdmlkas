"""The byte-lane oracle (docs section 25.6, B2a): concrete runs with per-byte
provenance against ``tdo_v2.lane_slice``.

``LaneInterpreter`` keeps, per byte, the set of inputs its value was computed
from: ("entry", space, offset) for a byte the function did not write before
reading it, ("call", call, space, offset) for a byte a call of the function
wrote itself, ("nested", call, space, offset) for a byte a call nested in the
callee activation of ``call`` wrote while that activation runs -- when ``call``
returns, every byte it left written is re-tagged ("call", call, space, offset)
at its current place (the callee may have moved it); one still "nested" is
unclassified. The exact byte maps are
the concrete semantics of the operations whose output byte i depends on a
known subset of input bytes (COPY / INT_NEGATE, LOAD and STORE with their
address bytes, SUBPIECE by a literal, PIECE, INT_ZEXT, INT_SEXT, INT_AND /
INT_OR / INT_XOR, ``x ^ x`` / ``x - x`` = 0); every other operation (and every
call) takes the union of all its inputs. These are p-code semantics, checked
against the interpreter's own arithmetic by the bit-flip table test.

``check_lanes(normalized, unit, observation)`` runs the function and, for
every executed operation with a register / temporary output and every byte
of that output, compares the byte's dynamic provenance with the lane slice
seeded at that byte of its definition: an entry register byte must be among
the reached register bytes; entry memory needs some entry memory input (or
an unknown-address debt) reached; a call result needs that call's node (or a
debt) reached. A missing element is "missing" when the lane slice reached no
debt at all, else "unclassified" (a debt that may or may not explain it --
counted, never a pass). The lane slice must also never reach a node the node
slice misses.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pcode_interpreter import Interpreter, Unsupported, _SELF_CANCELLING
from tdo_v2._scope_contracts import VarnodeKindCode
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.lane_slice import is_node_subset, lane_index, lane_slice, reached_bytes
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.span_geometry import ByteSpan, StorageObjectKind

_CALLS = ("CALL", "CALLIND", "CALLOTHER")
_CALL_RESULT = object()   # a write a call makes: tagged with the call and the byte


class _Lanes(dict):
    """Per-byte lanes; remembers, inside an outermost activation, each byte's
    lanes before the activation first changed them (``_lane_pre``)."""

    def __init__(self, owner):
        super().__init__()
        self._owner = owner

    def __setitem__(self, key, value):
        owner = self._owner
        if owner._activations and key not in owner._lane_pre:
            owner._lane_pre[key] = self.get(key)
        super().__setitem__(key, value)


class LaneInterpreter(Interpreter):
    def __init__(self, *args, **kwargs):
        self._lane_pre: dict = {}
        super().__init__(*args, **kwargs)
        self.lanes: dict = _Lanes(self)
        self.outputs: dict = {}      # op key -> [per-byte provenance tuple per execution]
        self._lane_scope = None      # the function's storage scope (relative object ids)
        self._lane_default = None
        self._heap_origin = self._heap   # blocks allocated during the run lie in [origin, self._heap)

    def _lane_at(self, space, offset):
        key = self._key(space, offset)
        found = self.lanes.get(key)
        return found if found is not None else frozenset({("entry", key[0], key[1])})

    def _operand(self, varnode):
        if varnode is None or varnode.kind is VarnodeKindCode.CONSTANT:
            return None
        return [self._lane_at(varnode.coordinate.space_id, varnode.coordinate.byte_offset + index)
                for index in range(varnode.byte_size)]

    def _quiet(self, varnode):
        if varnode.kind is VarnodeKindCode.CONSTANT:
            return varnode.coordinate.byte_offset
        return sum(self._byte(varnode.coordinate.space_id, varnode.coordinate.byte_offset + index)[0] << (8 * index)
                   for index in range(varnode.byte_size))

    def _caller_call(self, writer):
        """The call of the observed function a write belongs to."""
        return self._activations[0][1] if self._activations else writer

    def _call_tag(self, writer, key):
        # a call of the observed function writes its result register itself:
        # the byte is exact; a call nested in a callee activation writes a
        # coordinate of the activation, which the callee may move before it
        # returns -- only the outermost call is known
        if self._activations:
            return frozenset({("nested", self._caller_call(writer), key[0], key[1])})
        return frozenset({("call", writer, key[0], key[1])})

    def _write(self, writer, space_id, offset, size, value):
        super()._write(writer, space_id, offset, size, value)
        for index in range(size):
            key = self._key(space_id, offset + index)
            if self._lane_default is _CALL_RESULT or self._lane_default is None:
                tags = self._call_tag(writer, key)
            else:
                tags = self._lane_default
            self.lanes[key] = tags

    def _restore_identity_bytes(self):
        # a byte the activation restored to exactly its pre-call value by
        # provenance (a callee-saved register pushed and popped) keeps its
        # pre-call writer in the interpreter -- and its pre-call lanes here
        # (the push/pop path's stack address is not a source of the value)
        # (restored: its activation serial goes back to the pre-call one --
        # the writer text may be the same when one call site runs twice)
        before = {key: self._byte_activation.get(key) for key in self._activation_written}
        super()._restore_identity_bytes()
        for key, serial in before.items():
            if self._byte_activation.get(key) != serial and key in self._lane_pre:
                previous = self._lane_pre[key]
                if previous is None:
                    dict.pop(self.lanes, key, None)
                else:
                    dict.__setitem__(self.lanes, key, previous)

    def _record_footprint(self):
        # the outermost activation returned: a byte a nested call produced
        # and the activation left written is the outermost call's product at
        # the byte's current place -- the exact register-byte check applies
        super()._record_footprint()
        serial = self._activation_serial
        call = self.activation_snapshots[serial][0]
        for key in self.activation_writes.get(serial, ()):
            tags = self.lanes.get(key)
            if tags and any(tag[0] == "nested" for tag in tags):
                self.lanes[key] = frozenset(tag for tag in tags if tag[0] != "nested") | {("call", call, key[0], key[1])}
        self._lane_pre.clear()

    def _put(self, writer, space_id, offset, size, value, tags):
        super()._put(writer, space_id, offset, size, value, tags)
        for index in range(size):
            key = self._key(space_id, offset + index)
            self.lanes[key] = self._call_tag(writer, key)

    def _at_rep_site(self, key):
        parts = key.split(":")
        return (int(parts[0], 16), int(parts[1], 16)) in self._rep

    def _execute(self, key, operation, run):
        opcode, inputs, output = operation.opcode, operation.inputs, operation.output
        operands = [self._operand(varnode) for varnode in inputs]
        union = frozenset().union(*(tags for lanes in operands if lanes for tags in lanes))
        memory = None
        if opcode in ("LOAD", "STORE"):
            space = inputs[0].coordinate.byte_offset
            address = self._quiet(inputs[1])
            if opcode == "LOAD" and output is not None:
                memory = [self._lane_at(space, address + index) for index in range(output.byte_size)]
                union = union | frozenset().union(*memory)
        self._lane_default = _CALL_RESULT if opcode in _CALLS else union
        try:
            result = super()._execute(key, operation, run)
        finally:
            self._lane_default = None
        if opcode == "STORE":
            address_tags = frozenset().union(*operands[1]) if operands[1] else frozenset()
            written = []
            for index in range(inputs[2].byte_size):
                tags = (operands[2][index] if operands[2] else frozenset()) | address_tags
                self.lanes[self._key(space, address + index)] = tags
                written.append(tags)
            if not self._activations and not self._at_rep_site(key):
                self.outputs.setdefault(key, []).append(tuple(written))
            return result
        if output is None or opcode in _CALLS:
            return result
        lanes = _exact(opcode, inputs, output, operands, memory)
        if lanes is not None:
            for index, tags in enumerate(lanes):
                self.lanes[self._key(output.coordinate.space_id, output.coordinate.byte_offset + index)] = tags
        if self._activations or self._at_rep_site(key):
            # an operation of a callee activation (the same code may be this
            # function's own when it calls itself): its provenance is relative
            # to the activation, not to this function's entry; an operation of
            # a rep string site: the engine summarizes its iterations as one
            # block -- not compared per iteration
            return result
        produced = tuple(self._lane_at(output.coordinate.space_id, output.coordinate.byte_offset + index)
                         for index in range(output.byte_size))
        self.outputs.setdefault(key, []).append(produced)
        return result


def _exact(opcode, inputs, output, operands, memory):
    """Per output byte provenance for the exact ops (None: keep the union)."""
    size = output.byte_size
    empty = frozenset()
    if opcode in _SELF_CANCELLING and len(inputs) == 2 and inputs[0] == inputs[1]:
        return [empty] * size
    if opcode in ("COPY", "INT_NEGATE") and operands[0]:
        return [operands[0][index] if index < len(operands[0]) else empty for index in range(size)]
    if opcode == "LOAD" and memory is not None:
        address = frozenset().union(*operands[1]) if operands[1] else empty
        return [memory[index] | address for index in range(size)]
    if opcode == "SUBPIECE" and operands[0] and inputs[1].kind is VarnodeKindCode.CONSTANT:
        shift = inputs[1].coordinate.byte_offset
        return [operands[0][shift + index] if shift + index < len(operands[0]) else empty for index in range(size)]
    if opcode == "PIECE" and operands[0] is not None and operands[1] is not None:
        low = len(operands[1])
        return [operands[1][index] if index < low else operands[0][index - low] for index in range(size)]
    if opcode == "PIECE":
        return None
    if opcode == "INT_ZEXT" and operands[0]:
        return [operands[0][index] if index < len(operands[0]) else empty for index in range(size)]
    if opcode == "INT_SEXT" and operands[0]:
        top = operands[0][-1]
        return [operands[0][index] if index < len(operands[0]) else top for index in range(size)]
    if opcode in ("INT_AND", "INT_OR", "INT_XOR"):
        left = operands[0] or [empty] * size
        right = operands[1] or [empty] * size
        return [left[index] | right[index] for index in range(size)]
    return None


@dataclass
class LaneReport:
    runs: int = 0
    unsupported: int = 0
    seeds: int = 0
    checked: int = 0
    missing: list = field(default_factory=list)
    unclassified: int = 0
    nested: int = 0          # nested-call bytes left without a place (counted unclassified)
    not_subset: int = 0


def _output_definition(normalized, key, span):
    actions = {action.operation_key: action for action in normalized.memory_ssa.actions}
    action = actions.get(key)
    if action is None:
        return None
    for definition_id in action.write_definition_ids:
        if normalized.memory_ssa.definitions[definition_id].span == span:
            return normalized.memory_graph.definition_nodes[definition_id]
    return None


def check_lanes(normalized, unit, *, seeds=range(4), register_pools=None, const_space=0, havoc_calls=None,
                reg_space=2, unique_space=3, **interpreter_options) -> LaneReport:
    """``interpreter_options``: program / externals / image / no_effect_userops /
    address_bits, as ``Interpreter``."""
    from tdo_v2.model import ResolvedStorage
    from tdo_v2.normalize import _storage_ref
    from tdo_v2.storage import _resolve_validated_storage

    observation = unit.observation
    report = LaneReport()
    graph = normalized.dependencies
    context = unit.scopes.resolution_context
    keys = {}
    for instruction in observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            output = operation.output
            if output is None or output.kind not in (VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE):
                continue
            resolved = _resolve_validated_storage(_storage_ref(output), context)
            if type(resolved) is not ResolvedStorage:
                continue
            key = f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}:{ordinal}:{operation.opcode}"
            node = _output_definition(normalized, key, resolved.span)
            if node is not None:
                keys[key] = (node, resolved.span)
    # STORE destinations: the one projected definition a definite STORE writes
    actions = {action.operation_key: action for action in normalized.memory_ssa.actions}
    for instruction in observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            if operation.opcode != "STORE" or len(operation.inputs) < 3:
                continue
            key = f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}:{ordinal}:STORE"
            action = actions.get(key)
            if action is None or len(action.write_definition_ids) != 1:
                continue
            definition = normalized.memory_ssa.definitions[action.write_definition_ids[0]]
            if definition.kind is MemoryDefinitionKind.DATA_WRITE and definition.span.size == operation.inputs[2].byte_size:
                keys[key] = (normalized.memory_graph.definition_nodes[action.write_definition_ids[0]], definition.span)
    slices = {}
    walk_index = lane_index(normalized, unit)

    def lanes_for(node, span, index):
        if (node, index) not in slices:
            seed = [(node, (ByteSpan(span.object_id, span.start + index, 1),))]
            found = lane_slice(normalized, unit, seed, walk_index)
            if not is_node_subset(found, normalized, seed):
                report.not_subset += 1
            debts = any(graph.node(item).kind is NodeKind.MEMORY_DEBT for item in found.nodes)
            slices[(node, index)] = (reached_bytes(found, normalized), *_memory_and_calls(normalized, found), debts)
        return slices[(node, index)]

    register_object = next((span.object_id for span in (item[1] for item in keys.values())
                            if span.object_id.kind is StorageObjectKind.REGISTER_FILE), None)
    memory_spaces = sorted({operation.inputs[0].coordinate.byte_offset for row in observation.instructions
                            for operation in row.operations if operation.opcode in ("LOAD", "STORE")})
    for seed in seeds:
        interpreter = LaneInterpreter(observation, constant_space=const_space, seed=seed, havoc_calls=havoc_calls,
                                      **interpreter_options)
        interpreter._lane_scope = normalized.memory_ssa.function_scope
        for register, value in (register_pools(seed) if register_pools else {}).items():
            interpreter.preset(reg_space, register, 8, value)
        try:
            interpreter.run()
        except Unsupported:
            report.unsupported += 1
            continue
        report.runs += 1
        bases = _entry_bases(interpreter, register_object, reg_space, memory_spaces)
        for key, executions in sorted(interpreter.outputs.items()):
            if key not in keys or key.count(":") != 3:
                continue
            node, span = keys[key]
            report.seeds += 1
            for produced in executions:
                for index, tags in enumerate(produced):
                    registers, absolute, relative, call_bytes, call_memory, debts = lanes_for(node, span, index)
                    located, unlocated = _locate(relative, bases, interpreter)
                    for tag in tags:
                        report.checked += 1
                        uncertain = False
                        if tag[0] == "entry" and tag[1] == reg_space:
                            ok = tag[2] in registers
                        elif tag[0] == "entry" and tag[1] == unique_space:
                            ok = True   # a temporary read before any write: not an input the graph models
                        elif tag[0] == "entry":
                            # a global entry byte: exact; a relative one (no
                            # correspondence to an address): unclassified
                            ok = (tag[1], tag[2]) in absolute or (tag[1], tag[2]) in located
                            # a never-written byte of a block allocated during
                            # the run: the allocator call's content
                            uncertain = unlocated or interpreter._heap_origin <= tag[2] < interpreter._heap
                        elif tag[0] == "nested":
                            # produced by a call nested in the call tag[1] and
                            # not re-tagged when tag[1] returned (a byte the
                            # activation moved by a model): no exact place
                            report.nested += 1
                            ok, uncertain = False, True
                        elif tag[2] == reg_space:
                            # a register byte the call produced: one of its
                            # rows' definitions with that very byte demanded
                            ok = (tag[1], tag[3]) in call_bytes
                        else:
                            ok = False
                            uncertain = tag[1] in call_memory
                        if ok:
                            continue
                        if debts or uncertain:
                            report.unclassified += 1
                        else:
                            report.missing.append((key, index, tag))
    return report


def _entry_bases(interpreter, register_object, reg_space, spaces):
    """object id -> (space, base address) of the relative objects based on an
    entry register value (the engine's objects of a single entry atom)."""
    from tdo_v2.relative_memory import _function_relative_object_id

    found = {}
    if register_object is None:
        return found
    scope_box = interpreter._lane_scope
    if scope_box is None:
        return found
    for offset in range(0, 0x100, 8):
        values = [interpreter.entry_values.get((reg_space, offset + index)) for index in range(8)]
        if None in values:
            continue
        value = sum(byte << (8 * index) for index, byte in enumerate(values))
        anchor = ByteSpan(register_object, offset, 8)
        for space in spaces:
            found[_function_relative_object_id(scope_box, anchor, space)] = (space, value)
    return found


def _locate(relative, bases, interpreter):
    """({(space, address)} of relative entry bytes whose object is based on an
    entry register, whether any relative byte stays unlocated)."""
    located, unlocated = set(), False
    for object_id, offset in relative:
        base = bases.get(object_id)
        if base is None:
            unlocated = True
            continue
        space, value = base
        modulus = interpreter._moduli.get(space, 1 << 64)
        located.add((space, (value + offset - (1 << 64)) % modulus))
    return located, unlocated


def _memory_and_calls(normalized, found):
    """(absolute entry memory bytes {(space, address)} demanded -- global
    storage, relative entry memory bytes {(object, offset)} demanded, {(call, register byte)}
    demanded of definitions a call's rows wrote, {call} with a memory
    definition reached)."""
    from tdo_v2.lane_slice import FULL

    absolute, relative, call_bytes, call_memory = set(), set(), set(), set()
    for definition_id, node in enumerate(normalized.memory_graph.definition_nodes):
        if node not in found.demands:
            continue
        definition = normalized.memory_ssa.definitions[definition_id]
        span = definition.span
        demand = found.demands[node]
        wanted = range(span.start, span.end) if demand is FULL else [b for b in demand if span.start <= b < span.end]
        if definition.kind is MemoryDefinitionKind.ENTRY:
            if span.object_id.kind is StorageObjectKind.ADDRESS_SPACE:
                absolute.update((span.object_id.space_key, byte) for byte in wanted)
            elif span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE:
                relative.update((span.object_id, byte) for byte in wanted)
            continue
        writer = definition.operation_key or ""
        call = writer.split("~")[0]
        if writer.rsplit(":", 1)[-1].split("~")[0] not in _CALLS:
            continue
        if span.object_id.kind is StorageObjectKind.REGISTER_FILE:
            call_bytes.update((call, byte) for byte in wanted)
        else:
            call_memory.add(call)
    return absolute, relative, call_bytes, call_memory


def _entry_is_memory(normalized, node) -> bool:
    for definition_id, definition_node in enumerate(normalized.memory_graph.definition_nodes):
        if definition_node == node:
            definition = normalized.memory_ssa.definitions[definition_id]
            return definition.kind is MemoryDefinitionKind.ENTRY and definition.span.object_id.kind in (
                StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)
    return False
