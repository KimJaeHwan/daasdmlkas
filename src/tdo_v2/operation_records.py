"""Operation records (docs 25.28): the p-code operations a value went through.

Diagnostics only: nothing here changes a result (labels, completeness,
summaries, templates, assumptions). A record is an expression graph over the
function's entry bytes, constants, call results and debts, built from the
normalized dependency graph:

* ``op`` -- one p-code operation (or a rep element ``~e<i>``): opcode, output,
  ``operands`` in p-code input order, each assembled from ``parts``
  (``{node, bytes: [a, b), at: [c, d)}``: bytes a..b of the producer's value
  placed at bytes c..d of the operand; several parts concatenate fragments of
  different definitions; ``{pruned: true, at}``: bytes no demanded result
  byte depends on). LOAD: operand 1 is the address, ``memory`` the loaded
  bytes per candidate place. A producer's value is its output (STORE: the
  stored value). ``debts``: debt nodes on the operation. ``override``: the
  operation the address evaluator sees instead after a proven rep string
  (``override`` node, the observed op kept as ``replaced``), or "unproven".
* ``const`` -- a constant operand.
* ``entry`` -- an entry span (register, or memory place).
* ``phi`` -- ALTERNATIVES: the value is one of these (a JOIN, an exit run's or
  a read fragment's several definitions, a definition with several writers);
  the SSA keeps no predecessor selection.
* ``call`` -- one output row of a summarized call (``~<i>`` / ``~sink<k>`` /
  ``~u<j>`` ...), its staging rows (``~in`` / ``~ld`` / ``~iu`` ...) folded
  into ``inputs`` with roles, and the call decision facts.
* ``debt`` -- a MEMORY_DEBT node: kind, site, predecessors (may-alias
  writers: their STORE nodes, address and value operands both).
* ``cut`` -- a node not expanded (limits or the demand budget), with the
  target and the reason; the record is then ``truncated``.

Stitching (docs 25.31 C-9, increment 1; only with a ``stitch`` context): after
the record is built, each ``call`` node of a register output whose effect is
a callee summary of this run gets ``stitched`` -- per output register span
the callee's own expression of those bytes: per callee exit an ``assemble``
of its runs' bytes (bytes an exit leaves unchanged: the caller's value at the
call), several exits a phi "callee exits" (alternatives: an overapproximation,
no path feasibility). The callee's entry registers are ``bound`` nodes: the
caller's values of those registers at the call (the call's ``~in`` read).
Imported nodes carry ``import`` (the call instance: call keys from the
root); a call not stitched carries ``stitch_cut`` (the reason). Imports never
change the caller's own nodes, ``truncated`` flag or evaluation (route
"injected": an import is ignored by ``eligibility`` / ``evaluate``).

``origins`` lists the source labels the engine attached to a node. Parts
reaching a node that is being expanded (a loop-carried value) are marked
``loop: true``. ``evaluate`` computes a record's value from concrete entry
values when it is eligible (no cut, loop, debt, rep element, unproven
override or unsupported operation): the set of values its alternatives allow.
"""

from __future__ import annotations

from .phases import measured

import sys
from dataclasses import dataclass

from .resource_limits import DiagnosticExhausted

from ._scope_contracts import VarnodeKindCode
from .graph_contracts import EdgeKind, NodeKind
from .memory_contracts import MemoryDefinitionKind
from .span_geometry import StorageObjectKind

RECORD_VERSION = 2   # (2: stitched calls, docs 25.31 C-9)
_MEMORY_OBJECTS = (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)
_DEBT_EDGES = frozenset({EdgeKind.UNRESOLVED_READ.value, EdgeKind.CALL_CLOBBER_READ.value,
                         EdgeKind.MAY_ALIAS_READ.value})
# staging rows of a summarized call, folded into its output rows
_STAGING = ("in", "ld", "iu", "ext", "sp", "cr", "cw", "ck", "sr")
# p-code inputs that are not data (``normalize._data_input_start``)
_META_INPUT = {"LOAD": "space", "STORE": "space", "CALL": "target", "CALLIND": "target",
               "CALLOTHER": "userop", "BRANCH": "target", "CBRANCH": "target"}
_X64_REGISTERS = {0x0: "rax", 0x8: "rcx", 0x10: "rdx", 0x18: "rbx", 0x20: "rsp", 0x28: "rbp", 0x30: "rsi",
                  0x38: "rdi", 0x80: "r8", 0x88: "r9", 0x90: "r10", 0x98: "r11", 0xA0: "r12", 0xA8: "r13",
                  0xB0: "r14", 0xB8: "r15", 0x288: "rip"}


@dataclass(frozen=True)
class Limits:
    nodes: int = 4000           # record nodes
    edges: int = 20000          # parts
    depth: int = 256            # expansion depth
    writers: int = 8            # writers kept per may-alias debt
    demand_steps: int = 200000  # the demand (lane) pass: worklist steps
    demand_bytes: int = 8000000  # ... and bytes it may materialize (charged per step)
    call_depth: int = 4         # stitched call levels (docs 25.31 C-9)


class _Truncated(Exception):
    pass


class _StitchCut(Exception):
    """One call instance not stitched (the reason)."""


class _Ledger:
    """What a record's builders share (the caller's and every stitched
    callee's): the edge count, the start of the innermost stitch attempt
    (records older than it are never changed by it) and whether an attempt
    ran out of a limit (no more attempts)."""

    def __init__(self):
        self.edges = 0
        self.frozen = 0
        self.exhausted = False


class StitchContext:
    """The run's analysis instances (``interprocedural._analyze_units``'
    ``record_provenance``: id(AnalyzedFunction) -> (it, CallProvenance)) and
    the callees' lane indexes, built once."""

    def __init__(self, table):
        self.table = table
        self.indices: dict = {}

    def provenance(self, analyzed):
        found = self.table.get(id(analyzed))
        return found[1] if found is not None and found[0] is analyzed else None

    def index(self, normalized, unit):
        found = self.indices.get(id(normalized))
        if found is None or found[0] is not normalized:
            from .lane_slice import lane_index

            found = self.indices[id(normalized)] = (normalized, lane_index(normalized, unit))
        return found[1]


class _Binding:
    """A stitched call instance's callee entry registers -> the caller's
    values at the call: the call's ``~in<k>`` reads (the caller register at
    the call is the callee's entry register, same offsets -- except the
    call shape's stack-pointer base, which the call changes: cut)."""

    def __init__(self, caller, reads, stack):
        self.caller, self.reads, self.stack = caller, reads, stack

    def parts(self, start, end):
        if start < self.stack[0] + self.stack[1] and self.stack[0] < end:
            raise _StitchCut("stack pointer")
        for read in self.reads:
            span = read.span
            if span.object_id.kind is StorageObjectKind.REGISTER_FILE and span.start <= start and end <= span.end:
                return _slice_parts(self.caller._fragments(read, None, 0), start - span.start, end - span.start)
        raise _StitchCut("unbound register")

    def bind(self, builder, node, span):
        """A ``bound`` node for a callee entry definition (the SSA may
        coalesce several registers into one): per byte range the caller's
        value, or a gap ("stack pointer" / "unbound register") -- an
        import using a gap byte is cut (``_gap_used``)."""
        if span.object_id.kind is not StorageObjectKind.REGISTER_FILE:
            raise _StitchCut("entry memory")
        classes = []
        for offset in range(span.start, span.end):
            if self.stack[0] <= offset < self.stack[0] + self.stack[1]:
                classes.append("stack pointer")
                continue
            read = next((read for read in self.reads if read.span.object_id.kind is StorageObjectKind.REGISTER_FILE
                         and read.span.start <= offset < read.span.end), None)
            classes.append("unbound register" if read is None else read)
        parts, gaps = [], []
        position = 0
        while position < len(classes):
            end = position
            while end < len(classes) and (classes[end] == classes[position] if isinstance(classes[position], str)
                                          else classes[end] is classes[position]):
                end += 1
            low, high = span.start + position, span.start + end
            found = classes[position]
            if isinstance(found, str):
                gaps.append({"at": [position, end], "reason": found})
            else:
                for piece in _slice_parts(self.caller._fragments(found, None, 0), low - found.span.start,
                                          high - found.span.start):
                    piece["at"] = [piece["at"][0] + position, piece["at"][1] + position]
                    parts.append(piece)
            position = end
        record = {"kind": "bound", "callee_entry": _span_text(span), "size": span.size, "parts": parts}
        if gaps:
            record["gaps"] = gaps
        return builder._new(node, record)["id"]


def _node_parts(node):
    """Every part a record node holds (whatever its kind)."""
    for name in ("alternatives", "parts", "root"):
        yield from node.get(name, ())
    for name in ("operands", "inputs", "memory", "reads"):
        for item in node.get(name, ()):
            yield from item.get("parts", ())


def _gap_used(records, start, outputs):
    """The reason of a ``bound`` gap byte an import (records from ``start``,
    and the stitched outputs) uses, or None."""
    for part in (*(part for record in records[start:] for part in _node_parts(record)),
                 *(item["part"] for item in outputs)):
        target = records[part["node"]] if "node" in part and part["node"] < len(records) else None
        if target is None or target["kind"] != "bound" or not target.get("gaps") or "bytes" not in part:
            continue
        a, b = part["bytes"]
        for gap in target["gaps"]:
            if a < gap["at"][1] and gap["at"][0] < b:
                return gap["reason"]
    return None


def _slice_parts(parts, low, high):
    """Bytes [low, high) of a value given as ``parts`` (placed by ``at``)."""
    found = []
    for part in parts:
        a, b = part["at"]
        start, end = max(a, low), min(b, high)
        if start >= end:
            continue
        piece = dict(part)
        if "bytes" in part:
            piece["bytes"] = [part["bytes"][0] + start - a, part["bytes"][0] + end - a]
        piece["at"] = [start - low, end - low]
        found.append(piece)
    return found


class _Builder:
    def __init__(self, normalized, unit, *, origins=None, declared=None, limits=None, demands=None,
                 provenance=None, stitch=None, records=None, ledger=None, parent=None, binding=None, path=(),
                 index=None):
        from .lane_slice import lane_index

        self.normalized = normalized
        self.unit = unit
        self.index = index if index is not None else lane_index(normalized, unit)
        self.graph = normalized.dependencies
        self.ssa = normalized.memory_ssa
        self.limits = limits or Limits()
        self.origins = {node: sorted(labels) for node, labels in (origins or {}).items()}
        self.declared = dict(declared or {})
        self.provenance = provenance   # interprocedural.CallProvenance of this instance, or None
        self.proven = dict(normalized.proven_call_effects)
        self.value_inputs = dict(normalized.call_value_inputs)
        self.overrides = dict(normalized.operation_overrides)
        self.rep_blocks = {row[0] for row in normalized.rep_blocks}
        self.objects = dict(normalized.address_objects)
        self.atoms = dict(normalized.address_atoms)
        self.effects = {effect.operation_key: effect for effect in normalized.effects}
        self.debt_rows = {}
        for rows, nodes in ((normalized.call_clobber_reads, normalized.call_clobber_nodes),
                            (normalized.may_alias_reads, normalized.may_alias_nodes)):
            for row, node in zip(rows, nodes):
                self.debt_rows[node] = row
        self.records: list = records if records is not None else []
        self.id_of: dict = {}
        self.expanding: set = set()
        self.ledger = ledger or _Ledger()
        self.truncated = False
        # stitching (docs 25.31 C-9): the run's instances, the caller builder,
        # its binding of this callee's entry registers, the call path
        # ((function key, call key) from the root) and this builder's calls
        self.stitch, self.parent, self.binding, self.path = stitch, parent, binding, path
        self.call_ids: list = []
        self._actions = None
        self._transitions = None
        entry = unit.scopes.function.entry
        self.function_key = f"{entry.space_id:x}:{entry.byte_offset:x}"
        self.demands = demands
        self.register_space = _register_space(unit)
        evidence = unit.scopes.program.evidence
        self.address_bits = {row.space_id: row.address_size_bits for row in evidence.address_spaces
                             if row.is_memory_space}
        self.x64 = evidence.translation_namespace.language_id.startswith("x86:LE:64")

    # -- nodes ---------------------------------------------------------------
    _FIELDS = {"op": ("operands",), "override": ("operands",), "call": ("inputs",), "phi": ("alternatives",),
               "debt": ("from",)}

    def _new(self, key, record):
        if len(self.records) >= self.limits.nodes:
            self.truncated = True
            raise _Truncated()
        for name in self._FIELDS.get(record["kind"], ()):
            record.setdefault(name, [])
        if record["kind"] in self._FIELDS:
            # cleared by ``_done``: a node a limit interrupted keeps the mark
            record["interrupted"] = True
        record["id"] = len(self.records)
        self.records.append(record)
        if key is not None:
            self.id_of[key] = record["id"]
        return record

    def _done(self, record):
        record.pop("interrupted", None)

    def _cut(self, target, reason, demand=None):
        self.truncated = True
        if len(self.records) >= self.limits.nodes + 64:
            return self.records[-1]["id"]   # (the cuts themselves are bounded too)
        record = {"kind": "cut", "target": target, "reason": reason}
        if demand is not None:
            record["demand"] = demand
        record["id"] = len(self.records)
        self.records.append(record)
        return record["id"]

    def _with_origins(self, record, *nodes):
        if record["id"] < self.ledger.frozen:
            return   # (a record older than the stitch attempt: unchanged)
        labels = sorted({label for node in nodes for label in self.origins.get(node, ())})
        if labels:
            record["origins"] = sorted(set(record.get("origins", ())) | set(labels))

    def _demand(self, node):
        if self.demands is None:
            return None
        found = self.demands.demands.get(node, "missing")
        return found

    # -- definitions (transparent: a part names the producer) ------------------
    def definition(self, node, depth):
        """(record id, base offset of the definition in its producer's value,
        loop flag) of a definition node."""
        definition_id = self.index.definition_of[node]
        definition = self.ssa.definitions[definition_id]
        loop = node in self.expanding
        if definition.kind is MemoryDefinitionKind.ENTRY:
            return self._entry(node, definition), 0, False
        if definition.kind is MemoryDefinitionKind.JOIN:
            return self._phi_join(node, definition_id, definition, depth), 0, loop
        writers = [source for source, _, record in self.graph.in_edges(node)
                   if record.kind == EdgeKind.MEMORY_DEFINES.value]
        if len(writers) == 1:
            writer = writers[0]
            loop = writer in self.expanding
            producer = self.operation(writer, depth)
            self._with_origins(self.records[producer], node)
            return producer, self._base(producer, definition), loop
        key = ("writers", node)
        if key in self.id_of:
            return self.id_of[key], 0, loop
        record = self._new(key, {"kind": "phi", "reason": "several writers", "span": _span_text(definition.span),
                                 "size": definition.span.size, "alternatives": []})
        self.expanding.add(node)
        try:
            for writer in writers:
                writer_loop = writer in self.expanding
                producer = self.operation(writer, depth + 1)
                base = self._base(producer, definition)
                record["alternatives"].append(self._named({"node": producer, "loop": writer_loop,
                                                           "bytes": [base, base + definition.span.size],
                                                           "at": [0, definition.span.size]}, definition))
                self._edge()
        finally:
            self.expanding.discard(node)
        self._done(record)
        return record["id"], 0, loop

    def _base(self, producer, definition):
        """Where ``definition``'s bytes start in its producer's value (an op's
        output; a STORE / call / other producer: the definition itself)."""
        record = self.records[producer]
        output = record.get("output")
        if record["kind"] == "op" and output is not None and output.get("start") is not None \
                and output.get("object") == _object_text(definition.span) and record["opcode"] != "STORE":
            return definition.span.start - output["start"]
        return 0

    def _named(self, part, definition):
        """A part of a call output names the definition (the output) it is:
        one call row may write several registers, all with base 0."""
        if self.records[part["node"]]["kind"] == "call":
            part["output"] = _span_dict(definition.span)
        return part

    def _entry(self, node, definition):
        if node in self.id_of:
            return self.id_of[node]
        if self.binding is not None:   # a stitched callee: the caller's value at the call
            return self.binding.bind(self, node, definition.span)
        span = definition.span
        record = {"kind": "entry", "span": _span_text(span)}
        if span.object_id.kind is StorageObjectKind.REGISTER_FILE:
            record["register"] = {"space": self.register_space, "offset": span.start, "size": span.size}
            if self.x64:
                record["x64"] = True
        elif span.object_id.kind is StorageObjectKind.ADDRESS_SPACE:
            record["absolute"] = {"space": span.object_id.space_key, "address": span.start, "size": span.size}
        elif span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE:
            record["place"] = self._place(span)
        record = self._new(node, record)
        self._with_origins(record, node)
        return record["id"]

    def _place(self, span):
        found = self.objects.get(span.object_id)
        if found is None:
            return {"object": _object_text(span), "start": span.start, "size": span.size}
        atoms, space_id = found
        bits = self.address_bits.get(space_id, 64)
        terms = [f"{coefficient}*{self.atoms.get(atom, f'atom#{atom & 0xffffffff:08x}')}"
                 if coefficient != 1 else str(self.atoms.get(atom, f"atom#{atom & 0xffffffff:08x}"))
                 for atom, coefficient in atoms]
        displacement = span.start - (1 << bits)
        return {"space": space_id, "base": " + ".join(terms) or "0", "displacement": displacement,
                "size": span.size}

    def _phi_join(self, node, definition_id, definition, depth):
        if node in self.id_of:
            return self.id_of[node]
        record = self._new(node, {"kind": "phi", "reason": "join", "span": _span_text(definition.span),
                                  "size": definition.span.size, "alternatives": []})
        self.expanding.add(node)
        try:
            for source_id in self.index.joins.get(definition_id, ()):
                source = self.index.definition_node[source_id]
                source_definition = self.ssa.definitions[source_id]
                produced, base, loop = self._definition_guarded(source, depth + 1)
                start = max(source_definition.span.start, definition.span.start) \
                    if source_definition.span.object_id == definition.span.object_id else definition.span.start
                end = min(source_definition.span.end, definition.span.end) \
                    if source_definition.span.object_id == definition.span.object_id else definition.span.end
                record["alternatives"].append(self._named({
                    "node": produced, "loop": loop or source in self.expanding,
                    "bytes": [base + start - source_definition.span.start, base + end - source_definition.span.start],
                    "at": [start - definition.span.start, end - definition.span.start],
                    "defined_by": source_definition.operation_key or source_definition.block_key,
                }, source_definition))
                self._edge()
        finally:
            self.expanding.discard(node)
        self._done(record)
        return record["id"]

    def _definition_guarded(self, node, depth):
        if depth > self.limits.depth:
            return self._cut(self.graph.node(node).key, "depth"), 0, False
        if self._unexplored(node):
            return self._cut(self.graph.node(node).key, "demand budget", self._demand_text(node)), 0, False
        return self.definition(node, depth)

    def _unexplored(self, node):
        """The demand pass ran out before this node was processed (or reached)."""
        return self.demands is not None and self.demands.exhausted and (
            node in self.demands.frontier or node not in self.demands.demands)

    def _demand_text(self, node):
        found = None if self.demands is None else self.demands.demands.get(node, "none")
        return "full" if found is None else found if found == "none" else sorted(found)

    def _edge(self):
        self.ledger.edges += 1
        if self.ledger.edges > self.limits.edges:
            self.truncated = True
            raise _Truncated()

    # -- operations ----------------------------------------------------------
    def operation(self, node, depth):
        if node in self.id_of:
            return self.id_of[node]
        if depth > self.limits.depth:
            return self._cut(self.graph.node(node).key, "depth")
        if self._unexplored(node):
            return self._cut(self.graph.node(node).key, "demand budget", self._demand_text(node))
        record_node = self.graph.node(node)
        if record_node.kind is NodeKind.MEMORY_DEBT:
            return self._debt(node, depth)
        if record_node.kind is not NodeKind.OPERATION:
            record = self._new(node, {"kind": "node", "node_kind": record_node.kind.value, "key": record_node.key})
            return record["id"]
        key = record_node.key[len("op:"):]
        base, _, tag = key.partition("~")
        if tag and base in self.proven:
            return self._call(node, key, base, tag, depth)
        if tag.startswith("e") and tag[1:].isdigit():
            return self._rep_element(node, key, base, int(tag[1:]), depth)
        return self._op(node, key, depth)

    def _op(self, node, key, depth):
        action_id = self.index.action_of.get(node)
        found = None if action_id is None else self.index.operation(action_id)
        record = self._new(node, {"kind": "op", "key": key, "opcode": self.graph.node(node).label})
        _, address, ordinal = _key_parts(key)
        record["address"], record["ordinal"] = address, ordinal
        self._with_origins(record, node)
        self.expanding.add(node)
        try:
            if found is None:
                record["operands"] = []
                record["reads"] = self._all_reads(action_id, depth)
            else:
                operation, spans, output = found
                record["opcode"] = operation.opcode
                if output is not None:
                    record["output"] = _span_dict(output)
                elif operation.output is not None:
                    record["output"] = {"size": operation.output.byte_size}
                record["operands"] = self._operands(node, action_id, operation, spans, depth)
                if operation.opcode == "LOAD":
                    record["memory"] = self._loaded(node, action_id, spans, depth)
                    record["space"] = operation.inputs[0].coordinate.byte_offset
                if operation.opcode == "STORE":
                    record["space"] = operation.inputs[0].coordinate.byte_offset
                    record["writes"] = [_span_text(self.ssa.definitions[item].span)
                                        for item in self.ssa.actions[action_id].write_definition_ids] \
                        if action_id is not None else []
                if operation.opcode in ("INT_XOR", "INT_SUB", "BOOL_XOR") and action_id is not None \
                        and not self.index.reads.get(action_id) and len(operation.inputs) == 2 \
                        and operation.inputs[0] == operation.inputs[1]:
                    record["value"] = 0   # self-cancelling: the engine reads nothing
            override = self.overrides.get(key, "absent")
            if override != "absent":
                instruction = ":".join(key.split(":")[:2])
                if override is None or instruction not in self.rep_blocks:
                    record["override"] = "unproven"
                else:
                    record["override"] = self._override(node, action_id, override, found, depth)
            debts = self._debts(node, depth)
            if debts:
                record["debts"] = debts
        finally:
            self.expanding.discard(node)
        self._done(record)
        return record["id"]

    def _override(self, node, action_id, operation, found, depth):
        record = self._new(None, {"kind": "override", "opcode": operation.opcode,
                                  "reason": "proven rep string", "replaced": self.id_of[node]})
        if operation.output is not None:
            record["output"] = {"size": operation.output.byte_size}
        operands = []
        for position, varnode in enumerate(operation.inputs):
            if varnode.kind is VarnodeKindCode.CONSTANT:
                operands.append(self._constant_operand(position, varnode))
                continue
            from .model import ResolvedStorage
            from .normalize import _storage_ref
            from .storage import _resolve_validated_storage

            resolved = _resolve_validated_storage(_storage_ref(varnode), self.unit.scopes.resolution_context)
            span = resolved.span if type(resolved) is ResolvedStorage else None
            reads = [read for read in self.index.reads.get(action_id, ()) if read.span == span]
            if not reads:
                operands.append({"index": position, "width": varnode.byte_size, "role": "value",
                                 "parts": [], "unresolved": True})
                continue
            operands.append({"index": position, "width": varnode.byte_size, "role": "value",
                             "parts": self._fragments(reads[0], None, depth)})
        record["operands"] = operands
        self._done(record)
        return record["id"]

    def _constant_operand(self, position, varnode, role="value"):
        key = ("const", varnode.coordinate.byte_offset, varnode.byte_size)
        if key in self.id_of:
            identifier = self.id_of[key]
        else:
            identifier = self._new(key, {"kind": "const", "value": varnode.coordinate.byte_offset,
                                         "size": varnode.byte_size})["id"]
        self._edge()
        return {"index": position, "width": varnode.byte_size, "role": role,
                "parts": [{"node": identifier, "bytes": [0, varnode.byte_size], "at": [0, varnode.byte_size]}]}

    def _operands(self, node, action_id, operation, spans, depth):
        from .lane_slice import FULL, _operand_demands

        demand = self._demand(node)
        found = self.index.operation(action_id) if action_id is not None else None
        operand_demands = None
        if demand not in (None, "missing", FULL) and found is not None and self.index.little:
            operand_demands = _operand_demands(found, demand)
        reads = self.index.reads.get(action_id, ()) if action_id is not None else ()
        operands = []
        for position, varnode in enumerate(operation.inputs):
            meta = _META_INPUT.get(operation.opcode)
            if position == 0 and meta is not None:
                operands.append({"index": 0, "width": varnode.byte_size, "role": meta,
                                 "value": varnode.coordinate.byte_offset})
                continue
            role = "address" if operation.opcode in ("LOAD", "STORE") and position == 1 else "value"
            if varnode.kind is VarnodeKindCode.CONSTANT:
                operands.append(self._constant_operand(position, varnode, role))
                continue
            span = spans[position] if position < len(spans) else None
            wanted = None
            if operand_demands is not None:
                wanted = operand_demands.get(position, frozenset())
                if not wanted:
                    operands.append({"index": position, "width": varnode.byte_size, "role": role,
                                     "pruned": True})
                    continue
            matching = [read for read in reads if span is not None and read.span == span]
            if not matching:
                operands.append({"index": position, "width": varnode.byte_size, "role": role, "parts": [],
                                 "unresolved": True})
                continue
            operands.append({"index": position, "width": varnode.byte_size, "role": role,
                             "parts": self._fragments(matching[0], wanted, depth)})
        return operands

    def _fragments(self, read, wanted, depth):
        """Parts of one read: each fragment's bytes from its definition(s)."""
        parts = []
        for fragment in read.fragments:
            offsets = range(fragment.span.start - read.span.start, fragment.span.end - read.span.start)
            if wanted is not None and not any(offset in wanted for offset in offsets):
                parts.append({"pruned": True, "at": [offsets.start, offsets.stop]})
                continue
            if len(fragment.definition_ids) == 1:
                source = self.index.definition_node[fragment.definition_ids[0]]
                produced, base, loop = self._definition_guarded(source, depth + 1)
                definition = self.ssa.definitions[fragment.definition_ids[0]]
                start = fragment.span.start - definition.span.start + base
                part = self._named({"node": produced, "bytes": [start, start + fragment.span.size],
                                    "at": [offsets.start, offsets.stop]}, definition)
                if loop:
                    part["loop"] = True
            else:
                part = {"node": self._fragment_phi(fragment, depth), "bytes": [0, fragment.span.size],
                        "at": [offsets.start, offsets.stop]}
            self._edge()
            parts.append(part)
        return parts

    def _fragment_phi(self, fragment, depth):
        key = ("fragment", fragment.span, tuple(fragment.definition_ids))
        if key in self.id_of:
            return self.id_of[key]
        record = self._new(key, {"kind": "phi", "reason": "several definitions", "span": _span_text(fragment.span),
                                 "size": fragment.span.size, "alternatives": []})
        for definition_id in fragment.definition_ids:
            source = self.index.definition_node[definition_id]
            produced, base, loop = self._definition_guarded(source, depth + 1)
            definition = self.ssa.definitions[definition_id]
            start = fragment.span.start - definition.span.start + base
            record["alternatives"].append(self._named({"node": produced, "loop": loop,
                                                       "bytes": [start, start + fragment.span.size],
                                                       "at": [0, fragment.span.size]}, definition))
            self._edge()
        self._done(record)
        return record["id"]

    def _loaded(self, node, action_id, spans, depth):
        """A LOAD's dereferenced bytes, one entry per candidate place."""
        explicit = {span for span in spans if span is not None}
        candidates = []
        for read in self.index.reads.get(action_id, ()):
            if read.span.object_id.kind in _MEMORY_OBJECTS and read.span not in explicit:
                place = {"span": _span_text(read.span), "parts": self._fragments(read, None, depth)}
                if read.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE:
                    place["place"] = self._place(read.span)
                candidates.append(place)
        return candidates

    def _all_reads(self, action_id, depth):
        if action_id is None:
            return []
        return [{"span": _span_text(read.span), "parts": self._fragments(read, None, depth)}
                for read in self.index.reads.get(action_id, ())]

    def _debts(self, node, depth):
        found = []
        for source, _, record in self.graph.in_edges(node):
            if record.kind in _DEBT_EDGES:
                found.append(self._debt(source, depth + 1))
                self._edge()
        return sorted(set(found))

    def _rep_element(self, node, key, base, iteration, depth):
        found = self.index.operations.get(base)
        record = self._new(node, {"kind": "op", "key": key, "opcode": found[0].opcode if found else "?",
                                  "rep_iteration": iteration})
        _, record["address"], record["ordinal"] = _key_parts(base)
        rep = next((row for row in self.normalized.rep_blocks if row[0] == ":".join(base.split(":")[:2])), None)
        if rep is not None and found is not None:
            size = (found[0].output or found[0].inputs[-1]).byte_size
            direction = rep[2]
            record.update({"element_size": size, "direction": direction, "displacement": direction * iteration * size})
        self.expanding.add(node)
        try:
            record["reads"] = self._all_reads(self.index.action_of.get(node), depth)
            debts = self._debts(node, depth)
            if debts:
                record["debts"] = debts
        finally:
            self.expanding.discard(node)
        self._done(record)
        return record["id"]

    # -- summarized calls ----------------------------------------------------
    def _call(self, node, key, base, tag, depth):
        effect = self.proven[base]
        record = self._new(node, {"kind": "call", "key": key, "call": base, "row": tag,
                                  "callee": effect.callee})
        label = self.declared.get(base)
        record["source"] = _effect_source(effect.callee, label)
        if label:
            record["model"] = label
        record["facts"] = {
            "restores_stack": effect.restores_stack, "preserves_memory": effect.preserves_memory,
            "escapes_stack": effect.escapes_stack, "noreturn": effect.noreturn,
            "state_proof": effect.state_proof,
            "writer_conditions": len(effect.writer_conditions),
        }
        runs = [("register", run) for run in effect.runs] + [("memory", run) for run in effect.memory_runs]
        if tag.isdigit() and int(tag) < len(runs):
            kind, run = runs[int(tag)]
            record["output"] = {"run": int(tag), "kind": kind}
            if kind == "register":
                record["output"]["writes"] = [_span_text(span) for span in run.writes]
            else:
                record["output"]["write"] = repr(run.write)
                record["output"]["keeps_old"] = run.keeps_old
            if run.conditions:
                record["output"]["conditions"] = len(run.conditions)
            if run.origins:
                record["output"]["callee_origins"] = list(run.origins)
        elif tag.startswith("sink") and tag[4:].isdigit() and int(tag[4:]) < len(effect.sink_demands):
            demand = effect.sink_demands[int(tag[4:])]
            record["output"] = {"sink": demand.label, "complete": demand.complete}
        elif tag.startswith("u") and tag[1:].isdigit():
            record["output"] = {"kind": "unknown memory write", "index": int(tag[1:])}
        if self.provenance is not None:
            record["provenance"] = _call_provenance(self.provenance, base, effect, tag)
        self.call_ids.append(record["id"])
        self._with_origins(record, node)
        self.expanding.add(node)
        try:
            folded: set = set()
            record["inputs"] = self._call_inputs(node, base, depth, seen=folded)
            # the staging rows' own debts and labels (the caller's reads happen there)
            self._with_origins(record, *folded)
            debts = sorted({debt for row in sorted(folded | {node}) for debt in self._debts(row, depth)})
            if debts:
                record["debts"] = debts
        finally:
            self.expanding.discard(node)
        self._done(record)
        return record["id"]

    def _call_inputs(self, node, base, depth, role=None, via=None, seen=None):
        """The reads of a call row, staging rows folded in: [{role, via, parts}]."""
        seen = set() if seen is None else seen
        action_id = self.index.action_of.get(node)
        if action_id is None or node in seen:
            return []
        seen.add(node)
        row_key = self.graph.node(node).key[len("op:"):]
        _, _, tag = row_key.partition("~")
        value_count = self.value_inputs.get(row_key)
        found = []
        for read in self.index.reads.get(action_id, ()):
            this_role = role
            if tag.startswith("in") and value_count is not None:
                this_role = "value" if read.read_ordinal < value_count else "address"
            elif tag.startswith("ld"):
                this_role = "memory" if read.span.object_id.kind in _MEMORY_OBJECTS else "anchor"
            elif tag.startswith("iu"):
                this_role = "address"
            elif this_role is None:
                this_role = "value"
            staged = []
            for fragment in read.fragments:
                for definition_id in fragment.definition_ids:
                    definition = self.ssa.definitions[definition_id]
                    writer = definition.operation_key or ""
                    writer_base, _, writer_tag = writer.partition("~")
                    if writer_base == base and writer_tag.rstrip("0123456789") in _STAGING:
                        staged.append(self.index.definition_node[definition_id])
            if staged:
                for definition_node in staged:
                    for source, _, record in self.graph.in_edges(definition_node):
                        if record.kind == EdgeKind.MEMORY_DEFINES.value:
                            stage = self.graph.node(source).key[len("op:"):].partition("~")[2]
                            found.extend(self._call_inputs(source, base, depth, this_role, stage, seen))
                continue
            entry = {"role": this_role, "span": _span_text(read.span), "parts": self._fragments(read, None, depth)}
            if via:
                entry["via"] = via
            found.append(entry)
        return found

    # -- debts ---------------------------------------------------------------
    def _debt(self, node, depth):
        if node in self.id_of:
            return self.id_of[node]
        graph_node = self.graph.node(node)
        record = self._new(node, {"kind": "debt", "debt": graph_node.label, "key": graph_node.key})
        self._with_origins(record, node)
        row = self.debt_rows.get(node)
        if row is not None:
            record["site"] = row.operation_key
            record["spans"] = [_span_text(span) for span in row.spans]
            if hasattr(row, "intervening_calls"):
                record["calls"] = list(row.intervening_calls)
            if getattr(row, "uncertain", ()):
                record["uncertain_writers"] = list(row.uncertain)
        sources = []
        writers = 0
        self.expanding.add(node)
        try:
            for source, _, edge in self.graph.in_edges(node):
                if edge.kind == EdgeKind.CONTROL_DEPENDENCE.value:
                    continue
                if edge.kind == EdgeKind.MAY_ALIAS_WRITE.value:
                    writers += 1
                    if writers > self.limits.writers:
                        record["writers_truncated"] = True
                        self.truncated = True
                        continue
                if source in self.index.definition_of:
                    produced, _, loop = self._definition_guarded(source, depth + 1)
                else:
                    produced, loop = self.operation(source, depth + 1), source in self.expanding
                sources.append({"node": produced, "edge": edge.kind, "loop": loop})
                self._edge()
        finally:
            self.expanding.discard(node)
        record["from"] = sources
        self._done(record)
        return record["id"]

    # -- stitching (docs 25.31 C-9, increment 1) -------------------------------
    def stitch_all(self):
        """Phase 2: try every call node this builder made (in id order)."""
        for identifier in list(self.call_ids):
            if identifier < len(self.records):
                self._stitch(self.records[identifier])

    def _staged_reads(self, row_key):
        if self._actions is None:
            self._actions = {action.operation_key: action_id for action_id, action in enumerate(self.ssa.actions)}
        action_id = self._actions.get(row_key)
        return self.index.reads.get(action_id, ()) if action_id is not None else ()

    def _stack_base(self, call_key):
        """(offset, size) of the register the observed call shape adjusts (the
        stack pointer), or None (no observed shape)."""
        if self._transitions is None:
            from .observed_call_state import observed_call_state_projections

            self._transitions = {row.call_operation_key: row.memory_transition
                                 for row in observed_call_state_projections(self.unit.observation)}
        transition = self._transitions.get(call_key)
        if transition is None:
            return None
        return transition.caller_base.byte_offset, transition.caller_base.byte_size

    def _stitch_reason(self, record):
        """Why a call node is not stitched, or None."""
        base, tag = record["call"], record["row"]
        if self.ledger.exhausted:
            return "limit"
        if self.provenance is None or self.stitch is None:
            return "no provenance"
        source = self.provenance.sources.get(base)
        if source is None:
            return "source: none"
        if source[0] != "summary":
            return f"source: {source[0]}"
        done = source[1]
        if done.summary is None or type(done.normalized).__name__ != "NormalizedFunction":
            return "no callee body"
        effect = self.proven[base]
        if not tag.isdigit() or int(tag) >= len(effect.runs):
            return "not a register output"
        run = effect.runs[int(tag)]
        if run.loads:
            return "loads"
        if run.conditions or effect.writer_conditions:
            return "conditions"
        if effect.tail_stack or done.summary.tail_exits:
            return "tail"
        if not done.summary.exits:
            return "no exit"
        if len(self.path) >= self.limits.call_depth:
            return "depth"
        if done.key == self.function_key or any(done.key == key for key, _ in self.path):
            return "recursion"
        if self._stack_base(base) is None:
            return "no call shape"
        return None

    def _stitch(self, record):
        """One call instance: built whole, or rolled back with the reason;
        the records before the attempt, every builder's ``id_of`` and
        ``truncated`` flag end as they were."""
        reason = self._stitch_reason(record)
        if reason is not None:
            record["stitch_cut"] = reason
            return
        base, tag = record["call"], record["row"]
        done = self.provenance.sources[base][1]
        run = self.proven[base].runs[int(tag)]
        start = len(self.records)
        chain = []
        builder = self
        while builder is not None:
            chain.append(builder)
            builder = builder.parent
        saved = [(item, item.truncated) for item in chain]
        frozen, self.ledger.frozen = self.ledger.frozen, start
        path = (*self.path, (self.function_key, base))
        instance = "/".join(call for _, call in path)
        try:
            nested = _Builder(done.normalized, done.unit, origins=done.origins, declared=done.declared,
                              limits=self.limits, provenance=self.stitch.provenance(done), stitch=self.stitch,
                              records=self.records, ledger=self.ledger, parent=self,
                              binding=_Binding(self, self._staged_reads(f"{base}~in{tag}"), self._stack_base(base)),
                              path=path, index=self.stitch.index(done.normalized, done.unit))
            outputs = [{"output": _span_dict(span), "part": nested._stitched_output(span, done.summary, instance)}
                       for span in run.writes]
            if nested.truncated or any(item.truncated != flag for item, flag in saved):
                raise _StitchCut("limit")   # (a cut inside: never a partial import)
            gap = _gap_used(self.records, start, outputs)
            if gap is not None:
                raise _StitchCut(gap)
            nested.stitch_all()
            if nested.truncated or any(item.truncated != flag for item, flag in saved):
                raise _StitchCut("limit")
        except (_StitchCut, _Truncated, RecursionError, DiagnosticExhausted) as error:
            for item in chain:
                for key in [key for key, value in item.id_of.items() if value >= start]:
                    del item.id_of[key]
                item.call_ids = [identifier for identifier in item.call_ids if identifier < start]
            del self.records[start:]
            reason = str(error) if isinstance(error, _StitchCut) else "limit"
            if reason == "limit":
                self.ledger.exhausted = True   # (out of a limit: no more attempts)
            record["stitch_cut"] = reason
        else:
            for item in self.records[start:]:
                item.setdefault("import", instance)   # (nested instances tagged theirs first)
            record["stitched"] = outputs
        finally:
            for item, flag in saved:
                item.truncated = flag
            self.ledger.frozen = frozen

    def _stitched_output(self, span, summary, instance):
        """This callee's value of the caller's output bytes ``span``
        (register offsets) as one part: per exit the runs' bytes assembled
        (bytes the exit does not write: the caller's value at the call);
        several exits -> a phi "callee exits"."""
        from .span_geometry import ByteSpan

        alternatives = []
        definition_nodes = self.normalized.memory_graph.definition_nodes
        for exit_summary in summary.exits:
            parts, covered = [], set()
            for run in exit_summary.runs:
                if run.span.object_id.kind is not StorageObjectKind.REGISTER_FILE:
                    continue
                low, high = max(run.span.start, span.start), min(run.span.end, span.end)
                if low >= high or run.kind.value == "identity":
                    continue
                if run.kind.value != "computed" or run.crossed or run.debts or run.conditions:
                    raise _StitchCut("run not exact")
                nodes = [definition_nodes[item] for item in run.definitions if 0 <= item < len(definition_nodes)]
                if not nodes:
                    raise _StitchCut("run not exact")
                piece = ByteSpan(run.span.object_id, low, high - low)
                values = [self._whole(self.seed(node, (piece,)), high - low) for node in nodes]
                if len(values) == 1:
                    part = values[0]
                else:
                    phi = self._new(None, {"kind": "phi", "reason": "exit run definitions",
                                           "span": _span_text(piece), "size": high - low, "alternatives": values})
                    self._done(phi)
                    part = {"node": phi["id"], "bytes": [0, high - low]}
                parts.append({**part, "at": [low - span.start, high - span.start]})
                covered.update(range(low, high))
            offset = span.start
            while offset < span.end:   # bytes this exit leaves as they were before the call
                if offset in covered:
                    offset += 1
                    continue
                end = offset
                while end < span.end and end not in covered:
                    end += 1
                bound = self._new(None, {"kind": "bound", "callee_entry": f"unchanged at {exit_summary.block_key}",
                                         "unchanged": True, "size": end - offset,
                                         "parts": self.binding.parts(offset, end)})
                parts.append({"node": bound["id"], "bytes": [0, end - offset],
                              "at": [offset - span.start, end - span.start]})
                offset = end
            parts.sort(key=lambda part: part["at"][0])
            alternatives.append(self._whole(parts, span.size))
        if len(alternatives) == 1:
            return alternatives[0]
        phi = self._new(None, {"kind": "phi", "reason": "callee exits", "instance": instance, "size": span.size,
                               "alternatives": alternatives})
        self._done(phi)
        return {"node": phi["id"], "bytes": [0, span.size], "at": [0, span.size]}

    def _whole(self, parts, size):
        """One part holding a ``size``-byte value given as ``parts``: the
        part itself when it is the whole value, else an ``assemble`` node."""
        if any(part.get("whole") or part.get("pruned") or "node" not in part for part in parts):
            raise _StitchCut("run not exact")
        position = 0
        for a, b in sorted(tuple(part["at"]) for part in parts):
            if a != position:
                raise _StitchCut("run not exact")   # (a gap or an overlap)
            position = b
        if position != size:
            raise _StitchCut("run not exact")
        if len(parts) == 1:
            piece = {key: value for key, value in parts[0].items() if key in ("node", "bytes", "output", "loop")}
            piece["at"] = [0, size]
            return piece
        record = self._new(None, {"kind": "assemble", "size": size, "parts": [
            {key: value for key, value in part.items() if key in ("node", "bytes", "at", "output", "loop")}
            for part in parts]})
        return {"node": record["id"], "bytes": [0, size], "at": [0, size]}

    # -- seeds ---------------------------------------------------------------
    def seed(self, node, spans, depth=0):
        """Parts for a root seed: a definition node with its demanded spans,
        or any other node (all of it)."""
        if node in self.index.definition_of:
            definition = self.ssa.definitions[self.index.definition_of[node]]
            produced, base, loop = self._definition_guarded(node, depth)
            parts = []
            for span in spans or (definition.span,):
                if span.object_id != definition.span.object_id:
                    span = definition.span
                start = max(span.start, definition.span.start)
                end = min(span.end, definition.span.end)
                if start >= end:
                    continue
                # ``at``: within the demanded span (``span``), whose bytes the root is
                parts.append(self._named({"node": produced, "bytes": [base + start - definition.span.start,
                                                                      base + end - definition.span.start],
                                          "at": [start - span.start, end - span.start], "span": _span_text(span),
                                          "def": _span_text(definition.span), "loop": loop}, definition))
            return parts
        return [{"node": self.operation(node, depth), "whole": True}]


def _call_provenance(provenance, call, effect, tag) -> dict:
    """A call row's provenance (docs 25.31 C9-5): where the effect came from,
    the published verdict of each alias condition of the row (and of the
    effect's writer conditions) in pair order, and the call's derivation-time
    rejections. A verdict is "proven" only when the last pass decided the
    pair disjoint and it never failed; "failed" / "open" otherwise, and
    "undecided" where no decision is kept -- absence never means proven. A
    "recursive hypothesis" source had every condition failed by construction
    (``interprocedural._recursive_hypothesis``)."""
    source = provenance.sources.get(call)
    found: dict = {"source": None if source is None else source[0]}
    if source is not None:
        if source[0] == "summary":
            found["function"] = source[1].key
        else:
            found["label"] = source[1]
    failed = provenance.failed.get(call, frozenset())

    def verdicts(pairs, rows):
        published = []
        for position, pair in enumerate(pairs):
            row = rows[position] if position < len(rows) else None
            if pair in failed or row == "fail":
                verdict = "failed"
            elif row == "ok":
                verdict = "proven"
            elif row is None:
                verdict = "undecided"
            else:
                verdict = "open"
            published.append({"pair": [_anchored_text(side) for side in pair], "verdict": verdict})
        return published

    runs = (*effect.runs, *effect.memory_runs)
    if tag.isdigit() and int(tag) < len(runs) and runs[int(tag)].conditions:
        found["conditions"] = verdicts(runs[int(tag)].conditions, provenance.final.get((call, f"cr{tag}"), ()))
    elif tag.startswith("sink") and tag[4:].isdigit() and int(tag[4:]) < len(effect.sink_demands) \
            and effect.sink_demands[int(tag[4:])].conditions:
        found["conditions"] = verdicts(effect.sink_demands[int(tag[4:])].conditions,
                                       provenance.sink.get((call, f"ck{tag[4:]}"), ()))
    if effect.writer_conditions:
        found["writer_conditions"] = verdicts(effect.writer_conditions, provenance.final.get((call, "cw"), ()))
    rejections = provenance.rejections.get(call, ())
    if rejections:
        found["rejections"] = [
            {"where": where if isinstance(where, str) else f"{where[0]} {_span_text(where[1])}",
             "pair": [_anchored_text(side) if hasattr(side, "displacement") else _span_text(side)
                      for side in pair], "reason": reason}
            for where, pair, reason in rejections]
    return found


def _anchored_text(place) -> str:
    """An ``AnchoredSpan`` (a caller-located callee address) as text."""
    if place.pointer is not None:
        return f"[{_anchored_text(place.pointer)}]{place.displacement:+#x}+{place.size}"
    if place.anchor is not None:
        return f"{_span_text(place.anchor)}{place.displacement:+#x}+{place.size}"
    return f"{place.space_id:x}:{place.displacement:x}+{place.size}"


def _effect_source(callee, label):
    if label is None:
        return "summary" if ":" in callee and not callee.startswith("test-only") else "unknown"
    for prefix in ("external-model:", "derived-model:", "supplied-model:", "bound-model:", "test-only-boundary:"):
        if label.startswith(prefix):
            return prefix[:-1]
    return "model"


def _register_space(unit):
    from .may_alias import _register_space_id

    return _register_space_id(unit.observation)


def _key_parts(key):
    parts = key.split(":")
    try:
        return parts[0], int(parts[1], 16), int(parts[2])
    except (IndexError, ValueError):
        return parts[0], None, None


def _object_text(span):
    object_id = span.object_id
    return f"{object_id.kind.value}:{object_id.scope.digest.hex()[:8]}:{object_id.space_key}"


def _span_text(span):
    object_id = span.object_id
    if object_id.kind is StorageObjectKind.FUNCTION_RELATIVE:   # (a digest as its space key)
        return f"relative:{object_id.space_key & 0xffffffff:08x}:{span.start:x}+{span.size}"
    if object_id.kind is StorageObjectKind.REGISTER_FILE:
        name = _X64_REGISTERS.get(span.start - span.start % 8)
        if name is not None and span.start % 8 == 0 and span.size == 8:
            return f"register:{name}"
        return f"register:{span.start:x}+{span.size}"
    return f"{object_id.kind.value}:{object_id.space_key:x}:{span.start:x}+{span.size}"


def _span_text_of(place):
    """``_span_text`` of a ``_span_dict``."""
    if place["kind"] == "register_file":
        name = _X64_REGISTERS.get(place["start"])
        return name if name is not None and place["size"] == 8 else f"reg:{place['start']:x}+{place['size']}"
    return f"{place['kind']}:{place['start']:x}+{place['size']}"


def _span_dict(span):
    return {"object": _object_text(span), "kind": span.object_id.kind.value, "start": span.start,
            "size": span.size}


def _build(normalized, unit, seeds, metadata, *, origins=None, declared=None, limits=None, provenance=None,
           stitch=None):
    from .lane_slice import lane_slice

    limits = limits or Limits()
    demand_seeds = [(node, spans) for node, spans in seeds]
    demands = lane_slice(normalized, unit, demand_seeds, budget=limits.demand_steps,
                         byte_budget=limits.demand_bytes)
    builder = _Builder(normalized, unit, origins=origins, declared=declared, limits=limits, demands=demands,
                       provenance=provenance, stitch=stitch)
    root = []
    # one expansion level takes a few Python frames: room for ``limits.depth``
    previous = sys.getrecursionlimit()
    sys.setrecursionlimit(max(previous, 16 * limits.depth + 2000))
    try:
        for node, spans in seeds:
            root.extend(builder.seed(node, spans))
    except _Truncated:
        pass
    except RecursionError:
        builder.truncated = True
        builder.records.append({"kind": "cut", "target": None, "reason": "recursion", "id": len(builder.records)})
    except BaseException:
        sys.setrecursionlimit(previous)
        raise
    try:
        if stitch is not None:
            builder.stitch_all()   # (after the record is whole; an attempt never changes it)
    finally:
        sys.setrecursionlimit(previous)
    entry = unit.scopes.function.entry
    evidence = unit.scopes.program.evidence
    language = evidence.translation_namespace.language_id
    return {
        "version": RECORD_VERSION,
        "function": f"{entry.space_id:x}:{entry.byte_offset:x}",
        "program": evidence.executable_sha256.hex() if hasattr(evidence, "executable_sha256") else None,
        "language": language,
        "endianness": "little" if ":LE:" in language else "big",
        "truncated": builder.truncated or demands.exhausted,
        "demand_complete": not demands.exhausted,
        "limits": vars(limits) if not hasattr(limits, "__dataclass_fields__") else {
            name: getattr(limits, name) for name in limits.__dataclass_fields__},
        **metadata,
        "root": root,
        "nodes": builder.records,
        "partial_provenance": ("assumptions that act by excluding writers or debts are not attributable to "
                               "one root; the run-level assumption list is the authority"),
    }


@measured("records")
def root_record(normalized, unit, seeds, *, origins=None, declared=None, limits=None, completeness=None,
                provenance=None, stitch=None):
    """The record of a sink root: ``seeds`` as ``lane_slice`` takes them
    ((node, spans) of the root's raw sink rows); ``provenance``: the
    instance's ``CallProvenance`` (call nodes then carry it, docs 25.31 C9-5)."""
    metadata = {"record": "root"}
    if completeness is not None:
        metadata["completeness"] = {"complete": completeness.complete,
                                    "reachable_unresolved_reads": completeness.reachable_unresolved_reads,
                                    "function_unresolved_writes": completeness.function_unresolved_writes}
    # function-wide unresolved writes (outside the slice too)
    metadata["function_unresolved_writes"] = len(normalized.memory_graph.unresolved_write_nodes) \
        if normalized.memory_graph is not None else None
    return _build(normalized, unit, seeds, metadata, origins=origins, declared=declared, limits=limits,
                  provenance=provenance, stitch=stitch)


def run_records(normalized, unit, summary, *, origins=None, declared=None, limits=None):
    """One record per output run of every normal exit of ``summary`` (the
    function's ``FunctionSummary``), with the run's own facts."""
    found = []
    for exit_summary in summary.exits:
        for run in exit_summary.runs:
            if run.span.object_id.kind is StorageObjectKind.FUNCTION_UNIQUE:
                continue
            nodes = [normalized.memory_graph.definition_nodes[item] for item in run.definitions
                     if 0 <= item < len(normalized.memory_graph.definition_nodes)]
            metadata = {
                "record": "summary run", "exit": exit_summary.block_key, "span": _span_text(run.span),
                "place": _span_dict(run.span),
                "run_kind": run.kind.value, "crossed": list(run.crossed), "debts": list(run.debts),
                "conditions": len(run.conditions), "writer_conditions": len(summary.writer_conditions),
                "unknown_writers": list(summary.unknown_writers), "tail_exits": list(summary.tail_exits),
                "origins": list(run.origins),
            }
            if run.kind.value == "identity":
                found.append({**metadata, "truncated": False, "demand_complete": True, "root": [], "nodes": []})
                continue
            if len(nodes) > 1:
                record = _run_phi(normalized, unit, nodes, run, metadata, origins, declared, limits)
            else:
                record = _build(normalized, unit, [(node, (run.span,)) for node in nodes], metadata,
                                origins=origins, declared=declared, limits=limits)
            found.append(record)
    return found


def _run_phi(normalized, unit, nodes, run, metadata, origins, declared, limits):
    """A run with several definitions: a synthesized phi over them."""
    record = _build(normalized, unit, [(node, (run.span,)) for node in nodes], metadata,
                    origins=origins, declared=declared, limits=limits)
    alternatives = list(record["root"])
    phi = {"kind": "phi", "reason": "exit run definitions", "span": _span_text(run.span), "size": run.span.size,
           "alternatives": alternatives, "id": len(record["nodes"])}
    record["nodes"].append(phi)
    record["root"] = [{"node": phi["id"], "bytes": [0, run.span.size], "at": [0, run.span.size]}]
    return record


# -- rendering ------------------------------------------------------------------

def render(record) -> str:
    """A text form: one line per node, ``n<id> = ...``."""
    facts = []
    if record.get("record") == "summary run":
        facts.append(f"kind={record.get('run_kind')}")
        for name in ("crossed", "debts", "unknown_writers", "tail_exits"):
            if record.get(name):
                facts.append(f"{name}={','.join(record[name])}")
        for name in ("conditions", "writer_conditions"):
            if record.get(name):
                facts.append(f"{name}={record[name]}")
        if record.get("origins"):
            facts.append(f"origins={','.join(record['origins'])}")
    elif record.get("completeness") is not None and not record["completeness"]["complete"]:
        facts.append("incomplete")
    if record.get("truncated"):
        facts.append("truncated")
    lines = [f"# {record.get('record')} {record.get('function')} {record.get('span', '')}"
             + (f" [{' '.join(facts)}]" if facts else "")]
    nodes = {node["id"]: node for node in record.get("nodes", ())}
    for node in record.get("nodes", ()):
        if node["kind"] == "entry" and "register" in node and not node.get("origins"):
            continue   # shown by name where used
        lines.append(f"n{node['id']} = {_render_node(node, nodes)}")
    lines.append("root = " + " | ".join(_render_parts(record.get("root", ()), nodes)))
    return "\n".join(lines)


def _render_parts(parts, nodes=None):
    found = []
    for part in parts:
        target = (nodes or {}).get(part.get("node"))
        if target is not None and target["kind"] == "entry" and "register" in target and not part.get("pruned"):
            found.append(_register_name(target, *part["bytes"]))
            continue
        if part.get("pruned"):
            found.append(f"_[{part['at'][0]}:{part['at'][1]}]")
        elif part.get("whole"):
            found.append(f"n{part['node']}")
        else:
            loop = "^" if part.get("loop") else ""
            output = part.get("output")
            which = f"<{_span_text_of(output)}>" if output else ""
            found.append(f"{loop}n{part['node']}{which}[{part['bytes'][0]}:{part['bytes'][1]}]")
    return found


def _register_name(entry, start, end):
    """``rdi``, ``ecx``-style names as ``rcx[0:4]`` (x86-64), else ``reg[0x38+8]``."""
    offset = entry["register"]["offset"] + start
    size = end - start
    if entry.get("x64"):
        base = offset - offset % 8
        name = _X64_REGISTERS.get(base)
        if name is not None:
            return name if (offset, size) == (base, 8) else f"{name}[{offset - base}:{offset - base + size}]"
    return f"reg[0x{offset:x}+{size}]"


def _render_node(node, nodes=None):
    kind = node["kind"]
    origins = f"  <- {','.join(node['origins'])}" if node.get("origins") else ""
    if kind == "const":
        return f"0x{node['value']:x}:{node['size']}"
    if kind == "entry":
        return f"entry {node.get('name') or node['span']}{origins}"
    if kind == "phi":
        return "phi(" + ", ".join(_render_parts(node["alternatives"], nodes)) + f") [{node['reason']}]{origins}"
    if kind == "cut":
        return f"cut {node['target']} ({node['reason']})"
    if kind == "debt":
        return f"debt {node['debt']} {node.get('site', '')} from " + \
            ", ".join(f"n{item['node']}" for item in node.get("from", ())) + origins
    if kind == "call":
        inputs = "; ".join(f"{item['role']}=" + "+".join(_render_parts(item["parts"], nodes)) for item in node["inputs"])
        text = f"call {node['callee']} ~{node['row']} [{node.get('source')}] ({inputs}){origins}"
        for item in node.get("stitched", ()):
            text += f" => {_render_parts([item['part']], nodes)[0]}"
        if node.get("stitch_cut"):
            text += f" [not stitched: {node['stitch_cut']}]"
        return text
    if kind == "bound":
        return f"bound {node['callee_entry']} = " + "+".join(_render_parts(node["parts"], nodes))
    if kind == "assemble":
        return "assemble(" + ", ".join(_render_parts(node["parts"], nodes)) + ")"
    if kind in ("op", "override"):
        operands = []
        for operand in node.get("operands", ()):
            if "value" in operand and "parts" not in operand:
                continue   # a space id / call target
            if operand.get("pruned"):
                operands.append("_")
            else:
                operands.append("+".join(_render_parts(operand.get("parts", ()), nodes)) or "?")
        text = f"{node['opcode']}({', '.join(operands)})"
        if node.get("memory"):
            text += " mem{" + " | ".join("+".join(_render_parts(item["parts"], nodes)) for item in node["memory"]) + "}"
        if node.get("reads"):
            text += " reads{" + " | ".join("+".join(_render_parts(item["parts"], nodes)) for item in node["reads"]) + "}"
        if "value" in node:
            text += f" = {node['value']}"
        if node.get("address") is not None:
            text += f" @{node['address']:x}:{node.get('ordinal')}"
        if node.get("override") == "unproven":
            text += " [rep unproven]"
        elif node.get("override") is not None:
            text += f" [override n{node['override']}]"
        if node.get("debts"):
            text += " debts{" + ",".join(f"n{item}" for item in node["debts"]) + "}"
        return text + origins
    return f"{kind} {node.get('key', '')}"


# -- evaluation -----------------------------------------------------------------

class Ineligible(Exception):
    """The record is not checked for equality (the reason)."""


_SUPPORTED = frozenset({
    "COPY", "INT_ADD", "INT_SUB", "INT_MULT", "INT_AND", "INT_OR", "INT_XOR", "INT_NEGATE", "INT_2COMP",
    "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_ZEXT", "INT_SEXT", "SUBPIECE", "PIECE", "POPCOUNT",
    "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_LESSEQUAL", "INT_SLESS", "INT_SLESSEQUAL", "INT_CARRY",
    "INT_SCARRY", "INT_SBORROW", "BOOL_NEGATE", "BOOL_AND", "BOOL_OR", "BOOL_XOR", "LOAD", "STORE",
    "INT_DIV", "INT_REM", "INT_SDIV", "INT_SREM",
})


def eligibility(record) -> str | None:
    """None when ``record`` is checked for equality, else the first reason it
    is not (loops are checked before any alternative)."""
    if record.get("run_kind") == "identity":
        return "identity"   # unchanged: nothing to evaluate
    if record.get("truncated"):
        return "truncated"
    # (route "injected": a stitched call's imported subtree is not this
    # record's value -- docs 25.31 C-9)
    nodes = [node for node in record.get("nodes", ()) if "import" not in node]
    if any(node["kind"] == "cut" or node.get("interrupted") for node in nodes):
        return "cut"
    for node in nodes:
        parts = [*node.get("alternatives", ()),
                 *(part for operand in node.get("operands", ()) for part in operand.get("parts", ())),
                 *(part for item in node.get("memory", ()) for part in item["parts"])]
        if any(part.get("loop") for part in parts):
            return "loop"
    if any(part.get("loop") for part in record.get("root", ())):
        return "loop"
    for node in nodes:
        if node["kind"] == "debt" or node.get("debts"):
            return "debt"
        if node.get("override") == "unproven":
            return "unproven rep"
        if node.get("rep_iteration") is not None or node["kind"] == "override":
            return "rep"
        if node["kind"] == "op" and node["opcode"] not in _SUPPORTED:
            return f"unsupported {node['opcode']}"
        if node["kind"] == "op" and "value" not in node \
                and any(operand.get("unresolved") for operand in node.get("operands", ())):
            return "unresolved operand"
        if node["kind"] == "node":
            return "unsupported node"
    if record.get("record") == "root" and record.get("completeness") is not None \
            and not record["completeness"]["complete"]:
        return "root incomplete"
    if any(part.get("whole") for part in record.get("root", ())):
        return "whole-node root"
    if len({part.get("span") for part in record.get("root", ())}) > 1:
        return "several selectors"   # separate outputs: never one value
    placed: set = set()
    for part in record.get("root", ()):
        if "at" in part:
            covered = set(range(*part["at"]))
            if covered & placed:
                return "overlapping root parts"   # two values for one byte
            placed |= covered
    if record.get("record") == "summary run" and (
            record.get("run_kind") == "unknown" or record.get("crossed") or record.get("conditions")
            or record.get("writer_conditions") or record.get("debts")):
        return "run not exact"
    return None


def evaluate(record, entry, *, call=None, max_choices=256):
    """The set of values (little-endian ints over the root's bytes) the
    record allows: ``entry(node)`` -> the value of an entry node or None (not
    known), ``entry(("memory", space, address, size))`` -> entry memory at a
    concrete address or None; ``call(node, part)`` -> a call output's bytes or
    None. Raises ``Ineligible`` with the reason when not evaluable."""
    reason = eligibility(record)
    if reason is not None:
        raise Ineligible(reason)
    nodes = {node["id"]: node for node in record["nodes"]}
    own = [node for node in record["nodes"] if "import" not in node]   # (route "injected")
    choices = [node["id"] for node in own if node["kind"] == "phi"] + \
              [node["id"] for node in own
               if node["kind"] == "op" and node["opcode"] == "LOAD" and len(node.get("memory", ())) > 1]
    sizes = {identifier: max(1, len(nodes[identifier].get("alternatives", nodes[identifier].get("memory", ()))))
             for identifier in choices}
    total = 1
    for identifier in choices:
        total *= sizes[identifier]
    if total > max_choices:
        raise Ineligible("alternatives")
    results = set()
    unknown = False
    for number in range(total):
        assignment = {}
        for identifier in choices:
            assignment[identifier] = number % sizes[identifier]
            number //= sizes[identifier]
        try:
            results.add(_evaluate_once(nodes, entry, call, assignment, record))
        except _Unknown:
            unknown = True
    if unknown or not results:
        # an alternative that cannot be evaluated may be the one taken: the
        # known ones are no result (approved R2)
        raise Ineligible("unknown inputs" if unknown else "no alternative")
    return results


class _Unknown(Exception):
    pass


def _evaluate_once(nodes, entry, call, assignment, record):
    """One assignment's value, with room for the record's depth (one level
    takes a few Python frames); running out is ineligibility, not a crash."""
    depth = record.get("limits", {}).get("depth", Limits.depth)
    previous = sys.getrecursionlimit()
    sys.setrecursionlimit(max(previous, 16 * depth + 2000))   # (the build cut deeper chains)
    try:
        return _Evaluator(nodes, entry, call, assignment).root(record["root"])
    except RecursionError:
        raise Ineligible("recursion") from None
    finally:
        sys.setrecursionlimit(previous)


class _Evaluator:
    def __init__(self, nodes, entry, call, assignment):
        self.nodes, self.entry, self.call, self.assignment = nodes, entry, call, assignment
        self.memo: dict = {}

    def root(self, parts):
        value = 0
        for part in parts:
            if part.get("whole"):
                raise _Unknown()
            value |= self.part(part) << (8 * part["at"][0])
        return value

    def part(self, part, node_value=None):
        a, b = part["bytes"]
        node = self.nodes[part["node"]]
        if node["kind"] == "call":
            if self.call is None:
                raise _Unknown()
            found = self.call(node, part)
            if found is None:
                raise _Unknown()
            return found
        value = self.value(part["node"]) if node_value is None else node_value
        return (value >> (8 * a)) & ((1 << (8 * (b - a))) - 1)

    def _alternative(self, node, choice, read):
        """A phi's value: the chosen alternative's bytes at their place; a
        byte it does not cover is not known."""
        alternative = node["alternatives"][choice]
        if alternative["at"] != [0, node.get("size", alternative["at"][1])]:
            raise _Unknown()
        return read(alternative)

    def _located_part(self, part, space, address):
        """``part`` of a value in memory whose producer's bytes start at
        ``address``: entry memory is read there (through phis too)."""
        node = self.nodes[part["node"]]
        a, b = part["bytes"]
        if node["kind"] == "entry" and "register" not in node:
            found = self.entry(("memory", space, address + a, b - a))
            if found is None:
                raise _Unknown()
            return found
        if node["kind"] == "phi":
            # the phi's bytes start at ``address``; its chosen alternative's
            # producer at address + at[0] - bytes[0]
            value = self._alternative(
                node, self.assignment[part["node"]],
                lambda alternative: self._located_part(alternative, space,
                                                       address + alternative["at"][0] - alternative["bytes"][0]))
            return (value >> (8 * a)) & ((1 << (8 * (b - a))) - 1)
        return self.part(part)

    def operand(self, operand, address=None):
        """An operand's value; bytes pruned (no demanded result byte depends on
        them -- exact lane maps only) read as 0."""
        if operand.get("pruned"):
            return 0
        value = 0
        for part in operand["parts"]:
            if not part.get("pruned"):
                value |= self.part(part) << (8 * part["at"][0])
        return value

    def value(self, identifier):
        if identifier in self.memo:
            return self.memo[identifier]
        node = self.nodes[identifier]
        kind = node["kind"]
        if kind == "const":
            found = node["value"]
        elif kind == "entry":
            found = self.entry(node)
            if found is None:
                raise _Unknown()
        elif kind == "phi":
            found = self._alternative(node, self.assignment[identifier], self.part)
        elif kind == "op":
            found = self._op(identifier, node)
        else:
            raise _Unknown()
        self.memo[identifier] = found
        return found

    def _op(self, identifier, node):
        if "value" in node:
            return node["value"]
        opcode = node["opcode"]
        operands = [operand for operand in node["operands"] if "parts" in operand]
        if opcode == "STORE":
            value_operand = next(operand for operand in operands if operand["index"] == 2)
            return self.operand(value_operand)
        if opcode == "LOAD":
            address = self.operand(next(operand for operand in operands if operand["index"] == 1))
            places = node["memory"]
            if not places:
                raise _Unknown()
            place = places[self.assignment.get(identifier, 0)]
            size = node["output"]["size"]
            value = 0
            covered = set()
            for part in place["parts"]:
                if part.get("pruned"):
                    continue
                start, end = part["at"]
                # the producer's value starts at address + start - bytes[0]
                found = self._located_part(part, node["space"], address + start - part["bytes"][0])
                value |= found << (8 * start)
                covered.update(range(start, end))
            if not set(range(size)) <= covered:
                raise _Unknown()
            return value
        operands = [operand for operand in node["operands"] if "parts" in operand or operand.get("pruned")]
        values = [self.operand(operand) for operand in operands]
        widths = [operand["width"] for operand in operands]
        size = node.get("output", {}).get("size") or (widths[0] if widths else 1)
        return _compute(opcode, values, widths, size) & ((1 << (8 * size)) - 1)


def _signed(value, size):
    bits = 8 * size
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) & 1 else value


def _compute(opcode, values, widths, out_size):
    """The p-code semantics (as ``tests/intra/pcode_interpreter._compute``)."""
    size = widths[0] if widths else out_size
    a = values[0] if values else 0
    b = values[1] if len(values) > 1 else 0
    mask = (1 << (8 * size)) - 1
    if opcode == "COPY" or opcode == "INT_ZEXT":
        return a
    table = {
        "INT_ADD": lambda: a + b, "INT_SUB": lambda: a - b, "INT_MULT": lambda: a * b,
        "INT_AND": lambda: a & b, "INT_OR": lambda: a | b, "INT_XOR": lambda: a ^ b,
        "INT_NEGATE": lambda: ~a, "INT_2COMP": lambda: -a,
        "INT_LEFT": lambda: a << b if b < 8 * out_size else 0, "INT_RIGHT": lambda: a >> b,
        "INT_SRIGHT": lambda: _signed(a, size) >> min(b, 8 * size), "INT_SEXT": lambda: _signed(a, size),
        "SUBPIECE": lambda: a >> (8 * b), "PIECE": lambda: (a << (8 * widths[1])) | b,
        "POPCOUNT": lambda: bin(a).count("1"),
        "INT_EQUAL": lambda: int(a == b), "INT_NOTEQUAL": lambda: int(a != b),
        "INT_LESS": lambda: int(a < b), "INT_LESSEQUAL": lambda: int(a <= b),
        "INT_SLESS": lambda: int(_signed(a, size) < _signed(b, size)),
        "INT_SLESSEQUAL": lambda: int(_signed(a, size) <= _signed(b, size)),
        "INT_CARRY": lambda: int(a + b > mask),
        "INT_SCARRY": lambda: int(not -(1 << (8 * size - 1)) <= _signed(a, size) + _signed(b, size)
                                  < (1 << (8 * size - 1))),
        "INT_SBORROW": lambda: int(not -(1 << (8 * size - 1)) <= _signed(a, size) - _signed(b, size)
                                   < (1 << (8 * size - 1))),
        "BOOL_NEGATE": lambda: int(not a), "BOOL_AND": lambda: int(bool(a) and bool(b)),
        "BOOL_OR": lambda: int(bool(a) or bool(b)), "BOOL_XOR": lambda: int(bool(a) != bool(b)),
    }
    if opcode in ("INT_DIV", "INT_REM", "INT_SDIV", "INT_SREM"):
        if b == 0:
            raise _Unknown()
        if opcode == "INT_DIV":
            return a // b
        if opcode == "INT_REM":
            return a % b
        sa, sb = _signed(a, size), _signed(b, size)
        quotient = abs(sa) // abs(sb) * (1 if (sa < 0) == (sb < 0) else -1)
        return quotient if opcode == "INT_SDIV" else sa - quotient * sb
    if opcode not in table:
        raise _Unknown()
    return table[opcode]()


__all__ = ("Ineligible", "Limits", "RECORD_VERSION", "StitchContext", "eligibility", "evaluate", "render",
           "root_record", "run_records")
