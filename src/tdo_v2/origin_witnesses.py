"""Origin witnesses: why a root reports an origin label (diagnostics only,
docs 25.19). Nothing here changes which labels a root reports or whether it
is complete.

Per root (its raw sink rows), per reported label:
- ``has_debt_free_path``: the label is reached by the same byte-lane slice
  ``summary_engine._lane_origin_labels`` uses, with every MEMORY_DEBT node
  left out -- a property of the graph, not a proof that the label reaches
  the root;
- ``witnesses``: debts the label arrives through. For a may-alias debt, one
  witness per (writer, reader) transfer whose writer's STORED VALUE reaches
  the label (the writer's address inputs excluded): a STORE's value operand,
  a summarized memory run's value reads (``NormalizedFunction.
  call_value_inputs``) and the origins its callee attached
  (``provenance: callee``), a rep element's value read. When both endpoints'
  addresses are exact (one span each, address operands on no debt, the
  writer not an uncertain-address writer) and their atom tuples differ in
  exactly one atom each with coefficient 1, the transfer's any-byte overlap
  condition: writer atom - reader atom in [low, high] modulo 2^bits
  ("this transfer requires ..."); with 0 outside the window, equal pointers
  exclude it. For a call-clobber debt: the labels of the values from before
  the calls in the bytes they may have changed ("if they leave it
  unchanged"), and the labels on the debt node itself (a value the call
  produced). Other debts: their kind and site, labels reached through the
  debt node itself. At most ``MAX_WITNESSES`` per label (``truncated``).
Every seed keeps the bytes it stands for (a STORE's value operand, a run's
value reads, the clobbered bytes), never the whole definition.
``traversal``: "lane", or "node-fallback" when the reported labels came from
the node slice (lane origins switched off, or ``_lane_origin_labels`` fell
back to it) -- the witnesses still use lane slices.
"""

from __future__ import annotations

from .phases import measured

from .graph_contracts import NodeKind
from .span_geometry import ByteSpan, StorageObjectKind

MAX_WITNESSES = 8
_RELATIVE = StorageObjectKind.FUNCTION_RELATIVE
_NOT_MEMORY = (StorageObjectKind.REGISTER_FILE, StorageObjectKind.FUNCTION_UNIQUE)


def labels_in_lanes(lanes, index, rows) -> set:
    """The SOURCE rows' labels a lane slice reaches (the rule of
    ``summary_engine._lane_origin_labels``): a row with physical spans counts
    only if a demanded byte of its node lies in them, a spanless one when its
    node is reached."""
    from .boundary import BoundaryKind
    from .lane_slice import FULL

    found = set()
    for row in rows:
        if row.kind is not BoundaryKind.SOURCE or row.node not in lanes.demands:
            continue
        demand = lanes.demands[row.node]
        span_of = lanes.definition_span(index, row.node)
        spans = [span for span in row.physical_spans if span_of is not None and span.object_id == span_of.object_id]
        if not spans or demand is FULL or any(byte in demand for span in spans for byte in range(span.start, span.end)):
            found.add(row.label)
    return found


@measured("witnesses")
def root_witnesses(normalized, unit, rows, seeds, labels, index, origins, traversal="lane") -> dict:
    """``seeds``: the root's lane seeds; ``labels``: its reported labels;
    ``origins``: node -> labels attached by summarized calls; ``traversal``:
    how the labels were found (``summary_engine._witnesses``)."""
    from .lane_slice import lane_slice

    graph = normalized.dependencies
    labels = set(labels)
    lanes = lane_slice(normalized, unit, seeds, index)
    free = labels_in_lanes(lane_slice(normalized, unit, seeds, index, ignore_debts=True), index, rows) & labels
    context = _Context(normalized, unit, origins)
    may_rows = dict(zip(normalized.may_alias_nodes, normalized.may_alias_reads))
    clobber_rows = dict(zip(normalized.call_clobber_nodes, normalized.call_clobber_reads))
    found: dict = {label: [] for label in labels}
    truncated: set = set()
    root_debts = []
    unattributed = []

    def add(label, witness):
        if len(found[label]) >= MAX_WITNESSES:
            truncated.add(label)
        elif witness not in found[label]:
            found[label].append(witness)

    for node in sorted(lanes.demands):
        record = graph.node(node)
        if record.kind is not NodeKind.MEMORY_DEBT:
            continue
        clobber = clobber_rows.get(node)
        if clobber is not None:
            # the value from before the calls reaches the read only if they
            # left those bytes unchanged
            root_debts.append({"kind": record.label, "sites": [clobber.operation_key]})
            seeds_before = context.clobbered_inputs(clobber)
            reached = labels_in_lanes(lane_slice(normalized, unit, seeds_before, index), index, rows) & labels \
                if seeds_before else set()
            calls = ", ".join(clobber.intervening_calls[:3]) + (" ..." if len(clobber.intervening_calls) > 3 else "")
            for label in sorted(reached):
                add(label, {"kind": "call_clobber", "sites": [clobber.operation_key],
                            "condition": f"the value from before {calls}, if they leave it unchanged",
                            "reason": None})
            produced = labels_in_lanes(lane_slice(normalized, unit, [(node, None)], index), index, rows) & labels
            for label in sorted(produced):
                add(label, {"kind": "call_value", "sites": [clobber.operation_key], "condition": None,
                            "reason": f"a value {calls} may have produced"})
            continue
        row = may_rows.get(node)
        if row is None or record.label != "may_alias_read":
            sites = sorted(context.consumers(node))
            root_debts.append({"kind": record.label, "sites": sites})
            reached = labels_in_lanes(lane_slice(normalized, unit, [(node, None)], index), index, rows) & labels
            for label in sorted(reached):
                add(label, {"kind": record.label, "sites": sites, "condition": None})
            continue
        root_debts.append({"kind": record.label, "sites": [row.operation_key]})
        for writer in sorted(row.writers):
            seeds_of_writer, callee = context.value_seeds(writer)
            if seeds_of_writer is None:
                unattributed.append(writer)
                continue
            reached = labels_in_lanes(lane_slice(normalized, unit, seeds_of_writer, index), index, rows) \
                if seeds_of_writer else set()
            condition, reason = context.condition(row, writer)
            for label in sorted((reached | callee) & labels):
                add(label, {
                    "kind": "may_alias", "writer": writer, "reader": row.operation_key,
                    "provenance": "local" if label in reached else "callee",
                    "condition": condition, "reason": reason,
                })
    return {
        "origin_witnesses": {
            label: {"has_debt_free_path": label in free, "witnesses": found[label],
                    "truncated": label in truncated, "traversal": traversal}
            for label in sorted(labels)
        },
        "root_debts": root_debts,
        "unattributed_writers": sorted(set(unattributed)),
    }


class _Context:
    def __init__(self, normalized, unit, origins) -> None:
        from .normalize import _storage_ref
        from .storage import _resolve_validated_storage

        self.normalized = normalized
        self.origins = origins or {}
        self.graph = normalized.dependencies
        self.context = unit.scopes.resolution_context
        self._resolve = lambda varnode: _resolve_validated_storage(_storage_ref(varnode), self.context)
        self.effects = {effect.operation_key: effect for effect in normalized.effects}
        self.operations = {}
        for instruction in unit.observation.instructions:
            for ordinal, operation in enumerate(instruction.operations):
                key = (f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}:"
                       f"{ordinal}:{operation.opcode}")
                self.operations[key] = operation
        self.value_inputs = dict(normalized.call_value_inputs)
        self.objects = dict(normalized.address_objects)
        self.atoms = dict(normalized.address_atoms)
        self.anchors = {row: (evaluation, anchor) for row, evaluation, anchor in normalized.call_anchors}
        self.clobbers: dict = {}
        for row, debt in zip(normalized.call_clobber_reads, normalized.call_clobber_nodes):
            self.clobbers.setdefault(row.operation_key, []).append((row.spans, debt))

    def node(self, key):
        try:
            return self.graph.node_for_key(f"op:{key}")
        except KeyError:
            return None

    def consumers(self, debt) -> set:
        found = set()
        for _, target, _ in self.graph._graph.out_edges(debt):
            key = self.graph.node(int(target)).key
            if key.startswith("op:"):
                found.add(key[3:])
        return found

    def _seeds(self, key, spans) -> list:
        """(definition node, the bytes of ``spans`` it supplies) for every
        definition operation ``key`` reads in ``spans`` -- lane seeds that
        stand for those bytes only."""
        node = self.node(key)
        if node is None:
            return []
        found = []
        for source, _, record in self.graph._graph.in_edges(node):
            if record.span is None:
                continue
            # each part: the bytes of that span this edge supplies
            parts = tuple(
                ByteSpan(span.object_id, max(span.start, record.span.start),
                         min(span.end, record.span.end) - max(span.start, record.span.start))
                for span in spans if record.span.overlaps(span) and span.object_id == record.span.object_id)
            if parts:
                found.append((int(source), parts))
        return found

    def _operand_inputs(self, key, varnode):
        """Nodes feeding ``varnode`` of operation ``key`` (span edges), plus the
        call-clobber debts on that operation whose spans overlap it."""
        node = self.node(key)
        resolved = self._resolve(varnode)
        if node is None or not hasattr(resolved, "span"):
            return None
        return [
            int(source) for source, _, record in self.graph._graph.in_edges(node)
            if record.span is not None and record.span.overlaps(resolved.span)
        ] + [
            debt for spans, debt in self.clobbers.get(key, ())
            if any(span.overlaps(resolved.span) for span in spans)
        ]

    def clobbered_inputs(self, clobber) -> list:
        """Seeds for the values from before the calls in the bytes they may
        have changed (operation ``clobber.operation_key``'s reads there)."""
        return self._seeds(clobber.operation_key, clobber.spans)

    def value_seeds(self, writer):
        """(seeds standing for the writer's stored value, labels its callee
        attached) -- (None, set()) for a writer of another shape."""
        operation = self.operations.get(writer)
        if operation is not None and operation.opcode == "STORE" and len(operation.inputs) == 3:
            if operation.inputs[2].kind.name == "CONSTANT":
                return [], set()
            value = self._resolve(operation.inputs[2])
            if not hasattr(value, "span"):
                return None, set()
            return self._seeds(writer, (value.span,)), set()
        base, _, tag = writer.rpartition("~")
        if tag.startswith("e") and tag[1:].isdigit():
            effect = self.effects.get(writer)
            if effect is None or len(effect.reads) < 2 or not hasattr(effect.reads[1], "span"):
                return None, set()
            return self._seeds(writer, (effect.reads[1].span,)), set()
        if tag.isdigit():
            stage = f"{base}~in{tag}"
            count = self.value_inputs.get(stage)
            effect = self.effects.get(stage)
            if count is None or effect is None:
                return None, set()
            spans = tuple(item.span for item in effect.reads[:count] if hasattr(item, "span"))
            seeds = self._seeds(stage, spans)
            from .interprocedural import run_definition_nodes

            callee = set()
            for definition in run_definition_nodes(self.normalized, writer):
                callee |= set(self.origins.get(definition, ()))
            return seeds, callee
        return None, set()

    def address_on_debt(self, key) -> bool:
        """The address of access ``key`` rests on a debt (or is not known)."""
        from .function_summary import _address_slice

        operation = self.operations.get(key)
        if operation is not None and operation.opcode in ("LOAD", "STORE") and len(operation.inputs) >= 2:
            if operation.inputs[1].kind.name == "CONSTANT":
                return False
            inputs = self._operand_inputs(key, operation.inputs[1])
        elif key in self.anchors:
            evaluation, anchor = self.anchors[key]
            if type(anchor) is tuple:
                node = self.node(anchor[1])
                inputs = [node] if node is not None else None
            else:
                inputs = self._operand_inputs(evaluation, anchor)
        else:
            return True
        if inputs is None:
            return True
        return any(self.graph.node(item).kind is NodeKind.MEMORY_DEBT for item in _address_slice(self.graph, inputs, {}))

    def _span(self, key, role):
        effect = self.effects.get(key)
        if effect is None:
            return None
        items = effect.reads if role == "read" else effect.writes
        spans = [item.span for item in items
                 if hasattr(item, "span") and item.span.object_id.kind not in _NOT_MEMORY]
        return spans[0] if len(spans) == 1 and spans[0].object_id.kind is _RELATIVE else None

    def condition(self, row, writer):
        """(condition text, None) or (None, reason)."""
        if row.unknown_address:
            return None, "the read's address is unknown"
        if writer in row.uncertain:
            return None, "uncertain-address writer"
        read, write = self._span(row.operation_key, "read"), self._span(writer, "write")
        if read is None or write is None:
            return None, "not one relative span each"
        r_atoms, r_space = self.objects.get(read.object_id, (None, None))
        w_atoms, w_space = self.objects.get(write.object_id, (None, None))
        if r_atoms is None or w_atoms is None or r_space != w_space:
            return None, "address expressions not recorded"
        r_map, w_map = dict(r_atoms), dict(w_atoms)
        w_only = {atom: c for atom, c in w_map.items() if r_map.get(atom) != c}
        r_only = {atom: c for atom, c in r_map.items() if w_map.get(atom) != c}
        if len(w_only) != 1 or len(r_only) != 1 or set(w_only.values()) != {1} or set(r_only.values()) != {1} \
                or set(w_only) & set(r_map) or set(r_only) & set(w_map):
            return None, "the addresses differ in more than one pointer"
        if self.address_on_debt(row.operation_key):
            return None, "the reader's address rests on a debt"
        if self.address_on_debt(writer):
            return None, "the writer's address rests on a debt"
        bits = next((b for b in (32, 64) if abs(read.start - (1 << b)) < 1 << (b - 2)), None)
        if bits is None:
            return None, "address width unknown"
        dr, dw = read.start - (1 << bits), write.start - (1 << bits)
        low, high = dr - dw - write.size + 1, dr - dw + read.size - 1
        (w_atom,), (r_atom,) = w_only, r_only
        text = (f"[{self.atoms.get(w_atom, f'atom {w_atom:#x}')}] - [{self.atoms.get(r_atom, f'atom {r_atom:#x}')}]"
                f" in [{low}, {high}] (mod 2^{bits})")
        if not low <= 0 <= high:
            text += "; equal pointers exclude this transfer"
        return text, None


__all__ = ("MAX_WITNESSES", "labels_in_lanes", "root_witnesses")
