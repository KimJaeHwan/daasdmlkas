"""Post-analysis call-body expressions over the *selected* physical SSA.

No new analysis, ABI inference, or summary substitution happens here. Two
optional observers retain the derivation and normalization witnesses used by
the final analysis. Records refer to those immutable snapshots; missing or
stale witnesses leave an explicit unavailable call output. Trial snapshots
are replaced, never accumulated. Not a path-feasibility proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from .call_summary_effects import AnchoredSpan, MAX_POINTER_DEPTH
from .operation_records import _Builder, _Truncated, _span_dict, _span_text
from .span_geometry import ByteSpan, StorageObjectKind as Kind


def _key(unit):
    entry = unit.scopes.function.entry
    return f"{entry.space_id:x}:{entry.byte_offset:x}"


@dataclass(frozen=True)
class FunctionView:
    unit: object
    normalized: object
    summary: object
    anchors: tuple
    origins: tuple
    declared: tuple
    stages: tuple
    derivations: tuple
    approved: tuple
    pending_proofs: tuple


class RecordProvider:
    """Pass to ``analyze_units(record_provider=...)``, then to record APIs.

    A provider belongs to ONE analysis invocation. Publishing keeps only exact
    final object references (including callee SSA and effect, not equality).
    Real allocation/analysis errors propagate; there is no catch-all fallback.
    """

    def __init__(self):
        self.analysis_id = uuid4().hex
        self._normalizations = {}
        self._selected = {}
        self.views = {}

    def normalized(self, unit, normalized, stages):
        self._normalizations[_key(unit)] = (normalized, tuple(stages.items()))

    def selected(self, unit, normalized, derivations, approved=None, pending_proofs=None):
        candidate = self._normalizations.pop(_key(unit), None)
        stages = candidate[1] if candidate is not None and candidate[0] is normalized else ()
        self._selected[_key(unit)] = (normalized, stages, tuple(derivations.items()),
                                     tuple((call, frozenset(pairs)) for call, pairs in (approved or {}).items()),
                                     tuple((call, tuple(pairs.items())) for call, pairs in (pending_proofs or {}).items()))

    def publish(self, results):
        self.analysis_id = uuid4().hex
        views = {}
        for key, item in results.items():
            candidate = self._selected.get(key)
            if candidate is None or candidate[0] is not item.normalized or item.summary is None:
                continue
            derivations = []
            effects = dict(item.normalized.proven_call_effects)
            for call, receipt in candidate[2]:
                unit, normalized, summary, effect, anchors = receipt
                final = results.get(_key(unit))
                if final is not None and final.unit is unit and final.normalized is normalized \
                        and final.summary is summary and effects.get(call) is effect:
                    derivations.append((call, receipt))
            views[key] = FunctionView(
                item.unit, item.normalized, item.summary, tuple(item.anchors.items()),
                tuple((node, tuple(labels)) for node, labels in item.origins.items()),
                tuple(item.declared.items()), candidate[1], tuple(derivations), candidate[3], candidate[4],
            )
        self.views = views
        self.discard_trials()

    def discard_trials(self):
        self._normalizations.clear()
        self._selected.clear()

    def view(self, unit, normalized):
        view = self.views.get(_key(unit))
        return view if view is not None and view.unit is unit and view.normalized is normalized else None


def _anchored(span, anchors, depth=0):
    """The summary's symbolic entry-place identity, NOT address evaluation."""
    if span.object_id.kind is Kind.ADDRESS_SPACE:
        return AnchoredSpan(None, span.start, span.size, span.object_id.space_key, span)
    if span.object_id.kind is not Kind.FUNCTION_RELATIVE or span.object_id not in anchors:
        return None
    anchor, space = anchors[span.object_id]
    displacement = span.start - (1 << (8 * anchor.size))
    if anchor.object_id.kind is Kind.REGISTER_FILE:
        return AnchoredSpan(anchor, displacement, span.size, space)
    if depth >= MAX_POINTER_DEPTH:
        return None
    pointer = _anchored(anchor, anchors, depth + 1)
    return None if pointer is None else AnchoredSpan(None, displacement, span.size, space, pointer=pointer)


def _same_base(a, b):
    if a is None or b is None or (a.anchor, a.pointer, a.space_id) != (b.anchor, b.pointer, b.space_id):
        return False
    if a.anchor is None and a.pointer is None:
        return a.span is not None and b.span is not None and a.span.object_id == b.span.object_id
    return True


def _slice(parts, start, end, *, at=0):
    """Slice assembled bytes, retaining their producer/output selectors."""
    found = []
    for part in parts:
        low, high = max(start, part["at"][0]), min(end, part["at"][1])
        if low >= high:
            continue
        item = dict(part)
        item["at"] = [at + low - start, at + high - start]
        if not part.get("pruned"):
            offset = part["bytes"][0] + low - part["at"][0]
            item["bytes"] = [offset, offset + high - low]
        found.append(item)
    return found


def _covered(parts, size):
    cursor = 0
    for part in sorted(parts, key=lambda part: part["at"]):
        if part.get("pruned") or part["at"][0] != cursor:
            return False
        cursor = part["at"][1]
    return cursor == size


def _gaps(ranges, low, high):
    cursor = low
    for start, end in sorted(ranges):
        if start > cursor:
            yield cursor, min(start, high)
        cursor = max(cursor, end)
        if cursor >= high:
            return
    if cursor < high:
        yield cursor, high


def _coalesce(parts):
    found = []
    for part in sorted(parts, key=lambda part: part['at']):
        if found and found[-1]['at'][1] == part['at'][0] and found[-1]['bytes'][1] == part['bytes'][0] \
                and {k: v for k, v in found[-1].items() if k not in ('at', 'bytes')} == \
                    {k: v for k, v in part.items() if k not in ('at', 'bytes')}:
            found[-1]['at'][1] = part['at'][1]
            found[-1]['bytes'][1] = part['bytes'][1]
        else:
            found.append(dict(part))
    return found


class ExpressionBuilder(_Builder):
    """One context's local SSA index, sharing ONE bounded record DAG."""

    def __init__(self, normalized, unit, *, provider, parent=None, call=None, owner=None,
                 context=None, base_depth=0, approved=frozenset(), **options):
        super().__init__(normalized, unit, **options)
        self.provider = provider
        self.view = provider.view(unit, normalized)
        self.parent, self.call_key = parent, call
        self.owner = owner or self
        self.context = context or _key(unit)
        self.base_depth = base_depth
        self.current_depth = base_depth
        self.children = {}
        self.approved = approved
        self.alias_conditions = None
        if owner is not None:
            self.records = owner.records   # references, no copies of callee graphs/RAM

    def _new(self, key, record):
        record.update(function=_key(self.unit), context=self.context)
        try:
            return super()._new(key, record)
        except _Truncated:
            self.owner.truncated = True
            raise

    def _edge(self):
        if self.owner is self:
            return super()._edge()
        return self.owner._edge()

    def _cut(self, *args, **kwargs):
        self.owner.truncated = True
        return super()._cut(*args, **kwargs)

    def operation(self, node, depth):
        previous = self.current_depth
        self.current_depth = depth
        try:
            return super().operation(node, depth)
        finally:
            self.current_depth = previous

    def _unavailable(self, reason, size):
        return self._new(None, {"kind": "unavailable", "reason": reason, "size": size})["id"]

    def _conditions_hold(self, pairs):
        anchors = dict(self.view.anchors) if self.view is not None else {}
        return all((left := _anchored(read, anchors)) is not None
                   and (right := _anchored(write, anchors)) is not None
                   and (left, right) in self.approved for read, write in pairs)

    def _approved_disjoint(self, read, write):
        """Cover a crossing with final, symmetric non-alias range proofs."""
        anchors = dict(self.view.anchors) if self.view is not None else {}
        left, right = _anchored(read, anchors), _anchored(write, anchors)
        if left is None or right is None:
            return False
        covered = []
        for first, second in self.approved:
            for a, b in ((first, second), (second, first)):
                if _same_base(a, left) and a.displacement <= left.displacement \
                        and left.displacement + left.size <= a.displacement + a.size and _same_base(b, right):
                    low = max(right.displacement, b.displacement)
                    high = min(right.displacement + right.size, b.displacement + b.size)
                    if low < high:
                        covered.append((low, high))
        return not any(_gaps(covered, right.displacement, right.displacement + right.size))

    def _debt(self, node, depth):
        if self.parent is not None:
            if self.alias_conditions is None:
                from .function_summary import _alias_conditions
                self.alias_conditions = _alias_conditions(self.normalized)
            pairs = self.alias_conditions.get(node)
            if pairs and self._conditions_hold(pairs):
                if node not in self.id_of:
                    self._new(node, {'kind': 'condition', 'status': 'caller-proven disjoint',
                                     'call': self.call_key,
                                     'pairs': [[_span_dict(a), _span_dict(b)] for a, b in pairs]})
                return self.id_of[node]
        return super()._debt(node, depth)

    def _entry(self, node, definition):
        if self.parent is None:
            return super()._entry(node, definition)
        if node in self.id_of:
            return self.id_of[node]
        return self._bind(definition.span, key=node)

    def _bind(self, span, key=None):
        key = ("binding", span) if key is None else key
        if key in self.id_of:
            return self.id_of[key]
        record = self._new(key, {"kind": "binding", "span": _span_text(span), "size": span.size,
                                 "parts": [], "call": self.call_key})
        if span.object_id.kind in (Kind.ADDRESS_SPACE, Kind.FUNCTION_RELATIVE):
            access = _anchored(span, dict(self.view.anchors)) if self.view is not None else None
            if access is not None:
                address = {"space": access.space_id, "bits": self.address_bits.get(access.space_id, 64),
                           "displacement": access.displacement}
                if span.object_id.kind is Kind.ADDRESS_SPACE:
                    address["value"] = span.start
                else:
                    anchor, _ = dict(self.view.anchors)[span.object_id]
                    identifier = self._bind(anchor)
                    address["parts"] = [{"node": identifier, "bytes": [0, anchor.size], "at": [0, anchor.size]}]
                    self._edge()
                record["address"] = address
        parts, debts, adjustments = self._caller_entry(span)
        record["parts"], record["debts"] = parts, debts
        if adjustments:
            record["adjustments"] = adjustments
        if not _covered(parts, span.size):
            # SSA entry definitions can coalesce untouched adjacent bytes.
            # Retain holes explicitly; only a *demanded* hole is an error.
            record["unbound_ranges"] = list(_gaps([part['at'] for part in parts], 0, span.size))
        self._done(record)
        return record["id"]

    def _caller_entry(self, span):
        parent, call = self.parent, self.call_key
        stages = dict(parent.view.stages).get(call) if parent.view is not None else None
        if stages is None:
            return [], [], []
        loads, stack_delta = stages
        candidates = []
        adjustments = []
        if span.object_id.kind is Kind.REGISTER_FILE:
            # Every staging read precedes every output write. Use final SSA
            # fragments, not a second memory/address analysis at the CALL.
            for action_id, reads in parent.index.reads.items():
                key = parent.ssa.actions[action_id].operation_key
                if key.startswith(call + "~") and key[len(call) + 1:].startswith(("in", "ld", "sp", "cr", "cw")):
                    candidates.extend((read, read.span.start - span.start, action_id) for read in reads
                                      if read.span.object_id == span.object_id and read.span.overlaps(span))
            if stack_delta is not None and span.start <= stack_delta[0] \
                    and stack_delta[0] + stack_delta[1] <= span.end:
                at = stack_delta[0] - span.start
                adjustments.append({"at": [at, at + stack_delta[1]], "addend": stack_delta[2]})
        else:
            access = _anchored(span, dict(self.view.anchors)) if self.view is not None else None
            for loaded, stage in loads:
                if not _same_base(access, loaded):
                    continue
                operation = parent.graph.node_for_key("op:" + stage)
                action_id = parent.index.action_of.get(operation)
                for read in parent.index.reads.get(action_id, ()):
                    if read.span.object_id.kind in (Kind.ADDRESS_SPACE, Kind.FUNCTION_RELATIVE) \
                            and read.span.size == loaded.size:
                        candidates.append((read, loaded.displacement - access.displacement, action_id))
        parts, debts = self._pushed_parts(span), set()
        for read, offset, action_id in candidates:
            # deterministic cover: the same register can occur in several staging rows
            low, high = max(0, offset), min(span.size, offset + read.span.size)
            missing = list(_gaps([part['at'] for part in parts], low, high))
            if missing:
                fragments = parent._fragments(read, None, self.current_depth + 1)
                for start, end in missing:
                    parts.extend(_slice(fragments, start - offset, end - offset, at=start))
                debts.update(parent._debts(parent.normalized.memory_graph.action_nodes[action_id],
                                           self.current_depth + 1))
        return _coalesce(parts), sorted(debts), adjustments

    def _pushed_parts(self, span):
        """An observed CALL's transient STORE supplies these entry bytes.

        The core deliberately removes that push from caller SSA. Reading the
        old caller stack slot instead would be wrong when expanding callee
        RETURN-address calculations. No ABI or return-register guess is used.
        """
        access = _anchored(span, dict(self.view.anchors)) if self.view is not None else None
        if access is None or access.anchor is None or (access.anchor.start, access.anchor.size) != (0x20, 8) \
                or access.pointer is not None:
            return []
        low, high = max(0, access.displacement), min(8, access.displacement + access.size)
        if low >= high:
            return []
        space, address = self.call_key.split(':')[:2]
        instruction = next(row for row in self.parent.unit.observation.instructions
                           if (row.address.space_id, row.address.byte_offset) == (int(space, 16), int(address, 16)))
        from ._scope_contracts import VarnodeKindCode as V
        operations = instruction.operations
        if instruction.fallthrough is None or len(operations) not in (3, 4):
            return []
        adjust, push, call = operations[-3:]
        rsp = adjust.output
        if rsp is None or rsp.kind is not V.REGISTER or (rsp.coordinate.byte_offset, rsp.byte_size) != (0x20, 8) \
                or adjust.opcode != 'INT_SUB' or len(adjust.inputs) != 2 or adjust.inputs[0] != rsp \
                or adjust.inputs[1].kind is not V.CONSTANT or adjust.inputs[1].coordinate.byte_offset != 8 \
                or push.opcode != 'STORE' or len(push.inputs) != 3 or push.inputs[1] != rsp \
                or push.inputs[0].kind is not V.CONSTANT or push.inputs[0].coordinate.byte_offset != access.space_id \
                or push.inputs[2].kind is not V.CONSTANT or push.inputs[2].byte_size != 8 \
                or push.inputs[2].coordinate.byte_offset != instruction.fallthrough.byte_offset:
            return []
        if len(operations) == 3:
            if call.opcode != 'CALL':
                return []
        else:
            target = operations[0]
            if call.opcode != 'CALLIND' or len(call.inputs) != 1 or target.opcode != 'COPY' \
                    or len(target.inputs) != 1 or target.output is None or target.output.kind is not V.UNIQUE \
                    or target.output != call.inputs[0]:
                return []
        literal = push.inputs[2]
        identifier = self._new(None, {'kind': 'const', 'value': literal.coordinate.byte_offset,
                                     'size': literal.byte_size, 'witness': 'observed CALL push',
                                     'call': self.call_key})['id']
        self._edge()
        return [{'node': identifier, 'bytes': [low, high],
                 'at': [low - access.displacement, high - access.displacement]}]

    def _named(self, part, definition):
        part = super()._named(part, definition)
        call = self.records[part["node"]]
        if call["kind"] == "call":
            outputs = call.setdefault("expansions", [])
            output = _span_dict(definition.span)
            if not any(item["output"] == output for item in outputs):
                identifier = self._expand(call, definition.span)
                outputs.append({"output": output, "node": identifier})
                self._edge()
        return part

    def _exit_aliases_disjoint(self, run, caller_span, callee, anchors, effect, call, child):
        """Use final output projections to discharge exported-write crossings.

        Reuse final approved non-alias ranges, or the final projections of
        separately exported writes. Only exact same-object disjoint bytes
        (or distinct physical address spaces) prove anything in the latter
        case. Different symbolic objects are NOT assumed disjoint.
        """
        if not run.crossed or run.debts or any(not label.startswith('alias:') for label in run.crossed):
            return False
        for label in run.crossed:
            writer = label[len('alias:'):]
            writes = [d.span for d in callee.memory_ssa.definitions if d.operation_key == writer
                      and d.span.object_id.kind in (Kind.ADDRESS_SPACE, Kind.FUNCTION_RELATIVE)]
            if not writes:
                return False
            for written in writes:
                access = _anchored(written, anchors)
                # Coalesced exit writes can cover several individually
                # approved condition ranges. Reuse those final proofs only
                # when their union covers the entire crossing writer.
                proven = child._approved_disjoint(run.span, written)
                if proven:
                    continue
                for index, output in enumerate(effect.memory_runs, start=len(effect.runs)):
                    target = output.write
                    if not _same_base(access, target) or target.displacement > access.displacement \
                            or access.displacement + access.size > target.displacement + target.size:
                        continue
                    node = self.graph.node_for_key(f'op:{call}~{index}')
                    action = self.index.action_of.get(node)
                    if action is None:
                        continue
                    projected = [self.ssa.definitions[d].span for d in self.ssa.actions[action].write_definition_ids]
                    if len(projected) != 1 or projected[0].size != target.size:
                        continue
                    span = ByteSpan(projected[0].object_id,
                                    projected[0].start + access.displacement - target.displacement, access.size)
                    if span.object_id == caller_span.object_id:
                        proven = not span.overlaps(caller_span)
                    elif span.object_id.kind is Kind.ADDRESS_SPACE and caller_span.object_id.kind is Kind.ADDRESS_SPACE:
                        proven = span.object_id.space_key != caller_span.object_id.space_key
                    if proven:
                        break
                if not proven:
                    return False
        return True

    def _expand(self, call, caller_span):
        depth = self.current_depth + 1
        if depth > self.limits.depth:
            return self._cut(call["key"], "call expansion depth")
        receipt = dict(self.view.derivations).get(call["call"]) if self.view is not None else None
        if receipt is None:
            return self._unavailable("no selected raw-body derivation (model, recursive, or stale)", caller_span.size)
        unit, normalized, summary, effect, anchors = receipt
        if effect is not self.proven.get(call["call"]) or not call["row"].isdigit():
            return self._unavailable("effect/row witness mismatch", caller_span.size)
        approved = dict(self.view.approved).get(call['call'], frozenset())
        # An inner call's condition may be open in its own function but proven
        # at an outer caller. Follow the selected physical pair, not names or
        # transitive assumptions about arbitrary pointers.
        approved = approved | frozenset(pair for pair, located in
                                       dict(self.view.pending_proofs).get(call['call'], ())
                                       if self._conditions_hold((located,)))
        if summary.tail_exits or any(pair not in approved for pair in effect.writer_conditions):
            return self._unavailable("tail or unproven writer conditions", caller_span.size)
        if not summary.exits:
            return self._unavailable("callee has no normal exit", caller_span.size)
        child_view = self.provider.view(unit, normalized)
        if child_view is None or child_view.summary is not summary:
            return self._unavailable("callee snapshot mismatch", caller_span.size)
        context = self.context + "/" + call["call"] + "->" + _key(unit)
        if context not in self.children:
            self.children[context] = ExpressionBuilder(
                normalized, unit, provider=self.provider, parent=self, call=call["call"], owner=self.owner,
                context=context, base_depth=depth, origins=dict(child_view.origins),
                declared=dict(child_view.declared), limits=self.limits, approved=approved,
            )
        child = self.children[context]
        child.current_depth = depth
        index = int(call["row"])
        memory = index >= len(effect.runs)
        if memory:
            run_index = index - len(effect.runs)
            if run_index >= len(effect.memory_runs):
                return self._unavailable("not a value output row", caller_span.size)
            run = effect.memory_runs[run_index]
            action = self.index.action_of[self.graph.node_for_key("op:" + call["key"])]
            writes = [self.ssa.definitions[item].span for item in self.ssa.actions[action].write_definition_ids]
            if len(writes) != 1 or writes[0].size != run.write.size or not writes[0].contains(caller_span):
                return self._unavailable("ambiguous memory output projection", caller_span.size)
            target = run.write
            displacement = target.displacement + caller_span.start - writes[0].start
        else:
            if index >= len(effect.runs):
                return self._unavailable("not a register output row", caller_span.size)
            run = effect.runs[index]
            if not any(span.contains(caller_span) for span in run.writes):
                return self._unavailable("register output selector mismatch", caller_span.size)
            target, displacement = None, caller_span.start
        if any(pair not in approved for pair in run.conditions):
            return self._unavailable("unproven output conditions", caller_span.size)
        if not child._conditions_hold(summary.writer_conditions):
            return self._unavailable("unproven callee writer conditions", caller_span.size)
        record = self._new(None, {
            "kind": "call_output", "call": call["call"], "callee": _key(unit), "size": caller_span.size,
            "output": _span_dict(caller_span), "choice_group": context,
            "exit_domain": [exit.block_key for exit in summary.exits], "alternatives": [],
        })
        for exit in summary.exits:
            parts, covered = [], []
            for callee_run in exit.runs:
                if memory:
                    place = _anchored(callee_run.span, dict(anchors))
                    if not _same_base(place, target):
                        continue
                    start = place.displacement
                else:
                    if callee_run.span.object_id.kind is not Kind.REGISTER_FILE:
                        continue
                    start = callee_run.span.start
                low, high = max(displacement, start), min(displacement + caller_span.size, start + callee_run.span.size)
                if low >= high:
                    continue
                selected = ByteSpan(callee_run.span.object_id, callee_run.span.start + low - start, high - low)
                placed = ByteSpan(caller_span.object_id, caller_span.start + low - displacement, high - low)
                cleared_crossings = memory and self._exit_aliases_disjoint(
                    callee_run, placed, normalized, dict(anchors), effect, call['call'], child)
                if callee_run.kind.value == "identity":
                    identifier = child._bind(selected)
                    produced = [{"node": identifier, "bytes": [0, selected.size], "at": [0, selected.size]}]
                elif (callee_run.kind.value == "unknown" and not cleared_crossings) \
                        or not child._conditions_hold(callee_run.conditions) or callee_run.debts \
                        or (callee_run.crossed and not cleared_crossings):
                    identifier = child._unavailable("callee exit run not exact", selected.size)
                    produced = [{"node": identifier, "bytes": [0, selected.size], "at": [0, selected.size]}]
                else:
                    produced = child._run_parts(callee_run, selected, depth + 1)
                    if cleared_crossings:
                        proof = self._new(None, {'kind': 'condition', 'status': 'caller output bytes disjoint',
                                                  'call': call['call'], 'crossings': list(callee_run.crossed),
                                                  'output': _span_dict(placed)})
                        record.setdefault('debts', []).append(proof['id'])
                        self._edge()
                parts.extend({**part, "at": [part["at"][0] + low - displacement,
                                             part["at"][1] + low - displacement]} for part in produced)
                covered.append((low - displacement, high - displacement))
            # A byte absent on this exit is unchanged. Never infer this from
            # effect.preserved: that includes written output bytes as well.
            for low, high in _gaps(covered, 0, caller_span.size):
                if memory:
                    source = child._identity_memory(target, displacement + low, high - low)
                else:
                    source = child._bind(ByteSpan(caller_span.object_id, displacement + low, high - low))
                parts.append({"node": source, "bytes": [0, high - low], "at": [low, high]})
            for _ in parts:
                self._edge()
            record["alternatives"].append({"exit": exit.block_key, "parts": parts})
        self._done(record)
        return record["id"]

    def _identity_memory(self, target, displacement, size):
        # Find an original callee place using the same anchored identity.
        for exit in self.view.summary.exits:
            for run in exit.runs:
                place = _anchored(run.span, dict(self.view.anchors))
                if _same_base(place, target) and place.displacement <= displacement \
                        and displacement + size <= place.displacement + place.size:
                    return self._bind(ByteSpan(run.span.object_id, run.span.start + displacement - place.displacement, size))
        return self._unavailable("no identity memory place witness", size)

    def _run_parts(self, run, selected, depth):
        alternatives = []
        for definition in run.definitions:
            node = self.normalized.memory_graph.definition_nodes[definition]
            span = self.ssa.definitions[definition].span
            if span.contains(selected):
                alternatives.extend(self.seed(node, (selected,), depth))
        if len(alternatives) == 1:
            return alternatives
        if not alternatives:
            identifier = self._unavailable("missing exit SSA definition", selected.size)
        else:
            phi = self._new(None, {"kind": "phi", "reason": "exit run definitions", "size": selected.size,
                                    "alternatives": alternatives})
            for _ in alternatives:
                self._edge()
            self._done(phi)
            identifier = phi["id"]
        return [{"node": identifier, "bytes": [0, selected.size], "at": [0, selected.size]}]


__all__ = ("RecordProvider", "ExpressionBuilder")
