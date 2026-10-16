"""Discharge local call-clobber debt with exact internal-callee evidence.

``call_clobber_read`` debt (``tdo_v2.call_clobber``) says that bytes read at R
may come from before calls {C}. The debt for one span S is discharged only
when, for every intervening call C, the callee is an internal function and:

* PRESERVED: S is a register and every observed exit of the callee leaves S
  equal to its entry value through COPY/STORE/LOAD transfers, none of which
  reads bytes that the callee's own calls may clobber; or
* MUST_WRITTEN: C is the only intervening call and a certified
  ``ObservedCallByteReplacement`` attaches R's bytes to the callee's terminal
  write W, whose own backward slice in the callee is locally complete.

* FRAME_PRESERVED: S lies in the caller's own stack object (relative to its
  entry stack pointer) and the callee provably writes none of S's bytes.
  The call token gives the callee's entry stack pointer in caller
  coordinates, so S becomes an interval P relative to the callee's entry SP.
  Every memory write of the callee must be either relative to its own entry
  SP and disjoint from P, or to a constant loaded-image address (axiom: such
  an address is never a stack byte). A write through any other base
  (pointer argument, loaded pointer, opaque value), an unresolved write,
  CALLOTHER, or a register call-clobber read in the callee (an address may
  be computed from a clobbered register) fails the proof. Nested calls are
  checked recursively with P shifted by their own token, and each nested
  call's return-address slot counts as written. Recursion fails.

CALLIND, CALLOTHER, external or unresolved targets, and other memory are
never discharged here. For PRESERVED, a self-call clobbers the callee's own
reads, so the trace fails.
"""

from __future__ import annotations

from ..resource_limits import RESOURCE_FAILURES

from dataclasses import dataclass
from enum import StrEnum

from ..memory_contracts import MemoryDefinitionKind
from ..model import StorageObjectKind
from ..query import BackwardSliceQuery
from ..scope_identity import AddressCoordinate
from ..span_geometry import ByteSpan
from .configured_function_view import _FunctionView
from ..relative_memory import _function_relative_object_id
from .configured_interprocedural_contracts import (
    InterproceduralOriginProof,
    InterproceduralTransferProof,
    ObservedCallByteReplacement,
)
from .configured_recursive_frame_inventory import build_recursive_frame_inventory
from .configured_target_resolution import _selected_resolved_target

MAX_TRACE_DEPTH = 64
MAX_FRAME_DEPTH = 16
MAX_FRAME_OFFSET = 1 << 31


class DischargeKind(StrEnum):
    PRESERVED = "preserved"
    MUST_WRITTEN = "must_written"
    FRAME_PRESERVED = "frame_preserved"
    OUTPARAM_MUST_WRITTEN = "outparam_must_written"


@dataclass(frozen=True, slots=True)
class CallClobberDischarge:
    reader_operation_key: str
    debt_node: int
    kinds: tuple[DischargeKind, ...]


class CallClobberDischarger:
    """Per-program cache of callee facts; one instance per engine run.

    Debt is judged in a *context*: the root function uses its completion's
    certified replacements and origin proofs; a callee reached while proving
    a root's debt uses the proof chain's prior transfers. The same rules apply
    recursively, guarded against cycles and depth.
    """

    def __init__(self, analyses) -> None:
        self._views = {analysis.entry: _FunctionView(analysis) for analysis in analyses}
        self._targets = {
            entry: _direct_internal_targets(view, self._views)
            for entry, view in self._views.items()
        }
        self._frames: dict[AddressCoordinate, _Frame | None] = {}
        self._preserved: dict[tuple[AddressCoordinate, tuple[object, ...]], bool] = {}
        self._frame_safe: dict[tuple[AddressCoordinate, int, int], bool] = {}
        self._clobber_rows = {
            entry: dict(zip(
                view.normalized.call_clobber_nodes,
                view.normalized.call_clobber_reads,
                strict=True,
            ))
            for entry, view in self._views.items()
        }

    def discharge(
        self,
        entry: AddressCoordinate,
        replacements: tuple[ObservedCallByteReplacement, ...],
        proofs: tuple[InterproceduralOriginProof, ...] = (),
        labels: tuple[str, ...] = (),
    ) -> tuple[CallClobberDischarge, ...]:
        """``labels`` are the origin labels the root reports (local and proven)."""
        context = _Context.root(replacements, proofs, labels)
        rows = []
        for node, read in self._clobber_rows[entry].items():
            kinds = self._discharge_read(entry, read, context, ())
            if kinds is not None:
                rows.append(CallClobberDischarge(read.operation_key, node, kinds))
        return tuple(rows)

    # -- one read in one context ---------------------------------------------
    def _discharge_read(self, entry, read, context, active):
        marker = (entry, read.operation_key)
        if marker in active or len(active) >= MAX_FRAME_DEPTH:
            return None
        active = (*active, marker)
        targets = self._targets[entry]
        kinds: set[DischargeKind] = set()
        for span in read.spans:
            kind = self._discharge_span(entry, read, span, targets, context, active)
            if kind is None:
                return None
            kinds.add(kind)
        return tuple(sorted(kinds))

    def _discharge_span(self, entry, read, span, targets, context, active):
        calls = read.intervening_calls
        if all(c in targets for c in calls):
            if span.object_id.kind is StorageObjectKind.REGISTER_FILE and all(
                self._preserves(targets[c], span, active) for c in calls
            ):
                return DischargeKind.PRESERVED
            if span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE and all(
                self._frame_preserved(entry, c, span, active) for c in calls
            ):
                return DischargeKind.FRAME_PRESERVED
        if len(calls) == 1 and any(
            row.proof.call_operation_key == calls[0]
            and row.read_span.contains(span)
            and row.proof.callee_entry == targets.get(calls[0])
            and self._write_slice_effective(
                row.proof.callee_entry,
                row.proof.callee_write_operation_key,
                row.proof.prior_transfers,
                active,
                entry,
                calls[0],
                context,
            )
            for row in context.replacements.get(read.operation_key, ())
        ):
            return DischargeKind.MUST_WRITTEN
        for evidence, chain in context.evidence:
            if self._evidence_discharges(entry, read, span, evidence, chain, context, active):
                return (
                    DischargeKind.MUST_WRITTEN
                    if span.object_id.kind is StorageObjectKind.REGISTER_FILE
                    else DischargeKind.OUTPARAM_MUST_WRITTEN
                )
        return None

    # -- MUST_WRITTEN from an origin proof / transfer -------------------------
    def _evidence_discharges(self, entry, read, span, evidence, chain, context, active) -> bool:
        """The callee of one intervening call is the last writer of ``span``."""
        call = evidence.call_operation_key
        targets = self._targets[entry]
        view = self._views[entry]
        if (
            call not in read.intervening_calls
            or targets.get(call) != evidence.callee_entry
            or evidence.caller_scope_digest != view.memory.function_scope.digest
            or evidence.pointer_dereferences != 0
            or not evidence.target_span.contains(span)
        ):
            return False
        callee = evidence.callee_entry
        write_key = evidence.callee_write_operation_key
        if not self._ordered_last_call(entry, read, span, call, active):
            return False
        if span.object_id.kind is StorageObjectKind.REGISTER_FILE:
            if not self._terminal_register_write(callee, write_key, span):
                return False
        else:
            interval = self._callee_interval(entry, call, span)
            if interval is None or not self._outparam_must_write(
                callee, write_key, *interval, chain, context, active
            ):
                return False
        return self._write_slice_effective(
            callee, write_key, chain, active, entry, call, context
        )

    def _ordered_last_call(self, entry, read, span, call, active) -> bool:
        """``call`` runs before the read on every path and no later call may clobber."""
        view = self._views[entry]
        if not view.definitely_precedes(call, read.operation_key):
            return False
        targets = self._targets[entry]
        for other in read.intervening_calls:
            if other == call or not view.may_precede(call, other):
                continue
            if other not in targets:
                return False
            if span.object_id.kind is StorageObjectKind.REGISTER_FILE:
                if not self._preserves(targets[other], span, active):
                    return False
            elif not self._frame_preserved(entry, other, span, active):
                return False
        return True

    def _terminal_register_write(self, callee, write_key, span) -> bool:
        view = self._views.get(callee)
        if view is None:
            return False
        return any(
            definition.operation_key == write_key
            and definition.kind is MemoryDefinitionKind.DATA_WRITE
            and definition.span.contains(span)
            and _sole_terminal_writer(view, definition_id, span)
            for definition_id, definition in enumerate(view.memory.definitions)
        )

    def _outparam_must_write(self, callee, write_key, start, stop, chain, context, active) -> bool:
        """The callee's last write to the caller bytes is ``write_key`` on every exit.

        ``[start, stop)`` is the caller span relative to the callee's entry SP.
        Every other memory write must be provably elsewhere, and the callee's
        own call debt must be discharged so its address chain is exact.
        """
        view = self._views.get(callee)
        frame = None if view is None else self._frame(callee)
        if frame is None or frame.unresolved_writes:
            return False
        written = tuple(
            definition_id
            for definition_id, definition in enumerate(view.memory.definitions)
            if definition.operation_key == write_key
            and definition.kind is MemoryDefinitionKind.DATA_WRITE
            and definition.span.object_id.kind is not StorageObjectKind.REGISTER_FILE
        )
        if len(written) != 1:
            return False
        (written_id,) = written
        definition = view.memory.definitions[written_id]
        base = definition.span.object_id
        if base.kind is not StorageObjectKind.FUNCTION_RELATIVE or base == frame.stack_object:
            return False
        if not _sole_terminal_writer(view, written_id, definition.span):
            return False  # not the only last write on every exit
        if any(object_id not in (base,) for object_id in frame.other_bases):
            return False  # a write through another pointer may alias
        if any(low < stop and start < high for low, high in frame.stack_writes):
            return False
        if not self._nested_calls_frame_safe(callee, frame, start, stop, active):
            return False
        return self._function_effective(callee, chain, context, active)

    def _callee_interval(self, caller, call, span):
        frame = self._frame(caller)
        if frame is None or span.object_id != frame.stack_object:
            return None
        token = frame.tokens.get(call)
        if token is None:
            return None
        start = span.start - frame.bias - token
        if start < frame.slot and 0 < start + span.size:
            return None  # the call itself writes the return-address slot
        return start, start + span.size

    # -- effective completeness inside a callee -------------------------------
    def _write_slice_effective(self, callee, write_key, chain, active, caller, call, context) -> bool:
        """W's value is fully explained: the callee's debt is discharged, and every
        value it takes from caller registers is itself complete with reported
        origins. ``_value_origins`` may silently skip an entry input whose caller
        state it cannot map, so the existence of a proof alone does not show that
        all origins were found.
        """
        view = self._views.get(callee)
        if view is None:
            return False
        node = view.normalized.dependencies.node_for_key(f"op:{write_key}")
        if node is None:
            return False
        if self._reported_source_write(view, write_key, context):
            return True  # a source boundary: its value is the reported label by definition
        result = BackwardSliceQuery().run(view.normalized, node)
        if result.function_unresolved_write_nodes:
            return False
        inner = context.callee(chain)
        if not self._debt_discharged(callee, result.reachable_unresolved_read_nodes, inner, active):
            return False
        if not self._labels_reported(view, result.reachable_nodes, context):
            return False
        entries = dict(view.normalized.memory_graph.entry_bindings)
        position = self._views[caller].position(call)
        if position is None:
            return False
        for input_node in result.observed_input_nodes:
            storage = entries.get(input_node)
            if storage is None or storage.span.object_id.kind is not StorageObjectKind.REGISTER_FILE:
                return False  # a value read from caller memory: not proven in v1
            if not self._caller_state_explained(caller, storage.span, position, context, active):
                return False
        return True

    def _caller_state_explained(self, caller, span, position, context, active) -> bool:
        view = self._views[caller]
        definition_id = view.state_definition(span, position)
        if definition_id is None:
            return False
        node = view.normalized.memory_graph.definition_nodes[definition_id]
        result = BackwardSliceQuery().run(view.normalized, node)
        if result.function_unresolved_write_nodes:
            return False
        if not self._debt_discharged(caller, result.reachable_unresolved_read_nodes, context, active):
            return False
        return self._labels_reported(view, result.reachable_nodes, context)

    @staticmethod
    def _reported_source_write(view, write_key, context) -> bool:
        """W's own definition is a SOURCE origin node whose label the root reports."""
        written = {
            view.normalized.memory_graph.definition_nodes[definition_id]
            for definition_id, definition in enumerate(view.memory.definitions)
            if definition.operation_key == write_key
        }
        return any(
            boundary.node in written and boundary.label in context.labels
            for boundary in view.analysis.boundaries.report_origins
        )

    @staticmethod
    def _labels_reported(view, reachable_nodes, context) -> bool:
        reachable = set(reachable_nodes)
        return all(
            boundary.label in context.labels
            for boundary in view.analysis.boundaries.report_origins
            if boundary.node in reachable
        )

    def _function_effective(self, callee, chain, context, active) -> bool:
        view = self._views[callee]
        if view.normalized.memory_graph.unresolved_write_nodes:
            return False
        return self._debt_discharged(
            callee, tuple(self._clobber_rows[callee]), context.callee(chain), active
        )

    def _debt_discharged(self, callee, nodes, context, active) -> bool:
        rows = self._clobber_rows[callee]
        for node in nodes:
            read = rows.get(node)
            if read is None:
                return False  # unresolved memory debt, not call debt
            if self._discharge_read(callee, read, context, active) is None:
                return False
        return True

    # -- PRESERVED -----------------------------------------------------------
    def _preserves(self, callee: AddressCoordinate, span: ByteSpan, active) -> bool:
        key = (callee, span.canonical_key)
        if key not in self._preserved:
            view = self._views.get(callee)
            self._preserved[key] = view is not None and _callee_preserves(
                view,
                span,
                lambda operation_key: self._callee_read_discharged(callee, operation_key, active),
            )
        return self._preserved[key]

    def _callee_read_discharged(self, callee, operation_key, active) -> bool:
        context = _EMPTY_CONTEXT
        return all(
            self._discharge_read(callee, read, context, active) is not None
            for read in self._clobber_rows[callee].values()
            if read.operation_key == operation_key
        )

    # -- FRAME_PRESERVED -----------------------------------------------------
    def _frame(self, entry: AddressCoordinate) -> "_Frame | None":
        if entry not in self._frames:
            self._frames[entry] = _Frame.build(self._views[entry])
        return self._frames[entry]

    def _frame_preserved(self, caller, call: str, span: ByteSpan, active) -> bool:
        interval = self._callee_interval(caller, call, span)
        if interval is None or call not in self._targets[caller]:
            return False
        return self._callee_frame_safe(self._targets[caller][call], *interval, active)

    def _callee_frame_safe(self, callee, start: int, stop: int, active) -> bool:
        """The callee never writes [start, stop) relative to its entry stack pointer."""
        if abs(start) >= MAX_FRAME_OFFSET or abs(stop) >= MAX_FRAME_OFFSET:
            return False
        if len(active) >= MAX_FRAME_DEPTH or any(item[0] == callee for item in active):
            return False
        key = (callee, start, stop)
        if key not in self._frame_safe:
            self._frame_safe[key] = self._check_callee_frame(callee, start, stop, active)
        return self._frame_safe[key]

    def _check_callee_frame(self, callee, start: int, stop: int, active) -> bool:
        frame = self._frame(callee)
        if frame is None or not frame.write_safe(start, stop):
            return False
        if not self._nested_calls_frame_safe(callee, frame, start, stop, active):
            return False
        # an address computed from a call-clobbered register must be re-proved
        context = _EMPTY_CONTEXT
        nested = (*active, (callee, ""))
        return all(
            self._discharge_read(callee, read, context, nested) is not None
            for read in self._clobber_rows[callee].values()
            if any(s.object_id.kind is StorageObjectKind.REGISTER_FILE for s in read.spans)
        )

    def _nested_calls_frame_safe(self, callee, frame, start, stop, active) -> bool:
        if set(frame.calls) - set(frame.tokens):
            return False  # a call without an observed stack token
        targets = self._targets[callee]
        nested = (*active, (callee, ""))
        for call, token in frame.tokens.items():
            if token < stop and start < token + frame.slot:
                return False  # the nested call's return-address slot
            if call not in targets or not self._callee_frame_safe(
                targets[call], start - token, stop - token, nested
            ):
                return False
        return True


@dataclass(frozen=True, slots=True)
class _Context:
    """Evidence available while judging debt in one function."""

    replacements: dict[str, tuple[ObservedCallByteReplacement, ...]]
    evidence: tuple[tuple[object, tuple[InterproceduralTransferProof, ...]], ...]
    labels: frozenset[str]

    @staticmethod
    def root(replacements, proofs, labels) -> "_Context":
        by_reader: dict[str, list[ObservedCallByteReplacement]] = {}
        for row in replacements:
            by_reader.setdefault(row.reader_operation_key, []).append(row)
        return _Context(
            {key: tuple(rows) for key, rows in by_reader.items()},
            tuple((proof, proof.prior_transfers) for proof in proofs),
            frozenset(labels),
        )

    def callee(self, chain) -> "_Context":
        return _Context({}, tuple((transfer, chain) for transfer in chain), self.labels)


@dataclass(frozen=True, slots=True)
class _Frame:
    """Stack-frame facts of one function, relative to its entry stack pointer."""

    stack_object: object
    bias: int
    slot: int
    tokens: dict[str, int]  # call key -> callee entry SP displacement
    calls: tuple[str, ...]  # every CALL/CALLIND operation key
    stack_writes: tuple[tuple[int, int], ...]
    other_bases: tuple[object, ...]  # write bases other than the stack or constants
    unresolved_writes: bool  # unresolved write or CALLOTHER

    @staticmethod
    def build(view: _FunctionView) -> "_Frame | None":
        try:
            inventory = build_recursive_frame_inventory(view.analysis)
        except RESOURCE_FAILURES:  # a resource failure is no verdict
            raise
        except Exception:  # an inventory we cannot build proves nothing
            return None
        anchors = {
            (row.interval.anchor_span, row.interval.address_space_id)
            for row in (*inventory.call_tokens, *inventory.return_tokens)
        }
        if len(anchors) != 1:
            return None
        ((anchor_span, space_id),) = anchors
        bits = view.space_bits.get(space_id)
        if bits is None:
            return None
        stack_object = _function_relative_object_id(
            view.memory.function_scope, anchor_span, space_id
        )
        bias = 1 << bits
        normalized = view.normalized
        keys = tuple(view.operations)
        unresolved = bool(normalized.memory_graph.unresolved_write_nodes) or any(
            key.endswith(":CALLOTHER") for key in keys
        )
        writes = []
        other_bases = set()
        for definition in view.memory.definitions:
            if definition.kind not in (MemoryDefinitionKind.DATA_WRITE, MemoryDefinitionKind.KILL):
                continue
            kind = definition.span.object_id.kind
            if kind in (StorageObjectKind.REGISTER_FILE, StorageObjectKind.FUNCTION_UNIQUE):
                continue
            if kind is StorageObjectKind.ADDRESS_SPACE:
                continue  # axiom: a constant loaded-image address is never a stack byte
            if definition.span.object_id != stack_object:
                other_bases.add(definition.span.object_id)  # pointer argument or loaded pointer
                continue
            writes.append((definition.span.start - bias, definition.span.end - bias))
        return _Frame(
            stack_object,
            bias,
            anchor_span.size,
            {row.call_operation_key: row.interval.offset for row in inventory.call_tokens},
            tuple(sorted(key for key in keys if key.endswith((":CALL", ":CALLIND")))),
            tuple(writes),
            tuple(sorted(other_bases, key=lambda item: (item.kind.value, item.scope.digest, item.space_key))),
            unresolved,
        )

    def write_safe(self, start: int, stop: int) -> bool:
        """No write of this function (ignoring its calls) can touch [start, stop)."""
        if self.unresolved_writes or self.other_bases:
            return False
        return not any(low < stop and start < high for low, high in self.stack_writes)


def _sole_terminal_writer(view, definition_id: int, span: ByteSpan) -> bool:
    """On every observed exit, every byte of ``span`` holds exactly this definition.

    ``_shared_terminal_writes`` only requires the definition to be among the
    reaching ones (a JOIN with the entry value still qualifies), which is not
    a must-write.
    """
    states = view.memory.observed_terminal_states
    if not states or any(state.root_node_id is None for state in states):
        return False
    for state in states:
        covered = 0
        for atom, definition_ids in view._terminal_definition_map(state.root_node_id).items():
            if atom.object_id != span.object_id or not atom.overlaps(span):
                continue
            if tuple(definition_ids) != (definition_id,):
                return False
            covered += min(atom.end, span.end) - max(atom.start, span.start)
        if covered != span.size:
            return False
    return True


def _direct_internal_targets(view, views) -> dict[str, AddressCoordinate]:
    """Call operation key -> exact internal callee entry (direct CALL only)."""
    targets = {}
    evidence = view.analysis.evidence
    for seed, naming in zip(evidence.seeds.callsites, evidence.naming.rows, strict=True):
        target = _selected_resolved_target(naming)
        if (
            seed.operation_key.endswith(":CALL")
            and target is not None
            and not target.is_external
            and target.coordinate in views
        ):
            targets[seed.operation_key] = target.coordinate
    return targets


def _callee_preserves(callee: _FunctionView, span: ByteSpan, read_ok) -> bool:
    """Every exit restores ``span`` from its entry value.

    A step that reads call-clobbered bytes is accepted only if ``read_ok``
    discharges that read's debt inside the callee.
    """
    covering = tuple(
        (definition_id, target)
        for definition_id, target in callee.terminal_data_writes()
        if target.contains(span)
    )
    if len(covering) != 1 or callee.normalized.memory_graph.unresolved_write_nodes:
        # an unresolved write could overwrite a saved copy between save and restore
        return False
    clobbered = {row.operation_key for row in callee.normalized.call_clobber_reads}
    accepted: dict[str, bool] = {}
    definition_id, full = covering[0]
    active: set[tuple[int, tuple[object, ...]]] = set()

    def trace(definition_id: int, requested: ByteSpan, depth: int) -> bool:
        marker = (definition_id, requested.canonical_key)
        if depth > MAX_TRACE_DEPTH or marker in active:
            return False
        active.add(marker)
        try:
            definition = callee.memory.definitions[definition_id]
            if definition.kind is MemoryDefinitionKind.ENTRY:
                return definition.span.contains(requested) and requested == full
            if (
                definition.kind is not MemoryDefinitionKind.DATA_WRITE
                or definition.span != requested
            ):
                return False
            key = definition.operation_key
            if key in clobbered:
                if key not in accepted:
                    accepted[key] = read_ok(key)
                if not accepted[key]:
                    return False
            operation = callee.operation(key)
            if operation is None:
                return False
            if operation.opcode in ("COPY", "CAST") and len(operation.inputs) == 1:
                parent = callee.definition_for_input(key, operation.inputs[0])
                return parent is not None and trace(*parent, depth + 1)
            if operation.opcode == "STORE" and len(operation.inputs) == 3:
                parent = callee.definition_for_input(key, operation.inputs[2])
                return parent is not None and trace(*parent, depth + 1)
            if operation.opcode == "LOAD" and operation.output is not None:
                action_id = callee.action_ids.get(key)
                reads = tuple(
                    read for read in callee.memory.reads
                    if read.action_id == action_id
                    and read.span.object_id.kind in (
                        StorageObjectKind.ADDRESS_SPACE,
                        StorageObjectKind.FUNCTION_RELATIVE,
                    )
                    and read.span.size == operation.output.byte_size
                    and len(read.fragments) == 1
                    and read.fragments[0].span == read.span
                    and len(read.fragments[0].definition_ids) == 1
                )
                return len(reads) == 1 and trace(
                    reads[0].fragments[0].definition_ids[0], reads[0].span, depth + 1
                )
            return False
        finally:
            active.remove(marker)

    return trace(definition_id, full, 0)


_EMPTY_CONTEXT = _Context({}, (), frozenset())


__all__ = (
    "CallClobberDischarge",
    "CallClobberDischarger",
    "DischargeKind",
)
