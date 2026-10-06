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

CALLIND, CALLOTHER, external or unresolved targets, and memory spans are
never discharged here. Recursion is not special-cased: a self-call clobbers
the callee's own reads, so the PRESERVED trace fails.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..memory_contracts import MemoryDefinitionKind
from ..model import StorageObjectKind
from ..query import BackwardSliceQuery
from ..scope_identity import AddressCoordinate
from ..span_geometry import ByteSpan
from .configured_function_view import _FunctionView
from .configured_interprocedural_contracts import ObservedCallByteReplacement
from .configured_target_resolution import _selected_resolved_target

MAX_TRACE_DEPTH = 64


class DischargeKind(StrEnum):
    PRESERVED = "preserved"
    MUST_WRITTEN = "must_written"


@dataclass(frozen=True, slots=True)
class CallClobberDischarge:
    reader_operation_key: str
    debt_node: int
    kinds: tuple[DischargeKind, ...]


class CallClobberDischarger:
    """Per-program cache of callee facts; one instance per engine run."""

    def __init__(self, analyses) -> None:
        self._views = {analysis.entry: _FunctionView(analysis) for analysis in analyses}
        self._preserved: dict[tuple[AddressCoordinate, tuple[object, ...]], bool] = {}
        self._complete_writes: dict[tuple[AddressCoordinate, str], bool] = {}
        self._targets = {
            entry: _direct_internal_targets(view, self._views)
            for entry, view in self._views.items()
        }

    def discharge(
        self,
        entry: AddressCoordinate,
        replacements: tuple[ObservedCallByteReplacement, ...],
    ) -> tuple[CallClobberDischarge, ...]:
        normalized = self._views[entry].normalized
        targets = self._targets[entry]
        by_reader: dict[str, list[ObservedCallByteReplacement]] = {}
        for row in replacements:
            by_reader.setdefault(row.reader_operation_key, []).append(row)
        rows = []
        for read, node in zip(
            normalized.call_clobber_reads, normalized.call_clobber_nodes, strict=True
        ):
            kinds = self._discharge_read(read, targets, by_reader.get(read.operation_key, ()))
            if kinds is not None:
                rows.append(CallClobberDischarge(read.operation_key, node, kinds))
        return tuple(rows)

    def _discharge_read(self, read, targets, replacements):
        kinds: set[DischargeKind] = set()
        for span in read.spans:
            if all(
                call in targets and self._preserves(targets[call], span)
                for call in read.intervening_calls
            ):
                kinds.add(DischargeKind.PRESERVED)
                continue
            if len(read.intervening_calls) == 1 and any(
                row.proof.call_operation_key == read.intervening_calls[0]
                and row.read_span.contains(span)
                and row.proof.callee_entry == targets.get(read.intervening_calls[0])
                and self._write_slice_complete(
                    row.proof.callee_entry, row.proof.callee_write_operation_key
                )
                for row in replacements
            ):
                kinds.add(DischargeKind.MUST_WRITTEN)
                continue
            return None
        return tuple(sorted(kinds))

    # -- MUST_WRITTEN ------------------------------------------------------
    def _write_slice_complete(self, callee: AddressCoordinate, write_key: str) -> bool:
        key = (callee, write_key)
        if key not in self._complete_writes:
            view = self._views.get(callee)
            node = (
                None if view is None
                else view.normalized.dependencies.node_for_key(f"op:{write_key}")
            )
            self._complete_writes[key] = node is not None and BackwardSliceQuery().run(
                view.normalized, node
            ).is_complete
        return self._complete_writes[key]

    # -- PRESERVED ---------------------------------------------------------
    def _preserves(self, callee: AddressCoordinate, span: ByteSpan) -> bool:
        if span.object_id.kind is not StorageObjectKind.REGISTER_FILE:
            return False
        key = (callee, span.canonical_key)
        if key not in self._preserved:
            view = self._views.get(callee)
            self._preserved[key] = view is not None and _callee_preserves(view, span)
        return self._preserved[key]


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


def _callee_preserves(callee: _FunctionView, span: ByteSpan) -> bool:
    """Every exit restores ``span`` from its entry value, without clobbered reads."""
    covering = tuple(
        (definition_id, target)
        for definition_id, target in callee.terminal_data_writes()
        if target.contains(span)
    )
    if len(covering) != 1 or callee.normalized.memory_graph.unresolved_write_nodes:
        # an unresolved write could overwrite a saved copy between save and restore
        return False
    clobbered = {row.operation_key for row in callee.normalized.call_clobber_reads}
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


__all__ = (
    "CallClobberDischarge",
    "CallClobberDischarger",
    "DischargeKind",
)
