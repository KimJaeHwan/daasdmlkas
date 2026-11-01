"""Select existing unconditional scalar call-value contracts, not new proofs.

Staging temporaries aggregate dependencies and are NOT numeric values. The
selected metadata names original pre-output register or memory byte reads.
Consumers retain their own source-debt, taint and final-use debt checks.
"""

from dataclasses import dataclass

from .model import ByteSpan, ResolvedStorage, StorageObjectKind
from .resource_limits import step


@dataclass(frozen=True, slots=True)
class CallValuePort:
    row: tuple
    width: int


def _overlapping_register_outputs(effect):
    groups, blocked = {}, set()
    for index, run in enumerate(effect.runs):
        for span in run.writes:
            step()
            groups.setdefault(span.object_id, []).append((span.start, span.end, index))
    for spans in groups.values():
        stop, owner = -1, None
        for start, end, index in sorted(spans):
            step()
            if start < stop:
                blocked.update((owner, index))
            if end > stop:
                stop, owner = end, index
    return blocked


def scalar_call_rows(normalized):
    """Cross-check scalar metadata against its original proven run and source.

    No allocator identity, accessor result, conditional or overlapping output
    is converted to a scalar identity here. A source with debt remains such
    a source; this selector does not certify its numeric value.
    """
    if not normalized.pointer_rows or not normalized.proven_call_effects \
            or normalized.memory_ssa is None or normalized.scopes is None \
            or normalized.scopes.program.evidence.translation_namespace.language_id.split(":")[1:2] != ["LE"]:
        return {}
    from ._scope_contracts import ValidatedVarnode, VarnodeKindCode
    from .call_summary_effects import AnchoredSpan, call_load_keys
    from .relative_memory import _storage_ref
    from .storage import _resolve_validated_storage

    rows = {key: row for key, row in normalized.pointer_rows
            if type(row) is tuple and row and row[0] in ("const", "reg", "off", "mem")}
    if not rows:
        return {}
    overlapped = {key for _, keys in normalized.overlap_rows for key in keys}
    ssa = normalized.memory_ssa
    step(len(ssa.actions))
    outputs, actions = {}, {row.operation_key: (index, row) for index, row in enumerate(ssa.actions)}
    memory_reads = None
    context = normalized.scopes.resolution_context
    for call, effect in normalized.proven_call_effects:
        if effect.writer_conditions:
            continue
        overlap_registers = _overlapping_register_outputs(effect)
        loads = None
        for index, run in enumerate((*effect.runs, *effect.memory_runs)):
            step()
            key = f"{call}~{index}"
            row = rows.get(key)
            if row is None or key not in actions or key in overlapped or index in overlap_registers or run.conditions:
                continue
            widths = tuple(span.size for span in run.writes) if index < len(effect.runs) else (run.write.size,)
            if len(widths) != 1 or type(widths[0]) is not int or not 0 < widths[0] <= 16 \
                    or type(row) is not tuple or not row:
                continue
            width = widths[0]
            definitions = [ssa.definitions[i] for i in actions[key][1].write_definition_ids]
            if len(definitions) != 1 or definitions[0].span.size != width \
                    or index < len(effect.runs) and definitions[0].span != run.writes[0]:
                continue
            if row[0] == "const":
                if len(row) == 3 and type(row[1]) is int and type(row[2]) is int \
                        and run.literal is not None and row == ("const", width, run.literal.unsigned) \
                        and run.literal.byte_size == width:
                    outputs[key] = CallValuePort(row, width)
                continue
            value = run.value
            if value is None or type(value) is not tuple or len(value) != 3:
                continue
            if row[0] in ("reg", "off"):
                if row[0] == "reg":
                    if len(row) != 5 or value[0] != "same_reg" or value[2] is not False \
                            or row[3] is not False or type(row[4]) is not bool:
                        continue
                elif len(row) != 4 or value[0] != "offset_reg" \
                        or type(row[3]) is not int or row[3] != value[2]:
                    continue
                if row[1] != f"{call}~in{index}" or row[1] not in actions \
                        or type(row[2]) is not ValidatedVarnode or type(value[1]) is not ByteSpan \
                        or row[2].kind is not VarnodeKindCode.REGISTER:
                    continue
                source = _resolve_validated_storage(_storage_ref(row[2]), context)
                if type(source) is not ResolvedStorage or source.span != value[1] \
                        or source.span.object_id.kind is not StorageObjectKind.REGISTER_FILE \
                        or source.span.size != width:
                    continue
            elif row[0] == "mem":
                if len(row) != 5 or value[0] != "same_mem" or value[2] is not False \
                        or row[3] is not False or type(row[4]) is not bool \
                        or type(row[2]) is not int or row[2] != width \
                        or type(value[1]) is not AnchoredSpan or value[1].size != width:
                    continue
                if loads is None:
                    loads = call_load_keys(call, effect)
                if loads.get(value[1]) != row[1] or row[1] not in actions:
                    continue
                if memory_reads is None:
                    step(len(ssa.reads) + len(ssa.unresolved_reads) + len(normalized.may_alias_reads))
                    memory_reads = {}
                    for read in ssa.reads:
                        if read.span.object_id.kind in (StorageObjectKind.ADDRESS_SPACE,
                                                       StorageObjectKind.FUNCTION_RELATIVE):
                            memory_reads.setdefault(read.action_id, []).append(read)
                    unresolved = {read.action_id for read in ssa.unresolved_reads}
                    unknown = {read.operation_key for read in normalized.may_alias_reads if read.unknown_address}
                read_id = actions[row[1]][0]
                reads = memory_reads.get(read_id, ())
                if read_id in unresolved or row[1] in unknown or len(reads) != 1 \
                        or reads[0].span.size != width or reads[0].span.object_id in normalized.wild_objects:
                    continue
            else:
                continue
            outputs[key] = CallValuePort(row, width)
    return outputs
