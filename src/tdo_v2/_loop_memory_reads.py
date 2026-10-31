"""Same-visit last-STORE fragments over the existing affine family cut-DAG.

No new SSA, global fixed point, visit/path enumeration or memory-object
assumption. Each family shares one finite interval must-analysis. Entry is
unknown; predecessor meets retain only identical writers and byte maps.
All original uncertain/alias reads remain in the graph, even after a proof.
"""

from dataclasses import replace

from ._loop_memory import LoopMemoryReadFrom
from ._scope_contracts import TranslationNamespace, VarnodeKindCode
from .model import ByteSpan, StorageObjectKind
from .resource_limits import step


def derive_read_from(index, memory, families, accesses, namespace):
    # Byte offsets are significance offsets only with original LE semantics.
    if type(namespace) is not TranslationNamespace or namespace.language_id.split(":")[1:2] != ["LE"]:
        return ()
    writers = {row.operation_key: (number, row) for number, row in enumerate(accesses) if row.direction == "write"}
    groups = {(row.family_index, row.space_id) for _, row in writers.values()}
    readers = {(row.family_index, row.space_id): {} for row in accesses
               if row.direction == "read" and (row.family_index, row.space_id) in groups}
    for number, row in enumerate(accesses):
        if row.direction == "read" and (row.family_index, row.space_id) in readers:
            readers[row.family_index, row.space_id][row.operation_key] = number, row
    if not writers or not readers:
        return ()
    blocks, result, value_sources = index.memory_blocks, [], {}
    for (family_id, space_id), selected_reads in sorted(readers.items()):
        step()
        family = families[family_id]
        modulus = 1 << family.address_bits
        order = index.orders[index.region_of[family.header]]
        # Offsets live in one modular family coordinate, not absolute RAM.
        # A huge address space starts as ONE unknown interval, never bytes.
        states, unknown = {}, ((0, modulus, None, 0),)
        for key, predecessors in order:
            state = unknown if key == family.header else states[predecessors[0]]
            for predecessor in predecessors[1:]:
                state = _meet(state, states[predecessor])
            for action in blocks[key].actions:
                step()
                if action.operation_key in selected_reads:
                    reader_id, reader = selected_reads[action.operation_key]
                    result.extend(_read_rows(index, accesses, reader_id, reader, state, modulus, value_sources))
                raw = index.raw.get(action.operation_key)
                if raw is not None and raw.opcode == "STORE":
                    # Distinct raw p-code address spaces have separate bytes.
                    if len(raw.inputs) == 3 and raw.inputs[0].kind is VarnodeKindCode.CONSTANT \
                            and raw.inputs[0].coordinate.byte_offset != space_id:
                        continue
                    item = writers.get(action.operation_key)
                    if item is None or item[1].family_index != family_id \
                            or item[1].space_id != space_id or item[1].width >= modulus:
                        state = unknown
                        continue
                    writer_id, writer = item
                    # Update even if this STORE's value cannot be projected:
                    # lack of a source never resurrects an earlier writer.
                    for lo, hi, bias in _pieces(writer.offset, writer.width, modulus):
                        state = _overwrite(state, lo, hi, writer_id, bias)
                elif action.unresolved_writes or any(span.object_id.kind not in (
                        StorageObjectKind.REGISTER_FILE, StorageObjectKind.FUNCTION_UNIQUE) for span in action.writes) \
                        or raw is not None and raw.output is not None and raw.output.kind not in (
                            VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE):
                    # Includes direct memory writes, KILL and effects not
                    # admitted as one of the family's original STOREs.
                    state = unknown
            states[key] = state
    rows = []
    for row in sorted(result, key=lambda row: (row.reader_access, row.read_offset, row.writer_access)):
        if rows and (rows[-1].writer_access, rows[-1].reader_access, rows[-1].source_definition_id,
                     rows[-1].constant) == (row.writer_access, row.reader_access, row.source_definition_id, row.constant) \
                and rows[-1].read_offset + rows[-1].width == row.read_offset \
                and rows[-1].write_offset + rows[-1].width == row.write_offset \
                and (row.source_span is None or (
                    rows[-1].source_span.object_id == row.source_span.object_id
                    and rows[-1].source_span.end == row.source_span.start)):
            previous, width = rows[-1], rows[-1].width + row.width
            source = None if previous.source_span is None else ByteSpan(
                previous.source_span.object_id, previous.source_span.start, width)
            rows[-1] = replace(previous, width=width, source_span=source,
                output_span=ByteSpan(previous.output_span.object_id, previous.output_span.start, width))
        else:
            rows.append(row)
    return tuple(rows)


def _pieces(offset, width, modulus):
    """Address interval -> at most two modular pieces and value-byte bias."""
    yield offset, min(modulus, offset + width), -offset
    if offset + width > modulus:
        yield 0, offset + width - modulus, modulus - offset


def _value_sources(index, key, value):
    """Original STORE operand-use fragments, not a new value/address solve.

    ENTRY, JOIN and KILL retain their original definition nodes and meaning.
    An unsupported fragment never authorizes restoring a preceding STORE.
    """
    span = index.span(value)
    read = index.reads.get((index.actions.get(key), span))
    if span is None or read is None:
        return ()
    rows = []
    for fragment in read.fragments:
        step()
        if len(fragment.definition_ids) != 1 or not span.contains(fragment.span):
            continue
        identifier = fragment.definition_ids[0]
        if not 0 <= identifier < len(index.ssa.definitions) \
                or not index.ssa.definitions[identifier].span.contains(fragment.span):
            continue
        rows.append((identifier, fragment.span, fragment.span.start - span.start))
    return tuple(rows)


def _read_rows(index, accesses, reader_id, reader, state, modulus, value_sources):
    operation = index.raw[reader.operation_key]
    output = None if operation.output is None else index.span(operation.output)
    if output is None or output.size != reader.width or reader.width >= modulus:
        return
    for start, stop, read_bias in _pieces(reader.offset, reader.width, modulus):
        for lo, hi, writer_id, write_bias in state:
            step()
            lo, hi = max(lo, start), min(hi, stop)
            if lo >= hi or writer_id is None:
                continue
            writer = accesses[writer_id]
            value = index.raw[writer.operation_key].inputs[2]
            width = hi - lo
            write_offset, read_offset = lo + write_bias, lo + read_bias
            if value.kind is VarnodeKindCode.CONSTANT:
                constant = value.coordinate.space_id, value.coordinate.byte_offset, value.byte_size
                yield LoopMemoryReadFrom(writer_id, reader_id, write_offset, read_offset, width,
                    None, None, constant, ByteSpan(output.object_id, output.start + read_offset, width))
                continue
            sources = value_sources.get(writer.operation_key)
            if sources is None:
                sources = _value_sources(index, writer.operation_key, value)
                value_sources[writer.operation_key] = sources
            for source_id, span, offset in sources:
                step()
                source_start = max(write_offset, offset)
                source_stop = min(write_offset + width, offset + span.size)
                if source_start >= source_stop:
                    continue
                size, target = source_stop - source_start, read_offset + source_start - write_offset
                source = ByteSpan(span.object_id, span.start + source_start - offset, size)
                yield LoopMemoryReadFrom(writer_id, reader_id, source_start, target, size,
                    source_id, source, None, ByteSpan(output.object_id, output.start + target, size))


def _append(rows, lo, hi, writer, bias):
    if writer is None:
        bias = 0
    if rows and rows[-1][1] == lo and rows[-1][2:] == (writer, bias):
        rows[-1] = rows[-1][0], hi, writer, bias
    else:
        rows.append((lo, hi, writer, bias))


def _overwrite(state, lo, hi, writer, bias):
    rows = []
    for start, end, old, old_bias in state:
        step()
        if end <= lo or start >= hi:
            _append(rows, start, end, old, old_bias)
            continue
        if start < lo:
            _append(rows, start, lo, old, old_bias)
        _append(rows, max(start, lo), min(end, hi), writer, bias)
        if end > hi:
            _append(rows, hi, end, old, old_bias)
    return tuple(rows)


def _meet(left, right):
    rows, i, j = [], 0, 0
    while i < len(left) and j < len(right):
        step()
        a, b = left[i], right[j]
        lo, hi = max(a[0], b[0]), min(a[1], b[1])
        writer, bias = a[2:] if a[2:] == b[2:] else (None, 0)
        _append(rows, lo, hi, writer, bias)
        i += int(a[1] <= b[1])
        j += int(b[1] <= a[1])
    return tuple(rows)
