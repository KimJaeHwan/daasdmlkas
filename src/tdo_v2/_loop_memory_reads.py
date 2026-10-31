"""Last-STORE fragments over the existing affine family cut-DAG.

No new SSA, global fixed point, visit/path enumeration or memory-object
assumption. Two finite passes per family: unknown entry, then a shifted meet
of the original latch exits. Only the latter can issue backedge-qualified
previous-visit rows. States include writer occurrence as well as byte maps;
the second pass never feeds itself back into the header.
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
        unknown = ((0, modulus, None, 0, 0),)

        def visit(initial, required_delta):
            states = {}
            for key, predecessors in order:
                state = initial if key == family.header else states[predecessors[0]]
                for predecessor in predecessors[1:]:
                    state = _meet(state, states[predecessor])
                for action in blocks[key].actions:
                    step()
                    if action.operation_key in selected_reads:
                        reader_id, reader = selected_reads[action.operation_key]
                        result.extend(_read_rows(index, accesses, reader_id, reader, state, modulus,
                                                 value_sources, required_delta))
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
                        # A current STORE always has delta 0, even when its
                        # static operation key also wrote the previous visit.
                        # Missing source bytes never revive an earlier writer.
                        for lo, hi, bias in _pieces(writer.offset, writer.width, modulus):
                            state = _overwrite(state, lo, hi, writer_id, bias)
                    elif action.unresolved_writes or any(span.object_id.kind not in (
                            StorageObjectKind.REGISTER_FILE, StorageObjectKind.FUNCTION_UNIQUE) for span in action.writes) \
                            or raw is not None and raw.output is not None and raw.output.kind not in (
                                VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE):
                        # Includes direct writes, KILL and effects not admitted
                        # as one of this family's original STOREs.
                        state = unknown
                states[key] = state
            return states

        states = visit(unknown, 0)
        previous = states[family.latches[0]]
        for latch in family.latches[1:]:
            previous = _meet(previous, states[latch])
        if any(row[2] is not None for row in previous):
            # Conditional on an actual backedge entry, never on preheader
            # entry. The phase qualifier remains part of every issued row.
            previous = _previous(previous, family.stride, modulus)
            if _overlaps_reads(previous, selected_reads, modulus):
                visit(previous, -1)
    rows = []
    for row in sorted(result, key=lambda row: (row.reader_access, row.read_offset, row.visit_delta, row.writer_access)):
        if rows and (rows[-1].writer_access, rows[-1].reader_access, rows[-1].source_definition_id,
                     rows[-1].constant, rows[-1].visit_delta) == (row.writer_access, row.reader_access,
                     row.source_definition_id, row.constant, row.visit_delta) \
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


def _read_rows(index, accesses, reader_id, reader, state, modulus, value_sources, required_delta):
    operation = index.raw[reader.operation_key]
    output = None if operation.output is None else index.span(operation.output)
    if output is None or output.size != reader.width or reader.width >= modulus:
        return
    for start, stop, read_bias in _pieces(reader.offset, reader.width, modulus):
        for lo, hi, writer_id, write_bias, delta in state:
            step()
            lo, hi = max(lo, start), min(hi, stop)
            if lo >= hi or writer_id is None or delta != required_delta:
                continue
            writer = accesses[writer_id]
            value = index.raw[writer.operation_key].inputs[2]
            width = hi - lo
            write_offset, read_offset = lo + write_bias, lo + read_bias
            if value.kind is VarnodeKindCode.CONSTANT:
                constant = value.coordinate.space_id, value.coordinate.byte_offset, value.byte_size
                yield LoopMemoryReadFrom(writer_id, reader_id, write_offset, read_offset, width,
                    None, None, constant, ByteSpan(output.object_id, output.start + read_offset, width),
                    delta, delta == -1)
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
                    source_id, source, None, ByteSpan(output.object_id, output.start + target, size),
                    delta, delta == -1)


def _append(rows, lo, hi, writer, bias, delta):
    if writer is None:
        bias, delta = 0, 0
    if rows and rows[-1][1] == lo and rows[-1][2:] == (writer, bias, delta):
        rows[-1] = rows[-1][0], hi, writer, bias, delta
    else:
        rows.append((lo, hi, writer, bias, delta))


def _previous(state, stride, modulus):
    """Move latch bytes into next-header coordinates, preserving value bytes."""
    shifted = []
    for lo, hi, writer, bias, _ in state:
        step()
        for start, stop, moved_bias in _pieces((lo - stride) % modulus, hi - lo, modulus):
            shifted.append((start, stop, writer, lo + bias + moved_bias, -1))
    rows = []
    for row in sorted(shifted):
        step()
        _append(rows, *row)
    return tuple(rows)


def _overlaps_reads(state, readers, modulus):
    """Skip the second visit when no carried byte can reach any reader.

    Sorted intervals and one sweep, not a reader-by-writer cross product.
    This is only a negative filter; actual prefix writes are still checked.
    """
    intervals = []
    for _, reader in readers.values():
        step()
        if reader.width < modulus:
            intervals.extend((lo, hi) for lo, hi, _ in _pieces(reader.offset, reader.width, modulus))
    intervals.sort()
    position = 0
    for lo, hi, writer, _, _ in state:
        step()
        if writer is None:
            continue
        while position < len(intervals) and intervals[position][1] <= lo:
            step()
            position += 1
        if position < len(intervals) and intervals[position][0] < hi:
            return True
    return False


def _overwrite(state, lo, hi, writer, bias):
    rows = []
    for start, end, old, old_bias, delta in state:
        step()
        if end <= lo or start >= hi:
            _append(rows, start, end, old, old_bias, delta)
            continue
        if start < lo:
            _append(rows, start, lo, old, old_bias, delta)
        _append(rows, max(start, lo), min(end, hi), writer, bias, 0)
        if end > hi:
            _append(rows, hi, end, old, old_bias, delta)
    return tuple(rows)


def _meet(left, right):
    rows, i, j = [], 0, 0
    while i < len(left) and j < len(right):
        step()
        a, b = left[i], right[j]
        lo, hi = max(a[0], b[0]), min(a[1], b[1])
        writer, bias, delta = a[2:] if a[2:] == b[2:] else (None, 0, 0)
        _append(rows, lo, hi, writer, bias, delta)
        i += int(a[1] <= b[1])
        j += int(b[1] <= a[1])
    return tuple(rows)
