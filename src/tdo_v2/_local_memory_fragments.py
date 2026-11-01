"""Bounded byte-wise last writes over original acyclic CFG corridors.

Only identical writer occurrences and source bytes meet across CFG arms.
Unknown writes kill facts; partial results add graph relations, never a
whole-LOAD value certificate. No paths, addresses or loop visits are enumerated.
"""

from dataclasses import replace

from ._guarded_image_reads import _Refused
from ._scope_contracts import VarnodeKindCode
from .model import ByteSpan, StorageObjectKind
from .resource_limits import step


def _base(term, width):
    """Peel exact same-width constant ADD/SUB in the address bitvector."""
    offset, modulus = 0, 1 << (width * 8)
    for _ in range(64):
        step()
        if term[0] == "const" and term[1] == width:
            return ("zero", width), (offset + term[2]) % modulus
        if term[0] not in ("INT_ADD", "INT_SUB") or term[1] != width:
            return term, offset % modulus
        operands = term[2]
        found = False
        for i, operand in enumerate(operands):
            if operand[0] == "const" and operand[1] == width and (i == 1 or term[0] == "INT_ADD"):
                offset += operand[2] if term[0] == "INT_ADD" else -operand[2]
                term, found = operands[1 - i], True
                break
        if not found:
            return term, offset % modulus
    raise _Refused()


def _region(index, source, target, dom):
    start, stop = index.locations[source], index.locations[target]
    if not dom._dominates(start, stop):
        return None
    blocks, pending = {stop}, [stop]
    while pending:
        step()
        block = pending.pop()
        if block != start:
            for pred in index.predecessors[block] - blocks:
                blocks.add(pred)
                pending.append(pred)
                if len(blocks) > 128:
                    return None
    if start not in blocks:
        return None
    degree = {b: len(index.predecessors[b] & blocks) for b in blocks}
    ready, ordered = sorted(b for b, n in degree.items() if not n), []
    while ready:
        block = ready.pop()
        ordered.append(block)
        for successor in index.blocks[block].successors:
            if successor in degree:
                degree[successor] -= 1
                if not degree[successor]:
                    ready.append(successor)
    return (start, stop, blocks, ordered) if len(ordered) == len(blocks) else None


def _parts(index, state):
    from ._loop_memory_reads import _value_sources
    from ._memory_read_sources import ReadSourcePart
    cache, result, cursor = {}, [], 0
    while cursor < len(state):
        step()
        item = state[cursor]
        if item is None:
            cursor += 1
            continue
        writer, offset = item
        stop = cursor + 1
        while stop < len(state) and state[stop] == (writer, offset + stop - cursor):
            stop += 1
        value = index.raw[writer].inputs[2]
        if writer not in cache:
            if value.kind is VarnodeKindCode.CONSTANT:
                cache[writer] = (ReadSourcePart(None, None,
                    (value.coordinate.space_id, value.coordinate.byte_offset, value.byte_size),
                    0, 0, value.byte_size, writer),)
            else:
                span = index.span(value)
                cache[writer] = () if span is None or any(span.overlaps(s)
                    for s in index.clobbered.get(writer, ())) else tuple(
                    ReadSourcePart(i, s, None, o, o, s.size, writer)
                    for i, s, o in _value_sources(index, writer, value))
        for part in cache[writer]:
            lo, hi = max(offset, part.value_offset), min(offset + stop - cursor, part.value_offset + part.width)
            if lo < hi:
                span = None if part.source_span is None else ByteSpan(part.source_span.object_id,
                    part.source_span.start + lo - part.value_offset, hi - lo)
                result.append(replace(part, source_span=span, value_offset=lo,
                                      output_offset=cursor + lo - offset, width=hi - lo))
        cursor = stop
    return tuple(result)


def derive_fragments(index, dom, reader, read_term, space, recent, read_witnesses, allowance):
    from ._memory_read_sources import _Address, _same_address, _shape, LocalReadFrom
    raw, best, spent = index.raw[reader], None, 0
    output = index.span(raw.output)
    if output is None:
        return None, spent
    width, address_width = output.size, raw.inputs[1].byte_size
    modulus = 1 << (address_width * 8)
    try:
        read_base, read_offset = _base(read_term, address_width)
        signature = _shape(read_base)
    except _Refused:
        return None, spent
    for anchor, sid, term, initial_witnesses in reversed(recent):
        if spent >= allowance:
            break
        if sid != space.space_id:
            continue
        try:
            base, _ = _base(term, address_width)
            if _shape(base) != signature:
                continue
        except _Refused:
            continue
        spent += 1
        region = _region(index, anchor, reader, dom)
        if region is None:
            continue
        start, stop, blocks, ordered = region
        states, evidence, ports, used, work = {}, [], [], set(read_witnesses) | set(initial_witnesses), 0
        for block in ordered:
            predecessors = [states[p] for p in index.predecessors[block] & blocks]
            state = list(predecessors[0]) if predecessors else [None] * width
            for incoming in predecessors[1:]:
                state = [x if x == y else None for x, y in zip(state, incoming, strict=True)]
            keys = index.keys[block]
            lo = keys.index(anchor) if block == start else 0
            hi = keys.index(reader) if block == stop else len(keys)
            if lo > hi:
                break
            for action in index.memory[block].actions[lo:hi]:
                step()
                work += 1
                if work > 1024:
                    return best, spent
                key, op = action.operation_key, index.raw.get(action.operation_key)
                evidence.append(key)
                if key in index.excluded or op is None or op.opcode in ("CALL", "CALLIND", "CALLOTHER"):
                    state = [None] * width
                    continue
                if op.opcode == "STORE":
                    try:
                        if len(op.inputs) != 3 or op.inputs[0].kind is not VarnodeKindCode.CONSTANT \
                                or op.inputs[0].coordinate.byte_offset != space.space_id \
                                or op.inputs[1].byte_size != address_width or not 0 < op.inputs[2].byte_size <= 32:
                            raise _Refused()
                        tree = _Address(index)
                        store_base, offset = _base(tree.operand(key, op.inputs[1]), address_width)
                        if not _same_address(store_base, read_base, index, dom, ports):
                            raise _Refused()
                        used.update(tree.used)
                        for byte in range(op.inputs[2].byte_size):
                            at = (offset - read_offset + byte) % modulus
                            if at < width:
                                state[at] = key, byte
                    except _Refused:
                        state = [None] * width
                elif action.unresolved_writes or any(s.object_id.kind not in (
                        StorageObjectKind.REGISTER_FILE, StorageObjectKind.FUNCTION_UNIQUE) for s in action.writes):
                    state = [None] * width
            states[block] = tuple(state)
        else:
            parts = _parts(index, states[stop])
            if not parts:
                continue
            complete = sum(p.width for p in parts) == width
            row = LocalReadFrom(anchor, reader, output, parts, tuple(sorted(set(evidence))),
                                tuple(sorted(used)), tuple(ports), complete)
            if complete:
                return row, spent
            if best is None or sum(p.width for p in parts) > sum(p.width for p in best.parts):
                best = row
    return best, spent
