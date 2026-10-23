"""Observed, return-validated physical acyclic-call expression contexts.

This layer reuses original SSA definitions/terminal states and the record
builder. It does not add SSA output rows, solve RD, assign ABI roles, remove
debts, or execute a second instruction model. Contexts are serialized graph
relations; their explicit physical interpretation verifies RETURN and SP.
"""

from __future__ import annotations

from ._scope_contracts import VarnodeKindCode
from .call_seeds import _operation_key
from .memory_contracts import MemoryDefinitionKind, RegisterStateFragment
from .resource_limits import AnalysisBudgetExceeded, AnalysisReportingFailed, step
from .span_geometry import ByteSpan, StorageObjectKind


def _identity(builder, base):
    return "/".join((*[call for _, call in builder.path], base))


def _raw(builder, key):
    for row in builder.unit.observation.instructions:
        for ordinal, operation in enumerate(row.operations):
            step()
            if _operation_key(row.address, ordinal, operation.opcode) == key:
                return row, ordinal, operation
    return None


def _checkpoint(builder):
    chain, seen, item = [], set(), builder
    while item is not None:
        chain.append((item, item.truncated, set(item.control_refs), dict(item.control_decisions)))
        seen.add(item)
        item = item.parent
    # An existing earlier context can acquire a newly demanded terminal part
    # while a later context is being built. Its caches/exports participate
    # in the same transaction; otherwise rollback leaves dangling node IDs.
    for child, _, _ in builder.physical_call_builders.values():
        if child not in seen:
            chain.append((child, child.truncated, set(child.control_refs), dict(child.control_decisions)))
            seen.add(child)
    return (len(builder.records), builder.ledger.edges, builder.controls.checkpoint(), chain,
            dict(builder.physical_calls), dict(builder.physical_call_builders),
            {key: len(value["outputs"]) for key, value in builder.physical_calls.items()})


def _restore(builder, checkpoint):
    start, edges, controls, chain, calls, builders, output_lengths = checkpoint
    builder.controls.restore(controls)
    for item, truncated, refs, decisions in chain:
        item.truncated, item.control_refs, item.control_decisions = truncated, refs, decisions
        item.id_of = {key: value for key, value in item.id_of.items() if value < start}
        item.call_ids = [identifier for identifier in item.call_ids if identifier < start]
    del builder.records[start:]
    builder.ledger.edges = edges
    builder.physical_calls.clear()
    builder.physical_calls.update(calls)
    for key, length in output_lengths.items():
        del calls[key]["outputs"][length:]
    builder.physical_call_builders.clear()
    builder.physical_call_builders.update(builders)


def context(builder, base):
    from .operation_records import _StitchCut, _Truncated

    identity = _identity(builder, base)
    if identity in builder.physical_calls:
        return builder.physical_calls[identity]
    if identity in builder.physical_call_cuts or identity in builder.physical_call_building:
        return None
    checkpoint = _checkpoint(builder)
    frozen, builder.ledger.frozen = builder.ledger.frozen, len(builder.records)
    prior_physical, builder.building_physical = builder.building_physical, True
    builder.physical_call_building.add(identity)
    try:
        result, child, block, return_key = _context(builder, base, identity)
        if child.truncated or any(item.truncated != flag for item, flag, _, _ in checkpoint[3]):
            raise _StitchCut("limit")
        child._control_record()
    except (MemoryError, AnalysisBudgetExceeded, AnalysisReportingFailed):
        raise
    except (_StitchCut, _Truncated, RecursionError) as error:
        _restore(builder, checkpoint)
        builder.physical_call_cuts[identity] = str(error) if isinstance(error, _StitchCut) else "limit"
        return None
    else:
        builder.physical_calls[identity] = result
        builder.physical_call_builders[identity] = child, block, return_key
        for node in builder.records[checkpoint[0]:]:
            node.setdefault("physical_only", True)
            if node.get("physical_context") == identity:
                node.setdefault("import", identity)
        return result
    finally:
        builder.physical_call_building.discard(identity)
        builder.ledger.frozen = frozen
        builder.building_physical = prior_physical


def _context(builder, base, identity):
    from ._record_memory import MemoryIndex
    from .call_summary_effects import call_load_keys
    from .operation_records import _Binding, _Builder, _StitchCut

    if builder.stitch is None or builder.provenance is None:
        raise _StitchCut("physical call context unavailable")
    if len(builder.path) >= builder.limits.call_depth:
        raise _StitchCut("physical call depth")
    source = builder.provenance.sources.get(base)
    if source is None or source[0] != "summary":
        raise _StitchCut("physical call requires one analyzed body")
    done = source[1]
    raw = _raw(builder, base)
    if raw is None or raw[2].opcode != "CALL" or not raw[2].inputs:
        raise _StitchCut("physical call requires a direct CALL")
    instruction, _, operation = raw
    target = operation.inputs[0].coordinate
    if done.key != f"{target.space_id:x}:{target.byte_offset:x}" \
            or done.key == builder.function_key or any(done.key == key for key, _ in builder.path):
        raise _StitchCut("physical call target mismatch or recursion")
    projection = builder._projection(base)
    if projection is None or instruction.fallthrough is None:
        raise _StitchCut("physical call projection unavailable")
    if type(done.normalized).__name__ != "NormalizedFunction" or done.summary is None:
        raise _StitchCut("physical call body unavailable")
    effect = builder.proven.get(base)
    if effect is None:
        raise _StitchCut("physical call effect unavailable")
    reads = []
    for action in builder.ssa.actions:
        key, _, tag = action.operation_key.partition("~")
        if key == base and tag.rstrip("0123456789") in ("in", "sp", "ld", "iu", "sr"):
            reads.extend(read for read in builder._staged_reads(action.operation_key) if read not in reads)
    binding = _Binding(builder, tuple(reads), builder._stack_base(base), builder._stack_base(base, delta=True),
                       done.anchors, call_load_keys(base, effect), call=base, effect=effect)
    binding.physical_context = identity
    child = _Builder(done.normalized, done.unit, origins=done.origins, declared=done.declared,
                     limits=builder.limits, provenance=builder.stitch.provenance(done), stitch=builder.stitch,
                     records=builder.records, ledger=builder.ledger, parent=builder, binding=binding,
                     path=(*builder.path, (builder.function_key, base)),
                     index=builder.stitch.index(done.normalized, done.unit), physical_memory=True)
    child.physical_context, child.building_physical = identity, True
    conditions = child._condition_index()
    if conditions._reason is not None:
        raise _StitchCut("physical callee requires an acyclic complete CFG")
    returns = [(key, _raw(child, key)) for key in conditions._raw_blocks if key.endswith(":RETURN")]
    if not returns:
        raise _StitchCut("physical callee has no original RETURN")
    child.memory_index = MemoryIndex(child.normalized, child.unit, child.index, conditions)
    body, reason = child.memory_index.inventory()
    if body is None:
        raise _StitchCut(reason or "physical callee has an opaque effect")
    if builder.memory_index is None:
        builder.memory_index = MemoryIndex(builder.normalized, builder.unit, builder.index, builder._condition_index())
    prefix, reason = builder.memory_index.prefix(projection.transient_operation_keys[0])
    if prefix is None:
        raise _StitchCut(reason or "physical call prefix unavailable")
    before = binding.pre_stack_parts()
    stack_node = binding._stack_value(child)
    if before is None or stack_node is None:
        raise _StitchCut("physical call stack input unavailable")
    stack_size = binding.stack[1]
    stores = []
    for key in projection.transient_operation_keys:
        raw_store = _raw(builder, key)
        if raw_store is not None and raw_store[2].opcode == "STORE":
            stores.append((raw_store, key))
    if len(stores) != 1:
        raise _StitchCut("physical call push unavailable")
    (_, _, store), store_key = stores[0]
    if store.inputs[2].kind is not VarnodeKindCode.CONSTANT:
        raise _StitchCut("physical push value is not observed")
    guard, reason = builder._condition_index().reach_guard(base)
    if guard is None:
        raise _StitchCut(reason or "physical call reach unavailable")
    guard = builder._guard_ref(guard)
    value = builder._new(None, {"kind": "const", "size": store.inputs[2].byte_size,
                                "value": store.inputs[2].coordinate.byte_offset})["id"]
    push = builder._new(None, {"kind": "op", "key": store_key, "opcode": "STORE",
                               "space": store.inputs[0].coordinate.byte_offset, "physical_guard": guard,
                               "physical_call_push": identity, "operands": [
                                   {"index": 0, "role": "space", "width": store.inputs[0].byte_size,
                                    "value": store.inputs[0].coordinate.byte_offset},
                                   {"index": 1, "role": "address", "width": store.inputs[1].byte_size,
                                    "parts": [{"node": stack_node, "bytes": [0, stack_size], "at": [0, stack_size]}]},
                                   {"index": 2, "role": "value", "width": store.inputs[2].byte_size,
                                    "parts": [{"node": value, "bytes": [0, store.inputs[2].byte_size],
                                               "at": [0, store.inputs[2].byte_size]}]}]})
    builder._done(push)
    stack_span = next((span for span in child.ssa.atomic_spans
                       if span.object_id.kind is StorageObjectKind.REGISTER_FILE
                       and span.start <= binding.stack[0] < span.end), None)
    if stack_span is None:
        raise _StitchCut("physical terminal SP unavailable")
    returned_records, terminals = [], []
    for return_key, returned in returns:
        if returned is None or returned[2].output is not None or len(returned[2].inputs) != 1:
            raise _StitchCut("unsupported physical RETURN")
        block = conditions._raw_blocks[return_key]
        return_node = child.normalized.dependencies.node_for_key(f"op:{return_key}")
        if return_node is None:
            raise _StitchCut("physical RETURN node unavailable")
        record = child.records[child.operation(return_node, 0)]
        operand = next((item for item in record.get("operands", ()) if item["index"] == 0), None)
        if operand is None:
            raise _StitchCut("physical RETURN operand unavailable")
        stack_part = terminal_register(child, ByteSpan(stack_span.object_id, binding.stack[0], stack_size),
                                       block, return_key)
        return_guard, reason = conditions.reach_guard(return_key)
        if return_guard is None:
            raise _StitchCut(reason or "physical RETURN reach unavailable")
        returned_records.append({"key": return_key, "guard": child._guard_ref(return_guard), "operand": operand,
                                 "stack": {"width": stack_size, "parts": [stack_part]},
                                 "expected_target": instruction.fallthrough.byte_offset,
                                 "expected_stack": {"width": stack_size, "parts": before}})
        terminals.append((block, return_key))
    result = {"id": identity, "call": base, "function": done.key, "guard": guard,
              "parent_context": builder.physical_context,
              "scope": child.ssa.function_scope.digest.hex(), "unit": child.ssa.unit_digest.hex(),
              "projection": {"transient": list(projection.transient_operation_keys),
                             "stack_offset": binding.stack[0], "stack_size": stack_size,
                             "delta": binding.delta},
              "prefix": builder._physical_events(prefix),
              "push": {"key": store_key, "kind": "store", "guard": guard, "node": push["id"],
                       "space": store.inputs[0].coordinate.byte_offset, "width": store.inputs[2].byte_size},
              "events": child._physical_events(body), "outputs": [], "returns": returned_records}
    if len(returned_records) == 1:
        result["return"] = returned_records[0]  # singular v6 reader compatibility
    return result, child, tuple(terminals), None


def terminal_register(builder, span, block, return_key):
    """Requested terminal register bytes from the existing raw run-tree only."""
    from .operation_records import _StitchCut

    states = [state for state in builder.ssa.observed_terminal_states if state.block_key == block]
    if len(states) != 1 or states[0].root_node_id is None:
        raise _StitchCut("physical terminal state unavailable")
    pieces, pending = [], [states[0].root_node_id]
    while pending:
        step()
        node = builder.ssa.state_nodes[pending.pop()]
        pending.extend(child for child in (node.left_node_id, node.right_node_id) if child is not None)
        first, last = builder.ssa.atomic_spans[node.start_atom], builder.ssa.atomic_spans[node.stop_atom - 1]
        if first.object_id != span.object_id:
            continue
        low, high = max(first.start, span.start), min(last.end, span.end)
        if low >= high:
            continue
        fragment = RegisterStateFragment(ByteSpan(span.object_id, low, high - low), node.definition_ids)
        if any(builder.ssa.definitions[identifier].kind is MemoryDefinitionKind.KILL
               for identifier in fragment.definition_ids):
            raise _StitchCut("physical terminal register is killed")
        if len(fragment.definition_ids) == 1:
            identifier = fragment.definition_ids[0]
            definition = builder.ssa.definitions[identifier]
            producer, base, loop = builder._definition_guarded(builder.index.definition_node[identifier], 1)
            start = low - definition.span.start + base
            part = builder._named({"node": producer, "bytes": [start, start + high - low],
                                   "at": [low - span.start, high - span.start]}, definition)
            if loop:
                part["loop"] = True
        else:
            producer = builder._fragment_phi(fragment, 0, boundary=(block, return_key))
            part = {"node": producer, "bytes": [0, high - low], "at": [low - span.start, high - span.start]}
        builder._edge()
        pieces.append(part)
    pieces.sort(key=lambda piece: piece["at"])
    return builder._whole(pieces, span.size)


def output_part(builder, found, span):
    from .operation_records import _StitchCut, _Truncated

    for output in found["outputs"]:
        if output["offset"] == span.start and output["size"] == span.size:
            return output["part"]
    child, terminals, _ = builder.physical_call_builders[found["id"]]
    checkpoint = _checkpoint(child)
    physical_flags = [(item, item.building_physical) for item, *_ in checkpoint[3]]
    for item, _ in physical_flags:
        item.building_physical = True
    try:
        if len(terminals) == 1:
            block, return_key = terminals[0]
            part = terminal_register(child, span, block, return_key)
        else:
            alternatives = [child._exit_part(terminal_register(child, span, block, return_key), block, span.size)
                            for block, return_key in terminals]
            phi = child._new(None, {"kind": "phi", "reason": "callee exits", "instance": found["id"],
                                    "size": span.size, "alternatives": alternatives})
            child._done(phi)
            part = {"node": phi["id"], "bytes": [0, span.size], "at": [0, span.size]}
        child._control_record()
        if child.truncated:
            raise _StitchCut("limit")
    except (_StitchCut, _Truncated, RecursionError):
        _restore(child, checkpoint)
        return None
    finally:
        for item, value in physical_flags:
            item.building_physical = value
    found["outputs"].append({"offset": span.start, "size": span.size, "part": part})
    for node in builder.records[checkpoint[0]:]:
        node.setdefault("physical_only", True)
        if node.get("physical_context") == found["id"]:
            node.setdefault("import", found["id"])
    return part


def physical_event(builder, event):
    base = event.key if event.kind == "call" else None
    if base is None:
        for projection in builder._projections.values() if builder._transitions is not None else ():
            if event.key in projection.transient_operation_keys and event.key.endswith(":STORE"):
                base = projection.call_operation_key
                break
        if base is None:
            builder._stack_base("")  # initialize the existing projection index
            base = next((projection.call_operation_key for projection in builder._projections.values()
                         if event.key in projection.transient_operation_keys and event.key.endswith(":STORE")), None)
    if base is None:
        return None
    found = context(builder, base)
    if found is None:
        return None
    if event.key == found["push"]["key"]:
        return dict(found["push"])
    if event.kind == "call":
        return {"key": base, "kind": "call", "guard": found["guard"], "context": found["id"]}
    return None


def _unmodified_read(builder, base, read, span):
    """The named call dominates this exact read, with no intervening overwrite."""
    conditions = builder._condition_index()
    if conditions._reason is not None:
        return False
    original_read = read.partition("~")[0]
    location = conditions._raw_blocks.get(original_read)
    if location is None or base not in conditions._raw_blocks:
        return False
    from .operation_records import _key_parts

    _, _, ordinal = _key_parts(original_read)
    if read != original_read:
        projection = builder._projection(original_read)
        if projection is None:
            return False
        _, _, ordinal = _key_parts(projection.transient_operation_keys[0])
    memo = {}

    def trace(key, stop=None):
        step()
        identity = key, stop
        if identity in memo:
            return memo[identity]
        block = conditions.blocks[key]
        row = conditions.instructions[block.instruction]
        for index in range((block.stop if stop is None else stop) - 1, block.start - 1, -1):
            step()
            operation = row.operations[index]
            raw_key = _operation_key(row.address, index, operation.opcode)
            if raw_key == base:
                memo[identity] = True
                return True
            if operation.opcode in ("CALL", "CALLIND", "CALLOTHER"):
                return False
            output = operation.output
            if output is not None and output.kind is VarnodeKindCode.REGISTER \
                    and output.coordinate.space_id == builder.register_space \
                    and output.coordinate.byte_offset < span.end \
                    and span.start < output.coordinate.byte_offset + output.byte_size:
                return False
        incoming = conditions.predecessors[key]
        found = key != conditions.entry and bool(incoming) and all(trace(item) for item in incoming)
        memo[identity] = found
        return found

    return ordinal is not None and trace(location, ordinal)


def bind_register_operand(builder, read, span):
    rows = [row for row in builder.normalized.call_clobber_reads if row.operation_key == read
            and any(piece.object_id == span.object_id and piece.overlaps(span) for piece in row.spans)]
    if not rows:
        return None
    calls = {call for row in rows for call in row.intervening_calls}
    if len(calls) != 1:
        return None
    base, = calls
    if not _unmodified_read(builder, base, read, span):
        return None
    found = context(builder, base)
    if found is None:
        return None
    part = output_part(builder, found, span)
    if part is None:
        return None
    return {"context": found["id"], "part": part, "offset": 0, "size": span.size,
            "register_offset": span.start, "read": read, "call": base}


def snapshot_parts(builder, snapshot, start, end):
    """A prior body's observed terminal bytes at this exact call boundary.

    A register-only snapshot is not evidence that an intervening call kept
    those bytes. Reuse its original boundary, and require one dominating raw
    call with no later overwrite; obtain the bytes from that body's existing
    terminal state instead. No new read or SSA definition is introduced.
    """
    conditions = builder._condition_index()
    location = conditions._locations.get(snapshot.first_action_key)
    if location is None or location[0] != snapshot.block_key \
            or conditions._raw_blocks.get(snapshot.boundary_key) != snapshot.block_key:
        return None
    objects = {span.object_id for span in builder.ssa.atomic_spans
               if span.object_id.kind is StorageObjectKind.REGISTER_FILE}
    if len(objects) != 1:
        return None
    span = ByteSpan(next(iter(objects)), start, end - start)
    candidates = [base for base in builder.proven
                  if _unmodified_read(builder, base, snapshot.first_action_key, span)]
    if len(candidates) != 1:
        return None
    found = context(builder, candidates[0])
    if found is None:
        return None
    part = output_part(builder, found, span)
    return [dict(part)] if part is not None else None


def bind_call_debts(builder, record, debts):
    covered = []
    for row, raw_node in zip(builder.normalized.call_clobber_reads, builder.normalized.call_clobber_nodes):
        if row.operation_key != record.get("key"):
            continue
        identifier = builder.id_of.get(raw_node)
        if identifier not in debts:
            continue
        if any(context(builder, base) is None for base in row.intervening_calls):
            continue
        registers = [part for part in row.spans if part.object_id.kind is StorageObjectKind.REGISTER_FILE]
        memory = [part for part in row.spans if part.object_id.kind in
                  (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)]
        bindings = [operand["physical_register"] for operand in record.get("operands", ())
                    if "physical_register" in operand]
        if len(registers) + len(memory) != len(row.spans):
            continue
        if memory:
            load_complete = record.get("opcode") == "LOAD" and record.get("physical_memory", {}).get("complete")
            direct_complete = identifier in record.get("physical_read_debt_ids", ())
            if not (load_complete or direct_complete):
                continue
        if any(not any(binding["call"] in row.intervening_calls and binding["register_offset"] <= span.start
                       and span.end <= binding["register_offset"] + binding["size"] for binding in bindings)
               for span in registers):
            continue
        covered.append(identifier)
    if covered:
        record["physical_call_debt_ids"] = covered


def bind_call_row(builder, record):
    from .operation_records import _output_run, _span_dict

    run = _output_run(builder.proven[record["call"]], record["row"])
    if run is None or not hasattr(run, "writes"):
        return
    found = context(builder, record["call"])
    if found is None:
        return
    outputs = []
    for span in run.writes:
        part = output_part(builder, found, span)
        if part is None:
            return
        outputs.append({"output": _span_dict(span), "part": part, "context": found["id"]})
    record["physical_stitched"] = outputs
