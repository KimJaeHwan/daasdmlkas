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
            {key: len(value["outputs"]) for key, value in builder.physical_calls.items()},
            dict(builder.target_selectors),
            {key: ("caller_register_writes" in value, len(value.get("caller_register_writes", ())))
             for key, value in builder.physical_calls.items()})


def _restore(builder, checkpoint):
    start, edges, controls, chain, calls, builders, output_lengths, selectors, write_lengths = checkpoint
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
        present, writes = write_lengths[key]
        if present:
            del calls[key]["caller_register_writes"][writes:]
        else:
            calls[key].pop("caller_register_writes", None)
    builder.physical_call_builders.clear()
    builder.physical_call_builders.update(builders)
    builder.target_selectors.clear()
    builder.target_selectors.update(selectors)


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
        raw = _raw(builder, base)
        if raw is not None and raw[2].opcode == "CALLIND":
            result = _indirect_context(builder, base, identity)
            child = None
        else:
            result, child, block, return_key = _context(builder, base, identity)
        if child is not None and child.truncated or any(item.truncated != flag for item, flag, _, _ in checkpoint[3]):
            raise _StitchCut("limit")
        if child is not None:
            child._control_record()
    except (MemoryError, AnalysisBudgetExceeded, AnalysisReportingFailed):
        raise
    except (_StitchCut, _Truncated, RecursionError) as error:
        _restore(builder, checkpoint)
        builder.physical_call_cuts[identity] = str(error) if isinstance(error, _StitchCut) else "limit"
        return None
    else:
        builder.physical_calls[identity] = result
        if child is not None:
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


def target_producer(unit, base):
    """Original straight instruction-local producer, not a new RD analysis."""
    from .pcode_blocks import has_internal_flow

    for row in unit.observation.instructions:
        for ordinal, operation in enumerate(row.operations):
            step()
            if _operation_key(row.address, ordinal, operation.opcode) != base:
                continue
            if operation.opcode != "CALLIND" or len(operation.inputs) != 1 or has_internal_flow(row):
                return None
            target = operation.inputs[0]
            for index in range(ordinal - 1, -1, -1):
                earlier = row.operations[index]
                output = earlier.output
                if output is None or output.coordinate.space_id != target.coordinate.space_id:
                    continue
                if output.coordinate.byte_offset < target.coordinate.byte_offset + target.byte_size \
                        and target.coordinate.byte_offset < output.coordinate.byte_offset + output.byte_size:
                    return (_operation_key(row.address, index, earlier.opcode), target) if output == target else None
            return None
    return None


def _target_operand(builder, base):
    from .operation_records import _Binding, _StitchCut

    instruction, ordinal, operation = _raw(builder, base)
    target, = operation.inputs
    producer = target_producer(builder.unit, base)
    operand = {"index": 0, "role": "target", "width": target.byte_size}
    source = {"operation": base, "index": 0, "kind": target.kind.name,
              "space": target.coordinate.space_id, "offset": target.coordinate.byte_offset,
              "width": target.byte_size, "context": builder.physical_context}
    operand["target_read"] = {name: source[name] for name in ("kind", "space", "offset", "width")}
    if producer is not None:
        key, _ = producer
        node = builder.graph.node_for_key(f"op:{key}")
        if node is None or node not in builder.index.action_of:
            raise _StitchCut("physical target has no existing producer")
        operand["parts"] = [{"node": builder.operation(node, 0), "bytes": [0, target.byte_size],
                             "at": [0, target.byte_size]}]
        source["producer"] = key
    elif target.kind is VarnodeKindCode.CONSTANT:
        operand.update(builder._constant_operand(0, target, "target"))
    elif target.kind is VarnodeKindCode.REGISTER:
        # A snapshot is pre-staging, not a license to ignore a target write
        # later in the same instruction. Partial writes and unmodeled local
        # control therefore cut instead of reading an earlier register value.
        from .pcode_blocks import has_internal_flow

        if has_internal_flow(instruction):
            raise _StitchCut("physical target has internal control")
        for earlier in instruction.operations[:ordinal]:
            output = earlier.output
            if output is not None and output.coordinate.space_id == target.coordinate.space_id \
                    and output.coordinate.byte_offset < target.coordinate.byte_offset + target.byte_size \
                    and target.coordinate.byte_offset < output.coordinate.byte_offset + output.byte_size:
                raise _StitchCut("physical target has no exact local producer")
        binding = _Binding(builder, (), builder._stack_base(base), builder._stack_base(base, delta=True),
                           call=base, effect=builder.proven[base])
        binding.physical_context = _identity(builder, base)
        operand["parts"] = binding.parts(target.coordinate.byte_offset,
                                          target.coordinate.byte_offset + target.byte_size)
    else:
        raise _StitchCut("physical target read unavailable")
    builder._edge()
    return operand, source


def _indirect_context(builder, base, identity):
    from .operation_records import _StitchCut

    if builder.stitch is None or builder.provenance is None:
        raise _StitchCut("physical indirect call has no provenance")
    if builder.stitch.assumptions is None:
        raise _StitchCut("physical indirect call requires explicit run assumptions")
    analyzed = builder.stitch.analyzed(builder.normalized, builder.unit, builder.provenance)
    source = builder.provenance.sources.get(base)
    if analyzed is None or source is None or source[0] not in ("summary", "summaries"):
        raise _StitchCut("physical indirect call has no final analyzed targets")
    members = (source[1],) if source[0] == "summary" else tuple(source[1])
    proven = analyzed.multi_calls.get(base, ()) or ((analyzed.calls[base],) if base in analyzed.calls else ())
    if not members or len(members) > 8 or tuple(done.key for done in members) != tuple(proven) \
            or len(set(proven)) != len(proven):
        raise _StitchCut("physical indirect target set mismatch")
    operand, target_source = _target_operand(builder, base)
    candidates, common = [], None
    for done in members:
        retained = builder.stitch.table.get(id(done))
        if retained is None or retained[0] is not done \
                or done.unit.scopes.program is not builder.unit.scopes.program:
            raise _StitchCut("physical target body is not from the same admitted run/program")
        child_id = f"{identity}@{done.key}"
        found, child, terminals, _ = _context(builder, base, child_id, done=done, shared=common)
        child._control_record()
        if child.truncated:
            raise _StitchCut("limit")
        found["selected_by"] = identity
        builder.physical_calls[child_id] = found
        builder.physical_call_builders[child_id] = child, terminals, None
        if common is None:
            common = found
            builder.records[found["push"]["node"]]["physical_call_push"] = identity
        entry = done.unit.scopes.function.entry
        candidates.append({"value": entry.byte_offset, "space": entry.space_id,
                           "function": done.key, "context": child_id,
                           "scope": found["scope"], "unit": found["unit"]})
    selector = {"id": identity, "call": base, "parent_context": builder.physical_context,
                "guard": common["guard"], "operand": operand, "source": target_source,
                "space": builder.unit.scopes.function.entry.space_id, "width": operand["width"],
                "program": getattr(builder.unit.scopes.program.evidence, "executable_sha256", b"").hex(),
                "scope": builder.ssa.function_scope.digest.hex(), "unit": builder.ssa.unit_digest.hex(),
                "function": builder.function_key, "requires": list(builder.stitch.assumptions),
                "candidates": candidates}
    builder.target_selectors[identity] = selector
    return {"id": identity, "kind": "target_selection", "target_selector": identity,
            "call": base, "function": "CALLIND", "parent_context": builder.physical_context,
            "guard": common["guard"], "prefix": common["prefix"], "push": common["push"],
            "projection": common["projection"], "events": [], "outputs": [],
            "scope": selector["scope"], "unit": selector["unit"]}


def _push(builder, identity, store, store_key, before, stack_size, delta, guard):
    """One caller-owned push, shared by all targets of the same call."""
    number = builder._new(None, {"kind": "const", "size": stack_size,
                                "value": delta & ((1 << (8 * stack_size)) - 1)})["id"]
    address = builder._new(None, {"kind": "op", "key": "stitch:call-shape", "opcode": "INT_ADD",
                                  "output": {"size": stack_size}, "physical_guard": guard,
                                  "operands": [{"index": 0, "width": stack_size, "parts": before},
                                               {"index": 1, "width": stack_size, "parts": [
                                                   {"node": number, "bytes": [0, stack_size],
                                                    "at": [0, stack_size]}]}]})
    builder._done(address)
    width, space = store.inputs[2].byte_size, store.inputs[0].coordinate.byte_offset
    value = builder._new(None, {"kind": "const", "size": width,
                                "value": store.inputs[2].coordinate.byte_offset})["id"]
    push = builder._new(None, {"kind": "op", "key": store_key, "opcode": "STORE", "space": space,
                               "physical_guard": guard, "physical_call_push": identity, "operands": [
                                   {"index": 0, "role": "space", "width": store.inputs[0].byte_size, "value": space},
                                   {"index": 1, "role": "address", "width": store.inputs[1].byte_size,
                                    "parts": [{"node": address["id"], "bytes": [0, stack_size], "at": [0, stack_size]}]},
                                   {"index": 2, "role": "value", "width": width,
                                    "parts": [{"node": value, "bytes": [0, width], "at": [0, width]}]}]})
    builder._done(push)
    return {"key": store_key, "kind": "store", "guard": guard, "node": push["id"], "space": space, "width": width}


def _context(builder, base, identity, *, done=None, shared=None):
    from ._record_memory import MemoryIndex
    from .call_summary_effects import call_load_keys
    from .operation_records import _Binding, _Builder, _StitchCut

    if builder.stitch is None or builder.provenance is None:
        raise _StitchCut("physical call context unavailable")
    if len(builder.path) >= builder.limits.call_depth:
        raise _StitchCut("physical call depth")
    if done is None:
        source = builder.provenance.sources.get(base)
        if source is None or source[0] != "summary":
            raise _StitchCut("physical call requires one analyzed body")
        done = source[1]
    raw = _raw(builder, base)
    if raw is None or raw[2].opcode not in ("CALL", "CALLIND") or not raw[2].inputs:
        raise _StitchCut("physical call requires an observed CALL")
    instruction, _, operation = raw
    target = operation.inputs[0].coordinate
    if operation.opcode == "CALL" and done.key != f"{target.space_id:x}:{target.byte_offset:x}" \
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
                       done.anchors, call_load_keys(base, effect), call=base, effect=effect,
                       relations=dict(done.summary.address_relations))
    binding.physical_context = identity
    child = _Builder(done.normalized, done.unit, origins=done.origins, declared=done.declared,
                     limits=builder.limits, provenance=builder.stitch.provenance(done), stitch=builder.stitch,
                     records=builder.records, ledger=builder.ledger, parent=builder, binding=binding,
                     path=(*builder.path, (builder.function_key,
                           f"{base}@{done.key}" if operation.opcode == "CALLIND" else base)),
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
    if before is None:
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
    # the raw replay's push is the graph's: the ~push literal row (width and
    # value), when the normalizer has one (survey #10, design_d_push.md E)
    literal = next((row for key, row in builder.normalized.pointer_rows if key == f"{base}~push"), None)
    if literal is None:
        raise _StitchCut("physical push has no ~push literal")   # (the graph cuts it too)
    if literal[0] != "const" or literal[1] != store.inputs[2].byte_size             or literal[2] != store.inputs[2].coordinate.byte_offset:
        raise _StitchCut("physical push differs from the ~push literal")
    guard, reason = builder._condition_index().reach_guard(base)
    if guard is None:
        raise _StitchCut(reason or "physical call reach unavailable")
    guard = builder._guard_ref(guard)
    push = shared["push"] if shared is not None else _push(
        builder, identity, store, store_key, before, stack_size, binding.delta, guard)
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
              "prefix": builder._physical_events(prefix) if shared is None else shared["prefix"],
              "push": push,
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
    if found.get("kind") == "target_selection":
        checkpoint = _checkpoint(builder)
        try:
            choices = builder.target_selectors[found["id"]]["candidates"]
            parts = [output_part(builder, builder.physical_calls[item["context"]], span) for item in choices]
            if any(part is None for part in parts):
                raise _StitchCut("physical target output unavailable")
            node = builder._new(None, {"kind": "phi", "reason": "physical call targets", "size": span.size,
                                       "register_offset": span.start,
                                       "target_selector": found["id"], "alternatives": parts,
                                       "physical_only": True})
            builder._done(node)
            part = {"node": node["id"], "bytes": [0, span.size], "at": [0, span.size]}
            found["outputs"].append({"offset": span.start, "size": span.size, "part": part})
            return part
        except (_StitchCut, _Truncated, RecursionError):
            _restore(builder, checkpoint)
            return None
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
    """Validate a known producer's dominance and absence of later writes.

    ``span=None`` checks dominance/no intervening calls only, for validating
    that an existing post-call SSA write really follows that call.
    """
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
            if span is not None and output is not None and output.kind is VarnodeKindCode.REGISTER \
                    and output.coordinate.space_id == builder.register_space \
                    and output.coordinate.byte_offset < span.end \
                    and span.start < output.coordinate.byte_offset + output.byte_size:
                return False
        incoming = conditions.predecessors[key]
        found = key != conditions.entry and bool(incoming) and all(trace(item) for item in incoming)
        memo[identity] = found
        return found

    return ordinal is not None and trace(location, ordinal)


def _post_call_definition(builder, base, read, piece, resolution):
    """Validate the single definition already supplied by this SSA fragment."""
    fragments = [fragment for fragment in resolution.fragments if fragment.span.contains(piece)]
    if len(fragments) != 1 or len(fragments[0].definition_ids) != 1:
        return None
    identifier, = fragments[0].definition_ids
    definition = builder.ssa.definitions[identifier]
    if definition.kind is not MemoryDefinitionKind.DATA_WRITE or not definition.span.contains(piece):
        return None
    raw = _raw(builder, definition.operation_key)
    output = raw[2].output if raw is not None else None
    if output is None or output.kind is not VarnodeKindCode.REGISTER \
            or output.coordinate.space_id != builder.register_space \
            or not output.coordinate.byte_offset <= piece.start < piece.end <= output.coordinate.byte_offset + output.byte_size:
        return None
    if not _unmodified_read(builder, base, definition.operation_key, None) \
            or not _unmodified_read(builder, definition.operation_key, read, piece):
        return None
    return definition.operation_key


def _guarded_register_plan(builder, base, read, piece, resolution, parts, origin):
    """Reuse a supplied SSA phi's exact guards, never invent a new source."""
    from .operation_records import _slice_parts

    if not _unmodified_read(builder, base, read, None):
        return None
    originals = _slice_parts(parts, piece.start - origin, piece.end - origin)
    if len(originals) != 1 or originals[0].get("loop") or originals[0].get("pruned"):
        return None
    source = originals[0]
    phi = builder.records[source["node"]]
    if phi.get("kind") != "phi" or not any(field in phi for field in ("condition", "guarded_sources")):
        return None
    fragments = [fragment for fragment in resolution.fragments if fragment.span.contains(piece)]
    if len(fragments) != 1:
        return None
    identifiers = []
    for identifier in fragments[0].definition_ids:
        identifiers.extend(builder.index.joins.get(identifier, (identifier,)))
    alternatives = phi.get("alternatives", ())
    sources = [part.get("definition_ref", {}).get("id") for part in alternatives]
    if len(sources) != len(set(sources)) or set(sources) != set(identifiers):
        return None
    conditions = builder._condition_index()
    location = conditions._locations.get(read)
    if location is None:
        return None
    guarded, _ = conditions.guarded_sources(piece, tuple(sources), location[0], read)
    if guarded is None:
        return None
    if "guarded_sources" in phi and phi["guarded_sources"] != {
            "guards": [builder._guard_ref(guard) for guard in guarded.guards],
            "reach": builder._guard_ref(guarded.reach)}:
        return None
    low, high = source["bytes"]
    selected = []
    for identifier, alternative in zip(sources, alternatives, strict=True):
        definition = builder.ssa.definitions[identifier]
        if not definition.span.contains(piece):
            return None
        sliced = _slice_parts([alternative], low, high)
        if len(sliced) != 1 or sliced[0].get("loop") or sliced[0].get("pruned"):
            return None
        part, = sliced
        producer = builder.records[part["node"]]
        if definition.kind is MemoryDefinitionKind.ENTRY:
            if producer.get("kind") not in ("entry", "bound"):
                return None
            kind = "call"
        elif definition.kind is MemoryDefinitionKind.DATA_WRITE:
            raw = _raw(builder, definition.operation_key)
            output = raw[2].output if raw is not None else None
            if producer.get("kind") != "op" or producer.get("key") != definition.operation_key \
                    or producer.get("interrupted") or output is None or output.kind is not VarnodeKindCode.REGISTER \
                    or output.coordinate.space_id != builder.register_space \
                    or not output.coordinate.byte_offset <= piece.start < piece.end \
                        <= output.coordinate.byte_offset + output.byte_size:
                return None
            if _unmodified_read(builder, base, definition.operation_key, None):
                kind = "retained"
            elif _unmodified_read(builder, definition.operation_key, base, piece):
                kind = "call"
            else:
                return None
        else:
            return None
        selected.append({"kind": kind, "original": part, "operation": definition.operation_key})
    return {"source": source, "sources": selected}


def _guarded_register_part(builder, found, base, read, piece, plan):
    """A physical-only overlay; the original SSA phi is left unchanged."""
    from copy import deepcopy
    from .operation_records import _StitchCut

    phi = builder.records[plan["source"]["node"]]
    alternatives = []
    for item in plan["sources"]:
        if item["operation"] is not None:
            producer = builder.records[item["original"]["node"]]
            boundary = {"operation": item["operation"], "node": producer["id"],
                        "context": builder.physical_context, "output": producer["output"],
                        "phase": "after" if item["kind"] == "retained" else "before"}
            inventory = found.setdefault("caller_register_writes", [])
            if boundary not in inventory:
                inventory.append(boundary)
        part = output_part(builder, found, piece) if item["kind"] == "call" else item["original"]
        if part is None:
            raise _StitchCut("guarded register export unavailable")
        alternatives.append(dict(part))
        builder._edge()
    record = builder._new(None, {"kind": "phi", "reason": "physical register choices", "size": piece.size,
                                 "alternatives": alternatives, "physical_only": True,
                                 "physical_register_choice": {**plan, "register_offset": piece.start,
                                                              "size": piece.size, "call": base, "read": read,
                                                              "context": found["id"]}})
    for name in ("condition", "choices", "guarded_sources"):
        if name in phi:
            record[name] = deepcopy(phi[name])
    builder._done(record)
    return {"node": record["id"], "bytes": [0, piece.size], "at": [0, piece.size]}


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


def bind_register_fragments(builder, read, span, resolution, parts=None, input_index=None):
    """Overlay only the original call-clobber spans, keeping other SSA parts.

    Bounds come from the existing read fragments and debt spans, not another
    reaching-definition walk. Each replacement still needs an unchanged path
    from exactly one observed call and an exact terminal export.
    """
    from .operation_records import _StitchCut, _Truncated, _register_overlay, _slice_parts

    if resolution.span.object_id != span.object_id or not resolution.span.contains(span) \
            or builder.ssa.actions[resolution.action_id].operation_key != read:
        return None
    rows = [row for row in builder.normalized.call_clobber_reads if row.operation_key == read
            and any(piece.overlaps(span) for piece in row.spans)]
    if not rows:
        return None
    calls = {call for row in rows for call in row.intervening_calls}
    if len(calls) != 1:
        return None
    base, = calls
    bands = [piece for row in rows for piece in row.spans if piece.overlaps(span)]
    points = {span.start, span.end}
    for piece in (*bands, *(fragment.span for fragment in resolution.fragments)):
        if piece.overlaps(span):
            points.update((max(span.start, piece.start), min(span.end, piece.end)))
    points = sorted(points)
    checkpoint = _checkpoint(builder)
    try:
        if parts is None:
            parts = _slice_parts(builder._fragments(resolution, None, 0), span.start - resolution.span.start,
                                 span.end - resolution.span.start)
        wanted, retained, guarded = [], [], []
        for low, high in zip(points, points[1:]):
            if not any(piece.start <= low and high <= piece.end for piece in bands):
                continue
            piece = ByteSpan(span.object_id, low, high - low)
            if _unmodified_read(builder, base, read, piece):
                wanted.append(piece)
            else:
                definition = _post_call_definition(builder, base, read, piece, resolution)
                if definition is not None:
                    retained.append((piece, definition))
                    continue
                plan = _guarded_register_plan(builder, base, read, piece, resolution, parts, span.start)
                if plan is None:
                    raise _StitchCut("guarded register source unavailable")
                guarded.append((piece, plan))
        if not wanted and not guarded:
            raise _StitchCut("no call register fragments")
        found = context(builder, base)
        if found is None:
            raise _StitchCut("partial register call unavailable")
        replacements = []
        for piece in wanted:
            part = output_part(builder, found, piece)
            if part is None:
                raise _StitchCut("partial register export unavailable")
            replacements.append({"context": found["id"], "part": part,
                                 "offset": piece.start - span.start, "size": piece.size,
                                 "register_offset": piece.start, "read": read, "call": base})
        for piece, plan in guarded:
            part = _guarded_register_part(builder, found, base, read, piece, plan)
            replacements.append({"context": found["id"], "part": part,
                                 "offset": piece.start - span.start, "size": piece.size,
                                 "register_offset": piece.start, "read": read, "call": base})
        replacements.sort(key=lambda item: item["offset"])
        merged = _register_overlay(parts, span.size, replacements)
        retained_parts = []
        for piece, operation in retained:
            (part,) = _slice_parts(parts, piece.start - span.start, piece.end - span.start)
            retained_parts.append({"offset": piece.start - span.start, "size": piece.size,
                                   "register_offset": piece.start, "operation": operation,
                                   "part": part, "call": base, "context": found["id"]})
        return {"read": read, "input": input_index,
                "register_offset": span.start, "size": span.size, "context": builder.physical_context,
                "overrides": replacements, "retained": retained_parts, "parts": merged}
    except (_StitchCut, _Truncated, RecursionError, ValueError):
        _restore(builder, checkpoint)
        return None


def register_bindings(operands, *, retained=False):
    for operand in operands:
        if "physical_register" in operand:
            yield operand["physical_register"]
        if "physical_register_fragments" in operand:
            yield from operand["physical_register_fragments"].get("overrides", ())
            if retained:
                yield from operand["physical_register_fragments"].get("retained", ())


def covers_register(start, size, bindings, calls):
    """Exact union coverage, not one successful fragment for a whole debt."""
    position = start
    bands = sorted((item["register_offset"], item["register_offset"] + item["size"])
                   for item in bindings if item["call"] in calls)
    for low, high in bands:
        if low > position:
            break
        if low <= position < high:
            position = high
        if position >= start + size:
            return True
    return False


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
    from .call_clobber import rows_by_node

    covered = []
    for raw_node, rows in rows_by_node(builder.normalized.call_clobber_reads,
                                       builder.normalized.call_clobber_nodes).items():
        if rows[0].operation_key != record.get("key"):
            continue
        identifier = builder.id_of.get(raw_node)
        if identifier not in debts:
            continue
        # a debt is covered only if every row of its node is (a copy proof
        # splits one reader's row)
        if all(_row_covered(builder, record, row, identifier) for row in rows):
            covered.append(identifier)
    if covered:
        record["physical_call_debt_ids"] = covered


def _row_covered(builder, record, row, identifier) -> bool:
    if any(context(builder, base) is None for base in row.intervening_calls):
        return False
    registers = [part for part in row.spans if part.object_id.kind is StorageObjectKind.REGISTER_FILE]
    memory = [part for part in row.spans if part.object_id.kind in
              (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)]
    bindings = list(register_bindings(record.get("operands", ()), retained=True))
    if len(registers) + len(memory) != len(row.spans):
        return False
    if memory:
        load_complete = record.get("opcode") == "LOAD" and record.get("physical_memory", {}).get("complete")
        direct_complete = identifier in record.get("physical_read_debt_ids", ())
        if not (load_complete or direct_complete):
            return False
    return all(covers_register(span.start, span.size, bindings, row.intervening_calls) for span in registers)


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
