"""Guarded physical memory relations over existing raw operations and SSA.

The optional record view retains every debt and the ordinary evaluator's
eligibility. Its separate concrete interpretation requires known physical
addresses and actual CFG guards; it never assumes that two bases differ.
"""

from __future__ import annotations

from dataclasses import dataclass
from heapq import heappop, heappush

from ._scope_contracts import VarnodeKindCode
from .call_seeds import _operation_key
from .resource_limits import step
from .span_geometry import StorageObjectKind

_MEMORY = (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)
_CALLS = ("CALL", "CALLIND", "CALLOTHER")


@dataclass(frozen=True, slots=True)
class MemoryEvent:
    key: str
    kind: str
    guard: int
    width: int | None
    space: int | None
    node: int | None
    action_id: int | None
    reason: str | None = None
    address: int | None = None


@dataclass(frozen=True, slots=True)
class MemoryPlan:
    space: int
    width: int
    address_bits: int
    little_endian: bool
    guard: int
    events: tuple[MemoryEvent, ...]
    complete: bool = True  # complete event inventory, not a claim that values are known
    address: int | None = None


class MemoryIndex:
    """Index all physical writes, including definite SSA writes, in CFG order.

    A topological order only orders potentially coexecuted operations. The
    existing ConditionIndex's reach guards decide which of them ran. Taking
    only may-alias writers would be wrong when a later definite write kills
    some bytes of an earlier aliasing store.
    """

    def __init__(self, normalized, unit, index, conditions):
        self.normalized, self.unit, self.index, self.conditions = normalized, unit, index, conditions
        self._plans, self._points, self._events = {}, {}, []
        self._direct_plans = {}
        self._prefixes, self._block_points = {}, {}
        self._problem = None
        self.address_bits = {row.space_id: row.address_size_bits
                             for row in unit.scopes.program.evidence.address_spaces if row.is_memory_space}
        self.little = index.little
        self.operations = {}
        self.actions = {action.operation_key: identifier for identifier, action in enumerate(index.ssa.actions)}
        self.proven = dict(normalized.proven_call_effects)
        graph = getattr(conditions, "blocks", {})
        memory = normalized.memory_unit
        if memory is None or not graph or set(graph) != {block.key for block in memory.blocks}:
            self._problem = "physical cfg unavailable"
            return
        predecessors = {block.key: set(block.predecessors) for block in memory.blocks}
        successors = {key: [] for key in graph}
        for key, values in predecessors.items():
            step()
            for previous in values:
                step()
                successors[previous].append(key)
        degree = {key: len(values) for key, values in predecessors.items()}
        pending = []
        for key, count in degree.items():
            if count == 0:
                heappush(pending, key)
        order = []
        while pending:
            step()
            key = heappop(pending)
            order.append(key)
            for target in successors[key]:
                step()
                degree[target] -= 1
                if degree[target] == 0:
                    heappush(pending, target)
        if len(order) != len(graph):
            self._problem = "cyclic physical cfg"
            return
        rows = {row.address: row for row in unit.observation.instructions}
        effect_memory = {
            effect.operation_key for effect in normalized.effects
            if effect.memory_write is not None or effect.unresolved_writes
            or any(getattr(write, "span", None) is not None and write.span.object_id.kind in _MEMORY
                   for write in effect.writes)
        }
        for rank, key in enumerate(order):
            block = graph[key]
            self._block_points[key] = (rank, block.stop)
            row = rows[block.instruction]
            for ordinal in range(block.start, block.stop):
                step()
                operation = row.operations[ordinal]
                operation_key = _operation_key(row.address, ordinal, operation.opcode)
                self.operations[operation_key] = operation
                point = self._points[operation_key] = (rank, ordinal)
                kind, width, space, reason, address = None, None, None, None, None
                if operation.opcode == "STORE" and len(operation.inputs) == 3:
                    kind, width = "store", operation.inputs[2].byte_size
                    if operation.inputs[0].kind is VarnodeKindCode.CONSTANT:
                        space = operation.inputs[0].coordinate.byte_offset
                    else:
                        kind, reason = "opaque", "unknown memory space"
                elif operation.opcode in _CALLS or row.flow.is_call and operation.opcode in ("BRANCH", "BRANCHIND"):
                    kind, reason = "call", "call memory boundary"
                elif operation.output is not None and (
                    operation.output.kind is VarnodeKindCode.ADDRESS
                    and operation.output.coordinate.space_id in self.address_bits
                ):
                    kind, width = "write", operation.output.byte_size
                    space, address = operation.output.coordinate.space_id, operation.output.coordinate.byte_offset
                elif operation_key in effect_memory:
                    kind, reason = "opaque", "memory writer is not a raw STORE"
                if kind is None:
                    continue
                # Normalization can omit transient call setup operations from
                # SSA actions. Their observed block still gives exact reach;
                # the missing STORE node remains opaque if that path is taken.
                guard, why = conditions.reach_guard(key)
                if guard is None:
                    self._problem = why or "memory event reach unavailable"
                    return
                node = normalized.dependencies.node_for_key(f"op:{operation_key}")
                if kind in ("store", "write") and node is None:
                    kind, reason = "opaque", "memory writer has no existing operation node"
                self._events.append((point, MemoryEvent(operation_key, kind, guard, width, space, node,
                                                       self.actions.get(operation_key), reason, address)))
        # A modeled call's synthetic writes are covered by its raw call
        # boundary. Any other unrepresented write prevents an exact inventory.
        for key in effect_memory:
            step()
            base = key.split("~", 1)[0]
            if key not in self._points and (base not in self.operations or self.operations[base].opcode not in _CALLS):
                self._problem = "unrepresented memory event"
                return

    def plan(self, load_key):
        """``(MemoryPlan, None)`` or ``(None, reason)`` for one original LOAD."""
        if load_key not in self._plans:
            step()
            self._plans[load_key] = self._plan(load_key)
        return self._plans[load_key]

    def plan_direct(self, operation_key, input_index):
        """An original ADDRESS-valued data input reads fixed physical RAM.

        Direct control destinations are coordinates, not memory contents.
        Indirect control operands, like other data ADDRESS operands, retain
        their original dereference meaning; this does not resolve the call.
        """
        key = operation_key, input_index
        if key not in self._direct_plans:
            step()
            self._direct_plans[key] = self._plan_direct(operation_key, input_index)
        return self._direct_plans[key]

    def _plan_direct(self, operation_key, input_index):
        if self._problem is not None:
            return None, self._problem
        operation = self.operations.get(operation_key)
        if operation is None or type(input_index) is not int or not 0 <= input_index < len(operation.inputs) \
                or input_index == 0 and operation.opcode in ("CALL", "BRANCH", "CBRANCH"):
            return None, "not an original ADDRESS data input"
        source = operation.inputs[input_index]
        if source.kind is not VarnodeKindCode.ADDRESS or source.coordinate.space_id not in self.address_bits:
            return None, "not an original physical memory input"
        action_id = self.actions.get(operation_key)
        matched = False
        for read in self.index.reads.get(action_id, ()):
            step()
            if read.span.object_id.kind is StorageObjectKind.ADDRESS_SPACE \
                    and read.span.object_id.space_key == source.coordinate.space_id \
                    and read.span.start == source.coordinate.byte_offset and read.span.size == source.byte_size:
                matched = True
                break
        if action_id is None or not matched:
            return None, "no existing exact physical memory read"
        if not self.little:
            return None, "unsupported physical memory geometry"
        guard, reason = self.conditions.reach_guard(operation_key)
        if guard is None:
            return None, reason or "memory input reach unavailable"
        prefix, reason = self.prefix(operation_key)
        if prefix is None:
            return None, reason
        space = source.coordinate.space_id
        step(len(prefix) + 1)
        events = tuple(event for event in prefix if event.space is None or event.space == space)
        return MemoryPlan(space, source.byte_size, self.address_bits[space], self.little,
                          guard, events, address=source.coordinate.byte_offset), None

    def prefix(self, operation_or_block):
        """All original memory events before an operation, or through a block.

        This inventory is independent of whether the root has a LOAD. A
        consumer must inspect event reach before rejecting an opaque/call
        boundary; topological order does not itself prove coexecution.
        """
        if operation_or_block not in self._prefixes:
            step()
            point = self._points.get(operation_or_block, self._block_points.get(operation_or_block))
            if point is None and operation_or_block in self.actions:
                base, separator, tag = operation_or_block.partition("~")
                effect = self.proven.get(base)
                operation = self.operations.get(base)
                if separator and tag.isdigit() and effect is not None and base in self._points \
                        and operation is not None and operation.opcode in ("CALL", "CALLIND"):
                    from .operation_records import _output_run

                    if _output_run(effect, tag) is not None:
                        rank, ordinal = self._points[base]
                        point = rank, ordinal + 1
            if self._problem is not None:
                found = None, self._problem
            elif point is None:
                found = None, "unknown physical root location"
            else:
                events = []
                for previous, event in self._events:
                    step()
                    if previous >= point:
                        break
                    events.append(event)
                found = tuple(events), None
            self._prefixes[operation_or_block] = found
        return self._prefixes[operation_or_block]

    def inventory(self):
        """The complete existing acyclic event inventory, in CFG order.

        A prefix at one RETURN is not a whole-function inventory: another
        exit's events may be later in the topological order. Consumers still
        select actual execution with the original operation reach guards.
        """
        if self._problem is not None:
            return None, self._problem
        if not hasattr(self, "_inventory"):
            self._inventory = tuple(event for _, event in self._events)
            step(len(self._inventory) + 1)
        return self._inventory, None

    def _plan(self, load_key):
        if self._problem is not None:
            return None, self._problem
        operation = self.operations.get(load_key)
        if operation is None or operation.opcode != "LOAD" or len(operation.inputs) != 2 or operation.output is None:
            return None, "not an original LOAD"
        if operation.inputs[0].kind is not VarnodeKindCode.CONSTANT:
            return None, "unknown memory space"
        space = operation.inputs[0].coordinate.byte_offset
        if space not in self.address_bits or not self.little:
            return None, "unsupported physical memory geometry"
        guard, reason = self.conditions.reach_guard(load_key)
        if guard is None:
            return None, reason or "LOAD reach unavailable"
        prefix, reason = self.prefix(load_key)
        if prefix is None:
            return None, reason
        events = [event for event in prefix if event.space is None or event.space == space]
        return MemoryPlan(space, operation.output.byte_size, self.address_bits[space], self.little,
                          guard, tuple(events)), None


@dataclass(frozen=True, slots=True)
class PhysicalEvaluation:
    value: int
    evidence: tuple[dict, ...]


def evaluate_physical(record, entry, *, max_steps=200000):
    """One explicitly requested concrete interpretation of a physical record.

    Reuses the ordinary evaluator's arithmetic and byte assembly. The entry
    callback supplies physical register values and ``('memory', space,
    address, size)`` function-entry bytes. A known-body call is interpreted
    only after its original RETURN target and stack value are verified.
    Unknown guards/calls, missing addresses, cuts or unexplained debts refuse.
    This does not change ``eligibility(record)`` or the record's debts.
    """
    from .operation_records import (
        Ineligible, Limits, _Evaluator, _Unknown, _choice_contract, _compose, _register_overlay, _slice_parts,
    )

    if record.get("truncated") is not False or record.get("demand_complete") is not True:
        raise Ineligible("incomplete physical record")
    try:
        nodes = {node["id"]: node for node in record.get("nodes", ())}
        _, control = _choice_contract(record, nodes, list(nodes.values()), route="stitched")
    except (KeyError, IndexError, TypeError, ValueError):
        raise Ineligible("invalid physical record") from None

    class PhysicalEvaluator(_Evaluator):
        def __init__(self):
            super().__init__(nodes, entry, None, {}, "injected", control=control)
            self.guard_values, self.guard_active, self.value_active = {}, set(), set()
            self.context_values, self.context_active, self.entry_active = {}, set(), set()
            self.context_returns = {}
            self.context_outputs = {}
            self.read_debts = {}
            self.context_reach_values, self.context_reach_active = {}, set()
            self.contexts = record.get("physical_calls", {})
            self.selectors = record.get("target_selectors", {})
            self.target_values, self.target_active = {}, set()
            self.evidence, self.remaining = [], max_steps

        def tick(self, cost=1):
            step(cost)
            self.remaining -= cost
            if self.remaining < 0:
                raise Ineligible("physical work limit")

        def physical_guard(self, reference):
            self.tick()
            if type(reference) is not int or reference < 0:
                raise Ineligible("missing physical guard")
            if reference in self.guard_values:
                return self.guard_values[reference]
            guards = self.control.get("nodes", ())
            if reference >= len(guards) or guards[reference] is None:
                raise Ineligible("unserialized physical guard")
            if reference in self.guard_active:
                raise Ineligible("physical guard cycle")
            self.guard_active.add(reference)
            try:
                guard = guards[reference]
                if type(guard) is bool:
                    found = guard
                elif isinstance(guard, dict):
                    decision = self.control.get("decisions", {}).get(guard.get("decision"))
                    if decision is None or "operand" not in decision:
                        raise Ineligible("unknown physical decision")
                    outcome = bool(self.full_operand(decision["operand"]))
                    found = self.physical_guard(guard["true"] if outcome else guard["false"])
                    self.evidence.append({"kind": "decision", "decision": guard["decision"], "taken": outcome})
                else:
                    raise Ineligible("invalid physical guard")
                self.guard_values[reference] = found
                return found
            finally:
                self.guard_active.remove(reference)

        def require_context(self, node):
            if "physical_context" in node:
                context_id = node["physical_context"]
                if context_id not in self.context_active:
                    self.validate_context(context_id)
                elif not self.context_reached(context_id):
                    raise Ineligible("physical call unreached")

        def require_reach(self, node):
            self.require_context(node)
            if "physical_guard" in node:
                if not self.physical_guard(node["physical_guard"]):
                    raise Ineligible("physical operation unreached")
                return
            key = node.get("key")
            if key is not None:
                reference = self.control.get("reach", {}).get(key)
                if reference is None or not self.physical_guard(reference):
                    raise Ineligible("physical operation unreached")

        def guard(self, reference):
            return self.physical_guard(reference)

        def context(self, identifier, call=None):
            self.tick()
            context = self.contexts.get(identifier)
            if not isinstance(context, dict) or context.get("complete", True) is not True \
                    or type(context.get("call")) is not str or call is not None and context["call"] != call:
                raise Ineligible("unknown physical call context")
            for name in ("prefix", "events"):
                if not isinstance(context.get(name), (tuple, list)):
                    raise Ineligible("incomplete physical call context")
            if not isinstance(context.get("push"), dict):
                raise Ineligible("incomplete physical call context")
            if context.get("kind") != "target_selection":
                self.return_rows(context)
            return context

        def selected_context(self, identifier):
            self.tick()
            if identifier in self.target_values:
                return self.target_values[identifier]
            if identifier in self.target_active:
                raise Ineligible("physical target selection cycle")
            selector = self.selectors.get(identifier)
            if not isinstance(selector, dict) or not self.context_reached(identifier):
                raise Ineligible("physical indirect call unreached")
            self.target_active.add(identifier)
            try:
                target = self.full_operand(selector["operand"])
                matches = [item for item in selector["candidates"] if item["value"] == target]
                if len(matches) != 1:
                    raise Ineligible("physical target outside proven candidates")
                chosen, = matches
                self.target_values[identifier] = chosen["context"]
                self.evidence.append({"kind": "target", "selector": identifier, "call": selector["call"],
                                      "target": target, "function": chosen["function"],
                                      "context": chosen["context"], "requires": selector["requires"]})
                return chosen["context"]
            finally:
                self.target_active.remove(identifier)

        def return_rows(self, context):
            self.tick()
            returned = context.get("returns")
            if returned is None:
                returned = (context.get("return"),)  # v6 single-return records
            if not isinstance(returned, (tuple, list)) or not returned:
                raise Ineligible("incomplete physical return inventory")
            for item in returned:
                self.tick()
                if not isinstance(item, dict):
                    raise Ineligible("incomplete physical return inventory")
            if "return" in context and (len(returned) != 1 or context["return"] != returned[0]):
                raise Ineligible("inconsistent physical return alias")
            return returned

        def context_reached(self, identifier):
            """Caller-local reach is meaningful only after ancestor reach.

            This checks execution, not completion. In particular it must not
            validate a parent transaction while reading its entry memory.
            """
            self.tick()
            if identifier in self.context_reach_values:
                return self.context_reach_values[identifier]
            if identifier in self.context_reach_active:
                raise Ineligible("physical context reach cycle")
            context = self.context(identifier)
            self.context_reach_active.add(identifier)
            try:
                parent = context.get("parent_context")
                found = (parent is None or self.context_reached(parent)) \
                    and self.physical_guard(context.get("guard"))
                if found and context.get("selected_by") is not None:
                    found = self.selected_context(context["selected_by"]) == identifier
                self.context_reach_values[identifier] = found
                return found
            finally:
                self.context_reach_active.remove(identifier)

        def validate_context(self, identifier, call=None):
            """Publish success only after the recorded body actually returns.

            A RETURN's LOAD may read this context's entry view while validation
            is active. That view is the earlier caller prefix plus the observed
            push, and does not recursively claim the callee already returned.
            """
            context = self.context(identifier, call)
            if identifier in self.context_values:
                return self.context_values[identifier]
            if identifier in self.context_active:
                raise Ineligible("physical call context cycle")
            parent = context.get("parent_context")
            if parent is not None and parent not in self.context_active and parent not in self.context_values:
                # A detached child result cannot bypass unverified effects in
                # its containing call. Parent validation will enter the child
                # normally while that parent transaction is active.
                self.validate_context(parent)
                if identifier in self.context_values:
                    return self.context_values[identifier]
            if not self.context_reached(identifier):
                raise Ineligible("physical call unreached")
            self.context_active.add(identifier)
            try:
                if context.get("kind") == "target_selection":
                    selected = self.selected_context(identifier)
                    body = self.validate_context(selected, call)
                    self.context_values[identifier] = body
                    self.context_returns[identifier] = self.context_returns[selected]
                    return body
                # Earlier and nested calls publish only fully validated
                # effects. An active unknown call or opaque event still fails.
                tuple(self.stores(context["prefix"]))
                body = tuple(self.stores(context["events"]))
                for event in body:
                    self.store_pointer(event)
                push = context["push"]
                if push.get("kind") != "store" or not self.physical_guard(push.get("guard")):
                    raise Ineligible("missing physical call push")
                self.store_pointer(push)
                reached = [item for item in self.return_rows(context) if self.physical_guard(item.get("guard"))]
                if len(reached) != 1:
                    raise Ineligible("physical call has no unique reached RETURN")
                returned, = reached
                operand = returned["operand"]
                expected = returned["expected_target"]
                if type(expected) is not int or expected < 0:
                    raise Ineligible("invalid physical return target")
                target = self.full_operand(operand)
                if expected >= 1 << (8 * operand["width"]) or target != expected:
                    raise Ineligible("physical return target mismatch")
                push_value = self.value(push["node"])
                if push_value != expected:
                    raise Ineligible("physical push target mismatch")
                stack, expected_stack = returned["stack"], returned["expected_stack"]
                if stack.get("width") != expected_stack.get("width") \
                        or self.full_operand(stack) != self.full_operand(expected_stack):
                    raise Ineligible("physical return stack mismatch")
                # A body transaction is complete only when every executed
                # STORE's value is known, including writes the result/RETURN
                # does not read. Inactive stores remain unevaluated.
                for event in body:
                    self.value(event["node"])
                self.context_returns[identifier] = returned["key"]
                self.context_values[identifier] = body
                self.evidence.append({"kind": "call", "context": identifier, "call": context["call"],
                                      "return": returned["key"], "target": target})
                return body
            finally:
                self.context_active.remove(identifier)

        def stores(self, events):
            """Flatten proved call relations, not a forward execution state."""
            for event in events:
                self.tick()
                known_call = event.get("kind") == "call" and event.get("context") is not None
                if known_call and not self.context_reached(event["context"]) \
                        or not known_call and not self.physical_guard(event.get("guard")):
                    continue
                if event.get("kind") == "call":
                    yield from self.validate_context(event.get("context"), event.get("key"))
                elif event.get("kind") in ("store", "write"):
                    yield event
                else:
                    raise Ineligible("active or unknown physical memory event")

        def store_pointer(self, event, space=None, bits=None):
            self.tick()
            writer = self.nodes.get(event.get("node"))
            if event.get("kind") == "write":
                pointer = self.write_geometry(event, writer)
                if space is not None and event["space"] != space \
                        or bits is not None and event["width"] > 1 << bits:
                    raise Ineligible("invalid physical direct-write relation")
                self.require_reach(writer)
                return pointer if bits is None else pointer & ((1 << bits) - 1)
            operands = {operand["index"]: operand for operand in writer.get("operands", ())} \
                if writer is not None else {}
            width = event.get("width")
            if event.get("kind") != "store" or writer is None or writer.get("opcode") != "STORE" \
                    or type(event.get("space")) is not int or writer.get("space") != event["space"] \
                    or writer.get("key") != event.get("key") or 1 not in operands or 2 not in operands \
                    or type(width) is not int or width <= 0 or width != operands[2].get("width") \
                    or space is not None and event["space"] != space \
                    or bits is not None and width > 1 << bits:
                raise Ineligible("invalid physical STORE relation")
            self.require_reach(writer)
            pointer = self.full_operand(operands[1])
            return pointer if bits is None else pointer & ((1 << bits) - 1)

        def write_geometry(self, event, writer):
            """An ADDRESS output is an observed fixed-address byte write.

            Only its coordinate is literal; its value is still evaluated by
            the original operation and remains subject to every input debt.
            """
            self.tick()
            detail = writer.get("physical_write") if isinstance(writer, dict) else None
            output = writer.get("output") if isinstance(writer, dict) else None
            address, width, space = event.get("address"), event.get("width"), event.get("space")
            if not isinstance(detail, dict) or not isinstance(output, dict) \
                    or writer.get("kind") != "op" or writer.get("key") != event.get("key") \
                    or type(address) is not int or address < 0 \
                    or type(width) is not int or width <= 0 or type(space) is not int or space < 0 \
                    or any(type(detail.get(key)) is not int or detail[key] != value
                           for key, value in (("space", space), ("address", address), ("width", width))) \
                    or output.get("kind") != StorageObjectKind.ADDRESS_SPACE.value \
                    or type(output.get("start")) is not int or output["start"] != address \
                    or type(output.get("size")) is not int or output["size"] != width:
                raise Ineligible("invalid physical direct-write relation")
            return address

        def active_stores(self, events, space, bits):
            found = []
            for event in self.stores(events):
                # Distinct physical memory spaces cannot overlap. Unknown
                # spaces remain opaque events, never a disjointness claim.
                if type(event.get("space")) is not int:
                    raise Ineligible("unknown physical memory space")
                if event["space"] == space:
                    found.append((event, self.store_pointer(event, space, bits)))
            return found

        def memory_byte(self, active, space, address, bits, entry_context=None):
            self.tick()
            mask = (1 << bits) - 1
            for event, pointer in reversed(active):
                self.tick()
                displacement = (address - pointer) & mask
                if displacement < event["width"]:
                    value = (self.value(event["node"]) >> (8 * displacement)) & 255
                    return value, {"writer": event["key"], "offset": displacement}
            if entry_context is not None:
                identity = entry_context, space, address, bits
                if identity in self.entry_active:
                    raise Ineligible("physical memory entry cycle")
                context = self.context(entry_context)
                if not self.context_reached(entry_context):
                    raise Ineligible("physical call entry unreached")
                self.entry_active.add(identity)
                try:
                    events = (*context["prefix"], context["push"])
                    prior = self.active_stores(events, space, bits)
                    return self.memory_byte(prior, space, address, bits, context.get("parent_context"))
                finally:
                    self.entry_active.remove(identity)
            value = self.entry(("memory", space, address, 1))
            if value is None:
                raise _Unknown()
            return value & 255, {"entry": address}

        def check_part(self, item, width=None):
            """A byte projection must fit its original producer's value.

            Definition fragments may start inside a larger raw output; their
            offsets are not rebased to the fragment's own width. Conversely,
            equal projection widths do not justify reading beyond that output.
            """
            self.tick()
            if not isinstance(item, dict) or item.get("node") not in self.nodes or item.get("loop"):
                raise Ineligible("invalid physical part reference")
            a, b = item["bytes"]
            if type(a) is not int or type(b) is not int or not 0 <= a < b \
                    or width is not None and b - a != width:
                raise Ineligible("invalid physical part range")
            node = self.nodes[item["node"]]
            kind, size = node.get("kind"), None
            if kind == "const" or kind in ("bound", "assemble", "phi"):
                size = node.get("size")
            elif kind == "entry":
                place = next((node[name] for name in ("register", "absolute", "place") if name in node), {})
                size = place.get("size") if isinstance(place, dict) else None
            elif kind == "op":
                if node.get("opcode") == "STORE":
                    value = next((operand for operand in node.get("operands", ()) if operand.get("index") == 2), {})
                    size = value.get("width")
                else:
                    output = node.get("output")
                    size = output.get("size") if isinstance(output, dict) else None
            elif kind == "call":
                output = item.get("output")
                size = output.get("size") if isinstance(output, dict) else None
            else:
                # Cuts/debts have no value extent; any selected use is still
                # rejected by value(). Do not evaluate inactive references.
                return
            if type(size) is not int or size <= 0 or b > size:
                raise Ineligible("physical part outside producer")

        def register_operand(self, operand):
            override = operand["physical_register"]
            width = operand.get("width")
            if not isinstance(override, dict) or type(override.get("offset")) is not int or override["offset"] != 0 \
                    or type(override.get("size")) is not int or override["size"] != width \
                    or type(override.get("register_offset")) is not int or override["register_offset"] < 0 \
                    or type(override.get("read")) is not str or type(override.get("call")) is not str:
                raise Ineligible("partial or invalid physical register projection")
            part = override["part"]
            a, b = part["bytes"]
            if type(a) is not int or type(b) is not int or not 0 <= a < b or b - a != width \
                    or part.get("at", [0, width]) != [0, width]:
                raise Ineligible("partial physical register value")
            self.exported_part(override.get("context"), override["register_offset"], width, part)
            self.validate_context(override.get("context"), override["call"])
            return self.part(part)

        def register_fragments(self, operand, owner=None, owner_context=None):
            """Validate an exact byte overlay; untouched parts are still SSA."""
            self.tick()
            relation = operand.get("physical_register_fragments")
            width = operand.get("width")
            if not isinstance(relation, dict) or "physical_register" in operand or "physical_read" in operand \
                    or operand.get("pruned") or operand.get("unresolved") \
                    or type(width) is not int or width <= 0 or type(relation.get("size")) is not int \
                    or relation["size"] != width \
                    or type(relation.get("register_offset")) is not int or relation["register_offset"] < 0 \
                    or type(relation.get("input")) is not int \
                    or relation.get("input") != operand.get("index") \
                    or type(relation.get("read")) is not str \
                    or owner is not None and (relation["read"] != owner or relation.get("context") != owner_context):
                raise Ineligible("invalid physical register fragment source")
            overrides = relation.get("overrides")
            if not isinstance(overrides, (tuple, list)) or not overrides:
                raise Ineligible("missing physical register fragments")
            owners = [node for node in self.nodes.values() if node.get("kind") == "op"
                      and node.get("key") == relation["read"]
                      and node.get("physical_context") == relation.get("context")]
            if len(owners) != 1:
                raise Ineligible("unknown physical register fragment owner")
            original, = owners
            bands = [(span, debt.get("calls", ())) for identifier in original.get("debts", ())
                     for debt in (self.nodes.get(identifier, {}),) if debt.get("debt") == "call_clobber_read"
                     for span in debt.get("physical_spans", ()) if span.get("kind") == "register_file"]
            for item in overrides:
                self.tick()
                if not isinstance(item, dict):
                    raise Ineligible("invalid physical register fragment")
                start, size = item.get("offset"), item.get("size")
                if type(start) is not int or type(size) is not int or not 0 <= start < start + size <= width \
                        or item.get("register_offset") != relation["register_offset"] + start \
                        or item.get("read") != relation["read"] or type(item.get("call")) is not str:
                    raise Ineligible("invalid physical register fragment range")
                self.context(item.get("context"), item["call"])
                self.check_part(item["part"], size)
                chosen = self.nodes[item["part"]["node"]]
                if "physical_register_choice" in chosen:
                    relation_choice = self.register_choice(chosen)
                    if item["part"].get("bytes") != [0, size] or item["part"].get("at") != [0, size] \
                            or any(relation_choice.get(name) != item.get(name) for name in (
                                "context", "call", "read", "register_offset", "size")):
                        raise Ineligible("physical guarded register projection mismatch")
                else:
                    self.exported_part(item.get("context"), item["register_offset"], size, item["part"])
                if not any(item["call"] in calls and span["start"] <= item["register_offset"]
                           and item["register_offset"] + size <= span["start"] + span["size"] for span, calls in bands):
                    raise Ineligible("register fragment is not an original call debt")
            retained = relation.get("retained")
            if not isinstance(retained, (tuple, list)):
                raise Ineligible("missing original register fragment inventory")
            covered = [(item["offset"], item["offset"] + item["size"]) for item in overrides]
            for item in retained:
                self.tick()
                if not isinstance(item, dict):
                    raise Ineligible("invalid original register fragment")
                start, size = item.get("offset"), item.get("size")
                if type(start) is not int or type(size) is not int or not 0 <= start < start + size <= width \
                        or item.get("register_offset") != relation["register_offset"] + start \
                        or type(item.get("operation")) is not str or type(item.get("call")) is not str \
                        or any(low < start + size and start < high for low, high in covered):
                    raise Ineligible("overlapping or invalid retained register fragment")
                covered.append((start, start + size))
                self.context(item.get("context"), item.get("call"))
                pieces = _slice_parts(operand.get("parts", ()), start, start + size)
                if pieces != [item.get("part")]:
                    raise Ineligible("retained register fragment is not original SSA")
                part = item["part"]
                self.check_part(part, size)
                producer = self.nodes[part["node"]]
                output = producer.get("output", {})
                if producer.get("kind") != "op" or producer.get("key") != item.get("operation") \
                        or producer.get("physical_context") != relation.get("context") \
                        or output.get("kind") != "register_file" \
                        or type(output.get("start")) is not int or type(output.get("size")) is not int \
                        or not output["start"] <= item["register_offset"] < item["register_offset"] + size \
                            <= output["start"] + output["size"] \
                        or part.get("bytes") != [item["register_offset"] - output["start"],
                                                 item["register_offset"] - output["start"] + size]:
                    raise Ineligible("retained register write correspondence")
            try:
                parts = _register_overlay(operand.get("parts", ()), width, overrides)
            except (KeyError, TypeError, ValueError):
                raise Ineligible("invalid physical register fragment assembly") from None
            if relation.get("parts") != parts:
                raise Ineligible("physical register fragments replaced original SSA bytes")
            return parts

        def register_choice(self, node):
            """A separate physical phi must keep the original SSA choice."""
            self.tick()
            choice, width = node.get("physical_register_choice"), node.get("size")
            if not isinstance(choice, dict) or node.get("kind") != "phi" \
                    or node.get("reason") != "physical register choices" \
                    or type(width) is not int or width <= 0 or choice.get("size") != width \
                    or type(choice.get("register_offset")) is not int or choice["register_offset"] < 0 \
                    or type(choice.get("read")) is not str or type(choice.get("call")) is not str:
                raise Ineligible("invalid physical register choice")
            self.check_part(choice.get("source"), width)
            source = choice["source"]
            original = self.nodes[source["node"]]
            if original is node or original.get("kind") != "phi" or "physical_register_choice" in original \
                    or original.get("physical_context") != node.get("physical_context") \
                    or source.get("at") != [0, width] \
                    or not any(field in original for field in ("condition", "guarded_sources")) \
                    or any(node.get(field) != original.get(field) for field in (
                        "condition", "choices", "guarded_sources")):
                raise Ineligible("physical register choice changed original control")
            context = self.context(choice.get("context"), choice["call"])
            if context.get("parent_context") != node.get("physical_context"):
                raise Ineligible("physical register choice has a different caller")
            sources, alternatives = choice.get("sources"), node.get("alternatives", ())
            if not isinstance(sources, (tuple, list)) or len(sources) != len(original.get("alternatives", ())) \
                    or len(sources) != len(alternatives):
                raise Ineligible("incomplete physical register choice")
            low, high = source["bytes"]
            for item, old, current in zip(sources, original["alternatives"], alternatives, strict=True):
                if not isinstance(item, dict) or item.get("kind") not in ("call", "retained") \
                        or item.get("operation") != old.get("definition_ref", {}).get("operation"):
                    raise Ineligible("physical register choice source mismatch")
                sliced = _slice_parts([old], low, high)
                if sliced != [item.get("original")]:
                    raise Ineligible("physical register choice is not original SSA")
                reference = old.get("definition_ref", {})
                if reference.get("kind") == "entry":
                    producer = self.nodes[item["original"]["node"]]
                    if item["kind"] != "call" or item["operation"] is not None \
                            or producer.get("kind") not in ("entry", "bound") \
                            or producer.get("physical_context") != node.get("physical_context"):
                        raise Ineligible("physical entry register choice classification")
                elif reference.get("kind") == "data_write":
                    producer = self.nodes[item["original"]["node"]]
                    boundary = {"operation": item["operation"], "node": producer["id"],
                                "context": node.get("physical_context"), "output": producer.get("output"),
                                "phase": "after" if item["kind"] == "retained" else "before"}
                    rows = [row for row in context.get("caller_register_writes", ())
                            if row.get("operation") == item["operation"]]
                    if rows != [boundary] or producer.get("kind") != "op" \
                            or producer.get("key") != item["operation"] \
                            or producer.get("physical_context") != node.get("physical_context"):
                        raise Ineligible("physical register choice crossed original call boundary")
                else:
                    raise Ineligible("unsupported original register choice definition")
                self.check_part(current, width)
                if current.get("at") != [0, width]:
                    raise Ineligible("physical register choice placement")
                if item["kind"] == "call":
                    self.exported_part(choice["context"], choice["register_offset"], width, current)
                else:
                    producer = self.nodes[current["node"]]
                    output = producer.get("output", {})
                    offset = choice["register_offset"]
                    if current != item["original"] or producer.get("kind") != "op" \
                            or producer.get("key") != item["operation"] \
                            or producer.get("physical_context") != node.get("physical_context") \
                            or output.get("kind") != "register_file" \
                            or type(output.get("start")) is not int or type(output.get("size")) is not int \
                            or not output["start"] <= offset < offset + width <= output["start"] + output["size"] \
                            or current["bytes"] != [offset - output["start"], offset - output["start"] + width]:
                        raise Ineligible("physical register choice changed retained SSA write")
            return choice

        def exported_part(self, identifier, offset, size, part):
            """Match an exact named projection of this body's terminal state."""
            self.tick()
            if type(offset) is not int or offset < 0 or type(size) is not int or size <= 0 \
                    or self.context_outputs.get(identifier, {}).get((offset, size)) != part:
                raise Ineligible("physical call output is not an exported projection")

        def exit_phi(self, node):
            """A physical export's choices are the original RETURN guards."""
            self.tick()
            identifier = node.get("instance")
            context = self.context(identifier)
            returned = self.return_rows(context)
            alternatives = node.get("alternatives", ())
            size = node.get("size")
            if node.get("physical_context") != identifier or node.get("kind") != "phi" \
                    or node.get("reason") != "callee exits" or len(returned) != len(alternatives) \
                    or type(size) is not int or size <= 0 or "condition" in node or "guarded_sources" in node \
                    or "choices" in node:
                raise Ineligible("physical exit selection mismatch")
            for alternative, exit_row in zip(alternatives, returned, strict=True):
                self.check_part(alternative, size)
                wrapper = self.nodes[alternative["node"]]
                if alternative.get("at") != [0, size] or wrapper.get("kind") != "assemble" \
                        or wrapper.get("physical_context") != identifier \
                        or wrapper.get("execution_guard") != exit_row.get("guard"):
                    raise Ineligible("physical exit guard correspondence")
            return returned

        def target_phi(self, node):
            identifier = node.get("target_selector")
            selector = self.selectors.get(identifier)
            alternatives, size = node.get("alternatives", ()), node.get("size")
            if not isinstance(selector, dict) or node.get("kind") != "phi" \
                    or node.get("reason") != "physical call targets" \
                    or type(size) is not int or size <= 0 \
                    or len(alternatives) != len(selector["candidates"]) \
                    or any(name in node for name in ("condition", "guarded_sources", "choices")):
                raise Ineligible("physical target output selection mismatch")
            for item, candidate in zip(alternatives, selector["candidates"], strict=True):
                self.check_part(item, size)
                exports = self.context_outputs.get(candidate["context"], {})
                if item.get("at") != [0, size] or exports.get((node.get("register_offset"), size)) != item:
                    raise Ineligible("physical target output is not a candidate export")
            return selector

        def operand(self, operand, address=None):
            if "physical_read" in operand:
                return self.read_operand(operand)
            if "physical_read_source" in operand:
                raise Ineligible("no complete physical direct-read relation")
            if "physical_register" in operand:
                if operand.get("pruned") or operand.get("unresolved"):
                    raise Ineligible("unknown physical register operand")
                return self.register_operand(operand)
            if "physical_register_fragments" in operand:
                parts = self.register_fragments(operand)
                relation = operand["physical_register_fragments"]
                for item in relation["overrides"]:
                    self.validate_context(item["context"], item["call"])
                value = super().operand({"parts": parts})
                self.evidence.append({"kind": "register_fragments", "key": relation["read"],
                                      "register_offset": relation["register_offset"], "width": operand["width"],
                                      "overrides": [{key: item[key] for key in
                                                     ("offset", "size", "register_offset", "context", "call")}
                                                    for item in relation["overrides"]]})
                return value
            return super().operand(operand, address)

        def read_geometry(self, operand, owner=None, owner_context=None, owner_guard=None):
            self.tick()
            source, memory = operand.get("physical_read_source"), operand.get("physical_read")
            if not isinstance(source, dict) or not isinstance(memory, dict) \
                    or "physical_register" in operand or memory.get("complete") is not True \
                    or memory.get("little_endian") is not True:
                raise Ineligible("no complete physical direct-read relation")
            width, bits, space, address = (memory.get(name) for name in ("width", "address_bits", "space", "address"))
            if type(width) is not int or width <= 0 or width != operand.get("width") \
                    or type(bits) is not int or not 1 <= bits <= 64 \
                    or type(space) is not int or space < 0 or type(address) is not int or not 0 <= address < 1 << bits \
                    or width > 1 << bits or any(type(source.get(name)) is not int or source[name] != value
                                             for name, value in (("space", space), ("address", address), ("width", width))) \
                    or type(source.get("operation")) is not str or type(source.get("index")) is not int \
                    or source["index"] < 0 or source["index"] != operand.get("index") \
                    or source.get("context") != memory.get("entry_context") \
                    or owner is not None and (source["operation"] != owner or source.get("context") != owner_context) \
                    or owner_guard is not None and memory.get("guard") != owner_guard:
                raise Ineligible("invalid physical direct-read relation")
            context_id = source.get("context")
            if context_id is not None:
                self.context(context_id)
            return memory

        def read_operand(self, operand):
            memory = self.read_geometry(operand)
            source = operand["physical_read_source"]
            owner = {"key": source["operation"], "physical_guard": memory.get("guard")}
            if source.get("context") is not None:
                owner["physical_context"] = source["context"]
            self.require_reach(owner)
            return self.read_bytes(memory, source["operation"], operand.get("index"),
                                   preserved_debts=self.read_debts.get((source.get("context"), source["operation"]), ()))

        def validate_schema(self):
            """Check new references alongside the shared choice contracts.

            No entry callback is consulted until every serialized context,
            imported guard and explicit register/output projection is checked.
            """
            dag = self.control.get("nodes", ())

            def guard(reference):
                self.tick()
                if type(reference) is not int or not 0 <= reference < len(dag) or dag[reference] is None:
                    raise Ineligible("invalid physical guard reference")

            def part(item, width=None):
                self.check_part(item, width)

            def operand(item, owner=None, owner_context=None, owner_guard=None):
                width = item.get("width")
                if type(width) is not int or width <= 0:
                    raise Ineligible("invalid physical operand width")
                for piece in item.get("parts", ()):
                    if not piece.get("pruned"):
                        part(piece)
                if "physical_read" in item:
                    memory = self.read_geometry(item, owner, owner_context, owner_guard)
                    guard(memory.get("guard"))
                    events(memory.get("events", ()), item["physical_read_source"].get("context"))
                if "physical_register" in item:
                    override = item["physical_register"]
                    if type(override.get("offset")) is not int or override["offset"] != 0 \
                            or type(override.get("size")) is not int \
                            or override["size"] != width \
                            or type(override.get("register_offset")) is not int or override["register_offset"] < 0 \
                            or type(override.get("read")) is not str \
                            or owner is not None and override["read"] != owner:
                        raise Ineligible("partial or invalid physical register projection")
                    self.context(override.get("context"), override["call"])
                    part(override["part"], width)
                    self.exported_part(override.get("context"), override["register_offset"], width,
                                       override["part"])
                if "physical_register_fragments" in item:
                    for piece in self.register_fragments(item, owner, owner_context):
                        part(piece)

            def events(items, owner):
                if not isinstance(items, (tuple, list)):
                    raise Ineligible("incomplete physical event inventory")
                for event in items:
                    guard(event.get("guard"))
                    if event.get("kind") in ("store", "write"):
                        writer = self.nodes.get(event.get("node"))
                        # An inactive raw transient STORE may still be a cut
                        # in the ordinary record. Validate its reference here;
                        # only an executed STORE needs its full relation.
                        if event.get("node") is not None and writer is None:
                            raise Ineligible("invalid physical STORE reference")
                        if writer is not None and writer.get("physical_context") != owner:
                            raise Ineligible("physical STORE has a different owner")
                        if writer is not None and "physical_guard" in writer \
                                and writer["physical_guard"] != event.get("guard"):
                            raise Ineligible("physical STORE guard mismatch")
                        if event.get("kind") == "write" and writer is not None:
                            self.write_geometry(event, writer)
                    elif event.get("kind") == "call" and event.get("context") is not None:
                        called = self.context(event["context"], event.get("key"))
                        if called.get("parent_context") != owner or called.get("guard") != event.get("guard"):
                            raise Ineligible("physical call has a different owner or guard")

            if not isinstance(self.contexts, dict):
                raise Ineligible("invalid physical call registry")
            if not isinstance(self.selectors, dict):
                raise Ineligible("invalid physical target registry")
            groups = {identifier for identifier, item in self.contexts.items()
                      if isinstance(item, dict) and item.get("kind") == "target_selection"}
            if set(self.selectors) != groups:
                raise Ineligible("physical target registry mismatch")
            parents = {}
            for identifier in self.contexts:
                if type(identifier) is not str:
                    raise Ineligible("invalid physical context identity")
                parent = self.context(identifier).get("parent_context")
                if parent is not None and (type(parent) is not str or parent not in self.contexts):
                    raise Ineligible("unknown physical context parent")
                parents[identifier] = parent
            for identifier, selector in self.selectors.items():
                if not isinstance(selector, dict):
                    raise Ineligible("invalid physical target contract")
                group = self.context(identifier)
                source = selector.get("source", {})
                candidates = selector.get("candidates")
                target_operand = selector.get("operand", {})
                if not isinstance(source, dict) or not isinstance(target_operand, dict) \
                        or not isinstance(candidates, (tuple, list)) \
                        or any(not isinstance(item, dict) for item in candidates):
                    raise Ineligible("invalid physical target contract")
                width, space = selector.get("width"), selector.get("space")
                parent = group.get("parent_context")
                owner = self.context(parent) if parent is not None else {
                    "function": record.get("function"), "scope": record.get("physical_scope"),
                    "unit": record.get("physical_unit")}
                if selector.get("id") != identifier or group.get("target_selector") != identifier \
                        or selector.get("call") != group.get("call") \
                        or selector.get("parent_context") != parent or selector.get("guard") != group.get("guard") \
                        or any(selector.get(key) != owner.get(key) for key in ("function", "scope", "unit")) \
                        or selector.get("program") != record.get("program") \
                        or selector.get("requires") != record.get("physical_assumptions") \
                        or type(width) is not int or not 1 <= width <= 8 \
                        or width != target_operand.get("width") or width != source.get("width") \
                        or type(space) is not int or space < 0 \
                        or source.get("operation") != group.get("call") or source.get("index") != 0 \
                        or source.get("context") != parent or target_operand.get("index") != 0 \
                        or source.get("kind") not in ("CONSTANT", "REGISTER", "UNIQUE", "ADDRESS") \
                        or type(source.get("space")) is not int or source["space"] < 0 \
                        or type(source.get("offset")) is not int or source["offset"] < 0 \
                        or target_operand.get("target_read") != {
                            name: source.get(name) for name in ("kind", "space", "offset", "width")} \
                        or not isinstance(candidates, (tuple, list)) or not 0 < len(candidates) <= 8 \
                        or group.get("events") != []:
                    raise Ineligible("invalid physical target contract")
                operand(target_operand, group["call"], parent, group["guard"])
                if source.get("producer") is not None:
                    pieces = target_operand.get("parts", ())
                    producer = self.nodes.get(pieces[0].get("node"), {}) if len(pieces) == 1 else {}
                    if producer.get("key") != source["producer"] or producer.get("physical_context") != parent:
                        raise Ineligible("physical target producer correspondence")
                    output = producer.get("output", {})
                    kind = {"REGISTER": "register_file", "UNIQUE": "function_unique", "ADDRESS": "address_space"}
                    if output.get("start") != source["offset"] or output.get("size") != width \
                            or output.get("kind") != kind.get(source["kind"]):
                        raise Ineligible("physical target varnode correspondence")
                values, children = set(), set()
                for candidate in candidates:
                    value, child_id = candidate.get("value"), candidate.get("context")
                    child = self.context(child_id, group["call"])
                    if type(value) is not int or not 0 <= value < 1 << (8 * width) or value in values \
                            or child_id in children or candidate.get("space") != space \
                            or candidate.get("function") != f"{space:x}:{value:x}" \
                            or any(candidate.get(key) != child.get(key) for key in ("function", "scope", "unit")) \
                            or child.get("selected_by") != identifier or child.get("parent_context") != parent \
                            or child.get("guard") != group.get("guard") \
                            or child.get("push") != group.get("push") or child.get("prefix") != group.get("prefix") \
                            or child.get("projection") != group.get("projection"):
                        raise Ineligible("physical target context correspondence")
                    values.add(value)
                    children.add(child_id)
                actual_children = {key for key, item in self.contexts.items() if item.get("selected_by") == identifier}
                if children != actual_children:
                    raise Ineligible("physical target candidate inventory mismatch")
            if any(item.get("selected_by") is not None and item["selected_by"] not in groups
                   for item in self.contexts.values()):
                raise Ineligible("unknown physical target owner")
            depths = {}
            limit = record.get("limits", {}).get("call_depth", Limits.call_depth)
            if type(limit) is not int or limit < 0:
                raise Ineligible("invalid physical call depth")
            for identifier in parents:
                pending, active, current = [], set(), identifier
                while current is not None and current not in depths:
                    self.tick()
                    if current in active:
                        raise Ineligible("physical context parent cycle")
                    pending.append(current)
                    active.add(current)
                    current = parents[current]
                depth = depths.get(current, 0)
                for current in reversed(pending):
                    self.tick()
                    depth += 1
                    if depth > limit:
                        raise Ineligible("physical call depth limit")
                    depths[current] = depth
            # Exports are the cross-reference between a caller selector and
            # the child's existing terminal raw-definition projection. Index
            # every context first, since a later call may use an earlier one.
            for identifier in self.contexts:
                context = self.context(identifier)
                outputs = context.get("outputs")
                if not isinstance(outputs, (tuple, list)):
                    raise Ineligible("missing physical call exports")
                exported = self.context_outputs[identifier] = {}
            for identifier in sorted(self.contexts, key=lambda key: self.contexts[key].get("kind") == "target_selection"):
                context = self.context(identifier)
                outputs = context["outputs"]
                exported = self.context_outputs[identifier]
                for output in outputs:
                    self.tick()
                    if not isinstance(output, dict):
                        raise Ineligible("invalid physical call export")
                    offset, size = output.get("offset"), output.get("size")
                    if type(offset) is not int or offset < 0 or type(size) is not int or size <= 0 \
                            or (offset, size) in exported:
                        raise Ineligible("ambiguous physical call export")
                    piece = output["part"]
                    part(piece, size)
                    if context.get("kind") == "target_selection":
                        producer = self.nodes[piece["node"]]
                        if producer.get("target_selector") != identifier:
                            raise Ineligible("physical export has no shared target selection")
                        self.target_phi(producer)
                    elif piece.get("at") != [0, size] \
                            or self.nodes[piece["node"]].get("physical_context") != identifier:
                        raise Ineligible("physical call export is not child-owned")
                    if context.get("kind") != "target_selection" and len(self.return_rows(context)) > 1:
                        producer = self.nodes[piece["node"]]
                        if producer.get("instance") != identifier:
                            raise Ineligible("physical export has no shared exit selection")
                        self.exit_phi(producer)
                    exported[offset, size] = piece
            return_nodes = {(node.get("physical_context"), node.get("key")): node for node in self.nodes.values()
                            if node.get("kind") == "op" and node.get("opcode") == "RETURN"}
            for identifier in self.contexts:
                context = self.context(identifier)
                guard(context.get("guard"))
                events(context["prefix"], context.get("parent_context"))
                events((context["push"],), context.get("parent_context"))
                if self.nodes.get(context["push"].get("node"), {}).get("physical_call_push") != context.get("selected_by", identifier) \
                        or context["push"].get("guard") != context.get("guard"):
                    raise Ineligible("physical push has a different owner")
                events(context["events"], identifier)
                if context.get("kind") == "target_selection":
                    continue
                returned_rows = self.return_rows(context)
                keys = set()
                for returned in returned_rows:
                    self.tick()
                    key = returned.get("key")
                    if type(key) is not str or not key.endswith(":RETURN") or key in keys:
                        raise Ineligible("invalid physical RETURN identity")
                    keys.add(key)
                    guard(returned.get("guard"))
                    original = return_nodes.get((identifier, key))
                    if original is None or original.get("physical_guard") != returned.get("guard") \
                            or not any(item.get("index") == 0 and item == returned.get("operand")
                                       for item in original.get("operands", ())):
                        raise Ineligible("physical RETURN operation correspondence")
                    if returned.get("expected_target") != returned_rows[0].get("expected_target") \
                            or returned.get("expected_stack") != returned_rows[0].get("expected_stack"):
                        raise Ineligible("inconsistent physical RETURN continuation")
                    for name in ("operand", "stack", "expected_stack"):
                        operand(returned[name], key, identifier, returned.get("guard"))
            for node in self.nodes.values():
                self.tick()
                if "physical_guard" in node:
                    guard(node["physical_guard"])
                if "physical_context" in node:
                    self.context(node["physical_context"])
                if node.get("reason") == "callee exits" and node.get("instance") in self.contexts \
                        and node.get("physical_context") == node.get("instance"):
                    self.exit_phi(node)
                if node.get("reason") == "physical call targets":
                    self.target_phi(node)
                if "physical_register_choice" in node:
                    self.register_choice(node)
                for item in node.get("operands", ()):
                    if any(field in item for field in ("physical_register", "physical_read", "physical_register_fragments")):
                        operation_guard = node.get("physical_guard", self.control.get("reach", {}).get(node.get("key")))
                        if "physical_read" in item and (node.get("kind") != "op" \
                                or type(node.get("key")) is not str or operation_guard is None):
                            raise Ineligible("physical direct-read has no original owning operation")
                        operand(item, node.get("key"), node.get("physical_context"), operation_guard)
                for item in node.get("physical_stitched", ()):
                    self.context(item.get("context"), node.get("call"))
                    selector = item.get("output", {})
                    width = selector.get("size")
                    if selector.get("kind") != StorageObjectKind.REGISTER_FILE.value \
                            or type(width) is not int or width <= 0:
                        raise Ineligible("invalid physical call selector")
                    part(item["part"], width)
                    self.exported_part(item.get("context"), selector.get("start"), width, item["part"])
                for identifier in node.get("physical_call_debt_ids", ()):
                    if identifier not in node.get("debts", ()) \
                            or self.nodes.get(identifier, {}).get("debt") != "call_clobber_read":
                        raise Ineligible("invalid physical call debt coverage")
                    if any("physical_register_fragments" in item for item in node.get("operands", ())):
                        from ._record_calls import covers_register, register_bindings

                        debt = self.nodes[identifier]
                        bindings = list(register_bindings(node.get("operands", ()), retained=True))
                        for span in debt.get("physical_spans", ()):
                            if span["kind"] == "register_file" and not covers_register(
                                    span["start"], span["size"], bindings, debt.get("calls", ())):
                                raise Ineligible("incomplete physical register debt coverage")
                direct_reads = [item["physical_read"] for item in node.get("operands", ()) if "physical_read" in item]
                if direct_reads:
                    self.read_debts[node.get("physical_context"), node.get("key")] = node.get("debts", ())
                for identifier in node.get("physical_read_debt_ids", ()):
                    if identifier not in node.get("debts", ()) or not direct_reads \
                            or self.nodes.get(identifier, {}).get("debt") not in (
                                "may_alias_read", "uncertain_write_read", "unresolved_memory_read", "call_clobber_read"):
                        raise Ineligible("invalid physical direct-read debt coverage")
                memory = node.get("physical_memory")
                if memory is not None:
                    guard(memory.get("guard"))
                    events(memory.get("events", ()), node.get("physical_context"))
                    if memory.get("entry_context") != node.get("physical_context"):
                        raise Ineligible("physical LOAD has a different entry context")
                    if memory.get("entry_context") is not None:
                        self.context(memory["entry_context"])
                condition = node.get("condition")
                if condition is not None and any(field in condition.get("operand", {}) for field in (
                        "physical_read", "physical_register", "physical_register_fragments")):
                    operand(condition["operand"], condition.get("decision"), node.get("physical_context"),
                            self.control.get("reach", {}).get(condition.get("decision"))
                            if node.get("physical_context") is None else None)
            for decision in self.control.get("decisions", {}).values():
                if any(field in decision.get("operand", {}) for field in (
                        "physical_read", "physical_register", "physical_register_fragments")):
                    operand(decision["operand"], decision.get("decision"), decision.get("import"),
                            self.control.get("reach", {}).get(decision.get("decision"))
                            if decision.get("import") is None else None)
            guard(record.get("physical_root_guard"))
            events(record.get("physical_root_events", ()), None)

        def full_operand(self, operand):
            if "physical_read" in operand:
                return self.read_operand(operand)
            if "physical_read_source" in operand:
                raise Ineligible("no complete physical direct-read relation")
            if operand.get("unresolved") or operand.get("pruned"):
                raise Ineligible("unknown physical operand")
            width = operand.get("width")
            if type(width) is not int or width <= 0:
                raise Ineligible("invalid physical operand width")
            self.tick(width)
            if "value" in operand and "parts" not in operand:
                value = operand["value"]
                if type(value) is not int or not 0 <= value < 1 << (8 * width):
                    raise Ineligible("invalid physical literal")
                return value
            covered = set()
            for part in operand.get("parts", ()):
                if part.get("pruned") or "at" not in part:
                    raise Ineligible("incomplete physical operand")
                start, stop = part["at"]
                if type(start) is not int or type(stop) is not int or not 0 <= start < stop <= width:
                    raise Ineligible("invalid physical operand range")
                if covered.intersection(range(start, stop)):
                    raise Ineligible("overlapping physical operand")
                covered.update(range(start, stop))
            if covered != set(range(width)):
                raise Ineligible("incomplete physical operand")
            return self.operand(operand)

        def debts(self, node, memory=None):
            from ._record_calls import register_bindings

            context_ids = {item.get("context") for item in register_bindings(node.get("operands", ()))}
            if memory is not None:
                context_ids.update(event.get("context") for event in memory.get("events", ())
                                   if event.get("kind") == "call" and event.get("context") is not None)
            direct_reads = [operand["physical_read"] for operand in node.get("operands", ()) if "physical_read" in operand]
            context_ids.update(event["context"] for read in direct_reads for event in read.get("events", ())
                               if event.get("kind") == "call" and event.get("context") is not None)
            for identifier in node.get("debts", ()):
                self.tick()
                debt = self.nodes[identifier]
                label = debt.get("debt")
                if memory is not None and identifier in memory.get("debt_ids", ()) \
                        and label in ("may_alias_read", "uncertain_write_read", "unresolved_memory_read"):
                    continue  # retained evidence, interpreted by this complete byte overlay
                if identifier in node.get("physical_read_debt_ids", ()) and direct_reads \
                        and all(read.get("complete") is True for read in direct_reads) \
                        and label in ("may_alias_read", "uncertain_write_read", "unresolved_memory_read"):
                    continue  # the builder proves full original row-span coverage
                if label == "call_clobber_read" and debt.get("calls"):
                    for call in debt["calls"]:
                        reference = self.control.get("reach", {}).get(call)
                        matching = [context_id for context_id in context_ids
                                    if self.context(context_id).get("call") == call]
                        if reference is None and len(matching) == 1:
                            reference = self.context(matching[0])["guard"]
                        if reference is None:
                            raise Ineligible("active or unknown physical call")
                        if not self.physical_guard(reference):
                            continue
                        if identifier not in node.get("physical_call_debt_ids", ()) or len(matching) != 1:
                            raise Ineligible("active or unknown physical call")
                        self.validate_context(matching[0], call)
                        self.evidence.append({"kind": "preserved_call_debt", "debt": identifier,
                                              "call": call, "context": matching[0]})
                    continue
                raise Ineligible(f"unexplained physical debt: {label}")

        def _choice(self, node):
            self.tick()
            guarded = node.get("guarded_sources")
            if node.get("reason") == "physical call targets":
                selector = self.target_phi(node)
                self.validate_context(selector["id"])
                selected = self.selected_context(selector["id"])
                chosen = [index for index, candidate in enumerate(selector["candidates"])
                          if candidate["context"] == selected]
            elif guarded is not None:
                if not self.physical_guard(guarded.get("reach")):
                    raise Ineligible("physical phi unreached")
                guards = guarded.get("guards", ())
                if len(guards) != len(node.get("alternatives", ())):
                    raise Ineligible("physical source guard mismatch")
                chosen = [index for index, guard in enumerate(guards) if self.physical_guard(guard)]
            elif node.get("condition") is not None:
                value = bool(self.full_operand(node["condition"]["operand"]))
                chosen = [index for index, choice in enumerate(node.get("choices", ())) if choice is value]
            elif node.get("reason") == "callee exits":
                returned = self.exit_phi(node)
                chosen = [index for index, item in enumerate(returned) if self.physical_guard(item.get("guard"))]
                known = self.context_returns.get(node.get("instance"))
                if len(chosen) == 1 and known is not None and returned[chosen[0]]["key"] != known:
                    raise Ineligible("physical export and RETURN disagree")
            elif len(node.get("alternatives", ())) == 1:
                chosen = [0]
            else:
                raise Ineligible("unconditioned physical alternatives")
            if len(chosen) != 1:
                raise Ineligible("ambiguous physical source")
            return chosen[0]

        def part(self, part, node_value=None):
            self.check_part(part)
            node = self.nodes[part["node"]]
            self.require_context(node)
            if "execution_guard" in node and not self.physical_guard(node["execution_guard"]):
                raise Ineligible("physical value unreached")
            if node.get("kind") == "call":
                items = node.get("physical_stitched", ())
                selector = part.get("output")
                matching = [item for item in items if item.get("output") == selector] \
                    if selector is not None else []
                if len(matching) != 1:
                    raise Ineligible("no exact physical call output")
                item = matching[0]
                call = node.get("call", node.get("key", "").partition("~")[0])
                self.exported_part(item.get("context"), selector.get("start"), selector.get("size"), item["part"])
                self.validate_context(item.get("context"), call)
                a, b = part["bytes"]
                inner = item["part"]
                if type(a) is not int or type(b) is not int or not 0 <= a < b \
                        or inner["bytes"][1] - inner["bytes"][0] < b:
                    raise Ineligible("partial physical call output")
                # The exact raw terminal part replaces synthetic staging
                # values, not the debt-bearing body's own LOADs/operations.
                self.evidence.append({"kind": "preserved_staging_debts", "node": node["id"],
                                      "context": item["context"], "debts": list(node.get("debts", ()))})
                return self.part(_compose(inner, a, b))
            return super().part(part, node_value)

        def value(self, identifier):
            self.tick()
            if identifier in self.memo:
                return self.memo[identifier]
            if identifier in self.value_active:
                raise Ineligible("physical value cycle")
            node = self.nodes[identifier]
            if node.get("kind") in ("cut", "debt", "call", "override") or node.get("interrupted"):
                raise Ineligible(f"selected physical {node.get('kind')}")
            self.require_context(node)
            if "physical_register_choice" in node:
                choice = node["physical_register_choice"]
                self.validate_context(choice["context"], choice["call"])
            self.value_active.add(identifier)
            try:
                if "execution_guard" in node and not self.physical_guard(node["execution_guard"]):
                    raise Ineligible("physical value unreached")
                if node.get("kind") == "op":
                    self.require_reach(node)
                    memory = node.get("physical_memory") if node.get("opcode") == "LOAD" else None
                    if memory is not None and memory.get("complete") is not True:
                        raise Ineligible("incomplete physical memory inventory")
                    self.debts(node, memory)
                return super().value(identifier)
            finally:
                self.value_active.remove(identifier)

        def _op(self, identifier, node):
            if node.get("override") == "unproven" or node.get("rep_iteration") is not None:
                raise Ineligible("physical override")
            if node["opcode"] == "LOAD":
                value = self.load(node)
            elif node["opcode"] == "STORE":
                operands = {operand["index"]: operand for operand in node["operands"]}
                address, value = self.full_operand(operands[1]), self.full_operand(operands[2])
                self.evidence.append({"kind": "store", "key": node["key"], "space": node.get("space"),
                                      "address": address, "width": operands[2]["width"], "value": value})
                return value
            else:
                if "physical_write" in node and "value" not in node:
                    for operand in node.get("operands", ()):
                        self.full_operand(operand)
                value = super()._op(identifier, node)
            if "physical_write" in node:
                detail = node["physical_write"]
                self.evidence.append({"kind": "write", "key": node["key"], "value": value, **detail})
            return value

        def load(self, node):
            memory = node.get("physical_memory")
            if memory is None or memory.get("complete") is not True or memory.get("little_endian") is not True:
                raise Ineligible("no complete physical memory relation")
            if not self.physical_guard(memory.get("guard")):
                raise Ineligible("physical LOAD unreached")
            width, bits, space = memory["width"], memory["address_bits"], memory["space"]
            if type(width) is not int or width <= 0 or type(bits) is not int or not 1 <= bits <= 64:
                raise Ineligible("unsupported physical geometry")
            self.tick(width)
            mask = (1 << bits) - 1
            address_operand = next(operand for operand in node["operands"] if operand["index"] == 1)
            address = self.full_operand(address_operand) & mask
            return self.read_bytes(memory, node["key"], address=address, preserved_debts=node.get("debts", ()))

        def read_bytes(self, memory, key, input_index=None, *, address=None, preserved_debts=()):
            """LOAD and raw ADDRESS inputs share one exact byte overlay."""
            if not self.physical_guard(memory.get("guard")):
                raise Ineligible("physical read unreached")
            width, bits, space = memory["width"], memory["address_bits"], memory["space"]
            self.tick(width)
            mask = (1 << bits) - 1
            if address is None:
                address = memory["address"]
            address &= mask
            active = self.active_stores(memory.get("events", ()), space, bits)
            value, sources = 0, []
            for byte in range(width):
                self.tick()
                at = (address + byte) & mask
                found, source = self.memory_byte(active, space, at, bits, memory.get("entry_context"))
                value |= found << (8 * byte)
                sources.append({"at": byte, **source})
            evidence = {"kind": "load" if input_index is None else "read", "key": key, "space": space,
                        "address": address, "width": width, "sources": sources,
                        "preserved_debts": list(preserved_debts)}
            if input_index is not None:
                evidence["input"] = input_index
            self.evidence.append(evidence)
            return value

    evaluator = PhysicalEvaluator()
    try:
        evaluator.validate_schema()
        if "physical_root_guard" not in record or not evaluator.physical_guard(record["physical_root_guard"]):
            raise Ineligible("physical root unreached or unknown")
        if record.get("physical_effect_inventory") is not True or "physical_root_events" not in record:
            raise Ineligible("no complete physical root inventory")
        for event in record["physical_root_events"]:
            if event.get("kind") in ("store", "write"):
                raise Ineligible("invalid physical root boundary inventory")
            if evaluator.physical_guard(event.get("guard")):
                if event.get("kind") != "call" or event.get("context") is None:
                    raise Ineligible("active or unknown physical root memory event")
                evaluator.validate_context(event["context"], event.get("key"))
        # Ordinary STOREs belong to each LOAD's overlay. A resolved call
        # boundary may proceed only after its whole body transaction returns.
        if record.get("record") == "summary run" and record.get("run_kind") not in ("computed", "affine"):
            raise Ineligible("physical summary run not exact")
        root = record.get("root", ())
        if not root or any(part.get("whole") for part in root):
            raise Ineligible("unknown physical root")
        if len({part.get("span") for part in root}) > 1:
            raise Ineligible("several physical selectors")
        covered = set()
        for part in root:
            start, stop = part["at"]
            if type(start) is not int or type(stop) is not int or start < 0 or stop <= start:
                raise Ineligible("invalid physical root range")
            evaluator.tick(stop - start)
            if covered.intersection(range(start, stop)):
                raise Ineligible("overlapping physical root")
            covered.update(range(start, stop))
        if covered != set(range(max(covered, default=-1) + 1)):
            raise Ineligible("incomplete physical root")
        value = evaluator.root(root)
    except _Unknown:
        raise Ineligible("unknown physical inputs") from None
    except RecursionError:
        raise Ineligible("physical recursion") from None
    except (KeyError, IndexError, TypeError, ValueError):
        raise Ineligible("invalid physical record") from None
    return PhysicalEvaluation(value, tuple(evaluator.evidence))


__all__ = ("MemoryEvent", "MemoryIndex", "MemoryPlan", "PhysicalEvaluation", "evaluate_physical")
