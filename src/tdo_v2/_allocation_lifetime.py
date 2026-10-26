"""Demanded allocation facts over ORIGINAL SSA values and observed CFG events.

StorageObjectId and legacy fresh/same-object address atoms are deliberately
not allocation identities. No facts here alter an SSA edge. Only a separate
validated range consumer can refine a memory obligation.
"""
from dataclasses import dataclass, replace

from ._load_identity import definition_identity
from .memory_contracts import MemoryDefinitionKind
from .resource_limits import step
from .span_geometry import ByteSpan, StorageObjectKind


def identity_operand(operation):
    """Exact full-width transport (e.g. machine TEST x,x), not a new solver."""
    if operation.output is None or operation.output.byte_size != 8:
        return None
    if operation.opcode == "COPY" and operation.inputs[0].byte_size == 8:
        return operation.inputs[0]
    if operation.opcode in ("INT_AND", "INT_OR") and len(operation.inputs) == 2 \
            and operation.inputs[0] == operation.inputs[1] and operation.inputs[0].byte_size == 8:
        return operation.inputs[0]
    if operation.opcode in ("INT_ADD", "INT_SUB"):
        from ._scope_contracts import VarnodeKindCode
        for ordinal, operand in enumerate(operation.inputs):
            if operand.kind is VarnodeKindCode.CONSTANT and operand.byte_size == 8 \
                    and operand.coordinate.byte_offset == 0 and operation.inputs[1 - ordinal].byte_size == 8 \
                    and (operation.opcode == "INT_ADD" or ordinal == 1):
                return operation.inputs[1 - ordinal]
    return None


@dataclass(frozen=True, slots=True)
class AllocationRef:
    function: str
    context: tuple
    event: str
    result: tuple
    occurrence: str
    contract: str


@dataclass(frozen=True, slots=True)
class PointerTarget:
    allocation: AllocationRef
    offset: int = 0


@dataclass(frozen=True, slots=True)
class PointerFact:
    targets: frozenset = frozenset()
    # None is an independent literal NULL; an AllocationRef is its failed
    # allocation outcome. Only the latter can be refined by that event's guard.
    nulls: frozenset = frozenset()
    unknown: bool = True
    definitions: frozenset = frozenset()
    requires: frozenset = frozenset()

    def joined(self, other):
        if len(self.targets | other.targets) > 16:
            return PointerFact(requires=self.requires | other.requires)
        return PointerFact(self.targets | other.targets, self.nulls | other.nulls,
                           self.unknown or other.unknown, self.definitions | other.definitions,
                           self.requires | other.requires)


@dataclass(frozen=True, slots=True)
class LifetimeEvidence:
    point: str | None
    pointer: PointerFact
    states: tuple
    events: tuple
    requires: tuple
    reason: str
    calls: tuple = ()
    outcomes: tuple = ()

    @property
    def live(self):
        return self.reason == "live" and bool(self.states)


class AllocationAnalysis:
    """One immutable source snapshot; caches are private derivations only.

    ``models`` are original verified call->(file,entry,symbol) bindings, not
    guessed allocator names. Contracts are opt-in and independently labelled.
    """

    def __init__(self, item, *, readonly_image=None, results=None, _parent=None,
                 _call=None, _entry_states=(), _call_path=()):
        from .forward import _analyze
        from .lifecycle_contracts import LifecycleContract
        from .pcode_blocks import build_pcode_block_graph
        from .relative_memory import single_execution_keys
        from .summary_engine import run_assumptions
        self.item, self.normalized = item, item.normalized
        from ._forward_memory import RefinementRefused
        from .normalize import NormalizedFunction
        if type(self.normalized) is not NormalizedFunction:
            raise RefinementRefused("lifecycle input requires an accepted original normalization")
        self.ssa = self.normalized.memory_ssa
        from ._call_activation import _policy
        try:
            with _policy(item):
                pass  # Reject a stale/disabled runtime profile before deriving facts.
        except RefinementRefused as error:
            raise RefinementRefused(f"lifecycle input policy: {error}") from error
        if self.normalized.forward_inputs is None or self.ssa is None \
                or readonly_image is not dict(item.normalization_options).get("readonly_image") \
                or item.unit.scopes.program.evidence.translation_namespace.language_id.split(":")[1:3] != ["LE", "64"]:
            raise RefinementRefused("lifecycle input policy, reader, or address width unsupported")
        self.results = results or {}
        self.entry = {}
        self.parent, self.parent_call = _parent, _call
        self.entry_states = dict(_entry_states)
        self.call_path = _call_path or (item.key,)
        self.options = dict(item.normalization_options)
        self.readonly = readonly_image
        self.context = (() if self.normalized.activation_entry is None
                        else self.normalized.activation_entry.context)
        if self.parent is not None:
            self.context = (*self.parent.context, self.parent.item.key, _call)
        # Retain the complete original run/CFG dependencies, not just the
        # allocator used by a particular pointer. Never launder a weaker-policy
        # claim by deleting inherited labels from a normalized source.
        sources = {**self.results, item.key: item}
        self.requires = frozenset(run_assumptions(
            sources, readonly_image=readonly_image,
            home_space=self.options.get("private_frame_above", 0))) | frozenset(
                label for source in sources.values() for label in
                (source.summary_inputs[2] if source.summary_inputs else ()))
        self.graph = build_pcode_block_graph(item.unit.observation, item.unit.scopes.function.entry)
        self.once = single_execution_keys(item.unit.observation, self.graph)
        self.ops, self.positions, self.block_ops = {}, {}, {}
        instructions = {row.address: row for row in item.unit.observation.instructions}
        for block in self.graph.blocks:
            step()
            row = instructions[block.instruction]
            keys = []
            for ordinal in range(block.start, block.stop):
                step()
                operation = row.operations[ordinal]
                key = f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:{operation.opcode}"
                self.ops[key] = operation
                self.positions[key] = (block.key, ordinal)
                keys.append(key)
            self.block_ops[block.key] = tuple(keys)
        self.blocks = {block.key: block for block in self.graph.blocks}
        self.actions = {row.operation_key: index for index, row in enumerate(self.ssa.actions)}
        self.reads = {}
        for row in self.ssa.reads:
            self.reads.setdefault(row.action_id, []).append(row)
        self.joins = {row.join_definition_id: row.source_definition_ids for row in self.ssa.joins}
        self.effects = dict(self.normalized.proven_call_effects)
        self.models = {call: (file, model, symbol) for call, file, model, symbol in item.allocation_models}
        self.contracts = {}
        for call, (file, model, symbol) in self.models.items():
            matches = [contract for contract in item.allocation_contracts
                       if type(contract) is LifecycleContract and contract.matches_symbol(symbol)
                       and any(contract.matches(file, original)
                               and replace(model, inherited=original.inherited) == original
                               and set(original.inherited) <= set(model.inherited)
                               and set(model.inherited) - set(original.inherited)
                               <= {"import-slots-hold-their-exports", "library-internal-model-cuts"}
                               for original in file.entries)]
            if len(matches) == 1 and self.effects.get(call) is not None \
                    and self.effects[call].callee == model.label and not model.refusal and not model.callbacks_invokes \
                    and all(port is None or port[1] == 8 for port in (matches[0].pointer, matches[0].result)):
                self.contracts[call] = matches[0]
        self.numeric = _analyze(self.normalized, item.unit, readonly_image=readonly_image,
                                assumptions=self.requires)
        self._definitions, self._arguments, self._lives, self._extents = {}, {}, {}, {}
        self._argument_active, self._live_active, self._quiet = set(), set(), {}
        self._call_states = {}
        self._occurrences = {}
        self._operation_edges = None
        self._failures = {}

    def operation_edges(self):
        if self._operation_edges is None:
            successors = {}
            for block in self.graph.blocks:
                keys = self.block_ops[block.key]
                for ordinal, key in enumerate(keys):
                    step()
                    successors[key] = ((keys[ordinal + 1],) if ordinal + 1 < len(keys) else tuple(dict.fromkeys(
                        entry for target in block.successors for entry in self.block_entries(target))))
            self._operation_edges = successors
        return self._operation_edges

    def block_entries(self, key):
        """Original empty p-code blocks are epsilon edges, not dead paths."""
        pending, seen, entries = [key], set(), set()
        while pending:
            step()
            target = pending.pop()
            if target in seen or target not in self.block_ops:
                continue
            seen.add(target)
            if self.block_ops[target]:
                entries.add(self.block_ops[target][0])
            else:
                pending.extend(self.blocks[target].successors)
        return tuple(sorted(entries))

    def local_occurrence(self, pointer, allocation, point):
        """A family has a current instance only inside a closed birth→use cone.

        No unroll bound or equality of returned addresses is used. An SSA
        JOIN (possibly carrying an older iteration) is deliberately refused.
        The all-visit state solve below still closes events after this use.
        """
        cache = pointer, allocation, point
        if cache in self._occurrences:
            return self._occurrences[cache]
        if point is None or point not in self.ops or allocation.event not in self.ops \
                or any(identity[0] is MemoryDefinitionKind.JOIN for identity in pointer.definitions):
            return False
        successors = self.operation_edges()
        pending, reached = list(self.block_entries(self.graph.entry)), set()
        while pending:
            step()
            key = pending.pop()
            if key == allocation.event or key in reached:
                continue
            if key == point:
                self._occurrences[cache] = False  # birth does not dominate.
                return False
            reached.add(key)
            pending.extend(successors[key])
        # A second birth starts another instance, not a continuation of this
        # one (including a nullable failure arm that retries allocation).
        # Only uninterrupted current-instance provenance can pass below.
        pending, cone = list(successors[allocation.event]), set()
        while pending:
            step()
            key = pending.pop()
            if key == point or key in cone:
                continue
            if key == allocation.event:
                continue
            cone.add(key)
            pending.extend(successors[key])
        from .relative_memory import _cyclic_blocks
        region = cone | {point, allocation.event}
        result = any(identity[0] is MemoryDefinitionKind.DATA_WRITE
                     and identity[1] is not None and identity[1].startswith(allocation.event + "~")
                     for identity in pointer.definitions)
        for kind, operation, *_ in pointer.definitions:
            step()
            if kind is not MemoryDefinitionKind.DATA_WRITE or operation is None:
                result = False
                break
            origin = operation.split("~", 1)[0]
            if origin not in region:
                result = False
                break
        edges = {key: [target for target in successors[key] if target in cone] for key in cone}
        step(len(edges) + sum(map(len, edges.values())))
        result = result and not _cyclic_blocks(edges)
        self._occurrences[cache] = result
        return result

    def span(self, varnode):
        from .relative_memory import _resolve_validated_storage, _storage_ref
        from .model import ResolvedStorage
        found = _resolve_validated_storage(_storage_ref(varnode), self.item.unit.scopes.resolution_context)
        return found.span if type(found) is ResolvedStorage else None

    def first(self, call):
        from .forward import first_effect
        return first_effect(self.normalized, call) or call

    def port(self, port):
        from .interprocedural import _register_file
        register, _ = _register_file(self.item.unit.observation, self.item.unit.scopes.resolution_context)
        return ByteSpan(register, *port)

    def argument(self, call, port):
        from .forward import probe
        key = call, port
        if key not in self._arguments:
            if key in self._argument_active:
                return PointerFact()
            self._argument_active.add(key)
            span = self.port(port)
            try:
                found, used = probe(self.normalized, self.first(call), (span,))
                identifier = found[span]
                fact = self.definition(identifier, span) if type(identifier) is int else PointerFact()
                if type(identifier) is int and fact.unknown and not fact.targets and self.numeric.bind is not None:
                    # Reuse the existing exact-value proof, e.g. XOR EDI,EDI
                    # followed by architectural zero-extension into RDI.
                    # No nonzero scalar is promoted to allocation provenance.
                    values, labels = self.numeric.bind(call, (span,))
                    if values[span].bits == span.size * 8 and values[span].single_number() == 0:
                        fact = replace(fact, nulls=frozenset({None}), unknown=False,
                                       requires=fact.requires | frozenset(labels) | frozenset(self.numeric.labels))
                self._arguments[key] = replace(fact, requires=fact.requires | frozenset(used) | self.requires)
            finally:
                self._argument_active.remove(key)
        return self._arguments[key]

    def extent(self, allocation):
        if allocation.function != self.item.key or allocation.context != self.context:
            return (self.parent.extent(allocation) if self.parent is not None
                    else (None, tuple(sorted(self.requires))))
        if allocation not in self._extents:
            contract = self.contracts[allocation.event]
            extent, used = None, ()
            ports = tuple(port for port in (contract.size, contract.count) if port is not None)
            if ports and self.numeric.bind is not None:
                spans = tuple(self.port(port) for port in ports)
                values, used = self.numeric.bind(allocation.event, spans)
                numbers = [values[span].single_number() for span in spans]
                if all(number is not None for number in numbers):
                    extent = numbers[0] * (numbers[1] if len(numbers) == 2 else 1)
                    if not 0 < extent < 1 << (8 * contract.result[1]):
                        extent = None
            self._extents[allocation] = (extent, tuple(sorted(set(used) | set(self.numeric.labels)
                                                            | {contract.label})))
        return self._extents[allocation]

    def input(self, key, varnode, active=frozenset()):
        from ._scope_contracts import VarnodeKindCode
        if varnode.kind is VarnodeKindCode.CONSTANT:
            return PointerFact(nulls=frozenset({None}), unknown=False) if varnode.coordinate.byte_offset == 0 else PointerFact()
        span = self.span(varnode)
        return PointerFact() if span is None else self.read(key, span, active)

    def read(self, key, span, active=frozenset()):
        identifier = self.read_definition(key, span)
        return PointerFact() if identifier is None else self.definition(identifier, span, active)

    def read_definition(self, key, span):
        # Never turn a projected address with debt into a pointer certificate.
        if any(row.operation_key == key and any(part.overlaps(span) for part in row.spans)
               for row in self.normalized.call_clobber_reads):
            return None
        if any(row.operation_key == key and (row.unknown_address or any(part.overlaps(span) for part in row.spans))
               for row in self.normalized.may_alias_reads):
            return None
        rows = [row for row in self.reads.get(self.actions.get(key), ()) if row.span == span]
        # TEST x,x / AND x,x reads the same physical span twice. Only exact
        # identical complete reaching fragments commute; mixed reads do not.
        if not rows or any(row.fragments != rows[0].fragments for row in rows) \
                or len(rows[0].fragments) != 1 or rows[0].fragments[0].span != span \
                or len(rows[0].fragments[0].definition_ids) != 1:
            return None
        return rows[0].fragments[0].definition_ids[0]

    def definition(self, identifier, span, active=frozenset()):
        step()
        cache = identifier, span
        if cache in self._definitions:
            return self._definitions[cache]
        if cache in active:
            return PointerFact()  # Recurrence is not a unique dynamic occurrence.
        active = active | {cache}
        row = self.ssa.definitions[identifier]
        witness = frozenset({definition_identity(row)})
        fact = PointerFact(definitions=witness)
        if row.kind is MemoryDefinitionKind.ENTRY:
            if self.parent is not None and span.object_id.kind is StorageObjectKind.REGISTER_FILE and span.size == 8:
                # A side fact on an original full-width ENTRY, not a new SSA
                # definition or a seed for a partially overwritten register.
                fact = self.parent.argument(self.parent_call, (span.start, span.size))
            else:
                fact = self.entry.get(span, fact)
        elif row.kind is MemoryDefinitionKind.JOIN:
            parts = [self.definition(source, span, active) for source in self.joins.get(identifier, ())]
            if parts:
                fact = parts[0]
                for part in parts[1:]:
                    fact = fact.joined(part)
        elif row.kind is MemoryDefinitionKind.DATA_WRITE and row.span == span:
            key = row.operation_key
            call = key.split("~", 1)[0]
            contract = self.contracts.get(call)
            if contract is not None and contract.result is not None and span == self.port(contract.result) and "~" in key:
                ref = AllocationRef(self.item.key, self.context, call, contract.result,
                                    "single" if call in self.once else "family", contract.canonical_digest)
                fact = PointerFact(frozenset({PointerTarget(ref)}),
                                   frozenset({ref}) if contract.nullable else frozenset(), False,
                                   witness, frozenset({contract.label, self.models[call][1].label})
                                   | frozenset(self.models[call][1].inherited))
                extent, used = self.extent(ref)
                fact = replace(fact, unknown=extent is None, requires=fact.requires | frozenset(used))
                # A resize relation is not a legacy same-object equality.
                if contract.kind == "resize":
                    old = self.argument(call, contract.pointer)
                    valid = (not old.unknown and not old.targets and old.nulls == {None}) or (
                        not old.unknown and bool(old.targets) and all(t.offset == 0 for t in old.targets)
                        and self.lifetime(old, call).live)
                    if not valid:
                        fact = PointerFact(requires=fact.requires | old.requires)
                    elif contract.inplace == "retain":
                        fact = fact.joined(replace(old, nulls=frozenset()))
                    if contract.inplace == "unknown" or contract.moved == "unknown":
                        fact = replace(fact, unknown=True)
            else:
                operation = self.ops.get(key)
                if operation is not None and operation.opcode == "STORE":
                    if operation.inputs[2].byte_size == span.size:
                        fact = self.input(key, operation.inputs[2], active)
                elif operation is not None and operation.output is not None and operation.output.byte_size == span.size:
                    transport = identity_operand(operation)
                    if transport is not None:
                        fact = self.input(key, transport, active)
                    elif operation.opcode == "LOAD":
                        memory = [read for read in self.reads.get(self.actions.get(key), ())
                                  if read.span.object_id.kind in (StorageObjectKind.FUNCTION_RELATIVE,
                                                                 StorageObjectKind.ADDRESS_SPACE)]
                        if len(memory) == 1 and memory[0].span.size == span.size:
                            fact = self.read(key, memory[0].span, active)
                    elif operation.opcode in ("INT_ADD", "INT_SUB") and span.size == 8 \
                            and all(operand.byte_size == 8 for operand in operation.inputs):
                        for index, operand in enumerate(operation.inputs):
                            from ._scope_contracts import VarnodeKindCode
                            if operand.kind is VarnodeKindCode.CONSTANT and (index == 1 or operation.opcode == "INT_ADD"):
                                other = self.input(key, operation.inputs[1 - index], active)
                                delta = operand.coordinate.byte_offset
                                if delta >= 1 << (8 * operand.byte_size - 1):
                                    delta -= 1 << (8 * operand.byte_size)
                                if operation.opcode == "INT_SUB":
                                    delta = -delta
                                fact = replace(other, targets=frozenset(PointerTarget(t.allocation, t.offset + delta)
                                               for t in other.targets),
                                               unknown=other.unknown or (delta != 0 and None in other.nulls))
        fact = replace(fact, definitions=fact.definitions | witness, requires=fact.requires | self.requires)
        self._definitions[cache] = fact
        return fact

    def quiet(self, call, active=frozenset()):
        if call not in self._quiet:
            self._quiet[call] = self._quiet_call(call, active)
        return self._quiet[call]

    def _quiet_call(self, call, active):
        model = self.models.get(call)
        if model is not None:
            entry = model[1]
            return entry.frees == () and not entry.callbacks_invokes and not entry.refusal
        target = self.item.calls.get(call)
        callee = self.results.get(target)
        if callee is None or target in active or callee.summary is None:
            return False
        if callee.unit.scopes.program != self.item.unit.scopes.program:
            return False
        # Closed raw leaves, not a guessed ABI or a memory-preserving effect
        # which could itself hide a free. General calls are handled separately.
        if callee.summary.inner_calls or callee.summary.tail_exits or not callee.summary.exits:
            return False
        from .may_alias import _stack_pointer, _unit_stub
        stack = _stack_pointer(_unit_stub(callee.unit.scopes), callee.unit.observation,
                               callee.unit.scopes.resolution_context,
                               callee.unit.scopes.program.evidence.address_spaces)
        if stack is None:
            return False
        effects = {effect.operation_key: effect for effect in callee.normalized.effects}
        for row in callee.unit.observation.instructions:
            step()
            for ordinal, operation in enumerate(row.operations):
                step()
                if operation.opcode in ("CALL", "CALLIND", "CALLOTHER", "BRANCHIND"):
                    return False
                if operation.output is not None:
                    from ._scope_contracts import VarnodeKindCode
                    if operation.output.kind is VarnodeKindCode.ADDRESS:
                        return False
                if operation.opcode == "STORE":
                    key = f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:STORE"
                    effect = effects.get(key)
                    if effect is None or effect.memory_write is not None or effect.unresolved_writes:
                        return False
                    spans = [value.span for value in effect.writes if hasattr(value, "span")]
                    if not spans or any(span.object_id != stack[0] or span.end > stack[1] for span in spans):
                        return False
        return True

    def predicate(self, key, varnode, active=frozenset()):
        """Original equality-to-NULL predicate only; no new path solver."""
        span = self.span(varnode)
        if span is None:
            return None
        identifier = self.read_definition(key, span)
        if identifier is None:
            return None
        if identifier in active:
            return None
        definition = self.ssa.definitions[identifier]
        operation = self.ops.get(definition.operation_key)
        if operation is None or operation.output is None or self.span(operation.output) != span \
                or definition.span != span:
            return None
        from ._scope_contracts import VarnodeKindCode
        if operation.opcode in ("COPY", "BOOL_NEGATE"):
            result = self.predicate(definition.operation_key, operation.inputs[0], active | {identifier})
            return None if result is None else (result[0], not result[1] if operation.opcode == "BOOL_NEGATE" else result[1])
        if operation.opcode not in ("INT_EQUAL", "INT_NOTEQUAL"):
            return None
        for index, operand in enumerate(operation.inputs):
            if operand.kind is VarnodeKindCode.CONSTANT and operand.coordinate.byte_offset == 0:
                fact = self.input(definition.operation_key, operation.inputs[1 - index])
                if not fact.unknown and len(fact.targets) == 1:
                    target = next(iter(fact.targets))
                    if target.offset == 0 and fact.nulls <= {target.allocation}:
                        return target.allocation, operation.opcode == "INT_NOTEQUAL"
        return None

    def lifetime(self, pointer, point):
        key = pointer, point
        if key in self._lives:
            return self._lives[key]
        if key in self._live_active:
            return LifetimeEvidence(point, pointer, (), (), tuple(sorted(pointer.requires | self.requires)),
                                    "cyclic-lifetime-obligation")
        self._live_active.add(key)
        try:
            evidence = self._lifetime(pointer, point)
            self._lives[key] = evidence
            return evidence
        finally:
            self._live_active.remove(key)

    def _lifetime(self, pointer, point):
        from ._scope_contracts import VarnodeKindCode
        requires = set(pointer.requires | self.requires)
        if (point is not None and point not in self.positions) or self.graph.unsupported is not None \
                or pointer.unknown or not pointer.targets:
            return LifetimeEvidence(point, pointer, (), (), tuple(sorted(requires)), "pointer-unproved")
        all_states, events, calls, outcomes = [], set(), [], []
        for target in sorted(pointer.targets, key=repr):
            ref = target.allocation
            foreign = ref in self.entry_states
            if not foreign and (ref.context != self.context or ref.function != self.item.key
                    or (ref.occurrence != "single" and not self.local_occurrence(pointer, ref, point))):
                return LifetimeEvidence(point, pointer, (), (), tuple(sorted(requires)), "occurrence-unproved")
            incoming = {self.graph.entry: frozenset(self.entry_states[ref]) if foreign
                        else frozenset({"not-created"})}
            pending = [self.graph.entry]
            reached = set()
            while pending:
                step()
                block_key = pending.pop()
                state = incoming[block_key]
                block = self.blocks[block_key]
                stopped = False
                for operation_key in self.block_ops[block_key]:
                    step()
                    if operation_key == point:
                        reached.update(state)
                        # The same static read may run again after a backedge.
                        # Keep solving the suffix: a later free can reach its
                        # next dynamic occurrence. Do not certify only visit 1.
                        if point in self.once:
                            stopped = True
                            break
                    operation = self.ops[operation_key]
                    if point is None and operation.opcode == "RETURN":
                        reached.update(state)
                        stopped = True
                        break
                    if operation.opcode not in ("CALL", "CALLIND", "CALLOTHER"):
                        continue
                    contract = self.contracts.get(operation_key)
                    events.add(operation_key)
                    model = self.models.get(operation_key)
                    if model is not None:
                        requires.update((model[1].label, *model[1].inherited))
                    if operation_key == ref.event:
                        contract = self.contracts[ref.event]
                        state = frozenset({"live", "not-created"} if contract.nullable else {"live"}) \
                            | (state & {"invalid-event"})
                        events.add(operation_key)
                        requires.add(contract.label)
                    elif contract is not None and contract.pointer is not None:
                        candidate = self.argument(operation_key, contract.pointer)
                        requires.update(candidate.requires)
                        requires.add(contract.label)
                        # An invalid free/realloc is not a bounded effect on
                        # just its apparent allocation. Validate its contract
                        # precondition BEFORE excluding other identities.
                        null = not candidate.unknown and not candidate.targets and candidate.nulls == {None}
                        same = not candidate.unknown and bool(candidate.targets) \
                            and all(t.allocation == ref and t.offset == 0 for t in candidate.targets)
                        if ref.occurrence == "family":
                            same = same and self.local_occurrence(candidate, ref, operation_key)
                        current = same and bool(state) and state <= {"live", "not-created"} \
                            and ("not-created" not in state or candidate.nulls == {ref})
                        valid = null or current or (not candidate.unknown and bool(candidate.targets)
                            and all(t.offset == 0 for t in candidate.targets)
                            and self.lifetime(candidate, operation_key).live)
                        if not valid:
                            state = state | {"unknown", "invalid-event"}
                            continue
                        aliases = any(t.allocation == ref for t in candidate.targets)
                        if aliases:
                            if contract.kind == "resize":
                                from ._allocation_outcomes import failed_resize
                                failure = failed_resize(self, operation_key, point)
                                if failure:
                                    outcomes.append(failure)
                                    requires.update(failure.requires)
                                    continue  # Query-path-only retain; never CALL-wide preservation.
                            events.add(operation_key)
                            state = state | {"ended"}
                            if contract.kind == "release" and not candidate.unknown and len(candidate.targets) == 1 \
                                    and None not in candidate.nulls and next(iter(candidate.targets)).offset == 0:
                                state = frozenset({"ended"}) | (state & {"invalid-event"})
                    elif not self.quiet(operation_key):
                        from ._allocation_calls import transfer_lifetime
                        crossing = transfer_lifetime(self, operation_key, ref, state)
                        if crossing is None:
                            state = state | {"ended", "unknown"}
                        else:
                            state = frozenset(crossing.output_states)
                            requires.update(crossing.requires)
                            calls.append(crossing)
                if stopped:
                    continue
                if point is None and block.exits:
                    # A tail/unknown exit is not a normal-return certificate.
                    reached.update({"unknown"})
                last_key = self.block_ops[block_key][-1] if self.block_ops[block_key] else None
                last = self.ops.get(last_key)
                predicate = self.predicate(last_key, last.inputs[1]) if last is not None and last.opcode == "CBRANCH" else None
                for successor in block.successors:
                    if successor not in self.blocks:
                        continue
                    outgoing = state
                    if predicate is not None and predicate[0] == ref:
                        destination = last.inputs[0]
                        if destination.kind is VarnodeKindCode.ADDRESS:
                            true = self.blocks[successor].instruction == destination.coordinate
                            live = true == predicate[1]
                            outgoing = state - ({"not-created"} if live else {"live", "ended"})
                    if not outgoing:
                        continue
                    previous = incoming.get(successor, frozenset())
                    merged = previous | outgoing
                    if merged != previous:
                        incoming[successor] = merged
                        pending.append(successor)
            all_states.append((ref, tuple(sorted(reached))))
        nulls = pointer.nulls
        live = all(states == ("live",) for _, states in all_states) and None not in nulls
        reason = "live" if live else "allocation-lifetime-unproved"
        evidence = LifetimeEvidence(point, pointer, tuple(all_states), tuple(sorted(events)), tuple(sorted(requires)), reason,
                                    tuple(dict.fromkeys(calls)), tuple(dict.fromkeys(outcomes)))
        return evidence

    def access(self, writer):
        operation = self.ops.get(writer)
        if operation is None or operation.opcode != "STORE" or operation.inputs[1].byte_size != 8:
            return None
        fact = self.input(writer, operation.inputs[1])
        evidence = self.lifetime(fact, writer)
        if not evidence.live:
            return None
        requires = set(evidence.requires)
        for target in fact.targets:
            extent, used = self.extent(target.allocation)
            contract = self.contracts[target.allocation.event]
            if not contract.owned_footprint or extent is None or target.offset < 0 \
                    or target.offset + operation.inputs[2].byte_size > extent:
                return None
            requires.update(used)
        return replace(evidence, requires=tuple(sorted(requires)))
