"""State at a position: an answer only when nothing may change it in between.

``latest_definition`` / ``state_definition`` pick a definition from the
chi-free value view and the raw operations; that view has no definition for an
opaque call, orders no modeled (``~``) row, and sees neither partial nor
conditional overwrites as candidates. Every such lookup therefore passes this
barrier (Stage 0.1 R1a, ``.census6/design_s0_r5.md`` A1-A2): the answer stands
only when no operation that may change the span can lie on a path from the
chosen definition (the function entry for an ENTRY answer) to the position,
judged conservatively -- every walk counts (backedges included), an operation
without a known block or position counts as between, and a function whose
successor graph is incomplete (a BRANCHIND without targets) proves nothing.
Otherwise the lookup refuses (None) and its consumer takes the unknown path.
"""

from __future__ import annotations

from ..memory_contracts import MemoryDefinitionKind
from ..model import ByteSpan, StorageObjectKind

_CALLS = frozenset(("CALL", "CALLIND", "CALLOTHER"))
_WRITES = (MemoryDefinitionKind.DATA_WRITE, MemoryDefinitionKind.KILL)
_MEMORY = (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)
_UNSET = object()


def _raw_key(operation_key: str) -> str:
    """The raw operation a normalized row is anchored at (``op~row`` -> ``op``)."""
    return operation_key.split("~", 1)[0]


class _BarrierFacts:
    __slots__ = ("place", "calls", "preserved", "keeping", "writes", "complete", "entry",
                 "successors", "predecessors", "reach", "coreach", "_stack")

    def __init__(self, view) -> None:
        unit = view.analysis.normalized.memory_unit
        self.entry = unit.entry_block_key
        self.successors = {key: frozenset(targets) for key, targets in view._successors.items()}
        self.predecessors = {block.key: frozenset(block.predecessors) for block in unit.blocks}
        # every raw operation's (block, position); an operation without an
        # action takes its instruction's block (a call's push lowered into
        # ``~push``); none known -> None (counts as between)
        self.place: dict = {}
        for key, (position, _) in view.operations.items():
            block = view.operation_blocks.get(key)
            if block is None:
                blocks = {view.operation_blocks.get(other)
                          for other in view.instruction_operation_keys.get(key, ())} - {None}
                block = next(iter(blocks)) if len(blocks) == 1 else None
            self.place[key] = None if block is None else (block, position)
        # the calls that may change state, and what each leaves unchanged: the
        # exemption contract the reads' call-clobber rows used (a call with an
        # assumed effect is its rows; a callee's proven bytes; the stack
        # pointer of a restored call shape; memory a summarized call keeps).
        # Without a recorded contract every call op changes everything.
        contract = getattr(view.normalized, "call_clobber_contract", ())
        raw_calls = tuple(key for key, (_, operation) in view.operations.items() if operation.opcode in _CALLS)
        if contract:
            clobbering, preserved, keeping = contract
            self.calls = tuple(key for key in raw_calls if key in clobbering)
            self.preserved = {key: preserved.get(key, ()) for key in self.calls}
            self.keeping = frozenset(keeping)
        else:
            self.calls = raw_calls
            self.preserved = {}
            self.keeping = frozenset()
        # (definition id, span, raw anchor or None): every write the value view
        # may hold, modeled rows ordered by the raw operation they belong to
        rows = []
        for definition_id, definition in enumerate(view.memory.definitions):
            if definition.kind not in _WRITES:
                continue
            anchor = _raw_key(definition.operation_key)
            spans = view.definition_access_spans(definition) or (definition.span,)
            rows.append((definition_id, spans, anchor if anchor in view.operations else None))
        for item in view.memory.unresolved_writes:
            key = view.memory.actions[item.action_id].operation_key
            anchor = _raw_key(key)
            rows.append((None, None, anchor if anchor in view.operations else None))
        for key, _ in getattr(view.normalized, "uncertain_writers", ()):
            anchor = _raw_key(key) if type(key) is str else None
            rows.append((None, None, anchor if anchor in view.operations else None))
        self.writes = tuple(rows)
        # an indirect branch whose targets Ghidra did not resolve leaves the
        # successor graph incomplete: no path claim is a proof
        self.complete = not any(
            operation.opcode == "BRANCHIND" and not view.operation_flow_targets.get(key)
            for key, (_, operation) in view.operations.items())
        self.reach: dict = {}
        self.coreach: dict = {}
        self._stack = _UNSET

    def _closure(self, start, edges, memo) -> frozenset:
        """Blocks reached from ``start`` by one or more edges."""
        found = memo.get(start)
        if found is None:
            seen: set = set()
            pending = list(edges.get(start, ()))
            while pending:
                block = pending.pop()
                if block not in seen:
                    seen.add(block)
                    pending.extend(edges.get(block, ()))
            found = memo[start] = frozenset(seen)
        return found

    def stack_object(self, view):
        """The function's stack object as the may-alias policy identifies it."""
        if self._stack is _UNSET:
            from ..may_alias import stack_object_of

            self._stack = stack_object_of(view.analysis.evidence.unit.scopes, view.observation)
        return self._stack

    def keeps(self, call: str, span: ByteSpan) -> bool:
        """The call leaves every byte of ``span`` unchanged (per the contract)."""
        if call in self.keeping and span.object_id.kind in _MEMORY:
            return True
        covered = sorted((item.start, item.end) for item in self.preserved.get(call, ())
                         if item.object_id == span.object_id)
        position = span.start
        for start, end in covered:
            if start > position:
                break
            position = max(position, end)
        return position >= span.end

    def between(self, place, origin, target) -> bool:
        """May ``place`` lie on a walk from ``origin`` (None: the entry) to
        ``target``? Unknown places always may."""
        if place is None:
            return True
        block, position = place
        if origin is None:
            after = block == self.entry or block in self._closure(self.entry, self.successors, self.reach)
        else:
            after = (block == origin[0] and position > origin[1]) or block in self._closure(
                origin[0], self.successors, self.reach)
        if not after:
            return False
        return (block == target[0] and position < target[1]) or block in self._closure(
            target[0], self.predecessors, self.coreach)


def _may_alias(left: ByteSpan, right: ByteSpan, stack) -> bool:
    """Two spans may share bytes: the same object overlapping, or two memory
    objects not proven disjoint -- different address spaces never; a constant
    address and THE function's stack object (``stack``: given only under the
    function's named globals-disjoint-from-stack assumption) by that
    assumption, as the may-alias policy decides (``may_alias._Policy``). Any
    other relative object (an entry pointer's) may be anywhere."""
    if left.object_id == right.object_id:
        return left.overlaps(right)
    kinds = (left.object_id.kind, right.object_id.kind)
    if any(kind not in _MEMORY for kind in kinds):
        return False
    if kinds == (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.ADDRESS_SPACE):
        return False
    if stack is not None and (
        (kinds[0] is StorageObjectKind.ADDRESS_SPACE and right.object_id == stack)
        or (kinds[1] is StorageObjectKind.ADDRESS_SPACE and left.object_id == stack)
    ):
        return False
    return True


class _FunctionStateBarrierMixin:
    def _barrier_facts(self) -> _BarrierFacts:
        facts = getattr(self, "_state_barrier", None)
        if facts is None:
            facts = self._state_barrier = _BarrierFacts(self)
        return facts

    def state_unchanged(
        self,
        span: ByteSpan,
        origin_key: str | None,
        before_key: str,
        *,
        own_definition_id: int | None = None,
    ) -> bool:
        """Nothing that may change ``span`` lies between ``origin_key`` (None:
        the function entry) and ``before_key``'s own effects (rows anchored at
        ``before_key`` follow the consumption, as the lookups always ordered)."""
        return self.state_barrier(
            span, origin_key, before_key, own_definition_id=own_definition_id
        ) is None

    def state_barrier(
        self,
        span: ByteSpan,
        origin_key: str | None,
        before_key: str,
        *,
        own_definition_id: int | None = None,
    ) -> str | None:
        """Why the span may change in between (None: it may not)."""
        facts = self._barrier_facts()
        if not facts.complete:
            return "incomplete-successors"
        target = facts.place.get(before_key)
        if target is None:
            return "unplaced-position"
        origin = None
        if origin_key is not None:
            origin = facts.place.get(origin_key)
            if origin is None:
                return "unplaced-definition"
        # the consuming operation's own effects follow this consumption, but an
        # earlier execution of it (a loop back to it) precedes it
        recurs = facts.between(target, origin, target)
        for key in facts.calls:
            if key == before_key and not recurs or key == origin_key:
                continue
            if not facts.keeps(key, span) and facts.between(facts.place[key], origin, target):
                return "call"
        memory = span.object_id.kind in _MEMORY
        stack = facts.stack_object(self) if getattr(
            self.normalized, "assumes_globals_disjoint_from_stack", False) else None
        for definition_id, spans, anchor in facts.writes:
            if definition_id is not None and definition_id == own_definition_id:
                continue
            if spans is None:
                # an unresolved / uncertain write: any memory byte
                if not memory:
                    continue
                kind = "unresolved-write"
            elif not any(_may_alias(span, other, stack) for other in spans):
                continue
            else:
                kind = "write" if any(span.object_id == other.object_id for other in spans) else "alias-write"
            if anchor == before_key:
                if recurs:
                    return kind
                continue
            if anchor is None or anchor == origin_key:
                return f"unordered-{kind}"   # no order against the chosen definition
            if facts.between(facts.place[anchor], origin, target):
                return kind
        return None

    def read_settled(self, action_id: int, span: ByteSpan) -> bool:
        """A value followed through this action's read of ``span`` is the one it
        reads: no call-clobber or may-alias row of the action covers the span,
        and, for memory, the action carries no other memory debt (uncertain or
        opaque writer, open condition, unresolved read) and the function has no
        unresolved write (first version: function-wide). Every decision
        consumer evaluates inputs through here, so a stale input is unknown,
        never followed (Stage 0.1 R1a A4)."""
        debts = getattr(self, "_read_debts", None)
        if debts is None:
            normalized = self.normalized
            spanned: dict = {}
            for row in getattr(normalized, "call_clobber_reads", ()):
                spanned.setdefault(row.operation_key, []).extend(row.spans)
            for row in getattr(normalized, "may_alias_reads", ()):
                # (an unknown-address row: every byte the action reads)
                spanned.setdefault(row.operation_key, []).extend(row.spans or (None,))
            memory = set(getattr(normalized, "opaque_nodes", ()))
            memory.update(node for node, _ in getattr(normalized, "uncertain_nodes", ()))
            memory.update(node for node, _ in getattr(normalized, "open_nodes", ()))
            memory.update(self.memory_graph.unresolved_read_nodes)
            debts = self._read_debts = (spanned, frozenset(memory))
        spanned, memory_debts = debts
        if not self._barrier_facts().complete:
            return False   # the SSA's reaching definitions miss the unresolved jumps' paths
        key = self.memory.actions[action_id].operation_key
        if any(item is None or item.overlaps(span) for item in spanned.get(key, ())):
            return False
        if span.object_id.kind not in _MEMORY:
            return True
        if self.memory.unresolved_writes:
            return False
        node = self.memory_graph.action_nodes[action_id]
        return not any(item in memory_debts for item in self.normalized.dependencies.predecessors(node))

    def keys_between(self, origin_key: str, before_key: str) -> tuple[str, ...] | None:
        """The raw operations that may lie between two placed operations, for
        a caller relating raw STOREs itself; None when a call, an unordered row
        or a memory write no raw STORE stands for (a normalized row, an
        unresolved or uncertain write) may lie there -- or nothing is proven."""
        facts = self._barrier_facts()
        origin = facts.place.get(origin_key)
        target = facts.place.get(before_key)
        if not facts.complete or origin is None or target is None:
            return None
        recurs = facts.between(target, origin, target)
        found = tuple(
            key
            for key, place in facts.place.items()
            if key != origin_key and (key != before_key or recurs) and facts.between(place, origin, target)
        )
        stores = {key for key in (origin_key, *found) if self.operations[key][1].opcode == "STORE"}
        if any(self.operations[key][1].opcode in _CALLS for key in found):
            return None
        for definition_id, spans, anchor in facts.writes:
            if spans is not None and not any(item.object_id.kind in _MEMORY for item in spans):
                continue
            if anchor == before_key and not recurs:
                continue
            # a raw STORE's own write is the caller's to relate; a normalized
            # row anchored at it (a rep element ``op~e<i>``) or an unresolved /
            # uncertain row there is not what the STORE's pointer names
            if anchor in stores and definition_id is not None \
                    and self.memory.definitions[definition_id].operation_key == anchor:
                continue
            if anchor is None or anchor == origin_key or facts.between(facts.place[anchor], origin, target):
                return None
        return found


__all__ = ["_FunctionStateBarrierMixin"]
