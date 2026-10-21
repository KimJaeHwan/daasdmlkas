"""Forward value facts, increment F0 (docs 25.33): an abstract interpreter over
a normalized function's own memory SSA (registers, temporaries and memory in
one SSA), producing facts about the values that operations read. F0 has no
consumer: nothing in the engine reads these facts, so analysis results are
the same with or without them; ``semantic_snapshot`` records them only when
``TDO_V2_FORWARD=1``.

Domain (per value of a fixed bit width): TOP, or up to ``MAX_BASES`` items
(base, offsets). A base is ``("abs",)`` (a plain number) or ``("entry", offset,
size)`` (the function's entry value of that register span); offsets are an
unsigned interval [lo, hi] with a stride, never wrapping (an operation whose
result could wrap becomes TOP for that item). Transfer rules
(``_transfer``): a base survives only INT_ADD / INT_SUB with a number and
COPY; every other operation on a based value gives TOP; numeric rules are
sound over-approximations (property-tested against concrete evaluation);
operations whose inputs are all single numbers are evaluated exactly
(``operation_records._compute``).

Memory: a read the backward engine gave a debt (call-clobber, may-alias,
unknown address) is TOP; any other read takes the value of its single
reaching definition when that
definition covers it (low bytes of a number keep their interval only when it
fits; any constant is sliced exactly); a read with several fragments or
definitions, an unresolved read, a call effect's definition, a KILL, or an
entry value of memory (other than a read-only image byte under
readonly-image-data-is-constant) is TOP. JOIN definitions join their sources;
after ``WIDEN_AFTER`` changes a join widens to the full range. The iteration
is ascending: a definition not evaluated yet contributes nothing (bottom), so
every value only grows until the fixpoint; facts are published only there.
``requires`` lists readonly-image-data-is-constant on every fact of a function
that read a read-only image byte (per function, an over-report).

Subjects (F0): the target of every CALLIND / BRANCHIND and the address of
every LOAD / STORE.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from math import gcd

from .memory_contracts import MemoryDefinitionKind
from .span_geometry import StorageObjectKind

MAX_BASES = 8          # items per value; more -> TOP
WIDEN_AFTER = 3        # changes of a JOIN before it widens
MAX_PASSES = 256       # fixpoint passes (a safety bound; widening converges first)
SUBJECTS = {"CALLIND": 0, "BRANCHIND": 0, "LOAD": 1, "STORE": 1}
_ABS = ("abs",)


@dataclass(frozen=True, slots=True)
class Interval:
    """[lo, hi] of a ``bits`` wide value, every ``stride``-th number from lo
    (stride 0: the single number lo); unsigned for plain numbers, signed
    (two's complement, within [-2**(bits-1), 2**(bits-1))) for the offsets of
    a based value -- offsets below an entry value are common (the stack)."""
    lo: int
    hi: int
    stride: int
    bits: int
    signed: bool = False

    @staticmethod
    def const(value: int, bits: int) -> "Interval":
        value &= (1 << bits) - 1
        return Interval(value, value, 0, bits)

    @staticmethod
    def offset(value: int, bits: int) -> "Interval":
        """A based value's single (signed) offset."""
        return Interval(value, value, 0, bits, True)

    @staticmethod
    def full(bits: int, signed: bool = False) -> "Interval":
        if signed:
            return Interval(-(1 << (bits - 1)), (1 << (bits - 1)) - 1, 1, bits, True)
        return Interval(0, (1 << bits) - 1, 1, bits)

    @property
    def single(self) -> bool:
        return self.lo == self.hi

    def contains(self, value: int) -> bool:
        value &= (1 << self.bits) - 1
        if self.signed and value >= 1 << (self.bits - 1):
            value -= 1 << self.bits
        if not self.lo <= value <= self.hi:
            return False
        return value == self.lo if self.stride == 0 else (value - self.lo) % self.stride == 0

    def join(self, other: "Interval") -> "Interval":
        lo, hi = min(self.lo, other.lo), max(self.hi, other.hi)
        if lo == hi:
            return Interval(lo, hi, 0, self.bits, self.signed)
        stride = gcd(gcd(self.stride, other.stride), abs(self.lo - other.lo))
        return Interval(lo, hi, stride or 1, self.bits, self.signed)

    def widen(self, other: "Interval") -> "Interval":
        joined = self.join(other)
        if joined == self:
            return self
        return Interval.full(self.bits, self.signed)


def _make(lo: int, hi: int, stride: int, bits: int, signed: bool = False) -> Interval | None:
    """The interval, or None when it leaves the representable range (it
    could wrap)."""
    low, high = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
    if lo < low or hi > high or lo > hi:
        return None
    if lo == hi:
        return Interval(lo, hi, 0, bits, signed)
    return Interval(lo, hi, stride or 1, bits, signed)


@dataclass(frozen=True, slots=True)
class Value:
    """TOP (``items`` None) or base -> offsets items, sorted by base."""
    bits: int
    items: tuple | None   # ((base, Interval), ...)

    @staticmethod
    def top(bits: int) -> "Value":
        return Value(bits, None)

    @staticmethod
    def number(value: int, bits: int) -> "Value":
        return Value(bits, ((_ABS, Interval.const(value, bits)),))

    @property
    def is_top(self) -> bool:
        return self.items is None

    def single_number(self) -> int | None:
        if self.items is not None and len(self.items) == 1 and self.items[0][0] == _ABS \
                and self.items[0][1].single:
            return self.items[0][1].lo
        return None

    def numeric(self) -> Interval | None:
        """The interval when the value is a plain number."""
        if self.items is not None and len(self.items) == 1 and self.items[0][0] == _ABS:
            return self.items[0][1]
        return None


def _value(bits: int, items: dict) -> Value:
    if any(interval is None for interval in items.values()) or len(items) > MAX_BASES:
        return Value.top(bits)
    if not items:
        return Value.top(bits)
    return Value(bits, tuple(sorted(items.items())))


def join(left: Value, right: Value, *, widen: bool = False) -> Value:
    if left.is_top or right.is_top or left.bits != right.bits:
        return Value.top(left.bits)
    found = dict(left.items)
    for base, interval in right.items:
        if base in found:
            found[base] = found[base].widen(interval) if widen else found[base].join(interval)
        else:
            found[base] = Interval.full(left.bits, base != _ABS) if widen else interval
    return _value(left.bits, found)


# -- transfer ----------------------------------------------------------------------

def _shift(value: Value, delta: Interval, negative: bool) -> Value:
    """value +/- a number interval, modulo 2**bits (exact): a based item's
    signed offsets move by the delta read as signed; a plain number's
    unsigned interval moves when the whole interval wraps the same way."""
    bits, modulus, half = value.bits, 1 << value.bits, 1 << (value.bits - 1)
    if delta.hi < half:
        low, high = delta.lo, delta.hi
    elif delta.lo >= half:
        low, high = delta.lo - modulus, delta.hi - modulus
    else:
        return Value.top(bits)   # (the delta's sign is not known)
    if negative:
        low, high = -high, -low
    items = {}
    for base, offsets in value.items:
        stride = gcd(offsets.stride, delta.stride)
        lo, hi = offsets.lo + low, offsets.hi + high
        if base != _ABS:
            items[base] = _make(lo, hi, stride, bits, True)
            continue
        if lo >= modulus or hi < 0:
            lo, hi = (lo - modulus, hi - modulus) if lo >= modulus else (lo + modulus, hi + modulus)
        items[base] = _make(lo, hi, stride, bits)
    return _value(bits, items)


def _numeric(opcode: str, inputs: list[Interval], constant: list, bits: int) -> Interval | None:
    """Sound interval transfer of a numeric operation (None: no rule -> TOP)."""
    a = inputs[0] if inputs else None
    c = constant[1] if len(constant) > 1 else None
    full = (1 << bits) - 1
    if opcode in ("INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_LESSEQUAL", "INT_SLESS", "INT_SLESSEQUAL",
                  "INT_CARRY", "INT_SCARRY", "INT_SBORROW", "BOOL_NEGATE", "BOOL_AND", "BOOL_OR", "BOOL_XOR"):
        return Interval(0, 1, 1, bits)
    if opcode == "POPCOUNT" and a is not None:
        return _make(0, a.bits, 1, bits)
    if a is None:
        return None
    if opcode == "COPY" or opcode == "INT_ZEXT":
        return _make(a.lo, a.hi, a.stride, bits)
    if opcode == "INT_SEXT":
        return _make(a.lo, a.hi, a.stride, bits) if a.hi < 1 << (a.bits - 1) else None
    if opcode == "SUBPIECE" and c == 0:
        return _make(a.lo, a.hi, a.stride, bits)   # (None when it does not fit: truncation)
    if opcode == "INT_AND" and c is not None:
        if a.hi <= c and (c + 1) & c == 0:
            return _make(a.lo, a.hi, a.stride, bits)   # a low-bit mask covering the interval
        return _make(0, min(c, a.hi) if (c + 1) & c == 0 else c, 1, bits)
    if opcode == "INT_MULT" and c is not None:
        return _make(a.lo * c, a.hi * c, a.stride * c, bits)
    if opcode == "INT_LEFT" and c is not None and c < bits:
        return _make(a.lo << c, a.hi << c, a.stride << c, bits)
    if opcode == "INT_RIGHT" and c is not None:
        return _make(a.lo >> c, a.hi >> c, 1, bits)
    if opcode in ("INT_REM",) and c:
        return _make(0, min(c - 1, a.hi), 1, bits)
    if opcode == "INT_DIV" and c:
        return _make(a.lo // c, a.hi // c, 1, bits)
    del full
    return None


def _transfer(opcode: str, values: list[Value], widths: list[int], out_size: int) -> Value:
    """The output value of one operation from its inputs' values."""
    from .operation_records import _compute

    bits = 8 * out_size
    singles = [value.single_number() for value in values]
    if values and all(single is not None for single in singles):
        try:
            return Value.number(_compute(opcode, singles, widths, out_size), bits)
        except Exception:   # (an opcode the exact evaluator has no rule for)
            return Value.top(bits)
    if any(value.is_top for value in values) and opcode not in ("POPCOUNT",):
        if opcode in ("INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_LESSEQUAL", "INT_SLESS",
                      "INT_SLESSEQUAL", "INT_CARRY", "INT_SCARRY", "INT_SBORROW", "BOOL_NEGATE", "BOOL_AND",
                      "BOOL_OR", "BOOL_XOR"):
            return Value(bits, ((_ABS, Interval(0, 1, 1, bits)),))
        if opcode == "INT_AND" and len(values) > 1 and singles[1] is not None:
            interval = _numeric(opcode, [Interval.full(8 * widths[0])], singles, bits)
            return Value.top(bits) if interval is None else Value(bits, ((_ABS, interval),))
        return Value.top(bits)
    if opcode == "COPY" and values:
        return Value(bits, values[0].items) if values[0].bits == bits else Value.top(bits)
    if opcode in ("INT_ADD", "INT_SUB") and len(values) == 2:
        left, right = values
        delta = right.numeric()
        if delta is not None:
            return _shift(left, delta, opcode == "INT_SUB")
        if opcode == "INT_ADD" and left.numeric() is not None:
            return _shift(right, left.numeric(), False)
        return Value.top(bits)
    numbers = [value.numeric() for value in values]
    if any(number is None for number in numbers):
        return Value.top(bits)   # (a based value through any other operation: no base kept)
    interval = _numeric(opcode, numbers, singles, bits)
    return Value.top(bits) if interval is None else Value(bits, ((_ABS, interval),))


def _slice(value: Value, definition_span, span) -> Value:
    """The value of ``span`` (inside ``definition_span``) of a definition."""
    bits = 8 * span.size
    if definition_span == span:
        return value
    single = value.single_number()
    shift = 8 * (span.start - definition_span.start)
    if single is not None:
        return Value.number(single >> shift, bits)
    number = value.numeric()
    if shift == 0 and number is not None and number.hi < 1 << bits:
        return Value(bits, ((_ABS, Interval(number.lo, number.hi, number.stride, bits)),))
    return Value.top(bits)


# -- the analysis -------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Fact:
    id: str
    function: str
    operation: str          # operation key
    input: int              # input index
    claim: Value
    requires: tuple[str, ...]


_NORMALIZATION_ASSUMPTIONS = (
    ("assumes_globals_disjoint_from_stack", "globals-disjoint-from-stack"),
    ("assumes_readonly_image_constant", "readonly-image-data-is-constant"),
    ("assumes_import_slots_hold_exports", "import-slots-hold-their-exports"),
    ("assumes_entry_values_not_frame", "entry-values-do-not-address-the-new-frame"),
    ("assumes_opaque_callees_leave_no_stack_addresses", "opaque-callees-leave-no-stack-addresses"),
    ("assumed_direction_flag_clear", "direction-flag-clear"),
)


def forward_facts(normalized, unit, *, readonly_image=None, assumptions=()) -> tuple[Fact, ...]:
    """The F0 facts of one normalized function (docs 25.33), in a stable
    order; () when the function has no memory SSA. Every fact's ``requires``
    lists ``assumptions`` -- callers pass every assumption the analysis run
    rests on (``EngineRun.assumptions`` / ``summary_engine.run_assumptions``:
    the absence of a debt, the SSA's paths and the call effects may rest on
    any of them; per run, an over-report) -- with the function's own
    normalization assumptions and readonly-image-data-is-constant when a
    read-only image byte was used."""
    from .relative_memory import _operation_key, _resolve_validated_storage, _storage_ref
    from ._scope_contracts import VarnodeKindCode
    from .model import ResolvedStorage

    ssa = normalized.memory_ssa
    if ssa is None or unit.observation is None:
        return ()
    context = normalized.scopes.resolution_context
    operations = {
        _operation_key(instruction.address, ordinal, operation): operation
        for instruction in unit.observation.instructions
        for ordinal, operation in enumerate(instruction.operations)
    }
    operations.update(dict(normalized.operation_overrides))
    action_ids = {action.operation_key: index for index, action in enumerate(ssa.actions)}
    reads_of: dict = {}
    for read in ssa.reads:
        reads_of.setdefault(read.action_id, []).append(read)
    joins = {row.join_definition_id: row.source_definition_ids for row in ssa.joins}
    unresolved = {row.action_id for row in ssa.unresolved_reads}
    # reads the backward engine gave a debt (a call may have clobbered them,
    # another write may have reached them): the SSA's reaching definition is
    # not their value -- TOP (docs 25.33 R2-3)
    debts: dict = {}
    for row in normalized.call_clobber_reads:
        debts.setdefault(row.operation_key, []).extend(row.spans)
    for row in normalized.may_alias_reads:
        debts.setdefault(row.operation_key, []).extend(row.spans if not row.unknown_address else (None,))
    function = f"{unit.scopes.function.entry.space_id:x}:{unit.scopes.function.entry.byte_offset:x}"

    def span_of(varnode):
        resolved = _resolve_validated_storage(_storage_ref(varnode), context)
        return resolved.span if type(resolved) is ResolvedStorage else None

    values: dict = {}
    used_readonly: set = set()
    changes: dict = {}
    # definitions resting on a read with a debt (transitively): their value
    # is sound (a debt read is TOP), but a memory place the backward engine
    # projected from such an address may not be the place really accessed
    tainted: set = set()
    taint = [False]

    def definition_value(index, span):
        """None: not evaluated yet (bottom). Part of a register entry
        definition (entry spans are coalesced) is that part's own entry value."""
        definition = ssa.definitions[index]
        if definition.kind is MemoryDefinitionKind.ENTRY \
                and definition.span.object_id.kind is StorageObjectKind.REGISTER_FILE:
            return Value(8 * span.size, ((("entry", span.start, span.size), Interval.offset(0, 8 * span.size)),))
        current = values.get(index)
        return None if current is None else _slice(current, definition.span, span)

    def read_value(action_id, span):
        """The value an action's read of ``span`` takes, or TOP."""
        for debt in debts.get(ssa.actions[action_id].operation_key, ()):
            if debt is None or debt.overlaps(span):
                taint[0] = True
                return Value.top(8 * span.size)
        rows = [read for read in reads_of.get(action_id, ()) if read.span == span]
        if any(index in tainted for row in rows for fragment in row.fragments for index in fragment.definition_ids):
            taint[0] = True   # (before any TOP below: a TOP read of a tainted place is tainted too)
        if len(rows) != 1 or len(rows[0].fragments) != 1:
            return Value.top(8 * span.size)
        fragment = rows[0].fragments[0]
        if len(fragment.definition_ids) != 1 or fragment.span != span:
            return Value.top(8 * span.size)
        index = fragment.definition_ids[0]
        if not ssa.definitions[index].span.contains(span):
            return Value.top(8 * span.size)
        return definition_value(index, span)

    def input_value(operation_key, varnode):
        if varnode.kind is VarnodeKindCode.CONSTANT:
            return Value.number(varnode.coordinate.byte_offset, 8 * varnode.byte_size)
        span = span_of(varnode)
        action_id = action_ids.get(operation_key)
        if span is None or action_id is None:
            return Value.top(8 * varnode.byte_size)
        return read_value(action_id, span)

    def memory_value(operation_key, operation):
        """A LOAD's loaded value: its single memory read (not an input's)."""
        action_id = action_ids.get(operation_key)
        size = operation.output.byte_size
        if action_id is None or action_id in unresolved:
            return Value.top(8 * size)
        inputs = {span_of(item) for item in operation.inputs if item.kind is not VarnodeKindCode.CONSTANT}
        rows = [read for read in reads_of.get(action_id, ()) if read.span not in inputs]
        if any(index in tainted for row in rows for fragment in row.fragments for index in fragment.definition_ids):
            taint[0] = True
        if len(rows) != 1 or rows[0].span.size != size:
            return Value.top(8 * size)
        return read_value(action_id, rows[0].span)

    def address_tainted(key, varnode):
        """Whether an access's address rests on a debt (its value is then
        still sound, but the place the SSA projected may be wrong)."""
        saved, taint[0] = taint[0], False
        input_value(key, varnode)
        found, taint[0] = taint[0], saved or taint[0]
        return found

    def evaluate(index):
        taint[0] = False
        found = _evaluate(index)
        if taint[0]:
            tainted.add(index)
        return found

    def _evaluate(index):
        definition = ssa.definitions[index]
        bits = 8 * definition.span.size
        kind = definition.kind
        if kind is MemoryDefinitionKind.ENTRY:
            span = definition.span
            if span.object_id.kind is StorageObjectKind.REGISTER_FILE:
                return Value(bits, ((("entry", span.start, span.size), Interval.offset(0, bits)),))
            if readonly_image is not None and span.object_id.kind is StorageObjectKind.ADDRESS_SPACE:
                constant = readonly_image.value(span.object_id.space_key, span.start, span.size)
                if constant is not None:
                    used_readonly.add(index)
                    return Value.number(constant, bits)
            return Value.top(bits)
        if kind is MemoryDefinitionKind.JOIN:
            found = None
            for source in joins.get(index, ()):
                if source in tainted:
                    taint[0] = True
                part = definition_value(source, definition.span)
                if part is None:
                    continue
                found = part if found is None else join(found, part)
            if found is None:
                return None
            previous = values.get(index)
            if previous is not None and found != previous:
                changes[index] = changes.get(index, 0) + 1
                if changes[index] > WIDEN_AFTER:
                    found = join(previous, found, widen=True)
            return found
        if kind is not MemoryDefinitionKind.DATA_WRITE:
            return Value.top(bits)
        operation = operations.get(definition.operation_key)
        if operation is None:   # (a call effect's row: ``~k``, ``~in`` ...)
            return Value.top(bits)
        key = definition.operation_key
        if operation.opcode == "STORE" and len(operation.inputs) == 3:
            if address_tainted(key, operation.inputs[1]):
                return Value.top(bits)
            stored = input_value(key, operation.inputs[2])
            return stored if stored is None or stored.bits == bits else Value.top(bits)
        if operation.output is None:
            return Value.top(bits)
        output_span = span_of(operation.output)
        if operation.opcode == "LOAD":
            if len(operation.inputs) > 1 and address_tainted(key, operation.inputs[1]):
                whole = Value.top(8 * operation.output.byte_size)
            else:
                whole = memory_value(key, operation)
        elif operation.opcode in ("CALL", "CALLIND", "CALLOTHER"):
            whole = Value.top(8 * operation.output.byte_size)
        else:
            inputs = list(operation.inputs)
            found = [input_value(key, item) for item in inputs]
            whole = None if any(item is None for item in found) else _transfer(
                operation.opcode, found, [item.byte_size for item in inputs], operation.output.byte_size)
        if output_span is None or not output_span.contains(definition.span):
            return Value.top(bits)
        return None if whole is None else _slice(whole, output_span, definition.span)

    for _ in range(MAX_PASSES):
        changed = False
        before = len(tainted)
        for index in range(len(ssa.definitions)):
            found = evaluate(index)
            if found is not None and values.get(index) != found:
                values[index] = found
                changed = True
        if not changed and len(tainted) == before:
            break   # (values and taint both stable: a newly tainted definition changes its readers)
    else:
        return ()   # (no fixpoint within the bound: no facts)

    def local_value(instruction, ordinal, varnode):
        """A CALLIND / BRANCHIND target: the call's own action reads nothing,
        so the value is the definition an earlier operation of the same
        instruction made of that varnode (``COPY t <- r``, ``LOAD t <- [..]``)."""
        from .pcode_blocks import has_internal_flow

        if has_internal_flow(instruction):
            return None   # (a branch inside the instruction: no straight line)
        span = span_of(varnode)
        for index in range(ordinal - 1, -1, -1):
            earlier = instruction.operations[index]
            output = earlier.output
            if output is not None and output != varnode and _overlap(output, varnode):
                return None   # (a later partial write of the target)
            if output != varnode:
                continue
            action_id = action_ids.get(_operation_key(instruction.address, index, earlier))
            if action_id is None or span is None:
                return None
            for definition in ssa.actions[action_id].write_definition_ids:
                if ssa.definitions[definition].span == span:
                    return values.get(definition)
            return None
        return None

    labels = tuple(sorted({*assumptions, *(label for attribute, label in _NORMALIZATION_ASSUMPTIONS
                                           if getattr(normalized, attribute, False)),
                           *(("readonly-image-data-is-constant",) if used_readonly else ())}))
    facts = []
    for instruction in unit.observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            position = SUBJECTS.get(operation.opcode)
            if position is None or len(operation.inputs) <= position:
                continue
            key = _operation_key(instruction.address, ordinal, operation)
            if key in dict(normalized.operation_overrides):
                continue   # (an override's operands are its own: F0 leaves rep sites out)
            varnode = operation.inputs[position]
            if operation.opcode in ("CALLIND", "BRANCHIND") and varnode.kind is not VarnodeKindCode.CONSTANT:
                claim = local_value(instruction, ordinal, varnode)
            else:
                claim = input_value(key, varnode)
            if claim is None or claim.is_top:
                continue
            requires = labels
            digest = hashlib.sha256(f"forward-v0|{function}|{key}|{position}".encode()).hexdigest()[:16]
            facts.append(Fact(digest, function, key, position, claim, requires))
    return tuple(sorted(facts, key=lambda fact: fact.operation))


def _overlap(left, right) -> bool:
    """Whether two varnodes share a byte."""
    return left.coordinate.space_id == right.coordinate.space_id \
        and left.coordinate.byte_offset < right.coordinate.byte_offset + right.byte_size \
        and right.coordinate.byte_offset < left.coordinate.byte_offset + left.byte_size


def concretizes(claim: Value, concrete: int, entry) -> bool:
    """Whether ``concrete`` is one of the values ``claim`` allows, ``entry(offset,
    size)`` giving the run's entry value of a register span (oracles)."""
    if claim.is_top:
        return True
    modulus = 1 << claim.bits
    for base, offsets in claim.items:
        start = 0 if base == _ABS else entry(base[1], base[2])
        if offsets.contains((concrete - start) % modulus):
            return True
    return False
