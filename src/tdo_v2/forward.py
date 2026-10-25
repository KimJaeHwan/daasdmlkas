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
fits; any constant is sliced exactly); a read of several fragments whose
values are all exact numbers is their concatenation in byte order (little-
endian languages only, as every byte slice here); a read with several
definitions or other fragments, an unresolved read, a call effect's definition, a KILL, or an
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
MAX_CANDIDATES = 8     # candidate places of a ranged read (F4a)
ENTRY_VALUE = "entry"  # (``probe``: a register's own entry value alone reaches the read)
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
    return _moved(value, low, high, delta.stride)


def _moved(value: Value, low: int, high: int, step: int) -> Value:
    """value + every ``step``-th number of [low, high] (signed), modulo
    2**bits: as ``_shift``."""
    bits, modulus = value.bits, 1 << value.bits
    items = {}
    for base, offsets in value.items:
        stride = gcd(offsets.stride, step)
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
    if opcode == "INT_AND" and len(values) > 1 and singles[1] is not None and numbers[0] is None:
        # x & c <= c whatever x is (a based value's bits included)
        interval = _numeric(opcode, [Interval.full(8 * widths[0])], singles, bits)
        return Value.top(bits) if interval is None else Value(bits, ((_ABS, interval),))
    if any(number is None for number in numbers):
        return Value.top(bits)   # (a based value through any other operation: no base kept)
    interval = _numeric(opcode, numbers, singles, bits)
    return Value.top(bits) if interval is None else Value(bits, ((_ABS, interval),))


def _slice(value: Value, definition_span, span, little: bool) -> Value:
    """The value of ``span`` (inside ``definition_span``) of a definition
    (byte offsets read little-endian: TOP for a big-endian part)."""
    bits = 8 * span.size
    if definition_span == span:
        return value
    if not little:
        return Value.top(bits)
    single = value.single_number()
    shift = 8 * (span.start - definition_span.start)
    if single is not None:
        return Value.number(single >> shift, bits)
    number = value.numeric()
    if shift == 0 and number is not None and number.hi < 1 << bits:
        return Value(bits, ((_ABS, Interval(number.lo, number.hi, number.stride, bits)),))
    return Value.top(bits)


# -- the analysis -------------------------------------------------------------------

@dataclass(frozen=True)
class ForwardInputs:
    """The frozen inputs of one accepted normalization's call-clobber and
    may-alias derivations (docs 25.33 F4a): ``NormalizedFunction.forward_inputs``
    with the forward switch on. Policies are the CONFIGURED ones, not the
    "used" flags; collections are copies the normalization no longer mutates."""
    effect_unit: object
    observation: object
    context: object
    address_spaces: tuple
    assumed_calls: frozenset
    quiet_calls: frozenset
    observed_calls: dict
    escaping_calls: frozenset
    opaque_calls: frozenset
    private_frame_above: int
    assume_globals_disjoint_from_stack: bool
    wild_objects: frozenset
    fresh_objects: frozenset
    nonstack_objects: frozenset
    uncertain_writers: tuple       # ((writer key, conditions | None), ...)
    separations: tuple
    proven_call_effects: tuple     # ((call key, ProvenCallEffect), ...)
    kept_memory: tuple             # ((call key, spans), ...)
    below_bounds: tuple            # ((call key, stack object, first kept offset), ...)
    entry_values_not_frame: bool = True      # (may_alias.ENTRY_VALUES_NOT_FRAME as configured)
    opaque_no_stack_addresses: bool = True   # (may_alias.OPAQUE_NO_STACK_ADDRESSES as configured)
    read_separations: object = None
    nonstack_spans: frozenset = frozenset()


def probe(normalized, load_key: str, spans) -> tuple[dict, tuple[str, ...]]:
    """The backward engine's own debt judgement and reaching definition for
    reads of ``spans`` at the operation ``load_key`` (docs 25.33 F4a): the
    final effect unit with those reads added (``normalized.forward_inputs``)
    goes through the same call-clobber and may-alias derivations, with the same
    frozen inputs, and through the memory SSA build. Returns span -> the
    ORIGINAL SSA definition id that alone covers it with no debt, or None
    (a debt overlapping it, several or partial definitions, or a definition
    with no identical one in the normalized function's SSA), or ``ENTRY_VALUE``
    when a register's entry definition alone covers it -- with the named
    assumptions the probe's derivations used (its private-frame and opaque-call
    decisions). The derivations run under the normalization's CONFIGURED
    policies (``ForwardInputs``), not the ambient defaults. Nothing of the
    normalized function changes (fresh collectors and copies throughout)."""
    from dataclasses import replace

    from .call_clobber import derive_call_clobber_reads
    from .call_observation_contracts import build_bound_local_memory_ssa
    from .effect_decode import decode_effect_unit
    from .may_alias import ENTRY_VALUES_NOT_FRAME, OPAQUE_NO_STACK_ADDRESSES, EscapeMemo, derive_may_alias_reads
    from .model import ResolvedStorage
    from .normalize import _memory_spans_except_below

    inputs = normalized.forward_inputs
    spans = tuple(spans)
    found = {span: None for span in spans}
    if inputs is None or not spans:
        return found, ()
    unit = inputs.effect_unit
    blocks, hit = [], False
    for block in unit.blocks:
        effects = []
        for effect in block.effects:
            if effect.operation_key == load_key:
                hit = True
                effect = replace(effect, reads=(*effect.reads, *(ResolvedStorage(span) for span in spans)))
            effects.append(effect)
        blocks.append(replace(block, effects=tuple(effects)))
    if not hit:
        return found, ()
    probed = replace(unit, blocks=tuple(blocks))
    rows = dict(inputs.proven_call_effects)
    preserved = {key: tuple(row.preserved) for key, row in rows.items()}
    for key, kept in inputs.kept_memory:
        preserved[key] = preserved.get(key, ()) + tuple(kept)
    for key, object_id, bound in inputs.below_bounds:
        preserved[key] = preserved.get(key, ()) + _memory_spans_except_below(probed, object_id, bound)
    clobbers = derive_call_clobber_reads(
        probed, inputs.observation, inputs.context, assumed_calls=inputs.assumed_calls,
        proven_preserved=preserved,
        memory_keeping=frozenset(key for key, row in rows.items() if row.preserves_memory and not row.clobbers_below),
        unrestored_stack_calls=frozenset(key for key, row in rows.items() if not row.restores_stack),
    )
    uncertain = dict(inputs.uncertain_writers)
    frame_uses: list = []
    opaque_uses: list = []
    tokens = (ENTRY_VALUES_NOT_FRAME.set(inputs.entry_values_not_frame),
              OPAQUE_NO_STACK_ADDRESSES.set(inputs.opaque_no_stack_addresses))
    try:
        aliases = derive_may_alias_reads(
        probed, inputs.observation, inputs.context, inputs.address_spaces,
        assumed_calls=inputs.quiet_calls,
        assume_globals_disjoint_from_stack=inputs.assume_globals_disjoint_from_stack,
        wild_objects=inputs.wild_objects, fresh_objects=inputs.fresh_objects,
        nonstack_objects=inputs.nonstack_objects, observed_calls=dict(inputs.observed_calls),
        nonstack_spans=inputs.nonstack_spans,
        escaping_calls=inputs.escaping_calls, opaque_calls=inputs.opaque_calls, opaque_uses=opaque_uses,
        private_above=inputs.private_frame_above,
        uncertain_writers=frozenset(uncertain),
        no_kill_writers=frozenset(key for key, conditions in uncertain.items() if conditions is None),
        uses=frame_uses, separations=inputs.separations,
        escape_memo=EscapeMemo(probed, inputs.observation, inputs.context, inputs.address_spaces),
        read_separations=inputs.read_separations,
        )
    finally:
        OPAQUE_NO_STACK_ADDRESSES.reset(tokens[1])
        ENTRY_VALUES_NOT_FRAME.reset(tokens[0])
    used = []
    used.extend(normalized.forward_memory_requires)
    if any(frame_uses):
        used.append("entry-values-do-not-address-the-new-frame")
        if inputs.private_frame_above:
            used.append("win64-home-space-callee-private")
    if any(opaque_uses):
        used.append("opaque-callees-leave-no-stack-addresses")
    if inputs.assume_globals_disjoint_from_stack:
        used.append("globals-disjoint-from-stack")
    indebted = [span for row in (*clobbers, *aliases) if row.operation_key == load_key for span in row.spans]
    ssa = build_bound_local_memory_ssa(decode_effect_unit(probed)).result
    original = normalized.memory_ssa

    def identity(definition):
        return (definition.kind, definition.operation_key, definition.write_ordinal, definition.block_key,
                definition.span)

    by_identity = {identity(definition): index for index, definition in enumerate(original.definitions)}
    action = next((index for index, row in enumerate(ssa.actions) if row.operation_key == load_key), None)
    for span in spans:
        if any(debt.overlaps(span) for debt in indebted):
            continue
        reads = [read for read in ssa.reads if read.action_id == action and read.span == span]
        if not reads or len(reads[0].fragments) != 1 or any(read.fragments != reads[0].fragments for read in reads):
            continue   # (an effect that already reads the span reads it twice: one place, the same definitions)
        fragment = reads[0].fragments[0]
        if fragment.span != span or len(fragment.definition_ids) != 1:
            continue
        definition = ssa.definitions[fragment.definition_ids[0]]
        if not definition.span.contains(span):
            continue
        if definition.kind is MemoryDefinitionKind.ENTRY \
                and definition.span.object_id.kind is StorageObjectKind.REGISTER_FILE:
            found[span] = ENTRY_VALUE   # (the original SSA may have no such definition: nothing else read it)
        else:
            found[span] = by_identity.get(identity(definition))
    return found, tuple(used)


@dataclass(frozen=True, slots=True)
class Fact:
    id: str
    function: str
    operation: str          # operation key
    input: int              # input index
    claim: Value
    requires: tuple[str, ...]
    # the activation the claim's entry bases belong to (F2a): () -- the
    # function's own; (caller key, call key) -- the caller's, for the callee's
    # executions entered from that call (a call instruction two overlapping
    # functions share is two contexts)
    context: tuple[str, ...] = ()


_NORMALIZATION_ASSUMPTIONS = (
    ("assumes_globals_disjoint_from_stack", "globals-disjoint-from-stack"),
    ("assumes_readonly_image_constant", "readonly-image-data-is-constant"),
    ("assumes_import_slots_hold_exports", "import-slots-hold-their-exports"),
    ("assumes_entry_values_not_frame", "entry-values-do-not-address-the-new-frame"),
    ("assumes_opaque_callees_leave_no_stack_addresses", "opaque-callees-leave-no-stack-addresses"),
    ("assumed_direction_flag_clear", "direction-flag-clear"),
)


def forward_facts(normalized, unit, *, readonly_image=None, assumptions=()) -> tuple[Fact, ...]:
    """The F0 facts of one normalized function (``_analyze``)."""
    return _analyze(normalized, unit, readonly_image=readonly_image, assumptions=assumptions).facts


@dataclass(frozen=True, slots=True)
class _Analysis:
    facts: tuple            # (Fact, ...)
    labels: tuple           # every fact's requires
    bind: object            # (call key, register spans) -> ({span: Value}, assumptions), or None


def _analyze(normalized, unit, *, readonly_image=None, assumptions=()) -> _Analysis:
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
    if ssa is None or unit.observation is None or _projection_sensitive(unit.observation):
        return _Analysis((), (), None)
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
    unknown_address_reads = set()   # (operations whose memory read's address is unknown: that read only)
    for row in normalized.may_alias_reads:
        if row.unknown_address:
            unknown_address_reads.add(row.operation_key)
        else:
            debts.setdefault(row.operation_key, []).extend(row.spans)
    function = f"{unit.scopes.function.entry.space_id:x}:{unit.scopes.function.entry.byte_offset:x}"
    # (byte offsets as significance: the language must be little-endian, as relative_memory's)
    little = unit.scopes.program.evidence.translation_namespace.language_id.split(":")[1:2] == ["LE"]

    def span_of(varnode):
        resolved = _resolve_validated_storage(_storage_ref(varnode), context)
        return resolved.span if type(resolved) is ResolvedStorage else None

    values: dict = {}
    literal_rows = {key: row for key, row in normalized.pointer_rows if row[0] == "const"}
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
        definition = None if index == ENTRY_VALUE else ssa.definitions[index]
        if definition is None or (definition.kind is MemoryDefinitionKind.ENTRY
                                  and definition.span.object_id.kind is StorageObjectKind.REGISTER_FILE):
            return Value(8 * span.size, ((("entry", span.start, span.size), Interval.offset(0, 8 * span.size)),))
        current = values.get(index)
        return None if current is None else _slice(current, definition.span, span, little)

    def pieces(fragments, span):
        """A read of several fragments (docs 25.33 "틀": the reaching values
        per fragment joined in byte order): the
        fragments' values joined in byte order -- only when every fragment is
        one exact number and they tile the read (little-endian), else TOP;
        None while a fragment is not evaluated yet."""
        bits = 8 * span.size
        if not little:
            return Value.top(bits)
        position, number = span.start, 0
        for fragment in sorted(fragments, key=lambda row: row.span.start):
            if fragment.span.start != position or len(fragment.definition_ids) != 1 \
                    or not ssa.definitions[fragment.definition_ids[0]].span.contains(fragment.span):
                return Value.top(bits)
            part = definition_value(fragment.definition_ids[0], fragment.span)
            if part is None:
                return None
            single = part.single_number()
            if single is None:
                return Value.top(bits)
            number |= single << (8 * (position - span.start))
            position += fragment.span.size
        return Value.number(number, bits) if position == span.start + span.size else Value.top(bits)

    def read_value(action_id, span):
        """The value an action's read of ``span`` takes, or TOP."""
        for debt in debts.get(ssa.actions[action_id].operation_key, ()):
            if debt.overlaps(span):
                taint[0] = True
                return Value.top(8 * span.size)
        rows = [read for read in reads_of.get(action_id, ()) if read.span == span]
        if any(index in tainted for row in rows for fragment in row.fragments for index in fragment.definition_ids):
            taint[0] = True   # (before any TOP below: a TOP read of a tainted place is tainted too)
        if len(rows) != 1:
            return Value.top(8 * span.size)
        if len(rows[0].fragments) > 1:
            return pieces(rows[0].fragments, span)
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

    probes: dict = {}
    probe_labels: set = set()
    anchors = None

    def ranged_value(operation_key, operation):
        """F4a: a LOAD at a ranged address of an entry-anchored object
        (docs 25.33): every candidate span through ``probe`` -- the engine's
        own debt rules and reaching definitions; all candidates clean -> the
        join of their values (each candidate definition's taint carried), else
        TOP. Needs ``normalized.forward_inputs``."""
        nonlocal anchors
        size = operation.output.byte_size
        if normalized.forward_inputs is None or len(operation.inputs) < 2:
            return Value.top(8 * size)
        address = input_value(operation_key, operation.inputs[1])
        if address is None or address.is_top or len(address.items) != 1:
            return Value.top(8 * size)
        base, offsets = address.items[0]
        if base == _ABS or (offsets.stride and (offsets.hi - offsets.lo) // offsets.stride + 1 > MAX_CANDIDATES):
            return Value.top(8 * size)
        if anchors is None:
            from .interprocedural import _relative_anchors

            anchors = _relative_anchors(unit, normalized)
        found = [(object_id, space) for object_id, (span, space) in anchors.items()
                 if span.object_id.kind is StorageObjectKind.REGISTER_FILE and span.start == base[1]
                 and span.size == base[2]]
        if len(found) != 1:
            return Value.top(8 * size)
        object_id, space = found[0]
        selector = operation.inputs[0]
        if selector.kind is not VarnodeKindCode.CONSTANT or selector.coordinate.byte_offset != space:
            return Value.top(8 * size)   # (the LOAD's space is not the anchored object's)
        bits = next((row.address_size_bits for row in normalized.forward_inputs.address_spaces
                     if row.space_id == space), None)
        if bits is None:
            return Value.top(8 * size)
        from .span_geometry import ByteSpan

        step_ = offsets.stride or 1
        spans = tuple(ByteSpan(object_id, (1 << bits) + offset, size)
                      for offset in range(offsets.lo, offsets.hi + 1, step_))
        # (per candidate span: a loop's address interval grows pass by pass --
        # only the spans not probed yet are probed. A probe read defines
        # nothing and its debts are per span; probing spans together can at
        # most widen an ENTRY definition so a span maps to no original one
        # (None, conservative) -- every cached result is valid on its own.
        # Labels over-report the union)
        found_ids, labels = probes.setdefault(operation_key, ({}, set()))
        missing = tuple(span for span in spans if span not in found_ids)
        if missing:
            found_new, used_new = probe(normalized, operation_key, missing)
            found_ids.update(found_new)
            labels.update(used_new)
        used = tuple(sorted(labels))
        result = None
        for span in spans:
            index = found_ids[span]
            if index is None:
                taint[0] = True   # (an indebted or unplaced candidate: the old taint contract)
                return Value.top(8 * size)
            if index in tainted:
                taint[0] = True
            part = definition_value(index, span)
            if part is None:
                return None   # (not evaluated yet: bottom)
            result = part if result is None else join(result, part)
        probe_labels.update(used)   # (a value resting on the probe rests on its assumptions)
        return result

    def memory_value(operation_key, operation):
        """A LOAD's loaded value: its single memory read (not an input's), or
        a ranged read (``ranged_value``)."""
        action_id = action_ids.get(operation_key)
        size = operation.output.byte_size
        if action_id is None:
            return Value.top(8 * size)
        if action_id in unresolved or operation_key in unknown_address_reads:
            value = ranged_value(operation_key, operation)
            if value is not None and value.is_top and operation_key in unknown_address_reads:
                taint[0] = True   # (no probe settled it: the unknown-address debt stands, Fable F4a round 2)
            return value
        inputs = {span_of(item) for item in operation.inputs if item.kind is not VarnodeKindCode.CONSTANT}
        rows = [read for read in reads_of.get(action_id, ()) if read.span not in inputs]
        if any(index in tainted for row in rows for fragment in row.fragments for index in fragment.definition_ids):
            taint[0] = True
        if len(rows) != 1 or rows[0].span.size != size:
            return ranged_value(operation_key, operation)
        if rows[0].span.object_id in getattr(normalized, "wild_objects", frozenset()):
            return ranged_value(operation_key, operation)   # (an index object: its read is no single place)
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
            row = literal_rows.get(definition.operation_key)
            if little and row is not None and len(row) == 3 and type(row[1]) is int and type(row[2]) is int \
                    and row[1] == definition.span.size and 0 < row[1] <= 16 \
                    and 0 <= row[2] < 1 << bits:
                return Value.number(row[2], bits)
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
        return None if whole is None else _slice(whole, output_span, definition.span, little)

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
        return _Analysis((), (), None)   # (no fixpoint within the bound: no facts)

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

    labels = tuple(sorted({*assumptions, *normalized.forward_memory_requires,
                           *(label for attribute, label in _NORMALIZATION_ASSUMPTIONS
                                           if getattr(normalized, attribute, False)),
                           *(("readonly-image-data-is-constant",) if used_readonly else ()),
                           *probe_labels}))
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

    def bind(call_key, spans):
        """The caller's values of register ``spans`` just before the call
        ``call_key`` (F2a): probe reads on the call's FIRST effect (its
        ``~in`` / ``~ld`` staging, or the bare call -- before any of the call's
        writes) -> the value of each span's single debt-free reaching
        definition, else TOP; with the probe's assumptions."""
        first = next((effect.operation_key for block in normalized.forward_inputs.effect_unit.blocks
                      for effect in block.effects
                      if effect.operation_key == call_key or effect.operation_key.startswith(call_key + "~")),
                     None) if normalized.forward_inputs is not None else None
        if first is None:
            return {span: Value.top(8 * span.size) for span in spans}, ()
        found, used = probe(normalized, first, spans)
        bound = {}
        for span in spans:
            value = None if found[span] is None else definition_value(found[span], span)
            bound[span] = Value.top(8 * span.size) if value is None else value
        return bound, used

    return _Analysis(tuple(sorted(facts, key=lambda fact: fact.operation)), labels, bind)


def substitute(claim: Value, binding: dict) -> Value:
    """A callee claim with each entry base replaced by its binding (F2a):
    entry(r) + [a, b] with r bound to {(base', [c, d])} -> {(base', [a + c,
    b + d])} (signed, wrap -> TOP); plain numbers unchanged; an unbound,
    TOP or other-width base -> TOP."""
    if claim.is_top:
        return claim
    found = None
    for base, offsets in claim.items:
        if base == _ABS:
            part = Value(claim.bits, ((base, offsets),))
        else:
            bound = binding.get(base)
            if bound is None or bound.is_top or bound.bits != claim.bits:
                return Value.top(claim.bits)
            part = _moved(bound, offsets.lo, offsets.hi, offsets.stride)
        if part.is_top:
            return part
        found = part if found is None else join(found, part)
    return found


def context_facts(results, *, readonly_image=None, assumptions=lambda key, item: ()) -> tuple[Fact, ...]:
    """F2a (docs 25.33): at every direct call to a function normalized in the
    same run, the callee's parametric facts with the caller's values of their
    entry registers SUBSTITUTED -- facts for the callee's executions entered
    from that call, in the caller's activation (``Fact.context`` = (caller
    key, call key)).
    The binding is taken at callee entry: the caller's register values just
    before the call (``_Analysis.bind``, debts included); the stack pointer is
    the caller's pre-push value + the observed call shape's delta, applied
    once -- a call with no observed shape, or whose push is still in the
    effect unit (not projected), binds nothing; a register the call
    instruction writes after the push binds to TOP (``_call_local_writes``). A callee fact keeps
    holding for every activation (its own requires); requires = the caller's
    + the binding probe's + the callee fact's. Only callers normalized with
    the forward switch on; ``assumptions(key, item)`` as ``forward_facts``'s."""
    from .normalize import NormalizedFunction
    from .observed_call_state import observed_call_state_projections
    from .span_geometry import ByteSpan

    analyses: dict = {}

    def analysis(key):
        if key not in analyses:
            item = results.get(key)
            analyses[key] = None if item is None or type(item.normalized) is not NormalizedFunction else _analyze(
                item.normalized, item.unit, readonly_image=readonly_image, assumptions=assumptions(key, item))
        return analyses[key]

    facts = []
    for key, item in sorted(results.items()):
        if type(item.normalized) is not NormalizedFunction or item.normalized.forward_inputs is None:
            continue
        transitions = None
        # (``item.calls`` also holds tail jumps: no observed call shape, so they bind nothing)
        for call_key, callee_key in sorted(item.calls.items()):
            callee = analysis(callee_key)
            parametric = [fact for fact in (callee.facts if callee is not None else ())
                          if any(base != _ABS for base, _ in fact.claim.items)]
            if not parametric:
                continue
            register = next((definition.span.object_id for definition in results[callee_key].normalized.memory_ssa
                             .definitions if definition.span.object_id.kind is StorageObjectKind.REGISTER_FILE), None)
            if transitions is None:
                transitions = {row.call_operation_key: row
                               for row in observed_call_state_projections(item.unit.observation)}
                effect_keys = {effect.operation_key for block in item.normalized.forward_inputs.effect_unit.blocks
                               for effect in block.effects}
            projection = transitions.get(call_key)
            caller = analysis(key)
            if register is None or projection is None or caller is None or caller.bind is None \
                    or any(transient in effect_keys for transient in projection.transient_operation_keys):
                continue   # (a push still in the unit: the binding would see the post-push SP)
            transition = projection.memory_transition
            stack = (transition.callee_base.byte_offset, transition.callee_base.byte_size)
            written = _call_local_writes(item.unit.observation, call_key, stack)
            if written is None:
                continue
            bases = sorted({base for fact in parametric for base, _ in fact.claim.items if base != _ABS})
            spans = {base: ByteSpan(register, base[1], base[2]) for base in bases}
            values, used = caller.bind(call_key, tuple(spans.values()))
            binding = {}
            for base, span in spans.items():
                value = values[span]
                if (base[1], base[2]) == stack:
                    if not value.is_top:   # (callee entry SP = the caller's pre-push SP + delta, once)
                        value = _moved(value, transition.displacement_delta, transition.displacement_delta, 0)
                elif base[1] < stack[0] + stack[1] and stack[0] < base[1] + base[2]:
                    value = Value.top(value.bits)   # (part of the stack pointer: not the shape's base)
                if any(base[1] < start + size and start < base[1] + base[2] for start, size in written):
                    value = Value.top(value.bits)   # (written inside the call instruction after the push)
                binding[base] = value
            for fact in parametric:
                claim = substitute(fact.claim, binding)
                if claim.is_top:
                    continue   # (an equal claim is kept: its entry bases are the caller's now)
                requires = tuple(sorted({*caller.labels, *used, *fact.requires}))
                digest = hashlib.sha256(
                    f"forward-v0|{fact.function}|{fact.operation}|{fact.input}|{key}|{call_key}".encode()
                ).hexdigest()[:16]
                facts.append(Fact(digest, fact.function, fact.operation, fact.input, claim, requires, (key, call_key)))
    return tuple(sorted(facts, key=lambda fact: (fact.context, fact.operation)))


def _projection_sensitive(observation) -> bool:
    """Whether a projected call shape has an operation between its push's
    stack-pointer adjustment and its call (other than the return-address
    store) that reads or writes the stack pointer: the projection removes the
    push, so such an operation's value in the memory SSA uses the pre-push
    stack pointer while the execution uses the pushed one (Astra F2a round 2;
    Ghidra's x86 calls compute their target before the push). Such a function
    gets no forward facts and binds nothing. (The recognizer now refuses any
    call instruction with an operation between the push and the call, so this
    never fires; it stays as a guard.)"""
    from ._scope_contracts import VarnodeKindCode
    from .observed_call_state import observed_call_state_projections

    instructions = {(row.address.space_id, row.address.byte_offset): row for row in observation.instructions}
    for projection in observed_call_state_projections(observation):
        space, address, call = projection.call_operation_key.split(":")[:3]
        adjust, store = (int(key.split(":")[2]) for key in projection.transient_operation_keys)
        instruction = instructions[(int(space, 16), int(address, 16))]
        stack = projection.memory_transition.caller_base
        for ordinal in range(adjust + 1, int(call)):
            if ordinal == store:
                continue
            operation = instruction.operations[ordinal]
            for varnode in (*operation.inputs, *((operation.output,) if operation.output is not None else ())):
                if varnode.kind is VarnodeKindCode.REGISTER \
                        and varnode.coordinate.byte_offset < stack.byte_offset + stack.byte_size \
                        and stack.byte_offset < varnode.coordinate.byte_offset + varnode.byte_size:
                    return True
    return False


def _call_local_writes(observation, call_key: str, stack) -> list | None:
    """(offset, size) of the registers the call instruction writes before its
    call operation, other than the one stack-pointer adjustment of the push:
    the normalized call shape projects the push away, so a register written
    after it may hold a value the binding (read before the call's effects)
    does not see (Astra F2a round 1). None: an output that is neither a
    register nor a temporary, or no such instruction (the call binds nothing)."""
    from ._scope_contracts import VarnodeKindCode

    space, address, ordinal = call_key.split(":")[:3]
    instruction = next((row for row in observation.instructions if row.address.space_id == int(space, 16)
                        and row.address.byte_offset == int(address, 16)), None)
    if instruction is None:
        return None
    written, pushed = [], False
    for operation in instruction.operations[:int(ordinal)]:
        output = operation.output
        if output is None or output.kind is VarnodeKindCode.UNIQUE:
            continue
        if output.kind is not VarnodeKindCode.REGISTER:
            return None
        place = (output.coordinate.byte_offset, output.byte_size)
        if place == tuple(stack) and not pushed:
            pushed = True   # (the push's adjustment: the transition's delta)
            continue
        written.append(place)
    return written


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
