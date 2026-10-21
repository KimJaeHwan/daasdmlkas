"""Derived models: a library function's summary saved for reuse (design
section 23, step 3).

A library (a DLL) is analyzed once with the engine (``interprocedural``,
``own_library``, cut at ``internal`` hand models); an exported function's
``FunctionSummary`` plus its anchors is saved as a caller-independent
TEMPLATE in a model file of ``"kind": "summary"``. A program importing the
function loads it (``summary_store``) and gets the call effect exactly as if
the function were in its own Bundle: the template goes through the same
``derive_proven_call_effect`` at the call site, with the same alias-condition
feedback (``interprocedural``).

Objects (the only caller-dependent part) are a table:
* the register file: rebased to the importer's (same ``language_id``);
* a FUNCTION_RELATIVE object addressed from one entry register value, or
  from a pointer held in entry memory of such an object (``anchors``):
  ``{"anchor": span}`` -- the importer binds it at the call;
* everything else -- the library's globals (ADDRESS_SPACE: the importer
  cannot locate them), objects with no anchor, call-local temporaries
  appearing as sources: ``{"local": true}``, an object no caller can locate
  (writes keep no memory, values from it are unknown, conditions on it are
  undecidable). Never an importer ADDRESS_SPACE id.

Operation keys are prefixed ``dll:`` (they only match inside one summary).
Serialization fails closed: an unknown field, kind or version is an error.

Export refuses (``TemplateRefused``) a function whose summary is missing,
an unverified recursion member, one with tail exits not composed, one using
TEST-ONLY inputs, source labels or sink demands (a library has no program
sources or sinks), writer conditions on objects no caller can locate, or
whose analysis -- or that of a function it calls -- took a number depending
on the library's load address as a fact (``relative_memory.IMAGE_BASE_TRACKING``).
"""

from __future__ import annotations

import hashlib
import json

from .function_summary import (
    FUNCTION_SUMMARY_VERSION, ExitSummary, FunctionSummary, SinkDemand, SummaryKind, SummaryRun,
)
from .span_geometry import ByteSpan, StorageObjectId, StorageObjectKind, StorageScopeId, StorageScopeKind

TEMPLATE_VERSION = 2   # 2: stack_values_out
# bumped on any change of what a summary means: normalization, alias
# reasoning, constant evaluation, effect derivation (not only its fields)
# 2: stack-mixed objects wild (docs 25.7); index addresses, index objects
# wild, the wrap seam bound (docs 25.8). 3: templates carry the label
# entry-values-do-not-address-the-new-frame when they rest on it (docs 25.9)
# -- older ones rest on it unlabelled. 4: nested same-object pointer values
# composed (a callee's "same as what I was passed" through the caller's own
# copies, docs 25.11). 5: a call not keeping memory keeps the bytes its
# external model's memory runs write at an exactly known place (docs 25.15).
# 6: jumps to the import thunk of a function that never returns end their
# path (``noreturn`` models, docs 25.16). 7: SUBPIECE boundary atoms, once-join
# atoms, the low bytes of ZEXT(x) at x's width are x (docs 25.17). 8:
# same-result accessor atoms under same-result-functions (docs 25.20/25.21).
# 9: proven state-keeping calls (docs 25.26); terminal jmp to an import thunk
# takes the model as a tail call. 10: a summarized call observes exactly the
# registers its complete effect reads; one that may let a stack-derived value
# out (or is not exported whole) is a stack escape (docs 25.27); once-join
# addresses at a LOAD read each candidate place; noreturn longjmp /
# __stack_chk_fail models; import-slot-bound models carry their label. 11:
# templates carry opaque-callees-leave-no-stack-addresses when they rest on it
# (docs 25.29) -- older ones rest on it unlabelled. 12: model entries declare
# callbacks / frees; templates carry registered-handlers-are-not-observed when
# derived over entries running registered handlers (docs 25.33)
ENGINE_SEMANTICS_VERSION = 12
KEY_PREFIX = "dll:"
_CROSSING_KINDS = ("call", "alias", "unknown", "uncertain")


class TemplateError(ValueError):
    """A malformed template (loading)."""


class TemplateRefused(ValueError):
    """A function that cannot be exported as a template (the reason).
    ``kind``: "semantic" (the analysis cannot express it), "budget" (a
    bound of the analysis was reached), "infrastructure" (it was not
    analyzed at all) or "transient" (a function of its closure ran out of a
    resource: ``NormalizationFailureReason.ANALYSIS_DEPTH`` / ``ANALYSIS_BUDGET``
    -- never stored, retried next run) -- how linking stores and retries it."""

    def __init__(self, message: str, kind: str = "semantic"):
        super().__init__(message)
        self.kind = kind


class Refusal(str):
    """A refusal reason as ``build_file`` returns it: the text, and its ``kind``."""

    kind = "semantic"

    def __new__(cls, text: str, kind: str = "semantic"):
        item = super().__new__(cls, text)
        item.kind = kind
        return item


# ---------------------------------------------------------------- export

def export_summary(analyzed, results, base_dependent=frozenset()) -> dict:
    """The serialized template of ``analyzed`` (an ``AnalyzedFunction``).
    ``results``: the whole run (callees are checked too); ``base_dependent``:
    function scope digests ``IMAGE_BASE_TRACKING`` recorded."""
    from .normalize import NormalizationFailureReason

    closure = _closure(analyzed, results)
    resource = (NormalizationFailureReason.ANALYSIS_DEPTH, NormalizationFailureReason.ANALYSIS_BUDGET,
                NormalizationFailureReason.ANALYSIS_RUN_BUDGET)
    for item in closure:
        # (its callers saw an opaque call: a resource failure is no verdict on the export)
        if getattr(item.normalized, "reason", None) in resource:
            raise TemplateRefused(f"{item.key}: {item.normalized.reason.value}", "transient")
    summary = analyzed.summary
    if summary is None:
        raise TemplateRefused("no summary")
    for item in closure:
        # a function of the closure the analysis refused (an unsupported shape):
        # the export is refused too, never shipped with that call left opaque
        if item is not analyzed and getattr(item.normalized, "reason", None) is not None:
            raise TemplateRefused(f"{item.key}: {item.normalized.reason.value}")
    for item in closure:
        if item.recursion_unresolved:
            raise TemplateRefused(f"{item.key}: recursion without a verified fixpoint", "budget")
        if item.test_only_inputs or any(label.startswith("test-only-boundary:") for label in item.declared.values()):
            raise TemplateRefused(f"{item.key}: TEST-ONLY inputs")
        if not item.image_tracked:
            raise TemplateRefused(f"{item.key}: not analyzed under ImageBaseTracking")
        if item.image_unproven:
            raise TemplateRefused(f"{item.key}: an absolute place in the image not proven to move with its "
                                  f"load address")
        normalized = item.normalized
        scope = getattr(getattr(normalized, "memory_ssa", None), "function_scope", None)
        if scope is not None and scope.digest in base_dependent:
            raise TemplateRefused(f"{item.key}: depends on the library's load address")
    if summary.tail_exits:
        raise TemplateRefused("tail exits not composed")
    if summary.sink_demands:
        raise TemplateRefused("sink demands")
    if any(run.origins for item in summary.exits for run in item.runs):
        raise TemplateRefused("source labels")
    if len({space for _, space in analyzed.anchors.values()}) > 1:
        raise TemplateRefused("objects addressed in several memory spaces")
    table = _ObjectTable(analyzed.anchors)
    out = {
        # runs ending in call-local temporaries say nothing to a caller (derive
        # skips them); temporaries as sources stay, as objects no caller locates
        "exits": [{"block": _key(item.block_key), "runs": [
            table.run(run) for run in item.runs if run.span.object_id.kind is not StorageObjectKind.FUNCTION_UNIQUE]}
            for item in summary.exits],
        "unknown_writers": [_key(key) for key in summary.unknown_writers],
        "writer_objects": [[_key(key), table.object(object_id)] for key, object_id in summary.writer_objects],
        "inner_calls": [[_key(key), [table.span(span) for span in kept], keeps, below]
                        for key, kept, keeps, below in summary.inner_calls],
        "register_deltas": [[list(slot), delta] for slot, delta in summary.register_deltas],
        "dead_exits": [_key(key) for key in summary.dead_exits],
        "writer_conditions": [table.pair(pair) for pair in summary.writer_conditions],
        "stack_values_out": summary.stack_values_out,
    }
    if any(table.local(side) for pair in summary.writer_conditions for side in pair):
        raise TemplateRefused("writer conditions on objects no caller can locate")
    out["objects"] = table.rows
    return out


def _closure(analyzed, results):
    seen, pending = {}, [analyzed]
    while pending:
        item = pending.pop()
        if item.key in seen:
            continue
        seen[item.key] = item
        pending.extend(results[callee] for callee in item.calls.values() if callee in results)
    return list(seen.values())


def _key(key: str) -> str:
    return KEY_PREFIX + key


def _crossing(label: str) -> str:
    kind, _, key = label.partition(":")
    if kind not in _CROSSING_KINDS or not key:
        raise TemplateRefused(f"unknown crossing {label!r}")
    return f"{kind}:{_key(key)}"


class _ObjectTable:
    def __init__(self, anchors) -> None:
        self.anchors = anchors
        self.rows: list = []
        self.index: dict = {}

    def object(self, object_id):
        if object_id.kind is StorageObjectKind.REGISTER_FILE:
            return "registers"
        if object_id in self.index:
            return self.index[object_id]
        self.index[object_id] = len(self.rows)
        self.rows.append(None)   # reserved: anchors may refer to objects (no cycles)
        row = {"local": True}
        anchor = self.anchors.get(object_id) if object_id.kind is StorageObjectKind.FUNCTION_RELATIVE else None
        if anchor is not None:
            span = anchor[0]
            if span.object_id.kind is StorageObjectKind.REGISTER_FILE:
                row = {"anchor": {"object": "registers", "start": span.start, "size": span.size}}
            elif span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE and span.object_id != object_id:
                # a pointer held in entry memory: locatable when its own object is
                # (one still being built -- a cycle -- is not)
                reference = self.object(span.object_id)
                if self.rows[reference] is not None and "anchor" in self.rows[reference]:
                    row = {"anchor": {"object": reference, "start": span.start, "size": span.size}}
        self.rows[self.index[object_id]] = row
        return self.index[object_id]

    def local(self, span) -> bool:
        reference = self.object(span.object_id)
        return reference != "registers" and "local" in self.rows[reference]

    def span(self, span):
        return {"object": self.object(span.object_id), "start": span.start, "size": span.size}

    def pair(self, pair):
        return [self.span(pair[0]), self.span(pair[1])]

    def run(self, run):
        value = run.value
        if value is not None and value != ("nonstack",):
            value = [value[0], self.span(value[1]), value[2]]
        elif value is not None:
            value = ["nonstack"]
        return {
            "span": self.span(run.span), "kind": run.kind.value,
            "writers": [_key(key) for key in run.writers],
            "sources": [self.span(span) for span in run.sources],
            "entry_readers": [_key(key) for key in run.entry_readers],
            "debts": list(run.debts), "crossed": [_crossing(label) for label in run.crossed],
            "conditions": [self.pair(pair) for pair in run.conditions], "value": value,
        }


# ---------------------------------------------------------------- import

def instantiate(template: dict, label: str, register_object, memory_space_id: int):
    """(FunctionSummary, anchors) of a template at an importer: the
    register file is ``register_object``; anchored objects are addressed in
    ``memory_space_id``. Object ids are fixed per template ``label`` (stable
    across re-derivations: alias-condition feedback compares them)."""
    _exact(template, ("exits", "unknown_writers", "writer_objects", "inner_calls", "register_deltas",
                      "dead_exits", "writer_conditions", "stack_values_out", "objects"), "template")
    if type(template["stack_values_out"]) is not bool:
        raise TemplateError("stack_values_out must be a bool")
    scope = StorageScopeId(StorageScopeKind.FUNCTION, hashlib.sha256(f"template:{label}".encode()).digest())
    rows = template["objects"]
    if type(rows) is not list:
        raise TemplateError("objects must be a list")
    objects = [StorageObjectId(StorageObjectKind.FUNCTION_RELATIVE, scope,
                               int.from_bytes(hashlib.sha256(f"{label}#{index}".encode()).digest(), "big"))
               for index in range(len(rows))]

    def object_of(reference):
        if reference == "registers":
            return register_object
        if type(reference) is not int or not 0 <= reference < len(objects):
            raise TemplateError(f"bad object reference {reference!r}")
        return objects[reference]

    def span(raw):
        _exact(raw, ("object", "start", "size"), "span")
        if type(raw["start"]) is not int or type(raw["size"]) is not int or raw["size"] <= 0 or raw["start"] < 0:
            raise TemplateError("span start/size")
        return ByteSpan(object_of(raw["object"]), raw["start"], raw["size"])

    anchors = {}
    for index, row in enumerate(rows):
        if row == {"local": True}:
            continue
        if type(row) is not dict or set(row) != {"anchor"}:
            raise TemplateError(f"object {index}: local or anchor")
        anchor = span(row["anchor"])
        if anchor.object_id == objects[index]:
            raise TemplateError(f"object {index} anchored on itself")
        anchors[objects[index]] = (anchor, memory_space_id)
    _acyclic(anchors)

    def pair(raw):
        if type(raw) is not list or len(raw) != 2:
            raise TemplateError("pair")
        return (span(raw[0]), span(raw[1]))

    def run(raw):
        _exact(raw, ("span", "kind", "writers", "sources", "entry_readers", "debts", "crossed", "conditions",
                     "value"), "run")
        value = raw["value"]
        if value == ["nonstack"]:
            value = ("nonstack",)
        elif value is not None:
            if type(value) is not list or len(value) != 3 or value[0] != "same" or type(value[2]) is not bool:
                raise TemplateError("run value")
            value = ("same", span(value[1]), value[2])
        return SummaryRun(span(raw["span"]), SummaryKind(raw["kind"]), (0,), _strings(raw["writers"]),
                          tuple(span(item) for item in raw["sources"]), _strings(raw["entry_readers"]),
                          _strings(raw["debts"]), _strings(raw["crossed"]), (),
                          tuple(pair(item) for item in raw["conditions"]), value)

    exits = []
    for item in template["exits"]:
        _exact(item, ("block", "runs"), "exit")
        exits.append(ExitSummary(_string(item["block"]), tuple(run(row) for row in item["runs"])))
    inner = []
    for row in template["inner_calls"]:
        if type(row) is not list or len(row) != 4 or type(row[2]) is not bool or type(row[3]) is not bool:
            raise TemplateError("inner call")
        inner.append((_string(row[0]), tuple(span(item) for item in row[1]), row[2], row[3]))
    deltas = []
    for row in template["register_deltas"]:
        if type(row) is not list or len(row) != 2 or type(row[1]) is not int or type(row[0]) is not list \
                or len(row[0]) != 2 or any(type(item) is not int for item in row[0]):
            raise TemplateError("register delta")
        deltas.append((tuple(row[0]), row[1]))
    writer_objects = []
    for row in template["writer_objects"]:
        if type(row) is not list or len(row) != 2:
            raise TemplateError("writer object")
        writer_objects.append((_string(row[0]), object_of(row[1])))
    summary = FunctionSummary(
        FUNCTION_SUMMARY_VERSION, tuple(exits), _strings(template["unknown_writers"]), tuple(writer_objects),
        (), tuple(inner), (), tuple(deltas), _strings(template["dead_exits"]),
        tuple(pair(item) for item in template["writer_conditions"]),
        template["stack_values_out"],
    )
    return summary, anchors


def _acyclic(anchors) -> None:
    for start in anchors:
        seen, current = set(), start
        while current in anchors:
            if current in seen:
                raise TemplateError("anchor cycle")
            seen.add(current)
            current = anchors[current][0].object_id


def _exact(raw, keys, what) -> None:
    if type(raw) is not dict or set(raw) != set(keys):
        raise TemplateError(f"{what} fields must be exactly {sorted(keys)}")


def _string(value) -> str:
    if type(value) is not str:
        raise TemplateError("expected a string")
    return value


def _strings(values) -> tuple:
    if type(values) is not list:
        raise TemplateError("expected a list of strings")
    return tuple(_string(item) for item in values)


# ---------------------------------------------------------------- the file and its checks

# x86-64 opcodes with a ModRM byte (one-byte map); the 0F map has one except
# the listed ones; 0F 38 / 0F 3A and VEX / EVEX always do
_MODRM_ONE_BYTE = frozenset(
    [op + low for op in range(0x00, 0x40, 8) for low in range(4)]
    + [0x62, 0x63, 0x69, 0x6B] + list(range(0x80, 0x90)) + [0xC0, 0xC1, 0xC6, 0xC7]
    + list(range(0xD0, 0xD4)) + list(range(0xD8, 0xE0)) + [0xF6, 0xF7, 0xFE, 0xFF])
_NO_MODRM_0F = frozenset([0x05, 0x06, 0x07, 0x08, 0x09, 0x0B, 0x0E, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x37,
                          0x77, 0xA0, 0xA1, 0xA2, 0xA8, 0xA9, 0xAA] + list(range(0x80, 0x90))
                         + list(range(0xC8, 0xD0)))
_LEGACY_PREFIXES = frozenset([0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67])


def _rip_displacement(code: bytes):
    """(True, disp32, its offset) for an x86-64 instruction addressing memory
    RIP-relative (ModRM mod 00, r/m 101), (False, None, None) for one that does
    not, None when the encoding is not understood (then nothing about its
    operands is proven): also an address-size override (67: the effective
    address is truncated to 32 bits) and XOP (8F with a map select)."""
    position = 0
    # legacy prefixes and REX in any order (a REX before a legacy prefix is
    # ignored; only the last one before the opcode counts -- decoding the
    # ModRM position does not depend on which)
    rex = 0   # the REX right before the opcode (an earlier one is ignored)
    while position < len(code) and (code[position] in _LEGACY_PREFIXES or 0x40 <= code[position] <= 0x4F):
        if code[position] == 0x67:
            return None
        rex = code[position] if 0x40 <= code[position] <= 0x4F else 0
        position += 1
    if position >= len(code):
        return None
    first = code[position]
    if first == 0x8F and position + 1 < len(code) and (code[position + 1] >> 3) & 7:
        return None   # XOP, not POP r/m
    if first in (0xC4, 0xC5, 0x62):   # VEX 3/2-byte, EVEX: prefix, opcode, ModRM
        position += {0xC4: 3, 0xC5: 2, 0x62: 4}[first] + 1
        has_modrm = True
    elif first == 0x0F:
        if position + 1 >= len(code):
            return None
        second = code[position + 1]
        if second in (0x38, 0x3A):
            position += 3
            has_modrm = True
        else:
            if 0x80 <= second <= 0x8F:
                return None   # jcc rel32
            position += 2
            has_modrm = second not in _NO_MODRM_0F
    else:
        if first in _RELATIVE_FLOW:
            return None
        position += 1
        has_modrm = first in _MODRM_ONE_BYTE
        if not has_modrm and first not in _NO_MODRM_KNOWN:
            return None
    if not has_modrm:
        return (False, None, None)
    if position >= len(code):
        return None
    modrm = code[position]
    if first == 0xC7 and modrm == 0xF8:
        return None   # xbegin rel32: a relative fallback address
    if first == 0x8D and not rex & 0x08 and modrm >> 6 == 0 and modrm & 7 == 5:
        return None   # lea r32, [rip+d]: the address truncated to 32 bits
    if modrm >> 6 == 0 and modrm & 7 == 5:
        if position + 5 > len(code):
            return None
        return (True, int.from_bytes(code[position + 1:position + 5], "little", signed=True), position + 1)
    return (False, None, None)


def _also_encoded(code: bytes, value: int, skip: int, skip_size: int) -> bool:
    """``value`` also fits another field of the instruction (1, 2, 4 or 8
    bytes, signed or unsigned), outside the proving field at ``skip``: the
    p-code constant may be that one (Astra: mov qword [rip+d], imm32)."""
    for size in (1, 2, 4, 8):
        for offset in range(len(code) - size + 1):
            if offset < skip + skip_size and skip < offset + size:
                continue
            data = code[offset:offset + size]
            if value % (1 << 64) in (int.from_bytes(data, "little", signed=True) % (1 << 64),
                                     int.from_bytes(data, "little")):
                return True
    return False


# one-byte opcodes known to have no ModRM (immediates, register forms, flow)
_NO_MODRM_KNOWN = frozenset(
    [op + low for op in range(0x00, 0x40, 8) for low in (4, 5)]
    + list(range(0x50, 0x60)) + [0x68, 0x6A] + list(range(0x70, 0x80)) + list(range(0x90, 0xA0))
    + list(range(0xA8, 0xC0)) + [0xC2, 0xC3, 0xC9, 0xCC, 0xE8, 0xE9, 0xEB, 0xF4, 0xF5, 0xF8, 0xF9, 0xFC, 0xFD]
    + list(range(0xA4, 0xA8)))


# relative flow (call / jmp / jcc rel): their constants are code addresses
# computed from the instruction's own address
_RELATIVE_FLOW = frozenset([0xE8, 0xE9, 0xEB, 0xE0, 0xE1, 0xE2, 0xE3] + list(range(0x70, 0x80)))


def image_provenance(read, relocations):
    """``relocates(instruction address, length, value)`` for
    ``ImageBaseTracking``: True -- the instruction proves ``value`` an image
    address: an 8-byte relocation entry inside it holds exactly ``value`` (an
    absolute address the loader rewrites), or it addresses memory RIP-relative
    (decoded: ModRM mod 00, r/m 101) and ``address + length + disp32 ==
    value`` -- and no other field of it encodes ``value``; False -- decoded,
    with neither a relocation entry nor a RIP-relative operand (its numbers
    are fixed; a ``ret``'s 8 also with an unknown length); None -- anything
    else: not understood, relative flow, 67, XOP, a relocated or RIP-relative
    instruction's other constants, an unknown length. ``read(address, size)``: the image's
    bytes as an unsigned little-endian int, or None; ``relocations``:
    (address, size) of the image's relocation entries."""
    import bisect

    starts = sorted(relocations)
    keys = [start for start, _ in starts]
    decoded: dict = {}

    def code_at(address: int, length):
        """The instruction's bytes (its first 15 when the length is unknown)."""
        for size in ((length,) if length is not None else range(15, 0, -1)):
            data = read(address, size)
            if data is not None:
                return data.to_bytes(size, "little")
        return None

    def relocates(address: int, length, value: int):
        window = 15 if length is None else length
        entries = [(start, size) for start, size in starts[bisect.bisect_left(keys, address):
                                                             bisect.bisect_left(keys, address + window)]
                   if start + size <= address + window]
        if (address, length) not in decoded:
            code = code_at(address, length)
            decoded[(address, length)] = (None if code is None else _rip_displacement(code), code)
        found, code = decoded[(address, length)]
        if found is None:
            return None
        rip, displacement, offset = found
        if not entries and not rip:
            return False   # understood: no relocated field, no RIP-relative operand
        if length is None:
            return None
        # exactly one proving field, and no other field of the instruction can
        # give the same constant; any other constant of such an instruction
        # (a truncated or extended address, an immediate) proves nothing
        for start, size in entries:
            if size == 8 and read(start, size) == value:
                return None if _also_encoded(code, value, start - address, size) else True
        if rip and address + length + displacement == value:
            return None if _also_encoded(code, value, offset, 4) else True
        return None

    return relocates


def pcodeop_digest(models) -> str:
    """Of the p-code op models of a run (no-effect ops and traps shape summaries)."""
    rows = sorted(
        [model.file_id, model.version, sorted(map(list, model.languages)), sorted(model.no_effect.items()),
         sorted((index, sorted(operands)) for index, operands in (model.traps or {}).items())]
        for model in (models or ())
    )
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def refusal(model_file, entry, *, external_models, pcodeop_models, private_frame_above,
            language=None) -> str | None:
    """Why a template may not be applied in this run, or None: another engine
    version or language version (register offsets are read in this program's
    register file); other analysis parameters or p-code op models; a model
    file it was derived with missing or changed, replaced by an override, or
    joined by another file matching the same names (the lookup it took may
    resolve otherwise, or fail)."""
    if entry.refusal is not None:
        return entry.refusal
    recorded_language = model_file.source_field("language")
    if language is None or recorded_language != {"id": language[0], "major": language[1], "minor": language[2]}:
        return f"derived for language {recorded_language}, this program is {language}"
    parameters = dict(model_file.source_field("parameters") or {})
    recorded_home = parameters.pop("private_frame_above", 0)
    if parameters:
        return f"derived with unknown parameters {parameters}"
    # the home space matters only to a template that rests on it (reported
    # per use, with entry-values-do-not-address-the-new-frame): then this run
    # must take the same extent; one that never used it applies anywhere
    if "win64-home-space-callee-private" in entry.inherited and recorded_home != private_frame_above:
        return f"derived with private_frame_above={recorded_home}, this run private_frame_above={private_frame_above}"
    if model_file.source_field("pcodeops") != pcodeop_digest(pcodeop_models):
        return "derived with other p-code op models"
    files = {item.file_id: item for item in external_models.files}
    recorded = {row["file"]: row["sha256"] for row in model_file.source_field("models")}
    for file_id, digest in recorded.items():
        if file_id not in files or files[file_id].digest != digest:
            return f"model file {file_id} differs from the one it was derived with"
    # what each entry can match (as ``ExternalModels.lookup``): a file naming
    # its libraries matches (library, original name) only; any other file
    # matches by name, whatever the import's library, with leading
    # underscores stripped -- plain names are compared that way on both sides
    def plain_form(names):
        return {name.lstrip("_") for name in names}

    def matches(model_file, item):
        if model_file.libraries:
            return {("qualified", library, name) for library in model_file.libraries
                    for name in item.original_names}, set()
        return set(), {*item.names, *item.original_names}

    qualified, plain = set(), set()
    for file_id in recorded:
        for item in files[file_id].entries:
            keys, names = matches(files[file_id], item)
            qualified |= keys
            plain |= names
    every_name = plain_form(plain | {key[2] for key in qualified})
    plain = plain_form(plain)
    for item in external_models.files:
        if item.file_id in recorded:
            continue
        if any(target.split("/", 1)[0] in recorded for target in item.overrides):
            return f"model file {item.file_id} overrides a model it was derived with"
        for other in item.entries:
            keys, names = matches(item, other)
            other_names = plain_form(names | {key[2] for key in keys})
            if keys & qualified or plain_form(names) & every_name or other_names & plain:
                return f"model file {item.file_id} also models a function a model it was derived with names"
    return None


def build_file(results, exports, *, file_id, version, library, external_models, pcodeop_models,
               private_frame_above, base_dependent, readonly_image=None, traps=False, notes=None,
               producer=None):
    """(file dict, {export name: refusal reason}) for ``exports`` -- (function
    key, name, original names) -- of one ``analyze_units`` run of ``library``
    under ``relative_memory.ImageBaseTracking`` (``base_dependent``: its
    ``found``) with read-only image folding off. ``producer``: recorded only
    (e.g. the engine revision; never compared)."""
    from .summary_engine import run_assumptions

    if readonly_image is not None:
        raise TemplateRefused("derive with read-only image folding off (image bytes may hold relocated addresses)")
    if base_dependent is None:
        raise TemplateRefused("derive under ImageBaseTracking")
    entries, refused = [], {}
    for key, name, original_names in exports:
        analyzed = results.get(key)
        try:
            if analyzed is None:
                raise TemplateRefused("not analyzed", "infrastructure")
            if any(label.startswith("derived-model:") for item in _closure(analyzed, results)
                   for label in item.declared.values()):
                raise TemplateRefused("derived from another derived model")
            entries.append({"name": name, "original_names": list(original_names),
                            "summary": export_summary(analyzed, results, base_dependent)})
        except TemplateRefused as error:
            refused[name] = Refusal(str(error), error.kind)
    first = next(iter(results.values()))
    evidence = first.unit.scopes.program.evidence
    namespace = evidence.translation_namespace
    source = {
        "kind": "derived", "library": library, "sha256": evidence.executable_sha256.hex(),
        "image_base": evidence.image_base.byte_offset,
        "language": {"id": namespace.language_id, "major": namespace.major_version, "minor": namespace.minor_version},
        "engine": {"summary_version": FUNCTION_SUMMARY_VERSION, "template_version": TEMPLATE_VERSION,
                   "semantics_version": ENGINE_SEMANTICS_VERSION},
        "parameters": {"private_frame_above": private_frame_above},
        "models": [{"file": item.file_id, "sha256": item.digest} for item in external_models.files]
        if external_models is not None else [],
        "pcodeops": pcodeop_digest(pcodeop_models),
        "assumptions": list(run_assumptions(results, home_space=private_frame_above, traps=traps,
                                            pcodeop_models=pcodeop_models)),
    }
    if producer:
        source["producer"] = dict(producer)
    raw = {"format_version": 1, "kind": "summary", "id": file_id, "version": version,
           "language_id": namespace.language_id, "abi_tag": _abi_tag(external_models),
           "libraries": [library], "source": source, "entries": entries}
    if notes:
        raw["notes"] = notes
    return raw, refused


def _abi_tag(external_models) -> str:
    tags = {item.abi_tag for item in (external_models.files if external_models is not None else ())}
    if len(tags) != 1:
        raise TemplateRefused("the run's model files name no single ABI")
    return tags.pop()


__all__ = ("ENGINE_SEMANTICS_VERSION", "KEY_PREFIX", "TEMPLATE_VERSION", "TemplateError", "TemplateRefused",
           "build_file", "export_summary", "instantiate", "pcodeop_digest", "refusal")
