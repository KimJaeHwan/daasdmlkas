"""Declared effect models of external functions, in function-summary form.

A model file (JSON, ``format_version`` 1) describes library functions the
Bundle does not contain (CRT imports, DLL exports) for one ``language_id``
and ``abi_tag``. The engine assumes no calling convention: the file states
physical register slices, like ``boundary_rules``. Each applied model is a
named assumption (``external-model:<file id>/<entry>@v<version>``) reported
in ``EngineRun.assumptions``.

File::

    {"format_version": 1, "kind": "declared", "id": "crt-win64", "version": 1,
     "language_id": "x86:LE:64:default", "abi_tag": "win64",
     "stack_pointer": [32, 8], "stack_delta": 8,
     "preserved": [[24, 8], ...],          # registers every entry leaves unchanged
     "entries": [
       {"name": "memcpy", "aliases": ["memmove"],
        "registers": [{"write": [0, 8], "from": [[8, 8]]}],
        "memory": [{"write": {"base": [8, 8], "disp": 0, "size": {"reg": [64, 8]}},
                    "from": [[16, 8], [8, 8], [64, 8]],
                    "loads": [{"base": [16, 8], "disp": 0, "size": {"reg": [64, 8]}}]}],
        "other_memory": "preserved"}]}

Semantics, all sound by construction: registers neither written nor listed in
``preserved`` (nor the stack pointer) are UNKNOWN after the call; a register
write depends on its ``from`` registers and ``loads`` (memory at entry, as a
memory row's ``loads``) (``"fresh": true``: the written value
is the address of a block the call allocates -- not an address of any memory
existing before it, the stack included; ``"same_object_as": slice``: the
written value addresses the same object as that register did at the call --
realloc, under the assumption that the old pointer is not used afterwards);
``observes`` (optional, per entry): the registers the function may use as a
memory address or keep -- a stack address held only in other registers does
not escape at the call (default: every register); a memory write covers exactly
``size`` bytes at (entry value of ``base``) + ``disp`` and depends on its
``from`` registers and ``loads`` (``"value": "unknown"`` instead of ``from``
/ ``loads``: exactly those bytes get a value the model does not state -- the
caller reads them with debt, the rest of memory is as ``other_memory`` says).
A size given by a register is used only
when the caller proves that register constant at the call (``constants``);
otherwise the write is dropped and no memory is kept. ``other_memory``:
"preserved" (only the listed writes; the callee's own frame below its entry
stack pointer is always treated as clobbered) or "clobbered" (everything but
the listed writes: those are the bytes' values when the call returns, and the
caller keeps them where it places them exactly -- ``normalize._kept_call_memory``).
``noreturn`` (optional, per entry): the function never returns to its caller
(no register or memory rows; ``observes`` declared): a call of it, or a jump
to its import thunk, ends the paths through it.
``same_result`` (optional, per entry; docs 25.20, named assumption
same-result-functions, off by default): ``{"result": slice, "inputs":
[slices], "reads": [{base, disp, size}]}`` -- an accessor:
within one activation of the caller, two calls with equal ``inputs`` values,
the same read-slot address and a read-slot value of the same class, at the
same accessor state, return the same bits in ``result`` (one of the entry's
register writes), failure included. One read slot. ``"write_back": true``: the call may rewrite
the slot with a value of the same class (a normalizing cache: an unresolved
handle becomes the resolved pointer) -- the entry then has one memory row
writing exactly the slot and loading it (its value rests on the old one).
``result_separate_from_reads`` (optional, with ``same_result``; named
assumption accessor-result-separate, off by default): ``{"extent": N}`` --
the bytes [result, result + N) never overlap the read slot of any call of
the entry in the caller's activation.
A ``fresh`` row may state the block's size (docs 25.79): ``"extent"``: bytes,
``{"reg": slice}`` or ``{"product": [slice, slice]}`` (calloc) -- read at the
call when the caller proves the registers constant (``~ext`` rows); the
calling function then keeps accesses inside [result, result + size) apart
from the stack, but only where a null test of the result dominates them --
unless the entry declares ``"never_null": {"rests_on": "<this file id>:<id>"}``
(it never returns null on a normal return; a declared assumption, switchable).
``result_nonstack`` (optional, per entry; docs 25.75): ``{"result": slice,
"extent": N, "rests_on": "<this file id>:<id>"}`` -- every byte [result,
result + N) of every result is in no thread's stack, null included: in the
calling function an object addressed by exactly that result, every access of
which lies inside the N bytes, is kept apart from the stack (its private frame
and pushes included, ``may_alias`` nonstack windows). The claim rests on the
declared assumption ``rests_on`` -- reported where a window is made,
switched off by its label (the entry still applies, without the window).
Only in the function making the call: summaries export no extent.
``omits_private_writes`` (optional, per entry; named assumption
accessor-private-state, off by default): the entry leaves out writes to
library-private state (locks, tracking tables, a resolver's caches) -- applied
only under that assumption.
``preserves_accessor_state`` (optional, per entry): ``["<file id>/<entry>",
...]`` or ``["*"]`` -- a call of this entry leaves those accessors' hidden
state unchanged (its transitive effects, callbacks included); every other
call changes it.
``callbacks`` / ``callbacks_evidence`` / ``frees`` (per entry; docs 25.33 --
every model file of this repository declares them, a test checks it): what
user code the function runs and what it frees, audited from its documented
behaviour. ``callbacks``: ``"none"`` or ``{"registered": [mechanism, ...],
"invokes": [register slice, ...]}`` -- ``registered``: handlers registered
earlier that the function may run (a new handler, a signal handler, an
allocator object's virtual functions, ...): the entry rests on the named
assumption registered-handlers-are-not-observed (reported per use; off: the
entry is not applied); ``invokes``: code pointers it calls (not applied --
the call stays opaque -- until callbacks are composed). ``callbacks_evidence``:
the audit's documentation reference, date and reviewer. ``frees``:
``"none"`` or the register slices whose pointed-to block the function frees
or may move. An entry declaring none of the three is loaded but never
applied (``ModelEntry.refusal``), so models from other directories keep
loading.

Matching an import: a file listing ``libraries`` (e.g. a C++ engine DLL)
matches only imports of one of those libraries whose original (mangled) name
-- or, for an import with no separate original (a C export), its name -- is
in an entry's ``original_names``; a file without ``libraries`` (the C
runtime, whose import library varies) matches by short name, never a C++
(``?``-mangled) import. Two entries matching one import is an error unless one
file lists the other entry in ``overrides`` (``"<file id>/<entry name>"``).

Provenance (optional ``source``; default ``{"kind": "hand"}``): ``hand``
(written by a person), ``derived`` (the engine's analysis of the real library
code, e.g. ``{"kind": "derived", "library": ..., "sha256": ...}``) or
``external`` (produced elsewhere, ``{"kind": "external", "tool": ...,
"version": ...}``). Other keys are kept as recorded provenance. ``assumptions``
(list of labels; also per entry) are the assumptions the model itself rests on: each use
reports them with the model's own label -- ``external-model:`` (hand),
``derived-model:`` or ``supplied-model:`` + ``<file id>/<entry>@v<version>``.
A label is a registry name (``assumptions``), an engine provenance label
(``assumptions.PROVENANCE_PREFIXES``), or ``<file id>:<id>`` -- an assumption a
model file declares (top level ``"declares_assumptions": [{"id", "statement",
"fails_when"}]``; what only that library's models rest on). Every
``<file id>:<id>`` must resolve in the run's catalog (``assumption_catalog``:
the run's model files and binding model files together) -- a declared file
referring to an undeclared one is an error, a derived file's entries are
refused. Rows add the registry labels they rest on themselves: a ``fresh``
row allocator-results-are-fresh and no-use-after-free, a ``frees`` row
no-use-after-free, a ``same_object_as`` row all three with
no-use-of-old-pointer-after-realloc. File ids are ``[a-z0-9]`` words joined by
``-``.
Extra model directories: ``model_paths`` (``--model-dir``,
``TDO_V2_MODEL_DIRS``).

Derived summaries (``"kind": "summary"``, ``summary_templates``): entries
carry a serialized function summary (``"summary"``) instead of registers /
memory rows, matched like any entry; ``source`` is derived and records the
derivation (library sha256, image base, engine versions, parameters, the
model files and p-code op models it used, every assumption of that run).
A template whose engine versions differ is loaded but never applied
(``ModelEntry.refusal``); the run-dependent checks are ``interprocedural``'s.

``"internal": true`` (per entry, files with ``libraries`` only): the entry is
also valid for callers inside its own library, so analyzing that library
(``interprocedural.analyze_units(own_library=...)``) may cut there -- the
function's body is not analyzed and calls to it take the model, under the
named assumption library-internal-model-cuts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from pathlib import Path

from .function_summary import FUNCTION_SUMMARY_VERSION, ExitSummary, FunctionSummary, SummaryKind, SummaryRun
from .span_geometry import StorageObjectId, StorageObjectKind, StorageScopeId, StorageScopeKind
from .span_geometry import ByteSpan

FORMAT_VERSION = 1
MAX_MODEL_EXTENT = 1 << 16   # larger proven extents are not materialized byte-exact


class ModelError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Access:
    base: tuple[int, int]            # register (offset, size) holding the address at entry
    disp: int
    size: int | tuple[int, int]      # bytes, or a register (offset, size) holding the byte count


@dataclass(frozen=True, slots=True)
class ModelEntry:
    file_id: str
    version: int
    name: str
    names: tuple[str, ...]
    registers: tuple[tuple[tuple[int, int], tuple[tuple[int, int], ...]], ...]
    memory: tuple[tuple[Access, tuple[tuple[int, int], ...], tuple[Access, ...]], ...]
    keeps_other_memory: bool
    fresh: tuple[tuple[int, int], ...] = ()   # register writes holding a new block's address
    observes: tuple[tuple[int, int], ...] | None = None   # None: every register
    original_names: tuple[str, ...] = ()
    same_object: tuple[tuple[tuple[int, int], tuple[int, int]], ...] = ()
    source_kind: str = "hand"
    inherited: tuple[str, ...] = ()   # assumption labels the model rests on (``source.assumptions``)
    # usable as a cut inside its own library (``interprocedural`` ``own_library``):
    # its claims hold for callers inside that library too
    internal: bool = False
    unknown_memory: tuple[Access, ...] = ()   # memory written with an unstated value
    template: dict | None = None   # a derived summary (``summary_templates``) instead of rows
    refusal: str | None = None     # why a template is never applied (engine version mismatch)
    # never returns to its caller (e.g. abort): the paths through a call of it,
    # or a jump to it (``interprocedural._noreturn_jumps``), end there
    noreturn: bool = False
    # an accessor (docs 25.20): (result slice, input slices, the read slot's
    # Access, write_back) -- applied under same-result-functions only
    same_result: tuple | None = None
    # result_nonstack: (result slice, extent in bytes, the declared label it
    # rests on), or None
    nonstack_result: tuple | None = None
    # fresh rows' sizes: (write slice, bytes | ("reg", slice) | ("product",
    # slice, slice)); never_null: the declared label it rests on, or None
    fresh_extents: tuple = ()
    never_null: str | None = None
    # model ids ("<file>/<entry>", or "*") whose accessor state a call of this
    # entry leaves unchanged
    preserves_accessor_state: tuple[str, ...] = ()
    # (register write, the memory it also depends on: Access loads)
    register_loads: tuple = ()
    # result_separate_from_reads extent (bytes), or None
    separate_extent: int | None = None
    # callbacks / frees (docs 25.33): registered handler mechanisms, code
    # pointer registers it calls, register slices whose block it frees;
    # None: not declared
    callbacks_registered: tuple[str, ...] = ()
    callbacks_invokes: tuple[tuple[int, int], ...] = ()
    frees: tuple[tuple[int, int], ...] | None = None

    @property
    def model_id(self) -> str:
        return f"{self.file_id}/{self.name}"

    identity: str = ""   # derived: the first 12 hex digits of the library's sha256

    @property
    def label(self) -> str:
        suffix = f"#{self.identity}" if self.identity else ""
        return f"{_LABEL_PREFIX[self.source_kind]}:{self.file_id}/{self.name}@v{self.version}{suffix}"

    @property
    def labels(self) -> tuple[str, ...]:
        """Every assumption one use of this model reports."""
        return (self.label, *self.inherited)

    def extent_registers(self) -> tuple[tuple[int, int], ...]:
        found = set()
        for write, _, loads in self.memory:
            for access in (write, *loads):
                if type(access.size) is tuple:
                    found.add(access.size)
        for _, loads in self.register_loads:
            for access in loads:
                if type(access.size) is tuple:
                    found.add(access.size)
        for access in self.unknown_memory:
            if type(access.size) is tuple:
                found.add(access.size)
        for _, size in self.fresh_extents:
            if type(size) is tuple:
                found.update(size[1:])
        return tuple(sorted(found))


@dataclass(frozen=True, slots=True)
class ModelFile:
    file_id: str
    version: int
    language_id: str
    abi_tag: str
    stack_pointer: tuple[int, int]
    stack_delta: int
    preserved: tuple[tuple[int, int], ...]
    entries: tuple[ModelEntry, ...]
    libraries: tuple[str, ...] = ()   # upper case; empty: matched by short name
    source: tuple = (("kind", "hand"),)   # provenance, as sorted (key, value) pairs
    overrides: tuple[str, ...] = ()       # "<file id>/<entry name>" this file replaces
    digest: str = ""                      # sha256 of the file's bytes (template dependencies)
    # (label "<file id>:<id>", statement, fails_when) of each declared assumption
    declares: tuple[tuple[str, str, str], ...] = ()

    def source_field(self, key):
        return next((json.loads(value) for name, value in self.source if name == key), None)


SOURCE_KINDS = ("hand", "derived", "external")
_LABEL_PREFIX = {"hand": "external-model", "derived": "derived-model", "external": "supplied-model"}


_WORD = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*\Z")


def _file_id(raw, path) -> str:
    from .assumptions import PROVENANCE_PREFIXES

    file_id = raw.get("id")
    if type(file_id) is not str or not _WORD.match(file_id) \
            or any(file_id == prefix[:-1] for prefix in PROVENANCE_PREFIXES):
        raise ModelError(f"{path}: id must be [a-z0-9] words joined by '-' (not a provenance prefix)")
    return file_id


def _label_problem(label) -> str | None:
    """None for a registry name, a provenance label or ``<file id>:<id>``."""
    from .assumptions import PROVENANCE_PREFIXES, REGISTRY

    if label in {item.name for item in REGISTRY} or label.startswith(PROVENANCE_PREFIXES):
        return None
    namespace, separator, name = label.partition(":")
    if separator and _WORD.match(namespace) and _WORD.match(name):
        return None
    return f"{label!r} is neither a registered assumption, a provenance label nor <file id>:<id>"


def _assumption_labels(assumptions, path, what) -> tuple[str, ...]:
    if type(assumptions) is not list or any(type(item) is not str or not item for item in assumptions):
        raise ModelError(f"{path}: {what} must be a list of labels")
    for item in assumptions:
        problem = _label_problem(item)
        if problem is not None:
            raise ModelError(f"{path}: {what} {problem}")
    return tuple(assumptions)


def _declarations(raw, file_id, path) -> tuple:
    items = raw.get("declares_assumptions", [])
    if type(items) is not list or any(
            type(item) is not dict or set(item) != {"id", "statement", "fails_when"}
            or any(type(value) is not str or not value for value in item.values()) or not _WORD.match(item["id"])
            for item in items):
        raise ModelError(f"{path}: declares_assumptions lists {{id, statement, fails_when}} ([a-z0-9-] ids)")
    ids = [item["id"] for item in items]
    if len(set(ids)) != len(ids):
        raise ModelError(f"{path}: an assumption is declared twice")
    return tuple((f"{file_id}:{item['id']}", item["statement"], item["fails_when"]) for item in items)


def _row_labels(fresh, frees, same_object) -> tuple[str, ...]:
    """The registry assumptions an entry's own rows rest on."""
    labels = []
    if fresh or same_object:   # (realloc(NULL) is a fresh block)
        labels.append("allocator-results-are-fresh")
    if fresh or frees or same_object:
        labels.append("no-use-after-free")
    if same_object:
        labels.append("no-use-of-old-pointer-after-realloc")
    return tuple(labels)


def unresolved_labels(labels, catalog) -> list:
    """The ``<file id>:<id>`` labels of ``labels`` the run's catalog lacks."""
    from .assumptions import PROVENANCE_PREFIXES

    return [label for label in labels if ":" in label and label not in catalog
            and not label.startswith(PROVENANCE_PREFIXES)]


def assumption_catalog(*model_sets) -> dict:
    """``{label: (file id, statement, fails_when)}`` of every assumption the
    run's model files declare (``ExternalModels`` -- the run's models, each
    binding's), checked together: one file id names one file (the same file
    loaded twice is one), and every ``<file id>:<id>`` a declared entry rests
    on is declared (a derived entry resting on an undeclared one is refused
    instead, ``summary_templates.refusal``)."""
    files: dict = {}
    for models in model_sets:
        for item in models.files:
            seen = files.get(item.file_id)
            if seen is not None and seen.digest != item.digest:
                raise ModelError(f"two model files have the id {item.file_id}")
            files.setdefault(item.file_id, item)   # (the first: the run's own copy)
    catalog = {label: (item.file_id, statement, fails_when)
               for item in files.values() for label, statement, fails_when in item.declares}
    for models in model_sets:
        for item in models.files:
            for entry in item.entries:
                missing = [] if entry.template is not None else unresolved_labels(entry.inherited, catalog)
                if missing:
                    raise ModelError(f"model {entry.model_id} rests on {', '.join(missing)}, which no loaded model "
                                     "file declares")
    return catalog


def _source(raw, path, *, recorded=False):
    """``recorded``: a derived file's assumptions are the record of its
    derivation run -- labels this engine does not know refuse its entries
    (``_load_summary_file``), they are no error."""
    source = raw.get("source", {"kind": "hand"})
    if type(source) is not dict or source.get("kind") not in SOURCE_KINDS:
        raise ModelError(f"{path}: source must be an object with kind in {SOURCE_KINDS}")
    if recorded:
        if type(source.get("assumptions")) is not list or any(
                type(item) is not str or not item for item in source["assumptions"]):
            raise ModelError(f"{path}: source.assumptions must be a list of labels")
    else:
        _assumption_labels(source.get("assumptions", []), path, "source.assumptions")
    if source["kind"] == "derived" and not (type(source.get("library")) is str and type(source.get("sha256")) is str
                                            and len(source["sha256"]) == 64):
        raise ModelError(f"{path}: a derived model names its library and the library file's sha256")
    return source


def _slice(value, what) -> tuple[int, int]:
    if type(value) is not list or len(value) != 2 or any(type(item) is not int or item < 0 for item in value) \
            or value[1] == 0:
        raise ModelError(f"model {what} must be a register slice [offset, size]")
    return value[0], value[1]


def _access(raw, what) -> Access:
    if type(raw) is not dict or set(raw) != {"base", "disp", "size"}:
        raise ModelError(f"model {what} must have base, disp, size")
    size = raw["size"]
    if type(size) is int and size > 0:
        extent = size
    elif type(size) is dict and set(size) == {"reg"}:
        extent = _slice(size["reg"], f"{what} size register")
    else:
        raise ModelError(f"model {what} size must be bytes or {{'reg': slice}}")
    if type(raw["disp"]) is not int:
        raise ModelError(f"model {what} disp must be an int")
    return Access(_slice(raw["base"], f"{what} base"), raw["disp"], extent)


def _callbacks(item, path):
    """(registered mechanisms, invoked code pointer slices, freed slices | None,
    refusal | None) of a declared entry's callbacks / callbacks_evidence /
    frees (docs 25.33)."""
    keys = {"callbacks", "callbacks_evidence", "frees"} & set(item)
    if not keys:
        return (), (), None, "callbacks / frees not declared (callbacks, callbacks_evidence, frees)"
    if len(keys) != 3:
        raise ModelError(f"{path}: {item['name']}: callbacks, callbacks_evidence and frees go together")
    evidence = item["callbacks_evidence"]
    if type(evidence) is not str or not evidence.strip():
        raise ModelError(f"{path}: {item['name']}: callbacks_evidence names the audit (reference, date, reviewer)")
    callbacks = item["callbacks"]
    registered, invokes = (), ()
    if callbacks != "none":
        if type(callbacks) is not dict or not callbacks or set(callbacks) - {"registered", "invokes"}:
            raise ModelError(f"{path}: {item['name']}: callbacks is \"none\" or {{registered, invokes}}")
        mechanisms = callbacks.get("registered", [])
        if type(mechanisms) is not list or any(type(name) is not str or not name for name in mechanisms):
            raise ModelError(f"{path}: {item['name']}: callbacks.registered lists mechanism names")
        registered = tuple(mechanisms)
        pointers = callbacks.get("invokes", [])
        if type(pointers) is not list:
            raise ModelError(f"{path}: {item['name']}: callbacks.invokes lists register slices")
        invokes = tuple(_slice(s, "invoked code pointer") for s in pointers)
        if not registered and not invokes:
            raise ModelError(f"{path}: {item['name']}: empty callbacks: use \"none\"")
    frees = item["frees"]
    if frees == "none":
        frees = ()
    elif type(frees) is list and frees:
        frees = tuple(_slice(s, "freed pointer") for s in frees)
    else:
        raise ModelError(f"{path}: {item['name']}: frees is \"none\" or register slices")
    refusal = "invokes callbacks (not composed yet)" if invokes else None
    return registered, invokes, frees, refusal


def load_model_file(path: str | Path) -> ModelFile:
    import hashlib

    data = Path(path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    raw = json.loads(data.decode("utf-8"))
    if type(raw) is dict and raw.get("kind") == "summary":
        return replace(_load_summary_file(raw, path), digest=digest)
    keys = {"format_version", "kind", "id", "version", "language_id", "abi_tag", "stack_pointer",
            "stack_delta", "preserved", "entries"}
    if type(raw) is not dict or set(raw) - {"notes", "libraries", "source", "overrides",
                                            "declares_assumptions"} != keys:
        raise ModelError(f"{path}: model file fields must be exactly {sorted(keys)}")
    if raw["format_version"] != FORMAT_VERSION or raw["kind"] != "declared":
        raise ModelError(f"{path}: unsupported model format or kind")
    file_id = _file_id(raw, path)
    declares = _declarations(raw, file_id, path)
    source = _source(raw, path)
    overrides = raw.get("overrides", [])
    if type(overrides) is not list or any(type(item) is not str or "/" not in item for item in overrides):
        raise ModelError(f"{path}: overrides must be a list of \"<file id>/<entry name>\"")
    if any(item.split("/", 1)[0] == raw["id"] for item in overrides):
        raise ModelError(f"{path}: a file cannot override its own entries")
    entries = []
    for item in raw["entries"]:
        allowed = {"name", "aliases", "registers", "memory", "other_memory", "notes", "observes",
                   "original_names", "internal", "assumptions", "noreturn", "same_result", "result_nonstack", "never_null",
                   "preserves_accessor_state", "result_separate_from_reads", "omits_private_writes",
                   "callbacks", "callbacks_evidence", "frees"}
        if type(item) is not dict or not {"name", "registers", "memory", "other_memory"} <= set(item) <= allowed:
            raise ModelError(f"{path}: entry fields must be {sorted(allowed)}")
        if item["other_memory"] not in ("preserved", "clobbered"):
            raise ModelError(f"{path}: other_memory must be preserved or clobbered")
        if type(item.get("internal", False)) is not bool:
            raise ModelError(f"{path}: internal must be true or false")
        if type(item.get("omits_private_writes", False)) is not bool:
            raise ModelError(f"{path}: omits_private_writes must be true or false")
        if type(item.get("noreturn", False)) is not bool:
            raise ModelError(f"{path}: noreturn must be true or false")
        if item.get("noreturn") and (item["registers"] or item["memory"] or "observes" not in item):
            # what it observes is declared, not implied by never returning
            raise ModelError(f"{path}: a noreturn entry has no register or memory rows and declares observes")
        for row in item["registers"]:
            if type(row) is not dict or not {"write"} <= set(row) \
                    <= {"write", "from", "loads", "fresh", "same_object_as", "extent"} \
                    or type(row.get("fresh", False)) is not bool \
                    or (row.get("fresh") and "same_object_as" in row) or ("extent" in row and not row.get("fresh")):
                raise ModelError(f"{path}: register rows are {{write, from, loads, fresh | same_object_as}}")
        registers = tuple(
            (_slice(row["write"], "register write"), tuple(_slice(s, "register read") for s in row.get("from", ())))
            for row in item["registers"]
        )
        fresh = tuple(_slice(row["write"], "register write") for row in item["registers"] if row.get("fresh"))
        fresh_extents = tuple((_slice(row["write"], "register write"), _fresh_extent(row["extent"], path))
                              for row in item["registers"] if row.get("fresh") and "extent" in row)
        never_null = item.get("never_null")
        if never_null is not None and (
                type(never_null) is not dict or set(never_null) != {"rests_on"} or not fresh
                or never_null["rests_on"] not in {label for label, _, _ in declares}
                or not never_null["rests_on"].startswith(f"{file_id}:")):
            raise ModelError(f"{path}: {item['name']}: never_null is {{rests_on: <this file id>:<id>}} of an "
                             "entry with a fresh row")
        register_loads = tuple(
            (_slice(row["write"], "register write"), tuple(_access(load, "register load") for load in row["loads"]))
            for row in item["registers"] if row.get("loads"))
        if len({write for write, _ in registers}) != len(registers):
            raise ModelError(f"{path}: {item['name']}: a register is written by one row")
        same_object = tuple(
            (_slice(row["write"], "register write"), _slice(row["same_object_as"], "same object register"))
            for row in item["registers"] if "same_object_as" in row
        )
        for row in item["memory"]:
            if type(row) is not dict or "write" not in row or (
                    set(row) - {"write", "from", "loads"} if "value" not in row
                    else set(row) != {"write", "value"} or row["value"] != "unknown"):
                raise ModelError(f"{path}: memory rows are {{write, from, loads}} or {{write, value: unknown}}")
        memory = tuple(
            (_access(row["write"], "memory write"),
             tuple(_slice(s, "memory write input") for s in row.get("from", ())),
             tuple(_access(load, "memory load") for load in row.get("loads", ())))
            for row in item["memory"] if "value" not in row
        )
        unknown_memory = tuple(_access(row["write"], "memory write") for row in item["memory"] if "value" in row)
        same_result = _same_result(item, registers, fresh, same_object, register_loads, path)
        nonstack_result = _nonstack_result(item, registers, fresh, same_object, file_id, declares, path)
        separate = item.get("result_separate_from_reads")
        if separate is not None and (same_result is None or type(separate) is not dict or set(separate) != {"extent"}
                                     or type(separate["extent"]) is not int
                                     or not 0 < separate["extent"] <= MAX_MODEL_EXTENT):
            raise ModelError(f"{path}: {item['name']}: result_separate_from_reads is {{extent: bytes}} "
                             "of a same_result entry")
        preserving = item.get("preserves_accessor_state", [])
        if type(preserving) is not list or any(
                type(name) is not str or (name != "*" and name.count("/") != 1) for name in preserving):
            raise ModelError(f"{path}: {item['name']}: preserves_accessor_state lists \"<file id>/<entry>\" or \"*\"")
        registered, invokes, frees, refusal = _callbacks(item, path)
        names = (item["name"], *item.get("aliases", ()))
        entries.append(ModelEntry(raw["id"], raw["version"], item["name"], tuple(names), registers, memory,
                                  item["other_memory"] == "preserved", fresh,
                                  None if "observes" not in item
                                  else tuple(_slice(s, "observed register") for s in item["observes"]),
                                  tuple(item.get("original_names", ())), same_object,
                                  source_kind=source["kind"], inherited=(*source.get("assumptions", ()), *_assumption_labels(
                                      item.get("assumptions", []), path, f"{item['name']}: assumptions"),
                                      *(("accessor-private-state",) if item.get("omits_private_writes") else ()),
                                      *(("registered-handlers-are-not-observed",) if registered else ()),
                                      *_row_labels(fresh, frees, same_object)),
                                  identity=source["sha256"][:12] if source["kind"] == "derived" else "",
                                  internal=item.get("internal", False), unknown_memory=unknown_memory,
                                  noreturn=item.get("noreturn", False), same_result=same_result,
                                  nonstack_result=nonstack_result, fresh_extents=fresh_extents,
                                  never_null=None if never_null is None else never_null["rests_on"],
                                  preserves_accessor_state=tuple(preserving), register_loads=register_loads,
                                  separate_extent=None if separate is None else separate["extent"],
                                  callbacks_registered=registered, callbacks_invokes=invokes, frees=frees,
                                  refusal=refusal))
    libraries = tuple(str(item).upper() for item in raw.get("libraries", ()))
    if libraries and any(not entry.original_names for entry in entries):
        raise ModelError(f"{path}: a file with libraries matches by original_names only")
    return ModelFile(raw["id"], raw["version"], raw["language_id"], raw["abi_tag"],
                     _slice(raw["stack_pointer"], "stack pointer"), raw["stack_delta"],
                     tuple(_slice(s, "preserved") for s in raw["preserved"]), tuple(entries), libraries,
                     tuple(sorted((key, json.dumps(value, sort_keys=True)) for key, value in source.items())),
                     tuple(overrides), digest, declares)


def _overlaps(write, read) -> bool:
    """Two accesses on one base register may share a byte (a register-sized
    write may)."""
    if type(write.size) is not int:
        return True
    return write.disp < read.disp + read.size and read.disp < write.disp + write.size


def _same_result(item, registers, fresh, same_object, register_loads, path):
    """An entry's ``same_result`` (see the docstring), or None. The result's
    register row states every input in its ``from`` and the read slot in its
    ``loads``: the result's ordinary dependencies, with the switch off too."""
    raw = item.get("same_result")
    if raw is None:
        return None
    where = f"{path}: {item['name']}: same_result"
    if type(raw) is not dict or not {"result", "inputs", "reads"} <= set(raw) \
            <= {"result", "inputs", "reads", "write_back"}:
        raise ModelError(f"{where} has result, inputs, reads (write_back); a result off the stack is "
                         "result_nonstack, with its extent")
    if type(raw.get("write_back", False)) is not bool:
        raise ModelError(f"{where}: write_back must be true or false")
    if item.get("noreturn"):
        raise ModelError(f"{where}: a noreturn entry returns nothing")
    result = _slice(raw["result"], "same_result result")
    if result not in [write for write, _ in registers] or result in fresh             or result in [write for write, _ in same_object]:
        raise ModelError(f"{where}: result must be one of the entry's plain register writes")
    if type(raw["inputs"]) is not list:
        raise ModelError(f"{where}: inputs must be a list of register slices")
    inputs = tuple(_slice(s, "same_result input") for s in raw["inputs"])
    if type(raw["reads"]) is not list or len(raw["reads"]) != 1:
        raise ModelError(f"{where}: exactly one read slot")
    read = _access(raw["reads"][0], "same_result read")
    if type(read.size) is not int:
        raise ModelError(f"{where}: the read slot's size is bytes")
    sources = dict(registers)[result]
    if any(item not in sources for item in inputs) or read not in dict(register_loads).get(result, ()):
        raise ModelError(f"{where}: the result's register row reads every input (from) and the slot (loads)")
    rows = [row for row in item["memory"] if "value" not in row and _access(row["write"], "memory write") == read]
    if raw.get("write_back", False) and (
            len(rows) != 1 or read not in [_access(load, "memory load") for load in rows[0].get("loads", ())]
            or any(item not in [_slice(s, "memory write input") for s in rows[0].get("from", ())]
                   for item in inputs)):
        raise ModelError(f"{where}: write_back: one memory row writes exactly the slot, loads it and reads "
                         "every input (from)")
    for row in item["memory"]:
        write = _access(row["write"], "memory write")
        if write.base == read.base and _overlaps(write, read) and not (
                raw.get("write_back") and "value" not in row and write == read):
            raise ModelError(f"{where}: another memory row writes the slot's bytes "
                             "(only the one write-back row may)")
    return result, inputs, read, raw.get("write_back", False)


def _fresh_extent(raw, path):
    """A fresh row's ``extent``: bytes, ("reg", slice) or ("product", slice, slice)."""
    if type(raw) is int and raw > 0:
        return raw
    if type(raw) is dict and set(raw) == {"reg"}:
        return ("reg", _slice(raw["reg"], "fresh extent register"))
    if type(raw) is dict and set(raw) == {"product"} and type(raw["product"]) is list and len(raw["product"]) == 2:
        return ("product", *(_slice(item, "fresh extent factor") for item in raw["product"]))
    raise ModelError(f"{path}: a fresh extent is bytes, {{reg: slice}} or {{product: [slice, slice]}}")


def fresh_extent_bytes(size, constants) -> int | None:
    """A fresh block's size at a call (``constants``: register slice -> the
    value the caller proves): None when a register is not proven, the size is
    zero, or a product overflows -- unsigned at the factors' width (the
    narrowest slice), refused from half of it (2^63 for 8-byte slices)."""
    if type(size) is int:
        return size
    factors = [constants.get(item) for item in size[1:]]
    width_bits = 8 * min(item[1] for item in size[1:])
    if any(type(value) is not int or not 0 <= value < 1 << width_bits for value in factors):
        return None
    product = 1
    for value in factors:
        product *= value
    return product if 0 < product < 1 << (width_bits - 1) else None


def _nonstack_result(item, registers, fresh, same_object, file_id, declares, path):
    """An entry's ``result_nonstack`` (see the docstring), or None."""
    raw = item.get("result_nonstack")
    if raw is None:
        return None
    where = f"{path}: {item['name']}: result_nonstack"
    if type(raw) is not dict or set(raw) != {"result", "extent", "rests_on"} or type(raw["extent"]) is not int \
            or not 0 < raw["extent"] <= MAX_MODEL_EXTENT:
        raise ModelError(f"{where} is {{result, extent: bytes, rests_on}}")
    result = _slice(raw["result"], "result_nonstack result")
    if result not in [write for write, _ in registers] or result in fresh \
            or result in [write for write, _ in same_object]:
        raise ModelError(f"{where}: result must be one of the entry's plain register writes")
    if raw["rests_on"] not in {label for label, _, _ in declares} or not raw["rests_on"].startswith(f"{file_id}:"):
        raise ModelError(f"{where}: rests_on names an assumption this file declares (<file id>:<id>)")
    return result, raw["extent"], raw["rests_on"]


DERIVED_SOURCE_KEYS = {"kind", "library", "sha256", "image_base", "language", "engine", "parameters",
                       "models", "pcodeops", "assumptions"}


def _load_summary_file(raw, path) -> ModelFile:
    """A ``"kind": "summary"`` file (derived templates, see the docstring)."""
    from .function_summary import FUNCTION_SUMMARY_VERSION
    from .summary_templates import ENGINE_SEMANTICS_VERSION, TEMPLATE_VERSION

    keys = {"format_version", "kind", "id", "version", "language_id", "abi_tag", "libraries", "source", "entries"}
    if set(raw) - {"notes", "overrides"} != keys:
        raise ModelError(f"{path}: summary file fields must be exactly {sorted(keys)}")
    if raw["format_version"] != FORMAT_VERSION:
        raise ModelError(f"{path}: unsupported model format")
    _file_id(raw, path)
    source = _source(raw, path, recorded=True)
    if source["kind"] != "derived" or set(source) - {"producer", "declarations"} != DERIVED_SOURCE_KEYS:
        raise ModelError(f"{path}: a summary file's source is derived with {sorted(DERIVED_SOURCE_KEYS)}")
    declarations = source.get("declarations", {})
    if type(declarations) is not dict or any(
            label not in source["assumptions"] or type(stated) is not list or len(stated) != 2
            or any(type(text) is not str for text in stated) for label, stated in declarations.items()):
        raise ModelError(f"{path}: source.declarations maps assumption labels to [statement, fails_when]")
    engine = source["engine"]
    expected = {"summary_version": FUNCTION_SUMMARY_VERSION, "template_version": TEMPLATE_VERSION,
                "semantics_version": ENGINE_SEMANTICS_VERSION}
    if type(engine) is not dict or set(engine) != set(expected):
        raise ModelError(f"{path}: source.engine must give {sorted(expected)}")
    refusal = None if engine == expected else f"derived by engine {engine}, this engine is {expected}"
    unknown = [label for label in source["assumptions"] if _label_problem(label) is not None]
    if refusal is None and unknown:
        refusal = f"derived resting on {', '.join(unknown)}, which this engine does not know"
    models = source["models"]
    if type(models) is not list or any(type(row) is not dict or set(row) != {"file", "sha256"} for row in models):
        raise ModelError(f"{path}: source.models must list {{file, sha256}}")
    if type(source["parameters"]) is not dict or type(source["pcodeops"]) is not str:
        raise ModelError(f"{path}: source.parameters / pcodeops")
    language = source["language"]
    if type(language) is not dict or set(language) != {"id", "major", "minor"} \
            or language["id"] != raw["language_id"]:
        raise ModelError(f"{path}: source.language must be {{id, major, minor}} of the file's language_id")
    libraries = raw["libraries"]
    if type(libraries) is not list or not libraries or any(type(item) is not str for item in libraries):
        raise ModelError(f"{path}: a summary file names its libraries")
    entries = []
    for item in raw["entries"]:
        if type(item) is not dict or not {"name", "original_names", "summary"} <= set(item) \
                <= {"name", "original_names", "summary", "notes"}:
            raise ModelError(f"{path}: summary entries are {{name, original_names, summary, notes}}")
        if type(item["original_names"]) is not list or not item["original_names"]:
            raise ModelError(f"{path}: {item['name']}: original_names")
        if type(item["summary"]) is not dict:
            raise ModelError(f"{path}: {item['name']}: summary")
        entries.append(ModelEntry(raw["id"], raw["version"], item["name"], (item["name"],), (), (), False,
                                  original_names=tuple(item["original_names"]), source_kind="derived",
                                  inherited=(*source["assumptions"], "derived-model-runtime-matches"),
                                  identity=source["sha256"][:12], template=item["summary"], refusal=refusal))
    overrides = raw.get("overrides", [])
    if type(overrides) is not list or any(type(item) is not str or "/" not in item for item in overrides):
        raise ModelError(f"{path}: overrides must be a list of \"<file id>/<entry name>\"")
    return ModelFile(raw["id"], raw["version"], raw["language_id"], raw["abi_tag"], (0, 0), 0, (), tuple(entries),
                     tuple(item.upper() for item in libraries),
                     tuple(sorted((key, json.dumps(value, sort_keys=True)) for key, value in source.items())),
                     tuple(overrides))


@dataclass(frozen=True, slots=True)
class ExternalModels:
    """Model entries for imported symbols (see the module docstring)."""

    files: tuple[ModelFile, ...]

    def lookup(self, symbol) -> tuple[ModelFile, ModelEntry] | None:
        """``symbol``: an ``image_info.ImportedSymbol`` (or a short name)."""
        if type(symbol) is str:
            name, library, original = symbol, None, None
        else:
            name, library, original = symbol.name, symbol.library, symbol.original_name
        found = []
        for model_file in self.files:
            for entry in model_file.entries:
                if model_file.libraries:
                    # (library, the name as imported): an import with no separate
                    # original (a C export) is imported under its name -- as
                    # ``linking`` keys the calls it derives for
                    imported = original if original is not None else name
                    hit = library is not None and library.upper() in model_file.libraries \
                        and imported in entry.original_names
                else:
                    hit = not (original or "").startswith("?") and bool({name, name.lstrip("_")} & set(entry.names))
                if hit:
                    found.append((model_file, entry))
        # an entry another matching file explicitly replaces drops out
        replaced = {item for model_file, _ in found for item in model_file.overrides}
        matched = len(found)
        found = [(model_file, entry) for model_file, entry in found if entry.model_id not in replaced]
        if matched and not found:
            raise ModelError(f"import {library}!{original or name}: overrides remove every matching model")
        if len(found) > 1:
            raise ModelError(
                f"import {library}!{original or name} matches several models "
                f"({', '.join(entry.label for _, entry in found)}): list one in the other's overrides")
        if found:
            return found[0]
        return None


def model_paths(builtin: Path, extra_dirs=()) -> list[Path]:
    """Model files: ``builtin`` (the repository's models/external), then each
    extra directory (``--model-dir``), then ``TDO_V2_MODEL_DIRS`` (os.pathsep
    separated) -- every ``*.json`` in each, sorted. Which model applies to an
    import never depends on this order (``ExternalModels.lookup``)."""
    import os

    dirs = [Path(builtin), *(Path(item) for item in extra_dirs)]
    dirs += [Path(item) for item in os.environ.get("TDO_V2_MODEL_DIRS", "").split(os.pathsep) if item]
    found, seen = [], set()
    for directory in dirs:
        if not directory.is_dir():
            raise ModelError(f"model directory not found: {directory}")
        for path in sorted(directory.glob("*.json")):
            if path.resolve() not in seen:   # a directory given twice is read once
                seen.add(path.resolve())
                found.append(path)
    return found


def load_external_models(paths, language_id: str, abi_tag: str) -> ExternalModels:
    """The model files for one language and ABI, validated together: file ids
    are unique, every override names an existing entry of another file, and
    overrides form no cycle between files."""
    files = [load_model_file(path) for path in paths]
    return validated_models(item for item in files if item.language_id == language_id and item.abi_tag == abi_tag)


def with_model_files(models: ExternalModels, paths) -> ExternalModels:
    """``models`` and the model files at ``paths`` (of the same language and
    ABI, else an error), validated together as ``load_external_models``."""
    files = [load_model_file(path) for path in paths]
    tags = {(item.language_id, item.abi_tag) for item in models.files}
    for item in files:
        if tags and (item.language_id, item.abi_tag) not in tags:
            raise ModelError(f"model file {item.file_id}: {item.language_id} / {item.abi_tag} is not this run's")
    return validated_models((*models.files, *files))


def validated_models(files) -> ExternalModels:
    files = list(files)
    ids = [item.file_id for item in files]
    if len(set(ids)) != len(ids):
        raise ModelError(f"model file ids are not unique: {sorted(i for i in set(ids) if ids.count(i) > 1)}")
    entries = {entry.model_id: item.file_id for item in files for entry in item.entries}
    edges = {}
    for item in files:
        for target in item.overrides:
            if target not in entries:
                raise ModelError(f"model file {item.file_id} overrides {target}, which no loaded file has")
            edges.setdefault(item.file_id, set()).add(entries[target])

    def cyclic(start):
        pending, seen = list(edges.get(start, ())), set()
        while pending:
            current = pending.pop()
            if current == start:
                return True
            if current not in seen:
                seen.add(current)
                pending.extend(edges.get(current, ()))
        return False

    for file_id in edges:
        if cyclic(file_id):
            raise ModelError(f"model overrides form a cycle through {file_id}")
    accessors = {entry.model_id for item in files for entry in item.entries if entry.same_result is not None}
    for item in files:
        for entry in item.entries:
            for name in entry.preserves_accessor_state:
                if name != "*" and name not in accessors:
                    raise ModelError(f"model {entry.model_id}: preserves_accessor_state names {name}, "
                                     "which is no loaded entry with same_result")
    return ExternalModels(tuple(files))


@dataclass(frozen=True, slots=True)
class ModelBinding:
    """A binding file (``"kind": "binding"``, docs 25.20 F): model entries for
    functions of one exact binary that export no name, by entry RVA::

        {"format_version": 1, "kind": "binding", "id": "...",
         "executable_sha256": "<64 hex>", "language_id": "...", "abi_tag": "...",
         "models": ["<model file, relative to this file>", ...],
         "bindings": [{"rva": "0x4e10", "model": "<file id>/<entry>", "symbol": "..."}]}

    Applied only to the binary of that SHA-256 (``interprocedural._bound_cuts``):
    the function at image base + RVA is cut and its callers take the model, each
    use labelled ``bound-model:<id>@<rva>``. ``symbol`` is a note for people,
    never a locator. The model files load only through bindings (never matched
    by import name)."""

    binding_id: str
    executable_sha256: str
    language_id: str
    abi_tag: str
    models: ExternalModels
    rows: tuple[tuple[int, str, str | None], ...]   # (rva, model id, symbol)
    digest: str

    def entry(self, model_id: str) -> tuple[ModelFile, ModelEntry]:
        for model_file in self.models.files:
            for entry in model_file.entries:
                if entry.model_id == model_id:
                    return model_file, entry
        raise ModelError(f"binding {self.binding_id}: no model {model_id}")


def load_binding_file(path: str | Path) -> ModelBinding:
    import hashlib

    path = Path(path)
    data = path.read_bytes()
    raw = json.loads(data.decode("utf-8"))
    keys = {"format_version", "kind", "id", "executable_sha256", "language_id", "abi_tag", "models", "bindings"}
    if type(raw) is not dict or set(raw) - {"notes"} != keys or raw["kind"] != "binding" \
            or raw["format_version"] != FORMAT_VERSION:
        raise ModelError(f"{path}: binding file fields must be exactly {sorted(keys)} (kind binding)")
    sha = raw["executable_sha256"]
    if type(sha) is not str or len(sha) != 64 or any(char not in "0123456789abcdef" for char in sha):
        raise ModelError(f"{path}: executable_sha256 is 64 lower-case hex digits")
    if type(raw["models"]) is not list or not raw["models"]:
        raise ModelError(f"{path}: models lists model files")
    files = [load_model_file(path.parent / item) for item in raw["models"]]
    if any((item.language_id, item.abi_tag) != (raw["language_id"], raw["abi_tag"]) for item in files):
        raise ModelError(f"{path}: every model file is of the binding's language and ABI")
    if any(entry.template is not None for item in files for entry in item.entries):
        # a derived summary has run-dependent compatibility checks a cut skips
        raise ModelError(f"{path}: bindings take declared models only, not derived summaries")
    models = validated_models(files)
    rows, seen = [], set()
    known = {entry.model_id for item in files for entry in item.entries}
    for row in raw["bindings"]:
        if type(row) is not dict or not {"rva", "model"} <= set(row) <= {"rva", "model", "symbol"}:
            raise ModelError(f"{path}: bindings are {{rva, model, symbol}}")
        rva = int(row["rva"], 16) if type(row["rva"]) is str else row["rva"]
        if type(rva) is not int or rva <= 0 or rva in seen or row["model"] not in known:
            raise ModelError(f"{path}: binding {row}: a new positive rva and a model of the listed files")
        seen.add(rva)
        rows.append((rva, row["model"], row.get("symbol")))
    return ModelBinding(raw["id"], sha, raw["language_id"], raw["abi_tag"], models, tuple(rows),
                        hashlib.sha256(data).hexdigest())


def model_summary(model_file: ModelFile, entry: ModelEntry, register_object, register_limit: int,
                  register_space_id: int, memory_space_id: int, constants: dict):
    """(FunctionSummary, anchors, complete) of one model at one call site.
    ``constants``: register (offset, size) -> value the caller proves at the
    call (extents). ``complete`` is False when a write was dropped for an
    unknown extent (then no memory may be kept)."""
    scope = StorageScopeId(StorageScopeKind.FUNCTION, _digest(f"external:{entry.label}"))
    anchors: dict = {}

    def register(slice_):
        return ByteSpan(register_object, slice_[0], slice_[1])

    def extent(access):
        if type(access.size) is int:
            return access.size
        value = constants.get(access.size)
        return value if value is not None and 0 < value <= MAX_MODEL_EXTENT else None

    def memory_span(access, size):
        base = register(access.base)
        object_id = StorageObjectId(StorageObjectKind.FUNCTION_RELATIVE, scope,
                                    int.from_bytes(_digest(f"anchor:{access.base}"), "big"))
        anchors[object_id] = (base, memory_space_id)
        return ByteSpan(object_id, (1 << (8 * base.size)) + access.disp, size)

    runs = []
    written = set()
    complete = True
    register_loads = dict(entry.register_loads)
    for target, sources in entry.registers:
        span = register(target)
        written.update(range(span.start, span.end))
        loads = register_loads.get(target, ())
        sizes = [extent(load) for load in loads]
        if None in sizes:
            # a load of unknown extent: the value may come from anywhere there
            runs.append(SummaryRun(span, SummaryKind.UNKNOWN, (0,), ("model",), (), (), (), ("call:model",)))
            continue
        runs.append(_computed(span, tuple(register(s) for s in sources)
                              + tuple(memory_span(load, n) for load, n in zip(loads, sizes))))
    for write, sources, loads in entry.memory:
        size = extent(write)
        load_sizes = [extent(load) for load in loads]
        if size is None or None in load_sizes:
            complete = False  # unknown extent: the write may land anywhere in that object
            continue
        inputs = [register(s) for s in sources] + [memory_span(load, n) for load, n in zip(loads, load_sizes)]
        runs.append(_computed(memory_span(write, size), tuple(inputs)))
    for write in entry.unknown_memory:
        size = extent(write)
        if size is None:
            complete = False
            continue
        runs.append(SummaryRun(memory_span(write, size), SummaryKind.UNKNOWN, (0,), ("model",),
                               (), (), (), ("call:model",)))
    kept = {offset for slice_ in model_file.preserved for offset in range(slice_[0], slice_[0] + slice_[1])}
    sp = range(model_file.stack_pointer[0], sum(model_file.stack_pointer))
    unknown = [offset for offset in range(register_limit)
               if offset not in kept and offset not in written and offset not in sp]
    for start, size in _ranges(unknown):
        runs.append(SummaryRun(ByteSpan(register_object, start, size), SummaryKind.UNKNOWN, (0,), ("model",),
                               (), (), (), ("call:model",)))
    summary = FunctionSummary(
        FUNCTION_SUMMARY_VERSION, (ExitSummary("model", tuple(runs)),), (), (),
        register_deltas=((model_file.stack_pointer, model_file.stack_delta),),
    )
    return summary, anchors, complete


def model_effect(derive, model_file, entry, *args):
    """The ProvenCallEffect of a model at a call site: ``derive`` is
    ``derive_proven_call_effect`` bound to the call site except for the
    summary and anchors (see ``interprocedural``)."""
    summary, anchors, complete = model_summary(model_file, entry, *args)
    effect = derive(summary, anchors)
    if effect is None:
        return None
    return replace(
        effect,
        # A free/realloc declaration is a lifetime boundary, not evidence
        # that every old byte remains readable. Without an extent/lifetime
        # proof it cannot license whole-memory preservation, even when a
        # same-object result relation is declared. The existing call-clobber
        # graph retains the old writers as candidates WITH debt. Explicit
        # final memory runs, register effects and model labels stay intact.
        preserves_memory=effect.preserves_memory and complete and entry.keeps_other_memory and not entry.frees,
        memory_runs_final=True,    # the listed writes; other_memory is about the rest
        noreturn=entry.noreturn,   # the path behind the call is cut (``function_summary._dead_region``)
        clobbers_below=True,       # a library function has its own frame
        # it may keep any pointer it receives, unless the model lists what it observes
        observes_registers=entry.observes is None or bool(entry.observes),
        observed_registers=None if entry.observes is None
        else tuple(ByteSpan(args[0], start, size) for start, size in entry.observes),
        escapes_stack=False,       # declared: what it observes is what it may keep
        fresh_registers=tuple(ByteSpan(args[0], start, size) for start, size in entry.fresh),
        nonstack_results=() if entry.nonstack_result is None else (
            (ByteSpan(args[0], *entry.nonstack_result[0]), *entry.nonstack_result[1:]),),
        fresh_extents=tuple(
            (ByteSpan(args[0], *write), size, entry.never_null) for write, size in
            ((write, fresh_extent_bytes(size, args[-1])) for write, size in entry.fresh_extents) if size),
        same_object_registers=tuple(
            (ByteSpan(args[0], *write), ByteSpan(args[0], *source)) for write, source in entry.same_object
        ),
    )


def _computed(span, sources):
    return SummaryRun(span, SummaryKind.COMPUTED, (0,), ("model",),
                      tuple(sorted(set(sources), key=lambda item: item.canonical_key)), (), (), ())


def _ranges(offsets):
    start = previous = None
    for offset in sorted(offsets):
        if previous is not None and offset == previous + 1:
            previous = offset
            continue
        if start is not None:
            yield start, previous + 1 - start
        start = previous = offset
    if start is not None:
        yield start, previous + 1 - start


def _digest(text: str) -> bytes:
    import hashlib
    return hashlib.sha256(text.encode()).digest()


__all__ = ("Access", "ExternalModels", "ModelBinding", "ModelEntry", "ModelError", "ModelFile",
           "load_binding_file", "load_external_models", "load_model_file", "model_effect", "model_summary")
