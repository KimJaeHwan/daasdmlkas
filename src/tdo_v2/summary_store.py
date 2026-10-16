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
[slices], "reads": [{base, disp, size}], "nonstack": bool}`` -- an accessor:
within one activation of the caller, two calls with equal ``inputs`` values,
the same read-slot address and a read-slot value of the same class, at the
same accessor state, return the same bits in ``result`` (one of the entry's
register writes), failure included; ``nonstack``: the result addresses no
thread's stack. One read slot. ``"write_back": true``: the call may rewrite
the slot with a value of the same class (a normalizing cache: an unresolved
handle becomes the resolved pointer) -- the entry then has one memory row
writing exactly the slot and loading it (its value rests on the old one).
``result_separate_from_reads`` (optional, with ``same_result``; named
assumption accessor-result-separate, off by default): ``{"extent": N}`` --
the bytes [result, result + N) never overlap the read slot of any call of
the entry in the caller's activation.
``omits_private_writes`` (optional, per entry; named assumption
accessor-private-state, off by default): the entry leaves out writes to
library-private state (locks, tracking tables, a resolver's caches) -- applied
only under that assumption.
``preserves_accessor_state`` (optional, per entry): ``["<file id>/<entry>",
...]`` or ``["*"]`` -- a call of this entry leaves those accessors' hidden
state unchanged (its transitive effects, callbacks included); every other
call changes it.

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
    # Access, nonstack) -- applied under same-result-functions only
    same_result: tuple | None = None
    # model ids ("<file>/<entry>", or "*") whose accessor state a call of this
    # entry leaves unchanged
    preserves_accessor_state: tuple[str, ...] = ()
    # (register write, the memory it also depends on: Access loads)
    register_loads: tuple = ()
    # result_separate_from_reads extent (bytes), or None
    separate_extent: int | None = None

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

    def source_field(self, key):
        return next((json.loads(value) for name, value in self.source if name == key), None)


SOURCE_KINDS = ("hand", "derived", "external")
_LABEL_PREFIX = {"hand": "external-model", "derived": "derived-model", "external": "supplied-model"}


def _assumption_labels(assumptions, path, what) -> tuple[str, ...]:
    """Registered assumption names or namespaced labels (``<namespace>:<name>``)."""
    if type(assumptions) is not list or any(type(item) is not str or not item for item in assumptions):
        raise ModelError(f"{path}: {what} must be a list of labels")
    from .assumptions import REGISTRY

    registered = {item.name for item in REGISTRY}
    for item in assumptions:
        if item not in registered and ":" not in item:
            raise ModelError(f"{path}: {what} {item!r} is neither a registered assumption "
                             "nor a namespaced label (<namespace>:<name>)")
    return tuple(assumptions)


def _source(raw, path):
    source = raw.get("source", {"kind": "hand"})
    if type(source) is not dict or source.get("kind") not in SOURCE_KINDS:
        raise ModelError(f"{path}: source must be an object with kind in {SOURCE_KINDS}")
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


def load_model_file(path: str | Path) -> ModelFile:
    import hashlib

    data = Path(path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    raw = json.loads(data.decode("utf-8"))
    if type(raw) is dict and raw.get("kind") == "summary":
        return replace(_load_summary_file(raw, path), digest=digest)
    keys = {"format_version", "kind", "id", "version", "language_id", "abi_tag", "stack_pointer",
            "stack_delta", "preserved", "entries"}
    if type(raw) is not dict or set(raw) - {"notes", "libraries", "source", "overrides"} != keys:
        raise ModelError(f"{path}: model file fields must be exactly {sorted(keys)}")
    if raw["format_version"] != FORMAT_VERSION or raw["kind"] != "declared":
        raise ModelError(f"{path}: unsupported model format or kind")
    source = _source(raw, path)
    overrides = raw.get("overrides", [])
    if type(overrides) is not list or any(type(item) is not str or "/" not in item for item in overrides):
        raise ModelError(f"{path}: overrides must be a list of \"<file id>/<entry name>\"")
    if any(item.split("/", 1)[0] == raw["id"] for item in overrides):
        raise ModelError(f"{path}: a file cannot override its own entries")
    entries = []
    for item in raw["entries"]:
        allowed = {"name", "aliases", "registers", "memory", "other_memory", "notes", "observes",
                   "original_names", "internal", "assumptions", "noreturn", "same_result",
                   "preserves_accessor_state", "result_separate_from_reads", "omits_private_writes"}
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
            if type(row) is not dict or not {"write"} <= set(row) <= {"write", "from", "loads", "fresh", "same_object_as"} \
                    or type(row.get("fresh", False)) is not bool \
                    or (row.get("fresh") and "same_object_as" in row):
                raise ModelError(f"{path}: register rows are {{write, from, loads, fresh | same_object_as}}")
        registers = tuple(
            (_slice(row["write"], "register write"), tuple(_slice(s, "register read") for s in row.get("from", ())))
            for row in item["registers"]
        )
        fresh = tuple(_slice(row["write"], "register write") for row in item["registers"] if row.get("fresh"))
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
        names = (item["name"], *item.get("aliases", ()))
        entries.append(ModelEntry(raw["id"], raw["version"], item["name"], tuple(names), registers, memory,
                                  item["other_memory"] == "preserved", fresh,
                                  None if "observes" not in item
                                  else tuple(_slice(s, "observed register") for s in item["observes"]),
                                  tuple(item.get("original_names", ())), same_object,
                                  source_kind=source["kind"], inherited=(*source.get("assumptions", ()), *_assumption_labels(
                                      item.get("assumptions", []), path, f"{item['name']}: assumptions"),
                                      *(("accessor-private-state",) if item.get("omits_private_writes") else ())),
                                  identity=source["sha256"][:12] if source["kind"] == "derived" else "",
                                  internal=item.get("internal", False), unknown_memory=unknown_memory,
                                  noreturn=item.get("noreturn", False), same_result=same_result,
                                  preserves_accessor_state=tuple(preserving), register_loads=register_loads,
                                  separate_extent=None if separate is None else separate["extent"]))
    libraries = tuple(str(item).upper() for item in raw.get("libraries", ()))
    if libraries and any(not entry.original_names for entry in entries):
        raise ModelError(f"{path}: a file with libraries matches by original_names only")
    return ModelFile(raw["id"], raw["version"], raw["language_id"], raw["abi_tag"],
                     _slice(raw["stack_pointer"], "stack pointer"), raw["stack_delta"],
                     tuple(_slice(s, "preserved") for s in raw["preserved"]), tuple(entries), libraries,
                     tuple(sorted((key, json.dumps(value, sort_keys=True)) for key, value in source.items())),
                     tuple(overrides), digest)


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
    if type(raw) is not dict or not {"result", "inputs", "reads"} <= set(raw)             <= {"result", "inputs", "reads", "write_back", "nonstack"}:
        raise ModelError(f"{where} has result, inputs, reads (write_back, nonstack)")
    if type(raw.get("write_back", False)) is not bool:
        raise ModelError(f"{where}: write_back must be true or false")
    if type(raw.get("nonstack", False)) is not bool:
        raise ModelError(f"{where}: nonstack must be true or false")
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
    return result, inputs, read, raw.get("nonstack", False), raw.get("write_back", False)


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
    source = _source(raw, path)
    if source["kind"] != "derived" or set(source) - {"producer"} != DERIVED_SOURCE_KEYS:
        raise ModelError(f"{path}: a summary file's source is derived with {sorted(DERIVED_SOURCE_KEYS)}")
    engine = source["engine"]
    expected = {"summary_version": FUNCTION_SUMMARY_VERSION, "template_version": TEMPLATE_VERSION,
                "semantics_version": ENGINE_SEMANTICS_VERSION}
    if type(engine) is not dict or set(engine) != set(expected):
        raise ModelError(f"{path}: source.engine must give {sorted(expected)}")
    refusal = None if engine == expected else f"derived by engine {engine}, this engine is {expected}"
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
                                  inherited=(*_assumption_labels(source["assumptions"], path,
                                                                 "source.assumptions"),
                                             "derived-model-runtime-matches"),
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
        preserves_memory=effect.preserves_memory and complete and entry.keeps_other_memory,
        memory_runs_final=True,    # the listed writes; other_memory is about the rest
        noreturn=entry.noreturn,   # the path behind the call is cut (``function_summary._dead_region``)
        clobbers_below=True,       # a library function has its own frame
        # it may keep any pointer it receives, unless the model lists what it observes
        observes_registers=entry.observes is None or bool(entry.observes),
        observed_registers=None if entry.observes is None
        else tuple(ByteSpan(args[0], start, size) for start, size in entry.observes),
        escapes_stack=False,       # declared: what it observes is what it may keep
        fresh_registers=tuple(ByteSpan(args[0], start, size) for start, size in entry.fresh),
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
