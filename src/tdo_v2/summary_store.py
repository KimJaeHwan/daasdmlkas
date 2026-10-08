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
write depends on its ``from`` registers; a memory write covers exactly
``size`` bytes at (entry value of ``base``) + ``disp`` and depends on its
``from`` registers and ``loads``. A size given by a register is used only
when the caller proves that register constant at the call (``constants``);
otherwise the write is dropped and no memory is kept. ``other_memory``:
"preserved" (only the listed writes; the callee's own frame below its entry
stack pointer is always treated as clobbered) or "clobbered".
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

    @property
    def label(self) -> str:
        return f"external-model:{self.file_id}/{self.name}@v{self.version}"

    def extent_registers(self) -> tuple[tuple[int, int], ...]:
        found = set()
        for write, _, loads in self.memory:
            for access in (write, *loads):
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
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    keys = {"format_version", "kind", "id", "version", "language_id", "abi_tag", "stack_pointer",
            "stack_delta", "preserved", "entries"}
    if type(raw) is not dict or set(raw) - {"notes"} != keys:
        raise ModelError(f"{path}: model file fields must be exactly {sorted(keys)}")
    if raw["format_version"] != FORMAT_VERSION or raw["kind"] != "declared":
        raise ModelError(f"{path}: unsupported model format or kind")
    entries = []
    for item in raw["entries"]:
        allowed = {"name", "aliases", "registers", "memory", "other_memory", "notes"}
        if type(item) is not dict or not {"name", "registers", "memory", "other_memory"} <= set(item) <= allowed:
            raise ModelError(f"{path}: entry fields must be {sorted(allowed)}")
        if item["other_memory"] not in ("preserved", "clobbered"):
            raise ModelError(f"{path}: other_memory must be preserved or clobbered")
        registers = tuple(
            (_slice(row["write"], "register write"), tuple(_slice(s, "register read") for s in row.get("from", ())))
            for row in item["registers"]
        )
        memory = tuple(
            (_access(row["write"], "memory write"),
             tuple(_slice(s, "memory write input") for s in row.get("from", ())),
             tuple(_access(load, "memory load") for load in row.get("loads", ())))
            for row in item["memory"]
        )
        names = (item["name"], *item.get("aliases", ()))
        entries.append(ModelEntry(raw["id"], raw["version"], item["name"], tuple(names), registers, memory,
                                  item["other_memory"] == "preserved"))
    return ModelFile(raw["id"], raw["version"], raw["language_id"], raw["abi_tag"],
                     _slice(raw["stack_pointer"], "stack pointer"), raw["stack_delta"],
                     tuple(_slice(s, "preserved") for s in raw["preserved"]), tuple(entries))


@dataclass(frozen=True, slots=True)
class ExternalModels:
    """Model entries by import name (the first file listing a name wins)."""

    files: tuple[ModelFile, ...]

    def lookup(self, name: str) -> tuple[ModelFile, ModelEntry] | None:
        candidates = {name, name.lstrip("_")}
        for model_file in self.files:
            for entry in model_file.entries:
                if candidates & set(entry.names):
                    return model_file, entry
        return None


def load_external_models(paths, language_id: str, abi_tag: str) -> ExternalModels:
    files = [load_model_file(path) for path in paths]
    return ExternalModels(tuple(
        item for item in files if item.language_id == language_id and item.abi_tag == abi_tag
    ))


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
    for target, sources in entry.registers:
        span = register(target)
        written.update(range(span.start, span.end))
        runs.append(_computed(span, tuple(register(s) for s in sources)))
    for write, sources, loads in entry.memory:
        size = extent(write)
        load_sizes = [extent(load) for load in loads]
        if size is None or None in load_sizes:
            complete = False  # unknown extent: the write may land anywhere in that object
            continue
        inputs = [register(s) for s in sources] + [memory_span(load, n) for load, n in zip(loads, load_sizes)]
        runs.append(_computed(memory_span(write, size), tuple(inputs)))
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
        clobbers_below=True,       # a library function has its own frame
        observes_registers=True,   # it may keep any pointer it receives
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


__all__ = ("Access", "ExternalModels", "ModelEntry", "ModelError", "ModelFile", "load_external_models",
           "load_model_file", "model_effect", "model_summary")
