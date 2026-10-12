"""Sealed image facts of a Bundle (``image-info.json``, schema tdo-v2-image-info-1).

The Ghidra exporter (``GhidraV2BundleExport.imageInfo``) writes, beside the
memory blocks: block permissions and names, imported symbols with the memory
slots Ghidra binds to them (IAT entries, MinGW ``.refptr``-style pointers) and
their thunks, exported entry points, and relocated addresses. The member is
listed and hashed in the sealed manifest (admission verifies it like every
member); ``load_image_info`` re-checks the seal, the manifest entry and the
member digest before parsing, and returns None for Bundles exported before
the member existed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

SCHEMA = "tdo-v2-image-info-1"


@dataclass(frozen=True, slots=True)
class BlockPermissions:
    space_id: int
    start: int
    size: int
    name: str
    read: bool
    write: bool
    execute: bool
    volatile: bool
    initialized: bool


@dataclass(frozen=True, slots=True)
class ImportedSymbol:
    library: str
    name: str
    original_name: str | None
    slots: tuple[tuple[int, int], ...]     # (space id, byte offset) of data slots holding its address
    thunks: tuple[tuple[int, int], ...]    # thunk function entries that jump to it


@dataclass(frozen=True, slots=True)
class ExportedSymbol:
    space_id: int
    byte_offset: int
    name: str
    primary: bool


@dataclass(frozen=True, slots=True)
class ImageInfo:
    executable_format: str
    blocks: tuple[BlockPermissions, ...]
    imports: tuple[ImportedSymbol, ...]
    exports: tuple[ExportedSymbol, ...]
    relocations: tuple[tuple[int, int, int], ...]   # (space id, byte offset, byte size)

    def block_at(self, space_id: int, offset: int, size: int = 1) -> BlockPermissions | None:
        """The block wholly containing [offset, offset + size), or None."""
        for block in self.blocks:
            if block.space_id == space_id and block.start <= offset and offset + size <= block.start + block.size:
                return block
        return None

    def import_at_slot(self, space_id: int, offset: int) -> ImportedSymbol | None:
        for row in self.imports:
            if (space_id, offset) in row.slots:
                return row
        return None

    def import_at_thunk(self, space_id: int, offset: int) -> ImportedSymbol | None:
        for row in self.imports:
            if (space_id, offset) in row.thunks:
                return row
        return None


class ImageInfoError(ValueError):
    pass


def _exact(row, keys, what):
    if type(row) is not dict or set(row) != set(keys):
        raise ImageInfoError(f"image info {what} has unexpected fields")


def _int(value, what):
    if type(value) is not int or value < 0:
        raise ImageInfoError(f"image info {what} must be a non-negative int")
    return value


def _bool(value, what):
    if type(value) is not bool:
        raise ImageInfoError(f"image info {what} must be a bool")
    return value


def _text(value, what, *, optional=False):
    if value is None and optional:
        return None
    if type(value) is not str:
        raise ImageInfoError(f"image info {what} must be text")
    return value


def _coordinates(rows, what):
    if type(rows) is not list:
        raise ImageInfoError(f"image info {what} must be a list")
    result = []
    for row in rows:
        _exact(row, ("space_id", "byte_offset"), what)
        result.append((_int(row["space_id"], what), _int(row["byte_offset"], what)))
    return tuple(result)


_SLOT_BYTES = 8   # an import slot is at most pointer-sized; wider is only more conservative


class ReadOnlyImage:
    """Initial values of read-only image memory, for the named assumption
    ``readonly-image-data-is-constant``: bytes of a loaded, initialized,
    non-writable, non-volatile block keep their image value while the program
    runs (no ``VirtualProtect``-style rewriting). Values are the Bundle's
    sealed memory-block bytes (Ghidra's image, relocated to its image base).
    Import slots are excluded: the loader writes them (the image holds a
    name-table reference, the running program the imported address)."""

    def __init__(self, generation_path: str | Path, info: ImageInfo) -> None:
        self._generation = Path(generation_path)
        self._info = info
        manifest = json.loads((self._generation / "manifest.json").read_bytes())
        self._members = {row["id"]: row for row in manifest["members"]}
        self._block_members = {(row["space_id"], row["byte_start"]): row["member_id"] for row in manifest["blocks"]}
        self._cache: dict = {}

    def value(self, space_id: int, offset: int, size: int) -> int | None:
        block = self._info.block_at(space_id, offset, size)
        if block is None or not block.initialized or block.write or block.volatile or not block.read:
            return None
        if any(slot_space == space_id and slot < offset + size and offset < slot + _SLOT_BYTES
               for row in self._info.imports for slot_space, slot in row.slots):
            return None  # loader-written: not the image value at run time
        member_id = self._block_members.get((block.space_id, block.start))
        if member_id is None:
            return None
        data = self._cache.get(member_id)
        if data is None:
            member = self._members[member_id]
            data = (self._generation / member["path"]).read_bytes()
            if hashlib.sha256(data).hexdigest() != member["sha256"]:
                raise ImageInfoError("memory block does not match the sealed manifest")
            self._cache[member_id] = data
        start = offset - block.start
        return int.from_bytes(data[start:start + size], "little")


def load_image_info(generation_path: str | Path) -> ImageInfo | None:
    generation = Path(generation_path)
    manifest_bytes = (generation / "manifest.json").read_bytes()
    seal = json.loads((generation / "seal.json").read_bytes())
    if seal.get("manifest_sha256") != hashlib.sha256(manifest_bytes).hexdigest():
        raise ImageInfoError("bundle manifest seal does not match")
    manifest = json.loads(manifest_bytes)
    member_id = manifest.get("image_info_member")
    if member_id is None:
        return None
    (member,) = [row for row in manifest["members"] if row["id"] == member_id]
    payload = (generation / member["path"]).read_bytes()
    if len(payload) != member["size"] or hashlib.sha256(payload).hexdigest() != member["sha256"]:
        raise ImageInfoError("image info member does not match the sealed manifest")
    raw = json.loads(payload)
    _exact(raw, ("schema", "executable_format", "block_permissions", "imports", "exports", "relocations"),
           "document")
    if raw["schema"] != SCHEMA:
        raise ImageInfoError("unknown image info schema")

    geometry = {row["id"]: row for row in manifest["blocks"]}
    blocks = []
    for row in raw["block_permissions"]:
        _exact(row, ("block_id", "name", "read", "write", "execute", "volatile"), "block")
        block = geometry.get(row["block_id"])
        if block is None:
            raise ImageInfoError("image info names an unknown block")
        blocks.append(BlockPermissions(
            block["space_id"], block["byte_start"], block["byte_size"], _text(row["name"], "block name"),
            _bool(row["read"], "read"), _bool(row["write"], "write"), _bool(row["execute"], "execute"),
            _bool(row["volatile"], "volatile"), block["is_initialized"] and block["is_loaded"],
        ))
    if len(blocks) != len(geometry):
        raise ImageInfoError("image info must describe every block")
    imports = []
    for row in raw["imports"]:
        _exact(row, ("library", "name", "original_name", "slots", "thunks"), "import")
        imports.append(ImportedSymbol(
            _text(row["library"], "library", optional=True) or "", _text(row["name"], "import name"),
            _text(row["original_name"], "original name", optional=True),
            _coordinates(row["slots"], "import slots"), _coordinates(row["thunks"], "import thunks"),
        ))
    exports = []
    for row in raw["exports"]:
        _exact(row, ("space_id", "byte_offset", "name", "primary"), "export")
        exports.append(ExportedSymbol(_int(row["space_id"], "export space"), _int(row["byte_offset"], "export"),
                                      _text(row["name"], "export name"), _bool(row["primary"], "primary")))
    relocations = []
    for row in raw["relocations"]:
        _exact(row, ("space_id", "byte_offset", "byte_size"), "relocation")
        relocations.append((_int(row["space_id"], "relocation"), _int(row["byte_offset"], "relocation"),
                            _int(row["byte_size"], "relocation size")))
    return ImageInfo(_text(raw["executable_format"], "format"), tuple(blocks), tuple(imports),
                     tuple(exports), tuple(sorted(relocations)))


__all__ = ("BlockPermissions", "ExportedSymbol", "ImageInfo", "ImageInfoError", "ImportedSymbol",
           "ReadOnlyImage", "load_image_info")
