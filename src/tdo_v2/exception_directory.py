"""The PE32+ exception directory of a Bundle's sealed original image -- the
evidence of hazard H1 of the fault premise (F1, docs 25.94).

Reads data directory 3 (the RUNTIME_FUNCTION table) and the UNWIND_INFO
records it names, every read range-checked against the file and the section
that maps it. A verdict per image-relative address:

* ``handler`` -- a valid entry covers it and its unwind chain carries
  UNW_FLAG_EHANDLER or UNW_FLAG_UHANDLER (a language handler may resume);
* ``no-handler`` -- a valid entry covers it, no handler on its chain;
* ``no-entry`` -- the (valid) directory has no entry for it;
* ``malformed`` -- the directory, the entry or a record of its chain failed a
  check (truncated, out of range, unsorted, overlapping, a cycle ...).

Only ``no-handler`` and ``no-entry`` are "no H1 hazard". A Bundle without an
original image member, or one that is not PE32+, has no directory
(``load_exception_directory`` returns None: every site is unverifiable).
Absence of a handler is evidence, never a proof that none runs.
"""

from __future__ import annotations

import hashlib
import json
import struct
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path

READER_VERSION = 1
UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER, UNW_FLAG_CHAININFO = 1, 2, 4
IMAGE_SCN_MEM_EXECUTE = 0x20000000
MAX_CHAIN = 32


class _Malformed(Exception):
    pass


@dataclass(frozen=True, slots=True)
class _Section:
    rva: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    executable: bool


@dataclass(frozen=True, slots=True)
class ExceptionDirectory:
    image_digest: str                 # SHA-256 of the image the directory was read from
    entries: tuple                    # sorted (begin, end, unwind rva)
    sections: tuple                   # _Section
    data: bytes = b""
    malformed: str | None = None      # the whole directory failed a check (every verdict "malformed")

    def verdict(self, rva: int) -> str:
        if self.malformed is not None:
            return "malformed"
        index = bisect_right(self.entries, (rva, 1 << 64, 1 << 64)) - 1
        if index < 0 or not (self.entries[index][0] <= rva < self.entries[index][1]):
            return "no-entry"
        try:
            return self._chain(self.entries[index])
        except _Malformed:
            return "malformed"

    def entry_range(self, rva: int):
        """(begin, end) of the entry covering ``rva`` or None (evidence record)."""
        if self.malformed is not None:
            return None
        index = bisect_right(self.entries, (rva, 1 << 64, 1 << 64)) - 1
        if index >= 0 and self.entries[index][0] <= rva < self.entries[index][1]:
            return self.entries[index][:2]
        return None

    def _bytes(self, rva: int, size: int) -> bytes:
        for section in self.sections:
            if section.rva <= rva and rva + size <= section.rva + min(section.virtual_size or section.raw_size,
                                                                      section.raw_size):
                offset = section.raw_offset + rva - section.rva
                if offset + size > len(self.data):
                    raise _Malformed("past the file")
                return self.data[offset:offset + size]
        raise _Malformed(f"rva {rva:#x}+{size} is not mapped")

    def _chain(self, entry) -> str:
        seen = set()
        for _ in range(MAX_CHAIN + 1):
            begin, end, unwind = entry
            if begin >= end or unwind & 1 or unwind in seen or not any(
                    section.executable and section.rva <= begin
                    and end <= section.rva + (section.virtual_size or section.raw_size)
                    for section in self.sections):
                raise _Malformed("entry")
            seen.add(unwind)
            first, _, count, _ = struct.unpack("<BBBB", self._bytes(unwind, 4))
            version, flags = first & 7, first >> 3
            if version not in (1, 2):
                raise _Malformed("unwind version")
            codes = 2 * (count + (count & 1))
            self._bytes(unwind + 4, codes) if codes else None
            if flags & UNW_FLAG_CHAININFO and flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
                raise _Malformed("chained record with a handler")
            if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
                self._bytes(unwind + 4 + codes, 4)   # (the handler RVA is there)
                return "handler"
            if not flags & UNW_FLAG_CHAININFO:
                return "no-handler"
            entry = struct.unpack("<III", self._bytes(unwind + 4 + codes, 12))
        raise _Malformed("chain too long")


def parse_exception_directory(data: bytes) -> ExceptionDirectory | None:
    """The directory of a PE32+ image (None: not PE32+, or no exception directory)."""
    digest = hashlib.sha256(data).hexdigest()

    def unpack(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            raise _Malformed("header past the file")
        return struct.unpack_from(fmt, data, offset)

    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return None
        (lfanew,) = unpack("<I", 0x3C)
        if data[lfanew:lfanew + 4] != b"PE\0\0":
            return None
        _, count, _, _, _, optional_size, _ = unpack("<HHIIIHH", lfanew + 4)
        optional = lfanew + 24
        (magic,) = unpack("<H", optional)
        if magic != 0x20B:
            return None
        (directories,) = unpack("<I", optional + 108)
        if directories < 4:
            return None
        if optional_size < 112 + 8 * min(directories, 16):
            raise _Malformed("data directories outside the optional header")
        rva, size = unpack("<II", optional + 112 + 3 * 8)
        if rva == 0 and size == 0:
            return None
        sections = []
        table = optional + optional_size
        for index in range(count):
            _, virtual_size, section_rva, raw_size, raw_offset = unpack("<8sIIII", table + 40 * index)
            (characteristics,) = unpack("<I", table + 40 * index + 36)
            sections.append(_Section(section_rva, virtual_size, raw_offset, raw_size,
                                     bool(characteristics & IMAGE_SCN_MEM_EXECUTE)))
        directory = ExceptionDirectory(digest, (), tuple(sections), data)
        if size % 12:
            raise _Malformed("directory size")
        raw = directory._bytes(rva, size)
        entries = [struct.unpack_from("<III", raw, 12 * index) for index in range(size // 12)]
        previous_end = -1
        for begin, end, _ in entries:
            if begin >= end or begin < previous_end:
                raise _Malformed("unsorted or overlapping entries")
            if not any(section.executable and section.rva <= begin
                       and end <= section.rva + (section.virtual_size or section.raw_size)
                       for section in sections):
                raise _Malformed("entry outside executable code")
            previous_end = end
        return ExceptionDirectory(digest, tuple(entries), tuple(sections), data)
    except _Malformed as error:
        return ExceptionDirectory(digest, (), (), b"", str(error))


def load_exception_directory(generation_path) -> ExceptionDirectory | None:
    """The exception directory of a Bundle's sealed original image (its
    manifest member's size and SHA-256 checked, as ``load_image_info`` does);
    None when the Bundle has no original member or it is not PE32+."""
    generation = Path(generation_path)
    manifest_bytes = (generation / "manifest.json").read_bytes()
    seal = json.loads((generation / "seal.json").read_bytes())
    if seal.get("manifest_sha256") != hashlib.sha256(manifest_bytes).hexdigest():
        raise ValueError("bundle manifest seal does not match")
    manifest = json.loads(manifest_bytes)
    member_id = manifest.get("original_member_id")
    rows = [row for row in manifest.get("members", ()) if row.get("id") == member_id]
    if member_id is None or len(rows) != 1:
        return None
    payload = (generation / rows[0]["path"]).read_bytes()
    if len(payload) != rows[0]["size"] or hashlib.sha256(payload).hexdigest() != rows[0]["sha256"]:
        raise ValueError("original image member does not match the sealed manifest")
    return parse_exception_directory(payload)


__all__ = ("READER_VERSION", "ExceptionDirectory", "load_exception_directory", "parse_exception_directory")
