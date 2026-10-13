"""The export table of a PE file (DLL), read from the file itself.

Linking (design section 24) checks that a program's imports from a library
are exports of the library file it is linked with, before anything is
derived, and derives only function exports. A PE export address entry may
name code, data or a forwarder (an RVA inside the export directory: the text
"OTHERDLL.Name"); code vs data is told by the executable flag of the section
holding the RVA. Read from the file, independently of Ghidra.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

_EXECUTE = 0x20000000   # IMAGE_SCN_MEM_EXECUTE


class PeError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PeExport:
    name: str | None           # None: exported by ordinal only
    ordinal: int
    rva: int
    kind: str                  # "code" | "data" | "forwarder"
    forward: str | None = None


@dataclass(frozen=True, slots=True)
class PeExports:
    sha256: str
    image_base: int
    machine: int
    exports: tuple[PeExport, ...]

    def by_name(self) -> dict:
        return {item.name: item for item in self.exports if item.name is not None}

    def by_ordinal(self) -> dict:
        return {item.ordinal: item for item in self.exports}


def read_pe_exports(path) -> PeExports:
    data = Path(path).read_bytes()
    try:
        return _parse(data)
    except (struct.error, IndexError, UnicodeDecodeError) as error:
        raise PeError(f"{path}: not a readable PE file ({error})") from error


def _parse(data: bytes) -> PeExports:
    if data[:2] != b"MZ":
        raise PeError("no MZ header")
    (pe,) = struct.unpack_from("<I", data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise PeError("no PE signature")
    machine, sections, _, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", data, pe + 4)
    optional = pe + 24
    (magic,) = struct.unpack_from("<H", data, optional)
    if magic == 0x20B:     # PE32+
        (image_base,) = struct.unpack_from("<Q", data, optional + 24)
        directories = optional + 112
    elif magic == 0x10B:   # PE32
        (image_base,) = struct.unpack_from("<I", data, optional + 28)
        directories = optional + 96
    else:
        raise PeError(f"unknown optional header magic {magic:#x}")
    export_rva, export_size = struct.unpack_from("<II", data, directories)
    table = optional + optional_size
    rows = []
    for index in range(sections):
        _, virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<8sIIII", data, table + 40 * index)
        (characteristics,) = struct.unpack_from("<I", data, table + 40 * index + 36)
        rows.append((virtual_address, max(virtual_size, raw_size), raw_pointer, characteristics))

    def section_of(rva):
        return next((row for row in rows if row[0] <= rva < row[0] + row[1]), None)

    def offset(rva):
        row = section_of(rva)
        if row is None:
            raise PeError(f"RVA {rva:#x} in no section")
        return row[2] + rva - row[0]

    def text(rva):
        start = offset(rva)
        return data[start:data.index(b"\0", start)].decode("ascii")

    exports = []
    if export_rva and export_size:
        directory = offset(export_rva)
        _, _, _, _, _, base, functions, names, address_of_functions, address_of_names, address_of_ordinals = \
            struct.unpack_from("<IIHHIIIIIII", data, directory)
        function_rvas = struct.unpack_from(f"<{functions}I", data, offset(address_of_functions)) if functions else ()
        name_rvas = struct.unpack_from(f"<{names}I", data, offset(address_of_names)) if names else ()
        name_ordinals = struct.unpack_from(f"<{names}H", data, offset(address_of_ordinals)) if names else ()
        named = {index: text(name_rva) for name_rva, index in zip(name_rvas, name_ordinals)}
        for index, rva in enumerate(function_rvas):
            if rva == 0:
                continue   # an unused ordinal
            if export_rva <= rva < export_rva + export_size:
                kind, forward = "forwarder", text(rva)
            else:
                row = section_of(rva)
                kind, forward = ("code" if row is not None and row[3] & _EXECUTE else "data"), None
            exports.append(PeExport(named.get(index), base + index, rva, kind, forward))
    return PeExports(hashlib.sha256(data).hexdigest(), image_base, machine, tuple(exports))


__all__ = ("PeError", "PeExport", "PeExports", "read_pe_exports")
