"""Synthetic PE32+ images for G1 decode_check tests (synthetic bytes only; never
a real binary). ``make_pe(sections, ...)`` returns the file bytes; the
matching sealed blocks are the header region and each section's mapped bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import struct

IMAGE_BASE = 0x140000000
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200


@dataclass
class Section:
    name: str
    rva: int
    data: bytes
    vsize: int | None = None          # default: len(data)
    characteristics: int = 0x60000020  # code | execute | read
    raw: bytes | None = None          # file bytes when they must differ from data (a mapping test)


@dataclass
class Directory:
    index: int
    rva: int
    size: int


def _align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def make_pe(sections: list, *, image_base=IMAGE_BASE, directories=(), size_of_headers=0x200,
            section_alignment=SECTION_ALIGNMENT, file_alignment=FILE_ALIGNMENT, machine=0x8664) -> bytes:
    optional_size = 240
    header = bytearray(size_of_headers)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", header, 0x44, machine, len(sections), 0, 0, 0, optional_size, 0x22)
    optional = 0x58
    end = max(section.rva + _align(section.vsize or len(section.data), section_alignment) for section in sections)
    struct.pack_into("<H", header, optional, 0x20B)
    struct.pack_into("<Q", header, optional + 24, image_base)
    struct.pack_into("<II", header, optional + 32, section_alignment, file_alignment)
    struct.pack_into("<II", header, optional + 56, end, size_of_headers)
    struct.pack_into("<I", header, optional + 108, 16)
    for directory in directories:
        struct.pack_into("<II", header, optional + 112 + 8 * directory.index, directory.rva, directory.size)
    table = optional + optional_size
    raw_cursor = size_of_headers
    payload = bytearray()
    for index, section in enumerate(sections):
        data = section.raw if section.raw is not None else section.data
        raw_size = _align(len(data), file_alignment)
        base = table + 40 * index
        header[base:base + 8] = section.name.encode()[:8].ljust(8, b"\0")
        struct.pack_into("<IIII", header, base + 8, section.vsize or len(section.data), section.rva, raw_size,
                         raw_cursor)
        struct.pack_into("<I", header, base + 36, section.characteristics)
        payload += data.ljust(raw_size, b"\0")
        raw_cursor += raw_size
    return bytes(header) + bytes(payload)


def blocks_for(sections: list, original: bytes, *, image_base=IMAGE_BASE, size_of_headers=0x200, header=True):
    """The sealed blocks a loader would map: (start VA, bytes) of the header region and each section."""
    out = []
    if header:
        out.append((image_base, original[:size_of_headers]))
    for section in sections:
        size = section.vsize or len(section.data)
        out.append((image_base + section.rva, section.data.ljust(size, b"\0")[:size]))
    return out
