"""Synthetic ELF64 x86-64 images for G1 decode_check tests (synthetic bytes only;
never a real binary). ``make_elf(segments, ...)`` returns the file bytes and the
(link VA, sealed bytes) of every PT_LOAD; a Ghidra-style sealed block is that
VA plus the load bias.

Layout: a read-only PT_LOAD at ``link_base`` holds the ELF header and the
program headers; each given segment follows at a page-congruent file offset;
unless ``dynamic=False`` a read-write PT_LOAD holds the relocation tables, the
symbol sizes and the dynamic array (PT_DYNAMIC).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import struct

PAGE = 0x1000
DT_RELA, DT_RELASZ, DT_RELAENT, DT_PLTGOT, DT_SYMTAB, DT_SYMENT = 7, 8, 9, 3, 6, 11
DT_RELR, DT_RELRSZ, DT_RELRENT = 36, 35, 37


@dataclass
class Segment:
    vaddr: int
    data: bytes
    memsz: int | None = None       # default: len(data)
    flags: int = 5                 # R + X
    raw: bytes | None = None       # file bytes when they must differ from the sealed data
    offset: int | None = None      # default: the next page-congruent file offset
    align: int = PAGE


@dataclass
class Reloc:
    offset: int
    kind: int
    symbol: int = 0
    addend: int = 0


@dataclass
class Elf:
    data: bytes
    loads: list = field(default_factory=list)   # (link VA, sealed bytes)


def _phdr(kind, flags, offset, vaddr, filesz, memsz, align):
    return struct.pack("<IIQQQQQQ", kind, flags, offset, vaddr, vaddr, filesz, memsz, align)


def make_elf(segments: list, *, e_type=3, link_base=0, relocations=(), relr=(), symbol_sizes=(), pltgot=None,
             extra_dynamic=(), dynamic=True, dyn_vaddr=None, machine=62) -> Elf:
    segments = list(segments)
    count = 1 + len(segments) + (2 if dynamic else 0)
    header_size = 64 + 56 * count
    file = bytearray(header_size)
    loads = []
    phdrs = [None]
    cursor = PAGE
    for segment in segments:
        raw = segment.raw if segment.raw is not None else segment.data
        offset = segment.offset if segment.offset is not None else \
            (cursor + PAGE - 1) // PAGE * PAGE + segment.vaddr % PAGE
        memsz = segment.memsz if segment.memsz is not None else len(segment.data)
        file = file.ljust(offset, b"\0")
        file[offset:offset + len(raw)] = raw
        cursor = max(cursor, offset + len(raw))
        phdrs.append(_phdr(1, segment.flags, offset, segment.vaddr, len(raw), memsz, segment.align))
        loads.append((segment.vaddr, segment.data.ljust(memsz, b"\0")[:memsz]))
    if dynamic:
        dyn_vaddr = dyn_vaddr if dyn_vaddr is not None else \
            max(s.vaddr + (s.memsz or len(s.data)) for s in segments) // PAGE * PAGE + 2 * PAGE
        body = bytearray()
        tags = []
        if relocations:
            tags += [(DT_RELA, dyn_vaddr + len(body)), (DT_RELASZ, 24 * len(relocations)), (DT_RELAENT, 24)]
            for item in relocations:
                body += struct.pack("<QQq", item.offset, item.symbol << 32 | item.kind, item.addend)
        if relr:
            tags += [(DT_RELR, dyn_vaddr + len(body)), (DT_RELRSZ, 8 * len(relr)), (DT_RELRENT, 8)]
            for entry in relr:
                body += struct.pack("<Q", entry)
        if symbol_sizes:
            tags += [(DT_SYMTAB, dyn_vaddr + len(body)), (DT_SYMENT, 24)]
            for size in symbol_sizes:
                body += struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, size)
        if pltgot is not None:
            tags.append((DT_PLTGOT, pltgot))
        tags += list(extra_dynamic)
        dynamic_at = len(body)
        for tag, value in tags + [(0, 0)]:
            body += struct.pack("<qQ", tag, value)
        offset = (cursor + PAGE - 1) // PAGE * PAGE + dyn_vaddr % PAGE
        file = file.ljust(offset, b"\0")
        file[offset:offset + len(body)] = body
        phdrs.append(_phdr(1, 6, offset, dyn_vaddr, len(body), len(body), PAGE))
        phdrs.append(_phdr(2, 6, offset + dynamic_at, dyn_vaddr + dynamic_at, len(body) - dynamic_at,
                           len(body) - dynamic_at, 8))
        loads.append((dyn_vaddr, bytes(body)))
    phdrs[0] = _phdr(1, 4, 0, link_base, header_size, header_size, PAGE)
    file[0:16] = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", file, 16, e_type, machine, 1, 0, 64, 0, 0, 64, 56, count, 64, 0, 0)
    for index, item in enumerate(phdrs):
        file[64 + 56 * index:64 + 56 * (index + 1)] = item
    loads.insert(0, (link_base, bytes(file[:header_size])))
    return Elf(bytes(file), loads)
