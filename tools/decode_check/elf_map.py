"""ELF64 x86-64 file mapping of G1 decode_check: ``elf-loader-rules-1``.
Only the file's own headers are read (never Ghidra data).

Coordinates are offsets from ``image_base`` = the page floor of the lowest
PT_LOAD p_vaddr (the same role as a PE RVA), so a Bundle VA maps to
``va - bundle_image_base``. ET_EXEC images are position-dependent
(``fixed_base``: the Bundle must sit at the linked base); ET_DYN images may sit
anywhere, because every byte the loader changes is a relocation target and
relocation targets are loader-written ranges here.

Rules (one revision, pinned by RULES):
- ELFCLASS64, ELFDATA2LSB, EV_CURRENT, EM_X86_64, ET_EXEC or ET_DYN; the program
  header table inside the file with e_phentsize 56.
- A PT_LOAD maps [p_vaddr, p_vaddr + p_filesz) from p_offset and zero-fills
  [p_vaddr + p_filesz, p_vaddr + p_memsz). A segment is ``ambiguous`` when
  p_filesz > p_memsz, p_offset + p_filesz is past the file end, p_align is not 0,
  1 or a power of two, or p_vaddr and p_offset are not congruent modulo the
  4 KiB page. p_memsz 0 maps nothing.
- Pages two PT_LOADs share are ``ambiguous`` (the later mmap replaces the page).
- Bytes outside every PT_LOAD are outside the mapping.
- Loader-written ranges: every relocation target the runtime applies (DT_RELA,
  DT_REL, DT_JMPREL, DT_RELR / DT_ANDROID_RELR and every SHF_ALLOC SHT_RELA /
  SHT_REL / SHT_RELR section), the whole PT_DYNAMIC (ld.so may adjust entries
  in place, DT_DEBUG), and GOT[1], GOT[2] at DT_PLTGOT (lazy binding). Width
  per relocation type from WIDTHS; COPY uses the symbol's st_size; an unknown
  type is 16 bytes (the largest x86-64 write, TLSDESC). Android packed
  relocations (DT_ANDROID_REL / DT_ANDROID_RELA) are not parsed: indeterminate.
  A static image (no PT_DYNAMIC) without section headers is indeterminate: its
  startup-applied relocations cannot be located. Non-SHF_ALLOC relocation
  sections (--emit-relocs) are link-time only and are not loader writes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import struct

from pe_map import Parsed, Range

RULES = "elf-loader-rules-1"
EM_X86_64 = 62
ET_EXEC, ET_DYN = 2, 3
PT_LOAD, PT_DYNAMIC = 1, 2
PAGE = 0x1000
SHF_ALLOC = 0x2
SHT_RELA, SHT_REL, SHT_RELR = 4, 9, 19

DT = {"PLTRELSZ": 2, "PLTGOT": 3, "SYMTAB": 6, "RELA": 7, "RELASZ": 8, "RELAENT": 9, "SYMENT": 11, "REL": 17,
      "RELSZ": 18, "RELENT": 19, "PLTREL": 20, "JMPREL": 23, "RELRSZ": 35, "RELR": 36, "RELRENT": 37,
      "ANDROID_REL": 0x6000000F, "ANDROID_RELSZ": 0x60000010, "ANDROID_RELA": 0x60000011,
      "ANDROID_RELASZ": 0x60000012, "ANDROID_RELR": 0x6FFFE000, "ANDROID_RELRSZ": 0x6FFFE001,
      "ANDROID_RELRENT": 0x6FFFE003}

# bytes written per R_X86_64_* type (psABI); NONE (0) and TLSDESC_CALL (35) write nothing; COPY (5) uses st_size
WIDTHS = {1: 8, 2: 4, 3: 4, 4: 4, 6: 8, 7: 8, 8: 8, 9: 4, 10: 4, 11: 4, 12: 2, 13: 2, 14: 1, 15: 1, 16: 8, 17: 8,
          18: 8, 19: 4, 20: 4, 21: 4, 22: 4, 23: 4, 24: 8, 25: 8, 26: 4, 27: 8, 28: 8, 29: 8, 30: 8, 31: 8, 32: 4,
          33: 8, 34: 4, 36: 16, 37: 8, 38: 8, 41: 4, 42: 4, 43: 4, 44: 4}
NO_WRITE = {0, 35}
R_COPY = 5
UNKNOWN_WIDTH = 16
NAMES = {1: "64", 2: "PC32", 5: "COPY", 6: "GLOB_DAT", 7: "JUMP_SLOT", 8: "RELATIVE", 10: "32", 11: "32S",
         16: "DTPMOD64", 17: "DTPOFF64", 18: "TPOFF64", 36: "TLSDESC", 37: "IRELATIVE"}


@dataclass
class ElfImage:
    ok: bool
    why: str = ""
    format: str = "elf"
    rules: str = RULES
    image_base: int = 0
    fixed_base: bool = False
    e_type: int = 0
    ranges: list = field(default_factory=list)
    segments: list = field(default_factory=list)
    header_fields: dict = field(default_factory=dict)
    relocations: Parsed = None      # ELF relocations are loader writes: listed under ``written``
    written: Parsed = None
    mapping_id: str = ""

    def at(self, rva: int) -> Range | None:
        for item in self.ranges:
            if item.start <= rva < item.end:
                return item
        return None


class _Unreadable(Exception):
    pass


def _pow2(value):
    return value > 0 and value & (value - 1) == 0


def _floor(value):
    return value // PAGE * PAGE


def _ceil(value):
    return (value + PAGE - 1) // PAGE * PAGE


def parse(data: bytes) -> ElfImage:
    try:
        image = _parse(data)
    except (struct.error, IndexError, ValueError) as error:
        image = ElfImage(False, f"header parse failed: {error}")
    return image if image.mapping_id else _finish(image)


def _parse(data: bytes) -> ElfImage:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return ElfImage(False, "not an ELF image")
    if data[4] != 2 or data[5] != 1 or data[6] != 1:
        return ElfImage(False, "not ELFCLASS64 / ELFDATA2LSB / EV_CURRENT")
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    e_phoff, e_shoff = struct.unpack_from("<QQ", data, 32)
    e_phentsize, e_phnum, e_shentsize, e_shnum = struct.unpack_from("<HHHH", data, 54)
    if e_machine != EM_X86_64:
        return ElfImage(False, f"machine {e_machine} is not EM_X86_64")
    if e_type not in (ET_EXEC, ET_DYN):
        return ElfImage(False, f"e_type {e_type} is not ET_EXEC / ET_DYN")
    if e_phentsize != 56 or e_phnum == 0 or e_phoff + 56 * e_phnum > len(data):
        return ElfImage(False, "program header table outside the file or malformed")
    phdrs = [struct.unpack_from("<IIQQQQQQ", data, e_phoff + 56 * index) for index in range(e_phnum)]
    loads = [p for p in phdrs if p[0] == PT_LOAD and p[6] > 0]
    if not loads:
        return ElfImage(False, "no PT_LOAD segment")
    image_base = _floor(min(p[3] for p in loads))
    fields = {"e_type": e_type, "e_machine": e_machine, "e_phoff": e_phoff, "e_phnum": e_phnum,
              "e_shoff": e_shoff, "e_shnum": e_shnum, "e_shentsize": e_shentsize, "image_base": image_base,
              "file_size": len(data), "file_sha256": hashlib.sha256(data).hexdigest()}
    image = ElfImage(True, image_base=image_base, fixed_base=e_type == ET_EXEC, e_type=e_type, header_fields=fields)
    ranges = []
    for index, (_, flags, offset, vaddr, _, filesz, memsz, align) in enumerate(loads):
        why = ""
        if filesz > memsz:
            why = "p_filesz > p_memsz"
        elif offset + filesz > len(data):
            why = "segment file range past the end of the file"
        elif align not in (0, 1) and not _pow2(align):
            why = "p_align not a power of two"
        elif (vaddr - offset) % PAGE:
            why = "p_vaddr and p_offset not congruent modulo the page"
        start = vaddr - image_base
        image.segments.append({"index": index, "vaddr": vaddr, "offset": offset, "filesz": filesz, "memsz": memsz,
                               "flags": flags, "align": align, "state": "ambiguous" if why else "mapped", "why": why})
        if why:
            ranges.append(Range(start, start + memsz, "ambiguous", why=why))
            continue
        if filesz:
            ranges.append(Range(start, start + filesz, "file", offset))
        if memsz > filesz:
            ranges.append(Range(start + filesz, start + memsz, "zero"))
    # pages two PT_LOADs share (r: the later mmap replaces the page)
    shared = []
    pages = sorted((_floor(p[3]), _ceil(p[3] + p[6])) for p in loads)
    for (a0, a1), (b0, b1) in zip(pages, pages[1:]):
        if b0 < a1:
            shared.append((b0 - image_base, min(a1, b1) - image_base))
    image.ranges = _overlay_ambiguous(ranges, shared, "PT_LOAD segments share a page")
    overlapping = [(a, b) for a, b in zip(image.ranges, image.ranges[1:]) if b.start < a.end]
    if overlapping:
        image.ok, image.why = False, "PT_LOAD segments overlap"
        return _finish(image)
    image.written = _written(image, data, phdrs, e_shoff, e_shnum, e_shentsize)
    image.relocations = Parsed("absent", why="ELF relocations are loader writes: listed under written")
    return _finish(image)


def _overlay_ambiguous(ranges, cuts, why):
    """Split ``ranges`` so the parts inside ``cuts`` become ambiguous."""
    if not cuts:
        return sorted(ranges, key=lambda item: item.start)
    out = []
    for item in ranges:
        pieces = [item]
        for c0, c1 in cuts:
            nxt = []
            for piece in pieces:
                if piece.kind == "ambiguous" or c1 <= piece.start or c0 >= piece.end:
                    nxt.append(piece)
                    continue
                if piece.start < c0:
                    nxt.append(Range(piece.start, c0, piece.kind, piece.file_offset, piece.why))
                nxt.append(Range(max(piece.start, c0), min(piece.end, c1), "ambiguous", why=why))
                if c1 < piece.end:
                    shift = c1 - piece.start if piece.kind == "file" else 0
                    nxt.append(Range(c1, piece.end, piece.kind,
                                     piece.file_offset + shift if piece.kind == "file" else -1, piece.why))
            pieces = nxt
        out.extend(pieces)
    # (a shared page cut from both segments leaves two identical ambiguous pieces: keep one)
    unique = {}
    for item in out:
        unique.setdefault((item.start, item.end, item.kind), item)
    return sorted(unique.values(), key=lambda item: item.start)


def _finish(image: ElfImage) -> ElfImage:
    payload = {"rules": RULES, "fields": image.header_fields, "ok": image.ok,
               "ranges": [[r.start, r.end, r.kind, r.file_offset] for r in image.ranges]}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    image.mapping_id = hashlib.sha256(canonical).hexdigest()
    if image.relocations is None:
        image.relocations = Parsed("indeterminate", why=image.why or "no mapping")
    if image.written is None:
        image.written = Parsed("indeterminate", why=image.why or "no mapping")
    return image


def _read(image: ElfImage, data: bytes, va: int, size: int) -> bytes:
    """Bytes at a link-time VA through the mapping (file or zero-fill only)."""
    out = bytearray()
    cursor = va - image.image_base
    end = cursor + size
    while cursor < end:
        item = image.at(cursor)
        if item is None or item.kind == "ambiguous":
            raise _Unreadable(f"VA {cursor + image.image_base:#x} not readable")
        take = min(item.end, end) - cursor
        if item.kind == "zero":
            out += bytes(take)
        else:
            offset = item.file_offset + (cursor - item.start)
            if offset + take > len(data):
                raise _Unreadable("past the end of the file")
            out += data[offset:offset + take]
        cursor += take
    return bytes(out)


def _relocation_targets(table: bytes, entsize: int, rela: bool, symbol_size, label: str) -> list:
    expected = 24 if rela else 16
    if entsize != expected or len(table) % expected:
        raise _Unreadable(f"{label}: entry size {entsize} is not {expected}")
    out = []
    for cursor in range(0, len(table), expected):
        offset, info = struct.unpack_from("<QQ", table, cursor)
        kind, symbol = info & 0xFFFFFFFF, info >> 32
        if kind in NO_WRITE:
            continue
        if kind == R_COPY:
            width = symbol_size(symbol)
        else:
            width = WIDTHS.get(kind, UNKNOWN_WIDTH)
        name = NAMES.get(kind, str(kind)) if kind in WIDTHS or kind == R_COPY else f"{kind}-unknown-width"
        out.append((offset, offset + width, f"R_X86_64_{name}"))
    return out


def _relr_targets(table: bytes, entsize: int, label: str) -> list:
    if entsize != 8 or len(table) % 8:
        raise _Unreadable(f"{label}: RELR entry size {entsize} is not 8")
    out = []
    base = None
    for cursor in range(0, len(table), 8):
        entry, = struct.unpack_from("<Q", table, cursor)
        if entry & 1 == 0:
            out.append((entry, entry + 8, "RELR"))
            base = entry + 8
            continue
        if base is None:
            raise _Unreadable(f"{label}: RELR bitmap before any address")
        bits = entry >> 1
        for index in range(63):
            if bits >> index & 1:
                at = base + 8 * index
                out.append((at, at + 8, "RELR"))
        base += 63 * 8
    return out


def _written(image, data, phdrs, e_shoff, e_shnum, e_shentsize) -> Parsed:
    ranges = []
    problems = []
    dynamic = [p for p in phdrs if p[0] == PT_DYNAMIC]
    tags = {}
    if dynamic:
        _, _, _, vaddr, _, filesz, memsz, _ = dynamic[0]
        ranges.append((vaddr, vaddr + memsz, "dynamic"))
        try:
            raw = _read(image, data, vaddr, filesz)
            for cursor in range(0, len(raw) - 15, 16):
                tag, value = struct.unpack_from("<qQ", raw, cursor)
                if tag == 0:
                    break
                tags.setdefault(tag, value)
        except _Unreadable as error:
            problems.append(f"PT_DYNAMIC: {error}")

    def dynamic_symbol_size(symbol):
        if DT["SYMTAB"] not in tags:
            raise _Unreadable("COPY relocation without DT_SYMTAB")
        entsize = tags.get(DT["SYMENT"], 24)
        return struct.unpack_from("<Q", _read(image, data, tags[DT["SYMTAB"]] + entsize * symbol, 24), 16)[0]

    if tags:
        for kind in ("ANDROID_REL", "ANDROID_RELA"):
            if DT[kind] in tags:
                problems.append(f"DT_{kind}: Android packed relocations are not parsed")
        tables = [("RELA", "RELASZ", tags.get(DT["RELAENT"], 24), True),
                  ("REL", "RELSZ", tags.get(DT["RELENT"], 16), False)]
        if DT["JMPREL"] in tags:
            plt_rela = tags.get(DT["PLTREL"], DT["RELA"]) == DT["RELA"]
            tables.append(("JMPREL", "PLTRELSZ", 24 if plt_rela else 16, plt_rela))
        for start, size, entsize, rela in tables:
            if DT[start] not in tags:
                continue
            try:
                table = _read(image, data, tags[DT[start]], tags.get(DT[size], 0))
                ranges.extend(_relocation_targets(table, entsize, rela, dynamic_symbol_size, f"DT_{start}"))
            except (_Unreadable, struct.error) as error:
                problems.append(f"DT_{start}: {error}")
        for start, size, ent in (("RELR", "RELRSZ", "RELRENT"), ("ANDROID_RELR", "ANDROID_RELRSZ", "ANDROID_RELRENT")):
            if DT[start] not in tags:
                continue
            try:
                table = _read(image, data, tags[DT[start]], tags.get(DT[size], 0))
                ranges.extend(_relr_targets(table, tags.get(DT[ent], 8), f"DT_{start}"))
            except _Unreadable as error:
                problems.append(f"DT_{start}: {error}")
        if DT["PLTGOT"] in tags:
            got = tags[DT["PLTGOT"]]
            ranges.append((got + 8, got + 24, "got-plt-reserved"))
    # SHF_ALLOC relocation sections (static images apply .rela.iplt at startup; duplicates of DT_ tables are harmless)
    if e_shoff and e_shnum:
        if e_shentsize != 64 or e_shoff + 64 * e_shnum > len(data):
            problems.append("section header table outside the file or malformed")
        else:
            sections = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + 64 * index) for index in range(e_shnum)]
            for _, sh_type, flags, _, offset, size, link, _, _, entsize in sections:
                if sh_type not in (SHT_RELA, SHT_REL, SHT_RELR) or not flags & SHF_ALLOC:
                    continue
                if offset + size > len(data):
                    problems.append("relocation section past the end of the file")
                    continue
                table = data[offset:offset + size]

                def section_symbol_size(symbol, link=link):
                    if link >= len(sections):
                        raise _Unreadable("COPY relocation with a bad sh_link")
                    sym_offset = sections[link][4] + 24 * symbol
                    if sym_offset + 24 > len(data):
                        raise _Unreadable("COPY symbol past the end of the file")
                    return struct.unpack_from("<Q", data, sym_offset + 16)[0]

                try:
                    if sh_type == SHT_RELR:
                        ranges.extend(_relr_targets(table, entsize or 8, "SHT_RELR"))
                    else:
                        ranges.extend(_relocation_targets(table, entsize, sh_type == SHT_RELA, section_symbol_size,
                                                          "SHT_RELA" if sh_type == SHT_RELA else "SHT_REL"))
                except _Unreadable as error:
                    problems.append(str(error))
    elif not dynamic:
        problems.append("static image without section headers: startup-applied relocations cannot be located")
    ranges = sorted({(start - image.image_base, end - image.image_base, label) for start, end, label in ranges})
    if problems:
        return Parsed("indeterminate", ranges, "; ".join(problems))
    return Parsed("complete", ranges)
