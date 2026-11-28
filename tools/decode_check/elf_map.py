"""ELF64 x86-64 file mapping of G1 decode_check: ``elf-loader-rules-4``.
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
- Pages two PT_LOADs share are ``ambiguous`` (the later mmap replaces the page); any
  byte two ranges cover is ambiguous (pe_map.disjoint).
- Bytes outside every PT_LOAD are outside the mapping.
- Loader-written ranges: every relocation target the runtime applies (DT_RELA,
  DT_REL, DT_JMPREL, DT_RELR / DT_ANDROID_RELR and every SHF_ALLOC SHT_RELA /
  SHT_REL / SHT_RELR section), the whole PT_DYNAMIC (ld.so may adjust entries
  in place, DT_DEBUG), and GOT[1], GOT[2] at DT_PLTGOT (lazy binding). Width
  per relocation type from WIDTHS; COPY uses the symbol's st_size; an unknown
  type is 16 bytes (the largest x86-64 write, TLSDESC). Android packed
  relocations (DT_ANDROID_REL / DT_ANDROID_RELA) are not parsed: indeterminate.
  The PLT range glibc may rewrite (DT_X86_64_PLT / DT_X86_64_PLTSZ, -z mark-plt) is
  written too, and so is each JUMP_SLOT's PLT entry [align_down(r_addend, PLTENT), +PLTENT)
  (glibc-2.39-288-gce65d944e3 dl-machine.h 578-678: the union of IBT off / on); DT_X86_64_PLT
  without DT_X86_64_PLTENT, an unsupported PLTENT, a PLTSZ that is not a multiple of it, REL
  relocations and a truncated table are indeterminate (rules v4). A table tag without its size tag, a duplicated write-affecting tag
  (glibc keeps the last) or more than one PT_DYNAMIC is indeterminate (rules v2).
  A static image (no PT_DYNAMIC) without section headers is indeterminate: its
  startup-applied relocations cannot be located. Non-SHF_ALLOC relocation
  sections (--emit-relocs) are link-time only and are not loader writes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import struct

from pe_map import Parsed, Range, disjoint

RULES = "elf-loader-rules-4"
ARM64_RULES = "elf-aarch64-loader-rules-1"
EM_X86_64, EM_AARCH64 = 62, 183
ET_EXEC, ET_DYN = 2, 3
PT_LOAD, PT_DYNAMIC = 1, 2
PAGE = 0x1000
ARM64_PAGES = (0x1000, 0x4000, 0x10000)
U64_END = 1 << 64
SHF_ALLOC = 0x2
SHT_RELA, SHT_REL, SHT_RELR = 4, 9, 19

DT = {"PLTRELSZ": 2, "PLTGOT": 3, "SYMTAB": 6, "RELA": 7, "RELASZ": 8, "RELAENT": 9, "SYMENT": 11, "REL": 17,
      "RELSZ": 18, "RELENT": 19, "PLTREL": 20, "JMPREL": 23, "RELRSZ": 35, "RELR": 36, "RELRENT": 37,
      "ANDROID_REL": 0x6000000F, "ANDROID_RELSZ": 0x60000010, "ANDROID_RELA": 0x60000011,
      "ANDROID_RELASZ": 0x60000012, "ANDROID_RELR": 0x6FFFE000, "ANDROID_RELRSZ": 0x6FFFE001,
      "ANDROID_RELRENT": 0x6FFFE003, "X86_64_PLT": 0x70000000, "X86_64_PLTSZ": 0x70000001,
      "X86_64_PLTENT": 0x70000003, "RELACOUNT": 0x6FFFFFF9, "RELCOUNT": 0x6FFFFFFA,
      "CREL": 0x40000026, "TLSDESC_PLT": 0x6FFFFEF6, "TLSDESC_GOT": 0x6FFFFEF7}
# tags whose value decides a loader-written range: a duplicate is indeterminate (glibc keeps the last value)
WRITE_TAGS = ("RELA", "RELASZ", "RELAENT", "REL", "RELSZ", "RELENT", "JMPREL", "PLTRELSZ", "PLTREL", "RELR",
              "RELRSZ", "RELRENT", "ANDROID_REL", "ANDROID_RELSZ", "ANDROID_RELA", "ANDROID_RELASZ", "ANDROID_RELR",
              "ANDROID_RELRSZ", "ANDROID_RELRENT", "PLTGOT", "SYMTAB", "SYMENT", "X86_64_PLT", "X86_64_PLTSZ",
              "X86_64_PLTENT")

# bytes written per R_X86_64_* type (psABI); NONE (0) and TLSDESC_CALL (35) write nothing; COPY (5) uses st_size
WIDTHS = {1: 8, 2: 4, 3: 4, 4: 4, 6: 8, 7: 8, 8: 8, 9: 4, 10: 4, 11: 4, 12: 2, 13: 2, 14: 1, 15: 1, 16: 8, 17: 8,
          18: 8, 19: 4, 20: 4, 21: 4, 22: 4, 23: 4, 24: 8, 25: 8, 26: 4, 27: 8, 28: 8, 29: 8, 30: 8, 31: 8, 32: 4,
          33: 8, 34: 4, 36: 16, 37: 8, 38: 8, 41: 4, 42: 4, 43: 4, 44: 4}
NO_WRITE = {0, 35}
R_COPY = 5
UNKNOWN_WIDTH = 16
NAMES = {1: "64", 2: "PC32", 5: "COPY", 6: "GLOB_DAT", 7: "JUMP_SLOT", 8: "RELATIVE", 10: "32", 11: "32S",
         16: "DTPMOD64", 17: "DTPOFF64", 18: "TPOFF64", 36: "TLSDESC", 37: "IRELATIVE"}
# AAELF64 LP64 dynamic relocations whose write extent this model knows.
ARM64_WRITES = {
    257: ("ABS64", 8), 1025: ("GLOB_DAT", 8), 1026: ("JUMP_SLOT", 8), 1027: ("RELATIVE", 8),
    1028: ("TLS_DTPMOD", 8), 1029: ("TLS_DTPREL", 8), 1030: ("TLS_TPREL", 8),
    1031: ("TLSDESC", 16), 1032: ("IRELATIVE", 8),
}


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
    phdrs: list = field(default_factory=list)       # every program header tuple (G2b; not in mapping_id)

    def at(self, rva: int) -> Range | None:
        for item in self.ranges:
            if item.start <= rva < item.end:
                return item
        return None


class _Unreadable(Exception):
    pass


def _pow2(value):
    return value > 0 and value & (value - 1) == 0


def _floor(value, page):
    return value // page * page


def _ceil(value, page):
    return (value + page - 1) // page * page


def parse(data: bytes, *, arm64_page: int | None = None) -> ElfImage:
    if arm64_page is not None and arm64_page not in ARM64_PAGES:
        raise ValueError("unsupported AArch64 page size")
    try:
        image = _parse(data, arm64_page)
    except (struct.error, IndexError, ValueError) as error:
        image = ElfImage(False, f"header parse failed: {error}")
    if arm64_page is not None:
        image.rules = ARM64_RULES
        image.header_fields["modeled_page_size"] = arm64_page
    return _finish(image)


def _parse(data: bytes, arm64_page: int | None) -> ElfImage:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return ElfImage(False, "not an ELF image")
    if data[4] != 2 or data[5] != 1 or data[6] != 1:
        return ElfImage(False, "not ELFCLASS64 / ELFDATA2LSB / EV_CURRENT")
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    e_phoff, e_shoff = struct.unpack_from("<QQ", data, 32)
    e_phentsize, e_phnum, e_shentsize, e_shnum = struct.unpack_from("<HHHH", data, 54)
    arm64 = arm64_page is not None
    page = arm64_page if arm64 else PAGE
    if arm64 and e_machine != EM_AARCH64:
        return ElfImage(False, f"machine {e_machine} is not EM_AARCH64")
    if not arm64 and e_machine != EM_X86_64:
        return ElfImage(False, f"machine {e_machine} is not EM_X86_64")
    if arm64 and (struct.unpack_from("<I", data, 20)[0] != 1 or struct.unpack_from("<H", data, 52)[0] != 64
                  or e_phoff < 64 or e_phnum == 0xFFFF):
        return ElfImage(False, "malformed or unsupported AArch64 ELF header")
    if e_type not in (ET_EXEC, ET_DYN):
        return ElfImage(False, f"e_type {e_type} is not ET_EXEC / ET_DYN")
    if e_phentsize != 56 or e_phnum == 0 or e_phoff + 56 * e_phnum > len(data):
        return ElfImage(False, "program header table outside the file or malformed")
    phdrs = [struct.unpack_from("<IIQQQQQQ", data, e_phoff + 56 * index) for index in range(e_phnum)]
    if arm64 and any(p[0] == PT_LOAD and (p[5] > p[6] or p[3] + p[6] > U64_END) for p in phdrs):
        return ElfImage(False, "invalid PT_LOAD memory extent")
    loads = [(index, p) for index, p in enumerate(phdrs) if p[0] == PT_LOAD and p[6] > 0]
    if not loads:
        return ElfImage(False, "no PT_LOAD segment")
    image_base = _floor(min(p[3] for _, p in loads), page)
    fields = {"e_type": e_type, "e_machine": e_machine, "e_phoff": e_phoff, "e_phnum": e_phnum,
              "e_shoff": e_shoff, "e_shnum": e_shnum, "e_shentsize": e_shentsize, "image_base": image_base,
              "file_size": len(data), "file_sha256": hashlib.sha256(data).hexdigest()}
    image = ElfImage(True, image_base=image_base, fixed_base=e_type == ET_EXEC, e_type=e_type, header_fields=fields)
    image.phdrs = phdrs
    ranges = []
    for ordinal, (phdr_index, (_, flags, offset, vaddr, _, filesz, memsz, align)) in enumerate(loads):
        index = phdr_index if arm64 else ordinal
        why = ""
        if filesz > memsz:
            why = "p_filesz > p_memsz"
        elif offset + filesz > len(data):
            why = "segment file range past the end of the file"
        elif align not in (0, 1) and not _pow2(align):
            why = "p_align not a power of two"
        elif arm64 and align > 1 and (vaddr - offset) % align:
            why = "p_vaddr and p_offset not congruent modulo p_align"
        elif (vaddr - offset) % page:
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
    pages = sorted((_floor(p[3], page), _ceil(p[3] + p[6], page)) for _, p in loads)
    for index, (a0, a1) in enumerate(pages):
        for following in range(index + 1, len(pages)):
            b0, b1 = pages[following]
            if b0 >= a1:
                break
            if a0 < b1:
                shared.append((max(a0, b0) - image_base, min(a1, b1) - image_base))
    image.ranges = disjoint(_overlay_ambiguous(ranges, shared, "PT_LOAD segments share a page"))
    image.header_fields["writable_code_segments"] = [item["index"] for item in image.segments
                                                     if item["flags"] & 3 == 3]   # (PF_X | PF_W)
    image.written = _written(image, data, phdrs, e_shoff, e_shnum, e_shentsize, arm64=arm64)
    image.relocations = Parsed("absent", why="ELF relocations are loader writes: listed under written")
    return image


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
    payload = {"rules": image.rules, "fields": image.header_fields, "ok": image.ok,
               "ranges": [[r.start, r.end, r.kind, r.file_offset] for r in image.ranges]}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    image.mapping_id = hashlib.sha256(canonical).hexdigest()
    if image.relocations is None:
        image.relocations = Parsed("indeterminate", why=image.why or "no mapping")
    if image.written is None:
        image.written = Parsed("indeterminate", why=image.why or "no mapping")
    return image


def _read(image: ElfImage, data: bytes, va: int, size: int, *, file_only=False) -> bytes:
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
            if file_only:
                raise _Unreadable("table is not entirely file-backed")
            out += bytes(take)
        else:
            offset = item.file_offset + (cursor - item.start)
            if offset + take > len(data):
                raise _Unreadable("past the end of the file")
            out += data[offset:offset + take]
        cursor += take
    return bytes(out)


def _maps_file_table(image, va, offset, size):
    start = va - image.image_base
    span = image.at(start)
    return (span is not None and span.kind == "file" and start + size <= span.end
            and span.file_offset + start - span.start == offset)


def _relocation_targets(table: bytes, entsize: int, rela: bool, symbol_size, label: str, *, arm64=False) -> list:
    expected = 24 if rela else 16
    if entsize != expected or len(table) % expected:
        raise _Unreadable(f"{label}: entry size {entsize} is not {expected}")
    out = []
    for cursor in range(0, len(table), expected):
        offset, info = struct.unpack_from("<QQ", table, cursor)
        kind, symbol = info & 0xFFFFFFFF, info >> 32
        if arm64:
            if kind in (0, 256):  # R_AARCH64_NONE and its withdrawn alias.
                continue
            if kind not in ARM64_WRITES:
                raise _Unreadable(f"{label}: unsupported AArch64 relocation {kind}")
            name, width = ARM64_WRITES[kind]
            out.append((offset, offset + width, f"R_AARCH64_{name}"))
            continue
        if kind in NO_WRITE:
            continue
        if kind == R_COPY:
            width = symbol_size(symbol)
        else:
            width = WIDTHS.get(kind, UNKNOWN_WIDTH)
        name = NAMES.get(kind, str(kind)) if kind in WIDTHS or kind == R_COPY else f"{kind}-unknown-width"
        out.append((offset, offset + width, f"R_X86_64_{name}"))
    return out


def _relr_targets(table: bytes, entsize: int, label: str, *, arm64=False) -> list:
    if entsize != 8 or len(table) % 8:
        raise _Unreadable(f"{label}: RELR entry size {entsize} is not 8")
    out = []
    base = None
    for cursor in range(0, len(table), 8):
        entry, = struct.unpack_from("<Q", table, cursor)
        if entry & 1 == 0:
            if arm64 and entry % 8:
                raise _Unreadable(f"{label}: unaligned RELR address")
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


def _plt_entries(image, data, tags, plt_size, ranges) -> list:
    """The PLT entry bytes glibc may rewrite per JUMP_SLOT (Astra impl r4 s1; glibc-2.39-288-gce65d944e3
    sysdeps/x86_64/dl-machine.h 578-678, same start / end in 2.41): with E = DT_X86_64_PLTENT and
    A = load_bias + r_addend, IBT off writes [align_down(A, E), +E), IBT on [A, +E); runtime IBT is not
    known here, so the union [align_down(A, E), +E) is written. Only R_X86_64_JUMP_SLOT; written means "may
    be written" (glibc may skip an entry). The load bias is page aligned, so aligning the link VA is the same
    when E <= the page. Returns the problems (-> indeterminate)."""
    entry = tags[DT["X86_64_PLTENT"]]
    if entry < 16 or not _pow2(entry) or entry > PAGE:
        return [f"DT_X86_64_PLTENT {entry} is not a supported power of two (16 .. page)"]
    if plt_size < entry or plt_size % entry:
        return [f"DT_X86_64_PLTSZ {plt_size} is not a positive multiple of DT_X86_64_PLTENT {entry}"]
    if DT["JMPREL"] not in tags:
        return []                      # (no JUMP_SLOT table: the declared range only)
    if DT["PLTRELSZ"] not in tags:
        return []                      # (reported by the table / size rule)
    if tags.get(DT["PLTREL"], DT["RELA"]) != DT["RELA"]:
        return ["PLT rewrite with DT_PLTREL REL: the JUMP_SLOT addends are not determinable"]
    try:
        table = _read(image, data, tags[DT["JMPREL"]], tags[DT["PLTRELSZ"]])
    except _Unreadable as error:
        return [f"DT_JMPREL (PLT rewrite entries): {error}"]
    if len(table) % 24:
        return ["DT_JMPREL (PLT rewrite entries): truncated RELA table"]
    for cursor in range(0, len(table), 24):
        _, info, addend = struct.unpack_from("<QQq", table, cursor)
        if info & 0xFFFFFFFF != 7:     # (R_X86_64_JUMP_SLOT only: not IRELATIVE)
            continue
        start = addend // entry * entry
        if addend < 0 or start + entry > 1 << 64:
            return [f"PLT rewrite entry address {addend:#x} out of range"]
        ranges.append((start, start + entry, "plt-rewrite-entry"))
    return []


def _written(image, data, phdrs, e_shoff, e_shnum, e_shentsize, *, arm64=False) -> Parsed:
    ranges = []
    problems = []
    dynamic = [p for p in phdrs if p[0] == PT_DYNAMIC]
    tags = {}
    if len(dynamic) > 1:
        problems.append("more than one PT_DYNAMIC")
    if dynamic:
        _, _, offset, vaddr, _, filesz, memsz, _ = dynamic[0]
        ranges.append((vaddr, vaddr + memsz, "dynamic"))
        try:
            if arm64 and (filesz < 16 or filesz % 16 or filesz > memsz
                          or not _maps_file_table(image, vaddr, offset, filesz)):
                raise _Unreadable("PT_DYNAMIC does not identify a single complete file table")
            raw = _read(image, data, vaddr, filesz, file_only=arm64)
            seen = {}
            for cursor in range(0, len(raw) - 15, 16):
                tag, value = struct.unpack_from("<qQ", raw, cursor)
                if tag == 0:
                    break
                seen[tag] = seen.get(tag, 0) + 1
                tags[tag] = value   # (glibc: the last value wins)
            else:
                if arm64:
                    problems.append("PT_DYNAMIC without DT_NULL")
            relevant = (*WRITE_TAGS, "RELACOUNT", "RELCOUNT") if arm64 else WRITE_TAGS
            duplicated = sorted(name for name in relevant if seen.get(DT[name], 0) > 1)
            if duplicated:
                problems.append("duplicated dynamic tags: " + ", ".join("DT_" + name for name in duplicated))
        except _Unreadable as error:
            problems.append(f"PT_DYNAMIC: {error}")

    def dynamic_symbol_size(symbol):
        if DT["SYMTAB"] not in tags:
            raise _Unreadable("COPY relocation without DT_SYMTAB")
        entsize = tags.get(DT["SYMENT"], 24)
        return struct.unpack_from("<Q", _read(image, data, tags[DT["SYMTAB"]] + entsize * symbol, 24), 16)[0]

    if tags:
        for table_tag, size_tag in (("RELA", "RELASZ"), ("REL", "RELSZ"), ("JMPREL", "PLTRELSZ"), ("RELR", "RELRSZ"),
                                    ("ANDROID_RELR", "ANDROID_RELRSZ"), ("X86_64_PLT", "X86_64_PLTSZ")):
            if DT[table_tag] in tags and DT[size_tag] not in tags:
                problems.append(f"DT_{table_tag} without DT_{size_tag}")
            if arm64 and DT[size_tag] in tags and DT[table_tag] not in tags:
                problems.append(f"DT_{size_tag} without DT_{table_tag}")
        if arm64 and any(0x70000000 <= tag <= 0x7FFFFFFF for tag in tags):
            problems.append("unsupported processor-specific AArch64 dynamic tag")
        if arm64:
            for name in ("CREL", "TLSDESC_PLT", "TLSDESC_GOT"):
                if DT[name] in tags:
                    problems.append(f"DT_{name} is unsupported for AArch64")
            for table, count in (("RELA", "RELACOUNT"), ("REL", "RELCOUNT")):
                if DT[count] in tags and DT[table] not in tags:
                    problems.append(f"DT_{count} without DT_{table}")
            for table in ("RELA", "REL", "RELR", "ANDROID_RELR"):
                if DT[table] in tags and DT[table + "ENT"] not in tags:
                    problems.append(f"DT_{table} without DT_{table}ENT")
        if not arm64 and DT["X86_64_PLT"] in tags and DT["X86_64_PLTENT"] not in tags:
            problems.append("DT_X86_64_PLT without DT_X86_64_PLTENT")
        if not arm64 and DT["X86_64_PLT"] in tags and DT["X86_64_PLTSZ"] in tags:
            plt, plt_size = tags[DT["X86_64_PLT"]], tags[DT["X86_64_PLTSZ"]]
            ranges.append((plt, plt + plt_size, "plt-rewrite"))
            if DT["X86_64_PLTENT"] in tags:
                problems.extend(_plt_entries(image, data, tags, plt_size, ranges))
        for kind in ("ANDROID_REL", "ANDROID_RELA"):
            if DT[kind] in tags or (arm64 and DT[kind + "SZ"] in tags):
                problems.append(f"DT_{kind}: Android packed relocations are not parsed")
        tables = [("RELA", "RELASZ", tags.get(DT["RELAENT"], 24), True),
                  ("REL", "RELSZ", tags.get(DT["RELENT"], 16), False)]
        if DT["JMPREL"] in tags:
            plt_type = tags.get(DT["PLTREL"], None if arm64 else DT["RELA"])
            if arm64 and plt_type not in (DT["REL"], DT["RELA"]):
                problems.append("DT_JMPREL without a supported DT_PLTREL")
            else:
                plt_rela = plt_type == DT["RELA"]
                tables.append(("JMPREL", "PLTRELSZ", 24 if plt_rela else 16, plt_rela))
        for start, size, entsize, rela in tables:
            if DT[start] not in tags:
                continue
            try:
                table = _read(image, data, tags[DT[start]], tags.get(DT[size], 0), file_only=arm64)
                if arm64 and start in ("REL", "RELA"):
                    count_tag = start + "COUNT"
                    count = tags.get(DT[count_tag], 0)
                    stride = 24 if rela else 16
                    if count > len(table) // stride or any(
                            struct.unpack_from("<Q", table, i * stride + 8)[0] != 1027 for i in range(count)):
                        problems.append(f"DT_{count_tag} disagrees with the R_AARCH64_RELATIVE prefix")
                ranges.extend(_relocation_targets(table, entsize, rela, dynamic_symbol_size, f"DT_{start}",
                                                  arm64=arm64))
            except (_Unreadable, struct.error) as error:
                problems.append(f"DT_{start}: {error}")
        for start, size, ent in (("RELR", "RELRSZ", "RELRENT"), ("ANDROID_RELR", "ANDROID_RELRSZ", "ANDROID_RELRENT")):
            if DT[start] not in tags:
                continue
            try:
                table = _read(image, data, tags[DT[start]], tags.get(DT[size], 0), file_only=arm64)
                ranges.extend(_relr_targets(table, tags.get(DT[ent], 8), f"DT_{start}", arm64=arm64))
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
            for _, sh_type, flags, va, offset, size, link, _, _, entsize in sections:
                if arm64 and flags & SHF_ALLOC and sh_type in (0x60000001, 0x60000002, 0x6FFFFF00):
                    problems.append("unsupported allocated Android relocation section")
                if arm64 and flags & SHF_ALLOC and sh_type == 0x40000014:
                    problems.append("unsupported allocated SHT_CREL section")
                if arm64 and flags & SHF_ALLOC and sh_type == 0x70000004:
                    problems.append("unsupported allocated SHT_AARCH64_AUTH_RELR section")
                if sh_type not in (SHT_RELA, SHT_REL, SHT_RELR) or not flags & SHF_ALLOC:
                    continue
                if offset + size > len(data):
                    problems.append("relocation section past the end of the file")
                    continue
                if arm64 and not _maps_file_table(image, va, offset, size):
                    problems.append("allocated relocation section does not name its mapped file bytes")
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
                        ranges.extend(_relr_targets(table, entsize if arm64 else entsize or 8, "SHT_RELR",
                                                    arm64=arm64))
                    else:
                        ranges.extend(_relocation_targets(table, entsize, sh_type == SHT_RELA, section_symbol_size,
                                                          "SHT_RELA" if sh_type == SHT_RELA else "SHT_REL", arm64=arm64))
                except _Unreadable as error:
                    problems.append(str(error))
    elif arm64 and (e_shoff or e_shnum):
        problems.append("inconsistent or extended AArch64 section header table")
    elif not dynamic:
        problems.append("static image without section headers: startup-applied relocations cannot be located")
    if arm64 and any(not any(s["state"] == "mapped" and s["vaddr"] <= start < end <= s["vaddr"] + s["memsz"]
                             for s in image.segments) for start, end, _ in ranges):
        problems.append("loader write range is outside an eligible PT_LOAD")
    ranges = sorted({(start - image.image_base, end - image.image_base, label) for start, end, label in ranges})
    if problems:
        return Parsed("indeterminate", ranges, "; ".join(problems))
    return Parsed("complete", ranges)
