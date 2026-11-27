"""G2b code-byte facts (design_tbr_g2b_code_facts r1 + r2 + r3; closed G2 design r5 s5 / s9).

File layer (this part): Bundle-independent parsing of the original file into file coordinates (offsets from the
map's ``image_base``: the PE RVA / the ELF offset from the lowest PT_LOAD page). Two byte bases (r2 E1):

- ``file_record``: what the file records as lookup data (import / delay-import tables, ILT and initial FirstThunk,
  ELF dynamic tags, relocation tables, dynsym / dynstr, section headers, the exception directory and UNWIND_INFO
  read as table structure). Read only from ``file`` ranges of the map (never zero-fill or ambiguous), allowed inside
  loader-written ranges: the basis is the pre-load value.
- ``file_runtime``: bytes as they are at run time (register-pointed strings). Additionally not loader-written, not
  relocated, and the written / relocation parses must be complete (else MAP_INDETERMINATE).

Everything here reads the file through the G1 maps (``pe_map`` / ``elf_map``); nothing reads Ghidra data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import struct
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from dataclasses import replace

FACTS_RULE = "g2b-1"
PREMISE = "image-code-unmodified-at-runtime"
IMPORT_PREMISE = "import-slot-holds-loader-bound-import"
LINEAR_PREMISE = "linear-entry-at-first-path-row"
VERIFIED_THRESHOLD = 8_388_608          # canonical UTF-8 bytes of all explicit verified lists of one Bundle (r3 E6)

# closed reason-code enum (r1 s1); a code not listed here is a programming error
REASONS = frozenset({
    # byte bases
    "ZERO_FILL", "AMBIGUOUS_MAPPING", "LOADER_WRITTEN", "RELOCATED", "OUTSIDE_FILE", "TRUNCATED",
    "NONCONTIGUOUS", "MAP_INDETERMINATE",
    # regions / unwind
    "HANDLER_DATA_LENGTH", "UNWIND_VERSION", "UNWIND_FLAGS", "UNWIND_INDIRECT", "CHAIN_CYCLE", "NO_SECTION_HEADERS",
    "EH_FRAME_PTR_ENCODING", "EH_FRAME_PTR_OMITTED", "SECTION_NOT_LOADED", "MAP_NOT_OK",
    # trap
    "NO_WINDOW", "GLOBAL_REASON", "BALLOT_MISSING", "RELOCATED_OPCODE", "TRAP_FORM_UNDECIDED", "VENDOR_SPLIT_FORM",
    "ALL_INVALID_NOT_CE", "NO_ABI_BASIS", "G2C",
    # imports and transfers
    "TRANSFER_UNBOUND", "SEGMENT_BASE", "POINTER_WIDTH", "SPACE_MISMATCH", "VENDOR_VIEW_CONFLICT", "FORM_MISMATCH",
    "SLOT_NOT_IMPORT", "PARSER_UNSUPPORTED", "SLOT_NAME_U", "NO_IMPORT_DIRECTORY", "IMPORT_BY_ORDINAL",
    "TARGET_LIFT_U", "ELF_STUB_UNSUPPORTED", "ELF_RELOC_UNSUPPORTED", "MULTI_HOP", "TARGET_NOT_ROW_START",
    "TARGET_OUTSIDE_ROWS", "INDEX_INCOMPLETE", "COMPUTED_TARGET", "BOUND_IAT_NO_ILT", "ILT_ENTRY_INVALID",
    "DELAY_FORMAT", "SYM_COUNT_U", "NO_RWX_REGISTER",
    # stores / values
    "STORE_ADDRESS_NOT_CONSTANT", "STORE_WIDTH_U", "STORE_SPACE_U", "ADDRESS_WRAP", "TARGET_MAPPING_U",
    "INTRA_ROW_FLOW",
    # survey
    "NOT_X86",
})


class Unread(Exception):
    """A read that fails a byte-basis test; ``reason`` is in REASONS."""

    def __init__(self, reason, detail=""):
        assert reason in REASONS, reason
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


def record_read(image, data, rva, size):
    if size < 0:
        raise Unread("OUTSIDE_FILE")
    if not size:
        return b"", {"file_record": [0, 0]}

    first = None
    cursor = rva
    end = rva + size
    while cursor < end:
        item = image.at(cursor)
        if item is None:
            raise Unread("OUTSIDE_FILE" if cursor == rva else "TRUNCATED")
        if item.kind != "file":
            raise Unread({"zero": "ZERO_FILL", "ambiguous": "AMBIGUOUS_MAPPING"}
                         .get(item.kind, "OUTSIDE_FILE"))
        offset = item.file_offset + cursor - item.start
        if first is None:
            first = offset
        if offset != first + cursor - rva:
            raise Unread("NONCONTIGUOUS")
        stop = min(end, item.end)
        if stop <= cursor or offset < 0 or offset + stop - cursor > len(data):
            raise Unread("OUTSIDE_FILE")
        cursor = stop
    return data[first:first + size], {"file_record": [first, size]}


def runtime_read(image, data, rva, size):
    for parsed, why in ((image.written, "LOADER_WRITTEN"), (image.relocations, "RELOCATED")):
        if parsed is None or parsed.state not in ("complete", "absent"):
            raise Unread("MAP_INDETERMINATE")
        if _touches(parsed, rva, rva + size):
            raise Unread(why)
    raw, basis = record_read(image, data, rva, size)
    return raw, {"file_runtime": basis["file_record"]}


def record_cstring(image, data, rva, limit=4096):
    _, ref = record_read(image, data, rva, 1)
    off = ref["file_record"][0]
    nul = data.find(b"\0", off, off + limit)
    if nul < off:
        raise Unread("TRUNCATED")
    raw, ref = record_read(image, data, rva, nul - off + 1)
    return raw[:-1].decode("latin-1"), ref


@dataclass
class Region:
    """A file-coordinate region (r5 s5): ``end`` None means U (start known)."""
    start: int
    end: int | None
    role: str                       # code | unwind_metadata
    executable: bool | None = None
    writable: bool | None = None
    name: str = ""
    basis: dict = field(default_factory=dict)


@dataclass
class FileFacts:
    format: str                     # pe | elf | none
    ok: bool
    why: str = ""
    image_base: int = 0
    code: list = field(default_factory=list)          # [Region]
    unwind: list = field(default_factory=list)        # [Region] (merged where contiguous)
    diagnostics: list = field(default_factory=list)   # [{"range": {start, end|None} | "what": str, reason, basis}]
    imports: dict = field(default_factory=dict)       # slot coordinate -> {dll?, name, ordinal?, kind, basis}
    import_state: str = "absent"                      # absent | complete | partial | indeterminate
    import_problems: list = field(default_factory=list)   # [{"range"|"what", reason, basis?}]
    slot_failures: dict = field(default_factory=dict)  # slot coordinate -> reason
    import_ranges: list = field(default_factory=list)  # [(start, end)] of every parsed import slot table (IAT / GOT)


def _diag(out, reason, *, start=None, end=None, what=None, basis=None):
    assert reason in REASONS, reason
    item = {"reason": reason}
    if start is not None:
        item["range"] = {"start": start, "end": end}
    else:
        item["what"] = what
    if basis:
        item["basis"] = basis
    out.append(item)


def file_facts(image, data):
    if image is None or not image.ok:
        return FileFacts(getattr(image, "format", "none"), False,
                         getattr(image, "why", "no map"), import_state="indeterminate")

    out = FileFacts(image.format, True, image_base=image.image_base)
    if image.format == "pe":
        for s in image.sections:
            flags = s["characteristics"]
            if flags & SCN_EXECUTE:
                region = Region(s["va"], s["va"] + s["vsize"], "code", True,
                                bool(flags & SCN_WRITE), s["name"],
                                {"pe_section": [s["index"], s["name"], flags]})
                _code_region(out, image, region, s["state"] == "mapped")
        for n, directory in enumerate(image.directories):
            if n == 3 and any(directory):
                _pe_unwind(image, data, directory, out)
            if n in (1, 13) and any(directory):
                out.import_state = "complete"
                _pe_table(image, data, directory, n, out)
    elif image.format == "elf":
        _elf_file(image, data, out)
    else:
        return FileFacts(image.format, False, "unsupported format", import_state="indeterminate")

    if (out.import_problems or out.slot_failures) and out.import_state != "indeterminate":
        out.import_state = "partial"
    return out


# -- PE32+ ------------------------------------------------------------------------------------------------------------

SCN_EXECUTE, SCN_WRITE = 0x20000000, 0x80000000
UNW_EHANDLER, UNW_UHANDLER, UNW_CHAININFO = 1, 2, 4


def _pe_unwind(image, data, directory, out):
    start, size = directory
    ref = {"pe_directory": 3}
    out.unwind.append(Region(start, start + size, "unwind_metadata", name=".pdata", basis=ref))
    seen = set()

    for pos in range(start, start + size, 12):
        if pos + 12 > start + size:
            _issue(out.diagnostics, "TRUNCATED", pos, start + size, ref)
            break
        try:
            entry, parent = record_read(image, data, pos, 12)
        except Unread as exc:
            _issue(out.diagnostics, exc.reason, pos, pos + 12, ref)
            continue

        u = struct.unpack_from("<I", entry, 8)[0]
        path = set()
        while True:
            if u & 1 or u in path:
                _issue(out.diagnostics, "UNWIND_INDIRECT" if u & 1 else "CHAIN_CYCLE",
                       u, u + 4, parent)
                break
            if u in seen:
                break
            seen.add(u)
            path.add(u)
            lo, hi = u, u + 4
            known = 0
            basis = parent
            try:
                head, basis = runtime_read(image, data, u, 4)
                flags = head[0] >> 3
                if (head[0] & 7) not in (1, 2):
                    raise Unread("UNWIND_VERSION")
                if flags not in (0, 1, 2, 3, 4):
                    raise Unread("UNWIND_FLAGS")
                known = 4
                hi = u + 4 + 2 * ((head[2] + 1) & ~1)
                _, basis = runtime_read(image, data, u, hi - u)
                known = hi - u
                lo = hi
                hi += 12 if flags == 4 else 4 if flags else 0
                raw, whole = runtime_read(image, data, u, hi - u)
                out.unwind.append(Region(u, hi, "unwind_metadata", name=".xdata", basis=whole))
                if flags == 4:
                    parent = whole
                    u = struct.unpack_from("<I", raw, len(raw) - 4)[0]
                    continue
                if flags:
                    _issue(out.diagnostics, "HANDLER_DATA_LENGTH", hi, None, whole)
            except Unread as exc:
                if known:
                    out.unwind.append(Region(u, u + known, "unwind_metadata", name=".xdata", basis=basis))
                _issue(out.diagnostics, exc.reason, lo, hi, basis)
            break


# -- ELF64 ------------------------------------------------------------------------------------------------------------

PF_X, PF_W = 1, 2
PT_DYNAMIC, PT_GNU_EH_FRAME = 2, 0x6474E550
SHT_DYNSYM = 11
DT_STRTAB, DT_STRSZ, DT_HASH, DT_GNU_HASH = 5, 10, 4, 0x6FFFFEF5
R_GLOB_DAT, R_JUMP_SLOT = 6, 7


# -- trap sites (r2 E2, r3 E2) ------------------------------------------------------------------------------------

TRAP_BYTES = {0xCC: ("int3", 1, 3, None), 0xF1: ("int1", 1, 1, None)}   # opcode -> (form, length, vector, imm)
TRAP_FLOWS = {"int3", "int_n", "int1", "into", "syscall", "sysenter"}


def _ballot_ok(ballot):
    import decoders

    if not ballot:
        return False
    for vendor, names in (("intel", decoders.INTEL_VOTERS), ("amd", decoders.AMD_VOTERS)):
        votes = ballot.get(vendor, ())
        if sorted(d.voter for d in votes) != sorted(names) or any(d.amd != (vendor == "amd") for d in votes):
            return False
    return True


def ballot_digest(votes):
    import common_facts as cf
    import decoders

    by_name = {d.voter: d for d in votes}
    names = decoders.AMD_VOTERS if votes[0].amd else decoders.INTEL_VOTERS
    return cf.digest([by_name[name].as_json() for name in names])


def _byte_form(data):
    """(form, length, vector, immediate) from the verified bytes after a prefix run; ("none", None, ...) when the
    opcode is not a trap; None when the bytes end before the opcode is complete."""
    import compare

    prefix = compare._prefix_run(data)
    p = len(prefix)
    rest = data[p:]
    if not rest:
        return None
    op = rest[0]
    if op == 0xCD:
        if len(rest) < 2:
            return None
        return "int_n", p + 2, rest[1], rest[1]
    if op in TRAP_BYTES:
        form, length, vector, imm = TRAP_BYTES[op]
        return form, p + length, vector, imm
    if op == 0x0F:
        if len(rest) < 2:
            return None
        if rest[1] == 0x05:
            return "syscall", p + 2, None, None
        if rest[1] == 0x34:
            return "sysenter", p + 2, None, None
    if op == 0xCE:
        return "ce", p + 1, None, None
    return "none", None, None, None


def _vote_form(d):
    if d.flow == "int_n":
        return "int_n", d.int_vector
    return d.flow, None


def trap_outcome(result, ballot, window_bytes, global_reason=False):
    if result is None:
        return "unresolved", "GLOBAL_REASON" if global_reason else "NO_WINDOW"
    w = result.get("window") or {}
    data = (window_bytes or b"")[:w.get("verified", 0)]
    if not data:
        return "unresolved", "NO_WINDOW"
    if not _ballot_ok(ballot):
        return "unresolved", "BALLOT_MISSING"
    intel, amd = ballot["intel"], ballot["amd"]
    votes = (*intel, *amd)
    shape = _byte_form(data)
    undecided = "unresolved", "TRAP_FORM_UNDECIDED"
    invalid = all(d.status == "invalid" for d in votes)
    if invalid and (shape is None or shape[0] != "ce"):
        return *undecided, "ALL_INVALID_NOT_CE"
    if shape is None:
        return undecided
    form, length, vector, immediate = shape
    reloc = w.get("relocations") or ()

    if form == "none":
        n = votes[0].length
        if (not 0 < n <= len(data) or any(d.status != "ok" or d.length != n or
                _vote_form(d) != _vote_form(votes[0]) or d.flow in TRAP_FLOWS for d in votes)):
            return undecided
        for a, size, _ in reloc:
            for pos in range(max(a, 0), min(a + size, n)):
                if not all(any(x <= pos < x + width for x, width in d.value_fields) for d in votes):
                    return "unresolved", "RELOCATED_OPCODE"
        return None

    if length > len(data):
        return undecided
    if any(a < length and a + size > 0 for a, size, _ in reloc):
        return "unresolved", "RELOCATED_OPCODE"
    if form == "ce":
        return None if invalid else undecided

    want = (form, vector if form == "int_n" else None)

    def agreed(group):
        return all(d.status == "ok" and d.length == length and _vote_form(d) == want for d in group)

    if not agreed(intel):
        return undecided
    split = form == "sysenter"
    if not agreed(amd) and not (split and all(d.status == "invalid" for d in amd)):
        return undecided
    site = dict(form=form, length=length, vector=vector, immediate=immediate,
                syscall_abi=None if form in ("int1", "int3") else {"unobserved": "NO_ABI_BASIS"},
                basis={"decoders": {v: ballot_digest(ballot[v]) for v in ("intel", "amd")}})
    if split:
        site["form"] = {"unobserved": "VENDOR_SPLIT_FORM"}
        site["vendor_views"] = {"intel": {"form": "sysenter"},
                                "amd": {"form": "invalid_encoding",
                                        "basis": {"isa_conditions": "SYSENTER.f5.amd"}}}
    return "site", site


# -- Bundle binding (r1 s3 / s5, r2 E5 / E6, r3 E5 / E6) ----------------------------------------------------------

def name_table():
    """(kinds {kind: [names]}, sha256 of the file bytes): the table is data, versioned with FACTS_RULE."""
    import hashlib
    import json
    from pathlib import Path

    raw = Path(__file__).with_name("code_site_names.json").read_bytes()
    table = json.loads(raw)
    assert table["rule"] == FACTS_RULE
    return table["kinds"], hashlib.sha256(raw).hexdigest()


def _hx(value):
    return format(value, "x")


def _canonical(x):
    import json

    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _item_key(item):
    return (item["row"], -1 if item.get("op") is None else item["op"]) if "row" in item else (-1, -1)


def _groups(pairs):
    grouped = defaultdict(dict)
    for why, item in pairs:
        if why not in REASONS:
            raise ValueError(why)
        grouped[why][_canonical(item)] = item
    return [{"reason": why, "items": [items[k] for k in sorted(items, key=lambda k: (_item_key(items[k]), k))]}
            for why, items in sorted(grouped.items())]


def _union_length(intervals):
    total, end = 0, None
    for a, b in sorted(intervals):
        if end is None or a > end:
            total += b - a
            end = b
        elif b > end:
            total += b - end
            end = b
    return total


class CodeBinder:
    def __init__(self, ff, base, space, rows, code_rows, row_set_sha256, missing=()):
        import common_facts as cf

        self.ff, self.base, self.space, self.rows = ff, base, space, rows
        self.keys = [cf.rr(r) for r in rows]
        self.proofs = [code_rows[k] for k in self.keys]
        self.va = [int(r["offset"], 16) for r in rows]
        self.digest = row_set_sha256
        self.missing = sorted(missing)

    def _range(self, start, end, why="SECTION_EXTENT_U"):
        return {"space": self.space, "load_base": _hx(self.base), "start": _hx(self.base + start),
                "end": {"unobserved": why} if end is None else _hx(self.base + end)}

    def diagnostic(self, d):
        why = d["reason"]
        if "range" in d:
            result = {"reason": why, "scope_item": {"basis": d["basis"],
                      "range": self._range(**d["range"], why=why)}}
        else:
            result = dict(d)
        if "file_runtime" in d["basis"]:
            result["holds_if"] = [PREMISE]
        return result

    def coverage(self, kind, method, unresolved=(), unsupported=(), ranges=(), groups=None):
        arm = method == "a64_instruction"
        excluded = [{"row": i, "reason": "NOT_A64" if arm else "NOT_X86"}
                    for i, p in enumerate(self.proofs) if p.isa != ("aarch64" if arm else "x86-64")]
        scope = {"facts_rows": self.digest, "excluded": excluded}
        if len(excluded) == len(self.rows):
            scope["empty"] = True
        return dict(kind=kind, method=method, rows_examined=scope, ranges_examined=list(ranges),
                    unresolved=_groups(unresolved) if groups is None else groups,
                    unsupported=_groups(unsupported), missing_functions=self.missing)

    def program_code(self, sha, imports=None):
        regions = []
        diagnostics = [self.diagnostic(d) for d in self.ff.diagnostics]
        unknown = {(d["range"]["start"], _canonical(d["basis"])): d["reason"] for d in self.ff.diagnostics
                   if "range" in d and d["range"]["end"] is None}
        for r in self.ff.code + self.ff.unwind:
            why = unknown.get((r.start, _canonical(r.basis)), "SECTION_EXTENT_U") if r.end is None else None
            item = dict(range=self._range(r.start, r.end, why), role=r.role, name=r.name, basis=r.basis)
            if r.role == "code":
                item.update(executable=r.executable, writable=r.writable)
            if "file_runtime" in r.basis:
                item["holds_if"] = [PREMISE]
            regions.append(item)

        lengths = [p.verified for p in self.proofs]
        verified, totals = verified_lists(self.rows, regions, lengths)
        enc = verified_encoding(len(_canonical(verified)))
        out = dict(premise=PREMISE, name_table_sha256=sha,
                   file=dict(format=self.ff.format, ok=self.ff.ok, why=self.ff.why),
                   regions=regions, diagnostics=diagnostics, verified_encoding=enc)
        for r, v, total in zip(regions, verified, totals, strict=True):
            r["verified_bytes"] = total
            if enc["form"] == "explicit":
                r["verified"] = v
        if enc["form"] == "compact":
            out.update(verified_lengths=lengths, verified_rule={"per_row_window": self.digest})
        out["rows_outside_code"] = [i for i, a in enumerate(self.va) if self.rows[i]["space"] != self.space or
                                    not any(r.start <= a - self.base < r.end for r in self.ff.code)]

        sites, unresolved, syscalls, arm, details = [], [], [], [], Counter()
        for i, p in enumerate(self.proofs):
            at = {"row": i, "op": None}
            if p.isa == "aarch64":
                arm.append(("G2C", at))
            if not p.trap:
                continue
            state, value, *detail = p.trap
            if state == "unresolved":
                unresolved.append((value, at))
                details.update(detail)
                continue
            site = dict(value, row=i, kind="trap_instruction", symbol=None, arguments=[], holds_if=[PREMISE],
                        basis=dict(value["basis"], **window_ref(self.rows, i)))
            sites.append(site)
            if "vendor_views" in site or site["form"] in ("syscall", "int_n"):
                syscalls.append(("NO_ABI_BASIS", at))

        surveys = [self.coverage("trap_instruction", "x86_instruction", unresolved),
                   self.coverage("cache_maintenance", "syscall", unresolved, syscalls)]
        for kind in ("trap_instruction", "cache_maintenance"):
            surveys.append(self.coverage(kind, "a64_instruction", unsupported=arm))

        if imports is not None:
            found, us = imports.run()
            sites.extend(found)
            groups = _groups((w, it) for w, it in us if w not in ("NO_RWX_REGISTER", "PARSER_UNSUPPORTED"))
            rwx = _groups((w, it) for w, it in us if w == "NO_RWX_REGISTER")
            failures = [(w, it) for w, it in us if w == "PARSER_UNSUPPORTED"]
            problems = [self.diagnostic(d) for d in self.ff.import_problems]
            for d in problems:
                if "scope_item" in d:
                    failures.append((d["reason"], d["scope_item"]))
            for kind in sorted(set(imports.kind_of.values())):
                selected = sorted(groups + rwx, key=lambda g: g["reason"]) if kind == RWX_KIND else groups
                cov = self.coverage(kind, "import_transfer", unsupported=failures, groups=selected)
                cov["import_table"] = {"state": self.ff.import_state, "problems": problems}
                surveys.append(cov)

            found, us = imports.stores()
            sites.extend(found)
            ranges = [dict(range=r["range"], basis=r["basis"]) for r in regions if r["role"] == "code"]
            surveys.append(dict(self.coverage("code_write", "static_store", us, ranges=ranges),
                                write="static_store_candidate"))
        return dict(out, sites=sorted(sites, key=lambda s: (s["row"], s["kind"], s.get("op", -1))),
                    survey=surveys, trap_unresolved_details=dict(details))


def summary(code):
    if code["name_table_sha256"] != name_table()[1]:
        raise ValueError("name table digest mismatch")
    sites = code["sites"]
    counts = Counter(s["kind"] for s in sites)
    forms = Counter(s["form"] if isinstance(s["form"], str) else "vendor_split"
                    for s in sites if s["kind"] == "trap_instruction")
    api = Counter((s["symbol"]["name"], "candidate") for s in sites if s.get("candidate"))
    methods, unresolved, unsupported = {}, {}, {}
    for c in code["survey"]:
        k, m = c["kind"], c["method"]
        key = k + "/" + m
        if m == "import_transfer":
            selected = [s for s in sites if s["kind"] == k and "route" in s]
        elif m in ("x86_instruction", "static_store"):
            selected = [s for s in sites if s["kind"] == k and "route" not in s]
        else:
            selected = []
        for field, target in (("unsupported", unsupported), ("unresolved", unresolved)):
            target[key] = {g["reason"]: len(g["items"]) for g in c[field]}
        methods[key] = dict(sites=len(selected), candidates=sum(bool(s.get("candidate")) for s in selected),
                            excluded=len(c["rows_examined"]["excluded"]),
                            unresolved=unresolved[key], unsupported=unsupported[key])
        for g in c["unresolved"]:
            if g["reason"] == "NO_RWX_REGISTER":
                api.update((it["api"], g["reason"]) for it in g["items"])
    return dict(rule=FACTS_RULE, sites=dict(counts), trap_forms=dict(forms), methods=methods,
                unresolved=unresolved, unsupported=unsupported, trap_unresolved_details=code["trap_unresolved_details"],
                import_routes=dict(Counter(s["route"] for s in sites if "route" in s)),
                rwx_per_api={a + "/" + why: n for (a, why), n in sorted(api.items())},
                regions=[{k: r[k] for k in ("name", "role", "verified_bytes")} for r in code["regions"]],
                rows_outside_code=len(code["rows_outside_code"]), verified_encoding=code["verified_encoding"],
                name_table_sha256=code["name_table_sha256"])


# -- import transfer sites and register values (r1 s4.2 / s4.3, r2 E3 / E4, r3 E3) --------------------------------

GPR = {0x00: "RAX", 0x08: "RCX", 0x10: "RDX", 0x18: "RBX", 0x20: "RSP", 0x28: "RBP", 0x30: "RSI", 0x38: "RDI",
       0x80: "R8", 0x88: "R9", 0x90: "R10", 0x98: "R11", 0xA0: "R12", 0xA8: "R13", 0xB0: "R14", 0xB8: "R15"}
TRANSFER_OPS = {"CALL": "call", "CALLIND": "call", "BRANCH": "jump", "BRANCHIND": "jump", "CBRANCH": "jcc"}
DECODER_FORMS = {"call_near": "call", "jmp_near": "jump", "jcc": "jcc"}
RWX = {"pe": (0x40, 0x80), "elf": (7,)}
ENDBR64 = b"\xf3\x0f\x1e\xfa"


def decoder_flows(ballot):
    """The flows of the required voters (Intel then AMD), or None when the ballot is not complete."""
    if not _ballot_ok(ballot):
        return None
    return tuple(d.flow for d in sorted(ballot["intel"], key=lambda d: d.voter)) + \
        tuple(d.flow for d in sorted(ballot["amd"], key=lambda d: d.voter))


def _gpr(v):
    """(offset of the 64-bit register, width in bits) of a REGISTER varnode inside a GPR, else None."""
    if not v or v.get("kind") != "REGISTER":
        return None
    base = v["offset"] & ~7
    if base in GPR and v["offset"] - base + v["size"] <= 8:
        return base, v["offset"], v["size"]
    return None


def _overlaps(a, b):
    return a["space"] == b["space"] and a["offset"] < b["offset"] + b["size"] and b["offset"] < a["offset"] + a["size"]


class ImportSites:
    def __init__(self, binder, raw, kinds, complete, image=None, original=None):
        b = self.b = binder
        self.ff = b.ff
        self.raw = [raw[k] for k in b.keys]
        self.kind_of = {name: kind for kind, names in kinds.items() for name in names}
        self.complete = complete
        self.image, self.original = image, original
        self.starts, self.by_space = defaultdict(list), defaultdict(list)
        self.entries, self.unknown_edges = defaultdict(set), set()
        self.parents, self.endbr, self.stubs, self.states = {}, {}, {}, {}
        # G2b's indexes can use a verified decoder length without changing the G2a row.
        self.lengths = bytearray(_index_length(row, proof) for row, proof in zip(b.rows, b.proofs, strict=True))

        for i, r in enumerate(b.rows):
            space, a = r["space"], b.va[i]
            self.starts[space, a].append(i)
            self.by_space[space].append((a, i))
            f = self.raw[i]
            for target in f.get("flow_target_coords", ()):
                self.entries[tuple(target)].add((i, "encoded_target"))
            for target in f.get("recorded_landing_pads") or ():
                self.entries[tuple(target)].add((i, "pad"))
            for t in (r["transfer"], *(r.get("vendor_views") or {}).values()):
                edges = t.get("edges")
                if not isinstance(edges, list):
                    self.unknown_edges.add(space)
                    continue
                for e in edges:
                    to = self.edge_coord(i, e)
                    if to is not None:
                        self.entries[to].add((i, e["source"]))
                    elif e.get("source") in ("encoded_target", "sequential"):
                        self.unknown_edges.add(space)
        for spans in self.by_space.values():
            spans.sort()

    def edge_coord(self, i, edge):
        to = edge.get("to")
        if isinstance(to, dict) and "offset" in to:
            return to["space"], int(to["offset"], 16)
        if edge.get("source") != "sequential" or to != {"unobserved": "length unavailable"}:
            return None

        import lifting
        import producer_override

        b = self.b
        row, proof = b.rows[i], b.proofs[i]
        length = self.lengths[i]
        if (row["length"] is not None or not length or proof.failure or proof.signature is None
                or proof.signature[:2] != proof.form):
            return None
        coordinate = row["space"], (b.va[i] + length) % (1 << 64)
        raw = self.raw[i]
        observed = lifting.continuation(raw)
        override = raw.get("override")
        if (raw["flow"].get("is_override") or (override is not None and producer_override.present(override))
                or (observed is not None and observed != coordinate)):
            return None
        return coordinate

    def between(self, space, a, z):
        spans = self.by_space.get(space, ())
        return spans[bisect_left(spans, (a,)):bisect_left(spans, (z,))]

    def covering(self, space, va):
        for a, j in self.between(space, va - 14, va):
            length = self.lengths[j]
            if not length or a + length > va:
                yield j, bool(length)

    def predecessor(self, i):
        import lifting

        if i in self.parents:
            return self.parents[i]
        b = self.b
        r = b.rows[i]

        def same(j):
            s = b.rows[j]
            return (s["observation"], s["view"]) == (r["observation"], r["view"])

        here = r["space"], b.va[i]
        seq = [j for j, role in self.entries[here] if role == "sequential" and same(j)]
        parent = None
        if len(seq) == 1:
            j = seq[0]
            s = b.rows[j]
            edges = s["transfer"].get("edges")
            if (self.entries[here] == {(j, "sequential")} and self.lengths[j]
                    and b.va[j] + self.lengths[j] == here[1]
                    and s["transfer"]["kind"] == "none" and isinstance(edges, list) and len(edges) == 1
                    and edges[0]["source"] == "sequential" and self.edge_coord(j, edges[0]) == here
                    and not any(same(k) for k, _ in self.covering(*here))
                    and not any(same(k) for k, _ in self.covering(r["space"], b.va[j]))
                    and not any(a > b.va[j] and same(k) for a, k in self.between(r["space"], b.va[j], here[1]))
                    and sum(same(k) for k in self.starts[r["space"], b.va[j]]) == 1
                    and sum(same(k) for k in self.starts[here]) == 1
                    and not any(o["opcode"] in lifting.FLOW_OPS for o in self.raw[j]["ops"])):
                parent = j
        self.parents[i] = parent
        return parent

    def _apply(self, defs, j):
        for n, op in enumerate(self.raw[j]["ops"]):
            out = op.get("output")
            if not out:
                continue
            s, a, w = key = out["space"], out["offset"], out["size"]
            args = op["inputs"]
            value = None
            if _gpr(out):
                if (op["opcode"] == "COPY" and len(args) == 1 and args[0]
                        and args[0]["kind"] == "CONSTANT" and args[0]["size"] == w):
                    value = args[0]["offset"] % (1 << (8 * w))
                elif (op["opcode"] in ("INT_XOR", "INT_SUB") and len(args) == 2
                      and args[0] == args[1] and _gpr(args[0]) and args[0]["size"] == w):
                    value = 0
                elif (op["opcode"] == "INT_ZEXT" and w == 8 and a % 8 == 0
                      and len(args) == 1 and args[0] == dict(out, size=4)):
                    prior = defs.get((s, a, 4))
                    if prior and prior[1:] == (j, n - 1):
                        value = prior[0]
            for k in list(defs):
                if k[0] == s and k[1] < a + w and a < k[1] + k[2]:
                    del defs[k]
            if value is not None:
                defs[key] = value, j, n

    def register_values(self, i, ordinal, wanted=None):
        if not self.complete or self.b.rows[i]["space"] in self.unknown_edges:
            return [], "INDEX_INCOMPLETE"
        j, todo = i, []
        while j not in self.states:
            j = self.predecessor(j)
            if j is None:
                break
            todo.append(j)
        defs = self.states.get(j, {}).copy()
        for k in reversed(todo):
            self._apply(defs, k)
        if i not in self.states:
            if len(self.states) >= 1024:
                self.states.pop(next(iter(self.states)))
            self.states[i] = defs

        values = []
        for key, (v, j, n) in sorted(defs.items()):
            if wanted is not None and key not in wanted:
                continue
            path = [i]
            while path[-1] != j:
                path.append(self.predecessor(path[-1]))
            s, a, w = key
            values.append(dict(register=dict(name=GPR[a & ~7], space=s, offset=a, size=w),
                               value=dict(constant=_hx(v), width=8 * w), definition=dict(row=j, op=n),
                               use=dict(row=i, op=ordinal), path=path[::-1], basis="ghidra_pcode",
                               holds_if=[PREMISE, LINEAR_PREMISE]))
        return values, None

    def exact(self, i):
        import common_facts as cf

        r, p = self.b.rows[i], self.b.proofs[i]
        keys = r["transfer"].get("op_keys")
        op = keys.get("transfer") if isinstance(keys, dict) else None
        if not op or op.get("ordinal") not in p.raw_ops:
            return None
        try:
            cf.resolve(op, r, self.raw[i])
        except ValueError:
            return None
        return op["ordinal"]

    def transfer(self, i, n):
        import common_facts as cf

        b = self.b
        r, p = b.rows[i], b.proofs[i]
        flow, ind = p.form
        opcode = self.raw[i]["ops"][n]["opcode"]
        mem = (r["transfer"].get("target_value") or {}).get("memory", {})
        if ind:
            operand = self.raw[i]["ops"][n]["inputs"][0]
            if p.segment or mem.get("segment_base") is not None:
                raise Unread("SEGMENT_BASE")
            if (operand and operand["size"] != 8) or (mem and mem["size"] != 8):
                raise Unread("POINTER_WIDTH")
            if r["space"] != b.space or (mem and mem["space"] != b.space):
                raise Unread("SPACE_MISMATCH")
            if operand and operand["kind"] in ("REGISTER", "UNIQUE"):
                for op in reversed(self.raw[i]["ops"][:n]):
                    o = op.get("output")
                    if o and _overlaps(o, operand):
                        if o == operand and op["opcode"] == "LOAD":
                            sel = op["inputs"][0]
                            if sel and sel["kind"] == "CONSTANT" and sel["offset"] != b.space:
                                raise Unread("SPACE_MISMATCH")
                        break

        if p.failure:
            raise Unread(p.failure)
        fl, indirect, length, dst = p.signature
        if (fl, indirect) != (flow, ind) or fl not in DECODER_FORMS:
            raise Unread("FORM_MISMATCH")
        form = DECODER_FORMS[fl]
        if r["space"] != b.space:
            raise Unread("SPACE_MISMATCH")
        # (a Bundle without row lengths claims none: the agreed decoder length stands; only a claimed different
        #  length is a mismatch)
        if r["length"] is not None and length != r["length"]:
            raise Unread("FORM_MISMATCH")
        if (ind != (opcode in ("CALLIND", "BRANCHIND")) or
                TRANSFER_OPS[opcode] != form and not (form == "call" and opcode == "BRANCH")):
            raise Unread("FORM_MISMATCH")

        role = cf.TAKEN if form == "jcc" else cf.DIRECT
        edge = None
        for vendor in (None, *cf.VENDORS) if r.get("vendor_views") else (None,):
            m = cf.member(r, vendor)
            if (m["length"] is not None and m["length"] != length) or (
                    ind and m.get("target_value") != r["transfer"]["target_value"]):
                raise Unread("VENDOR_VIEW_CONFLICT")
            if not ind:
                es = [e for e in m["edges"] if cf.triple(e) == role] if isinstance(m["edges"], list) else []
                if len(es) != 1 or not isinstance(es[0].get("to"), dict) or "offset" not in es[0]["to"]:
                    raise Unread("VENDOR_VIEW_CONFLICT" if vendor else "TARGET_LIFT_U")
                to = es[0]["to"]
                if to["space"] != b.space:
                    raise Unread("SPACE_MISMATCH")
                if dst != int(to["offset"], 16):
                    raise Unread("VENDOR_VIEW_CONFLICT" if vendor or r.get("vendor_views") else "FORM_MISMATCH")
                edge = dict(zip(cf.EC, role), to=to)

        step = dict(row=i, op=n, step="ghidra_pcode")
        if edge is not None:
            step["edge"] = edge
            return form, False, dst, step
        if mem and p.target_kind != "memory":
            raise Unread("FORM_MISMATCH")
        addr = mem.get("address", {})
        if set(addr) != {"constant", "width"} or addr["width"] != 64:
            raise Unread("COMPUTED_TARGET")
        return form, True, int(addr["constant"], 16), step

    def read_endbr(self, i):
        if not self.lengths[i]:
            raise Unread("INDEX_INCOMPLETE")
        if self.lengths[i] != 4:
            return False
        va = self.b.va[i]
        if va not in self.endbr:
            try:
                if self.image is None:
                    raise Unread("MAP_INDETERMINATE")
                raw, basis = runtime_read(self.image, self.original, va - self.b.base, 4)
                self.endbr[va] = (basis if raw == ENDBR64 else False), None
            except Unread as exc:
                self.endbr[va] = None, exc.reason
        result, why = self.endbr[va]
        if why:
            raise Unread(why)
        return result

    def stub(self, space, va):
        """Fourth route for an unlisted [ENDBR64] [BND] RIP-relative slot jump in decided executable bytes."""
        import decoders

        b = self.b
        if space != b.space or not self.image or not self.ff.ok:
            return None
        if va in self.stubs:
            return self.stubs[va]
        self.stubs[va] = None
        start = va - b.base

        def read(offset, n):
            return runtime_read(self.image, self.original, start + offset, n)

        try:
            first, _ = read(0, 1)
            skip = 0
            if first == b"\xf3":
                if read(0, 4)[0] != ENDBR64:
                    return None
                skip = 4
            bnd = int(read(skip, 1)[0] == b"\xf2")
            n = bnd + 6
            size = skip + n
            if not any(r.executable and r.start <= start and start + size <= r.end for r in self.ff.code):
                return None
            raw, basis = read(0, size)
        except Unread:
            return None
        jump = raw[skip:]
        if jump[bnd:bnd + 2] != b"\xff\x25":
            return None
        votes = decoders.ballot(jump, va + skip)
        if not _ballot_ok(votes) or any(d.status != "ok" or d.flow != "jmp_near" or
                not d.indirect or d.length != n for v in ("intel", "amd") for d in votes[v]):
            return None
        slot = (va + size + int.from_bytes(jump[-4:], "little", signed=True)) % (1 << 64)
        step = dict(stub=_hx(va), space=space, load_base=_hx(b.base), length=size, jump_offset=skip,
                    decoders={v: ballot_digest(votes[v]) for v in ("intel", "amd")}, **basis)
        self.stubs[va] = slot, [step]
        return self.stubs[va]

    def thunk(self, j):
        b = self.b
        path = []
        if b.rows[j]["transfer"]["kind"] == "none":
            marker = self.read_endbr(j)
            if marker:
                if b.proofs[j].signature != ("none", False, 4, None):
                    raise Unread("TARGET_LIFT_U")
                path.append(dict(row=j, op=None, **marker))
                r = b.rows[j]
                va = b.va[j] + 4
                ns = [k for k in self.starts[r["space"], va] if b.rows[k]["view"] == r["view"]
                      and b.rows[k]["observation"] == r["observation"]]
                edges = r["transfer"]["edges"]
                if (len(ns) != 1 or len(edges) != 1 or edges[0]["source"] != "sequential"
                        or self.edge_coord(j, edges[0]) != (r["space"], va)
                        or any(b.rows[k]["observation"] == r["observation"] and b.rows[k]["view"] == r["view"]
                               for k, _ in self.covering(r["space"], va))):
                    raise Unread("TARGET_LIFT_U")
                j = ns[0]
        p = b.proofs[j]
        n = self.exact(j)
        if n is None:
            if p.raw_ops or p.candidate or b.rows[j]["transfer"]["kind"] == "unknown" or p.failure:
                raise Unread("TARGET_LIFT_U")
            if path:
                raise Unread("ELF_STUB_UNSUPPORTED" if self.ff.format == "elf" else "TARGET_LIFT_U")
            return None
        form, ind, dst, step = self.transfer(j, n)
        if form == "jump":
            if not ind:
                raise Unread("MULTI_HOP")
            return dst, path + [step]
        if path:
            raise Unread("ELF_STUB_UNSUPPORTED" if self.ff.format == "elf" else "TARGET_LIFT_U")
        return None

    def direct(self, i, va):
        b = self.b
        space = b.rows[i]["space"]
        candidates = self.starts.get((space, va), ())
        inside = list(self.covering(space, va))
        if any(known for _, known in inside):
            raise Unread("VENDOR_VIEW_CONFLICT" if candidates else "TARGET_NOT_ROW_START")
        if inside:
            raise Unread("INDEX_INCOMPLETE")
        if not candidates:
            if not self.complete:
                raise Unread("INDEX_INCOMPLETE")
            result = self.stub(space, va)
            if result is None:
                raise Unread("TARGET_OUTSIDE_ROWS")
            return *result, [], "via_stub_bytes"
        if any(b.rows[j]["view"] != b.rows[i]["view"] for j in candidates):
            raise Unread("VENDOR_VIEW_CONFLICT")

        outcomes = []
        for j in candidates:
            try:
                outcomes.append((self.thunk(j), None))
            except Unread as exc:
                outcomes.append((None, exc.reason))

        def meaning(result, why):
            if result is None:
                return why, None
            return None, (result[0], tuple((b.va[s["row"]], s["op"]) for s in result[1]))

        if len({meaning(*v) for v in outcomes}) != 1:
            raise Unread("VENDOR_VIEW_CONFLICT")
        first, why = outcomes[0]
        if why:
            raise Unread(why)
        if first is None:
            return None
        paths = [v[0][1] for v in outcomes]
        return first[0], paths[0], paths[1:], "via_thunk"

    def run(self):
        b = self.b
        sites, unresolved, reached = [], [], set()
        for i, p in enumerate(b.proofs):
            if p.isa != "x86-64":
                continue
            n = self.exact(i)
            for k in p.raw_ops:
                if k != n:
                    unresolved.append(("TRANSFER_UNBOUND", dict(row=i, op=k)))
            if n is None:
                if not p.raw_ops and (p.candidate or b.rows[i]["transfer"]["kind"] == "unknown" and p.failure):
                    unresolved.append(("TRANSFER_UNBOUND", dict(row=i, op=None)))
                continue

            at = dict(row=i, op=n)
            try:
                form, ind, slot, source = self.transfer(i, n)
                hop, alternatives, route = [], [], "direct_slot"
                if not ind:
                    result = self.direct(i, slot)
                    if result is None:
                        continue
                    slot, hop, alternatives, route = result

                coord = slot - b.base
                if coord in self.ff.slot_failures:
                    raise Unread(self.ff.slot_failures[coord])
                item = self.ff.imports.get(coord)
                if item is None:
                    raise Unread({"complete": "SLOT_NOT_IMPORT", "absent": "NO_IMPORT_DIRECTORY"}
                                 .get(self.ff.import_state, "PARSER_UNSUPPORTED"))
                if "ordinal" in item:
                    raise Unread("IMPORT_BY_ORDINAL")
                if not item.get("undefined", True):
                    raise Unread("SLOT_NOT_IMPORT")
                name = item["name"]
                kind = self.kind_of.get(name)
                if kind is None:
                    continue
                if route == "via_thunk":
                    reached.update((q[-1]["row"], q[-1]["op"], kind) for q in [hop, *alternatives])
                values, reason = self.register_values(i, n)
                basis = {k: dict(v, slot_va=_hx(slot)) for k, v in item["basis"].items()}
                basis.update(path=[source, *hop], step="ghidra_pcode")
                if alternatives:
                    basis["equivalent_paths"] = [[source, *q] for q in alternatives]
                site = dict(at, form=form, kind=kind, route=route, arguments=[], register_values=values,
                            symbol=dict(name=name, dll=item.get("dll"), slot=_hx(slot), basis=basis),
                            holds_if=[PREMISE, IMPORT_PREMISE] + ([LINEAR_PREMISE] if values else []))
                if reason:
                    site["register_values_reason"] = reason
                if kind == RWX_KIND:
                    hits = [v["register"]["name"] for v in values if v["register"]["offset"] % 8 == 0
                            and v["value"]["width"] in (32, 64)
                            and int(v["value"]["constant"], 16) in RWX[self.ff.format]]
                    if not hits:
                        unresolved.append(("NO_RWX_REGISTER", dict(at, api=name)))
                        continue
                    site.update(candidate=True, rwx_registers=hits, protection_argument={"unobserved": "NO_ABI_BASIS"})
                if kind == "dynamic_resolution":
                    site["requested_name"] = {"unobserved": "NO_ABI_BASIS"}
                sites.append(site)
            except Unread as exc:
                unresolved.append((exc.reason, at))

        for s in sites:
            if s["route"] == "direct_slot" and (s["row"], s["op"], s["kind"]) in reached:
                s["route"] = "thunk_row"
        return sites, unresolved

    def stores(self):
        import common_facts as cf
        import lifting

        b = self.b
        sites, unresolved = [], []
        for i, (p, f) in enumerate(zip(b.proofs, self.raw, strict=True)):
            if p.isa != "x86-64":
                continue
            for n, op in enumerate(f["ops"]):
                if op["opcode"] != "STORE":
                    continue
                at = dict(row=i, op=n)
                try:
                    args = op["inputs"]
                    if len(args) != 3 or not cf.const(args[0]):
                        raise Unread("STORE_SPACE_U")
                    if not args[2] or type(args[2]["size"]) is not int or args[2]["size"] <= 0:
                        raise Unread("STORE_WIDTH_U")
                    if b.space is None:
                        raise Unread("TARGET_MAPPING_U")
                    if args[0]["offset"] != b.space:
                        continue
                    if any(o["opcode"] in lifting.FLOW_OPS for o in f["ops"][:n]):
                        raise Unread("INTRA_ROW_FLOW")
                    expr, used = cf.value(f, args[1], n)
                    defs, regs = [], {}
                    wanted = {(r["space"], r["offset"], r["size"])
                              for leaf in _leaves(expr) for r in [leaf["pre_register"]]}
                    if wanted:
                        defs, why = self.register_values(i, n, wanted)
                        if why:
                            raise Unread(why)
                        for v in defs:
                            r = v["register"]
                            regs[r["space"], r["offset"], r["size"]] = int(v["value"]["constant"], 16)
                    address = _evaluate(expr, regs) if expr.get("width") == 64 else None
                    if address is None:
                        raise Unread("STORE_ADDRESS_NOT_CONSTANT")
                    end = address + args[2]["size"]
                    if end > 1 << 64:
                        raise Unread("ADDRESS_WRAP")
                    if not self.ff.ok:
                        raise Unread("TARGET_MAPPING_U")
                    a, z = address - b.base, end - b.base
                    hit = [j for j, r in enumerate(self.ff.code) if r.start < z and a < r.end]
                    if not hit:
                        if any(d.get("basis", {}).keys() & {"pe_section", "elf_segment"} and
                               d["range"]["start"] < z and a < d["range"]["end"] for d in self.ff.diagnostics):
                            raise Unread("TARGET_MAPPING_U")
                        continue
                    basis = dict(step="ghidra_pcode", use=at, in_row=[dict(row=i, op=j) for j in sorted(used)],
                                 expression=expr, register_values=defs)
                    sites.append(dict(at, form="store", kind="code_write", write="static_store_candidate",
                                      symbol=None, arguments=[], target_range=b._range(a, z), regions=hit,
                                      static_basis=basis, holds_if=[PREMISE] + ([LINEAR_PREMISE] if defs else [])))
                except Unread as exc:
                    unresolved.append((exc.reason, at))
        return sites, unresolved


# -- code_write static candidates (r1 s4.4, r2 E4 / E5) ------------------------------------------------------------

def _leaves(e):
    if isinstance(e, dict):
        if "pre_register" in e:
            yield e
        for v in e.values():
            yield from _leaves(v)
    elif isinstance(e, list):
        for v in e:
            yield from _leaves(v)


def _evaluate(e, regs):
    """The integer value of a value() expression of constants and register constants, else None (memory never)."""
    if not isinstance(e, dict) or "unobserved" in e or "memory" in e or "op_output" in e:
        return None
    w = e.get("width")
    mask = (1 << w) - 1 if type(w) is int else None
    if "constant" in e:
        return int(e["constant"], 16)
    if "pre_register" in e:
        r = e["pre_register"]
        return regs.get((r["space"], r["offset"], r["size"]))
    for op in ("add", "sub", "mul"):
        if op in e:
            a, b = (_evaluate(x, regs) for x in e[op])
            if a is None or b is None or mask is None:
                return None
            return (a + b if op == "add" else a - b if op == "sub" else a * b) & mask
    for op in ("zext", "trunc"):
        if op in e:
            a = _evaluate(e[op], regs)
            return None if a is None or mask is None else a & mask
    if "sext" in e:
        inner = e["sext"]
        a = _evaluate(inner, regs)
        iw = inner.get("width") if isinstance(inner, dict) else None
        if a is None or mask is None or type(iw) is not int:
            return None
        if a >> (iw - 1) & 1:
            a -= 1 << iw
        return a & mask
    return None


# -- G2b impl review r1 fixes (Astra-written, g2b_impl_astra2_code.md) ---------------------------------------

RWX_KIND = "rwx_allocation_constant_args"

REASONS |= {"NOT_A64", "SECTION_EXTENT_U"}


def _touches(parsed, start, end):
    # G1 has finished constructing this Parsed object before file_facts runs.
    index = getattr(parsed, "_g2_intervals", None)
    if index is None:
        starts, ends = [], []
        for a, z, *_ in sorted(parsed.ranges):
            if starts and a <= ends[-1]:
                ends[-1] = max(z, ends[-1])
            else:
                starts.append(a)
                ends.append(z)
        index = parsed._g2_intervals = starts, ends
    starts, ends = index
    j = bisect_right(ends, start)
    return start < end and j < len(starts) and starts[j] < end


def _issue(out, reason, start, end, basis):
    _diag(out, reason, start=start, end=end, basis=basis)


def _code_region(out, image, region, valid):
    cursor = region.start
    for m in image.ranges:
        lo, hi = max(cursor, m.start), min(region.end, m.end)
        if hi <= lo:
            continue
        if cursor < lo:
            _issue(out.diagnostics, "AMBIGUOUS_MAPPING", cursor, lo, region.basis)
        if valid and m.kind in ("file", "zero"):
            if out.code and out.code[-1].basis == region.basis and out.code[-1].end == lo:
                out.code[-1].end = hi
            else:
                out.code.append(replace(region, start=lo, end=hi))
        else:
            _issue(out.diagnostics, "AMBIGUOUS_MAPPING", lo, hi, region.basis)
        cursor = hi
    if cursor < region.end:
        _issue(out.diagnostics, "AMBIGUOUS_MAPPING", cursor, region.end, region.basis)


def _publish(out, slot, item, reason=None):
    if slot in out.imports or slot in out.slot_failures:
        out.imports.pop(slot, None)
        reason = "SLOT_NAME_U"
    if reason:
        out.slot_failures[slot] = reason
    else:
        out.imports[slot] = item


def _mapped_slot(image, slot):
    m = image.at(slot)
    return m is not None and m.kind in ("file", "zero") and slot + 8 <= m.end


def _pe_table(image, data, directory, n, out):
    start, size = directory
    stride = 20 if n == 1 else 32
    parent = {"pe_directory": n}
    for pos in range(start, start + size - stride + 1, stride):
        basis = parent
        staged = []
        fallback = False
        try:
            raw, basis = record_read(image, data, pos, stride)
            if not any(raw):
                return
            if n == 1:
                lookup, stamp, _, name, slots = struct.unpack("<5I", raw)
                if not lookup and stamp:
                    raise Unread("BOUND_IAT_NO_ILT")
                fallback = not lookup
                lookup = lookup or slots
                if not name or not slots:
                    raise Unread("ILT_ENTRY_INVALID")
            else:
                attr, name, _, slots, lookup, _, _, _ = struct.unpack("<8I", raw)
                if attr != 1 or not all((name, slots, lookup)):
                    raise Unread("DELAY_FORMAT")

            dll, dll_ref = record_cstring(image, data, name)
            if not dll:
                raise Unread("SLOT_NAME_U")
            index = 0
            while True:
                slot = slots + 8 * index
                raw, entry = record_read(image, data, lookup + 8 * index, 8)
                v = int.from_bytes(raw, "little")
                if not v:
                    break
                try:
                    if not _mapped_slot(image, slot):
                        raise Unread("ILT_ENTRY_INVALID")
                    fact = dict(dll=dll, descriptor=basis, dll_record=dll_ref, lookup=entry)
                    item = dict(dll=dll, kind="import" if n == 1 else "delay")
                    if v >> 63:
                        if v & ~((1 << 63) | 0xffff):
                            raise Unread("ILT_ENTRY_INVALID")
                        item["ordinal"] = fact["ordinal"] = v & 0xffff
                        text = "#" + str(item["ordinal"])
                    else:
                        if v >= 1 << 31:
                            raise Unread("ILT_ENTRY_INVALID")
                        text, string = record_cstring(image, data, v + 2)
                        if not text:
                            raise Unread("SLOT_NAME_U")
                        _, fact["hint_name"] = record_read(image, data, v, 2 + string["file_record"][1])
                    fact["name"] = item["name"] = text
                    item["basis"] = {"pe_import": fact}
                    if fallback:
                        staged.append((slot, item))
                    else:
                        _publish(out, slot, item)
                except Unread as exc:
                    if fallback:
                        _publish(out, slot, None, "ILT_ENTRY_INVALID")
                        raise Unread("ILT_ENTRY_INVALID") from exc
                    _publish(out, slot, None, exc.reason)
                index += 1
            for slot, item in staged:
                _publish(out, slot, item)
        except Unread as exc:
            for slot, _ in staged:
                _publish(out, slot, None, "ILT_ENTRY_INVALID")
            why = "ILT_ENTRY_INVALID" if fallback and staged else exc.reason
            _issue(out.import_problems, why, pos, pos + stride, basis)
    _issue(out.import_problems, "TRUNCATED", start, start + size, parent)


def _sections(image, data, out):
    shoff, = struct.unpack_from("<Q", data, 40)
    stride, count, names = struct.unpack_from("<3H", data, 58)
    if not shoff and not count:
        return [], False
    if not shoff or stride != 64 or not count or shoff + 64 * count > len(data) or names >= count:
        raise Unread("TRUNCATED")

    sections = []
    for i in range(count):
        at = shoff + 64 * i
        n, t, flags, va, off, size, link, _, _, ent = struct.unpack_from("<IIQQQQIIQQ", data, at)
        sections.append(dict(n=n, type=t, flags=flags, va=va, off=off, size=size,
                             link=link, ent=ent, ref={"file_record": [at, 64]}))
    strings = sections[names]
    if names and (strings["type"] != 3 or strings["off"] + strings["size"] > len(data)):
        raise Unread("TRUNCATED")
    for s in sections:
        s["name"] = ""
        if s["type"] != 8 and s["off"] + s["size"] > len(data):
            _issue(out.diagnostics, "TRUNCATED", s["va"] - image.image_base, None, s["ref"])
        if names:
            a = strings["off"] + s["n"]
            z = data.find(b"\0", a, strings["off"] + strings["size"])
            if z < 0:
                _issue(out.diagnostics, "TRUNCATED", s["va"] - image.image_base, None, s["ref"])
            else:
                s["name"] = data[a:z].decode("latin-1")
    return sections, True


def _loaded_section(image, data, s):
    if not s["flags"] & 2 or s["type"] == 8 or s["off"] + s["size"] > len(data):
        raise Unread("SECTION_NOT_LOADED")
    loads = [p for p in image.phdrs if p[0] == 1 and p[3] <= s["va"]
             and s["va"] + s["size"] <= p[3] + min(p[5], p[6])
             and p[2] + s["va"] - p[3] == s["off"]]
    if len(loads) != 1:
        raise Unread("SECTION_NOT_LOADED")
    if s["size"]:
        _, ref = record_read(image, data, s["va"] - image.image_base, s["size"])
        if ref["file_record"][0] != s["off"]:
            raise Unread("AMBIGUOUS_MAPPING")


def _elf_file(image, data, out):
    base = image.image_base
    for s in image.segments:
        if s["flags"] & PF_X:
            a = s["vaddr"] - base
            region = Region(a, a + s["memsz"], "code", True, bool(s["flags"] & PF_W),
                            f"PT_LOAD[{s['index']}]", {"elf_segment": [s["index"], s["flags"]]})
            _code_region(out, image, region, s["state"] == "mapped")
    try:
        sections, present = _sections(image, data, out)
    except Unread as exc:
        sections, present = [], True
        for problems in (out.diagnostics, out.import_problems):
            _diag(problems, exc.reason, what="section headers", basis={"file_record": [0, 64]})

    body = False
    for s in sections:
        if s["name"] not in (".eh_frame", ".gcc_except_table"):
            continue
        a = s["va"] - base
        try:
            _loaded_section(image, data, s)
        except Unread as exc:
            _issue(out.diagnostics, exc.reason, a, a + s["size"], s["ref"])
            continue
        out.unwind.append(Region(a, a + s["size"], "unwind_metadata", name=s["name"], basis=s["ref"]))
        body |= s["name"] == ".eh_frame"

    hdrs = [(i, p) for i, p in enumerate(image.phdrs) if p[0] == PT_GNU_EH_FRAME]
    if not hdrs and not present:
        _diag(out.diagnostics, "NO_SECTION_HEADERS", what="eh_frame", basis={"file_record": [0, 64]})
    for i, p in hdrs:
        a = p[3] - base
        basis = {"phdr": i}
        out.unwind.append(Region(a, a + p[6], "unwind_metadata", name=".eh_frame_hdr", basis=basis))
        if body:
            continue
        try:
            head, basis = runtime_read(image, data, a, min(p[5], p[6], 8))
            if len(head) < 2 or head[0] != 1:
                raise Unread("EH_FRAME_PTR_ENCODING")
            enc = head[1]
            if enc == 255:
                raise Unread("EH_FRAME_PTR_OMITTED")
            if enc not in (3, 11, 0x13, 0x1b) or len(head) != 8:
                raise Unread("EH_FRAME_PTR_ENCODING")
            value = int.from_bytes(head[4:], "little", signed=bool(enc & 8))
            start = value + (a + 4 if enc & 0x10 else -base)
            if not 0 <= base + start < 1 << 64:
                raise Unread("EH_FRAME_PTR_ENCODING")
            why = "SECTION_EXTENT_U" if present else "NO_SECTION_HEADERS"
            ref = dict(basis, encoding=enc)
            out.unwind.append(Region(start, None, "unwind_metadata", name=".eh_frame", basis=ref))
            _issue(out.diagnostics, why, start, None, ref)
        except Unread as exc:
            _diag(out.diagnostics, exc.reason, what="eh_frame", basis=basis)
    _elf_tables(image, data, sections, out)


def _dynamic_symbol_count(image, data, tags):
    base = image.image_base
    try:
        if DT_HASH in tags:
            at = tags[DT_HASH] - base
            raw, _ = record_read(image, data, at, 8)
            buckets, count = struct.unpack("<II", raw)
            if not buckets:
                return None
            record_read(image, data, at, 8 + 4 * (buckets + count))
            return count
        if DT_GNU_HASH in tags:
            at = tags[DT_GNU_HASH] - base
            head, _ = record_read(image, data, at, 16)
            buckets, first, bloom, _ = struct.unpack("<4I", head)
            if not buckets or not bloom:
                return None
            at += 16 + 8 * bloom
            raw, _ = record_read(image, data, at, 4 * buckets)
            last = max(n for n, in struct.iter_unpack("<I", raw))
            if last == 0:
                return first
            if last < first:
                return None
            at += 4 * (buckets + last - first)
            while True:
                raw, _ = record_read(image, data, at, 4)
                last += 1
                if raw[0] & 1:
                    return last
                at += 4
    except Unread:
        pass
    return None


def _elf_tables(image, data, sections, out):
    base = image.image_base
    dynamic = [p for p in image.phdrs if p[0] == PT_DYNAMIC]
    tags = {}
    table_ref = {"file_record": [0, 64]}
    try:
        if dynamic:
            if len(dynamic) != 1:
                raise Unread("PARSER_UNSUPPORTED")
            p = dynamic[0]
            raw, table_ref = record_read(image, data, p[3] - base, p[5])
            for at in range(0, len(raw) - 15, 16):
                tag, val = struct.unpack_from("<qQ", raw, at)
                if not tag:
                    break
                if tag in {2, 4, 5, 6, 7, 8, 9, 10, 11, 20, 23, DT_GNU_HASH}:
                    if tag in tags and tags[tag] != val:
                        raise Unread("PARSER_UNSUPPORTED")
                    tags[tag] = val
                elif tag in (17, 18) and val:
                    _diag(out.import_problems, "ELF_RELOC_UNSUPPORTED", what="DT_REL", basis=table_ref)
            else:
                raise Unread("TRUNCATED")
    except Unread as exc:
        out.import_state = "indeterminate"
        _diag(out.import_problems, exc.reason, what="PT_DYNAMIC", basis=table_ref)
        return

    def linked(sym):
        if sym["type"] != 11 or sym["ent"] != 24 or sym["size"] % 24 or sym["link"] >= len(sections):
            raise Unread("SYM_COUNT_U")
        st = sections[sym["link"]]
        if st["type"] != 3:
            raise Unread("SLOT_NAME_U")
        for s in (sym, st):
            _loaded_section(image, data, s)
        if any(k in tags and tags[k] != v for k, v in
               ((6, sym["va"]), (11, 24), (5, st["va"]), (10, st["size"]))):
            raise Unread("SYM_COUNT_U")
        return sym["va"], sym["size"] // 24, st["va"], st["size"]

    def symbols(section):
        if section:
            if section["link"] >= len(sections):
                raise Unread("SYM_COUNT_U")
            return linked(sections[section["link"]])
        matches = [s for s in sections if s["type"] == 11 and s["va"] == tags.get(6)]
        if len(matches) == 1:
            return linked(matches[0])
        if matches or not {5, 6, 10, 11} <= tags.keys() or tags[11] != 24:
            raise Unread("SYM_COUNT_U")
        return tags[6], _dynamic_symbol_count(image, data, tags), tags[5], tags[10]

    for label, ptr, sz, expected, names in (
            ("DT_JMPREL", 23, 2, 7, (".rela.plt", ".rela.plt.sec")),
            ("DT_RELA", 7, 8, 6, (".rela.dyn",))):
        ss = [s for s in sections if s["type"] == 4 and s["name"] in names and s["flags"] & 2]
        if ptr not in tags and sz not in tags and not ss:
            continue
        out.import_state = "complete"
        try:
            if ptr in tags or sz in tags:
                encoding_ok = tags.get(20) == 7 if ptr == 23 else tags.get(9) == 24
                if ptr not in tags or sz not in tags or not encoding_ok:
                    raise Unread("ELF_RELOC_UNSUPPORTED")
                matches = [s for s in sections if s["type"] == 4 and s["va"] == tags[ptr] and s["flags"] & 2]
                if len(matches) > 1:
                    raise Unread("ELF_RELOC_UNSUPPORTED")
                tables = [(tags[ptr], tags[sz], next(iter(matches), None))]
            else:
                tables = [(s["va"], s["size"], s) for s in ss]

            for va, size, section in tables:
                if size % 24:
                    raise Unread("ELF_RELOC_UNSUPPORTED")
                if section:
                    _loaded_section(image, data, section)
                    if section["ent"] != 24 or section["size"] != size:
                        raise Unread("ELF_RELOC_UNSUPPORTED")
                symbol_error = None
                try:
                    symva, count, strva, strsz = symbols(section)
                except Unread as exc:
                    symbol_error = exc.reason
                    _diag(out.import_problems, exc.reason, what=label, basis=table_ref)

                for off in range(0, size, 24):
                    raw, entry = record_read(image, data, va - base + off, 24)
                    dest, info, _ = struct.unpack("<QQq", raw)
                    slot, index, kind = dest - base, info >> 32, info & 0xffffffff
                    try:
                        if kind != expected:
                            raise Unread("ELF_RELOC_UNSUPPORTED")
                        if symbol_error:
                            raise Unread(symbol_error)
                        if count is None or index >= count:
                            raise Unread("SYM_COUNT_U")
                        if not _mapped_slot(image, slot):
                            raise Unread("TARGET_MAPPING_U")
                        raw, sym = record_read(image, data, symva - base + 24 * index, 24)
                        n, _, _, shndx = struct.unpack_from("<IBBH", raw)
                        if n >= strsz:
                            raise Unread("SLOT_NAME_U")
                        name, st = record_cstring(image, data, strva - base + n, strsz - n)
                        if not name:
                            raise Unread("SLOT_NAME_U")
                        basis = {"elf_reloc": dict(name=name, type=kind, table=label, entry=entry,
                                                   symbol=sym, string=st)}
                        _publish(out, slot, dict(name=name, undefined=shndx == 0, basis=basis))
                    except Unread as exc:
                        _publish(out, slot, None, exc.reason)
        except Unread as exc:
            _diag(out.import_problems, exc.reason, what=label, basis=table_ref)


@dataclass(frozen=True, slots=True)
class Proof:
    isa: str | None
    verified: int
    trap: tuple | None
    raw_ops: tuple
    candidate: bool
    signature: tuple | None
    failure: str | None
    form: tuple
    segment: bool
    decoded_length: int | None = None
    target_kind: str | None = None


def row_proof(f, result, lift, ballot, window, global_reason=False):
    import common_facts as cf
    import compare
    import decoders

    w = (result or {}).get("window") or {}
    n = w.get("verified", 0)
    data = (window or b"")[:n]
    isa = f.get("isa")
    if isa != "x86-64":
        return Proof(isa, n, None, (), False, None, None, (None, False), False)

    skip = set(lift.skipped if lift else ())
    if lift and lift.pattern in ("interrupt", "interrupt-return", "fault"):
        skip.add(1)
    ops = tuple(i for i, op in enumerate(f["ops"]) if i not in skip and op["opcode"] in TRANSFER_OPS)
    trap = trap_outcome(result, ballot, data, global_reason)
    votes = [d for v, names in (("intel", decoders.INTEL_VOTERS), ("amd", decoders.AMD_VOTERS))
             for d in (ballot or {}).get(v, ()) if d.voter in names and d.amd == (v == "amd")]
    candidate = any(d.status == "ok" and d.flow in DECODER_FORMS for d in votes)
    sig = failure = decoded_length = target_kind = None
    if not _ballot_ok(ballot):
        failure = "BALLOT_MISSING"
    elif any(d.status != "ok" or type(d.length) is not int
             or not 1 <= d.length <= min(15, len(data)) for d in votes):
        failure = "VENDOR_VIEW_CONFLICT"
    else:
        length = votes[0].length
        if all(d.length == length for d in votes) and not any(
                offset < length and offset + size > 0 for offset, size, _ in w.get("relocations", ())):
            decoded_length = length
        signatures = {(d.flow, d.indirect, d.length, None if d.indirect else d.target) for d in votes}
        if len(signatures) == 1:
            sig = signatures.pop()
            if sig[0] in ("call_near", "jmp_near") and sig[1]:
                kinds = {d.target_kind for d in votes}
                if kinds in ({"memory"}, {"register"}):
                    target_kind = kinds.pop()
                else:
                    failure = "VENDOR_VIEW_CONFLICT"
        else:
            failure = "VENDOR_VIEW_CONFLICT"
    prefix = compare._prefix_run(data)
    return Proof(isa, n, trap, ops, candidate, sig, failure, cf.producer_form(f, lift, data),
                 any(b in (0x64, 0x65) for b in prefix), decoded_length, target_kind)


def _index_length(row, proof):
    claimed = row["length"]
    length = proof.decoded_length if claimed is None else claimed
    if type(length) is not int or not 1 <= length <= 15:
        return 0
    if proof.decoded_length is not None and proof.decoded_length != length:
        return 0
    for member in (row.get("vendor_views") or {}).values():
        vendor_length = member["length"]
        if vendor_length is not None and (type(vendor_length) is not int or vendor_length != length):
            return 0
    return length


def window_ref(rows, i):
    return {"g1_window": {"row": i, "decode_row": [rows[i]["space"], rows[i]["offset"]]}}


def verified_lists(rows, regions, lengths):
    windows = defaultdict(list)
    for i, (r, n) in enumerate(zip(rows, lengths, strict=True)):
        if n:
            a = int(r["offset"], 16)
            windows[r["space"]].append((a, i, a + n))
    for wins in windows.values():
        wins.sort()

    result, totals = [], []
    for item in regions:
        r = item["range"]
        spans, refs = [], []
        if isinstance(r["end"], str):
            a, z = int(r["start"], 16), int(r["end"], 16)
            wins = windows.get(r["space"], [])
            j = bisect_left(wins, (a - 14,))
            while j < len(wins) and wins[j][0] < z:
                x, i, y = wins[j]
                lo, hi = max(a, x), min(z, y)
                if lo < hi:
                    spans.append((lo, hi))
                    refs.append((i, lo, hi))
                j += 1
        result.append([{"interval": [_hx(lo), _hx(hi)], "basis": window_ref(rows, i)}
                       for i, lo, hi in sorted(refs)])
        totals.append(_union_length(spans))
    return result, totals


def verified_encoding(size):
    return {"form": "compact" if size > VERIFIED_THRESHOLD else "explicit",
            "explicit_bytes": size, "threshold": VERIFIED_THRESHOLD}


def build_code(rows, raw, proofs, image, original, space, base, complete, missing):
    import common_facts as cf

    ff = file_facts(image, original)
    if ff.ok and image.fixed_base and image.image_base != base:
        ff = FileFacts(ff.format, False, "fixed load base mismatch", import_state="indeterminate")
    kinds, sha = name_table()
    binder = CodeBinder(ff, base, space, rows, proofs, cf.row_set_digest(rows), missing)
    return binder.program_code(sha, ImportSites(binder, raw, kinds, complete, image, original))
