"""Whole-program stack-switch evidence (design section 24.1, decision 6).

The named assumption globals-disjoint-from-stack (a constant address never
falls in the stack) fails for a process whose code runs on a stack placed in
static data (fibers, coroutines on a static buffer). The engine withdraws it
when a function it analyzes switches its stack
(``interprocedural.program_switches_stack``) -- but a Bundle holds a closure
of selected functions, no evidence about the rest of the binary.

``ghidra/GhidraV2StackSwitchScanner.java`` scans EVERY function of a program
analyzed in a Ghidra project (and the instructions outside functions) with
the same MUST rule -- the stack coefficient: a write of the stack pointer with
anything but "the stack pointer + a number" is a switch
(``may_alias.stack_switches``) -- and writes an evidence file (format
``tdo-v2-stack-switch-evidence``): the program's executable SHA-256, how much
was scanned (functions, instructions -- those outside every function too)
and every switch found.

Version 2 (X-1, design_x1 r2 part 4 as amended by r3 / r4.1; detector v5)
carries two verdicts: ``s3-off`` (today's conservative v4 rule, byte for
byte) and ``s3-on`` (the S3-aware transfer: unknown seeds, kernel transfers
classified by bytes, traps and covered candidates listed for the consuming
run). A v2 file sealed into a Bundle by the exporter is *bound* (listing
digest, seal); a standalone file is unbound and counts only for ``s3-off``.

``authority`` is the one reader (X-1 r3 4.5 / r4 4.5): ``s3-off`` reads v1 and
v2 as before; ``s3-on`` needs, for every image of the run, bound v2 evidence of
that image's Bundle, a clean s3-on verdict, every covered row admitted and
every trap row decided by the run -- otherwise the assumption is withdrawn,
with its reason. A clean scan is no proof: bytes Ghidra never disassembled,
and binaries not scanned, are outside it -- reported.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import struct
from dataclasses import astuple, dataclass, replace
from pathlib import Path

FORMAT = "tdo-v2-stack-switch-evidence"
# the detector rule versions this engine accepts (the newest last; equal to
# GhidraV2StackSwitchScanner.DETECTOR). v3 remains explicitly legacy evidence:
# it assumes language-wide nonvolatile preservation, unlike conservative v4 / v5.
DETECTORS = ("stack-switch-coefficient-v3", "stack-switch-coefficient-v4", "stack-switch-coefficient-v5")
POLICIES = ("s3-off", "s3-on")
_FIELDS = {"format", "version", "detector", "executable_sha256", "program", "language", "stack_pointer",
           "functions_scanned", "instructions_scanned", "instructions_outside_functions", "switches",
           "call_preserved", "exceptions"}
_FIELDS_V2 = {"format", "version", "detector", "executable_sha256", "program", "language", "stack_pointer",
              "functions_scanned", "instructions_scanned", "instructions_outside_functions",
              "stack_pointer_coordinate", "policies", "bound", "listing_digest"}
# what a clean scan rests on besides finding no switch (the reported assumption
# stack-switch-check-exceptions): exactly these, in this order
EXCEPTIONS = ("loaded-and-call-result-values-hold-no-stack-pointer", "user-ops-change-only-their-output",
              "calls-preserve-the-common-nonvolatile-registers")
CONSERVATIVE_EXCEPTIONS = EXCEPTIONS[:2]
# (X-1 r4.1, Fable r4 P2-1) v5 names the s3-off reading of entry registers;
# under s3-on the user-op exception covers non-kernel CALLOTHERs only
V5_OFF_EXCEPTIONS = (*CONSERVATIVE_EXCEPTIONS, "entry-registers-hold-no-stack-derived-value")
V5_ON_EXCEPTIONS = ("loaded-and-call-result-values-hold-no-stack-pointer", "non-kernel-user-ops-change-only-their-output")
KERNEL_CLASSES = ("covered", "trap", "uncovered", "undecidable")


class EvidenceError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class KernelTransfer:
    """(X-1 r3 4.3) one kernel-transfer row of the s3-on scan."""

    space_id: int
    byte_offset: int
    bytes: str
    kind: str               # one of KERNEL_CLASSES
    vector: str | None      # "3", "41", "46", "ud", another int vector, or None
    lift: str               # "callother:<name>", "empty" or "contradictory"
    lift_vector: str | None
    exported: bool

    @property
    def site(self) -> tuple[int, int]:
        return self.space_id, self.byte_offset


@dataclass(frozen=True, slots=True)
class StackEvidence:
    path: str
    digest: str                      # sha256 of the evidence file
    executable_sha256: str
    program: str
    call_preserved: tuple
    detector: str
    functions_scanned: int
    instructions_scanned: int
    instructions_outside_functions: int
    switches: tuple                  # (function, instruction, ordinal, opcode) per switch -- the s3-off verdict
    version: int = 1
    # (X-1, v2 only) the s3-on verdict: its switch rows (function, instruction,
    # ordinal, opcode, cause) and kernel-transfer rows; whether the exporter
    # sealed it into a Bundle (bound) and that Bundle's manifest SHA-256
    on_switches: tuple | None = None
    kernel_transfers: tuple = ()
    bound: bool = False
    listing_digest: tuple | None = None   # (verifiable, attested)
    # (Astra X-1a r1 P1-3 / P1-4) set only by ``verify_bundle_evidence`` -- the
    # admission of the Bundle the evidence is sealed in: that Bundle's manifest
    # SHA-256, the S3 applicability of its original image (True / False / None
    # undecidable) and whether the scanner's stack pointer is the unique
    # eight-byte RSP of its sealed register table
    seal: str | None = None
    applicable: bool | None = None
    rsp_verified: bool = False
    # (Astra X-1a r2 P1-1) the admission's attestation over every field it
    # vouches for (verdicts, kernel rows, digest, seal, applicability, RSP):
    # a copy with any of them changed is not verified
    attestation: str | None = None
    # (v2) the s3-on scan's language flag and the fallback verdict (every
    # instruction start a destination, r4 4.8 -- measured, not authority)
    stack_pointer: tuple | None = None
    language_x86_64: bool | None = None
    fallback_switches: tuple | None = None

    def _scanned(self) -> bool:
        return self.functions_scanned > 0 and self.instructions_scanned > 0

    @property
    def verified(self) -> bool:
        """Issued by a Bundle admission (``verify_bundle_evidence``) and unchanged since."""
        return self.attestation is not None and hmac.compare_digest(self.attestation, _attestation(self))

    def describe(self) -> str:
        found = f"{len(self.switches)} switch(es)" if self.switches else "no switch"
        calls = (f"legacy declared preservation {','.join(self.call_preserved)}"
                 if self.detector == DETECTORS[0] else "conservative unknown post-call registers")
        text = (f"{self.program} (sha256 {self.executable_sha256[:12]}): {self.functions_scanned} functions, "
                f"{self.instructions_scanned} instructions scanned ({self.instructions_outside_functions} of them "
                f"outside functions); {found} [{self.detector}; {calls}; "
                f"exceptions: stack-switch-check-exceptions]")
        if self.version == 2:
            text += (f"; s3-on: {len(self.on_switches)} switch(es), {len(self.kernel_transfers)} kernel row(s), "
                     f"{'bound' if self.bound else 'unbound'}")
        return text


def load_stack_evidence(path, *, data: bytes | None = None) -> StackEvidence:
    """A v1 or v2 evidence file (``data``: its bytes, e.g. a Bundle member).
    The result is unverified: only ``verify_bundle_evidence`` binds it to a
    Bundle (Astra X-1a r1 P1-3)."""
    if data is None:
        data = Path(path).read_bytes()
    try:
        raw = json.loads(data.decode("utf-8"))
    except ValueError as error:
        raise EvidenceError(f"{path}: not JSON") from error
    if type(raw) is dict and raw.get("version") == 2:
        return _load_v2(path, data, raw)
    if type(raw) is not dict or set(raw) != _FIELDS or raw["format"] != FORMAT \
            or type(raw["version"]) is not int or raw["version"] != 1:
        raise EvidenceError(f"{path}: not a {FORMAT} file (version 1)")
    if any(type(raw[key]) is not str or not raw[key] for key in ("program", "language", "stack_pointer")):
        raise EvidenceError(f"{path}: program / language / stack_pointer")
    if type(raw["call_preserved"]) is not list or any(type(item) is not str for item in raw["call_preserved"]):
        raise EvidenceError(f"{path}: call_preserved")
    if raw["detector"] not in DETECTORS[:2]:
        raise EvidenceError(f"{path}: detector {raw['detector']!r} is not one this engine knows {DETECTORS[:2]}")
    exceptions = EXCEPTIONS if raw["detector"] == DETECTORS[0] else CONSERVATIVE_EXCEPTIONS
    if raw["exceptions"] != list(exceptions):
        raise EvidenceError(f"{path}: exceptions must be exactly {list(exceptions)}")
    if raw["detector"] == DETECTORS[1] and raw["call_preserved"]:
        raise EvidenceError(f"{path}: conservative v4 call_preserved must be empty")
    sha = _sha(raw, path)
    counts = _counts(raw, path)
    switches = _switches(raw["switches"], path)
    return StackEvidence(str(path), hashlib.sha256(data).hexdigest(), sha, str(raw["program"]),
                         tuple(raw["call_preserved"]), raw["detector"], *counts,
                         tuple(row[:4] for row in switches))


def _sha(raw: dict, path) -> str:
    sha = raw["executable_sha256"]
    if type(sha) is not str or len(sha) != 64 or any(item not in "0123456789abcdef" for item in sha):
        raise EvidenceError(f"{path}: executable_sha256")
    return sha


def _counts(raw: dict, path) -> list:
    counts = [raw[key] for key in ("functions_scanned", "instructions_scanned", "instructions_outside_functions")]
    if any(type(item) is not int or item < 0 for item in counts):
        raise EvidenceError(f"{path}: counts")
    return counts


def _switches(rows, path, *, cause: bool = False) -> list:
    if type(rows) is not list:
        raise EvidenceError(f"{path}: switches")
    switches = []
    for row in rows:
        if type(row) is not dict or not {"function", "instruction", "ordinal", "opcode"} <= set(row) \
                or type(row["ordinal"]) is not int \
                or any(type(row[key]) is not str for key in ("function", "instruction", "opcode")) \
                or (cause and type(row.get("cause")) is not str):
            raise EvidenceError(f"{path}: switch rows")
        switches.append((row["function"], row["instruction"], row["ordinal"], row["opcode"],
                         row.get("cause")))
    return switches


def _load_v2(path, data: bytes, raw: dict) -> StackEvidence:
    if set(raw) != _FIELDS_V2 or raw["format"] != FORMAT or raw["detector"] != DETECTORS[2]:
        raise EvidenceError(f"{path}: not a {FORMAT} file (version 2, {DETECTORS[2]})")
    if any(type(raw[key]) is not str or not raw[key] for key in ("program", "language", "stack_pointer")):
        raise EvidenceError(f"{path}: program / language / stack_pointer")
    policies = raw["policies"]
    if type(policies) is not dict or set(policies) != set(POLICIES):
        raise EvidenceError(f"{path}: policies")
    off, on = policies["s3-off"], policies["s3-on"]
    if type(off) is not dict or set(off) != {"switches", "exceptions"} or off["exceptions"] != list(V5_OFF_EXCEPTIONS):
        raise EvidenceError(f"{path}: s3-off policy")
    if type(on) is not dict or set(on) != {"switches", "exceptions", "kernel_transfers", "language_x86_64",
                                           "fallback_switches"} \
            or on["exceptions"] != list(V5_ON_EXCEPTIONS) or type(on["language_x86_64"]) is not bool:
        raise EvidenceError(f"{path}: s3-on policy")
    if type(raw["bound"]) is not bool:
        raise EvidenceError(f"{path}: bound")
    digest = raw["listing_digest"]
    if type(digest) is not dict or set(digest) != {"verifiable_sha256", "attested_sha256"} \
            or any(type(item) is not str or len(item) != 64 for item in digest.values()):
        raise EvidenceError(f"{path}: listing_digest")
    pointer = raw["stack_pointer_coordinate"]
    if type(pointer) is not dict or set(pointer) != {"space_id", "byte_offset", "size"} \
            or any(type(item) is not int for item in pointer.values()):
        raise EvidenceError(f"{path}: stack_pointer_coordinate")
    kernels = []
    if type(on["kernel_transfers"]) is not list:
        raise EvidenceError(f"{path}: kernel transfer rows")
    for row in on["kernel_transfers"]:
        names = {"space_id", "byte_offset", "bytes", "class", "vector", "lift", "lift_vector", "exported"}
        if type(row) is not dict or set(row) != names or row["class"] not in KERNEL_CLASSES \
                or type(row["space_id"]) is not int or type(row["byte_offset"]) is not int \
                or type(row["bytes"]) is not str or type(row["lift"]) is not str \
                or type(row["exported"]) is not bool \
                or any(row[key] is not None and type(row[key]) is not str for key in ("vector", "lift_vector")):
            raise EvidenceError(f"{path}: kernel transfer rows")
        kernels.append(KernelTransfer(row["space_id"], row["byte_offset"], row["bytes"], row["class"], row["vector"],
                                      row["lift"], row["lift_vector"], row["exported"]))
    return StackEvidence(
        str(path), hashlib.sha256(data).hexdigest(), _sha(raw, path), str(raw["program"]), (), raw["detector"],
        *_counts(raw, path), tuple(row[:4] for row in _switches(off["switches"], path)), version=2,
        on_switches=tuple(_switches(on["switches"], path, cause=True)), kernel_transfers=tuple(kernels),
        bound=raw["bound"], listing_digest=(digest["verifiable_sha256"], digest["attested_sha256"]),
        stack_pointer=(pointer["space_id"], pointer["byte_offset"], pointer["size"]),
        language_x86_64=on["language_x86_64"],
        fallback_switches=tuple(_switches(on["fallback_switches"], path, cause=True)))


_ATTESTATION_KEY = secrets.token_bytes(32)   # (process-local: an attestation never leaves this process)


def _attestation(item: "StackEvidence") -> str:
    vouched = [item.digest, item.executable_sha256, item.detector, item.version, item.functions_scanned,
               item.instructions_scanned, item.instructions_outside_functions, list(item.switches),
               None if item.on_switches is None else list(item.on_switches),
               [list(astuple(row)) for row in item.kernel_transfers], item.bound,
               None if item.listing_digest is None else list(item.listing_digest), item.seal, item.applicable,
               item.rsp_verified, None if item.stack_pointer is None else list(item.stack_pointer),
               item.language_x86_64, None if item.fallback_switches is None else list(item.fallback_switches)]
    data = json.dumps(vouched, sort_keys=True, default=str).encode()
    return hmac.new(_ATTESTATION_KEY, data, hashlib.sha256).hexdigest()


def _attest(item: "StackEvidence", *, seal: str, applicable, rsp_verified: bool) -> "StackEvidence":
    """The admission's verified object (``verify_bundle_evidence`` only; tests)."""
    bound = replace(item, seal=seal, applicable=applicable, rsp_verified=rsp_verified, attestation=None)
    return replace(bound, attestation=_attestation(bound))


@dataclass(frozen=True, slots=True)
class Coverage:
    """(X-1 r4 4.4 / 4.5) what the consuming run decided for one image's s3-on
    conditions: the admitted covered sites and the trap sites the run itself
    resolved (cut as dead traps under the active premise and model, or an F1
    discharge valid for the analysis), each a (space, offset) of that image."""

    admitted: frozenset = frozenset()
    trap_decisions: frozenset = frozenset()
    # (Astra X-1a r1 P1-5) the verified Bundle seal these decisions were made
    # for: a decision of another export (another seal) decides nothing here
    seal: str | None = None


def authority(evidences, *, policy: str = "s3-off", images=(), seals=None, coverage=None) -> tuple[bool, list[str]]:
    """(X-1 r3 4.5 / r4 4.5) whether globals-disjoint-from-stack may rest on
    these evidence files, with the reasons when not -- the one reader.

    ``images``: executable SHA-256s that must each have evidence (the main
    image and every linked one; a missing image is a failure). Under s3-on the
    inventory is required and nonempty (Astra X-1a r1 P1-5, Fable r1 P2-1).
    ``seals`` (s3-on): executable SHA-256 -> the verified Bundle manifest
    SHA-256 the evidence must be bound to.
    ``coverage`` (s3-on): executable SHA-256 -> ``Coverage`` (bound to a seal).
    Under s3-on an image whose sealed original is affirmatively not S3's (not
    PE32+ / AMD64 / subsystem 1-3) is read by its s3-off verdict."""
    if policy not in POLICIES:
        raise ValueError(f"unknown stack evidence policy {policy!r}")
    evidences = tuple(evidences)
    images = tuple(images)
    reasons = []
    if policy == "s3-on" and not images:
        reasons.append("no participating-image inventory given (s3-on)")
    by_sha = {}
    for item in evidences:
        by_sha.setdefault(item.executable_sha256, []).append(item)
    for sha in images:
        if sha not in by_sha:
            reasons.append(f"no whole-program stack evidence for {sha[:12]}")
    for item in evidences:
        if not item._scanned():
            reasons.append(f"{item.program}: nothing scanned")
            continue
        if policy == "s3-off":
            if item.switches:
                reasons.append(f"stack switch evidence in {item.program}")
            continue
        if item.version != 2 or item.on_switches is None:
            reasons.append(f"{item.program}: stack evidence predates S3-aware scanning")
            continue
        if not item.bound or item.seal is None or not item.verified:
            reasons.append(f"{item.program}: unbound stack evidence carries no s3-on authority "
                           "(not verified by its Bundle's admission)")
            continue
        expected = None if seals is None else seals.get(item.executable_sha256)
        if expected is None or item.seal != expected:   # (Astra X-1a r2 P1-1: before either verdict)
            reasons.append(f"{item.program}: stack evidence is not bound to the run's verified Bundle")
            continue
        if item.applicable is False:   # (affirmatively outside S3: its verified s3-off verdict)
            if item.switches:
                reasons.append(f"stack switch evidence in {item.program}")
            continue
        if item.applicable is None:
            reasons.append(f"{item.program}: S3 applicability of the image is undecidable")
            continue
        if not item.rsp_verified or item.language_x86_64 is not True:
            reasons.append(f"{item.program}: the scan's stack pointer is not the sealed eight-byte RSP")
            continue
        if item.on_switches:
            reasons.append(f"stack switch evidence (s3-on) in {item.program}")
            continue
        decided = (coverage or {}).get(item.executable_sha256, Coverage())
        if decided.seal != item.seal:
            decided = Coverage()   # (decisions of another export decide nothing)
        open_rows = [row for row in item.kernel_transfers
                     if (row.kind == "covered" and row.site not in decided.admitted)
                     or (row.kind == "trap" and row.site not in decided.trap_decisions)
                     or row.kind in ("uncovered", "undecidable")]
        if open_rows:
            listed = ", ".join(f"{row.kind}@{row.space_id}:{row.byte_offset:x}" for row in open_rows[:5])
            more = f" (+{len(open_rows) - 5})" if len(open_rows) > 5 else ""
            reasons.append(f"{item.program}: kernel transfer row(s) not admitted or decided by the run: "
                           f"{listed}{more}")
    return not reasons, reasons


def assumption_allowed(evidences, *, requested: bool, require_for: str | None = None,
                       policy: str = "s3-off") -> tuple[bool, list[str]]:
    """(whether globals-disjoint-from-stack may be taken, report lines).
    ``requested``: the run asks for it; ``require_for``: an executable SHA-256
    whose own clean evidence is required (a library derivation) -- without it
    the assumption is not taken. Reads through ``authority``."""
    evidences = tuple(evidences)
    lines = [item.describe() for item in evidences]
    if not requested:
        return False, lines
    # (s3-on: the inventory the one reader requires; s3-off reads as before)
    images = (require_for,) if require_for is not None and policy == "s3-on" else ()
    allowed, reasons = authority([item for item in evidences], policy=policy, images=images)
    if not allowed:
        dirty = [item for item in evidences if not authority([item], policy=policy, images=images)[0]] \
            or list(evidences)
        return False, lines + [f"globals-disjoint-from-stack withdrawn: stack switch evidence in "
                               f"{', '.join(item.program for item in dirty)}"]
    if require_for is not None and not any(item.executable_sha256 == require_for for item in evidences):
        return False, lines + ["globals-disjoint-from-stack not taken: no whole-program stack evidence for "
                               f"{require_for[:12]}"]
    return True, lines


def verifiable_row_line(row: dict, read_bytes) -> str:
    """One row of the verifiable listing digest, exactly as
    ``GhidraV2StackSwitchScanner.rowLine`` writes it: ``R <space>:<offset hex>
    <length> <bytes hex | -> <flow override> <fallthrough 0/1> <length 0/1>
    <references space:offset:type:primary,... | ->``. Bytes come only from a sealed
    block member that holds the whole row."""
    address = row["address"]
    space, offset, length = address["space_id"], address["byte_offset"], row["length"]
    payload = read_bytes(space, offset, length)
    data = "-" if payload is None else payload.hex()
    override = row["override"]
    references = sorted(f"{item['address']['space_id']}:{item['address']['byte_offset']:x}:{item['type']}:"
                        f"{int(item['primary'])}" for item in override["override_references"])
    return (f"R {space}:{offset:x} {length} {data} {override['flow_override']} "
            f"{int(override['fallthrough_overridden'])} {int(override['length_overridden'])} "
            f"{','.join(references) if references else '-'}")


def pe_header_facts(data: bytes) -> tuple[int, int, int] | None:
    """(design_s3_r16 1.1, Astra X-1a r2 P2-7) (optional-header magic, COFF
    machine, subsystem) of a PE image, read from ``e_lfanew`` within the whole
    sealed original and bounds-checked against ``SizeOfOptionalHeader``; None
    when not decidable (the PE header or the subsystem field lies outside the
    file or the declared optional header)."""
    if len(data) < 0x40:
        return None
    (offset,) = struct.unpack_from("<I", data, 0x3C)
    if offset + 24 > len(data) or data[offset:offset + 4] != b"PE\0\0":
        return None
    machine, size_of_optional = struct.unpack_from("<H", data, offset + 4)[0], \
        struct.unpack_from("<H", data, offset + 20)[0]
    optional = offset + 24
    if size_of_optional < 70 or optional + size_of_optional > len(data):
        return None   # (the subsystem field, optional-header offset 68, is not inside the declared header)
    (magic,) = struct.unpack_from("<H", data, optional)
    (subsystem,) = struct.unpack_from("<H", data, optional + 68)
    return magic, machine, subsystem


def s3_applicable(data: bytes) -> bool | None:
    """(design_s3_r16 1.1) True for a PE32+ AMD64 image of subsystem 1 / 2 / 3,
    False for any other image (not PE at all, or another kind of PE), None when
    a PE's headers are not decidable. ``data``: the whole sealed original."""
    if data[:2] != b"MZ":
        return False
    facts = pe_header_facts(data)
    if facts is None:
        return None
    magic, machine, subsystem = facts
    return magic == 0x20B and machine == 0x8664 and subsystem in (1, 2, 3)


def sealed_rsp(program: dict) -> tuple[int, int, int] | None:
    """(Astra X-1a r1 P1-4) the unique eight-byte RSP of the sealed register
    table, when no other register of eight bytes or more overlaps it (its
    aliases -- ESP, SP, SPL -- lie inside it); None otherwise."""
    rows = ((program.get("register_evidence") or {}).get("registers") or [])
    rsp = [row for row in rows if str(row.get("name", "")).upper() == "RSP" and row.get("byte_size") == 8]
    if len(rsp) != 1:
        return None
    space, offset = rsp[0]["space_id"], rsp[0]["byte_offset"]
    for row in rows:
        if row is rsp[0] or row.get("space_id") != space:
            continue
        start, size = row.get("byte_offset"), row.get("byte_size")
        if type(start) is not int or type(size) is not int:
            return None
        overlaps = start < offset + 8 and offset < start + size
        if overlaps and (size >= 8 or not (offset <= start and start + size <= offset + 8)):
            return None
    return space, offset, 8


def observation_lines(raw: bytes, read_bytes) -> tuple[tuple[int, int], list[str]]:
    """(Astra X-1a r2 P2-6) one sealed observation reduced to its entry and its
    verifiable digest lines (the parsed object is dropped by the caller)."""
    observation = json.loads(raw)
    entry = observation["entry"]
    rows = sorted(observation["instructions"],
                  key=lambda row: (row["address"]["space_id"], row["address"]["byte_offset"]))
    return (entry["space_id"], entry["byte_offset"]), [verifiable_row_line(row, read_bytes) for row in rows]


def verify_bundle_evidence(*, evidence_bytes: bytes, manifest_sha256: str, original_sha256: str, original: bytes,
                           program: dict, functions) -> StackEvidence:
    """(X-1 r4 4.2, Astra X-1a r1 P1-3 / P1-4, r2 P1-1 / P1-4) the admission
    check of a profiled Bundle's sealed stack-switch evidence -- the only issuer
    of a verified (attested) object: bound v2, the executable SHA-256 of the
    sealed original, the verifiable listing digest recomputed from
    ``functions`` (``(entry, row lines)`` per observation), then the S3
    applicability of the original and the RSP identity. Raises
    ``EvidenceError`` when the evidence is not this Bundle's."""
    item = load_stack_evidence("stack-switch-evidence", data=evidence_bytes)
    if item.version != 2 or not item.bound:
        raise EvidenceError("the sealed stack-switch evidence is not bound version-2 evidence")
    if item.executable_sha256 != original_sha256:
        raise EvidenceError("the sealed stack-switch evidence is of another executable than the sealed original")
    digest = hashlib.sha256()
    for (space, offset), lines in sorted(functions):
        digest.update(f"F {space}:{offset:x}\n".encode())
        for line in lines:
            digest.update((line + "\n").encode())
    if digest.hexdigest() != item.listing_digest[0]:
        raise EvidenceError("the sealed stack-switch evidence's listing digest is not this Bundle's")
    rsp = sealed_rsp(program)
    return _attest(item, seal=manifest_sha256, applicable=s3_applicable(original),
                   rsp_verified=rsp is not None and item.stack_pointer == rsp)


def bundle_stack_evidence(generation) -> StackEvidence:
    """(X-1) the verified stack-switch evidence of a profiled frozen Bundle,
    through its normal admission (the provider verifies it while admitting)."""
    from ._configured_bundle_reader import read_configured_bundle
    from .integration.configured_bundle import admit_frozen_bundle

    provider = read_configured_bundle(admit_frozen_bundle(generation))
    try:
        return provider.stack_switch_evidence()
    finally:
        provider.close()


__all__ = ("Coverage", "DETECTORS", "EvidenceError", "FORMAT", "KernelTransfer", "POLICIES", "StackEvidence",
           "assumption_allowed", "authority", "bundle_stack_evidence", "load_stack_evidence", "pe_header_facts",
           "s3_applicable", "sealed_rsp", "verifiable_row_line", "verify_bundle_evidence")
