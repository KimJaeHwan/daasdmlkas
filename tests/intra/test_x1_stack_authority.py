"""X-1a (design_x1 r2 part 4, r3 4.5 / 4.7, r4 4.4 / 4.5; code review r1): version-2 stack evidence and the one
reader.

A v2 file (detector v5) carries the s3-off verdict (today's v4 rule), the S3-aware s3-on verdict, the fallback
verdict and the kernel-transfer rows. Loading binds nothing: only the admission of the Bundle the evidence is
sealed in (``verify_bundle_evidence``) assigns its seal, its S3 applicability and the RSP check. ``authority``
reads every file: under s3-off as before; under s3-on it needs a nonempty participating-image inventory and,
per image, verified evidence of the run's verified Bundle, a decidable applicability (an inapplicable image is
read by its s3-off verdict), the sealed eight-byte RSP, a clean s3-on verdict, every covered row admitted and
every trap row decided by the run -- decisions bound to the same seal; anything less withdraws the assumption
with its reason."""

from __future__ import annotations

import json
import struct
from dataclasses import replace

import pytest

from tdo_v2.stack_evidence import (
    Coverage, DETECTORS, EvidenceError, V5_OFF_EXCEPTIONS, V5_ON_EXCEPTIONS, _attest, assumption_allowed, authority,
    load_stack_evidence, pe_header_facts, s3_applicable, sealed_rsp,
)

CORE = "c" * 64
SEAL = "5" * 64
COVERED, TRAP = (1, 0x100), (1, 0x200)


def _row(address: str, cause: str | None = None) -> dict:
    row = {"function": "f", "instruction": address, "ordinal": 0, "opcode": "COPY", "text": "x"}
    if cause is not None:
        row["cause"] = cause
    return row


def _kernel(offset: int, kind: str, vector: str | None = None) -> dict:
    return {"space_id": 1, "byte_offset": offset, "bytes": "0f05", "class": kind, "vector": vector,
            "lift": "callother:syscall", "lift_vector": None, "exported": True}


def _v2(tmp_path, *, off=(), on=(), kernels=(), bound=True, name="core", x86=True, fallback=(), **change):
    raw = {
        "format": "tdo-v2-stack-switch-evidence", "version": 2, "detector": DETECTORS[2],
        "executable_sha256": CORE, "program": "/core.dll", "language": "x86:LE:64:default", "stack_pointer": "RSP",
        "functions_scanned": 3, "instructions_scanned": 30, "instructions_outside_functions": 0,
        "stack_pointer_coordinate": {"space_id": 4, "byte_offset": 32, "size": 8},
        "policies": {"s3-off": {"switches": list(off), "exceptions": list(V5_OFF_EXCEPTIONS)},
                     "s3-on": {"switches": list(on), "exceptions": list(V5_ON_EXCEPTIONS),
                               "kernel_transfers": list(kernels), "language_x86_64": x86,
                               "fallback_switches": list(fallback)}},
        "bound": bound, "listing_digest": {"verifiable_sha256": "a" * 64, "attested_sha256": "b" * 64},
    }
    raw.update(change)
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(raw))
    return path


def _load(tmp_path, **kwargs):
    return load_stack_evidence(_v2(tmp_path, **kwargs))


def _verified(item, *, seal=SEAL, applicable=True, rsp=True):
    """What a successful admission (``verify_bundle_evidence``) issues: an attested object."""
    return _attest(item, seal=seal, applicable=applicable, rsp_verified=rsp)


FULL = Coverage(frozenset({COVERED}), frozenset({TRAP}), SEAL)


def _on(items, *, images=(CORE,), seals=None, coverage=None):
    return authority(items, policy="s3-on", images=images, seals={CORE: SEAL} if seals is None else seals,
                     coverage={CORE: FULL} if coverage is None else coverage)


def test_v2_reads_its_verdicts_and_binds_nothing(tmp_path):
    item = _load(tmp_path, on=[_row("2000", "value")], kernels=[_kernel(0x100, "covered")],
                 fallback=[_row("3000", "value")])
    assert item.version == 2 and item.switches == () and len(item.on_switches) == 1
    assert item.on_switches[0][4] == "value" and item.kernel_transfers[0].site == COVERED
    assert item.fallback_switches[0][1] == "3000" and item.language_x86_64 is True
    assert item.stack_pointer == (4, 32, 8)
    assert item.seal is None and not item.verified and "s3-on: 1 switch(es)" in item.describe()


def test_s3_off_reads_v2_by_its_s3_off_verdict(tmp_path):
    clean = _load(tmp_path, on=[_row("2000", "value")])   # (s3-on dirty, s3-off clean)
    assert authority([clean])[0]
    assert assumption_allowed([clean], requested=True, require_for=CORE)[0]
    dirty = _load(tmp_path, off=[_row("2000")], name="dirty")
    assert not authority([dirty])[0]


KERNELS = [_kernel(0x100, "covered"), _kernel(0x200, "trap", "3")]
CASES = {
    "v1": "predates S3-aware scanning",
    "unbound": "not verified by its Bundle's admission",
    "loaded, not verified": "not verified by its Bundle's admission",
    "other seal": "not bound to the run's verified Bundle",
    "no seal given": "not bound to the run's verified Bundle",
    "applicability undecidable": "applicability of the image is undecidable",
    "rsp not verified": "not the sealed eight-byte RSP",
    "not x86-64 scan": "not the sealed eight-byte RSP",
    "s3-on switch": "stack switch evidence (s3-on)",
    "uncovered": "uncovered@1:300",
    "undecidable": "undecidable@1:300",
    "covered not admitted": "covered@1:100",
    "trap not decided": "trap@1:200",
    "coverage of another seal": "covered@1:100",
    "missing image": "no whole-program stack evidence for dddddddddddd",
    "no image inventory": "no participating-image inventory",
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_s3_on_withdraws_without_full_authority(tmp_path, case):
    """Astra X-1a r1 P1-3 / P1-4 / P1-5, Fable r1 P2-1: each missing piece withdraws, with its reason."""
    kwargs, verify, images, seals, coverage = dict(kernels=KERNELS), {}, (CORE,), None, None
    if case == "unbound":
        kwargs["bound"] = False
    elif case == "s3-on switch":
        kwargs["on"] = [_row("3000", "kernel-uncovered")]
    elif case in ("uncovered", "undecidable"):
        kwargs["kernels"] = [*KERNELS, _kernel(0x300, case, "128")]
    elif case == "not x86-64 scan":
        kwargs["x86"] = False
    elif case == "applicability undecidable":
        verify["applicable"] = None
    elif case == "rsp not verified":
        verify["rsp"] = False
    elif case == "covered not admitted":
        coverage = {CORE: Coverage(frozenset(), frozenset({TRAP}), SEAL)}
    elif case == "trap not decided":
        coverage = {CORE: Coverage(frozenset({COVERED}), frozenset(), SEAL)}
    elif case == "coverage of another seal":   # (a UD2 discharge / admission of an earlier export)
        coverage = {CORE: Coverage(frozenset({COVERED}), frozenset({TRAP}), "6" * 64)}
    elif case == "other seal":
        seals = {CORE: "6" * 64}
    elif case == "no seal given":
        seals = {}
    elif case == "missing image":
        images = (CORE, "d" * 64)
    elif case == "no image inventory":
        images = ()
    if case == "v1":
        from tdo_v2.stack_evidence import StackEvidence

        item = StackEvidence("p", "0" * 64, CORE, "/core.dll", (), DETECTORS[1], 1, 1, 0, ())
    else:
        item = _load(tmp_path, **kwargs)
        if case not in ("unbound", "loaded, not verified"):
            item = _verified(item, **verify)
    allowed, reasons = _on([item], images=images, seals=seals, coverage=coverage)
    assert not allowed and any(CASES[case] in reason for reason in reasons), reasons
    # the control: the same file, verified and fully covered, under the same run
    control = _verified(_load(tmp_path, kernels=KERNELS, name="control"))
    assert _on([control]) == (True, [])


def test_an_inapplicable_image_is_read_by_its_s3_off_verdict(tmp_path):
    """r4 4.3: an image affirmatively outside S3 (not PE32+ / AMD64 / subsystem 1-3) uses its verified s3-off
    verdict -- only after the run's seal (Astra X-1a r2 P1-1): two exports of one inapplicable image, the clean
    one of seal A does not stand for a run requiring seal B."""
    clean = _verified(_load(tmp_path, on=[_row("3000", "kernel-uncovered")]), applicable=False)
    assert _on([clean])[0]
    dirty = _verified(_load(tmp_path, off=[_row("3000")], name="dirty"), applicable=False, seal="6" * 64)
    assert not _on([dirty], seals={CORE: "6" * 64})[0]
    assert not _on([clean], seals={CORE: "6" * 64})[0]   # (A's clean verdict, B required)
    assert not _on([clean], seals={})[0]                 # (no seal for the image)


def test_a_changed_copy_of_a_verified_object_is_not_verified(tmp_path):
    """Astra X-1a r2 P1-1: verified only as issued -- clearing the s3-on switches (or any vouched field) of a
    copy drops it."""
    dirty = _verified(_load(tmp_path, kernels=KERNELS, on=[_row("3000", "value")]))
    assert dirty.verified and not _on([dirty])[0]
    forged = replace(dirty, on_switches=())
    assert not forged.verified
    assert any("not verified" in reason for reason in _on([forged])[1])
    assert not replace(dirty, applicable=False).verified and not replace(dirty, seal="6" * 64).verified


def test_empty_s3_on_input_fails_closed():
    """Astra X-1a r1 P1-5 / Fable r1 P2-1: no evidence and no inventory does not pass under s3-on."""
    assert authority([], policy="s3-on") == (False, ["no participating-image inventory given (s3-on)"])
    assert not assumption_allowed([], requested=True, policy="s3-on")[0]
    assert authority([])[0]   # (s3-off: as before)


def test_every_image_needs_evidence_under_either_policy(tmp_path):
    item = _load(tmp_path)
    assert not authority([item], images=(CORE, "d" * 64))[0]   # (a linked image without a scan)
    assert authority([item], images=(CORE,))[0]
    assert not authority([], images=(CORE,))[0]


def _pe(magic=0x20B, machine=0x8664, subsystem=3, *, offset=0x80, size=0x200, optional=240) -> bytes:
    data = bytearray(max(size, offset + 24 + max(optional, 70)))
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, offset)
    data[offset:offset + 4] = b"PE\0\0"
    struct.pack_into("<H", data, offset + 4, machine)
    struct.pack_into("<H", data, offset + 20, optional)
    struct.pack_into("<H", data, offset + 24, magic)
    struct.pack_into("<H", data, offset + 24 + 68, subsystem)
    return bytes(data[:size]) if size < len(data) else bytes(data)


def test_the_s3_applicability_predicate():
    """design_s3_r16 1.1 / Astra X-1a r1 P1-4: PE32+, AMD64, subsystem 1 / 2 / 3; anything else inapplicable;
    a PE whose headers cannot be read undecidable."""
    assert pe_header_facts(_pe()) == (0x20B, 0x8664, 3) and s3_applicable(_pe()) is True
    assert s3_applicable(_pe(subsystem=1)) is True and s3_applicable(_pe(subsystem=2)) is True
    assert s3_applicable(_pe(subsystem=10)) is False       # (an EFI application: excluded subsystem)
    assert s3_applicable(_pe(magic=0x10B)) is False        # (PE32)
    assert s3_applicable(_pe(machine=0x14C)) is False      # (i386)
    assert s3_applicable(b"\x7fELF" + bytes(60)) is False  # (not a PE at all)
    assert s3_applicable(_pe(offset=5000, size=6000)) is True   # (Astra X-1a r2 P2-7: read where e_lfanew says)
    assert s3_applicable(_pe(optional=0)) is None          # (no optional header declared: undecidable)
    assert s3_applicable(_pe(optional=60)) is None         # (the subsystem field outside the declared header)
    assert s3_applicable(_pe(offset=0x1F0, size=0x200)) is None   # (the header past the end of the file)
    assert s3_applicable(b"MZ" + bytes(10)) is None        # (truncated)


def _registers(*rows):
    return {"register_evidence": {"revision": 1, "registers": [
        {"name": name, "space_id": 4, "byte_offset": offset, "byte_size": size} for name, offset, size in rows]}}


def test_the_sealed_rsp_identity():
    """Astra X-1a r1 P1-4: the unique eight-byte RSP with its aliases inside it; anything else has none."""
    ok = _registers(("RSP", 32, 8), ("ESP", 32, 4), ("SP", 32, 2), ("SPL", 32, 1), ("RAX", 0, 8))
    assert sealed_rsp(ok) == (4, 32, 8)
    assert sealed_rsp(_registers(("RSP", 32, 4))) is None                         # (a four-byte SP)
    assert sealed_rsp(_registers(("RSP", 32, 8), ("RSP", 40, 8))) is None         # (not unique)
    assert sealed_rsp(_registers(("RSP", 32, 8), ("XSP", 32, 8))) is None         # (another 8-byte alias)
    assert sealed_rsp(_registers(("RSP", 32, 8), ("WIDE", 24, 16))) is None       # (a wider overlap)
    assert sealed_rsp({}) is None


@pytest.mark.parametrize("change", [{"detector": DETECTORS[1]}, {"policies": {}}, {"bound": 1},
                                    {"listing_digest": {"verifiable_sha256": "a"}},
                                    {"stack_pointer_coordinate": {"space_id": 4}}, {"extra": 1}])
def test_malformed_v2_is_rejected(tmp_path, change):
    with pytest.raises(EvidenceError):
        _load(tmp_path, **change)


def test_malformed_v2_rows_are_rejected(tmp_path):
    with pytest.raises(EvidenceError):
        _load(tmp_path, on=[_row("2000")])   # (an s3-on row without its cause)
    with pytest.raises(EvidenceError):
        _load(tmp_path, kernels=[{**_kernel(0x100, "covered"), "class": "maybe"}])
    with pytest.raises(EvidenceError):
        _load(tmp_path, x86="yes")


def test_unknown_policy_is_an_error(tmp_path):
    with pytest.raises(ValueError):
        authority([_load(tmp_path)], policy="s3-maybe")


def test_an_s3_on_template_needs_its_recorded_authority():
    """r4 4.5 item 4 / Fable r1 P2-1: an s3-on run refuses a template without the stack-switch authority it was
    derived under, with another, or when the run passes none; an s3-off run is unchanged."""
    from types import SimpleNamespace

    from tdo_v2.summary_templates import refusal

    current = {"policy": "s3-on", "seal": SEAL, "evidence_digest": "e" * 64, "coverage": "c" * 64}
    from tdo_v2.summary_store import stack_authority_problem

    assert stack_authority_problem(current) is None
    for key in current:   # (Astra X-1a r2 P1-5: every field required)
        assert stack_authority_problem({k: v for k, v in current.items() if k != key}) is not None
    assert stack_authority_problem({}) is not None

    def template(recorded):
        return SimpleNamespace(source_field=lambda key: recorded if key == "stack_authority" else None)

    entry = SimpleNamespace(refusal=None)
    common = dict(external_models=None, pcodeop_models=None, private_frame_above=0)
    on = dict(common, policy="s3-on")
    assert "without the s3-on" in refusal(template(None), entry, stack_authority=current, **on)
    assert "another stack-switch authority" in refusal(template({**current, "seal": "6" * 64}), entry,
                                                       stack_authority=current, **on)
    assert "another stack-switch authority" in refusal(template({**current, "coverage": "d" * 64}), entry,
                                                       stack_authority=current, **on)
    assert "needs the complete s3-on stack-switch authority" in refusal(template(current), entry, **on)   # (forgotten)
    assert "needs the complete s3-on stack-switch authority" in refusal(template({}), entry, stack_authority={}, **on)
    assert "derived under s3-on" in refusal(template(current), entry, **common)   # (an ON template under OFF)
    off = {**current, "policy": "s3-off"}   # (Astra X-1a r3 #5: matching s3-off records do not serve an s3-on run)
    assert refusal(template(off), entry, stack_authority=off, **on) is not None
    refused = SimpleNamespace(refusal="engine version")
    assert refusal(template(None), refused, stack_authority=current, **on) == "engine version"


def test_an_actual_standalone_scan_loads_and_withdraws():
    """Astra X-1a r1 P1-2 / r2 P2-11: real standalone wrapper output (ntdll, the v5 wrapper with null fields kept:
    its syscall rows carry ``vector: null``) loads, and its s3-off switches withdraw the assumption through the
    reader the linker uses."""
    import os
    from pathlib import Path

    path = Path(os.environ.get("TDO_X1_STANDALONE_SCAN", "/root/x1_scan_ntdll2/x1.json"))
    if not path.is_file():
        pytest.skip("set TDO_X1_STANDALONE_SCAN to a standalone v5 scan")
    item = load_stack_evidence(path)
    assert item.version == 2 and not item.bound and not item.verified
    assert any(row.kind == "covered" and row.vector is None for row in item.kernel_transfers)   # (syscall rows)
    assert item.switches   # (ntdll's s3-off switches)
    assert not authority([item])[0]   # (linking.py: `if not authority([load_stack_evidence(evidence)])[0]`)
    assert not assumption_allowed([item], requested=True)[0]
    assert not authority([item], policy="s3-on", images=(item.executable_sha256,))[0]   # (unbound)
