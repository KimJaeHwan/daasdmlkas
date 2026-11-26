"""X-1a (design_x1 r2 part 4, r3 4.5 / 4.7, r4 4.4 / 4.5): version-2 stack evidence and the one reader.

A v2 file (detector v5) carries the s3-off verdict (today's v4 rule), the S3-aware s3-on verdict and the
kernel-transfer rows. ``authority`` reads every file: under s3-off as before; under s3-on only bound evidence of
the run's verified Bundle counts, with a clean s3-on verdict, every covered row admitted and every trap row
decided by the run; v1, unbound or mis-sealed evidence, an image without evidence, an uncovered or undecidable
kernel row withdraw the assumption with their reasons."""

from __future__ import annotations

import json

import pytest

from tdo_v2.stack_evidence import (
    Coverage, DETECTORS, EvidenceError, V5_OFF_EXCEPTIONS, V5_ON_EXCEPTIONS, assumption_allowed, authority,
    load_stack_evidence,
)

CORE = "c" * 64
SEAL = "5" * 64


def _row(address: str, cause: str | None = None) -> dict:
    row = {"function": "f", "instruction": address, "ordinal": 0, "opcode": "COPY", "text": "x"}
    if cause is not None:
        row["cause"] = cause
    return row


def _kernel(offset: int, kind: str, vector: str | None = None) -> dict:
    return {"space_id": 1, "byte_offset": offset, "bytes": "0f05", "class": kind, "vector": vector,
            "lift": "callother:syscall", "lift_vector": None, "exported": True}


def _v2(tmp_path, *, off=(), on=(), kernels=(), bound=True, name="core", **change) -> dict:
    raw = {
        "format": "tdo-v2-stack-switch-evidence", "version": 2, "detector": DETECTORS[2],
        "executable_sha256": CORE, "program": "/core.dll", "language": "x86:LE:64:default", "stack_pointer": "RSP",
        "functions_scanned": 3, "instructions_scanned": 30, "instructions_outside_functions": 0,
        "stack_pointer_coordinate": {"space_id": 4, "byte_offset": 32, "size": 8},
        "policies": {"s3-off": {"switches": list(off), "exceptions": list(V5_OFF_EXCEPTIONS)},
                     "s3-on": {"switches": list(on), "exceptions": list(V5_ON_EXCEPTIONS),
                               "kernel_transfers": list(kernels)}},
        "bound": bound, "listing_digest": {"verifiable_sha256": "a" * 64, "attested_sha256": "b" * 64},
    }
    raw.update(change)
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(raw))
    return path


def _load(tmp_path, *, seal=SEAL, **kwargs):
    return load_stack_evidence(_v2(tmp_path, **kwargs), seal=seal)


def test_v2_reads_both_verdicts(tmp_path):
    item = _load(tmp_path, on=[_row("2000", "value")], kernels=[_kernel(0x100, "covered")])
    assert item.version == 2 and item.switches == () and len(item.on_switches) == 1
    assert item.on_switches[0][4] == "value" and item.kernel_transfers[0].site == (1, 0x100)
    assert item.bound and item.seal == SEAL and "s3-on: 1 switch(es)" in item.describe()


def test_an_unbound_file_has_no_seal(tmp_path):
    assert _load(tmp_path, bound=False).seal is None


def test_s3_off_reads_v2_by_its_s3_off_verdict(tmp_path):
    clean = _load(tmp_path, on=[_row("2000", "value")])   # (s3-on dirty, s3-off clean)
    assert authority([clean])[0]
    assert assumption_allowed([clean], requested=True, require_for=CORE)[0]
    dirty = _load(tmp_path, off=[_row("2000")], name="dirty")
    assert not authority([dirty])[0]


@pytest.mark.parametrize("case", ("v1", "unbound", "other seal", "no seal given", "s3-on switch", "uncovered",
                                  "undecidable", "covered not admitted", "trap not decided", "missing image"))
def test_s3_on_withdraws_without_full_authority(tmp_path, case):
    seals, coverage, images = {CORE: SEAL}, {CORE: Coverage(frozenset({(1, 0x100)}), frozenset({(1, 0x200)}))}, ()
    kernels = [_kernel(0x100, "covered"), _kernel(0x200, "trap", "3")]
    kwargs = dict(kernels=kernels)
    if case == "unbound":
        kwargs["bound"] = False
    elif case == "s3-on switch":
        kwargs["on"] = [_row("3000", "kernel-uncovered")]
    elif case == "uncovered":
        kwargs["kernels"] = [*kernels, _kernel(0x300, "uncovered", "128")]
    elif case == "undecidable":
        kwargs["kernels"] = [*kernels, _kernel(0x300, "undecidable")]
    elif case == "covered not admitted":
        coverage = {CORE: Coverage(frozenset(), frozenset({(1, 0x200)}))}
    elif case == "trap not decided":
        coverage = {CORE: Coverage(frozenset({(1, 0x100)}), frozenset())}
    elif case == "other seal":
        seals = {CORE: "6" * 64}
    elif case == "no seal given":
        seals = None
    elif case == "missing image":
        images = (CORE, "d" * 64)
    if case == "v1":
        from tdo_v2.stack_evidence import StackEvidence

        item = StackEvidence("p", "0" * 64, CORE, "/core.dll", (), DETECTORS[1], 1, 1, 0, ())
    else:
        item = _load(tmp_path, **kwargs)
    allowed, reasons = authority([item], policy="s3-on", images=images, seals=seals, coverage=coverage)
    assert not allowed and reasons
    expected = {"v1": "predates S3-aware scanning", "unbound": "unbound stack evidence",
                "other seal": "not bound to the run's verified Bundle"}.get(case)
    assert expected is None or any(expected in reason for reason in reasons), reasons
    # the control: the same file, fully covered, under the same run
    control = _load(tmp_path, kernels=kernels, name="control")
    assert authority([control], policy="s3-on", seals={CORE: SEAL},
                     coverage={CORE: Coverage(frozenset({(1, 0x100)}), frozenset({(1, 0x200)}))})[0]


def test_every_image_needs_evidence_under_either_policy(tmp_path):
    item = _load(tmp_path)
    assert not authority([item], images=(CORE, "d" * 64))[0]   # (a linked image without a scan)
    assert authority([item], images=(CORE,))[0]
    assert not authority([], images=(CORE,))[0]


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


def test_unknown_policy_is_an_error(tmp_path):
    with pytest.raises(ValueError):
        authority([_load(tmp_path)], policy="s3-maybe")


def test_an_s3_on_template_needs_its_recorded_authority():
    """r4 4.5 item 4: an s3-on run refuses a template without the stack-switch authority it was derived under,
    or with another (seal, evidence, policy or coverage); an s3-off run (no authority asked) is unchanged."""
    from types import SimpleNamespace

    from tdo_v2.summary_templates import refusal

    current = {"policy": "s3-on", "seal": SEAL, "evidence_digest": "e" * 64, "coverage": "c" * 64}

    def template(recorded):
        return SimpleNamespace(source_field=lambda key: recorded if key == "stack_authority" else None)

    entry = SimpleNamespace(refusal=None)
    common = dict(external_models=None, pcodeop_models=None, private_frame_above=0)
    assert "without the s3-on" in refusal(template(None), entry, stack_authority=current, **common)
    assert "another stack-switch authority" in refusal(template({**current, "seal": "6" * 64}), entry,
                                                       stack_authority=current, **common)
    assert "another stack-switch authority" in refusal(template({**current, "coverage": "d" * 64}), entry,
                                                       stack_authority=current, **common)
    refused = SimpleNamespace(refusal="engine version")
    assert refusal(template(None), refused, stack_authority=current, **common) == "engine version"
