"""G1 ``tools/decode_check``: mapping and decoder cross-check on synthetic sealed
Bundles whose `original` is a synthetic PE32+ (tools/decode_check/_pe_fixture.py).

POSIX (admission) and the built decoders ($G1_DECODERS, build_decoders.sh) are
required; the tests skip otherwise.
"""

import os
from pathlib import Path
import sys

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "decode_check"))
sys.path.insert(0, str(REPO / "tools" / "bundle_lint"))

DECODERS = Path(os.environ.get("G1_DECODERS", "/root/g1_decoders"))
needs = pytest.mark.skipif(os.name != "posix" or not (DECODERS / "lib" / "libdc_xed.so").exists(),
                           reason="POSIX admission and the built decoders are required")

BASE = 0x140000000
CODE = BASE + 0x1000


def _bundle(tmp_path, functions, code: bytes, *, code_raw=None, image_base=BASE, program_base=None, pe_base=None):
    import _pe_fixture as pf
    import _sealed as s

    section = pf.Section(".text", 0x1000, code, raw=code_raw)
    original = pf.make_pe([section], image_base=pe_base or image_base)
    blocks = [s.Block(start=start, data=data, name=".text" if start != image_base else "Headers")
              for start, data in pf.blocks_for([section], original, image_base=image_base)]
    bundle = s.Bundle(functions, blocks=blocks, program=s.program(image_base=program_base or image_base),
                      overrides={"original": original})
    os.chmod(tmp_path, 0o755)
    return s.write(tmp_path, bundle)


def _pair(s, call_bytes=b"\xE8\x0B\x00\x00\x00", call_length=None):
    """A at CODE: call B (CODE + 0x10), ret; B: mov rax, rcx; ret."""
    length = call_length or len(call_bytes)
    after = CODE + len(call_bytes)
    a = s.Function("A", s.observation(CODE, [s.call(CODE, CODE + 0x10, length=length), s.ret(after)]))
    if call_length is not None:   # (a Ghidra row whose length disagrees with the bytes)
        a.observation["instructions"][0]["fallthrough"] = s.coord(after)
        a.observation["instructions"][0]["operations"][1]["inputs"][2] = s.const(after)
    b = s.Function("B", s.observation(CODE + 0x10, [s.plain(CODE + 0x10, 3, ("COPY", [s.reg(s.RCX)], s.reg(s.RAX))),
                                                     s.ret(CODE + 0x13)]))
    code = bytearray(b"\xCC" * 0x20)
    code[0:len(call_bytes)] = call_bytes
    code[len(call_bytes)] = 0xC3
    code[0x10:0x14] = b"\x48\x89\xC8\xC3"
    return [a, b], bytes(code)


def _run(gen, premise=True):
    import _sealed as s
    import decode_check

    header, rows = decode_check.run(gen, s.NAMING_SOURCE, premise, full=True)
    found = {row.ident(): row for row in rows}
    assert len(found) == len(rows)
    return header, found


@needs
def test_reference_pair_rows_are_applied_with_the_translation_premise(tmp_path):
    import _sealed as s

    functions, code = _pair(s)
    header, rows = _run(_bundle(tmp_path, functions, code))
    assert header["global_reason"] is None
    assert rows[("mapping", "original", "bundle")].verdict == "applied"
    for key in ("function-000000/1:140001000", "function-000000/1:140001005", "function-000001/1:140001010",
                "function-000001/1:140001013"):
        row = rows[("decode", "row", key)]
        assert (row.run_state, row.verdict) == ("evaluated", "applied"), (key, row.detail)
    call = rows[("decode", "row", "function-000000/1:140001000")].detail["attributes"]
    assert call["a5"]["value"] == CODE + 0x10 and call["a7"]["value"] == [64, CODE + 5]


@needs
def test_without_the_premise_only_a1_a2_a4_are_compared(tmp_path):
    import _sealed as s

    functions, code = _pair(s)
    _, rows = _run(_bundle(tmp_path, functions, code), premise=False)
    row = rows[("decode", "row", "function-000000/1:140001000")]
    attributes = row.detail["attributes"]
    assert {name for name, item in attributes.items() if item["state"] == "applied"} == {"a1", "a2", "a4"}
    assert attributes["a5"]["reason"].startswith("translation-unverified")
    assert row.run_state == "unobserved"


@needs
def test_a_wrong_ghidra_length_is_a_decode_suspect(tmp_path):
    """B's mov rax, rcx is 3 bytes; Ghidra says 2 (its listing continuation stays the next row)."""
    import _sealed as s

    functions, code = _pair(s)
    functions[1].observation["instructions"][0]["length"] = 2
    _, rows = _run(_bundle(tmp_path, functions, code))
    row = rows[("decode", "row", "function-000001/1:140001010")]
    attributes = row.detail["attributes"]
    assert attributes["a2"]["kind"] == "ghidra-decode-suspect" and attributes["a4"]["state"] == "applied"
    assert row.verdict == "unrecognized" and row.detail["kind"] == "ghidra-decode-suspect"
    assert any(ident[1] == "suspect" for ident in rows)


@needs
def test_a_native_call_whose_length_and_continuation_disagree_is_an_internal_inconsistency(tmp_path):
    import _sealed as s

    functions, code = _pair(s, call_length=4)
    _, rows = _run(_bundle(tmp_path, functions, code))
    row = rows[("decode", "row", "function-000000/1:140001000")]
    assert row.detail["attributes"]["a2"]["kind"] == "ghidra-internal-inconsistency"


@needs
def test_66_e8_is_withheld_as_a_vendor_or_amd_split(tmp_path):
    import _sealed as s

    functions, code = _pair(s, call_bytes=b"\x66\xE8\x0A\x00\x00\x00")
    _, rows = _run(_bundle(tmp_path, functions, code))
    row = rows[("decode", "row", "function-000000/1:140001000")]
    assert row.verdict == "withheld", row.detail
    assert row.detail["attributes"]["a2"]["state"] == "withheld"


@needs
def test_a_sealed_byte_that_differs_from_the_file_stops_the_window(tmp_path):
    import _sealed as s

    functions, code = _pair(s)
    raw = bytearray(code)
    raw[2] ^= 0xFF   # (the file's call displacement differs from Ghidra's sealed bytes)
    _, rows = _run(_bundle(tmp_path, functions, code, code_raw=bytes(raw)))
    assert rows[("mapping", "block", "#1/1:140001000")].verdict == "unrecognized"
    row = rows[("decode", "row", "function-000000/1:140001000")]
    assert row.run_state == "unobserved"


@needs
def test_a_bundle_not_at_the_preferred_base_is_not_compared(tmp_path):
    import _sealed as s

    functions, code = _pair(s)
    header, rows = _run(_bundle(tmp_path, functions, code, pe_base=BASE + 0x10000000))
    assert "preferred base" in header["global_reason"]
    decode = [row for ident, row in rows.items() if ident[:2] == ("decode", "row")]
    assert decode and all(row.run_state == "unobserved" for row in decode)
