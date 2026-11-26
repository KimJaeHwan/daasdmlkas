"""X-1a (design_x1 r3 4.3, r4 4.3; Astra X-1a r1 P1-6): the scanner's byte classifier, compiled from its source.

``GhidraV2StackSwitchScanner.classifyBytes`` classifies the bytes at an instruction start: covered candidates
(unprefixed ``0F 05`` / ``CD 2E``), traps (``CC`` / ``CD 03`` / ``CD 29`` / ``0F 0B``), other kernel transfers
(uncovered), and -- whenever the readable bytes end inside a kernel-form prefix (a bare ``0F`` or ``CD``, ``0F 01``,
prefixes only) or a prefix / REX byte precedes a kernel form -- undecidable. Only the classified bytes are
recorded. The harness compiles the actual Java members (no reimplementation)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def _member(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


CASES = [
    # (bytes, readable count, expected "kind/vector/formLength/bytes" or "null")
    ("0f05", 2, "covered/null/2/0f05"),
    ("0f0590", 3, "covered/null/2/0f05"),          # (a final-byte NOP after it is not part of the form)
    ("cd2e", 2, "covered/46/2/cd2e"),
    ("cc", 1, "trap/3/1/cc"),
    ("cd03", 2, "trap/3/2/cd03"),
    ("cd29", 2, "trap/41/2/cd29"),
    ("0f0b", 2, "trap/ud/2/0f0b"),
    ("cd80", 2, "uncovered/128/2/cd80"),
    ("0f34", 2, "uncovered/null/2/0f34"),
    ("f4", 1, "uncovered/null/1/f4"),
    ("0f01c1", 3, "uncovered/null/3/0f01c1"),
    ("0f01d0", 3, "null"),                          # (xgetbv: not a kernel form)
    ("0f", 1, "undecidable/null/1/0f"),             # (a bare 0F at a gap)
    ("0f01", 2, "undecidable/null/2/0f01"),         # (0F 01 at a gap)
    ("cd", 1, "undecidable/null/1/cd"),
    ("480f05", 3, "undecidable/null/3/480f05"),     # (REX before syscall)
    ("66480f05", 4, "undecidable/null/4/66480f05"), # (mixed legacy prefix and REX)
    ("f3", 1, "undecidable/null/1/f3"),             # (a truncated prefix at a gap)
    ("", 0, "undecidable/null/0/"),                 # (no readable byte)
    ("4889c3", 3, "null"),                          # (REX + an ordinary mov)
    ("90", 1, "null"),
]


def test_the_byte_classifier(tmp_path):
    if shutil.which("javac") is None or shutil.which("java") is None:
        pytest.skip("Java compiler/runtime unavailable")
    source = (Path(__file__).resolve().parents[2] / "ghidra" / "GhidraV2StackSwitchScanner.java").read_text()
    helpers = "\n".join(_member(source, signature) for signature in (
        "record Kernel(", "static Kernel classifyBytes(", "private static Kernel kernel(", "private static String hex(",
    ))
    constants = source[source.index("    private static final Set<Integer> LEGACY_PREFIXES"):]
    constants = constants[:constants.index(";") + 1]
    checks = "\n".join(
        f'        check("{data}", {count}, "{expected}");' for data, count, expected in CASES)
    harness = f"""import java.util.*;
public class ClassifyTest {{
{constants}
{helpers}
    static void check(String data, int count, String expected) {{
        byte[] buffer = new byte[15];
        for (int index = 0; index < data.length() / 2; index++) {{
            buffer[index] = (byte) Integer.parseInt(data.substring(2 * index, 2 * index + 2), 16);
        }}
        Kernel kernel = classifyBytes(buffer, count);
        String actual = kernel == null ? "null"
            : kernel.kind() + "/" + kernel.vector() + "/" + kernel.formLength() + "/" + kernel.bytes();
        if (!actual.equals(expected)) {{
            throw new AssertionError(data + ": " + actual + " != " + expected);
        }}
    }}
    public static void main(String[] args) {{
{checks}
    }}
}}
"""
    path = tmp_path / "ClassifyTest.java"
    path.write_text(harness)
    subprocess.run(["javac", str(path)], check=True, capture_output=True, text=True, timeout=60)
    done = subprocess.run(["java", "-cp", str(tmp_path), "ClassifyTest"], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
