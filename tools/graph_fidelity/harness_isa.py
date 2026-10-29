"""Per-language register facts the measurement oracles seed and havoc by:
Ghidra register offsets (TEST-ONLY tool data, never read by the engine).
``sp``: the stack pointer used when a function shows no call shape;
``registers``: the pointer-sized registers seeded with candidate values."""

from __future__ import annotations

_TABLES = {
    "x86:LE:64": {"sp": (0x20, 8), "registers": tuple(range(0, 0x40, 8))},         # RAX..RDI; RSP
    "x86:LE:32": {"sp": (0x10, 4), "registers": tuple(range(0, 0x40, 8))},         # (as before); ESP
    "AARCH64:LE:64": {"sp": (0x8, 8), "registers": tuple(range(0x4000, 0x40F8, 8))},  # x0..x30; sp
}


def isa_of(language_id: str) -> dict:
    """The table of a Ghidra language id (processor:endian:size); unknown
    languages are refused, never read as x86."""
    key = ":".join(language_id.split(":")[:3])
    if key not in _TABLES:
        raise ValueError(f"no oracle register table for {language_id}")
    return _TABLES[key]
