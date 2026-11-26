"""Build the userop classification test binary from sleigh_userops.py output (POSIX / WSL, GNU as + ld).

For every instruction constructor that uses a userop, an Intel-syntax line is generated from its display text
(operand symbols -> concrete operands; register form first, a memory form as the fallback), assembled with GNU as
(failing lines are dropped and retried with the next form), and placed in its own function ``u<NNNN>: insn ; ret``
of an ELF shared object. ``<out>/map.json`` maps each function to its userops, constructor and text; constructors
no form assembles are listed as ``not_assembled`` (classified "not exercisable", never guessed).

Generated artefacts stay local; only this generator is committed.

    python3 tools/decode_check/userop_testbin.py userops.json --out <dir>
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess

SIZES = {"8": "byte", "16": "word", "32": "dword", "64": "qword", "80": "tbyte", "128": "xmmword", "256": "ymmword",
         "512": "zmmword"}
GPR = {"Reg8": "bl", "Reg16": "bx", "Reg32": "ebx", "Reg64": "rbx", "rm8": "cl", "rm16": "cx", "rm32": "ecx",
       "rm64": "rcx", "Rmr8": "dl", "Rmr16": "dx", "Rmr32": "edx", "Rmr64": "rdx", "r32": "esi", "r64": "rsi",
       "Reg32_m8": "ebx", "Reg32_m16": "ebx", "Reg64_m8": "rbx"}


class Allocator:
    """Distinct registers per class in order of appearance (xmm1, xmm2, ...)."""

    def __init__(self) -> None:
        self.next = {}

    def take(self, kind: str) -> str:
        index = self.next.get(kind, 1)
        self.next[kind] = index + 1
        return f"{kind}{index}"


def operand(token: str, alloc: Allocator, memory: bool):
    """The concrete operand for one SLEIGH display operand, or None when not mapped."""
    token = token.split("^")[0].strip()
    if not token:
        return None
    for kind, register in (("Zmm", "zmm"), ("Ymm", "ymm"), ("Xmm", "xmm")):
        if kind + "Reg2_m" in token or token.startswith(f"{kind}Reg2_m"):
            if memory:
                size = re.search(r"_m(\d+)", token)
                return f"{SIZES.get(size.group(1), '') + ' ptr ' if size else ''}[rax]"
            return alloc.take(register)
        if kind + "Reg" in token:
            return alloc.take(register)
    if token.startswith("mmxreg2_m") and memory:
        return "qword ptr [rax]"
    if token.startswith("mmxreg"):
        return alloc.take("mm")
    if token.startswith("KReg"):
        return alloc.take("k")
    if token.startswith("bnd"):
        return "bnd0"
    if re.fullmatch(r"(s?imm|imm)\d*", token) or re.fullmatch(r"imm\d+_\d+", token):
        return "1"
    match = re.fullmatch(r"m(\d+)", token)
    if match:
        return f"{SIZES.get(match.group(1), '')} ptr [rax]"
    if token in ("m", "Mem", "mem"):
        return "[rax]"
    if token in GPR:
        return GPR[token]
    vsib = re.fullmatch(r"([xyz])_vm(32|64)[xyz]", token)
    if vsib:
        return f"[rax+{vsib.group(1)}mm4*4]"
    if re.fullmatch(r"(AL|AX|EAX|RAX|CL|CX|ECX|RCX|DX|EDX|RDX|ST0|ST\d|CS|DS|ES|FS|GS|SS)", token):
        return token.lower()
    return None


def forms(display: str) -> list:
    """Candidate assembly lines for one constructor display (register form, then memory form)."""
    body = display[1:] if display.startswith(":") else display
    parts = body.split(" ", 1)
    mnemonic = parts[0].split("^")[0].lower()
    if not re.fullmatch(r"[a-z][a-z0-9.]*", mnemonic):
        return []
    tokens = [item.strip() for item in parts[1].split(",")] if len(parts) > 1 and parts[1].strip() else []
    out = []
    for memory in (False, True):
        alloc = Allocator()
        ops = [operand(token, alloc, memory) for token in tokens]
        if any(op is None for op in ops):
            continue
        line = mnemonic + (" " + ", ".join(ops) if ops else "")
        if line not in out:
            out.append(line)
    return out


def assemble(lines: dict, workdir: Path) -> set:
    """Names whose line GNU as accepts (iteratively drop the failing lines)."""
    names = sorted(lines)
    for _ in range(12):
        source = [".intel_syntax noprefix", ".text"]
        line_of = {}
        for name in names:
            source.append(f".globl {name}")
            source.append(f".type {name}, @function")
            source.append(f"{name}:")
            line_of[len(source) + 1] = name
            source.append("    " + lines[name])
            source.append("    ret")
        path = workdir / "probe.s"
        path.write_text("\n".join(source) + "\n", encoding="utf-8")
        result = subprocess.run(["as", "--64", "-o", str(workdir / "probe.o"), str(path)], capture_output=True,
                                text=True)
        bad = set()
        for match in re.finditer(r"probe\.s:(\d+): Error", result.stderr):
            name = line_of.get(int(match.group(1)))
            if name:
                bad.add(name)
        if not bad:
            return set(names)
        names = [name for name in names if name not in bad]
    return set(names)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("userops", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    usage = json.loads(args.userops.read_text(encoding="utf-8"))["usage"]
    constructors = {}
    for userop, rows in usage.items():
        for row in rows:
            if row["table"] != "instruction":
                continue
            entry = constructors.setdefault(row["display"], {"userops": set(), "flows": row["flows"]})
            entry["userops"].add(userop)
    candidates = {display: forms(display) for display in constructors}
    chosen, attempt = {}, 0
    remaining = {display for display, lines in candidates.items() if lines}
    while remaining and attempt < 2:
        lines = {}
        for index, display in enumerate(sorted(remaining)):
            if attempt < len(candidates[display]):
                lines[f"u{len(chosen) + index:05d}_{attempt}"] = (display, candidates[display][attempt])
        accepted = assemble({name: line for name, (_, line) in lines.items()}, args.out)
        for name in accepted:
            display, line = lines[name]
            chosen[display] = line
        remaining = {display for display in remaining if display not in chosen}
        attempt += 1
    functions = {}
    for index, display in enumerate(sorted(chosen)):
        functions[f"u{index:05d}"] = {"display": display, "line": chosen[display],
                                      "userops": sorted(constructors[display]["userops"]),
                                      "flows": constructors[display]["flows"]}
    source = [".intel_syntax noprefix", ".text"]
    for name, item in functions.items():
        source += [f".globl {name}", f".type {name}, @function", f"{name}:", "    " + item["line"], "    ret",
                   f".size {name}, .-{name}"]
    (args.out / "userops_test.s").write_text("\n".join(source) + "\n", encoding="utf-8")
    subprocess.run(["as", "--64", "-o", str(args.out / "userops_test.o"), str(args.out / "userops_test.s")],
                   check=True)
    subprocess.run(["ld", "-shared", "-o", str(args.out / "userops_test.so"), str(args.out / "userops_test.o")],
                   check=True)
    not_assembled = sorted(display for display in constructors if display not in chosen)
    (args.out / "map.json").write_text(json.dumps({"functions": functions, "not_assembled": not_assembled},
                                                  indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"constructors {len(constructors)}, assembled {len(functions)}, not assembled {len(not_assembled)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
