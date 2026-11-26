"""Which SLEIGH constructors use which userop (CALLOTHER), read from Ghidra's own x86 SLEIGH sources.

Pure text processing, no Ghidra run: follows ``@include`` from ``x86-64.slaspec`` with the ``IA64`` define,
evaluates ``@ifdef`` / ``@ifndef`` / ``@else`` / ``@endif``, collects ``define pcodeop`` names, macros and
constructors, and records for each userop every constructor that uses it directly or through macros, with the
constructor's table, display text (mnemonic) and the flow statements of its semantic body.

The spec alone cannot say whether a userop transfers control at run time (``syscall()`` and ``cpuid()`` look
alike); that is decided per instruction form by the voters (decode_check), never here.

    python3 tools/decode_check/sleigh_userops.py <ghidra>/Ghidra/Processors/x86/data/languages --out userops.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

DEFINES = {"IA64"}
IDENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
HEAD = re.compile(r"(?m)^[ \t]*([A-Za-z_][A-Za-z0-9_.]*)?:(?!:)([^\n]*)")


def preprocess(path: Path, defines: set, seen: list) -> str:
    """The text of ``path`` with includes expanded and conditionals evaluated."""
    seen.append(path.name)
    out = []
    stack = []   # (active, taken)
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        active = all(item[0] for item in stack)
        if stripped.startswith("@ifdef") or stripped.startswith("@ifndef"):
            name = stripped.split()[1]
            value = (name in defines) == stripped.startswith("@ifdef")
            stack.append((value, value))
            continue
        if stripped.startswith("@else"):
            value, _ = stack.pop()
            stack.append((not value, True))
            continue
        if stripped.startswith("@endif"):
            stack.pop()
            continue
        if not active:
            continue
        if stripped.startswith("@define"):
            defines.add(stripped.split()[1])
            continue
        if stripped.startswith("@include"):
            name = stripped.split('"')[1]
            out.append(preprocess(path.parent / name, defines, seen))
            continue
        out.append(line)
    return "\n".join(out)


def _strip_comments(text: str) -> str:
    return re.sub(r"#[^\n]*", "", text)


def _body(text: str, start: int):
    """(body, end) of the brace block that opens at or after ``start`` (before any newline-terminated
    ``unimpl``); None when the constructor is ``unimpl``."""
    brace = text.find("{", start)
    unimpl = text.find("unimpl", start)
    if brace < 0 or (0 <= unimpl < brace):
        return None, (unimpl + 6 if unimpl >= 0 else len(text))
    depth = 0
    for index in range(brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:index], index + 1
    return text[brace + 1:], len(text)


def flow_statements(body: str) -> list:
    """The flow statements of a semantic body: goto / call / return, with their destination form."""
    out = []
    for match in re.finditer(r"\b(goto|call|return)\b\s*([^;]*);", body):
        kind, target = match.group(1), match.group(2).strip()
        if target.startswith("<"):
            form = "label"                       # intra-instruction (a p-code relative index)
        elif target == "inst_next":
            form = "inst_next"
        elif target.startswith("["):
            form = "indirect"
        else:
            form = "direct"
        out.append(f"{kind}:{form}")
    return sorted(set(out))


def parse(languages: Path) -> dict:
    seen = []
    text = _strip_comments(preprocess(languages / "x86-64.slaspec", set(DEFINES), seen))
    pcodeops = sorted(set(re.findall(r"define\s+pcodeop\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", text)))
    opset = set(pcodeops)
    macros = {}
    for match in re.finditer(r"\bmacro\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)", text):
        body, _ = _body(text, match.end())
        macros[match.group(1)] = body or ""

    def used(body, depth=0):
        found, flows = set(), set(flow_statements(body))
        for name in IDENT.findall(body):
            if name in opset:
                found.add(name)
            elif name in macros and depth < 8:
                inner, inner_flows = used(macros[name], depth + 1)
                found |= inner
                flows |= inner_flows
        return found, flows

    usage = {name: [] for name in pcodeops}
    constructors = 0
    position = 0
    while True:
        match = HEAD.search(text, position)
        if match is None:
            break
        line_start = text.rfind("\n", 0, match.start()) + 1
        head_line = text[line_start:text.find("\n", match.start())].strip()
        position = match.end()
        if head_line.startswith(("with", "define", "macro", "attach", "@")) or " is " not in text[match.start():
                                                                                                   match.start() + 4000]:
            continue
        is_at = text.find(" is", match.start())
        body, end = _body(text, is_at)
        position = max(position, end)
        constructors += 1
        if body is None:
            continue
        ops, flows = used(body)
        display = re.sub(r"\s+", " ", text[match.start():is_at]).strip()
        table = match.group(1) or "instruction"
        for name in ops:
            usage[name].append({"table": table, "display": display[:120], "flows": sorted(flows)})
    sla = languages / "x86-64.sla"
    return {"source": "Ghidra x86 SLEIGH sources", "files": sorted(set(seen)),
            "sources_sha256": hashlib.sha256("".join(
                f"{name}\0{hashlib.sha256((languages / name).read_bytes()).hexdigest()}\n"
                for name in sorted(set(seen))).encode()).hexdigest(),
            "sla_sha256": hashlib.sha256(sla.read_bytes()).hexdigest() if sla.exists() else None,
            "constructors": constructors, "pcodeops": len(pcodeops), "usage": usage}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("languages", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    result = parse(args.languages)
    args.out.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    used = sum(1 for rows in result["usage"].values() if rows)
    print(f"files {len(result['files'])}, constructors {result['constructors']}, pcodeops {result['pcodeops']}, "
          f"used {used}, sla {str(result['sla_sha256'])[:8]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
