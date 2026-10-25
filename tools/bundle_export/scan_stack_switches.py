#!/usr/bin/env python3
"""Whole-program stack-switch evidence from a prepared Ghidra project.

    python3 tools/bundle_export/scan_stack_switches.py <the DLL/EXE file> \
        --ghidra-project /root/ghidra_proj/link.gpr --project-program /libs/UNREALEDITOR-CORE.DLL \
        -o core.stack.json

Runs ghidra/GhidraV2StackSwitchScan.java on the program the user imported AND
analyzed in the project (-process -noanalysis -readOnly; nothing is saved
back). The script refuses a program that is not analyzed or whose recorded
executable SHA-256 differs from the file given. The evidence file is then
passed to tools/bundle_export/run_dfbench.py / tools/derive_models with
--stack-evidence (tdo_v2.stack_evidence). Run on Linux/WSL, like the exporter.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import export_bundle as eb  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("binary", type=Path)
    parser.add_argument("--ghidra-project", type=Path, required=True)
    parser.add_argument("--project-program", required=True)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path, default=eb.DEFAULT_GHIDRA)
    parser.add_argument("--max-mem", default="8G")
    parser.add_argument("--mode", choices=("conservative", "legacy-v3"), default="conservative",
                        help="v4 unknown post-call registers (default), or explicit ABI-dependent v3")
    args = parser.parse_args()

    project = args.ghidra_project.resolve()
    folder, _, program = args.project_program.rpartition("/")
    output = args.output.resolve()
    log = output.with_suffix(".ghidra.log")
    command = ["bash", str(args.ghidra / "support" / "analyzeHeadless"), str(project.parent), project.stem + folder,
               "-process", program, "-noanalysis", "-readOnly", "-scriptPath", str(eb.GHIDRA_DIR),
               "-log", str(log), "-postScript", "GhidraV2StackSwitchScan.java",
               "--output", str(output), "--expected-sha256", eb.sha256_file(args.binary.resolve()),
               "--mode", args.mode]
    if output.exists():
        output.unlink()
    started = time.time()
    result = subprocess.run(command, env={**os.environ, "MAXMEM": args.max_mem}, capture_output=True, text=True)
    for line in (result.stdout + result.stderr).splitlines():
        if "stack-switch scan:" in line or "SCRIPT ERROR" in line:
            print(line.split("> ", 1)[-1])
    if not output.is_file():
        print(f"[scan] FAILED ({time.time() - started:.0f}s); see {log}", file=sys.stderr)
        return 1
    print(f"[scan] wrote {output} ({time.time() - started:.0f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
