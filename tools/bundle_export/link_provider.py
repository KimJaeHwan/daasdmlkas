"""The Ghidra provider of ``tdo_v2.linking`` (run_dfbench --link).

Works on the user's prepared Ghidra project only (the library imported with
the program -- loadLibraries -- and analyzed there; see README.md): it never
imports or analyzes anything. Per linked library and run:

* ``stack_evidence``: ghidra/GhidraV2StackSwitchScan.java over the library's
  analyzed program (scan_stack_switches.py), once per DLL build (cached);
* ``export``: one Bundle of the missing exports' call closure
  (export_bundle.py --entry ... --stop-at-internal-models LIB), into
  ``<cache>/bundles``.

Run on Linux/WSL, like the exporter.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import export_bundle as eb  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from tdo_v2.linking import INFRASTRUCTURE, ProviderError  # noqa: E402

_GENERATION = re.compile(r"\[export\] generation ([0-9a-f]{64})")


class GhidraLinkProvider:
    def __init__(self, ghidra_project: Path, cache_root: Path, *, folder: str = "/libs",
                 ghidra: Path = eb.DEFAULT_GHIDRA, model_dirs=(), max_mem: str = "8G", log=print):
        self.project = Path(ghidra_project)
        self.cache_root = Path(cache_root)
        self.folder = folder.rstrip("/")
        self.ghidra = Path(ghidra)
        self.model_dirs = list(model_dirs)
        self.max_mem = max_mem
        self.log = log

    def identity(self) -> dict:
        """Ghidra and exporter identity (part of the cache profile). The
        project's own analysis is not hashable: --link-refresh after
        re-analyzing a library with other options."""
        sources = {name: eb.sha256_file(eb.GHIDRA_DIR / name)
                   for name in sorted({*eb.SOURCES.values(), "GhidraV2StackSwitchScan.java"})}
        version = (self.ghidra / "Ghidra" / "application.properties")
        properties = version.read_text(encoding="utf-8") if version.is_file() else ""
        release = re.search(r"application\.version=(\S+)", properties)
        return {"ghidra": release.group(1) if release else str(self.ghidra.name), "sources": sources,
                "stack_scanner": sources["GhidraV2StackSwitchScan.java"]}

    def program(self, target) -> str:
        return f"{self.folder}/{target.library}"

    def stack_evidence(self, target, path: Path) -> Path:
        command = [sys.executable, str(Path(__file__).resolve().parent / "scan_stack_switches.py"), str(target.dll),
                   "--ghidra-project", str(self.project), "--project-program", self.program(target),
                   "-o", str(path), "--ghidra", str(self.ghidra), "--max-mem", self.max_mem]
        path.parent.mkdir(parents=True, exist_ok=True)
        self.log(f"[link] {target.library}: scanning the analyzed library for stack switches (once per build)")
        result = subprocess.run(command, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            self.log(f"[link]   {line}")
        if result.returncode != 0 or not path.is_file():
            raise ProviderError(f"stack scan failed: {(result.stderr or result.stdout).strip()[-400:]}")
        return path

    def export(self, target, entries, space_id: int) -> Path:
        output = self.cache_root / "bundles"
        command = [sys.executable, str(Path(__file__).resolve().parent / "export_bundle.py"), str(target.dll),
                   "--ghidra-project", str(self.project), "--project-program", self.program(target),
                   "--output-root", str(output), "--ghidra", str(self.ghidra), "--max-mem", self.max_mem]
        try:
            eb.internal_model_names(target.library, self.model_dirs)
            command += ["--stop-at-internal-models", target.library]
            for directory in self.model_dirs:
                command += ["--model-dir", str(directory)]
        except SystemExit:
            pass   # the library has no internal models: nothing to cut at
        for _, address in entries:
            command += ["--entry", str(space_id), str(address)]
        result = subprocess.run(command, capture_output=True, text=True, env=dict(os.environ))
        found = _GENERATION.search(result.stdout)
        if result.returncode != 0 or found is None:
            raise ProviderError(f"Ghidra export failed (rc {result.returncode}): "
                                f"{(result.stderr or result.stdout).strip()[-400:]}", INFRASTRUCTURE)
        for line in result.stdout.splitlines():
            if line.startswith("[export] published"):
                self.log(f"[link]   {line}")
        return output / found.group(1)
