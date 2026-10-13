# Bundle export helpers

Turn a binary into a format-2 Ghidra Bundle with `ghidra/GhidraV2BundleExport.java`,
then admit/normalize/run it with `tdo_v2`. None of these scripts touch `src/` or `ghidra/`.

| Script | Where | Purpose |
|---|---|---|
| `export_bundle.py` | WSL/Linux (`python3`) | Runs `analyzeHeadless` + exporter, checks the receipt, `--mirror-to` copies the result |
| `bundle_stats.py` | WSL (`~/venvs/tdo/bin/python`) | `admit_frozen_bundle`, then session + `FunctionNormalizer` over every function; collects stats instead of stopping at the first failure; `--analyses` also runs `build_observed_function_analyses` with `NullBoundaryProvider` |
| `scope_diagnose.py` | WSL | Prints `ScopeConstructionReason` for each function. Use it when the session fails with `observed function scope could not be constructed` |
| `run_dfbench.py` | WSL | The summary engine (`tdo_v2.summary_engine`, default; `--legacy-engine` for the older `analyze_frozen_bundle`) with a DataFlowBench `SymbolBoundaryProvider` table, compared against `cases_manifest.json` |

## Requirements

* Ghidra 12.0.4 at `../ghidra_12.0.4_PUBLIC`. The exporters require exactly this version.
* JDK 21 in WSL: `apt-get install -y openjdk-21-jdk-headless`. Ghidra itself runs from `/mnt/d/...`.
* **Run the export on Linux, not Windows.** On Windows the exporter fails at
  `GhidraV2BundleExport.forceDirectory` (it fsyncs a directory via `FileChannel.open`), with this error:
  `java.nio.file.AccessDeniedException: ...\<gen>.staging`. Admission is POSIX-only too. It requires
  the owner uid, nlink 1 and no group/other write permission, so `/mnt/d` (drvfs, 0777) is not admissible.
  Write bundles to the Linux filesystem, e.g. `/root/tdo_bundles/...`.

## Export

```bash
cd /mnt/d/01_gitproject/14_TDO_v2/daasdmlkas
TB=/mnt/d/01_gitproject/09_tdo_testbed
python3 tools/bundle_export/export_bundle.py $TB/build/win-debug/dfbench_win_core.exe \
    --functions-from-manifest $TB/manifests/cases_manifest.json \
    --output-root /root/tdo_bundles/win-debug --mirror-to output/bundles/win-debug
```

* Selection works in one of three ways: `--functions-from-manifest` (every `case_*` function of the
  binary, or, for `libdfbench_importlib*.dll`, its 4 exported functions), `--function-name NAME`
  (repeatable), or `--entry SPACE OFFSET`. With names or entries, the exporter adds the transitive call/reference
  closure itself (sources, sinks and helpers). Thunks and externals are excluded. The limit is 4096.
* `--exclude-function NAME` drops names from the selection (see "Known issues").
* The generation id is a random 64-hex value. The nonce is random. The script computes the original's
  size and SHA-256 and the SHA-256 of all 4 exporter sources, and passes them as script arguments.
  Ghidra headless passes `--xxx` script arguments through, because only its own option names end the
  script-argument list.
* Logs go to `<output-root>.logs/<gen>.{command.json,ghidra.log,script.log,receipt}` and `index.jsonl`.
  `run_dfbench.py` reads root function names from `command.json`, because the `--function-name` order
  matches `function-%06d`.
* One binary takes about 60–100 s (Ghidra import + auto-analysis + export).

## Exporting library (DLL) code from a prepared Ghidra project

Linking a program with the real code of the DLLs it imports (design section 24) reads the libraries
from a Ghidra project **the user prepares and analyzes**. The tools never import or analyze a library
on their own: which DLLs to load, with which analysis options (PDB, analyzers), and when to spend the
time (UnrealEditor-Core: ~9 min; Engine is much larger) is the user's decision.

1. Import the program with its libraries loaded and linked, into a project kept on disk. In the GUI:
   File > Import, Options: *Load Libraries From Disk*, a library search path holding the DLLs to link,
   destination folder `/libs`, *Link Existing Project Libraries*. Headless (Ghidra 12.0.4):
   ```bash
   analyzeHeadless /root/ghidra_proj link -import <plugin.dll>        -loader-loadLibraries true -loader-libraryLoadDepth 1 -librarySearchPaths <folder with the DLLs>        -loader-libraryDestinationFolder /libs -loader-linkExistingProjectLibraries true
   ```
   Only DLLs found on the search path are loaded; put only the ones to link there. Ghidra analyzes the
   imported program, **not** the loaded libraries.
2. Analyze each library to link, once (GUI: open it, Analysis > Auto Analyze; headless:
   `analyzeHeadless /root/ghidra_proj link/libs -process UNREALEDITOR-CORE.DLL`). The project keeps the
   result; exports never re-analyze it.
3. Check the links: the program's *External Programs* (Symbol Tree > Imports, or Window > External
   Programs) name `/libs/<LIBRARY>` for each linked library.
4. Export library functions from the project:
   ```bash
   python3 tools/bundle_export/export_bundle.py "<path to>/UnrealEditor-Core.dll"        --ghidra-project /root/ghidra_proj/link.gpr --project-program /libs/UNREALEDITOR-CORE.DLL        --stop-at-internal-models UNREALEDITOR-CORE.DLL --entry 433 6442678912 --output-root <dir>
   ```
   **Save and close the project in the GUI first** (an open project is locked; the export then fails).
   The program is processed as it is in the project (`-process -noanalysis -readOnly`: nothing is
   saved back). The exporter **refuses** a program that is not analyzed, one whose recorded executable
   SHA-256 differs from the DLL file given, and one whose exception landing pads would need disassembly
   and analysis first (export such a library by import instead). `--stop-at-internal-models LIB` (or
   `--stop-at-name SYMBOL`, an error when no function has it) exports the library's functions with an
   internal model (models/external, `--model-dir`) without following their calls: the derivation
   (`tools/derive_models`) cuts there anyway. Such a Bundle holds only the closure up to those
   functions: it is no evidence about the rest of the library (the derivation never takes
   globals-disjoint-from-stack). Measured on UnrealEditor-Core (FString(), ~FString,
   AppendChar): 49 files / 43 MB in 98 s, against 10,495 files / 510 MB in 632 s (new project, import +
   analysis each time) -- and the same templates.

## Admit / normalize / run

```bash
PY=~/venvs/tdo/bin/python
G=/root/tdo_bundles/win-debug/<generation>
$PY tools/bundle_export/bundle_stats.py $G --analyses --json /tmp/stats.json
$PY tools/bundle_export/scope_diagnose.py $G
$PY tools/bundle_export/run_dfbench.py $G --expected $TB/manifests/cases_manifest.json --binary dfbench_win_core
```

`expected/dfbench_win_core.expected.json` is stale. It has 50 cases, while the manifest has 75.
Compare against the manifest instead.

## Known issues (as of 2026-10-06)

1. *(resolved; kept for history)* **Calls through the IAT (`call [__imp_X]`) → `invalid_function_observation`.** Ghidra records an
   EXTERNAL-space (space id 42) flow target on the instruction. `_scope_observation._flow_targets` then
   rejects that observation because it is not a memory coordinate. `ObservedFunctionSession` raises
   `ValueError: observed function scope could not be constructed` and its iterator stops, so the whole
   Bundle cannot be analyzed. In dfbench_win_core this affects DFB074, DFB075, DFB130 and DFB131 (DLL
   imports), plus `dfb_longjmp_writer` (`longjmp` import, in the closure of DFB110). The workaround
   is to drop those five cases with `--exclude-function`.
2. **Recursion cases (DFB060–065), legacy engine only** → `RuntimeError: interprocedural write-event fixed
   point did not stabilize` in `analyze_frozen_bundle` (`--legacy-engine`). The default summary engine
   handles recursion (verified SCC fixpoint) and analyzes the full 09 debug Bundle with all 75 cases.
3. **DFB111 (C++ exceptions, mingw x64 SEH: `__gxx_personality_seh0`, `.pdata/.xdata`) produces no sink root.**
   The Bundle contains only the case function, `dfb_cpp_throw_writer` and one helper. The catch block
   that calls `dfb_sink_int` is not in the observed body. The exporter only recovers landing pads from
   `.eh_frame` LSDA and ARM EHABI, and the LSDA path for SEH (via `.xdata`) does not appear to be
   covered. This has not been verified.
