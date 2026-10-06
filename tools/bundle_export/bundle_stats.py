#!/usr/bin/env python3
"""Admit a frozen format-2 Bundle and collect per-function normalization stats.

POSIX only (run inside WSL with the tdo venv). Unlike
tdo_v2.engine.analyze_frozen_bundle this does not stop at the first
unresolved function; it records every outcome, then optionally runs
build_observed_function_analyses on the normalized functions with a
NullBoundaryProvider (--analyses) to surface later-stage failures.

  ~/venvs/tdo/bin/python tools/bundle_export/bundle_stats.py /root/tdo_bundles/<gen> \
      [--analyses] [--json out.json]
"""

from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import sys
import time
import traceback

REPO = Path(__file__).resolve().parents[2]


def entry_names(generation: Path) -> dict[tuple[int, int], str]:
    """Best-effort entry->name map scraped from call-names sidecars."""
    names: dict[tuple[int, int], str] = {}

    def walk(node):
        if isinstance(node, dict):
            coordinate = node.get("coordinate")
            aliases = node.get("aliases")
            if isinstance(coordinate, dict) and isinstance(aliases, list):
                values = [row.get("value") for row in aliases if isinstance(row, dict)]
                values = [v for v in values if isinstance(v, str) and v != ".text"
                          and not v.startswith("Ordinal_")]
                if values:
                    key = (int(coordinate["space_id"]), int(coordinate["byte_offset"]))
                    names.setdefault(key, values[-1])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    for path in sorted(generation.glob("call-names-*.json")):
        try:
            walk(json.loads(path.read_text(encoding="utf-8")))
        except ValueError:
            pass
    return names


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("generation", type=Path)
    parser.add_argument("--naming-source", type=Path,
                        default=REPO / "ghidra" / "GhidraV2CallNaming.java")
    parser.add_argument("--analyses", action="store_true")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()

    from tdo_v2.boundary import NullBoundaryProvider
    from tdo_v2.configured_naming_contracts import (
        CALL_NAMING_GHIDRA_VERSION,
        NamingBindingExpectation,
    )
    from tdo_v2.integration.configured_bundle import admit_frozen_bundle
    from tdo_v2.integration.configured_interprocedural_slice import (
        build_observed_function_analyses,
    )
    from tdo_v2.integration.observed_function_session import (
        open_observed_function_session,
    )
    from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction
    from tdo_v2.scope_identity import ConstructedFunctionScope, ConstructedProgramScope

    report: dict[str, object] = {"generation": str(args.generation)}
    started = time.time()
    try:
        snapshot = admit_frozen_bundle(str(args.generation))
    except Exception as exc:  # noqa: BLE001
        report["admission"] = "FAILED"
        report["admission_error"] = "".join(traceback.format_exception(exc))
        print(report["admission_error"], file=sys.stderr)
        _dump(report, args.json)
        return 2
    report["admission"] = "OK"
    report["admission_seconds"] = round(time.time() - started, 2)
    print(f"[stats] admitted in {report['admission_seconds']}s: {type(snapshot).__name__}")

    names = entry_names(args.generation)
    binding = NamingBindingExpectation(
        sha256(args.naming_source.read_bytes()).digest(), CALL_NAMING_GHIDRA_VERSION)
    normalizer = FunctionNormalizer()
    outcomes: list[dict[str, object]] = []
    rows = []
    reasons: Counter[str] = Counter()
    try:
        with open_observed_function_session(snapshot, naming_binding=binding) as session:
            program = session.program_result
            report["program_scope"] = type(program).__name__
            if type(program) is not ConstructedProgramScope:
                report["program_reason"] = str(getattr(program, "reason", ""))
            iterator = session.iter_functions()
            index = 0
            while True:
                try:
                    evidence = next(iterator)
                except StopIteration:
                    break
                except Exception as exc:  # noqa: BLE001 - iterator is now dead
                    report["iterator_error_at"] = index
                    report["iterator_error"] = "".join(traceback.format_exception(exc))
                    print(report["iterator_error"], file=sys.stderr)
                    break
                function = evidence.unit.scopes.function
                entry = (function.entry.space_id, function.entry.byte_offset) \
                    if type(function) is ConstructedFunctionScope else None
                row: dict[str, object] = {
                    "index": index,
                    "entry": None if entry is None else f"{entry[0]:x}:{entry[1]:x}",
                    "name": names.get(entry) if entry else None,
                }
                try:
                    normalized = normalizer.normalize(evidence.unit)
                    if type(normalized) is NormalizedFunction:
                        row["result"] = "ok"
                        rows.append((evidence, normalized))
                    else:
                        row["result"] = "unresolved"
                        row["reason"] = normalized.reason.value
                        reasons[normalized.reason.value] += 1
                except Exception as exc:  # noqa: BLE001
                    row["result"] = "exception"
                    row["error"] = "".join(traceback.format_exception(exc))
                    reasons["exception:" + type(exc).__name__] += 1
                outcomes.append(row)
                index += 1
            report["functions"] = len(outcomes)
            report["normalized_ok"] = len(rows)
            report["unresolved_reasons"] = dict(reasons)
            report["normalize_seconds"] = round(time.time() - started, 2)
            if args.analyses and rows:
                t0 = time.time()
                try:
                    analyses = build_observed_function_analyses(
                        tuple(rows), NullBoundaryProvider(), None)
                    report["analyses"] = f"OK ({len(analyses)} functions)"
                except Exception as exc:  # noqa: BLE001
                    report["analyses"] = "FAILED"
                    report["analyses_error"] = "".join(traceback.format_exception(exc))
                    print(report["analyses_error"], file=sys.stderr)
                report["analyses_seconds"] = round(time.time() - t0, 2)
    except Exception as exc:  # noqa: BLE001
        report["session_error"] = "".join(traceback.format_exception(exc))
        print(report["session_error"], file=sys.stderr)
    report["outcomes"] = outcomes
    summary = {k: v for k, v in report.items() if k != "outcomes"}
    print(json.dumps({k: (v if not isinstance(v, str) or len(v) < 400 else v[-400:])
                      for k, v in summary.items()}, indent=1))
    for row in outcomes:
        if row["result"] != "ok":
            print(f"  [{row['index']}] {row['entry']} {row['name']}: "
                  f"{row.get('reason') or row.get('error', '')[-300:]}")
    _dump(report, args.json)
    return 0


def _dump(report, path):
    if path is not None:
        path.write_text(json.dumps(report, indent=1), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
