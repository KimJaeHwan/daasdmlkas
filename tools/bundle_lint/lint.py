#!/usr/bin/env python3
"""``bundle_lint``: what of a Bundle the TDO engine accepts, uses and loses
(design G0, .census6/design_g0_bundle_lint_r0..r6.md). POSIX / WSL.

    PYTHONPATH=src python3 tools/bundle_lint/lint.py <generation> [--out report.json]
        [--expect expect.json] [--timeout 600] [--no-summary] [--options options.json]

Processes: the diagnosis pass (layers 1-3 and the stop predictions) and each
pipeline path (summary strict, summary retain, base_graph) run in their own
child process with a fresh admission and PYTHONHASHSEED=0; the engine's own
analysis-worker setting is kept. Exit 0 = report written (and ``--expect``
matched), 1 = ``--expect`` differences, 2 = usage / internal error.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

import children  # noqa: E402
import diagnose  # noqa: E402
import feature_layer  # noqa: E402
from report import Row, compare, dumps  # noqa: E402

TOOL_REVISION = 1


def pipeline_rows(diagnosis: dict, predictions: dict, results: dict) -> list[Row]:
    rows = []
    claims = diagnosis.get("claims", [])
    for path in children.PATHS:
        child = results.get(path)
        if child is None:
            rows.append(Row("pipeline", "stop", path, "not_run"))
            rows.append(Row("pipeline", "completion", path, "not_run"))
            continue
        state, verdict, detail = diagnose.check_stop(predictions.get(path), child)
        rows.append(Row("pipeline", "stop", path, state, verdict, "lint", detail))
        if child.get("run_state") != "evaluated":
            rows.append(Row("pipeline", "completion", path, child.get("run_state", "error"), None, "lint",
                            {"child": child}))
            continue
        if not child.get("completed"):
            rows.append(Row("pipeline", "completion", path, "evaluated", "refused", "engine",
                            {"exception": child.get("exception"), "analysed": 0}))
            continue
        if path == "base_graph":
            detail = {name: child[name] for name in ("stop", "pending", "failures", "entry_links_finished",
                                                     "local_pass_finished", "graphs", "admission_failures")}
            complete = child["stop"] == "finished" and not child["pending"] and child["entry_links_finished"]
        else:
            admitted = sum(1 for claim in claims if claim.get("scope") == "constructed"
                           and claim.get("naming") == "ok")
            detail = {"admitted": admitted, "succeeded": len(child["succeeded"]),
                      "failed": child["failed_functions"], "admission_failures": child["admission_failures"],
                      "supports_count": child["supports_count"]}
            if child["supports_count"] != len(child["supported_functions"]):
                rows.append(Row("pipeline", "completion", path, "error", None, "lint",
                                {**detail, "why": "supports are not one row per function"}))
                continue
            complete = not child["failed_functions"]
        rows.append(Row("pipeline", "completion", path, "evaluated",
                        "applied" if complete else "withheld", "engine", detail))
    return rows


def run(generation: Path, naming_source: Path, *, timeout: float, summary: bool, options: dict) -> tuple:
    diag = children.spawn(_HERE / "diagnose.py",
                          [generation, naming_source] + ([json.dumps(options, sort_keys=True)] if options else []),
                          timeout=timeout)
    if diag.get("run_state") != "evaluated":
        raise RuntimeError(f"diagnosis pass failed: {json.dumps(diag)[:4000]}")
    results = {}
    for path in children.PATHS:
        if path != "base_graph" and not summary:
            continue
        results[path] = children.run_path(path, generation, naming_source, timeout=timeout,
                                          options=options if path != "base_graph" else None)
    rows = [Row.from_json(row) for row in diag["rows"]]
    rows.extend(pipeline_rows(diag["diagnosis"], diag["predictions"], results))
    rows.extend(feature_layer.trap_application_rows(rows, results, options))
    header = {
        "tool": "bundle_lint", "revision": TOOL_REVISION, "generation": generation.name,
        "naming_source_sha256": sha256(naming_source.read_bytes()).hexdigest(),
        "options": options, "summary": summary, "timeout": timeout,
        "workers": {path: result.get("worker") for path, result in results.items()},
        "elapsed": {"diagnosis": diag.get("elapsed"),
                    **{path: result.get("elapsed") for path, result in results.items()}},
        "PYTHONHASHSEED": "0",
    }
    return header, rows, diag


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("generation", type=Path)
    parser.add_argument("--naming-source", type=Path, default=_HERE.parents[1] / "ghidra" / "GhidraV2CallNaming.java")
    parser.add_argument("--out", type=Path, default=Path("bundle_lint_report.json"))
    parser.add_argument("--expect", type=Path)
    parser.add_argument("--timeout", type=float, default=600.0)
    parser.add_argument("--no-summary", action="store_true")
    parser.add_argument("--options", type=Path, help="JSON object of summary-entry keyword options")
    parser.add_argument("--normalize", action="store_true",
                        help="standalone FunctionNormalizer run per function (labelled standalone)")
    parser.add_argument("--pcodeop-models", type=Path, action="append",
                        help="p-code op model files for a summary run with them (hash in the header)")
    args = parser.parse_args(argv)
    options = json.loads(args.options.read_text()) if args.options else {}
    if args.normalize:
        options["lint_normalize"] = True
    if args.pcodeop_models:
        options["pcodeop_models"] = [str(path) for path in args.pcodeop_models]
        options["lint_pcodeop_models_sha256"] = {str(path): sha256(path.read_bytes()).hexdigest()
                                                 for path in args.pcodeop_models}
    header, rows, _ = run(args.generation, args.naming_source, timeout=args.timeout,
                          summary=not args.no_summary, options=options)
    text = dumps(header, rows)
    args.out.write_text(text, encoding="utf-8")
    if args.expect:
        diffs = compare(json.loads(args.expect.read_text()), json.loads(text))
        for line in diffs:
            print(line)
        return 1 if diffs else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
