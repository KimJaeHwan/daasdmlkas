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


def _diagnosis_resource(diagnosis: dict) -> bool:
    """A resource failure in the diagnosis leaves the admitted set unknown (Astra impl r5 P2)."""
    if diagnosis.get("admission", {}).get("resource") or (diagnosis.get("fatal") or {}).get("resource"):
        return True
    return any((claim.get(name) or {}).get("resource") for claim in diagnosis.get("claims", [])
               for name in ("seeds_error", "naming_error"))


def _admitted(claims) -> tuple[int, set]:
    members = [claim for claim in claims if claim.get("scope") == "constructed" and claim.get("naming") == "ok"]
    return len(members), {claim["entry"] for claim in members}


def _completion(path: str, child: dict, claims) -> tuple[str, dict]:
    """(verdict, detail) of a completed path: ``applied`` only when nothing was
    lost -- no failed function, no admission refusal, every admitted member
    analysed once (duplicate entries collapse in the summary). Fable / Astra
    impl r1 P1."""
    members, keys = _admitted(claims)
    why = []
    if path == "base_graph":
        detail = {name: child[name] for name in ("stop", "pending", "failures", "entry_links_finished",
                                                 "local_pass_finished", "graphs", "admission_failures")}
        if child["stop"] != "finished" or child["pending"] or not child["entry_links_finished"]:
            why.append("not finished")
        if child["failures"]:
            why.append("failed functions")
        if set(child["graphs"]) != keys:
            why.append("graphs differ from the admitted function keys")
    else:
        detail = {"admitted_members": members, "admitted_keys": len(keys), "succeeded": len(child["succeeded"]),
                  "failed": child["failed_functions"], "supports_count": child["supports_count"]}
        if child["failed_functions"]:
            why.append("failed functions")
        if set(child["succeeded"]) != keys - {row[0] for row in child["failed_functions"]}:
            why.append("analysed keys differ from the admitted function keys")
    detail["admission_failures"] = child["admission_failures"]
    if child["admission_failures"]:
        why.append("admission refusals")
    if members != len(keys):
        why.append("duplicate entries")
    if why:
        detail["why"] = why
    return ("withheld" if why else "applied"), detail


def pipeline_rows(diagnosis: dict, predictions: dict, results: dict) -> list[Row]:
    rows = []
    claims = diagnosis.get("claims", [])
    for path in children.PATHS:
        child = results.get(path)
        if child is None:
            rows.append(Row("pipeline", "stop", path, "not_run"))
            rows.append(Row("pipeline", "completion", path, "not_run"))
            continue
        prediction = predictions.get(path)
        state, verdict, detail = diagnose.check_stop(prediction, child)
        if (child.get("exception") or {}).get("resource"):
            state, verdict = "error", None   # (a resource failure is no stop verdict)
        rows.append(Row("pipeline", "stop", path, state, verdict, "lint", detail))
        if child.get("run_state") != "evaluated":
            rows.append(Row("pipeline", "completion", path, child.get("run_state", "error"), None, "lint",
                            {"child": child}))
            continue
        if not child.get("completed"):
            # 0 analysed only when the stop is known to come before analysis; a
            # later exception keeps what the child recovered (base_graph snapshot).
            # An engine refusal is a stop the diagnosis predicted; anything else
            # (a resource or execution error) is run_state error (Astra impl r2 P2)
            known = verdict == "applied" and diagnose.pre_analysis(prediction)
            stopped = {"exception": child.get("exception"), "analysed": 0 if known else None}
            for name in ("stop", "pending", "failures", "graphs", "entry_links_finished", "admission_failures"):
                if name in child:
                    stopped[name] = child[name]
            resource = bool((child.get("exception") or {}).get("resource"))   # (isinstance in the child)
            if verdict == "applied" and not resource:
                rows.append(Row("pipeline", "completion", path, "evaluated", "refused", "engine", stopped))
            else:   # (a resource failure or an unpredicted stop is no verdict on the Bundle)
                rows.append(Row("pipeline", "completion", path, "error", None, "lint", stopped))
            continue
        if diagnosis.get("failed") or _diagnosis_resource(diagnosis):
            # admitted keys are unknown without the diagnosis: no completion verdict (Astra r3 P2, Fable r3 P3-4)
            kept = {name: child[name] for name in ("succeeded", "failed_functions", "graphs", "failures")
                    if name in child}
            rows.append(Row("pipeline", "completion", path, "error", None, "lint",
                            {"why": "diagnosis failed: admitted function keys unknown", **kept}))
            continue
        if path != "base_graph" and child["supports_count"] != len(child["supported_functions"]):
            rows.append(Row("pipeline", "completion", path, "error", None, "lint",
                            {"why": "supports are not one row per function"}))
            continue
        verdict, detail = _completion(path, child, claims)
        rows.append(Row("pipeline", "completion", path, "evaluated", verdict, "lint", detail))
        if path != "base_graph":
            # the run's final columns, read from EngineRun (r2 s2): --expect compares them
            rows.append(Row("pipeline", "run_columns", path, "evaluated", "applied", "engine",
                            {name: child[name] for name in ("assumptions", "control_exemptions", "fault_report",
                                                            "control_sites")}))
    return rows


def branchind_final_rows(rows, results: dict) -> list[Row]:
    """Per BRANCHIND site of the member the summary analyses (Astra impl r4 P1):
    a member replaced by a later one of the same entry -> not_reached; the
    adopted member's site: ``control_sites`` kind ``unknown-transfer`` ->
    unknown / withheld, ``import-tail-reentry`` -> import-tail-reentry /
    withheld, else exempted (``control_exemptions``) -> applied, else no
    candidate -> known / not_applicable, else a candidate the run published
    nowhere -> unobserved. The exemption and fault-report rows of the key are
    kept in the detail."""
    name, summary = feature_layer.summary_run(results)
    exemptions, kinds, faults, failed = {}, {}, {}, set()
    if name is not None:
        failed = {row[0] for row in summary["failed_functions"]}
        for site, assumption in summary["control_exemptions"]:
            exemptions.setdefault(site, []).append(assumption)
        for row in summary["control_sites"]:
            kinds.setdefault(row[0], set()).add(row[1])
        for row in summary["fault_report"]:
            faults.setdefault(row[0], []).append(list(row[1:]))
    out = []
    for row in rows:
        if row.check != "branchind":
            continue
        site = row.key.split("/", 1)[1]
        candidate = bool(row.detail.get("unknown_transfer"))
        superseded = bool(row.detail.get("superseded_by_duplicate_entry"))
        state, _ = feature_layer.site_state(results, superseded)
        if state != "evaluated":
            out.append(Row("pipeline", "branchind_final", row.key, state, None, "lint",
                           {"why": "a later member of the same entry is the one the summary analyses"}
                           if superseded and state == "not_reached" else {}))
            continue
        function = ":".join(site.split(":")[1:3])
        detail = {"run": name, "candidate": candidate, "exemptions": sorted(exemptions.get(site, [])),
                  "control_site_kinds": sorted(kinds.get(site, ())), "fault_report": faults.get(site, []),
                  "function_failed": function in failed}
        if "unknown-transfer" in kinds.get(site, ()):
            final, verdict, state = "unknown", "withheld", "evaluated"
        elif "import-tail-reentry" in kinds.get(site, ()):
            final, verdict, state = "import-tail-reentry", "withheld", "evaluated"
        elif site in exemptions:
            final, verdict, state = "exempted", "applied", "evaluated"
        elif not candidate:
            final, verdict, state = "known", "not_applicable", "evaluated"
        else:
            final, verdict, state = "unpublished", None, "unobserved"
        out.append(Row("pipeline", "branchind_final", row.key, state, verdict,
                       "engine" if verdict else "lint", {**detail, "final": final}))
    return out


def run(generation: Path, naming_source: Path, *, timeout: float, summary: bool, options: dict) -> tuple:
    diag = children.spawn(_HERE / "diagnose.py",
                          [generation, naming_source] + ([json.dumps(options, sort_keys=True)] if options else []),
                          timeout=timeout)
    diagnosis_failed = diag.get("run_state") != "evaluated"
    if diagnosis_failed:   # (the pipelines still run; the report says the diagnosis failed)
        diag = {**diag, "rows": [], "diagnosis": {"claims": [], "failed": True}, "predictions": {}}
    results = {}
    for path in children.PATHS:
        if path != "base_graph" and not summary:
            continue
        results[path] = children.run_path(path, generation, naming_source, timeout=timeout,
                                          options=options if path != "base_graph" else None)
    rows = [Row.from_json(row) for row in diag["rows"]]
    if diagnosis_failed:
        rows.append(Row("transport", "diagnosis", "bundle", diag.get("run_state", "error"), None, "lint",
                        {key: diag.get(key) for key in ("returncode", "stderr", "elapsed")}))
    rows.extend(pipeline_rows(diag["diagnosis"], diag["predictions"], results))
    rows.extend(feature_layer.trap_application_rows(rows, {**results, "_predictions": diag["predictions"]},
                                                    options))
    rows.extend(branchind_final_rows(rows, results))
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
    if not args.naming_source.is_file() or not args.generation.is_dir():
        print("bundle_lint: the generation directory and the naming source must exist", file=sys.stderr)
        return 2
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
