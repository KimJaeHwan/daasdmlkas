#!/usr/bin/env python3
"""Pipeline child processes of ``bundle_lint`` (design G0 r4 section 3, r5, r6 section 1).

Each pipeline path runs in its own process with a fresh admission, through the
engine's public entry point unchanged -- so the engine's own analysis-worker
choice applies exactly as in a normal run (r6: no TDO_V2_ANALYSIS_WORKER
override). The parent sets PYTHONHASHSEED=0 and enforces the time limit.

    python children.py <path> <generation> <naming_source> [json options]

paths: ``summary`` (strict ``iter_functions``), ``summary-retain``
(``iter_outcomes``), ``base_graph``. One JSON object on stdout.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time

PATHS = ("summary", "summary-retain", "base_graph")
_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parents[1]


def worker_state() -> dict:
    from tdo_v2 import resource_limits

    return {"worker_supported": resource_limits.worker_supported(),
            "stack_megabytes": resource_limits.stack_megabytes(),
            "env_TDO_V2_ANALYSIS_WORKER": os.environ.get("TDO_V2_ANALYSIS_WORKER"),
            "PYTHONHASHSEED": os.environ.get("PYTHONHASHSEED")}


def _error(error: BaseException) -> dict:
    return {"class": f"{type(error).__module__}.{type(error).__qualname__}", "message": str(error)}


def summary_options(options: dict) -> dict:
    """The summary entry's keyword options for a lint run (NullBoundaryProvider,
    the rest as given; unknown option names are rejected by the entry itself)."""
    from tdo_v2.boundary import NullBoundaryProvider

    kwargs = {name: value for name, value in options.items() if not name.startswith("lint_")}
    if kwargs.get("pcodeop_models") is not None:   # (paths in the JSON options -> loaded models)
        from tdo_v2.pcodeop_models import load_pcodeop_models

        kwargs["pcodeop_models"] = load_pcodeop_models(kwargs["pcodeop_models"])
    kwargs["boundary_provider"] = NullBoundaryProvider()
    return kwargs


def run_summary(generation: str, naming_source: str, *, retain: bool, options: dict) -> dict:
    from tdo_v2.summary_engine import analyze_frozen_bundle_with_summaries

    out = {"path": "summary-retain" if retain else "summary", "worker": worker_state()}
    try:
        run = analyze_frozen_bundle_with_summaries(
            generation, naming_exporter_source=naming_source,
            retain_admission_failures=retain, **summary_options(options))
    except Exception as error:   # (the stop: compared with the diagnosis prediction)
        out["completed"] = False
        out["exception"] = _error(error)
        return out
    supports = tuple(run.supports)
    keys = sorted({row.function for row in supports})
    failed = [list(row) for row in run.failed_functions]
    failed_keys = {row[0] for row in failed}
    out.update(
        completed=True,
        supports_count=len(supports),
        supported_functions=keys,
        failed_functions=failed,
        succeeded=sorted(set(keys) - failed_keys),
        assumptions=sorted(run.assumptions),
        control_exemptions=[list(map(str, row)) for row in run.control_exemptions],
        fault_report=[list(map(str, row)) for row in run.fault_report],
        control_sites=[list(map(str, row)) for row in run.control_sites],
        admission_failures=[{"function_id": item.function_id, "stage": item.stage, "reason": item.reason}
                            for item in run.admission_failures],
    )
    return out


def run_base_graph(generation: str, naming_source: str) -> dict:
    from tdo_v2.base_graph import build_frozen_bundle_graphs

    out = {"path": "base_graph", "worker": worker_state()}
    handle = {}
    try:
        snapshot = build_frozen_bundle_graphs(generation, naming_exporter_source=naming_source,
                                              on_publication=lambda h: handle.setdefault("h", h))
    except Exception as error:
        out["completed"] = False
        out["exception"] = _error(error)
        snapshot = getattr(handle.get("h"), "snapshot", None)
        if snapshot is None:
            return out
    else:
        out["completed"] = True
    out.update(
        stop=snapshot.stop,
        pending=list(snapshot.pending),
        failures={key: {"reason": getattr(row.reason, "value", str(row.reason)), "detail": row.detail}
                  for key, row in sorted(snapshot.failures.items())},
        graphs=sorted(snapshot.graphs),
        local_pass_finished=snapshot.local_pass_finished,
        entry_links_finished=snapshot.entry_links_finished,
        admission_failures=[{"function_id": item.function_id, "stage": item.stage, "reason": item.reason}
                            for item in snapshot.admission_failures],
    )
    return out


def child_main(argv) -> int:
    path, generation, naming_source = argv[:3]
    options = json.loads(argv[3]) if len(argv) > 3 else {}
    if path == "base_graph":
        result = run_base_graph(generation, naming_source)
    elif path in ("summary", "summary-retain"):
        result = run_summary(generation, naming_source, retain=path == "summary-retain", options=options)
    else:
        raise SystemExit(f"unknown path {path!r}")
    sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
    return 0


def child_env(base=None) -> dict:
    """The environment of every child: inherited (engine settings preserved),
    PYTHONHASHSEED=0, ``src`` on PYTHONPATH."""
    env = dict(os.environ if base is None else base)
    env["PYTHONHASHSEED"] = "0"
    parts = [str(_REPO / "src")] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
    env["PYTHONPATH"] = os.pathsep.join(parts)
    return env


def spawn(script: Path, args, *, timeout: float, env=None) -> dict:
    """Run ``script args`` in a child; parse its one JSON line. A timeout kills it
    (``run_state = timeout`` with elapsed seconds); a crash is ``error``."""
    start = time.monotonic()
    try:
        done = subprocess.run([sys.executable, str(script), *map(str, args)], capture_output=True,
                              text=True, timeout=timeout, env=child_env(env))
    except subprocess.TimeoutExpired:
        return {"run_state": "timeout", "elapsed": round(time.monotonic() - start, 3)}
    elapsed = round(time.monotonic() - start, 3)
    if done.returncode != 0:
        return {"run_state": "error", "elapsed": elapsed, "returncode": done.returncode,
                "stderr": done.stderr[-4000:]}
    try:
        result = json.loads(done.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"run_state": "error", "elapsed": elapsed, "stdout": done.stdout[-4000:],
                "stderr": done.stderr[-4000:]}
    result["run_state"] = "evaluated"
    result["elapsed"] = elapsed
    return result


def run_path(path: str, generation, naming_source, *, timeout: float, options=None, env=None) -> dict:
    if path not in PATHS:
        raise ValueError(f"unknown path {path!r}")
    args = [path, generation, naming_source]
    if options:
        args.append(json.dumps(options, sort_keys=True))
    return spawn(Path(__file__), args, timeout=timeout, env=env)


if __name__ == "__main__":
    raise SystemExit(child_main(sys.argv[1:]))
