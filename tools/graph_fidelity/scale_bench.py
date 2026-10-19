"""Scale benchmark (docs 25.30 K2): runs scale_point.py for each point
(configuration x size x seed x repetition) in its own process under
tools/run_supervised.py and merges, OUTSIDE the killable workload, the
supervisor's evidence with the point's last telemetry and its result file.

    scale_bench.py OUT.jsonl [--sizes 10000,30000,100000,250000]
                   [--configs target,calls,...] [--seeds 3] [--reps 2]
                   [--deadline 1800] [--memory 12G] [--records] [--witnesses]

Each output line: the point spec, process status (supervisor), analysis
completeness (failed functions), probe verdicts, validity ("valid" only if
completed, probes all passed, outputs present and no unexpected failed
functions), stage timings, the phase table, counts, the active stage / phase
at a kill (from telemetry), the budget environment used, and the machine."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# single-factor configurations around "target" (scale_fixtures.DEFAULTS)
CONFIGS = {
    "target": {},
    "calls": {"calls": 1 / 6},
    "branches": {"branches": 1 / 3},
    "loops": {"loops": 1 / 60},
    "chain": {"chain": 0.6},
    "growing_fields": {"growing_fields": True},
    "widths": {"mixed_widths": True, "memory": 0.5},
    "escapes": {"escapes": 0.01},
    "unknown_stores": {"unknown_stores": 0.01},
    "two_pointer": {"two_pointer": 0.4},
    "fanin": {"fanin": 0.002},
    "rep": {"rep": 0.005},
    "traps": {"traps": 0.005},
    "resolvable": {"resolvable_indirect": 0.2},
    "recursion": {"recursion": True},
    "sinks": {"sinks": 0.2},
    "callee_size": {"callee_size": 64},
}


def machine() -> dict:
    info = {"python": sys.version.split()[0], "platform": platform.platform(), "cpus": os.cpu_count()}
    try:
        info["memory_kb"] = int(next(line for line in open("/proc/meminfo") if line.startswith("MemTotal")).split()[1])
        info["cpu"] = next(line for line in open("/proc/cpuinfo") if line.startswith("model name")).split(":", 1)[1].strip()
    except (OSError, StopIteration):
        pass
    return info


def last_telemetry(path: Path) -> dict:
    """The last complete line; the stage entered and not exited."""
    open_stages, open_phases, last, progress = [], [], None, None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    for line in lines:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue   # (a truncated last line)
        last = row
        event = row.get("event")
        if event == "enter":
            open_stages.append(row["stage"])
        elif event == "exit" and open_stages and open_stages[-1] == row["stage"]:
            open_stages.pop()
        elif event == "phase_enter":
            open_phases.append(row["phase"])
        elif event == "phase_exit" and open_phases and open_phases[-1] == row["phase"]:
            open_phases.pop()
        elif event == "progress" and row.get("phase"):
            progress = row
    # the interrupted engine phase: the top-level phase entered and not exited
    # (from the transitions); the last 5-s observation kept beside it
    return {"last": last, "open_stages": open_stages, "open_phases": open_phases,
            "last_observation": progress}


def run_point(spec: dict, *, deadline: float, memory: str, workdir: Path, budgets: dict) -> dict:
    tag = f"{spec['config']}-{spec['ops']}-s{spec['seed']}-r{spec['rep']}"
    telemetry, result = workdir / f"{tag}.telemetry", workdir / f"{tag}.result.json"
    stdout, stderr = workdir / f"{tag}.out", workdir / f"{tag}.err"
    env = {key: value for key, value in os.environ.items() if not key.startswith("TDO_V2_")}
    env.update({"TDO_V2_PHASES": "1", **budgets})
    command = [sys.executable, str(REPO / "tools" / "run_supervised.py"), "--memory", memory,
               "--deadline", str(deadline), "--grace", "30", "--status", str(workdir / f"{tag}.status.json"), "--",
               sys.executable, str(REPO / "tools" / "graph_fidelity" / "scale_point.py"),
               json.dumps(spec), str(telemetry), str(result)]
    started = time.time()
    with open(stdout, "w") as out, open(stderr, "w") as err:
        subprocess.run(command, env=env, stdout=out, stderr=err)
    wall = time.time() - started
    try:
        status = json.loads((workdir / f"{tag}.status.json").read_text())
    except (OSError, json.JSONDecodeError):
        status = {"status": "infrastructure", "error": "no supervisor status"}
    try:
        point = json.loads(result.read_text())
    except (OSError, json.JSONDecodeError):
        point = None
    record = {"spec": spec, "process": status.get("status"), "supervisor": {
        key: status.get(key) for key in ("final", "unit_result", "events", "scope_empty", "error")},
        "wall_seconds": round(wall, 2), "budgets": budgets, "telemetry": last_telemetry(telemetry)}
    if point is None:
        record["valid"] = False
        record["why"] = "no result (killed / failed before the end)"
        return record
    record.update(point)
    unexpected = [row for row in point["failed_functions"]]
    record["valid"] = (status.get("status") == "completed" and point["probes_ok"] and point.get("phases") is not None
                       and not unexpected)
    if not record["valid"]:
        record["why"] = "process " + str(status.get("status")) if status.get("status") != "completed" else (
            "probes failed" if not point["probes_ok"] else "failed functions" if unexpected else "no phase table")
    return record


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("out", type=Path)
    parser.add_argument("--sizes", default="10000,30000,100000,250000")
    parser.add_argument("--configs", default=",".join(CONFIGS))
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--reps", type=int, default=2)
    parser.add_argument("--deadline", type=float, default=1800.0)
    parser.add_argument("--memory", default="12G")
    parser.add_argument("--records", action="store_true")
    parser.add_argument("--witnesses", action="store_true")
    parser.add_argument("--target-closure", action="store_true", help="also the 250k point with 980 targets")
    args = parser.parse_args(argv)
    sizes = [int(item) for item in args.sizes.split(",")]
    workdir = Path(tempfile.mkdtemp(prefix="tdo_scale_"))
    budgets: dict = {}   # all off (recorded); a profile under test sets TDO_V2_* here
    points = []
    for config in args.configs.split(","):
        for ops in sizes:
            seeds = args.seeds if ops <= 100_000 else max(1, args.seeds - 1)
            reps = args.reps if ops <= 100_000 else 1
            for seed in range(seeds):
                for rep in range(reps):
                    points.append({"config": config, "ops": ops, "seed": seed, "rep": rep, "series": "scaled",
                                   "knobs": CONFIGS[config], "records": args.records, "witnesses": args.witnesses})
    if args.target_closure:
        for seed in range(max(1, args.seeds - 1)):
            points.append({"config": "target-closure", "ops": 250_000, "seed": seed, "rep": 0,
                           "series": "target-closure", "knobs": {"targets": 980},
                           "records": args.records, "witnesses": args.witnesses})
    with args.out.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"machine": machine(), "workdir": str(workdir), "points": len(points)}) + "\n")
        for spec in points:
            record = run_point(spec, deadline=args.deadline, memory=args.memory, workdir=workdir, budgets=budgets)
            stream.write(json.dumps(record, sort_keys=True, default=str) + "\n")
            stream.flush()
            print(f"[scale] {spec['config']} {spec['ops']} s{spec['seed']} r{spec['rep']}: "
                  f"{record['process']} valid={record['valid']} {record.get('stages', {}).get('analysis')}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
