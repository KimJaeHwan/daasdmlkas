"""One scale-benchmark point (docs 25.30 K2), run by scale_bench.py in its own
process under tools/run_supervised.py:

    scale_point.py SPEC_JSON TELEMETRY_FILE RESULT_FILE

SPEC: {"ops": N, "seed": S, "series": "scaled"|"target-closure", "knobs": {...},
       "witnesses": bool, "records": bool}
Writes telemetry lines (enter / exit of the outer stages, progress every 5 s
with the engine's innermost top-level phase) to TELEMETRY_FILE as it goes,
and one result object to RESULT_FILE at the end: counts, timings per stage,
probe verdicts, failed functions, the engine's phase table, and the function
ledgers split into the caller, its callees and the shared remainder."""

from __future__ import annotations

import time

STARTED = time.perf_counter()

import json  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
import threading  # noqa: E402
import uuid  # noqa: E402
from pathlib import Path  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / "src"), str(REPO / "tests" / "intra")]


class Telemetry:
    def __init__(self, path: Path) -> None:
        self.handle = open(path, "a", encoding="utf-8")
        self.run = uuid.uuid4().hex[:12]
        self.sequence = 0
        self.lock = threading.Lock()

    def write(self, event: str, **fields) -> None:
        with self.lock:
            self.sequence += 1
            row = {"run": self.run, "seq": self.sequence, "event": event, "mono": round(time.perf_counter(), 4),
                   "wall": round(time.time(), 3), **fields}
            self.handle.write(json.dumps(row, sort_keys=True) + "\n")
            self.handle.flush()

    def stage(self, name: str):
        telemetry = self

        class _Stage:
            def __enter__(self):
                self.start = time.perf_counter()
                telemetry.write("enter", stage=name)
                return self

            def __exit__(self, kind, value, traceback):
                self.seconds = time.perf_counter() - self.start
                telemetry.write("exit", stage=name, seconds=round(self.seconds, 4),
                                error=None if kind is None else kind.__name__)
                return False

        return _Stage()


def _progress(telemetry: Telemetry, stop: threading.Event) -> None:
    from tdo_v2 import phases

    while True:
        table = phases._TABLE
        telemetry.write("progress", phase=None if table is None else table.top)
        if stop.wait(5.0):
            return


def _check_probes(program, run) -> list:
    """Each probe against the measured EngineRun (docs 25.30 K2 C)."""
    verdicts = []
    for probe in program.probes:
        label = f"{probe.sink}.arg0"
        rows = [root for root in run.roots if root.function_byte_offset == probe.function]
        if probe.occurrence >= 0:
            found = [root for root in rows if root.label == label and root.occurrence_ordinal == probe.occurrence]
        else:   # projected through the sink caller: the function's only projected row (identity first)
            found = [root for root in rows if root.occurrence_ordinal >= probe.base]
            if len(found) == 1 and found[0].label != label:
                verdicts.append({"probe": probe.name, "found": 1, "ok": False,
                                 "why": f"projected root of {found[0].label}, expected {label}"})
                continue
        verdict = {"probe": probe.name, "found": len(found)}
        if len(found) != 1:
            verdict["ok"] = False
            verdict["why"] = f"{len(found)} roots"
        else:
            root = found[0]
            labels = set(root.reached_origin_labels)
            local = root.effective_completeness
            # the probe's own path: no unresolved read reachable from the root and
            # the root bound; unresolved writes elsewhere in the function (which
            # make every root of the function incomplete) are reported apart
            path_complete = (local.reachable_unresolved_reads == 0 and local.unbound_roots == 0
                             and not root.inherited_incomplete and "failure" not in root.explanation
                             and "rests_on_failed" not in root.explanation
                             and (local.complete or local.function_unresolved_writes > 0))
            verdict.update(labels=sorted(labels), complete=root.is_effectively_complete, path_complete=path_complete,
                           unresolved_reads=local.reachable_unresolved_reads,
                           function_unresolved_writes=local.function_unresolved_writes)
            ok = labels == set(probe.labels)
            if probe.complete is not None:
                ok = ok and path_complete == probe.complete
            verdict["ok"] = ok
        verdicts.append(verdict)
    return verdicts


def main(argv) -> int:
    spec = json.loads(argv[1])
    telemetry = Telemetry(Path(argv[2]))
    result_path = Path(argv[3])
    imports_done = time.perf_counter()
    telemetry.write("start", spec=spec, imports_seconds=round(imports_done - STARTED, 4),
                    environment={key: value for key, value in os.environ.items() if key.startswith("TDO_V2_")})
    stages = {}
    with telemetry.stage("import"):
        import scale_fixtures
        import synthetic
        from tdo_v2 import resource_limits
        from tdo_v2.summary_engine import analyze_observed_with_summaries
    with telemetry.stage("fixture") as stage:
        program = scale_fixtures.realistic(spec["ops"], spec["seed"], series=spec.get("series", "scaled"),
                                           **spec.get("knobs", {}))
    stages["fixture"] = stage.seconds
    with telemetry.stage("admission") as stage:
        inputs = synthetic.summary_inputs(program.functions, program.names, layout=program.layout,
                                          data=program.data, image=True)
    stages["admission"] = stage.seconds
    from tdo_v2 import phases

    phases.LISTENER = lambda event, name: telemetry.write("phase_" + event, phase=name)
    stop = threading.Event()
    progress = threading.Thread(target=_progress, args=(telemetry, stop), daemon=True)
    progress.start()
    # the cyclic collector's share (K2: phase times grew faster than their sizes)
    import gc

    collections = {0: [0, 0.0], 1: [0, 0.0], 2: [0, 0.0]}
    started_gc = [0.0]

    def on_gc(event, info):
        if event == "start":
            started_gc[0] = time.perf_counter()
        else:
            row = collections[info["generation"]]
            row[0] += 1
            row[1] += time.perf_counter() - started_gc[0]

    gc.callbacks.append(on_gc)
    try:
        with telemetry.stage("analysis") as stage:
            run = analyze_observed_with_summaries(
                inputs.program, inputs.evidences, image_info=inputs.image_info, readonly_image=inputs.readonly_image,
                boundary_provider=program.provider, pcodeop_models=program.pcodeop_models(inputs.evidences),
                origin_witnesses=spec.get("witnesses", False), operation_records=spec.get("records", False))
        stages["analysis"] = stage.seconds
    finally:
        stop.set()
        progress.join()
        phases.LISTENER = None
        gc.callbacks.remove(on_gc)
    last = resource_limits.last_run()
    with telemetry.stage("result") as stage:
        sys.path.insert(0, str(REPO / "tools" / "graph_fidelity"))
        from semantic_snapshot import encode

        encoded = json.dumps(encode(run))
        probes = _check_probes(program, run)
    stages["result"] = stage.seconds
    caller_key = ("function", next(unit.scopes.function.scope for unit in (item.unit for item in inputs.evidences)
                                   if unit.scopes.function.entry.byte_offset == program.caller_entry))
    ledgers = getattr(last, "ledgers", {}) or {}
    caller = ledgers.get(caller_key)
    callee_work = sum(item.work for key, item in ledgers.items() if key != caller_key)
    callee_seconds = sum(item.seconds for key, item in ledgers.items() if key != caller_key)
    record = {
        "spec": spec, "counts": program.counts, "stages": {key: round(value, 4) for key, value in stages.items()},
        "imports_seconds": round(imports_done - STARTED, 4),
        "probes": probes, "probes_ok": all(item["ok"] for item in probes) and bool(probes),
        "failed_functions": [list(row) for row in run.failed_functions],
        "roots": len(run.roots), "serialized_bytes": len(encoded),
        "work": {"run": getattr(last, "work", None),
                 "caller": None if caller is None else caller.work, "caller_seconds": None if caller is None
                 else round(caller.seconds, 4), "callees": callee_work, "callees_seconds": round(callee_seconds, 4)},
        "phases": getattr(last, "phases", None),
        "gc": {str(generation): {"collections": count, "seconds": round(seconds, 3)}
               for generation, (count, seconds) in collections.items()},
    }
    if record["work"]["run"] is not None and caller is not None:
        record["work"]["shared"] = record["work"]["run"] - caller.work - callee_work
    partial = result_path.with_name(result_path.name + ".partial")
    partial.write_text(json.dumps(record, sort_keys=True, default=str), encoding="utf-8")
    partial.replace(result_path)
    telemetry.write("done", probes_ok=record["probes_ok"])
    return 0 if record["probes_ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
