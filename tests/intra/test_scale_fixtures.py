"""K2 measurement machinery (docs 25.30 K2 / 25.31): the scale fixtures'
embedded probes hold on the measured EngineRun for each stress axis, the
per-phase table is opt-in and does not change results, the in-memory
read-only image follows the file-backed rules."""

import json
import sys
import threading
from pathlib import Path

import pytest

import scale_fixtures
import synthetic
from tdo_v2 import phases, resource_limits
from tdo_v2.summary_engine import analyze_observed_with_summaries

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "graph_fidelity"))


def _run(program, **options):
    inputs = synthetic.summary_inputs(program.functions, program.names, layout=program.layout, data=program.data)
    return analyze_observed_with_summaries(
        inputs.program, inputs.evidences, image_info=inputs.image_info, readonly_image=inputs.readonly_image,
        boundary_provider=program.provider, pcodeop_models=program.pcodeop_models(inputs.evidences), **options)


@pytest.mark.parametrize("config", ["target", "escapes", "recursion", "fanin", "rep", "traps", "resolvable",
                                    "two_pointer", "unknown_stores", "growing_fields"])
def test_every_probe_holds_on_each_stress_axis(config):
    from scale_bench import CONFIGS
    from scale_point import _check_probes

    program = scale_fixtures.realistic(1500, 1, **CONFIGS[config])
    run = _run(program)
    verdicts = _check_probes(program, run)
    assert len(verdicts) == 9 and all(item["ok"] for item in verdicts), [item for item in verdicts if not item["ok"]]
    assert run.failed_functions == ()
    counts = program.counts
    assert counts["caller_ops"] >= 1000 and counts["caller_call_sites"] > 0


def test_the_generator_is_deterministic_and_reports_what_it_built():
    first, second = scale_fixtures.realistic(1500, 7), scale_fixtures.realistic(1500, 7)
    assert [b.to_json() for b in first.functions] == [b.to_json() for b in second.functions]
    assert first.counts == second.counts
    with pytest.raises(ValueError, match="unknown knobs"):
        scale_fixtures.realistic(1500, 0, nonsense=1)


def test_phases_off_records_nothing(monkeypatch):
    monkeypatch.delenv("TDO_V2_PHASES", raising=False)
    _run(scale_fixtures.realistic(800, 0))
    assert resource_limits.last_run().phases is None
    assert phases.phase("anything") is phases._NULL


def test_phases_on_records_the_table_and_changes_no_result(monkeypatch):
    from semantic_snapshot import encode

    program = scale_fixtures.realistic(800, 0)
    monkeypatch.delenv("TDO_V2_PHASES", raising=False)
    off = encode(_run(program))
    monkeypatch.setenv("TDO_V2_PHASES", "1")
    on = encode(_run(program))
    assert json.dumps(on, sort_keys=True) == json.dumps(off, sort_keys=True)
    table = resource_limits.last_run().phases
    rows = table["phases"]
    for name in ("analyze_units", "normalize", "memory_ssa", "may_alias", "summarize", "binding", "roots",
                 "reporting"):
        assert rows[name]["count"] >= 1, name
    assert all(row["time_exclusive"] <= row["time"] + 1e-9 for row in rows.values())
    assert all(row["work_exclusive"] <= row["work"] for row in rows.values())
    assert rows["normalize"]["counters"]["graph_nodes"] > 0
    assert table["open"] == []
    assert not any(thread.name == "tdo-phase-sampler" for thread in threading.enumerate())


def test_logical_work_counts_pending_units():
    def body():
        before = resource_limits.logical_work()
        for _ in range(17):
            resource_limits.step()
        return resource_limits.logical_work() - before

    assert resource_limits.run_analysis(body) == 17


def test_the_in_memory_readonly_image_follows_the_rules():
    layout = synthetic.DEFAULT_LAYOUT
    data = bytearray(layout.data_size)
    data[0x10:0x18] = (0x1234).to_bytes(8, "little")
    half = layout.data_size // 2
    data[half + 0x10:half + 0x18] = (0x5678).to_bytes(8, "little")
    info, image = synthetic.synthetic_image(layout, bytes(data))
    assert image.value(synthetic.RAM, layout.data_base + 0x10, 8) == 0x1234          # .rdata: r--
    assert image.value(synthetic.RAM, layout.data_base + half + 0x10, 8) is None    # .data: writable
    assert info.executable_format.startswith("Portable Executable")


def test_the_target_closure_series_references_every_target():
    for series, extra in (("target-closure", {"targets": 60}), ("scaled", {"recursion": True})):
        program = scale_fixtures.realistic(6000, 0, series=series, **extra)
        assert program.counts["unreferenced_targets"] == 0, series


def test_a_truncated_telemetry_line_is_tolerated(tmp_path):
    from scale_bench import last_telemetry

    path = tmp_path / "t"
    path.write_text('{"event": "enter", "stage": "analysis", "seq": 1}\n'
                    '{"event": "phase_enter", "phase": "normalize", "seq": 2}\n'
                    '{"event": "progress", "phase": "normalize", "seq": 3}\n'
                    '{"event":"progress","phase":', encoding="utf-8")
    found = last_telemetry(path)
    assert found["open_stages"] == ["analysis"] and found["open_phases"] == ["normalize"]
    assert found["last_observation"]["seq"] == 3


def test_inherited_incompleteness_fails_a_path_complete_probe():
    from dataclasses import replace
    from scale_point import _check_probes

    program = scale_fixtures.realistic(800, 0)
    run = _run(program)
    probe = next(item for item in program.probes if item.name == "positive")
    roots = tuple(replace(root, inherited_incomplete=True)
                  if root.function_byte_offset == probe.function and root.occurrence_ordinal == probe.occurrence
                  else root for root in run.roots)
    verdicts = {item["probe"]: item for item in _check_probes(program, replace(run, roots=roots))}
    assert not verdicts["positive"]["ok"] and verdicts["negative"]["ok"]
