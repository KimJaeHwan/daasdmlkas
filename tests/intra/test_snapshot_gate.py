"""The snapshot gate (tools/graph_fidelity/snapshot_gate.py): its exit status
for each way a new snapshot directory can disagree with the baseline."""

import gzip
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "graph_fidelity"))

from snapshot_gate import gate, read_manifest  # noqa: E402

MANIFEST = "a.default\nb.legacy rc=1   # known failure\nfixture-f\n"


def _snapshot(path: Path, sections: dict, complete=True):
    document = {"complete": complete, "meta": {"config": "default"},
                "digests": {name: json.dumps(value, sort_keys=True) for name, value in sections.items()},
                "sections": sections}
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(document, handle)


def _directory(root: Path, name: str, *, runs=None, fixtures=None, artifacts=None):
    directory = root / name
    directory.mkdir()
    runs = {"a.default": 0, "b.legacy": 1} if runs is None else runs
    fixtures = {"f": 0} if fixtures is None else fixtures
    (directory / "status.txt").write_text("".join(f"{run} rc={code} tail\n" for run, code in runs.items()))
    (directory / "fixtures.txt").write_text("".join(f"{run} rc={code} 1.0 s 10 KB\n" for run, code in fixtures.items()))
    artifacts = {"a.default": {"x": 1}, "fixture-f": {"y": 2}} if artifacts is None else artifacts
    for artifact, sections in artifacts.items():
        _snapshot(directory / f"{artifact}.json.gz", sections)
    return directory


def _run(tmp_path, **new):
    manifest = tmp_path / "expected.txt"
    manifest.write_text(MANIFEST)
    baseline = _directory(tmp_path, "base")
    lines: list = []
    return gate(baseline, _directory(tmp_path, "new", **new), manifest, out=lines.append), lines


def test_identical_passes(tmp_path):
    status, lines = _run(tmp_path)
    assert status == 0, lines
    assert lines[-1] == "COMPAREDONE status=0 differences=0 incomplete=0"


def test_a_section_difference_fails(tmp_path):
    status, _ = _run(tmp_path, artifacts={"a.default": {"x": 9}, "fixture-f": {"y": 2}})
    assert status == 1


def test_a_missing_artifact_is_incomplete(tmp_path):
    status, lines = _run(tmp_path, artifacts={"a.default": {"x": 1}})
    assert status == 2 and "MISSING fixture-f.json.gz" in lines


def test_a_run_not_run_is_incomplete(tmp_path):
    status, lines = _run(tmp_path, runs={"b.legacy": 1})
    assert status == 2 and "NOT RUN a.default" in lines


def test_an_unexpected_failure_and_an_unexpected_pass_fail(tmp_path):
    status, lines = _run(tmp_path, runs={"a.default": 1, "b.legacy": 1})
    assert status == 1 and any(line.startswith("RC a.default") for line in lines)


def test_a_declared_failure_that_passes_fails(tmp_path):
    status, lines = _run(tmp_path, runs={"a.default": 0, "b.legacy": 0})
    assert status == 1 and any(line.startswith("RC b.legacy") for line in lines)


def test_an_unlisted_run_or_artifact_is_incomplete(tmp_path):
    status, lines = _run(tmp_path, runs={"a.default": 0, "b.legacy": 1, "c.default": 0},
                         artifacts={"a.default": {"x": 1}, "fixture-f": {"y": 2}, "c.default": {}})
    assert status == 2
    assert "UNEXPECTED RUN c.default rc=0" in lines and "UNEXPECTED c.default.json.gz" in lines


def test_an_incomplete_artifact_is_incomplete(tmp_path):
    manifest = tmp_path / "expected.txt"
    manifest.write_text(MANIFEST)
    baseline = _directory(tmp_path, "base")
    new = _directory(tmp_path, "new")
    _snapshot(new / "a.default.json.gz", {"x": 1}, complete=False)
    assert gate(baseline, new, manifest, out=lambda line: None) == 2


def test_a_baseline_extra_is_ignored(tmp_path):
    manifest = tmp_path / "expected.txt"
    manifest.write_text(MANIFEST)
    baseline = _directory(tmp_path, "base")
    _snapshot(baseline / "zlib.phases.json.gz", {"p": 1})
    lines: list = []
    assert gate(baseline, _directory(tmp_path, "new"), manifest, out=lines.append) == 0
    assert "(ignored baseline extra zlib.phases.json.gz)" in lines


def test_a_timeout_is_incomplete_not_a_difference(tmp_path):
    status, lines = _run(tmp_path, runs={"a.default": 124, "b.legacy": 1})
    assert status == 2 and any(line.startswith("NOT COMPLETED a.default") for line in lines)


def test_malformed_and_repeated_status_lines_are_incomplete(tmp_path):
    manifest = tmp_path / "expected.txt"
    manifest.write_text(MANIFEST)
    baseline = _directory(tmp_path, "base")
    new = _directory(tmp_path, "new")
    with (new / "status.txt").open("a") as handle:
        handle.write("extra rc=broken\na.default rc=124 tail\n")
    lines: list = []
    assert gate(baseline, new, manifest, out=lines.append) == 2
    assert any(line.startswith("MALFORMED status.txt:3") for line in lines)
    assert any(line.startswith("REPEATED status.txt:4: a.default") for line in lines)


def test_a_malformed_artifact_is_incomplete(tmp_path):
    manifest = tmp_path / "expected.txt"
    manifest.write_text(MANIFEST)
    baseline = _directory(tmp_path, "base")
    new = _directory(tmp_path, "new")
    with gzip.open(new / "a.default.json.gz", "wt", encoding="utf-8") as handle:
        json.dump({"complete": True}, handle)   # (no meta / digests)
    lines: list = []
    assert gate(baseline, new, manifest, out=lines.append) == 2
    assert any(line.startswith("MALFORMED a.default.json.gz") for line in lines)


def test_a_difference_and_an_incomplete_run_are_both_counted(tmp_path):
    status, lines = _run(tmp_path, artifacts={"a.default": {"x": 9}})
    assert status == 2
    assert lines[-1] == "COMPAREDONE status=2 differences=1 incomplete=1"


def test_an_artifact_of_a_declared_failure_is_ignored(tmp_path):
    status, lines = _run(tmp_path, artifacts={"a.default": {"x": 1}, "fixture-f": {"y": 2}, "b.legacy": {}})
    assert status == 0, lines
    assert "(ignored artifact of a declared failure b.legacy.json.gz)" in lines


def test_a_bad_manifest_is_incomplete(tmp_path, capsys):
    from snapshot_gate import main

    manifest = tmp_path / "expected.txt"
    manifest.write_text("a.default\na.default\n")
    baseline, new = _directory(tmp_path, "base"), _directory(tmp_path, "new")
    assert main(["snapshot_gate.py", str(baseline), str(new), str(manifest)]) == 2
    assert capsys.readouterr().out.splitlines()[-1] == "COMPAREDONE status=2 differences=0 incomplete=1"


def test_the_repository_manifest_parses():
    expected = read_manifest(REPO / "tools" / "graph_fidelity" / "snapshot_expected.txt")
    assert expected["v2-win-debug-full.legacy"] == 1
    assert sum(1 for code in expected.values() if code == 0) == 35
