"""The snapshot gate (snapshot_compare.sh): a new snapshot directory against
a baseline, every run of the expected manifest (snapshot_expected.txt).

    snapshot_gate.py BASELINE_DIR NEW_DIR [MANIFEST]

Exit status (the worst found; the last line counts both kinds):
  0  every expected run has its expected exit code in both directories and
     every artifact is identical to the baseline's;
  1  a result differs (investigate the engine): an artifact's sections, or a
     run's exit code (an unexpected failure, or a declared failure that now
     passes);
  2  the gate is incomplete (fix or rerun the harness): an expected run or
     artifact is missing, a run did not complete (timeout / killed), an
     artifact is unreadable, incomplete or malformed, a status line is
     malformed or repeated, the baseline disagrees with the manifest, or the
     new directory has a run / artifact the manifest does not list.
Baseline files the manifest does not list are reported and ignored (e.g. a
one-off phases dump kept next to the baseline)."""

import re
import sys
from pathlib import Path

from semantic_snapshot import compare

HERE = Path(__file__).resolve().parent
_LINE = re.compile(r"^(\S+) rc=(-?\d+)(?:\s|$)")
# ``timeout``'s own exit (124) and a run killed by SIGKILL / SIGTERM: no result
_NOT_COMPLETED = {124, 137, 143}


def read_manifest(path: Path) -> dict[str, int]:
    """name -> expected exit code."""
    expected: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name, *rest = line.split()
        code = 0
        for item in rest:
            if not item.startswith("rc="):
                raise ValueError(f"{path}: bad field {item!r} on {name}")
            code = int(item[3:])
        if name in expected:
            raise ValueError(f"{path}: {name} listed twice")
        expected[name] = code
    return expected


def read_statuses(directory: Path) -> tuple[dict[str, int], list[str]]:
    """(run name -> exit code, problems), from status.txt (Bundles) and
    fixtures.txt (fixtures, named "fixture-<name>"); a malformed line or a
    run listed twice is a problem."""
    found: dict[str, int] = {}
    problems: list[str] = []
    for file, prefix in (("status.txt", ""), ("fixtures.txt", "fixture-")):
        path = directory / file
        if not path.exists():
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if not line.strip():
                continue
            match = _LINE.match(line)
            if match is None:
                problems.append(f"MALFORMED {path.name}:{number}: {line[:80]}")
                continue
            name = prefix + match.group(1)
            if name in found:
                problems.append(f"REPEATED {path.name}:{number}: {name}")
                continue
            found[name] = int(match.group(2))
    return found, problems


def gate(baseline: Path, new: Path, manifest: Path, out=print) -> int:
    expected = read_manifest(manifest)
    differences = incomplete = 0

    def differ(message):
        nonlocal differences
        out(message)
        differences += 1

    def missing(message):
        nonlocal incomplete
        out(message)
        incomplete += 1

    if not baseline.is_dir() or not new.is_dir():
        out(f"[gate] missing directory: {baseline if not baseline.is_dir() else new}")
        out("COMPAREDONE status=2 differences=0 incomplete=1")
        return 2
    (old_runs, old_problems), (new_runs, new_problems) = read_statuses(baseline), read_statuses(new)
    for problem in old_problems:
        missing(f"BASELINE {problem}")
    for problem in new_problems:
        missing(problem)
    for name, code in expected.items():
        if old_runs.get(name) != code:
            missing(f"BASELINE {name}: rc={old_runs.get(name)} (manifest rc={code})")
        if name not in new_runs:
            missing(f"NOT RUN {name}")
            continue
        if new_runs[name] != code:
            if new_runs[name] in _NOT_COMPLETED:
                missing(f"NOT COMPLETED {name}: rc={new_runs[name]} (expected rc={code})")
            else:
                differ(f"RC {name}: rc={new_runs[name]} (expected rc={code})")
            continue
        if code != 0:
            out(f"{name}: expected failure rc={code}")
            continue
        left, right = baseline / f"{name}.json.gz", new / f"{name}.json.gz"
        if not left.exists():
            missing(f"BASELINE MISSING {left.name}")
            continue
        if not right.exists():
            missing(f"MISSING {right.name}")
            continue
        try:
            found = compare(left, right)
        except SystemExit as error:   # (unreadable / incomplete artifact)
            missing(str(error))
            continue
        except Exception as error:    # (a malformed artifact: never a verdict of 1 or a crash)
            missing(f"MALFORMED {right.name} or {left.name}: {type(error).__name__}: {error}")
            continue
        if found == 1:
            differences += 1
        elif found != 0:
            incomplete += 1           # (2: the two runs' inputs differ)
    artifacts = {f"{name}.json.gz" for name, code in expected.items() if code == 0}
    declared = {f"{name}.json.gz" for name, code in expected.items() if code != 0}
    for name in sorted(set(new_runs) - set(expected)):
        missing(f"UNEXPECTED RUN {name} rc={new_runs[name]}")
    for path in sorted(new.glob("*.json.gz")):
        if path.name in declared:
            out(f"(ignored artifact of a declared failure {path.name})")
        elif path.name not in artifacts:
            missing(f"UNEXPECTED {path.name}")
    for path in sorted(baseline.glob("*.json.gz")):
        if path.name not in artifacts:
            out(f"(ignored baseline extra {path.name})")
    status = 2 if incomplete else 1 if differences else 0
    out(f"COMPAREDONE status={status} differences={differences} incomplete={incomplete}")
    return status


def main(argv) -> int:
    if len(argv) not in (3, 4):
        print(__doc__)
        return 2
    manifest = Path(argv[3]) if len(argv) == 4 else HERE / "snapshot_expected.txt"
    try:
        return gate(Path(argv[1]), Path(argv[2]), manifest)
    except Exception as error:   # (the gate itself failed: never exit 0 / 1)
        print(f"[gate] error: {type(error).__name__}: {error}")
        print("COMPAREDONE status=2 differences=0 incomplete=1")
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
