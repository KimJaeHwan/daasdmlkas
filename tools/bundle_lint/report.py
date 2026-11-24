"""Report rows of ``bundle_lint`` (design G0 r0..r6).

Every row carries a closed ``run_state``; a ``verdict`` only when the state is
``evaluated``. ``source`` says who decided: ``engine`` (an engine result read
back) or ``lint`` (computed by the lint from engine functions). A lint-derived
verdict is never ``refused`` (only the engine refuses).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json

RUN_STATES = ("evaluated", "not_reached", "not_run", "unobserved", "timeout", "error")
VERDICTS = ("applied", "not_applicable", "unrecognized", "withheld", "refused", "unsupported", "error")
SOURCES = ("engine", "lint")
LAYERS = ("transport", "operations", "features", "pipeline")


def source_row_key(function_id: str, index: int) -> str:
    """A source row (refused / unvalidated / maybe without address): r6 section 5."""
    if type(index) is not int or index < 0:
        raise ValueError("source row index must be a non-negative int")
    return f"{function_id}/#{index}"


def operation_row_key(function_id: str, operation_key) -> str:
    """A validated operation or site: ``<manifest function id>/<operation key>``."""
    return f"{function_id}/{_operation_text(operation_key)}"


def _operation_text(key) -> str:
    # (call_seeds.py: address, ordinal, opcode -- any tuple-like key is rendered stably)
    if isinstance(key, str):
        return key
    if isinstance(key, tuple):
        return ":".join(_operation_text(part) for part in key)
    if isinstance(key, int):
        return f"{key:#x}"
    for names in (("address", "ordinal", "opcode"), ("instruction", "ordinal", "opcode")):
        if all(hasattr(key, name) for name in names):
            return ":".join(_operation_text(getattr(key, name)) for name in names)
    return str(key)


@dataclass(frozen=True)
class Row:
    layer: str
    check: str
    key: str
    run_state: str
    verdict: str | None = None
    source: str = "lint"
    detail: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.layer not in LAYERS:
            raise ValueError(f"unknown layer {self.layer!r}")
        if self.run_state not in RUN_STATES:
            raise ValueError(f"unknown run_state {self.run_state!r}")
        if self.source not in SOURCES:
            raise ValueError(f"unknown source {self.source!r}")
        if self.run_state == "evaluated":
            if self.verdict not in VERDICTS:
                raise ValueError(f"evaluated row needs a verdict, got {self.verdict!r}")
            if self.verdict == "refused" and self.source != "engine":
                raise ValueError("only the engine refuses")
        elif self.verdict is not None:
            raise ValueError("a verdict exists only when evaluated")

    def ident(self) -> tuple:
        return (self.layer, self.check, self.key)

    def as_json(self) -> dict:
        row = {"layer": self.layer, "check": self.check, "key": self.key,
               "run_state": self.run_state, "source": self.source}
        if self.verdict is not None:
            row["verdict"] = self.verdict
        if self.detail:
            row["detail"] = self.detail
        return row

    @classmethod
    def from_json(cls, data: dict) -> "Row":
        return cls(data["layer"], data["check"], data["key"], data["run_state"],
                   data.get("verdict"), data.get("source", "lint"), data.get("detail", {}))


def _finite(value):
    """Non-finite floats (a member's 1e400) become null: the report is strict JSON."""
    if isinstance(value, float) and value != value or value in (float("inf"), float("-inf")):
        return None
    if isinstance(value, dict):
        return {key: _finite(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_finite(item) for item in value]
    return value


def dumps(header: dict, rows) -> str:
    rows = sorted(rows, key=Row.ident)
    seen = set()
    for row in rows:
        if row.ident() in seen:
            raise ValueError(f"duplicate report row {row.ident()!r}")
        seen.add(row.ident())
    return json.dumps(_finite({"header": header, "rows": [row.as_json() for row in rows]}),
                      indent=1, sort_keys=True, allow_nan=False) + "\n"


def compare(expect: dict, actual: dict) -> list[str]:
    """Differences between an ``--expect`` report and an actual one (rows by ident;
    ``run_state``, ``verdict``, ``source`` and every ``detail`` key present in the
    expected row). An expected row missing in the actual report is a difference;
    actual rows not listed in the expectation are ignored unless the expectation
    sets ``"exhaustive": true``."""
    got = {Row.from_json(row).ident(): row for row in actual["rows"]}
    diffs = []
    wanted = set()
    for raw in expect["rows"]:
        row = Row.from_json(raw)
        wanted.add(row.ident())
        other = got.get(row.ident())
        if other is None:
            diffs.append(f"missing row {row.ident()!r}")
            continue
        for name in ("run_state", "verdict", "source"):
            if raw.get(name) != other.get(name) and (name != "source" or "source" in raw):
                diffs.append(f"{row.ident()!r}: {name} {raw.get(name)!r} != {other.get(name)!r}")
        actual_detail = other.get("detail", {})
        for name, value in raw.get("detail", {}).items():
            if name not in actual_detail:     # (a missing key is not a null: Astra impl r1 P3)
                diffs.append(f"{row.ident()!r}: detail.{name} {value!r} missing")
            elif actual_detail[name] != value:
                diffs.append(f"{row.ident()!r}: detail.{name} {value!r} != {actual_detail[name]!r}")
    if expect.get("exhaustive"):
        for ident in sorted(set(got) - wanted):
            diffs.append(f"unexpected row {ident!r}")
    return diffs
