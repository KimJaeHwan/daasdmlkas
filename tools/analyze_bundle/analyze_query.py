#!/usr/bin/env python3
"""Run a source / sink query (query.json) over one exported Bundle (WSL / POSIX).

The question is data, not engine code: each rule names a call target as the
Bundle's call naming reports it (an import such as ``strlen`` through its PLT
stub, an export, a FUN_ name), whether it is a source (the value it returns) or
a sink (a value it receives), and where that value lives at the call --
a register or bytes at an address held in a register. Registers may be given
by name (``"x0"``, ``"rdx"``): they are resolved against the Bundle's own
exported register table (an ISA fact), never against a calling convention.

query.json -- a list of rules (or {"rules": [...]}):

  {"target_name": "strlen", "kind": "sink", "label": "strlen.string",
   "physical_state": [{"base": {"register": "x0"}, "displacement": 0, "byte_size": 1}]}
  {"target_name": "getenv", "kind": "source", "label": "getenv.ret",
   "physical_state": [{"register": "x0"}]}

  physical_state rows: {"register": NAME[, "byte_size": N]} or
  {"byte_offset": OFF, "byte_size": N} (a register slice), or
  {"base": <register row>, "displacement": D, "byte_size": N} (memory at base + D).
  "language_id" defaults to the Bundle's language. Sources: register state only
  (the engine attaches source labels to registers); a memory source is refused.

Output (--out, default ./tdo_query_result.json): every root with its origins
and completeness, the run's assumptions, failed functions, and the call target
names the run classified with how many times each was classified (a count of
classification calls, not of unique call sites). An incomplete root's origins
are candidates, not a proof; with failed functions, an empty origin list does
not prove absence.

Example:
  PYTHONPATH=src python3 tools/analyze_bundle/analyze_query.py /root/tdo_bundles_so/libyolo/<generation> \
      --query query.json --out /tmp/libyolo_result.json
  (--list-calls: no rules, only report which call targets the Bundle has)
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import json
import os
from pathlib import Path
import sys
import time

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "bundle_export"))


def program_evidence(generation: Path):
    """The Bundle's verified program evidence (language, register table)."""
    from hashlib import sha256

    from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
    from tdo_v2.integration.configured_bundle import admit_frozen_bundle
    from tdo_v2.integration.observed_function_session import open_observed_function_session

    binding = NamingBindingExpectation(sha256((REPO / "ghidra/GhidraV2CallNaming.java").read_bytes()).digest(),
                                       CALL_NAMING_GHIDRA_VERSION)
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        for evidence in session.iter_functions():
            return evidence.unit.scopes.program.evidence
    raise ValueError("the Bundle has no admitted function")


def _register(row: dict, table: dict):
    from tdo_v2.physical_state import PhysicalRegisterSlice

    if "register" in row:
        name = row["register"]
        if name in table:   # the exact name first
            offset, size = table[name]
        else:               # then a case-insensitive match, only when unambiguous
            found = {value for key, value in table.items() if key.lower() == name.lower()}
            if len(found) != 1:
                raise ValueError(f"register {name!r} is not (or not unambiguously) in the Bundle's register table")
            offset, size = found.pop()
        return PhysicalRegisterSlice(offset, int(row.get("byte_size", size)))
    return PhysicalRegisterSlice(int(row["byte_offset"]), int(row["byte_size"]))


def _state(row: dict, table: dict):
    from tdo_v2.physical_state import PhysicalMemorySlice

    if "base" in row:
        return PhysicalMemorySlice(_register(row["base"], table), int(row.get("displacement", 0)),
                                   int(row["byte_size"]))
    return _register(row, table)


def load_rules(path: Path, evidence) -> tuple:
    from tdo_v2.boundary import BoundaryKind
    from tdo_v2.boundary_rules import BoundaryRule

    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data["rules"] if isinstance(data, dict) else data
    table = {}
    if evidence.register_evidence is not None:
        for register in evidence.register_evidence.registers:
            table[register.name] = (register.byte_offset, register.byte_size)
    for row in rows:
        # the engine attaches source labels to register state only
        # (summary_engine source boundaries): a memory source would be accepted
        # and silently never attached
        if row["kind"] == "source" and any("base" in item for item in row["physical_state"]):
            raise ValueError(f"source {row['label']!r}: only register sources are supported (no 'base' selector)")
    language = evidence.translation_namespace.language_id
    return tuple(BoundaryRule(row["target_name"], row.get("language_id", language), BoundaryKind(row["kind"]),
                              row["label"], tuple(_state(item, table) for item in row["physical_state"]),
                              bool(row.get("assume_call_effect", False)))
                 for row in rows)


class RecordingProvider:
    """The query's provider, also recording every call target it is asked about."""

    def __init__(self, inner) -> None:
        self.inner = inner
        self.seen: Counter = Counter()

    def classify(self, call):
        self.seen.update(call.target_names or ("<unnamed>",))
        return self.inner.classify(call)

    def state(self, call, match):
        return self.inner.state(call, match)

    def __getattr__(self, name):
        return getattr(self.inner, name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("generation", type=Path)
    parser.add_argument("--query", type=Path)
    parser.add_argument("--list-calls", action="store_true", help="no rules: only report the call targets")
    parser.add_argument("--out", type=Path, default=Path("tdo_query_result.json"))
    parser.add_argument("--forward", choices=("0", "1"), help="default 1 (or TDO_V2_FORWARD)")
    parser.add_argument("--function-seconds", help="default 60 (or TDO_V2_FUNCTION_SECONDS)")
    parser.add_argument("--run-seconds", help="default 1800 (or TDO_V2_RUN_SECONDS)")
    args = parser.parse_args()
    if (args.query is None) == (not args.list_calls):
        parser.error("give exactly one of --query or --list-calls")

    import run_dfbench
    from tdo_v2.boundary_rules import SymbolBoundaryProvider
    from tdo_v2.summary_engine import analyze_frozen_bundle_with_summaries

    # an explicit option wins over the environment; the environment over the default
    for name, value, default in (("TDO_V2_FORWARD", args.forward, "1"),
                                 ("TDO_V2_FUNCTION_SECONDS", args.function_seconds, "60"),
                                 ("TDO_V2_RUN_SECONDS", args.run_seconds, "1800")):
        if value is not None:
            os.environ[name] = value
        else:
            os.environ.setdefault(name, default)
    evidence = program_evidence(args.generation)
    rules = load_rules(args.query, evidence) if args.query else ()
    provider = RecordingProvider(SymbolBoundaryProvider(rules))
    started = time.time()
    run = analyze_frozen_bundle_with_summaries(
        args.generation, naming_exporter_source=REPO / "ghidra/GhidraV2CallNaming.java",
        boundary_provider=provider, external_models=run_dfbench.external_models(args.generation),
        pcodeop_models=run_dfbench.pcodeop_models(), origin_witnesses=True, operation_records=False)
    roots = [{"function": hex(root.function_byte_offset), "label": root.label,
              "occurrence": root.occurrence_ordinal, "origins": root.reached_origin_labels,
              "complete": root.is_effectively_complete,
              "local_completeness": asdict(root.local_completeness),
              "effective_completeness": asdict(root.effective_completeness),
              "inherited_incomplete": root.inherited_incomplete, "explanation": root.explanation}
             for root in run.roots]
    result = {"generation": str(args.generation), "sha256": run.executable_sha256,
              "language_id": evidence.translation_namespace.language_id,
              "seconds": round(time.time() - started, 1), "rules": [asdict(rule) for rule in rules],
              "assumptions": run.assumptions, "failed_functions": run.failed_functions, "roots": roots,
              "call_targets": dict(provider.seen.most_common())}
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(f"{len(roots)} roots, {sum(root['complete'] for root in roots)} complete, "
          f"{len(run.failed_functions)} failed functions, {len(provider.seen)} call targets, "
          f"{result['seconds']} s -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
