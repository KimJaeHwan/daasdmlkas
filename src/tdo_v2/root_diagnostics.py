"""Per-function / per-root blocker diagnostics (opt-in, reporting only).

``EngineRun.diagnostics`` (``root_diagnostics=True`` on the summary-engine
entries): one run names, per function and per root, the already-computed facts
a root's completeness rests on -- which calls are proven, which writer rows a
call contributes, which sink demands of the function's summary are incomplete
and why, which root nodes are operation-bound, and which callee demand a
projected root comes from. A diff of two runs' reports says WHAT changed; it
never says why a baseline differed by itself.

Contract (C1-C4): built after ``report()`` inside ONE ``diagnostic(work)``
context -- it reads final results only, adds no analysis-phase step, charge,
checkpoint or retention, and charges only its own diagnostic ledger, so every
semantic output and every run / function work ledger is identical with the
option on or off (``run.diagnostic_work`` aside). Overhead is bounded by
``TDO_V2_DIAGNOSTIC_WORK`` units (default 5,000,000; every potentially large
read, copy or sort is charged by its known size BEFORE it happens) and
``TDO_V2_DIAGNOSTIC_ITEMS`` per inner list (default 64; the top-level
``functions`` / ``roots`` tables are bounded by the work allowance only);
wall-clock / RSS outcomes are not promised identical. Output is deterministic:
every list is put in canonical order before it is capped, and no process
``id()`` appears.

Truncation: a capped inner list keeps its first ``items`` entries and carries
``<name>_total``; a work cut stops at a function / root boundary, discards the
unfinished record, and leaves the tables built so far. ``truncated`` holds one
row per (where, reason): items -- ``{"where", "reason": "items", "lists",
"shown", "total"}`` summed over the cut lists of records that were kept; work --
``{"where", "reason": "work", "shown", "total": None}``.

A fact the analysis did not retain is reported as ``"unavailable"``; the
builder never reconstructs it by re-running an analysis step.

Phase P1a (this module): F0 status, F1 call inventory (no producers), F2
writers and call rows, F4 sink demands, R3 operation-bound candidates, R4
projected roots (no producers). Producers, the control table, F3 / R5 (P1b),
per-root read debts R1 (P2) and refusal / source-demand capture (P3) are not
built yet.
"""

from __future__ import annotations

import os

VERSION = 1
PHASE = "P1a"
DEFAULT_ITEMS = 64
DEFAULT_WORK = 5_000_000
_CALL_OPCODES = frozenset({"CALL", "CALLIND"})
UNAVAILABLE = "unavailable"
STACK_PREMISE = "opaque-callees-restore-stack-pointer"


def limits_from_environment() -> tuple[int, int]:
    """(items per inner list, diagnostic work units)."""

    def read(name, default):
        raw = os.environ.get(name)
        if raw is None or raw == "":
            return default
        value = int(raw)
        if value < 1:
            raise ValueError(f"{name} must be a positive integer")
        return value

    return read("TDO_V2_DIAGNOSTIC_ITEMS", DEFAULT_ITEMS), read("TDO_V2_DIAGNOSTIC_WORK", DEFAULT_WORK)


def build_diagnostics(run, results, by_key) -> dict:
    """The run's diagnostics dict (``EngineRun.diagnostics``). Any exception
    other than a cancellation yields ``{"version", "phase", "error"}``: the run
    itself is returned unchanged by the caller."""
    from .resource_limits import AnalysisCancelled, diagnostic

    try:
        items, work = limits_from_environment()
        with diagnostic(work):
            return _Builder(run, results, by_key, items, work).build()
    except AnalysisCancelled:
        raise
    except Exception as error:   # (a builder bug never breaks the run)
        return {"version": VERSION, "phase": PHASE, "error": f"{type(error).__name__}: {error}"}


# -- canonical order -----------------------------------------------------------------

def _operation_order(key: str):
    """Sort key of an operation key "space:offset:ordinal:OPCODE[~row]" (hex
    space / offset, decimal ordinal); unparsable keys sort last by text."""
    base, _, row = key.partition("~")
    parts = base.split(":")
    try:
        return (0, int(parts[0], 16), int(parts[1], 16), int(parts[2]), parts[3], _row_order(row))
    except (ValueError, IndexError):
        return (1, 0, 0, 0, key, ())


def _row_order(row: str):
    """Rows "u6" / "12" / "sink3": the letters, then the number (so u10 > u9)."""
    head = row.rstrip("0123456789")
    tail = row[len(head):]
    return (head, int(tail) if tail else -1, row)


def _function_order(key: str):
    try:
        space, offset = key.split(":")
        return (0, int(space, 16), int(offset, 16), "")
    except ValueError:
        return (1, 0, 0, key)


class _Builder:
    def __init__(self, run, results, by_key, items: int, work: int) -> None:
        self.run, self.results, self.by_key = run, results, by_key
        self.items, self.work = items, work
        self.cuts: dict = {}      # where -> [lists, shown, total] of kept records
        self.pending: dict = {}   # the same for the record being built
        self.lookups: dict = {}   # (function key, name) -> dict built once (charged)

    # -- budget, caps, lookups ----------------------------------------------------------

    @staticmethod
    def charge(n: int) -> None:
        from .resource_limits import charge

        charge(max(1, n))

    def cap(self, record: dict, name: str, values: list, where: str) -> None:
        """``record[name]`` = the first ``items`` of ``values`` (already in
        canonical order); a cut adds ``<name>_total`` and is staged for the
        record's truncation row (committed only if the record is kept)."""
        if len(values) > self.items:
            record[name] = values[:self.items]
            record[f"{name}_total"] = len(values)
            row = self.pending.setdefault(where, [0, 0, 0])
            row[0] += 1
            row[1] += self.items
            row[2] += len(values)
        else:
            record[name] = values

    def commit(self) -> None:
        for where, (lists, shown, total) in self.pending.items():
            row = self.cuts.setdefault(where, [0, 0, 0])
            row[0] += lists
            row[1] += shown
            row[2] += total
        self.pending = {}

    def lookup(self, key: str, name: str, pairs) -> dict:
        """A dict of the function's ``pairs`` (a tuple of (key, value)), built
        once per function and charged by its size first."""
        found = self.lookups.get((key, name))
        if found is None:
            self.charge(len(pairs))
            found = self.lookups[(key, name)] = dict(pairs)
        return found

    # -- the report ----------------------------------------------------------------------

    def build(self) -> dict:
        from .resource_limits import DiagnosticExhausted

        functions: dict = {}
        roots: list = []
        truncated: list = []
        where = "functions"
        try:
            self.charge(len(self.run.failed_functions) + len(self.results))
            failed = {key: (reason, detail) for key, reason, detail in self.run.failed_functions}
            keys = set(self.results) | set(failed)
            self.charge(len(keys))
            for key in sorted(keys, key=_function_order):
                self.pending = {}
                record = self.function(key, failed.get(key))
                functions[key] = record   # (atomic: built, then kept)
                self.commit()
            where = "roots"
            self.charge(len(self.run.roots))
            ordered = sorted(self.run.roots, key=lambda root: (
                root.function_space_id, root.function_byte_offset, root.label, root.occurrence_ordinal))
            for root in ordered:
                self.pending = {}
                record = self.root(root)
                roots.append(record)
                self.commit()
            where = None
        except DiagnosticExhausted:
            self.pending = {}
            truncated.append({"where": where, "reason": "work",
                              "shown": len(functions) if where == "functions" else len(roots), "total": None})
            if where == "functions":
                truncated.append({"where": "roots", "reason": "work", "shown": 0, "total": None})
        for name in sorted(self.cuts):
            lists, shown, total = self.cuts[name]
            truncated.append({"where": name, "reason": "items", "lists": lists, "shown": shown, "total": total})
        return {
            "version": VERSION, "phase": PHASE, "functions": functions, "roots": roots,
            "limits": {"items": self.items, "work": self.work}, "truncated": truncated,
        }

    # -- FunctionRecord ------------------------------------------------------------------

    def function(self, key: str, failure) -> dict:
        from .normalize import NormalizedFunction

        self.charge(1)
        item = self.results.get(key)
        normalized = getattr(item, "normalized", None)
        record: dict = {}
        # F0: a late failure wins over a published normalization (Astra 10.5)
        if failure is not None:
            reason, detail = failure
            record["status"] = f"failed:{reason}"
            record["failure_detail"] = detail
        elif type(normalized) is NormalizedFunction:
            record["status"] = "normalized"
        else:
            record["status"] = "unresolved"
            record["failure_detail"] = getattr(item, "failure_detail", "") if item is not None else ""
        record["recursion_unresolved"] = bool(getattr(item, "recursion_unresolved", False))
        if type(normalized) is not NormalizedFunction or item is None:
            record["calls"] = record["writers"] = record["call_rows"] = UNAVAILABLE
            record["demands"] = self.demands(record, item)
            return record
        self.calls(record, key, item, normalized)
        self.writers(record, item, normalized)
        self.call_rows(record, normalized)
        record["demands"] = self.demands(record, item)
        return record

    def calls(self, record: dict, key: str, item, normalized) -> None:
        """F1: every CALL / CALLIND of the observation and every tail call the
        engine seeded (``call_seeds.seed_tail_calls``: a call-flagged BRANCH /
        CBRANCH / BRANCHIND, its operation key -- bound, resolved or opaque);
        the target, the effect, and its stack restoration. Map entries of
        other operations are not listed."""
        observation = getattr(item.unit, "observation", None)
        instructions = getattr(observation, "instructions", ()) if observation is not None else ()
        self.charge(len(instructions))
        self.charge(sum(len(row.operations) for row in instructions))
        evidence = self.by_key.get(key)
        tails = tuple(getattr(evidence, "tails", ()) or ())
        self.charge(len(tails))
        tail_keys = {seed.operation_key for seed in tails}
        keys = set(tail_keys)
        for row in instructions:
            for ordinal, operation in enumerate(row.operations):
                if operation.opcode in _CALL_OPCODES:
                    keys.add(f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:{operation.opcode}")
        proven = self.lookup(key, "proven", normalized.proven_call_effects)
        assumed = self.lookup(key, "assumed", normalized.assumed_call_effects)
        self.charge(len(normalized.premise_uses))
        sp_uses = {where for name, stage, where in normalized.premise_uses
                   if name == STACK_PREMISE and stage == "normalize"}
        self.charge(len(keys))
        rows = []
        for call in sorted(keys, key=_operation_order):
            self.charge(1)
            row: dict = {"call": call, "target": self.target(item, call)}
            if call in tail_keys:
                row["tail"] = True
            if call in item.refused_models:
                row["refused_model"] = str(item.refused_models[call])
            effect = proven.get(call)
            if effect is not None:
                row["effect"] = "proven"
                row["stack"] = str(effect.stack_restoration.value)
                row["preserves_memory"] = bool(effect.preserves_memory)
                row["clobbers_below"] = bool(effect.clobbers_below)
                row["runs"] = len(effect.runs)
                row["memory_runs"] = len(effect.memory_runs)
                row["sink_demands"] = len(effect.sink_demands)
                row["tail_stack"] = bool(effect.tail_stack)
            elif call in assumed:
                row["effect"] = "assumed"   # (TEST-ONLY assumed boundary effect)
                row["stack"] = None
            else:
                row["effect"] = "none"
                # the exact use the normalization recorded (normalize._premise_uses)
                row["stack"] = "assumed" if call in sp_uses else "unknown"
            rows.append(row)
        record["calls_summary"] = {
            "total": len(rows),
            "proven": sum(1 for row in rows if row["effect"] == "proven"),
            "assumed": sum(1 for row in rows if row["effect"] == "assumed"),
            "none": sum(1 for row in rows if row["effect"] == "none"),
        }
        self.cap(record, "calls", rows, "functions.calls")
        for row in record["calls"]:   # (inner caps on kept entries only)
            if row["target"] is not None and "members" in row["target"]:
                self.cap(row["target"], "members", row["target"]["members"], "functions.calls.members")

    def cap_kept(self, record: dict, name: str, rows: list, where: str, inner: tuple) -> None:
        """Cap ``rows`` into ``record[name]``, then each kept row's ``inner``
        (field, where) lists -- a dropped row's lists are never counted."""
        self.cap(record, name, rows, where)
        for row in record[name]:
            for field, inner_where in inner:
                self.cap(row, field, row[field], inner_where)

    def target(self, item, call: str):
        """The call's target: the callee function (``calls``), the members of a
        multi-target call (``multi_calls``), and the model label it takes
        (``bound_calls`` / ``declared`` -- also a TEST-ONLY declared boundary);
        None when the engine resolved none."""
        found: dict = {}
        if call in item.calls:
            found["function"] = item.calls[call]
        elif call in item.multi_calls:
            members = item.multi_calls[call]
            self.charge(len(members))
            found["members"] = sorted(members, key=_function_order)   # (capped once the row is kept)
        if call in item.bound_calls:
            found["model"] = str(item.bound_calls[call][4])
        elif call in item.declared:
            found["model"] = str(item.declared[call])
        return found or None

    def writers(self, record: dict, item, normalized) -> None:
        """F2: every unresolved-write occurrence of the memory SSA with its
        destination class; only WILD blocks the function's data completeness
        (``write_classes``)."""
        from .write_classes import WILD, WriterClasses

        ssa, graph = normalized.memory_ssa, normalized.memory_graph
        if ssa is None or graph is None:
            record["writers"] = UNAVAILABLE
            return
        observation = getattr(item.unit, "observation", None)
        instructions = getattr(observation, "instructions", ()) if observation is not None else ()
        self.charge(len(instructions))
        self.charge(sum(len(row.operations) for row in instructions))   # (the classifier's operation index)
        classes = WriterClasses(normalized.scopes, observation)
        self.charge(len(ssa.unresolved_writes))
        rows = []
        for occurrence in ssa.unresolved_writes:
            op = ssa.actions[occurrence.action_id].operation_key
            kind = classes.classify(op)
            rows.append({"id": f"{op}#{occurrence.occurrence_ordinal}", "op": op,
                         "occurrence": occurrence.occurrence_ordinal, "class": kind,
                         "blocks_function_data_completeness": kind == WILD})
        self.charge(len(rows))
        rows.sort(key=lambda row: (_operation_order(row["op"]), row["occurrence"]))
        record["writers_summary"] = {
            "total": len(rows),
            "ram": sum(1 for row in rows if row["class"] != WILD),
            "wild": sum(1 for row in rows if row["class"] == WILD),
        }
        self.cap(record, "writers", rows, "functions.writers")

    def call_rows(self, record: dict, normalized) -> None:
        """F2 call rows: per call, every effect row derived from it
        (``<call>~<suffix>``) in the FINAL effects, and the rows that write
        memory with exact / unresolved destination counts (Astra 10.1): exact
        -- each ResolvedStorage write naming a memory object (address space or
        function-relative); unresolved -- the memory write, each unresolved
        write, each raw StorageRef write."""
        from .model import ResolvedStorage, StorageRef
        from .span_geometry import StorageObjectKind

        memory = (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE)
        effects = normalized.effects
        self.charge(len(effects))
        by_call: dict = {}
        for effect in effects:
            base, separator, _ = effect.operation_key.partition("~")
            if not separator:
                continue
            self.charge(1 + len(effect.writes) + len(effect.unresolved_writes))
            exact = sum(1 for value in effect.writes
                        if type(value) is ResolvedStorage and value.span.object_id.kind in memory)
            unresolved = (effect.memory_write is not None) + len(effect.unresolved_writes) \
                + sum(1 for value in effect.writes if type(value) is StorageRef)
            by_call.setdefault(base, []).append((effect.operation_key, exact, unresolved))
        self.charge(len(by_call))
        rows = []
        for call in sorted(by_call, key=_operation_order):
            self.charge(len(by_call[call]))
            found = sorted(by_call[call], key=lambda row: _operation_order(row[0]))
            writers = [{"row": key, "exact": exact, "unresolved": unresolved}
                       for key, exact, unresolved in found if exact or unresolved]
            row: dict = {"call": call, "derived": len(found), "writer_rows": len(writers),
                         "exact": sum(item["exact"] for item in writers),
                         "unresolved": sum(item["unresolved"] for item in writers)}
            row["derived_rows"] = [key for key, _, _ in found]
            row["writers"] = writers
            rows.append(row)
        self.cap_kept(record, "call_rows", rows, "functions.call_rows",
                      (("derived_rows", "functions.call_rows.derived_rows"),
                       ("writers", "functions.call_rows.writers")))

    def demands(self, record: dict, item):
        """F4: the summary's sink demands in order -- what one sink root of the
        function needs from callers, whether it is complete, and its debts
        (``index`` is the demand's position in ``summary.sink_demands``)."""
        summary = getattr(item, "summary", None)
        if summary is None:
            return UNAVAILABLE
        demands = summary.sink_demands
        self.charge(len(demands))
        rows = []
        for index, demand in enumerate(demands):
            self.charge(1 + len(demand.debts))
            row: dict = {"index": index, "label": demand.label, "complete": bool(demand.complete),
                         "conditions": len(demand.conditions)}
            row["debts"] = [str(debt) for debt in demand.debts]
            rows.append(row)
        record["demands_summary"] = {"total": len(rows),
                                     "incomplete": sum(1 for row in rows if not row["complete"])}
        found: dict = {}
        self.cap_kept(found, "demands", rows, "functions.demands", (("debts", "functions.demands.debts"),))
        if "demands_total" in found:
            record["demands_total"] = found["demands_total"]
        return found["demands"]

    # -- RootRecord ----------------------------------------------------------------------

    def root(self, root) -> dict:
        from .graph_contracts import NodeKind
        from .interprocedural import function_key_of
        from .normalize import NormalizedFunction

        key = function_key_of(root.function_space_id, root.function_byte_offset)
        self.charge(1 + len(root.root_nodes))
        completeness = root.effective_completeness
        record: dict = {"function": key, "label": root.label, "occurrence": root.occurrence_ordinal,
                        "complete": bool(completeness.complete), "inherited": bool(root.inherited_incomplete)}
        item = self.results.get(key)
        normalized = getattr(item, "normalized", None)
        if not root.root_nodes or type(normalized) is not NormalizedFunction:
            # a failure root (no nodes): what it rests on is in failed_functions
            record["unbound"] = record["projected"] = UNAVAILABLE
            return record
        # R3: operation-bound candidates (a consume-event binding); the
        # refusal that made the binder fall back is not retained (P3)
        graph = normalized.dependencies
        assumed = self.lookup(key, "assumed", normalized.assumed_call_effects)
        candidates = []
        for node in root.root_nodes:
            node_record = graph.node(node)
            if node_record.kind is not NodeKind.OPERATION:
                continue
            op = node_record.key[3:] if node_record.key.startswith("op:") else node_record.key
            row: dict = {"op": op}
            effect = assumed.get(op)
            if effect is not None and effect.label == root.label and effect.reads:
                row["exception"] = "not-evaluated"   # (the TEST-ONLY assumed-effect exception may apply)
            candidates.append(row)
        self.charge(len(candidates))
        candidates.sort(key=lambda row: _operation_order(row["op"]))
        if candidates:
            unbound: dict = {"cause": UNAVAILABLE}
            self.cap(unbound, "candidates", candidates, "roots.unbound")
            record["unbound"] = unbound
        projected = self.projected(key, item, normalized, root)
        if projected is not None:
            record["projected"] = projected
        return record

    def projected(self, key, item, normalized, root):
        """R4: the callee demand a projected root comes from (occurrences after
        the function's own call sites and tails, ``summary_engine.bind``)."""
        evidence = self.by_key.get(key)
        if evidence is None:
            return None
        base = len(evidence.seeds.callsites) + len(evidence.tails)
        index = root.occurrence_ordinal - base
        if index < 0:
            return None
        if index >= len(item.projected_sinks):
            return UNAVAILABLE
        call, demand_index, label, nodes, complete = item.projected_sinks[index]
        effect = self.lookup(key, "proven", normalized.proven_call_effects).get(call)
        lowered = None
        if effect is not None and 0 <= demand_index < len(effect.sink_demands):
            lowered = bool(effect.sink_demands[demand_index].complete)
        return {"call": call, "demand_index": demand_index, "label": label,
                "lowered_complete": UNAVAILABLE if lowered is None else lowered,
                "projected_complete": bool(complete), "materialized": bool(nodes),
                "source_demand": UNAVAILABLE}


__all__ = ("DEFAULT_ITEMS", "DEFAULT_WORK", "PHASE", "VERSION", "build_diagnostics", "limits_from_environment")
