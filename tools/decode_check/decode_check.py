#!/usr/bin/env python3
"""G1 ``decode_check``: original-file mapping (L7) + independent-decoder cross-check
(L2) of one sealed Bundle whose original is PE32+ (AMD64) or ELF64 (x86-64)
(design .census6/design_g1_decode_check_r0..r4.md; ELF: elf_map.RULES).
POSIX / WSL; decoders from build_decoders.sh ($G1_DECODERS).

    PYTHONPATH=src python3 tools/decode_check/decode_check.py <generation> --out report.json
        [--assume-stock-ghidra-translator] [--naming-source ghidra/GhidraV2CallNaming.java]

Scope (stated in the report header): only Ghidra-listed rows (L5); 64-bit long
mode; `decoder-matches-cpu` stays the named premise for what decoders cannot
show; instruction meaning beyond the compared attributes is not compared.
Without --assume-stock-ghidra-translator the lift table does not apply (the
Bundle carries no compiled-SLEIGH identity): table-dependent attributes are
unobserved, A1 and an explicit A2 (and the listing continuation A4) compared.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent / "bundle_lint"))

import check  # noqa: E402
import decoders  # noqa: E402
import dependents  # noqa: E402
import evidence  # noqa: E402
import guards  # noqa: E402
import lifting  # noqa: E402
from report import Row, dumps  # noqa: E402

REVISION = 2
G1_LAYERS = ("mapping", "decode")
# (reserved for TBR part A3 / C1 -- decoder read / write sets vs p-code, execution differential:
#  .census6/design_tbr_semantics_r2.md) its own revision; never counted as G1 applied
RESERVED_LAYERS = {"semantics": {"revision": None, "status": "reserved (TBR A3 / C1); not produced by G1; "
                                 "never counted in G1 counts"}}
SCOPE = ("only Ghidra-listed rows are checked (L5); 64-bit long mode only (no compatibility-mode switches); "
         "decoder agreement is not a proof of CPU behaviour (premise decoder-matches-cpu); vendor agreement covers "
         "only what the decoders model; instruction meaning beyond the compared attributes (mnemonic, data effects, "
         "registers written) is not compared; whether a producer guard fired cannot be decided from the Bundle; the "
         "continuation compared is the no-fault one: faults (memory access, privilege, CPU feature availability) are not "
         "compared -- privileged / OS-gated userops are never pinned as no-flow, and per-row privilege / feature facts are "
         "the TBR to-do 'ISA fact annotations'")


def _offset(coordinate_text: str) -> tuple:
    """``space:offset[:...]`` (G0 coordinate / operation key text) -> ``(space, offset)``: rows of
    different address spaces never share a key (Astra impl r2 P1-2)."""
    space, offset = coordinate_text.split(":")[:2]
    return int(space, 16), int(offset, 16)


def baseline_of(claim, raw, function_keys, superseded) -> dict:
    """The engine facts G0 reports for one function, reduced to plain data for the
    dependents table (r2 s6): calls (naming, push projection / relation, plain push),
    S1 exits, BRANCHIND sites, return shapes."""
    import ops_layer

    calls = {}
    for row in ops_layer.call_rows(claim, function_keys):
        op = row.key.split("/", 1)[1]
        item = calls.setdefault(op, {"op": op, "address": _offset(op), "opcode": op.rsplit(":", 1)[1], "facts": {}})
        item["facts"]["naming" if row.check == "call" else row.check] = row.verdict
    exits = [{"source": _offset(row.detail["source"]), "target": _offset(row.detail["target"])}
             for row in ops_layer.exit_rows(claim, raw, function_keys, superseded) if row.verdict != "unrecognized"]
    # (site key control:<entry>:<space>:<offset>; the entry itself contains ':')
    branchind = [{"site": row.key.split("/", 1)[1], "address": _offset(":".join(row.key.rsplit(":", 2)[-2:])),
                  "unknown_transfer": row.detail["unknown_transfer"]}
                 for row in ops_layer.branchind_rows(claim, raw, superseded)]
    returns = [{"op": row.key.split("/", 1)[1], "address": _offset(row.key.split("/", 1)[1]),
                "return_shape": row.verdict} for row in ops_layer.return_rows(claim)]
    return {"calls": list(calls.values()), "exits": exits, "branchind": branchind, "returns": returns}


def collect(generation: Path, naming_source: Path, *, common_facts=False) -> dict:
    from dataclasses import asdict

    import diagnose
    import engine_api
    import ops_layer

    found = {"functions": [], "language": None, "image_base": None, "complete": False,
             "registers": {}, "address_spaces": []}

    def keep(diagnosis):
        program = diagnosis.program_value
        if program is None or not diagnosis.program.get("ok"):
            return
        ev = program.evidence
        ns = ev.translation_namespace
        found.update(language=ns.language_id, language_version=(ns.major_version, ns.minor_version),
                     image_base=ev.image_base.byte_offset)
        if common_facts:
            import common_facts as cf
            from tdo_v2.call_relations import call_relations
            from tdo_v2.isa_identity import link_register, program_counter, stack_register
            from tdo_v2.pcode_blocks import tail_transfers

            prefix = tuple(ns.language_id.split(":")[:3])
            found["isa"] = {("x86", "LE", "64"): "x86-64", ("AARCH64", "LE", "64"): "aarch64"}.get(prefix)
            found["address_spaces"] = [asdict(s) for s in ev.address_spaces]
            found["registers"] = {name: cf.register(reader(ev)) for name, reader in
                                  (("sp", stack_register), ("lr", link_register), ("pc", program_counter))}
            found["complete"] = not diagnosis.fatal and all(c.evidence is not None for c in diagnosis.claims)
        function_keys = {c.entry for c in diagnosis.claims if c.entry}
        last = {c.entry: c for c in diagnosis.claims if c.evidence is not None}
        for claim in diagnosis.claims:
            if claim.evidence is None:
                continue
            unit = claim.unit
            obs = unit.observation
            exits = {r.source: r for r in getattr(obs, "fallthrough_exits", ())}
            rows = []
            for instruction in obs.instructions:
                f = lifting.row_facts(instruction, exits.get(instruction.address))
                f["native_call"] = engine_api.is_native_call(instruction)
                if common_facts:
                    f["isa"] = found["isa"]
                rows.append(f)
            try:
                raw = ops_layer._raw_observation(generation, claim)
                baseline = baseline_of(claim, raw, function_keys, last.get(claim.entry) is not claim)
                baseline_error = None
            except Exception as error:
                baseline, baseline_error = None, f"{type(error).__qualname__}: {error}"
            fn = {"function_id": claim.function_id, "entry": claim.entry, "rows": rows,
                  "s1": bool(getattr(obs, "call_fallthrough_isa", False)),
                  "producer_profile": getattr(obs, "producer_profile", None),
                  "baseline": baseline, "baseline_error": baseline_error}
            if common_facts:
                try:
                    rels = call_relations(obs, unit.scopes)
                    fn.update(engine_relations={k: cf.engine_fields(r) for k, r in rels.items()}, engine_error=None)
                except Exception as error:
                    fn.update(engine_relations=None, engine_error=f"{type(error).__qualname__}: {error}")
                try:
                    tails = tail_transfers(obs, unit.scopes.function.entry)
                    fn.update(tails={k: dict(kind=x.kind, target=cf.addr(x.target.space_id, x.target.byte_offset)
                                             if x.target is not None else None) for k, x in tails.items()},
                              tail_error=None)
                except Exception as error:
                    fn.update(tails=None, tail_error=f"{type(error).__qualname__}: {error}")
            found["functions"].append(fn)

    diagnosis = diagnose.diagnose(generation, naming_source, keep=keep)
    found["admission"] = diagnosis.admission
    return found


def dependents_rows(functions: list, states: dict, reason: str | None, full: bool, header: dict) -> list[Row]:
    """Layer ``dependents`` (r1-r4 s6). Without --full only the would-block rows are
    kept; the per-consumer summary in the header counts every unit."""
    header["dependents"] = {"consumers": {name: {"unit": unit, "reads": reads, "status": status, "design": ref}
                                          for name, (unit, reads, status, ref) in dependents.CONSUMERS.items()},
                            "undetermined": dependents.UNDETERMINED,
                            "rows": "every unit" if full else "would-block units only (the summary counts every unit)"}
    if reason is not None:
        header["dependents"]["summary"] = None
        return [Row("dependents", "table", "program", "unobserved", None, "lint", {"reason": reason})]
    out, judged = [], []
    for function in functions:
        if function["baseline"] is None:
            out.append(Row("dependents", "baseline", function["function_id"], "error", None, "lint",
                           {"reason": function["baseline_error"]}))
            continue
        mine = {(facts["space"], facts["address"]):
                states.get((function["function_id"], facts["space"], facts["address"]), {"*": "unobserved"})
                for facts in function["rows"]}
        for consumer, key, run_state, verdict, detail in dependents.function_rows(function, mine):
            judged.append((consumer, key, run_state, verdict, detail))
            if full or detail["would_block"]:
                out.append(Row("dependents", consumer, key, run_state, verdict, "lint", detail))
    header["dependents"]["summary"] = dependents.summary(judged)
    return out


class IsaCollector:
    """ISA facts step 3: computes isa_facts.row_facts for every row G1 compared (check.decode_rows calls it with
    the verified window and the ballot) and keeps the per-function status (design r3 s2 / s5)."""

    def __init__(self) -> None:
        import isa_tables

        self.tables = isa_tables.load()
        self.functions = {}

    def __call__(self, fid, space, address, window, ballot) -> None:
        import isa_facts

        entry = self.functions.setdefault(fid, {"status": {kind: "checked" for kind in isa_facts.KINDS}, "rows": {}})
        try:
            row = isa_facts.row_facts(
                self.tables, ballot, window,
                redecode=lambda data: decoders.xed_redecode(data, address),
                decode_profile=lambda name, data: decoders.decode_profile(name, data, address),
                decode_without=lambda isa_set, data: decoders.decode_without(isa_set, data, address))
        except Exception as error:          # (one failing row fails the function's status, never the run)
            entry["status"] = {kind: f"failed:{type(error).__name__}: {error}"[:200] for kind in isa_facts.KINDS}
            return
        entry["rows"][(space, address)] = row

    def block(self, facts: dict | None = None, states: dict | None = None) -> dict:
        """The evidence-2 ISA block. With the G1 facts / states, ``checked`` is verified (review r1 P2-1): the rows
        G1 compared (not '*') must be exactly the rows this collector processed, else failed:row-set-mismatch."""
        import isa_facts

        if facts is not None and states is not None:
            for function in facts["functions"]:
                fid = function["function_id"]
                compared = {(row["space"], row["address"]) for row in function["rows"]
                            if "*" not in states.get((fid, row["space"], row["address"]), {"*": "unobserved"})}
                entry = self.functions.get(fid)
                processed = set(entry["rows"]) if entry else set()
                if compared != processed and (entry is None or all(v == "checked" for v in entry["status"].values())):
                    self.functions[fid] = {"status": {kind: "failed:row-set-mismatch" for kind in isa_facts.KINDS},
                                           "rows": {}}
        return {"header": isa_facts.header_block(self.tables, decoders.profile_catalogue()),
                "functions": self.functions}


class _UnitsView:
    """Read-only mapping (id, observation) -> unit dicts, expanded on access from the interned sets."""

    def __init__(self, owner):
        self._owner = owner

    def __getitem__(self, k):
        import common_facts as cf

        return [cf.from_unit(x) for x in self._owner.unit_sets[self._owner.row_set[k]]]

    def __iter__(self):
        return iter(self._owner.row_set)

    def __len__(self):
        return len(self._owner.row_set)

    def __contains__(self, k):
        return k in self._owner.row_set

    def __setitem__(self, k, units):
        """(tests) replace one row's units: interned like finish does; verdict_block5 renumbers canonically"""
        import common_facts as cf

        key = tuple(cf.to_unit(u) for u in units)
        sets = self._owner.unit_sets
        self._owner.row_set[k] = sets.index(key) if key in sets else len(sets)
        if self._owner.row_set[k] == len(sets):
            sets.append(key)

    def keys(self):
        return self._owner.row_set.keys()

    def values(self):
        return (self[k] for k in self._owner.row_set)

    def items(self):
        return ((k, self[k]) for k in self._owner.row_set)


class CommonFactsCollector:
    """design_tbr_g2a_cost r1 C1 / C3: per row only vote summaries are kept (the ballots go to the other hooks and
    the G1 report as before); finish interns each row's units into ordered unit sets numbered by first use in
    (id, observation) order. TDO_V2_G2A_COST_CROSSCHECK=1 also keeps the ballots and checks every row against the
    frozen 798b903 verdict functions (_g2a_reference)."""

    def __init__(self, facts, isa_collector=None):
        import os

        self.facts = facts
        self.isa_collector = isa_collector
        self.rows = {}
        self.raw = {}
        self.summaries = {}
        import common_facts as cf

        self._empty3 = (cf.EMPTY,) * 3
        self.crosscheck = os.environ.get("TDO_V2_G2A_COST_CROSSCHECK") == "1"
        self.checked = {}
        self.unit_sets = []          # set id -> tuple of unit values
        self.row_set = {}            # (id, observation) -> set id
        self.units = _UnitsView(self)
        self.crosschecked = 0
        self.lengths = {}
        self.groups = {}
        self.branch_self = 0

    def __call__(self, fid, facts, result, lift, ballot, window=None):
        import common_facts as cf

        k = cf.identity(facts, fid)
        if k in self.rows:
            raise ValueError(f"duplicate common row {k}")
        w = (result or {}).get("window", {})
        data = (window or b"")[:w.get("verified", 0)]
        # Bytes covered by a relocation do not establish an encoded displacement or a prefix.
        stop = min((max(0, a) for a, n, _ in w.get("relocations", ()) if a + n > 0), default=len(data))
        data = data[:stop]
        self.raw[k] = facts
        self.rows[k] = cf.derive_row(facts, lift, fid, self.facts["registers"], data,
                                     cf.split_needed(ballot, result))
        self.branch_self += int(lift is not None and lift.pattern == "branch-self")
        # Retain only the comparison inputs: per vendor view a vote summary (r1 C1); the ballots themselves are
        # not kept. Non-x86 rows and rows without accepted votes share the EMPTY summary (r2 D2).
        accepted = {v: cf.votes(ballot, result, v) for v in (None, *cf.VENDORS)}
        for v, vs in accepted.items():
            self.lengths[k, v] = cf.independent_length(vs)
        x86 = facts.get("isa") == "x86-64"

        def summarize(vendor):
            if not x86:
                return cf.EMPTY
            try:
                return cf.summarize_votes(accepted[vendor], facts["address"])
            except Exception as error:      # (crosscheck: carried to finish and compared with the reference)
                if self.crosscheck:
                    return error
                raise

        summary = tuple(summarize(v) for v in (None, *cf.VENDORS))
        self.summaries[k] = self._empty3 if summary == self._empty3 else summary
        if self.crosscheck:
            self.checked[k] = accepted
        n = facts["length"]
        if type(n) is int and 0 < n <= len(data):
            group = facts.get("isa"), facts["space"], facts["address"], facts.get("view", "0"), data[:n]
            self.groups.setdefault(group, []).append(k)

    def finish(self, complete):
        import common_facts as cf

        cf.finish_landings(list(self.rows.values()), complete)
        views = (None, *cf.VENDORS)
        index = {v: cf.Index(((f["space"], f["address"], self.lengths[k, v], k) for k, f in self.raw.items()),
                             complete) for v in views}
        numbered = {}
        for k in sorted(self.rows):                  # == the facts document's (id, observation) order
            r, f = self.rows[k], self.raw[k]
            info = {}
            if self.isa_collector:
                fn = self.isa_collector.functions.get(k[1], {})
                source = fn.get("rows", {}).get((f["space"], f["address"]), {})
                status = fn.get("status", {})
                info = dict(facts={name: val for name, val in source.get("facts", {}).items()
                                   if status.get(name) == "checked"},
                            unobserved=source.get("unobserved", {}))
            units = []                               # base, then intel, then amd (the 798b903 order)
            for j, v in enumerate(views):
                summary = self.summaries[k][j]
                if v and not r["vendor_views"]:
                    if isinstance(summary, Exception):
                        raise AssertionError(f"crosscheck {k} {v}: summary={summary!r}, reference view absent") \
                            from summary
                    continue
                if self.crosscheck:
                    part = self._crosscheck(k, r, f, v, index[v], info, summary)
                else:
                    part = cf.row_verdicts(r, summary, index[v], info, v)
                units.extend(part)
            key = tuple(cf.to_unit(u) for u in units)    # values only after row_verdicts returned (r1 C2)
            sid = numbered.get(key)
            if sid is None:
                sid = numbered[key] = len(self.unit_sets)
                self.unit_sets.append(key)
            self.row_set[k] = sid
        self.summaries.clear()
        self.checked.clear()

    def _crosscheck(self, k, r, f, vendor, index, info, summary):
        """Both paths run; the same exception on both is the original failure, any other mismatch is reported
        with its row and view (Astra impl r1 item 3)."""
        import common_facts as cf
        import _g2a_reference as ref

        def outcome(call):
            try:
                return call(), None
            except Exception as error:
                return None, error

        def new_units():
            if isinstance(summary, Exception):
                raise summary
            return cf.row_verdicts(r, summary, index, info, vendor)

        votes = self.checked[k][vendor] if f.get("isa") == "x86-64" else []
        got, new_error = outcome(new_units)
        want, old_error = outcome(lambda: ref.row_verdicts(r, votes, index, info, vendor))
        if new_error is not None or old_error is not None:
            if (new_error is not None and old_error is not None
                    and type(new_error) is type(old_error) and new_error.args == old_error.args):
                raise new_error
            raise AssertionError(f"crosscheck {k} {vendor}: summary={new_error!r}, reference={old_error!r}")
        if got != want:
            raise AssertionError(f"crosscheck {k} {vendor}: units differ")
        self.crosschecked += 1
        return got

    def denominators(self):
        import common_facts as cf

        return cf.denominators_of_sets(self.unit_sets, self.row_set)

    def row_states(self):
        from collections import Counter

        import common_facts as cf

        states = [cf.row_state(s) for s in self.unit_sets]
        return dict(Counter(states[sid] for sid in self.row_set.values()))


def _chain(*hooks):
    hooks = [hook for hook in hooks if hook is not None]
    if not hooks:
        return None

    def call(*args):
        for hook in hooks:
            hook(*args)
    return call


class OverrideCollector:
    """design_tbr_g1_x1 r1-r3: one verdict code per compared profile row (producer_override.row_verdict) and the
    star details; ``block`` verifies the coded rows against the rows G1 compared (failed:row-set-mismatch)."""

    def __init__(self, declared) -> None:
        self.declared = declared            # the manifest's producer_profile (None: a legacy Bundle)
        self.functions = {}

    def __call__(self, fid, facts, result, lift, ballot, window=None) -> None:
        import producer_override

        entry = self.functions.setdefault(fid, {"codes": {}, "details": {}, "rows": {}, "error": None})
        where = (facts["space"], facts["address"])
        try:
            verdict = producer_override.row_verdict(facts, result, lift, ballot, window)
            entry["rows"][where] = producer_override.g3b7b_row(facts, ballot, window, lift)
        except Exception as error:          # (one failing row fails the function's status, never the run)
            entry["error"] = f"failed:{type(error).__name__}: {error}"[:200]
            return
        if verdict is None:
            return
        code, detail = verdict
        if code is not None:
            entry["codes"][where] = code
        if detail is not None:
            entry["details"][where] = detail

    def block(self, facts: dict, states: dict, engine_source: dict) -> dict:
        import producer_override

        functions = {}
        for function in facts["functions"]:
            fid = function["function_id"]
            entry = self.functions.get(fid, {"codes": {}, "details": {}, "rows": {}, "error": None})
            never = {(row["space"], row["address"]) for row in function["rows"]
                     if "*" in states.get((fid, row["space"], row["address"]), {"*": "unobserved"})}
            compared = sorted((row["space"], row["address"]) for row in function["rows"]
                              if (row["space"], row["address"]) not in never)
            # (impl r1 Astra P2-2) the star details and the C / U / O details expected from the rows themselves
            star = {(row["space"], row["address"]) for row in function["rows"]
                    if (row["space"], row["address"]) in never and row.get("override") is not None
                    and producer_override.present(row["override"])}
            needing = {where for where, code in entry["codes"].items() if code in producer_override.DETAIL_CODES}
            out = {"status": "checked", "codes": {}, "details": {}, "rows": {}}
            profile = function.get("producer_profile")
            if profile is None:
                out["status"] = "failed:parser-without-profile" if self.declared is not None else "not_reported"
            elif profile != self.declared:
                out["status"] = "failed:profile-mismatch"
            elif any(row.get(name) is None for row in function["rows"]
                     for name in ("override", "external_flow_targets", "recorded_landing_pads")):
                # (impl r2 Astra P2-2: the X-1 contract's three row fields come together; [] is a recorded empty
                #  pad list, None a missing field)
                out["status"] = "failed:missing-row-fields"
            elif entry["error"]:
                out["status"] = entry["error"]
            elif sorted(entry["codes"]) != compared or set(entry["details"]) != needing | star \
                    or {w for w, d in entry["details"].items() if d.get("star")} != star:
                out["status"] = "failed:row-set-mismatch"
            else:
                out["codes"], out["details"] = dict(entry["codes"]), dict(entry["details"])
                out["rows"] = dict(entry["rows"])
            functions[fid] = out
        return {"header": producer_override.header_block(self.declared, engine_source), "functions": functions}


def engine_source() -> dict:
    """The TDO tree G1 imported for admission and parsing (design_tbr_g1_x1 r1 s5 / s7): the digest of the imported
    ``tdo_v2`` package and its git revision when known -- not wt_lint/src unless that is what was imported."""
    import hashlib
    import subprocess

    import tdo_v2

    package = Path(tdo_v2.__file__).resolve().parent
    files = sorted(package.rglob("*.py"))
    digest = hashlib.sha256("".join(
        f"{path.relative_to(package.parent).as_posix()}\0{hashlib.sha256(path.read_bytes()).hexdigest()}\n"
        for path in files).encode("utf-8")).hexdigest()
    try:
        # (impl r1 Astra P2-4: a revision only when that repository tracks the imported package itself -- an
        #  archive unpacked under another repository would otherwise report the outer HEAD)
        tracked = subprocess.run(["git", "-C", str(package), "ls-files", "--error-unmatch", "__init__.py"],
                                 capture_output=True, text=True, timeout=30).returncode == 0
        revision = subprocess.run(["git", "-C", str(package), "rev-parse", "HEAD"], capture_output=True, text=True,
                                  timeout=30).stdout.strip() or None if tracked else None
        dirty = bool(subprocess.run(["git", "-C", str(package), "status", "--porcelain", "--", "."],
                                    capture_output=True, text=True, timeout=60).stdout.strip()) if tracked else None
    except (OSError, subprocess.SubprocessError):
        revision, dirty = None, None
    if revision is None:
        dirty = None                        # (git did not answer: neither the revision nor its state is known)
    return {"package": "tdo_v2", "digest": digest, "revision": revision, "dirty": dirty}


def write_evidence(path: Path, generation: Path, naming_source: Path, manifest: dict, original: bytes, mapping,
                   facts: dict, states: dict, use_table: bool, reason, isa: dict | None = None,
                   override: dict | None = None, engine: dict | None = None, common: dict | None = None) -> None:
    """``g1-decode-evidence-1`` (design .census6/design_g1_engine_evidence_r3.md, s2 / s3 / s7); with ``isa``
    ``g1-decode-evidence-2`` (design .census6/design_tbr_isa_facts_r3.md s5)."""
    import hashlib

    seal = json.loads((generation / "seal.json").read_bytes())
    members = {row["id"]: row for row in manifest["members"]}
    observation = {row["id"]: members[row["observation_member"]]["sha256"] for row in manifest["functions"]}
    # (design_tbr_g1_x1 r1 s5: the engine G1 actually imported, not wt_lint/src)
    engine_digest = (engine or engine_source())["digest"]      # (computed once per run, impl r1 P2-4)
    document = evidence.build(
        bundle={"generation_id": seal["generation_id"], "manifest_sha256": seal["manifest_sha256"],
                "original_sha256": hashlib.sha256(original).hexdigest()},
        producer={"decode_check_revision": REVISION, "tool_digest": evidence.tool_digest(_HERE.parents[1]),
                  "decoders": decoders.manifest(),
                  "voters": {"intel": list(decoders.INTEL_VOTERS), "amd": list(decoders.AMD_VOTERS)},
                  "rules": mapping.rules, "lift_table": lifting.TABLE["id"],
                  "diagnosis_engine": {"source_digest": engine_digest},
                  "naming_source_sha256": hashlib.sha256(naming_source.read_bytes()).hexdigest()},
        mapping={"format": mapping.format, "mapping_id": mapping.mapping_id},
        premises=["decoder-matches-cpu"] + ([lifting.TRANSLATION_PREMISE] if use_table else []),
        table_applied=use_table, global_reason=reason,
        functions=[{"function_id": function["function_id"], "observation_sha256": observation[function["function_id"]],
                    "rows": [(row["space"], row["address"]) for row in function["rows"]],
                    "states": {(row["space"], row["address"]): states.get((function["function_id"], row["space"],
                                                                           row["address"]), {"*": "unobserved"})
                               for row in function["rows"]}}
                   for function in facts["functions"]],
        isa=isa, override=override, common=common)
    path.write_bytes(evidence.dumps(document))


def _summarize_rows(facts: dict, common, document: dict) -> dict:
    from collections import Counter

    import common_facts as cf

    records, inputs, errors = [], [], []
    source_rows = source_ops = 0
    for fn in facts["functions"]:
        for f in fn["rows"]:
            count = sum(op["opcode"] in cf.CALLS for op in f["ops"])
            source_rows += bool(count)
            source_ops += count
        records.extend(cf.parity(fn, common.rows, facts["registers"], common.lengths))
        inputs.extend(cf.input_checks(fn, common.rows))
        for field in ("engine_error", "tail_error"):
            if fn.get(field):
                errors.append(dict(observation=fn["function_id"], check=field, reason=fn[field]))
    base = [item for item in records if item.get("vendor") is None and "op" in item]
    counts = Counter(item["status"] for item in base)
    vendor_counts = {v: sum(bool(r["vendor_views"]) for r in document["rows"]) for v in cf.VENDORS}

    # (fixture results come from the test suite (test_g2a_required_*), never from an analysis run: a run
    #  that executes the test suite would be slow and environment-dependent)
    fixtures = {"source": "tests/intra/test_decode_check.py",
                "required": ["test_g2a_required_vendor", "test_g2a_required_xbegin",
                             "test_g2a_required_push_parity", "test_g2a_required_blr_x30",
                             "test_g2a_required_binding", "test_g2a_required_values_and_index",
                             "test_g2a_required_conditions_and_traps"]}

    return {"schema": cf.SCHEMA, "rule": cf.VERDICT_RULE, "rows": len(document["rows"]),
            "unit": "(id, observation), field path, edge triple when applicable, op reference when applicable",
            "fields": common.denominators(),
            "row_states": common.row_states(),
            "vendor_rows": vendor_counts, "ambiguous_hlt_or_self_jump": common.branch_self,
            "parity": {"source_rows": source_rows, "source_ops": source_ops, "base_joins": len(base),
                       "base_status": dict(counts), "base_outside_engine_relation": counts["neither"] + counts["extra"],
                       "reasons": dict(Counter(x["reason"] for x in records if x.get("reason"))),
                       "records": records, "errors": errors, "return_and_tail_inputs": inputs,
                       "different_lifts": cf.different_lifts(common.groups, common.rows, common.raw,
                                                             facts["registers"])},
            "fixtures": fixtures}


def common_summary(facts, common, document, *, complete, missing_functions):
    from collections import Counter
    import common_facts as cf

    report = _summarize_rows(facts, common, document)
    parity = report["parity"]
    base = [x for x in parity["records"] if x.get("vendor") is None]
    actual = Counter((cf.rr(x["row"]), x["call_key"]) for x in base if "op" in x)
    expected = Counter(
        (cf.identity(f, fn["function_id"]), cf.opkey(f, i))
        for fn in facts["functions"] for f in fn["rows"]
        for i, op in enumerate(f["ops"]) if op["opcode"] in cf.CALLS
    )
    if actual != expected or any(n != 1 for n in actual.values()):
        raise ValueError("source row and call op join multiplicity")
    parity.update(
        complete=complete,
        missing_functions=sorted(missing_functions),
        base_status=dict(Counter(x["status"] for x in base)),
        reasons=dict(Counter(x["reason"] for x in base if x.get("reason"))),
    )
    return report


def run(generation: Path, naming_source: Path, premise: bool, full: bool = False,
        evidence_out: Path | None = None, isa_facts: bool = False,
        producer_override: bool = False, common_facts_out: Path | None = None) -> tuple[dict, list]:
    want_common = common_facts_out is not None
    facts = collect(generation, naming_source, common_facts=True) if want_common else collect(generation, naming_source)
    manifest = json.loads((generation / "manifest.json").read_bytes())
    original_path = next(r["path"] for r in manifest["members"] if r["id"] == manifest["original_member_id"])
    original = (generation / original_path).read_bytes()
    mapping = check.parse_original(original)
    header = {"tool": "decode_check", "revision": REVISION, "generation": generation.name,
              "premises": ["decoder-matches-cpu"] + ([lifting.TRANSLATION_PREMISE] if premise else []),
              "lift_table": {k: v for k, v in lifting.TABLE.items() if k not in ("allowed_prefix", "no_flow_userops")} | {
                  "allowed_prefix": sorted(lifting.TABLE["allowed_prefix"]),
                  "no_flow_userops_count": len(lifting.TABLE["no_flow_userops"])},
              "decoders": decoders.manifest(), "voters": {"intel": list(decoders.INTEL_VOTERS),
                                                          "amd": list(decoders.AMD_VOTERS)},
              "scope": SCOPE, "PYTHONHASHSEED": "0", "layers": {"g1": list(G1_LAYERS), "derived": ["dependents"],
                                                               "reserved": RESERVED_LAYERS}}
    if not facts["admission"].get("ok"):
        return header, [Row("mapping", "original", "bundle", "unobserved", None, "lint",
                            {"reason": "the Bundle is not admitted", "admission": facts["admission"]})]
    base = facts["image_base"]
    if base is None:
        return header, [Row("mapping", "original", "bundle", "unobserved", None, "lint",
                            {"reason": "the program scope is not constructed"})]
    image = check.Image(generation, mapping, base, original)
    rows = check.mapping_rows(image)
    reason = check.global_reason(mapping, base, facts["language"] or "")
    identity = lifting.table_identity(facts["language"] or "", *(facts.get("language_version") or (None, None)))
    use_table = premise and identity["state"] != "mismatch"
    unverified = None
    if premise and not use_table:
        unverified = f"translation identity mismatch ({identity['checks']['language']}): the table does not apply"
    elif not premise:
        unverified = f"translation-unverified (no compiled-SLEIGH digest in the Bundle; premise {lifting.TRANSLATION_PREMISE} off)"
    header["translation_identity"] = {**identity, "premise": premise, "table_applied": use_table}
    states = {}
    producer_override = producer_override or want_common
    collector = IsaCollector() if want_common or (isa_facts or producer_override) and evidence_out is not None else None
    verdicts = OverrideCollector(manifest.get("producer_profile")) if producer_override else None
    common = CommonFactsCollector(facts, collector) if want_common else None
    rows.extend(check.decode_rows(image, facts["functions"], use_table, reason, full, states, facts["language"] or "",
                                  unverified, isa=collector, override=_chain(verdicts, common)))
    isa_block = collector.block(facts, states) if collector else None
    common_block = None
    if common is not None:
        import common_facts as cf

        seen = {fn["function_id"] for fn in facts["functions"]}
        complete = facts["complete"] and seen == {m["id"] for m in manifest["functions"]}
        common.finish(complete)
        if common.crosscheck:
            print(f"decode_check: crosscheck passed for {common.crosschecked} row views", file=sys.stderr)
        seal = json.loads((generation / "seal.json").read_bytes())
        doc = cf.document(
            {k: seal[k] for k in ("generation_id", "manifest_sha256")},
            dict(name="tbr-derive-ghidra-p-code", lift_table=lifting.TABLE["id"], rule=cf.FACTS_RULE),
            dict(isa=facts["isa"] or cf.U("unsupported language"), address_spaces=facts["address_spaces"],
                 stack_register=facts["registers"]["sp"] or cf.U("no validated stack register"),
                 code=cf.U("code surveys belong to G2b"), tbi=cf.U("no TBI evidence")),
            common.rows.values())
        # (r1 C4: the facts file is streamed, byte-identical to canonical(doc) + LF; its digest excludes the LF)
        common_block = cf.verdict_block5(doc, cf.write_canonical(common_facts_out, doc), common.unit_sets,
                                         common.row_set)
        header["common_facts"] = common_summary(
            facts, common, doc, complete=complete,
            missing_functions={m["id"] for m in manifest["functions"]} - seen,
        )
    override_block = None
    engine = engine_source() if evidence_out is not None or verdicts is not None else None
    if verdicts is not None:
        override_block = verdicts.block(facts, states, engine)
        for function in facts["functions"]:
            function["override"] = override_block["functions"][function["function_id"]]
    rows.extend(check.suspect_rows(rows))
    rows.extend(dependents_rows(facts["functions"], states, reason, full, header))
    header["mapping"] = {"format": mapping.format, "rules": mapping.rules, "mapping_id": mapping.mapping_id,
                         "load_bias": base - mapping.image_base}
    header["mapping_id"] = mapping.mapping_id
    header["global_reason"] = reason
    header["guard"] = {"revision": guards.REVISION, "fired_at_production": guards.FIRED_AT_PRODUCTION,
                       "format": mapping.format,
                       "machine": mapping.header_fields.get("machine", mapping.header_fields.get("e_machine")),
                       "language": facts["language"], "language_agrees": (facts["language"] or "") == check.LANGUAGE}
    header["counts"] = g1_counts(rows)
    if evidence_out is not None:
        write_evidence(evidence_out, generation, naming_source, manifest, original, mapping, facts, states, use_table,
                       reason, isa_block, override_block, engine, common_block)
        header["evidence_out"] = str(evidence_out)
    return header, rows


def g1_counts(rows: list) -> dict:
    """G1's own counts: layers ``mapping`` and ``decode`` only. ``dependents`` is
    derived from them, and ``semantics`` (reserved, TBR) is never counted here."""
    out = {}
    for row in rows:
        if row.layer not in G1_LAYERS:
            continue
        name = f"{row.layer}/{row.check}"
        state = row.verdict if row.run_state == "evaluated" else row.run_state
        out.setdefault(name, {})
        out[name][state] = out[name].get(state, 0) + 1
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("generation", type=Path)
    parser.add_argument("--out", type=Path, default=Path("decode_check_report.json"))
    parser.add_argument("--naming-source", type=Path,
                        default=_HERE.parents[1] / "ghidra" / "GhidraV2CallNaming.java")
    parser.add_argument("--assume-stock-ghidra-translator", action="store_true",
                        help="named premise: the Bundle's p-code comes from the stock Ghidra 12.0.4 translator")
    parser.add_argument("--full", action="store_true", help="keep every attribute and vote of applied rows too")
    parser.add_argument("--isa-facts", action="store_true",
                        help="write g1-decode-evidence-2: the evidence file plus the per-row ISA facts")
    parser.add_argument("--producer-override", action="store_true",
                        help="write g1-decode-evidence-3: -2 plus the per-row producer-override verdicts (X-1)")
    parser.add_argument("--common-facts", type=Path, default=None,
                        help="G2a: write the derived tbr-common-facts-1 file here (evidence becomes -5 with --evidence-out)")
    parser.add_argument("--evidence-out", type=Path, default=None,
                        help="also write the engine evidence file g1-decode-evidence-1 (outside the Bundle)")
    args = parser.parse_args(argv)
    if not args.generation.is_dir() or not args.naming_source.is_file():
        print("decode_check: the generation directory and the naming source must exist", file=sys.stderr)
        return 2
    header, rows = run(args.generation, args.naming_source, args.assume_stock_ghidra_translator, args.full,
                       args.evidence_out, args.isa_facts, args.producer_override, args.common_facts)
    args.out.write_text(dumps(header, rows), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
