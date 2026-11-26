"""G1 dependents and loss table (design r1 s6, r2 s6, r3 s6, r4 s6): which engine
facts read which compared attribute, and what an L2 gate (an engine that keeps a
fact only when the decoders confirm what it reads) would block.

Pure functions over plain data (Rust-port surface): the baseline facts per
function come from G0's operation rows (reduced in decode_check.collect), the
attribute states from compare.compare_row (reduced by ``attribute_states``).

Per (consumer, unit):
- ``confirmed``   every attribute the consumer reads is applied / not applicable;
- ``would_block`` some read attribute is a disagreement (withheld / unrecognized)
                  or unobserved -- an L2 gate cannot confirm it (``cause``);
- ``loss``        1 when it would block and the baseline fact exists, 0 when the
                  fact is already absent, "unknown" for an estimate consumer
                  without a baseline in this engine (r4 s6). Counted once per
                  function and consumer for function-level consumers. The
                  summary splits it by cause: ``loss_disagreement`` (a decoder
                  disagreement) apart from ``loss_unobserved`` (not observed).

RP and pass-through stay undetermined: they need the PC the unwinder restores at
each fault point, which a Bundle does not carry (r3 s6, r4 s6) -- header only.
"""

from __future__ import annotations

OK = ("applied", "not_applicable")

# consumer -> (unit, attributes read, status, design reference). Attribute names as in compare.compare_row.
# (every fact reads A1 of each row it reads: on an all-invalid row the other attributes are not applicable,
#  which would otherwise read as confirmed -- Fable evidence r2 P1-1)
CALL_READS = ("a1", "a2", "a3", "a4", "a6", "a8", "F.is_call")
EXIT_READS = ("a1", "a4")
CONSUMERS = {
    "s1": ("function", "native-call rows: " + ", ".join(CALL_READS) + "; S1 exit rows: a1, a4 (exit target = A4)",
           "baseline", "r2 s6 S1 current contract"),
    "s1_l2_estimate": ("function", "the s1 reads + every row: a1, a2, a3, a4, a5, a6, a8, F.is_call; call "
                       "candidates (either side; any row where A7 was compared): a7", "estimate",
                       "r2 s6 adopted L2 acceptance, r3 s6"),
    "push_projection": ("call", "a1, F.is_call, a3, a4, a11b, a7", "baseline", "r2 s6, r4 s6"),
    "push_relation": ("call", "the push_projection reads (relations iterate surviving projections), a4",
                      "baseline", "r2 s6, r4 s6"),
    "plain_push": ("call", "a1, a4, a6, a7 (pattern plain near call, linked to the listing continuation)", "baseline",
                   "r2 s6"),
    "call_seed": ("call", "a1, a4, a5, a6, a8 (the seed's listing continuation)", "baseline", "r2 s6 call seeds / naming"),
    "return_shape": ("return", "a1, a11b (a9 reported apart)", "baseline", "r2 s6"),
    "unknown_transfer_site": ("branchind", "a8, a5: the engine's existing U2a unknown-site fact (baseline: "
                              "unknown_transfer true); its loss counts that fact's inputs not confirmed -- not a "
                              "precision loss (UNKNOWN is already the most conservative state); state-barrier "
                              "completeness needs fault cuts, not exported", "baseline", "r3 s6"),
    "resolved_transfer_site": ("branchind", "a8, a5: BRANCHIND with non-empty flow_targets (baseline "
                               "unknown_transfer=False; control_context.unknown_transfer_sites checks "
                               "not row.flow_targets) -- the fact an L2 gate can remove at a BRANCHIND",
                               "baseline", "Fable impl r2 P2-1, Astra impl r4 s6"),
    "g3b7b_none_estimate": ("function", "every row: a1, a2, a3, a4, a5, a8; a BRANCHIND row blocks (the exporter "
                            "refuses it); an observed disagreement blocks; otherwise unobserved: getParsedLength / "
                            "prototype flow not exported -- unconfirmable by definition here, a scope marker, "
                            "not a measurement", "estimate", "r3 s6 (not in this branch's engine: loss unknown)"),
}
READS = {
    "push_projection": ("a1", "F.is_call", "a3", "a4", "a11b", "a7"),
    "push_relation": ("a1", "F.is_call", "a3", "a4", "a11b", "a7"),
    "plain_push": ("a1", "a4", "a6", "a7"),
    "call_seed": ("a1", "a4", "a5", "a6", "a8"),
    "return_shape": ("a1", "a11b"),
    "unknown_transfer_site": ("a1", "a8", "a5"),
    "resolved_transfer_site": ("a1", "a8", "a5"),
}
G3B7B_READS = ("a1", "a2", "a3", "a4", "a5", "a8")
L2_EXTRA = ("a1", "a2", "a3", "a4", "a5", "a6", "a8", "F.is_call")
G3B7B_MISSING = "producer inputs not exported: getParsedLength, prototype flow (r3 s6)"
# (design_tbr_g1_x1 r2 s6) with the X-1 verdicts getParsedLength and the prototype flow are covered per row; the
# exporter's entry-reference refusal reads ordinary flow references G1 cannot see
G3B7B_X1_MISSING = "producer input not exported: ordinary flow references to the entry (entry-reference refusal)"
OVERRIDE = "override"
UNDETERMINED = {"rp": "needs the PC the unwinder restores at each fault point (not in a Bundle)",
                "pass_through": "needs the PC the unwinder restores at each fault point (not in a Bundle)"}
EXAMPLES = 5


def attribute_states(result: dict | None) -> dict:
    """{name: state} of the non-confirmed attributes of one compared row, plus ``+``: the
    names it confirmed. A row never compared (no result, or an early return such as
    unverified bytes / a relocation over the encoding: no attributes) is ``*``:
    every read unobserved."""
    if result is None or not result.get("attributes"):
        return {"*": "unobserved"}
    out = {name: item["state"] for name, item in result["attributes"].items() if item["state"] not in OK}
    out["+"] = frozenset(name for name, item in result["attributes"].items() if item["state"] in OK)
    # (``~``: the kinds of the non-confirmed attributes, for the evidence file's ``state:kind``)
    out["~"] = {name: item["kind"] for name, item in result["attributes"].items()
                if item["state"] not in OK and "kind" in item}
    return out


def _status(states: dict, name: str) -> str:
    """A read the row did not compare (absent from both sets) is unobserved, never confirmed."""
    if name in states:
        return states[name]
    if "*" in states:
        return states["*"]
    return "applied" if name in states.get("+", ()) else "unobserved"


def _where(address) -> str:
    """``(space, offset)`` -> ``space:offset`` (hex); a bare offset (pure tests) -> hex."""
    if isinstance(address, tuple):
        return f"{address[0]:x}:{address[1]:x}"
    return f"{address:x}"


def _judge(reads, baseline_present, extra=None):
    """reads: [(address, attribute, state)] -> (run state, verdict, detail). ``extra``: one or a list of
    (address, reason, state) the reads cannot show (a BRANCHIND row, a missing producer input, a reported producer
    override). Precedence (design_tbr_g1_x1 r2 s6): refused, disagreement, override, unobserved."""
    blocking = [(address, name, state) for address, name, state in reads if state not in OK]
    if extra is not None:
        blocking.extend(extra if isinstance(extra, list) else [extra])
    refused = [item for item in blocking if item[2] == "refused"]
    disagreement = [item for item in blocking if item[2] in ("withheld", "unrecognized")]
    overridden = [item for item in blocking if item[2] == OVERRIDE]
    if not blocking:
        return "evaluated", "applied", {"would_block": False, "baseline": baseline_present}
    cause = "refused" if refused else "disagreement" if disagreement else OVERRIDE if overridden else "unobserved"
    if baseline_present is None:
        loss = "unknown"
    else:
        loss = 1 if baseline_present else 0
    detail = {"would_block": True, "cause": cause, "baseline": baseline_present, "loss": loss,
              "blocking": [[_where(address), name, state] for address, name, state in
                           (refused or disagreement or overridden or blocking)[:EXAMPLES]],
              "blocking_count": len(blocking)}
    if refused:   # (the report contract keeps verdict "refused" for the engine: a lint row withholds)
        return "evaluated", "withheld", detail
    if disagreement or overridden:
        return "evaluated", "withheld", detail
    return "unobserved", None, detail


def function_rows(function: dict, states: dict) -> list[tuple]:
    """(consumer, unit key, run state, verdict, detail) of one function.

    function: {"function_id", "s1", "rows": [facts], "baseline": {"calls", "exits", "branchind", "returns"}}
    states:   {address: attribute_states(...)} of this function's rows."""
    fid = function["function_id"]
    baseline = function.get("baseline") or {}
    addresses = [(facts.get("space"), facts["address"]) if "space" in facts else facts["address"]
                 for facts in function["rows"]]
    native = [(facts.get("space"), facts["address"]) if "space" in facts else facts["address"]
              for facts in function["rows"] if facts.get("native_call")]
    exits = sorted({item["source"] for item in baseline.get("exits", ())})
    out = []

    def reads_of(address_list, names):
        return [(address, name, _status(states.get(address, {"*": "unobserved"}), name))
                for address in address_list for name in names]

    s1_reads = reads_of(native, CALL_READS) + reads_of(exits, EXIT_READS)
    out.append(("s1", fid, *_judge(s1_reads, bool(function["s1"]))))
    def compared_a7(address):
        row = states.get(address, {})
        return "a7" in row or "a7" in row.get("+", ())

    candidates = [address for address in addresses
                  if address in native or _status(states.get(address, {"*": "unobserved"}), "a6") != "applied"
                  or compared_a7(address)]
    out.append(("s1_l2_estimate", fid, *_judge(s1_reads + reads_of(addresses, L2_EXTRA)
                                               + reads_of(candidates, ("a7",)), bool(function["s1"]))))
    branchind = baseline.get("branchind", ())
    override = function.get("override")
    if branchind:
        extra = (branchind[0]["address"], "BRANCHIND (the exporter refuses the function)", "refused")
    elif override is not None and override["status"] == "checked":
        extra = _override_extras(function, override, addresses)
    else:
        extra = (addresses[0] if addresses else 0, G3B7B_MISSING, "unobserved")
    x1 = not branchind and override is not None and override["status"] == "checked"
    # (impl r1: the X-1 path also reads F.has_fallthrough -- the prototype hasFallthrough input -- and rests on the
    #  producer's raw claims, so its result names the premise)
    g3b7b = _judge(reads_of(addresses, G3B7B_READS + (("F.has_fallthrough",) if x1 else ())), None, extra)
    g3b7b[2]["branchind_rows"] = len(branchind)
    if x1:
        g3b7b[2]["premises"] = ["producer-override-report"]
    out.append(("g3b7b_none_estimate", fid, *g3b7b))
    for call in baseline.get("calls", ()):
        key = f"{fid}/{call['op']}"
        facts = call.get("facts", {})
        projection = _judge(reads_of([call["address"]], READS["push_projection"]),
                            facts.get("push_projection") == "applied")
        out.append(("push_projection", key, *projection))
        relation = _judge(reads_of([call["address"]], READS["push_relation"]), facts.get("push_relation") == "applied")
        out.append(("push_relation", key, *relation))
        if facts.get("plain_push") not in (None, "not_applicable"):
            out.append(("plain_push", key, *_judge(reads_of([call["address"]], READS["plain_push"]),
                                                   facts.get("plain_push") == "applied")))
        seed = _judge(reads_of([call["address"]], READS["call_seed"]), True)
        seed[2]["naming"] = facts.get("naming")
        out.append(("call_seed", key, *seed))
    for item in baseline.get("returns", ()):
        out.append(("return_shape", f"{fid}/{item['op']}",
                    *_judge(reads_of([item["address"]], READS["return_shape"]), item["return_shape"] == "applied")))
    for item in baseline.get("branchind", ()):
        for consumer, present in (("unknown_transfer_site", bool(item["unknown_transfer"])),
                                  ("resolved_transfer_site", not item["unknown_transfer"])):
            judged = _judge(reads_of([item["address"]], READS[consumer]), present)
            judged[2]["unknown_transfer"] = item["unknown_transfer"]
            out.append((consumer, f"{fid}/{item['site']}", *judged))
    return out


def _override_extras(function: dict, override: dict, addresses: list) -> list:
    """g3b7b inputs from the X-1 row facts and G1's evidence (design_tbr_g1_x1 r1 s6, r2 s6; impl r1 Astra P2-3),
    per row (``override["rows"]``: producer_override.g3b7b_row):
    - a reported length override: the exporter refuses every such row (block, cause override);
    - a prototype-fallthrough row (the voters' consensus form; the pinned shapes by their bits): Ghidra's own
      fallthrough must exist and equal address + parsed length (= the exported length when not length-overridden,
      a raw claim); a reported fallthrough override that misses it is the exporter's refusal (block), one that
      meets it passes; a missing fallthrough without the override is G1's a4 disagreement (the reads); a4 rebuilt
      from an S1 exit, a missing length or an undecided form -> unobserved;
    - a reported flow override on a call row: the exporter's refusal (block);
    - the entry-reference refusal reads ordinary references G1 cannot see: unobserved, on call rows only;
    - reference overrides alone never block here (they matter only through the entry-reference input)."""
    by_where = {(row.get("space"), row["address"]): row for row in function["rows"]}
    out = []
    call_rows = []
    for where, info in sorted(override.get("rows", {}).items()):
        row = by_where.get(where, {})
        kinds = info["kinds"]
        length = row.get("length")
        if info["call_row"]:
            call_rows.append(where)
        if "length" in kinds:
            out.append((where, "producer length override (exporter refusal: every row)", OVERRIDE))
        if info["isa_fallthrough"] is None:
            out.append((where, "prototype fallthrough undecided (the voters' form)", "unobserved"))
        elif info["isa_fallthrough"]:
            fallthrough = row.get("fallthrough")
            if fallthrough is None and row.get("exit"):
                out.append((where, "a4 rebuilt from an S1 exit (getFallThrough not exported)", "unobserved"))
            elif length is None:
                out.append((where, "length not exported (getParsedLength)", "unobserved"))
            elif "fallthrough" in kinds and "length" not in kinds \
                    and (fallthrough is None or fallthrough != row["address"] + length):
                out.append((where, "fallthrough override missing address + parsed length (exporter refusal)",
                            OVERRIDE))
        if info["call_row"] and any(kind.startswith("flow:") for kind in kinds):
            out.append((where, "flow override on a call row (exporter refusal)", OVERRIDE))
    if call_rows:
        out.append((call_rows[0], G3B7B_X1_MISSING, "unobserved"))
    return out


def summary(rows: list[tuple]) -> dict:
    """Per consumer: units, baseline present, confirmed, would_block (by cause), loss."""
    out = {}
    for consumer, _, run_state, verdict, detail in rows:
        item = out.setdefault(consumer, {"units": 0, "baseline_present": 0, "confirmed": 0,
                                         "would_block_disagreement": 0, "would_block_unobserved": 0,
                                         "would_block_refused": 0, "would_block_override": 0,
                                         "loss_disagreement": 0, "loss_unobserved": 0, "loss_refused": 0,
                                         "loss_override": 0, "loss_unknown": 0})
        item["units"] += 1
        if detail.get("baseline"):
            item["baseline_present"] += 1
        if not detail["would_block"]:
            item["confirmed"] += 1
            continue
        item["would_block_" + detail["cause"]] += 1
        if detail["loss"] == "unknown":
            item["loss_unknown"] += 1
        else:
            item["loss_" + detail["cause"]] += detail["loss"]
    return out
