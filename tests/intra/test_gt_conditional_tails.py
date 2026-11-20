"""(G-T G3a, docs 25.103) Conditional tail jumps composed on their edge block.

``jcc other_function`` whose fallthrough stays local: the target's summary is
composed on the taken outcome's edge block ``E`` only -- the staged rows and a
``site~edge`` crossing row sit in ``E``, the raw CBRANCH in ``S`` stays a plain
branch, the summary gets an exit state at ``E`` (no tail exit) and its register
deltas run through ``E``. A target that never returns makes ``E`` a dead edge
(the fallthrough stays live); a sink-only or refused effect leaves ``E`` an
unknown exit.
"""

from synthetic import (
    CODE_BASE, R9, RAX, RCX, RDI, RSI, RSP, ZF, FunctionBuilder, add, const, copy, program_units, ram, reg,
)
from tdo_v2.interprocedural import _direct_calls, analyze_units, function_key_of

CALLER, MIDDLE, TARGET = CODE_BASE, CODE_BASE + 0x600, CODE_BASE + 0x800


def _to(builder, index, target):
    """Rewrite the CBRANCH of instruction ``index`` (None: the first CBRANCH)
    to jump to ``target`` (its only observed flow target)."""
    raw = builder.to_json()
    if index is None:
        index = next(number for number, row in enumerate(raw["instructions"])
                     if any(item["opcode"] == "CBRANCH" for item in row["operations"]))
    row = raw["instructions"][index]
    (branch,) = [item for item in row["operations"] if item["opcode"] == "CBRANCH"]
    branch["inputs"][0] = ram(target)
    row["flow_targets"] = [{"space_id": branch["inputs"][0]["space_id"], "byte_offset": target}]
    builder.to_json = lambda raw=raw: raw
    return builder


def _middle():
    """rdi = rsi; jz TARGET; rax = 7; ret."""
    builder = (FunctionBuilder(entry=MIDDLE).ins(copy(reg(RDI), reg(RSI)))
               .cbranch("done", reg(ZF, 1)).ins(copy(reg(RAX), const(7))).label("done").ret())
    return _to(builder, 1, TARGET)


def _target():
    """rax = rdi + 1; ret."""
    return FunctionBuilder(entry=TARGET).ins(add(reg(RAX), reg(RDI), const(1))).ret()


def _caller():
    return FunctionBuilder(entry=CALLER).call(MIDDLE).ins(copy(reg(R9), reg(RAX))).ret()


def _site(unit):
    row = unit.observation.instructions[1]
    return f"{row.address.space_id:x}:{row.address.byte_offset:x}:0:CBRANCH"


def test_a_conditional_tail_is_a_call_site():
    units = program_units(_middle(), _target())
    assert _direct_calls(units[0], {function_key_of(1, TARGET): None}) == {_site(units[0]): function_key_of(1, TARGET)}


def test_a_conditional_tail_is_composed_on_its_edge_block():
    units = program_units(_caller(), _middle(), _target())
    results = analyze_units(units)
    middle = results[function_key_of(1, MIDDLE)]
    site = _site(units[1])
    assert site in middle.proven and middle.proven[site].tail_stack
    summary = middle.summary
    assert summary.tail_exits == ()
    exit_keys = sorted(item.block_key for item in summary.exits)
    assert any(">" in key for key in exit_keys) and len(exit_keys) == 2, exit_keys
    assert dict(summary.register_deltas)[(RSP, 8)] == 8
    # the staged rows and the crossing sit in the edge block, never in S
    blocks = {block.key: [action.operation_key for action in block.actions]
              for block in middle.normalized.memory_unit.blocks}
    (edge_key,) = [key for key in blocks if ">" in key]
    assert blocks[edge_key][-1] == f"{site}~edge"
    assert all(not key.startswith(site + "~") for block, keys in blocks.items() if block != edge_key for key in keys)
    # the caller composes middle: its effect is derivable now
    assert function_key_of(1, MIDDLE) in {effect.callee for effect in results[function_key_of(1, CALLER)].proven.values()}


def _oracle(results, units, key):
    import test_graph_fidelity as fidelity
    from program_oracle import check_program
    from synthetic import REG

    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    item = results[key]
    # ZF alternates with the seed: both outcomes of the conditional tail run
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000, ZF: seed % 2}
    return check_program(item.normalized, item.unit.observation, program, seeds=range(8),
                         register_pools=pools, havoc_calls=(REG, RSP, 8))


def test_both_outcomes_are_sound_under_the_program_oracle():
    """The taken path runs the target (rax = rsi + 1), the fallthrough sets
    rax = 7: the caller's r9 and middle's own values are checked on both."""
    units = program_units(_caller(), _middle(), _target())
    results = analyze_units(units)
    for key in (function_key_of(1, CALLER), function_key_of(1, MIDDLE)):
        report = _oracle(results, units, key)
        assert report.silent == [] and report.covered_by_debt == [], (key, report.silent, report.covered_by_debt)
        assert report.runs == 8 and report.unsupported == 0 and report.checked, key


def _edge_of(site):
    space, offset, ordinal, _ = site.split(":")
    return f"{space}:{offset}>{ordinal}t"


def test_the_memset_shape_composes_and_keeps_the_loop():
    """A loop whose body may leave through ``jae TARGET`` (memset's large-size
    path) and otherwise loops or returns: ``E`` is an exit state, the loop's
    own RETURN stays one, nothing is a tail exit."""
    from synthetic import CF, RDX

    builder = (FunctionBuilder(entry=MIDDLE).ins(copy(reg(RDI), reg(RSI)))
               .label("top")
               .cbranch("out", reg(CF, 1))
               .ins(add(reg(RDX), reg(RDX), const(1)))
               .cbranch("top", reg(ZF, 1))
               .label("out").ins(copy(reg(RAX), const(7))).ret())
    builder = _to(builder, 1, TARGET)
    units = program_units(_caller(), builder, _target())
    results = analyze_units(units)
    middle = results[function_key_of(1, MIDDLE)]
    site = _site(units[1])
    assert middle.summary.tail_exits == ()
    assert _edge_of(site) in {item.block_key for item in middle.summary.exits}
    for key in (function_key_of(1, CALLER), function_key_of(1, MIDDLE)):
        report = _oracle(results, units, key)
        assert report.silent == [] and report.covered_by_debt == [], key


def test_a_loop_left_only_through_a_composed_tail_has_one_exit_state():
    """Zero-to-one terminal (G1) composed: the edge block is the summary's
    only exit state, with the target's stack delta."""
    builder = _to(FunctionBuilder(entry=MIDDLE).label("top").ins(copy(reg(RDI), reg(RSI)))
                  .cbranch("top", reg(ZF, 1)).branch("top"), 1, TARGET)
    units = program_units(_caller(), builder, _target())
    results = analyze_units(units)
    summary = results[function_key_of(1, MIDDLE)].summary
    assert summary.tail_exits == ()
    assert [item.block_key for item in summary.exits] == [_edge_of(_site(units[1]))]
    assert dict(summary.register_deltas)[(RSP, 8)] == 8


def test_a_target_that_never_returns_makes_a_dead_edge_and_keeps_the_fallthrough():
    """``jz F`` where F traps (``int3``, debug-break traps do not return): ``E``
    is a dead exit (a Bundle-derived dead edge), never a cut of S -- the
    fallthrough's RETURN stays an exit and the caller composes middle."""
    from test_conditional_summaries import _analyze_traps, _int3

    target = FunctionBuilder(entry=TARGET).ins(_int3()).ret()
    results = _analyze_traps(_caller(), _middle(), target)
    middle = results[function_key_of(1, MIDDLE)]
    site = _site(program_units(_middle(), target)[0])
    assert middle.proven[site].noreturn
    assert middle.summary.tail_exits == ()
    assert middle.summary.dead_exits == (_edge_of(site),)
    assert len(middle.summary.exits) == 1 and ">" not in middle.summary.exits[0].block_key
    assert results[function_key_of(1, CALLER)].proven


def test_the_register_delta_proof_runs_through_the_edge_block():
    """``rsp += 16; jz TARGET`` in one instruction, target delta +8: the edge
    exit's delta is 16 + 8 from E's incoming value (S's outgoing); the
    fallthrough's RETURN gives the same 24."""
    from synthetic import op
    from tdo_v2.model import StorageObjectId
    from tdo_v2.register_delta_proofs import derive_register_delta_proof, validate_proof_record
    from tdo_v2.span_geometry import ByteSpan, StorageObjectKind

    builder = (FunctionBuilder(entry=MIDDLE).ins(copy(reg(RDI), reg(RSI)))
               .ins(add(reg(RSP), reg(RSP), const(16)), op("CBRANCH", [ram(TARGET), reg(ZF, 1)]))
               .ins(copy(reg(RAX), const(7))).ret())
    raw = builder.to_json()
    row = raw["instructions"][1]
    row["flow_targets"] = [{"space_id": row["operations"][-1]["inputs"][0]["space_id"], "byte_offset": TARGET}]
    row["flow_type"] = {**row["flow_type"], "is_flow": True, "is_jump": True, "is_conditional": True}
    builder.to_json = lambda raw=raw: raw
    units = program_units(_caller(), builder, _target())
    results = analyze_units(units)
    item = results[function_key_of(1, MIDDLE)]
    unit = item.unit
    span = ByteSpan(StorageObjectId(StorageObjectKind.REGISTER_FILE, unit.scopes.program.scope, 0), RSP, 8)
    proof = derive_register_delta_proof(unit, span, dict(item.normalized.proven_call_effects), {})
    assert proof is not None and proof.delta == 24
    assert [(fact.kind, fact.delta) for fact in proof.call_facts] == [("tail", 8)]
    assert validate_proof_record(proof.record()) == proof
    assert dict(item.summary.register_deltas)[(RSP, 8)] == 24


def test_a_stack_value_leaving_through_a_composed_edge_is_stack_values_out():
    """``rax = rsp + 8; jz TARGET`` with a target keeping rax: a register
    holding a stack-derived value leaves through the edge block."""
    builder = (FunctionBuilder(entry=MIDDLE).ins(add(reg(RAX), reg(RSP), const(8)))
               .cbranch("done", reg(ZF, 1)).ins(copy(reg(RAX), const(7))).label("done").ret())
    builder = _to(builder, 1, TARGET)
    keep = FunctionBuilder(entry=TARGET).ins(copy(reg(RCX), const(1))).ret()
    results = analyze_units(program_units(_caller(), builder, keep))
    assert results[function_key_of(1, MIDDLE)].summary.stack_values_out


def test_the_edge_block_names_its_taken_guard_even_as_the_sole_exit():
    """The labelled control dependence of ``E`` names the taken outcome of
    its CBRANCH in both shapes: the fallthrough also reaches an exit, and the
    loop whose only way out is ``E`` (where ``E`` postdominates ``S``)."""
    from tdo_v2.control_dependence import guard_rows, labelled_control_dependences

    loop = _to(FunctionBuilder(entry=MIDDLE).label("top").ins(copy(reg(RDI), reg(RSI)))
               .cbranch("top", reg(ZF, 1)).branch("top"), 1, TARGET)
    for builder in (_middle(), loop):
        unit = program_units(builder, _target())[0]
        site = _site(unit)
        rows = labelled_control_dependences(unit.observation, unit.scopes.function.entry)
        edge = _edge_of(site)
        assert (site, edge.split(">")[0], edge, edge) in guard_rows(rows, edge)


def test_staged_rows_and_the_crossing_are_never_call_boundaries():
    """The clobber engines' raw call recognition stays: no ``~`` row -- an
    ordinary CALL's staged rows or a conditional tail's ``~edge`` -- is in
    ``call_exemptions.calls`` (the crossing is the summary's alone)."""
    from tdo_v2.call_clobber import call_exemptions

    units = program_units(_caller(), _middle(), _target())
    results = analyze_units(units)
    for key in (function_key_of(1, CALLER), function_key_of(1, MIDDLE)):
        normalized = results[key].normalized
        keys = [action.operation_key for block in normalized.memory_unit.blocks for action in block.actions]
        calls = call_exemptions(keys, {}, dict(normalized.proven_call_effects)).calls
        assert all("~" not in item and not item.endswith(":CBRANCH") for item in calls), calls
        assert key != function_key_of(1, MIDDLE) or any(item.endswith("~edge") for item in keys)


def _rcx_target():
    """rcx = rdi + 2; ret -- a register middle's fallthrough never writes."""
    return FunctionBuilder(entry=TARGET).ins(add(reg(RCX), reg(RDI), const(2))).ret()


def _rcx_caller():
    return FunctionBuilder(entry=CALLER).call(MIDDLE).ins(copy(reg(R9), reg(RCX))).ret()


def test_the_target_acts_on_the_taken_outcome_only():
    """The target writes rcx; the fallthrough leaves it: with the target's
    rows anywhere but the edge block the fallthrough would see rcx changed --
    the program oracle checks the caller's r9 on both outcomes."""
    units = program_units(_rcx_caller(), _middle(), _rcx_target())
    results = analyze_units(units)
    for key in (function_key_of(1, CALLER), function_key_of(1, MIDDLE)):
        report = _oracle(results, units, key)
        assert report.silent == [] and report.covered_by_debt == [], (key, report.silent)
        assert report.runs == 8 and report.unsupported == 0 and report.checked, key


def test_the_fallthrough_exit_does_not_cross_the_target():
    """The crossing is the edge block's: a target calling an opaque function
    leaves rsi unknown (crossed) on the taken outcome only -- the fallthrough's
    RETURN keeps rsi (which middle only reads) as its entry value, uncrossed."""
    from tdo_v2.function_summary import SummaryKind

    opaque = CODE_BASE + 0xE00
    target = FunctionBuilder(entry=TARGET).sub_rsp(0x28).call(opaque).add_rsp(0x28).ret()
    units = program_units(_rcx_caller(), _middle(), target)
    item = analyze_units(units)[function_key_of(1, MIDDLE)]
    assert _site(units[1]) in item.proven
    summary = item.summary

    def rsi(exit_summary):
        return [run for run in exit_summary.runs if run.span.object_id.kind.name == "REGISTER_FILE"
                and run.span.start <= RSI < run.span.end]

    (ret,) = [entry for entry in summary.exits if ">" not in entry.block_key]
    assert rsi(ret) and all(run.kind is SummaryKind.IDENTITY and not run.crossed for run in rsi(ret)), rsi(ret)
    (edge,) = [entry for entry in summary.exits if ">" in entry.block_key]
    assert any(run.crossed for run in rsi(edge)), rsi(edge)


def test_integration_orders_the_edge_rows_after_the_raw_operations():
    """(design r8 A, r9 K) The integration view gives a conditional tail's
    rows -- in an edge block, with no raw operation -- positions after every
    raw one, so a staged write there is a later write (a known overwrite, not
    a skipped one); raw lookups stay raw; the state barrier anchors those rows
    in the edge block, not at the CBRANCH whose fallthrough they never run on."""
    from synthetic import summary_inputs
    from tdo_v2.integration.configured_function_view import _FunctionView
    from tdo_v2.integration.configured_interprocedural_contracts import ConfiguredFunctionAnalysis
    from tdo_v2.integration.configured_state_barrier import _BarrierFacts
    from tdo_v2.observed_boundary_projection import EMPTY_OBSERVED_BOUNDARIES

    builders = (_rcx_caller(), _middle(), _rcx_target())
    results = analyze_units(program_units(*builders))
    evidence = next(item for item in summary_inputs(list(builders), image=False).evidences
                    if item.unit.scopes.function.entry.byte_offset == MIDDLE)
    normalized = results[function_key_of(1, MIDDLE)].normalized
    view = _FunctionView(ConfiguredFunctionAnalysis(evidence, normalized, EMPTY_OBSERVED_BOUNDARIES, ()))
    site = _site(evidence.unit)
    edge = _edge_of(site)
    rows = [key for key, block in view.operation_blocks.items() if block == edge]
    in_order = sorted(rows, key=view.position)
    assert in_order and in_order[-1] == f"{site}~edge"
    last_raw = max(position for position, _ in view.operations.values())
    assert all(view.position(key) > last_raw for key in rows)
    assert all(view.operation(key) is None for key in rows)
    first = min(view.operations, key=view.position)
    staged = next(key for key in rows if not key.endswith("~edge"))
    assert view.definitely_precedes(first, staged) and not view.definitely_precedes(staged, first)
    facts = _BarrierFacts(view)
    assert all(facts.place[key][0] == edge for key in rows)


# -- review r1 pins ---------------------------------------------------------------

SINK, OPAQUE = CODE_BASE + 0xA00, CODE_BASE + 0xC00


def _with_sinks(monkeypatch, *functions):
    """analyze_summaries with a TEST-ONLY register sink ``sink(rcx)``: the run
    and the AnalyzedFunctions it published."""
    from synthetic import analyze_summaries, boundary
    from tdo_v2 import summary_engine

    captured = {}
    original = summary_engine.analyze_units

    def capture(*args, **kwargs):
        captured["results"] = original(*args, **kwargs)
        return captured["results"]

    monkeypatch.setattr(summary_engine, "analyze_units", capture)
    run = analyze_summaries([*functions, FunctionBuilder(entry=SINK).ret()], boundary({}, {"sink": 8}),
                            names={SINK: "sink"})
    return run, captured["results"]


def _sink_target():
    """rcx = rdi; call sink; ret -- a sink reached only through the tail."""
    return FunctionBuilder(entry=TARGET).sub_rsp(0x28).ins(copy(reg(RCX), reg(RDI))).call(SINK).add_rsp(0x28).ret()


def test_a_sink_reached_through_the_tail_depends_on_the_taken_edge(monkeypatch):
    """The staged sink row in E depends on the CBRANCH decision (its taken
    outcome) in the dependency graph -- exactly once."""
    from tdo_v2.graph import CONTROL_DEPENDENCE_EDGE

    _, results = _with_sinks(monkeypatch, _caller(), _middle(), _sink_target())
    middle = results[function_key_of(1, MIDDLE)]
    site = _site(middle.unit)
    graph = middle.normalized.dependencies
    decision = graph.node_for_key(f"op:{site}")
    rows = [key for block in middle.normalized.memory_unit.blocks for key in
            (action.operation_key for action in block.actions) if key.startswith(site + "~sink")]
    assert rows, "the target's sink is staged in E"
    edges = graph.weighted_edges()
    for row in rows:
        node = graph.node_for_key(f"op:{row}")
        found = [edge for edge in edges if edge[0] == decision and edge[1] == node
                 and getattr(edge[2].kind, "value", edge[2].kind) == CONTROL_DEPENDENCE_EDGE]
        assert len(found) == 1, (row, found)


def test_the_memset_loop_adds_no_duplicate_taken_edge():
    """In a loop the decision may already govern itself (its rows inherit
    it): the taken-edge dependence is not added a second time."""
    from synthetic import CF, RDX
    from tdo_v2.graph import CONTROL_DEPENDENCE_EDGE

    builder = _to(FunctionBuilder(entry=MIDDLE).ins(copy(reg(RDI), reg(RSI)))
                  .label("top").cbranch("out", reg(CF, 1)).ins(add(reg(RDX), reg(RDX), const(1)))
                  .cbranch("top", reg(ZF, 1)).label("out").ins(copy(reg(RAX), const(7))).ret(), 1, TARGET)
    units = program_units(_caller(), builder, _target())
    middle = analyze_units(units)[function_key_of(1, MIDDLE)]
    site = _site(units[1])
    graph = middle.normalized.dependencies
    decision = graph.node_for_key(f"op:{site}")
    pairs = [(edge[0], edge[1]) for edge in graph.weighted_edges()
             if edge[0] == decision and getattr(edge[2].kind, "value", edge[2].kind) == CONTROL_DEPENDENCE_EDGE]
    assert len(pairs) == len(set(pairs))


def _sink_only_target():
    """rcx = rdi; call sink; jmp rax -- its sink binds, but it leaves through an
    unknown transfer: a sink-only effect (no tail_stack)."""
    return (FunctionBuilder(entry=TARGET).sub_rsp(0x28).ins(copy(reg(RCX), reg(RDI))).call(SINK)
            .add_rsp(0x28).jump_indirect(reg(RAX)))


def test_a_sink_only_target_is_placed_but_not_composed(monkeypatch):
    """Placed, not composed: the sink row sits in E, E stays a tail exit, no
    exit state there, and E is no way out for stack_values_out (only a
    composed edge counts -- design r9 pin)."""
    _, results = _with_sinks(monkeypatch, _caller(), _middle(), _sink_only_target())
    middle = results[function_key_of(1, MIDDLE)]
    site = _site(middle.unit)
    effect = middle.proven[site]
    assert not effect.tail_stack and effect.sink_demands
    edge = _edge_of(site)
    assert edge in middle.summary.tail_exits
    assert edge not in {item.block_key for item in middle.summary.exits}
    blocks = {block.key: [action.operation_key for action in block.actions]
              for block in middle.normalized.memory_unit.blocks}
    assert blocks[edge][-1] == f"{site}~edge"
    # rax = rsp + 8 reaches E: with the sink-only target E is no way out (no
    # stack_values_out); with a composing target the same shape is (test above)
    tainted = _to(FunctionBuilder(entry=MIDDLE).ins(add(reg(RAX), reg(RSP), const(8)))
                  .cbranch("done", reg(ZF, 1)).ins(copy(reg(RAX), const(7))).label("done").ret(), None, TARGET)
    _, results = _with_sinks(monkeypatch, _caller(), tainted, _sink_only_target())
    item = results[function_key_of(1, MIDDLE)]
    assert not item.proven[_site(item.unit)].tail_stack
    assert not item.summary.stack_values_out


def test_a_zero_row_target_places_exactly_one_crossing():
    """A target with no effect of its own (``ret``): E holds exactly one
    ``s~edge`` crossing row, last."""
    target = FunctionBuilder(entry=TARGET).ret()
    units = program_units(_caller(), _middle(), target)
    middle = analyze_units(units)[function_key_of(1, MIDDLE)]
    site = _site(units[1])
    blocks = {block.key: [action.operation_key for action in block.actions]
              for block in middle.normalized.memory_unit.blocks}
    rows = blocks[_edge_of(site)]
    assert [key for key in rows if key.endswith("~edge")] == [f"{site}~edge"] and rows[-1] == f"{site}~edge"


def test_a_composed_edge_behind_an_earlier_cut_is_dead():
    """``int3`` (debug-break traps do not return) before ``jz TARGET``: E is
    unreached -- dead before composed: no exit state, no tail exit."""
    from test_conditional_summaries import _analyze_traps, _int3

    builder = _to(FunctionBuilder(entry=MIDDLE).ins(_int3())
                  .cbranch("done", reg(ZF, 1)).ins(copy(reg(RAX), const(7))).label("done").ret(), 1, TARGET)
    results = _analyze_traps(_caller(), builder, _target())
    summary = results[function_key_of(1, MIDDLE)].summary
    edge = _edge_of(_site(program_units(builder, _target())[0]))
    assert edge not in summary.tail_exits
    assert edge not in {item.block_key for item in summary.exits}
    assert edge not in summary.dead_exits   # (unreached edges stay out, as in G1)


def test_a_loop_whose_only_way_out_never_returns_is_noreturn():
    """The loop leaves only through ``jz F`` and F traps: E is a
    Bundle-derived dead exit, the function is provably noreturn, and its
    caller takes the noreturn effect."""
    from test_conditional_summaries import _analyze_traps, _int3
    from tdo_v2.call_summary_effects import summary_noreturn

    builder = _to(FunctionBuilder(entry=MIDDLE).label("top").ins(copy(reg(RDI), reg(RSI)))
                  .cbranch("top", reg(ZF, 1)).branch("top"), 1, TARGET)
    target = FunctionBuilder(entry=TARGET).ins(_int3()).ret()
    results = _analyze_traps(_caller(), builder, target)
    summary = results[function_key_of(1, MIDDLE)].summary
    assert summary.exits == () and summary.tail_exits == ()
    assert summary.dead_exits == (_edge_of(_site(program_units(builder, target)[0])),)
    assert summary_noreturn(summary)
    assert any(effect.noreturn for effect in results[function_key_of(1, CALLER)].proven.values())


def test_conditional_tail_rows_are_ram_writers():
    """A conditional tail's staged rows write RAM (as a BRANCH tail's), not WILD."""
    from tdo_v2.write_classes import RAM, WriterClasses

    units = program_units(_caller(), _middle(), _rcx_target())
    middle = analyze_units(units)[function_key_of(1, MIDDLE)]
    site = _site(units[1])
    classes = WriterClasses(middle.unit.scopes, middle.unit.observation)
    staged = [action.operation_key for block in middle.normalized.memory_unit.blocks for action in block.actions
              if action.operation_key.startswith(site + "~")]
    assert staged and all(classes.classify(key) == RAM for key in staged)


def test_the_conditional_tail_proof_record_is_validated_strictly():
    """A CBRANCH tail fact must name a well-formed site whose edge block is an
    exit with exactly that delta, one fact per edge exit: a malformed key, a
    changed delta or a missing fact is refused (None), never an exception."""
    import dataclasses
    from synthetic import op
    from tdo_v2 import register_delta_proofs as rdp
    from tdo_v2.model import StorageObjectId
    from tdo_v2.span_geometry import ByteSpan, StorageObjectKind

    builder = (FunctionBuilder(entry=MIDDLE).ins(copy(reg(RDI), reg(RSI)))
               .ins(add(reg(RSP), reg(RSP), const(16)), op("CBRANCH", [ram(TARGET), reg(ZF, 1)]))
               .ins(copy(reg(RAX), const(7))).ret())
    raw = builder.to_json()
    row = raw["instructions"][1]
    row["flow_targets"] = [{"space_id": row["operations"][-1]["inputs"][0]["space_id"], "byte_offset": TARGET}]
    row["flow_type"] = {**row["flow_type"], "is_flow": True, "is_jump": True, "is_conditional": True}
    builder.to_json = lambda raw=raw: raw
    item = analyze_units(program_units(_caller(), builder, _target()))[function_key_of(1, MIDDLE)]
    span = ByteSpan(StorageObjectId(StorageObjectKind.REGISTER_FILE, item.unit.scopes.program.scope, 0), RSP, 8)
    proof = rdp.derive_register_delta_proof(item.unit, span, dict(item.normalized.proven_call_effects), {})
    assert rdp.validate_proof_record(proof.record()) == proof

    def resealed(record):
        payload = {key: value for key, value in record.items() if key != "content_sha256"}
        return {**record, "content_sha256": rdp._digest(payload)}

    record = proof.record()
    (fact,) = [index for index, row in enumerate(record["call_facts"])
               if row["operation_key"].endswith(":CBRANCH")]
    site = record["call_facts"][fact]["operation_key"]
    space, offset, ordinal, _ = site.split(":")
    other_site = f"{space}:{offset}:{int(ordinal) + 1}:CBRANCH"   # well-formed, its edge is no exit
    for change in ("x:CBRANCH", "zz:1:0:CBRANCH", other_site, None):
        changed = dict(record)
        facts = [dict(row) for row in record["call_facts"]]
        keys = list(record["operation_keys"])
        if change is None:
            facts[fact]["delta"] = facts[fact]["delta"] + 8      # another delta
        else:
            facts[fact]["operation_key"] = change                # a malformed / other site, also listed
            keys = sorted(set(keys) | {change})
        changed["call_facts"] = sorted(facts, key=lambda row: row["operation_key"])
        changed["operation_keys"] = keys
        assert rdp.validate_proof_record(resealed(changed)) is None, change
    missing = dict(record)
    missing["call_facts"] = [row for index, row in enumerate(record["call_facts"]) if index != fact]
    assert rdp.validate_proof_record(resealed(missing)) is None


def test_a_records_stitch_never_crosses_a_conditional_tail():
    """The ordinary records view cuts per row at a conditional-tail site
    (reason ``conditional-tail``), whatever its effect."""
    from tdo_v2.operation_records import StitchContext, root_record

    table: dict = {}
    builders = (_caller(), _middle(), _target())   # (a caller: the program's call shape gives its stack pointer)
    results = analyze_units(program_units(*builders), record_provenance=table)
    middle = results[function_key_of(1, MIDDLE)]
    edge = _edge_of(_site(middle.unit))
    (exit_summary,) = [item for item in middle.summary.exits if item.block_key == edge]
    run = next(run for run in exit_summary.runs
               if run.span.object_id.kind.value == "register_file" and run.span.start == RAX)
    nodes = [middle.normalized.memory_graph.definition_nodes[item] for item in run.definitions]
    record = root_record(middle.normalized, middle.unit, [(nodes[0], (run.span,))], declared=middle.declared,
                         provenance=table[id(middle)][1], stitch=StitchContext(table))
    calls = [node for node in record["nodes"] if node["kind"] == "call"]
    assert calls and all(node.get("stitch_cut") == "conditional-tail" for node in calls), calls


def test_integration_sees_the_edge_overwrite_of_an_earlier_event():
    """(Astra r7 P1) An earlier opaque call's write to a global survives to no
    exit when the conditional tail's staged row in the sole terminal E
    overwrites it: both survival predicates say so."""
    from synthetic import DATA_BASE, store, summary_inputs
    from tdo_v2.integration.configured_function_view import _FunctionView
    from tdo_v2.integration.configured_interprocedural_contracts import ConfiguredFunctionAnalysis
    from tdo_v2.integration.configured_interprocedural_records import WriteEvent
    from tdo_v2.model import StorageObjectId
    from tdo_v2.observed_boundary_projection import EMPTY_OBSERVED_BOUNDARIES
    from tdo_v2.span_geometry import ByteSpan, StorageObjectKind

    middle = _to(FunctionBuilder(entry=MIDDLE).sub_rsp(0x28).call(OPAQUE).add_rsp(0x28)
                 .label("top").ins(copy(reg(RDI), reg(RSI))).cbranch("top", reg(ZF, 1)).branch("top"), None, TARGET)
    target = FunctionBuilder(entry=TARGET).ins(store(const(DATA_BASE), const(7, 8))).ret()
    builders = (_caller(), middle, target)
    results = analyze_units(program_units(*builders))
    normalized = results[function_key_of(1, MIDDLE)].normalized
    evidence = next(item for item in summary_inputs(list(builders), image=False).evidences
                    if item.unit.scopes.function.entry.byte_offset == MIDDLE)
    view = _FunctionView(ConfiguredFunctionAnalysis(evidence, normalized, EMPTY_OBSERVED_BOUNDARIES, ()))
    call = next(key for key, (_, operation) in view.operations.items() if operation.opcode == "CALL")
    scope = evidence.unit.scopes.program.scope
    space = next(row.space_id for row in evidence.unit.scopes.program.evidence.address_spaces
                 if row.is_memory_space and row.is_loaded_memory_space)
    target_span = ByteSpan(StorageObjectId(StorageObjectKind.ADDRESS_SPACE, scope, space), DATA_BASE, 8)
    event = WriteEvent(evidence.unit.scopes.function.scope.digest, view.position(call), call,
                       evidence.unit.scopes.function.entry, b"\0" * 32, "callee:write", target_span, 0, ())
    assert not view.event_reaches_every_exit(event, (event,))
    assert not view.event_reaches_an_exit(event, (event,))


# -- review r2 pins ---------------------------------------------------------------


def _legacy_case(thunk_body):
    """``jz ABORT`` where ABORT is the abort import thunk's address (a noreturn
    model) and ``thunk_body`` the Bundle function there."""
    from test_import_tail_jumps import ABORT, MODELS
    from tdo_v2.image_info import ImageInfo, ImportedSymbol
    from tdo_v2.summary_store import load_external_models

    image = ImageInfo("synthetic", (), (ImportedSymbol("CRT", "abort", None, (), ((1, ABORT),)),), (), ())
    middle = _to(FunctionBuilder(entry=MIDDLE).sub_rsp(0x28).cbranch("done", reg(ZF, 1))
                 .ins(copy(reg(RAX), const(7))).label("done").add_rsp(0x28).ret(), None, ABORT)
    units = program_units(_caller(), middle, thunk_body)
    results = analyze_units(units, image_info=image,
                            external_models=load_external_models(MODELS, "x86:LE:64:default", "win64"))
    return results[function_key_of(1, MIDDLE)], _site(units[1])


def test_a_bundle_thunk_that_composes_wins_over_the_legacy_noreturn_cut():
    """The thunk address holds a returning Bundle function: the conditional
    tail composes it -- E is an exit state, and no legacy abort cut or label is
    taken at the site."""
    from test_import_tail_jumps import ABORT

    middle, site = _legacy_case(FunctionBuilder(entry=ABORT).ret())
    assert middle.proven[site].tail_stack
    assert _edge_of(site) in {item.block_key for item in middle.summary.exits}
    assert site not in middle.declared
    assert not any(label.startswith("external-model:crt-win64/abort@") for label in middle.declared.values())
    assert site not in middle.refused_models


def test_the_legacy_noreturn_cut_is_the_fallback_when_the_bundle_thunk_composes_nothing():
    """The Bundle function at the thunk address leaves through an unknown tail
    of its own: no effect at the site -- the legacy abort cut applies as
    before G3a (a dead edge: no tail exit, no exit state, not a Bundle dead
    exit) and its model label is declared."""
    from test_import_tail_jumps import ABORT

    middle, site = _legacy_case(FunctionBuilder(entry=ABORT).tail_call(CODE_BASE + 0x900))
    assert site not in middle.proven
    edge = _edge_of(site)
    summary = middle.summary
    assert edge not in summary.tail_exits and edge not in summary.dead_exits
    assert edge not in {item.block_key for item in summary.exits}
    assert middle.declared.get(site, "").startswith("external-model:crt-win64/abort@")


def test_the_state_barrier_keeps_the_fallthrough_lookup():
    """(design r9 K) A global stored before the loop and overwritten only by
    the conditional tail's staged rows in E -- exactly, through the entry
    pointer, as an unresolved write (an indexed address) or as an uncertain
    writer (through a loaded pointer) -- is still the stored definition inside
    the loop body: E's rows are anchored in E, never at the CBRANCH."""
    from synthetic import CF, DATA_BASE, RBX, RDX, load, store, summary_inputs
    from tdo_v2.integration.configured_function_view import _FunctionView
    from tdo_v2.integration.configured_interprocedural_contracts import ConfiguredFunctionAnalysis
    from tdo_v2.model import StorageObjectId
    from tdo_v2.observed_boundary_projection import EMPTY_OBSERVED_BOUNDARIES
    from tdo_v2.span_geometry import ByteSpan, StorageObjectKind

    shapes = (
        ("exact", (store(const(DATA_BASE), const(7, 8)),)),
        ("entry pointer", (store(reg(RDI), const(7, 8)),)),
        ("unresolved", (add(reg(RAX), reg(RDI), reg(RDX)), store(reg(RAX), const(7, 8)))),
        ("uncertain", (load(reg(RAX), reg(RDI)), store(reg(RAX), const(7, 8)))),
    )
    for write, body in shapes:
        middle = _to(FunctionBuilder(entry=MIDDLE).ins(store(const(DATA_BASE), reg(RBX)))
                     .label("top").cbranch("out", reg(CF, 1)).ins(add(reg(RDX), reg(RDX), const(1)))
                     .cbranch("top", reg(ZF, 1)).label("out").ret(), None, TARGET)
        target = FunctionBuilder(entry=TARGET).ins(*body).ret()
        builders = (_caller(), middle, target)
        results = analyze_units(program_units(*builders))
        normalized = results[function_key_of(1, MIDDLE)].normalized
        evidence = next(item for item in summary_inputs(list(builders), image=False).evidences
                        if item.unit.scopes.function.entry.byte_offset == MIDDLE)
        site = _site(evidence.unit)
        if write == "unresolved":
            assert any(normalized.memory_ssa.actions[item.action_id].operation_key.startswith(site + "~")
                       for item in normalized.memory_ssa.unresolved_writes)
        if write == "uncertain":
            assert any(key.startswith(site + "~") for key, _ in normalized.uncertain_writers)
        view = _FunctionView(ConfiguredFunctionAnalysis(evidence, normalized, EMPTY_OBSERVED_BOUNDARIES, ()))
        scope = evidence.unit.scopes.program.scope
        space = next(row.space_id for row in evidence.unit.scopes.program.evidence.address_spaces
                     if row.is_memory_space and row.is_loaded_memory_space)
        span = ByteSpan(StorageObjectId(StorageObjectKind.ADDRESS_SPACE, scope, space), DATA_BASE, 8)
        stored = next(index for index, definition in enumerate(normalized.memory_ssa.definitions)
                      if definition.operation_key is not None and definition.operation_key.endswith(":STORE")
                      and not definition.operation_key.startswith(_site(evidence.unit))
                      and definition.span.overlaps(span))
        body = next(key for key, (_, operation) in view.operations.items() if operation.opcode == "INT_ADD")
        assert view.state_definition(span, view.position(body)) == stored, write


def test_a_physical_call_context_expands_a_callee_with_a_conditional_tail():
    """(design r9 final fixes) A physical context builds its callee's exits
    from RETURN blocks only: a callee with a register-only conditional tail is
    refused, never given a context missing the edge exit."""
    from test_physical_call_records import _caller as _physical_caller, _case, _record

    callee = _to(FunctionBuilder(entry=0x1800).cbranch("done", reg(ZF, 1)).ins(copy(reg(RAX), const(7)))
                 .label("done").ret(), None, 0x1a00)
    target = FunctionBuilder(entry=0x1a00).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    case = _case(_physical_caller(), callee, target)
    assert any(key.endswith(":CBRANCH") for key in case["callee"].proven)
    result = _record(case)
    cuts = result.get("physical_call_cuts", {})
    # (G-T G3b-4, docs 25.110) a composed tail is now a terminal: the callee is
    # expanded through a nested tail context instead of refused
    assert not cuts, cuts
    assert any(context.get("kind") == "tail" for context in result.get("physical_calls", {}).values())



def _legacy_case_with_sinks(monkeypatch, thunk_body):
    """``_legacy_case`` with the TEST-ONLY register sink available to the thunk body."""
    from synthetic import analyze_summaries, boundary
    from test_import_tail_jumps import ABORT, MODELS
    from tdo_v2 import summary_engine
    from tdo_v2.image_info import ImportedSymbol
    from tdo_v2.summary_store import load_external_models

    captured = {}
    original = summary_engine.analyze_units

    def capture(*args, **kwargs):
        captured["results"] = original(*args, **kwargs)
        return captured["results"]

    monkeypatch.setattr(summary_engine, "analyze_units", capture)
    middle = _to(FunctionBuilder(entry=MIDDLE).sub_rsp(0x28).cbranch("done", reg(ZF, 1))
                 .ins(copy(reg(RAX), const(7))).label("done").add_rsp(0x28).ret(), None, ABORT)
    analyze_summaries([_caller(), middle, thunk_body, FunctionBuilder(entry=SINK).ret()], boundary({}, {"sink": 8}),
                      names={SINK: "sink"}, image=True,
                      imports=(ImportedSymbol("CRT", "abort", None, (), ((1, ABORT),)),),
                      external_models=load_external_models(MODELS, "x86:LE:64:default", "win64"))
    results = captured["results"]
    item = results[function_key_of(1, MIDDLE)]
    return item, _site(item.unit)


def test_a_sink_only_bundle_thunk_keeps_the_legacy_noreturn_cut(monkeypatch):
    """(review r3, Fable P2-1) The Bundle function at the abort thunk address
    binds a sink and then leaves through an unknown transfer: a sink-only
    effect -- neither composed nor noreturn -- so the legacy abort cut stays
    (E no tail exit, no exit state, no dead exit; abort label declared) and
    the sink row stays placed."""
    from test_import_tail_jumps import ABORT

    thunk = (FunctionBuilder(entry=ABORT).sub_rsp(0x28).ins(copy(reg(RCX), reg(RDI))).call(SINK)
             .add_rsp(0x28).jump_indirect(reg(RAX)))
    middle, site = _legacy_case_with_sinks(monkeypatch, thunk)
    effect = middle.proven[site]
    assert not effect.tail_stack and not effect.noreturn and effect.sink_demands
    edge = _edge_of(site)
    summary = middle.summary
    assert edge not in summary.tail_exits and edge not in summary.dead_exits
    assert edge not in {item.block_key for item in summary.exits}
    assert middle.declared.get(site, "").startswith("external-model:crt-win64/abort@")
    blocks = {block.key: [action.operation_key for action in block.actions]
              for block in middle.normalized.memory_unit.blocks}
    assert any(key.startswith(site + "~sink") for key in blocks[edge])


def test_a_noreturn_bundle_thunk_wins_over_the_legacy_cut():
    """The Bundle function at the abort thunk address traps (debug-break
    traps do not return): the Bundle-derived dead edge wins -- E is a dead
    exit and no abort label is taken at the site."""
    from test_conditional_summaries import _int3
    from test_import_tail_jumps import ABORT, MODELS
    from tdo_v2.image_info import ImageInfo, ImportedSymbol
    from tdo_v2.pcodeop_models import PcodeOpModel
    from tdo_v2.summary_store import load_external_models

    image = ImageInfo("synthetic", (), (ImportedSymbol("CRT", "abort", None, (), ((1, ABORT),)),), (), ())
    middle = _to(FunctionBuilder(entry=MIDDLE).sub_rsp(0x28).cbranch("done", reg(ZF, 1))
                 .ins(copy(reg(RAX), const(7))).label("done").add_rsp(0x28).ret(), None, ABORT)
    units = program_units(_caller(), middle, FunctionBuilder(entry=ABORT).ins(_int3()).ret())
    namespace = units[0].scopes.program.evidence.translation_namespace
    model = PcodeOpModel("x86-markers", 1, frozenset({(namespace.language_id, namespace.major_version,
                                                        namespace.minor_version)}), {}, {16: frozenset({3})})
    results = analyze_units(units, image_info=image, pcodeop_models=(model,),
                            assume_debug_break_traps_do_not_return=True,
                            external_models=load_external_models(MODELS, "x86:LE:64:default", "win64"))
    item = results[function_key_of(1, MIDDLE)]
    site = _site(units[1])
    assert item.proven[site].noreturn
    assert item.summary.dead_exits == (_edge_of(site),)
    assert site not in item.declared
    assert not any(label.startswith("external-model:crt-win64/abort@") for label in item.declared.values())
