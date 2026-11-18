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
    """Rewrite the CBRANCH of instruction ``index`` to jump to ``target``
    (its only observed flow target)."""
    raw = builder.to_json()
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
    edge = site.rsplit(":", 2)[0].rsplit(":", 0)[0]
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
    assert rows and rows[-1] == f"{site}~edge" or f"{site}~edge" in rows
    last_raw = max(position for position, _ in view.operations.values())
    assert all(view.position(key) > last_raw for key in rows)
    assert all(view.operation(key) is None for key in rows)
    first = min(view.operations, key=view.position)
    staged = next(key for key in rows if not key.endswith("~edge"))
    assert view.definitely_precedes(first, staged) and not view.definitely_precedes(staged, first)
    facts = _BarrierFacts(view)
    assert all(facts.place[key][0] == edge for key in rows)
