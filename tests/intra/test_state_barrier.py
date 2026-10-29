"""Stage 0.1 R1a: a state-at-position answer is provably current or refused.

The sink selectors and the decision evaluators ask "which definition holds
this span before that operation" of the chi-free value view, which has no
definition for an opaque call and no candidate for a partial, conditional or
modeled overwrite. Each test below was answered with a stale definition before
R1a -- an empty, complete root (or a decision on a stale value) -- and must
now be either the true origin or incomplete (``.census6/design_s0_r5.md``).
"""

import pytest
from synthetic import (
    CODE_BASE, DATA_BASE, LANGUAGE, R8, R9, RAX, RCX, RDX, RSP, ZF,
    FunctionBuilder, add, analyze_program, analyze_summaries, boundary, const, copy, load, normalize, op, reg, store,
    summary_inputs,
)
from tdo_v2.boundary import BoundaryKind
from tdo_v2.boundary_rules import BoundaryRule, SymbolBoundaryProvider
from tdo_v2.engine import _unbound_roots
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.integration.configured_function_view import _FunctionView
from tdo_v2.integration.configured_interprocedural_contracts import ConfiguredFunctionAnalysis
from tdo_v2.integration.configured_physical_state import _FunctionPhysicalStateBackend, _register_span
from tdo_v2.normalize import FunctionNormalizer
from tdo_v2.observed_boundary_projection import EMPTY_OBSERVED_BOUNDARIES
from tdo_v2.physical_state import PhysicalMemorySlice, PhysicalRegisterSlice

MAIN, SOURCE, SINK, OPAQUE, HELPER = (
    CODE_BASE, CODE_BASE + 0x800, CODE_BASE + 0xA00, CODE_BASE + 0xC00, CODE_BASE + 0xE00)
NAMES = {SOURCE: "source", SINK: "sink", OPAQUE: "opaque", HELPER: "helper"}
REGISTER_SINK = boundary({"source": 4}, {"sink": 8})
ENGINES = ("summary", "legacy")


def _memory_sink(base: int, displacement: int = 0, size: int = 4):
    """``sink`` consumes ``size`` bytes at ``base + displacement`` (TEST-ONLY rule)."""
    selector = PhysicalMemorySlice(PhysicalRegisterSlice(base, 8), displacement, size)
    return SymbolBoundaryProvider((
        BoundaryRule("source", LANGUAGE, BoundaryKind.SOURCE, "source.ret", (PhysicalRegisterSlice(RAX, 4),)),
        BoundaryRule("sink", LANGUAGE, BoundaryKind.SINK, "sink.arg0", (selector,)),
    ))


def _source():
    return FunctionBuilder(entry=SOURCE).ins(copy(reg(RAX, 4), const(7, 4))).ret()


def _roots(main, engine, provider=REGISTER_SINK, extra=()):
    bodies = {"main": main, "source": _source(), "sink": FunctionBuilder(entry=SINK).ret(), **dict(extra)}
    if engine == "legacy":
        return [root for (name, label), root in analyze_program(bodies, provider).items()
                if name == "main" and label == "sink.arg0"]
    run = analyze_summaries(list(bodies.values()), provider, names=NAMES)
    return [root for root in run.roots if root.function_byte_offset == MAIN and root.label == "sink.arg0"]


def _sound(roots, *, origin="source.ret"):
    """Every root names the origin it may carry, or says it is incomplete."""
    assert roots, "the sink occurrence was dropped"
    return all(origin in root.reached_origin_labels or not root.is_effectively_complete for root in roots)


def _incomplete(roots):
    assert roots, "the sink occurrence was dropped"
    return all(not root.is_effectively_complete for root in roots)


def _main():
    return FunctionBuilder(entry=MAIN).sub_rsp(0x28)


# -- A1: calls, partial and conditional overwrites --------------------------

CROSSING = {
    # rcx = 0; call opaque; jmp sink
    "opaque_then_tail": lambda: _main().ins(copy(reg(RCX), const(0))).call(OPAQUE).add_rsp(0x28).tail_call(SINK),
    # rcx = 0; call opaque; call sink
    "opaque_then_call": lambda: _main().ins(copy(reg(RCX), const(0))).call(OPAQUE).call(SINK).add_rsp(0x28).ret(),
    # sink(entry rcx) after an opaque call: the ENTRY answer crosses it
    "entry_across_call": lambda: _main().call(OPAQUE).call(SINK).add_rsp(0x28).ret(),
}


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("case", sorted(CROSSING))
def test_an_opaque_call_between_leaves_the_sink_incomplete(case, engine):
    assert _incomplete(_roots(CROSSING[case](), engine))


@pytest.mark.parametrize("engine", ENGINES)
def test_a_partial_overwrite_after_the_containing_write(engine):
    """rcx = 0; call source; cl = al; call sink -- the sink reads the source's byte."""
    main = (_main().ins(copy(reg(RCX), const(0))).call(SOURCE).ins(copy(reg(RCX, 1), reg(RAX, 1)))
            .call(SINK).add_rsp(0x28).ret())
    assert _sound(_roots(main, engine))


@pytest.mark.parametrize("engine", ENGINES)
def test_a_conditional_overwrite_does_not_lose_to_the_dominating_write(engine):
    """rcx = 0; if (zf) { call source; rcx = rax }; call sink."""
    main = (_main().ins(copy(reg(RCX), const(0))).cbranch("join", reg(ZF, 1))
            .call(SOURCE).ins(copy(reg(RCX, 4), reg(RAX, 4))).label("join").call(SINK).add_rsp(0x28).ret())
    assert _sound(_roots(main, engine))


@pytest.mark.parametrize("engine", ENGINES)
def test_a_write_reached_through_a_backedge_counts_as_between(engine):
    """rcx = 0; loop: call sink; call source; rcx = rax; if (zf) goto loop.
    rcx = 0 dominates the sink and is its only candidate, but the source's
    value reaches the sink on the second iteration."""
    main = (_main().ins(copy(reg(RCX), const(0))).label("loop").call(SINK).call(SOURCE)
            .ins(copy(reg(RCX, 4), reg(RAX, 4))).cbranch("loop", reg(ZF, 1)).add_rsp(0x28).ret())
    assert _sound(_roots(main, engine))


@pytest.mark.parametrize("engine", ENGINES)
def test_a_callother_between_is_a_barrier(engine):
    """rcx = 0; CALLOTHER (no model: may change any state); jmp sink."""
    main = (_main().ins(copy(reg(RCX), const(0))).ins(op("CALLOTHER", [const(0x77, 4)]))
            .add_rsp(0x28).tail_call(SINK))
    assert _incomplete(_roots(main, engine))


@pytest.mark.parametrize("engine", ENGINES)
def test_an_unresolved_indirect_branch_proves_no_path(engine):
    """rcx = 0; BRANCHIND rax (no targets: the successor graph is incomplete); jmp sink."""
    main = (_main().ins(copy(reg(RCX), const(0))).ins(op("BRANCHIND", [reg(RAX)]))
            .add_rsp(0x28).tail_call(SINK))
    assert _incomplete(_roots(main, engine))


def test_a_proven_callee_write_to_the_sink_register_is_not_hidden():
    """rcx = 0; call helper (helper: call source; rcx = rax); call sink --
    the helper's proven write is a modeled row, invisible to the old lookup."""
    helper = FunctionBuilder(entry=HELPER).sub_rsp(0x28).call(SOURCE).ins(copy(reg(RCX, 4), reg(RAX, 4))) \
        .add_rsp(0x28).ret()
    main = _main().ins(copy(reg(RCX), const(0))).call(HELPER).call(SINK).add_rsp(0x28).ret()
    assert _sound(_roots(main, "summary", extra={"helper": helper}))


# -- A1: memory spans -------------------------------------------------------

@pytest.mark.parametrize("engine", ENGINES)
def test_a_write_through_another_pointer_may_alias_the_sink_bytes(engine):
    """*rdx = 0; *r8 = 1; sink(*rdx) -- rdx and r8 may point to the same bytes:
    the store through rdx is not provably the sink's value."""
    main = _main().ins(store(reg(RDX), const(0, 4))).ins(store(reg(R8), const(1, 4))).call(SINK).add_rsp(0x28).ret()
    assert _incomplete(_roots(main, engine, _memory_sink(RDX)))


# -- A4: the inputs of a decision -------------------------------------------

@pytest.mark.parametrize("engine", ENGINES)
def test_a_decision_input_read_across_a_call_is_unknown(engine):
    """rcx = rsp + 0x30; call opaque; rdx = rcx; *(rsp + 0x30) = 0; sink(*rdx) --
    nothing lies between rdx = rcx and the sink, and the slot's last write
    follows the call, but rdx's value comes from a read of rcx across the call:
    the pointer (and so the sink's bytes) is unknown, not the slot."""
    main = (_main().ins(add(reg(RCX), reg(RSP), const(0x30))).call(OPAQUE).ins(copy(reg(RDX), reg(RCX)))
            .ins(add(reg(RAX), reg(RSP), const(0x30)), store(reg(RAX), const(0, 4))).call(SINK).add_rsp(0x28).ret())
    assert _incomplete(_roots(main, engine, _memory_sink(RDX)))


# -- A5 / A6: an unbindable sink is an unbound root, never complete or lost --

def test_an_operation_root_is_unbound_whatever_the_operation_reads():
    """Binders root at an operation only when they could not bind the state; an
    operation with data inputs (a sink consuming a computed target, say) is
    still unbound -- the old rule counted only input-less operations."""
    normalized = normalize(_main().ins(copy(reg(RDX), reg(RCX))).add_rsp(0x28).ret())
    graph = normalized.dependencies
    (node,) = [node for node in normalized.memory_graph.action_nodes
               if graph.node(node).kind is NodeKind.OPERATION and graph.node(node).key.endswith(":COPY")]
    assert graph.backward_reachable((node,))[1:], "the operation reads RCX"
    assert _unbound_roots(normalized, (node,)) == 1


@pytest.mark.parametrize("engine", ENGINES)
def test_an_unresolvable_memory_selector_keeps_its_root(engine):
    """sink(*rdx) with rdx clobbered by an opaque call: no state to bind -- an
    unbound, incomplete root in both engines (the legacy engine dropped it)."""
    main = _main().ins(copy(reg(RDX), const(DATA_BASE))).call(OPAQUE).call(SINK).add_rsp(0x28).ret()
    assert _incomplete(_roots(main, engine, _memory_sink(RDX)))


def test_two_occurrences_on_one_entry_value_stay_two_roots():
    """if (zf) sink(rcx) else sink(rcx): both bind the ENTRY rcx -- two roots."""
    main = (_main().cbranch("other", reg(ZF, 1)).call(SINK).add_rsp(0x28).ret()
            .label("other").call(SINK).add_rsp(0x28).ret())
    roots = _roots(main, "summary")
    assert len({root.occurrence_ordinal for root in roots}) == 2


# -- the barrier itself (view level: no other incompleteness hides a rule) --

def _view(main):
    (evidence,) = summary_inputs([main], image=False).evidences
    normalized = FunctionNormalizer().normalize(evidence.unit)
    return _FunctionView(ConfiguredFunctionAnalysis(evidence, normalized, EMPTY_OBSERVED_BOUNDARIES, ()))


def _keys(view, opcode):
    return sorted((key for key, (_, operation) in view.operations.items() if operation.opcode == opcode),
                  key=view.position)


def _register(view, offset, size=8):
    return _register_span(view, PhysicalRegisterSlice(offset, size))


def _written(view, key):
    """The one definition an operation writes."""
    (found,) = [index for index, row in enumerate(view.memory.definitions) if row.operation_key == key]
    return found


def _rdx_slot(view, sink_key):
    """The bytes ``[rdx]`` names at the sink (rdx = its entry value)."""
    selector = PhysicalMemorySlice(PhysicalRegisterSlice(RDX, 8), 0, 4)
    (span,) = _FunctionPhysicalStateBackend(view).memory_candidates(selector, view.position(sink_key))
    return span


def test_a_store_through_another_pointer_is_an_alias_barrier():
    view = _view(_main().ins(store(reg(RDX), const(0, 4))).ins(store(reg(R8), const(1, 4))).call(SINK)
                 .add_rsp(0x28).ret())
    first = _keys(view, "STORE")[0]
    sink = _keys(view, "CALL")[0]
    assert view.state_barrier(_rdx_slot(view, sink), first, sink, own_definition_id=_written(view, first))         == "alias-write"


def test_an_unresolved_store_is_a_barrier_for_memory_only():
    """*rdx = 0; rax = rcx * r9; *rax = 1 (no affine address); sink."""
    view = _view(_main().ins(store(reg(RDX), const(0, 4))).ins(op("INT_MULT", [reg(RCX), reg(R9)], reg(RAX)))
                 .ins(store(reg(RAX), const(1, 4))).call(SINK).add_rsp(0x28).ret())
    assert view.memory.unresolved_writes
    first = _keys(view, "STORE")[0]
    sink = _keys(view, "CALL")[0]
    assert view.state_barrier(_rdx_slot(view, sink), first, sink, own_definition_id=_written(view, first))         == "unresolved-write"
    assert view.state_barrier(_register(view, RCX), None, sink) is None   # a register is not memory


def test_a_write_after_the_position_in_its_own_block_reaches_it_through_the_backedge():
    """rcx = 0; loop: { rdx = rcx; rcx = rax } (one instruction, one block);
    if (zf) goto loop -- the write of rcx follows the read lexically but
    reaches it on the next iteration."""
    view = _view(_main().ins(copy(reg(RCX), const(0))).label("loop")
                 .ins(copy(reg(RDX), reg(RCX)), copy(reg(RCX), reg(RAX))).cbranch("loop", reg(ZF, 1))
                 .add_rsp(0x28).ret())
    first, read, write = _keys(view, "COPY")[:3]
    assert view.operation_blocks[read] == view.operation_blocks[write]
    assert view.state_barrier(_register(view, RCX), first, read, own_definition_id=_written(view, first)) == "write"


def test_the_relational_scan_refuses_across_a_callother():
    """*rdx = 0; CALLOTHER; sink: the raw-STORE relation scan never sees past it."""
    view = _view(_main().ins(store(reg(RDX), const(0, 4))).ins(op("CALLOTHER", [const(0x77, 4)])).call(SINK)
                 .add_rsp(0x28).ret())
    assert view.keys_between(_keys(view, "STORE")[0], _keys(view, "CALL")[0]) is None
    plain = _view(_main().ins(store(reg(RDX), const(0, 4))).ins(copy(reg(RAX), const(1))).call(SINK)
                  .add_rsp(0x28).ret())
    assert plain.keys_between(_keys(plain, "STORE")[0], _keys(plain, "CALL")[0]) is not None


def test_a_read_with_call_debt_is_not_followed():
    """rcx = 0; call opaque; rdx = rcx: rdx's input is not the constant."""
    view = _view(_main().ins(copy(reg(RCX), const(0))).call(OPAQUE).ins(copy(reg(RDX), reg(RCX)))
                 .add_rsp(0x28).ret())
    assert view.definition_for_span(_keys(view, "COPY")[-1], _register(view, RCX)) is None
    clean = _view(_main().ins(copy(reg(RCX), const(0))).ins(copy(reg(RDX), reg(RCX))).add_rsp(0x28).ret())
    assert clean.definition_for_span(_keys(clean, "COPY")[-1], _register(clean, RCX)) is not None


def test_a_call_crosses_a_span_exactly_as_a_read_would():
    """sub rsp; call opaque; sink: the call's restored shape keeps RSP (the
    contract the reads' call-clobber rows use), so RSP's state stands; RCX
    is not kept."""
    view = _view(_main().call(OPAQUE).call(SINK).add_rsp(0x28).ret())
    sub, sink = _keys(view, "INT_SUB")[0], _keys(view, "CALL")[1]
    assert view.state_barrier(_register(view, RSP), sub, sink, own_definition_id=_written(view, sub)) is None
    assert view.state_barrier(_register(view, RCX), None, sink) == "call"


def test_a_debt_on_one_input_does_not_refuse_another():
    """call opaque; t = rsp + 0x20; eax = [t]: the slot read crosses the call
    (debt), its address input t does not."""
    view = _view(_main().call(OPAQUE).ins(add(reg(RDX), reg(RSP), const(0x20)), load(reg(RAX, 4), reg(RDX)))
                 .add_rsp(0x28).ret())
    load_key = _keys(view, "LOAD")[0]
    action = view.action_ids[load_key]
    (read,) = [read for read in view.reads_of_action[action] if read.span.object_id.kind.value == "function_relative"]
    assert not view.read_settled(action, read.span)
    assert view.definition_for_span(load_key, _register(view, RDX)) is not None


# -- review r1 (Astra): loops through the consumer, the stack object, incomplete
# successors in A4, an assumed effect's own label, KILL and partial rows --------

@pytest.mark.parametrize("engine", ENGINES)
def test_an_earlier_execution_of_the_consuming_call_counts(engine):
    """rcx = 0; loop: call sink; if (zf) goto loop -- sink itself calls source
    and leaves its result in RCX: the second consumption reads it."""
    sink = FunctionBuilder(entry=SINK).sub_rsp(0x28).call(SOURCE).ins(copy(reg(RCX, 4), reg(RAX, 4))) \
        .add_rsp(0x28).ret()
    main = (_main().ins(copy(reg(RCX), const(0))).label("loop").call(SINK).cbranch("loop", reg(ZF, 1))
            .add_rsp(0x28).ret())
    assert _sound(_roots(main, engine, extra={"sink": sink}))


@pytest.mark.parametrize("engine", ENGINES)
def test_an_entry_pointer_may_point_at_a_global(engine):
    """*rdx = 0; *global = 1; sink(*rdx) -- the globals-disjoint-from-stack
    assumption separates constant addresses from THE stack object only, never
    from an entry pointer's object."""
    main = (_main().ins(store(reg(RDX), const(0, 4))).ins(store(const(DATA_BASE), const(1, 4)))
            .call(SINK).add_rsp(0x28).ret())
    assert _incomplete(_roots(main, engine, _memory_sink(RDX)))


def test_no_input_is_followed_over_an_incomplete_successor_graph():
    """rcx = 8; rdx = rcx; BRANCHIND rax (no targets: it may jump back)."""
    view = _view(_main().ins(copy(reg(RCX), const(8))).ins(copy(reg(RDX), reg(RCX)))
                 .ins(op("BRANCHIND", [reg(RAX)])).add_rsp(0x28).ret())
    assert view.definition_for_span(_keys(view, "COPY")[-1], _register(view, RCX)) is None


def test_an_assumed_effect_binds_only_its_own_label():
    """One call, two sink labels: an assumed RCX sink and an ordinary [rdx]
    sink whose state cannot be bound (rdx clobbered): the memory root stays
    unbound although the call's operation reads RCX."""
    provider = SymbolBoundaryProvider((
        BoundaryRule("source", LANGUAGE, BoundaryKind.SOURCE, "source.ret", (PhysicalRegisterSlice(RAX, 4),), True),
        BoundaryRule("sink", LANGUAGE, BoundaryKind.SINK, "sink.arg0", (PhysicalRegisterSlice(RCX, 8),), True),
        BoundaryRule("sink", LANGUAGE, BoundaryKind.SINK, "sink.mem",
                     (PhysicalMemorySlice(PhysicalRegisterSlice(RDX, 8), 0, 4),)),
    ))
    main = _main().call(OPAQUE).ins(copy(reg(RCX), const(0))).call(SINK).add_rsp(0x28).ret()
    bodies = {"main": main, "source": _source(), "sink": FunctionBuilder(entry=SINK).ret()}
    roots = analyze_program(bodies, provider, assume_boundary_call_effects=True)
    memory = roots[("main", "sink.mem")]
    assert not memory.is_effectively_complete and memory.local_completeness.unbound_roots == 1


def test_a_partial_write_between_is_a_barrier_without_any_call():
    """rcx = 0; cl = 5; sink -- the containing write is not the sink's value."""
    view = _view(_main().ins(copy(reg(RCX), const(0))).ins(copy(reg(RCX, 1), const(5, 1))).call(SINK)
                 .add_rsp(0x28).ret())
    first = _keys(view, "COPY")[0]
    sink = _keys(view, "CALL")[0]
    assert view.state_barrier(_register(view, RCX), first, sink, own_definition_id=_written(view, first)) == "write"


def test_a_kill_between_is_a_barrier():
    """The partial write above as a KILL row (an unknown value): still a write."""
    from dataclasses import replace
    from types import SimpleNamespace
    from tdo_v2.memory_contracts import MemoryDefinitionKind

    view = _view(_main().ins(copy(reg(RCX), const(0))).ins(copy(reg(RCX, 1), const(5, 1))).call(SINK)
                 .add_rsp(0x28).ret())
    first, second = _keys(view, "COPY")[:2]
    killed = _written(view, second)
    # (the barrier's facts are built on first use: none yet, so they see the swap)
    assert getattr(view, "_state_barrier", None) is None
    view.memory = SimpleNamespace(
        definitions=tuple(replace(row, kind=MemoryDefinitionKind.KILL) if index == killed else row
                          for index, row in enumerate(view.memory.definitions)),
        unresolved_writes=view.memory.unresolved_writes, actions=view.memory.actions)
    sink = _keys(view, "CALL")[0]
    assert view.state_barrier(_register(view, RCX), first, sink, own_definition_id=_written(view, first)) == "write"



def test_the_relational_scan_relates_only_a_raw_stores_own_row():
    """*rdx = 0; rax = 1; sink -- plus a normalized row anchored at the STORE
    (a rep element ``store~e1``) on the next bytes: the scan relates the raw
    STORE's pointer only, so the row is a write it cannot place (Fable)."""
    from dataclasses import replace
    from types import SimpleNamespace

    view = _view(_main().ins(store(reg(RDX), const(0, 4))).ins(copy(reg(RAX), const(1))).call(SINK)
                 .add_rsp(0x28).ret())
    store_key, sink = _keys(view, "STORE")[0], _keys(view, "CALL")[0]
    assert view.keys_between(store_key, sink) is not None
    own = view.memory.definitions[_written(view, store_key)]
    element = replace(own, span=replace(own.span, start=own.span.start + 4), operation_key=f"{store_key}~e1")
    fresh = _view(_main().ins(store(reg(RDX), const(0, 4))).ins(copy(reg(RAX), const(1))).call(SINK)
                  .add_rsp(0x28).ret())
    fresh.memory = SimpleNamespace(definitions=fresh.memory.definitions + (element,),
                                   unresolved_writes=fresh.memory.unresolved_writes, actions=fresh.memory.actions)
    assert fresh.keys_between(store_key, sink) is None


@pytest.mark.parametrize("engine", ENGINES)
def test_a_current_definition_still_binds(engine):
    """The barrier refuses only what may be stale: rcx = 0; call sink is
    complete with no origin, and rax = source(); rcx = rax; call sink names
    the source -- never an always-refusing lookup."""
    (plain,) = _roots(_main().ins(copy(reg(RCX), const(0))).call(SINK).add_rsp(0x28).ret(), engine)
    assert plain.is_effectively_complete and plain.reached_origin_labels == ()
    (sourced,) = _roots(_main().call(SOURCE).ins(copy(reg(RCX), reg(RAX))).call(SINK).add_rsp(0x28).ret(), engine)
    assert sourced.reached_origin_labels == ("source.ret",)
    assert sourced.local_completeness.unbound_roots == 0
