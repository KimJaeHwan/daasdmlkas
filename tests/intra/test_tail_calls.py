"""Tail calls (``jmp other_function``) as boundary calls.

Ghidra flags such a BRANCH with a call flow type; the engine seeds it as a
``TailCallSeed`` (boundary recognition only, not a CALL callsite) and binds a
tail-called sink at the jump's state.
"""

from synthetic import (
    CODE_BASE, RAX, RCX, ZF,
    FunctionBuilder, _Provider, analyze_program, boundary, const, copy, ram, reg,
)
from tdo_v2._scope_contracts import _mint_orchestrator_capability
from tdo_v2._scope_envelope import open_configured_extraction
from tdo_v2.call_seeds import seed_function_calls, seed_tail_calls

MAIN, SOURCE, SINK = CODE_BASE, CODE_BASE + 0x800, CODE_BASE + 0xA00


def _functions(main):
    return {
        "main": main,
        "source": FunctionBuilder(entry=SOURCE).ins(copy(reg(RAX, 4), const(7, 4))).ret(),
        "sink": FunctionBuilder(entry=SINK).ret(),
    }


def _root(main, *, assume=False):
    provider = boundary({"source": 4}, {"sink": 4}, assume_call_effect=assume)
    roots = analyze_program(_functions(main), provider, assume_boundary_call_effects=assume)
    return roots.get(("main", "sink.arg0"))


def _direct_tail():
    """EAX = source(); ECX = EAX; jmp sink."""
    return FunctionBuilder(entry=MAIN).call(SOURCE).ins(copy(reg(RCX, 4), reg(RAX, 4))).tail_call(SINK)


def _joined_tail():
    """EAX = source(); ECX = ZF ? EAX : 0; jmp sink."""
    return (
        FunctionBuilder(entry=MAIN)
        .call(SOURCE)
        .cbranch("zero", reg(ZF, 1))
        .ins(copy(reg(RCX, 4), reg(RAX, 4)))
        .branch("join")
        .label("zero")
        .ins(copy(reg(RCX, 4), const(0, 4)))
        .label("join")
        .tail_call(SINK)
    )


def _unit(builder):
    with open_configured_extraction(_Provider([builder]), _mint_orchestrator_capability()) as env:
        (unit,) = env.iter_scoped_functions()
    return unit


def test_tail_call_is_seeded_apart_from_callsites():
    unit = _unit(_direct_tail())
    (tail,) = seed_tail_calls(unit)
    assert tail.opcode.value == "BRANCH"
    assert tail.target.coordinate.byte_offset == SINK
    callsites = seed_function_calls(unit).callsites
    assert len(callsites) == 1 and callsites[0].operation_key.endswith(":CALL")  # source only
    assert tail.operation_key not in {site.operation_key for site in callsites}


def test_branch_out_without_call_flag_is_not_a_tail_call():
    """A jump to shared code outside the function (Ghidra: plain jump)."""
    builder = FunctionBuilder(entry=MAIN).ins(copy(reg(RCX), reg(RAX))).ret()
    raw = builder.to_json()
    last = raw["instructions"][-1]
    last["operations"] = [{
        "ordinal": 0, "opcode": "BRANCH", "inputs": [ram(SINK)],
        "output_present": False, "output": None,
    }]
    last["flow_targets"] = [{"space_id": 1, "byte_offset": SINK}]
    last["flow_type"] = {**last["flow_type"], "is_call": False, "is_jump": True, "is_terminal": False}
    builder.to_json = lambda raw=raw: raw
    assert seed_tail_calls(_unit(builder)) == ()


def test_tail_called_sink_gets_a_root():
    root = _root(_direct_tail())
    assert root is not None
    assert not root.is_locally_complete  # the source call is still opaque by default


def test_tail_called_sink_with_assumed_boundaries_is_local_and_complete():
    """TEST-ONLY assumption: source writes EAX only, sink reads ECX only."""
    root = _root(_direct_tail(), assume=True)
    assert root.local_origin_labels == ("source.ret",)
    assert root.is_locally_complete


def test_joined_argument_to_tail_sink_is_unbound_by_default():
    root = _root(_joined_tail())
    assert root is not None
    assert not root.is_locally_complete
    assert root.local_completeness.unbound_roots == 1


def test_joined_argument_to_tail_sink_with_assumed_boundaries():
    root = _root(_joined_tail(), assume=True)
    assert root.local_origin_labels == ("source.ret",)
    assert root.is_locally_complete


def test_tail_called_source_has_no_root():
    """int f() { return source(); } -> jmp source: nothing local reads it."""
    main = FunctionBuilder(entry=MAIN).tail_call(SOURCE)
    provider = boundary({"source": 4}, {"sink": 4})
    roots = analyze_program(_functions(main), provider)
    assert not [key for key in roots if key[0] == "main"]
