"""One call exemption contract, two views (docs 25.83 S2c): normalize's
call_clobber rows and ``_exit_crossings`` read the same ``CallExemptions``
and keep their own below-bound semantics -- pinned around one below-bound
call (a leaf pushing into its own frame: the caller's stack below its call)."""

from synthetic import (
    CODE_BASE, DATA_BASE, R8, RBX, RCX, RDX, RSP, FunctionBuilder, add, const, load, program_units, reg, store,
    tmp,
)
from tdo_v2.call_clobber import _preserved_stack_pointers, call_exemptions
from tdo_v2.function_summary import _exit_crossings
from tdo_v2.interprocedural import analyze_units

LEAF, OPAQUE = CODE_BASE + 0x800, CODE_BASE + 0xE00
T = tmp(0x100)


def _run(offsets, target=LEAF, global_read=False):
    """caller: [rsp + d] = bl for each d; CALL target; r8b = [rsp + d] each
    (and a global byte); ret. -> (normalized, observation, reader keys)."""
    caller = FunctionBuilder().sub_rsp(0x40)
    for offset in offsets:
        caller.ins(add(T, reg(RSP), const(offset % (1 << 64))), store(T, reg(RBX, 1)))
    caller.call(target)
    for offset in offsets:
        caller.ins(add(T, reg(RSP), const(offset % (1 << 64))), load(reg(R8, 1), T))
    if global_read:
        caller.ins(load(reg(R8, 1), const(DATA_BASE + 0x40)))
    caller.add_rsp(0x40).ret()
    leaf = FunctionBuilder(entry=LEAF).push(RDX).pop(RCX).ret()
    item = analyze_units(program_units(caller, leaf))["1:1000"]
    return item.normalized, item.unit.observation


def _views(normalized, observation):
    """(read span start -> crossed by a call in normalize's rows,
    exit byte (object, offset) -> crossed by a call at the exit)."""
    rows = {}
    ssa = normalized.memory_ssa
    for read in ssa.reads:
        if read.span.size == 1 and read.span.object_id.kind.value == "function_relative":
            key = ssa.actions[read.action_id].operation_key
            rows[read.span.start] = any(row.operation_key == key and any(
                span.start <= read.span.start < span.end for span in row.spans) for row in normalized.call_clobber_reads)
    crossed = _exit_crossings(normalized, observation, normalized.scopes.resolution_context,
                              _preserved_stack_pointers, set())
    universe = crossed["label_universe"]
    exits = {}
    for key, offsets in crossed.items():
        if type(key) is tuple:
            for offset, bits in offsets.items():
                exits[(key[1].kind.value, offset)] = any(label.startswith("call:") for label in universe.decode(bits))
    return rows, exits


def test_a_below_bound_call_at_its_bound():
    """bound - 1 is clobbered, bound is kept -- in both views."""
    normalized, _ = _run((-0x20,))
    ((_, _, bound),) = normalized.call_below_bounds
    at = bound - (1 << 64) + 0x40   # (the bound as a displacement from the caller's rsp after sub rsp, 0x40)
    normalized, observation = _run((-0x20, at - 1, at))
    assert normalized.call_below_bounds[0][2] == bound
    rows, exits = _views(normalized, observation)
    assert rows[bound - 1] is True and rows[bound] is False
    assert exits.get(("function_relative", bound - 1)) is True
    assert not exits.get(("function_relative", bound), False)


def test_other_memory_is_kept_and_an_opaque_call_clobbers_all():
    normalized, observation = _run((0x10,), global_read=True)
    rows, exits = _views(normalized, observation)
    assert not any(rows.values()) and not any(exits.values())   # (the leaf keeps memory above its bound)
    normalized, observation = _run((0x10,), target=OPAQUE)
    rows, exits = _views(normalized, observation)
    assert all(rows.values()) and any(exits.values())


def test_every_view_reads_the_same_contract():
    """normalize's, a probe's and the exits' CallExemptions agree (one build)."""
    normalized, _ = _run((-0x20, 0x10))
    keys = [effect.operation_key for effect in normalized.effects]
    built = call_exemptions(keys, {key for key, _ in normalized.assumed_call_effects},
                            normalized.proven_call_effects, dict(normalized.kept_call_memory),
                            normalized.call_below_bounds)
    inputs = normalized.forward_inputs
    if inputs is not None:
        probed = call_exemptions(keys, inputs.assumed_calls, inputs.proven_call_effects, dict(inputs.kept_memory),
                                 inputs.below_bounds)
        assert probed == built
    assert built.below and built.below_keeping == frozenset(built.below)
    assert not built.memory_keeping & built.below_keeping
