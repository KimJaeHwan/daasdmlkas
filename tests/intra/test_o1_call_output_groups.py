"""(O-1, docs 25.105) A summarized call's output rows are one simultaneous
final state.

The callee writes ``[rcx+8]`` and ``[rsp+8]`` (the caller's home slot); with
entry-values-not-frame off the caller's ``rbx`` object may alias its stack, so
a LOAD of ``[rbx+8]`` after the call may see the stack row too. Whatever order
the two output rows are staged in, neither kills the other's candidate, and a
pre-call writer on a member's bytes is still killed (at the group's start). The
effect's row lists are ordered by a digest-free key (labels stable across
Bundles).
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from synthetic import (
    CODE_BASE, RAX, RBX, RCX, RDX, RSI, RSP, FunctionBuilder, add, const, copy, load, op, program_units, reg, store,
    tmp,
)
from tdo_v2 import _effect_order
from tdo_v2._call_groups import call_output_groups, output_call
from tdo_v2.effects import EffectKind, ObservedEffect
from tdo_v2.interprocedural import analyze_units, function_key_of
from tdo_v2.model import ResolvedStorage, StorageObjectId
from tdo_v2.span_geometry import ByteSpan, StorageObjectKind

CALLEE = CODE_BASE + 0x800


def _callee():
    """rax = rdx * rsi; [rcx+8] = rax; [rsp+8] = rax; ret."""
    a, b = tmp(0x400), tmp(0x408)
    return (FunctionBuilder(entry=CALLEE).ins(op("INT_MULT", [reg(RDX), reg(RSI)], reg(RAX)))
            .ins(add(a, reg(RCX), const(8)), store(a, reg(RAX)))
            .ins(add(b, reg(RSP), const(8)), store(b, reg(RAX))).ret())


def _caller():
    """rbx = rcx; call callee; rax = [rbx+8]; ret."""
    t = tmp(0x500)
    builder = FunctionBuilder().ins(copy(reg(RBX), reg(RCX))).sub_rsp(0x28).call(CALLEE).add_rsp(0x28)
    return builder.ins(add(t, reg(RBX), const(8)), load(reg(RAX), t)).ret()


def _call_writers(monkeypatch, reverse):
    """The call's staged-row writers (``~push`` aside) of the caller's
    ``[rbx+8]`` LOAD, with the effect's lists in the canonical order or
    reversed."""
    original = _effect_order._ordered

    def ordered(items):
        found = original(items)
        return tuple(reversed(found)) if reverse else found

    monkeypatch.setattr(_effect_order, "_ordered", ordered)
    units = program_units(_caller(), _callee())
    item = analyze_units(units, assume_entry_values_not_frame=False)[function_key_of(1, CODE_BASE)]
    row = units[0].observation.instructions[-2]    # (rax = [rbx+8]; the last row is the ret)
    site = f"{row.address.space_id:x}:{row.address.byte_offset:x}:"
    loads = [read for read in item.normalized.may_alias_reads if read.operation_key.startswith(site)]
    writers = [writer for read in loads for writer in read.writers if "~" in writer and not writer.endswith("~push")]
    monkeypatch.setattr(_effect_order, "_ordered", original)
    return item, sorted(writers)


@pytest.mark.parametrize("engine,check", [("sparse", "dense"), ("dense", "sparse")])
def test_no_output_row_kills_a_sibling_in_either_order(monkeypatch, engine, check):
    """The stack row may reach the rbx-object LOAD (the rcx row is its SSA
    writer): in both staging orders and both may-alias engines (cross-checked)
    -- before O-1 the rcx row, staged last, killed it."""
    from tdo_v2._sparse_dataflow import DATAFLOW_CROSSCHECK_ENV, DATAFLOW_ENGINE_ENV

    monkeypatch.setenv(DATAFLOW_ENGINE_ENV, engine)
    monkeypatch.setenv(DATAFLOW_CROSSCHECK_ENV, check)
    for reverse in (False, True):
        _, writers = _call_writers(monkeypatch, reverse)
        assert len(writers) == 1, (reverse, writers)


def test_the_exit_crossings_keep_every_sibling_in_either_order(monkeypatch):
    """The caller's own summary (``_exit_crossings``) is invariant under the
    call rows' order: the same number of ``alias:`` call-row crossings."""
    counts = []
    for reverse in (False, True):
        item, _ = _call_writers(monkeypatch, reverse)
        labels = {label for exit_ in item.summary.exits for run in exit_.runs
                  for label in getattr(run, "crossed", ()) if label.startswith("alias:") and "~" in label
                  and not label.endswith("~push")}
        counts.append(len(labels))
    assert counts[0] == counts[1], counts


# -- the group helper ------------------------------------------------------------------


def test_output_rows_by_their_tags():
    assert output_call("1:100:2:CALL~0") == "1:100:2:CALL"
    assert output_call("1:100:2:CALL~u3") == "1:100:2:CALL"
    assert output_call("1:100:2:CALL~ov1") == "1:100:2:CALL"
    for key in ("1:100:2:CALL~push", "1:100:2:CALL~ld0", "1:100:2:CALL~in0", "1:100:2:CALL~cr1", "1:100:2:CALL~iu0",
                "1:100:2:CALL~edge", "1:100:2:CALL~sink0", "1:100:2:CALL", "1:100:0:STORE", "1:100:2:CALL~e0"):
        assert output_call(key) is None, key


def _span(kind=StorageObjectKind.FUNCTION_RELATIVE, start=0, size=8, space=1):
    return ByteSpan(StorageObjectId(kind, _scope(), space), start, size)


def _scope(digest=b"\x00" * 32):
    from tdo_v2.model import StorageScopeId, StorageScopeKind

    return StorageScopeId(StorageScopeKind.FUNCTION, digest)


def _write(key, *, read=None):
    span = _span(start=8)
    reads = (ResolvedStorage(read),) if read is not None else ()
    return ObservedEffect(key, EffectKind.COPY, reads=reads, writes=(ResolvedStorage(span),))


def test_a_contiguous_group_hoists_and_the_fail_safes_kill_nothing():
    call = "1:100:2:CALL"
    plain = (_write("1:90:0:STORE"), _write(call + "~0"), _write(call + "~u0"), _write(call + "~ov0"))
    groups = call_output_groups(plain)
    assert groups[call + "~0"] == (1, (1, 2, 3)) and groups[call + "~ov0"] == (1, (1, 2, 3))
    assert "1:90:0:STORE" not in groups
    split = (_write(call + "~0"), _write("1:90:0:STORE"), _write(call + "~u0"))
    assert call_output_groups(split) == {call + "~0": None, call + "~u0": None}
    reading = (_write(call + "~0"), _write(call + "~u0", read=_span(start=64)))
    assert call_output_groups(reading) == {call + "~0": None, call + "~u0": None}
    single = (_write(call + "~0"),)
    assert call_output_groups(single) == {}


def test_a_no_kill_member_keeps_its_bytes_candidates():
    from tdo_v2.may_alias import _ObjectState, _hoisted_kill

    span = _span(start=8)
    state = {span.object_id: _ObjectState(frozenset(), {8: frozenset({"w"})})}
    effect = _write("1:100:2:CALL~0")
    policy = SimpleNamespace(no_kill_writers=frozenset({"1:100:2:CALL~0"}))
    assert _hoisted_kill(state, effect, policy)[span.object_id].bytes[8] == frozenset({"w"})
    policy = SimpleNamespace(no_kill_writers=frozenset())
    assert 8 not in _hoisted_kill(state, effect, policy)[span.object_id].bytes


# -- the digest-free order ----------------------------------------------------------------


def _register(start, size=8, digest=b"\x01" * 32):
    from tdo_v2.model import StorageScopeId, StorageScopeKind

    return ByteSpan(StorageObjectId(StorageObjectKind.REGISTER_FILE, StorageScopeId(StorageScopeKind.PROGRAM, digest), 0),
                    start, size)


def test_the_stable_key_ignores_scope_digests_and_keeps_every_value_field():
    from tdo_v2._effect_order import _Inexact, _stable

    assert _stable(_register(8, digest=b"\x01" * 32)) == _stable(_register(8, digest=b"\x02" * 32))
    assert _stable(("offset_reg", _register(8), 8)) != _stable(("offset_reg", _register(8), 16))
    assert _stable(("same_reg", _register(8), True)) != _stable(("same_reg", _register(8), False))
    assert _stable((1, 8)) != _stable((8, 1))
    with pytest.raises(_Inexact):
        _stable(_span())


def test_an_inexact_list_keeps_its_order_and_an_exact_one_is_sorted():
    from tdo_v2._effect_order import _ordered

    relative = (_span(start=16), _span(start=0))
    assert _ordered(relative) == relative
    registers = (_register(16), _register(0), _register(16))
    assert _ordered(registers) == (_register(0), _register(16))


def test_the_canonicaliser_leaves_stand_ins_alone():
    from tdo_v2._effect_order import canonical_effect

    stand_in = SimpleNamespace(runs=(), memory_runs=())
    assert canonical_effect(stand_in) is stand_in
    assert canonical_effect(None) is None


# -- review r1 pins ----------------------------------------------------------------------


ENGINES = [("sparse", "dense"), ("dense", "sparse")]


def _engine(monkeypatch, engine, check):
    from tdo_v2._sparse_dataflow import DATAFLOW_CROSSCHECK_ENV, DATAFLOW_ENGINE_ENV

    monkeypatch.setenv(DATAFLOW_ENGINE_ENV, engine)
    monkeypatch.setenv(DATAFLOW_CROSSCHECK_ENV, check)


def _caller_with_pre_call_store():
    """rbx = rcx; sub rsp; [rsp] = 1 (the bytes the callee's stack row writes);
    call; add rsp; rax = [rbx+8]; ret."""
    t = tmp(0x500)
    builder = (FunctionBuilder().ins(copy(reg(RBX), reg(RCX))).sub_rsp(0x28)
               .ins(store(reg(RSP), const(1, 8))).call(CALLEE).add_rsp(0x28))
    return builder.ins(add(t, reg(RBX), const(8)), load(reg(RAX), t)).ret()


def _final_load_writers(monkeypatch, no_kill=False):
    """Writers of the ``[rbx+8]`` LOAD of ``_caller_with_pre_call_store``;
    ``no_kill``: the call's relative-object members are uncertain, no-kill
    writers."""
    from tdo_v2 import normalize

    if no_kill:
        original = normalize.derive_may_alias_reads

        def derive(*args, **kwargs):
            members = {effect.operation_key for block in args[0].blocks for effect in block.effects
                       if output_call(effect.operation_key) is not None
                       and any(type(item) is ResolvedStorage and item.span.object_id.kind
                               is StorageObjectKind.FUNCTION_RELATIVE for item in effect.writes)}
            kwargs["uncertain_writers"] = frozenset(kwargs.get("uncertain_writers", ())) | members
            kwargs["no_kill_writers"] = frozenset(kwargs.get("no_kill_writers", ())) | members
            return original(*args, **kwargs)

        monkeypatch.setattr(normalize, "derive_may_alias_reads", derive)
    units = program_units(_caller_with_pre_call_store(), _callee())
    item = analyze_units(units, assume_entry_values_not_frame=False)[function_key_of(1, CODE_BASE)]
    row = units[0].observation.instructions[-2]
    site = f"{row.address.space_id:x}:{row.address.byte_offset:x}:"
    return sorted(writer for read in item.normalized.may_alias_reads if read.operation_key.startswith(site)
                  for writer in read.writers)


@pytest.mark.parametrize("engine,check", ENGINES)
def test_a_pre_call_writer_on_a_members_bytes_is_killed(monkeypatch, engine, check):
    """The pre-call store to the callee's stack-row bytes reaches the rbx
    object only until the call's rows: the group's hoisted kill removes it,
    the stack row's own candidate stays (both engines; all-kills-off or a
    dropped hoist leaves the store)."""
    _engine(monkeypatch, engine, check)
    writers = _final_load_writers(monkeypatch)
    assert not any(writer.endswith(":STORE") for writer in writers), writers
    assert any("~" in writer and not writer.endswith("~push") for writer in writers), writers


@pytest.mark.parametrize("engine,check", ENGINES)
def test_a_no_kill_member_kills_nothing_and_keeps_its_uncertain_gen(monkeypatch, engine, check):
    """The call's relative-object members are uncertain, no-kill writers:
    their hoisted kills are filtered like ``_written``'s (dense and sparse),
    so the pre-call store survives (it is killed when they kill)."""
    _engine(monkeypatch, engine, check)
    writers = _final_load_writers(monkeypatch, no_kill=True)
    assert any(writer.endswith(":STORE") for writer in writers), writers


def _normalised_crossings(item):
    import re

    label = re.compile(r"(CALL|BRANCH|CBRANCH)~(?:\d+|u\d+|ov\d+|ld\d+)")
    return sorted((exit_.block_key, run.span.object_id.kind.value, run.span.start, run.span.size,
                   tuple(sorted(label.sub(r"\1~*", crossed) for crossed in getattr(run, "crossed", ()))))
                  for exit_ in item.summary.exits for run in exit_.runs
                  if run.span.object_id.kind is not StorageObjectKind.FUNCTION_UNIQUE)


def test_the_exit_crossings_are_the_same_set_in_either_order(monkeypatch):
    """Per exit run, the crossing labels (staged labels normalised) are equal
    in both staging orders, and the call's rows cross (review r1)."""
    found = []
    for reverse in (False, True):
        item, _ = _call_writers(monkeypatch, reverse)
        found.append(_normalised_crossings(item))
    assert found[0] == found[1]
    assert any(any(label.startswith("alias:") and "CALL~*" in label for label in run[4]) for run in found[0])


def _run(anchor_start, space=1):
    from tdo_v2.call_summary_effects import AnchoredSpan, ProvenMemoryRun

    return ProvenMemoryRun(AnchoredSpan(_register(anchor_start), 8, 8, space), (), (), False)


def test_the_wrapper_canonicalises_every_returned_effect(monkeypatch):
    """Sink-only and noreturn shapes return early inside the derivation: the
    public wrapper orders their lists too (review r1)."""
    from tdo_v2 import call_summary_effects
    from tdo_v2.call_summary_effects import AnchoredSpan, ProvenCallEffect, ProvenSinkDemand

    late, early = AnchoredSpan(_register(32), 0, 8, 1), AnchoredSpan(_register(8), 0, 8, 1)
    demand = ProvenSinkDemand("sink0", (), (late, early), (), True)
    effect = ProvenCallEffect("1:1800", (), (), sink_demands=(demand,), noreturn=True, escapes_stack=True)
    monkeypatch.setattr(call_summary_effects, "_derive_proven_call_effect", lambda *a, **k: effect)
    summary = SimpleNamespace(control_support=())
    result = call_summary_effects.derive_proven_call_effect(summary)
    assert result.sink_demands[0].loads == (early, late)


def test_the_composed_lists_are_canonicalised():
    """``_compose_fixed_memory`` re-lists the runs: the result is ordered
    again (review r1: the canonicaliser after each transformation)."""
    from tdo_v2.call_summary_effects import ProvenCallEffect, _compose_fixed_memory

    from tdo_v2.call_summary_effects import AnchoredSpan, ProvenMemoryRun

    effect = ProvenCallEffect("1:1800", (), (), memory_runs=(_run(32), _run(8)))
    fixed = ProvenMemoryRun(AnchoredSpan(_register(8), 0, 8, 1), (), (), False)
    member = ProvenCallEffect("1:1900", (), (), memory_runs=(fixed,), preserves_memory=True)
    composed = _compose_fixed_memory(effect, ((0, member), (1, member)))
    assert [(run.write.anchor.start, run.write.displacement) for run in composed.memory_runs] ==         [(8, 0), (8, 8), (32, 8)]


def test_a_real_effect_lists_its_runs_in_the_digest_free_order():
    """The callee's two memory runs (rsp-anchored, rcx-anchored) come out
    anchor-ascending, and another program record (other scope digests)
    changes neither their order nor their encoding."""
    from tdo_v2._effect_order import _stable

    from synthetic import X64, register_evidence

    effects, scopes = [], []
    for registers in (None, register_evidence(X64)):   # (another program record: other digests)
        units = program_units(_caller(), _callee(), registers=registers)
        item = analyze_units(units, assume_entry_values_not_frame=False)[function_key_of(1, CODE_BASE)]
        (effect,) = item.proven.values()
        effects.append(effect)
        scopes.append(units[0].scopes.program.scope)
    starts = [run.write.anchor.start for run in effects[0].memory_runs]
    assert starts == sorted(starts) and len(starts) == 2
    assert [_stable(run) for run in effects[0].memory_runs] == [_stable(run) for run in effects[1].memory_runs]
    assert scopes[0] != scopes[1]


def test_the_stable_key_separates_enum_types_and_value_payloads():
    from enum import Enum

    from tdo_v2._effect_order import _stable

    class A(Enum):
        X = "x"

    class B(Enum):
        X = "x"

    assert _stable(A.X) != _stable(B.X)
    assert _stable(("nonstack", 8, True, ("a",))) != _stable(("nonstack", 8, False, ("a",)))
    assert _stable(("nonstack", 8, True, ("a",))) != _stable(("nonstack", 16, True, ("a",)))
