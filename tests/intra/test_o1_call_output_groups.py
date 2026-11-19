"""(O-1, docs 25.105) A summarized call's output rows are one simultaneous
final state.

The callee writes ``[rcx+8]`` and ``[rsp+8]`` (the caller's home slot); with
entry-values-not-frame off the caller's ``rbx`` object may alias its stack, so
a LOAD of ``[rbx+8]`` after the call may see the stack row too. Whatever order
the two output rows are staged in, neither kills the other's candidate; a later
ordinary write still kills both. The effect's row lists are ordered by a
digest-free key (labels stable across Bundles).
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
    scope = SimpleNamespace(kind=SimpleNamespace(value="function"), digest=b"x")
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
