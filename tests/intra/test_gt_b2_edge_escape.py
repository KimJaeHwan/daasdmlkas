"""(G-T G3b-2, docs 25.107) A conditional tail's stack escape at its edge block.

``jcc other_function`` with a local fallthrough runs its taken transfer only on
the outcome edge block ``E``: an escape it makes (a held frame slot while it
leaves, or a proven effect that escapes) is recorded at ``site~edge`` -- ``E``'s
one operation, no successor -- not at the raw CBRANCH in ``S``. The
fallthrough path therefore regains ``private_read`` / ``private_before``;
``private_write`` never changes (backward reachability from ``S``'s end and from
``E`` is the same set). A CBRANCH leaving without an edge block keeps the raw
escape.
"""

import pytest
from synthetic import (
    CODE_BASE, R9, RCX, RDI, RDX, RSP, ZF, FunctionBuilder, add, const, load, program_units, reg, store, tmp,
)
from test_gt_conditional_tails import _to
from test_held_frame_slots import T2, _analyze, _key, _spill

from tdo_v2 import may_alias

TARGET = CODE_BASE + 0x900


def _held(*, loop=False, eligible=True, before=None):
    """sub rsp; [rsp+8] = rsp+0x20 (held; or ``before``); [top:] jz TARGET;
    [rcx] = rdi; (loop: jz top;) r9 = [rsp+0x18]; add rsp; ret."""
    builder = FunctionBuilder().sub_rsp(0x28)
    builder = before(builder) if before is not None else _spill(builder)
    if loop:
        builder.label("top")
    builder.cbranch("out", reg(ZF, 1)).ins(store(reg(RCX), reg(RDI)))
    if loop:
        builder.cbranch("top", reg(ZF, 1))
    builder.ins(add(T2, reg(RSP), const(0x18)), load(reg(R9), T2)).label("out").add_rsp(0x28).ret()
    builder = _to(builder, 2, TARGET)
    if not eligible:
        raw = builder.to_json()
        raw["instructions"][2]["flow_targets"] = []   # (observed flow disagrees: no edge block)
        builder.to_json = lambda raw=raw: raw
    return builder


def _keys(builder, loop=False):
    site = _key(builder, 2, 0, "CBRANCH")
    write = _key(builder, 3, 0, "STORE")
    read = _key(builder, 5 if loop else 4, 1, "LOAD")
    return site, write, read


def _writes_reach(analyzed, write, read) -> bool:
    return any(write in row.writers for row in analyzed.normalized.may_alias_reads if row.operation_key == read)


def _escape(tmp_path, monkeypatch, builder, **options):
    """(analyzed, the final normalization's ``_Escape``)."""
    from tdo_v2.may_alias import _stack_escapes

    monkeypatch.setenv("TDO_V2_FORWARD", "1")   # (the normalization keeps its escape inputs)
    analyzed = _analyze(tmp_path, builder, **options)
    inputs = analyzed.normalized.forward_inputs
    _, escape, without, _, _ = _stack_escapes(
        inputs.effect_unit, inputs.observation, inputs.context, inputs.address_spaces, inputs.quiet_calls,
        dict(inputs.observed_calls), inputs.escaping_calls, inputs.opaque_calls,
        held=(inputs.assumed_calls, frozenset(), inputs.wild_objects, inputs.private_frame_above,
              inputs.assume_globals_disjoint_from_stack))
    return analyzed, escape, without


def test_an_acyclic_fallthrough_regains_its_private_frame(tmp_path, monkeypatch):
    """Held slot + ``jz TARGET``: the escape is at ``site~edge``; the
    fallthrough's frame read sees no write through rcx. (``private_write``
    comes from the run without held slots -- a held store is no write escape,
    docs 25.78 -- so it is true here before and after.)"""
    builder = _held()
    site, write, read = _keys(builder)
    analyzed, escape, _ = _escape(tmp_path, monkeypatch, builder)
    assert site in escape.edge_sites and f"{site}~edge" in escape.known
    assert f"{site}~edge" in escape.escaped and site not in escape.escaped
    assert escape.private_read(read) and escape.private_before(read)
    assert escape.private_read(write) and escape.private_before(write)
    spill = _key(builder, 1, 2, "STORE")
    assert escape.private_read(site) and escape.private_read(spill)
    assert not _writes_reach(analyzed, write, read)


def test_a_loop_fallthrough_reads_private_but_writes_still_reach_the_edge(tmp_path, monkeypatch):
    """memset shape with a held slot: no path to the loop body or the read
    passes ``E`` (``private_read`` / ``private_before`` true -- were false)."""
    builder = _held(loop=True)
    site, write, read = _keys(builder, loop=True)
    analyzed, escape, _ = _escape(tmp_path, monkeypatch, builder)
    assert escape.private_read(write) and escape.private_before(write)
    assert escape.private_read(read) and escape.private_before(read)
    assert not _writes_reach(analyzed, write, read)


def test_a_non_eligible_conditional_exit_keeps_the_raw_escape(tmp_path, monkeypatch):
    """The same jump without an edge block (observed flow disagrees): the raw
    CBRANCH escapes while the slot is held, the fallthrough is post-escape."""
    builder = _held(eligible=False)
    site, write, read = _keys(builder)
    analyzed, escape, _ = _escape(tmp_path, monkeypatch, builder)
    assert escape.edge_sites == frozenset()
    assert not escape.private_read(read)
    assert _writes_reach(analyzed, write, read)


def test_a_stack_address_stored_before_the_branch_escapes_on_both_paths(tmp_path, monkeypatch):
    """[rdx] = rsp + 0x20 before ``S``: an escape on every path, the edge
    changes nothing for the fallthrough."""
    def leak(builder):
        return builder.ins(add(tmp(0x100), reg(RSP), const(0x20)), store(reg(RDX), tmp(0x100)))

    builder = _held(before=leak)
    site, write, read = _keys(builder)
    analyzed, escape, _ = _escape(tmp_path, monkeypatch, builder)
    assert not escape.private_read(read)
    assert _writes_reach(analyzed, write, read)


def test_an_opaque_call_after_the_read_leaves_it_private_without_the_opaque_assumption(tmp_path, monkeypatch):
    """opaque-callees-leave-no-stack-addresses off: a later opaque call
    escapes, the conditional tail still only at its edge -- the fallthrough
    read before the call stays private (both escape runs use the edge)."""
    def build():
        builder = FunctionBuilder().sub_rsp(0x28)
        builder = _spill(builder)
        builder.cbranch("out", reg(ZF, 1)).ins(store(reg(RCX), reg(RDI)))
        builder.ins(add(T2, reg(RSP), const(0x18)), load(reg(R9), T2)).call(CODE_BASE + 0xA00)
        builder.label("out").add_rsp(0x28).ret()
        return _to(builder, 2, TARGET)

    builder = build()
    site, write, read = _keys(builder)
    analyzed, escape, _ = _escape(tmp_path, monkeypatch, builder,
                                  assume_opaque_callees_leave_no_stack_addresses=False)
    assert site in escape.edge_sites
    assert escape.private_read(read)
    call = _key(builder, 5, 2, "CALL")
    assert not escape.private_read(call)   # (the opaque call escapes: the assumption is off)


def _taint(builder, **options):
    units = program_units(builder)
    observation = units[0].observation
    return may_alias._stack_taint(observation, may_alias._register_space_id(observation), RSP, 8, **options)


def _plain(eligible=True):
    """jz TARGET; rcx = 1; ret -- no frame, no held slot."""
    builder = (FunctionBuilder().cbranch("out", reg(ZF, 1)).ins(add(reg(RCX), reg(RCX), const(1)))
               .label("out").ret())
    builder = _to(builder, 0, TARGET)
    if not eligible:
        raw = builder.to_json()
        raw["instructions"][0]["flow_targets"] = []
        builder.to_json = lambda raw=raw: raw
    return builder


def test_an_escaping_tail_effect_escapes_at_its_edge():
    """``escaping_calls`` stays site-keyed: the site escapes at
    ``site~edge`` (the edge block's one key), never at the raw CBRANCH."""
    builder = _plain()
    site = _key(builder, 0, 0, "CBRANCH")
    keys, successors, escapes, _ = _taint(builder, escaping_calls=frozenset({site}))
    (edge,) = [block for block, sequence in keys.items() if sequence == [f"{site}~edge"]]
    assert successors[edge] == []
    assert escapes == {f"{site}~edge"}
    _, _, none, _ = _taint(builder)
    assert none == set()
    keys, _, raw, _ = _taint(_plain(eligible=False), escaping_calls=frozenset({site}))
    assert raw == {site} and not any(key.endswith("~edge") for sequence in keys.values() for key in sequence)


def test_the_escape_maps_a_sites_rows_to_its_edge():
    """``_base``: ``s~N`` (any staged row) of an edge site -> ``s~edge``;
    ``s~edge`` -> itself; the raw CBRANCH -> itself; another call's rows -> the
    call."""
    site, call = "1:1008:0:CBRANCH", "1:1010:2:CALL"
    escape = may_alias._Escape(frozenset({site, f"{site}~edge", call}), frozenset({f"{site}~edge"}),
                               frozenset({site, call}), frozenset(), frozenset(), frozenset({site}))
    for key in (f"{site}~0", f"{site}~u1", f"{site}~push", f"{site}~ld0", f"{site}~edge"):
        assert escape._base(key) == f"{site}~edge"
        assert not escape.private_read(key)
    assert escape._base(site) == site and escape.private_read(site)
    assert escape._base(f"{call}~0") == call
    plain = may_alias._Escape(frozenset({site}), frozenset(), frozenset())
    assert plain._base(f"{site}~0") == site   # (no edge block reached: the site itself)


@pytest.mark.parametrize("loop", [False, True])
def test_the_escape_memo_changes_nothing_on_an_edge_site(tmp_path, monkeypatch, loop):
    """A memo hit gives the policy a fresh computation gives (the memo key
    keeps ``escaping_calls`` site-keyed; ``edge_sites`` is in the result)."""
    found = []
    for memo in (True, False):
        with monkeypatch.context() as patch:
            if not memo:
                patch.setattr(may_alias.EscapeMemo, "holds", lambda self, *args: False)
            builder = _held(loop=loop)
            analyzed = _analyze(tmp_path, builder)
            found.append(sorted((row.operation_key, tuple(sorted(row.writers)))
                                for row in analyzed.normalized.may_alias_reads))
    assert found[0] == found[1]


def _plain_loop():
    """top: jz TARGET; rcx += 1; jz top; rdx += 1; ret."""
    builder = (FunctionBuilder().label("top").cbranch("out", reg(ZF, 1)).ins(add(reg(RCX), reg(RCX), const(1)))
               .cbranch("top", reg(ZF, 1)).ins(add(reg(RDX), reg(RDX), const(1))).label("out").ret())
    return _to(builder, 0, TARGET)


@pytest.mark.parametrize("loop", [False, True])
def test_private_write_is_the_same_set_with_the_escape_at_the_edge(monkeypatch, loop):
    """An escaping tail effect (no held slot): ``reaches`` (backward from the
    escape) is the set it was with the escape at the raw CBRANCH -- ``S`` and,
    in a loop, the body that returns to ``S``; ``escaped`` loses the
    fallthrough (docs 25.107, design r12)."""
    from tdo_v2 import pcode_blocks

    builder = _plain_loop() if loop else _plain()
    site = _key(builder, 0, 0, "CBRANCH")
    observation = program_units(builder)[0].observation
    space = may_alias._register_space_id(observation)
    escape = may_alias._stack_escape(observation, space, RSP, 8, escaping_calls=frozenset({site}))
    body = _key(builder, 1, 0, "INT_ADD")
    assert escape.private_write(site) is False
    assert escape.private_write(body) is (not loop)       # (the loop body returns to S, as before)
    assert escape.private_read(body) and escape.private_before(body)   # (was: post-escape)
    # the baseline -- the escape at the raw CBRANCH (no edge site): the same ``reaches``
    monkeypatch.setattr(pcode_blocks, "conditional_tail_edges", lambda graph: {})
    raw = may_alias._stack_escape(observation, space, RSP, 8, escaping_calls=frozenset({site}))
    assert raw.edge_sites == frozenset() and not raw.private_read(body)
    original = {key for key in escape.known if not key.endswith("~edge")}
    assert {key for key in original if escape.private_write(key)} == {key for key in original if raw.private_write(key)}
