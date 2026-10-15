"""Index atoms of step 2 (docs 25.17): a SUBPIECE boundary atom, a once-join
atom (the value a block run once per activation picks from its candidates,
e.g. a ``cmov``), and the low bytes of ZEXT(x) at x's width being x. Each
makes an index a single value per activation, so the same element is one
exact place; a join in a loop stays without an atom."""

import random

import pytest

from graph_oracle import check
from synthetic import (
    RAX, RBP, RBX, RCX, RDI, RDX, RSI, RSP, FunctionBuilder, add, const, copy, load, normalize,
    normalize_with_observation, op, reg, slice_from, store, straight, tmp,
)
from test_index_addresses import _bytes, _load_node, _slice_of_load

FLAG, NOT_FLAG, PICKED = tmp(0x300, 1), tmp(0x301, 1), tmp(0x310, 4)


def _subpiece_element(out, base, index_register):
    """out = base + 8 * zext(subpiece(index + 1, 0) as 4 bytes)."""
    wide, low, extended, scaled = tmp(0x400), tmp(0x408, 4), tmp(0x410), tmp(0x418)
    return [add(wide, reg(index_register), const(1)),
            op("SUBPIECE", [wide, const(0, 4)], low),
            op("INT_ZEXT", [low], extended),
            op("INT_MULT", [extended, const(8)], scaled),
            add(out, reg(base), scaled)]


def _cmov_rows():
    """edi = esi (zero-extended into rdi); ebp = 0; cmovnz edi, ebp -- the
    p-code of a 32-bit cmov: copy the source, zero-extend the destination,
    then a relative CBRANCH around the copy."""
    return [
        [copy(reg(RDI, 4), reg(RSI, 4)), op("INT_ZEXT", [reg(RDI, 4)], reg(RDI))],
        [op("INT_XOR", [reg(RBP, 4), reg(RBP, 4)], reg(RBP, 4)), op("INT_ZEXT", [reg(RBP, 4)], reg(RBP))],
        [op("INT_NOTEQUAL", [reg(RCX), const(0)], FLAG),
         copy(PICKED, reg(RBP, 4)),
         op("INT_ZEXT", [reg(RDI, 4)], reg(RDI)),
         op("BOOL_NEGATE", [FLAG], NOT_FLAG),
         op("CBRANCH", [const(2, 4), NOT_FLAG]),
         copy(reg(RDI, 4), PICKED)],
    ]


def _picked_element(out, base):
    """out = base + 8 * sext(edi) (edi read back as the 32-bit part)."""
    wide, scaled = tmp(0x400), tmp(0x408)
    return [op("INT_SEXT", [reg(RDI, 4)], wide),
            op("INT_MULT", [wide, const(8)], scaled),
            add(out, reg(base), scaled)]


def test_a_truncated_index_is_one_exact_place():
    """a[x] = rdx; a[x] = rcx; rax = a[x], x = (u32)(rsi + 1): the second write kills the first."""
    t = tmp(0x100)
    found = _slice_of_load(straight(
        [*_subpiece_element(t, RBX, RSI), store(t, reg(RDX))],
        [*_subpiece_element(t, RBX, RSI), store(t, reg(RCX))],
        [*_subpiece_element(t, RBX, RSI), load(reg(RAX), t)],
    ), 2)
    assert found.is_complete
    assert _bytes(RCX) <= found.register_bytes and not _bytes(RDX) & found.register_bytes


def test_a_cmov_picked_index_is_one_exact_place():
    """i = rcx != 0 ? 0 : esi; a[i] = rdx; a[i] = r8 ... rax = a[i]."""
    t = tmp(0x100)
    rows = _cmov_rows() + [
        [*_picked_element(t, RBX), store(t, reg(RDX))],
        [*_picked_element(t, RBX), store(t, reg(RSI))],
        [*_picked_element(t, RBX), load(reg(RAX), t)],
    ]
    found = _slice_of_load(straight(*rows), 5)
    assert found.is_complete
    assert _bytes(RSI) <= found.register_bytes and not _bytes(RDX) & found.register_bytes


def test_without_the_c1_switch_a_cmov_index_stays_unknown(monkeypatch):
    monkeypatch.setenv("TDO_V2_INDEX_ADDRESSES", "0")
    t = tmp(0x100)
    rows = _cmov_rows() + [
        [*_picked_element(t, RBX), store(t, reg(RDX))],
        [*_picked_element(t, RBX), load(reg(RAX), t)],
    ]
    assert not _slice_of_load(straight(*rows), 4).is_complete


def test_a_join_in_a_loop_gets_no_atom():
    """The cmov inside a loop (both candidates fixed, the pick changing with
    rcx per iteration): no once-join atom, the element write keeps an unknown
    address."""
    t = tmp(0x100)
    builder = FunctionBuilder().sub_rsp(0x28)
    builder.label("top")
    for row in _cmov_rows():
        builder.ins(*row)
    builder.ins(*_picked_element(t, RBX), store(t, reg(RDX)))
    builder.ins(add(reg(RCX), reg(RCX), const(1)))  # esi, 0 fixed; the pick changes per iteration
    builder.cbranch("top", FLAG, op("INT_NOTEQUAL", [reg(RDX), const(0)], FLAG))
    builder.add_rsp(0x28).ret()
    function, observation = normalize_with_observation(builder)
    store_key = next(key for key in (effect.operation_key for effect in function.effects)
                     if key.endswith(":STORE") and ":1010:" in key)
    actions = {action.operation_key: index for index, action in enumerate(function.memory_ssa.actions)}
    unresolved = {item.action_id for item in function.memory_ssa.unresolved_writes}
    assert actions[store_key] in unresolved


# -- random programs under the graph oracle ------------------------------------------

def _random_function(rng):
    t = tmp(0x100)
    rows = list(_cmov_rows()) if rng.random() < 0.7 else []
    for _ in range(rng.randint(2, 7)):
        kind = rng.random()
        if kind < 0.4 and rows:
            address = _picked_element(t, RBX)
        elif kind < 0.8:
            address = _subpiece_element(t, RBX, rng.choice((RSI, RCX)))
        else:
            address = [add(t, reg(RBX), const(rng.choice((0, 8, 16))))]
        width = rng.choice((1, 2, 4, 8))
        if rng.random() < 0.5:
            rows.append([*address, store(t, reg(rng.choice((RAX, RDX)), width))])
        else:
            rows.append([*address, load(reg(rng.choice((RAX, RDX)), width), t)])
        if rng.random() < 0.15:
            rows.append([add(reg(RSI, 4), reg(RSI, 4), const(1, 4))])
    return straight(*rows)


def _pools(seed):
    rng = random.Random(seed)
    values = {RSP: 0x7000_0000, RBX: rng.choice((0x5000_0000, 0x5000_0008, 0x5000_0040))}
    for register in (RSI, RCX):
        values[register] = rng.choice((0, 1, 2, (-1) % (1 << 64), (-2) % (1 << 64), 0xFFFF_FFFF, 7))
    for register in (RAX, RDX):
        values[register] = rng.getrandbits(64)
    return values


@pytest.mark.parametrize("chunk", range(3))
def test_random_once_join_and_truncated_index_programs_have_no_silent_miss(chunk):
    silent, runs = [], 0
    for seed in range(chunk * 60, chunk * 60 + 60):
        builder = _random_function(random.Random(91_000 + seed))
        normalized, observation = normalize_with_observation(builder)
        report = check(normalized, observation, seeds=range(6), register_pools=_pools)
        runs += report.runs
        silent += [(seed, item) for item in report.silent]
    assert runs > 0
    assert silent == [], silent[:3]


def _write_is_unresolved(builder, instruction):
    """The STORE of ``instruction`` keeps an unknown address."""
    from synthetic import CODE_BASE

    function, _ = normalize_with_observation(builder)
    marker = f":{CODE_BASE + 4 * instruction:x}:"
    store_key = next(key for key in (effect.operation_key for effect in function.effects)
                     if key.endswith(":STORE") and marker in key)
    actions = {action.operation_key: index for index, action in enumerate(function.memory_ssa.actions)}
    return actions[store_key] in {item.action_id for item in function.memory_ssa.unresolved_writes}


def test_a_zero_extension_read_back_at_another_width_is_not_its_input():
    """rdi = zext(esi); a[sext(di)] = rdx: the 2 low bytes of a 4 -> 8 byte
    zero extension are not the 4-byte input -- no expression (2c needs the
    input's exact width)."""
    t, wide, scaled = tmp(0x100), tmp(0x400), tmp(0x408)
    builder = straight(
        [op("INT_ZEXT", [reg(RSI, 4)], reg(RDI))],
        [op("INT_SEXT", [reg(RDI, 2)], wide), op("INT_MULT", [wide, const(8)], scaled),
         add(t, reg(RBX), scaled), store(t, reg(RDX))],
    )
    assert _write_is_unresolved(builder, 1)


def test_a_zero_extension_read_back_at_its_input_width_is_its_input():
    """rdi = zext(esi); a[sext(edi)] = rdx: the 4 low bytes are esi -- an address."""
    t, wide, scaled = tmp(0x100), tmp(0x400), tmp(0x408)
    builder = straight(
        [op("INT_ZEXT", [reg(RSI, 4)], reg(RDI))],
        [op("INT_SEXT", [reg(RDI, 4)], wide), op("INT_MULT", [wide, const(8)], scaled),
         add(t, reg(RBX), scaled), store(t, reg(RDX))],
    )
    assert not _write_is_unresolved(builder, 1)
