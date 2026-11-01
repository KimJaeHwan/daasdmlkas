"""Original indirect operand SSA and modular negative sign-extension facts.

Small-bitvector enumeration is independent of the transfer implementation.
Concrete branch checks use the existing interpreter oracle: the original
prefix reaches its indirect jump, not necessarily a complete program target.
"""

import pytest

from forward_oracle import check_forward
from synthetic import (RAX, RBX, RDI, RDX, RSP, FunctionBuilder, const, copy,
                       load, op, program_units, reg)
from tdo_v2.forward import Interval, Value, _analyze, _numeric, _transfer, concretizes
from tdo_v2.normalize import FunctionNormalizer


def _members(interval):
    return set(range(interval.lo, interval.hi + 1, interval.stride or 1))


def _sext(number, inbits, outbits):
    signed = number if number < 1 << (inbits - 1) else number - (1 << inbits)
    return signed & ((1 << outbits) - 1)


@pytest.mark.parametrize("inbits", (2, 3, 4))
@pytest.mark.parametrize("extra", (0, 1, 4))
def test_sign_extension_small_bitvector_domains_exhaustively_preserve_each_member(inbits, extra):
    outbits, half, modulus = inbits + extra, 1 << (inbits - 1), 1 << inbits
    checked, negative_nonsingle, crossing = 0, 0, 0
    for low in range(modulus):
        for high in range(low, modulus):
            strides = (0,) if low == high else tuple(step for step in range(1, high - low + 1)
                                                     if (high - low) % step == 0)
            for stride in strides:
                source = Interval(low, high, stride, inbits)
                result = _numeric("INT_SEXT", [source], [low if source.single else None], outbits)
                if low < half <= high:
                    assert result is None  # a disjoint image is not one strided interval
                    crossing += 1
                else:
                    assert result is not None
                    assert _members(result) == {_sext(number, inbits, outbits) for number in _members(source)}
                    assert result.stride == stride
                    negative_nonsingle += int(low >= half and not source.single)
                checked += 1
    assert checked and negative_nonsingle and crossing


@pytest.mark.parametrize("low,high,stride", ((0, 0x7fffffff, 1),
    (0x80000000, 0xffffffff, 1), (0xffffaf15, 0xffffaf59, 1),
    (0xfffffff0, 0xfffffffc, 4), (0x7ffffffe, 0x80000002, 2)))
def test_nonsingle_32_to_64_sign_extension_keeps_sign_and_stride(low, high, stride):
    source = Value(32, ((("abs",), Interval(low, high, stride, 32)),))
    result = _transfer("INT_SEXT", [source], [4], 8)
    if low < 0x80000000 <= high:
        assert result.is_top
        return
    interval = result.numeric()
    assert interval is not None
    assert (interval.lo, interval.hi, interval.stride, interval.bits) == \
        (_sext(low, 32, 64), _sext(high, 32, 64), stride, 64)
    for number in {low, low + stride, high - stride, high}:
        assert concretizes(result, _sext(number, 32, 64), lambda *_: 0)


@pytest.mark.parametrize("low,high", ((0, 0), (0xffff, 0xffff),
                                      (1, 0x7fff), (0x8000, 0xffff), (0x7fff, 0x8000)))
def test_invalid_narrowing_sext_is_refused_before_single_literal_folding(low, high):
    interval = Interval(low, high, 0 if low == high else 1, 16)
    source = Value(16, ((("abs",), interval),))
    assert _numeric("INT_SEXT", [interval], [low if interval.single else None], 8) is None
    assert _transfer("INT_SEXT", [source], [2], 1).is_top


@pytest.mark.parametrize("base,expected", ((0, (0xfffffffffffffff0, 0xffffffffffffffff)),
                                         (8, None), (16, (0, 15)), (32, (16, 31))))
def test_sext_then_add_accepts_whole_wrap_but_refuses_partial_wrap(base, expected):
    source = Value(32, ((("abs",), Interval(0xfffffff0, 0xffffffff, 1, 32)),))
    extended = _transfer("INT_SEXT", [source], [4], 8)
    result = _transfer("INT_ADD", [extended, Value.number(base, 64)], [8, 8], 8)
    if expected is None:
        assert result.is_top
    else:
        assert _members(result.numeric()) == set(range(expected[0], expected[1] + 1))
        assert _members(result.numeric()) == {(_sext(value, 32, 64) + base) & ((1 << 64) - 1)
                                            for value in range(0xfffffff0, 0x100000000)}


@pytest.fixture(params=("sparse", "dense"))
def engine(monkeypatch, request):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)


def _branch(variant):
    builder = FunctionBuilder().ins(copy(reg(RAX), const(0x1122334455667788)))
    if variant == "intervening":
        builder.ins(copy(reg(RBX), const(0)))
    elif variant == "overwrite":
        builder.ins(copy(reg(RAX), const(0x12345678)))
    elif variant == "partial-known":
        # One-byte raw p-code register write, not an ISA zero-upper write.
        builder.ins(copy(reg(RAX, 1), const(0xab, 1)))
    elif variant == "partial-unknown":
        builder.ins(copy(reg(RAX, 1), reg(RDX, 1)))
    elif variant == "unknown-load":
        builder.ins(load(reg(RAX), reg(RDI)))
    elif variant == "call":
        builder.call(0x1f00)
    key = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:0:BRANCHIND"
    builder.ins(op("BRANCHIND", [reg(RAX)])).ret()
    unit, = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    facts = {fact.operation: fact for fact in _analyze(normalized, unit).facts}
    return normalized, unit, key, facts


@pytest.mark.parametrize("variant,expected", (("base", 0x1122334455667788),
    ("intervening", 0x1122334455667788), ("overwrite", 0x12345678),
    ("partial-known", 0x11223344556677ab)))
def test_branchind_uses_original_cross_instruction_operand_read(engine, variant, expected):
    normalized, unit, key, facts = _branch(variant)
    action, = [i for i, row in enumerate(normalized.memory_ssa.actions) if row.operation_key == key]
    reads = [row for row in normalized.memory_ssa.reads if row.action_id == action]
    assert len(reads) == 1 and reads[0].span.start == RAX and reads[0].span.size == 8
    fact = facts[key]
    assert fact.input == 0 and fact.claim.single_number() == expected
    report = check_forward(unit, [fact], seeds=range(3), register_pools=lambda _: {RSP: 0x70000000})
    assert report.checked == 3 and not report.failures and report.unexercised == 0


@pytest.mark.parametrize("variant", ("partial-unknown", "unknown-load", "call"))
def test_branchind_top_or_debt_never_scans_back_to_an_earlier_literal(engine, variant):
    normalized, _, key, facts = _branch(variant)
    assert key not in facts
    if variant == "call":
        assert any(row.operation_key == key and any(span.start == RAX for span in row.spans)
                   for row in normalized.call_clobber_reads)
    else:
        action = next(i for i, row in enumerate(normalized.memory_ssa.actions) if row.operation_key == key)
        assert any(row.action_id == action for row in normalized.memory_ssa.reads)


def test_callind_keeps_its_existing_same_instruction_snapshot_contract(engine):
    builder = FunctionBuilder().ins(copy(reg(RAX), const(0x1800))).call_indirect(RAX).ret()
    unit, = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    fact, = [fact for fact in _analyze(normalized, unit).facts if fact.operation.endswith(":CALLIND")]
    assert fact.claim.single_number() == 0x1800 and fact.input == 0
    # CALLIND itself intentionally has no ordinary SSA operand read. This
    # change must not remove the existing pre-push COPY snapshot consumer.
    action = next(i for i, row in enumerate(normalized.memory_ssa.actions) if row.operation_key == fact.operation)
    assert not any(row.action_id == action for row in normalized.memory_ssa.reads)
