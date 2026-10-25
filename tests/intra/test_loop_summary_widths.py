"""Low-bit algebra does not turn widening or high bytes into identities."""

import copy as copying

import pytest

from synthetic import RAX, RBX, RCX, RDX, RSI, R8, FunctionBuilder, const, copy, op, reg, tmp
from test_transition_records import _record, _Unreadable
from test_loop_summary_records import _summary, _evaluate
from tdo_v2._record_loop_summaries import _Normalizer, _Partial
from tdo_v2.operation_records import evaluate_loop_summary, Ineligible


def _promoted(*, extension='INT_ZEXT', wide_observed=False):
    flag, left, right, total = tmp(0x300, 1), tmp(0x400, 4), tmp(0x408, 4), tmp(0x410, 4)
    builder = (FunctionBuilder().ins(copy(reg(RAX, 1), reg(RCX, 1)), copy(reg(R8, 4), const(0, 4)))
            .label('header').cbranch('exit', flag, op('INT_EQUAL', [reg(RDX), const(0)], flag))
            .ins(op(extension, [reg(RAX, 1)], left), op(extension, [reg(RSI, 1)], right),
                 op('INT_ADD', [left, right], total), copy(reg(RAX, 1), total)))
    if wide_observed:
        builder.ins(op('INT_ADD', [reg(R8, 4), total], reg(R8, 4)))
    return (builder.ins(op('INT_SUB', [reg(RDX), const(1)], reg(RDX))).branch('header')
            .label('exit').ins(copy(reg(RBX), reg(RAX))).ret())


@pytest.mark.parametrize('extension', ('INT_ZEXT', 'INT_SEXT'))
@pytest.mark.parametrize('initial', (0, 127, 128, 255))
def test_low_byte_of_signed_or_unsigned_promotion_retains_modulo(extension, initial):
    record = _record(_promoted(extension=extension), known=True)
    result = _evaluate(record, initial=initial, delta=129, count=3)
    value, = [row for row in result['updates'] if int(row['span'][-2], 16) == RAX]
    assert value['value'] == (initial + 3 * 129) & 255


def test_low_byte_projection_never_truncates_the_termination_counter():
    record = _record(_promoted(), known=True)
    result = _evaluate(record, initial=255, delta=1, count=256)
    assert result['iterations'] == 256
    assert next(row['value'] for row in result['updates'] if int(row['span'][-2], 16) == RAX) == 255


@pytest.mark.parametrize('extension', ('INT_ZEXT', 'INT_SEXT'))
def test_observed_wide_result_cannot_erase_narrow_wrap_or_sign(extension):
    record = _record(_promoted(extension=extension, wide_observed=True), known=True)
    summary, = record['loop_summaries']
    assert not summary['complete']


def test_projection_and_strict_cache_are_separate_and_high_bytes_refused():
    record = _record(_promoted(), known=True)
    view, = record['cycle_graph']['transitions']
    normalizer = _Normalizer(view, record['limits'])
    ext = next(node for node in view['record']['nodes'] if node.get('opcode') == 'INT_ZEXT')
    assert normalizer.part(dict(node=ext['id'], bytes=[0, 1], at=[0, 1])).width == 1
    with pytest.raises(_Partial):
        normalizer.part(dict(node=ext['id'], bytes=[0, 1], at=[0, 1]), strict=True)
    with pytest.raises(_Partial):
        normalizer.part(dict(node=ext['id'], bytes=[1, 2], at=[0, 1]))


def test_modified_projection_evidence_is_rejected_before_inputs():
    record = _record(_promoted(), known=True)
    summary = _summary(record)
    item = next(row for row in summary['derivation'] if row['requested_width'] == 1)
    item['requested_width'] = 2
    with pytest.raises(Ineligible):
        evaluate_loop_summary(record, summary['id'], _Unreadable())
