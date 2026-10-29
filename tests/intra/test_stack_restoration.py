"""ARM64 Stage 0.2 / 0.3: no claim from the absence of evidence.

0.2 -- a call effect's stack restoration is PROVEN, DISPROVEN or UNKNOWN; an
empty call shape (no stack pointer known: AArch64 today) was vacuously
"restored". 0.3 -- the image-provenance decoder reads x86-64 encodings only;
on another language it proves nothing instead of calling a number "fixed".
"""

import pytest

from synthetic import RAX, RSP
from tdo_v2.call_summary_effects import StackRestoration, derive_proven_call_effect
from tdo_v2.function_summary import (
    FUNCTION_SUMMARY_VERSION, ExitSummary, FunctionSummary, SinkDemand, SummaryKind, SummaryRun,
)
from tdo_v2.span_geometry import ByteSpan, StorageObjectId, StorageObjectKind, StorageScopeId, StorageScopeKind
from tdo_v2.summary_templates import image_provenance

PROGRAM = StorageScopeId(StorageScopeKind.PROGRAM, b"p" * 32)
REGISTERS = StorageObjectId(StorageObjectKind.REGISTER_FILE, PROGRAM, 0)
SP = (RSP, 8)


def _summary(*, deltas=(), exits=1, tail_exits=(), sink_demands=()):
    run = SummaryRun(ByteSpan(REGISTERS, RAX, 8), SummaryKind.COMPUTED, (1,), ("write",), (), (), (), ())
    return FunctionSummary(FUNCTION_SUMMARY_VERSION,
                           tuple(ExitSummary(f"exit{i}", (run,)) for i in range(exits)), (), (),
                           tail_exits=tail_exits, sink_demands=sink_demands, register_deltas=deltas)


def _effect(summary, *, shape=True, tail=False):
    excluded = (ByteSpan(REGISTERS, RSP, 8),) if shape or tail else ()
    return derive_proven_call_effect(summary, "callee", REGISTERS, 0x100, excluded=excluded,
                                     stack_deltas={SP: -8} if shape else {}, tail=tail)


def test_a_matching_delta_proves_the_restoration():
    effect = _effect(_summary(deltas=((SP, 8),)))
    assert effect.stack_restoration is StackRestoration.PROVEN and effect.restores_stack
    assert effect.observed_registers is not None   # complete


def test_another_known_delta_disproves_it():
    effect = _effect(_summary(deltas=((SP, 16),)))
    assert effect.stack_restoration is StackRestoration.DISPROVEN and not effect.restores_stack


def test_no_known_delta_leaves_it_unknown():
    effect = _effect(_summary())
    assert effect.stack_restoration is StackRestoration.UNKNOWN and not effect.restores_stack


def test_an_untouched_register_is_delta_zero_only_for_a_link_shape():
    """2b-S (Astra r2 P2): the "unchanged, so 0" fallback serves a link call
    (shape delta 0); a push call's untouched stack pointer stays UNKNOWN -- its
    bytes are excluded from the merged state, not shown unchanged."""
    assert _effect(_summary()).stack_restoration is StackRestoration.UNKNOWN


def test_no_call_shape_is_never_a_restoration():
    """No stack pointer known at the call (no push shape): nothing was shown
    restored -- the old ``all(...)`` over an empty shape said True."""
    effect = _effect(_summary(deltas=((SP, 8),)), shape=False)
    assert effect.stack_restoration is StackRestoration.UNKNOWN
    assert not effect.restores_stack
    assert effect.observed_registers is None   # not complete (``observed_registers`` only when complete)


def test_a_sink_only_effect_claims_no_restoration():
    """A callee that leaves only by tail jumps: no state proven, its sink kept."""
    demand = SinkDemand("sink.arg0", (), (), (), True)
    effect = _effect(_summary(exits=0, tail_exits=("t",), sink_demands=(demand,)))
    assert effect.stack_restoration is StackRestoration.UNKNOWN and not effect.restores_stack


def test_a_tail_jump_stays_complete_by_its_composed_delta():
    """A tail jump pushes nothing: its stack pointer is composed by the
    target's delta (``tail_stack_delta``), not restored -- completeness keeps
    resting on that, as before."""
    effect = _effect(_summary(deltas=((SP, 0),)), shape=False, tail=True)
    assert effect.tail_stack_delta == 0
    assert effect.observed_registers is not None


def test_the_restoration_has_no_truth_value_default():
    from tdo_v2.call_summary_effects import ProvenCallEffect

    assert ProvenCallEffect("c", (), ()).stack_restoration is StackRestoration.UNKNOWN


# -- 0.3 ----------------------------------------------------------------------

def _reader(memory):
    def read(address, size):
        if any(address + index not in memory for index in range(size)):
            return None
        return int.from_bytes(bytes(memory[address + index] for index in range(size)), "little")
    return read


@pytest.mark.parametrize("language", ["AARCH64:LE:64:v8A", "x86:LE:32:default", "ARM:LE:32:v8"])
def test_provenance_proves_nothing_outside_x86_64(language):
    """AArch64 ``ADR x16, #0`` (10 00 00 10) decodes as an x86 instruction with
    no RIP operand -- "fixed" -- although its value moves with the image."""
    read = _reader({0x1000 + index: byte for index, byte in enumerate(bytes.fromhex("10000010"))})
    assert image_provenance(read, [], language_id="x86:LE:64:default")(0x1000, 4, 0x1000) is False
    assert image_provenance(read, [], language_id=language)(0x1000, 4, 0x1000) is None
    assert image_provenance(read, [(0x1000, 8)], language_id=language)(0x1000, 4, 0x1000) is None
