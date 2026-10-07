"""Calls and jumps through the import table (IAT) are admitted.

Ghidra lists the target of ``call [__imp_X]`` / ``jmp [__imp_X]`` in its
EXTERNAL space: not program memory and never this function's code. Such a
target is not a control successor; a jump to it leaves the function (a tail
call to an import). Any other non-memory target is still an invalid
observation.
"""

from synthetic import (
    CODE_BASE, DATA_BASE, EXTERNAL, RAX, RCX, FunctionBuilder, const, copy, load,
    normalize_with_observation, op, reg, tmp,
)
from tdo_v2.normalize import NormalizedFunction


class _ImportBuilder(FunctionBuilder):
    """Rewrite one instruction to an indirect call/jump through an IAT slot."""

    def __init__(self, kind: str, external_space: int = EXTERNAL):
        super().__init__()
        self._kind = kind
        self._external_space = external_space

    def to_json(self):
        value = super().to_json()
        row = value["instructions"][self._import_row]
        row["flow_targets"] = [{"space_id": self._external_space, "byte_offset": 9}]
        if self._kind == "jump":  # Ghidra: computed jump, not a call
            row["flow_type"].update(is_call=False, is_jump=True, is_computed=True,
                                    has_fallthrough=False, is_terminal=False)
        return value


def _function(kind, external_space=EXTERNAL):
    builder = _ImportBuilder(kind, external_space)
    builder.ins(copy(reg(RCX), reg(RAX)))
    builder._import_row = 1
    slot = [load(tmp(0x300), const(DATA_BASE + 0x10)), ]
    if kind == "jump":
        builder._rows.append(type(builder._rows[0])(slot + [op("BRANCHIND", [tmp(0x300)])], "tail"))
        return builder
    builder.call(CODE_BASE + 0x800)
    builder._rows[-1].ops[-1] = op("CALLIND", [tmp(0x300)])
    builder._rows[-1].ops[:0] = slot
    return builder.ret()


def test_import_call_is_admitted():
    function, _ = normalize_with_observation(_function("call"))
    assert type(function) is NormalizedFunction


def test_import_jump_is_admitted_and_leaves_the_function():
    function, observation = normalize_with_observation(_function("jump"))
    assert type(function) is NormalizedFunction
    jump = observation.instructions[-1]
    assert jump.flow_targets == ()  # the external target is not a successor


def test_other_non_memory_targets_stay_invalid():
    from synthetic import UNIQUE
    try:
        normalize_with_observation(_function("jump", external_space=UNIQUE))
    except Exception:  # noqa: BLE001 - the scope cannot be constructed
        return
    raise AssertionError("a jump into the unique space must not be admitted")
