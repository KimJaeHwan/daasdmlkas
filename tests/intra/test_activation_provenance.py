"""Activation record notes belong to exact, unchanged call effects only."""

from dataclasses import dataclass
from types import SimpleNamespace

from tdo_v2.interprocedural import CallProvenance, _activation_call_provenance
from tdo_v2.operation_records import _call_provenance


@dataclass(frozen=True)
class _Place:
    anchor: object = None
    pointer: object = None
    index: object = None
    displacement: int = 0x10
    size: int = 8
    space_id: int = 1


@dataclass(frozen=True)
class _Run:
    conditions: tuple


@dataclass(frozen=True)
class _Effect:
    runs: tuple
    memory_runs: tuple = ()
    sink_demands: tuple = ()
    writer_conditions: tuple = ()


PAIR_A = (_Place(), _Place(displacement=0x20))
PAIR_B = (_Place(displacement=0x30), _Place(displacement=0x40))


def _notes(calls):
    return CallProvenance(
        sources={call: ("model", "declared:" + call) for call in calls},
        rejections={call: (("cr0", PAIR_A, "failed"),) for call in calls},
        failed={call: frozenset((PAIR_B,)) for call in calls},
        opened={call: {PAIR_A: "open"} for call in calls},
        final={(call, "cr0"): ("ok",) for call in calls},
        sink={(call, "ck0"): ("ok",) for call in calls},
        memory_sources={call: {"write": ((0, "original"),)} for call in calls},
    )


def _owner(**effects):
    return SimpleNamespace(proven=effects)


def test_unchanged_effect_gets_fresh_independent_maps_and_changed_one_no_notes():
    exact = _Effect((_Run((PAIR_A,)),))
    changed = _Effect((_Run((PAIR_B,)),))
    generic = _owner(same=exact, altered=exact)
    context = _owner(same=exact, altered=changed)
    old = _notes(("same", "altered"))
    copied = _activation_call_provenance(generic, context, old)
    assert copied is not old
    assert copied.sources == {"same": old.sources["same"]}
    assert copied.rejections == {"same": old.rejections["same"]}
    assert copied.failed == {"same": old.failed["same"]}
    assert copied.opened == {"same": old.opened["same"]}
    assert copied.final == {("same", "cr0"): ("ok",)}
    assert copied.sink == {("same", "ck0"): ("ok",)}
    assert copied.memory_sources == {"same": old.memory_sources["same"]}
    for name in ("sources", "rejections", "failed", "opened", "final", "sink", "memory_sources"):
        assert getattr(copied, name) is not getattr(old, name)
    assert copied.opened["same"] is not old.opened["same"]
    assert copied.memory_sources["same"] is not old.memory_sources["same"]
    assert _call_provenance(copied, "altered", changed, "0")["source"] is None
    assert [row["verdict"] for row in _call_provenance(copied, "altered", changed, "0")["conditions"]] \
        == ["undecided"]
    assert old.sources["altered"] == ("model", "declared:altered")


def test_reordered_rows_cannot_reuse_cr_ordinal_verdict():
    old_effect = _Effect((_Run((PAIR_A,)), _Run((PAIR_B,))))
    reordered = _Effect(tuple(reversed(old_effect.runs)))
    old = _notes(("call",))
    copied = _activation_call_provenance(_owner(call=old_effect), _owner(call=reordered), old)
    assert copied.sources == copied.rejections == copied.failed == copied.opened == {}
    assert copied.final == copied.sink == copied.memory_sources == {}
    row = _call_provenance(copied, "call", reordered, "0")
    assert row["source"] is None and [item["verdict"] for item in row["conditions"]] == ["undecided"]


def test_changed_condition_with_same_row_number_remains_undecided():
    old_effect = _Effect((_Run((PAIR_A,)),))
    changed = _Effect((_Run((PAIR_B,)),))
    copied = _activation_call_provenance(_owner(call=old_effect), _owner(call=changed), _notes(("call",)))
    assert not copied.sources and not copied.final and not copied.failed
    assert _call_provenance(copied, "call", changed, "0")["conditions"][0]["verdict"] == "undecided"


def test_multiple_contexts_of_one_callee_do_not_share_mutable_notes():
    old_effect = _Effect((_Run((PAIR_A,)),))
    changed = _Effect((_Run((PAIR_B,)),))
    generic, old = _owner(call=old_effect), _notes(("call",))
    first = _activation_call_provenance(generic, _owner(call=old_effect), old)
    second = _activation_call_provenance(generic, _owner(call=old_effect), old)
    third = _activation_call_provenance(generic, _owner(call=changed), old)
    first.opened["call"][PAIR_B] = "new"
    first.memory_sources["call"]["extra"] = ()
    first.sources["call"] = ("model", "context-only")
    assert PAIR_B not in second.opened["call"] and PAIR_B not in old.opened["call"]
    assert "extra" not in second.memory_sources["call"] and "extra" not in old.memory_sources["call"]
    assert second.sources["call"] == old.sources["call"] == ("model", "declared:call")
    assert third.sources == third.final == third.memory_sources == {}


def test_old_note_mutation_after_copy_cannot_rewrite_context_verdict():
    effect = _Effect((_Run((PAIR_A,)),))
    old = _notes(("call",))
    copied = _activation_call_provenance(_owner(call=effect), _owner(call=effect), old)
    old.final[("call", "cr0")] = ("fail",)
    old.opened["call"][PAIR_B] = "changed"
    old.memory_sources["call"].clear()
    assert copied.final[("call", "cr0")] == ("ok",)
    assert PAIR_B not in copied.opened["call"]
    assert copied.memory_sources["call"] == {"write": ((0, "original"),)}
