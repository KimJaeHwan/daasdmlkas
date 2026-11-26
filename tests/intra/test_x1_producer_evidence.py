"""X-1a (design_x1 r2 parts 1-3, r3 part 1 amendment): the producer profile's raw row fields.

A function declaring ``producer_profile: "x1-producer-v1"`` carries, on every instruction row, the exporter's own
per-instruction override state (``override``) and the landing pads it recorded before its call-p-code filter
(``recorded_landing_pads``); the engine keeps them raw, counts the flow targets target validation drops as
external, and binds all of it into both identity encoders. A function without the profile is read and encoded
exactly as before (legacy digests unchanged); anything less than the full profile is malformed, never legacy."""

from __future__ import annotations

import copy
from hashlib import sha256

import pytest

from synthetic import EXTERNAL, RAM, RAX, FunctionBuilder, const, op, program_units, reg
from tdo_v2._scope_contracts import PRODUCER_PROFILE_X1
from tdo_v2._scope_wire import _observation_digest, _observation_preimage

CALLEE = 0x1800


def _coordinate(address: int, space: int = RAM) -> dict:
    return {"space_id": space, "byte_offset": address}


def _none_override() -> dict:
    return {"flow_override": "NONE", "fallthrough_overridden": False, "length_overridden": False,
            "override_references": []}


class Profiled(FunctionBuilder):
    """A FunctionBuilder whose JSON declares the producer profile (rows get the
    raw fields); ``edit`` makes a hand-made variant or defect."""

    def __init__(self, *, profile=True, edit=None, **kwargs):
        super().__init__(**kwargs)
        self._profile, self._edit = profile, edit

    def to_json(self) -> dict:
        data = copy.deepcopy(super().to_json())
        if self._profile:
            data["producer_profile"] = PRODUCER_PROFILE_X1
            for row in data["instructions"]:
                row["override"] = _none_override()
                row["recorded_landing_pads"] = []
        if self._edit is not None:
            self._edit(data)
        return data


def _caller(builder: FunctionBuilder) -> FunctionBuilder:
    return builder.call(CALLEE).ins(op("COPY", [const(1)], reg(RAX))).ret()


def _observation(builder: FunctionBuilder):
    units = program_units(builder, FunctionBuilder(entry=CALLEE).ret())
    return units[0].observation


def _digest(observation) -> bytes:
    preimage = _observation_preimage(observation)
    assert sha256(preimage).digest() == _observation_digest(observation)   # (both encoders agree)
    return _observation_digest(observation)


# the digest of the legacy observation ``_caller(FunctionBuilder())`` on main a70d6d5 (before X-1): a function
# without the profile is encoded byte for byte as before
MAIN_A70D6D5_LEGACY_DIGEST = "fb3180ec514340102f1a0dc87f5c7394742ce2dd3a8019e678be06f0fc92a3fd"


def test_the_legacy_digest_is_unchanged():
    observation = _observation(_caller(FunctionBuilder()))
    assert observation.producer_profile is None
    assert all(row.override is None and row.external_flow_targets is None and row.recorded_landing_pads is None
               for row in observation.instructions)
    preimage = _observation_preimage(observation)
    assert b"tdo-v2-instruction-override-v1" not in preimage and b"tdo-v2-producer-profile" not in preimage
    assert _digest(observation).hex() == MAIN_A70D6D5_LEGACY_DIGEST


def test_a_profiled_observation_keeps_the_raw_fields_and_binds_them():
    observation = _observation(_caller(Profiled()))
    assert observation is not None and observation.producer_profile == PRODUCER_PROFILE_X1
    assert all(row.override.none and row.external_flow_targets == 0 and row.recorded_landing_pads == ()
               for row in observation.instructions)
    preimage = _observation_preimage(observation)
    assert b"tdo-v2-instruction-override-v1" in preimage and b"tdo-v2-producer-profile:x1-producer-v1" in preimage
    assert _digest(observation) != _digest(_observation(_caller(FunctionBuilder())))


def _row(index: int, **fields):
    def edit(data):
        data["instructions"][index].update(copy.deepcopy(fields))
    return edit


def _override(**fields) -> dict:
    return {**_none_override(), **fields}


VARIANTS = {
    "branch override": _row(1, override=_override(flow_override="BRANCH")),
    "fallthrough override": _row(1, override=_override(fallthrough_overridden=True)),
    "length override": _row(1, override=_override(length_overridden=True)),
    "call override reference": _row(0, override=_override(override_references=[
        {"address": _coordinate(CALLEE), "type": "CALL_OVERRIDE_UNCONDITIONAL"}])),
    "other reference type": _row(0, override=_override(override_references=[
        {"address": _coordinate(CALLEE), "type": "JUMP_OVERRIDE_UNCONDITIONAL"}])),
    "other reference target": _row(0, override=_override(override_references=[
        {"address": _coordinate(CALLEE + 4), "type": "CALL_OVERRIDE_UNCONDITIONAL"}])),
    "one landing pad": _row(0, recorded_landing_pads=[_coordinate(CALLEE)]),
}


def test_every_raw_field_changes_the_digest():
    """design_x1 r2 part 1 test (Astra X-1 r1 P1-3): vary only one raw field -> distinct digests, and both
    encoders agree."""
    base = _digest(_observation(_caller(Profiled())))
    digests = {name: _digest(_observation(_caller(Profiled(edit=edit)))) for name, edit in VARIANTS.items()}
    assert base not in digests.values()
    assert len(set(digests.values())) == len(digests)


def test_the_external_target_count_is_bound():
    def external(data):
        data["instructions"][0]["flow_targets"].append(_coordinate(0x10, EXTERNAL))

    plain = _observation(_caller(Profiled()))
    counted = _observation(_caller(Profiled(edit=external)))
    assert counted.instructions[0].external_flow_targets == 1
    assert counted.instructions[0].flow_targets == plain.instructions[0].flow_targets   # (dropped, as before)
    assert _digest(counted) != _digest(plain)
    # without the profile the drop is not bound (legacy encoding): the digest is the legacy one
    legacy = _observation(_caller(Profiled(profile=False, edit=external)))
    assert legacy.instructions[0].external_flow_targets is None
    assert _digest(legacy) == _digest(_observation(_caller(FunctionBuilder())))


def test_an_override_reference_outside_the_program_is_recorded():
    """Fable X-1 r1 P2-4: an override reference to an external or unmapped address is recorded raw
    (``in_index`` false); the observation stays valid."""
    edit = _row(0, override=_override(override_references=[
        {"address": _coordinate(0x10, EXTERNAL), "type": "CALL_OVERRIDE_UNCONDITIONAL"},
        {"address": _coordinate(0x900000), "type": "CALL_OVERRIDE_UNCONDITIONAL"}]))
    observation = _observation(_caller(Profiled(edit=edit)))
    assert observation is not None
    references = observation.instructions[0].override.references
    assert [reference.in_index for reference in references] == [False, False]
    assert not observation.instructions[0].override.none


def _drop(index: int, name: str):
    def edit(data):
        data["instructions"][index].pop(name)
    return edit


DEFECTS = {
    "row without override": _drop(1, "override"),
    "row without landing pads": _drop(2, "recorded_landing_pads"),
    "unknown override key": _row(1, override={**_none_override(), "extra": 1}),
    "missing override key": _row(1, override={key: value for key, value in _none_override().items()
                                              if key != "length_overridden"}),
    "unknown flow override": _row(1, override=_override(flow_override="SOMETIMES")),
    "flag of the wrong type": _row(1, override=_override(fallthrough_overridden=0)),
    "reference without type": _row(0, override=_override(override_references=[{"address": _coordinate(CALLEE)}])),
    "unknown profile": lambda data: data.update(producer_profile="x1-producer-v0"),
}


@pytest.mark.parametrize("name", sorted(DEFECTS))
def test_less_than_the_full_profile_is_malformed(name):
    """r3 part 1: a declared profile with a missing or malformed row field is a defect (the function is
    refused), never read as legacy."""
    assert _observation(_caller(Profiled(edit=DEFECTS[name]))) is None


def test_profile_fields_without_the_profile_are_malformed():
    def stray(data):
        data["instructions"][0]["override"] = _none_override()

    assert _observation(_caller(Profiled(profile=False, edit=stray))) is None
