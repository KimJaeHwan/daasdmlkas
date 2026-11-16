"""S1 (design_scc_conditions r10 section 2): the ISA call-fallthrough contract of an observation.

The exporter disables Ghidra's non-returning analyzers and writes, per function, ``call_fallthrough: "isa"``
(every native call keeps its ISA fallthrough, verified per call), ``call_continuations`` (native calls whose
continuation is not an instruction of the function) and a ``length`` per instruction. The engine admits them,
refuses an observation that breaks the contract, keeps the digest of an observation without them unchanged, and
adds a continuation into another function as a reachability edge (control contexts, ``site_reach``, F1)."""

from __future__ import annotations

import copy
from hashlib import sha256
from types import SimpleNamespace

import pytest

from synthetic import RAM, RAX, CONST, FunctionBuilder, const, op, program_units, reg, tmp
from tdo_v2._scope_contracts import CONTINUATION_BOUNDARY, CONTINUATION_FUNCTION_ENTRY, is_native_call
from tdo_v2._scope_wire import _observation_digest, _observation_preimage
from tdo_v2.control_context import _edges
from tdo_v2.fault_premise import observed_calls
from tdo_v2.interprocedural import function_key

CALLEE = 0x1800
OTHER = 0x1900


class Patched(FunctionBuilder):
    """A FunctionBuilder whose JSON gets the S1 fields (or a hand-made defect)."""

    def __init__(self, *, isa="isa", lengths=True, continuations=None, edit=None, **kwargs):
        super().__init__(**kwargs)
        self._isa, self._lengths, self._continuations, self._edit = isa, lengths, continuations, edit

    def to_json(self) -> dict:
        data = copy.deepcopy(super().to_json())
        if self._lengths:
            for row in data["instructions"]:
                row["length"] = self.stride
        if self._isa is not None:
            data["call_fallthrough"] = self._isa
            data["call_continuations"] = list(self._continuations or ())
        if self._edit is not None:
            self._edit(data)
        return data


def _caller(builder: FunctionBuilder) -> FunctionBuilder:
    return builder.call(CALLEE).ins(op("COPY", [const(1)], reg(RAX))).ret()


def _callee(entry=CALLEE) -> FunctionBuilder:
    return FunctionBuilder(entry=entry).ret()


def _unit(builder: FunctionBuilder, *others: FunctionBuilder):
    """The scoped unit of ``builder`` (the first function given; units keep that order --
    a refused function's scope has no entry to look it up by)."""
    units = program_units(builder, *others)
    assert len(units) == 1 + len(others)
    return units[0]


def _coordinate(address: int) -> dict:
    return {"space_id": RAM, "byte_offset": address}


def test_old_observation_digest_unchanged():
    """An observation without the S1 fields hashes exactly as before (pinned on main a3c9b52)."""
    unit = _unit(_caller(FunctionBuilder()), _callee())
    observation = unit.observation
    assert not observation.call_fallthrough_isa and observation.call_continuations == ()
    assert all(row.length is None for row in observation.instructions)
    preimage = _observation_preimage(observation)
    assert b"tdo-v2-call-fallthrough" not in preimage and b"tdo-v2-instruction-length" not in preimage
    assert sha256(preimage).digest() == _observation_digest(observation)
    assert _observation_digest(observation).hex() == PINNED_OLD_DIGEST


def test_isa_observation_admitted_with_lengths():
    unit = _unit(_caller(Patched()), _callee())
    observation = unit.observation
    assert observation is not None and observation.call_fallthrough_isa
    assert observation.call_continuations == ()
    assert {row.length for row in observation.instructions} == {4}
    preimage = _observation_preimage(observation)
    assert b"tdo-v2-call-fallthrough-isa-v1" in preimage and b"tdo-v2-instruction-length-v1" in preimage
    assert sha256(preimage).digest() == _observation_digest(observation)
    old = _unit(_caller(FunctionBuilder()), _callee()).observation
    assert _observation_digest(observation) != _observation_digest(old)


def _drop_call_fallthrough(data):
    row = data["instructions"][0]
    row["fallthrough_present"], row["fallthrough"] = False, None


def test_isa_native_call_without_fallthrough_is_refused():
    """In an ``isa`` observation a native call without fallthrough is malformed: the function is refused."""
    unit = _unit(_caller(Patched(edit=_drop_call_fallthrough)), _callee())
    assert unit.observation is None
    # the same row in an older observation reads as today (a call leaving the function)
    legacy = _unit(_caller(Patched(isa=None, lengths=False, edit=_drop_call_fallthrough)), _callee())
    assert legacy.observation is not None and not legacy.observation.call_fallthrough_isa


def test_interrupt_row_is_no_native_call():
    """Ghidra's INT3 (CALLOTHER swi; CALLIND; RETURN 0, no fallthrough) is not under the contract."""
    target = tmp(0x600, 8)
    builder = Patched()
    builder.call(CALLEE)
    builder.jump_indirect(target, op("CALLOTHER", [const(0x10, 4), const(3, 1)], target))
    unit = _unit(builder, _callee())
    assert unit.observation is not None and unit.observation.call_fallthrough_isa
    interrupt = [row for row in unit.observation.instructions if any(o.opcode == "CALLOTHER" for o in row.operations)]
    assert interrupt and not is_native_call(interrupt[0])


def _continue_into(address: int):
    def edit(data):
        data["instructions"][0]["fallthrough"] = _coordinate(address)
    return edit


def _continuation(call: int, target: int, kind: int, function: int | None) -> dict:
    return {"call": _coordinate(call), "target": _coordinate(target), "kind": kind,
            "function": None if function is None else _coordinate(function)}


def test_listed_continuation_into_a_function_entry_is_an_edge():
    builder = Patched(continuations=[_continuation(0x1000, OTHER, CONTINUATION_FUNCTION_ENTRY, OTHER)],
                      edit=_continue_into(OTHER))
    unit = _unit(_caller(builder), _callee(), _callee(OTHER))
    observation = unit.observation
    assert observation is not None
    (item,) = observation.call_continuations
    assert item.kind == CONTINUATION_FUNCTION_ENTRY and item.function.byte_offset == OTHER
    keys = {function_key(unit.scopes.function.entry), function_key(item.function), function_key(item.target)}
    found, wildcard = observed_calls(unit, keys)
    assert function_key(item.function) in found
    assert function_key(item.function) in _edges(function_key(unit.scopes.function.entry),
                                                SimpleNamespace(unit=unit, calls={}, multi_calls={}), keys)


def test_boundary_continuation_is_a_wildcard_and_no_edge():
    builder = Patched(continuations=[_continuation(0x1000, 0x1F00, CONTINUATION_BOUNDARY, None)],
                      edit=_continue_into(0x1F00))
    unit = _unit(_caller(builder), _callee())
    assert unit.observation is not None
    keys = {function_key(unit.scopes.function.entry)}
    _, wildcard = observed_calls(unit, keys)
    assert wildcard
    assert _edges(function_key(unit.scopes.function.entry),
                  SimpleNamespace(unit=unit, calls={}, multi_calls={}), keys) == set()


@pytest.mark.parametrize("builder", [
    # a non-local continuation that is not listed
    lambda: Patched(edit=_continue_into(OTHER)),
    # a local continuation that is listed
    lambda: Patched(continuations=[_continuation(0x1000, 0x1004, CONTINUATION_BOUNDARY, None)]),
    # a listed continuation whose target is not the call's fallthrough
    lambda: Patched(continuations=[_continuation(0x1000, 0x1F00, CONTINUATION_BOUNDARY, None)],
                    edit=_continue_into(OTHER)),
    # continuations without the contract
    lambda: Patched(edit=lambda data: data.pop("call_fallthrough")),
    # an unknown contract value
    lambda: Patched(edit=lambda data: data.update(call_fallthrough="ghidra")),
    # a boundary naming a function; an entry kind whose function is not the target
    lambda: Patched(continuations=[_continuation(0x1000, 0x1F00, CONTINUATION_BOUNDARY, OTHER)],
                    edit=_continue_into(0x1F00)),
    lambda: Patched(continuations=[_continuation(0x1000, OTHER, CONTINUATION_FUNCTION_ENTRY, CALLEE)],
                    edit=_continue_into(OTHER)),
    # an instruction length out of range
    lambda: Patched(edit=lambda data: data["instructions"][1].update(length=0)),
])
def test_contract_violations_are_refused(builder):
    unit = _unit(_caller(builder()), _callee(), _callee(OTHER))
    assert unit.observation is None


# _observation_digest of _unit(_caller(FunctionBuilder()), _callee()).observation on main a3c9b52
PINNED_OLD_DIGEST = "fb3180ec514340102f1a0dc87f5c7394742ce2dd3a8019e678be06f0fc92a3fd"
