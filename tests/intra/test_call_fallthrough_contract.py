"""S1 (design_scc_conditions r10 section 2): the ISA call-fallthrough contract of an observation.

The exporter disables Ghidra's non-returning analyzers and writes, per function, ``call_fallthrough: "isa"``
(every native call keeps its ISA fallthrough, verified per call), ``fallthrough_exits`` (rows whose fallthrough
leaves the function or reaches another function's entry, classified 2 entry / 3 interior / 4 boundary) and a
``length`` per instruction. The engine admits them, refuses an observation that breaks the contract, keeps the
digest of an observation without them unchanged, reads a non-local exit as today's tail exit, and adds exits into
another function as reachability edges (control contexts, F1 / ``site_reach``, fault references)."""

from __future__ import annotations

import copy
from hashlib import sha256
from types import SimpleNamespace

import pytest

from synthetic import RAM, RAX, FunctionBuilder, const, op, program_units, reg, tmp
from tdo_v2._scope_contracts import (
    CONTINUATION_BOUNDARY, CONTINUATION_FOREIGN_INTERIOR, CONTINUATION_FUNCTION_ENTRY, is_interrupt_shape,
    is_native_call,
)
from tdo_v2._scope_wire import _observation_digest, _observation_preimage
from tdo_v2.control_context import _edges
from tdo_v2.fault_premise import observed_calls
from tdo_v2.function_summary import _tail_exits
from tdo_v2.interprocedural import _fallthrough_references, function_key
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction

CALLEE = 0x1800
OTHER = 0x1900
UNMAPPED = 0x900000   # outside the synthetic layout's memory


class Patched(FunctionBuilder):
    """A FunctionBuilder whose JSON gets the S1 fields (or a hand-made defect)."""

    def __init__(self, *, isa="isa", lengths=True, exits=None, edit=None, **kwargs):
        super().__init__(**kwargs)
        self._isa, self._lengths, self._exits, self._edit = isa, lengths, exits, edit

    def to_json(self) -> dict:
        data = copy.deepcopy(super().to_json())
        if self._lengths:
            for row in data["instructions"]:
                row["length"] = self.stride
        if self._isa is not None:
            data["call_fallthrough"] = self._isa
            data["fallthrough_exits"] = list(self._exits or ())
        if self._edit is not None:
            self._edit(data)
        return data


def _caller(builder: FunctionBuilder) -> FunctionBuilder:
    return builder.call(CALLEE).ins(op("COPY", [const(1)], reg(RAX))).ret()


CALL, PAD = 0x1004, 0x1008   # the call row of ``_branchy`` / ``_padded``; the padding row of ``_padded``


def _branchy(builder: FunctionBuilder) -> FunctionBuilder:
    """``jcc end; call CALLEE; end: ret`` -- the ret stays reachable when the call's fallthrough leaves."""
    return builder.cbranch("end", reg(RAX, 1)).call(CALLEE).label("end").ret()


def _padded(builder: FunctionBuilder) -> FunctionBuilder:
    """``jcc end; call CALLEE; pad; end: ret`` -- the pad row may fall out of the function."""
    return builder.cbranch("end", reg(RAX, 1)).call(CALLEE).ins(op("COPY", [const(0)], reg(RAX))).label("end").ret()


def _callee(entry=CALLEE) -> FunctionBuilder:
    return FunctionBuilder(entry=entry).ret()


def _other(entry=OTHER) -> FunctionBuilder:
    """A function with an interior instruction at ``entry + 4``."""
    return FunctionBuilder(entry=entry).ins(op("COPY", [const(2)], reg(RAX))).ret()


def _unit(builder: FunctionBuilder, *others: FunctionBuilder):
    """The scoped unit of ``builder`` (the first function given; units keep that order --
    a refused function's scope has no entry to look it up by)."""
    units = program_units(builder, *others)
    assert len(units) == 1 + len(others)
    return units[0]


def _coordinate(address: int) -> dict:
    return {"space_id": RAM, "byte_offset": address}


def _exit(source: int, target: int, kind: int, function: int | None) -> dict:
    return {"source": _coordinate(source), "target": _coordinate(target), "kind": kind,
            "function": None if function is None else _coordinate(function)}


def _fall_into(address: int, row: int = 0):
    def edit(data):
        data["instructions"][row]["fallthrough"] = _coordinate(address)
    return edit


def _digests_agree(observation) -> bytes:
    preimage = _observation_preimage(observation)
    assert sha256(preimage).digest() == _observation_digest(observation)
    return preimage


def _item(unit):
    return SimpleNamespace(unit=unit, calls={}, multi_calls={})


def _keys(unit, *entries):
    return {function_key(unit.scopes.function.entry), *(function_key(entry) for entry in entries)}


def test_old_observation_digest_unchanged():
    """An observation without the S1 fields hashes exactly as before (pinned on main a3c9b52)."""
    observation = _unit(_caller(FunctionBuilder()), _callee()).observation
    assert not observation.call_fallthrough_isa and observation.fallthrough_exits == ()
    assert all(row.length is None for row in observation.instructions)
    preimage = _digests_agree(observation)
    assert b"tdo-v2-call-fallthrough" not in preimage and b"tdo-v2-instruction-length" not in preimage
    assert _observation_digest(observation).hex() == PINNED_OLD_DIGEST


def test_isa_observation_admitted_with_lengths():
    observation = _unit(_caller(Patched()), _callee()).observation
    assert observation is not None and observation.call_fallthrough_isa
    assert observation.fallthrough_exits == ()
    assert {row.length for row in observation.instructions} == {4}
    preimage = _digests_agree(observation)
    assert b"tdo-v2-call-fallthrough-isa-v1" in preimage and b"tdo-v2-instruction-length-v1" in preimage
    old = _unit(_caller(FunctionBuilder()), _callee()).observation
    assert _observation_digest(observation) != _observation_digest(old)


def test_mixed_lengths_admitted():
    observation = _unit(_caller(Patched(edit=lambda data: data["instructions"][1].pop("length"))), _callee()).observation
    assert [row.length for row in observation.instructions] == [4, None, 4]
    _digests_agree(observation)


def _drop_call_fallthrough(data):
    row = data["instructions"][0]
    row["fallthrough_present"], row["fallthrough"] = False, None


def test_isa_native_call_without_fallthrough_is_refused():
    """In an ``isa`` observation a native call without fallthrough is malformed: the function is refused."""
    assert _unit(_caller(Patched(edit=_drop_call_fallthrough)), _callee()).observation is None
    # the same row in an older observation reads as today (a call leaving the function)
    legacy = _unit(_caller(Patched(isa=None, lengths=False, edit=_drop_call_fallthrough)), _callee())
    assert legacy.observation is not None and not legacy.observation.call_fallthrough_isa


def _operation(ordinal, opcode, inputs, output=None):
    return {"ordinal": ordinal, "opcode": opcode, "inputs": inputs, "output_present": output is not None,
            "output": output}


def _int3(data):
    """Row 1 becomes Ghidra's INT3: v = CALLOTHER swi(3); CALLIND v; RETURN 0 -- no fallthrough."""
    v = tmp(0x600, 8)
    row = data["instructions"][1]
    row["fallthrough_present"], row["fallthrough"] = False, None
    row["operations"] = [_operation(0, "CALLOTHER", [const(0x10, 4), const(3, 1)], v),
                         _operation(1, "CALLIND", [v]), _operation(2, "RETURN", [const(0, 1)])]


def _user_op_call(data):
    """Row 0 (the call) gets an unrelated CALLOTHER before its CALL and loses its fallthrough."""
    row = data["instructions"][0]
    row["operations"].insert(0, _operation(0, "CALLOTHER", [const(0x99, 4)], tmp(0x700, 8)))
    for ordinal, operation in enumerate(row["operations"]):
        operation["ordinal"] = ordinal
    row["fallthrough_present"], row["fallthrough"] = False, None


def test_interrupt_shape_is_no_native_call_but_other_user_ops_are():
    unit = _unit(_caller(Patched(edit=_int3)), _callee())
    assert unit.observation is not None and unit.observation.call_fallthrough_isa
    row = unit.observation.instructions[1]
    assert is_interrupt_shape(row) and not is_native_call(row)
    # a CALL beside an unrelated CALLOTHER is still a native call: no fallthrough -> refused
    assert _unit(_caller(Patched(edit=_user_op_call)), _callee()).observation is None


def test_exit_into_a_function_entry_is_a_tail_exit_and_an_edge():
    builder = Patched(exits=[_exit(CALL, OTHER, CONTINUATION_FUNCTION_ENTRY, OTHER)], edit=_fall_into(OTHER, row=1))
    unit = _unit(_branchy(builder), _callee(), _other())
    observation = unit.observation
    (item,) = observation.fallthrough_exits
    assert item.kind == CONTINUATION_FUNCTION_ENTRY and item.function.byte_offset == OTHER
    assert b"tdo-v2-call-fallthrough-isa-v1" in _digests_agree(observation)
    own, other = function_key(unit.scopes.function.entry), function_key(item.function)
    callee = function_key(unit.observation.instructions[1].flow_targets[0])
    found, wildcard = observed_calls(unit, {own, other, callee})
    assert found.get(other) == (CALL,) and not wildcard   # (the call to CALLEE is inside the keys too)
    assert other in _edges(own, _item(unit), {own, other})
    # read as today's tail exit (UNKNOWN state), never composed
    normalized = FunctionNormalizer().normalize(unit)
    assert type(normalized) is NormalizedFunction
    assert _tail_exits(normalized, observation)


def test_exit_into_another_functions_interior():
    interior = OTHER + 4
    builder = Patched(exits=[_exit(CALL, interior, CONTINUATION_FOREIGN_INTERIOR, OTHER)],
                      edit=_fall_into(interior, row=1))
    unit = _unit(_branchy(builder), _callee(), _other())
    (item,) = unit.observation.fallthrough_exits
    assert item.kind == CONTINUATION_FOREIGN_INTERIOR
    _digests_agree(unit.observation)
    own, other = function_key(unit.scopes.function.entry), function_key(item.function)
    assert other in _edges(own, _item(unit), {own, other})
    # a function outside the analysed keys: no edge, a wildcard for F1
    found, wildcard = observed_calls(unit, {own})
    assert wildcard and other not in found
    assert _edges(own, _item(unit), {own}) == set()


def test_unmapped_boundary_keeps_the_function():
    """A call whose ISA continuation is outside program memory: admitted as a kind-4 exit (the row keeps no
    fallthrough), the function stays; without the listing it is refused as before S1."""
    builder = Patched(exits=[_exit(CALL, UNMAPPED, CONTINUATION_BOUNDARY, None)], edit=_fall_into(UNMAPPED, row=1))
    unit = _unit(_branchy(builder), _callee())
    assert unit.observation is not None
    assert unit.observation.instructions[1].fallthrough is None
    (item,) = unit.observation.fallthrough_exits
    assert item.kind == CONTINUATION_BOUNDARY and item.target.byte_offset == UNMAPPED
    own = function_key(unit.scopes.function.entry)
    assert observed_calls(unit, {own})[1]   # kind 4: wildcard
    assert _edges(own, _item(unit), {own}) == set()
    assert _unit(_branchy(Patched(edit=_fall_into(UNMAPPED, row=1))), _callee()).observation is None


def test_non_call_row_falling_out_is_listed():
    """Padding after a call falls into the next function: a non-call row's exit, listed and an edge."""
    builder = Patched(exits=[_exit(PAD, OTHER, CONTINUATION_FUNCTION_ENTRY, OTHER)],
                      edit=_fall_into(OTHER, row=2))
    unit = _unit(_padded(builder), _callee(), _other())
    assert unit.observation is not None
    (item,) = unit.observation.fallthrough_exits
    own, other = function_key(unit.scopes.function.entry), function_key(item.function)
    assert other in _edges(own, _item(unit), {own, other})
    assert observed_calls(unit, {own, other})[0].get(other) == (PAD,)
    # unlisted: refused
    assert _unit(_padded(Patched(edit=_fall_into(OTHER, row=2))), _callee(), _other()).observation is None


def test_shared_entry_inside_the_function_is_kind_2():
    """A local successor that is another function's entry (shared code) is listed as kind 2 and is an edge."""
    shared = CALL + 4
    unit = _unit(_branchy(Patched(exits=[_exit(CALL, shared, CONTINUATION_FUNCTION_ENTRY, shared)])), _callee())
    assert unit.observation is not None
    (item,) = unit.observation.fallthrough_exits
    assert item.kind == CONTINUATION_FUNCTION_ENTRY and item.target == unit.observation.instructions[2].address
    own, shared_key = function_key(unit.scopes.function.entry), function_key(item.function)
    assert shared_key in _edges(own, _item(unit), {own, shared_key})
    # a local successor listed with another kind is refused
    wrong = Patched(exits=[_exit(CALL, shared, CONTINUATION_BOUNDARY, None)])
    assert _unit(_branchy(wrong), _callee()).observation is None


def _tail_exits_of(unit):
    normalized = FunctionNormalizer().normalize(unit)
    assert type(normalized) is NormalizedFunction
    return _tail_exits(normalized, unit.observation)


def test_unmapped_exit_beside_a_local_successor_is_a_tail_exit():
    """A conditional jump whose fallthrough is unmapped (kind 4) keeps its local branch target: the block is
    still a tail exit (UNKNOWN to callers, template refused) -- not only blocks without local successors."""
    def jump_on(builder):   # ``jcc body`` whose fallthrough is edited away; ``body: call CALLEE; ret``
        return builder.cbranch("body", reg(RAX, 1)).label("body").call(CALLEE).ret()

    builder = Patched(exits=[_exit(0x1000, UNMAPPED, CONTINUATION_BOUNDARY, None)], edit=_fall_into(UNMAPPED))
    unit = _unit(jump_on(builder), _callee())
    assert unit.observation is not None and unit.observation.instructions[0].fallthrough is None
    assert any(key.startswith("1:1000") for key in _tail_exits_of(unit))
    assert _tail_exits_of(_unit(jump_on(Patched()), _callee())) == ()


def test_shared_entry_successor_is_a_tail_exit():
    """Shared code: the local successor is another function's entry -- analysed inline, and still a tail exit."""
    unit = _unit(_caller(Patched(exits=[_exit(0x1000, 0x1004, CONTINUATION_FUNCTION_ENTRY, 0x1004)])), _callee())
    assert any(key.startswith("1:1000") for key in _tail_exits_of(unit))


def _empty_pad(data):
    """The pad row (row 2) has no p-code (a NOP) and falls into OTHER."""
    row = data["instructions"][2]
    row["operations"] = []
    row["fallthrough"] = _coordinate(OTHER)


def test_fault_reference_sites_of_exits():
    """Exits into another function are reported at an instruction-level site with a FALLTHROUGH suffix --
    a row without p-code (a NOP falling out) included."""
    unit = _unit(_padded(Patched(exits=[_exit(PAD, OTHER, CONTINUATION_FUNCTION_ENTRY, OTHER)], edit=_empty_pad)),
                 _callee(), _other())
    assert unit.observation is not None
    assert _fallthrough_references(unit.observation) == {f"1:{PAD:x}:0:FALLTHROUGH": {f"{RAM:x}:{OTHER:x}"}}
    call = _unit(_branchy(Patched(exits=[_exit(CALL, OTHER, CONTINUATION_FUNCTION_ENTRY, OTHER)],
                                  edit=_fall_into(OTHER, row=1))), _callee(), _other())
    (site,) = _fallthrough_references(call.observation)
    assert site.startswith(f"1:{CALL:x}:") and site.endswith(":FALLTHROUGH")
    assert _fallthrough_references(_unit(_caller(Patched()), _callee()).observation) == {}


def _drop_flag_fall_into_other(data):
    data.pop("call_fallthrough")
    _fall_into(OTHER, row=1)(data)


@pytest.mark.parametrize("builder", [
    # a non-local fallthrough that is not listed
    lambda: Patched(edit=_fall_into(OTHER, row=1)),
    # a listed exit whose target is not the row's fallthrough
    lambda: Patched(exits=[_exit(CALL, 0x1F00, CONTINUATION_BOUNDARY, None)], edit=_fall_into(OTHER, row=1)),
    # exits without the contract
    lambda: Patched(exits=[_exit(CALL, OTHER, CONTINUATION_FUNCTION_ENTRY, OTHER)],
                    edit=_drop_flag_fall_into_other),
    # an unknown contract value
    lambda: Patched(edit=lambda data: data.update(call_fallthrough="ghidra")),
    # a boundary naming a function; an entry kind whose function is not the target
    lambda: Patched(exits=[_exit(CALL, 0x1F00, CONTINUATION_BOUNDARY, OTHER)], edit=_fall_into(0x1F00, row=1)),
    lambda: Patched(exits=[_exit(CALL, OTHER, CONTINUATION_FUNCTION_ENTRY, CALLEE)], edit=_fall_into(OTHER, row=1)),
    # an exit naming the function itself
    lambda: Patched(exits=[_exit(CALL, 0x1F00, CONTINUATION_FOREIGN_INTERIOR, 0x1000)], edit=_fall_into(0x1F00, row=1)),
    # two exits for one row
    lambda: Patched(exits=[_exit(CALL, OTHER, CONTINUATION_FUNCTION_ENTRY, OTHER),
                           _exit(CALL, OTHER, CONTINUATION_FUNCTION_ENTRY, OTHER)], edit=_fall_into(OTHER, row=1)),
    # an instruction length out of range
    lambda: Patched(edit=lambda data: data["instructions"][1].update(length=0)),
])
def test_contract_violations_are_refused(builder):
    assert _unit(_branchy(builder()), _callee(), _other()).observation is None


# _observation_digest of _unit(_caller(FunctionBuilder()), _callee()).observation on main a3c9b52
PINNED_OLD_DIGEST = "fb3180ec514340102f1a0dc87f5c7394742ce2dd3a8019e678be06f0fc92a3fd"
