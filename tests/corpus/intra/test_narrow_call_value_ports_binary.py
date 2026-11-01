"""Original DFB072 scalar home-slot copies across two real target bodies.

This proves narrow copy transport, not a new summary of x+1/x+2 or a choice
of one indirect target. Original p-code and the source/target alternatives
remain unchanged; no test-only call effect or ABI declaration is supplied.
"""

import os
from pathlib import Path

import pytest

from pcode_interpreter import Interpreter
from test_forward_call_value_ports_binary import GENERATION, IMAGE_SHA, NAMING_SHA, _link
from tdo_v2._call_value_ports import scalar_call_rows
from tdo_v2.configured_naming_contracts import NamingBindingExpectation
from tdo_v2.image_info import load_image_info
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.interprocedural import analyze_units, function_key


CASE, INDIRECT = "1b1:140002869", "1b1:1400028a9:3:CALLIND"
TARGETS = {
    "1b1:14000284b": ("cce746744c245546e4293018bc7e47d984f4a111b89ab618c1016e87c86126cf",
                      "1b1:14000284f:1:COPY", "1b1:14000284f:2:STORE", "1b1:140002852:1:LOAD", 1),
    "1b1:14000285a": ("3680af93f84a395c9989587e5b961a86fe9efa809e341a5fe21f4eabc3b0a5ee",
                      "1b1:14000285e:1:COPY", "1b1:14000285e:2:STORE", "1b1:140002861:1:LOAD", 2),
}
PINS = {
    CASE: "9bc856e74f446f8c190d6f73527a110d749632e9d7b872f4d79efe85c55e2e58",
    "1b1:1400019d0": "7263cffceb0c4a4860e85c0c12818f40d2c352f23ff7c639e946dfd0ff2966f3",
    "1b1:1400019ee": "d0872b745a1fe7bc77e1da490260f16a68e655fba21ea86bf75e6f1f6fa3f4a4",
    "1b1:140001a27": "4b2fbad5fdff39b84dcdf0b1293d187b692845fd39154f35cd9aa036f18ef33e",
    **{key: row[0] for key, row in TARGETS.items()},
}


@pytest.fixture(scope="module", params=("sparse", "dense"))
def actual(request):
    location = os.environ.get("TDO_LOADED_POINTER_DATA")
    if not location:
        pytest.skip("set TDO_LOADED_POINTER_DATA to the sealed Suite09 data")
    generation = Path(location) / "tdo_bundles3/v2-win-debug-full" / GENERATION
    binding = NamingBindingExpectation(bytes.fromhex(NAMING_SHA), "12.0.4")
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        units = {function_key(row.unit.scopes.function.entry): row.unit for row in session.iter_functions()
                 if function_key(row.unit.scopes.function.entry) in PINS}
    assert set(units) == set(PINS)
    for key, unit in units.items():
        assert unit.scopes.function.observation_digest.hex() == PINS[key]
        assert unit.scopes.program.evidence.executable_sha256.hex() == IMAGE_SHA
    info = load_image_info(generation)
    assert info is not None
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
        patch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
        patch.setenv("TDO_V2_FORWARD", "1")
        results = analyze_units(tuple(units.values()), image_info=info,
                                assume_globals_disjoint_from_stack=False)
    assert all(not result.declared and not result.test_only_inputs for result in results.values())
    return units, results


@pytest.mark.parametrize("target", tuple(TARGETS))
def test_actual_home_slot_four_bytes_keep_the_original_entry_register_identity(actual, target):
    units, results = actual
    item, (_, copy, writer, reader, delta) = results[target], TARGETS[target]
    normalized = item.normalized
    run, = [run for exit_ in item.summary.exits for run in exit_.runs if writer in run.writers]
    assert run.span.object_id.kind.value == "function_relative"
    assert (run.span.start, run.span.size) == ((1 << 64) + 8, 4)
    assert run.value is not None and run.value[0] == "same" and run.value[2] is False
    assert run.value[1].object_id.kind.value == "register_file"
    assert (run.value[1].start, run.value[1].size) == (8, 4)
    assert not run.debts and not run.crossed and not run.conditions
    _link(normalized, copy, writer, 4)
    _link(normalized, writer, reader, 4)
    # The next operation is still a real 32-bit ADD followed by ZEXT. Copy
    # metadata cannot turn that arithmetic into an input-register identity.
    rax, = [run for exit_ in item.summary.exits for run in exit_.runs
            if run.span.object_id.kind.value == "register_file" and run.span.start == 0 and run.span.size == 8]
    assert rax.value is None and rax.literal is None
    unit = units[target]
    for value in (0, 1, 0x7fffffff, 0xffffffff):
        vm = Interpreter(unit.observation, constant_space=48, seed=value)
        vm.preset(548, 32, 8, 0x70000000)
        vm.preset(548, 8, 4, value)
        concrete = vm.run()
        assert concrete.completed and not vm.opaque_opcodes
        dependencies = [row for row in concrete.dependencies if row.reader == reader and row.space_id == 433]
        assert {(row.offset, row.writer) for row in dependencies} == {
            (0x70000008 + byte, writer) for byte in range(4)}
        written = vm.final_bytes()
        assert [written[433, 0x70000008 + byte][0] for byte in range(4)] == list(value.to_bytes(4, "little"))
        assert sum(written[548, byte][0] << (8 * byte) for byte in range(8)) == (value + delta) & 0xffffffff


def test_actual_two_targets_share_only_their_equal_home_slot_copy_not_their_different_return_arithmetic(actual):
    _, results = actual
    item = results[CASE]
    assert item.multi_calls[INDIRECT] == tuple(TARGETS)
    effect = item.proven[INDIRECT]
    index, run = next((index + len(effect.runs), run) for index, run in enumerate(effect.memory_runs)
                      if run.write.anchor is not None and run.write.anchor.start == 32
                      and (run.write.displacement, run.write.size) == (8, 4))
    assert run.value is not None and run.value[0] == "same_reg" and run.value[2] is False
    assert (run.value[1].start, run.value[1].size) == (8, 4)
    key = f"{INDIRECT}~{index}"
    port = scalar_call_rows(item.normalized)[key]
    assert (port.width, port.row[0], port.row[2].byte_size) == (4, "reg", 4)
    assert dict(item.normalized.call_value_inputs)[port.row[1]] == 2
    rax = [run for run in effect.runs if any(span.start == 0 for span in run.writes)]
    assert rax and all(run.value is None and run.literal is None for run in rax)
    assert not effect.fresh_registers and not effect.same_object_registers
    # No default premise was strengthened and ordinary source/global alias
    # diagnostics still exist. This is not a claim of complete DFB072 proof.
    assert item.normalized.may_alias_reads
    assert all(label != "globals-disjoint-from-stack" for label, _, _ in item.normalized.premise_uses)
