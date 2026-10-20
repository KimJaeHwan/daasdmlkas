"""The stack-switch check's overlap table (docs 25.31 B0-3): every
``_coefficient_pass`` on the exported Bundles and a scale fixture gives the
same switches as the former whole-state scan, kept here as the oracle."""

import sys
from hashlib import sha256
from pathlib import Path

import pytest

from tdo_v2 import may_alias
from tdo_v2.may_alias import _BOOLEAN_OPCODES, MAX_STACK_ALIGNMENT, VarnodeKindCode, _operation_key
from tdo_v2.resource_limits import step

REPO = Path(__file__).resolve().parents[2]
BUNDLES = Path("/root/tdo_bundles3")


def _old_coefficient_pass(graph, instructions, stack, preserved) -> set:
    """The former implementation (a scan of the whole state per access)."""
    blocks = {block.key: block for block in graph.blocks}

    def location(varnode):
        return (varnode.coordinate.space_id, varnode.coordinate.byte_offset, varnode.byte_size)

    def overlaps(a, b):
        return a[0] == b[0] and a[1] < b[1] + b[2] and b[1] < a[1] + a[2]

    def read(state, varnode):
        if varnode.kind is VarnodeKindCode.CONSTANT:
            return 0
        key = location(varnode)
        if key in state:
            return state[key]
        return None if any(value != 0 and overlaps(key, other) for other, value in state.items()) else 0

    def write(state, key, value):
        for other in [other for other in state if overlaps(key, other)]:
            covered = key[1] <= other[1] and other[1] + other[2] <= key[1] + key[2]
            if covered:
                del state[other]
            else:
                state[other] = None
        if value != 0:
            state[key] = value
        elif key in state:
            del state[key]

    def coefficient(operation, state):
        opcode = operation.opcode
        values = [read(state, item) for item in operation.inputs]
        if opcode == "COPY" and values:
            return values[0]
        if opcode in ("INT_ADD", "INT_SUB") and len(values) == 2:
            if None in values:
                return None
            total = values[0] + values[1] if opcode == "INT_ADD" else values[0] - values[1]
            return total if total in (0, 1) else None
        if opcode == "INT_AND" and len(values) == 2:
            for index in (0, 1):
                mask = operation.inputs[1 - index]
                if mask.kind is VarnodeKindCode.CONSTANT and values[index] is not None:
                    if values[index] == 0:
                        return 0
                    low = (1 << (8 * mask.byte_size)) - mask.coordinate.byte_offset
                    return 1 if 0 < low <= MAX_STACK_ALIGNMENT and low & (low - 1) == 0 else None
        if opcode == "LOAD" or opcode in _BOOLEAN_OPCODES:
            return 0
        return 0 if all(value == 0 for value in values) else None

    def transfer(block, state, switches):
        row = instructions[block.instruction]
        state = dict(state)
        for ordinal in range(block.start, block.stop):
            operation = row.operations[ordinal]
            if operation.opcode in ("CALL", "CALLIND"):
                for key in [key for key in state if key[0] == stack[0] and key != stack
                            and not any(key[1] >= kept[1] and key[1] + key[2] <= kept[1] + kept[2]
                                        for kept in preserved)]:
                    del state[key]
            output = operation.output
            if output is None or output.kind not in (VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE):
                continue
            value = coefficient(operation, state)
            key = location(output)
            if overlaps(key, stack):
                if switches is not None and not (key == stack and value == 1):
                    switches.add(_operation_key(row.address, ordinal, operation.opcode))
                write(state, key, 1)
                write(state, stack, 1)
                continue
            write(state, key, value)
        return state

    def merge(a, b):
        merged = {}
        for key in set(a) | set(b):
            left, right = a.get(key, 0), b.get(key, 0)
            value = left if left == right else None
            if value != 0:
                merged[key] = value
        return merged

    order = {block.key: index for index, block in enumerate(graph.blocks)}
    in_states = {graph.entry: {stack: 1}}
    pending = {graph.entry}
    while pending:
        step()
        key = min(pending, key=order.__getitem__)
        pending.remove(key)
        out = transfer(blocks[key], in_states[key], None)
        for target in blocks[key].successors:
            if target not in blocks:
                continue
            merged = out if target not in in_states else merge(out, in_states[target])
            if merged != in_states.get(target):
                in_states[target] = merged
                pending.add(target)
    switches: set[str] = set()
    for key, state in in_states.items():
        transfer(blocks[key], state, switches)
    return switches


@pytest.fixture
def compared(monkeypatch):
    """Every pass run both ways; the count of compared passes."""
    new = may_alias._coefficient_pass
    calls = []

    def both(graph, instructions, stack, preserved):
        found = new(graph, instructions, stack, preserved)
        assert found == _old_coefficient_pass(graph, instructions, stack, preserved)
        calls.append(len(found))
        return found

    monkeypatch.setattr(may_alias, "_coefficient_pass", both)
    return calls


def _generations():
    found = []
    for name in ("v2-win-debug-full", "v3-win32-release-full", "corpus/clang-x64-O2", "corpus/clang-x86-O2"):
        root = BUNDLES / name
        generations = sorted(path for path in root.glob("*/") if path.is_dir()) if root.is_dir() else []
        if generations:
            found.append(generations[0])
    return found


@pytest.mark.skipif(not _generations(), reason="no exported Bundle here")
@pytest.mark.parametrize("generation", _generations(), ids=lambda path: path.parent.name)
def test_bundle_switch_checks_match_the_scan(generation, compared):
    from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
    from tdo_v2.integration.configured_bundle import admit_frozen_bundle
    from tdo_v2.integration.observed_function_session import open_observed_function_session
    from tdo_v2.interprocedural import program_switches_stack

    exporter = REPO / "ghidra" / "GhidraV2CallNaming.java"
    binding = NamingBindingExpectation(sha256(exporter.read_bytes()).digest(), CALL_NAMING_GHIDRA_VERSION)
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        units = [evidence.unit for evidence in session.iter_functions()]
    program_switches_stack(units)
    assert compared   # (a non-vacuous comparison)


def test_scale_fixture_switch_checks_match_the_scan(compared):
    sys.path.insert(0, str(REPO / "tests" / "intra"))
    import scale_fixtures
    import synthetic
    from tdo_v2.interprocedural import program_switches_stack

    program = scale_fixtures.realistic(3000, 0)
    inputs = synthetic.summary_inputs(program.functions, program.names, layout=program.layout,
                                      data=program.data, image=True)
    program_switches_stack([evidence.unit for evidence in inputs.evidences])
    assert compared


@pytest.mark.parametrize("live", [0, 1, 4])
def test_stored_states_decoded_when_not_kept_live(live, compared, monkeypatch):
    """B0-10: pending blocks beyond ``_LIVE_STATES`` decode their stored
    state -- the same switches as the scan whatever the bound."""
    sys.path.insert(0, str(REPO / "tests" / "intra"))
    import scale_fixtures
    import synthetic
    from tdo_v2.interprocedural import program_switches_stack

    monkeypatch.setattr(may_alias, "_LIVE_STATES", live)
    program = scale_fixtures.realistic(3000, 1)
    inputs = synthetic.summary_inputs(program.functions, program.names, layout=program.layout,
                                      data=program.data, image=True)
    program_switches_stack([evidence.unit for evidence in inputs.evidences])
    assert compared
