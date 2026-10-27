"""_stack_taint's states as ints (docs 25.31 B0-6): on four exported
Bundles and a scale fixture every call gives the same reached keys,
successors, escapes, switches, returning RETURNs and worklist pops (work
units) as the former frozenset states, kept here as the oracle."""

import sys
from pathlib import Path

import pytest

from tdo_v2 import may_alias
from tdo_v2.call_seeds import _operation_key
from tdo_v2.may_alias import _BOOLEAN_OPCODES, _NON_VALUE_OPCODES, VarnodeKindCode
from tdo_v2.resource_limits import step

REPO = Path(__file__).resolve().parents[2]
BUNDLES = Path("/root/tdo_bundles3")


def _old_stack_taint(observation, register_space: int, offset: int, size: int,
                 assumed_calls=frozenset(), entry_key: str | None = None, observed_calls=None,
                 escaping_calls=frozenset(), returning: set | None = None, pops: list | None = None):
    """Forward over the p-code block graph (``pcode_blocks``), tracking which
    register and temporary bytes hold a stack-derived value at each point.

    Returns (operation keys per reached block, block successors, escape keys,
    switch keys), or None when the graph is unsupported. An operation escapes
    when it stores a stack-derived value to memory (a STORE, or any operation
    with a memory output), passes one to CALLOTHER, or
    is a call that is not a declared (TEST-ONLY assumed) boundary call while a
    register other than the stack pointer holds one (every register is
    visible to a callee; ``observed_calls``: call key -> the register byte
    offsets a call may use as an address or keep, when that is declared --
    then only those count), or is one of ``escaping_calls`` (a call that may
    leave a stack-derived value in an output, which this forward pass does not
    follow: an escape whatever is tainted). ``returning`` collects the
    RETURNs reached with a register other than the stack pointer holding a
    stack-derived value; ``pops`` ([0]) counts the worklist pops (one work
    unit each). ``push rbp`` before ``mov rbp, rsp`` therefore
    stores the caller's RBP, not a stack address. A switch writes the stack
    pointer with a value not derived from it (``mov rsp, [x]``).
    """
    from tdo_v2.pcode_blocks import build_pcode_block_graph, instruction_key

    instructions = {row.address: row for row in observation.instructions}
    if not instructions:
        return None
    stack_bytes = frozenset((register_space, offset + index) for index in range(size))
    entry = next(
        (address for address in instructions if instruction_key(address) == entry_key),
        min(instructions),
    )
    graph = build_pcode_block_graph(observation, entry)
    if graph.unsupported is not None:
        return None
    blocks = {block.key: block for block in graph.blocks}

    def bytes_of(varnode):
        return {
            (varnode.coordinate.space_id, varnode.coordinate.byte_offset + index)
            for index in range(varnode.byte_size)
        }

    def transfer(block, state, escapes, switches):
        row = instructions[block.instruction]
        tainted = set(state)
        for ordinal in range(block.start, block.stop):
            operation = row.operations[ordinal]
            touches = lambda varnode: varnode is not None and bool(bytes_of(varnode) & tainted)
            key = _operation_key(row.address, ordinal, operation.opcode)
            if escapes is not None and (
                (operation.opcode == "STORE" and len(operation.inputs) == 3 and touches(operation.inputs[2]))
                or (operation.opcode == "CALLOTHER" and any(touches(item) for item in operation.inputs))
                or key in escaping_calls
                # a direct memory output (``COPY ram[x], rsp``) is a store too
                or (operation.output is not None
                    and operation.output.kind not in (VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE)
                    and any(touches(item) for item in operation.inputs))
                or (
                    operation.opcode in ("CALL", "CALLIND")
                    and key not in assumed_calls
                    and any(item[0] == register_space
                            and (observed is None or item[1] in observed)
                            for item in tainted - stack_bytes
                            for observed in ((observed_calls or {}).get(key),))
                )
            ):
                escapes.add(key)
            if returning is not None and escapes is not None and operation.opcode == "RETURN" \
                    and any(item[0] == register_space for item in tainted - stack_bytes):
                returning.add(key)
            output = operation.output
            if output is None or output.kind not in (VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE):
                continue
            produced = (
                operation.opcode not in _NON_VALUE_OPCODES
                and operation.opcode not in _BOOLEAN_OPCODES
                and any(touches(item) for item in operation.inputs)
            )
            written = bytes_of(output)
            if switches is not None and written & stack_bytes and not produced:
                switches.add(key)
            tainted -= written
            if produced:
                tainted |= written
        return frozenset(tainted)

    order = {block.key: index for index, block in enumerate(graph.blocks)}
    in_states = {graph.entry: stack_bytes}
    pending = {graph.entry}
    while pending:
        step()   # (budget: docs 25.30 K1c)
        if pops is not None:
            pops[0] += 1   # (the units charged, replayed by an escape memo hit)
        key = min(pending, key=order.__getitem__)
        pending.remove(key)
        out = transfer(blocks[key], in_states[key], None, None)
        for target in blocks[key].successors:
            if target not in blocks:
                continue
            merged = out | in_states.get(target, frozenset())
            if merged != in_states.get(target):
                in_states[target] = merged
                pending.add(target)
    escapes: set[str] = set()
    switches: set[str] = set()
    for key, state in in_states.items():
        transfer(blocks[key], state, escapes, switches)
    keys = {}
    for block in graph.blocks:
        if block.key in in_states:
            row = instructions[block.instruction]
            keys[block.key] = [
                _operation_key(row.address, ordinal, row.operations[ordinal].opcode)
                for ordinal in range(block.start, block.stop)
            ]
    successors = {
        key: [target for target in blocks[key].successors if target in keys] for key in keys
    }
    return keys, successors, escapes, switches


@pytest.fixture
def compared(monkeypatch):
    new = may_alias._stack_taint
    calls = []

    def both(*args, returning=None, pops=None, frame=None, tainted_loads=None, **kwargs):
        # (the sets oracle has no held frame slots, docs 25.78: it is compared
        # with the bits run without ``frame``; the caller gets the real run)
        old_returning, new_returning = set(), set()
        old_pops, new_pops = [0], [0]
        expected = _old_stack_taint(*args, returning=old_returning, pops=old_pops, **kwargs)
        found = new(*args, returning=new_returning, pops=new_pops, **kwargs)
        assert found == expected
        assert new_returning == old_returning and new_pops == old_pops
        if frame is not None:
            new_returning, new_pops = set(), [0]
            found = new(*args, returning=new_returning, pops=new_pops, frame=frame, tainted_loads=tainted_loads,
                        **kwargs)
        calls.append(new_pops[0])
        if returning is not None:
            returning |= new_returning
        if pops is not None:
            pops[0] += new_pops[0]
        return found

    monkeypatch.setattr(may_alias, "_stack_taint", both)
    return calls


def _generations():
    found = []
    for name in ("v2-win-debug-full", "v3-win32-release-full", "corpus/clang-x64-O2", "corpus/gcc-x64-O3"):
        root = BUNDLES / name
        generations = sorted(path for path in root.glob("*/") if path.is_dir()) if root.is_dir() else []
        if generations:
            found.append(generations[0])
    return found


def _analyze_bundle(generation):
    sys.path.insert(0, str(REPO / "tools" / "bundle_export"))
    import run_dfbench
    from tdo_v2 import summary_engine

    summary_engine.analyze_frozen_bundle_with_summaries(
        generation, naming_exporter_source=REPO / "ghidra" / "GhidraV2CallNaming.java",
        boundary_provider=run_dfbench.boundary_provider(False, run_dfbench.abi_of(generation)),
        pcodeop_models=run_dfbench.pcodeop_models(), external_models=run_dfbench.external_models(generation))


@pytest.mark.skipif(not _generations(), reason="no exported Bundle here")
@pytest.mark.parametrize("generation", _generations(), ids=lambda path: path.parent.name)
def test_bundle_taints_match_the_sets(generation, compared):
    _analyze_bundle(generation)
    assert compared and sum(compared) > 0   # (a non-vacuous comparison)


def test_scale_fixture_taints_match_the_sets(compared):
    sys.path.insert(0, str(REPO / "tests" / "intra"))
    import scale_fixtures
    import synthetic
    from tdo_v2.summary_engine import analyze_observed_with_summaries

    program = scale_fixtures.realistic(3000, 0)
    inputs = synthetic.summary_inputs(program.functions, program.names, layout=program.layout,
                                      data=program.data, image=True)
    analyze_observed_with_summaries(
        inputs.program, inputs.evidences, image_info=inputs.image_info, readonly_image=inputs.readonly_image,
        boundary_provider=program.provider, pcodeop_models=program.pcodeop_models(inputs.evidences))
    assert compared and sum(compared) > 0
