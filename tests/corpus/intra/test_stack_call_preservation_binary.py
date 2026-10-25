"""Original Suite09 calls preserve stack-derived RBP by raw byte identity.

Set TDO_STACK_CALL_PRESERVATION_BUNDLE to the full sealed 115-function
Suite09 bundle. The smaller DFB044 fixture supplies the existing admission,
image and original p-code oracle helpers; no instruction is replaced.
"""

import os

import pytest

from forward_oracle import _Recording
from program_oracle import check_program
from test_forward_memory_footprints_binary import (
    SOURCE_INPUTS, VARIABLE, actual as _actual_fixture,
)
from tdo_v2 import _stack_preservation, may_alias
from tdo_v2.function_summary import SummaryKind
from tdo_v2.interprocedural import analyze_units, program_switches_stack
from tdo_v2.memory_contracts import MemoryDefinitionKind


CALLER, SOURCE_A, SINK = "1b1:1056f4", "1b1:10453b", "1b1:104595"
CALL, FRAME_COPY, RESTORE_SP = "1b1:1056ff:2:CALL", "1b1:1056f5:0:COPY", "1b1:105704:0:COPY"
SOURCE_ROWS = (
    (SOURCE_A, "1b1:10453b:2:STORE", "1b1:104548:1:LOAD", "1b1:104548:3:COPY"),
    ("1b1:10454a", "1b1:10454a:2:STORE", "1b1:104557:1:LOAD", "1b1:104557:3:COPY"),
    ("1b1:104559", "1b1:104559:2:STORE", "1b1:104566:1:LOAD", "1b1:104566:3:COPY"),
)
RSP, RBP, RDI = 0x20, 0x28, 0x38


@pytest.fixture(scope="module")
def suite():
    location = os.environ.get("TDO_STACK_CALL_PRESERVATION_BUNDLE")
    if not location:
        pytest.skip("set TDO_STACK_CALL_PRESERVATION_BUNDLE to the original full Suite09 bundle")
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("TDO_FORWARD_MEMORY_BUNDLE", location)
        result = _actual_fixture.__wrapped__()
    assert len(result["units"]) == 115
    assert sum(len(unit.observation.instructions) for unit in result["units"].values()) == 1833
    assert result["units"][CALLER].scopes.function.observation_digest.hex() == \
        "d75a200af030bc9b047aa651747530736f3adab99b671c37a49bdef473b7f6fe"
    return result


@pytest.fixture(params=("sparse", "dense"))
def engine(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_FORWARD", "0")


def _rbp_runs(summary):
    return [run for exit_ in summary.exits for run in exit_.runs
            if run.span.object_id.kind.value == "register_file"
            and run.span.start == RBP and run.span.size == 8]


def _independent(units):
    return analyze_units(units, assume_globals_disjoint_from_stack=False,
                         assume_entry_values_not_frame=False,
                         assume_opaque_callees_leave_no_stack_addresses=False)


@pytest.mark.parametrize("source,writer,reader,copy", SOURCE_ROWS)
def test_original_source_rbp_identity_uses_all_eight_saved_bytes(suite, engine, source, writer, reader, copy):
    unit = suite["units"][source]
    assert not any(op.opcode in ("CALL", "CALLIND", "CALLOTHER", "BRANCHIND")
                   for row in unit.observation.instructions for op in row.operations)
    # The source really writes RBP, then restores it: this is not a no-output
    # shortcut, an ABI contract, or a globals-ON summary passed to the checker.
    item = _independent([unit])[source]
    independent = _stack_preservation._leaf_summary(unit)
    assert independent is not None
    for summary in (item.summary, independent):
        (run,) = _rbp_runs(summary)
        assert run.kind is SummaryKind.IDENTITY
        assert not run.conditions and not run.debts and not run.crossed
    assert not item.declared and not item.inherited_assumptions and not item.proven
    normalized = item.normalized
    assert not normalized.assumes_globals_disjoint_from_stack
    assert not normalized.assumes_entry_values_not_frame
    ssa, graph = normalized.memory_ssa, normalized.dependencies
    (read,) = [read for read in ssa.reads if ssa.actions[read.action_id].operation_key == reader
               and read.span.object_id.kind.value == "function_relative"]
    assert read.span.size == 8 and len(read.fragments) == 1
    (fragment,) = read.fragments
    assert fragment.span == read.span and len(fragment.definition_ids) == 1
    (identifier,) = fragment.definition_ids
    definition = ssa.definitions[identifier]
    assert definition.kind is MemoryDefinitionKind.DATA_WRITE
    assert definition.operation_key == writer and definition.span == read.span
    definition_node = normalized.memory_graph.definition_nodes[identifier]
    assert any(source_node == graph.node_for_key("op:" + writer) and target == definition_node
               and edge.kind == "memory_defines" and edge.span == read.span
               for source_node, target, edge in graph.out_edges(graph.node_for_key("op:" + writer)))
    assert any(source_node == definition_node and target == graph.node_for_key("op:" + reader)
               and edge.kind == "memory_read" and edge.span == read.span
               for source_node, target, edge in graph.in_edges(graph.node_for_key("op:" + reader)))
    assert graph.node_for_key("op:" + copy) is not None


def test_original_call_certificate_replaces_the_language_register_exception(suite, engine, monkeypatch):
    units = [suite["units"][key] for key in (CALLER, SOURCE_A)]
    monkeypatch.setattr(may_alias, "CALL_PRESERVED", {"x86:LE:64": ()})
    evidence = {}
    assert program_switches_stack(units, call_evidence=evidence) == {}
    assert evidence[CALLER, CALL, suite["register"], RBP, 8] == (SOURCE_A, "identity")


@pytest.mark.parametrize("legacy", (True, False))
def test_denying_independent_evidence_keeps_legacy_explicit_or_flags_the_raw_sp_copy(suite, monkeypatch, legacy):
    units = [suite["units"][key] for key in (CALLER, SOURCE_A)]
    monkeypatch.setattr(_stack_preservation, "_leaf_summary", lambda unit: None)
    if not legacy:
        monkeypatch.setattr(may_alias, "CALL_PRESERVED", {"x86:LE:64": ()})
    evidence = {}
    found = program_switches_stack(units, call_evidence=evidence)
    assert found == ({} if legacy else {CALLER: (RESTORE_SP,)})
    assert evidence[CALLER, CALL, suite["register"], RBP, 8] == (SOURCE_A, "legacy")


@pytest.mark.parametrize("source,writer,reader,copy", SOURCE_ROWS)
def test_original_sources_preserve_raw_rbp_values_and_writer_bytes_for_eight_inputs(suite, source, writer, reader, copy):
    unit = suite["units"][source]
    for number, seed in enumerate(SOURCE_INPUTS):
        stack, initial = 0x70000000 + 0x100 * number, 0xA1B2C3D4E5F60000 + number
        vm = _Recording(unit.observation, subjects={reader: 1}, constant_space=suite["constant"], seed=number,
                        image=suite["image"], address_bits=suite["address_bits"])
        vm.preset(suite["register"], RSP, 8, stack)
        vm.preset(suite["register"], RBP, 8, initial)
        global_ = suite["source_global"]
        vm.preset(global_.space_id, global_.byte_offset, 4, seed)
        run = vm.run()
        assert run.completed and run.executed and not vm.opaque_opcodes
        assert vm.seen[reader] == [stack - 8]
        assert vm._peek(suite["register"], RBP, 8)[0] == initial
        expected = {stack - 8 + byte: writer for byte in range(8)}
        assert {row.offset: row.writer for row in run.dependencies
                if row.reader == reader and row.space_id == 0x1B1} == expected
        assert {stack - 8 + byte: vm._bytes[(0x1B1, stack - 8 + byte)][1] for byte in range(8)} == expected
        assert all(vm._bytes[(suite["register"], RBP + byte)][1] == copy for byte in range(8))


def test_original_source_only_caller_keeps_its_pre_call_rbp_byte_writers(suite, monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "0")
    units = [suite["units"][key] for key in (CALLER, SOURCE_A)]
    item = _independent(units)[CALLER]
    unique = next(space.space_id for space in item.unit.scopes.program.evidence.address_spaces if space.is_unique_space)
    report = check_program(
        item.normalized, item.unit.observation, suite["program"], seeds=range(8),
        register_pools=lambda seed: {RSP: 0x70000000 + 0x100 * seed, RBP: 0xA1B2C3D4E5F60000 + seed,
                                     RDI: seed}, spaces=(suite["constant"], suite["register"], unique),
        image=suite["image"], address_bits=suite["address_bits"])
    assert report.runs == 8 and report.checked
    assert not report.unsupported and not report.silent
    for number, seed in enumerate(SOURCE_INPUTS):
        stack = 0x70000000 + 0x100 * number
        vm = _Recording(item.unit.observation, subjects={RESTORE_SP: 0}, constant_space=suite["constant"],
                        seed=number, program=suite["program"], image=suite["image"],
                        address_bits=suite["address_bits"])
        vm.preset(suite["register"], RSP, 8, stack)
        vm.preset(suite["register"], RBP, 8, 0xA1B2C3D4E5F60000 + number)
        global_ = suite["source_global"]
        vm.preset(global_.space_id, global_.byte_offset, 4, seed)
        run = vm.run()
        assert run.completed and not vm.opaque_opcodes and vm.seen[RESTORE_SP] == [stack - 8]
        assert CALL in run.executed and "1b1:104548:3:COPY" in run.executed
        assert {row.offset: row.writer for row in run.dependencies
                if row.reader == RESTORE_SP and row.space_id == suite["register"]
                and RBP <= row.offset < RBP + 8} == {RBP + byte: FRAME_COPY for byte in range(8)}


def test_a_globals_on_sink_summary_is_not_an_independent_preservation_proof(suite, engine):
    sink = suite["units"][SINK]
    outer = analyze_units([sink], assume_globals_disjoint_from_stack=True,
                          assume_entry_values_not_frame=True)[SINK]
    assert all(run.kind is SummaryKind.IDENTITY for run in _rbp_runs(outer.summary))
    independent = _stack_preservation._leaf_summary(sink)
    assert independent is not None
    (run,) = _rbp_runs(independent)
    assert run.kind is SummaryKind.COMPUTED and len(run.conditions) == 1
    units = [suite["units"][key] for key in (VARIABLE, SOURCE_A, "1b1:104559", SINK)]
    evidence = {}
    assert program_switches_stack(units, call_evidence=evidence) == {}
    assert evidence[VARIABLE, "1b1:104c44:2:CALL", suite["register"], RBP, 8] == (SINK, "legacy")


def test_original_sink_really_can_overwrite_its_saved_rbp_at_a_global_overlap(suite):
    # A valid flat-RAM binary context, with globals-vs-stack deliberately NOT
    # assumed: the saved RBP slot is the sink's own global XOR destination.
    for seed in range(2):
        initial = 0x1234567890ABCD00 + seed
        reader = "1b1:1045ac:1:LOAD"
        vm = _Recording(suite["units"][SINK].observation, subjects={reader: 1},
                        constant_space=suite["constant"], seed=seed, image=suite["image"],
                        address_bits=suite["address_bits"])
        vm.preset(suite["register"], RSP, 8, 0x1090C8)
        vm.preset(suite["register"], RBP, 8, initial)
        vm.preset(suite["register"], RDI, 4, 1)
        run = vm.run()
        assert run.completed and not vm.opaque_opcodes and vm.seen[reader] == [0x1090C0]
        assert vm._peek(suite["register"], RBP, 8)[0] == initial ^ 1
        assert {row.offset: row.writer for row in run.dependencies
                if row.reader == reader and row.space_id == 0x1B1} == {
                    0x1090C0 + byte: "1b1:1045a5:0:COPY" if byte < 4 else "1b1:104595:2:STORE"
                    for byte in range(8)}
