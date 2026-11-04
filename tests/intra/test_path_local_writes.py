"""B' (docs 25.96): unknown-address writes are path-local for data, a site for control.

A RAM unknown-address writer (a STORE to a program memory space whose address
the projection could not place, a call effect's unanchored memory write) no
longer makes every root of its function incomplete: its data effect reaches a
root only through a debt on the slice or a refused binding. The function owns
``control:<f>:memory-writes`` instead -- a site like an unknown transfer (U2a,
U2b): every root of it and of its ancestors lists it. A WILD writer (another
space, a memory output we cannot place) keeps the function-wide blocker. A
noreturn decision declined by a veto leaves a site at the call.
"""

from synthetic import (
    CODE_BASE, DATA_BASE, RAX, RCX, RDX, REG,
    FunctionBuilder, analyze_summaries, boundary, const, copy, load, op, program_units, reg, store, tmp,
)
from tdo_v2.call_summary_effects import summary_noreturn, vetoed_noreturn
from tdo_v2.interprocedural import analyze_units
from tdo_v2.write_classes import RAM as RAM_CLASS, WILD, WriterClasses, wild_write_nodes

MAIN, G, H, SINK = CODE_BASE, CODE_BASE + 0x400, CODE_BASE + 0x800, CODE_BASE + 0xA00
NAMES = {SINK: "sink"}
REGISTER_SINK = boundary({}, {"sink": 8})
SWI = 16


def _key(entry):
    return f"1:{entry:x}"


def _ram_write():
    """``[rdx * rcx] = rax`` -- a STORE to RAM the projection cannot place."""
    return (op("INT_MULT", [reg(RDX), reg(RCX)], tmp(0x180)), store(tmp(0x180), reg(RAX)))


def _wild_write():
    """``STORE(register space, rdx) = rax`` -- a write the may-alias analysis does not track."""
    return (op("STORE", [const(REG), reg(RDX), reg(RAX)]),)


def _rooted(*writes, entry=MAIN):
    """``<writes>; rcx = 7; call sink; ret`` -- the root's slice reads no memory."""
    return FunctionBuilder(entry=entry).sub_rsp(0x28).ins(*writes).ins(copy(reg(RCX), const(7))) \
        .call(SINK).add_rsp(0x28).ret()


def _run(*functions, **options):
    return analyze_summaries([*functions, FunctionBuilder(entry=SINK).ret()], REGISTER_SINK, names=NAMES, **options)


def _root(run, entry=MAIN):
    (root,) = [root for root in run.roots if root.function_byte_offset == entry and root.label == "sink.arg0"]
    return root


def _memory_key(entry):
    return f"control:{_key(entry)}:memory-writes"


# -- classification ------------------------------------------------------------------

def test_writers_are_classified_from_the_raw_operation():
    for writes, expected in ((_ram_write(), RAM_CLASS), (_wild_write(), WILD)):
        (unit,) = program_units(FunctionBuilder(entry=MAIN).ins(*writes).ret())
        (item,) = analyze_units([unit]).values()
        classes = WriterClasses(item.normalized.scopes, unit.observation)
        assert [classes.classify(name) for name in item.summary.unknown_writers] == [expected]
        assert bool(wild_write_nodes(item.normalized, unit.observation)) == (expected == WILD)


# -- data: path-local for RAM, function-wide for WILD -----------------------------------

def test_a_ram_writer_leaves_the_value_bound_and_marks_the_root():
    root = _root(_run(_rooted(*_ram_write())))
    completeness = root.effective_completeness
    assert completeness.function_unresolved_writes == 1   # (still reported)
    assert completeness.reachable_unresolved_reads == 0 and not completeness.unbound_roots
    assert _memory_key(MAIN) in completeness.control_obligations
    assert not root.is_effectively_complete


def test_a_wild_writer_keeps_the_function_wide_blocker():
    root = _root(_run(_rooted(*_wild_write())))
    completeness = root.effective_completeness
    assert not completeness.complete and completeness.reachable_unresolved_reads == 0
    # (data incomplete whatever the control keys say: the local value never was complete)
    assert not root.local_completeness.complete


def test_a_read_after_a_ram_writer_keeps_its_debt():
    """``[rdx*rcx] = rax; rcx = [global]; call sink`` -- the load may read the unknown write."""
    body = FunctionBuilder(entry=MAIN).sub_rsp(0x28).ins(*_ram_write()) \
        .ins(load(reg(RCX), const(DATA_BASE + 0x40))).call(SINK).add_rsp(0x28).ret()
    completeness = _root(_run(body)).effective_completeness
    assert completeness.reachable_unresolved_reads >= 1


# -- control: the key is a site for every ancestor --------------------------------------

def test_a_callers_roots_list_the_callees_memory_writes_site():
    callee = FunctionBuilder(entry=G).ins(*_ram_write()).ret()
    caller = FunctionBuilder(entry=MAIN).sub_rsp(0x28).call(G).ins(copy(reg(RCX), const(7))).call(SINK) \
        .add_rsp(0x28).ret()
    run = _run(caller, callee)
    obligations = _root(run).effective_completeness.control_obligations
    assert _memory_key(G) in obligations and f"continuation:{_key(MAIN)}:*" in obligations
    kinds = {row[0]: row[1] for row in run.control_sites}
    assert kinds[_memory_key(G)] == "memory-writes"


def test_a_vetoed_noreturn_leaves_a_site_at_the_call():
    """F: [rdx*rcx] = rax; int3 -- dead-only, vetoed by its own support; G: call F; rax = 7; ret."""
    from tdo_v2.pcodeop_models import PcodeOpModel

    trap = op("CALLOTHER", [const(SWI, 4), const(3, 4)], None)
    f = FunctionBuilder(entry=G).ins(*_ram_write()).ins(trap).ret()
    g = FunctionBuilder(entry=H).sub_rsp(0x28).call(G).ins(copy(reg(RAX), const(7))).add_rsp(0x28).ret()
    units = program_units(f, g)
    namespace = units[0].scopes.program.evidence.translation_namespace
    model = PcodeOpModel("x86-markers", 1, frozenset({(namespace.language_id, namespace.major_version,
                                                        namespace.minor_version)}), {}, {SWI: frozenset({3})})
    results = analyze_units(units, pcodeop_models=(model,), assume_debug_break_traps_do_not_return=True)
    summary = results[_key(G)].summary
    assert vetoed_noreturn(summary) and not summary_noreturn(summary)
    caller = results[_key(H)]
    vetoed = [site for site in caller.normalized.callee_support if site.endswith(":vetoed-noreturn")]
    assert vetoed and vetoed[0].startswith(f"control:{_key(H)}:")
    assert vetoed[0] in caller.summary.control_support


def test_a_callee_without_a_summary_is_unavailable_to_its_caller():
    """Recursion left opaque has no summary for its caller to read: the dependency is unavailable."""
    a = FunctionBuilder(entry=G).sub_rsp(0x28).call(H).add_rsp(0x28).ret()
    b = FunctionBuilder(entry=H).sub_rsp(0x28).call(G).ins(*_ram_write()).add_rsp(0x28).ret()
    results = analyze_units(program_units(a, b))
    support = set(results[_key(G)].summary.control_support) | set(results[_key(H)].summary.control_support)
    assert any(site.endswith(":memory-writes") for site in support)


def test_no_writer_no_key():
    results = analyze_units(program_units(_rooted(entry=MAIN), FunctionBuilder(entry=SINK).ret()))
    assert results[_key(MAIN)].summary.control_support == ()


def test_every_memory_writing_function_is_a_static_writer():
    """Astra code r1-r3: no syntactic exemption survives (rewritten / partial stack pointer, other
    spaces, overlapping temporaries) -- any STORE makes a static writer; none does not."""
    from synthetic import RSP
    from tdo_v2.control_context import memory_writer

    stack = frozenset({(RSP, 8)})
    for body in (FunctionBuilder(entry=MAIN).ins(op("INT_MULT", [reg(RDX), reg(RCX)], reg(RSP)),
                                                 store(reg(RSP), reg(RAX))).ret(),
                 FunctionBuilder(entry=MAIN).sub_rsp(0x28).ins(store(reg(RSP), reg(RAX))).add_rsp(0x28).ret(),
                 FunctionBuilder(entry=MAIN).ins(op("STORE", [const(REG), reg(RSP), reg(RAX)])).ret()):
        (unit,) = program_units(body)
        assert memory_writer(unit, stack)
    (unit,) = program_units(FunctionBuilder(entry=MAIN).ins(copy(reg(RAX), const(1))).ret())
    assert not memory_writer(unit, stack)


def test_a_template_manifest_becomes_one_model_key_per_row_and_its_scope():
    """The shipped UE template's AppendChar states a memory-writes row: an importer owns its row key
    and, separately, the closure's continuation (settling the writer leaves it)."""
    import json
    from pathlib import Path
    from tdo_v2.interprocedural import _register_file
    from tdo_v2.summary_templates import instantiate

    path = Path(__file__).resolve().parents[2] / "models" / "derived" / "ue_core_win64_fstring.json"
    entries = {entry["name"]: entry for entry in json.loads(path.read_text(encoding="utf-8"))["entries"]}
    template = entries["?AppendChar@FString@@QEAAAEAV1@_W@Z"]["summary"]
    assert template["control"]["rows"][0][0] == "memory-writes" and template["control"]["scope"]
    (unit,) = program_units(FunctionBuilder(entry=MAIN).ret())
    register_object, _ = _register_file(unit.observation, unit.scopes.resolution_context)
    summary, _ = instantiate(template, "ue:AppendChar", register_object, 1)
    assert summary.control_support == ("control:model:ue:AppendChar:0:memory-writes",
                                       "control:model:ue:AppendChar:scope:continuation")



