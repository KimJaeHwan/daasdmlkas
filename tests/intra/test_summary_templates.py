"""Derived models (``summary_templates``): a library function analyzed once,
its summary saved as a template, then loaded by a program that imports it.
The program must get the call effect it would get with the function in its
own Bundle (objects it can locate), or a weaker one (the library's globals,
objects no caller can locate) -- never a stronger one."""

import json
from pathlib import Path

import pytest

from synthetic import (
    NO_CALLBACKS,
    CODE_BASE, CODE_SIZE, DATA_BASE, DATA_SIZE, R8, R9, RAX, RBX, RCX, RDI, RDX, RSI, RSP, FunctionBuilder, add,
    const, copy, load, operation_node_at, program_units, reg, slice_from, store, tmp,
)
from tdo_v2.image_info import ExportedSymbol, ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.relative_memory import ImageBaseTracking
from tdo_v2.summary_store import load_external_models
from tdo_v2.summary_templates import build_file

WIN64 = ("x86:LE:64:default", "win64")
LIBRARY = "SYNTH.DLL"
F = CODE_BASE + 0x800          # the library function (in the library's Bundle, or in the client's)
THUNK = CODE_BASE + 0xF00      # the client's import thunk for it
MANGLED = "?F@@YA_K_K@Z"
IMAGE = (CODE_BASE, DATA_BASE + DATA_SIZE)


def _hand_file(directory):
    """A model file the derivation run loads (its digest is a dependency)."""
    raw = {"format_version": 1, "kind": "declared", "id": "synth-hand", "version": 1,
           "language_id": WIN64[0], "abi_tag": WIN64[1], "libraries": ["OTHER.DLL"],
           "stack_pointer": [32, 8], "stack_delta": 8, "preserved": [[24, 8], [40, 8], [48, 8], [56, 8]],
           "entries": [{"name": "G", "original_names": ["?G@@YAXXZ"], "registers": [], "memory": [],
                        **NO_CALLBACKS, "other_memory": "preserved"}]}
    path = Path(directory) / "hand.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def _every_constant_relocates(address, length, value):
    """Synthetic encodings: a number in the image is a relocating address,
    any other a fixed number."""
    return IMAGE[0] <= value <= IMAGE[1]


def _derive(directory, body, *, private_frame_above=0, relocates=_every_constant_relocates):
    """(template file path, refused) for ``body`` (a FunctionBuilder at F);
    ``relocates``: which image addresses its instructions prove (default all)."""
    hand = _hand_file(directory)
    models = load_external_models([hand], *WIN64)
    info = ImageInfo("synthetic", (), (), (ExportedSymbol(1, F, MANGLED, True),), ())
    with ImageBaseTracking((IMAGE,), relocates) as found:
        results = analyze_units(program_units(body), image_info=info, external_models=models,
                                own_library=LIBRARY, private_frame_above=private_frame_above)
    raw, refused = build_file(results, [(f"1:{F:x}", "F", [MANGLED])], file_id="synth-derived", version=1,
                              library=LIBRARY, external_models=models, pcodeop_models=None,
                              private_frame_above=private_frame_above, base_dependent=found)
    path = Path(directory) / "derived.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path, refused, hand


def _client(directory, caller, body=None, *, template=True, extra=(), private_frame_above=0):
    """The client analyzed with F through the template (``template``) or with
    F's body in its own Bundle."""
    if template:
        path, refused, hand = _derive(directory, body, private_frame_above=private_frame_above)
        assert not refused, refused
        models = load_external_models([hand, path, *extra], *WIN64)
        info = ImageInfo("synthetic", (), (ImportedSymbol(LIBRARY, "F", MANGLED, (), ((1, THUNK),)),), (), ())
        return analyze_units(program_units(caller(THUNK)), image_info=info, external_models=models,
                             private_frame_above=private_frame_above)["1:1000"]
    return analyze_units(program_units(caller(F), body), private_frame_above=private_frame_above)["1:1000"]


def _views(analyzed, points):
    function = analyzed.normalized
    found = []
    for index, ordinal in points:
        view = slice_from(function, operation_node_at(function, index, ordinal))
        found.append((view.is_complete, view.register_bytes))
    return found


def _effect(analyzed):
    (effect,) = [effect for _, effect in analyzed.normalized.proven_call_effects]
    return effect


def _same(tmp_path, caller, body, points):
    """The template gives exactly the in-Bundle effect and slices."""
    inside = _client(tmp_path, caller, body, template=False)
    derived = _client(tmp_path, caller, body)
    a, b = _effect(inside), _effect(derived)
    assert (a.preserves_memory, a.restores_stack, a.preserved, a.observes_registers, a.clobbers_below) == \
        (b.preserves_memory, b.restores_stack, b.preserved, b.observes_registers, b.clobbers_below)
    assert len(a.runs) == len(b.runs) and len(a.memory_runs) == len(b.memory_runs)
    assert _views(inside, points) == _views(derived, points)
    assert any(label.startswith("derived-model:synth-derived/F@v1#") for label in derived.declared.values())
    assert "derived-model-runtime-matches" in derived.inherited_assumptions
    return inside, derived


def _caller_writes(target):
    """[rsp+0x30] = rbx; rcx = rsp+0x10; rdx = rsp+0x20; call; reload both."""
    t = tmp(0x100)
    return (FunctionBuilder().sub_rsp(0x48)
            .ins(add(t, reg(RSP), const(0x30)), store(t, reg(RBX)))
            .ins(add(reg(RCX), reg(RSP), const(0x10)))
            .ins(add(reg(RDX), reg(RSP), const(0x20)))
            .call(target)                                                                   # 4
            .ins(add(t, reg(RSP), const(0x30)), load(reg(R9), t))                           # 5: kept
            .ins(add(t, reg(RSP), const(0x20)), load(reg(R8), t))                           # 6: written
            .ins(copy(reg(RDI), reg(RAX)))                                                  # 7: result
            .add_rsp(0x48).ret())


POINTS = ((5, 1), (6, 1), (7, 0))


def test_register_and_anchored_memory_round_trip(tmp_path):
    """F: rax = rcx; [rdx] = rsi."""
    body = FunctionBuilder(entry=F).ins(copy(reg(RAX), reg(RCX))).ins(store(reg(RDX), reg(RSI))).ret()
    inside, derived = _same(tmp_path, _caller_writes, body, POINTS)
    kept, written, result = _views(derived, POINTS)
    assert kept[0] and set(range(RBX, RBX + 8)) <= kept[1]
    assert written[0] and set(range(RSI, RSI + 8)) <= written[1]


def test_a_frame_with_spills_round_trips(tmp_path):
    """F: its own frame (below its entry stack pointer) and a spill."""
    t = tmp(0x200)
    body = (FunctionBuilder(entry=F).sub_rsp(0x28)
            .ins(add(t, reg(RSP), const(0x8)), store(t, reg(RCX)))
            .ins(add(t, reg(RSP), const(0x8)), load(reg(RAX), t))
            .ins(store(reg(RDX), reg(RAX)))
            .add_rsp(0x28).ret())
    _, derived = _same(tmp_path, _caller_writes, body, POINTS)
    assert _effect(derived).preserves_memory


def test_a_pointer_slot_anchor_round_trips(tmp_path):
    """F: r8 = [rdx]; [r8+4] = rcx -- the write is at the pointer the caller's
    memory held at the call."""
    t = tmp(0x200)
    body = (FunctionBuilder(entry=F).ins(load(reg(R8), reg(RDX)))
            .ins(add(t, reg(R8), const(4)), store(t, reg(RCX))).ret())

    def caller(target):
        u = tmp(0x100)
        return (FunctionBuilder().sub_rsp(0x48)
                .ins(add(reg(RAX), reg(RSP), const(0x30)))
                .ins(add(u, reg(RSP), const(0x20)), store(u, reg(RAX)))                    # [rsp+0x20] = rsp+0x30
                .ins(add(reg(RDX), reg(RSP), const(0x20)))
                .ins(add(u, reg(RSP), const(0x10)), store(u, reg(RBX)))
                .call(target)                                                               # 5
                .ins(add(u, reg(RSP), const(0x34)), load(reg(R9), u))                       # 6: written
                .ins(add(u, reg(RSP), const(0x10)), load(reg(R8), u))                       # 7: kept
                .add_rsp(0x48).ret())
    _same(tmp_path, caller, body, ((6, 1), (7, 1)))


def test_a_library_global_write_keeps_no_memory(tmp_path):
    """F: [G] = rcx (a global of the library): in-Bundle the caller's memory
    is kept; through the template the importer cannot locate G -- weaker."""
    body = FunctionBuilder(entry=F).ins(store(const(DATA_BASE + 0x100), reg(RCX))).ret()
    inside = _client(tmp_path, _caller_writes, body, template=False)
    derived = _client(tmp_path, _caller_writes, body)
    assert _effect(inside).preserves_memory and not _effect(derived).preserves_memory
    assert not _views(derived, ((5, 1),))[0][0]


def test_a_library_global_read_keeps_memory(tmp_path):
    """F: rax = [G] -- an unchanged global (IDENTITY) keeps preservation; the
    value it read is unknown to the importer."""
    body = FunctionBuilder(entry=F).ins(load(reg(RAX), const(DATA_BASE + 0x100))).ret()
    derived = _client(tmp_path, _caller_writes, body)
    assert _effect(derived).preserves_memory
    kept, _, result = _views(derived, POINTS)
    assert kept[0] and not result[0]


@pytest.mark.parametrize("alias", [True, False])
def test_writer_conditions_are_decided_at_the_importer(tmp_path, alias, monkeypatch):
    """F writes through a pointer it loads from [rsi], then through rdi, then
    reloads the pointer and writes again: the summary holds only if [rsi]
    and [rdi] differ. The caller passes rsi == rdi (Astra, design review):
    nothing proven; or distinct objects: whatever the in-Bundle call proves."""
    t = tmp(0x200)
    body = (FunctionBuilder(entry=F)
            .ins(load(reg(R8), reg(RSI))).ins(store(reg(R8), reg(RCX)))
            .ins(store(reg(RDI), reg(RDX)))
            .ins(load(reg(R8), reg(RSI))).ins(add(t, reg(R8), const(8)), store(t, reg(RCX)))
            .ret())

    def caller(target):
        u = tmp(0x100)
        return (FunctionBuilder().sub_rsp(0x48)
                .ins(add(reg(RAX), reg(RSP), const(0x30)))
                .ins(add(u, reg(RSP), const(0x20)), store(u, reg(RAX)))
                .ins(add(reg(RSI), reg(RSP), const(0x20)))
                .ins(copy(reg(RDI), reg(RSI)) if alias else add(reg(RDI), reg(RSP), const(0x08)))
                .call(target)                                                               # 5
                .ins(add(u, reg(RSP), const(0x20)), load(reg(R9), u))                       # 6
                .add_rsp(0x48).ret())
    inside = _client(tmp_path, caller, body, template=False)
    derived = _client(tmp_path, caller, body)
    # A generic portable summary is compared with the generic in-Bundle
    # baseline. Raw caller-specific SSA may legitimately be more precise;
    # the importer must still refuse the template's failing writer guard.
    with monkeypatch.context() as patch:
        patch.setenv("TDO_V2_FORWARD", "0")
        generic = _client(tmp_path, caller, body, template=False)
    a, b = _effect(generic), _effect(derived)
    assert (a.preserves_memory, a.restores_stack, a.preserved) == (b.preserves_memory, b.restores_stack, b.preserved)
    if alias:
        # The writer guard still refuses every memory/register value claim.
        # A separately rechecked raw-CFG proof keeps only RET's stack delta.
        assert not b.preserves_memory and not b.preserved and not b.runs and not b.memory_runs
        assert b.restores_stack and b.register_delta_proofs
    assert _views(generic, ((6, 1),)) == _views(derived, ((6, 1),))
    if inside.activations and alias:
        actual = _effect(inside)
        assert any(run.write.anchor is not None and run.write.anchor.start == RDX
                   and run.write.displacement == 8 for run in actual.memory_runs)
        assert actual.preserves_memory and actual.restores_stack
        assert set(range(RDX, RDX + 8)) <= _views(inside, ((6, 1),))[0][1]
    else:
        assert _views(inside, ((6, 1),)) == _views(derived, ((6, 1),))


def test_a_temporary_source_stays_unknown(tmp_path):
    """F: rax = a temporary read before any write (Astra, design review):
    rax stays unknown through the template, as in-Bundle."""
    body = FunctionBuilder(entry=F).ins(copy(reg(RAX), tmp(0x300))).ret()
    inside, derived = _same(tmp_path, _caller_writes, body, POINTS)
    assert not _views(derived, ((7, 0),))[0][0]


@pytest.mark.parametrize("case", ["offset-from-entry", "masked-image-address"])
def test_a_load_address_dependent_derivation_is_refused(tmp_path, case):
    """Astra (design review, round 2): STORE(rcx + &G) and a byte of &G used
    as an offset are exact here and wrong under another load address."""
    t, u = tmp(0x200), tmp(0x208)
    if case == "offset-from-entry":
        body = FunctionBuilder(entry=F).ins(add(t, reg(RCX), const(DATA_BASE + 0x100)), store(t, reg(RDX))).ret()
    else:
        from synthetic import op

        body = (FunctionBuilder(entry=F)
                .ins(copy(t, const(DATA_BASE + 0x100)))
                .ins(op("SUBPIECE", [t, const(1)], tmp(0x210, 1)))
                .ins(op("INT_ZEXT", [tmp(0x210, 1)], u))
                .ins(add(t, reg(RCX), u), store(t, reg(RDX))).ret())
    _, refused, _ = _derive(tmp_path, body)
    assert "load address" in refused["F"]


def test_a_changed_dependency_refuses_the_template(tmp_path):
    body = FunctionBuilder(entry=F).ins(copy(reg(RAX), reg(RCX))).ret()
    path, refused, hand = _derive(tmp_path, body)
    raw = json.loads(hand.read_text(encoding="utf-8"))
    raw["preserved"] = [[24, 8]]   # a file-level default: the entry digest alone would not see it
    changed = Path(tmp_path) / "changed" / "hand.json"
    changed.parent.mkdir()
    changed.write_text(json.dumps(raw), encoding="utf-8")
    models = load_external_models([changed, path], *WIN64)
    info = ImageInfo("synthetic", (), (ImportedSymbol(LIBRARY, "F", MANGLED, (), ((1, THUNK),)),), (), ())
    analyzed = analyze_units(program_units(_caller_writes(THUNK)), image_info=info, external_models=models)["1:1000"]
    assert not analyzed.proven and "differs" in next(iter(analyzed.refused_models.values()))


def test_another_private_frame_refuses_the_template_resting_on_it(tmp_path):
    """A template whose derivation decided private frame bytes with the home
    space (labels entry-values-do-not-address-the-new-frame and
    win64-home-space-callee-private) needs the same home space; one that
    never did applies with any (docs 25.9)."""
    t = tmp(0x100)
    spilling = (FunctionBuilder(entry=F).sub_rsp(0x18)
                .ins(add(t, reg(RSP), const(8)), store(t, reg(RCX)))
                .ins(add(t, reg(RSP), const(8)), load(reg(RAX), t))
                .add_rsp(0x18).ret())
    plain = FunctionBuilder(entry=F).ins(copy(reg(RAX), reg(RCX))).ret()
    for body, refused in ((spilling, True), (plain, False)):
        directory = tmp_path / str(refused)
        directory.mkdir()
        path, _, hand = _derive(directory, body, private_frame_above=0x28)
        models = load_external_models([hand, path], *WIN64)
        info = ImageInfo("synthetic", (), (ImportedSymbol(LIBRARY, "F", MANGLED, (), ((1, THUNK),)),), (), ())
        analyzed = analyze_units(program_units(_caller_writes(THUNK)), image_info=info, external_models=models,
                                 private_frame_above=8)["1:1000"]
        if refused:
            assert not analyzed.proven and "private_frame_above" in next(iter(analyzed.refused_models.values()))
        else:
            assert analyzed.proven and not analyzed.refused_models


def _image_cases():
    """Derivations that are exact here and wrong under another load address
    (Astra / Fable, step-3 implementation review)."""
    from synthetic import op

    g = DATA_BASE + 0x100
    t, u, v = tmp(0x200), tmp(0x208), tmp(0x210)
    return {
        # a scalar equal to an image address cancels nothing
        "scalar-cancellation": FunctionBuilder(entry=F)
        .ins(copy(t, const(g))).ins(op("INT_SUB", [t, const(g)], u))
        .ins(add(v, reg(RCX), u), store(v, reg(RDX))).ret(),
        # a partial read of a masked image address
        "partial-read": FunctionBuilder(entry=F)
        .ins(op("INT_AND", [const(g), const(0x1000)], t)).ins(copy(reg(RAX), t))
        .ins(op("INT_ZEXT", [reg(RAX, 4)], u))
        .ins(add(v, reg(RCX), u), store(v, reg(RDX))).ret(),
        # restoration through a masked address: one place at this base only
        "masked-restore": FunctionBuilder(entry=F)
        .ins(load(reg(R8), const(g))).ins(store(const(g), reg(RCX)))
        .ins(op("INT_AND", [const(g), const(0xFFFFFFFFFFFEFFFF)], t), store(t, reg(R8))).ret(),
        # a page-masked global against an exact one: disjoint here only
        "page-mask": FunctionBuilder(entry=F)
        .ins(op("INT_AND", [const(g + 4), const(0xFFFFFFFFFFFFF000)], t))
        .ins(add(u, t, const(8)), store(u, reg(RDX)))
        .ins(load(reg(RAX), const(g + 0x8))).ret(),
        # subtracting an address, then adding a number equal to it (Fable / Astra, round 2)
        "neg-then-add": FunctionBuilder(entry=F)
        .ins(op("INT_SUB", [reg(RCX), const(g)], t)).ins(add(u, t, const(g)), store(u, reg(RDX))).ret(),
        # two addresses minus one
        "two-minus-one": FunctionBuilder(entry=F)
        .ins(add(t, const(g), const(g + 8))).ins(op("INT_SUB", [t, const(g + 8)], u))
        .ins(load(reg(R8), const(g))).ins(store(const(g), reg(RCX))).ins(store(u, reg(R8))).ret(),
        # the end of the image (a one-past-end address)
        "image-end": FunctionBuilder(entry=F)
        .ins(add(t, reg(RCX), const(DATA_BASE + DATA_SIZE)), store(t, reg(RDX))).ret(),
    }


@pytest.mark.parametrize("case", ["scalar-cancellation", "partial-read", "masked-restore", "page-mask",
                                  "neg-then-add", "two-minus-one", "image-end"])
def test_more_load_address_dependent_derivations_are_refused(tmp_path, case):
    _, refused, _ = _derive(tmp_path, _image_cases()[case])
    assert "load address" in refused.get("F", ""), refused


def test_a_fixed_literal_equal_to_an_image_address_is_not_one(tmp_path):
    """saved = [&G]; [&G] = rcx; [G'] = saved with G' a fixed literal equal to
    &G (its instruction proves no relocation): after relocation it misses G
    (Astra, round 2). As a constant operand, and as a direct memory operand."""
    from synthetic import ram

    g = DATA_BASE + 0x100
    for operand in (const(g), ram(g)):
        body = (FunctionBuilder(entry=F)
                .ins(load(reg(R8), const(g))).ins(store(const(g), reg(RCX)))
                .ins(store(operand, reg(R8)) if operand["kind_code"] == 1 else copy(operand, reg(R8))).ret())
        fixed = body._address(2)
        _, refused, _ = _derive(tmp_path, body, relocates=lambda address, length, value: address != fixed and _every_constant_relocates(address, length, value))
        assert "load address" in refused.get("F", ""), (operand, refused)


def test_an_unproven_image_number_used_only_as_a_value_is_exported(tmp_path):
    """A number in the image range that is never a fact (copied to rax)."""
    body = FunctionBuilder(entry=F).ins(copy(reg(RAX), const(DATA_BASE + 0x100))).ret()
    _, refused, _ = _derive(tmp_path, body, relocates=lambda address, length, value: False)
    assert not refused


def test_another_language_version_refuses_the_template(tmp_path):
    body = FunctionBuilder(entry=F).ins(copy(reg(RAX), reg(RCX))).ret()
    path, _, hand = _derive(tmp_path, body)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["source"]["language"]["major"] += 1
    path.write_text(json.dumps(raw), encoding="utf-8")
    models = load_external_models([hand, path], *WIN64)
    info = ImageInfo("synthetic", (), (ImportedSymbol(LIBRARY, "F", MANGLED, (), ((1, THUNK),)),), (), ())
    analyzed = analyze_units(program_units(_caller_writes(THUNK)), image_info=info, external_models=models)["1:1000"]
    assert not analyzed.proven and "language" in next(iter(analyzed.refused_models.values()))


def test_a_test_only_derivation_is_refused(tmp_path):
    """Export needs the run's provenance: TEST-ONLY call effects (Astra P2)."""
    from tdo_v2.assumed_call_effects import AssumedCallEffect
    from tdo_v2.summary_templates import TemplateRefused, export_summary

    body = FunctionBuilder(entry=F).call(CODE_BASE + 0xC00).ins(copy(reg(RAX), reg(RCX))).ret()
    (unit,) = program_units(body)
    call = next(f"{i.address.space_id:x}:{i.address.byte_offset:x}:{n}:{o.opcode}"
                for i in unit.observation.instructions for n, o in enumerate(i.operations) if o.opcode == "CALL")
    with ImageBaseTracking((IMAGE,), _every_constant_relocates) as found:
        results = analyze_units([unit], assumed_call_effects={
            f"1:{F:x}": {call: AssumedCallEffect("test", (), ())}})
    with pytest.raises(TemplateRefused, match="TEST-ONLY"):
        export_summary(results[f"1:{F:x}"], results, found)
    plain = analyze_units(program_units(body))
    with pytest.raises(TemplateRefused, match="ImageBaseTracking"):
        export_summary(plain[f"1:{F:x}"], plain, set())


def test_shipped_derived_models_match_this_engine():
    """models/derived: every template loads and none is refused for its engine
    versions (bump ENGINE_SEMANTICS_VERSION -> re-derive them)."""
    from tdo_v2.summary_store import load_model_file

    paths = sorted((Path(__file__).resolve().parents[2] / "models" / "derived").glob("*.json"))
    assert paths
    for path in paths:
        model = load_model_file(path)
        assert model.entries and all(entry.template is not None and entry.refusal is None for entry in model.entries)


def test_image_provenance_reads_the_encoding():
    """lea rax, [rip+0x2000] at 0x180001000 (48 8D 05 00 20 00 00, 7 bytes) ->
    0x180003007 proven; mov rax, imm64 at 0x180001010: proven with a
    relocation entry on its immediate, a fixed number without; Astra's imm64
    whose bytes hold a window equal to value - next_ip (round 3) is decoded as
    an immediate, not RIP-relative: fixed; an encoding not understood: None."""
    from tdo_v2.summary_templates import image_provenance

    memory = {}
    for address, data in ((0x180001000, bytes.fromhex("488d0500200000")),
                          (0x180001010, bytes.fromhex("48b8") + (0x180004000).to_bytes(8, "little")),
                          (0x180027ff2, bytes.fromhex("48b80000048001000000")),
                          (0x180001030, bytes.fromhex("0f0d0d00100000")),     # prefetch [rip+..]: 0F 0D /r
                          (0x180001040, bytes.fromhex("d6")),               # undefined: not understood
                          # Astra round 4: mov qword [rip+0x28ea], 0x4100 -- the immediate equals the target
                          (0x180b, bytes.fromhex("48c705ea28000000410000")),
                          # lea rax, [eip+0]: the address-size override truncates to 32 bits
                          (0x180002000, bytes.fromhex("67488d0500000000")),
                          # XOP vprotb xmm0, [rip+0x2000], xmm0: 8F with a map select, not POP
                          (0x180002010, bytes.fromhex("8fe978900500200000")),
                          # round 5: an ignored REX before 67; an unsigned imm32 equal to the target
                          (0x180002020, bytes.fromhex("4867488d0500000000")),
                          (0x80001000, bytes.fromhex("c705f630000000410080")),
                          # round 6: a 4-byte relocation on disp32 and a fixed imm32 equal to it;
                          # a sign-extended relocated imm32; a 32-bit (truncating) lea
                          (0x180c, bytes.fromhex("48c7042500410000004100" "00")),
                          (0x180003000, bytes.fromhex("48c7c000400080")),
                          (0x180003010, bytes.fromhex("8d0500000000")),
                          (0x180003020, bytes.fromhex("e800100000")),      # call rel32
                          (0x180003030, bytes.fromhex("c3")),               # ret
                          # round 7: lea eax, [rip] (truncated); xbegin rel32
                          (0x401000, bytes.fromhex("8d0500000000")),
                          (0x180003040, bytes.fromhex("c7f800100000"))):
        for index, byte in enumerate(data):
            memory[address + index] = byte

    def read(address, size):
        if any(address + index not in memory for index in range(size)):
            return None
        return int.from_bytes(bytes(memory[address + index] for index in range(size)), "little")

    relocates = image_provenance(read, [(0x180001012, 8), (0x1810, 4), (0x180003003, 4)])
    assert relocates(0x180001000, 7, 0x180003007) is True
    assert relocates(0x180001000, 7, 0x180003008) is None          # another constant of a RIP-relative one
    assert relocates(0x180001010, 10, 0x180004000) is True
    assert image_provenance(read, [])(0x180001010, 10, 0x180004000) is False
    assert relocates(0x180027ff2, 10, 0x180040000) is False
    assert relocates(0x180001030, 7, 0x180002037) is True
    assert relocates(0x180001040, 1, 0x180001041) is None
    assert relocates(0x180003030, None, 8) is False                  # ret's rsp + 8, length unknown
    assert relocates(0x401000, 6, 0x401006) is None
    assert relocates(0x180003040, 6, 0x180004046) is None
    assert relocates(0x180003040, None, 0x180004046) is None
    assert relocates(0x180b, 11, 0x4100) is None
    assert relocates(0x180002000, 8, 0x80002008) is None
    assert relocates(0x180002000, None, 0x80002008) is None
    assert relocates(0x180002010, 9, 0x180004019) is None
    assert relocates(0x180002020, 9, 0x80002029) is None
    assert relocates(0x180002020, None, 0x80002029) is None
    assert relocates(0x80001000, 10, 0x80004100) is None
    assert relocates(0x180c, 12, 0x4100) is None
    assert relocates(0x180003000, 7, 0xFFFFFFFF80004000) is None
    assert relocates(0x180003010, 6, 0x80003016) is None
    assert relocates(0x180003010, None, 0x80003016) is None
    assert relocates(0x180003020, 5, 0x180004025) is None
    assert relocates(0x180001040, None, 0x180001041) is None
