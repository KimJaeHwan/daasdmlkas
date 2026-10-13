"""Round trip of derived models over random programs (Fable, step-3 review):
a random library function analyzed in its own Bundle, exported as a
template, and called by a random client through an import. Compared with
the same client calling the function inside its own Bundle:

* a template with no object the client cannot locate (no library globals,
  no unanchored objects) gives the SAME call effect, field by field;
* otherwise the effect may only be weaker: nothing the template proves is
  more than in-Bundle (preserved registers, kept memory, complete slices).
"""

import json
import random
from dataclasses import replace
from pathlib import Path

import pytest

import test_interprocedural as ipt
from synthetic import FunctionBuilder, operation_node_at, program_units, slice_from
from test_summary_templates import F, LIBRARY, MANGLED, THUNK, WIN64, _derive
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import load_external_models


def _bodies(seed, target):
    leaf = ipt._random_body(random.Random(seed), FunctionBuilder(entry=F), stack_ops=False)
    caller = ipt._random_body(random.Random(seed + 1), FunctionBuilder(), calls=(target,))
    return leaf, caller


def _canonical(effect):
    """The effect without its callee name, its memory runs in a fixed order
    (derive orders them by object ids, which differ; the order carries no
    meaning: overlapping writes of one call stay unresolved)."""
    return replace(effect, callee="", memory_runs=tuple(sorted(effect.memory_runs, key=repr)),
                   unknown_memory=tuple(sorted(effect.unknown_memory, key=repr)))


def _views(analyzed):
    function = analyzed.normalized
    found = {}
    for index, instruction in enumerate(analyzed.unit.observation.instructions):
        for ordinal, _ in enumerate(instruction.operations):
            try:
                node = operation_node_at(function, index, ordinal)
            except (AssertionError, KeyError, LookupError):
                continue
            view = slice_from(function, node)
            found[(index, ordinal)] = (view.is_complete, view.register_bytes)
    return found


@pytest.mark.parametrize("chunk", range(4))
def test_random_templates_match_or_weaken_the_in_bundle_effect(tmp_path, chunk):
    equal = weaker = compared = 0
    for seed in range(chunk * 25, (chunk + 1) * 25):
        base = 70_000 + 7 * seed
        leaf, _ = _bodies(base, F)
        directory = Path(tmp_path) / str(seed)
        directory.mkdir()
        try:
            path, refused, hand = _derive(directory, leaf)
        except AssertionError:
            continue
        if refused:
            continue
        template = json.loads(path.read_text(encoding="utf-8"))["entries"][0]["summary"]
        portable = all("anchor" in row for row in template["objects"])
        models = load_external_models([hand, path], *WIN64)
        info = ImageInfo("synthetic", (), (ImportedSymbol(LIBRARY, "F", MANGLED, (), ((1, THUNK),)),), (), ())
        leaf, inside_caller = _bodies(base, F)
        try:
            inside = analyze_units(program_units(inside_caller, leaf))["1:1000"]
            _, derived_caller = _bodies(base, THUNK)
            derived = analyze_units(program_units(derived_caller), image_info=info, external_models=models)["1:1000"]
        except AssertionError:
            continue
        if type(inside.normalized).__name__ != "NormalizedFunction" or not inside.proven:
            continue
        compared += 1
        # the two callers differ only in the call target: same operation keys
        a, b = inside.proven, derived.proven
        assert set(b) <= set(a), seed
        for site, effect in b.items():
            ours, theirs = _canonical(effect), _canonical(a[site])
            if portable:
                assert ours == theirs, (seed, site)
                equal += 1
                continue
            weaker += 1
            assert set(ours.preserved) <= set(theirs.preserved) or all(
                any(span.start >= other.start and span.end <= other.end for other in theirs.preserved)
                for span in ours.preserved), (seed, site)
            assert not ours.preserves_memory or theirs.preserves_memory, (seed, site)
        if portable:
            assert _views(inside) == _views(derived), seed
        else:
            ours, theirs = _views(derived), _views(inside)
            for point, (complete, registers) in ours.items():
                if complete and point in theirs:
                    assert theirs[point][0], (seed, point)
    assert compared > 10 and equal > 0, (compared, equal, weaker)


def _relocated(builder, delta):
    """The same function with every image address moved by ``delta`` (the
    library loaded elsewhere); other constants unchanged."""
    from synthetic import CODE_BASE, DATA_BASE, DATA_SIZE

    def move(varnode):
        if type(varnode) is dict and varnode.get("kind_code") == 1 \
                and CODE_BASE <= varnode["byte_offset"] < DATA_BASE + DATA_SIZE:
            return {**varnode, "byte_offset": varnode["byte_offset"] + delta}
        return varnode

    for row in builder._rows:
        row.ops = [(opcode, [move(item) for item in inputs], output) for opcode, inputs, output in row.ops]
    return builder


@pytest.mark.parametrize("chunk", range(3))
def test_applied_templates_hold_for_the_library_loaded_elsewhere(tmp_path, chunk):
    """The client analyzed with the template; the interpreter runs the real
    library body at the import -- relocated by 0x10000 -- and the program
    oracle checks the client's graph: no silent miss (Astra, step-3
    implementation review: a dynamic check of applied templates)."""
    import test_graph_fidelity as fidelity
    from program_oracle import check_program
    from synthetic import RSP

    checked = through = 0
    for seed in range(chunk * 30, (chunk + 1) * 30):
        base = 80_000 + 11 * seed
        leaf, _ = _bodies(base, F)
        directory = Path(tmp_path) / str(seed)
        directory.mkdir()
        try:
            path, refused, hand = _derive(directory, leaf)
        except AssertionError:
            continue
        if refused:
            continue
        models = load_external_models([hand, path], *WIN64)
        info = ImageInfo("synthetic", (), (ImportedSymbol(LIBRARY, "F", MANGLED, (), ((1, THUNK),)),), (), ())
        _, caller = _bodies(base, THUNK)
        try:
            derived = analyze_units(program_units(caller), image_info=info, external_models=models)["1:1000"]
        except AssertionError:
            continue
        if type(derived.normalized).__name__ != "NormalizedFunction" or not derived.proven:
            continue
        body = _relocated(ipt._random_body(random.Random(base), FunctionBuilder(entry=THUNK), stack_ops=False),
                          0x10000)
        (unit,) = program_units(body)
        report = check_program(derived.normalized, derived.unit.observation, {(1, THUNK): unit.observation},
                               seeds=range(4), havoc_calls=ipt.HAVOC,
                               register_pools=lambda s: {**fidelity._register_inputs(s), RSP: 0x7000_0000})
        checked += report.runs
        through += report.through_calls
        assert report.silent == [], (seed, report.silent[:3])
    assert checked and through


def test_the_oracle_catches_a_base_dependent_template(tmp_path, monkeypatch):
    """Exported with the load-address check switched off, the masked-restore
    case claims the client's memory kept; the library run 0x10000 higher
    restores into the client's global instead -- a silent miss the oracle
    reports (the check is what keeps such templates out)."""
    import test_graph_fidelity as fidelity
    import tdo_v2.relative_memory as relative_memory
    from program_oracle import check_program
    from synthetic import DATA_BASE, R8, R9, RBX, RCX, RSP, const, load, op, reg, store, tmp
    from test_summary_templates import _image_cases

    monkeypatch.setattr(relative_memory, "_note_base_dependent", lambda scope: None)
    path, refused, hand = _derive(tmp_path, _image_cases()["masked-restore"])
    assert not refused
    g = DATA_BASE + 0x100

    def caller(target):
        return (FunctionBuilder().sub_rsp(0x28)
                .ins(store(const(g), reg(RBX)))
                .call(target)
                .ins(load(reg(R9), const(g)))
                .add_rsp(0x28).ret())
    models = load_external_models([hand, path], *WIN64)
    info = ImageInfo("synthetic", (), (ImportedSymbol(LIBRARY, "F", MANGLED, (), ((1, THUNK),)),), (), ())
    derived = analyze_units(program_units(caller(THUNK)), image_info=info, external_models=models,
                            assume_globals_disjoint_from_stack=True)["1:1000"]
    t = tmp(0x200)
    moved = (FunctionBuilder(entry=THUNK)
             .ins(load(reg(R8), const(g + 0x10000))).ins(store(const(g + 0x10000), reg(RCX)))
             .ins(op("INT_AND", [const(g + 0x10000), const(0xFFFFFFFFFFFEFFFF)], t), store(t, reg(R8))).ret())
    (unit,) = program_units(moved)
    report = check_program(derived.normalized, derived.unit.observation, {(1, THUNK): unit.observation},
                           seeds=range(4), havoc_calls=ipt.HAVOC,
                           register_pools=lambda s: {**fidelity._register_inputs(s), RSP: 0x7000_0000})
    assert report.silent
