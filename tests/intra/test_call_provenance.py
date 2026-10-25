"""The records-only call provenance side table (docs 25.31 C9-5): where each
call's effect came from and every alias-condition decision -- kept only when
asked for, and never changing a result."""

from test_open_conditions import HELPER, WRAPPER, _program

from synthetic import RBX, program_units
from tdo_v2.call_summary_effects import _anchored_conditions
from tdo_v2.interprocedural import CallProvenance, analyze_units
from tdo_v2.operation_records import _call_provenance


def _analyzed(same):
    table: dict = {}
    results = analyze_units(program_units(*_program(same)), record_provenance=table)
    provenance = {key: table[id(item)][1] for key, item in results.items() if id(item) in table}
    for key, item in results.items():
        assert table[id(item)][0] is item
    return results, provenance


def _call_of(analyzed, callee):
    (call,) = [call for call, target in analyzed.calls.items() if target == callee]
    return call


def test_results_are_the_same_with_and_without_the_table():
    for same in (False, True):
        plain = analyze_units(program_units(*_program(same)))
        recorded, _ = _analyzed(same)
        assert sorted(plain) == sorted(recorded)
        for key in plain:
            assert plain[key].summary == recorded[key].summary
            assert plain[key].proven == recorded[key].proven
            assert plain[key].normalized.proven_call_effects == recorded[key].normalized.proven_call_effects


def test_the_wrapper_keeps_the_pair_open():
    results, provenance = _analyzed(same=False)
    wrapper_key = f"1:{WRAPPER:x}"
    wrapper = results[wrapper_key]
    table = provenance[wrapper_key]
    assert isinstance(table, CallProvenance)
    call = _call_of(wrapper, f"1:{HELPER:x}")
    assert table.sources[call][0] == "summary" and table.sources[call][1] is results[f"1:{HELPER:x}"]
    assert table.opened.get(call)
    rows = [verdict for (row_call, tag), verdicts in table.final.items() if row_call == call
            for verdict in verdicts]
    assert rows and all(verdict not in ("ok", "fail") for verdict in rows)
    effect = dict(wrapper.normalized.proven_call_effects)[call]
    tags = [str(index) for index, run in enumerate((*effect.runs, *effect.memory_runs)) if run.conditions]
    assert tags
    for tag in tags:
        published = _call_provenance(table, call, effect, tag)
        assert published["source"] == "summary" and published["function"] == f"1:{HELPER:x}"
        assert published["conditions"] and {row["verdict"] for row in published["conditions"]} == {"open"}


def test_the_root_decides_it():
    """Disjoint arguments: proven at the root; the same slot: failed (and a
    failed pair is never published as proven)."""
    for same, expected in ((False, "proven"), (True, "failed")):
        results, provenance = _analyzed(same)
        caller = results["1:1000"]
        table = provenance["1:1000"]
        call = _call_of(caller, f"1:{WRAPPER:x}")
        source = caller.activations.get(call, results[f"1:{WRAPPER:x}"])
        assert table.sources[call] == ("summary", source)
        if call in caller.activations:
            assert source.normalized.activation_entry.context == (caller.key, call)
            assert source.activation_witness[1] is results[f"1:{WRAPPER:x}"]
        if same:
            assert table.failed.get(call)
        else:
            assert not table.failed.get(call)
            assert any(verdict == "ok" for (row_call, _), verdicts in table.final.items() if row_call == call
                       for verdict in verdicts)
        effect = dict(caller.normalized.proven_call_effects)[call]
        published = {}
        for index, run in enumerate((*effect.runs, *effect.memory_runs)):
            if run.conditions:
                for pair, row in zip(run.conditions, _call_provenance(table, call, effect, str(index))["conditions"]):
                    published[pair] = row["verdict"]
        if same:
            # the failing pair is never published proven; its runs were derived
            # again without it, the rejection kept (other pairs may stay proven)
            failing = table.failed[call]
            assert all(published.get(pair, "failed") == "failed" for pair in failing)
            assert any(reason == "failed" for _, _, reason in table.rejections.get(call, ()))
        else:
            if published:
                assert set(published.values()) == {expected}
            else:
                # A caller-specific raw SSA can discharge the generic alias
                # pair before lowering; absence of a conditional run is not
                # publication of an unchecked generic condition as proven.
                assert call in caller.activations
                assert not effect.writer_conditions
                assert any(any(span.start <= RBX < span.end for span in run.reads)
                           for run in effect.runs)


def test_no_table_unless_asked():
    results = analyze_units(program_units(*_program(False)))
    assert results   # (``record_provenance`` defaults to None: nothing kept)


class _Run:
    def __init__(self, conditions):
        self.conditions = conditions


def test_derivation_rejections_are_kept_with_their_reason():
    left, right, other = "a", "b", "c"
    located = {left: ("A",), right: ("B",)}
    anchored = located.get
    assert _anchored_conditions(_Run(((left, right),)), anchored, frozenset()) == frozenset({(("A",), ("B",))})
    # a side the caller cannot locate / a pair it found failing: None, with or without the list
    assert _anchored_conditions(_Run(((left, other),)), anchored, frozenset()) is None
    rows: list = []
    failing = frozenset({(("A",), ("B",))})
    assert _anchored_conditions(_Run(((left, other), (left, right))), anchored, failing, rows, "w") is None
    assert rows == [("w", (left, other), "unlocatable"), ("w", (left, right), "failed")]


def test_published_verdicts_never_assume_proven():
    """No decision kept for a pair: "undecided", not proven."""
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class Effect:
        runs: tuple
        memory_runs: tuple = ()
        sink_demands: tuple = ()
        writer_conditions: tuple = ()

    class Place:
        pointer = None
        anchor = None
        index = None
        displacement = 0x10
        size = 8
        space_id = 1

    pair = (Place(), Place())
    table = CallProvenance(sources={}, rejections={}, failed={}, opened={}, final={}, sink={})
    published = _call_provenance(table, "c", Effect(runs=(_Run((pair,)),)), "0")
    assert published["source"] is None
    assert [row["verdict"] for row in published["conditions"]] == ["undecided"]
    failed = CallProvenance(sources={}, rejections={}, failed={"c": frozenset({pair})}, opened={},
                            final={("c", "cr0"): ("ok",)}, sink={})
    assert [row["verdict"] for row in _call_provenance(failed, "c", Effect(runs=(_Run((pair,)),)), "0")[
        "conditions"]] == ["failed"]


def test_recursion_keeps_results_and_names_its_hypotheses():
    """Random (mutually) recursive programs: the same results with the table
    on; intra-SCC calls name the recursion hypothesis, and every pair such a
    hypothesis failed is kept with its reason."""
    import random

    from test_interprocedural import LEAF, MIDDLE, _random_body, _recursive_body
    from synthetic import FunctionBuilder

    hypotheses = 0
    for seed in range(30):
        rng = random.Random(61_000 + seed)
        mutual = rng.random() < 0.4
        functions = [_recursive_body(rng, LEAF, MIDDLE if mutual else LEAF)]
        if mutual:
            functions.append(_recursive_body(rng, MIDDLE, LEAF))
        functions.insert(0, _random_body(rng, FunctionBuilder(), calls=(LEAF,)))
        try:
            units = program_units(*functions)
        except AssertionError:
            continue
        plain = analyze_units(units)
        table: dict = {}
        recorded = analyze_units(program_units(*functions), record_provenance=table)
        for key in plain:
            assert plain[key].summary == recorded[key].summary
            assert plain[key].proven == recorded[key].proven
        for key, item in recorded.items():
            if id(item) not in table:
                continue
            provenance = table[id(item)][1]
            for call, source in provenance.sources.items():
                if source[0] == "recursive hypothesis":
                    hypotheses += 1
                    for where, _, reason in provenance.rejections.get(call, ()):
                        assert reason in ("failed", "unlocatable")
    assert hypotheses
