"""Every callee binding receives the same original address-relation contract."""
from synthetic import RAX
from record_oracle import entry_reader, final_register
from test_physical_call_records import _case, _record, _execute
from test_multi_target_stitching import A, B, caller, entry, record, target
from tdo_v2 import operation_records as records


def _observe(monkeypatch):
    original = records._Binding
    observed = []

    def binding(*args, **kwargs):
        # Callee-entry bindings pass anchors as argument 5. Target-operand
        # reads have no callee address space and are intentionally excluded.
        if len(args) >= 5:
            observed.append(kwargs.get("relations"))
        return original(*args, **kwargs)

    monkeypatch.setattr(records, "_Binding", binding)
    return observed


def test_direct_physical_binding_retains_relation_input_and_original_value(monkeypatch):
    observed = _observe(monkeypatch)
    case = _case()
    found = _record(case)
    vm = _execute(case)
    physical = records.evaluate_physical(found, entry_reader(vm))
    assert physical.value == final_register(vm, RAX, 8)
    assert observed and all(type(relations) is dict for relations in observed)


def test_multitarget_stitch_bindings_receive_each_original_relation_map(monkeypatch):
    observed = _observe(monkeypatch)
    _, found, _, _ = record(monkeypatch, caller(), target(A, 1, 10), target(B, 2, 20))
    assert records.evaluate(found, entry, route="stitched") == {18, 29}
    assert len(observed) >= 2 and all(type(relations) is dict for relations in observed)
