"""Opt-in x64 suite09 raw-body expression checks; no source-label PASS oracle.

Names/entries come from the historical selection inventory, matched to the
admitted observation digest. Old PASS/FAIL and naming/ABI semantics are NOT
consumed. The engine runs again on sealed raw observations.
"""

from collections import Counter
import json
import os
from pathlib import Path

import pytest

from tdo_v2._configured_bundle_reader import read_configured_bundle
from tdo_v2._scope_contracts import _mint_orchestrator_capability
from tdo_v2.call_expressions import RecordProvider
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import _ObservedScopeProvider
from tdo_v2.interprocedural import _direct_calls, analyze_units, function_key
from tdo_v2.normalize import NormalizedFunction
from tdo_v2.observed_call_state import observed_call_state_projections
from tdo_v2.operation_records import Ineligible, eligibility, evaluate, root_record
from tdo_v2.scope_identity import open_configured_extraction


def closure(roots, calls):
    found, todo = set(), list(roots)
    while todo:
        key = todo.pop()
        if key in found:
            continue
        found.add(key)
        todo.extend(calls.get(key, {}).values())
    return found


def load_suite(root):
    suites = {}
    for folder in sorted((Path(root) / 'binaries').iterdir()):
        generation = next(path for path in (folder / 'bundle').iterdir() if path.is_dir())
        adapter = _ObservedScopeProvider(read_configured_bundle(admit_frozen_bundle(generation)))
        units = {}
        with open_configured_extraction(adapter, _mint_orchestrator_capability()) as session:
            for unit in session.iter_scoped_functions():
                adapter.collect_function_roles()
                if hasattr(unit.scopes.function, 'entry'):
                    units[function_key(unit.scopes.function.entry)] = unit
        cases = {}
        inventory = json.loads((folder / 'report.json').read_text())
        for row in inventory['functions']:
            if not row.get('selection_name', '').startswith('case_'):
                continue
            entry = row['entry']
            key = f"{entry['space_id']:x}:{entry['byte_offset']:x}"
            assert units[key].scopes.function.observation_digest.hex() == row['observation_digest']
            cases[key] = row['selection_name']
        names = dict(cases)
        # Presentation only: never used to resolve calls or apply ABI effects.
        for path in generation.glob('call-names-*.json'):
            for call in json.loads(path.read_text())['calls']:
                for target in call.get('targets', ()):
                    if 'coordinate' in target:
                        c = target['coordinate']
                        key = f"{c['space_id']:x}:{c['byte_offset']:x}"
                        names.setdefault(key, next((a['value'] for a in target.get('aliases', ())
                                                   if a['kind'] == 'SYMBOL'), key))
        excluded = {key: name for key, name in cases.items()
                    if any(f'DFB{i:03d}_' in name for i in range(60, 66))}
        calls = {key: _direct_calls(unit, units) for key, unit in units.items()}
        # Keep indirect-only helpers too. Drop only bodies exclusive to the
        # explicitly excluded recursion cases; shared sources/sinks stay.
        removed = closure(excluded, calls) - closure(set(cases) - set(excluded), calls)
        provider = RecordProvider()
        results = analyze_units([unit for key, unit in units.items() if key not in removed],
                                record_provider=provider, assume_globals_disjoint_from_stack=True)
        suites[folder.name] = dict(generation=generation, units=units, cases=cases, excluded=excluded,
                                   names=names, results=results, provider=provider)
    return suites


def query_records(item, provider):
    """Every normalized raw value/STORE action, plus every call output row.

    Not just source/sink annotations or final outputs: dead intermediate
    computations and address arithmetic are queried as well.
    """
    if not isinstance(item.normalized, NormalizedFunction):
        return
    normalized, unit = item.normalized, item.unit
    raw = {f'{ins.address.space_id:x}:{ins.address.byte_offset:x}:{i}:{op.opcode}'
           for ins in unit.observation.instructions for i, op in enumerate(ins.operations)
           if op.output is not None or op.opcode == 'STORE'}
    for action in normalized.memory_ssa.actions:
        base, separator, tag = action.operation_key.partition('~')
        if action.operation_key not in raw and not (separator and tag.isdigit()):
            continue
        for d in action.write_definition_ids:
            span = normalized.memory_ssa.definitions[d].span
            node = normalized.memory_graph.definition_nodes[d]
            yield action.operation_key, span, root_record(normalized, unit, [(node, (span,))], provider=provider)
        if not action.write_definition_ids and action.operation_key in raw and action.operation_key.endswith(':STORE'):
            node = normalized.dependencies.node_for_key('op:' + action.operation_key)
            record = root_record(normalized, unit, [(node, ())], provider=provider)
            record['unresolved_store_target'] = True
            yield action.operation_key, None, record


def record_issues(record):
    issues = Counter()
    if record.get('unresolved_store_target'):
        issues['unresolved store target'] += 1
    for node in record['nodes']:
        if node['kind'] in ('cut', 'unavailable'):
            issues[node['kind'] + ':' + node['reason']] += 1
        elif node['kind'] == 'debt':
            issues['debt:' + node['debt']] += 1
        elif node['kind'] == 'op':
            for operand in node.get('operands', ()):
                if operand.get('unresolved'):
                    issues['unresolved operand:' + node['opcode']] += 1
    if record['truncated'] and not any(key.startswith('cut:') for key in issues):
        issues['truncated'] += 1
    return issues


def inspect_cases(suites):
    functions = {}
    rows = []
    for binary, suite in suites.items():
        results, provider = suite['results'], suite['provider']
        calls = {key: item.calls for key, item in results.items()}
        needed = closure(set(suite['cases']) - set(suite['excluded']), calls)
        for key in sorted(needed):
            if key not in results:
                continue
            item = results[key]
            reasons, samples, queries, evaluable = Counter(), {}, 0, 0
            for action, span, record in query_records(item, provider):
                queries += 1
                issues = record_issues(record)
                reasons.update(issues)
                evaluable += eligibility(record) is None
                for reason in issues:
                    samples.setdefault(reason, (action, span, record))
            functions[(binary, key)] = dict(queries=queries, reasons=reasons, samples=samples, evaluable=evaluable)
        for key, name in suite['cases'].items():
            if key in suite['excluded']:
                continue
            own = functions[(binary, key)]
            rows.append(dict(binary=binary, key=key, case=name, queries=own['queries'],
                             reasons=dict(own['reasons']), evaluable=own['evaluable']))
    return functions, rows


def _entry_value(vm, space, start, size):
    value = 0
    for offset in range(size):
        key = vm._key(space, start + offset)
        byte = vm.entry_values.get(key)
        if byte is None:
            byte = 0 if key in vm._bytes else vm._byte(*key)[0]
        value |= byte << (8 * offset)
    return value


def _place(span, item, vm, register, unique):
    kind = span.object_id.kind.value
    if kind == 'register_file':
        return register, span.start
    if kind == 'function_unique':
        return unique, span.start
    if kind == 'address_space':
        return span.object_id.space_key, span.start
    row = item.anchors.get(span.object_id)
    if row is None:
        return None
    anchor, space = row
    base = _place(anchor, item, vm, register, unique)
    if base is None:
        return None
    value = _entry_value(vm, *base, anchor.size)
    address = value + span.start - (1 << (8 * anchor.size))
    return space, address % vm._moduli.get(space, 1 << 64)


def execute_queries(suite, key, seeds=range(4)):
    """Use the existing interpreter, recording local writes for comparison.

    Unknown calls STOP the run; no invented call values or ABI effects.
    Every evaluated raw operation is compared, including STORE values and
    call output rows (from actual activation-return byte snapshots).
    """
    from pcode_interpreter import Interpreter, Unsupported

    class Trace(Interpreter):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.outputs = {}

        def _write(self, writer, space, address, size, value):
            if not self._activations:
                self.outputs.setdefault(writer, []).append((space, address, size, value & ((1 << (8 * size)) - 1)))
            super()._write(writer, space, address, size, value)

        def _execute(self, key, operation, run):
            if operation.opcode == 'CALL':
                target = operation.inputs[0].coordinate
                if (target.space_id, target.byte_offset) not in self._program:
                    raise Unsupported('external body absent')
            elif operation.opcode == 'CALLIND':
                if not self._activations or self._activations[-1][1] != key:
                    raise Unsupported('unresolved indirect call')
            return super()._execute(key, operation, run)

    item = suite['results'][key]
    spaces = item.unit.scopes.program.evidence.address_spaces
    register = next(row.space_id for row in spaces if row.is_register_space)
    unique = next(row.space_id for row in spaces if row.is_unique_space)
    constant = next(row.space_id for row in spaces if row.is_constant_space)
    program = {(u.scopes.function.entry.space_id, u.scopes.function.entry.byte_offset): u.observation
               for u in suite['units'].values()}
    manifest = json.loads((suite['generation'] / 'manifest.json').read_text())
    members = {row['id']: row['path'] for row in manifest['members']}
    blocks = [(row['space_id'], row['byte_start'],
               (suite['generation'] / members[row['member_id']]).read_bytes())
              for row in manifest['blocks'] if row['member_id'] and row['is_initialized']]

    def image(space, address):
        for block_space, start, data in blocks:
            if space == block_space and start <= address < start + len(data):
                return data[address - start]
        return None

    source_seeds = {span for function, name in suite['names'].items()
                    if name.startswith('dfb_source_') and function in suite['results']
                    for exit in suite['results'][function].summary.exits for run in exit.runs for span in run.sources
                    if span.object_id.kind.value == 'address_space' and span.size == 4}
    counts, failures, samples, unlocated = Counter(), [], [], Counter()
    records = list(query_records(item, suite['provider']))
    for seed in seeds:
        vm = Trace(item.unit.observation, constant_space=constant, seed=seed, program=program,
                   havoc_calls=(register, 0x20, 8), image=image, max_steps=10000,
                   address_bits={row.space_id: row.address_size_bits for row in spaces if row.is_memory_space})
        vm.preset(register, 0, 0x400, 0)
        vm.preset(register, 0x20, 8, 0x70000000)
        for span in source_seeds:
            vm.preset(span.object_id.space_key, span.start, span.size, seed)
        try:
            run = vm.run()
        except Unsupported as error:
            counts['stopped:' + str(error)] += 1
            continue
        if not run.completed:
            counts['execution limit'] += 1
            continue
        if vm.opaque_opcodes:
            counts['opaque opcode'] += 1
            continue
        counts['completed runs'] += 1

        def entry(node):
            if isinstance(node, tuple):
                return _entry_value(vm, *node[1:])
            if 'register' in node:
                span = node['register']
                return _entry_value(vm, span['space'], span['offset'], span['size'])
            if 'absolute' in node:
                span = node['absolute']
                return _entry_value(vm, span['space'], span['address'], span['size'])
            return None

        for action, span, record in records:
            if span is None:
                continue
            base, separator, tag = action.partition('~')
            produced = vm.outputs.get(action, ())
            if separator:
                place = _place(span, item, vm, register, unique)
                produced = []
                if place is not None:
                    for serial, (call, _) in vm.activation_snapshots.items():
                        state = vm.activation_returns.get(serial)
                        keys = [vm._key(place[0], place[1] + i) for i in range(span.size)]
                        if call == base and state is not None and all(k in state for k in keys):
                            value = sum(state[k] << (8 * i) for i, k in enumerate(keys))
                            produced.append((*place, span.size, value))
            if not produced:
                counts['not executed or unlocated'] += 1
                continue
            try:
                values = evaluate(record, entry)
            except Ineligible as error:
                counts['not evaluable:' + str(error)] += 1
                continue
            place = _place(span, item, vm, register, unique)
            # An indexed object may have no entry-register anchor. Check its
            # real address expression rather than skipping the STORE or
            # guessing the object address from this execution's memory.
            stores = [n for n in record['nodes'] if n['kind'] == 'op' and n.get('key') == action
                      and n.get('function') == key and n.get('opcode') == 'STORE']
            address_values = None
            if len(stores) == 1:
                operand = next(o for o in stores[0]['operands'] if o['index'] == 1)
                address_values = evaluate({**record, 'root': operand['parts']}, entry)
            if place is None:
                if address_values is None or len(record['root']) != 1:
                    counts['unlocated output'] += 1
                    unlocated[action] += 1
                    continue
            for space, address, size, value in produced:
                if address_values is not None:
                    counts['checked memory addresses'] += 1
                    if space != stores[0]['space'] or address not in address_values:
                        failures.append((seed, action, 'address', (space, address), sorted(address_values)[:8]))
                        continue
                delta = record['root'][0]['bytes'][0] if place is None else \
                    (place[1] - address) % vm._moduli.get(space, 1 << 64)
                if (place is not None and space != place[0]) or delta + span.size > size:
                    counts['output place mismatch'] += 1
                    failures.append((seed, action, 'place', place, (space, address, size)))
                    continue
                concrete = (value >> (8 * delta)) & ((1 << (8 * span.size)) - 1)
                counts['checked values'] += 1
                if concrete not in values:
                    failures.append((seed, action, concrete, sorted(values)[:8]))
                    if len(samples) < 3:
                        samples.append(record)
    return dict(counts=counts, failures=failures, samples=samples, unlocated=unlocated)


@pytest.fixture(scope='module')
def actual_suites():
    path = os.environ.get('TDO_SUITE09_X64')
    if not path:
        pytest.skip('set TDO_SUITE09_X64 to the actual x64 suite09 export root')
    return load_suite(path)


def test_real_nonrecursive_suite_inventory_is_explicit(actual_suites):
    suites = actual_suites
    assert sum(len(suite['cases']) for suite in suites.values()) == 80
    assert sum(len(suite['excluded']) for suite in suites.values()) == 6
    assert all(isinstance(item.normalized, NormalizedFunction) for suite in suites.values()
               for key, item in suite['results'].items() if key in suite['cases'])
    for suite in suites.values():
        for key in set(suite['cases']) - set(suite['excluded']):
            item = suite['results'][key]
            raw = {f'{ins.address.space_id:x}:{ins.address.byte_offset:x}:{i}:{op.opcode}'
                   for ins in item.unit.observation.instructions for i, op in enumerate(ins.operations)
                   if op.output is not None or op.opcode == 'STORE'}
            actions = {action.operation_key for action in item.normalized.memory_ssa.actions}
            transient = {key for row in observed_call_state_projections(item.unit.observation)
                         for key in row.transient_operation_keys}
            # CALL's observed SP adjustment / pushed coordinate are deliberately
            # folded out of persistent caller SSA. Account for them explicitly;
            # no other raw value/STORE may silently disappear from the inventory.
            assert raw - actions == transient, (suite['cases'][key], raw - actions - transient)


def test_real_intermediate_and_memory_records_do_not_regress(actual_suites):
    _, rows = inspect_cases(actual_suites)
    assert len(rows) == 74
    assert sum(row['queries'] for row in rows) >= 5384
    # Remaining unknowns are explicit. Resolving any of them is welcome;
    # introducing new unknown cases fails, rather than silently counting PASS.
    pending = {30, 31, 32, 33, 72, 74, 75, 80, 90, 91, 92,
               110, 111, 122, 123, 130, 131, 201}
    for row in rows:
        number = int(row['case'].split('DFB')[1][:3])
        if number not in pending:
            assert not row['reasons'], (row['case'], row['reasons'])
    assert sum(not row['reasons'] for row in rows) >= 56


def test_real_raw_execution_matches_intermediate_and_memory_values(actual_suites):
    counts = Counter()
    completed, stopped = [], []
    for suite in actual_suites.values():
        for key, name in suite['cases'].items():
            if key in suite['excluded']:
                continue
            result = execute_queries(suite, key)
            assert not result['failures'], (name, result['failures'][:10])
            counts.update(result['counts'])
            if result['counts']['completed runs']:
                completed.append(name)
            else:
                stopped.append((name, result['counts']))
    assert len(completed) >= 60, stopped
    assert counts['checked values'] >= 16614
    assert not counts['output place mismatch']
    assert counts['checked memory addresses'] > 0
    assert not counts['unlocated output']
    # This is not an all-cases PASS assertion: stopped calls, loop expressions,
    # debts and unlocated outputs above are unverified, not successful values.


def test_actual_tls_base_can_alias_return_memory_without_platform_evidence(actual_suites):
    """The raw observation alone does not promise that FS_BASE is outside SP."""
    from pcode_interpreter import Interpreter

    suite = actual_suites['dfbench_win_core']
    key = next(key for key, name in suite['cases'].items() if 'DFB091_' in name)
    item = suite['results'][key]
    program = {(u.scopes.function.entry.space_id, u.scopes.function.entry.byte_offset): u.observation
               for u in suite['units'].values()}
    vm = Interpreter(item.unit.observation, constant_space=48, program=program, seed=0, havoc_calls=(548, 0x20, 8))
    vm.preset(548, 0, 0x400, 0)
    vm.preset(548, 0x20, 8, 0x70000000)
    vm.preset(433, 0x70000000, 8, 0xfeedface)
    # Actual extracted instruction: STORE ram[register(0x110) - 4].
    vm.preset(548, 0x110, 8, 0x70000004)
    vm.preset(433, 0x109098, 4, 0)  # pinned binary's source seed -> source_A = 1
    assert vm.run().completed and not vm.opaque_opcodes
    returned = sum(vm._byte(548, 0x288 + i)[0] << (8 * i) for i in range(8))
    assert returned == 1  # not the original 0xfeedface return coordinate
    record = next(record for action, span, record in query_records(item, suite['provider'])
                  if action == '1b1:1057bb:0:LOAD')
    assert record_issues(record)['debt:may_alias_read']
    with pytest.raises(Ineligible):
        evaluate(record, lambda _: 0)
