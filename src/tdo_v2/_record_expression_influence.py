"""Byte noninterference over existing expression boundary bindings.

Only one existing input byte varies. Q/R/A and value observations are separate.
This is not source deletion, memory alias analysis or entry feasibility proof.
Proof-only overlays share the existing derived collection/authority contract.
"""

from copy import deepcopy
from dataclasses import dataclass, asdict
import time
import z3

from .operation_records import Ineligible, _slice_parts, _node_parts
from .resource_limits import step
from ._record_expression_views import (_build, _reselect, _namespace, _width, _conditions, _metadata, _fingerprint)
from ._record_expression_consumers import _base, _identity


@dataclass(frozen=True)
class InfluenceLimits:
    pairs: int = 16
    queries: int = 192
    solver_ms: int = 2000
    total_ms: int = 20000


class _Budget:
    def __init__(self, limits):
        self.limits, self.started, self.count, self.exhausted = limits, time.monotonic(), 0, False

    def check(self):
        step()
        remaining = self.limits.total_ms - int((time.monotonic() - self.started) * 1000)
        if remaining <= 0:
            self.exhausted = True
        return remaining

    def query(self, formula):
        remaining = self.check()
        if self.exhausted or self.count >= self.limits.queries:
            self.exhausted = True
            return 'unknown', None
        self.count += 1
        solver = z3.Solver()
        solver.set(timeout=min(self.limits.solver_ms, remaining), rlimit=2000000)
        solver.add(formula)
        answer = solver.check()
        # Cooperative deadline: do not publish a late answer as proof.
        if self.check() <= 0:
            return 'unknown', None
        return str(answer), solver.model() if answer == z3.sat else None


def _limits(limits):
    limits = limits or InfluenceLimits()
    if type(limits) is not InfluenceLimits or any(type(value) is not int or value <= 0 or value > getattr(InfluenceLimits(), key)
                                                for key, value in asdict(limits).items()):
        raise Ineligible('byte influence: invalid limits')
    return limits


def _pairs(pairs, selection, local, limits):
    if not isinstance(pairs, list) or not pairs or len(pairs) > limits.pairs:
        raise Ineligible('byte influence: pair limit or missing queries')
    outputs = {row['name']: row for row in selection['outputs']}
    nodes = {node['id']: node for node in local['nodes']}
    seen = set()
    for pair in pairs:
        if not isinstance(pair, dict) or set(pair) != {'input', 'output'}:
            raise Ineligible('byte influence: pair schema')
        source, target = pair['input'], pair['output']
        if not isinstance(source, dict) or not isinstance(target, dict) or set(source) != {'node', 'byte'} or set(target) != {'name', 'byte'}:
            raise Ineligible('byte influence: byte schema')
        node, byte, name, out = source['node'], source['byte'], target['name'], target['byte']
        if (type(node) is not int or node not in selection['nodes'] or nodes[node]['kind'] != 'entry'
                or type(byte) is not int or not 0 <= byte < _width(nodes[node])
                or not isinstance(name, str) or name not in outputs
                or type(out) is not int or not 0 <= out < outputs[name]['width']):
            raise Ineligible('byte influence: not an existing boundary/output byte')
        key = node, byte, name, out
        if key in seen:
            raise Ineligible('byte influence: duplicate pair')
        seen.add(key)
    return deepcopy(pairs)


def _address_flags(local, selection, source):
    """Conservative producer closure, NOT a byte-precise alias/effect proof."""
    nodes = {row['id']: row for row in local['nodes']}
    references = []
    for identifier in selection['nodes']:
        node = nodes[identifier]
        if node.get('opcode') not in ('LOAD', 'STORE'):
            continue
        address = next((arg for arg in node['operands'] if arg['index'] == 1), None)
        if address is None:
            references.append(dict(node=identifier, status='unassessed'))
            continue
        pending = [part['node'] for part in address.get('parts', ()) if 'node' in part]
        seen, unsupported = set(), bool(address.get('unresolved'))
        while pending:
            step()
            key = pending.pop()
            if key in seen:
                continue
            if key not in nodes or len(seen) >= 2000:
                unsupported = True
                break
            seen.add(key)
            item = nodes[key]
            unsupported |= item['kind'] in ('call', 'cut', 'debt') or bool(item.get('debts'))
            pending.extend(part['node'] for part in _node_parts(item) if 'node' in part)
        references.append(dict(node=identifier, status='unassessed' if unsupported else (
            'may_depend' if source in seen else 'not_in_syntactic_address_closure')))
    return dict(method='conservative_whole_producer_closure_not_alias_or_byte_independence',
                accesses=references, effects='not_proven', termination='not_proven',
                concrete_memory_correspondence='not_claimed')


def _context(record, selection, pairs, conditions, limits):
    _reselect(record, selection)
    local, visit = _namespace(record, selection['namespace'])
    pairs = _pairs(pairs, selection, local, limits)
    adapter, _, _, visit, _ = _build(record, selection)
    binding = {row['node']: row['id'] for row in adapter.bindings.values()}
    if any(pair['input']['node'] not in binding for pair in pairs):
        raise Ineligible('byte influence: input is not an actual original boundary binding')
    hypothesis = z3.And(*_conditions(adapter, conditions))
    observations = []
    for pair in pairs:
        target = next(row for row in selection['outputs'] if row['name'] == pair['output']['name'])
        byte = pair['output']['byte']
        port = dict(name=target['name'], width=1, guard=target['guard'],
                    parts=_slice_parts(target['parts'], byte, byte + 1))
        observed = adapter.observe(dict(outputs=[port]))[target['name']]
        observations.append(observed)
    return adapter, observations, hypothesis, visit, local, binding


def _second(adapter, pair, observation, hypothesis, binding, index):
    name = binding[pair['input']['node']]
    symbol = adapter.symbols[name]
    byte = pair['input']['byte']
    fresh = z3.BitVec('byte_influence_second_' + str(index), 8)
    pieces = []
    if (byte + 1) * 8 < symbol.size():
        pieces.append(z3.Extract(symbol.size() - 1, (byte + 1) * 8, symbol))
    pieces.append(fresh)
    if byte:
        pieces.append(z3.Extract(byte * 8 - 1, 0, symbol))
    replacement = z3.Concat(*pieces) if len(pieces) > 1 else fresh
    def other(value):
        return z3.substitute(value, (symbol, replacement))
    second = {key: other(value) for key, value in observation.items()}
    changed = z3.Extract(byte * 8 + 7, byte * 8, symbol) != fresh
    joint = z3.And(hypothesis, other(hypothesis), changed)
    domain = lambda row: z3.And(row['Q'], row['R'], row['A'])
    valid = z3.And(joint, domain(observation), domain(second))
    contexts = dict(variability=joint, comparable=valid,
                    value=z3.And(valid, observation['value'] != second['value']),
                    Q=joint, R=z3.And(joint, observation['Q'], second['Q']),
                    A=z3.And(joint, observation['Q'], second['Q'], observation['R'], second['R']))
    for key in ('Q', 'R', 'A'):
        contexts[key + '_change'] = z3.And(contexts[key], z3.Xor(observation[key], second[key]))
    return name, fresh, replacement, second, contexts


def _snapshot_values(adapter, name, replacement, observation, second, evaluate):
    first = {key: evaluate(symbol).as_long() for key, symbol in adapter.symbols.items()}
    other = dict(first)
    other[name] = evaluate(replacement).as_long()
    def observe(row):
        flags = {key: z3.is_true(evaluate(row[key])) for key in ('Q', 'R', 'A')}
        defined = all(flags.values())
        return dict(Q=flags['Q'], R=flags['R'] if flags['Q'] else None,
                    A=flags['A'] if flags['Q'] and flags['R'] else None,
                    byte_value=evaluate(row['value']).as_long() if defined else None,
                    observable=defined)
    return dict(first=first, second=other, first_observation=observe(observation), second_observation=observe(second),
                scope='original_abstract_boundary_model_not_concrete_entry_or_memory_reachability')


def _snapshot(model, adapter, name, replacement, observation, second):
    return _snapshot_values(adapter, name, replacement, observation, second,
                            lambda value: model.eval(value, model_completion=True))


def _analyze_pair(adapter, pair, observation, hypothesis, binding, index, budget):
    name, fresh, replacement, second, contexts = _second(adapter, pair, observation, hypothesis, binding, index)
    witnesses = {}
    def query(key):
        result, model = budget.query(contexts[key])
        if model is not None:
            witnesses[key] = _snapshot(model, adapter, name, replacement, observation, second)
        return result
    variability = query('variability')
    row = dict(pair=deepcopy(pair), variability=variability, comparable='not_checked',
               value='unknown', Q='unknown', R='unknown', A='unknown', witnesses=witnesses)
    if variability == 'unsat':
        row.update(value='fixed_by_hypothesis', Q='fixed_by_hypothesis', R='fixed_by_hypothesis', A='fixed_by_hypothesis')
        return row
    if variability != 'sat':
        return row
    comparable = query('comparable')
    row['comparable'] = comparable
    if comparable == 'sat':
        answer = query('value')
        row['value'] = {'sat': 'may_influence', 'unsat': 'independent_when_both_defined'}.get(answer, 'unknown')
    elif comparable == 'unsat':
        row['value'] = 'no_comparable_defined_pair'
    for key in ('Q', 'R', 'A'):
        baseline = 'sat' if key == 'Q' or comparable == 'sat' else query(key)
        if baseline != 'sat':
            row[key] = 'not_comparable' if baseline == 'unsat' else 'unknown'
            continue
        answer = query(key + '_change')
        row[key] = {'sat': 'may_change', 'unsat': 'stable_in_comparison_context'}.get(answer, 'unknown')
    return row


def prove_byte_influence(record, selection, pairs, *, conditions=(), limits=None, accept_unattributed_assumptions=False):
    """Classify explicit input-byte/output-byte pairs, preserving provenance.

    Pairs: [{input: {node, byte}, output: {name, byte}}]. Input nodes MUST be
    actual entry/one-visit bindings. No arbitrary node becomes a new input.
    """
    limits = _limits(limits)
    row, _ = _prove(record, selection, pairs, conditions, limits, accept_unattributed_assumptions, _Budget(limits))
    return row


def _prove(record, selection, pairs, conditions, limits, accept_unattributed_assumptions, budget):
    conditions = list(conditions)
    context = _context(record, selection, pairs, conditions, limits)
    adapter, observations, hypothesis, visit, local, binding = context
    metadata = _metadata(record, selection, adapter, visit)
    if not metadata['assumptions_complete'] and not accept_unattributed_assumptions:
        raise Ineligible('byte influence: run assumptions unattributed; explicit opt-in required')
    base, _ = budget.query(hypothesis)
    results = []
    for index, (pair, observation) in enumerate(zip(pairs, observations)):
        if base == 'sat':
            row = _analyze_pair(adapter, pair, observation, hypothesis, binding, index, budget)
        else:
            status = 'inconsistent_hypotheses' if base == 'unsat' else 'unknown'
            row = dict(pair=deepcopy(pair), variability='not_checked', comparable='not_checked',
                       value=status, Q=status, R=status, A=status, witnesses={})
        row['address_effects'] = _address_flags(local, selection, pair['input']['node'])
        results.append(row)
    budget.check()
    incomplete = budget.exhausted or base == 'unknown' or any(
        result[key] == 'unknown' for result in results for key in ('variability', 'comparable', 'value', 'Q', 'R', 'A'))
    row = _base(record, 'byte_influence', selection['namespace'], [])
    row.update(metadata, selection=deepcopy(selection), pairs=deepcopy(pairs), conditions=deepcopy(conditions),
               limits=asdict(limits), hypotheses=base, results=results, incomplete=incomplete,
               scope='selected_byte_value_and_QRA_in_original_abstract_boundary_model',
               original_provenance='retained_without_source_or_edge_removal',
               proof=dict(method='two_copy_one_byte_intervention', guard='Q=guard_defined,R=guard_true,A=value_defined'))
    row['id'] = _identity(row)
    return row, context


def _without_witnesses(value):
    result = deepcopy(value)
    result.pop('id', None)
    for row in result['results']:
        row.pop('witnesses', None)
    return result


def _revalidate(record, proof):
    if proof.get('kind') != 'byte_influence' or proof.get('id') != _identity(proof) or proof.get('source') != _fingerprint(record):
        raise Ineligible('byte influence: changed identity or source')
    limits = _limits(InfluenceLimits(**proof['limits']))
    budget = _Budget(limits)
    fresh, context = _prove(record, proof['selection'], proof['pairs'], proof['conditions'], limits, True, budget)
    if _without_witnesses(fresh) != _without_witnesses(proof):
        raise Ineligible('byte influence: classifications differ from original reproof')
    adapter, observations, hypothesis, visit, local, binding = context
    for index, (saved, canonical, pair, observed) in enumerate(zip(proof['results'], fresh['results'], proof['pairs'], observations)):
        name, variable, replacement, second, contexts = _second(adapter, pair, observed, hypothesis, binding, index)
        if set(saved['witnesses']) != set(canonical['witnesses']):
            raise Ineligible('byte influence: missing or unexpected SAT witness')
        for key, witness in saved['witnesses'].items():
            budget.check()
            if budget.exhausted:
                raise Ineligible('byte influence: witness verification budget')
            first, other = witness['first'], witness['second']
            if set(first) != set(adapter.symbols) or set(other) != set(first):
                raise Ineligible('byte influence: incomplete witness inputs')
            for identifier, symbol in adapter.symbols.items():
                if any(type(pool[identifier]) is not int or not 0 <= pool[identifier] < 1 << symbol.size() for pool in (first, other)):
                    raise Ineligible('byte influence: witness width')
                if identifier != name and first[identifier] != other[identifier]:
                    raise Ineligible('byte influence: witness changes other input')
            byte = pair['input']['byte']
            mask = 255 << (8 * byte)
            if first[name] == other[name] or (first[name] ^ other[name]) & ~mask:
                raise Ineligible('byte influence: witness changes wrong bytes')
            substitutions = [(symbol, z3.BitVecVal(first[identifier], symbol.size())) for identifier, symbol in adapter.symbols.items()]
            substitutions.append((variable, z3.BitVecVal((other[name] >> (8 * byte)) & 255, 8)))
            if not z3.is_true(z3.simplify(z3.substitute(contexts[key], *substitutions))):
                raise Ineligible('byte influence: invalid SAT witness')
            # Fully grounded replay, no unbudgeted solver/model choice.
            def evaluate(value):
                budget.check()
                return z3.simplify(z3.substitute(value, *substitutions))
            if _snapshot_values(adapter, name, replacement, observed, second, evaluate) != witness:
                raise Ineligible('byte influence: witness observations changed')
    budget.check()
    if budget.exhausted:
        raise Ineligible('byte influence: witness verification budget')
    return proof


def validate_byte_influence(record, proof, *, accept_unattributed_assumptions=False):
    try:
        result = _revalidate(record, proof)
        if not result['assumptions_complete'] and not accept_unattributed_assumptions:
            raise Ineligible('byte influence: run assumptions unattributed; explicit opt-in required')
        return result
    except (KeyError, TypeError, ValueError, IndexError, RecursionError, z3.Z3Exception) as error:
        raise Ineligible('byte influence: malformed contract') from error


def attach_byte_influence(record, proof, *, accept_unattributed_assumptions=False):
    validate_byte_influence(record, proof, accept_unattributed_assumptions=accept_unattributed_assumptions)
    result = deepcopy(record)
    rows = result.setdefault('expression_consumers', [])
    if not any(row['id'] == proof['id'] for row in rows):
        rows.append(deepcopy(proof))
    return result


def render_byte_influence(proof):
    lines = [f"byte influence {proof['id']} [proof-only; original provenance retained; abstract boundary model]"]
    for row in proof['results']:
        pair = row['pair']
        lines.append(f"  n{pair['input']['node']} byte {pair['input']['byte']} -> {pair['output']['name']} byte {pair['output']['byte']}: "
                     f"value={row['value']}; Q={row['Q']}; R={row['R']}; A={row['A']}; effects=not_proven")
    return lines
