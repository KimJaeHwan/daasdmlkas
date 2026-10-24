"""Proof-carrying reuse of P0 views, without rewriting their source network.

Authority v1 excludes only expression_views/expression_consumers. Consumers
reference P0 views, never other consumers. Original loop summaries stay intact.
"""

from copy import deepcopy
from dataclasses import dataclass
import time

import z3

from .operation_records import Ineligible
from .resource_limits import step
from ._record_expression_views import (_build, _digest, _fingerprint, _namespace, _metadata,
                                       validate_expression_view)
from ._record_expression_bv import encode, decode, simplify


AUTHORITY = 'original_record_except_expression_views_and_consumers_v1'


@dataclass(frozen=True)
class ConsumerLimits:
    views: int = 8
    queries: int = 128
    solver_ms: int = 2000
    total_ms: int = 20000


class _Budget:
    def __init__(self):
        self.limits, self.started, self.queries = ConsumerLimits(), time.monotonic(), 0

    def check(self, queries=0):
        step()
        self.queries += queries
        remaining = self.limits.total_ms - int((time.monotonic() - self.started) * 1000)
        if remaining <= 0 or self.queries > self.limits.queries:
            raise Ineligible('expression consumer: aggregate proof budget')
        return min(self.limits.solver_ms, remaining)

    def query(self, *formulas):
        solver = z3.Solver()
        solver.set(timeout=self.check(1), rlimit=2000000)
        solver.add(*formulas)
        result = solver.check()
        self.check()
        return result

    def implies(self, domain, assertion, reason):
        if self.query(domain) != z3.sat:
            raise Ineligible('expression consumer: empty or unproven consumer domain')
        if self.query(domain, z3.Not(assertion)) != z3.unsat:
            raise Ineligible('expression consumer: ' + reason)


def _identity(row):
    return 'consumer:' + _digest({key: value for key, value in row.items() if key not in ('id', 'proof')})


def _base(record, kind, namespace, view_ids):
    return dict(version=1, authority=AUTHORITY, kind=kind, source=_fingerprint(record),
                namespace=namespace, views=list(view_ids), original_graph_retained=True,
                conditional_on_original_analysis=True)


def _references(record, namespace, view_ids, budget):
    if (not isinstance(view_ids, (list, tuple)) or not view_ids or len(view_ids) > budget.limits.views
            or any(not isinstance(key, str) for key in view_ids) or len(set(view_ids)) != len(view_ids)):
        raise Ineligible('expression consumer: invalid P0 references')
    found = {}
    for key in view_ids:
        rows = [row for row in record.get('expression_views', ()) if row.get('id') == key]
        if len(rows) != 1 or rows[0]['selection']['namespace'] != namespace:
            raise Ineligible('expression consumer: unknown view or different namespace')
        view, = rows
        budget.check(2)
        adapter, values, domain = validate_expression_view(record, view)
        budget.check()
        found[key] = view, adapter, values, domain
    return found


def _ports(references, selected):
    ports, used, owners = {}, set(), {}
    for key, (view, _, values, _) in references.items():
        for row in view['selection']['outputs']:
            if len(row['parts']) != 1 or row['parts'][0]['at'] != [0, row['width']]:
                raise Ineligible('expression consumer: replacement needs one exact original byte port')
            part, = row['parts']
            if part['node'] not in selected:
                continue
            low, high = part['bytes']
            ports.setdefault(part['node'], []).append((low, high, values[row['name']]))
            owners[part['node'],low,high] = key
            used.add(key)
    if used != set(references):
        raise Ineligible('expression consumer: referenced view has no selected original port')
    for rows in ports.values():
        rows.sort(key=lambda row: row[:2])
        if any(a[1] > b[0] for a, b in zip(rows, rows[1:])):
            raise Ineligible('expression consumer: overlapping replacement ports')
    return ports, owners


def _reuse(record, selection, references, budget, *, restrict=None):
    # G is reconstructed from ORIGINAL outputs/guards, before substitutions.
    original, old, domain, visit, limits = _build(record, selection)
    if restrict is not None:
        domain = z3.And(domain, restrict(original))
    ports, owners = _ports(references, set(selection['nodes']))
    for _, _, _, hypothesis in references.values():
        budget.implies(domain, hypothesis, 'consumer does not imply referenced view domain')
    transformed, new, defined, _, _ = _build(record, selection, substitutions=ports)
    if {owners[key] for key in transformed.used_substitutions} != set(references):
        raise Ineligible('expression consumer: referenced byte port was not used')
    budget.implies(domain, defined, 'substituted expression is not defined')
    budget.implies(domain, z3.And(*(old[key] == new[key] for key in old)), 'substitution changes original outputs')
    graph = encode({key: simplify(value, limits=limits) for key, value in new.items()}, original.symbols, limits)
    final = decode(graph, original.symbols, limits)
    budget.implies(domain, z3.And(*(old[key] == final[key] for key in old)), 'final candidate changes original outputs')
    return original, old, domain, visit, limits, graph


def _concrete(value, symbols, read, *, limit=12000):
    """Lazy evaluation of a decoded PURE typed DAG using Z3's operators."""
    names = {symbol.get_id(): key for key, symbol in symbols.items()}
    memo = {}
    def visit(expr, depth=0):
        step()
        if expr.get_id() in memo:
            return memo[expr.get_id()]
        if depth > 512 or len(memo) >= limit:
            raise Ineligible('expression consumer: concrete DAG limit')
        if expr.get_id() in names:
            number = read(names[expr.get_id()])
            if type(number) is not int or not 0 <= number < 1 << expr.size():
                raise Ineligible('expression consumer: unknown or out-of-width input')
            result = z3.BitVecVal(number, expr.size())
        elif z3.is_bv_value(expr) or z3.is_true(expr) or z3.is_false(expr):
            result = expr
        elif z3.is_app_of(expr, z3.Z3_OP_ITE):
            condition = visit(expr.arg(0), depth+1)
            if not (z3.is_true(condition) or z3.is_false(condition)):
                raise Ineligible('expression consumer: unknown condition')
            result = visit(expr.arg(1 if z3.is_true(condition) else 2), depth+1)
        else:
            result = z3.simplify(expr.decl()(*(visit(child, depth+1) for child in expr.children())))
        memo[expr.get_id()] = result
        return result
    return visit(z3.simplify(value))


def derive_expression_consumer(record, selection, view_ids):
    """Reuse verified P0 byte ports in a same-namespace downstream expression."""
    budget = _Budget()
    refs = _references(record, selection['namespace'], view_ids, budget)
    adapter, old, domain, visit, limits, graph = _reuse(record, selection, refs, budget)
    result = _base(record, 'expression_substitution', selection['namespace'], view_ids)
    result.update(selection=deepcopy(selection), graph=graph, **_metadata(record, selection, adapter, visit))
    result['proof'] = dict(status='equivalent', consumer_domain='original', domain='sat',
                           domain_implication='unsat_counterexample', outputs_mismatch='unsat')
    result['id'] = _identity(result)
    return result


def _canonical(record, row):
    if row.get('source') != _fingerprint(record) or row.get('id') != _identity(row):
        raise Ineligible('expression consumer: source or identity changed')
    if row.get('kind') == 'expression_substitution':
        expected = derive_expression_consumer(record, row['selection'], row['views'])
    elif row.get('kind') == 'invariant_delta_countdown':
        from ._record_expression_loops import derive_loop_consumer
        expected = derive_loop_consumer(record, row['namespace'], row['views'])
    elif row.get('kind') == 'byte_influence':
        from ._record_expression_influence import validate_byte_influence
        return validate_byte_influence(record, row, accept_unattributed_assumptions=True)
    else:
        raise Ineligible('expression consumer: unsupported kind or consumer reference cycle')
    if row != expected:
        raise Ineligible('expression consumer: recipe differs from original derivation')
    return expected


def attach_expression_consumer(record, consumer):
    """Return a copy with an independently checked consumer overlay."""
    if consumer.get('kind') == 'byte_influence':
        raise Ineligible('expression consumer: use attach_byte_influence with explicit assumption policy')
    _canonical(record, consumer)
    result = deepcopy(record)
    rows = result.setdefault('expression_consumers', [])
    if not any(row['id'] == consumer['id'] for row in rows):
        rows.append(deepcopy(consumer))
    return result


def evaluate_expression_consumer(record, identity, inputs, *, accept_unattributed_assumptions=False):
    """Check source, referenced views, domains and recipe BEFORE input access."""
    try:
        rows = [row for row in record.get('expression_consumers', ()) if row['id'] == identity] \
            if isinstance(identity, str) else [identity]
        if len(rows) != 1:
            raise Ineligible('expression consumer: unknown identity')
        row = _canonical(record, rows[0])
        if row['kind'] == 'byte_influence':
            raise Ineligible('expression consumer: byte influence is proof-only, not a numeric expression')
        if not row['assumptions_complete'] and not accept_unattributed_assumptions:
            raise Ineligible('expression consumer: run assumptions unattributed; explicit opt-in required')
        if row['kind'] == 'invariant_delta_countdown':
            from ._record_expression_loops import evaluate_loop_consumer
            return evaluate_loop_consumer(record, row, inputs, accept_unattributed_assumptions)
        adapter, old, domain, visit, limits = _build(record, row['selection'])
        values = decode(row['graph'], adapter.symbols, limits)
        substitutions = []
        for key, symbol in adapter.symbols.items():
            value = inputs.get(key)
            if value is not None:
                if type(value) is not int or not 0 <= value < 1 << symbol.size():
                    raise Ineligible('expression consumer: input width')
                substitutions.append((symbol, z3.BitVecVal(value, symbol.size())))
        if not z3.is_true(z3.simplify(z3.substitute(domain, *substitutions))):
            raise Ineligible('expression consumer: outside original domain or unknown inputs')
        values = {key: z3.simplify(z3.substitute(value, *substitutions)) for key, value in values.items()}
        if any(not z3.is_bv_value(value) for value in values.values()):
            raise Ineligible('expression consumer: unknown output inputs')
        return dict(outputs={key: value.as_long() for key, value in values.items()}, scope=row['scope'],
                    conditional_on_original_analysis=True, assumptions_complete=row['assumptions_complete'])
    except (KeyError, TypeError, ValueError, IndexError, RecursionError, z3.Z3Exception) as error:
        raise Ineligible('expression consumer: malformed or exhausted contract') from error


def render_expression_consumers(record):
    lines = []
    def graph_text(graph, prefix):
        if graph is None:
            return
        for node in graph['nodes']:
            value=node.get('binding') if node['kind']=='input' else (
                str(node['value']) if node['kind']=='literal' else
                node['op']+str(node['parameters'])+'('+', '.join(prefix+'n'+str(ref) for ref in node['args'])+')')
            lines.append(f"  {prefix}n{node['id']}:{node['bits']} = {value}")
        for key,ref in graph['outputs'].items():
            lines.append(f"  {key} = {prefix}n{ref}")
    for index,row in enumerate(record.get('expression_consumers', ())):
        if row['kind'] == 'byte_influence':
            from ._record_expression_influence import render_byte_influence
            lines.extend(render_byte_influence(row))
            continue
        lines.append(f"expression consumer {row['id']} [{row['kind']}; original graph/summaries retained]")
        lines.append('  namespace = '+row['namespace']+'; P0 views = '+', '.join(row['views']))
        if row['kind'] == 'invariant_delta_countdown':
            lines.append(f"  n = unsigned({row['summary']['counter']['input']}_initial); no unrolling")
            for number,case in enumerate(row['summary'].get('cases', [row['summary']])):
                lines.append('  shared choices = ' + str(case.get('choices', [])))
                graph_text(case['invariant_delta']['graph'],f'c{index}.case{number}.')
                for update in case['updates']:
                    if update['input']==row['summary']['counter']['input']:
                        lines.append(f"  {update['input']}_final = 0 [original unit-decrement counter]")
                    else:
                        lines.append(f"  {update['input']}_final = ({update['input']}_initial + n*delta:{update['input']}) mod 2^{8 * update['width']}")
            lines.append('  effects = original schedule: n bodies + n+1 header checks; tracked region state only')
        else:
            lines.append('  verified P0 ports -> original downstream outputs: ' + ', '.join(row['graph']['outputs']))
            graph_text(row['graph'],f'c{index}.')
    return lines
