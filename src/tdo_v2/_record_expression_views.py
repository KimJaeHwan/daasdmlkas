"""Non-destructive, byte-addressed views of existing expression networks.

The source network (including cycles/effects/debts) remains the authority.
Selection does not build SSA, prove reachability, or turn an unknown memory
read into an input. Numeric equivalence is a separate, bounded local claim.
"""

from copy import deepcopy
from dataclasses import asdict, dataclass
import hashlib
import json

from .operation_records import Ineligible, _node_parts
from .resource_limits import step


@dataclass(frozen=True)
class ViewLimits:
    nodes: int = 2000
    edges: int = 12000
    depth: int = 120
    width_bytes: int = 256
    solver_ms: int = 2000
    solver_rlimit: int = 2000000
    ast_nodes: int = 12000
    ast_depth: int = 512
    conditions: int = 128


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def _fingerprint(record):
    # Adding another derived view must not invalidate either the authority or
    # existing transition/loop-summary contracts. Nothing else is excluded.
    return _digest({key: value for key, value in record.items() if key != 'expression_views'})


def _namespace(record, namespace):
    if namespace == 'original':
        return record, None
    rows = [*record.get('cycle_graph', {}).get('transitions', ()),
            *record.get('write_effect_transitions', ())]
    found = [row for row in rows if row['id'] == namespace]
    if len(found) != 1 or not found[0]['complete']:
        raise Ineligible('expression view: incomplete or unknown namespace')
    view, = found
    from ._record_transition_contract import validate
    if 'write_projection' in view:
        from ._record_write_effects import validate
    validate(record, view)
    return view['record'], view


def _width(node):
    if node.get('size'):
        return node['size']
    for field in ('output', 'register', 'absolute', 'place'):
        if node.get(field, {}).get('size'):
            return node[field]['size']
    if node.get('opcode') == 'STORE':
        return next(item['width'] for item in node['operands'] if item['index'] == 2)
    return max((part.get('at', [0, 0])[1] for name in ('parts', 'alternatives')
                for part in node.get(name, ())), default=0)


def _parts(parts, width, nodes, limits, *, complete=True):
    if type(width) is not int or not 0 < width <= limits.width_bytes:
        raise Ineligible('expression view: width limit or invalid width')
    covered = set()
    if not isinstance(parts, list) or len(parts) > limits.edges:
        raise Ineligible('expression view: parts limit')
    for part in parts:
        step()
        if not isinstance(part, dict) or type(part.get('node')) is not int or part['node'] not in nodes:
            raise Ineligible('expression view: missing producer')
        ranges = part.get('bytes'), part.get('at')
        if any(not isinstance(pair, list) or len(pair) != 2 or any(type(x) is not int for x in pair)
               for pair in ranges):
            raise Ineligible('expression view: invalid byte reference')
        (a, b), (c, d) = ranges
        if not (0 <= a < b <= _width(nodes[part['node']]) <= limits.width_bytes
                and 0 <= c < d <= width and b - a == d - c):
            raise Ineligible('expression view: invalid byte geometry')
        placed = set(range(c, d))
        if placed & covered:
            raise Ineligible('expression view: overlapping output bytes')
        covered |= placed
    if complete and covered != set(range(width)):
        raise Ineligible('expression view: missing output bytes')


def select_expression(record, outputs=None, *, namespace='original', limits=None):
    """Select existing outputs, preserving their producer/context/byte IDs.

    ``outputs`` is [{name, width (bytes), parts: existing PartRefs, guard?}].
    All output guards must hold together (conjunction, not alternative exits).
    ``None`` selects the original root. A one-visit namespace is its exact
    existing ID, never a new cut or a guessed recursion/iteration bound.
    Structural selection may include debt/cycles: numeric support is separate.
    """
    limits = limits or ViewLimits()
    local, visit = _namespace(record, namespace)
    nodes = {node['id']: node for node in local['nodes']}
    if len(nodes) != len(local['nodes']):
        raise Ineligible('expression view: duplicate producer')
    if outputs is None:
        root = deepcopy(local.get('root', []))
        outputs = [dict(name='root', width=max((part['at'][1] for part in root), default=0), parts=root,
                        guard=local.get('execution_guard', 1))]
    outputs = deepcopy(outputs)
    if not outputs or len(outputs) > limits.nodes or len({row['name'] for row in outputs}) != len(outputs):
        raise Ineligible('expression view: invalid outputs')
    control = local.get('control') or dict(nodes=[False, True], decisions={})
    selected, guards, pending = set(), set(), []
    edge_count = 0

    def guard(reference, depth):
        nonlocal edge_count
        if type(reference) is not int or not 0 <= reference < len(control.get('nodes', ())):
            raise Ineligible('expression view: invalid guard')
        if reference in guards:
            return
        if depth > limits.depth:
            raise Ineligible('expression view: guard depth limit')
        guards.add(reference)
        if len(guards) + len(selected) > limits.nodes:
            raise Ineligible('expression view: control/producer node limit')
        item = control['nodes'][reference]
        if type(item) is bool:
            return
        if not isinstance(item, dict) or any(type(item.get(side)) is not int or not 0 <= item[side] < reference
                                             for side in ('true', 'false')):
            raise Ineligible('expression view: invalid control DAG')
        decision = control.get('decisions', {}).get(item.get('decision'))
        if not decision:
            raise Ineligible('expression view: missing decision')
        for part in decision['operand']['parts']:
            pending.append((part['node'], depth + 1))
            edge_count += 1
        edge_count += 2
        if edge_count > limits.edges:
            raise Ineligible('expression view: control edge limit')
        guard(item['true'], depth + 1)
        guard(item['false'], depth + 1)

    for row in outputs:
        if not isinstance(row['name'], str) or not row['name']:
            raise Ineligible('expression view: invalid output name')
        _parts(row['parts'], row['width'], nodes, limits)
        row.setdefault('guard', 1)
        guard(row['guard'], 0)
        pending.extend((part['node'], 0) for part in row['parts'])
        edge_count += len(row['parts'])
        if edge_count > limits.edges:
            raise Ineligible('expression view: output edge limit')
    while pending:
        identifier, depth = pending.pop()
        step()
        if identifier in selected:
            continue
        if depth > limits.depth or len(selected) + len(guards) >= limits.nodes:
            raise Ineligible('expression view: selection limit')
        if identifier not in nodes:
            raise Ineligible('expression view: dangling producer')
        selected.add(identifier)
        node = nodes[identifier]
        if 'execution_guard' in node:
            guard(node['execution_guard'], depth)
        if 'guarded_sources' in node:
            for ref in (*node['guarded_sources']['guards'], node['guarded_sources']['reach']):
                guard(ref, depth)
        dependencies = [part['node'] for part in _node_parts(node) if 'node' in part]
        dependencies.extend(node.get('debts', ()))
        dependencies.extend(item['node'] for item in node.get('from', ()))
        if type(node.get('override')) is int:
            dependencies.append(node['override'])
        edge_count += len(dependencies)
        if edge_count > limits.edges:
            raise Ineligible('expression view: edge limit')
        pending.extend((ref, depth + 1) for ref in dependencies)
    result = dict(version=1, source=_fingerprint(record), namespace=namespace, outputs=outputs,
                  nodes=sorted(selected), guards=sorted(guards), limits=asdict(limits),
                  scope='local_value_equivalence_not_effects_reachability_or_termination')
    result['id'] = 'selection:' + _digest(result)
    return result


def _reselect(record, selection):
    limits = ViewLimits(**selection['limits'])
    # Serialized limits can lower a budget, never raise the consumer ceiling.
    if any(type(value) is not int or value <= 0 or value > getattr(ViewLimits(), key)
           for key, value in asdict(limits).items()):
        raise Ineligible('expression view: invalid resource limits')
    expected = select_expression(record, selection['outputs'], namespace=selection['namespace'], limits=limits)
    if expected != selection:
        raise Ineligible('expression view: source or selection changed')
    return limits


def _build(record, selection):
    from ._record_expression_bv import Adapter
    limits = _reselect(record, selection)
    local, visit = _namespace(record, selection['namespace'])
    adapter = Adapter(local, selection, limits, memory=visit is not None)
    values, domain = adapter.outputs(selection)
    return adapter, values, domain, visit, limits


def _conditions(adapter, conditions):
    """Optional caller hypotheses, never relabeled as original CFG facts."""
    import z3
    if len(conditions) > adapter.limits.conditions:
        raise Ineligible('expression view: user condition limit')
    result = []
    for row in conditions:
        step()
        if set(row) != {'binding', 'equals'} or row['binding'] not in adapter.symbols:
            raise Ineligible('expression view: invalid user condition')
        symbol, value = adapter.symbols[row['binding']], row['equals']
        if type(value) is not int or not 0 <= value < 1 << symbol.size():
            raise Ineligible('expression view: user condition width')
        result.append(symbol == z3.BitVecVal(value, symbol.size()))
    return result


def _prove(old, new, domain, limits):
    import z3
    if set(old) != set(new) or any(old[name].sort() != new[name].sort() for name in old):
        raise Ineligible('expression view: candidate output mismatch')
    solver = z3.Solver()
    solver.set(timeout=limits.solver_ms, rlimit=limits.solver_rlimit)
    solver.add(domain)
    step()
    feasible = solver.check()
    if feasible != z3.sat:
        return dict(status='inconsistent_domain' if feasible == z3.unsat else 'unproven',
                    domain=str(feasible), mismatch='not_checked',
                    reason='empty domain is not equivalence' if feasible == z3.unsat else solver.reason_unknown())
    solver.add(z3.Or(*(old[name] != new[name] for name in old)))
    step()
    mismatch = solver.check()
    return dict(status='equivalent' if mismatch == z3.unsat else ('refuted' if mismatch == z3.sat else 'unproven'),
                domain='sat', mismatch=str(mismatch),
                reason=None if mismatch == z3.unsat else (
                    'counterexample exists' if mismatch == z3.sat else solver.reason_unknown()))


def _metadata(record, selection, adapter, visit):
    context = (visit or record.get('cycle_graph', {})).get('analysis_context', {})
    return dict(bindings=[adapter.bindings[key] for key in sorted(adapter.bindings)],
                source_links=dict(selection=selection['id'], namespace=selection['namespace'],
                                  nodes=selection['nodes'], outputs=selection['outputs']),
                original_effects='retained in source network; not replaced or proven equivalent by this view',
                analysis_context=deepcopy(context),
                assumptions_complete=context.get('run_assumptions') is not None,
                conditional_on_original_analysis=True,
                scope=selection['scope'])


def _identity(view):
    return 'expression:' + _digest({key: value for key, value in view.items() if key not in ('id', 'proof')})


def simplify_expression(record, selection=None, *, candidate=None, conditions=()):
    """Simplify selected existing expressions and check local BV equivalence.

    Return a separate typed DAG overlay, never a replacement source graph.
    Unknown/cyclic/debt values return ``partial`` without a numeric candidate.
    A supplied candidate uses the same typed DAG format as ``graph``. Cached
    proof status is diagnostic: consumers always reconstruct and re-prove.
    """
    import z3
    from ._record_expression_bv import decode, encode, simplify
    selection = select_expression(record) if selection is None else selection
    conditions = list(conditions)
    # A changed authority/selection is an error, not an unsupported expression.
    limits = _reselect(record, selection)
    base = dict(version=1, selection=deepcopy(selection), user_conditions=deepcopy(list(conditions)),
                original_graph_retained=True, numeric_fallback='not_attempted')
    try:
        adapter, old, domain, visit, limits = _build(record, selection)
        metadata = _metadata(record, selection, adapter, visit)
        domain = z3.And(domain, *_conditions(adapter, conditions))
        memo = {}
        graph = encode({name: simplify(value, limits=limits, memo=memo) for name, value in old.items()}, adapter.symbols, limits) \
            if candidate is None else deepcopy(candidate)
        new = decode(graph, adapter.symbols, limits)
        base.update(metadata, graph=graph, proof=_prove(old, new, domain, limits))
    except (Ineligible, RecursionError, z3.Z3Exception, KeyError, TypeError, ValueError, IndexError) as error:
        base.update(proof=dict(status='partial', reason=str(error)), graph=None)
    base['id'] = _identity(base)
    return base


def validate_expression_view(record, view):
    """Rebuild original bytes and independently recheck before input access."""
    import z3
    from ._record_expression_bv import decode
    try:
        if view.get('id') != _identity(view) or not view.get('original_graph_retained') or view.get('graph') is None:
            raise Ineligible('expression view: changed or incomplete view')
        adapter, old, domain, visit, limits = _build(record, view['selection'])
        metadata = _metadata(record, view['selection'], adapter, visit)
        if any(view.get(key) != value for key, value in metadata.items()):
            raise Ineligible('expression view: source correspondence changed')
        domain = z3.And(domain, *_conditions(adapter, view['user_conditions']))
        new = decode(view['graph'], adapter.symbols, limits)
        proof = _prove(old, new, domain, limits)
        if proof['status'] != 'equivalent':
            raise Ineligible('expression view: candidate not equivalent: ' + proof['status'])
        return adapter, new, domain
    except (RecursionError, z3.Z3Exception, KeyError, TypeError, ValueError, IndexError) as error:
        raise Ineligible('expression view: malformed contract') from error


def attach_expression_view(record, view):
    """Return a copy with a verified overlay; original fields are untouched."""
    validate_expression_view(record, view)
    result = deepcopy(record)
    rows = result.setdefault('expression_views', [])
    if not any(row['id'] == view['id'] for row in rows):
        rows.append(deepcopy(view))
    return result


def evaluate_expression_view(record, view, inputs, *, accept_unattributed_assumptions=False):
    """Local output values under the original guards, not whole execution.

    ``inputs`` maps binding IDs to whole original producer values. Overlapping
    byte references share that single value. One-visit bindings additionally
    expose their existing ``transition_input`` slot IDs to callers.
    """
    import z3
    if isinstance(view, str):
        found = [row for row in record.get('expression_views', ()) if row['id'] == view]
        if len(found) != 1:
            raise Ineligible('expression view: unknown identity')
        view, = found
    adapter, values, domain = validate_expression_view(record, view)
    if not view['assumptions_complete'] and not accept_unattributed_assumptions:
        raise Ineligible('expression view: run assumptions unattributed; explicit opt-in required')
    substitutions = []
    for key, symbol in adapter.symbols.items():
        value = inputs.get(key)
        if value is not None:
            if type(value) is not int or not 0 <= value < 1 << symbol.size():
                raise Ineligible('expression view: input width')
            substitutions.append((symbol, z3.BitVecVal(value, symbol.size())))
    if not z3.is_true(z3.simplify(z3.substitute(domain, *substitutions))):
        raise Ineligible('expression view: unknown inputs or outside selected domain')
    result = {name: z3.simplify(z3.substitute(value, *substitutions)) for name, value in values.items()}
    if any(not z3.is_bv_value(value) for value in result.values()):
        raise Ineligible('expression view: unknown output inputs')
    return dict(outputs={name: value.as_long() for name, value in result.items()},
                scope=view['scope'], conditional_on_original_analysis=True,
                assumptions_complete=view['assumptions_complete'])


def render_expression_views(record):
    lines = []
    for index, view in enumerate(record.get('expression_views', ())):
        prefix = f'e{index}.'
        lines.append(f"expression view {view['id']} [{view['proof']['status']}; original graph retained]")
        lines.append('  ' + view['selection']['namespace'] + ' -> ' + view['selection']['scope'])
        for node in (view.get('graph') or {}).get('nodes', ()):
            value = node.get('binding') if node['kind'] == 'input' else (
                str(node['value']) if node['kind'] == 'literal' else
                node['op'] + str(node['parameters']) + '(' + ', '.join(prefix + 'n' + str(ref) for ref in node['args']) + ')')
            lines.append(f"{prefix}n{node['id']}:{node['bits']} = {value}")
        for name, ref in (view.get('graph') or {}).get('outputs', {}).items():
            lines.append(f"  {name} = {prefix}n{ref}; source parts retained in source_links.outputs")
    return lines
