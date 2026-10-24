"""Conditional pure regions over ORIGINAL SSA producers, not new entry SSA.

Ports are explicitly supplied, available whole producer outputs. Their source
and debt remain external obligations. Local BV equivalence and re-connection
under an original expression domain are independent claims.
"""

from copy import deepcopy
from dataclasses import asdict
import z3

from .operation_records import Ineligible, _node_parts
from .resource_limits import step
from ._record_expression_views import (_select, select_expression, _namespace, _width, ViewLimits,
    _metadata, _conditions, _build, _fingerprint, _digest)
from ._record_expression_bv import Adapter, encode, decode, simplify
from ._record_expression_consumers import _base, _identity, _Budget
from ._record_loop_summaries import _TOTAL_OPS


_PURE = _TOTAL_OPS - {'LOAD', 'STORE', 'BRANCH', 'CBRANCH'}
_SCOPE = 'conditional_pure_region_given_available_outputs_not_entry_reachability_or_effects'


def _operand_storage(operand):
    if ('physical_read' in operand or 'physical_read_source' in operand or operand.get('unresolved') or operand.get('pruned')):
        raise Ineligible('expression island: memory or incomplete operand provenance')


def _storage(node):
    # Raw p-code COPY can read/write ADDRESS storage without LOAD/STORE.
    if (node.get('absolute') or node.get('execution_fallback') or 'physical_write' in node or 'physical_memory' in node or
            any('physical_read' in operand or 'physical_read_source' in operand for operand in node.get('operands',())) or
            node.get('kind')=='entry' and 'register' not in node or
            node.get('kind')=='op' and (node.get('opcode') not in _PURE or
                node.get('output',{}).get('kind') not in ('register_file','function_unique'))):
        raise Ineligible('expression island: memory, effect or unsupported control in value provenance')
    for operand in (*node.get('operands',()),node.get('condition',{}).get('operand',{})):
        _operand_storage(operand)


def _provenance(record, roots, limits):
    """Bounded structural fence, not upstream expression/alias interpretation.

    Opaque call value origins stop at the call and remain obligations. Memory
    origins and recurrence cannot be laundered through one or more COPYs.
    """
    nodes = {node['id']:node for node in record['nodes']}
    seen,active,calls,debts,guards = set(),set(),set(),set(),set()
    control = record.get('control') or dict(nodes=[False,True],decisions={})
    edges = 0
    def guard(reference,depth):
        nonlocal edges
        step()
        if type(reference) is not int or not 0<=reference<len(control['nodes']):
            raise Ineligible('expression island: invalid upstream guard')
        if reference in guards:
            return
        if len(seen)+len(active)+len(guards)>=limits.nodes or depth>limits.depth:
            raise Ineligible('expression island: upstream control provenance limit')
        guards.add(reference)
        item = control['nodes'][reference]
        if type(item) is bool:
            return
        if (not isinstance(item,dict) or item.get('decision') not in control['decisions'] or
                any(type(item.get(side)) is not int or not 0<=item[side]<reference for side in ('true','false'))):
            raise Ineligible('expression island: invalid upstream control DAG')
        operand = control['decisions'][item['decision']]['operand']
        _operand_storage(operand)
        parts = operand.get('parts',())
        if not parts:
            raise Ineligible('expression island: incomplete upstream guard operand')
        edges += len(parts)+2
        if edges>limits.edges:
            raise Ineligible('expression island: upstream control edge limit')
        for part in parts:
            if part.get('loop') or part.get('pruned') or part.get('whole') or 'node' not in part:
                raise Ineligible('expression island: incomplete upstream guard PartRef')
            visit(part['node'],depth+1)
        guard(item['true'],depth+1)
        guard(item['false'],depth+1)

    def visit(key,depth):
        nonlocal edges
        step()
        if key in active:
            raise Ineligible('expression island: recurrent upstream producer')
        if key in seen:
            return
        if key not in nodes or len(seen)+len(active)+len(guards)>=limits.nodes or depth>limits.depth:
            raise Ineligible('expression island: boundary provenance unverified within limit')
        node = nodes[key]
        active.add(key)
        if 'execution_guard' in node:
            guard(node['execution_guard'],depth+1)
        if 'guarded_sources' in node:
            for reference in (*node['guarded_sources']['guards'],node['guarded_sources']['reach']):
                guard(reference,depth+1)
        if node['kind']=='call':
            if node.get('output',{}).get('kind')!='register':
                raise Ineligible('expression island: memory or unclassified call output in boundary provenance')
            seen.add(key)
            calls.add(node.get('key',str(key)))
            active.remove(key)
            return
        _storage(node)
        if node.get('interrupted') or node.get('override') is not None or node['kind']=='cut':
            raise Ineligible('expression island: incomplete boundary provenance')
        if node['kind']=='debt':
            if node.get('debt')!='call_clobber_read' or not node.get('spans') or any(
                    not span.startswith('register:') for span in node['spans']):
                raise Ineligible('expression island: non-register-call debt in boundary provenance')
            debts.add(key)
            calls.update(node.get('calls',()))
        refs = list(_node_parts(node))
        if any(part.get('loop') or part.get('pruned') or part.get('whole') or 'node' not in part or
               part.get('output',{}).get('kind','register_file') not in ('register_file','function_unique') for part in refs):
            raise Ineligible('expression island: loop or incomplete boundary PartRef')
        pending = [part['node'] for part in refs]+list(node.get('debts',()))
        pending.extend(row['node'] for row in node.get('from',()))
        edges += len(pending)
        if edges>limits.edges:
            raise Ineligible('expression island: boundary provenance edge limit')
        for ref in pending:
            visit(ref,depth+1)
        active.remove(key)
        seen.add(key)
    for key in roots:
        visit(key,0)
    return dict(nodes=sorted(seen),guards=sorted(guards),debt_nodes=sorted(debts),opaque_calls=sorted(calls),
                scope='bounded_nonmemory_nonrecurrence_fence_not_source_value_or_reachability_proof')


def _limits(limits):
    limits = limits or ViewLimits()
    if type(limits) is not ViewLimits or any(type(value) is not int or not 0 < value <= getattr(ViewLimits(), key)
                                            for key,value in asdict(limits).items()):
        raise Ineligible('expression island: invalid resource limits')
    return limits


def _selection(record, outputs, boundaries, namespace, limits):
    # Initial release: a single occurrence in an acyclic original function.
    # Do not cut a recurrent static producer into one supposedly stable value.
    if namespace != 'original' or any(row['cyclic'] for row in record.get('cycle_graph', {}).get('components', ())):
        raise Ineligible('expression island: loop/one-visit boundary outside initial scope')
    if record.get('execution_fallback') or record.get('truncated') or record.get('demand_complete') is False:
        raise Ineligible('expression island: cyclic/unsupported control or incomplete original record')
    if (not isinstance(boundaries,list) or not 0 < len(boundaries) <= 16
            or any(type(key) is not int for key in boundaries) or len(set(boundaries)) != len(boundaries)):
        raise Ineligible('expression island: invalid or excessive boundaries')
    nodes = {node['id']:node for node in record['nodes']}
    for key in boundaries:
        node = nodes.get(key,{})
        if (node.get('kind') != 'op' or node.get('opcode') not in _PURE or node.get('interrupted')
                or node.get('override') is not None or not 0 < _width(node) <= limits.width_bytes):
            raise Ineligible('expression island: boundary must be an existing total integer producer output')
    selection = _select(record, outputs, namespace=namespace, limits=limits, boundaries=boundaries)
    for key in selection['nodes']:
        _storage(nodes[key])
    selection['boundary_provenance'] = _provenance(record,boundaries,limits)
    selection['id'] = 'selection:'+_digest({key:value for key,value in selection.items() if key!='id'})
    return selection


def _reselect(record, selection):
    limits = _limits(ViewLimits(**selection['limits']))
    expected = _selection(record, selection['outputs'], selection['boundaries'], selection['namespace'], limits)
    if expected != selection:
        raise Ineligible('expression island: source or boundary selection changed')
    return limits


class _IslandAdapter(Adapter):
    """Reuse all ordinary operations/choices, intercept only declared ports."""
    def __init__(self, local, selection, limits):
        self.boundaries = set(selection['boundaries'])
        self.availability = {}
        super().__init__(local,selection,limits)

    def node(self, identifier):
        if identifier not in self.boundaries:
            return super().node(identifier)
        step()
        if identifier in self.cache:
            return self.cache[identifier]
        if identifier in self.active or identifier not in self.selected:
            raise Ineligible('expression island: cyclic or absent boundary guard')
        node = self.nodes[identifier]
        key, width = 'p'+str(identifier), _width(node)
        self.active.add(identifier)
        try:
            symbol = z3.BitVec(key,width*8)
            available = z3.Bool('island_available_'+key)
            self.symbols[key] = symbol
            self.availability[key] = available
            self.bindings[key] = dict(id=key,node=identifier,width=width,transition_input=None,
                                     role='supplied_original_producer_output',validity='available:'+key)
            defined = available  # Assumption, NEVER a discharged source debt.
            if 'execution_guard' in node:
                guard,gd = self.guard(node['execution_guard'])
                defined = z3.And(defined,gd,guard)
            self.cache[identifier] = symbol,defined
            return self.cache[identifier]
        finally:
            self.active.remove(identifier)


def _build_region(record, selection):
    limits = _reselect(record,selection)
    local,visit = _namespace(record,selection['namespace'])
    adapter = _IslandAdapter(local,selection,limits)
    values,domain = adapter.outputs(selection)
    if {row['node'] for row in adapter.bindings.values() if row.get('role')} != set(selection['boundaries']):
        raise Ineligible('expression island: unused boundary')
    # Even a cancelled/guard-inactive port is an explicit availability premise.
    return adapter,values,z3.And(domain,*adapter.availability.values()),visit,limits


def _obligations(record, selection):
    nodes = {node['id']:node for node in record['nodes']}
    result = []
    for key in selection['boundaries']:
        node = nodes[key]
        result.append(dict(port='p'+str(key),node=key,width=_width(node),key=node['key'],
            address=node.get('address'),ordinal=node.get('ordinal'),output=deepcopy(node.get('output')),
            source_parts=deepcopy(list(_node_parts(node))),
            debt_nodes=deepcopy([nodes[ref] for ref in node.get('debts',())]),
            source_proof='not_implied_by_supplied_availability',upstream='retained_in_original_network'))
    return result


def _connection(record, selection, adapter, domain, values, budget):
    """Put the ORIGINAL producer/definedness back, then prove the final view."""
    try:
        original_selection = select_expression(record,selection['outputs'],namespace=selection['namespace'],
                                                limits=ViewLimits(**selection['limits']))
        original,old,original_domain,_,_ = _build(record,original_selection)
    except Ineligible as error:
        return dict(status='unresolved',reason=str(error),entry_reachability='not_proven',effects='not_proven')
    substitutions = []
    for key,available in adapter.availability.items():
        value,defined = original.node(adapter.bindings[key]['node'])
        substitutions.extend(((adapter.symbols[key],value),(available,defined)))
    linked_domain = z3.substitute(domain,*substitutions)
    linked = {key:z3.substitute(value,*substitutions) for key,value in values.items()}
    if budget.query(original_domain) != z3.sat:
        return dict(status='unresolved',reason='original_domain_empty_or_unproven',entry_reachability='not_proven',effects='not_proven')
    if budget.query(original_domain,z3.Not(linked_domain)) != z3.unsat:
        return dict(status='unresolved',reason='original_domain_does_not_prove_region_premises',entry_reachability='not_proven',effects='not_proven')
    if budget.query(original_domain,z3.Or(*(old[key]!=linked[key] for key in old))) != z3.unsat:
        return dict(status='unresolved',reason='original_reconnection_equivalence_unproven',entry_reachability='not_proven',effects='not_proven')
    return dict(status='linked_under_original_domain',reason=None,entry_reachability='not_proven',effects='not_proven')


def _derive(record, selection, candidate, conditions, budget):
    adapter,old,domain,visit,limits = _build_region(record,selection)
    domain = z3.And(domain,*_conditions(adapter,conditions))
    graph = encode({key:simplify(value,limits=limits) for key,value in old.items()},adapter.symbols,limits) \
        if candidate is None else deepcopy(candidate)
    new = decode(graph,adapter.symbols,limits)
    if set(new)!=set(old) or any(new[key].sort()!=old[key].sort() for key in old):
        raise Ineligible('expression island: candidate output mismatch')
    budget.implies(domain,z3.And(*(old[key]==new[key] for key in old)),'region candidate not equivalent')
    metadata = _metadata(record,selection,adapter,visit)
    row = _base(record,'conditional_expression_island',selection['namespace'],[])
    row.update(metadata,selection=deepcopy(selection),graph=graph,conditions=deepcopy(conditions),
        island_namespace='island:'+selection['id'].split(':',1)[1],scope=_SCOPE,
        external_obligations=_obligations(record,selection),
        boundary_validity='explicit_user_availability_premise_not_source_proof',
        connection=_connection(record,selection,adapter,domain,new,budget),
        proof=dict(status='equivalent_given_available_boundaries',domain='sat',outputs_mismatch='unsat',
                   original_debt='retained',effects='not_proven',termination='not_proven'))
    budget.check()
    row['id'] = _identity(row)
    return row,adapter,new,domain


def derive_expression_island(record, outputs=None, *, boundaries, namespace='original', conditions=(), candidate=None, limits=None):
    """Derive a conditional pure region; unavailable source inputs stay unresolved.

    boundaries is a list of ORIGINAL total integer producer node IDs. Ports
    retain their full original width; callers do not invent byte/Boolean cuts.
    """
    limits = _limits(limits)
    budget = _Budget(solver_ms=limits.solver_ms,solver_rlimit=limits.solver_rlimit)
    selection = _selection(record,outputs,boundaries,namespace,limits)
    row,_,_,_ = _derive(record,selection,candidate,list(conditions),budget)
    return row


def _validate(record,row):
    if row.get('kind')!='conditional_expression_island' or row.get('id')!=_identity(row) or row.get('source')!=_fingerprint(record):
        raise Ineligible('expression island: changed identity or source')
    limits = _limits(ViewLimits(**row['selection']['limits']))
    expected,adapter,new,domain = _derive(record,row['selection'],row['graph'],row['conditions'],
        _Budget(solver_ms=limits.solver_ms,solver_rlimit=limits.solver_rlimit))
    if row!=expected:
        raise Ineligible('expression island: changed contract, premises or connection claim')
    return adapter,new,domain


def validate_expression_island(record, island, *, accept_unattributed_assumptions=False):
    try:
        _validate(record,island)
        if not island['assumptions_complete'] and not accept_unattributed_assumptions:
            raise Ineligible('expression island: run assumptions unattributed; explicit opt-in required')
        return island
    except (KeyError,TypeError,ValueError,IndexError,RecursionError,z3.Z3Exception) as error:
        raise Ineligible('expression island: malformed contract') from error


def attach_expression_island(record, island, *, accept_unattributed_assumptions=False):
    validate_expression_island(record,island,accept_unattributed_assumptions=accept_unattributed_assumptions)
    result = deepcopy(record)
    rows = result.setdefault('expression_consumers',[])
    if not any(row['id']==island['id'] for row in rows):
        rows.append(deepcopy(island))
    return result


def evaluate_expression_island(record, identity, inputs, validity, *, accept_conditional_boundaries=False,
                               accept_unattributed_assumptions=False):
    """Numeric region ONLY, given explicitly available original producer values.

    validity maps p# to True. It is caller acknowledgement, not a receipt or
    proof that the original CALL/LOAD/debt was resolved or reachable.
    """
    try:
        rows = [row for row in record.get('expression_consumers',()) if row['id']==identity] \
            if isinstance(identity,str) else [identity]
        if len(rows)!=1:
            raise Ineligible('expression island: unknown identity')
        row, = rows
        adapter,new,domain = _validate(record,row)  # Before either input map.
        if not accept_conditional_boundaries:
            raise Ineligible('expression island: explicit conditional boundary opt-in required')
        if not row['assumptions_complete'] and not accept_unattributed_assumptions:
            raise Ineligible('expression island: run assumptions unattributed; explicit opt-in required')
        substitutions = []
        for key,available in adapter.availability.items():
            if validity.get(key) is not True:
                raise Ineligible('expression island: every supplied boundary must be explicitly available')
            substitutions.append((available,z3.BoolVal(True)))
        for key,symbol in adapter.symbols.items():
            value = inputs.get(key)
            if value is not None:
                if type(value) is not int or not 0 <= value < 1<<symbol.size():
                    raise Ineligible('expression island: input width')
                substitutions.append((symbol,z3.BitVecVal(value,symbol.size())))
            elif key in adapter.availability:
                raise Ineligible('expression island: missing declared boundary value')
        if not z3.is_true(z3.simplify(z3.substitute(domain,*substitutions))):
            raise Ineligible('expression island: unknown inputs or outside region domain')
        values = {key:z3.simplify(z3.substitute(value,*substitutions)) for key,value in new.items()}
        if any(not z3.is_bv_value(value) for value in values.values()):
            raise Ineligible('expression island: unknown output inputs')
        return dict(outputs={key:value.as_long() for key,value in values.items()},scope=row['scope'],
                    connection=deepcopy(row['connection']),conditional_boundary_values=True,
                    assumptions_complete=row['assumptions_complete'],original_debt='retained')
    except (KeyError,TypeError,ValueError,IndexError,RecursionError,z3.Z3Exception) as error:
        raise Ineligible('expression island: malformed contract') from error


def render_expression_island(row):
    lines = [f"expression island {row['id']} [conditional; original graph/debt retained]",
             '  local = '+row['proof']['status']+'; original connection = '+row['connection']['status'],
             '  available ports are assumptions, not source/entry/effect proofs']
    for port in row['external_obligations']:
        lines.append(f"  {port['port']}:{8*port['width']} = original n{port['node']} @ {port['key']} [source obligation retained]")
    for node in row['graph']['nodes']:
        value = node.get('binding') if node['kind']=='input' else (str(node['value']) if node['kind']=='literal' else
            node['op']+str(node['parameters'])+'('+', '.join('i.n'+str(key) for key in node['args'])+')')
        lines.append(f"  i.n{node['id']}:{node['bits']} = {value}")
    for name,key in row['graph']['outputs'].items():
        lines.append(f'  {name} = i.n{key}')
    return lines
