"""Bounded composition of ORIGINAL validated one-visit expressions.

max_visits is a query bound, never a trip-count/termination proof. Existing
state byte identities and invariant addresses are retained; exit absorbs.
This adds a derived DAG, not SSA, RD, alias analysis or an instruction VM.
"""

from copy import deepcopy
import z3
from z3.z3util import get_vars

from .operation_records import Ineligible
from .resource_limits import step
from ._record_expression_views import _namespace, _fingerprint, ViewLimits
from ._record_expression_bv import Adapter, encode, decode
from ._record_expression_consumers import _base, _identity, _Budget, _concrete
from ._record_loop_summaries import _TOTAL_OPS


def _model(record, transition, max_visits):
    if type(max_visits) is not int or not 0<=max_visits<=8:
        raise Ineligible('transition chain: max_visits must be an integer from 0 to 8')
    local,view=_namespace(record,transition)
    if view is None or 'write_projection' in view:
        raise Ineligible('transition chain: original complete general one-visit required')
    states={row['id']:row for row in view['inputs']}
    tracked={key for key,row in states.items() if row['mutable']}
    by_span={tuple(row['span']):key for key,row in states.items()}
    for outcome in view['outcomes']:
        keys=[]
        for update in outcome['updates']:
            key=by_span.get(tuple(update['span']))
            if key is None or key not in tracked:
                raise Ineligible('transition chain: output lacks an exact captured mutable input byte span')
            keys.append(key)
        if set(keys)!=tracked or len(keys)!=len(tracked):
            raise Ineligible('transition chain: nonclosed state projection')
    limits=ViewLimits()
    selection=dict(nodes=[node['id'] for node in local['nodes']])
    adapter=Adapter(local,selection,limits,memory=True)
    requirements=[]
    for row in view['operations']:
        node=adapter.nodes[row['node']]
        if node['opcode'] not in _TOTAL_OPS:
            raise Ineligible('transition chain: partial or unsupported original operation')
        guard,gd=adapter.guard(row['guard'])
        if node['opcode'] not in ('BRANCH','CBRANCH'):
            _,defined=adapter.node(row['node'])
            requirements.extend((gd,z3.If(guard,defined,z3.BoolVal(True))))
    outcomes=[]
    for outcome in view['outcomes']:
        guard,gd=adapter.guard(outcome['guard'])
        values={}
        for update in outcome['updates']:
            key=by_span[tuple(update['span'])]
            value,defined=adapter.assemble([update['part']],int(update['span'][-1],16))
            values[key]=value
            requirements.append(z3.If(guard,defined,z3.BoolVal(True)))
        outcomes.append(dict(kind=outcome['kind'],edge=outcome['edge'],guard=guard,values=values))
        requirements.append(gd)
    requirements.append(z3.PbEq([(row['guard'],1) for row in outcomes],1))
    effects=[]
    for row in view['effects']:
        node=adapter.nodes[row['node']]
        guard,gd=adapter.guard(row['guard'])
        address,ad=adapter.operand(next(arg for arg in node['operands'] if arg['index']==1))
        value,defined=adapter.node(row['node'])
        requirements.extend((gd,z3.If(guard,z3.And(ad,defined),z3.BoolVal(True))))
        effects.append(dict(original=deepcopy(row),guard=guard,address=address,value=value,
            space=node['space'],width=value.size()//8,
            reads=deepcopy([read for read in view['reads'] if read['operation']==row['operation'] and
                           read['span'][1] in ('address_space','function_relative')])))
    decisions=[]
    for row in view['operations']:
        if row['operation'] in adapter.control['decisions']:
            predicate,defined=adapter.decision(row['operation'])
            guard,gd=adapter.guard(row['guard'])
            requirements.extend((gd,z3.If(guard,defined,z3.BoolVal(True))))
            decisions.append(dict(operation=row['operation'],guard=guard,value=predicate))
    bindings={key:row['transition_input'] for key,row in adapter.bindings.items()}
    if any(key is None or key not in states for key in bindings.values()) or len(set(bindings.values()))!=len(bindings):
        raise Ineligible('transition chain: ambiguous original state binding')
    symbols={key:z3.BitVec('initial:'+key,8*int(row['span'][-1],16)) for key,row in states.items()}
    mutable_symbols={adapter.symbols[key].get_id() for key,state in bindings.items() if state in tracked}
    for effect in effects:
        if {var.get_id() for var in get_vars(z3.simplify(effect['address']))} & mutable_symbols:
            raise Ineligible('transition chain: mutable memory address requires a different memory-state contract')
    return view,states,tracked,adapter,bindings,symbols,outcomes,effects,decisions,z3.And(*requirements),limits


def _visit_outputs(model):
    outputs={}
    for number,row in enumerate(model[6]):
        outputs[f'o{number}:guard']=row['guard']
        outputs.update({f'o{number}:state:{key}':value for key,value in row['values'].items()})
    for number,row in enumerate(model[7]):
        outputs.update({f'e{number}:{key}':row[key] for key in ('guard','address','value')})
    for number,row in enumerate(model[8]):
        outputs.update({f'd{number}:{key}':row[key] for key in ('guard','value')})
    return outputs


def _visit_model(model, graph, budget):
    """Reprove the saved local DAG BEFORE using it in any state substitution."""
    original=_visit_outputs(model)
    values=decode(graph,model[3].symbols,model[-1])
    if set(values)!=set(original) or any(values[key].sort()!=original[key].sort() for key in original):
        raise Ineligible('transition chain: one-visit output inventory or sort changed')
    budget.implies(model[-2],z3.And(*(values[key]==original[key] for key in original)),
                   'stored one-visit expressions differ from original guarded visit')
    outcomes=[dict(row,guard=values[f'o{number}:guard'],values={key:values[f'o{number}:state:{key}']
        for key in row['values']}) for number,row in enumerate(model[6])]
    effects=[dict(row,**{key:values[f'e{number}:{key}'] for key in ('guard','address','value')})
        for number,row in enumerate(model[7])]
    decisions=[dict(row,**{key:values[f'd{number}:{key}'] for key in ('guard','value')})
        for number,row in enumerate(model[8])]
    return (*model[:6],outcomes,effects,decisions,*model[9:])


def _compose(model, max_visits):
    view,states,tracked,adapter,bindings,symbols,outcomes,effects,decisions,defined,limits=model
    current=dict(symbols)
    alive=z3.BoolVal(True)
    visits=z3.BitVecVal(0,8)
    outputs,rounds,domain={},[],[]
    for number in range(max_visits):
        step()
        substitutions=[(adapter.symbols[key],current[state]) for key,state in bindings.items()]
        at=lambda value:z3.substitute(value,*substitutions)
        domain.append(z3.If(alive,at(defined),z3.BoolVal(True)))
        prefix=f'v{number}:'
        outputs[prefix+'active']=alive
        row=dict(visit=number,input_versions={key:('initial:'+key if number==0 or not state['mutable'] else f'v{number-1}:'+key)
            for key,state in states.items()},outcomes=[],effects=[],decisions=[])
        for index,outcome in enumerate(outcomes):
            name=prefix+'outcome:'+str(index)
            outputs[name]=z3.If(alive,at(outcome['guard']),z3.BoolVal(False))
            row['outcomes'].append(dict(edge=outcome['edge'],kind=outcome['kind'],active=name))
        for index,effect in enumerate(effects):
            name=prefix+'effect:'+str(index)
            outputs[name+':active']=z3.If(alive,at(effect['guard']),z3.BoolVal(False))
            outputs[name+':address'],outputs[name+':value']=at(effect['address']),at(effect['value'])
            row['effects'].append(dict(operation=effect['original']['operation'],kind=effect['original']['kind'],
                active=name+':active',address=name+':address',value=name+':value',space=effect['space'],width=effect['width'],
                source_reads=effect['reads'],state_version='initial' if number==0 else f'v{number-1}',
                definition_version=f'v{number}'))
        for index,decision in enumerate(decisions):
            name=prefix+'decision:'+str(index)
            outputs[name+':active']=z3.If(alive,at(decision['guard']),z3.BoolVal(False))
            outputs[name+':value']=at(decision['value'])
            row['decisions'].append(dict(operation=decision['operation'],active=name+':active',value=name+':value'))
        next_state=dict(current)
        for key in sorted(tracked):
            value=current[key]
            for index,outcome in enumerate(outcomes):
                value=z3.If(outputs[prefix+'outcome:'+str(index)],at(outcome['values'][key]),value)
            next_state[key]=value
            outputs[prefix+key]=next_state[key]
        visits=visits+z3.If(alive,z3.BitVecVal(1,8),z3.BitVecVal(0,8))
        alive=z3.If(alive,z3.Or(*(at(row['guard']) for row in outcomes if row['kind']=='continue')),z3.BoolVal(False))
        current=next_state
        rounds.append(row)
    outputs.update({'state:'+key:current[key] for key in sorted(tracked)})
    outputs.update(alive=alive,visits=visits)
    return outputs,z3.simplify(z3.And(*domain)),rounds


def derive_transition_chain(record, transition, max_visits):
    """Build at most max_visits original visits; exits absorb, k=0 is identity."""
    return _derive(record,transition,max_visits)


def _derive(record, transition, max_visits, candidate=None, visit_candidate=None):
    budget=_Budget()
    model=_model(record,transition,max_visits)
    view,states,tracked,adapter,bindings,symbols,_,_,_,_,limits=model
    # An unconditional one-visit theorem survives every width-correct state
    # substitution. This avoids repeatedly solving duplicated definedness in
    # an unrolled DAG, without assuming any user predicate or reachable state.
    universal=budget.query(z3.Not(model[-2]))==z3.unsat
    # Prove a small original visit once. Revalidation consumes this SAME saved
    # local DAG only after reproving it, so commutative simplifier order cannot
    # cascade into an expensive, structurally different eight-visit formula.
    visit_graph=encode({key:z3.simplify(value) for key,value in _visit_outputs(model).items()},
                       adapter.symbols,limits) if visit_candidate is None else deepcopy(visit_candidate)
    compiled=_visit_model(model,visit_graph,budget)
    composed_model=(*compiled[:-2],z3.BoolVal(True),compiled[-1]) if universal else compiled
    original,domain,rounds=_compose(composed_model,max_visits)
    # This overlay composes visits, not an additional global simplifier. Keep
    # the shared original formula DAG; local simplifications remain available
    # through the existing expression-view APIs with their separate proofs.
    graph=encode(original,symbols,limits) if candidate is None else deepcopy(candidate)
    values=decode(graph,symbols,limits)
    if set(values)!=set(original) or any(values[key].sort()!=original[key].sort() for key in original):
        raise Ineligible('transition chain: candidate output inventory or sort changed')
    budget.implies(domain,z3.And(*(z3.simplify(values[key]==original[key]) for key in original)),
                   'serialized bounded composition differs from original guarded visits')
    row=_base(record,'bounded_transition_chain',transition,[])
    row.update(max_visits=max_visits,graph=graph,visit_graph=visit_graph,rounds=rounds,inputs=deepcopy(view['inputs']),tracked=sorted(tracked),
        source_transition=transition,scope='bounded_original_visits_tracked_state_not_trip_count_or_whole_machine',
        limits=dict(max_visits=8,nodes=limits.nodes,solver_ms=budget.limits.solver_ms,total_ms=budget.limits.total_ms),
        analysis_context=deepcopy(view['analysis_context']),
        assumptions_complete=view['analysis_context']['run_assumptions'] is not None,
        original_effects='ordered guarded original effects with visit-scoped state and writer identities',
        proof=dict(method='original_guarded_visit_composition',domain='sat',serialized_mismatch='unsat',
                   one_visit_domain='unconditionally_total' if universal else 'retained_per_active_visit',
                   stored_one_visit_mismatch='unsat',
                   trip_count='not_proven',termination='not_proven',original_debt='retained'))
    budget.check()
    row['id']=_identity(row)
    return row


def _canonical(record,row):
    if row.get('kind')!='bounded_transition_chain' or row.get('source')!=_fingerprint(record) or row.get('id')!=_identity(row):
        raise Ineligible('transition chain: changed source or identity')
    expected=_derive(record,row['source_transition'],row['max_visits'],candidate=row['graph'],visit_candidate=row['visit_graph'])
    if row!=expected:
        raise Ineligible('transition chain: changed formula or original recipe')
    return expected


def evaluate_transition_chain(record,row,inputs,accept_unattributed_assumptions=False):
    """Called only after canonical reproof. Existing one-visit evaluator checks it."""
    from ._record_transitions import evaluate_transition
    model=_model(record,row['source_transition'],row['max_visits'])
    view,states,tracked,adapter,bindings,symbols,_,_,_,_,limits=model
    domain=z3.BoolVal(True) if row['proof']['one_visit_domain']=='unconditionally_total' else _compose(model,row['max_visits'])[1]
    graph=decode(row['graph'],symbols,limits)
    initial={}
    def read(key):
        if key not in initial:
            value=inputs.get(key)
            bits=symbols[key].size()
            if type(value) is not int or not 0<=value<1<<bits:
                raise Ineligible('transition chain: unknown or out-of-width initial input '+key)
            initial[key]=value
        return initial[key]
    current={}
    class Snapshot:
        def get(self,key):
            return current[key] if key in current else read(key)
    # Only the original guarded evaluator decides which inputs are observed.
    # Simplification may reorder boolean children; interpreting that order as
    # an input demand would incorrectly inspect an inactive visit/branch.
    steps=[]
    for visit in range(row['max_visits']):
        raw=evaluate_transition(record,view['id'],Snapshot(),accept_unattributed_assumptions=accept_unattributed_assumptions)
        updates={next(key for key,state in states.items() if state['span']==update['span']):update['value'] for update in raw['updates']}
        current.update(updates)
        steps.append(dict(visit=visit,**raw))
        if raw['kind']=='exit':
            break
    # k=0 still returns the identity of the requested mutable state; no guard,
    # invariant selector, memory effect or body expression is evaluated.
    final_original={key:current[key] if key in current else read(key) for key in row['tracked']}
    substitutions=[(symbols[key],z3.BitVecVal(value,symbols[key].size())) for key,value in initial.items()]
    def cached(key):
        if key not in initial:
            raise Ineligible('transition chain: observed formula requires an unobserved initial input '+key)
        return initial[key]
    def value(expression):
        return _concrete(z3.simplify(z3.substitute(expression,*substitutions)),symbols,cached)
    def number(name):
        answer=value(graph[name])
        return z3.is_true(answer) if z3.is_bool(answer) else answer.as_long()
    if not z3.is_true(value(domain)):
        raise Ineligible('transition chain: outside original guarded visit domain')
    symbolic=[]
    for recipe in row['rounds']:
        if not number(f"v{recipe['visit']}:active"):
            break
        selected=[outcome for outcome in recipe['outcomes'] if number(outcome['active'])]
        if len(selected)!=1:
            raise Ineligible('transition chain: symbolic outcome correspondence')
        outcome,=selected
        effects=[]
        for event in recipe['effects']:
            if number(event['active']):
                effects.append(dict(operation=event['operation'],kind=event['kind'],space=event['space'],width=event['width'],
                    address=number(event['address']),value=number(event['value'])))
        decisions={decision['operation']:number(decision['value']) for decision in recipe['decisions'] if number(decision['active'])}
        symbolic.append(dict(visit=recipe['visit'],kind=outcome['kind'],edge=outcome['edge'],effects=effects,decisions=decisions,
            state={key:number(f"v{recipe['visit']}:{key}") for key in row['tracked']}))
    if len(symbolic)!=len(steps):
        raise Ineligible('transition chain: observed visit count mismatch')
    for expected,raw in zip(symbolic,steps,strict=True):
        updates={next(key for key,state in states.items() if state['span']==update['span']):update['value'] for update in raw['updates']}
        stripped=[{key:value for key,value in event.items() if key!='read_sources'} for event in raw['effects']]
        if (raw['kind']!=expected['kind'] or raw['edge']!=expected['edge'] or raw['decisions']!=expected['decisions']
                or stripped!=expected['effects'] or updates!=expected['state']):
            raise Ineligible('transition chain: numeric original visit cross-check mismatch')
    final={key:number('state:'+key) for key in row['tracked']}
    if number('visits')!=len(steps) or number('alive')!=(not steps or steps[-1]['kind']!='exit'):
        raise Ineligible('transition chain: bounded status mismatch')
    if final!=final_original:
        raise Ineligible('transition chain: final state mismatch')
    return dict(status='exit' if steps and steps[-1]['kind']=='exit' else 'bound_exhausted',
        max_visits=row['max_visits'],evaluated_visits=len(steps),state=final,steps=steps,
        scope=row['scope'],conditional_on_original_analysis=True,assumptions_complete=row['assumptions_complete'],
        trip_count='not_proven',termination='not_proven',original_debt='retained')


def render_transition_chain(row):
    return [f"transition chain {row['id']} [max_visits={row['max_visits']}; exit absorbs; original graph retained]",
            '  scope = '+row['scope']+'; trip count/termination not proven',
            '  formula outputs = '+', '.join(row['graph']['outputs']),
            '  effects/writers = original operations, scoped by visit and exact state-byte links']
