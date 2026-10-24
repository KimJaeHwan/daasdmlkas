"""Existing countdown proofs with separately verified invariant-delta DAGs.

This consumes P0 views. It neither mutates legacy summaries nor widens their
counter/address/effect policy. Synthetic delta names are recipe parameters,
NOT new SSA definitions, bytes or captured-state inputs.
"""

from copy import deepcopy
import z3
from z3.z3util import get_vars

from .operation_records import Ineligible
from ._record_expression_views import select_expression, _namespace
from ._record_expression_bv import encode, decode, simplify
from ._record_expression_consumers import (_base, _identity, _references, _reuse, _Budget, _concrete)
from ._record_loop_summaries import _derive, _Normalizer, _Form, _Partial
from .resource_limits import step


def derive_loop_consumer(record, transition, view_ids):
    """Prove state'=state+delta(invariants), then reuse countdown machinery."""
    budget = _Budget()
    local, visit = _namespace(record, transition)
    if visit is None or 'write_projection' in visit:
        raise Ineligible('expression loop: requires original complete RAM/register one-visit')
    references = _references(record, transition, view_ids, budget)
    states = {row['id']: row for row in visit['inputs']}
    mutable = {key for key, row in states.items() if row['mutable']}
    body, = [row for row in visit['outcomes'] if row['kind']=='continue']
    outputs = [dict(name=str(i), width=int(row['span'][-1],16), parts=[row['part']], guard=body['guard'])
               for i,row in enumerate(body['updates'])]
    selection = select_expression(record, outputs, namespace=transition)
    proofs, delta_recipes = [], []

    def forms(assignments, counter_decision):
        counter_decision = counter_decision or next(iter(local['control']['decisions']))
        counter = _Normalizer(visit, record['limits']).zero_test(local['control']['decisions'][counter_decision]['operand'])
        assignments = assignments or {counter_decision: not counter['zero_when_decision']}
        logic = _Normalizer(visit, record['limits'], assignments)
        active = {row['operation']: assignments[row['operation']] for row in visit['operations']
                  if row['operation'] in assignments and logic.guard(row['guard'])}

        def original_case(adapter):
            conditions = []
            for key, truth in active.items():
                predicate, defined = adapter.decision(key)
                conditions.extend((defined, predicate if truth else z3.Not(predicate)))
            return z3.And(*conditions)

        adapter, old, domain, _, limits, graph = _reuse(record, selection, references, budget, restrict=original_case)
        values = decode(graph, adapter.symbols, limits)
        symbols = {}
        for key, binding in adapter.bindings.items():
            state = binding['transition_input']
            if state is None or state in symbols:
                raise Ineligible('expression loop: ambiguous original state binding')
            symbols[state] = adapter.symbols[key]
        if not mutable <= set(symbols):
            raise Ineligible('expression loop: incomplete mutable state coverage')
        replacements = [(symbols[key], z3.BitVecVal(1 if key==counter['input'] else 0, symbols[key].size()))
                        for key in sorted(mutable)]
        # A seed of ONE keeps the original body guard active. This is only a
        # candidate: the recurrence below is proved for ALL original G states.
        deltas, result = {}, {}
        for index,row in enumerate(body['updates']):
            step()
            span=tuple(row['span'])
            matches=[key for key,state in states.items() if state['span']==row['span']]
            if len(matches)!=1 or matches[0] not in mutable:
                raise Ineligible('expression loop: output is not original mutable input')
            key=matches[0]
            initial=symbols[key]
            value=values[str(index)]
            delta=simplify(z3.substitute(value-initial,*replacements),limits=limits)
            if {variable.get_id() for variable in get_vars(delta)} & {symbols[k].get_id() for k in mutable}:
                raise Ineligible('expression loop: delta retains mutable state')
            budget.implies(domain,old[str(index)]==initial+delta,'update is not an invariant translation')
            width=int(row['span'][-1],16)
            if key==counter['input']:
                if not z3.is_bv_value(delta) or delta.as_long()!=(1 << (8*width))-1:
                    raise Ineligible('expression loop: counter must decrement by exactly one')
                result[span]=_Form.make(width,terms=((key,1),)).add(_Form.make(width,-1))
            else:
                parameter='delta:'+key
                deltas[parameter]=delta
                result[span]=_Form.make(width,terms=((key,1),(parameter,1)))
        delta_graph=encode(deltas,adapter.symbols,limits) if deltas else None
        if delta_graph is not None:
            decoded=decode(delta_graph,adapter.symbols,limits)
            if set(decoded)!=set(deltas):
                raise Ineligible('expression loop: final delta outputs changed')
            for key in deltas:
                budget.implies(domain,decoded[key]==deltas[key],'final delta candidate changes recurrence')
        delta_recipes.append(dict(graph=delta_graph,
                                  bindings=[adapter.bindings[key] for key in sorted(adapter.bindings)],
                                  limits=selection['limits']))
        proofs.append(dict(selection=selection['id'], active_original_decisions=active,
                           referenced_views=list(references), domain='original_body_and_invariant_case',
                           recurrence_mismatch='unsat', mutable_delta_inputs=[]))
        return result

    try:
        summary = _derive(visit, record['limits'], update_forms=forms)
    except (_Partial, KeyError, ValueError, IndexError, StopIteration, RecursionError) as error:
        raise Ineligible('expression loop: '+str(error)) from error
    cases=summary.get('cases',[summary])
    if len(cases)!=len(delta_recipes):
        raise Ineligible('expression loop: case correspondence')
    for case,recipe in zip(cases,delta_recipes):
        case['invariant_delta']=recipe
    row=_base(record,'invariant_delta_countdown',transition,view_ids)
    row.update(summary=summary, recurrence_proofs=proofs, selection=selection,
               assumptions_complete=visit['analysis_context']['run_assumptions'] is not None,
               analysis_context=deepcopy(visit['analysis_context']),
               scope=summary['output_scope'], original_effects='original one-visit schedule retained',
               proof=dict(status='equivalent',kind='original_countdown_plus_verified_invariant_delta'))
    row['id']=_identity(row)
    return row


def evaluate_loop_consumer(record, consumer, inputs, accept_unattributed_assumptions):
    """Canonical recipe already checked by the public consumer dispatcher."""
    from ._record_transitions import evaluate_transition, _StepEvaluator
    from .operation_records import _choice_contract
    from ._record_expression_views import ViewLimits
    _,view=_namespace(record,consumer['namespace'])
    summary=consumer['summary']
    states={row['id']:row for row in view['inputs']}
    snapshot={}
    def read(key):
        if key not in snapshot:
            value=inputs.get(key)
            width=int(states[key]['span'][-1],16)
            if type(value) is not int or not 0<=value<1 << (8*width):
                raise Ineligible('expression loop: unknown or out-of-width state '+key)
            snapshot[key]=value
        return snapshot[key]
    n=read(summary['counter']['input'])
    case=summary.get('cases',[summary])[0]
    selected=[]
    if n and 'cases' in summary:
        nodes={node['id']:node for node in view['record']['nodes']}
        choices,control=_choice_contract(view['record'],nodes,list(nodes.values()),'injected')
        evaluator=_StepEvaluator(nodes,lambda node:read(node['transition_input']) if isinstance(node,dict) else None,
                                 None,{},choice_keys=choices,control=control)
        for operation in view['operations']:
            key=operation['operation']
            if key in summary['invariant_decisions'] and evaluator.guard(operation['guard']):
                selected.append(dict(decision=key,value=evaluator._decision(control['decisions'][key])==0))
        found=[case for case in summary['cases'] if case['choices']==selected]
        if len(found)!=1:
            raise Ineligible('expression loop: original shared choice correspondence')
        case=found[0]
    deltas={}
    if n and case['invariant_delta']['graph'] is not None:
        recipe=case['invariant_delta']
        symbols={row['id']:z3.BitVec(row['id'],row['width']*8) for row in recipe['bindings']}
        slots={row['id']:row['transition_input'] for row in recipe['bindings']}
        for name,value in decode(recipe['graph'],symbols,ViewLimits(**recipe['limits'])).items():
            concrete=_concrete(value,symbols,lambda key:read(slots[key]))
            if not z3.is_bv_value(concrete):
                raise Ineligible('expression loop: non-concrete invariant delta')
            deltas[name]=concrete.as_long()
    terminal,updates={},[]
    for update in case['updates']:
        key,width=update['input'],update['width']
        value=read(key)
        if n:
            delta=update['delta']['constant']
            for term in update['delta']['terms']:
                delta+=term['coefficient']*(deltas[term['input']] if term['input'] in deltas else read(term['input']))
            value=(value+n*delta)% (1 << (8*width))
        terminal[key]=value
        updates.append(dict(span=update['span'],value=value))
    class Terminal:
        def get(self,key):
            return terminal[key] if key in terminal else read(key)
    final=evaluate_transition(record,view['id'],Terminal(),accept_unattributed_assumptions=accept_unattributed_assumptions)
    if final['kind']!='exit' or final['edge']!=summary['exit_edge'] or final['updates']!=updates:
        raise Ineligible('expression loop: terminal original zero-visit mismatch')
    return dict(iterations=n,updates=updates,exit_edge=summary['exit_edge'],terminal_visit=final,
                transition=view['id'],selected_choices=selected,effect_template=summary['effect_template'],
                invariant_deltas=deltas,output_scope=consumer['scope'],conditional_on_original_analysis=True,
                assumptions_complete=consumer['assumptions_complete'],analysis_context=consumer['analysis_context'])
