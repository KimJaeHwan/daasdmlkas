"""Terminal tracked-state translations, derived ONLY from one-visit graphs.

This is a small bit-vector rewrite, not another SSA/RD, instruction engine,
trip-count heuristic or general loop solver. Original graphs stay authoritative.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
import sys

from .operation_records import Ineligible, Limits, _compute
from .resource_limits import step


class _Partial(Exception):
    pass


# Even a dead value operation must not introduce an unmodelled/partial effect
# during the visits skipped by the formula. In particular, division by a
# possibly zero divisor is not discharged by a linear terminal expression.
_TOTAL_OPS = frozenset(('COPY', 'CAST', 'LOAD', 'STORE', 'BRANCH', 'CBRANCH',
    'INT_ADD', 'INT_SUB', 'INT_MULT', 'INT_AND', 'INT_OR', 'INT_XOR', 'INT_NEGATE', 'INT_2COMP',
    'INT_LEFT', 'INT_RIGHT', 'INT_SRIGHT', 'INT_ZEXT', 'INT_SEXT', 'SUBPIECE', 'PIECE', 'POPCOUNT',
    'INT_EQUAL', 'INT_NOTEQUAL', 'INT_LESS', 'INT_LESSEQUAL', 'INT_SLESS', 'INT_SLESSEQUAL',
    'INT_CARRY', 'INT_SCARRY', 'INT_SBORROW', 'BOOL_NEGATE', 'BOOL_AND', 'BOOL_OR', 'BOOL_XOR'))


def _require(value, reason):
    if not value:
        raise _Partial(reason)


@dataclass(frozen=True)
class _Form:
    width: int
    constant: int
    terms: tuple[tuple[str, int], ...] = ()

    @classmethod
    def make(cls, width, constant=0, terms=()):
        _require(type(width) is int and 0 < width <= 16, 'translation width must be 1..16 bytes')
        modulus = 1 << (8 * width)
        combined = {}
        for key, coefficient in terms:
            step()
            combined[key] = (combined.get(key, 0) + coefficient) % modulus
        return cls(width, constant % modulus, tuple(sorted((key, value) for key, value in combined.items() if value)))

    def add(self, other, sign=1):
        _require(self.width == other.width, 'mixed-width arithmetic')
        return self.make(self.width, self.constant + sign * other.constant,
                         (*self.terms, *((key, sign * value) for key, value in other.terms)))

    def record(self):
        return dict(width=self.width, constant=self.constant,
                    terms=[dict(input=key, coefficient=value) for key, value in self.terms])


class _Normalizer:
    """Exact low-byte modular projection; predicates/addresses stay strict."""

    def __init__(self, view, limits, assignments=None):
        self.view, self.limits = view, limits
        self.nodes = {node['id']: node for node in view['record']['nodes']}
        self.inputs = {row['id']: row for row in view['inputs']}
        self.memo, self.active, self.evidence = {}, set(), []
        self.work = 0
        self.assignments = assignments or {}

    def guard(self, reference):
        dag = self.view['record']['control']['nodes']
        while reference >= 2:
            row = dag[reference]
            reference = row['true'] if self.assignments[row['decision']] else row['false']
        return bool(reference)

    def charge(self, amount=1):
        step(amount)
        self.work += amount
        _require(self.work <= self.limits.get('edges', Limits.edges), 'summary rewrite evidence limit')

    def parts(self, parts, width, depth, *, requested=None, strict=False):
        wanted = width if requested is None else requested
        _require(0 < wanted <= width, 'invalid requested operand width')
        selected = []
        for part in parts:
            low, high = part['at']
            start, stop = max(0, low), min(wanted, high)
            if start < stop:
                selected.append((start, stop, part['node'], part['bytes'][0] + start - low))
        selected.sort()
        _require(selected and selected[0][0] == 0 and selected[-1][1] == wanted
                 and all(a[1] == b[0] for a, b in zip(selected, selected[1:])),
                 'split or incomplete expression bytes')
        first = selected[0]
        _require(all(row[2] == first[2] and row[3] - row[0] == first[3] for row in selected),
                 'split bytes have different original producers')
        _require(first[3] == 0, 'nonzero source byte offset is not a low-byte projection')
        return self.part(dict(node=first[2], bytes=[0, wanted], at=[0, wanted]), depth + 1, strict=strict)

    def part(self, part, depth=0, *, strict=False):
        _require(depth <= self.limits.get('depth', Limits.depth), 'summary rewrite depth limit')
        node = self.nodes[part['node']]
        width = node.get('size') or node.get('output', {}).get('size')
        if node.get('opcode') == 'STORE':
            width = next(item['width'] for item in node['operands'] if item['index'] == 2)
        requested = part['bytes'][1] - part['bytes'][0]
        _require(width is not None and part['bytes'][0] == 0 and 0 < requested <= width
                 and not part.get('whole'), 'partial-byte or width-changing expression')
        _require(not strict or requested == width, 'partial-byte strict condition or address')
        identifier = node['id'], requested, strict
        if identifier in self.memo:
            return self.memo[identifier]
        _require(identifier not in self.active, 'unexpected value cycle in one visit')
        self.active.add(identifier)
        self.charge()
        children = []

        def operand(item):
            value = self.parts(item['parts'], item['width'], depth + 1, requested=requested, strict=strict)
            children.extend(part['node'] for part in item['parts'])
            return value

        if node['kind'] == 'entry':
            key = node['transition_input']
            _require(int(self.inputs[key]['span'][-1], 16) == width, 'input byte identity')
            form, rule = _Form.make(requested, terms=((key, 1),)), 'boundary_input_low_bits'
        elif node['kind'] == 'const':
            form, rule = _Form.make(requested, node['value']), 'literal_low_bits'
        elif node['kind'] == 'phi':
            _require('guarded_sources' in node and self.assignments, 'unselected phi')
            guarded = node['guarded_sources']
            _require(self.guard(guarded['reach']), 'inactive phi reach')
            choices = [i for i, guard in enumerate(guarded['guards']) if self.guard(guard)]
            _require(len(choices) == 1, 'guarded phi correspondence')
            alternative = node['alternatives'][choices[0]]
            form = self.parts([alternative], width, depth + 1, requested=requested, strict=strict)
            children.append(alternative['node'])
            rule = 'original_guarded_phi_case'
        else:
            _require(node['kind'] == 'op', 'nonlinear or selected expression')
            opcode = node['opcode']
            values = [item for item in node['operands'] if 'parts' in item]
            if opcode == 'LOAD':
                _require(len(node['memory']) == 1, 'multiple memory places')
                form = self.parts(node['memory'][0]['parts'], width, depth + 1, requested=requested, strict=strict)
                children.extend(part['node'] for part in node['memory'][0]['parts'])
                rule = 'original_load_value'
            elif opcode == 'STORE':
                form = operand(next(item for item in values if item['index'] == 2))
                rule = 'original_store_value'
            elif opcode in ('COPY', 'CAST'):
                _require(len(values) == 1, 'forwarding operand shape')
                _require(not strict or values[0]['width'] == width, 'strict forwarding width change')
                form, rule = operand(values[0]), 'low_bits_forward'
            elif opcode in ('INT_ZEXT', 'INT_SEXT'):
                _require(len(values) == 1 and not strict and requested <= values[0]['width'],
                         'observable extension is not a modular low-byte identity')
                form, rule = operand(values[0]), 'extension_discarded_by_low_bits'
            elif opcode == 'SUBPIECE':
                _require(not strict and len(values) == 2, 'strict SUBPIECE width change')
                offset = self.parts(values[1]['parts'], values[1]['width'], depth + 1)
                _require(not offset.terms and offset.constant == 0, 'nonzero SUBPIECE offset')
                form, rule = operand(values[0]), 'zero_offset_subpiece_low_bits'
            elif opcode in ('INT_ADD', 'INT_SUB', 'INT_AND', 'INT_OR', 'INT_XOR'):
                _require(len(values) == 2, 'binary operand shape')
                left, right = map(operand, values)
                _require(values[0]['width'] == values[1]['width'] == width, 'mixed-width arithmetic')
                _require(left.width == right.width == requested, 'projection width mismatch')
                if opcode in ('INT_ADD', 'INT_SUB'):
                    form = left.add(right, -1 if opcode == 'INT_SUB' else 1)
                    rule = 'same_width_' + opcode.lower()
                else:
                    zero, ones = _Form.make(requested), _Form.make(requested, -1)
                    if opcode == 'INT_AND' and (left == right or right == ones):
                        form = left
                    elif opcode == 'INT_AND' and left == ones:
                        form = right
                    elif opcode in ('INT_OR', 'INT_XOR') and right == zero:
                        form = left
                    elif opcode in ('INT_OR', 'INT_XOR') and left == zero:
                        form = right
                    else:
                        raise _Partial('nonlinear bitwise update')
                    rule = 'exact_bitwise_identity'
            else:
                raise _Partial('unsupported translation operator ' + opcode)
            _require(form.width == requested, 'width-changing value chain')
        self.charge(len(form.terms) + len(children))
        self.evidence.append(dict(node=node['id'], requested_width=requested, strict=strict,
                                  rule=rule, children=children, form=form.record()))
        self.active.remove(identifier)
        self.memo[identifier] = form
        return form

    def zero_test(self, operand):
        """Return the original full-width state counter and zero polarity."""
        _require(len(operand['parts']) == 1, 'split counter guard')
        part, = operand['parts']
        node = self.nodes[part['node']]
        _require(part['bytes'] == [0, 1] and part['at'] == [0, 1] and operand['width'] == 1,
                 'counter guard is not a whole boolean')
        seen, negate = set(), False
        while node.get('opcode') in ('COPY', 'CAST', 'BOOL_NEGATE'):
            self.charge()
            _require(node['id'] not in seen, 'cyclic counter guard')
            seen.add(node['id'])
            negate ^= node['opcode'] == 'BOOL_NEGATE'
            values = [item for item in node['operands'] if 'parts' in item]
            _require(len(values) == 1 and values[0]['width'] == 1, 'width-changing boolean guard')
            _require(len(values[0]['parts']) == 1, 'split boolean guard')
            part, = values[0]['parts']
            _require(part['bytes'] == [0, 1] and part['at'] == [0, 1], 'partial guard byte')
            node = self.nodes[part['node']]
        _require(node.get('opcode') in ('INT_EQUAL', 'INT_NOTEQUAL'), 'counter guard must test zero equality')
        operands = [item for item in node['operands'] if 'parts' in item]
        _require(len(operands) == 2, 'counter compare shape')
        left, right = [self.parts(item['parts'], item['width'], 0, strict=True) for item in operands]
        form = left.add(right, -1)
        _require(form.constant == 0 and len(form.terms) == 1, 'counter compare is not a full-width zero test')
        counter, coefficient = form.terms[0]
        _require(coefficient in (1, (1 << (8 * form.width)) - 1) and self.inputs[counter]['mutable'],
                 'counter compare is not an unscaled mutable state')
        return dict(input=counter, width=form.width, comparison_node=node['id'],
                    zero_when_decision=bool((node['opcode'] == 'INT_EQUAL') ^ negate))


def _derive_case(view, limits, assignments=None, counter_decision=None, *, write_effect=False, update_forms=None):
    _require(view['complete'], 'original one-visit view is incomplete')
    _require(len(view['entry_edges']) == len(view['cut_edges']) == 1, 'requires one entry edge and one recurrence cut')
    outcomes = view['outcomes']
    _require(len(outcomes) == 2 and [row['kind'] for row in outcomes] == ['continue', 'exit'],
             'requires one continue and one exit')
    body, exit = outcomes
    control = view['record']['control']
    _require(counter_decision is not None or len(control['decisions']) == 1, 'body branches are not translation summaries')
    decision = counter_decision or next(iter(control['decisions']))
    predicate = control['decisions'][decision]
    normalizer = _Normalizer(view, limits, assignments)
    _require(all(normalizer.nodes[row['node']]['opcode'] in _TOTAL_OPS for row in view['operations']),
             'unsupported or potentially partial operation in skipped visits')
    normalizer.charge(len(view['operations']))
    counter = normalizer.zero_test(predicate['operand'])
    # The one-decision Boolean DAG is checked locally; v12 validates it
    # against the original raw CFG before a consumer may use this recipe.
    truth = [(False, False), (True, True)]
    for row in control['nodes'][2:]:
        normalizer.charge()
        if row['decision'] == decision:
            truth.append((truth[row['false']][0], truth[row['true']][1]))
        else:
            _require(assignments is not None and row['decision'] in assignments, 'unshared loop decision')
            truth.append(truth[row['true'] if assignments[row['decision']] else row['false']])
    zero_when = counter['zero_when_decision']
    exit_truth = (not zero_when, zero_when)
    body_truth = tuple(not value for value in exit_truth)
    _require(truth[body['guard']] == body_truth and truth[exit['guard']] == exit_truth,
             'continue/exit polarity does not match the zero test')
    _require(all(truth[row['guard']] in ((False, False), (True, True), body_truth) for row in view['operations']),
             'operation outside the simple header/body schedule')
    inputs = {tuple(row['span']): row for row in view['inputs']}
    mutable = {row['id'] for row in view['inputs'] if row['mutable']}
    exits = {tuple(row['span']): row for row in exit['updates']}
    updates = []
    for row in body['updates']:
        normalizer.charge()
        span = tuple(row['span'])
        _require(span in inputs and span in exits, 'output has no original boundary input')
        state = inputs[span]
        width, key = int(span[-1], 16), state['id']
        initial = _Form.make(width, terms=((key, 1),))
        _require(normalizer.part(exits[span]['part']) == initial, 'zero-exit changes tracked state')
        value = normalizer.part(row['part']) if update_forms is None else update_forms[span]
        delta = value.add(initial, -1)
        _require(not (set(dict(delta.terms)) & mutable), 'delta depends on mutable state')
        if key == counter['input']:
            _require(width == counter['width'] and delta == _Form.make(width, -1), 'counter must decrement by exactly one')
        updates.append(dict(input=key, span=row['span'], width=width, one_visit_part=row['part'],
                            delta=delta.record(), rule='initial_plus_n_delta_modulo'))
    _require({row['input'] for row in updates} == mutable and counter['input'] in mutable,
             'incomplete mutable terminal-state coverage')
    addresses = []
    for i, event in enumerate(view['effects']):
        normalizer.charge()
        if truth[event['guard']] == (False, False):
            continue
        _require(truth[event['guard']] in ((True, True), body_truth), 'conditional memory schedule')
        _require(event['kind'] != 'store' or truth[event['guard']] == body_truth, 'write occurs on zero-exit')
        node = normalizer.nodes[event['node']]
        pointer, = [item for item in node['operands'] if item['index'] == 1]
        address = normalizer.parts(pointer['parts'], pointer['width'], 0, strict=True)
        _require(write_effect and event['kind'] == 'store' or not (set(dict(address.terms)) & mutable),
                 'memory address varies across visits')
        addresses.append(dict(effect=i, address=address.record(), phase='header' if truth[event['guard']] == (True, True) else 'body'))
    return dict(id=view['id'] + '/countdown-translation', transition=view['id'], complete=True,
                method='countdown_translation_v1', evaluation='closed_form_without_unrolling',
                counter=counter, count_domain='unsigned_counter_at_this_region_entry',
                continue_edge=body['edge'], exit_edge=exit['edge'], decision=decision,
                updates=updates, memory_addresses=addresses, derivation=normalizer.evidence,
                effect_template=dict(transition=view['id'], body_repetitions='n', header_repetitions='n+1',
                                     includes_terminal_zero_visit=True, full_trace_materialized=False),
                analysis_context=view['analysis_context'],
                output_scope='terminal_loop_carried_and_observed_RAM_bytes_not_full_machine_or_function_return')


def _guard_support(control, reference):
    found, seen, pending = set(), set(), [reference]
    while pending:
        step()
        reference = pending.pop()
        if reference < 2 or reference in seen:
            continue
        seen.add(reference)
        row = control['nodes'][reference]
        found.add(row['decision'])
        pending.extend((row['true'], row['false']))
    return found


def _predicate_inputs(view, decision, limits):
    """Full semantic dependencies, never low-byte value normalization."""
    from .operation_records import _node_parts

    nodes = {row['id']: row for row in view['record']['nodes']}
    states = {row['id']: row for row in view['inputs']}
    pending = [part['node'] for part in view['record']['control']['decisions'][decision]['operand']['parts']]
    seen, inputs = set(), set()
    while pending:
        step()
        identifier = pending.pop()
        if identifier in seen:
            continue
        seen.add(identifier)
        _require(len(seen) <= limits.get('edges', Limits.edges), 'predicate dependency limit')
        node = nodes[identifier]
        if node['kind'] == 'entry':
            key = node['transition_input']
            _require(not states[key]['mutable'], 'branch condition depends on mutable state')
            inputs.add(key)
        else:
            _require(node['kind'] == 'const' or (node['kind'] == 'op' and node['opcode'] in _TOTAL_OPS),
                     'predicate has unsupported or selected dependencies')
            pending.extend(part['node'] for part in _node_parts(node))
    return sorted(inputs)


def _derive(view, limits, *, update_forms=None):
    if 'write_projection' in view:
        return _derive_write(view, limits)
    if not view['complete'] or len(view['record']['control']['decisions']) <= 1:
        forms = None if update_forms is None else update_forms(None, None)
        return _derive_case(view, limits, update_forms=forms)
    control = view['record']['control']
    exits = [row for row in view['outcomes'] if row['kind'] == 'exit']
    _require(len(exits) == 1, 'requires one exit')
    exit, = exits
    support = _guard_support(control, exit['guard'])
    _require(len(support) == 1, 'exit depends on multiple decisions')
    counter_decision, = support
    counter = _Normalizer(view, limits).zero_test(control['decisions'][counter_decision]['operand'])
    others = [row['operation'] for row in view['operations']
              if row['operation'] in control['decisions'] and row['operation'] != counter_decision]
    _require(len(others) <= 4, 'invariant branch case limit')
    dependencies = {key: _predicate_inputs(view, key, limits) for key in others}
    operation = {row['operation']: row for row in view['operations']}
    cases, seen = [], set()
    baseline = None
    for values in product((False, True), repeat=len(others)):
        assignment = dict(zip(others, values))
        assignment[counter_decision] = not counter['zero_when_decision']
        logic = _Normalizer(view, limits, assignment)
        choices = [dict(decision=key, value=assignment[key]) for key in others if logic.guard(operation[key]['guard'])]
        identity = tuple((row['decision'], row['value']) for row in choices)
        if identity in seen:
            continue
        seen.add(identity)
        forms = None if update_forms is None else update_forms(assignment, counter_decision)
        derived = _derive_case(view, limits, assignment, counter_decision, update_forms=forms)
        if baseline is None:
            baseline = derived
        cases.append(dict(choices=choices, updates=derived['updates'], derivation=derived['derivation'],
                          memory_addresses=derived['memory_addresses']))
    result = {key: value for key, value in baseline.items() if key not in ('updates', 'derivation', 'memory_addresses')}
    result.update(method='guarded_countdown_translation_v1', cases=cases, invariant_decisions=dependencies)
    return result


def _derive_write(view, limits):
    """Scalar translations plus one parametric original STORE, never RAM RD."""
    derived = _derive_case(view, limits, write_effect=True)
    _require(len(view['effects']) == 1 and view['effects'][0]['kind'] == 'store', 'requires one STORE effect')
    event, = view['effects']
    address, = derived['memory_addresses']
    _require(address['phase'] == 'body', 'STORE is not body-only')
    normalizer = _Normalizer(view, limits)
    node = normalizer.nodes[event['node']]
    pointer = next(item for item in node['operands'] if item['index'] == 1)
    form = normalizer.parts(pointer['parts'], pointer['width'], 0, strict=True)
    _require(len(form.terms) == 1 and form.terms[0][1] == 1, 'STORE address is not one unscaled pointer')
    key, _ = form.terms[0]
    update, = [row for row in derived['updates'] if row['input'] == key]
    stride = update['delta']['constant']
    _require(update['width'] == form.width and not update['delta']['terms']
             and 0 < stride < 1 << (8 * form.width - 1), 'pointer needs positive constant stride')
    value_operand = next(item for item in node['operands'] if item['index'] == 2)
    value = normalizer.parts(value_operand['parts'], value_operand['width'], 0)
    mutable = {row['id'] for row in view['inputs'] if row['mutable']}
    _require(not (set(dict(value.terms)) & mutable), 'STORE value varies across visits')
    _require(stride >= value.width, 'overlapping STORE stride is not supported')
    modulus = 1 << (8 * form.width)
    offset = form.constant if form.constant < modulus // 2 else form.constant - modulus
    derived.update(method='strided_original_STORE_translation_v1', output_scope=view['output_scope'],
                   memory_transform=dict(initial='M_initial', pointer=key, pointer_width=form.width,
                                         offset=offset, stride=stride, width=value.width, value=value.record(),
                                         space=node['space'], operation=event['operation'],
                                         original_occurrences=view['write_projection']['occurrences'],
                                         relation='M_final = apply_STORE(M_initial, address=p_initial+offset+i*stride, value=v, i=0..n-1)',
                                         untouched_bytes='preserved', no_wrap='checked_before_numeric_result',
                                         mapped_writable_or_fault_free='not_claimed', full_RAM_materialized=False))
    derived['derivation'].extend(normalizer.evidence)
    return derived


def publish_loop_summaries(record):
    rows = []
    for view in [*record.get('cycle_graph', {}).get('transitions', ()), *record.get('write_effect_transitions', ())]:
        try:
            rows.append(_derive(view, record['limits']))
        except (_Partial, StopIteration, ValueError, RecursionError) as error:
            rows.append(dict(id=view['id'] + '/countdown-translation', transition=view['id'],
                             complete=False, reason=str(error) or 'unsupported summary shape or rewrite limit'))
    return rows


def render_loop_summaries(record):
    lines = []
    for row in record.get('loop_summaries', ()):
        lines.append(f"loop summary {row['id']} [complete={row['complete']}; original graph and one-visit retained]")
        if not row['complete']:
            lines.append('  partial: ' + row['reason'])
            continue
        lines.append(f"  n = unsigned({row['counter']['input']}_initial); exit edge {row['exit_edge']}; no unrolling")
        cases = row.get('cases', [dict(updates=row.get('updates', ()), choices=[])])
        for case in cases:
            if case['choices']:
                lines.append('  shared invariant choice: ' + str(case['choices']))
            for update in case['updates']:
                lines.extend(_render_update(row, update))
        lines.append('  effects = original one-visit template, n bodies + terminal zero check (not one equivalent STORE)')
        if 'memory_transform' in row:
            memory = row['memory_transform']
            lines.append(f"  {memory['relation']}; offset={memory['offset']}; stride={memory['stride']}; width={memory['width']}; untouched bytes preserved")
    return lines


def _render_update(row, update):
    delta = update['delta']
    modulus = 1 << (8 * update['width'])
    signed = lambda value: value if value < modulus // 2 else value - modulus
    terms = [str(signed(delta['constant']))] if delta['constant'] else []
    terms.extend(f"{signed(term['coefficient'])}*{term['input']}_initial" for term in delta['terms'])
    text = ' + '.join(terms) or '0'
    namespace = 'w' if '/write-visit/' in row['transition'] else 't'
    return [f"  {update['input']}_final = ({update['input']}_initial + n*({text})) mod 2^{8 * update['width']} "
            f"[derived translation rule; original {namespace}{row['transition'].rsplit('/', 1)[-1]}.n{update['one_visit_part']['node']}]"]


def evaluate_loop_summary(record, identity, inputs, *, accept_unattributed_assumptions=False):
    """Evaluate a proven terminal-state formula, never execute n visits."""
    from .operation_records import _NeedChoice, _Unknown, _Infeasible
    previous = sys.getrecursionlimit()
    sys.setrecursionlimit(max(previous, 16 * record.get('limits', {}).get('depth', Limits.depth) + 2000))
    try:
        return _evaluate(record, identity, inputs, accept_unattributed_assumptions)
    except (_Partial, _NeedChoice, _Unknown, _Infeasible, KeyError, ValueError, TypeError, IndexError, StopIteration, RecursionError) as error:
        raise Ineligible('loop summary: ' + (str(error) or 'invalid expression contract')) from error
    finally:
        sys.setrecursionlimit(previous)


def _evaluate(record, identity, inputs, accept_unattributed_assumptions):
    from ._record_transition_contract import validate
    from ._record_transitions import evaluate_transition

    summary = next((row for row in record.get('loop_summaries', ()) if row['id'] == identity), None)
    _require(summary is not None and summary['complete'], 'incomplete loop summary')
    views = [*record['cycle_graph']['transitions'], *record.get('write_effect_transitions', ())]
    view, = [row for row in views if row['id'] == summary['transition']]
    if 'write_projection' in view:
        from ._record_write_effects import validate
    validate(record, view)  # No input values are touched before BOTH contracts.
    _require(summary == _derive(view, record['limits']), 'summary differs from original one-visit derivation')
    context = summary['analysis_context']
    _require(context['run_assumptions'] is not None or accept_unattributed_assumptions,
             'unattributed run assumptions; explicit opt-in required')
    state = {row['id']: row for row in view['inputs']}
    snapshot = {}

    def read(key):
        if key in snapshot:
            return snapshot[key]
        value, width = inputs.get(key), int(state[key]['span'][-1], 16)
        _require(type(value) is int and 0 <= value < 1 << (8 * width), 'unknown or out-of-width input ' + key)
        snapshot[key] = value
        return value

    n = read(summary['counter']['input'])
    updates_recipe = summary.get('updates')
    selected_choices = []
    if 'cases' in summary:
        if not n:
            updates_recipe = summary['cases'][0]['updates']
        else:
            from ._record_transitions import _StepEvaluator
            from .operation_records import _choice_contract

            nodes = {node['id']: node for node in view['record']['nodes']}
            choices, control = _choice_contract(view['record'], nodes, list(nodes.values()), 'injected')
            evaluator = _StepEvaluator(nodes, lambda node: read(node['transition_input']) if isinstance(node, dict) else None,
                                       None, {}, choice_keys=choices, control=control)
            for operation in view['operations']:
                key = operation['operation']
                if key in summary['invariant_decisions'] and evaluator.guard(operation['guard']):
                    selected_choices.append(dict(decision=key, value=evaluator._decision(control['decisions'][key]) == 0))
            chosen, = [case for case in summary['cases'] if case['choices'] == selected_choices]
            updates_recipe = chosen['updates']
    terminal, updates = {}, []
    for update in updates_recipe:
        width, key = update['width'], update['input']
        value = read(key)
        if n:
            delta = update['delta']['constant']
            for term in update['delta']['terms']:
                delta += term['coefficient'] * read(term['input'])
            product = _compute('INT_MULT', [n, delta], [summary['counter']['width'], width], width)
            value = _compute('INT_ADD', [value, product], [width, width], width) & ((1 << (8 * width)) - 1)
        terminal[key] = value
        updates.append(dict(span=update['span'], value=value))

    memory_result = None
    if 'memory_transform' in summary:
        memory = summary['memory_transform']
        start, stride = read(memory['pointer']), memory['stride']
        modulus = 1 << (8 * memory['pointer_width'])
        _require(start + n * stride < modulus, 'final pointer wraps')
        first = start + memory['offset'] if n else None
        _require(not n or 0 <= first and first + (n - 1) * stride + memory['width'] <= modulus,
                 'STORE address or final byte wraps')
        value = None
        if n:
            value = memory['value']['constant'] + sum(term['coefficient'] * read(term['input'])
                                                       for term in memory['value']['terms'])
            value %= 1 << (8 * memory['width'])
        memory_result = dict(initial='M_initial', space=memory['space'], first_address=first, count=n,
                             stride=stride, width=memory['width'], value=value, operation=memory['operation'],
                             untouched_bytes='preserved', full_RAM_materialized=False,
                             mapped_writable_or_fault_free='not_claimed')

    class _Terminal:
        def get(self, key):
            return terminal[key] if key in terminal else read(key)

    # Reuse v12 for the FINAL zero visit, including its real condition LOADs.
    # It does not demand inactive delta/body operands or materialize n visits.
    final = evaluate_transition(record, view['id'], _Terminal(),
                                accept_unattributed_assumptions=accept_unattributed_assumptions)
    _require(final['kind'] == 'exit' and final['edge'] == summary['exit_edge'] and final['updates'] == updates,
             'terminal one-visit correspondence')
    result = dict(iterations=n, exit_edge=summary['exit_edge'], updates=updates, terminal_visit=final,
                effect_template=summary['effect_template'], transition=view['id'],
                conditional_on_original_analysis=True, assumptions_complete=context['run_assumptions'] is not None,
                analysis_context=context, output_scope=summary['output_scope'])
    if 'cases' in summary:
        result['selected_choices'] = selected_choices
    if memory_result is not None:
        result['memory_transform'] = memory_result
    return result
