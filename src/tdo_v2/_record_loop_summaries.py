"""Terminal tracked-state translations, derived ONLY from one-visit graphs.

This is a small bit-vector rewrite, not another SSA/RD, instruction engine,
trip-count heuristic or general loop solver. Original graphs stay authoritative.
"""

from __future__ import annotations

from dataclasses import dataclass
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
    """Exact full-byte, same-width rules over existing expression nodes."""

    def __init__(self, view, limits):
        self.view, self.limits = view, limits
        self.nodes = {node['id']: node for node in view['record']['nodes']}
        self.inputs = {row['id']: row for row in view['inputs']}
        self.memo, self.active, self.evidence = {}, set(), []
        self.work = 0

    def charge(self, amount=1):
        step(amount)
        self.work += amount
        _require(self.work <= self.limits.get('edges', Limits.edges), 'summary rewrite evidence limit')

    def parts(self, parts, width, depth):
        _require(len(parts) == 1 and parts[0]['at'] == [0, width], 'split or incomplete expression bytes')
        form = self.part(parts[0], depth + 1)
        _require(form.width == width, 'operand width change')
        return form

    def part(self, part, depth=0):
        _require(depth <= self.limits.get('depth', Limits.depth), 'summary rewrite depth limit')
        node = self.nodes[part['node']]
        width = node.get('size') or node.get('output', {}).get('size')
        if node.get('opcode') == 'STORE':
            width = next(item['width'] for item in node['operands'] if item['index'] == 2)
        _require(width is not None and part['bytes'] == [0, width] and not part.get('whole'),
                 'partial-byte or width-changing expression')
        identifier = node['id']
        if identifier in self.memo:
            return self.memo[identifier]
        _require(identifier not in self.active, 'unexpected value cycle in one visit')
        self.active.add(identifier)
        self.charge()
        children = []

        def operand(item):
            value = self.parts(item['parts'], item['width'], depth + 1)
            children.extend(part['node'] for part in item['parts'])
            return value

        if node['kind'] == 'entry':
            key = node['transition_input']
            _require(int(self.inputs[key]['span'][-1], 16) == width, 'input byte identity')
            form, rule = _Form.make(width, terms=((key, 1),)), 'boundary_input'
        elif node['kind'] == 'const':
            form, rule = _Form.make(width, node['value']), 'literal'
        else:
            _require(node['kind'] == 'op', 'nonlinear or selected expression')
            opcode = node['opcode']
            values = [item for item in node['operands'] if 'parts' in item]
            if opcode == 'LOAD':
                _require(len(node['memory']) == 1, 'multiple memory places')
                form = self.parts(node['memory'][0]['parts'], width, depth + 1)
                children.extend(part['node'] for part in node['memory'][0]['parts'])
                rule = 'original_load_value'
            elif opcode == 'STORE':
                form = operand(next(item for item in values if item['index'] == 2))
                rule = 'original_store_value'
            elif opcode in ('COPY', 'CAST'):
                _require(len(values) == 1, 'forwarding operand shape')
                form, rule = operand(values[0]), 'same_width_forward'
            elif opcode in ('INT_ADD', 'INT_SUB', 'INT_AND', 'INT_OR', 'INT_XOR'):
                _require(len(values) == 2, 'binary operand shape')
                left, right = map(operand, values)
                _require(left.width == right.width == width, 'mixed-width arithmetic')
                if opcode in ('INT_ADD', 'INT_SUB'):
                    form = left.add(right, -1 if opcode == 'INT_SUB' else 1)
                    rule = 'same_width_' + opcode.lower()
                else:
                    zero, ones = _Form.make(width), _Form.make(width, -1)
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
            _require(form.width == width, 'width-changing value chain')
        self.charge(len(form.terms) + len(children))
        self.evidence.append(dict(node=identifier, rule=rule, children=children, form=form.record()))
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
        left, right = [self.parts(item['parts'], item['width'], 0) for item in operands]
        form = left.add(right, -1)
        _require(form.constant == 0 and len(form.terms) == 1, 'counter compare is not a full-width zero test')
        counter, coefficient = form.terms[0]
        _require(coefficient in (1, (1 << (8 * form.width)) - 1) and self.inputs[counter]['mutable'],
                 'counter compare is not an unscaled mutable state')
        return dict(input=counter, width=form.width, comparison_node=node['id'],
                    zero_when_decision=bool((node['opcode'] == 'INT_EQUAL') ^ negate))


def _derive(view, limits):
    _require(view['complete'], 'original one-visit view is incomplete')
    _require(len(view['entry_edges']) == len(view['cut_edges']) == 1, 'requires one entry edge and one recurrence cut')
    outcomes = view['outcomes']
    _require(len(outcomes) == 2 and [row['kind'] for row in outcomes] == ['continue', 'exit'],
             'requires one continue and one exit')
    body, exit = outcomes
    control = view['record']['control']
    _require(len(control['decisions']) == 1, 'body branches are not translation summaries')
    decision, predicate = next(iter(control['decisions'].items()))
    normalizer = _Normalizer(view, limits)
    _require(all(normalizer.nodes[row['node']]['opcode'] in _TOTAL_OPS for row in view['operations']),
             'unsupported or potentially partial operation in skipped visits')
    normalizer.charge(len(view['operations']))
    counter = normalizer.zero_test(predicate['operand'])
    # The one-decision Boolean DAG is checked locally; v12 validates it
    # against the original raw CFG before a consumer may use this recipe.
    truth = [(False, False), (True, True)]
    for row in control['nodes'][2:]:
        normalizer.charge()
        _require(row['decision'] == decision, 'unshared loop decision')
        truth.append((truth[row['false']][0], truth[row['true']][1]))
    zero_when = counter['zero_when_decision']
    exit_truth = (not zero_when, zero_when)
    body_truth = tuple(not value for value in exit_truth)
    _require(truth[body['guard']] == body_truth and truth[exit['guard']] == exit_truth,
             'continue/exit polarity does not match the zero test')
    _require(all(truth[row['guard']] in ((True, True), body_truth) for row in view['operations']),
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
        delta = normalizer.part(row['part']).add(initial, -1)
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
        _require(truth[event['guard']] in ((True, True), body_truth), 'conditional memory schedule')
        _require(event['kind'] != 'store' or truth[event['guard']] == body_truth, 'write occurs on zero-exit')
        node = normalizer.nodes[event['node']]
        pointer, = [item for item in node['operands'] if item['index'] == 1]
        address = normalizer.parts(pointer['parts'], pointer['width'], 0)
        _require(not (set(dict(address.terms)) & mutable), 'memory address varies across visits')
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


def publish_loop_summaries(record):
    rows = []
    for view in record.get('cycle_graph', {}).get('transitions', ()):
        try:
            rows.append(_derive(view, record['limits']))
        except (_Partial, RecursionError) as error:
            rows.append(dict(id=view['id'] + '/countdown-translation', transition=view['id'],
                             complete=False, reason=str(error) or 'summary recursion limit'))
    return rows


def render_loop_summaries(record):
    lines = []
    for row in record.get('loop_summaries', ()):
        lines.append(f"loop summary {row['id']} [complete={row['complete']}; original graph and one-visit retained]")
        if not row['complete']:
            lines.append('  partial: ' + row['reason'])
            continue
        lines.append(f"  n = unsigned({row['counter']['input']}_initial); exit edge {row['exit_edge']}; no unrolling")
        for update in row['updates']:
            delta = update['delta']
            modulus = 1 << (8 * update['width'])
            signed = lambda value: value if value < modulus // 2 else value - modulus
            terms = [str(signed(delta['constant']))] if delta['constant'] else []
            terms.extend(f"{signed(term['coefficient'])}*{term['input']}_initial" for term in delta['terms'])
            text = ' + '.join(terms) or '0'
            lines.append(f"  {update['input']}_final = ({update['input']}_initial + n*({text})) mod 2^{8 * update['width']} "
                         f"[derived translation rule; original t{row['transition'].rsplit('/', 1)[-1]}.n{update['one_visit_part']['node']}]")
        lines.append('  effects = original one-visit template, n bodies + terminal zero check (not one equivalent STORE)')
    return lines


def evaluate_loop_summary(record, identity, inputs, *, accept_unattributed_assumptions=False):
    """Evaluate a proven terminal-state formula, never execute n visits."""
    previous = sys.getrecursionlimit()
    sys.setrecursionlimit(max(previous, 16 * record.get('limits', {}).get('depth', Limits.depth) + 2000))
    try:
        return _evaluate(record, identity, inputs, accept_unattributed_assumptions)
    except (_Partial, KeyError, ValueError, TypeError, IndexError, StopIteration, RecursionError) as error:
        raise Ineligible('loop summary: ' + (str(error) or 'invalid expression contract')) from error
    finally:
        sys.setrecursionlimit(previous)


def _evaluate(record, identity, inputs, accept_unattributed_assumptions):
    from ._record_transition_contract import validate
    from ._record_transitions import evaluate_transition

    summary = next((row for row in record.get('loop_summaries', ()) if row['id'] == identity), None)
    _require(summary is not None and summary['complete'], 'incomplete loop summary')
    view, = [row for row in record['cycle_graph']['transitions'] if row['id'] == summary['transition']]
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
    terminal, updates = {}, []
    for update in summary['updates']:
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

    class _Terminal:
        def get(self, key):
            return terminal[key] if key in terminal else read(key)

    # Reuse v12 for the FINAL zero visit, including its real condition LOADs.
    # It does not demand inactive delta/body operands or materialize n visits.
    final = evaluate_transition(record, view['id'], _Terminal(),
                                accept_unattributed_assumptions=accept_unattributed_assumptions)
    _require(final['kind'] == 'exit' and final['edge'] == summary['exit_edge'] and final['updates'] == updates,
             'terminal one-visit correspondence')
    return dict(iterations=n, exit_edge=summary['exit_edge'], updates=updates, terminal_visit=final,
                effect_template=summary['effect_template'], transition=view['id'],
                conditional_on_original_analysis=True, assumptions_complete=context['run_assumptions'] is not None,
                analysis_context=context, output_scope=summary['output_scope'])
