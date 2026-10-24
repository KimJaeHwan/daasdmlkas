"""Bounded typed bit-vector adapter, not an instruction/state interpreter.

Only existing expression producers and validated one-visit memory sources
are translated. No alias solver, new reaching definitions or free phi choice.
"""

import z3
from functools import reduce

from .operation_records import Ineligible, _choice_contract
from ._record_expression_views import _parts, _width
from .resource_limits import step


def resize(value, bits, *, signed=False):
    if value.size() > bits:
        return z3.Extract(bits - 1, 0, value)
    return (z3.SignExt if signed else z3.ZeroExt)(bits - value.size(), value) if value.size() < bits else value


class Adapter:
    def __init__(self, local, selection, limits, *, memory=False, substitutions=None):
        self.local, self.limits, self.memory = local, limits, memory
        self.control = local.get('control') or dict(nodes=[False, True], decisions={})
        self.nodes = {node['id']: node for node in local['nodes']}
        self.selected = set(selection['nodes'])
        self.cache, self.active, self.guards, self.decisions = {}, set(), {}, {}
        self.bindings, self.symbols = {}, {}
        self.substitutions = substitutions or {}
        self.used_substitutions = set()
        self.edges = 0
        _choice_contract(local, self.nodes, [self.nodes[i] for i in selection['nodes']], 'stitched')

    def part(self, part):
        if part.get('loop') or part.get('pruned') or part.get('whole'):
            raise Ineligible('expression view: cycle or incomplete bytes')
        low, high = part['bytes']
        replacements = [row for row in self.substitutions.get(part['node'], ())
                        if low < row[1] and row[0] < high]
        if replacements:
            # Ports refer to exact ORIGINAL byte ranges. Partial overlap is
            # assembled with unchanged source bytes, never widened to a node.
            chunks, definitions, cursor = [], [], low
            for source_low, source_high, value in replacements:
                self.used_substitutions.add((part['node'], source_low, source_high))
                start, stop = max(source_low, low), min(source_high, high)
                if cursor < start:
                    original, defined = self.node(part['node'])
                    chunks.append((cursor, start, z3.Extract(start * 8 - 1, cursor * 8, original)))
                    definitions.append(defined)
                offset = start - source_low
                chunks.append((start, stop, z3.Extract((offset + stop - start) * 8 - 1, offset * 8, value)))
                cursor = stop
            if cursor < high:
                original, defined = self.node(part['node'])
                chunks.append((cursor, high, z3.Extract(high * 8 - 1, cursor * 8, original)))
                definitions.append(defined)
            result = z3.BitVecVal(0, (high - low) * 8)
            for start, stop, value in chunks:
                result |= resize(value, (high - low) * 8) << (8 * (start - low))
            return result, z3.And(*definitions)
        value, defined = self.node(part['node'])
        if not 0 <= low < high <= value.size() // 8:
            raise Ineligible('expression view: source byte range')
        return z3.Extract(high * 8 - 1, low * 8, value), defined

    def assemble(self, parts, width):
        _parts(parts, width, self.nodes, self.limits)
        value, definitions = z3.BitVecVal(0, width * 8), []
        for part in parts:
            self.edges += 1
            if self.edges > self.limits.edges:
                raise Ineligible('expression view: adapter edge limit')
            item, defined = self.part(part)
            value = value | (resize(item, width * 8) << (8 * part['at'][0]))
            definitions.append(defined)
        return value, z3.And(*definitions)

    def operand(self, operand):
        if operand.get('unresolved'):
            raise Ineligible('expression view: unresolved operand')
        return self.assemble(operand['parts'], operand['width'])

    def decision(self, key):
        if key not in self.decisions:
            row = self.control['decisions'][key]
            value, defined = self.operand(row['operand'])
            self.decisions[key] = value != 0, defined
        return self.decisions[key]

    def guard(self, reference):
        if reference in self.guards:
            return self.guards[reference]
        if len(self.guards) > self.limits.nodes:
            raise Ineligible('expression view: guard limit')
        item = self.control['nodes'][reference]
        if type(item) is bool:
            result = z3.BoolVal(item), z3.BoolVal(True)
        else:
            predicate, defined = self.decision(item['decision'])
            yes, yd = self.guard(item['true'])
            no, nd = self.guard(item['false'])
            result = z3.If(predicate, yes, no), z3.And(defined, z3.If(predicate, yd, nd))
        self.guards[reference] = result
        return result

    def node(self, identifier):
        step()
        if identifier in self.cache:
            return self.cache[identifier]
        if identifier in self.active:
            raise Ineligible('expression view: original cycle requires an existing one-visit namespace')
        if identifier not in self.selected or len(self.active) > self.limits.depth:
            raise Ineligible('expression view: producer or adapter depth limit')
        node = self.nodes[identifier]
        if node.get('debts') or node.get('interrupted') or node.get('override') is not None:
            raise Ineligible('expression view: original debt or override')
        width = _width(node)
        if not 0 < width <= self.limits.width_bytes:
            raise Ineligible('expression view: producer width limit')
        self.active.add(identifier)
        try:
            result = self._node(node, width)
            if 'execution_guard' in node:
                guard, gd = self.guard(node['execution_guard'])
                result = result[0], z3.And(result[1], gd, guard)
            self.cache[identifier] = result
            return result
        finally:
            self.active.remove(identifier)

    def _node(self, node, width):
        kind = node['kind']
        if kind == 'entry':
            key = 'n' + str(node['id'])
            symbol = z3.BitVec(key, width * 8)
            self.symbols[key] = symbol
            self.bindings[key] = dict(id=key, node=node['id'], width=width,
                                      transition_input=node.get('transition_input'))
            return symbol, z3.BoolVal(True)
        if kind == 'const':
            return z3.BitVecVal(node['value'], width * 8), z3.BoolVal(True)
        if kind in ('bound', 'assemble'):
            if node.get('gaps'):
                raise Ineligible('expression view: bound gaps')
            return self.assemble(node['parts'], width)
        if kind == 'phi':
            alternatives = [self.assemble([part], width) for part in node['alternatives']]
            if 'guarded_sources' in node:
                row = node['guarded_sources']
                reach, rd = self.guard(row['reach'])
                guards = [self.guard(ref) for ref in row['guards']]
                if len(guards) != len(alternatives) or not guards:
                    raise Ineligible('expression view: guarded source correspondence')
                choices = [g for g, _ in guards]
                defined = z3.And(rd, reach, *(d for _, d in guards),
                                 z3.PbEq([(g, 1) for g in choices], 1),
                                 *(z3.Implies(g, d) for g, (_, d) in zip(choices, alternatives)))
                value = z3.BitVecVal(0, width * 8)
                for guard, (arm, _) in zip(choices, alternatives):
                    value = z3.If(guard, arm, value)
                return value, defined
            if 'condition' not in node or node.get('choices') != [True, False] or len(alternatives) != 2:
                raise Ineligible('expression view: unordered phi is not a free selector')
            predicate, pd = self.operand(node['condition']['operand'])
            (yes, yd), (no, nd) = alternatives
            return z3.If(predicate != 0, yes, no), z3.And(pd, z3.If(predicate != 0, yd, nd))
        if kind != 'op':
            raise Ineligible('expression view: unsupported ' + kind)
        opcode = node['opcode']
        if opcode in ('LOAD', 'STORE'):
            if not self.memory:
                raise Ineligible('expression view: memory requires validated one-visit correspondence')
            address, ad = self.operand(next(row for row in node['operands'] if row['index'] == 1))
            if opcode == 'STORE':
                value, defined = self.operand(next(row for row in node['operands'] if row['index'] == 2))
            else:
                if len(node.get('memory', ())) != 1:
                    raise Ineligible('expression view: ambiguous memory')
                value, defined = self.assemble(node['memory'][0]['parts'], width)
            return resize(value, width * 8), z3.And(ad, defined)
        if node.get('value') == 0 and opcode in ('INT_XOR', 'INT_SUB', 'BOOL_XOR') and not node['operands']:
            return z3.BitVecVal(0, width * 8), z3.BoolVal(True)
        operands = [self.operand(row) for row in node['operands'] if row.get('role') != 'target']
        values = [value for value, _ in operands]
        return arithmetic(opcode, values, width * 8), z3.And(*(defined for _, defined in operands))

    def outputs(self, selection):
        values, domain = {}, []
        for row in selection['outputs']:
            value, defined = self.assemble(row['parts'], row['width'])
            guard, gd = self.guard(row['guard'])
            values[row['name']] = value
            domain.extend((defined, guard, gd))
        return values, z3.And(*domain)


def arithmetic(opcode, values, bits):
    """Pure existing p-code integer semantics, never physical-state transfer."""
    if not values:
        raise Ineligible('expression view: missing operation inputs')
    a, *rest = values
    b = rest[0] if rest else None
    unary = {'COPY': lambda: resize(a, bits), 'CAST': lambda: resize(a, bits),
             'INT_ZEXT': lambda: resize(a, bits), 'INT_SEXT': lambda: resize(a, bits, signed=True),
             'INT_NEGATE': lambda: ~resize(a, bits), 'INT_2COMP': lambda: -resize(a, bits),
             'BOOL_NEGATE': lambda: z3.If(a == 0, z3.BitVecVal(1, bits), z3.BitVecVal(0, bits)),
             'POPCOUNT': lambda: sum((resize(z3.Extract(i, i, a), bits) for i in range(a.size())),
                                    z3.BitVecVal(0, bits))}
    if opcode in unary and len(values) == 1:
        return unary[opcode]()
    if len(values) != 2:
        raise Ineligible('expression view: unsupported arity ' + opcode)
    if opcode == 'PIECE':
        return resize(z3.Concat(a, b), bits)
    if opcode == 'SUBPIECE':
        # Widen shift amount before multiplying by 8 (no accidental wrap).
        wide = max(a.size(), b.size() + 3)
        return resize(z3.LShR(resize(a, wide), resize(b, wide) * 8), bits)
    if opcode in ('INT_LEFT', 'INT_RIGHT', 'INT_SRIGHT'):
        wide = max(bits, a.size(), b.size())
        left = resize(a, wide, signed=opcode == 'INT_SRIGHT')
        shift = resize(b, wide)
        result = left << shift if opcode == 'INT_LEFT' else (
            left >> shift if opcode == 'INT_SRIGHT' else z3.LShR(left, shift))
        return resize(result, bits)
    if a.size() != b.size():
        raise Ineligible('expression view: incompatible integer widths')
    aa, bb = resize(a, bits), resize(b, bits)
    binary = {'INT_ADD': lambda: aa + bb, 'INT_SUB': lambda: aa - bb, 'INT_MULT': lambda: aa * bb,
              'INT_AND': lambda: a & b, 'INT_OR': lambda: a | b, 'INT_XOR': lambda: a ^ b}
    if opcode in binary:
        return resize(binary[opcode](), bits)
    comparisons = {'INT_EQUAL': lambda: a == b, 'INT_NOTEQUAL': lambda: a != b,
                   'INT_LESS': lambda: z3.ULT(a, b), 'INT_LESSEQUAL': lambda: z3.ULE(a, b),
                   'INT_SLESS': lambda: a < b, 'INT_SLESSEQUAL': lambda: a <= b,
                   'BOOL_AND': lambda: z3.And(a != 0, b != 0),
                   'BOOL_OR': lambda: z3.Or(a != 0, b != 0), 'BOOL_XOR': lambda: z3.Xor(a != 0, b != 0),
                   'INT_CARRY': lambda: z3.ULT(a + b, a),
                   'INT_SCARRY': lambda: z3.SignExt(1, a + b) != z3.SignExt(1, a) + z3.SignExt(1, b),
                   'INT_SBORROW': lambda: z3.SignExt(1, a - b) != z3.SignExt(1, a) - z3.SignExt(1, b)}
    if opcode not in comparisons:
        raise Ineligible('expression view: unsupported integer operation ' + opcode)
    return z3.If(comparisons[opcode](), z3.BitVecVal(1, bits), z3.BitVecVal(0, bits))


def simplify(value, *, limits, memo=None, depth=0):
    """A small candidate generator. Every result still needs SMT proof."""
    memo = {} if memo is None else memo
    step()
    if value.get_id() in memo:
        return memo[value.get_id()]
    if len(memo) >= limits.ast_nodes or depth > limits.ast_depth:
        raise Ineligible('expression view: simplifier AST limit')
    original = value
    def strip(item):
        while True:
            if item.decl().kind() == z3.Z3_OP_EXTRACT and item.params() == [item.arg(0).size() - 1, 0]:
                item = item.arg(0)
            elif item.decl().kind() == z3.Z3_OP_BOR and any(z3.is_bv_value(c) and c.as_long() == 0 for c in item.children()):
                item = next((c for c in item.children() if not z3.is_bv_value(c) or c.as_long() != 0), item.arg(0))
            elif item.decl().kind() == z3.Z3_OP_BSHL and z3.is_bv_value(item.arg(1)) and item.arg(1).as_long() == 0:
                item = item.arg(0)
            else:
                return item
    value = strip(value)
    children = [strip(child) for child in value.children()]
    rebuilt = value
    # MBA: (x XOR y) + 2*(x AND y) == x+y modulo the exact bit width.
    if rebuilt.decl().kind() == z3.Z3_OP_BADD and len(children) == 2:
        for xor, twice in (children, children[::-1]):
            if xor.decl().kind() != z3.Z3_OP_BXOR or xor.num_args() != 2:
                continue
            term = None
            if twice.decl().kind() == z3.Z3_OP_BMUL:
                term = next((strip(twice.arg(1 - i)) for i in (0, 1)
                             if z3.is_bv_value(strip(twice.arg(i))) and strip(twice.arg(i)).as_long() == 2), None)
            elif twice.decl().kind() == z3.Z3_OP_BSHL and z3.is_bv_value(strip(twice.arg(1))) and strip(twice.arg(1)).as_long() == 1:
                term = strip(twice.arg(0))
            if term is not None and term.decl().kind() == z3.Z3_OP_BAND and term.num_args() == 2:
                x, y = (strip(item) for item in xor.children())
                ta, tb = (strip(item) for item in term.children())
                if (z3.eq(x, ta) and z3.eq(y, tb)) or (z3.eq(x, tb) and z3.eq(y, ta)):
                    rebuilt = x + y
    children = [simplify(child, limits=limits, memo=memo, depth=depth + 1) for child in rebuilt.children()]
    result = z3.simplify(rebuilt.decl()(*children) if children else rebuilt)
    if len(memo) >= limits.ast_nodes:
        raise Ineligible('expression view: simplifier AST limit')
    memo[original.get_id()] = result
    return result


def _sort(value):
    return 0 if z3.is_bool(value) else value.size()


def encode(outputs, symbols, limits):
    """Typed, shared DAG; no arbitrary SMT text or new SSA identities."""
    nodes, memo = [], {}
    inputs = {symbol.get_id(): key for key, symbol in symbols.items()}

    def emit(value, depth=0):
        step()
        if value.get_id() in memo:
            return memo[value.get_id()]
        if depth > limits.depth or len(nodes) >= limits.nodes:
            raise Ineligible('expression view: derived DAG limit')
        if value.get_id() in inputs:
            row = dict(kind='input', binding=inputs[value.get_id()])
        elif z3.is_bv_value(value):
            row = dict(kind='literal', value=str(value.as_long()))
        elif z3.is_true(value) or z3.is_false(value):
            row = dict(kind='literal', value=z3.is_true(value))
        else:
            row = dict(kind='op', op=str(value.decl().name()), parameters=list(value.params()),
                       args=[emit(child, depth + 1) for child in value.children()])
        row.update(id=len(nodes), bits=_sort(value))
        nodes.append(row)
        memo[value.get_id()] = row['id']
        return row['id']
    roots = {name: emit(value) for name, value in outputs.items()}
    return dict(nodes=nodes, outputs=roots)


def decode(graph, symbols, limits):
    nodes, depth, edges = [], [], 0
    if not isinstance(graph, dict) or not isinstance(graph.get('nodes'), list) or len(graph['nodes']) > limits.nodes:
        raise Ineligible('expression view: candidate node limit')
    operations = {'bvadd': lambda a, b: a + b, 'bvsub': lambda a, b: a - b,
                  'bvmul': lambda a, b: a * b, 'bvand': lambda a, b: a & b,
                  'bvor': lambda a, b: a | b, 'bvxor': lambda a, b: a ^ b,
                  'bvnot': lambda a: ~a, 'bvneg': lambda a: -a,
                  'bvshl': lambda a, b: a << b, 'bvlshr': z3.LShR, 'bvashr': lambda a, b: a >> b,
                  '=': lambda a, b: a == b, 'distinct': lambda a, b: a != b,
                  'bvult': z3.ULT, 'bvule': z3.ULE, 'bvugt': z3.UGT, 'bvuge': z3.UGE,
                  'bvslt': lambda a, b: a < b, 'bvsle': lambda a, b: a <= b,
                  'bvsgt': lambda a, b: a > b, 'bvsge': lambda a, b: a >= b,
                  'if': z3.If, 'and': z3.And, 'or': z3.Or, 'not': z3.Not, 'xor': z3.Xor,
                  '=>': z3.Implies, 'concat': z3.Concat}
    for number, row in enumerate(graph['nodes']):
        step()
        bits = row['bits']
        if row['id'] != number or type(bits) is not int or not 0 <= bits <= limits.width_bytes * 8:
            raise Ineligible('expression view: candidate sort or ID')
        refs = row.get('args', [])
        if not isinstance(refs, list) or any(type(ref) is not int or not 0 <= ref < number for ref in refs):
            raise Ineligible('expression view: candidate DAG reference')
        level = 1 + max((depth[ref] for ref in refs), default=0)
        edges += len(refs)
        if level > limits.depth or edges > limits.edges:
            raise Ineligible('expression view: candidate edge/depth limit')
        if row['kind'] == 'input':
            value = symbols[row['binding']]
        elif row['kind'] == 'literal':
            raw = row['value']
            if bits == 0:
                if type(raw) is not bool:
                    raise Ineligible('expression view: candidate Boolean literal')
                value = z3.BoolVal(raw)
            else:
                if not isinstance(raw, str) or len(raw) > limits.width_bytes * 3 or not raw.isdecimal():
                    raise Ineligible('expression view: candidate bit-vector literal')
                integer = int(raw)
                if integer >= 1 << bits:
                    raise Ineligible('expression view: candidate literal overflow')
                value = z3.BitVecVal(integer, bits)
        elif row['kind'] == 'op':
            args = [nodes[ref] for ref in refs]
            params = row['parameters']
            if not isinstance(params, list) or any(type(p) is not int or not 0 <= p <= limits.width_bytes * 8 for p in params):
                raise Ineligible('expression view: candidate parameters')
            if row['op'] == 'extract' and len(params) == 2 and len(args) == 1:
                value = z3.Extract(*params, args[0])
            elif row['op'] in ('zero_extend', 'sign_extend') and len(params) == 1 and len(args) == 1:
                value = (z3.ZeroExt if row['op'] == 'zero_extend' else z3.SignExt)(params[0], args[0])
            elif not params and row['op'] in operations:
                if row['op'] in ('bvadd', 'bvmul', 'bvand', 'bvor', 'bvxor') and len(args) >= 2:
                    value = reduce(operations[row['op']], args)
                else:
                    value = operations[row['op']](*args)
            else:
                raise Ineligible('expression view: unsupported candidate operator')
        else:
            raise Ineligible('expression view: candidate kind')
        if _sort(value) != bits:
            raise Ineligible('expression view: candidate sort mismatch')
        nodes.append(value)
        depth.append(level)
    if not isinstance(graph.get('outputs'), dict) or not graph['outputs']:
        raise Ineligible('expression view: candidate outputs')
    if any(type(ref) is not int or not 0 <= ref < len(nodes) for ref in graph['outputs'].values()):
        raise Ineligible('expression view: candidate output reference')
    return {name: nodes[ref] for name, ref in graph['outputs'].items()}
