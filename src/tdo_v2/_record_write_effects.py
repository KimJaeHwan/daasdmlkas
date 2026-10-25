"""Closed STORE-only projection. It never resolves or removes RAM debts.

Scalar byte correspondence reuses v12. Unknown destinations are retained as
the ORIGINAL ordered STORE effect, not invented concrete RAM definitions.
"""

from .operation_records import Ineligible
from .resource_limits import step


SCOPE = 'terminal_scalar_cut_state_and_original_STORE_effect_not_resolved_RAM'


def policy(graph, region):
    from ._record_transitions import _Partial

    def require(value, reason):
        if not value:
            raise _Partial('STORE-only projection: ' + reason)

    members = set(region['blocks'])
    operations = [row for row in graph['operations'] if row['block'] in members]
    require(operations, 'missing operations')
    stores = [row for row in operations if row['opcode'] == 'STORE']
    require(len(stores) == 1, 'requires exactly one STORE')
    for row in operations:
        step()
        require(row['opcode'] not in ('LOAD', 'CALL', 'CALLIND', 'CALLOTHER'), 'LOAD or call remains unsupported')
        values = row['inputs'][1:] if row['opcode'] in ('BRANCH', 'CBRANCH') else row['inputs']
        require(not any(value['kind'] == 'address' for value in values)
                and (row['output'] is None or row['output']['kind'] != 'address'), 'direct memory action')
    store, = stores
    require(len(store['inputs']) == 3 and store['output'] is None, 'STORE shape')
    pointer = store['inputs'][1]
    require(pointer['kind'] in ('register', 'unique'), 'STORE pointer is not a scalar read')
    keys = {row['key'] for row in operations}
    occurrences = [row for row in graph['unresolved_accesses'] if row['operation'] in keys]
    require(len(occurrences) == 1, 'unmatched unresolved occurrence')
    occurrence, = occurrences
    raw = occurrence['raw_address']
    action = occurrence['action_id']
    require(type(action) is int and 0 <= action < len(graph['writes'])
            and graph['writes'][action]['operation'] == store['key'], 'original STORE action identity')
    require(occurrence['operation'] == store['key'] and occurrence['kind'] == 'write'
            and occurrence['node'] == store['node'] and occurrence['occurrence_ordinal'] == 0
            and occurrence['width'] == store['inputs'][2]['size']
            and raw['kind'] == 'raw' and raw['storage_kind'] == pointer['kind']
            and raw['space_id'] == pointer['space'] and raw['offset'] == pointer['offset']
            and raw['size'] == pointer['size'], 'original STORE occurrence mismatch')
    address = occurrence['address']
    kind = {'register': 'register_file', 'unique': 'function_unique'}[pointer['kind']]
    pointer_reads = [row for row in graph['reads'] if row['operation'] == store['key'] and row['read_ordinal'] == 0
                     and row['span'][1] == kind and int(row['span'][-2], 16) == pointer['offset']
                     and int(row['span'][-1], 16) == pointer['size']]
    require(address['kind'] == 'resolved' and len(pointer_reads) == 1
            and address['span'] == pointer_reads[0]['span'], 'original STORE address read identity')
    reads = [row for row in graph['reads'] if row['operation'] in keys]
    require(all(row['span'][1] in ('register_file', 'function_unique') for row in reads), 'RAM read debt')
    return dict(kind='one_original_unresolved_STORE_no_RAM_reads_v1',
                occurrences=occurrences, output_scope=SCOPE)


def publish(original, graph, index):
    from ._record_transitions import _build, _Partial
    from ._record_conditions import _UnsupportedGuard
    from .operation_records import _Truncated

    rows = []
    for region in graph['cycle_hierarchy']:
        keys = {row['key'] for row in graph['operations'] if row['block'] in set(region['blocks'])
                and row['opcode'] == 'STORE'}
        if not any(row['operation'] in keys for row in graph['unresolved_accesses']):
            continue
        row = dict(id=graph['id'] + '/write-visit/' + str(region['id']), region=region['id'], complete=False)
        try:
            if not graph['coverage']['expression_complete']:
                raise _Partial('original expression projection is incomplete')
            row.update(_build(original, graph, index, region, write_projection=policy(graph, region)))
        except (_Partial, _UnsupportedGuard, _Truncated, RecursionError) as error:
            row['reason'] = str(error) or 'STORE projection limit'
        rows.append(row)
    return rows


def seal(record):
    from ._record_transition_contract import _digest, _authority

    rows = [row for row in record.get('write_effect_transitions', ()) if row['complete']]
    source = _digest(_authority(record)) if rows else None
    record['write_effect_contracts'] = {row['id']: dict(source=source, derived=_digest(row)) for row in rows}


def validate(record, view):
    from ._record_transition_contract import _validate
    from ._record_transitions import _Partial

    try:
        graph = record['cycle_graph']
        canonical = policy(graph, graph['cycle_hierarchy'][view['region']])
        if view['write_projection'] != canonical or view['id'] != graph['id'] + '/write-visit/' + str(view['region']):
            raise Ineligible('STORE-only contract: projection mismatch')
        if any(row['span'][1] not in ('register_file', 'function_unique')
               for row in [*view['inputs'], *view['proofs']]):
            raise Ineligible('STORE-only contract: fabricated RAM state')
        _validate(record, view, write_projection=canonical)
    except (_Partial, KeyError, TypeError, ValueError, IndexError, StopIteration) as error:
        raise Ineligible('STORE-only contract: malformed correspondence: ' + str(error)) from error
