"""Diagnostic address equations of issued weak loop relations.

No numeric evaluation, debt suppression or read-from authorization uses
this annotation. Original LOAD/STORE operands remain the value expression.
"""


def annotate(builder, record):
    from .operation_records import _span_dict

    memory = builder.normalized.memory_graph
    binding = None if memory is None else memory.loop_memory
    if binding is None:
        return
    index = getattr(builder, "_loop_address_index", None)
    if index is None:
        from .resource_limits import step

        step(len(binding.plan.accesses))
        index = builder._loop_address_index = {access.operation_key: access for access in binding.plan.accesses}
    access = index.get(record["key"])
    if access is None:
        return
    family = binding.plan.families[access.family_index]
    base = family.invariant_base
    record["loop_address"] = dict(
        family=builder.graph.node(binding.family_nodes[access.family_index]).key,
        header=family.header, induction=_span_dict(family.span), stride=family.stride,
        offset=access.offset, address_bits=family.address_bits,
        address_definition=builder._definition_ref(access.address_definition_id),
        invariant_base=None if base is None else dict(
            span=_span_dict(base.span), definition=builder._definition_ref(base.definition_id),
            operation=builder.ssa.definitions[base.definition_id].operation_key),
        equation=("S(k) + offset (mod 2^address_bits)" if base is None
                  else "invariant_base + S(k) + offset (mod 2^address_bits)"),
        weak=True, original_memory_debt_retained=True)
