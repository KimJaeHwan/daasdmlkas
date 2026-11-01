"""Expression ports for graph-owned read sources, never another alias solve.

The common view decides which ORIGINAL debt nodes are inactive. This module
only expresses its original SSA byte ports and conditional image alternatives.
"""


def _part(builder, identifier, span, offset, width, depth):
    source = builder.index.definition_node[identifier]
    definition = builder.ssa.definitions[identifier]
    produced, base, loop = builder._definition_guarded(source, depth + 1)
    start = base + span.start - definition.span.start
    result = builder._named(dict(node=produced, bytes=[start, start + width], at=[offset, offset + width]), definition)
    if loop:
        result["loop"] = True
    builder._edge()
    return result


def _constant(builder, value, size, offset=0, width=None):
    width = size if width is None else width
    key = "const", value, size
    identifier = builder.id_of.get(key)
    if identifier is None:
        identifier = builder._new(key, dict(kind="const", value=value, size=size))["id"]
    builder._edge()
    return dict(node=identifier, bytes=[offset, offset + width], at=[0, width])


def local_parts(builder, source, depth):
    """Original STORE value byte ports, not the whole STORE/address inputs."""
    parts = []
    for row in source.local.parts:
        if row.constant is not None:
            _, value, size = row.constant
            part = _constant(builder, value, size, row.value_offset, row.width)
            part["at"] = [row.output_offset, row.output_offset + row.width]
        else:
            part = _part(builder, row.source_definition_id, row.source_span,
                         row.output_offset, row.width, depth)
        parts.append(part)
    return parts


def annotate(builder, record, source, depth):
    """Attach an explicit conditional table; return True for an image read."""
    if source.local is not None:
        record["local_read"] = dict(operation=record["key"], writer=source.local.writer,
                                    corridor=list(source.local.corridor), output_width=source.output_span.size)
        if any(part.writer is not None for part in source.local.parts):
            record["local_read"]["writers"] = [dict(operation=part.writer or source.local.writer,
                value_offset=part.value_offset, output_offset=part.output_offset, width=part.width)
                for part in source.local.parts]
        return False
    row = source.image
    if row is None:
        return False
    selector = _part(builder, row.selector_definition_id, row.selector_span, 0, row.selector_span.size, depth)
    guard_node = builder.graph.node_for_key("op:" + row.guard)
    action = builder.index.action_of.get(guard_node)
    found = None if action is None else builder.index.operation(action)
    predicate = dict(width=1, parts=[], unresolved=True)
    success_when = None
    if found is not None:
        operation, spans, _ = found
        before = builder.building_condition
        builder.building_condition = True
        try:
            predicate = next(operand for operand in builder._operands(guard_node, action, operation, spans, depth + 1)
                             if operand["index"] == 1)
        finally:
            builder.building_condition = before
        conditions = builder._condition_index()
        block = conditions.blocks.get(row.success_edge[0])
        if block is not None:
            yes, no = conditions._target(block, operation), conditions._fallthrough(block)
            if row.success_edge[1] in (yes, no) and yes != no:
                success_when = row.success_edge[1] == yes
    record["image_read"] = dict(
        selection=builder._selection(f"image-selector:{row.selector_definition_id}:{row.selector_span.start}:{row.selector_span.size}"),
        guard=row.guard, success_edge=list(row.success_edge), output_width=row.output_span.size,
        selector_definition=builder._definition_ref(row.selector_definition_id),
        address_definition=builder._definition_ref(row.address_definition_id), reloads=list(row.reloads),
        selector=dict(width=row.selector_span.size, parts=[selector]),
        condition=dict(operation=row.guard, success_when=success_when, operand=predicate),
        candidates=[dict(selector=candidate.selector, value=candidate.value,
                         address=dict(space=candidate.span.object_id.space_key, start=candidate.span.start,
                                      size=candidate.span.size),
                         parts=[_constant(builder, candidate.value, row.output_span.size)])
                    for candidate in row.candidates],
        requires=["readonly-image-data-is-constant"],
    )
    return True


def parts(node):
    """Both selector and original predicate are required value evidence."""
    image = node.get("image_read")
    if not isinstance(image, dict):
        return
    selector, condition = image.get("selector"), image.get("condition")
    operands = [selector, condition.get("operand") if isinstance(condition, dict) else None]
    candidates = image.get("candidates")
    if isinstance(candidates, list):
        operands.extend(candidate for candidate in candidates if isinstance(candidate, dict))
    for operand in operands:
        byte_parts = operand.get("parts") if isinstance(operand, dict) else None
        if isinstance(byte_parts, list):
            yield from (part for part in byte_parts if isinstance(part, dict))


def _operand_valid(operand, nodes):
    if not isinstance(operand, dict) or operand.get("unresolved") \
            or type(operand.get("width")) is not int or operand["width"] <= 0 \
            or type(operand.get("parts")) is not list or not operand["parts"]:
        return False
    cursor = 0
    for part in operand["parts"]:
        if not isinstance(part, dict) or part.get("node") not in nodes or part.get("pruned"):
            return False
        source, target = part.get("bytes"), part.get("at")
        if type(source) is not list or type(target) is not list or len(source) != 2 or len(target) != 2 \
                or any(type(value) is not int for value in (*source, *target)) \
                or source[0] < 0 or source[1] <= source[0] or target[0] != cursor \
                or target[1] - target[0] != source[1] - source[0]:
            return False
        cursor = target[1]
    return cursor == operand["width"]


def validate(node, nodes):
    """Serialized annotation consistency, not a new semantic proof issuer."""
    from .forward import MAX_CANDIDATES

    image = node.get("image_read")
    if not isinstance(image, dict) or node.get("opcode") != "LOAD":
        return "guarded image annotation"
    width = image.get("output_width")
    selector, condition = image.get("selector"), image.get("condition")
    if not isinstance(selector, dict) or not isinstance(condition, dict):
        return "guarded image annotation"
    sw = selector.get("width")
    candidates = image.get("candidates")
    success = image.get("success_edge")
    if type(width) is not int or width <= 0 or node.get("output", {}).get("size") != width \
            or type(sw) is not int or not 0 < sw <= 32 or not _operand_valid(selector, nodes) \
            or not isinstance(image.get("selection"), str) \
            or not image["selection"] or type(condition.get("success_when")) is not bool \
            or condition.get("operation") != image.get("guard") \
            or not isinstance(image.get("guard"), str) or not image["guard"].endswith(":CBRANCH") \
            or not isinstance(success, list) or len(success) != 2 or any(type(key) is not str for key in success) \
            or not _operand_valid(condition.get("operand"), nodes) \
            or type(candidates) is not list or not 0 < len(candidates) <= MAX_CANDIDATES \
            or image.get("requires") != ["readonly-image-data-is-constant"]:
        return "guarded image annotation"
    seen = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            return "guarded image candidate"
        number, value, address = candidate.get("selector"), candidate.get("value"), candidate.get("address", {})
        byte_parts = candidate.get("parts", ())
        if type(number) is not int or not 0 <= number < 1 << (sw * 8) \
                or type(value) is not int or not 0 <= value < 1 << (width * 8) \
                or not isinstance(address, dict) or address.get("size") != width \
                or type(address.get("space")) is not int or type(address.get("start")) is not int \
                or address["start"] < 0 or type(byte_parts) is not list or len(byte_parts) != 1 \
                or not isinstance(byte_parts[0], dict):
            return "guarded image candidate"
        part = byte_parts[0]
        constant = nodes.get(part.get("node"), {})
        if constant.get("kind") != "const" or constant.get("value") != value or constant.get("size") != width \
                or part.get("bytes") != [0, width] or part.get("at") != [0, width] \
                or part.get("loop") or part.get("pruned"):
            return "guarded image candidate"
        seen.append(number)
    if sorted(set(seen)) != seen:
        return "guarded image selector domain"
    return None


def bind_choices(checked, nodes, choice_keys):
    """One unknown selector value shared by all of its table consumers."""
    from .operation_records import Ineligible

    domains = {}
    for node in checked:
        if "image_read" not in node:
            continue
        reason = validate(node, nodes)
        if reason:
            raise Ineligible(reason)
        image = node["image_read"]
        key = "image", image["selection"]
        ports = tuple((part.get("node"), tuple(part.get("bytes", ())), tuple(part.get("at", ())))
                      for part in image["selector"]["parts"])
        domain = image["selector"]["width"], tuple(candidate["selector"] for candidate in image["candidates"]), ports
        if key in domains and domains[key] != domain:
            raise Ineligible("guarded image selector correspondence")
        domains[key] = domain
        choice_keys[node["id"]] = key


def evaluate(evaluator, identifier, node):
    """Select with the actual selector/guard, or a shared conditional union."""
    from .operation_records import Ineligible, _Infeasible, _NeedChoice, _Unknown

    image = node["image_read"]
    condition = image["condition"]
    try:
        predicate = evaluator.operand(condition["operand"])
    except _Unknown:
        predicate = None
    if predicate is not None and bool(predicate) != condition["success_when"]:
        raise _Infeasible()
    try:
        selected = evaluator.operand(image["selector"])
    except _Unknown:
        selected = None
    candidates = image["candidates"]
    key = evaluator.choice_keys.get(identifier)
    if key is None:
        raise Ineligible("guarded image selection missing")
    if selected is None:
        if key not in evaluator.assignment:
            raise _NeedChoice(key, len(candidates))
        choice = evaluator.assignment[key]
    else:
        choices = [i for i, candidate in enumerate(candidates) if candidate["selector"] == selected]
        if not choices:
            raise _Infeasible()
        choice, = choices
        if key in evaluator.assignment and evaluator.assignment[key] != choice:
            raise _Infeasible()
    candidate = candidates[choice]
    return evaluator.operand(dict(width=image["output_width"], parts=candidate["parts"]))
