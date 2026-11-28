"""Bounded Arm decode constraints for the audited instruction families."""

from dataclasses import dataclass
import re
from xml.etree import ElementTree

from arm64_encoding_index import ARM_A64_REFERENCE, _cells, pinned_archive


RULE = "arm-a64-constrained-operands-1"
_BIT_FILES = frozenset("""
    axflag cfinv ldar ldarb ldaxp ldaxr ldaxrb ldaxrh ldlar ldlarb ldlarh
    ldxp ldxr ldxrb ldxrh sb smulh stllr stllrb stllrh stlr stlrb stlrh
    stlxr stlxrb stlxrh stxr stxrb stxrh umulh xaflag
""".split())
_OPERAND_FILES = frozenset("""
    ldap_gen ldapp_gen ldapr ldaxp ldclrp ldiapp ldnp_fpsimd ldnp_gen
    ldp_fpsimd ldp_gen ldra ldsetp ldtnp_fpsimd ldtnp_gen ldtp_fpsimd
    ldtp_gen ldxp rcwclrp rcwsclrp rcwsetp rcwssetp rcwsswpp rcwswpp
    stilp stlr stltxr stlxp stlxr stlxrb stlxrh stp_gen sttp_gen sttxr
    stxp stxr stxrb stxrh swpp
""".split())
_CLAUSE = re.compile(
    r"^if ([^\n;]+) then\s+let c : Constraint = ConstrainUnpredictable\((Unpredictable_\w+)\);"
    r"\s+assert c IN \{([^}]+)\};", re.M,
)
_WRITEBACK = re.compile(r"^(?:let|var) wback : boolean = ([^;]+);", re.M)
_ROLE = re.compile(r"^let (t2?|n|s) : integer(?:\{\})? = UInt\((R\w+)\);", re.M)
_EXPECTED_CHOICES = {
    "Unpredictable_LDPOVERLAP": ("UNKNOWN", "UNDEF", "NOP"),
    "Unpredictable_LSE128OVERLAP": ("UNKNOWN", "UNDEF", "NOP"),
    "Unpredictable_DATAOVERLAP": ("UNKNOWN", "UNDEF", "NOP"),
    "Unpredictable_BASEOVERLAP": ("UNKNOWN", "UNDEF", "NOP"),
    "Unpredictable_WBOVERLAPLD": ("WBSUPPRESS", "UNKNOWN", "UNDEF", "NOP"),
    "Unpredictable_WBOVERLAPST": ("NONE", "UNKNOWN", "UNDEF", "NOP"),
}
_GUARDS = {
    "t == t2": lambda v: v["t"] == v["t2"],
    "s == t": lambda v: v["s"] == v["t"],
    "s == t || (s == t2)": lambda v: v["s"] in (v["t"], v["t2"]),
    "s == n && n != 31": lambda v: v["s"] == v["n"] != 31,
    "n == t && n != 31": lambda v: v["n"] == v["t"] and v["n"] != 31,
    "wback && n == t && n != 31": lambda v: v["wback"] and v["n"] == v["t"] and v["n"] != 31,
    "wback && (t == n || t2 == n) && n != 31": lambda v: (
        v["wback"] and v["n"] in (v["t"], v["t2"]) and v["n"] != 31
    ),
}


@dataclass(frozen=True, slots=True)
class _ClauseRule:
    name: str
    stage: str
    guard: str
    choices: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Form:
    bits: tuple[tuple[str | None, int, int], ...]
    fields: dict
    roles: dict
    writeback: str | None
    clauses: tuple[_ClauseRule, ...]
    simd: bool


def _snippets(node, stage):
    return "\n".join("".join(p.itertext()) for p in node.findall(".//pstext") if p.get("section") == stage)


def _fixed_bits(diagram):
    for box in diagram:
        for top, width, text in _cells((box,)):
            match = re.fullmatch(r"\(([01]+)\)", (text or "").strip())
            if match:
                if len(match[1]) != width:
                    raise ValueError("Arm parenthesized bit field has the wrong width")
                for offset, bit in enumerate(match[1]):
                    yield box.get("name"), top - offset, int(bit)


def _operand_rules(decode, postdecode):
    code = decode + "\n" + postdecode
    roles = dict(_ROLE.findall(code))
    writeback = _WRITEBACK.search(code)
    writeback = writeback[1] if writeback else None
    if writeback not in (None, "TRUE", "FALSE", "W == '1'", "opc2[0] == '0'"):
        raise ValueError("unsupported Arm writeback selector")
    clauses = []
    for stage, text in (("Decode", decode), ("Postdecode", postdecode)):
        matches = _CLAUSE.findall(text)
        if text.count("ConstrainUnpredictable(") != len(matches):
            raise ValueError("unsupported Arm constraint clause")
        for guard, name, values in matches:
            choices = tuple(choice.strip().removeprefix("Constraint_") for choice in values.split(","))
            if guard not in _GUARDS or choices != _EXPECTED_CHOICES.get(name):
                raise ValueError(f"unsupported Arm guard or choices for {name}")
            clauses.append(_ClauseRule(name, stage, guard, choices))
    return roles, writeback, tuple(clauses)


def load_constraints(archive_path):
    """Load only the diagrams and ordered operand rules audited for this profile."""
    forms = {}
    expected = _BIT_FILES | _OPERAND_FILES
    seen = set()
    with pinned_archive(archive_path) as archive:
        for member in archive:
            prefix, _, file = member.name.partition("/")
            name = file.removesuffix(".xml")
            if prefix != ARM_A64_REFERENCE or file != name + ".xml" or name not in expected or not member.isfile():
                continue
            seen.add(name)
            with archive.extractfile(member) as content:
                root = ElementTree.parse(content).getroot()
            postdecode = _snippets(root, "Postdecode")
            for cls in root.findall("./classes/iclass"):
                diagram = cls.findall("./regdiagram/box")
                fields = {box.attrib["name"]: (int(box.attrib["hibit"]), int(box.get("width", "1")))
                          for box in diagram if "name" in box.attrib}
                # Operand families may have their own prescribed bits before the guard.
                bits = tuple(_fixed_bits(diagram))
                roles, writeback, clauses = ({}, None, ())
                if name in _OPERAND_FILES:
                    roles, writeback, clauses = _operand_rules(_snippets(cls, "Decode"), postdecode)
                for encoding in cls.findall("./encoding"):
                    overrides = encoding.findall("./box") + encoding.findall("./regdiagram/box")
                    overridden = {top - offset for top, width, _ in _cells(overrides) for offset in range(width)}
                    fixed = tuple(bit for bit in bits if bit[1] not in overridden)
                    fixed += tuple(_fixed_bits(overrides))
                    if fixed or clauses:
                        forms[file, encoding.attrib["name"]] = _Form(fixed, fields, roles, writeback, clauses,
                                                                    name.endswith("_fpsimd"))
    if seen != expected:
        raise ValueError("pinned Arm archive lacks a constrained instruction definition")
    return forms


def _field(word, bounds):
    top, width = bounds
    return word >> (top + 1 - width) & ((1 << width) - 1)


def _operand_values(form, word):
    values = {role: _field(word, form.fields[name]) for role, name in form.roles.items()}
    if form.writeback == "W == '1'":
        values["wback"] = bool(_field(word, form.fields["W"]))
    elif form.writeback == "opc2[0] == '0'":
        values["wback"] = _field(word, form.fields["opc2"]) & 1 == 0
    elif form.writeback is not None:
        values["wback"] = form.writeback == "TRUE"
    return values


def _register(form, role, selector):
    kind = "simd" if form.simd and role in ("t", "t2") else "gpr"
    state = "register"
    if selector == 31 and kind == "gpr":
        state = "sp" if role == "n" else "zero-register"
    return dict(field=form.roles[role], selector=selector, bank=kind, kind=state)


def _operand_choices(clause, form, values):
    data = ("t", "t2") if "t2" in values else ("t",)
    if clause.name == "Unpredictable_LDPOVERLAP":
        role, targets = "loaded-destination-data", data
    elif clause.name == "Unpredictable_LSE128OVERLAP":
        role, targets = "atomic-return-data", data
    elif clause.name == "Unpredictable_DATAOVERLAP":
        role, targets = "store-data", data
    elif clause.name == "Unpredictable_BASEOVERLAP":
        role, targets = "access-address", ("n",)
    elif clause.name == "Unpredictable_WBOVERLAPLD":
        role, targets = "writeback-value", ("n",)
    else:
        role = "store-data"
        targets = tuple(register for register in data if values[register] == values["n"])
    affected = [_register(form, target, values[target]) for target in targets]
    choices = []
    for option in clause.choices:
        if option == "UNDEF":
            choices.append(dict(kind="UNDEFINED", continues=False))
        elif option == "NOP":
            choices.append(dict(kind="NOP", continues=False))
        elif option == "WBSUPPRESS":
            choices.append(dict(kind="suppress-writeback", continues=True, scope="writeback", operands=affected))
        elif option == "NONE":
            choices.append(dict(kind="use-pre-writeback-data", continues=True, scope=role, operands=affected))
        else:
            unknown = dict(kind="UNKNOWN", continues=True, scope=role, operands=affected)
            if role in ("loaded-destination-data", "atomic-return-data"):
                unknown["operands"] = [operand for operand in affected if operand["kind"] != "zero-register"]
            choices.append(unknown)
    return choices


def constrained_encoding(word, index, reference, forms):
    """Describe scoped choices when the Arm rules accept a constrained decode path."""
    if len(index["candidates"]) != 1 or index.get("exclusions"):
        return None
    encoding, = index["candidates"]
    form = forms.get((encoding["file"], encoding["id"]))
    if form is None:
        return None
    clauses = []
    violations = []
    prescribed = word
    for field, bit, required in form.bits:
        actual = word >> bit & 1
        if actual != required:
            violations.append(dict(field=field, bit=bit, actual=actual, prescribed=required))
            prescribed = (prescribed & ~(1 << bit)) | (required << bit)
    if violations:
        clauses.append(dict(rule="Arm-DDI0487-C2.2.2", stage="encoding", requires="instruction-decode",
                            bits=violations, choices=[
                                dict(kind="UNDEFINED", continues=False),
                                dict(kind="NOP", continues=False),
                                dict(kind="execute-with-prescribed-bits", continues=True,
                                     word_le=prescribed.to_bytes(4, "little").hex()),
                                dict(kind="UNKNOWN", continues=None, scope="destination-registers"),
                            ]))
    if form.clauses and (not violations or reference.candidates(prescribed) == index):
        values = _operand_values(form, prescribed)
        requires = "execute-with-prescribed-bits" if violations else "instruction-decode"
        for rule in form.clauses:
            if _GUARDS[rule.guard](values):
                inputs = {name: _register(form, name, values[name])
                          for name in re.findall(r"\b(?:t2?|n|s)\b", rule.guard)}
                if "wback" in rule.guard:
                    inputs["wback"] = values["wback"]
                clauses.append(dict(rule=rule.name, stage=rule.stage, requires=requires, guard=rule.guard,
                                    inputs=inputs, choices=_operand_choices(rule, form, values)))
                requires = "prior-choice-continues"
    if clauses:
        return dict(kind="constrained-unpredictable-encoding", verdict="CONSTRAINED_UNPREDICTABLE", rule=RULE,
                    encoding=encoding, selected_outcome="unobserved", clauses=clauses)
    return None
