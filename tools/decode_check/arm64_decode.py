"""Independent LLVM decode diagnostics for admitted A64 snapshot words."""

from collections import Counter, defaultdict
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import struct
import subprocess

from arm64_facts import Arm64Facts, FLOAT_COMPARE_FORMS, INTEGER_COMPARE_OP, SELECT_FALSE_OP, TRAPS
import common_facts as cf


RULE = "aarch64-llvm-decode-1"
LLVM_OPTIONS = (
    "--disassemble", "--disassemble-zeroes",
    "--disassembler-options=no-aliases",
    "--mattr=+v8.5a,+fullfp16,+pauth,+bti,+lse",
)
BATCH_WORDS = 4096
SECTION = re.compile(r"^Disassembly of section (\.text[0-9]+):$")
INSTRUCTION = re.compile(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{8}|(?:[0-9a-fA-F]{2}[ \t]+){3}[0-9a-fA-F]{2})\s+(\S+)(?:\s+(.*))?$")
PC_LINE = re.compile(r"^\s*[0-9a-fA-F]+:")
REGISTER = re.compile(r"(?:[wx](?:[0-9]|[12][0-9]|30|zr)|[hsd](?:[0-9]|[12][0-9]|3[01])|w?sp)")
CONDITIONS = frozenset("eq ne cs cc mi pl vs vc hi ls ge lt gt le al nv".split())
# Normalize LLVM's no-alias HINT printing using the decoded immediate.
HINT_FORMS = {
    0: "nop", 7: "xpaclri", 8: "pacia1716", 10: "pacib1716", 12: "autia1716", 14: "autib1716",
    24: "paciaz", 25: "paciasp", 26: "pacibz", 27: "pacibsp",
    28: "autiaz", 29: "autiasp", 30: "autibz", 31: "autibsp",
    32: "bti", 34: "bti_c", 36: "bti_j", 38: "bti_jc",
}
DIRECT = {"b", "bl", "b.cond", "cbz", "cbnz", "tbz", "tbnz"}
REGISTER_BRANCH = {"br", "blr", "ret", "braa", "brab", "braaz", "brabz",
                   "blraa", "blrab", "blraaz", "blrabz"}
EXPLICIT_MODIFIER = {"braa", "brab", "blraa", "blrab"}


class ObserverError(ValueError):
    """The decoder output cannot be bound to the requested input."""


def verify_snapshot(manifest_bytes, bundle, blocks):
    if hashlib.sha256(manifest_bytes).hexdigest() != bundle["manifest_sha256"]:
        raise ObserverError("Bundle manifest digest differs from the admitted snapshot")
    manifest = json.loads(manifest_bytes)
    if manifest["generation_id"] != bundle["generation_id"]:
        raise ObserverError("Bundle generation differs from the admitted snapshot")
    if manifest["blocks"] != [block for block, _ in blocks]:
        raise ObserverError("memory block layout differs from the admitted snapshot")
    members = {m["id"]: m for m in manifest["members"]}
    for block, data in blocks:
        if block["member_id"] is None and data is None:
            continue
        member = members.get(block["member_id"])
        if (data is None or member is None or len(data) != member["size"]
                or hashlib.sha256(data).hexdigest() != member["sha256"]):
            raise ObserverError("memory member differs from the admitted snapshot")
    return manifest


def elf_words(words):
    """Transport distinct, aligned PCs in one space without filling gaps."""
    contents = bytearray(64)
    strings = bytearray(b"\0.shstrtab\0")
    headers = [bytes(64)]
    sections = {}
    for n, (_, group) in enumerate(itertools.groupby(enumerate(words.items()), lambda item: item[1][0] - 4 * item[0])):
        chunk = dict(item for _, item in group)
        name = f".text{n}"
        sections[name] = chunk
        headers.append(struct.pack("<IIQQQQIIQQ", len(strings), 1, 6, next(iter(chunk)),
                                   len(contents), 4 * len(chunk), 0, 0, 4, 0))
        strings.extend(name.encode("ascii") + b"\0")
        contents.extend(struct.pack(f"<{len(chunk)}I", *chunk.values()))
    headers.insert(1, struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, len(contents), len(strings), 0, 0, 1, 0))
    contents.extend(strings)
    contents.extend(bytes(-len(contents) % 8))
    # ELF64/LE, ET_EXEC, EM_AARCH64. Only section headers are needed by objdump.
    contents[:64] = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01", 2, 183, 1, 0, 0,
                                len(contents), 0, 64, 0, 0, 64, len(headers), 1)
    contents.extend(b"".join(headers))
    return contents, sections


def parse_disassembly(text, sections, source="LLVM"):
    decoded = {}
    seen = set()
    current = None
    for line in text.splitlines():
        if line.startswith("Disassembly of section "):
            match = SECTION.fullmatch(line)
            if match is None or match[1] not in sections or match[1] in seen:
                raise ObserverError(f"unexpected or duplicate {source} section")
            current = match[1]
            seen.add(current)
            continue
        if not (match := INSTRUCTION.fullmatch(line)):
            if PC_LINE.match(line):
                raise ObserverError(f"unsupported {source} instruction line")
            continue
        pc = int(match[1], 16)
        raw_bytes = match[2].split()
        word = int(raw_bytes[0], 16) if len(raw_bytes) == 1 else int.from_bytes(
            bytes(int(b, 16) for b in raw_bytes), "little")
        if current is None or pc in decoded or sections[current].get(pc) != word:
            raise ObserverError(f"{source} output has a duplicate, unexpected PC or different word")
        decoded[pc] = (match[3].lower(), match[4] or "")
    if len(decoded) != sum(len(words) for words in sections.values()):
        raise ObserverError(f"{source} output lacks a requested PC or has an unsupported layout")
    return decoded


class Objdump:
    name = "LLVM"
    version_pattern = r"\bLLVM version \d+"

    def __init__(self, path, options):
        try:
            self.path = Path(path).resolve(strict=True)
            with self.path.open("rb") as file:
                digest = hashlib.file_digest(file, "sha256").hexdigest()
        except OSError as error:
            raise ObserverError(f"{self.name} executable unavailable: {error.strerror}") from error
        version = next((line.strip() for line in self._run(("--version",)).splitlines()
                        if re.search(self.version_pattern, line)), None)
        if version is None:
            raise ObserverError(f"{self.name} executable did not report a recognizable version")
        self.identity = dict(path=str(self.path), sha256=digest, version=version, options=list(options))

    def _run(self, options, data=None):
        try:
            result = subprocess.run([str(self.path), *options], input=data, capture_output=True, timeout=30,
                                    env={**os.environ, "LC_ALL": "C"})
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ObserverError(f"{self.name} execution failed: {type(error).__name__}") from error
        if result.returncode or result.stderr.strip():
            tail = result.stderr.decode("utf-8", errors="replace").strip()[:500]
            raise ObserverError(f"{self.name} rejected the requested profile or input (exit {result.returncode}): {tail}")
        return result.stdout.decode("utf-8", errors="replace")

    def check_identity(self):
        try:
            with self.path.open("rb") as file:
                if hashlib.file_digest(file, "sha256").hexdigest() == self.identity["sha256"]:
                    return
        except OSError as error:
            raise ObserverError(f"{self.name} executable became unavailable") from error
        raise ObserverError(f"{self.name} executable changed during the run")


class LlvmObjdump(Objdump):
    def __init__(self, path):
        super().__init__(path, LLVM_OPTIONS)
        probe = self.decode({0x1000: 0x14000001, 0x1004: 0, 0x1008: 0xAA0103E0})
        if (normalize(*probe[0x1000])[0:2] != ("b", ["0x1004"])
                or normalize(*probe[0x1004])[0] != "udf"
                or normalize(*probe[0x1008])[0:2] != ("orr", ["x0", "xzr", "x1"])):
            raise ObserverError("LLVM did not pass the A64 word, address and no-alias probe")

    def decode(self, words, *, options=LLVM_OPTIONS):
        image, sections = elf_words(words)
        return parse_disassembly(self._run((*options, "-"), image), sections)


def condition_name(name):
    return {"hs": "cs", "lo": "cc"}.get(name, name)


def normalize(mnemonic, operands):
    tokens = [p.strip() for p in re.sub(r"\s+<[^<>]*>", "", operands.split("//", 1)[0]).lower().split(",")]
    tokens = [] if tokens == [""] else tokens
    cond = None
    if mnemonic.startswith("b.") and condition_name(mnemonic[2:]) in CONDITIONS:
        cond, mnemonic = condition_name(mnemonic[2:]), "b.cond"
    elif mnemonic == "hint" and len(tokens) == 1:
        mnemonic = HINT_FORMS.get(number(tokens[0]), mnemonic)
    elif mnemonic == "bti" and len(tokens) == 1 and tokens[0] in ("c", "j", "jc"):
        mnemonic += "_" + tokens[0]
    elif mnemonic in ("mrs", "msr", "ic", "dc") and len(tokens) == 2:
        mnemonic += "_" + tokens[int(mnemonic == "mrs")]
    if mnemonic == "ret" and not tokens:
        tokens = ["x30"]
    return (None if mnemonic.startswith(("<", ".")) else mnemonic), tokens, cond


def number(token):
    text = token.removeprefix("#")
    if text == "0.0":
        return 0
    try:
        return int(text, 16 if text.lower().startswith(("0x", "-0x")) else 10)
    except ValueError:
        return None


def register(token):
    token = {"lr": "x30", "fp": "x29"}.get(token, token)
    return token if REGISTER.fullmatch(token) else None


def operand(token, style, space):
    if style == "cc":
        token = condition_name(token)
        return token if token in CONDITIONS else None
    if style == "target":
        pc = number(token)
        return cf.addr(space, pc) if not token.startswith("#") and pc is not None and 0 <= pc < 1 << 64 else None
    if style == "address":
        return register(token[1:-1]) if token.startswith("[") and token.endswith("]") else None
    if style == "value":
        return 0 if token in ("wzr", "xzr") else register(token) or number(token)
    return number(token) if style == "number" else register(token)


def value_ref(value, *, zero_register=False):
    if not value or cf.unknown(value):
        return None
    if "pre_register" in value:
        return register(value["pre_register"].get("name", "").lower())
    if "constant" in value:
        bits = int(value["constant"], 16)
        return {32: "wzr", 64: "xzr"}.get(value["width"]) if bits == 0 and zero_register else bits
    return None


def destination(value, width):
    if value is None:
        return {32: "wzr", 64: "xzr"}.get(width)
    reg = register(value["register"].get("name", "").lower())
    if reg and re.fullmatch(r"x[0-9]+", reg) and width == 32 and value.get("extension") == "zero_extend":
        return "w" + reg[1:]
    return reg


def flag_name(condition):
    return condition.get("flags", condition.get("encoded_condition")) if isinstance(condition, dict) else None


def operand_claims(row, form, trap):
    """The expected operands come from G2c's actual fact, not its word."""
    t = row["transfer"]
    facts = row["aarch64"]
    if form in DIRECT:
        target = next((e.get("to") for e in t["edges"] if e["source"] == "encoded_target"), None)
        fields = [("target", "target", None if cf.unknown(target) else target)]
        if form in ("cbz", "cbnz", "tbz", "tbnz"):
            test = ((t.get("condition") or {}).get("test") or {})
            if form.startswith("tb"):
                test, bit = test.get("bit_clear" if form == "tbz" else "bit_set", (None, None))
                fields.insert(0, ("bit", "number", bit))
            else:
                test = test.get("zero" if form == "cbz" else "nonzero")
            fields.insert(0, ("source_register", "register", value_ref(test, zero_register=True)))
        return fields
    if form in REGISTER_BRANCH:
        fields = [("target_register", "register", value_ref(t.get("target_value"), zero_register=True))]
        if form in EXPLICIT_MODIFIER:
            fields.append(("modifier", "register", value_ref((t.get("target_auth") or {}).get("modifier"),
                                                            zero_register=True)))
        return fields
    if form in TRAPS:
        return [("immediate", "number", (trap or {}).get("immediate"))]
    if form in SELECT_FALSE_OP:
        v = facts.get("value_select", {})
        return [("destination", "register", destination(v["destination"], v["width"])
                 if "destination" in v else None),
                ("source_1", "register", value_ref(v.get("when_true"), zero_register=True)),
                ("source_2", "register", value_ref(v.get("when_false", {}).get("operand"), zero_register=True)),
                ("condition", "cc", flag_name(v.get("condition")))]
    if form in INTEGER_COMPARE_OP or form in FLOAT_COMPARE_FORMS:
        c = facts.get("flag_compare", {})
        left, right = c.get("when_true", {}).get("operands", (None, None))
        # G2c's constant zero can denote a literal or a zero register. Compare the
        # resulting value in this slot and retain LLVM's actual operand spelling.
        style = "value" if right and "constant" in right else "register"
        fields = [("source_1", "register", value_ref(left, zero_register=True)),
                  ("source_2", style, value_ref(right))]
        if form != "fcmp":
            fields.extend((("nzcv", "number", (c.get("when_false") or {}).get("nzcv")),
                           ("condition", "cc", flag_name(c.get("condition")))))
        return fields
    if form == "udiv":
        v = facts.get("value_operation", {})
        left, right = v.get("operands", (None, None))
        return [("destination", "register", destination(v["destination"], v["width"])
                 if "destination" in v else None),
                ("source_1", "register", value_ref(left, zero_register=True)),
                ("source_2", "register", value_ref(right, zero_register=True))]
    if form == "ldaddal":
        a = facts.get("atomic_access", {})
        return [("addend", "register", value_ref(a.get("addend"), zero_register=True)),
                ("old_value_destination", "register", destination(a["old_value_destination"], a["width"])
                 if "old_value_destination" in a else None),
                ("address_register", "address", value_ref(a.get("address")))]
    return []


def field(expected, observed, reason=None):
    if expected is None or observed is None:
        state = "unobserved"
    else:
        state = "match" if cf.canonical(expected) == cf.canonical(observed) else "mismatch"
    result = dict(state=state, g2c=expected, llvm=observed)
    if state == "unobserved":
        result["reason"] = reason or ("G2c field unavailable" if expected is None else "LLVM field unavailable")
    return result


def compare_row(row, decoded, trap, reason=None):
    form = row["aarch64"]["form"]
    expected = form if isinstance(form, str) else None
    observed, tokens, condition = normalize(*decoded) if decoded is not None else (None, [], None)
    output = {"form": field(expected, observed, reason)}
    if expected is not None and (observed is None or expected == observed):
        claims = operand_claims(row, expected, trap)
        same_form = expected == observed
        compare_operands = same_form and len(tokens) == len(claims)
        for n, (label, style, value) in enumerate(claims):
            actual = operand(tokens[n], style, row["space"]) if compare_operands else None
            output[label] = field(value, actual, reason)
            if style == "value" and compare_operands:
                output[label].update(comparison="value_only", llvm_operand=tokens[n])
        if expected == "b.cond":
            output["condition"] = field(flag_name((row["transfer"].get("condition") or {}).get("test")),
                                        condition if same_form else None, reason)
    return output


def matches_observation(row, raw):
    return (raw is not None and cf.identity(raw, row["observation"]) == cf.rr(row)
            and cf.canonical([row["space"], row["offset"], row["length"], row["view"]]) == cf.canonical([
                raw["space"], format(raw["address"], "x"), raw["length"], raw.get("view", "0")]))


def require_basis(row, raw, arm):
    if not matches_observation(row, raw):
        return None, "row does not match the admitted observation"
    basis = arm.basis(raw)
    if cf.canonical(basis) != cf.canonical(row["aarch64"]["basis"]):
        return None, "G2c byte basis differs from the admitted observation"
    if cf.unknown(basis):
        return None, basis["unobserved"]
    return (raw["space"], raw["address"], int(basis["word"], 16)), None


def bind_snapshot_rows(document, raw, *, admitted_bundle, manifest_bytes, blocks, binding):
    if document["bundle"] != admitted_bundle:
        raise ObserverError("G2c Bundle differs from the admitted snapshot")
    manifest = verify_snapshot(manifest_bytes, admitted_bundle, blocks)
    rows = document["rows"]
    index = {cf.rr(r): r["aarch64"] for r in rows}
    if len(index) != len(rows) or index.keys() != raw.keys():
        raise ObserverError("G2c row identities differ from the admitted row set")
    if not index:
        raise ObserverError("no admitted AArch64 instruction rows")
    if (binding["facts_sha256"] != cf.streamed_digest(document)
            or binding["row_set_sha256"] != cf.row_set_digest(rows)):
        raise ObserverError("diagnostic binding differs from the facts digest or row set")
    return manifest, index


def diagnose(document, raw, executable, *, admitted_bundle, manifest_bytes, blocks, binding, complete,
             gnu_executable=None):
    observed, checks, traps = {}, {}, {}
    words = defaultdict(dict)
    rows = document["rows"]
    observer, error = None, None
    try:
        _, index = bind_snapshot_rows(document, raw, admitted_bundle=admitted_bundle,
                                     manifest_bytes=manifest_bytes, blocks=blocks, binding=binding)
        for site in document["program"]["aarch64"]["survey"]["sites"]["trap_instruction"]:
            k = cf.rr(site["row"])
            if k in traps or k not in index:
                raise ObserverError("unexpected or duplicate G2c trap row")
            fact = index[k]
            if (site["form"] not in TRAPS or fact["form"] != site["form"]
                    or cf.canonical(fact["basis"]) != cf.canonical(site["basis"])):
                raise ObserverError("G2c trap form or basis differs from its instruction row")
            traps[k] = site
        basis = Arm64Facts(blocks, {}, {})
        for row in rows:
            k = cf.rr(row)
            request, reason = require_basis(row, raw[k], basis)
            checks[k] = (request, reason)
            if request is not None:
                space, pc, word = request
                if words[space].setdefault(pc, word) != word:
                    raise ObserverError("conflicting sealed words in one address space")
        observer = LlvmObjdump(executable)
        for space, values in sorted(words.items()):
            ordered = sorted(values.items())
            for start in range(0, len(ordered), BATCH_WORDS):
                decoded = observer.decode(dict(ordered[start:start + BATCH_WORDS]))
                observed.update({(space, pc, values[pc]): v for pc, v in decoded.items()})
        observer.check_identity()
    except ObserverError as failure:
        observed.clear()
        error = str(failure)

    counts, fields = Counter(), defaultdict(Counter)
    report_rows = []
    decoded_rows = 0
    for row in rows:
        k = cf.rr(row)
        request, reason = checks.get(k, (None, None))
        decoded = observed.get(request)
        decoded_rows += decoded is not None
        compared = compare_row(row, decoded, traps.get(k), reason or error)
        states = {f["state"] for f in compared.values()}
        state = "mismatch" if "mismatch" in states else "unobserved" if "unobserved" in states else "match"
        counts[state] += 1
        for path, f in compared.items():
            fields[path][f["state"]] += 1
        report_rows.append(dict(row=cf.ref(row), basis=row["aarch64"]["basis"], state=state, fields=compared))
    report = dict(rule=RULE, status="error" if error else "ok", error=error,
                  scope="independent decode of admitted sealed snapshot bytes",
                  decoder=observer.identity if observer else None, bundle=document["bundle"],
                  binding=binding, observation_complete=complete, observation_rows=len(rows), decoded_rows=decoded_rows,
                  requested_words=sum(map(len, words.values())), counts=dict(counts),
                  fields={k: dict(v) for k, v in fields.items()}, rows=report_rows)
    if gnu_executable is not None and not error:
        import arm64_profiles

        report["feature_audit"] = arm64_profiles.audit(rows, raw, checks, observed, observer, gnu_executable)
    return report
