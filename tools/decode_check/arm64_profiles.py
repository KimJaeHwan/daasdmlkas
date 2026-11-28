"""Compare AArch64 encodings separately from feature-specific decode observations."""

from collections import Counter, defaultdict
import tempfile

import arm64_decode as decode
from arm64_facts import AUTH_KEYS
import common_facts as cf


GNU_OPTIONS = ("--disassemble", "--disassemble-zeroes", "--disassembler-options=no-aliases")
FEATURE_FLAGS = {"FEAT_PAuth": "pauth", "FEAT_BTI": "bti", "FEAT_LSE": "lse"}
IMPLICIT_OPERANDS = frozenset(decode.HINT_FORMS.values()) | {"retaa", "retab"}
BTI_OPERANDS = (["c"], ["j"], ["jc"])
FEATURES = dict.fromkeys(AUTH_KEYS, "FEAT_PAuth")
for form in decode.HINT_FORMS.values():
    if form != "nop":
        FEATURES[form] = "FEAT_BTI" if form.startswith("bti") else "FEAT_PAuth"
FEATURES["ldaddal"] = "FEAT_LSE"


class GnuObjdump(decode.Objdump):
    name = "GNU objdump"
    version_pattern = r"^GNU objdump\b.*\b\d+\.\d+"

    def __init__(self, path):
        super().__init__(path, GNU_OPTIONS)
        probe = self.decode({0x1000: 0xAA0103E0, 0x1004: 0xF8E00041})
        if (decode.normalize(*probe[0x1000])[:2] != ("orr", ["x0", "xzr", "x1"])
                or decode.normalize(*probe[0x1004])[:2] != ("ldaddal", ["x0", "x1", "[x2]"])):
            raise decode.ObserverError("GNU objdump did not pass the A64 word and no-alias probe")

    def decode(self, words):
        image, sections = decode.elf_words(words)
        with tempfile.NamedTemporaryFile(suffix=".elf") as file:
            file.write(image)
            file.flush()
            return decode.parse_disassembly(self._run((*GNU_OPTIONS, file.name)), sections, self.name)


def disabled_options(feature):
    return (*decode.LLVM_OPTIONS[:-1], decode.LLVM_OPTIONS[-1] + ",-" + FEATURE_FLAGS[feature])


def decoder_fields(decoded):
    if decoded is None:
        return {"form": None}
    form, tokens, _ = decode.normalize(*decoded)
    mnemonic, _ = decoded
    if (form in IMPLICIT_OPERANDS and tokens and mnemonic != "hint"
            and not (mnemonic == "bti" and tokens in BTI_OPERANDS)):
        return {"form": None}
    observed = {"form": form}
    if form == "ldaddal":
        operands = (("addend", "register"), ("old_value_destination", "register"),
                    ("address_register", "address"))
    elif form in decode.EXPLICIT_MODIFIER:
        operands = (("target_register", "register"), ("modifier", "register"))
    elif form in AUTH_KEYS and form in decode.REGISTER_BRANCH:
        operands = (("target_register", "register"),)
    else:
        return observed
    for i, (key, style) in enumerate(operands):
        observed[key] = decode.operand(tokens[i], style, None) if len(tokens) == len(operands) else None
    return observed


def encoded_fields(row, llvm, gnu):
    left, right = decoder_fields(llvm), decoder_fields(gnu)
    form = row["aarch64"]["form"]
    expected = {"form": form if isinstance(form, str) else None}
    if isinstance(form, str) and form == left["form"] == right["form"]:
        expected.update((key, value) for key, _, value in decode.operand_claims(row, form, None))
    fields = {}
    for name in sorted(left.keys() | right.keys() | expected.keys()):
        l, r = left.get(name), right.get(name)
        agreement = decode.field(l, r)["state"]
        state = {"mismatch": "withheld", "unobserved": "unobserved"}.get(agreement)
        if state is None:
            state = decode.field(expected.get(name), l)["state"]
        fields[name] = dict(state=state, decoder_agreement=agreement, g2c=expected.get(name), llvm=l, gnu=r)
    return fields


def observation(decoded):
    if decoded is None:
        return None
    mnemonic, operands = decoded
    return dict(state="unrecognized" if decoder_fields(decoded)["form"] is None else "decoded",
                mnemonic=mnemonic, operands=operands)


def audit(rows, raw, checks, enabled, llvm, gnu_path):
    selected = []
    words = defaultdict(dict)
    for row in rows:
        k = cf.rr(row)
        request, reason = checks[k]
        observed = enabled.get(request)
        form = row["aarch64"]["form"]
        g2c = FEATURES.get(form) if isinstance(form, str) else None
        found = FEATURES.get(decoder_fields(observed)["form"])
        feature = found or g2c
        if feature is None:
            continue
        selected.append((row, feature, g2c, found, request, reason))
        if request is not None:
            space, pc, word = request
            words[space, feature][pc] = word

    metadata = dict(scope="PAC, BTI and LDADDAL forms in G2c or feature-enabled LLVM output",
                    candidate_rows=len(selected), gnu_scope="encoded form and explicit operands",
                    llvm_feature_options={feature: list(disabled_options(feature)) for feature in FEATURE_FLAGS})
    if not selected:
        return dict(metadata, status="unobserved", reason="no pilot forms selected", rows=[])
    gnu_words, limited, profile_errors = {}, {}, {}
    try:
        gnu = GnuObjdump(gnu_path)
        for (space, feature), group in sorted(words.items()):
            ordered = sorted(group.items())
            for start in range(0, len(ordered), decode.BATCH_WORDS):
                chunk = dict(ordered[start:start + decode.BATCH_WORDS])
                gnu_words.update({(space, pc, chunk[pc]): value for pc, value in gnu.decode(chunk).items()})
                if feature not in profile_errors:
                    try:
                        decoded = llvm.decode(chunk, options=disabled_options(feature))
                    except decode.ObserverError as error:
                        profile_errors[feature] = str(error)
                    else:
                        limited.update({((space, pc, chunk[pc]), feature): value for pc, value in decoded.items()})
        gnu.check_identity()
        llvm.check_identity()
    except (decode.ObserverError, OSError) as error:
        return dict(metadata, status="error", error=str(error), rows=[])

    report, counts = [], Counter()
    for row, feature, g2c, found, request, reason in selected:
        k = cf.rr(row)
        llvm_word, gnu_word = enabled.get(request), gnu_words.get(request)
        fields = encoded_fields(row, llvm_word, gnu_word)
        states = {f["state"] for f in fields.values()}
        state = next(s for s in ("withheld", "mismatch", "unobserved", "match") if s in states)
        counts[state] += 1
        claims = [i for i, fact in enumerate(row["isa"])
                  if any(c["source"] == "profile" and c["what"] == g2c for c in fact["conditions"])]
        listing = raw[k]
        ghidra = (dict(length=listing["length"], flow=listing["flow"],
                       opcode_sequence=[op["opcode"] for op in listing["ops"]])
                  if decode.matches_observation(row, listing) else cf.U("row does not match the admitted observation"))
        disabled = (cf.U(profile_errors[feature]) if feature in profile_errors
                    else observation(limited.get((request, feature))))
        report.append(dict(row=cf.ref(row), basis=row["aarch64"]["basis"], state=state, reason=reason,
                           feature=feature, g2c_feature=g2c, llvm_feature=found, g2_isa_indices=claims,
                           fields=fields, llvm_enabled=observation(llvm_word), llvm_feature_disabled=disabled,
                           gnu=observation(gnu_word), runtime_effect=cf.U("no CPU or OS observation"), ghidra=ghidra))
    return dict(metadata, status="partial" if profile_errors else "ok", profile_errors=profile_errors,
                gnu_decoder=gnu.identity, counts=dict(counts), rows=report)
