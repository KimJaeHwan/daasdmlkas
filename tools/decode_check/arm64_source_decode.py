"""Compare independent A64 disassemblies of the same original ELF words."""

import re

from arm64_decode import BATCH_WORDS, DIRECT, LLVM_OPTIONS, LlvmObjdump, normalize, number
from arm64_facts import CC, signed
from arm64_profiles import GnuObjdump
from arm64_source_facts import RULE, EXTENDED_RULE, compare_fields, common_fields


_IMMEDIATE = re.compile(r"#-?(?:0x[0-9a-f]+|[0-9]+)(?![\w.])")
SVE_SME_PROFILE = "sve-sme-v1"
SVE_SME_PROFILE_V2 = "sve-sme-v2"
_SVE_SME_OPTIONS = (*LLVM_OPTIONS[:-1], LLVM_OPTIONS[-1] + ",+sve,+sve2,+bf16,+i8mm,+sme,+sme2,+sme-f64f64")
SOURCE_DECODE_PROFILES = {
    SVE_SME_PROFILE: _SVE_SME_OPTIONS,
    SVE_SME_PROFILE_V2: _SVE_SME_OPTIONS,
}
SOURCE_DECODE_RULES = {SVE_SME_PROFILE: RULE, SVE_SME_PROFILE_V2: EXTENDED_RULE}


def _rendered(raw, *, gnu):
    form, operands, condition = normalize(*raw, expand_hints=False)
    if form is None or form in {"undefined", "unallocated", "unknown"}:
        return None
    if form in DIRECT and operands:
        target = operands[-1]
        if re.fullmatch(r"(?:0x)?[0-9a-f]+" if gnu else r"0x[0-9a-f]+", target):
            operands[-1] = hex(int(target, 16))
        else:
            return None
    operands = [_IMMEDIATE.sub(lambda match: f"#{number(match[0])}", token) for token in operands]
    return dict(form=form, operands=operands, condition=condition)


def _arm_check(pc, word, index, llvm, gnu):
    rows = {row["id"]: row for row in index["candidates"]}
    if set(rows) == {"B_only_condbranch"} and word & 0xff000010 == 0x54000000:
        target = (pc + 4 * signed((word >> 5) & 0x7ffff, 19)) % (1 << 64)
        expected = dict(form="b.cond", operands=[hex(target)], condition=CC[word & 15])
        return dict(kind="conditional-branch-encoding", encoding=rows["B_only_condbranch"], expected=expected,
                    llvm=llvm == expected if llvm is not None else None,
                    gnu=gnu == expected if gnu is not None else None)
    if word == 0xd503233f and set(rows) == {"HINT_HM_hints", "PACIASP_HI_hints"}:
        accepted = (dict(form="hint", operands=["#25"], condition=None),
                    dict(form="paciasp", operands=[], condition=None))
        return dict(kind="feature-dependent-hint-encoding", encodings=list(rows.values()),
                    runtime_feature_state="unobserved",
                    llvm=llvm in accepted if llvm is not None else None,
                    gnu=gnu in accepted if gnu is not None else None)
    return None


def _profile_probe(llvm, gnu, reference):
    # S=0 and S=1 expose printers that display an access-size shift in both cases.
    words = dict(zip(range(0x1000, 0x1020, 4), (
        0x647ae707, 0xc00800ff, 0x80820820, 0x80c40860,
        0xf8646801, 0xf8647801, 0x3ce16840, 0x3ce17840,
    ), strict=True))
    left, right = llvm.decode(words), gnu.decode(words)
    rows = []
    for pc, word in words.items():
        report = _source_row(pc, word, reference.candidates(word), left[pc], right[pc], profiled=True)
        if "common_facts" not in report:
            raise ValueError("profile probe could not bind the pinned Arm encoding")
        if pc < 0x1010 and any(result["state"] != "confirmed"
                              for votes in report["field_evidence"].values() for result in votes.values()):
            raise ValueError("decoder did not pass the SVE/SME form and operand probe")
        rows.append(report)
    return rows


def _source_row(pc, word, index, llvm, gnu, *, profiled, rule=RULE):
    first, second = _rendered(llvm, gnu=False), _rendered(gnu, gnu=True)
    state = ("unobserved" if first is None or second is None else
             "same-rendering" if first == second else "different-rendering")
    row = dict(address=pc, bytes_le=word.to_bytes(4, "little").hex(), encoding_index=index,
               llvm=dict(mnemonic=llvm[0], operands=llvm[1], normalized=first),
               gnu=dict(mnemonic=gnu[0], operands=gnu[1], normalized=second), comparison=state)
    check = _arm_check(pc, word, index, first, second)
    if check is not None:
        row["arm_check"] = check
    if profiled:
        fields = common_fields(word, index, rule=rule)
        if fields is not None:
            facts, expected = fields
            row["common_facts"] = facts
            row["field_evidence"] = compare_fields(facts, expected, first, second)
    return row


def observe(words, reference, llvm_path, gnu_path, *, profile=None):
    """Keep both rendered decodes and only check the Arm fields modeled here."""
    if profile is not None and profile not in SOURCE_DECODE_PROFILES:
        raise ValueError("unknown AArch64 source decode profile")
    llvm = (LlvmObjdump(llvm_path) if profile is None else
            LlvmObjdump(llvm_path, options=SOURCE_DECODE_PROFILES[profile]))
    gnu = GnuObjdump(gnu_path)
    decoders = dict(llvm=llvm.identity, gnu=gnu.identity)
    if profile is not None:
        decoders["profile_probes"] = _profile_probe(llvm, gnu, reference)
    rule = SOURCE_DECODE_RULES.get(profile, RULE)
    results = []
    for start in range(0, len(words), BATCH_WORDS):
        chunk = dict(words[start:start + BATCH_WORDS])
        left, right = llvm.decode(chunk), gnu.decode(chunk)
        results.extend(_source_row(pc, word, reference.candidates(word), left[pc], right[pc],
                                   profiled=profile is not None, rule=rule) for pc, word in chunk.items())
    llvm.check_identity()
    gnu.check_identity()
    return decoders, results
