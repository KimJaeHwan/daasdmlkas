#!/usr/bin/env python3
"""Sample the pinned Arm A64 encoding table and compare the decoder outputs."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import ExitStack
from hashlib import sha256
from itertools import product
import json
from pathlib import Path
import struct
from tempfile import NamedTemporaryFile
from xml.etree import ElementTree

import z3

from arm64_encoding_index import ARM_A64_REFERENCE, load_index, pinned_archive
from arm64_source_decode import SOURCE_DECODE_PROFILES, SVE_SME_PROFILE_V2, observe


SCHEMA = "tbr-a64-encoding-coverage-1"
BASE = 0x100000
_SIZE_FIELDS = {"size", "sz", "tsz", "tsize", "msize", "esize", "Q", "szl", "tszl"}


def _guard_term(word, guard):
    return z3.And(word & guard.mask == guard.value,
                  *(word & mask != value for mask, value in guard.exclusions))


def _section_paths(index, word):
    paths = defaultdict(list)
    pending = [(node, z3.BoolVal(True, ctx=word.ctx)) for node in index.roots]
    while pending:
        node, parent = pending.pop()
        here = z3.And(parent, _guard_term(word, node.guard))
        if node.children:
            pending.extend((child, here) for child in node.children)
        elif not node.unallocated:
            paths[node.section].append(here)
    return paths


def _model_word(solver, word, *assumptions):
    outcome = solver.check(*assumptions)
    if outcome == z3.unsat:
        return None
    if outcome != z3.sat:
        raise ValueError(f"could not solve the Arm table guards ({solver.reason_unknown()})")
    return solver.model().eval(word, model_completion=True).as_long()


def _witnesses(word, constraints):
    solver = z3.SolverFor("QF_BV", ctx=word.ctx)
    solver.set(random_seed=0)
    solver.add(constraints)
    anchor = _model_word(solver, word)
    if anchor is None:
        return (), 0

    samples, variation = [anchor], 0
    for position in range(32):
        bit = 1 << position
        if variation & bit:
            continue
        sample = _model_word(solver, word, word & bit != anchor & bit)
        if sample is not None:
            samples.append(sample)
            variation |= anchor ^ sample
    return tuple(sorted(samples)), variation


def _size_witnesses(word, constraints, samples, mask):
    if not samples:
        return ()

    solver = z3.SolverFor("QF_BV", ctx=word.ctx)
    solver.set(random_seed=0)
    solver.add(constraints)
    anchor = samples[0]
    existing = set(samples)
    seen_sizes = {sample & mask for sample in samples}
    size_bits = [1 << bit for bit in range(32) if mask & (1 << bit)]
    size_samples = []
    for bits in product((0, 1), repeat=len(size_bits)):
        size = sum(bit for bit, use in zip(size_bits, bits, strict=True) if use)
        # Vary the size without also changing unrelated operands such as lane indexes.
        sample = anchor & ~mask | size
        if sample in existing:
            continue
        if _model_word(solver, word, word == sample) is None:
            if size in seen_sizes:
                continue
            sample = _model_word(solver, word, word & mask == size)
        if sample is not None:
            size_samples.append(sample)
    return tuple(sorted(size_samples))


def _size_masks(archive_path, index):
    encodings = defaultdict(set)
    for _, rows in index.sections.values():
        for row in rows:
            if row.file is not None:
                encodings[row.file].add(row.encoding)
    masks = {}
    with pinned_archive(archive_path) as archive:
        for member in archive:
            prefix, separator, file = member.name.partition("/")
            if not (member.isfile() and prefix == ARM_A64_REFERENCE and separator and file in encodings):
                continue
            with archive.extractfile(member) as source:
                root = ElementTree.parse(source).getroot()
            for instruction in root.findall("./classes/iclass"):
                mask = 0
                for field in instruction.findall("./regdiagram/box"):
                    if field.get("name") in _SIZE_FIELDS:
                        top = int(field.attrib["hibit"])
                        width = int(field.get("width", "1"))
                        if not 0 < width <= top + 1 <= 32:
                            raise ValueError(f"invalid Arm operand size field in {file}")
                        mask |= ((1 << width) - 1) << (top + 1 - width)
                for encoding in instruction.findall("./encoding"):
                    name = encoding.get("name")
                    if name in encodings[file]:
                        masks[file, name] = masks.get((file, name), 0) | mask
    return masks


def _mops_sample(section, encoding, samples):
    if not samples or section != "memcms" or not encoding.endswith(("_CPY_memcms", "_SET_memcms")):
        return None
    # MOPS has coupled operand constraints. Select distinct low registers for Rd, Rn and Rs.
    register_fields = 31 | (31 << 5) | (31 << 16)
    return (samples[0] & ~register_fields) | (2 << 5) | (1 << 16)


def sample_index(index, *, size_masks=None):
    """Find table witnesses covering variable bits and documented operand size combinations."""
    # Isolate the solver's symbol order from other analyses in this process.
    word = z3.BitVec("a64_instruction", 32, ctx=z3.Context())
    paths = _section_paths(index, word)
    candidate_cache = {}
    size_masks = {} if size_masks is None else size_masks
    baseline = []
    for section, (section_guard, rows) in sorted(index.sections.items()):
        reachable = z3.Or(*paths[section]) if paths[section] else z3.BoolVal(False, ctx=word.ctx)
        enclosing = z3.And(reachable, _guard_term(word, section_guard))
        for ordinal, row in enumerate(rows):
            if row.file is None:
                continue
            identity = dict(section=section, row=ordinal, id=row.encoding, file=row.file,
                            feature_condition=row.feature_condition)
            samples, variable_bits = _witnesses(word, z3.And(enclosing, _guard_term(word, row.guard)))
            baseline.append((identity, samples, variable_bits))

    # Keep the per-bit witnesses stable when size queries add expressions to the solver context.
    for identity, samples, variable_bits in baseline:
        section = identity["section"]
        mask = size_masks.get((identity["file"], identity["id"]), 0) & variable_bits
        size_samples = ()
        if mask.bit_count() > 1:
            section_guard, rows = index.sections[section]
            constraints = z3.And(z3.Or(*paths[section]), _guard_term(word, section_guard),
                                 _guard_term(word, rows[identity["row"]].guard))
            size_samples = _size_witnesses(word, constraints, samples, mask)
        extra = _mops_sample(section, identity["id"], samples)
        supplement = [dict(word=sample, basis="operand-size-combination") for sample in size_samples]
        if extra is not None and extra not in samples and extra not in size_samples:
            supplement.append(dict(word=extra, basis="distinct-mops-registers"))
        samples = sorted((*samples, *(item["word"] for item in supplement)))
        for sample in samples:
            if sample not in candidate_cache:
                candidate_cache[sample] = index.candidates(sample)["candidates"]
            if identity not in candidate_cache[sample]:
                raise ValueError(f"Arm table witness did not round-trip for {identity['id']}")
        yield dict(**identity, variable_bit_mask=f"{variable_bits:08x}", samples=samples, supplement=supplement)


def _summarize(rows, observations):
    summary = Counter(allocated_rows=len(rows), unique_words=len(observations))
    word_by_value = {int.from_bytes(bytes.fromhex(row["bytes_le"]), "little"): row for row in observations}
    for row in rows:
        witnessed = [word_by_value[value] for value in row["samples"]]
        states = Counter(item["comparison"] for item in witnessed)
        if witnessed:
            summary["rows_with_witness"] += 1
        if row["supplement"]:
            summary["rows_with_supplementary_witness"] += 1
        if states["same-rendering"] or states["different-rendering"]:
            summary["rows_with_both_decoders_observed"] += 1
        if witnessed and not states["unobserved"]:
            summary["rows_with_all_samples_observed_by_both"] += 1
        for tool in ("llvm", "gnu"):
            if any(item[tool]["normalized"] is not None for item in witnessed):
                summary[f"rows_with_{tool}_observed"] += 1
        if states["different-rendering"]:
            summary["rows_with_rendering_difference"] += 1
        row["comparison_counts"] = dict(states)
    for item in observations:
        summary["words_" + item["comparison"].replace("-", "_")] += 1
        for tool in ("llvm", "gnu"):
            if item[tool]["normalized"] is None:
                summary[f"words_{tool}_unobserved"] += 1
        if len(item["encoding_index"]["candidates"]) > 1:
            summary["words_with_multiple_table_candidates"] += 1
        if item["encoding_index"]["exclusions"]:
            summary["words_with_table_exclusions"] += 1
    summary["rows_without_witness"] = len(rows) - summary["rows_with_witness"]
    summary.setdefault("words_with_table_exclusions", 0)
    return dict(summary)


def collect_coverage(archive, llvm_objdump, gnu_objdump, *, profile=SVE_SME_PROFILE_V2):
    index, identity = load_index(archive)
    rows = list(sample_index(index, size_masks=_size_masks(archive, index)))
    words = sorted({word for row in rows for word in row["samples"]})
    observations_by_address = [(BASE + 4 * i, word) for i, word in enumerate(words)]
    decoders, observations = observe(observations_by_address, index, llvm_objdump, gnu_objdump,
                                     profile=profile, encoding_archive=archive)
    binary = struct.pack(f"<{len(words)}I", *words)
    report = dict(schema=SCHEMA, arm_index=identity, solver=z3.get_full_version(),
                  scope="table-candidates-variable-bits-and-operand-size-combinations", profile=profile,
                  synthetic_base=BASE, sample_sha256=sha256(binary).hexdigest(), decoders=decoders,
                  summary=_summarize(rows, observations), rows=rows, words=observations)
    return report, binary


def _write_outputs(report_path, report, binary_path, binary):
    serialized = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    payloads = [(report_path, serialized)]
    if binary_path is not None:
        payloads.insert(0, (binary_path, binary))
    with ExitStack() as cleanup:
        staged = []
        for path, data in payloads:
            with NamedTemporaryFile(mode="wb", dir=path.parent, delete=False) as temp:
                staged_path = Path(temp.name)
                cleanup.callback(staged_path.unlink, missing_ok=True)
                temp.write(data)
            staged.append((staged_path, path))
        for staged_path, path in staged:
            staged_path.replace(path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("encoding_archive", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--llvm-objdump", required=True, type=Path)
    parser.add_argument("--gnu-objdump", required=True, type=Path)
    parser.add_argument("--profile", choices=SOURCE_DECODE_PROFILES, default=SVE_SME_PROFILE_V2)
    parser.add_argument("--words-out", type=Path, help="write the sampled little-endian A64 words for separate inspection")
    args = parser.parse_args(argv)
    inputs = (args.encoding_archive, args.llvm_objdump, args.gnu_objdump)
    destinations = (args.report,) if args.words_out is None else (args.report, args.words_out)
    if len({path.resolve() for path in (*inputs, *destinations)}) != len(inputs) + len(destinations):
        parser.error("input and output paths must be distinct")
    try:
        report, binary = collect_coverage(*inputs, profile=args.profile)
        _write_outputs(args.report, report, args.words_out, binary)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{parser.prog}: {error}\n")
    print(json.dumps(report["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
