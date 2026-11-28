"""Locate A64 encoding candidates in the pinned Arm hierarchy and class tables."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import tarfile
from xml.etree import ElementTree

ARM_A64_REFERENCE = "ISA_A64_xml_A_profile-2026-06"
ARM_A64_REFERENCE_SHA256 = "63a01a1696483bbe2edfef9e0f0cd053d6c1c619ec0587876cb7a60bb344f354"
ARM_ARCHIVE_BYTES = 34_182_920


@dataclass(frozen=True, slots=True)
class Guard:
    mask: int
    value: int
    exclusions: tuple[tuple[int, int], ...]

    def matches(self, word):
        return word & self.mask == self.value and all(word & mask != value for mask, value in self.exclusions)


@dataclass(frozen=True, slots=True)
class Node:
    guard: Guard
    children: tuple[Node, ...]
    section: str
    unallocated: bool


@dataclass(frozen=True, slots=True)
class EncodingRow:
    guard: Guard
    encoding: str
    feature_condition: str | None
    file: str | None


def _guard(fields):
    mask = value = 0
    exclusions = []
    for top, width, text in fields:
        if not 0 < width <= top + 1 <= 32:
            raise ValueError("invalid Arm decode field extent")
        pattern = (text or "").strip()
        if not pattern:
            continue
        excludes = pattern.startswith("!= ")
        if excludes:
            pattern = pattern[3:]
        if len(pattern) != width or set(pattern) - {"0", "1", "x"}:
            raise ValueError(f"unsupported Arm decode field pattern {pattern!r}")
        shift = top + 1 - width
        part_mask = int("".join("0" if bit == "x" else "1" for bit in pattern), 2) << shift
        part_value = int(pattern.replace("x", "0"), 2) << shift
        if excludes:
            exclusions.append((part_mask, part_value))
        else:
            if (part_value ^ value) & part_mask & mask:
                raise ValueError("conflicting constraints in an Arm decode guard")
            mask |= part_mask
            value |= part_value
    return Guard(mask, value, tuple(exclusions))


def _cells(boxes):
    for box in boxes:
        top = int(box.attrib["hibit"])
        bit = top
        for cell in box.findall("c"):
            width = int(cell.get("colspan", "1"))
            yield bit, width, cell.text
            bit -= width
        if bit != top - int(box.get("width", "1")):
            raise ValueError("Arm decode diagram does not cover the declared field")


def _node(item):
    children = tuple(_node(child) for child in item.findall("node"))
    return Node(_guard(_cells(item.findall("./decode/box"))), children,
                item.attrib["groupname" if children else "iclass"], item.get("unallocated") == "1")


def _section(item):
    diagram = item.findall("./regdiagram/box")
    fields = {box.attrib["name"]: (int(box.attrib["hibit"]), int(box.get("width", "1")))
              for box in diagram if "name" in box.attrib}
    columns = tuple(fields[header.text] for header in
                    item.findall("./instructiontable/thead/tr[@id='heading2']/th[@class='bitfields']"))
    rows = []
    for row in item.findall("./instructiontable/tbody/tr"):
        file = row.get("iformfile")
        if file is None and row.get("undef") != "1":
            raise ValueError("unclassified Arm instruction table row")
        texts = (cell.text for cell in row.findall("./td[@class='bitfield']"))
        cells = ((top, width, text) for (top, width), text in zip(columns, texts, strict=True))
        rows.append(EncodingRow(_guard(cells), row.attrib["encname"], row.get("arch_version"), file))
    return _guard(_cells(diagram)), tuple(rows)


class EncodingIndex:
    def __init__(self, root):
        if root.tag != "encodingindex" or root.get("instructionset") != "A64":
            raise ValueError("expected an Arm A64 encoding index")
        self.roots = tuple(_node(item) for item in root.findall("./hierarchy/node"))
        self.sections = {item.attrib["id"]: _section(item) for item in root.findall("iclass_sect")}

    def candidates(self, word):
        if type(word) is not int or not 0 <= word < 1 << 32:
            raise ValueError("A64 candidate lookup requires a 32-bit instruction word")
        pending = list(reversed(self.roots))
        matches, exclusions = [], []
        while pending:
            node = pending.pop()
            if not node.guard.matches(word):
                continue
            if node.children:
                pending.extend(reversed(node.children))
            elif node.unallocated:
                exclusions.append(dict(section=node.section, reason="unallocated-hierarchy"))
            else:
                guard, rows = self.sections[node.section]
                if not guard.matches(word):
                    continue
                for index, row in enumerate(rows):
                    if not row.guard.matches(word):
                        continue
                    coordinate = dict(section=node.section, row=index, id=row.encoding)
                    if row.file is None:
                        exclusions.append(dict(**coordinate, reason="undefined-table-row"))
                    else:
                        matches.append(dict(**coordinate, file=row.file, feature_condition=row.feature_condition))
        state = "candidates" if matches else "table-exclusion" if exclusions else "no-table-match"
        return dict(state=state, candidates=matches, exclusions=exclusions)


@contextmanager
def pinned_archive(archive_path, *, size=ARM_ARCHIVE_BYTES, digest=ARM_A64_REFERENCE_SHA256,
                   release=ARM_A64_REFERENCE):
    """Read an unmodified copy of the architecture release used by the verifier."""
    with Path(archive_path).open("rb") as source:
        data = source.read(size + 1)
    if len(data) != size:
        raise ValueError(f"expected a {size}-byte pinned Arm {release} archive")
    archive_sha = sha256(data).hexdigest()
    if archive_sha != digest:
        raise ValueError(f"expected the pinned Arm {release} archive, got SHA-256 {archive_sha}")
    with tarfile.open(fileobj=BytesIO(data), mode="r|gz") as archive:
        yield archive


def load_index(archive_path):
    name = ARM_A64_REFERENCE + "/encodingindex.xml"
    with pinned_archive(archive_path) as archive:
        for member in archive:
            if member.name == name and member.isfile():
                with archive.extractfile(member) as xml:
                    data = xml.read()
                return (EncodingIndex(ElementTree.fromstring(data)),
                        dict(rule="arm-a64-encoding-index-1", archive_sha256=ARM_A64_REFERENCE_SHA256,
                             member=name, member_sha256=sha256(data).hexdigest()))
    raise ValueError("pinned Arm archive has no A64 encoding index")
