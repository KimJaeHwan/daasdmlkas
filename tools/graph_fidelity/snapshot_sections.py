"""Disk-backed access to the named sections in a gzip semantic snapshot."""
from __future__ import annotations

import gzip
import json
import mmap
import re
import shutil
from contextlib import contextmanager
from tempfile import TemporaryFile

_STRING = rb'"[^"\\]*(?:\\.[^"\\]*)*"'
_STRUCTURAL = re.compile(_STRING + rb'|[\[\]{}"]', re.DOTALL)
_KEY = re.compile(_STRING, re.DOTALL)
_SPACE = re.compile(rb'[ \t\r\n]*')
_VALUE_END = re.compile(rb'[ \t\r\n,}\]]')
_SHARE_IDENTIFIERS_ABOVE = 32 << 20


def _end(buffer, start):
    """Find a value boundary. JSON decoding still validates each indexed value."""
    first = buffer[start:start + 1]
    if first == b'"':
        match = _KEY.match(buffer, start)
        if match:
            return match.end()
    elif first in (b"{", b"["):
        stack = []
        for match in _STRUCTURAL.finditer(buffer, start):
            token = match[0]
            if token in (b"{", b"["):
                stack.append(b"}" if token == b"{" else b"]")
            elif token in (b"}", b"]"):
                if not stack or stack.pop() != token:
                    break
                if not stack:
                    return match.end()
            elif token == b'"':
                break
    elif first:
        match = _VALUE_END.search(buffer, start)
        if match and match.start() > start:
            return match.start()
    raise ValueError(f"invalid or truncated JSON value at byte {start}")


def _object(buffer, start, *, sections=None):
    """Yield the immediate member names and byte ranges of one JSON object."""
    if buffer[start:start + 1] != b"{":
        raise ValueError(f"expected a JSON object at byte {start}")
    offset = _SPACE.match(buffer, start + 1).end()
    if buffer[offset:offset + 1] == b"}":
        return offset + 1
    seen = set()
    while True:
        key = _KEY.match(buffer, offset)
        if key is None:
            raise ValueError(f"expected an object key at byte {offset}")
        name = json.loads(key[0].decode("utf-8"))
        if name in seen:
            raise ValueError(f"duplicate object key {name!r}")
        seen.add(name)
        offset = _SPACE.match(buffer, key.end()).end()
        if buffer[offset:offset + 1] != b":":
            raise ValueError(f"expected ':' at byte {offset}")
        start_value = _SPACE.match(buffer, offset + 1).end()
        if name == "sections" and sections is not None:
            stop_value = _index_object(buffer, start_value, sections)
        else:
            stop_value = _end(buffer, start_value)
        yield name, (start_value, stop_value)
        offset = _SPACE.match(buffer, stop_value).end()
        token = buffer[offset:offset + 1]
        if token == b"}":
            return offset + 1
        if token != b",":
            raise ValueError(f"expected ',' or '}}' at byte {offset}")
        offset = _SPACE.match(buffer, offset + 1).end()


def _index_object(buffer, start, sections):
    entries = _object(buffer, start)
    while True:
        try:
            name, bounds = next(entries)
        except StopIteration as end:
            return end.value
        sections[name] = bounds


def _array(buffer, start):
    offset = _SPACE.match(buffer, start + 1).end()
    while buffer[offset:offset + 1] != b"]":
        stop = _end(buffer, offset)
        yield offset, stop
        offset = _SPACE.match(buffer, stop).end()
        if buffer[offset:offset + 1] == b"]":
            break
        offset = _SPACE.match(buffer, offset + 1).end()


def _display(buffer, extent):
    start, stop = extent
    if stop - start > 8192:
        return bytes(buffer[start:start + 200]).decode("utf-8", errors="replace") + "…"
    return json.loads(bytes(buffer[start:stop]).decode("utf-8"))


def _difference(a, ax, b, bx, path):
    if a[ax[0]] == b[bx[0]]:
        if a[ax[0]:ax[1]] == b[bx[0]:bx[1]]:
            return None
        kind = a[ax[0]]
        if kind == ord("{"):
            left, right = dict(_object(a, ax[0])), dict(_object(b, bx[0]))
            for key in sorted(left.keys() | right.keys()):
                child = f"{path}.{key}"
                if key not in left or key not in right:
                    return (child, _display(a, left[key]) if key in left else "<absent>",
                            _display(b, right[key]) if key in right else "<absent>")
                found = _difference(a, left[key], b, right[key], child)
                if found:
                    return found
            return None
        if kind == ord("["):
            left, right = _array(a, ax[0]), _array(b, bx[0])
            index = 0
            while True:
                x, y = next(left, None), next(right, None)
                if x is None or y is None:
                    if x != y:
                        return (f"{path}.length", index + (0 if x is None else 1 + sum(1 for _ in left)),
                                index + (0 if y is None else 1 + sum(1 for _ in right)))
                    return None
                found = _difference(a, x, b, y, f"{path}[{index}]")
                if found:
                    return found
                index += 1
    if any(mark in b"{[" for mark in (a[ax[0]], b[bx[0]])):
        return path, _display(a, ax), _display(b, bx)
    x, y = (json.loads(bytes(buffer[start:stop]).decode("utf-8"))
            for buffer, (start, stop) in ((a, ax), (b, bx)))
    return (path, x, y) if type(x) is not type(y) or x != y else None


class Sections:
    """Indexes values in a temporary file and decodes only the requested value."""

    def __init__(self, stream):
        self.stream = stream
        self.ranges = {}

    def __iter__(self):
        return iter(self.ranges)

    def __contains__(self, name):
        return name in self.ranges

    def __getitem__(self, name):
        start, stop = self.ranges[name]
        if stop - start <= _SHARE_IDENTIFIERS_ABOVE:
            return self._decode(start, stop)

        # Large function sections repeat scope digests, operation keys and
        # type tags in millions of rows. Share strings only within this read.
        identifiers = {}

        def share_identifiers(row):
            for field in ("type", "enum", "bytes", "operation_key"):
                value = row.get(field)
                if isinstance(value, str):
                    row[field] = identifiers.setdefault(value, value)
            return row

        self.stream.seek(start)
        if self.stream.read(1) != b"{":
            return self._decode(start, stop, share_identifiers)
        # Parse the large function's fields one at a time. This avoids
        # keeping the entire encoded section next to its decoded rows.
        with mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_READ) as buffer:
            fields = dict(_object(buffer, start))
        return {key: self._decode(*bounds, share_identifiers) for key, bounds in fields.items()}

    def _decode(self, start, stop, object_hook=None):
        self.stream.seek(start)
        text = self.stream.read(stop - start).decode("utf-8")
        return json.loads(text, object_hook=object_hook)

    def write(self, name, chunks):
        self.stream.seek(0, 2)
        start = self.stream.tell()
        for chunk in chunks:
            self.stream.write(chunk)
        self.ranges[name] = (start, self.stream.tell())

    def first_difference(self, name, other):
        self.stream.flush()
        other.stream.flush()
        with (mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_READ) as left,
              mmap.mmap(other.stream.fileno(), 0, access=mmap.ACCESS_READ) as right):
            # Views compare slices without allocating copies of the large section.
            with memoryview(left) as a, memoryview(right) as b:
                return _difference(a, self.ranges[name], b, other.ranges[name], "$")


@contextmanager
def open_snapshot(path):
    with TemporaryFile() as stream:
        with gzip.open(path, "rb") as compressed:
            shutil.copyfileobj(compressed, stream, 1 << 20)
        stream.flush()
        if not stream.tell():
            raise ValueError("empty snapshot")
        sections = Sections(stream)
        header = {}
        seen_sections = False
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as buffer:
            entries = _object(buffer, _SPACE.match(buffer).end(), sections=sections.ranges)
            while True:
                try:
                    name, (start, stop) = next(entries)
                except StopIteration as end:
                    if _SPACE.match(buffer, end.value).end() != len(buffer):
                        raise ValueError("trailing data after snapshot")
                    break
                if name == "sections":
                    seen_sections = True
                else:
                    header[name] = json.loads(buffer[start:stop].decode("utf-8"))
        if header.get("complete") is not True:
            raise ValueError("incomplete snapshot")
        if not isinstance(header.get("meta"), dict) or not isinstance(header.get("digests"), dict):
            raise ValueError("missing snapshot meta or digests")
        if not seen_sections or sections.ranges.keys() != header["digests"].keys():
            raise ValueError("snapshot section and digest inventories differ")
        yield {**header, "sections": sections}
