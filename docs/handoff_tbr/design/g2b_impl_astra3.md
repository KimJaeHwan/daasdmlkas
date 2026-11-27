REJECT

**두 적용 변경은 모두 타당합니다. 디코더 합의 길이를 G2b의 행 구간과 선행자 인덱스에 사용하는 제안도 채택합니다.** 반려 사유는 길이 누락으로 확정 가능한 경로를 잃는 문제와, 별도로 재현한 간접 분기 오탐입니다.

| `7a3cefe`에서 재현한 입력 | 현재 결과 | 교체 후 결과 |
|---|---|---|
| 길이가 `null`인 연속 두 행. 첫 행에서 레지스터에 상수를 쓰고 다음 행에서 그 레지스터를 주소로 STORE | `INDEX_INCOMPLETE` | 정의와 사용을 잇는 `[0, 1]` 경로와 `static_store_candidate` 1건 |
| 길이가 `null`인 6바이트 jump의 두 번째 바이트로 직접 분기 | `INDEX_INCOMPLETE` | `TARGET_NOT_ROW_START` |
| 검증 바이트 `FF E0`, 필수 표 전부 `jmp_near`, `indirect=True`, `target_kind="register"`. 같은 행의 p-code는 import 슬롯 LOAD를 주장 | `direct_slot` 1건 | 사이트 0건, `FORM_MISMATCH` |

1. **`CE` / `0F 34` 테스트.** 실제 G1은 첫 바이트부터 최대 15바이트를 디코더에 넘깁니다. 뒤를 `90`으로 채운 fixture는 그 호출 조건을 재현하며, 테스트는 소비 길이를 별도로 검사합니다. 짧은 창에서 `no_more_data`가 섞이면 현행 `trap_outcome()`은 계속 미해결로 분류합니다. [G1 창 구성](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/check.py:120) · [실제 voter 테스트](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tests/intra/test_decode_check.py)
2. **`transfer()`의 `None` 처리.** `length: null`에는 디코더 길이와 대조할 생산자 주장이 없습니다. 명시한 행 길이가 다르면 `FORM_MISMATCH`, vendor member가 다른 길이를 주장하면 `VENDOR_VIEW_CONFLICT`인 현재 구분이 맞습니다. 다만 `indirect=True`는 레지스터 분기와 메모리 분기에 공통입니다. 슬롯을 확정하려면 필수 표의 명시적 피연산자 종류도 확인해야 합니다. [transfer 판정](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/code_facts.py:759)
3. **길이 대체의 범위.** 구간에는 필수 표가 검증된 창 안에서 합의한 소비 길이를 씁니다. 순차 edge에는 조건이 하나 더 있습니다. G2a가 이미 `sequential`을 기록했고 목적지만 `length unavailable`이며, 디코더와 lift의 form이 일치해야 합니다. 기존 fallthrough와 충돌하거나 override가 있으면 경로를 열지 않습니다. `covering()`만 고치면 미확정 순차 edge 하나가 여전히 공간 전체를 `unknown_edges`에 넣으므로 STORE 사례가 복원되지 않습니다. [G2a 순차 목적지 생성](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/common_facts.py:434) · [G2b 인덱스](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/code_facts.py:609)

**검증 범위.** 현재 커밋에서 G2b는 로컬 **47 passed, 1 skipped**였습니다. 아래 교체 코드를 메모리에 적용하고 회귀 테스트를 추가한 결과는 seed 0과 1 각각 **48 passed, 1 skipped**였습니다. 건너뛴 항목은 POSIX와 빌드된 디코더를 요구하는 실제 voter 테스트입니다. 작업 트리에는 쓰지 않았습니다. 전체 587개, 다섯 Bundle 등가성, ABBA 수치는 제공한 결과를 사용했습니다. UE의 깨끗한 한 쌍은 시간 약 −1%, peak +7.4%로, 이번 반려의 근거는 정확성입니다. 교체 후 zlib의 1,776건과 1,793건 중 실제로 몇 건이 해소되는지는 실측 전입니다.

### `tools/decode_check/code_facts.py`

`Proof`와 `row_proof()`를 교체하고, 모듈 함수 `_index_length()`를 추가합니다. 보수적으로 소비 구간에 relocation이 하나라도 있으면 누락 길이의 대체 근거에서 제외했습니다. `verified`는 계속 G1 창의 길이이므로 compact 표현과 행 digest의 의미가 보존됩니다.

```python
@dataclass(frozen=True, slots=True)
class Proof:
    isa: str | None
    verified: int
    trap: tuple | None
    raw_ops: tuple
    candidate: bool
    signature: tuple | None
    failure: str | None
    form: tuple
    segment: bool
    decoded_length: int | None = None
    target_kind: str | None = None


def row_proof(f, result, lift, ballot, window, global_reason=False):
    import common_facts as cf
    import compare
    import decoders

    w = (result or {}).get("window") or {}
    n = w.get("verified", 0)
    data = (window or b"")[:n]
    isa = f.get("isa")
    if isa != "x86-64":
        return Proof(isa, n, None, (), False, None, None, (None, False), False)

    skip = set(lift.skipped if lift else ())
    if lift and lift.pattern in ("interrupt", "interrupt-return", "fault"):
        skip.add(1)
    ops = tuple(i for i, op in enumerate(f["ops"])
                if i not in skip and op["opcode"] in TRANSFER_OPS)
    trap = trap_outcome(result, ballot, data, global_reason)
    votes = [d for v, names in (("intel", decoders.INTEL_VOTERS), ("amd", decoders.AMD_VOTERS))
             for d in (ballot or {}).get(v, ()) if d.voter in names and d.amd == (v == "amd")]
    candidate = any(d.status == "ok" and d.flow in DECODER_FORMS for d in votes)
    sig = failure = decoded_length = target_kind = None
    if not _ballot_ok(ballot):
        failure = "BALLOT_MISSING"
    elif any(d.status != "ok" or type(d.length) is not int
             or not 1 <= d.length <= min(15, len(data)) for d in votes):
        failure = "VENDOR_VIEW_CONFLICT"
    else:
        length = votes[0].length
        if all(d.length == length for d in votes) and not any(
            a < length and a + size > 0 for a, size, _ in w.get("relocations", ())
        ):
            decoded_length = length
        signatures = {(d.flow, d.indirect, d.length, None if d.indirect else d.target)
                      for d in votes}
        if len(signatures) != 1:
            failure = "VENDOR_VIEW_CONFLICT"
        else:
            sig = signatures.pop()
            if sig[0] in ("call_near", "jmp_near") and sig[1]:
                kinds = {d.target_kind for d in votes}
                if kinds in ({"memory"}, {"register"}):
                    target_kind = kinds.pop()
                else:
                    failure = "VENDOR_VIEW_CONFLICT"

    prefix = compare._prefix_run(data)
    return Proof(isa, n, trap, ops, candidate, sig, failure, cf.producer_form(f, lift, data),
                 any(b in (0x64, 0x65) for b in prefix), decoded_length, target_kind)


def _index_length(row, proof):
    claimed = row["length"]
    length = proof.decoded_length if claimed is None else claimed
    if type(length) is not int or not 1 <= length <= 15:
        return 0
    if proof.decoded_length is not None and proof.decoded_length != length:
        return 0
    for member in (row.get("vendor_views") or {}).values():
        n = member["length"]
        if n is not None and (type(n) is not int or n != length):
            return 0
    return length
```

다음은 `ImportSites` 안에 넣을 메서드 전체입니다. `edge_coord()`는 새 메서드입니다. 인덱스 길이는 행당 1바이트이며, 원본 facts 행에 합성 길이나 edge를 쓰지 않습니다.

```python
    def __init__(self, binder, raw, kinds, complete, image=None, original=None):
        b = self.b = binder
        self.ff = b.ff
        self.raw = [raw[k] for k in b.keys]
        self.kind_of = {name: kind for kind, names in kinds.items() for name in names}
        self.complete = complete
        self.image, self.original = image, original
        self.starts, self.by_space = defaultdict(list), defaultdict(list)
        self.entries, self.unknown_edges = defaultdict(set), set()
        self.parents, self.endbr, self.stubs, self.states = {}, {}, {}, {}
        self.lengths = bytearray(_index_length(r, p) for r, p in zip(b.rows, b.proofs, strict=True))

        for i, r in enumerate(b.rows):
            space, a = r["space"], b.va[i]
            self.starts[space, a].append(i)
            self.by_space[space].append((a, i))
            f = self.raw[i]
            for target in f.get("flow_target_coords", ()):
                self.entries[tuple(target)].add((i, "encoded_target"))
            for target in f.get("recorded_landing_pads") or ():
                self.entries[tuple(target)].add((i, "pad"))
            for t in (r["transfer"], *(r.get("vendor_views") or {}).values()):
                edges = t.get("edges")
                if not isinstance(edges, list):
                    self.unknown_edges.add(space)
                    continue
                for e in edges:
                    to = self.edge_coord(i, e)
                    if to is not None:
                        self.entries[to].add((i, e["source"]))
                    elif e.get("source") in ("encoded_target", "sequential"):
                        self.unknown_edges.add(space)
        for spans in self.by_space.values():
            spans.sort()

    def edge_coord(self, i, edge):
        to = edge.get("to")
        if isinstance(to, dict) and "offset" in to:
            return to["space"], int(to["offset"], 16)
        if edge.get("source") != "sequential" or to != {"unobserved": "length unavailable"}:
            return None

        b = self.b
        r, p = b.rows[i], b.proofs[i]
        length = self.lengths[i]
        if (r["length"] is not None or not length or p.failure or p.signature is None
                or p.signature[:2] != p.form):
            return None
        coord = r["space"], (b.va[i] + length) % (1 << 64)
        f = self.raw[i]
        import lifting
        observed = lifting.continuation(f)
        override = f.get("override") or {}
        if (override.get("fallthrough_overridden") or f["flow"].get("is_override")
                or (observed is not None and observed != coord)):
            return None
        return coord

    def covering(self, space, va):
        for a, j in self.between(space, va - 14, va):
            length = self.lengths[j]
            if not length or a + length > va:
                yield j, bool(length)

    def predecessor(self, i):
        import lifting

        if i in self.parents:
            return self.parents[i]
        b = self.b
        r = b.rows[i]

        def same(j):
            s = b.rows[j]
            return (s["observation"], s["view"]) == (r["observation"], r["view"])

        here = r["space"], b.va[i]
        seq = [j for j, role in self.entries[here] if role == "sequential" and same(j)]
        parent = None
        if len(seq) == 1:
            j = seq[0]
            s = b.rows[j]
            edges = s["transfer"].get("edges")
            if (self.entries[here] == {(j, "sequential")} and self.lengths[j]
                    and b.va[j] + self.lengths[j] == here[1]
                    and s["transfer"]["kind"] == "none" and isinstance(edges, list) and len(edges) == 1
                    and edges[0]["source"] == "sequential" and self.edge_coord(j, edges[0]) == here
                    and not any(same(k) for k, _ in self.covering(*here))
                    and not any(same(k) for k, _ in self.covering(r["space"], b.va[j]))
                    and not any(a > b.va[j] and same(k)
                                for a, k in self.between(r["space"], b.va[j], here[1]))
                    and sum(same(k) for k in self.starts[r["space"], b.va[j]]) == 1
                    and sum(same(k) for k in self.starts[here]) == 1
                    and not any(o["opcode"] in lifting.FLOW_OPS for o in self.raw[j]["ops"])):
                parent = j
        self.parents[i] = parent
        return parent

    def transfer(self, i, n):
        import common_facts as cf

        b = self.b
        r, p = b.rows[i], b.proofs[i]
        flow, ind = p.form
        opcode = self.raw[i]["ops"][n]["opcode"]
        mem = (r["transfer"].get("target_value") or {}).get("memory", {})
        if ind:
            operand = self.raw[i]["ops"][n]["inputs"][0]
            if p.segment or mem.get("segment_base") is not None:
                raise Unread("SEGMENT_BASE")
            if (operand and operand["size"] != 8) or (mem and mem["size"] != 8):
                raise Unread("POINTER_WIDTH")
            if r["space"] != b.space or (mem and mem["space"] != b.space):
                raise Unread("SPACE_MISMATCH")
            if operand and operand["kind"] in ("REGISTER", "UNIQUE"):
                for op in reversed(self.raw[i]["ops"][:n]):
                    o = op.get("output")
                    if o and _overlaps(o, operand):
                        if o == operand and op["opcode"] == "LOAD":
                            sel = op["inputs"][0]
                            if sel and sel["kind"] == "CONSTANT" and sel["offset"] != b.space:
                                raise Unread("SPACE_MISMATCH")
                        break

        if p.failure:
            raise Unread(p.failure)
        fl, indirect, length, dst = p.signature
        if (fl, indirect) != (flow, ind) or fl not in DECODER_FORMS:
            raise Unread("FORM_MISMATCH")
        form = DECODER_FORMS[fl]
        if r["space"] != b.space:
            raise Unread("SPACE_MISMATCH")
        if r["length"] is not None and length != r["length"]:
            raise Unread("FORM_MISMATCH")
        if (ind != (opcode in ("CALLIND", "BRANCHIND")) or
                TRANSFER_OPS[opcode] != form and not (form == "call" and opcode == "BRANCH")):
            raise Unread("FORM_MISMATCH")

        role = cf.TAKEN if form == "jcc" else cf.DIRECT
        edge = None
        for vendor in (None, *cf.VENDORS) if r.get("vendor_views") else (None,):
            m = cf.member(r, vendor)
            if (m["length"] is not None and m["length"] != length) or (
                    ind and m.get("target_value") != r["transfer"]["target_value"]):
                raise Unread("VENDOR_VIEW_CONFLICT")
            if not ind:
                es = [e for e in m["edges"] if cf.triple(e) == role] if isinstance(m["edges"], list) else []
                if len(es) != 1 or not isinstance(es[0].get("to"), dict) or "offset" not in es[0]["to"]:
                    raise Unread("VENDOR_VIEW_CONFLICT" if vendor else "TARGET_LIFT_U")
                to = es[0]["to"]
                if to["space"] != b.space:
                    raise Unread("SPACE_MISMATCH")
                if dst != int(to["offset"], 16):
                    raise Unread("VENDOR_VIEW_CONFLICT" if vendor or r.get("vendor_views") else "FORM_MISMATCH")
                edge = dict(zip(cf.EC, role), to=to)

        step = dict(row=i, op=n, step="ghidra_pcode")
        if edge is not None:
            step["edge"] = edge
            return form, False, dst, step
        if mem and p.target_kind != "memory":
            raise Unread("FORM_MISMATCH")
        addr = mem.get("address", {})
        if set(addr) != {"constant", "width"} or addr["width"] != 64:
            raise Unread("COMPUTED_TARGET")
        return form, True, int(addr["constant"], 16), step

    def read_endbr(self, i):
        length = self.lengths[i]
        if not length:
            raise Unread("INDEX_INCOMPLETE")
        if length != 4:
            return False
        va = self.b.va[i]
        if va not in self.endbr:
            try:
                if self.image is None:
                    raise Unread("MAP_INDETERMINATE")
                raw, basis = runtime_read(self.image, self.original, va - self.b.base, 4)
                self.endbr[va] = (basis if raw == ENDBR64 else False), None
            except Unread as exc:
                self.endbr[va] = None, exc.reason
        result, why = self.endbr[va]
        if why:
            raise Unread(why)
        return result

    def thunk(self, j):
        b = self.b
        path = []
        if b.rows[j]["transfer"]["kind"] == "none":
            marker = self.read_endbr(j)
            if marker:
                if b.proofs[j].signature != ("none", False, 4, None):
                    raise Unread("TARGET_LIFT_U")
                path.append(dict(row=j, op=None, **marker))
                r = b.rows[j]
                va = b.va[j] + 4
                ns = [k for k in self.starts[r["space"], va] if b.rows[k]["view"] == r["view"]
                      and b.rows[k]["observation"] == r["observation"]]
                edges = r["transfer"]["edges"]
                if (len(ns) != 1 or len(edges) != 1 or edges[0]["source"] != "sequential"
                        or self.edge_coord(j, edges[0]) != (r["space"], va)
                        or any(b.rows[k]["observation"] == r["observation"] and b.rows[k]["view"] == r["view"]
                               for k, _ in self.covering(r["space"], va))):
                    raise Unread("TARGET_LIFT_U")
                j = ns[0]
        p = b.proofs[j]
        n = self.exact(j)
        if n is None:
            if p.raw_ops or p.candidate or b.rows[j]["transfer"]["kind"] == "unknown" or p.failure:
                raise Unread("TARGET_LIFT_U")
            if path:
                raise Unread("ELF_STUB_UNSUPPORTED" if self.ff.format == "elf" else "TARGET_LIFT_U")
            return None
        form, ind, dst, step = self.transfer(j, n)
        if form == "jump":
            if not ind:
                raise Unread("MULTI_HOP")
            return dst, path + [step]
        if path:
            raise Unread("ELF_STUB_UNSUPPORTED" if self.ff.format == "elf" else "TARGET_LIFT_U")
        return None
```

### `tests/intra/test_decode_check.py`

기존 `_g2b_votes()`를 아래 함수로 교체하고 회귀 테스트를 추가합니다. STORE 양성은 reader 재구성까지 확인하고, ballot 누락·창 초과·길이 불일치·relocation·fallthrough 충돌은 각각 차단되는지 검사합니다.

```python
def _g2b_votes(flow="none", length=1, indirect=False, target=None, status="ok", vector=None,
               target_kind=None):
    if target_kind is None:
        target_kind = "none"
        if flow in ("call_near", "jmp_near"):
            target_kind = "memory" if indirect else "direct"
    return {v: tuple(decoders.Decoded(name, "fixture", v == "amd", status,
                                      length if status == "ok" else 0, flow=flow, indirect=indirect,
                                      target=target, int_vector=vector, target_kind=target_kind)
                     for name in names)
            for v, names in (("intel", decoders.INTEL_VOTERS), ("amd", decoders.AMD_VOTERS))}


def test_g2b_missing_length_index_and_operand():
    from dataclasses import replace

    def no_length(e):
        fid, f, _, votes, result, data = e
        f = dict(f, length=None)
        return fid, f, lifting.identify(f), votes, result, data

    prev = no_length(_entry(_plain([_op("COPY", [_c(START)], _r(RAX_))]), "90"))
    use = no_length(_entry(_plain([_store(_r(RAX_))], START + 1), "90"))
    doc, ev, args = _case([prev, use], reader=True)
    evidence.bind_common_facts(ev, doc, **args)
    assert all(r["length"] is None for r in doc["rows"])
    site, = doc["program"]["code"]["sites"]
    assert site["static_basis"]["register_values"][0]["path"] == [0, 1]

    missing = (*prev[:3], None, *prev[4:])
    relocated = _entry(prev[1], "90", prev[3], rel=((0, 1, "R"),))
    long_vote = _entry(prev[1], "90", _g2b_votes(length=2))
    split = dict(prev[3], amd=tuple(replace(d, length=2) for d in prev[3]["amd"]))
    disagreement = _entry(prev[1], "9090", split)
    wrong_ft = _entry(dict(prev[1], fallthrough=START + 2), "90")
    for blocked in (missing, relocated, long_vote, disagreement, wrong_ft):
        code = _case([blocked, use])
        assert _reasons(code, "code_write", "static_store") == {
            "INDEX_INCOMPLETE": [dict(row=1, op=0)]}

    marker = no_length(_entry(_plain([], START, 4), g.ENDBR64))
    jump = no_length(_slot(START + 4, BASE + 0x5000, False))
    caller = no_length(_direct(START + 32, START, True))
    code = _case([caller, marker, jump], _g2b_elf())
    assert g.summary(code)["import_routes"] == {"via_thunk": 1, "thunk_row": 1}

    mid = no_length(_direct(START + 32, START + 5))
    assert "TARGET_NOT_ROW_START" in _reasons(_case([mid, jump], _g2b_elf()))

    votes = _g2b_votes("jmp_near", 2, True, target_kind="register")
    code = _case([_entry(jump[1], "ffe0", votes)], _g2b_elf())
    assert not code["sites"] and "FORM_MISMATCH" in _reasons(code)
```