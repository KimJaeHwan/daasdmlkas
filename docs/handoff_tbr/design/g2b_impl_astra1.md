REJECT

`fde5afb`에는 같은 입력에서 **확정할 수 없는 import와 STORE를 양성 site로 내보내는 경로**가 있습니다. 또한 `g2b-1` reader가 compact 길이와 name-table digest를 검증하지 않습니다. 다섯 Bundle의 기존 G2a 결과가 보존됐다는 등가성 결과와 별개로, 새 `program.code`의 정확성에 영향을 주는 문제입니다.

읽기 전용으로 `c15a29a..fde5afb`를 검토했습니다. 추가된 G2b 테스트는 직접 실행해 **26 passed**를 확인했습니다. 전체 565개, 다섯 Bundle의 등가성 및 비용 측정은 제시된 결과를 사용했습니다. 아래 교체 코드는 작업 트리에 적용하지 않았습니다.

### 직접 확인한 반례

| 입력 | `fde5afb` 결과 | 필요한 결과 |
|---|---|---|
| 기존 `_g2b_import_case()`의 `VirtualAlloc` 호출. 두 행 모두 ballot과 window가 없음 | `direct_slot`, `candidate:true`, `rwx_registers=["R9"]` | 필수 decoder 근거가 없어 import 양성 0 |
| 기존 `_g2_golden()`의 `66 E8`. Intel 길이 6, AMD 길이 4, 목적지도 다름 | `_form()`이 `("call", None)` 반환 | `VENDOR_VIEW_CONFLICT` |
| CMOV로 식별된 `CBRANCH next; COPY RAX,constant` 다음 행에서 `STORE [RAX]` | `[0x140001080,0x140001084)`에 `static_store_candidate` 1개 | COPY 실행 여부가 미정이므로 `STORE_ADDRESS_NOT_CONSTANT` |
| PE fixture에서 `UNWIND_INFO` 헤더 `[0x2410,0x2414)`를 `written`에 포함 | `.xdata [0x2410,0x241c)`를 생성하고 마지막 4바이트의 `file_record`만 basis로 기록 | 해당 runtime read는 `LOADER_WRITTEN` |
| OFT=0, stamp=0인 배열에 유효한 `VirtualProtect` 이름과 예약 비트가 켜진 ordinal을 함께 배치 | `import_state="complete"`, `VirtualProtect`와 `#5` 채택 | 해당 fallback 배열 전체 `ILT_ENTRY_INVALID` |
| 동일한 정상 jump ballot을 주고 stub의 위치와 남은 바이트 수만 변경 | 실행 영역 끝의 6바이트 및 ENDBR 포함 10바이트 stub은 실패. 비실행 영역의 11바이트 버퍼는 성공 | 앞의 두 경우는 정확한 길이로 인정. 비실행 영역은 양성 0 |
| `summary()`에 `name_table_sha256="WRONG"` 전달 | 보고서에도 `WRONG` 출력 | 실제 JSON 바이트와 불일치하므로 거부 |

### 1. Import 판정과 thunk

`decoder_flows()`는 `flow`만 남깁니다. `_form()`은 ballot이 없으면 p-code opcode만으로 성공하고, ballot이 있더라도 직접·간접, 길이, 목적지 차이를 보지 못합니다. `_thunk()`는 대상 행에 `_form()`조차 적용하지 않습니다. 그 결과 source와 thunk 각각에서 거짓 양성이 가능합니다. 반대 방향으로, 부분 ballot에 남아 있는 필수 voter 하나가 call을 보더라도 `decoder_flows()`가 `None`을 반환해 decoder-only 후보를 잃습니다. [collector](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/decode_check.py:308) · [decoder_flows](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/code_facts.py:952) · [_form](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/code_facts.py:1130)

후보 신호와 확정 근거를 따로 보존해야 합니다. 아래 코드는 collector에서 raw ballot을 폐기하기 전에 호출할 교체 코드입니다. `result.attributes`나 G1 verdict를 요구하지 않습니다.

```python
def transfer_ballot(ballot, verified):
    import decoders

    expected = {
        "intel": decoders.INTEL_VOTERS,
        "amd": decoders.AMD_VOTERS,
    }
    votes = [
        d
        for vendor, names in expected.items()
        for d in (ballot or {}).get(vendor, ())
        if d.voter in names and d.amd == (vendor == "amd")
    ]
    candidate = any(d.status == "ok" and d.flow in DECODER_FORMS for d in votes)

    if not _ballot_ok(ballot):
        return candidate, None, "BALLOT_MISSING"
    if any(d.status != "ok" or not 0 < d.length <= verified for d in votes):
        return candidate, None, "VENDOR_VIEW_CONFLICT"

    signatures = {
        (d.flow, d.indirect, d.length, d.target if not d.indirect else None)
        for d in votes
    }
    if len(signatures) != 1:
        return candidate, None, "VENDOR_VIEW_CONFLICT"
    return candidate, signatures.pop(), None
```

이 결과를 사용하는 `run()`, `_direct()`, `_thunk()`의 교체 규칙은 다음과 같습니다.

- `lift.skipped`와 식별된 trap 내부 op를 collector에서 보존해 해당 **op**를 raw 후보에서 제외합니다. 현재의 `t.kind == "trap" or trap_site` 행 전체 `continue`는 서로 다른 근거의 충돌까지 지웁니다. 제외 후 남은 raw 후보 또는 decoder 후보가 있고 exact transfer가 없으면 각 raw ordinal에 `TRANSFER_UNBOUND`를 기록합니다. raw 후보가 없으면 `(row,null)` 한 건입니다. 정상 CMOV·REP 내부 분기는 import 예외 0건입니다.
- exact op는 해당 observation의 raw op에 다시 바인딩합니다. 간접 메모리의 `SEGMENT_BASE`, `POINTER_WIDTH`, `SPACE_MISMATCH`를 E3 순서로 적용하고, vendor 충돌, `FORM_MISMATCH`, `COMPUTED_TARGET`을 구별합니다. `_form()`에서 `flows is None`이면 성공시키는 분기를 삭제합니다. 직접 분기는 agreed form·길이·목적지와 G2a의 해당 vendor member를 확인하고, `jcc`는 `("taken","encoded_target")` edge만 선택합니다. 경로 basis에도 선택한 edge를 남깁니다. `BRANCH`가 G2a에서 `call $+5`로 식별되는 경우처럼 raw opcode 하나로 form을 정할 수 없는 경우에는 exact lift와 transfer를 함께 사용합니다.
- 대상은 같은 image space·load base의 적용 가능한 view에서 찾습니다. 동일 `id`가 여러 observation에 있어도 lift나 slot은 다를 수 있습니다. `rows[0]` 선택을 삭제하고 대상별 결과가 일치하는지 확인합니다. 명확한 mid-row는 `TARGET_NOT_ROW_START`, 누락된 행 또는 미상 길이 때문에 분류할 수 없으면 `INDEX_INCOMPLETE`, 완전한 탐색에서 대상이 없으면 `TARGET_OUTSIDE_ROWS`입니다. 현재 `_inside()`는 미상 길이를 무시합니다.
- thunk의 `BRANCHIND`에도 source와 같은 ballot·form·64비트 memory-slot 검사를 적용합니다. `endbr64` 행은 정확한 4바이트와 길이 4, 같은 observation·space·view의 유일한 연속 후속 행이 필요합니다. `endbr64`와 jump 각각의 근거를 남깁니다. 대상 lift 미상은 `TARGET_LIFT_U`, 식별했으나 해석할 수 없는 ELF stub은 `ELF_STUB_UNSUPPORTED`입니다.
- `_thunk()`의 8회 chain 탐색을 제거합니다. 허용된 ENDBR 다음의 slot jump를 제외하고 **추가 direct jump를 한 번 더 따라야 하는 순간 `MULTI_HOP`**입니다. 지금은 두 번째 jump 뒤에 일반 행이 나오면 source를 결정적 음성으로 바꿉니다. 확정된 일반 non-thunk 행에 직접 도착한 경우만 음성입니다.
- `via_thunk` source와 독립적으로 성립하는 `thunk_row`를 각각 검사합니다. 여러 caller가 공유해도 `(row,transfer op,kind)` 기준 한 건입니다. `NO_RWX_REGISTER`도 source별 결과를 유지합니다. [thunk와 chain](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/code_facts.py:1182) · [후보와 집계](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/code_facts.py:1256)

**`via_stub_bytes`에 대한 판정은 조건부 채택입니다.** row가 없는 PLT·PE thunk를 `file_runtime` 바이트와 실제 ballot으로 식별하는 방식은 타당합니다. zlib 26건과 clang 4건은 이 경로를 유지할 실질적 이유입니다. 현재 구현의 11/7바이트 선읽기, 실행 권한 미검사, target space 미전달, 불완전한 index보다 먼저 성공하는 순서는 승인할 수 없습니다. r3의 `TARGET_OUTSIDE_ROWS`에 대한 좁은 예외이므로 네 번째 route와 근거를 설계에 명시해야 합니다.

다음은 `_stub_bytes()`의 교체 코드입니다. 호출 위치는 같은 space·base에서 **확정된 행 시작·내부가 없고 그 판정에 필요한 index가 완전한 경우**입니다. 실패 시 기존 target 분류를 유지합니다.

```python
def _stub_bytes(self, space, va):
    import decoders

    b = self.b
    if self.image is None or not self.ff.ok or space != b.space:
        return None
    start = va - b.base

    def read(offset, size):
        return runtime_read(self.image, self.original, start + offset, size)

    try:
        first, _ = read(0, 1)
        skip = 0
        if first == b"\xf3":
            prefix, _ = read(0, len(ENDBR64))
            if prefix != ENDBR64:
                return None
            skip = len(ENDBR64)

        first, _ = read(skip, 1)
        bnd = int(first == b"\xf2")
        length = bnd + 6
        total = skip + length
        if not any(r.start <= start and start + total <= r.end
                   for r in self.ff.code if r.executable and r.end is not None):
            return None
        raw, basis = read(0, total)
    except Unread:
        return None

    jmp = raw[skip:]
    if jmp[bnd:bnd + 2] != b"\xff\x25":
        return None
    at = va + skip
    ballot = decoders.ballot(jmp, at)
    if not _ballot_ok(ballot):
        return None
    if any(d.status != "ok" or d.flow != "jmp_near" or not d.indirect
           or d.length != length
           for vendor in ("intel", "amd") for d in ballot[vendor]):
        return None

    disp = int.from_bytes(jmp[bnd + 2:], "little", signed=True)
    slot = (at + length + disp) % (1 << 64)
    step = {
        "stub": _hx(va), "space": space, "load_base": _hx(b.base),
        "length": total, "file_runtime": basis["file_runtime"],
        "jump_offset": skip,
        "decoders": {v: ballot_digest(ballot[v]) for v in ("intel", "amd")},
    }
    return "slot", slot, [step]
```

### 2. 레지스터 경로, RWX, STORE

가장 중요한 오류는 `_predecessor()`가 `transfer.kind == "none"`을 확인한 뒤 raw op 중 `CALLOTHER`만 막는 것입니다. CMOV·REP·internal lift는 외부 transfer가 없어도 내부 분기가 있습니다. 현재 코드는 그 분기 뒤의 조건부 정의를 무조건 실행된 것처럼 재생합니다. 앞의 CMOV 반례는 실제 `StoreSites.run()`에서 양성이 됐습니다. [경로와 정의](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/code_facts.py:984) · [STORE](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/code_facts.py:1432)

`_predecessor()` 끝의 raw-op 검사와 `register_values()`의 경로 구성을 다음과 같이 교체해야 합니다. `ordinal`은 호출·점프의 실제 transfer ordinal 또는 STORE ordinal입니다.

```python
# _predecessor(), 유일한 predecessor j와 sequential edge를 확인한 뒤
import lifting

prior = self.raw[self.keys[j]]
if prior["space"] != r["space"]:
    return None
if any(op["opcode"] in lifting.FLOW_OPS for op in prior["ops"]):
    return None
return j
```

```python
def register_values(self, i, ordinal):
    if not self.complete:
        return [], "INDEX_INCOMPLETE"

    backward = []
    seen = {i}
    j = self._predecessor(i)
    while j is not None:
        if j in seen:
            return [], "INDEX_INCOMPLETE"
        seen.add(j)
        backward.append(j)
        j = self._predecessor(j)

    execution = list(reversed(backward))
    position = {row: n for n, row in enumerate(execution)}
    values = _Values()
    for row in execution:
        for n, op in enumerate(self.raw[self.keys[row]]["ops"]):
            values.apply(row, n, op)

    out = []
    for (space, offset, size), d in sorted(values.defs.items()):
        out.append({
            "register": {"name": GPR[offset & ~7], "space": space,
                         "offset": offset, "size": size},
            "value": {"constant": _hx(d["value"]), "width": 8 * size},
            "definition": {"row": d["row"], "op": d["op"]},
            "use": {"row": i, "op": ordinal},
            "path": execution[position[d["row"]]:] + [i],
            "basis": "ghidra_pcode",
            "holds_if": [PREMISE, LINEAR_PREMISE],
        })
    return out, None
```

아래 변경도 함께 필요합니다.

- predecessor 후보는 같은 observation·space·view의 **행 구간**으로 먼저 결정합니다. 미상 길이, 겹치는 행, 여러 후보, 다른 진입 edge, landing pad에서 중단합니다. `incoming`은 기본 transfer 외에 관측된 `flow_target_coords`와 적용 가능한 vendor edge도 반영해야 합니다. 같은 row id라는 이유로 서로 다른 observation의 상충하는 edge를 합치면 안 됩니다. Bundle의 행 집합은 완전하지만 관측 edge index가 불완전한 경우에도 교차 행 전파는 `INDEX_INCOMPLETE`입니다. 관측되지 않은 computed entry에 대한 `LINEAR_PREMISE`는 그대로 필요합니다.
- `len(path) < 64`와 `sorted(path)`를 제거합니다. 전자는 유효한 65행 전 정의를 잃고, 후자는 문자열 id 기준의 facts 순서를 실행 순서로 사용합니다. 정상 경로 길이가 비용에 영향을 주면 predecessor와 정의 상태를 캐시합니다.
- `_Values.apply()`의 **모든 overlapping output에 대한 kill**은 유지합니다. 여기에 64비트 `constant` 또는 상수만의 `add`로 확정되는 LEA를 추가합니다. G2a `value(f, output, n + 1)`의 식과 사용 op를 이용할 수 있습니다. `COPY`는 입출력 폭 일치, `INT_ZEXT` 특례는 같은 GPR 하위 32비트 정의와 그 정의를 읽는 64비트 출력인지 확인합니다. `xor/sub r,r`는 같은 좌표·폭의 두 입력을 확인합니다. `AL`, `AH` 등 부분 정의는 해당 byte slice로 표시하고 RWX에서는 제외합니다. `width >= 32`는 `width in (32,64)`와 GPR 시작 offset 일치로 바꿉니다. PE `0x40/0x80`, ELF `7`의 **정확한 값 비교**, `arguments:[]`, `protection_argument:U`는 맞습니다.
- `dynamic_resolution`에서 `requested_name:U("NO_ABI_BASIS")`만 쓰고 끝납니다. 상위 비트까지 확정된 64비트 레지스터가 파일의 읽기 전용 매핑을 가리키고, NUL까지 모든 바이트가 `file_runtime` 검사를 통과하면 그 **레지스터 값에** `string:{text,file_runtime,register}`를 추가합니다. `record_cstring()`은 먼저 NUL 이후까지 `runtime_read()`하므로 뒤쪽의 무관한 loader write 때문에 정상 문자열을 잃습니다. NUL 위치를 `file_record`로 찾고 실제 문자열과 NUL의 정확한 길이만 runtime·읽기 전용 검사를 하십시오.
- STORE에서 RSP를 일괄 제외하는 조건을 삭제합니다. 64비트 RSP 상수가 확정된 경로도 설계상 유효합니다. 반대로 좁은 `pre_register` 값을 명시적 확장 근거 없이 64비트 주소로 사용하면 안 됩니다. `cf.value()`의 `used` ordinal을 버리지 말고, 실제로 참조한 각 register leaf의 definition/use/path와 결합해 `static_basis`에 기록합니다. `_regs()`가 경로를 숫자순 집합으로 합치는 코드도 삭제합니다. `INDEX_INCOMPLETE` 때문에 경로를 쓸 수 없을 때와 실제 비상수 주소를 구별합니다. 같은 행 안에서 증명되는 주소는 계속 허용합니다.
- STORE site에 공통 필드 `form`이 없습니다. `"form":"store"`를 넣고, `(row,op)`별 결과를 유지합니다. `file_facts.ok == False`이거나 image 좌표를 바인딩할 수 없는 경우에는 빈 code 목록만 보고 음성 처리하지 말고 `TARGET_MAPPING_U`를 냅니다. 다른 것으로 **확정된** space는 검사한 음성입니다. `end > 2**64`인 wrap 처리와 확정된 여러 code region을 모두 기록하는 동작은 유지합니다.

### 3. 파일 바이트와 import parser

`file_record`와 `file_runtime`을 나눈 API는 적절합니다. 문제는 실제 read 위치와 실패 전파입니다. [파일 읽기](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/code_facts.py:65) · [PE unwind](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/code_facts.py:202) · [PE imports](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/code_facts.py:289) · [ELF imports](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/code_facts.py:498)

`record_read()`는 최대 두 mapping 조각까지만 허용하고, 두 번째 조각이 zero 또는 ambiguous이면 `TRUNCATED`로 바꿉니다. 다음 코드로 한 파일 구간 전체를 검사할 수 있습니다.

```python
def record_read(image, data, rva, size):
    if size < 0:
        raise Unread("OUTSIDE_FILE")
    if size == 0:
        return b"", {"file_record": [0, 0]}

    cursor = rva
    end = rva + size
    first_offset = None
    while cursor < end:
        item = image.at(cursor)
        if item is None:
            raise Unread("OUTSIDE_FILE" if cursor == rva else "TRUNCATED")
        if item.kind == "ambiguous":
            raise Unread("AMBIGUOUS_MAPPING")
        if item.kind == "zero":
            raise Unread("ZERO_FILL")
        if item.kind != "file" or item.end <= cursor:
            raise Unread("OUTSIDE_FILE")

        offset = item.file_offset + cursor - item.start
        if first_offset is None:
            first_offset = offset
        if offset != first_offset + cursor - rva:
            raise Unread("NONCONTIGUOUS")
        stop = min(end, item.end)
        if offset < 0 or offset + stop - cursor > len(data):
            raise Unread("OUTSIDE_FILE")
        cursor = stop

    return data[first_offset:first_offset + size], {"file_record": [first_offset, size]}
```

`runtime_read()`에서는 `written` 또는 `relocations`가 없거나 `indeterminate`면 `MAP_INDETERMINATE`를 반환해야 합니다. 현재는 `None`을 먼저 통과시킨 뒤 `.ranges`를 역참조합니다.

| 위치 | 필요한 교체 |
|---|---|
| PE exception directory | 디렉터리와 개별 12바이트 `RUNTIME_FUNCTION`은 `file_record`로 읽습니다. 디렉터리 전체 read가 실패했다고 유효한 앞쪽 entry까지 버리지 않습니다. 각 entry의 실패 위치와 basis를 남기고 다른 entry를 계속 처리합니다. |
| PE `UNWIND_INFO` | 헤더, 정렬된 code 슬롯, chain tail, handler RVA를 `runtime_read()`로 읽습니다. 전체 extent의 근거를 보존하고 `holds_if:[PREMISE]`를 붙입니다. 뒤쪽 tail만 실패하면 이미 확정한 본문은 유지합니다. `_merge()`가 여러 `.xdata` 영역을 합치면서 첫 basis만 남기는 동작을 제거하거나 모든 구성 basis를 보존합니다. chain cycle·version·flags·indirect·truncation·handler-length 진단에는 원래 entry/header basis가 필요합니다. |
| PE import/delay descriptor | `rva,_ = directory`를 없애고 `[rva,rva+size)` 안에서 완전한 20/32바이트 record만 읽습니다. 모든 필드가 0일 때만 terminator입니다. 부분 record나 종단 누락은 partial입니다. 지원하는 delay attributes는 정확히 `1`인지 검사하고 필수 INT/IAT 및 슬롯 좌표를 검증합니다. |
| PE ILT/FirstThunk | ordinal은 `value & ~((1 << 63) \| 0xffff) == 0`이어야 합니다. 이름은 hint 2바이트부터 NUL까지 읽혀야 합니다. OFT=0 fallback은 stamp 0과 **모든** entry 검증 후에만 publish합니다. `ordinal` 필드의 존재로 ordinal을 판정합니다. 이름이 `"#"`로 시작하는지를 검사하면 실제 named import도 오분류됩니다. descriptor·DLL·lookup·hint/name의 `file_record`와 바인딩한 slot VA를 유지합니다. |
| ELF dynamic/relocation | `DT_JMPREL`은 `DT_PLTREL=RELA` 및 `DT_PLTRELSZ`, `DT_RELA`는 올바른 size와 entry size를 확인합니다. 누락된 size를 0으로, 불명확한 encoding을 RELA로 간주해 `complete`를 만들지 않습니다. 지원하는 조합은 `DT_JMPREL/JUMP_SLOT`, `DT_RELA/GLOB_DAT`입니다. 다른 relocation이 대상 슬롯에 있으면 `ELF_RELOC_UNSUPPORTED`입니다. 현재 `continue`는 이를 `SLOT_NOT_IMPORT`로 바꿉니다. |
| ELF symbol/name | 첫 번째 임의의 `SHT_DYNSYM` 크기를 사용하지 말고 실제 `DT_SYMTAB`과 같은 table인지, entry size·범위·연결된 string table이 맞는지 검증합니다. r1이 요구하는 section-linked table 경로도 구현합니다. `.dynstr` 범위 안 NUL과 `SHN_UNDEF`를 확인합니다. 같은 이름의 self-definition은 import 양성 0입니다. 동일 slot에 상충하는 entry가 있으면 마지막 항목으로 덮어쓰지 않습니다. |
| ELF unwind | section-name table 및 대상 section의 file 범위, `SHF_ALLOC`, 실제 매핑된 `PT_LOAD` 포함을 검증합니다. `eh_frame_ptr`의 `DW_EH_PE_indirect` 비트를 현재 마스크가 무시합니다. 지원하지 않는 간접 encoding은 `EH_FRAME_PTR_ENCODING`과 header basis를 내야 합니다. 알려진 pointer와 미상 end는 진단할 수 있지만 교집합·합계에는 넣지 않습니다. |
| parser 실패 범위 | `file_facts()`가 실패했는데 기본 `import_state="absent"`가 되면 `NO_IMPORT_DIRECTORY`라는 잘못된 결론이 납니다. 이 경로는 `indeterminate`입니다. 부분 파싱 중 확인한 slot은 그 slot에 대한 충돌이 없을 때 유지하고, 실패한 slot·table 범위를 별도로 기록합니다. 완전한 검사로 배제한 상수 slot에만 `SLOT_NOT_IMPORT`를 사용합니다. |

### 4. Trap 판정과 ballot digest

raw hook에서 G1의 `attributes`와 독립적으로 판정하는 위치, `CD ib`의 `int_n`과 vector, `CC/F1`의 암시 vector, `CE` 전원 invalid 음성, `0F 34`의 Intel `sysenter` 및 AMD F5 split 처리 방향은 맞습니다. 세 가지 교체가 필요합니다. [trap_outcome](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/code_facts.py:676) · [고정 voter 순서](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/decoders.py:502)

1. `ballot_digest()`가 voter 이름을 사전순으로 정렬합니다. Intel은 설계 순서 `iced, zydis, xed`와 달라집니다. 기존 ballot으로 두 digest가 다름을 확인했습니다. 다음으로 교체합니다.

   ```python
   def ballot_digest(votes):
       import common_facts as cf
       import decoders

       votes = tuple(votes)
       names = decoders.AMD_VOTERS if votes[0].amd else decoders.INTEL_VOTERS
       by_name = {d.voter: d for d in votes}
       return cf.digest([by_name[name].as_json() for name in names])
   ```

2. non-trap 분기는 `n > verified`만 검사하고 relocation 검사를 건너뜁니다. `90`, 길이 1의 정상 표, offset 0 relocation에서 실제 결과가 결정적 음성입니다. `0 < n <= len(data)`를 요구하고, prefix/opcode가 relocation에 걸리면 `RELOCATED_OPCODE`로 기록합니다. operand에만 있는 relocation을 허용하려면 그 구간이 모든 voter의 operand field 안임을 증명해야 합니다.
3. 전원 invalid인 non-CE는 r3 closing대로 주 reason이 `TRAP_FORM_UNDECIDED`이고 별도 집계가 가능해야 합니다. `ALL_INVALID_NOT_CE`로 주 reason을 교체하면 소비자가 설계의 unresolved 분모를 복원하지 못합니다. 예를 들어 outcome의 세 번째 값에 detail을 두고 survey에는 주 reason을, report에는 detail count를 기록할 수 있습니다. `0F 34` golden은 현재 synthetic AMD `invalid` 한 경우만 확인합니다. 실제 voter별 `(voter,mode,status,flow,length)`과 `SYSENTER.f5.amd`를 고정하고, 허용된 두 AMD ballot 형태 및 AMD 내부 불일치도 검사해야 합니다.

### 5. Region, survey, reader, 결정성

`CodeBinder.regions()`의 교차 window sweep, per-region union 길이, `len(canonical(V)) > 8_388_608`에서만 compact를 선택하는 경계는 맞습니다. 하지만 `run()`이 행의 space가 하나일 때만 이를 image space로 쓰고, 여러 개이거나 빈 Bundle이면 `None`을 사용합니다. 이후 sweep과 `rows_outside_code`는 숫자 VA만 비교합니다. 다른 space의 window가 같은 region에 포함되고, STORE에서는 반대로 모든 실제 space가 `None`과 달라 음성이 될 수 있습니다. [run 바인딩](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/decode_check.py:704) · [region sweep](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/code_facts.py:809)

image space는 `collect()`에서 이미 접근하는 `ev.image_base.space_id`를 보존해 바인딩합니다. window는 동일 space·load base에만 교차시키고, `verified_lengths`에는 region 밖 행도 포함해 원래 G1 길이를 그대로 둡니다. 명시형과 compact 확장에 **동일한 교집합 함수**를 사용해야 합니다.

```python
# collect().keep()
found["image_space"] = ev.image_base.space_id

# run()
binder = code_facts.CodeBinder(
    file_facts, base, facts["image_space"], doc["rows"],
    common.code_rows, cf.row_set_digest(doc["rows"]),
)

# CodeBinder.regions()의 windows 생성
windows = []
for key, row in self.code_rows.items():
    i = self.index[key]
    if row[1] and self.rows[i]["space"] == self.space:
        windows.append((i, self.va[i], self.va[i] + row[1]))

# 각 명시형 교집합 및 trap site가 공유할 basis
def window_ref(rows, i):
    r = rows[i]
    return {"g1_window": {"row": i, "decode_row": [r["space"], r["offset"]]}}
```

추가로 다음 변경이 필요합니다.

- PE section·ELF segment의 `state`만 보지 말고 최종 `image.ranges`의 ambiguous 조각도 반영합니다. 특히 ELF 공유 페이지의 ambiguity는 segment에 `"mapped"`를 기록한 **뒤에** overlay됩니다. 확정된 code 구간과 겹치면 STORE 양성, 음성을 내려면 모호한 구간 해석이 필요한 경우 `TARGET_MAPPING_U`입니다. unwind read 실패 범위를 executable ambiguity로 섞지 않습니다. [ELF 최종 매핑](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/elf_map.py:173)
- `rows_examined.excluded`는 설계의 `[{row,reason}]`로 쓰고, 각 method에 실제 대상 행이 0이면 `empty:true`를 기록합니다. A64는 `not x86`이 아니라 실제 `isa == "aarch64"`로 식별합니다. A64 method에서 x86을 제외하면서 `NOT_X86`라고 쓰는 현재 표기도 수정합니다. syscall method는 trap 판정이 미해결인 행을 결정적 음성으로 만들지 말고 해당 unresolved를 전파합니다. 식별된 해당 syscall 계열은 `unsupported/NO_ABI_BASIS`입니다. run coverage 생략은 맞습니다.
- region 진단은 `{reason,scope_item}`로, range item은 `{range:{space,load_base,start,end},basis}`로 바인딩합니다. `eh_frame` 시작 미상 진단은 header basis를 보존합니다. import partial/indeterminate의 원시 `what` dict를 `unsupported.items`에 그대로 넣지 않습니다. 영향받는 `(row,op)` 또는 바인딩된 range를 써야 합니다. `missing_functions`는 해당 survey의 범위를 복원할 수 있게 연결합니다. 보고서에는 method별 site·candidate·excluded·unsupported·unresolved와 API별 RWX 집계를 냅니다.
- `_groups()`는 `set`을 순회한 뒤 range item 모두에 같은 `(-1,-1)` 정렬 키를 부여합니다. 같은 row/op에 다른 API가 있어도 tie입니다. 전체 canonical item을 마지막 정렬 키로 사용합니다. `program_code()` 재호출 때 이전 `sites`와 `coverage`가 다시 누적되지 않게 호출별로 초기화합니다.

  ```python
  def _groups(pairs):
      import json

      groups = {}
      for reason, item in pairs:
          if reason not in REASONS:
              raise ValueError(f"unknown reason {reason}")
          groups.setdefault(reason, {})[_canonical(item)] = item

      result = []
      for reason, items in sorted(groups.items()):
          ordered = sorted(items, key=lambda raw: (_item_key(items[raw]), raw))
          result.append({"reason": reason, "items": [json.loads(raw) for raw in ordered]})
      return result
  ```

- **reader 검증이 빠져 있습니다.** 기존 `evidence._bind_checked_rows()`는 facts 전체 SHA와 기존 행을 검증합니다. `program.code`의 내부 digest, 참조, compact 길이, 실제 name table은 검사하지 않습니다. report의 `summary()`도 입력 digest를 복사할 뿐입니다. 기존 `-4/-5` 호환을 유지하면서 `producer.rule == "g2b-1"`인 문서에만 새 검증을 연결해야 합니다. G1 길이는 row state나 claimed length로 복원할 수 없습니다. 같은 Bundle에 바인딩된 **decode report 행**을 받아야 하며, 존재하는 decode 행에 window가 없으면 0, decode 행 자체가 누락되면 reader 오류입니다. [기존 reader](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/evidence.py:648) · [현재 summary](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/code_facts.py:916)

  reader의 길이·digest 검사는 다음 코드로 구현할 수 있습니다. `decode_details`는 중복을 거부해 만든 `(observation,space,offset) → detail` 인덱스입니다.

  ```python
  def bound_lengths(rows, code, decode_details):
      import common_facts as cf

      digest = cf.row_set_digest(rows)
      if code["name_table_sha256"] != name_table()[1]:
          raise ValueError("name table digest mismatch")

      lengths = []
      for r in rows:
          key = (r["observation"], r["space"], int(r["offset"], 16))
          if key not in decode_details:
              raise ValueError(f"missing G1 decode row {key}")
          detail = decode_details[key]
          n = detail["window"]["verified"] if "window" in detail else 0
          if type(n) is not int or not 0 <= n <= 15:
              raise ValueError(f"invalid G1 window length {key}")
          lengths.append(n)

      form = code["verified_encoding"]["form"]
      if form == "compact":
          stored = code.get("verified_lengths")
          if code.get("verified_rule") != {"per_row_window": digest}:
              raise ValueError("verified row-set digest mismatch")
          if (not isinstance(stored, list) or len(stored) != len(rows)
                  or any(type(n) is not int for n in stored) or stored != lengths):
              raise ValueError("verified lengths disagree with G1")
      elif form != "explicit" or "verified_rule" in code or "verified_lengths" in code:
          raise ValueError("invalid verified representation")
      return digest, lengths
  ```

  이 길이와 바인딩된 region으로 `V`를 재구성한 뒤 explicit이면 각 목록을 직접 대조하고, 두 형식 모두 threshold 선택·`explicit_bytes`·각 union total을 확인합니다. `rows_examined.facts_rows`, 모든 행 인덱스의 음수·상한·중복, ordinal의 실제 op, path·range·API basis도 확장 시 검증합니다. report 생성 시에도 `summary()` 입구에서 실제 `name_table()[1]`과 대조합니다.

### 6. 재검토의 통과 조건

기존 G2b 테스트가 잘못된 동작 일부를 기대값으로 고정하고 있습니다. 대표적으로 ballot 없는 `VirtualAlloc` 양성, basis 없는 handler 진단, `ALL_INVALID_NOT_CE` 주 reason입니다. 다음 golden은 새 함수의 단위 결과뿐 아니라 **collector → facts → reader → summary**까지 확인해야 합니다. [추가된 테스트](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tests/intra/test_decode_check.py:4793)

| 영역 | 필요한 기대값 |
|---|---|
| Trap | `F1`, prefix, claimed length가 틀린 `CC`, `CD`의 relocated `ib`, relocated non-trap opcode, `NO_WINDOW`/`GLOBAL_REASON`/`BALLOT_MISSING`, 실제 `CE`와 `0F 34` ballot·digest·F5 basis |
| Import | decoder-only call은 `TRANSFER_UNBOUND(row,null)` 1개, 내부 CMOV는 0개. `66 E8` 충돌, direct/indirect 불일치, segment·폭·space 우선순위, jcc→thunk는 `direct_slot=0, via_thunk=1, thunk_row=1`. 추가 jump는 `MULTI_HOP` |
| 파일과 stub | delay import, 잘못된 OFT fallback 전체 거부, ordinal과 `#`로 시작하는 이름, section-linked ELF, GLOB_DAT, 잘못된 relocation과 dynsym index, self-definition, 6/7/10/11바이트 stub, 비실행·다른 space·재배치·불완전 index |
| 값과 STORE | CMOV 조건부 정의, overlapping partial kill, 8비트 단독 값, 32→64 zext, XOR/SUB, LEA, 64행 초과, branch·pad·gap·다중 후보, 알려진 RSP, 한 행의 양성 STORE와 미해결 STORE 동시 존재, 구간 끝 교차·wrap·ambiguous map |
| Region과 survey | 같은 VA의 다른 observation/view/space, region 밖에서 시작하는 window, unwind partial·cycle·handler U, empty/A64/syscall method, range basis, 순서 셔플과 다른 hash seed에서 동일한 canonical 결과 |
| Reader | 8,388,608바이트는 explicit, 8,388,609는 compact. 같은 입력을 두 형식으로 확장한 교집합·basis·합계 일치. facts SHA까지 다시 계산한 상태에서도 변조된 내부 digest·길이·row/op·name-table digest 거부 |

마지막으로 성능 게이트도 아직 열려 있습니다. 제시한 단일 쌍에서 UE는 **+13.4%**, zlib 최초 쌍은 **+17.8%**입니다. zlib 재측정과 UE의 과거 편차는 잡음의 근거지만 UE의 `+10%` 통과를 확정하지는 못합니다. 수정 후 같은 입력·옵션으로 base/new 순서를 교차해 Bundle별 시간과 peak RSS를 다시 비교해야 합니다. `equiv_g2b.py`도 현재 보고서에서는 `header.common_facts`만 비교하므로, r2 E7의 보고서 전체 등가성을 주장하려면 실행별 출력 경로를 동일하게 맞추거나 정규화한 뒤 **전체 header와 rows**를 비교해야 합니다.