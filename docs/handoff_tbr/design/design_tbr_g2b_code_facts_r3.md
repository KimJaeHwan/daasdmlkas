# TBR G2b: code-byte facts, design r3 (delta over r2)

r3 = design_tbr_g2b_code_facts_r2.md (itself a delta over r1) with the replacement texts below, written by Astra in
its round-3 review (.census6/g2b_design_astra3.md) and applied verbatim (owner rule: on repeated REJECT, Astra writes
the fix, Claude reviews, Fable reviews, close). Each block names the r2 part it replaces. Astra's verdict on the rest
of r2: items 1, 4, 7, 8 and Fable P1-1 resolved.

Claude's review notes (no change to the text):
- E6 item 3: Astra keeps the per-Bundle threshold with readers implementing both forms (Fable r2 P3 preferred one form
  per rule); Astra is followed on conflict.
- E3: the decoder-only candidate rule makes a row where a decoder sees a call but no raw transfer op exists an
  explicit TRANSFER_UNBOUND, closing the false-negative path.

### 1. E2 — `CE`와 `0F 34`의 투표 판정

`c15a29a`에서 `override`는 `compare_row()`가 반환한 **뒤에** 원시 ballot과 window 바이트를 받습니다. 또 `invalid` 투표에는 유효한 소비 길이가 없습니다. 따라서 E2의 일괄 조건 `status ok`와 `one consumed length`로는 합의된 invalid `CE`를 처리할 수 없습니다. `0F 34`의 AMD long-mode `#UD`는 저장소에 근거가 있지만, 그 근거는 `SYSENTER`의 F5 표입니다. 이를 AMD voter가 반환한 `invalid`로 기록하면 출처가 바뀝니다. [hook 호출](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/check.py:258) · [decoder 상태와 길이](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/decoders.py:41) · [SYSENTER의 F5 근거](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/isa_conditions_x64.json:231)

**E2의 `Inputs`부터 `Positive site basis`까지 교체**

> 매 x86-64 행의 `override`에서 `compare_row()` 반환 후, collector가 투표를 버리기 전에 판정한다. 입력은 `window` 원본 바이트, `result.window.verified`, `result.window.relocations`, 양 vendor의 원시 ballot이다. `result.attributes`는 진입 조건으로 쓰지 않는다. window가 없거나 verified가 0이면 `NO_WINDOW`다.
>
> Intel은 iced·Zydis·XED, AMD는 iced·Zydis의 이름·개수·모드를 확인한다. 필수 표 누락은 `BALLOT_MISSING`이다. 정상 디코드에서는 필수 표가 모두 `ok`이고 form과 양의 소비 길이에 합의해야 한다. trap의 소비 길이는 첫 prefix부터 마지막 opcode 바이트 또는 `CD`의 `ib`까지의 실제 길이와 같아야 한다. 전체가 verified 안에 있어야 하며, 그 구간의 relocation은 `RELOCATED_OPCODE`다. `CD ib`의 form은 `int_n`, vector와 immediate는 `ib`다. r1의 `CC`, `F1`, `0F 05`, `0F 34` 매핑을 유지한다. 정상 비대상은 완전히 검증한 명령에서 바이트 검사와 필수 표가 모두 비대상일 때만 확정한다.
>
> long-mode `CE`는 별도로 판정한다. prefix와 `CE`가 모두 검증되고 relocation이 없으며 양쪽 필수 표가 모두 `invalid`이면 검사한 비대상이다. 이때 길이 근거는 해당 바이트 구간이다. `invalid` 투표의 기본 길이 0을 소비 길이로 사용하지 않는다.
>
> `0F 34`에서는 원시 투표와 vendor별 실행 의미를 각각 기록한다. Intel 필수 표가 완전한 `sysenter`에 합의하고 AMD 필수 표가 같은 `sysenter`에 합의하거나 모두 `invalid`이면, site의 최상위 form은 `U("VENDOR_SPLIT_FORM")`이다. Intel의 `sysenter`에는 window와 Intel ballot을, AMD의 `invalid_encoding`에는 `SYSENTER`의 AMD long-mode F5 근거와 실제 AMD ballot을 연결한다. AMD 표 내부 불일치, `error`, `no_more_data`, 불완전 소비는 `TRAP_FORM_UNDECIDED`다. split site는 한 번만 집계한다.
>
> 양성 site는 g1_window ref와 vendor별 ballot digest를 보존한다. digest는 해당 vendor의 고정 voter 순서로 나열한 `Decoded.as_json()` 배열을 `common_facts.canonical()`로 인코딩한 바이트의 SHA-256이다. G2b site 판정은 기존 G1 verdict를 변경하지 않는다.

### 2. E3 — decoder만 찾은 후보, 분기 목적지와 thunk 집계

E3의 후보 조건은 원시 op로만 시작합니다. 반대로 원시 `CBRANCH`가 있어도 `c15a29a`의 lift가 CMOV·REP 내부 분기로 이미 식별한 경우가 있습니다. 또한 r1의 form 검사는 `call_near / jmp_near`만 허용하므로 새 jcc golden이 `FORM_MISMATCH`에 걸립니다. 직접 목적지 처리에서는 “row start”가 전제인 단계 아래에 “not a row start”가 있어 그 사유에 도달할 수 없습니다. [E3](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/design_tbr_g2b_code_facts_r2.md:92) · [G2a transfer op 선택](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/common_facts.py:445) · [CMOV·REP 내부 분기 식별](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/wt_lint/tools/decode_check/lifting.py:281)

**E3의 `Examined rows`, `Precedence`, `Path`, `Separate counts`를 교체하고 `ELF checks`는 유지**

> 모든 x86-64 행을 검사한다. 후보 신호는 decoder의 `call_near`, `jmp_near`, `jcc` 또는 원시 `CALL`, `CALLIND`, `BRANCH`, `BRANCHIND`, `CBRANCH`다. 식별된 trap의 내부 transfer와 lift가 내부 제어 흐름으로 입증한 op는 후보에서 제외한다. decoder가 외부 transfer를 가리키는데 정확한 G2a transfer op가 없으면 `TRANSFER_UNBOUND`다. 대응할 원시 op가 없으면 `(row, null)`, 있으면 해당 `(row, ordinal)`에 기록한다. decoder와 무관하게 남은 원시 후보도 정확한 transfer에 결합하지 못하면 같은 사유를 기록한다.
>
> 허용 form은 `call_near`, `jmp_near`, `jcc`다. jcc는 taken `encoded_target` edge만 따른다. 메모리 슬롯에는 주소 공간·64비트 포인터 폭·segment base 검사를 적용한다. 직접 edge에는 목적지 좌표와 vendor 합의를 확인한다. vendor 충돌은 `VENDOR_VIEW_CONFLICT`다.
>
> 직접 목적지는 먼저 같은 공간·load base에서 분류한다. 확인된 행 중간이면 `TARGET_NOT_ROW_START`, 행 집합의 불완전성 때문에 판별할 수 없으면 `INDEX_INCOMPLETE`, 완전한 집합에 목적지 행이 없으면 `TARGET_OUTSIDE_ROWS`다. 시작 행이 있으면 해당 view에서 해석한다. 확인한 일반 비-thunk만 음성이다. 누락된 lift, 지원하지 않는 stub, 두 번째 hop은 각각 기존 사유로 남긴다. 하나의 `endbr64`를 건너뛸 때는 같은 observation·space·view의 유일한 연속 후속 행을 확인한다. 경로의 각 단계는 `{row, op}`로 보존하고, `endbr64`에 대응 op가 없으면 `op: null`을 쓴다.
>
> 슬롯 파싱이 해당 슬롯에서 불확정이면 `PARSER_UNSUPPORTED` 또는 `SLOT_NAME_U`다. 완전한 검색으로 비-import 슬롯임을 확인했을 때 `SLOT_NOT_IMPORT`를 쓴다. 기존 `NO_IMPORT_DIRECTORY`, ordinal, 확인된 비대상 이름의 구별을 유지한다.
>
> site는 source row·transfer op·kind별 한 번 기록한다. `via_thunk`는 확인한 thunk를 경유한 source site, `thunk_row`는 그 경로의 마지막 `jmp [slot]` site, `direct_slot`은 나머지 직접 슬롯 site다. 여러 caller가 같은 thunk를 써도 `thunk_row`는 한 번이다. site form은 `call`, `jump`, `jcc` 중 하나다.

### 3. E5·E6 — 예외의 직렬화와 검색 범위

같은 행 예외가 r1에는 `[idx, op]`, E5에는 `{row, op}`, `NO_RWX_REGISTER`에는 `[idx, op, api]`로 정의됩니다. 또 E5의 range에는 r5가 요구하는 `load_base`가 없습니다. 기존 `NOT_X86` 제외 규칙을 모든 method에 그대로 적용하면 A64 method에서 정작 `G2C`를 기록할 행이 검색 범위 밖으로 빠집니다. [E5](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/design_tbr_g2b_code_facts_r2.md:175) · [r5 범위와 coverage 계약](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/design_tbr_g2_common_facts_r5.md:455)

**E5의 `Scope items`, `Coverage records`, `API recovery`와 E6 항목 1·2 교체**

> `unsupported`와 `unresolved`는 `[{reason, items}]`다. 행 item의 저장형은 `{"row": i, "op": ordinal|null}`이고 `NO_RWX_REGISTER`에는 `"api": name`을 추가한다. 범위 item은 `{"range":{"space":s,"load_base":b,"start":a,"end":e|U},"basis":ref}`다. 확장 시 `i`를 결합된 `rows[i]`의 전체 `row_ref`로 바꾸고 그룹의 `reason`을 각 item에 붙인다. ordinal이 있으면 해당 행의 op로 해석한다. API와 basis는 확장 후에도 보존한다. 각 그룹의 item은 정렬·중복 제거한다.
>
> region 진단은 `{reason, scope_item}`이다. 시작점을 모르는 `eh_frame`은 `{reason, what:"eh_frame", basis:ref}`로 기록하며, `basis`는 포인터를 찾거나 해석하려 한 header를 지목한다. 확정된 구간만 교집합·합계·`ranges_examined`에 포함한다. STORE가 확정된 code 구간과 겹치면 양성이다. 겹침을 배제하려면 모호한 매핑의 해석이 필요한 경우 `TARGET_MAPPING_U`다.
>
> 각 coverage의 단위는 `(kind, method)`이며 `code_write`는 `write`도 보존한다. `rows_examined`는 결합된 행 전체에서 그 **method에 적용되지 않는** `excluded` 행을 뺀 집합이다. A64 instruction method의 A64 행에는 `unsupported/G2C`, x86 cacheflush syscall method의 해당 x86 검색 범위에는 `unsupported/NO_ABI_BASIS`를 기록한다. parser 부분 실패는 영향을 받은 행·op 또는 범위에 연결한다. 빈 범위는 `empty:true`이며, 양성 0건이라는 결론은 실제 검사 범위에서 예외를 제외한 부분에만 적용한다. run coverage는 생략한다.

### 4. E6·E8 — Bundle별 표현 선택과 golden의 기대값

r1은 Bundle별로 임계값을 적용합니다. E6은 UE 하나의 측정 결과로 모든 Bundle의 형식을 바꿀 수 있게 해 같은 작은 Bundle에 두 출력이 가능합니다. 또한 E6의 jump 의미 개정에는 `rwx_allocation_constant_args`와 `cache_maintenance`의 import 경로가 빠졌습니다. [r1 크기 규칙](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/design_tbr_g2b_code_facts_r1.md:84) · [E6](D:/01_gitproject/14_TDO_v2/daasdmlkas/.census6/design_tbr_g2b_code_facts_r2.md:219)

**E6 항목 3과 항목 6의 jump 항목 교체**

> region 출력 순서로 모든 명시형 `verified` 리스트를 담은 배열 `V`를 구성한다. `len(common_facts.canonical(V)) <= 8_388_608`이면 해당 Bundle에 명시형을 쓰고, 초과하면 압축형을 쓴다. `g2b-1` reader는 두 형식을 읽는다. UE 측정은 비용 검증에 사용한다.
>
> 압축형의 `program.code.verified_rule.per_row_window`는 `row_set_sha256`과 같아야 한다. `program.code.verified_lengths`는 facts 행당 정수 하나이며 window가 없으면 0이다. 행 수·digest·각 길이를 결합된 G1 decode 행의 `window.verified`와 대조한다. window가 없는 G1 행의 기대값은 0이다. 각 양의 길이에 대해 동일 space·load base에서 `[row_va, row_va+length)`와 확정 region의 비어 있지 않은 교집합을 복원한다. basis는 해당 observation·view의 g1_window ref다. 두 표현의 교집합·basis·합집합 길이는 동일해야 한다.
>
> `self_modify_import_call`, `dynamic_resolution`, `rwx_allocation_constant_args`, `cache_maintenance`의 import method, `dynamic_unwind_registration`은 확인한 `call`, `jump`, `jcc`를 포함한다. jcc는 taken 경로에 한정하며, register 값은 source 행 진입 시점의 값이다. allocation의 no-ABI 후보 조건도 그대로 적용한다.

**E8의 `0F 34`, jcc·thunk 집계, threshold 기대값 교체 및 두 사례 추가**

> `0F 34` golden은 고정 voter의 실제 `(voter, mode, status, flow, length)`와 AMD F5 근거를 각각 검사하고 split site 1개를 기대한다. `CE`의 전원 `invalid` 사례는 site 0개·미해결 0개다. decoder만 call을 보고하고 원시 transfer op가 없는 사례는 site 0개·`TRANSFER_UNBOUND(row,null)` 1개다. 내부 분기로 식별한 CMOV는 import site 0개·미해결 0개다. 한 jcc가 `jmp [import_slot]` thunk를 경유하는 fixture는 `direct_slot=0`, `via_thunk=1`, `thunk_row=1`이며 jcc 경로에 taken edge만 포함한다. 크기 판정은 8,388,608에서 명시형, 8,388,609에서 압축형을 기대하고, 같은 입력을 두 표현으로 확장한 교집합·basis·합계를 대조한다.


## Closing (2026-11-27)

Fable final APPROVE on r2 + r3 (Astra r3 texts checked against c15a29a). Design CLOSED per the owner's rule.
Implementation clarifications from Fable (not blocking):
1. REASONS keeps SEGMENT_BASE, POINTER_WIDTH, SPACE_MISMATCH, FORM_MISMATCH, COMPUTED_TARGET (r1 §4.2 list still
   applies under r3 E3).
2. "The decoder indicates an external transfer" = any required voter in either vendor; a split gives
   TRANSFER_UNBOUND or VENDOR_VIEW_CONFLICT, never a silent negative.
3. An agreed all-invalid row other than CE is TRAP_FORM_UNDECIDED; report that count separately.
4. The result=None path for a global reason gets its own code GLOBAL_REASON (not NO_WINDOW).
