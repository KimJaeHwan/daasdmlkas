# 수정 계획: 함수 내부 데이터 추적 안정화

작성일: 2026-10-06 · 대상 커밋: `83fe661`

## 0. 목적과 범위

함수 간(interprocedural) 개선(out-pointer gap, 상호절차 간선 그래프화)에 앞서,
**단일 함수 안에서의 backward slice가 (1) 조용히 틀리지 않고 (2) 크래시 없이
typed debt로 끝나며 (3) 예측 가능한 비용으로 돈다**는 것을 먼저 보장한다.

범위 파일: `normalize.py`, `memory_ssa.py`, `_memory_ssa_state.py`,
`memory_graph.py`, `relative_memory.py`, `graph.py`, `graph_contracts.py`,
`query.py`, `engine.py`(함수 단위 실패 처리 부분만).

범위 밖: `integration/` 상호절차 로직, Bundle 수용(`fcntl` 이식성은 별도 항목).

## 1. 수정 항목 (우선순위 순)

### P0-1. FUNCTION_RELATIVE 객체 간 암묵적 no-alias 가정 — 조용한 누락 위험

> **해결 (2026-10-06, `src/tdo_v2/may_alias.py`)** — 함수 내부만으로 판단(call 증거 미사용).
> - 바이트 단위 forward 분석: 각 메모리 객체 바이트에 대해 "마지막 자기 write 이후
>   실행된 *다른* 객체로의 write" 집합을 추적. 읽기 시 집합이 비어 있지 않으면
>   `may_alias_read` debt. 그래프 간선은 **후보 writer → debt → read** 라서 가능한
>   writer 값이 출처 후보로 도달하면서 슬라이스는 incomplete.
> - 별칭 불가 증명: 같은 객체(SSA가 바이트 정밀), 서로 다른 주소 공간, 그리고
>   진입 SP **아래**의 자기 프레임 바이트(탈출 없을 때). SP는 관측된
>   `r'=*(r); r=r+size; RETURN r'` 형태(또는 call 형태)로만 식별 — 식별 실패 시
>   스택도 신뢰하지 않음. 탈출 = SP 파생 값이 STORE 값 / CALLOTHER 입력이 되거나,
>   call이 있는 함수에서 다른 레지스터로 복사됨. 진입 SP 이상(복귀주소·호출자 프레임)은
>   항상 별칭 가능.
> - 설명 출력에 `may_alias_read` gap(writers 포함), query가 unresolved read로 집계.
> - 테스트: `test_relative_alias.py` 11개(xfail 4건 해소), 하네스 `slice_op(index=)`.
> - 실측(64 케이스): 누락+확실 0 유지, 정확+확실 28 유지. DFB031·DFB054는 증명 불가한
>   포인터 별칭 때문에 금지 출처가 후보로 추가되어 PASS 41→39 (출처 누락 아님, 과다 보고).

- 근거: `relative_memory.py:382-387` 에서 ENTRY 정의마다 별도 atom을 만들고,
  `relative_memory.py:243-252` 가 atom 집합 digest로 `FUNCTION_RELATIVE` 객체를
  만든다. SSA(`memory_ssa.py`)는 서로 다른 `StorageObjectId`를 완전히 분리된
  저장소로 취급한다.
- 결과: `*(RDI)` 에 쓰고 `*(RSI)` 를 읽는 함수에서 런타임에 RDI == RSI 이면
  쓰기→읽기 의존이 **debt 없이** 사라진다. 포인터 인자가 전역(`ADDRESS_SPACE`)을
  가리키는 경우도 같다. README의 "추측 금지/명시적 gap" 원칙과 충돌한다.
- 수정안:
  1. 서로 다른 atom 집합을 가진 relative 객체, relative↔absolute 객체 사이에
     "may-alias" 관계를 명시적으로 정의한다.
  2. 기본 정책: 같은 함수 안에서 *다른* relative/absolute 객체에 대한 resolved
     write가 read보다 앞설 수 있으면, 그 read에 `MAY_ALIAS` debt를 붙인다
     (그래프에는 `MEMORY_DEBT` 노드 + `unresolved_read` 간선).
  3. no-alias를 증명할 수 있는 경우(같은 atom 집합 + 구간 비겹침, 스택 프레임
     내부 등)만 debt를 생략한다. 증명 규칙은 한 함수(`_alias_free(a, b)`)로 모은다.
- 검증: RDI/RSI 별칭 합성 케이스에서 슬라이스가 `is_complete == False` 가 되는지.
- **재현 완료 (2026-10-06)**: `tests/intra/test_relative_alias.py`
  - `*(RDI)=RDX; RAX=*(RSI)` → RDX 미도달, `is_complete=True`, debt 0건 (조용한 누락 확인)
  - `*(RDI)=RDX; RAX=*(0x1800)` → 동일 (relative↔absolute)
  - 대조군 `*(RDI)=RDX; RAX=*(RDI)` → RDX 도달, 정상
  - 수정 후에는 xfail(strict) 2건이 통과로 바뀌고 characterization 테스트가
    의도적으로 깨져야 한다.
- 주의: 무조건 may-alias로 두면 RSP 기반 지역 변수와 포인터 인자 사이에도 debt가
  생겨 대부분의 슬라이스가 incomplete가 된다. "주소가 탈출하지 않은 스택 프레임
  객체는 진입 포인터와 별칭 불가" 같은 증명 규칙이 함께 필요하다.

### P0-2. 크래시 경로를 typed debt / Unresolved 결과로 전환

- 근거:
  - `memory_ssa.py:165` JOIN 입력 충돌, `:475/:486` 빈 raw state,
    `:67` partition 커버리지 실패 → `AssertionError`
  - `relative_memory.py:132` alternative-address write → `AssertionError`
  - `normalize.py:635` ENTRY materialize 실패 → `AssertionError`
  - `engine.py:93-97` 함수 하나라도 normalize 실패 시 전체 실행 `ValueError`
- 문제: `python -O` 에서는 `assert` 문이 사라지고(`normalize.py:461,464`),
  `AssertionError` 는 "불변식 위반"과 "아직 지원하지 않는 입력"을 구분하지 못한다.
- 수정안:
  1. 입력에 의해 도달 가능한 경우(예: alternative-address write)는
     `UnresolvedNormalizedFunction` + 신규 `NormalizationFailureReason` 로 반환.
  2. 진짜 내부 불변식은 전용 예외 `InternalInvariantError` 로 통일하고 `assert`
     문은 명시적 `if ...: raise` 로 교체.
  3. `engine.py` 는 기본 동작(전체 실패)을 유지하되, 옵션
     `on_unresolved_function="report"` 로 실패 함수를 결과에 typed gap으로 남기고
     나머지를 계속 분석할 수 있게 한다. 단, 해당 함수에 의존하는 root는
     반드시 incomplete로 표시.

### P1-1. relative-memory 재투영 루프의 비용과 종료 보장

- 근거: `normalize.py:586-603` `while True` 루프가 매 반복마다
  `decode_effect_unit` + `build_local_memory_ssa` 를 처음부터 다시 수행.
- 종료성: 한 번 투영된 effect는 `memory_read/memory_write=None` 이 되어 다시
  투영되지 않으므로 반복 수 ≤ 미해결 접근 수. 따라서 종료는 하지만 최악
  O(k × SSA 비용).
- 수정안:
  1. 명시적 상한(`len(unresolved accesses) + 1`)과 초과 시 `InternalInvariantError`.
  2. 반복 횟수/해결 개수 계측(디버그 통계)을 남겨 실제 코퍼스에서 k 분포 확인.
  3. (후속) 변경 블록만 재계산하는 증분 SSA는 계측 결과를 본 뒤 결정.

### P1-2. 죽은 노드 종류 `VALUE_VERSION` 정리

- 근거: `normalize.py:515-532` 에서 OPERATION→VALUE_VERSION `defines` 간선만
  생성, 나가는 간선 없음. `NormalizedFunction.value_node()`(`normalize.py:368`)
  호출처 0건. 실제 데이터 흐름은 memory SSA 간선이 담당.
- 수정안: (a) 제거하거나 (b) 유지한다면 VALUE_VERSION→소비 OPERATION 간선을
  부여해 의미를 갖게 한다. backward 도달 집합에는 영향이 없으므로 (a) 권장.
  제거 시 `value_nodes` 필드, `_validate_*` 의 관련 검증도 함께 제거.

### P1-3. 간선 종류 `EdgeKind` enum 도입

- 근거: `graph_contracts.py:44` `EdgeRecord.kind` 가 자유 문자열.
  `"defines"`, `"memory_read"`, `"memory_defines"`, `"memory_join_input"`,
  `"unresolved_read"`, `"unresolved_write"` 등이 문자열 리터럴로 산재.
- 수정안: `NodeKind` 와 동일하게 `StrEnum` 으로 정의하고 `EdgeRecord.__post_init__`
  에서 exact type 검사. 문자열 값은 유지해 직렬화 호환성 보존.

### P2-1. `NormalizedFunction.__post_init__` 검증 비용

- 근거: `normalize.py:100-366` (약 270줄), `memory_graph.py:196-215` 가 그래프의
  모든 incident edge를 다시 세어 비교 → 생성 비용 O(E) 추가.
- 수정안: 타입/필드 정합성 검사는 유지, 그래프 토폴로지 전수 재검증은
  `TDO_V2_DEEP_VALIDATE=1` (또는 생성자 플래그) 뒤로 이동. 테스트/CI에서는 항상 켠다.

### P2-2. 사소한 비효율

- `normalize.py:368` `value_node()` 가 호출마다 `dict(...)` 재생성 → P1-2로 제거되면 해소.
- `query.py` 의 Python DFS(`graph.py:87`)는 현재 규모에서는 유지. 측정 후
  `rustworkx.ancestors` 로 교체 검토(결정적 정렬 순서 보장 필요).

## 2. 검증 계획

테스트 스위트가 이 스냅샷에 없으므로 함수 내부 전용 테스트를 새로 만든다.

1. **합성 단위 테스트** (`tests/intra/`): Bundle 없이 `LocalMemoryUnit` 을 직접
   구성해 `build_local_memory_ssa` / `BackwardSliceQuery` 검증.
   - 부분 레지스터 겹침, JOIN, KILL, 루프 고정점
   - P0-1 별칭 케이스(RDI/RSI), relative↔absolute 케이스
   - P0-2 각 크래시 경로가 typed 결과로 바뀌었는지
2. **실제 바이너리 회귀**: `D:\01_gitproject\09_tdo_testbed` 의
   `build/win-*/dfbench_*.exe` 를 Ghidra 12.0.4
   (`D:\01_gitproject\14_TDO_v2\ghidra_12.0.4_PUBLIC`) + `ghidra/*.java` 로
   export → `expected/*.expected.json` 과 비교. 함수 내부 케이스(단일 함수
   source→sink)부터 사용.
   - 현재 09 프로젝트에는 format-2 Bundle이 **없음**(manifest/seal 검색 0건) →
     export 스크립트 실행이 선행 작업.
3. 각 수정 전/후로 동일 Bundle의 `EngineRun` 결과 diff를 남긴다
   (origin 레이블 변화, incomplete 증가는 P0-1의 기대 효과).

## 3. 실행 환경

- Bundle 수용 코드(`integration/configured_bundle.py`)가 POSIX 전용(`fcntl`,
  `os.getuid`, `O_NOFOLLOW`)이므로 엔진 실행은 WSL Ubuntu에서 한다.
- 함수 내부 합성 테스트(위 1번)는 `configured_bundle` 을 import하지 않으므로
  Windows `.venv` 에서도 실행 가능.
- WSL 성능 문제가 지속되면 `configured_bundle.py` Windows 포팅(잠금:
  `msvcrt.locking`, 소유자 검사: 생략 또는 ACL 기반)을 별도 항목으로 진행.

## 4. 작업 순서 (2026-10-06 Fable 검토 반영)

1. **하네스 보강** — 완료. 간선 span 기반 판정(인접 레지스터가 한 ENTRY로
   합쳐지는 문제 해결), CBRANCH/BRANCH/루프, x86-64 push/pop·`sub rsp`(플래그
   포함)·현실적 ret(`RIP=*(RSP)`), 별도 data 블록.
2. **합성 테스트** — 완료. `tests/intra/` 16 passed / 4 xfailed(P0-1).
   - `test_memory_cases.py`: 지금 정확한 동작(수정 후에도 유지돼야 함)
   - `test_relative_alias.py`: P0-1 xfail + characterization
   - `test_harness.py`: 하네스 자체 검증
   - Fable 예상과 달리 루프 `RDI+=8` 케이스는 크래시가 아니라 incomplete(debt).
3. **P0-0 (신규)** — 완료. `query_contracts.LocalCompleteness` /
   `local_completeness()` 추가, `RootSlice.local_completeness` 필드와
   `is_locally_complete` 프로퍼티. root occurrence의 모든 root node 슬라이스를
   합쳐 하나라도 incomplete면 incomplete, debt 노드는 중복 없이 개수 집계.
   함수 간(caller/callee) 완전성은 포함하지 않음 — 후속 과제.
   테스트: `tests/intra/test_local_completeness.py` (Windows/WSL 모두 21 passed).
4. **P0-2** — 완료.
   - 무작위 합성 함수 2,000개(분기·루프·부분 레지스터·스택·전역·CALL) 정규화+슬라이스
     크래시 0건 (`tests/intra/test_robustness.py`). 코어의 `AssertionError` 들은
     현재 입력으로 도달 불가한 방어 검사로 판단 → 유지.
   - `normalize.py` `_ScopedNormalizer` 의 `assert` 문 2개를 명시적 raise로 교체
     (`python -O` 안전).
   - 실제 위험은 엔진의 all-or-nothing: 도달 불가 코드(DISCONNECTED_OBSERVED_CFG)
     하나로 전체 실행 실패. 실패 함수를 건너뛰면 그 함수를 호출하는 쪽 호출 간선이
     `configured_interprocedural_slice.py` 에서 조용히 사라지므로(대상이 views에
     없으면 `continue`) **건너뛰기 모드는 보류**. 대신 `engine.UnresolvedBundleFunctionError`
     (index, entry, reason)로 실패를 타입화.
   - 진행 중 **P0-3 발견**(아래).
4-1. **P0-3 (신규, 2026-10-06)**: 엔진 경로(`normalize`)에서 CALL이 상태를 전혀 바꾸지
   않음. `RAX=RDX; call f; RCX=RAX` → RCX가 RDX로 추적되고 complete, 호출 후
   `*(RDI)`/전역 읽기도 debt 없이 complete. CALL 효과에 write/debt가 없고
   (`normalize.py` CALL effect), 호출 후 쓰기를 넣는 곳은 엔진이 쓰지 않는
   `configured_call_augmentation.py` 뿐. `tests/intra/test_call_effects.py`
   (xfail 3 + characterization).
   - Fable 검토(확인됨): 함수 간 계층은 보정하지 않는다. `local_origin_labels` 가
     호출 전의 낡은 출처를 그대로 보고하고 `reached_origin_labels` 는 이를 proof
     라벨과 합친다. call_byte_replacements 는 설명 overlay 전용.
   - V4 사이드카 연결은 해법이 아님: POST_WRITE 는 반환값 슬롯 하나뿐
     (`GhidraV2CallEffect.java:603-606`)이라 RCX/RDX/R8-R11·메모리 부작용은 여전히
     투명. 파서/권한 체인 미구현으로 작업량도 큼 → 정밀도 P1 과제로 미룸.
   - **설계 결정: 수요 기반 "unknown writer" debt** (P0-1과 공유)
     - debt reason `{CALL_CLOBBER, MAY_ALIAS}`, 간선 `기존 정의 → debt → read`
       (기존 출처는 계속 도달하되 그 슬라이스만 incomplete)
     - read의 reaching 정의 D와 read 사이에 올 수 있는 CALL/CALLIND/CALLOTHER 가
       있으면 debt 삽입. CALL마다 무조건 unresolved write(방식 b)는 함수 전체가
       incomplete가 되어 금지.
     - 면제는 `_call_may_write(C, span)` 한 곳: RSP·반환주소 슬롯(공리),
       내부 callee 보존 증명(`configured_dynamic_alias_explanation.py:130-176,421`
       를 코어로), 탈출하지 않은 스택 객체(P0-1 `_alias_free` 와 같은 규칙).
   - 같은 종류의 경로: CALLOTHER(`normalize.py:920-928` 일반 WRITE 취급),
     CALLIND, 외부/thunk(호출 간선 자체가 사라짐).
   - **구현 완료 (1차)**: `src/tdo_v2/call_clobber.py`
     - 바이트 단위 forward 분석: "마지막 call 이후 모든 경로에서 다시 쓰인 바이트"만
       clean. clean이 아닌 바이트를 읽으면 그 연산에 `call_clobber_read` debt 노드
       (`normalize.py` `_materialize_call_clobber_debt`, debt → read 간선).
       기존 정의 간선은 그대로라 출처는 계속 보이고 그 슬라이스만 incomplete.
     - 면제(관측 증거만 사용): 모든 CALL/CALLIND가 `r=r-size; STORE r←복귀주소`
       형태이고 r이 하나일 때 그 레지스터(스택 포인터), 그리고 스택 파생 값이
       메모리 STORE 값·다른 레지스터·CALLOTHER 입력으로 새지 않을 때 그 스택 객체.
       CALLOTHER가 있는 함수는 면제 없음.
     - `query.py` 가 clobber 노드를 unresolved read로 집계, 설명 출력에
       `call_clobber_read` gap 추가(`configured_explanation_graph.py`).
     - 알려진 보수성: 프레임 포인터(`mov rbp, rsp`)도 "다른 레지스터로 복사"라
       탈출로 본다 → RBP 기반 지역 변수는 call 뒤에 incomplete. callee-saved
       레지스터(RBX 등)도 증거가 없으므로 incomplete. 실제 코퍼스 계측 후
       호출 규약 정책(provider) 도입 여부를 결정.
     - 테스트: `tests/intra/test_call_effects.py` 15개 (기존 xfail 3건 해결).
   - **P0-3b (2026-10-06, Fable 설계)**
     - 건전성 수정: 1차의 "탈출하지 않은 스택 객체 전체 면제"를 제거했다. callee는
       포인터를 받지 않아도 자기 SP의 양수 오프셋으로 호출자 프레임에 쓸 수 있다.
       로컬 면제는 관측된 call 형태에서 나온 스택 포인터 레지스터만 남긴다.
     - `CallClobberRead.intervening_calls`: 읽기마다 그 사이에 올 수 있는 call 집합.
     - 해소 `integration/configured_call_clobber_discharge.py`
       (`engine.RootSlice.effective_completeness`):
       - MUST_WRITTEN: 사이에 있는 call이 하나이고, 인증된
         `ObservedCallByteReplacement` 가 읽은 바이트를 callee의 마지막 write W에
         연결하며, callee 안에서 W의 슬라이스가 complete일 때.
       - PRESERVED(레지스터): 모든 exit에서 그 레지스터가 entry 값으로 복원되고
         (COPY/STORE/LOAD 추적), 그 추적 경로에 callee 자신의 call-clobber 읽기가
         없고, callee에 unresolved write가 없을 때.
       - CALLIND/CALLOTHER/외부/미해결 대상/메모리 span은 해소하지 않는다.
     - `engine.analyze_observed_functions` 분리(합성 전체 프로그램 테스트용),
       Bundle admission은 지연 import → 엔진이 Windows에서도 import됨.
     - 테스트: `tests/intra/test_call_clobber_discharge.py` (8개, 실제 함수 간 경로)
     - 실측 (64 케이스, 판정 기준 = "기대 출처 누락인데 확실"):

       | 버전 | 누락+확실 | 정확+확실 | 과다보고+확실 |
       |---|---|---|---|
       | P0-3 이전 | 1 | 39 | 22 |
       | P0-3 local | 0 | 2 | 0 |
       | P0-3b effective | 0 | 16 | 2 |

       남은 불확실 원인(함수 단위 근사): call 뒤 스택 슬롯 LOAD 47, 레지스터 COPY 33,
       RBP 기반 INT_ADD 13, 전역 COPY 11 → 다음은 프레임 보존(PRESERVED 메모리)
       증명(Fable 7단계), 그다음 outparam MUST_WRITTEN(8단계).
   - **P0-3c 프레임 보존 (2026-10-06, Fable 7단계 v1)**: FRAME_PRESERVED
     - 호출자 entry-SP 스택 객체의 span S를 call 토큰으로 callee entry-SP 좌표 P로
       바꾸고, callee의 모든 메모리 write가 (a) 자기 entry-SP 기준이며 P와 겹치지
       않거나 (b) 상수 주소(공리: 로드된 이미지 상수 주소는 스택이 아님)일 때만 해소.
     - 실패 조건: 그 외 base(포인터 인자, LOAD한 포인터, opaque)로의 write,
       unresolved write, CALLOTHER, callee 안의 레지스터 call-clobber 읽기(주소가
       clobber된 레지스터에서 계산됐을 수 있음), 토큰 없는 call, 재귀, 깊이 16 초과,
       S가 그 call의 복귀주소 슬롯과 겹침. 중첩 call은 P를 토큰만큼 옮겨 재귀 검사하고
       중첩 call의 복귀주소 슬롯도 write로 본다.
     - 호출자 쪽 탈출 분석은 필요 없음: callee의 비-SP base write는 전부 실패 처리.
     - 테스트 11개 추가(`test_call_clobber_discharge.py`), 오프셋만 다른 쌍
       (shadow +0x8 OK / 슬롯 +0x28 실패, 중첩 -0x10 OK / +0x50 실패)으로 좌표 변환 검증.
     - 실측(64 케이스): 누락+확실 0 유지, **정확+확실 16 → 23**, 과다보고+확실 2 → 9.
       남은 원인(함수 단위 근사): 레지스터 COPY 27, 스택 슬롯 LOAD 47 → 19,
       RBP INT_ADD 12, 전역 COPY 6.
   - **P0-3d 출력 인자 + 재귀 해소 (2026-10-06, Fable 8단계)**
     - 해소를 "문맥" 단위로 재귀 적용: 루트는 completion의 replacement·proof를,
       callee 안에서는 proof의 `prior_transfers` 를 증거로 쓴다(순환·깊이 가드).
     - OUTPARAM_MUST_WRITTEN: proof/transfer가 (call C, callee W, derefs 0,
       target_span ⊇ S)를 가리키고, C가 읽기를 지배하며 이후 call은 S를 보존하고,
       W가 **모든 exit에서 그 바이트의 유일한 마지막 정의**이며, callee의 다른
       메모리 write는 스택(겹치지 않음)/상수 주소뿐이고, 중첩 call이 S를 쓰지 않고,
       callee의 call debt가 모두 해소될 때.
     - W 값 설명 가드: W 슬라이스의 callee debt 해소 + 도달한 SOURCE 라벨이 루트
       보고 라벨에 있음 + 호출자 레지스터에서 온 입력은 호출자 쪽 상태가 완전하고
       라벨이 보고됨. 호출자 메모리에서 온 입력은 v1에서 실패. `_value_origins` 가
       매핑 실패 시 출처를 조용히 건너뛰므로 proof 존재만으로는 부족하다.
       W가 SOURCE 경계 정의 자체이면(라벨 보고됨) 그 값은 정의상 그 라벨 → 추적 중단.
     - PRESERVED 완화(7b): 보존 추적 경로의 clobber 읽기도 callee 안에서 재귀 해소되면 허용.
     - **건전성 버그 수정**: `_shared_terminal_writes` 는 "모든 exit에서 W가 후보 중
       하나"만 요구한다(JOIN 포함). must-write 판정은 `_sole_terminal_writer`
       (모든 exit에서 그 바이트의 정의 집합이 정확히 {W})로 대체.
     - 테스트: `test_outparam_discharge.py` 10개, discharge 테스트 갱신(총 81).
     - 실측(64 케이스): 누락+확실 0 유지, **정확+확실 23 → 28**, 과다보고+확실 9 → 16.
       단순 8케이스 4 → 7, dfbench_cpp 1 → 0(호출자 메모리 입력 가드로 보수화).
       남은 원인: 스택 슬롯 LOAD 15, 레지스터 COPY 13, RBP INT_ADD 9, 전역 COPY 5.
   - **순서: P0-3 → P0-1.** 공통 debt 구조를 먼저 세우고 P0-1은 reason만 추가.
     실제 코퍼스에서 incomplete 비율이 크게 오를 수 있어 09 testbed 계측이 필요.
5. **P0-1**: 방식 (a) may-alias debt. SSA는 후보만 기록(`memory_ssa.py` 읽기 루프),
   정책 `_alias_free` 는 `relative_memory.py`, debt 노드·간선(후보 write → debt →
   read)은 `memory_graph.py`. 초기 증명 규칙: RSP 단일 atom 객체는 RSP 표현식이
   STORE 값/CALL 입력/opaque 식에 나타나지 않을 때만 다른 객체와 alias-free.
   integration 파급: `configured_function_memory.py:260`,
   `configured_recursive_local_reads.py:243`(객체 identity 재생산),
   `memory_graph.py:196-215`(기대 간선 검증) 동시 수정.
6. 09 testbed Bundle export 후 회귀 비교
7. P1, P2

## 5. 그래프 충실성 (call 없는 함수, 2026-10-06)

목표: call 없는 함수에서 그래프가 실제 실행의 모든 의존을 담는다. 역추적은 그 위의 탐색일 뿐이다.

- **독립 오라클** `tests/intra/pcode_interpreter.py`: Low-Pcode 구체 실행기. 바이트마다
  "마지막으로 쓴 연산(또는 진입 상태)"을 추적해 동적 의존 W→R을 기록한다.
  `tests/intra/graph_oracle.py`: 각 동적 의존이 그래프의 역방향 경로 R→W로 있는지
  (진입 레지스터는 OBSERVED_INPUT 도달) 판정. 주소를 모르는 읽기의 진입 메모리는
  그 읽기에 직접 붙은 unresolved debt만 인정.
- **데이터 의존 구멍과 수정**
  1. 주소를 해석 못 하는 LOAD/STORE에 연결 간선이 없었다 → `may_alias.py` 확장:
     unknown-address write는 모든 객체(비공개 프레임 포함)를 덮을 수 있고, unknown-address
     read는 이전의 모든 메모리 write를 후보로 연결(writer → debt → read).
  2. 명령어 안의 조건 분기(`cmov`: `CBRANCH +2; COPY`)에서 건너뛸 수 있는 쓰기를 무조건
     쓰기로 처리 → 약한 갱신(이전 값도 읽음)으로 수정. 명령어 안 루프(REP), 상대 BRANCH,
     건너뛰는 메모리/제어 연산은 `UNSUPPORTED_INTRA_INSTRUCTION_FLOW` typed 실패.
- **제어 의존** `src/tdo_v2/control_dependence.py`: 명령어 CFG의 후지배자(가상 EXIT, 종료
  불가 노드·함수 밖 목적지는 EXIT로)로 Ferrante 제어 의존 계산, 명령어 안 forward
  CBRANCH 포함. 간선 `control_dependence`(결정 연산 → 의존 연산).
  `backward_reachable(follow_control=False)` / `BackwardSliceQuery.run(include_control=False)`
  기본은 데이터 전용 → 기존 결과 불변.
- **검증 결과**
  - 합성 무작위 함수(부분 레지스터, ZEXT/SEXT/SUBPIECE/PIECE, 비교→분기, 카운터 루프,
    cmov, 별칭 포인터, 메모리에서 꺼낸 포인터, 비-affine 주소) 480개: 동적 의존 누락 0.
  - 분기 뒤집기 오라클 300개: 제어 의존 위반 0.
  - 오라클 변이 검사: may-alias 간선 제거 시 누락 557건, 제어 간선 제거 시 위반 328건 검출.
  - 실제 call 없는 함수 38개(Bundle 4개, 동적 의존 약 9.9만): 누락 0. 단 이 함수들에는
    분기가 없어 제어 의존은 실제 코드로는 구조 확인만 함(분기 있는 실제 함수 23개 중 23개
    간선 생성, 함수 밖 조건 점프 수정 후).
  - 64 케이스 결과 불변(데이터 전용 기본값).
- **call이 있는 실제 함수까지 확대 (검증기 전용 확장)**: 실행기의 `havoc_calls` 모드에서 call은
  스택 포인터를 뺀 모든 레지스터를 임의 값으로 바꾸고 call 직전의 스택 포인터를 복원한다
  (callee의 메모리 효과는 재현하지 않음 → 그 부분은 검증 범위 밖). call이 만든 값을 읽는
  명령은 `call_clobber_read` debt가 직접 붙어 있어야 하고, 주소 계산에 call debt가 있는
  메모리 접근은 주소가 다를 수 있으므로 설명된 것으로 본다. call 명령의 복귀주소 push
  (transient 연산)는 엔진처럼 제외.
- **세 번째 구멍**: Ghidra는 `cmovcc` 를 `CBRANCH <다음 명령어 주소>; COPY` 로도 표현한다
  (실제 MinGW 함수 0x140004b00). 상대 분기만 처리하던 약한 갱신/제어 의존을 "명령어 중간의
  CBRANCH 이후 연산은 건너뛸 수 있음"으로 일반화(`control_dependence.in_instruction_skips`).
- 결과: 실제 Bundle 4개의 전체 함수 134개(call 포함 96개, 분기 포함 23개), 동적 의존 약
  39만 건 대조 — 누락 0, 설명되지 않는 누락 0, 제어 위반 0. BRANCHIND(점프 테이블) 실행은
  미지원으로 일부 run 제외.

## 6. source/sink 경계 자르기 — TEST-ONLY 특이 조건 (2026-10-06)

> **이 기능은 테스트를 위해 사용자가 허용한 특이 조건이다.** 관측된 증거가 아니라 선언된
> 가정이며 기본값은 꺼져 있다. 이 모드로 얻은 결과는 반드시 "가정 사용"으로 보고한다.

- 목적: 09/10 testbed의 복잡한 로직은 모두 source/sink를 호출하는 케이스 함수 안에 있다.
  경계 호출을 선언된 효과로 자르면 케이스 함수 본문을 call 없는 함수처럼 검증·역추적할 수 있다.
- 선언: `BoundaryRule(assume_call_effect=True)` + `analyze_frozen_bundle(assume_boundary_call_effects=True)`
  (`src/tdo_v2/assumed_call_effects.py`). source 호출 = 선언된 반환 레지스터에만 확실한 쓰기,
  sink 호출 = 인자 레지스터 읽기, 그 밖의 레지스터·메모리는 모두 보존된다고 **가정**.
  선언된 호출에는 call_clobber debt가 붙지 않고, source 쓰기가 호출자 쪽 SOURCE 출처 노드가 된다.
  도구: `run_dfbench.py --assume-boundary-effects`, `measure_bundle.py --assume-boundary-effects`
  (출력에 "TEST-ONLY ASSUMPTION" 표시).
- **함께 찾은 기존 버그(기본 모드)**: sink 인자가 분기 합류 값이면 sink 시작점이 CALL 명령에
  묶이는데, CALL은 그래프에서 아무것도 읽지 않아 "출처 없음 + 완전"이 나왔다. 이제 이런
  시작점은 `LocalCompleteness.unbound_roots` 로 집계되고 불완전으로 표시된다. 가정 모드에서는
  sink가 인자를 읽으므로 정상적으로 연결된다.
- 결과
  - 그래프 검증(가정 모드): source/sink만 부르는 케이스 함수 디버그 38개·최적화 29개 포함 전체
    함수에서 누락 0, 제어 위반 0.
  - 64 케이스 (기본 → 가정): PASS 39 → **50**, 함수 내부만으로 정확+확실 2 → **29**,
    효과적 정확+확실 28 → **40**, 누락+확실 0 유지(전 모드).
- **가정 모드에서 함수 내부만으로 불확실한 케이스 분석 (2026-10-06)**
  - 거의 전부가 source/sink가 아닌 함수 호출(보조 함수, malloc/free, memset, strcpy, 간접
    호출, TLS)을 포함 → 함수 내부 범위 밖(정의상 판단 불가).
  - 함수 내부 원인만 있는 것은 2건이었다.
    - DFB102: 스택 탈출 분석이 흐름을 보지 않아 `push rbp`(호출자 RBP 저장)를 "스택 주소를
      메모리에 저장"으로 오판 → 프레임이 비공개로 인정되지 않아 전역 쓰기와 지역 변수가 겹칠
      수 있다고 판정. **탈출 분석을 CFG 순방향(흐름 민감)으로 수정**하고, 선언된 경계 호출은
      레지스터를 관찰하지 않으므로 탈출 판단에서 제외. 실행 대조 누락 0 유지 확인.
    - DFB044 (`arr[source_C() & 3]`): 인덱스가 비-affine이라 주소를 알 수 없음 → 진짜
      불확실성. 값 범위 분석이 필요하므로 보류.
  - 64 케이스(가정 모드): PASS 50 → 53, 함수 내부만으로 정확+확실 29 → 30, 효과적 41,
    누락+확실 0. 기본 모드 결과 불변.

## 7. 꼬리 호출(`jmp sink`) 경계 지원 (2026-10-06, Fable 설계)

- 문제: MinGW -O2 빌드에서 케이스 함수 53개 중 45개가 sink를 `jmp dfb_sink_int`(P-code BRANCH)로
  부른다. 엔진은 CALL/CALLIND만 경계로 인식해 sink 시작점이 없었고 75 케이스 중 70개가 MISSING.
- 판별 기준: **Ghidra가 그 명령어의 flow type을 call로 분류했는가**(`FlowType.isCall()`, Bundle의
  `flow_type.is_call`). 함수 밖으로 나가는 분기 중에는 공유 코드 점프(is_call=False)도 있으므로
  "목적지가 함수 밖"만으로는 추측이 된다. 점프 테이블(COMPUTED_JUMP)은 자동 제외.
- 형식 변경: naming 사이드카 **v2** (`tdo-v2-call-naming-sidecar-v2`, exporter revision 2,
  content domain v2). 기존 `calls` 와 분리된 `tail_calls` 배열, opcode BRANCH/CBRANCH/BRANCHIND
  (BRANCHIND는 CALLIND처럼 target 없는 INDIRECT). exporter 소스 해시가 바인딩이므로 기존 v1 Bundle은
  재export가 필요(이중 디코드는 두지 않음).
- Python: `call_contracts.TailCallSeed`, `call_seeds.seed_tail_calls`(exporter와 같은 술어),
  `ObservedFunctionEvidence.tails`, `CapturedNamingSidecar.tail_rows`. 꼬리 호출은
  `FunctionCallSeedUnit.callsites` 에 넣지 않는다 — call effect·함수 간 계층이 CALL/CALLIND
  1:1을 가정하므로 **경계 인식 전용**이고 함수 간 의미는 바뀌지 않는다.
- 경계: 꼬리 호출된 **sink만** 처리(`_bind_tail_call_sinks`), 점프 시점의 인자 상태가 시작점.
  인자 정의를 못 찾으면 시작점을 버리지 않고 점프 연산에 묶어 `unbound_roots`(불완전)로 보고.
  꼬리 호출된 source(`return source()`)는 지역 reader가 없어 무시.
- TEST-ONLY 가정 모드: 꼬리 호출 sink는 인자 읽기만 선언(쓰기 금지). 검증기는 선언 적용 후에도
  점프를 수행한다.
- 영향 없음(근거): call_clobber(점프 뒤 코드 없음), 스택 탈출(점프 시 프레임 해제, 이후 읽기 없음),
  제어 의존(함수 밖 목적지는 EXIT).
- 테스트: `tests/intra/test_tail_calls.py` 7개.
- 결과 (v2 exporter로 재export: 디버그 64케이스 subset, 최적화 win_core)
  - 디버그: 기본 PASS 39, 가정 PASS 53 — 꼬리 호출이 없어 이전과 동일(회귀 없음).
  - 최적화(MinGW -O2): 시작점 5 → 57, MISSING 70 → 24(나머지는 인라인/병합으로 export 단계에서
    빠진 케이스). 기본 PASS 2 → 40, 가정 PASS 46. 가정 모드에서 함수 내부만으로 정확+확실 29,
    효과적 35. **누락+확실 0 (모든 모드)**.
  - 그래프 실행 대조(최적화, 두 모드): 함수 87개, 의존 약 10만 건, 누락 0, 제어 위반 0.


## 8. 검증 코퍼스 · IAT · p-code 블록 (2026-10-06, Fable 설계 A안)

완성 기준(call 없는 함수 그래프):
1. 검증 자료 전 함수에서 누락 0·제어 위반 0 (gcc/clang, -O0/-O2/-O3, 32비트 포함)
2. UNSUPPORTED 실패 0 (남으면 문서화)
3. 검증기(인터프리터)가 건너뛰는 run/연산 0
4. 가장 큰 함수도 합리적 시간
5. 09/10 전 모드에서 "누락+확실" 0

- **검증 코퍼스** `tests/corpus/intra/intra_corpus.c`: call 없는 export 함수 26개(switch 밀집/희소,
  문자열·메모리 루프, CRC, 상태기계, 행렬, 부동소수, 정렬, 이진탐색, 포인터 별칭 등).
  `build.sh` 로 7종 빌드(clang ELF x64 -O0/-O2/-O3(AVX2), x86 -O0/-O2, MinGW gcc PE -O2
  `rep_byte`, -O3). `tools/graph_fidelity/corpus_run.sh [runs] [--measure-only]` (WSL)이
  export + 실행 대조.
- **검증기 보강**: 마스크 폭 제한 제거(AVX 32/64바이트), BRANCHIND(점프 테이블) 선택을
  분기 결정으로 기록(-O0 switch 제어 위반 44/76건은 검증기 오탐이었음).
- **IAT 수정**: `call [__imp_X]` 의 흐름 대상이 외부(EXTERNAL) 공간 주소라 입장이 실패하던 문제.
  호출 명령어(flow.is_call)에 한해 외부 공간 대상을 건너뜀(`_scope_observation._flow_targets`,
  `_AddressSpaceIndex.external_coordinate`).
- **p-code 블록** (`src/tdo_v2/pcode_blocks.py`): 명령어 내부 흐름(cmov의 `CBRANCH`,
  `rep` 의 `CBRANCH <다음 명령어>` … `BRANCH <자기 주소>`, 상대 분기)이 있는 명령어만
  분기 지점에서 서브블록(`<명령어키>#<연산 번호>`)으로 쪼갬. 첫 서브블록은 명령어 키를 유지.
  - normalize: 효과 블록·선행자·종료 블록을 p-code 블록 그래프에서 구성. 이전의 "건너뛸 수
    있는 쓰기 = 약한 갱신" 근사와 `UNSUPPORTED_INTRA_INSTRUCTION_FLOW` (rep) 실패를 대체.
    도달 불가 서브블록의 연산은 실행되지 않으므로 제외.
  - 제어 의존(`control_dependence`)과 스택 탈출 분석(`may_alias._stack_escapes`)도 같은
    블록 그래프 위에서 계산(`in_instruction_skips` 삭제). 블록의 `exits` 는 함수를 떠날 수
    있음(RETURN, 함수 밖 분기)을 뜻하며 가상 EXIT로 이어짐.
  - 남은 미지원(타입 실패): 명령어 밖으로 나가는 상대 분기, 마지막이 아닌 BRANCHIND.
  - Fable이 찾은 구멍: 레지스터만 쓰는 명령어 내부 루프(`CBRANCH self`)에서 조용한 누락 96건
    → 0건 (`test_register_only_in_instruction_loop_carries_values_across_iterations`).
- **relative_memory 루프 규칙(확인)**: 주소식 원자는 ENTRY 값과 그 결정적 함수(불투명 토큰)뿐이고,
  JOIN은 모든 입력이 같은 식일 때만 받아들이며 순환(루프 운반 값)은 `None`(모름) → 루프마다 다른
  주소가 같은 객체로 합쳐지지 않음. 추가 코드 불필요.
- **점프 테이블 미복원**: Ghidra가 대상을 못 찾은 BRANCHIND는 함수 밖으로 나가는 것으로 취급되고,
  대상 코드는 함수 본문에 들어오지 않음. 본문에 있는데 도달 불가하면 기존대로
  `DISCONNECTED_OBSERVED_CFG` 타입 실패(측정 자료 전체에서 0건).

- **검증기 보강 2**: 반환하지 않는 호출(`call` 뒤 fallthrough 없음, MSVC 0x401d10)에서 run을
  건너뛰던 것을 "실행 종료"로 처리(건너뛴 run 6 → 0).
- **P1 정리**: P1-2 죽은 `VALUE_VERSION` 노드/`value_nodes`/`defines` 간선 제거. P1-3 `EdgeKind`
  (StrEnum, 닫힌 어휘) 도입 — `EdgeRecord` 는 EdgeKind 값만 받고 직렬화 호환을 위해 일반 str로 저장.
  P1-1(재투영 루프 상한)은 앞서 완료.
- **성능** (결과 동일성은 무작위 동치 검사로 확인):
  - 메모리 SSA 고정점을 직선 체인(단일 선행/단일 후속) 단위로 풀고 펼침 — 최소 고정점 불변.
  - 제어 의존 후지배자를 집합 교집합(O(n²))에서 Cooper-Harvey-Kennedy로 교체(무작위 그래프 3,000개 동치).
  - 상태 합집합/차집합/마스크: 양쪽이 비슷한 크기면 한 번의 sweep (무작위 5,000쌍 동치).
  - 합성(별칭 많음) 1000명령 56초 → 14초. zlib 실측: inflate(2,343명령) 295초 → 211초,
    1,423명령 49초 → 27초, 그 외 1,300명령 이하 20초 이하.
  - 남은 병목: 블록마다 상태 전체(수천 run)를 전파하는 구조(O(블록×상태)) + 재투영으로 SSA 3회.
    더 줄이려면 희소(sparse) 메모리 SSA 설계 변경 필요 → 별도 결정 사항.
- **관찰(범위 밖)**: win32 MSVC Bundle의 64케이스 실행(`run_dfbench`)이 함수 간 계층
  (`configured_write_event_engine` → `configured_function_memory.latest_definition`)에서 15분 이상
  끝나지 않음. 함수 내부 그래프 측정은 2.7초. 함수 간 작업 시 확인 필요.

결과:
- 코퍼스 7종 × 26함수: 누락 0, 설명 안 되는 누락 0, 제어 위반 0, 건너뛴 run 0, 정규화 실패 0
  (gcc rep 3건 해소). 대조한 동적 의존 약 101만 건.
- 실제 Bundle (기본·가정 모드 모두): v2 release 87함수, debug 106함수, win32 MSVC 79함수(IAT 수정으로
  입장), zlib 25함수(inflate 포함, 의존 24.7만 건) — 누락 0, 제어 위반 0, 건너뛴 run 0, 실패 0.
- 64케이스: 디버그 PASS(정확) 39 / 가정 53, 최적화 40 / 가정 46 — 변화 없음, 누락+확실 0.
- 테스트: Windows 129 passed 1 skipped, WSL 130 passed.

## 9. 결정: 메모리 SSA 묶음(atom class) 희소 계산 (2026-10-07, Fable 검토)

**결정**: 큰 함수 성능은 "묶음별 희소 계산"으로 해결한다. **채택, 착수 시점은 보류** — 함수 내부
추적의 기준선(골든)을 먼저 확정한 뒤 시작한다(아래 선행 조건).

- 근거: 격자에 atom 간 결합이 없다. write는 덮는 atom 구간을 strong kill(`_replace`)하고 읽기·JOIN·
  끝 상태는 "atom → 도달 raw 정의 집합"의 순수 함수. 결합은 출력 인코딩(fragment 병합, 끝 상태 트리)뿐.
  현재 비용 O(블록 × 상태 크기)는 레지스터·unique atom 수천 개가 모든 블록으로 흐르기 때문.
- 방법(Choi–Cytron–Ferrante sparse evaluation graph):
  1. atom을 서명 `(connected span, 그 atom을 덮는 write 집합)`으로 묶음(class)화 — 같은 서명이면
     모든 지점에서 도달 집합이 같다.
  2. 묶음별 관심 노드 T = writer ∪ reader ∪ terminal ∪ entry, SEG = T ∪ IDF(T), 간선은 dominator tree의
     가장 가까운 관심 조상. back-edge가 있으므로 SEG 위 fixpoint.
  3. 읽기는 블록 in-값에서 action 순서대로 블록 내 write를 재생해 fragment 구성(`_read_fragments` 동치).
- 기대: 메모리 SSA 6~15배(inflate 수 분 → 수십 초). 위험 중 — 기존 dense 엔진을 oracle로 보존.
- 탈락안: Cytron φ 단독(결국 같은 fixpoint), unique 특수 처리(p-code 서브블록 때문에 unique가 블록을
  넘음 — 가정이 틀림), 재투영 간 증분(무효화 위험; 묶음 이후 필요 시).
- 보존할 것: `_build_partition`/`_raw_definitions`/정렬 규칙 재사용, JOIN 식별자 (span, 읽는 블록 키),
  JOIN 소스는 raw id만, entry 블록 back-edge 허용, 한 빌드에 IdSet pool 하나.
- 함정: 부분 겹침(서명은 atom 단위), KILL write도 정의, unresolved write는 SSA 밖, 도달 불가 블록에는
  read/terminal이 없다는 암묵 불변을 명시 assert로, 서브블록 키 `addr#n` 유지.

**선행 조건(착수 전)**
0. 끝 상태 저장 정규화: 현재 `_serialize_terminal_states` 가 AVL 트리 모양을 그대로 저장해, 같은 의미라도
   계산 순서에 따라 `state_nodes` 가 달라진다(434bc56의 체인 압축·sweep도 모양을 바꿨을 수 있음).
   run 열에서 균형 트리를 다시 만들어 저장하도록 바꾸고, 노드 수가 함수 간 계층 한도(8192,
   `configured_function_memory.py:434`) 안인지 확인.
1. 골든 기준선: 코퍼스·실제 Bundle 전 함수의 `LocalMemorySsaResult` (와 그래프 요약)를 파일로 고정.
   이후 모든 성능 변경은 "골든과 완전히 같음"으로 검증.
2. 비교 장치: dense/sparse 엔진 env flag 분기 + 동치 테스트(무작위·실제 유닛, 재투영 각 패스 포함).

**선행 조건 진행 (2026-10-07)**
- 0 완료: `_serialize_terminal_states` 가 run 열로 균형 트리를 다시 만든 뒤 직렬화(트리 모양 무관).
  `tests/intra/test_terminal_state_canonical.py` (이전 코드에서는 실패함을 확인). 전 검증 자료
  752함수에서 내용(run 열) 차이 0, 최대 노드 1,306개(한도 8,192).
- 434bc56 속도 개선 검증: 속도 개선만 되돌린 코드(체인 압축·sweep·CHK 제거)와 비교해 752함수 전부
  메모리 SSA 내용·그래프(제어 의존 포함) 동일.
- 1 완료: 골든 기준선 `D:\01_gitproject\14_TDO_v2\golden\v1` (13MB, `MANIFEST.txt` 에 코드·Bundle
  generation). 도구 `tools/graph_fidelity/ssa_snapshot.py` (dump/compare, 결정적 — 같은 입력 두 번
  비교 0 차이), `golden_all.sh dump|compare <dir>`. 이후 변경은
  `golden_all.sh compare <골든> <새 결과>` 가 0이어야 한다(의도된 변경이면 골든 v2로 갱신하고 사유 기록).

## 10. 10_tdo_UE_testbed 재export와 검증 (2026-10-07)

- `tools/bundle_export/ue_export.sh`: cpp_like `.so` 4종(P0/P1 × x64/x86, 11케이스)과 UE 모듈
  DLL 2종(Development 22케이스, DebugGame) → `/root/tdo_bundles/ue-*`. 인라인으로 사라진 이름은
  하나씩 제외하며 재시도(이번엔 제외 0).
- **IAT 점프 입장**: `jmp [__imp_X]` (Ghidra는 computed jump로 분류)의 흐름 대상이 EXTERNAL 공간이라
  UE DLL 세션이 50번째 함수에서 멈췄다. EXTERNAL 공간은 이 함수의 코드가 아니므로 호출뿐 아니라
  모든 명령의 EXTERNAL 대상을 후속에서 제외(점프는 함수를 떠남). 다른 비메모리 대상은 여전히 실패.
  테스트 `tests/intra/test_import_targets.py` (synthetic에 EXTERNAL 공간 추가).
- **검증기 규칙 수정**: 호출의 반환주소 push가 남긴 스택 바이트를 주소 미상 읽기(`rep movsb`,
  unresolved_memory_read 부채)가 읽으면, 메모리 바이트에 대해 "주소 미상"을 설명으로 인정
  (CALL 작성자에 대해서만 이 규칙이 빠져 있었음). 엔진 변경 없음.
- **지표 도구 ABI 수정**: TEST-ONLY 경계 규칙의 sink 인자 레지스터가 Windows x64(RCX) 고정이라
  ELF에서 엉뚱한 레지스터를 추적("source 없음 + 확실" 11건, 측정 도구 오류). Bundle 원본 헤더로
  PE→RCX, ELF→RDI 선택(`run_dfbench.abi_of`). 32비트(스택 인자)는 규칙으로 표현 불가 → 지표 미지원.
  `dfbench_metric.sh` 는 10 UE 정답 형식(expected_data_sources 등)도 읽고, 각 실행에 timeout.
- 결과 (기본·가정 모드 모두, 누락 0 · 설명 안 되는 누락 0 · 제어 위반 0 · 건너뜀 0 · 실패 0):
  cpp_like 4종 각 16함수, UE DLL Development 71함수(의존 31만), DebugGame 119함수(의존 81만).
- 케이스 지표(x64): cpp P1 기본 정확 10/11, 가정 11/11(확실 10). cpp P0(-O0) 기본 1/11, 가정 9/11,
  누락+확실 0. UE DLL은 함수 간 계층에서 끝나지 않음(win32와 같은 `configured_write_event_engine`
  / `configured_origin_projection` 경로) → 함수 간 작업 때 확인.
- 골든 **v2** (`D:\01_gitproject\14_TDO_v2\golden\v2`, 20MB): v1(현재 코드와 0 차이) + UE 12세트,
  총 1,260 함수-모드.

## 11. 묶음(희소 SSA) 1단계: 엔진 동치 비교 장치 (2026-10-07)

- `memory_ssa.build_local_memory_ssa` 가 엔진 등록부로 분기: `dense`(기본, 현재 엔진),
  `dense-unchained`(체인 압축 없는 기준 구현). `TDO_V2_MEMORY_SSA_ENGINE=<이름>` 으로 엔진 선택,
  `TDO_V2_MEMORY_SSA_CROSSCHECK=<이름>` 이면 같은 입력을 그 엔진으로도 만들어 다르면
  `MemorySsaEngineMismatch` (첫 차이 필드·원소·값을 메시지에). 모르는 엔진 이름은 즉시 오류.
  새 엔진은 `register_memory_ssa_engine` 으로 등록.
- `memory_ssa_compare.memory_ssa_differences`: 필드별 첫 차이를 읽을 수 있게 설명.
- `tests/intra/memory_units.py`: 메모리 SSA 입력(`LocalMemoryUnit`) 무작위 생성 — 부분 겹침, 4종 객체,
  KILL 쓰기, 주소 미상 접근, back edge(entry·self loop 포함), 서브블록 키, 다중 종료 블록, 블록 순서 섞기.
- `tests/intra/test_memory_ssa_equivalence.py`: 등록된 모든 대체 엔진이 무작위 600개 입력과 정규화
  경로(재투영 패스 포함, rep 루프 포함)에서 dense와 완전히 같아야 함. 심은 결함을 정확히 보고하는지도 검사.
- 민감도 확인(변이 시험): back edge 누락 / KILL을 데이터 쓰기로 / 쓰기 폭 축소 — 600개 중 각각
  455 / 436 / 567개에서 차이 검출.
- 실제 Bundle: CROSSCHECK=dense-unchained 로 골든 전체(1,260 함수-모드, 재투영 패스마다 비교)를
  만들었을 때 불일치 0, 골든 v2와 0 차이. 환경 변수가 실제 경로에 적용됨도 확인.
- 묶음 엔진 검증 절차: (1) `pytest tests/intra/test_memory_ssa_equivalence.py` (sparse 등록 시 자동 포함),
  (2) `TDO_V2_MEMORY_SSA_ENGINE=sparse TDO_V2_MEMORY_SSA_CROSSCHECK=dense golden_all.sh dump <dir>` 후
  `golden_all.sh compare golden/v2 <dir>` 0 차이, (3) measure_bundle 누락 0.

## 12. 묶음 2단계: atom class (2026-10-07)

- `src/tdo_v2/_memory_ssa_classes.py`: atom을 서명 `(connected span, 덮는 write 정의 집합)`으로 묶음.
  `check_atom_classes(unit)` 는 dense 엔진의 모든 지점(블록 입구, action 사이, 블록 출구)에서 한 묶음의
  atom들이 같은 정의 집합인지 검사. dense 고정점은 `memory_ssa._dense_states` 로 분리(결과 불변:
  골든 v2와 1,260 함수-모드 0 차이).
- 테스트 `tests/intra/test_atom_classes.py`: 무작위 600개, 정규화 경로(재투영 포함), 묶음이 atom을 정확히
  분할·서명 유일, 잘못 묶으면 검사기가 잡는지.
- 실제 Bundle 검사(`tools/graph_fidelity/atom_class_report.py`): 09 3종, UE cpp·DLL, 코퍼스, zlib 전부
  class-check OK.
- 관찰: 묶음 수 ≈ atom 수(합쳐지는 atom은 적음). 이득은 각 묶음을 건드리는 블록이 적은 데서 온다.
  작업량 추정(블록×atom 대비 묶음별 관심 블록 합, IDF 추가 전): 09 3.8~4.6배, UE DLL 10~11배,
  코퍼스 -O3 9.5배, zlib 25.6배, inflate 단위 28~37배. 함수가 클수록 이득이 크다.

## 13. 묶음 3단계: sparse 엔진 (2026-10-07)

- `src/tdo_v2/_memory_ssa_sparse.py`, 엔진 이름 `sparse`. 묶음마다: 쓰는 블록의 출구 값 = {블록 안 마지막
  쓰기}, 그 외 블록은 통과. φ 지점 = entry + 쓰는 블록의 반복 지배 경계(Cytron IDF), φ 값은 ENTRY(entry만)
  + 선행자 출구 값의 합집합을 최소 고정점으로. 그 외 지점은 가장 가까운 지배 쓰기/φ 블록의 값
  (Choi–Cytron–Ferrante). 필요한 곳(읽기 블록, 종료 블록)의 입구 값만 계산하고, 읽기는 블록 안 쓰기를
  action 순서로 재생.
- 결과 조립(읽기 조각·JOIN·끝 상태)은 `memory_ssa._assemble` 로 분리해 dense와 공유 — 두 엔진이 다를 수
  있는 곳은 값 계산뿐.
- 검증: 동치 테스트(무작위 600 + 정규화 경로) 통과, 추가 무작위 5,000개 + 큰 입력(≤60블록) 600개 불일치 0.
  실제 Bundle 전체를 `ENGINE=sparse CROSSCHECK=dense` 로 생성 — 단위마다 교차 확인 불일치 0, 골든 v2와
  1,260 함수-모드 0 차이(그래프 포함이므로 실행 대조 결과도 동일).
- 성능(`tools/graph_fidelity/engine_timing.py`, zlib): 메모리 SSA 215.7초 → 14.3초(15배), inflate
  139초 → 4.6초(30배). 정규화 전체 284초 → 91초, inflate 188초 → 60초. 합성 1000명령 14.6초 → 8.2초.
- 남은 병목(inflate 프로파일): may_alias 전방 분석(`_meet`), call_clobber 전방 분석(`meet`) — 둘 다 블록마다
  전체 상태를 들고 다니는 같은 구조. 4단계(선택) 대상.
- 기본 엔진은 아직 `dense`(사용자 결정 대기).

## 14. 묶음 4단계: call_clobber · may_alias sparse (2026-10-07, Fable 검토)

- 두 분석을 바이트별 gen/kill 문제로 재정식화(Fable: 정확히 등가, SEG 공식 정확 확인).
  - call_clobber: 그 바이트를 보존하지 않는 호출 = gen(호출 키), 바이트를 덮는 쓰기 = kill. 한 effect 안에서
    읽기 → 호출 → 쓰기 순. 묶음 서명 (덮는 쓰기, 보존하는 호출).
  - may_alias: 객체 o의 바이트에 대해, `effect.writes` 순서대로 o에 대한 쓰기 = kill, 별칭 가능한 다른 객체에
    대한 쓰기(전부 private이 아니면) = gen, 그 뒤 주소 미상 쓰기 = 모든 객체 gen. `_ANY_WRITE` 는 kill 없는
    의사 바이트. private 프레임 필터·`elif` 주소 미상 읽기 행은 읽을 때 그대로 적용. 서명 (객체, 덮는 쓰기).
- 공용 `src/tdo_v2/_sparse_dataflow.py`: `DominatorGraph`(도달 가능 블록만) + `solve_gen_kill`
  (P = 이벤트 블록 ∪ IDF ∪ entry, gen만 있는 블록도 P에 포함, 최소 고정점). 메모리 SSA sparse도 같은 지배
  트리 사용. `run_dataflow` 로 엔진 선택(`TDO_V2_DATAFLOW_ENGINE`)·교차 확인(`TDO_V2_DATAFLOW_CROSSCHECK`).
- 구현 `_call_clobber_sparse.py`, `_may_alias_sparse.py`; dense는 `_dense_rows` 로 기준 유지.
- 검증: 솔버 단독 무작위 그래프 2,000개 = 전체 고정점(변이 3종 각각 1,100+개 검출), 정규화 경로 교차 확인
  테스트(`tests/intra/test_dataflow_equivalence.py`, 실제 행이 비교되는지 검사), 실제 Bundle 전체 교차 확인
  불일치 0, 골든 v2 0 차이.
- Fable이 우려한 "호출·쓰기 블록이 모든 묶음의 이벤트라 P가 CFG 전체에 가까워질 수 있음"은 실측에서
  문제되지 않았다(inflate 호출 24개 / 2,349블록).
- 성능(zlib, 메모리 SSA sparse 기준): 정규화 전체 74.8초 → 27.7초, inflate 49.4초 → 9.8초.
  처음(dense 전부) 대비 inflate 188초 → 9.8초(약 19배).
- 기본 엔진: 메모리 SSA·call_clobber·may_alias 모두 `sparse`. dense는 기준/교차 확인용.
- 남은 비용(inflate 프로파일): 메모리 SSA 결과 조립(`_assemble`)과 정의 집합 interning이 절반.
