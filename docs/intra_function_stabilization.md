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
