# 함수 간 설계: 요약 기반 (2026-10-07, Fable 검토 반영)

배경: `docs/interprocedural_investigation.md` — 기존 계층은 루트마다 재전개(요약·memo 없음), 평가 시점 없는
PointerPath(무한 루프), 재귀 미지원. 새 설계는 **완성된 intra 그래프에서 함수 요약을 bottom-up으로 만들고
호출 지점에서 물리 바이트로 인스턴스화**한다(Sharir–Pnueli functional approach: 데이터 의존에 대해 완전 문맥 민감).

원칙(유지): 놓치지 않는다(모르면 부채/불완전), 호출 규약 비가정, 선언(가정)과 증명을 결과에서 구분.

## 1. 함수 요약 (`FunctionSummary`)

끝 상태(`observed_terminal_states`)의 **모든 바이트 run**을 넷 중 하나로 분류한다(exit별, 그 뒤 합침).

| 분류 | 의미 | 비고 |
|---|---|---|
| `IDENTITY(src)` | 끝 값 = 입구 바이트 src의 값 그대로 | ENTRY 정의뿐 아니라 push/pop 복원 포함. 판정기 = `configured_call_clobber_discharge._callee_preserves` 승격. src가 같은 위치면 preserved. swap은 교차 IDENTITY |
| `AFFINE(src, c)` | SP 전용: 끝 SP = SP_entry + c | `relative_memory` 주소식으로 c 계산. stdcall `ret imm16` 지원 필수(`may_alias._return_shape` 는 미지원) |
| `COMPUTED(deps, origins, debts, control_deps)` | 끝 정의 → ENTRY 역추적 입구 바이트 집합 + 내부 source 라벨 + 도달 부채 종류 + 제어 의존 입력(별도) | 기본 데이터 전용 결과 불변 |
| `UNKNOWN(reason)` | unresolved write, 대상 미상 CALLIND/CALLOTHER/외부 호출 이후 | 현재 call_clobber 부채와 같은 의미 |

유도: must-write(모든 exit에서 IDENTITY 아님) / may-write / preserved(모든 exit에서 같은 위치 IDENTITY).

추가 처리:
- callee 프레임 쓰기(SP_entry 아래): caller 스택 (token + 음수 오프셋)으로 may-write. 프레임 바닥 아래는
  하나의 추상 원소 `below_frame` 으로 접음(재귀 종료성).
- 복귀 주소 읽기(`call next; pop ebx`): `*(SP_entry)` = caller의 transient push 상수(`ObservedCallStateProjection.transient_coordinate`).
- 메모리로 전달된 포인터(32비트 스택 인자 등): 앵커 `ENTRY(*(SP_entry+4))` 를 호출 지점에서 caller 도달 정의로 **한 번** 평가.
- 꼬리 호출 exit: 1단계는 UNKNOWN exit(부채). 이후 "지점 상태 ∘ 대상 요약" 합성.
- 비반환 callee: 호출 뒤 상태 bottom, kill 없음, `no_return`.
- CALLIND·외부 import: UNKNOWN. 외부 선언 모델은 **가정 라벨**(TEST-ONLY 모드와 같은 등급). varargs 특별 처리 없음.

## 2. 호출 지점 결합 (`bind_call_site`)

- caller 레지스터 바이트(호출 시점) = callee 입구 레지스터 바이트.
- callee 입구 SP = caller의 반환주소 push 후 SP(`observed_call_state` 토큰).
- callee 상대 객체(입구 원자 앵커) → 호출 지점에서 그 원자의 caller 값을 `relative_memory` 주소식 평가기로 한 번
  평가(caller 상대 객체 / 스택 슬롯 / 전역 / 미상→부채). 앵커 깊이 상한 k(예: 4) 초과 → 부채. **while 재대입 없음**.
- 같은 caller 객체가 두 인자로 넘어오면(경계 별칭) 해당 IDENTITY run을 may-write + 양쪽 의존으로 내림.

## 3. caller 그래프 통합 (CFL 질의 계층 대신 물질화)

- 호출 c의 쓰기 run마다 노드 `call_def:{c}:{run}`(NodeKind `CALL_EFFECT`).
  간선: 의존 입구 바이트의 caller 도달 정의 → call_def(`summary_transfer`), callee source 라벨 → call_def
  (`summary_origin`, 라벨 `source:X@callee`), UNKNOWN → 이유별 부채 노드.
- 메모리 SSA: 호출을 writer로. must-write = DATA_WRITE(strong kill), may-write = DATA_WRITE + 호출 전 정의에서
  call_def로 간선 하나 더(약한 갱신을 출처 관점에서 등가 표현).
- call_clobber: `_State.called(key, preserved)` 에 preserved ∪ 쓰기 집합 → UNKNOWN 바이트만 부채.
- 진입점: `normalize(assumed_call_effects=…)` 훅을 `EvidencedCallEffect`(provenance: declared | proven)로 일반화.
- 골든: intra 모드 v2 유지, 함수 간 모드 골든 v3 별도(모드 플래그).

## 4. 재귀

- SCC 단위. must-facts(GFP: 요약 가정 → 본문 재확인; 반환하는 실행의 호출 깊이 귀납으로 건전) 먼저,
  그 결과를 kill로 써서 may-facts(LFP).
- 활성화 프레임은 SP_entry 상대 + token으로 자연 분리.
- 종료성 widening 2개: callee 프레임 may-write → `below_frame`; 앵커 경로 깊이 k 초과 → 미상 포인터 객체 부채.
- 함수 포인터 재귀: CALLIND 미상 → UNKNOWN(건전).
- 판본: v1 SCC 내부 간선을 UNKNOWN 호출로(모두 종료, 출처 정확·불완전) → v2 LFP + widening → v3 GFP must.

## 5. 검증

- 인터프리터 확장: Bundle 안 callee로 실제 call/return(공유 메모리), 외부·미상만 havoc. 교차 호출 동적 의존이
  caller 그래프의 역경로인지 확인.
- S0용: 활성화 provenance(활성화 안에서 바이트별 전이 의존) → "동적 요약 ⊆ 정적 요약".
- 지표: 기존 + "SP 미상 호출 수", 부채 이유별 히스토그램. 함수 간 검증은 **내부 helper 호출**에서
  (source/sink는 외부라 기본 모드 확실은 선언 모델 없이는 불가 — 지표는 가정 모드 + 함수 간 모드로 읽음).

## 6. 단계 계획

| 단계 | 내용 | 완료 기준 |
|---|---|---|
| S0 요약 추출 | `FunctionSummary`, intra 그래프에서만, caller 불변, 덤프 도구 | 동적 요약 ⊆ 정적 요약, corpus/09/10/zlib 위반 0 |
| S1 잎 callee 직접 호출 | call_def 물질화, EvidencedCallEffect, call_clobber 보존 구간, may-write; 인터프리터 1단계 실제 호출 | DFB050/052/054/056~059/066/151/152/021~023 출처 정확, 누락 0, 가정 모드 확실 |
| S2 중첩·SP | bottom-up, DFB051/053/055, SP AFFINE(stdcall), 32비트 스택 인자, 내부 외부호출 부채 전파 | win32·ELF x86 Bundle 종료, 누락 0, SP 미상 호출 0(09) |
| S3 문맥 민감 부채 해소 | 사상 객체로 callee may_alias 해소, 메모리 내 포인터 앵커, 깊이 상한 | 09 비재귀 케이스 효과적 정확+확실 |
| S4 규모 | UE DLL·zlib·코퍼스, 예산(요약 시간 ≤ intra 정규화), CALLIND·import UNKNOWN 집계 | 전 Bundle 시간 상한 내 종료, 누락 0, 부채 히스토그램 |
| S5 재귀 | v1 → v2 → v3 | DFB060~065 종료·출처 정확, v2에서 확실 |
| S6 설명·골든 | proof 체인, 골든 v3 | 골든 compare 0 |

## 7. 재사용 / 재작성

- 재사용: `observed_call_state`(토큰·transient), `PhysicalMemoryTransition`, `_callee_preserves`(→ IDENTITY 판정),
  `DischargeKind` 4종(요약 분류로 흡수), `_function_relative_object_id`, relative_memory 주소식 평가기(공개화),
  `recursive_frame_inventory` 의 call token, Bundle/session/`_cyclic_nodes`.
- 재작성: `configured_write_event_engine`, `configured_origin_projection`, `configured_function_memory`(PointerPath),
  `configured_boundary_mapping`(→ `bind_call_site`), `configured_interprocedural_slice` 완성 경로.
- 보류: finite-context·recursive_* z3 모듈(엔진 미연결, 테스트 0), path_explanation은 S6에서 proof 체인 기반으로 축소.

## 8. S0 결과 (2026-10-07): 함수 요약 추출

- 구현: `src/tdo_v2/function_summary.py` (`summarize_function(normalized, observation)`), caller 불변.
  - 끝 상태 run마다 IDENTITY / COMPUTED / UNKNOWN (AFFINE은 S2). 건드리지 않은 바이트는 요약에 없음 = 보존.
  - 출처·entry 메모리 읽기 연산·부채: 그래프 조상 폐포를 한 번에 계산(`_AncestorClosure`, SCC 묶음 DP) —
    정의별 역추적과 결과 동일(무작위 500 함수), inflate 46초 → 0.3초.
  - 끝에서 지나간 호출·별칭 쓰기·주소 미상 쓰기: 끝 블록에서 거꾸로 걸으며 kill에서 멈추는 탐색
    (`_live_gens_at_exit`) — 고정점 solver와 결과 동일(무작위 600 함수).
  - 주소가 불확실한 쓰기(주소 피연산자가 부채 있는 읽기에 의존)는 어디든 쓸 수 있음 → `unknown_writers`,
    그 쓰기가 정의한 run은 UNKNOWN(이전 값이 남을 수 있음).
  - 꼬리 점프 출구(조건부 포함)는 `tail_exits`(S0에서는 호출자가 UNKNOWN으로 취급).
- 검증: 인터프리터에 바이트별 provenance(입구 레지스터 / 입구 메모리를 읽은 연산 / 호출) 추가,
  `tests/intra/summary_oracle.py` 가 "동적 ⊆ 정적" 검사(호출의 반환주소 push는 죽은 스택이라 제외).
  - 무작위 1,000 함수(실행 4,891회, 바이트 31만) 위반 0. 틀린 요약 4종(출처 삭제·거짓 IDENTITY·호출 숨김·
    쓰기 누락) 모두 검출. 테스트 `tests/intra/test_function_summary.py`.
  - 실제 Bundle 전체(코퍼스 7, 09 3, UE 6, zlib; 도구 `tools/graph_fidelity/measure_summary.py`) 위반 0.
    요약 시간: inflate 1.2초, zlib 전체 2.9초.
- S0에서 고친 검사 함정: JOIN을 거쳐 entry 메모리를 읽는 연산도 entry 읽기로 집계.
- 남은 것(S1~): push/pop 복원의 IDENTITY 판정, SP AFFINE, callee 프레임 쓰기(`below_frame`), 꼬리 호출 합성.

## 9. S1a 결과 (2026-10-07): 레지스터 효과 연결

- `src/tdo_v2/call_summary_effects.py`: 피호출자 요약 → 호출 지점의 `ProvenCallEffect`(레지스터만).
  쓰기 run 묶음별 (쓰는 바이트, 의존 바이트); 어떤 exit에서 그대로면 자기 자신도 의존(약한 갱신);
  UNKNOWN·부채·피호출자 입구 메모리 의존 → 증명 안 함(부채 유지). 꼬리 출구·정상 출구 없음 → 전체 미증명.
  피호출자가 직접 건드리지 않은 레지스터도 **내부 호출이 보존을 보장하지 않으면** 미증명
  (`FunctionSummary.inner_calls`).
- `normalize(proven_call_effects=…)`: 호출 직전에 2단계 효과 — 각 run의 입력을 호출 지역 임시값으로 모은 뒤
  (`~in<i>`) 출력 쓰기(`~<i>`). 한 단계로 하면 뒤 run이 앞 run의 쓰기를 읽는 오류(실제로 발견). call_clobber는
  증명된 보존 범위(쓰기 포함)를 그 호출의 보존으로 사용.
- `src/tdo_v2/interprocedural.py` `analyze_units`: 호출 그래프 SCC를 피호출자 먼저 처리, 같은 SCC 안의 호출
  (재귀)은 불투명 유지(S5).
- 검증기: 인터프리터 program 모드(Bundle 안 함수 실제 호출/반환, call 명령 시작부터 활성화로 취급, 활성화 안
  쓰기는 바깥 호출에 귀속하고 호출자 입력 출처를 기록, 반환 후 SP가 호출 전 값이면 정의 복원),
  `tests/intra/program_oracle.py`(호출을 거친 값의 호출자 입력까지 역추적 도달 확인).
  - 무작위 3단(호출자→중간→말단) 프로그램 160개: 호출 372개 모두 증명, 호출 경유 의존 3,837건, 누락 0.
  - 실제 Bundle(누락 0 전부): 09 debug 내부 호출 202/203 증명·경유 8,192건, release 111/113, win32 152/156
    (0.9초), UE DLL 108/116(3.7초)·206/218(8.8초), zlib 45/83. 이전 계층에서 끝나지 않던 win32·UE가 수 초에 끝남.
  - 골든 v2(함수 내부) 0 차이, 테스트 Win 179 / WSL 180.
- 가정(명시): 호출 모양은 피호출자가 SP를 복원한다고 가정(기존 엔진과 동일). 무작위 피호출자는 스택 균형으로
  생성 — SP 요약 검사는 S2.
- 남은 것: S1b 포인터·출력 인자 메모리 결합, S1c 엔진 연결과 09 케이스 지표(origin 라벨 전달).

## 10. S1b 결과 (2026-10-07): 포인터·출력 인자 메모리 결합

- 앵커: 피호출자의 FUNCTION_RELATIVE 객체 중 "입구 레지스터 값 하나 + 변위"인 것을 후보 레지스터(포인터 크기,
  메모리 공간별)의 객체 ID와 맞춰 찾음(`interprocedural._relative_anchors`). SP 앵커는 피호출자 프레임.
  전역(ADDRESS_SPACE)은 그대로. 앵커 없는 객체(메모리에서 읽은 포인터 등)에 쓰면 메모리 전체 부채.
- `call_summary_effects`: `ProvenMemoryRun`(앵커 쓰기 + 입력 레지스터·앵커 읽기), `loads`(피호출자 입구 메모리
  읽기), `preserves_memory`. 피호출자 자신이 내보내는 메모리 쓰기와의 별칭 때문에만 UNKNOWN인 run은 호출자의
  may-alias가 다루므로 계산값으로 취급. 내부 불투명 호출·주소 미상 쓰기·부채가 있으면 메모리 보존 아님.
- 정규화: `~ld<j>`(앵커 메모리 읽기) → `~in<i>`(입력 모음) → `~<i>`(출력). 앵커 주소는 relative_memory
  `project_anchored` 가 입력 모음 시점의 레지스터 값으로 **한 번** 평가(SP는 호출 모양의 push 크기만큼 보정).
  한 호출의 메모리 쓰기 둘이 호출자에서 같은 바이트에 겹치면(같은 객체를 두 인자로 넘김) 둘 다 미해결(부채).
- call_clobber: 메모리를 보존하는 증명된 호출은 메모리 바이트를 clobber하지 않음(dense: 메모리용 기본값 분리,
  sparse: 서명에 반영) — 두 엔진 동치 테스트 통과.
- 결과: 무작위 3단 프로그램 160개 메모리 run 160개, 메모리 보존 증명 241/372, 호출 경유 의존 4,607건, 누락 0.
  출력 인자(`*(rdi+8)=rsi`)·swap(x는 y의 옛 값만, 확실)·전역·스택 쓰는 피호출자·메모리에서 읽은 포인터(부채)·
  같은 객체 두 번(부채) 테스트. 실제 Bundle 누락 0, 호출 경유 의존: 09 debug 8,192→10,032, release 144→1,472,
  win32 352→1,704, UE Dev 112→688, DebugGame 84→796. 함수 내부 골든 v2 0 차이. 테스트 Win 184 / WSL 185.
- 한계(기록): 검증기의 메모리 경유 판정은 "그 호출의 메모리 run 중 하나에 도달"(동적 주소를 정적 객체로 사상하지
  않음) + 호출자 입력 도달 검사. 32비트 스택 인자(메모리 앵커)는 S2.

## 11. S1c 결과 (2026-10-07): 요약 엔진 경로와 케이스 지표

- `src/tdo_v2/summary_engine.py` `analyze_frozen_bundle_with_summaries`: 엔진의 루트별 함수 간 보완 대신
  하향식 요약 계층(`analyze_units`)으로 Bundle 전체를 정규화. `run_dfbench.py --summaries`
  (또는 `TDO_V2_INTERPROCEDURAL=summaries`).
  - origin: TEST-ONLY 선언 source 호출의 쓰기, Bundle 안 source 함수 호출의 run 출력(선택자 범위),
    피호출자 안에서 source에 닿은 run의 출력(요약이 `origins`로 전달).
  - sink: 엔진과 같은 방식(호출 지점·꼬리 호출). sink 래퍼·콜백 안의 sink는 그 함수의 루트(호출자로 요구 투영은 S2/S3).
- 요약 보강: 복사 사슬 IDENTITY(`_CopyTracer`, push/pop 보존 레지스터), `ProvenCallEffect.observes_registers`
  (받은 레지스터를 주소로 쓰지 않는 피호출자 → 그 호출에서 스택 포인터 복사가 탈출하지 않음).
- **스택 탈출을 위치별로**(`may_alias._Escape`): 함수 안 어디서든 탈출하면 함수 전체가 비공개가 아니던 규칙을
  "읽기: 입구→그 지점 경로에 탈출이 없으면 비공개, 쓰기: 그 지점→이후 경로에 탈출이 없으면 비공개"로.
  탈출 연산 자체와 그 호출의 요약 효과(`call~…`)는 탈출 쪽으로 취급. 옛 규칙 대비 행·작성자 **제거만**
  (전체 Bundle 비교, 추가 0). 함수 내부만으로는 거의 차이 없음(호출이 불투명하면 첫 호출에서 탈출) —
  효과는 요약 호출이 있을 때.
- **이름 붙은 가정 `globals-disjoint-from-stack`**(요약 엔진에서 **기본 켜짐** — 2026-10-07 사용자 결정;
  하위 API `normalize`/`analyze_units`는 기본 꺼짐): 상수 주소(전역)는 스택 객체(입구 SP 기준, 자기 프레임 +
  호출자 프레임)와 겹치지 않음. 포인터 기반 객체와 스택은 여전히 겹칠 수 있음.
  `stack_switches`: SP에 스택에서 유도되지 않은 값을 넣는 연산(`mov rsp,[x]` 등 — 파이버·코루틴 전환)이
  프로그램의 어느 함수에라도 있으면 가정을 프로그램 전체에서 철회(Bundle 안 함수만 보므로 Bundle 밖 전환
  코드는 못 봄). 적용 여부는 `NormalizedFunction.assumes_globals_disjoint_from_stack`, `EngineRun.assumptions`에
  기록, `run_dfbench` 출력에 "assumptions applied" 표시. 끄기: `run_dfbench --no-assume-globals-not-stack`
  또는 `TDO_V2_ASSUME_GLOBALS_NOT_STACK=0`(펌웨어·정적 버퍼 스택 등). 지표의 "확실"은 이 가정 아래에서 확실.
  검증(골든·동적 검증기)은 가정 없이도 계속 돌림.
- 케이스 지표(요약 엔진, 정확 / 정확+확실, 누락+확실은 모든 실행에서 0):

  | Bundle | 모드 | S1c 1부 | + 위치별 탈출 | + 전역·스택 가정 |
  |---|---|---|---|---|
  | 09 debug (61) | 기본 | 40 / 4 | 42 / 4 | **50 / 42** |
  | 09 debug | TEST-ONLY 가정 | 50 / 43 | 50 / 43 | 50 / 43 |
  | 09 release (51) | 기본 | — | 48 / 40 | 48 / 41 |
  | UE DLL Dev (22) | 기본 | — | 13 / 12 | 13 / 12 |
  | UE DLL DebugGame (22) | 기본 | — | 5 / 2 | 6 / 2 |

  09 debug 기본 모드가 가정을 켜면 TEST-ONLY 경계 가정과 거의 같아짐: 경계 함수가 Bundle 안에 있어 요약으로
  증명되고, 남던 원인이 "sink 안 전역 쓰기 ↔ 호출자 home space 재읽기" 별칭이었기 때문.
  (옛 엔진: 기본 39 / 28, 가정 53 / 41.)
- 남은 것(기록): cpp_like x64 기본 모드에서 요약 엔진이 source 라벨을 못 찾음(0/11, 옛 엔진 10/11) — source
  함수 호출이 증명되지 않으면 origin이 안 붙음(불투명 source 호출에 라벨 부착 필요). 32비트(win32, cpp x86)는
  지표 미지원(S2). sink 래퍼·콜백(DFB055/071/073)은 호출자로 요구 투영 필요. 요약의 `crossed`
  (function_summary 안 may_alias)에는 아직 가정을 적용하지 않음(더 보수적).
- 테스트: 위치별 탈출(탈출 전 읽기 비공개, 탈출 전 쓰기는 다른 기반에서 보임, 루프 뒤 탈출이 루프 머리에 영향),
  가정 켬/끔, 포인터는 여전히 별칭, 스택 전환 시 철회, 무작위 탈출 함수 400개 동적 검증기. 두 규칙을 일부러
  틀리게 바꾸면 손 테스트가 잡음(무작위 검증기는 못 잡음: 함수 안에서 실제 별칭은 주소 미상 접근으로만
  생기고 그건 항상 부채라서 — 위치별 규칙은 출처 추론의 안전장치).
