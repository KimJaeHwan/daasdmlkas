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
- 남은 것(당시 기록 → 12절에서 처리): cpp_like source 라벨, 32비트 지표, sink 래퍼·콜백, 요약 `crossed`의 가정.
- 테스트: 위치별 탈출(탈출 전 읽기 비공개, 탈출 전 쓰기는 다른 기반에서 보임, 루프 뒤 탈출이 루프 머리에 영향),
  가정 켬/끔, 포인터는 여전히 별칭, 스택 전환 시 철회, 무작위 탈출 함수 400개 동적 검증기. 두 규칙을 일부러
  틀리게 바꾸면 손 테스트가 잡음(무작위 검증기는 못 잡음: 함수 안에서 실제 별칭은 주소 미상 접근으로만
  생기고 그건 항상 부채라서 — 위치별 규칙은 출처 추론의 안전장치).


## 12. S1c 3부 · S2 (2026-10-07): 나머지 정리 — Fable 검토 순서(A → C1 → B, C2/C3)

1. **불투명 source 호출 라벨**(`summary_engine.extra_origins`): source 호출이 증명되지 않았거나 상태 바이트를
   쓰는 run이 없으면, 그 호출을 이름에 담은 call-clobber 부채 노드(상태 레지스터 바이트를 읽는 것)에 라벨.
   부채라 루트는 "불확실"로 남음. cpp_like x64 기본 0/11 → P0 5/11, P1 7/11(source 함수가 Bundle 밖).
2. **요약 `crossed`에도 전역·스택 가정**(`function_summary._exit_crossings`, `may_alias.stack_object_of`):
   09 debug 기본 50/42 → 50/43(TEST-ONLY와 같음).
3. **sink 요구 투영(A)**: `FunctionSummary.sink_demands`(루트별 입구 바이트·부채·출처·완전성; 함수 안
   주소 미상 쓰기가 있으면 불완전) → `ProvenSinkDemand`(레지스터 + 앵커 메모리 `loads`; 앵커 없는 입구
   메모리는 불완전) → 정규화 `~sink<k>` 행(입력 모음, 출력 쓰기 전) → 호출자의 루트(`AnalyzedFunction.
   projected_sinks`, 피호출자 부분이 불완전하면 루트도 불완전). 같은 하향식 한 번에 중첩 래퍼까지 합성.
   정상 출구가 없는 래퍼도 sink 요구는 전달(`ProvenCallEffect` 상태 없이). 자기 sink의 상태가 그래프에 없으면
   호출 연산에 묶어 "묶이지 않은 루트"로 보고(조용히 사라지던 경로 제거). 앵커 후보에 요약 호출의 앵커
   레지스터 포함(포인터를 그대로 넘기는 함수). DFB055: 없음 → 정확(불확실: 디버그 home space 재읽기와
   포인터 쓰기의 별칭 — S3 문맥 해소 대상).
   검증: 인터프리터가 활성화 안 sink 호출 인자의 호출자 입력을 기록(`Run.sink_reads`), `program_oracle.
   check_sink_demands` — 투영 루트가 있어야 하고 그 입력에 도달해야 함. 무작위 래퍼 160개 누락 0, 메모리
   입력을 버리는 변형을 잡음.
4. **32비트 지표**(`run_dfbench`): PE32/ELF32 → `x86-32`(언어 x86:LE:32, source = EAX, sink = 호출 시점
   `[ESP+0]` 메모리 선택자; TEST-ONLY 가정은 메모리 상태를 모델링하지 않아 32비트 sink는 일반 호출).
   **앵커 변위 버그 수정**: 상대 객체 바이어스를 2^64로 고정 → 포인터 폭(2^32/2^64). 32비트 앵커 메모리가
   전부 부채로 남던 원인. win32 33/1 → 35/25.
5. **SP AFFINE(C1, 건전성)**: `FunctionSummary.register_deltas`(포인터 크기 레지스터의 끝 값 = 입구 + c,
   모든 exit 같은 c; 주소식 평가기 `relative_memory.register_value_deltas`), `ProvenCallEffect.restores_stack`
   (c == −push 변위일 때만). 아니면 그 호출의 SP 면제를 call_clobber·요약 crossing에서 제거 → 호출 뒤 SP
   읽기가 부채(조용한 오프셋 오류 방지). 요약 안 된 호출은 기존 호출 모양 규칙 그대로이며
   `EngineRun.assumptions`에 `opaque-callees-restore-stack-pointer`로 표시. 우리 Bundle에는 stdcall
   (`ret imm`)이 없어 지표 변화 없음. 무작위 비균형 피호출자 160개 누락 0, 복원을 항상 참으로 두는 변형을 잡음.
6. **꼬리 점프 합성(C3)**: 프로그램 함수로의 무조건 꼬리 `BRANCH`를 호출처럼 요약 효과로(`_direct_calls`),
   SP는 런에서 빼고 exit 델타에 대상의 c를 더함(`tail_stack`, `tail_stack_delta`), 합성된 꼬리는
   `tail_exits`가 아님. 레지스터를 하나도 쓰지 않는 썽크는 프로그램 레지스터 파일·레지스터 공간으로 대체.
   검증: 꼬리 테스트 + 무작위 160개(대상 비균형 포함) 누락 0, 대상 c를 무시하는 변형은 손 테스트가 잡음
   (무작위 검증기는 기록자 노드 도달만 보므로 SP 값 오차에 약함 — 기록).
7. **상수 대상 간접 호출(B, DFB073형)**: `COPY t ← r; CALLIND t`에서 r의 값이 주소식 평가로 상수이고 그
   값이 Bundle 함수 입구이며 그 COPY의 역방향 슬라이스에 부채가 없으면 직접 호출로. 분석 → 해소 →
   재분석을 해소 집합이 안정될 때까지(매 라운드 재확인; 안정 안 되면 해소 없이). 불투명 호출 뒤 재적재는
   해소 안 함(부채). DFB071(다른 함수가 전역에 등록한 콜백)은 보류.

케이스 지표(요약 엔진 기본 모드, 정확 / 정확+확실, 누락+확실 모든 실행 0):

| Bundle | 11절 끝 | 12절 끝 |
|---|---|---|
| 09 debug | 50 / 42 (61건) | **52 / 45** (63건; DFB055·DFB073 새로 잡힘) |
| 09 release | 48 / 41 (51건) | 49 / 42 (52건) |
| win32 release | 지표 없음 | **35 / 27** (46건) |
| cpp P0 / P1 x64 | 0 / 0, 0 / 0 | 5 / 0, 7 / 0 |
| cpp P0 / P1 x86 | 지표 없음 | 7 / 0, 6 / 0 |
| UE DLL Dev / DebugGame | 13 / 12, 6 / 2 | 13 / 12, 6 / 2 |

함수 내부 골든: v2 대비 차이는 (a) 위치별 탈출로 may-alias 행·작성자 제거(제거만, 전 Bundle 확인),
(b) 32비트 TEST-ONLY 규칙이 이제 적용됨(win32·cpp x86 가정 모드) — 둘 다 의도된 변화. 골든 **v3** 로 갱신.

남은 것: S3(문맥 민감 부채 해소: DFB055 home space 별칭 등), DFB071(전역 콜백), stdcall SP 보정 행(현재는
부채), 조건부 꼬리 점프, S5 재귀, UE DebugGame의 extra-only(14건) 원인 분석.

## 13. S3 (2026-10-07 밤): 호출 지점에서 별칭 조건 판정 (Fable 검토 반영)

- 문제: 디버그 빌드는 인자를 home space(호출자 프레임, 입구 SP 위)에 저장했다 다시 읽는다. 피호출자 안에서는
  포인터 쓰기(`v->x`)가 그 슬롯과 겹칠 수 있어 재읽기에 may-alias 부채 → 요약 run·sink 요구가 불확실/UNKNOWN.
  호출자는 두 주소를 다 안다(`&s`와 자기 SP 기준 슬롯).
- **조건부 부채**(`function_summary._alias_conditions`): 읽기 주소가 정확하고 모든 후보 작성자가 정확한 범위를
  쓰는 may-alias 부채는 라벨 대신 (읽기 범위, 쓰기 범위) 쌍 = "서로 안 겹치면 부채 없음". `_AncestorClosure`가
  5번째 성분으로 모음. 주소가 그 부채에 기대는 저장(`_uncertain_address_writers`)도 같은 조건으로.
- 전달: `SinkDemand.conditions`, `SummaryRun.conditions` → `ProvenSinkDemand/ProvenRunEffect/ProvenMemoryRun.
  conditions`(앵커 쌍; 한쪽이라도 앵커 없으면 불완전/unknown) → 정규화 `~ck<k>`(sink 요구)·`~cr<i>`(run) 행이
  앵커 레지스터를 읽음 → `interprocedural._decide_conditions`가 호출 시점 값으로 양쪽 위치를 한 번 계산:
  같은 객체면 겹침 여부, 다른 객체면 두 주소 공간 / 전역·스택(이름 붙은 가정)만 안 겹침, 그 밖(두 포인터)은
  sink 요구에선 호출자 객체의 조건으로 위로 전달, run에선 실패 처리.
- run 조건 실패 → 그 바이트 unknown(`failed_conditions`)으로 효과를 다시 만들고 함수를 다시 정규화(실패 집합은
  커지기만 함, 유한). 겹치는 배치에서는 한 호출의 두 메모리 쓰기가 같은 호출자 바이트에 떨어져 기존 "둘 다
  미해결" 장치도 함께 막음.
- 검증: 합성 DFB055/DFB057(조건 해소), 겹치는 배치(불완전 유지), 배치 전수(변위 7 × 필드 4 등) 동적 검증기
  누락 0, "항상 해소" 변형은 sink 쪽 손·무작위 테스트가 잡음. 실제 Bundle 동적 검증: 09 debug 전체(125함수,
  의존 18.9만, 호출 경유 2,128), release, win32, UE Dev, UE DebugGame(52만), cpp 모두 누락 0.
- 검증기 수정: 인터프리터가 호출 활성화 안의 읽기도 기록하던 것을 최상위만 기록(재귀에서 호출자와 같은 연산
  키라 오탐 21,780건이 났음).
- 새 Bundle `v2-win-debug-full`(09 debug 75케이스 전부, 재귀 포함): 요약 엔진 9.5초, 옛 계층은 재귀에서 실패.
- 지표(기본 모드, 정확/확실): 09 debug 전체 74건 56/45 → **57/47**(DFB055·DFB057), 부분 Bundle 52/45 → 53/47.
- 남은 원인(09 debug 전체 불확실 27건): 외부 import(malloc·strcpy·memcpy·setjmp·DLL) 11 — 외부 모델 필요(가정
  등급); 재귀 6 — S5; MinGW `.refptr`(읽기 전용 `.rdata`의 전역 주소 슬롯을 읽어 전역에 접근 →
  "메모리에서 읽은 포인터"라 스택과 별칭) — 읽기 전용 이미지 데이터의 상수 접기 필요(섹션 권한 증거가 Bundle
  블록에 없음, 원본 PE 헤더로 가능); 비트 단위 3(보류).

## 14. 메모리 속 포인터 앵커 · S5 재귀 · 프레임 아래 접기 (2026-10-07 밤)

1. **메모리 속 포인터 앵커**(설계 1절의 `ENTRY(*(SP_entry+4))` 앵커): 피호출자가 입구 메모리에서 읽은 포인터
   크기 값으로 주소를 만든 객체를 `AnchoredSpan.pointer`(그 포인터가 놓인 위치 — 레지스터 앵커·전역·또 다른
   포인터, 깊이 2)로 표현. 호출자는 그 슬롯을 `~ld` 행으로 읽고, 반복 투영(normalize의 고정점 루프)에서 그
   행의 메모리 읽기 정의로 포인터 값을 평가(`relative_memory.project_anchored`의 `("mem", key)`). 32비트
   스택 인자 포인터, `**pp`, `this->member` 류. win32 35/27 → **43/34**, release 49/42 → 50/43.
   검증: `**pp` 손 테스트, 메모리로 넘긴 포인터 무작위 60개(변위를 8 틀리게 한 변형을 잡음).
2. **S5 재귀**(Fable 설계): SCC 안 호출은 낙관적 가설("아무것도 안 쓰고 SP 복원")에서 시작, 가설로 구성원을
   다시 분석해 유도한 효과가 가설과 같아질 때까지 반복(`interprocedural.solve`, 최대 8라운드). **검증된
   고정점만** 채택(돌아오는 활성화의 깊이에 대한 귀납으로 건전), 아니면 SCC 안 호출 불투명(기존, 부채)으로
   두고 `AnalyzedFunction.recursion_unresolved`. 가설에선 조건부 값은 실패로, sink 요구는 라벨별 병합(매 라운드
   자기 투영으로 늘지 않게). 09 debug 전체 SCC 모두 수렴. 검증: 무작위 자기/상호 재귀 160개(깊이 카운터)
   누락 0, "1라운드 결과를 검증 없이 채택" 변형을 잡음.
3. **프레임 아래 접기**(`ProvenCallEffect.clobbers_below`): 피호출자 입구 SP 아래(자기 프레임·그 아래 호출들의
   프레임)에 대한 쓰기는 바이트별로 내보내지 않고 "호출 시점 SP 아래 스택은 바뀔 수 있음"으로. 호출자는 `~sp`
   행으로 호출 시점 SP를 자기 스택 객체 오프셋으로 계산(`normalize._call_below_bounds`)하고, 메모리를 보존하는
   호출이면 그 경계 아래를 뺀 모든 추적 메모리 범위를 보존 범위로 call_clobber에 넘김(엔진 변경 없음). 요약
   crossing도 같은 경계. 재귀에서 프레임 쓰기가 라운드마다 더 깊이 투영되던 문제(수렴 불가)를 없앰.
   검증: 호출 뒤 SP 아래 읽기는 불확실, 위는 정확(경계를 16 틀리게 한 변형을 잡음).
   **도중 발견·수정한 건전성 버그 2건**: (a) 메모리를 보존하지 않는 호출에도 경계 보존 범위를 줌 → 09 debug
   "누락+확실" 2건(DFB023/066)으로 바로 드러남, 보존 호출만으로 제한. (b) SP 델타(C1)가 부채를 지나는 정의를
   증명으로 받아들임(복원 안 하는 호출 뒤 SP) → 비균형 무작위 테스트가 잡음, 부채·조건 있는 run은 델타 증명 안 함.
4. 지표(기본 모드, 정확/확실, 누락+확실 0): 09 debug 전체 57/47 → **58/51**(DFB062 상호 재귀 등).

## 15. 외부 함수 모델 · exporter 묶음 · 읽기 전용 데이터 (2026-10-08, Fable 설계)

1. **exporter 묶음 수정**(`GhidraV2BundleExport.imageInfo`): 봉인된 새 멤버 `image-info.json`
   (스키마 tdo-v2-image-info-1) — 블록별 권한·이름(read/write/execute/volatile), import 심볼과 Ghidra가 그
   주소를 묶은 메모리 칸(IAT, MinGW `.refptr`)·thunk, export 진입점, 재배치 주소. manifest에 선택 키
   `image_info_member`(블록 멤버 다음 정규 순서), admission이 다른 멤버처럼 digest 검증. 기존 v2 Bundle은
   그대로 읽힘(키 없음 → None). 블록 행·scope 다이제스트는 바꾸지 않음. 엔진 쪽 `tdo_v2.image_info`가 봉인을
   다시 확인하고 읽음. 전 Bundle 재export: `/root/tdo_bundles3`.
2. **외부 함수 모델**(`tdo_v2.summary_store`, `models/external/*.json`): 함수 요약 형식의 선언 모델을
   언어+ABI별 파일로 관리(물리 레지스터 조각으로 기술 → 엔진은 호출 규약 모름). 항목: 레지스터 쓰기와 그 입력,
   메모리 쓰기(입구 레지스터 기준 + 변위, 크기 = 바이트 또는 레지스터)와 입력·읽기, 나머지 메모리 보존 여부.
   **명시한 보존 레지스터 외에는 모두 unknown**(빠뜨리면 보수적). 자기 프레임 아래는 항상 바뀜, 받은 포인터는
   관찰 가능(탈출). 크기가 레지스터면 호출자가 그 값을 상수로 증명할 때만(`~ext` 행 → 재정규화) 정확한 쓰기,
   아니면 메모리 보존 안 함. 연결: `CALL` thunk 주소 또는 `COPY t ← [import 칸]; CALLIND t`
   (`interprocedural._external_sites`, image-info의 import 표). 쓰인 모델마다 `external-model:<파일>/<항목>
   @v<버전>`이 `EngineRun.assumptions`에. 기본 켜짐, `run_dfbench --no-external-models`로 끔.
   - 1차 모델: crt-win64 / crt-sysv64 — memcpy·memmove·memset(크기 증명 시 정확), strcpy 계열(메모리 보존
     안 함), strlen·strcmp 계열(결과 unknown, 메모리 보존), malloc·calloc(새 주소, 입력 없음), free(사용 후
     해제 없음 가정), realloc(메모리 보존 안 함). x86-32(스택 인자)는 메모리 속 포인터 베이스가 필요해 보류.
   - 검증: 인터프리터가 외부 함수를 실제 C 의미로 실행(`Interpreter(externals=…)`), 프로그램 검증기로 모델과
     대조 — 손 테스트 + 무작위 150개 누락 0, memcpy 모델에서 원본 읽기를 뺀 변형을 잡음.
   - 보류(Fable): 새 객체(malloc 결과가 아무것과도 안 겹침, 루프 안전성 필요), 결과 레지스터 기준 쓰기(realloc),
     setjmp/longjmp, DLL 요약 내보내기/가져오기(export 표는 이제 Bundle에 있음), TEST-ONLY 경계 가정의 모델
     통합(옛 엔진 경로와 assumed 골든이 아직 그 경로를 씀 — 요약 엔진을 기본으로 바꿀 때 함께).
3. **읽기 전용 데이터 상수**(이름 붙은 가정 `readonly-image-data-is-constant`, `image_info.ReadOnlyImage`,
   **기본 켜짐** — 2026-10-08 사용자 결정, 끄기: `--no-assume-readonly-image` / `TDO_V2_ASSUME_READONLY_IMAGE=0`;
   권한은 바이너리 섹션 헤더(Ghidra 블록), 가정은 "실행 중 권한을 바꿔 덮어쓰지 않음"뿐): 로드·초기화·쓰기 불가·volatile 아님 블록의 입구 내용은 이미지 값
   (봉인된 블록 바이트). 주소식 평가에서만 사용(출처 추적은 그대로). MinGW `.refptr` 경유 전역 접근이 전역
   쓰기로 해소. 테스트: 가정 켬/끔, 이미지가 실제로 그 포인터를 가질 때
   동적 검증 누락 0.
4. 지표(09 debug 전체, 새 Bundle, 기본 모드 정확/확실, 누락+확실 0): 58/51 → 모델 **58/52**(DFB123) →
   + 읽기 전용 가정 **60/54**.

## 16. 요약 엔진을 기본으로 (2026-10-08, 사용자 결정)

- `run_dfbench.py`는 이제 기본으로 요약 엔진(`tdo_v2.summary_engine`)을 쓴다. 옛 엔진(`engine.
  analyze_frozen_bundle`, 루트별 함수 간 보완)은 `--legacy-engine` 또는 `TDO_V2_INTERPROCEDURAL=legacy`.
  `--summaries`는 호환용으로 남김(무동작). 출력에 적용된 가정 목록이 항상 찍힌다.
- 같은 부분 Bundle(09 debug)에서: 요약 엔진 정확 53 / 확실 48, 옛 엔진 39 / 28 (재귀 케이스는 옛 엔진에서 실패).
- 남은 정리(다음): TEST-ONLY 경계 가정(`assumed_call_effects`)을 모델 파일 방식으로 통합. 옛 엔진과 함수 내부
  골든의 "-assumed" 세트가 아직 그 경로를 쓰므로, 옛 엔진을 실제로 걷어낼 때 함께.
- **TEST-ONLY 통합(완료)**: 요약 엔진에서 TEST-ONLY 선언 경계는 더 이상 `assumed_call_effects`(정규화의 원시
  호출 쓰기 + call_clobber·may_alias 예외) 경로를 타지 않는다. 같은 선언(`AssumedCallEffect`)을 "선언한
  레지스터만 선언한 입력으로 쓰고 나머지는 모두 보존, SP 복원" 요약으로 바꿔 요약·모델과 같은
  `ProvenCallEffect` 경로로 연결(`analyze_units(declared_boundaries=…)`). 결과의 가정 목록에
  `test-only-boundary:<label>`. 요약 엔진의 TEST-ONLY 결과는 이전과 루트 단위로 동일(8개 Bundle, 차이 0).
  옛 경로는 legacy 엔진과 함수 내부 골든 "-assumed" 세트(정규화 단위)용으로만 남음.

## 17. UE DebugGame 분석과 rep 문자열 명령 (2026-10-08, Fable 설계)

- **보고 방식 변경**: 지표를 "N개 케이스 중 정확 a(%) / 정확+확실 b(%) / 과다 / 누락(확실) / Bundle에 없음"으로
  출력(`dfbench_metric.sh` SUMMARY 줄). UE 테스트베드는 UE 플러그인 DLL의 손으로 쓴 22개 케이스(엔진 전체 아님).
- **DebugGame 주원인**: MSVC 비최적화 빌드는 구조체 복사·채우기를 `rep movsb`/`rep stosb`로 만든다(DebugGame
  33개/20함수, Development 0개). Ghidra는 명령 하나 안의 루프로 들어 올려 주소가 반복마다 바뀌므로 주소 미상
  읽기/쓰기 → 모든 메모리 별칭 부채 → 과다 출처. 22개 중 13개 케이스 함수에 rep.
- **해결**(`tdo_v2/rep_strings.py`, `normalize`): Ghidra 12 lifting(ia.sinc) 그대로의 `rep movs*`/`rep stos*`만
  피연산자 동일성까지 확인해 인식(다르면 기존 루프 처리). 인식한 명령은 직선 블록 하나
  (`build_pcode_block_graph(straight=…)`). 평가기에는 연산 대체(`operation_overrides`): 횟수 레지스터는 끝에 0,
  포인터 레지스터와 0번째 접근은 횟수·방향 증명 전엔 미상. 횟수(명령 시작의 RCX)·방향(DF)이 증명되면
  요소 행 `~e<i>`(movs: 읽기·값 복사·쓰기, stos: 쓰기)을 반복 순서대로 끼워 넣고 다시 정규화(겹치는 원본/대상도
  정확), 포인터는 끝에 방향·n·크기만큼 이동. 요소 행은 횟수 분기에 제어 의존. 4096바이트 상한.
  방향: 함수 안 CLD/STD면 증명, 함수 입구 값이면 이름 붙은 가정 `direction-flag-clear`(두 x86-64 ABI가 보장,
  쓰일 때만 표시, 기본 켜짐, `--no-assume-direction-flag-clear`).
- **검증**: 인터프리터가 실제 루프를 돌리며 i≥1회 요소 연산을 `~e<i>`로 기록, 블록이 요약하는 반복 간 내부
  레지스터 흐름은 제외. 횟수 0/1/2/5/16 × movs/stos × 겹침 4배치 × 방향 2 = 80 조합 + 미증명 횟수 + 가정
  사용 — 데이터·제어 의존 누락 0. 변위 부호/요소 하나 빠뜨린 변형을 잡음(42·51건 실패).
- **결과**: DebugGame 22개 중 정확 6(27%) → **10(45%)**, 확실 2 → 3, 과다 14 → 10.
- **남은 원인**(DebugGame 불확실 18): 증명된 호출인데 메모리 보존 실패 15 — UE 컨테이너 도우미(TArray/
  FString류)가 메모리에서 읽은 포인터·heap으로 쓰는 "주소 미상 쓰기"를 가짐 → 다음 단계 "새 객체(heap)·포인터
  체인" 과제와 직결.

## 18. 새 객체·포인터 체인 1단계 (2026-10-08, Fable 검토 반영)

진단(케이스별 부채 원인): 09 debug 힙 케이스(DFB030~033)는 malloc 결과 포인터에 주소식이 없어 주소 미상 접근,
UE DebugGame은 "메모리 보존 실패" 도우미(생성자·컨테이너)가 대부분. Fable 권고 순서: 정의 atom(좁게) → Q4 →
fresh → 함수 간.

1. **정의 atom**(`relative_memory._definition_atom`): 주소식이 없는 값이라도 **활성화당 한 번만 실행되는** 정의
   (호출의 효과 행 `~<i>`, 실제 LOAD; 레지스터/임시, 정의 폭 그대로)는 그 정의로 키를 삼은 atom이 된다(입력으로
   키 삼지 않음 — 같은 인자의 malloc 두 번은 다른 값). "한 번" = `single_execution_keys`: SSA와 같은 p-code 블록
   그래프에서 순환에 없는 블록, rep 직선 블록 제외, 그래프 미지원·대상 미상 BRANCHIND가 있으면 함수 전체 끔.
   기존 고정점에 도달한 **뒤에만** 켬(먼저 켜면 입구 atom으로 풀릴 접근이 다른 객체로 굳음 — 정밀도 문제).
   서로 다른 atom은 기존처럼 may-alias. 
2. **wild 객체**(`may_alias`): 호출 결과·읽은 포인터는 비공개 프레임을 가리킬 수 있다(피호출자가 자기 SP로
   호출자 프레임 주소를 돌려줌). 그런 객체로의 쓰기는 비공개 프레임 읽기에도 보이고(필터 `unknown_writers`에
   포함), 비공개 프레임 쓰기는 wild 객체에 닿는다(dense·sparse 둘 다). 변형 "wild 처리 없음"을 테스트가 잡음.
3. **fresh**(모델 `"fresh": true`, malloc/calloc): 새 블록 주소 — 스택 포함 기존 메모리가 아님 → wild 아님.
   **observes**(모델, malloc/free: `[]`): 함수가 주소로 쓰거나 보관할 수 있는 레지스터. 디버그 빌드는 RBP에
   프레임 주소를 들고 있어, 기본값(모든 레지스터)이면 첫 malloc에서 프레임 전체가 탈출 처리됐다. 둘 다 그
   모델의 가정 라벨 아래(crt-win64/sysv64 v2).
4. **조건부 주소 불확실 작성자**(`function_summary`, `call_summary_effects`): home space에 this를 저장했다
   다시 읽어 쓰는 쓰기(UE 생성자)는 S3 조건(읽은 슬롯 ∩ 쓴 범위 = ∅)으로 줄어들어도 `unknown_writers`에 남아
   호출을 "메모리 보존 안 함"으로 만들었다. 이제 조건부 작성자는 정적 객체에 쓰는 일반 쓰기로 보고, 조건은
   `FunctionSummary.writer_conditions` + IDENTITY/UNKNOWN 아닌 모든 run의 조건으로 전달 → 호출 지점이 판정.
   호출 지점이 위치를 못 잡거나 실패를 찾으면 그 호출 전체(레지스터·메모리·SP 복원)를 unknown으로
   (`_all_unknown`; 보존 주장도 조건에 기대므로). SP 델타는 조건 붙이기 전 run으로 계산(같은 조건 아래).
   검증: 배치 전수(home slot 겹침 포함) 누락 0; 변형 "조건 없이 신뢰"를 `*rdi = rcx; *(*rsi) = rbx` 배치가
   잡음(48건). 요약 검증기는 실행의 실제 입구 주소로 조건을 계산해 실패한 실행만 건너뜀(`conditional_skips`).
5. **검증기 보강**(`pcode_interpreter`): COPY 출처를 바이트 단위로, 호출 활성화가 쓴 바이트의 출처가 정확히
   자기 호출 전 값이면 원래 작성자 유지(값이 같다는 이유로는 아님). 기존엔 다른 부채에 가려져 있던 검증기
   오탐(`mov edx, edx`류)이 정의 atom으로 부채가 사라지며 드러났음.
6. **결과**(기본 모드, 누락+확실 0): 09 debug 75건 정확 60(80%) → **63(84%)**, 정확+확실 54(72%) →
   **59(79%)**; UE DebugGame 22건 확실 3 → **9**(정확 10); release·win32·UE Dev 변화 없음. 동적 검증
   (measure_program --models) 5개 Bundle 누락 0. 테스트 452개.
7. 보류: Q4(함수 어디든 미해결 쓰기 → 불확실) — 미해결 쓰기에 "출력 저장소 미상" 연산이 섞여 있어(레지스터를
   덮을 수 있음) 그대로는 못 뺌, 종류 구분 후 좁히기(측정상 win32 1건). fresh 객체의 다른 기준과의 불겹침(탈출
   분석), 함수 간 fresh 반환(A3), realloc 내용 보존, x86-32 모델.

## 19. 새 객체·포인터 체인 2단계: UE Core 모델 · realloc · fresh 불겹침 (2026-10-08, Fable 검토 반영)

Fable 권고 순서 (a) 엔진 DLL 모델 → (b) realloc = 같은 객체 → (c1) fresh 불겹침 → (c2) 탈출 분석 → (d) 함수 간
fresh. 이번 단계는 (a)(b)(c1)과, 측정 중 드러난 UE helper 원인들.

1. **엔진 DLL 모델 매칭**(`summary_store`): 파일에 `libraries`, 항목에 `original_names`(mangled). 라이브러리 + mangled
   이름으로만 매칭(C 런타임 파일은 짧은 이름, 단 `?` mangled import는 제외), 두 파일이 한 import에 맞으면 오류.
   새 파일 `models/external/ue_core_win64.json`: FMemory Malloc(fresh)/Free/QuantizeSize(순수)/Realloc,
   FDebug::CheckVerifyFailedImpl·UE4Array_Private::OnInvalidArrayNum(메모리 보존 — 가정
   "ue-core-diagnostics-no-reentrant-callback", noreturn은 verify()에서 틀리므로 쓰지 않음).
2. **realloc = 같은 객체**(모델 `same_object_as`, crt v3·ue-core): 결과 주소식 = 호출 시점 인자의 주소식(가정
   no-use-of-old-pointer-after-realloc, free의 no-use-after-free와 같은 꼴), 인자가 상수(realloc(NULL))면 fresh,
   other_memory 보존. 검증기 realloc은 항상 블록을 옮기고 각 바이트가 원래 작성자를 유지(이동), 옛 블록은 havoc.
   DFB031 정확·확실.
3. **fresh 불겹침(c1)**(`may_alias._Policy`): fresh 객체(fresh atom 하나 기준)는 상수 주소·스택·다른 fresh와
   안 겹침. **입구 레지스터 기준 객체는 제외** — 불투명 호출 뒤의 레지스터 읽기는 SSA상 입구 값이지만 실제로는
   그 호출이 돌려준 값(새 블록 주소일 수 있음)이라서(같은 원리의 기존 구멍 후보는 별도 작업으로 기록).
   테스트: 엔진이 따라갈 수 없는 경로(실행 시 G를 가리키는 rbx)로 돌아온 포인터는 겹침 유지, 변형 "fresh는
   무엇과도 안 겹침"을 검증기가 잡음.
4. **CALLOTHER 표시 연산**(`models/pcodeops/x86.json`, `pcodeop_models`): Bundle에는 userop 번호만 있으므로
   언어 버전별 번호→이름 표(`ghidra/GhidraV2ListUserOps.java`로 확인: x86 64/32 4.6에서 17=LOCK, 18=UNLOCK)로
   LOCK/UNLOCK(출력 없고 번호 피연산자뿐)을 읽기·쓰기 없는 선언 효과로(라벨 `pcodeop-model:x86-markers/...`).
   검증기도 같은 의미로 실행(`no_effect_userops`).
5. **`jmp [__imp_X]` 꼬리 호출**: 모델을 BRANCHIND 꼬리(마지막 연산, fallthrough 없음 — Ghidra는 terminal로
   표시하지 않음)에도 적용, BRANCH 꼬리와 같은 합성. 검증기는 외부 함수 실행 후 그 ret으로 호출자에 복귀.
   스택 모양이 없는 thunk가 스택 기준 객체를 전혀 건드리지 않으면 꼬리 지점의 프레임 아래 경계 0
   (`_stackless_tail_bounds`).
6. **요약의 비공개 프레임 규칙**: 엔진 may_alias는 비공개 프레임 쓰기가 다른 객체에 닿지 않는다고 보는데 요약의
   crossing은 그렇지 않아, 가변 인자 호출 전 스택 인자 쓰기만으로 입구 포인터 객체가 UNKNOWN이 됐다. 정규화가
   `private_frame_writes`·`wild_objects`를 남기고 요약이 같은 규칙을 씀.
7. **호출 효과의 레지스터 범위**: thunk처럼 레지스터 몇 개만 쓰는 함수의 호출 효과가 그 함수의 최대 레지스터까지만
   보존을 계산해 RBX·RDI 같은 보존 레지스터가 빠졌다 → 프로그램 전체 범위 이상으로.
8. **결과**(기본 모드, 누락+확실 0): 09 debug 75건 정확 63 → **64(85%)**, 확실 59 → **60(80%)**; release 51/46 →
   **52/47**; win32·UE 케이스 지표 변화 없음. UE Dev 호출 경유 의존 1,276 → 2,428, DebugGame 796 → 1,684, 모델
   적용 호출 5 → 70. 동적 검증 누락 0(zlib 256건은 기존과 동일, 별도 작업). 테스트 461개.
9. **UE 다음 원인**(R001/R011): TArray helper가 Realloc 결과를 `this->Data`에 쓰고 호출자가 그 포인터를 다시
   읽어 원소를 씀 → 그 포인터가 "새 블록(스택 아님)"이라는 사실이 함수 경계를 못 넘음 = (d) 함수 간 fresh.
   그 밖: 가상 호출(레지스터 CALLIND), FString 내부, 루프 안 쓰기.

## 20. (d) 함수 간 포인터 값 (2026-10-08, Fable + Astra 교차 검토)

설계 과정: 같은 설계 문서(`docs/design_brief_d_interprocedural_fresh.md`)를 Fable과 Astra(gpt-6-astra, Codex CLI,
읽기 전용)에 각각 주고, 서로의 답을 보여 준 2라운드에서 합의. 핵심 합의: (1) 첫 단계는 "정체성"이 아니라 "스택이
아님" 분리 사실 + 정확한 값 대입(복사, realloc 지연 전달) — 새 블록끼리 서로 안 겹친다는 정체성은 미룸(같은 블록이
두 출력으로 나갈 때의 위험); (2) 증거는 표현식 같음이 아니라 정의를 거슬러 올라가는 출처 추적(같은 식이어도
"realloc 결과"와 "옛 포인터 복사"는 NULL일 때 다름); (3) 긍정 테스트는 `is_complete`까지 확인(검증기는 부채가 있으면
놓침을 봐 줌), 주소 재사용(free 후 malloc) 시나리오. 내 판정: Fable의 "wild가 아니면 충분" 주장은 틀림 — 프레임이
이미 탈출한 경우(&Arr 전달) 별칭 부채는 정책의 "스택과 안 겹침"(Astra 안)으로만 없어짐.

1. **callee 요약**(`function_summary._pointer_values`, `_CopyTracer.origin`): 포인터 폭 run(COMPUTED, 또는 부채 없이
   alias crossing만 있는 UNKNOWN — 호출 효과가 내보낸 쓰기와의 겹침으로 풀 수 있는 것)의 모든 종단 정의를 정확한
   복사(COPY·STORE·LOAD 전달, 단일 도달 정의, 무조건 부채 없음 — S3 조건부 부채는 run 조건으로 호출 지점이 판정)로
   거슬러 올라가 출처를 구함: 입구 범위 → `("same", 범위, False)`; fresh 호출 결과·이미 nonstack인 하위 호출 run →
   `("nonstack",)`; same_object 결과(realloc) → 인자의 출처 위에 `("same", 범위, True)`(NULL이면 새 블록). 합류(JOIN 정의,
   또는 run의 여러 종단 정의): 같으면 유지, "입구 값 유지 ∪ 그 값의 realloc"은 `("same", 범위, True)`(객체면 같은 객체,
   NULL이면 NULL 또는 새 블록 — 둘 다 스택 아님), 그 밖은 없음.
2. **호출 효과**(`call_summary_effects`): 값을 바이트별 판정의 sources에 `("pointer", 값)` 표시로 실어(값 없음도 표시)
   출구 병합에서 다르면 버림, keeps_old면 버림, 한 run이 정확히 포인터 폭일 때만 `ProvenRunEffect/ProvenMemoryRun.value`
   (`nonstack` / `same_reg`(레지스터) / `same_mem`(앵커 메모리)) — 대입할 입력이 그 run의 입력 행에 있을 때만.
3. **caller**(`normalize._proven_call_rows` → `relative_memory._pointer_row`): `nonstack` → 한 번만 실행되는 호출의 행에
   nonstack atom(스택과만 안 겹침, `may_alias._Policy.nonstack_objects`); `same_*` → 호출 시점 값의 주소식 대입(입력 행
   `~in`/`~ld`), 상수 0 + NULL이면 새 블록 → nonstack atom, 그 밖 상수는 그 주소. 정규화 결과에 `fresh_rows`·
   `same_object_rows` 보존(요약이 사용).
4. **고친 버그**(Astra 지적): realloc 인자가 0이 아닌 상수여도 새 블록으로 보던 것 → 0만 새 블록, 그 밖 상수는 그 주소.
5. **검증기**: free된 주소를 다음 malloc이 재사용(가정 no-use-after-free를 실제로 시험).
6. **테스트**: TV2R001 모양(Data=0 → 원소 쓰기 뒤 프레임 필드 정확·확실), Data가 이미 블록일 때 realloc 너머 원소 출처
   유지, helper가 `this->Data = &this->Num`이면 값 없음, 변형 "모든 포인터 run을 nonstack으로"를 검증기가 잡음, free 후
   주소 재사용. 테스트 466개.
7. **결과**(누락+확실 0): UE Development 정확 13 → **14**(64%), 누락 2 → 1(R001이 확실이 됨, 남은 과다 출처 B는 8바이트
   구조체 복사의 바이트 정밀도 — 보류 항목); win32 확실 36 → **37**; 09 debug·release·UE DebugGame 변화 없음; 동적
   검증 누락 0(zlib 256 기존).
8. **다음**: DebugGame은 같은 패턴이 home space 경유로 더 깊음; 새 블록 정체성(그룹)·루프·재귀의 값; 가상 호출; 바이트
   정밀도(R001 B).

## 21. DebugGame: 조건부 별칭 너머의 값 · xor 0 · 반환 주소 슬롯 (2026-10-08)

원인(측정): DebugGame의 TArray helper(ResizeGrow)는 this를 home 슬롯에서 매번 다시 읽어 쓴다. (1) `this->Data =
Realloc(...)`의 주소가 "조건부 별칭 의심"(S3)을 지나 그 의심의 *작성자가 쓴 값*까지 거슬러 올라가, 그 값의 clobber 부채
때문에 조건 없는 불확실 쓰기가 됐다; (2) 그 clobber는 내부 helper의 `xor edx, edx`(입력과 무관한 0)가 앞선 import
호출이 덮은 edx를 "읽는" 것으로 처리돼 생긴 가짜 부채였다.

1. `function_summary._address_slice` / `_AncestorClosure`: 조건부 may-alias 부채는 닿되 지나가지 않음(조건 성립 시 그
   작성자는 읽은 바이트를 쓰지 않았으므로 그 값은 흐르지 않음, 실패 시 호출 전체가 unknown).
2. `normalize._scoped_effect`·검증기: 같은 레지스터끼리의 XOR/SUB/BOOL_XOR = 입력 없는 0. 주소식 평가기도 0, 상수의
   INT_SEXT·INT_MULT 접기.
3. writer 조건 쌍이 배제한 (작성자 → 바이트) 별칭은 요약 crossing에서 뺌(`_exit_crossings`의 excused).
4. 호출 모양이 push한 반환 주소 슬롯 run은 메모리 보존 판정에서 뺌(엔진이 원래 그 push를 transient로 지우고, 복귀 후
   호출자 SP 아래의 죽은 바이트로 보는 것과 일관).
5. 테스트: DebugGame 모양(this spill/reload, 모르는 값을 쓴 뒤 알려진 값으로 덮기) — 메모리 보존·확실, 배치 전수
   (home 슬롯 겹침 포함) 누락 0, 변형 "옛 주소 slice"는 다시 조건 없는 불확실 작성자가 됨; xor 0. 테스트 493개.
6. 결과: DebugGame 호출 경유 의존 1,684 → 2,466(helper가 메모리 보존으로 증명됨), 케이스 지표는 변화 없음; 다른
   Bundle 변화 없음, 동적 검증 누락 0. R001 DebugGame의 다음 원인: 호출자에서 다시 읽은 Data가 "스택 아님"으로
   인정되지 않는 경로(Add 안의 check() 실패 경로 등) — 조사 중.

## 22. 가정 레지스트리 · census 클래스 A 수정 (2026-10-12, Fable + Astra census)

배경: UE DebugGame/Development의 남은 케이스를 Fable과 Astra가 각자 전수 조사(census)하고 교차 검토해 근본 원인을
A(이번 트랙)/B(별도 주제)/C(정상)로 나눴다. 수정 중 필요한 가정이 늘어 **모든 가정을 한곳**에서 관리한다.

1. 가정 레지스트리 `src/tdo_v2/assumptions.py` (`REGISTRY`): 이름·종류(switch/reported/model/test-only)·기본값·
   주장·깨지는 경우·적용 위치. `docs/assumptions.md`는 `render_markdown()`으로 생성(테스트가 일치 확인).
   `run_dfbench`의 `--no-…` 플래그와 환경 변수도 레지스트리에서 만든다.
2. 새 가정 두 개, 기본 켜짐(사용자 결정 2026-10-12):
   - `win64-home-space-callee-private`: Win64에서 진입 SP 위 반환 주소 슬롯 + 32바이트 home space는 그 함수의
     private frame(`may_alias._Policy.private_above = 0x28`). 함수가 스택 포인터를 내보내면 기존 탈출 분석이 취소.
   - `debug-break-traps-do-not-return`: int 3 / int 0x29(`models/pcodeops/x86.json`의 `traps`) 뒤는 죽은 경로.
     `function_summary._dead_region`이 trap과 noreturn 호출에서 경로를 잘라 죽은 exit·호출·crossing을 뺀다; 모든
     경로가 trap으로 끝나는 함수는 `ProvenCallEffect.noreturn`(예: `__report_gsfailure`, 그 꼬리를 가진
     `__security_check_cookie`).
3. 클래스 A 수정(증명, 가정 아님):
   - A2 오래된 포인터 행 치환: 아직 주소 없는 쓰기가 남아 있으면 ENTRY에 닿는 메모리 포인터 행을 미룸.
   - A3 JOIN(NULL / 스택 아닌 블록): 한 번만 실행되는 블록의 JOIN은 활성화마다 고정된 "스택 아님" 값. 원자는
     블록이 아니라 **JOIN 소스 집합**으로 키(같은 소스의 JOIN 두 개는 같은 경로 → 같은 값).
   - A6 callee 안의 realloc(NULL): 호출의 유일한 포인터 값이면 fresh(값이 둘이면 같은 블록일 수 있어 nonstack).
   - A9 상수: 넓은 상수 쓰기의 일부 바이트, INT_AND/OR/XOR·SUBPIECE 상수 접기.
   - A8 죽은 쓰기: 어떤 run에도 없는(나중 쓰기가 모든 경로에서 덮은) 쓰기라도 대상 객체가 anchor 가능하면
     exported. 그 쓰기가 다른 바이트에 닿았다면 덮은 쓰기도 같은 주소에 닿고, 그건 exported라 호출자의 may-alias가 덮음.
   - BUG-1 IAT 슬롯은 읽기 전용 상수가 아님(85b7c27).
4. 테스트: `test_named_assumptions.py`(가정 끔/켬/위반을 oracle이 잡음), `test_dead_exported_writes.py`(같은 객체면
   덮은 값이 보임), `test_definition_atoms.py`(병합 할당). 503개 통과.
5. 결과(sure-missing 0 유지, 동적 검증 누락 0):
   - UE DebugGame exact/exact+sure 10/9 → **15/12** (과잉 보고 10 → 5): R011·U008·U009 exact+sure, R007·R008은 잘못된 B가 빠져 exact
     (아직 unsure), R001은 sure(B 과잉은 남음). 동적 검증의 부채로 덮인 차이 450 → 422.
   - UE Development 14/12 → **14/13**(U004 sure, A8).
   - 09 debug 64/60, release 52/47, win32 44/37 변화 없음. zlib 109730의 누락 256은 이전과 같음(기존 이슈, 별도 작업).
6. 남은 것: 클래스 B(바이트 정밀도, FName/FString 모델, CoreUObject 핸들, 해시/루프), memcpy 크기 증명.
7. 검수(census round 2, Fable + Astra 2라운드 + 설계 상담) 결과:
   - **오래된 투영(stale projection)**: 주소가 나중에 풀리는 쓰기 때문에 메모리에서 읽은 값의 도달 정의가 바뀌어도,
     이미 만든 투영은 다시 보지 않았다(HEAD에도 있던 문제, 호출 없이도 재현). 수정: `settle_pending`(주소 없는 쓰기가
     닿을 수 있는 읽기 값은 기다림, 마지막 단계에서만 사용하고 그 단계가 쓰기의 주소를 풀면 되돌림) + 최종 검증
     `relative_memory.stale_reads`(쓰인 값은 최종 SSA 값과 같아야 함, rep 개수는 부채도 없어야 함; 실패한 읽기는 막고 다시
     정규화). 테스트 `test_stale_pointer_rows.py`, `test_stale_projection_alias.py`(rep).
   - BUG-6(JOIN 원자 키를 SSA id 대신 안정 키로), BUG-7(trap 가정 보고 누락), BUG-11(pcodeop 모델 항상 전달),
     죽은 경로 쓰기의 조건 제거.
   - **남은 건전성 문제(설계 합의, 미구현)**: 주소가 부채 있는 읽기에 기대는 "불확실 주소 쓰기"가, 그 쓰기가 닿을 수
     있는 읽기에 부채를 만들지 않는다 — 루트 slice(와 Astra 재현으로는 요약의 레지스터 run, 호출 안 메모리 쓰기 `~k`)가
     놓칠 수 있음. 합의된 설계: may_alias에 "불확실 쓰기" 종류(어디든 쓸 수 있으나 kill하지 않음) + 그 쓰기의 조건을
     실은 부채 노드(`conditions_of`) + `_uncertain_address_writers`와 고정점(`~k`/`~e` 행 포함) + rep 개수/방향 증명의
     레지스터 clobber 검증; 재귀 대신 명시적 루프. xfail 테스트가 이 문제를 표시.
8. **불확실 주소 쓰기의 부채(구현, 2026-10-12, Fable + Astra 설계 합의)**: 주소가 부채 있는 읽기에 기대는 쓰기 W는
   "정적 위치에 쓴다(조건부: W의 조건 하에) 또는 어디든 쓴다(무조건)".
   - `function_summary.uncertain_writers_of`: STORE + 호출 메모리 행 `~k`·rep 원소 `~e`(anchor로 주소 slice), 호출
     clobber 부채는 그 행의 span이 주소 레지스터와 겹칠 때 셈. → `normalize`가 고정점까지 반복(재귀 대신 명시적 루프,
     막힌 읽기 `_blocked_reads`·막힌 rep 사이트와 함께).
   - `may_alias(uncertain_writers=…)`: W는 평소 효과에 더해 "?W"를 모든 객체의 모든 바이트(private 포함)에 gen;
     이후 정확한 쓰기만 kill. 행에 `MayAliasRead.uncertain`/`plain`.
   - 부채 노드: 무조건 W는 보통 `may_alias_read`(작성자 간선 포함, 후보 출처); 조건부 W는 별도
     `uncertain_write_read`(간선 없음, 조건=`NormalizedFunction.uncertain_nodes`). 루트 slice에선 부채(조건을 판단할
     호출자가 없음), 함수 요약에선 투명(그 조건은 이미 `writer_conditions`로 모든 주장에 붙음), 연쇄 판정엔 조건과 함께 셈.
   - rep: 개수의 최종 그래프 slice가 어떤 부채에도 닿으면 그 사이트는 펼치지 않음(레지스터 clobber 포함). 방향은 상수
     또는 `direction-flag-clear`(진입과 호출 복귀 시 DF=0, 레지스트리 문구 갱신).
   - 테스트 `test_stale_projection_alias.py` 5개(wild 포인터, callee 안 쓰기, clobber된 레지스터로 STORE, rep 개수 둘).
   - 결과(e9): 09 debug 64/60·release 52/47·win32 44/37, UE Development 14/13 변화 없음; UE DebugGame 15/12 → 13/12
     (R007·R008: 이미 unsure였고, 호출 뒤 다시 읽은 포인터로 쓴 무조건 불확실 쓰기의 값 B가 가능한 출처로 추가 — 과잉,
     누락 아님). sure-missing 0, 동적 검증 누락 0(zlib 109730 기존 이슈 제외). zlib 분석 시간 55 → 90초(고정점 반복).
9. **구현 검수(Fable + Astra 2라운드) 후 수정** — 모두 반례 테스트가 있고, 각 수정을 되돌리면 그 테스트가 실패함:
   - `_alias_conditions`: 무조건 불확실 작성자가 보통 별칭으로도 닿아도 부채는 무조건(조건 쌍으로 바뀌지 않음).
   - writer 조건을 호출 지점에서 **판정**(`ProvenCallEffect.writer_conditions`, `~cw` 행): 전엔 위치만 확인해 보존·
     IDENTITY 주장이 판정 없이 쓰일 수 있었음. 재귀 가설도 writer 조건을 실패로 둠.
   - 조건 판정·모델 extent·rep 개수/방향·호출의 below-stack 경계: 근거 값이 부채에 닿으면 쓰지 않음
     (`normalize._reaches_debt`/`_debt_nodes`/`_row_reaches_debt`, 호출 clobber는 그 행의 span이 겹칠 때만).
     extent 상수는 상태마다 다시 확인하고 틀리면 영구 철회. 검증은 may-alias 부채를 그래프에 만든 **뒤**에 함.
   - DF: `direction-flag-clear`로 받아들이는 건 "부채가 모두 DF 자신을 바꿀 수 있는 호출뿐이고 방향이 정방향(0)"일
     때만(호출 전 DF=1, 호출 뒤 다른 레지스터에서 DF 복사 → 거부).
   - 무조건 불확실 쓰기는 kill하지 않음(dense·sparse).
   남은 것(정밀도·성능): 중간 호출자에서 열린 조건 쌍을 위로 넘기기(BUG-5, `~cw` 포함), 불확실 집합만 바뀔 때
   재정규화 전체 대신 may-alias·부채만 다시 만들기(zlib 55 → ~100초).
10. **남은 작업(2026-10-12, Fable + Astra 설계 상담·2라운드 검수)**:
   - 속도: 불확실 쓰기 고정점을 한 번의 정규화 안에서 반복(그래프 `copy()` + may-alias·부채만 다시 만듦). zlib 104 → 약 60초.
   - 열린 조건 쌍(BUG-5, run 조건 `cr`만): 중간 함수에서 판단할 수 없는 쌍은 실패 대신 그 함수의 조건으로 남김 —
     run 행 `~{i}`에 "open_condition" 부채(조건부: 요약은 쌍을 위로 넘기고, 루트는 unsure). 한번 열린 쌍은 계속
     열림(나중에 실패하거나 다른 위치로 잡히면 실패). 조건에만 나오는 객체도 anchor 후보(`_relative_anchors`).
     writer 조건(`cw`)은 계속 실패로 둠(측정 결과 0건; 레지스터·SP 보존까지 지키려면 별도 장치 필요).
   - 실행 검증기: 호출 안에서 push/pop으로 메모리를 거쳐 되돌린 레지스터도 정확한 복사 출처(`_copy_source`)로
     호출 전 작성자를 되찾음 — 보존 주장을 믿지 않고도 거짓 누락이 없음(검수 중 넣었던 완화는 Astra가 실제 누락을
     숨길 수 있음을 보여 제거).
   - 테스트: `test_open_conditions.py` 6개, `test_program_oracle_copy_back.py` 2개. 526개 통과.

## 23. DLL 함수를 한 번 분석해 모델로 재사용 (2026-10-13, 사용자 결정 · Fable + Astra 설계)

배경: 외부 DLL(UE Core 등) 함수는 실제 코드를 같은 엔진으로 **한 번** 분석해 모델로 저장하고, 이후엔 DLL 없이 모델을
쓴다. 사람이 쓰는 모델은 분석이 막히는 곳(가상 할당기 등)에만. 다른 곳에서 만든 모델을 넣는 입구도 마련한다.
실험(UnrealEditor-Core.dll 5.1): 대상 5개 함수의 호출 폐포 3,493개 — `AppendChar`/`FName` 생성자는 2,830개(서로
부르는 2,046개 덩어리, 간접 호출 3,396개)로 끝나지 않음. 이미 모델이 있는 함수 6개에서 자르면 `AppendChar` 8개 함수,
`~FString` 2개(FName은 이름 풀 자체가 덩어리라 그대로 → 손 모델).

계획: (1) 출처와 외부 모델 입구 (2) DLL 분석 중 모델 있는 함수에서 자르기(주소로 일치; 손 모델의 "이 모듈 메모리"
문구가 DLL 안에선 뜻이 바뀌는 점 재확인) (3) 분석 결과를 호출자와 무관한 템플릿(요약 + anchor)으로 저장·로드
(레지스터 객체 재지정, DLL 전역은 모듈 구분 · 처음엔 보존 주장 포기, 가정은 전이적으로 수집) (4) FName 손 모델.

1단계(구현): 모델 파일 `source`(hand 기본 | derived: library + sha256 필수 | external: tool …), `assumptions`(등록된
가정 이름이나 `<namespace>:<name>`). 라벨: `external-model:`(hand, 기존 그대로) / `derived-model:…#<sha 12자리>` /
`supplied-model:`. 사용 시 모델 라벨과 그 모델이 기대는 가정을 함께 보고. 이번 실행에서 꺼진 가정에 기대는 모델은
적용하지 않음(호출은 불투명). 같은 import에 모델이 여럿이면 오류 — `overrides`(`<file id>/<entry>`)로만 명시 교체;
없는 대상·자기 파일·순환·중복 file id는 로드 시 오류, 교체 후 후보가 없으면 오류. 추가 모델 폴더: `run_dfbench
--model-dir`(반복), `TDO_V2_MODEL_DIRS`(OS 경로 구분자 `;`/`:`), 같은 폴더는 한 번만. 성능(결과 불변):
`interprocedural.site()` 함수별 캐시, `_preserved_stack_pointers` 레지스터 공간 1회 계산 — 재귀 덩어리 분석의 반복
계산 제거. exporter `--entry`도 호출 폐포 포함. 테스트 `test_model_sources.py` 12개, 538개 통과, 측정 불변.

2단계(구현): 라이브러리 자체를 분석할 때 모델 있는 함수에서 자르기. 모델 항목 `"internal": true`(그 라이브러리 안의
호출자에게도 모델이 맞음 — UE Core 6개 항목, v2). `analyze_units(own_library=...)`: export 이름이 internal 항목과
맞는 함수는 분석하지 않고, 직접 호출·꼬리 점프·상수 대상 간접 호출이 모델을 씀(라벨 + 새 가정
`library-internal-model-cuts`: 모델이 어디서 쓰이든 그 함수의 **완전한 계약** — 빠진 내부 상태는 아무도 관찰하지
않음). 프로그램 전체 사실(스택 포인터, 레지스터, 스택 전환에 따른 가정 철회)은 잘린 함수 포함 전체로 먼저 계산한
뒤 모델 적용 여부를 정함. 메모리를 안 건드리는 thunk(`jmp 모델`)의 꼬리 경계 0: 프로그램의 적재 메모리 공간이고
**스택 포인터를 쓰지 않을 때만**(`add rsp; jmp`는 제외 — Astra 반례). 실험: FString 대상 3개의 분석 범위 2,830 → 6개
함수(+6 잘림, 명령 154개), 1초 미만; `FString()`·`~FString` 메모리 보존, `AppendChar`는 `Data[Num] = c`(인덱스 주소)
쓰기 2개가 주소 모르는 쓰기로 남음 → 3단계 전에 "객체 안 어딘가" 표현 필요. 테스트 `test_library_cuts.py` 5개.

4단계(구현, 3단계보다 먼저 — 사용자 결정 A→B): **"정확한 위치, 모르는 값" 쓰기**와 FName 손 모델. 모델 메모리 행
`{"write": ..., "value": "unknown"}`: 그 바이트만 값을 말하지 않고 쓴다(나머지 메모리는 `other_memory` 대로).
일반화: 요약에서도 값이 UNKNOWN(빚·풀 수 없는 원천·실패한 조건)이지만 **위치가 anchor로 정확한** 메모리 run은 더 이상
"메모리 전부 보존 안 함"이 아니라 `ProvenCallEffect.unknown_memory`가 된다(위치를 못 찾는 쓰기, 주소 모르는 쓰기, 불투명
내부 호출은 그대로 보존 포기). 호출자: `~iu<j>`(다른 입력과 함께, 출력보다 먼저 주소를 계산 — Astra 반례: 래퍼가 호출 뒤
rcx를 바꾸면 위치가 틀렸음) → `~u<j>`(그 위치 쓰기 + 무조건 빚 "opaque_call_write"; query·설명 그래프·주소 불확실
목록에 포함 — 그 값으로 만든 주소의 쓰기는 주소 불확실 쓰기). 같은 호출의 anchor 쓰기가 그 호출이 직접 쓰는 전역과
겹치면 anchor 쓰기를 미해결로 둠(행 순서는 실제 순서를 말하지 않음 — HEAD에도 있던 구멍, 테스트로 확인). 모델 항목별
`assumptions` 허용(파일 `source.assumptions`와 같은 검사). FName 생성자 2개(WIDECHAR/ANSICHAR, `ue-core-win64` v3):
`[rcx, rcx+12)` 값 모름, `rax = rcx`, observes rcx·rdx, 나머지 보존 — 새 가정 `ue-core-name-pool-private`(이름 풀·락·
TLS·할당은 Core 내부, 모듈로 들어오는 콜백 없음, UE 5.1 에디터 빌드 FName 12바이트). 진단 항목 2개는
`ue-core-diagnostics-no-reentrant-callback`를 사용마다 보고. 오라클: 읽기가 그 호출의 `~u` 행만 읽고 슬라이스가
불완전할 때만 빚으로 설명(넓은 읽기가 다른 바이트를 같이 읽으면 원래 검사 — Fable·Astra 2차). 결과(e21): UE DebugGame
13/12 → 13/13, Development 14/13 → 14/14(R006 확실), 09 64/60·52/47·44/37 불변, 동적 누락 0(zlib 256 기존),
설명 안 된 의존 09·Dev 0, DebugGame 1270 → 1226. 테스트 `test_opaque_call_writes.py` 14개, 556개 통과.

3단계(구현, Fable + Astra 설계 2차까지): **분석 결과를 템플릿으로 저장·로드**. `summary_templates`: 내보낼 함수의 요약 +
anchor를 호출자와 무관한 형태로 저장(모델 파일 `"kind": "summary"`). 객체 표: 레지스터 파일(가져오는 프로그램의 것으로
재지정), entry 레지스터나 그 객체 안의 포인터 슬롯에서 주소가 정해지는 객체(`anchor`, 스택 프레임 포함), 나머지 —
DLL 전역, anchor 없는 객체, 원천으로 나오는 임시 저장소 — 는 **아무 호출자도 위치를 못 찾는 객체**(`local`: 그 쓰기는
메모리 보존 포기, 그 값은 모름, 그 조건은 결정 불가; 가져오는 쪽 전역 주소로는 절대 안 바꿈). 동작 키는 `dll:` 접두.
가져올 때는 Bundle 안 함수와 **같은 경로**(`site_effect`, 실패한 별칭 조건 되먹임 포함 — Astra: 기존 외부 모델 경로는
실패 조건을 버림; 객체 id 고정). 기준: 위치를 찾을 수 있는 부분은 Bundle 안 결과와 같고, 나머지는 약해질 뿐 강해지지
않음(테스트로 확인). **적재 주소 의존**(Astra 반례 `[rcx + &G]`, `&G`의 한 바이트를 오프셋으로): 파생 실행에서
`relative_memory.ImageBaseTracking` — 이미지 범위 상수가 들어간 주소식의 "이미지 기준 계수"를 따라가, 그 수가 entry 값
기준 위치·크기·스택 변화량 같은 **사실**이 되면 그 함수(와 그것을 부르는 함수)는 내보내지 않음; 읽기 전용 이미지 접기는
끔(재배치된 주소일 수 있음). 출처: Bundle의 executable sha256, 이미지 기준 주소, 언어 버전, 엔진 버전(요약·템플릿·
의미 — 다르면 적용 안 함), 파라미터(`private_frame_above` 값 — 다르면 적용 안 함), 파생 때 읽은 모델 파일 전부의 파일
sha256(파일 단위 — 파일 기본값 변경도 잡음; 바뀌었거나 없거나 다른 파일이 그것을 overrides하면 적용 안 함), p-code op
모델 digest(트랩 표 포함), 그 실행의 모든 가정(전이성: 실행 전체 합집합) + 새 가정 `derived-model-runtime-matches`.
내보내기 거부: 요약 없음, 검증 안 된 재귀, 꼬리 출구, TEST-ONLY 입력, 원천 라벨·sink 요구, 위치 못 찾는 쪽의 writer
조건, 다른 파생 모델 위의 파생, 적재 주소 의존. 적용 안 된 템플릿은 `AnalyzedFunction.refused_models`(이유).
`analyze_units(keep_uncut=...)`: 내보낼 함수는 자르지 않음. 도구 `tools/derive_models/derive_models.py`(폐포만 분석,
프로그램 전체 사실은 라이브러리 전체에서). 실험: UnrealEditor-Core `FString()`·`~FString`·`AppendChar` 템플릿
(`models/derived/ue_core_win64_fstring.json`, 폐포 6 + 잘림 6): 3개 모두 내보냄, UE DebugGame/Development에서 각
2회씩 적용·거부 0; 지표 불변(13/13, 14/14) — 해당 사례는 `AppendChar`의 `Data[Num] = c`(인덱스 주소, 주소 모르는 쓰기
2개)가 메모리 보존을 막음 → 다음 주제 배열/인덱스. 동적 오라클(`measure_program`)은 DLL 코드를 실행할 수 없어 템플릿
호출이 있는 실행은 건너뜀(검증 아님). 구현 리뷰 2차까지(Fable·Astra) 반영 — **적재 주소 의존의 근거는 명령어
인코딩**(리뷰 7차까지): 이미지 범위 안의 수는 그 자체로 주소라는 증거가 아님(같은 비트의 고정 상수는 옮겨지지
않음). 명령어를 디코딩(접두사·REX·VEX/EVEX·0F 맵·ModRM)해서 — 이해 못 함(모르는 opcode, 67 주소 크기, XOP, 상대 분기
call/jmp/jcc/xbegin, 32비트 `lea r32,[rip]`)이면 "모름"; 재배치 항목도 RIP 상대 피연산자도 없으면 "고정 수"; 그 외에는
8바이트 재배치 항목이 정확히 그 값을 담거나 RIP 상대 대상(`주소 + 길이 + disp32`)이 그 값이고 **명령어의 다른 어떤
필드도 같은 값을 담지 않을 때만** "이미지 주소", 나머지 상수는 모두 "모름"(길이를 모르면 증명 없음;
`summary_templates.image_provenance`). 범위보다 출처를 먼저 봄: 증명된 주소는 범위 밖이어도(`&end + 8`) 1, 고정 수는
범위 밖일 때만 0. 증명 안 된 이미지 범위(끝 포함) 수는 "모름". 계수는 {0, 1, 모름}만: 주소 + 수 = 1,
주소 + 주소·주소 − 주소(`&end − &start` 포함)·상쇄·마스크·부분 읽기 = 모름. 사실로 쓰일 때 검사: entry 값 기준 위치,
절대 위치(계수 1만 허용), 상수 값(크기·호출 대상), 스택 변화량·`~sp`, rep 개수·포인터·방향, null 검사(0만 허용). 직접
메모리 피연산자(ADDRESS varnode)도 증명이 없으면 그 함수는 내보내지 않음. 이미지 범위 = 이미지 공간의 모든 블록. 언어
major/minor가 다르면 적용 안 함; TEST-ONLY 입력·추적 없이 분석된 결과는 내보내기 거부; 기록된 모델 파일과 같은 이름을
모델하는 다른 파일(템플릿 포함)이 있으면 적용 안 함; 메모리 공간이 둘 이상이면 거부; 생성 정보(엔진 리비전, Bundle)
기록(비교 안 함). 검증: 무작위 왕복(위치를 찾는 템플릿은 Bundle 안과 효과가 필드 단위로 같고, 나머지는 약해질 뿐),
**재배치 동적 검사**(클라이언트는 템플릿으로, 인터프리터는 실제 라이브러리 본문을 0x10000 옮겨 실행 → 조용한 누락 0;
검사를 끄고 내보낸 "masked restore"는 이 오라클이 잡음), 리뷰 반례 거부 테스트 9종(고정 상수, 빼고 더하기, 주소 두 개,
이미지 끝, 마스크 복원, 페이지 마스크, 부분 읽기, 상쇄, entry 기준 오프셋). Core 실험: 상수 51개 — 이미지 주소 2개 증명, 고정 49개, 모름 0; 템플릿 3개
그대로 내보냄. 테스트 `test_summary_templates.py` 25개, `test_summary_template_roundtrip.py` 8개, 589개 통과.

## 24. 진짜 DLL 연결 — 필요할 때 분석 + 저장 (2026-10-13 설계, 사용자 결정 · Fable + Astra 2차까지; v1 구현은 24.2)

사용자 의도: 분석할 때 진짜 DLL을 연결해 플러그인이 부르는 Core 함수의 실제 코드로 따라 들어가고, 한 번 분석한
함수는 저장해 두었다가 다음부터 저장본으로 대체(23절처럼 내보낼 함수를 미리 사람이 고르지 않음).

구조(B — 둘 다 동의): 플러그인 분석은 지금처럼 한 프로그램. 연결된 라이브러리의 import 중 유효한 저장본이 없는 것은
그 라이브러리 Bundle에서 바로 파생(23절 템플릿)해 같은 실행에 적용하고 저장. 두 Bundle을 한 분석으로 합치는 A는
(함수 키 충돌 0x180000000, 프로그램 범위 사실, 이미지 간 별칭) 비용이 커서 보류 — B의 손실은 정확도뿐: DLL 전역 쓰기는
메모리 보존 포기, 템플릿은 원천/sink 경계를 담지 않음, 콜백·가상 호출은 둘 다 불투명.

사용자 결정: (a) **손 모델 먼저** — 손 모델이 있는 import는 파생하지 않음(꺼진 손 모델이어도; 그때는 불투명). (b) v1은
**내보낸 함수만 저장** — 내부 함수는 배치마다 다시 분석; 함수 단위 저장(의존 digest)은 다음 단계.

v1 설계(Fable·Astra 2차 합의):
1. `--link LIB=<DLL 경로>` 반복. 공급자 확인: 파일 sha256 = 저장된 라이브러리 Bundle의 executable_sha256 = 템플릿에
   기록된 sha256 (선택한 DLL 바이트 → Bundle → 파생 기록 → 템플릿 → import 이름까지 사슬로). **이름 커버리지**: 플러그인이
   그 라이브러리에서 가져오는 모든 이름(손 모델·데이터 포함)이 DLL export 표에 있어야 함, 하나라도 없으면 그 연결 거부(잘못된
   DLL). **파생 자격**은 따로: 이름 있는, forward 아닌, 몸체가 있는 함수 export만(데이터·forwarder·서수 전용은 손/불투명).
   이름이 같아도 다른 빌드일 수 있음 → `derived-model-runtime-matches` 유지, 버전 리소스·해시 보고.
2. 필요한 export: 기존 import 호출 인식 패턴(모델 유무와 무관하게) − 손 모델 있는 이름.
3. 환경을 먼저 고정: 플러그인 실행의 유효 설정 → 파생 설정(읽기 전용 이미지 접기는 항상 끔; `globals-disjoint-from-stack`은
   **아래 "스택 전환 증거"로만** — 일부 폐포의 스캔은 DLL 전체의 증거가 아니고, 연결된 코드가 플러그인 정적 버퍼에서
   실행될 수도 있음. 정정: 이 가정은 요약 엔진에서 **기본 켜짐**(summary_engine `assume_globals_disjoint_from_stack=True`)이라
   통째로 끄면 기본 결과가 약해짐) → 파생 프로필 = 실제로 쓴 설정(엔진 버전들, private_frame_above, 스위치 상태, p-code op
   digest, 손 모델 파일 (id, sha256) 집합, 언어, Ghidra·SLEIGH·exporter·naming 식별자). 순서: 손 모델 확정 → 유효 가정
   → **적용 가능한 잘림만** 계산 → 그 잘림으로 내보내기·파생 → 적용 시 `refusal()` + 상속 가정 꺼짐 검사 둘 다.
   가정이 꺼져 적용할 수 없는 잘림은 몸체를 내보내거나 명시적 불투명 경계로(몸체 없는 빈 함수로 두지 않음).
4. 저장소: `<cache>/<LIB>/<dll sha256>/<프로필 digest>/` — 불변 템플릿 파일 + 시도 기록. 거부 분류: 의미(같은 입력이면
   재시도 안 함) / 예산(더 큰 예산·작은 배치로 재시도) / 인프라(복구 후 재시도). 배치 실패를 export의 영구 성질로 만들지
   않음. v1은 export 하나씩 파생(배치 1개). import마다 후보 하나만 골라 적용(저장된 배치 파일을 통째로 싣지 않음).
5. 파생은 손 모델 파일만 싣고, 어떤 라이브러리의 저장본도 싣지 않음(파생 위의 파생 거부가 저장되는 것 방지).
6. 내보내기 비용: DLL·번역 설정마다 Ghidra 프로젝트 유지(직렬 접근, 결과 Bundle은 불변·식별). 잘림 함수를 몸체 없이
   내보내는 최적화는 잘림이 주소로 걸리도록 고친 뒤(Fable P1-A: 지금 `derive_models`는 몸체 없는 잘림을 못 찾아 불투명이
   됨) 전체 폐포 파생과 같은 결과인지 테스트로 확인한 다음에만.
7. 보고(import마다): 저장본 사용 / 새로 파생 / 맞지 않는 저장본(이유) / 의미 거부 / 예산 / 손 모델 적용 / 손 모델 있으나 꺼짐 /
   불투명 경계; 템플릿 파일 식별자; 파생 안의 경계(다른 DLL import, 간접 호출).
8. 보류: 중첩 연결(Core → 다른 UE DLL), 데이터 객체 연결(GMalloc/GLog), 내부 함수 저장, 동적 오라클에서 DLL 코드 실행
   (명령어 주소·데이터 안 포인터·import·TLS까지 옮기는 로더 어댑터가 필요 — ImageBaseTracking의 증명은 재배치 명세가
   아님; 그때까지 그런 호출은 "검증 안 됨"으로 보고), 플러그인 자체의 적재 주소 의존(열린 항목).
구현 전 필수 테스트: 잘림 뒤에 숨은 스택 전환, 가정 철회로 꺼진 잘림, 데이터/forward export와 없는 이름 구분, 다른 DLL의
저장본, 겹치는 저장 배치, 예산 그대로 재시도해 성공하는 인프라 실패.

**Ghidra 실험(2026-10-13, Ghidra 12.0.4 headless, 엔진 코드 변경 없음)** — 플러그인 `UnrealEditor-TraceUnrealPlayground.dll`
(Development), 유지되는 프로젝트 하나:
- `-import <플러그인> -loader-loadLibraries true -loader-libraryLoadDepth 1 -librarySearchPaths <폴더>
  -loader-libraryDestinationFolder /libs -loader-linkExistingProjectLibraries true`: 검색 폴더에 둔 Core·CoreUObject를
  `/libs`에 불러와 플러그인의 External Program으로 연결(Core·CoreUObject 서로도 연결). 158초. **분석은 주 프로그램
  (플러그인)만** — 불러온 라이브러리는 분석되지 않음(별도 `-process`로 분석).
- 연결 확인 스크립트(모든 외부 심볼, C++ 클래스 namespace 포함; original imported name으로 연결된 프로그램에서 찾기):
  Core import 24개 모두 있음(분석 후 함수 19, 데이터 5 — 데이터 export도 구분됨), CoreUObject 141개 모두 있음, 없는 이름 0.
  → 설계 1번의 이름 커버리지·함수/데이터 구분을 Ghidra 연결 정보로 할 수 있음(Engine은 검색 폴더에 안 둠 → 연결 없음).
- Core를 프로젝트에서 한 번 분석·저장(`-process UNREALEDITOR-CORE.DLL`): 557초.
- 분석된 Core에서 FString 3개 폐포 내보내기(`-process ... -noanalysis`): **138초**(전에는 매번 새로 분석해 632초).
  Bundle 크기는 같음(10,495 파일, 510 MB — 내보내기가 손 모델 잘림을 모름, 설계 6번의 잘림 반영 내보내기 필요).
- 이 Bundle에서 파생한 템플릿은 기존 `models/derived/ue_core_win64_fstring.json`과 **완전히 같음**(생성 정보 제외).
설계 반영: 6번 — DLL마다 Ghidra 프로젝트 유지가 실제로 동작(라이브러리 분석은 한 번, 내보내기만 반복); 1번 — import→export
연결과 함수/데이터 구분은 Ghidra의 External Program 연결을 쓰고, 우리는 sha256·커버리지를 확인. 라이브러리 분석은 import 때
자동이 아님 → 연결 모드는 "필요한 라이브러리만 `-process`로 분석"을 명시적으로 수행.

**사용자 결정(2026-10-13): Ghidra 프로젝트는 사용자가 준비** — 연결할 DLL을 프로젝트에 올리고(라이브러리 불러오기·연결)
분석까지 끝내 두는 것은 사용자 몫, 도구는 스스로 import·분석하지 않고 준비 상태를 확인만 함(설명서
`tools/bundle_export/README.md`에 순서 명시). 구현(`export_bundle.py --ghidra-project X.gpr --project-program
/libs/LIB`): 프로젝트의 프로그램을 그대로 처리(`-process -noanalysis -readOnly`), 분석 안 된 프로그램 거부(exporter
`--require-analyzed`), 기록된 실행 파일 SHA-256이 주어진 DLL과 다르면 거부(기존 검사). **잘림 반영 내보내기**
(`--stop-at-internal-models LIB` / `--stop-at-name`): 내부 손 모델 함수는 내보내되 그 호출은 따라가지 않음(몸체가 있어
`derive_models`가 이름으로 찾아 자름 — Fable P1-A 해결). Core FString 3개: 49 파일·43 MB·98초(전: 10,495 파일·510 MB),
템플릿은 전체 폐포 파생과 **완전히 같음**; 잘린 함수 6개 모두 찾음; 분석 안 된 CoreUObject는 거부됨; import 방식
내보내기도 그대로 동작(회귀 확인).

### 24.1 결정 사항 정리 (2026-10-13 기준)

| # | 결정 | 누가 | 이유 |
|---|---|---|---|
| 1 | DLL 연결은 B 방식: 플러그인 분석은 한 프로그램, 저장본이 없는 DLL 함수는 그 DLL 코드에서 바로 파생해 쓰고 저장 | Fable·Astra 합의, 사용자 승인 | 두 프로그램을 한 분석으로 합치는 A는 비용이 크고, B의 손실은 정확도뿐(건전성 아님) |
| 2 | 손 모델 먼저: 손 모델이 있는 import는 파생하지 않음(꺼져 있어도) | 사용자 | 손 모델이 있다 = 분석이 막히는 곳; Malloc의 "새 블록" 같은 사실 유지 |
| 3 | v1 저장 범위는 내보낸(export) 함수만; 내부 함수 저장은 다음 단계 | 사용자 | 함수 간 의존 기록 없이 시작 |
| 4 | Ghidra 프로젝트는 사용자가 준비(DLL 불러오기·연결·분석); 도구는 import·분석하지 않고 준비 상태만 확인, 설명서에 순서 명시 | 사용자 | 분석 시간·옵션은 사용자 책임, 동작 예측 가능 |
| 5 | 내보내기는 내부 손 모델 함수에서 멈춤(`--stop-at-internal-models`), 그 함수 몸체는 포함 | 구현·리뷰 | 510 MB → 43 MB, 결과 동일 |
| 6 | `globals-disjoint-from-stack`은 **스택 전환 증거**로 판단: 연결할 DLL(과 분석 대상 프로그램)의 **전체** 함수를 Ghidra 프로젝트에서 한 번 검사해 증거 파일로 저장; 증거가 있고(같은 DLL, 전체 검사, 전환 0) 플러그인 실행도 가정을 켰을 때만 그 가정으로 파생; 전환이 나오면 실행 전체에서 가정을 끔; 증거가 없으면 가정 없이 파생(약하지만 안전) | 사용자 | 잘린 Bundle은 DLL 전체의 증거가 아님; 같은 프로세스라 DLL의 전환은 플러그인에도 영향 |
| 7 | 스택 전환 판정은 "모든 경로에서 스택에서 유래한 값"(must)으로: 그렇지 않은 값으로 스택 포인터를 쓰면 전환 | 구현(이번 검토에서 발견) | 기존 판정은 한 경로라도 스택 유래면 통과시켜 일부 경로의 전환을 놓칠 수 있었음; 스택 포인터를 지역에서 못 정한 함수(호출·복귀 모양 없음)는 프로그램 전체의 스택 포인터로 검사 |
| 8 | 전체 검사도 증명은 아님(Ghidra가 못 찾은 코드, 연결 안 한 DLL): 가정 이름 유지, 보고에 검사 범위(DLL, 함수 수, 함수 밖 명령어 수) 기록 | 합의 | 정직한 보고 |
| 9 | 보류: 중첩 연결, 데이터 객체 연결, 내부 함수 저장, 동적 오라클의 DLL 코드 실행(로더 어댑터 필요), 플러그인 자체의 적재 주소 의존 | 합의 | v1 범위 |

**24.1의 6·7 구현(2026-10-13, 리뷰 3차까지 — 규칙 `stack-switch-coefficient-v3`)**: 스택 전환 판정 = **스택 계수** MUST
분석(`may_alias.stack_switches`와 Java `GhidraV2StackSwitchScan`이 같은 규칙): 레지스터·임시값의 위치(공간·오프셋·크기)마다
"스택 포인터 + 수"(1) / 스택 포인터 없음(0) / 그 외(모름), 합류에서 같지 않으면 모름. 전달: COPY 유지; 덧셈·뺄셈은 계수끼리
(rsp − rsp = 0, 0·1만 남음); AND는 정렬 마스크 −2^k(k ≤ 12)일 때만 1 유지, 다른 마스크는 모름; LOAD는 0; 나머지 연산은
입력이 모두 0이면 0 아니면 모름; 부분 쓰기는 덮이지 않은 기존 위치를 모름으로; CALL·CALLIND 뒤에는 스택 포인터와 공통
보존 레지스터(x86-64 rbx·rbp·r12–r15, x86-32 ebx·ebp·esi·edi)만 유지; CALLOTHER는 자기 출력만 정의. 스택 포인터를 계수 1이
아닌 값으로 쓰면 전환(그 뒤 스택 포인터는 다시 1 — 연쇄 보고 없음). 닿지 않는 코드·함수 밖 명령어도 "스택 포인터 = 1"에서
검사; 지역 호출 대상도 따라감; 처리할 수 없는 분기는 UNCHECKED(전환 취급). **의도된 예외 3개는 이름 붙은 보고 가정
`stack-switch-check-exceptions`**: 메모리에서 읽은 값이나 호출이 남긴 레지스터 값으로 스택 포인터를 조정하는 것(alloca·
__chkstk)은 스택 포인터가 없는 값으로 봄, 사용자 연산은 자기 출력만 바꿈, 호출은 공통 보존 레지스터를 지킴 —
`globals-disjoint-from-stack`이 쓰일 때 함께 보고, 증거 파일에 `exceptions`·`call_preserved`로 기록(정확히 일치해야 로드).
이 예외를 없애면(읽은 값·호출 결과를 모름으로) 거의 모든 Windows 바이너리에서 가정이 꺼짐. 리뷰 반례(Fable·Astra 3차까지):
호출 너머 남은 rax, 한 바이트·부분 쓰기, rsp − rsp + 정적 주소, 부호 비트·하위 마스크, `rsp = CALLOTHER(rsp)`, 출력 없는
사용자 연산 너머의 rax, 복귀 모양만 있는 프로그램, 닿지 않는 에필로그 — 테스트로 고정(전환이어야 할 것은 이전 규칙에서
실패). 중간 오류 기록: v2 초안은 SSE CALLOTHER를 호출로 보아 Core에서 `mov rsp, r11` 26건 거짓 양성, x86-32 보존
레지스터를 비워 win32 Bundle의 확실 37 → 27 → v3에서 둘 다 해결. 결과: 기존 Bundle 전부 전환 0, 전체 측정(e34) 기준선과
같음(09 64/60·52/47·44/37, UE 13/13·14/14, 동적 누락 0, zlib 256 기존); Ghidra 전체 검사 Core 52,211 함수·2.88 M 명령어
(함수 밖 15,196 포함) 전환 0, 플러그인 981 함수 0, **ntdll.dll 양성 대조 `MOV RSP,[RCX+0x10]` — Java와 엔진 검사(같은 함수의
Bundle 1,540 함수)가 같은 연산을 찾음**. 증거 파일(`tdo_v2.stack_evidence`): 엄격한 형식 검사, 빈 검사는 깨끗하지 않음,
현재 규칙만 허용(이전 규칙의 깨끗함은 현재 규칙을 함의하지 않음), Java DETECTOR와 같은지 테스트; `assumption_allowed`: 증거
중 하나라도 전환이면 가정 철회(같은 프로세스), 라이브러리 파생은 그 라이브러리 자신의 깨끗한 증거가 있을 때만. 연결:
`run_dfbench --stack-evidence`(범위 출력; 증거가 없으면 "Bundle 함수만 검사"), `derive_models --stack-evidence`, `tools/
bundle_export/scan_stack_switches.py`. Core FString 템플릿을 v3 증거로 다시 파생(요약 동일, 가정에 보고 가정 포함).
사용자 결정(2026-10-13): 플러그인 자신의 증거가 없을 때도 가정은 **유지**(Bundle 함수 검사로 철회만 하고, "Bundle 함수만
검사"라고 범위를 출력).

### 24.2 DLL 연결 v1 구현 (2026-10-13, Fable·Astra 리뷰 2차까지)

**사용법**: `run_dfbench --link UNREALEDITOR-CORE.DLL=<DLL 경로> --ghidra-project <준비된 .gpr>` (`--link-cache`,
`--link-refresh`, `--link-dry-run`, `--link-folder`). 설명서: `tools/bundle_export/README.md`의 "Linking a run with the
libraries".

**구조**: `tdo_v2.linking.Linker`를 요약 엔진이 분석 직전에 한 번 부름(`analyze_frozen_bundle_with_summaries(linker=)`).
Ghidra 쪽은 `tools/bundle_export/link_provider.py`(준비된 프로젝트에서 내보내기·스택 검사만, import·분석 없음), 파생은
`derive_models.derive_library`.

**순서** (DLL마다):
1. 확인 — 모든 DLL을 먼저 확인한 뒤에 검사·파생 시작: DLL 파일의 PE machine이 실행 언어와 맞는지, 플러그인이 그
   DLL에서 가져오는 모든 이름(또는 `Ordinal_N`)이 DLL의 export 표에 있는지(`tdo_v2.pe_exports`). 아니면 오류로 멈춤.
2. 스택 전환 증거 — 연결되는 DLL은 항상 검사(DLL 빌드마다 한 번, 저장; 키 = DLL sha256 + Ghidra 버전·검사기 소스).
   증거 파일의 실행 파일 sha256이 DLL과 다르면 증거 아님. 어느 DLL이든 전환이 있으면 **파생 전에** 가정을 끔(그 실행에서
   철회될 가정에 기대는 템플릿을 만들지 않음). `--link-dry-run`은 이미 있는 검사만 씀.
3. 필요한 함수 = 플러그인이 실제로 부르는 import 중 그 DLL 것. 이미 모델이 있으면 그 모델(손 모델 먼저). data export·
   forwarder·서수 전용 export는 보고만(v1).
4. 저장본 찾기 — `<cache>/<LIB>/<DLL sha256>/<profile>/templates|refusals/`. profile = 엔진 버전, 언어·ABI, **실행 설정
   (home space, traps, globals-disjoint 실효값, direction-flag)**, p-code 모델, 손 모델 파일(id·digest), Ghidra 버전과
   내보내기·검사기 소스, 그 DLL 증거 파일의 digest(없으면 없음 — 나중에 깨끗한 검사가 생기면 다시 파생).
5. 없으면 파생 — Ghidra 내보내기는 **한 번에**(Ghidra 한 번 실행, 내부 손 모델에서 멈춤), 분석·템플릿은 **함수 하나씩**
   (`derive_library(per_export=True)`: 그 함수의 closure와 거기서 닿는 잘린 함수만). 그래서 템플릿이 같이 파생된 다른
   함수에 따라 달라지지 않음(Astra 반례: 다른 export가 섞이면 "tail exits not composed"가 풀리는 경우). 손 모델만 써서
   파생(파생에서 파생 금지), 실행의 p-code 모델·설정 그대로.
6. 거부 종류 — 파생이 그 함수에 대해 내린 판정은 종류와 함께 저장(같은 Bundle·profile이면 같은 결과): 의미(분석이 표현
   못 함), 예산(재귀 고정점 라운드 초과 — 라운드 수는 profile에 포함), 기반("not analyzed", Bundle에 없음). 종류는 문구가
   아니라 거부를 만든 곳에서 붙임(`TemplateRefused(kind)` → `summary_templates.Refusal`). 저장 안 함: 파생 실행 자체의 실패
   (Ghidra/내보내기 실패, Bundle sha 불일치, 한 함수 파생 중 예외) — 다음 실행에서 다시 시도. 새 결과는 이전 저장본을 대체
   (거부가 템플릿을, 템플릿이 거부를 지움). 저장한 템플릿 옆에 sha256 파일 — 손상·수정된 파일은 없는 것으로.
   `--link-refresh`는 그 DLL 빌드의 **모든 profile**의 저장본과 증거를 지우고 다시(다시 분석한 결과는 어느 설정의 저장본도
   바꿀 수 있음).
7. 적용 전 검사 — 최종 모델 묶음에 대해 엔진이 호출 지점에서 쓸 `summary_templates.refusal`과 꺼진 가정을 미리 확인,
   못 쓰는 템플릿은 `unusable`로 보고하고 빼냄(연결됐다고 말하지 않음). 실행 후 `[link] templates applied in this run:
   N of M`(실행 가정 목록의 `derived-model:link-...` 기준).
8. DLL 증거는 실행의 증거에 합류(같은 프로세스): 전환이면 실행 전체에서 가정 철회.

**엔진 수정**: `summary_templates.refusal`의 이름 겹침 검사를 lookup과 같게 — 라이브러리를 적은 파일끼리는 (라이브러리,
원래 이름)이 같을 때만 겹침(Astra: ONE.DLL!F 손 모델과 TWO.DLL!F 템플릿이 공존 가능). 라이브러리를 안 적은 파일은 이름의
앞 밑줄을 떼고 비교(lookup이 그렇게 찾음: X.DLL!_foo와 일반 모델 foo는 겹침).

**리뷰 1차 반영 (Fable P1 1·P2 9, Astra P1 3·P2 4)**: 실행 설정을 무시한 파생(가정을 끈 실행에서 템플릿이 전부 버려짐) →
실효 설정으로 파생·profile에 포함; refresh가 증거를 다시 검사하지 않음; 거부가 이전 템플릿을 지우지 않음; 거부만 있거나
손 모델만 있을 때 증거 누락; 묶음 파생의 결과 의존 → 함수별 분석; 예산·입장 실패가 의미 거부로 저장; 적용 전 확인 없음;
PE machine 미확인; 깨진 저장 파일에서 실행 중단 → 없는 것으로; 증거 키에 Ghidra 버전 없음; 다른 DLL 전환이 먼저 파생된
템플릿을 무효로 만듦 → 모든 DLL 증거를 먼저 봄. 남은 한계(설명서에 명시): 사용자 Ghidra 분석 자체는 키에 없음 — 다른
옵션으로 다시 분석했으면 `--link-refresh`.

**리뷰 2차 반영 (Fable P2 7, Astra P1 2·P2 4)**: refresh가 다른 profile의 옛 템플릿을 남김 → 빌드 전체 삭제; 밑줄 뗀
이름 겹침; 예산·기반 판정을 매 실행 다시 내보냄(78초) → 종류와 함께 저장, 재귀 라운드 수는 profile에; 문구로 종류 판단 →
kind; 서수 import가 이름 있는 export를 가리키면 파생되지만 적용 안 됨 → v1은 `ordinal`로 보고; dry-run이 증거 없이 다른
profile을 봄 → 저장본을 보지 않고 `pending`; dry-run이 증거 파일을 지움 → 안 지움; 입장 못 한 export 하나가 같은 묶음의
다른 함수를 실패시킴 → 함수별로 처리(그 함수만 `not analyzed`); p-code 모델 없음(None)을 기본값으로 바꿈 → 그대로;
구조가 깨진 저장 템플릿 → sha256 확인. 남은 P2(보고 요약 개선)는 다음에.

**검증**: 합성 테스트 `tests/intra/test_linking.py`(가짜 Ghidra; 확인·손 모델 우선·저장·거부 종류·profile 변화·refresh·
증거·적용 전 검사·엔진을 통한 끝-끝 적용 — 템플릿 결과가 같은 함수 몸체를 Bundle에 넣은 결과와 같음). UE Development
실제 실행: Core 호출 import 9개 중 손 모델 6, 파생 3(FString(), ~FString, AppendChar — 예전에 손으로 고른 셋과 같음);
첫 실행 241초(Core 스택 검사 146초 + 내보내기 78초, 49 파일), 다음 실행 10초(전부 저장본), 두 실행 모두 "적용 3/3".
함수별 파생의 요약은 예전 손으로 만든 파일과 **같고**, 가정 목록만 함수별로 줄어듦(3·5·10개, 묶음일 때 11개). 연결 실행의
결과(모든 root의 출처·완전성)는 예전 템플릿 파일을 쓴 실행과 **완전히 같음**, 지표도 같음(22건 중 exact+sure 14) — 템플릿이
없는 실행과도 같음(AppendChar의 index 쓰기 때문, 배열 단계에서 다룸).
