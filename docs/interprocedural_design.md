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

## 25. 배열 · index 주소 (2026-10-13 설계, Fable + Astra 2차까지; A단계 25.4, B단계 25.5)

### 25.1 진단 (UE Development, 실패 8건; `.census6/why_origin.py`로 root에서 금지 출처까지의 경로 추적)

| 케이스 | 원인 | 배열 문제? |
|---|---|---|
| R001 TArray 원소, R011 큰 원소 | 원소는 `Data+0`에 쓰고 `Data+0`에서 같은 레지스터로 읽음 — 배열은 정확. B는 **제어 의존**으로 들어옴: `check(Index < Num)` 실패 경로의 `mov rax,[__imp_?GIgnoreDebugger@@3_NA]; cmp byte [rax],0`. import 칸에서 읽은 포인터를 "어디든 가리킬 수 있음"(wild)으로 봐서 그 1바이트 읽기가 B를 담은 스택 칸과 겹칠 수 있다고 판단. 그 칸은 Core의 **데이터 export**(bool 변수) | 아님 |
| R002 TArray 잘못된 index | 위와 같은 제어 경로 + 두 번째 `Add`의 `Data + Num*8` 쓰기 | 일부 |
| R005 FString 버퍼 | AppendChar(Core, 연결 템플릿) 안의 `Data[Num] = c`가 index 쓰기 → 주소 없음 → 호출 전체가 "메모리 보존 안 함", A가 사라짐 | 예 |
| R009 TMap, R010 중첩 TArray | index 쓰기가 많은 컨테이너 코드 | 예(완성은 목표 아님) |
| R007, R008 포인터 사슬 | source 호출 뒤 포인터를 다시 읽음 | 아님(별도) |

현재 엔진(조사 결과): 주소 = 원자(atom)들의 선형식(계수·상수). INT_MULT·INT_LEFT·INT_SEXT·INT_ZEXT·SUBPIECE는 **상수끼리만** 접음 →
`base + idx*8`은 주소가 없음 → "어디든 쓸 수 있는 쓰기"(아무것도 덮어쓰지 못함, 뒤의 모든 읽기에 부채, 요약에서는
`preserves_memory=False`). index 값이 정확히 알려져 있어도 마찬가지. 구간·보폭·합동 분석은 없음.

### 25.2 결정된 설계 (순서 A → B → C → D → E → F)

**A. 검증기(oracle) 먼저.** 지금 요약 검증기(`summary_oracle.py:158`)와 프로그램 검증기(`program_oracle.py:92`)는 호출의
아무 메모리 run이나 "덮음"으로 받아들임 → 새 정확성 주장을 검사 못 함. 주장된 run의 실제 목적지 바이트·폭·시점을
실행 값으로 계산해 그 바이트가 그 안에 있는지 확인; 완전하다고 주장한 범위 밖의 쓰기 = 실패; "겹치지 않음" 주장 =
실제 겹침이 없어야 함. 엔진의 별칭 판정 코드를 검증기에 재사용하지 않음. 새 무작위 프로그램: 폭·확장·자르기·shift·
wrap(작은 폭은 전수 검사), 구조체 배열(보폭 8/12/16/24, 필드 일부), 같은 index 재사용 / 다시 읽기 / index 칸 덮어쓰기,
같아지는 인자, 한 그룹 안 여러 index 접근, 조건부·부분 쓰기, 요약(index를 먼저 바꿈, 목적지가 index 칸과 겹침, 다른
스냅샷의 두 호출), import(칸 변경 + 가정 끔), 모듈 경계 밖으로 나가는 상수 offset, Astra의 반례(상수 + 접근 폭이 2^64
근처에서 wrap). 결과 집계는 완료 / 지원 안 됨 / 조건부 건너뜀 / 가정 위반을 따로 셈.

**B. import 칸에서 읽은 포인터 (단계 0).**
- 새 등록 가정 `import-slots-hold-their-exports`(기본 켬, 끌 수 있음, 보고): 알아본 import 칸(`image_info.imports[*].slots`)을
  통째로 정확히 읽으면 그 import가 가리키는 주소가 들어 있고, 분석하는 실행 동안 칸은 바뀌지 않으며, 그 주소의 모듈은
  계속 적재돼 있음. 틀리는 경우: IAT hooking·Detours·패치, 해석 전의 delay-load 칸, 언로드, 실행 중 재해석.
  `readonly-image-data-is-constant`(import 칸을 제외함)와는 별개.
- 효과: `p = *칸`은 "어떤 적재된 모듈 이미지 안의 정적 저장소를 가리키는 주소"라는 새 주소 값. **새 주소 공간이 아님**,
  export끼리·모듈끼리 겹치지 않는다는 주장 없음(같은 주소의 export, forwarder). 모든 전역과 겹칠 수 있음. 스택과는
  `globals-disjoint-from-stack`(문장을 "다른 모듈 이미지의 정적 저장소"까지 넓히고 assumptions.md 재생성)으로만 분리,
  모델로 만든 새 블록과는 그 모델의 가정 아래 분리.
- 적용 범위: 접근하는 **모든 바이트가 이미지 안**임이 보일 때만. DLL 파일이 있으면(연결) export RVA가 든 section의 경계로
  확인; 없으면 export 주소의 1바이트 접근만. `*p`(내용)와 `p + index`는 이 성질이 없음. 코드 export도 같음(함수 바이트도
  이미지 안).
- 기대: R001·R011의 가짜 스택 별칭 제거(제어 의존 자체는 남고, 출처는 실제 전역).

**C. 보폭 있는 주소(단계 1, 안정된 값만, 새 가정 없음).**
1. 폭별 선형식: 식은 그 폭의 고리(mod 2^w)에서의 선형식. 더하기·빼기·상수 곱·상수 shift(p-code 규칙, 너무 큰 shift = 0)는
   식 안에 남음. 폭이 바뀌는 곳(SEXT, ZEXT, SUBPIECE, 출력 폭이 다른 곱·shift)에서 식이 끝나고 **경계 원자**가 됨: 키 =
   (정의 연산, 입력 정의, 입출력 폭, 종류). 범위는 실제 연산이 보장하는 것만: SEXT w비트 → [-2^(w-1), 2^(w-1)-1], ZEXT →
   [0, 2^w-1], SUBPIECE는 추출(offset 포함) 규칙, 그 밖은 불투명(범위 없음). 상수가 아닌 배율 → 주소 없음(지금처럼).
2. 원자 규율: 경계 원자는 정의 원자와 같은 규칙 — 활성화당 한 번 실행되는 정의만(순환 안의 값 = 루프 변수는 이번
   단계에서 **주소 없음 그대로**), 입력 읽기가 미정·막힘이면 거부, 첫 고정점 뒤에만 켬. 메모리 읽기에서 온 사실(두 index
   값이 같음, 원자의 정체)로 별칭을 배제하거나 효과를 인정했으면 그 사실도 오래된 읽기 검사로 다시 확인하고, 틀리면
   그 판정에 기댄 결과를 다시 만듦. 종료: 무효가 된 의존은 그 분석 동안 영구히 막고, 반복 한도를 넘으면 보수적으로.
3. 접근 설명 + 관계(새 "객체"를 만들지 않음): 해결된 접근 = (주소 공간, 64비트 주소 전체의 선형식, 바이트 크기, 원자들의
   값 정체). 계수 1인 비경계 원자 = **비교용 그룹**일 뿐(소유 관계의 증거 아님). 두 접근의 관계:
   - `exact(d)`: 차이가 상수 d(같은 원자·같은 계수·같은 값 정체), d는 mod 2^64로 해석; wrap하는 바이트 범위는 나누거나
     보수적으로.
   - `disjoint`(겹치지 않음) 증명 두 가지:
     (i) 합동: g = gcd(2^64, 상쇄되지 않은 모든 계수). 겹침 창 W = [-(s1-1), s2-1] 안에 (c1-c2)와 mod g로 같은 값이
     없으면 겹치지 않음.
     (ii) 구간(Astra 공식): 차이 전체(상수 포함)의 정수 구간 [A, B]를 큰 정수로 계산(각 항: 계수 × 범위 양 끝의 최소·최대)
     하고, ⌈(A − W_max)/M⌉ > ⌊(B − W_min)/M⌋ (M = 2^64)이면 모든 wrap 위치에서 겹치지 않음. 크기 제한 조건 필요 없음.
     (Fable의 "|k|·범위 < 2^63" 조건은 빠른 판정용으로만.) 둘 다 아니면 `may`(겹칠 수 있음).
   - x86-32는 M = 2^32로 매개변수화(또는 이번 단계는 64비트 바이트 주소 공간만).
4. 메모리 의미: **index 쓰기는 덮어쓰기(kill) 없이 "겹칠 수 있는 곳에 추가"만**(strong update는 이번 단계에서 뺌 — 두
   리뷰 합의; 실패 케이스에 필요 없음). `relative_memory.py:338`에서 확정 SSA 쓰기를 만들지 않음. 정확한 쓰기 ↔ index
   읽기도 `disjoint`가 아니면 전달(Fable P1-4). 같은 그룹이라는 이유만으로 기존 "같은 객체 = 바이트 정확" 지름길
   (`may_alias.py:187`, 객체 2개 미만 조기 반환, `call_summary_effects.py:243`의 객체 소속 인정)을 쓰지 않음 — 모두 관계로.
   어디든 쓰는 쓰기·불확실 쓰기는 그대로.
5. 스택 기반 index(`rsp + 8*i`)는 이번 단계에서 **주소 없음 그대로**(프레임 안에 있다는 증명이 없음; 스택 유래 추적은 계속).
   같은 할당의 두 view는 서로 "다른 새 블록"으로 보지 않음.

**D. 요약·템플릿의 index(단계 3, 입구 값으로 표현되는 것만).**
- callee의 index 쓰기를 run으로 만드는 조건: base와 index 모두 **입구 값**(입구 레지스터, 입구 메모리 칸 — 다른 효과보다
  먼저 읽는 입구 스냅샷으로)의 식으로 callee 자신의 데이터 흐름이 증명. 예: `++self->Num; self->Data[self->Num] = A`는
  index = sext32(Num_입구 + 1)이지 Num_입구가 아님. 아니면 지금처럼 어디든 쓰는 쓰기.
- 저장 형식: `index: [{coefficient, extend: {kind, from_width}, form: {입구 칸들의 선형식, 상수}}]`, 확장 한 단계만;
  form은 mod 2^from_width로 계산 → 확장 → 주소 고리에서 계수 적용. 템플릿은 ImageBaseTracking 검사(index 식에 적재
  주소에 따라 바뀌는 상수 금지). 템플릿·캐시 profile 버전 올림, 왕복·재배치 테스트.
- 호출 지점: index 식을 그 호출 활성화의 호출 전 값에 묶음(두 호출이 같은 템플릿 칸을 써도 정체 공유 안 함), 묶은 뒤
  목적지 겹침·작성자 조건 다시 확인, 행 순서가 실행 순서를 만들지 않음.
- `preserves_memory` 계약(Astra 문안): 요약된 출구로 돌아오는 모든 실행에서, 호출자가 볼 수 있는 모든 메모리 효과가
  run(정확·index)·위치가 정해진 미상 값 효과·스택 효과로 덮이고, 각 효과는 가능한 값·출처를 보수적으로 담음. 그 밖의
  메모리 변경은 없음. → 호출자의 바이트는 모든 효과와 겹치지 않음이 증명될 때만 보존; 겹칠 수 있는 index run은 출처를
  더하고 옛 값도 남김. 범위가 넓어도(모든 객체와 겹칠 수 있어도) 완전하면 됨. 그래서 **D는 E 없이 가능**(Fable도 동의).
  R005: A가 `S[0]`의 가능한 출처로 돌아옴(확실은 아님). AppendChar의 성장·Data 교체·내부 호출이 모두 덮여야 완전.

**E. 소유 객체 안에 머무름(단계 2, 선택 가정, 기본 끔).** `indexed-access-stays-in-object`: 소유자가 **명시적으로 확인된**
(지금은 할당 모델의 새 블록만) base의 index 접근은 모든 바이트가 그 살아 있는 할당 안. 소유자는 모델에서만, 계수에서
추론하지 않음. 켬/끔 측정 후 확대. Fable 주의: base가 메모리에서 읽은 포인터(wild)면 효과가 작음 — 측정 먼저.

**F. 나중.** index 쓰기의 strong update(별도의 "확정 쓰기" 능력: 실행당 한 주소, 검증된 base·index, 정확한 바이트 덮음,
실행 확정, 조건·불확실성 없음, 별칭 전파·롤백), 루프 index(유한 may-footprint), index 값 분석(R002용 작은 상수 대입은
먼저 가능), realloc 내용 보존, TMap 등 컨테이너(완성은 목표 아님). R007·R008은 배열과 별개.

### 25.3 리뷰 기록
1차: Fable(P0 없음, P1 6 — 칸 무결성, 새 객체 종류, 원자 규율, 양방향 전달, 2 먼저, wild base 효과 작음), Astra(P0 9 —
mod 2^64 wrap, 폭 경계, 그룹 ≠ 소유, (O,T) 객체 대신 접근 관계, 같은 할당 view의 fresh 분리 오류, strong update 조건과
`relative_memory.py:338`, 오래된 읽기 규율, 입구 스냅샷 vs 나중 읽기, 검증기 빈틈). 2차(서로의 답을 읽고): Fable은 Astra
15개 모두 동의(모듈별 분리 주장 철회, D가 E보다 먼저 가능 인정), strong update 제외; Astra는 구간 조건 반례(상수 + 접근 폭,
2^63 근처)를 내고 [A,B] 번역 창 공식으로 대체(작은 폭 161,280건 검사, 거짓 분리 0), `p + 상수`의 이미지 포함 유지 반대,
스택 index 보류, 기존 지름길 3곳. 기록: `.census6/design_array_{prompt,prompt2,fable,astra,2_fable,2_astra}.md`.

### 25.4 A단계(검증기 보강) 구현 (2026-10-13, Fable 3차 · Astra 4차 승인)

**왜**: 요약 검증기는 "그 명령이 쓴다고 적힌 run이 있는가"만, 프로그램 검증기는 "그 호출의 아무 메모리 run에 닿는가"만 봐서,
run의 **위치**가 틀린 요약도 통과할 수 있었음(위치를 8바이트 옮긴 요약을 옛 검증기는 둘 다 통과시킴 — 테스트로 확인).

**바뀐 점** (`tests/intra/pcode_interpreter.py`, `program_oracle.py`, `summary_oracle.py`, `tools/graph_fidelity/measure_program.py`):
- 실행기: 바깥쪽 호출마다 **callee 입구 시점**(반환 주소 push 뒤)의 값 스냅샷, 각 바이트를 쓴 활성화 번호, 읽기마다 쓴 호출별
  활성화 집합, 다른 호출의 입력 꼬리표에도 활성화 번호, 주소는 공간의 **선언 폭**으로 wrap(Bundle 증거; 기본 64비트), 활성화별
  최저 스택 포인터, 쓴 바이트 목록(footprint), realloc으로 옮겨진 바이트의 원래 자리, 값을 되돌려 쓴 바이트의 이전 상태 복원.
- 프로그램 검증기: 호출이 쓴 바이트는 그 활성화 시점으로 계산한 run 위치 안에 있어야 함(앞선 호출의 입력, `~u` 행도); 위치가 안
  맞으면 **그 호출**을 이름 붙인 clobber 부채·주소 미상·그 호출의 open_condition만 인정(호출 노드에 닿는 것만으론 안 됨);
  `preserves_memory` 호출은 쓴 모든 바이트가 run/`unknown_memory` 위치 안이어야 함(자기 프레임·반환 주소·home space·할당
  모델이 옮기거나 해제한 바이트 제외).
- 요약 검증기: 메모리 바이트는 그 writer run의 위치(입구 값으로 계산; 레지스터 기준, 포인터 2단계, 변위는 상수 + 실제로 읽은
  입구 칸에서)가 담아야 함; UNKNOWN 대체도 위치 확인; writer 조건 겹침도 wrap.
- 집계: place_checked / covered / unlocated_only / failed / failed_debt / no_activation, footprint_checked / unlocated.

**결과**: 테스트 668개(새 위치 테스트 20개: ±1·±8·16 이동, 스택 포인터 기준, 앞선 호출 입력, footprint, wrap, 되돌려 쓰기,
home space 경계, 합성 변위, wrap 걸친 포인터, realloc 이동, 선언 폭). 실제 Bundle: 누락 0(zlib 기존 256 제외), 설명 안 됨
0/0/0/DebugGame 1227/0 — **DebugGame은 옛 검증기와 같은 집합(차이 0)**, 위치 확인 09 debug 320/320 · release 224/224 ·
win32 160/160 · UE Dev 568(400 담음, 168 부채) · DebugGame 1063(614 담음), 위치 미상만인 경우 0, footprint 위반 0.
→ **지금까지의 "동작함" 판정은 더 강한 기준에서도 그대로**. 리뷰 중 검증기 자체의 오류 3개(스냅샷 시점 −8, 외부 호출 push
슬롯, 피연산자 폭)를 찾아 고침(그 사이 거짓 경보가 테스트·Bundle에서 드러남).

**남긴 것**: C 시작 때 — 모듈러 exact/disjoint 기준 검사기, 작은 폭 전수 산술; B 동안 — import 칸 테스트; 스냅샷 비용(차분 저장),
요약 위치 미상 72바이트 목록(C 전에 0으로), `_Locator`의 8바이트 포인터 가정(32비트 요약 전).

### 25.5 B단계(import 칸 포인터) 구현 (2026-10-13, Fable 2차 · Astra 3차 승인)

- 새 등록 가정 `import-slots-hold-their-exports`(기본 켬, `--no-assume-import-slots`): import 칸(IAT)을 포인터 폭으로
  통째로 읽은 값(그 칸에 대해 함수 안에서 쓰기가 없는 ENTRY 값)은 그 import가 가리키는 주소. import마다 원자 하나(라이브러리
  + 이름으로 키 — 적재 주소와 무관, 같은 import의 두 칸은 같은 원자). 그 주소 **바로 그 1바이트**(변위 0, 적재 주소와 무관한
  변위)는 이미지 안 정적 데이터 → `globals-disjoint-from-stack`가 켜진 실행에서 스택과 겹치지 않음(nonstack 객체), private
  frame에도 닿지 않음. 더 넓은 접근·다른 변위·새 블록·다른 import와의 분리는 주장하지 않음(export 크기 근거 없음, forwarder).
- `relative_memory.IMPORT_SLOTS`(분석 1회 동안의 ContextVar), `import_object_ids`(import 원자 위 두 객체: 그 바이트 / 그 밖),
  `interprocedural._relative_anchors`가 두 객체를 칸에 anchor(포인터 폭 읽기만) — callee가 import 포인터로 쓴 run을 호출자가
  계속 찾음. 보고: `NormalizedFunction.assumes_import_slots_hold_exports`, 실행 가정 목록. 연결 profile·파생에도 실효값.
- 리뷰 반영: anchor 퇴행(Fable P1), 적재 주소 추적 우회(Astra P1 — 적재 주소에 따라 바뀌는 변위는 제외), 폭 제한(1바이트),
  폭이 다른 두 읽기 중 좁은 것이 anchor 되는 문제(Astra P1), 모델 없을 때 image_info 미전달(P2), 새 블록 분리 주장 삭제.
- 결과: 테스트 681개(새 13개), 지표 기준선과 같음(09 64/60·52/47·44/37, UE DebugGame 13/13, Dev 14/14), 동적 누락 0(zlib 기존 256).
- **정정**: root 출처는 데이터 의존만으로 계산함(`observed_slice` → `BackwardSliceQuery`, 제어 의존 제외). 진단 스크립트가 제어
  간선까지 따라가서 R001의 B가 GIgnoreDebugger 경로로 들어온다고 봤으나, 지표의 B는 **byte lane** 경로: 원소 `It`(A·B 8바이트)를
  64비트 레지스터 하나로 복사 → 그 4바이트만 읽어도 레지스터 값 노드 전체(B 포함)에 닿음. B단계는 올바른 별칭 정리지만 R001
  지표는 바꾸지 않음. 다음: **B2 byte lane 단계**(C 전에, 두 리뷰 권고).

### 25.6 B2a단계(byte lane을 따르는 root 출처) 구현 (2026-10-14, Fable · Astra 리뷰)

- 문제(25.5 정정): 8바이트 레지스터 하나에 A·B를 함께 담고 그중 4바이트(A)만 sink에 넘겨도, 기존 슬라이스는 값 노드 단위라
  B까지 출처로 잡음. B2a는 **root 출처 라벨만** 바이트 단위로 좁힘. 완전성 판정·노드 슬라이스·요약은 그대로(B2a′/B2b에서).
- `src/tdo_v2/lane_slice.py`: 기존 의존 그래프 위를 거꾸로 따라가며 노드마다 "필요한 바이트"를 들고 감. 정의 노드는 저장소의
  절대 바이트, 연산 노드는 결과 바이트 번호, `FULL`(전부)은 흡수. 정확한 바이트 대응은 리틀 엔디언(`language_id`의 `:LE:`)이고
  모양(입력 개수·폭)이 맞을 때만: COPY/INT_NEGATE, LOAD(+주소 전부), STORE(+주소 전부), 상수 SUBPIECE, PIECE, ZEXT,
  SEXT(맨 위 바이트는 전부), AND/OR/XOR 바이트별. 그 밖의 연산·호출·빚(debt)·알 수 없는 간선은 전부 FULL(보수적).
  JOIN: 필요한 바이트를 덮지 못하는 바이트가 있거나 다른 객체의 소스가 있으면 모든 소스 FULL.
  seed: sink 행의 선택자 span이 정의와 같은 객체이고 겹칠 때만 그 바이트, 아니면 FULL(x86-32에서 스택 칸 선택자 vs 임시
  정의 → 빈 요구로 출처를 다 잃던 문제 수정, 회귀 테스트).
- `summary_engine._raw_root_groups`: root를 raw sink 행 (label, occurrence)마다 그 occurrence의 **모든** 노드로 만듦. 정규화
  (`(kind, label, node)`마다 한 행)는 다른 occurrence가 이미 묶은 노드의 행을 지움 — 그룹 전체든 일부든(Astra 2차 P1: occ0이 A,
  occ1이 A+B면 occ1은 B만 남아 A의 출처를 잃던 문제, B2a 이전부터 있던 것). 빠진 노드는 다른 root의 같은 노드 슬라이스를 재사용,
  없으면 노드 질의(라벨은 닿은 SOURCE 행). 노드가 보충된 그룹 수 = `LANE_DIAGNOSTICS["restored"]`. 회귀 테스트. lane 결과는 노드 결과의 부분집합이어야 하며 아니면 노드 결과로 되돌림
  (`not_subset`, 현재 0). SOURCE 행의 span은 그 노드 자신의 정의와 같은 객체일 때만 바이트로, 아니면 span 없음(닿으면 셈).
  끄기: `TDO_V2_LANE_ORIGINS=0`.
- 검증기(`tests/intra/lane_oracle.py`): 바이트마다 출처 집합을 들고 실제 실행. 함수 자신의 연산 결과·STORE 대상 바이트를 seed로
  `lane_slice` 결과와 비교. 진입 레지스터 바이트·전역 바이트는 정확히, 진입 레지스터 기준 상대 객체는 그 레지스터의 실행 값으로
  주소를 맞춰 정확히. 함수 자신의 호출이 쓴 레지스터 바이트는 그 호출 행이 쓴 정의에서 그 바이트가 요구되어야 함.
  분류 불가(통과로 치지 않음): 빚에 닿음, 위치를 못 맞춘 상대 객체, 호출이 쓴 메모리, 실행 중 할당된 블록의 안 쓴 바이트
  (할당 호출의 내용). callee 안에서 중첩 호출이 쓴 바이트는 활성 동안 `nested`로 표시하고, 바깥 호출이 반환할 때 그 활성이
  남긴 바이트마다 **현재 위치**의 `("call", 바깥 호출, 위치)`로 다시 붙임(callee가 rax→rbx로 옮겼으면 rbx) → 정확한 레지스터
  바이트 검사가 그대로 적용(Fable·Astra 2차 P1: "바깥 호출의 정의 중 하나에 닿으면 통과"는 틀린 바이트 대응을 숨겼음 — 회귀
  테스트가 caller COPY 1바이트 이동을 잡음). 다시 붙지 못한 `nested`(모델이 옮긴 바이트)는 분류 불가.
  callee가 push/pop으로 되돌린 레지스터(인터프리터가 출처로 "호출 전 값 그대로"라고 복원하는 바이트 — 프로그램 검증기와 같은
  규칙)는 호출 전 lane으로 복원(push/pop의 스택 주소는 값의 출처가 아님; UE Dev 2,656건 오탐 수정, 회귀 테스트).
  rep 문자열 지점·callee 활성 안 연산은 실행마다 비교 안 함.
  변이 검사(무작위 함수 60개): 변이 없음 0 / LOAD 메모리 1바이트 회전 34,538 / STORE 값 이동 2,658 / SUBPIECE-1 3,013 /
  COPY 이동 54,720 / LOAD 주소 빠짐 283,070 / ZEXT 빠짐 2,035 — 모두 잡힘.
  Bundle lane 검증기(`.census6/run19.sh`): 09 debug·release·win32·UE DebugGame·UE Dev·zlib 모두 lane_missing 0, nested 0,
  not_subset 0.
- root 수준 검증(`.census6/root_lane_oracle.py`): 모든 Bundle 함수를 실제로 실행, source 호출이 반환할 때 rax에 라벨을 붙이고,
  함수 자신의 sink 호출 시점에 선택자 바이트 출처의 라벨이 엔진 출처 안에 있어야 함. 09 debug sink 실행 295·라벨 64·위반 1
  (DFB064 간접 재귀, root가 unsure로 보고되는 기존 한계 — lane 끈 상태와 같음), release 28/4/0, UE DebugGame 76/17/0,
  UE Dev 24/1/0. lane 켬/끔 결과 같음.
- 사례별(raw occurrence 단위, `.census6/run20.sh`): 기대 출처를 잃은 것 0, 넓어진 것 0, root 누락 0. 사라진 것은 금지 출처 B뿐
  (09 debug DFB046 occ2, UE DebugGame TV2R004 occ2 · TV2R001 occ7, UE Dev TV2R001 · TV2R011 occ5).
  지표: 09 debug 65/61(전 64/60), UE DebugGame 15/15(13/13), UE Dev 16/16(14/14), release·win32 그대로.
- B2a′(lane 단위 완전성)는 구현 전에 효과를 측정: 불완전한 root 중 "닿는 미해결 읽기 때문에만" 불완전하고 lane 슬라이스는
  그 읽기를 하나도 안 지나는 것 = 모든 Bundle에서 0(09 debug 12개 중 0, release 8개 중 0, UE DebugGame 5개 중 0, Dev 3개 중 0;
  `.census6/diag_lane_completeness.py`) → 보류.
- 알려진 한계: 완전성 판정은 노드 단위, 요약 경계를 넘는 lane은 FULL(B2b), 빅 엔디언은 전부 FULL, 검증기의 호출 메모리·할당
  블록 내용·다시 붙지 못한 중첩 호출 바이트는 분류 불가로만 셈, root 수준 검증기는 occurrence를 합쳐서 비교.
- 리뷰: Fable 1·2·3차, Astra 1·2·3차(`.census6/lanes_impl*_{fable,astra}.md`).

### 25.7 스택 주소에 다른 값을 섞은 주소 (2026-10-14, 기존 결함 수정, Fable 2차 · Astra 2차 승인)

- 발견: C단계 준비로 주소 원자 사용처를 조사하다 찾음(B2a 이전부터 있던 결함). `rsp + rdi`, `rdi + rsp`, `rsp - rdi`, `2*rsp`,
  `rbp = rsp; rbp + rdi`처럼 진입 스택 포인터 원자에 다른 원자가 섞인 주소는 원자 묶음의 해시로 보통 FUNCTION_RELATIVE 객체가
  됨(계수·원자 수 검사 없음). may-alias의 private frame 규칙("스택 값이 새기 전에는 **다른 기준**으로 이 함수의 새 프레임에 닿을
  수 없음")이 이 객체를 다른 기준으로 봐서, `[rsp+0x10]=rsi; [rsp+rdi]=rdx; rax=[rsp+0x10]`에서 rax ← {rsi}만, **완전**으로
  보고(rdi = 0x10이면 rdx). 읽기 방향도 같음. 무작위 레지스터 값으로는 충돌이 거의 안 나서 동적 검증기가 못 잡았음.
- 수정(`relative_memory`): 투영기가 may-alias 정책과 같은 스택 포인터(`may_alias._stack_pointer`)를 알고, 스택에서 온 원자 =
  스택 포인터와 겹치는 레지스터 범위의 진입 원자(폭 무관 — 원자를 만들 때 겹침으로 분류, 미리 나열한 목록도 함께), 그리고 그런
  입력으로 만든 opaque 원자(전이적). 원자 묶음이 정확히 `((스택 원자, 1),)`(스택 객체 자신)가 아니면서 스택에서 온 원자를 가진
  객체는 **wild**(기준이 어디든 가리킬 수 있음 — private frame 포함; 메모리에서 읽은 포인터·호출 결과와 같은 분류).
  wild가 맞는 이유: `rsp + rdi`는 rdi가 무엇이든 될 수 있어 프레임·호출자 프레임·전역·힙 어디든 닿음 — 더 좁은 분류는 index
  범위 근거(E단계)가 필요.
- 요약: 호출된 함수의 `rsp + rdi` 객체는 원래도 anchor가 안 돼 `preserves_memory`가 거짓이었음(변화 없음, 테스트로 고정).
- 결과: 테스트 13개(수정 없이 10개 실패, 대조 3개는 양쪽 통과; 방향 지정 실행 rdi = 0x10 포함), Bundle 동적 검증기 그대로,
  지표 그대로(정밀도 손실 없음).
- C단계에 주는 제약: 스택에서 온 주소는 세 종류 — 스택 객체(정확), wild(섞인 주소·opaque), 주소 없음(어디든 쓰기).
  `rsp + 8*i` 같은 스택 index는 E단계 전까지 wild(또는 주소 없음)로 둠(25.2 C.5와 같음).

### 25.8 C1단계: index 주소 (2026-10-14, 설계 검토 Fable·Astra 2차, 구현 리뷰 Fable·Astra 2차)

25.2 C의 가장 작은 쓸모 있는 부분. 기록: `.census6/step_c1_{prompt,prompt2,fable,astra,2_fable,2_astra}.md`, `wt_c1/.census6/c1_impl*`.

- **배율**: 원자가 있는 식에 상수를 곱하거나(INT_MULT) 상수만큼 왼쪽 shift(INT_LEFT; 폭 이상 shift = 0, p-code 규칙)하면 모든
  계수와 변위를 그 폭의 고리(mod 2^(8·폭))에서 곱함. 계수가 0이 되면 그 원자는 빠짐. 계수는 부호 있는 대표값으로 정규화.
- **경계 원자**: 원자가 있는 식의 INT_SEXT / INT_ZEXT → 새 원자. 키 = (종류, 입력 폭, 출력 폭, 입력 식의 원자 묶음(계수 포함),
  입력 변위; 연산 key는 넣지 않음 — 넣으면 같은 식의 정확한 관계를 잃음). 입력 식의 결정적 함수라 입력 원자가 한 값이면 한 값; 같은 식을 두 번 확장해도 같은 원자(a[i]와 a[i]가 정확히
  같은 곳). 범위(SEXT: [-2^(w-1), 2^(w-1)-1], ZEXT: [0, 2^w-1])는 C2용으로 저장만. 입력이 적재 주소에 따라 움직일 수 있으면
  (image ≠ 0) 거부. 원자는 식과 함께 매번 다시 계산되고 따로 저장되지 않음 → 입력 읽기가 오래된 읽기 검사로 막히면 식이
  없어지고 쓰기는 다시 "주소 없음", 다시 만든 SSA에서 앞의 덮어쓰기도 사라짐(입력 원자는 기존 규율: 진입·import 원자, 한 번만
  실행되는 정의의 정의 원자(첫 고정점 뒤, 미정·막힘 아님), 그런 입력의 opaque 원자).
- **객체 = 원자 묶음**(기존 구조 그대로, 25.2 C.3/C.4에서 바뀐 점 — 두 검토 확인): 원자 묶음(계수 포함)이 같은 두 접근은 매 실행
  상수만큼 차이 = `Exact(d)` → 바이트 정확, 덮어쓰기(strong update) 유효(모든 원자가 활성화당 한 값이므로). 묶음이 다르면
  겹칠 수 있음(덮어쓰기 없음) — "index 쓰기는 덮어쓰지 않음"(C.4)은 증명된 같은 주소를 뺀 모든 경우에 그대로. `DISJOINT`
  증명(다른 index의 필드 분리 등)은 C2(`index_relation`).
- **wild**: 경계 원자가 있거나 계수가 1이 아닌 원자가 있는 객체(index 객체; 전에는 보통 객체였던 `rdi - rsi`, `2*rdi`도 —
  더 보수적)는 wild — private frame에 닿을 수
  있음. 이유(Astra 반례): 진입 rdi = 진입 sp + 8(호출자 프레임 포인터), esi = -7이면 `rdi + 8*sext(esi)`가 이 함수의 새 프레임
  칸. 스택 index(`rsp + 8*i`)도 wild(C.5의 "주소 없음" 대신 — 별칭에서는 적어도 같은 만큼 보수적). opaque 연산은 입력의
  분류를 이어받음: 입력에 wild·경계·배율 원자가 있으면 opaque 원자도 wild(Astra 구현 1차 P1 — `(zext(edi) & mask) - 16`이
  wild를 잃던 문제), 스택에서 온 입력이면 스택에서 온 원자.
- **wrap 경계(기존 결함 수정, 모든 상대 객체)**: 상대 접근의 최종 변위 d(주소 폭 b비트의 부호 있는 값)가 |d| ≥ 2^(b-2)이면
  주소 없음. 그러면 같은 묶음의 두 접근은 변위 차이가 고리의 절반보다 작아 직선 span 비교 = mod 2^b 비교(Astra 반례: 변위
  2^63-1의 2바이트 쓰기와 -2^63의 1바이트 읽기는 mod 2^64로 겹치는데 span으로는 떨어져 있었음). `project_access`·
  `project_anchored`(덧붙는 변위 포함) 둘 다.
- 캐시: `ENGINE_SEMANTICS_VERSION` 1 → 2(25.7 + C1 — 전에 만든 템플릿은 다시 만들어야 함), 연결 profile·`derive_models`
  producer에 `index_addresses` 기록. `models/derived/ue_core_win64_fstring.json`을 이 엔진으로 다시 만듦(같은 Core Bundle·스택
  증거; 요약 3개는 바이트 단위로 같고 버전 정보만 바뀜, 모델 버전 2).
- 진단: `[run] index addresses (docs 25.8): on, index objects N, seam refusals M`(실행마다 초기화).
- 결과: 테스트 753개(새 18개: 같은 원소 덮어쓰기, 한 원소의 두 필드 분리, 다른 index는 겹칠 수 있음, 원소 쓰기가 포인터 칸에
  닿을 수 있음, 두 반례(방향 지정 실행 포함), 32/64비트 경계, 루프 index는 주소 없음, 배율 소거·wrap, 폭 이상 shift, 스위치
  끔, opaque wild, 오래된 index 재읽기, 무작위 index 함수 180개 × 6실행 graph 검증기 누락 0, "묶음 합치기" 변이 잡힘).
  Bundle: 지표 켬/끔 동일(09 debug 65/61, release 52/47, win32 44/37, UE DebugGame 15/15, UE Dev 16/16); index 객체 09 0개·
  release 0·win32 1·UE 5·5, wrap 경계 거부 0; 프로그램 검증기·lane 검증기 그대로(누락 0). → 건전하지만 지금 Bundle에는 거의
  영향 없음: 의미 있는 index 쓰기는 루프 변수이거나 호출된 함수 안(D단계)에 있음.
- 끄기: `TDO_V2_INDEX_ADDRESSES=0`(배율·경계 원자만 끔; wrap 경계와 wild 규칙은 항상 — "끔" = 고친 기준선). 가정 아님
  (정확한 산술 + 기존 원자 규율).
- 남은 일: 호출된 함수의 index 쓰기는 여전히 anchor 안 됨 → `preserves_memory` 거짓(D단계), DISJOINT(C2), SUBPIECE 경계 원자 없음.
- 별도 단계(검토 2명 동의, 사용자 확인 필요): 지금의 private frame 규칙은 **등록 안 된 가정** — "진입 값(진입 레지스터·진입 메모리·
  상수만으로 계산한 값)으로 만든 접근의 바이트는, 스택 값이 새기 전에는 이 함수의 새 프레임과 겹치지 않음". `rdi - 16`(rdi가
  호출자 프레임 바로 위를 가리킬 때)도 같은 반례. `entry-values-do-not-address-the-new-frame`(스위치, 기본 켬, 끄면 스택이 아닌
  모든 상대 객체가 private frame에 대해 wild)로 등록·보고 예정.

### 25.9 private frame 규칙을 가정으로 등록 (2026-10-14, 설계 검토 Fable·Astra)

- 왜: C1 검토에서 Astra의 반례 — 진입 rdi = 진입 sp + 8(호출자 프레임 안 포인터)이면 `rdi - 0x38`이 이 함수의 새 프레임 칸.
  지금까지 private frame 규칙(`may_alias._Policy.is_private`: 진입 sp 아래 바이트는 스택 값이 새기 전에는 다른 기준으로 닿지
  않음)은 증명으로 취급됐지만 실제로는 **가정**이었음(등록된 것은 win64 home space 확장뿐).
- 등록: `entry-values-do-not-address-the-new-frame`(스위치, 기본 켬; `--no-assume-entry-values-not-frame`,
  `TDO_V2_ASSUME_ENTRY_VALUES_NOT_FRAME=0`). 내용: 스택이 아닌 진입 레지스터 값·진입 메모리 값·상수만으로 계산한 주소(어떤
  산술·변위·폭 변화든)의 접근 바이트는, 스택 값이 새기 전에는 이 함수의 새 프레임과 겹치지 않음. 프레임에서 빠지는 기준 네
  종류 중 이 가정이 맡는 것은 진입 값 산술뿐(상수·import → globals-disjoint / import-slots, 새 블록 → 할당 모델, nonstack →
  callee 요약). wild 기준(읽은 포인터·호출 결과·index·스택 섞인 주소)은 언제나 프레임에 닿음. 틀리는 경우: 호출자가 준
  포인터를 호출자 프레임 바닥 아래로 옮기거나 index(버퍼 underflow, alloca 옆 산술), 인자·TLS로 프레임 주소를 계산하는 손 코드,
  context record로 callee 프레임을 쓰는 unwind handler.
- 끄면: private 바이트 없음(`escape = None`) — 다른 제외(globals-disjoint, 새 블록, nonstack)는 그대로. win64 home space는 이
  가정의 확장이라 이것이 꺼지면 효과도 보고도 없음.
- **사용할 때만 보고**(Fable P2-1): `is_private`가 어떤 바이트를 private로 판정한 함수만 `assumes_entry_values_not_frame` →
  실행 가정 목록. 그래서 이 규칙을 한 번도 쓰지 않은 템플릿은 이 가정을 끈 실행에서도 적용됨. `win64-home-space-callee-private`도
  이제 이것과 함께 사용할 때만 보고(전에는 "켜져 있으면 항상"). 예전 엔진 경로(`--legacy-engine`)는 스위치를 넘기지 않아 늘 켬.
- 템플릿 호환(Astra 구현 1·2차): 이 가정을 끄면 home space 확장도 모든 곳에서 0(요약 엔진·연결 profile·`derive_library`·
  linker 사전 검사). 템플릿의 `private_frame_above`는 그 템플릿이 `win64-home-space-callee-private`에 기댈 때(표시가 있을 때)만
  이 실행과 같아야 함 — 기대지 않은 템플릿은 어떤 home space에서도 적용. 꺼진 가정에 기댄 모델은 거부 이유를 기록
  (`refused_models`: "rests on ..., switched off in this run").
- 연결: `may_alias.ENTRY_VALUES_NOT_FRAME`(ContextVar, 기본 켬 — 직접 호출하는 도구·테스트는 지금과 같음),
  `interprocedural.analyze_units(assume_entry_values_not_frame=...)`가 실행마다 설정하고 끝나면 되돌림; 꺼진 가정 목록
  (`disabled`)에 들어가 그 가정에 기댄 모델은 쓰지 않음; 요약 엔진·`run_dfbench`(레지스트리에서 자동)·연결 profile·
  `derive_models`. `ENGINE_SEMANTICS_VERSION` 2 → 3(Astra P1: 예전 템플릿은 이 가정에 기대면서 표시가 없음 → 모두 다시 만들어야
  함). `models/derived/ue_core_win64_fstring.json` 다시 만듦(요약 3개 그대로, 출처 가정 목록에 이 이름 추가).
- 테스트(`test_frame_assumption.py`): 켬 — 반례에서 프레임 다시 읽기는 완전·쓰기 값 없음, 가정 보고, 방향 지정 실행은 실제로
  놓침(가정이 틀리는 경우를 고정); 끔 — 쓰기 값이 출처·불완전, 보고 없음(home space도), 방향 지정 실행 누락 0; 실행 뒤 스위치
  복구; 프레임을 안 쓰는 함수는 보고 안 함; 끈 상태에서도 callee 자기 프레임 쓰기는 호출자 메모리 보존(구조적 규칙).
- 결과: 테스트 758개. 켬(기본) = 지표 그대로, 모든 Bundle에서 이 가정이 실제로 쓰여 보고됨. 끔(가정의 무게): 09 debug
  65/61 → 65/58, release 그대로, win32 44/37 → 41/30, UE DebugGame 15/15 → 13/13, UE Dev 그대로; 모든 경우 "확실한데 놓침" 0.

### 25.10 D단계 전 진단: R005(FString::AppendChar)는 승인된 D로 안 풀림 (2026-10-14, Fable·Astra 의견 — 사용자 결정 필요)

진단(`.census6/diag_appendchar.py`, Core 라이브러리 Bundle의 AppendChar 폐포를 C1 켠 엔진으로 파생): 파생 템플릿에 주소 없는 쓰기
2개가 남음 — 1800f5078(`Data[i] = c`, 2바이트), 1800f50d6(`Data[i+1] = 0`). 주소 = RAX + 2*sext(EDI).
- 기준(RAX = 1800f5070의 `[rbx]` 다시 읽기, ResizeGrow 경로와 합류): 처음엔 wild로 봤으나 Fable 확인 결과 **진입 `*(this+0)` 원자**
  — realloc 모델의 같은 객체 행(`same_mem`, null_is_fresh)을 `_pointer_row`가 합성. 기준은 막히지 않음.
- index(EDI): `lea edi, [rdx-1]`(rdx = Num) 뒤 `cmovz edi, ebp`(ebp = 0) → index = (Num == 0) ? 0 : Num - 1. 식 사슬:
  INT_ADD(Num, -1) 됨 → SUBPIECE(경계 원자 없음) → cmov JOIN {없음, 0} → INT_ZEXT → 없음. **여기서 끊김.**
- 두 번째 끊김(Fable): 파생 템플릿의 `[this+0]` run 값이 None — `function_summary._pointer_values.value_of`가 안쪽 행의
  ("nonstack",)만 합성하고 ("same", span, flag)는 합성 안 함. 호출자의 `S[0]` 읽기가 알 수 없는 포인터를 거침.
- 그래서 승인된 D(진입 값만의 선형 index 식)는 지금 실패 사례 어느 것도 고치지 못함(R002/R009/R010 컨테이너·루프, R007/R008
  포인터 다시 읽기).

선택지(기록: `.census6/d_diagnosis_{prompt,astra,fable}.md`):
1. **두 의견 공통 첫걸음**: `_pointer_values`에서 안쪽 ("same", span, flag) 합성(가정 없음, 20절 (d)를 한 단계 더). R007/R008에도
   도움될 수 있음.
2. Fable "D-lite": SUBPIECE 경계 원자 + 한 번 실행되는 JOIN의 opaque 원자(일반 C1 규칙, 검증기로 확인) → 두 쓰기가 정확한 원자
   묶음 위치 하나를 얻음; 그다음 D를 줄여서(기준 = null_is_fresh 진입 칸 값, index = opaque 항, 범위만). 기대: R005에서 A가 가능한
   출처, B 없음. "확실"은 미검증, "정확"은 경로 조건(F단계)이 필요.
3. Astra: 배열 트랙은 여기서 멈추고(B/B2a/C1 완료) 포인터 다시 읽기(R007/R008)부터 — 1번은 그 일부.
4. 둘 다 거부: (b) 블록 단위 요약 + E(지금은 불필요, 비쌈), (a) 후보 쓰기(JOIN이 SUBPIECE/ZEXT 아래에 있어 비쌈, 정밀도만).
사용자 결정: R005의 목표(가능한 출처 A vs 정확+확실), 순서(D-lite vs 포인터 다시 읽기 먼저 — 1번은 어느 쪽이든 먼저),
D 완화(opaque index 항, realloc 모델의 기존 가정 위 같은 객체 기준, E 없음) 승인 여부, once-join 원자를 일반 규칙으로 할지.

### 25.11 중첩된 "같은 포인터" 값 합성 (25.10의 #1, 2026-10-14, 설계·구현 검토 Antigravity·Astra)

리뷰어 변경: Claude 사용량 한도 때문에 Fable 대신 Antigravity(`agy` CLI, Gemini 4 Argon High, 읽기 전용 계획 모드)를 씀.
기록: `.census6/nested_same_{prompt,agy,astra,impl_prompt,impl_agy,impl_astra}.md`.

- 문제: 함수 요약은 포인터 크기 출력에 값("이 출력은 진입 시 X와 같은 포인터")을 붙임. 호출된 함수의 값은 호출 지점에서
  `same_reg`/`same_mem`(호출 시점의 레지스터/메모리 값)으로 넘어오고 호출한 쪽 정규화가 `pointer_rows`로 받지만, 호출한 쪽이
  **자기 요약을 만들 때**(`function_summary._pointer_values`)는 이것을 합성하지 않아 한 단계만 지나도 값이 사라졌음.
- 수정: `NormalizedFunction.pointer_rows`를 내보내고, `_pointer_values`가 호출 행의 값을 "호출 시점에 넘긴 값의 출처"
  (staging 행이 읽은 레지스터 / 포인터 칸 load 행이 읽은 메모리 — 정확한 복사만 따라감)와 합성: ("same", 그 진입 span,
  안쪽 flag 또는 바깥 flag). 새 가정 없음(두 증명된 사실의 합성; flag는 realloc 모델의 기존 null-is-fresh).
- 안전장치: 행 자체나 그 호출의 **어느** `~ld` 행에든 hard debt가 있으면 거부(두 단계 load는 앞 load가 가리킨 곳을 읽음 —
  Antigravity P1); 같은 경로에서 이미 합성 중인 호출 행을 다시 만나면 값 없음(루프가 호출에 자기 결과를 넘기는 경우의 무한
  재귀 — Astra P1; 기존 realloc 경로에도 같은 재귀 가능성이 있었고 함께 막음).
- 함께 고친 것(`call_summary_effects._with_origins`): 호출 지점에서 값이 같은 두 포인터(rax, rcx 둘 다 rdi의 복사)가 16바이트
  레지스터 묶음 하나로 합쳐져 값을 잃었음 → 값이 있는 run의 표시에 위치(span)를 넣어 각자 포인터 크기 run으로 남김(여러 출구의
  같은 위치는 그대로 합쳐짐; 출구마다 값이 다르면 값 없음).
- `ENGINE_SEMANTICS_VERSION` 3 → 4, FString 템플릿 다시 만듦.
- 테스트 8개(수정 없이 3개 실패; 두 안전장치를 각각 빼면 해당 테스트 실패): 레지스터·메모리 합성, 복사가 아닌 인자는 값 없음,
  루프 종료, 호출자의 호출자(H → F → G가 rcx를 돌려줌)에서 `*(rax)`가 `*(rdi)`로 정확·완전, 그 프로그램의 실행 대조, 출구마다
  다른 포인터는 값 없음, 두 단계 load 부채 거부.
- 결과: 테스트 768개, 모든 Bundle 지표·검증기 그대로. **R005는 아직 그대로**: AppendChar 템플릿의 `[this+0]` run은 합성 문제가
  아니라 UNKNOWN 판정 때문 — (1) 주소 없는 index 쓰기 2개(25.10의 #2), (2) 이 함수 자신의 스택 쓰기(스택 값이 새 나간 뒤라 private
  frame이 아님 — 그러나 rcx 같은 진입 레지스터 객체는 `entry-values-do-not-address-the-new-frame` 아래서 새 프레임을 가리킬 수
  없으므로 정밀도 개선 여지), (3) ResizeGrow의 메모리 쓰기와 겹칠 수 있음.
- 남은 P2(두 리뷰): `~ld` 거부를 그 load의 주소 사슬로만 좁히기(지금은 호출 전체 — 보수적).

### 25.12 진입 레지스터 객체 vs 자기 새 프레임 — 효과 0으로 보류 (2026-10-14, 설계 검토 Antigravity·Astra 2차)

- 아이디어: `this`(진입 rcx + 변위)처럼 **진입 레지스터 값 하나 + 변위**인 객체는, 스택 값이 새 나간 뒤에도 이 함수의 새 프레임
  (진입 sp 아래 바이트)에 닿지 않는다고 보고, 프레임 쓰기 ↔ 그 객체 사이의 별칭을 없앰(AppendChar의 `[this+0]` run을 UNKNOWN으로
  만드는 원인 중 하나).
- 검토에서 나온 필수 조건(나중에 다시 할 때): 등록 가정의 **강화**로 명시(지금 문장은 "새기 전에는"만 말함 — Astra); 호출이
  바꿨을 수 있는 레지스터는 내부 표현이 여전히 진입 원자라서(`.census6/diag_clobber_entry.py`: 결과는 call_clobber 부채로 불완전 —
  지금도 건전) call_clobber 부채에서 앞으로 닿는 접근의 객체는 제외(Antigravity P0); 메모리를 거쳐 온 포인터(`[rdi]=rax; [rsi]=rsp;
  rbx=[rdi]`)도 may-alias 부채가 있으면 제외(둘 다 P0); 제외 자격은 새 규칙 없이 수렴한 분석에서 정하고 고정(Astra — 순환 방지);
  쓰기 주체 조건(주소 모르는/불확실한 쓰기가 섞이면 제외), (연산, 객체) 쌍은 모든 범위가 진입 sp 아래일 때만, 출구 판정에서만 쓰인
  경우도 사용 보고. 기록: `.census6/entry_frame_{prompt,prompt2,agy,astra,2_agy,2_astra}.md`.
- **효과 상한 먼저 측정**(B2a′와 같은 방식): 안전장치 없이 가장 낙관적으로 적용한 진단 버전(`.census6/p_entry_frame_ub.py`,
  `run_entry_frame_ub.sh`, 커밋 안 함)으로 모든 Bundle을 돌림 → **바뀐 root 0개**(09 debug·release·win32·UE DebugGame·UE Dev).
  → 보류. R005에서는 index 쓰기(#2)가 남아 있는 한 이것만으로는 의미 없음; #2 뒤에 다시 측정.
- 같은 방식으로 25.10의 #2(SUBPIECE 경계 원자 + 한 번 실행되는 블록의 일반 합류 원자)도 상한 측정(`.census6/p_index_ub.py`,
  `run_index_ub.sh`, 커밋 안 함): 주소 모르는 쓰기 09 debug 3 → 2, release 2 → 1, win32 11 그대로, UE DebugGame 86 → 88, UE Dev
  31 → 28, zlib 628 → 616; **바뀐 root 0개**(모든 Bundle). → #2 단독으로는 보류. R005는 #2 + #3(D-lite, 요약의 index 쓰기를
  호출한 쪽에서 위치 결정) + 호출한 쪽 판단이 한 묶음이어야 움직임.

### 25.13 남은 불확실·실패의 원인 분류 (2026-10-14, 진단만)

도구: `.census6/why_unknown.py`(주소 모르는 접근이 어디서 끊기나), `.census6/why_unsure.py`(케이스 root가 어떤 부채로 불확실한가,
call_clobber 부채의 읽기와 사이에 있는 호출의 대상), `.census6/what_target.py`(호출 대상 이름·import).

- **09 Bundle의 불확실은 거의 전부 `call_clobber_read`**(호출이 레지스터·메모리를 바꿨을 수 있음): debug 10개 중 9개(6개는 이것
  하나만), release 8개 모두, win32 10개 중 8개. 사이에 있는 호출의 종류:
  - 다른 DLL의 import(DFB130 arg→ret, DFB131 outparam): **이미 있는 DLL 연결(24.2, `--link`)**을 지표 실행에서 안 켬.
  - 함수 포인터 테이블(DFB072): 간접 호출 대상이 읽기 전용 테이블에서 옴 — 테이블의 후보 대상을 모두 합치는 기능이 없음.
  - 모델 없는 CRT 함수: strcpy(DFB122), setjmp(DFB110, 예외적 흐름도 있음).
  - TLS 접근 함수(DFB091, function-000109가 요약되지 않음 — 원인 미조사).
  - 원래 풀 수 없게 설계된 것: DFB074(unresolved indirect), DFB075(요약 없는 외부 호출) — 불확실이 정답.
  - DFB064: 간접 재귀(알려진 한계).
- **주소 모르는 접근**은 09에서는 몇 개뿐이고 케이스 결과에 거의 영향 없음(DFB044, win32 DFB122·DFB201의 함수에만). UE에서는
  루프 안에서 읽은 포인터(DebugGame 61 읽기·16 쓰기), rep 문자열(16·33), 판정 거부(32·21), 호출된 함수의 쓰기(16), 합류(Dev 26·6)
  순.
- UE 케이스(R002/R005/R007/R008/R009/R010)는 may_alias·call_clobber·opaque_call_write·주소 모르는 쓰기가 섞여 있음 — 앞 절들의
  분석(컨테이너, 포인터 다시 읽기, D)과 같음.

### 25.14 09 testbed의 import DLL 연결(DFB130/131) (2026-10-14, 구현 검토 Antigravity·Astra 7차 승인)

25.13에서 DFB130/131의 불확실은 "DLL 연결(24.2)을 안 켬"이 원인이었음. 켜 보니 두 결함이 나와 고침.

- **C DLL의 template이 적용되지 않던 문제**(`summary_store.ExternalModels.lookup`): `libraries`를 적은 모델 파일은 import를
  (라이브러리, `original_name`)으로만 찾았는데, C export는 `original_name`이 None → 연결이 만든 template이 한 번도 적용 안 됨(UE
  Core는 mangled 이름이 있어서 됐음). 이제 (라이브러리, original이 있으면 original, 없으면 import 이름) — `linking`이 template을
  만들 때 쓰는 열쇠와 같음. `libraries` 없는 파일(CRT)은 그대로(짧은 이름, `?`-mangled 제외).
- **debug 빌드의 import 호출 모양**(`interprocedural._slot_loaded_register`): debug 빌드는 `mov rax, [__imp_X]; call rax`로 DLL을
  부름(`call [__imp_X]`가 아님) → "호출 0개". 이 모양을 import 호출로 인정하는 조건(엔진의 p-code block 그래프 위에서):
  - CALLIND가 있는 block B가 자기 명령어의 시작이고, 함수 시작 block이 아니며, 앞 block P가 정확히 하나(P ≠ B);
  - P는 **평범한 명령어 하나 전체**(`_plain_into`): fallthrough가 B의 명령어, flow target 없음, call/override 아님, CALL·CALLIND·
    CALLOTHER·BRANCH·CBRANCH·BRANCHIND·RETURN 연산 없음 → P의 연산이 모두 순서대로 실행된 뒤 B로 들어감(관찰된 흐름과 p-code 중
    무엇을 믿든);
  - P에서 R과 겹치는 마지막 쓰기가 import 칸 주소에서 R 전체로의 COPY;
  - B에서 CALLIND 앞에 호출 없음, 대상은 R 자신(그 앞에 R과 겹치는 쓰기 없음) 또는 R의 COPY인 임시값(`UNIQUE`만 — 메모리는
    STORE가 이름 없이 덮을 수 있음);
  - BRANCHIND가 있는 함수(대상 모름)·그래프가 unsupported인 함수는 인정 안 함.
  - 이 연결은 `call [slot]`과 같은 사실(import 칸에 그 export 주소가 있음)에 기댐. `import-slots-hold-their-exports` 가정 보고는
    두 모양 모두에 아직 없음 — 한 번에 따로 다룰 일(두 리뷰 동의).
- **p-code block 그래프 보강**(`pcode_blocks`, 검토 중 나온 기존 결함): 관찰된 흐름과 p-code가 어긋날 수 있는 모양을 추측하지
  않고 unsupported로 보고: 마지막이 아닌 RETURN; 지역 flow target(예외 착지점)이 있는 call은 한 덩어리이고 마지막 연산이 유일한
  CALL/CALLIND일 때만; 쪼개진 명령어가 착지점 있는 call이거나 override 표시가 있음; 쪼개진 명령어에서 관찰된 다음 명령어가
  실행되는 sub-block에서 닿지 않거나, flow target이 실행되는 branch의 목적지가 아님. `.census6/graph_census.py`로 모든 Bundle의
  모든 함수(09 debug 125·release 91·win32 81, UE DebugGame 119·Dev 71, zlib 25)에서 HEAD와 새 코드 모두 전부 supported → 지금
  결과에 영향 없음. 쪼개지지 않은 명령어는 엔진 전체가 Ghidra의 관찰된 흐름을 믿는 기존 전제 그대로.
- 테스트: `tests/intra/test_model_lookup_c_imports.py`(2), `tests/intra/test_import_call_shapes.py`(22, 반례마다 그 반례를 막는
  조건으로 거부되는지 확인; 각 검토 차수의 새 반례 테스트는 이전 코드에서 실패).
- **결과**(DLL 연결 켬, `.census6/run_link09.sh`): debug: template 4개 중 4개 적용, DFB130 missing·불확실 → exact·확실,
  DFB131 missing → exact·확실, DFB075 missing → exact·확실(바뀐 root 3개). release: 2개 중 2개 적용, DFB130 exact·불확실 →
  exact·확실, DFB131 missing → exact·확실(바뀐 root 2개). 연결 없는 기본 지표는 그대로(09 debug 65/61, release 52/47, win32 44/37,
  UE DebugGame 15/15, Dev 16/16), oracle도 그대로(missing 0 — zlib 256은 기존, DebugGame unexplained 1227 기존; calls_modeled
  debug 19·release 13으로 HEAD와 같음). 테스트 792개 통과.
- 실행 방법: DLL을 Ghidra 프로젝트에 먼저 import·분석(`analyzeHeadless /root/ghidra_link_proj link/libs09<cfg> -import <사본
  LIBDFBENCH_IMPORTLIB.DLL>`), 그다음 `run_dfbench --link LIBDFBENCH_IMPORTLIB.DLL=<dll> --ghidra-project
  /root/ghidra_link_proj/link.gpr --link-cache /root/tdo_link_cache --link-folder /libs09<cfg>`. 기본 지표 실행(`dfbench_metric.sh`)은
  연결 없이 그대로 둠(기준선 비교용) — 연결 결과는 이 절의 숫자로 따로 기록.
- DFB075(`dfb_external_no_summary`)는 "요약 없는 외부 호출"로 설계된 케이스지만 DLL 안의 함수가 `return x`라서 연결하면 정답대로
  확실해짐. manifest의 `unresolved_call_boundary` 경고는 연결이 없을 때의 기대임.
- 기록: `.census6/linkfix{,2..7}_{prompt,agy,astra}.md`.

### 25.15 strcpy 모델과 "모델이 적은 쓰기는 호출 뒤에도 남음" (DFB122, 2026-10-14, 설계·구현 검토 Antigravity·Astra)

- 원인(25.13): 두 64-bit 빌드 모두 CRT import `strcpy`를 부름. 예전 모델(crt v3)은 "메모리 결과 없음, 나머지 메모리 모름" →
  호출 뒤 `dst[0]` 읽기가 call_clobber 부채.
- **모델**(crt v4, win64·sysv64): `strcpy`를 따로 둠 — 반환값 = dst, 정확한 쓰기 하나 dst[0,1) = src[0,1), 나머지 메모리 모름.
  근거: 정의된 호출(src가 NUL로 끝남, dst가 충분히 큼, 겹치지 않음 — 아니면 미정의 동작)이면 strcpy는 적어도 끝의 NUL을 복사하고
  src[0]을 먼저 옮기므로 돌아왔을 때 dst[0] == 호출 때의 src[0]. `strcat`(별칭 strncpy, strncat)은 예전 항목 그대로(strncpy는
  n == 0이면 아무것도 안 씀, strcat은 dst 문자열 뒤에 씀). 모델은 지금처럼 선언된 가정으로 사용마다 보고
  (`external-model:crt-win64/strcpy@v4`).
- **엔진**: 모델만 바꾸면 DFB122는 exact가 되지만 여전히 불확실 — 모델의 쓰기는 CALL 바로 앞에 놓이는데, 메모리를 지키지 않는
  호출은 CALL에서 모든 메모리를 덮은 것으로 봐서 방금 쓴 바이트까지 덮음. 모델 형식의 뜻("적은 쓰기는 정확히 그 바이트,
  나머지는 other_memory대로")과 어긋남. 고침(범위 B — 외부 모델만):
  - `ProvenCallEffect.memory_runs_final`(외부 모델만 True). `normalize._kept_call_memory`: 그 효과의 메모리 run 행
    `<call>~<len(runs)+i>`마다, memory SSA의 쓰기 정의가 모두 DATA_WRITE이고 wild 아닌 한 객체 안의 이어진 범위로 run 크기와 같고,
    주소 모르는 쓰기가 아니고, 주소가 불확실한 쓰기(`_uncertain`)가 아니고, 조건·writer 조건·keeps_old가 없을 때만 그 바이트를
    호출이 지키는 것으로(`proven_preserved`에 추가). 안쪽 고정점에서 지킨 행이 불확실한 주소로 바뀌면 `_Retry(uncertain=...)`로
    다시 정규화(불확실 목록은 늘기만 하므로 끝남).
  - `NormalizedFunction.kept_call_memory` → `function_summary._exit_crossings`도 같은 바이트를 지킴(지역 그래프와 요약이 같은 말).
  - 범위 A(파생 요약까지)는 안 함: tail exit·언급 안 된 exit의 "self" 합치기·exported aliasing 복구 경우가 먼저 검증돼야 함
    (Antigravity P0-2, Astra P1).
  - `ENGINE_SEMANTICS_VERSION` 4 → 5, `models/derived/ue_core_win64_fstring.json` 다시 만듦(템플릿 내용 같음).
- 테스트 `tests/intra/test_model_memory_runs_kept.py`: DFB122 모양(dst[0] 완전, dst[1] 불완전, oracle 놓침 없음), src 바이트의
  부채 유지, 뒤의 opaque 호출이 다시 덮음, 불확실한 목적지(다시 정규화 경로), wrapper 요약은 dst[0]을 run으로 내보내지만 그
  호출자는 여전히 덮음(범위 B), dense/sparse 교차 확인, 8바이트 쓰기(여러 원자), 호출 시점 스택 아래 목적지. 변형 확인: 모델 표시
  끔 → 3개 실패, exit crossing 변경 되돌림 → wrapper 테스트 실패, 불확실 제외 제거 → 불확실 테스트 실패.
- 결과: DFB122 debug·release 모두 missing·불확실 → exact·확실. 기본 지표 09 debug 65/61 → 66/62, release 52/47 → 53/48,
  win32 44/37·UE DebugGame 15/15·Dev 16/16 그대로; oracle 그대로(missing 0 — zlib 256 기존, DebugGame unexplained 1227 기존,
  calls_modeled 19·13 같음). 테스트 798개 통과(그 뒤 리뷰 P2 테스트 2개 추가).
- 기록: `.census6/strcpy_{prompt,agy,astra}.md`, `.census6/strcpy_impl_{prompt,agy,astra}.md`.

### 25.16 돌아오지 않는 함수(abort)와 그 import thunk로의 점프 (DFB091 1단계, 2026-10-14, 설계 검토 1차, 구현 검토 4차 Antigravity·Astra)

- 원인: 09 testbed는 MinGW gcc로 빌드돼서 `__thread` 변수를 libgcc의 `__emutls_get_address`(정적 링크, debug 0x140004b00 ·
  release 0x140003c40)로 읽고 씀. 이 함수는 요약이 있지만 `je <abort import thunk>` 4곳이 tail exit로 남아
  `derive_proven_call_effect`가 효과를 만들지 않음 → 이 함수를 부르는 호출은 모두 opaque.
- **모델**(crt v5, win64·sysv64): 항목 필드 `noreturn`(엄격한 bool; register·memory 행이 없어야 하고 `observes`를 반드시 선언).
  `abort`: noreturn, observes [] (C11 7.22.4.1: 호출한 곳으로 돌아오지 않음). `model_effect`가 `noreturn`을 넘겨 직접 호출은
  기존 `_dead_region`이 경로를 자름.
- **점프**(`interprocedural._noreturn_jumps`): 명령어의 마지막 연산이고(명령어 안 흐름 없음) 목적지가 함수 밖의 import
  thunk이며 그 모델이 noreturn인 점프만:
  - BRANCH: fall-through 없음, 관찰된 flow target이 thunk 하나뿐, Bundle 함수로의 tail call(`calls`)이 아님 →
    `summarize_function`의 `dead_ops`(기존 자르기 → dead exit);
  - CBRANCH: fall-through가 함수 안이고 관찰된 flow target이 thunk 또는 함수 안 → 가져간 쪽 edge만 죽음:
    `noreturn_jumps`로 넘겨 `_tail_exits`가 그 블록을(지역 후속이 있을 때만) tail exit로 세지 않음. fall-through 경로는 그대로.
  - 꺼진 가정·`usable` 거부 검사는 `_external_sites`와 같음; 적용된 점프만 `declared`에 모델 라벨로 보고(+ 상속 가정).
- **돌아오지 않는 효과의 공통 검사**(`interprocedural._unplaced_noreturn`, 검토 중 나온 기존 경로까지): 함수의 효과를 만든 뒤,
  noreturn 효과인데 그 명령어에 관찰된 다른 후속(자기 목적지 — 직접 BRANCH·CALL의 주소 — 와 CALL의 fall-through 말고)이
  있으면, 함수 안이든 밖이든, 그 효과를 빼고 호출을 opaque로 둠(`_dead_region`이 그 edge까지 자르기 때문). `jmp [__imp_abort]`,
  Bundle 함수인 abort thunk로의 tail jump, 착지점 있는 call 모두 해당. (검증 단계가 EXTERNAL 공간 target을 `flow_targets`에서
  빼므로 실제 `jmp [slot]`은 target 없음 — UE Bundle의 모든 `jmp [slot]`이 EXTERNAL target 하나뿐.)
- `ENGINE_SEMANTICS_VERSION` 5 → 6, FString 템플릿 다시 만듦(내용 같음). oracle 인터프리터: abort로의 CALL·BRANCH·가져간
  CBRANCH에서 실행 멈춤.
- 테스트 `tests/intra/test_noreturn_models.py`(13): 모델 로드·검증 3종, `je abort` 도우미(tail exit 없음, 호출자가 효과를 받고
  rax→rbx 완전, 도우미를 실제로 실행하는 oracle 포함), 모델 없으면 tail exit 유지, 무조건 `jmp abort`(dead exit), 두 쪽 다
  함수 밖으로 나가는 `je abort`는 제외, 다른 지역 target도 있는 `jmp abort`는 제외, 다른 target이 있는 `jmp [__imp_abort]`·Bundle thunk로의 `jmp`(함수 안·밖)는
  noreturn 아님. 각 검사를 끄면 해당 테스트 실패.
- 결과: `__emutls_get_address` 호출이 opaque가 아니게 됨(debug·release). 기본 지표·oracle 그대로(테스트 813개; oracle
  calls_modeled debug 19 → 24, release 13 → 18). DFB091은 여전히 불확실 — 이 함수 안의 libwinpthread 호출 때문.
- **libwinpthread-1.dll 연결 측정**(2단계 조사, `.census6/run_linkpthread.sh`; DLL은 `C:\Strawberry\c\bin`, Ghidra 프로젝트
  `/libswinpthread`): 7개 import 중 `pthread_mutex_init`·`lock`·`unlock`은 템플릿이 만들어지고 적용됨; `pthread_getspecific`·
  `setspecific`·`once`·`key_create`는 거부("depends on the library's load address" — 공통으로 쓰는 내부 함수 0x2e36570d7이
  라이브러리 자신의 코드 주소를 값으로 씀). DFB091은 연결해도 불확실. 남은 원인과 진행 여부는 사용자 결정 대기.
- 기록: `.census6/noreturn_{prompt,agy,astra}.md`, `.census6/noreturn_impl_{prompt,agy,astra}.md`.

### 25.17 배열 묶음 2단계: SUBPIECE 경계 원자, once-join 원자, ZEXT 아래 바이트 (R005, 2026-10-15, 설계 검토 Antigravity·Astra)

R005(FString)의 막힘을 25.10의 D-lite 순서대로. 이 단계는 가정 없는 일반 C1 규칙(모든 함수, `TDO_V2_INDEX_ADDRESSES`로 끔).
- **2a SUBPIECE 경계 원자**: 원자가 있는 식의 SUBPIECE(e, k)(출력이 더 좁음, k + 출력 ≤ 입력, image 0) → 새 경계 원자. 키 =
  (subpiece, 입력 폭, 출력 폭, k, e의 원자 묶음, e의 변위 mod 2^입력). 범위 [0, 2^(8·출력)-1]. 성질은 입력에서 이어받음(스택 유래,
  wild). 경계 원자이므로 그 위의 객체는 wild.
- **2b once-join 원자**: 한 번만 실행되는 블록(`_once_blocks`, 첫 고정점 뒤)의 JOIN이고 요청 span이 JOIN span이며 모든 후보가
  식을 가지고(미정·막힌 읽기면 식이 없음) image가 0이고 폭이 같을 때 → 새 원자: 이번 실행의 값은 후보 중 하나. 키 = 합류한
  정의들의 안정 키 + span + **후보들의 식**(나중 단계에서 후보가 바뀌면 원자도 바뀌어 오래된 읽기로 잡힘 — Antigravity P0-1;
  안정 키도 유지 — Astra). 범위는 후보가 모두 상수일 때만(최소·최대). 기존 같은-후보 규칙·join-nonstack 규칙 뒤에 적용.
  경계(index) 원자이므로 그 위의 객체는 wild. `_note_opaque_atom`으로 성질 이어받음.
- **2c ZEXT 아래 바이트**: ZEXT(x)가 쓴 칸을 x의 폭으로 다시 읽으면 x의 식(원자가 있어도). 32비트 레지스터 쓰기의 zero
  extension을 32비트로 다시 읽는 경우(AppendChar의 cmov 앞 `zext edi`). 전에는 상수만.
- AppendChar(`.census6/diag_oncejoin.py`, `diag_appendchar.py`): index = sext(once-join{subpiece(Num-1), 0}) → 두 쓰기 모두 주소
  식(기준 진입 `*(this+0)` 원자 + 2 × index 원자)을 얻음 → wild index 객체. 그 결과 AppendChar 템플릿은 **거부됨**("writer
  conditions on objects no caller can locate") — 전에는 주소 모르는 쓰기 2개를 가진 템플릿이었음. 3단계(요약의 index 쓰기)가
  이것을 다룸.
- `ENGINE_SEMANTICS_VERSION` 6 → 7; `models/derived/ue_core_win64_fstring.json` 다시 만듦(생성자·소멸자 2개, AppendChar 거부).
- 테스트 `tests/intra/test_index_atoms_once.py`(9): 잘린 index는 정확한 한 곳(두 번째 쓰기가 첫 쓰기를 덮음), cmov로 고른
  index도 정확한 한 곳, C1 스위치 끄면 모름, 루프 안 join은 원자 없음(쓰기 주소 모름 — 블록 검사를 빼면 실패), 무작위 cmov·
  SUBPIECE index 함수 180개 × 6실행 graph 검증기 누락 0, ZEXT를 다른 폭(2바이트)으로 다시 읽으면 주소 없음·같은 폭이면 주소 있음.
  HEAD 코드에서 "정확한 한 곳"·"같은 폭" 테스트는 실패.
- 결과(AppendChar 거부 상태): 테스트 813개(+ 새 9개); 지표 전부 그대로(09 debug 66/62, release 53/48, win32 44/37, UE DebugGame 15/15,
  Dev 16/16 — R005는 이미 missing); oracle 그대로(missing 0, zlib 256 기존; DebugGame unexplained 1227 기존).
- 기록: `.census6/bundle_{prompt,agy,astra}.md`(설계 1차), `.census6/step2_impl{,2}_*`(구현 검토 2차, 둘 다 승인).

### 25.18 배열 묶음 3단계 설계: 근거를 바꿔 끼울 수 있는 "버퍼 안" 판정과 범위 쓰기 (설계만, 2026-10-15)

사용자 결정(2026-10-15): 3단계는 **설계까지만** 하고 구현은 정방향 분석기(메모리: 나중 계획)를 붙일 때 함께. 이유: 지금 구현해도
얻는 것은 R005 하나(가정 E 필요, "A만·불확실")이고, 이 장치의 가치는 정방향 사실(호출 지점 값 → index·버퍼 크기 → 안에 있음 증명)과
함께 쓸 때 나옴. 설계 검토 2차(`.census6/step3_{prompt,agy,astra}.md`)의 지적을 반영.

**0. 근거 없는 index 쓰기(지금 2단계 상태의 처리 방향).** 요약 표시만 바꾸면 안 됨(Astra P0): 쓰기 조건은 레지스터 결과·포인터
값·스택 delta 같은 모든 의존 주장을 지키고 있고, `_AncestorClosure`는 조건부 별칭 부채에서 멈춤. 그래서 **정규화 단계에서부터**
wild index 객체에 쓰는 쓰기를 조건 없는(unconditional) 불확실 쓰기로 다룸 — `_alias_conditions`가 wild 객체의 쓰기로 조건 쌍을
만들지 않고(Antigravity P0-1), 그 읽기 부채는 그대로 단단한 부채로 남아 의존 주장 전부가 그 부채를 안고 계산됨. 남은(위치를 못
정하는) 쓰기 조건이 있으면 템플릿 거부는 유지. 결과는 2단계 전과 같은 뜻(주소 모르는 쓰기가 있는 템플릿).

**1. 할당 식별자(allocation reference).** 할당 모델(malloc의 fresh, realloc의 same-object + null_is_fresh)이 만든 블록에 붙는 식별자.
같은 호출의 포인터 출력(예: `[this+0]` run의 ("same", ..., null_is_fresh))과 index 쓰기가 **같은 식별자**를 공유; 호출한 쪽에서
호출 전 칸이 NULL이면 그 식별자는 그 호출의 새 블록 원자에 묶임. 묶을 근거가 없으면 index 쓰기를 내보내지 않음(지금의
`unique` 문 — 포인터 출력이 여럿이면 fresh를 주지 않음 — 그대로). 비NULL 입력의 same_mem은 할당 근거가 아님(Astra P0-2:
`_pointer_row`는 그 경로의 기존 식을 그대로 씀).

**2. "버퍼 안" 판정과 근거 기록.** `contained(access, allocation_ref, context) -> Evidence | None`: 그 접근이 실행될 **때마다 모든 바이트**가
그 시점에 살아 있는 그 할당 안에 있다는 주장. Evidence 기록 = (주장, 접근 식별자, 할당 식별자·판, 적용 상황, 만든 쪽·판,
기대는 사실·가정 목록). 종류: `proven`(엔진이 확인 — 할당 크기와 offset 범위; 지금은 없음), `external:<분석기>`(건전하다고
설정된 분석기의 기록된 증거 — 이름만으로는 신뢰 정책이 아님), 가정(`indexed-access-stays-in-object` = E, 기본 끔, 사용마다 보고;
도구가 낸 비건전 사실도 이름 붙은 가정). 기대는 것은 **이어받음**: 할당 모델이나 E에 기대는 입력으로 증명한 범위도 그 가정을
안고 감. 여러 경로는 가능한 모든 경로를 덮어야 하고 서로 다른 경로의 범위를 교집합하지 않음. 낡거나 서로 어긋나는 사실은
보수적으로 버림.

**3. 버퍼 안 ≠ 서로 다름(Astra P0-2, Antigravity P0-3).** E는 접근이 그 할당 안에 머문다는 것뿐, `this` 객체가 그 할당 밖이라는
증명이 아님(`this`가 버퍼 안을 가리킬 수도 있음). AppendChar 안에서는 Data의 할당과 `this`가 서로 다른지 모름 → 요약은 **전제
조건**으로 내보냄: (`this` 객체의 칸 span, 할당 식별자 범위) 쌍이 겹치지 않을 때만 성립. 호출한 쪽이 결정(R005: S는 스택,
버퍼는 그 호출의 새 블록 → 겹치지 않음). 그러려면 할당 식별자가 조건 쌍 안에서 호출한 쪽이 위치를 정할 수 있는 형태여야 함
(지금의 "writer conditions on objects no caller can locate" 거부를 푸는 길). 포함 판정은 **피호출자 정규화 단계에서** 적용(요약
내보낼 때 표시만 붙이면 늦음 — 첫 쓰기 → Data 다시 읽기 → 두 번째 쓰기 의존이 그 전에 풀려야 함).

**4. 범위 쓰기(ranged may-write) 통로.** 기존 장치는 모두 계약이 다름: 일반 SSA 쓰기는 덮어씀(`memory_ssa._apply_writes`),
불확실 쓰기는 모든 객체로 퍼짐, `~u`는 위치가 정확하고 값만 모름. 새 기록 = (쓰기 key, 할당 식별자, mod 2^비트 구간들,
출처, 부채, 근거 참조, 원래 접근 폭·접근 식별자). 별칭 분석(may_alias)의 작성자·의존 장치 위에 얹음: 덮어쓰지 않음(겹치는 바이트는
옛 출처를 유지하고 이 쓰기의 출처를 더함), 나중의 정확한 쓰기는 자기가 덮는 바이트에서만 지움, 같은 객체 읽기도 처리(지금
may_alias는 같은 객체를 건너뜀), 같은 할당을 가리키는 다른 view에도 전달, 합성 출력끼리 행 순서만으로 서로 지우지 않음, 피호출자가
그 바이트를 읽지 않아도 출구 요약에 실림. **바이트 단위로 펼치지 않음**(2^33 바이트 — `may_alias`·`call_clobber`의 바이트 반복이
멈춤, Antigravity P0-4); memory SSA와 `call_clobber`의 바이트 쓰기 목록에 넣지 않음.

**5. 요약·템플릿의 index run.** IndexRun = (기준 = 할당 식별자, footprint = [L, U+s)를 무한 정수로 계산해 mod 2^비트 구간 합으로
— 근거가 있는데 범위가 전체면 None = 그 할당 전체(Antigravity P1-2), 근거가 없으면 0번처럼 주소 모르는 쓰기, 출처·부채, 근거
참조, 전제 조건). 템플릿 필드·판 올림, 왕복·재배치 테스트, ImageBaseTracking(적재 주소에 따라 바뀌는 기준·offset 거부). E는 접근
자체를 제한하지 범위 추정치 전체를 제한하는 것이 아님(추정치가 할당보다 넓어도 건전한 과대 추정).

**6. 바깥 사실 입구(정방향 연결, 구현은 나중).** `Fact(id, subject, context, claim, evidence, requires, fingerprints)`:
subject = 호출한 함수·호출 지점(필요하면 피호출자의 접근 식별자), context = 호출 입구 스냅샷이나 접근 시점 상태·호출 문맥·조건,
claim = 레지스터·칸의 값 집합(칸은 위치와 스냅샷까지), 할당 기준 offset 범위 + 접근 폭, (나중) 분기 결정, evidence = 확인된 증명 /
신뢰 설정된 분석기 결과 / 이름 붙은 가정 + 만든 쪽·판·자료 참조. 호출 지점 사실은 그 문맥이 나타내는 모든 실행(루프 반복 포함)을
덮어야 함. 들어오는 곳: `interprocedural`의 derive → normalize → validate 반복(`_prove_extents`의 철회 규율). **주의**(Astra P1):
`_prove_extents`는 모델 효과만 다시 만듦 — 범위만 담은 템플릿으로는 `Num = 0`에서 `J = 0`을 다시 계산할 수 없음. 정방향 사실을
쓰려면 호출 문맥별로 피호출자 본문을 다시 분석하는 경로(특수화)나 보존된 기호 변환식이 필요.

**7. 검증과 테스트.** 프로그램·요약 oracle이 주장된 footprint·포함·출처·부채·보존 범위를 실행으로 확인; E에 기댄 포함의 반례는
**가정 위반**, 증명이라고 주장한 것의 반례는 **증명·구현 실패**로 따로 셈(표본 실행 성공은 검증일 뿐 포함 증거가 아님). 테스트:
NULL에서 새 블록 묶기, S/T 두 할당, 겹치는 run, wrap, 중첩 wrapper, E 켬/끔, E를 끄면 E에 기댄 템플릿 거부, `this`/Data
자기 별칭, 낡은 Data 사실, 포인터 출력 여럿, realloc 있는/없는 경로, 같은 객체 읽기, 범위 쓰기 뒤 정확한 덮어쓰기, wrapper를 통한
E-끔 캐시 재사용. E 켬/끔 기준선은 따로 둠.

**8. 캐시·템플릿 정체.** 코드·모델·의미 판 지문, 특수화 문맥, 근거 요구 사항을 포함하고 불러올 때·쓸 때(중첩 wrapper 포함)
다시 확인. E를 끄면 index 필드뿐 아니라 그것에 기댄 **모든** 주장(포인터 출력, 보존 주장)이 무효.

**9. E가 틀리는 경우(가정 설명에 적을 것).** 버퍼 오버플로·언더플로; realloc의 이동·축소·실패(NULL)·크기 0(이동은 기존
`no-use-of-old-pointer-after-realloc` 계약 아래에서만 논리 객체 하나와 맞음 — E가 그 보장을 몰래 더하면 안 됨); 해제 뒤 사용·주소
재사용; 같은 할당의 두 view(같은 식별자를 공유해야 함); 내부 포인터(할당 기준 변위가 필요); 같은 할당 지점의 반복 할당; SSO처럼
Data가 `this` 안을 가리키는 경우(할당 모델 식별자가 없으면 1번 규칙으로 제외); arena처럼 한 블록을 나눠 쓰는 할당기(모델이 없으면
제외); 내부 포인터에서 음수 index로 머리로 가는 경우.

**설계 검토 3차에서 더한 것**(`.census6/step3b_{prompt,agy,astra}.md`, 둘 다 설계 승인, 막는 문제 없음):
- **조건의 새 피연산자**(3번): 기존 조건 쌍은 레지스터 기준 칸·직접 span만 위치를 정함(`_decide_conditions`) — 포인터 칸 뒤의
  할당을 가리킬 수 없고, 호출 전 값으로 정하면 R005에서는 NULL(0)이 됨. 그래서 `AllocationRange(할당 식별자, 판, 구간 | 전체)`를
  조건 쪽에 더함: 직렬화·재배치, 만든 호출·출력·조건·요구 사항 포함; 입구 칸 묶음은 호출 전 스냅샷에서 부채 검사와 함께; 포인터
  출력·조건·IndexRun이 같은 묶음을 공유; 할당기 계약과 유효한 입구 사실로 결정(분리에 기대는 출력을 읽어서 분리를 증명하면
  안 됨); 범위를 바이트로 펼치지 않고 할당 정체·수명·view 변위로 비교(전체 할당 vs 스택은 크기 없이도 분리 가능); 결정 실패는
  의존 주장 전체를 철회하고 다시 정규화. wrapper: 지금은 결정 못 한 writer 조건이 실패(건전, 정밀도 손실) — 열린 조건으로
  넘기려면 요약 전체 guard를 wrapper로 넘기는 확장이 필요(선택).
- **"묶음 없음 → 내보내지 않음"의 뜻**(1번): IndexRun만 빼고 보존·포인터 주장을 남기면 건전하지 않음 → 묶음 실패·근거 없음·
  전제 실패는 **조건 없는 주소 모르는 쓰기로 남기거나 요약 전체를 거부**. 0번도 같음: 포함 근거가 없는 index 객체의 run은
  내보내지 않고, 그 객체가 나중에 덮여 보여도 주소 모르는 쓰기 효과를 유지(뒤에 다시 읽기 → 두 번째 쓰기가 없는 함수의 단독
  index 쓰기 포함 — Antigravity P1-1).
- **특수화 경로**(6번): 처음 길은 호출 문맥별 피호출자 재분석; 일반 템플릿과 따로 두고 지금의 입구 사실이 기록된 문맥을 만족할
  때만 사용; 본문·변환식 없음, 지원 안 되는 사실, 분석 예산 초과는 보수적으로. 문맥 수 제한, 재귀 고정점·widening, 이어지는
  철회 규칙을 정함; 특수화한 요약으로 얻은 사실이 그 요약의 근거가 되는 순환은 건전한 고정점 논증 없이는 금지. JSON 템플릿만
  있는 DLL 함수(AppendChar)는 (a) IndexRun에 기호 index·조건 설명을 남기거나 (b) 연결 캐시의 피호출자 단위를 써야 특수화 가능
  — 구현 때 선택. `_Projector`에 범위가 정해진 `entry_facts`(칸·레지스터 → 상수·구간)를 넣고 쓴 사실을 `used_reads`와
  Evidence.requires에 기록. 호출자 쪽 사실도 `_prove_extents`의 `rejected`처럼 단조 철회.
- **신뢰 정책 표면**: `trusted_fact_producers`(기본 비어 있음) — 만든 쪽·판, 지원하는 주장 종류, 대상 의미, 필요한 모델 가정까지;
  목록에 없는 외부 사실은 자동으로 가정(`external-fact:<만든 쪽>`, 명시적 opt-in)으로 내려감. 정책이 바뀌면 의존 캐시 무효·재검증.
- **통합 확인 두 가지**: 범위 쓰기의 출처는 연산·의존 노드에 붙임(`_run_origins`는 SSA 정의로 붙이는데 범위 쓰기는 정의가 없음);
  분리·묶음이 처음엔 성립했다가 철회되는 회귀 테스트(포인터 출력·레지스터 주장·보존·중첩 요약을 함께 확인).
- 0번만 먼저 구현할지: Antigravity는 지금(작은 변경, AppendChar 템플릿 회복), Astra는 미뤄도 됨(거부된 템플릿은 보수적인 정밀도
  손실). 사용자 결정(설계만)에 따라 미룸.
- "E 켬 → A만, B 없음, 불확실"은 목표이지 아직 확인된 결과가 아님.

**10. 예상과 순서(구현할 때).** E 끔: 2단계 전과 같음(R005 missing). E 켬: R005에서 A만, B 없음, 불확실(정확·확실은 경로 조건이나
정방향 사실). 순서: 0번(따로 구현 가능, 2단계 전 뜻 회복) → 1~5번과 7번 한 묶음 → 6번은 정방향 분석기와 함께. 기록:
`.census6/bundle_*`(설계 1차), `.census6/step3_*`(설계 2차), `.census6/step3b_*`(설계 3차).

### 25.19 출처 증거(origin witnesses): 보고된 출처가 왜 있는지 (R007/R008, 가정 없음, 2026-10-15, 설계 검토 3차·구현 검토 Antigravity·Astra)

사용자 요청: R007/R008을 **가정 없이** 개선. 확인 결과 "같은 칸을 다시 읽으면 같은 값"은 memory SSA가 이미 함; R007에서는 읽기 사이에
Get 호출(느린 경로가 간접 호출 결과를 돌려줘 rax가 "모름")과 주소 모르는 포인터 쓰기가 있어서 가정 없이는 p1 = p2 = p3를 증명 못 함 →
판정은 그대로("A·B 가능, 불확실"). 대신 **진단만** 하는 기능: 각 출처가 어떤 부채를 거쳐 오는지 보고(출처·완전성은 바뀌지 않음).
- **`has_debt_free_path`**: `_lane_origin_labels`와 같은 lane slice에서 MEMORY_DEBT 노드를 빼고(시드 포함), 호출이 바꿨을 수 있는
  읽기 조각(그 연산의 call-clobber 부채 span과 겹침 — 호출 전 값은 호출이 안 바꿨을 때만 옴)도 따라가지 않을 때 닿는가.
  그래프 성질일 뿐 "증명된 출처"가 아님. (첫 구현에서 R007의 B가 "부채 없는 길"로 나와 확인해 보니, Get 호출 뒤 rax를 읽는 연결이
  call-clobber 부채 노드를 거치지 않고 호출 전 rax(= B)로 이어짐 → 겹치는 조각 규칙을 더함.)
- **증거(witness)**, 출처마다 최대 8개(`truncated`): may_alias 부채는 (쓰기, 읽기) 전달마다 따로 — 그 쓰기의 **저장 값**(STORE의 값
  피연산자, 요약된 메모리 run의 값 읽기 `NormalizedFunction.call_value_inputs`, rep 원소의 값 읽기)에서 출처에 닿을 때만(주소 입력
  제외), 피호출자가 붙인 출처는 `provenance: callee`. call_clobber 부채는 그 연산의 겹치는 입력 조각의 호출 전 값에서 닿는 출처 —
  "the value from before <calls>, if they leave it unchanged". 그 밖의 부채는 종류와 위치.
- **주소 차이 조건**(may_alias 전달): 쓰기가 주소 불확실 쓰기가 아니고, 읽기·쓰기가 각각 relative span 하나, 두 주소 피연산자가
  부채에 기대지 않고(그 연산의 겹치는 call-clobber 부채 포함; 호출·rep 행은 `call_anchors`로), 원자 묶음이 서로 한 원자씩만 다르고
  계수 1일 때: 쓰기 원자 − 읽기 원자 ∈ [dr − dw − sw + 1, dr − dw + sr − 1] (mod 2^비트) = 어느 바이트든 겹침의 조건(값 전체 전달·
  충분 조건 아님). 0이 구간 밖이면 "equal pointers exclude this transfer". 문장은 "이 전달은 …일 때만"(그 출처 전체가 아님).
  원자 묶음은 projector가 객체를 만들 때 기록(`address_objects`: 객체 id → (원자 묶음, 공간) — id가 바로 그 묶음의 해시라 어느
  단계에서 기록해도 맞음; `address_atoms`: 원자 → 무엇의 값).
- 쓰는 법: `run_dfbench --witnesses`(기본 끔): JSON의 root에 `witnesses`, 케이스 줄 아래에 부채 없는 길이 없는 출처의 증거.
- **R007/R008에서 나온 것**(UE Development·DebugGame): A·B 모두 부채 없는 길 없음; B는 (1) Get 호출들이 rax(또는 메모리 칸)를
  바꾸지 않았다면 그 전 값 B가 포인터·값으로 쓰임, (2) 주소가 불확실한 쓰기 `[p2+0x34] = B`를 통해 옴 — 주소 조건은 나오지 않음
  (Get 결과가 "모름"이라 쓰기 주소가 불확실). 즉 진짜 원인은 Get 요약의 rax가 "모름"인 것(느린 경로의 간접 호출).
- 구현 검토 1차(Astra P1·P2, Antigravity P2) 반영: 모든 시작점은 **그 바이트만**(STORE 값 피연산자의 span, run의 값 읽기 span,
  호출이 바꿨을 수 있는 span)으로 시드 — 정의 전체(FULL)로 하면 `PIECE(B, A)`의 아래 4바이트만 저장해도 B가 붙음; ignore_debts는
  겹치는 조각을 통째로 버리지 않고 바뀌었을 수 있는 바이트만 뺌; call-clobber 부채 노드 자체에 붙은 출처는 `call_value`("a value
  <calls> may have produced"); `traversal`: "lane" 또는 lane 출처가 꺼졌거나 node slice로 대체됐을 때 "node-fallback"; 원자 이름은
  전체 16진; 텍스트에 `(callee)` 표시; 조건은 메모리 span이 정확히 하나(그리고 relative)일 때만.
- 구현 검토 2차(Astra P1·P2) 반영: 시드는 요청 span을 들어오는 연결의 span과 **교집합**(저장 전에 덮인 바이트 제외); `traversal`은
  `summary_engine._witnesses`가 `_lane_origin_labels`와 같은 기준으로 정함; 원자 설명에 짧은 id(`#하위 32비트`).
- 테스트 `tests/intra/test_origin_witnesses.py`(9 — 아래 7개 + 저장 전에 덮인 바이트는 저장 값 아님(교집합을 빼면 실패), 서로 다른
  포인터는 다르게 출력): 전달마다 따로 구간(A [-3,3] 문구 없음, B [-7,-1] "equal pointers exclude"),
  주소 불확실 쓰기는 조건 없음, 주소에만 쓰인 출처는 저장 값 증거가 아님(값 대신 연산 노드에서 찾게 바꾸면 실패), 호출 전 값 증거,
  넓은 값의 저장된 바이트만(바이트를 버리고 FULL로 시드하면 실패), 부채 노드의 출처는 call_value(그 증거를 빼면 실패),
  lane 출처 끔 → node-fallback.
- 기록: `.census6/cond_report{,2,3}_*`(설계 검토 3차), `.census6/witness_impl{,2,3}_*`(구현 검토 3차, 둘 다 승인). 결과: 테스트 831개, 지표·oracle 그대로.

### 25.20 같은 결과를 돌려주는 접근 함수(same-result accessor) 모델 설계 (설계만, 2026-10-15, 설계 검토 3차 Antigravity·Astra 승인)

사용자 요청: R007/R008의 "다시 얻은 포인터"(UE `TObjectPtr` 해석 Get)를 UE 전용이 아닌 **일반 모델**로 설계. 같은 모양: 지연 초기화
getter·singleton, TLS 접근(`__errno_location`, `pthread_getspecific`, `__emutls_get_address` — DFB091), 핸들 테이블 조회, 디버그 빌드에
남은 접근 함수. 25.19에서 확인한 대로 가정 없이는 더 못 감(Get의 느린 경로가 간접 호출 → rax 모름). 그래서 이름 붙은 가정 셋, 기본 끔.

**가정 스위치(정확히 셋).** `same-result-functions`(아래 A–C, 엔트리의 `nonstack`·`write_back` 필드 포함), `accessor-result-separate`(D),
`accessor-private-state`(라이브러리 내부 쓰기 생략). 각각 따로 켜고 끔(지금 `usable(entry)`는 `inherited` 하나만 꺼져도 엔트리 전체를
거부 — 이 셋은 효과를 만들 때 따로 검사; 끈 속성 때문에 실제 쓰기가 사라지면 안 되므로 그런 경우 연결 자체를 거부하고 본문을 분석).
분석된 함수는 그 안의 호출이 실제로 쓴 가정만 기록.

**A. 약속(엔트리 필드 `same_result: {result, inputs, reads, write_back, nonstack}`).** 분석하는 함수의 **한 번의 실행 안에서**(한 스레드,
호출 사이 fiber/coroutine 전환 없음 — 이름 붙은 제외) 같은 열쇠(B)로 부른 두 호출은 `result`에 같은 비트를 돌려줌 — **실패 포함**
(null을 낸 열쇠는 다시 null; null 뒤 성공은 약속 밖, v1에는 성공 조건부 형태 없음). 같다는 것은 non-null·살아 있음을 뜻하지 않음;
다른 열쇠는 아무것도 뜻하지 않음(결과 원자는 보수적으로 별칭 가능). 숨은 상태(핸들 테이블, TLS 연결)는 이 엔트리 호출(다시 쓰기
정규화)이나 상태 토큰을 바꾸는 호출(C3)로만 바뀜 — 파괴·핸들 재사용·hot reload·콜백·재진입은 이 가정이 제외. `nonstack: true`는
**기존 nonstack 뜻 그대로**(Astra 2차 P0): 결과가 가리키는 객체는 어느 스레드의 스택에도 없음(힙·이미지 데이터·TLS 블록·라이브러리
내부 저장소) — 어떤 offset으로 접근해도 스택에 닿지 않음. "이 함수의 스택 밖"으로는 부족(위쪽 함수의 지역 버퍼를 돌려주는 접근 함수
반례); 그런 엔트리는 nonstack을 쓰지 않음(그러면 지금처럼 wild). fresh는 절대 아님.

**B. 열쇠와 칸 종류(class) 토큰.** 열쇠 = (모델 정체·판·엔트리 digest, 출력 조각·폭, 순서 있는 입력 값 식, (읽는 칸 주소 식, 칸 종류
토큰), 상태 토큰). 모든 식은 settled·unblocked·`image == 0`(아니면 거부), 그리고 기존 한 번 실행 규칙(`_once_blocks`)을 지키는
원자만. 열쇠에 쓴 모든 읽기(`~ld`/`~in` 준비 읽기, 종류를 따라간 읽기)는 `same_result_reads`로 기록해 `rep_used`와 합쳐 부채 읽기와
교차 → 부채·낡은 읽기면 `_blocked_reads` + `_Retry`(지금의 행별 원자로 돌아감). 칸 종류 토큰(칸 span S, 도달 정의 d 하나; 일부만
쓰기·겹친 쓰기·모르는 덮어쓰기·정의 여럿이면 토큰 없음):
- d = 레지스터 아닌 객체의 ENTRY → ("entry", S) — 이 실행에서만.
- d = 같은 엔트리 호출의 다시 쓰기 run이고 그 span = S, 그 열쇠가 이 칸 말고는 같음 → 그 호출의 **호출 전** 토큰(다시 쓰기만 물려줌).
- d = 그 밖의 쓰기·run → ("def", d) — d가 한 번만 실행될 때만(아니면 토큰 없음); 같은 비트를 다시 써도 새 종류.
- d = JOIN → 반복 없는 합류이고 들어오는 토큰이 모두 같을 때만.
- 토큰 없음 → 같은 결과 원자 없음(지금 동작). v1은 읽는 칸 하나.
- 마지막 memory SSA에서 **판단 근거 전체**(칸마다 도달 정의 정체·span·다시 쓰기 기록, 상태 토큰, 입력 식)를 다시 계산해 같아야 함
  (값 식만 비교하면 같은 비트를 쓰는 늦게 발견된 저장을 놓침 — Astra 2차 P1). 정의 정체는 안정 정체로 비교(SSA 숫자 id는 회차마다
  바뀜); 각 호출은 자기의 이전 근거와 비교. 부채는 준비·주소·종류 추적 입력까지 전이적으로 확인. 다시 계산 실패가 값 식 변화 없이도
  재시도를 진전시키도록 해당 읽기를 막음(Antigravity 3차 P2).

**C. 연결된 호출의 효과.** (1) 결과: 열쇠로 정한 같은 결과 원자(`address_atoms` 이름 `same_result:<entry>(...)`, 출처 증거용).
(2) 다시 쓰기: S만 쓰는 ProvenMemoryRun(`keeps_old=True`, 입력 = inputs + reads) — `unknown_memory` 아님. (3) 상태 토큰(epoch 대신,
Astra 2차 P1): 접근 함수마다 정방향 데이터 흐름. 진입 ("state", entry); 모든 호출은 토큰을 ("state", c)로 바꿈 — 예외: 같은 엔트리
호출, 독립이라고 선언된 다른 same-result 엔트리, 모델이 `preserves_accessor_state: [엔트리 이름 | "*"]`를 명시한 호출(이름은 모호하지
않은 엔트리 정체로 풀고, 사용마다 보고, 캐시 의존에 포함; 콜백·재진입을 포함한 전이 효과를 덮는 주장). 쓰는 곳이 정해진 모델이나
요약된 내부 함수도 상태를 보존하지 않음(핸들 테이블 setter도 쓰는 곳이 정해짐; Antigravity의 내부 요약 예외안은 Astra 따라 안 씀) — 예외: 25.26의
본문 증명(호출·저장 없음, 진입 스택 위치의 pop 반환; 전제 accessor-hidden-state-in-memory)이 붙은 호출.
보존 호출은 들어온 토큰을 그대로(토큰 없음이면 계속 없음); ("state", c)는 c가 한 번만 실행될 때만; JOIN은 모든 앞쪽이 같은 알려진
토큰일 때만; 반복·미해결 → 토큰 없음. 상태 토큰은 A의 바이트에 대해 아무 말도 안 함(그건 일반 메모리 효과). (4) 그 밖의 메모리:
엔트리의 `memory` 줄; 라이브러리 내부 쓰기(lock·접근 추적 카운터)는 `accessor-private-state`가 켜졌을 때만 생략(프로그램 포인터·
새 나간 포인터·export·콜백으로 닿지 않고 이후 결과에 영향 없음); 끄면 엔트리가 일반 메모리로 선언하거나 연결 거부.

**D. 떨어져 있음(`result_separate_from_reads: {extent: N}`, `accessor-result-separate`).** [result, result+N)의 바이트는 이 실행의 이
엔트리 호출들이 읽는 칸 바이트 S와 겹치지 않음 — 바이트 단위·양방향(A 저장이 칸을 안 바꿈 / 칸 다시 쓰기가 [p3+0x30]을 안 바꿈),
객체 전체 주장 아님. `separated_extents`(결과 객체, 최소, 최대, 칸 span)를 projection에 두고 may_alias(dense·sparse)와 `_exit_crossings`에서
**양쪽 span이 모두 덮일 때만** 별칭 쌍을 지움(결과 쪽 접근이 [0, N) 안 + 칸 쪽 접근이 S 안; S를 포함하는 더 넓은 쓰기는 안 지움;
`_written`이 객체 전체로 퍼뜨리는 곳은 쓰기 span 유지; sparse 바이트 묶음은 S와 범위 경계에서 쪼갬). 범위 밖·index·모르는 offset·
주소 wrap → 떨어져 있지 않음. R007은 N ≥ 0x38.

**E. 요약 경계.** 같은 결과 원자·칸 종류 토큰·상태 토큰은 이 실행 안에서만 — 요약 경계에서 버림(호출한 쪽은 지금의 보수적 요약).
가정·연결 출처는 파생 요약에 유지. `ENGINE_SEMANTICS_VERSION`과 캐시 프로필 변경.

**F. 바이너리 안(export 안 된) 함수 연결.** 바이너리별 연결 파일 = 바이너리 전체 SHA-256 + 모듈 + 엔트리 RVA + ABI·언어; 심볼 이름은
그 바이너리에 대해 위치를 찾는 데만(모호하면 거부); 정규화 p-code 지문은 추가 확인일 뿐 대체 아님. `own_library is None`에서도 동작
(`_internal_model_cuts`: `by_entry`와 leaf 대상, 직접 호출·꼬리 점프·상수로 풀린 CALLIND). 가정이 켜졌을 때만 cut, 끄면 본문 분석.
사용마다 보고: 호출한 함수·지점, 대상 RVA/심볼, 바이너리·연결 digest, 엔트리·판·digest, 켜진 가정, 출력 조각, 열쇠·종류 근거, 떨어짐
범위, 또는 거부 이유.

**G. 증명 가능한 getter**는 가정 없음(본문을 따라가면 memory SSA가 같음을 앎).

**H. oracle.** 실제 본문(함수 테이블을 통한 지연 해석, 다시 쓰기, null 경우)을 가진 합성 프로그램을 program interpreter로 실행:
(i) 위반 — 같은 구체 열쇠인데 다른 결과, 결과 [0, N) 안 접근이 칸 바이트에 닿음 → "가정 위반" 개수; (ii) 독립적으로 검사 못 하는
의무(다시 쓰기 종류 같음 — 정의상 순환, 내부 상태 도달성) → "검사 못 함" 개수(통과로 세지 않음). program_oracle 보고에 따로.

**구현 순서(Astra).** S1: A+B+C, 출력 하나·칸 하나, 다시 쓰기 없음, D 없음, 내부 쓰기 생략 없음(모든 쓰기 선언), 보수적 상태 토큰,
실행 안에서만의 정체; 가정 스위치·사용 보고·마지막 SSA 근거 재확인·실제 본문 oracle 테스트를 처음부터; export/라이브러리 모델 엔트리만.
S1은 다시 쓰기 설정을 거부(건전한 일반 모델이 남지 않으면). S2: 다시 쓰기 종류(끄면 일반 보수적 쓰기 효과를 남기거나 거부). S3: D와
양쪽 span 검사. S4: `accessor-private-state` 생략 + 검증된 바이너리 안 연결(F) → R007/R008. 나중: 반복을 지나는 종류, 요약 너머 관계
내보내기, 성공 조건부 형태. 받아들임 조건(조건부): S4에서 셋 다 켜면 A exact, 열쇠가 같고 두 저장이 범위 안이고 두 Get 사이에 상태를
바꾸는 호출이 없을 때 B 제외; sure는 호출들이 A의 바이트를 지킬 때만. 다 끄면 지금 결과 그대로.
테스트 목록: 칸 재할당(같은 비트 포함), 일부 칸 쓰기, 별칭 포인터로 칸 쓰기, 칸이 바뀌는 반복 안 호출, 반복 안 같은 비트 저장,
상태 JOIN·backedge, 두 상황, null 뒤 성공, 사이의 모르는 호출, 쓰는 곳이 정해진 상태 변경(보존 주장 없음 → 거부), 모르는 상태 뒤의
보존 주장, 접근 함수 A만 보존·B는 아님, A가 관찰한 바이트를 쓰는 보존 호출(결과 같음은 유지, 그 메모리 값은 무효), nonstack 반례,
S를 넘는 쓰기, 범위 밖 접근, image ≠ 0, 다 끄면 지금과 같음.
- 기록: `.census6/same_result{,2,3}_{prompt,agy,astra}.md`(설계 검토 3차; 1차 둘 다 보류, 2차 Antigravity 승인·Astra 보류, 3차 둘 다 승인).

### 25.21 같은 결과 접근 함수 1단계(S1) 구현: 열쇠·칸 종류·상태 토큰 (2026-10-15, 구현 검토 2차 Antigravity·Astra 승인)

25.20의 S1. 가정 `same-result-functions`(스위치, **기본 끔**, `--assume-same-result-functions`,
`analyze_frozen_bundle_with_summaries(assume_same_result_functions=...)`). 끄면 결과가 지금과 정확히 같음(전체 실행으로 확인).
- **모델 형식**(`summary_store`): 엔트리 `same_result {result, inputs, reads(정확히 하나, 바이트 크기), nonstack}`(`write_back`은 S2 전까지
  거부); `preserves_accessor_state`(["<file>/<entry>"] 또는 ["*"], 불러온 접근 함수만 — `validated_models`에서 확인); 레지스터 줄에
  `loads`(결과가 진입 메모리에 기댐: `ModelEntry.register_loads`, `model_summary`). 레지스터 하나는 한 줄만 씀; 결과 줄은 모든
  입력을 `from`에, 읽는 칸을 `loads`에 적어야 함(스위치를 꺼도 결과의 일반 의존이 맞도록 — Antigravity 1차 P1-1).
- **효과**: `ProvenCallEffect.same_result`(모델 id, 정체 = 라벨 + 파일 digest, 결과·입력 레지스터, 칸 AnchoredSpan, nonstack),
  `preserves_accessor_state`. `interprocedural._accessor_effect`가 스위치가 켜졌을 때만 붙임; `_same_result_labels`가 같은 결과
  원자를 실제로 쓴 함수에만 `same-result-functions`와 `accessor-state-preserved-by:<label>`을 기록.
- **상태 토큰**(`normalize._accessor_states`): 접근 함수(모델 id)마다 p-code 블록 그래프 위 정방향 must 흐름 — 진입 ("entry",);
  접근 함수 호출·보존 선언 호출(주장 기록)·효과 없다고 선언된 CALLOTHER는 유지, 그 밖의 CALL/CALLIND/CALLOTHER는 블록이 한 번
  실행될 때 ("call", key), 아니면 None; 합류는 같은 토큰만; 진입에서 시작하는 최대 고정점(호출 없는 반복은 토큰 유지).
- **행**(`_proven_call_rows`): 토큰이 있는 접근 호출만 칸을 읽고(`~ld<j>`, 결과 줄의 load와 공유) `~sr` 행이 입력·칸 base·칸 load를
  읽음; 결과 줄의 pointer row = ("same_result", 정체, ~sr, 입력, base, disp, ~ld, 폭, nonstack, 상태).
- **원자**(`relative_memory._same_result_key`): 정체·폭·입력과 base의 식(settled, unblocked, image 0)·disp·칸 종류·상태의 digest.
  칸 종류(`_slot_class`/`_definition_class`): 읽기 하나·조각 하나·정의 하나 — ENTRY → ("entry", span); 한 번 실행되는 쓰기 →
  ("def", 안정 정의 키, span); 반복 없는 JOIN은 모든 출처가 같은 종류일 때만; 그 밖(일부 쓰기, 반복 쓰기, 순환)은 없음.
  nonstack 원자는 엔트리가 nonstack일 때만, 아니면 wild(정의 원자처럼). 원자는 함수 안에서만 — 요약의 rax에는 pointer value 없음.
- **재확인**: 쓴 열쇠는 `used_reads`에 (("same_result", row, ~sr), 폭)로 기록 → `stale_reads`가 마지막 상태에서 열쇠 전체를 다시
  계산; `~sr` 행이 부채에 닿으면(전이적) 실패 → `_blocked_reads` → `_Retry`(그 호출은 행별 원자로). 원자는 `once_keys`가 비어도
  접근 상태가 있으면 켬(Antigravity 1차 P1-2).
- **연결·캐시**: `Linker(same_result=...)`가 프로필 스위치·preflight `disabled`·deriver에 전달; `derive_models --assume-same-result-functions`.
  `ENGINE_SEMANTICS_VERSION` 7 → 8, `models/derived/ue_core_win64_fstring.json` 다시 만듦(템플릿 같음).
- **oracle**: `program_oracle._check_same_results` — 같은 원자를 받은 호출들의 실제 반환값이 같아야 함(`same_result_checked`,
  `same_result_violations`; `same_result_unchecked`는 다시 쓰기 전까지 0); `pcode_interpreter.activation_returns`.
- **테스트** `tests/intra/test_same_result_models.py`(32): 기본 끔(A·B, 보고 없음); 같은 열쇠 → 원자 하나, A exact·B 제외·complete·보고;
  칸 재할당 / 같은 비트 다시 쓰기 / 다른 포인터로 쓰기 / 쓰는 곳 정해진 모델 호출 / 모르는 호출 → 다른 원자; 보존 선언 호출 유지·보고;
  다른 칸 주소·다른 입력; 다른 상태의 합류 → 행 없음, 같은 상태 합류 유지; 열쇠가 그대로인 반복은 원자 공유; 결과로 쓰는 반복 →
  원자 없음(S3 필요); 반복마다 칸을 쓰면 원자 없음; nonstack 없으면 wild; 4바이트 일부 쓰기 → 종류 없음; 한 접근 함수만 보존;
  모르는 상태 뒤 보존 주장은 모름 유지; 그 뒤 한 번 실행되는 무효화 호출은 새 상태; 마지막 상태 재확인이 바뀐 열쇠를 잡음;
  요약 경계에서 정체를 버림; 모델 검증 7가지; 실제 getter 본문 oracle(위반 없음, silent 없음)과 약속을 어기는 본문(위반 보고).
  변형 확인: 반복 쓰기의 def 토큰, def = entry, 호출이 상태 유지, ~sr 부채 검사 없음, 입력이 열쇠에 없음, 합류가 아무 토큰,
  재확인 없음 — 각각 테스트 하나 이상 실패.
- R007(Development) 실제 모양: `p1 = Get(this+0x478); [p1+0x30] = A; source_B(); p2 = Get; [p2+0x34] = B; p3 = Get; x = [p3+0x30]` —
  source_B 호출이 사이에 있어 p1 ≠ p2(상태가 바뀜), p2 = p3. 그래서 S4 뒤 예상: B 제외(exact), A는 p1 객체에서 may-alias로(unsure).
  Get(0x180004e10): `[rcx]`가 미해결(최하위 비트)이면 전역 함수 포인터로 간접 호출해 풀고 `[rcx]`에 다시 씀, 추적 테이블 카운터를
  LOCK으로 올렸다 내리고 추적 함수를 부름, 푼 포인터를 돌려줌 — 다시 쓰기(S2)·내부 상태(S4)·떨어짐(S3)이 모두 필요.
- 기록: `.census6/sr_impl{,2}_{prompt,agy,astra}.md`(구현 검토 2차, 둘 다 승인; Astra P2: 늦게 풀리는 같은 비트 저장을 정규화
  전체로 거치는 통합 테스트는 아직 없음 — 재확인 함수 단위 테스트로 대신).

### 25.22 같은 결과 접근 함수 2단계(S2): 다시 쓰기 종류 (2026-10-15, 구현 검토 Antigravity·Astra)

- **모델**: `same_result.write_back: true` — 칸을 정확히 쓰고, 칸을 load하고, 모든 입력을 `from`에 둔 메모리 줄이 정확히 하나
  (값이 옛 칸 값에 기대므로 "쓰지 않을 수도 있음"도 덮음; 25.20 C2의 입력 = inputs + reads). 칸의 바이트를 쓰는 다른 메모리 줄은
  (값 unknown 줄 포함, 같은 base 레지스터에서 겹치면, 레지스터 크기 쓰기는 겹친다고 봄) 거부; write_back 없이 칸을 쓰는 줄도 거부.
- **정규화**: 토큰이 있는 다시 쓰기 접근 호출의 칸 쓰기 run에 pointer row ("write_back", 결과 행). 그 값 자체는 지금처럼 정의 원자.
- **칸 종류**: `_key_parts`(정체·입력과 base 식·disp·폭·상태; 칸 종류 빼고 열쇠 전부)와 칸 종류로 열쇠를 나눔. DATA_WRITE가
  "write_back" 줄이고, span이 칸 span과 같고, 쓴 호출의 `_key_parts`가 지금 호출과 같으면 → 쓴 호출의 **호출 전** 칸 종류
  (그 정의를 `active`에 넣고 재귀: 반복을 도는 다시 쓰기는 순환 → 없음). 아니면 S1 규칙(한 번 실행 → ("def", ...)).
- **oracle**: 함수가 그 접근 함수의 열쇠를 쓴 경우, 그 접근 함수 호출의 모든 활성에서 칸 바이트가 바뀌면 `same_result_unchecked`
  (같은 종류라는 의무는 독립적으로 검사 못 함 — 25.20 H). 결과를 쓰지 않은 호출의 다시 쓰기도 셈(Astra 1차 P2: 재현됨).
- **테스트**(44): 다시 쓰기 세 번 → 원자 하나·A exact·B 제외·complete; 다른 상태의 다시 쓰기는 일반 쓰기(a1 ≠ a2 = a3); 반복 안의
  다시 쓰기 → 종류 없음; 다른 입력으로 부른 호출의 다시 쓰기는 일반 쓰기(셋 다 다름); 검증 6가지(쓰기 줄 없음, write_back 없는
  칸 쓰기, 칸을 load 안 함, 입력을 안 읽음, 칸 위 unknown 쓰기, 겹치는 쓰기); 실제 지연 해석 본문 oracle(위반 없음, unchecked > 0,
  silent 없음); 결과를 버린 호출의 다시 쓰기도 unchecked로 셈. 변형: 다시 쓰기 → def(3 실패), 쓴 호출의 열쇠 무시(1 실패),
  재확인 없음(1 실패); "아무 span의 다시 쓰기"는 같은 동작(열쇠가 같으면 칸 주소·폭이 같음).
- 기록: `.census6/sr2_impl{,2}_{prompt,agy,astra}.md`.

### 25.23 같은 결과 접근 함수 3단계(S3): 결과와 칸이 떨어져 있음 (2026-10-15, 구현 검토 Antigravity·Astra)

- **가정** `accessor-result-separate`(스위치, 기본 끔, `--assume-accessor-result-separate`). 엔트리 필드
  `result_separate_from_reads: {extent: N}`(same_result 엔트리만, 0 < N ≤ 65536). Linker 프로필·preflight·derive_models 연결은 S1처럼.
- **짝**(`relative_memory.accessor_separations`): 투영 고정점 뒤 마지막 memory SSA에서, 정체마다 쓰인 열쇠의 원자 각각의 결과 객체
  [bias, bias+N)과 쓰인 호출 각각의 칸(정확한 읽기 하나) — (결과 객체, 시작, 끝, 칸 span, **칸의 호출**). 원자들은 뒤의 재확인·부채
  검사를 받고, 실패하면 정규화 전체를 다시 함(짝도 다시 만듦).
- **may-alias**(`_Policy.excluded`, `_written`): 결과의 [시작, 끝) 안에 **완전히** 든 쓰기는 칸 바이트에 닿지 않음; 칸 span 안에 완전히 든
  쓰기는 결과의 [시작, 끝)에 닿지 않음; 넘어서는 쓰기는 떨어뜨리지 않음. 짝은 **그 칸의 호출이 그 쓰기 전에 반드시 실행됐을 때만**
  (`_ran_before`: 쓰기가 그 호출 자신의 행이거나, 호출 블록이 쓰기 블록을 지배하거나 같은 블록에서 앞섬) — 약속은 실행된 호출에만
  해당(Astra 1차 P1: 조건문 안 호출의 칸으로 떨어뜨리면 그 호출이 안 돌 때 A를 잃음 — 재현되어 테스트로 남김). 제외된 바이트는 쓰기
  전 쓰기 집합 그대로 두고 나머지에만 쓰기를 더함. 짝이 있으면 dense 엔진(sparse는 객체 전체로 퍼뜨림).
- **기다림**(S1·S2에도 적용, 스위치 켰을 때만): 접근 호출의 열쇠가 **대기 중인 쓰기 때문에만** 없으면(`_settles`: 대기 검사를 끄고
  같은 계산을 하면 열쇠가 나옴; 식 캐시·사용 기록은 되돌림) 그 패스에서는 값 없음(`_WAIT`) — 행별 정의 원자로 대신하면 그 사이에
  `[p2+0x34]` 같은 접근이 다른 객체로 고정됨(건전하지만 떨어뜨림이 적용 안 됨). 진짜 이유로 없으면 바로 대신함.
- **아직 안 한 것**: `function_summary._exit_crossings`는 그대로(요약에서는 결과 객체 쓰기가 칸 객체로 건너갈 수 있다고 둠 — 보수적,
  요약 수준 떨어뜨림은 나중). v1 한계: 반복문 안에서 결과로 저장하면 칸 읽기가 그 저장을 기다리고 저장 주소는 열쇠를 기다림 — 마지막
  단계에서 풀리지만 대기 쓰기 규칙이 되돌림 → 열쇠·짝 없음(테스트로 고정).
- **oracle** `_check_separations`: 실행된 활성마다 [결과, 결과+N)과 모든 활성의 칸 위치가 겹치면 위반("separation").
- **테스트**(56): R007 모양(다시 쓰기 모델, N 0x38) → 원자 하나·A exact·B 제외·complete·두 가정 보고; 스위치 끄면 B 남음; 범위 밖
  [p1+0x40] 저장은 안 떨어뜨림; 칸 객체의 칸 밖 쓰기([this+8])는 결과에 닿음; 조건문 안 호출의 칸은 그보다 앞선 쓰기를 떨어뜨리지 않음
  (oracle silent 없음); 반복 한계; 검증 4가지; 실제 해석 본문 oracle 위반 없음, 칸 주소를 그대로 돌려주는 본문은 위반. 변형: 떨어뜨림 없음,
  결과 쪽 범위 넘음, 칸 쪽 아무 쓰기, 칸 쪽 끔, 기다림 없음, 호출 실행 무시, 지배 무시 — 각각 실패.
- 기록: `.census6/sr3_impl{,2}_{prompt,agy,astra}.md`.

### 25.24 같은 결과 접근 함수 4단계(S4): 라이브러리 내부 상태와 바이너리 안 함수 연결 → R007/R008 (2026-10-15, 구현 검토 Antigravity·Astra)

- **가정** `accessor-private-state`(스위치, 기본 끔). 엔트리 필드 `omits_private_writes` → `inherited`에 이 가정이 붙음: 끄면 기존
  검사(inherited ∩ disabled)로 import 호출은 opaque, 연결된 함수는 본문 분석.
- **연결 파일**(`summary_store.ModelBinding`, `load_binding_file`, `models/bindings/*.json`): id, executable_sha256(64 hex), language_id,
  abi_tag, models(그 파일 기준 경로 — import 이름으로는 절대 안 맞춤, 함께 검증, **선언 모델만**: 파생 요약은 거부), bindings
  [{rva, model, symbol?}](rva 하나씩, 모델 있어야 함; symbol은 사람용 메모).
- **적용**(`interprocedural._bound_cuts`): SHA-256·language가 이 프로그램과 같고 ABI가 이 실행의 모델 ABI와 같아야 함(다르거나 모델이
  없으면 오류); image base + rva가 프로그램의 함수여야 함(아니면 오류); 한 함수 두 번 연결은 오류; 꺼진 가정에 기대면 적용 안 하고 그
  함수의 `refused_models`에 이유. 적용하면 cut(`_cut_sites`가 호출·꼬리 점프를 모델 자리로) + 라벨
  `bound-model:<id>@<rva>#<연결 파일 digest 12>`, `AnalyzedFunction.bound_calls`(호출마다 연결 id·digest·rva·바이너리 SHA·모델 라벨·
  모델 파일 digest). summary_engine은 잘린 함수를 건너뜀 — 그 안의 호출이나 꼬리 점프가 출처/싱크면 오류.
- **도구**: run_dfbench `--binding`, dfbench_metric `METRIC_ARGS`, measure_program `--binding`(세 가정 켬 + run_dfbench와 같은 틀 가정:
  홈 공간 0x28·globals-disjoint·debug-break traps — 없으면 호출한 쪽 홈 공간 저장이 칸과 겹쳐 열쇠가 막힘; 모든 함수 본문을 실제로
  실행).
- **oracle**: 내부 쓰기를 뺀 모델의 호출이 범위 밖에 쓴 바이트 → `private_unchecked`; 호출한 쪽 읽기의 입력 중 그 활성 안에서 havoc된
  호출 값(("call", key))만 → `private_unchecked`(자리와 다른 입력은 그대로 검사; 첫 구현의 "의존 통째 면제"는 진짜 누락을 숨겨 Astra가
  재현 — 없앰); 인터프리터는 그런 활성 안에서 havoc하는 호출이 모델의 보존 레지스터를 건드리지 않게 함(`Interpreter(abi_calls=...)`:
  계약이 말하는 ABI — 실제 해석기는 win64 비휘발 레지스터를 지킴; 2차의 "보존 레지스터 면제"는 본문이 직접 덮어쓴 경우까지 숨겨 Astra가
  재현 — 없앰, 직접 덮어쓰기는 누락으로 보고); 결과가 havoc 값에 기대면 같은 결과·떨어짐 검사를 `same_result_unchecked`로.
- **모델**(`models/bound/tv2_tobjectptr_win64.json`, 실제 코드에서 읽음): ResolveHandle(rcx = 핸들 칸; 결과 rax는 rcx·rsp(본문이 값을
  스택에 저장했다 읽음)·칸에서; 다시 쓰기 줄; 그 밖 메모리 보존; observes rcx; omits_private_writes; same_result nonstack + write_back;
  떨어짐 범위 0x400 — R008은 +0x130/+0x138에 쓰고 핸들은 owner+0x478/0x480) / TrackAccess(DebugGame 추적 절반: 줄 없음,
  omits_private_writes, ResolveHandle 상태 보존). 연결: Development 0x4e10(해석 + 추적 inline), DebugGame 0xa970(해석) + 0x9200(추적).
- **결과**(세 가정 + 연결, `--assume-same-result-functions --assume-accessor-result-separate --assume-accessor-private-state --binding`):
  UE Development exact 16 → **18**(exact+sure 16 그대로), DebugGame 15 → **17**(15 그대로). R007·R008 모두 **A만**(B 제외), unsure —
  source_B 호출이 Get1과 Get2 사이에 있어 p1 ≠ p2(상태 바뀜), A는 p1 객체에서 may-alias로 옴(25.21의 예상대로). missing+sure 없음.
  oracle(같은 설정): Development missing 0·unexplained 0, 같은 결과 검사 0·위반 0·검사 못 함 16, private_unchecked 160; DebugGame
  missing 0, 같은 결과 검사 0·검사 못 함 20, private_unchecked 256 — UE에서는 모든 결과가 havoc된 호출 값에 기댐(인터프리터는 보존
  레지스터만 지키고 출력은 덮음 — 3차의 "rax까지 지킴"은 Astra가 재현한 잘못, 그때의 "검사 2"는 그 탓), 그래서 같은 결과는 합성 해석
  본문 테스트로만 검증됨. 스위치를 끄면 지표·oracle 그대로(전체 실행).
- **테스트**(70): 연결된 프로그램 안 함수가 잘리고 R007 모양 호출한 쪽이 A만·complete·라벨·호출별 출처; 내부 상태 끄면 본문 분석 +
  거부 이유; 다른 바이너리 SHA는 무시; 함수 아닌 rva·다른 ABI·모델 없는 실행은 오류; 연결 파일 검증 5가지 + 파생 요약 거부; import
  모델의 omits_private_writes는 스위치 필요; 연결된 본문 oracle(위반·누락 없음, 다시 쓰기 unchecked); 호출한 쪽이 보는 전역에 쓴 havoc
  값은 "write outside its run"으로 보고; 본문이 보존 레지스터를 직접 덮어쓰면 누락으로 보고; 한 함수 두 연결은 순서·스위치와 상관없이
  오류. 변형: 바이너리 무시, 스위치 무시, 내부 쓰기 라벨 없음 — 각각 실패. 한계: `bound_calls`는 직접 호출·꼬리 점프만(간접 호출이
  연결된 대상으로 풀려도 라벨은 inherited에 남음).
- 기록: `.census6/sr4_impl{,2}_{prompt,agy,astra}.md`, `.census6/run_ue_accessor.sh`, `.census6/diag_accessor.py`.

### 25.25 정방향 분석으로 풀 수 있는 것 — 표시 목록 (2026-10-15, 사용자 요청: 정방향으로 해결될 영역을 계속 표시)

앞으로 새 절은 남은 한계마다 **[정방향]**(정방향 사실이 가정을 대신하거나 결과를 바꿈), **[역방향]**(지금 엔진에 증명 규칙을 더해
풀림), **[가정]**(어느 쪽으로도 증명 못 함 — 이름 붙은 가정으로만) 중 하나를 붙인다. 지금까지의 것:

| 문제 | 표시 | 정방향이 주는 것 / 이유 |
|---|---|---|
| R005 배열 3단계, 가정 E (25.18) | [정방향] | 호출 지점 값 → index 범위·버퍼 크기 → "버퍼 안" 증명(`Fact` 입구, 25.18 6번)이 E를 대신 |
| R002/R009/R010 컨테이너·반복 (TArray/TMap) | [정방향] | index·길이·반복 횟수의 범위 → may-alias 구간이 좁아져 과잉 출처 제거 |
| 간접 호출 대상 (DFB072) | [정방향] | 함수 포인터 값(상수·vtable·전역에서 읽은 값)을 정방향으로 전파해 대상 확정 (지금은 설계만 규칙) |
| 콜백 (DFB091) | [정방향] + [가정] | 넘겨진 함수 포인터가 호출받은 함수 안 CALLIND까지 가는지는 정방향; 콜백이 하는 일은 그 함수 요약 또는 가정 |
| 크기가 레지스터인 모델 효과 (memcpy 등 `constants`) | [정방향] | 지금은 역방향 상수 증명(`_prove_extents`); 호출을 건너 계산된 값은 정방향이 더 넓게 앎 |
| accessor-result-separate (25.23) | 일부 [정방향] | 결과 객체가 어느 할당에서 왔는지·그 크기를 알면 범위 가정 일부를 증명으로 바꿈; 핸들과 객체의 관계 자체는 [가정] |
| R007/R008 "확실" (source_B 호출이 상태를 끊음) | [역방향] — 해결(25.26) | 본문 증명: 호출·저장 없음, 진입 스택 위치의 pop 반환; 전제 accessor-hidden-state-in-memory |
| same-result-functions 자체 (해석기가 결정적) | [가정] | 해석기가 간접 호출 + 숨은 상태라 어느 방향으로도 증명 못 함 |
| accessor-private-state | [가정] | 라이브러리 내부 상태에 프로그램이 닿지 않음 — 라이브러리 전체를 보지 않고는 증명 못 함 |
| 반복문 안에서 결과로 저장 (25.23 v1 한계) | [역방향] | 투영 순서와 대기 쓰기 규칙의 문제 — 정방향과 무관 |
| 요약 수준 떨어짐 (`_exit_crossings`, 25.23) | [역방향] | 요약에 짝을 실어 보내는 일 — 정방향과 무관 |
| 모델 `observes`(포인터가 새 나감) 정밀도 | 일부 [정방향] | 어떤 레지스터가 실제로 포인터인지 정방향 points-to가 알려 줌 |
| 요약된 호출의 관찰 레지스터·스택 탈출 (25.27) | [역방향] — 해결 | 완전한 효과만 정확한 집합; 불완전은 무조건 탈출(안쪽 호출 출력 추적이면 줄어듦 [역방향]) |
| 불투명 호출이 자기 스택 주소를 돌려줌 (25.27) | [가정] | 돌아온 뒤 수명이 끝난 주소 — 이름 붙은 가정으로 정리할 일 |
| once-join 주소 LOAD (25.27) | [역방향] — 해결 | 후보 자리마다 읽음; STORE는 원자 유지 |
| 플랫폼 가정(globals-disjoint, 홈 공간, 방향 플래그 등) | [가정] | ABI·실행 환경 규칙 — 증명 대상이 아님 |

### 25.26 상태를 바꾸지 않는 호출의 본문 증명 + import thunk로의 꼬리 점프 (2026-10-16, 설계 검토 4차·구현 검토 Antigravity·Astra) [역방향]

**증명**(`interprocedural._state_proof`, `ProvenCallEffect.state_proof`): Bundle 안 함수를 직접 CALL하고 그 요약이 정상으로 붙은
자리에서만(모델·템플릿·연결·시험 경계·재귀 가설·실패한 함수 제외), 다음이 모두 맞으면 그 호출은 모든 접근 함수의 상태를 바꾸지 않음:
- x86:LE:64(v1); 본문에 STORE·CALL·CALLIND·CALLOTHER·BRANCHIND 없음(저장이 없으니 반환 주소 칸도 그대로; 실제 CALL은 반환 주소를
  STORE하므로 호출 금지는 저장 금지와 겹침);
- 모든 출력이 unique·일반 레지스터([0x00,0x40), [0x80,0xC0) — 0x40..0x80의 세그먼트·FS/GS 기준 제외)·산술 플래그(CF PF AF ZF SF OF —
  TF IF DF 제외)·RIP;
- 명령 내부 p-code 흐름 없음, call·override 흐름 없음; 명령마다 p-code가 말하는 다음 위치 집합(RETURN → 없음, BRANCH → 대상, CBRANCH →
  대상 + fall-through, 그 밖 → fall-through)이 관찰된 다음 위치(`control_successor_coordinates`)와 **같고** 모두 함수 안(메타데이터와
  p-code가 다르면 스택 계산과 실제 경로가 갈라짐 — Astra 재현);
- 모든 RETURN이 RSP를 통한 pop 반환 모양(`may_alias._return_shape` = ((0x20, 8), 프로그램 메모리 공간))이고 그 LOAD에서 RSP가 진입
  값과 같음(`stack_offset_at` == 0) — 저장이 없으니 [S]는 호출한 쪽이 넣은 반환 주소: 원래 자리로 돌아감(`lea rsp,[rsp-8]; ret 8`,
  다른 레지스터로의 반환 모두 거부);
- 모든 RETURN의 LOAD는 8바이트;
- 호출 자리: 관찰된 호출 모양이 정확히 {RSP(0x20, 8): -8}이고 CALL이 프로그램 메모리 공간(돌아갈 자리를 넣은 push가 본문의 pop과 같은
  것 — 다른 레지스터로 push하는 CALL은 거부, Astra 구현 1차 재현), CALL 명령이 정확히 `RSP -= 8; STORE [RSP] <- 다음 명령 주소(8바이트);
  CALL` 세 연산(`_plain_push_call` — push 뒤에 덮어쓰면 반환이 다른 곳으로, Astra 구현 2차 재현), `restores_stack`, `preserves_memory`, 메모리 run·unknown memory·
  writer 조건·꼬리 합성·실패 조건 없음, 돌아오지 않음 아님.
**전제**(Astra 2차 P0): `accessor-hidden-state-in-memory`(reported) — 접근 함수의 숨은 상태는 스택 밖 메모리와 기계 상태(세그먼트·TLS
기준·제어 레지스터)에 있고, 결과는 레지스터에는 선언된 inputs로만 기대며, 증명된 본문이 읽는 메모리는 읽어도 부작용이 없음(사용자
모드 프로그램의 일반 RAM). 증명을 쓴 열쇠가 있으면 보고. `normalize._accessor_states`는 그 호출에서 상태를 그대로 두고 출처에
"proof:<이유>"(진단용, 가정 라벨 아님)를 남김. 1차안("호출 없음"만)은 테이블에 직접 쓰는 setter 반례로 거부됨(Astra), 2차안은
레지스터에 있는 숨은 상태·반환 주소 덮어쓰기·세그먼트 쓰기·MMIO, 3차안은 원래 자리로 돌아감 증명, 4차안은 메타데이터와 p-code의
다음 위치 일치가 빠져 각각 보완. 전이(순수 함수만 부르는 함수)는 나중.
**꼬리 점프**: 끝 명령의 `jmp` 대상이 Bundle 밖 import thunk면(관찰된 흐름도 그 thunk 하나) `jmp [slot]`처럼 그 모델을 꼬리 호출로
적용(`import_call_sites`); 대상이 프로그램 함수의 입구면(잘린 함수 포함) 그 본문으로 합성하거나 모르는 꼬리 출구로 남김 — 모델로 대신하지도,
외부 모델 사용으로 보고하지도 않음(Astra 구현 1차 재현); 돌아오지 않는 모델(abort)은 계속 `_noreturn_jumps`. 09에 debug 1·release 4개
(`jmp free`) — oracle의 모델 호출 수 debug 24 → 25, release 18 → 22, 지표·누락 그대로.
**결과**(접근 함수 가정 셋 + 연결): UE Development exact+sure 16 → **18**, DebugGame 15 → **17** — R007·R008이 A만·**확실**.
`ENGINE_SEMANTICS_VERSION` 8 → 9(FString 템플릿 다시 만듦, 같음).
**테스트**: 순수 함수 사이 → 원자 하나·A exact·sure·전제 보고; 거부 8가지(테이블 setter, push/pop, 순수 함수 호출(전이 없음),
CALLOTHER, 세그먼트 쓰기, `ret 8` 모양, 레지스터 RETURN, pop 후 다른 레지스터로 반환); 메타데이터와 p-code가 다른 분기 거부; 실제 순수
본문 oracle; 템플릿 왕복 테스트는 증명 없음을 "더 약함"으로 허용; `jmp free` 꼬리 호출 3가지. 변형: 다음 위치 검사 끔, 저장 허용,
출력 검사 끔, 반환 모양 검사 끔, 증명 안 붙임 — 각각 실패("호출 허용"은 저장 금지와 겹쳐 같은 동작).
- 기록: `.census6/callfree{,2,3,4}_{prompt,agy,astra}.md`, `.census6/diag_callfree.py`, `.census6/thunk_tail_status.py`.

### 25.27 역방향 정밀도 묶음: 호출의 스택 탈출 · 관찰 레지스터, once-join 읽기, import 칸 보고, 돌아오지 않는 모델 (2026-10-16, 설계 검토 2차·구현 검토 2차 Antigravity·Astra) [역방향]

**1. 요약된 호출이 보는 레지스터와 스택 탈출**(`call_summary_effects.derive_proven_call_effect`, `ProvenCallEffect.escapes_stack`).
- 발견한 구멍(Astra 재현): 호출받는 함수가 `rax = rcx; ret`이면 예전에는 "레지스터를 주소로 쓰지 않음"(`observes_registers` 거짓)으로
  보아, rcx에 프레임 주소가 있어도 호출이 탈출이 아니었음. 호출한 쪽의 스택 오염 추적(`_stack_taint`)은 호출 출력을 따라가지 않으므로
  `mov [전역], rax`도 탈출로 안 잡힘 → 개인 프레임 규칙이 프레임을 잘못 믿음.
- **완전한 효과**: 안쪽 호출 없음, 메모리 보존, 어느 바이트도 값 모름 아님(스택 포인터 바이트 포함 — 빼기 전에 검사), 스택 포인터 복구,
  모든 sink 요구 완전. 그때만 `observed_registers` = 모든 레지스터 run·메모리 run·sink 요구의 reads + 읽기·쓰기·모르는 메모리·조건
  자리의 뿌리 기준 레지스터(포인터 사슬을 따라감) − 호출한 쪽 자신의 스택 포인터. 완전하지 않으면 None(모든 레지스터).
  `rax = rcx; ret` → rcx를 봄 → rcx가 프레임 주소면 그 호출이 탈출. `rax = rdx + 1` → rdx만 봄 → rcx의 프레임 주소는 그대로 개인.
- **스택 탈출**: `escapes_stack = 완전하지 않음 또는 summary.stack_values_out`. `stack_values_out`(`may_alias.stack_values_out`)은
  호출받는 함수 자신의 p-code에 스택 오염 추적을 돌려, 스택 포인터에서 나온 값이 스택 포인터 말고 다른 레지스터에 남은 채 RETURN에
  닿거나, 안에서 탈출(그런 값을 STORE·메모리 출력·CALLOTHER로 내보내거나, 그런 값이 레지스터에 있는 채 CALL)하면 참; 스택 포인터나
  블록 그래프를 모르면 참. 이런 호출은 호출한 쪽에서 무엇이 오염됐든 탈출(`escaping_calls` → `private_frame_writes`·
  `derive_may_alias_reads`, 조용한·가정된 호출보다 우선). 설계 2차의 "reads가 스택 레지스터와 겹침" 규칙은 모든 함수의 `ret`
  (rip = [rsp])과 프레임 다시 읽기가 rsp를 주소로 읽어 모든 호출을 탈출로 만들어(Antigravity 2차 P1, 측정으로 확인) 이것으로 바꿈;
  불완전 → 탈출은 Astra 의견대로 유지(Antigravity는 정밀도 손실을 우려 — 지표는 그대로).
- 구현 검토 1차 Astra 반례: `COPY ram[x], rsp`(STORE 없이 메모리 varnode로 직접 씀)를 놓침 → 출력이 레지스터·unique가 아닌 연산에
  오염된 입력이 있으면 탈출(연산 종류 무관; 호출한 쪽 추적에도 적용). Antigravity 제안: 재귀 가설(`_bottom_summary`)은 탈출 없음에서
  시작해 반복으로 올림.
- 선언된 모델(`model_effect`)은 바뀌지 않음: 선언된 `observes`, `escapes_stack` 거짓. 시험용 경계도 거짓.
- 템플릿에 `stack_values_out` 실음(`TEMPLATE_VERSION` 2). FString 다시 만듦: 생성자·소멸자 그대로(거짓); `AppendChar`는 HEAD에서
  "어느 호출자도 못 찾는 객체의 writer 조건"으로 거부됐는데, 안에서 탈출이 늘어 그 writer들이 조건 없는 모르는 writer가 되면서 템플릿이
  됨(모르는 writer 2개 — 메모리 보존 아님, 이 변경으로 이분 탐색해 확인).
- 남은 한계: 불투명(요약 없는) 호출이 자기 스택 포인터에서 만든 주소를 돌려주는 경우는 호출한 쪽 추적이 못 봄 — 지금까지와 같음
  (C/C++에서는 돌아온 뒤 그 주소는 수명이 끝난 매개변수·지역 변수) **[가정]** — 이름 붙이기는 다음 일; 요약된 호출의 불완전 효과는
  무조건 탈출이라 정밀도를 잃음 — 안쪽 호출의 출력을 따라가는 추적이면 줄어듦 **[역방향]**; 어떤 레지스터가 실제 포인터인지
  **[정방향]**.

**2. import 칸으로 붙인 모델 보고**(`interprocedural._external_sites`): `call [slot]`, 끝 `jmp [slot]`, `mov r, [slot]; call r`(`:CALLIND`·
`:BRANCHIND` 열쇠)에 붙은 모델은 상속 라벨에 `import-slots-hold-their-exports`가 붙음 — 스위치(`_import_slots_switched_on`)만으로 판단
(전역·스택 분리와 묶지 않음); 끄면 그 호출은 불투명 + 거부 이유. `measure_program.py --models`는 실행 기본값처럼 이 가정을 켬(안 켜면
UE 오라클의 모델 호출 수가 71 → 11로 줄었음 — 칸으로 붙인 모델이 이제 정직하게 가정을 요구하기 때문). [가정]

**3. once-join 주소의 LOAD**(`relative_memory._Projector._candidate_expressions_for_input`): 25.17 이후 JOIN이 once-join 원자 하나(wild
index 객체)가 되어 LOAD가 정확한 후보 자리 대신 wild 객체 하나를 읽던 것을, 원자가 정확히 once-join 하나(계수 1, 변위 0)이고 JOIN의
후보 식이 모두 알려지고 2개 이상(최대 8)이면 각 후보 자리를 읽음. STORE는 원자 유지(어느 자리에 썼는지 확정 못 함). [역방향]

**4. 돌아오지 않는 모델**: `longjmp`(crt_win64 observes rcx, crt_sysv64 observes rdi — jmp_buf를 읽음; setjmp 쪽은 영향 없음, 호출 뒤
경로만 끊김), `__stack_chk_fail`(sysv, observes 없음). 모델 파일 v6. 실제 import: 09 debug·release·win32 longjmp 각 1, zlib
`__stack_chk_fail` 5. `TerminateProcess`는 다른 프로세스 핸들이면 돌아오므로 제외. [가정](모델)

**결과**: dfbench 지표 모두 그대로(09 66/62, release 53/48, win32 44/37, UE 15/15, 16/16; 접근 함수 가정 셋 + 연결 17, 18); 프로그램
오라클 누락 0(zlib 256은 원래). 오라클 모델 호출 수 09 debug 25 → 26, release 22 → 23(longjmp·칸 모델), UE 71·73 그대로.
UE Development의 place_failed 168 → 232: 탈출이 늘어 점검한 자리가 568 → 632, 늘어난 실패 64개는 모두 부채로 설명됨
(place_failed_debt = place_failed; 탈출 집합을 비우면 168로 돌아감 — `.census6/dev_place_bisect.sh`). 더 보수적이 된 것이지 놓친 것 없음.
`ENGINE_SEMANTICS_VERSION` 9 → 10.
**테스트**: `test_call_stack_escape.py` 9개(rcx를 돌려줌 → 탈출, rdx만 읽음 → 개인 유지, 프레임 주소 없으면 개인, `lea rax,[rsp+8]` 탈출,
esp 일부 겹침, 메모리 출력 COPY, index 주소로 불완전, 안쪽 호출, 선언 모델 그대로), `test_precision_batch.py`(once-join LOAD 후보 —
변경을 끄면 실패, once-join STORE, JOIN 뒤 다시 쓴 후보 자리, 모델 항목, longjmp 경로 끊김), `test_external_models.py`(칸 꼬리 점프 라벨·끔).
`test_definition_atoms.py`의 wild 변형 테스트는 탈출 집합도 비워야 놓침이 드러남(새 규칙이 같은 구멍을 함께 막음). 변형 9개 중 8개
잡힘; 포인터 사슬 따라가기는 뿌리 레지스터가 이미 reads에 있어(주소 입력도 출처) 보조로 남김.
- 기록: `.census6/batch{,2,3,4}_{prompt,agy,astra}.md`, `.census6/noreturn_imports.py`, `.census6/why_append*.sh`, `.census6/oracle_bisect*.sh`.

### 25.28 연산 기록(operation records): 값이 어떤 연산을 거쳐 왔는지 (2026-10-16, 설계 검토 3차·구현 검토 Antigravity 4차·Astra 4차) [역방향]

**목적**(사용자): 결과 확인·디버깅, 그리고 나중에 가상화(VM) 코드·인터프리터 분석 — 핸들러의 의미("vreg[a] = vreg[b] + vreg[c]")는
그 핸들러 함수 각 출력의 연산 식. 지금 요약은 출력이 기대는 바이트(종류 + sources)만 갖고 연산은 버림. 진단 전용: 켜도 라벨·완전성·
요약·템플릿·가정은 그대로(09 debug·release·win32·UE Development에서 켜기/끄기 JSON이 기록 말고 같음을 확인).

**형식**(`src/tdo_v2/operation_records.py`, 기록 하나 = 식 그래프, 노드 표 + id):
- `op`: 연산 키·주소·순번·opcode·출력, `operands`는 p-code 입력 순서, 각 입력은 `parts`(`{node, bytes: [a,b), at: [c,d)}` — 만든 쪽 값의
  a..b 바이트가 입력의 c..d 바이트; 여러 정의의 조각을 이어 붙임, `al` 쓰고 `rax` 읽기 등)로 조립; 결과에 안 쓰이는 바이트는
  `pruned`(정확한 바이트 지도가 있는 연산만; 계산에서는 0). 역할: value / address / space / target. LOAD는 `memory`(후보 자리별 읽은 바이트),
  STORE는 주소·값 입력을 가진 `op`. 같은 레지스터끼리 xor/sub(엔진이 읽지 않음)는 `value: 0`.
- `const`, `entry`(레지스터, 절대 주소, 상대 객체는 원자 설명 + 변위), `phi`(**대안**: 이 중 하나 — JOIN, 출구 run의 여러 정의, 조각의
  여러 정의, 여러 writer; SSA에 선행자 선택이 없어 어느 쪽인지는 모름), `call`(요약된 호출의 출력 행 하나 — `~in`·`~ld`·`~iu` 등 준비
  행은 접어서 역할 붙은 `inputs`로; callee·출처(summary / external-model / derived-model / test-only-boundary ...)·모델 라벨·판단 사실:
  restores_stack, preserves_memory, escapes_stack, noreturn, state_proof, writer 조건 수), `debt`(종류·자리·선행 노드 — may-alias는
  writer STORE 노드, 주소·값 둘 다), `override`(증명된 rep 뒤 주소 평가기가 쓰는 연산, 관찰된 연산은 `replaced`; 증명 안 된 rep은
  `override: "unproven"`), rep 원소(`rep_iteration`, 원소 크기, 방향, 변위), `cut`(한도).
- `origins`: 엔진이 라벨을 붙인 노드(입구 정의, 호출 run 정의, 선언된 source 호출, call-clobber 부채, `~sink`)에 그 라벨.
- 반복으로 돌아오는 값은 `loop: true` 표시가 붙은 역참조.
- 요약 run 기록은 run 종류·crossing·조건·부채·writer 조건·`unknown_writers`·`tail_exits`를 같이 실음(`7을 쓰고 모르는 호출 뒤 반환`이
  "7"로만 보이지 않게). root 기록은 완전성과 함수 전체의 풀리지 않은 쓰기 수를 따로 실음.
- **root별 가정 목록은 없음**: 쓰기·부채를 빼는 방식으로 작동하는 가정(개인 프레임, 전역·스택 분리, 읽기 전용 이미지, import 칸,
  불투명 호출의 스택 복구, 트랩)은 root 하나에 귀속할 수 없음 — 실행 전체 목록(`EngineRun.assumptions`)이 기준. 기록은 호출 노드에서
  관찰된 출처만(`partial_provenance` 명시).

**만들기**: 먼저 `lane_slice`로 바이트 수요의 고정점을 구하고(새 `budget` — 다 못 하면 `truncated`, 고정점 주장 안 함), 그 수요로 노드를
만듦(그래프 노드당 하나). 시작점: root는 sink 행(노드 + 물리 바이트), 요약 run은 그 정의들(여럿이면 phi). 한도: 노드·간선·깊이·부채당
writer 수(`Limits`); 넘으면 `cut`과 `truncated`(분석의 완전성과 별개).

**계산과 검증**(`evaluate`, `eligibility`): 잘림·반복·부채·rep·증명 안 된 rep·지원 안 하는 연산·결정 못 한 입력·정확하지 않은 run이
없는 기록만 같음을 검사(반복 검사는 phi보다 먼저); phi는 기록 전체에서 값 집합(같은 phi는 한 번의 선택, 조합 수 한도) — 포함 검사이지
경로 가능성 검사는 아님. 호출 출력은 주입 함수가 있어야 계산. 오라클(`tests/intra/record_oracle.py`): 함수를 실제 값으로 실행해, 나간
출구의 레지스터 run 기록이 최종 레지스터 바이트를 허용하는지 — 값 계산 함수 100개에서 3,426개 계산·실패 0, 별칭·반복이 섞인 무작위
함수 100개에서 1,254개 계산·실패 0(건너뜀은 이유별로 셈: 부채 256, 반복 275, 정확하지 않은 run 21 ...). 대안 중 하나라도 계산할 수
없으면 결과 없음(그것이 실제로 간 쪽일 수 있음); 실행이 읽지 않은 입구 바이트는 오라클이 고정값을 줌(실행 값이 그에 기대지 않음).
망가뜨린 기록(피연산자 뒤바꿈, 상수 틀림, 바이트 범위 틀림, phi 대안 빠짐)은 검사기가 거부.
**구현 검토에서 고친 것**: 접힌 준비 행의 부채·라벨을 호출 노드에(Antigravity P1-1); 여러 writer phi의 바이트 범위(P1-2); LOAD가
합류를 거쳐 입구 메모리를 읽을 때 실제 주소에서 읽음(P1-3); 호출 한 행이 쓴 서로 다른 출력(rax, rbx)은 `output`으로 구별(Astra P1-1);
선택 범위가 여러 개이거나 겹치는 root는 계산 안 함(Astra P1-2, Antigravity P2-1); 깊은 사슬에서 Python 재귀 한도 대신 깊이 한도로
자름 — 만들기·계산 모두(Astra P1-3, P2); 한도로 멈춘 노드도 모양을 갖추고 `interrupted` 표시(Astra P2-4); 수요 계산의 바이트 한도는
만들기 전에 누적 차감(Astra P2-5, 4차); 한도·수요 한도 넘으면 `cut`.

**도구**: `run_dfbench --records`(root마다 `--json`의 `record`, 기대 케이스는 텍스트로 출력), `tools/graph_fidelity/derivations.py
<generation> --function <entry>`(함수 하나의 출구별 출력 식 — 핸들러 분석용).

**남은 한계**: callee 안까지 식 이어 붙이기(2단계, 호출 노드가 callee와 쓴 바이트를 이름으로 가짐) [역방향]; 식 정리·같음 판정(z3,
3단계) [역방향]; phi의 어느 쪽 경로였는지 [정방향](분기 조건 사실); 반복의 최종 값 [정방향]; 가상화 디스패치·operand로 고르는 가상
레지스터 [정방향]; root별 가정 귀속(제외 방식 가정) [가정 — 귀속 불가, 실행 단위 목록만].
**테스트**: `test_operation_records.py`(오라클 8), `test_operation_record_shapes.py` 29개(조각난 입력, x op x, LOAD/STORE 역할, phi, 반복,
요약 호출 접기와 판단 사실, 준비 행 부채, 한 행의 두 출력, may-alias writer, 합류를 거친 입구 메모리, 한도·수요 한도·바이트 누적,
깊은 사슬 만들기·계산, origins, rep·override·증명 안 된 rep의 횟수 레지스터, 잘린 바이트 0, 계산 못 하는 대안, 여러·겹친 선택 범위,
망가뜨린 기록 거부). 변형 13개 잡힘(합류 대안이 조각 일부만 덮는 경우의 보호 장치 1개는 실제로 생기지 않아 남음).
- 기록: `.census6/oprec{,2,3}_{prompt,agy,astra}.md`, `.census6/records_identity.sh`.

### 25.29 A단계: 정방향 전에 결과를 믿을 수 있게 — 오라클 규약, 분석 깊이, 이름 없는 가정 (2026-10-16, 검토 Antigravity·Astra)

**A-1 zlib 오라클 누락 256 — 오라클 결함**: 함수 `1b1:109730`의 `call memcpy@plt` 뒤 `mov rcx, rax`. 엔진은 crt-sysv64 모델대로
`rax = rdi`(맞음), 오라클 해석기는 모델이 붙은 외부 함수(memcpy, strcpy, strlen, malloc, realloc, free ...)를 win64 인자(rcx, rdx, r8)와
win64 보존 레지스터로만 실행해 `rax = rcx`로 계산. 고침: `Interpreter(external_abi="win64"|"sysv64")` — 인자 레지스터
(rcx, rdx, r8 / rdi, rsi, rdx)와 보존 레지스터를 규약별로; `program_oracle.check_program`·`lane_oracle`(measure_program --lanes)도 넘김;
`measure_program.py`는 `run_dfbench.abi_of`가 sysv64면 그 규약. zlib 누락 256 → **0**. 엔진 결과는 처음부터 맞았음(이 불일치에 한해).
테스트: `test_external_models_sysv.py`(sysv 규약은 누락 0, win64 규약은 같은 거짓 누락을 재현).

**A-2 분석 깊이**: 서로 기대는 값 약 250개의 사슬에서 `relative_memory`의 식 계산(정의 → 연산 → 입력, 재귀)이 Python 재귀 한도에 걸려
분석 전체가 멈춤. 고침(계산 방식은 그대로): `analyze_units`가 실행 동안 Python 재귀 한도를 `ANALYSIS_RECURSION_LIMIT`(20000)로
올림(끝나면 되돌림; 프로세스 전체 설정이라 분석은 직렬); 재귀 경로의 generator 식을 리스트로 바꿔 단계마다 C 스택을 쓰지 않게 함
(Antigravity P0 — generator는 C 스택을 써서 Python 한도보다 먼저 프로세스가 죽을 수 있음); 그래도 넘는 함수는 그 함수만
`NormalizationFailureReason.ANALYSIS_DEPTH`(요약 없음 → 부르는 쪽은 모르는 호출), 그 함수의 import 칸 사용 표시도 지움. 깊이 제한에서
`None`(모름)을 돌려주는 방식은 캐시 때문에 결과가 계산 순서에 따라 달라져서 택하지 않음(두 리뷰어 같은 의견). 측정: 6,000개 사슬 2초에
분석, 10,000개는 그 함수만 실패. 테스트: `test_analysis_depth.py`. [역방향] 반복형 계산기로 바꾸면 한도 자체가 사라짐(나중).

**A-3 가정 `opaque-callees-leave-no-stack-addresses`**(switch, 기본 켬): 25.27에서 찾은 이름 없는 가정을 등록. 요약 없는(불투명) 호출은
자기가 볼 수 있는 레지스터에 스택에서 나온 값이 있을 때만 스택 탈출로 봤음 — 호출받는 쪽이 자기 스택 포인터에서 만든 주소(스택으로 넘어온
인자·홈 공간의 주소 = 호출한 쪽 프레임)를 돌려주거나 남기는 경우는 못 봄. 끄면 모든 불투명 호출이 탈출. **사용 단위로 보고**: 실제 탈출과
"불투명 호출도 탈출"인 두 번째 탈출 구조를 같이 계산해, 앞의 것으로는 개인이고 뒤의 것으로는 아닌 바이트가 있을 때만(읽기 앞·쓰기 뒤·
반복 경로 모두 같은 구조) 보고. 요약된 호출은 25.27의 `escapes_stack`, 선언 모델은 계약. 연결(linking)·`derive_models`·
`summary_engine`·`run_dfbench`(`--no-assume-opaque-callees-no-stack-addresses`) 모두 전달; 끈 실행에서는 그 가정에 기댄 템플릿 거부.
`ENGINE_SEMANTICS_VERSION` 10 → **11**(예전 템플릿은 이 가정에 이름 없이 기댐 — Astra); FString 다시 만듦(같음, 불투명 호출 없음).
문구에서 "C/C++ 수명이 보장" 주장은 뺌(수명이 끝나도 값은 레지스터·메모리에 남음 — Astra). sret(구조체 반환 버퍼)은 예외 아님:
호출한 쪽이 준 주소를 돌려줌(두 리뷰어 확인). 테스트: `test_opaque_stack_addresses.py` 10개(켬/끔, 이미 탈출인 호출, 불투명 호출
없음, 템플릿이 라벨을 실음·끈 실행에서 거부·켠 실행에서 적용·버전 10 거부, 호출 앞 읽기는 기대지 않음·호출 앞 쓰기는 기댐·반복으로
호출이 읽기 앞에 오면 기댐). 보고가 조금 넘칠 수 있음(쓰기 판정은 겹칠 객체가 없어도 이뤄짐 — 안전한 쪽, entry-values와 같은
방식; Antigravity P2). [가정]

**A-4**: 예전 의심(`function_summary.stack_pointer_escapes`)은 `1dec4e0`에서 `_stack_taint`로 바뀌며 이미 해결 — 닫음(두 리뷰어 동의).

**기타**: 브랜치를 오가며 git이 `.sh`를 CRLF로 다시 써 WSL 지표 스크립트가 깨짐 → `.gitattributes`에 `*.sh text eol=lf`.
- 기록: `.census6/stepA{,2}_{prompt,agy,astra}.md`, `.census6/zlib_missing.sh`, `.census6/zlib_probe.py`.

### 25.30 A-5 큰 함수: 멈추지 않고, 결과는 그대로, 넘치면 "불완전"으로 (2026-10-16, 설계 검토 6차·K1a 구현 검토 Antigravity 3차·Astra 3차)

**목표(사용자)**: 검수 중인 게임 클라이언트의 한 함수 — 코드 194,636바이트(명령 약 4.3~4.5만 개, p-code 약 20~26만 개), 서로 다른
피호출 함수 980개(내부 977, import 3), std::function·COM·가상 호출과 값 난독화 래퍼(`_ZtlSecureGet_*`)가 많고 실행 파일 약 256 MB —
"이 정도도 대응 가능해야 함". 지금까지 가장 큰 함수는 zlib inflate(명령 2,343, p-code 13,737). 계약: 프로세스가 죽지 않고, 지금
분석하는 모든 것의 결과는 바뀌지 않으며, 시간·메모리는 한정되고, 한도를 넘으면 그 사실이 형식이 있는 "불완전" 결과로 남음.

**phase 0~1(17e9bea)**: 의미 스냅샷(`tools/graph_fidelity/semantic_snapshot.py` — 모든 Bundle·설정의 정규화 결과·요약·호출 효과·루트를
정해진 형식으로 기록, 비교; 큰 함수 예제 `tests/intra/large_fixtures.py`)과 action별 읽기 색인(선형 탐색 5곳 제거, zlib 144 s → 118 s).
이후 모든 단계는 이 스냅샷과 같아야 함.

**설계 결정(검토 4~6차)**:
- 재귀 문제는 **T+C**: 지금은 큰 스택의 분석 전용 스레드(T, 엔진 코드 변경 없음 → 결과는 구조상 같음), 계산기를 코루틴으로 바꾸는 것(C)은
  측정에서 T의 한도가 실제로 문제일 때만(두 리뷰어 같은 의견). 측정: 1 GiB 스택에서 의존 값 3만 개 사슬 7 s / 415 MB, 2 GiB에서
  6만 개 14.5 s / 820 MB.
- 순서(Astra): **K1 격리**(작업 스레드, 함수별 실패 계약, 예산 장부, 외부 감독) → **K2 측정**(250k op까지 키운 합성 함수, 단계별 계측) →
  **K3 동작 보존 최적화**(스냅샷이 같아야 함) → **K4 실제 대상**(선택 함수 내보내기 모드 + 범위 계약, PE x64 예외 영역 포함) →
  **K5 코루틴**(필요한 곳만).
- 받아들이는 기준(잠정, K2 뒤 확정): 기존 스냅샷 그대로; 250k op 예제 10분 / 8 GiB 안; 실제 대상은 끝나거나 형식 있는 불완전 실패;
  감독 프로세스 12 GiB 강제 한도, 마감 + 30 s 유예, 고아 프로세스 없음; 협력적 만료는 1 s 안에 관측.

**K1a 구현(이 커밋)**:
- `resource_limits.py`: `RESOURCE_FAILURES`(RecursionError, MemoryError, `AnalysisBudgetExceeded`); `run_analysis` / `@analysis_entry` —
  바깥 진입점 하나마다 분석 스레드 하나(Linux CPython ≥ 3.14만; 그 밖이나 `TDO_V2_ANALYSIS_WORKER=0`이면 그 자리에서 실행), 안쪽
  진입점은 그 스레드에서 그대로, 재진입 잠금(RLock, 그 자리 실행도 잡음), contextvars 한 번 복사, `TDO_V2_ANALYSIS_STACK_MB`(64~16384,
  기본 1024) 검증, 재귀 한도는 MB × 200으로 올렸다가 끝나면 복원, 결과·예외(traceback 포함) 전달 후 참조 순환 끊음. Ctrl-C는 스레드를
  만들기 전부터 끝날 때까지 기록만 하고, 끝난 뒤 원래 처리기에 전달(기본은 KeyboardInterrupt; 돌아오는 처리기면 결과 유지).
- 진입점 4곳: `analyze_units`, `analyze_frozen_bundle_with_summaries`, 예전 엔진 `analyze_frozen_bundle`, `derive_library`.
- 함수별 실패(`interprocedural`): RecursionError → `ANALYSIS_DEPTH`, `AnalysisBudgetExceeded` → 새 `ANALYSIS_BUDGET`, 그 함수만 실패하고
  실행 동안 고정(재귀 묶음·간접 호출 라운드에서 다시 시도하지 않음); MemoryError는 실행 실패. 스택 전환 검사가 넘치면 그 함수
  `("unchecked",)`(가정 철회); 간접 호출 대상 검사가 넘치면 그 함수 실패(한 라운드 추가, 함수마다 최대 한 번); 상태 증명이 넘치면 그
  증명이 필요한 함수 실패(조용히 "증명 없음"으로 두지 않음).
- `summary_engine`: 자원 실패 함수는 더 이상 실행 전체의 ValueError가 아님 — `EngineRun.failed_functions`((키, 이유) 정렬)와,
  그 함수의 문법상 싱크 위치마다 불완전 루트(호출 위치 = 호출 seed 번호, 꼬리 점프 = 호출 수 + 꼬리 번호, 묶을 때와 같은 번호; 노드 없음,
  라벨 없음, 완전성 거짓, `explanation["failure"]`). 그 함수의 호출을 거친 투영 루트는 나열하지 않음(`failed_functions`에 문서화).
  싱크 묶기·루트 slicing도 함수별: 거기서 넘치면 그 함수의 중간 결과를 버리고 실패 함수로; 그 요약을 이미 쓴 호출자의 투영 루트는
  불완전 + `explanation["rests_on_failed"]`(분석 중 실패한 함수는 호출자에게 이미 모르는 호출이라 해당 없음). 다른 정규화 실패는 그대로 ValueError.
- 넓은 예외 처리: 오류를 판정으로 바꾸는 `except Exception` 16곳과 RuntimeError를 잡던 2곳(`configured_finite_root_replay`,
  Bundle 입력 `configured_bundle`)에서 자원 실패는 먼저 다시 던짐. `linking.py`의 것은 다시 시도하는 INFRASTRUCTURE 실패라 그대로.
  `configured_recursive_frame_inventory`의 RecursionError → `BUDGET_EXHAUSTED` 빚(명시적 불완전)은 유지. 연산 기록(25.28)은
  계약상 예외: 깊어서 잘리면 기록 안에 `cut`(reason "recursion")이 남고 루트 완전성은 영향 없음.
- 파생 템플릿: 내보낼 함수의 닫힘에 자원 실패 함수가 있으면 `TemplateRefused(kind="transient")` — linking이 저장하지 않고 다음 실행에서
  다시 시도(예전에는 "no summary" 의미 거부로 저장됐음). `derive_library`의 export별 처리에서 MemoryError는 실행 실패.
- 도구: `semantic_snapshot`의 `ADDED_FIELDS`(빈 `failed_functions`는 기록하지 않아 예전 기준과 비교 가능), `fixture_snapshot`도 분석
  스레드에서 실행.

**검토**: Astra 1차 4건(P1 Ctrl-C가 살아 있는 스레드를 두고 잠금을 풂, P1 나중 실패의 의존 루트가 완전으로 남음, P2 RuntimeError 처리,
P2 기록), Antigravity 1차 6건(P1 간접 대상·상태 증명 실패가 조용히 사라짐, P1 Ctrl-C, P2 참조 순환, P2 그 자리 실행의 잠금·검증,
P2 derive의 MemoryError) — 모두 반영. 2차: Astra P2(돌아오는 처리기에서 결과 유실), Antigravity 승인 + P2 3건(간접 라운드 예산, 같은 건,
나중 실패만 의존 표시) — 반영. 3차: 아래 기록.

**검증**: 전체 테스트, 의미 스냅샷이 phase 1 기준과 모두 같음 — 의도한 차이 하나: 예제 chain-8k(예전 주 스레드에서 `ANALYSIS_DEPTH`,
지금 분석 스레드에서 분석됨). 기준의 알려진 실패(`v2-win-debug-full.legacy`: write-event 고정점 불안정)는 그대로. 테스트:
`test_resource_limits.py`(스레드·한도 복원·안쪽 진입점·traceback·contextvars·끄기·크기 검증·서명·1만 개 사슬; 고정 실패·이유·
MemoryError; 스택 전환·간접 대상·상태 증명; 넓은 처리기; 실제 Bundle에서 강제 실패한 함수의 실패 루트; 템플릿 transient; Ctrl-C 유예와
돌아오는 처리기; 의존 루트), `test_analysis_depth.py`는 주 스레드에서(작업 스레드 끔).

**남은 한계**:
- [역방향] 실패한 함수의 호출을 거친 투영 루트는 나열되지 않음(`failed_functions`가 그 공백을 알림). 요약을 함수 일부만이라도 만들면 줄어듦.
- [역방향] 한도는 사라진 것이 아니라 옮겨짐(스택 크기와 메모리에 묶임): K5에서 필요한 곳만 반복형으로.
- [가정] 작업 스레드는 Linux CPython ≥ 3.14에서만 검증(3.14는 실제 C 스택을 검사); Windows·3.13에서는 예전 한도로 그 자리 실행.
- 아직 없음(다음): K1b 예전 엔진의 함수별 실패 계약, K1c 예산 장부·구조 한도·ValueError 상한 → `ANALYSIS_BUDGET`, K1d cgroup-v2 감독 +
  내보내기 시간 한도, K2~K5.
- 기록: `.census6/stepA5{,b,c,d,e,f,g,h,i}_{prompt,agy,astra}.md`, `.census6/k1a.diff`.

**K1b·K1c (2026-10-19, 설계 검토 3차·구현 검토 Antigravity·Astra)** — 위 "아직 없음"의 K1b·K1c.
- **K1b 예전 엔진(기준용)**: 함수 하나의 정규화가 자원을 다 쓰면 실행 전체가 형식 있는 실패(`UnresolvedBundleFunctionError`,
  `ANALYSIS_DEPTH` / `ANALYSIS_BUDGET`); 전체 프로그램 단계·루트 단계의 자원 실패는 진입점 밖으로(부분 루트 없음). 함수별 계약(L2)을
  택하지 않은 이유: 이 엔진은 호출 대상이 분석에 있어야 싱크를 묶음(`configured_interprocedural_slice.py`의 `if not targets: continue`)
  — 실패한 함수를 빼면 부르는 쪽의 싱크가 조용히 사라짐(두 리뷰어 같은 의견). `analyze_observed_functions`도 진입점.
- **K1c-1 형식 있는 거부**: 요약 엔진에서 정규화가 이유와 함께 거부된 함수(지원하지 않는 모양 등, 입력 검증을 통과한 함수만)는 실행 전체를
  멈추지 않고 그 함수만 실패(`failed_functions`, 실패 루트; 부르는 쪽은 이미 모르는 호출). 잘못된 Bundle·풀리지 않은 범위·임의의
  ValueError는 그대로 실행 실패. 스택 전환 검사: 입구 명령이 관찰에 없거나 관찰이 비면 모든 빠른 경로보다 먼저 "unchecked". 템플릿:
  닫힘 안의 다른 함수가 거부됐으면 내보내기도 의미 거부(저장됨).
- **K1c-2 예산 장부**(`resource_limits`): 함수별 누적 장부(함수 범위 식별자로 구분 — 라이브러리 실행에서 주소가 겹침; 활동 시간 누적,
  안쪽 활동 동안 바깥은 멈춤)와 실행 장부(하나의 마감). `step(n)`은 정확히 차감(빠른 카운터, QUANTUM 4096을 남은 한도로 잘라 정확한
  단위에서 멈춤, 활동이 바뀔 때·예외 때 한 번만 넘김), 느린 경로에서 시계(시간 한도가 있을 때만)·RSS(실행 RSS 한도가 있을 때만)·취소
  확인; 활동 시작마다 1단위와 강제 확인, 결과를 내기 전 강제 확인(`checkpoint`); `charge(n)`은 할당 전에 거절. 메모리는 실행 단위만
  (`/proc/self/statm`, 근사 — 강제 한도는 K1d). 구조 한도: 그래프 노드·간선, memory-SSA 정의, 집합 원소(`_AncestorClosure`), 요약
  run 수, 함수당 루트 수. 확인 지점: 주요 반복문 30곳(memory SSA, relative_memory + 주소식 계산마다, may_alias, call_clobber,
  function_summary, normalize 투영 반복, lane_slice, control_dependence, 그래프 역방향 도달, sparse dataflow)과 보고 단계.
  모든 한도는 기본 꺼짐(`TDO_V2_FUNCTION_WORK|SECONDS`, `TDO_V2_RUN_WORK|SECONDS|RSS_MB`, `TDO_V2_REPORTING_SECONDS`(기본 60),
  `TDO_V2_LIMIT_<구조>`) — K2에서 기본값을 정함. 잘못된 값은 오류. 꺼진 상태 비용: zlib 126.6 s → 132.7 s(+5%).
- **K1c-3 실행 예산 소진 = 마무리**: 검증된 근거 위의 결과만 냄, 소진 뒤에는 대체 분석을 하지 않음. 컴포넌트는 피호출자 먼저 —
  끝난 컴포넌트는 냄, 끊긴 재귀 컴포넌트는 구성원 하나도 내지 않음(낙관 가정 위의 결과), 그 뒤는 모두 `ANALYSIS_RUN_BUDGET`; 간접 호출
  라운드 2 이후에 끊기면 가정 없는 1라운드 결과를 냄(그 사이 기록된 함수 실패는 덮어씀); 이미 소진된 채 들어오면 아무것도 분석하지 않음;
  전체 프로그램 검사(스택 전환)가 끊기면 실행 실패. 요약 엔진: 끝나지 않은 함수는 `ANALYSIS_RUN_BUDGET`(그 요약을 쓴 쪽은
  `rests_on_failed`). 보고(실패 루트·의존 표시·EngineRun)는 언제나 따로 묶인 보고 단계에서 — 분석 한도는 멈추고 자기 마감만, 분석 진입
  거절; 마감을 넘기면 `AnalysisReportingFailed`(실행 실패, 부분 결과 없음). `failed_functions`는 (키, 이유, 자세히: "function:work",
  "run:time", "function:depth", 거부는 "") 셋. 연결 중 소진: `derive_library`가 남은 export를 일시 거부로 멈춤. `run_dfbench`는
  JSON을 임시 파일 + 이름 바꾸기로 씀.
- **K1c-4 취소**: 기본 SIGINT 처리기면 Ctrl-C가 취소 표시를 세우고 작업 스레드가 다음 확인에서 `AnalysisCancelled`(BaseException —
  함수별 처리에 잡히지 않음)로 멈춘 뒤 KeyboardInterrupt; SIG_IGN이면 가로채지 않음; 사용자 처리기면 끝난 뒤 전달(취소 없음).
- 테스트: `test_budgets.py`(정확한 단위, 누적, 안쪽 활동, 실행 소진 고정, 할당 전 거절, 구조 한도, 마무리 규칙 — 끝난 피호출자/
  끊긴 재귀/간접 검사/이미 소진, 보고 마감, Ctrl-C, v2-win-release를 절반 예산으로 돌리면 모든 실패가 실행 예산이고 낸 루트는 전체
  실행과 같거나 불완전), `test_resource_limits.py`(K1b, 형식 있는 거부, 입구 없는 스택 검사, 거부된 피호출자 템플릿).
- 남은 것: K1d(감독 프로세스, 설계 4차 검토 남음), K2~K3. [가정] 시간 한도 실패는 기계 속도에 따라 달라짐(그렇게 표시됨);
  작업량 한도는 순회·캐시 순서가 같을 때 재현됨.

**K1d 외부 감독 (2026-10-19, 설계 검토 5차·구현 검토 Antigravity·Astra)** — `tools/run_supervised.py` + `tools/_launcher.py`
(WSL/Linux, root, systemd; Windows 거절).
- 실행: `systemd-run --scope --expand-environment=no -p Delegate=yes -p MemoryMax=<12G> -p MemorySwapMax=0 -p OOMPolicy=continue
  -p TasksMax -p RuntimeMaxSec=<마감+유예+여유>` 안에서 launcher가 먼저 돎. cgroup이 `memory_localevents`로 마운트돼 있으면 시작 거절
  (범위의 memory.events가 하위를 세지 못함).
- 두 하위 cgroup: launcher는 `launcher/`로 옮기고 `work/`를 만든 뒤 `+memory +pids`를 켬(내부 프로세스 금지 규칙을 지킴, 한도는
  범위에). 작업 프로세스는 `work/`로 옮기고 setsid, oom_score_adj +500(launcher는 -1000) 뒤 확인 바이트, exec(실행 실패는
  close-on-exec 파이프로 알림 → infrastructure). 작업 트리를 끝낼 때는 숫자 PID에 신호를 보내지 않음: `work/cgroup.kill`(커널이
  재귀로, fork 중이거나 작업이 만든 하위 cgroup까지), 비었는지는 `work/cgroup.events populated 0`. TERM은 아직 거두지 않은 자식의
  프로세스 그룹에만(거둔 뒤에는 보내지 않음 — waitpid와 표시를 신호 차단 안에서 함께).
- 대기 중: 작업 종료, 범위 memory.events의 oom_kill 증가(→ 작업 트리 종료), 감독의 TERM(→ 그룹에 TERM, 유예 뒤 cgroup.kill).
  작업이 끝나면 작업 트리를 다 지우고 나서 memory.events를 마지막으로 읽음(배경 자손의 OOM까지 셈) → 최종 상태 한 줄.
- 감독: "ready" 또는 유효한 최종 줄이면 시작으로 인정(곧바로 끝난 실행도 정상 분류); 마감은 먼저 기록하고 TERM, 유예+5 s 뒤
  범위 cgroup.kill(뒷받침); 자신의 Ctrl-C/TERM은 취소로 기록하고 같은 길; 모든 끝에서 launcher를 거두고(한도 안, 안 되면
  강제 종료 뒤 다시 거둠) 범위가 비었음을 15 s 안에 확인(ENOENT/ENODEV = 사라짐) — 못 하면 cleanup-failed(유닛을 남김), 정리
  중의 신호는 기록만. 우선순위: cleanup-failed > cancelled > (시작 못 함) infrastructure > deadline > oom > launcher
  cleanup-failed > signalled > exited > completed. 결과 JSON(원래 증거 포함), 종료 코드. 분석 완전성은 명령 자신의 출력.
- `export_bundle.run_bounded`(Linux): 자기 세션·그룹, subreaper, 전체 시간 한도(`--total-timeout`, 기본 분석 한도 + 1 h). 지도자
  프로세스는 모든 신호를 보낼 때까지 거두지 않음(거두지 않은 PID가 그룹 번호의 재사용을 막음); /proc에서 살아 있는 구성원을 찾아
  TERM 5 s → KILL, 입양된 좀비만 거둠, 정상 종료 뒤에도 같은 정리; 그룹이 사라졌음을 보이지 못하면 내보내기 실패(프로젝트 보존).
  다른 플랫폼은 단순 시간 한도(문서화).
- [가정] 감독받는 명령(우리 분석기)은 자기 프로세스를 cgroup 밖으로 옮기지 않음 — root로 돌기 때문에 `Delegate=yes`가 막지 못함.
  [가정] 그룹을 떠난 자손은 독립 실행 내보내기의 정리에서 빠짐(감독 안에서는 cgroup이 잡음).
- 테스트 `test_supervisor.py`(WSL root): 정상, 종료 코드 3, OOM, 정상 종료 뒤 배경 자손 OOM, TERM을 무시하는 트리의 마감, 작업이
  만든 하위 cgroup, `$`가 든 인자 그대로, 감독 Ctrl-C, launcher 강제 종료, memory_localevents 거절, 실행 실패, 내보내기 정상 종료 뒤
  남은 자손, 내보내기 전체 시간 한도.


### 25.31 K2 측정 결과와 B0: 큰 함수에서 느리고 메모리가 큰 곳 (2026-10-19, 설계 검토 4차·구현 검토 Astra·Fable·Antigravity) [역방향]

**K2 측정 장치(731e03d)** — `scale_fixtures.realistic`(MSVC 같은 호출자 + 피호출자, 답을 따로 아는 탐침 9개), `scale_point` /
`scale_bench`(감독 아래 한 점씩, 단계·진행 기록), `phases.py`(`TDO_V2_PHASES=1`: 단계별 시간·작업량·RSS·이름 붙은 카운터; 꺼지면 확인
한 번), `analyze_observed_with_summaries`(메모리 안 증거 입력, Bundle 입구와 같은 결과 — 테스트), `RootSlice.inherited_incomplete`.

**1단계 측정(target 구성, WSL)**: 10k p-code op 20 s / 0.67 GB, 30k 200 s / 7.3 GB, 100k 12 GiB에서 메모리 부족(normalize 안).
30k 호출자 그래프 간선 967k 중 827k가 MAY_ALIAS_WRITE.

**찾은 것(모두 [역방향], 결과는 맞음 — 모르는 것은 "불완전"으로 남음)**
- (a) 읽지 않고 그대로 넘기는 인자는 싱크 루트가 묶이지 않음(unbound).
- (b) 주소를 모르는 쓰기가 하나라도 있으면 그 함수의 모든 루트가 불완전(함수 전체 규칙).
- (c) 주소를 모르는 쓰기는 탈출 여부와 상관없이 자기 프레임의 private 칸 읽기에도 닿음.
- (d) 불투명 호출 뒤의 읽기 전용 이미지(.rdata) 읽기도 call-clobber 빚을 받음(readonly-image-data-is-constant가 있어도).
- (e) 불투명 호출은 rsp 말고 모든 레지스터에 빚을 남김 → 그 레지스터로 주소를 만든 STORE는 "주소 불확실 쓰기"가 되고, 이후 모든
  읽기가 그 전부를 쓰기 후보로 가짐(크기의 제곱). 호출 규약을 가정해 rbx 등을 보존으로 보는 설계(A)는 사용자가 거절함 — 엔진은
  호출 규약을 가정하지 않음.

**2단계 측정(카운터, 4ff844a)** — 결과·작업량을 바꾸지 않는 카운터. 10k → 30k(3배)에서 제곱으로 늘어난 것: may-alias 행의 쓰기
목록 합(195k → 1.52M, 7.8배; 그중 일반 쓰기도 576k — 불확실 쓰기만의 문제가 아님), MAY_ALIAS_WRITE 간선, call-clobber 행의 사이
호출 합(62k → 488k), call-clobber 클래스 이벤트, 함수 출구 교차 라벨, `_AncestorClosure` 원소. 선형인 것: normalize 반복 라운드의
그래프 복사, 주소 슬라이스, 제어 의존. Python GC는 2.7%(원인 아님). cProfile(30k)과 tracemalloc(10k) 결과, 단순한 국소 원인이
따로 있었음 → B0.

**B0 — 결과·작업량 그대로인 국소 수정(설계 2차, 구현 검토)**
- B0-1(64d4b94) `block_dominators`: 블록마다 "모든 블록" 집합으로 시작하는 고정점(블록² 메모리, 10k 최고점 478 MB 중 408 MB) →
  즉시 지배자 트리 + pre/post 번호, 포함 여부만 답하는 보기. 도달 못 하는 블록은 "모든 블록", 입구는 {입구}, 바깥 선행자 KeyError —
  예전 고정점과 같은 답(무작위 그래프 300개의 모든 쌍 비교). 작업량 차감 없음(예전과 같음).
- B0-2(d45c6d4) memory SSA 입구 정의: 연결 구간마다 정의 전체를 훑던 것 → 한 번 표로.
- B0-3(126cd70) 스택 전환 검사: 읽기·쓰기마다 상태 전체를 훑던 겹침 검사 → 한 패스에 한 번 만드는 겹침 표(후보마다 `overlaps`로 다시
  확인). Bundle 4개 + 축척 예제에서 예전 함수와 모든 패스 비교.
- B0-4(3f8f22f) 스택 탈출 계산을 정규화당 한 번: 불확실 쓰기 고정점의 라운드마다 다시 하던 것 → `EscapeMemo`(효과 단위·관찰·문맥·
  주소 공간을 동일성으로 붙잡고, 입력 호출 집합과 두 가정 스위치로 열쇠). 다시 쓸 때 원래 계산이 차감한 작업량을 한 단위씩 다시 차감
  — 같은 단위·같은 소진 지점(한꺼번에 `step(n)`은 함수 예산 소진을 실행 예산 소진으로 바꿀 수 있음, Astra가 보임). 예산을 여러 지점에
  걸어 메모 켜고/끄고 같은 결과·장부.
- B0-5(aa62b2c) sparse 풀이의 FIFO 작업 목록을 deque로(같은 순서).
- B0-6(2556182) `_stack_taint`의 블록별 상태: (공간, 바이트) 쌍의 frozenset(10k에서 277 MB) → 함수가 건드리는 쌍에 번호를 매긴 정수
  하나(전체 상태 그대로 — 같은 집합이므로 같은 비교·작업 목록·답). 읽히지 않는 임시값을 지우는 안은 작업량(꺼내는 횟수)을 바꿔서
  거절(Astra·Fable). 예전 함수를 오라클로 Bundle 4개 + 축척 예제의 모든 호출 비교.
- 관문(매 커밋): 전체 테스트, 모든 말뭉치·예제 스냅샷이 k2c 기준과 같음, `PYTHONHASHSEED=0`으로 Bundle 7개의 실행 작업량과 함수별
  장부가 이전 커밋과 같음(`.census6/k2_work_compare.py`).

**B0 뒤 측정(1 seed)**: 10k 9.9 s / 0.29 GB, 30k 69 s / 1.2 GB(처음 200 s / 7.3 GB), 100k 처음으로 끝남: 2181 s / 11.1 GB, 탐침 모두 맞음, 실패 함수 없음. 100k의 시간: may_alias 1526 s(70%),
call_clobber 344 s, summarize 132 s; 그래프 간선 16.2M, MAY_ALIAS_WRITE 16.7M, 사이 호출 합 4.9M — 남은 제곱은 B2의 몫.

**알려진 제약** [가정 아님 — 재현성]: 해시 시드를 고정하지 않으면 같은 코드도 실행마다 작업량이 조금 다름(예: 95928 / 95932; 집합
순회 순서). 결과는 언제나 같음. 작업량 예산을 걸면 예산 경계의 함수가 실행마다 달라질 수 있음 — 예산은 기본 꺼짐, 검증은 시드 고정.
고치는 일은 Rust 포팅이나 예산을 실제로 쓸 때로 미룸.

**다음: B2(설계 4차 승인)** — 쓰기·호출·라벨 집합을 함수별 번호의 비트 배열(정수)로, 행의 `writers` / `uncertain` / `plain` /
`intervening_calls`는 풀어 보는 속성 + 세 직렬화(스냅샷, finite-context 입력, recursive-selector 정체성)가 지금과 똑같은 형식으로,
MAY_ALIAS_WRITE 간선은 그래프에 저장하지 않고 API가 지금과 같은 두 순서(`in_edges` = 정렬된 쓰기 키의 역순, 역방향 도달·
`weighted_edges` = 노드 번호 순)로 보여 줌(노드 추가 없음), call-clobber는 클래스마다 한 번 풀이(묶어 풀면 작업량이 바뀜),
`_exit_crossings`·`_AncestorClosure`도 비트 배열(`fact_members`는 원소 수 그대로), 옛 코드 경로(`TDO_V2_LABEL_SETS=0`)를
오라클로 유지. 기록: `.census6/stepB_ws*`, `stepB2_ws*`, `stepB3*`, `stepB4*`, `stepB0*`, `k2_*.py`.

**B2 진행과 K3 메모리(2026-10-19~21, 모두 결과·작업량 그대로)** — 커밋마다 관문(전체 테스트, 스냅샷 k2c와 같음, 시드 고정 작업량·장부가
이전 커밋과 같음)과 Astra 검토. 2026-10-20부터 성능 변경은 커밋 전에 대상 크기(30k, 큰 메모리면 100k)의 전후 시간·최고 메모리를 잰다
(B0-9가 모든 관문을 통과했지만 느려져서 되돌린 뒤 정한 규칙).
- B2 step 1(6feeb84) sparse may-alias / call-clobber 풀이를 정수 비트 집합으로; B0-7/8(fad72ba) 쓰기마다 종류 문자열·간선 레코드 하나.
- B2-d1(379f6cd) `_AncestorClosure` 사실을 비트 집합으로, B2-d2(ae2b272) `_exit_crossings`의 교차 라벨을 비트 집합으로.
- B2-b1(aed9d89) 간선 단위 그래프 읽기는 모두 facade로(직접 `_graph` 접근 22곳 정리, 지키는 테스트), B2-b2(1f154f4) MAY_ALIAS_WRITE
  간선을 그래프에 저장하지 않고 쓰기 표 + 빚마다 비트 집합으로(facade가 지금과 같은 두 순서로 보여 줌), B2-b3(215f86a) 닫힘 계산이
  가상 간선을 필요할 때 읽음.
- B2-c(5ffe11a) call-clobber gen 사건을 같은 보존 집합끼리 공유, B2-a1(921185b) may-alias gen 사건을 같은 객체끼리 공유,
  B2-a2a(a018680) 행의 튜플을 엔진 호출마다 하나로(같은 값이면 같은 객체).
- B2-a1b(eefee0a) B2-a1이 객체마다 전이 값(큰 정수)을 함수 끝까지 잡고 있던 것을 그 객체의 마지막 클래스 뒤에 버림: 60k normalize
  최고점 1067 → 622 MB, 100k 최고 메모리 3771 → 2715 MB(같은 시간). 100k 최고점이 오른 것을 B0-9 탓으로 보았으나 실제는 B2-a1.
- B0-9(81b2619) 스택 전환 검사 상태를 함수 전체 크기의 비트 집합 두 개로 → 30k 0.5 → 2.6 s, 100k 3.7 → 26 s로 느려져 되돌림(df8f2b2).
- B0-10(fc1168a) 스택 전환 검사: 계산은 dict 그대로, 블록별로 저장하는 상태만 (위치 번호 배열, 값 플래그 bytes)로 압축하고 대기 중인
  블록은 풀린 dict를 잠시 보관(최대 256개). 100k 최고 메모리 2715 → 2211 MB(이 검사가 더는 최고점이 아님), 그 단계 시간 3.5 → 6.3 s
  (1.8배; 전체 255 → 257 s). 저장 상태는 블록 수 × 살아 있는 위치 수(제곱)라 250k에서 더 중요.
- 측정(target, seed 0, fc1168a): 30k 29 s / 0.46 GB, 100k 257 s / 2.2 GB. 250k(7ee9d53) 처음으로 완료: 3027 s / 9.19 GB
  (최고점 normalize), 탐침 모두 맞음; 느린 단계 call_clobber 598 s, may_alias 495, slices 458, lanes 407, memory_ssa 237, summarize 176.
  목표(10분 / 8 GiB)까지 남음.
  60k normalize 최고점의 남은 큰 항목: 객체별 gen 사건 146 MB(`_may_alias_sparse`), 행의 writers 튜플 ~170 MB(`may_alias._row`) —
  다음은 B2-a2b(행을 비트로, 승인된 설계)와 gen 사건의 압축. [역방향]

### 25.32 C-9 연산식 이어 붙이기: 호출 결과 자리에 피호출 함수의 연산 (2026-10-20~21, 설계 검토 Astra 5차 + 증분 1 설계 3차·구현 2차) [역방향]

목표: 연산 기록(25.28)에서 요약된 호출의 출력이 "call 노드"로 끝나던 것을, 피호출 함수 안의 실제 연산으로 이어 보여 줌(검증·디버깅,
나중에 VM/인터프리터 핸들러의 `vreg[a] = vreg[b] + vreg[c]` 같은 식). 기록은 진단 정보: 켜든 끄든 라벨·완전성·요약·가정은 그대로.

- C9-0(22ce496) 기록은 모든 루트의 완전성이 끝난 뒤, 자기 진단 예산(`resource_limits.diagnostic`, `TDO_V2_RECORD_WORK`) 안에서 만듦 —
  기록이 분석 장부를 쓰지 않으므로 어떤 분석 결과도 기록에 의존하지 않음.
- C9-5(16c3383) 기록 전용 출처 표 `CallProvenance`(`analyze_units(record_provenance={})`, 기록을 켤 때만): 호출마다 효과의 출처(요약 =
  피호출 함수의 그 분석 인스턴스, 재귀 가설, 모델, 파생 모델, test-only 경계), 별칭 조건마다의 결정(도출 때 버린 쌍과 이유
  "unlocatable"/"failed", 재귀 가설이 실패시킨 쌍, 누적 failed/opened, 마지막 패스의 cr/cw 판정, 싱크 ck 판정). 기록의 call 노드는
  조건마다 공개 판정을 가짐: 마지막 패스가 "ok"이고 한 번도 실패하지 않았을 때만 proven, 아니면 failed/open/undecided(없음 = proven 아님).
- 증분 1(기록 전용): 레지스터 출력 행이고, 출처가 이번 실행의 요약이며, 메모리 읽기(loads)·조건·꼬리 호출이 없을 때만
  이어 붙임. 출력 레지스터 바이트마다 피호출 함수 출구별로 그 바이트의 정의를 모으고(`assemble`), 그 출구가 쓰지 않은 바이트는 호출 직전
  호출자의 값, 출구가 여럿이면 phi "callee exits"(경로 실현 가능성은 따지지 않는 과대 근사). 피호출 함수의 입구 레지스터는 `bound` 노드 =
  호출 지점의 호출자 값(`~in<k>` 읽기; 호출자 레지스터 = 피호출 입구 레지스터, 같은 오프셋 — 호출 모양이 바꾸는 스택 포인터만 예외라
  자름). 깊이 4, 호출 경로에 이미 있는 함수는 자름. 안 되는 경우는 `stitch_cut`에 이유(loads / conditions / stack pointer / entry memory /
  unbound register / source: model / recursion / depth / limit ...). 호출자 기록을 먼저 끝낸 뒤 남은 한도로 시도하고, 한도·잘림·재귀 한도
  초과 시 그 시도 전체를 되돌림(노드 목록, 모든 빌더의 캐시, truncated 플래그) — 호출자 기록·평가는 바뀌지 않음(평가는 "injected" 경로만:
  가져온 노드는 `import` 표시로 무시). 테스트: 한 출구, 두 출구, 출구 하나가 일부만 쓰는 경우, 2단계 호출, 재귀, 이유별 잘림, 한도 초과
  되돌림, 이어 붙여도 호출자 기록·평가가 같음.
- Bundle 집계(기록 켬, 7개): 루트 기록 220개, 이어 붙은 호출 9개(v3-win-release), 잘림: loads 237, 레지스터 출력 아님 122, 스택 포인터 16,
  모델 9 — 대부분 메모리로 전달되는 값(32비트 스택 인자, 포인터 체인)이라 다음 증분(C9-1: 스택 포인터 + displacement_delta 변환,
  리턴 주소 겹침, 포인터 체인 단계별 평가와 `~ld` 재사용 조건)이 필요.
- 증분 2(22b597e, 기록 전용): 호출 모양이 바꾸는 스택 포인터 = INT_ADD(호출 지점의 호출자 SP(push 전), displacement_delta),
  피호출 함수 입구 SP + 변위의 메모리(스택 인자) = 호출자의 그 호출 `~ld<j>` 읽기(바이트 단위; 리턴 주소 자리 [0, push)는 "return address"
  구멍). 그 밖의 입구 메모리([rcx], 포인터 단계, 전역)는 "memory: overlay unproven" 구멍 — 호출 모양이 없앤 리턴 주소 push가 거기
  있을 수 있음(예: 호출자 rcx = rsp - 8). 구멍은 실제로 쓰일 때만 자름. `call_load_keys`(`~ld` 키 순서)를 `_proven_call_rows`가 assert로
  확인. 집계: 이어 붙은 호출 9 → 38(+중첩 3), 남은 잘림 대부분 "memory: overlay unproven" 223.
- 증분 3 계획(Astra 상담, 미구현): 호출자 좌표에서 리턴 주소 자리와 겹치지 않음을 증명할 때만 연결 — 같은 호출의 SP 직접 `~ld`가 있으면
  그 해석 위치 s와 변위 d로 B = s - d(= o_sp + delta), 겹침 = 호출자 스택 객체 [B, B + push); 호출자 스택 객체로 해석된 읽기는 이 구간과
  비교, 전역은 globals-disjoint-from-stack 가정이 켜진 함수에서만(연결 노드에 가정 이름), 포인터 체인은 슬롯마다 같은 검사 + 주소에
  빚이 없을 것. entry-values-do-not-address-the-new-frame만으로는 부족(경계는 호출자의 입구 SP). [역방향]
- 남은 것: C9-1 메모리·스택 변환, C9-3 조건이 있는 행(판정 메타데이터를 붙여 설명용으로), C9-4 "stitched" 평가 경로, C9-6 프로그램 전체
  구체 실행 오라클(호출마다 반환 바이트를 기록, 돌연변이 거부). 기록: `.census6/stepC9_*`, `c9_stitch_census.py`.
