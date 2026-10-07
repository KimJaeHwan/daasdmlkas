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
