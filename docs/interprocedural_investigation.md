# 기존 함수 간 계층 조사 (2026-10-07)

대상: `src/tdo_v2/integration/` (약 23,000줄)과 `engine.py` 의 함수 간 경로. 코드는 수정하지 않았다.
조사 방법: 하위 에이전트 2개(핵심 경로 / 재귀·finite·설명)의 정적 분석 + 실제 Bundle 실행 계측
(`tools/graph_fidelity/hang_probe.py`).

## 1. 구조 요약

- 경로: `engine.analyze_observed_functions` → `build_observed_function_analyses`(경계 노드, sink 요구
  전파) → `complete_configured_interprocedural_slices`(`_stabilized_write_events` → `_complete_slice`) →
  `CallClobberDischarger`(PRESERVED / FRAME_PRESERVED / MUST_WRITTEN / OUTPARAM_MUST_WRITTEN) →
  설명 경로(`include_explanations`).
- 경계 연결은 **물리적·호출 규약 중립**: 레지스터는 같은 REGISTER_FILE 바이트, 스택은 호출 명령의
  `SP -= size; STORE ret` 모양으로 SP 상대 변환, 포인터 메모리는 callee의 ENTRY 앵커 + 오프셋 경로를
  caller의 실제 포인터에 합성.
- **요약(summary) 방식이 아니다.** 루트 함수마다 callee를 호출 문자열(call-string) 단위로 다시 펼치는
  문맥 민감 방식이며, 중첩 호출에서는 캐시를 쓰지 않는다(`configured_write_event_engine.py:242,410`).
  반면 sink 요구 전파는 문맥 비민감 — 두 모델이 섞여 있다.
- callee의 **모든 STORE**를 caller에서 가능한 쓰기 이벤트로 만든다(지역 프레임 쓰기 포함).
- 재귀: SCC/요약 고정점 없음. 전체 함수를 `len(views)+1` 회 반복, 수렴 실패 시 `RuntimeError`
  (DFB060~065 재귀 케이스는 Bundle 전체 실패, `tools/bundle_export/README.md:69`). 재귀 증명 모듈
  (rank_context, induction_closure 등)은 단일 self-recursion, n-1/n-2 감소, rank ≤ 32 등 특정 형태에
  맞춘 z3 장치이고 **engine에 연결되어 있지 않다**(frame_inventory만 사용).
- finite-context(z3 경로 전개, 루프 미지원)·root_replay·selector_discovery: engine 미연결, 테스트 0.
- 설명 계층(path_explanation 2,239줄 등)은 origin 판정과 독립. 단 call_byte_explanation은 MUST_WRITTEN
  부채 해소에 쓰인다.
- 이 계층은 intra의 `call_effect_contracts`(V4 call-effect)를 쓰지 않고 raw observation에서 호출 경계를
  다시 유도한다 — 같은 문제의 모델이 두 벌.
- 테스트: 이 repo에는 `tests/intra` 뿐. 재귀·finite 모듈은 테스트 0.

## 2. win32 / UE DLL 에서 끝나지 않는 원인 (실행으로 확인)

### 원인 1 — 무한 루프 (win32 MSVC, 확정)
`configured_function_memory.resolve_local_pointer_prefix` / `materialize_path` 의 `while` 루프에
방문 집합·반복 상한이 없다. 포인터 경로가 각 역참조를 "함수 시작 시점 값"으로 볼지 "현재 값"으로
볼지 기록하지 않아, 이미 반영한 지역 정의를 다시 대입한다.

- 재현: `v2-win32-release` 함수 `0x401960`, 호출 1회에서 같은 상태 `offsets=(4,4)`를 2분간 300만 번
  반복하고 반환하지 않음(`compose_pointer_path` 계측).
- 패턴(MSVC 꼬리 호출 인자 전달, 흔함):
  ```
  mov eax, [ebp+8]     ; 인자 읽기
  mov [eax+4], 2
  mov [eax+8], 4
  mov [ebp+8], eax     ; 같은 인자 칸에 읽은 값을 다시 씀
  jmp next
  ```
  `[ebp+8]` 의 최신 정의 = "`[ebp+8]` 에서 읽은 값" → 다시 `[ebp+8]` → 끝없이 반복.

### 원인 2 — 지수적 재전개 (UE DLL, 관측)
`ue-dll-development`(함수 71, 내부 호출 간선 116): 10분 동안 `_caller_write_events` 109회에서 거의
정지, `_origins_from_latest_state` 37.6만 회 호출에 서로 다른 입력은 1,770개(같은 계산 평균 200회 이상
반복). 스택은 `_latest_preceding_events`(이벤트 수의 제곱)에 머문다. 원인(정적 분석): 중첩 호출 캐시
없음 × 바깥 고정점 N+1회 × 루트 N개 × 부모 문맥을 따라 올라가며 분기하는 origin 역추적
(`configured_origin_projection.py:280-324`), 그리고 callee 지역 쓰기까지 이벤트로 만드는 것.

### 공통
WriteEvent 엔진 본체에는 작업 상한(budget)이 전혀 없다(설명 계층에만 있음). 그래서 실패가 "끝나지
않음"으로 나타난다.

## 3. 평가와 권고

유지할 것:
- 원칙: 증명된 것만 연결, 나머지는 부채(debt)로 남김. 증명 객체(`InterproceduralTransferProof`).
- 물리적 경계 연결(`PhysicalMemoryTransition`, ENTRY 앵커 `PointerPath`, `observed_call_state`).
- `recursive_frame_inventory`(호출 토큰 = caller 좌표의 callee 입구 SP), frame_separation의 한 단계 보조정리
  (callee 쓰기가 호출 토큰 아래인지) — 스택 보존 증명에 재사용 가능.
- discharge 4종 분류(PRESERVED / FRAME_PRESERVED / MUST_WRITTEN / OUTPARAM) — 요약 기반으로 일반화.
- 인프라: bundle, observed_function_session, path_wire, root_local_explanation, `_cyclic_nodes`(SCC).

바꿀 것:
- 루트마다 재전개 → **함수별 요약(bottom-up), 호출 지점에서 물리 바이트로 결합**. 요약은 완성된 intra
  그래프에서 읽는다(끝 바이트 ← 입구 바이트, must/may 쓰기 집합).
- `PointerPath` 에 평가 시점(입구 기준) 명시 — 원인 1 해소.
- 모든 반복·재귀에 상한과 gap(부채) 결과.
- 재귀: SCC 단위. may(origin)는 최소 고정점, must(보존·반드시 씀)는 "요약을 가정하고 본문이 다시 만족하는지"
  검사(정상 반환 실행은 호출 깊이가 유한하므로 깊이 귀납이 성립) — rank/z3 장치 불필요할 가능성.
- finite-context 장치는 engine에서 빼고, 작은 케이스용 독립 교차검증 오라클 후보로.
- 검증: 가상 실행기를 호출 안으로 들어가 실행하도록 확장해 함수 간 그래프도 "실제 의존이 그래프에 있나"로 검증.
