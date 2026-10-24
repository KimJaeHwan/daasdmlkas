# TDO v2 — Low P-code 데이터 출처 추적 엔진

바이너리(x86-64 / x86-32 PE, ELF)를 Ghidra로 Low P-code Bundle로 내보낸 뒤, **sink 호출의 인자 값이 어느 source에서
왔는지**를 거꾸로(backward) 추적하는 엔진입니다. 레지스터와 메모리를 **바이트 단위**로 다루고, 증명하지 못한 부분은
조용히 넘어가지 않고 **부채(debt)** 로 남겨 결과를 "불완전"으로 표시합니다.

- 소리 없이 틀리지 않는 것(soundness)이 먼저입니다. 정밀도를 위해 기대는 조건은 모두 **이름 붙은 가정**으로 등록하고,
  결과가 그 가정을 썼으면 결과에 그 이름을 함께 보고합니다.
- 출처가 비어 있거나 결과가 불완전하다고 해서 "출처가 없다"는 증명은 아닙니다.

## 연산식 1차 개발 — 완료 (2026-10-25)

**기존 SSA·원 그래프 보존 → 필요한 부분 선택 → 지원 범위의 간략화 → 동등성 확인 → 원본 연결**을 1차 개발의
완료 범위로 확정했습니다. 제한된 반복 최종 요약과 최대 8방문의 상태 합성도 포함하며, **확인된 필수 잔여 항목은 없습니다.**
모든 프로그램의 식을 가장 짧은 공식으로 만들거나 임의 반복 전체를 요약한다는 뜻은 아닙니다.

현재 지원 범위·제한·완료 근거·선택적 확장은
[`docs/interprocedural_design.md` §25.58](docs/interprocedural_design.md#2558-연산식-1차-개발-완료와-지원-계약-2026-10-25)를 기준으로 합니다.
기존 동결본은 **3350 passed / 32 skipped / 0 failed**, Astra 최종 승인 완료 상태입니다. 32 skip은 환경·미보유 Bundle
제약이며 성공으로 세지 않습니다. 이 완료 정리는 엔진 변경이나 새 테스트 실행 결과가 아닙니다.

일반 동적 메모리·새 RAM/반복 구간 경계·복잡한 반복 최종식 등은 **필수 잔여가 아닌 선택적 확장**입니다.
실제 사용에서 분석을 막는 사례와 완료 기준을 확인하고 별도 범위에 합의할 때만 착수합니다. 지원 범위 안의 결함은
수정 대상이며, 한계를 문서화했다는 이유로 오류를 허용하지 않습니다. 이 완료 선언은 연산식 계층의 1차 범위에 한정합니다.

## 구성

```text
바이너리 ──(Ghidra 12.0.4 + ghidra/*.java exporter)──▶ format-2 Bundle (봉인된 디렉터리)
  └─▶ 함수마다: 바이트 단위 저장소 · 메모리 SSA · may-alias · 호출 clobber ─▶ 함수 그래프 (NormalizedFunction)
        └─▶ 함수 요약 (FunctionSummary) ─▶ 호출 지점 효과 (ProvenCallEffect)   ← 외부 모델 · DLL 템플릿
              └─▶ sink root에서 거꾸로 질의 ─▶ 출처 라벨 · 완전성 · 쓴 가정 목록 (EngineRun)
```

| 위치 | 내용 |
|---|---|
| `src/tdo_v2/` | 엔진 (아래 "주요 모듈") |
| `ghidra/` | Bundle exporter와 보조 스크립트(Ghidra 12.0.4 전용) |
| `models/external/` | 외부 함수 모델: CRT(win64 / sysv64), UE Core |
| `models/derived/` | DLL 코드에서 엔진이 직접 만든 요약 템플릿 (예: UE `FString`) |
| `models/bound/`, `models/bindings/` | 바이너리 안(내보내지 않은) 함수에 붙이는 모델과 그 연결 파일 |
| `models/pcodeops/` | 사용자 정의 p-code 연산(CALLOTHER) 모델 |
| `tools/bundle_export/` | Bundle 내보내기, 벤치 실행기(`run_dfbench.py`), DLL 연결 — [README](tools/bundle_export/README.md) |
| `tools/derive_models/` | DLL 함수에서 요약 템플릿 만들기 |
| `tools/graph_fidelity/` | 검증 도구: 지표(`dfbench_metric.sh`), 프로그램 오라클(`measure_program.py`), golden 비교 |
| `tests/intra/` | 테스트 (합성 함수 + 실행 오라클) |
| `docs/` | 설계와 결과 기록 (아래 "문서") |

## 요구 사항

- Python 3.11 이상 (`rustworkx`, `z3-solver`) — `pip install -e .`
- Bundle 내보내기: Ghidra **12.0.4**, JDK 21, **Linux(WSL) 파일 시스템**. Bundle 수용(admission)은 POSIX 권한을 검사하므로
  Windows 드라이브(`/mnt/d` 등)에 둔 Bundle은 받아들이지 않습니다. 자세한 내용은 `tools/bundle_export/README.md`.

## 빠른 시작

### 1. Bundle 만들기

```bash
python3 tools/bundle_export/export_bundle.py <binary> \
    --function-name <root 함수 이름> \
    --output-root /root/tdo_bundles/<이름>
```

이름(또는 `--entry`, `--functions-from-manifest`)으로 고른 함수와 그 호출·참조 닫힘을 내보냅니다.

### 2. 실행

명령줄(DataFlowBench 형식의 source/sink 표와 기대 결과를 쓰는 실행기):

```bash
PYTHONPATH=src python tools/bundle_export/run_dfbench.py <Bundle generation 경로> \
    --expected <cases_manifest.json> [--json out.json]
```

Python에서:

```python
from tdo_v2.summary_engine import analyze_frozen_bundle_with_summaries

run = analyze_frozen_bundle_with_summaries(
    "/path/to/bundle/<generation>",
    naming_exporter_source="ghidra/GhidraV2CallNaming.java",
    boundary_provider=my_boundary_provider,   # source / sink 호출을 알려 주는 객체
)
for root in run.roots:
    # 출처 라벨, 그리고 부채 없이 끝났는지(호출받는 함수의 증거로 갚은 부채 포함)
    print(root.label, root.reached_origin_labels, root.is_effectively_complete)
print(run.assumptions)   # 이 실행이 기댄 이름 붙은 가정
```

`tdo_v2.boundary_rules.SymbolBoundaryProvider`는 표 기반의 일반 구현입니다. 엔진 안에 호출 규약이나 벤치 이름은 들어 있지
않습니다. 예전 엔진(`tdo_v2.engine.analyze_frozen_bundle`)은 `--legacy-engine`으로 남아 있습니다.

### 3. 테스트

```bash
PYTHONPATH=src python -m pytest tests/intra -q
```

## 이름 붙은 가정

목록은 `src/tdo_v2/assumptions.py`에 등록되어 있고, [`docs/assumptions.md`](docs/assumptions.md)는 거기서 만들어집니다.

- **switch**: 기본값이 있고 끌 수 있음. 예: `globals-disjoint-from-stack`(상수 주소는 스택이 아님),
  `readonly-image-data-is-constant`, `import-slots-hold-their-exports`, `entry-values-do-not-address-the-new-frame`.
  끄기: `--no-assume-...` 또는 환경 변수 `TDO_V2_ASSUME_...=0`.
- **기본으로 꺼진 switch**: `same-result-functions`, `accessor-result-separate`, `accessor-private-state`
  (같은 결과를 돌려주는 접근 함수 모델, 문서 25.20–25.24) — `--assume-...`로 켬.
- **model**: 모델 파일이 기대는 조건(예: `allocator-results-are-fresh`, `no-use-after-free`). 모델을 쓴 호출마다
  `external-model:<파일>/<항목>@v<n>`으로 보고됩니다.
- **reported**: 끌 수는 없지만 썼으면 보고되는 조건.
- **test-only**: 벤치용 특수 조건(`--assume-boundary-effects`). 실제 결과에는 쓰지 않습니다.

각 가정에는 "무엇을 가정하는지", "언제 틀리는지", "어디서 쓰는지"가 적혀 있습니다.

## 함수 간 분석

- **함수 요약**: 함수마다 출구에서 레지스터·메모리 바이트가 무엇에서 왔는지, 스택 포인터 변화, 안쪽 호출, sink 요구를
  요약합니다. 호출 지점에서는 이를 호출한 쪽의 값으로 바꿔 붙입니다(`call_summary_effects`). 재귀는 검증된 고정점으로 풉니다.
- **외부 모델**: import 함수는 `models/external`의 모델로 대신합니다(`--model-dir`로 추가, `--no-external-models`로 끔).
- **DLL 연결**: 사용자가 준비한 Ghidra 프로젝트에서 DLL 함수를 읽어 요약 템플릿을 만들고 캐시합니다
  (`run_dfbench --link LIB=DLL --ghidra-project X.gpr`). 템플릿은 `ENGINE_SEMANTICS_VERSION`이 바뀌면 다시 만들어야 합니다.
- **바인딩**: 바이너리 안 함수(내보내지 않은 함수)에 모델을 붙일 때는 sha256 + RVA + ABI로 확인합니다(`--binding`).

## 진단 출력 (결과는 바뀌지 않음)

- `run_dfbench --witnesses`: 출처 증거 — 보고된 라벨이 어떤 부채(쓰기 → 읽기)를 거쳐 왔는지 (문서 25.19).
- `run_dfbench --records`: 연산 기록 — root마다 값이 거친 p-code 연산의 식 그래프(입력 조각·바이트 범위, 합류의 대안, 요약된 호출과
  그 판단 사실, 부채)를 `--json`에 넣고 기대 케이스는 텍스트로 출력 (문서 25.28).
- `run_dfbench --physical-records`: `--records`도 켜고 원래 메모리 읽기/쓰기 및 지원되는 호출의 물리 바이트·반환 조건을
  추가합니다. 기본 summary 경로에서만 지원하며 legacy 경로와 함께 쓰면 오류입니다. Python API에서는
  `physical_memory_records=True`로 켭니다. 요약·가정·정적 eligibility와 기존 부채는 바뀌지 않습니다.
- `tools/graph_fidelity/derivations.py <generation> --function <entry>`: 함수 하나의 출구별 출력을 입구 값의 식으로 출력 —
  실제 연산과 메모리 의존을 살펴보는 진단 기능입니다. VM 구조를 복원하는 기능은 아닙니다.
- `run_dfbench --records`의 호출 본문 연결은 같은 실행에서 증명된 원래 함수의 연산을 사용합니다. 정방향
  (`TDO_V2_FORWARD=1`)으로 여러 후보가 증명된 간접 호출도 대상·출구 선택을 공유하며 연결합니다.
  동일한 물리 레지스터 기준의 고정 메모리 쓰기를 합치는 범위와 제한은 설계 문서 **25.34절**에 있습니다.
- 조건 표현은 기존 SSA·CFG를 재사용합니다. 비순환 중첩·연속 분기와 조건분기들로 컴파일된 switch의 원 CBRANCH 조건을
  공유하며, 조건이 알려지면 해당 대안을, 미지 입력이면 상관을 유지한 대안들을 남깁니다. 물리 기록은 중첩된 알려진 직접
  호출과 다중 RETURN을 같은 조건에 연결합니다. 간접 분기/호출의 미확정 목적지, 루프·재귀·미지원 효과를 임의의 경로로
  확정하지 않습니다. 증명된 유한 CALLIND 후보는 원 target 계산식의 공유 선택으로 물리 연결하며, 레지스터·RAM·RETURN은
  같은 대상을 따릅니다(미지/후보 밖 target은 거부). 정방향 후보 분석은 `TDO_V2_FORWARD=1`로 켭니다.
  호출 뒤 AL/AH/AX처럼 일부만 새로 쓰면 해당 SSA 조각을 유지하고, 덮이지 않은 구간만 호출 본문의 terminal register
  조각으로 연결합니다. EAX의 상위 0 처리도 추측하지 않고 원 p-code 쓰기를 따릅니다. 조건부 부분 쓰기도 원 SSA 합류의
  공유 조건에 따라 새 쓰기 또는 호출 결과를 선택합니다. 순환은 `cycle_graph`에 원 함수 CFG의 모든 간선과 기존 SSA의
  정의·읽기·쓰기·JOIN·바이트 식 참조로 보존합니다. 중첩·다중 진입·여러 갱신/되돌이·연속 루프도 같은 일반 그래프를
  사용합니다. 조건은 매 방문의 원 식이며 한 번 정해지는 고정 boolean이 아닙니다. 기록되지 않은 간선별 상태는
  `not_captured`로 남깁니다. CFG/식 구조 완전성과 수치 평가 가능성은 다르며, 원 순환 그래프 자체는 반복 횟수나 최종값을 계산하지 않습니다.
  단순 `recurrence`는 호환용 유도 뷰입니다. 원 그래프를 유지한 `cycle_graph.transitions`는 지원되는 단일 진입 영역의
  **한 회차**에 대해 현재 상태→분기 조건→읽기/순서 있는 쓰기→다음 상태를 기존 식으로 연결합니다. 원 SSA source 후보와
  captured cut 상태를 바이트별로 대조하며, 이전 회차와 이번 회차의 같은 STORE를 혼동하지 않습니다. 수치 API는
  `evaluate_transition(record, view_id, {state_id: value})`입니다. 실행 가정이 미귀속이면 기본 거부하며 명시적 opt-in만
  허용합니다. 한 회차 뷰는 반복 전체의 최종 공식이나 완전한 기계 상태가 아닙니다. 별도 `loop_summaries`는 검증된
  `counter != 0; counter -= 1` 반복의 일정한 누산을 `x_final = x_initial + n*delta (mod 2^bits)`로 요약합니다.
  `n`은 해당 영역 입구 counter의 unsigned 값이며 원 함수 인자로 추측하지 않습니다.
  `evaluate_loop_summary(record, summary_id, inputs)`는 반복을 풀어 실행하지 않고 영역 종료 시 tracked state를 계산하며,
  원 메모리 효과 템플릿과 마지막 zero-check를 보존합니다. low-byte 승격/절단은 해당 바이트의 modulo 항등식일 때만,
  분기는 원 전체 조건이 반복 중 불변임이 증명될 때만 공유 선택별 최종식을 만듭니다. 카운터와 주소에는 low-byte 축약을
  적용하지 않습니다. 한 STORE뿐이고 LOAD/호출이 없는 일정 간격 쓰기는 별도 `write_effect_transitions`를 통해
  `M_final = apply_STORE(M_initial, p+offset+i*stride, value, i=0..n-1)`로 표현합니다. 원 RAM 미해결 표시를 갚지 않으며,
  수치 평가 시 겹침/주소 및 최종 pointer wrap을 거부합니다. 가정·부채·기존 eligibility는 유지됩니다. 변하는 조건·
  LOAD/STORE alias·일반 비선형 갱신 등은 원 그래프/한 회차식을 남기고 사유를 표시합니다.
  `select_expression`으로 이미 있는 임의 node/바이트 출력을 선택하고 `simplify_expression`으로 별도 간략화 DAG를
  만들 수 있습니다. 기존 entry producer의 겹치는 바이트와 공유 분기를 보존하며, 원 domain SAT 후 값 불일치 UNSAT를
  확인합니다. `attach_expression_view`는 원본의 복사본에 `expression_views`만 추가하고 원 그래프·반복 요약·부채를
  변경하지 않습니다. 소비 시 원식 재구축과 동등성 재검사를 거치며, 이는 지역 값 동치이지 효과·종료·도달성 증명이
  아닙니다. 검증된 뷰를 후속식에 실제 치환하는 `derive_expression_consumer`와, 기존 감소 반복 판정에 불변 증가량
  DAG를 연결하는 `derive_loop_consumer`도 제공합니다. 새 `expression_consumers`에만 저장하며 원본과 기존 반복 요약은
  바꾸지 않습니다. 원 조건이 뷰의 가정을 함의하고 최종 저장식까지 동치일 때만 소비합니다.
  기존 경계 입력을 한 바이트만 바꿔 출력 값의 실제 영향 여부를 증명하는 `prove_byte_influence`도 제공합니다. 값과
  조건 평가·진입·정의가능성은 따로 판정하며, 무영향 결과로 원 간선/source를 삭제하지 않습니다.
  `derive_expression_island`는 명시한 원 producer 출력을 구간 입력으로 받아 비순환 순수 정수 부분식만 조건부로
  간략화합니다. 지역 동치와 원 식으로의 연결 증명을 분리하며, 미해결 호출 입력·원 부채는 그대로 남깁니다.
  `derive_transition_chain(record, transition_id, max_visits)`는 complete 한 회차식을 최대 8회 연결합니다. 원 공유 조건·
  정확한 byte 상태·고정 메모리·효과 순서를 보존하고 exit 후 상태를 유지합니다. 반복횟수 예측이나 전체 반복의 닫힌
  공식은 아니며, 상한 도달과 실제 종료를 구분합니다. 원 자료가 캡처한 O1 출구의 비항등 갱신도 연결합니다.
  설계 및 API 예시는 **25.39–25.57절**을 참고하세요.

물리 기록의 구체 값은 `tdo_v2.operation_records.evaluate_physical(record, entry)`로 별도 평가합니다. 입구 레지스터와 RAM을
실제 입력으로 제공해야 하며, 미지 값·지원하지 않는 효과·반환 불일치·예산 초과는 값으로 단정하지 않습니다. 이는 제한된
원본 p-code 관계를 검증하는 진단 기능이지 native 실행이나 함수 전체의 무조건적인 지원을 뜻하지 않습니다.
Bundle public API는 현재의 sealed naming-v2 자료가 필요합니다. 옛 naming-v1 sidecar를 수정하거나 진단 옵션으로
admission 검증을 우회하지 않습니다.

## 검증

- 개발 완료 판단은 테스트 통과와 별개로 Astra의 최종 목표 달성 검토를 거칩니다. 요청한 범위의 미구현·미검증 항목이
  남았는지 확인하고 마무리 승인을 받은 뒤 완료로 보고합니다. 제한된 테스트 범위를 전체 지원 완료로 바꾸어 말하지 않습니다.
- **지표**: `tools/graph_fidelity/dfbench_metric.sh` — 케이스마다 정확/누락/초과 × 확실/불확실.
- **프로그램 오라클**: `tools/graph_fidelity/measure_program.py <generation> --models` — 함수를 무작위 입력으로 실제로
  실행해, 값이 흘러간 바이트를 그래프가 놓쳤는지(missing) 봅니다. 놓친 바이트는 0이어야 합니다. 부채로 설명된 것은
  `unexplained`로 따로 셉니다.
- **golden 비교**: `tools/graph_fidelity/golden_all.sh compare <golden> <new>`.

2026-10-16에 기록한 지표 (정확 / 정확+확실; 이후 브랜치의 최신 성적으로 해석하지 않음):

| Bundle | 케이스 | 결과 |
|---|---|---|
| 09 testbed win-debug | 74 | 66 / 62 |
| 09 testbed win-release | 55 | 53 / 48 |
| 09 testbed win32-release | 47 | 44 / 37 |
| UE DLL DebugGame | 22 | 15 / 15 (접근 함수 가정 + 바인딩: 17) |
| UE DLL Development | 22 | 16 / 16 (접근 함수 가정 + 바인딩: 18) |

어느 Bundle에서도 "누락 + 확실"은 0이고, 프로그램 오라클의 누락은 zlib를 포함해 0입니다(zlib의 256건은 오라클 해석기의 호출 규약 결함이었음 — 문서 25.29).
위 표와 함께 기록했던 테스트 수는 935개입니다. 이후 구현·검증 상태는 설계 문서 25.29–25.34절을 확인합니다.

## 문서

- [`docs/interprocedural_design.md`](docs/interprocedural_design.md) — 함수 간 분석의 설계·결정·결과 기록(1–25절).
  25.25절은 남은 한계마다 **[정방향]**(정방향 분석이 풀 수 있음) / **[역방향]**(지금 엔진에 규칙을 더하면 풀림) /
  **[가정]**(이름 붙은 가정으로만) 표시를 모아 둔 표입니다.
- [`docs/intra_function_stabilization.md`](docs/intra_function_stabilization.md) — 함수 내부 그래프 안정화.
- [`docs/assumptions.md`](docs/assumptions.md) — 이름 붙은 가정 전체.
- [`tools/bundle_export/README.md`](tools/bundle_export/README.md) — 내보내기, DLL 연결, 스택 전환 검사.

## 프로젝트의 제한사항과 별도 확장 범위

아래는 프로젝트 전체의 지원 경계와 별도 과제이며 **연산식 1차 개발의 필수 잔여 작업 목록이 아닙니다.**
지원되는 기능의 결함 수정과 미지원 범위의 신규 개발을 구분합니다. 연산식 확장 착수 기준은 §25.58을 따릅니다.

- 정방향 값·범위 사실과 유한한 간접 호출 후보의 효과 합성은 구현했습니다(`TDO_V2_FORWARD=1`).
  서로 다른 메모리 기준의 일반적인 별칭 통합과 외부 콜백 실행 연결은 이 지원 범위에 포함하지 않습니다.
- 후보가 제한된 주소의 읽기와 동일 기준 메모리 출력은 지원하지만, 임의 index의 "버퍼 안" 증명이나
  일반적인 범위 쓰기까지 보장하지는 않습니다.
- 데이터 출처 추적은 바이트 단위입니다. 비트 단위 source 정밀도 확대는 별도 확장으로, 비트 연산식 자체의 표현·평가 지원과
  구별합니다.
- 함수 입구 메모리의 일반적인 호출 문맥 특수화와 모델 콜백 처리는 이번 표현 계층 완료 범위 밖입니다. 이미 구현된
  조건·공유 선택 및 지원되는 호출 연결은 위 "진단 출력"의 계약을 따릅니다.
- `feature/multi-target-memory-flow`는 엔진 의미 버전 13입니다. 동일 SHA-256의 UE 5.1.1 Win64 Core DLL을 확보해
  분석 자료·전체 스택 증거·FString 파생 모델을 다시 생성했고, 배포 모델 호환성 검사를 통과했습니다.
  재생성 근거와 검수 범위는 [`docs/interprocedural_design.md` §25.35](docs/interprocedural_design.md#2535-ue-core-원본-복구와-파생-모델-재생성-2026-10-23)를 참고하세요.
- 연산식은 향후 가상화·인터프리터 분석 도구가 소비할 표현 계층이며 VM 구조 복원이나 실제 VM 분석 개발이 아닙니다.
  현재 1차 완료 계약은 **§25.58**입니다. §25.36의 초기 점검·우선순위와 §25.54의 계획은 후속 구현으로 이행된
  과거 기록이므로 새 필수 개발 목록으로 사용하지 않습니다.
