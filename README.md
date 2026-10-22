# TDO v2 — Low P-code 데이터 출처 추적 엔진

바이너리(x86-64 / x86-32 PE, ELF)를 Ghidra로 Low P-code Bundle로 내보낸 뒤, **sink 호출의 인자 값이 어느 source에서
왔는지**를 거꾸로(backward) 추적하는 엔진입니다. 레지스터와 메모리를 **바이트 단위**로 다루고, 증명하지 못한 부분은
조용히 넘어가지 않고 **부채(debt)** 로 남겨 결과를 "불완전"으로 표시합니다.

- 소리 없이 틀리지 않는 것(soundness)이 먼저입니다. 정밀도를 위해 기대는 조건은 모두 **이름 붙은 가정**으로 등록하고,
  결과가 그 가정을 썼으면 결과에 그 이름을 함께 보고합니다.
- 출처가 비어 있거나 결과가 불완전하다고 해서 "출처가 없다"는 증명은 아닙니다.

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
- `tools/graph_fidelity/derivations.py <generation> --function <entry>`: 함수 하나의 출구별 출력을 입구 값의 식으로 출력 —
  실제 연산과 메모리 의존을 살펴보는 진단 기능입니다. VM 구조를 복원하는 기능은 아닙니다.
- `run_dfbench --records`의 호출 본문 연결은 같은 실행에서 증명된 원래 함수의 연산을 사용합니다. 정방향
  (`TDO_V2_FORWARD=1`)으로 여러 후보가 증명된 간접 호출도 대상·출구 선택을 공유하며 연결합니다.
  동일한 물리 레지스터 기준의 고정 메모리 쓰기를 합치는 범위와 제한은 설계 문서 **25.34절**에 있습니다.
- 지원되는 단순 if/else는 원래 조건식과 참/거짓 대안을 기록하며, 같은 분기의 여러 출력은 선택을 공유합니다.
  조건이 알려지면 한쪽을, 미지 입력이면 상관을 유지한 두 대안을 평가합니다. 반복·분기 안 호출 등은 이유를 남기고
  기존 무조건 대안으로 유지합니다. 실제 STORE→phi→LOAD 사례와 경계는 설계 문서 **25.37절**을 참고하세요.

## 검증

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

## 한계와 다음 단계

- 정방향 값·범위 사실과 유한한 간접 호출 후보의 효과 합성은 구현했습니다(`TDO_V2_FORWARD=1`).
  서로 다른 메모리 기준의 별칭 통합, 일반적인 외부 콜백 실행 연결은 남아 있습니다.
- 후보가 제한된 주소의 읽기와 동일 기준 메모리 출력은 지원하지만, 임의 index의 "버퍼 안" 증명이나
  일반적인 범위 쓰기는 후속 작업입니다.
- 비트 단위 정밀도(마스크·비트필드)는 미뤄 두었습니다. 엔진은 바이트 단위입니다.
- 함수 입구 메모리의 호출 문맥 대입, 조건부 연산 기록 연결, 모델 콜백 처리가 후속 범위입니다.
- `feature/multi-target-memory-flow`는 엔진 의미 버전 13입니다. 동일 SHA-256의 UE 5.1.1 Win64 Core DLL을 확보해
  분석 자료·전체 스택 증거·FString 파생 모델을 다시 생성했고, 배포 모델 호환성 검사를 통과했습니다.
  재생성 근거와 검수 범위는 [`docs/interprocedural_design.md` §25.35](docs/interprocedural_design.md#2535-ue-core-원본-복구와-파생-모델-재생성-2026-10-23)를 참고하세요.
- 연산식은 향후 가상화·인터프리터 분석 도구가 소비할 표현 계층입니다. 현재 목표는 기존 SSA·데이터 그래프의 연산·메모리·
  조건·불확실성을 손실 없이 조회·전달하는 것이며, VM 구조 복원이나 실제 VM 분석 개발이 아닙니다.
  표현 기능과 구현 우선순위 검토는 [`docs/interprocedural_design.md` §25.36](docs/interprocedural_design.md)에,
  1순위 조건·공유 선택의 구현 결과는 같은 문서 **§25.37**에 기록합니다.
