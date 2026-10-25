# TDO v2 — Low P-code 데이터 출처 추적 엔진

바이너리(x86-64 / x86-32 PE, ELF)를 Ghidra로 Low P-code Bundle로 내보낸 뒤, **sink 호출의 인자 값이 어느 source에서
왔는지**를 거꾸로(backward) 추적하는 엔진입니다. 레지스터와 메모리를 **바이트 단위**로 다루고, 증명하지 못한 부분은
조용히 넘어가지 않고 **부채(debt)** 로 남겨 결과를 "불완전"으로 표시합니다.

- 소리 없이 틀리지 않는 것(soundness)이 먼저입니다. 정밀도를 위해 기대는 조건은 모두 **이름 붙은 가정**으로 등록하고,
  결과가 그 가정을 썼으면 결과에 그 이름을 함께 보고합니다.
- 출처가 비어 있거나 결과가 불완전하다고 해서 "출처가 없다"는 증명은 아닙니다.

정방향 메모리 범위 강화는 `TDO_V2_FORWARD=1`에서 기존 주소 사실을 정확한 LOAD/STORE byte의 별칭 판단에 연결합니다.
실제 DFB044는 동일 STORE 값을 읽는 index LOAD를 공유해 배열 STORE→4byte 메모리 정의→배열 LOAD까지 연결합니다.
보존된 호출 레지스터의 저위 부분도 정확한 SUBPIECE로 이어집니다. 완성된 SSA의 정확한 상수 값과 호출 입구의
`base + scale * extend(index + offset)` 쓰기·별칭 조건도 요약/템플릿/호출자 메모리로 전달합니다.
UE 전체 완전성이나 추가 source 제거를 보장하지 않습니다. 지원 조건·실제 결과·한계는
[설계 §25.62](docs/interprocedural_design.md#2562-상수-메모리값과-입구-indexed-쓰기조건-전달-2026-10-25)에 있습니다.

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
  핸들러 함수(가상화 핸들러 등)의 의미를 볼 때.

## 검증

- **지표**: `tools/graph_fidelity/dfbench_metric.sh` — 케이스마다 정확/누락/초과 × 확실/불확실.
- **프로그램 오라클**: `tools/graph_fidelity/measure_program.py <generation> --models` — 함수를 무작위 입력으로 실제로
  실행해, 값이 흘러간 바이트를 그래프가 놓쳤는지(missing) 봅니다. 놓친 바이트는 0이어야 합니다. 부채로 설명된 것은
  `unexplained`로 따로 셉니다.
- **golden 비교**: `tools/graph_fidelity/golden_all.sh compare <golden> <new>`.

현재(2026-10-16) 지표 (정확 / 정확+확실):

| Bundle | 케이스 | 결과 |
|---|---|---|
| 09 testbed win-debug | 74 | 66 / 62 |
| 09 testbed win-release | 55 | 53 / 48 |
| 09 testbed win32-release | 47 | 44 / 37 |
| UE DLL DebugGame | 22 | 15 / 15 (접근 함수 가정 + 바인딩: 17) |
| UE DLL Development | 22 | 16 / 16 (접근 함수 가정 + 바인딩: 18) |

어느 Bundle에서도 "누락 + 확실"은 0이고, 프로그램 오라클의 누락은 zlib를 포함해 0입니다(zlib의 256건은 오라클 해석기의 호출 규약 결함이었음 — 문서 25.29).
현재 main 기반 브랜치의 최신 전체 회귀 수치와 skip 범위는 설계 §25.62에 기록합니다.

## 문서

- [`docs/interprocedural_design.md`](docs/interprocedural_design.md) — 함수 간 분석의 설계·결정·결과 기록(1–25절).
  25.25절은 남은 한계마다 **[정방향]**(정방향 분석이 풀 수 있음) / **[역방향]**(지금 엔진에 규칙을 더하면 풀림) /
  **[가정]**(이름 붙은 가정으로만) 표시를 모아 둔 표입니다.
- [`docs/intra_function_stabilization.md`](docs/intra_function_stabilization.md) — 함수 내부 그래프 안정화.
- [`docs/assumptions.md`](docs/assumptions.md) — 이름 붙은 가정 전체.
- [`tools/bundle_export/README.md`](tools/bundle_export/README.md) — 내보내기, DLL 연결, 스택 전환 검사.

## 한계와 다음 단계

- 증명 가능한 유한 간접 호출 대상은 연결하며, 대상 미해결·동적 등록 콜백은 별도의 모델/분석 근거가 필요합니다.
- 배열 index 쓰기의 "버퍼 안" 증명은 설계만 되어 있고(문서 25.18), 정방향 분석의 사실과 함께 구현할 예정입니다.
- 비트 단위 정밀도(마스크·비트필드)는 미뤄 두었습니다. 엔진은 바이트 단위입니다.
- 정방향 값/주소 사실과 기존 SSA의 동일 값 근거를 소비하고 있습니다. 다음 후보는 호출 요약의 상수 메모리값·가변 주소 효과와
  할당 identity 전달이며, 외부 함수 효과 모델 자체를 새로 만드는 작업과는 다릅니다. 연산식 브랜치와의 통합은 별도입니다.
