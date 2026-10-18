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
  핸들러 함수(가상화 핸들러 등)의 의미를 볼 때.
- `derivations.py ... --expand-calls --operation <p-code key> --json out.json --mermaid out.mmd`:
  호출 전 레지스터·RAM의 SSA 조각을 피호출 함수의 원래 연산과 연결합니다. 출력 바이트별 계산과 호출별 문맥,
  동일 호출 출력들의 공통 출구 선택을 유지하며, 메모리 주소 계산·저장·호출 후 읽기도 그래프에 포함합니다.
  `run_dfbench --expand-call-records`도 같은 기능을 사용합니다(`--records` 포함).
  분석 결과·요약·가정을 바꾸지 않는 선택 기능입니다. 확장된 기록은 v2이며, 조건부 출력은 최종 호출 지점의
  주소 비중첩 증명을 재사용합니다(중첩 호출·합쳐진 바이트 범위 포함). 실제 CALL/CALLIND의 raw 스택 쓰기도
  연결합니다. 재귀·외부 모델·증명되지 않은 조건 등 원래 본문과의 연결 근거가 없는 출력은 `unavailable`,
  확장 제한은 `cut`으로 남습니다.
  함수 내부 phi의 경로 실행 가능성이나 임의 프로그램의 정확한 상태 변환까지 증명하지는 않습니다.

Python에서는 `RecordProvider()`를 `analyze_units(..., record_provider=provider)`에 넘긴 뒤,
`root_record` / `run_records`에 `provider=provider`를 넘깁니다. 여러 출력의 상관관계가 필요하면
`evaluate_joint(records, entry)`를 사용합니다. 서로 다른 분석 스냅샷을 섞는 평가는 거부합니다.

실제 x64 DFB054의 보관 Bundle 회귀 테스트(네이티브 실행이 아닌, 실제 추출 raw p-code 실행과 식 평가 비교):

```bash
TDO_DFBENCH054_BUNDLE=/path/to/c6edcb2c812de6b6b226bcd7a83c9d418e1858a21e56cbadffb7ef92d63109d1 \
  PYTHONPATH=src:tests/intra python -m pytest tests/corpus/intra/test_call_expression_dfbench054.py -q
```

과거 naming-v1을 현재 naming-v2로 가장하지 않고, 봉인 검증된 원본·함수 관찰만 사용합니다.
해당 Bundle이 없으면 이 테스트는 명시적으로 skip합니다. 한 케이스의 106개 입력 비교이지 suite09 전체 통과가 아닙니다.

재귀 DFB060–065를 제외한 실제 x64 suite09 보관 Bundle 74개를 대상으로, source/sink뿐 아니라 정규화된 raw 값 출력·STORE와
각 호출 출력의 식을 조회하는 회귀 테스트(CALL의 일시적인 SP 조정·주소 push는 별도 물리 상태 전이에 접혀 있으며,
이외에 조회 목록에서 사라지는 raw 값 출력·STORE가 없는지도 확인):

```bash
TDO_SUITE09_X64=/path/to/suite09_fresh_x64_baseline_39 \
  PYTHONPATH=src:tests/intra python -m pytest tests/corpus/intra/test_call_expression_suite09.py -q
```

2026-10-18 정리한 raw 본문 기준 최신 결과: 5,392개 출력 조회 중 56개 케이스에서 연결의 미해결 표시가 없고,
18개에는 명시적인 부채/제한이 남습니다. 앞선 증명 전달·출력 간 비중첩·CALL 스택 쓰기 수정으로
44→54개, 이번 최종 call-copy 값 전달(071)·마스크 인덱스 범위/모듈러 비중첩 연결(044)로 54→56개가 됐습니다.
CALLIND의 잘못 연결된 반환 주소 값도 수정했습니다. readonly 이미지의 호출 대상 값도 최종 대상 해석에 전달하며,
그 사이 실제 STORE가 슬롯을 바꾸면 이미지 값으로 덮어쓰지 않습니다.
60개 케이스 × 4입력의 raw p-code 실행과 16,742개 값·880개 STORE 주소를 대조해 불일치는 없었습니다.
이것은 네이티브 실행이나 모든 경로의 완전성 증명이 아니며, phi는 추가 후보를 허용하는 may 식입니다.

| 남은 공통 원인 | 케이스 |
|---|---|
| 외부 본문/런타임 동작 부재: 실행 대조 중단 | 030–033, 074–075, 090, 092, 110–111, 122–123, 130–131 |
| 유한한 여러 함수 포인터 대상의 합류/호출 효과 연결이 필요(엔진 잔여 작업) | 072 |
| vtable의 읽기 전용 권한·relocation 근거가 없는 보관 데이터 | 080 |
| TLS 기준 주소와 스택/전역의 분리 근거 없음 | 091 |
| 상태 머신의 간접 주소·순환 메모리, 후보 writer 출력 제한 | 201 |

이 보관 세트에는 현재 image-info/import 모델 연결용 메타데이터가 없습니다. 옛 naming/ABI 정보를 현재 증거로
가장하거나 외부 호출 값을 주입하지 않았습니다. 스택/전역 분리 가정은 사용하며, 미실행·미해결·반복식·주소 미확인
출력은 성공한 값 비교로 세지 않습니다. 이 결과를 suite09 전체 PASS로 해석하지 않습니다.

### 남은 케이스에 필요한 정보

이 세트의 `dfbench_win_core`는 이름과 달리 **Linux x86-64 ELF PIE**입니다. 원본에서
`libdfbench_importlib.so`, `libc.so.6`, `GLIBC_2.34` 심볼 의존을 확인했습니다.
Windows DLL/Win64 모델로 대체할 수 없습니다. 이름 목록은 누락 자료를 설명하기 위한 것이며,
옛 naming-v1을 새 import/ABI 증거로 승인하지 않습니다.

| 케이스 | 빠진 함수/동작 | 필요한 근거와 잔여 구현 |
|---|---|---|
| 030–033 | malloc/free/realloc | 실제 libc 빌드와 import/ABI 연결 정보. SysV64 CRT 모델은 이미 있지만 선언된 메모리 경계 효과이며 내부 raw 연산 증명은 아님 |
| 122, 123 | strcpy/memset | 같은 libc 자료와 복사/설정 범위. 현재 strcpy 모델은 첫 바이트만 확정하며 나머지는 미확정이므로 전체 복사를 증명하려면 범위 근거/본문 필요 |
| 074, 075, 130, 131 | dfb_get_opaque_fn, dfb_external_no_summary, dfb_import_identity, dfb_import_write_out | 라이브러리와 봉인 Bundle은 아래 경로에서 확인. 남은 자료는 import 슬롯/라이브러리 연결, export/relocation과 현재 naming-v2/ABI 증거이며, 실제 본문까지 보이려면 모듈 간 raw 그래프 연결도 필요 |
| 090, 092 | pthread_create/join | 생성 콜백·상태 전달·join 동기화 근거. 라이브러리 본문 외에도 스레드 실행/합류 연결 구현 필요 |
| 110 | _setjmp/longjmp | jmp_buf의 실제 물리 상태 저장·복원 및 재개 지점 근거, 비지역 제어 이동 연결 구현 필요 |
| 111 | __cxa_allocate_exception/throw/begin_catch/end_catch, _Unwind_Resume | 대응 C++ 런타임/언와인더 및 landing-pad/복원 흐름 근거, 예외 제어 이동 연결 구현 필요 |
| 080 | 읽기 전용 vtable/target 슬롯 | 최신 exporter의 봉인된 image-info(권한·relocation·import), 기존 원본 메모리 바이트와 일치해야 함 |
| 091 | TLS 기준 레지스터(실제 raw register 0x110) | 실제 TLS 주소/메모리 매핑 또는 명시적 플랫폼 분리 계약. 현재 상태만으로는 분리라고 가정하지 않음 |

최신 Ghidra 12.0.4 exporter로 **같은 원본**을 다시 추출하면 image-info와 naming-v2/ABI 연결 자료를 얻을 수 있습니다.
추가 검색에서 `../tdo_testbed/dist/docker-linux/linux_amd64/build/libdfbench_importlib.so`를 찾았습니다.
같은 디렉터리의 실행 파일 SHA-256은 이 보관 원본과 일치하며, 라이브러리 SHA-256
`f0ec5debef288747673743b7de5f24370111621f1f9e34b211236ca10d1090e7`도 보관된 라이브러리 Bundle
`../lowpcode_data_origin_v2/output/evidence/c09-importlib-inputs-20261003/bundle/ee8961c5e91dff967166272e88fe84262caf499ba261212e687cf25592290e81`
원본과 일치합니다. 이 라이브러리까지 새로 제공할 필요는 없지만, 보관 Bundle에도 image-info가 없어 현재 유도/연결 경로에
바로 넣을 수 없습니다. 현재 Docker daemon은 실행 중이 아니며, 대응 libc/C++ 런타임과 UE 원본 파생 Bundle은 찾지 못했습니다.
로컬 실행도 시도했지만 Docker.app은 실행 파일 부재(`kLSNoExecutableErr`, -10827)로 열리지 않아 재추출을 진행하지 못했습니다.
자료만 확보해도 스레드·비지역 이동·072의 다중 대상·201의 순환 상태 분석이 자동으로 완성되는 것은 아닙니다.

091은 원본 p-code로 반례도 실행했습니다. SP=0x70000000, TLS 기준=0x70000004이면
`[TLS기준 - 4] = source_A`가 반환 주소를 실제로 1로 바꿉니다. 이때 엔진은 may-alias 부채를 유지합니다.
마스크 범위 밖·중간 인덱스 오염·넓은 인덱스의 전역 접근 반례도 회귀 테스트에 포함합니다.

alias/상수 추론 변경에 따라 `ENGINE_SEMANTICS_VERSION`을 11로 올렸습니다. 기존 배포된 UE FString 파생 모델(v10)은
안전하게 거부되며, `test_shipped_derived_models_match_this_engine`가 현재 실패합니다. 버전 숫자만 바꿔 승인하지 않습니다.
재생성에는 원래 Bundle `ea65ba0c9345504088f51de08e477313a79135fb99ae07e159816022ec7749aa`,
Core DLL SHA-256 `fdea959764879bb55602c88a80a1adf6307b637c0c04f4b01f2e28c2fcb7b942`와 그 stack scan 근거가 필요합니다.
따라서 이 변경은 UE 파생 모델 재생성까지 전체 회귀 완료/병합 가능 상태라고 보고하지 않습니다.
이번 최종 전체 회귀는 1,011개 통과·위 모델 호환성 검사 1개 실패입니다. 044/071은 각각 경계값·무작위값을 포함한
108입력 추가 실행에서도 값/주소 불일치가 없었습니다. 라이브러리 유도 경로의 image-info 부재도 실제로 재현했고,
일반 AttributeError 대신 필요한 export/import/relocation 정보를 명시하는 거부 메시지로 수정했습니다.

### 다른 PC에서 브랜치 검토하기 (2026-10-18)

검토 브랜치는 `feature/callee-operation-records`이며, 기준 커밋은 `6600983`입니다. main에 병합하지 않은
작업 중 스냅샷입니다. 다른 PC의 main 작업 폴더를 바꾸지 않고 별도 폴더에서 검토하려면, 해당 저장소에서 실행합니다
(아래 폴더가 이미 있으면 새 경로를 사용).

```bash
git fetch origin
git worktree add --detach ../tdo-callee-review origin/feature/callee-operation-records
cd ../tdo-callee-review
git diff --stat 6600983..HEAD
python3 -m venv .venv
.venv/bin/python -m pip install -e . pytest
PYTHONPATH=src:tests/intra .venv/bin/python -m pytest tests/intra/test_call_expressions.py tests/intra/test_call_value_targets.py tests/intra/test_bounded_index_aliases.py -q
```

핵심 검토 위치는 `call_expressions.py` / `operation_records.py`의 호출 전 SSA와 실제 연산 연결,
`relative_memory.py` / `may_alias.py`의 값·범위 전달과 불확실한 alias 유지입니다.
실제 데이터 비교는 위 `TDO_SUITE09_X64`와 `TDO_DFBENCH054_BUNDLE`을 지정하고 `.venv/bin/python -m pytest -q`로 재실행합니다.
Bundle·원본 바이너리·로컬 환경은 Git 관리 대상이 아니며 이 브랜치의 push에 포함하지 않습니다. 다른 PC에는 같은 봉인된
자료를 별도로 준비해야 하며, 지정하지 않으면 실제 데이터 테스트는 skip합니다.

검토 시점의 잔여 작업은 위 18개 케이스와 UE 파생 모델 v11의 정식 재생성입니다. 모델 원본 자료가 없어
호환성 검사 1개가 실패한 상태입니다. 전체 PASS나 main 병합 가능 상태로 해석하지 않습니다.
푸시 전 핵심 회귀 테스트(위 3개 파일) 37개와 실제 Bundle 회귀 테스트 5개를 다시 실행해 모두 통과했고,
기존 UE 모델 호환성 검사 실패도 별도로 재현했습니다.

## 검증

- **지표**: `tools/graph_fidelity/dfbench_metric.sh` — 케이스마다 정확/누락/초과 × 확실/불확실.
- **프로그램 오라클**: `tools/graph_fidelity/measure_program.py <generation> --models` — 함수를 무작위 입력으로 실제로
  실행해, 값이 흘러간 바이트를 그래프가 놓쳤는지(missing) 봅니다. 놓친 바이트는 0이어야 합니다. 부채로 설명된 것은
  `unexplained`로 따로 셉니다.
- **golden 비교**: `tools/graph_fidelity/golden_all.sh compare <golden> <new>`.

이전 main 기준(2026-10-16) 지표 (정확 / 정확+확실; 위 raw 연산식 검증과는 다른 지표):

| Bundle | 케이스 | 결과 |
|---|---|---|
| 09 testbed win-debug | 74 | 66 / 62 |
| 09 testbed win-release | 55 | 53 / 48 |
| 09 testbed win32-release | 47 | 44 / 37 |
| UE DLL DebugGame | 22 | 15 / 15 (접근 함수 가정 + 바인딩: 17) |
| UE DLL Development | 22 | 16 / 16 (접근 함수 가정 + 바인딩: 18) |

어느 Bundle에서도 "누락 + 확실"은 0이고, 프로그램 오라클의 누락은 0입니다(zlib의 256은 예전부터 있던 것).
이 브랜치의 최신 전체 자동 테스트는 1,011개 통과·1개 실패입니다(위에 설명한 UE 파생 모델 버전 불일치).
실제 DFB054 1개·suite09 4개 테스트를 포함하며, 해당 Bundle 환경 변수를 제공하지 않으면 이 5개는 skip합니다.

## 문서

- [`docs/interprocedural_design.md`](docs/interprocedural_design.md) — 함수 간 분석의 설계·결정·결과 기록(1–25절).
  25.25절은 남은 한계마다 **[정방향]**(정방향 분석이 풀 수 있음) / **[역방향]**(지금 엔진에 규칙을 더하면 풀림) /
  **[가정]**(이름 붙은 가정으로만) 표시를 모아 둔 표입니다.
- [`docs/intra_function_stabilization.md`](docs/intra_function_stabilization.md) — 함수 내부 그래프 안정화.
- [`docs/assumptions.md`](docs/assumptions.md) — 이름 붙은 가정 전체.
- [`tools/bundle_export/README.md`](tools/bundle_export/README.md) — 내보내기, DLL 연결, 스택 전환 검사.

## 한계와 다음 단계

- 단일 값으로 증명된 간접 호출 대상과 콜백의 실제 본문 연결은 구현했습니다. 여러 대상의 효과 합류(072),
  외부 콜백·스레드의 실행 연결은 남아 있습니다.
- 마스크로 제한된 index와 모듈러 주소의 비중첩 판정은 구현했습니다. 임의 index의 범위나 모든 버퍼 경계를
  증명하는 일반 정방향 분석은 아직 아닙니다.
- 비트 단위 정밀도(마스크·비트필드)는 미뤄 두었습니다. 엔진은 바이트 단위입니다.
- 다음 작업은 위 18개 잔여 케이스를 공통 원인별로 해결하고, 같은 원본을 다시 내보내 외부 연결 근거와
  UE 파생 모델을 갱신하는 것입니다. 재귀는 이번 검토 범위에서 제외합니다.
