# Android ARM64 .so 분석하기 (실행 순서)

ARM64 `.so` 하나를 Bundle로 내보내고, source/sink 질의를 돌려 결과를 보는 순서.
모든 명령은 저장소 루트(작업 트리)에서 실행한다. 개발 PC는 WSL(root), Mac은 `docs/mac_setup.md`.
아래 `python3`는 프로젝트 venv의 python이다(Mac: `~/venvs/tdo/bin/python`). Bundle 경로 `/root/...`는
Mac에서 `~/tdo_data/...`로 읽는다.

## 0. 준비

- APK 원본은 건드리지 않는다. `.so`만 새 빈 폴더에 꺼낸다:
  ```bash
  mkdir -p ~/so_in/libyolo && unzip -j -o APP.apk "lib/arm64-v8a/libyolo.so" -d ~/so_in/libyolo
  ```
- PAC 사용 여부(참고): `readelf -n libX.so` 에 PAC 표시가 있거나, 함수에 `paciasp`/`autiasp`가 보이면 PAC 사용.
  지금 엔진은 PAC이 있는 함수의 복귀를 "모름"으로 둔다(Stage 4에서 모델 추가 예정).

## 1. 진입점 고르기

JNI 진입점(`JNI_OnLoad`, `Java_*`)과 그 밖의 내보낸 함수:
```bash
readelf --dyn-syms -W ~/so_in/libyolo/libyolo.so | awk '$4=="FUNC" && $7!="UND" {print $8}' | sed 's/@.*//' | sort -u
```

## 2. Bundle로 내보내기 (Ghidra 12.0.4 headless)

선택한 함수와 그 호출 closure를 내보낸다. Bundle은 POSIX 파일시스템(WSL `/root/...`, Mac 홈 폴더)에 둔다(WSL의 `/mnt/d`는 admission 불가).
```bash
PYTHONPATH=src python3 tools/bundle_export/export_bundle.py ~/so_in/libyolo/libyolo.so \
    --function-name JNI_OnLoad --function-name Java_com_nx_assist_lua_YoloV5_nativeDetect \
    --output-root /root/tdo_bundles_so/libyolo
```
- 함수가 많으면 `--function-name`을 여러 번 쓴다. 출력 마지막 줄 `[export] published <경로>`의 경로가 이번 Bundle이다
  (같은 폴더에 여러 번 내보내면 generation이 여러 개 생긴다 -- 반드시 이번에 나온 경로를 쓴다).
- Ghidra 위치 기본값은 "저장소 폴더의 옆"(`../ghidra_12.0.4_PUBLIC`)이다. `.census6/wt_*` 같은 작업 트리에서 실행하면
  `--ghidra <Ghidra 폴더>`를 붙인다(개발 PC: `/mnt/d/01_gitproject/14_TDO_v2/ghidra_12.0.4_PUBLIC`).
- Mac에서는 JDK 위치도 붙인다: `--java-home "$(brew --prefix openjdk@21)/libexec/openjdk.jdk/Contents/Home"`.

## 3. 어떤 호출이 있는지 보기

```bash
G=/root/tdo_bundles_so/libyolo/<export가 출력한 generation>
PYTHONHASHSEED=0 PYTHONPATH=src python3 tools/analyze_bundle/analyze_query.py "$G" --list-calls --out /tmp/libyolo_calls.json
python3 -c "import json; print(json.load(open('/tmp/libyolo_calls.json'))['call_targets'])"
```
PLT를 거치는 라이브러리 함수도 이름으로 나온다(`memcpy`, `strlen`, ...). 숫자는 분류 호출 횟수다(호출 지점 수 아님).

## 4. 질의 파일(query.json) 쓰기

```json
[
  {"target_name": "getenv", "kind": "source", "label": "getenv.ret",
   "physical_state": [{"register": "x0"}]},
  {"target_name": "strlen", "kind": "sink", "label": "strlen.string_first_byte",
   "physical_state": [{"base": {"register": "x0"}, "displacement": 0, "byte_size": 1}]},
  {"target_name": "send", "kind": "sink", "label": "send.buffer_pointer",
   "physical_state": [{"register": "x1"}]}
]
```
- `register`: Bundle에 내보낸 레지스터 이름(`x0`..`x30`, `w0`.., `sp`). 크기는 생략하면 그 레지스터 크기.
- `base` + `displacement` + `byte_size`: 레지스터가 가리키는 메모리의 바이트.
- 인자/반환이 어느 레지스터에 있는지는 질의 작성자가 정한다(엔진은 호출 규약을 가정하지 않는다).
- source는 레지스터만 된다(메모리 source는 엔진이 붙이지 않으므로 도구가 거부한다).
- 레지스터 이름은 정확히 일치하는 것을 먼저 쓰고, 대소문자만 다른 후보가 여럿이면 오류로 멈춘다.

## 5. 실행과 결과

```bash
PYTHONHASHSEED=0 PYTHONPATH=src python3 tools/analyze_bundle/analyze_query.py "$G" --query query.json --out /tmp/libyolo_result.json
```
결과 JSON:
- `roots[]`: sink마다 `origins`(도달한 source 라벨), `complete`(빠진 경로 없이 증명됐는가),
  `effective_completeness`(왜 불완전한가: 남은 빚, 모르는 읽기 등)
- `assumptions`: 이번 실행이 기댄 가정
- `failed_functions`: 분석 실패 함수 -- 있으면 빈 origins가 "흐름 없음"의 증거가 아니다
- 불완전한 root의 `origins`는 후보다(증명이 아님)

- 함수 하나가 오래 걸리면 `failed_functions`에 `analysis_budget / function:time`으로 남는다(기본 60초).
  `--function-seconds 300`처럼 늘릴 수 있다. 전체 실행 한도는 `--run-seconds`(기본 1800).

## 실제 시험 결과 (2026-10-29, `.census6/field_cases/2026-10-29_android_so_smoke/`)

| .so | export | 분석 | roots / complete | 찾은 흐름 |
|---|---|---|---|---|
| libtsevent (30 KB) | 97 s | 13 s | 139 / 1 | free 포인터 <- malloc 반환 (23곳) |
| libyolo (59 KB) | 80 s | 33 s | 154 / 1 | memcpy 크기·목적지 <- strlen 반환, free <- malloc |
| libimgutils (67 KB) | 78 s | 151 s | 200 / 5 | memcpy 크기 <- strlen 반환 (12), free <- malloc (17); 함수 2개 시간 예산 초과 |

## 지금 ARM64 결과를 읽는 법 (2026-10-29 기준)

- 결과는 나오지만 대부분 **불완전**으로 표시된다: 모델 없는 라이브러리 호출(opaque)을 지나는 값은 정직하게 "모름".
- 엔진이 증명 못 하는 구간은 나중에 "분석가 링크"로 다리를 놓을 수 있다(예정).
- 막히는 사례는 `.census6/field_cases/`에 남기면 엔진 개선 우선순위에 반영된다.
