# Mac (Apple Silicon)에서 TDO_v2 돌리기

개발 PC(Windows + WSL Ubuntu)와 같은 일을 Mac Studio(M4 Max)에서 하기 위한 준비와 명령.
2026-10-30 작성. **아직 Mac에서 직접 확인하지 않았다**: 아래 "처음 할 일"의 확인 단계를 먼저 거친다.

## 무엇을 어디서 돌리나

| 일 | 네이티브 macOS | 비고 |
|---|---|---|
| Ghidra export (`export_bundle.py`) | 됨 | Ghidra 12.0.4에 `mac_arm_64` 디컴파일러가 들어 있다(`linux_arm_64`는 없음) |
| `.so` 분석 (`analyze_query.py`) | 됨 | `docs/analyze_so_runbook.md`의 명령 그대로, 경로만 바꾼다 |
| 단위 테스트 (`pytest`) | 될 것으로 예상 | Linux 전용 테스트는 스스로 skip한다(아래 "주의") |
| 전체 게이트 (`tools/gate/gate_par.sh`) | 확인 필요 | "처음 할 일" 3번의 결과로 정한다 |

### 주의: 큰 스택 worker는 Linux에서만 켜진다

`src/tdo_v2/resource_limits.py`의 `worker_supported()`는 Linux + CPython 3.14 이상에서만 참이다.
깊은 함수(값 의존이 수만 단계)를 분석할 때 쓰는 큰 스택 스레드가 macOS에서는 꺼진다.
그래서 같은 Bundle이라도 아주 깊은 함수는 macOS에서 실패(예산/재귀)하고 Linux에서는 성공할 수 있다.
게이트 결과가 개발 PC 기준선과 다르면 먼저 이것을 의심한다. 그때는 아래 "Linux VM으로 게이트 돌리기"를 쓴다.

## 설치

1. 기본 도구
   ```bash
   xcode-select --install
   brew install uv openjdk@21 binutils
   ```
   bash는 macOS 기본(3.2)으로 충분하다. 게이트는 GNU `time`/`timeout`이 필요 없다(`tools/gate/timed.py`가 대신한다).
   `readelf`(runbook의 진입점 목록)는 binutils에 있지만 PATH에 자동으로 들어가지 않는다:
   `export PATH="$(brew --prefix binutils)/bin:$PATH"` (셸 설정에 둔다).
2. 저장소
   ```bash
   mkdir -p ~/tdo && cd ~/tdo
   git clone https://github.com/KimJaeHwan/daasdmlkas.git
   ```
3. Python 3.14 가상환경 (개발 PC: Python 3.14.4)
   ```bash
   uv venv --python 3.14.4 ~/venvs/tdo
   uv pip install --python ~/venvs/tdo/bin/python -e ~/tdo/daasdmlkas        rustworkx==0.18.1 z3-solver==4.16.0.0 pytest==9.1.1 pytest-xdist==3.8.0
   ```
   개발 PC와 같은 버전으로 고정한다(`pyproject.toml`은 범위만 정한다: 결과 비교는 같은 버전끼리).
   arm64 macOS wheel이 없어 소스 빌드로 넘어가면 그 줄의 오류를 남겨 둔다(Rust/cmake 설치로 해결 가능).
4. Ghidra 12.0.4
   - `ghidra_12.0.4_PUBLIC`을 저장소 **옆**에 푼다: `~/tdo/ghidra_12.0.4_PUBLIC` (export의 기본 위치).
   - 다른 곳에 두면 export 때 `--ghidra <경로>`를 붙인다.
   - macOS가 처음 실행을 막으면(격리 속성): `xattr -dr com.apple.quarantine ~/tdo/ghidra_12.0.4_PUBLIC`.
   - JDK: export에 `--java-home "$(brew --prefix openjdk@21)/libexec/openjdk.jdk/Contents/Home"`를 붙인다
     (기본값은 Linux 경로라 Mac에서는 꼭 지정한다).
5. 데이터 패키지 (Bundle, 기준선 스냅샷 등: git에 없다)
   - 개발 PC에서 만든 `tdo_data_*.tar`를 받아 푼다. 받는 방법(USB, 개인 클라우드, 비공개 저장소)은
     소유자가 정한다. **공개 저장소(daasdmlkas)의 Release에는 올리지 않는다** (서드파티 .so, 기기 libc, UE 데이터).
   ```bash
   mkdir -p ~/tdo_data && tar -xf tdo_data_*.tar -C ~/tdo_data
   cd ~/tdo_data && shasum -a 256 -c MANIFEST.sha256 | grep -v ': OK$'   # (아무것도 안 나오면 정상)
   ```
   - Bundle admission은 "파일 주인 = 실행 사용자, 링크 1개, group/other 쓰기 금지"를 요구한다.
     위처럼 일반 사용자로 풀면 맞는다(`sudo tar`로 풀지 않는다).

## 환경 변수 (게이트와 스냅샷 스크립트)

`tools/gate/env.sh`가 읽는다. Mac에서는 셸 설정(`~/.zshrc`)에 둔다:
```bash
export TDO_DATA=~/tdo_data          # tdo_bundles3, tdo_snapshots, ghidra_link_evidence가 여기 있다
export TDO_PY=~/venvs/tdo/bin/python
```
나머지(`TDO_BUNDLES`, `TDO_SNAPSHOTS`, `TDO_LOGS`, `TDO_EVIDENCE`, `TDO_REPO`)는 기본값으로 충분하다.
경로에 공백이 있으면 게이트가 거부한다(`/Volumes/TDO Data` 같은 곳은 피한다).
게이트 로그는 `$TDO_DATA/gate_par_<label>/`에 생긴다.

## 처음 할 일 (확인 순서)

1. 테스트 한 묶음 (몇 분):
   ```bash
   cd ~/tdo/daasdmlkas
   PYTHONHASHSEED=0 PYTHONPATH=src:tests/intra ~/venvs/tdo/bin/python -m pytest -q -p no:cacheprovider -n 12 tests/intra/test_premises.py tests/intra/test_model_callbacks.py tests/intra/test_link_call_restoration.py
   ```
2. `.so` 하나 분석 (runbook 3~5단계, Bundle은 데이터 패키지의 `tdo_bundles_so`):
   ```bash
   G=$(ls -d ~/tdo_data/tdo_bundles_so/libyolo/*/ | head -1)
   PYTHONHASHSEED=0 PYTHONPATH=src ~/venvs/tdo/bin/python tools/analyze_bundle/analyze_query.py "$G" --list-calls --out /tmp/libyolo_calls.json
   ```
3. 전체 게이트: main을 기준선 `pc1b`(개발 PC에서 같은 코드로 만든 스냅샷)와 비교 (개발 PC 약 30분):
   ```bash
   SUITE_WORKERS=8 SNAP_JOBS=6 ORACLE_JOBS=8 bash tools/gate/gate_par.sh pc1b mac-main1
   grep -vE 'identical' ~/tdo_data/gate_par_mac-main1/snapshot.txt | head -30
   ```
   - 스냅샷이 모두 `identical`이고 테스트가 통과하면: Mac 네이티브 게이트를 그대로 쓴다.
   - 다르면: 차이 목록을 `.census6`/필드 케이스에 남기고, Mac에서 만든 `mac-main1`을 이후 Mac 게이트의
     기준선으로 쓴다(같은 기계끼리만 비교). 플랫폼 차이 자체는 개발 PC에서 원인을 본다.
   - 워커 수: M4 Max(코어 16, 메모리 넉넉)라면 위 값에서 시작해 늘려 본다. 개발 PC는 7/4/6(20 스레드, 15 GB).

## Linux VM으로 게이트 돌리기 (네이티브 결과가 다를 때)

OrbStack(또는 Lima/UTM)의 Ubuntu arm64 머신에서 개발 PC의 WSL과 같은 방식으로 돌린다.
- VM 안에 Python 3.14 venv(`~/venvs/tdo`)를 같은 방식으로 만든다(z3-solver, rustworkx는 Linux aarch64 wheel이 있다).
- Bundle은 VM의 Linux 파일시스템으로 복사한다(공유 폴더는 admission의 주인/권한 검사에 걸릴 수 있다):
  `rsync -a ~/tdo_data/ <vm>:~/tdo_data/`
- Ghidra export는 Mac 네이티브에서 하고, 나온 Bundle 폴더만 VM으로 복사한다(VM용 linux_arm_64 디컴파일러는 배포본에 없다).

## 비교 도구

- 두 게이트의 oracle 결과 비교: `bash tools/gate/oracle_compare.sh <old label> <new label>`
- 스냅샷만(빠른 확인): `STOP_AFTER=snapshot bash tools/gate/gate_par.sh <base> <new>`
- 게이트의 판정: 마지막 줄 `GATE RESULT: PASS` 또는 `GATE RESULT: FAIL: <실패한 검사들>`(종료 코드 0/1).
  스냅샷 차이가 의도된 변경이어도 FAIL로 나온다: 차이 목록을 보고 사람이 판단한다.
- 게이트 멈추기: 그 터미널에서 Ctrl-C(모든 작업이 함께 멈춘다).
- 다른 작업 트리를 게이트: `TDO_REPO=<트리 경로> bash tools/gate/gate_par.sh <base> <new>`
  (게이트 도구는 이 스크립트가 있는 트리의 것을 쓰고, 분석 코드는 `TDO_REPO`의 것을 쓴다)

## 규칙 (개발 PC와 같다)

- 게이트가 도는 동안 그 트리의 `src/`, `tests/`를 고치지 않는다(결과가 섞인다). 고칠 것은 다른 작업 트리에서.
- 작업 시간 비교(`step()` work)는 `PYTHONHASHSEED=0`으로만 비교한다.
- push는 소유자 확인 후.
