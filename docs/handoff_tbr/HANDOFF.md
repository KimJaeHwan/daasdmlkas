# TBR G2b 집 작업 인계 (2026-11-27, Mac Studio M4; 집 브랜치 전용 — main / feat 브랜치에 넣지 않는다)

브랜치: `home/tbr-g2b-2026-11-27` = `feat/g1-decode-check` 7a3cefe + 이 폴더(`docs/handoff_tbr/`, 집 브랜치 전용).
회사로 가져올 때 이 폴더는 빼고, 집에서 만든 커밋만 `feat/g1-decode-check`에 올린다.
원칙: **같은 입력이면 어느 기계에서든 결과가 같아야 한다**(속도만 다르다). 그래서 Mac에서 먼저 회사 결과와의 동일성(§4)을 확인한다.

## 1. 지금 어디까지 왔나

- TBR = Ghidra 독립(Trace Bedrock). 계획 문서는 브랜치 `docs/ghidra-independence`(push됨)에 있고, 사본이 이 폴더의
  `PLAN_ghidra_independence_dd7344f.md`. 전체 로드맵은 §1a.
- G0 lint → G1 해독 교차확인 → **G2 공통 사실 층**: G2a 닫힘, 비용 압축 닫힘, **G2b 구현 리뷰 중** → G2c(AArch64) → G3 …
- G2b = 코드 바이트 사실. 설계 `design/design_tbr_g2b_code_facts_r1.md` + `_r2.md` + `_r3.md`(닫힘), 바탕 `design_tbr_g2_common_facts_r5.md` §5.
  - 코드: `tools/decode_check/code_facts.py`, `code_site_names.json`, `decode_check.py`(collector `row_proof`, `run()`의
    `build_code`), `evidence.py`(`read_g2b`). 커밋 897d17d → ecc9074 → 89646f0 → fde5afb → **7a3cefe**(push됨).
  - 테스트 587개(G2b 48), 회사 WSL에서 시드 0·1 통과.
- 회사 측정(7a3cefe, 기준 c15a29a, 순서 base,new,new,base):
  - 동등성(`cost_probe/equiv_g2b.py`, 보고서 전체 비교): zlib·clang·v3·ntdll·UE **모두 PASS**.
  - 비용: UE 깨끗한 한 쌍 new 1068 s / base 1081 s(−1%), peak 5.65 → 6.07 GB(+7.4%); ntdll +3.5% / +6%;
    작은 Bundle은 잡음 범위. (첫 UE 쌍은 다른 세션이 13 GB를 쓰던 때라 제외.)
  - facts 크기: UE +14.1%, ntdll +9.0%, zlib +23.8%, clang +19.5%, v3 +27.4%.
  - 지점: ntdll trap 200; UE trap 1734 + self_modify 4 + dynamic_resolution 5, VirtualAlloc 6 NO_RWX_REGISTER.

## 1a. 전체 로드맵 G0 ~ G6 (상태 · 남은 작업량)

**계획 원문은 이 폴더의 `PLAN_ghidra_independence_dd7344f.md`** (= `docs/ghidra-independence` dd7344f 사본).
이 브랜치의 `docs/ghidra_independence_plan.md`는 **G2를 넣기 전 옛 번호(04ec1c7)라서 쓰지 않는다** (옛 G2~G5 = 지금 G3~G6).
계획을 고칠 때는 `wt_docs`(브랜치 `docs/ghidra-independence`)에서 고치고, 이 사본은 참고용이다.

작업량은 지금까지의 속도(G2a ≈ 설계 5라운드 + 구현 2라운드, G2b ≈ 설계 3라운드 + 구현 리뷰 진행 중)로 잡은 **대략치**다.
"덩어리" = 설계 → 구현 → 측정 → 리뷰 종결까지 한 묶음 (대략 하루~며칠).

| 단계 | 내용 | 상태 | 남은 작업량 |
|---|---|---|---|
| G0 | Bundle 규약 문서 + `bundle_lint` | 끝 (브랜치 `feat/g0-bundle-lint`, main에 넣지 않고 따로 둠) | 유지보수만 |
| G1 | 독립 해독기(iced / Zydis / XED) 교차 확인 | 끝 (`feat/g1-decode-check`에 포함) | 후속: XED target shim, ARM 투표자 |
| **G2** | x86 / ARM 공통 사실 층 (TBR 형식) | **진행 중** | **약 3~5 덩어리** |
| └ G2a | x86 제어 이동 사실 + 판정 -4 | 닫힘 798b903 | — |
| └ 비용 압축 | -5 판정 블록, UE peak 11.2 → 5.6 GB | 닫힘 c15a29a | 시간 줄이기는 Rust 포팅 때 |
| └ **G2b** | 코드 바이트 사실 (trap, import 분기, 레지스터 값, 코드 쓰기) | **구현 리뷰 중 7a3cefe — 집 작업 §2** | 1 덩어리 (Astra r2 반영 → r3) |
| └ G2c | AArch64 (EL0/EL1, PAC/BTI, exclusive, x30 link, TBI) | 다음 (시작 전 소유자 설명·승인) | 1~2 덩어리 (ARM 투표자 필요 여부에 따라) |
| └ 엔진 읽기 | TDO가 G2 사실을 읽음 | S3 뒤, 메인 세션 몫 | (TBR 밖) |
| G2 뒤 | **로더 적용 값** (재배치 식, import 정체, 채움 시점, RELRO+BIND_NOW, **DVRT**) | 계획만 (소유자 승인) | 1~2 덩어리 |
| G2 뒤 | dynamic_resolution용 문자열 / LEA 사실 | 후속 목록 | 작음 |
| G3 | 엔진의 Ghidra 관례 → "lifter 프로필" (엔진 코드, 회사 세션에서 게이트와 함께) | 시작 전 | 2~3 덩어리, 게이트 필요라 집 단독 불가 |
| G4 | **자체 생산자**: PE/ELF 로더 + 해독/lifter(추천: pypcode/libsla) + 최소 분석 + call-names | 시작 전 | **가장 큼, 약 5~10 덩어리** |
| └ G4 예약 | 바이트 출처 + 스냅샷 id, 해독 요청 id (G3/G4 형식에 자리만) | 계획에 기록 | G4 안에서 |
| └ G4 점프 테이블 | 필요할 때 해독 / 질의 주소 시작 / 불변 라운드 (컴파일러 패턴 금지) | 아이디어만, 설계는 G4에서 (Fable 리뷰) | G4 안에서 1~2 덩어리 |
| G5 | 대조: 같은 바이너리를 Ghidra Bundle vs 새 Bundle로 엔진 결과 비교, 차이 분류 | 시작 전 | 2~3 덩어리 (G4와 겹쳐 진행) |
| G6 | 전환 또는 병행 운영 결정 | — | 소유자 결정 |

추천 순서 (계획 §5): G0 → G1 → **G2 (지금)** → G4 1번 경로 + G5 → G3.
전부 합치면 대략 **15~25 덩어리**이고, 가장 큰 덩어리는 G4다. Rust 포팅(R0~R5)은 이 일정과 따로 잡혀 있고,
지금 만드는 형식은 언어 중립 스키마라서 포팅 때 다시 설계하지 않는다.

집에서 할 수 있는 범위: G2b/G2c, 로더 적용 값, G4, G5 (형식만 맞추면 되는 부분).
G3과 엔진 읽기는 엔진 코드라 회사 세션에서 게이트와 함께 한다.

## 2. 집에서 할 일 (순서대로)

1. **준비**: `mac/setup_home_mac.sh ~/Downloads` (아래 §3). 끝에 Mac ↔ 회사 동일성 검사(§4)까지 돈다.
2. **Astra 구현 리뷰 r2 반영** — `design/g2b_impl_astra3.md` (REJECT, 교체 코드 포함):
   - 받아들여진 것: 실제 디코더 테스트의 15바이트 창, 길이 없는 행에서 길이 비교 생략, **디코더 합의 길이 제안 채택**.
   - 고칠 것 (Astra가 코드를 씀): ① 행 길이 `null`인 Bundle에서 디코더 합의 길이로 행 구간·선행자 인덱스를 만든다
     (순차 edge 조건 포함; relocation이 소비 구간에 있으면 제외) — zlib의 `INDEX_INCOMPLETE` 1,776 / 1,793건이 줄어야 함;
     ② `FF E0`(jmp rax)처럼 레지스터 간접 분기를 슬롯 분기로 보지 않도록 디코더의 `target_kind`를 확인(`FORM_MISMATCH`).
   - 반영 방법: 같은 이름 최상위 정의 교체 + 새 정의 추가 + 테스트 추가 (회사에서는 AST로 교체하는 스크립트를 썼다).
3. **검증**: 시드 0·1 전체 테스트(skip 0) → `mac/run_abba_mac.sh`(기준/새 코드 번갈아, 동등성 포함) → 결과 기록.
4. **Astra 리뷰 r3** (Fable은 이번 라운드 생략했으니 다음부터 다시 받는다). 반려면 Astra에게 완전한 수정 코드를 받아 검토·반영.
5. G2b가 닫히면 다음은 G2c(AArch64). 시작 전에 소유자에게 쉽게 설명하고 승인받는다.

## 3. Mac 준비 (Apple silicon)

- 필요: Xcode Command Line Tools(clang이 `gcc`로 쓰임), git, Homebrew `python@3.14`, 네트워크(디코더 소스·pip).
- 파일 두 개를 `~/Downloads`에 둔다 (비공개, 견본 바이너리 포함 — 절대 공개 금지):
  - `tbr_g2b_home_data_2026-11-27.zip` (86 MB): Bundle 5개(각 Bundle 안에 원본 `original.bin` 포함) + `g1_runs/main_src_1828683`
    (clang Bundle 입장용 엔진, 원격에 없는 main 1828683).
  - `tbr_g2b_home_results_2026-11-27.zip` (49 MB): `g1_runs/g2b_r2_base`(c15a29a 기준 출력) + `g1_runs/g2b_r2_new`(7a3cefe 회사 출력).
  - 각 `.sha256` 파일.
- 실행: `REPO=~/work/daasdmlkas DATA=~/tbr_data bash mac/setup_home_mac.sh ~/Downloads`
  (저장소가 없으면 clone, worktree `wt_lint`=집 브랜치 / `wt_g2b_base`=c15a29a / `wt_docs`, venv `$REPO/.venv-tdo`,
  데이터는 `$DATA`에 회사 `/root`와 같은 상대 경로로 풀림).
- 디코더: 회사의 Linux 빌드는 못 쓴다. `tools/decode_check/build_decoders.sh`로 고정 버전(iced 1.22.0, Zydis v4.1.1 a2278f1d,
  XED v2026.08.23 0bcb6237)을 다시 빌드해 `G1_DECODERS=$DATA/g1_decoders`에 둔다. `decoders.py`가 이 환경변수를 읽는다.
  빌드가 Mac에서 실패하면 그 오류부터 고친다(스크립트는 `gcc -shared -fPIC`를 쓴다; clang으로 대개 그대로 된다).
- 매 셸: `source $REPO/.census6/wt_lint/docs/handoff_tbr/mac/env.sh` (REPO, DATA, PY, G1_DECODERS, Bundle 경로 변수).
- 시간·메모리 측정은 `mac/timed.py`(GNU `time -f` 대신). `ulimit -v`는 쓰지 않는다.

## 4. Mac ↔ 회사 동일성 (먼저 확인)

`mac/parity_mac.sh [zlib clang v3 ntdll ue_probe]`: 7a3cefe를 Mac에서 돌려 `$DATA/g1_runs/g2b_r2_new`(회사 출력)와 비교한다.
- 기대: facts 파일 **바이트 동일**, -5 블록 동일, 증거·보고서는 디코더 빌드 해시(`library_sha256`, `libxed_sha256`,
  `record_sha256`)와 출력 경로만 다름.
- 다르면 `mac/parity_check.py`가 처음 다른 행과 필드를 찍는다. 대개 디코더 빌드 차이이므로 그 행의 투표부터 본다.
  동일성이 확인되기 전에는 Mac의 측정·리뷰 결과를 회사 결과와 섞지 않는다.

## 5. 지켜야 할 규칙 (요약)

- **ABI 가정 금지** (no ret / no arg / no convention): 호출 인자는 "호출 시점 레지스터 값"만, 인자 번호는 U.
- **Ghidra 독립**: 근거는 파일 바이트 또는 디코더. Ghidra 관측을 쓰는 단계는 `ghidra_pcode`로 표시.
- 증명 못 하면 U / unresolved. 증명 없는 음성 판정 금지. 이유 코드는 `REASONS`(닫힌 목록).
- 바이트 근거: `file_record`(파일의 조회 정보, 로더 쓰기 구간 허용) / `file_runtime`(실행 시 내용, 쓰기·재배치 금지).
- 리뷰: Astra + Fable 2라운드 이상, 충돌 시 Astra. 반복 반려 시 Astra가 수정 코드를 쓰고 Claude가 검토.
- 실행 중 src/tests 수정 금지. `PYTHONHASHSEED=0`. 성능 변경은 전후 시간·peak 비교 후 커밋.
- 커밋 작성자 `-c user.name="김재환2 [rfkjh22]" -c user.email="rfkjh22@nexon.co.kr"`, 메시지 끝
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. push는 소유자 승인 후.

## 6. 회사에서 반영할 때 (집 → 회사)

1. 집 브랜치에 커밋 push (`docs/handoff_tbr/` 변경은 섞지 않거나 별도 커밋).
2. 회사 세션: fetch → `feat/g1-decode-check`(7a3cefe) 대비 diff → 집 커밋만 올림.
3. 회사에서 다시: 시드 0·1 전체 테스트(skip 0), 다섯 Bundle 동등성(`equiv_g2b.py`, 기준 c15a29a), ABBA 비용(+10%), Astra(+Fable) 리뷰.
4. Mac 결과는 §4 동일성이 PASS였을 때만 참고 수치로 같이 기록.

## 7. 폴더 안내

- `mac/`: `setup_home_mac.sh`, `env.sh`, `parity_mac.sh`, `parity_check.py`, `run_abba_mac.sh`, `timed.py`.
- `cost_probe/`: 회사(WSL) 측정·검증 스크립트 원본 (`equiv_g2b.py`는 Mac에서도 그대로 씀).
- `design/`: G2 r5, G2b 구현 설계 r1–r3, 구현 리뷰(Astra r1·r2, Fable r1), Astra가 쓴 r1 수정 코드.
- `requirements_wsl_tdo.txt`: 회사 venv 패키지 버전(`-e` 줄 제외하고 설치).
- `PLAN_ghidra_independence_dd7344f.md`: 최신 전체 계획 G0~G6 사본 (§1a). 이 브랜치의 `docs/ghidra_independence_plan.md`는 옛 판.
