# TBR G2b 집 작업 인계 (2026-11-27, 집 브랜치 전용 — main / feat 브랜치에 넣지 않는다)

브랜치: `home/tbr-g2b-2026-11-27` = `feat/g1-decode-check` 7a3cefe + 이 폴더(`docs/handoff_tbr/`, 집 브랜치 전용).
회사로 가져올 때 이 폴더는 빼고, 집에서 만든 커밋만 `feat/g1-decode-check`에 올린다.

## 1. 지금 어디까지 왔나

- TBR = Ghidra 독립(Trace Bedrock). 계획 문서: `docs/ghidra_independence_plan.md` (브랜치 `docs/ghidra-independence`).
- G0 lint → G1 해독 교차확인 → **G2 공통 사실 층** (G2a 닫힘, 비용 압축 닫힘, **G2b 진행 중**) → G2c(AArch64) → G3 …
- G2b = 코드 바이트 사실 (설계 r5 §5, 구현 설계 `design/design_tbr_g2b_code_facts_r1.md` + `_r2.md` + `_r3.md`, 닫힘).
  - 코드: `tools/decode_check/code_facts.py` (파일 층 / trap / import 지점 / 레지스터 경로 / STORE / survey / binder),
    `code_site_names.json`, `decode_check.py`(collector 훅 `row_proof`, `run()`의 `build_code`), `evidence.py`(`read_g2b`).
  - 커밋: 897d17d(1) ecc9074(2) 89646f0(3) fde5afb(4) 7a3cefe(5: 구현 리뷰 r1 수정, Astra가 쓴 코드 반영).
  - 테스트: `tests/intra/test_decode_check.py` 587개 (G2b 48개), 시드 0·1 통과 (WSL, 디코더 빌드 필요).

## 2. 남은 일 (순서대로)

1. **비용 판정**: 회사에서 ABBA 측정(기준 c15a29a / G2b 번갈아, UE 양쪽 2회) 중에 인계됨. 결과가 회사 세션 보고에 있으면
   그것을 쓰고, 없으면 `cost_probe/run_g2b_abba.lf.sh`로 다시 잰다. 예산: Bundle·지표별 +10%. 앞선 단일 쌍에서 UE +13%였으나
   잡음이 크다(zlib 같은 입력 15.7–25 s). G2b 자체 비용은 ntdll 5.2%(`cost_probe/g2b_own_time.py`).
2. **동등성**: `cost_probe/equiv_g2b.py <base_dir> <new_dir> <name>` (기준 = c15a29a 실행 결과). facts는 `producer.rule`과
   `program.code`만, -5 블록은 `facts_sha256`만, 증거는 `producer.tool_digest`만, 보고서는 새 `common_facts.code`와
   `evidence_out` 경로만 달라야 한다. (이번 수정본은 보고서 **전체** header/rows를 비교한다.)
3. **구현 리뷰 r2 (Astra만; 이번 라운드 Fable 생략 — 소유자 지시)**. 함께 올릴 것:
   - 반영하며 Claude가 고친 두 곳: 실제 디코더 테스트의 15바이트 창, 행 길이 없는 Bundle(zlib, v3)에서 길이 비교 생략
     (FORM_MISMATCH 1,885 → 0).
   - **제안**: 행 길이가 없는 Bundle에서 직접 대상 분류와 레지스터 경로가 전부 `INDEX_INCOMPLETE`가 된다(zlib 1,776건).
     디코더 합의 길이(모든 voter 합의, verified 창 안)로 행 범위를 정하면 판정 가능. 설계 판단 필요.
   - Astra가 반려하면: Astra에게 완전한 수정 코드를 쓰게 하고, 검토해 반영 (소유자 규칙).
4. G2b 닫힌 뒤: 다음은 G2c(AArch64). 시작 전에 소유자에게 쉽게 설명하고 승인받는다.

## 3. 지켜야 할 규칙 (요약)

- **ABI 가정 금지** (no ret / no arg / no convention). 호출 인자는 "호출 시점 레지스터 값"만; 인자 번호는 U.
- **Ghidra 독립**: 근거는 파일 바이트 또는 디코더. Ghidra 관측을 쓰는 단계는 `ghidra_pcode`로 표시.
- 증명 못 하면 U / unresolved. 증명 없는 음성 판정 금지. 이유 코드는 `REASONS`(닫힌 목록).
- 바이트 근거 둘: `file_record`(파일의 조회 정보, 로더 쓰기 구간 허용) / `file_runtime`(실행 시 내용, 쓰기·재배치 금지).
- 리뷰: Astra(+Fable) 2라운드 이상, 충돌 시 Astra. 반복 반려 시 Astra가 수정 코드를 쓰고 Claude가 검토.
- 실행 중에는 src/tests 수정 금지. 시드 `PYTHONHASHSEED=0`. 측정 전후 시간·peak 비교 후 커밋.
- 커밋 작성자: `-c user.name="김재환2 [rfkjh22]" -c user.email="rfkjh22@nexon.co.kr"`, 메시지 끝
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. push는 소유자 승인 후.

## 4. 환경

- WSL Ubuntu, Python 3.14 venv: pytest 9.1.1, pytest-xdist 3.8.0, numpy 2.5.3, rustworkx 0.18.1, z3-solver 4.16.0.0,
  그리고 저장소 `pip install -e .`.
- 디코더: `tools/decode_check/build_decoders.sh` (iced-x86 1.22.0, Zydis v4.1.1 a2278f1d, XED v2026.08.23 0bcb6237 —
  네트워크 필요) 또는 회사의 `/root/g1_decoders` 묶음(202 MB)을 같은 경로에 푼다. 디코더가 없으면 G2b 테스트 일부가 skip된다
  (skip 0이어야 통과로 친다).
- 테스트: `PYTHONHASHSEED=0 PYTHONPATH=src python -m pytest -q tests/intra/test_decode_check.py -rs` (시드 1도).

## 5. 파일로 가져갈 것 (git에 없음, 비공개 — 견본 바이너리 포함, 절대 공개 금지)

| 무엇 | 회사 경로 (WSL) | 크기 | 용도 |
|---|---|---|---|
| zlib Bundle | /root/tdo_bundles3/zlib/53a9289f… | 22 MB | ELF, 길이 없는 Bundle 시험 |
| v3-win-release-full Bundle | /root/tdo_bundles3/v3-win-release-full/9afa593e… | 2.7 MB | PE, import 68개 |
| clang-x64-O0 Bundle | /root/tdo_bundles4/corpus/clang-x64-O0/a5e1e272… | 2.1 MB | ELF PLT (main src 필요) |
| main src 스냅샷 | /root/g1_runs/main_src_1828683 | 8.5 MB | clang Bundle 입장용 엔진(main 1828683, 미push) |
| ntdll Bundle | /root/tdo_g2/ntdll/8d52446f… | 267 MB | trap 200개, compact verified |
| UE core probe Bundle | /root/tdo_bundles3/ue-core-probe/0ad2baf7… | 513 MB | 가장 큼, 비용 판정 |
| 디코더 빌드 | /root/g1_decoders | 202 MB | 재빌드 대신 쓸 때 |
| (선택) 기준 결과 | /root/g1_runs/g2b_r2_base | 수백 MB | c15a29a 기준 출력 (집에서 c15a29a로 다시 만들어도 됨) |

집에서는 같은 경로에 두면 `cost_probe/*.sh`를 그대로 쓸 수 있다. 스크립트 안의 `/mnt/d/01_gitproject/14_TDO_v2/daasdmlkas/.census6/...`
경로(작업 폴더 `wt_lint`, 기준 작업 폴더 `wt_g2b_base`)는 집 환경에 맞게 바꾼다. 기준 작업 폴더는 `git worktree add <dir> c15a29a`.

## 6. 회사에서 반영할 때 (집 → 회사)

1. 집 브랜치에 커밋을 push한다 (이 `docs/handoff_tbr/`는 커밋에 섞지 않거나 별도 커밋으로 둔다).
2. 회사 세션이 fetch → `feat/g1-decode-check` 대비 diff 확인 → 집 커밋만 cherry-pick/fast-forward.
3. 회사에서 다시 확인: 시드 0·1 전체 테스트(skip 0), 다섯 Bundle 동등성(`equiv_g2b.py`), ABBA 비용, Astra 리뷰.
