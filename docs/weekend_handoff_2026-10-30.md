# 주말 작업 인수인계 (2026-10-30 금 → 11-02 월)

집 Mac Studio(M4 Max)에서 주말에 할 일과, 월요일에 개발 PC에서 이어받을 방법.
이 문서는 집 작업 브랜치 `home/weekend-2026-10-31`에만 있다(main에는 없다). 주말 작업은 이 브랜치에서 시작한다.
Mac 준비는 `docs/mac_setup.md`, `.so` 분석 순서는 `docs/analyze_so_runbook.md`.

## 1. 지금 상태 (금요일 퇴근 시점)

- main에 들어간 것: ARM64 2a(호출 관계), 2b(복귀 증명서), 2b-S(링크 호출 SP 복원), 2b-P 일부
  (가정 사용 기록 B1-B9, 가정 이름 해석기 P-c1), `.so` 분석 도구(`tools/analyze_bundle/analyze_query.py`).
- 이번 주에 추가로 합친 것: AArch64/Android C 런타임 손모델(`models/external/crt_aarch64_android.json`),
  Mac에서도 도는 게이트(`tools/gate/`), `docs/mac_setup.md`.
- 실제 `.so` 3개 시험 결과(2026-10-29): 결과는 나오지만 대부분 "불완전". 가장 큰 원인은
  **메모리에서 읽어 온 포인터를 통한 쓰기의 주소를 모름**(힙/포인터 추적 부재, 분류 A = 엔진에 없는 그래프 사실).
  손모델은 적용되지만 숫자를 바꾸지 못했다(모델이 레버가 아님).
- 데이터(Bundle, 기준선 스냅샷, `.so` 모음, 기기 libc, `.census6` 설계 문서)는 git에 없다:
  데이터 패키지 `tdo_data_2026-10-30.tar`로 따로 옮긴다(공개 저장소 Release 금지).

## 2. 주말 할 일 (우선순위 순)

### (다) Mac 준비와 게이트 확인 — 먼저

`docs/mac_setup.md`의 "처음 할 일" 1→3. 3번(전체 게이트 main vs `macg2`)의 결과를 기록한다:
- 모두 identical: Mac 네이티브 게이트를 주말 변경의 검증에 쓴다.
- 차이: 차이 목록을 남기고(`~/tdo_data/gate_par_<label>/snapshot.txt`), Mac에서 만든 스냅샷을 Mac 기준선으로 쓴다.
  가장 의심되는 원인: 큰 스택 worker가 Linux에서만 켜짐(`resource_limits.worker_supported`).

### (나) 큰 `.so` 분석 + "읽어 온 포인터" 패턴 모으기 — 주 작업

목적: 다음 엔진 작업(힙/포인터 추적 설계)의 재료. 실제 바이너리에서 "포인터를 메모리에서 읽고, 그 포인터로 쓴다"가
어떤 모양으로 나오는지 모은다. **엔진 코드는 고치지 않는다**(설계 재료만).

1. 대상 고르기 (`~/tdo_data/so_corpus/<apk>/`):
   - 중간 크기부터: `libmmkv.so`(0.7 MB, PAC), `libtt_ugen_layout.so`(0.4 MB, PAC), `libsentry.so`(1.5 MB, PAC),
     `libtscolor.so`(1.7 MB), `libnative.so`(2.7 MB)
   - 큰 것: `libncnn.so`(5.2 MB), `libengine.so`(8.5 MB) — 시간/메모리 기록이 그 자체로 결과다
   - PAC이 있는 함수의 복귀는 지금 "모름"(Stage 4 예정): PAC 라이브러리는 그 점을 감안해 읽는다
2. 진입점: 내보낸 함수(JNI `Java_*`, `JNI_OnLoad`, 일반 export) 중 몇 개씩. 한 번에 수천 개를 넣지 않는다.
3. export → `--list-calls` → 질의(`~/tdo_data/census6/tools/so_query_generic.json`부터) → 결과 (runbook 2~5단계).
4. 패턴 수집: `~/tdo_data/census6/tools/so_origin.py <generation>`이 "주소를 모르는 쓰기"마다 주소가 어디서 왔는지
   (진입값 / 호출 뒤 / 읽어 온 포인터 / 계산)를 센다. **근사 도구**다(제어 흐름 무시, 선형 역방향 탐색;
   "호출 뒤"가 과대 집계된 적이 있다). 숫자보다 **대표 사례 몇 개를 손으로 확인**하는 것이 중요하다:
   - 어떤 포인터인가(구조체 필드? 전역 테이블? 인자로 받은 구조체 안의 포인터? vtable?)
   - 몇 단계 읽기인가(`*(p+8)` 한 번 / `*(*(p+8)+0x10)` 두 번 ...)
   - 같은 함수 안에서 그 포인터를 만든 곳(할당, 인자, 전역)이 보이는가
5. 기록: `~/tdo_data/census6/field_cases/_TEMPLATE_case.md` 형식으로 새 폴더(예: `2026-11-01_so_loaded_pointers/`).
   분류 A/B/C, 대표 사례의 주소와 명령, 시간/메모리, 실패 함수. 월요일에 개발 PC의 `.census6/field_cases/`로 옮긴다.

### (가) 분석가 링크 설계 r2 — 시간이 남으면

- 입력: `~/tdo_data/census6/design_analyst_links.md`, Astra 리뷰 `analyst_links_astra1.md`(P1 5개, P2 2개),
  가정 프레임워크 설계 `design_premise_2bp_r5.md`(승인본).
- 출력: `design_analyst_links_r2.md` — 리뷰 지적 하나하나에 대한 답. **설계만**, 코드는 쓰지 않는다.
- 순서 원칙: 링크는 2b-P 가정 프레임워크(P-c2~P-c5) 위에 얹는 "데이터 전용" 전제다. 프레임워크가 먼저다.

## 3. 건드리지 않을 것 (월요일에 개발 PC에서 이어 할 작업과 충돌)

다음 주 개발 PC 작업: 2b-P P-c2(생산자 인스턴스 + closure) → P-c3(typed support) → P-c4(보고) → P-c5(수용 측정),
그다음 2c, Stage 3, 힙/포인터 추적 설계, 기기 libc.so/libc++.so에서 모델 유도.
- 손대지 않기: `src/tdo_v2/premises.py`, `src/tdo_v2/assumptions.py`, `premise_uses`를 만드는 곳
  (normalize / summary / 해석 / 활성화 단계의 기록 코드).
- 주말에 엔진 `src/`를 꼭 고쳐야 하면: 별도 브랜치에서 작게, 회귀 테스트와 함께. 월요일에 여기서 게이트 + Astra 리뷰 후 합친다.

## 4. 브랜치와 넘기는 방법

- Mac 작업은 이 브랜치 `home/weekend-2026-10-31`에 커밋하고 push한다(주제를 나누고 싶으면 여기서
  `home/<주제>` 브랜치를 더 딴다). **main에 직접 push하지 않는다.**
  ```bash
  git fetch origin && git switch home/weekend-2026-10-31
  ```
- 데이터/문서(`.census6`에 둘 것)는 git에 넣지 않는다: 바뀐 파일만 묶어 월요일에 옮긴다.
- 월요일 개발 PC: `git fetch` → 브랜치 diff 확인 → 전체 게이트(이 PC 기준선) → Astra 리뷰 → main에 squash merge.

## 5. 알아 둘 함정

- 기준선 스냅샷은 `macg2`(2026-10-30, 이 main)를 쓴다. 그 전 기준선(`pc1b` 이하)의 fixture 스냅샷은 예전 게이트가
  고정된 다른 checkout으로 만든 것이라 지금 코드와 비교하면 fixture 10개가 다르게 나온다(Bundle 26개는 동일).
- 게이트가 도는 동안 그 트리(게이트 스크립트 포함)를 고치지 않는다. bash는 스크립트를 읽어 가며 실행한다.
  다른 트리를 게이트하려면 `TDO_REPO=<트리> bash tools/gate/gate_par.sh <base> <new>`.
- `step()` 작업량 비교는 `PYTHONHASHSEED=0`일 때만 의미가 있다.
- 결과가 "불완전"이면 `origins`는 후보일 뿐이다. `failed_functions`가 있으면 빈 결과가 "흐름 없음"의 증거가 아니다.
- 엔진은 호출 규약(인자/반환 레지스터, 보존 레지스터)을 가정하지 않는다. 그런 가정은 모델 파일에 이름 붙은 가정으로만 둔다.
