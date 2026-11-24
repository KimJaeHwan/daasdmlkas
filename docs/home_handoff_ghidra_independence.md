# 인수인계: Ghidra 독립 작업 (집 병렬 트랙, 2026-11-24)

이 문서만 보고 집에서 작업을 시작할 수 있게 적었다. 배경과 판단 근거:

- `docs/ghidra_independence_plan.md` — 계획. 7절이 Astra 협의 결과다.
- `docs/bundle_producer_contract.md` — Bundle 규약. 코드 기준 file:line을 담았다.

## 0. 한 줄 요약

- Ghidra는 **기준 생산자로 유지**한다.
- 집에서는 엔진 코드를 건드리지 않고 **"진단 결과를 만드는 일"**까지만 한다.
- 첫 산출물은 `bundle_lint`와 작은 x86-64 PE 기준 세트다.

## 1. 시작

```
git fetch origin
git switch -c home/g0-bundle-lint origin/docs/ghidra-independence
```

이 브랜치는 main 50f28f8 위에 문서 커밋만 얹은 것이다. 엔진 코드는 main과 같다.

## 2. 환경

| 항목 | 요구 | 이유 |
|---|---|---|
| Ghidra | **12.0.4** 정확히 | 이름 사이드카가 `"12.0.4"`와 `ghidra/GhidraV2CallNaming.java`의 SHA-256에 고정돼 있다 |
| JDK | 21 | Ghidra 12 실행 |
| 실행 위치 | **Linux 또는 WSL** | 엔진의 Bundle 수용(`admit_frozen_bundle`)이 POSIX 전용이다(`O_NOFOLLOW`, `fcntl`). Windows에서는 실패한다 |
| Python | 저장소 venv(테스트 의존성 포함) | 기존 엔진 수용 코드를 그대로 불러 쓴다 |

Bundle은 `tools/bundle_export/export_bundle.py <binary> --ghidra <Ghidra 경로> --output-root <dir> --function-name <이름>`으로
새 import해서 만든다. 사용법은 `tools/bundle_export/README.md`에 있다. 준비된 프로젝트(`--ghidra-project`)로 만든 Bundle에는
증명 사실(S1 등)이 붙지 않으니 기준 세트로 쓰지 않는다.

## 3. 첫 산출물: G0 `bundle_lint` + 기준 세트

### 3.1 `tools/bundle_lint/` (새 디렉터리)

이미 있는 엔진 수용 코드를 **그대로 호출**한다(재구현하지 않는다). 결과는 세 층의 기능별 판정표로 낸다.

1. **운송 / 메모리**
   - manifest / seal의 순서, 크기, 해시, 파일 규칙
   - 블록 플래그와 committed 범위
   - 원본(`original.bin`)과 이미지 매핑
   - image-info 누락, overlay / 중첩 블록
   - 내용을 읽지 않는 필수 멤버(`call-effects`, `call-interface-profile`)는 그 사실을 표시만 한다
2. **연산 / 이름**
   - 행 주소, 길이, flow, exit 교차 규칙
   - varnode 공간과 레지스터 별칭, LOAD / STORE 공간 id, 명령 내부 상대 분기, user-op 번호
   - CALL / RET / INT3 / `rep` / `ud2` 패턴이 Ghidra 모양과 같은지
   - CALL과 꼬리 호출마다 이름 행, ordinal, digest가 맞는지
   - 형식상 유효하지만 엔진이 모르는 opcode(일반 WRITE로 처리됨)를 드러낸다
3. **기능 / 증명**
   - 기능마다 `적용 / 해당 없음 / 보류 / 거부`를 함수, 주소, 이유와 함께 낸다
   - 함수 거부나 무시된 키가 "전체 성공"에 묻히지 않게 한다
   - S1 / `exception_handlers`에는 생산자, 입력 종류(`proof_input`), 전제를 표시한다

출력 형식은 사람이 읽는 표와 기계가 비교하는 JSON 두 가지로 한다.

### 3.2 기준 세트

- **원본**: 작은 x86-64 PE 하나. testbed 바이너리나 직접 빌드한 작은 C 프로그램을 쓴다. 제3자 바이너리는 쓰지 않는다.
- **기준 Bundle**: 위 원본을 새 import로 내보낸 것 1개.
- **변형 스크립트 3개**: 기준 Bundle을 복사해 조건 하나씩만 바꾼다. 세 변형이 **서로 다른 결과**를 내야 한다.
  1. seal 불일치 → **컨테이너 거부**
  2. CALL ordinal 불일치 → **이름 거부**
  3. 유효한 p-code에서 CALL 패턴만 바꿈(예: x86-64 CALL의 `INT_SUB RSP; STORE; CALL` 순서) → **그 패턴 기능만 미적용**.
     이 경우를 잡아야 "형식만 맞추고 기능을 잃는" 문제를 실제로 검출한 것이다.
- **기대 판정표**: JSON 1개(기준 + 변형 3개의 기대 결과).
- 변형 스크립트는 seal / manifest의 해시를 다시 계산해서 **의도한 조건 하나만** 깨지게 한다.

## 4. 지킬 것

- **`src/tdo_v2`는 수정하지 않는다.** 엔진 쪽 변경이 필요해 보이면 `docs/`에 "제안"으로만 적는다. 엔진 변경은 회사 쪽
  세션에서 게이트와 함께 한다.
- **Bundle, 바이너리, 덤프는 커밋하지 않는다.** 저장소가 공개라서 생성 스크립트, 변형 스크립트, 기대 판정표만 커밋하고,
  생성물은 `.gitignore`로 제외한다.
- 커밋 서명은 기존대로 `김재환2 [rfkjh22]`.
- 같은 Ghidra 버전, 같은 옵션으로 만든 Bundle끼리만 비교한다.

## 5. 끝나면

```
git push -u origin home/g0-bundle-lint
```

회사 쪽 세션에 "home 브랜치 올렸다"고 알리면 home-branch 절차대로 진행한다.

1. fetch
2. Linux에서 lint와 기준 세트 실행
3. 게이트
4. Astra / Fable 리뷰
5. 머지 승인 요청

## 6. 그다음 집 작업 후보 (순서대로; 모두 "진단까지")

1. **G1 진단 도구**
   - 원본 파일의 섹션표로 Ghidra 이미지 매핑을 검증한다: preferred base, RVA, 크기, zero-fill, 바이트.
   - 버전을 고정한 iced-x86(64비트 기본 모드 + AMD 모드)으로 각 행을 원본의 행 시작 주소부터 해독한다. Ghidra 길이로 자르지
     않는다.
   - 유효성, 길이, 직접 / 간접 흐름, 직접 목적지, fallthrough, 복귀 PC를 비교해 **불일치 보고서**를 낸다.
   - 엔진에 반영하는 것(불일치 → S1 보류)은 회사 쪽에서 한다.
2. **좁은 G3 실험**
   - pypcode(SLEIGH)로 x86-64 PE 하나의 p-code를 만들고, 같은 바이너리의 Ghidra Bundle과 **행 단위로 비교**한다:
     opcode, varnode, ordinal, 레지스터 오프셋.
   - pypcode의 `IMARK`를 행 경계로 다뤄야 CALL ordinal과 이름 사이드카가 맞는다.
   - 결과는 비교 보고서까지만 만든다. 새 생산자를 엔진이 정식으로 받으려면 먼저 최소 G2(생산자 식별, 이름 사이드카 고정 해제)가
     필요하고, 그것은 엔진 작업이다.
   - 새 생산자가 `proof_input: "attested-fresh-import-v1"`을 빌려 쓰면 안 된다.

## 7. 판단 기준 (G5 전에 정해 둘 것)

- 같은 SHA와 옵션에서 양쪽에만 있는 함수와 간선
- 누락 / 보류 사유, 이름 해석률, 실제로 제거된 재귀 간선, 실행 시간
- 기존 Ghidra 게이트 변화 = 0, 근거 없는 간선 제거 = 0
- 허용할 정밀도 손실과 기대하는 운영 이득을 **큰 UE DLL로 비교하기 전에** 정해 둔다
