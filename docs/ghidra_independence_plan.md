# Ghidra 독립 계획 (2026-11-24 초안)

> `.census6/...`로 적힌 파일은 로컬 작업 기록이다(저장소 밖). 이 문서와 `docs/bundle_producer_contract.md`만으로 작업할 수 있게 썼다.

목적: 나중에 Ghidra 없이도 엔진을 돌릴 수 있게 하려면 무엇을 해야 하는지 정리한다. 집에서 병렬로 작업할 수 있도록,
"엔진이 받는 형식(Bundle 규약)"과 "엔진 안에 숨어 있는 Ghidra 관례"를 나눠 적는다.
근거: Bundle 규약 조사(`docs/bundle_producer_contract.md`, 코드 기준 file:line 포함 — 아래 2절 요약), G3b-7b 리뷰에서 나온 해독 전제 결정.

## 1. 지금 Ghidra에 기대는 곳은 두 층이다

1. **Bundle을 만드는 쪽** (`ghidra/GhidraV2BundleExport.java`, `GhidraV2CallNaming.java`, `tools/bundle_export/export_bundle.py`)
   - 로더: PE / ELF 읽기, 메모리 블록, image base, import / export, 재배치
   - 해독 + lifter: 기계어 → p-code (SLEIGH)
   - 분석: 함수 경계, 흐름 대상, 점프 테이블, 참조, thunk, 이름
   - 증명 사실: S1(ISA fallthrough), 예외 처리기 없음(G3b-7b), 예외 착지 지점
2. **엔진 안의 Ghidra 관례** (형식만 맞춰서는 안 바뀌는 부분)
   - Ghidra의 p-code 모양을 그대로 찾는 패턴: INT3(`CALLOTHER; CALLIND; RETURN`), x86-64 CALL(`INT_SUB RSP; STORE; CALL`),
     RET(`LOAD; INT_ADD; RETURN`), AArch64 BL/BLR, `rep movs/stos`(11 / 17개 연산), `ud2`(`CALLOTHER 77; BRANCHIND`),
     `call $+5`(push + BRANCH)
   - SLEIGH 레지스터 오프셋 하드코딩: x86-64 RSP=0x20, 플래그 0x200..0x20B, RIP=0x288 (`interprocedural.py`), 모델 파일의
     AArch64 x0=16384 등
   - CALLOTHER 번호 표(LOCK=17, UNLOCK=18, 트랜잭션 84/85/86/99): Ghidra 12.0.4 언어 버전에 묶임
   - 문자열 검사: 언어 ID `x86:LE:64:default`, `executable_format`의 `"Portable Executable"`
   - 이름 사이드카(call-names)가 `GhidraV2CallNaming.java`의 SHA-256과 `"12.0.4"`에 고정
   - 고정된 관례가 안 맞으면 기능이 **조용히 꺼진다**(오류 없이 결과만 덜 정밀해짐) — 다른 생산자를 붙일 때 가장 큰 위험

## 2. Bundle 규약 요약 (생산자가 반드시 지킬 것)

- **컨테이너(엄격)**: 세대 디렉터리 이름 = 64자리 소문자 hex. 안에는 `manifest.json`, `seal.json`, 멤버 파일만.
  파일은 현재 uid 소유, 링크 1개, 그룹/기타 쓰기 금지, symlink 금지, 멤버마다 크기 + SHA-256 일치(읽을 때마다 다시 해시).
  `seal.json` = {schema_version 2, generation_id, manifest_size, manifest_sha256}. `manifest.json` format 2 = {schema_version,
  generation_id, original_member_id, program_member_id, members, blocks, functions, call_interface_profile_member,
  image_info_member?}; members 순서 고정(original → program → profile → 블록 메모리 → image-info → 함수마다 observation /
  call-names / call-effects); block / function id 정렬. 제어 JSON: 중복 키 금지, 정수는 u64, NaN 금지.
- **멤버**: `original.bin`(입력 파일 그대로), `program.json`, `call-interface-profile.json`(내용은 엔진이 안 읽음, 존재만),
  `memory-*.bin`(블록 바이트), `image-info.json`, 함수마다 `function-*.json` / `call-names-*.json` /
  `call-effects-*.json`(내용 안 읽음).
- **함수 JSON(관대)**: 모르는 키는 무시. 필수 `entry`, `instructions`(행마다 address, fallthrough_present / fallthrough,
  flow_targets, flow_type 9개 bool, operations, 선택 length / data_references). 선택 증명 필드 `call_fallthrough: "isa"` +
  `fallthrough_exits`(kind 2 / 3 / 4), `proof_input: "attested-fresh-import-v1"`, `exception_handlers: "none"` — 교차
  규칙이 있다(25.100, 25.115).
- **p-code**: operation {ordinal, opcode, inputs, output_present, output}, varnode {kind_code 1..5, 7; space_id;
  byte_offset; byte_size}. LOAD / STORE 입력 0 = 공간 id 상수, BRANCH / CBRANCH의 상수 목적지 = 명령 안 상대 인덱스,
  UNIQUE는 함수 범위 오프셋 키, REGISTER는 바이트 오프셋 키(하위 레지스터가 바이트로 겹쳐야 함).
- **program.json**: translation_namespace{language_id, major, minor}, address_spaces(rev 2 플래그), image_base(커밋된
  구간 시작), register_evidence(이름 → 공간 / 오프셋 / 크기; 실제로는 필요).
- **call-names(엄격)**: CALL / CALLIND 연산마다 정확히 한 행, 꼬리 호출 행, thunk 체인과 별칭, 행 / 대상 / 내용 digest.
- **digest**: 같은 의미라도 p-code가 다르면 관측 digest, 함수 / 프로그램 scope id, 이름 digest, 연산 키
  (`space:offset:ordinal:OPCODE`)가 모두 바뀐다. 템플릿 버전은 자동으로 안 바뀐다 — 생산자를 바꿀 때 수동 bump.
- 원본 조사 보고는 `docs/bundle_producer_contract.md`; 이것을 버전 고정 wire spec으로 굳히는 것이 G0 작업이다.

## 3. 단계 (각 단계는 따로 끝나고 따로 쓸모가 있다)

| 단계 | 내용 | Ghidra 필요 | 집에서 병렬 | 산출물 / 확인 |
|---|---|---|---|---|
| G0 | Bundle 규약을 문서(wire spec)와 **검사 도구**(`bundle_lint`)로 굳힌다. 엔진 admission을 재사용해 "이 Bundle을 엔진이 받는가 + 어느 기능이 꺼지는가"를 출력 | 아니오 | 예 | 기존 Ghidra Bundle 전부 통과; 일부러 망친 Bundle은 정확한 이유로 실패 |
| G1 | **독립 해독기 교차 확인**(XED 또는 iced-x86)을 엔진 쪽에: `original.bin`을 해독해 모든 행 길이를 대조, 다르면 증명 사실 보류 | 아니오 | 예 | proof-inputs 설계의 class 1 해독; G3b-7b 해독 전제의 후속 |
| G2 | 엔진의 Ghidra 관례를 **"lifter 프로필"**로 모은다: p-code 모양 패턴, 레지스터 오프셋(→ register_evidence 이름 조회로 통일), CALLOTHER 번호 표, 언어 / 포맷 문자열(→ 정규화된 ISA identity), call-names의 Ghidra 고정값(→ producer identity) | 아니오 | 일부(엔진 코드라 이 세션에서 게이트 필요) | 결과 변화 0(게이트 동일) + 생산자별 프로필 1개(Ghidra 12.0.4) |
| G3 | **두 번째 생산자**: 자체 로더(PE / ELF) + 해독 / lifter + 최소 분석 + call-names | 아니오 | 예 | G0 lint 통과하는 Bundle |
| G4 | **대조**: 같은 바이너리를 Ghidra Bundle과 새 Bundle로 만들어 엔진 결과 비교(oracle, census, gate); 차이를 분류 | 비교용으로만 | 예 | 차이 표 + 원인(생산자 / 엔진 관례 / 진짜 버그) |
| G5 | 전환 또는 병행 운영 결정 | — | — | 소유자 결정 |

### G3에서 가장 큰 선택: 해독 / lifter를 무엇으로 할까

1. **SLEIGH는 유지, Ghidra 앱만 벗기 (추천 시작점)**: Ghidra의 SLEIGH 명세를 Ghidra 없이 쓰는 라이브러리(libsla, Python
   바인딩 pypcode)로 p-code를 만든다. p-code 모양과 레지스터 오프셋이 Ghidra와 같아서 G2 없이도 엔진 기능이 거의 그대로
   켜진다. 대신 "해독 = SLEIGH"는 그대로라 G1(독립 해독기 교차 확인)이 함께 필요하다.
2. **다른 IR(VEX / LLVM / 자체)**: Ghidra 계열에서 완전히 벗어난다. G2가 먼저 끝나야 하고, p-code로 바꾸는 번역층이 필요하다.
   가장 크고 오래 걸린다.

### G3의 분석 부분 (Ghidra가 지금 해 주는 것)

- 함수 경계: 진입점 / 심볼 / `.pdata` / 재귀 하강. 증명 사실이 필요한 부분은 바이트 기준(class 1)으로.
- 흐름 대상, 점프 테이블(못 풀면 BRANCHIND로 두고 U2a가 표시), 데이터 참조, thunk / import 해석.
- 증명 사실(S1, G3b-7b)은 새 생산자가 **스스로** 증명해야 한다 — 같은 필드 이름을 쓰되 `proof_input` 값에 생산자 식별을 넣는
  방안(엔진 계약 확장)을 G2에서 정한다.

## 4. 집에서 병렬로 할 때 규칙

- 집 작업은 브랜치로 push → 이 세션이 fetch, 게이트, 리뷰, 머지(기존 home-branch 절차).
- **형식만 맞추면 되는 부분**: G0, G1, G3, G4. 엔진 코드를 바꾸지 않으므로 서로 부딪히지 않는다.
- **형식만으로는 안 되는 부분**: G2(엔진 관례). G2 없이 다른 p-code를 넣으면 오류 없이 기능이 꺼질 수 있다 — G0 lint가
  "꺼지는 기능"을 보고하게 만들어서 이것을 눈에 보이게 한다.
- 비교 기준은 항상 같은 바이너리의 Ghidra Bundle(G4).

## 5. 추천 순서

1. G0(규약 문서 + lint) — 다른 모든 단계의 기준. 집에서 바로 가능.
2. G1(독립 해독기 교차 확인) — 지금 증명 사실의 해독 전제를 줄이는 실익이 바로 있다.
3. G3 1번 경로(pypcode / libsla + 자체 로더) + G4 대조 — Ghidra 앱 없이 Bundle을 만드는 첫 증거.
4. G2(엔진 관례 분리) — 2번 경로나 다른 IR을 쓸 때 필요. 이 세션에서 게이트와 함께.

## 6. 결정이 필요한 것

- "Ghidra를 벗는다"의 정의: SLEIGH 명세까지 벗을지(2번 경로), Ghidra 앱만 벗을지(1번 경로).
- 새 생산자의 분석 품질(함수 경계, 점프 테이블)이 Ghidra보다 낮을 때 받아들일 기준.
- 생산자를 바꾸면 digest, 템플릿, 링크 캐시가 모두 새로 만들어진다 — 기준값(baseline) 재설정 시점.

## 7. Astra 협의 결과 (2026-11-24, `.census6/ghidra_independence_astra1.md`) -- 반영한 수정

**결론: Ghidra를 버리지 말고 "기준 생산자"로 유지한다. Ghidra 앱 없이 Bundle을 만드는 경로는 추가로 둔다.**
- 목적별 첫 단계:
  - 배포와 headless 분석 의존을 줄이려면: x86-64 PE 한정 SLEIGH / pypcode 실험.
  - 증명의 신뢰도를 높이려면: 원본 파일 매핑 검증(L7) + G1(독립 해독기). 기존 Ghidra Bundle에도 바로 효과가 있다.
- 앱을 바꿔도 해결되지 않는 것:
  - L1(로더 쓰기)은 L7을 해결해도 남는다.
  - L2: SLEIGH를 공유하는 두 생산자는 같은 오류를 낸다. 그래서 iced-x86(64비트 기본 + AMD 모드) 교차 확인이 따로 필요하고, 그것도 CPU 동작의 증명은 아니다.
  - L3: 호출마다 실제로 복원되는 PC를 증명해야 한다.
  - L5 / L6: 두 생산자가 같은 경로를 놓칠 수 있고, 실행 중 등록되는 표는 정적 Bundle 밖이다.
- 새 생산자가 직접 복원해야 하는 것(전환 비용의 대부분): 함수 경계, 간접 분기 대상, thunk / import 이름, 예외 착지점, 로더 상태.
  - 같은 SLEIGH라도 버전, 문맥, 연산 번호를 실측으로 맞춰야 한다. 예: pypcode는 `IMARK`를 행 경계로 다뤄야 CALL의 ordinal과 이름 사이드카가 어긋나지 않는다.
  - 다른 IR은 의미와 패턴 재검증 비용이 더해지므로 보류한다.

**집에서 병렬로 할 수 있는 범위 = "진단 결과를 만드는 일"까지** (G1 / G3 / G4 전체를 형식 작업으로 본 초안을 수정):

| 단계 | 집에서(엔진 변경 없음) | 엔진 + 게이트가 필요한 지점 |
|---|---|---|
| G0 | 버전 고정 wire spec, 기존 admission을 호출하는 lint, 정상 / 변형 fixture | 실제 소비 결과와 lint 판정이 같은지 확인(POSIX에서 실행) |
| G1 | 원본 매핑 + 독립 해독 도구, 행별 불일치 보고서 | 불일치가 S1과 종속 사실의 **소비**를 막는지 |
| G2 | 패턴 / 레지스터 / user-op 목록과 기대 결과 수집 | 프로필 선택, 생산자 식별, 이름 / 증명 / 캐시 바인딩, 기존 Ghidra 결과 변화 0 |
| G3 | 로더와 lifter 시제품, 증명 필드를 뺀 행과 사이드카 후보 | 이름 판독기가 Java 소스 SHA와 `12.0.4`를 검사한다 -- **최소 G2가 G3 정식 수용보다 먼저**; `attested-fresh-import-v1`을 빌려 쓰지 말 것 |
| G4-G5 | 같은 바이너리의 기준 Bundle, 비교 도구, 차이표 | 같은 엔진 / 옵션으로 oracle / census / gate를 돌린 뒤 결정 |

**G0 lint의 핵심 산출물 = 기능별 판정표** (컨테이너가 열렸다는 것만으로는 아무것도 알 수 없다). 세 층으로 본다.
1. **운송 / 메모리**: manifest / seal의 순서, 크기, 해시, 파일 규칙; 블록 플래그와 committed 범위; 원본과 이미지 매핑; image-info 누락; overlay / 중첩; 내용을 읽지 않는 필수 멤버.
2. **연산 / 이름**:
   - 행 주소, 길이, flow, exit 교차 규칙
   - varnode 공간과 레지스터 별칭, LOAD / STORE 공간 id, 명령 내부 상대 분기, user-op 번호
   - CALL / RET / INT3 / `rep` / `ud2` 패턴과 CALL / 꼬리 호출별 이름 행, ordinal, digest 대조
   - 형식상 유효하지만 엔진이 모르는 opcode가 일반 WRITE로 처리되는 경우도 드러낸다
3. **기능 / 증명**:
   - 기능마다 `적용 / 해당 없음 / 보류 / 거부`를 함수, 주소, 이유와 함께 낸다. 함수 거부나 무시된 키가 "전체 성공"에 묻히지 않게 한다.
   - S1 / `none`에는 생산자, 입력 종류, 검증한 바이트, 전제를 연결한다.
   - 분석 추정(함수 소유권, 간접 대상) 때문에 간선이 사라질 수 있으면 증명에 쓰지 않는다.

**권장 순서**:
1. G0 + G4 기준선
2. G1 진단과 좁은 G3 실험을 병행
3. 최소 G2
4. 엔진에 G1 / G3 통합
5. G4 / G5

새 생산자 결과를 재사용하기 **전에** producer, lifter 명세, 설정, 입력 종류, digest를 템플릿 / 링크 / stack-scan 캐시 키에 묶는다. 식별할 수 없는 기존 항목은 재사용하지 않는다.

**집 작업의 첫 산출물: `bundle_lint` + 작은 x86-64 PE 기준 세트.**
- 구성: 같은 원본의 frozen Ghidra Bundle 1개, 기대 기능표 1개, 조건을 하나씩 바꾼 변형 3개.
- 세 변형이 서로 다른 결과를 내야 한다.
  - seal 불일치 → 컨테이너 거부
  - CALL ordinal 불일치 → 이름 거부
  - 유효한 p-code에서 CALL 패턴만 변경 → 그 패턴 미적용
- 마지막 경우를 잡아야 "형식만 맞추고 기능을 잃는" 문제를 실제로 잡은 것이다.

**G5 판단 기준**(대형 UE DLL 비교 **전에** 정해 둘 것):
- 같은 SHA / 옵션에서 양쪽에만 있는 함수와 간선
- 누락 / 보류 사유, 이름 해석률, 실제로 제거된 재귀 간선, 실행 시간
- 기존 Ghidra 게이트 변화 = 0, 근거 없는 간선 제거 = 0
- 허용할 정밀도 손실과 기대하는 운영 이득

## 8. TDO 전용 생산자 설계 원칙 (소유자 방향 2026-11-24)

같은 일을 하는 상용 도구가 없으므로, 새 생산자는 "Ghidra를 대신하는 것"이 아니라 **"TDO 엔진이 원래 원하던 입력을 내는 것"**을
기준으로 한다.

| TDO 원칙 | Ghidra가 주는 것 | 새 생산자가 줄 것 |
|---|---|---|
| ABI / 호출 규약을 가정하지 않음 | noreturn 추측, 호출 규약, call-fixup 같은 추측 분석 | 추측 분석 없음; 모르는 것은 "모름"으로 표시 |
| 사실은 근거와 함께, 전제는 이름 붙여서 | 근거 없는 목록(함수 경계, 참조) | 행 / 간선마다 근거 종류: 바이트, 정적 흐름, 정방향 값, 분석가 링크, (전환기) Ghidra 힌트 |
| 증명은 바이트 기준 | 편집 가능한 DB 상태 | 원본 파일 대조 결과와 해독기 교차 확인 결과를 행마다 |
| 미지 이동은 버리지 않고 표시(U2a) | 못 푼 분기 = 목적지 없음 | "UNKNOWN 이동 지점"을 명시적인 출력으로 |
| 로더 = 로드 단계 모델 | 로드 결과만 | 초기 메모리 + "실행 중 바뀔 수 있는 바이트 집합" |
| 정방향 / 가상화 분석 | 한 번에 하는 일괄 내보내기, 주소 하나에 명령 하나 | 필요할 때 lifting, 점진적 흐름 그래프, 같은 바이트의 여러 해독(6.1절 인수인계 참고) |

### 복잡도는 어디로 가는가

- **생산자는 단순해진다.**
  - 해독, 구조적 흐름(직접 분기 / 호출 / fallthrough), 로더 메타데이터만 정확히 낸다. 못 푸는 것은 UNKNOWN으로 남긴다.
  - 점프 테이블 같은 간접 목적지도 생산자는 후보만 낸다. 확정은 TDO의 정방향 분석이 값으로 증명한다.
- **엔진의 방어 코드가 줄어든다.**
  - 지금은 "생산자 DB가 이상하지 않은지"를 검사하는 코드가 많다. G3b-7b의 Astra 리뷰 17라운드(코드 수정판 r1~r9k)의 대부분이 이것이었다.
  - 생산자가 근거와 바이트 대조 결과를 처음부터 내면, 그 검사는 "근거 표시를 읽고, 바이트 근거는 엔진이 `original.bin`으로
    다시 검사하는 일"이 된다. 생산자의 표시는 검사할 곳을 안내할 뿐 증명하지 않는다(T1 엔진 계약; Fable P2-3).
- **새로 생기는 일:**
  - 생산자: 근거 표시, 여러 해독(겹치는 코드에서만), 바뀔 수 있는 바이트 계산
  - 엔진: 새 정보를 읽는 Bundle v3(한 번)
- **전환기 비용:** 정방향 분석이 약한 동안에는 UNKNOWN이 Ghidra보다 많다. 그동안 Ghidra의 추측은 **"힌트" 근거**로만 붙인다. 힌트는 탐색 순서를 돕고, 증명에는 쓰지 않는다.
- **결론:** 어려운 판단이 한곳(TDO의 증명 + 정방향)에 모이므로 길게 보면 전체가 단순해진다. 조건은 **정방향 분석이 그만큼 자라야 한다**는 것이고, 따라서 이 트랙은 정방향 분석기 계획과 같이 간다.

### Astra 설계 리뷰 반영 (2026-11-24, `.census6/ghidra_independence_astra2.md`, APPROVE)

- **힌트 격리 (P1-2)**
  - v2에서는 미확정 후보, 소유권 추정, 대체 해독을 Bundle 밖 진단 파일에 둔다. 엔진 U2a는 목적지가 비어 있을 때만 UNKNOWN으로 기록하므로, 후보 하나만 넣어도 UNKNOWN이 사라진다.
  - 새 생산자의 v2 출력은 S1, `exception_handlers`, `proof_input`, Ghidra 신원을 빌려 쓰지 않는다.
  - v3는 **후보 발견**과 **모든 목적지의 완전성 증명**을 별개로 표현한다.
- **기준 커밋 고정 (P1-1)**: G0 기대표에 엔진 / exporter SHA를 적는다. main 50f28f8에서는 `proof_input` / `exception_handlers`를 미지원으로 둔다(인수인계 1.1).
- **발견 범위의 담당 (P2-3)**
  - 생산자: 시작 후보와 출처, 직접 흐름으로 방문한 행, 멈춘 지점.
  - TDO: 함수 소유권, 공유 꼬리, 간접 목적지의 완전성.
- **행 키와 갱신 단위 (P2-4)**
  - 행 키는 `(공간, 시작, 해독 문맥, 바이트 판)`, 간선은 row_id 참조, lift는 소비 범위와 실패 사유를 낸다.
  - 근거 철회와 종속 요약 무효화는 TDO가 맡는다.
- **검증 결과의 소비 조건 (P2-5)**
  - "일치" 표시는 대조 대상(바이트, 매핑, 해독기 버전 / 모드, 흐름 속성)을 식별한다. 불일치나 미검사는 의존 사실을 보류한다.
  - 로더 쓰기 범위는 **이름 붙은 로드 단계 모델**로 한정한다. 쓰기 목적지 메타데이터가 바뀔 수 있으면 이미지 전체로 넓힌다. 이후 프로그램이 쓰는 바이트는 정방향 상태에서 추적한다. 그래야 PE 목록이 Android나 실행 중 복호화에서 "나머지는 불변"이라는 전제로 바뀌지 않는다.
- **재사용 차단 규칙은 지금 정한다 (P2-6)**
  - 생산자, SLEIGH 명세 / 패치, 설정, 입력 종류, 바이트 판, 증명에 쓴 근거와 전제를 검증 가능한 식별자로 묶는다.
  - 이 식별자를 **최초 조회 전에** 템플릿 / 링크 / stack-scan 캐시에 적용한다. 구버전이나 신원 불명 항목은 cache miss로 처리한다.
  - 근거가 다른 입력에서 기존 템플릿을 직접 로드하는 경로도 막히는지를 최소 G2의 게이트로 둔다.
- **비교 분모 (P3)**: 요청한 시작점 / 실제 수록 함수 / v2 한도로 빠진 함수를 구분한다.

### Fable 설계 리뷰 반영 (2026-11-24, `.census6/ghidra_independence_fable1.md`, APPROVE -- G0는 그대로 시작, G3 / 라이브러리 전에 P1)

**P1-1. Ghidra의 추측은 지금도 증명 입력이다.** "힌트로만"은 새 생산자만의 문제가 아니라 **엔진을 바꾸는 일**이다.
예: `src/tdo_v2/integration/configured_state_barrier.py:99-100`은 BRANCHIND에 목적지가 하나라도 나열돼 있으면 후속 그래프를
완전하다고 본다. 아래 표는 Fable 지적을 옮긴 것이고, 각 항목의 정확한 영향은 G2 설계 때 코드로 확인한다.

| Ghidra가 추측한 필드 | 엔진에서 먹이는 결과 | 불완전하면 간선이 사라질 수 있나 |
|---|---|---|
| BRANCHIND `flow_targets`(점프 테이블) | 후속 그래프 완전성(상태 장벽), 흐름 간선 | 예 -- 나열된 집합을 완전하다고 본다 |
| 함수 몸체(행 집합) | 관찰 범위, G3b-7b 프레임 PC(L5) | 예(G3b-7b), 그 밖은 범위 |
| call-names의 thunk / import 해석 | 외부 모델 연결, 이름 | 잘못 연결되면 잘못된 모델의 효과 |
| `data_references` | 정밀도 힌트(configured_function_view) | 아니오(힌트로만 쓰임) |
| FlowType 비트(is_call, is_override, is_terminal, is_computed) | 꼬리 호출 시작점, 호출 관계 | 확인 필요 |
| `flow_targets`에 합쳐진 예외 착지점 | 예외 간선 | 예(R7-8은 보수적으로 남김) |

- **오늘의 동작을 지금 전제로 이름 붙인다**(v3 전에, 지금 보고 가능하게). 예: `producer-listed-indirect-targets-complete`, `producer-function-bodies-complete`.
- **v2 규칙**: 새 생산자는 **구조적으로 정해진 목적지만** 낸다. 후보를 v2 `flow_targets`에 넣으면 완전성 주장이 되므로, 구조상 힌트 누출이다.
- G4는 간접 목적지를 지운 Ghidra Bundle과도 비교해, 생산자 차이와 목적지 복원 차이를 나눈다.

**P1-2. 힌트 격리는 검사할 수 있어야 한다.**
- "힌트는 탐색 순서만 돕는다"는 예산이 있으면 깨진다. 순서가 바뀌면 어떤 일이 예산 안에서 끝나는지가 바뀐다(seeded work-unit 메모리).
- 힌트로만 발견한 함수는 범위 주장이기도 하다. 데이터를 코드로 해독하면 없는 코드에 대한 근(root)과 흐름이 생긴다.
- 둘 중 하나를 고른다(G3 설계 때 결정).
  - (a) 힌트를 실행 신원(digest, 캐시 키)에 넣고, 힌트로 발견한 함수 / 간선을 거쳐 도달한 모든 근과 요약에 `discovered-by:hint:<출처>`를 붙인다.
  - (b) 힌트 제거 게이트: 힌트가 있을 때와 없을 때 결과가 같다. 예산이 소진된 항목은 따로 나열한다.
- R6에 추가: **힌트는 증명 사실, 완전성 주장, CLOSED의 근거가 될 수 없다.**

**P1-3. 전환기 범위와 점프 테이블의 담당자.**
- "정방향이 자라면"이라는 조건에는 게이트가 없다. 그동안 단순한 생산자가 맡지 않는 것:
  - (i) 점프 테이블: UE DLL에서는 switch 전부
  - (ii) 간접으로만 도달하는 함수: vtable, 콜백, `.init_array`, 예외 funclet
  - (iii) `.pdata` 없는 leaf 함수
  - (iv) `.eh_frame`이 일부만 있는 stripped ARM64 `.so`
- **정책**: 함수 집합은 관찰 범위 진술이다. 없는 것은 "관찰 안 됨"이다. G3b-7b L5가 이미 이렇게 적는지 확인한다.
- **(i)의 임시 담당** = 엔진 또는 공용 증명 모듈 안의 **TDO 쪽 국소 유한 테이블 증명**이다. 생산자가 아니다. 조건은 셋이다.
  - 분기를 지배하고 인덱스를 묶는 guard가 있다.
  - 테이블 바이트가 로더가 쓰지 않는 쓰기 불가 메모리에 있다.
  - 모든 목적지가 해독 검증된 행 시작이다.
  - 그 밖은 UNKNOWN 지점으로 남는다.
- G5 기준에 "간접 분기 해결 비율(새 생산자 + TDO 대 Ghidra)"을 넣는다.

**P2 (G0 / G1을 넘어가기 전에)**: 6.1 인터페이스 정정 -- 순수 라이브러리, 전제 id 간선, 출처 있는 바이트, 해독 불가 결과,
v2에서 갈래를 고르지 않음, 닫힌 근거 열거형(인수인계 6.1). 로드 때 쓰기와 실행 중 쓰기 분리. 엔진은 바이트 근거를 스스로
다시 검사(T1). 생산자 신원을 digest / 템플릿 / 캐시 키에 넣기 전까지 집 진단은 분리된 캐시 루트. G0는 main을 대상으로(인수인계 1.1).

**순서 보정**: v2에서 먼저 위 전제들에 이름을 붙이고(P1-1), v3는 그 이름 붙은 전제를 간선별 근거로 바꾼다. 개념을 v3에서
처음 들여오지 않는다.

### 순서

1. 새 생산자는 먼저 지금 형식(Bundle v2)으로도 내보내 Ghidra Bundle과 대조한다(G4). 비교 기준을 잃지 않기 위해서다.
2. 생산자가 자리를 잡은 뒤 근거 / 여러 해독 / 바뀔 수 있는 바이트를 담는 **Bundle v3**를 엔진과 함께 설계한다. 엔진 작업이므로 회사 쪽 리뷰를 거친다.
3. Ghidra는 v3 전환 뒤에도 비교 기준으로 남긴다.
