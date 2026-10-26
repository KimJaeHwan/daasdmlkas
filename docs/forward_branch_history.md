# main 분기 이후의 정방향 강화 이력

기준일: 2026-10-26. 작업 브랜치: `feature/forward-memory-footprints`.
실제 분기 기준은 `origin/main`의 **9d1fdf1**이다. 이 PC의 다른 worktree에 있는 로컬 main `83fe661`과 혼동하지 않는다.
이 문서의 범위는 이 분기 이후이며, 그 이전 프로젝트 전체를 새로 개발했다는 뜻이 아니다.

## 왜 한 작업인가

정방향 분석은 별도 backward-slice 엔진을 만들기 위한 것이 아니다. 기존 SSA·데이터 흐름 그래프에서
**어느 쓰기와 읽기가 같은 바이트를 다루는지, 호출을 지나도 그 연결이 유효한지**를 더 정확히 판단하는 보강이다.
source/sink 표기는 테스트 관찰점이며 분석 범위를 그 표기에 제한하지 않는다.
계산식 계층은 이 원 그래프의 연산·분기·반복·메모리 연결을 소비하므로, 그래프 근거가 늘면 표현할 수 있는 범위도 늘어난다.

## 정방향 개발 이력: main 이후 첫 8개 커밋

| 순서 / 커밋 | 작업 | 실질적으로 달라진 점 |
|---|---|---|
| 1 / `915d5a6` | 기존 정방향 주소 범위를 별칭 판단에 연결 | 불필요한 STORE→LOAD 후보를 원 byte 근거로 제외. 44번의 가변 주소 연결 강화 시작 |
| 2 / `b89d6a7` | 같은 메모리 값을 읽는 LOAD의 정체성 공유, 호출 보존 레지스터 저위 부분 연결 | 44번의 배열 쓰기·읽기 주소가 같은 값임을 유지하고 실제 메모리 간선 연결 |
| 3 / `b23469e` | 상수 메모리값과 입구 indexed 쓰기 조건 전달 | 기존 SSA의 정확 상수와 가변 주소 조건을 함수 요약·템플릿·호출자까지 전달 |
| 4 / `1ec1782` | 할당 범위 밖 주소의 잘못된 분리 수정 | ‘할당 포인터니까 임의 offset도 스택과 안 겹친다’는 잘못된 추론 제거. 모르면 후보·부채 유지 |
| 5 / `e7cbbcb` | entry/frame 가정 OFF 검증과 Core 모델 재도출 | 44번 및 실제 UE 비교. 원 Core 코드에서 파생 모델 3개를 더 약한 전제로 다시 생성 |
| 6 / `af11642` | 원 raw leaf의 byte 보존 증거, free/realloc 메모리 장벽 | 근거 없는 호출 보존을 철회. UE R002의 부채 10→33은 새 UAF 검출이 아니라 이전 과도한 보존 철회 결과 |
| 7 / `40aef76` | 첫 Trace Grow의 NULL Realloc→스택 슬롯 8B 비변경 증명 | 특정 byte 의무를 닫는 첫 실제 수직 사례. 일반 비NULL realloc 해결은 아님 |
| 8 / `1cca97b` | 호출별 상태 전달과 CALL 메모리 보존 판정 분리 | caller→callee 입구 상태 연결과 개별 CALL/byte 판정의 책임을 분리. 수명 분석 확장 기반 정리 |

세부 근거는 `interprocedural_design.md` §25.60–25.68에 있다. `1cca97b` 시점의 이력이며,
연산식 개발 브랜치의 변경은 이 8개에 포함되지 않는다. 후속 개발과 통합은 아래 별도 기록을 따른다.

## 후속 수명·성공 내용 전이 개발 — `fbc1a62`

아래 개발은 통합 전 체크포인트 `fbc1a62`로 커밋했다. 원 main부터 정방향 개발 커밋은 총 9개다.

### 1. 필요한 구간의 할당 정체성·별칭·수명

새 SSA를 만들지 않고 원 정의·read fragment·원 CFG에 사실을 붙였다.

- 할당 사건·호출 문맥·반복 회차를 숫자 주소와 구분한다. 주소 재사용은 같은 할당이라는 증거가 아니다.
- 전체폭 pointer COPY·정확한 spill/reload·상수 offset·분기 합류를 추적한다.
- free/realloc·불명 호출을 거친 수명을 검사한다. invalid free를 UB라는 이유로 분석에서 삭제하지 않는다.
- 알려진 직접 비재귀 호출의 원 물리 register port로 caller 할당 사실을 callee에 전달한다.
- 반복은 현재 회차의 닫힌 birth→use 구간까지만 증명한다. 이전 회차 JOIN·old alias는 unknown을 유지한다.
- 양수 realloc 실패의 원 NULL 분기에서는 계약이 보장하는 old allocation의 수명 유지를 증명한다.

이는 별도 opt-in `lifecycle_contracts=` 입력이 있을 때만 동작한다. 기본값은 `()`로 유지한다.
외부 모델의 `fresh/same_object/frees` 표기만으로 크기·수명·내용 보존을 추측하지 않는다.
이 단계의 이전 동결 회귀는 OFF/ON 각각 **3408 passed / 32 skipped**였다(§25.69).
이번 성공 내용 전이 개발의 최종 회귀와 혼동하지 않는다.

### 2. 성공 realloc의 원 바이트 전달 — 연산식 통합 전 마지막 개발 범위

명시 `contents=preserve-prefix` 계약, 원 non-NULL 성공 분기, old allocation의 생존·크기,
원 결과 pointer provenance, **CALL 직전의 독립적인 writer snapshot**이 모두 닫힌 byte fragment만 승인한다.
복사 범위는 `min(old_size, new_size)` 안이다. `same_object`는 후보 좌표를 찾는 데 쓰일 뿐 복사 증명이 아니다.

원 SSA 정의·읽기·JOIN은 유지하고, 승인된 읽기 fragment의 원 그래프 간선만 다음처럼 표현한다.

```text
원 STORE → 원 메모리 정의 → realloc 바이트 전이 → 이후 LOAD
                              ↑            ↑
                           원 CALL      원 성공 분기
```

전이에는 원 CALL·reader·byte span·writer·성공 guard·계약과 전체 의존이 연결된다.
normalizer·정방향 probe·기존 byte query가 같은 봉인 근거를 소비한다.
CALL 전체의 메모리 보존으로 확대하지 않으며, 다른 CALL·미확인 writer·범위 밖 byte의 부채는 유지한다.
스택 STORE와 비겹침은 old birth뿐 아니라 **resize 시점에도 활성인 스택 범위**임을 확인한다.

실제 대상은 Suite09 DFB031과 별도 C→ELF→Ghidra Bundle의 grow/shrink/부분 덮어쓰기/불명 호출이다.
실제 분기 인식에서 발견한 full-width `x-0` 항등식과 zero-op NOP CFG 경유도 공통 로직으로 처리한다.
시험용 allocator outcome 관찰은 native libc 실행이나 실제 allocator 구현 인증이 아니다.

## 정방향 마일스톤 완료선 밖에 남긴 것

- 프로그램 전체 UAF 부재 증명, 일반 재귀 및 임의 heap ENTRY-memory/할당 pointer 반환 전달.
- 모든 realloc outcome의 물리 주소·epoch 확정, 불명 크기·size0·old alias의 일반 유효성 증명.
- 모든 외부 호출·callback·숨은 쓰기의 원 기계어 효과 닫기, UE R002 전체 부채 해소.
- 부분 덮어쓰기 뒤의 기존 CALL-clobber가 보수적으로 남는 byte를 모두 정밀화하는 별도 확장.
- 연산식 브랜치 merge 및 새 전이 정보를 연산식으로 표현하는 통합 검증(후속 통합은 아래 참조).

위 항목을 이번 한정 기능의 필수 잔여 작업과 섞어 무한히 확대하지 않는다.
새 계약이 들어간 결과의 portable template export도 의미 schema 감사 전까지 거부한다.
기존 모델·가정 registry·기본 정책을 자동 변경하지 않는다.

## 정방향 개발 당시의 통합 순서

성공 byte 전이의 실제/반례·전체 회귀 및 Astra 승인까지 끝낸 다음,
별도 단계에서 연산식 브랜치를 통합하고 같은 원 정의·byte span·guard가 식에 보존되는지 확인한다.
이 마일스톤 자체에서는 merge·rebase·커밋·push를 하지 않았으며, 이후 사용자 요청으로 체크포인트와 통합을 진행했다.

최종 검증 수치와 승인 상태는 아래 완료 기록 및 설계 §25.70에 기록한다.

## 정방향 단독 마일스톤의 최종 검증 기록

- 전체 회귀: OFF/ON 각각 **3540 passed / 32 skipped**, 실패·오류 0. 각 3572개 수집.
- 그 안의 신규 copy 검증 98개와 실제 ELF/Suite09 26개, 기존 실제 UE 86개는 모두 실행·통과했다.
  실제 26개는 신규 98개의 부분집합이다. Suite09 전체 케이스 통과 개수라는 뜻이 아니다.
- skip32는 기존 Linux worker9·Linux supervision14·미보유 Bundle9이며 신규 실제 copy 검증 skip은 없다.
- 최종 실행 전후 소스 합성 SHA256:
  `bf8dc2601ebcf5a77125909f32aa3a8b6d9391761ecff7a7efa06d11ad0859d5`.
- 기존 주소 증명 API와의 호환성 오류를 첫 전체 실행에서 발견해 수정했다. 첫 중단 실행은 최종 통과 수에 합산하지 않았다.
- 이 검증 당시에는 연산식 브랜치 통합·기본값 변경·커밋·push를 수행하지 않았다. 검증된 변경은 이후 `fbc1a62`로 보존했다.

로그·재현·지원 제한의 상세 근거는 설계 §25.70을 따른다.

Astra가 최종 XML·소스/Core 모델 해시·8커밋 이력·지원 범위를 독립 대조하고,
**이번 한정 목표 달성과 연산식 통합 직전 마일스톤의 마무리를 최종 승인했다.** 필수 잔여 차단은 없다.
전체 UAF 부재·일반 epoch 확정·연산식 통합 완료를 승인한 것은 아니다.

## 연산식 브랜치 통합 — 검증·최종 승인 완료

사용자 요청으로 `feature/multi-target-memory-flow`의 `c8379e8`까지 14개 커밋을 현재 정방향 브랜치에 병합한다.
main이나 다른 worktree의 미커밋 파일은 변경하지 않는다. 기존 전체 그래프·SSA·식 간략화·반복 요약 기능은 보존한다.

- 새 realloc 전이도 원 writer 식 → 조건부 `memory_transfer` → LOAD로 표현한다. 원 CALL·성공/실패 간선·결과 정의·계약 의존을 보존한다.
- 이 조건부 전이를 무조건 COPY로 평가하지 않는다. 현재 수치 평가·물리 평가·동등성/한 회차 소비기는 명시적으로 거부하거나 partial을 반환한다.
- indexed 메모리를 fixed 메모리로 합성하면서 조건을 잃는 경로와, 부분 출력이 원 전체 상수값을 물려받는 경로를 차단했다.
- 호출별로 달라진 효과에 generic 호출의 성공 판정·출처를 재사용하지 않는다. 전체 효과가 같은 호출만 독립 복사한다.
- record 형식은 15, 엔진 의미 판은 20, template 형식은 3이다. Core 모델은 원 DLL Bundle에서 실제 재도출했다.
  OFF는 3개 export, ON은 2개 export를 도출하며 Append는 caller 소유 activation의 portable export 제한으로 의도적으로 거부한다.

통합 동결본의 최종 회귀는 OFF/ON 각각 **4658 passed / 32 skipped / 0 failures / 0 errors**다.
양쪽 실제 바이너리 검사 308개는 모두 실행·통과했다. 신규 realloc 연산식 10개와 UE 관련 107개는 전체 4658개 결과의 부분집합이다.
수치가 Suite09 전체 80개 케이스의 완전성이나 모든 프로그램의 간선 증명을 뜻하지는 않는다.
소스 합성 SHA256은 `8d47231b782dcdc5d5896e81725f1991bf068f2b0dbabbab06d89d15d5c01361`이며 실행 중 유지했다.
초기 실제 부분 레지스터/조건부 사례의 표현 방식 기대 충돌은 원 byte·분기·callee 연결을 대조하고 검사를 강화했다.
위 3540/3350 수치는 통합 전 결과다. Astra가 최종 XML·해시·병합 부모·지원 경계를 독립 확인하고,
**이번 한정 통합 목표 달성과 현재 검증본의 커밋·푸시를 최종 승인했다.** 필수 잔여 차단은 없다.
원격 대상은 `origin/feature/forward-memory-footprints`이며 main이나 다른 worktree를 변경하지 않는다.
상세는 설계 §25.71, 실제 병합 커밋 ID·원격 반영은 Git 이력과 완료 응답을 따른다.

## main 병합 검토 (2026-10-26, 회사 PC)

집 PC Bundle이 필요한 343개를 뺀 전체 회귀는 OFF/ON 각각 **4354 passed / 343 skipped / 0 failures**다.
실행 대조(`measure_program`, Bundle 13개 설정, OFF/ON)는 빠진 의존 0이고 수치는 main과 같다.
Astra·Fable 검토(각 2차)에서 나온 기본 경로 수정 두 가지를 병합 전에 반영했다.

- **호출의 push 칸과 겹치는 인덱스 읽기** (Astra P1, 건전성): 피호출 함수의 `[SP+RDX]`처럼 인덱스 주소로
  읽는 접근도 push overlay 검사(`relative_memory.project_anchored`의 `pre_call_overlay`)를 받는다.
  `normalize._proven_call_rows`가 인덱스 접근의 입력만이 아니라 접근 자체를 보호한다.
  증명 안 되면 빚으로 남고(정밀도 손실, 건전), 재현 예제가 회귀 테스트(`test_indexed_call_overlay.py`)다.
  수정 전에는 완전하다고 한 조각이 실제 의존 48개를 놓쳤다.
- **스택 검사의 leaf 사전 분석 예산** (Fable P1): `_stack_preservation`의 사전 분석을 `("stack-check", scope)` 장부에 청구한다.
  같은 함수 한도가 걸리지만 leaf 자신의 분석 예산은 쓰지 않는다.
- 스냅샷 도구: 이 브랜치의 새 필드를 `semantic_snapshot.ADDED_FIELDS`에 등록했다. 기본값이면 생략되어 이전 기준선과 비교할 수 있다.

스냅샷 의미 차이(audit1 대비)는 다음과 같다.
- 정확한 상수(`literal`), 주소 관계, SSA flow edge가 새로 기록된다. 정의·노드 번호가 밀린다.
- 모델 설정에서는 free/realloc 보존 철회와 Core 모델 재도출로 일부 root가 불완전해지고, 출처 라벨에 `source_B`가 더해진다.
- 테스트베드 채점에서 v2-win-debug-full DFB030·DFB031이 PASS→FAIL이다. 금지된 `source_B`를 보고한 것으로, 근거 없던 보존을 철회한 보수적 변화다.
- v3 두 Bundle의 채점은 같다.

새 기준선은 `audit2`다.

남은 일:
- main에도 있던 같은 종류의 구멍을 고친다. 피호출 함수가 `[RSP]`를 인덱스 없이 직접 읽어도 push 이전 값에 묶인다(Fable 재현, 별도 수정).
- 스택 기준 인덱스 읽기의 정밀도를 회복한다.
- P2 후속: leaf identity 스위치, `definition_constants` 회귀 테스트, `_call_boundaries` 오류 처리.
