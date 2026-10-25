# main 분기 이후의 정방향 강화 이력

기준일: 2026-10-26. 작업 브랜치: `feature/forward-memory-footprints`.
실제 분기 기준은 `origin/main`의 **9d1fdf1**이다. 이 PC의 다른 worktree에 있는 로컬 main `83fe661`과 혼동하지 않는다.
이 문서의 범위는 이 분기 이후이며, 그 이전 프로젝트 전체를 새로 개발했다는 뜻이 아니다.

## 왜 한 작업인가

정방향 분석은 별도 backward-slice 엔진을 만들기 위한 것이 아니다. 기존 SSA·데이터 흐름 그래프에서
**어느 쓰기와 읽기가 같은 바이트를 다루는지, 호출을 지나도 그 연결이 유효한지**를 더 정확히 판단하는 보강이다.
source/sink 표기는 테스트 관찰점이며 분석 범위를 그 표기에 제한하지 않는다.
계산식 계층은 이 원 그래프의 연산·분기·반복·메모리 연결을 소비하므로, 그래프 근거가 늘면 표현할 수 있는 범위도 늘어난다.

## 커밋된 작업: main 이후 8개

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

세부 근거는 `interprocedural_design.md` §25.60–25.68에 있다. 현재 HEAD는 `1cca97b`다.
연산식 개발 브랜치의 변경은 이 8개에 포함되지 않고 아직 통합하지 않았다.

## 그 뒤 작업 트리의 개발

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

## 이번 완료선 밖에 남기는 것

- 프로그램 전체 UAF 부재 증명, 일반 재귀 및 임의 heap ENTRY-memory/할당 pointer 반환 전달.
- 모든 realloc outcome의 물리 주소·epoch 확정, 불명 크기·size0·old alias의 일반 유효성 증명.
- 모든 외부 호출·callback·숨은 쓰기의 원 기계어 효과 닫기, UE R002 전체 부채 해소.
- 부분 덮어쓰기 뒤의 기존 CALL-clobber가 보수적으로 남는 byte를 모두 정밀화하는 별도 확장.
- 연산식 브랜치 merge 및 새 전이 정보를 연산식으로 표현하는 통합 검증.

위 항목을 이번 한정 기능의 필수 잔여 작업과 섞어 무한히 확대하지 않는다.
새 계약이 들어간 결과의 portable template export도 의미 schema 감사 전까지 거부한다.
기존 모델·가정 registry·기본 정책을 자동 변경하지 않는다.

## 통합 순서

성공 byte 전이의 실제/반례·전체 회귀 및 Astra 승인까지 끝낸 다음,
별도 단계에서 연산식 브랜치를 통합하고 같은 원 정의·byte span·guard가 식에 보존되는지 확인한다.
이 작업에서는 merge·rebase·커밋·push를 수행하지 않는다. 기존 미커밋 수명 개발도 보존한다.

최종 검증 수치와 승인 상태는 아래 완료 기록 및 설계 §25.70에 기록한다.

## 최종 검증 기록

- 전체 회귀: OFF/ON 각각 **3540 passed / 32 skipped**, 실패·오류 0. 각 3572개 수집.
- 그 안의 신규 copy 검증 98개와 실제 ELF/Suite09 26개, 기존 실제 UE 86개는 모두 실행·통과했다.
  실제 26개는 신규 98개의 부분집합이다. Suite09 전체 케이스 통과 개수라는 뜻이 아니다.
- skip32는 기존 Linux worker9·Linux supervision14·미보유 Bundle9이며 신규 실제 copy 검증 skip은 없다.
- 최종 실행 전후 소스 합성 SHA256:
  `bf8dc2601ebcf5a77125909f32aa3a8b6d9391761ecff7a7efa06d11ad0859d5`.
- 기존 주소 증명 API와의 호환성 오류를 첫 전체 실행에서 발견해 수정했다. 첫 중단 실행은 최종 통과 수에 합산하지 않았다.
- 이번 작업에서는 연산식 브랜치 통합·기본값 변경·커밋·push를 수행하지 않았다. 변경 사항은 현재 작업 트리에 있다.

로그·재현·지원 제한의 상세 근거는 설계 §25.70을 따른다.

Astra가 최종 XML·소스/Core 모델 해시·8커밋 이력·지원 범위를 독립 대조하고,
**이번 한정 목표 달성과 연산식 통합 직전 마일스톤의 마무리를 최종 승인했다.** 필수 잔여 차단은 없다.
전체 UAF 부재·일반 epoch 확정·연산식 통합 완료를 승인한 것은 아니다.
