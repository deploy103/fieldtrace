# FieldTrace 구조와 확장 계약

## 경계

FieldTrace는 네 방향으로 나뉩니다.

- `ui`: 일반 `input()` 숫자 메뉴와 Rich 출력만 담당합니다. SQL이나 외부
  프로세스를 직접 실행하지 않습니다.
- `core`: 사례 폴더, 형식 감지, 등록 목록, 분석 실행, 외부 도구 제한,
  SQLite 저장, 검색과 타임라인을 소유합니다.
- `analyzers`: 입력을 읽고 타입이 명확한 분석 항목을 순서대로 내보냅니다.
  Rich와 SQLite에 의존하지 않습니다.
- `reports`: core가 조회한 자료를 Markdown, JSON, CSV로 직렬화합니다.

런타임에 임의 Python 파일을 찾거나 실행하지 않습니다. 지원 분석기는 코드에
명시된 등록 목록만 사용합니다.

## 분석기 계약

모든 분석기는 다음 세 메서드를 구현합니다.

```python
probe(sample, metadata) -> ProbeResult
capabilities(environment) -> Capability
analyze(context) -> Iterator[AnalysisItem]
```

`probe`는 core가 건넨 최대 64 KiB 표본만 검사하며 전체 분석을 하지 않습니다.
확장자는 보조 신호이고 PCAP magic, BOM, 실제 로그 패턴 같은 내용을 우선합니다.
`capabilities`는 외부 도구 부재를 예외 대신 사용 불가 사유로 돌려줍니다.

`AnalysisContext`에는 입력 경로, source/run/case ID, 취소 이벤트, 시간대 정책,
시간·레코드·줄 크기 예산, 안전한 외부 실행기, 프로필과 custom 항목이 있습니다.
분석기는 `Event`, `Finding`, `Artifact`, `Progress`, `Diagnostic`만 산출합니다.
쓰기와 배치 커밋은 core 실행기가 담당합니다.

새 분석기를 추가하려면 다음 순서로 작업합니다.

1. 제한 표본으로 내용 기반 `probe`를 구현합니다.
2. 누락 의존성과 실제 제공 기능을 `capabilities`에 적습니다.
3. 스트리밍 `analyze`에서 취소와 예산을 주기적으로 확인합니다.
4. 모든 결과에 source ID와 줄/frame 같은 재현 가능한 근거를 붙입니다.
5. 등록 목록에 명시적으로 추가하고 합성 정답 fixture 테스트를 작성합니다.

미구현 분석기를 사용 가능으로 등록하거나 빈 반복자를 성공 처리해서는 안 됩니다.

## 실행 흐름

```text
경로 수집 → 제한 표본 감지 → source/run 생성 → 분석기 선택
         → AnalysisItem 스트림 → core 배치 저장 → 상태/coverage 확정
         → 최신 run 조회 → UI 또는 보고서
```

여러 입력 중 한 분석기가 실패해도 진단과 traceback을 저장하고 다음 입력을
계속합니다. quick 예산 도달은 오류가 아니지만 coverage는 `partial`입니다.
사용자 취소는 이미 커밋된 배치를 남기고 run을 `cancelled`로 마칩니다.

외부 명령은 인자 배열, `shell=False`, 제한 출력, timeout과 프로세스 그룹 정리를
사용합니다. 임시 HOME/XDG 설정 폴더와 허용 목록 환경으로 사용자 프로필 영향을
줄입니다. TShark는 최소 `-n -r <입력>`으로 이름 해석 없이 기존 파일만 읽고,
FieldTrace가 정한 필드만 TSV로 받습니다.

## SQLite 개요

사건마다 `fieldtrace.sqlite3` 하나를 사용합니다. `schema_version` 테이블의 버전으로
스키마를 식별하며 현재 `SCHEMA_VERSION`은 2입니다. 버전 2는 같은 source를
재분석할 때 이전 백그라운드 해시가 새 결과를 덮지 못하도록 `hash_generation`을
추가했습니다. 주요 테이블은 다음과 같습니다.

- `sources`: 원본 절대 경로, 크기, mtime, 감지 형식·이유, SHA-256 상태,
  분석 뒤 변경 여부
- `runs`: source, 프로필, 분석기·도구·설정, 시작·종료, status, coverage,
  읽은 수, 실패 수와 생략 이유
- `events`: 원시·UTC 시각, 시간대 상태, category, 요약, 네트워크·사용자 필드,
  JSON 세부 필드와 EvidenceRef
- `findings`: 규칙 ID, 관측 사실, 제한적인 해석, severity와 별도 confidence,
  관련 근거
- `artifacts`: 파생 경로·해시·종류·분석기·원본 근거
- `diagnostics`: 실패 단계, 짧은 이유, 다음 행동과 진단 파일 참조

가능하면 FTS5 색인을 쓰고, SQLite 빌드에 FTS5가 없으면 escape된 `LIKE` 검색으로
동일한 literal 검색 기능을 느리게 제공합니다. 기본 집계는 source별 최신 run만
사용해 재실행 중복을 피합니다. 같은 UTC 시각에서는 source와 event 순서로
안정 정렬하고, UTC를 확정할 수 없는 이벤트는 시간 미상 영역에 둡니다.

Phase 2에서 스키마가 바뀌면 버전을 올리고 기존 DB를 위한 순차 마이그레이션과
되돌릴 수 있는 백업 절차를 함께 문서화해야 합니다.

## 시간과 원본성

오프셋이 있는 시각만 직접 UTC로 정규화합니다. 연도 없는 syslog는 설정으로 연도와
시간대를 모두 받기 전까지 `timestamp_raw`만 저장하며 현재 연도나 UTC로 조용히
확정하지 않습니다. DST 중복·누락 시각도 임의로 고르지 않습니다. 원본은 쓰지 않고
분석 전후 size/mtime을 비교합니다. SHA-256이 취소되면 완료 값 대신 중단 상태를
저장합니다.
