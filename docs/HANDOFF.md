# FieldTrace 인수인계

## 현재 상태

- 저장소: `deploy103/fieldtrace` (GitHub PRIVATE)
- Phase 1 보존 브랜치: `feat/codex-foundation`, 기준 커밋 `9132c97`
- Phase 2 작업 브랜치: `feat/codex-phase2` (`9132c97`에서 분기)
- Phase 2 기능·테스트 커밋: `d2b87b1`
- Phase 3 안정화 작업 브랜치: `feat/phase3-stabilization`
- Phase 3 기능·테스트 커밋: `c50567c`
- Phase 1 Draft PR: `#1` <https://github.com/deploy103/fieldtrace/pull/1>
  (`main` ← `feat/codex-foundation`, OPEN/DRAFT, 자동 병합하지 않음)
- Phase 2 stacked Draft PR: `#2` <https://github.com/deploy103/fieldtrace/pull/2>
  (`feat/codex-foundation` ← `feat/codex-phase2`, OPEN/DRAFT, 자동 병합하지 않음)
- 현재 구현 범위: `요구사항.md` Phase 1·2와 Phase 3의 Ubuntu/WSL 안정화 대부분

이 문서는 자기 자신을 포함하는 최종 커밋 해시를 주장하지 않는다. 아래 명령으로
현재 HEAD와 검증 상태를 확인한다.

```bash
git branch --show-current
git log -1 --oneline
git status --short
```

## 완료한 기반(Phase 1)

- Python 3.12 src layout, `uv.lock`, 설치를 자동 실행하지 않는 `run.sh`, Typer CLI,
  Rich 기반 한국어 숫자 메뉴와 `doctor`
- 내용 우선 형식 감지, 경로 붙여넣기·한글·공백·WSL 변환, 수동 형식/인코딩 복구
- 사건별 SQLite source/run/event/finding/artifact/diagnostic, 스키마 버전 2,
  최신 run 조회, FTS5/LIKE literal 검색, 통합 타임라인
- 분석기 오류 격리, 부분 커밋, Ctrl+C 취소, quick 예산, 원본 size/mtime 비교,
  취소 가능한 SHA-256과 hash generation 경쟁 방지
- generic text, Apache/Nginx Common/Combined, OpenSSH/sudo, TShark PCAP/PCAPNG 기본 분석
- Markdown/JSON/CSV 보고서, CSV 수식 주입 방어, 원문 근거 상세 보기

Phase 1 상세 이력과 실제 PCAP/PCAPNG 정답은 `개발일지.md`의 재개 기록 1~4에 있다.

## 완료한 핵심 분석 확장(Phase 2)

### EVTX/Sysmon

- `ElfFile\0` magic 감지, 수동 `--type evtx`, 메뉴의 Windows EVTX 선택, 명시적
  `EvtxAnalyzer` 등록
- 잠금된 `python-evtx 0.8.1`로 레코드를 순회하고 XML namespace/필드 버전 차이를
  허용하는 EventData/UserData 평탄화
- `channel:<채널>;record:<ID>` locator, 제한 XML preview, raw 시각, UTC, provider,
  channel, event ID, computer와 원문 필드 보존
- Security-Auditing+Security의 4624/4625/4688, Sysmon+Sysmon channel의 1/3,
  PowerShell+PowerShell channel의 4104, Service Control Manager+System의 7045만
  의미별로 분류. 같은 event ID라도 provider/channel이 다르면 `evtx.record`
- ProcessGuid 부모 연결 우선. GUID가 없을 때만 300초 안의 PID 후보가 정확히 하나인
  경우 `pid_time_window`로 연결하고 재사용 후보는 `pid_reuse_ambiguous`로 보존
- 깨진 XML 레코드 하나를 진단으로 격리하고 뒤 레코드를 계속 처리

### 설정 가능한 후보와 제한 디코딩

- `[patterns].flag_prefixes`가 text/web/auth/pcap/evtx에 실제 반영됨
- Base64/Hex/URL 후보 변환. 원문, 현재 encoded 값, 변환 종류와 chain, 결과, 깊이,
  truncation, EvidenceRef를 Event/Finding에 저장
- 기본 깊이 2, 입력 파일당 변환 후보 20개, 후보당 출력 4096자, encoded token
  8192자 상한. UTF-8로 안전하게 보이지 않는 결과와 무차별 긴 문자열은 버림
- 관련 설정 값의 양수/접두사 검증과 run config 기록

### 네트워크 검토 후보와 상세 분석

- DNS 전체 100자 이상 또는 label 50자 이상인 긴 질의 후보, 동일 질의 20회 이상인
  빈도 후보. 정상 원인 가능성을 명시하고 공격으로 확정하지 않음
- 웹 로그와 PCAP HTTP에 경로 이동, 민감 경로, SQL 형태, 명령 구분자, NUL 표현,
  TRACE/CONNECT를 설명 가능한 검토 후보로 표시
- TShark `follow,tcp,ascii,<stream>` 기반 TCP 대화 보기. 최대 5개, 256 KiB 외부
  출력 제한, 결과에 `completeness=unknown`과 `tcp.stream:N` 근거 기록
- TShark의 TCP/HTTP desegmentation을 사용한 `http.file_data` 본문 추출. 추출물은
  자동 실행하지 않고 core 소유 `derived/run-N/` 아래만 저장하며 SHA-256과 frame 근거 기록
- 결과 메뉴의 `상세 분석`에서 TCP 대화 보기/HTTP 본문 추출을 고를 수 있고,
  CLI custom task `tcp_streams,object_extraction`도 지원

### 교차 자료, 타임라인, 보고서

- `fieldtrace correlate --case ...`에서 source 둘 이상에 나타난 명시적 IP·도메인·
  계정·파일명을 묶음. source/event ID와 예시 근거를 표시하고 인과관계가 아님을 명시
- 기존 UTC/시간 미상 안정 정렬 timeline을 여러 source 통합 타임라인으로 사용
- Markdown/JSON/CSV 보고서에도 correlation과 artifact를 포함
- 외부 CDN/폰트/이미지 없는 HTML 보고서. 모든 동적 값과 원문을 stdlib
  `html.escape(..., quote=True)`로 escape하고 브라우저 내 검색 입력 제공

## 계약 변경과 마이그레이션

PCAP 파생 파일 쓰기가 필요해 `AnalysisContext.artifact_sink` 선택 필드와
`ArtifactSink` Protocol을 추가했다. 분석기는 경로를 직접 정하지 않고 bytes와
EvidenceRef만 core sink에 넘긴다. `SafeArtifactSink`가 basename 정규화, 개별
32 MiB 제한, 이름 충돌 회피, SHA-256을 담당한다.

기존 `AnalysisContext` 필드는 변경하지 않고 새 필드는 모두 기본값을 제공하므로 기존
분석기 호출자는 수정 없이 동작한다. Phase 2 자료는 기존 JSON fields와 artifacts
테이블로 표현되어 SQLite schema는 2를 유지하며 DB 마이그레이션은 없다.
`MenuController` 구현체는 새 `detail_tasks()`와 `analyze_detail()` 메서드를 제공해야
한다. 실제 구현은 UI에서 SQL/subprocess를 호출하지 않고 core service로 위임한다.

## 재현 명령

```bash
uv lock --check
uv sync --frozen --all-groups
uv run ruff check .
uv run pytest -q
uv run python -m compileall -q src/fieldtrace
git diff --check
```

Phase 3 대형/오프라인 재현:

```bash
uv run python scripts/benchmark-large-log.py --size-gib 1 --rss-limit-mib 512
uv run python scripts/benchmark-large-pcap.py --size-gib 1 --rss-limit-mib 512
./scripts/prepare-wheelhouse.sh ./wheelhouse
./scripts/rehearse-offline.sh ./wheelhouse
```

실제 TShark 4.2.2 임시 로컬 경로가 남아 있는 현재 WSL 세션:

```bash
env PATH="/tmp/fieldtrace-tshark-local-20260909/bin:$PATH" uv run pytest -q
```

공개 EVTX binary 통합 검사는 준비 단계에서 파일을 받은 뒤 분석 자체를 오프라인으로
실행한다. SHA-256이 아래 값과 다르면 테스트 자료로 사용하지 않는다.

```bash
curl -fL \
  https://raw.githubusercontent.com/williballenthin/python-evtx/master/tests/data/issue_38.evtx \
  -o /tmp/fieldtrace-public-issue-38.evtx
sha256sum /tmp/fieldtrace-public-issue-38.evtx
env FIELDTRACE_EVTX_ISSUE38_FIXTURE=/tmp/fieldtrace-public-issue-38.evtx \
  uv run pytest -q tests/test_evtx_integration.py
```

대표 CLI:

```bash
./run.sh doctor
./run.sh analyze ./input --profile full --case ./cases/demo
./run.sh analyze evidence.evtx --type evtx --case ./cases/evtx-demo
./run.sh analyze capture.pcapng --profile custom \
  --tasks tcp_streams,object_extraction --case ./cases/pcap-detail
./run.sh search --case ./cases/demo --text 'FLAG{'
./run.sh correlate --case ./cases/demo
./run.sh timeline --case ./cases/demo
./run.sh report --case ./cases/demo --format html
```

## 실제 검증 근거

- 합성 XML/fake reader에서 EVTX magic, Security 로그인, provider/channel 오분류 방지,
  Sysmon process/network, PowerShell, 깨진 레코드 격리, GUID/PID 부모 연결 검증
- 공개 `python-evtx` 회귀 자료 `issue_38.evtx`를 `/tmp`에서만 받아 실제 binary 종단
  검증: SHA-256 `becab64455866f8fae5583fbaa5dab901115e4397ea7abe14f37ad732d5d7eb9`,
  Security event 4672, record 17845, UTC `2017-06-23T05:31:19.787264+00:00`,
  `SubjectLogonId=0x000000000019d3af` 검색 성공
- 공개 자료 출처: <https://github.com/williballenthin/python-evtx/tree/master/tests/data>,
  upstream Apache-2.0. 실제 사용자 증거가 아니지만 합성 자료도 아니므로 저장소에는
  추적하지 않았다.
- 실제 TShark 4.2.2에서 DNS PCAP과 HTTP PCAPNG 기본 분석, HTTP PCAPNG의
  `tcp.stream:0` 재조립과 raw GET 요청을 확인
- mock TShark에서 HTTP body bytes→core sink 파일→SHA-256→Artifact DB 계약과
  DNS/HTTP 후보 규칙을 검증
- HTML 악성 `<script src=...>` 원문 escape, 로컬 검색 UI, artifact/correlation 표시 검증
- 시스템 TShark/외부 EVTX fixture 없는 기본 환경: `64 passed, 2 skipped`
- 로컬 TShark 4.2.2와 공개 EVTX fixture를 모두 지정한 환경: `66 passed`
- Ruff, compileall, `uv lock --check`, `git diff --check`: 통과

## Phase 3 현장 안정화 진행(2026-09-09)

- 작업 브랜치: `feat/phase3-stabilization` (`feat/codex-phase2`에서 분기)
- 동일 사례 분석 단일-writer 잠금, 중단된 `running` run의 `failed/partial` 복구와
  `recovery` 진단을 추가했다. SQLite lock/busy, disk full, read-only, 손상 오류는
  단계·이유·다음 행동이 있는 현장 오류로 분류한다.
- 보고서와 파생 파일을 `.part` 임시 파일→`fsync`→원자 교체로 저장한다. 실패 시 기존
  보고서를 보존하고 부분 파일을 제거한다.
- 외부 runner가 시작 전 취소를 확인하고 HOME/XDG_CONFIG_HOME을 호출자 override보다
  우선 격리한다. stdout/stderr 제한, timeout, 취소, 격리 HOME 테스트를 추가했다.
- `doctor`가 사례 폴더에서 SQLite WAL 쓰기·읽기 round-trip을 실제 확인한다. 파일 선택
  메뉴의 `d: 문제 해결`에서 동일 진단과 다음 행동을 바로 볼 수 있다.
- EVTX 프로세스 연결 캐시에 GUID 50,000개, PID 50,000개, PID별 이력 16개 제한을
  두고 제거 발생 시 부분 분석으로 표시한다. 교차 자료 입력 row는 스트리밍한다.
- 4 MiB 비후보 줄로 후보 추출기 단축 경로를 회귀 검증했다. 1 GiB/64 KiB 줄 합성
  UTF-8 텍스트 full 분석은 WSL2 Ubuntu 24.04.4, Python 3.12.3에서 55.294초,
  peak RSS 60.81 MiB, 16,384줄, 실패 0, complete였다. TShark 프로세스는 포함하지
  않았다. 최적화 전 같은 입력은 quick 30초 제한에도 603.989초가 걸린 실제 결함이었고
  이를 수정했다.
- 1.00005 GiB 합성 PCAP(65,535바이트 패딩 DNS frame 16,381개)을 실제 임시
  TShark 4.2.2로 full 분석했다. 201.297초, FieldTrace peak 63.74 MiB, TShark peak
  145.88 MiB, 동시 peak의 보수적 합산 상한 209.61 MiB, 이벤트 32,762건, 실패 0,
  complete였다. 외부 TShark를 포함한 RSS 목표 512 MiB 이하를 충족했다.
- 분석 직후 결과 화면은 전체 event를 RAM에 올리지 않고 집계와 후보/진단 각 200개만
  조회한다. 생략 여부와 전체 결과 확인 방법을 표시한다. 메뉴 timeline은 500개,
  CLI 기본 timeline은 1,000개로 제한했다.
- `/tmp/fieldtrace-phase3-wheelhouse`에서 잠긴 wheelhouse를 준비하고 Linux network
  namespace에서 새 venv `pip --no-index` 설치→doctor→합성 로그 full 분석→`FLAG{`
  검색→self-contained HTML 생성까지 통과했다. 준비 과정에서 wheel 미배포
  `hexdump 3.3` 때문에 기존 `--only-binary` 절차가 실패하는 것을 발견해 온라인에서
  모든 잠긴 의존성을 wheel로 빌드하도록 고쳤다.
- 사례 잠금/중단 복구/SQLite 오류/원자 저장/긴 줄/runner/결과 화면/문제 해결 메뉴 등
  안정화 회귀 테스트 16개를 추가했다.
- 임시 Ubuntu 패키지로 TShark 4.2.2를 `/tmp`에서 실행해 실제 DNS PCAP, HTTP PCAPNG,
  TCP stream 회귀를 다시 통과했다. SHA-256을 확인한 공개 `issue_38.evtx`도 실제
  python-evtx로 다시 통과했다. 두 통합 자료를 모두 지정한 전체 suite는 `81 passed`,
  시스템 TShark/외부 EVTX fixture가 없는 기본 환경은 `79 passed, 2 skipped`이다.

## 남은 제약과 다음 작업

- WSL에서 `/mnt/c/Windows/System32/winevt/Logs/*.evtx` 접근은 권한 거부된다. 권한을
  우회하지 않았으며 사용자가 읽을 수 있는 복사본을 입력으로 받아야 한다.
- 저장소에 추적한 합성 binary EVTX writer/fixture는 없다. 파서 의미는 합성 XML로,
  실제 바이너리 I/O는 출처가 확인된 `/tmp` 공개 fixture로 분리 검증했다.
- HTTP 객체 추출은 `http.file_data`가 제공하는 본문만 지원한다. 파일명/MIME 확장자
  자동 결정, 다른 프로토콜 객체, 자동 실행은 지원하지 않는다.
- TCP 재조립의 재전송·순서·누락 처리는 TShark에 맡기며 FieldTrace는 완전 복원을
  주장하지 않는다. 상세 보기는 현재 앞 5개 stream으로 제한된다.
- Kali는 아직 검증하지 않았다. 시스템 TShark는 설치하지 않았고 `/tmp`에 푼 Ubuntu
  24.04 패키지로 검증했다. 다른 TShark 버전과 Kali 패키지는 지원 확정하지 않는다.
- 실제 filesystem을 가득 채우지 않고 SQLite disk-full 오류 주입, 원자 쓰기 실패,
  4 MiB 긴 줄을 검증했다. 대형 손상 EVTX/PCAP과 다중 패킷·재전송·누락 PCAP fixture는
  추가 보강이 필요하다.
- 일반 검색/timeline은 제한할 수 있지만 전체 JSON/HTML/CSV 보고서와 상관 결과는 큰
  사례에서 결과 크기만큼 메모리를 사용할 수 있다. 보고서 스트리밍/페이지 제한은 다음
  안정화 우선순위다.
