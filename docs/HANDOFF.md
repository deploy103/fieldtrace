# FieldTrace Phase 1 인수인계

## 현재 상태

- 저장소: `deploy103/fieldtrace` (GitHub PRIVATE)
- 브랜치: `feat/codex-foundation`
- 기준 브랜치/커밋: `main` / `5a126fe`
- 구현 범위: `요구사항.md`의 Codex Phase 1
- Phase 1 기능 커밋: `3af5332`, `d076955`, 테스트 커밋 `06f9147`
- Draft PR: 브랜치 push 뒤 이 문서에 URL과 상태를 추가한다.

이 문서는 자신의 최종 커밋 해시를 주장하지 않는다. 아래 결과는 2026-09-09
현재 작업 폴더에서 실제 실행한 값이다.

## 완료한 Phase 1

- Python 3.12 src layout, `uv.lock`, 준비된 `.venv`만 쓰는 `run.sh`, Typer CLI와
  `doctor`
- 인자 없는 한국어 숫자 메뉴, 파일 페이지·검색·전체 선택·경로 붙여넣기,
  Enter quick, full/custom, 최근 폴더·사례 TOML 상태
- 공백·한글 경로 보존, 짝이 맞는 바깥 인용부호 제거, WSL 확인 뒤 Windows 경로
  변환, 터미널 제어 문자와 Rich 마크업 방어
- 최대 64 KiB 내용 우선 감지, 파일별 수동 형식 선택, CP949/EUC-KR/UTF 계열 수동
  인코딩 복구, 명시적 내장 분석기 등록
- 사례별 SQLite source/run/event/finding/artifact/diagnostic 저장, 스키마 버전 2,
  배치 커밋, 최신 run 기본 조회, FTS5와 escape된 LIKE 저하 검색
- 분석기 오류 격리와 traceback 진단 파일, 취소 뒤 부분 결과, quick 예산 부분
  coverage, 원본 전후 size/mtime 확인, 취소 가능한 백그라운드 SHA-256과 세대 경쟁 방지
- generic text 전체 안전 줄 색인, 줄 번호, IPv4/IPv6·도메인·인용 문자열·기본
  `FLAG{}`/`CTF{}` 후보
- Apache/Nginx Common/Combined의 IP·시각·method·URI raw/decode·status·bytes와 집계,
  미지원 줄 원문/비율/부분 상태
- OpenSSH 성공·실패와 sudo COMMAND, 미해석 줄 원문, 연도·시간대 미확정 보존,
  명시한 year/timezone 가정 및 DST 모호·존재하지 않는 시각 보존
- TShark `-n -r` 기반 PCAP/PCAPNG packet/protocol/IP/port/DNS/평문 HTTP 필드 요약과
  frame 근거, `shell=False`, timeout·출력·취소 제한과 임시 도구 설정 폴더
- 요약 → 후보 → 원문 근거 → 진단 UI, literal 검색, 시간순/시간 미상 보기,
  Markdown/JSON/CSV 보고서와 CSV 수식 방어
- 합성 text/web/auth 자료와 1패킷 PCAP hex fixture, mock TShark와 실제 TShark
  integration marker 분리

결과 메뉴의 별도 고비용 `상세 분석`은 Phase 1에 실제 항목이 없으므로 ‘준비 중’으로
비활성화했다. HTML 보고서, EVTX 등 후속 기능도 성공 기능처럼 등록하지 않았다.

## 재현 명령

준비와 자동 검사:

```bash
uv lock --check
uv sync --frozen --all-groups
uv run ruff check .
uv run pytest -q
uv run python -m compileall -q src/fieldtrace
git diff --check
```

CLI 종단 흐름:

```bash
./run.sh doctor
./run.sh
./run.sh analyze samples --profile quick --case cases/phase1-check
./run.sh analyze samples --profile full --case cases/phase1-full
./run.sh analyze samples --profile custom \
  --tasks network_summary,http_requests,login_activity,executed_commands,literal_search \
  --case cases/phase1-custom
./run.sh search --case cases/phase1-check --text 'FLAG{'
./run.sh timeline --case cases/phase1-check --limit 20
./run.sh report --case cases/phase1-check --format markdown
./run.sh report --case cases/phase1-check --format json
./run.sh report --case cases/phase1-check --format csv
```

실제 TShark가 있는 환경의 분리된 통합 검사:

```bash
uv run pytest -q -m integration tests/test_tshark_integration.py
```

## 실제 검증 결과

- Python `3.12.3`, Typer `0.27.2`, Rich `14.3.4`
- Ruff: 전체 통과
- pytest: `38 passed, 1 skipped in 6.33s`
- skip: 실제 TShark가 설치되지 않아 패킷 통합 검증을 수행하지 않음
- `compileall`, `git diff --check`: 통과
- quick/full/custom로 `samples/` 3개를 각각 분석: 모두 exit 0, source/run 3개,
  event 12개, finding 5개, failure 0, complete
- 검색 `FLAG{`: 4건, 웹 decoded URI와 generic `text.line` 포함
- 타임라인: 웹 UTC 3건과 auth/generic 시간 미상 영역 분리, `line:N` 보존
- Markdown/JSON/CSV: 세 형식 모두 생성 및 비어 있지 않음 확인
- 실제 숫자 메뉴: 파일 번호 → Enter quick → 후보 번호 → `line:3` 원문 → Markdown
  보고서 저장 성공
- 실제 숫자 메뉴: 전체 파일 → custom 5개 항목 → 결과 메뉴 성공
- 80열, `NO_COLOR=1`, `TERM=dumb`, stdout redirect: 메뉴 폭과 ANSI escape 없음 확인
- TShark 부재 혼합 입력: PCAP run만 unsupported/exit 1, 함께 넣은 텍스트 분석과
  `FLAG{offline_evidence_42}` 검색은 성공
- 원본 bytes/size/mtime/SHA-256 보존, state 손상 복구, LIKE wildcard escape,
  hash generation 경쟁은 자동 테스트로 확인

## 현재 환경에서 검증하지 못한 항목

현재 PATH에 `tshark`가 없다. 따라서 실제 TShark로 PCAP/PCAPNG을 분석했다고
주장하지 않는다. 추적한 fixture는 `file`에서 정상 classic PCAP(122 bytes)으로
확인했고, mock에서는 `-n -r`, DNS `challenge.example.test`, `frame:1` 계약을
검증했다. 실제 엔진 검증은 위 integration 명령을 TShark 준비 환경에서 실행해야 한다.

Ubuntu 24.04/WSL2 계열 현재 환경 외에 Kali, Windows 네이티브, macOS와 1GB급 자료도
검증하지 않았다. Windows 네이티브와 macOS는 초기 지원 범위가 아니다.

## 종료 코드와 알려진 제약

- 0: 요청 범위 성공. quick 예산 도달도 0이지만 run coverage는 `partial`이다.
- 1: 일부 실패, 미지원, 도구 부재 또는 full/custom 불완전
- 2: 입력·설정 오류
- 130: 사용자 취소, 이미 커밋한 결과 보존
- 일반 텍스트 검색을 위해 안전하게 읽은 줄 전체를 Event로 저장하므로 대형 로그는
  DB가 커질 수 있다. quick 기본 100,000레코드/30초 예산으로 제한한다.
- PCAP은 필드 요약만 제공한다. TCP 스트림 완전 재조립과 객체 추출은 하지 않는다.
- HTML 보고서는 Phase 2이며 현재 `--format html`은 exit 2와 준비 중 안내를 낸다.
- 빠른 결과를 막지 않기 위해 SHA-256이 잠시 `pending`일 수 있다. 완료 thread는
  generation이 일치할 때만 현재 source 상태를 갱신한다.

## Claude 다음 작업 우선순위

1. 이 문서의 실제 TShark integration을 준비된 Ubuntu/WSL 장비에서 실행하고 버전과
   결과를 기록한다.
2. Phase 1 회귀를 유지한 채 실제 메뉴 사용에서 발견되는 기반 결함부터 수정한다.
3. Phase 2의 EVTX/Sysmon 분석과 합성 정답 fixture를 추가한다.
4. TShark 엔진을 이용한 TCP 스트림 보기와 제한된 객체 추출을 추가하되 불완전 복원을
   표시하고 추출물을 실행하지 않는다.
5. 제한된 Base64/Hex/URL 디코딩, 교차 자료 검색, escape된 오프라인 HTML 보고서를
   구현한다.
6. Phase 3에서 1GB급 메모리/시간, 손상 파일, disk full, SQLite 잠금, Kali와 완전
   오프라인 반입 리허설을 수행한다.

계약 변경이 필요하면 `AGENTS.md` 규칙대로 이유·영향·마이그레이션을 먼저 문서화한다.
