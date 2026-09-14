# FieldTrace

FieldTrace는 CTF 대회장에서 전달받은 패킷, 로그, Windows 이벤트 같은 디지털
증거를 **인터넷 연결 없이 분석하는 한국어 CLI 도구**입니다. 사용자가 이벤트 ID,
TShark 필터, 정규식 또는 SQL을 외우지 않아도 파일을 선택하고 추천 분석을 실행한 뒤
답 후보와 원본 근거 위치까지 확인하는 흐름을 제공합니다.

현재 릴리스는 [v0.1.0](https://github.com/deploy103/fieldtrace/releases/tag/v0.1.0)입니다.
저장소가 private이므로 접근 권한이 있는 GitHub 계정으로 로그인해야 릴리스와 소스를
받을 수 있습니다.

> 분석 결과에서 정답이 바로 보이지 않으면
> [오프라인 문제풀이 플레이북](index.html)을 여세요. 결과 0건, 후보 폭증, 부분 분석,
> 인코딩·조각난 값·Blind SQL 재구성과 정답 제출 전 검증 절차를 증상별로 안내합니다.
> 파일을 내려받은 뒤 브라우저에서 `index.html`을 열면 외부 네트워크 없이 작동합니다.

## 주요 특징

- 인자 없이 실행하면 시작되는 한국어 숫자 메뉴
- 파일 확장자뿐 아니라 magic과 제한된 내용 표본을 이용한 형식 감지
- 일반 텍스트, 웹 접근 로그, Linux 인증 로그, PCAP/PCAPNG, EVTX 분석
- 플래그 형태 문자열, IP, 도메인, 계정, 명령, HTTP 요청 후보 추출
- 제한된 Base64, Hex, URL 디코딩과 변환 과정·원본 위치 보존
- 여러 자료에 반복해서 나타난 IP, 도메인, 계정, 파일명 교차 확인
- 사건별 SQLite 저장소와 시간순 보기, 원문 근거 조회
- Markdown, JSON, CSV, 자체 포함 HTML 보고서
- 원본 읽기 전용, 분석 중 외부 인터넷·DNS 조회·AI API 미사용
- 중단된 분석 복구, 단일 writer 잠금, 원자적 보고서 저장과 현장 오류 안내

## 목차

- [지원 환경](#지원-환경)
- [지원 형식과 분석 범위](#지원-형식과-분석-범위)
- [기술 스택](#기술-스택)
- [설치](#설치)
- [5분 빠른 시작](#5분-빠른-시작)
- [메뉴 사용법](#메뉴-사용법)
- [CLI 사용법](#cli-사용법)
- [설정](#설정)
- [결과와 증거 확인](#결과와-증거-확인)
- [오프라인 반입 준비](#오프라인-반입-준비)
- [문제 해결](#문제-해결)
- [보안과 데이터 처리 원칙](#보안과-데이터-처리-원칙)
- [개발과 검증](#개발과-검증)
- [알려진 제약](#알려진-제약)
- [문제풀이 플레이북](index.html)

## 지원 환경

| 항목 | 상태 |
| --- | --- |
| Ubuntu 24.04 | 지원 및 검증 |
| WSL2 Ubuntu 24.04 | 지원 및 검증 |
| Python | 3.12 기준 검증, 패키지 허용 범위는 3.12 이상 3.14 미만 |
| TShark | 패킷 분석 시 필요, 실제 4.2.2로 통합 검증 |
| Windows 네이티브 | 초기 지원 범위 밖 |
| macOS | 초기 지원 범위 밖 |
| Kali Linux | 아직 별도 검증하지 않음 |

텍스트와 EVTX 분석에는 실시간 캡처 권한이 필요하지 않습니다. TShark도 FieldTrace
안에서는 저장된 PCAP/PCAPNG 파일만 읽으며 라이브 캡처를 수행하지 않습니다.

## 지원 형식과 분석 범위

| 입력 형식 | 주요 분석 내용 | 재현 가능한 근거 위치 | 추가 도구 |
| --- | --- | --- | --- |
| 일반 텍스트 | IP, 도메인, 플래그 형태 문자열, 제한 디코딩 | 줄 번호 | 없음 |
| Apache/Nginx 로그 | Common/Combined 형식의 IP, 시각, method, URI, status, bytes와 HTTP 검토 후보 | 줄 번호 | 없음 |
| OpenSSH/sudo 로그 | 로그인 성공·실패, 사용자, 원격 IP, sudo 실행 명령 | 줄 번호 | 없음 |
| PCAP/PCAPNG | 패킷·프로토콜·IP·port·DNS·평문 HTTP 요약, TCP 대화 보기, HTTP 본문 추출 | frame 번호 또는 TCP stream 번호 | TShark |
| Windows EVTX/Sysmon | 로그인, 프로세스 생성, 네트워크 연결, PowerShell, 서비스 등록 | channel과 record ID | python-evtx |

EVTX는 provider와 channel이 맞는 경우에만 대표 이벤트를 의미별로 분류합니다.
현재 주요 대상은 Security 4624/4625/4688, Sysmon 1/3, PowerShell 4104,
Service Control Manager 7045입니다. 이벤트 ID만 같다고 같은 의미로 단정하지
않습니다.

DNS의 긴 질의·높은 반복 빈도와 HTTP의 경로 이동·민감 경로·SQL/명령 형태는
**검토 후보**로 표시합니다. 후보는 공격 성공, 침입 또는 CTF 정답 확정을 뜻하지
않으며 반드시 함께 표시된 원문 근거를 확인해야 합니다.

## 기술 스택

| 구분 | 기술 | 역할 |
| --- | --- | --- |
| 언어 | Python 3.12 | 런타임과 스트리밍 분석 |
| CLI | Typer | 명령어, 옵션, 종료 코드 |
| 터미널 출력 | Rich | 표, 진행 상태, 안전한 한국어 출력 |
| 사례 저장소 | 표준 sqlite3 | source, run, event, finding, artifact, diagnostic 저장 |
| 검색 | SQLite FTS5 | 사용할 수 없으면 LIKE 기반 literal 검색으로 저하 동작 |
| 설정 | TOML, 표준 tomllib | 분석 예산, 경로, 시간대, 플래그 패턴 |
| 데이터 계약 | dataclasses, typing, Protocol | 분석기와 core 사이의 명시적 타입 계약 |
| 패킷 엔진 | TShark subprocess | PCAP/PCAPNG 디섹션과 TCP follow |
| EVTX 엔진 | python-evtx | Windows EVTX 레코드와 XML 읽기 |
| 보고서 | Python 표준 라이브러리 | Markdown, JSON, CSV, escape된 HTML 생성 |
| 패키지 관리 | uv, uv.lock, Hatchling | 재현 가능한 개발 환경과 wheel/sdist 빌드 |
| 품질 검사 | pytest, Ruff | 회귀 테스트와 정적 검사 |

코드는 다음 책임 경계를 유지합니다.

```text
src/fieldtrace/
├── cli.py          # Typer 진입점과 계층 조립
├── ui/             # 메뉴와 화면 출력
├── core/           # 사례, 실행, DB, 검색, 진단, 상태
├── analyzers/      # text, web, auth, pcap, evtx 분석기
└── reports/        # Markdown/JSON/CSV/HTML 내보내기
```

UI는 SQL이나 subprocess를 직접 실행하지 않고, 분석기는 Rich 출력에 의존하지
않습니다. 분석기 등록 목록은 코드에 명시되어 있으며 임의의 Python 파일을 플러그인으로
자동 실행하지 않습니다.

## 설치

### 1. Ubuntu/WSL 기본 도구

Ubuntu 24.04 또는 WSL2 Ubuntu의 인터넷 가능한 준비 환경에서 Python 3.12,
가상환경 모듈, Git을 설치합니다.

```bash
sudo apt update
sudo apt install -y python3.12 python3.12-venv git
python3.12 --version
```

패킷을 분석할 계획이라면 TShark도 설치합니다.

```bash
sudo apt install -y tshark
tshark --version
```

TShark 설치 중 일반 사용자에게 패킷 캡처 권한을 줄지 묻는 화면이 나올 수 있습니다.
FieldTrace는 저장된 파일만 분석하므로 라이브 캡처 권한을 활성화할 필요가 없습니다.
조직 정책과 대회 규정을 우선하세요.

EVTX용 `python-evtx`, CLI용 Typer/Rich는 아래 설치 과정에서 Python 의존성으로
함께 설치되므로 별도 apt 설치가 필요하지 않습니다.

### 2. 소스와 uv로 설치

개발, 테스트, 오프라인 wheelhouse 준비까지 할 때 권장하는 방식입니다. `uv`가 없다면
인터넷 가능한 준비 환경에서 [uv 공식 설치 안내](https://docs.astral.sh/uv/getting-started/installation/)를
따르거나 다음 공식 standalone installer를 사용합니다.

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

설치 프로그램이 안내한 PATH 설정을 적용하거나 새 터미널을 연 뒤 `uv --version`으로
확인합니다. 그다음 private 저장소의 릴리스 태그를 내려받고 잠금 파일 그대로 환경을
만듭니다.

```bash
git clone --branch v0.1.0 --depth 1 git@github.com:deploy103/fieldtrace.git
cd fieldtrace
uv sync --frozen --all-groups
./run.sh doctor
```

`uv sync`는 저장소의 `.venv/`를 준비합니다. `run.sh`는 이 환경을 사용하기만 하며
분석 시작 시 패키지 설치, 업데이트 또는 네트워크 접근을 자동 수행하지 않습니다.

### 3. GitHub Release wheel로 설치

소스 개발 도구가 필요 없다면 릴리스의 wheel을 설치할 수 있습니다. private 저장소
접근 권한과 [GitHub CLI](https://cli.github.com/)가 있는 경우 다음처럼 받습니다.

```bash
sudo apt install -y gh
gh auth login
mkdir fieldtrace-v0.1.0
cd fieldtrace-v0.1.0
gh release download v0.1.0 \
  --repo deploy103/fieldtrace \
  --pattern 'fieldtrace_ctf-0.1.0*' \
  --pattern 'SHA256SUMS.txt'
sha256sum -c SHA256SUMS.txt
```

인터넷 가능한 준비 환경에서는 wheel의 호환 의존성을 함께 받을 수 있습니다.

```bash
python3.12 -m venv .venv
.venv/bin/pip install ./fieldtrace_ctf-0.1.0-py3-none-any.whl
.venv/bin/python -c 'import fieldtrace; print(fieldtrace.__version__)'
.venv/bin/fieldtrace doctor
```

wheel만 설치한 경우 실행 명령은 `.venv/bin/fieldtrace`입니다. 아래 예시의
`./run.sh`를 `.venv/bin/fieldtrace`로 바꾸면 됩니다. 의존성까지 인터넷 없이
설치하려면 [오프라인 반입 준비](#오프라인-반입-준비)를 따르세요.

## 5분 빠른 시작

### 메뉴로 합성 샘플 분석

소스 설치 기준으로 환경을 진단하고 메뉴를 엽니다.

```bash
./run.sh doctor
./run.sh menu ./samples
```

화면에서 다음 순서로 진행합니다.

1. `generic.txt`, `access.log`, `auth.log` 중 파일 번호를 입력합니다.
2. 분석 방법 화면에서 `Enter`를 눌러 추천 빠른 분석을 실행합니다.
3. 결과의 주목할 후보 번호를 골라 줄 번호와 원문을 확인합니다.
4. 결과 메뉴의 `검색`, `시간순 보기`, `보고서 저장`을 사용합니다.
5. 어느 화면에서든 `0`은 뒤로, `q`는 종료입니다.

### 명령 한 번으로 분석

```bash
./run.sh analyze ./samples --profile full --case ./cases/demo
./run.sh search --case ./cases/demo --text 'FLAG{'
./run.sh timeline --case ./cases/demo
./run.sh report --case ./cases/demo --format html
```

마지막 명령은 기본적으로
`cases/demo/reports/fieldtrace-report.html`을 만듭니다.

## 메뉴 사용법

인자 없는 `./run.sh` 또는 설치된 `fieldtrace`를 실행하면 전체 화면 TUI가 아닌
일반 입력 기반 숫자 메뉴가 열립니다. SSH, WSL, 컬러가 없는 터미널에서도 같은
방식으로 사용할 수 있습니다.

```bash
./run.sh
```

- 기본 탐색 위치는 `./input`입니다.
- 다른 폴더를 입력하거나 파일 경로를 직접 붙여넣을 수 있습니다.
- 한글과 공백은 보존하고, 양끝에 짝이 맞는 따옴표만 제거합니다.
- WSL에서 받은 `C:\Users\...` 경로는 존재 여부를 확인해 `/mnt/c/Users/...`로
  변환합니다.
- 파일 화면의 `d`를 누르면 Python, 의존성, TShark, 사례 저장소와 디스크 상태를
  바로 진단합니다.
- 분석 방법에서 `Enter`는 추천 빠른 분석, `1`은 전체 분석, `2`는 분석 항목 직접
  선택, `3`은 기존 결과 열기입니다.
- 직접 선택 항목은 `IP·도메인 요약`, `HTTP 요청`, `로그인 성공/실패`,
  `실행 명령`, `플래그·문자열 찾기`입니다.
- 분석 중 `Ctrl+C`를 누르면 취소하고 이미 커밋된 부분 결과를 보존합니다.
- 결과는 요약 → 주목할 후보 → 원문 근거 순서로 확인합니다.

## CLI 사용법

모든 명령과 옵션은 다음 도움말로 확인할 수 있습니다.

```bash
./run.sh --help
./run.sh analyze --help
./run.sh report --help
```

### 환경 진단

```bash
./run.sh doctor
```

Python과 필수 패키지, `python-evtx`, TShark, 사례 폴더 쓰기, SQLite WAL
트랜잭션과 여유 디스크를 확인합니다. TShark가 없어도 텍스트와 EVTX 분석은
계속 사용할 수 있습니다.

### 파일 또는 폴더 분석

```bash
./run.sh analyze <파일 또는 폴더> [추가 경로 ...] \
  --profile quick|full|custom \
  --case <사례 폴더> \
  --type text|web|linux_auth|pcap|evtx \
  --tasks <항목 키,항목 키> \
  --encoding <문자 인코딩>
```

폴더를 지정하면 하위 일반 파일을 재귀적으로 수집합니다. 사례 출력 폴더는 입력
대상에서 제외합니다. `--type`을 생략하면 제한된 표본의 magic과 내용으로 형식을
감지하고, 확신할 수 없을 때는 메뉴에서 수동 형식을 선택할 수 있습니다.

분석 프로필은 다음과 같습니다.

| 프로필 | 동작 |
| --- | --- |
| `quick` | 기본 30초 또는 100,000레코드 안에서 빠른 최초 결과를 만듦 |
| `full` | 선택 형식에서 구현되어 있고 사용할 수 있는 기본 분석을 모두 실행 |
| `custom` | `--tasks`로 지정한 항목만 실행 |

`quick`이 예산에 도달하면 실패로 위장하지 않고 `coverage=partial`과 제한 이유를
저장합니다. `full`은 기본 분석을 뜻하며 PCAP 객체 추출 같은 상세 작업은
`custom`으로 명시하는 것이 안전합니다.

사용 가능한 `--tasks` 키는 다음과 같습니다.

| 키 | 화면 이름 |
| --- | --- |
| `network_summary` | IP·도메인 요약 |
| `http_requests` | HTTP 요청 |
| `login_activity` | 로그인 성공/실패 |
| `executed_commands` | 실행 명령 |
| `literal_search` | 플래그·문자열 찾기 |
| `tcp_streams` | TCP 대화 재조립 보기 |
| `object_extraction` | HTTP 본문 파일 추출 |

예시:

```bash
# 빠른 자동 감지
./run.sh analyze ./input --profile quick --case ./cases/quick

# 공백이 있는 웹 로그를 수동 형식으로 분석
./run.sh analyze './input/access log.txt' \
  --type web --profile full --case ./cases/web

# 오래된 CP949 텍스트
./run.sh analyze './input/레거시 로그.txt' \
  --type text --encoding cp949 --case ./cases/legacy

# 여러 자료를 한 사례에 분석
./run.sh analyze ./input/auth.log ./input/access.log \
  --profile full --case ./cases/mixed

# PCAP TCP 대화와 HTTP 본문 추출
./run.sh analyze ./input/capture.pcapng \
  --type pcap --profile custom \
  --tasks tcp_streams,object_extraction \
  --case ./cases/packet-detail

# EVTX 전체 기본 분석
./run.sh analyze ./input/Security.evtx \
  --type evtx --profile full --case ./cases/windows
```

### literal 검색

```bash
./run.sh search \
  --case ./cases/demo \
  --text 'example.test' \
  --limit 100
```

검색어를 쿼리 문법으로 해석하지 않고 literal 문자열로 찾습니다. SQLite FTS5가
있으면 후보 검색을 가속하지만 최종 결과는 실제 부분 문자열 포함 여부를 다시
확인합니다. FTS5가 없으면 LIKE 검색으로 자동 저하됩니다.

### 시간순 보기

```bash
./run.sh timeline --case ./cases/demo --limit 1000
```

원시 시각, 정규화 가능한 UTC, 분류, 요약, 증거 위치를 표시합니다. 시간대나 연도가
없는 시각은 조용히 UTC로 단정하지 않고 `시간 미상` 영역에 분리합니다.

### 여러 자료 교차 확인

```bash
./run.sh correlate --case ./cases/demo
./run.sh correlate --case ./cases/demo --kind ip --min-sources 2
./run.sh correlate --case ./cases/demo \
  --kind domain --value example.test --limit 100
```

지원 종류는 `ip`, `domain`, `account`, `filename`입니다. 둘 이상의 source에서
같은 값이 관측됐다는 사실을 묶을 뿐, 인과관계나 동일 행위자임을 확정하지 않습니다.

### 보고서 저장

```bash
./run.sh report --case ./cases/demo --format markdown
./run.sh report --case ./cases/demo --format json
./run.sh report --case ./cases/demo --format csv
./run.sh report --case ./cases/demo --format html
./run.sh report --case ./cases/demo \
  --format html --output ./reports/demo.html
```

- Markdown은 사람이 읽기 쉬운 요약과 근거를 제공합니다.
- JSON은 구조화된 원문 필드를 보존하는 자동화용 형식입니다.
- CSV는 스프레드시트 수식 주입을 막기 위해 위험한 셀 앞에 작은따옴표를 붙입니다.
- HTML은 외부 CDN, 폰트, 이미지 없이 동작하고 동적 값과 원문을 escape합니다.

## 설정

기본 설정은 `configs/default.toml`입니다. 다른 파일을 사용하려면 전역
`--config` 옵션을 하위 명령보다 앞에 둡니다.

```bash
./run.sh --config ./configs/contest.toml doctor
./run.sh --config ./configs/contest.toml analyze ./input --profile quick
```

예시 설정:

```toml
[analysis]
quick_seconds = 30
quick_records = 100000
batch_size = 250
max_line_bytes = 1048576
max_preview_chars = 500
command_timeout_seconds = 120
command_output_bytes = 8388608

[paths]
input = "input"
cases = "cases"

[time]
default_timezone = "Asia/Seoul"
default_year = 2026

[patterns]
flag_prefixes = ["FLAG", "flag", "CTF", "ctf"]
decode_max_depth = 2
decode_max_output_chars = 4096
decode_max_candidates = 20
```

시간대와 연도는 자료의 출처가 명확할 때만 지정하세요. FieldTrace는 원시 시각,
적용한 오프셋, 정규화 UTC와 추정 여부를 함께 저장합니다. 플래그 접두사는 중괄호를
제외한 1~64자 문자열이어야 합니다.

## 결과와 증거 확인

`--case`를 생략하면 기본적으로 실행 위치의
`cases/<YYYYMMDD-HHMMSS>-<짧은ID>/`에 새 사례를 만듭니다. 명시한 사례를 다시
사용하면 기존 run을 지우지 않고 새 run으로 추가하며 일반 화면은 각 source의 최신
run을 기준으로 집계합니다.

```text
cases/demo/
├── fieldtrace.sqlite3   # source, run, event, finding, artifact, diagnostic
├── reports/             # Markdown, JSON, CSV, HTML
├── derived/             # 사용자가 요청한 HTTP 본문 등 파생 파일
├── diagnostics/         # 상세 오류와 traceback
└── .analysis.lock       # 동일 사례 분석의 단일-writer 잠금
```

증거 위치는 자료 형식에 맞게 저장됩니다.

- 텍스트, 웹, 인증 로그: `line:3`
- 패킷: `frame:42`
- TCP 대화: `tcp.stream:0`
- EVTX: `channel:Security;record:17845`

원본 preview가 제한 길이를 넘으면 잘림 여부를 함께 기록합니다. 입력 파일 SHA-256은
스트리밍으로 계산하고, 취소된 해시는 완료 값으로 표시하지 않습니다. 원본의
size/mtime이 분석 도중 바뀌면 결과에 경고를 남깁니다.

## 오프라인 반입 준비

wheelhouse는 **실제 사용할 장비와 같은 OS, CPU 아키텍처, Python 버전**의 인터넷
가능한 준비 장비에서 만드세요. 다른 컴퓨터에서 만든 `.venv` 폴더를 그대로 복사하는
방식은 지원하지 않습니다.

### 1. 온라인 준비 장비

```bash
uv sync --frozen --all-groups
./scripts/prepare-wheelhouse.sh ./wheelhouse
```

이 스크립트는 다음을 수행합니다.

1. `uv.lock` 상태를 검사합니다.
2. 런타임 의존성의 pip 호환 잠금 목록을 만듭니다.
3. FieldTrace wheel을 빌드합니다.
4. wheel이 배포되지 않은 잠긴 의존성도 온라인 단계에서 wheel로 빌드합니다.

가능하면 같은 장비에서 네트워크 namespace를 분리한 리허설도 실행합니다.

```bash
sudo apt install -y util-linux
./scripts/rehearse-offline.sh ./wheelhouse
```

리허설은 새 venv에서 네트워크를 차단한 뒤 `pip --no-index` 설치, `doctor`, 합성
로그 분석, `FLAG{` 검색, 자체 포함 HTML 보고서 생성을 확인합니다. user/network
namespace를 만들 권한이 없으면 완료로 간주하지 않고 종료합니다.

### 2. 반입

다음을 함께 복사합니다.

- `v0.1.0` 소스 또는 저장소
- 준비한 `wheelhouse/`
- 대상 배포판용 TShark 패키지와 모든 시스템 의존성
- 필요하다면 대상 배포판용 `python3.12-venv`

TShark는 Python wheel이 아니므로 `wheelhouse/`에 포함되지 않습니다. 오프라인용
OS 패키지는 대상 Ubuntu/Kali 버전에 맞는 공식 패키지 저장소나 사내 미러에서
별도로 준비해야 합니다.

### 3. 오프라인 장비

```bash
python3.12 -m venv .venv
.venv/bin/pip install \
  --no-index \
  --find-links ./wheelhouse \
  fieldtrace-ctf
./run.sh doctor
```

`doctor`에서 필요한 기능이 정상인지 확인한 뒤 네트워크를 연결하지 않은 상태로
분석합니다.

## 종료 코드

비대화형 자동화에서는 다음 종료 코드를 사용합니다.

| 코드 | 의미 |
| --- | --- |
| `0` | 요청한 범위 성공 또는 의도한 quick 예산 도달 |
| `1` | 일부 실패, 지원 기능 누락, 제한으로 불완전 |
| `2` | 입력 경로, 설정, 옵션 오류 |
| `130` | 사용자 취소 |

`quick` 예산 도달은 종료 코드 0일 수 있지만 DB의 `coverage`에는 `partial`로
기록됩니다. 자동화에서 종료 코드와 분석 범위를 함께 확인하세요.

## 문제 해결

| 증상 | 이유 | 다음 행동 |
| --- | --- | --- |
| `run.sh`가 `.venv`를 찾지 못함 | 준비 환경이 없음 | 인터넷 가능한 환경에서 `uv sync --frozen --all-groups` 실행 |
| TShark를 찾을 수 없음 | 시스템 패키지 미설치 또는 PATH 문제 | `sudo apt install tshark`, `tshark --version`, `doctor` 확인 |
| PCAP만 분석되지 않음 | TShark 누락 또는 필요한 field 미지원 | `doctor`의 버전·필드 진단 확인, 텍스트 분석은 계속 가능 |
| EVTX를 읽을 수 없음 | 권한, 손상, python-evtx 문제 | 읽기 가능한 복사본을 만들고 `doctor`와 diagnostics 확인 |
| WSL의 Windows EVTX 접근 거부 | Windows 로그 파일 권한 | 권한을 우회하지 말고 사용자가 읽을 수 있는 복사본을 입력으로 사용 |
| 인코딩 감지 실패 | BOM이 없거나 레거시 인코딩 | `--encoding cp949` 또는 메뉴의 수동 인코딩 선택 |
| 사례가 사용 중 | 같은 사례에 다른 분석 writer 실행 중 | 다른 분석을 완료·취소한 뒤 재실행 |
| SQLite 잠김/읽기 전용 | 다른 DB 작업 또는 권한 문제 | SQLite 뷰어를 닫고 사례 폴더 쓰기 권한 확인 |
| 디스크 부족 | DB, 보고서, 파생 파일을 저장할 공간 부족 | 사례 폴더가 있는 디스크 공간 확보 후 재실행 |
| 이전 run이 `running` | 강제 종료 또는 프로세스 중단 | 다음 분석이 부분 실패로 복구한 뒤 새 run으로 재분석 |
| `부분 분석` 표시 | quick 예산, 손상 줄, 도구·용량 제한 | 완료 화면의 실패·생략 이유를 확인하고 필요하면 full 실행 |
| 오프라인 리허설의 `unshare` 실패 | user/network namespace 권한 없음 | 정책을 확인하고 격리 가능한 동일 환경에서 다시 검증 |

화면에는 실패 단계, 짧은 이유와 다음 행동을 표시합니다. traceback과 상세 진단은
사례의 `diagnostics/`를 확인하세요.

## 보안과 데이터 처리 원칙

- 입력 증거는 읽기 전용으로 열며 원본을 수정하지 않습니다.
- 분석 문자열을 명령으로 실행하지 않습니다.
- 활성 스캔, 익스플로잇, 실시간 캡처, 추출 파일 자동 실행을 하지 않습니다.
- 분석 중 인터넷, AI API, 외부 DNS, 자동 업데이트, 원격 리소스를 사용하지 않습니다.
- TShark는 이름 해석을 끈 `-n -r <파일>` 방식으로 실행합니다.
- 외부 명령은 인자 배열과 `shell=False`, timeout, 출력 제한, 취소 시 자식 정리를
  적용합니다.
- 터미널 제어 문자와 Rich 마크업은 화면에서 무해하게 만들고, HTML 원문은
  escape합니다.
- 보고서와 파생 파일은 `.part`에 완전히 쓴 뒤 `fsync`하고 원자적으로 교체합니다.
- 같은 사례에는 분석 writer 하나만 허용하며 검색과 보고서 읽기는 별도로 사용할 수
  있습니다.

FieldTrace의 결과는 관측과 검토 후보입니다. 침입 여부나 CTF 정답은 원본 증거,
문제 문맥과 다른 자료를 함께 검토해 판단하세요.

## 개발과 검증

개발 의존성까지 동기화하고 기본 검사를 실행합니다.

```bash
uv lock --check
uv sync --frozen --all-groups
uv run ruff check .
uv run pytest -q
uv run python -m compileall -q src/fieldtrace scripts
bash -n run.sh scripts/*.sh
git diff --check
```

실제 TShark 또는 외부 EVTX fixture가 없는 테스트의 skip을 해당 포맷 검증 완료로
간주하지 않습니다. `v0.1.0`은 기본 환경에서 `79 passed, 2 skipped`, 실제
TShark 4.2.2와 공개 EVTX fixture를 함께 지정한 환경에서 `81 passed`를 확인했습니다.

대형 합성 입력은 다음 스크립트로 재측정할 수 있습니다. 충분한 디스크 공간을
확보하세요.

```bash
uv run python scripts/benchmark-large-log.py --size-gib 1 --rss-limit-mib 512
uv run python scripts/benchmark-large-pcap.py --size-gib 1 --rss-limit-mib 512
```

검증된 WSL2 Ubuntu 환경에서 1 GiB 텍스트는 55.294초와 peak RSS 60.81 MiB,
1.00005 GiB PCAP은 FieldTrace와 TShark 동시 peak의 보수적 합산 상한
209.61 MiB였습니다. 수치는 장비, 저장장치, 입력 내용과 TShark 버전에 따라
달라집니다.

## 알려진 제약

- Kali, Windows 네이티브, macOS는 아직 지원을 확정하지 않았습니다.
- 실제 시스템 TShark 패키지의 여러 버전을 모두 검증하지 않았습니다.
- 대형 손상 EVTX/PCAP과 복잡한 다중 패킷·재전송·누락 fixture는 추가 검증이
  필요합니다.
- TCP 재조립의 재전송·순서·누락 처리는 TShark에 맡기며 완전 복원을 주장하지
  않습니다.
- HTTP 추출은 TShark의 `http.file_data`로 확인되는 본문만 지원합니다.
- 압축 파일 재귀 해제, 라이브 캡처, GUI, 웹 서버, 런타임 LLM은 지원하지 않습니다.
- 매우 큰 사례의 전체 JSON/HTML/CSV 보고서와 상관 결과는 결과 크기만큼 메모리를
  사용할 수 있습니다.

## 문서

- [현장 가이드](docs/FIELD_GUIDE.md)
- [구조와 계약](docs/ARCHITECTURE.md)

## 라이선스

MIT License. 자세한 내용은 [LICENSE](LICENSE)를 확인하세요.
