# FieldTrace

FieldTrace는 CTF 대회장에서 받은 패킷과 로그를 완전 오프라인으로 분석하는
한국어 CLI입니다. 파일을 번호로 고르고 추천 분석을 실행한 뒤, 후보의 원문과
줄·패킷 위치까지 돌아가는 흐름을 우선합니다.

현재 Phase 1은 일반 텍스트, Apache/Nginx Common·Combined 로그, 대표
OpenSSH·sudo 로그와 TShark 기반 PCAP/PCAPNG 요약을 지원합니다. EVTX,
TCP 스트림 재조립·객체 추출, HTML 보고서는 후속 단계입니다.

## 지원 환경

- Ubuntu 24.04 또는 WSL2 Ubuntu, Python 3.12
- 준비 단계의 `uv`; 패킷 분석에는 `tshark`
- 분석 실행 중 인터넷, DNS 조회, AI API, 자동 업데이트를 사용하지 않음

Windows 네이티브와 macOS는 초기 지원 범위가 아닙니다. Kali는 아직 별도
검증이 필요합니다.

## 온라인 준비

저장소를 내려받고 인터넷을 사용할 수 있는 준비 환경에서 실행합니다.

```bash
uv sync --frozen --all-groups
./run.sh doctor
```

Ubuntu에서 패킷도 분석하려면 대회 전에 TShark와 시스템 의존성을 별도로
설치합니다.

```bash
sudo apt update
sudo apt install tshark
./run.sh doctor
```

FieldTrace는 실시간 캡처 권한이 필요하지 않습니다. 설치 질문에서 일반 사용자의
캡처 권한을 굳이 켤 필요가 없습니다.

## 실행

분석할 파일을 `input/`에 복사하고 메뉴를 엽니다. `input/`이 없거나 비어 있으면
다른 폴더나 붙여넣은 경로를 선택할 수 있습니다.

```bash
./run.sh
```

메뉴는 `Enter` 추천, 숫자 선택, `0` 뒤로, `q` 종료를 사용합니다. 파일명에
공백이나 한글이 있어도 유지하며, 터미널로 드래그해서 붙은 한 쌍의 인용부호는
자동 제거합니다. WSL에서만 `C:\...` 형식 경로를 `/mnt/c/...`로 변환합니다.

명령으로 자동화할 수도 있습니다.

```bash
./run.sh analyze ./input --profile quick --case ./cases/demo
./run.sh analyze './input/access log' --type web --case ./cases/demo
./run.sh search --case ./cases/demo --text 'example.test'
./run.sh timeline --case ./cases/demo
./run.sh report --case ./cases/demo --format markdown
```

보고서는 Markdown, JSON, CSV를 지원합니다. 입력 원본은 열어 읽기만 하며 결과는
기본적으로 `cases/<시각>-<짧은ID>/`의 DB, `reports/`, `derived/`,
`diagnostics/`에 저장됩니다.

## 오프라인 반입 준비

대상 장비와 같은 OS·아키텍처·Python 버전의 온라인 장비에서 wheelhouse를
만듭니다. 다른 환경에서 만든 `.venv` 폴더를 그대로 복사하는 방식은 지원하지
않습니다.

```bash
./scripts/export-requirements.sh requirements.lock.txt
uv build
python3 -m pip download --only-binary=:all: \
  --requirement requirements.lock.txt --dest wheelhouse
cp dist/fieldtrace_ctf-*.whl wheelhouse/
```

저장소, `wheelhouse/`, TShark 시스템 패키지와 의존성을 반입합니다. 오프라인
장비에서는 새 가상환경을 만들어 로컬 wheel만 설치합니다.

```bash
python3 -m venv .venv
.venv/bin/pip install --no-index --find-links wheelhouse fieldtrace-ctf
./run.sh doctor
```

`python3 -m venv`가 없다면 대상 OS용 `python3.12-venv`도 미리 준비해야 합니다.
TShark는 Python wheel이 아니므로 OS 패키지와 라이브러리를 별도로 반입합니다.

## 개발 검증

```bash
uv run pytest
uv run ruff check .
```

실제 TShark 통합 검증은 `tshark`가 설치된 환경에서만 성공으로 간주합니다.
자세한 구조는 `docs/ARCHITECTURE.md`, 현장 흐름은 `docs/FIELD_GUIDE.md`,
현재 구현과 알려진 한계는 `docs/HANDOFF.md`를 참고하세요.

