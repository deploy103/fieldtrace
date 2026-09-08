# FieldTrace 인수인계

이 문서는 Phase 1 최종 검증 뒤 현재 브랜치, 재현 명령과 실제 결과로 갱신합니다.
검증 전 상태를 통과로 추정하지 않습니다.

## 현재 작업

- 브랜치: `feat/codex-foundation`
- 기준 커밋: `5a126fe` (`main` 초기 커밋)
- 대상: `요구사항.md`의 Codex Phase 1과 인수인계 게이트

## 재현 명령

```bash
uv sync --frozen --all-groups
uv run pytest
uv run ruff check .
./run.sh doctor
./run.sh analyze samples --profile quick --case cases/synthetic-check
./run.sh search --case cases/synthetic-check --text 'FLAG{'
./run.sh timeline --case cases/synthetic-check
./run.sh report --case cases/synthetic-check --format json
```

## 검증 결과

구현 통합 뒤 실제 출력으로 갱신 예정입니다. 현재 환경에서 `tshark`는 PATH에 없어
실제 PCAP 통합 검증 완료로 기록할 수 없습니다.

## 후속 범위

EVTX/Sysmon, TCP 스트림 재조립과 객체 추출, 고급 교차 분석, 제한 디코딩,
HTML 보고서, 1GB급 성능·Kali 리허설은 Phase 2 이후 범위입니다. Phase 1 계약이나
재현 흐름을 깨는 결함은 기능 확장 전에 수정합니다.
