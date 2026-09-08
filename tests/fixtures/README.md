# 합성 fixture

`dns-query.pcap.hex`와 `http-request.pcapng.hex`는 실제 사용자 증거가 아닌 1패킷
캡처의 16진수 표현이다. 첫 파일은 classic PCAP의 Ethernet/IPv4/UDP DNS query,
둘째 파일은 PCAPNG의 Ethernet/IPv4/TCP 평문 HTTP GET을 포함한다. 테스트가 임시
폴더에서 캡처로 복원하므로 Git의 실제 증거 제외 규칙을 완화하지 않는다.

예상 정답:

- frame: `1`
- source: `192.0.2.10:53000`
- destination: `198.51.100.53:53`
- DNS query: `challenge.example.test`

HTTP PCAPNG 예상 정답:

- frame: `1`
- source/destination: `192.0.2.10:49152` → `198.51.100.80:80`
- method/host: `GET` / `challenge.example.test`
- URI raw/decoded: `/FLAG%7Bpcapng_http%7D` / `/FLAG{pcapng_http}`

실제 TShark 통합 테스트는 TShark가 없으면 skip된다. 별도의 mock 테스트는 설치
여부와 무관하게 argv의 `-n -r`, DNS 필드와 frame 근거를 검증한다.

EVTX 의미 분류는 `tests/test_evtx.py`의 합성 XML/fake reader로 정답을 고정한다.
실제 바이너리 I/O는 사용자 증거를 저장소에 넣지 않기 위해 추적 fixture와 분리했다.
`tests/test_evtx_integration.py`는 `FIELDTRACE_EVTX_ISSUE38_FIXTURE`에 upstream
`python-evtx` 공개 `issue_38.evtx` 경로를 지정했을 때만 실행되며, 다운로드 방법과
기대 SHA-256은 `docs/HANDOFF.md`에 기록했다.
