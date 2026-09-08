# 합성 fixture

`dns-query.pcap.hex`는 실제 사용자 증거가 아닌 1패킷 classic PCAP의 16진수
표현이다. Ethernet/IPv4/UDP DNS query `challenge.example.test` 하나를 포함한다.
테스트가 임시 폴더에서 `.pcap`으로 복원하므로 Git의 실제 증거 제외 규칙을
완화하지 않는다.

예상 정답:

- frame: `1`
- source: `192.0.2.10:53000`
- destination: `198.51.100.53:53`
- DNS query: `challenge.example.test`

실제 TShark 통합 테스트는 TShark가 없으면 skip된다. 별도의 mock 테스트는 설치
여부와 무관하게 argv의 `-n -r`, DNS 필드와 frame 근거를 검증한다.

