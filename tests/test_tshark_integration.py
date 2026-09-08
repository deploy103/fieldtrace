from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from fieldtrace.core import FieldTraceService


@pytest.mark.integration
def test_real_tshark_packet_fixtures(tmp_path: Path) -> None:
    if shutil.which("tshark") is None:
        pytest.skip("실제 TShark가 설치되지 않아 패킷 통합 검증을 수행하지 않음")
    dns_encoded = Path("tests/fixtures/dns-query.pcap.hex").read_text(encoding="ascii")
    dns_pcap = tmp_path / "dns-query.pcap"
    dns_pcap.write_bytes(bytes.fromhex(dns_encoded))
    dns_case = tmp_path / "dns-case"
    service = FieldTraceService()

    dns_summary = service.analyze(dns_pcap, case_dir=dns_case, profile="full")
    dns_hits = service.search(dns_case, "challenge.example.test")
    dns_bundle = service.report_bundle(dns_case)

    assert not dns_summary.partial
    dns = next(event for event in dns_bundle["events"] if event["category"] == "network.dns_query")
    assert dns["fields"]["query"] == "challenge.example.test"
    assert dns["evidence_locator"] == "frame:1"
    assert dns_hits

    http_encoded = Path("tests/fixtures/http-request.pcapng.hex").read_text(encoding="ascii")
    http_pcapng = tmp_path / "http-request.pcapng"
    http_pcapng.write_bytes(bytes.fromhex(http_encoded))
    http_case = tmp_path / "http-case"

    http_summary = service.analyze(http_pcapng, case_dir=http_case, profile="full")
    http_hits = service.search(http_case, "FLAG{pcapng_http}")
    http_bundle = service.report_bundle(http_case)

    assert not http_summary.partial
    http = next(
        event for event in http_bundle["events"] if event["category"] == "network.http_request"
    )
    assert http["src_ip"] == "192.0.2.10"
    assert http["src_port"] == 49152
    assert http["dst_ip"] == "198.51.100.80"
    assert http["dst_port"] == 80
    assert http["fields"]["method"] == "GET"
    assert http["fields"]["host"] == "challenge.example.test"
    assert http["fields"]["uri_raw"] == "/FLAG%7Bpcapng_http%7D"
    assert http["fields"]["uri_decoded"] == "/FLAG{pcapng_http}"
    assert http["evidence_locator"] == "frame:1"
    assert http_hits

    stream_case = tmp_path / "stream-case"
    stream_summary = service.analyze(
        http_pcapng,
        case_dir=stream_case,
        profile="custom",
        selected_tasks=("tcp_streams",),
    )
    stream_bundle = service.report_bundle(stream_case)
    stream = next(
        event for event in stream_bundle["events"] if event["category"] == "network.tcp_stream"
    )
    assert not stream_summary.partial
    assert stream["evidence_locator"] == "tcp.stream:0"
    assert stream["fields"]["reassembly_engine"] == "tshark follow,tcp,ascii"
    assert "GET /FLAG%7Bpcapng_http%7D HTTP/1.1" in stream["fields"]["stream_preview"]
