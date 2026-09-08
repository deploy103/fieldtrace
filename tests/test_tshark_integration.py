from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from fieldtrace.core import FieldTraceService


@pytest.mark.integration
def test_real_tshark_dns_fixture(tmp_path: Path) -> None:
    if shutil.which("tshark") is None:
        pytest.skip("실제 TShark가 설치되지 않아 패킷 통합 검증을 수행하지 않음")
    encoded = Path("tests/fixtures/dns-query.pcap.hex").read_text(encoding="ascii")
    pcap = tmp_path / "dns-query.pcap"
    pcap.write_bytes(bytes.fromhex(encoded))
    case = tmp_path / "case"
    service = FieldTraceService()

    summary = service.analyze(pcap, case_dir=case, profile="full")
    hits = service.search(case, "challenge.example.test")
    bundle = service.report_bundle(case)

    assert not summary.partial
    dns = next(event for event in bundle["events"] if event["category"] == "network.dns_query")
    assert dns["fields"]["query"] == "challenge.example.test"
    assert dns["evidence_locator"] == "frame:1"
    assert hits
