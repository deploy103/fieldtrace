from __future__ import annotations

import os
from pathlib import Path

import pytest

from fieldtrace.core import FieldTraceService


@pytest.mark.integration
def test_python_evtx_public_issue_38_fixture(tmp_path: Path) -> None:
    value = os.environ.get("FIELDTRACE_EVTX_ISSUE38_FIXTURE")
    if not value:
        pytest.skip("공개 issue_38.evtx 경로를 환경 변수로 지정하지 않아 통합 검증 생략")
    fixture = Path(value).resolve()
    if not fixture.is_file():
        pytest.fail(f"FIELDTRACE_EVTX_ISSUE38_FIXTURE 파일을 찾을 수 없음: {fixture}")
    service = FieldTraceService()
    case = tmp_path / "evtx-case"

    summary = service.analyze(fixture, case_dir=case, profile="full")
    bundle = service.report_bundle(case)
    event = next(item for item in bundle["events"] if item["fields"]["event_id"] == 4672)

    assert not summary.partial
    assert event["fields"]["provider"] == "Microsoft-Windows-Security-Auditing"
    assert event["fields"]["channel"] == "Security"
    assert event["fields"]["record_id"] == "17845"
    assert event["timestamp_utc"] == "2017-06-23T05:31:19.787264+00:00"
    assert event["evidence_locator"] == "channel:Security;record:17845"
    assert service.search(case, "0x000000000019d3af")
