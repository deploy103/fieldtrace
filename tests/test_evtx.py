from __future__ import annotations

from pathlib import Path

from fieldtrace.analyzers.evtx import EvtxAnalyzer
from fieldtrace.core.detector import FormatDetector
from fieldtrace.core.models import Diagnostic, Event, Finding, SourceFormat


class FakeRecord:
    def __init__(self, number: int, xml: str) -> None:
        self.number = number
        self.value = xml

    def xml(self) -> str:
        return self.value

    def record_num(self) -> int:
        return self.number


class FakeReader:
    def __init__(self, records: list[FakeRecord]) -> None:
        self._records = records

    def __enter__(self) -> FakeReader:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def records(self):  # type: ignore[no-untyped-def]
        yield from self._records


def reader_factory(records: list[FakeRecord]):  # type: ignore[no-untyped-def]
    return lambda _path: FakeReader(records)


def event_xml(
    *,
    provider: str,
    channel: str,
    event_id: int,
    record_id: int = 12,
    data: str = "",
    timestamp: str = "2026-09-08T05:20:15.125Z",
) -> str:
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{provider}"/>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="{timestamp}"/>
    <EventRecordID>{record_id}</EventRecordID>
    <Channel>{channel}</Channel>
    <Computer>workstation.example.test</Computer>
  </System>
  <EventData>{data}</EventData>
</Event>"""


def test_evtx_magic_detection_ignores_extension(tmp_path: Path) -> None:
    path = tmp_path / "events.txt"
    path.write_bytes(b"ElfFile\x00" + b"\x00" * 32)

    result = FormatDetector((EvtxAnalyzer(reader_factory([])),)).detect(path)

    assert result.format is SourceFormat.EVTX
    assert result.confidence == 1.0
    assert "magic" in result.reason


def test_security_login_preserves_timestamp_fields_and_locator(
    tmp_path: Path, make_context
) -> None:
    path = tmp_path / "Security.evtx"
    path.write_bytes(b"ElfFile\x00")
    xml = event_xml(
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        event_id=4624,
        record_id=77,
        data=(
            '<Data Name="TargetUserName">analyst</Data>'
            '<Data Name="IpAddress">192.0.2.25</Data>'
            '<Data Name="IpPort">55222</Data>'
            '<Data Name="LogonType">10</Data>'
        ),
    )
    analyzer = EvtxAnalyzer(reader_factory([FakeRecord(900, xml)]))

    items = list(analyzer.analyze(make_context(path)))

    event = next(item for item in items if isinstance(item, Event))
    assert event.category == "auth.login_success"
    assert event.user == "analyst"
    assert event.src_ip == "192.0.2.25"
    assert event.timestamp_raw == "2026-09-08T05:20:15.125Z"
    assert event.timestamp_utc == "2026-09-08T05:20:15.125000+00:00"
    assert event.timezone_status == "explicit"
    assert event.fields["LogonType"] == "10"
    assert event.fields["provider"] == "Microsoft-Windows-Security-Auditing"
    assert event.evidence.kind == "evtx"
    assert event.evidence.locator == "channel:Security;record:77"


def test_event_id_without_matching_provider_and_channel_is_not_classified(
    tmp_path: Path, make_context
) -> None:
    path = tmp_path / "Other.evtx"
    path.write_bytes(b"ElfFile\x00")
    xml = event_xml(
        provider="Third-Party-Product",
        channel="Application",
        event_id=4624,
        data='<Data Name="TargetUserName">decoy</Data>',
    )

    event = next(
        item
        for item in EvtxAnalyzer(reader_factory([FakeRecord(12, xml)])).analyze(make_context(path))
        if isinstance(item, Event)
    )

    assert event.category == "evtx.record"
    assert "로그인 성공" not in event.summary


def test_sysmon_process_and_network_fields_are_version_tolerant(
    tmp_path: Path, make_context
) -> None:
    path = tmp_path / "Sysmon.evtx"
    path.write_bytes(b"ElfFile\x00")
    process = event_xml(
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        record_id=31,
        data=(
            '<Data Name="ProcessGuid">{11111111-1111-1111-1111-111111111111}</Data>'
            '<Data Name="Image">C:\\Tools\\runner.exe</Data>'
            '<Data Name="CommandLine">runner.exe --check</Data>'
            '<Data Name="User">LAB\\analyst</Data>'
        ),
    )
    network = event_xml(
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=3,
        record_id=32,
        data=(
            '<Data Name="SourceIp">10.0.0.5</Data>'
            '<Data Name="SourcePort">51515</Data>'
            '<Data Name="DestinationIp">198.51.100.7</Data>'
            '<Data Name="DestinationPort">443</Data>'
        ),
    )
    analyzer = EvtxAnalyzer(reader_factory([FakeRecord(31, process), FakeRecord(32, network)]))

    events = [item for item in analyzer.analyze(make_context(path)) if isinstance(item, Event)]

    assert [item.category for item in events] == ["process.create", "network.connect"]
    assert events[0].fields["ProcessGuid"].startswith("{")
    assert events[0].user == "LAB\\analyst"
    assert events[1].src_ip == "10.0.0.5"
    assert events[1].src_port == 51515
    assert events[1].dst_ip == "198.51.100.7"
    assert events[1].dst_port == 443


def test_malformed_record_is_isolated_and_later_record_survives(
    tmp_path: Path, make_context
) -> None:
    path = tmp_path / "mixed.evtx"
    path.write_bytes(b"ElfFile\x00")
    valid = event_xml(
        provider="Microsoft-Windows-PowerShell",
        channel="Microsoft-Windows-PowerShell/Operational",
        event_id=4104,
        record_id=91,
        data='<Data Name="ScriptBlockText">Write-Host FLAG{evtx_ok}</Data>',
    )
    analyzer = EvtxAnalyzer(reader_factory([FakeRecord(90, "<not-closed>"), FakeRecord(91, valid)]))

    items = list(analyzer.analyze(make_context(path)))

    assert any(isinstance(item, Diagnostic) and item.stage == "evtx.parse" for item in items)
    unparsed = next(
        item for item in items if isinstance(item, Event) and item.category == "evtx.unparsed"
    )
    event = next(
        item for item in items if isinstance(item, Event) and item.category == "powershell.script"
    )
    assert unparsed.evidence.locator == "channel:Unknown;record:90"
    assert event.category == "powershell.script"
    assert event.evidence.locator.endswith("record:91")
    flag = next(
        item
        for item in items
        if isinstance(item, Finding) and item.rule_id == "evtx.flag_candidate"
    )
    assert flag.observation == "FLAG{evtx_ok}"


def test_oversized_evtx_record_keeps_bounded_preview_and_locator(
    tmp_path: Path, make_context
) -> None:
    path = tmp_path / "large.evtx"
    path.write_bytes(b"ElfFile\x00")
    xml = event_xml(
        provider="Third-Party-Product",
        channel="Application",
        event_id=100,
        record_id=55,
        data=f'<Data Name="Message">{"A" * 400}</Data>',
    )

    items = list(
        EvtxAnalyzer(reader_factory([FakeRecord(55, xml)])).analyze(
            make_context(path, max_line_bytes=256)
        )
    )

    event = next(
        item
        for item in items
        if isinstance(item, Event) and item.category == "evtx.oversized_record"
    )
    assert event.evidence.locator == "channel:Unknown;record:55"
    assert event.evidence.truncated
    assert any(isinstance(item, Diagnostic) and item.stage == "evtx.parse" for item in items)


def test_evtx_honors_cancel_before_reading_records(tmp_path: Path, make_context) -> None:
    path = tmp_path / "cancel.evtx"
    path.write_bytes(b"ElfFile\x00")
    context = make_context(path)
    context.cancel.set()

    items = list(EvtxAnalyzer(reader_factory([FakeRecord(1, "must not parse")])).analyze(context))

    diagnostic = next(item for item in items if isinstance(item, Diagnostic))
    assert diagnostic.stage == "cancel"
    assert not any(isinstance(item, Event) for item in items)


def test_process_tree_prefers_guid_and_bounds_pid_fallback(tmp_path: Path, make_context) -> None:
    path = tmp_path / "processes.evtx"
    path.write_bytes(b"ElfFile\x00")
    sysmon_parent = event_xml(
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        record_id=100,
        timestamp="2026-09-08T05:20:00Z",
        data=(
            '<Data Name="ProcessGuid">{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}</Data>'
            '<Data Name="ProcessId">100</Data>'
            '<Data Name="Image">C:\\Windows\\parent.exe</Data>'
        ),
    )
    sysmon_child = event_xml(
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
        record_id=101,
        timestamp="2026-09-08T05:20:01Z",
        data=(
            '<Data Name="ProcessGuid">{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}</Data>'
            '<Data Name="ParentProcessGuid">{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}</Data>'
            '<Data Name="ProcessId">101</Data>'
            '<Data Name="ParentProcessId">100</Data>'
            '<Data Name="Image">C:\\Tools\\child.exe</Data>'
        ),
    )
    security_parent = event_xml(
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        event_id=4688,
        record_id=102,
        timestamp="2026-09-08T05:21:00Z",
        data=(
            '<Data Name="NewProcessId">0x200</Data>'
            '<Data Name="ProcessId">0x4</Data>'
            '<Data Name="NewProcessName">C:\\Windows\\creator.exe</Data>'
        ),
    )
    security_child = event_xml(
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        event_id=4688,
        record_id=103,
        timestamp="2026-09-08T05:21:30Z",
        data=(
            '<Data Name="NewProcessId">0x201</Data>'
            '<Data Name="ProcessId">0x200</Data>'
            '<Data Name="NewProcessName">C:\\Tools\\worker.exe</Data>'
        ),
    )
    analyzer = EvtxAnalyzer(
        reader_factory(
            [
                FakeRecord(100, sysmon_parent),
                FakeRecord(101, sysmon_child),
                FakeRecord(102, security_parent),
                FakeRecord(103, security_child),
            ]
        )
    )

    items = list(analyzer.analyze(make_context(path)))
    events = [
        item for item in items if isinstance(item, Event) and item.category == "process.create"
    ]

    assert events[1].fields["parent_link_method"] == "process_guid"
    assert events[1].fields["parent_record_id"] == "100"
    assert events[3].fields["parent_link_method"] == "pid_time_window"
    assert events[3].fields["parent_record_id"] == "102"
    tree = next(
        item
        for item in items
        if isinstance(item, Finding) and item.rule_id == "evtx.process_tree_summary"
    )
    assert tree.fields["pid_window_seconds"] == 300.0
