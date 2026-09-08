from __future__ import annotations

import csv
import io
from pathlib import Path

from fieldtrace.analyzers.generic_text import GenericTextAnalyzer
from fieldtrace.analyzers.linux_auth import LinuxAuthAnalyzer
from fieldtrace.analyzers.pcap import PcapAnalyzer
from fieldtrace.analyzers.web import WebLogAnalyzer
from fieldtrace.core.models import Diagnostic, Environment, Event, Finding, TimePolicy


def test_generic_text_utf16_bom_and_evidence_line(tmp_path: Path, make_context) -> None:
    path = tmp_path / "이름 없음.bin"
    path.write_text("첫 줄\n주소 192.0.2.7\nFLAG{utf16_ok}\n", encoding="utf-16")

    items = list(GenericTextAnalyzer().analyze(make_context(path)))

    events = [item for item in items if isinstance(item, Event)]
    findings = [item for item in items if isinstance(item, Finding)]
    assert any(item.fields.get("value") == "192.0.2.7" for item in events)
    candidate = next(item for item in findings if item.rule_id == "text.flag_candidate")
    assert candidate.evidence is not None
    assert candidate.evidence.locator == "line:3"


def test_generic_text_refuses_binary(tmp_path: Path, make_context) -> None:
    path = tmp_path / "fake.log"
    path.write_bytes(b"\x00\x01\x02not text")

    items = list(GenericTextAnalyzer().analyze(make_context(path)))

    assert any(
        isinstance(item, Diagnostic) and item.level == "error" and item.stage == "probe"
        for item in items
    )
    assert not any(isinstance(item, Event) for item in items)


def test_generic_text_uses_explicit_cp949_fallback(tmp_path: Path, make_context) -> None:
    path = tmp_path / "legacy.log"
    path.write_bytes("한글 증거 FLAG{cp949_ok}\n".encode("cp949"))

    automatic = list(GenericTextAnalyzer().analyze(make_context(path)))
    selected = list(GenericTextAnalyzer().analyze(make_context(path, encoding="cp949")))

    assert any(isinstance(item, Diagnostic) and item.level == "error" for item in automatic)
    candidate = next(
        item
        for item in selected
        if isinstance(item, Finding) and item.rule_id == "text.flag_candidate"
    )
    assert candidate.evidence is not None
    assert candidate.evidence.preview.startswith("한글 증거")


def test_web_known_answers_timestamp_uri_and_line(tmp_path: Path, make_context) -> None:
    path = tmp_path / "not-a-log.data"
    path.write_text(
        "192.0.2.10 - alice [08/Sep/2026:14:12:30 +0900] "
        '"GET /find?q=FLAG%7Bline_one%7D HTTP/1.1" 200 123 "-" "agent"\n',
        encoding="utf-8",
    )

    items = list(WebLogAnalyzer().analyze(make_context(path)))

    event = next(
        item for item in items if isinstance(item, Event) and item.category == "web.request"
    )
    assert event.src_ip == "192.0.2.10"
    assert event.timestamp_utc == "2026-09-08T05:12:30+00:00"
    assert event.fields["uri_raw"] == "/find?q=FLAG%7Bline_one%7D"
    assert event.fields["uri_decoded"] == "/find?q=FLAG{line_one}"
    assert event.evidence.locator == "line:1"


def test_auth_success_failure_sudo_and_unknown_time(tmp_path: Path, make_context) -> None:
    path = tmp_path / "auth.log"
    path.write_text(
        "Sep  8 14:20:01 host sshd[1]: Failed password for invalid user guest "
        "from 203.0.113.8 port 51234 ssh2\n"
        "Sep  8 14:20:15 host sshd[2]: Accepted publickey for analyst "
        "from 192.0.2.55 port 55222 ssh2\n"
        "Sep  8 14:21:02 host sudo: analyst : TTY=pts/0 ; PWD=/tmp ; "
        "USER=root ; COMMAND=/usr/bin/id\n",
        encoding="utf-8",
    )

    items = list(LinuxAuthAnalyzer().analyze(make_context(path)))
    events = [item for item in items if isinstance(item, Event)]

    assert [item.category for item in events] == [
        "auth.login_failure",
        "auth.login_success",
        "auth.sudo_command",
    ]
    assert all(item.timestamp_utc is None and item.timezone_status == "unknown" for item in events)
    assert events[0].evidence.locator == "line:1"
    assert events[2].fields["command"] == "/usr/bin/id"


def test_auth_applies_explicit_year_timezone_as_assumption(tmp_path: Path, make_context) -> None:
    path = tmp_path / "auth.log"
    path.write_text(
        "Sep  8 14:20:15 host sshd[2]: Accepted publickey for analyst "
        "from 192.0.2.55 port 55222 ssh2\n",
        encoding="utf-8",
    )
    policy = TimePolicy(timezone="Asia/Seoul", assumed_year=2026)

    event = next(
        item
        for item in LinuxAuthAnalyzer().analyze(make_context(path, time_policy=policy))
        if isinstance(item, Event)
    )

    assert event.timestamp_raw == "Sep  8 14:20:15"
    assert event.timestamp_utc == "2026-09-08T05:20:15+00:00"
    assert event.timezone_status == "assumed"
    assert event.fields["assumed_year"] == 2026
    assert event.fields["assumed_timezone"] == "Asia/Seoul"


def test_auth_does_not_choose_ambiguous_dst_fold(tmp_path: Path, make_context) -> None:
    path = tmp_path / "auth.log"
    path.write_text(
        "Nov  1 01:30:00 host sshd[2]: Accepted password for analyst "
        "from 192.0.2.55 port 55222 ssh2\n",
        encoding="utf-8",
    )
    policy = TimePolicy(timezone="America/New_York", assumed_year=2026)

    event = next(
        item
        for item in LinuxAuthAnalyzer().analyze(make_context(path, time_policy=policy))
        if isinstance(item, Event)
    )

    assert event.timestamp_utc is None
    assert event.timezone_status == "ambiguous_local_time"


class TSharkFixtureRunner:
    def run(self, argv: list[str], **_kwargs: object) -> tuple[int, str, str]:
        assert argv[:3] == ["/usr/bin/tshark", "-n", "-r"]
        assert "_ws.col.protocol" in argv
        stream = io.StringIO()
        writer = csv.writer(stream, delimiter="\t", quotechar='"', lineterminator="\n")
        writer.writerow(
            [
                "7",
                "1788830000.125",
                "DNS",
                "eth:ethertype:ip:udp:dns",
                "",
                "192.0.2.10",
                "",
                "198.51.100.53",
                "",
                "",
                "53000",
                "",
                "53",
                "challenge.example.test",
                "",
                "",
                "",
            ]
        )
        return 0, stream.getvalue(), ""


def test_pcap_mock_dns_and_frame_evidence(tmp_path: Path, make_context) -> None:
    path = tmp_path / "fixture.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    analyzer = PcapAnalyzer()
    capability = analyzer.capabilities(Environment("/usr/bin/tshark", "TShark synthetic"))
    assert capability.available

    items = list(analyzer.analyze(make_context(path, runner=TSharkFixtureRunner())))

    dns = next(
        item for item in items if isinstance(item, Event) and item.category == "network.dns_query"
    )
    assert dns.fields["query"] == "challenge.example.test"
    assert dns.evidence.locator == "frame:7"
    summary = next(
        item for item in items if isinstance(item, Finding) and item.rule_id == "pcap.summary"
    )
    assert summary.fields["packets"] == 1


class FrequentDnsRunner:
    def run(self, _argv: list[str], **_kwargs: object) -> tuple[int, str, str]:
        stream = io.StringIO()
        writer = csv.writer(stream, delimiter="\t", quotechar='"', lineterminator="\n")
        query = f"{'a' * 55}.challenge.example.test"
        for frame in range(1, 21):
            writer.writerow(
                [
                    str(frame),
                    str(1788830000 + frame),
                    "DNS",
                    "eth:ip:udp:dns",
                    "",
                    "192.0.2.10",
                    "",
                    "198.51.100.53",
                    "",
                    "",
                    "53000",
                    "",
                    "53",
                    query,
                    "",
                    "",
                    "",
                ]
            )
        return 0, stream.getvalue(), ""


def test_pcap_dns_length_and_frequency_are_candidates_with_evidence(
    tmp_path: Path, make_context
) -> None:
    path = tmp_path / "dns.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    analyzer = PcapAnalyzer()
    analyzer.capabilities(Environment("/usr/bin/tshark", "TShark synthetic"))

    findings = [
        item
        for item in analyzer.analyze(make_context(path, runner=FrequentDnsRunner()))
        if isinstance(item, Finding)
    ]

    long_query = next(item for item in findings if item.rule_id == "pcap.dns_long_query_candidate")
    frequent = next(item for item in findings if item.rule_id == "pcap.dns_frequency_candidate")
    assert long_query.evidence is not None and long_query.evidence.locator == "frame:1"
    assert frequent.fields["count"] == 20
    assert "확정하지 않습니다" in frequent.interpretation


def test_web_suspicious_request_rule_remains_a_candidate(tmp_path: Path, make_context) -> None:
    path = tmp_path / "access.log"
    path.write_text(
        "192.0.2.10 - - [08/Sep/2026:14:12:30 +0900] "
        '"GET /download?file=../../etc/passwd HTTP/1.1" 200 20\n',
        encoding="utf-8",
    )

    finding = next(
        item
        for item in WebLogAnalyzer().analyze(make_context(path))
        if isinstance(item, Finding) and item.rule_id == "web.http_request_candidate"
    )

    assert finding.evidence is not None and finding.evidence.locator == "line:1"
    assert "상위 경로 이동 표현" in finding.fields["reasons"]
    assert "확정하지 않습니다" in finding.interpretation
