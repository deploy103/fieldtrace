from __future__ import annotations

import csv
import hashlib
import io
from pathlib import Path

import pytest

from fieldtrace.analyzers.pcap import PcapAnalyzer
from fieldtrace.core.artifacts import SafeArtifactSink
from fieldtrace.core.models import Artifact, Environment, Event, EvidenceRef


class DetailRunner:
    def run(self, argv: list[str], **_kwargs: object) -> tuple[int, str, str]:
        if "-z" in argv:
            assert "follow,tcp,ascii,3" in argv
            return (
                0,
                "Follow: tcp,ascii\nFilter: tcp.stream eq 3\nGET / HTTP/1.1\n",
                "",
            )
        if "http.file_data" in argv and "-Y" in argv:
            stream = io.StringIO()
            writer = csv.writer(stream, delimiter="\t", quotechar='"', lineterminator="\n")
            writer.writerow(["9", "3", "text/plain", "15", b"FLAG{object_ok}".hex()])
            return 0, stream.getvalue(), ""
        stream = io.StringIO()
        writer = csv.writer(stream, delimiter="\t", quotechar='"', lineterminator="\n")
        writer.writerow(
            [
                "9",
                "1788830000.125",
                "HTTP",
                "eth:ip:tcp:http",
                "3",
                "192.0.2.10",
                "",
                "198.51.100.80",
                "",
                "49152",
                "",
                "80",
                "",
                "",
                "GET",
                "challenge.example.test",
                "/",
            ]
        )
        return 0, stream.getvalue(), ""


def test_tcp_follow_and_http_object_use_tshark_and_core_sink(tmp_path: Path, make_context) -> None:
    path = tmp_path / "capture.pcapng"
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)
    analyzer = PcapAnalyzer()
    analyzer.capabilities(Environment("/usr/bin/tshark", "TShark synthetic"))
    sink = SafeArtifactSink(tmp_path / "case" / "derived" / "run-1")
    context = make_context(
        path,
        tasks=("tcp_streams", "object_extraction"),
        runner=DetailRunner(),
        artifact_sink=sink,
    )

    items = list(analyzer.analyze(context))

    stream_event = next(
        item for item in items if isinstance(item, Event) and item.category == "network.tcp_stream"
    )
    artifact = next(item for item in items if isinstance(item, Artifact))
    artifact_path = Path(artifact.path)
    assert stream_event.evidence.locator == "tcp.stream:3"
    assert stream_event.fields["completeness"] == "unknown"
    assert "GET / HTTP/1.1" in stream_event.fields["stream_preview"]
    assert artifact_path.is_relative_to(sink.directory)
    assert artifact_path.read_bytes() == b"FLAG{object_ok}"
    assert artifact.sha256 == hashlib.sha256(b"FLAG{object_ok}").hexdigest()
    assert artifact.evidence.locator == "frame:9"


def test_core_artifact_sink_sanitizes_names_and_enforces_size(tmp_path: Path) -> None:
    sink = SafeArtifactSink(tmp_path / "derived", max_artifact_bytes=4)
    evidence = EvidenceRef(1, "pcap_frame", "frame:1", "preview")

    artifact = sink.write_bytes(
        "../../unsafe name.exe",
        b"1234",
        kind="test",
        analyzer="test",
        evidence=evidence,
    )

    assert Path(artifact.path).parent == sink.directory
    assert Path(artifact.path).name == "unsafe_name.exe"
    with pytest.raises(ValueError, match="제한"):
        sink.write_bytes(
            "too-large.bin",
            b"12345",
            kind="test",
            analyzer="test",
            evidence=evidence,
        )
