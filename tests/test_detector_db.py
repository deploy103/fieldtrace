from __future__ import annotations

from pathlib import Path
from threading import Event as CancelEvent

from fieldtrace.analyzers import builtin_analyzers
from fieldtrace.core.db import CaseStore
from fieldtrace.core.detector import FormatDetector
from fieldtrace.core.hashing import HashJob
from fieldtrace.core.models import Coverage, Event, EvidenceRef, Finding, RunStatus, SourceFormat
from fieldtrace.core.search import correlations, evidence_detail, literal_search, timeline


def test_content_detection_ignores_misleading_extensions(tmp_path: Path) -> None:
    web = tmp_path / "capture.pcap"
    web.write_text(
        '192.0.2.2 - - [08/Sep/2026:14:12:30 +0900] "GET / HTTP/1.1" 200 1\n',
        encoding="utf-8",
    )
    packet = tmp_path / "notes.txt"
    packet.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 16)
    detector = FormatDetector(builtin_analyzers())

    assert detector.detect(web).format is SourceFormat.WEB
    assert detector.detect(packet).format is SourceFormat.PCAP


def test_unknown_binary_can_be_manually_typed(tmp_path: Path) -> None:
    path = tmp_path / "unknown.log"
    path.write_bytes(b"\x00\x01\x02\x03")
    detector = FormatDetector(builtin_analyzers())

    detected = detector.detect(path)
    forced = detector.detect(path, forced_type="text")

    assert detected.format is SourceFormat.UNKNOWN
    assert forced.format is SourceFormat.GENERIC_TEXT
    assert "직접 지정" in forced.reason


def test_case_search_timeline_evidence_and_latest_run(tmp_path: Path) -> None:
    evidence_path = tmp_path / "evidence.log"
    evidence_path.write_text("original", encoding="utf-8")
    case = tmp_path / "case"
    with CaseStore(case) as store:
        stat = evidence_path.stat()
        source_id = store.add_source(
            evidence_path,
            size=stat.st_size,
            mtime_ns=stat.st_mtime_ns,
            detected_format="text",
            detection_reason="test",
        )
        old_run = store.create_run(source_id, "quick")
        old_event = Event(
            category="old",
            summary="old-only marker",
            evidence=EvidenceRef(source_id, "text_line", "line:1", "old-only marker"),
            timestamp_raw="unknown",
        )
        store.write_items(old_run, [old_event])
        store.finish_run(
            old_run,
            status=RunStatus.COMPLETED,
            coverage=Coverage.COMPLETE,
            records_read=1,
            failures=0,
        )
        new_run = store.create_run(source_id, "full")
        new_event = Event(
            category="new",
            summary="new literal FLAG{latest}",
            evidence=EvidenceRef(source_id, "text_line", "line:9", "raw new literal FLAG{latest}"),
            timestamp_raw="Sep 8 12:00:00",
            timestamp_utc=None,
            timezone_status="unknown",
        )
        finding = Finding(
            rule_id="candidate",
            title="candidate",
            observation="FLAG{latest} observed",
            interpretation="needs review",
            confidence="medium",
            evidence=new_event.evidence,
        )
        store.write_items(new_run, [new_event, finding])
        store.finish_run(
            new_run,
            status=RunStatus.COMPLETED,
            coverage=Coverage.COMPLETE,
            records_read=1,
            failures=0,
        )

        hits = literal_search(store, "FLAG{latest}")
        entries = timeline(store)
        detail = evidence_detail(store, "event", new_event.id or 0)

        assert hits and all(hit.run_id == new_run for hit in hits)
        assert not literal_search(store, "old-only")
        assert len(entries) == 1 and entries[0].event_id == new_event.id
        assert entries[0].timestamp_utc is None
        assert detail is not None
        assert detail.locator == "line:9"
        assert detail.preview == "raw new literal FLAG{latest}"


def test_cancelled_hash_never_exposes_partial_digest(tmp_path: Path) -> None:
    path = tmp_path / "large.bin"
    path.write_bytes(b"x" * (2 * 1024 * 1024))
    cancel = CancelEvent()
    cancel.set()

    result = HashJob(path, cancel, chunk_size=1024).start().result(timeout=5)

    assert result is not None
    assert result.status == "cancelled"
    assert result.sha256 is None


def test_like_fallback_escapes_wildcards(tmp_path: Path) -> None:
    evidence_path = tmp_path / "fallback.log"
    evidence_path.write_text("literal", encoding="utf-8")
    with CaseStore(tmp_path / "case") as store:
        stat = evidence_path.stat()
        source_id = store.add_source(
            evidence_path,
            size=stat.st_size,
            mtime_ns=stat.st_mtime_ns,
            detected_format="text",
            detection_reason="test",
        )
        run_id = store.create_run(source_id, "full")
        store.write_items(
            run_id,
            [
                Event(
                    category="literal",
                    summary="marker 100%_done",
                    evidence=EvidenceRef(source_id, "text_line", "line:1", "marker 100%_done"),
                ),
                Event(
                    category="decoy",
                    summary="marker 100XXdone",
                    evidence=EvidenceRef(source_id, "text_line", "line:2", "marker 100XXdone"),
                ),
            ],
        )
        store.finish_run(
            run_id,
            status=RunStatus.COMPLETED,
            coverage=Coverage.COMPLETE,
            records_read=2,
            failures=0,
        )
        store.fts5_available = False

        hits = literal_search(store, "100%_done")

    assert len(hits) == 1
    assert "100%_done" in hits[0].preview


def test_stale_hash_generation_cannot_overwrite_new_result(tmp_path: Path) -> None:
    evidence_path = tmp_path / "race.log"
    evidence_path.write_text("same source", encoding="utf-8")
    stat = evidence_path.stat()
    with CaseStore(tmp_path / "case") as store:
        source_id = store.add_source(
            evidence_path,
            size=stat.st_size,
            mtime_ns=stat.st_mtime_ns,
            detected_format="text",
            detection_reason="first",
            hash_status="running",
            hash_generation="old-generation",
        )
        reused_source_id = store.add_source(
            evidence_path,
            size=stat.st_size,
            mtime_ns=stat.st_mtime_ns,
            detected_format="text",
            detection_reason="second",
            hash_status="running",
            hash_generation="new-generation",
        )

        stale_applied = store.update_source_hash(
            source_id,
            "old-digest",
            "complete",
            generation="old-generation",
        )
        current_applied = store.update_source_hash(
            source_id,
            "new-digest",
            "complete",
            generation="new-generation",
        )
        row = store.connection.execute(
            "SELECT sha256,hash_status,hash_generation FROM sources WHERE id=?",
            (source_id,),
        ).fetchone()

    assert reused_source_id == source_id
    assert stale_applied is False
    assert current_applied is True
    assert row is not None
    assert tuple(row) == ("new-digest", "complete", "new-generation")


def test_cross_source_correlations_group_explicit_entities_without_claiming_cause(
    tmp_path: Path,
) -> None:
    with CaseStore(tmp_path / "case") as store:
        for index, fields in enumerate(
            (
                {
                    "query": "shared.example.test",
                    "Image": r"C:\Tools\runner.exe",
                },
                {
                    "host": "shared.example.test",
                    "NewProcessName": "/opt/tools/runner.exe",
                },
            ),
            1,
        ):
            path = tmp_path / f"source-{index}.log"
            path.write_text("evidence", encoding="utf-8")
            stat = path.stat()
            source_id = store.add_source(
                path,
                size=stat.st_size,
                mtime_ns=stat.st_mtime_ns,
                detected_format="text",
                detection_reason="test",
            )
            run_id = store.create_run(source_id, "full")
            store.write_items(
                run_id,
                [
                    Event(
                        category="test.entity",
                        summary=f"source {index}",
                        evidence=EvidenceRef(source_id, "text_line", f"line:{index}", "raw"),
                        src_ip="192.0.2.40" if index == 1 else None,
                        dst_ip="192.0.2.40" if index == 2 else None,
                        user="Analyst",
                        fields=fields,
                    )
                ],
            )
            store.finish_run(
                run_id,
                status=RunStatus.COMPLETED,
                coverage=Coverage.COMPLETE,
                records_read=1,
                failures=0,
            )

        entries = correlations(store)

    keyed = {(entry.kind, entry.value.casefold()): entry for entry in entries}
    assert keyed[("ip", "192.0.2.40")].source_ids == (1, 2)
    assert keyed[("domain", "shared.example.test")].occurrences == 2
    assert keyed[("account", "analyst")].occurrences == 2
    assert keyed[("filename", "runner.exe")].occurrences == 2
    assert all("인과관계" in entry.interpretation for entry in entries)
