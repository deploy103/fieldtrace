from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from fieldtrace.analyzers._common import (
    extract_domains,
    extract_flags,
    extract_ipv4,
    extract_ipv6,
    extract_literals,
)
from fieldtrace.core.artifacts import SafeArtifactSink
from fieldtrace.core.cases import CaseInUseError, case_analysis_lock, prepare_case
from fieldtrace.core.config import AnalysisSettings, RuntimeConfig
from fieldtrace.core.db import CaseDatabaseError, CaseStore, case_database_error
from fieldtrace.core.models import Coverage, Diagnostic, Event, EvidenceRef, Finding, RunStatus
from fieldtrace.core.service import FieldTraceService
from fieldtrace.reports import OutputWriteError, export_report


def test_case_analysis_lock_rejects_concurrent_writer(tmp_path: Path) -> None:
    case = prepare_case(tmp_path / "case")

    with case_analysis_lock(case), pytest.raises(
        CaseInUseError, match="다른 FieldTrace 분석"
    ), case_analysis_lock(case):
        pass


def test_interrupted_run_is_recovered_before_new_analysis(tmp_path: Path) -> None:
    evidence_path = tmp_path / "evidence.log"
    evidence_path.write_text("plain evidence\n", encoding="utf-8")
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
        interrupted_run = store.create_run(source_id, "full")
        store.write_items(
            interrupted_run,
            [
                Event(
                    category="partial",
                    summary="committed before crash",
                    evidence=EvidenceRef(source_id, "text_line", "line:1", "plain evidence"),
                )
            ],
        )

    summary = FieldTraceService().analyze(
        evidence_path, case_dir=case, profile="full", forced_type="text"
    )

    with CaseStore(case, create=False) as store:
        runs = store.list_runs()
        diagnostics = store.diagnostic_rows(run_ids=[interrupted_run])
    assert summary.partial
    assert "이전 분석 1건" in " ".join(summary.messages)
    assert runs[0].status == RunStatus.FAILED.value
    assert runs[0].coverage == Coverage.PARTIAL.value
    assert runs[0].finished_at is not None
    assert runs[-1].status == RunStatus.COMPLETED.value
    assert diagnostics[0]["stage"] == "recovery"


def test_sqlite_lock_has_actionable_error_and_retry_succeeds(tmp_path: Path) -> None:
    case = prepare_case(tmp_path / "case")
    with CaseStore(case):
        pass
    blocker = sqlite3.connect(case.database, isolation_level=None)
    try:
        blocker.execute("BEGIN EXCLUSIVE")
        with pytest.raises(CaseDatabaseError) as captured:
            CaseStore(case, create=False, timeout=0.01)
        assert "잠겼습니다" in captured.value.reason
        assert "다시 실행" in captured.value.next_action
    finally:
        blocker.rollback()
        blocker.close()

    with CaseStore(case, create=False, timeout=0.1) as reopened:
        assert reopened.schema_version() >= 1


def test_disk_full_error_is_classified_without_success_claim(tmp_path: Path) -> None:
    error = case_database_error(
        tmp_path / "case.sqlite3",
        sqlite3.OperationalError("database or disk is full"),
        stage="분석 결과 저장",
    )

    assert error.stage == "분석 결과 저장"
    assert "공간이 부족" in error.reason
    assert "확보" in error.next_action


def test_database_write_failure_preserves_committed_batch_and_closes_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_path = tmp_path / "evidence.log"
    evidence_path.write_text("192.0.2.1 198.51.100.2\n", encoding="utf-8")
    case = tmp_path / "case"
    original = CaseStore.add_event
    calls = 0

    def fail_second_event(
        store: CaseStore, run_id: int, event: Event, *, commit: bool = True
    ) -> int:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise sqlite3.OperationalError("database or disk is full")
        return original(store, run_id, event, commit=commit)

    monkeypatch.setattr(CaseStore, "add_event", fail_second_event)
    service = FieldTraceService(RuntimeConfig(analysis=AnalysisSettings(batch_size=1)))

    with pytest.raises(CaseDatabaseError, match="공간이 부족"):
        service.analyze(evidence_path, case_dir=case, profile="full", forced_type="text")

    with CaseStore(case, create=False) as store:
        runs = store.list_runs()
        events = store.event_rows()
    assert len(events) == 1
    assert runs[0].status == RunStatus.FAILED.value
    assert runs[0].coverage == Coverage.PARTIAL.value
    assert (case / "diagnostics" / "storage-error.log").is_file()


def test_oversized_line_is_skipped_and_next_line_keeps_correct_locator(tmp_path: Path) -> None:
    evidence_path = tmp_path / "long.log"
    evidence_path.write_text("x" * 4096 + "\nFLAG{after_long_line}\n", encoding="utf-8")
    case = tmp_path / "case"
    service = FieldTraceService(RuntimeConfig(analysis=AnalysisSettings(max_line_bytes=1024)))
    summary = service.analyze(
        evidence_path, case_dir=case, profile="full", forced_type="text"
    )
    bundle = service.report_bundle(case)

    assert summary.partial
    assert any(row["stage"] == "read" for row in bundle["diagnostics"])
    candidate = next(row for row in bundle["findings"] if row["rule_id"] == "text.flag_candidate")
    assert candidate["evidence_locator"] == "line:2"


def test_atomic_report_failure_keeps_previous_file_and_removes_part(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "report.json"
    output.write_text("previous", encoding="utf-8")

    def fail_sync(_descriptor: int) -> None:
        raise OSError("synthetic disk full")

    monkeypatch.setattr("fieldtrace.reports._atomic.os.fsync", fail_sync)
    with pytest.raises(OutputWriteError) as captured:
        export_report({"case": {}, "summary": {}}, output, "json")

    assert "공간이 부족" in captured.value.reason
    assert "다시 실행" in captured.value.next_action
    assert output.read_text(encoding="utf-8") == "previous"
    assert not list(tmp_path.glob("*.part"))
    assert not list(tmp_path.glob(".*.part"))


def test_partial_artifact_is_removed_when_durable_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = SafeArtifactSink(tmp_path / "derived")

    def fail_sync(_descriptor: int) -> None:
        raise OSError("synthetic disk full")

    monkeypatch.setattr("fieldtrace.core.artifacts.os.fsync", fail_sync)
    with pytest.raises(OSError, match="disk full"):
        sink.write_bytes(
            "body.bin",
            b"partial",
            kind="test",
            analyzer="test",
            evidence=EvidenceRef(1, "test", "item:1", "raw"),
        )

    assert not list((tmp_path / "derived").iterdir())


def test_indicator_extractors_short_circuit_large_non_candidate_line() -> None:
    text = "x" * (4 * 1024 * 1024)

    assert extract_ipv4(text) == []
    assert extract_ipv6(text) == []
    assert extract_domains(text) == []
    assert extract_flags(text) == []
    assert extract_literals(text) == []


def test_result_bundle_is_bounded_but_keeps_total_counts(tmp_path: Path) -> None:
    evidence_path = tmp_path / "evidence.log"
    evidence_path.write_text("source", encoding="utf-8")
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
        run_id = store.create_run(source_id, "full")
        for index in range(5):
            store.add_finding(
                run_id,
                Finding(
                    rule_id=f"candidate-{index}",
                    title="candidate",
                    observation="observed",
                    interpretation="review",
                    confidence="medium",
                ),
            )
            store.add_diagnostic(
                Diagnostic("warning", "test", f"diagnostic {index}"),
                source_id=source_id,
                run_id=run_id,
            )
        store.finish_run(
            run_id,
            status=RunStatus.COMPLETED,
            coverage=Coverage.COMPLETE,
            records_read=1,
            failures=0,
        )

    bundle = FieldTraceService().result_bundle(case, max_findings=2, max_diagnostics=3)

    assert bundle["summary"]["findings"] == 5
    assert bundle["summary"]["diagnostics"] == 5
    assert len(bundle["findings"]) == 2
    assert len(bundle["diagnostics"]) == 3
    assert bundle["view_truncated"]["findings"] is True
    assert bundle["view_truncated"]["diagnostics"] is True
