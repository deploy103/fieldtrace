from __future__ import annotations

import hashlib
import time
from collections.abc import Iterator
from pathlib import Path
from threading import Event as CancelEvent

from fieldtrace.core.config import AnalysisSettings, PathSettings, RuntimeConfig
from fieldtrace.core.db import CaseStore
from fieldtrace.core.models import (
    AnalysisContext,
    AnalysisItem,
    Capability,
    Environment,
    Event,
    EvidenceRef,
    ProbeMetadata,
    ProbeResult,
    Progress,
    SourceFormat,
)
from fieldtrace.core.registry import AnalyzerRegistry
from fieldtrace.core.service import FieldTraceService, exit_code


class IsolatingAnalyzer:
    name = "isolating"
    formats = (SourceFormat.GENERIC_TEXT,)

    def probe(self, sample: bytes, metadata: ProbeMetadata) -> ProbeResult:
        del sample, metadata
        return ProbeResult(SourceFormat.GENERIC_TEXT, 1.0, "test", self.name)

    def capabilities(self, environment: Environment) -> Capability:
        del environment
        return Capability(True, "test")

    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisItem]:
        yield Event(
            category="test.line",
            summary=context.input_path.name,
            evidence=EvidenceRef(context.source_id, "text_line", "line:1", "preserved"),
        )
        yield Progress("test", 1)
        if context.input_path.name.startswith("broken"):
            raise RuntimeError("synthetic analyzer failure")


def test_analyzer_failure_keeps_partial_and_continues_next_file(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "input"
    evidence_dir.mkdir()
    (evidence_dir / "broken.log").write_text("broken", encoding="utf-8")
    (evidence_dir / "healthy.log").write_text("healthy", encoding="utf-8")
    case = tmp_path / "case"
    registry = AnalyzerRegistry((IsolatingAnalyzer(),))
    service = FieldTraceService(RuntimeConfig(), registry)

    summary = service.analyze(
        evidence_dir,
        case_dir=case,
        profile="full",
        forced_type="text",
    )

    bundle = service.report_bundle(case, latest_only=False)
    assert len(bundle["sources"]) == 2
    assert len(bundle["runs"]) == 2
    assert len(bundle["events"]) == 2
    assert summary.failures == 1
    assert any("synthetic analyzer failure" in item["message"] for item in bundle["diagnostics"])
    diagnostic_files = list((case / "diagnostics").glob("*.log"))
    assert diagnostic_files and "Traceback" in diagnostic_files[0].read_text(encoding="utf-8")


class CancellingAnalyzer(IsolatingAnalyzer):
    name = "cancelling"

    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisItem]:
        for number in range(300):
            yield Event(
                category="test.cancel",
                summary=str(number),
                evidence=EvidenceRef(
                    context.source_id,
                    "text_line",
                    f"line:{number + 1}",
                    str(number),
                ),
            )
            if number == 250:
                context.cancel.set()
                return


def test_cancel_keeps_committed_results_and_exit_130(tmp_path: Path) -> None:
    path = tmp_path / "cancel.log"
    path.write_text("cancel", encoding="utf-8")
    case = tmp_path / "case"
    service = FieldTraceService(
        RuntimeConfig(analysis=AnalysisSettings(batch_size=25)),
        AnalyzerRegistry((CancellingAnalyzer(),)),
    )
    cancel = CancelEvent()

    summary = service.analyze(
        path,
        case_dir=case,
        profile="full",
        forced_type="text",
        cancel=cancel,
    )

    with CaseStore(case, create=False) as store:
        run = store.list_runs()[0]
        assert store.counts()["events"] == 251
    assert summary.cancelled and summary.partial
    assert run.status == "cancelled" and run.coverage == "partial"
    assert exit_code(summary) == 130


def test_quick_budget_partial_is_success_exit_zero(tmp_path: Path) -> None:
    path = tmp_path / "budget.log"
    path.write_text("one\ntwo\n", encoding="utf-8")
    case = tmp_path / "case"
    config = RuntimeConfig(analysis=AnalysisSettings(quick_records=1))
    service = FieldTraceService(config)

    summary = service.analyze(path, case_dir=case, profile="quick")

    with CaseStore(case, create=False) as store:
        run = store.list_runs()[0]
    assert summary.partial and summary.failures == 0
    assert run.status == "completed" and run.coverage == "partial"
    assert exit_code(summary) == 0


def test_unparsed_web_line_is_partial_failure(tmp_path: Path) -> None:
    path = tmp_path / "custom-access.log"
    path.write_text(
        '192.0.2.1 - - [08/Sep/2026:14:12:30 +0900] "GET / HTTP/1.1" 200 1\n'
        "vendor-specific unsupported line\n",
        encoding="utf-8",
    )
    case = tmp_path / "case"
    service = FieldTraceService(RuntimeConfig())

    summary = service.analyze(path, case_dir=case, profile="full", forced_type="web")

    with CaseStore(case, create=False) as store:
        run = store.list_runs()[0]
    assert summary.partial and summary.failures == 1
    assert run.status == "partial" and run.coverage == "partial"
    assert exit_code(summary) == 1


def test_case_directory_is_not_recursively_collected(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    input_dir = root / "input"
    case_base = root / "cases"
    input_dir.mkdir(parents=True)
    case_base.mkdir()
    (input_dir / ".gitkeep").touch()
    (input_dir / "one.log").write_text("one", encoding="utf-8")
    (case_base / "old-result.txt").write_text("must not analyze", encoding="utf-8")
    config = RuntimeConfig(paths=PathSettings(cases=case_base))
    service = FieldTraceService(config)

    collected = service._collect_files(root)

    assert collected == [(input_dir / "one.log").resolve()]


def test_analysis_preserves_original_and_records_integrity(tmp_path: Path) -> None:
    path = tmp_path / "원본 증거.log"
    content = b"immutable evidence FLAG{original}\n"
    path.write_bytes(content)
    before = path.stat()
    expected_hash = hashlib.sha256(content).hexdigest()
    case = tmp_path / "case"
    service = FieldTraceService(RuntimeConfig())

    summary = service.analyze(path, case_dir=case, profile="full")

    after = path.stat()
    assert path.read_bytes() == content
    assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)
    assert summary.failures == 0

    deadline = time.monotonic() + 5
    while True:
        with CaseStore(case, create=False) as store:
            row = store.connection.execute("SELECT * FROM sources").fetchone()
            assert row is not None
            if row["hash_status"] != "pending" or time.monotonic() >= deadline:
                break
        time.sleep(0.01)

    assert row["size"] == before.st_size
    assert row["mtime_ns"] == before.st_mtime_ns
    assert row["size_after"] == before.st_size
    assert row["mtime_ns_after"] == before.st_mtime_ns
    assert row["changed_after"] == 0
    assert row["hash_status"] == "complete"
    assert row["sha256"] == expected_hash
