"""Cohesive service API shared by interactive and non-interactive clients."""

from __future__ import annotations

import sqlite3
import time
import traceback
import uuid
from collections.abc import Callable, Iterable, Iterator
from contextlib import suppress
from pathlib import Path
from threading import Event, Thread
from typing import Any

from .cases import CasePaths, create_case, prepare_case
from .config import RuntimeConfig, load_config
from .db import CaseStore
from .detector import DetectionResult, FormatDetector
from .doctor import detect_environment
from .hashing import HashJob, HashResult, start_hash
from .models import (
    AnalysisContext,
    AnalysisItem,
    AnalysisSummary,
    Artifact,
    Coverage,
    Diagnostic,
    Finding,
    Progress,
    RunStatus,
    SourceFormat,
)
from .models import (
    Event as AnalysisEvent,
)
from .registry import AnalyzerChoice, AnalyzerRegistry
from .runner import SafeExternalRunner
from .search import (
    EvidenceDetail,
    SearchHit,
    TimelineEntry,
    evidence_detail,
    literal_search,
)
from .search import (
    report_bundle as build_report_bundle,
)
from .search import (
    timeline as build_timeline,
)

ProgressCallback = Callable[[Progress], None]


class InputError(ValueError):
    """An invalid user path, profile, or manual type selection."""


def builtin_registry() -> AnalyzerRegistry:
    """Register only the maintained built-ins by explicit module/class name."""

    registry = AnalyzerRegistry()
    modules = (
        ("fieldtrace.analyzers.generic_text", "GenericTextAnalyzer"),
        ("fieldtrace.analyzers.web", "WebLogAnalyzer"),
        ("fieldtrace.analyzers.linux_auth", "LinuxAuthAnalyzer"),
        ("fieldtrace.analyzers.pcap", "PcapAnalyzer"),
    )
    import importlib

    for module_name, class_name in modules:
        try:
            module = importlib.import_module(module_name)
            analyzer_class = getattr(module, class_name)
        except (ImportError, AttributeError):
            continue
        registry.register(analyzer_class())
    return registry


class FieldTraceService:
    def __init__(
        self,
        config: RuntimeConfig | None = None,
        registry: AnalyzerRegistry | None = None,
    ) -> None:
        self.config = config or load_config()
        self.registry = registry or builtin_registry()
        self.runner = SafeExternalRunner(
            default_timeout=self.config.analysis.command_timeout_seconds,
            default_max_output=self.config.analysis.command_output_bytes,
        )

    def detect(
        self, path: Path | str, forced_type: SourceFormat | str | None = None
    ) -> DetectionResult:
        return FormatDetector(self.registry.all()).detect(path, forced_type=forced_type)

    def analyze(
        self,
        paths: Path | str | Iterable[Path | str],
        case_dir: Path | str | None = None,
        profile: str = "quick",
        forced_type: SourceFormat | str | None = None,
        selected_tasks: Iterable[str] = (),
        progress: ProgressCallback | None = None,
        cancel: Event | None = None,
        text_encoding: str | None = None,
    ) -> AnalysisSummary:
        if profile not in {"quick", "full", "custom"}:
            raise InputError("profile은 quick, full, custom 중 하나여야 합니다.")
        tasks = frozenset(selected_tasks)
        if text_encoding is not None:
            from fieldtrace.analyzers._common import normalize_encoding

            text_encoding = normalize_encoding(text_encoding)
        if profile == "custom" and not tasks:
            raise InputError("custom 분석에는 하나 이상의 분석 항목이 필요합니다.")
        cancel_event = cancel or Event()
        explicit_case = Path(case_dir).expanduser().resolve() if case_dir is not None else None
        input_files = self._collect_files(paths, excluded=explicit_case)
        if not input_files:
            raise InputError("분석할 일반 파일이 없습니다.")
        case = (
            prepare_case(explicit_case) if explicit_case else create_case(self.config.paths.cases)
        )
        summary = AnalysisSummary(case_dir=case.root)
        environment = detect_environment(runner=self.runner)
        with CaseStore(case) as store:
            try:
                for input_path in input_files:
                    if cancel_event.is_set():
                        summary.cancelled = True
                        summary.partial = True
                        break
                    self._analyze_source(
                        input_path,
                        store,
                        case,
                        profile,
                        forced_type,
                        tasks,
                        environment,
                        cancel_event,
                        progress,
                        summary,
                        text_encoding,
                    )
            except KeyboardInterrupt:
                cancel_event.set()
                summary.cancelled = True
                summary.partial = True
                summary.messages.append("사용자 취소: 이미 커밋된 부분 결과를 보존했습니다.")
                for running in store.list_runs():
                    if running.status == RunStatus.RUNNING.value:
                        store.finish_run(
                            running.id,
                            status=RunStatus.CANCELLED,
                            coverage=Coverage.PARTIAL,
                            records_read=running.records_read,
                            failures=running.failures,
                            skip_reason="사용자 취소",
                        )
        return summary

    def _analyze_source(
        self,
        input_path: Path,
        store: CaseStore,
        case: CasePaths,
        profile: str,
        forced_type: SourceFormat | str | None,
        tasks: frozenset[str],
        environment: Any,
        cancel: Event,
        progress_callback: ProgressCallback | None,
        summary: AnalysisSummary,
        text_encoding: str | None,
    ) -> None:
        try:
            before = input_path.stat()
            detection = self.detect(input_path, forced_type)
        except (OSError, ValueError) as exc:
            summary.failures += 1
            summary.partial = True
            summary.messages.append(f"{input_path}: 감지 실패: {exc}")
            return
        hash_generation = uuid.uuid4().hex
        source_id = store.add_source(
            input_path,
            size=before.st_size,
            mtime_ns=before.st_mtime_ns,
            detected_format=detection.format.value,
            detection_reason=detection.reason,
            hash_status="running",
            hash_generation=hash_generation,
        )
        summary.source_ids.append(source_id)
        hash_job = start_hash(
            input_path,
            cancel,
            expected_size=before.st_size,
            expected_mtime_ns=before.st_mtime_ns,
        )
        usable, unavailable = self.registry.available(
            detection.format, environment, selected_tasks=tasks
        )
        run_id = store.create_run(
            source_id,
            profile,
            analyzers=[choice.analyzer.name for choice in usable],
            tool_versions={"tshark": environment.tshark_version},
            config={
                "time_policy": {
                    "timezone": self.config.time_policy.timezone,
                    "assumed_year": self.config.time_policy.assumed_year,
                },
                "text_encoding": text_encoding,
                "budget": {
                    "max_seconds": self.config.analysis.budget(profile).max_seconds,
                    "max_records": self.config.analysis.budget(profile).max_records,
                    "max_line_bytes": self.config.analysis.max_line_bytes,
                    "max_preview_chars": self.config.analysis.max_preview_chars,
                },
            },
            selected_tasks=tasks,
        )
        summary.run_ids.append(run_id)
        for analyzer, capability in unavailable:
            store.add_diagnostic(
                Diagnostic(
                    "warning",
                    "capability",
                    f"{analyzer.name} 분석기를 사용할 수 없습니다: {capability.reason}",
                    "doctor 결과를 확인하거나 다른 형식을 분석하세요.",
                ),
                source_id=source_id,
                run_id=run_id,
            )

        records_read = 0
        failures = 0
        budget_limited = False
        cancelled = False
        for choice in usable:
            if cancel.is_set():
                cancelled = True
                break
            context = AnalysisContext(
                input_path=input_path,
                source_id=source_id,
                case_id=store.case_id,
                run_id=run_id,
                cancel=cancel,
                time_policy=self.config.time_policy,
                budget=self.config.analysis.budget(profile),
                external_runner=self.runner,
                profile=profile,
                started_at=time.monotonic(),
                selected_tasks=tasks,
                text_encoding=text_encoding,
            )
            try:
                outcome = self._consume(
                    choice,
                    context,
                    store,
                    run_id,
                    progress_callback,
                    summary,
                )
                records_read = max(records_read, outcome["records_read"])
                failures += outcome["failures"]
                if outcome["incomplete"]:
                    failures += 1
                budget_limited = budget_limited or outcome["budget_limited"]
                cancelled = cancelled or outcome["cancelled"]
            except KeyboardInterrupt:
                cancel.set()
                cancelled = True
                break
            except Exception as exc:
                failures += 1
                trace = traceback.format_exc()
                diagnostic = Diagnostic(
                    "error",
                    "analyzer",
                    f"{choice.analyzer.name} 분석 중 실패: {exc}",
                    "진단 파일을 확인하고 다른 파일 분석을 계속하세요.",
                    trace,
                )
                store.add_diagnostic(diagnostic, source_id=source_id, run_id=run_id)
                self._write_trace(case, run_id, choice.analyzer.name, trace)
                summary.messages.append(diagnostic.message)

        unsupported = not usable
        if unsupported:
            failures += 1
            reason = (
                "; ".join(f"{analyzer.name}: {cap.reason}" for analyzer, cap in unavailable)
                or f"{detection.format.value} 형식에 등록된 분석기가 없음"
            )
            store.add_diagnostic(
                Diagnostic(
                    "warning",
                    "selection",
                    f"분석 생략: {reason}",
                    "형식을 직접 지정하거나 doctor에서 도구 상태를 확인하세요.",
                ),
                source_id=source_id,
                run_id=run_id,
            )

        changed = False
        try:
            after = input_path.stat()
            changed = store.finish_source_stat(
                source_id, size=after.st_size, mtime_ns=after.st_mtime_ns
            )
        except OSError as exc:
            changed = True
            store.mark_source_changed(source_id)
            store.add_diagnostic(
                Diagnostic(
                    "error",
                    "integrity",
                    f"분석 후 원본 상태를 확인할 수 없습니다: {exc}",
                    "원본 파일 위치와 무결성을 직접 확인하세요.",
                ),
                source_id=source_id,
                run_id=run_id,
            )
        if changed:
            failures += 1
            store.add_diagnostic(
                Diagnostic(
                    "warning",
                    "integrity",
                    "분석 전후 원본 파일 크기 또는 수정 시각이 달라졌습니다.",
                    "변경되지 않은 원본 사본으로 다시 분석하세요.",
                ),
                source_id=source_id,
                run_id=run_id,
            )

        hash_result = hash_job.result(timeout=0)
        if hash_result is not None:
            self._apply_hash_result(store, source_id, hash_generation, hash_result)
            if hash_result.status in {"failed", "changed"}:
                failures += 1
        else:
            # Returning results is not held hostage by hashing. The status is
            # honestly pending if a short-lived CLI exits before completion.
            store.update_source_hash(source_id, None, "pending", generation=hash_generation)
            self._finish_hash_later(case.root, source_id, hash_generation, hash_job)

        if cancelled or cancel.is_set():
            status = RunStatus.CANCELLED
            coverage = Coverage.PARTIAL
            summary.cancelled = True
        elif unsupported:
            status = RunStatus.PARTIAL
            coverage = Coverage.UNSUPPORTED
        elif failures:
            status = RunStatus.PARTIAL
            coverage = Coverage.PARTIAL
        elif budget_limited:
            status = RunStatus.COMPLETED
            coverage = Coverage.PARTIAL
        else:
            status = RunStatus.COMPLETED
            coverage = Coverage.COMPLETE
        store.finish_run(
            run_id,
            status=status,
            coverage=coverage,
            records_read=records_read,
            failures=failures,
            skip_reason=("분석기 미지원 또는 도구 부재" if unsupported else None),
        )
        summary.failures += failures
        summary.partial = summary.partial or coverage is not Coverage.COMPLETE

    def _consume(
        self,
        choice: AnalyzerChoice,
        context: AnalysisContext,
        store: CaseStore,
        run_id: int,
        progress_callback: ProgressCallback | None,
        summary: AnalysisSummary,
    ) -> dict[str, Any]:
        records_read = 0
        failures = 0
        budget_limited = False
        cancelled = False
        incomplete = False
        pending = 0
        try:
            iterator: Iterator[AnalysisItem] = choice.analyzer.analyze(context)
            for item in iterator:
                if isinstance(item, Progress):
                    records_read = max(records_read, item.processed)
                    if progress_callback is not None:
                        with suppress(Exception):
                            progress_callback(item)
                    continue
                if isinstance(item, AnalysisEvent):
                    store.add_event(run_id, item, commit=False)
                    summary.events += 1
                elif isinstance(item, Finding):
                    store.add_finding(run_id, item, commit=False)
                    summary.findings += 1
                elif isinstance(item, Artifact):
                    store.add_artifact(run_id, item, commit=False)
                elif isinstance(item, Diagnostic):
                    store.add_diagnostic(
                        item, source_id=context.source_id, run_id=run_id, commit=False
                    )
                    if item.stage == "budget" or any(
                        marker in item.message for marker in ("출력 제한", "제한 시간")
                    ):
                        budget_limited = True
                    elif item.stage == "cancel":
                        cancelled = True
                    elif item.level.casefold() == "error":
                        failures += 1
                    elif item.stage in {"decode", "parse", "pcap.parse", "read", "timestamp"}:
                        incomplete = True
                else:
                    raise TypeError(f"알 수 없는 AnalysisItem: {type(item).__name__}")
                pending += 1
                if pending >= self.config.analysis.batch_size:
                    store.connection.commit()
                    pending = 0
            store.connection.commit()
        except sqlite3.Error:
            store.connection.rollback()
            raise
        except BaseException:
            # Items yielded before an analyzer/cancellation failure are valid
            # partial evidence and must survive the module boundary.
            store.connection.commit()
            raise
        return {
            "records_read": records_read,
            "failures": failures,
            "incomplete": incomplete,
            "budget_limited": budget_limited,
            "cancelled": cancelled,
        }

    @staticmethod
    def _apply_hash_result(
        store: CaseStore,
        source_id: int,
        generation: str,
        result: HashResult,
    ) -> None:
        applied = store.update_source_hash(
            source_id, result.sha256, result.status, generation=generation
        )
        if applied and result.status == "changed":
            store.mark_source_changed(source_id)

    @staticmethod
    def _finish_hash_later(
        case_root: Path,
        source_id: int,
        generation: str,
        job: HashJob,
    ) -> None:
        def update() -> None:
            result = job.result()
            if result is None:
                return
            try:
                with CaseStore(case_root, create=False) as background_store:
                    applied = background_store.update_source_hash(
                        source_id,
                        result.sha256,
                        result.status,
                        generation=generation,
                    )
                    if applied and result.status == "changed":
                        background_store.mark_source_changed(source_id)
            except Exception:
                # Pending remains truthful and can be recomputed on a later run.
                return

        Thread(target=update, name=f"fieldtrace-hash-db-{source_id}", daemon=True).start()

    @staticmethod
    def _write_trace(case: CasePaths, run_id: int, analyzer: str, trace: str) -> None:
        safe_name = "".join(character if character.isalnum() else "_" for character in analyzer)
        path = case.diagnostics / f"run-{run_id}-{safe_name}.log"
        try:
            with path.open("a", encoding="utf-8") as stream:
                stream.write(trace)
                stream.write("\n")
        except OSError:
            pass

    def _collect_files(
        self,
        paths: Path | str | Iterable[Path | str],
        *,
        excluded: Path | None = None,
    ) -> list[Path]:
        supplied = [paths] if isinstance(paths, (str, Path)) else list(paths)
        if not supplied:
            return []
        files: list[Path] = []
        seen: set[Path] = set()
        excluded_roots = [self.config.paths.cases.expanduser().resolve()]
        if excluded is not None:
            excluded_roots.append(excluded)
        for value in supplied:
            path = Path(value).expanduser().resolve()
            if not path.exists():
                raise InputError(f"입력 경로를 찾을 수 없습니다: {path}")
            candidates = [path] if path.is_file() else sorted(path.rglob("*"))
            for candidate in candidates:
                try:
                    resolved = candidate.resolve()
                    if any(resolved.is_relative_to(root) for root in excluded_roots):
                        continue
                    if (
                        not resolved.is_file()
                        or resolved.name == ".gitkeep"
                        or resolved in seen
                    ):
                        continue
                except OSError:
                    continue
                seen.add(resolved)
                files.append(resolved)
        return files

    def search(
        self,
        case: Path | str,
        text: str,
        limit: int = 100,
        *,
        latest_only: bool = True,
    ) -> list[SearchHit]:
        with CaseStore(case, create=False) as store:
            return literal_search(store, text, limit=limit, latest_only=latest_only)

    def timeline(
        self,
        case: Path | str,
        limit: int | None = None,
        *,
        latest_only: bool = True,
    ) -> list[TimelineEntry]:
        with CaseStore(case, create=False) as store:
            return build_timeline(store, limit=limit, latest_only=latest_only)

    def evidence(self, case: Path | str, kind: str, entity_id: int) -> EvidenceDetail | None:
        with CaseStore(case, create=False) as store:
            return evidence_detail(store, kind, entity_id)

    def report_bundle(self, case: Path | str, *, latest_only: bool = True) -> dict[str, Any]:
        with CaseStore(case, create=False) as store:
            return build_report_bundle(store, latest_only=latest_only)


def exit_code(summary: AnalysisSummary) -> int:
    """Map a completed request to the documented non-interactive exit contract."""

    if summary.cancelled:
        return 130
    # The documented quick record/time budget is an intentional successful
    # stop. It remains coverage=partial in SQLite but is not an exit failure.
    if summary.failures:
        return 1
    return 0
