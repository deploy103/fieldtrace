"""High-level interactive menu orchestration.

The controller protocol is the explicit UI/core seam.  Implementations belong
in the CLI/core composition layer; this module never queries SQLite or launches
an analyzer itself.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any, Protocol

from rich.console import Console
from rich.table import Table
from rich.text import Text

from fieldtrace.core.models import AnalysisSummary, Diagnostic, EvidenceRef, Finding
from fieldtrace.ui.menus import (
    FileChoice,
    InputFunction,
    MenuOption,
    MenuStatus,
    TaskOption,
    available_tasks,
    choose_analysis_mode,
    choose_custom_tasks,
    choose_files,
    choose_one,
    choose_result_action,
    choose_source_format,
)
from fieldtrace.ui.presentation import (
    render_error,
    render_evidence,
    render_result,
)
from fieldtrace.ui.safety import strip_terminal_controls


@dataclass(frozen=True, slots=True)
class ResultView:
    """Presentation data returned by analyze/open-results core services."""

    summary: AnalysisSummary | Mapping[str, Any]
    findings: tuple[Finding | Mapping[str, Any], ...] = ()
    diagnostics: tuple[Diagnostic | Mapping[str, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class DetectionView:
    format: str
    reason: str
    confidence: float = 0.0
    available: bool = True
    manual_selection_recommended: bool = False


class MenuController(Protocol):
    """Required core facade for :func:`run_menu`.

    ``list`` must return ordinary input files only. ``detect`` performs bounded
    content probing. ``analyze`` owns persistence/cancellation and should return
    committed partial results on Ctrl+C. Search/timeline/evidence/report operate
    on the current case/latest selected runs unless the core exposes a different
    scope in the returned data.
    """

    default_directory: Path

    def list(self, directory: Path) -> Sequence[Path]: ...

    def detect(self, paths: Sequence[Path]) -> Mapping[Path, DetectionView | Mapping[str, Any]]: ...

    def tasks(
        self, paths: Sequence[Path], detections: Mapping[Path, object]
    ) -> Sequence[TaskOption]: ...

    def has_results(self, paths: Sequence[Path]) -> bool: ...

    def analyze(
        self,
        paths: Sequence[Path],
        *,
        profile: str,
        selected_tasks: frozenset[str],
        manual_formats: Mapping[Path, str],
    ) -> ResultView: ...

    def open_results(self, paths: Sequence[Path]) -> ResultView: ...

    def search(self, text: str) -> Sequence[object]: ...

    def timeline(self) -> Sequence[object]: ...

    def evidence(self, item: object) -> EvidenceRef | Mapping[str, Any] | None: ...

    def report(self, format: str) -> Path: ...


def _as_mapping(value: object) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    values = getattr(value, "__dict__", None)
    return values if isinstance(values, Mapping) else {}


def _result(value: ResultView | Mapping[str, Any] | object) -> ResultView:
    if isinstance(value, ResultView):
        return value
    data = _as_mapping(value)
    return ResultView(
        summary=data.get("summary", data),
        findings=tuple(data.get("findings", ()) or ()),
        diagnostics=tuple(data.get("diagnostics", ()) or ()),
    )


def _format_of(value: object) -> str:
    data = _as_mapping(value)
    detected = data.get("format", data.get("detected_format"))
    if detected is None:
        detected = getattr(value, "format", getattr(value, "detected_format", "unknown"))
    return str(getattr(detected, "value", detected))


def _choose_item_evidence(
    controller: MenuController,
    items: Sequence[object],
    *,
    title: str,
    input_fn: InputFunction,
    console: Console,
) -> MenuStatus:
    if not items:
        return MenuStatus.BACK
    options: list[MenuOption[object]] = []
    for item in items:
        data = _as_mapping(item)
        label = data.get("title", data.get("summary", data.get("observation", "결과")))
        options.append(MenuOption(strip_terminal_controls(label), item))
    chosen = choose_one(title, options, input_fn=input_fn, console=console)
    if chosen.status is MenuStatus.QUIT:
        return MenuStatus.QUIT
    if chosen.status is not MenuStatus.SELECTED or chosen.value is None:
        return MenuStatus.BACK
    try:
        evidence = controller.evidence(chosen.value)
    except Exception as error:
        render_error("원문 근거 조회", error, "다른 후보를 선택하거나 진단을 확인하세요.", console=console)
        return MenuStatus.BACK
    if evidence is None:
        console.print("연결된 원문 근거가 없습니다.", markup=False)
    else:
        render_evidence(evidence, console=console)
    return MenuStatus.SELECTED


def _render_rows(title: str, rows: Sequence[object], *, console: Console) -> None:
    if not rows:
        console.print(f"{title}: 결과가 없습니다.", markup=False)
        return
    records = [_as_mapping(row) for row in rows]
    preferred = (
        "timestamp_utc",
        "timestamp_raw",
        "category",
        "summary",
        "title",
        "preview",
        "evidence_locator",
        "locator",
    )
    keys = [key for key in preferred if any(key in row for row in records)]
    if not keys:
        keys = list(dict.fromkeys(key for row in records[:10] for key in row))[:5]
    table = Table(title=title, expand=True)
    table.add_column("번호", width=5)
    for key in keys:
        table.add_column(key, overflow="fold")
    for index, row in enumerate(records, 1):
        table.add_row(
            str(index), *(Text(strip_terminal_controls(row.get(key, ""))) for key in keys)
        )
    console.print(table)


def _result_loop(
    controller: MenuController,
    result: ResultView,
    *,
    input_fn: InputFunction,
    console: Console,
) -> MenuStatus | str:
    render_result(result.summary, result.findings, result.diagnostics, console=console)
    if result.findings:
        candidate_status = _choose_item_evidence(
            controller,
            result.findings,
            title="후보 번호를 선택해 원문 근거 확인 (0: 결과 메뉴)",
            input_fn=input_fn,
            console=console,
        )
        if candidate_status is MenuStatus.QUIT:
            return MenuStatus.QUIT
    while True:
        action = choose_result_action(input_fn=input_fn, console=console)
        if action.status is MenuStatus.QUIT or action.value == "quit":
            return MenuStatus.QUIT
        if action.status is MenuStatus.BACK:
            candidate_status = _choose_item_evidence(
                controller,
                result.findings,
                title="후보 번호를 선택해 원문 근거 확인 (0: 결과 메뉴)",
                input_fn=input_fn,
                console=console,
            )
            if candidate_status is MenuStatus.QUIT:
                return MenuStatus.QUIT
            continue
        if action.value == "other_file":
            return "other_file"
        try:
            if action.value == "search":
                try:
                    raw = input_fn("찾을 문자열 (0: 뒤로, q: 종료): ")
                except EOFError:
                    return MenuStatus.QUIT
                except KeyboardInterrupt:
                    continue
                if raw.casefold() == "q":
                    return MenuStatus.QUIT
                if raw == "0" or not raw:
                    continue
                rows = tuple(controller.search(raw))
                _render_rows("검색 결과", rows, console=console)
                evidence_status = _choose_item_evidence(
                    controller,
                    rows,
                    title="검색 결과 번호로 근거 확인",
                    input_fn=input_fn,
                    console=console,
                )
                if evidence_status is MenuStatus.QUIT:
                    return MenuStatus.QUIT
            elif action.value == "timeline":
                rows = tuple(controller.timeline())
                _render_rows("시간순 보기 (시간 미상은 별도 표시)", rows, console=console)
                evidence_status = _choose_item_evidence(
                    controller,
                    rows,
                    title="이벤트 번호로 근거 확인",
                    input_fn=input_fn,
                    console=console,
                )
                if evidence_status is MenuStatus.QUIT:
                    return MenuStatus.QUIT
            elif action.value == "detail":
                console.print("상세 분석은 분석 항목 직접 선택에서 실행할 수 있습니다.", markup=False)
            elif action.value == "report":
                report_format = choose_one(
                    "보고서 형식",
                    (
                        MenuOption("Markdown", "markdown"),
                        MenuOption("JSON (원문 보존)", "json"),
                        MenuOption("CSV (스프레드시트 안전 표시용)", "csv"),
                    ),
                    default=1,
                    input_fn=input_fn,
                    console=console,
                )
                if report_format.status is MenuStatus.QUIT:
                    return MenuStatus.QUIT
                if report_format.status is MenuStatus.SELECTED and report_format.value:
                    path = controller.report(report_format.value)
                    console.print(Text(f"보고서 저장: {strip_terminal_controls(path)}"))
        except KeyboardInterrupt:
            console.print("작업을 취소했습니다. 저장된 결과로 돌아갑니다.", markup=False)
        except Exception as error:
            render_error("결과 작업", error, "결과 메뉴에서 다시 시도하세요.", console=console)


def run_menu(
    controller: MenuController,
    *,
    input_fn: InputFunction = input,
    console: Console | None = None,
) -> int:
    """Run the complete file → analysis → evidence → result-actions flow."""

    console = console or Console()
    directory = Path(controller.default_directory)
    while True:
        selection = choose_files(
            directory,
            input_fn=input_fn,
            console=console,
            file_provider=controller.list,
            detection_provider=controller.detect,
        )
        if selection.status is MenuStatus.QUIT:
            return 0
        if selection.status is MenuStatus.BACK:
            return 0
        assert isinstance(selection.value, FileChoice)
        paths = selection.value.paths
        directory = selection.value.directory
        try:
            detections = controller.detect(paths)
        except Exception as error:
            render_error("파일 형식 감지", error, "수동 형식을 선택해 계속할 수 있습니다.", console=console)
            detections = {}
        manual_formats: dict[Path, str] = {}
        abandoned = False
        for path in paths:
            detected = detections.get(path) or detections.get(str(path))  # type: ignore[arg-type]
            detected_format = _format_of(detected) if detected is not None else "unknown"
            detected_data = _as_mapping(detected) if detected is not None else {}
            manual_recommended = bool(
                detected_data.get(
                    "manual_selection_recommended",
                    getattr(detected, "manual_selection_recommended", False),
                )
            )
            if detected_format not in {"unknown", "", "none"} and not manual_recommended:
                continue
            reason = detected_data.get("reason", getattr(detected, "reason", ""))
            console.print(
                Text(
                    f"형식 확인이 필요합니다: {strip_terminal_controls(path.name)}"
                    + (f" — {strip_terminal_controls(reason)}" if reason else "")
                )
            )
            manual = choose_source_format(
                detected=detected_format if detected_format != "unknown" else None,
                input_fn=input_fn,
                console=console,
            )
            if manual.status is MenuStatus.QUIT:
                return 0
            if manual.status is MenuStatus.BACK or manual.value is None:
                abandoned = True
                break
            manual_formats[path] = manual.value
        if abandoned:
            continue
        effective_detections = dict(detections)
        for path, selected_format in manual_formats.items():
            effective_detections[path] = DetectionView(
                selected_format, "사용자가 형식을 직접 지정함", confidence=1.0
            )
        try:
            task_options = tuple(controller.tasks(paths, effective_detections))
        except Exception:
            task_options = available_tasks(())
        usable_labels = ", ".join(task.label for task in task_options if task.available)
        recommendation = usable_labels or "메타데이터와 공통 검색"
        try:
            has_results = controller.has_results(paths)
        except Exception:
            has_results = False
        mode = choose_analysis_mode(
            recommendation=recommendation,
            existing_results=has_results,
            input_fn=input_fn,
            console=console,
        )
        if mode.status is MenuStatus.QUIT:
            return 0
        if mode.status is MenuStatus.BACK or mode.value is None:
            continue
        selected_tasks: frozenset[str] = frozenset()
        if mode.value == "custom":
            custom = choose_custom_tasks(task_options, input_fn=input_fn, console=console)
            if custom.status is MenuStatus.QUIT:
                return 0
            if custom.status is MenuStatus.BACK or custom.value is None:
                continue
            selected_tasks = custom.value
        try:
            if mode.value == "existing":
                result = _result(controller.open_results(paths))
            else:
                result = _result(
                    controller.analyze(
                        paths,
                        profile=mode.value,
                        selected_tasks=selected_tasks,
                        manual_formats=manual_formats,
                    )
                )
        except KeyboardInterrupt:
            console.print("분석을 취소했습니다. 이미 저장된 부분 결과를 확인합니다.", markup=False)
            try:
                result = _result(controller.open_results(paths))
            except Exception as error:
                render_error("부분 결과 열기", error, "다른 파일을 선택하거나 진단을 확인하세요.", console=console)
                continue
        except Exception as error:
            render_error("분석", error, "진단을 확인한 뒤 다른 파일 또는 형식으로 다시 시도하세요.", console=console)
            continue
        destination = _result_loop(controller, result, input_fn=input_fn, console=console)
        if destination is MenuStatus.QUIT:
            return 0
