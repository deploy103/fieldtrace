"""Typer entry point and composition layer for FieldTrace."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from fieldtrace.core import (
    FieldTraceService,
    InputError,
    case_paths,
    create_case,
    exit_code,
    load_config,
    run_doctor,
)
from fieldtrace.core.models import AnalysisSummary, Environment, Progress, SourceFormat
from fieldtrace.core.state import LocalState, StateStore
from fieldtrace.reports import export_report
from fieldtrace.ui import (
    ANALYSIS_TASKS,
    DETAIL_TASKS,
    DetectionView,
    ResultView,
    TaskOption,
    analysis_progress,
    render_error,
    render_result,
    run_menu,
    strip_terminal_controls,
)

app = typer.Typer(
    name="fieldtrace",
    help="오프라인 CTF 패킷·로그 증거 분석기",
    no_args_is_help=False,
    pretty_exceptions_enable=False,
    rich_markup_mode=None,
)
console = Console()

_FORMAT_ALIASES = {
    "text": SourceFormat.GENERIC_TEXT,
    "generic": SourceFormat.GENERIC_TEXT,
    "generic_text": SourceFormat.GENERIC_TEXT,
    "web": SourceFormat.WEB,
    "auth": SourceFormat.LINUX_AUTH,
    "linux_auth": SourceFormat.LINUX_AUTH,
    "pcap": SourceFormat.PCAP,
    "pcapng": SourceFormat.PCAP,
    "evtx": SourceFormat.EVTX,
}
_TASKS_BY_FORMAT = {
    SourceFormat.GENERIC_TEXT.value: {"network_summary", "literal_search"},
    SourceFormat.WEB.value: {"network_summary", "http_requests", "literal_search"},
    SourceFormat.LINUX_AUTH.value: {
        "login_activity",
        "executed_commands",
        "literal_search",
    },
    SourceFormat.PCAP.value: {
        "network_summary",
        "http_requests",
        "literal_search",
        "tcp_streams",
        "object_extraction",
    },
    SourceFormat.EVTX.value: {
        "network_summary",
        "login_activity",
        "executed_commands",
        "literal_search",
    },
}


def _source_format(value: str | None) -> SourceFormat | None:
    if value is None:
        return None
    try:
        return _FORMAT_ALIASES[value.casefold()]
    except KeyError as exc:
        choices = ", ".join(sorted(_FORMAT_ALIASES))
        raise InputError(f"지원하지 않는 형식입니다: {value} (가능: {choices})") from exc


def _diagnostics(bundle: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    return tuple(bundle.get("diagnostics", ()) or ())


def _with_evidence(record: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(record)
    if "evidence" not in result and result.get("evidence_kind"):
        result["evidence"] = {
            "source_id": result.get("source_id"),
            "kind": result.get("evidence_kind"),
            "locator": result.get("evidence_locator"),
            "preview": result.get("evidence_preview", ""),
            "truncated": bool(result.get("evidence_truncated")),
        }
    return result


def _view_from_bundle(bundle: Mapping[str, Any]) -> ResultView:
    runs = tuple(bundle.get("runs", ()) or ())
    counts = bundle.get("summary", {})
    failures = sum(int(run.get("failures", 0)) for run in runs)
    partial = any(
        run.get("status") != "completed" or run.get("coverage") != "complete" for run in runs
    )
    summary = AnalysisSummary(
        case_dir=Path(str(bundle.get("case", {}).get("directory", "."))),
        run_ids=[int(run["id"]) for run in runs],
        source_ids=[int(item["id"]) for item in bundle.get("sources", ())],
        events=int(counts.get("events", len(bundle.get("events", ())))),
        findings=int(counts.get("findings", len(bundle.get("findings", ())))),
        failures=failures,
        partial=partial,
        cancelled=any(run.get("status") == "cancelled" for run in runs),
    )
    findings = tuple(_with_evidence(item) for item in bundle.get("findings", ()))
    return ResultView(summary, findings, _diagnostics(bundle))


def _merge_summary(target: AnalysisSummary, source: AnalysisSummary) -> None:
    for descriptor in fields(AnalysisSummary):
        name = descriptor.name
        if name == "case_dir":
            continue
        current = getattr(target, name)
        incoming = getattr(source, name)
        if isinstance(current, list):
            current.extend(incoming)
        elif isinstance(current, bool):
            setattr(target, name, current or incoming)
        elif isinstance(current, int):
            setattr(target, name, current + incoming)


@dataclass(slots=True)
class InteractiveController:
    service: FieldTraceService
    default_directory: Path
    state_store: StateStore
    state: LocalState
    terminal: Console
    current_case: Path | None = None
    current_paths: tuple[Path, ...] = ()
    _cached_environment: Environment | None = field(default=None, init=False, repr=False)

    def list(self, directory: Path) -> Sequence[Path]:
        try:
            return tuple(
                sorted(
                    (
                        path
                        for path in directory.iterdir()
                        if path.is_file() and path.name != ".gitkeep"
                    ),
                    key=lambda path: path.name.casefold(),
                )
            )
        except OSError:
            return ()

    def detect(self, paths: Sequence[Path]) -> Mapping[Path, DetectionView]:
        detected: dict[Path, DetectionView] = {}
        for path in paths:
            try:
                result = self.service.detect(path)
            except (OSError, ValueError) as exc:
                detected[path] = DetectionView("unknown", str(exc), available=False)
            else:
                detected[path] = DetectionView(
                    format=result.format.value,
                    reason=result.reason,
                    confidence=result.confidence,
                    available=self._format_available(result.format),
                    manual_selection_recommended=result.manual_selection_recommended,
                    encoding_required="인코딩 선택 필요" in result.reason,
                )
        return detected

    def _format_available(self, source_format: SourceFormat) -> bool:
        environment = self._environment()
        if source_format is SourceFormat.PCAP:
            return bool(environment.tshark_path)
        if source_format is SourceFormat.EVTX:
            return bool(environment.python_evtx_version)
        return True

    def _environment(self) -> Environment:
        from fieldtrace.core import detect_environment

        if self._cached_environment is None:
            self._cached_environment = detect_environment(runner=self.service.runner)
        return self._cached_environment

    def tasks(
        self, paths: Sequence[Path], detections: Mapping[Path, object]
    ) -> Sequence[TaskOption]:
        del paths
        available: set[str] = set()
        for detection in detections.values():
            value = getattr(detection, "format", None)
            if isinstance(detection, Mapping):
                value = detection.get("format", value)
            normalized = str(getattr(value, "value", value))
            environment = self._environment()
            if normalized == SourceFormat.PCAP.value and not environment.tshark_path:
                continue
            if normalized == SourceFormat.EVTX.value and not environment.python_evtx_version:
                continue
            available.update(_TASKS_BY_FORMAT.get(normalized, set()))
        return tuple(
            TaskOption(
                task.key,
                task.label,
                task.key in available,
                "선택한 파일에서 사용할 수 없거나 필요한 도구가 없습니다",
            )
            for task in ANALYSIS_TASKS
        )

    def _usable_case(self) -> Path | None:
        candidate = self.current_case or self.state.last_case
        if candidate is None or not case_paths(candidate).database.is_file():
            return None
        return candidate

    def has_results(self, paths: Sequence[Path]) -> bool:
        case = self._usable_case()
        if case is None:
            return False
        try:
            bundle = self.service.report_bundle(case)
        except (OSError, ValueError):
            return False
        wanted = {str(path.resolve()) for path in paths}
        return any(str(source.get("path")) in wanted for source in bundle.get("sources", ()))

    def analyze(
        self,
        paths: Sequence[Path],
        *,
        profile: str,
        selected_tasks: frozenset[str],
        manual_formats: Mapping[Path, str],
        manual_encodings: Mapping[Path, str],
    ) -> ResultView:
        case = create_case(self.service.config.paths.cases)
        combined = AnalysisSummary(case.root)
        with analysis_progress(console=self.terminal) as display:
            progress_id = display.add_task("분석 준비", total=None)
            for path in paths:
                current_name = strip_terminal_controls(path.name)

                def update(item: Progress, *, name: str = current_name) -> None:
                    message = strip_terminal_controls(item.message)
                    description = f"{name} · {item.stage}"
                    if message:
                        description += f" · {message}"
                    display.update(progress_id, description=description, completed=item.processed)

                summary = self.service.analyze(
                    path,
                    case_dir=case.root,
                    profile=profile,
                    forced_type=manual_formats.get(path),
                    selected_tasks=selected_tasks,
                    progress=update,
                    text_encoding=manual_encodings.get(path),
                )
                _merge_summary(combined, summary)
                if summary.cancelled:
                    break
        self.current_case = case.root
        self.current_paths = tuple(paths)
        self.state.last_directory = paths[0].parent if paths else self.default_directory
        self.state.last_case = case.root
        self.state_store.save(self.state)
        bundle = self.service.report_bundle(case.root)
        view = _view_from_bundle(bundle)
        return ResultView(
            combined,
            view.findings,
            view.diagnostics,
            detail_available=self._detail_available(),
        )

    def open_results(self, paths: Sequence[Path]) -> ResultView:
        del paths
        case = self._usable_case()
        if case is None:
            raise FileNotFoundError("최근 사례 결과를 찾을 수 없습니다")
        self.current_case = case
        bundle = self.service.report_bundle(case)
        self.current_paths = tuple(Path(str(source["path"])) for source in bundle["sources"])
        view = _view_from_bundle(bundle)
        return ResultView(
            view.summary,
            view.findings,
            view.diagnostics,
            detail_available=self._detail_available(),
        )

    def _detail_available(self) -> bool:
        if not self._environment().tshark_path:
            return False
        for path in self.current_paths:
            try:
                if self.service.detect(path).format is SourceFormat.PCAP:
                    return True
            except (OSError, ValueError):
                continue
        return False

    def detail_tasks(self) -> Sequence[TaskOption]:
        available = self._detail_available()
        return tuple(
            TaskOption(
                task.key,
                task.label,
                available,
                "선택한 사례에 사용 가능한 PCAP과 TShark가 필요합니다",
            )
            for task in DETAIL_TASKS
        )

    def analyze_detail(self, selected_tasks: frozenset[str]) -> ResultView:
        case = self._usable_case()
        if case is None:
            raise FileNotFoundError("상세 분석할 최근 사례 결과가 없습니다")
        packet_paths: list[Path] = []
        for path in self.current_paths:
            try:
                if self.service.detect(path).format is SourceFormat.PCAP:
                    packet_paths.append(path)
            except (OSError, ValueError):
                continue
        if not packet_paths:
            raise FileNotFoundError("상세 분석할 PCAP/PCAPNG 입력을 찾을 수 없습니다")
        combined = AnalysisSummary(case)
        comprehensive_tasks = selected_tasks | {
            "network_summary",
            "http_requests",
            "literal_search",
        }
        with analysis_progress(console=self.terminal) as display:
            progress_id = display.add_task("상세 분석 준비", total=None)
            for path in packet_paths:

                def update(item: Progress, *, name: str = path.name) -> None:
                    message = strip_terminal_controls(item.message)
                    description = f"{strip_terminal_controls(name)} · {item.stage}"
                    if message:
                        description += f" · {message}"
                    display.update(progress_id, description=description, completed=item.processed)

                summary = self.service.analyze(
                    path,
                    case_dir=case,
                    profile="custom",
                    forced_type="pcap",
                    selected_tasks=comprehensive_tasks,
                    progress=update,
                )
                _merge_summary(combined, summary)
        bundle = self.service.report_bundle(case)
        view = _view_from_bundle(bundle)
        return ResultView(
            combined,
            view.findings,
            view.diagnostics,
            detail_available=True,
        )

    def search(self, text: str) -> Sequence[object]:
        case = self._usable_case()
        if case is None:
            return ()
        return self.service.search(case, text)

    def timeline(self) -> Sequence[object]:
        case = self._usable_case()
        if case is None:
            return ()
        return self.service.timeline(case)

    def evidence(self, item: object) -> object | None:
        case = self._usable_case()
        if case is None:
            return None
        data = asdict(item) if hasattr(item, "__dataclass_fields__") else item
        if not isinstance(data, Mapping):
            return None
        if data.get("entity_type") and data.get("entity_id"):
            kind = str(data["entity_type"])
            entity_id = int(data["entity_id"])
        elif data.get("event_id"):
            kind, entity_id = "event", int(data["event_id"])
        elif data.get("rule_id") and data.get("id"):
            kind, entity_id = "finding", int(data["id"])
        elif data.get("category") and data.get("id"):
            kind, entity_id = "event", int(data["id"])
        else:
            evidence = data.get("evidence")
            return evidence if isinstance(evidence, Mapping) else None
        return self.service.evidence(case, kind, entity_id)

    def report(self, format: str) -> Path:
        case = self._usable_case()
        if case is None:
            raise FileNotFoundError("보고할 최근 사례 결과가 없습니다")
        extension = "md" if format == "markdown" else format
        stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
        output = case_paths(case).reports / f"fieldtrace-{stamp}.{extension}"
        return export_report(self.service.report_bundle(case), output, format)


def _make_service(config_path: Path | None) -> FieldTraceService:
    return FieldTraceService(load_config(config_path))


def _run_interactive(path: Path | None, config_path: Path | None) -> int:
    try:
        service = _make_service(config_path)
        state_store = StateStore()
        state = state_store.load()
        if path is not None:
            requested = path.expanduser()
            directory = requested if requested.is_dir() else requested.parent
        elif state.last_directory is not None and state.last_directory.is_dir():
            directory = state.last_directory
        else:
            directory = service.config.paths.input
        controller = InteractiveController(service, directory, state_store, state, console)
        return run_menu(controller, console=console)
    except (OSError, ValueError) as exc:
        render_error("메뉴 시작", exc, "입력 폴더와 설정 파일을 확인하세요.", console=console)
        return 2


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="TOML 설정 파일"),
    ] = None,
) -> None:
    """명령이 없으면 한국어 숫자 메뉴를 엽니다."""

    ctx.ensure_object(dict)
    ctx.obj["config"] = config
    if ctx.invoked_subcommand is None:
        raise typer.Exit(_run_interactive(None, config))


@app.command("menu")
def menu_command(
    ctx: typer.Context,
    path: Annotated[Path | None, typer.Argument(help="처음 탐색할 파일 또는 폴더")] = None,
) -> None:
    """지정 위치에서 한국어 숫자 메뉴를 엽니다."""

    raise typer.Exit(_run_interactive(path, ctx.obj.get("config")))


@app.command("analyze")
def analyze_command(
    ctx: typer.Context,
    paths: Annotated[list[Path], typer.Argument(help="분석할 파일 또는 폴더")],
    profile: Annotated[str, typer.Option("--profile", help="quick, full, custom")] = "quick",
    case: Annotated[Path | None, typer.Option("--case", help="사례 결과 폴더")] = None,
    input_type: Annotated[
        str | None,
        typer.Option("--type", help="text, web, linux_auth, pcap, evtx"),
    ] = None,
    tasks: Annotated[
        str | None,
        typer.Option("--tasks", help="custom 항목 키를 쉼표로 구분"),
    ] = None,
    encoding: Annotated[
        str | None,
        typer.Option("--encoding", help="utf-8, utf-16, cp949, euc-kr 등"),
    ] = None,
) -> None:
    """질문 없이 파일 또는 폴더를 분석합니다."""

    try:
        service = _make_service(ctx.obj.get("config"))
        forced = _source_format(input_type)
        selected = tuple(item.strip() for item in (tasks or "").split(",") if item.strip())
        with analysis_progress(console=console) as display:
            progress_id = display.add_task("분석 준비", total=None)

            def update(item: Progress) -> None:
                message = strip_terminal_controls(item.message)
                label = f"{item.stage}" + (f" · {message}" if message else "")
                display.update(progress_id, description=label, completed=item.processed)

            summary = service.analyze(
                paths,
                case_dir=case,
                profile=profile,
                forced_type=forced,
                selected_tasks=selected,
                progress=update,
                text_encoding=encoding,
            )
        bundle = service.report_bundle(summary.case_dir)
        view = _view_from_bundle(bundle)
        render_result(summary, view.findings, view.diagnostics, console=console)
        console.print(Text(f"사례 폴더: {summary.case_dir}"))
        raise typer.Exit(exit_code(summary))
    except typer.Exit:
        raise
    except (OSError, ValueError) as exc:
        render_error("분석", exc, "입력 경로, 형식, 프로필을 확인하세요.", console=console)
        raise typer.Exit(2) from exc


def _rows_table(title: str, rows: Sequence[object], columns: Sequence[str]) -> None:
    table = Table(title=title, expand=True)
    for column in columns:
        table.add_column(column, overflow="fold")
    for row in rows:
        data = asdict(row) if hasattr(row, "__dataclass_fields__") else row
        if not isinstance(data, Mapping):
            continue
        table.add_row(*(Text(strip_terminal_controls(data.get(column, ""))) for column in columns))
    console.print(table)


@app.command("search")
def search_command(
    ctx: typer.Context,
    case: Annotated[Path, typer.Option("--case", help="사례 결과 폴더")],
    text: Annotated[str, typer.Option("--text", help="찾을 literal 문자열")],
    limit: Annotated[int, typer.Option("--limit", min=1, max=10000)] = 100,
) -> None:
    """사례의 최신 run에서 문자열을 literal로 검색합니다."""

    try:
        rows = _make_service(ctx.obj.get("config")).search(case, text, limit)
    except (OSError, ValueError) as exc:
        render_error("검색", exc, "사례 경로와 검색어를 확인하세요.", console=console)
        raise typer.Exit(2) from exc
    _rows_table("검색 결과", rows, ("entity_type", "entity_id", "source_id", "preview"))


@app.command("timeline")
def timeline_command(
    ctx: typer.Context,
    case: Annotated[Path, typer.Option("--case", help="사례 결과 폴더")],
    limit: Annotated[int | None, typer.Option("--limit", min=1)] = None,
) -> None:
    """정규화된 시각순 결과와 시간 미상 결과를 표시합니다."""

    try:
        rows = _make_service(ctx.obj.get("config")).timeline(case, limit)
    except (OSError, ValueError) as exc:
        render_error("시간순 보기", exc, "사례 경로를 확인하세요.", console=console)
        raise typer.Exit(2) from exc
    known = [row for row in rows if row.timestamp_utc]
    unknown = [row for row in rows if not row.timestamp_utc]
    columns = ("timestamp_utc", "timestamp_raw", "category", "summary", "evidence_locator")
    _rows_table("시간순 보기", known, columns)
    _rows_table("시간 미상", unknown, columns)


@app.command("correlate")
def correlate_command(
    ctx: typer.Context,
    case: Annotated[Path, typer.Option("--case", help="사례 결과 폴더")],
    value: Annotated[str | None, typer.Option("--value", help="정확히 일치시킬 값")] = None,
    kind: Annotated[
        str | None, typer.Option("--kind", help="ip, domain, account, filename")
    ] = None,
    min_sources: Annotated[int, typer.Option("--min-sources", min=1)] = 2,
    limit: Annotated[int, typer.Option("--limit", min=1, max=10000)] = 100,
) -> None:
    """여러 입력 자료에서 함께 관측된 식별자를 표시합니다."""

    try:
        rows = _make_service(ctx.obj.get("config")).correlations(
            case,
            value=value,
            kind=kind,
            min_sources=min_sources,
            limit=limit,
        )
    except (OSError, ValueError) as exc:
        render_error("교차 자료", exc, "사례 경로와 종류·값을 확인하세요.", console=console)
        raise typer.Exit(2) from exc
    _rows_table(
        "교차 자료 관측(동일 값은 인과관계를 뜻하지 않음)",
        rows,
        ("kind", "value", "source_ids", "occurrences", "examples"),
    )


@app.command("report")
def report_command(
    ctx: typer.Context,
    case: Annotated[Path, typer.Option("--case", help="사례 결과 폴더")],
    format: Annotated[str, typer.Option("--format", help="markdown, json, csv, html")] = "markdown",
    output: Annotated[Path | None, typer.Option("--output", help="출력 파일 경로")] = None,
) -> None:
    """사례 최신 run을 오프라인 보고서로 저장합니다."""

    normalized = format.casefold()
    extension = "md" if normalized in {"markdown", "md"} else normalized
    if output is None:
        output = case_paths(case).reports / f"fieldtrace-report.{extension}"
    try:
        service = _make_service(ctx.obj.get("config"))
        result = export_report(service.report_bundle(case), output, normalized)  # type: ignore[arg-type]
    except (OSError, ValueError) as exc:
        render_error("보고서", exc, "사례 경로와 보고서 형식을 확인하세요.", console=console)
        raise typer.Exit(2) from exc
    console.print(Text(f"보고서 저장: {result.resolve()}"))


@app.command("doctor")
def doctor_command(ctx: typer.Context) -> None:
    """필수 환경과 선택 TShark 기능을 진단합니다."""

    try:
        result = run_doctor(load_config(ctx.obj.get("config")))
    except (OSError, ValueError) as exc:
        render_error("환경 진단", exc, "설정과 쓰기 권한을 확인하세요.", console=console)
        raise typer.Exit(2) from exc
    table = Table(title="FieldTrace 환경 진단", expand=True)
    table.add_column("상태", width=6)
    table.add_column("항목", width=18)
    table.add_column("확인 내용", overflow="fold")
    table.add_column("다음 행동", overflow="fold")
    for check in result.checks:
        status = "정상" if check.ok else ("오류" if check.required else "선택")
        table.add_row(
            status,
            Text(check.name),
            Text(strip_terminal_controls(check.detail)),
            Text(strip_terminal_controls(check.next_action)),
        )
    console.print(table)
    if result.degraded:
        console.print("선택 기능 일부가 비활성화됩니다. 텍스트 분석은 계속 사용할 수 있습니다.")
    if not result.ready:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
