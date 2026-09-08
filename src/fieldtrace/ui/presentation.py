"""Rich presentation helpers for analysis results."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from fieldtrace.core.models import AnalysisSummary, Diagnostic, EvidenceRef, Finding
from fieldtrace.ui.safety import strip_terminal_controls


def _record(value: object) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    values = getattr(value, "__dict__", None)
    return values if isinstance(values, Mapping) else {}


def render_error(
    stage: object,
    reason: object,
    next_action: object,
    *,
    console: Console | None = None,
) -> None:
    """Show a recoverable error without exposing a traceback."""

    console = console or Console()
    lines = (
        f"실패 단계: {strip_terminal_controls(stage)}\n"
        f"이유: {strip_terminal_controls(reason)}\n"
        f"다음 행동: {strip_terminal_controls(next_action)}"
    )
    console.print(Panel(Text(lines), title="처리하지 못했습니다", border_style="red"))


def render_summary(
    summary: AnalysisSummary | Mapping[str, Any], *, console: Console | None = None
) -> None:
    """Render the first summary layer, including partial/failure state."""

    console = console or Console()
    data = _record(summary)
    table = Table(title="분석 요약", show_header=False)
    table.add_column("항목", style="bold")
    table.add_column("값", justify="right")
    table.add_row("이벤트", str(data.get("events", 0)))
    table.add_row("주목할 후보", str(data.get("findings", 0)))
    table.add_row("실패", str(data.get("failures", 0)))
    if data.get("cancelled"):
        state = "취소됨 — 저장된 부분 결과를 표시합니다"
    elif data.get("partial"):
        state = "부분 분석 — 제한·실패·생략 내용을 확인하세요"
    else:
        state = "완료"
    table.add_row("상태", Text(state, style="yellow" if data.get("partial") else "green"))
    console.print(table)
    for message in data.get("messages", ()) or ():
        console.print(Text(f"• {strip_terminal_controls(message)}"))


def render_candidates(
    findings: Sequence[Finding | Mapping[str, Any]], *, console: Console | None = None
) -> None:
    """Render the candidate layer without claiming an inferred answer."""

    console = console or Console()
    table = Table(title="주목할 후보 (관측 신호)", expand=True)
    table.add_column("번호", width=5)
    table.add_column("제목", overflow="fold")
    table.add_column("관측 내용", overflow="fold")
    table.add_column("신뢰도", width=9)
    table.add_column("위치", width=15, overflow="fold")
    for index, finding in enumerate(findings, 1):
        data = _record(finding)
        evidence = _record(data.get("evidence") or {})
        table.add_row(
            str(index),
            Text(strip_terminal_controls(data.get("title", "후보"))),
            Text(strip_terminal_controls(data.get("observation", ""))),
            Text(strip_terminal_controls(data.get("confidence", "unknown"))),
            Text(strip_terminal_controls(evidence.get("locator", "-"))),
        )
    console.print(table)
    if not findings:
        console.print(
            "표시할 후보가 없습니다. 검색이나 시간순 보기를 사용할 수 있습니다.",
            markup=False,
        )


def render_evidence(
    evidence: EvidenceRef | Mapping[str, Any], *, console: Console | None = None
) -> None:
    """Render the evidence layer with source locator and sanitized raw preview."""

    console = console or Console()
    data = _record(evidence)
    header = (
        f"source {data.get('source_id', '?')} · "
        f"{strip_terminal_controls(data.get('kind', 'evidence'))} · "
        f"{strip_terminal_controls(data.get('locator', '위치 미상'))}"
    )
    preview = strip_terminal_controls(data.get("preview", ""), multiline=True)
    if data.get("truncated"):
        preview += "\n… (미리보기 길이 제한으로 잘림)"
    console.print(Panel(Text(preview), title=Text(header), expand=True))


def render_diagnostics(
    diagnostics: Sequence[Diagnostic | Mapping[str, Any]], *, console: Console | None = None
) -> None:
    """Display failures and skips that made a run incomplete."""

    if not diagnostics:
        return
    console = console or Console()
    table = Table(title="실패·생략 내용", expand=True)
    table.add_column("수준", width=8)
    table.add_column("단계", width=16, overflow="fold")
    table.add_column("이유", overflow="fold")
    table.add_column("다음 행동", overflow="fold")
    for diagnostic in diagnostics:
        data = _record(diagnostic)
        table.add_row(
            Text(strip_terminal_controls(data.get("level", "info"))),
            Text(strip_terminal_controls(data.get("stage", ""))),
            Text(strip_terminal_controls(data.get("message", ""))),
            Text(strip_terminal_controls(data.get("next_action", ""))),
        )
    console.print(table)


def render_result(
    summary: AnalysisSummary | Mapping[str, Any],
    findings: Sequence[Finding | Mapping[str, Any]],
    diagnostics: Sequence[Diagnostic | Mapping[str, Any]] = (),
    *,
    console: Console | None = None,
) -> None:
    """Render results in the required summary → candidates order."""

    console = console or Console()
    render_summary(summary, console=console)
    render_candidates(findings, console=console)
    render_diagnostics(diagnostics, console=console)


def analysis_progress(*, console: Console | None = None) -> Progress:
    """Create elapsed/processed progress without a fabricated percentage."""

    return Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        TextColumn("{task.completed:,.0f}건"),
        TimeElapsedColumn(),
        console=console,
    )


def format_path(path: Path) -> Text:
    """Return an untrusted path as literal Rich text."""

    return Text(strip_terminal_controls(path))
