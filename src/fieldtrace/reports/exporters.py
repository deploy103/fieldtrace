"""Offline Markdown, JSON, CSV, and escaped HTML exporters."""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Literal

from fieldtrace.reports._atomic import atomic_text_output
from fieldtrace.reports.html_report import export_html
from fieldtrace.reports.models import ReportBundle, to_plain

type ReportFormat = Literal["markdown", "md", "json", "csv", "html"]
_FORMULA_PREFIX = re.compile(r"^[\s\x00-\x1f]*[=+\-@]")


def protect_csv_cell(value: object) -> str:
    """Protect a display CSV cell from spreadsheet formula execution.

    JSON is the lossless machine-readable export; the leading apostrophe added
    here intentionally belongs only to the display CSV.
    """

    if value is None:
        return ""
    if isinstance(value, (Mapping, list, tuple, set, frozenset)):
        text = json.dumps(to_plain(value), ensure_ascii=False, sort_keys=True)
    elif isinstance(value, bool):
        text = "true" if value else "false"
    else:
        text = str(value)
    return "'" + text if _FORMULA_PREFIX.match(text) else text


def _bundle(value: ReportBundle | Mapping[str, Any]) -> ReportBundle:
    return value if isinstance(value, ReportBundle) else ReportBundle.from_mapping(value)


def _evidence(record: Mapping[str, Any]) -> Mapping[str, Any]:
    value = record.get("evidence") or record.get("evidence_ref") or {}
    if isinstance(value, Mapping) and value:
        return value
    return {
        "source_id": record.get("source_id", ""),
        "kind": record.get("evidence_kind", ""),
        "locator": record.get("evidence_locator", ""),
        "preview": record.get("evidence_preview", record.get("raw_evidence", "")),
        "truncated": record.get("evidence_truncated", False),
    }


def _markdown_cell(value: object) -> str:
    text = str(value if value is not None else "")
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")


def _fenced(value: object) -> str:
    text = str(value if value is not None else "")
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text}\n{fence}"


def _table(headers: tuple[str, ...], rows: Iterable[Iterable[object]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(_markdown_cell(cell) for cell in row) + " |" for row in rows)
    return lines


def export_json(bundle: ReportBundle | Mapping[str, Any], output: Path) -> Path:
    """Write a lossless UTF-8 JSON report, including raw evidence previews."""

    report = _bundle(bundle)
    with atomic_text_output(output, encoding="utf-8") as stream:
        json.dump(report.as_dict(), stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
    return output


def export_markdown(bundle: ReportBundle | Mapping[str, Any], output: Path) -> Path:
    """Write a human-readable Markdown report with candidate evidence."""

    report = _bundle(bundle)
    lines = [
        "# FieldTrace 분석 보고서",
        "",
        "> 관측된 신호와 근거를 정리한 보고서입니다. 후보는 침입 또는 정답 확정을 뜻하지 않습니다.",
        "",
        "## 요약",
        "",
        f"- 입력 파일: {report.summary.get('sources', len(report.sources))}개",
        f"- 실행: {report.summary.get('runs', len(report.runs))}개",
        f"- 이벤트: {report.summary.get('events', len(report.events))}건",
        f"- 주목할 후보: {report.summary.get('findings', len(report.findings))}건",
        f"- 진단: {report.summary.get('diagnostics', len(report.diagnostics))}건",
        "",
    ]
    if report.selection:
        scope = json.dumps(to_plain(report.selection), ensure_ascii=False, indent=2)
        lines.extend(("### 보고 범위", "", _fenced(scope), ""))
    lines.extend(("## 입력 자료", ""))
    if report.sources:
        lines.extend(
            _table(
                ("ID", "경로", "형식", "SHA-256", "해시 상태"),
                (
                    (
                        source.get("id", ""),
                        source.get("path", ""),
                        source.get("detected_format", source.get("format", "")),
                        source.get("sha256", ""),
                        source.get("hash_status", ""),
                    )
                    for source in report.sources
                ),
            )
        )
    else:
        lines.append("기록 없음")
    lines.extend(("", "## 분석 실행", ""))
    if report.runs:
        lines.extend(
            _table(
                ("ID", "Source", "프로필", "상태", "범위", "읽은 수", "실패/생략"),
                (
                    (
                        run.get("id", ""),
                        run.get("source_id", ""),
                        run.get("profile", ""),
                        run.get("status", ""),
                        run.get("coverage", ""),
                        run.get("records_read", ""),
                        run.get("skip_reason", ""),
                    )
                    for run in report.runs
                ),
            )
        )
    else:
        lines.append("기록 없음")
    lines.extend(("", "## 주목할 후보", ""))
    if not report.findings:
        lines.append("기록 없음")
    for index, finding in enumerate(report.findings, 1):
        evidence = _evidence(finding)
        lines.extend(
            (
                f"### {index}. {_markdown_cell(finding.get('title', '후보'))}",
                "",
                f"- 규칙: {_markdown_cell(finding.get('rule_id', ''))}",
                "- 심각도 / 신뢰도: "
                f"{_markdown_cell(finding.get('severity', ''))} / "
                f"{_markdown_cell(finding.get('confidence', ''))}",
                f"- 관측: {_markdown_cell(finding.get('observation', ''))}",
                f"- 추정 해석: {_markdown_cell(finding.get('interpretation', ''))}",
                f"- 근거 위치: source {_markdown_cell(evidence.get('source_id', ''))}, "
                f"{_markdown_cell(evidence.get('locator', ''))}",
                "",
                _fenced(evidence.get("preview", finding.get("raw_evidence", ""))),
                "",
            )
        )
    lines.extend(("## 이벤트", ""))
    if report.events:
        lines.extend(
            _table(
                ("ID", "시각(원문)", "UTC", "분류", "요약", "근거 위치"),
                (
                    (
                        event.get("id", ""),
                        event.get("timestamp_raw", ""),
                        event.get("timestamp_utc", ""),
                        event.get("category", ""),
                        event.get("summary", ""),
                        _evidence(event).get("locator", ""),
                    )
                    for event in report.events
                ),
            )
        )
        lines.extend(("", "### 이벤트 원문 근거", ""))
        for index, event in enumerate(report.events, 1):
            evidence = _evidence(event)
            lines.extend(
                (
                    f"#### 이벤트 {_markdown_cell(event.get('id', index))} — "
                    f"{_markdown_cell(evidence.get('locator', '위치 미상'))}",
                    "",
                    _fenced(evidence.get("preview", event.get("raw_evidence", ""))),
                    "",
                )
            )
    else:
        lines.append("기록 없음")
    lines.extend(("", "## 교차 자료 관측", ""))
    if report.correlations:
        lines.extend(
            _table(
                ("종류", "값", "Source IDs", "관측 수", "해석"),
                (
                    (
                        item.get("kind", ""),
                        item.get("value", ""),
                        item.get("source_ids", ""),
                        item.get("occurrences", ""),
                        item.get("interpretation", ""),
                    )
                    for item in report.correlations
                ),
            )
        )
    else:
        lines.append("여러 입력에서 함께 관측된 명시적 식별자 없음")
    lines.extend(("", "## 파생 파일", ""))
    if report.artifacts:
        lines.extend(
            _table(
                ("경로", "종류", "SHA-256", "분석기", "원본 근거"),
                (
                    (
                        item.get("path", ""),
                        item.get("kind", ""),
                        item.get("sha256", ""),
                        item.get("analyzer", ""),
                        _evidence(item).get("locator", ""),
                    )
                    for item in report.artifacts
                ),
            )
        )
    else:
        lines.append("기록 없음")
    lines.extend(("", "## 실패·생략·진단", ""))
    if report.diagnostics:
        lines.extend(
            _table(
                ("수준", "단계", "내용", "다음 행동"),
                (
                    (
                        diagnostic.get("level", ""),
                        diagnostic.get("stage", ""),
                        diagnostic.get("message", ""),
                        diagnostic.get("next_action", ""),
                    )
                    for diagnostic in report.diagnostics
                ),
            )
        )
    else:
        lines.append("기록 없음")
    with atomic_text_output(output, encoding="utf-8") as stream:
        stream.write("\n".join(lines).rstrip() + "\n")
    return output


_CSV_COLUMNS = (
    "record_type",
    "id",
    "source_id",
    "run_id",
    "timestamp_raw",
    "timestamp_utc",
    "category",
    "title",
    "summary_or_observation",
    "evidence_kind",
    "evidence_locator",
    "raw_evidence",
    "record_json",
)


def _csv_row(record_type: str, record: Mapping[str, Any]) -> dict[str, object]:
    evidence = _evidence(record)
    return {
        "record_type": record_type,
        "id": record.get("id", ""),
        "source_id": record.get("source_id", evidence.get("source_id", "")),
        "run_id": record.get("run_id", ""),
        "timestamp_raw": record.get("timestamp_raw", ""),
        "timestamp_utc": record.get("timestamp_utc", ""),
        "category": record.get("category", ""),
        "title": record.get("title", ""),
        "summary_or_observation": record.get(
            "summary", record.get("observation", record.get("message", ""))
        ),
        "evidence_kind": evidence.get("kind", ""),
        "evidence_locator": evidence.get("locator", ""),
        "raw_evidence": evidence.get("preview", record.get("raw_evidence", "")),
        "record_json": record,
    }


def export_csv(bundle: ReportBundle | Mapping[str, Any], output: Path) -> Path:
    """Write a spreadsheet-safe display CSV with every report record."""

    report = _bundle(bundle)
    groups = (
        ("source", report.sources),
        ("run", report.runs),
        ("event", report.events),
        ("finding", report.findings),
        ("diagnostic", report.diagnostics),
        ("artifact", report.artifacts),
        ("correlation", report.correlations),
    )
    with atomic_text_output(output, encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=_CSV_COLUMNS)
        writer.writerow({column: protect_csv_cell(column) for column in _CSV_COLUMNS})
        for record_type, records in groups:
            for record in records:
                row = _csv_row(record_type, record)
                writer.writerow(
                    {column: protect_csv_cell(row.get(column, "")) for column in _CSV_COLUMNS}
                )
    return output


def export_report(
    bundle: ReportBundle | Mapping[str, Any], output: Path, format: ReportFormat
) -> Path:
    """Export one scoped report in the requested offline format."""

    normalized = format.casefold()
    if normalized in {"markdown", "md"}:
        return export_markdown(bundle, output)
    if normalized == "json":
        return export_json(bundle, output)
    if normalized == "csv":
        return export_csv(bundle, output)
    if normalized == "html":
        return export_html(bundle, output)
    raise ValueError(f"지원하지 않는 보고서 형식: {format}")
