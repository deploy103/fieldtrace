"""Self-contained HTML report with strict escaping and local-only filtering."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from html import escape
from pathlib import Path
from typing import Any

from fieldtrace.reports._atomic import atomic_text_output
from fieldtrace.reports.models import ReportBundle, to_plain


def _bundle(value: ReportBundle | Mapping[str, Any]) -> ReportBundle:
    return value if isinstance(value, ReportBundle) else ReportBundle.from_mapping(value)


def _evidence(record: Mapping[str, Any]) -> Mapping[str, Any]:
    value = record.get("evidence") or record.get("evidence_ref") or {}
    if isinstance(value, Mapping) and value:
        return value
    return {
        "source_id": record.get("source_id", ""),
        "locator": record.get("evidence_locator", ""),
        "preview": record.get("evidence_preview", record.get("raw_evidence", "")),
    }


def _html(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (Mapping, list, tuple, set, frozenset)):
        value = json.dumps(to_plain(value), ensure_ascii=False, sort_keys=True)
    return escape(str(value), quote=True)


def _table(headers: tuple[str, ...], rows: Iterable[Iterable[object]]) -> str:
    head = "".join(f"<th>{_html(header)}</th>" for header in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{_html(cell)}</td>" for cell in row) + "</tr>" for row in rows
    )
    return (
        f"<div class=table-wrap><table><thead><tr>{head}</tr></thead>"
        f"<tbody>{body}</tbody></table></div>"
    )


def export_html(bundle: ReportBundle | Mapping[str, Any], output: Path) -> Path:
    """Write one self-contained report with escaped evidence and local filtering."""

    report = _bundle(bundle)
    summary_cards = "".join(
        f"<li><strong>{_html(label)}</strong><span>{_html(value)}</span></li>"
        for label, value in (
            ("입력", report.summary.get("sources", len(report.sources))),
            ("실행", report.summary.get("runs", len(report.runs))),
            ("이벤트", report.summary.get("events", len(report.events))),
            ("후보", report.summary.get("findings", len(report.findings))),
            ("진단", report.summary.get("diagnostics", len(report.diagnostics))),
        )
    )
    source_table = _table(
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
    finding_cards: list[str] = []
    for index, finding in enumerate(report.findings, 1):
        evidence = _evidence(finding)
        finding_cards.append(
            "<article class=record>"
            f"<h3>{index}. {_html(finding.get('title', '후보'))}</h3>"
            f"<p><b>규칙</b> {_html(finding.get('rule_id', ''))}</p>"
            f"<p><b>관측</b> {_html(finding.get('observation', ''))}</p>"
            f"<p><b>추정 해석</b> {_html(finding.get('interpretation', ''))}</p>"
            f"<p><b>근거</b> source {_html(evidence.get('source_id', ''))} · "
            f"{_html(evidence.get('locator', ''))}</p>"
            f"<pre>{_html(evidence.get('preview', ''))}</pre>"
            "</article>"
        )
    event_rows = _table(
        ("ID", "원시 시각", "UTC", "분류", "요약", "근거"),
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
    event_evidence = "".join(
        "<article class=record>"
        f"<h3>이벤트 {_html(event.get('id', index))} · "
        f"{_html(_evidence(event).get('locator', '위치 미상'))}</h3>"
        f"<pre>{_html(_evidence(event).get('preview', ''))}</pre>"
        "</article>"
        for index, event in enumerate(report.events, 1)
    )
    correlation_table = _table(
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
    artifact_table = _table(
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
    diagnostic_table = _table(
        ("수준", "단계", "내용", "다음 행동"),
        (
            (
                item.get("level", ""),
                item.get("stage", ""),
                item.get("message", ""),
                item.get("next_action", ""),
            )
            for item in report.diagnostics
        ),
    )
    document = f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FieldTrace 분석 보고서</title>
<style>
:root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
body {{ max-width: 1180px; margin: auto; padding: 1.5rem; line-height: 1.55; }}
h1,h2 {{ border-bottom: 1px solid #8886; padding-bottom: .35rem; }}
.notice {{ border-left: .3rem solid #d58b00; padding: .7rem 1rem; background: #8881; }}
.summary {{ display:flex; flex-wrap:wrap; gap:.7rem; padding:0; }}
.summary li {{ list-style:none; border:1px solid #8886; border-radius:.4rem; padding:.6rem 1rem; }}
.summary span {{ margin-left:.7rem; font-size:1.2rem; }}
input {{ width:100%; box-sizing:border-box; padding:.7rem; margin:.7rem 0 1rem; }}
.table-wrap {{ overflow-x:auto; }} table {{ border-collapse:collapse; width:100%; }}
th,td {{ border:1px solid #8886; padding:.45rem; text-align:left; vertical-align:top; }}
.record {{ border:1px solid #8886; border-radius:.4rem; padding:.5rem 1rem; margin:.7rem 0; }}
pre {{ white-space:pre-wrap; overflow-wrap:anywhere; background:#8881; padding:.7rem; }}
[hidden] {{ display:none !important; }}
</style></head><body>
<h1>FieldTrace 분석 보고서</h1>
<p class=notice>관측 신호와 근거입니다. 후보는 침입 또는 정답 확정을 뜻하지 않습니다.</p>
<label for=report-search><b>보고서 안에서 찾기</b></label>
<input id=report-search type=search placeholder="IP, 도메인, 계정, 후보, 근거 위치">
<main id=report-content>
<section><h2>요약</h2><ul class=summary>{summary_cards}</ul></section>
<section><h2>입력 자료</h2>{source_table}</section>
<section><h2>주목할 후보</h2>{"".join(finding_cards) or "<p>기록 없음</p>"}</section>
<section><h2>통합 이벤트</h2>{event_rows}{event_evidence}</section>
<section><h2>교차 자료 관측</h2>{correlation_table}</section>
<section><h2>파생 파일</h2>{artifact_table}</section>
<section><h2>실패·생략·진단</h2>{diagnostic_table}</section>
</main>
<script>
const input=document.getElementById('report-search');
input.addEventListener('input',()=>{{
 const q=input.value.toLocaleLowerCase();
 document.querySelectorAll('#report-content tr,#report-content article').forEach((node)=>{{
   node.hidden=Boolean(q)&&!node.textContent.toLocaleLowerCase().includes(q);
 }});
}});
</script></body></html>
"""
    with atomic_text_output(output, encoding="utf-8") as stream:
        stream.write(document)
    return output
