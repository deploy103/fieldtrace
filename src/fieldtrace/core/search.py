"""Literal search, stable timeline, and evidence detail queries."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .db import CaseStore


@dataclass(frozen=True, slots=True)
class SearchHit:
    entity_type: str
    entity_id: int
    source_id: int | None
    run_id: int | None
    preview: str


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    event_id: int
    source_id: int
    run_id: int
    timestamp_raw: str | None
    timestamp_utc: str | None
    timezone_status: str
    category: str
    summary: str
    evidence_kind: str
    evidence_locator: str


@dataclass(frozen=True, slots=True)
class EvidenceDetail:
    entity_type: str
    entity_id: int
    source_id: int | None
    run_id: int | None
    source_path: str | None
    kind: str | None
    locator: str | None
    preview: str | None
    truncated: bool
    fields: dict[str, Any]


def _latest_clause(
    store: CaseStore, latest_only: bool, *, column: str = "run_id"
) -> tuple[str, list[int]]:
    run_ids = store.latest_run_ids() if latest_only else []
    if latest_only and not run_ids:
        return " AND 0", []
    if latest_only:
        return f" AND {column} IN ({','.join('?' for _ in run_ids)})", run_ids
    return "", []


def literal_search(
    store: CaseStore, text: str, *, limit: int = 100, latest_only: bool = True
) -> list[SearchHit]:
    if not text:
        raise ValueError("검색어는 비어 있을 수 없습니다.")
    if limit <= 0:
        raise ValueError("검색 결과 제한은 0보다 커야 합니다.")
    clause, run_ids = _latest_clause(store, latest_only)
    rows: list[dict[str, Any]] = []
    if store.fts5_available and len(text) >= 2:
        phrase = '"' + text.replace('"', '""') + '"'
        try:
            rows = store.rows(
                "SELECT entity_type,entity_id,source_id,run_id,body FROM search_fts "
                f"WHERE search_fts MATCH ?{clause} LIMIT ?",
                [phrase, *run_ids, limit * 4],
            )
            # FTS is a candidate accelerator; enforce actual literal semantics.
            folded = text.casefold()
            rows = [row for row in rows if folded in str(row["body"]).casefold()]
        except Exception:
            rows = []
    if len(rows) < limit:
        escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        like_rows = store.rows(
            "SELECT entity_type,entity_id,source_id,run_id,body FROM search_documents "
            f"WHERE body LIKE ? ESCAPE '\\'{clause} LIMIT ?",
            [f"%{escaped}%", *run_ids, limit],
        )
        seen = {(str(row["entity_type"]), int(row["entity_id"])) for row in rows}
        rows.extend(
            row for row in like_rows if (str(row["entity_type"]), int(row["entity_id"])) not in seen
        )
    hits: list[SearchHit] = []
    folded = text.casefold()
    for row in rows[:limit]:
        body = str(row["body"])
        offset = body.casefold().find(folded)
        start = max(0, offset - 100) if offset >= 0 else 0
        preview = body[start : start + 300].replace("\x00", "�")
        hits.append(
            SearchHit(
                entity_type=str(row["entity_type"]),
                entity_id=int(row["entity_id"]),
                source_id=int(row["source_id"]) if row["source_id"] is not None else None,
                run_id=int(row["run_id"]) if row["run_id"] is not None else None,
                preview=preview,
            )
        )
    return hits


def timeline(
    store: CaseStore, *, limit: int | None = None, latest_only: bool = True
) -> list[TimelineEntry]:
    if limit is not None and limit <= 0:
        raise ValueError("시간순 결과 제한은 0보다 커야 합니다.")
    clause, run_ids = _latest_clause(store, latest_only, column="e.run_id")
    sql = (
        "SELECT e.id,e.source_id,e.run_id,e.timestamp_raw,e.timestamp_utc,e.timezone_status,"
        "e.category,e.summary,e.evidence_kind,e.evidence_locator FROM events e WHERE 1=1"
        f"{clause} ORDER BY CASE WHEN e.timestamp_utc IS NULL THEN 1 ELSE 0 END,"
        "e.timestamp_utc,e.source_id,e.id"
    )
    params: list[object] = list(run_ids)
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    return [
        TimelineEntry(
            event_id=int(row["id"]),
            source_id=int(row["source_id"]),
            run_id=int(row["run_id"]),
            timestamp_raw=row["timestamp_raw"],
            timestamp_utc=row["timestamp_utc"],
            timezone_status=str(row["timezone_status"]),
            category=str(row["category"]),
            summary=str(row["summary"]),
            evidence_kind=str(row["evidence_kind"]),
            evidence_locator=str(row["evidence_locator"]),
        )
        for row in store.rows(sql, params)
    ]


_EVIDENCE_TABLES = {
    "event": ("events", "fields_json"),
    "finding": ("findings", "fields_json"),
    "artifact": ("artifacts", None),
}


def evidence_detail(store: CaseStore, entity_type: str, entity_id: int) -> EvidenceDetail | None:
    normalized = entity_type.lower().rstrip("s")
    if normalized not in _EVIDENCE_TABLES:
        raise ValueError("근거 종류는 event, finding, artifact 중 하나여야 합니다.")
    table, fields_column = _EVIDENCE_TABLES[normalized]
    row = store.connection.execute(
        f"SELECT t.*,s.path source_path FROM {table} t "
        "LEFT JOIN sources s ON s.id=t.source_id WHERE t.id=?",
        (entity_id,),
    ).fetchone()
    if row is None:
        return None
    fields: dict[str, Any] = {}
    if fields_column:
        try:
            value = json.loads(row[fields_column])
            fields = value if isinstance(value, dict) else {"value": value}
        except (json.JSONDecodeError, TypeError):
            fields = {"decode_error": True}
    return EvidenceDetail(
        entity_type=normalized,
        entity_id=entity_id,
        source_id=int(row["source_id"]) if row["source_id"] is not None else None,
        run_id=int(row["run_id"]) if row["run_id"] is not None else None,
        source_path=row["source_path"],
        kind=row["evidence_kind"],
        locator=row["evidence_locator"],
        preview=row["evidence_preview"],
        truncated=bool(row["evidence_truncated"]),
        fields=fields,
    )


def report_bundle(store: CaseStore, *, latest_only: bool = True) -> dict[str, Any]:
    run_ids = store.latest_run_ids() if latest_only else None
    runs = [asdict(run) for run in store.list_runs(latest_only=latest_only)]
    selected_source_ids = {int(run["source_id"]) for run in runs}
    sources = [
        asdict(source)
        for source in store.list_sources()
        if not latest_only or source.id in selected_source_ids
    ]
    events = store.event_rows(run_ids=run_ids)
    findings = store.finding_rows(run_ids=run_ids)
    diagnostics = store.diagnostic_rows(run_ids=run_ids)
    artifacts_sql = "SELECT * FROM artifacts"
    parameters: list[object] = []
    if run_ids:
        artifacts_sql += f" WHERE run_id IN ({','.join('?' for _ in run_ids)})"
        parameters.extend(run_ids)
    elif latest_only:
        artifacts_sql += " WHERE 0"
    artifacts = store.rows(artifacts_sql + " ORDER BY id", parameters)
    for row in [*events, *findings]:
        for key in ("fields_json", "related_event_ids_json"):
            if key in row:
                try:
                    row[key.removesuffix("_json")] = json.loads(row.pop(key))
                except (json.JSONDecodeError, TypeError):
                    row[key.removesuffix("_json")] = None
    return {
        "case": {
            "id": store.case_id,
            "directory": str(Path(store.paths.root)),
            "schema_version": store.schema_version(),
            "latest_only": latest_only,
        },
        "summary": store.counts(latest_only=latest_only),
        "sources": sources,
        "runs": runs,
        "events": events,
        "findings": findings,
        "artifacts": artifacts,
        "diagnostics": diagnostics,
    }
