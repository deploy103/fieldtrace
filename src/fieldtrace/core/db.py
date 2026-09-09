"""Versioned, per-case SQLite persistence.

Only this module translates analysis items into SQL. Analyzers stay unaware of
transactions and the UI consumes ordinary records/dictionaries.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .cases import CasePaths, prepare_case
from .models import (
    AnalysisItem,
    Artifact,
    Coverage,
    Diagnostic,
    Event,
    Finding,
    Progress,
    RunRecord,
    RunStatus,
    SourceRecord,
    utc_now,
)

SCHEMA_VERSION = 2


class SchemaError(RuntimeError):
    """Raised for an unsupported or corrupt case database schema."""


class CaseDatabaseError(OSError):
    """A SQLite failure translated into a field-recoverable Korean error."""

    def __init__(self, stage: str, reason: str, next_action: str) -> None:
        self.stage = stage
        self.reason = reason
        self.next_action = next_action
        super().__init__(f"{reason} 다음 행동: {next_action}")


def case_database_error(path: Path, exc: sqlite3.Error, *, stage: str) -> CaseDatabaseError:
    """Classify common SQLite failures without claiming that data was saved."""

    detail = str(exc).strip() or type(exc).__name__
    folded = detail.casefold()
    if "locked" in folded or "busy" in folded:
        reason = f"사례 DB가 다른 작업에 의해 잠겼습니다: {path}"
        action = "다른 FieldTrace/SQLite 작업을 닫고 잠시 후 같은 명령을 다시 실행하세요."
    elif "database or disk is full" in folded or "disk full" in folded:
        reason = f"사례 결과를 저장할 디스크 공간이 부족합니다: {path}"
        action = "사례 폴더가 있는 디스크의 여유 공간을 확보한 뒤 다시 실행하세요."
    elif "readonly" in folded or "read-only" in folded:
        reason = f"사례 DB 또는 폴더가 읽기 전용입니다: {path}"
        action = "--case를 쓰기 가능한 폴더로 지정하고 원본 증거는 그대로 두세요."
    elif any(marker in folded for marker in ("malformed", "not a database", "corrupt")):
        reason = f"사례 DB가 손상되었거나 SQLite 형식이 아닙니다: {path}"
        action = "기존 DB를 보존하고 새 사례 폴더로 다시 분석하세요."
    else:
        reason = f"사례 DB 처리에 실패했습니다: {detail}"
        action = "사례 폴더 권한과 디스크 상태를 확인한 뒤 다시 실행하세요."
    return CaseDatabaseError(stage, reason, action)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


_SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    detected_format TEXT NOT NULL,
    detection_reason TEXT NOT NULL,
    sha256 TEXT,
    hash_status TEXT NOT NULL DEFAULT 'pending',
    changed_after INTEGER NOT NULL DEFAULT 0 CHECK(changed_after IN (0, 1)),
    size_after INTEGER,
    mtime_ns_after INTEGER,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    profile TEXT NOT NULL,
    analyzers_json TEXT NOT NULL DEFAULT '[]',
    tool_versions_json TEXT NOT NULL DEFAULT '{}',
    config_json TEXT NOT NULL DEFAULT '{}',
    selected_tasks_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL,
    coverage TEXT NOT NULL,
    records_read INTEGER NOT NULL DEFAULT 0,
    failures INTEGER NOT NULL DEFAULT 0,
    skip_reason TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS runs_source_id_idx ON runs(source_id, id);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    run_id INTEGER NOT NULL REFERENCES runs(id),
    timestamp_raw TEXT,
    timestamp_utc TEXT,
    timezone_status TEXT NOT NULL,
    category TEXT NOT NULL,
    summary TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    user TEXT,
    fields_json TEXT NOT NULL,
    evidence_kind TEXT NOT NULL,
    evidence_locator TEXT NOT NULL,
    evidence_preview TEXT NOT NULL,
    evidence_truncated INTEGER NOT NULL CHECK(evidence_truncated IN (0, 1))
);
CREATE INDEX IF NOT EXISTS events_run_idx ON events(run_id, id);
CREATE INDEX IF NOT EXISTS events_time_idx ON events(timestamp_utc, source_id, id);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    source_id INTEGER REFERENCES sources(id),
    run_id INTEGER NOT NULL REFERENCES runs(id),
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    observation TEXT NOT NULL,
    interpretation TEXT NOT NULL,
    confidence TEXT NOT NULL,
    severity TEXT NOT NULL,
    related_event_ids_json TEXT NOT NULL,
    fields_json TEXT NOT NULL,
    evidence_kind TEXT,
    evidence_locator TEXT,
    evidence_preview TEXT,
    evidence_truncated INTEGER NOT NULL DEFAULT 0 CHECK(evidence_truncated IN (0, 1))
);
CREATE INDEX IF NOT EXISTS findings_run_idx ON findings(run_id, id);
CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    run_id INTEGER NOT NULL REFERENCES runs(id),
    path TEXT NOT NULL,
    sha256 TEXT,
    kind TEXT NOT NULL,
    analyzer TEXT NOT NULL,
    evidence_kind TEXT NOT NULL,
    evidence_locator TEXT NOT NULL,
    evidence_preview TEXT NOT NULL,
    evidence_truncated INTEGER NOT NULL CHECK(evidence_truncated IN (0, 1))
);
CREATE INDEX IF NOT EXISTS artifacts_run_idx ON artifacts(run_id, id);
CREATE TABLE IF NOT EXISTS diagnostics (
    id INTEGER PRIMARY KEY,
    source_id INTEGER REFERENCES sources(id),
    run_id INTEGER REFERENCES runs(id),
    level TEXT NOT NULL,
    stage TEXT NOT NULL,
    message TEXT NOT NULL,
    next_action TEXT NOT NULL,
    exception TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS diagnostics_run_idx ON diagnostics(run_id, id);
CREATE TABLE IF NOT EXISTS search_documents (
    entity_type TEXT NOT NULL,
    entity_id INTEGER NOT NULL,
    source_id INTEGER,
    run_id INTEGER,
    body TEXT NOT NULL,
    PRIMARY KEY(entity_type, entity_id)
);
CREATE INDEX IF NOT EXISTS search_documents_run_idx ON search_documents(run_id);
"""

_SCHEMA_V2 = """
ALTER TABLE sources ADD COLUMN hash_generation TEXT;
"""


class CaseStore:
    """Persistence facade for one prepared case directory."""

    def __init__(
        self,
        case: Path | str | CasePaths,
        *,
        create: bool = True,
        timeout: float = 10.0,
    ) -> None:
        if isinstance(case, CasePaths):
            self.paths = case
        elif create:
            self.paths = prepare_case(case)
        else:
            root = Path(case).expanduser().resolve()
            from .cases import case_paths

            self.paths = case_paths(root)
            if not self.paths.database.is_file():
                raise FileNotFoundError(f"사례 DB를 찾을 수 없습니다: {self.paths.database}")
        if timeout < 0:
            raise ValueError("SQLite timeout은 0 이상이어야 합니다.")
        try:
            self.connection = sqlite3.connect(self.paths.database, timeout=timeout)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.execute(f"PRAGMA busy_timeout={round(timeout * 1000)}")
            # WAL lets read-only result views stay responsive during batch writes.
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.fts5_available = False
            self._run_source_cache: dict[int, int] = {}
            self._migrate()
        except CaseDatabaseError:
            connection = getattr(self, "connection", None)
            if connection is not None:
                connection.close()
            raise
        except sqlite3.Error as exc:
            connection = getattr(self, "connection", None)
            if connection is not None:
                connection.close()
            raise case_database_error(self.paths.database, exc, stage="사례 DB 열기") from exc

    def __enter__(self) -> CaseStore:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        self.connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self.connection
        except sqlite3.Error as exc:
            self.connection.rollback()
            raise case_database_error(self.paths.database, exc, stage="사례 DB 저장") from exc
        except BaseException:
            self.connection.rollback()
            raise
        else:
            try:
                self.connection.commit()
            except sqlite3.Error as exc:
                self.connection.rollback()
                raise case_database_error(
                    self.paths.database, exc, stage="사례 DB 저장"
                ) from exc

    def commit(self) -> None:
        try:
            self.connection.commit()
        except sqlite3.Error as exc:
            self.connection.rollback()
            raise case_database_error(self.paths.database, exc, stage="사례 DB 저장") from exc

    def recover_interrupted_runs(self) -> int:
        """Mark runs left active by a terminated process as honest partial failures."""

        try:
            rows = list(
                self.connection.execute(
                    "SELECT id,source_id,records_read,failures FROM runs WHERE status=?",
                    (RunStatus.RUNNING.value,),
                )
            )
        except sqlite3.Error as exc:
            raise case_database_error(self.paths.database, exc, stage="사례 DB 복구") from exc
        if not rows:
            return 0
        with self.transaction():
            for row in rows:
                run_id = int(row["id"])
                self.connection.execute(
                    "UPDATE runs SET status=?,coverage=?,failures=?,skip_reason=?,finished_at=? "
                    "WHERE id=? AND status=?",
                    (
                        RunStatus.FAILED.value,
                        Coverage.PARTIAL.value,
                        int(row["failures"]) + 1,
                        "이전 분석 프로세스가 완료 전에 종료됨",
                        utc_now(),
                        run_id,
                        RunStatus.RUNNING.value,
                    ),
                )
                self.connection.execute(
                    "INSERT INTO diagnostics(source_id,run_id,level,stage,message,next_action,"
                    "exception,created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        int(row["source_id"]),
                        run_id,
                        "error",
                        "recovery",
                        "이전 분석이 완료 상태를 기록하지 못하고 종료되었습니다.",
                        "저장된 부분 결과를 확인한 뒤 같은 입력을 새 run으로 다시 분석하세요.",
                        None,
                        utc_now(),
                    ),
                )
        return len(rows)

    def _migrate(self) -> None:
        table = self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'"
        ).fetchone()
        current = 0
        if table:
            row = self.connection.execute("SELECT MAX(version) FROM schema_version").fetchone()
            current = int(row[0] or 0)
        if current > SCHEMA_VERSION:
            raise SchemaError(
                f"사례 DB 스키마 {current}은 이 프로그램({SCHEMA_VERSION})보다 새 버전입니다."
            )
        with self.transaction():
            if current < 1:
                self.connection.executescript(_SCHEMA_V1)
                self.connection.execute(
                    "INSERT INTO schema_version(version, applied_at) VALUES (?, ?)", (1, utc_now())
                )
                current = 1
            if current < 2:
                self.connection.executescript(_SCHEMA_V2)
                self.connection.execute(
                    "INSERT INTO schema_version(version, applied_at) VALUES (?, ?)", (2, utc_now())
                )
            self.connection.execute(
                "INSERT OR IGNORE INTO case_metadata(key, value) VALUES ('case_id', ?)",
                (str(uuid.uuid4()),),
            )
        self._prepare_fts()

    def _prepare_fts(self) -> None:
        try:
            self.connection.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5("
                "entity_type UNINDEXED, entity_id UNINDEXED, source_id UNINDEXED, "
                "run_id UNINDEXED, body)"
            )
            self.connection.commit()
            self.fts5_available = True
        except sqlite3.OperationalError:
            self.connection.rollback()
            self.fts5_available = False
        self.set_metadata("fts5_available", "1" if self.fts5_available else "0")

    @property
    def case_id(self) -> str:
        value = self.get_metadata("case_id")
        if value is None:
            raise SchemaError("case_id 메타데이터가 없습니다.")
        return value

    def schema_version(self) -> int:
        row = self.connection.execute("SELECT MAX(version) FROM schema_version").fetchone()
        return int(row[0])

    def set_metadata(self, key: str, value: str) -> None:
        with self.transaction():
            self.connection.execute(
                "INSERT INTO case_metadata(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def get_metadata(self, key: str) -> str | None:
        row = self.connection.execute(
            "SELECT value FROM case_metadata WHERE key=?", (key,)
        ).fetchone()
        return None if row is None else str(row[0])

    def add_source(
        self,
        path: Path | str,
        *,
        size: int,
        mtime_ns: int,
        detected_format: str,
        detection_reason: str,
        hash_status: str = "pending",
        hash_generation: str | None = None,
    ) -> int:
        resolved_path = str(Path(path).resolve())
        existing = self.connection.execute(
            "SELECT id FROM sources WHERE path=? AND size=? AND mtime_ns=?"
            " ORDER BY id DESC LIMIT 1",
            (resolved_path, size, mtime_ns),
        ).fetchone()
        if existing is not None:
            source_id = int(existing["id"])
            with self.transaction():
                self.connection.execute(
                    "UPDATE sources SET detected_format=?,detection_reason=?,sha256=NULL,"
                    "hash_status=?,hash_generation=?,changed_after=0,size_after=NULL,"
                    "mtime_ns_after=NULL WHERE id=?",
                    (
                        detected_format,
                        detection_reason,
                        hash_status,
                        hash_generation,
                        source_id,
                    ),
                )
            return source_id
        with self.transaction():
            cursor = self.connection.execute(
                "INSERT INTO sources(path,size,mtime_ns,detected_format,detection_reason,"
                "hash_status,hash_generation,created_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    resolved_path,
                    size,
                    mtime_ns,
                    detected_format,
                    detection_reason,
                    hash_status,
                    hash_generation,
                    utc_now(),
                ),
            )
        return int(cursor.lastrowid)

    def update_source_hash(
        self,
        source_id: int,
        sha256: str | None,
        status: str,
        *,
        generation: str | None = None,
    ) -> bool:
        sql = "UPDATE sources SET sha256=?, hash_status=? WHERE id=?"
        parameters: tuple[object, ...] = (sha256, status, source_id)
        if generation is not None:
            sql += " AND hash_generation=?"
            parameters = (*parameters, generation)
        with self.transaction():
            cursor = self.connection.execute(sql, parameters)
        return cursor.rowcount == 1

    def finish_source_stat(self, source_id: int, *, size: int, mtime_ns: int) -> bool:
        row = self.connection.execute(
            "SELECT size, mtime_ns FROM sources WHERE id=?", (source_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"source_id {source_id}")
        changed = int(row["size"]) != size or int(row["mtime_ns"]) != mtime_ns
        with self.transaction():
            self.connection.execute(
                "UPDATE sources SET changed_after=?, size_after=?, mtime_ns_after=? WHERE id=?",
                (int(changed), size, mtime_ns, source_id),
            )
        return changed

    def mark_source_changed(self, source_id: int) -> None:
        with self.transaction():
            self.connection.execute("UPDATE sources SET changed_after=1 WHERE id=?", (source_id,))

    def get_source(self, source_id: int) -> SourceRecord | None:
        row = self.connection.execute("SELECT * FROM sources WHERE id=?", (source_id,)).fetchone()
        return None if row is None else self._source_record(row)

    def list_sources(self) -> list[SourceRecord]:
        rows = self.connection.execute("SELECT * FROM sources")
        return [self._source_record(row) for row in rows]

    @staticmethod
    def _source_record(row: sqlite3.Row) -> SourceRecord:
        return SourceRecord(
            id=int(row["id"]),
            path=str(row["path"]),
            size=int(row["size"]),
            mtime_ns=int(row["mtime_ns"]),
            detected_format=str(row["detected_format"]),
            detection_reason=str(row["detection_reason"]),
            sha256=row["sha256"],
            hash_status=str(row["hash_status"]),
            changed_after=bool(row["changed_after"]),
        )

    def create_run(
        self,
        source_id: int,
        profile: str,
        *,
        analyzers: Sequence[str] = (),
        tool_versions: dict[str, Any] | None = None,
        config: dict[str, Any] | None = None,
        selected_tasks: Iterable[str] = (),
    ) -> int:
        with self.transaction():
            cursor = self.connection.execute(
                "INSERT INTO runs(source_id,profile,analyzers_json,tool_versions_json,"
                "config_json,selected_tasks_json,status,coverage,started_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    source_id,
                    profile,
                    _json(list(analyzers)),
                    _json(tool_versions or {}),
                    _json(config or {}),
                    _json(sorted(selected_tasks)),
                    RunStatus.RUNNING.value,
                    Coverage.PARTIAL.value,
                    utc_now(),
                ),
            )
        run_id = int(cursor.lastrowid)
        self._run_source_cache[run_id] = source_id
        return run_id

    def finish_run(
        self,
        run_id: int,
        *,
        status: RunStatus | str,
        coverage: Coverage | str,
        records_read: int,
        failures: int,
        skip_reason: str | None = None,
    ) -> None:
        with self.transaction():
            self.connection.execute(
                "UPDATE runs SET status=?,coverage=?,records_read=?,failures=?,skip_reason=?,"
                "finished_at=? WHERE id=?",
                (
                    str(status),
                    str(coverage),
                    records_read,
                    failures,
                    skip_reason,
                    utc_now(),
                    run_id,
                ),
            )

    def get_run(self, run_id: int) -> RunRecord | None:
        row = self.connection.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return None if row is None else self._run_record(row)

    def list_runs(self, *, latest_only: bool = False) -> list[RunRecord]:
        sql = "SELECT r.* FROM runs r"
        if latest_only:
            sql += (
                " JOIN (SELECT source_id, MAX(id) id FROM runs GROUP BY source_id) x ON x.id=r.id"
            )
        sql += " ORDER BY r.id"
        return [self._run_record(row) for row in self.connection.execute(sql)]

    @staticmethod
    def _run_record(row: sqlite3.Row) -> RunRecord:
        return RunRecord(
            id=int(row["id"]),
            source_id=int(row["source_id"]),
            profile=str(row["profile"]),
            status=str(row["status"]),
            coverage=str(row["coverage"]),
            records_read=int(row["records_read"]),
            failures=int(row["failures"]),
            skip_reason=row["skip_reason"],
            started_at=str(row["started_at"]),
            finished_at=row["finished_at"],
        )

    def add_event(self, run_id: int, event: Event, *, commit: bool = True) -> int:
        evidence = event.evidence
        self._validate_evidence_source(run_id, evidence.source_id)
        cursor = self.connection.execute(
            "INSERT INTO events(source_id,run_id,timestamp_raw,timestamp_utc,timezone_status,"
            "category,summary,src_ip,dst_ip,src_port,dst_port,user,fields_json,evidence_kind,"
            "evidence_locator,evidence_preview,evidence_truncated) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                evidence.source_id,
                run_id,
                event.timestamp_raw,
                event.timestamp_utc,
                event.timezone_status,
                event.category,
                event.summary,
                event.src_ip,
                event.dst_ip,
                event.src_port,
                event.dst_port,
                event.user,
                _json(event.fields),
                evidence.kind,
                evidence.locator,
                evidence.preview,
                int(evidence.truncated),
            ),
        )
        event.id = int(cursor.lastrowid)
        body = "\n".join(
            part
            for part in (
                event.category,
                event.summary,
                event.src_ip,
                event.dst_ip,
                event.user,
                evidence.locator,
                evidence.preview,
                _json(event.fields),
            )
            if part
        )
        self._index("event", event.id, evidence.source_id, run_id, body)
        if commit:
            self.commit()
        return event.id

    def add_finding(self, run_id: int, finding: Finding, *, commit: bool = True) -> int:
        evidence = finding.evidence
        if evidence is not None:
            self._validate_evidence_source(run_id, evidence.source_id)
        source_id = evidence.source_id if evidence is not None else self._run_source(run_id)
        cursor = self.connection.execute(
            "INSERT INTO findings(source_id,run_id,rule_id,title,observation,interpretation,"
            "confidence,severity,related_event_ids_json,fields_json,evidence_kind,evidence_locator,"
            "evidence_preview,evidence_truncated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                source_id,
                run_id,
                finding.rule_id,
                finding.title,
                finding.observation,
                finding.interpretation,
                finding.confidence,
                finding.severity,
                _json(finding.related_event_ids),
                _json(finding.fields),
                evidence.kind if evidence else None,
                evidence.locator if evidence else None,
                evidence.preview if evidence else None,
                int(evidence.truncated) if evidence else 0,
            ),
        )
        finding.id = int(cursor.lastrowid)
        body = "\n".join(
            part
            for part in (
                finding.rule_id,
                finding.title,
                finding.observation,
                finding.interpretation,
                evidence.locator if evidence else None,
                evidence.preview if evidence else None,
                _json(finding.fields),
            )
            if part
        )
        self._index("finding", finding.id, source_id, run_id, body)
        if commit:
            self.commit()
        return finding.id

    def add_artifact(self, run_id: int, artifact: Artifact, *, commit: bool = True) -> int:
        evidence = artifact.evidence
        self._validate_evidence_source(run_id, evidence.source_id)
        cursor = self.connection.execute(
            "INSERT INTO artifacts(source_id,run_id,path,sha256,kind,analyzer,evidence_kind,"
            "evidence_locator,evidence_preview,evidence_truncated) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                evidence.source_id,
                run_id,
                artifact.path,
                artifact.sha256,
                artifact.kind,
                artifact.analyzer,
                evidence.kind,
                evidence.locator,
                evidence.preview,
                int(evidence.truncated),
            ),
        )
        artifact_id = int(cursor.lastrowid)
        self._index(
            "artifact",
            artifact_id,
            evidence.source_id,
            run_id,
            "\n".join(
                (
                    artifact.path,
                    artifact.kind,
                    evidence.locator,
                    evidence.preview,
                    artifact.sha256 or "",
                )
            ),
        )
        if commit:
            self.commit()
        return artifact_id

    def add_diagnostic(
        self,
        diagnostic: Diagnostic,
        *,
        source_id: int | None = None,
        run_id: int | None = None,
        commit: bool = True,
    ) -> int:
        cursor = self.connection.execute(
            "INSERT INTO diagnostics(source_id,run_id,level,stage,message,next_action,exception,"
            "created_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                source_id,
                run_id,
                diagnostic.level,
                diagnostic.stage,
                diagnostic.message,
                diagnostic.next_action,
                diagnostic.exception,
                utc_now(),
            ),
        )
        if commit:
            self.commit()
        return int(cursor.lastrowid)

    def write_items(
        self, run_id: int, items: Iterable[AnalysisItem], *, batch_size: int = 250
    ) -> dict[str, int]:
        """Persist items in bounded commits so Ctrl+C leaves useful results."""

        counts = {"events": 0, "findings": 0, "artifacts": 0, "diagnostics": 0}
        pending = 0
        try:
            for item in items:
                if isinstance(item, Event):
                    self.add_event(run_id, item, commit=False)
                    counts["events"] += 1
                elif isinstance(item, Finding):
                    self.add_finding(run_id, item, commit=False)
                    counts["findings"] += 1
                elif isinstance(item, Artifact):
                    self.add_artifact(run_id, item, commit=False)
                    counts["artifacts"] += 1
                elif isinstance(item, Diagnostic):
                    self.add_diagnostic(
                        item, source_id=self._run_source(run_id), run_id=run_id, commit=False
                    )
                    counts["diagnostics"] += 1
                elif isinstance(item, Progress):
                    continue
                else:
                    raise TypeError(f"알 수 없는 AnalysisItem: {type(item).__name__}")
                pending += 1
                if pending >= batch_size:
                    self.commit()
                    pending = 0
        except CaseDatabaseError:
            raise
        except sqlite3.Error as exc:
            self.connection.rollback()
            raise case_database_error(self.paths.database, exc, stage="사례 DB 저장") from exc
        except BaseException:
            self.connection.rollback()
            raise
        else:
            self.commit()
        return counts

    def _run_source(self, run_id: int) -> int:
        cached = self._run_source_cache.get(run_id)
        if cached is not None:
            return cached
        row = self.connection.execute("SELECT source_id FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            raise KeyError(f"run_id {run_id}")
        source_id = int(row[0])
        self._run_source_cache[run_id] = source_id
        return source_id

    def _validate_evidence_source(self, run_id: int, evidence_source_id: int) -> None:
        run_source_id = self._run_source(run_id)
        if evidence_source_id != run_source_id:
            raise ValueError(
                f"근거 source_id {evidence_source_id}가 run {run_id}의 "
                f"source_id {run_source_id}와 다릅니다."
            )

    def _index(self, kind: str, entity_id: int, source_id: int, run_id: int, body: str) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO search_documents(entity_type,entity_id,source_id,run_id,body)"
            " VALUES (?,?,?,?,?)",
            (kind, entity_id, source_id, run_id, body),
        )
        if self.fts5_available:
            self.connection.execute(
                "DELETE FROM search_fts WHERE entity_type=? AND entity_id=?", (kind, entity_id)
            )
            self.connection.execute(
                "INSERT INTO search_fts(entity_type,entity_id,source_id,run_id,body)"
                " VALUES (?,?,?,?,?)",
                (kind, entity_id, source_id, run_id, body),
            )

    def rows(self, sql: str, parameters: Sequence[object] = ()) -> list[dict[str, Any]]:
        """Internal/report query helper; SQL must be owned by trusted application code."""

        try:
            return [dict(row) for row in self.connection.execute(sql, parameters)]
        except sqlite3.Error as exc:
            raise case_database_error(self.paths.database, exc, stage="사례 DB 조회") from exc

    def event_rows(self, *, run_ids: Sequence[int] | None = None) -> list[dict[str, Any]]:
        return list(self.iter_event_rows(run_ids=run_ids))

    def iter_event_rows(
        self, *, run_ids: Sequence[int] | None = None
    ) -> Iterator[dict[str, Any]]:
        """Stream event dictionaries for memory-bounded aggregate queries."""

        sql = "SELECT * FROM events"
        params: list[object] = []
        if run_ids:
            sql += f" WHERE run_id IN ({','.join('?' for _ in run_ids)})"
            params.extend(run_ids)
        sql += " ORDER BY id"
        try:
            for row in self.connection.execute(sql, params):
                yield dict(row)
        except sqlite3.Error as exc:
            raise case_database_error(self.paths.database, exc, stage="사례 DB 조회") from exc

    def finding_rows(
        self, *, run_ids: Sequence[int] | None = None, limit: int | None = None
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM findings"
        params: list[object] = []
        if run_ids:
            sql += f" WHERE run_id IN ({','.join('?' for _ in run_ids)})"
            params.extend(run_ids)
        sql += " ORDER BY id"
        if limit is not None:
            if limit < 1:
                raise ValueError("finding limit은 0보다 커야 합니다.")
            sql += " LIMIT ?"
            params.append(limit)
        return self.rows(sql, params)

    def diagnostic_rows(
        self, *, run_ids: Sequence[int] | None = None, limit: int | None = None
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM diagnostics"
        params: list[object] = []
        if run_ids:
            sql += f" WHERE run_id IN ({','.join('?' for _ in run_ids)})"
            params.extend(run_ids)
        sql += " ORDER BY id"
        if limit is not None:
            if limit < 1:
                raise ValueError("diagnostic limit은 0보다 커야 합니다.")
            sql += " LIMIT ?"
            params.append(limit)
        return self.rows(sql, params)

    def latest_run_ids(self) -> list[int]:
        return [
            int(row[0])
            for row in self.connection.execute("SELECT MAX(id) FROM runs GROUP BY source_id")
        ]

    def counts(self, *, latest_only: bool = True) -> dict[str, int]:
        run_ids = self.latest_run_ids() if latest_only else []
        result: dict[str, int] = {}
        for table in ("events", "findings", "artifacts", "diagnostics"):
            if latest_only and not run_ids:
                result[table] = 0
            elif latest_only:
                marks = ",".join("?" for _ in run_ids)
                result[table] = int(
                    self.connection.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE run_id IN ({marks})", run_ids
                    ).fetchone()[0]
                )
            else:
                result[table] = int(
                    self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                )
        return result
