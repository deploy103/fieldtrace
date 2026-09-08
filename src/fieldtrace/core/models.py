"""Stable analyzer and persistence contracts."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from threading import Event as ThreadEvent
from typing import Any, Protocol, TypeAlias


class SourceFormat(StrEnum):
    GENERIC_TEXT = "text"
    WEB = "web"
    LINUX_AUTH = "linux_auth"
    PCAP = "pcap"
    UNKNOWN = "unknown"


class Coverage(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"


class RunStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(slots=True)
class EvidenceRef:
    source_id: int
    kind: str
    locator: str
    preview: str
    truncated: bool = False


@dataclass(slots=True)
class Event:
    category: str
    summary: str
    evidence: EvidenceRef
    timestamp_raw: str | None = None
    timestamp_utc: str | None = None
    timezone_status: str = "unknown"
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    user: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    id: int | None = None


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    observation: str
    interpretation: str
    confidence: str
    evidence: EvidenceRef | None = None
    related_event_ids: list[int] = field(default_factory=list)
    severity: str = "info"
    fields: dict[str, Any] = field(default_factory=dict)
    id: int | None = None


@dataclass(slots=True)
class Artifact:
    path: str
    sha256: str | None
    kind: str
    analyzer: str
    evidence: EvidenceRef


@dataclass(slots=True)
class Progress:
    stage: str
    processed: int
    total: int | None = None
    message: str = ""


@dataclass(slots=True)
class Diagnostic:
    level: str
    stage: str
    message: str
    next_action: str = ""
    exception: str | None = None


AnalysisItem: TypeAlias = Event | Finding | Artifact | Progress | Diagnostic


@dataclass(slots=True)
class ProbeMetadata:
    path: Path
    size: int
    suffix: str


@dataclass(slots=True)
class ProbeResult:
    format: SourceFormat
    confidence: float
    reason: str
    analyzer: str | None = None


@dataclass(slots=True)
class Environment:
    tshark_path: str | None = None
    tshark_version: str | None = None


@dataclass(slots=True)
class Capability:
    available: bool
    reason: str
    features: tuple[str, ...] = ()


@dataclass(slots=True)
class TimePolicy:
    timezone: str | None = None
    assumed_year: int | None = None


@dataclass(slots=True)
class ExecutionBudget:
    max_seconds: float | None = None
    max_records: int | None = None
    max_line_bytes: int = 1_048_576
    max_preview_chars: int = 500


class ExternalRunner(Protocol):
    def run(
        self,
        argv: list[str],
        *,
        cancel: ThreadEvent,
        timeout: float | None = None,
        max_output_bytes: int | None = None,
        env: dict[str, str] | None = None,
    ) -> tuple[int, str, str]: ...


@dataclass(slots=True)
class AnalysisContext:
    input_path: Path
    source_id: int
    case_id: str
    run_id: int
    cancel: ThreadEvent
    time_policy: TimePolicy
    budget: ExecutionBudget
    external_runner: ExternalRunner
    profile: str
    started_at: float
    selected_tasks: frozenset[str] = frozenset()


class Analyzer(Protocol):
    name: str
    formats: tuple[SourceFormat, ...]

    def probe(self, sample: bytes, metadata: ProbeMetadata) -> ProbeResult: ...

    def capabilities(self, environment: Environment) -> Capability: ...

    def analyze(self, context: AnalysisContext) -> Iterator[AnalysisItem]: ...


@dataclass(slots=True)
class SourceRecord:
    id: int
    path: str
    size: int
    mtime_ns: int
    detected_format: str
    detection_reason: str
    sha256: str | None
    hash_status: str
    changed_after: bool


@dataclass(slots=True)
class RunRecord:
    id: int
    source_id: int
    profile: str
    status: str
    coverage: str
    records_read: int
    failures: int
    skip_reason: str | None
    started_at: str
    finished_at: str | None


@dataclass(slots=True)
class AnalysisSummary:
    case_dir: Path
    run_ids: list[int] = field(default_factory=list)
    source_ids: list[int] = field(default_factory=list)
    events: int = 0
    findings: int = 0
    failures: int = 0
    partial: bool = False
    cancelled: bool = False
    messages: list[str] = field(default_factory=list)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
